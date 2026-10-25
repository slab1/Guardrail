import z3
import re
from typing import Any, Dict, List, Optional

class ASTNode:
    pass

class BinaryOp(ASTNode):
    def __init__(self, left, op, right):
        self.left = left
        self.op = op
        self.right = right

class UnaryOp(ASTNode):
    def __init__(self, op, operand):
        self.op = op
        self.operand = operand

class Identifier(ASTNode):
    def __init__(self, name):
        self.name = name

class Literal(ASTNode):
    def __init__(self, value):
        self.value = value

class PolicyParser:
    """
    Simple AST-based parser for policy expressions.
    Supports: AND, OR, NOT, ==, !=, startswith, contains, IMPLIES
    """
    def __init__(self):
        self.tokens = []
        self.pos = 0

    def tokenize(self, expr: str):
        # Regex for tokens: words, quoted strings, operators, parentheses
        token_specification = [
            ('STRING',  r"'[^']*'|\"[^\"]*\""),
            ('OP',      r"==|!=|<=|>=|<|>|AND|OR|NOT|IMPLIES"),
            ('BOOL',    r"true|false"),
            ('IDENT',   r"[a-zA-Z_][a-zA-Z0-9_]*"),
            ('DOT',     r"\."),
            ('LPAREN',  r"\("),
            ('RPAREN',  r"\)"),
            ('SKIP',    r"[ \t\n]+"),
            ('MISMATCH',r"."),
        ]
        tok_regex = '|'.join('(?P<%s>%s)' % pair for pair in token_specification)
        self.tokens = []
        for mo in re.finditer(tok_regex, expr):
            kind = mo.lastgroup
            value = mo.group()
            if kind == 'STRING':
                self.tokens.append(('STRING', value[1:-1]))
            elif kind == 'BOOL':
                self.tokens.append(('BOOL', value == 'true'))
            elif kind == 'SKIP':
                continue
            elif kind == 'MISMATCH':
                raise ValueError(f'Unexpected character: {value}')
            else:
                self.tokens.append((kind, value))
        self.pos = 0

    def peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else (None, None)

    def consume(self, expected_kind=None):
        kind, value = self.peek()
        if expected_kind and kind != expected_kind:
            raise ValueError(f'Expected {expected_kind}, got {kind} ({value}) at pos {self.pos}')
        self.pos += 1
        return value

    def parse(self, expr: str) -> ASTNode:
        self.tokenize(expr)
        return self.parse_implies()

    def parse_implies(self):
        node = self.parse_or()
        while self.peek()[1] == 'IMPLIES':
            self.consume()
            right = self.parse_or()
            node = BinaryOp(node, 'IMPLIES', right)
        return node

    def parse_or(self):
        node = self.parse_and()
        while self.peek()[1] == 'OR':
            self.consume()
            right = self.parse_and()
            node = BinaryOp(node, 'OR', right)
        return node

    def parse_and(self):
        node = self.parse_not()
        while self.peek()[1] == 'AND':
            self.consume()
            right = self.parse_not()
            node = BinaryOp(node, 'AND', right)
        return node

    def parse_not(self):
        if self.peek()[1] == 'NOT':
            self.consume()
            return UnaryOp('NOT', self.parse_not())
        return self.parse_comparison()

    def parse_comparison(self):
        node = self.parse_primary()
        kind, value = self.peek()
        if kind == 'OP' and value in ['==', '!=', 'startswith', 'contains']:
            self.consume()
            right = self.parse_primary()
            return BinaryOp(node, value, right)
        return node

    def parse_primary(self):
        kind, value = self.peek()
        if kind == 'LPAREN':
            self.consume()
            node = self.parse_implies()
            self.consume('RPAREN')
            return node
        elif kind == 'IDENT':
            name = self.consume()
            if self.peek()[0] == 'DOT':
                self.consume() # dot
                method = self.consume('IDENT')
                if method in ['startswith', 'contains']:
                    self.consume('LPAREN')
                    arg = self.parse_primary()
                    self.consume('RPAREN')
                    return BinaryOp(Identifier(name), method, arg)
                # If it's not a method call we recognize, treat it as a nested ident (e.g. action.type)
                return Identifier(f"{name}.{method}")
            return Identifier(name)
        elif kind == 'STRING' or kind == 'BOOL':
            return Literal(self.consume())
        else:
            # Handle constants like 'True' if needed
            if value == 'True':
                self.consume()
                return Literal(True)
            raise ValueError(f'Unexpected token in primary: {kind} ({value})')

class Z3Compiler:
    def __init__(self, ctx: z3.Context):
        self.ctx = ctx
        self.vars = {}

    def get_var(self, name: str):
        if name not in self.vars:
            if name == 'consent_granted':
                self.vars[name] = z3.Bool(name, ctx=self.ctx)
            else:
                self.vars[name] = z3.String(name, ctx=self.ctx)
        return self.vars[name]

    def compile(self, node: ASTNode):
        if isinstance(node, Literal):
            if isinstance(node.value, bool):
                return z3.BoolVal(node.value, ctx=self.ctx)
            return z3.StringVal(node.value, ctx=self.ctx)
        
        if isinstance(node, Identifier):
            return self.get_var(node.name)
        
        if isinstance(node, UnaryOp):
            operand = self.compile(node.operand)
            if node.op == 'NOT':
                return z3.Not(operand)
        
        if isinstance(node, BinaryOp):
            left = self.compile(node.left)
            right = self.compile(node.right)
            
            if node.op == '==':
                return left == right
            elif node.op == '!=':
                return left != right
            elif node.op == 'AND':
                return z3.And(left, right)
            elif node.op == 'OR':
                return z3.Or(left, right)
            elif node.op == 'IMPLIES':
                return z3.Implies(left, right)
            elif node.op == 'startswith':
                # Z3 string PrefixOf
                return z3.PrefixOf(right, left)
            elif node.op == 'contains':
                # Z3 string Contains
                return z3.Contains(left, right)
        
        raise ValueError(f'Unknown AST node or operator: {type(node)}')
