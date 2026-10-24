"""Policy Expression Parser - AST-based policy language parser.

Implements a formal grammar for policy expressions with lexer and parser.
Supports syntax validation and error reporting.
"""

from enum import Enum, auto
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Union, Tuple
from collections import deque
import re


class TokenType(Enum):
    """Token types for policy language."""
    # Keywords
    KEYWORD_POLICY = auto()
    KEYWORD_RULE = auto()
    KEYWORD_IF = auto()
    KEYWORD_THEN = auto()
    KEYWORD_ALLOW = auto()
    KEYWORD_DENY = auto()
    KEYWORD_REQUIRE_APPROVAL = auto()
    KEYWORD_FORALL = auto()
    KEYWORD_EXISTS = auto()
    KEYWORD_ALWAYS = auto()
    KEYWORD_EVENTUALLY = auto()
    KEYWORD_UNTIL = auto()
    KEYWORD_NEXT = auto()
    KEYWORD_PRIORITY = auto()
    
    # Operators
    OP_EQ = auto()
    OP_NE = auto()
    OP_LT = auto()
    OP_LE = auto()
    OP_GT = auto()
    OP_GE = auto()
    OP_AND = auto()
    OP_OR = auto()
    OP_NOT = auto()
    OP_IMPLIES = auto()
    OP_IFF = auto()
    OP_IN = auto()
    OP_NOT_IN = auto()
    OP_CONTAINS = auto()
    OP_MATCHES = auto()
    OP_STARTS_WITH = auto()
    OP_ENDS_WITH = auto()
    
    # Delimiters
    L_PAREN = auto()
    R_PAREN = auto()
    L_BRACE = auto()
    R_BRACE = auto()
    L_BRACKET = auto()
    R_BRACKET = auto()
    COLON = auto()
    COMMA = auto()
    SEMICOLON = auto()
    DOT = auto()
    
    # Literals
    IDENTIFIER = auto()
    STRING = auto()
    NUMBER = auto()
    BOOLEAN = auto()
    
    # Special
    EOF = auto()
    UNKNOWN = auto()


@dataclass
class Token:
    """A token in the policy language."""
    type: TokenType
    value: str
    line: int
    column: int
    
    def __repr__(self) -> str:
        return f"Token({self.type.name}, {self.value!r}, {self.line}:{self.column})"


class Lexer:
    """Lexer for policy language."""
    
    KEYWORDS = {
        'policy': TokenType.KEYWORD_POLICY,
        'rule': TokenType.KEYWORD_RULE,
        'if': TokenType.KEYWORD_IF,
        'then': TokenType.KEYWORD_THEN,
        'allow': TokenType.KEYWORD_ALLOW,
        'deny': TokenType.KEYWORD_DENY,
        'require_approval': TokenType.KEYWORD_REQUIRE_APPROVAL,
        'forall': TokenType.KEYWORD_FORALL,
        'exists': TokenType.KEYWORD_EXISTS,
        'always': TokenType.KEYWORD_ALWAYS,
        'eventually': TokenType.KEYWORD_EVENTUALLY,
        'until': TokenType.KEYWORD_UNTIL,
        'next': TokenType.KEYWORD_NEXT,
        'priority': TokenType.KEYWORD_PRIORITY,
        'in': TokenType.OP_IN,
        'contains': TokenType.OP_CONTAINS,
        'matches': TokenType.OP_MATCHES,
        'starts_with': TokenType.OP_STARTS_WITH,
        'ends_with': TokenType.OP_ENDS_WITH,
        'and': TokenType.OP_AND,
        'or': TokenType.OP_OR,
        'not': TokenType.OP_NOT,
        'implies': TokenType.OP_IMPLIES,
        'iff': TokenType.OP_IFF,
        'true': TokenType.BOOLEAN,
        'false': TokenType.BOOLEAN,
    }
    
    SINGLE_CHAR_TOKENS = {
        '(': TokenType.L_PAREN,
        ')': TokenType.R_PAREN,
        '{': TokenType.L_BRACE,
        '}': TokenType.R_BRACE,
        '[': TokenType.L_BRACKET,
        ']': TokenType.R_BRACKET,
        ':': TokenType.COLON,
        ',': TokenType.COMMA,
        ';': TokenType.SEMICOLON,
        '.': TokenType.DOT,
    }
    
    MULTI_CHAR_OPERATORS = {
        '==': TokenType.OP_EQ,
        '!=': TokenType.OP_NE,
        '<=': TokenType.OP_LE,
        '>=': TokenType.OP_GE,
        '<': TokenType.OP_LT,
        '>': TokenType.OP_GT,
    }
    
    def __init__(self, text: str):
        self.text = text
        self.pos = 0
        self.line = 1
        self.column = 1
        self.tokens: List[Token] = []
    
    def tokenize(self) -> List[Token]:
        """Tokenize the input text."""
        while self.pos < len(self.text):
            char = self.text[self.pos]
            
            if char in ' \t\r':
                self._advance()
                continue
            if char == '\n':
                self._advance_line()
                continue
            
            if char == '#':
                self._skip_comment()
                continue
            
            if char in ('"', "'"):
                self._read_string(char)
                continue
            
            if char.isdigit() or (char == '.' and self._peek().isdigit()):
                self._read_number()
                continue
            
            if char.isalpha() or char == '_':
                self._read_identifier()
                continue
            
            if self._try_read_operator():
                continue
            
            if char in self.SINGLE_CHAR_TOKENS:
                token_type = self.SINGLE_CHAR_TOKENS[char]
                self.tokens.append(Token(token_type, char, self.line, self.column))
                self._advance()
                continue
            
            self.tokens.append(Token(TokenType.UNKNOWN, char, self.line, self.column))
            self._advance()
        
        self.tokens.append(Token(TokenType.EOF, '', self.line, self.column))
        return self.tokens
    
    def _advance(self):
        self.pos += 1
        self.column += 1
    
    def _advance_line(self):
        self.pos += 1
        self.line += 1
        self.column = 1
    
    def _peek(self, offset: int = 1) -> str:
        pos = self.pos + offset
        return self.text[pos] if pos < len(self.text) else ''
    
    def _skip_comment(self):
        while self.pos < len(self.text) and self.text[self.pos] != '\n':
            self._advance()
    
    def _read_string(self, quote_char: str):
        start_line = self.line
        start_column = self.column
        self._advance()
        
        value = ''
        while self.pos < len(self.text) and self.text[self.pos] != quote_char:
            if self.text[self.pos] == '\n':
                self._advance_line()
            else:
                value += self.text[self.pos]
                self._advance()
        
        self._advance()
        self.tokens.append(Token(TokenType.STRING, value, start_line, start_column))
    
    def _read_number(self):
        start = self.pos
        start_line = self.line
        start_column = self.column
        
        while self.pos < len(self.text) and (self.text[self.pos].isdigit() or self.text[self.pos] == '.'):
            self._advance()
        
        value = self.text[start:self.pos]
        self.tokens.append(Token(TokenType.NUMBER, value, start_line, start_column))
    
    def _read_identifier(self):
        start = self.pos
        start_line = self.line
        start_column = self.column
        
        while self.pos < len(self.text) and (self.text[self.pos].isalnum() or self.text[self.pos] in ['_', '-']):
            self._advance()
        
        value = self.text[start:self.pos]
        token_type = self.KEYWORDS.get(value.lower(), TokenType.IDENTIFIER)
        self.tokens.append(Token(token_type, value, start_line, start_column))
    
    def _try_read_operator(self) -> bool:
        two_char = self.text[self.pos:self.pos+2]
        if two_char in self.MULTI_CHAR_OPERATORS:
            token_type = self.MULTI_CHAR_OPERATORS[two_char]
            self.tokens.append(Token(token_type, two_char, self.line, self.column))
            self._advance()
            self._advance()
            return True
        
        one_char = self.text[self.pos]
        if one_char in ['=', '!', '<', '>']:
            self.tokens.append(Token(TokenType.UNKNOWN, one_char, self.line, self.column))
            self._advance()
            return True
        
        return False


# AST Node Types
class ASTNode:
    """Base class for AST nodes."""
    pass


@dataclass
class PolicyNode(ASTNode):
    """Policy declaration node."""
    name: str
    rules: List['RuleNode']
    line: int = 0


@dataclass
class RuleNode(ASTNode):
    """Rule declaration node."""
    id: str
    name: Optional[str]
    condition: 'ExpressionNode'
    action: str
    priority: int = 0
    line: int = 0


@dataclass
class ExpressionNode(ASTNode):
    """Base class for expressions."""
    pass


@dataclass
class VariableNode(ExpressionNode):
    """Variable reference node."""
    name: str
    line: int = 0


@dataclass
class LiteralNode(ExpressionNode):
    """Literal value node."""
    value: Any
    type: str
    line: int = 0


@dataclass
class ConditionNode(ExpressionNode):
    """Condition node."""
    variable: str
    operator: str
    value: Any
    line: int = 0


@dataclass
class BinaryOpNode(ExpressionNode):
    """Binary operation node."""
    operator: str
    left: ExpressionNode
    right: ExpressionNode
    line: int = 0


@dataclass
class UnaryOpNode(ExpressionNode):
    """Unary operation node."""
    operator: str
    operand: ExpressionNode
    line: int = 0


@dataclass
class QuantifierNode(ExpressionNode):
    """Quantifier node (forall/exists)."""
    quantifier: str
    variable: str
    expression: ExpressionNode
    line: int = 0


@dataclass
class TemporalNode(ExpressionNode):
    """Temporal logic node."""
    operator: str
    expression: ExpressionNode
    line: int = 0


class ParseError(Exception):
    """Parser error."""
    def __init__(self, message: str, line: int, column: int):
        self.message = message
        self.line = line
        self.column = column
        super().__init__(f"Parse error at {line}:{column}: {message}")


class Parser:
    """Parser for policy language."""
    
    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.pos = 0
        self.current = tokens[0] if tokens else Token(TokenType.EOF, '', 0, 0)
    
    def parse(self) -> PolicyNode:
        """Parse policy file."""
        return self._parse_policy()
    
    def _advance(self):
        self.pos += 1
        if self.pos < len(self.tokens):
            self.current = self.tokens[self.pos]
        else:
            self.current = Token(TokenType.EOF, '', 0, 0)
    
    def _match(self, *types: TokenType) -> bool:
        if self.current.type in types:
            self._advance()
            return True
        return False
    
    def _consume(self, token_type: TokenType, message: str) -> Token:
        if self.current.type == token_type:
            token = self.current
            self._advance()
            return token
        
        raise ParseError(message, self.current.line, self.current.column)
    
    def _parse_policy(self) -> PolicyNode:
        """Parse policy declaration."""
        self._consume(TokenType.KEYWORD_POLICY, "Expected 'policy'")
        name_token = self._consume(TokenType.IDENTIFIER, "Expected policy name")
        self._consume(TokenType.L_BRACE, "Expected '{' after policy name")
        
        rules = []
        while not self._match(TokenType.R_BRACE):
            if self.current.type == TokenType.KEYWORD_RULE:
                rules.append(self._parse_rule())
            else:
                raise ParseError(f"Unexpected token in policy: {self.current}", 
                               self.current.line, self.current.column)
        
        return PolicyNode(name=name_token.value, rules=rules, line=name_token.line)
    
    def _parse_rule(self) -> RuleNode:
        """Parse rule declaration."""
        line = self.current.line
        self._consume(TokenType.KEYWORD_RULE, "Expected 'rule'")
        
        id_token = self._consume(TokenType.IDENTIFIER, "Expected rule ID")
        rule_id = id_token.value
        
        rule_name = None
        if self._match(TokenType.COLON):
            name_token = self._consume(TokenType.IDENTIFIER, "Expected rule name")
            rule_name = name_token.value
        
        self._consume(TokenType.L_BRACE, "Expected '{' after rule declaration")
        
        condition = None
        action = None
        priority = 0
        
        while not self._match(TokenType.R_BRACE):
            if self._match(TokenType.KEYWORD_IF):
                condition = self._parse_expression()
            elif self._match(TokenType.KEYWORD_PRIORITY):
                priority_token = self._consume(TokenType.NUMBER, "Expected priority number")
                priority = int(priority_token.value)
            elif self._match(TokenType.KEYWORD_THEN):
                if self._match(TokenType.KEYWORD_ALLOW):
                    action = 'allow'
                elif self._match(TokenType.KEYWORD_DENY):
                    action = 'deny'
                elif self._match(TokenType.KEYWORD_REQUIRE_APPROVAL):
                    action = 'require_approval'
                else:
                    raise ParseError("Expected action after 'then'", self.current.line, self.current.column)
            elif self._match(TokenType.KEYWORD_ALLOW):
                action = 'allow'
            elif self._match(TokenType.KEYWORD_DENY):
                action = 'deny'
            elif self._match(TokenType.KEYWORD_REQUIRE_APPROVAL):
                action = 'require_approval'
            else:
                raise ParseError(f"Unexpected token in rule: {self.current}",
                               self.current.line, self.current.column)
            
            self._match(TokenType.SEMICOLON)
        
        if condition is None:
            raise ParseError("Rule must have an 'if' condition", line, 0)
        if action is None:
            raise ParseError("Rule must have an action", line, 0)
        
        return RuleNode(id=rule_id, name=rule_name, condition=condition, 
                       action=action, priority=priority, line=line)
    
    def _parse_expression(self) -> ExpressionNode:
        """Parse expression with operator precedence."""
        return self._parse_or()
    
    def _parse_or(self) -> ExpressionNode:
        left = self._parse_and()
        while self._match(TokenType.OP_OR):
            right = self._parse_and()
            left = BinaryOpNode(operator='or', left=left, right=right, line=self.current.line)
        return left
    
    def _parse_and(self) -> ExpressionNode:
        left = self._parse_not()
        while self._match(TokenType.OP_AND):
            right = self._parse_not()
            left = BinaryOpNode(operator='and', left=left, right=right, line=self.current.line)
        return left
    
    def _parse_not(self) -> ExpressionNode:
        if self._match(TokenType.OP_NOT):
            operand = self._parse_comparison()
            return UnaryOpNode(operator='not', operand=operand, line=self.current.line)
        return self._parse_comparison()
    
    def _parse_comparison(self) -> ExpressionNode:
        left = self._parse_primary()
        
        comp_ops = [
            TokenType.OP_EQ, TokenType.OP_NE, TokenType.OP_LT, TokenType.OP_LE,
            TokenType.OP_GT, TokenType.OP_GE, TokenType.OP_IN, TokenType.OP_CONTAINS,
            TokenType.OP_MATCHES, TokenType.OP_STARTS_WITH, TokenType.OP_ENDS_WITH
        ]
        
        if self.current.type in comp_ops:
            op_token = self.current
            self._advance()
            right = self._parse_primary()
            
            if isinstance(left, VariableNode):
                return ConditionNode(
                    variable=left.name,
                    operator=op_token.value,
                    value=self._extract_value(right),
                    line=op_token.line
                )
            
            return BinaryOpNode(operator=op_token.value, left=left, right=right, line=op_token.line)
        
        return left
    
    def _parse_primary(self) -> ExpressionNode:
        """Parse primary expression."""
        if self._match(TokenType.L_PAREN):
            expr = self._parse_expression()
            self._consume(TokenType.R_PAREN, "Expected ')'")
            return expr
        
        if self._match(TokenType.KEYWORD_FORALL):
            var_token = self._consume(TokenType.IDENTIFIER, "Expected variable name after forall")
            self._consume(TokenType.COLON, "Expected ':' after variable name")
            expr = self._parse_expression()
            return QuantifierNode(quantifier='forall', variable=var_token.value, 
                                expression=expr, line=var_token.line)
        
        if self._match(TokenType.KEYWORD_EXISTS):
            var_token = self._consume(TokenType.IDENTIFIER, "Expected variable name after exists")
            self._consume(TokenType.COLON, "Expected ':' after variable name")
            expr = self._parse_expression()
            return QuantifierNode(quantifier='exists', variable=var_token.value,
                                expression=expr, line=var_token.line)
        
        if self._match(TokenType.IDENTIFIER):
            return VariableNode(name=self.tokens[self.pos-1].value, line=self.tokens[self.pos-1].line)
        
        if self._match(TokenType.STRING):
            return LiteralNode(value=self.tokens[self.pos-1].value, type='string', line=self.tokens[self.pos-1].line)
        
        if self._match(TokenType.NUMBER):
            val = self.tokens[self.pos-1].value
            return LiteralNode(value=float(val) if '.' in val else int(val),
                             type='number', line=self.tokens[self.pos-1].line)
        
        if self._match(TokenType.BOOLEAN):
            return LiteralNode(value=True if self.tokens[self.pos-1].value.lower() == 'true' else False,
                             type='bool', line=self.tokens[self.pos-1].line)
        
        raise ParseError(f"Unexpected token: {self.current}", self.current.line, self.current.column)
    
    def _extract_value(self, node: ExpressionNode) -> Any:
        """Extract value from literal node."""
        if isinstance(node, LiteralNode):
            return node.value
        elif isinstance(node, VariableNode):
            return node.name
        raise ValueError(f"Cannot extract value from {type(node)}")


class PolicyParser:
    """Main parser interface for policy language."""
    
    def __init__(self):
        self.errors: List[ParseError] = []
        self.warnings: List[str] = []
    
    def parse_file(self, filepath: str) -> Optional[PolicyNode]:
        """Parse policy file."""
        try:
            with open(filepath, 'r') as f:
                text = f.read()
            return self.parse_text(text)
        except Exception as e:
            self.errors.append(ParseError(str(e), 0, 0))
            return None
    
    def parse_text(self, text: str) -> Optional[PolicyNode]:
        """Parse policy text."""
        self.errors = []
        self.warnings = []
        
        lexer = Lexer(text)
        tokens = lexer.tokenize()
        
        unknown_tokens = [t for t in tokens if t.type == TokenType.UNKNOWN]
        for token in unknown_tokens:
            self.errors.append(ParseError(f"Unknown token: {token.value}", token.line, token.column))
        
        try:
            parser = Parser(tokens)
            policy = parser.parse()
            return policy
        except ParseError as e:
            self.errors.append(e)
            return None
    
    def validate(self, policy: PolicyNode) -> Tuple[bool, List[str]]:
        """Validate parsed policy."""
        warnings = []
        
        for rule in policy.rules:
            if rule.condition is None:
                warnings.append(f"Rule {rule.id} has no condition")
            
            if not (0 <= rule.priority <= 1000):
                warnings.append(f"Rule {rule.id} has unusual priority: {rule.priority}")
        
        return len(warnings) == 0, warnings
    
    def to_ast(self, policy: PolicyNode) -> Dict[str, Any]:
        """Convert AST to dictionary for inspection."""
        def node_to_dict(node: ASTNode) -> Dict[str, Any]:
            if isinstance(node, PolicyNode):
                return {
                    'type': 'Policy',
                    'name': node.name,
                    'rules': [node_to_dict(r) for r in node.rules]
                }
            elif isinstance(node, RuleNode):
                return {
                    'type': 'Rule',
                    'id': node.id,
                    'name': node.name,
                    'action': node.action,
                    'priority': node.priority,
                    'condition': node_to_dict(node.condition)
                }
            elif isinstance(node, ConditionNode):
                return {
                    'type': 'Condition',
                    'variable': node.variable,
                    'operator': node.operator,
                    'value': node.value
                }
            elif isinstance(node, BinaryOpNode):
                return {
                    'type': 'BinaryOp',
                    'operator': node.operator,
                    'left': node_to_dict(node.left),
                    'right': node_to_dict(node.right)
                }
            elif isinstance(node, UnaryOpNode):
                return {
                    'type': 'UnaryOp',
                    'operator': node.operator,
                    'operand': node_to_dict(node.operand)
                }
            return {'type': type(node).__name__}
        
        return node_to_dict(policy)


if __name__ == "__main__":
    sample_policy = """
    policy guardrail_safety {
        rule safety_001 {
            if action_type == "admin" and user_consent == false;
            then deny;
            priority 100;
        }
    }
    """
    
    parser = PolicyParser()
    policy = parser.parse_text(sample_policy)
    
    if policy:
        print(f"Parsed policy: {policy.name}")
        print(f"Rules: {len(policy.rules)}")
        for rule in policy.rules:
            print(f"  - {rule.id}: {rule.action} (priority {rule.priority})")
    else:
        print("Parse errors:")
        for error in parser.errors:
            print(f"  {error}")
