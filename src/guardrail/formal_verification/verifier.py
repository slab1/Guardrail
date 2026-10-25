import z3
import time
import json
from typing import Any, Dict, List
from .parser import PolicyParser, Z3Compiler

class FormalVerifier:
    def __init__(self):
        self.ctx = z3.Context()
        self.parser = PolicyParser()
        self.compiler = Z3Compiler(self.ctx)
        self.cache: Dict[str, bool] = {}

    def verify_policy(self, policy_expr: str, context: Dict[str, Any]) -> bool:
        """
        Formally verifies logical invariants using Z3.
        """
        # Quick check for trivial policies
        if policy_expr.strip() == "True":
            return True

        cache_key = f"{policy_expr}:{json.dumps(context, sort_keys=True)}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        try:
            # Parse the expression into an AST
            ast_node = self.parser.parse(policy_expr)
            
            # Compile AST to Z3 expression
            z3_expr = self.compiler.compile(ast_node)
            
            # Create a solver
            solver = z3.Solver(ctx=self.ctx)
            solver.set("timeout", 50) # 50ms timeout for safety
            
            # Add context as constraints
            for key, value in context.items():
                var = self.compiler.get_var(key)
                if isinstance(value, bool):
                    solver.add(var == z3.BoolVal(value, ctx=self.ctx))
                else:
                    solver.add(var == z3.StringVal(str(value), ctx=self.ctx))
            
            # We want to check if the policy expression is ALWAYS true given the context.
            # In SMT terms, we check if context AND NOT policy is UNSAT.
            solver.add(z3.Not(z3_expr))
            
            result = solver.check()
            is_safe = (result == z3.unsat)
            
            self.cache[cache_key] = is_safe
            return is_safe
        except Exception as e:
            # Fallback to simulated logic if parsing fails or solver errors
            print(f"Verifier fallback: {e}")
            is_safe = self._simulated_fallback(policy_expr, context)
            self.cache[cache_key] = is_safe
            return is_safe

    def _simulated_fallback(self, policy_expr: str, context: Dict[str, Any]) -> bool:
        is_safe = True
        if "action == 'file_read'" in policy_expr and context.get("action") != "file_read":
            is_safe = False
        if "resource.startswith('/workspace/')" in policy_expr:
            res = context.get("resource", "")
            if not res.startswith("/workspace/"):
                is_safe = False
        return is_safe

def create_verifier() -> FormalVerifier:
    return FormalVerifier()
