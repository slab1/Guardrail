"""Token service for Guardrail - JWT-like tokens with intent binding and per-step tokens."""
import time
import hashlib
import hmac
import json
import base64
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from enum import Enum


class TokenType(Enum):
    PLAN = "plan"
    STEP = "step"


@dataclass
class TokenPayload:
    """Payload for a token."""
    token_type: TokenType
    plan_id: str
    step_id: Optional[str] = None
    intent: str = ""
    agent_class: str = ""
    user_id: str = ""
    autonomy_level: int = 0
    issued_at: int = field(default_factory=lambda: int(time.time()))
    expires_at: int = 0
    nonce: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token_type": self.token_type.value,
            "plan_id": self.plan_id,
            "step_id": self.step_id,
            "intent": self.intent,
            "agent_class": self.agent_class,
            "user_id": self.user_id,
            "autonomy_level": self.autonomy_level,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TokenPayload":
        return cls(
            token_type=TokenType(data["token_type"]),
            plan_id=data["plan_id"],
            step_id=data.get("step_id"),
            intent=data["intent"],
            agent_class=data["agent_class"],
            user_id=data["user_id"],
            autonomy_level=data["autonomy_level"],
            issued_at=data["issued_at"],
            expires_at=data["expires_at"],
            nonce=data["nonce"],
        )


class TokenService:
    """Service for creating and validating tokens."""

    def __init__(self, secret_key: str = "guardrail-secret-key-change-in-production"):
        self.secret_key = secret_key.encode()
        self.token_ttl = 900  # 15 minutes default

    def _sign(self, payload: Dict[str, Any]) -> str:
        """Create HMAC signature for payload."""
        message = json.dumps(payload, sort_keys=True).encode()
        signature = hmac.new(self.secret_key, message, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(signature).decode().rstrip("=")

    def _create_token(self, payload: TokenPayload) -> str:
        """Create a signed token string."""
        payload_dict = payload.to_dict()
        payload_dict["signature"] = self._sign(payload_dict)
        token_json = json.dumps(payload_dict, separators=(",", ":"))
        return base64.urlsafe_b64encode(token_json.encode()).decode().rstrip("=")

    def _verify_token(self, token: str) -> Optional[TokenPayload]:
        """Verify and decode a token."""
        try:
            token_json = base64.urlsafe_b64decode(token + "==").decode()
            payload_dict = json.loads(token_json)
            signature = payload_dict.pop("signature", None)
            if not signature:
                return None
            expected_sig = self._sign(payload_dict)
            if not hmac.compare_digest(signature, expected_sig):
                return None
            # Check expiration
            if payload_dict["expires_at"] < int(time.time()):
                return None
            return TokenPayload.from_dict(payload_dict)
        except Exception:
            return None

    def create_plan_token(
        self,
        plan_id: str,
        intent: str,
        agent_class: str,
        user_id: str,
        autonomy_level: int,
        ttl: Optional[int] = None
    ) -> str:
        """Create a plan-level token."""
        ttl = ttl or self.token_ttl
        now = int(time.time())
        payload = TokenPayload(
            token_type=TokenType.PLAN,
            plan_id=plan_id,
            intent=intent,
            agent_class=agent_class,
            user_id=user_id,
            autonomy_level=autonomy_level,
            issued_at=now,
            expires_at=now + ttl,
            nonce=hashlib.sha256(f"{plan_id}{now}".encode()).hexdigest()[:16],
        )
        return self._create_token(payload)

    def create_step_token(
        self,
        plan_id: str,
        step_id: str,
        intent: str,
        agent_class: str,
        user_id: str,
        autonomy_level: int,
        ttl: Optional[int] = None
    ) -> str:
        """Create a per-step token bound to the plan."""
        ttl = ttl or self.token_ttl
        now = int(time.time())
        payload = TokenPayload(
            token_type=TokenType.STEP,
            plan_id=plan_id,
            step_id=step_id,
            intent=intent,
            agent_class=agent_class,
            user_id=user_id,
            autonomy_level=autonomy_level,
            issued_at=now,
            expires_at=now + ttl,
            nonce=hashlib.sha256(f"{plan_id}{step_id}{now}".encode()).hexdigest()[:16],
        )
        return self._create_token(payload)

    def validate_token(self, token: str) -> Optional[TokenPayload]:
        """Validate a token and return its payload if valid."""
        return self._verify_token(token)

    def validate_plan_token(self, token: str, plan_id: str) -> Optional[TokenPayload]:
        """Validate a plan token for a specific plan."""
        payload = self._verify_token(token)
        if payload and payload.token_type == TokenType.PLAN and payload.plan_id == plan_id:
            return payload
        return None

    def validate_step_token(self, token: str, plan_id: str, step_id: str) -> Optional[TokenPayload]:
        """Validate a step token for a specific plan and step."""
        payload = self._verify_token(token)
        if (payload and payload.token_type == TokenType.STEP and 
            payload.plan_id == plan_id and payload.step_id == step_id):
            return payload
        return None


# Global token service instance
_token_service: Optional[TokenService] = None


def get_token_service() -> TokenService:
    """Get the global token service instance."""
    global _token_service
    if _token_service is None:
        _token_service = TokenService()
    return _token_service


def create_plan_token(
    plan_id: str,
    intent: str,
    agent_class: str,
    user_id: str,
    autonomy_level: int,
    ttl: Optional[int] = None
) -> str:
    """Convenience function to create a plan token."""
    return get_token_service().create_plan_token(
        plan_id, intent, agent_class, user_id, autonomy_level, ttl
    )


def create_step_token(
    plan_id: str,
    step_id: str,
    intent: str,
    agent_class: str,
    user_id: str,
    autonomy_level: int,
    ttl: Optional[int] = None
) -> str:
    """Convenience function to create a step token."""
    return get_token_service().create_step_token(
        plan_id, step_id, intent, agent_class, user_id, autonomy_level, ttl
    )


def validate_token(token: str) -> Optional[TokenPayload]:
    """Convenience function to validate a token."""
    return get_token_service().validate_token(token)


def validate_plan_token(token: str, plan_id: str) -> Optional[TokenPayload]:
    """Convenience function to validate a plan token."""
    return get_token_service().validate_plan_token(token, plan_id)


def validate_step_token(token: str, plan_id: str, step_id: str) -> Optional[TokenPayload]:
    """Convenience function to validate a step token."""
    return get_token_service().validate_step_token(token, plan_id, step_id)