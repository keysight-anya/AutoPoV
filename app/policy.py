"""
AutoPoV Policy Router
Selects models for each stage using routing mode and learning store.
"""

from typing import Optional

from app.config import settings
from app.learning_store import get_learning_store


class PolicyRouter:
    """Model routing policy for agent stages."""

    def __init__(self):
        self._learning = get_learning_store()

    def select_model(self, stage: str, cwe: Optional[str] = None, language: Optional[str] = None) -> str:
        mode = settings.ROUTING_MODE

        if mode == "fixed":
            return settings.MODEL_NAME

        if mode == "learning":
            recommended = self._learning.get_model_recommendation(stage, cwe=cwe, language=language)
            if recommended:
                return recommended
            # Fall back to auto router if learning has no signal
            return settings.AUTO_ROUTER_MODEL

        # Default: auto router
        return settings.AUTO_ROUTER_MODEL


policy_router = PolicyRouter()


def get_policy_router() -> PolicyRouter:
    return policy_router
