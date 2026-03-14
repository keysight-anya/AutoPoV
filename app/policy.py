"""
AutoPoV Policy Router
Selects models for each stage using routing mode and learning store.
"""

from typing import Optional, Dict, Any

from app.config import settings
from app.learning_store import get_learning_store


class PolicyRouter:
    """Model routing policy for agent stages."""

    def __init__(self):
        self._learning = get_learning_store()

    def select_model(self, stage: str, cwe: Optional[str] = None, language: Optional[str] = None) -> str:
        mode = settings.ROUTING_MODE
        auto_model = settings.AUTO_ROUTER_MODEL or "openrouter/auto"

        if mode == "fixed":
            return settings.MODEL_NAME or auto_model

        if mode == "learning":
            recommended = self._learning.get_model_recommendation(stage, cwe=cwe, language=language)
            if recommended:
                return recommended
            return auto_model

        if mode == "hierarchical":
            if stage == "investigate":
                return settings.HIERARCHICAL_SIFTER_MODEL or auto_model
            if stage == "pov":
                return settings.HIERARCHICAL_ARCHITECT_MODEL or auto_model
            return settings.HIERARCHICAL_SIFTER_MODEL or auto_model

        return auto_model

    def get_hierarchical_config(self) -> Dict[str, Any]:
        """Get hierarchical routing configuration."""
        return {
            "mode": "hierarchical",
            "sifter_model": settings.HIERARCHICAL_SIFTER_MODEL,
            "architect_model": settings.HIERARCHICAL_ARCHITECT_MODEL,
            "confidence_threshold": settings.HIERARCHICAL_SIFTER_CONFIDENCE_THRESHOLD
        }


policy_router = PolicyRouter()


def get_policy_router() -> PolicyRouter:
    return policy_router
