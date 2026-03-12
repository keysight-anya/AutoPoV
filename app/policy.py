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

        if mode == "fixed":
            return settings.MODEL_NAME

        if mode == "learning":
            recommended = self._learning.get_model_recommendation(stage, cwe=cwe, language=language)
            if recommended:
                return recommended
            # Fall back to auto router if learning has no signal
            return settings.AUTO_ROUTER_MODEL

        if mode == "hierarchical":
            # Hierarchical mode: use sifter for investigation, architect for PoV generation
            if stage == "investigate":
                return settings.HIERARCHICAL_SIFTER_MODEL
            elif stage == "pov":
                return settings.HIERARCHICAL_ARCHITECT_MODEL
            else:
                # Default to sifter for other stages
                return settings.HIERARCHICAL_SIFTER_MODEL

        # Default: auto router
        return settings.AUTO_ROUTER_MODEL

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
