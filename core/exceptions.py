"""Exceptions custom du projet."""


class AgentError(Exception):
    """Base pour toutes les erreurs du projet."""
    pass


class LLMError(AgentError):
    """Erreur lors d'un appel LLM."""
    pass


class ScopeError(AgentError):
    """Scope invalide ou cible non autorisee."""
    pass


class ConfigError(AgentError):
    """Configuration manquante ou invalide."""
    pass
