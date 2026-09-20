"""Classe mère des agents. Chaque agent hérite de BaseAgent."""
from abc import ABC, abstractmethod


class BaseAgent(ABC):
    name = "base"

    def __init__(self):
        self.findings = []
        self.history = []

    @abstractmethod
    def run(self, *args, **kwargs):
        """Chaque agent implémente sa logique ici."""
        ...
