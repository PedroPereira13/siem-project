"""
Classe base para todas as regras de detecção
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Optional


class Rule(ABC):
    """
    Classe base abstrata para regras de detecção.

    Cada regra implementa:
    - name: nome da regra
    - severity: severidade (low, medium, high, critical)
    - description: descrição do que a regra detecta
    - evaluate(): lógica de detecção
    """

    def __init__(self):
        self.name = "Base Rule"
        self.severity = "low"
        self.description = "Base rule description"
        self.state = {}  # Estado interno (memória)

    @abstractmethod
    def evaluate(self, event: Dict) -> Optional[Dict]:
        """
        Avalia um evento e retorna um alerta se a regra disparar.

        Args:
            event: Dicionário com os campos do evento

        Returns:
            Dict com o alerta ou None se não disparar
        """
        pass

    def create_alert(self, event: Dict, count: int, extra: Dict = None) -> Dict:
        """
        Cria um alerta padronizado.

        Args:
            event: Evento que disparou o alerta
            count: Contagem de eventos relacionados
            extra: Campos adicionais

        Returns:
            Dict com o alerta
        """
        alert = {
            "rule.name": self.name,
            "rule.severity": self.severity,
            "rule.description": self.description,
            "alert.timestamp": datetime.utcnow().isoformat() + "Z",
            "alert.count": count,
            "event.original": event.get("message", ""),
        }

        # Adiciona campos úteis do evento
        for field in ["source.ip", "user.name", "event.type", "event.outcome"]:
            if field in event:
                alert[field] = event[field]

        # Adiciona campos extras
        if extra:
            alert.update(extra)

        return alert
