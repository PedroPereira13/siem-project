"""
Regra: SSH Brute Force

Detecta múltiplas falhas de login SSH do mesmo IP em curto período.
"""

from datetime import datetime, timedelta
from typing import Dict, Optional, List
from .base import Rule


class SSHBruteForceRule(Rule):
    """
    Detecta tentativas de brute force SSH.

    Condição: 5+ falhas de SSH do mesmo IP em 60 segundos.
    """

    def __init__(self):
        super().__init__()
        self.name = "SSH Brute Force"
        self.severity = "high"
        self.description = "Múltiplas falhas de login SSH do mesmo IP"

        # Configurações da regra
        self.threshold = 5           # Número de falhas para disparar
        self.window_seconds = 60     # Janela de tempo em segundos

        # Estado: {ip: [timestamp1, timestamp2, ...]}
        self.failures: Dict[str, List[datetime]] = {}

        # Evitar alertas duplicados
        # {ip: ultimo_timestamp_alerta}
        self.last_alert: Dict[str, datetime] = {}

    def evaluate(self, event: Dict) -> Optional[Dict]:
        """
        Avalia um evento de falha de SSH.

        Args:
            event: Evento do Elasticsearch

        Returns:
            Alerta se a regra disparar, None caso contrário
        """
        # 1. Verificar se é uma falha de SSH
        if not self._is_ssh_failure(event):
            return None

        # 2. Extrair IP de origem
        source_ip = event.get("source.ip")
        if not source_ip:
            return None

        # 3. Obter timestamp do evento
        event_time = self._get_event_time(event)
        if not event_time:
            return None

        # 4. Atualizar estado
        if source_ip not in self.failures:
            self.failures[source_ip] = []

        self.failures[source_ip].append(event_time)

        # 5. Limpar timestamps antigos (fora da janela)
        cutoff = event_time - timedelta(seconds=self.window_seconds)
        self.failures[source_ip] = [
            ts for ts in self.failures[source_ip] if ts >= cutoff
        ]

        # 6. Verificar se atingiu o threshold
        count = len(self.failures[source_ip])
        if count < self.threshold:
            return None

        # 7. Evitar alertas duplicados (1 alerta por minuto por IP)
        if self._should_skip_alert(source_ip, event_time):
            return None

        # 8. Criar alerta
        self.last_alert[source_ip] = event_time

        return self.create_alert(
            event=event,
            count=count,
            extra={
                "rule.threshold": self.threshold,
                "rule.window_seconds": self.window_seconds,
                "alert.description": f"IP {source_ip} fez {count} tentativas de login SSH falhas em {self.window_seconds} segundos",
            }
        )

    def _is_ssh_failure(self, event: Dict) -> bool:
        """Verifica se o evento é uma falha de SSH."""
        # Verificar tags
        tags = event.get("tags", [])
        if "parsed_ssh_failure" in tags:
            return True

        # Verificar campos
        if event.get("event.type") == "authentication" and \
           event.get("event.outcome") == "failure":
            return True

        # Verificar mensagem
        message = event.get("message", "")
        if "Failed password" in message:
            return True

        return False

    def _get_event_time(self, event: Dict) -> Optional[datetime]:
        """Extrai o timestamp do evento."""
        ts = event.get("@timestamp")
        if not ts:
            return datetime.utcnow()

        try:
            # Formato ISO 8601: 2026-09-23T10:30:00.123Z
            ts = ts.replace("Z", "+00:00")
            # Remove microssegundos se houver
            if "." in ts:
                ts = ts.split(".")[0] + "+00:00"
            return datetime.fromisoformat(ts.replace("+00:00", ""))
        except Exception:
            return datetime.utcnow()

    def _should_skip_alert(self, source_ip: str, event_time: datetime) -> bool:
        """Evita alertas duplicados em curto período."""
        if source_ip not in self.last_alert:
            return False

        last = self.last_alert[source_ip]
        diff = (event_time - last).total_seconds()

        # Só alerta novamente após 60 segundos
        return diff < self.window_seconds
