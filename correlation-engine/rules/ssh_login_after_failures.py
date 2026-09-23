"""
Regra: SSH Login bem-sucedido após múltiplas falhas

Detecta quando um login SSH é bem-sucedido após várias tentativas falhas,
indicando possível comprometimento de credenciais.
"""

from datetime import datetime, timedelta
from typing import Dict, Optional, List
from .base import Rule


class SSHLoginAfterFailuresRule(Rule):
    """
    Detecta login SSH bem-sucedido após múltiplas falhas.

    Condição: 3+ falhas e depois 1 sucesso do mesmo IP em 5 minutos.
    Severidade: CRÍTICA (possível comprometimento)
    """

    def __init__(self):
        super().__init__()
        self.name = "SSH Login After Failures"
        self.severity = "critical"
        self.description = "Login SSH bem-sucedido após múltiplas falhas (possível comprometimento)"

        # Configurações
        self.failure_threshold = 3      # Falhas necessárias antes do sucesso
        self.window_seconds = 300       # 5 minutos

        # Estado: {ip: [timestamps de falhas]}
        self.failures: Dict[str, List[datetime]] = {}

        # Evitar alertas duplicados: {ip: timestamp}
        self.last_alert: Dict[str, datetime] = {}

    def evaluate(self, event: Dict) -> Optional[Dict]:
        """Avalia um evento de autenticação SSH."""
        source_ip = event.get("source.ip")
        if not source_ip:
            return None

        event_time = self._get_event_time(event)
        if not event_time:
            return None

        # Caso 1: É uma falha?
        if self._is_ssh_failure(event):
            self._register_failure(source_ip, event_time)
            return None

        # Caso 2: É um sucesso?
        if self._is_ssh_success(event):
            return self._check_success_after_failures(
                source_ip, event_time, event
            )

        return None

    def _register_failure(self, source_ip: str, event_time: datetime):
        """Registra uma falha no estado."""
        if source_ip not in self.failures:
            self.failures[source_ip] = []

        self.failures[source_ip].append(event_time)

        # Limpar falhas antigas
        cutoff = event_time - timedelta(seconds=self.window_seconds)
        self.failures[source_ip] = [
            ts for ts in self.failures[source_ip] if ts >= cutoff
        ]

    def _check_success_after_failures(
        self,
        source_ip: str,
        event_time: datetime,
        event: Dict
    ) -> Optional[Dict]:
        """Verifica se houve sucesso após falhas."""
        # 1. Tem falhas registradas?
        if source_ip not in self.failures:
            return None

        # 2. Limpar falhas antigas
        cutoff = event_time - timedelta(seconds=self.window_seconds)
        self.failures[source_ip] = [
            ts for ts in self.failures[source_ip] if ts >= cutoff
        ]

        # 3. Tem falhas suficientes?
        count = len(self.failures[source_ip])
        if count < self.failure_threshold:
            return None

        # 4. Evitar alertas duplicados
        if self._should_skip_alert(source_ip, event_time):
            return None

        # 5. Criar alerta
        self.last_alert[source_ip] = event_time

        # Limpar estado após alerta (para não repetir)
        self.failures[source_ip] = []

        return self.create_alert(
            event=event,
            count=count,
            extra={
                "rule.threshold": self.failure_threshold,
                "rule.window_seconds": self.window_seconds,
                "alert.description": f"🚨 POSSÍVEL COMPROMETIMENTO: Login SSH bem-sucedido para '{event.get('user.name', 'unknown')}' após {count} falhas do IP {source_ip}",
                "alert.recommendation": "Verificar imediatamente a conta do usuário e o IP de origem",
            }
        )

    def _is_ssh_failure(self, event: Dict) -> bool:
        """Verifica se é uma falha de SSH."""
        tags = event.get("tags", [])
        if "parsed_ssh_failure" in tags:
            return True

        message = event.get("message", "")
        return "Failed password" in message

    def _is_ssh_success(self, event: Dict) -> bool:
        """Verifica se é um sucesso de SSH."""
        tags = event.get("tags", [])
        if "parsed_ssh_success" in tags:
            return True

        message = event.get("message", "")
        return "Accepted password" in message or "Accepted publickey" in message

    def _get_event_time(self, event: Dict) -> Optional[datetime]:
        """Extrai o timestamp do evento."""
        ts = event.get("@timestamp")
        if not ts:
            return datetime.utcnow()

        try:
            ts = ts.replace("Z", "+00:00")
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
        return diff < 60  # 1 minuto
