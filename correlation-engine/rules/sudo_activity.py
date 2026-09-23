"""
Regra: Atividade Sudo Suspeita

Detecta múltiplas tentativas de sudo em curto período,
especialmente tentativas que falharam (usuário fora do sudoers).
"""

from datetime import datetime, timedelta
from typing import Dict, Optional, List
from .base import Rule


class SudoActivityRule(Rule):
    """
    Detecta atividade sudo suspeita.

    Condição: 3+ tentativas de sudo em 30 segundos.
    Severidade: média (ou alta se houver falhas)
    """

    def __init__(self):
        super().__init__()
        self.name = "Sudo Activity"
        self.severity = "medium"
        self.description = "Múltiplas tentativas de sudo em curto período"

        # Configurações
        self.threshold = 3           # Número de tentativas
        self.window_seconds = 30     # Janela de tempo

        # Estado: {user: [timestamps]}
        self.sudo_attempts: Dict[str, List[datetime]] = {}

        # Contador de falhas por usuário
        self.failed_attempts: Dict[str, int] = {}

        # Evitar alertas duplicados
        self.last_alert: Dict[str, datetime] = {}

    def evaluate(self, event: Dict) -> Optional[Dict]:
        """Avalia um evento de sudo."""
        # 1. Verificar se é evento de sudo
        if not self._is_sudo_event(event):
            return None

        # 2. Extrair usuário
        user = event.get("user.name")
        if not user:
            return None

        # 3. Extrair timestamp
        event_time = self._get_event_time(event)
        if not event_time:
            return None

        # 4. Verificar se o sudo falhou
        is_failure = self._is_sudo_failure(event)

        # 5. Registrar tentativa
        if user not in self.sudo_attempts:
            self.sudo_attempts[user] = []
            self.failed_attempts[user] = 0

        self.sudo_attempts[user].append(event_time)

        if is_failure:
            self.failed_attempts[user] += 1

        # 6. Limpar tentativas antigas
        cutoff = event_time - timedelta(seconds=self.window_seconds)
        self.sudo_attempts[user] = [
            ts for ts in self.sudo_attempts[user] if ts >= cutoff
        ]

        # 7. Verificar threshold
        count = len(self.sudo_attempts[user])
        if count < self.threshold:
            return None

        # 8. Evitar duplicados
        if self._should_skip_alert(user, event_time):
            return None

        # 9. Criar alerta
        self.last_alert[user] = event_time

        # Severidade dinâmica
        severity = "high" if self.failed_attempts[user] > 0 else self.severity
        original_severity = self.severity
        self.severity = severity

        alert = self.create_alert(
            event=event,
            count=count,
            extra={
                "rule.threshold": self.threshold,
                "rule.window_seconds": self.window_seconds,
                "sudo.failed_attempts": self.failed_attempts[user],
                "alert.description": f"Usuário '{user}' fez {count} tentativas de sudo em {self.window_seconds}s ({self.failed_attempts[user]} falhas)",
                "alert.recommendation": "Verificar se o usuário deveria ter acesso sudo e o que estava tentando executar",
            }
        )

        # Restaurar severidade original
        self.severity = original_severity

        # Limpar estado
        self.sudo_attempts[user] = []
        self.failed_attempts[user] = 0

        return alert

    def _is_sudo_event(self, event: Dict) -> bool:
        """Verifica se é um evento de sudo."""
        tags = event.get("tags", [])
        if "parsed_sudo" in tags:
            return True

        message = event.get("message", "")
        return "sudo:" in message

    def _is_sudo_failure(self, event: Dict) -> bool:
        """Verifica se o sudo falhou."""
        message = event.get("message", "")
        return "NOT in sudoers" in message or "incorrect password" in message

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

    def _should_skip_alert(self, user: str, event_time: datetime) -> bool:
        """Evita alertas duplicados."""
        if user not in self.last_alert:
            return False

        last = self.last_alert[user]
        diff = (event_time - last).total_seconds()
        return diff < 30

