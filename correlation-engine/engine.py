"""
Motor de Correlação do SIEM

Responsável por:
1. Consultar logs no Elasticsearch
2. Aplicar regras de detecção
3. Gerar alertas
4. Salvar alertas no Elasticsearch
"""

import time
import logging
import sys
from datetime import datetime, timedelta
from typing import List, Dict, Optional

from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError, NotFoundError

from config import (
    ELASTICSEARCH_HOST,
    ELASTICSEARCH_INDEX_LOGS,
    ELASTICSEARCH_INDEX_ALERTS,
    POLL_INTERVAL,
    LOOKBACK_WINDOW,
    LOG_LEVEL,
)

# Importar regras
from rules.ssh_brute_force import SSHBruteForceRule
from rules.ssh_login_after_failures import SSHLoginAfterFailuresRule
from rules.sudo_activity import SudoActivityRule


# ============================================================
# Configuração de Logging
# ============================================================
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("correlation-engine")


# ============================================================
# Classe Principal do Motor
# ============================================================
class CorrelationEngine:
    """
    Motor de correlação que avalia eventos contra regras de detecção.
    """

    def __init__(self):
        """Inicializa o motor."""
        logger.info("=" * 60)
        logger.info("Iniciando Correlation Engine")
        logger.info("=" * 60)

        # Conectar ao Elasticsearch
        self.es = self._connect_elasticsearch()

        # Carregar regras
        self.rules = self._load_rules()
        logger.info(f"✓ {len(self.rules)} regras carregadas:")
        for rule in self.rules:
            logger.info(f"  - {rule.name} (severidade: {rule.severity})")

        # Estatísticas
        self.stats = {
            "events_processed": 0,
            "alerts_generated": 0,
            "cycles": 0,
            "started_at": datetime.utcnow(),
        }

        # Controle de tempo
        self.last_check = datetime.utcnow() - timedelta(seconds=LOOKBACK_WINDOW)

        logger.info(f"✓ Motor inicializado")
        logger.info(f"  - Poll interval: {POLL_INTERVAL}s")
        logger.info(f"  - Lookback window: {LOOKBACK_WINDOW}s")
        logger.info("=" * 60)

    # ========================================================
    # Inicialização
    # ========================================================
    def _connect_elasticsearch(self) -> Elasticsearch:
        """Conecta ao Elasticsearch com retry."""
        max_retries = 10
        for attempt in range(1, max_retries + 1):
            try:
                es = Elasticsearch(ELASTICSEARCH_HOST, request_timeout=10)
                if es.ping():
                    logger.info(f"✓ Conectado ao Elasticsearch: {ELASTICSEARCH_HOST}")
                    return es
            except Exception as e:
                logger.warning(f"Tentativa {attempt}/{max_retries} falhou: {e}")

            if attempt < max_retries:
                logger.info(f"Aguardando 5s antes de tentar novamente...")
                time.sleep(5)

        logger.error(" Não foi possível conectar ao Elasticsearch")
        sys.exit(1)

    def _load_rules(self) -> List:
        """Carrega todas as regras de detecção."""
        return [
            SSHBruteForceRule(),
            SSHLoginAfterFailuresRule(),
            SudoActivityRule(),
        ]

    # ========================================================
    # Busca de Eventos
    # ========================================================
    def _fetch_events(self) -> List[Dict]:
        """
        Busca eventos novos no Elasticsearch.

        Retorna eventos ocorridos desde o último check.
        """
        try:
            query = {
                "query": {
                    "range": {
                        "@timestamp": {
                            "gte": self.last_check.isoformat(),
                            "lte": datetime.utcnow().isoformat(),
                        }
                    }
                },
                "sort": [{"@timestamp": "asc"}],
                "size": 1000,
            }

            result = self.es.search(
                index=ELASTICSEARCH_INDEX_LOGS,
                body=query,
            )

            hits = result.get("hits", {}).get("hits", [])
            events = [hit["_source"] for hit in hits]

            return events

        except NotFoundError:
            # Índice ainda não existe
            return []
        except ConnectionError as e:
            logger.error(f"Erro de conexão ao buscar eventos: {e}")
            return []
        except Exception as e:
            logger.error(f"Erro ao buscar eventos: {e}")
            return []

    # ========================================================
    # Avaliação de Eventos
    # ========================================================
    def _evaluate_event(self, event: Dict):
        """Avalia um evento contra todas as regras."""
        for rule in self.rules:
            try:
                alert = rule.evaluate(event)
                if alert:
                    self._handle_alert(alert)
            except Exception as e:
                logger.error(
                    f"Erro ao avaliar evento com regra '{rule.name}': {e}"
                )

    # ========================================================
    # Tratamento de Alertas
    # ========================================================
    def _handle_alert(self, alert: Dict):
        """Salva um alerta no Elasticsearch."""
        try:
            # Adicionar metadados
            alert["@timestamp"] = alert.get(
                "alert.timestamp", datetime.utcnow().isoformat() + "Z"
            )
            alert["engine.version"] = "1.0.0"

            # Salvar no índice de alertas
            self.es.index(
                index=ELASTICSEARCH_INDEX_ALERTS,
                document=alert,
            )

            self.stats["alerts_generated"] += 1

            logger.warning(
                f" ALERTA: {alert.get('rule.name')} "
                f"[{alert.get('rule.severity')}] "
                f"- {alert.get('alert.description', '')}"
            )

        except Exception as e:
            logger.error(f"Erro ao salvar alerta: {e}")

    # ========================================================
    # Loop Principal
    # ========================================================
    def run(self):
        """Loop principal do motor."""
        logger.info("▶ Motor iniciado. Pressione Ctrl+C para parar.")

        try:
            while True:
                self._cycle()
                time.sleep(POLL_INTERVAL)

        except KeyboardInterrupt:
            logger.info("")
            logger.info(" Recebido Ctrl+C. Encerrando...")
            self._print_stats()
            logger.info(" Motor encerrado.")

    def _cycle(self):
        """Executa um ciclo completo de detecção."""
        self.stats["cycles"] += 1

        # Buscar eventos
        events = self._fetch_events()

        if not events:
            logger.debug("Nenhum evento novo encontrado.")
            self.last_check = datetime.utcnow()
            return

        logger.info(f" {len(events)} evento(s) para processar")

        # Avaliar cada evento
        for event in events:
            self._evaluate_event(event)
            self.stats["events_processed"] += 1

        # Atualizar timestamp do último check
        self.last_check = datetime.utcnow()

    # ========================================================
    # Estatísticas
    # ========================================================
    def _print_stats(self):
        """Imprime estatísticas do motor."""
        uptime = datetime.utcnow() - self.stats["started_at"]
        logger.info("")
        logger.info("=" * 60)
        logger.info(" Estatísticas")
        logger.info("=" * 60)
        logger.info(f"  Uptime: {uptime}")
        logger.info(f"  Ciclos: {self.stats['cycles']}")
        logger.info(f"  Eventos processados: {self.stats['events_processed']}")
        logger.info(f"  Alertas gerados: {self.stats['alerts_generated']}")
        logger.info("=" * 60)


# ============================================================
# Entry Point
# ============================================================
def main():
    """Ponto de entrada do motor."""
    engine = CorrelationEngine()
    engine.run()


if __name__ == "__main__":
    main()
