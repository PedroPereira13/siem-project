"""
Configurações do Motor de Correlação
"""

# Conexão com Elasticsearch
ELASTICSEARCH_HOST = "http://elasticsearch:9200"
ELASTICSEARCH_INDEX_LOGS = "logstash-logs-*"
ELASTICSEARCH_INDEX_ALERTS = "siem-alerts"

# Configuração do motor
POLL_INTERVAL = 10  # segundos entre cada consulta
LOOKBACK_WINDOW = 10  # segundos para trás que buscamos eventos

# Configuração de logging
LOG_LEVEL = "INFO"
