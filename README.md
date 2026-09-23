cd ~/Projetos/siem-project

# ============================================================
# 1. Abrir o README e colar a versão final (sem emojis + Nível 3)
# ============================================================
cat > README.md << 'EOF'
# SIEM Project

SIEM (Security Information and Event Management) construído do zero com Docker, Elastic Stack e Python.

## Sobre

Projeto educacional para aprender a construir um SIEM profissional, do zero ao avançado, sem uso de máquinas virtuais.

O objetivo é entender como um SIEM funciona internamente, desde a coleta de logs até a geração de alertas, e ser capaz de defender tecnicamente cada decisão arquitetural.

## Arquitetura

[Fontes de Logs] --> [Logstash] --> [Elasticsearch] --> [Kibana]
                                          |
                                          v
                              [Correlation Engine (Python)]
                                          |
                                          v
                                  [Alertas: siem-alerts]

## Tecnologias

| Tecnologia | Versão | Função |
|------------|--------|--------|
| Docker | 24+ | Containerização |
| Docker Compose | 2.x | Orquestração |
| Elasticsearch | 8.11.0 | Armazenamento e busca |
| Kibana | 8.11.0 | Visualização |
| Logstash | 8.11.0 | Coleta e parsing |
| Python | 3.11 | Motor de correlação |

## Estrutura

siem-project/
├── config/
│   └── logstash/
│       └── pipeline/
│           └── siem.conf
├── correlation-engine/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── config.py
│   ├── engine.py
│   └── rules/
│       ├── __init__.py
│       ├── base.py
│       ├── ssh_brute_force.py
│       ├── ssh_login_after_failures.py
│       └── sudo_activity.py
├── docs/
│   └── screenshots/
├── scripts/
├── volumes/
├── docker-compose.yml
├── .gitignore
├── LICENSE
└── README.md

## Como Executar

### Pre-requisitos

- Docker + Docker Compose
- 4GB RAM disponível
- 10GB de espaço em disco

### Passos

git clone https://github.com/PedroPereira13/siem-project.git
cd siem-project
mkdir -p volumes/elasticsearch-data
sudo chown -R 1000:1000 volumes/elasticsearch-data
docker-compose up -d
docker ps

### Acessar

- Kibana: http://localhost:5601
- Elasticsearch: http://localhost:9200
- Logstash (TCP): localhost:5000

## Teste

### Enviar log de falha SSH

echo '{"message": "Failed password for admin from 192.168.1.100 port 22 ssh2"}' | nc localhost 5000

### Simular brute force (5 falhas em lote)

for i in {1..5}; do
  echo '{"message": "Failed password for admin from 10.99.99.99 port 22 ssh2"}'
done | nc -q 1 localhost 5000

Aguarde 15 segundos e verifique:

docker logs --tail 20 siem-correlation-engine

## Regras de Deteccao

| Regra | Condição | Severidade |
|-------|----------|------------|
| SSH Brute Force | 5+ falhas SSH do mesmo IP em 60s | high |
| SSH Login After Failures | Login bem-sucedido após 3+ falhas | critical |
| Sudo Activity | 3+ tentativas de sudo em 30s | medium/high |

## Nota sobre o Parsing de Sudo

O pipeline do Logstash (config/logstash/pipeline/siem.conf) contém dois padrões Grok para sudo:

1. Sudo com sucesso:
   sudo: %{DATA:user.name} : TTY=pts/%{NUMBER:tty} ; ...

2. Sudo com falha:
   sudo: %{DATA:user.name} : user NOT in sudoers ; TTY=pts/%{NUMBER:tty} ; ...

Isso garante que tanto tentativas bem-sucedidas quanto falhas sejam detectadas pela regra Sudo Activity.

## Screenshots

### Alertas no Kibana
![Discover Alerts](docs/screenshots/discover-alerts.png)

### Logs do Motor
![Engine Logs](docs/screenshots/engine-logs.png)

## Progresso

- [x] Nível 1 - Fundamentos
- [x] Nível 2 - MVP com Docker
  - [x] Elasticsearch
  - [x] Kibana
  - [x] Logstash
  - [x] Pipeline com Grok
- [x] Nível 3 - Motor de Correlação
  - [x] 3 regras de detecção
  - [x] Geração de alertas
  - [x] Persistência em siem-alerts
- [ ] Nível 4 - Threat Intelligence (próximo)
- [ ] Nível 5 - API e Dashboard
- [ ] Nível 6 - Incident Response
- [ ] Nível 7 - Hardening
- [ ] Nível 8 - Projeto Profissional
- [ ] Nível 9 - Portfólio

## Licença

MIT - veja LICENSE.

## Autor

Pedro Antonio Ribeiro Pereira
EOF

# ============================================================
# 2. Verificar se não sobrou conflito
# ============================================================
echo "--- Verificando conflitos ---"
grep -n "<<<<<<<\|=======\|>>>>>>>" README.md && echo "AINDA TEM CONFLITO!" || echo "OK - sem conflitos"

# ============================================================
# 3. Marcar como resolvido e continuar o rebase
# ============================================================
git add README.md
git rebase --continue

# ============================================================
# 4. Push
# ============================================================
git push
