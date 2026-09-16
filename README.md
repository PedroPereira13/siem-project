#  SIEM Project

SIEM (Security Information and Event Management) construído do zero com Docker, Elastic Stack e Python.

##  Sobre

Projeto educacional para aprender a construir um SIEM profissional, do zero ao avançado, sem uso de máquinas virtuais.

##  Arquitetura

[Fontes de Logs] → [Logstash] → [Elasticsearch] → [Kibana]

##  Tecnologias

- Docker / Docker Compose
- Elasticsearch 8.11.0
- Kibana 8.11.0
- Logstash 8.11.0
- Python (em breve)

## Estrutura

siem-project/
├── config/
│   └── logstash/
│       └── pipeline/
│           └── siem.conf
├── scripts/
├── volumes/
├── docker-compose.yml
├── .gitignore
├── LICENSE
└── README.md

## Como Executar

### Passos

git clone https://github.com/SEU-USUARIO/siem-project.git
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

echo '{"message": "Failed password for admin from 192.168.1.100 port 22 ssh2"}' | nc localhost 5000

Depois acesse o Kibana → Discover → data view logstash-logs-*

## Progresso

- [x] Nível 1 — Fundamentos
- [x] Nível 2 — MVP com Docker
- [ ] Nível 3 — Motor de Correlação (em desenvolvimento)
- [ ] Nível 4 — Threat Intelligence
- [ ] Nível 5 — API e Dashboard
- [ ] Nível 6 — Incident Response
- [ ] Nível 7 — Hardening
- [ ] Nível 8 — Projeto Profissional
- [ ] Nível 9 — Portfólio

## Licença

MIT — veja LICENSE.

## Autor

Pedro Antonio Ribeiro Pereira
