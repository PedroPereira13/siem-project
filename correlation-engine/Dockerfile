# ============================================================
# Dockerfile - Motor de Correlação do SIEM
# ============================================================

# 1. Imagem base
FROM python:3.11-slim

# 2. Metadados
LABEL maintainer="Pedro"
LABEL description="SIEM Correlation Engine"

# 3. Diretório de trabalho dentro do container
WORKDIR /app

# 4. Variáveis de ambiente do Python
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# 5. Copiar requirements primeiro (cache de camadas)
COPY requirements.txt .

# 6. Instalar dependências
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# 7. Copiar o código da aplicação
COPY . .

# 8. Usuário não-root (segurança)
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app
USER appuser

# 9. Comando padrão
CMD ["python", "-u", "engine.py"]
