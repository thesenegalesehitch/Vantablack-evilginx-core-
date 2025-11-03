# --- STAGE 1: Compilation des Moteurs Go ---
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY engines/ /app/engines/
RUN cd /app/engines && go build -o /app/evilginx -mod=vendor main.go
RUN cd /app/engines && go build -o /app/gophish -mod=vendor gophish.go

# --- STAGE 2: Environnement d'Exécution Python (The Nervous System) ---
FROM python:3.14-rc-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    sudo \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /vanta

# Copie des binaires
COPY --from=builder /app/evilginx /vanta/bin/evilginx
COPY --from=builder /app/gophish /vanta/bin/gophish

# Installation des dépendances Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt fastapi uvicorn requests psutil pyyaml rich

COPY . .

# Droits et points d'exposition
RUN chmod +x /vanta/bin/evilginx /vanta/bin/gophish /vanta/vanta.py
EXPOSE 80 443 3333 8000

# Commande de lancement universelle
CMD ["python", "vanta.py", "--stealth-level", "3"]
