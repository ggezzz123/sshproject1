# node:sqlite needs Node >=22.13 without a flag; 24 matches package.json's engines field.
FROM node:24-slim

# Tailscale binaries, used to reach the Oracle database running on a private PC.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates iptables iproute2 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=docker.io/tailscale/tailscale:stable /usr/local/bin/tailscaled /usr/local/bin/tailscaled
COPY --from=docker.io/tailscale/tailscale:stable /usr/local/bin/tailscale /usr/local/bin/tailscale
RUN mkdir -p /var/run/tailscale /var/cache/tailscale

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY . .

ENV NODE_ENV=production
EXPOSE 8080

# sed strips CRLF in case the script was saved on Windows
RUN sed -i 's/\r$//' start.sh && chmod +x start.sh

CMD ["./start.sh"]
