FROM --platform=linux/amd64 node:24.22.1-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends util-linux ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /mago-ski
COPY package.json package-lock.json tsconfig.json tsconfig.build.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY tests/live/container/package.json tests/live/container/package-lock.json tests/live/container/
RUN npm ci --prefix tests/live/container --ignore-scripts --no-audit --no-fund
COPY . .
RUN find /mago-ski -perm /022 -exec chmod go-w {} + && npm run build

ENV CODEX_BIN=/mago-ski/tests/live/container/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex
ENV CLAUDE_BIN=/mago-ski/tests/live/container/node_modules/@anthropic-ai/claude-code-linux-x64/claude
ENTRYPOINT ["node", "scripts/live-scenarios.mjs"]
