# Deps stage: Install Node dependencies
FROM node:20-alpine AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev

# Builder stage: Prepare app code
FROM node:20-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build --omit=dev

# Production Stage: Final production image
FROM node:20-alpine AS runner
WORKDIR /app

# Install Infisical
RUN apk add --no-cache curl \
    && curl -1sLf 'https://dl.cloudsmith.io/public/infisical/infisical-cli/setup.alpine.sh' | sh \
    && apk add --no-cache infisical \
    && apk del curl  \
    && rm -rf /var/cache/apk/*

# Install minimal production dependencies with pnpm
COPY --from=builder /app/package.json ./package.json
RUN npm install -g pnpm \
    && pnpm install --prod --no-optional \
    && pnpm store prune \
    && find /app/node_modules -name "*.md" -delete \
    && find /app/node_modules -name "*.ts" -delete \
    && find /app/node_modules -name "*.map" -delete \
    && npm uninstall -g pnpm \
    && rm -rf /root/.npm /root/.pnpm-store

# Copy essential build output
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/next.config.mjs ./next.config.mjs
COPY ./run.sh ./run.sh
RUN chmod +x ./run.sh \
    && sed -i 's/\r$//' ./run.sh

EXPOSE 3000
