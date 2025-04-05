FROM python:3.12-slim

# Deps stage: Install Python dependencies
FROM python:3.12-alpine AS deps
WORKDIR /app
COPY requirements.txt ./
RUN apk add --no-cache python3-dev musl-dev linux-headers gcc \
    && pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && apk del python3-dev musl-dev linux-headers gcc

# Builder stage: Prepare app code
FROM python:3.12-alpine AS builder
WORKDIR /app
COPY --from=deps /usr/local/lib/python3.12/site-packages/ /usr/local/lib/python3.12/site-packages/
COPY --from=deps /usr/local/bin/ /usr/local/bin/
COPY . .

# Runner stage: Final production image
FROM python:3.12-alpine AS runner
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install postgresql-client and Infisical
RUN apk add --no-cache curl postgresql-client \
    && curl -1sLf 'https://dl.cloudsmith.io/public/infisical/infisical-cli/setup.alpine.sh' | sh \
    && apk add --no-cache infisical \
    && apk del curl \
    && rm -rf /var/cache/apk/*

# Copy Python dependencies and app code
COPY --from=builder /usr/local/lib/python3.12/site-packages/ /usr/local/lib/python3.12/site-packages/
COPY --from=builder /usr/local/bin/ /usr/local/bin/
COPY ./backend ./backend
COPY ./auth_api ./auth_api
COPY ./core_db ./core_db
COPY ./static ./static
COPY ./manage.py ./manage.py
COPY ./run.sh ./run.sh
RUN chmod +x ./run.sh \
    && sed -i 's/\r$//' ./run.sh

EXPOSE 8000
