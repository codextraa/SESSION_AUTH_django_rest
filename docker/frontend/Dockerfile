FROM node:22-alpine

WORKDIR /app
COPY ./frontend/package.json ./frontend/package-lock.json* ./

RUN npm install
RUN apk add --no-cache bash curl && \
    curl -1sLf 'https://dl.cloudsmith.io/public/infisical/infisical-cli/setup.alpine.sh' | distro=alpine version=3.20 bash && \
    apk add --no-cache infisical

EXPOSE 3000
