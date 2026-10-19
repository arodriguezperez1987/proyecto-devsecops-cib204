# Etapa 1: instalación de dependencias
FROM node:22-trixie-slim AS builder

WORKDIR /app

COPY package.json package-lock.json ./

RUN npm ci --omit=dev

# Etapa 2: imagen de ejecución reducida
FROM gcr.io/distroless/nodejs22-debian13:nonroot

WORKDIR /app

COPY --from=builder --chown=nonroot:nonroot /app/node_modules ./node_modules

COPY --chown=nonroot:nonroot . .

EXPOSE 3000

CMD ["servidor.js"]