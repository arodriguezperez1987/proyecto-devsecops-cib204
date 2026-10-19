
FROM node:22-trixie-slim

WORKDIR /app

COPY package.json package-lock.json ./

RUN npm ci --omit=dev

COPY --chown=node:node . .

USER node

EXPOSE 3000

CMD ["node", "servidor.js"]
