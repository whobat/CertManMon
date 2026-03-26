FROM node:20-alpine

WORKDIR /app

COPY package.json ./
RUN npm install --production

COPY server.js ./
COPY public ./public

VOLUME ["/data"]

ENV PORT=3000
ENV DB_PATH=/data/certs.db

EXPOSE 3000

CMD ["node", "server.js"]
