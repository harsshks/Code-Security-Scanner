FROM node:20-alpine
# git is required by the worker to clone repositories
RUN apk add --no-cache git
WORKDIR /app
COPY package.json .
RUN npm install --omit=dev
COPY . .
EXPOSE 4000
# Default cmd — overridden per-service in docker-compose.yml
CMD ["node", "server.js"]
