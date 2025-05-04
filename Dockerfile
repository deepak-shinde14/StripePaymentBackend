FROM node:16-alpine

WORKDIR /app

COPY package*.json ./

RUN npm install

COPY . .

RUN npm install -g swagger-jsdoc swagger-ui-express

EXPOSE 5000

CMD ["node", "server.js"]