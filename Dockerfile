FROM node:18
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN mkdir uploads
EXPOSE 5000
CMD ["node", "server.js"]
