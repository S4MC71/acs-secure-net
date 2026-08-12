FROM node:20-slim

RUN apt-get update && apt-get install -y \
    cron sudo curl net-tools procps bash \
    --no-install-recommends && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package.json .
RUN npm install
COPY . .

RUN mkdir -p /app/data /app/uploads /app/files /var/www /opt /var/log /etc/acs

RUN chown -R node:node /app/data /app/uploads /app/files
RUN chmod +x /app/scripts/start.sh

EXPOSE 3000
CMD ["/app/scripts/start.sh"]
