FROM node:22-alpine AS build
ENV npm_config_fetch_retries=5 \
    npm_config_fetch_retry_mintimeout=10000 \
    npm_config_fetch_retry_maxtimeout=60000 \
    npm_config_fetch_timeout=180000
WORKDIR /app
COPY package.json tsconfig.json index.html ./
COPY src ./src
RUN npm install --no-audit --no-fund && npm run build
FROM nginx:alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
