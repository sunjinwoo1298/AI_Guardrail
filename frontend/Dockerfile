FROM node:20-alpine AS build
WORKDIR /web
COPY package*.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

# alpine-slim drops the optional nginx modules (njs, perl, geoip, ...) we don't use.
FROM nginx:1.27-alpine-slim
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /web/dist /usr/share/nginx/html
EXPOSE 80
