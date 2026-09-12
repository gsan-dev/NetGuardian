# Build context: frontend/
FROM node:20-alpine AS build

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

COPY . .

# La URL del backend queda "horneada" en el bundle en tiempo de build
# (Vite resuelve import.meta.env.* de forma estática). Para un homelab
# esto es suficiente; si el backend cambia de host/puerto, reconstruye
# la imagen con --build-arg VITE_API_BASE_URL=...
ARG VITE_API_BASE_URL=http://localhost:8000
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL

RUN npm run build

FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
