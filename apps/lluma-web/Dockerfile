# Minimal static server for the Lluma site — usable on a DigitalOcean Droplet,
# App Platform (Dockerfile deploy), or any container host.
#   docker build -t lluma-web apps/lluma-web
#   docker run -p 8080:80 lluma-web
FROM nginx:1.27-alpine
COPY index.html /usr/share/nginx/html/index.html
# Long cache for assets is moot (single file); keep it simple.
EXPOSE 80
