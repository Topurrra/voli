# voli website (docs-site/) as a static site, served by nginx.
# For self-hosting on Hetzner behind your own reverse proxy / firewall.
#
#   docker compose up -d --build
#
# The mockups in redesign/ are gitignored and not part of docs-site/, so they
# are never copied into the image.
FROM nginx:1.27-alpine

COPY docs-site/ /usr/share/nginx/html/
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
