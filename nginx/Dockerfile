FROM nginx:1.25-alpine

# Remove default config
RUN rm -rf /usr/share/nginx/html/* /etc/nginx/conf.d/default.conf

# Copy our hardened WAF config
COPY nginx/waf.conf /etc/nginx/conf.d/default.conf
COPY nginx/ssl /etc/nginx/ssl

EXPOSE 80 443
