FROM nginx:alpine

# SSL 인증서 발급을 위한 certbot 설치
RUN apk add --no-cache \
    certbot \
    certbot-nginx \
    openssl

# 기본 nginx 설정 제거
RUN rm /etc/nginx/nginx.conf

# nginx 설정 파일 복사
COPY nginx.conf /etc/nginx/nginx.conf
COPY nginx-ssl.conf /etc/nginx/nginx-ssl.conf

# SSL 인증서 디렉토리 생성
RUN mkdir -p /etc/letsencrypt/live /var/www/certbot

# 보안 강화를 위한 dhparam 생성 (선택사항, 시간 소요)
# RUN openssl dhparam -out /etc/nginx/dhparam.pem 2048

# 포트 노출
EXPOSE 80 443

# 헬스 체크
HEALTHCHECK --interval=30s --timeout=3s \
    CMD wget --quiet --tries=1 --spider http://localhost/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
