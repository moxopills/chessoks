#!/bin/bash

# Let's Encrypt SSL 인증서 초기 발급 스크립트
# 사용법: ./scripts/init-letsencrypt.sh

set -e

# 환경 변수 로드
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# 도메인 확인
if [ -z "$DOMAIN" ]; then
    echo "Error: DOMAIN 환경 변수가 설정되지 않았습니다."
    echo ".env 파일에 DOMAIN을 설정해주세요."
    exit 1
fi

# 이메일 확인
if [ -z "$SSL_EMAIL" ]; then
    echo "Error: SSL_EMAIL 환경 변수가 설정되지 않았습니다."
    echo ".env 파일에 SSL_EMAIL을 설정해주세요."
    exit 1
fi

echo "=== Let's Encrypt SSL 인증서 발급 시작 ==="
echo "도메인: $DOMAIN"
echo "이메일: $SSL_EMAIL"
echo ""

# 기존 인증서 확인
if [ -d "volumes/certbot/conf/live/$DOMAIN" ]; then
    read -p "기존 인증서가 존재합니다. 삭제하고 새로 발급하시겠습니까? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "인증서 발급을 취소합니다."
        exit 1
    fi
    echo "기존 인증서를 삭제합니다..."
    rm -rf volumes/certbot/conf/live/$DOMAIN
    rm -rf volumes/certbot/conf/archive/$DOMAIN
    rm -rf volumes/certbot/conf/renewal/$DOMAIN.conf
fi

# 더미 인증서 생성 (nginx 시작을 위해)
echo "더미 인증서 생성 중..."
mkdir -p volumes/certbot/conf/live/$DOMAIN
docker-compose run --rm --entrypoint "\
    openssl req -x509 -nodes -newkey rsa:2048 -days 1 \
    -keyout /etc/letsencrypt/live/$DOMAIN/privkey.pem \
    -out /etc/letsencrypt/live/$DOMAIN/fullchain.pem \
    -subj '/CN=localhost'" certbot

echo "nginx 시작 중..."
docker-compose up -d nginx

echo "더미 인증서 삭제 중..."
docker-compose run --rm --entrypoint "\
    rm -rf /etc/letsencrypt/live/$DOMAIN && \
    rm -rf /etc/letsencrypt/archive/$DOMAIN && \
    rm -rf /etc/letsencrypt/renewal/$DOMAIN.conf" certbot

# Let's Encrypt 인증서 발급
echo "Let's Encrypt 인증서 발급 중..."
docker-compose run --rm --entrypoint "\
    certbot certonly --webroot -w /var/www/certbot \
    --email $SSL_EMAIL \
    --agree-tos \
    --no-eff-email \
    -d $DOMAIN \
    -d www.$DOMAIN" certbot

echo ""
echo "=== SSL 인증서 발급 완료 ==="
echo ""
echo "다음 단계:"
echo "1. nginx 설정을 SSL 모드로 변경:"
echo "   docker-compose down"
echo "   # nginx/nginx.conf를 nginx-ssl.conf로 교체"
echo "   docker-compose up -d"
echo ""
echo "2. 인증서는 자동으로 12시간마다 갱신됩니다."
echo ""
