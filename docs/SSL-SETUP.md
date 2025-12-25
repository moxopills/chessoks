# SSL/HTTPS 설정 가이드

이 문서는 Let's Encrypt를 사용하여 무료 SSL 인증서를 발급받고 HTTPS를 설정하는 방법을 설명합니다.

## 사전 준비사항

1. **도메인 이름**: 실제 도메인이 필요합니다 (예: example.com)
2. **DNS 설정**: 도메인의 A 레코드가 서버 IP를 가리켜야 합니다
3. **포트 개방**: 80, 443 포트가 열려있어야 합니다

```bash
# 포트 확인
sudo ufw status
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
```

## 환경 변수 설정

`.env` 파일에 도메인과 이메일을 설정하세요:

```bash
# .envs/.env.prod 또는 .env 파일
DOMAIN=your-domain.com
SSL_EMAIL=your-email@example.com
ALLOWED_HOSTS=your-domain.com,www.your-domain.com
```

## SSL 인증서 발급 방법

### 1단계: 초기 설정 (HTTP 모드)

먼저 HTTP 모드로 서버를 시작합니다:

```bash
# 환경 변수 설정
cp .envs/.env.prod .env
nano .env  # DOMAIN, SSL_EMAIL 수정

# Docker Compose로 서비스 시작
docker-compose up -d
```

### 2단계: Let's Encrypt 인증서 발급

SSL 인증서 발급 스크립트를 실행합니다:

```bash
# 실행 권한 부여
chmod +x scripts/init-letsencrypt.sh

# 인증서 발급
./scripts/init-letsencrypt.sh
```

스크립트가 수행하는 작업:
1. 더미 인증서 생성 (nginx 시작용)
2. nginx 컨테이너 시작
3. Let's Encrypt에 인증서 요청
4. 인증서 발급 완료

### 3단계: SSL 모드로 전환

인증서 발급 후 nginx를 SSL 모드로 전환:

```bash
# nginx 설정을 SSL 버전으로 변경
docker-compose exec nginx cp /etc/nginx/nginx-ssl.conf /etc/nginx/nginx.conf

# nginx 재시작
docker-compose restart nginx
```

또는 자동 전환 스크립트 사용:

```bash
./scripts/switch-to-ssl.sh
```

### 4단계: 확인

HTTPS로 접속되는지 확인:

```bash
# HTTP → HTTPS 리다이렉트 확인
curl -I http://your-domain.com

# HTTPS 접속 확인
curl -I https://your-domain.com

# SSL 인증서 정보 확인
openssl s_client -connect your-domain.com:443 -servername your-domain.com
```

## 인증서 자동 갱신

certbot 컨테이너가 **12시간마다** 자동으로 인증서 갱신을 확인합니다.

### 수동 갱신

필요시 수동으로 갱신할 수 있습니다:

```bash
# 인증서 갱신 (dry-run 테스트)
docker-compose run --rm certbot renew --dry-run

# 실제 갱신
docker-compose run --rm certbot renew

# nginx 재시작
docker-compose restart nginx
```

### 갱신 로그 확인

```bash
docker-compose logs certbot
```

## nginx 설정 파일

### HTTP 모드 (nginx.conf)
- 포트 80만 사용
- SSL 없이 동작
- 로컬 개발이나 초기 설정에 사용

### HTTPS 모드 (nginx-ssl.conf)
- 포트 80: HTTP → HTTPS 리다이렉트
- 포트 443: HTTPS로 서비스
- Let's Encrypt 인증서 사용
- 보안 헤더 추가
- HSTS 활성화

## 디렉토리 구조

```
DjangoProject/
├── nginx/
│   ├── Dockerfile          # nginx + certbot 이미지
│   ├── nginx.conf          # HTTP 모드 설정
│   └── nginx-ssl.conf      # HTTPS 모드 설정
├── scripts/
│   ├── init-letsencrypt.sh # SSL 인증서 발급 스크립트
│   └── switch-to-ssl.sh    # SSL 모드 전환 스크립트
└── volumes/
    └── certbot/
        ├── conf/           # 인증서 저장 위치
        └── www/            # ACME challenge 파일
```

## 트러블슈팅

### 인증서 발급 실패

**문제**: `Failed to verify domain ownership`

**해결방법**:
1. DNS 설정 확인: 도메인이 서버 IP를 가리키는지 확인
```bash
nslookup your-domain.com
dig your-domain.com
```

2. 방화벽 확인: 80번 포트가 열려있는지 확인
```bash
sudo netstat -tulpn | grep :80
sudo ufw status
```

3. nginx가 실행 중인지 확인
```bash
docker-compose ps nginx
docker-compose logs nginx
```

### 인증서 갱신 실패

**문제**: 인증서가 만료될 예정인데 갱신되지 않음

**해결방법**:
```bash
# certbot 로그 확인
docker-compose logs certbot

# 수동 갱신 시도
docker-compose run --rm certbot renew --force-renewal

# nginx 재시작
docker-compose restart nginx
```

### Mixed Content 경고

**문제**: HTTPS 사이트에서 HTTP 리소스 로드 시도

**해결방법**:
1. settings.py에서 HTTPS 강제:
```python
SECURE_SSL_REDIRECT = True  # HTTP → HTTPS 리다이렉트
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
```

2. 모든 리소스를 HTTPS로 변경

### 인증서 경로 문제

**문제**: nginx가 인증서를 찾지 못함

**해결방법**:
```bash
# 인증서 존재 확인
docker-compose exec nginx ls -la /etc/letsencrypt/live/$DOMAIN/

# 볼륨 마운트 확인
docker-compose config | grep certbot

# nginx 설정 확인
docker-compose exec nginx nginx -t
```

## 보안 강화

### 1. DH 파라미터 생성 (선택사항)

더 강력한 암호화를 위해:

```bash
docker-compose exec nginx openssl dhparam -out /etc/nginx/dhparam.pem 2048
```

nginx-ssl.conf에서 주석 해제:
```nginx
ssl_dhparam /etc/nginx/dhparam.pem;
```

### 2. OCSP Stapling 활성화

nginx-ssl.conf에 추가:
```nginx
ssl_stapling on;
ssl_stapling_verify on;
ssl_trusted_certificate /etc/letsencrypt/live/$DOMAIN/chain.pem;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;
```

### 3. SSL 테스트

SSL 설정 등급 확인:
- https://www.ssllabs.com/ssltest/

목표: A+ 등급

## 프로덕션 체크리스트

SSL 배포 전 확인사항:

- [ ] 도메인 DNS가 서버 IP를 가리킴
- [ ] 80, 443 포트가 개방됨
- [ ] `.env` 파일에 올바른 DOMAIN 설정
- [ ] SSL_EMAIL이 유효한 이메일 주소
- [ ] DEBUG=False 설정
- [ ] SECRET_KEY가 안전한 랜덤 값
- [ ] ALLOWED_HOSTS에 도메인 추가
- [ ] 인증서 발급 성공
- [ ] HTTPS 접속 테스트 완료
- [ ] HTTP → HTTPS 리다이렉트 동작 확인
- [ ] WebSocket (wss://) 테스트
- [ ] 인증서 자동 갱신 설정 확인

## 참고 자료

- Let's Encrypt 문서: https://letsencrypt.org/docs/
- Certbot 가이드: https://certbot.eff.org/
- nginx SSL 설정: https://nginx.org/en/docs/http/configuring_https_servers.html
- Mozilla SSL Configuration Generator: https://ssl-config.mozilla.org/
