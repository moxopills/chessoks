# ♟️ ChessOk - 멀티플레이 체스 웹 애플리케이션

Django 6.0 기반 실시간 멀티플레이 체스 게임 플랫폼

🌐 **서비스 URL**: https://chessok.o-r.kr

## 📂 빠른 시작 명령어

### 로컬 실행
```bash
cp .envs/.env.local .env
docker compose -f docker-compose.local.yml up
# http://localhost:8000
```

### 개발 도구
```bash
./scripts/format.sh      # 코드 포맷팅
./scripts/test.sh        # 테스트 실행
```

## 📋 프로젝트 개요

Django 6.0 기반 실시간 체스 게임

- WebSocket을 통한 실시간 멀티플레이어 지원
- Django Channels + Daphne 사용
- PostgreSQL 16 데이터베이스
- Docker 기반 배포

## 🗂️ 프로젝트 구조

```
.
├── apps/                        # Django 앱 모음
│   ├── accounts/               # 인증, 프로필, 친구, 메시지
│   │   ├── models/             # User, SocialUser, Friend, Message
│   │   ├── serializers/        # DRF Serializers
│   │   ├── services/           # 비즈니스 로직
│   │   ├── views/              # API Views
│   │   └── utils/              # 이메일 전송 등 유틸리티
│   ├── adminpanel/             # 관리자 패널 (유저 관리, 제재, 통계)
│   ├── chess/                  # 체스 게임 앱
│   │   ├── consumers.py        # WebSocket Consumer
│   │   ├── routing.py          # WebSocket URL 라우팅
│   │   ├── models/             # Room, Game, Move
│   │   ├── services/           # RatingService, GameService
│   │   └── engine/             # 체스 엔진 로직
│   ├── notifications/          # 실시간 알림
│   └── core/                   # 공통 유틸리티 (GCP Storage 등)
├── config/                      # Django 프로젝트 설정
│   ├── settings.py             # 메인 설정 파일
│   ├── urls.py                 # URL 라우팅
│   ├── asgi.py                 # ASGI 설정 (WebSocket)
│   ├── celery.py               # Celery 설정
│   └── wsgi.py                 # WSGI 설정
├── templates/                   # HTML 템플릿
│   ├── accounts/               # 로그인, 회원가입, 프로필
│   ├── chess/                  # 게임, 로비, 기보
│   ├── components/             # 공통 컴포넌트
│   └── base.html               # 기본 레이아웃
├── static/                      # 정적 파일
│   ├── css/                    # 스타일시트
│   ├── js/                     # JavaScript
│   │   ├── core/               # API, 유틸리티
│   │   ├── components/         # 토스트, 알림
│   │   └── pages/              # 페이지별 로직
│   └── images/                 # 이미지, 아이콘
├── scripts/                     # 유틸리티 스크립트
│   ├── format.sh               # 코드 포맷팅 (black, isort, ruff)
│   ├── test.sh                 # 테스트 실행 (pytest)
│   ├── entrypoint.sh           # Docker 엔트리포인트
│   └── init-letsencrypt.sh     # SSL 인증서 발급
├── nginx/                       # Nginx 설정
├── .envs/                       # 환경 변수 파일
│   ├── .env.local              # 로컬 개발
│   ├── .env.dev                # 개발 서버
│   └── .env.prod               # 프로덕션
├── .github/                     # GitHub Actions
│   └── workflows/              # CI/CD 워크플로우
├── Dockerfile                   # Docker 이미지 설정
├── docker-compose.local.yml     # 로컬 개발용
├── docker-compose.dev.yml       # 개발 서버용
├── docker-compose.prod.yml      # 프로덕션용
└── pyproject.toml               # Python 패키지 설정
```

## 🛠️ 기술 스택

| 영역 | 기술 |
|------|------|
| **백엔드** | Django 6.0, Django REST Framework |
| **WebSocket** | Django Channels + Daphne |
| **데이터베이스** | PostgreSQL 16, Redis |
| **비동기 작업** | Celery + Redis |
| **인증** | Session + OAuth 2.0 (카카오, 네이버) |
| **스토리지** | Google Cloud Storage |
| **웹 서버** | Nginx + SSL (Let's Encrypt) |
| **컨테이너** | Docker Compose |
| **패키지 매니저** | uv |
| **코드 품질** | Ruff, Black, isort, MyPy, Pytest |

## ⚙️ 핵심 기능

- **실시간 게임**: WebSocket 기반 양방향 통신
- **체스 규칙**: 국제 체스 규칙 구현
- **이동 기록**: Move 모델로 게임 리플레이 가능
- **보드 저장**: 체스판 상태 DB 저장
- **동시성 제어**: select_for_update()로 race condition 방지
- **소셜 로그인**: OAuth 연동 (카카오, 네이버)
- **ELO 레이팅**: ELO 레이팅을 활용한 랜덤 매칭
- **랭킹 시스템**: ELO레이팅 시스템으로 랭킹 서비스
- **친구 시스템**: 친구 추가/삭제, 온라인 상태 확인
- **실시간 채팅**: 로비 채팅, 게임 내 채팅, 관전 채팅
- **관전 모드**: 진행 중인 게임 실시간 관전
- **기보 다시보기**: 완료된 게임 수순 재생
- **1:1 메시지**: 유저 간 다이렉트 메시지
- **알림 시스템**: 친구 요청, 메시지 실시간 알림
- **다크/라이트 모드**: 테마 토글 지원
- **관리자 패널**: 유저 관리, 제재(정지/뮤트), 통계

## 🎯 아키텍처 특징

- **Service Layer**: 비즈니스 로직과 모델 분리 (Clean Architecture)
- **Custom Managers**: 재사용 가능한 쿼리셋
- **Model Validation**: clean() 메서드 + DB Constraints
- **비동기 우선**: AsyncWebsocketConsumer 사용
- **환경 분리**: .env.local / .env.dev / .env.prod로 설정 분리
- **Atomic 트랜잭션**: @transaction.atomic으로 데이터 무결성 보장
- **정적 파일**: WhiteNoise로 처리
- **SSL 자동 갱신**: Let's Encrypt + Certbot (12시간마다)

## 📁 환경별 실행 명령어

### Local (로컬 개발)
```bash
cp .envs/.env.local .env
docker compose -f docker-compose.local.yml up
# http://localhost:8000
# PostgreSQL: localhost:5432
```

### Dev (개발 서버)
```bash
cp .envs/.env.dev .env
docker compose -f docker-compose.dev.yml up -d
# http://server-ip
```

### Prod (프로덕션)
```bash
cp .envs/.env.prod .env
docker compose -f docker-compose.prod.yml up -d
# https://chessok.o-r.kr
```

## 설치 및 실행

### Docker 사용 (권장)

1. Docker 및 Docker Compose 설치 확인:
```bash
docker --version
docker-compose --version
```

2. 환경 변수 설정:
```bash
cp .envs/.env.local .env
# .env 파일 수정
```

3. 컨테이너 빌드 및 실행:
```bash
# 로컬 개발
docker compose -f docker-compose.local.yml up

# 백그라운드 실행
docker compose -f docker-compose.local.yml up -d
```

4. 애플리케이션 접속:
- 웹: https://chessok.o-r.kr
- PostgreSQL: localhost:5432

### 로컬 개발 환경

1. uv 설치:
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

2. 의존성 설치:
```bash
uv sync
```

3. PostgreSQL 설정 (.env 파일에서 DB_HOST=localhost로 변경)

4. 마이그레이션:
```bash
uv run python manage.py migrate
```

5. 슈퍼유저 생성:
```bash
uv run python manage.py createsuperuser
```

6. 개발 서버 실행:
```bash
uv run daphne -b 0.0.0.0 -p 8000 config.asgi:application
```

## 개발 가이드

### 코드 품질 관리

```bash
# 코드 포맷팅 (isort + black + ruff)
./scripts/format.sh

# 테스트 및 커버리지
./scripts/test.sh
```

### 새로운 앱 생성

```bash
# apps 폴더 내에 새 앱 생성
uv run python manage.py startapp app_name apps/app_name

# apps.py에서 name과 label 설정
# name = "apps.app_name"
# label = "app_name"

# settings.py의 INSTALLED_APPS에 추가
# "apps.app_name",
```

### 마이그레이션

```bash
uv run python manage.py makemigrations
uv run python manage.py migrate
```

### Static 파일 수집

```bash
uv run python manage.py collectstatic
```

### WebSocket 개발

WebSocket Consumer는 `chess/consumers.py`에서 개발하고,
`chess/routing.py`에서 URL 패턴을 정의하세요.

## 배포 (GCP + Nginx)

1. GCP 인스턴스에 Docker 설치

2. 프로젝트 클론:
```bash
git clone https://github.com/moxopills/chessoks.git
cd chessoks
```

3. 프로덕션 환경 변수 설정:
```bash
cp .envs/.env.prod .env
nano .env  # SECRET_KEY, DB_PASSWORD, DOMAIN 수정 필수
```

4. Docker Compose로 실행:
```bash
docker compose -f docker-compose.prod.yml up -d
```

5. SSL 인증서 발급 (선택):
```bash
./scripts/init-letsencrypt.sh
```

6. 방화벽 설정 (포트 80, 443 오픈)

## 구현된 기능

### 데이터베이스 모델
- **User 모델**: 커스텀 유저 + ELO 레이팅 시스템
- **SocialUser 모델**: OAuth 연동 (카카오, 네이버)
- **Room 모델**: 게임 방 생성 + 관전자 시스템
- **Game 모델**: FEN 표기법 보드 상태 저장
- **Move 모델**: SAN/UCI 표기법 착수 기록

### Service Layer
- **RatingService**: ELO 레이팅 계산
- **GameService**: 게임 로직 관리
- **RoomService**: 방 입장/시작 관리

## 개발 로드맵

- [x] 체스 게임 로직 구현
- [x] 실시간 매칭 시스템
- [x] 게임 기록 저장 및 조회
- [x] 랭킹 시스템
- [x] 친구 시스템
- [x] 채팅 기능
- [x] 소셜 로그인 (카카오, 네이버)
- [x] 관리자 패널

## GitHub Actions

자동 실행 워크플로우:
- ✅ **Lint**: Ruff, Black, isort, MyPy
- ✅ **Test**: Pytest + Coverage
- ✅ **Security**: Django security check
- ✅ **Build**: Docker 이미지 빌드
- 🚀 **Deploy**: EC2 자동 배포 (main 브랜치)

## 개발자

**Minsoo** - Django 6.0 기반 실시간 멀티플레이 체스 게임 플랫폼
