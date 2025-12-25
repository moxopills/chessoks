# 배포 가이드

이 문서는 GitHub Actions를 통한 자동 배포 설정 방법을 설명합니다.

## GitHub Secrets 설정

배포 워크플로우가 작동하려면 다음 GitHub Secrets를 설정해야 합니다:

### AWS 설정 (선택사항)
- `AWS_ACCESS_KEY_ID`: AWS 액세스 키 ID
- `AWS_SECRET_ACCESS_KEY`: AWS 시크릿 액세스 키
- `AWS_REGION`: AWS 리전 (예: ap-northeast-2)

### EC2 SSH 설정
- `EC2_HOST`: EC2 인스턴스의 공용 IP 또는 도메인
- `EC2_USERNAME`: SSH 사용자명 (예: ubuntu, ec2-user)
- `EC2_SSH_KEY`: EC2 인스턴스 접속용 SSH 프라이빗 키 (PEM 파일 내용)
- `EC2_SSH_PORT`: SSH 포트 (기본값: 22)

### 애플리케이션 설정
- `PROJECT_PATH`: EC2 인스턴스 내 프로젝트 경로 (예: /home/ubuntu/DjangoProject)
- `APP_URL`: 애플리케이션 URL (헬스 체크용, 예: https://your-domain.com)

## GitHub Secrets 등록 방법

1. GitHub 저장소 페이지로 이동
2. `Settings` 탭 클릭
3. 좌측 사이드바에서 `Secrets and variables` > `Actions` 클릭
4. `New repository secret` 버튼 클릭
5. Secret 이름과 값을 입력하고 저장

## EC2 인스턴스 초기 설정

배포하기 전에 EC2 인스턴스에 다음을 설정해야 합니다:

### 1. Docker 설치

```bash
# Docker 설치
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Docker Compose 설치
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# 사용자를 docker 그룹에 추가
sudo usermod -aG docker $USER

# 로그아웃 후 다시 로그인
```

### 2. 프로젝트 클론

```bash
cd ~
git clone <your-repository-url> chessok
cd chessok
```

### 3. 환경 변수 설정

```bash
# 프로덕션 환경 변수 복사
cp .envs/.env.prod .env

# 환경 변수 편집
nano .env
```

필수 환경 변수:
- `SECRET_KEY`: 강력한 랜덤 키로 변경
- `DB_PASSWORD`: 안전한 비밀번호로 변경
- `ALLOWED_HOSTS`: 실제 도메인으로 변경
- `DEBUG`: False로 설정

### 4. 방화벽 설정

```bash
# 필요한 포트 오픈 (AWS Security Group에서도 설정 필요)
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 22/tcp
sudo ufw enable
```

### 5. 초기 배포

```bash
# Docker Compose로 서비스 시작
docker-compose up -d --build

# 마이그레이션 실행
docker-compose exec web uv run python manage.py migrate

# 슈퍼유저 생성
docker-compose exec web uv run python manage.py createsuperuser

# Static 파일 수집
docker-compose exec web uv run python manage.py collectstatic --noinput
```

## 워크플로우 설명

### 1. Build Workflow (build.yml)

**트리거**: Push 또는 PR이 main/develop 브랜치에 발생할 때

**동작**:
- Docker 이미지 빌드
- 마이그레이션 체크
- 테스트 실행

### 2. Check Workflow (check.yml)

**트리거**: Push 또는 PR이 main/develop 브랜치에 발생할 때

**동작**:
- Python 문법 체크
- 코드 품질 검사
- 보안 검사
- 마이그레이션 누락 체크

### 3. Deploy Workflow (deploy.yml)

**트리거**:
- main 브랜치에 Push될 때 자동 배포
- 수동으로 워크플로우 실행 (Actions 탭에서)

**동작**:
1. EC2에 SSH 접속
2. 최신 코드 Pull
3. Docker Compose로 재배포
4. 마이그레이션 실행
5. Static 파일 수집
6. 헬스 체크
7. 실패 시 자동 롤백

## 수동 배포 트리거

1. GitHub 저장소의 `Actions` 탭으로 이동
2. 좌측에서 `Deploy to EC2` 워크플로우 선택
3. `Run workflow` 버튼 클릭
4. 배포 환경 선택 (production/development)
5. `Run workflow` 확인

## 배포 확인

배포 후 다음을 확인하세요:

```bash
# 컨테이너 상태 확인
docker-compose ps

# 로그 확인
docker-compose logs -f web

# 데이터베이스 연결 확인
docker-compose exec web uv run python manage.py dbshell

# 웹사이트 접속
curl https://your-domain.com
```

## 트러블슈팅

### SSH 연결 실패
- EC2 Security Group에서 SSH 포트(22)가 열려있는지 확인
- SSH 키가 올바른지 확인
- EC2_HOST가 정확한지 확인

### Docker 권한 오류
```bash
sudo usermod -aG docker $USER
# 로그아웃 후 다시 로그인
```

### 포트 충돌
```bash
# 사용 중인 포트 확인
sudo lsof -i :80
sudo lsof -i :8000

# 프로세스 종료
sudo kill -9 <PID>
```

### 데이터베이스 연결 실패
- .env 파일의 DB_HOST가 'db'로 설정되어 있는지 확인
- PostgreSQL 컨테이너가 실행 중인지 확인: `docker-compose ps`

## 롤백 방법

자동 롤백이 실패한 경우 수동으로 롤백:

```bash
# EC2에 SSH 접속
ssh -i your-key.pem ubuntu@your-ec2-ip

# 프로젝트 디렉토리로 이동
cd chessok

# 이전 커밋으로 되돌리기
git log  # 커밋 해시 확인
git reset --hard <previous-commit-hash>

# 재배포
docker-compose down
docker-compose up -d --build
```

## 모니터링

배포 후 모니터링 권장사항:

```bash
# 실시간 로그 모니터링
docker-compose logs -f

# 리소스 사용량 확인
docker stats

# 디스크 사용량 확인
df -h

# Docker 리소스 정리 (주기적으로)
docker system prune -a
```
