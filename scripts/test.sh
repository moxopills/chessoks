#!/bin/bash

# 테스트 및 커버리지 실행 스크립트

set -e

# Docker 환경변수 충돌 방지
unset VIRTUAL_ENV

# 프로젝트 루트로 이동
cd "$(dirname "$0")/.."

echo "=== 테스트 및 커버리지 검사 시작 ==="
echo ""

# pytest 실행 (pyproject.toml 설정 사용)
echo "🧪 pytest 실행 중..."
uv run pytest

echo ""
echo "=== ✅ 테스트 완료 ==="
