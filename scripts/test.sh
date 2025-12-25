#!/bin/bash

# 테스트 및 커버리지 실행 스크립트

set -e

echo "=== 테스트 및 커버리지 검사 시작 ==="
echo ""

# pytest 실행
echo "🧪 pytest 실행 중..."
uv run pytest

echo ""
echo "=== ✅ 테스트 완료 ==="
echo ""

# 커버리지 리포트
echo "📊 커버리지 리포트:"
echo ""
uv run coverage report

echo ""
echo "📁 HTML 커버리지 리포트 생성됨: htmlcov/index.html"
echo "브라우저에서 확인: open htmlcov/index.html"
