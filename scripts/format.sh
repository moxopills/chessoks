#!/bin/bash

# 코드 자동 포맷팅 스크립트

set -e

echo "=== 코드 자동 포맷팅 시작 ==="
echo ""

# isort로 import 정렬
echo "📦 isort로 import 정렬 중..."
uv run isort .

echo ""
echo "✅ import 정렬 완료"
echo ""

# Black으로 코드 포맷팅
echo "🎨 Black으로 코드 포맷팅 중..."
uv run black .

echo ""
echo "✅ 코드 포맷팅 완료"
echo ""

# Ruff로 자동 수정 가능한 문제 수정
echo "📋 Ruff로 자동 수정 중..."
uv run ruff check --fix .

echo ""
echo "✅ Ruff 자동 수정 완료"
echo ""

echo "=== ✅ 코드 포맷팅 완료 ==="
echo ""
echo "변경된 파일을 확인하세요:"
git status --short
