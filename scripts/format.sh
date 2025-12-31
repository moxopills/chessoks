#!/bin/bash

set -eo pipefail

COLOR_GREEN=$(tput setaf 2)
COLOR_BLUE=$(tput setaf 4)
COLOR_NC=$(tput sgr0)

cd "$(dirname "$0")/.."

echo "${COLOR_BLUE}Starting isort${COLOR_NC}"
uv run isort .
echo "OK"

echo "${COLOR_BLUE}Starting black${COLOR_NC}"
uv run black .
echo "OK"

echo "${COLOR_BLUE}Starting ruff${COLOR_NC}"
uv run ruff check --fix .
echo "OK"

echo "${COLOR_GREEN}Code Formatting successfully!${COLOR_NC}"
