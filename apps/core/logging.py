"""구조화된 로깅 포맷터"""

import json
import logging
from datetime import UTC, datetime


class JsonFormatter(logging.Formatter):
    """JSON 형식 로그 포맷터 (프로덕션용)"""

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # 예외 정보 추가
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # 추가 필드
        if hasattr(record, "request_id"):
            log_data["request_id"] = record.request_id

        if hasattr(record, "user_id"):
            log_data["user_id"] = record.user_id

        # 파일/라인 정보 (DEBUG 레벨)
        if record.levelno <= logging.DEBUG:
            log_data["location"] = f"{record.pathname}:{record.lineno}"

        return json.dumps(log_data, ensure_ascii=False)
