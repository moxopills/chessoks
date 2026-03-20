"""구조화된 로깅 포맷터"""

import json
import logging
from datetime import UTC, datetime

STRUCTURED_LOG_FIELDS = (
    "request_id",
    "user_id",
    "event",
    "reason",
    "room_id",
    "game_id",
    "notification_id",
    "task_name",
    "duration_ms",
    "component",
    "status_code",
    "request_method",
    "request_path",
    "queue_name",
    "queue_depth",
    "subscription_count",
)


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

        for field_name in STRUCTURED_LOG_FIELDS:
            field_value = getattr(record, field_name, None)
            if field_value is not None:
                log_data[field_name] = field_value

        # 파일/라인 정보 (DEBUG 레벨)
        if record.levelno <= logging.DEBUG:
            log_data["location"] = f"{record.pathname}:{record.lineno}"

        return json.dumps(log_data, ensure_ascii=False)
