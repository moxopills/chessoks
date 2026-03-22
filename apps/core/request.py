from apps.chess.utils import parse_int


def parse_bool_query(value, *, truthy: tuple[str, ...] = ("1", "true", "True")) -> bool:
    return value in truthy


def parse_pagination_query(
    query_params,
    *,
    default_limit: int,
    max_limit: int,
    default_offset: int = 0,
    max_offset: int = 10_000,
) -> tuple[int, int, bool]:
    limit = parse_int(
        query_params.get("limit"),
        default=default_limit,
        min_value=1,
        max_value=max_limit,
    )
    offset = parse_int(
        query_params.get("offset"),
        default=default_offset,
        min_value=0,
        max_value=max_offset,
    )
    no_count = parse_bool_query(query_params.get("no_count"))
    return limit, offset, no_count
