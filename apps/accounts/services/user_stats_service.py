from __future__ import annotations


class UserStatsService:
    """UserStats 계산/카탈로그/정규화 로직 전용 서비스."""

    NICKNAME_COLOR_CATALOG = [
        {"key": "", "label": "기본", "cost": 0},
        {"key": "mint", "label": "민트", "cost": 100},
        {"key": "sunset", "label": "선셋", "cost": 250},
        {"key": "gold", "label": "골드", "cost": 450},
    ]

    PROFILE_BORDER_CATALOG = [
        {"key": "", "label": "기본", "cost": 0},
        {"key": "mint_ring", "label": "민트 링", "cost": 120},
        {"key": "royal_ring", "label": "로열 링", "cost": 300},
        {"key": "champion_ring", "label": "챔피언 링", "cost": 500},
    ]

    PROFILE_CARD_FRAME_CATALOG = [
        {"key": "", "label": "기본 프레임", "cost": 0},
        {"key": "season_champion_frame", "label": "시즌 챔피언 프레임", "cost": 0},
        {"key": "season_runnerup_frame", "label": "시즌 준우승 프레임", "cost": 0},
        {"key": "season_third_frame", "label": "시즌 3위 프레임", "cost": 0},
        {"key": "season_top10_frame", "label": "시즌 TOP 10 프레임", "cost": 0},
    ]

    NICKNAME_COLOR_ALIAS_MAP = {
        "mint_color": "mint",
        "mintgreen": "mint",
        "sunset_color": "sunset",
        "gold_color": "gold",
    }

    PROFILE_BORDER_ALIAS_MAP = {
        "mint": "mint_ring",
        "mint_border": "mint_ring",
        "royal": "royal_ring",
        "royal_border": "royal_ring",
        "champion": "champion_ring",
        "champion_border": "champion_ring",
    }
    NICKNAME_COLOR_MAP = {item["key"]: item for item in NICKNAME_COLOR_CATALOG}
    PROFILE_BORDER_MAP = {item["key"]: item for item in PROFILE_BORDER_CATALOG}
    PROFILE_CARD_FRAME_MAP = {item["key"]: item for item in PROFILE_CARD_FRAME_CATALOG}

    @classmethod
    def get_win_rate(cls, stats) -> float:
        games_played = getattr(stats, "games_played", 0) or 0
        if games_played <= 0:
            return 0.0
        games_won = getattr(stats, "games_won", 0) or 0
        return round((games_won / games_played) * 100, 2)

    @classmethod
    def get_rank_tier(cls, stats) -> str:
        competitive_games_played = getattr(stats, "competitive_games_played", 0) or 0
        if competitive_games_played < 5:
            return "Unranked"
        rating = getattr(stats, "rating", 0) or 0
        if rating >= 3500:
            return "Master"
        if rating >= 2700:
            return "Expert"
        if rating >= 2100:
            return "Advanced"
        if rating >= 1700:
            return "Intermediate"
        if rating >= 1200:
            return "Junior"
        return "Beginner"

    @classmethod
    def normalize_nickname_color_key(cls, key: str) -> str:
        value = (key or "").strip()
        return cls.NICKNAME_COLOR_ALIAS_MAP.get(value, value)

    @classmethod
    def normalize_profile_border_key(cls, key: str) -> str:
        value = (key or "").strip()
        return cls.PROFILE_BORDER_ALIAS_MAP.get(value, value)

    @staticmethod
    def _catalog_with_owned(catalog: list[dict], owned_keys: set[str]) -> list[dict]:
        return [
            {
                **item,
                "owned": item["cost"] == 0 or item["key"] in owned_keys,
            }
            for item in catalog
        ]

    @classmethod
    def get_nickname_color_item(cls, key: str) -> dict | None:
        return cls.NICKNAME_COLOR_MAP.get(cls.normalize_nickname_color_key(key))

    @classmethod
    def get_profile_border_item(cls, key: str) -> dict | None:
        return cls.PROFILE_BORDER_MAP.get(cls.normalize_profile_border_key(key))

    @classmethod
    def get_profile_card_frame_item(cls, key: str) -> dict | None:
        return cls.PROFILE_CARD_FRAME_MAP.get((key or "").strip())

    @classmethod
    def get_nickname_color_options(cls, stats) -> list[dict]:
        owned = {
            cls.normalize_nickname_color_key(item)
            for item in (getattr(stats, "owned_nickname_colors", None) or [])
        }
        current = cls.normalize_nickname_color_key(getattr(stats, "nickname_color", "") or "")
        if current:
            owned.add(current)
        return cls._catalog_with_owned(cls.NICKNAME_COLOR_CATALOG, owned)

    @classmethod
    def get_profile_border_options(cls, stats) -> list[dict]:
        owned = {
            cls.normalize_profile_border_key(item)
            for item in (getattr(stats, "owned_profile_borders", None) or [])
        }
        current = cls.normalize_profile_border_key(getattr(stats, "profile_border", "") or "")
        if current:
            owned.add(current)
        return cls._catalog_with_owned(cls.PROFILE_BORDER_CATALOG, owned)

    @classmethod
    def get_available_season_titles(cls, stats) -> list[dict]:
        current = getattr(stats, "season_title", "") or ""
        owned_titles = list(
            dict.fromkeys(
                (getattr(stats, "owned_season_titles", None) or []) + ([current] if current else [])
            )
        )
        options = [{"key": "", "label": "표시 안 함", "cost": 0, "owned": True}]
        options.extend(
            {
                "key": title,
                "label": title,
                "cost": 0,
                "owned": True,
            }
            for title in owned_titles
            if title
        )
        return options

    @classmethod
    def get_available_profile_card_frames(cls, stats) -> list[dict]:
        owned = set(getattr(stats, "owned_profile_card_frames", None) or [])
        current = (getattr(stats, "profile_card_frame", "") or "").strip()
        if current:
            owned.add(current)
        return [
            {
                **item,
                "owned": item["key"] == "" or item["key"] in owned,
            }
            for item in cls.PROFILE_CARD_FRAME_CATALOG
        ]

    @staticmethod
    def get_selected_board_skin_class(stats) -> str:
        return getattr(
            getattr(stats, "selected_board_skin", None), "css_class", "skin-board-classic"
        )

    @staticmethod
    def get_selected_piece_skin_class(stats) -> str:
        return getattr(
            getattr(stats, "selected_piece_skin", None), "css_class", "skin-piece-classic"
        )
