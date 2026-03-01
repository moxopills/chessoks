from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

import chess
from apps.chess.models import Puzzle


class Command(BaseCommand):
    help = "Lichess 퍼즐 CSV를 pandas로 읽어 Puzzle 테이블에 적재합니다."

    DEFAULT_USECOLS = [
        "PuzzleId",
        "FEN",
        "Moves",
        "Rating",
        "Themes",
        "GameUrl",
    ]

    def add_arguments(self, parser):
        parser.add_argument("csv_path", type=str, help="Lichess 퍼즐 CSV 파일 경로")
        parser.add_argument("--chunk-size", type=int, default=5000, help="pandas 청크 크기")
        parser.add_argument("--limit", type=int, default=0, help="최대 처리 행 수 (0=전체)")
        parser.add_argument("--min-rating", type=int, default=0, help="최소 레이팅 필터")
        parser.add_argument(
            "--max-rating", type=int, default=0, help="최대 레이팅 필터 (0=제한 없음)"
        )
        parser.add_argument(
            "--update-existing",
            action="store_true",
            help="이미 존재하는 lichess_id 레코드도 갱신",
        )
        parser.add_argument(
            "--validate-moves",
            action="store_true",
            help="FEN 기준으로 Moves 합법성까지 검증(느리지만 안전)",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="DB 반영 없이 파싱/검증만 수행",
        )

    def handle(self, *args, **options):
        try:
            import pandas as pd
        except Exception as exc:
            raise CommandError(
                "pandas를 불러올 수 없습니다. `uv sync`로 의존성을 설치해주세요."
            ) from exc

        csv_path = Path(options["csv_path"]).expanduser().resolve()
        if not csv_path.exists():
            raise CommandError(f"CSV 파일을 찾을 수 없습니다: {csv_path}")

        chunk_size = max(1, int(options["chunk_size"]))
        limit = max(0, int(options["limit"]))
        min_rating = int(options["min_rating"])
        max_rating = int(options["max_rating"])
        update_existing = bool(options["update_existing"])
        validate_moves = bool(options["validate_moves"])
        dry_run = bool(options["dry_run"])

        stats = {
            "processed": 0,
            "valid": 0,
            "created": 0,
            "updated": 0,
            "skipped": 0,
            "invalid": 0,
        }

        self.stdout.write(self.style.NOTICE(f"CSV 로딩 시작: {csv_path}"))
        if dry_run:
            self.stdout.write(self.style.WARNING("DRY RUN 모드: DB에는 반영하지 않습니다."))

        reader = pd.read_csv(
            csv_path,
            chunksize=chunk_size,
            dtype=str,
            keep_default_na=False,
            usecols=lambda col: col in self.DEFAULT_USECOLS,
        )

        for idx, chunk in enumerate(reader, start=1):
            if limit and stats["processed"] >= limit:
                break

            rows = chunk.to_dict(orient="records")
            if limit:
                remaining = limit - stats["processed"]
                rows = rows[:remaining]

            normalized = []
            for raw in rows:
                stats["processed"] += 1
                parsed = self._normalize_row(
                    raw=raw,
                    min_rating=min_rating,
                    max_rating=max_rating,
                    validate_moves=validate_moves,
                )
                if not parsed:
                    stats["invalid"] += 1
                    continue
                normalized.append(parsed)
                stats["valid"] += 1

            if not normalized:
                self._print_progress(chunk_index=idx, stats=stats)
                continue

            if dry_run:
                self._print_progress(chunk_index=idx, stats=stats)
                continue

            created, updated, skipped = self._upsert_batch(
                rows=normalized,
                update_existing=update_existing,
            )
            stats["created"] += created
            stats["updated"] += updated
            stats["skipped"] += skipped
            self._print_progress(chunk_index=idx, stats=stats)

        self.stdout.write(self.style.SUCCESS("퍼즐 import 완료"))
        self.stdout.write(
            f"processed={stats['processed']} valid={stats['valid']} "
            f"created={stats['created']} updated={stats['updated']} "
            f"skipped={stats['skipped']} invalid={stats['invalid']}"
        )

    def _normalize_row(self, *, raw, min_rating, max_rating, validate_moves):
        lichess_id = (raw.get("PuzzleId") or "").strip()
        fen = (raw.get("FEN") or "").strip()
        moves_raw = (raw.get("Moves") or "").strip()
        themes_raw = (raw.get("Themes") or "").strip()
        game_url = (raw.get("GameUrl") or "").strip()
        rating_str = (raw.get("Rating") or "").strip()

        if not lichess_id or not fen or not moves_raw:
            return None
        if len(fen) > 120:
            return None

        try:
            rating = int(float(rating_str or "0"))
        except ValueError:
            return None
        if rating < min_rating:
            return None
        if max_rating and rating > max_rating:
            return None

        moves = [m.strip().lower() for m in moves_raw.split(" ") if m.strip()]
        if not moves:
            return None
        themes = [t.strip() for t in themes_raw.split(" ") if t.strip()]

        try:
            board = chess.Board(fen)
        except ValueError:
            return None

        if validate_moves and not self._validate_moves(board=board, moves=moves):
            return None

        return {
            "lichess_id": lichess_id,
            "fen": fen,
            "moves": moves,
            "rating": rating,
            "themes": themes,
            "game_url": game_url,
        }

    @staticmethod
    def _validate_moves(*, board: chess.Board, moves):
        for uci in moves:
            try:
                move = chess.Move.from_uci(uci)
            except ValueError:
                return False
            if move not in board.legal_moves:
                return False
            board.push(move)
        return True

    def _print_progress(self, *, chunk_index, stats):
        self.stdout.write(
            f"[chunk {chunk_index}] processed={stats['processed']} "
            f"created={stats['created']} updated={stats['updated']} "
            f"invalid={stats['invalid']}"
        )

    @staticmethod
    def _upsert_batch(*, rows, update_existing):
        ids = [r["lichess_id"] for r in rows]
        existing_qs = Puzzle.objects.filter(lichess_id__in=ids)
        existing_map = {p.lichess_id: p for p in existing_qs}

        to_create = []
        to_update = []
        skipped = 0

        for row in rows:
            current = existing_map.get(row["lichess_id"])
            if not current:
                to_create.append(Puzzle(**row))
                continue
            if not update_existing:
                skipped += 1
                continue
            current.fen = row["fen"]
            current.moves = row["moves"]
            current.rating = row["rating"]
            current.themes = row["themes"]
            current.game_url = row["game_url"]
            to_update.append(current)

        created = 0
        updated = 0
        with transaction.atomic():
            if to_create:
                Puzzle.objects.bulk_create(to_create, batch_size=2000, ignore_conflicts=True)
                created = len(to_create)
            if to_update:
                Puzzle.objects.bulk_update(
                    to_update,
                    fields=["fen", "moves", "rating", "themes", "game_url"],
                    batch_size=2000,
                )
                updated = len(to_update)
        return created, updated, skipped
