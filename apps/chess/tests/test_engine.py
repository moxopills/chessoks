from apps.chess.engine.board import (
    Move,
    apply_move,
    from_fen,
    game_status,
    generate_legal_moves,
    move_to_uci,
    to_fen,
    uci_to_move,
)


def _moves_to_uci(moves: list[Move]) -> set[str]:
    return {move_to_uci(move) for move in moves}


def test_fen_round_trip_initial() -> None:
    fen = "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1"
    position = from_fen(fen)
    assert to_fen(position).startswith("rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq -")


def test_initial_legal_move_count() -> None:
    position = from_fen("rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1")
    legal = generate_legal_moves(position)
    assert len(legal) == 20


def test_castling_moves_available() -> None:
    position = from_fen("r3k2r/8/8/8/8/8/8/R3K2R w KQkq - 0 1")
    legal = _moves_to_uci(generate_legal_moves(position))
    assert "e1g1" in legal
    assert "e1c1" in legal


def test_en_passant_capture() -> None:
    position = from_fen("8/8/8/3pP3/8/8/8/8 w - d6 0 1")
    legal = _moves_to_uci(generate_legal_moves(position))
    assert "e5d6" in legal

    next_position = apply_move(position, uci_to_move("e5d6"))
    assert (3, 4) not in next_position.board


def test_promotion_moves() -> None:
    position = from_fen("8/P7/8/8/8/8/8/8 w - - 0 1")
    legal = _moves_to_uci(generate_legal_moves(position))
    assert {"a7a8q", "a7a8r", "a7a8b", "a7a8n"} <= legal

    next_position = apply_move(position, uci_to_move("a7a8q"))
    assert next_position.board[(0, 7)] == "Q"


def test_checkmate_and_stalemate() -> None:
    checkmate_pos = from_fen("7k/6Q1/6K1/8/8/8/8/8 b - - 0 1")
    assert game_status(checkmate_pos) == "checkmate_white"

    stalemate_pos = from_fen("7k/5Q2/6K1/8/8/8/8/8 b - - 0 1")
    assert game_status(stalemate_pos) == "stalemate"
