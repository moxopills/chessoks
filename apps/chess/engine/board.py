from __future__ import annotations

from dataclasses import dataclass

FILES = "abcdefgh"
PROMOTIONS = ("q", "r", "b", "n")

# 방향 상수
DIAGONAL_DIRS = ((-1, -1), (-1, 1), (1, -1), (1, 1))
STRAIGHT_DIRS = ((-1, 0), (1, 0), (0, -1), (0, 1))
ALL_DIRS = DIAGONAL_DIRS + STRAIGHT_DIRS
KNIGHT_DIRS = ((-2, -1), (-2, 1), (-1, -2), (-1, 2), (1, -2), (1, 2), (2, -1), (2, 1))


@dataclass(frozen=True)
class Move:
    from_sq: tuple[int, int]
    to_sq: tuple[int, int]
    promotion: str | None = None


@dataclass(frozen=True)
class Position:
    board: dict[tuple[int, int], str]
    turn: str
    castling: set[str]
    en_passant: tuple[int, int] | None
    halfmove_clock: int
    fullmove_number: int


def from_fen(fen: str) -> Position:
    parts = fen.split()
    placement, turn, castling, en_passant = parts[:4]
    halfmove = int(parts[4]) if len(parts) > 4 else 0
    fullmove = int(parts[5]) if len(parts) > 5 else 1

    board: dict[tuple[int, int], str] = {}
    ranks = placement.split("/")
    for rank_index, rank in enumerate(ranks):
        file_index = 0
        for char in rank:
            if char.isdigit():
                file_index += int(char)
            else:
                board[(file_index, 7 - rank_index)] = char
                file_index += 1

    castling_rights = set() if castling == "-" else set(castling)
    ep_square = None if en_passant == "-" else square_to_coord(en_passant)
    turn_color = "white" if turn == "w" else "black"

    return Position(
        board=board,
        turn=turn_color,
        castling=castling_rights,
        en_passant=ep_square,
        halfmove_clock=halfmove,
        fullmove_number=fullmove,
    )


def to_fen(position: Position) -> str:
    ranks = []
    for rank_idx in range(7, -1, -1):
        empty = 0
        parts = []
        for file_idx in range(8):
            piece = position.board.get((file_idx, rank_idx))
            if piece is None:
                empty += 1
            else:
                if empty:
                    parts.append(str(empty))
                    empty = 0
                parts.append(piece)
        if empty:
            parts.append(str(empty))
        ranks.append("".join(parts))

    placement = "/".join(ranks)
    turn = "w" if position.turn == "white" else "b"
    castling = "-" if not position.castling else "".join(sorted(position.castling))
    en_passant = "-" if position.en_passant is None else coord_to_square(position.en_passant)
    return f"{placement} {turn} {castling} {en_passant} {position.halfmove_clock} {position.fullmove_number}"


def uci_to_move(uci: str) -> Move:
    uci = uci.strip()
    from_sq = square_to_coord(uci[:2])
    to_sq = square_to_coord(uci[2:4])
    promotion = uci[4].lower() if len(uci) > 4 else None
    return Move(from_sq=from_sq, to_sq=to_sq, promotion=promotion)


def move_to_uci(move: Move) -> str:
    promotion = move.promotion or ""
    return f"{coord_to_square(move.from_sq)}{coord_to_square(move.to_sq)}{promotion}"


def generate_legal_moves(position: Position) -> list[Move]:
    color = position.turn
    king_pos = _find_king(position, color)

    # 킹 없는 포지션 (테스트용) - 모든 pseudo-legal 수 반환
    if king_pos is None:
        return list(generate_pseudo_moves(position, color))

    opponent = "black" if color == "white" else "white"
    in_check = _square_attacked(position, king_pos, opponent)
    pinned = _get_pinned_pieces(position, king_pos, color)

    legal = []
    for move in generate_pseudo_moves(position, color):
        piece = position.board.get(move.from_sq)
        if piece is None:
            continue

        # 킹 이동은 항상 체크 검증 필요
        if piece.lower() == "k":
            next_pos = apply_move(position, move)
            if not is_in_check(next_pos, color):
                legal.append(move)
            continue

        # 체크 상태면 모든 수 검증 필요
        if in_check:
            next_pos = apply_move(position, move)
            if not is_in_check(next_pos, color):
                legal.append(move)
            continue

        # 핀된 기물은 핀 방향으로만 이동 가능
        if move.from_sq in pinned:
            pin_dir = pinned[move.from_sq]
            if _is_along_pin_ray(move, pin_dir):
                legal.append(move)
            continue

        # 앙파상은 특수 케이스 - 항상 검증
        if piece.lower() == "p" and move.to_sq == position.en_passant:
            next_pos = apply_move(position, move)
            if not is_in_check(next_pos, color):
                legal.append(move)
            continue

        legal.append(move)

    return legal


def generate_pseudo_moves(position: Position, color: str | None = None) -> list[Move]:
    moves: list[Move] = []
    color = color or position.turn
    for (file_idx, rank_idx), piece in position.board.items():
        if piece_color(piece) != color:
            continue
        piece_type = piece.lower()
        if piece_type == "p":
            moves.extend(_pawn_moves(position, file_idx, rank_idx, color))
        elif piece_type == "n":
            moves.extend(_knight_moves(position, file_idx, rank_idx))
        elif piece_type == "b":
            moves.extend(_slider_moves(position, file_idx, rank_idx, DIAGONAL_DIRS))
        elif piece_type == "r":
            moves.extend(_slider_moves(position, file_idx, rank_idx, STRAIGHT_DIRS))
        elif piece_type == "q":
            moves.extend(_slider_moves(position, file_idx, rank_idx, ALL_DIRS))
        elif piece_type == "k":
            moves.extend(_king_moves(position, file_idx, rank_idx))
    return moves


def apply_move(position: Position, move: Move) -> Position:
    board = dict(position.board)
    piece = board.pop(move.from_sq)
    captured = board.get(move.to_sq)

    is_pawn = piece.lower() == "p"
    is_capture = captured is not None

    if is_pawn and position.en_passant and move.to_sq == position.en_passant and captured is None:
        capture_square = (move.to_sq[0], move.from_sq[1])
        captured = board.pop(capture_square, None)
        is_capture = captured is not None

    if piece.lower() == "k" and abs(move.to_sq[0] - move.from_sq[0]) == 2:
        board = _apply_castling(board, piece, move)
    else:
        board[move.to_sq] = piece

    if is_pawn and _is_promotion_rank(move.to_sq, piece_color(piece)):
        promotion = (move.promotion or "q").lower()
        board[move.to_sq] = promotion.upper() if piece.isupper() else promotion

    castling = _update_castling(position.castling, piece, move.from_sq, move.to_sq, captured)

    en_passant = None
    if is_pawn and abs(move.to_sq[1] - move.from_sq[1]) == 2:
        middle_rank = (move.from_sq[1] + move.to_sq[1]) // 2
        en_passant = (move.from_sq[0], middle_rank)

    halfmove = 0 if is_pawn or is_capture else position.halfmove_clock + 1
    fullmove = position.fullmove_number + (1 if position.turn == "black" else 0)
    next_turn = "black" if position.turn == "white" else "white"

    return Position(
        board=board,
        turn=next_turn,
        castling=castling,
        en_passant=en_passant,
        halfmove_clock=halfmove,
        fullmove_number=fullmove,
    )


def is_in_check(position: Position, color: str) -> bool:
    king_pos = _find_king(position, color)
    if king_pos is None:
        return False
    opponent = "black" if color == "white" else "white"
    return _square_attacked(position, king_pos, opponent)


def game_status(position: Position, history: list[str] | None = None) -> str:
    if _insufficient_material(position):
        return "insufficient"
    if position.halfmove_clock >= 100:
        return "fifty_move"
    if history is not None:
        key = position_key(position)
        if sum(1 for item in history if item == key) >= 3:
            return "threefold"

    legal_moves = generate_legal_moves(position)
    if legal_moves:
        return "ongoing"

    if is_in_check(position, position.turn):
        return "checkmate_white" if position.turn == "black" else "checkmate_black"

    return "stalemate"


def position_key(position: Position) -> str:
    placement = to_fen(position).split()[0]
    turn = "w" if position.turn == "white" else "b"
    castling = "-" if not position.castling else "".join(sorted(position.castling))
    en_passant = "-" if position.en_passant is None else coord_to_square(position.en_passant)
    return f"{placement} {turn} {castling} {en_passant}"


def _apply_castling(
    board: dict[tuple[int, int], str], piece: str, move: Move
) -> dict[tuple[int, int], str]:
    board[move.to_sq] = piece
    if move.to_sq[0] == 6:
        rook_from = (7, move.from_sq[1])
        rook_to = (5, move.from_sq[1])
    else:
        rook_from = (0, move.from_sq[1])
        rook_to = (3, move.from_sq[1])
    rook = board.pop(rook_from, None)
    if rook:
        board[rook_to] = rook
    return board


def _update_castling(
    castling: set[str],
    piece: str,
    from_sq: tuple[int, int],
    to_sq: tuple[int, int],
    captured: str | None,
) -> set[str]:
    rights = set(castling)
    if piece.lower() == "k":
        rights.discard("K" if piece.isupper() else "k")
        rights.discard("Q" if piece.isupper() else "q")
    if piece.lower() == "r":
        _discard_rook_rights(rights, from_sq, piece.isupper())
    if captured and captured.lower() == "r":
        _discard_rook_rights(rights, to_sq, captured.isupper())
    return rights


def _discard_rook_rights(rights: set[str], coord: tuple[int, int], is_white: bool) -> None:
    if coord == (0, 0):
        rights.discard("Q")
    elif coord == (7, 0):
        rights.discard("K")
    elif coord == (0, 7):
        rights.discard("q")
    elif coord == (7, 7):
        rights.discard("k")


def _square_attacked(position: Position, target: tuple[int, int], attacker_color: str) -> bool:
    file_idx, rank_idx = target

    # 폰 공격
    pawn_dir = 1 if attacker_color == "white" else -1
    for df in (-1, 1):
        pos = (file_idx + df, rank_idx - pawn_dir)
        if _on_board(*pos) and _is_piece(position, pos, attacker_color, "p"):
            return True

    # 나이트 공격
    for df, dr in KNIGHT_DIRS:
        pos = (file_idx + df, rank_idx + dr)
        if _on_board(*pos) and _is_piece(position, pos, attacker_color, "n"):
            return True

    # 킹 공격
    for df, dr in ALL_DIRS:
        pos = (file_idx + df, rank_idx + dr)
        if _on_board(*pos) and _is_piece(position, pos, attacker_color, "k"):
            return True

    # 슬라이더 공격 (비숍/퀸: 대각선, 룩/퀸: 직선)
    if _ray_attacked(position, target, attacker_color, DIAGONAL_DIRS, ("b", "q")):
        return True
    if _ray_attacked(position, target, attacker_color, STRAIGHT_DIRS, ("r", "q")):
        return True

    return False


def _ray_attacked(
    position: Position,
    target: tuple[int, int],
    color: str,
    directions: tuple,
    pieces: tuple[str, ...],
) -> bool:
    for df, dr in directions:
        file_idx, rank_idx = target
        while True:
            file_idx += df
            rank_idx += dr
            if not _on_board(file_idx, rank_idx):
                break
            occupant = position.board.get((file_idx, rank_idx))
            if occupant is None:
                continue
            if piece_color(occupant) == color and occupant.lower() in pieces:
                return True
            break
    return False


def _pawn_moves(position: Position, file_idx: int, rank_idx: int, color: str) -> list[Move]:
    moves: list[Move] = []
    direction = 1 if color == "white" else -1
    start_rank = 1 if color == "white" else 6
    last_rank = 7 if color == "white" else 0

    forward = (file_idx, rank_idx + direction)
    if _on_board(*forward) and forward not in position.board:
        if forward[1] == last_rank:
            moves.extend(_promotion_moves(file_idx, rank_idx, forward))
        else:
            moves.append(Move((file_idx, rank_idx), forward))
        double_forward = (file_idx, rank_idx + 2 * direction)
        if rank_idx == start_rank and double_forward not in position.board:
            moves.append(Move((file_idx, rank_idx), double_forward))

    for df in (-1, 1):
        capture = (file_idx + df, rank_idx + direction)
        if not _on_board(*capture):
            continue
        target = position.board.get(capture)
        if target and piece_color(target) != color:
            if capture[1] == last_rank:
                moves.extend(_promotion_moves(file_idx, rank_idx, capture))
            else:
                moves.append(Move((file_idx, rank_idx), capture))

    if position.en_passant:
        ep_file, ep_rank = position.en_passant
        if ep_rank == rank_idx + direction and abs(ep_file - file_idx) == 1:
            moves.append(Move((file_idx, rank_idx), position.en_passant))

    return moves


def _promotion_moves(file_idx: int, rank_idx: int, target: tuple[int, int]) -> list[Move]:
    return [Move((file_idx, rank_idx), target, promotion=promo) for promo in PROMOTIONS]


def _knight_moves(position: Position, file_idx: int, rank_idx: int) -> list[Move]:
    moves: list[Move] = []
    color = piece_color(position.board[(file_idx, rank_idx)])
    for df, dr in KNIGHT_DIRS:
        nf, nr = file_idx + df, rank_idx + dr
        if not _on_board(nf, nr):
            continue
        occupant = position.board.get((nf, nr))
        if occupant is None or piece_color(occupant) != color:
            moves.append(Move((file_idx, rank_idx), (nf, nr)))
    return moves


def _slider_moves(position: Position, file_idx: int, rank_idx: int, directions) -> list[Move]:
    moves: list[Move] = []
    color = piece_color(position.board[(file_idx, rank_idx)])
    for df, dr in directions:
        nf, nr = file_idx + df, rank_idx + dr
        while _on_board(nf, nr):
            occupant = position.board.get((nf, nr))
            if occupant is None:
                moves.append(Move((file_idx, rank_idx), (nf, nr)))
            else:
                if piece_color(occupant) != color:
                    moves.append(Move((file_idx, rank_idx), (nf, nr)))
                break
            nf += df
            nr += dr
    return moves


def _king_moves(position: Position, file_idx: int, rank_idx: int) -> list[Move]:
    moves: list[Move] = []
    color = piece_color(position.board[(file_idx, rank_idx)])
    for df, dr in ALL_DIRS:
        nf, nr = file_idx + df, rank_idx + dr
        if not _on_board(nf, nr):
            continue
        occupant = position.board.get((nf, nr))
        if occupant is None or piece_color(occupant) != color:
            moves.append(Move((file_idx, rank_idx), (nf, nr)))

    moves.extend(_castling_moves(position, color, file_idx, rank_idx))
    return moves


def _castling_moves(position: Position, color: str, file_idx: int, rank_idx: int) -> list[Move]:
    if (color == "white" and (file_idx, rank_idx) != (4, 0)) or (
        color == "black" and (file_idx, rank_idx) != (4, 7)
    ):
        return []
    if is_in_check(position, color):
        return []

    moves: list[Move] = []
    opponent = "black" if color == "white" else "white"

    if ("K" if color == "white" else "k") in position.castling:
        path = [(5, rank_idx), (6, rank_idx)]
        if all(square not in position.board for square in path):
            if not any(_square_attacked(position, square, opponent) for square in path):
                moves.append(Move((file_idx, rank_idx), (6, rank_idx)))

    if ("Q" if color == "white" else "q") in position.castling:
        path = [(3, rank_idx), (2, rank_idx), (1, rank_idx)]
        if all(square not in position.board for square in path):
            if not any(_square_attacked(position, square, opponent) for square in path[:2]):
                moves.append(Move((file_idx, rank_idx), (2, rank_idx)))

    return moves


def _find_king(position: Position, color: str) -> tuple[int, int] | None:
    target = "K" if color == "white" else "k"
    for coord, piece in position.board.items():
        if piece == target:
            return coord
    return None


def piece_color(piece: str) -> str:
    return "white" if piece.isupper() else "black"


def _is_piece(position: Position, coord: tuple[int, int], color: str, kind: str) -> bool:
    piece = position.board.get(coord)
    if piece is None:
        return False
    return piece_color(piece) == color and piece.lower() == kind


def _is_promotion_rank(coord: tuple[int, int], color: str) -> bool:
    return coord[1] == (7 if color == "white" else 0)


def square_to_coord(square: str) -> tuple[int, int]:
    return (FILES.index(square[0]), int(square[1]) - 1)


def coord_to_square(coord: tuple[int, int]) -> str:
    return f"{FILES[coord[0]]}{coord[1] + 1}"


def _on_board(file_idx: int, rank_idx: int) -> bool:
    return 0 <= file_idx < 8 and 0 <= rank_idx < 8


def _get_pinned_pieces(
    position: Position, king_pos: tuple[int, int], color: str
) -> dict[tuple[int, int], tuple[int, int]]:
    """핀된 기물과 핀 방향을 반환"""
    pinned: dict[tuple[int, int], tuple[int, int]] = {}

    for df, dr in ALL_DIRS:
        file_idx, rank_idx = king_pos
        potential_pinned = None

        while True:
            file_idx += df
            rank_idx += dr
            if not _on_board(file_idx, rank_idx):
                break

            piece = position.board.get((file_idx, rank_idx))
            if piece is None:
                continue

            if piece_color(piece) == color:
                if potential_pinned is None:
                    potential_pinned = (file_idx, rank_idx)
                else:
                    break  # 두 번째 아군 기물 - 핀 없음
            else:
                # 상대 기물
                if potential_pinned is not None:
                    is_diagonal = df != 0 and dr != 0
                    is_straight = df == 0 or dr == 0
                    piece_type = piece.lower()

                    if (
                        piece_type == "q"
                        or (piece_type == "b" and is_diagonal)
                        or (piece_type == "r" and is_straight)
                    ):
                        pinned[potential_pinned] = (df, dr)
                break

    return pinned


def _is_along_pin_ray(move: Move, pin_dir: tuple[int, int]) -> bool:
    """이동이 핀 방향과 일치하는지 확인"""
    df = move.to_sq[0] - move.from_sq[0]
    dr = move.to_sq[1] - move.from_sq[1]

    # 방향 정규화
    if df != 0:
        df = df // abs(df)
    if dr != 0:
        dr = dr // abs(dr)

    # 핀 방향 또는 반대 방향으로 이동 가능
    return (df, dr) == pin_dir or (df, dr) == (-pin_dir[0], -pin_dir[1])


def _insufficient_material(position: Position) -> bool:
    pieces = list(position.board.values())
    material = [piece.lower() for piece in pieces if piece.lower() != "k"]
    if not material:
        return True
    if len(material) == 1 and material[0] in {"b", "n"}:
        return True

    if all(piece == "b" for piece in material):
        colors = []
        for coord, piece in position.board.items():
            if piece.lower() != "b":
                continue
            colors.append((coord[0] + coord[1]) % 2)
        return len(set(colors)) <= 1

    return False
