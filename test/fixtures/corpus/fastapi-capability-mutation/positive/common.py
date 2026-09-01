from ulid import ULID


def unique_id() -> str:
    return str(ULID())
