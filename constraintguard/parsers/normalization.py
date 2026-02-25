import re
from decimal import Decimal

_SIZE_PATTERN = re.compile(
    r"^\s*(\d+(?:\.\d+)?)\s*(B|KB|MB|GB|K|M|G)?\s*$",
    re.IGNORECASE,
)

_TIME_PATTERN = re.compile(
    r"^\s*(\d+(?:\.\d+)?)\s*(us|ms|s)\s*$",
    re.IGNORECASE,
)

_SIZE_MULTIPLIERS: dict[str, int] = {
    "b": 1,
    "kb": 1024,
    "mb": 1024**2,
    "gb": 1024**3,
    "k": 1024,
    "m": 1024**2,
    "g": 1024**3,
}

_TIME_MULTIPLIERS: dict[str, int] = {
    "us": 1,
    "ms": 1_000,
    "s": 1_000_000,
}


def parse_size_to_bytes(value: str | int) -> int:
    if isinstance(value, int):
        return value
    stripped = str(value).strip()
    if stripped.lower().startswith("0x"):
        return int(stripped, 16)
    match = _SIZE_PATTERN.match(stripped)
    if not match:
        raise ValueError(
            f"Cannot parse size value: {value!r}. "
            "Expected format: '2KB', '256K', '1MB', or plain integer bytes."
        )
    number = Decimal(match.group(1))
    unit = (match.group(2) or "b").lower()
    return int(number * _SIZE_MULTIPLIERS[unit])


def parse_time_to_us(value: str | int) -> int:
    if isinstance(value, int):
        return value
    match = _TIME_PATTERN.match(str(value).strip())
    if not match:
        raise ValueError(
            f"Cannot parse time value: {value!r}. "
            "Expected format: '50us', '100ms', '1s', or plain integer (microseconds)."
        )
    number = Decimal(match.group(1))
    unit = match.group(2).lower()
    return int(number * _TIME_MULTIPLIERS[unit])
