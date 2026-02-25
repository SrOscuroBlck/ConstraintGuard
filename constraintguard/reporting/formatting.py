def format_bytes(n: int) -> str:
    if n >= 1_048_576:
        return f"{n // 1_048_576}MB"
    if n >= 1024:
        return f"{n // 1024}KB"
    return f"{n}B"


def format_us(n: int) -> str:
    if n >= 1_000_000:
        return f"{n // 1_000_000}s"
    if n >= 1000:
        return f"{n // 1000}ms"
    return f"{n}µs"
