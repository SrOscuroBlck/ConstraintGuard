"""Timing utilities for CI/CD overhead measurement (Experiment 5)."""

from __future__ import annotations

import contextlib
import statistics
import time
from typing import Callable


@contextlib.contextmanager
def stage_timer(name: str, results: dict[str, float]):
    """Context manager that measures wall-clock time for a pipeline stage."""
    t0 = time.perf_counter()
    yield
    results[name] = time.perf_counter() - t0


def measure_repeated(fn: Callable, n: int = 5) -> tuple[float, float]:
    """Run fn n times and return (mean_seconds, std_seconds)."""
    times = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        times.append(time.perf_counter() - t0)
    mean = statistics.mean(times)
    std = statistics.stdev(times) if len(times) > 1 else 0.0
    return mean, std
