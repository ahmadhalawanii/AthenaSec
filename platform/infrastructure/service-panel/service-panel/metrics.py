"""Read-only Linux machine CPU/RAM samples; no third-party dependencies."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Usage:
    cpu_percent: float | None = None
    memory_percent: float | None = None
    memory_used: int | None = None
    memory_total: int | None = None
    cpu_detail: str = "Sampling…"
    memory_detail: str = "Unavailable"


def parse_cpu(text):
    """Use aggregate user..steal counters; guest time is already in user/nice."""
    fields = text.splitlines()[0].split()
    if not fields or fields[0] != "cpu" or len(fields) < 5:
        raise ValueError("Missing aggregate CPU counters")
    counters = tuple(int(value) for value in fields[1:9])
    if any(value < 0 for value in counters):
        raise ValueError("Negative CPU counter")
    # Older kernels may omit counters after idle; pad to the modern eight.
    return counters + (0,) * (8 - len(counters))


def cpu_percent(previous, current):
    if previous is None:
        return None
    deltas = tuple(new - old for old, new in zip(previous, current))
    # Counter resets, CPU hotplug, and decreasing iowait must not show spikes.
    if len(deltas) != 8 or any(value < 0 for value in deltas):
        return None
    total = sum(deltas)
    if total <= 0:
        return None
    idle = deltas[3] + deltas[4]
    return max(0.0, min(100.0, 100.0 * (total - idle) / total))


def parse_memory(text):
    values = {}
    for line in text.splitlines():
        fields = line.split()
        if fields and fields[0] in ("MemTotal:", "MemAvailable:"):
            if len(fields) != 3 or fields[2] != "kB":
                raise ValueError("Unexpected memory units")
            values[fields[0]] = int(fields[1]) * 1024
    total, available = values["MemTotal:"], values["MemAvailable:"]
    if total <= 0 or not 0 <= available <= total:
        raise ValueError("Invalid memory counters")
    used = total - available
    return used, total, 100.0 * used / total


class Sampler:
    """One instance per panel; called by one non-overlapping metrics worker."""
    def __init__(self):
        self.previous = None

    def sample(self):
        cpu = None
        cpu_detail = "Sampling…"
        try:
            with open("/proc/stat", encoding="ascii") as stream:
                current = parse_cpu(stream.readline())
            cpu = cpu_percent(self.previous, current)
            self.previous = current
        except (OSError, ValueError, IndexError, UnicodeError):
            self.previous = None
            cpu_detail = "Unavailable"
        used = total = memory = None
        memory_detail = "Unavailable"
        try:
            with open("/proc/meminfo", encoding="ascii") as stream:
                used, total, memory = parse_memory(stream.read(65536))
            memory_detail = f"{used / 1024**3:.1f} / {total / 1024**3:.1f} GiB"
        except (OSError, ValueError, KeyError, UnicodeError):
            pass
        return Usage(cpu, memory, used, total, cpu_detail, memory_detail)
