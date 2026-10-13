"""Operator-declared runtime facts (status, CPU, memory). Unverifiable by design: shown, never trusted."""
from __future__ import annotations

from typing import Callable

from docker.errors import DockerException, NotFound

from poi.gate import utcnow


def _cpu_percent(stats: dict) -> float:
    cpu, pre = stats.get("cpu_stats", {}), stats.get("precpu_stats", {})
    cpu_delta = cpu.get("cpu_usage", {}).get("total_usage", 0) - pre.get("cpu_usage", {}).get("total_usage", 0)
    sys_delta = cpu.get("system_cpu_usage", 0) - pre.get("system_cpu_usage", 0)
    if cpu_delta <= 0 or sys_delta <= 0:
        return 0.0
    return round(cpu_delta / sys_delta * cpu.get("online_cpus", 1) * 100, 1)


def declaration(client, workload_id: str, clock: Callable[[], str] = utcnow) -> dict:
    out = {"status": "unknown", "started_at": None, "cpu_percent": None, "mem_bytes": None,
           "observed_at": clock()}
    try:
        c = client.containers.get(workload_id)
        c.reload()
        out["status"] = c.status
        out["started_at"] = c.attrs.get("State", {}).get("StartedAt")
        if c.status == "running":
            stats = c.stats(stream=False)
            out["cpu_percent"] = _cpu_percent(stats)
            out["mem_bytes"] = stats.get("memory_stats", {}).get("usage")
    except (NotFound, DockerException):
        pass
    return out
