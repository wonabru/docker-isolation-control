"""policy.yaml: allow-list of endpoints, request schemas, mounts, and channel-capacity bounds."""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path

import jsonschema
import yaml

from poi.canonical import b2b256, canonical_json

INF = math.inf
FLOAT_BITS = 64


class PolicyError(Exception):
    pass


@dataclass(frozen=True)
class Endpoint:
    host: str
    method: str
    path: str
    request_schema: dict
    max_requests_per_minute: int | None = None


@dataclass
class Decision:
    verdict: str              # "allow" | "block"
    reason: str               # "" when allowed
    body: bytes = b""         # canonical body to forward (allow only)
    endpoint: Endpoint | None = None


@dataclass
class Policy:
    raw: bytes
    endpoints: list[Endpoint]
    on_violation: str = "pause"
    tick_seconds: float = 5.0
    output_volume: str | None = None
    fingerprint_k: int = 32
    fingerprint_w: int = 16
    upstream_insecure: bool = False
    forward_headers: dict[str, str] = field(default_factory=dict)

    @property
    def digest(self) -> str:
        return b2b256(self.raw)

    @property
    def hosts(self) -> set[str]:
        return {e.host for e in self.endpoints}

    def find(self, host: str, method: str, path: str) -> Endpoint | None:
        for e in self.endpoints:
            if e.host == host and e.method == method and e.path == path:
                return e
        return None

    def decide(self, host: str, method: str, path: str, body: bytes) -> Decision:
        """Hard boundary: exact endpoint, no query string, JSON body valid against schema."""
        if host not in self.hosts:
            return Decision("block", "host-not-allowed")
        if "?" in path:
            return Decision("block", "query-string")
        ep = self.find(host, method, path)
        if ep is None:
            return Decision("block", "endpoint-not-allowed")
        try:
            value = json.loads(body.decode("utf-8")) if body else None
        except (UnicodeDecodeError, json.JSONDecodeError):
            return Decision("block", "body-not-json")
        try:
            jsonschema.validate(value, ep.request_schema)
        except jsonschema.ValidationError:
            return Decision("block", "schema")
        return Decision("allow", "", canonical_json(value) if body else b"", ep)


def load(path: Path) -> Policy:
    return parse(Path(path).read_bytes())


def parse(raw: bytes) -> Policy:
    d = yaml.safe_load(raw)
    if not isinstance(d, dict) or d.get("version") != 1:
        raise PolicyError("policy must be a mapping with version: 1")
    if d.get("on_violation", "pause") not in ("pause", "alert"):
        raise PolicyError("on_violation must be pause or alert")
    eps = []
    for e in d.get("endpoints", []):
        schema = e["request_schema"]
        jsonschema.Draft202012Validator.check_schema(schema)
        eps.append(Endpoint(e["host"], e["method"].upper(), e["path"], schema,
                            e.get("max_requests_per_minute")))
    fp = d.get("fingerprint", {})
    return Policy(raw=raw, endpoints=eps, on_violation=d.get("on_violation", "pause"),
                  tick_seconds=float(d.get("tick_seconds", 5)), output_volume=d.get("output_volume"),
                  fingerprint_k=int(fp.get("k", 32)), fingerprint_w=int(fp.get("w", 16)),
                  upstream_insecure=bool(d.get("upstream_insecure", False)),
                  forward_headers=dict(d.get("forward_headers", {})))


# --- channel capacity (spec §6.3) -------------------------------------------

def _log2_count(n: float) -> float:
    return math.log2(n) if n > 1 else 0.0


def capacity_bits(schema: dict) -> float:
    """Upper bound on bits encodable by choosing a value that satisfies `schema`.

    The proxy re-serialises bodies canonically, so formatting carries no information;
    only the choice of value does. Unbounded constructs return INF.
    """
    if schema is True or schema == {}:
        return INF
    if "const" in schema:
        return 0.0
    if "enum" in schema:
        return _log2_count(len(schema["enum"]))
    t = schema.get("type")
    if isinstance(t, list):
        return _log2_count(len(t)) + max(capacity_bits({**schema, "type": x}) for x in t)
    if t == "null":
        return 0.0
    if t == "boolean":
        return 1.0
    if t == "integer":
        lo, hi = schema.get("minimum"), schema.get("maximum")
        if lo is None or hi is None:
            return INF
        return _log2_count(hi - lo + 1)
    if t == "number":
        return FLOAT_BITS
    if t == "string":
        n = schema.get("maxLength")
        return INF if n is None else 8 * n + _log2_count(n + 1)
    if t == "array":
        n = schema.get("maxItems")
        if n is None:
            return INF
        return n * capacity_bits(schema.get("items", True)) + _log2_count(n + 1)
    if t == "object":
        if schema.get("additionalProperties", True) is not False:
            return INF
        required = set(schema.get("required", []))
        total = 0.0
        for name, sub in schema.get("properties", {}).items():
            total += capacity_bits(sub) + (0 if name in required else 1)
        return total
    return INF


def endpoint_capacity(ep: Endpoint) -> float:
    return capacity_bits(ep.request_schema)


# --- container configuration rules (spec §7.4) ------------------------------

def config_violations(doc: dict, policy: Policy) -> list[str]:
    """Empty list iff the workload configuration enforces the isolation the proof relies on."""
    v = []
    nets = doc.get("networks", [])
    if len(nets) != 1 or not nets[0].get("internal"):
        v.append("workload must be attached to exactly one internal network")
    elif doc.get("network_mode") != nets[0]["name"]:
        v.append("network_mode must be the internal network")
    if doc.get("privileged"):
        v.append("privileged container")
    if doc.get("cap_add"):
        v.append(f"added capabilities: {doc['cap_add']}")
    if doc.get("devices"):
        v.append("host devices attached")
    for mode in ("pid_mode", "ipc_mode"):
        if doc.get(mode) == "host":
            v.append(f"{mode}=host")
    if not doc.get("dns"):
        v.append("DNS not pointed at the poi stub")
    for m in doc.get("mounts", []):
        if m["rw"] and m["destination"] != policy.output_volume:
            v.append(f"undeclared read-write mount: {m['destination']}")
    return v
