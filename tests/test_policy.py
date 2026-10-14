import math

import pytest

from poi.policy import INF, PolicyError, capacity_bits, parse

from helpers import POLICY


def test_parse_fields():
    p = parse(POLICY)
    assert p.tick_seconds == 2 and p.output_volume == "/srv/out"
    assert p.hosts == {"api.example.com"}
    assert p.forward_headers == {"authorization": "Bearer test-token"}
    assert len(p.digest) == 64


def test_bad_version_rejected():
    with pytest.raises(PolicyError):
        parse(b"version: 2\n")


@pytest.mark.parametrize("host,method,path,body,verdict,reason", [
    ("evil.com", "POST", "/v1/score", b"{}", "block", "host-not-allowed"),
    ("api.example.com", "GET", "/v1/score", b"", "block", "endpoint-not-allowed"),
    ("api.example.com", "POST", "/v1/score?x=1", b"{}", "block", "query-string"),
    ("api.example.com", "POST", "/v1/score", b"not json", "block", "body-not-json"),
    ("api.example.com", "POST", "/v1/score", b'{"model":"small","count":1,"x":"leak"}', "block", "schema"),
    ("api.example.com", "POST", "/v1/score", b'{"count": 3,  "model":"small"}', "allow", ""),
])
def test_decide(host, method, path, body, verdict, reason):
    d = parse(POLICY).decide(host, method, path, body)
    assert (d.verdict, d.reason) == (verdict, reason)


def test_allowed_body_is_canonicalised():
    d = parse(POLICY).decide("api.example.com", "POST", "/v1/score", b'{ "count": 3, "model": "small" }')
    assert d.body == b'{"count":3,"model":"small"}'


def test_capacity():
    ep = parse(POLICY).endpoints[0]
    assert capacity_bits(ep.request_schema) == pytest.approx(1 + 8)
    assert capacity_bits({"type": "string"}) == INF
    assert capacity_bits({"type": "object", "properties": {}}) == INF
    assert capacity_bits({"type": "string", "maxLength": 3}) == pytest.approx(24 + 2)
    assert capacity_bits({"type": "object", "additionalProperties": False,
                          "properties": {"b": {"type": "boolean"}}}) == 2
    assert capacity_bits({"type": "array", "maxItems": 3, "items": {"type": "boolean"}}) == pytest.approx(3 + 2)
    assert capacity_bits({"const": 5}) == 0
    assert math.isinf(capacity_bits({"type": "integer", "minimum": 0}))


def _doc(**kw):
    d = {"networks": [{"name": "int", "internal": True}], "network_mode": "int", "privileged": False,
         "cap_add": [], "devices": 0, "pid_mode": "", "ipc_mode": "", "dns": ["10.0.0.2"],
         "mounts": [{"destination": "/srv/out", "rw": True, "type": "bind"},
                    {"destination": "/etc/poi", "rw": False, "type": "bind"}]}
    d.update(kw)
    return d


def test_config_ok():
    from poi.policy import config_violations
    assert config_violations(_doc(), parse(POLICY)) == []


@pytest.mark.parametrize("kw", [
    {"networks": [{"name": "int", "internal": True}, {"name": "bridge", "internal": False}]},
    {"networks": [{"name": "int", "internal": False}]},
    {"network_mode": "host"},
    {"privileged": True},
    {"cap_add": ["NET_ADMIN"]},
    {"pid_mode": "host"},
    {"dns": []},
    {"mounts": [{"destination": "/data", "rw": True, "type": "bind"}]},
])
def test_config_violations(kw):
    from poi.policy import config_violations
    assert config_violations(_doc(**kw), parse(POLICY))


def test_llm_policy_fields_default_and_parse():
    p = parse(POLICY)
    assert (p.allow_gpu, p.image_attestation, p.attest_mounts) == (False, "files", [])
    q = parse(POLICY + b"allow_gpu: true\nimage_attestation: digest\nattest_mounts: [/hf]\n")
    assert (q.allow_gpu, q.image_attestation, q.attest_mounts) == (True, "digest", ["/hf"])
    with pytest.raises(PolicyError):
        parse(POLICY + b"image_attestation: maybe\n")


def test_gpu_needs_policy_permission():
    from poi.policy import config_violations
    doc = _doc(gpus=[{"count": -1, "capabilities": ["gpu"], "driver": ""}])
    assert "GPU attached but not allowed by policy" in config_violations(doc, parse(POLICY))
    assert config_violations(doc, parse(POLICY + b"allow_gpu: true\n")) == []


@pytest.mark.parametrize("mounts,phrase", [
    ([], "attested mount missing: /hf"),
    ([{"destination": "/hf", "rw": True, "type": "bind", "content": "c" * 64}], "must be read-only"),
    ([{"destination": "/hf", "rw": False, "type": "bind"}], "no content digest"),
])
def test_attested_mount_rules(mounts, phrase):
    from poi.policy import config_violations
    pol = parse(POLICY + b"attest_mounts: [/hf]\n")
    base = [{"destination": "/srv/out", "rw": True, "type": "bind"}]
    assert any(phrase in v for v in config_violations(_doc(mounts=base + mounts), pol))


def test_attested_mount_ok():
    from poi.policy import config_violations
    pol = parse(POLICY + b"attest_mounts: [/hf]\n")
    mounts = [{"destination": "/srv/out", "rw": True, "type": "bind"},
              {"destination": "/hf", "rw": False, "type": "bind", "content": "c" * 64}]
    assert config_violations(_doc(mounts=mounts), pol) == []
