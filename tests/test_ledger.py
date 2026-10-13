import json
import os
import stat

from poi import canonical as c
from poi.ledger import generate_key, load_key, pubkey_hex

from helpers import make_run


def test_generate_and_load_key(tmp_path):
    p = tmp_path / "k"
    pub = generate_key(p)
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    assert pubkey_hex(load_key(p)) == pub
    assert (tmp_path / "k.pub").read_text().strip() == pub


def test_chain_links_and_files(tmp_path, key):
    led = make_run(tmp_path, key)
    cps = [json.loads(p.read_bytes()) for p in sorted((tmp_path / "ledger").glob("*.json"))]
    assert [cp["seq"] for cp in cps] == [0, 1, 2]
    assert cps[0]["prev"] is None
    assert cps[1]["prev"] == c.checkpoint_digest(cps[0])
    assert cps[2]["egress"]["count"] == 3
    assert (tmp_path / "pubkey").read_text().strip() == pubkey_hex(key)
    assert len(led.read_delta(1)) == 2 + 2 * 2


def test_signature_valid(tmp_path, key):
    make_run(tmp_path, key)
    cp = json.loads((tmp_path / "ledger" / "000001.json").read_bytes())
    key.public_key().verify(bytes.fromhex(cp["sig"]), c.checkpoint_signing_bytes(cp))
