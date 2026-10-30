"""Command line: poi keygen | fingerprint | run | resume | finalize | verify | report | clean | serve
| dashboard | client-keygen | seal | grant | unseal."""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from poi import policy as pol


def _pubkey(args) -> str:
    if args.pubkey:
        return args.pubkey
    return Path(args.pubkey_file or Path(args.run_dir) / "pubkey").read_text().strip()


def _client_sk(path) -> bytes:
    from poi.seal import keyfile
    return keyfile.load_private(Path(path), keyfile.get_password())


def _client_sealer(args, sealed_raw: bytes | None = None):
    """(Sealer | None, exit code) for --client-key; reads run_dir/sealed.json unless `sealed_raw` is given."""
    if not getattr(args, "client_key", None):
        return None, 0
    from poi.seal import SealError
    from poi.seal.keyfile import BadPassword
    from poi.seal.sealer import open_sealed_doc
    from poi.verify import E_SEALED
    try:
        raw = sealed_raw if sealed_raw is not None else (Path(args.run_dir) / "sealed.json").read_bytes()
    except FileNotFoundError:
        print("not a sealed run: sealed.json is missing", file=sys.stderr)
        return None, 2
    try:
        return open_sealed_doc(raw, _client_sk(args.client_key)), 0
    except BadPassword as e:
        print(f"sealed: {e}", file=sys.stderr)
        return None, 2
    except SealError as e:
        print(f"FAIL [{E_SEALED}] {e}", file=sys.stderr)
        return None, E_SEALED


def cmd_client_keygen(args) -> int:
    from poi.seal import keyfile
    keyfile.create(Path(args.key), keyfile.get_password(confirm=True))
    print(f"client key {args.key}, public key {keyfile.pub_path(Path(args.key))}")
    return 0


def cmd_seal(args) -> int:
    from poi.seal import bundle, keyfile
    digest = bundle.seal_dir(Path(args.data), Path(args.out), keyfile.load_public(Path(args.to)))
    print(f"{args.out} {digest}")
    return 0


def cmd_grant(args) -> int:
    from poi.seal import SealError, bundle
    from poi.seal.grant import FP_LABEL, bundle_label, make_grant
    try:
        sk = _client_sk(args.key)
        keys = {bundle_label(bundle.file_digest(Path(b))): bundle.dek_for(Path(b), sk) for b in args.bundles}
        if args.fp_key:
            keys[FP_LABEL] = Path(args.fp_key).read_bytes()
        raw = make_grant(Path(args.run_pub).read_bytes(), keys)
    except SealError as e:
        print(f"sealed: {e}", file=sys.stderr)
        return 2
    out = Path(args.out)
    tmp = out.with_name(out.name + ".tmp")
    tmp.write_bytes(raw)
    os.replace(tmp, out)                    # the run polls this file: never expose a partial grant
    print(f"grant with {len(keys)} key(s) → {out}")
    return 0


def cmd_unseal(args) -> int:
    from poi.seal import SealError, bundle
    try:
        bundle.unseal_to(Path(args.bundle), bundle.dek_for(Path(args.bundle), _client_sk(args.key)), Path(args.out))
    except SealError as e:
        print(f"sealed: {e}", file=sys.stderr)
        return 2
    print(f"{args.bundle} → {args.out}")
    return 0


def cmd_finalize(args) -> int:
    """Sign the end of a run that stopped without a final checkpoint (runs from before `final`, or a
    daemon that died after the workload exited): one checkpoint with no changes, marked final."""
    from poi.gate import utcnow
    from poi.ledger import Ledger, load_key
    from poi.lthash import LtHash
    from poi.publish import LocalPublisher
    from poi.runtime import RuntimeInfo
    run = Path(args.run_dir)
    ledger = Ledger(run, load_key(Path(args.key)))
    last = ledger.last()
    if last is None:
        print("no checkpoints to finalize", file=sys.stderr)
        return 2
    if last.get("final"):
        print(f"already final at checkpoint {last['seq']}")
        return 0
    if not args.force:
        try:
            import docker
            from docker.errors import NotFound
            try:
                status = docker.from_env().containers.get(RuntimeInfo.load(run).workload_id).status
            except NotFound:
                status = "removed"
            if status not in ("exited", "dead", "removed"):
                print(f"workload is {status}: finalize only a finished run (--force to override)", file=sys.stderr)
                return 2
        except Exception as e:                          # no Docker / no runtime.json: the operator decides
            print(f"cannot check the workload ({type(e).__name__}); use --force if it has finished", file=sys.stderr)
            return 2
    cp = ledger.append(t=max(utcnow(), last["t"]), container=last["container"], policy_digest=last["policy"],
                       accs={a: LtHash.from_b64(last[a]["vec"]) for a in ("state", "egress", "ingress")},
                       counts={"egress": last["egress"]["count"], "ingress": last["ingress"]["count"]},
                       ops=[], final=True)
    LocalPublisher(run).publish(cp)
    print(f"final checkpoint {cp['seq']} signed")
    return 0


def cmd_keygen(args) -> int:
    from poi.ledger import generate_key
    print(generate_key(Path(args.key)))
    return 0


def cmd_fingerprint(args) -> int:
    from poi.fingerprint import FingerprintSet
    kp = Path(args.fp_key)
    if not kp.exists():
        fd = os.open(kp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(os.urandom(32))
    fs = FingerprintSet.from_dir(Path(args.data), kp.read_bytes(), args.k, args.w)
    fs.save(Path(args.out))
    print(f"{len(fs.prints)} fingerprints → {args.out}")
    return 0


def cmd_run(args) -> int:
    from poi import daemon
    from poi.seal import SealError
    if args.sealed_mount and not args.sealed:
        raise SystemExit("--sealed-mount requires --sealed")
    sealed = None
    if args.sealed:
        from poi.seal.keyfile import load_public
        from poi.sealed_run import SealedOptions
        if not args.client_pub:
            raise SystemExit("--sealed requires --client-pub")
        if args.fp_key:
            raise SystemExit("in sealed mode the fingerprint key comes from the client's grant: drop --fp-key")
        sealed = SealedOptions(load_public(Path(args.client_pub)),
                               dict(m.split(":", 1) for m in args.sealed_mount),
                               list(dict.fromkeys(["/tmp", *args.tmpfs])), args.allow_swap, args.grant_timeout)
        fps = (Path(args.fingerprints), None) if args.fingerprints else None
    else:
        fps = (Path(args.fingerprints), Path(args.fp_key).read_bytes()) if args.fingerprints else None
    mounts = dict(m.split(":", 1) for m in args.mount)
    env = dict(e.split("=", 1) for e in args.env)
    spec = daemon.RunSpec(Path(args.run_dir), Path(args.policy), Path(args.key), args.image,
                          args.cmd or None, fps, mounts, gpus=args.gpus, shm_size=args.shm_size, env=env,
                          sealed=sealed, gpu_runtime=args.gpu_runtime)
    try:
        rt = daemon.start(spec)
    except SealError as e:
        print(f"sealed: {e}", file=sys.stderr)
        return 2
    rt.teardown(keep_workload=not args.rm and sealed is None)
    return 0


def cmd_resume(args) -> int:
    from poi import daemon
    from poi.seal import SealError
    try:
        daemon.resume(Path(args.run_dir), Path(args.key)).teardown()
    except SealError as e:
        print(f"sealed: {e}", file=sys.stderr)
        return 2
    return 0


def _verified(args, sealer=None):
    from poi.verify import verify_chain, verify_policy
    run = Path(args.run_dir)
    policy = pol.load(Path(args.policy) if args.policy else run / "policy.yaml")
    res = verify_chain(run, _pubkey(args))
    verify_policy(res, run, policy, sealer)
    return res, policy


def cmd_verify(args) -> int:
    from poi.verify import E_LIVE, VerifyError
    if args.live and (Path(args.run_dir) / "sealed.json").exists():
        print("--live is not available for sealed runs: the container was removed", file=sys.stderr)
        return 2
    sealer, rc = _client_sealer(args)
    if rc:
        return rc
    try:
        res, _ = _verified(args, sealer)
        if args.live:
            from poi.livecheck import live_state
            if live_state(Path(args.run_dir)) != res.accs["state"]:
                raise VerifyError(E_LIVE, res.last["seq"], "live container state differs from last checkpoint")
    except VerifyError as e:
        print(f"FAIL {e}", file=sys.stderr)
        return e.code
    print(f"OK {len(res.checkpoints)} checkpoints, {len(res.egress)} egress events, "
          f"state {res.last['state']['digest']}")
    if res.sealed_unchecked:
        print(f"sealed: {res.sealed_unchecked} egress events not schema-checked (needs --client-key)")
    return 0


def cmd_report(args) -> int:
    from poi.fingerprint import FingerprintSet
    from poi.report import build_report, render_text
    from poi.verify import VerifyError
    sealer, rc = _client_sealer(args)
    if rc:
        return rc
    try:
        res, policy = _verified(args, sealer)
    except VerifyError as e:
        print(f"FAIL {e}", file=sys.stderr)
        return e.code
    fps = None
    if args.data:
        fps = FingerprintSet.from_dir(Path(args.data), Path(args.fp_key).read_bytes(),
                                      policy.fingerprint_k, policy.fingerprint_w)
    r = build_report(res, Path(args.run_dir), policy, fps, sealer)
    print(json.dumps(r, indent=2, default=str) if args.json else render_text(r))
    return 0


def cmd_clean(args) -> int:
    import docker
    from poi.runtime import Runtime, RuntimeInfo, root_rm
    from poi.sealed_run import SHM, run_id_of, wipe_dir
    run = Path(args.run_dir)
    client = docker.from_env()
    if (run / "runtime.json").exists():
        Runtime(client, run, RuntimeInfo.load(run)).teardown(keep_workload=False)
    if (rid := run_id_of(run)) is not None:
        wipe_dir(SHM / f"poi-{rid}", lambda p: root_rm(client, p))     # leftovers of a crashed sealed run
    return 0


def _hostport(s: str) -> tuple[str, int]:
    host, _, port = s.rpartition(":")
    return host or "127.0.0.1", int(port)


def cmd_serve(args) -> int:
    from poi.serve import make_server, new_token
    tf = Path(args.token_file)
    if args.new_token:
        new_token(tf)
        print(f"new token written to {tf}")
    token = tf.read_text().strip()
    run = Path(args.run_dir)

    def runtime() -> dict:
        try:
            import docker
            from poi.runtime import RuntimeInfo
            from poi.runtime_info import declaration
            return declaration(docker.from_env(), RuntimeInfo.load(run).workload_id)
        except Exception:
            return {"status": "unknown"}

    host, port = _hostport(args.listen)
    srv = make_server(run, token, host, port, runtime)
    print(f"serving {run} on http://{host}:{srv.server_address[1]} (put TLS in front of it)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def build_dashboard(args):
    """Returns (server, mirror, url) without blocking; raises SourceError on a bad source."""
    from poi.dashboard import DashboardApp, make_dashboard_server, new_session_key
    from poi.fingerprint import FingerprintSet
    from poi.mirror import Mirror
    from poi.source import HttpSource, LocalSource
    if args.source.startswith(("http://", "https://")):
        if not args.token_file:
            raise SystemExit("--token-file is required for an HTTP source")
        source = HttpSource(args.source, Path(args.token_file).read_text().strip())
    else:
        source = LocalSource(Path(args.source))
    source.policy()                                   # fail fast on a wrong URL or token
    pubkey = args.pubkey or Path(args.pubkey_file).read_text().strip()
    sealer = None
    if getattr(args, "client_key", None):
        from poi.source import NotFound
        try:
            sealed_raw = source.sealed()
        except NotFound:
            raise SystemExit("not a sealed run: the operator feed has no sealed.json")
        sealer, rc = _client_sealer(args, sealed_raw)
        if rc:
            raise SystemExit(rc)
    fps = None
    if args.data:
        policy_raw = source.policy()
        p = pol.parse(policy_raw)
        fps = FingerprintSet.from_dir(Path(args.data), Path(args.fp_key).read_bytes(), p.fingerprint_k, p.fingerprint_w)
    mirror = Mirror(Path(args.mirror), source, pubkey, fps, source_label=args.source, sealer=sealer)
    key = new_session_key()
    host, port = _hostport(args.listen)
    srv = make_dashboard_server(DashboardApp(mirror, args.source), key, host, port)
    return srv, mirror, f"http://{host}:{srv.server_address[1]}/?key={key}"


def cmd_dashboard(args) -> int:
    import threading
    from poi.source import SourceError
    try:
        srv, mirror, url = build_dashboard(args)
    except SourceError as e:
        print(f"cannot read the operator feed: {e}", file=sys.stderr)
        return 2
    stop = threading.Event()
    threading.Thread(target=mirror.run, args=(stop,), daemon=True).start()
    threading.Thread(target=mirror.run_runtime, args=(stop,), daemon=True).start()
    print(f"dashboard: {url}")
    if args.open:
        import webbrowser
        webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="poi", description="Proof of Isolation")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("finalize", help="operator: sign the end of a run that has no final checkpoint")
    s.add_argument("run_dir")
    s.add_argument("--key", required=True)
    s.add_argument("--force", action="store_true", help="skip the check that the workload has exited")
    s.set_defaults(fn=cmd_finalize)

    s = sub.add_parser("keygen", help="generate an Ed25519 signing key")
    s.add_argument("key")
    s.set_defaults(fn=cmd_keygen)

    s = sub.add_parser("fingerprint", help="fingerprint user data for the proxy")
    s.add_argument("--data", required=True)
    s.add_argument("--fp-key", required=True, help="32-byte key file (created if missing)")
    s.add_argument("--out", required=True)
    s.add_argument("--k", type=int, default=32)
    s.add_argument("--w", type=int, default=16)
    s.set_defaults(fn=cmd_fingerprint)

    s = sub.add_parser("client-keygen", help="data owner: create a password-protected sealing key")
    s.add_argument("key")
    s.set_defaults(fn=cmd_client_keygen)

    s = sub.add_parser("seal", help="data owner: encrypt a data directory for a sealed run")
    s.add_argument("--data", required=True)
    s.add_argument("--to", required=True, help="client public key (client.pub)")
    s.add_argument("--out", required=True)
    s.set_defaults(fn=cmd_seal)

    s = sub.add_parser("grant", help="data owner: release data keys to one sealed run")
    s.add_argument("bundles", nargs="+")
    s.add_argument("--run-pub", required=True)
    s.add_argument("--key", required=True)
    s.add_argument("--fp-key", help="fingerprint key to hand to the run's proxy")
    s.add_argument("--out", required=True)
    s.set_defaults(fn=cmd_grant)

    s = sub.add_parser("unseal", help="data owner: decrypt a sealed bundle (e.g. out.sealed)")
    s.add_argument("bundle")
    s.add_argument("--key", required=True)
    s.add_argument("--out", required=True)
    s.set_defaults(fn=cmd_unseal)

    s = sub.add_parser("run", help="run a workload under attestation")
    s.add_argument("--policy", required=True)
    s.add_argument("--key", required=True)
    s.add_argument("--run-dir", required=True)
    s.add_argument("--fingerprints")
    s.add_argument("--fp-key")
    s.add_argument("--mount", action="append", default=[], help="HOST:TARGET read-only mount")
    s.add_argument("--rm", action="store_true", help="remove the workload container at the end")
    s.add_argument("--gpus", help="'all', a number of GPUs or device ids '0,1' (policy must set allow_gpu)")
    s.add_argument("--gpu-runtime", help="attach GPUs through this runtime (e.g. nvidia) instead of --gpus "
                                         "device requests; needed when the NVIDIA toolkit runs in CDI mode")
    s.add_argument("--shm-size", help="size of /dev/shm, e.g. 1g")
    s.add_argument("--env", action="append", default=[], help="KEY=VALUE for the workload")
    s.add_argument("--sealed", action="store_true", help="client data only in tmpfs; evidence sealed to the client")
    s.add_argument("--client-pub", help="client public key (sealed mode)")
    s.add_argument("--sealed-mount", action="append", default=[], help="BUNDLE:TARGET sealed read-only mount")
    s.add_argument("--tmpfs", action="append", default=[], help="extra writable tmpfs PATH or PATH:OPTIONS, e.g. /jit:exec (sealed; /tmp always)")
    s.add_argument("--allow-swap", action="store_true", help="sealed: run even though swap is active")
    s.add_argument("--grant-timeout", type=float, default=600.0, help="sealed: seconds to wait for grant.bin")
    s.add_argument("image")
    s.add_argument("cmd", nargs=argparse.REMAINDER)
    s.set_defaults(fn=cmd_run)

    s = sub.add_parser("resume", help="restart the daemon for an existing run")
    s.add_argument("--key", required=True)
    s.add_argument("--run-dir", required=True)
    s.set_defaults(fn=cmd_resume)

    for name, fn in (("verify", cmd_verify), ("report", cmd_report)):
        s = sub.add_parser(name)
        s.add_argument("run_dir")
        s.add_argument("--pubkey")
        s.add_argument("--pubkey-file")
        s.add_argument("--policy")
        s.add_argument("--client-key", help="sealed runs: read sealed fields and evidence")
        s.set_defaults(fn=fn)
    sub.choices["verify"].add_argument("--live", action="store_true")
    sub.choices["report"].add_argument("--data")
    sub.choices["report"].add_argument("--fp-key")
    sub.choices["report"].add_argument("--json", action="store_true")

    s = sub.add_parser("clean", help="remove the workload container and internal network")
    s.add_argument("run_dir")
    s.set_defaults(fn=cmd_clean)

    s = sub.add_parser("serve", help="operator: read-only feed of a run for the data owner")
    s.add_argument("run_dir")
    s.add_argument("--token-file", required=True)
    s.add_argument("--new-token", action="store_true", help="generate a new token into --token-file")
    s.add_argument("--listen", default="127.0.0.1:8765")
    s.set_defaults(fn=cmd_serve)

    s = sub.add_parser("dashboard", help="data owner: verify a run live and show it in the browser")
    s.add_argument("--source", required=True, help="https://… (poi serve behind TLS) or a local run directory")
    s.add_argument("--token-file")
    s.add_argument("--pubkey")
    s.add_argument("--pubkey-file")
    s.add_argument("--mirror", required=True, help="local directory that keeps the verified copy")
    s.add_argument("--data")
    s.add_argument("--fp-key")
    s.add_argument("--listen", default="127.0.0.1:8780")
    s.add_argument("--open", action="store_true", help="open the dashboard in the default browser")
    s.add_argument("--client-key", help="sealed runs: read sealed fields and evidence")
    s.set_defaults(fn=cmd_dashboard)
    return p


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
