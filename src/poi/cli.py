"""Command line: poi keygen | fingerprint | run | resume | verify | report | clean | serve | dashboard."""
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
    fps = (Path(args.fingerprints), Path(args.fp_key).read_bytes()) if args.fingerprints else None
    mounts = dict(m.split(":", 1) for m in args.mount)
    env = dict(e.split("=", 1) for e in args.env)
    spec = daemon.RunSpec(Path(args.run_dir), Path(args.policy), Path(args.key), args.image,
                          args.cmd or None, fps, mounts, gpus=args.gpus, shm_size=args.shm_size, env=env)
    rt = daemon.start(spec)
    rt.teardown(keep_workload=not args.rm)
    return 0


def cmd_resume(args) -> int:
    from poi import daemon
    daemon.resume(Path(args.run_dir), Path(args.key)).teardown()
    return 0


def _verified(args):
    from poi.verify import verify_chain, verify_policy
    run = Path(args.run_dir)
    policy = pol.load(Path(args.policy) if args.policy else run / "policy.yaml")
    res = verify_chain(run, _pubkey(args))
    verify_policy(res, run, policy)
    return res, policy


def cmd_verify(args) -> int:
    from poi.verify import E_LIVE, VerifyError
    try:
        res, _ = _verified(args)
        if args.live:
            from poi.livecheck import live_state
            if live_state(Path(args.run_dir)) != res.accs["state"]:
                raise VerifyError(E_LIVE, res.last["seq"], "live container state differs from last checkpoint")
    except VerifyError as e:
        print(f"FAIL {e}", file=sys.stderr)
        return e.code
    print(f"OK {len(res.checkpoints)} checkpoints, {len(res.egress)} egress events, "
          f"state {res.last['state']['digest']}")
    return 0


def cmd_report(args) -> int:
    from poi.fingerprint import FingerprintSet
    from poi.report import build_report, render_text
    from poi.verify import VerifyError
    try:
        res, policy = _verified(args)
    except VerifyError as e:
        print(f"FAIL {e}", file=sys.stderr)
        return e.code
    fps = None
    if args.data:
        fps = FingerprintSet.from_dir(Path(args.data), Path(args.fp_key).read_bytes(),
                                      policy.fingerprint_k, policy.fingerprint_w)
    r = build_report(res, Path(args.run_dir), policy, fps)
    print(json.dumps(r, indent=2, default=str) if args.json else render_text(r))
    return 0


def cmd_clean(args) -> int:
    import docker
    from poi.runtime import Runtime, RuntimeInfo
    Runtime(docker.from_env(), Path(args.run_dir), RuntimeInfo.load(Path(args.run_dir))).teardown(keep_workload=False)
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
    fps = None
    if args.data:
        policy_raw = source.policy()
        p = pol.parse(policy_raw)
        fps = FingerprintSet.from_dir(Path(args.data), Path(args.fp_key).read_bytes(), p.fingerprint_k, p.fingerprint_w)
    mirror = Mirror(Path(args.mirror), source, pubkey, fps, source_label=args.source)
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

    s = sub.add_parser("run", help="run a workload under attestation")
    s.add_argument("--policy", required=True)
    s.add_argument("--key", required=True)
    s.add_argument("--run-dir", required=True)
    s.add_argument("--fingerprints")
    s.add_argument("--fp-key")
    s.add_argument("--mount", action="append", default=[], help="HOST:TARGET read-only mount")
    s.add_argument("--rm", action="store_true", help="remove the workload container at the end")
    s.add_argument("--gpus", help="'all' or a number of GPUs to attach (policy must set allow_gpu)")
    s.add_argument("--shm-size", help="size of /dev/shm, e.g. 1g")
    s.add_argument("--env", action="append", default=[], help="KEY=VALUE for the workload")
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
    s.set_defaults(fn=cmd_dashboard)
    return p


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
