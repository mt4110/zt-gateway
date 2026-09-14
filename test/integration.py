#!/usr/bin/env python3
"""Exercise the packaged CLI with isolated, short-lived test keys and tool pins."""

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", default="local-smoketest",
                        help="name of the synthetic test recipient")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_-]+", args.client):
        parser.error("--client must contain only letters, digits, underscores or hyphens")

    repo = Path(__file__).resolve().parents[1]
    binary = os.environ.get("ZT_BIN")
    if not binary:
        package = subprocess.check_output(
            ["nix", "build", ".#zt", "--no-link", "--print-out-paths"],
            cwd=repo, text=True).strip()
        binary = str(Path(package) / "bin/zt")
    binary = str(Path(binary).resolve())
    if not os.access(binary, os.X_OK):
        parser.error("ZT_BIN must name an executable zt binary")
    for tool in ("gpg", "gpgconf", "tar", "go"):
        if not shutil.which(tool):
            parser.error(f"{tool} is required; run inside nix develop")

    # Keep test state for inspection. Never alter the checkout's keys or policy.
    temp = Path(tempfile.mkdtemp(prefix="zt-integration-"))
    workspace = temp / "workspace"
    workspace.mkdir()
    files = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=repo)
    for name in set(os.fsdecode(files).split("\0")) - {""}:
        source = repo / name
        if source.is_file() and not source.is_symlink():
            target = workspace / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)

    home = temp / "gnupg"
    home.mkdir(mode=0o700)
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("ZT_", "SECURE_PACK_"))}
    env.update(GNUPGHOME=str(home), ZT_NO_AUTO_SYNC="1",
               ZT_LOCAL_SOR_DB_PATH=str(temp / "sor.db"),
               ZT_LOCAL_SOR_MASTER_KEY_B64=base64.b64encode(os.urandom(32)).decode())

    def run(command, *, expected=0, overrides=None):
        result = subprocess.run(command, cwd=workspace, env=env | (overrides or {}),
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if result.returncode != expected:
            raise RuntimeError(f"{command[0]} exited {result.returncode}, expected {expected}:\n"
                               + result.stdout)
        return result.stdout

    print(f"Integration workspace: {temp}", flush=True)
    try:
        batch = temp / "key.batch"
        batch.write_text("Key-Type: EDDSA\nKey-Curve: ed25519\nSubkey-Type: ECDH\n"
                         "Subkey-Curve: cv25519\nName-Real: ZT Integration\n"
                         "Name-Email: integration@example.invalid\nExpire-Date: 1d\n"
                         "%no-protection\n%commit\n")
        run(["gpg", "--batch", "--gen-key", str(batch)])
        listing = run(["gpg", "--batch", "--with-colons", "--list-secret-keys"])
        fingerprint = next(line.split(":")[9] for line in listing.splitlines()
                           if line.startswith("fpr:"))
        env.update(ZT_SECURE_PACK_ROOT_PUBKEY_FINGERPRINTS=fingerprint,
                   ZT_SECURE_PACK_SIGNER_FINGERPRINTS=fingerprint)
        pack = workspace / "tools/secure-pack"
        # This trust root exists only in the fixture; production pins stay intact.
        run(["gpg", "--batch", "--yes", "--armor", "--output",
             str(pack / "ROOT_PUBKEY.asc"), "--export", fingerprint])
        (pack / "SIGNERS_ALLOWLIST.txt").write_text(fingerprint + "\n")
        recipients = pack / "recipients"
        recipients.mkdir(exist_ok=True)
        (recipients / f"{args.client}.txt").write_text(fingerprint + "\n")
        lock = pack / "tools.lock"
        pins = {}
        for tool in ("gpg", "tar"):
            pins[f"{tool}_sha256"] = hashlib.sha256(Path(shutil.which(tool)).read_bytes()).hexdigest()
            pins[f"{tool}_version"] = run([tool, "--version"]).splitlines()[0].strip()
        lock.write_text("".join(f"{k}={json.dumps(v)}\n" for k, v in pins.items()))
        run(["gpg", "--batch", "--yes", "--armor", "--detach-sign", "-u", fingerprint,
             "--output", str(lock) + ".sig", str(lock)])
        (workspace / "policy/scan_policy.toml").write_text(
            "required_scanners = []\nrequire_clamav_db = false\n")
        (workspace / "safe.txt").write_text("This is safe test content.\n")
        (workspace / "blocked.exe").write_text("Executable test content\n")
        expiry = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat(timespec="seconds")
        reason = f"incident=ci-smoketest;approved_by=ci;expires_at={expiry}"
        send = [binary, "send", "--client", args.client, "--allow-degraded-scan",
                "--break-glass-reason", reason, "--force-public"]

        # Exercise rejection first so any unexpectedly generated packet is visible.
        rejection = run(send + ["blocked.exe"], expected=1)
        if "policy.extension_denied:.exe" not in rejection:
            raise RuntimeError("send failed for an unexpected reason:\n" + rejection)
        if list(workspace.glob("bundle_*.spkg.tgz")):
            raise RuntimeError("blocked file unexpectedly produced a packet")
        print("PASS: blocked extension produces no packet", flush=True)
        run(send + ["safe.txt"])
        packets = list(workspace.glob(f"bundle_{args.client}_*.spkg.tgz"))
        if len(packets) != 1:
            raise RuntimeError(f"expected one packet, got {len(packets)}")
        run([binary, "verify", str(packets[0])])
        print("PASS: encrypted packet creation and signature verification", flush=True)
        rejection = run([binary, "verify", str(packets[0])], expected=1,
                        overrides={"ZT_SECURE_PACK_SIGNER_FINGERPRINTS": "0" * 40})
        if "packet signer fingerprint mismatch" not in rejection:
            raise RuntimeError("verify failed for an unexpected reason:\n" + rejection)
        print("PASS: mismatched signer pin is rejected", flush=True)
        # Corrupt the signed tool lock without re-signing it: send must fail closed.
        lock.write_text(lock.read_text() + "# tampered\n")
        rejection = run(send + ["safe.txt"], expected=1)
        if "tools.lock signature verification failed" not in rejection:
            raise RuntimeError("send failed for an unexpected reason:\n" + rejection)
        if list(workspace.glob(f"bundle_{args.client}_*.spkg.tgz")) != packets:
            raise RuntimeError("tampered tools.lock unexpectedly produced a packet")
        print("PASS: tampered tools.lock is rejected", flush=True)
    finally:
        subprocess.run(["gpgconf", "--kill", "gpg-agent"], env=env, check=False)


if __name__ == "__main__":
    main()
