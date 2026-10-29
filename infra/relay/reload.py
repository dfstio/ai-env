#!/usr/bin/python3 -I
# ai-env-relay-reload (S13, plans/s13-contracts.md §I-infra.4.5), root's, every minute. One line per run, never a
# value. Exit 0 ok, 1 a failure, 2 a bad environment. Test knobs only with AI_ENV_RELAY_ROOT (a prefix of every path).
import grp
import hashlib
import json
import os
import re
import resource
import subprocess
import sys
import time

SELF = "ai-env-relay-reload"
# In this order (infra/policies.ts RELAY_PARAMETERS, bridge::egress::RELAY_PARAMETERS); `tls` alone is a SecureString.
PARAMETERS = ["artifact", "workers", "grants", "token-signers", "tls"]
LISTS = ["workers", "grants", "token-signers"]
BINARY_RE = re.compile(r"ai-env-relay-([0-9a-f]{16})")
BINARY_MAX = 64 << 20
# PEM markers built from parts: no key block in this file (I-R78).
D5 = "-" * 5


def block(label):
    return D5 + "BEGIN " + label + D5 + r"\r?\n(?:[A-Za-z0-9+/=]+\r?\n)+" + D5 + "END " + label + D5


TLS_RE = re.compile(r"\s*(?:" + block("CERTIFICATE") + r"\s*)+" + block("PRIVATE" + " KEY") + r"\s*")


class Run:
    def __init__(self, env):
        test = bool(env.get("AI_ENV_RELAY_ROOT"))
        knob = lambda k, d: env.get(k, d) if test else d
        root = knob("AI_ENV_RELAY_ROOT", "")
        self.aws, self.systemctl = knob("AI_ENV_RELAY_AWS", "aws"), knob("AI_ENV_RELAY_SYSTEMCTL", "systemctl")
        wait = knob("AI_ENV_RELAY_WAIT_S", "60")
        self.wait_s = int(wait) if wait.isdigit() else 60
        self.libexec = root + "/usr/local/libexec/ai-env-relay"
        self.current = self.libexec + "/current"
        self.state = root + "/var/lib/ai-env-relay"
        self.previous, self.stage, self.live = self.state + "/previous", self.state + "/stage", self.state + "/live"
        self.trying, self.refused = self.state + "/trying", self.state + "/refused"
        self.log = root + "/var/log/ai-env-relay/reload.log"
        self.root = os.geteuid() == 0
        self.why, self.changed, self.absent = [], [], []
        self.fetched, self.artifact, self.relay, self.rollback = "none", "none", "unknown", None

    def line(self):
        text = "%s: %s fetched=%s changed=%s absent=%s artifact=%s tls=%s relay=%s" % (
            SELF, "FAILED" if self.why else "ok", self.fetched, ",".join(self.changed) or "none", ",".join(self.absent) or "none",
            self.artifact, "present" if os.path.lexists(self.live + "/tls.pem") else "absent", self.relay)
        text += (" rollback=" + self.rollback if self.rollback else "") + (" why=" + "; ".join(self.why) if self.why else "")
        print(text, file=sys.stderr, flush=True)
        try:
            with os.fdopen(os.open(self.log, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o644), "a") as f:
                f.write(text + "\n")
        except OSError:
            pass


def call(argv, timeout, fsize=0):
    """(exit code, stdout, the last stderr line); -1 when it did not run."""
    cap = (lambda: resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))) if fsize else None
    try:
        r = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, preexec_fn=cap)
    except subprocess.TimeoutExpired:
        return -1, b"", "timed out after %d s" % timeout
    except OSError as e:
        return -1, b"", "cannot run %s: %s" % (argv[0], e.strerror)
    lines = r.stderr.decode("utf-8", "replace").split("\n")
    last = ([l.strip() for l in lines if l.strip()] or ["exit %d" % r.returncode])[-1]
    return r.returncode, r.stdout, re.sub(r"[^ -~]", "?", last)[:200]


def fetch(run, prefix, region):
    """name -> value (None: absent), three tries 1 s and 2 s apart; None when all failed."""
    argv = [run.aws, "ssm", "get-parameters", "--names"] + ["%s/%s" % (prefix, p) for p in PARAMETERS] + [
        "--with-decryption", "--region", region, "--endpoint-url", "https://ssm.%s.amazonaws.com" % region, "--output", "json"]
    for attempt in range(3):
        time.sleep(attempt)
        code, out, why = call(argv, 60)
        if code == 0:
            try:
                given = {p["Name"]: p["Value"] for p in json.loads(out)["Parameters"] if isinstance(p.get("Value"), str)}
                return {p: given.get("%s/%s" % (prefix, p)) for p in PARAMETERS}
            except (ValueError, KeyError, TypeError, AttributeError):
                why = "unexpected output (not the get-parameters JSON)"
    run.why.append("get-parameters: " + why)
    return None


def no_constant(name):
    raise ValueError(name)


def artifact_of(value):
    """(the artifact, None) or (None, why): infra/relay-spec.ts parseRelayArtifactValue's rules."""
    try:
        a = json.loads(value, parse_constant=no_constant)
    except ValueError:
        return None, "not JSON"
    if not isinstance(a, dict) or sorted(a) != ["bucket", "key", "sha256", "version"] or not all(isinstance(v, str) for v in a.values()):
        return None, "not bucket, key, sha256, version"
    if not re.fullmatch(r"ai-env-artifacts-[a-z0-9-]{1,46}", a["bucket"]):
        return None, "bucket is not ai-env-artifacts-<suffix>"
    if not re.fullmatch(r"[0-9a-f]{64}", a["sha256"]) or a["key"] != "relay/ai-env-relay-" + a["sha256"][:16]:
        return None, "sha256 or key malformed"
    if not re.fullmatch(r"[0-9A-Za-z.+-]{1,32}", a["version"]):
        return None, "version malformed"
    return a, None


def invalid(param, value):
    """Why `value` cannot be published (None: it can)."""
    raw = value.encode("utf-8", "surrogatepass")
    if len(raw) > 4096:
        return "over 4096 bytes"
    if re.search(rb"[^\t\n\r -~]", raw):
        return "not printable ASCII"
    if param == "artifact":
        return artifact_of(value)[1]
    if param == "tls":
        return None if TLS_RE.fullmatch(value) else "not certificates then one PKCS#8 key block"
    try:
        json.loads(value, parse_constant=no_constant)
    except ValueError:
        return "not JSON"
    return None


def write(run, path, data, mode, group):
    """`data` at `path` through a temporary beside it and one rename."""
    tmp = "%s/.%s.%d.tmp" % (os.path.dirname(path), os.path.basename(path), os.getpid())
    if os.path.lexists(tmp):
        os.unlink(tmp)
    try:
        with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode), "wb") as f:
            f.write(data)
            f.flush()
            os.fchmod(f.fileno(), mode)
            if run.root:
                os.fchown(f.fileno(), 0, grp.getgrnam("ai-env-relay").gr_gid if group else 0)
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.lexists(tmp):
            os.unlink(tmp)


def read(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return None


def named(path):
    """The binary a state file names ("" when none)."""
    return (read(path) or b"").decode("utf-8", "replace").strip()


def drop(path):
    if os.path.lexists(path):
        os.unlink(path)


def publish(run, values):
    """The lists and tls.pem (I-R32), then `fetched`."""
    for param in LISTS + ["tls"]:
        path = "%s/%s" % (run.live, "tls.pem" if param == "tls" else param + ".json")
        value = values[param]
        why = value is not None and invalid(param, value)
        if why:
            run.why.append("%s: %s" % (param, why))
        if value is None or (why and param != "tls"):
            if os.path.lexists(path):
                os.unlink(path)
                run.changed.append(param)
        elif not why and read(path) != value.encode():
            write(run, path, value.encode(), 0o640, True)
            run.changed.append(param)
    now = int(time.time())
    write(run, run.live + "/fetched", b"%d\n" % now, 0o640, True)
    run.fetched = str(now)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def pointed(run):
    try:
        return os.readlink(run.current)
    except OSError:
        return None


def point(run, name):
    link = "%s/.current.%d.tmp" % (run.libexec, os.getpid())
    if os.path.lexists(link):
        os.unlink(link)
    os.symlink(name, link)
    os.replace(link, run.current)


def install(run, a, region):
    """True when this run made the artifact's binary current."""
    name = "ai-env-relay-" + a["sha256"][:16]
    path = "%s/%s" % (run.libexec, name)
    target = pointed(run)
    good = os.path.isfile(path) and not os.path.islink(path) and sha256(path) == a["sha256"]
    if target == name and good:
        return False
    if named(run.refused) == name:
        run.why.append(name[-16:] + " did not come up: not switched to again until the artifact names another binary")
        return False
    if not good:
        download = run.stage + "/download"
        if os.path.lexists(download):
            os.unlink(download)
        # Capped while written; the bytes hashed are the bytes installed.
        code, _, why = call([run.aws, "s3api", "get-object", "--bucket", a["bucket"], "--key", a["key"], "--region", region,
                             "--endpoint-url", "https://s3.%s.amazonaws.com" % region, download], 120, BINARY_MAX + 1)
        try:
            if os.path.isfile(download) and os.path.getsize(download) > BINARY_MAX:
                why = "the artifact is over 64 MiB"
            elif code != 0:
                why = "get-object: " + why
            else:
                with open(download, "rb") as f:
                    data = f.read()
                why = None if hashlib.sha256(data).hexdigest() == a["sha256"] else "the artifact's SHA-256 is not the parameter's"
                if not why:
                    write(run, path, data, 0o755, False)
        finally:
            if os.path.lexists(download):
                os.unlink(download)
        if why:
            run.why.append(why + ": nothing installed")
            return False
    if target != name and BINARY_RE.fullmatch(target or "") and os.path.isfile("%s/%s" % (run.libexec, target)):
        write(run, run.previous, (target + "\n").encode(), 0o600, False)
    elif target != name:
        drop(run.previous)
    write(run, run.trying, (name + "\n").encode(), 0o600, False)
    point(run, name)
    return True


def systemctl(run, verb):
    code, out, _ = call([run.systemctl, verb, "ai-env-relay.service"], 120)
    return code, (out.decode("utf-8", "replace").split() or [""])[0]


def started(run):
    """reset-failed (past its start limit a unit refuses a restart), restart, then wait for active."""
    systemctl(run, "reset-failed")
    systemctl(run, "restart")
    deadline = time.monotonic() + run.wait_s
    while True:
        code, word = systemctl(run, "is-active")
        if code == 0 and word == "active" or time.monotonic() >= deadline:
            return word or "unknown"
        time.sleep(2)


def lifecycle(run, switched):
    code, word = systemctl(run, "is-active")
    active = code == 0 and word == "active"
    # A trial: this run switched, or a run cut off before its verdict left `trying` naming the current binary.
    new = pointed(run)
    trial = switched or named(run.trying) == new
    if not os.path.lexists(run.live + "/tls.pem"):
        if run.changed and active:
            systemctl(run, "reload")
        run.relay = "waiting-for-tls"
    elif trial or not active:
        run.relay = started(run)
        old = named(run.previous)
        if run.relay == "active":
            if trial:
                drop(run.refused)
        elif trial and BINARY_RE.fullmatch(old) and os.path.isfile("%s/%s" % (run.libexec, old)):
            point(run, old)
            run.rollback = old[-16:]
            run.relay = started(run)
            if run.relay == "active":
                write(run, run.refused, (new + "\n").encode(), 0o600, False)
            run.why.append("the new binary did not come up: rolled back")
        else:
            run.why.append("the relay is " + run.relay)
        if trial:
            drop(run.trying)
    else:
        run.relay = "active"
        if run.changed:
            systemctl(run, "reload")


def prune(run):
    keep = {named(run.previous), pointed(run)}
    for name in os.listdir(run.libexec):
        if BINARY_RE.fullmatch(name) and name not in keep:
            os.unlink("%s/%s" % (run.libexec, name))


def main():
    prefix, region = os.environ.get("PARAM_PREFIX", ""), os.environ.get("REGION", "")
    if not re.fullmatch(r"(/[A-Za-z0-9_.-]+)+", prefix) or not re.fullmatch(r"[a-z]{2}(-[a-z]+)+-[0-9]+", region):
        print(SELF + ": reload.env: PARAM_PREFIX or REGION missing or malformed", file=sys.stderr, flush=True)
        return 2
    os.umask(0o077)
    run = Run(os.environ)
    try:
        # Made again in §3.3's modes when gone (the umask is 077).
        for d, mode, group in ((run.libexec, 0o755, False), (run.state, 0o750, True), (run.live, 0o750, True), (run.stage, 0o700, False)):
            if not os.path.isdir(d):
                os.makedirs(d, mode)
                os.chmod(d, mode)
                if run.root:
                    os.chown(d, 0, grp.getgrnam("ai-env-relay").gr_gid if group else 0)
        values = fetch(run, prefix, region)
        if values is None:
            run.line()
            return 1
        run.absent = [p for p in PARAMETERS if values[p] is None]
        publish(run, values)
        switched = False
        why = "absent" if values["artifact"] is None else invalid("artifact", values["artifact"])
        if why:
            run.why.append("artifact: %s: nothing installed" % why)
        else:
            a = artifact_of(values["artifact"])[0]
            run.artifact = a["sha256"][:16]
            switched = install(run, a, region)
        lifecycle(run, switched)
        if not run.why:
            prune(run)
    except OSError as e:
        run.why.append("%s: %s" % (e.filename or "a file", e.strerror))
    run.line()
    return 1 if run.why else 0


if __name__ == "__main__":
    sys.exit(main())
