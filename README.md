# gitlab-firing-range

Authorized security-research firing range for **CVE-2026-110264** — the
Onigmo (Ruby regex compiler) integer-overflow, CVSS 10.0, unauthenticated
RCE affecting GitLab CE/EE 7.0 → pre-19.5.1 (fixed 2026-10-21 in
18.11.13 / 19.0.10 / 19.1.9 / 19.2.9 / 19.3.6 / 19.4.3 / 19.5.1).
Sibling project to php-firing-range; same rules, same discipline.

## Rules of engagement (hard)
- Loopback ONLY. Every service binds 127.0.0.1. Tools must hard-refuse
  any other host. No third-party targets, ever.
- Pre-patch versions are pulled PINNED from Docker Hub official images.
  Patched control is pinned too — every finding gets a patched-target
  negative control before it's believed.
- Canary scoring: every target carries /CANARY `FLAG{<target>:<32hex>}`;
  "exploit works" == canary read via the exploited path, verified with
  docker exec.
- Public safe-harbor programs only for any real-world work; enrollment
  and submissions stay Dean's hands.

## Layout
- `docker-compose.yml` — targets (profiles: heavy GitLabs one-at-a-time)
- `range/regrush/` — minimal Ruby "compile attacker regex" harness app
  (shaping lab: seconds to restart, unlike GitLab)
- `lanes/` — one dir per research agent; `notes.md` is authoritative state
- `research/` — shared findings, advisory analysis, detection engineering
- `BRIEF.md` — the current work ladder (like php-firing-range TODO.md)

## Why this bug
Parser/compiler-level memory corruption, reachable pre-auth, shipped
inside Ruby itself — same strategic shape as CVE-2026-109618 (php2shell):
no app gadget needed, only an endpoint that compiles attacker-supplied
regex source (GitLab: many; detection names confirm worker crashes +
"Org mode render error burst"). Ruby apps other than GitLab may share
the bug — the harness lane answers which Ruby versions.
