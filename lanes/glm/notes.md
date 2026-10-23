# glm lane — CVE-2026-110264 research

Authoritative state. Commit per finding. Probes log: lanes/glm/probes.log

## Harness (regrush33 :8021)
- 2026-10-22: build was crash-looping — webrick missing from ruby:3.3-bookworm
  (not a default gem since 3.0). Fixed: `gem install webrick` in Dockerfile. Up.
- Target ID: ruby 3.3.12 (patchlevel 206, aarch64-linux), Onigmo **6.1.3**
  (from /usr/local/include/ruby-3.3.0/ruby/oniguruma.h).
- /pid oracle caveat: WEBrick is single-process (pid 1) under
  restart:unless-stopped, so pid does NOT change across container restarts.
  Crash oracle = HTTP request fails (conn reset/timeout) + container
  Restarting + `docker logs` exit code. docker exec ruby -e exit code
  (134=SIGABRT, 139=SIGSEGV) is the fast triage oracle.

## Findings
- **F1 CRASHER (deterministic, native)**: regex source
  `(?<=\g<n19>)|\k<-5` -> Onigmo compile-time double-free,
  glibc "free(): double free detected in tcache 2", SIGABRT (rc=134).
  Requirements mapped so far: subexp CALL (`\g<n19>`) with UNDEFINED
  name inside a LOOKBEHIND, in the FIRST branch of an ALTERNATION, with
  an invalid backref (`\k<-5` or `\k<-5>`) in the SECOND branch. Without
  `|` it's a clean RegexpError; reversed order clean; concat clean;
  named-call-defined clean. Bug = parse-error cleanup path freeing a
  node also owned by the lookbehind/call setup (fuzzer seed 1267).
  Found by structured fuzz (range/regrush/fuzz2.rb, batch mode).
- F1a: HTTP oracle works: POST /compile {source: F1} -> connection
  killed (HTTP 000), container restarts (Up 1 second), native crash
  in docker logs. = GitLab "Onigmo native worker crash" signature.
- F1b: fuzzer also found same-class variants (seed 1266, 1268):
  calls+lookbehind+quantifiers, same double-free family.
- **F1-N (reclassified)**: F1 double-free (`a|\k<-2>` etc.) crashes ONLY
  official ruby image builds (3.3.12, 3.4.11, fresh 3.3-bookworm tag);
  GitLab's embedded ruby 3.3.12 rejects the family cleanly ("invalid
  group name" / "invalid backref"). No post-fix ruby releases exist yet
  (3.3.13/3.4.12 absent from Docker Hub) -> F1 = NEW bug of ours,
  separate from CVE-2026-110264, range-relevant, unpatched upstream.
- **R2 libruby identical**: sha256(/opt/gitlab/embedded/lib/libruby.so.3.3)
  is BYTE-IDENTICAL between gitlab-ce 19.5.0-ce.0 and 19.5.1-ce.0
  (both ruby 3.3.12 rev 0581089df9). => the CVE fix in 19.5.1 is
  APP-LAYER (gitlab-rails guard), NOT an Onigmo rebuild. Consequence:
  the Onigmo integer overflow STILL EXISTS in 19.5.1's ruby; crashers
  found against 19.5.0's embedded ruby are natively valid on both; the
  patched control must reject at the APP layer (validation), not native.
- Ladder 1 DONE: gitlab-vuln up (127.0.0.1:8022, port fix 8022:8022;
  19.5 dropped `grafana` key -> removed from OMNIBUS_CONFIG).
  sign_in 200; version asserted 19.5.0 (VERSION + version-manifest).
  Embedded ruby: 3.3.12 aarch64, same parse guards (repeat 100000,
  parse-depth, 32767 groups), DIFFERENT \k<-n> handling vs official.
- Embedded-ruby fuzz round 1 (12k samples): 0 crashes. Round 2 running
  (100k samples, seeds 9000+).
- Lookbehind length int-cast (regcomp.c:2511) wraps negative for
  char_len*count>2^31 but runtime step_back(n<0) is a no-op: benign.

- Correction (probes.log): `\nnnn` multi-digit backref overflow theory
  REFUTED - `\99999999999` is literal 9s (skip_backref path), not int
  wrap. Backref/group paths bounded (ONIG_MAX_CAPTURE_GROUP_NUM=32767,
  MemNumType short; onig_scan_unsigned_number overflow-checked).
- Ruby matrix for F1: 3.0/3.1/3.2 clean (different \k<-n> parse),
  3.3.12 + 3.4.11 CRASH. Official-ruby-build-specific.

- **R3 (MAJOR): 19.5.0-ce.0 vs 19.5.1-ce.0 FULL image diff — NO CVE fix
  visible.** Hashed ALL of gitlab-rails (57k files): only 8 changed .rb
  (GraphQL scopes, OIDC discovery host, LDAP email escape, milestone API,
  backup select, pipeline iid — none regex-related) + new
  rouge_fallthrough_patch.rb (PERF only: raise Fallthrough without
  backtrace — explains "Org mode render error burst" detection).
  Gem diff: gitlab-markup 2.1.0->2.2.0 (RDoc-8 compat only, NO regex
  change), rdoc/rbs/psych/stringio churn. libruby.so byte-identical
  (R2). => The Docker Hub 19.5.1-ce.0 image contains NOTHING that
  patches an Onigmo integer overflow; its build layer date (Oct 20)
  PRECEDES the advisory (Oct 21). The :8023 "patched control" premise is
  questionable — flag to orchestrator. Practical consequence: both
  images are equally crashable natively; the crasher hunt target is
  GitLab's embedded ruby 3.3.12 (omnibus build), which so far survives
  212k+ fuzz samples (grammar v1+v2, incl. IGNORECASE/fold atoms).
- Embedded ruby fuzz rounds: v1 12k + v2 100k (IGNORECASE+fold) = 0
  native crashes. Official-ruby fuzz same grammar: many F1-family
  hits (baseline confirms grammar covers crash-prone space).

## Open questions
- CVE crasher for GitLab's Onigmo (integer overflow per advisory):
  grammar v3 needed — deeper int-field coverage: named-group table
  sizes, (?(cond)) huge nums, \g<rel> calls, absent-operator (?~)
  nestings, possessive quantifier stacks, cc-range folding combos.
  Consider also: MALLOC_PERTURB_ in harness to surface silent corruption.
- R3 follow-up: if orchestrator confirms control image is pre-advisory,
  the patched-control negative may need a rebuilt image or the rails
  diff gives the surface: none seen -> CVE fix must come from a
  different distribution artifact.
- What EXACTLY did 19.5.1 change at app layer? -> diff gitlab-rails
  between the two images (regex-compile guard location) = tells us the
  vulnerable SURFACE too (ladder 3 lead).
- F1 upstream: not fixed in any current ruby release (3.3.12/3.4.11
  both crash); watch for 3.3.13/3.4.12 to see if the Oct-21 patch set
  covers it.

## Ladder status
- [x] harness build+run (regrush33 :8021 up)
- [x] enumerate Onigmo version (6.1.3 @ ruby 3.3.12; gitlab embedded
      ruby 3.3.12 = same guards, different \k<-n> handling, ver string n/a)
- [x] LADDER 2 CRASHER: deterministic worker crash on /compile (F1,
      official-ruby-only -> F1-N)
- [x] LADDER 1: gitlab-vuln up, healthy (:8022 200), version 19.5.0
- [x] ruby matrix (3.0/3.1/3.2/3.3/3.4) + gitlab embedded ruby tested
- [x] patched-control libruby diff (identical -> app-layer fix)
- [ ] ladder 3: pre-auth surface in gitlab (org-mode render)
- both gitlab images pulled; only gitlab-vuln RUNS (one-heavy rule)
- NOTE: push failed 21:3x (remote: repository disabled, 403). Commit is\n  local; retry push later.

## Rung 8 deliverable (gitlab2shell.py)
- 2026-10-23: gitlab2shell.py at repo ROOT, phpbleed-bastet conventions
  (loopback guard, [>]/[+]/[x] timestamped lines, --target profiles:
  regrush/gitlab/control, modes probe/crash/rce-TODO).
- probe: gitlab -> sign_in 200 CE, /api/v4/version 401 (anon cannot
  read version; used embedded VERSION file instead - 19.5.0), public
  projects 0 (ladder 3 needs admin-created public repo), /explore 200.
  regrush -> ruby 3.3.12 p206, canary present, pid-oracle note.
- crash: regrush F1-N family ALL WORKER CRASH (request killed +
  service recovered). gitlab: surface driver ready, no public repo yet.
- rce: TODO structure documented (leak-first, no shipped constants).
- Fuzz round 2 (v2 grammar, embedded ruby): DONE, 0 crashes (no
  134/139 hits). Round 3 (deeper int fields) next.
