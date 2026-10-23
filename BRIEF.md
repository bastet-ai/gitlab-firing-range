# BRIEF - work ladder (gitlab-firing-range)

Authoritative current-task file. Same conventions as php-firing-range's
TODO.md: checkboxes, commit+push after every step, lanes/<agent>/notes.md
is the authoritative running state. Authorized research, loopback-only.

## Intel (fixed points, do not re-derive)
- CVE-2026-110264, CVSS 10.0, unauth RCE, integer overflow when
  COMPILING a crafted regex; Ruby Onigmo engine; affects 7.0 -> fixed
  2026-10-21: 18.11.13 19.0.10 19.1.9 19.2.9 19.3.6 19.4.3 19.5.1.
  (Oct-12 fixes for the SIBLING CVE-2026-97229 covered only 19.2.8/
  19.3.5/19.4.2 and their line; instances that took Oct-12 are back in
  range - our :8023 19.5.1 control is patched for BOTH.)
- Advisory details go public on GitLab's issue tracker ~90 days post
  release; today there is NO public exploit chain. GitLab detections:
  "Onigmo native worker crash" + "Org mode render error burst" (Sigma,
  TLDR framework) -> confirms: native crashes occur, org-mode render is
  one attacker-regex input surface.
- Reachable pre-auth surfaces to enumerate: Org-mode/README render,
  CI regex rules (may be post-auth), import paths, /explore. The
  unauthenticated claim needs us to FIND the pre-auth compile surface.
- The bug class is shared with other Ruby apps (Onigmo ships in Ruby).
  Harness lane answers which ruby builds compile the same crasher.

## Ladder
- [x] 0. repo + compose skeleton: regrush harness (:8021), gitlab-vuln
      19.5.0 profile (:8022, heavy, arm64 image EXISTS = native),
      gitlab-patched 19.5.1 control (:8023, profile-gated).
- [ ] 1. bring up ONE gitlab (vuln) with profile up; wait for health
      (curl :8022/users/sign_in 200; first boot 5-15 min, native arm64).
      Assert version via /api/v4 or sign-in page footer -> 19.5.0.
- [ ] 2. harness first: build+run regrush33; enumerate Onigmo versions
      inside ruby:3.3-bookworm (ruby -e 'p Regp...' via docker exec;
      onigmo version is in ext/Onigmo/... or Regexp engine fingerprint).
      Craft overflow candidates: huge quantifier counts, nested
      {n,m} repetition, alternation-count fields. Goal: deterministic
      WORKER CRASH (SIGSEGV/SIGABRT) on /compile with the worker pid
      changing across the request. Log every probe to lanes/REGRUSH-NOTES.
      ruby versions to matrix: 3.0/3.1/3.2/3.3/3.4 official images +
      the ruby omnibus ships in gitlab-ce 19.5.0 (docker exec into the
      running gitlab, /opt/gitlab/embedded/bin/ruby -v).
- [ ] 3. reproduce the crash INSIDE gitlab-vuln pre-auth: find the
      unauth regex-compile surface (candidates: org-mode file render in
      public repos requires a repo = authenticated creation but PUBLIC
      read is unauth: an admin-created public repo is fine for the lab;
      README org-mode render happens for anonymous readers); crash
      puma worker == detection-signature match + DoS primitive.
- [ ] 4. from crash to read: overflow -> what corrupts? run puma under
      ASAN? (omnibus is closed; use harness: build ruby with ASAN,
      get the exact OOB write shape: size, value, offset). Decide
      primitive class (heap OOB write in regex compile buffer?).
- [ ] 5. exploit design in harness first (arbitrary read/write ->
      read /CANARY), then port to gitlab target. Win ==
      FLAG{gitlab-vuln:...} or FLAG{regrush:...} via the exploited
      path; score by docker exec compare (same score.sh style as php
      range: scripts/score.sh <target> <evidence>).
- [ ] 6. patched-control negative: same payload vs :8023 + patched
      harness control -> must NOT crash. Record.
- [ ] 7. detection: run GitLab's two Sigma rules against our own logs
      (defense lane - we want detection + hardening notes too).

## Hard rules
- loopback only; tools refuse other hosts. ONE heavy gitlab at a time
  (host has 119G RAM, 16G available - check free -g before upping).
- pinned images; assert php... sorry: ruby/gitlab versions before and
  after every experiment.
- timeout 20 on every shell-out; small turns (pi 900s wall); commit
  per finding; notes.md incrementally (lanes die, notes survive).
- no third-party targets; vendor PoC does not exist publicly - if one
  appears, STATIC AUDIT FIRST, never run unchecked.
- memory: docker compose down -v frees the big volumes when idle.
