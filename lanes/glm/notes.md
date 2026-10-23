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
- (none yet)

## Open questions
- Onigmo repeat-count limit (ONIG_MAX_REPEAT_VALUE) in 6.1.3 — probe.
- Which ruby versions in matrix (3.0-3.4) ship vulnerable Onigmo.

## Ladder status
- [x] harness build+run (regrush33 :8021 up)
- [x] enumerate Onigmo version (6.1.3 @ ruby 3.3.12)
- [ ] craft integer-overflow crashers, deterministic worker crash
- gitlab-vuln image pull running in background (/tmp/gl-pull.log)
