#!/bin/bash
# glab7: boot x86_64 Debian 13 guest for CVE-2026-110264 PoC
# Host is aarch64, no KVM -> TCG, slow boots (minutes). One heavy thing.
# Net: SLIRP user-net. Guest reaches host loopback via 10.0.2.2.
#  - reverse_tcp: guest stager connects 10.0.2.2:4444 -> host 127.0.0.1:4444
#  - ssh: hostfwd tcp:127.0.0.1:2222-:22 (loopback ONLY)
set -u
BASE="$(cd "$(dirname "$0")/.." && pwd)"
IMG="$BASE/vm/debian-13.qcow2"
SEED="$BASE/vm/seed.iso"
PUBKEY="${PUBKEY:-$HOME/.ssh/id_ed25519.pub}"
CANARY="FLAG{debvm:$(head -c8 /dev/urandom | xxd -p)}"

[ -f "$IMG" ] || { echo "[x] no $IMG (pull first)"; exit 1; }

# --- seed ISO: user + ssh key + CANARY + pristine ruby 3.3.12 build ---
cat > "$BASE/vm/user-data" <<EOF
#cloud-config
users:
  - name: debvm
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - $(cat "$PUBKEY")
write_files:
  - path: /root/CANARY
    content: "$CANARY"
    permissions: "0644"
  - path: /root/build-ruby.sh
    permissions: "0755"
    content: |
      #!/bin/bash
      # pristine ruby 3.3.12 from tarball, -O1 -g, plus gdb/gcc
      set -x
      export CFLAGS="-O1 -g"
      export MAKEFLAGS="-j2"
      apt-get update
      apt-get install -y build-essential gdb libssl-dev zlib1g-dev libyaml-dev libffi-dev curl
      cd /usr/local/src
      curl -fsSLO https://cache.ruby-lang.org/pub/ruby/3.3/ruby-3.3.12.tar.gz
      tar xf ruby-3.3.12.tar.gz
      cd ruby-3.3.12
      ./configure --disable-install-doc --enable-shared
      make || make
      make install
      hash -r
      ruby -v > /root/RUBY_BUILT 2>&1
      echo "$CANARY" > /CANARY
      chmod 644 /CANARY
      echo DONE > /root/BUILD_DONE
runcmd:
  - [ bash, -c, "nohup /root/build-ruby.sh >/var/log/ruby-build.log 2>&1 &" ]
EOF
echo "[>] CANARY: $CANARY"
cloud-localds "$SEED" "$BASE/vm/user-data" || exit 1

# fresh overlay so guest is reproducible per boot session
if [ ! -f "$BASE/vm/overlay.qcow2" ]; then
  qemu-img create -f qcow2 -b "$IMG" -F qcow2 "$BASE/vm/overlay.qcow2" 40G
fi

echo "[>] booting TCG x86_64 (slow, minutes)"
nohup qemu-system-x86_64 \
  -M pc,accel=tcg -cpu max -m 4096 -smp 2 \
  -drive file="$BASE/vm/overlay.qcow2",if=virtio \
  -drive file="$SEED",if=virtio,media=cdrom,format=raw \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:2222-:22 \
  -device virtio-net-pci,netdev=n0 \
  -display none -serial file:$BASE/vm/serial.log -pidfile "$BASE/vm/qemu.pid" \
  > "$BASE/vm/qemu.log" 2>&1 &
echo "[+] qemu pid $(cat $BASE/vm/qemu.pid 2>/dev/null)"
echo "[+] ssh: ssh -p 2222 debvm@127.0.0.1"
echo "[+] handler (host): msfconsole multi/handler SRVHOST=127.0.0.1 LPORT=4444"
echo "[+] guest->host payload addr: LHOST=10.0.2.2 (SLIRP -> host 127.0.0.1)"
