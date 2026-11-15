#!/bin/sh
# The Kali cycle, inside kalilinux/kali-rolling as root. Installs what a Kali desktop already
# has, starts a virtual display, installs pwn-broker with the real installer, runs the unit
# suite with the real asciinema, then drives one whole box with kali-cycle.py. Everything worth
# reading afterwards goes into /evidence, whatever happens. The repository is mounted read-only
# at /src.

set -u

EVIDENCE=/evidence
WORK=/work
CHECKOUT="$WORK/pwn-broker"
OPT=/opt/pwn-broker
PACKAGES="python3 python3-venv python3-pip vim zsh kali-defaults openvpn iproute2 iputils-ping curl ca-certificates tar procps xvfb xterm imagemagick git"
SUITE_STATUS=not-run
CYCLE_STATUS=not-run

export HOME=/root
export DEBIAN_FRONTEND=noninteractive
mkdir -p "$EVIDENCE"

say() {
    printf '\n==== %s\n' "$1"
}

stop() {
    printf 'fail  %s\n' "$1"
    exit 1
}

collect() {
    say "evidence"
    cp /etc/hosts "$EVIDENCE/hosts.after" 2>/dev/null
    if [ -f "$EVIDENCE/hosts.before" ] && [ -f "$EVIDENCE/hosts.after" ]; then
        if cmp "$EVIDENCE/hosts.before" "$EVIDENCE/hosts.after" >"$EVIDENCE/hosts.cmp.txt" 2>&1; then
            echo "/etc/hosts at the end is byte for byte what it was before" >>"$EVIDENCE/hosts.cmp.txt"
        fi
        diff -u "$EVIDENCE/hosts.before" "$EVIDENCE/hosts.after" >>"$EVIDENCE/hosts.cmp.txt" 2>&1
    fi
    cp "$OPT/run/vpn/openvpn.log" "$EVIDENCE/openvpn.log" 2>/dev/null
    { ip addr; echo; ip route; } >"$EVIDENCE/ip-addr.txt" 2>&1
    {
        ls -la "$OPT" "$OPT/bin" "$OPT/run" "$OPT/tools" 2>&1
        echo
        find "$OPT" -path "$OPT/app" -prune -o -print 2>&1 | sort
    } >"$EVIDENCE/opt-pwn-broker.txt"
    mkdir -p "$EVIDENCE/box-recordings"
    find /root/pwn-broker -path '*/recordings/*' -name '*.txt' -exec cp {} "$EVIDENCE/box-recordings/" \; 2>/dev/null
    ps -eo pid,ppid,tty,stat,args >"$EVIDENCE/processes.txt" 2>&1
    if [ -n "${DISPLAY-}" ]; then
        import -display "$DISPLAY" -window root "$EVIDENCE/screen-at-end.png" >/dev/null 2>&1
    fi
    chmod -R a+rX "$EVIDENCE"
    ls -la "$EVIDENCE"
}
trap collect EXIT

say "1. packages"
if ! apt-get update >"$EVIDENCE/apt.txt" 2>&1; then
    tail -n 40 "$EVIDENCE/apt.txt"
    stop "apt-get update failed"
fi
# shellcheck disable=SC2086
if ! apt-get install -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold $PACKAGES >>"$EVIDENCE/apt.txt" 2>&1; then
    tail -n 40 "$EVIDENCE/apt.txt"
    stop "the packages could not be installed"
fi
{
    cat /etc/os-release
    for version in "python3 --version" "vim --version" "zsh --version" "openvpn --version" "ip -V" \
        "ping -V" "curl --version" "tar --version" "ps --version" "xterm -version" \
        "Xvfb -version" "import -version" "git --version"; do
        echo
        echo "\$ $version"
        # shellcheck disable=SC2086
        $version 2>&1 | head -n 4
    done
    echo
    # shellcheck disable=SC2086
    dpkg-query -W -f '${Package} ${Version}\n' $PACKAGES
} >"$EVIDENCE/versions.txt" 2>&1
cat "$EVIDENCE/versions.txt"

say "2. Kali's zsh settings for root"
if [ ! -e /root/.zshrc ]; then
    cp /etc/skel/.zshrc /root/.zshrc || stop "kali-defaults left no /etc/skel/.zshrc"
    echo "copied /etc/skel/.zshrc to /root/.zshrc"
else
    echo "/root/.zshrc was already there"
fi
export SHELL=/usr/bin/zsh

say "3. a virtual display"
Xvfb :99 -screen 0 1280x800x24 -nolisten tcp >"$EVIDENCE/xvfb.txt" 2>&1 &
export DISPLAY=:99
tries=0
while [ ! -S /tmp/.X11-unix/X99 ]; do
    tries=$((tries + 1))
    if [ "$tries" -gt 100 ]; then
        cat "$EVIDENCE/xvfb.txt"
        stop "Xvfb did not start"
    fi
    sleep 0.1
done
echo "Xvfb is up on $DISPLAY"
terminal="$(command -v x-terminal-emulator)" || stop "x-terminal-emulator does not resolve"
echo "x-terminal-emulator is $terminal, which is $(readlink -f "$terminal")"
update-alternatives --display x-terminal-emulator

say "4. the installer"
mkdir -p "$WORK"
rm -rf "$CHECKOUT"
cp -R /src "$CHECKOUT" || stop "cannot copy /src to $CHECKOUT"
(cd "$CHECKOUT" && sh install.sh --from .) >"$EVIDENCE/install.txt" 2>&1
status=$?
cat "$EVIDENCE/install.txt"
[ "$status" -eq 0 ] || stop "install.sh exited with status $status"
grep -qxF "ok    asciinema 3.2.1 in $OPT/app/bin/asciinema" "$EVIDENCE/install.txt" \
    || stop "the installer did not report the pinned asciinema"
"$OPT/app/bin/asciinema" --version

say "5. /etc/hosts as it was"
cp /etc/hosts "$EVIDENCE/hosts.before" || stop "cannot copy /etc/hosts"
cat /etc/hosts

say "6. the unit suite in Kali as root"
# DISPLAY is left out, as in the other jobs: no test may open a real window
if python3 -m venv "$WORK/venv" >"$EVIDENCE/suite-install.txt" 2>&1 \
    && "$WORK/venv/bin/pip" install -e "$CHECKOUT[dev]" >>"$EVIDENCE/suite-install.txt" 2>&1; then
    (cd "$CHECKOUT" && env -u DISPLAY PWN_BROKER_REAL_ASCIINEMA="$OPT/app/bin/asciinema" \
        "$WORK/venv/bin/python" -m pytest -q -W error) >"$EVIDENCE/unit-tests.txt" 2>&1
    SUITE_STATUS=$?
    tail -n 40 "$EVIDENCE/unit-tests.txt"
else
    tail -n 40 "$EVIDENCE/suite-install.txt"
    SUITE_STATUS=install-failed
fi
echo "unit suite: $SUITE_STATUS"

say "7. the cycle"
"$OPT/app/bin/python" "$CHECKOUT/.github/scripts/kali-cycle.py" --evidence "$EVIDENCE"
CYCLE_STATUS=$?

say "result"
echo "unit suite: $SUITE_STATUS"
echo "cycle:      $CYCLE_STATUS"
if [ -f "$EVIDENCE/steps.txt" ]; then
    cat "$EVIDENCE/steps.txt"
fi
if [ "$SUITE_STATUS" = 0 ] && [ "$CYCLE_STATUS" = 0 ]; then
    exit 0
fi
exit 1
