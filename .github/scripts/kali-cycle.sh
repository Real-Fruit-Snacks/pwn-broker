#!/bin/sh
# The Kali cycle, inside kalilinux/kali-rolling as root. CI starts the container detached with
# this repository at /src and the release-file job's artifact at /release, both read-only, and
# an evidence folder at /evidence; then runs this three times:
#
#   kali-cycle.sh prepare   with the network on: what a Kali desktop already has, Kali's zsh
#                           settings for root, a copy of the checkout, a virtual environment on
#                           Kali's own Python for the unit suite, the pinned Python build that
#                           the cycle's runtime package carries, and pwn-shop's published report
#                           package, each checked
#   kali-cycle.sh install   with the network off: shows that it is off, then installs the release
#                           file with the real installer and checks what it installed
#   kali-cycle.sh cycle     with the network on again: a virtual display, the unit suite with the
#                           real asciinema, then one whole box driven by kali-cycle.py on the
#                           app's bundled Python
#
# Each run starts a fresh shell, so what a later phase needs is kept under /work. Everything
# worth reading afterwards goes into /evidence at the end of every phase, whatever happens.

set -u

PHASE="${1-}"
EVIDENCE=/evidence
WORK=/work
CHECKOUT="$WORK/pwn-broker"
OPT=/opt/pwn-broker
PACKAGES="python3 python3-venv python3-pip vim zsh kali-defaults openvpn iproute2 iputils-ping curl ca-certificates tar procps xvfb xterm imagemagick git"
SUITE_VENV="$WORK/venv"
# prepare writes whether the unit suite's environment was made; cycle reads it
SUITE_VENV_STATUS="$WORK/suite-venv-status"
SUITE_STATUS=not-run
CYCLE_STATUS=not-run
# The Python build the cycle's runtime package carries, as pwn-shop's python-3.13 recipe pins it
RUNTIME_VERSION="3.13.18"
RUNTIME_URL="https://github.com/astral-sh/python-build-standalone/releases/download/20261110/cpython-3.13.18+20261110-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz"
RUNTIME_SIZE=35596130
RUNTIME_SHA256=f2d2199eb25880e07863b391cf7124e7ffa1338b0d65600dfcec117c4223a7fb
RUNTIME_ARCHIVE="$WORK/downloads/python.tar.gz"
# pwn-shop's report package as published, with the size and SHA-256 its index gives it
REPORT_URL="https://github.com/Real-Fruit-Snacks/pwn-shop/releases/download/report-v0.1.1-1/report-0.1.1-1.zip"
REPORT_SIZE=31448
REPORT_SHA256=94b939f198995a1e0d931d4347e48acdbcfa223bc498e3323ff65dd32c8bacdb
REPORT_PACKAGE="$WORK/downloads/report-0.1.1-1.zip"

export HOME=/root
export DEBIAN_FRONTEND=noninteractive

say() {
    printf '\n==== %s\n' "$1"
}

stop() {
    printf 'fail  %s\n' "$1"
    exit 1
}

collect() {
    say "evidence after $PHASE"
    cp /etc/hosts "$EVIDENCE/hosts.after" 2>/dev/null
    if [ -f "$EVIDENCE/hosts.before" ] && [ -f "$EVIDENCE/hosts.after" ]; then
        if cmp "$EVIDENCE/hosts.before" "$EVIDENCE/hosts.after" >"$EVIDENCE/hosts.cmp.txt" 2>&1; then
            echo "/etc/hosts at the end is byte for byte what it was before" >>"$EVIDENCE/hosts.cmp.txt"
        fi
        diff -u "$EVIDENCE/hosts.before" "$EVIDENCE/hosts.after" >>"$EVIDENCE/hosts.cmp.txt" 2>&1
    fi
    cp "$OPT/run/vpn/openvpn.log" "$EVIDENCE/openvpn.log" 2>/dev/null
    { ip addr; echo; ip route; } >"$EVIDENCE/ip-addr-$PHASE.txt" 2>&1
    {
        ls -la "$OPT" "$OPT/bin" "$OPT/run" "$OPT/tools" 2>&1
        echo
        find "$OPT" -path "$OPT/app" -prune -o -path "$OPT/python" -prune -o -print 2>&1 | sort
    } >"$EVIDENCE/opt-pwn-broker.txt"
    mkdir -p "$EVIDENCE/box-recordings"
    find /root/pwn-broker -path '*/recordings/*' -name '*.txt' -exec cp {} "$EVIDENCE/box-recordings/" \; 2>/dev/null
    ps -eo pid,ppid,tty,stat,args >"$EVIDENCE/processes-$PHASE.txt" 2>&1
    if [ -n "${DISPLAY-}" ]; then
        import -display "$DISPLAY" -window root "$EVIDENCE/screen-at-end.png" >/dev/null 2>&1
    fi
    chmod -R a+rX "$EVIDENCE"
    ls -la "$EVIDENCE"
}

prepare_kali() {
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
        # the format is dpkg-query's own, not the shell's
        # shellcheck disable=SC2016,SC2086
        dpkg-query -W -f '${Package} ${Version}\n' $PACKAGES
    } >"$EVIDENCE/versions.txt" 2>&1
    cat "$EVIDENCE/versions.txt"

    say "2. Kali's zsh settings for root"
    [ -f /etc/skel/.zshrc ] || stop "kali-defaults left no /etc/skel/.zshrc"
    if [ ! -e /root/.zshrc ]; then
        cp /etc/skel/.zshrc /root/.zshrc || stop "cannot copy /etc/skel/.zshrc to /root/.zshrc"
        echo "copied /etc/skel/.zshrc to /root/.zshrc"
    else
        echo "/root/.zshrc was already there"
    fi

    say "3. the checkout and the unit suite's environment on Kali's own Python"
    mkdir -p "$WORK" || stop "cannot create $WORK"
    rm -rf "$CHECKOUT"
    cp -R /src "$CHECKOUT" || stop "cannot copy /src to $CHECKOUT"
    # a failure here is reported by cycle as the unit suite's result, and the cycle still runs
    rm -rf "$SUITE_VENV"
    if python3 -m venv "$SUITE_VENV" >"$EVIDENCE/suite-install.txt" 2>&1 \
        && "$SUITE_VENV/bin/pip" install -e "${CHECKOUT}[dev]" >>"$EVIDENCE/suite-install.txt" 2>&1; then
        echo ready >"$SUITE_VENV_STATUS"
        echo "the unit suite's environment is in $SUITE_VENV"
    else
        tail -n 40 "$EVIDENCE/suite-install.txt"
        echo install-failed >"$SUITE_VENV_STATUS"
        echo "fail  the unit suite's environment could not be made"
    fi

    say "4. the Python build for the runtime package"
    mkdir -p "$WORK/downloads" || stop "cannot create $WORK/downloads"
    rm -f "$RUNTIME_ARCHIVE"
    echo "$RUNTIME_URL"
    curl -fsSL --retry 3 -o "$RUNTIME_ARCHIVE" "$RUNTIME_URL" || stop "the Python build could not be downloaded"
    size="$(wc -c <"$RUNTIME_ARCHIVE" | tr -d ' ')"
    [ "$size" = "$RUNTIME_SIZE" ] || stop "the Python build is $size bytes, not $RUNTIME_SIZE"
    echo "$RUNTIME_SHA256  $RUNTIME_ARCHIVE" | sha256sum -c - || stop "the Python build's SHA-256 is not $RUNTIME_SHA256"
    echo "$RUNTIME_ARCHIVE: $size bytes, SHA-256 as pinned"

    say "5. pwn-shop's report package"
    rm -f "$REPORT_PACKAGE"
    echo "$REPORT_URL"
    curl -fsSL --retry 3 -o "$REPORT_PACKAGE" "$REPORT_URL" || stop "the report package could not be downloaded"
    size="$(wc -c <"$REPORT_PACKAGE" | tr -d ' ')"
    [ "$size" = "$REPORT_SIZE" ] || stop "the report package is $size bytes, not $REPORT_SIZE"
    echo "$REPORT_SHA256  $REPORT_PACKAGE" | sha256sum -c - || stop "the report package's SHA-256 is not $REPORT_SHA256"
    echo "$REPORT_PACKAGE: $size bytes, SHA-256 as pinned"
}

network_off() {
    say "6. the network is off"
    interfaces="$(ls /sys/class/net)"
    {
        echo "\$ ls /sys/class/net"
        echo "$interfaces"
        echo
        echo "\$ ip addr; ip route"
        ip addr
        ip route
        echo
        echo "\$ getent hosts github.com"
        timeout 60 getent hosts github.com
        resolved=$?
        echo "status $resolved"
        echo
        echo "\$ curl -k https://1.1.1.1/ (port 443)"
        curl -k -sS -o /dev/null --connect-timeout 10 https://1.1.1.1/
        connected=$?
        echo "status $connected"
    } >"$EVIDENCE/network-off.txt" 2>&1
    cat "$EVIDENCE/network-off.txt"
    [ "$interfaces" = lo ] || stop "the container has network interfaces besides lo: $(echo "$interfaces" | tr '\n' ' ')"
    echo "ok    the only network interface is lo"
    [ "$resolved" -ne 0 ] || stop "github.com resolves, so the network is not off"
    echo "ok    github.com does not resolve"
    # 7 is curl's could not connect, 28 its connect timeout; 0 or anything else got further
    case "$connected" in
        7 | 28) echo "ok    no connection to 1.1.1.1:443" ;;
        0) stop "a connection to 1.1.1.1:443 was made, so the network is not off" ;;
        *) stop "curl to 1.1.1.1:443 ended with status $connected, past the connection" ;;
    esac
}

install_release() {
    export SHELL=/usr/bin/zsh
    [ -d "$CHECKOUT" ] || stop "$CHECKOUT is missing; run prepare first"
    network_off

    say "7. the installer, from the release file"
    set -- /release/pwn-broker-*-linux-x86_64.tar.gz
    if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
        ls -la /release
        stop "/release does not hold exactly one release file"
    fi
    release="$1"
    echo "$release"
    (cd "$WORK" && sh /src/install.sh --from "$release") >"$EVIDENCE/install.txt" 2>&1
    status=$?
    cat "$EVIDENCE/install.txt"
    [ "$status" -eq 0 ] || stop "install.sh exited with status $status"
    asciinema_version="$(sed -n 's/^VERSION = "\(.*\)"$/\1/p' /src/src/pwn_broker/recorder.py)"
    [ -n "$asciinema_version" ] || stop "no VERSION line in /src/src/pwn_broker/recorder.py"
    grep -qxF "ok    asciinema $asciinema_version in $OPT/app/bin/asciinema" "$EVIDENCE/install.txt" \
        || stop "the installer did not report the pinned asciinema $asciinema_version"
    shown="$("$OPT/app/bin/asciinema" --version)" || stop "$OPT/app/bin/asciinema --version failed"
    echo "$shown"
    case "$shown" in
        *"$asciinema_version"*) ;;
        *) stop "$OPT/app/bin/asciinema --version does not show $asciinema_version" ;;
    esac
    # root's .zshrc is Kali's own: /etc/skel/.zshrc plus the installer's one PATH line, nothing else
    # shellcheck disable=SC2016
    path_line="export PATH=\"$OPT/bin:\$PATH\"  # pwn-broker"
    [ "$(grep -cxF "$path_line" /root/.zshrc)" = 1 ] || stop "/root/.zshrc does not hold the installer's PATH line once"
    grep -vxF "$path_line" /root/.zshrc >"$WORK/zshrc-without-path-line"
    if ! cmp "$WORK/zshrc-without-path-line" /etc/skel/.zshrc; then
        diff -u /etc/skel/.zshrc /root/.zshrc
        stop "/root/.zshrc is not /etc/skel/.zshrc plus the PATH line"
    fi
    echo "/root/.zshrc is /etc/skel/.zshrc plus: $path_line"

    say "8. the app's Python and Kali's"
    version_code='import platform, sys; print(platform.python_version(), sys.executable)'
    app_python="$("$OPT/app/bin/python" -I -c "$version_code")" || stop "$OPT/app/bin/python does not run"
    kali_python="$(python3 -I -c "$version_code")" || stop "Kali's python3 does not run"
    echo "app:  $app_python"
    echo "Kali: $kali_python"
    [ "${app_python%% *}" = "$RUNTIME_VERSION" ] || stop "$OPT/app/bin/python is Python ${app_python%% *}, not $RUNTIME_VERSION"
    [ "${kali_python%% *}" != "$RUNTIME_VERSION" ] || stop "Kali's python3 is $RUNTIME_VERSION too, so it cannot be told from the app's"
    real="$(readlink -f "$OPT/app/bin/python")"
    echo "$OPT/app/bin/python resolves to $real"
    case "$real" in
        "$OPT/python/"*) ;;
        *) stop "$OPT/app/bin/python does not resolve under $OPT/python/" ;;
    esac
    kali_real="$(readlink -f "$(command -v python3)")"
    echo "Kali's python3 resolves to $kali_real"
    case "$kali_real" in
        "$OPT"/*) stop "Kali's python3 resolves under $OPT" ;;
    esac
    echo "ok    the app runs on its own Python $RUNTIME_VERSION, Kali's python3 is ${kali_python%% *}"
}

run_cycle() {
    export SHELL=/usr/bin/zsh
    [ -x "$OPT/app/bin/python" ] || stop "$OPT/app/bin/python is missing; run install first"

    say "9. a virtual display"
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

    say "10. /etc/hosts as it was"
    cp /etc/hosts "$EVIDENCE/hosts.before" || stop "cannot copy /etc/hosts"
    cat /etc/hosts

    say "11. the unit suite in Kali as root"
    venv_status="$(cat "$SUITE_VENV_STATUS" 2>/dev/null)" || venv_status=not-prepared
    if [ "$venv_status" = ready ]; then
        # DISPLAY is left out, as in the other jobs: no test may open a real window
        (cd "$CHECKOUT" && env -u DISPLAY PWN_BROKER_REAL_ASCIINEMA="$OPT/app/bin/asciinema" \
            "$SUITE_VENV/bin/python" -m pytest -q -W error -rs) >"$EVIDENCE/unit-tests.txt" 2>&1
        SUITE_STATUS=$?
        tail -n 40 "$EVIDENCE/unit-tests.txt"
        # the real-asciinema tests skip themselves without it; here they must run
        if grep -E '^SKIPPED .*test_record_real\.py' "$EVIDENCE/unit-tests.txt"; then
            echo "fail  tests in test_record_real.py were skipped"
            SUITE_STATUS=record-tests-skipped
        fi
    else
        SUITE_STATUS="$venv_status"
    fi
    echo "unit suite: $SUITE_STATUS"

    say "12. the cycle"
    "$OPT/app/bin/python" "$CHECKOUT/.github/scripts/kali-cycle.py" --evidence "$EVIDENCE" \
        --runtime-archive "$RUNTIME_ARCHIVE" --report-package "$REPORT_PACKAGE"
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
}

case "$PHASE" in
    prepare | install | cycle) ;;
    *)
        echo "usage: kali-cycle.sh prepare|install|cycle" >&2
        exit 2
        ;;
esac

mkdir -p "$EVIDENCE"
trap collect EXIT

case "$PHASE" in
    prepare) prepare_kali ;;
    install) install_release ;;
    cycle) run_cycle ;;
esac
