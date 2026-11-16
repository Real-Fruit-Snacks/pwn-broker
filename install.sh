#!/bin/sh
set -eu

# Everything runs from main, called on the last line, so a download cut short
# by `curl | sh` runs nothing.

usage_line() {
    echo "usage: install.sh [--from <file>] [--config <path>] [--no-path] [--help]"
}

usage_full() {
    usage_line
    cat <<'HELP'

  --from <file>    install from a release file on disk instead of the latest release
  --config <path>  copy a settings file to config.toml
  --no-path        do not add /opt/pwn-broker/bin to PATH in ~/.zshrc and ~/.bashrc
  --help           show this text

Run it as the user who will use pwn-broker, not with sudo.
PWN_BROKER_OPT sets the install folder (default /opt/pwn-broker).
HELP
}

ok() {
    printf 'ok    %s\n' "$1"
}

fail() {
    printf 'fail  %s\n' "$1" >&2
    exit 1
}

need() {
    command -v "$1" >/dev/null 2>&1 || fail "$1 is not installed. run: apt install $2"
}

add_path_line() {
    rc="$1"
    if [ -f "$rc" ]; then
        if grep -qF '# pwn-broker' "$rc"; then
            ok "PATH line already in $rc"
            return 0
        fi
        if [ -n "$(tail -c 1 "$rc")" ]; then
            printf '\n' >>"$rc"
        fi
    fi
    # $PATH is written as it stands, for the shell that reads the file to expand
    # shellcheck disable=SC2016
    printf 'export PATH="%s/bin:$PATH"  # pwn-broker\n' "$OPT" >>"$rc"
    ok "PATH line added to $rc"
}

put_back() {
    name="$1"
    if [ ! -e "$WORK/old-$name" ]; then
        return 0
    fi
    if [ -e "$OPT/$name" ] || [ -L "$OPT/$name" ] || ! mv "$WORK/old-$name" "$OPT/$name"; then
        KEPT=1
        return 0
    fi
    PUT_BACK=1
}

# Runs on every exit, Ctrl-C and TERM included. An install that did not reach the end takes
# away what it made and puts the previous python/ and app/ back from the work folder.
finish() {
    if [ -z "$WORK" ]; then
        return 0
    fi
    if [ "$DONE" -eq 0 ]; then
        if [ "$MADE_APP" -eq 1 ]; then
            rm -rf "$OPT/app" || true
        fi
        if [ "$MADE_PYTHON" -eq 1 ]; then
            rm -rf "$OPT/python" || true
        fi
        KEPT=0
        PUT_BACK=0
        put_back app
        put_back python
        if [ "$KEPT" -eq 1 ]; then
            printf 'fail  %s\n' "could not put the previous install back. it is in $WORK" >&2
            return 0
        fi
        if [ "$PUT_BACK" -eq 1 ]; then
            ok "the previous install was put back"
        fi
    fi
    rm -rf "$WORK" || true
}

main() {
    BASE="https://github.com/Real-Fruit-Snacks/pwn-broker/releases/latest/download"
    FROM=""
    CONFIG=""
    NO_PATH=0
    HAVE_FROM=0
    HAVE_CONFIG=0
    WORK=""
    DONE=0
    MADE_APP=0
    MADE_PYTHON=0

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --from)
                if [ "$#" -lt 2 ] || [ -z "$2" ]; then usage_line >&2; exit 2; fi
                FROM="$2"
                HAVE_FROM=1
                shift 2
                ;;
            --config)
                if [ "$#" -lt 2 ] || [ -z "$2" ]; then usage_line >&2; exit 2; fi
                CONFIG="$2"
                HAVE_CONFIG=1
                shift 2
                ;;
            --no-path)
                NO_PATH=1
                shift
                ;;
            --help)
                usage_full
                exit 0
                ;;
            *)
                usage_line >&2
                exit 2
                ;;
        esac
    done

    OPT="${PWN_BROKER_OPT:-/opt/pwn-broker}"
    if [ -z "$OPT" ] || [ "$OPT" = "/" ]; then
        fail "the install folder must not be empty or /"
    fi

    trap finish EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM

    if [ "$HAVE_FROM" -eq 1 ]; then
        if [ ! -e "$FROM" ] && [ ! -L "$FROM" ]; then
            fail "$FROM does not exist"
        fi
        case "$FROM" in
            *.whl) FROM_IS_FILE=0 ;;
            *) if [ -f "$FROM" ]; then FROM_IS_FILE=1; else FROM_IS_FILE=0; fi ;;
        esac
        if [ "$FROM_IS_FILE" -eq 0 ]; then
            fail "--from takes a release file, pwn-broker-<version>-linux-x86_64.tar.gz. build one from a checkout with: python3 release/build.py"
        fi
        case "$FROM" in
            /*) ;;
            *) FROM="$(pwd)/$FROM" ;;
        esac
    fi
    if [ "$HAVE_CONFIG" -eq 1 ]; then
        [ -f "$CONFIG" ] || fail "$CONFIG does not exist"
    fi

    need tar tar
    need gzip gzip
    need sha256sum coreutils
    if [ "$HAVE_FROM" -eq 0 ]; then
        need curl curl
    fi
    arch="$(uname -m)" || fail "cannot tell this machine's architecture with uname -m"
    if [ "$arch" != "x86_64" ]; then
        fail "pwn-broker is built for x86_64 Linux. this machine is $arch"
    fi

    if [ -d "$OPT" ]; then
        owner_uid="$(stat -c %u "$OPT")"
        if [ "$owner_uid" != "$(id -u)" ]; then
            owner_name="$(stat -c %U "$OPT")"
            fail "$OPT belongs to $owner_name. run the installer as that user"
        fi
    elif ! mkdir -p "$OPT" 2>/dev/null; then
        sudo mkdir -p "$OPT" || fail "cannot create $OPT"
        if ! sudo chown "$(id -u):$(id -g)" "$OPT"; then
            sudo rmdir "$OPT" || true
            fail "cannot give $OPT to $(id -un)"
        fi
    fi
    ok "install folder $OPT"

    # everything is unpacked and checked here before anything in $OPT is touched
    WORK="$(mktemp -d "$OPT/.install.XXXXXX")" || fail "cannot create a work folder in $OPT"

    if [ "$HAVE_FROM" -eq 1 ]; then
        RELEASE="$FROM"
        RELEASE_NAME="${FROM##*/}"
        digest="$(sha256sum <"$RELEASE")" || fail "cannot read $RELEASE"
        ok "release file $RELEASE_NAME, SHA-256 ${digest%% *}"
    else
        curl -fsSL -o "$WORK/SHA256SUMS.txt" "$BASE/SHA256SUMS.txt" || fail "cannot download SHA256SUMS.txt from $BASE"
        sums_line="$(grep -e '-linux-x86_64\.tar\.gz$' "$WORK/SHA256SUMS.txt" || true)"
        case "$sums_line" in
            "") fail "SHA256SUMS.txt lists no release file" ;;
            *"
"*) fail "SHA256SUMS.txt lists more than one release file" ;;
        esac
        RELEASE_NAME="${sums_line#*  }"
        case "$RELEASE_NAME" in
            */* | *..*) fail "SHA256SUMS.txt names an unsafe file: $RELEASE_NAME" ;;
            pwn-broker-*-linux-x86_64.tar.gz) ;;
            *) fail "SHA256SUMS.txt names an unsafe file: $RELEASE_NAME" ;;
        esac
        RELEASE="$WORK/$RELEASE_NAME"
        curl -fsSL -o "$RELEASE" "$BASE/$RELEASE_NAME" || fail "cannot download $RELEASE_NAME from $BASE"
        (cd "$WORK" && printf '%s\n' "$sums_line" | sha256sum -c - >/dev/null 2>&1) || fail "checksum of $RELEASE_NAME does not match SHA256SUMS.txt. nothing was installed"
        ok "checksum verified for $RELEASE_NAME"
    fi

    # the file is read on stdin, so tar never takes its name for anything else
    not_release="$RELEASE_NAME is not a pwn-broker release file"
    mkdir "$WORK/release" || fail "cannot create a folder in $WORK"
    tar -xzf - --no-same-owner -C "$WORK/release" <"$RELEASE" >/dev/null 2>&1 || fail "$not_release"
    count=0
    top=""
    for entry in "$WORK/release"/* "$WORK/release"/.[!.]* "$WORK/release"/..?*; do
        if [ -e "$entry" ] || [ -L "$entry" ]; then
            count=$((count + 1))
            top="$entry"
        fi
    done
    if [ "$count" -ne 1 ] || [ ! -d "$top" ] || [ -L "$top" ]; then
        fail "$not_release"
    fi
    top_name="${top##*/}"
    case "$top_name" in
        pwn-broker-*) VERSION="${top_name#pwn-broker-}" ;;
        *) fail "$not_release" ;;
    esac
    case "$VERSION" in
        "" | *[!A-Za-z0-9.+-]*) fail "$not_release" ;;
    esac
    if [ ! -f "$top/python.tar.gz" ] || [ ! -f "$top/wheels.lock" ] || [ ! -d "$top/wheels" ] || [ ! -f "$top/asciinema" ]; then
        fail "$not_release"
    fi
    for part in python.tar.gz wheels.lock wheels asciinema; do
        if [ -L "$top/$part" ]; then
            fail "$not_release"
        fi
    done

    mkdir "$WORK/py" || fail "cannot create a folder in $WORK"
    tar -xzf - --no-same-owner -C "$WORK/py" <"$top/python.tar.gz" >/dev/null 2>&1 || fail "$not_release"
    # python/bin/python3 is a link upstream; the folders above it must be real
    for part in python python/bin; do
        if [ -L "$WORK/py/$part" ] || [ ! -d "$WORK/py/$part" ]; then
            fail "$not_release"
        fi
    done
    no_python="the Python in this release does not run on this machine. pwn-broker needs x86_64 Linux with glibc"
    "$WORK/py/python/bin/python3" -I -c 'import sys' >/dev/null 2>&1 || fail "$no_python"
    PY_VERSION="$("$WORK/py/python/bin/python3" -I -c 'import platform; print(platform.python_version())' 2>/dev/null)" || fail "$no_python"

    # only folders this installer made are moved aside: a Python holds bin/python3, an environment pyvenv.cfg
    if [ -e "$OPT/python" ] || [ -L "$OPT/python" ]; then
        if [ -L "$OPT/python" ] || [ ! -d "$OPT/python" ] || { [ ! -e "$OPT/python/bin/python3" ] && [ ! -L "$OPT/python/bin/python3" ]; }; then
            fail "$OPT/python exists and is not a pwn-broker Python. move it or choose another folder"
        fi
    fi
    if [ -e "$OPT/app" ] || [ -L "$OPT/app" ]; then
        if [ -L "$OPT/app" ] || [ ! -d "$OPT/app" ] || [ ! -f "$OPT/app/pyvenv.cfg" ]; then
            fail "$OPT/app exists and is not a pwn-broker environment. move it or choose another folder"
        fi
    fi

    # The previous python/ and app/ wait in the work folder until the install reaches the end;
    # finish puts them back if it does not. A rename inside $OPT is atomic.
    again="run the installer again"
    if [ -d "$OPT/app" ]; then
        mv "$OPT/app" "$WORK/old-app" || fail "cannot move $OPT/app aside. $again"
    fi
    if [ -d "$OPT/python" ]; then
        mv "$OPT/python" "$WORK/old-python" || fail "cannot move $OPT/python aside. $again"
    fi
    MADE_PYTHON=1
    mv "$WORK/py/python" "$OPT/python" || fail "cannot move the Python to $OPT/python. $again"
    ok "Python $PY_VERSION in $OPT/python"

    # an empty pyvenv.cfg first, so a half-made environment is known as this installer's own
    MADE_APP=1
    mkdir "$OPT/app" || fail "cannot create $OPT/app. $again"
    : >"$OPT/app/pyvenv.cfg" || fail "cannot write $OPT/app/pyvenv.cfg. $again"
    "$OPT/python/bin/python3" -I -m venv "$OPT/app" || fail "cannot create the virtual environment in $OPT/app. $again"
    ok "virtual environment created in $OPT/app"

    PIP_CONFIG_FILE=/dev/null "$OPT/app/bin/python" -I -m pip --isolated install --quiet --no-index --find-links "$top/wheels" --only-binary :all: --require-hashes -r "$top/wheels.lock" || fail "pip could not install the wheels in $RELEASE_NAME. $again"
    ok "pwn-broker $VERSION installed"

    cp "$top/asciinema" "$OPT/app/bin/asciinema" || fail "cannot copy asciinema to $OPT/app/bin/asciinema. $again"
    chmod 755 "$OPT/app/bin/asciinema" || fail "cannot make $OPT/app/bin/asciinema executable. $again"

    PWN_BROKER_OPT="$OPT"
    export PWN_BROKER_OPT
    "$OPT/app/bin/python" -I -m pwn_broker setup || fail "pwn-broker setup failed. $again"
    DONE=1
    ok "launcher and data written in $OPT"

    if [ "$HAVE_CONFIG" -eq 1 ]; then
        cp "$CONFIG" "$OPT/config.toml" || fail "cannot copy $CONFIG to $OPT/config.toml"
        ok "settings copied to $OPT/config.toml"
    fi

    if [ "$NO_PATH" -eq 0 ]; then
        add_path_line "$HOME/.zshrc"
        if [ -f "$HOME/.bashrc" ]; then
            add_path_line "$HOME/.bashrc"
        fi
    fi

    ok "open a new terminal, then run: pwn-broker"
}

main "$@"
