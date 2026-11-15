#!/bin/sh
set -eu

# Everything runs from main, called on the last line, so a download cut short
# by `curl | sh` runs nothing.

usage_line() {
    echo "usage: install.sh [--from <path>] [--config <path>] [--no-path] [--no-asciinema] [--help]"
}

usage_full() {
    usage_line
    cat <<'HELP'

  --from <path>    install from a local folder or wheel instead of the latest release
  --config <path>  copy a settings file to config.toml
  --no-path        do not add /opt/pwn-broker/bin to PATH in ~/.zshrc and ~/.bashrc
  --no-asciinema   do not download asciinema; record and replay will not work
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

main() {
    BASE="https://github.com/Real-Fruit-Snacks/pwn-broker/releases/latest/download"
    FROM=""
    CONFIG=""
    NO_PATH=0
    NO_ASCIINEMA=0
    HAVE_FROM=0
    HAVE_CONFIG=0
    TMP=""

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
            --no-asciinema)
                NO_ASCIINEMA=1
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

    trap 'if [ -n "$TMP" ]; then rm -rf "$TMP"; fi' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM

    if [ "$HAVE_FROM" -eq 1 ]; then
        [ -e "$FROM" ] || fail "$FROM does not exist"
        # A bare name would be read by pip as a package on PyPI.
        case "$FROM" in
            /*) ;;
            *) FROM="./$FROM" ;;
        esac
    fi
    if [ "$HAVE_CONFIG" -eq 1 ]; then
        [ -f "$CONFIG" ] || fail "$CONFIG does not exist"
    fi

    need python3 python3
    if [ "$HAVE_FROM" -eq 0 ]; then
        need curl curl
        need sha256sum coreutils
    fi

    python3 -m venv --help >/dev/null 2>&1 || fail "python3 cannot create virtual environments. run: apt install python3-venv"
    python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' || fail "python3 is older than 3.11. pwn-broker needs 3.11 or later"
    ok "python3 and venv present"

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

    if [ -x "$OPT/app/bin/python" ] && "$OPT/app/bin/python" -m pip --version >/dev/null 2>&1; then
        ok "virtual environment reused in $OPT/app"
    else
        # only a folder that is a virtual environment is ours to replace
        if [ -f "$OPT/app/pyvenv.cfg" ]; then
            rm -rf "$OPT/app"
        elif [ -e "$OPT/app" ] || [ -L "$OPT/app" ]; then
            fail "$OPT/app exists and is not a pwn-broker environment. move it or choose another folder"
        fi
        APP_CREATED=0
        if [ ! -e "$OPT/app" ]; then APP_CREATED=1; fi
        if ! python3 -m venv "$OPT/app"; then
            if [ "$APP_CREATED" -eq 1 ]; then
                rm -rf "$OPT/app"
            fi
            fail "cannot create the virtual environment in $OPT/app. try: apt install python3-venv"
        fi
        ok "virtual environment created in $OPT/app"
    fi

    if [ "$HAVE_FROM" -eq 1 ]; then
        TARGET="$FROM"
    else
        TMP="$(mktemp -d)" || fail "cannot create a temporary folder"
        curl -fsSL -o "$TMP/SHA256SUMS.txt" "$BASE/SHA256SUMS.txt" || fail "cannot download SHA256SUMS.txt from $BASE"
        sums_line="$(grep '\.whl$' "$TMP/SHA256SUMS.txt" || true)"
        case "$sums_line" in
            "") fail "SHA256SUMS.txt lists no wheel" ;;
            *"
"*) fail "SHA256SUMS.txt lists more than one wheel" ;;
        esac
        wheel="${sums_line#*  }"
        case "$wheel" in
            */* | *..*) fail "SHA256SUMS.txt names an unsafe file: $wheel" ;;
        esac
        curl -fsSL -o "$TMP/$wheel" "$BASE/$wheel" || fail "cannot download $wheel from $BASE"
        (cd "$TMP" && printf '%s\n' "$sums_line" | sha256sum -c - >/dev/null 2>&1) || fail "checksum of $wheel does not match SHA256SUMS.txt. nothing was installed"
        ok "checksum verified for $wheel"
        TARGET="$TMP/$wheel"
    fi

    "$OPT/app/bin/python" -m pip install --quiet --upgrade "$TARGET" || fail "pip could not install $TARGET"
    ok "pwn-broker installed"

    PWN_BROKER_OPT="$OPT"
    export PWN_BROKER_OPT
    if [ "$NO_ASCIINEMA" -eq 1 ]; then
        PWN_BROKER_SKIP_ASCIINEMA=1
        export PWN_BROKER_SKIP_ASCIINEMA
    fi
    "$OPT/app/bin/python" -m pwn_broker setup || fail "pwn-broker setup failed"
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
