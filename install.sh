#!/bin/sh
set -eu

BASE="https://github.com/Real-Fruit-Snacks/pwn-broker/releases/latest/download"
USAGE="usage: install.sh [--from <path>] [--config <path>] [--no-path] [--help]"

FROM=""
CONFIG=""
NO_PATH=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --from)
            [ "$#" -ge 2 ] || { echo "$USAGE" >&2; exit 2; }
            FROM="$2"
            shift 2
            ;;
        --config)
            [ "$#" -ge 2 ] || { echo "$USAGE" >&2; exit 2; }
            CONFIG="$2"
            shift 2
            ;;
        --no-path)
            NO_PATH=1
            shift
            ;;
        --help)
            cat <<'HELP'
usage: install.sh [--from <path>] [--config <path>] [--no-path] [--help]

  --from <path>    install from a local folder or wheel instead of the latest release
  --config <path>  copy a settings file to config.toml
  --no-path        do not add /opt/pwn-broker/bin to PATH in ~/.zshrc and ~/.bashrc
  --help           show this text

PWN_BROKER_OPT sets the install folder (default /opt/pwn-broker).
HELP
            exit 0
            ;;
        *)
            echo "$USAGE" >&2
            exit 2
            ;;
    esac
done

OPT="${PWN_BROKER_OPT:-/opt/pwn-broker}"
TMP=""
trap 'if [ -n "$TMP" ]; then rm -rf "$TMP"; fi' EXIT

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

need python3 python3
if [ -z "$FROM" ]; then
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
else
    if ! mkdir -p "$OPT" 2>/dev/null; then
        sudo mkdir -p "$OPT" || fail "cannot create $OPT"
        sudo chown "$(id -u):$(id -g)" "$OPT" || fail "cannot give $OPT to $(id -un)"
    fi
fi
ok "install folder $OPT"

if [ ! -x "$OPT/app/bin/python" ]; then
    python3 -m venv "$OPT/app" || fail "cannot create the virtual environment in $OPT/app. try: apt install python3-venv"
    ok "virtual environment created in $OPT/app"
else
    ok "virtual environment reused in $OPT/app"
fi

if [ -n "$FROM" ]; then
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
"$OPT/app/bin/python" -m pwn_broker setup >/dev/null || fail "pwn-broker setup failed"
ok "launcher and data written in $OPT"

if [ -n "$CONFIG" ]; then
    [ -f "$CONFIG" ] || fail "$CONFIG does not exist"
    cp "$CONFIG" "$OPT/config.toml" || fail "cannot copy $CONFIG to $OPT/config.toml"
    ok "settings copied to $OPT/config.toml"
fi

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
    printf 'export PATH="%s/bin:$PATH"  # pwn-broker\n' "$OPT" >>"$rc"
    ok "PATH line added to $rc"
}

if [ "$NO_PATH" -eq 0 ]; then
    add_path_line "$HOME/.zshrc"
    if [ -f "$HOME/.bashrc" ]; then
        add_path_line "$HOME/.bashrc"
    fi
fi

ok "open a new terminal, then run: pwn-broker"
