from pathlib import Path

import pytest

from pwn_broker.config import (
    ConfigError,
    Settings,
    State,
    load,
    load_state,
    platform_default,
    save_state,
)


def test_defaults(tmp_path):
    paths, settings = load({}, home_dir=tmp_path)
    assert paths.opt == Path("/opt/pwn-broker")
    assert paths.home == tmp_path / "pwn-broker"
    assert paths.active == paths.home / "active" and paths.wrapped == paths.home / "wrapped"
    assert settings == Settings()


def test_config_file_overrides(tmp_path):
    opt = tmp_path / "opt"
    opt.mkdir()
    (opt / "config.toml").write_text(
        'home = "~/boxes"\ncopy_to = "/mnt/share"\ndefault_platform = "thm"\n'
    )
    paths, settings = load({"PWN_BROKER_OPT": str(opt)}, home_dir=tmp_path)
    assert paths.home == tmp_path / "boxes"
    assert settings.copy_to == Path("/mnt/share") and settings.default_platform == "thm"


def test_env_home_override(tmp_path):
    paths, _ = load({"PWN_BROKER_HOME": str(tmp_path / "h")}, home_dir=tmp_path)
    assert paths.home == tmp_path / "h"


def test_config_home_beats_env(tmp_path):
    opt = tmp_path / "opt"
    opt.mkdir()
    (opt / "config.toml").write_text('home = "~/boxes"\n')
    env = {"PWN_BROKER_OPT": str(opt), "PWN_BROKER_HOME": str(tmp_path / "h")}
    paths, _ = load(env, home_dir=tmp_path)
    assert paths.home == tmp_path / "boxes"


def test_unknown_config_keys_ignored(tmp_path):
    opt = tmp_path / "opt"
    opt.mkdir()
    (opt / "config.toml").write_text('mystery = 1\nterminal = "xterm"\n')
    _, settings = load({"PWN_BROKER_OPT": str(opt)}, home_dir=tmp_path)
    assert settings == Settings(terminal="xterm")


def test_bad_config_names_the_file(tmp_path):
    opt = tmp_path / "opt"
    opt.mkdir()
    (opt / "config.toml").write_text("home = [")
    with pytest.raises(ConfigError, match="config.toml"):
        load({"PWN_BROKER_OPT": str(opt)}, home_dir=tmp_path)


def test_paths_properties(tmp_path):
    paths, _ = load({"PWN_BROKER_OPT": str(tmp_path / "o")}, home_dir=tmp_path)
    o = tmp_path / "o"
    assert paths.run == o / "run" and paths.bin == o / "bin"
    assert paths.config_file == o / "config.toml" and paths.state_file == o / "state.toml"
    assert paths.templates == o / "templates" and paths.vim_dir == o / "vim"


def test_platform_default_order():
    assert platform_default(State("thm"), Settings(default_platform="pg")) == "thm"
    assert platform_default(State(None), Settings(default_platform="pg")) == "pg"
    assert platform_default(State(None), Settings()) == "htb"


def test_state_missing_or_corrupt_is_empty(tmp_path):
    assert load_state(tmp_path / "state.toml") == State()
    (tmp_path / "state.toml").write_text("last_platform = [")
    assert load_state(tmp_path / "state.toml") == State()


def test_state_round_trip(tmp_path):
    save_state(tmp_path / "state.toml", State("thm"))
    assert load_state(tmp_path / "state.toml") == State("thm")
