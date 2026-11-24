from pathlib import Path

import pytest

from pwn_broker import config
from pwn_broker.config import (
    ConfigError,
    Settings,
    State,
    load,
    load_state,
    platform_default,
    save_state,
)


def test_default_install_root_without_reading_it(tmp_path, monkeypatch):
    read = []
    monkeypatch.setattr(config, "_read_toml", lambda path: read.append(path) or {})
    paths, _ = load({}, home_dir=tmp_path)
    assert paths.opt == Path("/opt/pwn-broker")
    assert read == [Path("/opt/pwn-broker/config.toml")]


def test_an_empty_install_root_is_the_default(tmp_path, monkeypatch):
    # PWN_BROKER_OPT="" is "not set", as an empty PWN_BROKER_HOME is, never the current folder
    monkeypatch.setattr(config, "_read_toml", lambda path: {})
    paths, _ = load({"PWN_BROKER_OPT": ""}, home_dir=tmp_path)
    assert paths.opt == Path("/opt/pwn-broker")


@pytest.mark.parametrize("key", ["home", "copy_to"])
def test_a_relative_folder_in_config_is_refused(tmp_path, key):
    # the note window, serve, scan and record each run from another folder: a relative one would
    # name a different place in each
    opt = tmp_path / "opt"
    opt.mkdir()
    (opt / "config.toml").write_text(f'{key} = "pwn-work"\n', encoding="utf-8")
    with pytest.raises(ConfigError, match=f"{key} must be a whole path"):
        load({"PWN_BROKER_OPT": str(opt)}, home_dir=tmp_path)


@pytest.mark.parametrize("variable", ["PWN_BROKER_HOME", "PWN_BROKER_OPT"])
def test_a_relative_folder_in_the_environment_is_refused(tmp_path, variable):
    env = {"PWN_BROKER_OPT": str(tmp_path / "opt"), variable: "pwn-work"}
    with pytest.raises(ConfigError, match=f"{variable} must be a whole path"):
        load(env, home_dir=tmp_path)


def test_defaults(tmp_path):
    paths, settings = load({"PWN_BROKER_OPT": str(tmp_path / "opt")}, home_dir=tmp_path)
    assert paths.home == tmp_path / "pwn-broker"
    assert paths.active == paths.home / "active" and paths.wrapped == paths.home / "wrapped"
    assert settings == Settings()


@pytest.mark.parametrize("key", ["home", "copy_to"])
def test_empty_path_setting_means_not_set(tmp_path, key):
    opt = tmp_path / "opt"
    opt.mkdir()
    (opt / "config.toml").write_text(f'{key} = ""\n')
    env = {"PWN_BROKER_OPT": str(opt), "PWN_BROKER_HOME": str(tmp_path / "h")}
    paths, settings = load(env, home_dir=tmp_path)
    assert getattr(settings, key) is None
    assert paths.home == tmp_path / "h"


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
    env = {"PWN_BROKER_OPT": str(tmp_path / "opt"), "PWN_BROKER_HOME": str(tmp_path / "h")}
    paths, _ = load(env, home_dir=tmp_path)
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


def _settings_for(tmp_path, text):
    opt = tmp_path / "opt"
    opt.mkdir(exist_ok=True)
    (opt / "config.toml").write_text(text)
    return load({"PWN_BROKER_OPT": str(opt)}, home_dir=tmp_path)[1]


def test_tools_index_default_and_constant(tmp_path):
    assert Settings().tools_index is None
    assert config.DEFAULT_TOOLS_INDEX.endswith("/releases/download/index/index.toml")
    assert _settings_for(tmp_path, "").tools_index is None


@pytest.mark.parametrize("url", ["http://x.test/index.toml", "https://x.test/i.toml"])
def test_tools_index_url_kept(tmp_path, url):
    assert _settings_for(tmp_path, f'tools_index = "{url}"\n').tools_index == url


def test_tools_index_folder_expands_home(tmp_path):
    got = _settings_for(tmp_path, 'tools_index = "~/shop"\n').tools_index
    assert got == str(tmp_path / "shop")
    assert _settings_for(tmp_path, 'tools_index = "/srv/shop"\n').tools_index == str(
        Path("/srv/shop")
    )


def test_tools_index_empty_means_not_set(tmp_path):
    assert _settings_for(tmp_path, 'tools_index = ""\n').tools_index is None


def test_tools_index_wrong_type(tmp_path):
    with pytest.raises(ConfigError, match="config.toml"):
        _settings_for(tmp_path, "tools_index = 3\n")


def test_state_round_trip_with_vpn_file(tmp_path):
    f = tmp_path / "state.toml"
    for state in (State("thm", "lab.ovpn"), State(None, "lab.ovpn"), State("thm"), State()):
        save_state(f, state)
        assert load_state(f) == state


def test_state_ignores_a_vpn_file_of_the_wrong_type(tmp_path):
    f = tmp_path / "state.toml"
    f.write_text('last_vpn_file = 3\nlast_platform = "htb"\n')
    assert load_state(f) == State("htb", None)


def test_playbooks_setting_is_unset_true_or_false(tmp_path):
    assert Settings().playbooks is None
    assert _settings_for(tmp_path, "").playbooks is None
    assert _settings_for(tmp_path, "playbooks = true\n").playbooks is True
    assert _settings_for(tmp_path, "playbooks = false\n").playbooks is False


def test_playbooks_setting_wrong_type(tmp_path):
    with pytest.raises(ConfigError, match="config.toml: playbooks must be a bool"):
        _settings_for(tmp_path, 'playbooks = "yes"\n')


def test_state_round_trip_with_the_playbooks_answer(tmp_path):
    f = tmp_path / "state.toml"
    for state in (
        State("thm", "lab.ovpn", True),
        State(None, None, False),
        State("htb", new_box_playbooks=True),
        State(),
    ):
        save_state(f, state)
        assert load_state(f) == state


def test_state_ignores_a_playbooks_answer_of_the_wrong_type(tmp_path):
    f = tmp_path / "state.toml"
    f.write_text('new_box_playbooks = "yes"\nlast_platform = "htb"\n')
    assert load_state(f) == State("htb")


def test_report_setting_is_unset_true_or_false(tmp_path):
    assert Settings().report is None
    assert _settings_for(tmp_path, "").report is None
    assert _settings_for(tmp_path, "report = true\n").report is True
    assert _settings_for(tmp_path, "report = false\n").report is False


def test_report_setting_wrong_type(tmp_path):
    with pytest.raises(ConfigError, match="config.toml: report must be a bool"):
        _settings_for(tmp_path, 'report = "yes"\n')


def test_state_round_trip_with_the_report_answer(tmp_path):
    f = tmp_path / "state.toml"
    for state in (
        State("thm", "lab.ovpn", True, False),
        State("htb", new_box_report=True),
        State(None, None, None, False),
    ):
        save_state(f, state)
        assert load_state(f) == state


def test_state_ignores_a_report_answer_of_the_wrong_type(tmp_path):
    f = tmp_path / "state.toml"
    f.write_text('new_box_report = "yes"\nlast_platform = "htb"\n')
    assert load_state(f) == State("htb")
