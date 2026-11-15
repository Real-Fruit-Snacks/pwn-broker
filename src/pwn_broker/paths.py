import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path

_UNSAFE = re.compile(r"[^a-z0-9.-]+")


@dataclass(frozen=True)
class AppPaths:
    opt: Path
    home: Path

    @property
    def run(self) -> Path:
        return self.opt / "run"

    @property
    def bin(self) -> Path:
        return self.opt / "bin"

    @property
    def config_file(self) -> Path:
        return self.opt / "config.toml"

    @property
    def state_file(self) -> Path:
        return self.opt / "state.toml"

    @property
    def templates(self) -> Path:
        return self.opt / "templates"

    @property
    def vim_dir(self) -> Path:
        return self.opt / "vim"

    @property
    def tools(self) -> Path:
        return self.opt / "tools"

    @property
    def upload(self) -> Path:
        return self.opt / "upload"

    @property
    def cache(self) -> Path:
        return self.opt / "cache"

    @property
    def tools_state(self) -> Path:
        return self.tools / "installed.toml"

    @property
    def run_box(self) -> Path:
        return self.run / "box"

    @property
    def run_tools(self) -> Path:
        return self.run / "tools"

    @property
    def active(self) -> Path:
        return self.home / "active"

    @property
    def wrapped(self) -> Path:
        return self.home / "wrapped"


def safe_name(text: str) -> str:
    name = _UNSAFE.sub("-", text.lower()).strip("-.")
    if not name:
        raise ValueError(f"nothing usable in {text!r}")
    return name


def box_folder_name(day: date, platform: str, name: str) -> str:
    return f"{day.isoformat()}_{safe_name(platform)}_{safe_name(name)}"
