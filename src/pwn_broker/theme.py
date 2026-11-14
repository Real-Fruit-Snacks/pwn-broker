from collections.abc import Mapping

from prompt_toolkit.styles import Style

EMBER = "#FF6A3D"
TEXT = "#E8E6E1"
MINT = "#3DDC97"
AMBER = "#FFC247"
RASPBERRY = "#F06292"
MUTE = "#8A8F99"


def color_enabled(env: Mapping[str, str]) -> bool:
    return not env.get("NO_COLOR")


def prompt_style() -> Style:
    return Style.from_dict(
        {
            "prompt": f"{EMBER} bold",
            "toolbar": MUTE,
            "suggestion": MUTE,
        }
    )
