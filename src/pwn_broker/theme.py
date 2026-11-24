from collections.abc import Mapping

from prompt_toolkit.styles import Style

EMBER = "#FF9254"
TEXT = "#F2F4F8"
MINT = "#3DDC97"
AMBER = "#FFC247"
FAULT = "#FF5C6C"
RASPBERRY = FAULT
MUTE = "#8F95A6"


def color_enabled(env: Mapping[str, str]) -> bool:
    return not env.get("NO_COLOR")


def prompt_style() -> Style:
    return Style.from_dict(
        {
            "prompt": f"{EMBER} bold",
            # questions asked by commands: only the shell prompt is Beacon Orange
            "question": MUTE,
            "answer": TEXT,
            "toolbar": MUTE,
            # the default bottom-toolbar style is reverse video
            "bottom-toolbar": f"noreverse {MUTE} bg:default",
            "suggestion": MUTE,
        }
    )
