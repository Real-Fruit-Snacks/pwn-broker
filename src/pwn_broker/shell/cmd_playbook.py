from pwn_broker import playbooks, toolstate
from pwn_broker.playbooks import Playbook
from pwn_broker.session import Session
from pwn_broker.shell.commands import command, take_args

NONE_INSTALLED = "no playbooks for this box: tool install playbooks gets them"


def box_playbooks(session: Session) -> list[Playbook]:
    """Every playbook installed for the open box, from the folders :Pb reads."""
    installed = toolstate.load_installed(session.paths)
    return playbooks.installed(toolstate.notes_packages(installed, session.box))


def _packages(found: list[Playbook]) -> str:
    named = sorted({(p.package, p.version) for p in found})
    return " and ".join(f"{name} {version}" for name, version in named)


@command("playbook list", "list this box's playbooks; words narrow the list", "[<word>...]")
def playbook_list(session: Session, args: list[str]) -> None:
    console = session.console
    found = box_playbooks(session)
    if not found:
        console.info(NONE_INSTALLED)
        return
    titles = {p.file: playbooks.title(playbooks.read_lines(p.file)) for p in found}
    # every word in the name, the folder or the title, in any case, as tool search matches
    wanted = [w.lower() for w in args]
    listed = [p for p in found if all(w in f"{p.rel} {titles[p.file]}".lower() for w in wanted)]
    if not listed:
        console.info(f"no playbooks match {' '.join(args)}")
        return
    # a package column only when two packages could hold the same name
    several = len({p.package for p in found}) > 1
    columns = ["name", *(["package"] if several else []), "folder", "title"]
    rows = [
        [p.name, *([p.package] if several else []), p.rel.rpartition("/")[0], titles[p.file]]
        for p in listed
    ]
    console.table(columns, rows, cut="title")
    count = f"{len(listed)} of {len(found)}" if args else f"{len(found)}"
    noun = "playbook" if len(found) == 1 else "playbooks"
    console.info(f"{count} {noun} in {_packages(found)}; playbook show <name> prints one")


@command("playbook show", "print one of this box's playbooks, without its run block", "<name>")
def playbook_show(session: Session, args: list[str]) -> None:
    (wanted,) = take_args(args, required=("playbook name",))
    found = box_playbooks(session)
    if not found:
        raise ValueError(NONE_INSTALLED)
    matches = playbooks.find(found, wanted)
    if not matches:
        raise ValueError(f"no playbook named {wanted}; playbook list shows them")
    if len(matches) > 1:
        each = ", ".join(f"{p.package}/{p.rel}" for p in matches)
        raise ValueError(f"{wanted} is in more than one package; give one of {each}")
    pick = matches[0]
    line, body = playbooks.shown(playbooks.read_lines(pick.file))
    console = session.console
    console.heading(line if line is not None else pick.rel)
    console.gap()
    # flush left so its commands copy cleanly; it is a package's text, so log, which writes each
    # control character as "?", not raw
    for text in body:
        console.log(text)


def names(session: Session) -> list[str]:
    """The names playbook show takes, for completion: only what is on disk."""
    return sorted({p.name for p in box_playbooks(session)})
