from pwn_broker import search as finder
from pwn_broker.session import Session
from pwn_broker.shell.commands import ArgumentError, command


def _scope(session: Session, words: list[str]) -> tuple[str | None, str, str]:
    """(target or None for the whole box, the text, how the scope is named). A first word that is
    `all` or a target's exact name sets the scope when more follows; otherwise it is searched for."""
    names = {t.name for t in session.targets}
    if len(words) > 1 and words[0] == "all":
        return None, " ".join(words[1:]), "the box"
    if len(words) > 1 and words[0] in names:
        return words[0], " ".join(words[1:]), words[0]
    if session.current is None:
        raise ValueError("no target is selected; search all <text> searches the whole box")
    return session.current.name, " ".join(words), session.current.name


@command("search", "find text in the current target, a named one, or all of the box", "[all|<target>] <text>")
def search(session: Session, args: list[str]) -> None:
    if not args:
        raise ArgumentError("missing argument: text")
    target, text, where = _scope(session, args)
    found = finder.search(session.box.path, text, target)
    console = session.console
    if not found.hits:
        console.info(f"no hits for {text} in {where}")
    last = None
    for hit in found.hits:
        if hit.path != last:
            console.info(hit.path)
            last = hit.path
        console.detail(f"{hit.line:>5}  {hit.text}")
    if found.hits:
        total = len(found.hits) + found.more
        hits = "1 hit" if total == 1 else f"{total} hits"
        files = "1 file" if found.files == 1 else f"{found.files} files"
        console.info(f"{hits} in {files} in {where}")
    if found.more:
        console.info(f"the first {finder.MAX_HITS} are shown; narrow the search for the rest")
    if found.too_large:
        console.info(f"skipped as larger than 16 MiB: {', '.join(found.too_large)}")
