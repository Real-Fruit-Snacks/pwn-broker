from pwn_broker import lifecycle
from pwn_broker.recstate import windows
from pwn_broker.session import Session, recordings
from pwn_broker.shell.commands import Quit, command, take_args


@command("export", "write a snapshot archive and keep working")
def export(session: Session, args: list[str]) -> None:
    take_args(args)
    lifecycle.export_box(session)


@command("finish", "archive the box and close it")
def finish(session: Session, args: list[str]) -> None:
    take_args(args)
    if lifecycle.finish_box(session) is not None:
        raise Quit


@command("quit", "leave the shell")
def quit_shell(session: Session, args: list[str]) -> None:
    take_args(args)
    box = session.box
    console = session.console
    live = len(recordings(session))
    if live:
        # nothing stops them: each keeps recording into the box after the prompt is gone
        console.warn(f"{windows(live)} still recording for this box")
    if box.status == "active" and console.confirm(f"export {box.name} before you go?", default=True):
        exported = lifecycle.export_box(session, strict_copy=True)
        if exported is None and not console.confirm("the export failed. quit anyway?"):
            return
    raise Quit
