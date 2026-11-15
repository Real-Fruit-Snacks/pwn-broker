from pwn_broker import lifecycle
from pwn_broker.session import Session
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
    if box.status == "active" and session.console.confirm(
        f"export {box.name} before you go?", default=True
    ):
        lifecycle.export_box(session)
    raise Quit
