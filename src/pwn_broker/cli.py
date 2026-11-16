import os
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from pwn_broker import __version__, boxes, checks, config, lifecycle, note, notewindow, privilege
from pwn_broker import hostflow, hosts, kalihooks, questions, recorder, session as sessions, setup
from pwn_broker import targetflow, toolhooks, vpn
from pwn_broker.boxes import BoxError
from pwn_broker.config import ConfigError, Settings
from pwn_broker.console import INDENT, Cancelled, Console, TermConsole
from pwn_broker.model import Box, Target
from pwn_broker.note import NoteError
from pwn_broker.paths import AppPaths
from pwn_broker.session import Session
from pwn_broker.shell.app import run_shell
from pwn_broker.store import StoreError, load_box

NO_ARCHIVE = "give the path of an exported box"
SUBCOMMANDS = ("new", "import", "resume")
HELP = (
    "pwn-broker                 open the menu, or the box you are inside",
    "pwn-broker new             start a new box",
    "pwn-broker import <file>   unpack an exported box",
    "pwn-broker resume [name]   reopen an active box",
)


@dataclass
class Env:
    paths: AppPaths
    settings: Settings
    console: Console
    clock: Callable[[], datetime]
    environ: Mapping[str, str]
    cwd: Path
    pid: int
    home: Path
    run: Callable[[Session], None] = run_shell
    # what the launch and its sessions reach /etc/hosts through; tests give each Env stand-ins
    hosts_path: Path = hosts.DEFAULT_PATH
    is_root: Callable[[], bool] = privilege.is_root
    run_privileged: Callable = privilege.run_privileged
    tunnel: Callable[[], vpn.Tunnel | None] = vpn.tunnel


def _load(env: Env, box: Box) -> Session:
    session = sessions.load_session(env.paths, env.settings, env.console, box, env.clock)
    session.hosts_path = env.hosts_path
    session.is_root = env.is_root
    session.run_privileged = env.run_privileged
    session.tunnel = env.tunnel
    return session


def new_box(env: Env) -> Session:
    console = env.console
    state = config.load_state(env.paths.state_file)
    answers = questions.ask_box(
        console,
        default_platform=config.platform_default(state, env.settings),
        today=env.clock().date(),
    )
    box = boxes.create_box(
        env.paths,
        name=answers.name,
        platform=answers.platform,
        day=answers.day,
        os_name=answers.os_name,
        difficulty=answers.difficulty,
        now=env.clock(),
    )
    targets: list[Target] = []
    try:
        adding = console.confirm("add a target?", default=True)
        while adding:
            given = questions.ask_target(
                console, heading=f"Target {len(targets) + 1}", taken={t.name for t in targets}
            )
            try:
                target = boxes.add_target(
                    box,
                    targets,
                    ips=given.ips,
                    hostnames=given.hostnames,
                    scope=given.scope,
                    name=given.name,
                    now=env.clock(),
                )
            except (BoxError, OSError, ValueError) as exc:
                console.fail(f"could not add the target: {exc}")
            else:
                console.ok(f"target {target.name} created")
            adding = console.confirm("add another?", default=False)
    except Cancelled:
        # the box exists on disk already; keep it and what was added
        pass

    try:
        sessions.write_new_note(env.paths, box, targets)
    except (OSError, NoteError, StoreError) as exc:
        console.warn(f"the note could not be written: {exc}")
    try:
        session = _load(env, box)
        # the clock may not tick between targets, so keep the order they were typed in
        session.targets = targets
        sessions.set_current(session, targets[0] if targets else None)
        sessions.refresh(session)
        config.save_state(env.paths.state_file, config.State(last_platform=answers.platform))
        for target in targets:
            targetflow.after_add(session, target)
    except (StoreError, OSError) as exc:
        # the box, its note and its targets are on disk and can be resumed
        raise BoxError(f"box {box.path.name} was created but not finished: {exc}") from exc
    console.ok(f"box {box.name} created")
    return session


def _date(value: datetime) -> str:
    return value.strftime("%Y-%m-%d")


def choose(env: Env) -> Session | None:
    console = env.console
    found, problems = boxes.list_boxes(env.paths)
    for problem in problems:
        console.warn(problem)

    entries: list[tuple[str, Box | None]] = [("new", None), ("import", None)]
    console.heading("Boxes")
    console.info("1  new box")
    console.info("2  import a box from a file")
    for box in (b for b in found if b.status == "active"):
        entries.append(("resume", box))
        console.info(
            f"{len(entries)}  resume {box.name} ({box.platform}, started {_date(box.started)})"
        )
    for box in (b for b in found if b.status == "finished"):
        entries.append(("reopen", box))
        shown = box.finished or box.started
        console.info(
            f"{len(entries)}  reopen {box.name} ({box.platform}, finished {_date(shown)})"
        )

    console.gap()
    while True:
        answer = console.ask("choice")
        if answer.isdecimal() and 1 <= int(answer) <= len(entries):
            break
        console.fail(f"choose a number from 1 to {len(entries)}")
    console.gap()

    kind, box = entries[int(answer) - 1]
    if kind == "new":
        return new_box(env)
    if kind == "import":
        while True:
            given = console.ask("file")
            if given != "":
                break
            console.fail(NO_ARCHIVE)
        return _import(env, Path(given).expanduser())
    assert box is not None
    if kind == "reopen":
        lifecycle.reopen_box(box)
        session = _load(env, box)
        for hook in lifecycle.RESTORE_HOOKS:
            hook(session)
        return session
    return _load(env, box)


def _import(env: Env, archive: Path) -> Session | None:
    box = lifecycle.import_box(env.paths, env.settings, env.console, archive, env.clock)
    return None if box is None else _load(env, box)


def box_for_cwd(env: Env) -> Box | None:
    try:
        relative = env.cwd.resolve().relative_to(env.paths.active.resolve())
        if not relative.parts:
            return None
        box = load_box(env.paths.active / relative.parts[0])
    except (ValueError, OSError, StoreError):
        return None
    return box if box.status == "active" else None


def _resume(env: Env, name: str | None) -> Session | None:
    found, problems = boxes.list_boxes(env.paths)
    for problem in problems:
        env.console.warn(problem)
    active = [b for b in found if b.status == "active"]
    if name is None:
        if len(active) == 1:
            return _load(env, active[0])
        env.console.fail(
            "no active boxes to resume" if not active else "more than one active box, name one"
        )
        return None
    for box in active:
        if name in (box.name, box.path.name):
            return _load(env, box)
    env.console.fail(f"no active box named {name}")
    return None


def _pick_session(env: Env, argv: list[str]) -> Session | None:
    if argv[:1] == ["new"]:
        return new_box(env)
    if argv[:1] == ["import"]:
        if argv[1] == "":
            env.console.fail(NO_ARCHIVE)
            return None
        return _import(env, Path(argv[1]).expanduser())
    if argv[:1] == ["resume"]:
        return _resume(env, argv[1] if len(argv) > 1 else None)
    here = box_for_cwd(env)
    if here is not None:
        return _load(env, here)
    return choose(env)


def _asciinema(env: Env) -> int:
    """Check the copy of asciinema the release carries; nothing is downloaded."""
    if recorder.present(env.paths):
        env.console.ok(f"asciinema {recorder.VERSION} in {env.paths.asciinema}")
        return 0
    env.console.fail(
        f"asciinema is missing from {env.paths.asciinema} or does not match its checksum. "
        "run the installer again"
    )
    return 1


def _usage(env: Env, argv: list[str]) -> int | None:
    console = env.console
    if argv == ["--version"]:
        console.raw(f"pwn-broker {__version__}")
        return 0
    if argv in (["--help"], ["-h"]):
        for line in HELP:
            console.raw(line)
        return 0
    if argv[:1] == ["setup"]:
        try:
            setup.install_data(env.paths)
            console.ok(f"data installed in {env.paths.opt}")
            launcher = setup.write_launcher(env.paths, Path(sys.executable))
            console.ok(f"launcher {launcher}")
        except OSError as exc:
            console.fail(str(exc))
            return 1
        return _asciinema(env)
    if argv and argv[0] not in SUBCOMMANDS:
        console.fail(f"unknown option {argv[0]}, see pwn-broker --help")
        return 2
    if argv[:1] == ["import"] and len(argv) < 2:
        console.fail("import needs a file: pwn-broker import <file>")
        return 2
    return None


def _prepare(env: Env) -> int | None:
    console = env.console
    owner = privilege.wrong_owner(env.paths.opt)
    if owner is not None:
        console.fail(f"pwn-broker was installed by {owner}; run it as {owner}")
        return 1

    if not (env.paths.vim_dir / "vimrc").exists():
        try:
            setup.install_data(env.paths)
        except OSError as exc:
            console.fail(f"cannot install pwn-broker data: {exc}")
            console.info("run the installer again to repair the install")
            return 1

    if not env.paths.record_launcher.exists():
        try:
            setup.write_launcher(env.paths, Path(sys.executable))
        except OSError as exc:
            console.warn(f"cannot write the record launcher: {exc}")

    results = checks.launch_checks(
        env.paths,
        env.settings,
        env.environ,
        env.home,
        include_version=False,
        tunnel=env.tunnel,
    )
    checks.report(console, results)
    if any(r.status == "fail" for r in results):
        return 1

    # another prompt may be half way through an install: its files are not leftovers
    if not _another_prompt(env):
        toolhooks.leftovers(env.paths, console)
        hostflow.leftovers(
            env.paths,
            console,
            hosts_path=env.hosts_path,
            is_root=env.is_root,
            run=env.run_privileged,
        )

    newer = checks.newer_release_within(env.settings)
    if newer is not None:
        console.warn(f"{newer.name}   {newer.message}")
    console.gap()
    return None


def _another_prompt(env: Env) -> bool:
    try:
        return boxes.open_box_folder(env.paths, alive=boxes.pid_alive) is not None
    except (BoxError, StoreError, OSError):
        # start reports the problem; nothing is swept on a guess
        return True


def start(env: Env, argv: list[str]) -> int:
    console = env.console
    done = _usage(env, argv)
    if done is not None:
        return done
    if argv[:1] != ["import"]:
        console.header(f"pwn-broker {__version__}")
    done = _prepare(env)
    if done is not None:
        return done

    try:
        busy = boxes.open_box_folder(env.paths, alive=boxes.pid_alive)
        if busy is not None:
            console.fail(f"{busy.name} is open in another prompt; quit that prompt first")
            return 1
        session = _pick_session(env, argv)
    except Cancelled:
        console.info("cancelled")
        return 0
    except (BoxError, StoreError, OSError) as exc:
        console.fail(f"could not open the box: {exc}")
        return 1
    if session is None:
        return 1

    try:
        boxes.acquire_open(env.paths, session.box, pid=env.pid)
    except BoxError as exc:
        console.fail(str(exc))
        return 1
    try:
        hostflow.on_open(session)
        if notewindow.find_note(env.paths, session.box) is not None:
            console.ok("the note is already open")
        elif not notewindow.open_note(env.paths, env.settings, session.box, env.environ):
            command = notewindow.vim_command(env.paths, session.box.path / note.NOTE_NAME)
            console.warn("no note window opened, run: " + " ".join(command))
        # one blank line between whatever the launch printed last and the first prompt
        console.gap()
        env.run(session)
    finally:
        boxes.release_open(env.paths, pid=env.pid)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    try:
        paths, settings = config.load(os.environ, Path.home())
    except ConfigError as exc:
        TermConsole(os.environ).fail(str(exc))
        return 1
    import pwn_broker.shell  # noqa: F401  (importing it fills the command registry)

    toolhooks.register()
    kalihooks.register()

    try:
        cwd = Path.cwd()
    except OSError:
        cwd = Path.home()
    env = Env(
        paths=paths,
        settings=settings,
        # setup runs inside the installer's output, which is flush left
        console=TermConsole(os.environ, indent="" if args[:1] == ["setup"] else INDENT),
        clock=lambda: datetime.now().astimezone(),
        environ=os.environ,
        cwd=cwd,
        pid=os.getpid(),
        home=Path.home(),
    )
    try:
        return start(env, args)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        env.console.fail(f"unexpected error: {type(exc).__name__}: {exc}")
        return 1
