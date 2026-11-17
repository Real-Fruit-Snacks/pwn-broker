from pwn_broker import casttext, hostflow, lifecycle, vpnctl
from pwn_broker.console import Cancelled
from pwn_broker.recstate import windows
from pwn_broker.session import Session, current_tunnel, recordings, vpn_checks
from pwn_broker.shell import cmd_vpn


def recording_block(session: Session) -> str | None:
    """finish waits for every window recording into the box: what it records later would be lost."""
    found = recordings(session)
    if not found:
        return None
    names = ", ".join(sorted({r.target for r in found}))
    them = "it" if len(found) == 1 else "them"
    return f"{windows(len(found))} still recording ({names}). exit {them}, then finish again"


def recordings_pre_pack(session: Session) -> None:
    """Before packing, warn about windows still recording and write the missing text copies.

    At finish no window is recording (recording_block), so the warning is only ever an export's.
    """
    count = len(recordings(session))
    if count:
        them = "it" if count == 1 else "them"
        session.console.warn(f"{windows(count)} still recording; the export holds {them} up to now")
    casttext.refresh(session.box, session.console, tz=session.clock().tzinfo)


def vpn_question(session: Session) -> None:
    """At finish, offer to stop the app's VPN; the default keeps it for the next box.

    It never raises: a failed undo step would keep the working folder.
    """
    console = session.console
    try:
        marker = vpnctl.ours(session.paths, **vpn_checks(session))
        if marker is None:
            return
        found = current_tunnel(session, fresh=True)
        up = f"up ({found.address})" if found else "running"
        if console.confirm(f"the VPN is still {up}. stop it?", default=False):
            cmd_vpn.stop(session, marker)
    except Cancelled:
        console.warn("the VPN was left running")
    except vpnctl.VpnError as exc:
        console.warn(str(exc))
    except Exception as exc:
        console.warn(f"could not stop the VPN: {exc}")


def register() -> None:
    for hooks, hook in (
        (lifecycle.BLOCK_HOOKS, recording_block),
        (lifecycle.PRE_PACK_HOOKS, recordings_pre_pack),
        (lifecycle.SUMMARY_HOOKS, hostflow.summary),
        (lifecycle.UNDO_HOOKS, hostflow.undo),
        (lifecycle.UNDO_HOOKS, vpn_question),
        (lifecycle.IMPORT_HOOKS, hostflow.on_import),
    ):
        if hook not in hooks:
            hooks.append(hook)
