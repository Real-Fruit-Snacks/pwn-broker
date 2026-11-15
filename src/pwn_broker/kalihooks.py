from pwn_broker import hostflow, lifecycle, vpnctl
from pwn_broker.console import Cancelled
from pwn_broker.session import Session, current_tunnel, vpn_checks
from pwn_broker.shell import cmd_vpn


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
        (lifecycle.SUMMARY_HOOKS, hostflow.summary),
        (lifecycle.UNDO_HOOKS, hostflow.undo),
        (lifecycle.UNDO_HOOKS, vpn_question),
    ):
        if hook not in hooks:
            hooks.append(hook)
