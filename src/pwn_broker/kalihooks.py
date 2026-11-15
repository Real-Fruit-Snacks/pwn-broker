from pwn_broker import hostflow, lifecycle


def register() -> None:
    for hooks, hook in (
        (lifecycle.SUMMARY_HOOKS, hostflow.summary),
        (lifecycle.UNDO_HOOKS, hostflow.undo),
    ):
        if hook not in hooks:
            hooks.append(hook)
