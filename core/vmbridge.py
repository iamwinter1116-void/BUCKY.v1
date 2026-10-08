"""BUCKY vmbridge — Windows↔Kali VM execution core.

Every quirk encoded here was learned LIVE during a 181-cycle bug-bounty
campaign (Oct 2026); none of this is theoretical:

- VM dead → all remote tools die together → ``ensure_vm()`` auto-boots and
  waits for sshd (~90 s) so lanes never hit a cold VM.
- remote zsh expands ``=word=`` → markers use ``FRG<hex>`` tokens, never
  ``===`` separators.
- leftover test-server ports block binds → ``port_free()`` fuser-k hygiene.
- the operator watches every long command live → ``shadow_run()`` executes
  inside the guest's ``shadow`` tmux session (visible via ``tmux attach -t shadow``).

Security: commands are executed over SSH with a dedicated key; output is
marker-sliced so ssh-banner noise can never be confused with command output.
"""
from __future__ import annotations

import secrets
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .config import Config, VMConfig, load_config

_CFG: Config | None = None


def _cfg() -> Config:
    """Lazily load and cache config (import-time disk reads break tests)."""
    global _CFG
    if _CFG is None:
        _CFG = load_config()
    return _CFG


@dataclass(frozen=True)
class CmdResult:
    """Result of a remote command: real exit code + sliced clean output."""
    ok: bool
    exit: int | None
    output: str
    stderr: str = ""
    live: bool = False


def _ssh_base(vm: VMConfig) -> list[str]:
    return [
        "ssh", "-i", str(vm.key_path), "-p", str(vm.port),
        "-o", "ConnectTimeout=15", "-o", "BatchMode=yes",
        vm.ssh_target,
    ]


def _scp_base(vm: VMConfig) -> list[str]:
    return [
        "scp", "-i", str(vm.key_path), "-P", str(vm.port),
        "-o", "ConnectTimeout=15", "-o", "BatchMode=yes",
    ]


# ---------------------------------------------------------------- VM lifecycle
def vm_running(vm: VMConfig | None = None) -> bool:
    """True if the Kali VM is powered on (host-side VBoxManage check)."""
    vm = vm or _cfg().vm
    try:
        r = subprocess.run(
            [vm.vboxmanage, "list", "runningvms"],
            capture_output=True, text=True, timeout=30,
        )
        return vm.name in r.stdout
    except (OSError, subprocess.SubprocessError):
        return False


def boot_vm(vm: VMConfig | None = None, wait_s: int = 95) -> tuple[bool, str]:
    """Boot the VM headless and block until sshd answers.

    Args:
        vm: VM settings (defaults to config).
        wait_s: max seconds to wait for sshd (default 95 — measured boot time
            for this image is ~90 s including autologin + sshd).

    Returns:
        ``(ok, message)`` — message is human-readable either way.
    """
    vm = vm or _cfg().vm
    if vm_running(vm):
        return True, "already running"
    subprocess.run(
        [vm.vboxmanage, "startvm", vm.name, "--type", "headless"],
        capture_output=True, text=True, timeout=120,
    )
    t0 = time.time()
    while time.time() - t0 < wait_s:
        r = subprocess.run(_ssh_base(vm) + ["echo OK"],
                           capture_output=True, text=True, timeout=25)
        if r.returncode == 0 and "OK" in r.stdout:
            return True, f"booted in {int(time.time() - t0)}s"
        time.sleep(8)
    return False, "boot timeout — check VBoxManage console"


def ensure_vm() -> tuple[bool, str]:
    """Guarantee the VM is up before any remote op. Boots if dead."""
    vm = _cfg().vm
    if vm_running(vm):
        return True, "running"
    return boot_vm(vm)


# ---------------------------------------------------------------- remote exec
def _marker() -> str:
    return "FRG" + secrets.token_hex(4)


def run(cmd: str, timeout: int = 300) -> CmdResult:
    """Run a shell command on Kali and return its real exit code + clean output.

    Protocol: the command is wrapped in ``FRG<hex>`` markers. This both
    defeats zsh's ``=word=`` expansion (plain ``===`` breaks) and lets us
    slice ssh-banner noise from the true command output.
    """
    vm = _cfg().vm
    token = _marker()
    wrapped = f'echo "{token}-START"; {cmd}; echo "{token}-EXIT:$?"'
    try:
        r = subprocess.run(_ssh_base(vm) + [wrapped],
                           capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return CmdResult(False, -1, "", "host-side timeout")
    out = r.stdout or ""
    i = out.find(f"{token}-START")
    j = out.find(f"{token}-EXIT:")
    exit_code: int | None = None
    if j >= 0:
        tail = out[j:].split(":", 1)[1].splitlines()[0].strip()
        try:
            exit_code = int(tail)
        except ValueError:
            exit_code = None
    body = out[i + len(token) + 7: j] if (i >= 0 and j > i) else out
    return CmdResult(
        ok=exit_code == 0,
        exit=exit_code,
        output=body.strip(),
        stderr=(r.stderr or "")[-2000:],
    )


# ---------------------------------------------------------------- file sync
def _abs_remote(remote: str, workdir: str) -> str:
    remote = remote.replace("\\", "/")
    if not remote.startswith("/"):
        remote = f"{workdir}/{remote}"
    return remote


def sync_up(local: str, remote: str) -> CmdResult:
    """Windows → Kali file copy."""
    vm = _cfg().vm
    r = subprocess.run(
        _scp_base(vm) + [local.replace("\\", "/"),
                         f"{vm.ssh_target}:{_abs_remote(remote, vm.workdir)}"],
        capture_output=True, text=True, timeout=300,
    )
    return CmdResult(r.returncode == 0, r.returncode, r.stdout, r.stderr[-500:])


def sync_down(remote: str, local: str) -> CmdResult:
    """Kali → Windows file copy. Creates parent dirs as needed."""
    vm = _cfg().vm
    Path(local).parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(
        _scp_base(vm) + [f"{vm.ssh_target}:{_abs_remote(remote, vm.workdir)}",
                         local.replace("\\", "/")],
        capture_output=True, text=True, timeout=300,
    )
    return CmdResult(r.returncode == 0, r.returncode, r.stdout, r.stderr[-500:])


# ---------------------------------------------------------------- shadow lane
def shadow_run(cmd: str, timeout: int = 300, poll: float = 6) -> CmdResult:
    """Run a command inside the guest's ``shadow`` tmux session so the
    operator can watch it live on the VM screen (``tmux attach -t shadow``).

    The command is sent with ``send-keys -l`` (literal) after POSIX-safe
    single-quote escaping, so no remote shell metacharacter surprises.
    """
    vm = _cfg().vm
    token = _marker()
    ensure = (
        "tmux has-session -t shadow 2>/dev/null || "
        "tmux new-session -d -s shadow -x 200 -y 50"
    )
    subprocess.run(_ssh_base(vm) + [ensure],
                   capture_output=True, text=True, timeout=30)
    safe = cmd.replace("'", "'\\''")
    send = (
        f"tmux send-keys -t shadow -l 'echo {token}-START; {safe}; echo {token}-DONE'; "
        f"tmux send-keys -t shadow Enter"
    )
    subprocess.run(_ssh_base(vm) + [send],
                   capture_output=True, text=True, timeout=30)
    t0 = time.time()
    while time.time() - t0 < timeout:
        r = subprocess.run(
            _ssh_base(vm) + ["tmux capture-pane -t shadow -p -S -300"],
            capture_output=True, text=True, timeout=30,
        )
        pane = r.stdout or ""
        if f"{token}-DONE" in pane:
            i = pane.find(f"{token}-START")
            return CmdResult(True, 0, pane[i:].strip(), live=True)
        time.sleep(poll)
    return CmdResult(
        False, None,
        "(timeout — session still attached, check VM screen)",
        live=True,
    )


# ---------------------------------------------------------------- hygiene
def port_free(ports: list[int]) -> bool:
    """Kill leftover listeners on the VM (test-servers often block rebinds)."""
    for p in ports:
        run(f"fuser -k {p}/tcp 2>/dev/null", timeout=30)
    return True
