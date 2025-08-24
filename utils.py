import psutil

def safe_proc_info(proc: psutil.Process) -> dict:
    """
    Safely extract process information without raising AccessDenied errors.
    Args:
        proc (psutil.Process): A process object.
    Returns:
        dict: Process info (pid, name, exe, username, cmdline).
    """
    info = {"pid": str(proc.pid)}
    try:
        info["name"] = proc.name()
    except Exception:
        info["name"] = "N/A"

    try:
        info["exe"] = proc.exe()
    except Exception:
        info["exe"] = "N/A"

    try:
        info["username"] = proc.username()
    except Exception:
        info["username"] = "N/A"

    try:
        info["cmdline"] = " ".join(proc.cmdline())
    except Exception:
        info["cmdline"] = "N/A"

    return info
