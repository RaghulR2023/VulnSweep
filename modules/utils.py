"""
utils.py — shared helpers used across all ReconForge modules.

Provides:
  * A simple colored logger (info / success / warning / error / stage).
  * A helper to confirm an external tool exists before we try to run it.
  * A safe subprocess wrapper that handles timeouts and missing tools.

Keeping these here avoids repeating the same boilerplate in every module.
"""

import shutil
import subprocess

# colorama makes ANSI colors work on Windows terminals too. If it isn't
# installed for some reason, we degrade gracefully to plain text.
try:
    from colorama import Fore, Style, init as _colorama_init
    _colorama_init(autoreset=True)  # auto-reset color after every print
    _COLOR = True
except ImportError:  # pragma: no cover - fallback path
    _COLOR = False

    class _Dummy:
        # Any attribute access returns an empty string so f-strings still work.
        def __getattr__(self, _):
            return ""

    Fore = Style = _Dummy()


class Logger:
    """Tiny logger with leveled, colored output.

    We deliberately avoid the stdlib `logging` module here to keep the
    console output clean and easy to theme with colors. Each method just
    prints a tagged, colored line.
    """

    @staticmethod
    def stage(msg):
        # Big visual separator marking the start of a pipeline stage.
        print(f"\n{Fore.CYAN}{Style.BRIGHT}{'='*60}")
        print(f"{Fore.CYAN}{Style.BRIGHT}[*] {msg}")
        print(f"{Fore.CYAN}{Style.BRIGHT}{'='*60}")

    @staticmethod
    def info(msg):
        print(f"{Fore.BLUE}[i]{Style.RESET_ALL} {msg}")

    @staticmethod
    def success(msg):
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")

    @staticmethod
    def warning(msg):
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")

    @staticmethod
    def error(msg):
        print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")


def tool_exists(tool):
    """Return True if `tool` can be found.

    shutil.which() resolves bare command names against PATH and also
    accepts absolute paths, so this works whether the user left the
    default name in config.yaml or supplied a full path.
    """
    return shutil.which(tool) is not None


def run_command(cmd, timeout, stdin_data=None):
    """Run an external command safely and return its CompletedProcess.

    Wraps subprocess.run() with:
      * text mode (so we get str output, not bytes),
      * captured stdout/stderr,
      * a timeout so a hung tool can't block the whole pipeline.

    Returns the CompletedProcess on success, or None if the command
    timed out or the binary was missing. Callers decide what to do next.
    """
    try:
        result = subprocess.run(
            cmd,
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result
    except subprocess.TimeoutExpired:
        Logger.error(f"Command timed out after {timeout}s: {' '.join(cmd)}")
        return None
    except FileNotFoundError:
        # The binary named in cmd[0] does not exist on this system.
        Logger.error(f"Tool not found: {cmd[0]}")
        return None
    except Exception as e:  # pragma: no cover - unexpected OS-level errors
        Logger.error(f"Command failed ({cmd[0]}): {e}")
        return None
