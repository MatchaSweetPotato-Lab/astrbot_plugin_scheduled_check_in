"""Installing and reinstalling dependencies from the dashboard.

The fingerprints on offer are whatever the installed curl_cffi build ships. An
AstrBot whose dependency install failed, or that installed this plugin before
its requirement moved on, can be left on a build without ``chrome150``. The
dashboard's reinstall button runs pip through AstrBot's own installer, so the
user's index mirror, extra pip arguments and core constraints apply, and in the
packaged desktop runtime the package lands in AstrBot's shared site-packages.

That desktop runtime installs with ``pip --target``, which deletes the old
package directory before moving the new one in. On Windows the extension module
this process has loaded cannot be deleted, so pip fails partway, after removing
everything around it and leaving the package unimportable. Renaming works where
deleting does not, so a distribution's files are first moved aside into a stash
directory, put back if the install fails, and deleted at the next start, when
nothing holds them any more. ``--target`` also ignores what is installed and
would reinstall every dependency the same way, so dependencies are installed
one at a time with ``--no-deps``, and only those the new build needs.

A running process keeps the build it imported: AstrBot must be restarted.

Playwright, which the headless-browser fallback needs, is optional and not in
requirements.txt; it is installed the same way on request. Not having been
imported, it is usable at once. It drives a browser it does not ship: Chrome or
Edge if the machine has one, otherwise the Chromium build Playwright downloads,
which :func:`download_chromium` fetches with Playwright's own installer.
"""

from __future__ import annotations

import asyncio
import collections
import contextlib
import importlib
import importlib.metadata
import importlib.util
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

logger = logging.getLogger("astrbot")

# Keep in step with requirements.txt; tests/test_dependencies.py checks it.
CURL_CFFI_REQUIREMENT = "curl_cffi>=0.16.2,<1.0.0"
_CURL_CFFI = "curl_cffi"
# Optional, so deliberately absent from requirements.txt. 1.49 is the first
# release whose "chromium" channel is the full build in new-headless mode.
PLAYWRIGHT_REQUIREMENT = "playwright>=1.49.0"
_PLAYWRIGHT = "playwright"
# Where displaced files wait, inside the target so that moving them is a rename.
STASH_DIR_NAME = ".checkin-reinstall-stash"
# Distributions one reinstall may install into a --target directory in total.
_MAX_TARGET_INSTALLS = 8
# pip's AdjacentTempDirectory.LEADING_CHARS.
_PIP_STASH_FILLERS = "-~.=%0123456789"

# The full Chromium build, which core/browser.py launches as channel
# "chromium"; the headless shell, which Playwright would fetch alongside it by
# default, is never used, so it is skipped.
_BROWSER_INSTALL_ARGS = ("install", "--no-shell", "chromium")
# About 200 MB, and on Linux possibly a round of apt-get before it.
_DOWNLOAD_TIMEOUT_SECONDS = 30 * 60
_DOWNLOAD_PROGRESS = re.compile(r"(\d+)%\s+of\s+([\d.]+\s*[KMG]i?B)")
# "Downloading Chrome for Testing 151.0.7922.34 (playwright chromium v1234) from https://..."
_DOWNLOAD_START = re.compile(r"^Downloading (.+?)(?: \(playwright [^)]*\))?(?: from \S+)?$")
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
# Where Playwright's registry looks for the "chrome" and "msedge" channels. On
# Windows the path is under each of several install roots; elsewhere it is the
# only place looked, so a browser installed anywhere else cannot be launched.
_SYSTEM_BROWSER_PATHS = {
    "chrome": {
        "linux": "/opt/google/chrome/chrome",
        "darwin": "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "win32": "Google\\Chrome\\Application\\chrome.exe",
    },
    "msedge": {
        "linux": "/opt/microsoft/msedge/msedge",
        "darwin": "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        "win32": "Microsoft\\Edge\\Application\\msedge.exe",
    },
}

# One pip run at a time, whichever package it installs.
_lock = asyncio.Lock()
_job = ""
_download_lock = asyncio.Lock()
# The download's latest output line, made readable, while one runs.
_download_progress = ""


class ReinstallError(RuntimeError):
    """The reinstall could not be carried out; the message says why."""


def reinstall_running() -> bool:
    """Whether a curl_cffi reinstall is in progress."""
    return _lock.locked() and _job == _CURL_CFFI


@contextlib.asynccontextmanager
async def _pip_job(name: str) -> AsyncIterator[None]:
    """Hold the pip lock for installing ``name``, refusing if it is taken."""
    global _job
    if _lock.locked():
        raise ReinstallError(f"正在安装 {_job or 'pip 依赖'}，请稍候")
    async with _lock:
        _job = name
        try:
            yield
        finally:
            _job = ""


def astrbot_pip_environment() -> tuple[Any, str | None]:
    """AstrBot's pip installer, and the ``--target`` directory it installs into.

    The directory is ``None`` outside the packaged desktop runtime, where pip
    installs into the interpreter's own environment.
    """
    from astrbot.core import pip_installer
    from astrbot.core.utils.astrbot_path import get_astrbot_site_packages_path
    from astrbot.core.utils.runtime_env import is_packaged_desktop_runtime

    target = get_astrbot_site_packages_path() if is_packaged_desktop_runtime() else None
    return pip_installer, target


def installed_version(name: str, path: list[str] | None = None) -> str:
    """Version of the first distribution called ``name`` on ``path``, or ``""``."""
    for dist in importlib.metadata.distributions(name=name, path=path if path is not None else sys.path):
        return str(dist.version or "")
    return ""


def curl_cffi_status() -> dict[str, str]:
    """The curl_cffi version this process runs and the one installed on disk.

    They differ after a reinstall until AstrBot restarts.
    """
    import curl_cffi

    return {
        "loaded_version": str(getattr(curl_cffi, "__version__", "") or ""),
        "installed_version": installed_version(_CURL_CFFI),
        "requirement": CURL_CFFI_REQUIREMENT,
    }


async def reinstall_curl_cffi(installer: Any, target_dir: str | None) -> str:
    """Reinstall curl_cffi at its newest version the requirement allows.

    Args:
        installer: AstrBot's pip installer, or anything with its ``install()``.
        target_dir: The ``--target`` directory installs go to, if any.

    Returns:
        The version now installed.

    Raises:
        ReinstallError: A pip install is already running, or it did not succeed.
    """
    async with _pip_job(_CURL_CFFI):
        path = [target_dir] if target_dir else None
        if target_dir:
            await _install_into_target(
                installer,
                Path(target_dir),
                CURL_CFFI_REQUIREMENT,
                f"{CURL_CFFI_REQUIREMENT} --force-reinstall --no-deps",
            )
        else:
            # Alone first, so the dependencies this process has loaded are left
            # where they are; then whatever the new build needs is filled in.
            await installer.install(package_name=f"{CURL_CFFI_REQUIREMENT} --force-reinstall --no-deps")
            await installer.install(package_name=CURL_CFFI_REQUIREMENT)
        importlib.invalidate_caches()
        version = installed_version(_CURL_CFFI, path)
        if not version:
            raise ReinstallError("pip 已执行完毕，但没有找到安装后的 curl_cffi")
        return version


def cleanup_leftovers(target_dir: str | None) -> None:
    """Delete what earlier reinstalls had to leave behind while it was loaded.

    That is this module's stash under a ``--target`` directory, and the
    ``~url_cffi`` directory pip leaves next to curl_cffi on Windows when it
    cannot delete the loaded extension module it moved there.
    """
    import curl_cffi

    if target_dir:
        shutil.rmtree(Path(target_dir) / STASH_DIR_NAME, ignore_errors=True)
    site_dir = Path(curl_cffi.__file__).resolve().parent.parent
    with contextlib.suppress(OSError):
        for leftover in site_dir.glob("~*"):
            if _is_pip_stash_name(leftover.name, _CURL_CFFI) and leftover.is_dir():
                shutil.rmtree(leftover, ignore_errors=True)


def _is_pip_stash_name(name: str, package: str) -> bool:
    """Whether ``name`` is pip's adjacent stash for ``package`` (``~url_cffi``).

    pip's ``AdjacentTempDirectory`` overwrites the package name's leading
    characters with ``~`` and then its filler characters (``~-rl_cffi``), as
    many as it takes to find a free name.
    """
    if len(name) != len(package) or not name.startswith("~"):
        return False
    return any(
        name[i:] == package[i:] and all(char in _PIP_STASH_FILLERS for char in name[1:i])
        for i in range(1, len(package))
    )


# ----------------------------------------------------------------------
# Playwright and its browser
# ----------------------------------------------------------------------
def playwright_status(target_dir: str | None) -> dict[str, Any]:
    """What the dashboard shows about Playwright and the browser it drives.

    Args:
        target_dir: The ``--target`` directory installs go to, if any.
    """
    # Imported here: importing it does not import Playwright, but it is the
    # module that does, and that keeps what it managed to import.
    from .browser import playwright_import_error, playwright_installed

    chromium = chromium_status()
    return {
        "requirement": PLAYWRIGHT_REQUIREMENT,
        "installed_version": installed_version(_PLAYWRIGHT),
        "loaded": playwright_installed(),
        "import_error": playwright_import_error(),
        "installing": _lock.locked() and _job == _PLAYWRIGHT,
        "chromium": chromium,
        "browsers": installed_browsers(chromium),
        "commands": install_commands(target_dir),
    }


async def install_playwright(installer: Any, target_dir: str | None) -> str:
    """Install Playwright at the newest version the requirement allows.

    Args:
        installer: AstrBot's pip installer, or anything with its ``install()``.
        target_dir: The ``--target`` directory installs go to, if any.

    Returns:
        The version now installed.

    Raises:
        ReinstallError: A pip install is already running, or it did not succeed.
    """
    async with _pip_job(_PLAYWRIGHT):
        if target_dir:
            await _install_into_target(
                installer, Path(target_dir), PLAYWRIGHT_REQUIREMENT, f"{PLAYWRIGHT_REQUIREMENT} --no-deps"
            )
        else:
            await installer.install(package_name=PLAYWRIGHT_REQUIREMENT)
        importlib.invalidate_caches()
        version = installed_version(_PLAYWRIGHT, [target_dir] if target_dir else None)
        if not version:
            raise ReinstallError("pip 已执行完毕，但没有找到安装后的 Playwright")
        return version


def chromium_status() -> dict[str, Any]:
    """Whether the Chromium build the installed Playwright drives is downloaded.

    Read from disk, the way Playwright's own registry decides it, so nothing is
    launched: the build is the ``chromium`` revision the package pins, and it
    is complete once Playwright has written its marker file next to it.
    """
    status: dict[str, Any] = {
        "downloaded": False,
        "version": "",
        "downloading": _download_lock.locked(),
        "progress": _download_progress,
    }
    package = _playwright_package_dir()
    if package is None:
        return status
    try:
        manifest = json.loads((package / "driver" / "package" / "browsers.json").read_text(encoding="utf-8"))
        chromium = next(b for b in manifest["browsers"] if b.get("name") == "chromium")
        revision = str(chromium["revision"])
    except (OSError, ValueError, KeyError, TypeError, StopIteration):
        return status
    status["version"] = str(chromium.get("browserVersion") or "")
    directory = _browsers_dir(package) / f"chromium-{revision}"
    status["downloaded"] = (directory / "INSTALLATION_COMPLETE").is_file()
    return status


def installed_browsers(chromium: dict[str, Any] | None = None) -> list[dict[str, str]]:
    """The browsers Playwright would find on this machine, in "auto" order.

    Chrome and Edge are looked for exactly where Playwright's registry looks
    for its "chrome" and "msedge" channels, and Chromium is its own download,
    so what is listed is what a launch can find; nothing is started.

    Args:
        chromium: :func:`chromium_status`, if already read.

    Returns:
        One entry per browser found: its channel, name, version when it can
        be read from disk, and executable (Chromium's is its directory).
    """
    from .browser import AUTO_ORDER, CHANNEL_NAMES

    found = []
    for channel in AUTO_ORDER:
        if channel == "chromium":
            chromium = chromium if chromium is not None else chromium_status()
            if chromium["downloaded"]:
                found.append({"channel": channel, "name": CHANNEL_NAMES[channel], "version": chromium["version"], "path": ""})
            continue
        executable = _system_browser(channel)
        if executable is not None:
            found.append({
                "channel": channel,
                "name": CHANNEL_NAMES[channel],
                "version": _system_browser_version(executable),
                "path": str(executable),
            })
    return found


def _system_browser(channel: str) -> Path | None:
    """The executable of an installed Chrome or Edge, found as Playwright finds it."""
    suffix = _SYSTEM_BROWSER_PATHS.get(channel, {}).get(sys.platform)
    if not suffix:
        return None
    if sys.platform == "win32":
        drive = os.environ.get("HOMEDRIVE", "")
        prefixes = [
            os.environ.get("LOCALAPPDATA", ""),
            os.environ.get("PROGRAMFILES", ""),
            os.environ.get("PROGRAMFILES(X86)", ""),
            # When the two above are unset.
            f"{drive}\\Program Files" if drive else "",
            f"{drive}\\Program Files (x86)" if drive else "",
        ]
        candidates = [Path(prefix) / suffix for prefix in prefixes if prefix]
    else:
        candidates = [Path(suffix)]
    return next((path for path in candidates if os.access(path, os.F_OK)), None)


def _system_browser_version(executable: Path) -> str:
    """An installed browser's version, where it shows on disk; ``""`` otherwise.

    On Windows each version lives in a directory named after it beside the
    executable; the newest is the one the executable starts.
    """
    if sys.platform != "win32":
        return ""
    versions = []
    with contextlib.suppress(OSError):
        for entry in executable.parent.iterdir():
            if entry.is_dir() and re.fullmatch(r"\d+(\.\d+){3}", entry.name):
                versions.append(tuple(int(part) for part in entry.name.split(".")))
    return ".".join(map(str, max(versions))) if versions else ""


def install_commands(target_dir: str | None) -> dict[str, str]:
    """Shell commands doing what the dashboard's install buttons do.

    For a user who would rather run them. The packaged desktop runtime has no
    interpreter to name, so its browser command runs Playwright's driver
    directly, and it gets no pip command: only AstrBot's installer knows where
    its packages go.
    """
    executable = Path(sys.executable)
    python = _quote(str(executable)) if executable.name.lower().startswith("python") else "python"
    browser_args = list(_BROWSER_INSTALL_ARGS)
    if sys.platform.startswith("linux"):
        # Chromium's system libraries; Playwright asks for sudo if need be.
        browser_args.append("--with-deps")
    driver = _driver() if target_dir else None
    if driver is not None:
        browser = " ".join([*map(_quote, driver[0]), *browser_args])
    else:
        browser = " ".join([python, "-m", "playwright", *browser_args])
    return {
        "pip": "" if target_dir else f'{python} -m pip install "{PLAYWRIGHT_REQUIREMENT}"',
        "browser": browser,
    }


async def download_chromium() -> str:
    """Download the Chromium build Playwright drives, with Playwright's installer.

    It is the same as ``python -m playwright install --no-shell chromium``, run
    through the driver directly, as the packaged desktop runtime has no
    ``python`` to run it with. Run as root on Linux (as in Docker), the system
    libraries Chromium needs are installed too; anyone else lacks the rights.

    Returns:
        The Chromium version now downloaded.

    Raises:
        ReinstallError: Playwright is missing, a download is already running,
            or it did not succeed.
    """
    global _download_progress
    if _download_lock.locked():
        raise ReinstallError("Chromium 正在下载，请稍候")
    async with _download_lock:
        driver = _driver()
        if driver is None:
            raise ReinstallError("未安装 Playwright，请先安装 Playwright")
        argv, env = driver
        argv = [*argv, *_BROWSER_INSTALL_ARGS]
        if sys.platform.startswith("linux") and hasattr(os, "geteuid") and os.geteuid() == 0:
            argv.append("--with-deps")
        _download_progress = "正在准备下载…"
        try:
            code, output = await asyncio.to_thread(_run_driver, argv, env)
        finally:
            _download_progress = ""
    if code != 0:
        raise ReinstallError(f"下载 Chromium 失败（退出码 {code}）：{output or '没有输出'}")
    status = chromium_status()
    if not status["downloaded"]:
        raise ReinstallError(f"下载已结束，但没有找到下载好的 Chromium：{output or '没有输出'}")
    return status["version"]


def _playwright_package_dir() -> Path | None:
    """The installed ``playwright`` package's directory, without importing it."""
    importlib.invalidate_caches()
    try:
        spec = importlib.util.find_spec(_PLAYWRIGHT)
    except (ImportError, ValueError):
        return None
    if spec is None or not spec.submodule_search_locations:
        return None
    return Path(list(spec.submodule_search_locations)[0])


def _browsers_dir(package: Path) -> Path:
    """Where Playwright keeps its browsers, as its registry works it out."""
    configured = os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "")
    if configured == "0":
        return package / "driver" / "package" / ".local-browsers"
    if configured:
        return Path(configured).resolve()
    if sys.platform == "win32":
        cache = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    elif sys.platform == "darwin":
        cache = str(Path.home() / "Library" / "Caches")
    else:
        cache = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(cache) / "ms-playwright"


def _driver() -> tuple[list[str], dict[str, str]] | None:
    """Playwright's bundled Node.js and CLI script, and their environment.

    What ``python -m playwright`` runs; ``None`` without Playwright.
    """
    try:
        from playwright._impl._driver import compute_driver_executable, get_driver_env
    except Exception:
        return None
    node, cli = compute_driver_executable()
    return [str(node), str(cli)], get_driver_env()


def _quote(arg: str) -> str:
    """Quote ``arg`` for a shell, the same way on Windows and POSIX."""
    return f'"{arg}"' if re.search(r"[\s\"'&|<>^()$;]", arg) else arg


def _run_driver(argv: list[str], env: dict[str, str]) -> tuple[int, str]:
    """Run Playwright's installer to the end, keeping its progress readable meanwhile.

    Returns:
        The exit code, and the last lines it printed other than progress bars.
    """
    global _download_progress
    kwargs: dict[str, Any] = {}
    if sys.platform == "win32":
        # AstrBot may run without a console; do not open one for Node.js.
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
    logger.info("Downloading Chromium: %s", " ".join(map(_quote, argv)))
    process = subprocess.Popen(
        argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, **kwargs
    )
    timed_out = threading.Event()

    def kill() -> None:
        timed_out.set()
        process.kill()

    timer = threading.Timer(_DOWNLOAD_TIMEOUT_SECONDS, kill)
    timer.start()
    tail: collections.deque[str] = collections.deque(maxlen=3)
    # What is being downloaded: Chromium, then small helpers Playwright adds.
    item = "Chromium"
    try:
        assert process.stdout is not None
        for raw in process.stdout:
            # A progress bar redraws itself with carriage returns on one line.
            line = _ANSI_ESCAPE.sub("", raw.decode("utf-8", "replace")).strip().rsplit("\r", 1)[-1].strip()
            if not line:
                continue
            progress = _DOWNLOAD_PROGRESS.findall(line)
            if progress:
                percent, size = progress[-1]
                _download_progress = f"{item} 已下载 {percent}%（共 {size}）"
                continue
            start = _DOWNLOAD_START.match(line)
            if start:
                item = start.group(1)
                _download_progress = f"正在下载 {item}"
            else:
                _download_progress = line[:200]
            tail.append(line)
            logger.info("playwright install: %s", line)
        code = process.wait()
    finally:
        timer.cancel()
        if process.poll() is None:
            process.kill()
            process.wait()
    if timed_out.is_set():
        return code or -1, f"超过 {_DOWNLOAD_TIMEOUT_SECONDS // 60} 分钟仍未完成，已中止"
    return code, " / ".join(tail)


# ----------------------------------------------------------------------
# --target installs
# ----------------------------------------------------------------------
async def _install_into_target(installer: Any, target: Path, requirement: str, spec: str) -> None:
    """Install ``requirement`` with ``spec``, then each dependency it lacks, one at a time."""
    root = Requirement(requirement)
    queue: list[tuple[Requirement, str]] = [(root, spec)]
    done: set[str] = set()
    while queue:
        requirement, spec = queue.pop(0)
        name = canonicalize_name(requirement.name)
        if name in done:
            continue
        if len(done) >= _MAX_TARGET_INSTALLS:
            raise ReinstallError(f"{root.name} 的依赖超过 {_MAX_TARGET_INSTALLS} 个，已停止安装")
        done.add(name)
        await _install_one(installer, target, requirement, spec)
        queue.extend(
            (dependency, f"{dependency.name}{dependency.specifier} --no-deps")
            for dependency in _unmet_requirements(requirement.name, target)
        )


async def _install_one(installer: Any, target: Path, requirement: Requirement, spec: str) -> None:
    """Install one distribution into ``target`` with its old files moved aside."""
    moved = _stash(target, requirement.name)
    try:
        await installer.install(package_name=spec)
    except Exception as exc:
        # AstrBot checks after installing that the new files are the ones in
        # use, which they cannot be before a restart when the old build was
        # imported from elsewhere. The install itself is what counts here.
        if _satisfied(requirement, [str(target)]):
            logger.info("Installed %s; AstrBot reported: %s", requirement.name, exc)
            return
        _restore(moved)
        raise
    if not _satisfied(requirement, [str(target)]):
        _restore(moved)
        raise ReinstallError(f"pip 已执行完毕，但 {target} 中没有满足 {requirement} 的版本")


def _satisfied(requirement: Requirement, path: list[str]) -> bool:
    """Whether the first ``requirement.name`` found on ``path`` meets it."""
    version = installed_version(requirement.name, path)
    return bool(version) and requirement.specifier.contains(version, prereleases=True)


def _unmet_requirements(name: str, target: Path) -> list[Requirement]:
    """What the distribution just installed into ``target`` needs and lacks.

    Extras are not wanted, so a requirement guarded by an ``extra`` marker is
    skipped. What the process would import after a restart is checked:
    ``target`` first, as AstrBot puts it at the front of ``sys.path``.
    """
    dists = list(importlib.metadata.distributions(name=name, path=[str(target)]))
    if not dists:
        return []
    path = [str(target), *sys.path]
    unmet = []
    for line in dists[0].requires or []:
        requirement = Requirement(line)
        if requirement.marker is not None and not requirement.marker.evaluate({"extra": ""}):
            continue
        if not _satisfied(requirement, path):
            unmet.append(requirement)
    return unmet


def _top_level_owners(target: Path) -> dict[str, set[str]]:
    """Map each top-level entry of ``target`` to the distributions whose files it holds."""
    owners: dict[str, set[str]] = {}
    for dist_info in target.glob("*.dist-info"):
        dist = importlib.metadata.PathDistribution(dist_info)
        dist_name = canonicalize_name(dist.metadata["Name"] or dist_info.name.split("-")[0])
        entries = {dist_info.name}
        for file in dist.files or []:
            top = file.parts[0] if file.parts else ""
            # Scripts are recorded as ../../bin/..., outside the target.
            if top and top != ".." and not os.path.isabs(str(file)):
                entries.add(top)
        for entry in entries:
            owners.setdefault(entry, set()).add(dist_name)
    return owners


def _stash(target: Path, name: str) -> list[tuple[Path, Path]]:
    """Move ``name``'s top-level entries out of ``target``, returning each move.

    An entry another distribution also has files in (a namespace package) is
    left in place, since moving it would take that distribution's files too.
    """
    wanted = canonicalize_name(name)
    entries = sorted(
        entry
        for entry, dists in _top_level_owners(target).items()
        if dists == {wanted} and (target / entry).exists()
    )
    if not entries:
        return []
    stash_root = target / STASH_DIR_NAME
    stash_root.mkdir(exist_ok=True)
    stash = Path(tempfile.mkdtemp(prefix=f"{wanted}-", dir=stash_root))
    moved: list[tuple[Path, Path]] = []
    for entry in entries:
        source, destination = target / entry, stash / entry
        try:
            os.replace(source, destination)
        except OSError as exc:
            _restore(moved)
            raise ReinstallError(f"无法移开旧的 {entry}：{exc}") from exc
        moved.append((source, destination))
    return moved


def _restore(moved: list[tuple[Path, Path]]) -> None:
    """Put stashed entries back where nothing new has taken their place."""
    for source, destination in reversed(moved):
        if source.exists() or not destination.exists():
            continue
        try:
            os.replace(destination, source)
        except OSError as exc:
            logger.warning("Could not restore %s from %s: %s", source, destination, exc)
