"""Tests for core/dependencies.py: the dashboard's curl_cffi reinstall, and its
Playwright install and Chromium download.

AstrBot's pip installer is replaced by a fake that lays distributions out the
way ``pip --target`` does, so what is checked is what this module does around
pip: which specs it asks for, and that the old files are out of the way while
pip runs and back in place when it fails.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from unittest import mock

import tests  # noqa: F401
from core import dependencies
from core.dependencies import (
    CURL_CFFI_REQUIREMENT,
    PLAYWRIGHT_REQUIREMENT,
    STASH_DIR_NAME,
    ReinstallError,
    chromium_status,
    cleanup_leftovers,
    download_chromium,
    install_commands,
    installed_browsers,
    install_playwright,
    reinstall_curl_cffi,
)

PLUGIN_DIR = Path(__file__).resolve().parent.parent


def write_dist(target: Path, name: str, version: str, requires: tuple[str, ...] = (), top: str | None = None) -> None:
    """Lay out an installed distribution: its package and a dist-info with RECORD."""
    top = top or name
    package = target / top
    package.mkdir(parents=True, exist_ok=True)
    (package / f"{name}_{version.replace('.', '_')}.py").write_text("", encoding="utf-8")
    dist_info = target / f"{name}-{version}.dist-info"
    dist_info.mkdir()
    metadata = ["Metadata-Version: 2.1", f"Name: {name}", f"Version: {version}"]
    metadata += [f"Requires-Dist: {line}" for line in requires]
    (dist_info / "METADATA").write_text("\n".join(metadata) + "\n", encoding="utf-8")
    record = [
        f"{top}/{name}_{version.replace('.', '_')}.py,,",
        f"{dist_info.name}/METADATA,,",
        f"{dist_info.name}/RECORD,,",
        f"../../bin/{name}.exe,,",
    ]
    (dist_info / "RECORD").write_text("\n".join(record) + "\n", encoding="utf-8")


class FakeInstaller:
    """Records each ``install()`` and runs the matching action, like pip would."""

    def __init__(self, actions: dict[str, Callable[[], None]] | None = None) -> None:
        self.specs: list[str] = []
        self.actions = actions or {}

    async def install(self, package_name: str) -> None:
        self.specs.append(package_name)
        action = self.actions.get(package_name)
        if action:
            action()


class TargetReinstallTests(unittest.IsolatedAsyncioTestCase):
    """The packaged desktop runtime, where pip installs with --target."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.target = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    async def test_old_files_are_moved_aside_before_pip_runs(self) -> None:
        write_dist(self.target, "curl_cffi", "0.15.0")
        seen_during_install: list[bool] = []

        def pip() -> None:
            seen_during_install.append((self.target / "curl_cffi").exists())
            write_dist(self.target, "curl_cffi", "0.16.3")

        installer = FakeInstaller({f"{CURL_CFFI_REQUIREMENT} --force-reinstall --no-deps": pip})
        version = await reinstall_curl_cffi(installer, str(self.target))

        self.assertEqual(version, "0.16.3")
        self.assertEqual(seen_during_install, [False])
        self.assertFalse((self.target / "curl_cffi-0.15.0.dist-info").exists())
        stashed = list((self.target / STASH_DIR_NAME).glob("*/curl_cffi-0.15.0.dist-info"))
        self.assertEqual(len(stashed), 1)

    async def test_only_unmet_dependencies_are_installed_one_by_one(self) -> None:
        write_dist(self.target, "curl_cffi", "0.15.0")
        write_dist(self.target, "cffi", "1.17.1")
        write_dist(self.target, "certifi", "2026.7.22")

        def pip_curl_cffi() -> None:
            write_dist(
                self.target,
                "curl_cffi",
                "0.16.3",
                requires=("cffi>=2.0.0", "certifi>=2024.2.2", 'rich; extra == "cli"'),
            )

        def pip_cffi() -> None:
            self.assertFalse((self.target / "cffi-1.17.1.dist-info").exists())
            write_dist(self.target, "cffi", "2.1.1")

        installer = FakeInstaller({
            f"{CURL_CFFI_REQUIREMENT} --force-reinstall --no-deps": pip_curl_cffi,
            "cffi>=2.0.0 --no-deps": pip_cffi,
        })
        await reinstall_curl_cffi(installer, str(self.target))

        self.assertEqual(
            installer.specs,
            [f"{CURL_CFFI_REQUIREMENT} --force-reinstall --no-deps", "cffi>=2.0.0 --no-deps"],
        )

    async def test_failed_install_puts_the_old_files_back(self) -> None:
        write_dist(self.target, "curl_cffi", "0.15.0")

        def pip() -> None:
            raise RuntimeError("Installation failed with error code 1")

        installer = FakeInstaller({f"{CURL_CFFI_REQUIREMENT} --force-reinstall --no-deps": pip})
        with self.assertRaises(RuntimeError):
            await reinstall_curl_cffi(installer, str(self.target))

        self.assertTrue((self.target / "curl_cffi" / "curl_cffi_0_15_0.py").exists())
        self.assertTrue((self.target / "curl_cffi-0.15.0.dist-info").exists())

    async def test_error_after_a_complete_install_is_not_a_failure(self) -> None:
        # AstrBot's check that the new files are the ones in use fails until a
        # restart when the old build was imported from outside the target.
        write_dist(self.target, "curl_cffi", "0.15.0")

        def pip() -> None:
            write_dist(self.target, "curl_cffi", "0.16.3")
            raise RuntimeError("A conflict between plugin dependencies and the current runtime was detected")

        installer = FakeInstaller({f"{CURL_CFFI_REQUIREMENT} --force-reinstall --no-deps": pip})
        self.assertEqual(await reinstall_curl_cffi(installer, str(self.target)), "0.16.3")
        self.assertFalse((self.target / "curl_cffi" / "curl_cffi_0_15_0.py").exists())

    async def test_install_that_leaves_nothing_behind_is_a_failure(self) -> None:
        write_dist(self.target, "curl_cffi", "0.15.0")
        with self.assertRaises(ReinstallError):
            await reinstall_curl_cffi(FakeInstaller(), str(self.target))
        self.assertTrue((self.target / "curl_cffi-0.15.0.dist-info").exists())

    async def test_directory_shared_with_another_distribution_stays(self) -> None:
        write_dist(self.target, "curl_cffi", "0.15.0", top="shared")
        write_dist(self.target, "other", "1.0", top="shared")
        moved = dependencies._stash(self.target, "curl_cffi")

        self.assertTrue((self.target / "shared").exists())
        self.assertEqual([source.name for source, _ in moved], ["curl_cffi-0.15.0.dist-info"])

    async def test_second_reinstall_while_one_runs_is_refused(self) -> None:
        write_dist(self.target, "curl_cffi", "0.15.0")
        release = asyncio.Event()

        class SlowInstaller:
            async def install(inner_self, package_name: str) -> None:
                await release.wait()
                write_dist(self.target, "curl_cffi", "0.16.3")

        first = asyncio.create_task(reinstall_curl_cffi(SlowInstaller(), str(self.target)))
        await asyncio.sleep(0)
        self.assertTrue(dependencies.reinstall_running())
        with self.assertRaises(ReinstallError):
            await reinstall_curl_cffi(FakeInstaller(), str(self.target))
        release.set()
        self.assertEqual(await first, "0.16.3")

    def test_cleanup_removes_the_stash(self) -> None:
        (self.target / STASH_DIR_NAME / "curl_cffi-x" / "curl_cffi").mkdir(parents=True)
        cleanup_leftovers(str(self.target))
        self.assertFalse((self.target / STASH_DIR_NAME).exists())


class EnvironmentReinstallTests(unittest.IsolatedAsyncioTestCase):
    """A normal interpreter or venv, where pip uninstalls by renaming."""

    async def test_package_alone_first_then_its_dependencies(self) -> None:
        installer = FakeInstaller()
        version = await reinstall_curl_cffi(installer, None)

        self.assertEqual(
            installer.specs,
            [f"{CURL_CFFI_REQUIREMENT} --force-reinstall --no-deps", CURL_CFFI_REQUIREMENT],
        )
        self.assertEqual(version, dependencies.installed_version("curl_cffi"))


class RequirementTests(unittest.TestCase):
    def test_requirement_matches_requirements_txt(self) -> None:
        lines = (PLUGIN_DIR / "requirements.txt").read_text(encoding="utf-8").splitlines()
        self.assertIn(CURL_CFFI_REQUIREMENT, [line.strip() for line in lines])

    def test_playwright_stays_optional(self) -> None:
        # AstrBot installs requirements.txt unasked; Playwright is on request.
        text = (PLUGIN_DIR / "requirements.txt").read_text(encoding="utf-8").lower()
        self.assertNotIn("playwright", text)

    def test_pip_stash_names(self) -> None:
        self.assertTrue(dependencies._is_pip_stash_name("~url_cffi", "curl_cffi"))
        self.assertTrue(dependencies._is_pip_stash_name("~~rl_cffi", "curl_cffi"))
        self.assertTrue(dependencies._is_pip_stash_name("~-rl_cffi", "curl_cffi"))
        self.assertFalse(dependencies._is_pip_stash_name("~xrl_cffi", "curl_cffi"))
        self.assertFalse(dependencies._is_pip_stash_name("curl_cffi", "curl_cffi"))
        self.assertFalse(dependencies._is_pip_stash_name("~ffi", "curl_cffi"))
        self.assertFalse(dependencies._is_pip_stash_name("~url_cffi2", "curl_cffi"))


class PlaywrightInstallTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.target = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    async def test_into_a_target_only_unmet_dependencies_follow(self) -> None:
        write_dist(self.target, "greenlet", "3.2.0")

        def pip_playwright() -> None:
            write_dist(self.target, "playwright", "1.62.0", requires=("checkin-fake-pyee<14,>=13", "greenlet<4.0.0,>=3.1.1"))

        installer = FakeInstaller({
            f"{PLAYWRIGHT_REQUIREMENT} --no-deps": pip_playwright,
            "checkin-fake-pyee<14,>=13 --no-deps": lambda: write_dist(self.target, "checkin_fake_pyee", "13.0.0", top="pyee"),
        })
        version = await install_playwright(installer, str(self.target))

        self.assertEqual(version, "1.62.0")
        self.assertEqual(installer.specs, [f"{PLAYWRIGHT_REQUIREMENT} --no-deps", "checkin-fake-pyee<14,>=13 --no-deps"])

    async def test_into_an_environment_pip_resolves_it(self) -> None:
        installer = FakeInstaller()
        with mock.patch.object(dependencies, "installed_version", return_value="1.62.0"):
            self.assertEqual(await install_playwright(installer, None), "1.62.0")
        self.assertEqual(installer.specs, [PLAYWRIGHT_REQUIREMENT])

    async def test_a_curl_cffi_reinstall_is_not_reported_as_running_meanwhile(self) -> None:
        release = asyncio.Event()

        class SlowInstaller:
            async def install(inner_self, package_name: str) -> None:
                await release.wait()
                write_dist(self.target, "playwright", "1.62.0")

        first = asyncio.create_task(install_playwright(SlowInstaller(), str(self.target)))
        await asyncio.sleep(0)
        self.assertFalse(dependencies.reinstall_running())
        with self.assertRaises(ReinstallError) as caught:
            await reinstall_curl_cffi(FakeInstaller(), str(self.target))
        self.assertIn("playwright", str(caught.exception))
        release.set()
        await first


class ChromiumTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.package = root / "playwright"
        manifest = self.package / "driver" / "package" / "browsers.json"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(json.dumps({"browsers": [
            {"name": "chromium", "revision": "1234", "browserVersion": "151.0.7922.34"},
            {"name": "chromium-headless-shell", "revision": "1234", "browserVersion": "151.0.7922.34"},
        ]}), encoding="utf-8")
        self.browsers = root / "browsers"
        self.patches = [
            mock.patch.object(dependencies, "_playwright_package_dir", return_value=self.package),
            mock.patch.dict(os.environ, {"PLAYWRIGHT_BROWSERS_PATH": str(self.browsers)}),
        ]
        for patch in self.patches:
            patch.start()

    def tearDown(self) -> None:
        for patch in reversed(self.patches):
            patch.stop()
        self.temp_dir.cleanup()

    def test_only_a_complete_full_build_counts(self) -> None:
        self.assertFalse(chromium_status()["downloaded"])
        # The headless shell alone is not what core/browser.py launches.
        shell = self.browsers / "chromium_headless_shell-1234"
        shell.mkdir(parents=True)
        (shell / "INSTALLATION_COMPLETE").touch()
        self.assertFalse(chromium_status()["downloaded"])
        # A download that stopped halfway leaves the directory without its marker.
        full = self.browsers / "chromium-1234"
        full.mkdir()
        self.assertFalse(chromium_status()["downloaded"])
        (full / "INSTALLATION_COMPLETE").touch()
        status = chromium_status()
        self.assertTrue(status["downloaded"])
        self.assertEqual(status["version"], "151.0.7922.34")

    def test_an_older_revision_does_not_count(self) -> None:
        old = self.browsers / "chromium-1228"
        old.mkdir(parents=True)
        (old / "INSTALLATION_COMPLETE").touch()
        self.assertFalse(chromium_status()["downloaded"])

    async def test_download_runs_the_driver_and_reports_progress(self) -> None:
        # A stand-in driver: prints what Playwright's installer prints, then
        # leaves the build in place as it would.
        script = Path(self.temp_dir.name) / "driver.py"
        target = self.browsers / "chromium-1234"
        script.write_text(
            "import pathlib, sys, time\n"
            "print('Downloading Chrome for Testing 151.0.7922.34 (playwright chromium v1234)\x1b[2m from https://cdn/chrome-win64.zip\x1b[22m', flush=True)\n"
            "print('|■■■■■■■■      |  10% of 172.8 MiB', flush=True)\n"
            "time.sleep(0.5)\n"
            f"d = pathlib.Path({str(target)!r}); d.mkdir(parents=True)\n"
            "(d / 'INSTALLATION_COMPLETE').touch()\n"
            "print('Chrome for Testing downloaded to ' + str(d))\n"
            "print(' '.join(sys.argv[1:]))\n",
            encoding="utf-8",
        )
        seen: list[str] = []

        async def watch() -> None:
            while not seen or chromium_status()["downloading"]:
                seen.append(chromium_status()["progress"])
                await asyncio.sleep(0.05)

        driver = ([sys.executable, str(script)], {**os.environ, "PYTHONIOENCODING": "utf-8"})
        with mock.patch.object(dependencies, "_driver", return_value=driver):
            watcher = asyncio.create_task(watch())
            version = await download_chromium()
            await watcher

        self.assertEqual(version, "151.0.7922.34")
        self.assertIn("Chrome for Testing 151.0.7922.34 已下载 10%（共 172.8 MiB）", seen)
        self.assertFalse(chromium_status()["downloading"])

    async def test_a_failed_download_says_why(self) -> None:
        driver = ([sys.executable, "-c", "import sys; print('Error: getaddrinfo ENOTFOUND cdn.playwright.dev'); sys.exit(1)"],
                  dict(os.environ))
        with mock.patch.object(dependencies, "_driver", return_value=driver):
            with self.assertRaises(ReinstallError) as caught:
                await download_chromium()
        self.assertIn("ENOTFOUND", str(caught.exception))

    async def test_without_playwright_there_is_nothing_to_run(self) -> None:
        with mock.patch.object(dependencies, "_driver", return_value=None):
            with self.assertRaises(ReinstallError):
                await download_chromium()

    def test_commands_skip_the_headless_shell(self) -> None:
        commands = install_commands(None)
        self.assertIn("-m playwright install --no-shell chromium", commands["browser"])
        self.assertIn(f'-m pip install "{PLAYWRIGHT_REQUIREMENT}"', commands["pip"])
        # The desktop runtime has no interpreter to name, nor a pip to run.
        with mock.patch.object(dependencies, "_driver", return_value=(["C:/pw/node.exe", "C:/pw dir/cli.js"], {})):
            commands = install_commands("C:/site-packages")
        self.assertTrue(commands["browser"].startswith('C:/pw/node.exe "C:/pw dir/cli.js" install --no-shell chromium'))
        self.assertEqual(commands["pip"], "")



class InstalledBrowserTests(unittest.TestCase):
    """What the browser dropdown offers: what Playwright would find, nothing launched."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _install(self, prefix: str, suffix: str, versions: tuple[str, ...] = ()) -> Path:
        executable = self.root / prefix / suffix
        executable.parent.mkdir(parents=True)
        executable.touch()
        for version in versions:
            (executable.parent / version).mkdir()
        return executable

    @unittest.skipUnless(sys.platform == "win32", "Windows install roots")
    def test_windows_install_roots_as_playwright_searches_them(self) -> None:
        chrome = self._install("pf", r"Google\Chrome\Application\chrome.exe", ("152.0.1.2", "153.0.8010.54", "SetupMetrics"))
        edge = self._install("pf86", r"Microsoft\Edge\Application\msedge.exe")
        env = {
            "LOCALAPPDATA": str(self.root / "local"),
            "PROGRAMFILES": str(self.root / "pf"),
            "PROGRAMFILES(X86)": str(self.root / "pf86"),
            "HOMEDRIVE": str(self.root / "nowhere"),
        }
        with mock.patch.dict(os.environ, env),                 mock.patch.object(dependencies, "chromium_status", return_value={"downloaded": False, "version": ""}):
            found = installed_browsers()

        self.assertEqual([b["channel"] for b in found], ["chrome", "msedge"])
        self.assertEqual(found[0]["path"], str(chrome))
        # The newest version directory; others beside it are not versions.
        self.assertEqual(found[0]["version"], "153.0.8010.54")
        self.assertEqual((found[1]["path"], found[1]["version"]), (str(edge), ""))

    def test_listed_in_auto_order_with_the_chromium_download_last(self) -> None:
        edge = self.root / "msedge"
        edge.touch()
        chromium = {"downloaded": True, "version": "151.0.7922.34"}
        with mock.patch.object(dependencies, "_system_browser", lambda channel: edge if channel == "msedge" else None):
            found = installed_browsers(chromium)
        self.assertEqual([(b["channel"], b["name"]) for b in found], [("msedge", "Edge"), ("chromium", "Chromium")])
        self.assertEqual(found[1]["version"], "151.0.7922.34")

    def test_nothing_found_lists_nothing(self) -> None:
        with mock.patch.object(dependencies, "_system_browser", return_value=None):
            self.assertEqual(installed_browsers({"downloaded": False, "version": "151.0"}), [])

if __name__ == "__main__":
    unittest.main()
