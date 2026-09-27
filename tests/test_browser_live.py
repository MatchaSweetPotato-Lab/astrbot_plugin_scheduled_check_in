"""The browser solver against a local stand-in for a managed challenge, in a real browser.

Skipped when Playwright or a browser it can drive is missing. The stand-in
answers 403 ``cf-mitigated: challenge`` with a page whose script sets
``cf_clearance`` and reloads, which is the shape the solver has to handle;
it says nothing about whether Cloudflare's own challenge passes.
"""

from __future__ import annotations

import unittest
from unittest import mock

import tests  # noqa: F401
from core import browser as browser_module
from core.browser import (
    BrowserOptions,
    BrowserRequest,
    BrowserSolver,
    BrowserUnavailable,
    playwright_installed,
)


try:
    from aiohttp import web
except ImportError:  # pragma: no cover
    web = None

CHALLENGE = """<html><head><title>Just a moment...</title></head><body>
<script>window._cf_chl_opt = {cType: 'managed'};
setTimeout(() => { document.cookie = 'cf_clearance=ok; path=/'; location.reload(); }, 800);</script>
</body></html>"""
STATION = "127.0.0.2"
# An interactive challenge: nothing happens until the checkbox in the widget,
# a cross-site frame, is clicked by a trusted hand.
INTERACTIVE = """<html><head><title>Just a moment...</title></head><body>
<script>window._cf_chl_opt = {cType: 'managed'};
addEventListener('message', e => { document.cookie = 'cf_clearance=ok; path=/';
  document.cookie = 'moves=' + e.data + '; path=/'; location.reload(); });</script>
<div style="height:180px"></div><iframe src="http://%s:%d/widget" style="width:300px;height:65px;border:0"></iframe>
</body></html>"""
WIDGET = """<html><body style="margin:0">
<label style="display:flex;align-items:center;margin:20px 9px"><input type="checkbox" id="cb">Verify you are human</label>
<script>let moves = 0; addEventListener('mousemove', () => moves++);
document.getElementById('cb').addEventListener('click', e => { if (e.isTrusted) parent.postMessage(moves, '*'); });</script>
</body></html>"""
# Measured by a challenge page once laid out (a window's outer size reads 0
# while its first document parses, headed too) and written into a cookie, so
# it comes back with the response.
GEOMETRY = """<html><head><title>Just a moment...</title></head><body><div style="height:3000px"></div><script>
setTimeout(() => {
  document.cookie = 'geometry=' + [innerWidth, outerWidth, innerHeight, outerHeight,
    innerWidth - document.documentElement.clientWidth, screen.width, screen.availHeight, screen.height].join('_') + '; path=/';
  document.cookie = 'cf_clearance=ok; path=/'; location.reload();
}, 300);
</script></body></html>"""


@unittest.skipUnless(playwright_installed() and web is not None, "Playwright or aiohttp is not installed")
class LiveBrowserTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.hits: list[tuple] = []
        app = web.Application()
        app.add_routes([
            web.get("/oauth2/authorize", self.authorize),
            web.get("/hop", self.hop),
            web.get("/login", self.login),
            web.get("/oauth/linuxdo", self.callback),
            web.get("/", self.root),
            web.route("*", "/api/user/checkin", self.checkin),
            web.get("/ticked", self.ticked),
            web.get("/widget", self.widget),
            web.get("/geometry", self.geometry),
        ])
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        self.port = site._server.sockets[0].getsockname()[1]
        await web.TCPSite(self.runner, STATION, self.port).start()
        self.base = f"http://127.0.0.1:{self.port}"
        self.solver = BrowserSolver(idle_close=0)
        self.options = BrowserOptions(timeout=20)
        try:
            await self.solver.check(self.options)
        except BrowserUnavailable as exc:
            await self.runner.cleanup()
            self.skipTest(str(exc))

    async def asyncTearDown(self) -> None:
        await self.solver.aclose()
        await self.runner.cleanup()

    @staticmethod
    def gate(request: web.Request) -> web.Response | None:
        if request.cookies.get("cf_clearance") == "ok":
            return None
        return web.Response(status=403, text=CHALLENGE, content_type="text/html",
                            headers={"cf-mitigated": "challenge"})

    async def authorize(self, request: web.Request) -> web.Response:
        self.hits.append(("authorize", dict(request.cookies)))
        blocked = self.gate(request)
        if blocked is not None:
            return blocked
        if request.cookies.get("_t") != "tok":
            raise web.HTTPFound("/login")
        response = web.HTTPFound(f"/hop?state={request.query['state']}")
        response.set_cookie("_t", "tok2")
        raise response

    async def hop(self, request: web.Request) -> web.Response:
        raise web.HTTPFound(f"http://{STATION}:{self.port}/oauth/linuxdo?code=CODE&state={request.query['state']}")

    async def login(self, request: web.Request) -> web.Response:
        return web.Response(text="<html>login</html>", content_type="text/html")

    async def callback(self, request: web.Request) -> web.Response:
        self.hits.append(("callback",))
        return web.Response(text="spent the code")

    async def root(self, request: web.Request) -> web.Response:
        # Never challenged: vsllm.cc's rule covers /api/user/checkin alone.
        return web.Response(text="<html>home</html>", content_type="text/html")

    async def checkin(self, request: web.Request) -> web.Response:
        # The gate is Cloudflare's edge, in front of the origin, so it
        # challenges every method; only then does the origin refuse a GET.
        blocked = self.gate(request)
        if blocked is not None:
            return blocked
        if request.method != "POST":
            self.hits.append(("solve", dict(request.cookies)))
            return web.json_response({"success": False}, status=405)
        self.hits.append(("checkin", dict(request.cookies), request.headers.get("New-Api-User"), await request.text()))
        response = web.json_response({"success": True})
        response.set_cookie("session", "rotated")
        return response

    async def ticked(self, request: web.Request) -> web.Response:
        if request.cookies.get("cf_clearance") != "ok":
            return web.Response(status=403, text=INTERACTIVE % (STATION, self.port), content_type="text/html",
                                headers={"cf-mitigated": "challenge"})
        self.hits.append(("ticked", int(request.cookies.get("moves", 0))))
        return web.json_response({"success": True})

    async def widget(self, request: web.Request) -> web.Response:
        return web.Response(text=WIDGET, content_type="text/html")

    async def geometry(self, request: web.Request) -> web.Response:
        if request.cookies.get("cf_clearance") != "ok":
            return web.Response(status=403, text=GEOMETRY, content_type="text/html", headers={"cf-mitigated": "challenge"})
        return web.Response(text="<html>measured</html>", content_type="text/html")

    async def test_navigation_solves_the_challenge_and_stops_before_the_station(self) -> None:
        outcome = await self.solver.request(BrowserRequest(
            "GET", f"{self.base}/oauth2/authorize?client_id=c&state=ST",
            {"Cookie": "_t=tok; _forum_session=fs"}, navigate=True,
        ), self.options)
        response = outcome.response
        self.assertTrue(outcome.solved)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["location"], f"http://{STATION}:{self.port}/oauth/linuxdo?code=CODE&state=ST")
        self.assertEqual(response.cookies["_t"], "tok2")
        self.assertNotIn(("callback",), self.hits)
        self.assertEqual([c["name"] for c in outcome.clearance], ["cf_clearance"])

        # The clearance spares the next request the challenge.
        again = await self.solver.request(BrowserRequest(
            "GET", f"{self.base}/oauth2/authorize?client_id=c&state=S2", {"Cookie": "_t=bad"}, navigate=True,
        ), self.options, outcome.clearance)
        self.assertFalse(again.solved)
        self.assertEqual(again.response.status_code, 302)
        self.assertEqual(again.response.headers["location"], f"{self.base}/login")

    async def test_an_api_call_is_made_with_fetch_after_the_challenge(self) -> None:
        """A POST to a path the rule covers alone: the challenge is met on that
        path, not on the root, and without the user's credentials."""
        outcome = await self.solver.request(BrowserRequest(
            "POST", f"{self.base}/api/user/checkin",
            {"Cookie": "session=abc", "New-Api-User": "7", "Content-Type": "application/json",
             "Referer": f"{self.base}/console", "Sec-Fetch-Site": "same-origin"},
            body='{"a":1}',
        ), self.options)
        self.assertTrue(outcome.solved)
        self.assertEqual(outcome.response.status_code, 200)
        self.assertEqual(outcome.response.cookies.get("session"), "rotated")
        self.assertEqual(self.hits, [
            ("solve", {"cf_clearance": "ok"}),
            ("checkin", {"cf_clearance": "ok", "session": "abc"}, "7", '{"a":1}'),
        ])

    async def test_an_interactive_challenge_has_its_checkbox_ticked(self) -> None:
        # The stand-in widget is served from the station's address rather than Cloudflare's.
        with mock.patch.object(browser_module, "_CHALLENGE_HOST_SUFFIXES", (STATION,)):
            outcome = await self.solver.request(BrowserRequest("GET", f"{self.base}/ticked"), self.options)
        self.assertTrue(outcome.solved)
        self.assertEqual(outcome.response.status_code, 200)
        # Reached by the solving navigation and again by the fetch() after it.
        self.assertEqual({name for name, _ in self.hits}, {"ticked"})
        # The pointer travelled across the widget, not teleported onto the box.
        self.assertGreater(self.hits[-1][1], 3)

    async def test_the_window_looks_like_a_desktop_window(self) -> None:
        outcome = await self.solver.request(BrowserRequest("GET", f"{self.base}/geometry"), self.options)
        inner_w, outer_w, inner_h, outer_h, scrollbar, screen_w, avail_h, screen_h = map(
            int, outcome.response.cookies["geometry"].split("_"))
        self.assertLess(inner_h, outer_h)
        self.assertLessEqual(inner_w, outer_w)
        self.assertGreater(scrollbar, 0)
        self.assertLess(outer_w, screen_w)
        self.assertLess(avail_h, screen_h)


if __name__ == "__main__":
    unittest.main()
