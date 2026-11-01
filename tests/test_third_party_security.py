"""Exercise third-party responses with Flask's real request/session machinery.

Run with: python -m unittest discover -s tests -v
"""

import base64
import unittest
from unittest.mock import AsyncMock, patch
from urllib.parse import quote

from werkzeug.exceptions import InternalServerError

from reddash.app import FlaskApp
from reddash.app.utils import initialize_babel, register_extensions

# Routes use the application's module-level singleton at import time.
app = FlaskApp()
app.config.update(TESTING=True, SECRET_KEY="test-session-key")
app.data = {"core": {"allow_unsecure_http_requests": True}, "disabled_third_parties": []}
register_extensions(app)
initialize_babel(app)

from reddash.app.third_parties import routes  # noqa: E402

app.register_blueprint(routes.blueprint)


def raw_response(body=b"asset", content_type="text/javascript", headers=None):
    return {
        "body_base64": base64.b64encode(body).decode("ascii"),
        "content_type": content_type,
        "headers": headers or {},
    }


class AssetPathSecurityTests(unittest.TestCase):
    def test_unsafe_paths_never_reach_rpc(self):
        for asset_path in (
            "C:/Windows/win.ini",
            "C:relative.txt",
            "assets/icon.svg:payload",
            "../secret",
            "assets/../../secret",
            "assets/./secret",
            "assets//secret",
            "\\\\server\\share\\secret",
            "assets\\..\\secret",
            "assets/secret\x00",
            "assets/secret\n",
        ):
            with self.subTest(asset_path=asset_path), patch.object(
                routes, "get_result", new_callable=AsyncMock,
            ) as rpc:
                response = app.test_client().get(
                    "/third-party/Test/static/" + quote(asset_path, safe="/"),
                )
                self.assertEqual(response.status_code, 404)
                rpc.assert_not_awaited()

    def test_normal_asset_paths_are_allowed(self):
        for asset_path in ("assets/index-a123.js", "fonts/main.woff2", "icons/icon 1.png"):
            with self.subTest(asset_path=asset_path):
                self.assertTrue(routes._is_safe_asset_path(asset_path))


class RawResponseSecurityTests(unittest.TestCase):
    def test_raw_documents_are_sandboxed(self):
        for content_type in (
            "text/html; charset=utf-8",
            "image/svg+xml",
            "text/xml",
            "application/xml",
            "application/xhtml+xml",
            "application/custom+xml",
        ):
            with self.subTest(content_type=content_type), app.test_request_context():
                body = b"<script>parent.compromised = true</script>"
                response = routes._build_raw_response(raw_response(body, content_type))
                self.assertEqual(response.data, body)
                self.assertEqual(response.headers["Content-Type"], content_type)
                self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
                self.assertEqual(response.headers["Content-Security-Policy"], "sandbox")

    def test_cogs_cannot_override_security_or_set_cookies(self):
        with app.test_request_context():
            response = routes._build_raw_response(
                raw_response(
                    headers={
                        "cOnTeNt-SeCuRiTy-PoLiCy": "sandbox allow-scripts allow-same-origin",
                        "X-Content-Type-Options": "",
                        "Content-Type": "text/html",
                        "Set-Cookie": "session=attacker",
                        "Location": "https://example.com",
                        "Service-Worker-Allowed": "/",
                        "cAcHe-CoNtRoL": "public, max-age=3600",
                        "ETag": '"bundle-v1"',
                    },
                ),
            )
        self.assertEqual(response.headers["Content-Security-Policy"], "sandbox")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.mimetype, "text/javascript")
        self.assertNotIn("Set-Cookie", response.headers)
        self.assertNotIn("Location", response.headers)
        self.assertNotIn("Service-Worker-Allowed", response.headers)
        self.assertEqual(response.headers["Cache-Control"], "public, max-age=3600")
        self.assertEqual(response.headers["ETag"], '"bundle-v1"')

    def test_binary_assets_keep_their_bytes_and_mime_type(self):
        for content_type in ("image/png", "font/woff2", "text/css", "text/javascript"):
            with self.subTest(content_type=content_type), app.test_request_context():
                body = bytes(range(256))
                response = routes._build_raw_response(raw_response(body, content_type))
                self.assertEqual(response.data, body)
                self.assertEqual(response.mimetype, content_type)
                self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")

    def test_invalid_body_returns_500(self):
        for payload in ({}, {"body_base64": "!!!"}, {"body_base64": None}):
            with (
                self.subTest(payload=payload),
                app.test_request_context(),
                self.assertRaises(InternalServerError),
            ):
                routes._build_raw_response(payload)


if __name__ == "__main__":
    unittest.main()
