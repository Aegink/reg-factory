"""K12 reauth API integration; all accounts, tokens and upstreams are synthetic."""

import asyncio
import io
import json
import tempfile
import threading
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from fastapi.testclient import TestClient

from k12 import server
from k12.reauth import ReauthService
from tests.reauth_web.test_convert import sub2_account
from tests.reauth_web.test_formats_and_totp import fake_session
from vendor.reauth_web import engine, jobs
from vendor.reauth_web.formats import OUTPUT_KINDS
from vendor.reauth_web.formats import session_to_payloads
from vendor.reauth_web.parsing import parse_account_line

SECRET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
ACCOUNT = f"owner@example.com----test-password----{SECRET}"


class K12ReauthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.config = {**server._default_config(), "network_mode": "direct", "concurrency": 1,
                       "reauth_proxy": "", "reauth_upstream_base": "", "reauth_upstream_key": ""}
        self.runtime = ReauthService(Path(self.temp.name) / "reauth", lambda: self.config, server._child_environment)
        self.patches = [patch.object(server, "CONFIG", self.config),
                        patch.object(server, "REAUTH_SERVICE", self.runtime),
                        patch.object(server, "_persist", new_callable=AsyncMock),
                        patch.dict("os.environ", {"REAUTH_MIN_INTERVAL_SECONDS": "0"})]
        for item in self.patches:
            item.start()
        self.client = TestClient(server.app)
        token = self.client.get("/api/reauth/session").json()["token"]
        self.headers = {"X-REAUTH-TOKEN": token}

    def tearDown(self):
        asyncio.run(self.runtime.close())
        self.client.close()
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def convert(self, count=1):
        body = {"accounts": [sub2_account(f"owner-{index}@example.com", "plus") for index in range(count)]}
        response = self.client.post("/api/reauth/convert", json={"text": json.dumps(body)}, headers=self.headers)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def wait_job(self, job_id):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            response = self.client.get(f"/api/reauth/job/{job_id}")
            self.assertEqual(response.status_code, 200, response.text)
            if response.json()["finished"]:
                return response.json()
            time.sleep(0.01)
        self.fail("Mock job did not finish")

    def test_k12_page_and_existing_api_are_available(self):
        page = self.client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertIn("reauth.js", page.text)
        self.assertIn("协议重登", page.text)
        self.assertEqual(self.client.get("/static/reauth.js").status_code, 200)
        self.assertEqual(self.client.get("/api/health").json()["service"], "reg-factory-k12")

    def test_convert_downloads_all_formats_without_network(self):
        with patch.object(jobs, "reauth_account", side_effect=AssertionError("Network login forbidden")), \
             patch("vendor.reauth_web.upstream.requests.Session.request", side_effect=AssertionError("Network forbidden")):
            job = self.convert(2)
            self.assertTrue(job["finished"])
            self.assertEqual(job["ok"], 2)
            self.assertEqual(job["accounts"][0]["plan_type"], "plus")
            for kind in OUTPUT_KINDS:
                response = self.client.get(f"/api/reauth/job/{job['job_id']}/download/{kind}")
                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual(response.headers["cache-control"], "no-store")
                if kind == "sub2-merged":
                    self.assertEqual(len(response.json()["accounts"]), 2)
                else:
                    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
                        self.assertEqual(len(archive.namelist()), 2)
                        self.assertTrue(all(name.endswith(".json") for name in archive.namelist()))
                        self.assertTrue(all(json.loads(archive.read(name)) for name in archive.namelist()))

    def test_single_account_download_is_json(self):
        job = self.convert()
        response = self.client.get(f"/api/reauth/job/{job['job_id']}/download/cpa")
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(response.json()["email"], "owner-0@example.com")

    def test_submissions_require_valid_session_token(self):
        for path in ("submit", "convert"):
            response = self.client.post(f"/api/reauth/{path}", json={"text": "test"})
            self.assertEqual(response.status_code, 403)
        self.assertEqual(self.client.post("/api/reauth/submit", json={"text": ACCOUNT},
                                         headers={"X-REAUTH-TOKEN": "forged"}).status_code, 403)

    def test_invalid_modes_and_credentials_fail_before_execution(self):
        with patch.object(jobs, "reauth_account") as login:
            for body in ({"text": ACCOUNT, "mode": "unknown"}, {"text": "invalid"},
                         {"text": f"owner@example.com--------{SECRET}"},
                         {"text": "owner@example.com----pw----ABCDEFGHI"}):
                response = self.client.post("/api/reauth/submit", json=body, headers=self.headers)
                self.assertEqual(response.status_code, 422, response.text)
            login.assert_not_called()

    def test_invalid_conversion_does_not_return_server_error(self):
        for text in ('{"hello":1}', "not json", json.dumps({"accounts": [sub2_account("bad@example.com", "plus") | {"concurrency": "invalid"}]})):
            response = self.client.post("/api/reauth/convert", json={"text": text}, headers=self.headers)
            self.assertEqual(response.status_code, 422, response.text)

    def test_convert_limit(self):
        response = self.client.post("/api/reauth/convert", json={"text": json.dumps({"accounts": [sub2_account("owner@example.com", "free")] * 201})}, headers=self.headers)
        self.assertEqual(response.status_code, 422, response.text)

    def test_mock_protocol_chain_uses_totp_pkce_and_releases_sessions(self):
        session = fake_session("owner@example.com")
        with patch.object(engine, "ChatGPTClient") as chat_cls, patch.object(engine, "OAuthClient") as oauth_cls:
            chat = chat_cls.return_value
            chat.ua = "test-agent"
            chat.impersonate = "chrome133a"
            oauth = oauth_cls.return_value
            initial = oauth.session

            def authorize(url, client, **kwargs):
                self.assertIn("code_challenge_method=S256", url)
                self.assertEqual(kwargs["email"], "owner@example.com")
                self.assertEqual(kwargs["password"], "test-password")
                self.assertRegex(kwargs["mfa_client"].get_mfa_code(), r"^\d{6}$")
                self.assertIs(client, chat)
                return {"ok": True, "code": "test-code", "state": kwargs["expected_state"]}

            oauth.authorize_external_oauth_url.side_effect = authorize
            oauth._exchange_code_for_tokens.return_value = {"access_token": session["accessToken"],
                "refresh_token": session["refreshToken"], "id_token": session["idToken"]}
            response = self.client.post("/api/reauth/submit", json={"text": ACCOUNT}, headers=self.headers)
            self.assertEqual(response.status_code, 200, response.text)
            job = self.wait_job(response.json()["job_id"])
            self.assertEqual(job["ok"], 1, job)
            self.assertEqual(job["accounts"][0]["plan_type"], "plus")
            self.assertTrue(all(step["status"] == "done" for step in job["accounts"][0]["steps"]))
            chat.session.close.assert_called_once()
            initial.close.assert_called_once()
            response = self.client.get(f"/api/reauth/job/{job['job_id']}/download/cpa")
            self.assertEqual(response.json()["refresh_token"], "refresh-token")
            self.assertNotIn(SECRET, json.dumps(job))
            self.assertNotIn("test-password", json.dumps(job))
            self.assertNotIn(session["accessToken"], json.dumps(job))

    def test_protocol_failure_releases_session_and_redacts_credentials(self):
        with patch.object(jobs, "reauth_account", side_effect=engine.ReauthError(f"bad test-password {SECRET} refresh_token=private-token")):
            response = self.client.post("/api/reauth/submit", json={"text": ACCOUNT}, headers=self.headers)
            job = self.wait_job(response.json()["job_id"])
        self.assertEqual(job["failed"], 1)
        self.assertNotIn(SECRET, json.dumps(job))
        self.assertNotIn("test-password", json.dumps(job))
        self.assertNotIn("private-token", json.dumps(job))
        self.assertEqual(self.client.get(f"/api/reauth/job/{job['job_id']}/download/sub2-merged").status_code, 404)

    def test_engine_closes_session_on_login_failure(self):
        with patch.object(engine, "ChatGPTClient") as chat_cls, patch.object(engine, "OAuthClient") as oauth_cls:
            oauth_cls.return_value.authorize_external_oauth_url.return_value = {"ok": False, "error": "phone_required"}
            with self.assertRaises(engine.ReauthError):
                engine.reauth_account(parse_account_line(ACCOUNT), self.runtime.settings())
            chat_cls.return_value.session.close.assert_called_once()

    def test_accounts_in_one_batch_run_concurrently(self):
        self.config["concurrency"] = 2
        barrier = threading.Barrier(2, timeout=2)

        def login(account, settings, on_step):
            self.assertEqual(settings.concurrency, 2)
            barrier.wait()
            return {"plan_type": "plus", "payloads": session_to_payloads(fake_session(account.email))}

        with patch.object(jobs, "reauth_account", side_effect=login):
            response = self.client.post("/api/reauth/submit", json={"text": ACCOUNT + "\n" + ACCOUNT.replace("owner@", "second@")}, headers=self.headers)
            self.assertEqual(response.status_code, 200, response.text)
            job = self.wait_job(response.json()["job_id"])
        self.assertEqual(job["ok"], 2, job)
        response = self.client.get(f"/api/reauth/job/{job['job_id']}/download/sub2-merged")
        self.assertEqual(len(response.json()["accounts"]), 2)

    def test_redeem_configuration_is_required(self):
        response = self.client.post("/api/reauth/submit", json={"text": ACCOUNT, "mode": "redeem"}, headers=self.headers)
        self.assertEqual(response.status_code, 400)

    def test_redeem_download_keeps_original_upstream_after_config_change(self):
        self.config.update(reauth_upstream_base="https://first.example", reauth_upstream_key="first-key")
        with patch("vendor.reauth_web.upstream.UpstreamClient.lookup", return_value={"available": True}), \
             patch.object(jobs, "reauth_account", side_effect=AssertionError("Redeem must not log in")):
            response = self.client.post("/api/reauth/submit", json={"text": ACCOUNT, "mode": "redeem"}, headers=self.headers)
            job = self.wait_job(response.json()["job_id"])
        self.assertEqual(job["ok"], 1)
        manager, _ = self.runtime.job(job["job_id"])
        self.config.update(reauth_upstream_base="https://second.example", reauth_upstream_key="second-key")
        self.assertIsNot(self.runtime.manager(), manager)
        manager.upstream.export = Mock(return_value=("成品.json", b'{"test":true}', "application/json"))
        for _ in range(2):
            response = self.client.get(f"/api/reauth/job/{job['job_id']}/download/cpa")
            self.assertEqual(response.status_code, 200, response.text)
        manager.upstream.export.assert_called_once_with(ACCOUNT, "cpa")
        self.assertEqual(manager.upstream.server_key, "first-key")

    def test_config_redacts_secrets_and_supports_keep_and_clear(self):
        response = self.client.patch("/api/config", json={"reauth_proxy": "http://user:secret@proxy.example:8080", "reauth_upstream_key": "test-key", "reauth_upstream_base": "https://stock.example"})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertNotIn("secret", response.text)
        self.assertNotIn("test-key", response.text)
        self.assertTrue(response.json()["config"]["reauth_proxy_present"])
        self.client.patch("/api/config", json={"reauth_proxy": "", "reauth_upstream_key": ""})
        self.assertEqual(self.config["reauth_upstream_key"], "test-key")
        self.client.patch("/api/config", json={"clear_reauth_proxy": True, "clear_reauth_upstream_key": True})
        self.assertEqual(self.config["reauth_proxy"], "")
        self.assertEqual(self.config["reauth_upstream_key"], "")
        self.assertEqual(self.runtime.settings().proxy, "")

    def test_invalid_upstream_url_is_rejected(self):
        for url in ("file:///tmp/test", "https://user:password@host", "https://host?key=secret"):
            response = self.client.patch("/api/config", json={"reauth_upstream_base": url})
            self.assertEqual(response.status_code, 400)

    def test_reauth_config_survives_k12_backup_restore(self):
        self.config.update(reauth_proxy="http://proxy.example:8080", reauth_upstream_base="https://stock.example", reauth_upstream_key="test-key")
        with patch.object(server, "DATA_ROOT", Path(self.temp.name)), patch.object(server, "EMAILS", {}), patch.object(server, "TASKS", {}):
            bundle = self.client.get("/api/data/export").json()
            self.config.update(reauth_proxy="", reauth_upstream_base="", reauth_upstream_key="")
            response = self.client.post("/api/data/import", json=bundle)
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(self.config["reauth_proxy"], "http://proxy.example:8080")
            self.assertEqual(self.config["reauth_upstream_key"], "test-key")

    def test_malformed_upstream_reply_finishes_as_failed_job(self):
        self.config.update(reauth_upstream_base="https://stock.example", reauth_upstream_key="test-key")
        with patch("vendor.reauth_web.upstream.UpstreamClient.lookup", side_effect=ValueError("bad upstream payload")):
            response = self.client.post("/api/reauth/submit", json={"text": ACCOUNT, "mode": "redeem"}, headers=self.headers)
            job = self.wait_job(response.json()["job_id"])
        self.assertTrue(job["finished"])
        self.assertEqual(job["failed"], 1)

    def test_rate_limit_returns_retry_after(self):
        self.runtime.limiter.limit = 1
        first = self.client.post("/api/reauth/submit", json={"text": "invalid"}, headers=self.headers)
        self.assertEqual(first.status_code, 422)
        response = self.client.post("/api/reauth/submit", json={"text": "invalid"}, headers=self.headers)
        self.assertEqual(response.status_code, 429)
        self.assertIn("retry-after", response.headers)

    def test_k12_proxy_and_concurrency_are_used_for_new_jobs(self):
        self.config.update(network_mode="residential", reauth_proxy="http://special.example:8080", concurrency=3)
        self.assertEqual(self.runtime.settings().proxy, "http://special.example:8080")
        self.assertEqual(self.runtime.manager().settings.concurrency, 3)
        self.config.update(network_mode="direct", reauth_proxy="", concurrency=2)
        self.assertEqual(self.runtime.settings().proxy, "")
        self.assertEqual(self.runtime.manager().settings.concurrency, 2)

    def test_results_expire_and_no_credentials_are_written(self):
        job = self.convert()
        manager, stored = self.runtime.job(job["job_id"])
        stored.finished_at = time.time() - 30000
        self.assertEqual(self.client.get(f"/api/reauth/job/{job['job_id']}").status_code, 404)
        self.assertFalse(manager.jobs)
        self.assertEqual(list(Path(self.temp.name).rglob("*")), [])

    def test_running_or_foreign_jobs_cannot_be_downloaded(self):
        job = self.convert()
        _, stored = self.runtime.job(job["job_id"])
        stored.finished_at = 0
        self.assertEqual(self.client.get(f"/api/reauth/job/{job['job_id']}/download/cpa").status_code, 409)
        stored.owner_ip = "other-client"
        self.assertEqual(self.client.get(f"/api/reauth/job/{job['job_id']}").status_code, 404)
        self.assertEqual(self.client.get(f"/api/reauth/job/{job['job_id']}/download/cpa").status_code, 404)

    def test_anonymous_visits_and_seven_day_counts(self):
        response = self.client.post("/api/reauth/visit", json={"visitor_id": "test-visitor"})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["today_visitors"], 1)
        self.assertEqual(len(self.client.get("/api/reauth/visit").json()["days"]), 7)
        saved = (self.runtime.data_root / "visits.json").read_text(encoding="utf-8")
        self.assertNotIn("test-visitor", saved)


if __name__ == "__main__":
    unittest.main()
