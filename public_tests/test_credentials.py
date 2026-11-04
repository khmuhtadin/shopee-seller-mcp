import asyncio
import concurrent.futures
import json
import multiprocessing
import os
import stat
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from shopee_mcp.credentials import CredentialStore, CredentialError, RefreshNotSent, TokenUpdate
from shopee_mcp.signing import signed_parameters


def make_env(path, **overrides):
    values = dict(SHOPEE_ENV="sandbox", SHOPEE_BASE_URL="https://openplatform.sandbox.test-stable.shopee.sg",
                  SHOPEE_PARTNER_ID="123456", SHOPEE_PARTNER_KEY="partner-secret",
                  SHOPEE_SHOP_ID="987654", SHOPEE_ACCESS_TOKEN="access-secret",
                  SHOPEE_REFRESH_TOKEN="refresh-secret", SHOPEE_ACCESS_TOKEN_EXPIRES_AT="1100",
                  SHOPEE_REFRESH_TOKEN_EXPIRES_AT="9000", SHOPEE_AUTH_EXPIRES_AT="9000")
    values.update(overrides)
    path.write_text("# keep comment\nOTHER=keep\n" + "".join(f"{k}={v}\n" for k, v in values.items()))
    path.chmod(0o600)


def process_refresh(path, queue):
    store = CredentialStore(Path(path), clock=lambda: 1000)
    def refresh(snapshot):
        queue.put("request")
        time.sleep(0.05)
        return TokenUpdate("new-access", "new-refresh", 5000, 8000)
    queue.put(store.ensure(refresh).access_token)


class CredentialsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / ".env"
        make_env(self.path)
        self.store = CredentialStore(self.path, clock=lambda: 1000)

    def test_valid_token_does_not_invoke_refresh_and_constructor_does_not_write(self):
        make_env(self.path, SHOPEE_ACCESS_TOKEN_EXPIRES_AT="5000")
        before = self.path.read_bytes()
        store = CredentialStore(self.path, clock=lambda: 1000)
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])
        self.assertEqual(store.ensure(lambda _: self.fail("network")).access_token, "access-secret")
        self.assertEqual(self.path.read_bytes(), before)

    def test_rotation_preserves_comments_and_permissions_in_same_file(self):
        got = self.store.ensure(lambda _: TokenUpdate("new-access", "new-refresh", 5000, 8000))
        self.assertEqual(got.access_token, "new-access")
        self.assertIn("# keep comment\nOTHER=keep\n", self.path.read_text())
        self.assertIn("SHOPEE_REFRESH_TOKEN=new-refresh\n", self.path.read_text())
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_processes_deduplicate_rotation_and_reload_generation(self):
        ctx = multiprocessing.get_context("spawn")
        queue = ctx.Queue()
        processes = [ctx.Process(target=process_refresh, args=(str(self.path), queue)) for _ in range(2)]
        for process in processes:
            process.start()
        for process in processes:
            process.join(10)
            self.assertEqual(process.exitcode, 0)
        received = [queue.get(timeout=1) for _ in range(3)]
        self.assertEqual(sorted(received), ["new-access", "new-access", "request"])

    def test_unknown_rotation_is_quarantined_across_new_store_instances(self):
        def uncertain(_):
            raise TimeoutError("refresh-secret https://evil/?sign=secret")
        with self.assertRaisesRegex(CredentialError, "refresh_outcome_unknown") as caught:
            self.store.ensure(uncertain)
        self.assertNotIn("refresh-secret", str(caught.exception))
        with self.assertRaisesRegex(CredentialError, "credential_quarantined"):
            CredentialStore(self.path, clock=lambda: 1000).ensure(lambda _: self.fail("replayed"))

    def test_refresh_definitely_not_sent_is_retried_once(self):
        attempts = 0

        def refresh(_):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise RefreshNotSent("connect_error")
            return TokenUpdate("new-access", "new-refresh", 5000, 8000)

        result = self.store.ensure(refresh)

        self.assertEqual(attempts, 2)
        self.assertEqual(result.access_token, "new-access")

    def test_repeated_refresh_not_sent_is_safe_and_recoverable_by_fresh_store(self):
        attempts = 0

        def not_sent(_):
            nonlocal attempts
            attempts += 1
            raise RefreshNotSent("pool_timeout")

        with self.assertRaisesRegex(CredentialError, r"^refresh_not_sent: pool_timeout$"):
            self.store.ensure(not_sent)
        self.assertEqual(attempts, 2)

        recovered = CredentialStore(self.path, clock=lambda: 1000).ensure(
            lambda _: TokenUpdate("recovered-access", "recovered-refresh", 5000, 8000)
        )
        self.assertEqual(recovered.access_token, "recovered-access")

    def test_refresh_not_sent_diagnostic_does_not_include_unapproved_reason(self):
        with self.assertRaises(CredentialError) as caught:
            self.store.ensure(lambda _: (_ for _ in ()).throw(RefreshNotSent("refresh-secret")))

        self.assertEqual(str(caught.exception), "refresh_not_sent")
        self.assertNotIn("refresh-secret", str(caught.exception))

    def test_unknown_failure_after_refresh_not_sent_still_quarantines(self):
        attempts = 0

        def refresh(_):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise RefreshNotSent("connect_timeout")
            raise TimeoutError("refresh-secret")

        with self.assertRaisesRegex(CredentialError, "refresh_outcome_unknown") as caught:
            self.store.ensure(refresh)
        self.assertEqual(attempts, 2)
        self.assertNotIn("refresh-secret", str(caught.exception))
        with self.assertRaisesRegex(CredentialError, "credential_quarantined"):
            CredentialStore(self.path, clock=lambda: 1000).ensure(lambda _: self.fail("replayed"))

    def test_force_reuses_valid_generation_newer_than_rejected_snapshot(self):
        rejected = self.store.snapshot()
        self.store.update_local({
            "SHOPEE_ACCESS_TOKEN": "new-access",
            "SHOPEE_REFRESH_TOKEN": "new-refresh",
            "SHOPEE_ACCESS_TOKEN_EXPIRES_AT": "5000",
            "SHOPEE_REFRESH_TOKEN_EXPIRES_AT": "8000",
        })

        current = self.store.ensure(
            lambda _: self.fail("stale auth failure must not rotate a newer generation"),
            force=True,
            rejected_snapshot=rejected,
        )

        self.assertEqual(current.access_token, "new-access")
        self.assertEqual(current.refresh_token, "new-refresh")

    def test_force_reuses_valid_new_access_when_refresh_generation_is_unchanged(self):
        rejected = self.store.snapshot()
        self.store.update_local({
            "SHOPEE_ACCESS_TOKEN": "new-access",
            "SHOPEE_ACCESS_TOKEN_EXPIRES_AT": "5000",
        })

        current = self.store.ensure(
            lambda _: self.fail("stale auth failure must not rotate a newer access token"),
            force=True,
            rejected_snapshot=rejected,
        )

        self.assertEqual(current.access_token, "new-access")
        self.assertEqual(current.refresh_token, "refresh-secret")

    def test_rejected_snapshot_binding_or_scope_mismatch_is_refused_before_rotation(self):
        snapshot = self.store.snapshot()
        before = self.path.read_bytes()

        for rejected in (replace(snapshot, subject_id=123), replace(snapshot, scope="merchant")):
            with self.subTest(binding=rejected.binding):
                with self.assertRaisesRegex(CredentialError, "credential_binding_mismatch") as caught:
                    self.store.ensure(
                        lambda _: self.fail("mismatched rejected snapshot must not rotate"),
                        force=True,
                        rejected_snapshot=rejected,
                    )

                self.assertEqual(self.path.read_bytes(), before)
                self.assertNotIn("refresh-secret", str(caught.exception))

    def test_persistence_failure_can_retry_local_save_without_rotating_again(self):
        with patch.object(self.store, "_save", side_effect=OSError("refresh-secret")):
            with self.assertRaisesRegex(CredentialError, "credential_persistence_failed"):
                self.store.ensure(lambda _: TokenUpdate("new-access", "new-refresh", 5000, 8000))
        with self.assertRaisesRegex(CredentialError, "credential_quarantined"):
            CredentialStore(self.path, clock=lambda: 1000).ensure(lambda _: self.fail("replayed"))
        self.assertEqual(self.store.retry_save().access_token, "new-access")

    def test_post_replace_directory_fsync_failure_quarantines_visible_new_generation_until_retry_save(self):
        real_fsync = os.fsync
        refresh_calls = 0

        def fail_directory_fsync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("new-refresh")
            return real_fsync(fd)

        def refresh(_):
            nonlocal refresh_calls
            refresh_calls += 1
            return TokenUpdate("new-access", "new-refresh", 5000, 8000)

        with patch("shopee_mcp.credentials.os.fsync", side_effect=fail_directory_fsync):
            with self.assertRaisesRegex(CredentialError, "credential_persistence_failed") as caught:
                self.store.ensure(refresh)

        self.assertEqual(refresh_calls, 1)
        self.assertNotIn("new-refresh", str(caught.exception))
        self.assertEqual(self.store.snapshot().refresh_token, "new-refresh")
        with self.assertRaisesRegex(CredentialError, "credential_quarantined"):
            CredentialStore(self.path, clock=lambda: 1000).ensure(lambda _: self.fail("remote replayed"))

        recovered = self.store.retry_save()
        self.assertEqual(refresh_calls, 1)
        self.assertEqual(recovered.refresh_token, "new-refresh")

    def test_post_replace_failure_quarantines_rolled_back_old_generation(self):
        real_fsync = os.fsync

        def fail_directory_fsync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("synthetic directory fsync failure")
            return real_fsync(fd)

        with patch("shopee_mcp.credentials.os.fsync", side_effect=fail_directory_fsync):
            with self.assertRaisesRegex(CredentialError, "credential_persistence_failed"):
                self.store.ensure(lambda _: TokenUpdate("new-access", "new-refresh", 5000, 8000))

        make_env(self.path)
        with self.assertRaisesRegex(CredentialError, "credential_quarantined"):
            CredentialStore(self.path, clock=lambda: 1000).ensure(lambda _: self.fail("remote replayed"))
        self.assertEqual(self.store.retry_save().refresh_token, "new-refresh")

    def test_stale_retry_rejects_unrelated_third_generation_which_can_resume_normally(self):
        real_fsync = os.fsync

        def fail_directory_fsync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("synthetic directory fsync failure")
            return real_fsync(fd)

        with patch("shopee_mcp.credentials.os.fsync", side_effect=fail_directory_fsync):
            with self.assertRaisesRegex(CredentialError, "credential_persistence_failed"):
                self.store.ensure(lambda _: TokenUpdate("new-access", "new-refresh", 5000, 8000))

        make_env(
            self.path,
            SHOPEE_ACCESS_TOKEN="third-access",
            SHOPEE_REFRESH_TOKEN="third-refresh",
            SHOPEE_ACCESS_TOKEN_EXPIRES_AT="5000",
            SHOPEE_REFRESH_TOKEN_EXPIRES_AT="8000",
        )
        with self.assertRaisesRegex(CredentialError, "credential_generation_changed"):
            self.store.retry_save()

        current = CredentialStore(self.path, clock=lambda: 1000).ensure(
            lambda _: self.fail("valid external generation must not refresh")
        )
        self.assertEqual(current.refresh_token, "third-refresh")

    def test_malformed_generation_markers_fail_closed(self):
        valid_hash = "a" * 64
        invalid_markers = (
            {},
            [],
            [valid_hash],
            [valid_hash, ""],
            [valid_hash, "b" * 64, "c" * 64],
            "not-a-generation-hash",
        )

        self.store.lock_path.parent.mkdir(parents=True, exist_ok=True)
        for marker in invalid_markers:
            with self.subTest(marker=marker):
                self.store.lock_path.write_text(json.dumps({"shop": marker}))
                self.store.lock_path.chmod(0o600)
                with self.assertRaisesRegex(CredentialError, "credential_quarantined: invalid recovery marker"):
                    CredentialStore(self.path, clock=lambda: 1000).ensure(lambda _: self.fail("remote called"))

    def test_missing_merchant_scope_does_not_block_shop(self):
        self.assertEqual(self.store.snapshot().subject_id, 987654)
        with self.assertRaisesRegex(CredentialError, "SHOPEE_MERCHANT_ID"):
            self.store.snapshot("merchant")

    def test_environment_switch_is_rejected_after_startup(self):
        make_env(self.path, SHOPEE_ENV="production", SHOPEE_BASE_URL="https://partner.shopeemobile.com")
        with self.assertRaisesRegex(CredentialError, "credential_binding_changed"):
            self.store.ensure(lambda _: self.fail("network"))

    def test_expiry_and_permissions_fail_closed_without_revealing_values(self):
        make_env(self.path, SHOPEE_AUTH_EXPIRES_AT="999")
        with self.assertRaisesRegex(CredentialError, "reauthorize"):
            self.store.ensure(lambda _: self.fail("network"))
        self.path.chmod(0o644)
        with self.assertRaisesRegex(CredentialError, "0600"):
            self.store.snapshot()

    def test_signing_scopes_use_exact_sequence_and_require_matching_scope(self):
        import hashlib
        import hmac
        snap = self.store.snapshot()
        signed = signed_parameters(snap, "/api/v2/shop/get_shop_info", 1000, "shop")
        expected = hmac.new(b"partner-secret", b"123456/api/v2/shop/get_shop_info1000access-secret987654", hashlib.sha256).hexdigest()
        self.assertEqual(signed["sign"], expected)
        with self.assertRaisesRegex(CredentialError, "scope"):
            signed_parameters(snap, "/api/v2/merchant/get_merchant_info", 1000, "merchant")

    def test_public_and_merchant_signatures_and_separate_rotation(self):
        import hashlib
        import hmac
        make_env(self.path, SHOPEE_MERCHANT_ID="55", SHOPEE_MERCHANT_ACCESS_TOKEN="merchant-access",
                 SHOPEE_MERCHANT_REFRESH_TOKEN="merchant-refresh", SHOPEE_MERCHANT_ACCESS_TOKEN_EXPIRES_AT="1100",
                 SHOPEE_MERCHANT_REFRESH_TOKEN_EXPIRES_AT="8000", SHOPEE_MERCHANT_AUTH_EXPIRES_AT="9000")
        merchant = self.store.snapshot("merchant")
        cases = [("public", "/api/v2/auth/access_token/get", b"123456/api/v2/auth/access_token/get1000"),
                 ("merchant", "/api/v2/merchant/get_merchant_info", b"123456/api/v2/merchant/get_merchant_info1000merchant-access55")]
        for scope, path, base in cases:
            expected = hmac.new(b"partner-secret", base, hashlib.sha256).hexdigest()
            self.assertEqual(signed_parameters(merchant, path, 1000, scope)["sign"], expected)
        self.store.ensure(lambda _: TokenUpdate("ma2", "mr2", 5000, 8000), scope="merchant")
        self.assertEqual(self.store.snapshot("shop").refresh_token, "refresh-secret")
        self.assertEqual(self.store.snapshot("merchant").refresh_token, "mr2")

    def test_cancelled_async_caller_does_not_abort_persistence(self):
        import threading
        started, release = threading.Event(), threading.Event()
        def callback(_):
            started.set()
            release.wait(3)
            return TokenUpdate("new-access", "new-refresh", 5000, 8000)
        async def scenario():
            task = asyncio.create_task(self.store.ensure_async(callback))
            await asyncio.to_thread(started.wait, 3)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            release.set()
            result = await CredentialStore(self.path, clock=lambda: 1000).ensure_async(lambda _: self.fail("duplicate"))
            self.assertEqual(result.refresh_token, "new-refresh")
        asyncio.run(scenario())

    def test_local_update_waits_for_refresh_and_preserves_rotated_tokens(self):
        import threading
        started, update_started, release = threading.Event(), threading.Event(), threading.Event()

        def refresh(_):
            started.set()
            release.wait(3)
            return TokenUpdate("new-access", "new-refresh", 5000, 8000)

        def update_metadata():
            update_started.set()
            self.store.update_local({"SHOPEE_AUTH_STATE": "new-state"})

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            rotating = pool.submit(self.store.ensure, refresh)
            self.assertTrue(started.wait(3))
            updating = pool.submit(update_metadata)
            self.assertTrue(update_started.wait(3))
            self.assertFalse(updating.done(), "Local metadata update must wait for credential rotation")
            release.set()
            rotating.result(3)
            updating.result(3)

        values = self.path.read_text()
        self.assertIn("SHOPEE_ACCESS_TOKEN=new-access\n", values)
        self.assertIn("SHOPEE_REFRESH_TOKEN=new-refresh\n", values)
        self.assertIn("SHOPEE_AUTH_STATE=new-state\n", values)

    def test_failed_shop_save_survives_successful_merchant_rotation_for_retry(self):
        make_env(self.path, SHOPEE_MERCHANT_ID="55", SHOPEE_MERCHANT_ACCESS_TOKEN="merchant-access",
                 SHOPEE_MERCHANT_REFRESH_TOKEN="merchant-refresh", SHOPEE_MERCHANT_ACCESS_TOKEN_EXPIRES_AT="1100",
                 SHOPEE_MERCHANT_REFRESH_TOKEN_EXPIRES_AT="8000", SHOPEE_MERCHANT_AUTH_EXPIRES_AT="9000")
        original_save = self.store._save

        def fail_shop(update, scope):
            if scope == "shop":
                raise OSError("synthetic save failure")
            return original_save(update, scope)

        with patch.object(self.store, "_save", side_effect=fail_shop):
            with self.assertRaisesRegex(CredentialError, "credential_persistence_failed"):
                self.store.ensure(lambda _: TokenUpdate("shop-access-2", "shop-refresh-2", 5000, 8000))
            merchant = self.store.ensure(
                lambda _: TokenUpdate("merchant-access-2", "merchant-refresh-2", 5000, 8000),
                scope="merchant",
            )
        self.assertEqual(merchant.access_token, "merchant-access-2")
        recovered = self.store.retry_save(scope="shop")
        self.assertEqual(recovered.access_token, "shop-access-2")
        self.assertEqual(recovered.refresh_token, "shop-refresh-2")


if __name__ == "__main__":
    unittest.main()
