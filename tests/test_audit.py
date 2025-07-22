import os
import unittest

from cryptography.fernet import Fernet

import cryptography_suite.audit as audit
from cryptography_suite.audit import audit_log, set_audit_logger, InMemoryAuditLogger


class TestAuditLogging(unittest.TestCase):
    def tearDown(self):
        # Clean up any global logger and environment variables
        set_audit_logger(None)
        os.environ.pop("AUDIT_MODE", None)
        os.environ.pop("AUDIT_LOG_FILE", None)
        os.environ.pop("AUDIT_LOG_KEY", None)

    def test_memory_logging_success_and_failure(self):
        logger = InMemoryAuditLogger()
        set_audit_logger(logger)

        @audit_log
        def ok(x):
            return x * 2

        @audit_log
        def bad():
            raise ValueError("boom")

        self.assertEqual(ok(2), 4)
        with self.assertRaises(ValueError):
            bad()

        self.assertEqual(len(logger.logs), 2)
        self.assertEqual(logger.logs[0]["operation"], "ok")
        self.assertEqual(logger.logs[0]["status"], "success")
        self.assertEqual(logger.logs[1]["status"], "failure")

    def test_audit_mode_env_variable(self):
        os.environ["AUDIT_MODE"] = "1"

        # No explicit logger set. Should create default InMemoryAuditLogger.
        @audit_log
        def sample():
            return "test"

        sample()
        self.assertIsInstance(audit._AUDIT_LOGGER, audit.InMemoryAuditLogger)
        self.assertEqual(len(audit._AUDIT_LOGGER.logs), 1)
        self.assertEqual(audit._AUDIT_LOGGER.logs[0]["status"], "success")

    def test_encrypted_file_logging(self):
        key = Fernet.generate_key()
        log_path = "audit.log"
        set_audit_logger(log_file=log_path, key=key)

        @audit_log
        def action():
            return 1

        action()
        set_audit_logger(None)

        with open(log_path, "rb") as f:
            line = f.readline().strip()
        os.remove(log_path)

        entry = Fernet(key).decrypt(line).decode()
        self.assertIn("action", entry)
        self.assertIn("success", entry)


if __name__ == "__main__":  # pragma: no cover - manual execution
    unittest.main()
