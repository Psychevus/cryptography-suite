from freezegun import freeze_time
from cryptography.fernet import Fernet

from cryptography_suite.audit import EncryptedFileAuditLogger, InMemoryAuditLogger


@freeze_time("2024-02-03 04:05:06")
def test_in_memory_logger_uses_frozen_time():
    logger = InMemoryAuditLogger()
    logger.log("encrypt", "success")

    assert logger.logs[0]["timestamp"] == "2024-02-03T04:05:06"


@freeze_time("2024-02-03 04:05:06")
def test_encrypted_file_logger_contract_format(tmp_path):
    log_file = tmp_path / "audit.log"
    key = Fernet.generate_key()
    logger = EncryptedFileAuditLogger(str(log_file), key)

    logger.log("decrypt", "failure")

    line = log_file.read_bytes().strip()
    plaintext = Fernet(key).decrypt(line).decode()

    assert plaintext == "2024-02-03T04:05:06|decrypt|failure"
