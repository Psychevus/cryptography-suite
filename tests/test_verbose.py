import importlib
import os
import logging

import cryptography_suite.debug as debug


def reload_modules():
    importlib.reload(debug)
    importlib.reload(importlib.import_module('cryptography_suite.symmetric.aes'))
    importlib.reload(importlib.import_module('cryptography_suite.pipeline'))


def test_verbose_mode_env_variable(tmp_path, caplog):
    _ = tmp_path  # unused fixture to satisfy vulture
    os.environ['CRYPTOSUITE_VERBOSE_MODE'] = '1'
    reload_modules()
    from cryptography_suite.pipeline import AESGCMEncrypt

    package_logger = logging.getLogger('cryptography-suite')
    package_logger.setLevel(logging.DEBUG)
    module_logger = logging.getLogger('cryptography_suite.symmetric.aes')
    module_logger.setLevel(logging.DEBUG)
    with caplog.at_level(logging.DEBUG, logger='cryptography-suite'):
        AESGCMEncrypt(password='pass').run('msg')

    assert 'Derived key' in caplog.text
    os.environ.pop('CRYPTOSUITE_VERBOSE_MODE')
    reload_modules()
