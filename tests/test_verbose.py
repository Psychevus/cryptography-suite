import importlib
import os
from unittest.mock import patch

import cryptography_suite.debug as debug


def reload_modules():
    importlib.reload(debug)
    importlib.reload(importlib.import_module('cryptography_suite.symmetric.aes'))


def test_verbose_mode_env_variable(tmp_path):
    os.environ['VERBOSE_MODE'] = '1'
    reload_modules()
    from cryptography_suite.symmetric import aes_encrypt

    with patch('builtins.print') as mock_print:
        aes_encrypt('msg', 'pass')

    assert any('Derived key' in call.args[0] for call in mock_print.call_args_list)
    os.environ.pop('VERBOSE_MODE')
    reload_modules()
