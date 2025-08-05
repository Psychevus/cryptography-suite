
def test_cli_cryptography_suite(script_runner):
    result = script_runner.run(["cryptography-suite", "--help"])
    assert result.returncode == 0


def test_cli_cryptosuite_fuzz(script_runner):
    result = script_runner.run(["cryptosuite-fuzz", "--help"])
    assert result.returncode == 0
