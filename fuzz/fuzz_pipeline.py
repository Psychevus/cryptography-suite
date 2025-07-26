import atheris
import sys
from cryptography_suite.pipeline import Pipeline


class Upper:
    def run(self, data: str) -> str:
        return data.upper()


class Reverse:
    def run(self, data: str) -> str:
        return data[::-1]


PIPELINES = [Pipeline([Upper(), Reverse()])]


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicodeNoSurrogates(32)
    pipe = fdp.PickValueInList(PIPELINES)
    try:
        pipe.run(text)
    except Exception:
        pass


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
