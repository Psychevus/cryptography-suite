from hypothesis import given, strategies as st
from cryptography_suite.pipeline import Pipeline


class Upper:
    def run(self, data: bytes) -> bytes:
        return data.upper()


class Reverse:
    def run(self, data: bytes) -> bytes:
        return data[::-1]


@given(st.binary())
def test_pipeline_semantics(data: bytes) -> None:
    pipe = Pipeline() >> Upper() >> Reverse()
    assert pipe.run(data) == data.upper()[::-1]
