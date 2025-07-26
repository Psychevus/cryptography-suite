from __future__ import annotations


from typing import Callable, Optional

from mypy.plugin import Plugin, FunctionContext
from mypy.nodes import StrExpr
from mypy.types import Type


class CryptoCheckerPlugin(Plugin):
    """Static analysis checks for insecure crypto usage."""

    insecure_hashes = {"hashlib.md5", "hashlib.sha1"}

    def get_function_hook(
        self, fullname: str
    ) -> Optional[Callable[[FunctionContext], Type]]:
        if (
            fullname in self.insecure_hashes
            or fullname == "hashlib.new"
            or fullname == "Crypto.Cipher.AES.new"
            or fullname.endswith("openssl_md5")
            or fullname.endswith("openssl_sha1")
        ):

            def hook(ctx: FunctionContext, fname=fullname) -> Type:
                return self._check_call(ctx, fname)

            return hook
        return None

    def _check_call(self, ctx: FunctionContext, fullname: str) -> Type:
        if (
            fullname in {"hashlib.md5", "hashlib.sha1"}
            or fullname.endswith("openssl_md5")
            or fullname.endswith("openssl_sha1")
        ):
            alg = fullname.split(".")[-1]
            ctx.api.fail(
                f"Insecure hash function '{alg}' used; use SHA-256 or stronger.",
                ctx.context,
            )
        elif fullname == "hashlib.new":
            if ctx.args and ctx.args[0] and isinstance(ctx.args[0][0], StrExpr):
                alg = ctx.args[0][0].value.lower()
                if alg in {"md5", "sha1"}:
                    ctx.api.fail(
                        f"Insecure hash function '{alg}' used; use SHA-256 or stronger.",
                        ctx.context,
                    )
        elif fullname == "Crypto.Cipher.AES.new":
            if ctx.args and len(ctx.args) > 1:
                mode_arg = ctx.args[1][0]
                if isinstance(mode_arg, StrExpr) and mode_arg.value.upper() == "ECB":
                    ctx.api.fail(
                        "Insecure cipher mode 'ECB'; use AES-GCM instead.",
                        ctx.context,
                    )
        return ctx.default_return_type


def plugin(version: str) -> type[Plugin]:
    return CryptoCheckerPlugin
