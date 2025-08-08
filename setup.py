from setuptools import setup
from setuptools.command.build_ext import build_ext


class BuildExt(build_ext):
    """Accept extra compiler arguments via setup.cfg."""

    user_options = build_ext.user_options + [
        ("extra-compile-args=", None, "Extra compiler flags")
    ]

    def initialize_options(self):
        super().initialize_options()
        self.extra_compile_args = None

    def finalize_options(self):
        super().finalize_options()
        if isinstance(self.extra_compile_args, str):
            self.extra_compile_args = self.extra_compile_args.split()

    def build_extensions(self):
        if self.extra_compile_args:
            for ext in self.extensions:
                ext.extra_compile_args = list(self.extra_compile_args)
        super().build_extensions()


if __name__ == "__main__":
    setup(cmdclass={"build_ext": BuildExt})
