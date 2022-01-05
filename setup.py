import os
from runpy import run_path

from setuptools import setup


def get_version():
    """
    Get the version of the version as determined by
    :py:`_zkapauthorizer._version`.

    Note: This only works when run from an tree generated
    by git-archive (such as a tarball from github).
    """
    version_path = os.path.join(
        os.path.dirname(__file__), "src/_zkapauthorizer/_version.py"
    )
    context = run_path(version_path)
    return context["__version__"]


setup(
    version=get_version(),
    package_data={
        "": ["testing-signing.key"],
    },
)
