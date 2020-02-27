from setuptools import setup

import versioneer

setup(
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    package_data={
        "": ["testing-signing.key"],
    },
)
