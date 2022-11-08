from setuptools import find_packages, setup

install_requires = ["toml==0.10.2", "pycryptodome==3.15.0", "web3==5.31.1"]

setup(name="erever", version="0.0.8", description="EVM Reversing Tools", packages=["erever"], author="minaminao", entry_points={'console_scripts': ['erever = erever.__main__:main']}, install_requires=install_requires)
