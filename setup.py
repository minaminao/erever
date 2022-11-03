from setuptools import find_packages, setup

setup(name="erever", version="0.0.6", description="EVM Reversing Tools", packages=["erever"], author="minaminao", entry_points={'console_scripts': ['erever = erever.__main__:main']})
