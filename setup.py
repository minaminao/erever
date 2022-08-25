from setuptools import setup, find_packages

setup(name="erever", version="0.0.1", description="EVM Reversing Tools", packages=["erever"], author="minaminao", entry_points={'console_scripts': ['erever = erever.__main__:main']})
