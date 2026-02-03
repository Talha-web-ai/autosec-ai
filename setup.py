from setuptools import setup, find_packages

setup(
    name="autosec",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "rich",
        "python-nmap"
    ],
    entry_points={
        "console_scripts": [
            "autosec=autosec.cli:main"
        ]
    },
    author="AutoSec AI",
    description="AI-assisted cybersecurity scanning CLI tool",
)
