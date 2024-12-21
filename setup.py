from setuptools import setup, find_packages

setup(
    name="toty",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "rich",
        "cryptography"
    ],
    entry_points={
        'console_scripts': [
            'toty=toty.toty:main',
        ],
    }
)
