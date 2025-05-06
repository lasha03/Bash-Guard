from setuptools import setup, find_packages

setup(
    name="bashguard",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "tree-sitter-bash",
    ],
    python_requires=">=3.8",
) 