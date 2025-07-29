from setuptools import setup, find_packages

setup(
    name="bashguard",
    use_scm_version=True,
    setup_requires=['setuptools_scm'],
    packages=find_packages(),
    install_requires=[
        "click==8.1.8",
        "click-default-group",
        "colorama==0.4.6",
        "iniconfig==2.1.0",
        "packaging==24.2",
        "pluggy==1.5.0",
        "pytest==8.3.5",
        "shellcheck-py==0.10.0.1",
        "tree-sitter==0.24.0",
        "tree-sitter-bash==0.23.3"
    ],
    python_requires=">=3.10",
    entry_points={
        'console_scripts': [
            'bashguard = bashguard.__main__:cli',
        ],
    },
)
