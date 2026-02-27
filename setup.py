#!/usr/bin/env python3
import importlib.util
from pathlib import Path

from setuptools import find_packages, setup

# Paths
ROOT = Path(__file__).resolve().parent
PKG = "tlslibhunter"
ABOUT = ROOT / PKG / "about.py"
README = ROOT / "README.md"

# Load metadata from about.py safely
spec = importlib.util.spec_from_file_location(f"{PKG}.about", ABOUT)
about = importlib.util.module_from_spec(spec)
spec.loader.exec_module(about)  # type: ignore[attr-defined]

# Long description
long_description = README.read_text(encoding="utf-8") if README.exists() else ""

# Runtime requirements
install_requires = [
    "frida>=16.0.0",
    "frida-tools>=12.0.0",
    "rich",
]

setup(
    name="tlsLibHunter",
    version=about.__version__,
    description=("Identifies TLS/SSL libraries in running processes using Frida-based dynamic instrumentation."),
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/fkie-cad/tlsLibHunter",
    author=about.__author__,
    author_email="daniel.baier@fkie.fraunhofer.de",
    license="GPL-3.0-only",
    packages=find_packages(exclude=("tests",)),
    python_requires=">=3.8",
    install_requires=install_requires,
    # Include non-Python assets inside the package
    package_data={
        "tlslibhunter": [
            "scripts/*.js",
        ],
    },
    include_package_data=True,
    classifiers=[
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Natural Language :: English",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: JavaScript",
        "Topic :: Security",
        "Topic :: Software Development :: Debuggers",
    ],
    keywords=["frida", "ssl", "tls", "instrumentation", "security"],
    entry_points={
        "console_scripts": [
            "tlsLibHunter=tlslibhunter.cli:main",
        ],
    },
    project_urls={
        "Source": "https://github.com/fkie-cad/tlsLibHunter",
        "Issues": "https://github.com/fkie-cad/tlsLibHunter/issues",
    },
)
