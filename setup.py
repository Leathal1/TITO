"""
ATIP Setup Configuration
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text() if readme_file.exists() else ""

setup(
    name="atip",
    version="0.1.0",
    description="Advanced Threat Intelligence Platform - An intelligence organism that transforms chaos into clarity",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="ATIP Team",
    author_email="security@example.com",
    url="https://github.com/yourusername/atip",
    packages=find_packages(),
    include_package_data=True,
    python_requires=">=3.8",
    install_requires=[
        "click>=8.1.0",
        "pyyaml>=6.0",
        "requests>=2.31.0",
        "python-dateutil>=2.8.0",
        "coloredlogs>=15.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "black>=23.12.0",
            "mypy>=1.7.0",
        ],
        "api": [
            "fastapi>=0.104.0",
            "uvicorn>=0.24.0",
        ],
        "postgres": [
            "sqlalchemy>=2.0.0",
            "psycopg2-binary>=2.9.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "atip=atip.cli.main:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    keywords="security threat-intelligence stride cvss cve vulnerability",
)
