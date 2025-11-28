# setup.py
from setuptools import setup, find_packages
from pathlib import Path

HERE = Path(__file__).parent
README = (HERE / "README.md").read_text(encoding="utf-8") if (HERE / "README.md").exists() else ""

setup(
    name="Sublist3r",
    version="1.0.1-dev",
    description="Subdomains enumeration tool for penetration testers",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/mazennafee/Sublist3r",            # <- your fork URL (use git remote get-url origin)
    author="Mazen Nafee",                                     # <- your name or GitHub handle
    author_email="123456+mazennafee@users.noreply.github.com",# <- your email or GitHub no-reply
    license="GPL-2.0",
    project_urls={
        "Source (upstream)": "https://github.com/aboul3la/Sublist3r",  # credit original repo
        "Fork": "https://github.com/mazennafee/Sublist3r",
    },  
    packages=find_packages(exclude=("tests", "docs", "build")),
    py_modules=["sublist3r"],
    include_package_data=True,
    python_requires=">=3.8",
    install_requires=[
        "dnspython>=2.0.0",
        "requests>=2.20.0",
        "beautifulsoup4>=4.9.0",
    ],
    extras_require={
        "dev": ["pytest>=6.0", "requests-mock"],
    },
    entry_points={
        "console_scripts": [
            "sublist3r = sublist3r:interactive",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: Security",
    ],
    keywords="subdomain dns detection",
)
