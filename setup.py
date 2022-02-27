#!/usr/bin/env python
import os
from setuptools import setup, find_packages


def read(fname: str) -> str:
    """Open files relative to package."""
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


setup(
    name='sublist3r2',
    version='1.0.1',
    python_requires='>=3.6',
    description='Subdomains enumeration tool for penetration testers',
    long_description=read('README.md'),
    long_description_content_type='text/markdown',
    keywords='subdomain dns detection',
    url='https://github.com/RoninNakomoto/Sublist3r2',
    license='GPL-2.0',
    packages=find_packages(),
    include_package_data=True,
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Telecommunications Industry',
        'License :: OSI Approved :: GNU General Public License v2',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
    ],
    install_requires=[
        'argparse',
        'dnspython',
        'requests',
        'asyncio',
        'uvloop',
        'tqdm',
        'aiodns',
        'click',
    ],
    entry_points={
        'console_scripts': [
            'sublist3r2 = sublist3r2:interactive',
        ],
    },
)
