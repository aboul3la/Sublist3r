#!/usr/bin/env python
import os
from setuptools import setup


def read(fname: str) -> str:
    """Open files relative to package."""
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


setup(
    name='Sublist3r2',
    version='1.0.0',
    python_requires='>=3.6',
    description='Subdomains enumeration tool for penetration testers',
    long_description=read('README.md'),
    long_description_content_type='text/markdown',
    keywords='subdomain dns detection',
    url='https://github.com/RoninNakomoto/Sublist3r2',
    license='GPL-2.0',
    py_modules=['sublist3r2'],
    include_package_data=True,
    package_data={
        '': ['data/*.txt'],
    },
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
        'aiodnsbrute',
    ],
    entry_points={
        'console_scripts': [
            'sublist3r2 = sublist3r2:interactive',
        ],
    },
)
