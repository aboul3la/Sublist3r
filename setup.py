from setuptools import setup, find_packages

setup(
    name='Sublist3r',
    version='3.0',
    python_requires='>=3.6',
    install_requires=[
        'dnspython>=2.0.0',
        'requests>=2.25.0',
        'colorama>=0.4.4'  # For cross-platform colored output
    ],
    packages=find_packages() + ['.'],
    include_package_data=True,
    url='https://github.com/aboul3la/Sublist3r',
    license='GPL-2.0',
    description='Fast subdomains enumeration tool for penetration testers - Enhanced v3.0 by Shaheer Yasir',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Telecommunications Industry',
        'License :: OSI Approved :: GNU General Public License v2',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS',
        'Operating System :: Microsoft :: Windows',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Security',
    ],
    keywords='subdomain enumeration, dns detection, security, pentest, reconnaissance',
    entry_points={
        'console_scripts': [
            'sublist3r = sublist3r:interactive',
        ],
    },
)
