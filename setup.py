from setuptools import setup, find_packages

setup(
    name='Sublist3r',
    version='1.0',
    python_requires='>=2.7',
    install_requires=['dnspython', 'requests', 'argparse; python_version==\'2.7\''],
    packages=find_packages()+['.'],
    include_package_data=True,
    url='https://github.com/aboul3la/Sublist3r',
    license='GPL-2.0',
    description='Subdomains enumeration tool for penetration testers',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Telecommunications Industry',
        'License :: OSI Approved :: GNU General Public License v2',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Security',
    ],
    keywords='subdomain dns detection',
    entry_points={
        'console_scripts': [
            'sublist3r = sublist3r:interactive',
        ],
    },
)
