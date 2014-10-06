#!/usr/bin/env python
from setuptools import setup

setup(
    name="ExternalNaginator",
    version="0.0.1",
    packages=[
        'external_naginator',
    ],
    package_dir={'external_naginator': 'external_naginator'},
    include_package_data=True,
    zip_safe=False,
    author="Daniel Lawrence",
    author_email="dannyla@linux.com",
    description="Generate nagios configuration from puppetdb",
    license="MIT",
    keywords="puppetdb nagios",
    url="http://github.com/daniellawrence/external_naginator",
    install_requires=[
        'pypuppetdb >= 0.0.4'
    ],
    entry_points={
        'console_scripts':
        ['external-naginator = external_naginator:main']
    },
)
