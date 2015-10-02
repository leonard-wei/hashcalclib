#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4
# python version: 2.7.5 final, serial: 0

import io
import textwrap
from distutils.util import convert_path
from ez_setup import use_setuptools
use_setuptools()
from setuptools import setup, find_packages


mainNS = {}
initPath = convert_path('hashcalclib/__init__.py')
with open(initPath, 'r') as file_:
    exec(file_.read(), mainNS)

readmeFile = io.open('README.txt', encoding='utf-8')
with readmeFile:
    longDescription = readmeFile.read()

setupParams = dict(\
    name='hashcalclib', \
    version=mainNS['__version__'], \
    description='A hash calculation and verification library.', \
    long_description=longDescription, \
    author=mainNS['__author__'], \
    author_email=mainNS['__email__'], \
    license=mainNS['__license__'], \
    keywords='', \
    url=mainNS['__url__'], \
    packages=find_packages(exclude=['*.tests']), \
    zip_safe=False, \
    classifiers=textwrap.dedent(\
        """
        Development Status :: 4 - Beta
        Environment :: Console
        Environment :: Win32 (MS Windows)
        Environment :: X11 Applications
        Intended Audience :: Developers
        Intended Audience :: End Users/Desktop
        License :: OSI Approved :: GNU General Public License v2 (GPLv2)
        License :: OSI Approved :: Python Software Foundation License
        Operating System :: OS Independent
        Programming Language :: Python :: 2.6
        Programming Language :: Python :: 2.7
        Topic :: Security :: Cryptography
        Topic :: Utilities
        """
    ).strip().splitlines(),
)


if __name__ == '__main__':
    setup(**setupParams)

