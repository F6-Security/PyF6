#!/usr/bin/python
from setuptools import setup

setup(
    name='pyf6',
    version="0.7.14",
    description='Package provides poller for TI, DRP, ASM products',
    python_requires='>=3.6.0',
    install_requires=['requests>=2.25.1', 'dataclasses', 'urllib3', 'pyaml'],
    packages=['pyf6'],
    author='F6-Integration',
    author_email='integration@f6.ru',
    license='MIT',
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url='https://github.com/F6-Integration/pyf6',
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    project_urls={
        "Homepage": "https://github.com/F6-Integration/PyF6",
        "Repository": "https://github.com/F6-Integration/PyF6",
    },
)
