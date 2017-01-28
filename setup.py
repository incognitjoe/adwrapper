from setuptools import find_packages
from setuptools import setup

setup(
        name='adwrapper',
        version='0.0.3',
        packages=find_packages(exclude=['tests', 'test.*']),
        url='https://github.com/incognitjoe/adwrapper',
        author='Joe Butler',
        author_email='incognitjoeb@gmail.com',
        description='Simple wrapper for common Active Directory actions.',
        install_requires=[
            'python-ldap',
        ]
)