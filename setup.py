try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

# PYPI UPLOAD METHOD:
# python setup.py sdist

long_description = '''
Lithium Python SDK wrapping Lithium Rest API and Lithium BULK API.
'''

setup(
    name='lithium-python-sdk',
    version='0.0.1',
    url='https://github.com/laura-barkauskaite/lithium-python-sdk.git',
    author='Laura Barkauskaite',
    author_email='laura.barkauskaite@gmail.com',
    packages=['lithiumpythonsdk'],
    install_requires=[
        'requests','google-api-python-client'
    ],
    description='Lithium Python SDK',
    long_description=long_description
)