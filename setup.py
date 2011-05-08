from setuptools import setup, find_packages
from nessus import __version__

setup(
    name='nessus',
    version=__version__,
    description='Nessus XMLrpc interface',
    author='Alfred Hall',
    author_email='ahall@ahall.org',
    url='http://digitsecurity.github.com/python-nessus/',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False
)
