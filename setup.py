import os

PROJECT_DIR = os.path.dirname(os.path.realpath(__file__))

try:
    from setuptools import setup
    from setuptools import find_packages
    packages = find_packages()
except ImportError:
    from distutils.core import setup
    packages = []
    for root, _, filenames in os.walk(PROJECT_DIR):
        if "__init__.py" in filenames:
            packages.append(root)


setup(
    name='patcherex',
    version='1.2',
    description='The patcherex',
    packages=packages,
    install_requires=[
        'angr',
        'capstone',
        'psutil',
        'timeout-decorator',
        'subprocess32',
        'tracer',
        'povsim',
        'compilerex',
        'shellphish-qemu',
        'fidget',
   ],
    package_data={
        'patcherex': ['*.py', 'techniques/*','backends/*'],
    },
)
