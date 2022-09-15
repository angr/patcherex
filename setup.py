from setuptools import setup, find_packages

setup(
    name='patcherex',
    version='1.2',
    description='The patcherex',
    packages=find_packages(),
    scripts=["patcherex/patcherex"],
    install_requires=[
        'angr',
        'capstone',
        'keystone-engine',
        'psutil',
        'povsim',
        'compilerex',
        'shellphish-qemu',
        'fidget',
        'pyyaml',
        'pyelftools',
        'python-magic',
        'termcolor',
        'tracer',
   ],
)
