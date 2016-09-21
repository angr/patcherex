from distutils.core import setup

setup(
    name='patcherex',
    version='1.1',
    description='The patcherex',
    packages=['patcherex'],
    scripts=["patcherex/patcherex"],
    install_requires=[
        'angr',
        'capstone',
        'psutil',
        'timeout-decorator',
        'subprocess32',
        'tracer',
        'povsim',
        'shellphish-qemu',
        'fidget',
        'identifier',
        'pyyaml',
   ],
)
