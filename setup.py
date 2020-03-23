from distutils.core import setup

setup(
    name='patcherex',
    version='1.2',
    description='The patcherex',
    packages=['patcherex'],
    scripts=["patcherex/patcherex"],
    install_requires=[
        'angr',
        'capstone',
        'psutil',
        'timeout-decorator',
        'subprocess32',
        'povsim @ git+https://github.com/mechaphish/povsim.git',
        'compilerex @ git+https://github.com/mechaphish/compilerex.git',
        'shellphish-qemu',
        'fidget @ git+https://github.com/angr/fidget.git',
        'python-resources',
        'pyyaml',
        'pyelftools',
        'python-magic',
        'tracer @ git+https://github.com/angr/tracer.git',
   ],
)
