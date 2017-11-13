from distutils.core import setup

setup(
    name = 'dukpt',
    version = '1.0.0',
    py_modules = ['dukpt'],
    long_description = open('README.md').read(),
    install_requires = open('requirements.txt').readlines(),
)
