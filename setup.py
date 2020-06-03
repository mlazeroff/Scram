from setuptools import setup, find_packages

setup(
    name='scram',
    author='Matthew Lazeroff',
    version='0.1dev',
    packages=find_packages(),
    package_data={'scram': ['*']},
    include_package_data=True,
    setup_requires=['wheel'],
    install_requires=['cryptography'],
    entry_points={'console_scripts': 'scram = scram.scrammer:main'},
    tests='tests',
    tests_require=['pytest', 'pytest-mock']
)
