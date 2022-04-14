from setuptools import setup

setup(
    name='pystepupidp',
    version='0.1.0',
    packages=['pystepupidp'],
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        'flask',
        'Flask-WTF',
        'gunicorn',
        'ldap3',
        'pysaml2',
        'requests',
    ],
)
