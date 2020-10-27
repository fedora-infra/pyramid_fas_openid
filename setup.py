import os
import sys
from setuptools import setup, find_packages
version = '0.4.0'
README = os.path.join(os.path.dirname(__file__), 'README.txt')
long_description = open(README).read()

install_requires = ['pyramid', 'python-openid-teams',
                    'python-openid-cla', 'six']
if sys.version_info.major == 3:
    install_requires.append('python3-openid')
else:
    install_requires.append('python-openid')


setup(name='pyramid_fas_openid',
        version=version,
        url='http://github.com/lmacken/pyramid_fas_openid',
        description=('A view for pyramid that functions as an '
            'OpenID consumer.'),
        long_description=long_description,
        classifiers=[
            'Intended Audience :: Developers',
            'License :: Repoze Public License',
            'Programming Language :: Python',
            'Programming Language :: Python :: 2.7',
            'Programming Language :: Python :: 3.6',
            'Framework :: Pyramid',
            'Topic :: Internet :: WWW/HTTP',
            'Topic :: Internet :: WWW/HTTP :: WSGI'],
        keywords='pyramid openid fedora',
        author='Luke Macken, Thomas Hill',
        author_email='lmacken@redhat.com',
        license='BSD-derived (http://www.repoze.org/LICENSE.txt)',
        packages=find_packages(),
        install_requires=install_requires
)
