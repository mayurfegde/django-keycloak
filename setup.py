import setuptools

setuptools.setup(
    name='Django KeyCloak',
    version='0.0.1',
    author='Mayur Fegde',
    author_email='mayur.fegde@solytics-partners.com',
    description='KeyCloak wrapper for authentication and authorization',
    url='https://github.com/mayurfegde/django-keycloak.git',
    project_urls = {
        "Bug Tracker": "https://github.com/mayurfegde/django-keycloak.git"
    },
    license='PRIVATE',
    packages=['django-keycloak'],
    install_requires=['requests'],
)