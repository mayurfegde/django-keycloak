from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from .keycloak import KeycloakRester
from .compose import create_django_user

missing = []
for att in ['KEYCLOAK_SERVER', 'REALM_NAME', 'CLIENT']:
    try:
        getattr(settings, att)
    except AttributeError:
        missing.append(att)
if missing:
    raise ImproperlyConfigured(missing)