from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from .keycloak_rester import KeycloakRester

missing = []
for att in ['ssssssssssssssssssssssss', 'REALM_NAME', 'CLIENT']:
    try:
        getattr(settings, att)
    except AttributeError:
        missing.append(att)
if missing:
    raise ImproperlyConfigured(missing)