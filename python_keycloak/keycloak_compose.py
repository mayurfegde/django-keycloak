import requests
from django.conf import settings

from django.db import transaction
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group

from .keycloak_exceptions import APICallError

ALLOWED_GROUPS = ['ADMIN']
User = get_user_model()

class KCConstant:
    TOKEN_NOT_FOUND = "Token not found"
    TOKEN_EXPIRED = "Token expired"
    PERMISSION_DENIED = "You dont have enough permission to perform this action"

class KeyCloakUrlLibrary:
    URL_CREATE_REALMS = "admin/realms"
    URL_GET_REALMS = "admin/realms"
    URL_GET_REALM_BY_NAME = "admin/realms/{realm_name}"
    URL_UPDATE_REALM_BY_NAME = "admin/realms/{realm_name}"
    URL_DELETE_REALM = "admin/realms/{realm_name}"

    URL_CREATE_CLIENT_SCOPE_MAPPER = "admin/realms/{realm_name}/client-scopes/{client_scope_id}/protocol-mappers/models"
    URL_CREATE_REALM_CLIENT_SCOPE = "admin/realms/{realm_name}/client-scopes"
    URL_GET_CLIENT_SCOPE = "admin/realms/{realm_name}/client-scopes"
    URL_SET_DEFAULT_CLIENT_SCOPE = "admin/realms/{realm_name}/default-default-client-scopes/{realm_client_scope_id}"
    URL_SET_REALM_CLIENT_SCOPE_TO_CLIENT = "admin/realms/{realm_name}/clients/{client_id}/default-client-scopes/{scope_id}"

    URL_CREATE_CLIENT = "admin/realms/{realm_name}/clients"
    URL_GET_CLIENTS = "admin/realms/{realm_name}/clients"
    URL_UPDATE_CLIENT = "admin/realms/{realm_name}/clients/{client_id}"
    URL_DELETE_CLIENT = "admin/realms/{realm_name}/clients/{client_id}"

    URL_USER_INFO = "realms/{realm_name}/protocol/openid-connect/userinfo"
    URL_CREATE_USER = "admin/realms/{realm_name}/users"
    URL_GET_USERS = "admin/realms/{realm_name}/users"
    URL_GET_USERS_BY_ID = "admin/realms/{realm_name}/users/{user_id}"
    URL_GET_USERS_BY_SEARCH = "admin/realms/{realm_name}/users?search={search}"
    URL_UPDATE_USER = "admin/realms/{realm_name}/users/{user_id}"
    URL_DELETE_USER = "admin/realms/{realm_name}/users/{user_id}"
    URL_USER_RESET_PASSWORD = "admin/realms/{realm_name}users/{user_id}/reset-password"

    URL_CREATE_GROUP = "admin/realms/{realm_name}/groups"
    URL_GET_GROUP = "admin/realms/{realm_name}/groups"
    URL_GET_GROUP_BY_ID = "admin/realms/{realm_name}/groups/{group_id}"
    URL_GET_GROUP_BY_SEARCH = "/admin/realms/{realm_name}/groups?search={search}"
    URL_GET_GROUP_BY_SEARCH_WITH_EXACT = "admin/realms/{realm_name}/groups?search={search}&exact={exact}"
    URL_UPDATE_GROUP = "admin/realms/{realm_name}/groups/{group_id}"
    URL_DELETE_GROUP = "admin/realms/{realm_name}/groups/{group_id}"
    URL_GET_USERS_BY_GROUP_ID = "admin/realms/{realm_name}/groups/{group_id}/members"
    URL_ADD_USER_TO_GROUP = "admin/realms/{realm_name}/users/{user_id}/groups/{group_id}"
    URL_REMOVE_USER_FROM_GROUP = ""
    URL_GET_GROUPS_BY_USERID = "admin/realms/{realm_name}/users/{user_id}/groups"

    URL_GET_REALM_ROLE_BY_USERID = "admin/realms/{realm_name}/ui-ext/available-roles/groups/{group_id}?search={search}"
    URL_SET_REALM_ROLE_TO_GROUP_BY_GROUP_ID = "/admin/realms/{realm_name}/groups/{group_id}/role-mappings/clients/{client_id}"

    URL_SET_ACTIVE_DIRECTORY = "admin/realms/{realm_name}/identity-provider/instances"
    URL_GET_ACTIVE_DIRECTORY = "admin/realms/{realm_name}/identity-provider/instances"


def create_django_user(user_details):
    """
    Create a Django user based on the provided user details.
    Assign django user to the provided groups
    """
    with transaction.atomic():
        user, _ = User.objects.get_or_create(
            username=user_details['username'])
        user.groups.clear()
        for group_name in user_details.get('groups', []):
            if group_name in ALLOWED_GROUPS:
                user.groups.add(Group.objects.get_or_create(name=group_name)[0])
        return user

def format_attributes(kc_attributes):
    """
    kc_attributes: dictionary with multivalued attributes
    """
    if not kc_attributes:return dict()
    for key, value in kc_attributes.items():
       if value is None:kc_attributes[key] = None
       else:kc_attributes[key] = value[0]
    return kc_attributes

def parse_error_message(api_response):
    """
    Used to get error message from API Call
    :param api_response:
    :return: error: str
    Why if elif conditions - because API call didn't' return error message on 400 status code
    """
    if api_response.status_code == 401:
        return KCConstant.TOKEN_EXPIRED
    elif api_response.status_code == 403:
        return KCConstant.PERMISSION_DENIED
    try:
        return api_response.json()['errorMessage']
    except KeyError:
        return api_response.json().get('error')

def fetch_data(**kwargs):
    try:
        kwargs = add_server_url(**kwargs)
        print("from package - kwargs", kwargs)
        response = requests.get(**kwargs)
        print("from package - GET API CALL -- :", response.status_code)
        response.raise_for_status()
        return response.json()
    except Exception:
        raise APICallError(parse_error_message(response), response.status_code)

def create_data(**kwargs):
    try:
        kwargs = add_server_url(**kwargs)
        response = requests.post(**kwargs)
        print("from package - response", response.status_code)
        response.raise_for_status()
    except Exception:
        raise APICallError(parse_error_message(response), response.status_code)

def update_data(**kwargs):
    try:
        kwargs = add_server_url(**kwargs)
        response = requests.put(**kwargs)
        print("response from package - ", response.status_code)
        response.raise_for_status()
    except Exception:
        raise APICallError(parse_error_message(response), response.status_code)

def delete_data(**kwargs):
    try:
        kwargs = add_server_url(**kwargs)
        response = requests.delete(**kwargs)
        print("response from package - ", response.status_code)
        response.raise_for_status()
    except Exception:
        raise APICallError(parse_error_message(response), response.status_code)

def add_server_url(**kwargs):
    kwargs['url'] = f'{settings.KEYCLOAK_SERVER}/{kwargs["url"]}'
    return kwargs
