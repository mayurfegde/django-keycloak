import base64
import json

import requests
from django.conf import settings

from .keycloak_compose import format_attributes, KeyCloakUrlLibrary, \
    fetch_data, create_data, update_data, delete_data

def get(**kwargs):
    return requests.get(**kwargs)

def post(**kwargs):
    return requests.post(**kwargs)


def put(**kwargs):
    return requests.put(**kwargs)

def delete(**kwargs):
    return requests.delete(**kwargs)


class Base(KeyCloakUrlLibrary):
    def __init__(self, realm_name=None, access_token=None):
        self.base_url = settings.KEYCLOAK_SERVER
        self.realm_name = realm_name
        self.access_token = access_token

    def get_master_access_token(self):
        username = "no-reply@solytics-partners.com"
        password = "admin"

        response = post(
            url="{0}/realms/master/protocol/openid-connect/token".format(self.base_url),
            data='grant_type=password&client_id=admin-cli&username=%s&password=%s' % (username, password),
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        self.access_token = response.json()['access_token'] if response.status_code == 200 else None
        return self.access_token

class KeyCloakRealmManagement(Base):
    def create_realm(self, realm_name, **kwargs):
        """Create new Keycloak realm (Organization)"""
        self.realm_name = realm_name
        create_data(
            url=self.URL_CREATE_REALMS,
            data=json.dumps(dict(
                realm=realm_name, enabled=kwargs['is_active'],
                sslRequired="external", displayName=kwargs['title'])),
            headers={"Authorization": self.access_token}
        )

        realm_detail = self.get_realm_detail(realm_name=self.realm_name)
        scope_details = self.create_realm_client_scope()
        info = dict(realm_id=realm_detail['id'], client_scope=[scope_details])
        return True, "Success", info

    def get_realms(self):
        """ Get all realms"""
        response = fetch_data(url=self.URL_GET_REALMS, headers={"Authorization": self.access_token})
        return [dict(id=x['id'], title=x['realm'],display_name=x['displayName'], enabled=x['enabled']
        ) for x in response.json()]

    def update_realm(self, realm_name: str = None, is_active: bool = True):
        """ Update the realms """
        update_data(
            url=self.URL_UPDATE_REALM_BY_NAME.format(realm_name=self.realm_name),
            data=json.dumps(dict(realm=realm_name,enabled=is_active)),
            headers={"Authorization": self.access_token, 'Content-Type': 'application/json'}
        )

    def get_realm_detail(self, realm_name: str = None):
        """ Retrieve the ID of given realm name"""
        response = fetch_data(
            url=self.URL_GET_REALM_BY_NAME.format(realm_name=self.realm_name),
            headers={"Authorization": self.access_token}
        )
        print("-- response --", response)
        return dict(
            id=response['id']
        )

    def delete_realm(self):
        """ Delete the realms"""
        delete_data(
            url=self.URL_DELETE_REALM.format(realm_name=self.realm_name),
            headers={"Authorization": self.access_token}
        )

    def create_realm_client_scope(self):
        """ Create the client scope which requires for client mapping """
        create_data(
            url=self.URL_CREATE_REALM_CLIENT_SCOPE.format(realm_name=self.realm_name),
            data=json.dumps({
                "name": "group-details",
                "protocol": "openid-connect",
                "attributes": {"include.in.token.scope": "true"},
            }),
            headers={"Authorization": self.access_token,
                     'Content-Type': 'application/json'},
        )
        info = self.get_realm_client_scope(client_realm_scope="group-details")
        self.make_default_realm_client_scope(info['id'])
        self.client_scope_mapper(client_scope_id=info['id'])
        return info

    def get_realm_client_scope(self, client_realm_scope):
        response = fetch_data(
            url=self.URL_GET_CLIENT_SCOPE.format(realm_name=self.realm_name),
            headers={"Authorization": self.access_token,
                     'Content-Type': 'application/json'},
        )
        return [dict(id=x['id'], name=x['name']) for x in response if x['name'] == client_realm_scope][0]

    def make_default_realm_client_scope(self, client_realm_scope_id):
        update_data(
            url=self.URL_SET_DEFAULT_CLIENT_SCOPE.format(realm_name=self.realm_name, realm_client_scope_id=client_realm_scope_id),
            headers={"Authorization": self.access_token}
        )

    def client_scope_mapper(self, client_scope_id):
        create_data(
            url=self.URL_CREATE_CLIENT_SCOPE_MAPPER.format(realm_name=self.realm_name, client_scope_id=client_scope_id),
            data=json.dumps({
                'name': 'group-membership-mapper',
                'protocol': 'openid-connect',
                'protocolMapper': 'oidc-group-membership-mapper',
                'config': {
                    'full.path': 'false',
                    'id.token.claim': 'true',
                    'access.token.claim': 'true',
                    'userinfo.token.claim': 'true',
                    'claim.name': 'groups',
                    'jsonType.label': 'String',
                    'multivalued': 'true'
                }}),
            headers={"Authorization": self.access_token}
        )

    def assign_reals_client_scope_to_client(self, client_id, scope_id):
        update_data(
            url=self.URL_SET_REALM_CLIENT_SCOPE_TO_CLIENT.\
                format(realm_name=self.realm_name, client_id=client_id, scope_id=scope_id),
            headers={"Authorization": self.access_token}
        )


class KeyCloakClientManagement(Base):
    def create_client_application(self, **payload):
        """ To create application under realms """

        logout_url = payload.pop('logoutUrl')
        create_data(
            url=self.URL_CREATE_CLIENT.format(realm_name=self.realm_name),
            data=json.dumps(dict(**payload, baseUrl=payload['rootUrl'],
                name=payload.get('clientId'), webOrigins=["*"], publicClient=True,
                attributes={"post.logout.redirect.uris": logout_url})),
            headers={"Authorization": self.access_token, 'Content-Type': 'application/json'}
        )
        return True, "Created Successfully", self.get_client_applications(search=payload['clientId'])[0]

    def get_client_applications(self, search=None):
        """ To Get Applications under realms"""
        response = fetch_data(
            url=self.URL_GET_CLIENTS.format(realm_name=self.realm_name),
            headers={"Authorization": self.access_token}
        )
        if search:return [dict(id=x['id'], name=x['name']) for x in response if x['name'] == search]
        else:return [dict(id=x['id'], name=x['name']) for x in response]

    def update_client_application(self, client_id, **payload):
        """ To Update Applications under realms"""
        logout_url = payload.pop('logoutUrl')
        update_data(
            url=self.URL_UPDATE_CLIENT.format(realm_name=self.realm_name, client_id=client_id),
            data=json.dumps(dict(**payload, baseUrl=payload['rootUrl'],
                name=payload.get('clientId'), webOrigins=["*"], publicClient=True,
                attributes={"post.logout.redirect.uris": logout_url})),
            headers={"Authorization": self.access_token, 'Content-Type': 'application/json'}
        )
        return True, "Updated Successfully", self.get_client_applications(search=payload['clientId'])[0]

    def delete_client(self, client_id):
        """ To Delete Clients under realms"""
        delete_data(
            url=self.URL_DELETE_CLIENT.format(realm_name=self.realm_name, client_id=client_id),
            headers={"Authorization": self.access_token}
        )

class KeyCloakAuthSettings(Base):
    def set_authentication(self, **kwargs):
        """ Allow SuperAdmin to set up an authentication system for given realm """
        update_data(
            url=self.URL_UPDATE_REALM_BY_NAME.format(realm_name=self.realm_name),
            data=json.dumps(dict(
                registrationAllowed=kwargs.get('allow_user_registration', False),
                verifyEmail=kwargs.get('verify_user_email', False),
                resetPasswordAllowed=kwargs.get('allow_forget_email', False),
                accessTokenLifespan=kwargs.get('token_expiration', False),
                ssoSessionMaxLifespan=kwargs.get('token_expiration', 84000))),
            headers={"Authorization": self.access_token, 'Content-Type': 'application/json'}
        )
        return True, "Successfully created"

    def update_email_settings(self, **payload):
        update_data(
            url=self.URL_UPDATE_REALM_BY_NAME.format(realm_name=self.realm_name),
            data=json.dumps(
                dict(smtpServer={
                    "auth": True, "from": payload['email'],
                    "user":payload['email'], "password": payload.get('password'),
                    "replyTo": payload['reply_to'], "fromDisplayName": payload['display_name'], "starttls": True,
                    "host": payload['host'], "port": payload['port'],
                })),
            headers={"Authorization": self.access_token, 'Content-Type': 'application/json'}
        )

    def set_active_directory(self, client_id, tenant_id, client_secret):
        base_url = "https://login.microsoftonline.com"
        create_data(
            url=self.URL_SET_ACTIVE_DIRECTORY.format(realm_name=self.realm_name),
            data=json.dumps({
                "alias": "ActiveDirectory", "displayName": "MS AD",
                "providerId": "oidc", "enabled": True, "authenticateByDefault": False,
                "config": {
                    "issuer": f"{base_url}/{tenant_id}/v2.0",
                    "tokenUrl": f"{base_url}/{tenant_id}/oauth2/v2.0/token",
                    "jwksUrl": f"{base_url}/{tenant_id}/discovery/v2.0/keys",
                    "logoutUrl": f"{base_url}/{tenant_id}/oauth2/v2.0/logout",
                    "userInfoUrl": "https://graph.microsoft.com/oidc/userinfo",
                    "authorizationUrl": f"{base_url}/{tenant_id}/oauth2/v2.0/authorize",
                    "validateSignature": True, "clientId": client_id,
                    "useJwksUrl": True, "pkceEnabled": False,
                    "clientSecret": client_secret,
                    "clientAuthMethod": "client_secret_post",
                }
            }),
            headers={"Authorization": self.access_token,
                     'Content-Type': 'application/json'},
        )

    def get_active_directory_detail(self):
        response = fetch_data(
            url=self.URL_GET_ACTIVE_DIRECTORY.format(realm_name=self.realm_name),
            headers={"Authorization": self.access_token}
        )
        data_list = list()
        for ad in response:
            config = ad["config"]
            data_list.append(dict(
                internal_id=ad['internalId'],
                alise=ad.get("alias"),
                displayName=ad.get("displayName"),
                client_id=config.get("clientId"),
                client_secret = config.get("clientSecret"),)
            )
        return data_list


class KeyCloakUserManagement(Base):
    def create_user(self, group_ids=[], **payload):
        create_data(
            url=self.URL_CREATE_USER.format(realm_name=self.realm_name),
            data=json.dumps(dict(**payload, credentials=[{"type": "password", "value": "#Nimbus", "temporary": True}],)),
            headers={"Authorization": self.access_token, 'Content-Type': 'application/json'},
        )

        user_info = self.get_users(username=payload['username'])[0]
        for group_id in group_ids:
            self.assign_user_to_group(
                user_id=user_info['id'], group_id=group_id
            )
        return True, "Created Successfully"

    def get_users(self, username=None, group_details=False, user_id=None):

        url = self.URL_GET_USERS.format(realm_name=self.realm_name)
        if username: url = self.URL_GET_USERS_BY_SEARCH.format(realm_name=self.realm_name, search=username)
        if user_id: url = self.URL_GET_USERS_BY_ID.format(realm_name=self.realm_name, user_id=user_id)

        response = fetch_data(url=url, headers={"Authorization": self.access_token})
        user_details = list()
        response_data = [response] if isinstance(response, dict) else response

        for user_info in response_data:
            data_dict = dict(
                id=user_info.get('id', None), username=user_info.get('username', None),
                email=user_info.get('email', None), first_name=user_info.get('firstName', None),
                last_name=user_info.get('lastName', None), enabled=user_info.get('enabled', None),
                email_verified=user_info.get('emailVerified', None),
                groups=self.get_group_and_attributes_for_user(user_info.get('id', None)),
            )
            user_details.append(data_dict)
        return user_details

    def update_user_details(self, user_id, payload):
        response = update_data(
            url=self.URL_UPDATE_USER.format(realm_name=self.realm_name, user_id=user_id),
            data=json.dumps(payload),
            headers={"Authorization": self.access_token}
        )
    def delete_user(self, user_id):
        delete_data(
            url=self.URL_UPDATE_USER.format(realm_name=self.realm_name, user_id=user_id),
            headers={"Authorization": self.access_token}
        )
    def reset_user_password(self, user_id):
        update_data(
            url=self.URL_USER_RESET_PASSWORD.format(realm_name=self.realm_name, user_id=user_id),
            data=json.dumps({"type": "password", "value": "*Nimbus", "temporary": True}),
            headers={"Authorization": self.access_token, 'Content-Type': 'application/json'},
        )
    def get_total_users(self):
        return len(self.get_users())
    def create_group(self, group_name, attributes={}):
        create_data(
            url=self.URL_CREATE_GROUP.format(realm_name=self.realm_name),
            data=json.dumps({"name": group_name, "attributes": attributes}),
            headers={"Authorization": self.access_token,
                     'Content-Type': 'application/json'}
        )

        groups = self.get_all_groups()
        groups = next(filter(lambda x: x['name'] == group_name, groups), None)

        if groups['name'] == 'ADMIN':
            realm_admin_role_client = self.get_groups_realm_roles(search="realm_admin", group_id=groups['id'])[0]
            self.assign_realm_role_to_group(groups['id'], realm_admin_role_client)

        # TODO - Can be optimize
        groups['permissions'] = self.get_all_groups(group_id=groups['id'])['permissions']
        return groups

    def get_all_groups(self, search=None, exact=False, group_id=None, user_details=False):
        url = self.URL_GET_GROUP.format(realm_name=self.realm_name)
        if search: url = self.URL_GET_GROUP_BY_SEARCH_WITH_EXACT.format(realm_name=self.realm_name, search=search, exact=exact)
        if group_id:url = self.URL_GET_GROUP_BY_ID.format(realm_name=self.realm_name, group_id=group_id)

        response = fetch_data(url=url, headers={"Authorization": self.access_token})
        if group_id and response:
            data = response
            [data.pop(x) for x in ['subGroups', 'access', 'clientRoles', 'realmRoles', 'subGroupCount', 'path']]
            data['permissions'] = format_attributes(data.pop('attributes'))
            if user_details:
                data['users'] = self.users_based_on_group(group_id=group_id)
            return data
        return [dict(id=j['id'], name=j['name']) for j in response]
    def update_group_details(self, new_group_name, group_id, attributes={}):
        update_data(
            url=self.URL_UPDATE_GROUP.format(realm_name=self.realm_name, group_id=group_id),
            data=json.dumps({"name": new_group_name, "attributes": attributes}),
            headers={"Authorization": self.access_token,
                     'Content-Type': 'application/json'}
        )
        group_info = self.get_all_groups(group_id=group_id)
        return group_info
    def delete_group(self, group_id):
        delete_data(
            url=self.URL_DELETE_GROUP.format(realm_name=self.realm_name, group_id=group_id),
            headers={"Authorization": self.access_token, 'Content-Type': 'application/json'}
        )

    def assign_user_to_group(self, user_id, group_id):
        url = self.URL_ADD_USER_TO_GROUP.format(
            realm_name=self.realm_name, user_id=user_id, group_id=group_id
        )
        update_data(url=url, headers={"Authorization": self.access_token})

    def get_groups_for_user(self, user_id):
        response = fetch_data(
            url=self.URL_GET_GROUPS_BY_USERID.format(realm_name=self.realm_name, user_id=user_id),
            headers={"Authorization": self.access_token}
        )

        groups = list(dict(id=x['id'], name=x['name']) for x in response)
        return groups

    def assign_groups_to_user(self, user_id, group_ids):
        for group_id in group_ids:
            self.assign_user_to_group(
                user_id=user_id, group_id=group_id
            )

    def remove_user_from_groups(self, user_id, group_ids):
        for group_id in group_ids:
            url = '{base_url}/admin/realms/{realm_name}/users/{user_id}/groups/{group_id}'.format(
            base_url=self.base_url, realm_name=self.realm_name, user_id=user_id, group_id=group_id
        )
        delete_data(url=url, headers={"Authorization": self.access_token})

    def get_group_and_attributes_for_user(self, user_id):
        response = []
        for group in self.get_groups_for_user(user_id):
            group['permissions'] = self.get_all_groups(group_id=group['id']).get('permissions')
            response.append(group)
        return response

    def users_based_on_group(self, group_id):
        response = fetch_data(
            url = self.URL_GET_USERS_BY_GROUP_ID.format(realm_name=self.realm_name, group_id=group_id),
            headers={"Authorization": self.access_token},
        )
        return self.parse_user_details(response) if response else []

    def get_groups_realm_roles(self, group_id=None, search=None):
        response = fetch_data(
            url=self.URL_GET_REALM_ROLE_BY_USERID.format(realm_name=self.realm_name, group_id=group_id, search=search),
            headers={"Authorization": self.access_token}
        )
        return response

    def assign_realm_role_to_group(self, group_id, client_role_details):
        create_data(
            url = self.URL_SET_REALM_ROLE_TO_GROUP_BY_GROUP_ID.format(realm_name=self.realm_name, 
                group_id=group_id, client_id=client_role_details['clientId']),
            data=json.dumps([dict(
                id=client_role_details['id'],
                name=client_role_details['role'],
                description=client_role_details['description'],
            )]),
            headers={"Authorization": self.access_token}
        )

    def parse_user_details(self, data):
        response = []
        for user_info in data:
             response.append(dict(
                id=user_info['id'],
                username=user_info['username'],
                email=user_info['email'],
                first_name=user_info['firstName'],
                last_name=user_info['lastName'],
                enabled=user_info['enabled'],
                email_verified=user_info['emailVerified'],
            ))
        return response

    def decode_token(self):
        response = fetch_data(
            url=KeyCloakUrlLibrary.URL_USER_INFO.format(realm_name=self.realm_name),
            headers={"Authorization": self.access_token}    # This token has prefix Bearer
        )
        return self.get_users(user_id=response['sub'])[0]

class KeycloakRester(KeyCloakUserManagement, KeyCloakRealmManagement, KeyCloakAuthSettings, KeyCloakClientManagement):
    def get_user_info(self, realm_name, access_token):
        response = get(
            url="{0}/realms/{1}/protocol/openid-connect/userinfo".format(self.base_url, realm_name),
            headers={"Authorization": access_token})
        if response.status_code != 200:
            return None
        return response.json()

    def get_user_based_on_user_id(self, realm_name, user_id):
        master_token = self.get_master_access_token()
        response = get(
            url="{0}/admin/realms/{1}/users/{2}".format(self.base_url, realm_name, user_id),
            headers={"Authorization": 'Bearer %s' % master_token})
        if response.status_code != 200:
            return None
        return response.json()

    def get_user_based_on_token(self, realm_name, access_token):
        token_parts = access_token.split('.')
        decoded_token = base64.b64decode(token_parts[1] + '==').decode('utf-8')
        token_json = json.loads(decoded_token)
        user_id = token_json['sub']
        return self.get_user_based_on_user_id(realm_name=realm_name, user_id=user_id)

