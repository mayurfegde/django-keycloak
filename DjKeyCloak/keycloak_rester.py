import base64
import json

import requests

from django.conf import settings

def parse_error_message(api_response):
    if api_response.status_code == 401:
        return "Unauthorized access"
    try:
        return api_response.json()['errorMessage']
    except KeyError:
        return api_response.json().get('error')

def get(**kwargs):
    return requests.get(**kwargs)

def getAPI(**kwargs):
    response = requests.get(**kwargs)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(parse_error_message(response))

def post(**kwargs):
    for x, v in kwargs.items():
        print(x, v)
    return requests.post(**kwargs)


def put(**kwargs):
    for x, v in kwargs.items():
        print(x, v)
    return requests.put(**kwargs)

def delete(**kwargs):
    for x, v in kwargs.items():
        print(x, v)
    return requests.delete(**kwargs)


class Base:
    def __init__(self, realm_name=None, access_token=None):
        self.base_url = settings.KEYCLOAK_SERVER
        self.realm_name = settings.REALM_NAME
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
    def create_realm(self, realm_name: str = None, is_active: bool = True):
        """
        Create a new Realm with the given name
        """
        self.realm_name = realm_name
        response = post(
            url="{0}/admin/realms".format(self.base_url),
            data=json.dumps(dict(
                realm=realm_name,
                enabled=is_active,
                sslRequired="external",
                displayName=realm_name,
            )),
            headers={"Authorization": self.access_token}
        )
        if response.status_code == 201:
            realm_detail = self.get_realm_detail(realm_name=self.realm_name)
            scope_details = self.create_realm_client_scope()
            info = dict(
                realm_id=realm_detail['id'],
                client_scope=[scope_details]
            )
            return True, "Success", info
        else:
            raise Exception(
                "Error in creating %s due to error in keycloak - %s" % \
                (realm_name, response.json().get('error') or response.json().get('errorMessage'))
            )

    def get_realms(self):
        """ Get all realms"""
        response = get(
            url="{0}/admin/realms".format(self.base_url),
            headers={"Authorization": self.access_token}
        )
        if response.status_code == 200:
            return [dict(
                id=x['id'], title=x['realm'],
                display_name=x['displayName'], enabled=x['enabled']
            ) for x in response.json()]

        raise Exception("Error in getting Organization")

    def update_realm(self, realm_name: str = None, is_active: bool = True):
        """ Update the realms """
        response = put(
            url="{0}/admin/realms/{1}".format(self.base_url, self.realm_name),
            data=json.dumps(dict(
                realm=realm_name,
                enabled=is_active,
            )),
            headers={"Authorization": 'Bearer %s' % self.get_master_access_token(),
                     'Content-Type': 'application/json'}
        )
        if response.status_code != 204:
            raise Exception(
                "Error in updating organization due to error in keycloak %s" % \
                (response.json().get('error') or response.json().get('errorMessage'))
            )
        else:
            return True, "Successfully created"

    def get_realm_detail(self, realm_name: str = None):
        """ Retrieve the ID of given realm name"""
        response = get(
            url="{0}/admin/realms".format(self.base_url),
            headers={"Authorization": self.access_token}
        )
        if response.status_code == 200:
            return [
                dict(id=x['id']) for x in response.json() if x['realm'] == realm_name or self.realm_name
            ][0]

        raise Exception("Error in getting Organization")

    def delete_realm(self):
        """ Delete the realms"""
        response = delete(
            url="{0}/admin/realms/{1}".format(self.base_url, self.realm_name),
            headers={"Authorization": self.access_token}
        )

    def create_realm_client_scope(self):
        """ Create the client scope which requires for client mapping """
        post(
            url="{0}/admin/realms/{1}/client-scopes".format(self.base_url, self.realm_name),
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
        response = get(
            url="{0}/admin/realms/{1}/client-scopes".format(self.base_url, self.realm_name),
            headers={"Authorization": self.access_token,
                     'Content-Type': 'application/json'},
        )

        if response.status_code == 200:
            return [dict(id=x['id'], name=x['name']) for x in response.json() if x['name'] == client_realm_scope][0]

        raise Exception("Error in getting client scope")

    def make_default_realm_client_scope(self, client_realm_scope_id):
        put(url=f'{self.base_url}/admin/realms/{self.realm_name}/default-default-client-scopes/{client_realm_scope_id}',
            headers={"Authorization": self.access_token}
        )

    def client_scope_mapper(self, client_scope_id):
        post(
            url="{0}/admin/realms/{1}/client-scopes/{2}/protocol-mappers/models".format(self.base_url, self.realm_name, client_scope_id),
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
        put(
            url="{0}/admin/realms/{1}/clients/{2}/default-client-scopes/{3}".\
                format(self.base_url, self.realm_name, client_id, scope_id),
            headers={"Authorization": self.access_token}
        )


class KeyCloakClientManagement(Base):
    def create_client_application(self, **payload):
        logoutUrl = payload.pop('logoutUrl')
        response = post(
            url="{0}/admin/realms/{1}/clients".format(self.base_url, self.realm_name),
            data=json.dumps(dict(
                **payload,
                baseUrl=payload['rootUrl'],
                name=payload.get('clientId'), webOrigins=["*"], publicClient=True,
                attributes={"post.logout.redirect.uris": logoutUrl},
            )),
            headers={"Authorization": self.access_token,
                     'Content-Type': 'application/json'}
        )
        if response.status_code != 201:
            raise Exception("Error in creating client due to %s "%response.json().get('errorMessage'))

        return True, "Created Successfully", self.get_client_applications(search=payload['clientId'])[0]

    def get_client_applications(self, search=None):
        response = get(
            url="{0}/admin/realms/{1}/clients".format(self.base_url, self.realm_name),
            headers={"Authorization": self.access_token}
        )
        if response.status_code != 200:
            raise Exception("Error in getting client applications")

        if search is not None:
            return [dict(id=x['id'], name=x['name']) for x in response.json() if x['name'] == search]
        else:
            return [dict(id=x['id'], name=x['name']) for x in response.json()]

    def update_client_application(self, client_id, **payload):
        logoutUrl = payload.pop('logoutUrl')
        print("payload" , payload)
        response = put(
            url="{0}/admin/realms/{1}/clients/{2}".format(self.base_url, self.realm_name, client_id),
            data=json.dumps(dict(
                **payload,
                baseUrl=payload['rootUrl'],
                name=payload.get('clientId'), webOrigins=["*"], publicClient=True,
                attributes={"post.logout.redirect.uris": logoutUrl},
            )),
            headers={"Authorization": self.access_token,
                     'Content-Type': 'application/json'}
        )
        if response.status_code != 204:
            raise Exception("Error in updating client")

        return True, "Updated Successfully", self.get_client_applications(search=payload['clientId'])[0]

    def delete_client(self, client_id):
        response = delete(
            url="{0}/admin/realms/{1}/clients/{2}".format(self.base_url, self.realm_name, client_id),
            headers={"Authorization": self.access_token}
        )
        print(response.status_code)

class KeyCloakAuthSettings(Base):
    def set_authentication(self, allow_user_registration=False, verify_user_email=False, allow_forget_email=False,
                           token_expiration=84000):
        # Allow SuperAdmin to set up an authentication system for given realm

        response = put(
            url="{0}/admin/realms/{1}".format(self.base_url, self.realm_name),
            data=json.dumps(dict(
                registrationAllowed=allow_user_registration,
                verifyEmail=verify_user_email,
                resetPasswordAllowed=allow_forget_email,
                accessTokenLifespan=token_expiration,
                ssoSessionMaxLifespan=token_expiration,
            )),
            headers={"Authorization": self.access_token,
                     'Content-Type': 'application/json'}
        )
        if response.status_code != 204:
            raise Exception(
                "Error in creating auth settings due to error in keycloak %s" % \
                (response.json().get('error') or response.json().get('errorMessage'))
            )
        else:
            return True, "Successfully created"

    def update_email_settings(self, **payload):
        response = put(
            url="{0}/admin/realms/{1}".format(self.base_url, self.realm_name),
            data=json.dumps(
                dict(smtpServer={
                    "auth": True,
                    "from": payload['email'],
                    "user":payload['email'],
                    "password": payload.get('password'),
                    "replyTo": payload['reply_to'],
                    "fromDisplayName": payload['display_name'],
                    "starttls": True,
                    "host": payload['host'], "port": payload['port'],
                })),
            headers={"Authorization": 'Bearer %s' % self.get_master_access_token(),
                     'Content-Type': 'application/json'}
        )
        if response.status_code != 204:
            raise Exception(
                "Error in updating organization due to error in keycloak %s" % \
                (response.json().get('error') or response.json().get('errorMessage'))
            )
        else:
            return True, "Successfully created"

    def set_active_directory(self, client_id, tenant_id, client_secret):
        base_url = "https://login.microsoftonline.com"
        response = post(
            url="{0}/admin/realms/{1}/identity-provider/instances".format(self.base_url, self.realm_name),
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
            headers={"Authorization": 'Bearer %s' % self.get_master_access_token(),
                     'Content-Type': 'application/json'},
        )

    def get_active_directory_detail(self):
        response = get(
            url="{0}/admin/realms/{1}/identity-provider/instances".format(self.base_url, self.realm_name),
            headers={"Authorization": self.access_token}
        )
        if response.status_code != 200:
            raise Exception("Error in getting client applications")

        data_list = list()
        for ad in response.json():
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
        response = post(
            url="{base_url}/admin/realms/{realm}/users".format(base_url=self.base_url, realm=self.realm_name),
            data=json.dumps(dict(
                **payload,
                credentials=[{"type": "password", "value": "#Nimbus", "temporary": True}],
            )),
            headers={"Authorization": self.access_token,
                     'Content-Type': 'application/json'},
        )
        if response.status_code != 201:
            raise Exception("Error in creating user in Keycloak %s" % (response.json().get('errorMessage') or response.json().get('error')))

        user_info = self.get_users(username=payload['username'])[0]

        for group_id in group_ids:

            self.assign_user_to_group(
                user_id=user_info['id'], group_id=group_id
            )


        return True, "Created Successfully"

    def get_users(self, username=None, permissions=True):
        url = "{0}/admin/realms/{1}/users".format(self.base_url, self.realm_name)
        if username: url = f'{url}?username={username}'

        response = get(url=url, headers={"Authorization": self.access_token})
        if response.status_code == 200:
            user_details = list()
            for user_info in response.json():
                data_dict = dict(
                    id=user_info['id'],
                    username=user_info['username'],
                    email=user_info['email'],
                    first_name=user_info['firstName'],
                    last_name=user_info['lastName'],
                    enabled=user_info['enabled'],
                    email_verified=user_info['emailVerified'],
                    groups=self.get_groups_for_user(user_info['id']),
                )
                if permissions:
                    data_dict['permission'] = self.get_group_and_attributes_for_user(user_info['id'])
                user_details.append(data_dict)
            return user_details
        else:
            error_message = parse_error_message(response)
            print("response", response.json())
            raise Exception("Failed to retrieve users from Keycloak due to %s" % error_message)

    def update_user_details(self, user_id, payload):
        response = put(
            url=f'{self.base_url}/admin/realms/{self.realm_name}/users/{user_id}',
            data=json.dumps(payload),
            headers={"Authorization": self.access_token}
        )

        if response.status_code !=204:
            raise Exception("Error in updating user information at keyclock due to %s" % (response.json().get('errorMessage') or response.json().get('error')))

    def delete_user(self, user_id):
        response = delete(
            url=f"{self.base_url}/admin/realms/{self.realm_name}/users/{user_id}",
            headers={"Authorization": self.access_token}
        )

        if response.status_code != 204:
            raise Exception("delete not happened ")

    def reset_user_password(self, user_id):
        response = put(
            url=f'{self.base_url}/admin/realms/{self.realm_name}/users/{user_id}/reset-password',
            data=json.dumps(
                {"type": "password", "value": "*Nimbus", "temporary": True}
            ),
            headers={"Authorization": 'Bearer %s' % self.get_master_access_token(),
                     'Content-Type': 'application/json'},
        )
        if response.status_code != 204:
            raise Exception("Error in creating user in Keycloak %s" % response.json().get('errorMessage') or response.json().get('error'))

    def get_total_users(self):
        return len(self.get_users())

    def create_group(self, group_name, attributes={}):
        print("attributes", attributes)
        response = post(
            url="{0}/admin/realms/{1}/groups".format(self.base_url, self.realm_name),
            data=json.dumps({"name": group_name, "attributes": attributes}),
            headers={"Authorization": self.access_token,
                     'Content-Type': 'application/json'}
        )
        if response.status_code == 201:
            groups = self.get_all_groups(self.realm_name)
            groups = next(filter(lambda x: x['name'] == group_name, groups), None)
            print("groups", groups)
            groups['permissions'] = self.format_attributes(attributes=self.get_all_groups(group_id=groups['id'])['permissions'])

            if groups['name'] == 'ADMIN':
                realm_admin_role_client = self.get_groups_realm_roles(search="realm_admin", group_id=groups['id'])[0]
                self.assign_realm_role_to_group(groups['id'], realm_admin_role_client)
            return groups
        raise Exception("Error in creating Group in Keycloak due to %s" % response.json().get('errorMessage') or response.json().get('error'))

    def get_all_groups(self, realm_name=None, search=None, exact=False, group_id=None, user_details=False):
        url = "{0}/admin/realms/{1}/groups".format(self.base_url, realm_name or self.realm_name)
        if search: url = f'{url}?search={search}&exact={exact}'
        if group_id:url = f'{url}/{group_id}'

        response = get(url=url, headers={"Authorization": self.access_token})
        if response.status_code != 200:
            raise Exception("Error in getting groups due to error in keycloak due to %s" % response.json().get('errorMessage'))
        if group_id and response.json():
            data = response.json()
            [data.pop(x) for x in ['subGroups', 'access', 'clientRoles', 'realmRoles', 'subGroupCount', 'path']]
            data['permissions'] = self.format_attributes(data.pop('attributes'))
            if user_details:
                data['users'] = self.users_based_on_group(group_id=group_id)
            return data
        return [dict(id=j['id'], name=j['name']) for j in response.json()]

    def update_group_details(self, new_group_name, group_id, attributes={}):
        response = put(
            url=f"{self.base_url}/admin/realms/{self.realm_name}/groups/{group_id}",
            data=json.dumps({"name": new_group_name, "attributes": attributes}),
            headers={"Authorization": self.access_token,
                     'Content-Type': 'application/json'}
        )

        if response.status_code != 204:
            raise Exception("Error in renaming group in Keycloak %s" % (response.json().get('errorMessage') or response.json().get('error')))

        group_info = self.get_all_groups(realm_name=self.realm_name, group_id=group_id)
        # if group_info['name'] == 'ADMIN':
        #     realm_admin_role_client = self.get_groups_realm_roles(search="realm_admin", group_id=group_id)[0]
        #     print("realm_admin_role_client", realm_admin_role_client)
        #     self.assign_realm_role_to_group(group_id, realm_admin_role_client)
        return group_info

    def delete_group(self, group_id):
        response = delete(
            url=f"{self.base_url}/admin/realms/{self.realm_name}/groups/{group_id}",
            headers={"Authorization": self.access_token,
                     'Content-Type': 'application/json'}
        )
        if response.status_code != 204:
            raise Exception("Error in renaming group in Keycloak %s" % (response.json().get('errorMessage') or response.json().get('error')))

    def assign_user_to_group(self, user_id, group_id):
        url = '{base_url}/admin/realms/{realm_name}/users/{user_id}/groups/{group_id}'.format(
            base_url=self.base_url, realm_name=self.realm_name, user_id=user_id, group_id=group_id
        )
        response = put(url=url, headers={"Authorization": self.access_token})
        return response

    def get_groups_for_user(self, user_id):
        response = get(
            url="{0}/admin/realms/{1}/users/{2}/groups".format(self.base_url, self.realm_name, user_id),
            headers={"Authorization": self.access_token}
        )
        if response.status_code == 200:
            groups = list(dict(
                id=x['id'], name=x['name']
            ) for x in response.json())
            return groups
        else:
            return []

    def get_group_and_attributes_for_user(self, user_id):
        user_groups = self.get_groups_for_user(user_id)
        user_permissions = {}

        for group in user_groups:
            attributes = self.get_all_groups(group_id=group['id']).get('permissions')
            user_permissions.update(self.format_attributes(attributes))

        return user_permissions


    def format_attributes(self, attributes):
        if attributes:
            for key, value in attributes.items():
                if value is None:
                    attributes[key] = None
                else:
                    attributes[key] = value
        return attributes

    def users_based_on_group(self, group_id):
        response = get(
            url = "{0}/admin/realms/{1}/groups/{2}/members".format(self.base_url, self.realm_name, group_id),
            headers={"Authorization": self.access_token},
        )
        return self.parse_user_details(response.json()) if response.status_code == 200 else []

    def get_groups_realm_roles(self, group_id=None, search=None):
        response = getAPI(
            url="{0}/admin/realms/{1}/ui-ext/available-roles/groups/{2}?search={3}".\
                format(self.base_url, self.realm_name, group_id, search),
            headers={"Authorization": self.access_token}
        )
        return response


    def assign_realm_role_to_user(self, user_id, client_role_id):
        response = post(
           url="{0}/admin/realms/{1}/users/{2}/role-mappings/clients/3/".format(
               self.base_url, self.realm_name, user_id, client_role_id,),
            headers={"Authorization": self.access_token}
        )
        print("response", response.status_code)

    def assign_realm_role_to_group(self, group_id, client_role_details):
        print("Assigning Role", client_role_details)
        response = post(
            url="{0}/admin/realms/{1}/groups/{2}/role-mappings/clients/{3}".format(
               self.base_url, self.realm_name, group_id, client_role_details['clientId']),
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
        response = getAPI(
            url="{0}/realms/{1}/protocol/openid-connect/userinfo".format(self.base_url, self.realm_name),
            headers={"Authorization": self.access_token}    # This token has prefix Bearer
        )
        return self.get_users(username=response['preferred_username'], permissions=True)


class KeycloakRester(KeyCloakUserManagement, KeyCloakRealmManagement, KeyCloakAuthSettings, KeyCloakClientManagement):

    def add_user_into_group(self, realm_name, username, group_name, master_token=None):
        master_token = master_token or self.get_master_access_token()
        groups = self.get_all_groups(realm_name, search=group_name, exact=True)
        group = next(filter(lambda x: x['name'] == group_name, groups), None)
        users = self.get_users(realm_name, username)
        group_id = group['id']

        if group and users:
            user_instance = User.objects.get(username=username)
            for user in users:
                user_id = user['id']
                put(
                    url="{0}/admin/realms/{1}/users/{2}/groups/{3}".format(self.base_url, realm_name, user_id,
                                                                           group_id),
                    data=json.dumps({"name": group_name, "path": "/new_group"}),
                    headers={"Authorization": 'Bearer %s' % master_token,
                             'Content-Type': 'application/json'}
                )

                user_instance.groups.add(Group.objects.get_or_create(name=group_name)[0])

    def remove_user_from_group(self, realm_name, username, group_name):
        # master_token = self.get_master_access_token()
        groups = self.get_all_groups(realm_name, search=group_name, exact=True)
        group = next(filter(lambda x: x['name'] == group_name, groups), None)
        users = self.get_users(realm_name, username)
        group_id = group['id']

        if group and users:
            user_instance = User.objects.get(username=username)
            for user in users:
                pass

    def get_user_info(self, realm_name, access_token):
        response = get(
            url="{0}/realms/{1}/protocol/openid-connect/userinfo".format(self.base_url, realm_name),
            headers={"Authorization": access_token})
        print("response", response.status_code)
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
        print("user_id", user_id)
        return self.get_user_based_on_user_id(realm_name=realm_name, user_id=user_id)

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
        response = delete(url=url, headers={"Authorization": self.access_token})
        print("response", response.status_code)



    def get_group_attributes(self, group_id):
        pass



