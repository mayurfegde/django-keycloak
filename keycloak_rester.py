import base64
import json
import typing

import requests

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group

User = get_user_model()


def get(**kwargs):
    return requests.get(**kwargs)


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

class KeycloakRester(object):
    base_url = "http://192.168.1.5:8080"

    def __init__(self, realm_name=None, access_token=None):
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

    def get_realm_detail(self, realm_name: str = None):
        response = get(
            url="{0}/admin/realms".format(self.base_url),
            headers={"Authorization": self.access_token}
        )
        if response.status_code == 200:
            return [
                dict(id=x['id']) for x in response.json() if x['realm'] == realm_name or self.realm_name
            ][0]

        raise Exception("Error in getting Organization")

    def update_realm(self, realm_name: str = None, is_active: bool = True):
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

    def create_realm_client_scope(self):
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

    def make_default_realm_client_scope(self, client_realm_scope_id):
        response = put(
            url=f'{self.base_url}/admin/realms/{self.realm_name}/default-default-client-scopes/{client_realm_scope_id}',
            headers={"Authorization": self.access_token}
        )

        print("response.status_code", response.status_code)

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
        response = put(
            url="{0}/admin/realms/{1}/clients/{2}/default-client-scopes/{3}".format(self.base_url, self.realm_name,
                                                                                    client_id, scope_id),
            headers={"Authorization": self.access_token}
        )
        print("Assign status",response.status_code)

    def get_realm_client_scope(self, client_realm_scope):
        response = get(
            url="{0}/admin/realms/{1}/client-scopes".format(self.base_url, self.realm_name),
            headers={"Authorization": self.access_token,
                     'Content-Type': 'application/json'},
        )

        if response.status_code == 200:
            return [dict(id=x['id'], name=x['name']) for x in response.json() if x['name'] == client_realm_scope][0]

        raise Exception("Error in getting client scope")

    def get_all_groups(self, realm_name=None, search=None, exact=False):
        url = "{0}/admin/realms/{1}/groups".format(self.base_url, realm_name or self.realm_name)
        if search: url = f'{url}?search={search}&exact={exact}'

        response = get(url=url, headers={"Authorization": self.access_token})
        if response.status_code != 200:
            raise Exception("Error in getting groups due to error in keycloak")

        return [dict(id=j['id'], name=j['name']) for j in response.json()]

    def create_group(self, group_name):
        response = post(
            url="{0}/admin/realms/{1}/groups".format(self.base_url, self.realm_name),
            data=json.dumps({"name": group_name, "path": "/new_group"}),
            headers={"Authorization": self.access_token,
                     'Content-Type': 'application/json'}
        )
        groups = []
        if response.status_code == 201:
            groups = self.get_all_groups(self.realm_name)
            groups = next(filter(lambda x: x['name'] == group_name, groups), None)
            return groups
        raise Exception("Error in creating Group in Keycloak due to %s" % response.json().get('errorMessage') or response.json().get('error'))

    def get_users(self, username=None):
        url = "{0}/admin/realms/{1}/users".format(self.base_url, self.realm_name)
        if username: url = f'{url}?username={username}'

        response = get(url=url, headers={"Authorization": self.access_token})
        if response.status_code == 200:
            user_details = list()

            for user_info in response.json():
                user_details.append(dict(
                    id=user_info['id'],
                    username=user_info['username'],
                    email=user_info['email'],
                    first_name=user_info['firstName'],
                    last_name=user_info['lastName'],
                    enabled=user_info['enabled'],
                    email_verified=user_info['emailVerified'],
                    groups=self.get_groups_for_user(user_info['id']),
                ))
            return user_details
        else:
            raise Exception("Failed to retrieve users from Keycloak")

    def get_groups_for_user(self, user_id):
        response = get(
            url="{0}/admin/realms/{1}/users/{2}/groups".format(self.base_url, self.realm_name, user_id),
            headers={"Authorization": self.access_token}
        )
        if response.status_code == 200:
            return response.json()
        else:
            return []

    def assign_user_to_group(self, user_id, group_id):
        url = '{base_url}/admin/realms/{realm_name}/users/{user_id}/groups/{group_id}'.format(
            base_url=self.base_url, realm_name=self.realm_name, user_id=user_id, group_id=group_id
        )
        response = put(url=url, headers={"Authorization": self.access_token})
        print("response", response.status_code)

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
        return self.get_user_based_on_user_id(realm_name="master", user_id=user_id)

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
        print("response.status_code", response.status_code)
        if response.status_code != 204:
            raise Exception(
                "Error in updating organization due to error in keycloak %s" % \
                (response.json().get('error') or response.json().get('errorMessage'))
            )
        else:
            return True, "Successfully created"

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
            raise Exception("Error in creating client")

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

    def assign_groups_to_user(self, user_id, group_ids):
        for group_id in group_ids:
            self.assign_user_to_group(
                user_id=user_id, group_id=group_id
            )

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
        print("response", response.json())
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

    def update_group_details(self, new_group_name, group_id):
        response = put(
            url=f"{self.base_url}/admin/realms/{self.realm_name}/groups/{group_id}",
            data=json.dumps({"name": new_group_name}),
            headers={"Authorization": self.access_token,
                     'Content-Type': 'application/json'}
        )
        print("status code: ", response.status_code)

        if response.status_code != 204:
            raise Exception("Error in renaming group in Keycloak %s" % (response.json().get('errorMessage') or response.json().get('error')))
        return self.get_all_groups(realm_name=self.realm_name, search=new_group_name, exact=True)[0]

    def delete_group(self, group_id):
        response = delete(
            url=f"{self.base_url}/admin/realms/{self.realm_name}/groups/{group_id}",
            headers={"Authorization": self.access_token,
                     'Content-Type': 'application/json'}
        )
        if response.status_code != 204:
            raise Exception("Error in renaming group in Keycloak %s" % (response.json().get('errorMessage') or response.json().get('error')))


    def delete_user(self, user_id):
        response = delete(
            url=f"{self.base_url}/admin/realms/{self.realm_name}/users/{user_id}",
            headers={"Authorization": self.access_token}
        )
        print("response", response.status_code)

        if response.status_code != 204:
            raise Exception("delete not happened ")


    def update_user_details(self, user_id, payload):
        response = put(
            url=f'{self.base_url}/admin/realms/{self.realm_name}/users/{user_id}',
            data=json.dumps(payload),
            headers={"Authorization": self.access_token}
        )

        if response.status_code !=204:
            raise Exception("Error in updating user information at keyclock due to %s" % (response.json().get('errorMessage') or response.json().get('error')))
