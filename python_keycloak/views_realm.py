from .compose import Base, json, format_attributes,\
    fetch_data, create_data, update_data, delete_data



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
        return dict(id=response['id'])

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