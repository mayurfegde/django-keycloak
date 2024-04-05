from .compose import Base, json, format_attributes,\
    fetch_data, create_data, update_data, delete_data


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
        update_data(
            url=self.URL_UPDATE_USER.format(realm_name=self.realm_name, user_id=user_id),
            data=json.dumps(payload),
            headers={"Authorization": self.access_token}
        )

    def delete_user(self, user_id):
        delete_data(
            url=self.URL_UPDATE_USER.format(realm_name=self.realm_name, user_id=user_id),
            headers={"Authorization": self.access_token}
        )

    def reset_user_password(self, user_id, default_password="*Nimbus", temporary=True):
        update_data(
            url=self.URL_USER_RESET_PASSWORD.format(realm_name=self.realm_name, user_id=user_id),
            data=json.dumps({"type": "password", "value": default_password, "temporary": temporary}),
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
        update_data(
            url = self.URL_ADD_USER_TO_GROUP.format(realm_name=self.realm_name, user_id=user_id, group_id=group_id),
            headers={"Authorization": self.access_token}
        )

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
            url = self.URL_REMOVE_USER_FROM_GROUP.format(
            realm_name=self.realm_name, user_id=user_id, group_id=group_id
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
            url=self.URL_USER_INFO.format(realm_name=self.realm_name),
            headers={"Authorization": self.access_token}    # This token has prefix Bearer
        )
        return self.get_users(user_id=response['sub'])[0]