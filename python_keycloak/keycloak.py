from .compose import base64, json, Base, fetch_data

from .views_realm import KeyCloakRealmManagement, KeyCloakAuthSettings, KeyCloakClientManagement
from .views_user import KeyCloakUserManagement


class KeycloakRester(KeyCloakRealmManagement, KeyCloakAuthSettings, KeyCloakClientManagement, KeyCloakUserManagement):

    def get_user_info(self, realm_name, access_token):
        response = fetch_data(
            url=self.URL_USER_INFO.format(realm_name=self.realm_name),
            headers={"Authorization": access_token})
        return response

    def get_user_based_on_user_id(self, realm_name, user_id):
        master_token = self.get_master_access_token()
        response = fetch_data(
            url=self.URL_GET_USERS_BY_ID.format(realm_name=self.realm_name, user_id=user_id),
            headers={"Authorization": 'Bearer %s' % master_token})
        return response

    def get_user_based_on_token(self, realm_name, access_token):
        token_parts = access_token.split('.')
        decoded_token = base64.b64decode(token_parts[1] + '==').decode('utf-8')
        token_json = json.loads(decoded_token)
        user_id = token_json['sub']
        return self.get_user_based_on_user_id(realm_name=realm_name, user_id=user_id)

