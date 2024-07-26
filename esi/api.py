import frappe
from frappe import _
import requests
import json
import base64

@frappe.whitelist(allow_guest=True)
def oauth2_login(code, state):
    try:
        # Fetch client details from Social Login Key doctype
        social_login_key = frappe.get_doc("Social Login Key", "esi")
        client_id = social_login_key.client_id
        client_secret = social_login_key.get_password("client_secret")
        base_url = social_login_key.base_url
        token_url = f"{base_url}{social_login_key.access_token_url}"
        redirect_uri = social_login_key.redirect_url

        # Decode the state parameter
        state_data = json.loads(base64.b64decode(state).decode('utf-8'))

        # Create the authorization header
        auth_header = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Basic {auth_header}"
        }
        payload = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri
        }

        response = requests.post(token_url, headers=headers, json=payload)
        response.raise_for_status()

        token_info = response.json()
        # Extract token information
        access_token = token_info.get('access_token')
        refresh_token = token_info.get('refresh_token')
        expires_in = token_info.get('expires_in')

        # Fetch user information from EVE Online's verify endpoint
        verify_url = social_login_key.api_endpoint
        verify_headers = {
            "Authorization": f"Bearer {access_token}"
        }

        verify_response = requests.get(verify_url, headers=verify_headers)
        verify_response.raise_for_status()

        user_info = verify_response.json()
        character_id = user_info.get('CharacterID')
        character_name = user_info.get('CharacterName')

        # Create or update the user account in Frappe
        user_name = frappe.db.get_value('User', {'username': character_name}, 'name')
        if not user_name:
            user = frappe.new_doc('User')
            user.update({
                'username': character_name,
                'first_name': character_name,
                'email': f"{character_id}@eveonline.com",
                'enabled': 1,
                'user_type': 'System User',
                'user_image': f"https://images.evetech.net/characters/{character_id}/portrait"
            })
            user.flags.ignore_permissions = True
            user.save()
            user_name = user.name
        
        # Createthe Character record if it does not exist
        character_doc_name = frappe.db.get_value('Character', {'name': character_name}, 'name')
        if not character_doc_name:
            character_doc = frappe.new_doc('Character')
            character_doc.character_id = character_id
            character_doc.character_name = character_name
            character_doc.name = character_name
            character_doc.user = user_name
            character_doc.flags.ignore_permissions = True
            character_doc.save()
        
        # Create or update the OAuth Token record
        oauth_token_name = frappe.db.get_value('OAuth Token', {'user': user_name}, 'name')
        if not oauth_token_name:
            oauth_token = frappe.new_doc('OAuth Token')
            oauth_token.user = user_name
            oauth_token.character = character_name
        else:
            oauth_token = frappe.get_doc('OAuth Token', oauth_token_name)

        

        oauth_token.update({
            'access_token': access_token,
            'refresh_token': refresh_token,
            'expires_in': int(expires_in),  # Ensure this is an integer
            'character': character_name
        })
        oauth_token.flags.ignore_permissions = True
        oauth_token.save()
        frappe.local.login_manager.login_as(user_name)
        frappe.local.response["type"] = "redirect"
        frappe.local.response["location"] = "/desk"
        frappe.utils

    except requests.exceptions.RequestException as e:
        frappe.log_error(message=str(e), title="OAuth2 Login Failed")
        frappe.throw(_("Failed to fetch OAuth2 token. Please check your credentials and try again."), frappe.AuthenticationError)
    except Exception as e:
        frappe.log_error(message=str(e), title="OAuth2 Login Error")
        frappe.throw(_("An unexpected error occurred during OAuth2 login."), frappe.AuthenticationError)


def refresh_oauth_token(token_name=None):
    try:
        # Fetch all OAuth Token records if token_name is not specified
        if token_name:
            oauth_tokens = frappe.get_all('OAuth Token', filters={"name": token_name}, fields=['name', 'user', 'refresh_token'])
        else:
            oauth_tokens = frappe.get_all('OAuth Token', fields=['name', 'user', 'refresh_token'])

        for token in oauth_tokens:
            refresh_token = token.refresh_token

            if not refresh_token:
                continue

            # Fetch client details from Social Login Key doctype
            social_login_key = frappe.get_doc("Social Login Key", "esi")
            client_id = social_login_key.client_id
            client_secret = social_login_key.get_password("client_secret")
            base_url = social_login_key.base_url
            token_url = f"{base_url}{social_login_key.access_token_url}"

            # Create the authorization header
            auth_header = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Basic {auth_header}"
            }
            payload = {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token
            }

            response = requests.post(token_url, headers=headers, json=payload)
            response.raise_for_status()

            token_info = response.json()

            # Extract new token information
            new_access_token = token_info.get('access_token')
            new_refresh_token = token_info.get('refresh_token', refresh_token)
            expires_in = token_info.get('expires_in')

            # Update the OAuth Token record
            oauth_token = frappe.get_doc('OAuth Token', token.name)
            oauth_token.update({
                'access_token': new_access_token,
                'refresh_token': new_refresh_token,
                'expires_in': int(expires_in)
            })
            oauth_token.flags.ignore_permissions = True
            oauth_token.save()

    except requests.exceptions.RequestException as e:
        frappe.log_error(message=str(e), title="OAuth2 Token Refresh Failed")
    except Exception as e:
        frappe.log_error(message=str(e), title="Unexpected Error in OAuth2 Token Refresh")
    try:
        # Fetch all OAuth Token records
        oauth_tokens = frappe.get_all('OAuth Token', fields=['name', 'user', 'refresh_token'])

        for token in oauth_tokens:
            refresh_token = token.refresh_token

            if not refresh_token:
                continue

            # Fetch client details from Social Login Key doctype
            social_login_key = frappe.get_doc("Social Login Key", "esi")
            client_id = social_login_key.client_id
            client_secret = social_login_key.get_password("client_secret")
            base_url = social_login_key.base_url
            token_url = f"{base_url}{social_login_key.access_token_url}"

            # Create the authorization header
            auth_header = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Basic {auth_header}"
            }
            payload = {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token
            }

            response = requests.post(token_url, headers=headers, json=payload)
            response.raise_for_status()

            token_info = response.json()

            # Extract new token information
            new_access_token = token_info.get('access_token')
            new_refresh_token = token_info.get('refresh_token', refresh_token)
            expires_in = token_info.get('expires_in')

            # Update the OAuth Token record
            oauth_token = frappe.get_doc('OAuth Token', token.name)
            oauth_token.update({
                'access_token': new_access_token,
                'refresh_token': new_refresh_token,
                'expires_in': int(expires_in)
            })
            oauth_token.flags.ignore_permissions = True
            oauth_token.save()

    except requests.exceptions.RequestException as e:
        frappe.log_error(message=str(e), title="OAuth2 Token Refresh Failed")
    except Exception as e:
        frappe.log_error(message=str(e), title="Unexpected Error in OAuth2 Token Refresh")

def get_oauth_details():
    social_login_key = frappe.get_doc("Social Login Key", "esi")
    oauth_token = frappe.get_all("OAuth Token", filters={}, fields=["name", "access_token", "refresh_token"])

    if not oauth_token:
        frappe.throw("No OAuth Token found for the service 'esi'")

    oauth_details = {
        "client_id": social_login_key.client_id,
        "client_secret": social_login_key.client_secret,
        "access_token": frappe.get_value("OAuth Token", oauth_token[0].name, "access_token"),
        "refresh_token": frappe.get_value("OAuth Token", oauth_token[0].name, "refresh_token"),
        "base_url": social_login_key.base_url,
        "token_name": oauth_token[0].name
    }
    return oauth_details

def fetch_data(character_id, endpoint):
    oauth_details = get_oauth_details(character_id)
    url = f"https://esi.evetech.net/latest{endpoint}"
    headers = {
        "Authorization": f"Bearer {oauth_details['access_token']}"
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 401:
        refresh_oauth_token(oauth_details['token_name'])
        oauth_details = get_oauth_details(character_id)
        headers["Authorization"] = f"Bearer {oauth_details['access_token']}"
        response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        frappe.log_error(message=f"Failed to fetch data from {endpoint}. Status Code: {response.status_code}, Response: {response.text}", title="Data Fetch Failed")
        frappe.throw(f"Failed to fetch data from {endpoint}")

def sync_data_to_erpnext(data, doctype):
    # Get the meta for the doctype to ensure proper field mapping
    doctype_meta = frappe.get_meta(doctype)
    valid_fields = {field.fieldname for field in doctype_meta.fields}

    for item in data:
        # Filter out invalid fields
        valid_data = {key: value for key, value in item.items() if key in valid_fields}
        
        doc = frappe.get_doc({
            "doctype": doctype,
            **valid_data
        })
        doc.insert(ignore_permissions=True)
        frappe.db.commit()


@frappe.whitelist()
def sync_swagger_data():
    # Fetch character wallet journal data
    character_wallet_journal_data = fetch_data("/characters/667496692/wallet/journal/")
    sync_data_to_erpnext(character_wallet_journal_data, "Character Wallet Journal")

    # Fetch character wallet transaction data
    character_wallet_transaction_data = fetch_data("/characters/667496692/wallet/transactions/")
    sync_data_to_erpnext(character_wallet_transaction_data, "Character Wallet Transaction")
