import os
from pathlib import Path
import requests
import json
from key_common import *

PUB_ID_PREFIX = "pub_id_"

def retrieve_keys_handler(baseReq, env, token):
    headers = {'X-Vault-Token': token}
    response = {}
    response['cmd'] = GET_KEYS_CMD

    val = get_consortium_keys(baseReq, env, headers)
    if val:
        response['consortium'] = val

    val = get_publishers_keys(baseReq, env, headers)
    if val:
        response['publishers'] = val

    return response

def retrieve_ckeys_handler(baseReq, env, token):
    headers = {'X-Vault-Token': token}
    response = {}
    response['cmd'] = GET_CKEYS_CMD

    val = get_consortium_keys(baseReq, env, headers)
    if val:
        response['consortium'] = val

    return response

def retrieve_pkeys_handler(baseReq, env, token, pub_id):
    headers = {'X-Vault-Token': token}
    response = {}
    response['cmd'] = GET_PKEYS_CMD

    if not pub_id:
        return response
    else:
        publisher = {}
        val = []
        publisher['keys'], publisher['pub_id'], publisher['name'] = get_pub_keys(baseReq, env, headers, "pub_id_{}".format(pub_id))
        if not publisher['keys'] or not publisher['pub_id']:
            return response
            
        val.append(publisher)
        if val:
            response['publishers'] = val

    return response

def get_consortium_keys(baseReq, env, headers):
    try:
        vaultReq = baseReq + "/v1/secret/data/" + env + "/consortium"
        r = requests.get(url=vaultReq, headers=headers)
        consortium_keys = json.loads(r.text)
        for consortium_key in consortium_keys['data']['data']['consortium_keys']:
            key_id  = consortium_key['key_id']
            key     = consortium_key['key']
            issued  = consortium_key['issued']
            print("key={}, key_id={}, issued={}".format(key, key_id, issued))

        return consortium_keys['data']['data']['consortium_keys']
    except Exception as e:
        print('error in getting consortium keys: {}'.format(e))
    return None

def get_pub_keys(baseReq, env, headers, pub_id):
    try:
        vaultReq = baseReq + "/v1/secret/data/" + env + "/publisher/{}".format(pub_id)
        r = requests.get(url=vaultReq, headers=headers)
        if r.ok:
            pub_keys = json.loads(r.text)
            name = pub_keys['data']['data']['name'] if pub_keys['data']['data']['name'] else "unknown"

            for pub_key in pub_keys['data']['data']['publisher_keys']:
                key_id  = pub_key['key_id']
                key     = pub_key['key']
                issued  = pub_key['issued'] if 'issued' in pub_key.keys() else None
                expires = pub_key['expires'] if 'expires' in pub_key.keys() else None
                print("key={}, key_id={}, issued={}, expires={}, name={}".format(key, key_id, issued, expires, name))

            return pub_keys['data']['data']['publisher_keys'], pub_id[len(PUB_ID_PREFIX):], name
    except Exception as e:
        print('error in getting publisher key({}): {}'.format(vaultReq, e))
    return None, None, None

def delete_pub_keys(baseReq, env, headers, pub_id):
    try:
        vaultReq = baseReq + "/v1/secret/metadata/" + env + "/publisher/pub_id_{}".format(pub_id)
        r = requests.delete(url=vaultReq, headers=headers)

        return r.ok
    except Exception as e:
        print('error in deleting publisher keys({}): {}'.format(vaultReq, e))
    return False

def get_publishers_keys(baseReq, env, headers):
    try:
        vaultReq = baseReq + "/v1/secret/metadata/" + env + "/publisher/?list=true"
        r = requests.get(url=vaultReq, headers=headers)
        if r.ok:
            pub_ids = json.loads(r.text)
            response = []
            for pub_id in pub_ids['data']['keys']:
                publisher = {}
                publisher['keys'], publisher['pub_id'], publisher['name'] = get_pub_keys(baseReq, env, headers, pub_id)
                response.append(publisher)
            return response

    except Exception as e:
        print('error in getting publishers keys: {}'.format(e))
    return None

def create_pub_token_handler(baseReq, token, role_id, secret_id):
    try:
        response = {}
        response['cmd'] = CREATE_TOKEN_CMD
        vaultReq = baseReq + "/v1/auth/approle/login"
        data = { "role_id": role_id,
                 "secret_id": secret_id }

        r = requests.post(url=vaultReq, data = json.dumps(data))
        vaultRes = json.loads(r.text)
        if vaultRes['auth']['client_token']:
            response['token'] = vaultRes['auth']['client_token']
            response['ret'] = True
    except Exception as e:
        print('error in creating a publisher token: {}'.format(e))
        response['ret'] = False
    return response

def revoke_pub_token_handler(baseReq, token, token_revoke):
    try:
        headers = {'X-Vault-Token': token}
        response = {}
        response['cmd'] = REVOKE_TOKEN_CMD
        response['token'] = token
        response['token_revoke'] = token_revoke
        vaultReq = baseReq + "/v1/auth/token/revoke"
        data = { "token": token_revoke }

        r = requests.post(url=vaultReq, headers=headers, data = json.dumps(data))
        response['ret'] = True if r.ok else False
    except Exception as e:
        print('error in revoking a publisher token: {}'.format(e))
        response['ret'] = False
    return response

def check_pub_role(baseReq, headers, pub_id):
    try:
        vaultReq = baseReq + f"/v1/auth/approle/role/publisher_{pub_id}"
        r = requests.get(url=vaultReq, headers=headers)
        vaultRes = json.loads(r.text)

        if not 'data' in vaultRes.keys():
            return True 
    except Exception as e:
        print(f'error in checking publisher role : {e}')
    return False

def create_pub_role(baseReq, headers, pub_id):
    try:
        vaultReq = baseReq + f"/v1/auth/approle/role/publisher_{pub_id}"
        data = { 'policies': [
            "consortium_ro",
            f"pub_{pub_id}_rw"
        ]}
        r = requests.post(url=vaultReq, headers=headers, data=json.dumps(data))

        return True if r.ok else False
    except Exception as e:
        print(f'error in creating a publisher role : {e}')
    return False

def delete_pub_role(baseReq, headers, pub_id):
    try:
        vaultReq = baseReq + f"/v1/auth/approle/role/publisher_{pub_id}"
        r = requests.delete(url=vaultReq, headers=headers)

        return r.ok
    except Exception as e:
        print(f'error in deleting a publisher role : {e}')
    return False


def create_pub_policy(baseReq, headers, pub_id):
    try:
        vaultReq = baseReq + f"/v1/sys/policy/pub_{pub_id}_rw"
        hclFile = os.path.dirname(Path(__file__).absolute()) + "/pub_policy.hcl"
        print(f"{vaultReq}, {hclFile}")
        with open(hclFile) as pub_policy_hcl:
            pub_policy = pub_policy_hcl.read()
        pub_policy = pub_policy.replace('pub_id_n', f"pub_id_{pub_id}")
        pub_policy = pub_policy.replace('"', '\"')

        data = { "policy": pub_policy }

        r = requests.put(url=vaultReq, headers=headers, data=json.dumps(data))

        return True if r.ok else False
    except Exception as e:
        print(f'error in checking publisher policy : {e}')
    return False

def delete_pub_policy(baseReq, headers, pub_id):
    try:
        vaultReq = baseReq + f"/v1/sys/policy/pub_{pub_id}_rw"
        r = requests.delete(url=vaultReq, headers=headers)

        return r.ok
    except Exception as e:
        print(f'error in deleting publisher policy : {e}')
    return False

def read_role_id(baseReq, headers, pub_id):
    try:
        vaultReq = baseReq + f"/v1/auth/approle/role/publisher_{pub_id}/role-id"
        r = requests.get(url=vaultReq, headers=headers)
        vaultRes = json.loads(r.text)
        if 'data' in vaultRes.keys():
            return vaultRes['data']['role_id'] 
    except Exception as e:
        print(f'error in reading publisher role_id : {e}')
    return None

def pull_secret_id(baseReq, headers, pub_id):
    try:
        vaultReq = baseReq + f"/v1/auth/approle/role/publisher_{pub_id}/secret-id"
        r = requests.post(url=vaultReq, headers=headers)
        vaultRes = json.loads(r.text)
        if 'data' in vaultRes.keys():
            return vaultRes['data']['secret_id'] 
    except Exception as e:
        print(f'error in pulling publisher secret_id : {e}')
    return None

def create_publisher_handler(baseReq, token, pub_id):
    try:
        headers = {'X-Vault-Token': token}
        response = {}
        response['cmd'] = CREATE_PUB_CMD
        
        """ check if publisher with pub_id already exists in KMS """
        if not check_pub_role(baseReq, headers, pub_id):
            raise Exception(f'pub_id_{pub_id} role exists')

        """ create a policy for a new publisher """
        if not create_pub_policy(baseReq, headers, pub_id):
            raise Exception(f'pub_id_{pub_id} policy exists')
        
        """ create a role for a new publisher """
        if not create_pub_role(baseReq, headers, pub_id):
            raise Exception(f"error : can't create pub_id_{pub_id}'s role")

        """ read role_id """
        role_id = read_role_id(baseReq, headers, pub_id)
        if not role_id:
            raise Exception(f"error : can't read pub_id_{pub_id}'s role_id")

        """ pull secret_id """
        secret_id = pull_secret_id(baseReq, headers, pub_id)
        if not secret_id:
            raise Exception(f"error : can't pull pub_id_{pub_id}'s secret_id")

        """ create a token """
        res = create_pub_token_handler(baseReq, token, role_id, secret_id)
        if not res['ret']:
            raise Exception(f"error : can't creat a token for pub_id_{pub_id}")

        response['ret'] = True
        response['role_id'] = role_id
        response['secret_id'] = secret_id
        response['token'] = res['token']
    except Exception as e:
        print('error in creating a publisher : {}'.format(e))
        response['ret'] = False
    return response

def delete_publisher_handler(baseReq, env, token, pub_id):
    try:
        headers = {'X-Vault-Token': token}
        response = {}
        response['cmd'] = DELETE_PUB_CMD
        response['pub_id'] = pub_id
        
        """ delete a role of a publisher """
        if not delete_pub_role(baseReq, headers, pub_id):
            raise Exception(f"error : can't delete pub_id_{pub_id}'s role")

        """ delete a policy of a publisher """
        if not delete_pub_policy(baseReq, headers, pub_id):
            raise Exception(f'error : pub_id_{pub_id} policy exists')
        
        """ delete all publisher keys """
        if not delete_pub_keys(baseReq, env, headers, pub_id):
            raise Exception(f'error : fail to delete publisher keys (pub_id_{pub_id})')

        response['ret'] = True
    except Exception as e:
        print('error in deleting a publisher : {}'.format(e))
        response['ret'] = False
    return response

def put_ckeys_handler(baseReq, env, token, uploadKeys):
    try:
        vaultReq = baseReq + "/v1/secret/data/" + env + "/consortium"
        headers = {'X-Vault-Token': token}
        data = { "data": uploadKeys}
        response = {}
        response['cmd'] = PUT_CKEYS_CMD
        print(data)
        r = requests.post(url=vaultReq, headers=headers, data=json.dumps(data))

        response['ret'] = True if r.ok else False
    except Exception as e:
        print(f"error in uploading consortium keys")
        response['ret'] = False
    return response

def put_pkeys_handler(baseReq, env, token, uploadKeys):
    try:
        pub_id = uploadKeys['pub_id']
        del uploadKeys['pub_id']
        vaultReq = baseReq + "/v1/secret/data/" + env + f"/publisher/pub_id_{pub_id}"
        headers = {'X-Vault-Token': token}
        data = { "data": uploadKeys}
        response = {}
        response['cmd'] = PUT_PKEYS_CMD
        print(data)
        r = requests.post(url=vaultReq, headers=headers, data=json.dumps(data))

        response['ret'] = True if r.ok else False
    except Exception as e:
        print(f"error in uploading publisher keys of the publisher (pub_id : {pub_id})")
        response['ret'] = False
    return response
