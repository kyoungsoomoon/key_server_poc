from datetime import datetime
import kms_api_handler as kmsa
import key_cache_handler as key_cache
from key_common import *
import key_xml_parser as keyParser
from key_res_formatter import KeyResFormatter

def get_keys_handler(**args):
    # required argument : token
    # optional  arguments : 'ts'
    if not args['token']:
        print(f"error : missing argument token={args['token']} in get_keys_handler")
        return None

    # look up key cache
    res = key_cache.lookup(token=args['token'], ts=args['ts'])
    if not res:
        # retrieve keys from KMS
        response = kmsa.retrieve_keys_handler(args['baseURL'], args['env'], args['token'])

        if response:
            keyResFormatter = KeyResFormatter(response['cmd'])

            # read last_updated or current time
            last_updated = key_cache.read_mem_last_updated()
            if not last_updated:
                last_updated = key_cache.read_last_updated()
            if not last_updated:
                last_updated = datetime.utcnow().isoformat()
                # write last_updated
                key_cache.write_last_updated(last_updated)
            keyResFormatter.set_last_updated(last_updated)

            res = keyResFormatter.generate_response(response)

            # write key response into cache if token is the same as tv token
            if key_cache.tv_token_lookup(args['token']) and not key_cache.check_response():
                key_cache.write_response(resXML=res)

    return res

def get_pkeys_handler(**args):
    # required argument : token & pub_id
    if not args['token'] or not args['pub_id']:
        print(f"error : missing arguments token={args['token']}, pub_id={args['pub_id']} in get_pkeys_handler")
        return None

    # look up key cache
    res = key_cache.lookup(token=args['token'], pub_id=args['pub_id'], ts=args['ts'])
    if not res:
        # retrieve keys from KMS
        response = kmsa.retrieve_pkeys_handler(args['baseURL'], args['env'], args['token'], args['pub_id'])

        if response:
            keyResFormatter = KeyResFormatter(response['cmd'])

            # read last_updated or current time
            last_updated = key_cache.read_mem_last_updated()
            if not last_updated:
                last_updated = key_cache.read_last_updated()
            if last_updated:
                # set last_updated
                keyResFormatter.set_last_updated(last_updated)

            res = keyResFormatter.generate_response(response)

    return res

def get_ckeys_handler(**args):
    # required argument : token
    if not args['token']:
        print(f"error : missing arguments token={args['token']} in get_ckeys_handler")
        return None

    # look up key cache
    res = key_cache.lookup(token=args['token'], bConsortiumOnly=True, ts=args['ts'])
    if not res:
        # retrieve keys from KMS
        response = kmsa.retrieve_ckeys_handler(args['baseURL'], args['env'], args['token'])

        if response:
            keyResFormatter = KeyResFormatter(response['cmd'])

            # read last_updated or current time
            last_updated = key_cache.read_mem_last_updated()
            if not last_updated:
                last_updated = key_cache.read_last_updated()
            if last_updated:
                # set last_updated
                keyResFormatter.set_last_updated(last_updated)

            res = keyResFormatter.generate_response(response)

    return res

def create_token_handler(**args):
    # required argument : token, role_id & secret_id
    if not args['token'] or not args['role_id'] or not args['secret_id']:
        print(f"error : missing arguments token={args['token']}, role_id={args['role_id']}, secret_id={args['secret_id']} in create_token_handler")
        return None

    res = kmsa.create_pub_token_handler(args['baseURL'], args['token'], args['role_id'], args['secret_id'])
    if res:
        keyResFormatter = KeyResFormatter(res['cmd'])
        res = keyResFormatter.generate_response(res)

    return res

def revoke_token_handler(**args):
    # required argument : token
    if not args['token']:
        print(f"error : missing arguments token={args['token']} in revoke_token_handler")
        return None

    token = args['token_revoke'] if args['token_revoke'] else args['token']

    res = kmsa.revoke_pub_token_handler(args['baseURL'], args['token'], token)
    if res:
        keyResFormatter = KeyResFormatter(res['cmd'])
        res = keyResFormatter.generate_response(res)

    return res

def create_pub_handler(**args):
    # required argument : token & pub_id
    if not args['token'] or not args['pub_id']:
        print(f"error : missing arguments token={args['token']}, pub_id={args['pub_id']} in create_pub_handler")
        return None

    res = kmsa.create_publisher_handler(args['baseURL'], args['token'], args['pub_id'])
    if res:
        keyResFormatter = KeyResFormatter(res['cmd'])
        res = keyResFormatter.generate_response(res)

    return res

def delete_pub_handler(**args):
    # required argument : token & pub_id
    if not args['token'] or not args['pub_id']:
        print(f"error : missing arguments token={args['token']}, pub_id={args['pub_id']} in delete_pub_handler")
        return None

    res = kmsa.delete_publisher_handler(args['baseURL'], args['env'], args['token'], args['pub_id'])
    if res:
        keyResFormatter = KeyResFormatter(res['cmd'])

        if res['ret']:
            # update last_updated
            last_updated = datetime.utcnow().isoformat()
            key_cache.write_last_updated(last_updated)

        res = keyResFormatter.generate_response(res)
        # delete key reponse
        key_cache.delete_response()

    return res

def put_ckeys_handler(**args):
    # required argument : token
    if not args['token'] or not args['uploadKeys']:
        print(f"error : missing arguments token={args['token']}, uploadKeys={args['uploadKeys']} in put_ckeys_handler")
        return None

    uploadKeys = keyParser.parse_ckeys(args['uploadKeys'])
    if not uploadKeys:
        print(f"error : invalid upload key syntax in put_ckeys_handler, {args['uploadKeys']}")
        return None

    res = kmsa.put_ckeys_handler(args['baseURL'], args['env'], args['token'], uploadKeys)

    if res:
        keyResFormatter = KeyResFormatter(res['cmd'])

        if res['ret']:
            # update key response and last_updated
            last_updated = datetime.utcnow().isoformat()
            key_cache.write_last_updated(last_updated)

        res = keyResFormatter.generate_response(res)
        # delete key reponse
        key_cache.delete_response()

    return res

def put_pkeys_handler(**args):
    # required argument : token
    if not args['token'] or not args['uploadKeys']:
        print(f"error : missing arguments token={args['token']}, uploadKeys={args['uploadKeys']} in put_pkeys_handler")
        return None

    uploadKeys = keyParser.parse_pkeys(args['uploadKeys'])
    if not uploadKeys or not uploadKeys[0]:
        print(f"error : invalid upload key syntax in put_pkeys_handler, {args['uploadKeys']}")
        return None

    pub_id = uploadKeys[0]['pub_id']
    res = kmsa.put_pkeys_handler(args['baseURL'], args['env'], args['token'], uploadKeys[0])
    if res:
        keyResFormatter = KeyResFormatter(res['cmd'])

        print(pub_id, res)

        if res['ret']:
            # update key response and last_updated
            last_updated = datetime.utcnow().isoformat()
            key_cache.write_last_updated(last_updated)

        res = keyResFormatter.generate_response(res)
        # delete key reponse
        key_cache.delete_response()

    return res

def delete_expired_keys_handler(**args):
    return None

def write_tv_token_handler(**args):
    key_cache.write_tv_token(args['token'])
    return None

cmd_handlers = {
    GET_KEYS_CMD            : get_keys_handler,
    GET_PKEYS_CMD           : get_pkeys_handler,
    PUT_PKEYS_CMD           : put_pkeys_handler,
    CREATE_TOKEN_CMD        : create_token_handler,
    REVOKE_TOKEN_CMD        : revoke_token_handler,
    CREATE_PUB_CMD          : create_pub_handler,
    DELETE_PUB_CMD          : delete_pub_handler,
    GET_CKEYS_CMD           : get_ckeys_handler,
    PUT_CKEYS_CMD           : put_ckeys_handler,
    DEL_EXPIRED_KEYS_CMD    : delete_expired_keys_handler,
    WRITE_TV_TOKEN_CMD      : write_tv_token_handler,
}