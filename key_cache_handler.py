import boto3
from botocore.errorfactory import ClientError
from datetime import datetime, timezone
from threading import Lock
from key_common import *
from key_server import key_cache_bucket, key_cache_path, key_cache_response, key_cache_last_updated, key_cache_token
import key_xml_parser as KeyParser
from key_res_formatter import KeyResFormatter

memKeyRes = memLastUpdated = memTvToken = None
memCacheLock = Lock()
s3_resource = boto3.resource('s3')

def tv_token_lookup(token):
    try:
        tv_token = read_mem_tv_token()
        if not tv_token:
            tv_token = read_tv_token()

        if tv_token and tv_token == token:
            print("confirms it's tv token")
            return True

        return False

    except ClientError as e:
        print(f"error in looking up token in cache : {e}")
    return True

def check_tv_token():
    try:
        token_path = f"{key_cache_path}/{key_cache_token}"
        return True if 'Contents' in s3_resource.meta.client.list_objects(Bucket=key_cache_bucket, Prefix=token_path) else False
    except ClientError as e:
        print(f"error in checking tv token from cache : {e}")
    return False

def read_tv_token():
    try:
        token_path = f"{key_cache_path}/{key_cache_token}"
        if check_tv_token():
            token_obj = s3_resource.Object(bucket_name=key_cache_bucket, key=token_path)

            if token_obj:
                token = token_obj.get()['Body'].read().decode("utf-8")
                token_obj.get()['Body'].close()
                return token
    except ClientError as e:
        print(f"error in reading tv token from cache : {e}")
    return None

def write_tv_token(token):
    try:
        token_path = f"{key_cache_path}/{key_cache_token}"
        token_obj = s3_resource.Object(bucket_name=key_cache_bucket, key=token_path)
        if token_obj:
            token_obj.put(Body=token, ACL='private', ServerSideEncryption='AES256')
            write_mem_tv_token(token)
            print(f"tv token is stored to s3 and mem cache - {token}")
            return True

    except ClientError as e:
        print(f"error in writing token to s3 : {e}")
    return False

def is_ts_latest(ts):
    try:
        if not check_mem_response() and not check_response():
            return False

        if ts:
            last_updated = read_mem_last_updated()
            if not last_updated:
                last_updated = read_last_updated()
            if last_updated:
                last_updated_time = datetime.strptime(last_updated, "%Y-%m-%dT%H:%M:%S.%f")
                known_last_updated_time = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f")
                return False if last_updated_time > known_last_updated_time else True

    except ClientError as e:
        print(f"error in looking up last_updated in cache : {e}")
    return False

def response_lookup(bConsortiumOnly, pub_id):
    try:
        response = read_mem_response()
        if not response:
            response = read_response()

        if response:
            if bConsortiumOnly:
                return KeyParser.extract_consortium_keys(response)
            elif pub_id:
                return KeyParser.extract_publisher_keys(response, pub_id)
            else:
                return response

    except ClientError as e:
        print(f"error in looking up response in cache : {e}")
    return None

def lookup(token, pub_id=None, bConsortiumOnly=False, ts=None):
    try:
        # check tv token
        if not tv_token_lookup(token):
            return None

        # check if timestamp is the latest (i.e. greater than or equal to last_updated)
        if (check_mem_response() or check_response()) and (check_mem_last_updated() or check_last_updated()):
            if is_ts_latest(ts):
                print("no update")
                keyResFormatter = KeyResFormatter(GET_KEYS_CMD)
                res = keyResFormatter.generate_response(None)
                return res
            else:
                # return cached response if there is
                return response_lookup(bConsortiumOnly, pub_id)

    except ClientError as e:
        print(f"error in looking up cache : {e}")
    return None

def check_response():
    try:
        response_path = f"{key_cache_path}/{key_cache_response}"
        return True if 'Contents' in s3_resource.meta.client.list_objects(Bucket=key_cache_bucket, Prefix=response_path) else False
    except ClientError as e:
        print(f"error in checking response from cache : {e}")
    return False

def read_response():
    try:
        response_path = f"{key_cache_path}/{key_cache_response}"
        if check_response():
            response_obj = s3_resource.Object(bucket_name=key_cache_bucket, key=response_path)

            if response_obj:
                response = response_obj.get()['Body'].read().decode("utf-8")
                response_obj.get()['Body'].close()
                return response
    except ClientError as e:
        print(f"error in reading response from cache : {e}")
    return None

def write_response(resXML, pub_id=None, bConsortiumOnly=False):
    try:
        response_path = f"{key_cache_path}/{key_cache_response}"
        response_obj = s3_resource.Object(bucket_name=key_cache_bucket, key=response_path)
        if response_obj:
            response_obj.put(Body=resXML, ACL='private', ServerSideEncryption='AES256')
            write_mem_response(resXML)
            print(f"key response is stored to s3 and mem cache\n- {resXML}")

    except ClientError as e:
        print(f"error in writing key response to s3 : {e}")
    return False

def delete_response():
    try:
        response_path = f"{key_cache_path}/{key_cache_response}"
        response_obj = s3_resource.Object(bucket_name=key_cache_bucket, key=response_path)
        if response_obj:
            response_obj.delete()
            write_mem_response(None)
            return True

    except ClientError as e:
        print(f"error in deleteing response to s3 : {e}")
    return False

def check_last_updated():
    try:
        last_updated_path = f"{key_cache_path}/{key_cache_last_updated}"
        return True if 'Contents' in s3_resource.meta.client.list_objects(Bucket=key_cache_bucket, Prefix=last_updated_path) else False

    except ClientError as e:
        print(f"error in checking last_updated from s3 : {e}")
    return False

def read_last_updated():
    try:
        if not check_last_updated():
            return None

        last_updated_path = f"{key_cache_path}/{key_cache_last_updated}"
        last_updated_obj = s3_resource.Object(bucket_name=key_cache_bucket, key=last_updated_path)
        if last_updated_obj:
            last_updated = last_updated_obj.get()['Body'].read().decode("utf-8")
            last_updated_obj.get()['Body'].close()
            return last_updated

    except ClientError as e:
        print(f"error in reading last_updated from s3 : {e}")
    return None

def write_last_updated(last_updated):
    try:
        last_updated_path = f"{key_cache_path}/{key_cache_last_updated}"
        last_updated_obj = s3_resource.Object(bucket_name=key_cache_bucket, key=last_updated_path)
        if last_updated_obj:
            last_updated_obj.put(Body=last_updated, ACL='private', ServerSideEncryption='AES256')
            write_mem_last_updated(last_updated)
            print(f"last_updated timestamp is updated in s3 and mem cache - {last_updated}")
            return True

    except ClientError as e:
        print(f"error in writing last_updated to s3 : {e}")
    return False

def delete_last_updated():
    try:
        last_updated_path = f"{key_cache_path}/{key_cache_last_updated}"
        last_updated_obj = s3_resource.Object(bucket_name=key_cache_bucket, key=last_updated_path)
        if last_updated_obj:
            last_updated_obj.delete()
            write_mem_last_updated(None)
            print(f"last_updated.txt is deleted")
            return True

    except ClientError as e:
        print(f"error in deleteing last_updated to s3 : {e}")
    return False

def check_mem_response():
    if memKeyRes:
        return True
    return False

def write_mem_response(response):
    global memCacheLock, memKeyRes

    if memCacheLock:
        memCacheLock.acquire()
        memKeyRes = response
        memCacheLock.release()
        return True
    return False

def read_mem_response(bLock=True):
    global memCacheLock, memKeyRes

    response = None
    if bLock == False:
        return memKeyRes
    elif memCacheLock and memKeyRes:
        memCacheLock.acquire()
        response = memKeyRes
        memCacheLock.release()
        print("reading key response from mem cache")
    return response

def check_mem_last_updated():
    if memLastUpdated:
        return True
    return False

def write_mem_last_updated(last_updated):
    global memCacheLock, memLastUpdated

    if memCacheLock:
        memCacheLock.acquire()
        memLastUpdated = last_updated
        memCacheLock.release()
        return True
    return False

def read_mem_last_updated(bLock=True):
    global memCacheLock, memLastUpdated

    last_updated = ""
    response = None
    if bLock == False:
        return memLastUpdated
    elif memCacheLock and memLastUpdated:
        memCacheLock.acquire()
        last_updated = memLastUpdated
        memCacheLock.release()
        print("reading last_updated from mem cache")
    return last_updated

def check_mem_tv_token():
    if memTvToken:
        return True
    return False

def write_mem_tv_token(tv_token):
    global memCacheLock, memTvToken

    if memCacheLock:
        memCacheLock.acquire()
        memTvToken = tv_token
        memCacheLock.release()
        return True
    return False

def read_mem_tv_token(bLock=True):
    global memCacheLock, memTvToken

    tv_token = ""
    response = None
    if bLock == False:
        return memTvToken
    elif memCacheLock and memTvToken:
        memCacheLock.acquire()
        tv_token = memTvToken
        memCacheLock.release()
        print("reading tv token from mem cache")
    return tv_token