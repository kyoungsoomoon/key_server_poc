import sys
import os
import requests
import bottle
import key_cmd_handler as cmdh
import key_checker_thread as thr

app = bottle.Bottle()
env = "prod"
key_cache_bucket = os.environ.get('KEY_CACHE_BUCKET', 'oar-dev')
key_cache_path = os.environ.get('KEY_CACHE_PATH', 'key_cache')
key_cache_response = os.environ.get('KEY_CACHE_RESPONSE', 'key_response.xml')
key_cache_last_updated = os.environ.get('KEY_CACHE_LAST_UPDATED', 'last_updated.txt')
key_cache_token = os.environ.get('KEY_CACHE_TOKEN', 'tv_token.txt')
ec2DomainName = None

vaultURL = "ec2-18-207-131-126.compute-1.amazonaws.com"
REQUIRED_FIELDS = ('token', 'cmd')

def validate_request(request, required=REQUIRED_FIELDS):
    for field in required:
        if field not in request.query:
            raise Exception(f'{field} is missing from request')

def get_params_from_request(request, basic=False):
    try:
        # validate the request
        validate_request(request)
        token   = request.query.token
        cmd     = request.query.cmd
        if not basic:
            pub_id  = request.query.pub_id if request.query.pub_id else None
            ts      = request.query.ts if request.query.ts else None
            role_id = request.query.role_id if request.query.role_id else None
            secret_id = request.query.secret_id if request.query.secret_id else None
            token_revoke = request.query.token_revoke if request.query.token_revoke else None
            print(f"token={token}, cmd={cmd}, pub_id={pub_id}, ts={ts}, role_id={role_id}, secret_id={secret_id}, token_revoke={token_revoke}")
        else:
            print(f"token={token}, cmd={cmd}")

        if basic:
            return token, cmd
        else:
            return token, cmd, pub_id, ts, role_id, secret_id, token_revoke
    except Exception as e:
        print('error parsing key request params: {}'.format(e))
    if basic:
        return None, None
    else:
        return None, None, None, None, None, None, None

@app.route('/key', method='GET')
def get_keys():
    token, cmd, pub_id, ts, role_id, secret_id, token_revoke = get_params_from_request(bottle.request)
    if (not token) or (not cmd):
        return bottle.HTTPError(status=401)

    baseURL = "http://" + vaultURL + ":8200"
    res = cmdh.cmd_handlers[cmd](baseURL=baseURL, env=env, token=token, cmd=cmd, pub_id=pub_id, ts=ts, role_id=role_id, secret_id=secret_id, token_revoke=token_revoke)
  
    if res:
        bottle.response.set_header('Content-Type', "text/xml")
        return res
    bottle.HTTPError(status=401)

@app.route('/key', method='POST')
def upload_keys():
    print("POST: upload_keys")
    token, cmd = get_params_from_request(bottle.request, basic=True)
    if (not token) or (not cmd):
        return bottle.HTTPError(status=401)

    uploadKeys = bottle.request.body.read().decode("utf-8")

    baseURL = "http://" + vaultURL + ":8200"
    res = cmdh.cmd_handlers[cmd](baseURL=baseURL, env=env, token=token, cmd=cmd, uploadKeys=uploadKeys)

    if res:
        bottle.response.set_header('Content-Type', "text/xml")
        return res
    bottle.HTTPError(status=401)

def main():
    global ec2DomainName

    ec2DomainNameURL = "http://169.254.169.254/latest/meta-data/public-hostname"
    r = requests.get(url = ec2DomainNameURL)
    print(r.text)
    ec2DomainName = r.text
    app.run(server='paste', host=r.text, port=80, debug=True)

if __name__ == '__main__':
    responseCheckThread = thr.ResponseChecker(20*60) # 20min
    responseCheckThread.setName('Key Response Checker Thread')
    responseCheckThread.start()

    main()

    responseCheckThread.terminate()
    responseCheckThread.join()
