
from functools import wraps
from urllib.parse import urlencode
from urllib.request import pathname2url
from base64 import b64encode
from secrets import randbits
import hmac
from datetime import datetime
from os import getenv

def load_accesskey(func):
    with open(getenv("ALIDNS_ACCESSKEY", "accesskey.txt"), "r") as f:
        lines = f.readlines()
        accessKeyId = lines[0].strip()
        accessKeySecret = lines[1].strip()
    @wraps(func)
    def wrapper():
        return accessKeyId, accessKeySecret
    return wrapper

@load_accesskey
def get_accesskey():
    pass

def replace_urlencode(url):
    return url.replace("+", "%20").replace("*", "%2A").replace("%7E", "~")

def get_string_to_sign(method, params):
    sorted_params = sorted(params.items(), key=lambda param: param[0])
    sorted_string = replace_urlencode(urlencode(sorted_params))
    return method + "&%2F&" + replace_urlencode(pathname2url(sorted_string))

def get_signed_string(key, string_to_sign):
    h = hmac.new(key.encode("ascii"), msg=string_to_sign.encode("utf-8"), digestmod="SHA1")
    return b64encode(h.digest()).decode("ascii")

def get_timestamp():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def get_nonce():
    return randbits(48)

def get_url_data(params):
    url = "https://alidns.aliyuncs.com/?Action={}".format(params["Action"])
    accessKeyId, accessKeySecret = get_accesskey()

    params.update({
        "Format": "JSON",
        "Version": "2015-01-09",
        "AccessKeyId": accessKeyId,
        "SignatureMethod": "HMAC-SHA1",
        "Timestamp": get_timestamp(),
        "SignatureVersion": "1.0",
        "SignatureNonce": get_nonce(),
    })

    string_to_sign = get_string_to_sign("POST", params)
    signed_string = get_signed_string(accessKeySecret + "&", string_to_sign)

    params["Signature"] = signed_string

    return url, params

