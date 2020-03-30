
from alidns import get_url_data

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, ECDSA, SECP256R1, SECP384R1
from cryptography.hazmat.primitives.serialization import load_der_parameters, Encoding, PrivateFormat, NoEncryption

from cryptography import x509
from cryptography.x509.oid import NameOID

from requests import request
from requests.exceptions import ConnectionError, ProxyError

from functools import wraps
from base64 import urlsafe_b64encode
from json import dumps
from json.decoder import JSONDecodeError
from time import sleep
from os import getenv
from sys import exit

def i2b(i):
    return i.to_bytes((i.bit_length() + 7) // 8, "big")

def b64(b):
    return urlsafe_b64encode(b).decode("ascii").replace("=", "")

def serialize(o):
    return b64(dumps(o).encode("utf-8"))

def sha256(b):
    digest = Hash(SHA256(), default_backend())
    digest.update(b)
    return digest.finalize()

def get_env(key, default_value=None):
    value = getenv(key)
    if value == None:
        if default_value == None:
            print("get_env error\n\t{}".format(key))
            exit(1)
        value = default_value
    return value

def check_resp(resp):
    if not resp.status_code in (200, 201,):
        print(resp.status_code, resp.request.method, resp.request.url)
        print(resp.text)
        exit(1)

def log(func):
    @wraps(func)
    def wrapper_verbose(*args, **kwargs):
        print("call")
        print("\t{}".format(func.__name__))
        print("argument")
        for arg in args:
            print("\t{}".format(arg))
        for k in kwargs:
            print("\t{}: {}".format(k, kwargs[k]))

        return func(*args, **kwargs)

    @wraps(func)
    def wrapper_log(*args, **kwargs):
        print("call\n\t{}".format(func.__name__))

        return func(*args, **kwargs)

    verbose = getenv("ACME_VERBOSE", "false")

    if verbose == "true":
        return wrapper_verbose
    else:
        return wrapper_log


def retry(errors, update=None):
    retry_limit = getenv("ACME_RETRY_LIMIT", 6)

    def wrapper(func):
        @wraps(func)
        def wrapper_(*args, **kwargs):
            count = retry_limit
            while True:
                try:
                    return func(*args, **kwargs)
                except errors as err:
                    if count < 1:
                        raise err
                    count = count - 1
                    if update is not None:
                        args, kwargs = update(*args, **kwargs)
        return wrapper_
    return wrapper

@log
def generate_jwk(key):
    return {
            "kty": "EC",
            "crv": "P-256",
            "x": b64(i2b(key.public_key().public_numbers().x)),
            "y": b64(i2b(key.public_key().public_numbers().y)),
            }

@log
def generate_csr(domain):
    key = generate_private_key(SECP384R1(), default_backend())

    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domain),
        ]))
    builder = builder.add_extension(x509.SubjectAlternativeName([
        x509.DNSName(domain),
        ]), critical=False)

    csr = builder.sign(key, SHA256(), default_backend())
    csr = b64(csr.public_bytes(Encoding.DER))

    output = getenv("ACME_OUTPUT", ".")
    with open("{}/{}".format(output, "key.pem"), "wb") as f:
        f.write(key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))

    return csr

@log
def save_cert(cert):
    output = getenv("ACME_OUTPUT", ".")
    with open("{}/{}".format(output, "cert.pem"), "wb") as f:
        f.write(cert)

@retry((ConnectionError, ProxyError))
@log
def call_dns_api(params):
    url, data = get_url_data(params)

    resp = request("POST", url, data=data)
    check_resp(resp)

    return resp.json()

@log
def get_record_id(domainName, rrKeyWord):
    params = {
        "Action": "DescribeDomainRecords",
        "DomainName": domainName,
        "RRKeyWord": rrKeyWord,
        "TypeKeyWord": "TXT",
        "SearchMode": "/ADVANCED",
        "PageSize": "1",
    }

    json = call_dns_api(params)

    records = json["DomainRecords"]["Record"]

    return records[0]["RecordId"]

@log
def set_record(rr, recordId, value):
    params = {
        "Action": "UpdateDomainRecord",
        "RR": rr,
        "RecordId": recordId,
        "Type": "TXT",
        "Value": value,
    }

    json = call_dns_api(params)

    return json["RecordId"]

@log
def update_rr(domain, rr, value):
    dn = domain[len(rr) + 3:] if domain[0] == "*" else domain[len(rr) + 1:]
    rr = "_acme-challenge." + rr

    record_id = get_record_id(dn, rr)
    set_record(rr, record_id, value)

@retry((ConnectionError, ProxyError))
@log
def get_directory():
    if getenv("ACME_TEST", "false") == "true":
        url = getenv("ACME_ENVIROMENT", "https://acme-staging-v02.api.letsencrypt.org/directory")
    else:
        url = getenv("ACME_ENVIROMENT", "https://acme-v02.api.letsencrypt.org/directory")

    headers = {
            "User-Agent": "client",
            }

    resp = request("GET", url, headers=headers)
    check_resp(resp)

    return resp.json()

@retry((ConnectionError, ProxyError))
@log
def head_new_nonce(directory):
    url = directory["newNonce"]
    headers = {
            "User-Agent": "client",
            }

    resp = request("HEAD", url, headers=headers)
    check_resp(resp)

    return resp.headers["Replay-Nonce"]

@log
def update_post_with_sign(directory, url, nonce, key, jwk, kid, payload):
    return (directory, url, head_new_nonce(directory), key, jwk, kid, payload), {}

@retry((ConnectionError, ProxyError), update=update_post_with_sign)
@log
def post_with_sign(directory, url, nonce, key, jwk, kid, payload):
    headers = {
            "User-Agent": "client",
            "Content-Type": "application/jose+json",
            }

    protected = {
            "alg": "ES256",
            "url": url,
            "nonce": nonce,
            }

    if kid == None:
        protected["jwk"] = jwk
    else:
        protected["kid"] = kid

    protected = serialize(protected)
    payload = "" if payload is None else serialize(payload)

    signature = key.sign("{}.{}".format(protected, payload).encode("ascii"), ECDSA(SHA256()))
    signature = load_der_parameters(signature, default_backend()).parameter_numbers()
    signature = b64(i2b(signature.p) + i2b(signature.g))

    json = {
            "protected": protected,
            "payload": payload,
            "signature": signature,
        }

    resp = request("POST", url, headers=headers, data=dumps(json).encode("ascii"))
    check_resp(resp)

    try:
        return resp.headers, resp.json()
    except JSONDecodeError:
        return resp.headers, resp.content

@log
def post_new_account(directory, nonce, key, jwk):
    payload = {
            "termsOfServiceAgreed": True,
            }
    headers, _ = post_with_sign(directory, directory["newAccount"], nonce, key, jwk, None, payload)

    return headers["Replay-Nonce"], headers["Location"]

@log
def post_new_order(directory, nonce, key, kid, domain):
    payload = {
            "identifiers": [ { "type": "dns", "value": domain }, ],
            }

    headers, json = post_with_sign(directory, directory["newOrder"], nonce, key, None, kid, payload)

    return headers["Replay-Nonce"], headers["Location"], json["authorizations"][0], json["finalize"]

@log
def get_authorization(directory, nonce, key, kid, authorization):
    headers, json = post_with_sign(directory, authorization, nonce, key, None, kid, None)

    challenge, token = [(i["url"], i["token"]) for i in json["challenges"] if i["type"] == "dns-01"][0]

    return headers["Replay-Nonce"], challenge, token

@log
def post_chanllenge(directory, nonce, key, kid, challenge):
    headers, json = post_with_sign(directory, challenge, nonce, key, None, kid, {})

    return headers["Replay-Nonce"]

@log
def get_order(directory, nonce, key, kid, order):
    headers, json = post_with_sign(directory, order, nonce, key, None, kid, None)

    return headers["Replay-Nonce"], json["status"]

@log
def post_finalize(directory, nonce, key, kid, finalize, csr):
    payload = {
            "csr": csr,
            }
    headers, json = post_with_sign(directory, finalize, nonce, key, None, kid, payload)

    return headers["Replay-Nonce"], json["certificate"]

@log
def get_certificate(directory, nonce, key, kid, certificate):
    headers, data = post_with_sign(directory, certificate, nonce, key, None, kid, None)

    return headers["Replay-Nonce"], data

@log
def post_account(directory, nonce, key, kid):
    payload = {
            "status": "deactivated",
            }
    headers, json = post_with_sign(directory, kid, nonce, key, None, kid, payload)

    return headers["Replay-Nonce"]

@log
def check_status(directory, nonce, key, kid, order):
    interval = getenv("ACME_INTERVAL", 30)

    for i in range(6):
        nonce, status = get_order(directory, nonce, key, kid, order)
        if status == "ready":
            break
        sleep(interval)

    if not status == "ready":
        print("check_status error\n\tstatus = {}".format(status))
        exit(1)

    return nonce

@log
def get_cert():
    domain = get_env("ACME_DOMAIN")
    rr = get_env("ACME_RR")

    key = generate_private_key(SECP256R1(), default_backend())
    jwk = generate_jwk(key)
    thumbprint = b64(sha256(dumps(jwk, sort_keys=True, separators=(",", ":")).encode("utf-8")))
    csr = generate_csr(domain)

    directory = get_directory()
    nonce = head_new_nonce(directory)
    nonce, kid = post_new_account(directory, nonce, key, jwk)
    nonce, order, authorization, finalize = post_new_order(directory, nonce, key, kid, domain)
    nonce, challenge, token = get_authorization(directory, nonce, key, kid, authorization)

    update_rr(domain, rr, b64(sha256("{}.{}".format(token, thumbprint).encode("ascii"))))
    nonce = post_chanllenge(directory, nonce, key, kid, challenge)
    nonce = check_status(directory, nonce, key, kid, order)

    nonce, certificate = post_finalize(directory, nonce, key, kid, finalize, csr)
    nonce, cert = get_certificate(directory, nonce, key, kid, certificate)
    save_cert(cert)

    nonce = post_account(directory, nonce, key, kid)

if __name__ == "__main__":
    get_cert()

