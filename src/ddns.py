
from alidns import get_url_data

from dns.resolver import Resolver
from dns.exception import Timeout
from requests import post
from requests.exceptions import ConnectionError, ProxyError

from functools import wraps
from time import sleep
from os import getenv
from sys import exit

def get_env(key, default_value=None):
    value = getenv(key)
    if value == None:
        if default_value == None:
            print("get_env error\n\t{}".format(key))
            exit(1)
        value = default_value
    return value

def retry(errors):
    retry_limit = getenv("DDNS_RETRY_LIMIT", 6)

    def wrapper0(func):
        @wraps(func)
        def wrapper1(*args, **kwargs):
            count = retry_limit
            while True:
                try:
                    return func(*args, **kwargs)
                except errors as err:
                    if count < 1:
                        raise err
                    count = count - 1
        return wrapper1
    return wrapper0

@retry((Timeout))
def get_public_ip():
    resolver = Resolver(configure=False)
    resolver.nameservers = ["208.67.222.222", "208.67.220.220"]
    resolver.timeout = getenv("DDNS_TIMEOUT", 6)

    answer = resolver.query("myip.opendns.com", "A")

    return answer[0].to_text()

@retry((ConnectionError, ProxyError))
def call_api(params):
    url, data = get_url_data(params)

    resp = post(url, data=data)
    if not resp.status_code == 200:
        print(resp.status_code, resp.request.method, resp.request.url)
        print(resp.text)
        exit(1)

    return resp.json()

def get_record(domainName, rrKeyWord):
    params = {
        "Action": "DescribeDomainRecords",
        "DomainName": domainName,
        "RRKeyWord": rrKeyWord,
        "TypeKeyWord": "A",
        "SearchMode": "/ADVANCED",
        "PageSize": "1",
    }

    json = call_api(params)

    records = json["DomainRecords"]["Record"]
    if len(records) < 1:
        print("get_record error\n\tlen(records) = {}".format(len(records)))
        exit(1)

    return records[0]["RecordId"], records[0]["Value"]

def set_record(rr, recordId, value):
    params = {
        "Action": "UpdateDomainRecord",
        "RR": rr,
        "RecordId": recordId,
        "Type": "A",
        "Value": value,
    }

    json = call_api(params)

    return json["RecordId"]

def ddns():
    domainName = get_env("DDNS_DOMAINNAME")
    rr = get_env("DDNS_RR")

    ip = get_public_ip()
    print("get_public_ip {}".format(ip))

    id_, record = get_record(domainName, rr)
    print("get_record {} {}".format(id_, record))
        
    if not ip == record:
        id_ = set_record(rr, id_, ip)
        print("set_record {}".format(id_))

if __name__ == "__main__":
    ddns()

