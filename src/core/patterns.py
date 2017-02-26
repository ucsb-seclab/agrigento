import re
import json

from urlparse import parse_qs
from time import time

from config.compare_config import TIMESTAMP, RANDOM_ID


ts = str(int(time()))
ts_regex = ts[0] + "(\.)?" + ts[1:3] + "[0-9]{4,}(\.[0-9]+)?"

gcm_regex = "APA91([a-zA-Z0-9\-_\+]{40,})"


def is_url(url):
    regex = re.compile(
            r'^(?:http|ftp)s?://' # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
            r'localhost|'
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
            r'(?::\d+)?' # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    return url is not None and regex.match(url) is not None


def is_http_query(string):
    try:
        res = parse_qs(string)
        if res:
            return True
        else:
            return False
    except:
        return False


def is_json(string):
    try:
        res = json.loads(string)
        if res:
            # JSON should have keys
            if type(res) is list:
                res[0].keys()
            else:
                res.keys()
            return True
        else:
            return False
    except:
        return False


def is_recent_timestamp(string):
    ts = str(int(time()))

    if not string.isdigit():
        return False

    if string[:3] != ts[:3]:
        return False

    return True


def are_urls(values):
    result = True

    for value in values:
        result = is_url(value)
        if not result:
            break

    return result


def are_http_queries(values):
    result = True

    for value in values:
        result = is_http_query(value)
        if not result:
            break

    return result


def are_jsons(values):
    result = True

    for value in values:
        result = is_json(value)
        if not result:
            break

    return result

def are_timestamps(values):
    result = True
    length = len(values[0])

    for value in values:
        result = is_recent_timestamp(value)
        result = result and len(value) == length
        if not result:
            break

    return result


def replace_timestamps(string):
    return re.sub(ts_regex, TIMESTAMP, string)


def contains_timestamps(string):
    return re.search(ts_regex, string) is not None


def replace_gcm(string):
    return re.sub(gcm_regex, RANDOM_ID, string)


def contains_gcm(string):
    return re.search(gcm_regex, string) is not None
