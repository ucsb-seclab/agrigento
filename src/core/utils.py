import zlib
from copy import deepcopy
from operator import attrgetter

from config.compare_config import DELIMITERS


def tuples_to_dict(tuples):
    d = {}

    for x in tuples:
        if x[0] not in d:
            d[x[0]] = []

        if type(x[1]) is list or type(x[1]) is set:
            d[x[0]].extend(x[1])
        else:
            d[x[0]].append(x[1])

    return d


def escape_seq(seq):
    res = deepcopy(seq)

    special_bytes = [ord('*'), ord('|'), ord('\\'), ord('?'), ord('.'),
                     ord('^'), ord('['), ord(']'), ord('('), ord(')'), ord('+'),
                     ord('{'), ord('}')]

    indexes = [i for i in range(len(res)) if res[i] in special_bytes]

    for i in sorted(indexes, reverse=True):
        res.insert(i, ord('\\'))

    return res


def unescape_regex(regex):
    unescaped = deepcopy(regex)
    unescaped = unescaped.replace('\\\\', '<JUSTAPLACEHOLDER>')
    unescaped = unescaped.replace('\\', '')
    unescaped = unescaped.replace('<JUSTAPLACEHOLDER>', '\\')
    return unescaped


def strip_values(values):
    for i in range(len(values)):
        values[i] = values[i].strip()


def str_to_bytes(string):
    return [ord(c) for c in string]


def decompress_gzip(payload):
    return zlib.decompress(payload, 16+zlib.MAX_WBITS)


def dict_merge(dct, merge_dct):
    for k in merge_dct:
        if (k in dct and isinstance(dct[k], dict)
                and isinstance(merge_dct[k], dict)):
            dict_merge(dct[k], merge_dct[k])
        else:
            dct[k] = merge_dct[k]


def merge_queries(q, merge_q):
    for k in merge_q:
        if k in q:
            q[k].extend(merge_q[k])
        else:
            q[k] = merge_q[k]


def come_from_network(values, traces):
    result = True

    for i in range(len(values)):
        value = values[i]
        trace = traces[i].keys()[0]

        min_ts = min(traces[i][trace], key=attrgetter('timestamp')).timestamp

        if not trace.contains(value, min_ts):
            result = False
            break

    return result


def extend_matches(values, subvalues):
    return [extend_match(values[i], subvalues[i]) for i in range(len(values))]


def extend_match(value, subvalue):
    if subvalue not in value:
        raise Exception('Subvalue not found')

    start = value.find(subvalue)
    end = value.find(subvalue) + len(subvalue)

    for i in range(start-1, -1, -1):
        if value[i] in DELIMITERS:
            start = i
            break

    for i in range(end, len(value)):
        if value[i] in DELIMITERS:
            end = i
            break

    start_offset = value.find(subvalue) - start
    end_offset = end - (value.find(subvalue) + len(subvalue))

    return value[start + 1: end], start_offset, end_offset


def contains_any(list, string):
    result = False

    for value in list:
        try:
            if value in string.decode('utf-8'):
                result = True
                break
        except UnicodeError, e:
            pass

    return result


def valid_string(string):
    try:
        unicode(string)
        return True
    except UnicodeDecodeError:
        return False

