import json
import re
import logging
import editdistance

from urlparse import urlparse, parse_qs
from PI import *
from difflib import SequenceMatcher
from copy import deepcopy

from core.utils import str_to_bytes, tuples_to_dict, strip_values, escape_seq
from core.utils import unescape_regex
from core.patterns import are_jsons, are_urls, are_http_queries

from config.compare_config import GAP_BYTE, GAPS_THRESHOLD, WILDCARD
from config.general_config import LOGGING_LEVEL

logging.basicConfig(level=LOGGING_LEVEL,
                    format='[%(asctime)s] %(levelname)s:%(name)s:%(message)s',
                    datefmt='%d-%m-%Y %H:%M:%S')
logger = logging.getLogger('compare')


def compare_urls(values_list):
    values = []
    for v in values_list:
        u = urlparse(v)
        value = parse_qs(u.query, True)
        # TODO this is bad, find a better way
        value['<DOMAIN>'] = [u.hostname]
        value['<PATH>'] = [u.path]
        for k in value: # no list
            value[k] = value[k][0]
        values.append(value)

    # strip values
    for j in values:
        for k in j:
            j[k] = str(j[k]).strip()

    common_keys = set(values[0].keys())
    all_keys = set(values[0].keys())

    for value in values[1:]:
        common_keys = common_keys & set(value.keys())
        all_keys = all_keys | set(value.keys())

    invariants = []
    variants = []
    others = []

    for key in common_keys:
        equal = True
        v = values[0][key]
        for value in values[1:]:
            if value[key] != v:
                equal = False
                break

        if equal:
            invariants.append((key, v))
        else:
            for i, value in enumerate(values):
                variants.append((key, value[key]))

    for key in all_keys - common_keys:
        for i, value in enumerate(values):
            if key in value:
                others.append((key, value[key]))

    return invariants, variants, others


def compare_jsons(values_list):
    values = []
    for v in values_list:
        values.append(json.loads(v))

    tmp_values = []

    for i in range(len(values)):
        if type(values[i]) is list:
            for j in values[i]:
                tmp_values.append(j)
        else:
            tmp_values.append(values[i])

    values = tmp_values

    # strip values
    for j in values:
        for k in j:
            j[k] = str(j[k]).strip()

    common_keys = set(values[0].keys())
    all_keys = set(values[0].keys())

    for value in values[1:]:
        common_keys = common_keys & set(value.keys())
        all_keys = all_keys | set(value.keys())

    invariants = []
    variants = []
    others = []

    for key in common_keys:
        equal = True
        v = values[0][key]
        for value in values[1:]:
            if value[key] != v:
                equal = False
                break

        if equal:
            invariants.append((key, v))
        else:
            for i, value in enumerate(values):
                variants.append((key, value[key]))

    for key in all_keys - common_keys:
        for i, value in enumerate(values):
            if key in value:
                others.append((key, value[key]))

    return invariants, variants, others


def compare_http_queries(values_list):
    values = []
    for v in values_list:
        aux = parse_qs(v, True)
        for k in aux: # no list
            aux[k] = aux[k][0]
        values.append(aux)

    # strip values
    for j in values:
        for k in j:
            j[k] = str(j[k]).strip()

    common_keys = set(values[0].keys())
    all_keys = set(values[0].keys())

    for value in values[1:]:
        common_keys = common_keys & set(value.keys())
        all_keys = all_keys | set(value.keys())

    invariants = []
    variants = []
    others = []

    for key in common_keys:
        equal = True
        v = values[0][key]
        for value in values[1:]:
            if value[key] != v:
                equal = False
                break

        if equal:
            invariants.append((key, v))
        else:
            for i, value in enumerate(values):
                variants.append((key, value[key]))

    for key in all_keys - common_keys:
        for i, value in enumerate(values):
            if key in value:
                others.append((key, value[key]))

    return invariants, variants, others


def seq_to_str(seq):
    return ''.join([chr(x) if x != GAP_BYTE else WILDCARD for x in seq])


def seq_to_regex(seq):
    escaped = escape_seq(seq)
    return ''.join([chr(x) if x != GAP_BYTE else '(.*)?' for x in escaped])


def get_alignment_seqs(alignment):
    return [alignment[i][1] for i in range(len(alignment))]


def get_alignment_matches(values, sequence):
    regex = seq_to_regex(sequence)
    result = []

    for value in values:
        match = re.search(regex, value)
        if match:
            result.append(match.groups())

    return result


def fast_get_value_matches(value, regex):
    subs = unescape_regex(regex).split('(.*)?')
    match = set()
    aux_value = value

    aux_value = str(aux_value)

    for i in range(len(subs) - 1):
        subs[i] = str(subs[i])
        start = aux_value.find(subs[i]) + len(subs[i])
        end = aux_value[start:].find(subs[i + 1])
        # handle case in which regex ends with (.*)?
        if i + 1 == len(subs) - 1 and subs[i + 1] == '':
            end = len(aux_value) - start
        match.add(aux_value[start:start + end])
        aux_value = aux_value[start + end:]

    return match


def get_value_matches(value, regex):
    match = re.search(regex, value)

    if match:
        return match.groups()
    else:
        return []


def merge_gaps(sequence, gaps_threshold=GAPS_THRESHOLD):
    previous_gap = 0
    to_be_deleted = []

    for i in range(len(sequence)):
        if sequence[i] == GAP_BYTE:
            if i - previous_gap <= gaps_threshold + 1:
                to_be_deleted.extend(range(previous_gap, i))
            previous_gap = i

    for i in sorted(to_be_deleted, reverse=True):
        del sequence[i]


def merge_sequences(sequences, mergegaps=True, gaps_threshold=GAPS_THRESHOLD):
    seq_length = len(sequences[0])
    result = []

    for i in range(seq_length):
        byte = sequences[0][i]
        y = True
        for j in range(1, len(sequences)):
            try:
                if sequences[j][i] != byte:
                    y = False
                    break
            except IndexError, e:
                y = False
                break
        if y:
            result.append(byte)
        else:
            if not result or result[-1] != GAP_BYTE:
                result.append(GAP_BYTE)

    if mergegaps:
        merge_gaps(result, gaps_threshold=gaps_threshold)

    return result


def align_values(values, weight=1.0):
    seq_set = set()
    sequences = []

    # remove duplicated
    for value in values:
        seq_set.add(value)

    for i, value in enumerate(values):
        sequences.append((i, str_to_bytes(value)))

    dmx = distance.LocalAlignment(sequences)
    phylo = phylogeny.UPGMA(sequences, dmx, minval=weight)

    alist = []
    for cluster in phylo:
        aligned = multialign.NeedlemanWunsch(cluster)
        alist.append(aligned)

    if alist:
        return alist[0]
    else:
        # TODO better handle exception
        raise Exception('Alignment failed')


def compare_values(value, values, trace, min_ts, whitelist):
    logger.debug('Comparing values')

    values.append(value)

    if  len(values) > 1:
        # Hanlde JSONs
        if are_jsons(values):
            logger.debug('Comparing JSONs, {0}'.format(values))
            result = compare_jsons(values)
            invariants, variants, others = result

            variants = tuples_to_dict(variants)
            others = tuples_to_dict(others)

            value = json.loads(value)
            # TODO value is a list of JSON

            diffs = dict_diffs(value, variants, others, trace, min_ts, whitelist)

        # Handle HTTP_QUERIES
        elif are_http_queries(values):
            logger.debug('Comparing HTTP queries, {0}'.format(values))
            result = compare_http_queries(values)
            invariants, variants, others = result

            variants = tuples_to_dict(variants)
            others = tuples_to_dict(others)

            value = parse_qs(value, True)
            for k in value: # no list
                value[k] = value[k][0].strip()

            diffs = dict_diffs(value, variants, others, trace, min_ts, whitelist)

        # Handle URLs
        elif are_urls(values):
            logger.debug('Comparing URLs, {0}'.format(values))
            result = compare_urls(values)
            invariants, variants, others = result

            variants = tuples_to_dict(variants)
            others = tuples_to_dict(others)

            # value to dict
            u = urlparse(value)
            value = parse_qs(u.query, True)
            value['<DOMAIN>'] = [u.hostname]
            value['<PATH>'] = [u.path]

            for k in value: # no list
                value[k] = value[k][0].strip()

            diffs = dict_diffs(value, variants, others, trace, min_ts, whitelist)
        else:
            logger.debug('Comparing values, {0}'.format(values))
            diffs = value_diffs(value, values)

        return diffs

    elif len(values) == 1:
        return values[0]


def merge_diffs(diffs, regex):
    logger.debug('Merging differences')
    regex_subs = regex.split('(.*)?')
    merging = False
    l = []
    diffs_list = list(diffs)
    new_diffs = list(deepcopy(diffs))

    for j,i in enumerate(diffs_list):
        if len(i) == 1:
            if merging:
                l[-1].append(j)
            else:
                l.append([j])
                merging = True
        else:
            merging = False

    for indexes in l:
        assert all([indexes[i]+1 == indexes[i+1] for i in range(len(indexes) -1)])
        aux = diffs_list[indexes[0]]
        for index in indexes[1:]:
            aux = aux + regex_subs[index] + diffs_list[index]
        new_diffs.append(aux)

        for index in indexes:
            new_diffs.remove(diffs_list[index])

    # TODO check if indexes == 1
    return new_diffs


def value_diffs(value, values):
    try:
        values.remove(value)
    except ValueError, e:
        pass

    if not values:
        return [value]

    max_similarity = 0
    most_similar = None
    for v in values:
        similarity = SequenceMatcher(None, v, value).ratio()
        if similarity >= max_similarity:
            max_similarity = similarity
            most_similar = v

    if most_similar is None:
        return [value]

    to_align = [value, most_similar]

    a = align_values(to_align)
    seqs = get_alignment_seqs(a)
    try:
        seq = merge_sequences(seqs)
        regex = seq_to_regex(seq)
        diffs = fast_get_value_matches(value, regex)
    except AssertionError:
        # TODO horrible code here.
        try:
            seq = merge_sequences(seqs, gaps_threshold=(GAPS_THRESHOLD+1))
            regex = seq_to_regex(seq)
            diffs = fast_get_value_matches(value, regex)
        except AssertionError:
            seq = merge_sequences(seqs, gaps_threshold=(GAPS_THRESHOLD+2))
            regex = seq_to_regex(seq)
            diffs = fast_get_value_matches(value, regex)

    return diffs
    # return merge_diffs(diffs, regex)


def dict_diffs(value, variants, others, trace, min_ts, whitelist):
    diffs = {}

    if type(value) is list:
        # JSON list of dict
        for dict_elem in value:
            for k in dict_elem:
                v = dict_elem[k]
                if type(v) is dict:
                    v = json.dumps(v)
                if type(v) is not str:
                    v = str(v)

                if k in variants:
                    if v not in whitelist and not trace.contains(v, min_ts):
                        if k not in diffs:
                            diffs[k] = set()
                        diffs[k].update(value_diffs(v, variants[k]))

                elif k in others:
                    if len(others[k]) > 1:
                        if v not in whitelist and not trace.contains(v, min_ts):
                            if k not in diffs:
                                diffs[k] = set()
                            diffs[k].update(value_diffs(v, others[k]))
                    else:
                        if k not in diffs:
                            diffs[k] = set()
                        diffs[k].update([k, v])
    else:
        for k in value:
            v = value[k]
            if type(v) is dict:
                v = json.dumps(v)
            if type(v) is not str:
                v = str(v)

            if k in variants:
                try:
                    if v not in whitelist and not trace.contains(v, min_ts):
                        diffs[k] = value_diffs(v, variants[k])
                except UnicodeDecodeError:
                    diffs[k] = value_diffs(v, variants[k])

            elif k in others:
                if len(others[k]) > 1:
                    try:
                        if v not in whitelist and not trace.contains(v, min_ts):
                            diffs[k] = value_diffs(v, others[k])
                    except UnicodeDecodeError:
                        diffs[k] = value_diffs(v, others[k])
                else:
                    diffs[k] = [k, v]

    return diffs


def bit_edit_distance(value1, value2):
    l1 = len(value1)
    l2 = len(value2)
    max_l = max(l1, l2)

    # what if len(new) < len(whitelisted)
    distance = 0
    for i in range(max_l):
        if i >= l1:
            # distance += 8
            # if len(new) < len(whitelisted), no more bits
            pass
        elif i >= l2:
            distance += 8
        else:
            xor = ord(value1[i]) ^ ord(value2[i])
            distance += bin(xor).count('1')

    return distance


def calc_score(value, values):
    distance = 1000000000
    for v in values:
        if len(value) == len(v):
            d = bit_edit_distance(value, v)
        else:
            d = editdistance.eval(value, v) * 8
        distance = min(distance, d)

    return distance
