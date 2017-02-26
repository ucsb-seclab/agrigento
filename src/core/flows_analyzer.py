# encoding=utf8
import sys
import os
import logging

from base64 import b64decode
from urllib import unquote
from difflib import SequenceMatcher

from core.flow_parser import FlowParser
from core.whitetree import WhiteTree
from core.hooked import HookedData
from core.compare import compare_values, calc_score, value_diffs
from core.patterns import replace_timestamps, replace_gcm
from core.utils import valid_string

from config.general_config import FLOWS_FOLDER, WHITE_TREES_FOLDER
from config.general_config import CRYPTOHOOKER_LOGS_FOLDER
from config.general_config import MAX_DECRYPTION_CYCLES
from config.general_config import LOGGING_LEVEL
from config.compare_config import NUM_FLOWS_PER_APP, WHITELISTED_DOMAINS
from config.compare_config import RANDOM_ID


reload(sys)
sys.setdefaultencoding('utf8')

logging.basicConfig(level=LOGGING_LEVEL,
                    format='[%(asctime)s] %(levelname)s:%(name)s:%(message)s',
                    datefmt='%d-%m-%Y %H:%M:%S')
logger = logging.getLogger('flows-analyzer')


def setup_folders(app_name):
    try:
        os.stat(WHITE_TREES_FOLDER)
    except:
        os.mkdir(WHITE_TREES_FOLDER)

    output_dir = os.path.join(WHITE_TREES_FOLDER, app_name)

    try:
        os.stat(output_dir)
    except:
        os.mkdir(output_dir)


def create_whitetree(app_name, num_flows=NUM_FLOWS_PER_APP, field=None):
    logger.debug('Creating WhiteTree, ' + app_name)
    fp = FlowParser()
    flows_folder = os.path.join(FLOWS_FOLDER, app_name)

    if not os.path.isdir(flows_folder) or not os.listdir(flows_folder):
        logger.warning('No flows found for {0}'.format(app_name))
        # return None

    wt = WhiteTree()

    flows = sorted(os.listdir(flows_folder), reverse=True)
    try:
        sorted_flows = [flows[-1]]
    except IndexError:
        sorted_flows = []
    sorted_flows.extend(flows[:-1])

    if field:
        try:
            flow = [f for f in os.listdir(flows_folder) if f.endswith(field)][0]
            t = fp.parse_trace(os.path.join(flows_folder, flow))
            wt.add_trace(t)
        except Exception:
            return None
    else:
        n = 0
        for flow in sorted_flows:
            t = fp.parse_trace(os.path.join(flows_folder, flow))
            wt.add_trace(t)

            n += 1
            if n >= num_flows:
                break

    return wt


def set_hooked_data(wt, app_name, num_logs=NUM_FLOWS_PER_APP, field=None):
    logger.debug('Processing hooked data, ' + app_name)
    hooked_folder = os.path.join(CRYPTOHOOKER_LOGS_FOLDER, app_name)
    hd = HookedData()

    if not os.path.isdir(hooked_folder) or not os.listdir(hooked_folder):
        logger.warning('No hooked data found for {0}'.format(app_name))
        # return None

    logs = sorted(os.listdir(hooked_folder), reverse=True)
    try:
        sorted_logs = [logs[-1]]
    except IndexError:
        sorted_logs = []
    sorted_logs.extend(logs[:-1])

    if field:
        try:
            log = [f for f in os.listdir(hooked_folder) if f.endswith(field)][0]
            hd.parse_log(os.path.join(hooked_folder, log))
        except Exception:
            return None
    else:
        n = 0
        for log in sorted_logs:
            hd.parse_log(os.path.join(hooked_folder, log))

            n += 1
            if n >= num_logs:
                break

    enc_map = hd.get_encryption_map()
    random_IDs = hd.get_random_IDs()
    timestamps = hd.get_timestamps()

    wt.enrich_data(enc_map, random_IDs, timestamps)


def build_whitetree(wt, app_name, num_runs=NUM_FLOWS_PER_APP):
    logger.debug('Building WhiteTree, ' + app_name)
    output_dir = os.path.join(WHITE_TREES_FOLDER, app_name)
    logWT(wt, os.path.join(output_dir, 'initial'), num_runs=num_runs)

    for i in range(MAX_DECRYPTION_CYCLES):
        logger.debug('Iteration #{0}, decryption phase'.format(i))

        wt, status = wt.decrypt()
        logWT(wt, os.path.join(output_dir, '{0}-decrypted'.format(i)),
              num_runs=num_runs)

        if not status:
            break

    logger.debug('Marking random IDs')

    wt = wt.mark_random_IDs()
    logWT(wt, os.path.join(output_dir, 'mark-random'), num_runs=num_runs)

    logger.debug('Marking timestamps')

    wt = wt.mark_timestamps()
    wt = wt.mark_timestamps_patterns()
    logWT(wt, os.path.join(output_dir, 'mark-ts'), num_runs=num_runs)

    wt = wt.mark_gcm()

    return wt


def logWT(wt, fname, num_runs=NUM_FLOWS_PER_APP):
    with open(fname + '-elems-{0}'.format(num_runs), 'w') as outfile:
        for elem in wt.get_elements():
            outfile.write(elem + '\n')
        outfile.close()


def filter_node(node, trace, min_ts, wt):
    domain = node[0]
    path = node[1]
    try:
        key = node[2]
    except IndexError:
        key = None
    try:
        value = node[3]
    except IndexError:
        value = None

    whitelist = ''
    for elem in wt.get_elements():
        try:
            whitelist = whitelist + elem + '\n'
        except UnicodeDecodeError:
            pass

    if domain not in whitelist and not trace.contains(domain, min_ts):
        return False

    if path not in whitelist and not trace.contains(path, min_ts):
        return False

    if key:
        if key not in whitelist and not trace.contains(key, min_ts):
            return False

    if value:
        try:
            if value not in whitelist and not trace.contains(value, min_ts):
                return False
        except UnicodeError:
            return False

    return True


def align_filter_node(node, trace, min_ts, wt):
    domain = node[0]
    path = node[1]
    try:
        key = node[2]
    except IndexError:
        key = None
    try:
        value = node[3]
    except IndexError:
        value = None

    whitelist = ''
    for elem in wt.get_elements():
        try:
            whitelist = whitelist + elem + '\n'
        except UnicodeDecodeError:
            pass

    _domains = wt._root
    if domain not in _domains:
        v = domain
        vs = _domains.keys()
        matches = compare_values(v, vs, trace, min_ts, whitelist)

        if type(matches) is dict:
            for k in matches:
                for m in matches[k]:
                    if m not in whitelist and not trace.contains(m, min_ts):
                        return False
        else:
            for m in matches:
                if m not in whitelist and not trace.contains(m, min_ts):
                    return False

        return True

    _paths = _domains[domain]['paths']
    if path not in _paths:
        v = path
        vs = _paths.keys()
        matches = compare_values(v, vs, trace, min_ts, whitelist)

        if type(matches) is dict:
            for k in matches:
                for m in matches[k]:
                    if m not in whitelist and not trace.contains(m, min_ts):
                        return False
        else:
            splitted_matches = set()
            for m in matches:
                splitted_matches.update(m.split('/'))

            for m in splitted_matches:
                if m not in whitelist and not trace.contains(m, min_ts):
                    return False

        return True

    if key:
        _keys = _paths[path]['keys']
        if key not in _keys:
            v = key
            vs = _keys.keys()
            matches = compare_values(v, vs, trace, min_ts, whitelist)

            if type(matches) is dict:
                for k in matches:
                    for m in matches[k]:
                        if m not in whitelist and not trace.contains(m, min_ts):
                            return False
            else:
                for m in matches:
                    if m not in whitelist and not trace.contains(m, min_ts):
                        return False

            return True

    if value:
        _values = _keys[key]['values']
        if value not in _values:
            v = value
            vs = _values.keys()
            matches = compare_values(v, vs, trace, min_ts, whitelist)

            if type(matches) is dict:
                for k in matches:
                    for m in matches[k]:
                        try:
                            if m not in whitelist and not trace.contains(m, min_ts):
                                return False
                        except UnicodeDecodeError:
                            return False
            else:
                for m in matches:
                    try:
                        if m not in whitelist and not trace.contains(m, min_ts):
                            return False
                    except UnicodeDecodeError:
                        return False

            return True

    return True


def pre_alignment(value, values, leak_wt, wt):
    max_similarity = 0
    most_similar = None
    for v in values:
        similarity = SequenceMatcher(None, v, value).ratio()
        if similarity >= max_similarity:
            max_similarity = similarity
            most_similar = v

    value = str(value)
    most_similar = str(most_similar)

    for ctx in leak_wt.enc_map:
        if ctx:
             value = value.replace(ctx, leak_wt.enc_map[ctx])
    value = replace_timestamps(value)
    value = replace_gcm(value)
    for randomid in leak_wt.random_IDs:
        if randomid:
            value = value.replace(str(randomid), RANDOM_ID)

    for ctx in wt.enc_map:
        if ctx:
            most_similar = most_similar.replace(ctx, wt.enc_map[ctx])
    most_similar = replace_timestamps(most_similar)
    most_similar = replace_gcm(most_similar)
    for randomid in wt.random_IDs:
        if randomid:
            most_similar = most_similar.replace(str(randomid), RANDOM_ID)

    return value, [most_similar]


def pre_alignment_enc(value, values, leak_wt, wt):
    max_similarity = 0
    most_similar = None
    for v in values:
        similarity = SequenceMatcher(None, v, value).ratio()
        if similarity >= max_similarity:
            max_similarity = similarity
            most_similar = v

    try:
        dec_value = b64decode(value + '===')
        dec_most_similar = b64decode(most_similar + '===')
    except TypeError:
        return value, [most_similar]

    if valid_string(dec_value) and valid_string(dec_most_similar):
        return pre_alignment(dec_value, [dec_most_similar], leak_wt, wt)
    else:
        return value, [most_similar]


def just_another_node(node, trace, min_ts, wt, leak_wt):
    domain = node[0]
    path = node[1]
    try:
        key = node[2]
    except IndexError:
        key = None
    try:
        value = node[3]
    except IndexError:
        value = None

    whitelist = ''
    for elem in wt.get_elements():
        try:
            whitelist = whitelist + elem + '\n'
        except UnicodeDecodeError:
            pass

    _domains = wt._root
    if domain not in _domains:
        v = domain
        vs = _domains.keys()
        v, vs = pre_alignment(v, vs, leak_wt, wt)
        matches = compare_values(v, vs, trace, min_ts, whitelist)

        if type(matches) is dict:
            for k in matches:
                for m in matches[k]:
                    if m not in whitelist and not trace.contains(m, min_ts):
                        return False
        else:
            for m in matches:
                try:
                    if m not in whitelist and not trace.contains(m, min_ts):
                        return False
                except UnicodeDecodeError:
                    return False

        return True

    _paths = _domains[domain]['paths']
    if path not in _paths:
        v = path
        vs = _paths.keys()
        v, vs = pre_alignment(v, vs, leak_wt, wt)
        matches = compare_values(v, vs, trace, min_ts, whitelist)

        if type(matches) is dict:
            for k in matches:
                for m in matches[k]:
                    if m not in whitelist and not trace.contains(m, min_ts):
                        return False
        else:
            splitted_matches = set()
            for m in matches:
                splitted_matches.update(m.split('/'))

            for m in splitted_matches:
                try:
                    if m not in whitelist and not trace.contains(m, min_ts):
                        return False
                except UnicodeDecodeError:
                    return False

        return True

    if key:
        _keys = _paths[path]['keys']
        if key not in _keys:
            v = key
            vs = _keys.keys()
            v, vs = pre_alignment(v, vs, leak_wt, wt)
            matches = compare_values(v, vs, trace, min_ts, whitelist)

            if type(matches) is dict:
                for k in matches:
                    for m in matches[k]:
                        try:
                            if m not in whitelist and not trace.contains(m, min_ts):
                                return False
                        except UnicodeDecodeError:
                            return False
            else:
                for m in matches:
                    try:
                        if m not in whitelist and not trace.contains(m, min_ts):
                            return False
                    except UnicodeDecodeError:
                        return False

            return True

    if value:
        _values = _keys[key]['values']
        if value not in _values:
            v = value
            vs = _values.keys()

            v, vs = pre_alignment(v, vs, leak_wt, wt)
            matches = compare_values(v, vs, trace, min_ts, whitelist)

            if type(matches) is dict:
                for k in matches:
                    for m in matches[k]:
                        try:
                            if m not in whitelist and not trace.contains(m, min_ts):
                                return False
                        except UnicodeDecodeError:
                            return False
            else:
                for m in matches:
                    try:
                        if m not in whitelist and not trace.contains(m, min_ts):
                            return False
                    except UnicodeDecodeError:
                        return False

            return True

    return True


def just_another_encoded_node(node, trace, min_ts, wt, leak_wt):
    domain = node[0]
    path = node[1]
    try:
        key = node[2]
    except IndexError:
        key = None
    try:
        value = node[3]
    except IndexError:
        value = None

    whitelist = ''
    for elem in wt.get_elements():
        try:
            whitelist = whitelist + elem + '\n'
        except UnicodeDecodeError:
            pass

    _domains = wt._root
    if domain not in _domains:
        v = domain
        vs = _domains.keys()
        if vs:
            v, vs = pre_alignment_enc(v, vs, leak_wt, wt)
        matches = compare_values(v, vs, trace, min_ts, whitelist)

        if type(matches) is dict:
            for k in matches:
                for m in matches[k]:
                    if m not in whitelist and not trace.contains(m, min_ts):
                        return False
        else:
            for m in matches:
                try:
                    if m not in whitelist and not trace.contains(m, min_ts):
                        return False
                except UnicodeDecodeError:
                    return False

        return True

    _paths = _domains[domain]['paths']
    if path not in _paths:
        v = path
        vs = _paths.keys()
        v, vs = pre_alignment_enc(v, vs, leak_wt, wt)
        matches = compare_values(v, vs, trace, min_ts, whitelist)

        if type(matches) is dict:
            for k in matches:
                for m in matches[k]:
                    if m not in whitelist and not trace.contains(m, min_ts):
                        return False
        else:
            splitted_matches = set()
            for m in matches:
                splitted_matches.update(m.split('/'))

            for m in splitted_matches:
                try:
                    if m not in whitelist and not trace.contains(m, min_ts):
                        return False
                except UnicodeDecodeError:
                    return False

        return True

    if key:
        _keys = _paths[path]['keys']
        if key not in _keys:
            v = key
            vs = _keys.keys()
            v, vs = pre_alignment_enc(v, vs, leak_wt, wt)
            matches = compare_values(v, vs, trace, min_ts, whitelist)

            if type(matches) is dict:
                for k in matches:
                    for m in matches[k]:
                        if m not in whitelist and not trace.contains(m, min_ts):
                            return False
            else:
                for m in matches:
                    try:
                        if m not in whitelist and not trace.contains(m, min_ts):
                            return False
                    except UnicodeDecodeError:
                        return False

            return True

    if value:
        _values = _keys[key]['values']
        if value not in _values:
            v = value
            vs = _values.keys()

            v, vs = pre_alignment_enc(v, vs, leak_wt, wt)
            # v = v.decode('utf8')
            # vs[0] = vs[0].decode('utf8')
            # v = ''.join([i if ord(i) < 128 else '' for i in v])
            # vs[0] = ''.join([i if ord(i) < 128 else '' for i in vs[0]])
            matches = compare_values(v, vs, trace, min_ts, whitelist)

            if type(matches) is dict:
                for k in matches:
                    for m in matches[k]:
                        m = str(m)
                        if m not in whitelist and not trace.contains(m, min_ts):
                            return False
            else:
                for m in matches:
                    m = str(m)
                    try:
                        if m not in whitelist and not trace.contains(m, min_ts):
                            return False
                    except UnicodeDecodeError:
                        return False

            return True

    return True


def align_node_no_patterns(node, trace, min_ts, wt):
    domain = node[0]
    path = node[1]
    try:
        key = node[2]
    except IndexError:
        key = None
    try:
        value = node[3]
    except IndexError:
        value = None

    whitelist = ''
    for elem in wt.get_elements():
        try:
            whitelist = whitelist + elem + '\n'
        except UnicodeDecodeError:
            pass

    _domains = wt._root
    if domain not in _domains:
        v = domain
        vs = _domains.keys()
        matches = value_diffs(v, vs)

        for m in matches:
            if m not in whitelist and not trace.contains(m, min_ts):
                return False

        return True

    _paths = _domains[domain]['paths']
    if path not in _paths:
        v = path
        vs = _paths.keys()
        matches = value_diffs(v, vs)

        splitted_matches = set()
        for m in matches:
            splitted_matches.update(m.split('/'))

        for m in splitted_matches:
            if m not in whitelist and not trace.contains(m, min_ts):
                return False

        return True

    if key:
        _keys = _paths[path]['keys']
        if key not in _keys:
            v = key
            vs = _keys.keys()
            matches = value_diffs(v, vs)

            for m in matches:
                if m not in whitelist and not trace.contains(m, min_ts):
                    return False

            return True

    if value:
        _values = _keys[key]['values']
        if value not in _values:
            v = value
            vs = _values.keys()
            matches = value_diffs(v, vs)

            for m in matches:
                try:
                    if m not in whitelist and not trace.contains(m, min_ts):
                        return False
                except UnicodeDecodeError:
                    return False

            return True

    return True


def known_encoding_node(node, trace, min_ts, wt):
    domain = node[0]
    path = node[1]
    try:
        key = node[2]
    except IndexError:
        key = None
    try:
        value = node[3]
    except IndexError:
        value = None

    whitelist = ''
    for elem in wt.get_elements():
        try:
            whitelist = whitelist + elem + '\n'
        except UnicodeDecodeError:
            pass

    _domains = wt._root
    if domain not in _domains:
        v = domain
        decoded_values = set()
        decoded_values.add(v)
        try:
            decoded_values.add(b64decode(v + '==='))
        except TypeError:
            pass
        try:
            decoded_values.add(unquote(v))
        except TypeError:
            pass
        try:
            decoded_values.add(unquote(b64decode(v + '===')))
        except TypeError:
            pass

        for decoded in decoded_values:
            try:
                if decoded in whitelist or trace.contains(decoded, min_ts):
                    return True
            except UnicodeError:
                pass

        return False

    _paths = _domains[domain]['paths']
    if path not in _paths:
        splitted = path.split('/')

        for v in splitted:
            decoded_values = set()
            decoded_values.add(v)
            try:
                decoded_values.add(b64decode(v + '==='))
            except TypeError:
                pass
            try:
                decoded_values.add(unquote(v))
            except TypeError:
                pass
            try:
                decoded_values.add(unquote(b64decode(v + '===')))
            except TypeError:
                pass

            result = False
            for decoded in decoded_values:
                try:
                    if decoded in whitelist or trace.contains(decoded, min_ts):
                        result = True
                        break
                except UnicodeError:
                    pass

            if not result:
                return False

        return True

    if key:
        _keys = _paths[path]['keys']
        if key not in _keys:
            v = key
            decoded_values = set()
            decoded_values.add(v)
            try:
                decoded_values.add(b64decode(v + '==='))
            except TypeError:
                pass
            try:
                decoded_values.add(unquote(v))
            except TypeError:
                pass
            try:
                decoded_values.add(unquote(b64decode(v + '===')))
            except TypeError:
                pass

            for decoded in decoded_values:
                try:
                    if decoded in whitelist or trace.contains(decoded, min_ts):
                        return True
                except UnicodeError:
                    pass

            return False

    if value:
        _values = _keys[key]['values']
        if value not in _values:
            v = value
            decoded_values = set()
            decoded_values.add(v)
            try:
                decoded_values.add(b64decode(v + '==='))
            except TypeError:
                pass
            try:
                decoded_values.add(unquote(v))
            except TypeError:
                pass
            try:
                decoded_values.add(unquote(b64decode(v + '===')))
            except TypeError:
                pass

            for decoded in decoded_values:
                try:
                    if decoded in whitelist or trace.contains(decoded, min_ts):
                        return True
                except UnicodeError:
                    pass

            return False

    return True


def align_encoded_node(node, trace, min_ts, wt):
    domain = node[0]
    path = node[1]
    try:
        key = node[2]
    except IndexError:
        key = None
    try:
        value = node[3]
    except IndexError:
        value = None

    whitelist = ''
    for elem in wt.get_elements():
        try:
            whitelist = whitelist + elem + '\n'
        except UnicodeDecodeError:
            pass

    _domains = wt._root
    if domain not in _domains:
        v = domain
        vs = _domains.keys()
        decoded_values = set()
        try:
            decoded_v = b64decode(v + '===')
        except TypeError:
            return False

        for x in vs:
            try:
                decoded_values.add(b64decode(x + '==='))
            except TypeError:
                decoded_values.add(x)

        matches = value_diffs(decoded_v, list(decoded_values))

        for m in matches:
            try:
                if m not in whitelist and not trace.contains(m, min_ts):
                    return False
            except UnicodeDecodeError:
                return False

        return False

    _paths = _domains[domain]['paths']
    if path not in _paths:
        v = path
        vs = _paths.keys()
        decoded_values = set()
        try:
            decoded_v = b64decode(v + '===')
        except TypeError:
            return False

        for x in vs:
            try:
                decoded_values.add(b64decode(x + '==='))
            except TypeError:
                decoded_values.add(x)

        matches = value_diffs(decoded_v, list(decoded_values))

        splitted_matches = set()
        for m in matches:
            splitted_matches.update(m.split('/'))

        for m in splitted_matches:
            try:
                if m not in whitelist and not trace.contains(m, min_ts):
                    return False
            except UnicodeDecodeError:
                return False

        return True

    if key:
        _keys = _paths[path]['keys']
        if key not in _keys:
            v = key
            vs = _keys.keys()
            decoded_values = set()
            try:
                decoded_v = b64decode(v + '===')
            except TypeError:
                return False

            for x in vs:
                try:
                    decoded_values.add(b64decode(x + '==='))
                except TypeError:
                    decoded_values.add(x)

            matches = value_diffs(decoded_v, list(decoded_values))

            for m in matches:
                try:
                    if m not in whitelist and not trace.contains(m, min_ts):
                        return False
                except UnicodeDecodeError:
                    return False

            return True

    if value:
        _values = _keys[key]['values']
        if value not in _values:
            v = value
            vs = _values.keys()
            decoded_values = set()
            try:
                decoded_v = b64decode(v + '===')
            except TypeError:
                return False

            for x in vs:
                try:
                    decoded_values.add(b64decode(x + '==='))
                except TypeError:
                    decoded_values.add(x)

            matches = value_diffs(decoded_v, list(decoded_values))

            for m in matches:
                try:
                    if m not in whitelist and not trace.contains(m, min_ts):
                        return False
                except UnicodeDecodeError:
                    return False

            return True

    return True



def filter_network_content(leaks, leak_wt, wt):
    logger.info('Filtering network content')
    aux = set()
    for leak in leaks:
        node = leak.split(' - ', 3)
        trace, min_ts = leak_wt.get_trace(node)
        if filter_node(node, trace, min_ts, wt):
            aux.add(leak)

    leaks = leaks - aux
    return leaks


def align_filter(leaks, leak_wt, wt):
    logger.info('Aligning and filtering')
    aux = set()
    for leak in leaks:
        node = leak.split(' - ', 3)
        trace, min_ts = leak_wt.get_trace(node)

        if align_filter_node(node, trace, min_ts, wt):
            aux.add(leak)

    leaks = leaks - aux
    return leaks


def handle_specials(leaks, leak_wt, wt):
    logger.info('Handling specials')
    aux = set()
    for leak in leaks:
        node = leak.split(' - ', 3)
        trace, min_ts = leak_wt.get_trace(node)

        if align_node_no_patterns(node, trace, min_ts, wt):
            aux.add(leak)

    leaks = leaks - aux
    return leaks


def align_encoded(leaks, leak_wt, wt):
    logger.info('Aligning encoded')
    aux = set()
    for leak in leaks:
        node = leak.split(' - ', 3)
        trace, min_ts = leak_wt.get_trace(node)

        if align_encoded_node(node, trace, min_ts, wt):
            aux.add(leak)

    leaks = leaks - aux
    return leaks


def just_another(leaks, leak_wt, wt):
    logger.info('Just another')
    aux = set()
    for leak in leaks:
        node = leak.split(' - ', 3)
        trace, min_ts = leak_wt.get_trace(node)

        if just_another_node(node, trace, min_ts, wt, leak_wt):
            aux.add(leak)

    leaks = leaks - aux
    return leaks


def just_another_encoded(leaks, leak_wt, wt):
    logger.info('Just another encoded')
    aux = set()
    for leak in leaks:
        node = leak.split(' - ', 3)
        trace, min_ts = leak_wt.get_trace(node)

        if just_another_encoded_node(node, trace, min_ts, wt, leak_wt):
            aux.add(leak)

    leaks = leaks - aux
    return leaks


def handle_known_encoding(leaks, leak_wt, wt):
    logger.info('Handling known encoding')
    aux = set()
    for leak in leaks:
        node = leak.split(' - ', 3)
        trace, min_ts = leak_wt.get_trace(node)

        if known_encoding_node(node, trace, min_ts, wt):
            logger.debug('Found known encoding')
            aux.add(leak)

    leaks = leaks - aux
    return leaks


def whitelist_requests(leaks):
    logger.info('Whitelisting known requests')
    aux = set()
    for leak in leaks:
        node = leak.split(' - ', 3)
        domain = node[0]

        if domain in WHITELISTED_DOMAINS:
            aux.add(leak)

        # low score, whitelistable
        if 'a.applovin.com - /2.0/ad - etf -' in leak:
            aux.add(leak)

    leaks = leaks - aux
    return leaks


def leak_score(leaks, leak_wt, wt):
    logger.info('Calculating leak scores')

    leaks_with_scores = set()

    for leak in leaks:
        node = leak.split(' - ', 3)

        domain = node[0]
        path = node[1]
        try:
            key = node[2]
        except IndexError:
            key = None
        try:
            value = node[3]
        except IndexError:
            value = None

        _domains = wt._root
        if domain not in _domains:
            score = calc_score(domain, _domains.keys())
            leaks_with_scores.add((leak, score))
            continue

        _paths = _domains[domain]['paths']
        if path not in _paths:
            score = calc_score(path, _paths.keys())
            leaks_with_scores.add((leak, score))
            continue

        if key:
            _keys = _paths[path]['keys']
            if key not in _keys:
                score = calc_score(key, _keys.keys())
                leaks_with_scores.add((leak, score))
                continue

        if value:
            _values = _keys[key]['values']
            if value not in _values:
                score = calc_score(value, _values.keys())
                leaks_with_scores.add((leak, score))
                continue

    return leaks_with_scores


def identify_leaks(wt, app_name, num_runs=NUM_FLOWS_PER_APP, field=''):
    logger.debug('Identifying leaks, ' + app_name)

    leak_app_name = app_name + '_final'
    setup_folders(leak_app_name + field)

    leak_wt = create_whitetree(leak_app_name, field=field)
    set_hooked_data(leak_wt, leak_app_name, field=field)
    # workaround. TODO: do it better
    leak_wt.num_traces = 2
    leak_wt = build_whitetree(leak_wt, leak_app_name + field)

    leak_elems = leak_wt.get_elements()
    elems = wt.get_elements()

    leaks = leak_elems - elems

    leaks = filter_network_content(leaks, leak_wt, wt)
    # compare/align the rest
    leaks = align_filter(leaks, leak_wt, wt)

    leaks = handle_specials(leaks, leak_wt, wt)
    leaks = handle_known_encoding(leaks, leak_wt, wt)
    leaks = align_encoded(leaks, leak_wt, wt)
    leaks = just_another(leaks, leak_wt, wt)
    leaks = just_another_encoded(leaks, leak_wt, wt)

    leaks_with_scores = leak_score(leaks, leak_wt, wt)

    output_dir = os.path.join(WHITE_TREES_FOLDER, app_name)
    leaks_file = os.path.join(output_dir, 'leaks-{0}-{1}'.format(num_runs, field))
    with open(leaks_file, 'w') as outfile:
        for elem, score in leaks_with_scores:
            outfile.write(elem + ';\t' + str(score) + '\n')
        outfile.close()

    leaks_withelisted = whitelist_requests(leaks)
    leaks_with_scores = leak_score(leaks_withelisted, leak_wt, wt)
    logger.info('# Leaks detected: {0}'.format(len(leaks_withelisted)))

    leaks_file = os.path.join(output_dir, 'leaks-whitelisted-{0}-{1}'.format(num_runs, field))
    with open(leaks_file, 'w') as outfile:
        for elem, score in leaks_with_scores:
            outfile.write(elem + ';\t' + str(score) + '\n')
        outfile.close()

    return leaks_with_scores


def whitelist_analysis(app_name, field=None, num_runs=NUM_FLOWS_PER_APP, fdir=None, cdir=None, wtdir=None):
    logger.info('Starting analysis. App: {0}, num_runs: {1}'.format(app_name,
                                                                    num_runs))
    if fdir:
        global FLOWS_FOLDER
        FLOWS_FOLDER = fdir
    if wtdir:
        global WHITE_TREES_FOLDER
        WHITE_TREES_FOLDER = wtdir
    if cdir:
        global CRYPTOHOOKER_LOGS_FOLDER
        CRYPTOHOOKER_LOGS_FOLDER = cdir

    setup_folders(app_name)
    wt = create_whitetree(app_name, num_flows=num_runs)
    set_hooked_data(wt, app_name, num_logs=num_runs)
    wt = build_whitetree(wt, app_name, num_runs=num_runs)
    if field:
        if type(field) is list:
            for f in field:
                leaks = identify_leaks(wt, app_name, num_runs=num_runs, field=f)
        else:
            leaks = identify_leaks(wt, app_name, num_runs=num_runs, field=field)
    else:
        leaks = identify_leaks(wt, app_name, num_runs=num_runs)
    return leaks
