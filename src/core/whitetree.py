import json
import logging
import pprint
import re

from copy import deepcopy
from operator import attrgetter

from core.utils import dict_merge, tuples_to_dict, contains_any
from core.utils import come_from_network, extend_matches
from core.compare import align_values, merge_sequences, get_alignment_seqs
from core.compare import seq_to_regex, get_alignment_matches
from core.compare import compare_http_queries, compare_jsons, compare_urls
from core.patterns import are_timestamps, are_urls
from core.patterns import contains_timestamps, replace_timestamps
from core.patterns import contains_gcm, replace_gcm
from core.patterns import are_jsons, are_http_queries
from config.general_config import LOGGING_LEVEL
from config.core_config import INV_TERM
from config.compare_config import RANDOM_ID, NETWORK, TIMESTAMP, WILDCARD

logging.basicConfig(level=LOGGING_LEVEL,
                    format='[%(asctime)s] %(levelname)s:%(name)s:%(message)s',
                    datefmt='%d-%m-%Y %H:%M:%S')
logger = logging.getLogger('whitetree')


class WhiteTree(object):

    def __init__(self):
        self._root = {}
        self.num_traces = 0
        self.enc_map = None
        self.random_IDs = None
        self.timestamps = None


    def add_trace(self, trace):
        logger.debug('New network trace')
        for connection in trace.connections:
            if connection.request.direction == 'out':
                self.add_entry(connection.request, trace)

        self.num_traces += 1


    def add_entry(self, entry, trace):
        logger.debug('New entry')
        domain = entry.http_domain
        path = entry.http_path
        query_keys = entry.http_query.keys()

        # root level: domains
        if not domain:
            return

        _domains = self._root
        if domain not in _domains:
            _domains[domain] = dict(paths={}, traces={})

        if trace not in _domains[domain]['traces']:
            _domains[domain]['traces'][trace] = []
        _domains[domain]['traces'][trace].append(entry)

        # second level: HTTP paths
        if not path:
            return

        _paths = _domains[domain]['paths']

        if path not in _paths:
            _paths[path] = dict(keys={}, traces={})

        if trace not in _paths[path]['traces']:
            _paths[path]['traces'][trace] = []
        _paths[path]['traces'][trace].append(entry)

        # third level: query keys
        if not query_keys:
            return

        _keys = _paths[path]['keys']

        for q_key in query_keys:
            if q_key not in _keys:
                _keys[q_key] = dict(values={}, traces={})

            if trace not in _keys[q_key]['traces']:
                _keys[q_key]['traces'][trace] = []
            _keys[q_key]['traces'][trace].append(entry)

            _values = _keys[q_key]['values']

            for q_value in entry.http_query[q_key]:

                # fourth level: query values
                if not q_value:
                    continue

                if q_value not in _values:
                    _values[q_value] = dict(traces={})

                if trace not in _values[q_value]['traces']:
                    _values[q_value]['traces'][trace] = []
                _values[q_value]['traces'][trace].append(entry)


    def enrich_data(self, enc_map, random_IDs, timestamps):
        self.enc_map = enc_map
        self.random_IDs = random_IDs
        self.timestamps = timestamps


    def decrypt(self):
        _new_wt = deepcopy(self)
        _domains = _new_wt._root
        num_traces = self.num_traces

        encr_domains = []
        encr_paths = []
        encr_keys = []
        encr_values = []

        status = False

        for domain in _domains:
            if domain in self.enc_map:
                encr_domains.append(domain)

            _paths = _domains[domain]['paths']
            for path in _paths:
                if path in self.enc_map:
                    encr_paths.append((domain, path))

                _keys = _paths[path]['keys']
                for q_key in _keys:
                    if q_key in self.enc_map:
                        encr_keys.append((domain, path, q_key))

                    _values = _keys[q_key]['values']
                    for q_value in _values:
                        if q_value in self.enc_map or q_value.replace('\n', '') in self.enc_map:
                            encr_values.append((domain, path, q_key, q_value))

        # do this in the right order (bottom->up)
        # values, keys, paths, domains

        # values
        for domain, path, key, value in encr_values:
            if 'icon_hash' == key:
                continue
            # substitute ctx with ptx
            try:
                new = self.enc_map[value]
            except KeyError:
                new = self.enc_map[value.replace('\n', '')]
            from core.utils import valid_string
            if not valid_string(new):
                aux = []
                for i in new:
                    if ord(i) >= 33 and ord(i) <= 125:
                        aux.append(i)
                new = ''.join(aux)
                #continue
            parent = _domains[domain]['paths'][path]['keys'][key]['values']
            WhiteTree.merge_nodes(parent, new, value)
            status = True

        # keys
        for domain, path, key in encr_keys:
            # substitute ctx with ptx
            new = self.enc_map[key]
            parent = _domains[domain]['paths'][path]['keys']
            WhiteTree.merge_nodes(parent, new, key)
            status = True

        # paths
        for domain, path in encr_paths:
            # substitute ctx with ptx
            new = self.enc_map[path]
            parent = _domains[domain]['paths']
            WhiteTree.merge_nodes(parent, new, path)
            status = True

        # domains
        for domain in encr_domains:
            # substitute ctx with ptx
            new = self.enc_map[domain]
            parent = _domains
            WhiteTree.merge_nodes(parent, new, domain)
            status = True

        return _new_wt, status


    def mark_network_content(self):
        _new_wt = deepcopy(self)
        _domains = _new_wt._root
        num_traces = self.num_traces

        net_domains = []
        net_paths = []
        net_keys = []
        net_values = []

        for domain in _domains:
            if len(_domains[domain]['traces'].keys()) != num_traces:
                trace =_domains[domain]['traces'].keys()[0]
                min_ts = min(_domains[domain]['traces'][trace],
                             key=attrgetter('timestamp')).timestamp
                if trace.contains(domain, min_ts):
                    net_domains.append(domain)

            _paths = _domains[domain]['paths']
            for path in _paths:
                if len(_paths[path]['traces'].keys()) != num_traces:
                    trace =_paths[path]['traces'].keys()[0]
                    min_ts = min(_paths[path]['traces'][trace],
                                 key=attrgetter('timestamp')).timestamp
                    if trace.contains(path, min_ts):
                        net_paths.append((domain, path))

                _keys = _paths[path]['keys']
                for q_key in _keys:
                    if len(_keys[q_key]['traces'].keys()) != num_traces:
                        trace =_keys[q_key]['traces'].keys()[0]
                        min_ts = min(_keys[q_key]['traces'][trace],
                                     key=attrgetter('timestamp')).timestamp
                        if trace.contains(q_key, min_ts):
                            net_keys.append((domain, path, q_key))

                    _values = _keys[q_key]['values']
                    for q_value in _values:
                        if len(_values[q_value]['traces'].keys()) != num_traces:
                            trace =_values[q_value]['traces'].keys()[0]
                            min_ts = min(_values[q_value]['traces'][trace],
                                         key=attrgetter('timestamp')).timestamp
                            if trace.contains(q_value, min_ts):
                                net_values.append((domain, path,
                                                         q_key, q_value))

        for domain, path, key, value in net_values:
            parent = _domains[domain]['paths'][path]['keys'][key]['values']
            WhiteTree.merge_nodes(parent, NETWORK, value)

        for domain, path, key in net_keys:
            parent = _domains[domain]['paths'][path]['keys']
            WhiteTree.merge_nodes(parent, NETWORK, key)

        for domain, path in net_paths:
            parent = _domains[domain]['paths']
            WhiteTree.merge_nodes(parent, NETWORK, path)

        for domain in net_domains:
            parent = _domains
            WhiteTree.merge_nodes(parent, NETWORK, domain)

        return _new_wt


    def mark_gcm(self):
        _new_wt = deepcopy(self)
        _domains = _new_wt._root
        num_traces = self.num_traces

        ts_domains = []
        ts_paths = []
        ts_keys = []
        ts_values = []

        for domain in _domains:
            if contains_gcm(domain):
                ts_domains.append(domain)

            _paths = _domains[domain]['paths']
            for path in _paths:
                if contains_gcm(path):
                    ts_paths.append((domain, path))

                _keys = _paths[path]['keys']
                for q_key in _keys:
                    if contains_gcm(q_key):
                        ts_keys.append((domain, path, q_key))

                    _values = _keys[q_key]['values']
                    for q_value in _values:
                        if contains_gcm(q_value):
                            ts_values.append((domain, path, q_key, q_value))

        # do this in the right order (bottom->up)
        # values, keys, paths, domains

        # values
        for domain, path, key, value in ts_values:
            # replace timestamps
            parent = _domains[domain]['paths'][path]['keys'][key]['values']
            WhiteTree.merge_nodes(parent, replace_gcm(value), value)

        # keys
        for domain, path, key in ts_keys:
            # replace timestamps
            parent = _domains[domain]['paths'][path]['keys']
            WhiteTree.merge_nodes(parent, replace_gcm(key), key)

        # paths
        for domain, path in ts_paths:
            # replace timestamps
            parent = _domains[domain]['paths']
            WhiteTree.merge_nodes(parent, replace_gcm(path), path)

        # domains
        for domain in ts_domains:
            # replace timestamps
            parent = _domains
            WhiteTree.merge_nodes(parent, replace_gcm(domain), domain)

        return _new_wt


    def mark_timestamps_patterns(self):
        _new_wt = deepcopy(self)
        _domains = _new_wt._root
        num_traces = self.num_traces

        ts_domains = []
        ts_paths = []
        ts_keys = []
        ts_values = []

        for domain in _domains:
            if contains_timestamps(domain):
                ts_domains.append(domain)

            _paths = _domains[domain]['paths']
            for path in _paths:
                if contains_timestamps(path):
                    ts_paths.append((domain, path))

                _keys = _paths[path]['keys']
                for q_key in _keys:
                    if contains_timestamps(q_key):
                        ts_keys.append((domain, path, q_key))

                    _values = _keys[q_key]['values']
                    for q_value in _values:
                        if contains_timestamps(q_value):
                            ts_values.append((domain, path, q_key, q_value))

        # do this in the right order (bottom->up)
        # values, keys, paths, domains

        # values
        for domain, path, key, value in ts_values:
            # replace timestamps
            parent = _domains[domain]['paths'][path]['keys'][key]['values']
            WhiteTree.merge_nodes(parent, replace_timestamps(value), value)

        # keys
        for domain, path, key in ts_keys:
            # replace timestamps
            parent = _domains[domain]['paths'][path]['keys']
            WhiteTree.merge_nodes(parent, replace_timestamps(key), key)

        # paths
        for domain, path in ts_paths:
            # replace timestamps
            parent = _domains[domain]['paths']
            WhiteTree.merge_nodes(parent, replace_timestamps(path), path)

        # domains
        for domain in ts_domains:
            # replace timestamps
            parent = _domains
            WhiteTree.merge_nodes(parent, replace_timestamps(domain), domain)

        return _new_wt


    def mark_timestamps(self):
        _new_wt = deepcopy(self)
        _domains = _new_wt._root
        whitelist = ''

        for elem in self.get_elements():
            try:
                whitelist = whitelist + elem + '<END>\n'
            except UnicodeDecodeError:
                pass

        elems = whitelist.split('<END>\n')

        for ts in self.timestamps:
            try:
                whitelist = whitelist.replace(ts, TIMESTAMP)
            except UnicodeDecodeError:
                whitelist = whitelist.decode('latin-1').encode('utf8')
                whitelist = whitelist.replace(ts, TIMESTAMP)

        new_elems = whitelist.split('<END>\n')

        try:
            assert(len(elems) == len(new_elems))
        except AssertionError:
            return _new_wt

        for i in range(len(elems)):
            if elems[i] != new_elems[i]:
                node = elems[i].split(' - ', 3)
                new_node = new_elems[i].split(' - ', 3)

                assert(len(node) == len(new_node))

                domain = node[0]
                new_domain = new_node[0]
                path = node[1]
                new_path = new_node[1]
                try:
                    key = node[2]
                    new_key = new_node[2]
                except IndexError:
                    key = None
                    new_key = None
                try:
                    value = node[3]
                    new_value = new_node[3]
                except IndexError:
                    value = None
                    new_value = None

                if value:
                    try:
                        parent = _domains[domain]['paths'][path]['keys']
                    except KeyError:
                        # path already merged
                        parent = _domains[domain]['paths'][new_path]['keys']
                    parent = parent[key]['values']
                    WhiteTree.merge_nodes(parent, new_value, value)

                if key:
                    try:
                        parent = _domains[domain]['paths'][path]['keys']
                    except KeyError:
                        # path already merged
                        parent = _domains[domain]['paths'][new_path]['keys']
                    WhiteTree.merge_nodes(parent, new_key, key)

                parent = _domains[domain]['paths']
                # check if path was already merged
                if path in parent and new_path not in parent:
                    WhiteTree.merge_nodes(parent, new_path, path)

                parent = _domains
                WhiteTree.merge_nodes(parent, new_domain, domain)

        return _new_wt


    def mark_random_IDs(self):
        _new_wt = deepcopy(self)
        _domains = _new_wt._root
        num_traces = self.num_traces

        rand_domains = []
        rand_paths = []
        rand_keys = []
        rand_values = []

        for domain in _domains:
            if contains_any(self.random_IDs, domain):
                rand_domains.append(domain)

            _paths = _domains[domain]['paths']
            for path in _paths:
                if contains_any(self.random_IDs, path):
                    rand_paths.append((domain, path))

                _keys = _paths[path]['keys']
                for q_key in _keys:
                    if contains_any(self.random_IDs, q_key):
                        rand_keys.append((domain, path, q_key))

                    _values = _keys[q_key]['values']
                    for q_value in _values:
                        if contains_any(self.random_IDs, q_value):
                            rand_values.append((domain, path, q_key, q_value))

        # do this in the right order (bottom->up)
        # values, keys, paths, domains

        # values
        for domain, path, key, value in rand_values:
            # replace timestamps
            parent = _domains[domain]['paths'][path]['keys'][key]['values']
            new = value
            for r in self.random_IDs:
                new = new.replace(r, RANDOM_ID)
            WhiteTree.merge_nodes(parent, new, value)

        # keys
        for domain, path, key in rand_keys:
            # replace timestamps
            parent = _domains[domain]['paths'][path]['keys']
            new = key
            for r in self.random_IDs:
                new = new.replace(r, RANDOM_ID)
            WhiteTree.merge_nodes(parent, new, key)

        # paths
        for domain, path in rand_paths:
            # replace timestamps
            parent = _domains[domain]['paths']
            new = path
            for r in self.random_IDs:
                new = new.replace(r, RANDOM_ID)
            WhiteTree.merge_nodes(parent, new, path)

        # domains
        for domain in rand_domains:
            # replace timestamps
            parent = _domains
            new = domain
            for r in self.random_IDs:
                new = new.replace(r, RANDOM_ID)
            WhiteTree.merge_nodes(parent, new, domain)

        return _new_wt


    def align_variants(self):
        _new_wt = deepcopy(self)
        _domains = _new_wt._root
        num_traces = self.num_traces

        variant_domains = []
        variant_paths = {}
        variant_keys = {}
        variant_values = {}

        status = False

        for domain in _domains:
            if len(_domains[domain]['traces'].keys()) != num_traces:
                variant_domains.append(domain)

            _paths = _domains[domain]['paths']
            for path in _paths:
                if len(_paths[path]['traces'].keys()) != num_traces:
                    if domain not in variant_paths:
                        variant_paths[domain] = []
                    variant_paths[domain].append(path)

                _keys = _paths[path]['keys']
                for q_key in _keys:
                    if len(_keys[q_key]['traces'].keys()) != num_traces:
                        if (domain, path) not in variant_keys:
                            variant_keys[(domain, path)] = []
                        variant_keys[(domain, path)].append(q_key)

                    _values = _keys[q_key]['values']
                    for q_value in _values:
                        if len(_values[q_value]['traces'].keys()) != num_traces:
                            if (domain, path, q_key) not in variant_values:
                                variant_values[(domain, path, q_key)] = []
                            variant_values[(domain, path, q_key)].append(q_value)

        # values
        for domain, path, key in variant_values:
            parent = _domains[domain]['paths'][path]['keys'][key]
            variants_list = variant_values[(domain, path, key)]
            regex = self.compare_variants(parent, 'values', variants_list)
            if regex and WILDCARD not in regex and len(variants_list) > 1:
                status = True
                for v in variants_list:
                    parent = _domains[domain]['paths'][path]['keys'][key]['values']
                    WhiteTree.merge_nodes(parent, regex, v)

        # keys
        for domain, path in variant_keys:
            parent = _domains[domain]['paths'][path]
            variants_list = variant_keys[(domain, path)]
            regex = self.compare_variants(parent, 'keys', variants_list)
            if regex and WILDCARD not in regex and len(variants_list) > 1:
                status = True
                for v in variants_list:
                    parent = _domains[domain]['paths'][path]['keys']
                    WhiteTree.merge_nodes(parent, regex, v)

        # paths
        for domain in variant_paths:
            parent = _domains[domain]
            variants_list = variant_paths[domain]
            regex = self.compare_variants(parent, 'paths', variants_list)
            if regex and WILDCARD not in regex and len(variants_list) > 1:
                status = True
                for v in variants_list:
                    parent = _domains[domain]['paths']
                    WhiteTree.merge_nodes(parent, regex, v)

        # domains
        parent = None  # there is no domains parent node
        variants_list = variant_domains
        regex = self.compare_variants(parent, 'domains', variants_list)
        if regex and WILDCARD not in regex and len(variants_list) > 1:
            status = True
            for v in variants_list:
                parent = _domains
                WhiteTree.merge_nodes(parent, regex, v)

        # _new_wt.domains_regex = self.domains_regex  # copy in the new wt

        return _new_wt, status


    def generate_regex(self, values, traces):
        a = align_values(values)
        seq = merge_sequences(get_alignment_seqs(a))
        regex =  seq_to_regex(seq)

        all_matches = get_alignment_matches(values, seq)

        if len(all_matches) == len(values):

            for matches in zip(*all_matches):

                ptxs = set([self.enc_map.get(x, None) for x in matches])

                extended_matches = extend_matches(values, matches)
                extended_match_values = [v[0] for v in extended_matches]
                start = regex.find('(.*)?') - extended_matches[0][1] + 1
                end = regex.find('(.*)?') + len('(.*)?') + \
                      extended_matches[0][2]

                # pattern matching
                if are_timestamps(matches):
                    regex = regex.replace('(.*)?', TIMESTAMP, 1)

                elif are_timestamps(extended_match_values):
                    regex = regex.replace(regex[start: end], TIMESTAMP, 1)

                # network filter
                elif come_from_network(matches, traces):
                    regex = regex.replace('(.*)?', NETWORK, 1)

                elif come_from_network(extended_match_values, traces):
                    regex = regex.replace(regex[start: end], NETWORK, 1)

                # randomIDs
                elif set(extended_match_values) < set(self.random_IDs):
                    regex = regex.replace('(.*)?', RANDOM_ID, 1)

                # same encrypted ptx
                elif len(ptxs) == 1 and None not in ptxs:
                    regex = regex.replace('(.*)?', ptxs[0], 1)

                # set as optional if len == 1
                matches = [m for m in matches if m]  # filter null values
                if len(matches) == 1:
                    regex = regex.replace('(.*)?', matches[0], 1)

        else:
            Exception("len(all_matches) != len(values). Is it expected?")

        return regex


    def generate_dict_regex(self, inv, variants, others, var_to_values, traces):
        regexes = {}

        for k in variants:
            if len(variants[k]) > 1:
                found = True

                # network filter
                local_traces = [traces[var_to_values[(k, v)]] for v in variants[k]]

                ptxs = set([self.enc_map.get(x, None) for x in variants[k]])

                # pattern matching
                if are_timestamps(variants[k]):
                    regexes[k] = TIMESTAMP

                elif come_from_network(variants[k], local_traces):
                    regexes[k] = NETWORK

                # randomIDs
                elif set(variants[k]) < set(self.random_IDs):
                    regexes[k] = RANDOM_ID

                # same encrypted ptx
                elif len(ptxs) == 1 and None not in ptxs:
                    regexes[k] = ptxs[0]

                else:
                    regexes[k] = self.generate_regex(variants[k], local_traces)

            # len(variants[k]) == 1
            else:
                regexes[k] = variants[k][0]

        for k in others:
            if len(others[k]) > 1:
                found = True

                # network filter
                local_traces = [traces[var_to_values[(k, v)]] for v in others[k]]

                ptxs = set([self.enc_map.get(x, None) for x in others[k]])

                # pattern matching
                if are_timestamps(others[k]):
                    regexes[k] = TIMESTAMP

                elif come_from_network(others[k], local_traces):
                    regexes[k] = NETWORK

                # randomIDs
                elif set(others[k]) < set(self.random_IDs):
                    regexes[k] = RANDOM_ID

                # same encrypted ptx
                elif len(ptxs) == 1 and None not in ptxs:
                    regexes[k] = ptxs[0]

                else:
                    regexes[k] = self.generate_regex(others[k], local_traces)

            else:
                regexes[k] = others[k][0]
                # regexes[k] = WILDCARD

        final = {}

        for k in inv:
            final[k] = inv[k]

        for k in variants:
            final[k] = regexes[k]

        for k in others:
            # better "encoding"?
            final['(' + k + ')?'] = '(' + regexes[k] + ')?'

        regex = str(final)
        return regex


    def compare_variants(self, parent, parent_key, values):
        logger.debug('Comparing variants ({0})'.format(parent_key))

        if parent:
            traces_by_value = {v: parent[parent_key][v]['traces'] for v in values}
            traces = [parent[parent_key][v]['traces'] for v in values]
        else:
            traces_by_value = {v: self._root[v]['traces'] for v in values}
            traces = [self._root[v]['traces'] for v in values]

        if  len(values) > 1:
            # Hanlde JSONs
            if are_jsons(values):
                logger.debug('Comparing JSONs, {0}'.format(values))
                result = compare_jsons(values)
                invariants, variants, others, var_to_values = result

                variants = tuples_to_dict(variants)
                invariants = tuples_to_dict(invariants)
                others = tuples_to_dict(others)

                regex = self.generate_dict_regex(invariants, variants, others,
                                                 var_to_values, traces_by_value)

            # Handle HTTP_QUERIES
            elif are_http_queries(values):
                logger.debug('Comparing HTTP queries, {0}'.format(values))
                result = compare_http_queries(values)
                invariants, variants, others, var_to_values = result

                variants = tuples_to_dict(variants)
                invariants = tuples_to_dict(invariants)
                others = tuples_to_dict(others)

                regex = self.generate_dict_regex(invariants, variants, others,
                                                 var_to_values, traces_by_value)

            # Handle URLs
            elif are_urls(values):
                logger.debug('Comparing URLs, {0}'.format(values))
                result = compare_urls(values)
                invariants, variants, others, var_to_values = result

                variants = tuples_to_dict(variants)
                invariants = tuples_to_dict(invariants)
                others = tuples_to_dict(others)

                regex = self.generate_dict_regex(invariants, variants, others,
                                                 var_to_values, traces_by_value)

            elif are_timestamps(values):
                logger.debug('Identified timestamps, {0}'.format(values))
                regex = TIMESTAMP

            else:
                logger.debug('Comparing values, {0}'.format(values))
                regex = self.generate_regex(values, traces)

            return regex

        elif len(values) == 1:
            return values[0]


    def delete_nodes(self, nodes):
        _new_wt = deepcopy(self)
        _domains = _new_wt._root
        num_traces = self.num_traces

        domains = []
        paths = []
        keys = []
        values = []

        for node in nodes:
            if len(node) == 4:
                values.append(node)
            elif len(node) == 3:
                keys.append(node)
            elif len(node) == 2:
                paths.append(node)
            elif len(node) == 1:
                domains.append(node)
            else:
                raise Exception("Unexpected node length")

        # do this in the right order (bottom->up)
        # values, keys, paths, domains

        # values
        for domain, path, key, value in values:
            del _domains[domain]['paths'][path]['keys'][key]['values'][value]

        # keys
        for domain, path, key in keys:
            del _domains[domain]['paths'][path]['keys'][key]

        # paths
        for domain, path in paths:
            del _domains[domain]['paths'][path]

        # domains
        for domain in domains:
            del _domains[domain]

        return _new_wt


    @staticmethod
    def merge_nodes(parent, node, merge_node, delete=True):
        if node != merge_node:
            if node in parent:
                dict_merge(parent[node], parent[merge_node])
            else:
                parent[node] = parent[merge_node]
            if delete:
                del parent[merge_node]


    def get_trace(self, node):
        _domains = self._root

        if len(node) == 4:
            domain, path, key, value = node
            _values = _domains[domain]['paths'][path]['keys'][key]['values']
            trace = _values[value]['traces'].keys()[0]
            min_ts = min(_values[value]['traces'][trace],
                         key=attrgetter('timestamp')).timestamp

        elif len(node) == 3:
            domain, path, key = node
            _keys = _domains[domain]['paths'][path]['keys']
            trace = _keys[key]['traces'].keys()[0]
            min_ts = min(_keys[key]['traces'][trace],
                         key=attrgetter('timestamp')).timestamp

        elif len(node) == 2:
            domain, path = node
            _paths = _domains[domain]['paths']
            trace = _paths[path]['traces'].keys()[0]
            min_ts = min(_paths[path]['traces'][trace],
                         key=attrgetter('timestamp')).timestamp

        else:
            raise Exception("Unexpected node length")

        return trace, min_ts


    def get_elements(self):
        _domains = self._root
        elements = set()

        for domain in _domains:
            _paths = _domains[domain]['paths']
            for path in _paths:
                _keys = _paths[path]['keys']
                
                if not _keys:
                    elements.add((domain, path))

                else:
                    for q_key in _keys:
                        _values = _keys[q_key]['values']
                                       
                        if not _values:
                            elements.add((domain, path, q_key))
                
                        else:
                            for q_value in _values:
                                elements.add((domain, path, q_key, q_value))

        return {' - '.join(i) for i in elements}


    def pretty_print(self):
        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(self.__dict__)


    def pretty_print_to_file(self, out_file):
        pp = pprint.PrettyPrinter(stream=out_file, indent=2)
        pp.pprint(self.__dict__)


    def to_json(self):
        data = json.dumps(self.__dict__, sort_keys=True)
        return data


    def from_json(self, json_string):
        data = json.loads(json_string)

        self._root = data['_root']
        self.num_traces = data['num_traces']

        return self
