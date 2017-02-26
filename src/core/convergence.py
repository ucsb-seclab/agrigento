# encoding=utf8
import sys
import os
import logging

from base64 import b64decode
from urllib import unquote

from core.flow_parser import FlowParser
from core.whitetree import WhiteTree
from core.hooked import HookedData
from core.compare import compare_values, calc_score, value_diffs

from core.flows_analyzer import filter_network_content, align_filter
from core.flows_analyzer import handle_specials, handle_known_encoding
from core.flows_analyzer import whitelist_requests, leak_score, align_encoded
from core.flows_analyzer import just_another, just_another_encoded

from config.general_config import FLOWS_FOLDER, WHITE_TREES_FOLDER
from config.general_config import CRYPTOHOOKER_LOGS_FOLDER
from config.general_config import MAX_DECRYPTION_CYCLES
from config.general_config import LOGGING_LEVEL
from config.compare_config import NUM_FLOWS_PER_APP, WHITELISTED_DOMAINS


reload(sys)
sys.setdefaultencoding('utf8')

logging.basicConfig(level=LOGGING_LEVEL,
                    format='[%(asctime)s] %(levelname)s:%(name)s:%(message)s',
                    datefmt='%d-%m-%Y %H:%M:%S')
logger = logging.getLogger('convergence')


def create_whitetree(app_name, num_flows, final=False):
    logger.debug('Creating WhiteTree, ' + app_name)
    fp = FlowParser()
    flows_folder = os.path.join(FLOWS_FOLDER, app_name)

    if not os.path.isdir(flows_folder) or not os.listdir(flows_folder):
        logger.warning('No flows found for {0}'.format(app_name))

    wt = WhiteTree()

    flows = sorted(os.listdir(flows_folder), reverse=True)
    try:
        sorted_flows = [flows[-1]]
    except IndexError:
        sorted_flows = []
    sorted_flows.extend(flows[:-1])

    if final:
        try:
            flow = sorted_flows[num_flows - 1]
            t = fp.parse_trace(os.path.join(flows_folder, flow))
            wt.add_trace(t)
        except IndexError:
            pass

    else:
        for flow in sorted_flows[:num_flows - 1]:
            t = fp.parse_trace(os.path.join(flows_folder, flow))
            wt.add_trace(t)

    return wt


def set_hooked_data(wt, app_name, num_logs, final=False):
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

    if final:
        try:
            log = sorted_logs[num_logs - 1]
            hd.parse_log(os.path.join(hooked_folder, log))
        except IndexError:
            pass

    else:
        for log in sorted_logs[:num_logs - 1]:
            hd.parse_log(os.path.join(hooked_folder, log))

    enc_map = hd.get_encryption_map()
    random_IDs = hd.get_random_IDs()
    timestamps = hd.get_timestamps()

    wt.enrich_data(enc_map, random_IDs, timestamps)


def build_whitetree(wt, app_name):
    logger.debug('Building WhiteTree, ' + app_name)

    for i in range(MAX_DECRYPTION_CYCLES):
        logger.debug('Iteration #{0}, decryption phase'.format(i))

        wt, status = wt.decrypt()

        if not status:
            break

    logger.debug('Marking random IDs')
    wt = wt.mark_random_IDs()

    logger.debug('Marking timestamps')
    wt = wt.mark_timestamps()
    wt = wt.mark_timestamps_patterns()

    return wt


def identify_leaks(wt, app_name, num_runs):
    logger.debug('Identifying leaks, ' + app_name)

    leak_wt = create_whitetree(app_name, num_runs, final=True)
    set_hooked_data(leak_wt, app_name, num_runs, final=True)
    # workaround. TODO do it better
    leak_wt.num_traces = 2
    leak_wt = build_whitetree(leak_wt, app_name)

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

    leaks_withelisted = whitelist_requests(leaks)
    leaks_with_scores = leak_score(leaks_withelisted, leak_wt, wt)
    logger.info('# Leaks detected: {0}'.format(len(leaks_withelisted)))

    return leaks_with_scores


def convergence_analysis(app_name, num_runs, fdir=None, cdir=None):
    logger.info('Convergence analysis. App: {0}, num_runs: {1}'.format(app_name,
                                                                       num_runs))
    if fdir:
        global FLOWS_FOLDER
        FLOWS_FOLDER = fdir
    if cdir:
        global CRYPTOHOOKER_LOGS_FOLDER
        CRYPTOHOOKER_LOGS_FOLDER = cdir

    wt = create_whitetree(app_name, num_runs)
    set_hooked_data(wt, app_name, num_runs)
    wt = build_whitetree(wt, app_name)
    leaks = identify_leaks(wt, app_name, num_runs)

    return leaks
