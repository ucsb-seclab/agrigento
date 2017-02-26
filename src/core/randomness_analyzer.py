# encoding=utf8
import sys
import os
import logging

from core.whitetree import WhiteTree
from core.flows_analyzer import create_whitetree, leak_score

from config.general_config import WHITE_TREES_FOLDER
from config.general_config import CRYPTOHOOKER_LOGS_FOLDER
from config.general_config import FLOWS_FOLDER
from config.general_config import LOGGING_LEVEL
from config.compare_config import NUM_FLOWS_PER_APP


reload(sys)
sys.setdefaultencoding('utf8')

logging.basicConfig(level=LOGGING_LEVEL,
                    format='[%(asctime)s] %(levelname)s:%(name)s:%(message)s',
                    datefmt='%d-%m-%Y %H:%M:%S')
logger = logging.getLogger('randomness-analyzer')


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


def identify_leaks(wt, app_name, num_runs=NUM_FLOWS_PER_APP, field=''):
    logger.debug('Identifying leaks, ' + app_name)

    leak_app_name = app_name + '_final'
    setup_folders(leak_app_name + field)

    leak_wt = create_whitetree(leak_app_name, field=field)

    leak_elems = leak_wt.get_elements()
    elems = wt.get_elements()

    leaks = leak_elems - elems
    leaks_with_scores = leak_score(leaks, leak_wt, wt)

    output_dir = os.path.join(WHITE_TREES_FOLDER, app_name)
    leaks_file = os.path.join(output_dir, 'leaks-{0}'.format(num_runs))
    with open(leaks_file, 'w') as outfile:
        for elem, score in leaks_with_scores:
            outfile.write(elem + ';\t' + str(score) + '\n')
        outfile.close()

    logger.info('# Leaks detected: {0}'.format(len(leaks)))
    return leaks_with_scores


def randomness_analysis(app_name, num_runs=NUM_FLOWS_PER_APP, fdir=None, cdir=None, wtdir=None):
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
    leaks = identify_leaks(wt, app_name, num_runs=num_runs)
    return leaks
