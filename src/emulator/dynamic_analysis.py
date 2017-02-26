import os
import logging

from time import sleep, time
from copy import deepcopy

from emulator.adb_driver import ADBDriver, ADBDriverError
from emulator.utils import *

from core.flows_analyzer import whitelist_analysis

from config.emulator_config import OPERATIONS_SLEEPTIME, SEED, ANALYSIS_TIMEOUT
from config.general_config import FLOWS_FOLDER, LOGGING_LEVEL
from config.general_config import RUNS_PER_APP, DEF_LAT, DEF_LON
from config.general_config import CRYPTOHOOKER_LOGS_FOLDER
from config.hooked_config import CRYPTOHOOKER_FOLDER, CRYPTOHOOKER_LOG_DEVICE
from config.hooked_config import CRYPTOHOOKER_PACKAGENAME_FILE
from config.hooked_config import CRYPTOHOOKER_RANDOMNUM_FILE
from config.hooked_config import RANDOM_NUM_FILE
from config.hooked_config import CHANGER_FOLDER, CHANGER_PACKAGENAME_FILE
from config.values import data_default, data_special

from proxy.proxy_server import Proxy
from proxy.proxy_server import set_iptables, delete_iptables

logging.basicConfig(level=LOGGING_LEVEL,
                    format='[%(asctime)s] %(levelname)s:%(name)s:%(message)s',
                    datefmt='%d-%m-%Y %H:%M:%S')
logger = logging.getLogger('dynamic-analysis')


class DynamicAnalysisError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg


class DynamicAnalysis(object):
    """DynamicAnalysis"""

    def __init__(self, device_name, apk_path, n_runs=RUNS_PER_APP, emulator=False):
        if not os.path.isfile(apk_path):
            raise DynamicAnalysisError('File not found {0}'.format(apk_path))

        self.n_runs = n_runs
        self.max_trials = n_runs + 3
        self.emulator = emulator
        self.apk_path = apk_path
        self.apk_name = os.path.basename(apk_path)
        self.device_name = device_name
        self.start_ts = None
        self.stop_ts = None


    def start_analysis(self):
        self.start_ts = int(time())
        logger.info('Starting analysis')

        ip_address = ADBDriver.get_device_ipaddress(self.device_name)
        self.proxy_port = int('40' + ip_address.split('.')[-1])

        # set proxy iptables
        logger.debug('Setting proxy iptables')
        set_iptables(ip_address, self.proxy_port)

        success_runs = 0
        total_runs = 0
        while success_runs < self.n_runs and total_runs < self.max_trials:
            logger.info('APK: {0} Run #{1}'.format(self.apk_name, success_runs))

            if success_runs == 0:
                # firts run, record ts
                status = self.run_apk(first=True)
            else:
                status = self.run_apk()

            if status:
                success_runs += 1
                logger.info('Run completed')
            else:
                logger.info('Run failed')
            total_runs += 1

        if total_runs == self.max_trials:
            logger.error('Reached max number of trials')

        # change all
        success_runs = 0
        total_runs = 0
        while success_runs < 1 and total_runs < 2:
            logger.info('APK: {0} Final Run'.format(self.apk_name))
            status = self.run_apk(final=True, field='all')
            if status:
                success_runs += 1
                logger.info('Final Run (all) completed')
            else:
                logger.info('Final Run (all) failed')
            total_runs += 1

        leaks = whitelist_analysis(self.apk_name, field='all')
        sensitive_fields = data_default.keys()
        if leaks:
            for field in sensitive_fields:
                success_runs = 0
                total_runs = 0
                while success_runs < 1 and total_runs < 2:
                    logger.info('APK: {0} Final Run'.format(self.apk_name))
                    status = self.run_apk(final=True, field=field)
                    if status:
                        success_runs += 1
                        logger.info('Final Run ({0}) completed'.format(field))
                    else:
                        logger.info('Final Run ({0}) failed'.format(field))
                    total_runs += 1

        self.stop_ts = int(time())
        elapsed_time = self.stop_ts - self.start_ts

        # delete proxy iptables
        logger.debug('Deleting proxy iptables')
        delete_iptables(ip_address, self.proxy_port)

        logger.info('Analysis completed, {0}'.format(self.apk_name))
        logger.info('Elapsed time: {0} seconds'.format(elapsed_time))


    def run_apk(self, first=False, final=False, field=None):
        logger.debug('Preparing to run apk {0}'.format(self.apk_name))
        # Setting up folders

        try:
            os.stat(FLOWS_FOLDER)
        except:
            os.mkdir(FLOWS_FOLDER)

        if final:
            output_dir = os.path.join(FLOWS_FOLDER, self.apk_name + '_final')
        else:
            output_dir = os.path.join(FLOWS_FOLDER, self.apk_name)

        try:
            os.stat(output_dir)
        except:
            os.mkdir(output_dir)

        try:
            os.stat(CRYPTOHOOKER_LOGS_FOLDER)
        except:
            os.mkdir(CRYPTOHOOKER_LOGS_FOLDER)

        if final:
            hooked_data_dir = os.path.join(CRYPTOHOOKER_LOGS_FOLDER,
                                           self.apk_name + '_final')
        else:
            hooked_data_dir = os.path.join(CRYPTOHOOKER_LOGS_FOLDER,
                                           self.apk_name)

        try:
            os.stat(hooked_data_dir)
        except:
            os.mkdir(hooked_data_dir)

        self.proxy = Proxy(port=self.proxy_port)

        ts = int(time())

        self.adb = ADBDriver(self.device_name, emulator=self.emulator)
        if self.emulator:
            self.adb.start()

        package = get_APK_package_name(self.apk_path)
        activity = get_APK_main_activity(self.apk_path)

        if final:
            flow_name = '{0}_{1}.flow_{2}'.format(self.apk_name, ts, field)
        else:
            flow_name = '{0}_{1}.flow'.format(self.apk_name, ts)
        flow_file = os.path.join(output_dir, flow_name)
        self.proxy.start(flow_file)

        if self.emulator:
            self.adb.completeboot()

        sleep(OPERATIONS_SLEEPTIME)
        self.adb.install_cert()

        self.adb.create_writeble_folder(CHANGER_FOLDER)
        self.adb.write_file(CHANGER_PACKAGENAME_FILE, package)
        self.set_sensitive_field(field)

        # self.adb.flush_logcat()
        self.adb.delete_folder(CRYPTOHOOKER_FOLDER)
        self.adb.create_writeble_folder(CRYPTOHOOKER_FOLDER)
        self.adb.set_logfile(CRYPTOHOOKER_LOG_DEVICE)
        self.adb.write_file(CRYPTOHOOKER_PACKAGENAME_FILE, package)
        self.adb.adb_cmd(['push', RANDOM_NUM_FILE, CRYPTOHOOKER_RANDOMNUM_FILE])

        if first:
            self.adb.set_record_ts(True)
        else:
            self.adb.set_record_ts(False)

        if not self.emulator:
            self.adb.turn_on_screen()
        self.adb.unlock()
        sleep(OPERATIONS_SLEEPTIME)

        try:
            self.adb.install(self.apk_path)
        except ADBDriverError as e:
            self.finish_run()
            # remove flow file
            if os.path.isfile(flow_file):
                os.remove(flow_file)
            return False

        if not self.emulator:
            self.adb.set_iptables(package)
        sleep(OPERATIONS_SLEEPTIME)

        try:
            self.adb.start_activity(package, activity)
        except ADBDriverError as e:
            self.finish_run()
            # remove flow file
            if os.path.isfile(flow_file):
                os.remove(flow_file)
            return False

        sleep(OPERATIONS_SLEEPTIME)

        try:
            self.adb.start_monkey(package=package, seed=SEED)
        except ADBDriverError as e:
            logger.warning('Monkey execution hit timeout')
            self.adb.kill_monkey()

        # wait the end of the analysis
        sleep(ANALYSIS_TIMEOUT)

        if final:
            log_name = '{0}_{1}.log_{2}'.format(self.apk_name, ts, field)
        else:
            log_name = '{0}_{1}.log'.format(self.apk_name, ts)
        cryptohookerlog = os.path.join(hooked_data_dir, log_name)
        self.adb.get_file(CRYPTOHOOKER_LOG_DEVICE, cryptohookerlog)

        self.finish_run()
        return True
        # check run results 
        # return self.check_run([flow_file, cryptohookerlog])


    def finish_run(self):
        if self.emulator:
            self.adb.stop()
            self.adb.destroy()
        else:
            package = get_APK_package_name(self.apk_path)
            self.adb.del_iptables(package)

            try:
                self.adb.uninstall(package)
            except ADBDriverError as e:
                logger.warning('Uninstall FAILED')

            self.adb.delete_folder('/data/data/' + package)
            self.adb.delete_folder(CRYPTOHOOKER_FOLDER)

        self.proxy.stop()


    def check_run(self, output_files):
        status = True

        for f in output_files:
            if not os.path.isfile(f) or os.path.getsize(f) == 0:
                status = False

        # delete files if (part of) the analysis failed
        if not status:
            for f in output_files:
                if os.path.isfile(f):
                    os.remove(f)

        return status


    def set_sensitive_field(self, field):
        if field is None:
            data = deepcopy(data_default)
        elif field == 'all':
            data = deepcopy(data_special)
        else:
            data = deepcopy(data_default)
            data[field] = data_special[field]

        self.set_sensitive_data(data)


    def set_sensitive_data(self, data):
        if 'location' in data:
            lat, lon = data['location']
            self.adb.set_mock_location(lat, lon)

        if 'phone_number' in data:
            self.adb.set_phone_number(data['phone_number'])

        if 'mac_addr' in data:
            self.adb.set_mac_addr(data['mac_addr'])

        if 'sim_serial_num' in data:
            self.adb.set_sim_serial_num(data['sim_serial_num'])

        if 'subscriber_id' in data:
            self.adb.set_subscriber_id(data['subscriber_id'])

        if 'device_id' in data:
            self.adb.set_device_id(data['device_id'])

        if 'email' in data:
            self.adb.set_email(data['email'])

        if 'gender' in data:
            self.adb.set_gender(data['gender'])

        if 'contacts' in data:
            self.adb.set_contacts(data['contacts'])

        if 'android_id' in data:
            self.adb.set_android_id(data['android_id'])
