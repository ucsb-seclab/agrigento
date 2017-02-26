import subprocess
import os
import time
import logging
import re
import tempfile
import shutil
import signal

from config.emulator_config import *
from config.proxy_config import *
from config.general_config import LOGGING_LEVEL
from config.hooked_config import *

from emulator.utils import convert_cert


logging.basicConfig(level=LOGGING_LEVEL,
                    format='[%(asctime)s] %(levelname)s:%(name)s:%(message)s',
                    datefmt='%d-%m-%Y %H:%M:%S')
logger = logging.getLogger('adb-driver')


class ADBDriverError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg


class ADBDriver:

    def __init__(self, device_name, emulator=False, avd_name=AVD_NAME, avd_folder=AVD_FOLDER):
        self.emulator = emulator
        self.device_name = device_name

        self.avd_name = avd_name
        self.avd_folder = avd_folder
        self.avd_tmp_ini = None
        self.avd_tmp_home = None

        self.nowindow = NO_WINDOW
        self.scale = SCALE
        self.use_proxy = USE_PROXY
        self.proxy_addr = PROXY_ADDR

        self.emulator = EMULATOR_PATH
        self.adb_path = ADB_PATH

        self.running = False
        self.emu_process = None
        self.copied = False

        if emulator:
            self.fresh_copy()

    @staticmethod
    def get_device_names():
        cmd = [ADB_PATH, 'devices']
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)

        out, err = p.communicate()

        lines = out.splitlines()
        names = []
        if len(lines) > 1:
            index = 1
            if 'daemon not running' in lines[1]:
                index = 3

            names = [line.split('\t')[0] for line in lines[index:] if line]

        return names


    @staticmethod
    def get_device_ipaddress(device_name):
        cmd = [ADB_PATH, '-s', device_name, 'shell', 'ifconfig', 'wlan0']
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)

        out, err = p.communicate()
        ipaddress = out.split(' ')[2]
        return ipaddress


    def adb_cmd(self, args, cmd_wait_time=CMD_WAIT_TIME):
        cmd = [self.adb_path, '-s', self.device_name]
        cmd.extend(args)
        logger.debug('Executing ' + ' '.join(cmd))
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)

        signalset = False
        # Install an alarm if there was no one installed yet.
        if signal.getsignal(signal.SIGALRM) == signal.SIG_DFL:
            signal.signal(signal.SIGALRM, self.adb_sighandler)
            signal.alarm(cmd_wait_time)
            signalset = True

        try:
            out, err = p.communicate()
            # Reset the alarm.
            if signalset:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, signal.SIG_DFL)

        except ADBDriverError:
            p.terminate()
            raise ADBDriverError('Timeout executing adb command: ' + str(cmd))

        return out, err


    def adb_su_cmd(self, args, cmd_wait_time=CMD_WAIT_TIME):
        cmd = self.adb_path + ' -s ' + self.device_name
        cmd = cmd + ' shell su -c \'{0}\''.format(args)
        logger.debug('Executing ' + cmd)
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE,
                                  shell=True)

        signalset = False
        # Install an alarm if there was no one installed yet.
        if signal.getsignal(signal.SIGALRM) == signal.SIG_DFL:
            signal.signal(signal.SIGALRM, self.adb_sighandler)
            signal.alarm(cmd_wait_time)
            signalset = True

        try:
            out, err = p.communicate()
            # Reset the alarm.
            if signalset:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, signal.SIG_DFL)

        except ADBDriverError:
            p.terminate()
            raise ADBDriverError('Timeout executing adb command: ' + str(cmd))

        return out, err


    def adb_sighandler(self, signum, frame):
        # Restore to default signal handler
        signal.signal(signal.SIGALRM, signal.SIG_DFL)
        raise ADBDriverError('Could not execute adb command: timeout')


    def waitfor(self, cmd, result):
        while True:
            out, err = self.adb_cmd(cmd)
            if re.search(result, out):
                break
            time.sleep(3)

            # Check if emulator process has terminated. This should not happen.
            self.emu_process.poll()
            if self.emu_process.returncode != None:
                out, err = self.emu_process.communicate()
                raise ADBDriverError('emulator process terminated\n' +
                                     'out: ' + out + '\nerr: ' + err)


    def completeboot(self):
        # wait until the emulator is booted
        self.waitfor(['shell', 'getprop', 'dev.bootcomplete'], '1')
        self.waitfor(['shell', 'getprop', 'sys.boot_completed'], '1')
        self.waitfor(['shell', 'getprop', 'init.svc.bootanim'], 'stopped')
        self.waitfor(['shell', 'pm', 'path', 'android'], 'package')


    def install_cert(self, cert_path=CERT_PATH):
        cert_path = convert_cert(cert_path)
        cert_name = os.path.basename(cert_path)

        self.adb_cmd(['push', cert_path, '/sdcard/' + cert_name])
        self.adb_su_cmd('mount -o remount,rw /system')
        self.adb_su_cmd('cp /sdcard/' + cert_name + \
                        ' /system/etc/security/cacerts/')
        self.adb_su_cmd('cp /storage/emulated/0/' + cert_name + \
                        ' /system/etc/security/cacerts/')
        self.adb_su_cmd('chmod 644 /system/etc/security/cacerts/' + cert_name)
        self.adb_su_cmd('touch -t /system/etc/security/cacerts/' + cert_name)


    def get_UID(self, package):
        cmd = ['shell', 'dumpsys', 'package', package, '|', 'grep', 'userId=']
        out, err = self.adb_cmd(cmd)
        out = out[out.find('=') + 1:]
        out = out[:out.find(' ')]

        return out


    def get_ipaddress(self):
        cmd = ['shell', 'ifconfig', 'wlan0']
        out, err = self.adb_cmd(cmd)
        ipaddress = out.split(' ')[2]
        return ipaddress


    def set_iptables(self, package, proxy_ip=PROXY_IP):
        uid = self.get_UID(package)
        self.adb_su_cmd('iptables -t mangle -A OUTPUT -p TCP -m owner ' + \
                        '--uid-owner {0} -j MARK --set-mark 0x15'.format(uid))
        self.adb_su_cmd('ip rule add fwmark 0x15 table 0x15')
        self.adb_su_cmd('ip route add default via {0} table 0x15'.format(
                                                                    proxy_ip))


    def del_iptables(self, package):
        uid = self.get_UID(package)
        self.adb_su_cmd('iptables -t mangle -D OUTPUT -p TCP -m owner ' + \
                        '--uid-owner {0} -j MARK --set-mark 0x15'.format(uid))


    def turn_on_screen(self):
        logger.debug('Turning on screen')
        out, err = self.adb_cmd(['shell', 'dumpsys', 'power', '|', 'grep',
                                 'mScreenOn'])
        if 'false' in out:
            self.adb_cmd(['shell', 'input', 'keyevent', '26'])


    def turn_off_screen(self):
        logger.debug('Turning off screen')
        out, err = self.adb_cmd(['shell', 'dumpsys', 'power', '|', 'grep',
                                 'mScreenOn'])
        if 'true' in out:
            self.adb_cmd(['shell', 'input', 'keyevent', '26'])


    def unlock(self, pin=None):
        logger.debug('Unlocking device')
        self.adb_cmd(['shell', 'input', 'keyevent', '82'])

        if pin:
            time.sleep(2)
            self.adb_cmd(['shell', 'input', 'text', pin])
            time.sleep(2)
            self.adb_cmd(['shell', 'input', 'keyevent', '66'])


    def set_record_ts(self, record):
        aux = ['elapsedRealtime',
               'elapsedRealtimeNanos',
               'currentThreadTimeMillis',
               'uptimeMillis',
               'currentTimeMillis',
               'nanoTime']


        if record:
            self.delete_folder(CRYPTOHOOKER_TS_FOLDER)
            self.create_writeble_folder(CRYPTOHOOKER_TS_FOLDER)
            self.write_file(RECORD_TS_FILE, 'record')
            self.adb_su_cmd('chmod 777 ' + RECORD_TS_FILE)

        else:
            for i in aux:
                self.write_file(INDEX_FILE_BASE + i, '0')
                self.adb_su_cmd('chmod 777 ' + INDEX_FILE_BASE + i)

            self.adb_su_cmd('rm ' + RECORD_TS_FILE)
            self.adb_su_cmd('chmod 777 ' + TS_FILES_BASE + '*')


    def start_activity(self, package, activity):
        logger.debug('Starting activity ' + activity)
        self.adb_cmd(['shell', 'am', 'start', '-n', package + '/' + activity])


    def start_capturing(self, filename):
        logger.debug('Waiting for device')
        self.adb_cmd(['emu', 'network', 'capture', 'start', filename])
        logger.debug('Stared capturing')


    def stop_capturing(self):
        logger.debug('Stopping capturing')
        self.adb_cmd(['emu', 'network', 'capture', 'stop'])


    def start_monkey(self, package=None, seed=None):
        logger.debug('Starting monkey')
        self.turn_on_screen()

        cmd = ['shell', 'monkey',
                        '--throttle', THROTTLE,
                        '--pct-syskeys', PCT_SYSKEYS,
                        '--pct-anyevent', PCT_ANYEVENT
              ]

        if IGNORE_CRASHES:
            cmd.append('--ignore-crashes')

        if IGNORE_TIMEOUTS:
            cmd.append('--ignore-timeouts')

        if IGNORE_SECURITY_EXCEPTIONS:
            cmd.append('--ignore-security-exceptions')

        if seed:
            cmd.extend(['-s', seed])

        if package:
            cmd.extend(['-p', package])  # only target app

        cmd.append(NUM_EVENTS)

        return self.adb_cmd(cmd, cmd_wait_time=MONKEY_TIMEOUT)


    def kill_monkey(self):
        pid = self.adb_su_cmd('ps | grep com.android.commands.monkey ' +\
                              '|awk \'{print $2}\'')[0]
        self.adb_su_cmd('kill ' + pid.strip())


    def install(self, filename):
        for i in range(1, MAX_INSTALLATION_TRIALS):
            try:
                logger.debug('Trying to install APK ' + filename)
                out, err = self.adb_cmd(['install', '-rgd', filename])

                if 'Success' in out:
                    logger.debug('APK successfully installed')
                    return

                else:
                    logger.warning('Error installing APK {0}. Stdout: {1}. '
                                   'Stderr: {2}.'.format(filename, out, err))

            except ADBDriverError as e:
                logger.warning('Could not install APK:' + str(e))

        raise ADBDriverError('Error installing APK {0}. Reached max tries')


    def uninstall(self, package):
        logger.debug('Uninstalling package ' + package)
        self.adb_cmd(['shell', 'pm', 'clear', package])
        # clear play store data?
        # self.adb_cmd(['shell', 'pm', 'clear', 'com.android.vending'])
        out, err = self.adb_cmd(['uninstall', package])


    def get_file(self, src_path, dst_path):
        logger.debug('Getting file {0}'.format(src_path))
        return self.adb_cmd(['pull', src_path, dst_path])


    def write_file(self, file_path, content):
        logger.debug('Writing file {0}'.format(file_path))
        self.adb_su_cmd('rm ' + file_path)
        self.adb_su_cmd('echo ' + content + ' > ' + file_path)


    def set_logfile(self, file_path):
        logger.debug('Setting logfile {0}'.format(file_path))
        self.adb_su_cmd('rm ' + file_path)
        self.adb_su_cmd('touch ' + file_path)
        self.adb_su_cmd('chmod 777 ' + file_path)


    def create_writeble_folder(self, folder_path):
        logger.debug('Creating folder {0}'.format(folder_path))
        self.adb_su_cmd('mkdir ' + folder_path)
        self.adb_su_cmd('chmod -R 777 ' + folder_path)


    def delete_folder(self, folder_path):
        logger.debug('Deleting folder {0}'.format(folder_path))
        self.adb_su_cmd('rm -r ' + folder_path)


    def create_writeble_ram_folder(self, folder_path):
        logger.debug('Creating RAM folder {0}'.format(folder_path))
        self.adb_su_cmd('mkdir ' + folder_path)
        self.adb_su_cmd('chmod 777 ' + folder_path)
        self.adb_su_cmd('mount -o size=256M -t tmpfs tmpfs ' + folder_path)


    def delete_ram_folder(self, folder_path):
        logger.debug('Deleting RAM folder {0}'.format(folder_path))
        out, err = self.adb_su_cmd('umount ' + folder_path)
        logger.debug('umount out:{0}, err:{1}'.format(out, err))
        self.adb_su_cmd('rm -r ' + folder_path + '/*')
        self.adb_su_cmd('rm -r ' + folder_path)


    def flush_logcat(self):
        logger.debug('Flushing logcat')
        return self.adb_cmd(['logcat', '-c'])


    def dump_logcat(self, file_path, tag):
        logger.debug('Flushing logcat')
        return self.adb_cmd(['logcat', '-f', file_path, '-d', '-s', tag])


    def start(self):
        if self.running:
            logger.error('Emulator is already running')
            return

        cmd = [self.emulator, '-avd', self.avd_name,
                              '-no-audio']

        if self.nowindow:
            cmd.extend(['-no-window'])

        if self.scale:
            cmd.extend(['-scale', '0.5'])

        if self.use_proxy:
            cmd.extend(['-http-proxy', self.proxy_addr])

        logger.debug('Starting the emulator with arguments: ' + str(cmd))
        try:
            self.emu_process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                                     stderr=subprocess.PIPE)
        except OSError as exception:
            raise ADBDriverError('Could not start emulator: ' + str(exception))

        # should be up and running now.
        self.running = True


    def stop(self):
        logger.debug('Terminanting emulator')
        # terminate process, if any.
        if self.emu_process:
            try:
                self.emu_process.terminate()
                self.emu_process.wait()
            except OSError as exception:
                # Do not raise an exception if there's no such process to kill.
                if exception.errno != 3:
                   raise ADBDriverError('Could not stop emulator: ' +
                                        str(exception))

            self.emu_process = None

        # no longer running.
        self.running = False


    def fresh_copy(self):
        logger.debug('Generating a fresh copy...')

        # create a temporary directory to store a working copy of the AVD.
        tmp_home = tempfile.mkdtemp()
        tmp_folder = os.path.join(tmp_home, self.avd_name + '.avd')

        # copy the original AVD to this temporary directory.
        shutil.copytree(self.avd_folder, tmp_folder)

        # create a temporary .ini file for this AVD.
        handle, tmp_ini_path = tempfile.mkstemp(prefix=self.avd_name + '.',
                                                suffix='.ini',
                                                dir=AVD_HOME)
        tmp_ini = os.fdopen(handle, 'w')
        tmp_name = os.path.splitext(os.path.basename(tmp_ini_path))[0]

        avd_ini = os.path.join(AVD_HOME, self.avd_name + '.ini')
        org_ini = open(avd_ini)

        # copy its contents to the temporary .ini
        for line in org_ini:
            # update path=* line so that it points to the temporary location
            tmp_ini.write(re.sub('path=.*', 'path=' + tmp_folder, line))

        tmp_ini.close()
        org_ini.close()

        self.avd_name = tmp_name
        self.avd_tmp_ini = tmp_ini_path
        self.avd_tmp_home = tmp_home


    def destroy(self):
        logger.debug('Destroying copy')

        if self.running or self.emu_process:
            raise ADBDriverError('Emulator is still running')

        # remove the temporary directory (if any).
        shutil.rmtree(self.avd_tmp_home, ignore_errors=True)

        # remove the temporary .ini (if any).
        try:
            os.remove(self.avd_tmp_ini)
        except OSError as exception:
            # do not raise an exception if the file does not exist.
            if exception.errno != 2:
                raise exception

    # Set sensitive information values

    def set_mock_location(self, lat, lon):
        '''
        https://github.com/amotzte/android-mock-location-for-development
        required to be installed
        '''
        logger.debug('Setting mock location')

        cmd = ['shell', 'am', 'broadcast', '-a',
               'com.example.amotz.mockLocationForDeveloper.updateLocation',
               '-e', 'lat', str(lat), '-e', 'lon', str(lon)]

        return self.adb_cmd(cmd)


    def set_phone_number(self, phone_number):
        logger.debug('Setting phone number')
        self.write_file(PHONE_NUMBER_FILE, phone_number)


    def set_mac_addr(self, mac_addr):
        logger.debug('Setting mac address')
        self.write_file(MAC_ADDR_FILE, mac_addr)


    def set_sim_serial_num(self, sim_serial_num):
        logger.debug('Setting sim serial num')
        self.write_file(SIM_SERIAL_NUM_FILE, sim_serial_num)


    def set_subscriber_id(self, subscriber_id):
        logger.debug('Setting subscriber id')
        self.write_file(SUBSCRIBER_ID_FILE, subscriber_id)


    def set_device_id(self, device_id):
        logger.debug('Setting device id')
        self.write_file(DEVICE_ID_FILE, device_id)


    def set_email(self, email):
        logger.debug('Setting email')
        self.write_file(EMAIL_FILE, email)


    def set_gender(self, gender):
        logger.debug('Setting gender')
        self.write_file(GENDER_FILE, gender)


    def set_contacts(self, contacts):
        logger.debug('Setting contacts')
        # clear contact list
        self.adb_cmd(['shell', 'pm', 'clear', 'com.android.providers.contacts'])

        self.turn_on_screen()
        self.unlock()
        # add contacts
        for name, phone_num in contacts:
            self.adb_cmd(['shell', 'am', 'start', '-a',
                          'android.intent.action.INSERT', '-t',
                          'vnd.android.cursor.dir/contact', '-e',
                          'name', name, '-e', 'phone', phone_num])
            time.sleep(1)
            self.adb_cmd(['shell', 'input', 'keyevent', '4'])
            self.adb_cmd(['shell', 'input', 'keyevent', '4'])
            self.adb_cmd(['shell', 'input', 'keyevent', '4'])
            time.sleep(1)


    def set_android_id(self, android_id):
        logger.debug('Setting android id')
        self.adb_cmd(['shell', 'content', 'update', '--uri',
                      'content://settings/secure', '--bind',
                      'value:s:' + android_id, '--where',
                      '"name=\'android_id\'"'])
