import subprocess
import os

from config.emulator_config import AAPT_PATH
from config.proxy_config import OUTPUT_CERT_FOLDER


def get_APK_package_name(apk_path):
    cmd = AAPT_PATH + ' dump badging {0}'.format(apk_path)
    cmd += '|awk -F\" \" \'/package/ {print $2}\''
    cmd += '|awk -F\"\'\" \'/name=/ {print $2}\''
    cmd += '|head -1'

    p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,
                              shell=True)

    out, err = p.communicate()
    
    return out.strip()


def get_APK_main_activity(apk_path):
    cmd = AAPT_PATH + ' dump badging {0}'.format(apk_path)
    cmd += '|awk -F\" \" \'/launchable-activity/ {print $2}\''
    cmd += '|awk -F\"\'\" \'/name=/ {print $2}\''

    p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,
                              shell=True)

    out, err = p.communicate()
    
    return out.strip()


def convert_cert(cert_path):
    # convert cert to Android format
    cmd = 'openssl x509 -inform PEM '
    cmd += '-subject_hash_old -in ' + cert_path
    cmd += '| head -1'
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,
                              shell=True)
    out, err = p.communicate()
    cert_name = out.strip() + '.0'
    output_cert = os.path.join(OUTPUT_CERT_FOLDER, cert_name)

    try:
        os.stat(OUTPUT_CERT_FOLDER)
    except:
        os.mkdir(OUTPUT_CERT_FOLDER)

    cmd = 'cat {0} > {1}'.format(cert_path, output_cert)
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,
                              shell=True)
    p.communicate()

    cmd = 'openssl x509 -inform PEM -text -in ' + cert_path
    cmd += ' -out /dev/null >> ' + output_cert
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,
                              shell=True)
    p.communicate()

    return output_cert
