import logging

from subprocess import Popen, PIPE
from multiprocessing import Process
from mitmproxy import proxy, flow, dump

from proxy.js_injector import inject_js
from config.general_config import LOGGING_LEVEL
from config.proxy_config import PROXY_PORT, PROXY_TRANSPARENT, IFACE, JSINJECTOR

logging.basicConfig(level=LOGGING_LEVEL)
logger = logging.getLogger('proxy')

'''
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A PREROUTING -i <iface> -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -i <iface> -p tcp --dport 443 -j REDIRECT --to-port 8080
'''

class ProxyMaster(dump.DumpMaster):

    def run(self):
        try:
            flow.FlowMaster.run(self)
        except KeyboardInterrupt:
            self.shutdown()


    def handle_request(self, r):
        f = flow.FlowMaster.handle_request(self, r)

        if f:
            r.reply()
        return f


    def handle_response(self, r):
        f = flow.FlowMaster.handle_response(self, r)

        if f:
            if JSINJECTOR:
                response = f.response
                content = response.get_decoded_content()
                if 'Math.random' in content or 'getRandomValues' in content:
                    inject_js(f)

            r.reply()

        return f


class Proxy(object):

    def __init__(self, port=PROXY_PORT, transparent=PROXY_TRANSPARENT):
        self.proxy_process = None
        self.port = port
        self.transparent = transparent

    def start_master(self, dump_file_path, op_mode):
        logger.info('Starting master')
        config = proxy.ProxyConfig(
            port = self.port,
            mode = op_mode
        )

        dump_options = dump.Options(
            verbosity = 3,
            eventlog = True,
            flow_detail = True,
            showhost = True,
            outfile = (dump_file_path, 'wb')
        )

        server = proxy.ProxyServer(config)
        proxy_master = ProxyMaster(server, dump_options)
        proxy_master.run()


    def start(self, dump_file_path):
        logger.info('Starting proxy')
        if self.transparent:
            self.proxy_process = Process(target=self.start_master,
                                         args=(dump_file_path, 'transparent'))
        else:
            self.proxy_process = Process(target=self.start_master,
                                         args=(dump_file_path, 'regular'))
        self.proxy_process.start()


    def stop(self):
        logger.info('Stopping proxy')
        self.proxy_process.terminate()


def set_iptables(ipaddress, port):
    curr_iptables = Popen('iptables-save', stdout=PIPE,
                           shell=True).communicate()[0]

    cmd = 'iptables -t nat -A PREROUTING -i {0} -p tcp '.format(IFACE) + \
          '--dport 80 -s {0} -j REDIRECT --to-port {1}'.format(ipaddress, port)

    if cmd[16:] not in curr_iptables:
        logger.debug('Executing, ' + cmd)
        p = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True)
        out, err = p.communicate()
        logger.debug('stdout:{0}, stderr:{1}'.format(out, err))

    cmd = 'iptables -t nat -A PREROUTING -i {0} -p tcp '.format(IFACE) + \
          '--dport 443 -s {0} -j REDIRECT --to-port {1}'.format(ipaddress, port)

    if cmd[16:] not in curr_iptables:
        logger.debug('Executing, ' + cmd)
        p = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True)
        out, err = p.communicate()
        logger.debug('stdout:{0}, stderr:{1}'.format(out, err))


def delete_iptables(ipaddress, port):
    cmd = 'iptables -t nat -D PREROUTING -i {0} -p tcp '.format(IFACE) + \
          '--dport 80 -s {0} -j REDIRECT --to-port {1}'.format(ipaddress, port)
    logger.debug('Executing, ' + cmd)
    p = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True)
    out, err = p.communicate()
    logger.debug('stdout:{0}, stderr:{1}'.format(out, err))

    cmd = 'iptables -t nat -D PREROUTING -i {0} -p tcp '.format(IFACE) + \
          '--dport 443 -s {0} -j REDIRECT --to-port {1}'.format(ipaddress, port)
    logger.debug('Executing, ' + cmd)
    p = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True)
    out, err = p.communicate()
    logger.debug('stdout:{0}, stderr:{1}'.format(out, err))
