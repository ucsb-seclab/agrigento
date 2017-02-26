"""Proxy config"""

USE_PROXY = True
PROXY_PORT = 8080
PROXY_IP = '192.168.1.1'
# use: http://ip:port
PROXY_ADDR = 'http://{0}:{1}'.format(PROXY_IP, PROXY_PORT)
PROXY_TRANSPARENT = True
JSINJECTOR = True

IFACE = 'eth0'

CERT_PATH = '~/.mitmproxy/mitmproxy-ca-cert.cer'
OUTPUT_CERT_FOLDER = 'data/cert/'
