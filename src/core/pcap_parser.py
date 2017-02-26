import sys
import logging
import scapy_http.http

from scapy.all import *
from scapy_http.http import HTTPRequest, HTTPResponse
from os.path import isfile
from urlparse import urlparse, parse_qs

from core.classes import HTTP, HTTPConnection, NetworkTrace
from config.general_config import LOGGING_LEVEL
from core.utils import decompress_gzip

logging.basicConfig(level=LOGGING_LEVEL)
logger = logging.getLogger('pcap-parser')

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


class PCAPParser(object):

    def __init__(self):
        pass


    def is_http_request(self, payload):
        _methods = {b'GET', b'POST', b'PUT', b'DELETE', b'HEAD', b'TRACE',
                    b'OPTIONS', b'PATCH'}
        return payload[0: payload.find(b' ')] in _methods


    def is_http_response(self, payload):
        p = payload.replace('\r\n\r\n', '').replace(' ', '')
        return p.startswith(b'HTTP')


    def merge_http_entries(self, http_entries):
        connections = []

        for conn_index in http_entries:
            for i in range(len(http_entries[conn_index])):
                if http_entries[conn_index][i].http_type == 'request':
                    request = http_entries[conn_index][i]

                    # get response by inverting conn_index tuple
                    # (src_ip:port, dst_ip:port)
                    try:
                        response = http_entries[(conn_index[1],
                                                 conn_index[0])][i]
                    except KeyError:
                        # no response found
                        response = None
                    except IndexError:
                        # no response found
                        response = None

                    http_connection = HTTPConnection(request, response)
                    connections.append(http_connection)

        return connections


    def decode_response(self, http_response):
        payload = str(http_response.payload)
        fields = http_response.fields


        if 'text' in fields.get('Content-Type', ''):
            if 'gzip' in fields.get('Content-Encoding', ''):
                if 'chunked' in fields.get('Transfer-Encoding', ''):
                    new_payload = ''

                    while (payload != ''):
                        off = int(payload[:payload.index('\r\n')],16)
                        if off == 0:
                            break
                        payload = payload[payload.index('\r\n') + 2:]
                        new_payload = new_payload + payload[:off]
                        payload = payload[off+2:]

                    payload = new_payload

                try:
                    payload = decompress_gzip(payload)
                except Exception, e:
                    logger.error('Error decompressing data')
                    logger.debug('Error: {0}'.format(e))

        return payload


    def parse_trace(self, file_path):
        if not isfile(file_path):
            logger.error('File {0} does not exitst'.format(file_path))
            return None

        logger.debug('Reading file')
        pcap_reader = PcapReader(file_path)

        http_entries = self.preprocess_pcap(pcap_reader)

        for conn_index in http_entries:
            for i in range(len(http_entries[conn_index])):
                http_entry = http_entries[conn_index][i]
                http_payload = http_entry.payload

                if self.is_http_request(http_payload):
                    http_request = HTTPRequest(http_payload)

                    try:
                        http_entry.http_req_method = str(http_request.Method)
                    except AttributeError:
                        logger.error('Malformed HTTP request packet')
                        logger.debug('Payload: ' + http_payload)
                        continue

                    http_domain = http_request.Host
                    http_entry.http_domain = http_domain
                    
                    http_full_path = http_request.Path
                    http_path = http_full_path.split('?')[0]
                    http_entry.http_path = http_path

                    http_url = http_domain + http_full_path
                    http_entry.http_url = http_url

                    # get parameters
                    if len(http_full_path.split('?')) > 1:
                        try:
                            url_parsed = urlparse(http_url)
                            keep_blank_values = True
                            url_query = parse_qs(url_parsed.query,
                                                 keep_blank_values)
                            http_query = url_query.copy()
                            http_entry.http_query = http_query

                        except Exception, e:
                            logger.error('HTTP Request, {0}'.format(e))

                elif self.is_http_response(http_payload):                
                    http_response = HTTPResponse(http_payload)
                    http_entry.content_type = http_response.fields.get(
                                                            'Content-Type', '')
                    http_entry.headers = str(http_response.Headers)
                    http_entry.payload = self.decode_response(http_response)

                else:
                    logger.warning('Unexpected HTTP entry.')

        connections = self.merge_http_entries(http_entries)

        return NetworkTrace(connections)


    def preprocess_pcap(self, pcap_reader):
        """
        Reconstruct HTTP flows parsing and merging packets
        """
        packets_cnt = 0
        http_packets_count = 0

        http_entries = {}

        for packet in pcap_reader:
            packets_cnt += 1

            http_entry = HTTP()
            http_entry.timestamp = packet.time

            # internet layer
            if packet.haslayer('IP'):
                http_entry.ip_src = packet['IP'].src
                http_entry.ip_dst = packet['IP'].dst
                http_entry.set_direction()

            # transport layer
            if packet.haslayer('TCP'):
                http_entry.port_src = packet.sport
                http_entry.port_dst = packet.dport

            else:
                # Unsupported protocol
                pass

            conn_index = ((http_entry.ip_src, http_entry.port_src),
                          (http_entry.ip_dst, http_entry.port_dst))

            # application layer
            # http
            if packet.haslayer('HTTP'):
                http_packets_count += 1

                http_payload = str(packet['HTTP'].payload)
                http_entry.payload = http_payload

                # handle new HTTP request
                if self.is_http_request(http_payload):
                    http_entry.http_type = 'request'

                    # Keep-alive connection re-use the sampe TCP connection
                    # for new HTTP request. To handle them, use a stack of 
                    # traces for each connection 
                    if conn_index not in http_entries:
                        http_entries[conn_index] = []

                    http_entries[conn_index].append(http_entry)

                # handle new HTTP response
                elif self.is_http_response(http_payload):
                    http_entry.http_type = 'response'

                    # Keep-alive connection re-use the sampe TCP connection
                    # for new HTTP request. To handle them, use a stack of 
                    # traces for each connection 
                    if conn_index not in http_entries:
                        http_entries[conn_index] = []

                    http_entries[conn_index].append(http_entry)

                # handle new packet for existing HTTP connections 
                else:
                    try:
                        # Append payload in the most recent trace (the last one)
                        old_payload = http_entries[conn_index][-1].payload
                        new_payload = old_payload + http_payload
                        http_entries[conn_index][-1].payload = new_payload
                    except:
                        logger.warning("Can't find existing HTTP connection")

            else:
                # Unsupported protocol
                pass

        logger.info('Successfully parsed {0} packets'.format(packets_cnt))
        logger.info('{0} HTTP packets'.format(http_packets_count))
        logger.info('{0} HTTP flows'.format(sum([len(x)
                                              for x in http_entries.values()])))

        return http_entries
