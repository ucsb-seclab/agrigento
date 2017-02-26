import sys
import logging
import json

from os.path import isfile
from urlparse import urlparse, parse_qs
from mitmproxy.flow import FlowReader

from core.classes import HTTP, HTTPConnection, NetworkTrace
from core.patterns import is_http_query, is_json
from core.utils import merge_queries, valid_string
from config.general_config import LOGGING_LEVEL

logging.basicConfig(level=LOGGING_LEVEL)
logger = logging.getLogger('flow-parser')


class FlowParser(object):
    '''Parse mitmproxy flows dump'''

    def __init__(self):
        pass


    def parse_trace(self, file_path):
        if not isfile(file_path):
            logger.error('File {0} does not exitst'.format(file_path))
            return None

        logger.debug('Reading file')
        flow_reader = FlowReader(open(file_path))

        connections = []

        for flow in flow_reader.stream():
            request = HTTP()
            response = HTTP()

            # request
            request.timestamp = flow.request.timestamp_start
            request.http_type = 'request'
            request.direction = 'out'

            request.http_req_method = flow.request.method

            # request.http_domain = flow.request.host
            request.http_domain = flow.request.pretty_host
            # request.http_url = flow.request.url
            request.http_url = flow.request.pretty_url
            http_full_path = flow.request.path
            request.http_path = http_full_path.split('?')[0]

            request.payload = flow.request.get_decoded_content()

            if len(http_full_path.split('?')) > 1:
                # get parameters
                try:
                    url_parsed = urlparse(request.http_url)
                    keep_blank_values = True
                    url_query = parse_qs(url_parsed.query,
                                         keep_blank_values)
                    http_query = url_query.copy()
                    request.http_query = http_query

                except Exception, e:
                    logger.error('HTTP Request, {0}'.format(e))

            headers = dict(flow.request.headers)
            for k in headers:
                headers[k] = [str(headers[k])]
            merge_queries(request.http_query, headers)


            if flow.request.method == 'POST':
                content_type = flow.request.headers.get('Content-Type','')
                if 'application/x-www-form-urlencoded' in content_type:
                    if is_http_query(request.payload) and valid_string(request.payload):
                        query = parse_qs(request.payload, True)
                        merge_queries(request.http_query, query)

                elif 'application/json' in content_type:
                    if is_json(request.payload) and valid_string(request.payload):
                        query = json.loads(request.payload)
                        # workaround
                        if type(query) is dict:
                            for k in query:
                                query[k] = [str(query[k])]
                            merge_queries(request.http_query, query)

                elif 'application/octet-stream' in content_type:
                    query = {'content': [request.payload]}
                    merge_queries(request.http_query, query)

                elif is_http_query(request.payload) and valid_string(request.payload):
                    query = parse_qs(request.payload, True)
                    merge_queries(request.http_query, query)

            # response
            if flow.response is None:
                response = None
            else:
                response.timestamp = flow.response.timestamp_end
                response.http_type = 'response'
                response.direction = 'in'
                response.content_type = flow.response.headers.get('Content-Type','')
                response.headers = str(flow.response.headers)
                response.payload = flow.response.get_decoded_content()

            # create connection
            http_connection = HTTPConnection(request, response)
            connections.append(http_connection)

        return NetworkTrace(connections)
