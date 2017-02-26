import json
import pprint

from config.core_config import LOCAL_SUBNET_DESC


class NetworkTrace(object):
    """
    NetworkTrace
    """

    def __init__(self, connections=[]):
        self.connections = connections


    def contains(self, value, ts):
        responses = [con.response for con in self.connections if con.response]

        for response in responses:
            # check only only preavious received responses
            if response.direction == 'in':
                if float(response.timestamp) <= float(ts):
                    # if 'text' in response.content_type:
                    try:
                        if value in response.payload.decode('utf-8'):
                            return True

                        # check the value also in the header
                        if value in response.headers.decode('utf-8'):
                            return True
                    except UnicodeDecodeError:
                        pass
        return False


class HTTPConnection(object):
    """
    HTTPConnection
    """

    def __init__(self, request=None, response=None):
        self.request = request
        self.response = response


class HTTP(object):
    """
    HTTPRequest
    """

    def __init__(self):
        # general
        self.timestamp = -1
        self.payload = ''

        # internet layer - ip
        self._local_subnet_desc = LOCAL_SUBNET_DESC
        self.ip_src = ''
        self.ip_dst = ''
        self.direction = ''  # in, out,self, err

        # transport layer - tcp
        self.port_src = ''
        self.port_dst = ''
        
        # application layer - http
        self.http_type = ''
        self.http_req_method = ''
        self.http_url = ''
        self.http_domain = ''
        self.http_path = ''
        self.http_query = {}
        self.content_type = ''
        self.headers = ''


    def set_direction(self):
        subnet_desc = self._local_subnet_desc
        
        if self.ip_src and self.ip_dst:
            if self.ip_src[0:len(subnet_desc)] == subnet_desc:
                if self.ip_dst[0:len(subnet_desc)] == subnet_desc:
                        self.direction = 'self'
                else:
                    self.direction = 'out'
            
            elif self.ip_dst[0:len(subnet_desc)] == subnet_desc:
                self.direction = 'in'
           

    # input/output
    def pretty_print(self):
        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(self.__dict__)


    def to_json(self):
        data = json.dumps(self.__dict__, sort_keys=True)
        return data


    def from_json(self, json_string):
        data = json.loads(json_string)

        self.timestamp = data['timestamp']
        self.payload = data['payload']

        self._local_subnet_desc = data['_local_subnet_desc']
        self.ip_src = data['ip_src']
        self.ip_dst = data['ip_dst']
        self.direction = data['direction']

        self.port_src = data['port_src']
        self.port_dst = data['port_dst']
        
        self.http_req_method = data['http_type']
        self.http_req_method = data['http_req_method']
        self.http_url = data['http_url']
        self.http_domain = data['http_domain']
        self.http_domain_2nd = data['http_domain_2nd']
        self.http_path = data['http_path']
        self.http_query = data['http_query']

        return self
