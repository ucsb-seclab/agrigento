import sys
import logging
import json

from os.path import isfile
from base64 import b64decode, b64encode
from binascii import hexlify

from config.general_config import LOGGING_LEVEL
from config.hooked_config import TAG


logging.basicConfig(level=LOGGING_LEVEL)
logger = logging.getLogger('hooked')

ENCRYPT_MODE = 1
DECRYPT_MODE = 2


class HookedData(object):
    """HookedData"""

    def __init__(self):
        self.ciphers = {}
        self.digests = {}
        self.macs = {}
        self.random_ids = []
        self.timestamps = set()

        self.encr_map = None


    def parse_log(self, file_path):
        if not isfile(file_path):
            logger.error('File {0} does not exitst'.format(file_path))
            return None

        logger.debug('Reading file')
        logfile = open(file_path)

        for line in logfile.readlines():
            if TAG not in line:
                continue

            line = line[len(TAG):]
            op = line[1: line.find(']')]
            try:
                data = json.loads(line[line.find(']') + 1:])
            except ValueError, e:
                logger.error('Error parsing JSON, {0}'.format(e))

            try:
                if op == 'CIPHER_INIT':
                    #logger.debug('CIPHER_INIT')

                    if data['Cipher'] not in self.ciphers:
                        self.ciphers[data['Cipher']] = []

                    x = {'opmode': data['opmode'], 'data': []}
                    self.ciphers[data['Cipher']].append(x)

                elif op == 'CIPHER_ENTRY':
                    #logger.debug('CIPHER_ENTRY')

                    c = self.ciphers[data['Cipher']][-1]['data']

                    # list is empty
                    if not c:
                        # add new entry
                        x = {'in': b64decode(data['in']),
                             'out': b64decode(data['out']),
                             'done': False}
                        c.append(x)
                    else:
                        if c[-1]['done']:
                            # add new entry
                            x = {'in': b64decode(data['in']),
                                 'out': b64decode(data['out']),
                                 'done': False}
                            c.append(x)
                        else:
                            # update entry
                            c[-1]['in'] += b64decode(data['in'])
                            c[-1]['out'] += b64decode(data['out'])

                elif op == 'CIPHER_FINAL':
                    #logger.debug('CIPHER_FINAL')

                    c = self.ciphers[data['Cipher']][-1]['data']

                    # list is empty
                    if not c:
                        # add new entry
                        x = {'in': b64decode(data['in']),
                             'out': b64decode(data['out']),
                             'done': True}
                        c.append(x)
                    else:
                        if c[-1]['done']:
                            # add new entry
                            x = {'in': b64decode(data['in']),
                                 'out': b64decode(data['out']),
                                 'done': True}
                            c.append(x)
                        else:
                            # update entry
                            c[-1]['in'] += b64decode(data['in'])
                            c[-1]['out'] += b64decode(data['out'])
                            c[-1]['done'] = True

                elif op == 'HASH_INIT':
                    #logger.debug('HASH_INIT')

                    if data['Digest'] not in self.digests:
                        self.digests[data['Digest']] = []

                    self.digests[data['Digest']].append([])

                elif op == 'HASH_ENTRY':
                    #logger.debug('HASH_ENTRY')

                    c = self.digests[data['Digest']][-1]

                    # list is empty
                    if not c:
                        # add new entry
                        x = {'in': b64decode(data['in']),
                             'out': b64decode(data['out']),
                             'done': False}
                        c.append(x)
                    else:
                        if c[-1]['done']:
                            # add new entry
                            x = {'in': b64decode(data['in']),
                                 'out': b64decode(data['out']),
                                 'done': False}
                            c.append(x)
                        else:
                            # update entry
                            c[-1]['in'] += b64decode(data['in'])
                            c[-1]['out'] += b64decode(data['out'])

                elif op == 'HASH_FINAL':
                    #logger.debug('HASH_FINAL')

                    c = self.digests[data['Digest']][-1]

                    # list is empty
                    if not c:
                        # add new entry
                        x = {'in': b64decode(data['in']),
                             'out': b64decode(data['out']),
                             'done': True}
                        c.append(x)
                    else:
                        if c[-1]['done']:
                            # add new entry
                            x = {'in': b64decode(data['in']),
                                 'out': b64decode(data['out']),
                                 'done': True}
                            c.append(x)
                        else:
                            # update entry
                            c[-1]['in'] += b64decode(data['in'])
                            c[-1]['out'] += b64decode(data['out'])
                            c[-1]['done'] = True

                elif op == 'HASH_RESET':
                    #logger.debug('HASH_RESET')

                    c = self.digests[data['Digest']][-1]

                    if c:
                        c[-1]['done'] = True

                elif op == 'HASH_CLONE':
                    #logger.debug('HASH_CLONE')

                    self.digests[data['Cloned']] = []
                    cloned = self.digests[data['Cloned']]
                    cloned.append([])

                    c = self.digests[data['Digest']][-1]
                    if not c[-1]['done']:
                        cloned[-1].append(c[-1])

                elif op == 'MAC_INIT':
                    #logger.debug('MAC_INIT')

                    if data['Mac'] not in self.macs:
                        self.macs[data['Mac']] = []

                    self.macs[data['Mac']].append([])

                elif op == 'MAC_ENTRY':
                    #logger.debug('MAC_ENTRY')

                    c = self.macs[data['Mac']][-1]

                    # list is empty
                    if not c:
                        # add new entry
                        x = {'in': b64decode(data['in']),
                             'out': b64decode(data['out']),
                             'done': False}
                        c.append(x)
                    else:
                        if c[-1]['done']:
                            # add new entry
                            x = {'in': b64decode(data['in']),
                                 'out': b64decode(data['out']),
                                 'done': False}
                            c.append(x)
                        else:
                            # update entry
                            c[-1]['in'] += b64decode(data['in'])
                            c[-1]['out'] += b64decode(data['out'])

                elif op == 'MAC_FINAL':
                    #logger.debug('MAC_FINAL')

                    c = self.macs[data['Mac']][-1]

                    # list is empty
                    if not c:
                        # add new entry
                        x = {'in': b64decode(data['in']),
                             'out': b64decode(data['out']),
                             'done': True}
                        c.append(x)
                    else:
                        if c[-1]['done']:
                            # add new entry
                            x = {'in': b64decode(data['in']),
                                 'out': b64decode(data['out']),
                                 'done': True}
                            c.append(x)
                        else:
                            # update entry
                            c[-1]['in'] += b64decode(data['in'])
                            c[-1]['out'] += b64decode(data['out'])
                            c[-1]['done'] = True

                elif op == 'MAC_RESET':
                    #logger.debug('MAC_RESET')

                    c = self.macs[data['Mac']][-1]

                    if c:
                        c[-1]['done'] = True

                elif op == 'MAC_CLONE':
                    #logger.debug('MAC_CLONE')

                    self.macs[data['Cloned']] = []
                    cloned = self.macs[data['Cloned']]
                    cloned.append([])

                    c = self.macs[data['Mac']][-1]
                    if not c[-1]['done']:
                        cloned[-1].append(c[-1])

                elif op == 'RANDOM_ID':
                    #logger.debug('RANDOM_ID')

                    self.random_ids.append(data['ID'])

                elif op == 'TIMESTAMP':
                    #logger.debug('TIMESTAMP')

                    if len(data['TS']) != 15 and data['TS'] != '-1' and len(data['TS']) > 4:
                        self.timestamps.add(data['TS'])

            except Exception, e:
                logger.error('Error: {0}'.format(e))

        logger.info('Log successfully parsed')


    def get_encryption_map(self):
        if self.encr_map:
            return self.encr_map

        self.encr_map = {}

        for cipher in self.ciphers:
            for encr_run in self.ciphers[cipher]:
                if encr_run['opmode'] == ENCRYPT_MODE:
                    merged_data_in = ''
                    merged_data_out = ''
                    for data in encr_run['data']:
                        self.encr_map[data['out']] = data['in']
                        self.encr_map[b64encode(data['out'])] = data['in']
                        aux = b64encode(data['out']).replace('-', '<TEMP2>').replace('/', '<TEMP>')
                        aux = aux.replace('+', '-').replace('<TEMP2>', '+')
                        aux = aux.replace('_', '/').replace('<TEMP>', '_')
                        self.encr_map[aux] = data['in']
                        # self.encr_map[b64encode(data['out']).replace('/','\/')] = data['in']
                        self.encr_map[hexlify(data['out']).lower()] = data['in']
                        self.encr_map[hexlify(data['out']).upper()] = data['in']
                        merged_data_in += data['in']
                        merged_data_out += data['out']
                    self.encr_map[merged_data_out] = merged_data_in
                    self.encr_map[b64encode(merged_data_out)] = merged_data_in
                    # self.encr_map[b64encode(merged_data_out).replace('/','\/')] = data['in']
                    self.encr_map[hexlify(merged_data_out).lower()] = merged_data_in
                    self.encr_map[hexlify(merged_data_out).upper()] = merged_data_in


        for digest in self.digests:
            for digest_run in self.digests[digest]:
                merged_data_in = ''
                merged_data_out = ''
                for data in digest_run:
                    self.encr_map[data['out']] = data['in']
                    self.encr_map[b64encode(data['out'])] = data['in']
                    aux = b64encode(data['out']).replace('-', '<TEMP2>').replace('/', '<TEMP>')
                    aux = aux.replace('+', '-').replace('<TEMP2>', '+')
                    aux = aux.replace('_', '/').replace('<TEMP>', '_')
                    self.encr_map[aux] = data['in']
                    # self.encr_map[b64encode(data['out']).replace('/','\/')] = data['in']
                    self.encr_map[hexlify(data['out']).lower()] = data['in']
                    self.encr_map[hexlify(data['out']).upper()] = data['in']
                    merged_data_in += data['in']
                    merged_data_out += data['out']
                self.encr_map[merged_data_out] = merged_data_in
                self.encr_map[b64encode(merged_data_out)] = merged_data_in
                # self.encr_map[b64encode(merged_data_out).replace('/','\/')] = data['in']
                self.encr_map[hexlify(merged_data_out).lower()] = merged_data_in
                self.encr_map[hexlify(merged_data_out).upper()] = merged_data_in


        for mac in self.macs:
            for mac_run in self.macs[mac]:
                merged_data_in = ''
                merged_data_out = ''
                for data in mac_run:
                    self.encr_map[data['out']] = data['in']
                    self.encr_map[b64encode(data['out'])] = data['in']
                    aux = b64encode(data['out']).replace('-', '<TEMP2>').replace('/', '<TEMP>')
                    aux = aux.replace('+', '-').replace('<TEMP2>', '+')
                    aux = aux.replace('_', '/').replace('<TEMP>', '_')
                    self.encr_map[aux] = data['in']
                    # self.encr_map[b64encode(data['out']).replace('/','\/')] = data['in']
                    self.encr_map[hexlify(data['out']).lower()] = data['in']
                    self.encr_map[hexlify(data['out']).upper()] = data['in']
                    merged_data_in += data['in']
                    merged_data_out += data['out']
                self.encr_map[merged_data_out] = merged_data_in
                self.encr_map[b64encode(merged_data_out)] = merged_data_in
                # self.encr_map[b64encode(merged_data_out).replace('/','\/')] = data['in']
                self.encr_map[hexlify(merged_data_out).lower()] = merged_data_in
                self.encr_map[hexlify(merged_data_out).upper()] = merged_data_in

        return self.encr_map


    def get_random_IDs(self):
        tmp = []

        for x in self.random_ids:
            tmp.append(x)
            tmp.append(x.replace('-', ''))

        return tmp


    def get_timestamps(self):
        tmp = set()

        for x in self.timestamps:
            tmp.add(x)
            tmp.add(str(int(x)))

        return tmp
