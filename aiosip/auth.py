import secrets

from hashlib import md5

from .log import application_logger

def md5digest(*args):
    return md5(':'.join(args).encode()).hexdigest()


class Auth(dict):
    def __init__(self):
        super().__init__()

    def __str__(self):
        if self['method'] == 'Digest':
            r = 'Digest '
            l = []
            # import ipdb; ipdb.set_trace()
            for k, v in self.items():
                if k == 'algorithm':
                    l.append('%s=%s' % (k, v))
                elif k in ('method', 'password'):
                    continue
                else:
                    l.append('%s="%s"' % (k, v))
            r += ','.join(l)
        else:
            raise ValueError('Authentication method not supported')
        return r

    def request_auth(self, nonce=None, realm='sip', algorithm='MD5',
                     method='Digest'):

        if algorithm != 'MD5':
            raise ValueError('Algorithm not supported')

        if not nonce:
            nonce = str(secrets.randbits(128))

        self['method'] = method
        self['nonce'] = nonce
        self['realm'] = realm
        self['algorithm'] = algorithm
        return str(self)

    def do_auth(self, uri, username, password):

        if self['algorithm'] == 'MD5':
            self['username'] = username
            self['uri'] = uri
            self['password'] = password
            self._calculate_response()
            return str(self)
        else:
            raise ValueError('Algorithm not supported')

    def _calculate_response(self):
        ha1 = md5digest(self['username'], self['realm'], self['password'])
        ha2 = md5digest(self['method'], self['uri'])
        self['response'] = md5digest(ha1, self['nonce'], ha2)

    @classmethod
    def from_header(cls, header):
        auth = cls()

        if header.startswith('Digest'):
            auth['method'] = 'Digest'
            params = header[7:].split(',')
            for param in params:
                k, v = param.split('=')
                k = k.strip()
                v = v.strip().strip('"')
                auth[k] = v

        return auth

    def __eq__(self, other):

        self._calculate_response()

        # application_logger.warning(self['response'])
        # application_logger.warning(other['response'])
        #
        # application_logger.warning(self['uri'])
        # application_logger.warning(other['uri'])
        #
        # application_logger.warning(self['username'])
        # application_logger.warning(other['username'])
        #
        # application_logger.warning(self['nonce'])
        # application_logger.warning(other['nonce'])
        #
        # application_logger.warning(self['realm'])
        # application_logger.warning(other['realm'])

        return all((self['response'] == other.get('response'),
                    self['uri'] == other.get('uri'),
                    self['username'] == other.get('username'),
                    self['nonce'] == other.get('nonce'),
                    self['realm'] == other.get('realm')))
