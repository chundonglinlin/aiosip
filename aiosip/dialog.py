import asyncio
from collections import defaultdict

from multidict import CIMultiDict

from aiosip.auth import Auth
from .contact import Contact
from .exceptions import RegisterFailed, RegisterOngoing, InviteFailed, \
    InviteOngoing
from .log import dialog_logger
from .message import Request, Response
from .router import Router


class Dialog:
    def __init__(self,
                 app,
                 routes,
                 from_uri,
                 to_uri,
                 call_id,
                 protocol,
                 *,
                 contact_uri=None,
                 local_addr=None,
                 remote_addr=None,
                 password='',
                 logger=dialog_logger,
                 loop=None):
        if loop is None:
            loop = asyncio.get_event_loop()

        self.app = app
        self.router = Router(routes=routes)
        self.from_details = Contact.from_header(from_uri)
        self.to_details = Contact.from_header(to_uri)
        if contact_uri:
            self.contact_details = Contact.from_header(contact_uri)
        else:
            self.contact_details = self.from_details
        self.call_id = call_id
        self._protocol = protocol
        self.local_addr = local_addr
        self.remote_addr = remote_addr
        self.password = password
        self.logger = logger
        self.loop = loop
        self.cseqs = defaultdict(int)
        self._msgs = defaultdict(dict)
        self.invite_current_attempt = None
        self.register_current_attempt = None
        self.auth = None

    async def incoming_response(self, msg):
        if msg.cseq in self._msgs[msg.method]:
            if msg.status_code == 401:
                if msg.method.upper() == 'REGISTER':
                    self.register_current_attempt -= 1
                    if self.register_current_attempt < 1:
                        self._msgs[msg.method].pop(
                            msg.cseq).future.set_exception(
                            RegisterFailed('Too many unauthorized attempts !'))
                        return
                    username = self.to_details['uri']['user']
                elif msg.method.upper() == 'INVITE':
                    self.invite_current_attempt -= 1
                    if self.invite_current_attempt < 1:
                        self._msgs[msg.method].pop(
                            msg.cseq).future.set_exception(
                            InviteFailed('Too many unauthorized attempts !'))
                        return
                    username = msg.from_details['uri']['user']

                    hdrs = CIMultiDict()
                    hdrs['From'] = msg.headers['From']
                    hdrs['To'] = msg.headers['To']
                    hdrs['Call-ID'] = msg.headers['Call-ID']
                    hdrs['CSeq'] = msg.headers['CSeq'].replace('INVITE', 'ACK')
                    hdrs['Via'] = msg.headers['Via']
                    self.send_message(method='ACK', headers=hdrs)
                else:
                    username = self.to_details['uri']['user']

                original_msg = self._msgs[msg.method].pop(msg.cseq)

                del (original_msg.headers['CSeq'])

                auth = Auth.from_header(msg.headers['WWW-Authenticate'])
                original_msg.headers['Authorization'] = auth.do_auth(
                    uri=original_msg.to_details.from_repr(),
                    username=username,
                    password=self.password
                )

                await self.send_message(msg.method,
                                        to_details=original_msg.to_details,
                                        from_details=original_msg.from_details,
                                        headers=original_msg.headers,
                                        payload=original_msg.payload,
                                        future=original_msg.future)

            # for proxy authentication
            elif msg.status_code == 407:
                original_msg = self._msgs[msg.method].pop(msg.cseq)
                del (original_msg.headers['CSeq'])
                original_msg.headers['Proxy-Authorization'] = str(
                    Auth.from_authenticate_header(
                        authenticate=msg.headers['Proxy-Authenticate'],
                        method=msg.method,
                        uri=str(self.to_details),
                        username=self.to_details['uri']['user'],
                        password=self.password))
                await self.send_message(msg.method,
                                        headers=original_msg.headers,
                                        payload=original_msg.payload,
                                        future=original_msg.future)

            elif msg.status_code == 100:
                pass
            elif msg.status_code == 180:
                pass
            else:
                if msg.method.upper() == 'REGISTER':
                    self.register_current_attempt = None
                if msg.method.upper() == 'INVITE':
                    self.invite_current_attempt = None
                self._msgs[msg.method].pop(msg.cseq).future.set_result(
                    msg)  # Transaction end
        else:
            raise ValueError('SIP Response without a Request: "%s"' % msg)

    async def incoming_request(self, request):
        handler = self.router.routes.get(request.method.upper())
        if handler:
            for factory in reversed(self.app.middleware):
                handler = await factory(self, handler)
            try:
                await handler(request, self)
            except Exception as e:
                dialog_logger.exception(e)
                raise
        else:
            response = Response.from_request(request,
                                             status_code=404,
                                             status_message='NOT FOUND')
            self.send_response(response)

    async def send_message(self, method, to_uri=None, to_details=None,
                           from_details=None, contact_details=None,
                           headers=None, content_type=None, payload=None,
                           future=None):
        if not headers:
            headers = CIMultiDict()
        if type(headers) == dict:
            headers = CIMultiDict(**headers)

        if 'Call-ID' not in headers:
            headers['Call-ID'] = self.call_id

        if to_uri:
            to_details = Contact.from_header(to_uri)
        elif not to_details:
            to_details = self.to_details

        if from_details:
            from_details = Contact(from_details)
        else:
            from_details = self.from_details
        from_details.add_tag()

        self.cseqs[method] += 1
        request = Request(method=method,
                          from_details=from_details,
                          to_details=to_details,
                          contact_details=contact_details if contact_details else self.contact_details,
                          headers=headers,
                          content_type=content_type,
                          payload=payload)
        if future:
            request.future = future

        return await self._send_request(request)

    async def _send_request(self, request):
        self.cseqs[request.method] += 1
        request.cseq = self.cseqs[request.method]
        self._msgs[request.method][self.cseqs[request.method]] = request
        self._protocol.send_message(request)
        return await request.future

    def send_response(self, response):
        self._protocol.send_message(response)

    def close(self):
        self.app.stop_dialog(self)

    async def register(self, headers=None, attempts=3, expires=360):
        if self.register_current_attempt:
            raise RegisterOngoing(
                'Already a registration going on ! (attempt %s)' % self.register_current_attempt)

        self.register_current_attempt = attempts
        if not headers:
            headers = CIMultiDict()

        if 'Allow' not in headers:
            headers[
                'Allow'] = 'INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH'

        if 'Expires' not in headers:
            headers['Expires'] = int(expires)

        if 'Allow-Events' not in headers:
            headers['Allow-Events'] = 'talk,hold,conference,refer,check-sync'

        return await self.send_message(method='REGISTER',
                                       headers=headers,
                                       payload='')

    async def invite(self, headers=None, sdp=None, attempts=3):
        if self.invite_current_attempt:
            raise InviteOngoing(
                'Already a invite going on ! (attempt %s)' % self.invite_current_attempt)

        self.invite_current_attempt = attempts
        if not headers:
            headers = CIMultiDict()

        return await self.send_message(method='INVITE',
                                       headers=headers,
                                       payload=sdp)

    def ask_auth(self, request, nonce=None, realm='sip', algorithm='MD5',
                 method='Digest'):

        if algorithm != 'MD5':
            raise ValueError('Algorithm not supported')

        if not self.auth:
            self.auth = Auth()

        response = Response.from_request(request)
        response.status_code = 401
        response.status_message = 'Unauthorized'
        response.headers['WWW-Authenticate'] = self.auth.request_auth(nonce,
                                                                      realm,
                                                                      algorithm,
                                                                      method)
        self.send_response(response)

    def validate_auth(self, request_auth, username, password, uri):
        self.auth['username'] = username
        self.auth['password'] = password
        self.auth['uri'] = uri
        return self.auth == request_auth

    def ok(self, request):
        response = Response.from_request(request)
        self.send_response(response)
