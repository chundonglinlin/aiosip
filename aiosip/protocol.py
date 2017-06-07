import asyncio

from . import message
from .log import protocol_logger


class UDP(asyncio.DatagramProtocol):
    def __init__(self, handler, loop):
        self._handler = handler
        self._loop = loop
        self.transport = None
        self.ready = asyncio.Future()

    def send_message(self, msg):
        msg.headers['Via'] %= {'protocol': UDP.__name__.upper()}
        protocol_logger.debug('Sent: "%s"', msg)
        self.transport.sendto(str(msg).encode())

    def connection_made(self, transport):
        protocol_logger.debug('Connection from {}'.format(
            transport.get_extra_info('peername')))
        self.transport = transport
        self.ready.set_result(self.transport)

    def datagram_received(self, data, addr):
        msg = data.decode()
        protocol_logger.debug('Received: "%s"', msg)
        msg_obj = message.Message.from_raw_message(msg)
        asyncio.ensure_future(self._handler(self, msg_obj, addr))

    # def error_received(self, exc):
    #     print('Error received:', exc)
    #
    # def connection_lost(self, exc):
    #     print("Socket closed, stop the event loop")


class TCP(asyncio.Protocol):
    def __init__(self, handler, loop):
        self._handler = handler
        self._loop = loop
        self.transport = None
        self.ready = asyncio.Future()

    def send_message(self, msg):
        msg.headers['Via'] %= {'protocol': TCP.__name__.upper()}
        protocol_logger.debug('Sent: "%s"', msg)
        self.transport.write(str(msg).encode())

    def connection_made(self, transport):
        protocol_logger.debug('Connection made to {}'.format(
            transport.get_extra_info('peername')))
        self.transport = transport
        self.ready.set_result(self.transport)

    def data_received(self, data):
        msg = data.decode()
        protocol_logger.debug('Received: "%s"', msg)
        msg_obj = message.Message.from_raw_message(msg)
        asyncio.ensure_future(self._handler(self, msg_obj))

    def connection_lost(self, error):
        protocol_logger.debug('Connection lost from {}'.format(
            self.transport.get_extra_info('peername')))
        super().connection_lost(error)
