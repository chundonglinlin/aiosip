import logging
import aiosip


sip_config = {  'srv_host' : 'XXXXXXX',
                 'srv_port'  : '5060',
                 'realm' : 'XXXXXX',
                 'user'  : 'YYYYYY',
                 'pwd'   : 'ZZZZZZ',
                 'local_ip' : '127.0.0.1',
                 'local_port': 6002
             }

async def register(request, dialog):

    response = aiosip.Response.from_request(request)
    dialog.send_response(response)


async def subscribe(request, dialog):

    response = aiosip.Response.from_request(request)
    dialog.send_response(response)


def start(app=None):
    if not app:
        app = aiosip.Application()
    handler = app.make_handler()
    server = app.loop.run_until_complete(app.loop.create_server(handler, sip_config['local_ip'], sip_config['local_port']))
    print('Serving on {}'.format(server.sockets[0].getsockname()))

    app.router.add_route('REGISTER', register)
    app.router.add_route('SUBSCRIBE', subscribe)

    try:
        app.loop.run_forever()
    except KeyboardInterrupt:
        pass

    print('Closing')
    server.close()
    app.loop.run_until_complete(server.wait_closed())
    app.loop.close()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    start()
