class Router(object):
    def __init__(self, routes=None):
        if not routes:
            routes = {}

        self.routes = routes

    def add_route(self, method, handler):
        self.routes[method] = handler
