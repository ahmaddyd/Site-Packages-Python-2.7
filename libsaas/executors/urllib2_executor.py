import logging

from libsaas import http, port

from . import base

__all__ = ['urllib2_executor']


logger = logging.getLogger('libsaas.executor.urllib2_executor')


class RequestWithMethod(port.urllib_request.Request):

    def set_method(self, method):
        self.method = method

    def get_method(self):
        return self.method


def encode_uri(request):
    if not request.params:
        return request.uri

    return request.uri + '?' + http.urlencode_any(request.params)


def encode_data(request):
    if not request.params:
        return b''

    if isinstance(request.params, (port.text_type, port.binary_type)):
        return port.to_b(request.params)

    return http.urlencode_any(request.params)


class ErrorSwallower(port.urllib_request.HTTPErrorProcessor):

    def http_response(self, request, response):
        return response

    https_response = http_response


class Urllib2Executor(object):

    def __init__(self, extra_handlers):
        self.handlers = (ErrorSwallower, ) + extra_handlers

    def __call__(self, request, parser):
        """
        The default executor, using Python's builtin urllib2 module.
        """
        logger.info('requesting %r', request)

        uri = request.uri
        data = None

        if request.method.upper() in http.URLENCODE_METHODS:
            uri = encode_uri(request)
        else:
            data = encode_data(request)

        logger.debug('request uri: %r, data: %r, headers: %r',
                     uri, data, request.headers)

        req = RequestWithMethod(uri, data, request.headers)
        req.set_method(request.method)

        opener = port.urllib_request.build_opener(*self.handlers)
        resp = opener.open(req)

        body = resp.read()
        headers = dict(resp.info())
        logger.debug('response code: %r, body: %r, headers: %r',
                     resp.code, body, headers)

        return parser(body, resp.code, headers)


def use(extra_handlers=()):
    base.use_executor(Urllib2Executor(extra_handlers=extra_handlers))
