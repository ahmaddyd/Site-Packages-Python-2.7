"""
HTTP utilities.
"""
from itertools import chain

from libsaas import port

URLENCODE_METHODS = ('GET', 'HEAD', 'OPTIONS')


class HTTPError(Exception):
    """
    A non-2xx code has been returned.
    """
    def __init__(self, body, code, headers):
        self.body = body
        self.code = code
        self.headers = headers

    def __repr__(self):
        return '<{0} code {1}>'.format(self.__class__.__name__, self.code)

    __str__ = __repr__


class Request(object):
    """
    Everything that's needed to make a HTTP request.
    """
    def __init__(self, method, uri, params=None, headers=None):
        """
        :var method: the HTTP method
        :vartype method: str using only ASCII characters

        :var uri: the URI, without query parameters
        :vartype uri: str using only ASCII characters

        :var params: query parameters or body
        :vartype params: dict or string, keys and values can be text, binary or
            integer and the executor will encode and quote them

        :var headers: HTTP headers
        :vartype headers: dict of str to str, both
            keys and values using only ASCII characters
        """
        self.method = method
        self.uri = uri
        self.params = params if params is not None else {}
        self.headers = headers if headers is not None else {}

    def __repr__(self):
        return "<Request [%s %s] at 0x%x>" % (self.method, self.uri,
                                              id(self))

    def __eq__(self, other):
        if not isinstance(other, Request):
            return False

        return ((other.method, other.uri, other.params, other.headers) ==
                (self.method, self.uri, self.params, self.headers))

    def __ne__(self, other):
        return not self == other


def quote_any(val):
    """
    Percent quote any value, be it binary, text or integer.
    """
    return port.quote(port.to_b(val))


def urlencode_any(d):
    """
    Encode a dictionary or a sequence of two-element tuples consisting of a
    mixture of bytes, text and integers into a str object that only uses ASCII
    characters.
    """
    try:
        d = d.items()
    except AttributeError:
        pass
    as_bytes = tuple((port.to_b(key), port.to_b(value)) for key, value in d)
    return port.urlencode(as_bytes)


def serialize_flatten(name, value, array_indices=True):
    """
    Transform a parameter name and a value (which can by any Python object)
    into a flat tuple of param tuples. This is a common way of serializing
    parameters in PHP applications.

    If array_indices is True, lists are serialized as:

        param[0]=val1&param[1]=val2

    whereas is it's False, they are serialized as:

        param[]=val1&param[]=val2

    The former is more generic and allows list values to be objects, while the
    latter is there for compatibility with services that don't understand
    numeric indices.

    >>> serialize_flatten('p1', ['v1', 'v2', 'v3'], True)
    (('p1[0]', 'v1'), ('p1[1]', 'v2'), ('p1[2]', 'v3'))

    >>> serialize_flatten('p1', ['v1', 'v2', 'v3'], False)
    (('p1[]', 'v1'), ('p1[]', 'v2'), ('p1[]', 'v3'))

    >>> serialize_flatten('p1', [{'k1': 'v1', 'k2': True},
    ...                          {'k1': 'v2', 'k2': False}])
    (('p1[0][k1]', 'v1'), ('p1[0][k2]', 'true'),
     ('p1[1][k1]', 'v2'), ('p1[1][k2]', 'false'))
    """
    # call the recursive function that returns a tuple of tuples
    return tuple(serialize_flatten_rec(name, value, array_indices))


def serialize_flatten_rec(prefix, value, array_indices):
    """
    Recursive helper for serialize_flatten.
    """
    if isinstance(value, dict):
        # serializing a dictionary, use prefix[key] as the prefix, recurse for
        # all dict items and flatten the result
        return chain.from_iterable(
            (serialize_flatten_rec('{0}[{1}]'.format(
                        port.to_u(prefix), port.to_u(key)),
                                   val, array_indices)
             for key, val in value.items()))
    elif isinstance(value, list):
        # serializing a list, use prefix[] as the prefix, recurse for
        # all items and flatten the result
        return chain.from_iterable(
            (serialize_flatten_rec('{0}[{1}]'.format(
                        port.to_u(prefix), i if array_indices else ''),
                                   val, array_indices)
             for i, val in enumerate(value)))
    elif isinstance(value, bool):
        # serializing a boolean, take the prefix as-is and serialize the value
        # to string
        return ((port.to_u(prefix), 'true' if value else 'false'), )
    else:
        # anything else, just use the prefix and value as-is
        return ((port.to_u(prefix), port.to_u(value)), )
