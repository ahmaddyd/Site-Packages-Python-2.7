"""
Utilities for writing code compatible with different versions of Python.

Mostly stolen from six, but we don't want to make it a dependency.
"""
import sys


PY3 = sys.version_info[0] == 3


if PY3:

    text_type = str
    binary_type = bytes
    integer_types = int,
    numeric_types = int, float

    from urllib import request as urllib_request
    from urllib.parse import urlencode, urlparse, urlunparse, quote, parse_qsl

    from io import StringIO

else:

    text_type = unicode
    binary_type = str
    integer_types = int, long
    numeric_types = int, long, float

    import urllib2 as urllib_request
    from urllib import urlencode, quote
    from urlparse import urlparse, urlunparse, parse_qsl

    try:
        from cStringIO import StringIO
    except ImportError:
        from StringIO import StringIO


def to_u(val, encoding='utf-8'):
    """
    Take a number, text (unicode) or binary value and return unicode. Binary
    values are decoded using the provided encoding.
    """
    if isinstance(val, text_type):
        return val
    elif isinstance(val, numeric_types):
        return text_type(val)

    return val.decode(encoding)


def to_b(val, encoding='utf-8'):
    """
    Take a number, text (unicode) or binary value and return binary. Univode
    values are encoded using the provided encoding.
    """
    if isinstance(val, binary_type):
        return val
    elif isinstance(val, numeric_types):
        return text_type(val).encode(encoding)

    return val.encode(encoding)


def method_func(klass, method_name):
    """
    Get the function object from a class and a method name.

    In Python 2 doing getattr(SomeClass, 'methodname') returns an
    instancemethod and in Python 3 a function. Use this helper to reliably get
    the function object
    """
    method = getattr(klass, method_name)
    # in Python 2 method will be an instancemethod, try to get its __func__
    # attribute and fall back to what we already have (for Python 3)
    return getattr(method, '__func__', method)


# copy-pasted from Python 2.7 sources, with the regex parameter removed

class _AssertRaisesContext(object):
    """A context manager used to implement TestCase.assertRaises* methods."""

    def __init__(self, expected):
        self.expected = expected

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tb):
        if exc_type is None:
            try:
                exc_name = self.expected.__name__
            except AttributeError:
                exc_name = str(self.expected)
            raise self.failureException(
                "{0} not raised".format(exc_name))
        if not issubclass(exc_type, self.expected):
            # let unexpected exceptions pass through
            return False
        self.exception = exc_value # store for later retrieval
        return True


def assertRaises(exception):
    return _AssertRaisesContext(exception)
