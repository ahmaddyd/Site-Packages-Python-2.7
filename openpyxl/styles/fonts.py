from __future__ import absolute_import
# Copyright (c) 2010-2014 openpyxl
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
# @license: http://www.opensource.org/licenses/mit-license.php
# @author: see AUTHORS file

from openpyxl.descriptors import Strict, Float, Integer, Set, Bool, String, Alias, Typed
from .hashable import HashableObject
from .colors import Color


class Font(HashableObject):
    """Font options used in styles."""

    spec = """18.8.22, p.3930"""

    UNDERLINE_NONE = 'none'
    UNDERLINE_DOUBLE = 'double'
    UNDERLINE_DOUBLE_ACCOUNTING = 'doubleAccounting'
    UNDERLINE_SINGLE = 'single'
    UNDERLINE_SINGLE_ACCOUNTING = 'singleAccounting'


    name = String()
    charset = Integer(allow_none=True)
    family = String(allow_none=True)
    sz = Float()
    size = Alias("sz")
    b = Bool()
    bold = Alias("b")
    i = Bool()
    italic = Alias("i")
    strike = Bool()
    strikethrough = Alias("strike")
    outline = Bool()
    shadow = Bool()
    condense = Bool()
    extend = Bool()
    superscript = Bool()
    subscript = Bool()
    u = Set(values=set([None, UNDERLINE_DOUBLE, UNDERLINE_NONE,
                        UNDERLINE_DOUBLE_ACCOUNTING, UNDERLINE_SINGLE,
                        UNDERLINE_SINGLE_ACCOUNTING]))
    underline = Alias("u")
    color = Typed(expected_type=Color)
    schema = String(allow_none=True)

    __fields__ = ('name',
                  'sz',
                  'b',
                  'i',
                  'u',
                  'strike',
                  'color')

    def __init__(self, name='Calibri', sz=11, b=False, i=False, charset=None,
                 u=UNDERLINE_NONE, strike=False, color=Color(), scheme=None, family=None,
                 size=None, bold=None, italic=None, strikethrough=None, underline=None):
        self.name = name
        if size is not None:
            sz = size
        self.sz = sz
        if bold is not None:
            b = bold
        self.b = b
        if italic is not None:
            i = italic
        self.i = i
        if underline is not None:
            u = underline
        self.u = u
        if strikethrough is not None:
            strike = strikethrough
        self.strike = strike
        self.color = color
