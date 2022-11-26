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

import datetime
import os.path

import pytest

from openpyxl.tests.helper import DATADIR
from openpyxl.worksheet.iter_worksheet import get_range_boundaries, read_dimension
from openpyxl.reader.excel import load_workbook
from openpyxl.compat import range, izip


def test_open_many_sheets(datadir):
    datadir.join("reader").chdir()
    wb = load_workbook("bigfoot.xlsx", True) # if
    assert len(wb.worksheets) == 1024


@pytest.mark.parametrize("filename, expected",
                         [
                             ("sheet2.xml", ('D', 1, 'AA', 30)),
                             ("sheet2_no_dimension.xml", None),
                             ("sheet2_no_span.xml", None),
                          ]
                         )
def test_read_dimension(datadir, filename, expected):
    datadir.join("reader").chdir()
    with open(filename) as handle:
        dimension = read_dimension(handle)
    assert dimension == expected


def test_calculate_dimension(datadir):
    datadir.join("genuine").chdir()
    wb = load_workbook("empty.xlsx", use_iterators=True)
    sheet2 = wb.get_sheet_by_name('Sheet2 - Numbers')
    dimensions = sheet2.calculate_dimension()
    assert '%s%s:%s%s' % ('D', 1, 'AA', 30) == dimensions


def test_get_highest_row(datadir):
    datadir.join("genuine").chdir()
    wb = load_workbook("empty.xlsx", use_iterators=True)
    sheet2 = wb.get_sheet_by_name('Sheet2 - Numbers')
    max_row = sheet2.get_highest_row()
    assert 30 == max_row



class TestWorksheet(object):

    workbook_name = os.path.join(DATADIR, 'genuine', 'empty.xlsx')

    def _open_wb(self, data_only=False):
        return load_workbook(filename=self.workbook_name,
                             use_iterators=True,
                             data_only=data_only)

    def test_getitem(self):
        wb = self._open_wb()
        ws = wb['Sheet1 - Text']
        assert list(ws.iter_rows("A1"))[0][0] == ws['A1']
        assert list(ws.iter_rows("A1:D30")) == list(ws["A1:D30"])
        assert list(ws.iter_rows("A1:D30")) == list(ws["A1":"D30"])

        ws = wb['Sheet2 - Numbers']
        assert ws['A1'] is None


class TestDims(TestWorksheet):
    expected = [
        ("Sheet1 - Text", 'A1:G5'),
        ("Sheet2 - Numbers", 'D1:AA30'),
        ("Sheet3 - Formulas", 'D2:D2'),
        ("Sheet4 - Dates", 'A1:C1')
                 ]
    @pytest.mark.parametrize("sheetname, dims", expected)
    def test_get_dimensions(self, sheetname, dims):
        wb = self._open_wb()
        ws = wb[sheetname]
        assert ws.dimensions == dims

    expected = [
        ("Sheet1 - Text", 7),
        ("Sheet2 - Numbers", 27),
        ("Sheet3 - Formulas", 4),
        ("Sheet4 - Dates", 3)
                 ]
    @pytest.mark.parametrize("sheetname, col", expected)
    def test_get_highest_column_iter(self, sheetname, col):
        wb = self._open_wb()
        ws = wb[sheetname]
        assert ws.get_highest_column() == col


def test_get_boundaries_range():
    assert get_range_boundaries('C1:C4') == (3, 1, 4, 4)

def test_get_boundaries_one():
    assert get_range_boundaries('C1') == (3, 1, 4, 1)


class TestText(TestWorksheet):
    sheet_name = 'Sheet1 - Text'
    expected = [['This is cell A1 in Sheet 1', None, None, None, None, None, None],
                [None, None, None, None, None, None, None],
                [None, None, None, None, None, None, None],
                [None, None, None, None, None, None, None],
                [None, None, None, None, None, None, 'This is cell G5'], ]
    def test_read_fast_integrated(self):
        wb = self._open_wb()
        ws = wb.get_sheet_by_name(name = self.sheet_name)
        for row, expected_row in izip(ws.iter_rows(), self.expected):
            row_values = [x.value for x in row]
            assert row_values == expected_row

    def test_read_single_cell_range(self):
        wb = self._open_wb()
        ws = wb.get_sheet_by_name(name = self.sheet_name)
        assert 'This is cell A1 in Sheet 1' == list(ws.iter_rows('A1'))[0][0].value

class TestIntegers(TestWorksheet):

    sheet_name = 'Sheet2 - Numbers'
    expected = [[x + 1] for x in range(30)]
    query_range = 'D1:D30'

    def test_read_fast_integrated(self):
        wb = self._open_wb()
        ws = wb.get_sheet_by_name(name = self.sheet_name)
        for row, expected_row in izip(ws.iter_rows(self.query_range), self.expected):
            row_values = [x.value for x in row]
            assert row_values == expected_row


class TestFloats(TestWorksheet):

    sheet_name = 'Sheet2 - Numbers'
    query_range = 'K1:K30'
    expected = expected = [[(x + 1) / 100.0] for x in range(30)]

    def test_read_fast_integrated(self):
        wb = self._open_wb()
        ws = wb.get_sheet_by_name(name = self.sheet_name)
        for row, expected_row in izip(ws.iter_rows(self.query_range), self.expected):
            row_values = [x.value for x in row]
            assert row_values == expected_row


class TestDates(TestWorksheet):

    sheet_name = 'Sheet4 - Dates'

    @pytest.mark.parametrize("cell, value",
        [
        ("A1", datetime.datetime(1973, 5, 20)),
        ("C1", datetime.datetime(1973, 5, 20, 9, 15, 2))
        ]
        )
    def test_read_single_cell_date(self, cell, value):
        wb = self._open_wb()
        ws = wb.get_sheet_by_name(name = self.sheet_name)
        rows = ws.iter_rows(cell)
        cell = list(rows)[0][0]
        assert cell.value == value

class TestFormula(TestWorksheet):

    @pytest.mark.parametrize("data_only, expected",
        [
        (True, 5),
        (False, "='Sheet2 - Numbers'!D5")
        ]
        )
    def test_read_single_cell_formula(self, data_only, expected):
        wb = self._open_wb(data_only)
        ws = wb.get_sheet_by_name("Sheet3 - Formulas")
        rows = ws.iter_rows("D2")
        cell = list(rows)[0][0]
        assert ws.parent.data_only == data_only
        assert cell.value == expected


class TestBoolean(TestWorksheet):

    @pytest.mark.parametrize("cell, expected",
        [
        ("G9", True),
        ("G10", False)
        ]
        )
    def test_read_boolean(self, cell, expected):
        wb = self._open_wb()
        ws = wb["Sheet2 - Numbers"]
        row = list(ws.iter_rows(cell))
        assert row[0][0].coordinate == cell
        assert row[0][0].data_type == 'b'
        assert row[0][0].value == expected
