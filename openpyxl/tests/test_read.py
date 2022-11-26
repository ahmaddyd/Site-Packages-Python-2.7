# coding=utf8

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

# Python stdlib imports
from datetime import datetime
from io import BytesIO, StringIO
import os.path
from operator import itemgetter
from tempfile import NamedTemporaryFile
import zipfile

import pytest

# compatibility imports
from openpyxl.compat import unicode, tempfile

# package imports
from openpyxl.collections import IndexedList
from openpyxl.worksheet import Worksheet
from openpyxl.workbook import Workbook
from openpyxl.styles import NumberFormat, Style
from openpyxl.reader.worksheet import read_worksheet
from openpyxl.reader.excel import load_workbook
from openpyxl.exceptions import InvalidFileException
from openpyxl.date_time import CALENDAR_WINDOWS_1900, CALENDAR_MAC_1904


def test_read_standalone_worksheet(datadir):

    class DummyWb(object):

        encoding = 'utf-8'

        excel_base_date = CALENDAR_WINDOWS_1900
        _guess_types = True
        data_only = False

        def get_sheet_by_name(self, value):
            return None

        def get_sheet_names(self):
            return []

    datadir.join("reader").chdir()
    ws = None
    shared_strings = IndexedList(['hello'])

    with open('sheet2.xml') as src:
        ws = read_worksheet(src.read(), DummyWb(), 'Sheet 2', shared_strings,
                            {1: Style()})
        assert isinstance(ws, Worksheet)
        assert ws.cell('G5').value == 'hello'
        assert ws.cell('D30').value == 30
        assert ws.cell('K9').value == 0.09


@pytest.fixture
def standard_workbook(datadir):
    datadir.join("genuine").chdir()
    return load_workbook("empty.xlsx")


def test_read_standard_workbook(standard_workbook):
    wb = standard_workbook
    assert isinstance(wb, Workbook)


def test_read_standard_workbook_from_fileobj(datadir):
    datadir.join("genuine").chdir()
    fo = open('empty.xlsx', mode='rb')
    wb = load_workbook(fo)
    assert isinstance(wb, Workbook)


def test_read_worksheet(standard_workbook):
    wb = standard_workbook
    sheet2 = wb['Sheet2 - Numbers']
    assert isinstance(sheet2, Worksheet)
    assert 'This is cell G5' == sheet2['G5'].value
    assert 18 == sheet2['D18'].value
    assert sheet2['G9'].value is True
    assert sheet2['G10'].value is False


def test_read_nostring_workbook(datadir):
    datadir.join("genuine").chdir()
    wb = load_workbook('empty-no-string.xlsx')
    assert isinstance(wb, Workbook)


def test_read_empty_file(datadir):
    datadir.join("reader").chdir()
    with pytest.raises(InvalidFileException):
        load_workbook('null_file.xlsx')


def test_read_empty_archive(datadir):
    datadir.join("reader").chdir()
    with pytest.raises(InvalidFileException):
        load_workbook('null_archive.xlsx')


@pytest.mark.xfail
def test_read_workbook_with_no_properties():
    genuine_wb = os.path.join(DATADIR, 'genuine', \
                'empty_with_no_properties.xlsx')
    load_workbook(filename=genuine_wb)


@pytest.fixture
def workbook_with_styles(datadir):
    datadir.join("genuine").chdir()
    wb = load_workbook('empty-with-styles.xlsx')
    return wb["Sheet1"]

class TestReadWorkbookWithStyles(object):

    def test_read_general_style(self, workbook_with_styles):
        ws = workbook_with_styles
        assert ws.cell('A1').style.number_format.format_code == NumberFormat.FORMAT_GENERAL

    def test_read_date_style(self, workbook_with_styles):
        ws = workbook_with_styles
        assert ws.cell('A2').style.number_format.format_code == NumberFormat.FORMAT_DATE_XLSX14

    def test_read_number_style(self, workbook_with_styles):
        ws = workbook_with_styles
        assert ws.cell('A3').style.number_format.format_code == NumberFormat.FORMAT_NUMBER_00

    def test_read_time_style(self, workbook_with_styles):
        ws = workbook_with_styles
        assert ws.cell('A4').style.number_format.format_code == NumberFormat.FORMAT_DATE_TIME3

    def test_read_percentage_style(self, workbook_with_styles):
        ws = workbook_with_styles
        assert ws.cell('A5').style.number_format.format_code == NumberFormat.FORMAT_PERCENTAGE_00


@pytest.fixture
def date_mac_1904(datadir):
    datadir.join("reader").chdir()
    wb = load_workbook('date_1904.xlsx')
    return wb

@pytest.fixture
def date_std_1900(datadir):
    datadir.join("reader").chdir()
    wb = load_workbook('date_1900.xlsx')
    return wb


class TestReadBaseDateFormat(object):

    def test_read_win_base_date(self, date_std_1900):
        wb = date_std_1900
        assert wb.properties.excel_base_date == CALENDAR_WINDOWS_1900

    def test_read_mac_base_date(self, date_mac_1904):
        wb = date_mac_1904
        assert wb.properties.excel_base_date == CALENDAR_MAC_1904

    def test_read_date_style_mac(self, date_mac_1904):
        ws = date_mac_1904["Sheet1"]
        assert ws.cell('A1').style.number_format.format_code == NumberFormat.FORMAT_DATE_XLSX14

    def test_read_date_style_win(self, date_std_1900):
        ws = date_std_1900["Sheet1"]
        assert ws.cell('A1').style.number_format.format_code == NumberFormat.FORMAT_DATE_XLSX14

    def test_read_date_value(sel, date_std_1900, date_mac_1904):
        win = date_std_1900["Sheet1"]
        mac = date_mac_1904["Sheet1"]
        datetuple = (2011, 10, 31)
        dt = datetime(datetuple[0], datetuple[1], datetuple[2])
        assert mac.cell('A1').value == dt
        assert win.cell('A1').value == dt
        assert mac.cell('A1').value == win.cell('A1').value


def test_repair_central_directory():
    from openpyxl.reader.excel import repair_central_directory, CENTRAL_DIRECTORY_SIGNATURE

    data_a = b"foobarbaz" + CENTRAL_DIRECTORY_SIGNATURE
    data_b = b"bazbarfoo1234567890123456890"

    # The repair_central_directory looks for a magic set of bytes
    # (CENTRAL_DIRECTORY_SIGNATURE) and strips off everything 18 bytes past the sequence
    f = repair_central_directory(BytesIO(data_a + data_b), True)
    assert f.read() == data_a + data_b[:18]

    f = repair_central_directory(BytesIO(data_b), True)
    assert f.read() == data_b


def test_read_no_theme(datadir):
    datadir.join("genuine").chdir()
    wb = load_workbook('libreoffice_nrt.xlsx')
    assert wb


def test_read_cell_formulae(datadir):
    from openpyxl.reader.worksheet import fast_parse
    datadir.join("reader").chdir()
    wb = Workbook()
    ws = wb.active
    fast_parse(ws, open( "worksheet_formula.xml"), ['', ''], {}, None)
    b1 = ws['B1']
    assert b1.data_type == 'f'
    assert b1.value == '=CONCATENATE(A1,A2)'
    a6 = ws['A6']
    assert a6.data_type == 'f'
    assert a6.value == '=SUM(A4:A5)'


def test_read_complex_formulae(datadir):
    datadir.join("reader").chdir()
    wb = load_workbook('formulae.xlsx')
    ws = wb.get_active_sheet()

    # Test normal forumlae
    assert ws.cell('A1').data_type != 'f'
    assert ws.cell('A2').data_type != 'f'
    assert ws.cell('A3').data_type == 'f'
    assert 'A3' not in ws.formula_attributes
    assert ws.cell('A3').value == '=12345'
    assert ws.cell('A4').data_type == 'f'
    assert 'A4' not in ws.formula_attributes
    assert ws.cell('A4').value == '=A2+A3'
    assert ws.cell('A5').data_type == 'f'
    assert 'A5' not in ws.formula_attributes
    assert ws.cell('A5').value == '=SUM(A2:A4)'

    # Test unicode
    expected = '=IF(ISBLANK(B16), "Düsseldorf", B16)'
    # Hack to prevent pytest doing it's own unicode conversion
    try:
        expected = unicode(expected, "UTF8")
    except TypeError:
        pass
    assert ws['A16'].value == expected

    # Test shared forumlae
    assert ws.cell('B7').data_type == 'f'
    assert ws.formula_attributes['B7']['t'] == 'shared'
    assert ws.formula_attributes['B7']['si'] == '0'
    assert ws.formula_attributes['B7']['ref'] == 'B7:E7'
    assert ws.cell('B7').value == '=B4*2'
    assert ws.cell('C7').data_type == 'f'
    assert ws.formula_attributes['C7']['t'] == 'shared'
    assert ws.formula_attributes['C7']['si'] == '0'
    assert 'ref' not in ws.formula_attributes['C7']
    assert ws.cell('C7').value == '='
    assert ws.cell('D7').data_type == 'f'
    assert ws.formula_attributes['D7']['t'] == 'shared'
    assert ws.formula_attributes['D7']['si'] == '0'
    assert 'ref' not in ws.formula_attributes['D7']
    assert ws.cell('D7').value == '='
    assert ws.cell('E7').data_type == 'f'
    assert ws.formula_attributes['E7']['t'] == 'shared'
    assert ws.formula_attributes['E7']['si'] == '0'
    assert 'ref' not in ws.formula_attributes['E7']
    assert ws.cell('E7').value == '='

    # Test array forumlae
    assert ws.cell('C10').data_type == 'f'
    assert 'ref' not in ws.formula_attributes['C10']['ref']
    assert ws.formula_attributes['C10']['t'] == 'array'
    assert 'si' not in ws.formula_attributes['C10']
    assert ws.formula_attributes['C10']['ref'] == 'C10:C14'
    assert ws.cell('C10').value == '=SUM(A10:A14*B10:B14)'
    assert ws.cell('C11').data_type != 'f'


def test_data_only(datadir):
    datadir.join("reader").chdir()
    wb = load_workbook('formulae.xlsx', data_only=True)
    ws = wb.active
    ws.parent.data_only = True
    # Test cells returning values only, not formulae
    assert ws.formula_attributes == {}
    assert ws['A2'].data_type == 'n' and ws.cell('A2').value == 12345
    assert ws['A3'].data_type == 'n' and ws.cell('A3').value == 12345
    assert ws['A4'].data_type == 'n' and ws.cell('A4').value == 24690
    assert ws['A5'].data_type == 'n' and ws.cell('A5').value == 49380


@pytest.mark.parametrize("excel_file, expected", [
    ("bug137.xlsx", [
        {'path': 'xl/worksheets/sheet1.xml', 'title': 'Sheet1'}
        ]
     ),
    ("contains_chartsheets.xlsx", [
        {'path': 'xl/worksheets/sheet2.xml', 'title': 'moredata'},
        {'path': 'xl/worksheets/sheet1.xml', 'title': 'data'},
        ]),
    ("bug304.xlsx", [
    {'path': 'xl/worksheets/sheet.xml', 'title': 'Sheet3'},
    {'path': 'xl/worksheets/sheet2.xml', 'title': 'Sheet2'},
    {'path': 'xl/worksheets/sheet3.xml', 'title': 'Sheet1'},
    ])
]
                         )
def test_detect_worksheets(datadir, excel_file, expected):
    from openpyxl.reader.excel import detect_worksheets
    datadir.join("reader").chdir()
    archive = zipfile.ZipFile(excel_file)
    assert sorted(detect_worksheets(archive), key=itemgetter("title")) == sorted(expected, key=itemgetter("title"))


@pytest.mark.parametrize("excel_file, expected", [
    ("bug137.xlsx", {
        "rId1": {'path': 'xl/chartsheets/sheet1.xml'},
        "rId2": {'path': 'xl/worksheets/sheet1.xml'},
        "rId3": {'path': 'xl/theme/theme1.xml'},
        "rId4": {'path': 'xl/styles.xml'},
        "rId5": {'path': 'xl/sharedStrings.xml'}
    }),
    ("bug304.xlsx", {
        'rId1': {'path': 'xl/worksheets/sheet3.xml'},
        'rId2': {'path': 'xl/worksheets/sheet2.xml'},
        'rId3': {'path': 'xl/worksheets/sheet.xml'},
        'rId4': {'path': 'xl/theme/theme.xml'},
        'rId5': {'path': 'xl/styles.xml'},
        'rId6': {'path': '../customXml/item1.xml'},
        'rId7': {'path': '../customXml/item2.xml'},
        'rId8': {'path': '../customXml/item3.xml'}
    }),
]
                         )
def test_read_rels(datadir, excel_file, expected):
    datadir.join("reader").chdir()
    from openpyxl.reader.workbook import read_rels
    archive = zipfile.ZipFile(excel_file)
    assert dict(read_rels(archive)) == expected


def test_read_content_types(datadir):
    from openpyxl.reader.workbook import read_content_types
    datadir.join("reader").chdir()
    archive = zipfile.ZipFile("contains_chartsheets.xlsx")
    assert list(read_content_types(archive)) == [
    ('/xl/workbook.xml', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml'),
    ('/xl/worksheets/sheet1.xml', 'application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml'),
    ('/xl/chartsheets/sheet1.xml', 'application/vnd.openxmlformats-officedocument.spreadsheetml.chartsheet+xml'),
    ('/xl/worksheets/sheet2.xml', 'application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml'),
    ('/xl/theme/theme1.xml', 'application/vnd.openxmlformats-officedocument.theme+xml'),
    ('/xl/styles.xml', 'application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml'),
    ('/xl/sharedStrings.xml', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml'),
    ('/xl/drawings/drawing1.xml', 'application/vnd.openxmlformats-officedocument.drawing+xml'),
    ('/xl/charts/chart1.xml', 'application/vnd.openxmlformats-officedocument.drawingml.chart+xml'),
    ('/xl/drawings/drawing2.xml', 'application/vnd.openxmlformats-officedocument.drawing+xml'),
    ('/xl/charts/chart2.xml', 'application/vnd.openxmlformats-officedocument.drawingml.chart+xml'),
    ('/xl/calcChain.xml', 'application/vnd.openxmlformats-officedocument.spreadsheetml.calcChain+xml'),
    ('/docProps/core.xml', 'application/vnd.openxmlformats-package.core-properties+xml'),
    ('/docProps/app.xml', 'application/vnd.openxmlformats-officedocument.extended-properties+xml')
    ]


@pytest.mark.parametrize("excel_file, expected", [
    ("bug137.xlsx",
     {"rId1":"Chart1", "rId2":"Sheet1"}
     ),
    ("bug304.xlsx",
     {'rId1': 'Sheet1', 'rId2': 'Sheet2', 'rId3': 'Sheet3'}
     )
])
def test_read_sheets(datadir, excel_file, expected):
    from openpyxl.reader.workbook import read_sheets
    datadir.join("reader")
    archive = zipfile.ZipFile(excel_file)
    assert dict(read_sheets(archive)) == expected


def test_guess_types(datadir):
    datadir.join("genuine").chdir()
    for guess, dtype in ((True, float), (False, unicode)):
        wb = load_workbook('guess_types.xlsx', guess_types=guess)
        ws = wb.get_active_sheet()
        assert isinstance(ws.cell('D2').value, dtype), 'wrong dtype (%s) when guess type is: %s (%s instead)' % (dtype, guess, type(ws.cell('A1').value))


def test_get_xml_iter():
    #1 file object
    #2 stream (file-like)
    #3 string
    #4 zipfile
    from openpyxl.reader.worksheet import _get_xml_iter
    from tempfile import TemporaryFile
    FUT = _get_xml_iter
    s = b""
    stream = FUT(s)
    assert isinstance(stream, BytesIO), type(stream)

    u = unicode(s)
    stream = FUT(u)
    assert isinstance(stream, BytesIO), type(stream)

    f = TemporaryFile(mode='rb+', prefix='openpyxl.', suffix='.unpack.temp')
    stream = FUT(f)
    assert isinstance(stream, tempfile), type(stream)
    f.close()

    from zipfile import ZipFile
    t = TemporaryFile()
    z = ZipFile(t, mode="w")
    z.writestr("test", "whatever")
    stream = FUT(z.open("test"))
    assert hasattr(stream, "read")
    z.close()


def test_read_autofilter(datadir):
    datadir.join("reader").chdir()
    wb = load_workbook("bug275.xlsx")
    ws = wb.active
    assert ws.auto_filter.ref == 'A1:B6'


class TestBadFormats:

    def test_xlsb(self):
        tmp = NamedTemporaryFile(suffix='.xlsb')
        with pytest.raises(InvalidFileException):
            load_workbook(filename=tmp.name)

    def test_xls(self):
        tmp = NamedTemporaryFile(suffix='.xls')
        with pytest.raises(InvalidFileException):
            load_workbook(filename=tmp.name)

    def test_no(self):
        tmp = NamedTemporaryFile(suffix='.no-format')
        with pytest.raises(InvalidFileException):
            load_workbook(filename=tmp.name)
