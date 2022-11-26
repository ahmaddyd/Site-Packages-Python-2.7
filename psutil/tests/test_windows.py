#!/usr/bin/env python
# -*- coding: UTF-8 -*

# Copyright (c) 2009, Giampaolo Rodola'. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Windows specific tests."""

import errno
import glob
import os
import platform
import signal
import subprocess
import sys
import time
import traceback

try:
    import wmi  # requires "pip install wmi"
except ImportError:
    wmi = None
try:
    import win32api  # requires "pip install pypiwin32"
    import win32con
except ImportError:
    win32api = win32con = None

import psutil
from psutil import WINDOWS
from psutil._compat import basestring
from psutil._compat import callable
from psutil._compat import long
from psutil._compat import PY3
from psutil.tests import APPVEYOR
from psutil.tests import get_test_subprocess
from psutil.tests import mock
from psutil.tests import reap_children
from psutil.tests import retry_before_failing
from psutil.tests import run_test_module_by_name
from psutil.tests import unittest


cext = psutil._psplatform.cext

# are we a 64 bit process
IS_64_BIT = sys.maxsize > 2**32


def wrap_exceptions(fun):
    def wrapper(self, *args, **kwargs):
        try:
            return fun(self, *args, **kwargs)
        except OSError as err:
            from psutil._pswindows import ACCESS_DENIED_SET
            if err.errno in ACCESS_DENIED_SET:
                raise psutil.AccessDenied(None, None)
            if err.errno == errno.ESRCH:
                raise psutil.NoSuchProcess(None, None)
            raise
    return wrapper


@unittest.skipUnless(WINDOWS, "not a Windows system")
class WindowsSpecificTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.pid = get_test_subprocess().pid

    @classmethod
    def tearDownClass(cls):
        reap_children()

    def test_issue_24(self):
        p = psutil.Process(0)
        self.assertRaises(psutil.AccessDenied, p.kill)

    def test_special_pid(self):
        p = psutil.Process(4)
        self.assertEqual(p.name(), 'System')
        # use __str__ to access all common Process properties to check
        # that nothing strange happens
        str(p)
        p.username()
        self.assertTrue(p.create_time() >= 0.0)
        try:
            rss, vms = p.memory_info()[:2]
        except psutil.AccessDenied:
            # expected on Windows Vista and Windows 7
            if not platform.uname()[1] in ('vista', 'win-7', 'win7'):
                raise
        else:
            self.assertTrue(rss > 0)

    def test_send_signal(self):
        p = psutil.Process(self.pid)
        self.assertRaises(ValueError, p.send_signal, signal.SIGINT)

    def test_nic_names(self):
        p = subprocess.Popen(['ipconfig', '/all'], stdout=subprocess.PIPE)
        out = p.communicate()[0]
        if PY3:
            out = str(out, sys.stdout.encoding or sys.getfilesystemencoding())
        nics = psutil.net_io_counters(pernic=True).keys()
        for nic in nics:
            if "pseudo-interface" in nic.replace(' ', '-').lower():
                continue
            if nic not in out:
                self.fail(
                    "%r nic wasn't found in 'ipconfig /all' output" % nic)

    def test_exe(self):
        for p in psutil.process_iter():
            try:
                self.assertEqual(os.path.basename(p.exe()), p.name())
            except psutil.Error:
                pass

    # --- Process class tests

    @unittest.skipIf(wmi is None, "wmi module is not installed")
    def test_process_name(self):
        w = wmi.WMI().Win32_Process(ProcessId=self.pid)[0]
        p = psutil.Process(self.pid)
        self.assertEqual(p.name(), w.Caption)

    @unittest.skipIf(wmi is None, "wmi module is not installed")
    def test_process_exe(self):
        w = wmi.WMI().Win32_Process(ProcessId=self.pid)[0]
        p = psutil.Process(self.pid)
        # Note: wmi reports the exe as a lower case string.
        # Being Windows paths case-insensitive we ignore that.
        self.assertEqual(p.exe().lower(), w.ExecutablePath.lower())

    @unittest.skipIf(wmi is None, "wmi module is not installed")
    def test_process_cmdline(self):
        w = wmi.WMI().Win32_Process(ProcessId=self.pid)[0]
        p = psutil.Process(self.pid)
        self.assertEqual(' '.join(p.cmdline()),
                         w.CommandLine.replace('"', ''))

    @unittest.skipIf(wmi is None, "wmi module is not installed")
    def test_process_username(self):
        w = wmi.WMI().Win32_Process(ProcessId=self.pid)[0]
        p = psutil.Process(self.pid)
        domain, _, username = w.GetOwner()
        username = "%s\\%s" % (domain, username)
        self.assertEqual(p.username(), username)

    @unittest.skipIf(wmi is None, "wmi module is not installed")
    def test_process_rss_memory(self):
        time.sleep(0.1)
        w = wmi.WMI().Win32_Process(ProcessId=self.pid)[0]
        p = psutil.Process(self.pid)
        rss = p.memory_info().rss
        self.assertEqual(rss, int(w.WorkingSetSize))

    @unittest.skipIf(wmi is None, "wmi module is not installed")
    def test_process_vms_memory(self):
        time.sleep(0.1)
        w = wmi.WMI().Win32_Process(ProcessId=self.pid)[0]
        p = psutil.Process(self.pid)
        vms = p.memory_info().vms
        # http://msdn.microsoft.com/en-us/library/aa394372(VS.85).aspx
        # ...claims that PageFileUsage is represented in Kilo
        # bytes but funnily enough on certain platforms bytes are
        # returned instead.
        wmi_usage = int(w.PageFileUsage)
        if (vms != wmi_usage) and (vms != wmi_usage * 1024):
            self.fail("wmi=%s, psutil=%s" % (wmi_usage, vms))

    @unittest.skipIf(wmi is None, "wmi module is not installed")
    def test_process_create_time(self):
        w = wmi.WMI().Win32_Process(ProcessId=self.pid)[0]
        p = psutil.Process(self.pid)
        wmic_create = str(w.CreationDate.split('.')[0])
        psutil_create = time.strftime("%Y%m%d%H%M%S",
                                      time.localtime(p.create_time()))
        self.assertEqual(wmic_create, psutil_create)

    # --- psutil namespace functions and constants tests

    @unittest.skipUnless('NUMBER_OF_PROCESSORS' in os.environ,
                         'NUMBER_OF_PROCESSORS env var is not available')
    def test_cpu_count(self):
        num_cpus = int(os.environ['NUMBER_OF_PROCESSORS'])
        self.assertEqual(num_cpus, psutil.cpu_count())

    @unittest.skipIf(wmi is None, "wmi module is not installed")
    def test_total_phymem(self):
        w = wmi.WMI().Win32_ComputerSystem()[0]
        self.assertEqual(int(w.TotalPhysicalMemory),
                         psutil.virtual_memory().total)

    # @unittest.skipIf(wmi is None, "wmi module is not installed")
    # def test__UPTIME(self):
    #     # _UPTIME constant is not public but it is used internally
    #     # as value to return for pid 0 creation time.
    #     # WMI behaves the same.
    #     w = wmi.WMI().Win32_Process(ProcessId=self.pid)[0]
    #     p = psutil.Process(0)
    #     wmic_create = str(w.CreationDate.split('.')[0])
    #     psutil_create = time.strftime("%Y%m%d%H%M%S",
    #                                   time.localtime(p.create_time()))
    #

    # Note: this test is not very reliable
    @unittest.skipIf(wmi is None, "wmi module is not installed")
    @unittest.skipIf(APPVEYOR, "test not relieable on appveyor")
    def test_pids(self):
        # Note: this test might fail if the OS is starting/killing
        # other processes in the meantime
        w = wmi.WMI().Win32_Process()
        wmi_pids = set([x.ProcessId for x in w])
        psutil_pids = set(psutil.pids())
        self.assertEqual(wmi_pids, psutil_pids)

    @unittest.skipIf(wmi is None, "wmi module is not installed")
    @retry_before_failing()
    def test_disks(self):
        ps_parts = psutil.disk_partitions(all=True)
        wmi_parts = wmi.WMI().Win32_LogicalDisk()
        for ps_part in ps_parts:
            for wmi_part in wmi_parts:
                if ps_part.device.replace('\\', '') == wmi_part.DeviceID:
                    if not ps_part.mountpoint:
                        # this is usually a CD-ROM with no disk inserted
                        break
                    try:
                        usage = psutil.disk_usage(ps_part.mountpoint)
                    except OSError as err:
                        if err.errno == errno.ENOENT:
                            # usually this is the floppy
                            break
                        else:
                            raise
                    self.assertEqual(usage.total, int(wmi_part.Size))
                    wmi_free = int(wmi_part.FreeSpace)
                    self.assertEqual(usage.free, wmi_free)
                    # 10 MB tollerance
                    if abs(usage.free - wmi_free) > 10 * 1024 * 1024:
                        self.fail("psutil=%s, wmi=%s" % (
                            usage.free, wmi_free))
                    break
            else:
                self.fail("can't find partition %s" % repr(ps_part))

    @unittest.skipIf(win32api is None, "pywin32 module is not installed")
    def test_num_handles(self):
        p = psutil.Process(os.getpid())
        before = p.num_handles()
        handle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION,
                                      win32con.FALSE, os.getpid())
        after = p.num_handles()
        self.assertEqual(after, before + 1)
        win32api.CloseHandle(handle)
        self.assertEqual(p.num_handles(), before)

    @unittest.skipIf(win32api is None, "pywin32 module is not installed")
    def test_num_handles_2(self):
        # Note: this fails from time to time; I'm keen on thinking
        # it doesn't mean something is broken
        def call(p, attr):
            attr = getattr(p, name, None)
            if attr is not None and callable(attr):
                attr()
            else:
                attr

        p = psutil.Process(self.pid)
        failures = []
        for name in dir(psutil.Process):
            if name.startswith('_') \
                or name in ('terminate', 'kill', 'suspend', 'resume',
                            'nice', 'send_signal', 'wait', 'children',
                            'as_dict'):
                continue
            else:
                try:
                    call(p, name)
                    num1 = p.num_handles()
                    call(p, name)
                    num2 = p.num_handles()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                else:
                    if num2 > num1:
                        fail = \
                            "failure while processing Process.%s method " \
                            "(before=%s, after=%s)" % (name, num1, num2)
                        failures.append(fail)
        if failures:
            self.fail('\n' + '\n'.join(failures))

    def test_name_always_available(self):
        # On Windows name() is never supposed to raise AccessDenied,
        # see https://github.com/giampaolo/psutil/issues/627
        for p in psutil.process_iter():
            try:
                p.name()
            except psutil.NoSuchProcess:
                pass

    @unittest.skipUnless(sys.version_info >= (2, 7),
                         "CTRL_* signals not supported")
    def test_ctrl_signals(self):
        p = psutil.Process(get_test_subprocess().pid)
        p.send_signal(signal.CTRL_C_EVENT)
        p.send_signal(signal.CTRL_BREAK_EVENT)
        p.kill()
        p.wait()
        self.assertRaises(psutil.NoSuchProcess,
                          p.send_signal, signal.CTRL_C_EVENT)
        self.assertRaises(psutil.NoSuchProcess,
                          p.send_signal, signal.CTRL_BREAK_EVENT)

    @unittest.skipIf(wmi is None, "wmi module is not installed")
    def test_net_if_stats(self):
        ps_names = set(cext.net_if_stats())
        wmi_adapters = wmi.WMI().Win32_NetworkAdapter()
        wmi_names = set()
        for wmi_adapter in wmi_adapters:
            wmi_names.add(wmi_adapter.Name)
            wmi_names.add(wmi_adapter.NetConnectionID)
        self.assertTrue(ps_names & wmi_names,
                        "no common entries in %s, %s" % (ps_names, wmi_names))


@unittest.skipUnless(WINDOWS, "not a Windows system")
class TestDualProcessImplementation(unittest.TestCase):
    """
    Certain APIs on Windows have 2 internal implementations, one
    based on documented Windows APIs, another one based
    NtQuerySystemInformation() which gets called as fallback in
    case the first fails because of limited permission error.
    Here we test that the two methods return the exact same value,
    see:
    https://github.com/giampaolo/psutil/issues/304
    """

    fun_names = [
        # function name, tolerance
        ('proc_cpu_times', 0.2),
        ('proc_create_time', 0.5),
        ('proc_num_handles', 1),  # 1 because impl #1 opens a handle
        ('proc_memory_info', 1024),  # KB
        ('proc_io_counters', 0),
    ]

    def test_compare_values(self):
        def assert_ge_0(obj):
            if isinstance(obj, tuple):
                for value in obj:
                    self.assertGreaterEqual(value, 0, msg=obj)
            elif isinstance(obj, (int, long, float)):
                self.assertGreaterEqual(obj, 0)
            else:
                assert 0  # case not handled which needs to be fixed

        def compare_with_tolerance(ret1, ret2, tolerance):
            if ret1 == ret2:
                return
            else:
                if isinstance(ret2, (int, long, float)):
                    diff = abs(ret1 - ret2)
                    self.assertLessEqual(diff, tolerance)
                elif isinstance(ret2, tuple):
                    for a, b in zip(ret1, ret2):
                        diff = abs(a - b)
                        self.assertLessEqual(diff, tolerance)

        from psutil._pswindows import ntpinfo
        failures = []
        for p in psutil.process_iter():
            try:
                nt = ntpinfo(*cext.proc_info(p.pid))
            except psutil.NoSuchProcess:
                continue
            assert_ge_0(nt)

            for name, tolerance in self.fun_names:
                if name == 'proc_memory_info' and p.pid == os.getpid():
                    continue
                if name == 'proc_create_time' and p.pid in (0, 4):
                    continue
                meth = wrap_exceptions(getattr(cext, name))
                try:
                    ret = meth(p.pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                # compare values
                try:
                    if name == 'proc_cpu_times':
                        compare_with_tolerance(ret[0], nt.user_time, tolerance)
                        compare_with_tolerance(ret[1],
                                               nt.kernel_time, tolerance)
                    elif name == 'proc_create_time':
                        compare_with_tolerance(ret, nt.create_time, tolerance)
                    elif name == 'proc_num_handles':
                        compare_with_tolerance(ret, nt.num_handles, tolerance)
                    elif name == 'proc_io_counters':
                        compare_with_tolerance(ret[0], nt.io_rcount, tolerance)
                        compare_with_tolerance(ret[1], nt.io_wcount, tolerance)
                        compare_with_tolerance(ret[2], nt.io_rbytes, tolerance)
                        compare_with_tolerance(ret[3], nt.io_wbytes, tolerance)
                    elif name == 'proc_memory_info':
                        try:
                            rawtupl = cext.proc_memory_info_2(p.pid)
                        except psutil.NoSuchProcess:
                            continue
                        compare_with_tolerance(ret, rawtupl, tolerance)
                except AssertionError:
                    trace = traceback.format_exc()
                    msg = '%s\npid=%s, method=%r, ret_1=%r, ret_2=%r' % (
                        trace, p.pid, name, ret, nt)
                    failures.append(msg)
                    break

        if failures:
            self.fail('\n\n'.join(failures))

    # ---
    # same tests as above but mimicks the AccessDenied failure of
    # the first (fast) method failing with AD.
    # TODO: currently does not take tolerance into account.

    def test_name(self):
        name = psutil.Process().name()
        with mock.patch("psutil._psplatform.cext.proc_exe",
                        side_effect=psutil.AccessDenied(os.getpid())) as fun:
            psutil.Process().name() == name
            assert fun.called

    def test_memory_info(self):
        mem = psutil.Process().memory_info()
        with mock.patch("psutil._psplatform.cext.proc_memory_info",
                        side_effect=OSError(errno.EPERM, "msg")) as fun:
            psutil.Process().memory_info() == mem
            assert fun.called

    def test_create_time(self):
        ctime = psutil.Process().create_time()
        with mock.patch("psutil._psplatform.cext.proc_create_time",
                        side_effect=OSError(errno.EPERM, "msg")) as fun:
            psutil.Process().create_time() == ctime
            assert fun.called

    def test_cpu_times(self):
        cpu_times = psutil.Process().cpu_times()
        with mock.patch("psutil._psplatform.cext.proc_cpu_times",
                        side_effect=OSError(errno.EPERM, "msg")) as fun:
            psutil.Process().cpu_times() == cpu_times
            assert fun.called

    def test_io_counters(self):
        io_counters = psutil.Process().io_counters()
        with mock.patch("psutil._psplatform.cext.proc_io_counters",
                        side_effect=OSError(errno.EPERM, "msg")) as fun:
            psutil.Process().io_counters() == io_counters
            assert fun.called

    def test_num_handles(self):
        io_counters = psutil.Process().io_counters()
        with mock.patch("psutil._psplatform.cext.proc_io_counters",
                        side_effect=OSError(errno.EPERM, "msg")) as fun:
            psutil.Process().io_counters() == io_counters
            assert fun.called

    # --- other tests

    def test_compare_name_exe(self):
        for p in psutil.process_iter():
            try:
                a = os.path.basename(p.exe())
                b = p.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            else:
                self.assertEqual(a, b)

    def test_zombies(self):
        # test that NPS is raised by the 2nd implementation in case a
        # process no longer exists
        ZOMBIE_PID = max(psutil.pids()) + 5000
        for name, _ in self.fun_names:
            meth = wrap_exceptions(getattr(cext, name))
            self.assertRaises(psutil.NoSuchProcess, meth, ZOMBIE_PID)


@unittest.skipUnless(WINDOWS, "not a Windows system")
class RemoteProcessTestCase(unittest.TestCase):
    """Certain functions require calling ReadProcessMemory.  This trivially
    works when called on the current process.  Check that this works on other
    processes, especially when they have a different bitness."""

    @staticmethod
    def find_other_interpreter():
        # find a python interpreter that is of the opposite bitness from us
        code = "import sys; sys.stdout.write(str(sys.maxsize > 2**32))"

        # XXX: a different and probably more stable approach might be to access
        # the registry but accessing 64 bit paths from a 32 bit process
        for filename in glob.glob(r"C:\Python*\python.exe"):
            proc = subprocess.Popen(args=[filename, "-c", code],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT)
            output, _ = proc.communicate()
            if output == str(not IS_64_BIT):
                return filename

    @classmethod
    def setUpClass(cls):
        other_python = cls.find_other_interpreter()

        if other_python is None:
            raise unittest.SkipTest(
                "could not find interpreter with opposite bitness")

        if IS_64_BIT:
            cls.python64 = sys.executable
            cls.python32 = other_python
        else:
            cls.python64 = other_python
            cls.python32 = sys.executable

    test_args = ["-c", "import sys; sys.stdin.read()"]

    def setUp(self):
        env = os.environ.copy()
        env["THINK_OF_A_NUMBER"] = str(os.getpid())
        self.proc32 = get_test_subprocess([self.python32] + self.test_args,
                                          env=env,
                                          stdin=subprocess.PIPE)
        self.proc64 = get_test_subprocess([self.python64] + self.test_args,
                                          env=env,
                                          stdin=subprocess.PIPE)

    def tearDown(self):
        self.proc32.communicate()
        self.proc64.communicate()
        reap_children()

    @classmethod
    def tearDownClass(cls):
        reap_children()

    def test_cmdline_32(self):
        p = psutil.Process(self.proc32.pid)
        self.assertEqual(len(p.cmdline()), 3)
        self.assertEqual(p.cmdline()[1:], self.test_args)

    def test_cmdline_64(self):
        p = psutil.Process(self.proc64.pid)
        self.assertEqual(len(p.cmdline()), 3)
        self.assertEqual(p.cmdline()[1:], self.test_args)

    def test_cwd_32(self):
        p = psutil.Process(self.proc32.pid)
        self.assertEqual(p.cwd(), os.getcwd())

    def test_cwd_64(self):
        p = psutil.Process(self.proc64.pid)
        self.assertEqual(p.cwd(), os.getcwd())

    def test_environ_32(self):
        p = psutil.Process(self.proc32.pid)
        e = p.environ()
        self.assertIn("THINK_OF_A_NUMBER", e)
        self.assertEquals(e["THINK_OF_A_NUMBER"], str(os.getpid()))

    def test_environ_64(self):
        p = psutil.Process(self.proc64.pid)
        e = p.environ()
        self.assertIn("THINK_OF_A_NUMBER", e)
        self.assertEquals(e["THINK_OF_A_NUMBER"], str(os.getpid()))


@unittest.skipUnless(WINDOWS, "not a Windows system")
class TestServices(unittest.TestCase):

    def test_win_service_iter(self):
        valid_statuses = set([
            "running",
            "paused",
            "start",
            "pause",
            "continue",
            "stop",
            "stopped",
        ])
        valid_start_types = set([
            "automatic",
            "manual",
            "disabled",
        ])
        valid_statuses = set([
            "running",
            "paused",
            "start_pending",
            "pause_pending",
            "continue_pending",
            "stop_pending",
            "stopped"
        ])
        for serv in psutil.win_service_iter():
            data = serv.as_dict()
            self.assertIsInstance(data['name'], basestring)
            self.assertNotEqual(data['name'].strip(), "")
            self.assertIsInstance(data['display_name'], basestring)
            self.assertIsInstance(data['username'], basestring)
            self.assertIn(data['status'], valid_statuses)
            if data['pid'] is not None:
                psutil.Process(data['pid'])
            self.assertIsInstance(data['binpath'], basestring)
            self.assertIsInstance(data['username'], basestring)
            self.assertIsInstance(data['start_type'], basestring)
            self.assertIn(data['start_type'], valid_start_types)
            self.assertIn(data['status'], valid_statuses)
            self.assertIsInstance(data['description'], basestring)
            pid = serv.pid()
            if pid is not None:
                p = psutil.Process(pid)
                self.assertTrue(p.is_running())
            # win_service_get
            s = psutil.win_service_get(serv.name())
            # test __eq__
            self.assertEqual(serv, s)

    def test_win_service_get(self):
        name = next(psutil.win_service_iter()).name()

        with self.assertRaises(psutil.NoSuchProcess) as cm:
            psutil.win_service_get(name + '???')
        self.assertEqual(cm.exception.name, name + '???')

        # test NoSuchProcess
        service = psutil.win_service_get(name)
        exc = WindowsError(
            psutil._psplatform.cext.ERROR_SERVICE_DOES_NOT_EXIST, "")
        with mock.patch("psutil._psplatform.cext.winservice_query_status",
                        side_effect=exc):
            self.assertRaises(psutil.NoSuchProcess, service.status)
        with mock.patch("psutil._psplatform.cext.winservice_query_config",
                        side_effect=exc):
            self.assertRaises(psutil.NoSuchProcess, service.username)

        # test AccessDenied
        exc = WindowsError(
            psutil._psplatform.cext.ERROR_ACCESS_DENIED, "")
        with mock.patch("psutil._psplatform.cext.winservice_query_status",
                        side_effect=exc):
            self.assertRaises(psutil.AccessDenied, service.status)
        with mock.patch("psutil._psplatform.cext.winservice_query_config",
                        side_effect=exc):
            self.assertRaises(psutil.AccessDenied, service.username)

        # test __str__ and __repr__
        self.assertIn(service.name(), str(service))
        self.assertIn(service.display_name(), str(service))
        self.assertIn(service.name(), repr(service))
        self.assertIn(service.display_name(), repr(service))


if __name__ == '__main__':
    run_test_module_by_name(__file__)
