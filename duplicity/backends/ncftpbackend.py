# -*- Mode:Python; indent-tabs-mode:nil; tab-width:4; encoding:utf8 -*-
#
# Copyright 2002 Ben Escoto <ben@emerose.org>
# Copyright 2007 Kenneth Loafman <kenneth@loafman.com>
#
# This file is part of duplicity.
#
# Duplicity is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.
#
# Duplicity is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with duplicity; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

from future import standard_library
standard_library.install_aliases()
import os.path
import urllib.request  # pylint: disable=import-error
import urllib.parse  # pylint: disable=import-error
import urllib.error  # pylint: disable=import-error
import re

import duplicity.backend
from duplicity import config
from duplicity import log
from duplicity import tempdir
from duplicity import util


class NCFTPBackend(duplicity.backend.Backend):
    u"""Connect to remote store using File Transfer Protocol"""
    def __init__(self, parsed_url):
        duplicity.backend.Backend.__init__(self, parsed_url)

        # we expect an error return, so go low-level and ignore it
        try:
            p = os.popen(u"ncftpls -v")
            fout = p.read()
            ret = p.close()
        except Exception:
            pass
        # the expected error is 8 in the high-byte and some output
        if ret != 0x0800 or not fout:
            log.FatalError(u"NcFTP not found:  Please install NcFTP version 3.1.9 or later",
                           log.ErrorCode.ftp_ncftp_missing)

        # version is the second word of the first line
        version = fout.split(u'\n')[0].split()[1]
        if version < u"3.1.9":
            log.FatalError(u"NcFTP too old:  Duplicity requires NcFTP version 3.1.9,"
                           u"3.2.1 or later.  Version 3.2.0 will not work properly.",
                           log.ErrorCode.ftp_ncftp_too_old)
        elif version == u"3.2.0":
            log.Warn(u"NcFTP (ncftpput) version 3.2.0 may fail with duplicity.\n"
                     u"see: http://www.ncftpd.com/ncftp/doc/changelog.html\n"
                     u"If you have trouble, please upgrade to 3.2.1 or later",
                     log.WarningCode.ftp_ncftp_v320)
        log.Notice(u"NcFTP version is %s" % version)

        self.parsed_url = parsed_url

        self.url_string = duplicity.backend.strip_auth_from_url(self.parsed_url)

        # strip ncftp+ prefix
        self.url_string = duplicity.backend.strip_prefix(self.url_string, u'ncftp')

        # This squelches the "file not found" result from ncftpls when
        # the ftp backend looks for a collection that does not exist.
        # version 3.2.2 has error code 5, 1280 is some legacy value
        self.popen_breaks[u'ncftpls'] = [5, 1280]

        # Use an explicit directory name.
        if self.url_string[-1] != u'/':
            self.url_string += u'/'

        self.password = self.get_password()

        if config.ftp_connection == u'regular':
            self.conn_opt = u'-E'
        else:
            self.conn_opt = u'-F'

        self.tempfd, self.tempname = tempdir.default().mkstemp()
        self.tempfile = os.fdopen(self.tempfd, u"w")
        self.tempfile.write(u"host %s\n" % self.parsed_url.hostname)
        self.tempfile.write(u"user %s\n" % self.parsed_url.username)
        self.tempfile.write(u"pass %s\n" % self.password)
        self.tempfile.close()
        self.flags = u"-f %s %s -t %s -o useCLNT=0,useHELP_SITE=0 " % \
            (self.tempname, self.conn_opt, config.timeout)
        if parsed_url.port is not None and parsed_url.port != 21:
            self.flags += u" -P '%s'" % (parsed_url.port)

    def _put(self, source_path, remote_filename):
        remote_filename = util.fsdecode(remote_filename)
        remote_path = os.path.join(urllib.parse.unquote(re.sub(u'^/', u'', self.parsed_url.path)),
                                   remote_filename).rstrip()
        commandline = u"ncftpput %s -m -V -C '%s' '%s'" % \
            (self.flags, source_path.uc_name, remote_path)
        self.subprocess_popen(commandline)

    def _get(self, remote_filename, local_path):
        remote_filename = util.fsdecode(remote_filename)
        remote_path = os.path.join(urllib.parse.unquote(re.sub(u'^/', u'', self.parsed_url.path)),
                                   remote_filename).rstrip()
        commandline = u"ncftpget %s -V -C '%s' '%s' '%s'" % \
            (self.flags, self.parsed_url.hostname, remote_path.lstrip(u'/'), local_path.uc_name)
        self.subprocess_popen(commandline)

    def _list(self):
        # Do a long listing to avoid connection reset
        commandline = u"ncftpls %s -l '%s'" % (self.flags, self.url_string)
        _, l, _ = self.subprocess_popen(commandline)
        # Look for our files as the last element of a long list line
        return [util.fsencode(x.split()[-1]) for x in l.split(u'\n') if x and not x.startswith(u"total ")]

    def _delete(self, filename):
        commandline = u"ncftpls %s -l -X 'DELE %s' '%s'" % \
            (self.flags, filename, self.url_string)
        self.subprocess_popen(commandline)


duplicity.backend.register_backend(u"ncftp+ftp", NCFTPBackend)
duplicity.backend.uses_netloc.extend([u'ncftp+ftp'])
