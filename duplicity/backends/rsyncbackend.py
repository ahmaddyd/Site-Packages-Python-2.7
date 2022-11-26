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

from __future__ import print_function
from builtins import map
import os
import re
import tempfile

import duplicity.backend
from duplicity.errors import InvalidBackendURL
from duplicity import config, tempdir, util


class RsyncBackend(duplicity.backend.Backend):
    u"""Connect to remote store using rsync

    rsync backend contributed by Sebastian Wilhelmi <seppi@seppi.de>
    rsyncd auth, alternate port support
        Copyright 2010 by Edgar Soldin <edgar.soldin@web.de>

    """
    def __init__(self, parsed_url):
        u"""rsyncBackend initializer"""
        duplicity.backend.Backend.__init__(self, parsed_url)
        u"""
        rsyncd module url: rsync://[user:password@]host[:port]::[/]modname/path
                      Note: 3.0.7 is picky about syntax use either 'rsync://' or '::'
                      cmd: rsync [--port=port] host::modname/path
        -or-
        rsync via ssh/rsh url: rsync://user@host[:port]://some_absolute_path
             -or-              rsync://user@host[:port]:/some_relative_path
                          cmd: rsync -e 'ssh [-p=port]' [user@]host:[/]path
        """
        host = parsed_url.hostname
        port = u""
        # RSYNC_RSH from calling shell might conflict with our settings
        if u'RSYNC_RSH' in os.environ:
            del os.environ[u'RSYNC_RSH']
        if self.over_rsyncd():
            # its a module path
            (path, port) = self.get_rsync_path()
            self.url_string = u"%s::%s" % (host, path.lstrip(u'/:'))
            if port:
                port = u" --port=%s" % port
        else:
            host_string = host + u":" if host else u""
            if parsed_url.path.startswith(u"//"):
                # its an absolute path
                self.url_string = u"%s/%s" % (host_string, parsed_url.path.lstrip(u'/'))
            else:
                # its a relative path
                self.url_string = u"%s%s" % (host_string, parsed_url.path.lstrip(u'/'))
            if parsed_url.port:
                port = u"-p %s" % parsed_url.port
        # add trailing slash if missing
        if self.url_string[-1] != u'/':
            self.url_string += u'/'
        # user?
        if parsed_url.username:
            if self.over_rsyncd():
                os.environ[u'USER'] = parsed_url.username
            else:
                self.url_string = parsed_url.username + u"@" + self.url_string
        # password?, don't ask if none was given
        self.use_getpass = False
        password = self.get_password()
        if password:
            os.environ[u'RSYNC_PASSWORD'] = password
        if self.over_rsyncd():
            portOption = port
        else:
            portOption = u"-e 'ssh %s -oBatchMode=yes %s'" % (port, config.ssh_options)
        rsyncOptions = config.rsync_options
        # build cmd
        self.cmd = u"rsync %s %s" % (portOption, rsyncOptions)

    def over_rsyncd(self):
        url = self.parsed_url.url_string
        if re.search(u'::[^:]*$', url):
            return True
        else:
            return False

    def get_rsync_path(self):
        url = self.parsed_url.url_string
        m = re.search(r"(:\d+|)?::([^:]*)$", url)
        if m:
            return m.group(2), m.group(1).lstrip(u':')
        raise InvalidBackendURL(u"Could not determine rsync path: %s"
                                u"" % self.munge_password(url))

    def _put(self, source_path, remote_filename):
        remote_filename = util.fsdecode(remote_filename)
        remote_path = os.path.join(self.url_string, remote_filename)
        commandline = u"%s %s %s" % (self.cmd, source_path.uc_name, remote_path)
        self.subprocess_popen(commandline)

    def _get(self, remote_filename, local_path):
        remote_filename = util.fsdecode(remote_filename)
        remote_path = os.path.join(self.url_string, remote_filename)
        commandline = u"%s %s %s" % (self.cmd, remote_path, local_path.uc_name)
        self.subprocess_popen(commandline)

    def _list(self):
        def split(str):  # pylint: disable=redefined-builtin
            line = str.split()
            if len(line) > 4 and line[4] != u'.':
                return line[4]
            else:
                return None
        commandline = u"%s %s" % (self.cmd, self.url_string)
        result, stdout, stderr = self.subprocess_popen(commandline)
        return [util.fsencode(x) for x in map(split, stdout.split(u'\n')) if x]

    def _delete_list(self, filename_list):
        delete_list = filename_list
        dont_delete_list = []
        for file in self._list():
            if file in delete_list:
                delete_list.remove(file)
            else:
                dont_delete_list.append(file)

        dir = tempfile.mkdtemp()  # pylint: disable=redefined-builtin
        exclude, exclude_name = tempdir.default().mkstemp_file()
        to_delete = [exclude_name]
        for file in dont_delete_list:
            file = util.fsdecode(file)
            path = os.path.join(dir, file)
            to_delete.append(path)
            try:
                f = open(path, u'w')
            except IsADirectoryError:
                print(file, file=exclude)
                continue
            print(file, file=exclude)
            f.close()
        exclude.close()
        commandline = (u"%s --recursive --delete --exclude-from=%s %s/ %s" %
                       (self.cmd, exclude_name, dir, self.url_string))
        self.subprocess_popen(commandline)
        for file in to_delete:
            try:
                util.ignore_missing(os.unlink, file)
            except IsADirectoryError:
                pass
        os.rmdir(dir)


duplicity.backend.register_backend(u"rsync", RsyncBackend)
duplicity.backend.uses_netloc.extend([u'rsync'])
