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

from builtins import range
import os
import duplicity.backend
from duplicity import util

hsi_command = u"hsi"


class HSIBackend(duplicity.backend.Backend):
    def __init__(self, parsed_url):
        duplicity.backend.Backend.__init__(self, parsed_url)
        self.host_string = parsed_url.hostname
        self.remote_dir = parsed_url.path
        if self.remote_dir:
            self.remote_prefix = self.remote_dir + u"/"
        else:
            self.remote_prefix = u""

    def _put(self, source_path, remote_filename):
        if isinstance(remote_filename, b"".__class__):
            remote_filename = util.fsdecode(remote_filename)
        commandline = u'%s "put %s : %s%s"' % (hsi_command, source_path.uc_name, self.remote_prefix, remote_filename)
        self.subprocess_popen(commandline)

    def _get(self, remote_filename, local_path):
        if isinstance(remote_filename, b"".__class__):
            remote_filename = util.fsdecode(remote_filename)
        commandline = u'%s "get %s : %s%s"' % (hsi_command, local_path.uc_name, self.remote_prefix, remote_filename)
        self.subprocess_popen(commandline)

    def _list(self):
        commandline = u'%s "ls -l %s"' % (hsi_command, self.remote_dir)
        l = self.subprocess_popen(commandline)[2]
        l = l.split(os.linesep.encode())[3:]
        for i in range(0, len(l)):
            if l[i]:
                l[i] = l[i].split()[-1]
        return [util.fsencode(x) for x in l if x]

    def _delete(self, filename):
        if isinstance(filename, b"".__class__):
            filename = util.fsdecode(filename)
        commandline = u'%s "rm %s%s"' % (hsi_command, self.remote_prefix, filename)
        self.subprocess_popen(commandline)


duplicity.backend.register_backend(u"hsi", HSIBackend)
duplicity.backend.uses_netloc.extend([u'hsi'])
