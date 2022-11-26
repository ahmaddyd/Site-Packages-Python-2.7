# -*- Mode:Python; indent-tabs-mode:nil; tab-width:4; encoding:utf8 -*-
#
# Copyright 2014 Andrea Grandi <a.grandi@gmail.com>
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

import os.path
import duplicity.backend
import duplicity.util


class SXBackend(duplicity.backend.Backend):
    u"""Connect to remote store using Skylable Protocol"""
    def __init__(self, parsed_url):
        duplicity.backend.Backend.__init__(self, parsed_url)
        self.url_string = parsed_url.url_string

    def _put(self, source_path, remote_filename):
        remote_filename = util.fsdecode(remote_filename)
        remote_path = os.path.join(self.url_string, remote_filename)
        commandline = u"sxcp {0} {1}".format(source_path.uc_name, remote_path)
        self.subprocess_popen(commandline)

    def _get(self, remote_filename, local_path):
        remote_filename = util.fsdecode(remote_filename)
        remote_path = os.path.join(self.url_string, remote_filename)
        commandline = u"sxcp {0} {1}".format(remote_path, local_path.uc_name)
        self.subprocess_popen(commandline)

    def _list(self):
        # Do a long listing to avoid connection reset
        commandline = u"sxls {0}/".format(self.url_string)
        _, l, _ = self.subprocess_popen(commandline)
        # Look for our files as the last element of a long list line
        return [util.fsencode(x[x.rindex(u'/') + 1:].split()[-1]) for x in l.split(u'\n')
                if x and not x.startswith(u"total ")]

    def _delete(self, filename):
        commandline = u"sxrm {0}/{1}".format(self.url_string, filename)
        self.subprocess_popen(commandline)


duplicity.backend.register_backend(u"sx", SXBackend)
