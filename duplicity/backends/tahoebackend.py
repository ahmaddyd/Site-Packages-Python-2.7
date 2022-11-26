# -*- Mode:Python; indent-tabs-mode:nil; tab-width:4; encoding:utf8 -*-
#
# Copyright 2008 Francois Deppierraz
#
# This file is part of duplicity.
#
# Duplicity is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 3 of the License, or (at your
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

from duplicity import log
from duplicity import util
import duplicity.backend


class TAHOEBackend(duplicity.backend.Backend):
    u"""
    Backend for the Tahoe file system
    """

    def __init__(self, parsed_url):
        duplicity.backend.Backend.__init__(self, parsed_url)

        url = parsed_url.path.strip(u'/').split(u'/')

        self.alias = url[0]

        if len(url) > 1:
            self.directory = u"/".join(url[1:])
        else:
            self.directory = u""

        log.Debug(u"tahoe: %s -> %s:%s" % (url, self.alias, self.directory))

    def get_remote_path(self, filename=None):
        if filename is None:
            if self.directory != u"":
                return u"%s:%s" % (self.alias, self.directory)
            else:
                return u"%s:" % self.alias

        if isinstance(filename, b"".__class__):
            filename = util.fsdecode(filename)
        if self.directory != u"":
            return u"%s:%s/%s" % (self.alias, self.directory, filename)
        else:
            return u"%s:%s" % (self.alias, filename)

    def run(self, *args):
        cmd = u" ".join(args)
        _, output, _ = self.subprocess_popen(cmd)
        return output

    def _put(self, source_path, remote_filename):
        self.run(u"tahoe", u"cp", source_path.uc_name, self.get_remote_path(remote_filename))

    def _get(self, remote_filename, local_path):
        self.run(u"tahoe", u"cp", self.get_remote_path(remote_filename), local_path.uc_name)

    def _list(self):
        output = self.run(u"tahoe", u"ls", self.get_remote_path())
        return [util.fsencode(x) for x in output.split(u'\n') if x]

    def _delete(self, filename):
        self.run(u"tahoe", u"rm", self.get_remote_path(filename))


duplicity.backend.register_backend(u"tahoe", TAHOEBackend)
