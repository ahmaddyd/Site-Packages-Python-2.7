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

import os

import duplicity.backend
from duplicity import path, progress
from duplicity.errors import BackendException


class LocalBackend(duplicity.backend.Backend):
    u"""Use this backend when saving to local disk

    Urls look like file://testfiles/output.  Relative to root can be
    gotten with extra slash (file:///usr/local).

    """
    def __init__(self, parsed_url):
        duplicity.backend.Backend.__init__(self, parsed_url)
        # The URL form "file:MyFile" is not a valid duplicity target.
        if not parsed_url.path.startswith(u'//'):
            raise BackendException(u"Bad file:// path syntax.")
        self.remote_pathdir = path.Path(parsed_url.path[2:])
        try:
            os.makedirs(self.remote_pathdir.base)
        except Exception:
            pass

    def _move(self, source_path, remote_filename):
        target_path = self.remote_pathdir.append(remote_filename)
        try:
            source_path.rename(target_path)
            return True
        except OSError:
            return False

    def _put(self, source_path, remote_filename):
        target_path = self.remote_pathdir.append(remote_filename)
        source_path.setdata()
        source_size = source_path.getsize()
        progress.report_transfer(0, source_size)
        target_path.writefileobj(source_path.open(u"rb"))
        progress.report_transfer(source_size, source_size)

    def _get(self, filename, local_path):
        source_path = self.remote_pathdir.append(filename)
        local_path.writefileobj(source_path.open(u"rb"))

    def _list(self):
        return self.remote_pathdir.listdir()

    def _delete(self, filename):
        self.remote_pathdir.append(filename).delete()

    def _query(self, filename):
        target_file = self.remote_pathdir.append(filename)
        target_file.setdata()
        size = target_file.getsize() if target_file.exists() else -1
        return {u'size': size}


duplicity.backend.register_backend(u"file", LocalBackend)
