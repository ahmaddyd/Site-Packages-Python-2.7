# -*- Mode:Python; indent-tabs-mode:nil; tab-width:4; encoding:utf8 -*-
#
# Copyright 2019 Francesco Magno
# Copyright 2019 Kenneth Loafman <kenneth@loafman.com>
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

import os
import os.path

from duplicity import log
from duplicity import util
from duplicity.errors import BackendException
import duplicity.backend


class RcloneBackend(duplicity.backend.Backend):

    def __init__(self, parsed_url):
        duplicity.backend.Backend.__init__(self, parsed_url)
        self.parsed_url = parsed_url
        self.remote_path = self.parsed_url.path
        self.rclone_cmd = u"rclone"

        try:
            rc, o, e = self._subprocess_safe_popen(self.rclone_cmd + u" version")
        except Exception:
            log.FatalError(u"rclone not found: please install rclone", log.ErrorCode.backend_error)

        verb = log.getverbosity()
        if verb >= log.DEBUG:
            os.environ[u"RCLONE_LOG_LEVEL"] = u"DEBUG"
        elif verb >= log.INFO:
            os.environ[u"RCLONE_LOG_LEVEL"] = u"INFO"
        elif verb >= log.NOTICE:
            os.environ[u"RCLONE_LOG_LEVEL"] = u"NOTICE"
        elif verb >= log.ERROR:
            os.environ[u"RCLONE_LOG_LEVEL"] = u"ERROR"

        if parsed_url.path.startswith(u"//"):
            self.remote_path = self.remote_path[2:].replace(u":/", u":", 1)

        self.remote_path = util.fsdecode(self.remote_path)

    def _get(self, remote_filename, local_path):
        remote_filename = util.fsdecode(remote_filename)
        local_pathname = util.fsdecode(local_path.name)
        commandline = u"%s copyto %s/%s %s" % (
            self.rclone_cmd, self.remote_path, remote_filename, local_pathname)
        rc, o, e = self._subprocess_safe_popen(commandline)
        if rc != 0:
            if os.path.isfile(local_pathname):
                os.remove(local_pathname)
            raise BackendException(e)

    def _put(self, source_path, remote_filename):
        source_pathname = util.fsdecode(source_path.name)
        remote_filename = util.fsdecode(remote_filename)
        commandline = u"%s copyto %s %s/%s" % (
            self.rclone_cmd, source_pathname, self.remote_path, remote_filename)
        rc, o, e = self._subprocess_safe_popen(commandline)
        if rc != 0:
            raise BackendException(e)

    def _list(self):
        filelist = []
        commandline = u"%s lsf %s" % (
            self.rclone_cmd, self.remote_path)
        rc, o, e = self._subprocess_safe_popen(commandline)
        if rc == 3:
            return filelist
        if rc != 0:
            raise BackendException(e)
        if not o:
            return filelist
        return [util.fsencode(x) for x in o.split(u'\n') if x]

    def _delete(self, remote_filename):
        remote_filename = util.fsdecode(remote_filename)
        commandline = u"%s deletefile --drive-use-trash=false %s/%s" % (
            self.rclone_cmd, self.remote_path, remote_filename)
        rc, o, e = self._subprocess_safe_popen(commandline)
        if rc != 0:
            raise BackendException(e)

    def _subprocess_safe_popen(self, commandline):
        import shlex
        from subprocess import Popen, PIPE
        args = shlex.split(commandline)
        p = Popen(args, stdout=PIPE, stderr=PIPE, universal_newlines=True)
        stdout, stderr = p.communicate()
        for l in stderr.split(u'\n'):
            if len(l) > 1:
                print(l)
        return p.returncode, stdout, stderr


duplicity.backend.register_backend(u"rclone", RcloneBackend)
