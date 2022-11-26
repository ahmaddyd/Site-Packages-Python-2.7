# -*- Mode:Python; indent-tabs-mode:nil; tab-width:4; encoding:utf8 -*-
#
# Copyright 2017 Tomas Vondra (Launchpad id: tomas-v)
# Copyright 2017 Kenneth Loafman <kenneth@loafman.com>
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
from future import standard_library
standard_library.install_aliases()

from duplicity import util
from duplicity.errors import BackendException
import duplicity.backend

import os
import subprocess


class MegaBackend(duplicity.backend.Backend):
    u"""Connect to remote store using Mega.co.nz API"""

    def __init__(self, parsed_url):
        duplicity.backend.Backend.__init__(self, parsed_url)

        # ensure all the necessary megatools binaries exist
        self._check_binary_exists(u'megals')
        self._check_binary_exists(u'megamkdir')
        self._check_binary_exists(u'megaget')
        self._check_binary_exists(u'megaput')
        self._check_binary_exists(u'megarm')

        # store some basic info
        self._hostname = parsed_url.hostname

        if parsed_url.password is None:
            self._megarc = os.getenv(u'HOME') + u'/.megarc'
        else:
            self._megarc = False
            self._username = parsed_url.username
            self._password = self.get_password()

        # remote folder (Can we assume /Root prefix?)
        self._root = u'/Root'
        self._folder = self._root + u'/' + parsed_url.path[1:]

        # make sure the remote folder exists (the whole path)
        self._makedir_recursive(parsed_url.path[1:].split(u'/'))

    def _check_binary_exists(self, cmd):
        u'checks that a specified command exists in the current path'

        try:
            # ignore the output, we only need the return code
            subprocess.check_output([u'which', cmd])
        except Exception as e:
            raise BackendException(u"command '%s' not found, make sure megatools are installed" % (cmd,))

    def _makedir(self, path):
        u'creates a remote directory'

        if self._megarc:
            cmd = [u'megamkdir', u'--config', self._megarc, path]
        else:
            cmd = [u'megamkdir', u'-u', self._username, u'-p', self._password, path]

        self.subprocess_popen(cmd)

    def _makedir_recursive(self, path):
        u'creates a remote directory (recursively the whole path), ingores errors'

        print(u"mkdir: %s" % (u'/'.join(path),))

        p = self._root

        for folder in path:
            p = p + u'/' + folder
            try:
                self._makedir(p)
            except:
                pass

    def _put(self, source_path, remote_filename):
        u'uploads file to Mega (deletes it first, to ensure it does not exist)'

        try:
            self.delete(util.fsdecode(remote_filename))
        except Exception:
            pass

        self.upload(local_file=util.fsdecode(source_path.get_canonical()),
                    remote_file=util.fsdecode(remote_filename))

    def _get(self, remote_filename, local_path):
        u'downloads file from Mega'

        self.download(remote_file=util.fsdecode(remote_filename),
                      local_file=util.fsdecode(local_path.name))

    def _list(self):
        u'list files in the backup folder'

        return self.folder_contents(files_only=True)

    def _delete(self, filename):
        u'deletes remote '

        self.delete(remote_file=util.fsdecode(filename))

    def folder_contents(self, files_only=False):
        u'lists contents of a folder, optionally ignoring subdirectories'

        print(u"megals: %s" % (self._folder,))

        if self._megarc:
            cmd = [u'megals', u'--config', self._megarc, self._folder]
        else:
            cmd = [u'megals', u'-u', self._username, u'-p', self._password, self._folder]

        files = subprocess.check_output(cmd)
        files = util.fsdecode(files.strip()).split(u'\n')

        # remove the folder name, including the path separator
        files = [f[len(self._folder) + 1:] for f in files]

        # optionally ignore entries containing path separator (i.e. not files)
        if files_only:
            files = [f for f in files if u'/' not in f]

        return [util.fsencode(f) for f in files]

    def download(self, remote_file, local_file):

        print(u"megaget: %s" % (remote_file,))

        if self._megarc:
            cmd = [u'megaget', u'--config', self._megarc, u'--no-progress',
                   u'--path', local_file, self._folder + u'/' + remote_file]
        else:
            cmd = [u'megaget', u'-u', self._username, u'-p', self._password, u'--no-progress',
                   u'--path', local_file, self._folder + u'/' + remote_file]

        self.subprocess_popen(cmd)

    def upload(self, local_file, remote_file):

        print(u"megaput: %s" % (remote_file,))

        if self._megarc:
            cmd = [u'megaput', u'--config', self._megarc, u'--no-progress',
                   u'--path', self._folder + u'/' + remote_file, local_file]
        else:
            cmd = [u'megaput', u'-u', self._username, u'-p', self._password, u'--no-progress',
                   u'--path', self._folder + u'/' + remote_file, local_file]

        try:
            self.subprocess_popen(cmd)
        except Exception as e:
            error_str = str(e)
            if u"EOVERQUOTA" in error_str:
                raise BackendException(u"MEGA account over quota, could not write file : '%s' . "
                                       u"Upgrade your storage at https://mega.nz/pro or remove some data." %
                                       (remote_file,))
            else:
                raise BackendException(u"Failed writing file '%s' to MEGA , reason : '%s'" % (remote_file, e))

    def delete(self, remote_file):

        print(u"megarm: %s" % (remote_file,))

        if self._megarc:
            cmd = [u'megarm', u'--config', self._megarc, self._folder + u'/' + remote_file]
        else:
            cmd = [u'megarm', u'-u', self._username, u'-p', self._password, self._folder + u'/' + remote_file]

        self.subprocess_popen(cmd)


duplicity.backend.register_backend(u'mega', MegaBackend)
duplicity.backend.uses_netloc.extend([u'mega'])
