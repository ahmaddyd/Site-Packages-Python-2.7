# -*- Mode:Python; indent-tabs-mode:nil; tab-width:4; encoding:utf8 -*-
#
# Copyright 2020 Jose L. Domingo Lopez <github@24x7linux.com>
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
import re


class Megav2Backend(duplicity.backend.Backend):
    u""" Backend for MEGA.nz cloud storage, only one that works for accounts created since Nov. 2018
         See https://github.com/megous/megatools/issues/411 for more details

         This MEGA backend resorts to official tools (MEGAcmd) as available at https://mega.nz/cmd
         MEGAcmd works through a single binary called "mega-cmd", which talks to a backend server
         "mega-cmd-server", which keeps state (for example, persisting a session). Multiple "mega-*"
         shell wrappers (ie. "mega-ls") exist as the user interface to "mega-cmd" and MEGA API
         The full MEGAcmd User Guide can be found in the software's GitHub page below :
         https://github.com/meganz/MEGAcmd/blob/master/UserGuide.md """

    def __init__(self, parsed_url):
        duplicity.backend.Backend.__init__(self, parsed_url)

        # Sanity check : ensure all the necessary "MEGAcmd" binaries exist
        self._check_binary_exists(u'mega-login')
        self._check_binary_exists(u'mega-logout')
        self._check_binary_exists(u'mega-cmd')
        self._check_binary_exists(u'mega-cmd-server')
        self._check_binary_exists(u'mega-ls')
        self._check_binary_exists(u'mega-mkdir')
        self._check_binary_exists(u'mega-get')
        self._check_binary_exists(u'mega-put')
        self._check_binary_exists(u'mega-rm')

        # "MEGAcmd" does not use a config file, however it is handy to keep one (with the old ".megarc" format) to
        # securely store the username and password
        self._hostname = parsed_url.hostname
        if parsed_url.password is None:
            self._megarc = os.getenv(u'HOME') + u'/.megav2rc'
            try:
                conf_file = open(self._megarc, u"r")
            except Exception as e:
                raise BackendException(u"No password provided in URL and MEGA configuration "
                                       u"file for duplicity does not exist as '%s'" %
                                       (self._megarc,))

            myvars = {}
            for line in conf_file:
                name, var = line.partition(u"=")[::2]
                myvars[name.strip()] = str(var.strip())
            conf_file.close()
            self._username = myvars[u"Username"]
            self._password = myvars[u"Password"]

        else:
            self._username = parsed_url.username
            self._password = self.get_password()

        # Remote folder ("MEGAcmd" no longer shows "Root/" at the top of the hierarchy)
        self._folder = u'/' + parsed_url.path[1:]

        # Only create the remote folder if it doesn't exist yet
        self.mega_login()
        cmd = [u'mega-ls', self._folder]
        try:
            self.subprocess_popen(cmd)
        except Exception as e:
            self._makedir(self._folder)

    def _check_binary_exists(self, cmd):
        u'Checks that a specified command exists in the running user command path'

        try:
            # Ignore the output, as we only need the return code
            subprocess.check_output([u'which', cmd])
        except Exception as e:
            raise BackendException(u"Command '%s' not found, make sure 'MEGAcmd' tools (https://mega.nz/cmd) is "
                                   u"properly installed and in the running user command path" % (cmd,))

    def _makedir(self, path):
        u'Creates a remote directory (recursively if necessary)'

        self.mega_login()
        cmd = [u'mega-mkdir', u'-p', path]
        try:
            self.subprocess_popen(cmd)
        except Exception as e:
            error_str = str(e)
            if u"Folder already exists" in error_str:
                raise BackendException(u"Folder '%s' could not be created on MEGA because it already exists. "
                                       u"Use another path or remove the folder in MEGA manually" % (path,))
            else:
                raise BackendException(u"Folder '%s' could not be created, reason : '%s'" % (path, e))

    def _put(self, source_path, remote_filename):
        u'''Uploads file to the specified remote folder (tries to delete it first to make
            sure the new one can be uploaded)'''

        try:
            self.delete(remote_filename.decode())
        except Exception:
            pass
        self.upload(local_file=source_path.get_canonical().decode(), remote_file=remote_filename.decode())

    def _get(self, remote_filename, local_path):
        u'Downloads file from the specified remote path'

        self.download(remote_file=remote_filename.decode(), local_file=local_path.name.decode())

    def _list(self):
        u'Lists files in the specified remote path'

        return self.folder_contents(files_only=True)

    def _delete(self, filename):
        u'Deletes file from the specified remote path'

        self.delete(remote_file=filename.decode())

    def _close(self):
        u'Function called when backend is done being used'

        cmd = [u'mega-logout']
        self.subprocess_popen(cmd)

    def mega_login(self):
        u'''Helper function to call from each method interacting with MEGA to make
            sure a session already exists or one is created to start with'''

        # Abort if command doesn't return in a reasonable time (somehow "mega-session" sometimes
        # doesn't return), and create session if one doesn't exist yet
        try:
            subprocess.check_output(u'mega-session', timeout=30)
        except subprocess.TimeoutExpired:
            raise BackendException(u"Timed out while trying to determine if a MEGA session exists")
        except Exception as e:
            cmd = [u'mega-login', self._username, self._password]
            try:
                subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
            except Exception as e:
                raise BackendException(u"Could not log in to MEGA, error : '%s'" % (e,))

    def folder_contents(self, files_only=False):
        u'Lists contents of a remote MEGA path, optionally ignoring subdirectories'

        cmd = [u'mega-ls', u'-l', self._folder]

        self.mega_login()
        files = subprocess.check_output(cmd)
        files = files.decode().split(u'\n')

        # Optionally ignore directories
        if files_only:
            files = [f.split()[5] for f in files if re.search(u'^-', f)]

        return files

    def download(self, remote_file, local_file):
        u'Downloads a file from a remote MEGA path'

        cmd = [u'mega-get', self._folder + u'/' + remote_file, local_file]
        self.mega_login()
        self.subprocess_popen(cmd)

    def upload(self, local_file, remote_file):
        u'Uploads a file to a remote MEGA path'

        cmd = [u'mega-put', local_file, self._folder + u'/' + remote_file]
        self.mega_login()
        try:
            self.subprocess_popen(cmd)
        except Exception as e:
            error_str = str(e)
            if u"Reached storage quota" in error_str:
                raise BackendException(u"MEGA account over quota, could not write file : '%s' . "
                                       u"Upgrade your storage at https://mega.nz/pro or remove some data." %
                                       (remote_file,))
            else:
                raise BackendException(u"Failed writing file '%s' to MEGA, reason : '%s'" % (remote_file, e))

    def delete(self, remote_file):
        u'Deletes a file from a remote MEGA path'

        cmd = [u'mega-rm', u'-f', self._folder + u'/' + remote_file]
        self.mega_login()
        self.subprocess_popen(cmd)


duplicity.backend.register_backend(u'megav2', Megav2Backend)
duplicity.backend.uses_netloc.extend([u'megav2'])
