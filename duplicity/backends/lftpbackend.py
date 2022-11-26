# -*- Mode:Python; indent-tabs-mode:nil; tab-width:4; encoding:utf8 -*-
#
# Copyright 2002 Ben Escoto <ben@emerose.org>
# Copyright 2007 Kenneth Loafman <kenneth@loafman.com>
# Copyright 2010 Marcel Pennewiss <opensource@pennewiss.de>
# Copyright 2014 Edgar Soldin
#                 - webdav, fish, sftp support
#                 - https cert verification switches
#                 - debug output
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
import re
import urllib.request  # pylint: disable=import-error
import urllib.parse  # pylint: disable=import-error
import urllib.error  # pylint: disable=import-error
try:
    from shlex import quote as cmd_quote
except ImportError:
    from pipes import quote as cmd_quote

import duplicity.backend
from duplicity import config
from duplicity import log
from duplicity import tempdir
from duplicity import util


class LFTPBackend(duplicity.backend.Backend):
    u"""Connect to remote store using File Transfer Protocol"""
    def __init__(self, parsed_url):
        duplicity.backend.Backend.__init__(self, parsed_url)

        # we expect an output
        try:
            p = os.popen(u"lftp --version")
            fout = p.read()
            ret = p.close()
        except Exception:
            pass
        # there is no output if lftp not found
        if not fout:
            log.FatalError(u"LFTP not found:  Please install LFTP.",
                           log.ErrorCode.ftps_lftp_missing)

        # version is the second word of the second part of the first line
        version = fout.split(u'\n')[0].split(u' | ')[1].split()[1]
        log.Notice(u"LFTP version is %s" % version)

        self.parsed_url = parsed_url

        self.scheme = duplicity.backend.strip_prefix(parsed_url.scheme, u'lftp').lower()
        self.scheme = re.sub(u'^webdav', u'http', self.scheme)
        self.url_string = self.scheme + u'://' + parsed_url.hostname
        if parsed_url.port:
            self.url_string += u":%s" % parsed_url.port

        self.remote_path = re.sub(u'^/', u'', parsed_url.path)

        # Fix up an empty remote path
        if len(self.remote_path) == 0:
            self.remote_path = u'/'

        # Use an explicit directory name.
        if self.remote_path[-1] != u'/':
            self.remote_path += u'/'

        self.authflag = u''
        if self.parsed_url.username:
            self.username = self.parsed_url.username
            self.password = self.get_password()
            self.authflag = u"-u '%s,%s'" % (self.username, self.password)

        if config.ftp_connection == u'regular':
            self.conn_opt = u'off'
        else:
            self.conn_opt = u'on'

        # check for cacert file if https
        self.cacert_file = config.ssl_cacert_file
        if self.scheme == u'https' and not config.ssl_no_check_certificate:
            cacert_candidates = [u"~/.duplicity/cacert.pem",
                                 u"~/duplicity_cacert.pem",
                                 u"/etc/duplicity/cacert.pem"]
            # look for a default cacert file
            if not self.cacert_file:
                for path in cacert_candidates:
                    path = os.path.expanduser(path)
                    if (os.path.isfile(path)):
                        self.cacert_file = path
                        break

        # save config into a reusable temp file
        self.tempfd, self.tempname = tempdir.default().mkstemp()
        self.tempfile = os.fdopen(self.tempfd, u"w")
        self.tempfile.write(u"set ssl:verify-certificate " +
                            (u"false" if config.ssl_no_check_certificate else u"true") + u"\n")
        if self.cacert_file:
            self.tempfile.write(u"set ssl:ca-file " + cmd_quote(self.cacert_file) + u"\n")
        if config.ssl_cacert_path:
            self.tempfile.write(u"set ssl:ca-path " + cmd_quote(config.ssl_cacert_path) + u"\n")
        if self.parsed_url.scheme == u'ftps':
            self.tempfile.write(u"set ftp:ssl-allow true\n")
            self.tempfile.write(u"set ftp:ssl-protect-data true\n")
            self.tempfile.write(u"set ftp:ssl-protect-list true\n")
        elif self.parsed_url.scheme == u'ftpes':
            self.tempfile.write(u"set ftp:ssl-force on\n")
            self.tempfile.write(u"set ftp:ssl-protect-data on\n")
            self.tempfile.write(u"set ftp:ssl-protect-list on\n")
        else:
            self.tempfile.write(u"set ftp:ssl-allow false\n")
        self.tempfile.write(u"set http:use-propfind true\n")
        self.tempfile.write(u"set net:timeout %s\n" % config.timeout)
        self.tempfile.write(u"set net:max-retries %s\n" % config.num_retries)
        self.tempfile.write(u"set ftp:passive-mode %s\n" % self.conn_opt)
        if log.getverbosity() >= log.DEBUG:
            self.tempfile.write(u"debug\n")
        if self.parsed_url.scheme == u'ftpes':
            self.tempfile.write(u"open %s %s\n" % (self.authflag, self.url_string.replace(u'ftpes', u'ftp')))
        else:
            self.tempfile.write(u"open %s %s\n" % (self.authflag, self.url_string))
        self.tempfile.close()
        # print settings in debug mode
        if log.getverbosity() >= log.DEBUG:
            f = open(self.tempname, u'r')
            log.Debug(u"SETTINGS: \n"
                      u"%s" % f.read())

    def _put(self, source_path, remote_filename):
        if isinstance(remote_filename, b"".__class__):
            remote_filename = util.fsdecode(remote_filename)
        commandline = u"lftp -c \"source %s; mkdir -p %s; put %s -o %s\"" % (
            self.tempname,
            cmd_quote(self.remote_path),
            cmd_quote(source_path.uc_name),
            cmd_quote(self.remote_path) + util.fsdecode(remote_filename)
        )
        log.Debug(u"CMD: %s" % commandline)
        s, l, e = self.subprocess_popen(commandline)
        log.Debug(u"STATUS: %s" % s)
        log.Debug(u"STDERR:\n"
                  u"%s" % (e))
        log.Debug(u"STDOUT:\n"
                  u"%s" % (l))

    def _get(self, remote_filename, local_path):
        if isinstance(remote_filename, b"".__class__):
            remote_filename = util.fsdecode(remote_filename)
        commandline = u"lftp -c \"source %s; get %s -o %s\"" % (
            cmd_quote(self.tempname),
            cmd_quote(self.remote_path) + remote_filename,
            cmd_quote(local_path.uc_name)
        )
        log.Debug(u"CMD: %s" % commandline)
        _, l, e = self.subprocess_popen(commandline)
        log.Debug(u"STDERR:\n"
                  u"%s" % (e))
        log.Debug(u"STDOUT:\n"
                  u"%s" % (l))

    def _list(self):
        # Do a long listing to avoid connection reset
        # remote_dir = urllib.unquote(self.parsed_url.path.lstrip('/')).rstrip()
        remote_dir = urllib.parse.unquote(self.parsed_url.path)
        # print remote_dir
        quoted_path = cmd_quote(self.remote_path)
        # failing to cd into the folder might be because it was not created already
        commandline = u"lftp -c \"source %s; ( cd %s && ls ) || ( mkdir -p %s && cd %s && ls )\"" % (
            cmd_quote(self.tempname),
            quoted_path, quoted_path, quoted_path
        )
        log.Debug(u"CMD: %s" % commandline)
        _, l, e = self.subprocess_popen(commandline)
        log.Debug(u"STDERR:\n"
                  u"%s" % (e))
        log.Debug(u"STDOUT:\n"
                  u"%s" % (l))

        # Look for our files as the last element of a long list line
        return [util.fsencode(x.split()[-1]) for x in l.split(u'\n') if x]

    def _delete(self, filename):
        commandline = u"lftp -c \"source %s; cd %s; rm %s\"" % (
            cmd_quote(self.tempname),
            cmd_quote(self.remote_path),
            cmd_quote(util.fsdecode(filename))
        )
        log.Debug(u"CMD: %s" % commandline)
        _, l, e = self.subprocess_popen(commandline)
        log.Debug(u"STDERR:\n"
                  u"%s" % (e))
        log.Debug(u"STDOUT:\n"
                  u"%s" % (l))


duplicity.backend.register_backend(u"ftp", LFTPBackend)
duplicity.backend.register_backend(u"ftps", LFTPBackend)
duplicity.backend.register_backend(u"fish", LFTPBackend)
duplicity.backend.register_backend(u"ftpes", LFTPBackend)

duplicity.backend.register_backend(u"lftp+ftp", LFTPBackend)
duplicity.backend.register_backend(u"lftp+ftps", LFTPBackend)
duplicity.backend.register_backend(u"lftp+fish", LFTPBackend)
duplicity.backend.register_backend(u"lftp+ftpes", LFTPBackend)
duplicity.backend.register_backend(u"lftp+sftp", LFTPBackend)
duplicity.backend.register_backend(u"lftp+webdav", LFTPBackend)
duplicity.backend.register_backend(u"lftp+webdavs", LFTPBackend)
duplicity.backend.register_backend(u"lftp+http", LFTPBackend)
duplicity.backend.register_backend(u"lftp+https", LFTPBackend)

duplicity.backend.uses_netloc.extend([u'ftp', u'ftps', u'fish', u'ftpes',
                                      u'lftp+ftp', u'lftp+ftps',
                                      u'lftp+fish', u'lftp+ftpes',
                                      u'lftp+sftp',
                                      u'lftp+webdav', u'lftp+webdavs',
                                      u'lftp+http', u'lftp+https']
                                     )
