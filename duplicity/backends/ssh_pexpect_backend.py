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

# The following can be redefined to use different shell commands from
# ssh or scp or to add more arguments.  However, the replacements must
# have the same syntax.  Also these strings will be executed by the
# shell, so shouldn't have strange characters in them.

from __future__ import division
from future import standard_library
standard_library.install_aliases()
from builtins import map

import os
import re

from duplicity import config
from duplicity import log
from duplicity import util
from duplicity.errors import BackendException
import duplicity.backend


class SSHPExpectBackend(duplicity.backend.Backend):
    u"""This backend copies files using scp.  List not supported.  Filenames
       should not need any quoting or this will break."""
    def __init__(self, parsed_url):
        u"""scpBackend initializer"""
        duplicity.backend.Backend.__init__(self, parsed_url)

        try:
            global pexpect
            import pexpect

        except ImportError:
            raise

        self.retry_delay = 10

        self.scp_command = u"scp"
        if config.scp_command:
            self.scp_command = config.scp_command

        self.sftp_command = u"sftp"
        if config.sftp_command:
            self.sftp_command = config.sftp_command

        self.scheme = duplicity.backend.strip_prefix(parsed_url.scheme, u'pexpect')
        self.use_scp = (self.scheme == u'scp')

        # host string of form [user@]hostname
        if parsed_url.username:
            self.host_string = parsed_url.username + u"@" + parsed_url.hostname
        else:
            self.host_string = parsed_url.hostname
        # make sure remote_dir is always valid
        if parsed_url.path:
            # remove leading '/'
            self.remote_dir = re.sub(r'^/', r'', parsed_url.path, 1)
        else:
            self.remote_dir = u'.'
        self.remote_prefix = self.remote_dir + u'/'
        # maybe use different ssh port
        if parsed_url.port:
            config.ssh_options = config.ssh_options + u" -oPort=%s" % parsed_url.port
        # set some defaults if user has not specified already.
        if u"ServerAliveInterval" not in config.ssh_options:
            config.ssh_options += u" -oServerAliveInterval=%d" % ((int)(config.timeout / 2))
        if u"ServerAliveCountMax" not in config.ssh_options:
            config.ssh_options += u" -oServerAliveCountMax=2"

        # set up password
        self.use_getpass = config.ssh_askpass
        self.password = self.get_password()

    def run_scp_command(self, commandline):
        u""" Run an scp command, responding to password prompts """
        log.Info(u"Running '%s'" % commandline)
        child = pexpect.spawn(commandline, timeout=None)
        if config.ssh_askpass:
            state = u"authorizing"
        else:
            state = u"copying"
        while 1:
            if state == u"authorizing":
                match = child.expect([pexpect.EOF,
                                      u"(?i)timeout, server not responding",
                                      u"(?i)pass(word|phrase .*):",
                                      u"(?i)permission denied",
                                      u"authenticity"])
                log.Debug(u"State = %s, Before = '%s'" % (state, child.before.strip()))
                if match == 0:
                    log.Warn(u"Failed to authenticate")
                    break
                elif match == 1:
                    log.Warn(u"Timeout waiting to authenticate")
                    break
                elif match == 2:
                    child.sendline(self.password)
                    state = u"copying"
                elif match == 3:
                    log.Warn(u"Invalid SSH password")
                    break
                elif match == 4:
                    log.Warn(u"Remote host authentication failed (missing known_hosts entry?)")
                    break
            elif state == u"copying":
                match = child.expect([pexpect.EOF,
                                      u"(?i)timeout, server not responding",
                                      u"stalled",
                                      u"authenticity",
                                      u"ETA"])
                log.Debug(u"State = %s, Before = '%s'" % (state, child.before.strip()))
                if match == 0:
                    break
                elif match == 1:
                    log.Warn(u"Timeout waiting for response")
                    break
                elif match == 2:
                    state = u"stalled"
                elif match == 3:
                    log.Warn(u"Remote host authentication failed (missing known_hosts entry?)")
                    break
            elif state == u"stalled":
                match = child.expect([pexpect.EOF,
                                      u"(?i)timeout, server not responding",
                                      u"ETA"])
                log.Debug(u"State = %s, Before = '%s'" % (state, child.before.strip()))
                if match == 0:
                    break
                elif match == 1:
                    log.Warn(u"Stalled for too long, aborted copy")
                    break
                elif match == 2:
                    state = u"copying"
        child.close(force=True)
        if child.exitstatus != 0:
            raise BackendException(u"Error running '%s'" % commandline)

    def run_sftp_command(self, commandline, commands):
        u""" Run an sftp command, responding to password prompts, passing commands from list """
        maxread = 2000  # expected read buffer size
        responses = [pexpect.EOF,
                     u"(?i)timeout, server not responding",
                     u"sftp>",
                     u"(?i)pass(word|phrase .*):",
                     u"(?i)permission denied",
                     u"authenticity",
                     u"(?i)no such file or directory",
                     u"Couldn't delete file: No such file or directory",
                     u"Couldn't delete file",
                     u"open(.*): Failure"]
        max_response_len = max([len(p) for p in responses[1:]])
        log.Info(u"Running '%s'" % (commandline))
        child = pexpect.spawn(commandline, timeout=None, maxread=maxread, encoding=config.fsencoding)
        cmdloc = 0
        passprompt = 0
        while 1:
            msg = u""
            match = child.expect(responses,
                                 searchwindowsize=maxread + max_response_len)
            log.Debug(u"State = sftp, Before = '%s'" % (child.before.strip()))
            if match == 0:
                break
            elif match == 1:
                msg = u"Timeout waiting for response"
                break
            if match == 2:
                if cmdloc < len(commands):
                    command = commands[cmdloc]
                    log.Info(u"sftp command: '%s'" % (command,))
                    child.sendline(command)
                    cmdloc += 1
                else:
                    command = u'quit'
                    child.sendline(command)
                    res = child.before
            elif match == 3:
                passprompt += 1
                child.sendline(self.password)
                if (passprompt > 1):
                    raise BackendException(u"Invalid SSH password.")
            elif match == 4:
                if not child.before.strip().startswith(u"mkdir"):
                    msg = u"Permission denied"
                    break
            elif match == 5:
                msg = u"Host key authenticity could not be verified (missing known_hosts entry?)"
                break
            elif match == 6:
                if not child.before.strip().startswith(u"rm"):
                    msg = u"Remote file or directory does not exist in command='%s'" % (commandline,)
                    break
            elif match == 7:
                if not child.before.strip().startswith(u"Removing"):
                    msg = u"Could not delete file in command='%s'" % (commandline,)
                    break
            elif match == 8:
                msg = u"Could not delete file in command='%s'" % (commandline,)
                break
            elif match == 9:
                msg = u"Could not open file in command='%s'" % (commandline,)
                break
        child.close(force=True)
        if child.exitstatus == 0:
            return res
        else:
            raise BackendException(u"Error running '%s': %s" % (commandline, msg))

    def _put(self, source_path, remote_filename):
        remote_filename = util.fsdecode(remote_filename)
        if self.use_scp:
            self.put_scp(source_path, remote_filename)
        else:
            self.put_sftp(source_path, remote_filename)

    def put_sftp(self, source_path, remote_filename):
        commands = [u"put \"%s\" \"%s.%s.part\"" %
                    (source_path.uc_name, self.remote_prefix, remote_filename),
                    u"rename \"%s.%s.part\" \"%s%s\"" %
                    (self.remote_prefix, remote_filename, self.remote_prefix, remote_filename)]
        commandline = (u"%s %s %s" % (self.sftp_command,
                                      config.ssh_options,
                                      self.host_string))
        self.run_sftp_command(commandline, commands)

    def put_scp(self, source_path, remote_filename):
        commandline = u"%s %s %s %s:%s%s" % \
            (self.scp_command, config.ssh_options, source_path.uc_name, self.host_string,
             self.remote_prefix, remote_filename)
        self.run_scp_command(commandline)

    def _get(self, remote_filename, local_path):
        remote_filename = util.fsdecode(remote_filename)
        if self.use_scp:
            self.get_scp(remote_filename, local_path)
        else:
            self.get_sftp(remote_filename, local_path)

    def get_sftp(self, remote_filename, local_path):
        commands = [u"get \"%s%s\" \"%s\"" %
                    (self.remote_prefix, remote_filename, local_path.uc_name)]
        commandline = (u"%s %s %s" % (self.sftp_command,
                                      config.ssh_options,
                                      self.host_string))
        self.run_sftp_command(commandline, commands)

    def get_scp(self, remote_filename, local_path):
        commandline = u"%s %s %s:%s%s %s" % \
            (self.scp_command, config.ssh_options, self.host_string, self.remote_prefix,
             remote_filename, local_path.uc_name)
        self.run_scp_command(commandline)

    def _list(self):
        # Note that this command can get confused when dealing with
        # files with newlines in them, as the embedded newlines cannot
        # be distinguished from the file boundaries.
        dirs = self.remote_dir.split(os.sep)
        if len(dirs) > 0:
            if dirs[0] == u'':
                dirs[0] = u'/'
        mkdir_commands = []
        for d in dirs:
            mkdir_commands += [u"mkdir \"%s\"" % (d)] + [u"cd \"%s\"" % (d)]

        commands = mkdir_commands + [u"ls -1"]
        commandline = (u"%s %s %s" % (self.sftp_command,
                                      config.ssh_options,
                                      self.host_string))

        l = self.run_sftp_command(commandline, commands).split(u'\n')[1:]

        return [x for x in map(u"".__class__.strip, l) if x]

    def _delete(self, filename):
        commands = [u"cd \"%s\"" % (self.remote_dir,)]
        commands.append(u"rm \"%s\"" % util.fsdecode(filename))
        commandline = (u"%s %s %s" % (self.sftp_command, config.ssh_options, self.host_string))
        self.run_sftp_command(commandline, commands)


duplicity.backend.register_backend(u"pexpect+sftp", SSHPExpectBackend)
duplicity.backend.register_backend(u"pexpect+scp", SSHPExpectBackend)
duplicity.backend.uses_netloc.extend([u'pexpect+sftp', u'pexpect+scp'])
