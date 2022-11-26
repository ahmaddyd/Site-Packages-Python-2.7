# -*- Mode:Python; indent-tabs-mode:nil; tab-width:4; -*-
#
# Copyright 2014 Havard Gulldahl
#
# in part based on dpbxbackend.py:
# Copyright 2013 jno <jno@pisem.net>
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

# stdlib
import logging
import posixpath

# import duplicity stuff
from duplicity import log
from duplicity.errors import BackendException
import duplicity.backend


def get_jotta_device(jfs):
    jottadev = None
    for j in jfs.devices:  # find Jotta/Shared folder
        if j.name == u'Jotta':
            jottadev = j
    return jottadev


def get_root_dir(jfs):
    jottadev = get_jotta_device(jfs)
    root_dir = jottadev.mountPoints[u'Archive']
    return root_dir


def set_jottalib_logging_level(log_level):
    logger = logging.getLogger(u'jottalib')
    logger.setLevel(getattr(logging, log_level))


def set_jottalib_log_handlers(handlers):
    logger = logging.getLogger(u'jottalib')
    for handler in handlers:
        logger.addHandler(handler)


def get_duplicity_log_level():
    u""" Get the current duplicity log level as a stdlib-compatible logging level"""
    duplicity_log_level = log.LevelName(log.getverbosity())

    # notice is a duplicity-specific logging level not supported by stdlib
    if duplicity_log_level == u'NOTICE':
        duplicity_log_level = u'INFO'

    return duplicity_log_level


class JottaCloudBackend(duplicity.backend.Backend):
    u"""Connect to remote store using JottaCloud API"""

    def __init__(self, parsed_url):
        duplicity.backend.Backend.__init__(self, parsed_url)

        # Import JottaCloud libraries.
        try:
            from jottalib import JFS
            from jottalib.JFS import JFSNotFoundError, JFSIncompleteFile
        except ImportError:
            raise BackendException(u'JottaCloud backend requires jottalib'
                                   u' (see https://pypi.python.org/pypi/jottalib).')

        # Set jottalib loggers to the same verbosity as duplicity
        duplicity_log_level = get_duplicity_log_level()
        set_jottalib_logging_level(duplicity_log_level)

        # Ensure jottalib and duplicity log to the same handlers
        set_jottalib_log_handlers(log._logger.handlers)

        # Will fetch jottacloud auth from environment or .netrc
        self.client = JFS.JFS()

        self.folder = self.get_or_create_directory(parsed_url.path.lstrip(u'/'))
        log.Debug(u"Jottacloud folder for duplicity: %r" % self.folder.path)

    def get_or_create_directory(self, directory_name):
        root_directory = get_root_dir(self.client)
        full_path = posixpath.join(root_directory.path, directory_name)
        try:
            return self.client.getObject(full_path)
        except JFSNotFoundError:
            return root_directory.mkdir(directory_name)

    def _put(self, source_path, remote_filename):
        # - Upload one file
        # - Retried if an exception is thrown
        resp = self.folder.up(source_path.open(), remote_filename)
        log.Debug(u'jottacloud.put(%s,%s): %s' % (source_path.name, remote_filename, resp))

    def _get(self, remote_filename, local_path):
        # - Get one file
        # - Retried if an exception is thrown
        remote_file = self.client.getObject(posixpath.join(self.folder.path, remote_filename))
        log.Debug(u'jottacloud.get(%s,%s): %s' % (remote_filename, local_path.name, remote_file))
        with open(local_path.name, u'wb') as to_file:
            for chunk in remote_file.stream():
                to_file.write(chunk)

    def _list(self):
        # - List all files in the backend
        # - Return a list of filenames
        # - Retried if an exception is thrown
        return list([f.name for f in self.folder.files()
                     if not f.is_deleted() and f.state != u'INCOMPLETE'])

    def _delete(self, filename):
        # - Delete one file
        # - Retried if an exception is thrown
        remote_path = posixpath.join(self.folder.path, filename)
        remote_file = self.client.getObject(remote_path)
        log.Debug(u'jottacloud.delete deleting: %s (%s)' % (remote_file, type(remote_file)))
        remote_file.delete()

    def _query(self, filename):
        u"""Get size of filename"""
        #  - Query metadata of one file
        #  - Return a dict with a 'size' key, and a file size value (-1 for not found)
        #  - Retried if an exception is thrown
        log.Info(u'Querying size of %s' % filename)
        remote_path = posixpath.join(self.folder.path, filename)
        try:
            remote_file = self.client.getObject(remote_path)
        except JFSNotFoundError:
            return {u'size': -1}
        return {
            u'size': remote_file.size,
        }

    def _close(self):
        # - If your backend needs to clean up after itself, do that here.
        pass


duplicity.backend.register_backend(u"jottacloud", JottaCloudBackend)
u""" jottacloud is a Norwegian backup company """
