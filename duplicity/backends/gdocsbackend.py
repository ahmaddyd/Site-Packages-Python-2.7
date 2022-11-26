# -*- Mode:Python; indent-tabs-mode:nil; tab-width:4; encoding:utf8 -*-
#
# Copyright 2011 Carlos Abalde <carlos.abalde@gmail.com>
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
from builtins import input
from builtins import str
import os.path
import string
import urllib.request  # pylint: disable=import-error
import urllib.parse  # pylint: disable=import-error
import urllib.error  # pylint: disable=import-error

import duplicity.backend
from duplicity import __version__
from duplicity.errors import BackendException


class GDocsBackend(duplicity.backend.Backend):
    u"""Connect to remote store using Google Google Documents List API"""

    ROOT_FOLDER_ID = u'folder%3Aroot'
    BACKUP_DOCUMENT_TYPE = u'application/binary'

    def __init__(self, parsed_url):
        duplicity.backend.Backend.__init__(self, parsed_url)

        # Import Google Data APIs libraries.
        try:
            global atom
            global gdata
            import atom.data
            import gdata.client
            import gdata.docs.client
            import gdata.docs.data
        except ImportError as e:
            raise BackendException(u"""\
Google Docs backend requires Google Data APIs Python Client Library (see http://code.google.com/p/gdata-python-client/).
Exception: %s""" % str(e))

        # Setup client instance.
        self.client = gdata.docs.client.DocsClient(source=u'duplicity %s' % __version__)
        self.client.ssl = True
        self.client.http_client.debug = False
        self._authorize(parsed_url.username + u'@' + parsed_url.hostname, self.get_password())

        # Fetch destination folder entry (and crete hierarchy if required).
        folder_names = string.split(parsed_url.path[1:], u'/')
        parent_folder = None
        parent_folder_id = GDocsBackend.ROOT_FOLDER_ID
        for folder_name in folder_names:
            entries = self._fetch_entries(parent_folder_id, u'folder', folder_name)
            if entries is not None:
                if len(entries) == 1:
                    parent_folder = entries[0]
                elif len(entries) == 0:
                    folder = gdata.docs.data.Resource(type=u'folder', title=folder_name)
                    parent_folder = self.client.create_resource(folder, collection=parent_folder)
                else:
                    parent_folder = None
                if parent_folder:
                    parent_folder_id = parent_folder.resource_id.text
                else:
                    raise BackendException(u"Error while creating destination folder '%s'." % folder_name)
            else:
                raise BackendException(u"Error while fetching destination folder '%s'." % folder_name)
        self.folder = parent_folder

    def _put(self, source_path, remote_filename):
        self._delete(remote_filename)

        # Set uploader instance. Note that resumable uploads are required in order to
        # enable uploads for all file types.
        # (see http://googleappsdeveloper.blogspot.com/2011/05/upload-all-file-types-to-any-google.html)
        file = source_path.open()
        uploader = gdata.client.ResumableUploader(
            self.client, file,
            GDocsBackend.BACKUP_DOCUMENT_TYPE,
            os.path.getsize(file.name),
            chunk_size=gdata.client.ResumableUploader.DEFAULT_CHUNK_SIZE,
            desired_class=gdata.docs.data.Resource)
        if uploader:
            # Chunked upload.
            entry = gdata.docs.data.Resource(title=atom.data.Title(text=remote_filename))
            uri = self.folder.get_resumable_create_media_link().href + u'?convert=false'
            entry = uploader.UploadFile(uri, entry=entry)
            if not entry:
                raise BackendException(u"Failed to upload file '%s' to remote folder '%s'"
                                       % (source_path.get_filename(), self.folder.title.text))
        else:
            raise BackendException(u"Failed to initialize upload of file '%s' to remote folder '%s'"
                                   % (source_path.get_filename(), self.folder.title.text))
        assert not file.close()

    def _get(self, remote_filename, local_path):
        entries = self._fetch_entries(self.folder.resource_id.text,
                                      GDocsBackend.BACKUP_DOCUMENT_TYPE,
                                      remote_filename)
        if len(entries) == 1:
            entry = entries[0]
            self.client.DownloadResource(entry, local_path.name)
        else:
            raise BackendException(u"Failed to find file '%s' in remote folder '%s'"
                                   % (remote_filename, self.folder.title.text))

    def _list(self):
        entries = self._fetch_entries(self.folder.resource_id.text,
                                      GDocsBackend.BACKUP_DOCUMENT_TYPE)
        return [entry.title.text for entry in entries]

    def _delete(self, filename):
        entries = self._fetch_entries(self.folder.resource_id.text,
                                      GDocsBackend.BACKUP_DOCUMENT_TYPE,
                                      filename)
        for entry in entries:
            self.client.delete(entry.get_edit_link().href + u'?delete=true', force=True)

    def _authorize(self, email, password, captcha_token=None, captcha_response=None):
        try:
            self.client.client_login(email,
                                     password,
                                     source=u'duplicity %s' % __version__,
                                     service=u'writely',
                                     captcha_token=captcha_token,
                                     captcha_response=captcha_response)
        except gdata.client.CaptchaChallenge as challenge:
            print(u'A captcha challenge in required. Please visit ' + challenge.captcha_url)
            answer = None
            while not answer:
                answer = eval(input(u'Answer to the challenge? '))
            self._authorize(email, password, challenge.captcha_token, answer)
        except gdata.client.BadAuthentication:
            raise BackendException(
                u'Invalid user credentials given. Be aware that accounts '
                u'that use 2-step verification require creating an application specific '
                u'access code for using this Duplicity backend. Follow the instruction in '
                u'http://www.google.com/support/accounts/bin/static.py?page=guide.cs&guide=1056283&topic=1056286 '
                u'and create your application-specific password to run duplicity backups.')

    def _fetch_entries(self, folder_id, type, title=None):  # pylint: disable=redefined-builtin
        # Build URI.
        uri = u'/feeds/default/private/full/%s/contents' % folder_id
        if type == u'folder':
            uri += u'/-/folder?showfolders=true'
        elif type == GDocsBackend.BACKUP_DOCUMENT_TYPE:
            uri += u'?showfolders=false'
        else:
            uri += u'?showfolders=true'
        if title:
            uri += u'&title=' + urllib.parse.quote(title) + u'&title-exact=true'

        # Fetch entries.
        entries = self.client.get_all_resources(uri=uri)

        # When filtering by entry title, API is returning (don't know why) documents in other
        # folders (apart from folder_id) matching the title, so some extra filtering is required.
        if title:
            result = []
            for entry in entries:
                resource_type = entry.get_resource_type()
                if (not type) \
                   or (type == u'folder' and resource_type == u'folder') \
                   or (type == GDocsBackend.BACKUP_DOCUMENT_TYPE and resource_type != u'folder'):

                    if folder_id != GDocsBackend.ROOT_FOLDER_ID:
                        for link in entry.in_collections():
                            folder_entry = self.client.get_entry(link.href, None, None,
                                                                 desired_class=gdata.docs.data.Resource)
                            if folder_entry and (folder_entry.resource_id.text == folder_id):
                                result.append(entry)
                    elif len(entry.in_collections()) == 0:
                        result.append(entry)
        else:
            result = entries

        # Done!
        return result


u""" gdata is an alternate way to access gdocs, currently 05/2015 lacking OAuth support """
duplicity.backend.register_backend(u'gdata+gdocs', GDocsBackend)
duplicity.backend.uses_netloc.extend([u'gdata+gdocs'])
