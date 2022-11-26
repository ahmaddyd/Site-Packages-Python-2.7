# -*- Mode:Python; indent-tabs-mode:nil; tab-width:4; encoding:utf8 -*-
#
# Copyright 2015 Yigal Asnis
# Copyright 2021 Jindrich Makovicka
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.
#
# It is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with duplicity; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

from builtins import str

import os
import pickle

from duplicity import log
from duplicity import util
from duplicity.errors import BackendException
import duplicity.backend


class GDriveBackend(duplicity.backend.Backend):
    u"""Connect to remote store using Google Drive API V3"""

    PAGE_SIZE = 100
    MIN_RESUMABLE_UPLOAD = 5 * 1024 * 1024

    def __init__(self, parsed_url):
        duplicity.backend.Backend.__init__(self, parsed_url)
        try:
            from googleapiclient.discovery import build
            from google.oauth2.service_account import Credentials
        except ImportError as e:
            raise BackendException(u"""\
GDrive backend requires Google API client installation.
Please read the manpage for setup details.
Exception: %s""" % str(e))

        # Note Google has 2 drive methods, `Shared(previously Team) Drives` and `My Drive`
        #   both can be shared but require different addressing
        # For a Google Shared Drives folder
        # ---------------------------------
        # Share Drive ID specified as a query parameter in the backend URL.
        # Example:
        #  gdrive://developer.gserviceaccount.com/target-folder/?driveID=<SHARED DRIVE ID>
        #
        # For a Google My Drive based shared folder
        # -----------------------------------------
        # MyDrive folder ID specified as a query parameter in the backend URL
        #
        # Example
        #  export GOOGLE_SERVICE_ACCOUNT_URL=<serviceaccount-name>@<serviceaccount-name>.iam.gserviceaccount.com
        #  gdrive://${GOOGLE_SERVICE_ACCOUNT_URL}/<target-folder-name/>?myDriveFolderID=<google-myDrive-folder-id>
        #
        # both methods use a Google Services Account
        # export GOOGLE_SERVICE_JSON_FILE=<serviceaccount-credentials.json>
        # export GOOGLE_SERVICE_ACCOUNT_URL=<serviceaccount-name>@<serviceaccount-name>.iam.gserviceaccount.com

        self.shared_drive_corpora = {}
        self.shared_drive_id = {}
        self.shared_drive_flags_include = {}
        self.shared_drive_flags_support = {}
        self.shared_root_folder_id = None
        if u'driveID' in parsed_url.query_args:
            self.shared_drive_corpora = {u'corpora': u'drive'}
            self.shared_drive_id = {u'driveId': parsed_url.query_args[u'driveID'][0]}
            self.shared_drive_flags_include = {u'includeItemsFromAllDrives': True}
            self.shared_drive_flags_support = {u'supportsAllDrives': True}
        elif u'myDriveFolderID' in parsed_url.query_args:
            self.shared_drive_corpora = {u'corpora': u'user'}
            self.shared_drive_flags_include = {u'includeItemsFromAllDrives': True}
            self.shared_drive_flags_support = {u'supportsAllDrives': True}
            self.shared_root_folder_id = parsed_url.query_args[u'myDriveFolderID'][0]
        else:
            raise BackendException(
                u"gdrive: backend requires a query paramater should either be driveID or myDriveFolderID")
        if parsed_url.username is not None:
            client_id = parsed_url.username + u'@' + parsed_url.hostname
        else:
            client_id = parsed_url.hostname

        if u'GOOGLE_SERVICE_JSON_FILE' in os.environ:
            credentials = Credentials.from_service_account_file(os.environ[u'GOOGLE_SERVICE_JSON_FILE'])
            if credentials.service_account_email != client_id:
                raise BackendException(
                    u'Service account email in the JSON file (%s) does not match the URL (%s)' %
                    (credentials.service_account_email, client_id))

        elif u'GOOGLE_CLIENT_SECRET_JSON_FILE' in os.environ and u'GOOGLE_CREDENTIALS_FILE' in os.environ:
            from google_auth_oauthlib.flow import InstalledAppFlow
            from google.auth.transport.requests import Request

            credentials = None
            if os.path.exists(os.environ[u'GOOGLE_CREDENTIALS_FILE']):
                with open(os.environ[u'GOOGLE_CREDENTIALS_FILE'], u'rb') as token:
                    credentials = pickle.load(token)

            # If there are no (valid) credentials available, let the user log in.
            if not credentials or not credentials.valid:
                if credentials and credentials.expired and credentials.refresh_token:
                    credentials.refresh(Request())
                else:
                    flow = InstalledAppFlow.from_client_secrets_file(
                        os.environ[u'GOOGLE_CLIENT_SECRET_JSON_FILE'],
                        u'https://www.googleapis.com/auth/drive.file')

                    if flow.client_config[u'client_id'] != client_id:
                        raise BackendException(
                            u'Client ID in the JSON file (%s) does not match the URL (%s)' %
                            (flow.client_config[u'client_id'], client_id))

                    credentials = flow.run_console()
                # Save the credentials for the next run
                with open(os.environ[u'GOOGLE_CREDENTIALS_FILE'], u'wb') as token:
                    pickle.dump(credentials, token)

            if credentials.client_id != client_id:
                raise BackendException(
                    u'Client ID in the credentials file (%s) does not match the URL (%s)' %
                    (credentials.client_id, client_id))

        else:
            raise BackendException(
                u'GOOGLE_SERVICE_JSON_FILE or GOOGLE_CLIENT_SECRET_JSON_FILE environment '
                u'variable not set. Please read the manpage to fix.')

        self.drive = build(u'drive', u'v3', credentials=credentials)

        if self.shared_drive_id:
            parent_folder_id = self.shared_drive_id[u'driveId']
        elif self.shared_root_folder_id:
            parent_folder_id = self.shared_root_folder_id
        else:
            parent_folder_id = u'root'

        # Fetch destination folder entry and create hierarchy if required.
        folder_names = parsed_url.path.split(u'/')
        for folder_name in folder_names:

            if not folder_name:
                continue
            q = (u"name = '" + folder_name + u"' and '" + parent_folder_id +
                 u"' in parents and mimeType = 'application/vnd.google-apps.folder' and trashed=false")
            results = self.drive.files().list(q=q,
                                              pageSize=1,
                                              fields=u"files(name,id),nextPageToken",
                                              **self.shared_drive_corpora,
                                              **self.shared_drive_id,
                                              **self.shared_drive_flags_include,
                                              **self.shared_drive_flags_support).execute()
            file_list = results.get(u'files', [])
            if len(file_list) == 0:
                file_metadata = {u'name': folder_name,
                                 u'mimeType': u"application/vnd.google-apps.folder",
                                 u'parents': [parent_folder_id]}
                file_metadata.update(self.shared_drive_id)
                folder = self.drive.files().create(body=file_metadata,
                                                   fields=u'id',
                                                   **self.shared_drive_flags_support).execute()
            else:
                folder = file_list[0]

            parent_folder_id = folder[u'id']

        self.folder = parent_folder_id
        self.id_cache = {}

    def file_by_name(self, filename):
        from googleapiclient.errors import HttpError

        filename = util.fsdecode(filename)

        if filename in self.id_cache:
            # It might since have been locally moved, renamed or deleted, so we
            # need to validate the entry.
            file_id = self.id_cache[filename]
            try:
                drive_file = self.drive.files().get(fileId=file_id,
                                                    fields=u'id,size,name,parents,trashed',
                                                    **self.shared_drive_flags_support).execute()
                if drive_file[u'name'] == filename and not drive_file[u'trashed']:
                    for parent in drive_file[u'parents']:
                        if parent == self.folder:
                            log.Info(u"GDrive backend: found file '%s' with id %s in ID cache" %
                                     (filename, file_id))
                            return drive_file
            except HttpError as error:
                # A 404 occurs if the ID is no longer valid
                if error.resp.status != 404:
                    raise
            # If we get here, the cache entry is invalid
            log.Info(u"GDrive backend: invalidating '%s' (previously ID %s) from ID cache" %
                     (filename, file_id))
            del self.id_cache[filename]

        # Not found in the cache, so use directory listing. This is less
        # reliable because there is no strong consistency.
        q = u"name = '%s' and '%s' in parents and trashed = false" % (filename, self.folder)
        results = self.drive.files().list(q=q, fields=u'files(name,id,size),nextPageToken',
                                          pageSize=2,
                                          **self.shared_drive_corpora,
                                          **self.shared_drive_id,
                                          **self.shared_drive_flags_include,
                                          **self.shared_drive_flags_support).execute()
        file_list = results.get(u'files', [])
        if len(file_list) > 1:
            log.FatalError(u"GDrive backend: multiple files called '%s'." % (filename,))
        elif len(file_list) > 0:
            file_id = file_list[0][u'id']
            self.id_cache[filename] = file_list[0][u'id']
            log.Info(u"GDrive backend: found file '%s' with id %s on server, "
                     u"adding to cache" % (filename, file_id))
            return file_list[0]

        log.Info(u"GDrive backend: file '%s' not found in cache or on server" %
                 (filename,))
        return None

    def id_by_name(self, filename):
        drive_file = self.file_by_name(filename)
        if drive_file is None:
            return u''
        else:
            return drive_file[u'id']

    def _put(self, source_path, remote_filename):
        from googleapiclient.http import MediaFileUpload

        remote_filename = util.fsdecode(remote_filename)
        drive_file = self.file_by_name(remote_filename)
        if remote_filename.endswith(u'.gpg'):
            mime_type = u'application/pgp-encrypted'
        else:
            mime_type = u'text/plain'

        file_size = os.path.getsize(source_path.name)
        if file_size >= self.MIN_RESUMABLE_UPLOAD:
            resumable = True
            num_retries = 5
        else:
            resumable = False
            num_retries = 0

        media = MediaFileUpload(source_path.name, mimetype=mime_type, resumable=resumable)
        if drive_file is None:
            # No existing file, make a new one
            file_metadata = {u'name': remote_filename, u'parents': [self.folder]}
            file_metadata.update(self.shared_drive_id)
            log.Info(u"GDrive backend: creating new file '%s'" % (remote_filename,))
            drive_file = self.drive.files().create(
                body=file_metadata,
                media_body=media,
                **self.shared_drive_flags_support).execute(num_retries=num_retries)
        else:
            log.Info(u"GDrive backend: replacing existing file '%s' with id '%s'" % (
                remote_filename, drive_file[u'id']))
            drive_file = self.drive.files().update(
                media_body=media,
                fileId=drive_file[u'id'],
                **self.shared_drive_flags_support).execute(num_retries=num_retries)

        self.id_cache[remote_filename] = drive_file[u'id']

    def _get(self, remote_filename, local_path):
        from googleapiclient.http import MediaIoBaseDownload

        drive_file = self.file_by_name(remote_filename)
        request = self.drive.files().get_media(fileId=drive_file[u'id'],
                                               **self.shared_drive_flags_support)
        with open(util.fsdecode(local_path.name), u"wb") as fh:
            done = False
            downloader = MediaIoBaseDownload(fh, request)
            while done is False:
                status, done = downloader.next_chunk()

    def _list(self):
        page_token = None
        drive_files = []
        while True:
            response = self.drive.files().list(
                q=u"'" + self.folder + u"' in parents and trashed=false",
                pageSize=self.PAGE_SIZE,
                fields=u"files(name,id),nextPageToken",
                pageToken=page_token,
                **self.shared_drive_corpora,
                **self.shared_drive_id,
                **self.shared_drive_flags_include,
                **self.shared_drive_flags_support).execute()

            drive_files += response.get(u'files', [])

            page_token = response.get(u'nextPageToken', None)
            if page_token is None:
                break

        filenames = set(item[u'name'] for item in drive_files)
        # Check the cache as well. A file might have just been uploaded but
        # not yet appear in the listing.
        # Note: do not use iterkeys() here, because file_by_name will modify
        # the cache if it finds invalid entries.
        for filename in list(self.id_cache.keys()):
            if (filename not in filenames) and (self.file_by_name(filename) is not None):
                filenames.add(filename)
        return list(filenames)

    def _delete(self, filename):
        file_id = self.id_by_name(filename)
        if file_id == u'':
            log.Warn(u"File '%s' does not exist while trying to delete it" % (util.fsdecode(filename),))
        else:
            self.drive.files().delete(fileId=file_id,
                                      **self.shared_drive_flags_support).execute()

    def _query(self, filename):
        drive_file = self.file_by_name(filename)
        if drive_file is None:
            size = -1
        else:
            size = int(drive_file[u'size'])
        return {u'size': size}

    def _error_code(self, operation, error):  # pylint: disable=unused-argument
        from google.auth.exceptions import RefreshError
        from googleapiclient.errors import HttpError
        if isinstance(error, HttpError):
            return log.ErrorCode.backend_not_found
        elif isinstance(error, RefreshError):
            return log.ErrorCode.backend_permission_denied
        return log.ErrorCode.backend_error


duplicity.backend.register_backend(u'gdrive', GDriveBackend)

duplicity.backend.uses_netloc.extend([u'gdrive'])
