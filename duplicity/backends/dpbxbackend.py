# -*- Mode:Python; indent-tabs-mode:nil; tab-width:4; encoding:utf8 -*-
#
# Copyright 2013 jno <jno@pisem.net>
# Copyright 2016 Dmitry Nezhevenko <dion@dion.org.ua>
#
# Version: 0.3
#
# 0. You can make me happy with https://www.dropbox.com/referrals/NTE2ODA0Mzg5
# 1. Most of the code was taken from cli_client.py. The ftpsbackend.py was used as a template
# 2. DPBX & dpbx are used because the use of the actual name is prohibited
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
from __future__ import division
from future import standard_library
standard_library.install_aliases()
from builtins import input
from builtins import str
import io
import os
import re
import sys
import time
import traceback
import urllib.request  # pylint: disable=import-error
import urllib.parse  # pylint: disable=import-error
import urllib.error  # pylint: disable=import-error

from duplicity import log, config
from duplicity import progress
from duplicity.errors import BackendException
from requests.exceptions import ConnectionError  # pylint: disable=redefined-builtin
import duplicity.backend

# This is chunk size for upload using Dpbx chumked API v2. It doesn't
# make sense to make it much large since Dpbx SDK uses connection pool
# internally. So multiple chunks will sent using same keep-alive socket
# Plus in case of network problems we most likely will be able to retry
# only failed chunk
DPBX_UPLOAD_CHUNK_SIZE = 16 * 1024 * 1024

# Download internal buffer size. Files are downloaded using one request.
DPBX_DOWNLOAD_BUF_SIZE = 512 * 1024

DPBX_AUTORENAMED_FILE_RE = re.compile(r' \([0-9]+\)\.[^\.]+$')


def log_exception(e):
    log.Error(u'Exception [%s]:' % (e,))
    f = io.StringIO()
    traceback.print_exc(file=f)
    f.seek(0)
    for s in f.readlines():
        log.Error(u'| ' + s.rstrip())
    f.close()


def command(login_required=True):  # pylint: disable=unused-argument
    u"""a decorator for handling authentication and exceptions"""
    def decorate(f):
        def wrapper(self, *args):
            try:
                return f(self, *args)
            except ApiError as e:
                log_exception(e)
                raise BackendException(u'dpbx api error "%s"' % (e,))
            except Exception as e:
                log_exception(e)
                log.Error(u'dpbx code error "%s"' % (e,), log.ErrorCode.backend_code_error)
                raise

        wrapper.__doc__ = f.__doc__
        return wrapper
    return decorate


class DPBXBackend(duplicity.backend.Backend):
    u"""Connect to remote store using Dr*pB*x service"""

    def __init__(self, parsed_url):
        duplicity.backend.Backend.__init__(self, parsed_url)

        global Dropbox
        global AuthError, BadInputError, ApiError
        global UploadSessionCursor, CommitInfo
        global WriteMode, GetMetadataError
        global DeleteError, UploadSessionLookupError
        global ListFolderError
        global DropboxOAuth2FlowNoRedirect
        try:
            from dropbox import Dropbox
            from dropbox.exceptions import AuthError, BadInputError, ApiError
            from dropbox.files import (UploadSessionCursor, CommitInfo,
                                       WriteMode, GetMetadataError,
                                       DeleteError, UploadSessionLookupError,
                                       ListFolderError)
            from dropbox.oauth import DropboxOAuth2FlowNoRedirect
        except ImportError as e:
            raise BackendException(u"""\
This backend requires the dropbox package version 6.9.0
To install use "sudo pip install dropbox==6.9.0"
Exception: %s""" % str(e))

        self.api_account = None
        self.api_client = None
        self.auth_flow = None

        self.login()

    def user_authenticated(self):
        try:
            account = self.api_client.users_get_current_account()
            log.Debug(u"User authenticated as ,%s" % account)
            return True
        except:
            log.Debug(u'User not authenticated')
            return False

    def load_access_token(self):
        return os.environ.get(u'DPBX_ACCESS_TOKEN', None)

    def save_access_token(self, access_token):
        raise BackendException(u'dpbx: Please set DPBX_ACCESS_TOKEN=\"%s\" environment variable' %
                               access_token)

    def obtain_access_token(self):
        log.Info(u"dpbx: trying to obtain access token")
        for env_var in [u'DPBX_APP_KEY', u'DPBX_APP_SECRET']:
            if env_var not in os.environ:
                raise BackendException(u'dpbx: %s environment variable not set' % env_var)

        app_key = os.environ[u'DPBX_APP_KEY']
        app_secret = os.environ[u'DPBX_APP_SECRET']

        if not sys.stdout.isatty() or not sys.stdin.isatty():
            log.FatalError(u'dpbx error: cannot interact, but need human attention',
                           log.ErrorCode.backend_command_error)

        auth_flow = DropboxOAuth2FlowNoRedirect(app_key, app_secret)
        log.Debug(u'dpbx,auth_flow.start()')
        authorize_url = auth_flow.start()
        print()
        print(u'-' * 72)
        print(u"1. Go to: " + authorize_url)
        print(u"2. Click \"Allow\" (you might have to log in first).")
        print(u"3. Copy the authorization code.")
        print(u'-' * 72)
        auth_code = input(u"Enter the authorization code here: ").strip()
        try:
            log.Debug(u'dpbx,auth_flow.finish(%s)' % auth_code)
            authresult = auth_flow.finish(auth_code)
        except Exception as e:
            raise BackendException(u'dpbx: Unable to obtain access token: %s' % e)
        log.Info(u"dpbx: Authentication successfull")
        self.save_access_token(authresult.access_token)

    def login(self):
        if self.load_access_token() is None:
            self.obtain_access_token()

        self.api_client = Dropbox(self.load_access_token())
        self.api_account = None
        try:
            log.Debug(u'dpbx,users_get_current_account([token])')
            self.api_account = self.api_client.users_get_current_account()
            log.Debug(u"dpbx,%s" % self.api_account)

        except (BadInputError, AuthError) as e:
            log.Debug(u'dpbx,exception: %s' % e)
            log.Info(u"dpbx: Authentication failed. Trying to obtain new access token")

            self.obtain_access_token()

            # We're assuming obtain_access_token will throw exception.
            # So this line should not be reached
            raise BackendException(u"dpbx: Please update DPBX_ACCESS_TOKEN and try again")

        log.Info(u"dpbx: Successfully authenticated as %s" %
                 self.api_account.name.display_name)

    def _error_code(self, operation, e):  # pylint: disable=unused-argument
        if isinstance(e, ApiError):
            err = e.error

            if isinstance(err, GetMetadataError) and err.is_path():
                if err.get_path().is_not_found():
                    return log.ErrorCode.backend_not_found
            elif isinstance(err, DeleteError) and err.is_path_lookup():
                lookup = e.error.get_path_lookup()
                if lookup.is_not_found():
                    return log.ErrorCode.backend_not_found

    @command()
    def _put(self, source_path, remote_filename):
        remote_dir = urllib.parse.unquote(self.parsed_url.path.lstrip(u'/'))
        remote_path = u'/' + os.path.join(remote_dir, remote_filename.decode()).rstrip()

        file_size = os.path.getsize(source_path.name)
        progress.report_transfer(0, file_size)

        if file_size < DPBX_UPLOAD_CHUNK_SIZE:
            # Upload whole file at once to avoid extra server request
            res_metadata = self.put_file_small(source_path, remote_path)
        else:
            res_metadata = self.put_file_chunked(source_path, remote_path)

        # A few sanity checks
        if res_metadata.path_display != remote_path:
            raise BackendException(u'dpbx: result path mismatch: %s (expected: %s)' %
                                   (res_metadata.path_display, remote_path))
        if res_metadata.size != file_size:
            raise BackendException(u'dpbx: result size mismatch: %s (expected: %s)' %
                                   (res_metadata.size, file_size))

    def put_file_small(self, source_path, remote_path):
        if not self.user_authenticated():
            self.login()

        file_size = os.path.getsize(source_path.name)
        f = source_path.open(u'rb')
        try:
            log.Debug(u'dpbx,files_upload(%s, [%d bytes])' % (remote_path, file_size))

            res_metadata = self.api_client.files_upload(f.read(), remote_path,
                                                        mode=WriteMode.overwrite,
                                                        autorename=False,
                                                        client_modified=None,
                                                        mute=True)
            log.Debug(u'dpbx,files_upload(): %s' % res_metadata)
            progress.report_transfer(file_size, file_size)
            return res_metadata
        finally:
            f.close()

    def put_file_chunked(self, source_path, remote_path):
        if not self.user_authenticated():
            self.login()

        file_size = os.path.getsize(source_path.name)
        f = source_path.open(u'rb')
        try:
            buf = f.read(DPBX_UPLOAD_CHUNK_SIZE)
            log.Debug(u'dpbx,files_upload_session_start([%d bytes]), total: %d' %
                      (len(buf), file_size))
            upload_sid = self.api_client.files_upload_session_start(buf)
            log.Debug(u'dpbx,files_upload_session_start(): %s' % upload_sid)
            upload_cursor = UploadSessionCursor(upload_sid.session_id, f.tell())
            commit_info = CommitInfo(remote_path, mode=WriteMode.overwrite,
                                     autorename=False, client_modified=None,
                                     mute=True)
            res_metadata = None
            progress.report_transfer(f.tell(), file_size)

            requested_offset = None
            current_chunk_size = DPBX_UPLOAD_CHUNK_SIZE
            retry_number = config.num_retries
            is_eof = False

            # We're doing our own error handling and retrying logic because
            # we can benefit from Dpbx chunked upload and retry only failed
            # chunk
            while not is_eof or not res_metadata:
                try:
                    if requested_offset is not None:
                        upload_cursor.offset = requested_offset

                    if f.tell() != upload_cursor.offset:
                        f.seek(upload_cursor.offset)
                    buf = f.read(current_chunk_size)

                    is_eof = f.tell() >= file_size
                    if not is_eof and len(buf) == 0:
                        continue

                    # reset temporary status variables
                    requested_offset = None
                    current_chunk_size = DPBX_UPLOAD_CHUNK_SIZE
                    retry_number = config.num_retries

                    if not is_eof:
                        assert len(buf) != 0
                        log.Debug(u'dpbx,files_upload_sesssion_append([%d bytes], offset=%d)' %
                                  (len(buf), upload_cursor.offset))
                        self.api_client.files_upload_session_append(buf,
                                                                    upload_cursor.session_id,
                                                                    upload_cursor.offset)
                    else:
                        log.Debug(u'dpbx,files_upload_sesssion_finish([%d bytes], offset=%d)' %
                                  (len(buf), upload_cursor.offset))
                        res_metadata = self.api_client.files_upload_session_finish(buf,
                                                                                   upload_cursor,
                                                                                   commit_info)

                    upload_cursor.offset = f.tell()
                    log.Debug(u'progress: %d of %d' % (upload_cursor.offset,
                                                       file_size))
                    progress.report_transfer(upload_cursor.offset, file_size)
                except ApiError as e:
                    error = e.error
                    if isinstance(error, UploadSessionLookupError) and error.is_incorrect_offset():
                        # Server reports that we should send another chunk.
                        # Most likely this is caused by network error during
                        # previous upload attempt. In such case we'll get
                        # expected offset from server and it's enough to just
                        # seek() and retry again
                        new_offset = error.get_incorrect_offset().correct_offset
                        log.Debug(u'dpbx,files_upload_session_append: incorrect offset: %d (expected: %s)' %
                                  (upload_cursor.offset, new_offset))
                        if requested_offset is not None:
                            # chunk failed even after seek attempt. Something
                            # strange and no safe way to recover
                            raise BackendException(u"dpbx: unable to chunk upload")
                        else:
                            # will seek and retry
                            requested_offset = new_offset
                        continue
                    raise
                except ConnectionError as e:
                    log.Debug(u'dpbx,files_upload_session_append: %s' % e)

                    retry_number -= 1

                    if not self.user_authenticated():
                        self.login()

                    if retry_number == 0:
                        raise

                    # We don't know for sure, was partial upload successful or
                    # not. So it's better to retry smaller amount to avoid extra
                    # reupload
                    log.Info(u'dpbx: sleeping a bit before chunk retry')
                    time.sleep(30)
                    current_chunk_size = DPBX_UPLOAD_CHUNK_SIZE / 5
                    requested_offset = None
                    continue

            if f.tell() != file_size:
                raise BackendException(u'dpbx: something wrong')

            log.Debug(u'dpbx,files_upload_sesssion_finish(): %s' % res_metadata)
            progress.report_transfer(f.tell(), file_size)

            return res_metadata

        finally:
            f.close()

    @command()
    def _get(self, remote_filename, local_path):
        if not self.user_authenticated():
            self.login()

        remote_dir = urllib.parse.unquote(self.parsed_url.path.lstrip(u'/'))
        remote_path = u'/' + os.path.join(remote_dir, remote_filename.decode()).rstrip()

        log.Debug(u'dpbx,files_download(%s)' % remote_path)
        res_metadata, http_fd = self.api_client.files_download(remote_path)
        log.Debug(u'dpbx,files_download(%s): %s, %s' % (remote_path, res_metadata,
                                                        http_fd))
        file_size = res_metadata.size
        to_fd = None
        progress.report_transfer(0, file_size)
        try:
            to_fd = local_path.open(u'wb')
            for c in http_fd.iter_content(DPBX_DOWNLOAD_BUF_SIZE):
                to_fd.write(c)
                progress.report_transfer(to_fd.tell(), file_size)

        finally:
            if to_fd:
                to_fd.close()
            http_fd.close()

        # It's different from _query() check because we're not querying metadata
        # again. Since this check is free, it's better to have it here
        local_size = os.path.getsize(local_path.name)
        if local_size != file_size:
            raise BackendException(u"dpbx: wrong file size: %d (expected: %d)" %
                                   (local_size, file_size))

        local_path.setdata()

    @command()
    def _list(self):
        # Do a long listing to avoid connection reset
        if not self.user_authenticated():
            self.login()
        remote_dir = u'/' + urllib.parse.unquote(self.parsed_url.path.lstrip(u'/')).rstrip()

        log.Debug(u'dpbx.files_list_folder(%s)' % remote_dir)
        res = []
        try:
            resp = self.api_client.files_list_folder(remote_dir)
            log.Debug(u'dpbx.list(%s): %s' % (remote_dir, resp))

            while True:
                res.extend([entry.name for entry in resp.entries])
                if not resp.has_more:
                    break
                resp = self.api_client.files_list_folder_continue(resp.cursor)
        except ApiError as e:
            if (isinstance(e.error, ListFolderError) and e.error.is_path() and
                    e.error.get_path().is_not_found()):
                log.Debug(u'dpbx.list(%s): ignore missing folder (%s)' % (remote_dir, e))
            else:
                raise

        # Warn users of old version dpbx about automatically renamed files
        self.check_renamed_files(res)

        return res

    @command()
    def _delete(self, filename):
        if not self.user_authenticated():
            self.login()

        remote_dir = urllib.parse.unquote(self.parsed_url.path.lstrip(u'/'))
        remote_path = u'/' + os.path.join(remote_dir, filename.decode()).rstrip()

        log.Debug(u'dpbx.files_delete(%s)' % remote_path)
        self.api_client.files_delete(remote_path)

        # files_permanently_delete seems to be better for backup purpose
        # but it's only available for Business accounts
        # self.api_client.files_permanently_delete(remote_path)

    @command()
    def _close(self):
        u"""close backend session? no! just "flush" the data"""
        log.Debug(u'dpbx.close():')

    @command()
    def _query(self, filename):
        if not self.user_authenticated():
            self.login()
        remote_dir = urllib.parse.unquote(self.parsed_url.path.lstrip(u'/'))
        remote_path = u'/' + os.path.join(remote_dir, filename.decode()).rstrip()

        log.Debug(u'dpbx.files_get_metadata(%s)' % remote_path)
        info = self.api_client.files_get_metadata(remote_path)
        log.Debug(u'dpbx.files_get_metadata(%s): %s' % (remote_path, info))
        return {u'size': info.size}

    def check_renamed_files(self, file_list):
        if not self.user_authenticated():
            self.login()
        bad_list = [x for x in file_list if DPBX_AUTORENAMED_FILE_RE.search(x) is not None]
        if len(bad_list) == 0:
            return
        log.Warn(u'-' * 72)
        log.Warn(u'Warning! It looks like there are automatically renamed files on backend')
        log.Warn(u'They were probably created when using older version of duplicity.')
        log.Warn(u'')
        log.Warn(u'Please check your backup consistency. Most likely you will need to choose')
        log.Warn(u'largest file from duplicity-* (number).gpg and remove brackets from its name.')
        log.Warn(u'')
        log.Warn(u'These files are not managed by duplicity at all and will not be')
        log.Warn(u'removed/rotated automatically.')
        log.Warn(u'')
        log.Warn(u'Affected files:')
        for x in bad_list:
            log.Warn(u'\t%s' % x)
        log.Warn(u'')
        log.Warn(u'In any case it\'s better to create full backup.')
        log.Warn(u'-' * 72)


duplicity.backend.register_backend(u"dpbx", DPBXBackend)
