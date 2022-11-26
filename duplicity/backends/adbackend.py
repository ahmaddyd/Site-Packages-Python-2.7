# -*- Mode:Python; indent-tabs-mode:nil; tab-width:4; encoding:utf8 -*-
#
# Copyright 2016 Stefan Breunig <stefan-duplicity@breunig.xyz>
# Based on the backend onedrivebackend.py
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
from builtins import input
import os.path
import json
import sys
import time
import re
from io import DEFAULT_BUFFER_SIZE

import duplicity.backend
from duplicity.errors import BackendException
from duplicity import config
from duplicity import log


class ADBackend(duplicity.backend.Backend):
    u"""
    Backend for Amazon Drive. It communicates directly with Amazon Drive using
    their RESTful API and does not rely on externally setup software (like
    acd_cli).
    """

    OAUTH_TOKEN_PATH = os.path.expanduser(u'~/.duplicity_ad_oauthtoken.json')

    OAUTH_AUTHORIZE_URL = u'https://www.amazon.com/ap/oa'
    OAUTH_TOKEN_URL = u'https://api.amazon.com/auth/o2/token'
    # NOTE: Amazon requires https, which is why I am using my domain/setup
    # instead of Duplicity's. Mail me at stefan-duplicity@breunig.xyz once it is
    # available through https and I will whitelist the new URL.
    OAUTH_REDIRECT_URL = u'https://breunig.xyz/duplicity/copy.html'
    OAUTH_SCOPE = [u'clouddrive:read_other', u'clouddrive:write']

    CLIENT_ID = u'amzn1.application-oa2-client.791c9c2d78444e85a32eb66f92eb6bcc'
    CLIENT_SECRET = u'5b322c6a37b25f16d848a6a556eddcc30314fc46ae65c87068ff1bc4588d715b'

    MULTIPART_BOUNDARY = u'DuplicityFormBoundaryd66364f7f8924f7e9d478e19cf4b871d114a1e00262542'

    def __init__(self, parsed_url):
        duplicity.backend.Backend.__init__(self, parsed_url)

        self.metadata_url = u'https://drive.amazonaws.com/drive/v1/'
        self.content_url = u'https://content-na.drive.amazonaws.com/cdproxy/'

        self.names_to_ids = {}
        self.backup_target_id = None
        self.backup_target = parsed_url.path.lstrip(u'/')

        if config.volsize > (10 * 1024 * 1024 * 1024):
            # https://forums.developer.amazon.com/questions/22713/file-size-limits.html
            # https://forums.developer.amazon.com/questions/22038/support-for-chunked-transfer-encoding.html
            log.FatalError(
                u'Your --volsize is bigger than 10 GiB, which is the maximum '
                u'file size on Amazon Drive that does not require work arounds.')

        try:
            global requests
            global OAuth2Session
            import requests
            from requests_oauthlib import OAuth2Session
        except ImportError:
            raise BackendException(
                u'Amazon Drive backend requires python-requests and '
                u'python-requests-oauthlib to be installed.\n\n'
                u'For Debian and derivates use:\n'
                u'  apt-get install python-requests python-requests-oauthlib\n'
                u'For Fedora and derivates use:\n'
                u'  yum install python-requests python-requests-oauthlib')

        self.initialize_oauth2_session()
        self.resolve_backup_target()

    def initialize_oauth2_session(self):
        u"""Setup or refresh oauth2 session with Amazon Drive"""

        def token_updater(token):
            u"""Stores oauth2 token on disk"""
            try:
                with open(self.OAUTH_TOKEN_PATH, u'w') as f:
                    json.dump(token, f)
            except Exception as err:
                log.Error(u'Could not save the OAuth2 token to %s. This means '
                          u'you may need to do the OAuth2 authorization '
                          u'process again soon. Original error: %s' % (
                              self.OAUTH_TOKEN_PATH, err))

        token = None
        try:
            with open(self.OAUTH_TOKEN_PATH) as f:
                token = json.load(f)
        except IOError as err:
            log.Notice(u'Could not load OAuth2 token. '
                       u'Trying to create a new one. (original error: %s)' % err)

        self.http_client = OAuth2Session(
            self.CLIENT_ID,
            scope=self.OAUTH_SCOPE,
            redirect_uri=self.OAUTH_REDIRECT_URL,
            token=token,
            auto_refresh_kwargs={
                u'client_id': self.CLIENT_ID,
                u'client_secret': self.CLIENT_SECRET,
            },
            auto_refresh_url=self.OAUTH_TOKEN_URL,
            token_updater=token_updater)

        if token is not None:
            self.http_client.refresh_token(self.OAUTH_TOKEN_URL)

        endpoints_response = self.http_client.get(self.metadata_url +
                                                  u'account/endpoint')
        if endpoints_response.status_code != requests.codes.ok:
            token = None

        if token is None:
            if not sys.stdout.isatty() or not sys.stdin.isatty():
                log.FatalError(u'The OAuth2 token could not be loaded from %s '
                               u'and you are not running duplicity '
                               u'interactively, so duplicity cannot possibly '
                               u'access Amazon Drive.' % self.OAUTH_TOKEN_PATH)
            authorization_url, _ = self.http_client.authorization_url(
                self.OAUTH_AUTHORIZE_URL)

            print(u'')
            print(u'In order to allow duplicity to access Amazon Drive, please '
                  u'open the following URL in a browser and copy the URL of the '
                  u'page you see after authorization here:')
            print(authorization_url)
            print(u'')

            redirected_to = (input(u'URL of the resulting page: ')
                             .replace(u'http://', u'https://', 1)).strip()

            token = self.http_client.fetch_token(
                self.OAUTH_TOKEN_URL,
                client_secret=self.CLIENT_SECRET,
                authorization_response=redirected_to)

            endpoints_response = self.http_client.get(self.metadata_url +
                                                      u'account/endpoint')
            endpoints_response.raise_for_status()
            token_updater(token)

        urls = endpoints_response.json()
        if u'metadataUrl' not in urls or u'contentUrl' not in urls:
            log.FatalError(u'Could not retrieve endpoint URLs for this account')
        self.metadata_url = urls[u'metadataUrl']
        self.content_url = urls[u'contentUrl']

    def resolve_backup_target(self):
        u"""Resolve node id for remote backup target folder"""

        response = self.http_client.get(
            self.metadata_url + u'nodes?filters=kind:FOLDER AND isRoot:true')
        parent_node_id = response.json()[u'data'][0][u'id']

        for component in [x for x in self.backup_target.split(u'/') if x]:
            # There doesn't seem to be escaping support, so cut off filter
            # after first unsupported character
            query = re.search(u'^[A-Za-z0-9_-]*', component).group(0)
            if component != query:
                query = query + u'*'

            matches = self.read_all_pages(
                self.metadata_url + u'nodes?filters=kind:FOLDER AND name:%s '
                                    u'AND parents:%s' % (query, parent_node_id))
            candidates = [f for f in matches if f.get(u'name') == component]

            if len(candidates) >= 2:
                log.FatalError(u'There are multiple folders with the same name '
                               u'below one parent.\nParentID: %s\nFolderName: '
                               u'%s' % (parent_node_id, component))
            elif len(candidates) == 1:
                parent_node_id = candidates[0][u'id']
            else:
                log.Debug(u'Folder %s does not exist yet. Creating.' % component)
                parent_node_id = self.mkdir(parent_node_id, component)

        log.Debug(u"Backup target folder has id: %s" % parent_node_id)
        self.backup_target_id = parent_node_id

    def get_file_id(self, remote_filename):
        u"""Find id of remote file in backup target folder"""

        if remote_filename not in self.names_to_ids:
            self._list()

        return self.names_to_ids.get(remote_filename)

    def mkdir(self, parent_node_id, folder_name):
        u"""Create a new folder as a child of a parent node"""

        data = {u'name': folder_name, u'parents': [parent_node_id], u'kind': u'FOLDER'}
        response = self.http_client.post(
            self.metadata_url + u'nodes',
            data=json.dumps(data))
        response.raise_for_status()
        return response.json()[u'id']

    def multipart_stream(self, metadata, source_path):
        u"""Generator for multipart/form-data file upload from source file"""

        boundary = self.MULTIPART_BOUNDARY

        yield str.encode(u'--%s\r\nContent-Disposition: form-data; '
                         u'name="metadata"\r\n\r\n' % boundary +
                         u'%s\r\n' % json.dumps(metadata) +
                         u'--%s\r\n' % boundary)
        yield b'Content-Disposition: form-data; name="content"; filename="i_love_backups"\r\n'
        yield b'Content-Type: application/octet-stream\r\n\r\n'

        with source_path.open() as stream:
            while True:
                f = stream.read(DEFAULT_BUFFER_SIZE)
                if f:
                    yield f
                else:
                    break

        yield str.encode(u'\r\n--%s--\r\n' % boundary +
                         u'multipart/form-data; boundary=%s' % boundary)

    def read_all_pages(self, url):
        u"""Iterates over nodes API URL until all pages were read"""

        result = []
        next_token = u''
        token_param = u'&startToken=' if u'?' in url else u'?startToken='

        while True:
            paginated_url = url + token_param + next_token
            response = self.http_client.get(paginated_url)
            if response.status_code != 200:
                raise BackendException(u"Pagination failed with status=%s on "
                                       u"URL=%s" % (response.status_code, url))

            parsed = response.json()
            if u'data' in parsed and len(parsed[u'data']) > 0:
                result.extend(parsed[u'data'])
            else:
                break

            # Do not make another HTTP request if everything is here already
            if len(result) >= parsed[u'count']:
                break

            if u'nextToken' not in parsed:
                break
            next_token = parsed[u'nextToken']

        return result

    def raise_for_existing_file(self, remote_filename):
        u"""Report error when file already existed in location and delete it"""

        self._delete(remote_filename)
        raise BackendException(u'Upload failed, because there was a file with '
                               u'the same name as %s already present. The file was '
                               u'deleted, and duplicity will retry the upload unless '
                               u'the retry limit has been reached.' % remote_filename)

    def _put(self, source_path, remote_filename):
        u"""Upload a local file to Amazon Drive"""

        quota = self.http_client.get(self.metadata_url + u'account/quota')
        quota.raise_for_status()
        available = quota.json()[u'available']

        source_size = os.path.getsize(source_path.name)

        if source_size > available:
            raise BackendException(
                u'Out of space: trying to store "%s" (%d bytes), but only '
                u'%d bytes available on Amazon Drive.' % (
                    source_path.name, source_size, available))

        # Just check the cached list, to avoid _list for every new file being
        # uploaded
        if remote_filename in self.names_to_ids:
            log.Debug(u'File %s seems to already exist on Amazon Drive. Deleting '
                      u'before attempting to upload it again.' % remote_filename)
            self._delete(remote_filename)

        metadata = {u'name': remote_filename, u'kind': u'FILE',
                    u'parents': [self.backup_target_id]}
        headers = {u'Content-Type': u'multipart/form-data; boundary=%s' % self.MULTIPART_BOUNDARY}
        data = self.multipart_stream(metadata, source_path)

        response = self.http_client.post(
            self.content_url + u'nodes?suppress=deduplication',
            data=data,
            headers=headers)

        if response.status_code == 409:  # "409 : Duplicate file exists."
            self.raise_for_existing_file(remote_filename)
        elif response.status_code == 201:
            log.Debug(u'%s uploaded successfully' % remote_filename)
        elif response.status_code == 408 or response.status_code == 504:
            log.Info(u'%s upload failed with timeout status code=%d. Speculatively '
                     u'waiting for %d seconds to see if Amazon Drive finished the '
                     u'upload anyway' % (remote_filename, response.status_code,
                                         config.timeout))
            tries = config.timeout / 15
            while tries >= 0:
                tries -= 1
                time.sleep(15)

                remote_size = self._query(remote_filename)[u'size']
                if source_size == remote_size:
                    log.Debug(u'Upload turned out to be successful after all.')
                    return
                elif remote_size == -1:
                    log.Debug(u'Uploaded file is not yet there, %d tries left.'
                              % (tries + 1))
                    continue
                else:
                    self.raise_for_existing_file(remote_filename)
            raise BackendException(u'%s upload failed and file did not show up '
                                   u'within time limit.' % remote_filename)
        else:
            log.Debug(u'%s upload returned an undesirable status code %s'
                      % (remote_filename, response.status_code))
            response.raise_for_status()

        parsed = response.json()
        if u'id' not in parsed:
            raise BackendException(u'%s was uploaded, but returned JSON does not '
                                   u'contain ID of new file. Retrying.\nJSON:\n\n%s'
                                   % (remote_filename, parsed))

        # XXX: The upload may be considered finished before the file shows up
        # in the file listing. As such, the following is required to avoid race
        # conditions when duplicity calls _query or _list.
        self.names_to_ids[parsed[u'name']] = parsed[u'id']

    def _get(self, remote_filename, local_path):
        u"""Download file from Amazon Drive"""

        with local_path.open(u'wb') as local_file:
            file_id = self.get_file_id(remote_filename)
            if file_id is None:
                raise BackendException(
                    u'File "%s" cannot be downloaded: it does not exist' %
                    remote_filename)

            response = self.http_client.get(
                self.content_url + u'/nodes/' + file_id + u'/content', stream=True)
            response.raise_for_status()
            for chunk in response.iter_content(chunk_size=DEFAULT_BUFFER_SIZE):
                if chunk:
                    local_file.write(chunk)
            local_file.flush()

    def _query(self, remote_filename):
        u"""Retrieve file size info from Amazon Drive"""

        file_id = self.get_file_id(remote_filename)
        if file_id is None:
            return {u'size': -1}
        response = self.http_client.get(self.metadata_url + u'nodes/' + file_id)
        response.raise_for_status()

        return {u'size': response.json()[u'contentProperties'][u'size']}

    def _list(self):
        u"""List files in Amazon Drive backup folder"""

        files = self.read_all_pages(
            self.metadata_url + u'nodes/' + self.backup_target_id +
            u'/children?filters=kind:FILE')

        self.names_to_ids = {f[u'name']: f[u'id'] for f in files}

        return list(self.names_to_ids.keys())

    def _delete(self, remote_filename):
        u"""Delete file from Amazon Drive"""

        file_id = self.get_file_id(remote_filename)
        if file_id is None:
            raise BackendException(
                u'File "%s" cannot be deleted: it does not exist' % (
                    remote_filename))
        response = self.http_client.put(self.metadata_url + u'trash/' + file_id)
        response.raise_for_status()
        del self.names_to_ids[remote_filename]


duplicity.backend.register_backend(u'ad', ADBackend)
