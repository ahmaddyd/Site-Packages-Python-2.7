# -*- Mode:Python; indent-tabs-mode:nil; tab-width:4; encoding:utf8 -*-
# vim:tabstop=4:shiftwidth=4:expandtab
#
# Copyright 2014 Google Inc.
# Contact Michael Stapelberg <stapelberg+duplicity@google.com>
# This is NOT a Google product.
# Revised for Microsoft Graph API 2019 by David Martin
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
from past.utils import old_div
from builtins import input
from builtins import str
import time
import json
import os
import sys

import duplicity.backend
from duplicity.errors import BackendException
from duplicity import config
from duplicity import log

# For documentation on the API, see
# The previous Live SDK API required the use of opaque folder IDs to navigate paths, but the Microsoft Graph
# API allows the use of parent/child/grandchild pathnames.
# Old Live SDK API: https://docs.microsoft.com/en-us/previous-versions/office/developer/onedrive-live-sdk/dn659731(v%3doffice.15)  # noqa
# Files API: https://docs.microsoft.com/en-us/graph/api/resources/onedrive?view=graph-rest-1.0
# Large file upload API: https://docs.microsoft.com/en-us/onedrive/developer/rest-api/api/driveitem_createuploadsession?view=odsp-graph-online  # noqa


class OneDriveBackend(duplicity.backend.Backend):
    u"""Uses Microsoft OneDrive (formerly SkyDrive) for backups."""

    OAUTH_TOKEN_PATH = os.path.expanduser(
        u'~/.duplicity_onedrive_oauthtoken.json')

    API_URI = u'https://graph.microsoft.com/v1.0/'
    # The large file upload API says that uploaded chunks (except the last) must be multiples of 327680 bytes.
    REQUIRED_FRAGMENT_SIZE_MULTIPLE = 327680
    CLIENT_ID = u'000000004C12E85D'
    OAUTH_TOKEN_URI = u'https://login.live.com/oauth20_token.srf'
    OAUTH_AUTHORIZE_URI = u'https://login.live.com/oauth20_authorize.srf'
    OAUTH_REDIRECT_URI = u'https://login.live.com/oauth20_desktop.srf'
    # Files.Read is for reading files,
    # Files.ReadWrite  is for creating/writing files,
    # User.Read is needed for the /me request to see if the token works.
    # offline_access is necessary for duplicity to access onedrive without
    # the user being logged in right now.
    OAUTH_SCOPE = [u'Files.Read', u'Files.ReadWrite', u'User.Read', u'offline_access']

    # OAUTHLIB_RELAX_TOKEN_SCOPE prevents the oauthlib from complaining about a mismatch between
    # the requested scope and the delivered scope. We need this because we don't get a refresh
    # token without asking for offline_access, but Microsoft Graph doesn't include offline_access
    # in its response (even though it does send a refresh_token).

    os.environ[u'OAUTHLIB_RELAX_TOKEN_SCOPE'] = u'TRUE'

    def __init__(self, parsed_url):
        duplicity.backend.Backend.__init__(self, parsed_url)

        # Import requests and requests-oauthlib
        try:
            # On debian (and derivatives), get these dependencies using:
            # apt-get install python-requests python-requests-oauthlib
            # On fedora (and derivatives), get these dependencies using:
            # yum install python-requests python-requests-oauthlib
            global requests
            global OAuth2Session
            import requests
            from requests_oauthlib import OAuth2Session
        except ImportError as e:
            raise BackendException((
                u'OneDrive backend requires python-requests and '
                u'python-requests-oauthlib to be installed. Please install '
                u'them and try again.\n' + str(e)))

        self.directory = parsed_url.path.lstrip(u'/')
        self.directory_onedrive_path = u'me/drive/root:/%s/' % self.directory
        if self.directory == u"":
            raise BackendException((
                u'You did not specify a path. '
                u'Please specify a path, e.g. onedrive://duplicity_backups'))

        if config.volsize > (10 * 1024 * 1024 * 1024):
            raise BackendException((
                u'Your --volsize is bigger than 10 GiB, which is the maximum '
                u'file size on OneDrive.'))

        self.initialize_oauth2_session()

    def initialize_oauth2_session(self):
        def token_updater(token):
            try:
                with open(self.OAUTH_TOKEN_PATH, u'w') as f:
                    json.dump(token, f)
            except Exception as e:
                log.Error((u'Could not save the OAuth2 token to %s. '
                           u'This means you may need to do the OAuth2 '
                           u'authorization process again soon. '
                           u'Original error: %s' % (
                               self.OAUTH_TOKEN_PATH, e)))

        token = None
        try:
            with open(self.OAUTH_TOKEN_PATH) as f:
                token = json.load(f)
        except IOError as e:
            log.Error((u'Could not load OAuth2 token. '
                       u'Trying to create a new one. (original error: %s)' % e))

        self.http_client = OAuth2Session(
            self.CLIENT_ID,
            scope=self.OAUTH_SCOPE,
            redirect_uri=self.OAUTH_REDIRECT_URI,
            token=token,
            auto_refresh_kwargs={
                u'client_id': self.CLIENT_ID,
            },
            auto_refresh_url=self.OAUTH_TOKEN_URI,
            token_updater=token_updater)

        # We have to refresh token manually because it's not working "under the covers"
        if token is not None:
            self.http_client.refresh_token(self.OAUTH_TOKEN_URI)

        # Send a request to make sure the token is valid (or could at least be
        # refreshed successfully, which will happen under the covers). In case
        # this request fails, the provided token was too old (i.e. expired),
        # and we need to get a new token.
        user_info_response = self.http_client.get(self.API_URI + u'me')
        if user_info_response.status_code != requests.codes.ok:
            token = None

        if token is None:
            if not sys.stdout.isatty() or not sys.stdin.isatty():
                log.FatalError((u'The OAuth2 token could not be loaded from %s '
                                u'and you are not running duplicity '
                                u'interactively, so duplicity cannot possibly '
                                u'access OneDrive.' % self.OAUTH_TOKEN_PATH))
            authorization_url, state = self.http_client.authorization_url(
                self.OAUTH_AUTHORIZE_URI, display=u'touch')

            print()
            print(u'In order to authorize duplicity to access your OneDrive, '
                  u'please open %s in a browser and copy the URL of the blank '
                  u'page the dialog leads to.' % authorization_url)
            print()

            redirected_to = input(u'URL of the blank page: ').strip()

            token = self.http_client.fetch_token(
                self.OAUTH_TOKEN_URI,
                authorization_response=redirected_to)

            user_info_response = self.http_client.get(self.API_URI + u'me')
            user_info_response.raise_for_status()

            try:
                with open(self.OAUTH_TOKEN_PATH, u'w') as f:
                    json.dump(token, f)
            except Exception as e:
                log.Error((u'Could not save the OAuth2 token to %s. '
                           u'This means you need to do the OAuth2 authorization '
                           u'process on every start of duplicity. '
                           u'Original error: %s' % (
                               self.OAUTH_TOKEN_PATH, e)))

    def _list(self):
        accum = []
        next_url = self.API_URI + self.directory_onedrive_path + u':/children'
        while True:
            response = self.http_client.get(next_url)
            if response.status_code == 404:
                # No further files here
                break
            response.raise_for_status()
            responseJson = response.json()
            if u'value' not in responseJson:
                raise BackendException((
                    u'Malformed JSON: expected "value" member in %s' % (
                        responseJson)))
            accum += responseJson[u'value']
            if u'@odata.nextLink' in responseJson:
                next_url = responseJson[u'@odata.nextLink']
            else:
                break

        return [x[u'name'] for x in accum]

    def _get(self, remote_filename, local_path):
        remote_filename = remote_filename.decode(u"UTF-8")
        with local_path.open(u'wb') as f:
            response = self.http_client.get(
                self.API_URI + self.directory_onedrive_path + remote_filename + u':/content', stream=True)
            response.raise_for_status()
            for chunk in response.iter_content(chunk_size=4096):
                if chunk:
                    f.write(chunk)
            f.flush()

    def _put(self, source_path, remote_filename):
        # Happily, the OneDrive API will lazily create the folder hierarchy required to contain a pathname

        # Check if the user has enough space available on OneDrive before even
        # attempting to upload the file.
        remote_filename = remote_filename.decode(u"UTF-8")
        source_size = os.path.getsize(source_path.name)
        start = time.time()
        response = self.http_client.get(self.API_URI + u'me/drive?$select=quota')
        response.raise_for_status()
        if (u'quota' in response.json()):
            available = response.json()[u'quota'].get(u'remaining', None)
            if available:
                log.Debug(u'Bytes available: %d' % available)
                if source_size > available:
                    raise BackendException((
                        u'Out of space: trying to store "%s" (%d bytes), but only '
                        u'%d bytes available on OneDrive.' % (
                            source_path.name, source_size,
                            available)))
        log.Debug(u"Checked quota in %fs" % (time.time() - start))

        with source_path.open() as source_file:
            start = time.time()
            url = self.API_URI + self.directory_onedrive_path + remote_filename + u':/createUploadSession'

            response = self.http_client.post(url)
            response.raise_for_status()
            response_json = json.loads(response.content.decode(u"UTF-8"))
            if u'uploadUrl' not in response_json:
                raise BackendException((
                    u'File "%s" cannot be uploaded: could not create upload session: %s' % (
                        remote_filename, response.content)))
            uploadUrl = response_json[u'uploadUrl']

            # https://docs.microsoft.com/en-us/onedrive/developer/rest-api/api/driveitem_createuploadsession?
            # indicates 10 MiB is optimal for stable high speed connections.
            offset = 0
            desired_num_fragments = old_div(10 * 1024 * 1024, self.REQUIRED_FRAGMENT_SIZE_MULTIPLE)
            while True:
                chunk = source_file.read(desired_num_fragments * self.REQUIRED_FRAGMENT_SIZE_MULTIPLE)
                if len(chunk) == 0:
                    break
                headers = {
                    u'Content-Length': u'%d' % (len(chunk)),
                    u'Content-Range': u'bytes %d-%d/%d' % (offset, offset + len(chunk) - 1, source_size),
                }
                log.Debug(u'PUT %s %s' % (remote_filename, headers[u'Content-Range']))
                response = self.http_client.put(
                    uploadUrl,
                    headers=headers,
                    data=chunk)
                response.raise_for_status()
                offset += len(chunk)

            log.Debug(u"PUT file in %fs" % (time.time() - start))

    def _delete(self, remote_filename):
        remote_filename = remote_filename.decode(u"UTF-8")
        response = self.http_client.delete(self.API_URI + self.directory_onedrive_path + remote_filename)
        if response.status_code == 404:
            raise BackendException((
                u'File "%s" cannot be deleted: it does not exist' % (
                    remote_filename)))
        response.raise_for_status()

    def _query(self, remote_filename):
        remote_filename = remote_filename.decode(u"UTF-8")
        response = self.http_client.get(self.API_URI + self.directory_onedrive_path + remote_filename)
        if response.status_code != 200:
            return {u'size': -1}
        if u'size' not in response.json():
            raise BackendException((
                u'Malformed JSON: expected "size" member in %s' % (
                    response.json())))
        return {u'size': response.json()[u'size']}

    def _retry_cleanup(self):
        self.initialize_oauth2_session()


duplicity.backend.register_backend(u'onedrive', OneDriveBackend)
