# -*- Mode:Python; indent-tabs-mode:nil; tab-width:4; encoding:utf8 -*-
#
# Copyright (c) 2014 Gu1
# Licensed under the MIT license

from __future__ import print_function
from future import standard_library
standard_library.install_aliases()
from builtins import str

import configparser
import os
import re
import time
import urllib.parse  # pylint: disable=import-error

from requests.compat import quote, quote_plus
import requests


OAUTH_ENDPOINT = u"https://api.hubic.com/oauth/"
API_ENDPOINT = u"https://api.hubic.com/1.0/"
TOKENS_FILE = os.path.expanduser(u"~/.hubic_tokens")


class BearerTokenAuth(requests.auth.AuthBase):
    def __init__(self, token):
        self.token = token

    def __call__(self, req):
        req.headers[u'Authorization'] = u'Bearer ' + self.token
        return req


class HubicIdentity(BaseIdentity):
    def __init__(self):
        try:
            from pyrax.base_identity import BaseIdentity, Service
            import pyrax
            import pyrax.exceptions as exc
        except ImportError as e:
            raise BackendException(u"""\
Hubic backend requires the pyrax library available from Rackspace.
Exception: %s""" % str(e))

    def _get_auth_endpoint(self):
        return u""

    def set_credentials(self, email, password, client_id,
                        client_secret, redirect_uri,
                        authenticate=False):
        u"""Sets the username and password directly."""
        self._email = email
        self._password = password
        self._client_id = client_id
        self.tenant_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri
        if authenticate:
            self.authenticate()

    def _read_credential_file(self, cfg):
        u"""
        Parses the credential file with Rackspace-specific labels.
        """
        self._email = cfg.get(u"hubic", u"email")
        self._password = cfg.get(u"hubic", u"password")
        self._client_id = cfg.get(u"hubic", u"client_id")
        self.tenant_id = self._client_id
        self._client_secret = cfg.get(u"hubic", u"client_secret")
        self._redirect_uri = cfg.get(u"hubic", u"redirect_uri")

    def _parse_error(self, resp):
        if u'location' not in resp.headers:
            return None
        query = urllib.parse.urlsplit(resp.headers[u'location']).query
        qs = dict(urllib.parse.parse_qsl(query))
        return {u'error': qs[u'error'], u'error_description': qs[u'error_description']}

    def _get_access_token(self, code):
        r = requests.post(
            OAUTH_ENDPOINT + u'token/',
            data={
                u'code': code,
                u'redirect_uri': self._redirect_uri,
                u'grant_type': u'authorization_code',
            },
            auth=(self._client_id, self._client_secret)
        )
        if r.status_code != 200:
            try:
                err = r.json()
                err[u'code'] = r.status_code
            except:
                err = {}

            raise exc.AuthenticationFailed(u"Unable to get oauth access token, "
                                           u"wrong client_id or client_secret ? (%s)" %
                                           str(err))

        oauth_token = r.json()

        config = configparser.ConfigParser()
        config.read(TOKENS_FILE)

        if not config.has_section(u"hubic"):
            config.add_section(u"hubic")

        if oauth_token[u'access_token'] is not None:
            config.set(u"hubic", u"access_token", oauth_token[u'access_token'])
            with open(TOKENS_FILE, u'wb') as configfile:
                config.write(configfile)
        else:
            raise exc.AuthenticationFailed(
                u"Unable to get oauth access token, wrong client_id or client_secret ? (%s)" %
                str(err))

        if oauth_token[u'refresh_token'] is not None:
            config.set(u"hubic", u"refresh_token", oauth_token[u'refresh_token'])
            with open(TOKENS_FILE, u'wb') as configfile:
                config.write(configfile)
        else:
            raise exc.AuthenticationFailed(u"Unable to get the refresh token.")

        # removing username and password from .hubic_tokens
        if config.has_option(u"hubic", u"email"):
            config.remove_option(u"hubic", u"email")
            with open(TOKENS_FILE, u'wb') as configfile:
                config.write(configfile)
            print(u"username has been removed from the .hubic_tokens file sent to the CE.")
        if config.has_option(u"hubic", u"password"):
            config.remove_option(u"hubic", u"password")
            with open(TOKENS_FILE, u'wb') as configfile:
                config.write(configfile)
            print(u"password has been removed from the .hubic_tokens file sent to the CE.")

        return oauth_token

    def _refresh_access_token(self):

        config = configparser.ConfigParser()
        config.read(TOKENS_FILE)
        refresh_token = config.get(u"hubic", u"refresh_token")

        if refresh_token is None:
            raise exc.AuthenticationFailed(u"refresh_token is null. Not acquiered before ?")

        success = False
        max_retries = 20
        retries = 0
        sleep_time = 30
        max_sleep_time = 3600

        while retries < max_retries and not success:
            r = requests.post(
                OAUTH_ENDPOINT + u'token/',
                data={
                    u'refresh_token': refresh_token,
                    u'grant_type': u'refresh_token',
                },
                auth=(self._client_id, self._client_secret)
            )
            if r.status_code != 200:
                if r.status_code == 509:
                    print(u"status_code 509: attempt #", retries, u" failed")
                    retries += 1
                    time.sleep(sleep_time)
                    sleep_time = sleep_time * 2
                    if sleep_time > max_sleep_time:
                        sleep_time = max_sleep_time
                else:
                    try:
                        err = r.json()
                        err[u'code'] = r.status_code
                    except:
                        err = {}

                    raise exc.AuthenticationFailed(
                        u"Unable to get oauth access token, wrong client_id or client_secret ? (%s)" %
                        str(err))
            else:
                success = True

        if not success:
            raise exc.AuthenticationFailed(
                u"All the attempts failed to get the refresh token: "
                u"status_code = 509: Bandwidth Limit Exceeded")

        oauth_token = r.json()

        if oauth_token[u'access_token'] is not None:
            return oauth_token
        else:
            raise exc.AuthenticationFailed(u"Unable to get oauth access token from json")

    def authenticate(self):
        config = configparser.ConfigParser()
        config.read(TOKENS_FILE)

        if config.has_option(u"hubic", u"refresh_token"):
            oauth_token = self._refresh_access_token()
        else:
            r = requests.get(
                OAUTH_ENDPOINT + u'auth/?client_id={0}&redirect_uri={1}'
                u'&scope=credentials.r,account.r&response_type=code&state={2}'.format(
                    quote(self._client_id),
                    quote_plus(self._redirect_uri),
                    pyrax.utils.random_ascii()  # csrf ? wut ?..
                ),
                allow_redirects=False
            )
            if r.status_code != 200:
                raise exc.AuthenticationFailed(u"Incorrect/unauthorized "
                                               u"client_id (%s)" % str(self._parse_error(r)))

            try:
                from lxml import html as lxml_html
            except ImportError:
                lxml_html = None

            if lxml_html:
                oauth = lxml_html.document_fromstring(r.content).xpath(u'//input[@name="oauth"]')
                oauth = oauth[0].value if oauth else None
            else:
                oauth = re.search(
                    r'<input\s+[^>]*name=[\'"]?oauth[\'"]?\s+[^>]*value=[\'"]?(\d+)[\'"]?>',
                    r.content)
                oauth = oauth.group(1) if oauth else None

            if not oauth:
                raise exc.AuthenticationFailed(u"Unable to get oauth_id from authorization page")

            if self._email is None or self._password is None:
                raise exc.AuthenticationFailed(u"Cannot retrieve email and/or password. "
                                               u"Please run expresslane-hubic-setup.sh")

            r = requests.post(
                OAUTH_ENDPOINT + u'auth/',
                data={
                    u'action': u'accepted',
                    u'oauth': oauth,
                    u'login': self._email,
                    u'user_pwd': self._password,
                    u'account': u'r',
                    u'credentials': u'r',

                },
                allow_redirects=False
            )

            try:
                query = urllib.parse.urlsplit(r.headers[u'location']).query
                code = dict(urllib.parse.parse_qsl(query))[u'code']
            except:
                raise exc.AuthenticationFailed(u"Unable to authorize client_id, "
                                               u"invalid login/password ?")

            oauth_token = self._get_access_token(code)

        if oauth_token[u'token_type'].lower() != u'bearer':
            raise exc.AuthenticationFailed(u"Unsupported access token type")

        r = requests.get(
            API_ENDPOINT + u'account/credentials',
            auth=BearerTokenAuth(oauth_token[u'access_token']),
        )

        swift_token = r.json()
        self.authenticated = True
        self.token = swift_token[u'token']
        self.expires = swift_token[u'expires']
        self.services[u'object_store'] = Service(self, {
            u'name': u'HubiC',
            u'type': u'cloudfiles',
            u'endpoints': [
                {u'public_url': swift_token[u'endpoint']}
            ]
        })
        self.username = self.password = None
