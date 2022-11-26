# -*- Mode:Python; indent-tabs-mode:nil; tab-width:4; encoding:utf8 -*-
#
# Copyright 2013 Matthieu Huin <mhu@enovance.com>
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

from builtins import str
import os
import copy

import duplicity.backend
from duplicity import config
from duplicity import log
from duplicity import util
from duplicity.errors import BackendException


class SwiftBackend(duplicity.backend.Backend):
    u"""
    Backend for Swift
    """
    def __init__(self, parsed_url):
        duplicity.backend.Backend.__init__(self, parsed_url)

        try:
            from swiftclient.service import SwiftService
            from swiftclient import Connection
            from swiftclient import ClientException
        except ImportError as e:
            raise BackendException(u"""\
Swift backend requires the python-swiftclient library.
Exception: %s""" % str(e))

        self.resp_exc = ClientException
        conn_kwargs = {}

        # if the user has already authenticated
        if u'SWIFT_PREAUTHURL' in os.environ and u'SWIFT_PREAUTHTOKEN' in os.environ:
            conn_kwargs[u'preauthurl'] = os.environ[u'SWIFT_PREAUTHURL']
            conn_kwargs[u'preauthtoken'] = os.environ[u'SWIFT_PREAUTHTOKEN']

        else:
            if u'SWIFT_USERNAME' not in os.environ:
                raise BackendException(u'SWIFT_USERNAME environment variable '
                                       u'not set.')

            if u'SWIFT_PASSWORD' not in os.environ:
                raise BackendException(u'SWIFT_PASSWORD environment variable '
                                       u'not set.')

            if u'SWIFT_AUTHURL' not in os.environ:
                raise BackendException(u'SWIFT_AUTHURL environment variable '
                                       u'not set.')

            conn_kwargs[u'user'] = os.environ[u'SWIFT_USERNAME']
            conn_kwargs[u'key'] = os.environ[u'SWIFT_PASSWORD']
            conn_kwargs[u'authurl'] = os.environ[u'SWIFT_AUTHURL']

        os_options = {}

        if u'SWIFT_AUTHVERSION' in os.environ:
            conn_kwargs[u'auth_version'] = os.environ[u'SWIFT_AUTHVERSION']
            if os.environ[u'SWIFT_AUTHVERSION'] == u'3':
                if u'SWIFT_USER_DOMAIN_NAME' in os.environ:
                    os_options.update({u'user_domain_name': os.environ[u'SWIFT_USER_DOMAIN_NAME']})
                if u'SWIFT_USER_DOMAIN_ID' in os.environ:
                    os_options.update({u'user_domain_id': os.environ[u'SWIFT_USER_DOMAIN_ID']})
                if u'SWIFT_PROJECT_DOMAIN_NAME' in os.environ:
                    os_options.update({u'project_domain_name': os.environ[u'SWIFT_PROJECT_DOMAIN_NAME']})
                if u'SWIFT_PROJECT_DOMAIN_ID' in os.environ:
                    os_options.update({u'project_domain_id': os.environ[u'SWIFT_PROJECT_DOMAIN_ID']})
                if u'SWIFT_TENANTNAME' in os.environ:
                    os_options.update({u'tenant_name': os.environ[u'SWIFT_TENANTNAME']})
                if u'SWIFT_ENDPOINT_TYPE' in os.environ:
                    os_options.update({u'endpoint_type': os.environ[u'SWIFT_ENDPOINT_TYPE']})
                if u'SWIFT_USERID' in os.environ:
                    os_options.update({u'user_id': os.environ[u'SWIFT_USERID']})
                if u'SWIFT_TENANTID' in os.environ:
                    os_options.update({u'tenant_id': os.environ[u'SWIFT_TENANTID']})
                if u'SWIFT_REGIONNAME' in os.environ:
                    os_options.update({u'region_name': os.environ[u'SWIFT_REGIONNAME']})

        else:
            conn_kwargs[u'auth_version'] = u'1'
        if u'SWIFT_TENANTNAME' in os.environ:
            conn_kwargs[u'tenant_name'] = os.environ[u'SWIFT_TENANTNAME']
        if u'SWIFT_REGIONNAME' in os.environ:
            os_options.update({u'region_name': os.environ[u'SWIFT_REGIONNAME']})

        svc_options = copy.deepcopy(os_options)
        svc_options[u'os_username'] = conn_kwargs[u'user']
        svc_options[u'os_password'] = conn_kwargs[u'key']
        svc_options[u'os_auth_url'] = conn_kwargs[u'authurl']

        conn_kwargs[u'os_options'] = os_options

        # This folds the null prefix and all null parts, which means that:
        #  //MyContainer/ and //MyContainer are equivalent.
        #  //MyContainer//My/Prefix/ and //MyContainer/My/Prefix are equivalent.
        url_parts = [x for x in parsed_url.path.split(u'/') if x != u'']

        self.container = url_parts.pop(0)
        if url_parts:
            self.prefix = u'%s/' % u'/'.join(url_parts)
        else:
            self.prefix = u''

        policy = config.swift_storage_policy
        policy_header = u'X-Storage-Policy'

        container_metadata = None
        try:
            self.conn = Connection(**conn_kwargs)
            self.svc = SwiftService(options=svc_options)
            container_metadata = self.conn.head_container(self.container)
        except ClientException:
            pass
        except Exception as e:
            log.FatalError(u"Connection failed: %s %s"
                           % (e.__class__.__name__, str(e)),
                           log.ErrorCode.connection_failed)

        if container_metadata is None:
            log.Info(u"Creating container %s" % self.container)
            try:
                headers = dict([[policy_header, policy]]) if policy else None
                self.conn.put_container(self.container, headers=headers)
            except Exception as e:
                log.FatalError(u"Container creation failed: %s %s"
                               % (e.__class__.__name__, str(e)),
                               log.ErrorCode.connection_failed)
        elif policy and container_metadata[policy_header.lower()] != policy:
            log.FatalError(u"Container '%s' exists but its storage policy is '%s' not '%s'."
                           % (self.container, container_metadata[policy_header.lower()], policy))

    def _error_code(self, operation, e):  # pylint: disable=unused-argument
        if isinstance(e, self.resp_exc):
            if e.http_status == 404:
                return log.ErrorCode.backend_not_found

    def _put(self, source_path, remote_filename):
        lp = util.fsdecode(source_path.name)
        if config.mp_segment_size > 0:
            from swiftclient.service import SwiftUploadObject
            st = os.stat(lp)
            # only upload using Dynamic Large Object if mpvolsize is triggered
            if st.st_size >= config.mp_segment_size:
                mp = self.svc.upload(
                    self.container,
                    [SwiftUploadObject(lp,
                                       object_name=self.prefix + util.fsdecode(remote_filename))],
                    options={u'segment_size': config.mp_segment_size}
                )
                uploads = [a for a in mp if u'container' not in a[u'action']]
                for upload in uploads:
                    if not upload[u'success']:
                        raise BackendException(upload[u'traceback'])
                return
        self.conn.put_object(self.container,
                             self.prefix + util.fsdecode(remote_filename),
                             open(lp, u'rb'))

    def _get(self, remote_filename, local_path):
        headers, body = self.conn.get_object(self.container,
                                             self.prefix + util.fsdecode(remote_filename),
                                             resp_chunk_size=1024)
        with open(local_path.name, u'wb') as f:
            for chunk in body:
                f.write(chunk)

    def _list(self):
        headers, objs = self.conn.get_container(self.container, full_listing=True, path=self.prefix)
        # removes prefix from return values. should check for the prefix ?
        return [o[u'name'][len(self.prefix):] for o in objs]

    def _delete(self, filename):
        # use swiftservice to correctly delete all segments in case of multipart uploads
        deleted = [a for a in self.svc.delete(self.container, [self.prefix + util.fsdecode(filename)])]

    def _query(self, filename):
        # use swiftservice to correctly report filesize in case of multipart uploads
        sobject = [a for a in self.svc.stat(self.container, [self.prefix + util.fsdecode(filename)])][0]
        return {u'size': int(sobject[u'headers'][u'content-length'])}


duplicity.backend.register_backend(u"swift", SwiftBackend)
