# -*- Mode:Python; indent-tabs-mode:nil; tab-width:4; encoding:utf8 -*-
#
# Copyright 2013 Matthieu Huin <mhu@enovance.com>
# Copyright 2017 Xavier Lucas <xavier.lucas@corp.ovh.com>
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

import duplicity.backend
from duplicity import log
from duplicity import util
from duplicity.errors import BackendException
import time


class PCABackend(duplicity.backend.Backend):
    u"""
    Backend for OVH PCA
    """
    def __init__(self, parsed_url):
        duplicity.backend.Backend.__init__(self, parsed_url)

        try:
            from swiftclient import Connection
            from swiftclient import ClientException
        except ImportError as e:
            raise BackendException(u"""\
PCA backend requires the python-swiftclient library.
Exception: %s""" % str(e))

        self.resp_exc = ClientException
        self.conn_cls = Connection
        conn_kwargs = {}

        # if the user has already authenticated
        if u'PCA_PREAUTHURL' in os.environ and u'PCA_PREAUTHTOKEN' in os.environ:
            conn_kwargs[u'preauthurl'] = os.environ[u'PCA_PREAUTHURL']
            conn_kwargs[u'preauthtoken'] = os.environ[u'PCA_PREAUTHTOKEN']

        else:
            if u'PCA_USERNAME' not in os.environ:
                raise BackendException(u'PCA_USERNAME environment variable '
                                       u'not set.')

            if u'PCA_PASSWORD' not in os.environ:
                raise BackendException(u'PCA_PASSWORD environment variable '
                                       u'not set.')

            if u'PCA_AUTHURL' not in os.environ:
                raise BackendException(u'PCA_AUTHURL environment variable '
                                       u'not set.')

            conn_kwargs[u'user'] = os.environ[u'PCA_USERNAME']
            conn_kwargs[u'key'] = os.environ[u'PCA_PASSWORD']
            conn_kwargs[u'authurl'] = os.environ[u'PCA_AUTHURL']

        os_options = {}

        if u'PCA_AUTHVERSION' in os.environ:
            conn_kwargs[u'auth_version'] = os.environ[u'PCA_AUTHVERSION']
            if os.environ[u'PCA_AUTHVERSION'] == u'3':
                if u'PCA_USER_DOMAIN_NAME' in os.environ:
                    os_options.update({u'user_domain_name': os.environ[u'PCA_USER_DOMAIN_NAME']})
                if u'PCA_USER_DOMAIN_ID' in os.environ:
                    os_options.update({u'user_domain_id': os.environ[u'PCA_USER_DOMAIN_ID']})
                if u'PCA_PROJECT_DOMAIN_NAME' in os.environ:
                    os_options.update({u'project_domain_name': os.environ[u'PCA_PROJECT_DOMAIN_NAME']})
                if u'PCA_PROJECT_DOMAIN_ID' in os.environ:
                    os_options.update({u'project_domain_id': os.environ[u'PCA_PROJECT_DOMAIN_ID']})
                if u'PCA_TENANTNAME' in os.environ:
                    os_options.update({u'tenant_name': os.environ[u'PCA_TENANTNAME']})
                if u'PCA_ENDPOINT_TYPE' in os.environ:
                    os_options.update({u'endpoint_type': os.environ[u'PCA_ENDPOINT_TYPE']})
                if u'PCA_USERID' in os.environ:
                    os_options.update({u'user_id': os.environ[u'PCA_USERID']})
                if u'PCA_TENANTID' in os.environ:
                    os_options.update({u'tenant_id': os.environ[u'PCA_TENANTID']})
                if u'PCA_REGIONNAME' in os.environ:
                    os_options.update({u'region_name': os.environ[u'PCA_REGIONNAME']})

        else:
            conn_kwargs[u'auth_version'] = u'2'
        if u'PCA_TENANTNAME' in os.environ:
            conn_kwargs[u'tenant_name'] = os.environ[u'PCA_TENANTNAME']
        if u'PCA_REGIONNAME' in os.environ:
            os_options.update({u'region_name': os.environ[u'PCA_REGIONNAME']})

        conn_kwargs[u'os_options'] = os_options
        conn_kwargs[u'retries'] = 0

        self.conn_kwargs = conn_kwargs

        # This folds the null prefix and all null parts, which means that:
        #  //MyContainer/ and //MyContainer are equivalent.
        #  //MyContainer//My/Prefix/ and //MyContainer/My/Prefix are equivalent.
        url_parts = [x for x in parsed_url.path.split(u'/') if x != u'']

        self.container = url_parts.pop(0)
        if url_parts:
            self.prefix = u'%s/' % u'/'.join(url_parts)
        else:
            self.prefix = u''

        policy = u'PCA'
        policy_header = u'X-Storage-Policy'

        container_metadata = None
        try:
            self.conn = Connection(**self.conn_kwargs)
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
                headers = dict([[policy_header, policy]])
                self.conn.put_container(self.container, headers=headers)
            except Exception as e:
                log.FatalError(u"Container creation failed: %s %s"
                               % (e.__class__.__name__, str(e)),
                               log.ErrorCode.connection_failed)
        elif policy and container_metadata[policy_header.lower()] != policy:
            log.FatalError(u"Container '%s' exists but its storage policy is '%s' not '%s'."
                           % (self.container, container_metadata[policy_header.lower()], policy))

    def _error_code(self, operation, e):  # pylint: disable= unused-argument
        if isinstance(e, self.resp_exc):
            if e.http_status == 404:
                return log.ErrorCode.backend_not_found

    def _put(self, source_path, remote_filename):
        self.conn.put_object(self.container, self.prefix + util.fsdecode(remote_filename),
                             open(util.fsdecode(source_path.name), u'rb'))

    def _get(self, remote_filename, local_path):
        body = self.preprocess_download(util.fsdecode(remote_filename), 60)
        if body:
            with open(util.fsdecode(local_path.name), u'wb') as f:
                for chunk in body:
                    f.write(chunk)

    def _list(self):
        headers, objs = self.conn.get_container(self.container, full_listing=True, path=self.prefix)
        # removes prefix from return values. should check for the prefix ?
        return [util.fsencode(o[u'name'][len(self.prefix):]) for o in objs]

    def _delete(self, filename):
        self.conn.delete_object(self.container, self.prefix + util.fsdecode(filename))

    def _query(self, filename):
        sobject = self.conn.head_object(self.container, self.prefix + util.fsdecode(filename))
        return {u'size': int(sobject[u'content-length'])}

    def preprocess_download(self, remote_filename, retry_period, wait=True):
        body = self.unseal(remote_filename)
        try:
            if wait:
                while not body:
                    time.sleep(retry_period)
                    self.conn = self.conn_cls(**self.conn_kwargs)
                    body = self.unseal(remote_filename)
                    self.conn.close()
        except Exception as e:
            log.FatalError(u"Connection failed: %s %s" % (e.__class__.__name__, str(e)),
                           log.ErrorCode.connection_failed)
        return body

    def unseal(self, remote_filename):
        try:
            _, body = self.conn.get_object(self.container, self.prefix + remote_filename,
                                           resp_chunk_size=1024)
            log.Info(u"File %s was successfully unsealed." % remote_filename)
            return body
        except self.resp_exc as e:
            # The object is sealed but being released.
            if e.http_status == 429:
                # The retry-after header contains the remaining duration before
                # the unsealing operation completes.
                duration = int(e.http_response_headers[u'Retry-After'])
                m, s = divmod(duration, 60)
                h, m = divmod(m, 60)
                eta = u"%dh%02dm%02ds" % (h, m, s)
                log.Info(u"File %s is being unsealed, operation ETA is %s." %
                         (remote_filename, eta))
            else:
                raise


duplicity.backend.register_backend(u"pca", PCABackend)
