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

from __future__ import division
from builtins import str
from concurrent.futures import ThreadPoolExecutor
import os
import time

import duplicity.backend
from duplicity import config
from duplicity import log
from duplicity.errors import FatalBackendException, BackendException
from duplicity import progress
from duplicity import util

BOTO_MIN_VERSION = u"2.1.1"


def get_connection(scheme, parsed_url, storage_uri):
    try:
        from boto.s3.connection import S3Connection
        assert hasattr(S3Connection, u'lookup')

        # Newer versions of boto default to using
        # virtual hosting for buckets as a result of
        # upstream deprecation of the old-style access
        # method by Amazon S3. This change is not
        # backwards compatible (in particular with
        # respect to upper case characters in bucket
        # names); so we default to forcing use of the
        # old-style method unless the user has
        # explicitly asked us to use new-style bucket
        # access.
        #
        # Note that if the user wants to use new-style
        # buckets, we use the subdomain calling form
        # rather than given the option of both
        # subdomain and vhost. The reason being that
        # anything addressable as a vhost, is also
        # addressable as a subdomain. Seeing as the
        # latter is mostly a convenience method of
        # allowing browse:able content semi-invisibly
        # being hosted on S3, the former format makes
        # a lot more sense for us to use - being
        # explicit about what is happening (the fact
        # that we are talking to S3 servers).

        try:
            from boto.s3.connection import OrdinaryCallingFormat
            from boto.s3.connection import SubdomainCallingFormat
            cfs_supported = True
            calling_format = OrdinaryCallingFormat()
        except ImportError:
            cfs_supported = False
            calling_format = None

        if config.s3_use_new_style:
            if cfs_supported:
                calling_format = SubdomainCallingFormat()
            else:
                log.FatalError(u"Use of new-style (subdomain) S3 bucket addressing was"
                               u"requested, but does not seem to be supported by the "
                               u"boto library. Either you need to upgrade your boto "
                               u"library or duplicity has failed to correctly detect "
                               u"the appropriate support.",
                               log.ErrorCode.boto_old_style)
        else:
            if cfs_supported:
                calling_format = OrdinaryCallingFormat()
            else:
                calling_format = None

    except ImportError:
        log.FatalError(u"This backend (s3) requires boto library, version %s or later, "
                       u"(http://code.google.com/p/boto/)." % BOTO_MIN_VERSION,
                       log.ErrorCode.boto_lib_too_old)

    if not parsed_url.hostname:
        # Use the default host.
        conn = storage_uri.connect(is_secure=(not config.s3_unencrypted_connection))
    else:
        assert scheme == u's3'
        conn = storage_uri.connect(host=parsed_url.hostname, port=parsed_url.port,
                                   is_secure=(not config.s3_unencrypted_connection))

    if hasattr(conn, u'calling_format'):
        if calling_format is None:
            log.FatalError(u"It seems we previously failed to detect support for calling "
                           u"formats in the boto library, yet the support is there. This is "
                           u"almost certainly a duplicity bug.",
                           log.ErrorCode.boto_calling_format)
        else:
            conn.calling_format = calling_format

    else:
        # Duplicity hangs if boto gets a null bucket name.
        # HC: Caught a socket error, trying to recover
        raise BackendException(u'Boto requires a bucket name.')
    return conn


class BotoBackend(duplicity.backend.Backend):
    u"""
    Backend for Amazon's Simple Storage System, (aka Amazon S3), though
    the use of the boto module, (http://code.google.com/p/boto/).

    To make use of this backend you must set aws_access_key_id
    and aws_secret_access_key in your ~/.boto or /etc/boto.cfg
    with your Amazon Web Services key id and secret respectively.
    Alternatively you can export the environment variables
    AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.
    """

    def __init__(self, parsed_url):
        duplicity.backend.Backend.__init__(self, parsed_url)

        try:
            import boto  # pylint: disable=import-error
            from boto.s3.connection import Location
        except ImportError:
            raise

        assert boto.Version >= BOTO_MIN_VERSION

        # This folds the null prefix and all null parts, which means that:
        #  //MyBucket/ and //MyBucket are equivalent.
        #  //MyBucket//My///My/Prefix/ and //MyBucket/My/Prefix are equivalent.
        self.url_parts = [x for x in parsed_url.path.split(u'/') if x != u'']

        if self.url_parts:
            self.bucket_name = self.url_parts.pop(0)
        else:
            # Duplicity hangs if boto gets a null bucket name.
            # HC: Caught a socket error, trying to recover
            raise BackendException(u'Boto requires a bucket name.')

        self.scheme = parsed_url.scheme

        if self.url_parts:
            self.key_prefix = u'%s/' % u'/'.join(self.url_parts)
        else:
            self.key_prefix = u''

        self.straight_url = duplicity.backend.strip_auth_from_url(parsed_url)
        self.parsed_url = parsed_url

        # duplicity and boto.storage_uri() have different URI formats.
        # boto uses scheme://bucket[/name] and specifies hostname on connect()
        self.boto_uri_str = u'://'.join((parsed_url.scheme[:2],
                                         parsed_url.path.lstrip(u'/')))
        if config.s3_european_buckets:
            self.my_location = Location.EU
        else:
            self.my_location = u''
        self.resetConnection()
        self._listed_keys = {}

    def _close(self):
        del self._listed_keys
        self._listed_keys = {}
        self.bucket = None
        self.conn = None
        self.storage_uri = None
        del self.conn
        del self.storage_uri

    def resetConnection(self):
        import boto  # pylint: disable=import-error

        if getattr(self, u'conn', False):
            self.conn.close()
        self.bucket = None
        self.conn = None
        self.storage_uri = None
        del self.conn
        del self.storage_uri
        self.storage_uri = boto.storage_uri(self.boto_uri_str)
        self.conn = get_connection(self.scheme, self.parsed_url, self.storage_uri)
        if not self.conn.lookup(self.bucket_name):
            self.bucket = self.conn.create_bucket(self.bucket_name,
                                                  location=self.my_location)
        else:
            self.bucket = self.conn.get_bucket(self.bucket_name)

    def _retry_cleanup(self):
        self.resetConnection()

    def _put(self, source_path, remote_filename):
        remote_filename = util.fsdecode(remote_filename)

        if config.s3_european_buckets:
            if not config.s3_use_new_style:
                raise FatalBackendException(u"European bucket creation was requested, but not new-style "
                                            u"bucket addressing (--s3-use-new-style)",
                                            code=log.ErrorCode.s3_bucket_not_style)

        if self.bucket is None:
            try:
                self.bucket = self.conn.get_bucket(self.bucket_name)
            except Exception as e:
                if u"NoSuchBucket" in str(e):
                    self.bucket = self.conn.create_bucket(self.bucket_name,
                                                          location=self.my_location)
                else:
                    raise

        key = self.bucket.new_key(self.key_prefix + remote_filename)

        if config.s3_use_rrs:
            storage_class = u'REDUCED_REDUNDANCY'
        elif config.s3_use_ia:
            storage_class = u'STANDARD_IA'
        elif config.s3_use_onezone_ia:
            storage_class = u'ONEZONE_IA'
        elif config.s3_use_glacier and u"manifest" not in remote_filename:
            storage_class = u'GLACIER'
        else:
            storage_class = u'STANDARD'
        log.Info(u"Uploading %s/%s to %s Storage" % (self.straight_url, remote_filename, storage_class))
        if config.s3_use_sse:
            headers = {
                u'Content-Type': u'application/octet-stream',
                u'x-amz-storage-class': storage_class,
                u'x-amz-server-side-encryption': u'AES256'
            }
        elif config.s3_use_sse_kms:
            if config.s3_kms_key_id is None:
                raise FatalBackendException(u"S3 USE SSE KMS was requested, but key id not provided "
                                            u"require (--s3-kms-key-id)",
                                            code=log.ErrorCode.s3_kms_no_id)
            headers = {
                u'Content-Type': u'application/octet-stream',
                u'x-amz-storage-class': storage_class,
                u'x-amz-server-side-encryption': u'aws:kms',
                u'x-amz-server-side-encryption-aws-kms-key-id': config.s3_kms_key_id
            }
            if config.s3_kms_grant is not None:
                headers[u'x-amz-grant-full-control'] = config.s3_kms_grant
        else:
            headers = {
                u'Content-Type': u'application/octet-stream',
                u'x-amz-storage-class': storage_class
            }

        upload_start = time.time()
        self.upload(source_path.name, key, headers)
        upload_end = time.time()
        total_s = abs(upload_end - upload_start) or 1  # prevent a zero value!
        rough_upload_speed = os.path.getsize(source_path.name) / total_s
        log.Debug(u"Uploaded %s/%s to %s Storage at roughly %f bytes/second" %
                  (self.straight_url, remote_filename, storage_class,
                   rough_upload_speed))

    def _get(self, remote_filename, local_path):
        remote_filename = util.fsdecode(remote_filename)
        key_name = self.key_prefix + remote_filename
        self.pre_process_download(remote_filename, wait=True)
        key = self._listed_keys[key_name]
        self.resetConnection()
        key.get_contents_to_filename(local_path.name)

    def _list(self):
        if not self.bucket:
            raise BackendException(u"No connection to backend")
        return self.list_filenames_in_bucket()

    def list_filenames_in_bucket(self):
        # We add a 'd' to the prefix to make sure it is not null (for boto) and
        # to optimize the listing of our filenames, which always begin with 'd'.
        # This will cause a failure in the regression tests as below:
        #   FAIL: Test basic backend operations
        #   <tracback snipped>
        #   AssertionError: Got list: []
        #   Wanted: ['testfile']
        # Because of the need for this optimization, it should be left as is.
        # for k in self.bucket.list(prefix = self.key_prefix + 'd', delimiter = '/'):
        filename_list = []
        for k in self.bucket.list(prefix=self.key_prefix):
            try:
                filename = k.key.replace(self.key_prefix, u'', 1)
                filename_list.append(filename)
                self._listed_keys[k.key] = k
                log.Debug(u"Listed %s/%s" % (self.straight_url, filename))
            except AttributeError:
                pass
        return filename_list

    def _delete(self, filename):
        filename = util.fsdecode(filename)
        self.bucket.delete_key(self.key_prefix + filename)

    def _query(self, filename):
        filename = util.fsdecode(filename)
        key = self.bucket.lookup(self.key_prefix + filename)
        if key is None:
            return {u'size': -1}
        return {u'size': key.size}

    def upload(self, filename, key, headers):
        key.set_contents_from_filename(filename, headers,
                                       cb=progress.report_transfer,
                                       num_cb=(max(2, 8 * config.volsize / (1024 * 1024)))
                                       )  # Max num of callbacks = 8 times x megabyte
        key.close()

    def pre_process_download(self, remote_filename, wait=False):
        # Used primarily to move files in Glacier to S3
        key_name = self.key_prefix + remote_filename
        if not self._listed_keys.get(key_name, False):
            self._listed_keys[key_name] = list(self.bucket.list(key_name))[0]
        key = self._listed_keys[key_name]

        if key.storage_class == u"GLACIER":
            # We need to move the file out of glacier
            if not self.bucket.get_key(key.key).ongoing_restore:
                log.Info(u"File %s is in Glacier storage, restoring to S3" % remote_filename)
                key.restore(days=1)  # Shouldn't need this again after 1 day
            if wait:
                log.Info(u"Waiting for file %s to restore from Glacier" % remote_filename)
                while self.bucket.get_key(key.key).ongoing_restore:
                    time.sleep(60)
                    self.resetConnection()
                log.Info(u"File %s was successfully restored from Glacier" % remote_filename)

    def pre_process_download_batch(self, remote_filenames):
        log.Info(u"Starting batch unfreezing from Glacier")
        # Used primarily to move all necessary files in Glacier to S3 at once
        with ThreadPoolExecutor(thread_name_prefix=u's3-unfreeze-glacier') as executor:
            for remote_filename in remote_filenames:
                remote_filename = util.fsdecode(remote_filename)
                executor.submit(self.pre_process_download, remote_filename, False)
        log.Info(u"Batch unfreezing from Glacier finished")
