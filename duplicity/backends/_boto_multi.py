# -*- Mode:Python; indent-tabs-mode:nil; tab-width:4; encoding:utf8 -*-
#
# Copyright 2002 Ben Escoto <ben@emerose.org>
# Copyright 2007 Kenneth Loafman <kenneth@loafman.com>
# Copyright 2011 Henrique Carvalho Alves <hcarvalhoalves@gmail.com>
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
from future import standard_library
standard_library.install_aliases()
from builtins import range

import os
import psutil
import queue
import socket
import sys
import threading
import time
import traceback

from duplicity import config
from duplicity import log
from duplicity import progress
from duplicity.errors import *  # pylint: disable=unused-wildcard-import
from duplicity.filechunkio import FileChunkIO

from ._boto_single import BotoBackend as BotoSingleBackend
from ._boto_single import get_connection

BOTO_MIN_VERSION = u"2.1.1"

# Multiprocessing is not supported on *BSD
if sys.platform not in (u'darwin', u'linux2'):
    from multiprocessing import dummy as multiprocessing
    log.Debug(u'Multiprocessing is not supported on %s, will use threads instead.' % sys.platform)
else:
    import multiprocessing


class ConsumerThread(threading.Thread):
    u"""
    A background thread that collects all written bytes from all
    the pool workers, and reports it to the progress module.
    Wakes up every second to check for termination
    """
    def __init__(self, queue, total):
        super(ConsumerThread, self).__init__()
        self.daemon = True
        self.finish = False
        self.progress = {}
        self.queue = queue
        self.total = total

    def run(self):
        wait = True
        while not self.finish:
            try:
                args = self.queue.get(wait, 1)
                self.progress[args[0]] = args[1]
                wait = False
            except queue.Empty as e:
                progress.report_transfer(sum(self.progress.values()), self.total)
                wait = True
                pass


class BotoBackend(BotoSingleBackend):
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
        BotoSingleBackend.__init__(self, parsed_url)
        try:
            import boto
        except ImportError:
            raise
        self._setup_pool()

    def _setup_pool(self):
        number_of_procs = config.s3_multipart_max_procs
        if not number_of_procs:
            number_of_procs = psutil.cpu_count(logical=False)

        if getattr(self, u'_pool', False):
            log.Debug(u"A process pool already exists. Destroying previous pool.")
            self._pool.terminate()  # pylint:disable=access-member-before-definition
            self._pool.join()  # pylint:disable=access-member-before-definition
            self._pool = None

        log.Debug(u"Setting multipart boto backend process pool to %d processes" % number_of_procs)

        self._pool = multiprocessing.Pool(processes=number_of_procs)

    def _close(self):
        BotoSingleBackend._close(self)
        log.Debug(u"Closing pool")
        self._pool.terminate()
        self._pool.join()

    def upload(self, filename, key, headers=None):
        import boto  # pylint: disable=import-error

        chunk_size = config.s3_multipart_chunk_size

        # Check minimum chunk size for S3
        if chunk_size < config.s3_multipart_minimum_chunk_size:
            log.Warn(u"Minimum chunk size is %d, but %d specified." % (
                config.s3_multipart_minimum_chunk_size, chunk_size))
            chunk_size = config.s3_multipart_minimum_chunk_size

        # Decide in how many chunks to upload
        bytes = os.path.getsize(filename)  # pylint: disable=redefined-builtin
        if bytes < chunk_size:
            chunks = 1
        else:
            chunks = bytes // chunk_size
            if (bytes % chunk_size):
                chunks += 1

        log.Debug(u"Uploading %d bytes in %d chunks" % (bytes, chunks))

        mp = self.bucket.initiate_multipart_upload(key.key, headers, encrypt_key=config.s3_use_sse)

        # Initiate a queue to share progress data between the pool
        # workers and a consumer thread, that will collect and report
        queue = None
        if config.progress:
            manager = multiprocessing.Manager()
            queue = manager.Queue()
            consumer = ConsumerThread(queue, bytes)
            consumer.start()
        tasks = []
        for n in range(chunks):
            storage_uri = boto.storage_uri(self.boto_uri_str)
            params = [self.scheme, self.parsed_url, storage_uri, self.bucket_name,
                      mp.id, filename, n, chunk_size, config.num_retries,
                      queue]
            tasks.append(self._pool.apply_async(multipart_upload_worker, params))

        log.Debug(u"Waiting for the pool to finish processing %s tasks" % len(tasks))
        while tasks:
            try:
                tasks[0].wait(timeout=config.s3_multipart_max_timeout)
                if tasks[0].ready():
                    if tasks[0].successful():
                        del tasks[0]
                    else:
                        log.Debug(u"Part upload not successful, aborting multipart upload.")
                        self._setup_pool()
                        break
                else:
                    raise multiprocessing.TimeoutError
            except multiprocessing.TimeoutError:
                log.Debug(u"%s tasks did not finish by the specified timeout,"
                          u"aborting multipart upload and resetting pool." % len(tasks))
                self._setup_pool()
                break

        log.Debug(u"Done waiting for the pool to finish processing")

        # Terminate the consumer thread, if any
        if config.progress:
            consumer.finish = True
            consumer.join()

        if len(tasks) > 0 or len(mp.get_all_parts()) < chunks:
            mp.cancel_upload()
            raise BackendException(u"Multipart upload failed. Aborted.")

        return mp.complete_upload()


def multipart_upload_worker(scheme, parsed_url, storage_uri, bucket_name, multipart_id,
                            filename, offset, bytes, num_retries, queue):  # pylint: disable=redefined-builtin
    u"""
    Worker method for uploading a file chunk to S3 using multipart upload.
    Note that the file chunk is read into memory, so it's important to keep
    this number reasonably small.
    """

    def _upload_callback(uploaded, total):
        worker_name = multiprocessing.current_process().name
        log.Debug(u"%s: Uploaded %s/%s bytes" % (worker_name, uploaded, total))
        if queue is not None:
            queue.put([offset, uploaded])  # Push data to the consumer thread

    def _upload(num_retries):
        worker_name = multiprocessing.current_process().name
        log.Debug(u"%s: Uploading chunk %d" % (worker_name, offset + 1))
        try:
            conn = get_connection(scheme, parsed_url, storage_uri)
            bucket = conn.lookup(bucket_name)

            for mp in bucket.list_multipart_uploads():
                if mp.id == multipart_id:
                    with FileChunkIO(filename, u'r', offset=offset * bytes, bytes=bytes) as fd:
                        start = time.time()
                        try:
                            mp.upload_part_from_file(fd, offset + 1, cb=_upload_callback,
                                                     num_cb=max(2, 8 * bytes / (1024 * 1024))
                                                     )  # Max num of callbacks = 8 times x megabyte
                        except socket.gaierror as ex:
                            log.Warn(ex.strerror)
                        end = time.time()
                        log.Debug((u"{name}: Uploaded chunk {chunk} "
                                   u"at roughly {speed} bytes/second").format(name=worker_name,
                                                                              chunk=offset + 1,
                                                                              speed=(bytes /
                                                                                     max(1, abs(end - start)))))
                    break
            conn.close()
            conn = None
            bucket = None
            del conn
        except Exception as e:
            traceback.print_exc()
            if num_retries:
                log.Debug(u"%s: Upload of chunk %d failed. Retrying %d more times..." % (
                    worker_name, offset + 1, num_retries - 1))
                return _upload(num_retries - 1)
            log.Debug(u"%s: Upload of chunk %d failed. Aborting..." % (
                worker_name, offset + 1))
            raise e
        log.Debug(u"%s: Upload of chunk %d complete" % (worker_name, offset + 1))

    return _upload(num_retries)
