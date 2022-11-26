# -*- Mode:Python; indent-tabs-mode:nil; tab-width:4; encoding:utf8 -*-
#
# Copyright 2013 Matthieu Huin <mhu@enovance.com>
# Copyright 2015 Scott McKenzie <noizyland@gmail.com>
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
import re

import duplicity.backend
from duplicity import config
from duplicity import log
from duplicity.errors import BackendException
from duplicity.util import fsdecode


_VALID_CONTAINER_NAME_RE = re.compile(r"^[a-z0-9](?!.*--)[a-z0-9-]{1,61}[a-z0-9]$")


def _is_valid_container_name(name):
    u"""
    Check, whether the given name conforms to the rules as defined in
    https://docs.microsoft.com/en-us/rest/api/storageservices/naming-and-referencing-containers--blobs--and-metadata
    for valid names.
    """
    match = _VALID_CONTAINER_NAME_RE.match(name)
    return match is not None


class AzureBackend(duplicity.backend.Backend):
    u"""
    Backend for Azure Blob Storage Service
    """
    def __init__(self, parsed_url):
        duplicity.backend.Backend.__init__(self, parsed_url)

        # Import Microsoft Azure Storage SDK for Python library.
        try:
            import azure
            import azure.storage
            import azure.storage.blob
            from azure.storage.blob import BlobServiceClient
        except ImportError as e:
            raise BackendException(u"""\
Azure backend requires Microsoft Azure Storage SDK for Python (https://pypi.org/project/azure-storage-blob/).
Exception: %s""" % str(e))

        self.container_name = parsed_url.path.lstrip(u'/')

        if not _is_valid_container_name(self.container_name):
            raise BackendException(u'Invalid Azure Storage Blob container name.')

        if u'AZURE_CONNECTION_STRING' not in os.environ:
            raise BackendException(u'AZURE_CONNECTION_STRING environment variable not set.')

        kwargs = {}

        if config.timeout:
            kwargs[u'timeout'] = config.timeout

        if config.azure_max_single_put_size:
            kwargs[u'max_single_put_size'] = config.azure_max_single_put_size

        if config.azure_max_block_size:
            kwargs[u'max_block_size'] = config.azure_max_single_put_size

        conn_str = os.environ[u'AZURE_CONNECTION_STRING']
        self.blob_service = BlobServiceClient.from_connection_string(conn_str, None, **kwargs)
        self._get_or_create_container()

    def _get_or_create_container(self):
        from azure.core.exceptions import ResourceExistsError

        try:
            self.container = self.blob_service.get_container_client(self.container_name)
            self.container.create_container()
        except ResourceExistsError:
            pass
        except Exception as e:
            log.FatalError(u"Could not create Azure container: %s"
                           % str(e.message).split(u'\n', 1)[0],
                           log.ErrorCode.connection_failed)

    def _put(self, source_path, remote_filename):
        remote_filename = fsdecode(remote_filename)
        kwargs = {}

        if config.azure_max_connections:
            kwargs[u'max_concurrency'] = config.azure_max_connections

        with source_path.open(u"rb") as data:
            self.container.upload_blob(remote_filename, data, **kwargs)

        self._set_tier(remote_filename)

    def _set_tier(self, remote_filename):
        if config.azure_blob_tier is not None:
            self.container.set_standard_blob_tier_blobs(config.azure_blob_tier, remote_filename)

    def _get(self, remote_filename, local_path):
        # https://docs.microsoft.com/en-us/python/api/azure-storage-blob/azure.storage.blob.containerclient?view=azure-python#download-blob-blob--offset-none--length-none----kwargs-
        blob = self.container.download_blob(remote_filename)
        with local_path.open(u"wb") as download_file:
            download_file.write(blob.readall())

    def _list(self):
        # https://docs.microsoft.com/en-us/python/api/azure-storage-blob/azure.storage.blob.containerclient?view=azure-python#list-blobs-name-starts-with-none--include-none----kwargs-
        blobs = []
        blob_list = self.container.list_blobs()
        for blob in blob_list:
            blobs.append(blob)

        return [blob.name for blob in blobs]

    def _delete(self, filename):
        # https://docs.microsoft.com/en-us/python/api/azure-storage-blob/azure.storage.blob.containerclient?view=azure-python#delete-blob-blob--delete-snapshots-none----kwargs-
        self.container.delete_blob(fsdecode(filename))

    def _query(self, filename):
        client = self.container.get_blob_client(fsdecode(filename))
        prop = client.get_blob_properties()
        return {u'size': int(prop.size)}

    def _error_code(self, operation, e):  # pylint: disable=unused-argument
        return log.ErrorCode.backend_not_found


duplicity.backend.register_backend(u'azure', AzureBackend)
