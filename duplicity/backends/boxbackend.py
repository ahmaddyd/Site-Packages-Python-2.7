# -*- Mode:Python; indent-tabs-mode:nil; tab-width:4; encoding:utf8 -*-
#
# Copyright 2020 Jose L. Domingo Lopez <github@24x7linux.com>
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

import os

import duplicity.backend
from boxsdk import Client, JWTAuth
from duplicity.errors import BackendException
from future import standard_library

standard_library.install_aliases()


class BoxBackend(duplicity.backend.Backend):
    def __init__(self, parsed_url):
        duplicity.backend.Backend.__init__(self, parsed_url)

        self._client = self.get_box_client(parsed_url)
        self._folder = (
            parsed_url.path[1:]
            if parsed_url.path[0] == u'/'
            else parsed_url.path
        )

        self._file_to_metadata_map = {}
        self._folder_id = self.get_id_from_path(self._folder)
        if self._folder_id is None:
            self._folder_id = self.makedirs(self._folder)

    def get_box_client(self, parsed_url):
        try:
            config_path = os.path.expanduser(
                parsed_url.query_args[u'config'][0]
            )
            return Client(JWTAuth.from_settings_file(config_path))
        except Exception as e:
            config_path = os.environ.get(u'BOX_CONFIG_PATH')
            if config_path is not None:
                try:
                    return Client(JWTAuth.from_settings_file(config_path))
                except Exception as e:
                    raise BackendException(u'box config file is not found.')

            raise BackendException(
                u'box config file is not specified or not found.'
            )

    def _put(self, source_path, remote_filename):
        u"""Uploads file to the specified remote folder
        (tries to delete it first to make sure the new one can be uploaded)"""

        try:
            self.delete(remote_filename.decode())
        except Exception:
            pass
        self.upload(
            local_file=source_path.get_canonical().decode(),
            remote_file=remote_filename.decode(),
        )

    def _get(self, remote_filename, local_path):
        u'Downloads file from the specified remote path'

        self.download(
            remote_file=remote_filename.decode(),
            local_file=local_path.name.decode(),
        )

    def _list(self):
        u'Lists files in the specified remote path'

        return self.folder_contents()

    def _delete(self, filename):
        u'Deletes file from the specified remote path'

        self.delete(remote_file=filename.decode())

    def _query_list(self, filename_list):
        u'Query metadata for a list of file'
        return {
            filename: self._file_to_metadata_map.get(
                filename.decode(), {u'size': -1}
            )
            for filename in filename_list
        }

    def get_id_from_path(self, remote_path, parent_id=u'0'):
        u'Get the folder or file id from its path'
        path_items = [
            x.strip() for x in remote_path.split(u'/') if x.strip() != u''
        ]
        head = path_items[0]
        tail = path_items[1:]

        while True:
            selected_item_id = None
            for item in self._client.folder(folder_id=parent_id).get_items():
                if item.name == head:
                    selected_item_id = item.id
                    break

            if selected_item_id is None:
                return None
            elif len(tail) == 0:
                return selected_item_id

            parent_id = selected_item_id
            head = tail[0]
            tail = tail[1:]

        return None

    def get_file_id_from_filename(self, remote_filename):
        u'Get the fild id by its file name'
        file = self._file_to_metadata_map.get(remote_filename)

        if file is not None:
            return file[u'id']

        file_id = self.get_id_from_path(
            remote_filename, parent_id=self._folder_id
        )
        file = self._client.file(file_id).get()
        self._file_to_metadata_map[file.name] = {
            u'id': file.id,
            u'size': file.size,
        }
        return file_id

    def makedirs(self, remote_path):
        u'Create folder(s) in a path if necessary'
        path_items = [
            x.strip() for x in remote_path.split(u'/') if x.strip() != u''
        ]
        parent_id = u'0'

        start_folder_id = None
        while len(path_items) > 0:
            selected_item_id = None
            for item in self._client.folder(folder_id=parent_id).get_items():
                if item.name == path_items[0]:
                    selected_item_id = item.id
                    break

            if selected_item_id is None:
                start_folder_id = parent_id
                break

            parent_id = selected_item_id
            path_items = path_items[1:]

        if start_folder_id is not None:
            parent_id = start_folder_id
            for item in path_items:
                subfolder = self._client.folder(parent_id).create_subfolder(
                    item
                )
                parent_id = subfolder.id

        return parent_id

    def folder_contents(self):
        u'Lists files of a remote box path'

        items = [
            x
            for x in self._client.folder(folder_id=self._folder_id).get_items(
                fields=[u'id', u'name', u'size']
            )
            if x.type == u'file'
        ]

        self._file_to_metadata_map.update(
            {x.name: {u'id': x.id, u'size': x.size} for x in items}
        )

        return [x.name for x in items]

    def upload(self, remote_file, local_file):
        u'Upload local file to the box folder'
        new_file = self._client.folder(self._folder_id).upload(
            file_path=local_file, file_name=remote_file
        )

        self._file_to_metadata_map[new_file.name] = {
            u'id': new_file.id,
            u'size': new_file.size,
        }

    def download(self, remote_file, local_file):
        u'Download file in box folder'
        file_id = self.get_file_id_from_filename(remote_file)
        with open(local_file, u'wb') as fp:
            self._client.file(file_id).download_to(fp)

    def delete(self, remote_file):
        u'Delete file in box folder'
        file_id = self.get_file_id_from_filename(remote_file)
        self._client.file(file_id).delete()


duplicity.backend.register_backend(u'box', BoxBackend)
