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

u"""Create and edit manifest for session contents"""

from builtins import map
from builtins import range
from builtins import object

import re
import sys

from duplicity import config
from duplicity import log
from duplicity import config
from duplicity import util


class ManifestError(Exception):
    u"""
    Exception raised when problem with manifest
    """
    pass


class Manifest(object):
    u"""
    List of volumes and information about each one
    """
    def __init__(self, fh=None):
        u"""
        Create blank Manifest

        @param fh: fileobj for manifest
        @type fh: DupPath

        @rtype: Manifest
        @return: manifest
        """
        self.hostname = None
        self.local_dirname = None
        self.volume_info_dict = {}  # dictionary vol numbers -> vol infos
        self.fh = fh
        self.files_changed = []

    def set_dirinfo(self):
        u"""
        Set information about directory from config,
        and write to manifest file.

        @rtype: Manifest
        @return: manifest
        """
        self.hostname = config.hostname
        self.local_dirname = config.local_path.name
        if self.fh:
            if self.hostname:
                self.fh.write(b"Hostname %s\n" % self.hostname.encode())
            if self.local_dirname:
                self.fh.write(b"Localdir %s\n" % Quote(self.local_dirname))
        return self

    def check_dirinfo(self):
        u"""
        Return None if dirinfo is the same, otherwise error message

        Does not raise an error message if hostname or local_dirname
        are not available.

        @rtype: string
        @return: None or error message
        """
        if config.allow_source_mismatch:
            return

        # Check both hostname and fqdn (we used to write the fqdn into the
        # manifest, so we want to keep comparing against that)
        if (self.hostname and
                self.hostname != config.hostname and
                self.hostname != config.fqdn):
            errmsg = _(u"Fatal Error: Backup source host has changed.\n"
                       u"Current hostname: %s\n"
                       u"Previous hostname: %s") % (config.hostname, self.hostname)
            code = log.ErrorCode.hostname_mismatch
            code_extra = u"%s %s" % (util.escape(config.hostname), util.escape(self.hostname))

        elif (self.local_dirname and self.local_dirname != config.local_path.name):
            errmsg = _(u"Fatal Error: Backup source directory has changed.\n"
                       u"Current directory: %s\n"
                       u"Previous directory: %s") % (config.local_path.name, self.local_dirname)
            code = log.ErrorCode.source_dir_mismatch
            code_extra = u"%s %s" % (util.escape(config.local_path.name),
                                     util.escape(self.local_dirname))
        else:
            return

        log.FatalError(errmsg + u"\n\n" +
                       _(u"Aborting because you may have accidentally tried to "
                         u"backup two different data sets to the same remote "
                         u"location, or using the same archive directory.  If "
                         u"this is not a mistake, use the "
                         u"--allow-source-mismatch switch to avoid seeing this "
                         u"message"), code, code_extra)

    def set_files_changed_info(self, files_changed):
        if files_changed:
            self.files_changed = files_changed

        if self.fh:
            self.fh.write(b"Filelist %d\n" % len(self.files_changed))
            for fileinfo in self.files_changed:
                self.fh.write(b"    %-7s  %s\n" % (fileinfo[1], Quote(fileinfo[0])))

    def add_volume_info(self, vi):
        u"""
        Add volume info vi to manifest and write to manifest

        @param vi: volume info to add
        @type vi: VolumeInfo

        @return: void
        """
        vol_num = vi.volume_number
        self.volume_info_dict[vol_num] = vi
        if self.fh:
            self.fh.write(vi.to_string() + b"\n")

    def del_volume_info(self, vol_num):
        u"""
        Remove volume vol_num from the manifest

        @param vol_num: volume number to delete
        @type vi: int

        @return: void
        """
        try:
            del self.volume_info_dict[vol_num]
        except Exception:
            raise ManifestError(u"Volume %d not present in manifest" % (vol_num,))

    def to_string(self):
        u"""
        Return string version of self (just concatenate vi strings)

        @rtype: string
        @return: self in string form
        """
        result = b""
        if self.hostname:
            result += b"Hostname %s\n" % self.hostname.encode()
        if self.local_dirname:
            result += b"Localdir %s\n" % Quote(self.local_dirname)

        result += b"Filelist %d\n" % len(self.files_changed)
        for fileinfo in self.files_changed:
            result += b"    %-7s  %s\n" % (fileinfo[1], Quote(fileinfo[0]))

        vol_num_list = list(self.volume_info_dict.keys())
        vol_num_list.sort()

        def vol_num_to_string(vol_num):
            return self.volume_info_dict[vol_num].to_string()
        result = b"%s%s\n" % (result,
                              b"\n".join(map(vol_num_to_string, vol_num_list)))
        return result

    __str__ = to_string

    def from_string(self, s):
        u"""
        Initialize self from string s, return self
        """

        def get_field(fieldname):
            u"""
            Return the value of a field by parsing s, or None if no field
            """
            if not isinstance(fieldname, bytes):
                fieldname = fieldname.encode()
            m = re.search(b"(^|\\n)%s\\s(.*?)\n" % fieldname, s, re.I)
            if not m:
                return None
            else:
                return Unquote(m.group(2))
        self.hostname = get_field(u"hostname")
        if self.hostname is not None:
            self.hostname = self.hostname.decode()
        self.local_dirname = get_field(u"localdir")

        highest_vol = 0
        latest_vol = 0
        vi_regexp = re.compile(b"(?:^|\\n)(volume\\s.*(?:\\n.*)*?)(?=\\nvolume\\s|$)", re.I)
        vi_iterator = vi_regexp.finditer(s)
        for match in vi_iterator:
            vi = VolumeInfo().from_string(match.group(1))
            self.add_volume_info(vi)
            latest_vol = vi.volume_number
            highest_vol = max(highest_vol, latest_vol)
            log.Debug(_(u"Found manifest volume %s") % latest_vol)
        # If we restarted after losing some remote volumes, the highest volume
        # seen may be higher than the last volume recorded.  That is, the
        # manifest could contain "vol1, vol2, vol3, vol2."  If so, we don't
        # want to keep vol3's info.
        for i in range(latest_vol + 1, highest_vol + 1):
            self.del_volume_info(i)
        log.Info(_(u"Found %s volumes in manifest") % latest_vol)

        # Get file changed list - not needed if --file-changed not present
        filecount = 0
        if config.file_changed is not None:
            filelist_regexp = re.compile(b"(^|\\n)filelist\\s([0-9]+)\\n(.*?)(\\nvolume\\s|$)", re.I | re.S)
            match = filelist_regexp.search(s)
            if match:
                filecount = int(match.group(2))
            if filecount > 0:
                def parse_fileinfo(line):
                    fileinfo = line.strip().split()
                    return (fileinfo[0], b''.join(fileinfo[1:]))

                self.files_changed = list(map(parse_fileinfo, match.group(3).split(b'\n')))

            if filecount != len(self.files_changed):
                log.Error(_(u"Manifest file '%s' is corrupt: File count says %d, File list contains %d" %
                            (self.fh.base if self.fh else u"", filecount, len(self.files_changed))))
                self.corrupt_filelist = True

        return self

    def get_files_changed(self):
        return self.files_changed

    def __eq__(self, other):
        u"""
        Two manifests are equal if they contain the same volume infos
        """
        vi_list1 = list(self.volume_info_dict.keys())
        vi_list1.sort()
        vi_list2 = list(other.volume_info_dict.keys())
        vi_list2.sort()

        if vi_list1 != vi_list2:
            log.Notice(_(u"Manifests not equal because different volume numbers"))
            return False

        for i in range(len(vi_list1)):
            if not vi_list1[i] == vi_list2[i]:
                log.Notice(_(u"Manifests not equal because volume lists differ"))
                return False

        if (self.hostname != other.hostname or
                self.local_dirname != other.local_dirname):
            log.Notice(_(u"Manifests not equal because hosts or directories differ"))
            return False

        return True

    def __ne__(self, other):
        u"""
        Defines !=.  Not doing this always leads to annoying bugs...
        """
        return not self.__eq__(other)

    def write_to_path(self, path):
        u"""
        Write string version of manifest to given path
        """
        assert not path.exists()
        fout = path.open(u"wb")
        fout.write(self.to_string())
        assert not fout.close()
        path.setdata()

    def get_containing_volumes(self, index_prefix):
        u"""
        Return list of volume numbers that may contain index_prefix
        """
        if len(index_prefix) == 1 and isinstance(index_prefix[0], u"".__class__):
            index_prefix = (index_prefix[0].encode(),)
        return [vol_num for vol_num in list(self.volume_info_dict.keys()) if
                self.volume_info_dict[vol_num].contains(index_prefix)]


class VolumeInfoError(Exception):
    u"""
    Raised when there is a problem initializing a VolumeInfo from string
    """
    pass


class VolumeInfo(object):
    u"""
    Information about a single volume
    """
    def __init__(self):
        u"""VolumeInfo initializer"""
        self.volume_number = None
        self.start_index = None
        self.start_block = None
        self.end_index = None
        self.end_block = None
        self.hashes = {}

    def set_info(self, vol_number,
                 start_index, start_block,
                 end_index, end_block):
        u"""
        Set essential VolumeInfo information, return self

        Call with starting and ending paths stored in the volume.  If
        a multivol diff gets split between volumes, count it as being
        part of both volumes.
        """
        self.volume_number = vol_number
        self.start_index = start_index
        self.start_block = start_block
        self.end_index = end_index
        self.end_block = end_block

        return self

    def set_hash(self, hash_name, data):
        u"""
        Set the value of hash hash_name (e.g. "MD5") to data
        """
        if isinstance(hash_name, bytes):
            hash_name = hash_name.decode()
        if isinstance(data, bytes):
            data = data.decode()
        self.hashes[hash_name] = data

    def get_best_hash(self):
        u"""
        Return pair (hash_type, hash_data)

        SHA1 is the best hash, and MD5 is the second best hash.  None
        is returned if no hash is available.
        """
        if not self.hashes:
            return None
        try:
            return (u"SHA1", self.hashes[u'SHA1'])
        except KeyError:
            pass
        try:
            return (u"MD5", self.hashes[u'MD5'])
        except KeyError:
            pass
        return list(self.hashes.items())[0]

    def to_string(self):
        u"""
        Return nicely formatted string reporting all information
        """
        def index_to_string(index):
            u"""Return printable version of index without any whitespace"""
            if index:
                s = b"/".join(index)
                return Quote(s)
            else:
                return b"."

        def bfmt(x):
            if x is None:
                return b" "
            return str(x).encode()

        slist = [b"Volume %d:" % self.volume_number]
        whitespace = b"    "
        slist.append(b"%sStartingPath   %s %s" %
                     (whitespace, index_to_string(self.start_index), bfmt(self.start_block)))
        slist.append(b"%sEndingPath     %s %s" %
                     (whitespace, index_to_string(self.end_index), bfmt(self.end_block)))
        for key in self.hashes:
            slist.append(b"%sHash %s %s" %
                         (whitespace, key.encode(), self.hashes[key].encode()))
        return b"\n".join(slist)

    __str__ = to_string

    def from_string(self, s):
        u"""
        Initialize self from string s as created by to_string
        """
        def string_to_index(s):
            u"""
            Return tuple index from string
            """
            s = Unquote(s)
            if s == b".":
                return ()
            return tuple(s.split(b"/"))

        linelist = s.strip().split(b"\n")

        # Set volume number
        m = re.search(b"^Volume ([0-9]+):", linelist[0], re.I)
        if not m:
            raise VolumeInfoError(u"Bad first line '%s'" % (linelist[0],))
        self.volume_number = int(m.group(1))

        # Set other fields
        for line in linelist[1:]:
            if not line:
                continue
            line_split = line.strip().split()
            field_name = line_split[0].lower()
            other_fields = line_split[1:]
            if field_name == b"Volume":
                log.Warn(_(u"Warning, found extra Volume identifier"))
                break
            elif field_name == b"startingpath":
                self.start_index = string_to_index(other_fields[0])
                if len(other_fields) > 1:
                    self.start_block = int(other_fields[1])
                else:
                    self.start_block = None
            elif field_name == b"endingpath":
                self.end_index = string_to_index(other_fields[0])
                if len(other_fields) > 1:
                    self.end_block = int(other_fields[1])
                else:
                    self.end_block = None
            elif field_name == b"hash":
                self.set_hash(other_fields[0], other_fields[1])

        if self.start_index is None or self.end_index is None:
            raise VolumeInfoError(u"Start or end index not set")
        return self

    def __eq__(self, other):
        u"""
        Used in test suite
        """
        if not isinstance(other, VolumeInfo):
            log.Notice(_(u"Other is not VolumeInfo"))
            return None
        if self.volume_number != other.volume_number:
            log.Notice(_(u"Volume numbers don't match"))
            return None
        if self.start_index != other.start_index:
            log.Notice(_(u"start_indicies don't match"))
            return None
        if self.end_index != other.end_index:
            log.Notice(_(u"end_index don't match"))
            return None
        hash_list1 = list(self.hashes.items())
        hash_list1.sort()
        hash_list2 = list(other.hashes.items())
        hash_list2.sort()
        if hash_list1 != hash_list2:
            log.Notice(_(u"Hashes don't match"))
            return None
        return 1

    def __ne__(self, other):
        u"""
        Defines !=
        """
        return not self.__eq__(other)

    def contains(self, index_prefix, recursive=1):
        u"""
        Return true if volume might contain index

        If recursive is true, then return true if any index starting
        with index_prefix could be contained.  Otherwise, just check
        if index_prefix itself is between starting and ending
        indicies.
        """
        if recursive:
            return (self.start_index[:len(index_prefix)] <=
                    index_prefix <= self.end_index)
        else:
            return self.start_index <= index_prefix <= self.end_index


nonnormal_char_re = re.compile(b"(\\s|[\\\\\"'])")


def Quote(s):
    u"""
    Return quoted version of s safe to put in a manifest or volume info
    """
    if not nonnormal_char_re.search(s):
        return s  # no quoting necessary
    slist = []
    for i in range(0, len(s)):
        char = s[i:i + 1]
        if nonnormal_char_re.search(char):
            slist.append(b"\\x%02x" % ord(char))
        else:
            slist.append(char)
    return b'"%s"' % b"".join(slist)


def maybe_chr(ch):
    if sys.version_info.major >= 3:
        return chr(ch)
    else:
        return ch


def Unquote(quoted_string):
    u"""
    Return original string from quoted_string produced by above
    """
    if not maybe_chr(quoted_string[0]) == u'"' or maybe_chr(quoted_string[0]) == u"'":
        return quoted_string
    assert quoted_string[0] == quoted_string[-1]
    return_list = []
    i = 1  # skip initial char
    while i < len(quoted_string) - 1:
        char = quoted_string[i:i + 1]
        if char == b"\\":
            # quoted section
            assert maybe_chr(quoted_string[i + 1]) == u"x"
            if sys.version_info.major >= 3:
                return_list.append(int(quoted_string[i + 2:i + 4].decode(), 16).to_bytes(1, byteorder=u'big'))
            else:
                return_list.append(chr(int(quoted_string[i + 2:i + 4], 16)))
            i += 4
        else:
            return_list.append(char)
            i += 1
    return b"".join(return_list)
