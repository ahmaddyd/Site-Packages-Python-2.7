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

u"""Wrapper class around a file like "/usr/bin/env"

This class makes certain file operations more convenient and
associates stat information with filenames

"""

from __future__ import print_function
from future import standard_library
standard_library.install_aliases()
from builtins import str
from builtins import object

import errno
import gzip
import os
import re
import shutil
import socket
import stat
import time

from duplicity import cached_ops
from duplicity import config
from duplicity import dup_time
from duplicity import file_naming
from duplicity import gpg
from duplicity import librsync
from duplicity import log
from duplicity import tarfile
from duplicity import util
from duplicity.lazy import *  # pylint: disable=unused-wildcard-import,redefined-builtin

_copy_blocksize = 64 * 1024
_tmp_path_counter = 1


class StatResult(object):
    u"""Used to emulate the output of os.stat() and related"""
    # st_mode is required by the TarInfo class, but it's unclear how
    # to generate it from file permissions.
    st_mode = 0


class PathException(Exception):
    pass


class ROPath(object):
    u"""Read only Path

    Objects of this class doesn't represent real files, so they don't
    have a name.  They are required to be indexed though.

    """
    def __init__(self, index, stat=None):  # pylint: disable=unused-argument
        u"""ROPath initializer"""
        self.opened, self.fileobj = None, None
        self.index = index
        self.stat, self.type = None, None
        self.mode, self.devnums = None, None

    def set_from_stat(self):
        u"""Set the value of self.type, self.mode from self.stat"""
        if not self.stat:
            self.type = None

        st_mode = self.stat.st_mode
        if stat.S_ISREG(st_mode):
            self.type = u"reg"
        elif stat.S_ISDIR(st_mode):
            self.type = u"dir"
        elif stat.S_ISLNK(st_mode):
            self.type = u"sym"
        elif stat.S_ISFIFO(st_mode):
            self.type = u"fifo"
        elif stat.S_ISSOCK(st_mode):
            raise PathException(util.fsdecode(self.get_relative_path()) +
                                u"is a socket, unsupported by tar")
            self.type = u"sock"  # pylint: disable=unreachable
        elif stat.S_ISCHR(st_mode):
            self.type = u"chr"
        elif stat.S_ISBLK(st_mode):
            self.type = u"blk"
        else:
            raise PathException(u"Unknown type")

        self.mode = stat.S_IMODE(st_mode)
        if self.type in (u"chr", u"blk"):
            try:
                self.devnums = (os.major(self.stat.st_rdev),
                                os.minor(self.stat.st_rdev))
            except:
                log.Warn(_(u"Warning: %s invalid devnums (0x%X), treating as (0, 0).")
                         % (util.fsdecode(self.get_relative_path()), self.stat.st_rdev))
                self.devnums = (0, 0)

    def blank(self):
        u"""Black out self - set type and stat to None"""
        self.type, self.stat = None, None

    def exists(self):
        u"""True if corresponding file exists"""
        return self.type

    def isreg(self):
        u"""True if self corresponds to regular file"""
        return self.type == u"reg"

    def isdir(self):
        u"""True if self is dir"""
        return self.type == u"dir"

    def issym(self):
        u"""True if self is sym"""
        return self.type == u"sym"

    def isfifo(self):
        u"""True if self is fifo"""
        return self.type == u"fifo"

    def issock(self):
        u"""True is self is socket"""
        return self.type == u"sock"

    def isdev(self):
        u"""True is self is a device file"""
        return self.type == u"chr" or self.type == u"blk"

    def getdevloc(self):
        u"""Return device number path resides on"""
        return self.stat.st_dev

    def getsize(self):
        u"""Return length in bytes from stat object"""
        return self.stat.st_size

    def getmtime(self):
        u"""Return mod time of path in seconds"""
        return int(self.stat.st_mtime)

    def get_relative_path(self):
        u"""Return relative path, created from index"""
        if self.index:
            return b"/".join(self.index)
        else:
            return b"."

    def getperms(self):
        u"""Return permissions mode, owner and group"""
        s1 = self.stat
        return u'%s:%s %o' % (s1.st_uid, s1.st_gid, self.mode)

    def open(self, mode):
        u"""Return fileobj associated with self"""
        assert mode == u"rb" and self.fileobj and not self.opened, \
            u"%s %s %s" % (mode, self.fileobj, self.opened)
        self.opened = 1
        return self.fileobj

    def get_data(self):
        u"""Return contents of associated fileobj in string"""
        fin = self.open(u"rb")
        buf = fin.read()
        assert not fin.close()
        return buf

    def setfileobj(self, fileobj):
        u"""Set file object returned by open()"""
        assert not self.fileobj
        self.fileobj = fileobj
        self.opened = None

    def init_from_tarinfo(self, tarinfo):
        u"""Set data from tarinfo object (part of tarfile module)"""
        # Set the typepp
        type = tarinfo.type  # pylint: disable=redefined-builtin
        if type == tarfile.REGTYPE or type == tarfile.AREGTYPE:
            self.type = u"reg"
        elif type == tarfile.LNKTYPE:
            raise PathException(u"Hard links not supported yet")
        elif type == tarfile.SYMTYPE:
            self.type = u"sym"
            self.symtext = tarinfo.linkname
            if isinstance(self.symtext, u"".__class__):
                self.symtext = util.fsencode(self.symtext)
        elif type == tarfile.CHRTYPE:
            self.type = u"chr"
            self.devnums = (tarinfo.devmajor, tarinfo.devminor)
        elif type == tarfile.BLKTYPE:
            self.type = u"blk"
            self.devnums = (tarinfo.devmajor, tarinfo.devminor)
        elif type == tarfile.DIRTYPE:
            self.type = u"dir"
        elif type == tarfile.FIFOTYPE:
            self.type = u"fifo"
        else:
            raise PathException(u"Unknown tarinfo type %s" % (type,))

        self.mode = tarinfo.mode
        self.stat = StatResult()

        u""" If do_not_restore_owner is False,
        set user and group id
        use numeric id if name lookup fails
        OR
        --numeric-owner is set
        """
        try:
            if config.numeric_owner:
                raise KeyError
            self.stat.st_uid = cached_ops.getpwnam(tarinfo.uname)[2]
        except KeyError:
            self.stat.st_uid = tarinfo.uid
        try:
            if config.numeric_owner:
                raise KeyError
            self.stat.st_gid = cached_ops.getgrnam(tarinfo.gname)[2]
        except KeyError:
            self.stat.st_gid = tarinfo.gid

        self.stat.st_mtime = int(tarinfo.mtime)
        if self.stat.st_mtime < 0:
            log.Warn(_(u"Warning: %s has negative mtime, treating as 0.")
                     % (tarinfo.uc_name))
            self.stat.st_mtime = 0
        self.stat.st_size = tarinfo.size

    def get_ropath(self):
        u"""Return ropath copy of self"""
        new_ropath = ROPath(self.index, self.stat)
        new_ropath.type, new_ropath.mode = self.type, self.mode
        if self.issym():
            new_ropath.symtext = self.symtext
        elif self.isdev():
            new_ropath.devnums = self.devnums
        if self.exists():
            new_ropath.stat = self.stat
        return new_ropath

    def get_tarinfo(self):
        u"""Generate a tarfile.TarInfo object based on self

        Doesn't set size based on stat, because we may want to replace
        data wiht other stream.  Size should be set separately by
        calling function.

        """
        ti = tarfile.TarInfo()
        if self.index:
            ti.name = util.fsdecode(b"/".join(self.index))
        else:
            ti.name = u"."
        if self.isdir():
            ti.name += u"/"  # tar dir naming convention

        ti.size = 0
        if self.type:
            # Lots of this is specific to tarfile.py, hope it doesn't
            # change much...
            if self.isreg():
                ti.type = tarfile.REGTYPE
                ti.size = self.stat.st_size
            elif self.isdir():
                ti.type = tarfile.DIRTYPE
            elif self.isfifo():
                ti.type = tarfile.FIFOTYPE
            elif self.issym():
                ti.type = tarfile.SYMTYPE
                ti.linkname = self.symtext
                if isinstance(ti.linkname, bytes):
                    ti.linkname = util.fsdecode(ti.linkname)
            elif self.isdev():
                if self.type == u"chr":
                    ti.type = tarfile.CHRTYPE
                else:
                    ti.type = tarfile.BLKTYPE
                ti.devmajor, ti.devminor = self.devnums
            else:
                raise PathException(u"Unrecognized type " + str(self.type))

            ti.mode = self.mode
            ti.uid, ti.gid = self.stat.st_uid, self.stat.st_gid
            if self.stat.st_mtime < 0:
                log.Warn(_(u"Warning: %s has negative mtime, treating as 0.")
                         % (util.fsdecode(self.get_relative_path())))
                ti.mtime = 0
            else:
                ti.mtime = int(self.stat.st_mtime)

            try:
                ti.uname = cached_ops.getpwuid(ti.uid)[0]
            except KeyError:
                ti.uname = u''
            try:
                ti.gname = cached_ops.getgrgid(ti.gid)[0]
            except KeyError:
                ti.gname = u''

            if ti.type in (tarfile.CHRTYPE, tarfile.BLKTYPE):
                if hasattr(os, u"major") and hasattr(os, u"minor"):
                    ti.devmajor, ti.devminor = self.devnums
        else:
            # Currently we depend on an uninitiliazed tarinfo file to
            # already have appropriate headers.  Still, might as well
            # make sure mode and size set.
            ti.mode, ti.size = 0, 0
        return ti

    def __eq__(self, other):
        u"""Used to compare two ROPaths.  Doesn't look at fileobjs"""
        if not self.type and not other.type:
            return 1  # neither exists
        if not self.stat and other.stat or not other.stat and self.stat:
            return 0
        if self.type != other.type:
            return 0

        if self.isreg() or self.isdir() or self.isfifo():
            # Don't compare sizes, because we might be comparing
            # signature size to size of file.
            if not self.perms_equal(other):
                return 0
            if int(self.stat.st_mtime) == int(other.stat.st_mtime):
                return 1
            # Below, treat negative mtimes as equal to 0
            return self.stat.st_mtime <= 0 and other.stat.st_mtime <= 0
        elif self.issym():
            # here only symtext matters
            return self.symtext == other.symtext
        elif self.isdev():
            return self.perms_equal(other) and self.devnums == other.devnums
        assert 0

    def __ne__(self, other):
        return not self.__eq__(other)

    def compare_verbose(self, other, include_data=0):
        u"""Compare ROPaths like __eq__, but log reason if different

        This is placed in a separate function from __eq__ because
        __eq__ should be very time sensitive, and logging statements
        would slow it down.  Used when verifying.

        Only run if include_data is true.

        """
        def log_diff(log_string):
            log_str = _(u"Difference found:") + u" " + log_string
            log.Notice(log_str % (util.fsdecode(self.get_relative_path())))

        if include_data is False:
            return True

        if not self.type and not other.type:
            return 1
        if not self.stat and other.stat:
            log_diff(_(u"New file %s"))
            return 0
        if not other.stat and self.stat:
            log_diff(_(u"File %s is missing"))
            return 0
        if self.type != other.type:
            log_diff(_(u"File %%s has type %s, expected %s") %
                     (other.type, self.type))
            return 0

        if self.isreg() or self.isdir() or self.isfifo():
            if not self.perms_equal(other):
                log_diff(_(u"File %%s has permissions %s, expected %s") %
                         (other.getperms(), self.getperms()))
                return 0
            if ((int(self.stat.st_mtime) != int(other.stat.st_mtime)) and
                    (self.stat.st_mtime > 0 or other.stat.st_mtime > 0)):
                log_diff(_(u"File %%s has mtime %s, expected %s") %
                         (dup_time.timetopretty(int(other.stat.st_mtime)),
                          dup_time.timetopretty(int(self.stat.st_mtime))))
                return 0
            if self.isreg():
                if self.compare_data(other):
                    return 1
                else:
                    log_diff(_(u"Data for file %s is different"))
                    return 0
            else:
                return 1
        elif self.issym():
            if self.symtext == other.symtext or self.symtext + util.fsencode(os.sep) == other.symtext:
                return 1
            else:
                log_diff(_(u"Symlink %%s points to %s, expected %s") %
                         (other.symtext, self.symtext))
                return 0
        elif self.isdev():
            if not self.perms_equal(other):
                log_diff(_(u"File %%s has permissions %s, expected %s") %
                         (other.getperms(), self.getperms()))
                return 0
            if self.devnums != other.devnums:
                log_diff(_(u"Device file %%s has numbers %s, expected %s")
                         % (other.devnums, self.devnums))
                return 0
            return 1
        assert 0

    def compare_data(self, other):
        u"""Compare data from two regular files, return true if same"""
        f1 = self.open(u"rb")
        f2 = other.open(u"rb")

        def close():
            assert not f1.close()
            assert not f2.close()

        while 1:
            buf1 = f1.read(_copy_blocksize)
            buf2 = f2.read(_copy_blocksize)
            if buf1 != buf2:
                close()
                return 0
            if not buf1:
                close()
                return 1

    def perms_equal(self, other):
        u"""True if self and other have same permissions and ownership"""
        s1, s2 = self.stat, other.stat
        return (self.mode == other.mode and
                s1.st_gid == s2.st_gid and s1.st_uid == s2.st_uid)

    def copy(self, other):
        u"""Copy self to other.  Also copies data.  Other must be Path"""
        if self.isreg():
            other.writefileobj(self.open(u"rb"))
        elif self.isdir():
            os.mkdir(other.name)
        elif self.issym():
            os.symlink(self.symtext, other.name)
            if not config.do_not_restore_ownership:
                os.lchown(other.name, self.stat.st_uid, self.stat.st_gid)
            other.setdata()
            return  # no need to copy symlink attributes
        elif self.isfifo():
            os.mkfifo(other.name)
        elif self.issock():
            socket.socket(socket.AF_UNIX).bind(other.name)
        elif self.isdev():
            if self.type == u"chr":
                devtype = u"c"
            else:
                devtype = u"b"
            other.makedev(devtype, *self.devnums)
        self.copy_attribs(other)

    def copy_attribs(self, other):
        u"""Only copy attributes from self to other"""
        if isinstance(other, Path):
            if self.stat and not config.do_not_restore_ownership:
                util.maybe_ignore_errors(lambda: os.chown(other.name, self.stat.st_uid, self.stat.st_gid))
            util.maybe_ignore_errors(lambda: os.chmod(other.name, self.mode))
            util.maybe_ignore_errors(lambda: os.utime(other.name, (time.time(), self.stat.st_mtime)))
            other.setdata()
        else:
            # write results to fake stat object
            assert isinstance(other, ROPath)
            stat = StatResult()
            stat.st_uid, stat.st_gid = self.stat.st_uid, self.stat.st_gid
            stat.st_mtime = int(self.stat.st_mtime)
            other.stat = stat
            other.mode = self.mode

    def __str__(self):
        u"""Return string representation"""
        return u"(%s %s)" % (util.uindex(self.index), self.type)


class Path(ROPath):
    u"""
    Path class - wrapper around ordinary local files

    Besides caching stat() results, this class organizes various file
    code.
    """
    regex_chars_to_quote = re.compile(u"[\\\\\\\"\\$`]")

    def rename_index(self, index):
        if not config.rename or not index:
            return index  # early exit
        path = os.path.normcase(os.path.join(*index))
        tail = []
        while path and path not in config.rename:
            path, extra = os.path.split(path)
            tail.insert(0, extra)
        if path:
            return config.rename[path].split(util.fsencode(os.sep)) + tail
        else:
            return index  # no rename found

    def __init__(self, base, index=()):
        u"""Path initializer"""
        # self.opened should be true if the file has been opened, and
        # self.fileobj can override returned fileobj
        self.opened, self.fileobj = None, None
        if isinstance(base, str):
            # For now (Python 2), it is helpful to know that all paths
            # are starting with bytes -- see note above util.fsencode definition
            base = util.fsencode(base)
        self.base = base

        # Create self.index, which is the path as a tuple
        self.index = self.rename_index(index)

        self.name = os.path.join(base, *self.index)

        # We converted any unicode base to filesystem encoding, so self.name should
        # be in filesystem encoding already and does not need to change
        self.uc_name = util.fsdecode(self.name)

        self.setdata()

    def setdata(self):
        u"""Refresh stat cache"""
        try:
            # We may be asked to look at the target of symlinks rather than
            # the link itself.
            if config.copy_links:
                self.stat = os.stat(self.name)
            else:
                self.stat = os.lstat(self.name)
        except OSError as e:
            err_string = errno.errorcode[e.errno]
            if err_string in [u"ENOENT", u"ENOTDIR", u"ELOOP", u"ENOTCONN", u"ENODEV"]:
                self.stat, self.type = None, None  # file doesn't exist
                self.mode = None
            else:
                raise
        else:
            self.set_from_stat()
            if self.issym():
                self.symtext = os.readlink(self.name)

    def append(self, ext):
        u"""Return new Path with ext added to index"""
        if isinstance(ext, u"".__class__):
            ext = util.fsencode(ext)
        return self.__class__(self.base, self.index + (ext,))

    def new_index(self, index):
        u"""Return new Path with index index"""
        return self.__class__(self.base, index)

    def listdir(self):
        u"""Return list generated by os.listdir"""
        return os.listdir(self.name)

    def isemptydir(self):
        u"""Return true if path is a directory and is empty"""
        return self.isdir() and not self.listdir()

    def contains(self, child):
        u"""Return true if path is a directory and contains child"""
        if isinstance(child, u"".__class__):
            child = util.fsencode(child)
        # We don't use append(child).exists() here because that requires exec
        # permissions as well as read. listdir() just needs read permissions.
        return self.isdir() and child in self.listdir()

    def open(self, mode=u"rb"):
        u"""
        Return fileobj associated with self

        Usually this is just the file data on disk, but can be
        replaced with arbitrary data using the setfileobj method.
        """
        assert not self.opened
        if self.fileobj:
            result = self.fileobj
        else:
            result = open(self.name, mode)
        return result

    def makedev(self, type, major, minor):  # pylint: disable=redefined-builtin
        u"""Make a device file with specified type, major/minor nums"""
        cmdlist = [u'mknod', self.name, type, str(major), str(minor)]
        if os.spawnvp(os.P_WAIT, u'mknod', cmdlist) != 0:
            raise PathException(u"Error running %s" % cmdlist)
        self.setdata()

    def mkdir(self):
        u"""Make directory(s) at specified path"""
        log.Info(_(u"Making directory %s") % self.uc_name)
        try:
            os.makedirs(self.name)
        except OSError:
            if (not config.force):
                raise PathException(u"Error creating directory %s" % self.uc_name, 7)
        self.setdata()

    def delete(self):
        u"""Remove this file"""
        log.Info(_(u"Deleting %s") % self.uc_name)
        if self.isdir():
            util.ignore_missing(os.rmdir, self.name)
        else:
            util.ignore_missing(os.unlink, self.name)
        self.setdata()

    def touch(self):
        u"""Open the file, write 0 bytes, close"""
        log.Info(_(u"Touching %s") % self.uc_name)
        fp = self.open(u"wb")
        fp.close()

    def deltree(self):
        u"""Remove self by recursively deleting files under it"""
        from duplicity import selection  # todo: avoid circ. dep. issue
        log.Info(_(u"Deleting tree %s") % self.uc_name)
        itr = IterTreeReducer(PathDeleter, [])
        for path in selection.Select(self).set_iter():
            itr(path.index, path)
        itr.Finish()
        self.setdata()

    def get_parent_dir(self):
        u"""Return directory that self is in"""
        if self.index:
            return Path(self.base, self.index[:-1])
        else:
            components = self.base.split(b"/")
            if len(components) == 2 and not components[0]:
                return Path(b"/")  # already in root directory
            else:
                return Path(b"/".join(components[:-1]))

    def writefileobj(self, fin):
        u"""Copy file object fin to self.  Close both when done."""
        fout = self.open(u"wb")
        while 1:
            buf = fin.read(_copy_blocksize)
            if not buf:
                break
            fout.write(buf)
        if fin.close() or fout.close():
            raise PathException(u"Error closing file object")
        self.setdata()

    def rename(self, new_path):
        u"""Rename file at current path to new_path."""
        shutil.move(self.name, new_path.name)
        self.setdata()
        new_path.setdata()

    def move(self, new_path):
        u"""Like rename but destination may be on different file system"""
        self.copy(new_path)
        self.delete()

    def chmod(self, mode):
        u"""Change permissions of the path"""
        os.chmod(self.name, mode)
        self.setdata()

    def patch_with_attribs(self, diff_ropath):
        u"""Patch self with diff and then copy attributes over"""
        assert self.isreg() and diff_ropath.isreg()
        temp_path = self.get_temp_in_same_dir()
        fbase = self.open(u"rb")
        fdiff = diff_ropath.open(u"rb")
        patch_fileobj = librsync.PatchedFile(fbase, fdiff)
        temp_path.writefileobj(patch_fileobj)
        assert not fbase.close()
        assert not fdiff.close()
        diff_ropath.copy_attribs(temp_path)
        temp_path.rename(self)

    def get_temp_in_same_dir(self):
        u"""Return temp non existent path in same directory as self"""
        global _tmp_path_counter
        parent_dir = self.get_parent_dir()
        while 1:
            temp_path = parent_dir.append(u"duplicity_temp." +
                                          str(_tmp_path_counter))
            if not temp_path.type:
                return temp_path
            _tmp_path_counter += 1
            assert _tmp_path_counter < 10000, \
                u"Warning too many temp files created for " + self.uc_name

    def compare_recursive(self, other, verbose=None):
        u"""Compare self to other Path, descending down directories"""
        from duplicity import selection  # todo: avoid circ. dep. issue
        selfsel = selection.Select(self).set_iter()
        othersel = selection.Select(other).set_iter()
        return Iter.equal(selfsel, othersel, verbose)

    def __repr__(self):
        u"""Return string representation"""
        return u"(%s %s %s)" % (self.index, self.name, self.type)

    def quote(self, s=None):
        u"""
        Return quoted version of s (defaults to self.name)

        The output is meant to be interpreted with shells, so can be
        used with os.system.
        """
        if not s:
            s = self.uc_name
        return u'"%s"' % self.regex_chars_to_quote.sub(lambda m: u"\\" + m.group(0), s)

    def unquote(self, s):
        u"""Return unquoted version of string s, as quoted by above quote()"""
        assert s[0] == s[-1] == u"\""  # string must be quoted by above
        result = u""
        i = 1
        while i < len(s) - 1:
            if s[i] == u"\\":
                result += s[i + 1]
                i += 2
            else:
                result += s[i]
                i += 1
        return result

    def get_filename(self):
        u"""Return filename of last component"""
        components = self.name.split(b"/")
        assert components and components[-1]
        return components[-1]

    def get_canonical(self):
        u"""
        Return string of canonical version of path

        Remove ".", and trailing slashes where possible.  Note that
        it's harder to remove "..", as "foo/bar/.." is not necessarily
        "foo", so we can't use path.normpath()
        """
        newpath = b"/".join([x for x in self.name.split(b"/") if x and x != b"."])
        if self.uc_name[0] == u"/":
            return b"/" + newpath
        elif newpath:
            return newpath
        else:
            return b"."


class DupPath(Path):
    u"""
    Represent duplicity data files

    Based on the file name, files that are compressed or encrypted
    will have different open() methods.
    """
    def __init__(self, base, index=(), parseresults=None):
        u"""
        DupPath initializer

        The actual filename (no directory) must be the single element
        of the index, unless parseresults is given.

        """
        if parseresults:
            self.pr = parseresults
        else:
            assert len(index) == 1
            self.pr = file_naming.parse(index[0])
            assert self.pr, u"must be a recognizable duplicity file"

        Path.__init__(self, base, index)

    def filtered_open(self, mode=u"rb", gpg_profile=None):
        u"""
        Return fileobj with appropriate encryption/compression

        If encryption is specified but no gpg_profile, use
        config.default_profile.
        """
        assert not self.opened and not self.fileobj
        assert not (self.pr.encrypted and self.pr.compressed)
        if gpg_profile:
            assert self.pr.encrypted

        if self.pr.compressed:
            return gzip.GzipFile(self.name, mode)
        elif self.pr.encrypted:
            if not gpg_profile:
                gpg_profile = config.gpg_profile
            if mode == u"rb":
                return gpg.GPGFile(False, self, gpg_profile)
            elif mode == u"wb":
                return gpg.GPGFile(True, self, gpg_profile)
        else:
            return self.open(mode)


class PathDeleter(ITRBranch):
    u"""Delete a directory.  Called by Path.deltree"""
    def start_process(self, index, path):  # pylint: disable=unused-argument
        self.path = path

    def end_process(self):
        self.path.delete()

    def can_fast_process(self, index, path):  # pylint: disable=unused-argument
        return not path.isdir()

    def fast_process(self, index, path):  # pylint: disable=unused-argument
        path.delete()
