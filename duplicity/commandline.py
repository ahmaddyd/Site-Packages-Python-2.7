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

u"""Parse command line, check for consistency, and set config"""

from __future__ import print_function
from future import standard_library
standard_library.install_aliases()
from builtins import str
from builtins import range

from copy import copy
import optparse
import os
import re
import sys
import socket
import io

try:
    from hashlib import md5
except ImportError:
    from md5 import new as md5

from duplicity import backend
from duplicity import dup_time
from duplicity import config
from duplicity import gpg
from duplicity import log
from duplicity import path
from duplicity import selection
from duplicity import util


select_opts = []  # Will hold all the selection options
select_files = []  # Will hold file objects when filelist given

full_backup = None  # Will be set to true if full command given
list_current = None  # Will be set to true if list-current command given
collection_status = None  # Will be set to true if collection-status command given
cleanup = None  # Set to true if cleanup command given
verify = None  # Set to true if verify command given
replicate = None  # Set to true if replicate command given

commands = [u"cleanup",
            u"collection-status",
            u"full",
            u"incremental",
            u"list-current-files",
            u"remove-older-than",
            u"remove-all-but-n-full",
            u"remove-all-inc-of-but-n-full",
            u"restore",
            u"verify",
            u"replicate"
            ]


def old_fn_deprecation(opt):
    log.Log(_(u"Warning: Option %s is pending deprecation "
              u"and will be removed in version 0.9.0.\n"
              u"Use of default filenames is strongly suggested.") % opt,
            log.ERROR, force_print=True)


def old_globbing_filelist_deprecation(opt):
    log.Log(_(u"Warning: Option %s is pending deprecation and will be removed in a future release.\n"
              u"--include-filelist and --exclude-filelist now accept globbing characters and should "
              u"be used instead.") % opt,
            log.ERROR, force_print=True)


def stdin_deprecation(opt):
    # See https://bugs.launchpad.net/duplicity/+bug/1423367
    # In almost all Linux distros stdin is a file represented by /dev/stdin,
    # so --exclude-file=/dev/stdin will work as a substitute.
    log.Log(_(u"Warning: Option %s is pending deprecation and will be removed in a future release.\n"
              u"On many GNU/Linux systems, stdin is represented by /dev/stdin and\n"
              u"--include-filelist=/dev/stdin or --exclude-filelist=/dev/stdin could\n"
              u"be used as a substitute.") % opt,
            log.ERROR, force_print=True)


# log options handled in log.py.  Add noop to make optparse happy
def noop():
    pass


def expand_fn(filename):
    return os.path.expanduser(os.path.expandvars(filename))


def expand_archive_dir(archdir, backname):
    u"""
    Return expanded version of archdir joined with backname.
    """
    assert config.backup_name is not None, \
        u"expand_archive_dir() called prior to config.backup_name being set"

    return expand_fn(os.path.join(archdir, backname))


def generate_default_backup_name(backend_url):
    u"""
    @param backend_url: URL to backend.
    @returns A default backup name (string).
    """
    # For default, we hash args to obtain a reasonably safe default.
    # We could be smarter and resolve things like relative paths, but
    # this should actually be a pretty good compromise. Normally only
    # the destination will matter since you typically only restart
    # backups of the same thing to a given destination. The inclusion
    # of the source however, does protect against most changes of
    # source directory (for whatever reason, such as
    # /path/to/different/snapshot). If the user happens to have a case
    # where relative paths are used yet the relative path is the same
    # (but duplicity is run from a different directory or similar),
    # then it is simply up to the user to set --archive-dir properly.
    burlhash = md5()
    burlhash.update(backend_url.encode())
    return burlhash.hexdigest()


def check_file(option, opt, value):  # pylint: disable=unused-argument
    return expand_fn(value)


def check_time(option, opt, value):  # pylint: disable=unused-argument
    try:
        return dup_time.genstrtotime(value)
    except dup_time.TimeException as e:
        raise optparse.OptionValueError(str(e))


def check_verbosity(option, opt, value):  # pylint: disable=unused-argument
    fail = False

    value = value.lower()
    if value in [u'e', u'error']:
        verb = log.ERROR
    elif value in [u'w', u'warning']:
        verb = log.WARNING
    elif value in [u'n', u'notice']:
        verb = log.NOTICE
    elif value in [u'i', u'info']:
        verb = log.INFO
    elif value in [u'd', u'debug']:
        verb = log.DEBUG
    else:
        try:
            verb = int(value)
            if verb < 0 or verb > 9:
                fail = True
        except ValueError:
            fail = True

    if fail:
        # TRANSL: In this portion of the usage instructions, "[ewnid]" indicates which
        # characters are permitted (e, w, n, i, or d); the brackets imply their own
        # meaning in regex; i.e., only one of the characters is allowed in an instance.
        raise optparse.OptionValueError(u"Verbosity must be one of: digit [0-9], character [ewnid], "
                                        u"or word ['error', 'warning', 'notice', 'info', 'debug']. "
                                        u"The default is 4 (Notice).  It is strongly recommended "
                                        u"that verbosity level is set at 2 (Warning) or higher.")

    return verb


class DupOption(optparse.Option):
    TYPES = optparse.Option.TYPES + (u"file", u"time", u"verbosity",)
    TYPE_CHECKER = copy(optparse.Option.TYPE_CHECKER)
    TYPE_CHECKER[u"file"] = check_file
    TYPE_CHECKER[u"time"] = check_time
    TYPE_CHECKER[u"verbosity"] = check_verbosity

    ACTIONS = optparse.Option.ACTIONS + (u"extend",)
    STORE_ACTIONS = optparse.Option.STORE_ACTIONS + (u"extend",)
    TYPED_ACTIONS = optparse.Option.TYPED_ACTIONS + (u"extend",)
    ALWAYS_TYPED_ACTIONS = optparse.Option.ALWAYS_TYPED_ACTIONS + (u"extend",)

    def take_action(self, action, dest, opt, value, values, parser):
        if action == u"extend":
            if not value:
                return
            if hasattr(values, dest) and getattr(values, dest):
                setattr(values, dest, getattr(values, dest) + u' ' + value)
            else:
                setattr(values, dest, value)
        else:
            optparse.Option.take_action(
                self, action, dest, opt, value, values, parser)


def parse_cmdline_options(arglist):
    u"""Parse argument list"""
    global select_opts, select_files, full_backup
    global list_current, collection_status, cleanup, remove_time, verify, replicate

    def set_log_fd(fd):
        if fd < 1:
            raise optparse.OptionValueError(u"log-fd must be greater than zero.")
        log.add_fd(fd)

    def set_time_sep(sep, opt):
        if sep == u'-':
            raise optparse.OptionValueError(u"Dash ('-') not valid for time-separator.")
        config.time_separator = sep
        old_fn_deprecation(opt)

    def add_selection(o, option, additional_arg, p):  # pylint: disable=unused-argument
        if o.type in (u"string", u"file"):
            addarg = util.fsdecode(additional_arg)
        else:
            addarg = additional_arg
        select_opts.append((util.fsdecode(option), addarg))

    def add_filelist(o, s, filename, p):  # pylint: disable=unused-argument
        select_opts.append((util.fsdecode(s), util.fsdecode(filename)))
        try:
            select_files.append(io.open(filename, u"rt", encoding=u"UTF-8"))
        except IOError:
            log.FatalError(_(u"Error opening file %s") % filename,
                           log.ErrorCode.cant_open_filelist)

    def print_ver(o, s, v, p):  # pylint: disable=unused-argument
        print(u"duplicity %s" % (config.version))
        sys.exit(0)

    def add_rename(o, s, v, p):  # pylint: disable=unused-argument
        key = util.fsencode(os.path.normcase(os.path.normpath(v[0])))
        config.rename[key] = util.fsencode(v[1])

    parser = optparse.OptionParser(option_class=DupOption, usage=usage())

    # If this is true, only warn and don't raise fatal error when backup
    # source directory doesn't match previous backup source directory.
    parser.add_option(u"--allow-source-mismatch", action=u"store_true")

    # Set to the path of the archive directory (the directory which
    # contains the signatures and manifests of the relevent backup
    # collection), and for checkpoint state between volumes.
    # TRANSL: Used in usage help to represent a Unix-style path name. Example:
    # --archive-dir <path>
    parser.add_option(u"--archive-dir", type=u"file", metavar=_(u"path"))

    # Asynchronous put/get concurrency limit
    # (default of 0 disables asynchronicity).
    parser.add_option(u"--asynchronous-upload", action=u"store_const", const=1,
                      dest=u"async_concurrency")

    parser.add_option(u"--compare-data", action=u"store_true")

    # config dir for future use
    parser.add_option(u"--config-dir", type=u"file", metavar=_(u"path"),
                      help=optparse.SUPPRESS_HELP)

    # When symlinks are encountered, the item they point to is copied rather than
    # the symlink.
    parser.add_option(u"--copy-links", action=u"store_true")

    # for testing -- set current time
    parser.add_option(u"--current-time", type=u"int",
                      dest=u"current_time", help=optparse.SUPPRESS_HELP)

    # Don't actually do anything, but still report what would be done
    parser.add_option(u"--dry-run", action=u"store_true")

    # TRANSL: Used in usage help to represent an ID for a GnuPG key. Example:
    # --encrypt-key <gpg_key_id>
    parser.add_option(u"--encrypt-key", type=u"string", metavar=_(u"gpg-key-id"),
                      dest=u"", action=u"callback",
                      callback=lambda o, s, v, p: config.gpg_profile.recipients.append(v))

    # secret keyring in which the private encrypt key can be found
    parser.add_option(u"--encrypt-secret-keyring", type=u"string", metavar=_(u"path"))

    parser.add_option(u"--encrypt-sign-key", type=u"string", metavar=_(u"gpg-key-id"),
                      dest=u"", action=u"callback",
                      callback=lambda o, s, v, p: (config.gpg_profile.recipients.append(v), set_sign_key(v)))

    # TRANSL: Used in usage help to represent a "glob" style pattern for
    # matching one or more files, as described in the documentation.
    # Example:
    # --exclude <shell_pattern>
    parser.add_option(u"--exclude", action=u"callback", metavar=_(u"shell_pattern"),
                      dest=u"", type=u"string", callback=add_selection)

    parser.add_option(u"--exclude-device-files", action=u"callback",
                      dest=u"", callback=add_selection)

    parser.add_option(u"--exclude-filelist", type=u"file", metavar=_(u"filename"),
                      dest=u"", action=u"callback", callback=add_filelist)

    parser.add_option(u"--exclude-filelist-stdin", action=u"callback", dest=u"",
                      callback=lambda o, s, v, p: (select_opts.append((u"--exclude-filelist", u"standard input")),
                                                   select_files.append(sys.stdin),
                                                   stdin_deprecation(o)),
                      help=optparse.SUPPRESS_HELP)

    parser.add_option(u"--exclude-globbing-filelist", type=u"file", metavar=_(u"filename"),
                      dest=u"", action=u"callback", callback=lambda o, s, v, p: (add_filelist(o, s, v, p),
                                                                                 old_globbing_filelist_deprecation(s)),
                      help=optparse.SUPPRESS_HELP)

    # TRANSL: Used in usage help to represent the name of a file. Example:
    # --log-file <filename>
    parser.add_option(u"--exclude-if-present", metavar=_(u"filename"), dest=u"",
                      type=u"file", action=u"callback", callback=add_selection)

    parser.add_option(u"--exclude-other-filesystems", action=u"callback",
                      dest=u"", callback=add_selection)

    # TRANSL: Used in usage help to represent a regular expression (regexp).
    parser.add_option(u"--exclude-regexp", metavar=_(u"regular_expression"),
                      dest=u"", type=u"string", action=u"callback", callback=add_selection)

    # Exclude any files with modification dates older than this from the backup
    parser.add_option(u"--exclude-older-than", type=u"time", metavar=_(u"time"),
                      dest=u"", action=u"callback", callback=add_selection)

    # used in testing only - raises exception after volume
    parser.add_option(u"--fail-on-volume", type=u"int",
                      help=optparse.SUPPRESS_HELP)

    # used to provide a prefix on top of the defaul tar file name
    parser.add_option(u"--file-prefix", type=u"string", dest=u"file_prefix", action=u"store")

    # used to provide a suffix for manifest files only
    parser.add_option(u"--file-prefix-manifest", type=u"string", dest=u"file_prefix_manifest", action=u"store")

    # used to provide a suffix for archive files only
    parser.add_option(u"--file-prefix-archive", type=u"string", dest=u"file_prefix_archive", action=u"store")

    # used to provide a suffix for sigature files only
    parser.add_option(u"--file-prefix-signature", type=u"string", dest=u"file_prefix_signature", action=u"store")

    # used in testing only - skips upload for a given volume
    parser.add_option(u"--skip-volume", type=u"int",
                      help=optparse.SUPPRESS_HELP)

    # If set, restore only the subdirectory or file specified, not the
    # whole root.
    # TRANSL: Used in usage help to represent a Unix-style path name. Example:
    # --archive-dir <path>
    parser.add_option(u"--file-to-restore", u"-r", action=u"callback", type=u"file",
                      metavar=_(u"path"), dest=u"restore_dir",
                      callback=lambda o, s, v, p: setattr(p.values, u"restore_dir", util.fsencode(v.strip(u'/'))))

    # Used to confirm certain destructive operations like deleting old files.
    parser.add_option(u"--force", action=u"store_true")

    # FTP data connection type
    parser.add_option(u"--ftp-passive", action=u"store_const", const=u"passive", dest=u"ftp_connection")
    parser.add_option(u"--ftp-regular", action=u"store_const", const=u"regular", dest=u"ftp_connection")

    # If set, forces a full backup if the last full backup is older than
    # the time specified
    parser.add_option(u"--full-if-older-than", type=u"time", dest=u"full_force_time", metavar=_(u"time"))

    parser.add_option(u"--gio", action=u"callback", dest=u"use_gio",
                      callback=lambda o, s, v, p: (setattr(p.values, o.dest, True),
                                                   old_fn_deprecation(s)))

    parser.add_option(u"--gpg-binary", type=u"file", metavar=_(u"path"))

    parser.add_option(u"--gpg-options", action=u"extend", metavar=_(u"options"))

    # TRANSL: Used in usage help to represent an ID for a hidden GnuPG key. Example:
    # --hidden-encrypt-key <gpg_key_id>
    parser.add_option(u"--hidden-encrypt-key", type=u"string", metavar=_(u"gpg-key-id"),
                      dest=u"", action=u"callback",
                      callback=lambda o, s, v, p: config.gpg_profile.hidden_recipients.append(v))

    # Fake-root for iDrived backend
    parser.add_option(u"--idr-fakeroot", dest=u"fakeroot", type=u"file", metavar=_(u"path"))

    # ignore (some) errors during operations; supposed to make it more
    # likely that you are able to restore data under problematic
    # circumstances. the default should absolutely always be False unless
    # you know what you are doing.
    parser.add_option(u"--ignore-errors", action=u"callback",
                      dest=u"ignore_errors",
                      callback=lambda o, s, v, p: (log.Warn(
                          _(u"Running in 'ignore errors' mode due to %s; please "
                            u"re-consider if this was not intended") % s),
                          setattr(p.values, u"ignore_errors", True)))

    # Whether to use the full email address as the user name when
    # logging into an imap server. If false just the user name
    # part of the email address is used.
    parser.add_option(u"--imap-full-address", action=u"store_true")

    # Name of the imap folder where we want to store backups.
    # Can be changed with a command line argument.
    # TRANSL: Used in usage help to represent an imap mailbox
    parser.add_option(u"--imap-mailbox", metavar=_(u"imap_mailbox"))

    parser.add_option(u"--include", action=u"callback", metavar=_(u"shell_pattern"),
                      dest=u"", type=u"string", callback=add_selection)
    parser.add_option(u"--include-filelist", type=u"file", metavar=_(u"filename"),
                      dest=u"", action=u"callback", callback=add_filelist)
    parser.add_option(u"--include-filelist-stdin", action=u"callback", dest=u"",
                      callback=lambda o, s, v, p: (select_opts.append((u"--include-filelist", u"standard input")),
                                                   select_files.append(sys.stdin),
                                                   stdin_deprecation(o)),
                      help=optparse.SUPPRESS_HELP)
    parser.add_option(u"--include-globbing-filelist", type=u"file", metavar=_(u"filename"),
                      dest=u"", action=u"callback", callback=lambda o, s, v, p: (add_filelist(o, s, v, p),
                                                                                 old_globbing_filelist_deprecation(s)),
                      help=optparse.SUPPRESS_HELP)
    parser.add_option(u"--include-regexp", metavar=_(u"regular_expression"), dest=u"",
                      type=u"string", action=u"callback", callback=add_selection)

    parser.add_option(u"--log-fd", type=u"int", metavar=_(u"file_descriptor"),
                      dest=u"", action=u"callback",
                      callback=lambda o, s, v, p: set_log_fd(v))

    # TRANSL: Used in usage help to represent the name of a file. Example:
    # --log-file <filename>
    parser.add_option(u"--log-file", type=u"file", metavar=_(u"filename"),
                      dest=u"", action=u"callback",
                      callback=lambda o, s, v, p: log.add_file(v))

    # log option to add timestamp and level to log entries
    parser.add_option(u"--log-timestamp", action=u"callback",
                      callback=lambda o, s, v, p: noop())

    # Maximum block size for large files
    parser.add_option(u"--max-blocksize", type=u"int", metavar=_(u"number"))

    # TRANSL: Used in usage help (noun)
    parser.add_option(u"--name", dest=u"backup_name", metavar=_(u"backup name"))

    # If set to false, then do not encrypt files on remote system
    parser.add_option(u"--no-encryption", action=u"store_false", dest=u"encryption")

    # If set to false, then do not compress files on remote system
    parser.add_option(u"--no-compression", action=u"store_false", dest=u"compression")

    # If set, print the statistics after every backup session
    parser.add_option(u"--no-print-statistics", action=u"store_false", dest=u"print_statistics")

    # If true, filelists and directory statistics will be split on
    # nulls instead of newlines.
    parser.add_option(u"--null-separator", action=u"store_true")

    # number of retries on network operations
    # TRANSL: Used in usage help to represent a desired number of
    # something. Example:
    # --num-retries <number>
    parser.add_option(u"--num-retries", type=u"int", metavar=_(u"number"))

    # File owner uid keeps number from tar file. Like same option in GNU tar.
    parser.add_option(u"--numeric-owner", action=u"store_true")

    # Do no restore the uid/gid when finished, useful if you're restoring
    # data without having root privileges or Unix users support
    parser.add_option(u"--do-not-restore-ownership", action=u"store_true")

    # Whether the old filename format is in effect.
    parser.add_option(u"--old-filenames", action=u"callback",
                      dest=u"old_filenames",
                      callback=lambda o, s, v, p: (setattr(p.values, o.dest, True),
                                                   old_fn_deprecation(s)))

    # Sync only required metadata
    parser.add_option(u"--metadata-sync-mode",
                      default=u"partial",
                      choices=(u"full", u"partial"))

    # Level of Redundancy in % for Par2 files
    parser.add_option(u"--par2-redundancy", type=u"int", metavar=_(u"number"))

    # Verbatim par2 options
    parser.add_option(u"--par2-options", action=u"extend", metavar=_(u"options"))

    # Used to display the progress for the full and incremental backup operations
    parser.add_option(u"--progress", action=u"store_true")

    # Used to control the progress option update rate in seconds. Default: prompts each 3 seconds
    parser.add_option(u"--progress-rate", type=u"int", metavar=_(u"number"))

    # option to trigger Pydev debugger
    parser.add_option(u"--pydevd", action=u"store_true")

    # option to rename files during restore
    parser.add_option(u"--rename", type=u"file", action=u"callback", nargs=2,
                      callback=add_rename)

    # Restores will try to bring back the state as of the following time.
    # If it is None, default to current time.
    # TRANSL: Used in usage help to represent a time spec for a previous
    # point in time, as described in the documentation. Example:
    # duplicity remove-older-than time [options] target_url
    parser.add_option(u"--restore-time", u"--time", u"-t", type=u"time", metavar=_(u"time"))

    # user added rsync options
    parser.add_option(u"--rsync-options", action=u"extend", metavar=_(u"options"))

    # Whether to create European buckets (sorry, hard-coded to only
    # support european for now).
    parser.add_option(u"--s3-european-buckets", action=u"store_true")

    # Whether to use S3 Reduced Redundancy Storage
    parser.add_option(u"--s3-use-rrs", action=u"store_true")

    # Whether to use S3 Infrequent Access Storage
    parser.add_option(u"--s3-use-ia", action=u"store_true")

    # Whether to use S3 Glacier Storage
    parser.add_option(u"--s3-use-glacier", action=u"store_true")

    # Whether to use S3 Glacier Deep Archive Storage
    parser.add_option(u"--s3-use-deep-archive", action=u"store_true")

    # Whether to use S3 One Zone Infrequent Access Storage
    parser.add_option(u"--s3-use-onezone-ia", action=u"store_true")

    # Whether to use "new-style" subdomain addressing for S3 buckets. Such
    # use is not backwards-compatible with upper-case buckets, or buckets
    # that are otherwise not expressable in a valid hostname.
    parser.add_option(u"--s3-use-new-style", action=u"store_true")

    # Whether to use plain HTTP (without SSL) to send data to S3
    # See <https://bugs.launchpad.net/duplicity/+bug/433970>.
    parser.add_option(u"--s3-unencrypted-connection", action=u"store_true")

    # Chunk size used for S3 multipart uploads.The number of parallel uploads to
    # S3 be given by chunk size / volume size. Use this to maximize the use of
    # your bandwidth. Defaults to 25MB
    parser.add_option(u"--s3-multipart-chunk-size", type=u"int", action=u"callback", metavar=_(u"number"),
                      callback=lambda o, s, v, p: setattr(p.values, u"s3_multipart_chunk_size", v * 1024 * 1024))

    # Number of processes to set the Processor Pool to when uploading multipart
    # uploads to S3. Use this to control the maximum simultaneous uploads to S3.
    parser.add_option(u"--s3-multipart-max-procs", type=u"int", metavar=_(u"number"))

    # Number of seconds to wait for each part of a multipart upload to S3. Use this
    # to prevent hangups when doing a multipart upload to S3.
    parser.add_option(u"--s3-multipart-max-timeout", type=u"int", metavar=_(u"number"))

    # Option to allow the s3/boto backend use the multiprocessing version.
    parser.add_option(u"--s3-use-multiprocessing", action=u"store_true")

    # Option to allow use of server side encryption in s3
    parser.add_option(u"--s3-use-server-side-encryption", action=u"store_true", dest=u"s3_use_sse")

    # Options to allow use of server side KMS encryption
    parser.add_option(u"--s3-use-server-side-kms-encryption", action=u"store_true", dest=u"s3_use_sse_kms")
    parser.add_option(u"--s3-kms-key-id", action=u"store", dest=u"s3_kms_key_id")
    parser.add_option(u"--s3-kms-grant", action=u"store", dest=u"s3_kms_grant")

    # Options for specifying region and endpoint of s3
    parser.add_option(u"--s3-region-name", type=u"string", dest=u"s3_region_name", action=u"store")
    parser.add_option(u"--s3-endpoint-url", type=u"string", dest=u"s3_endpoint_url", action=u"store")

    # Option to specify a Swift container storage policy.
    parser.add_option(u"--swift-storage-policy", type=u"string", metavar=_(u"policy"))

    # Number of the largest supported upload size where the Azure library makes only one put call.
    # This is used to upload a single block if the content length is known and is less than this value.
    # The default is 67108864 (64MiB)
    parser.add_option(u"--azure-max-single-put-size", type=u"int", metavar=_(u"number"))

    # Number for the block size used by the Azure library to upload a blob if the length is unknown
    # or is larger than the value set by --azure-max-single-put-size".
    # The maximum block size the service supports is 100MiB.
    # The default is 4 * 1024 * 1024 (4MiB)
    parser.add_option(u"--azure-max-block-size", type=u"int", metavar=_(u"number"))

    # The number for the maximum parallel connections to use when the blob size exceeds 64MB.
    # max_connections (int) - Maximum number of parallel connections to use when the blob size exceeds 64MB.
    parser.add_option(u"--azure-max-connections", type=u"int", metavar=_(u"number"))

    # Standard storage tier used for storring backup files (Hot|Cool|Archive).
    parser.add_option(u"--azure-blob-tier", type=u"string", metavar=_(u"Hot|Cool|Archive"))

    # scp command to use (ssh pexpect backend)
    parser.add_option(u"--scp-command", metavar=_(u"command"))

    # sftp command to use (ssh pexpect backend)
    parser.add_option(u"--sftp-command", metavar=_(u"command"))

    # allow the user to switch cloudfiles backend
    parser.add_option(u"--cf-backend", metavar=_(u"pyrax|cloudfiles"))

    # Option that causes the B2 backend to hide files instead of deleting them
    parser.add_option(u"--b2-hide-files", action=u"store_true")

    # If set, use short (< 30 char) filenames for all the remote files.
    parser.add_option(u"--short-filenames", action=u"callback",
                      dest=u"short_filenames",
                      callback=lambda o, s, v, p: (setattr(p.values, o.dest, True),
                                                   old_fn_deprecation(s)))

    # TRANSL: Used in usage help to represent an ID for a GnuPG key. Example:
    # --encrypt-key <gpg_key_id>
    parser.add_option(u"--sign-key", type=u"string", metavar=_(u"gpg-key-id"),
                      dest=u"", action=u"callback",
                      callback=lambda o, s, v, p: set_sign_key(v))

    # default to batch mode using public-key encryption
    parser.add_option(u"--ssh-askpass", action=u"store_true")

    # user added ssh options
    parser.add_option(u"--ssh-options", action=u"extend", metavar=_(u"options"))

    # user added ssl options (used by webdav, lftp backend)
    parser.add_option(u"--ssl-cacert-file", metavar=_(u"pem formatted bundle of certificate authorities"))
    parser.add_option(u"--ssl-cacert-path", metavar=_(u"path to a folder with certificate authority files"))
    parser.add_option(u"--ssl-no-check-certificate", action=u"store_true")

    # Working directory for the tempfile module. Defaults to /tmp on most systems.
    parser.add_option(u"--tempdir", dest=u"temproot", type=u"file", metavar=_(u"path"))

    # network timeout value
    # TRANSL: Used in usage help. Example:
    # --timeout <seconds>
    parser.add_option(u"--timeout", type=u"int", metavar=_(u"seconds"))

    # Character used like the ":" in time strings like
    # 2002-08-06T04:22:00-07:00.  The colon isn't good for filenames on
    # windows machines.
    # TRANSL: abbreviation for "character" (noun)
    parser.add_option(u"--time-separator", type=u"string", metavar=_(u"char"),
                      action=u"callback",
                      callback=lambda o, s, v, p: set_time_sep(v, s))

    # Whether to specify --use-agent in GnuPG options
    parser.add_option(u"--use-agent", action=u"store_true")

    parser.add_option(u"--verbosity", u"-v", type=u"verbosity", metavar=u"[0-9]",
                      dest=u"", action=u"callback",
                      callback=lambda o, s, v, p: log.setverbosity(v))

    parser.add_option(u"-V", u"--version", action=u"callback", callback=print_ver)

    # option for mediafire to purge files on delete instead of sending to trash
    parser.add_option(u"--mf-purge", action=u"store_true")

    def set_mpsize(o, s, v, p):  # pylint: disable=unused-argument
        setattr(p.values, u"mp_segment_size", v * 1024 * 1024)
        setattr(p.values, u"mp_set", True)
    parser.add_option(u"--mp-segment-size", type=u"int", action=u"callback", metavar=_(u"number"),
                      callback=set_mpsize)
    # volume size
    # TRANSL: Used in usage help to represent a desired number of
    # something. Example:
    # --num-retries <number>

    def set_volsize(o, s, v, p):  # pylint: disable=unused-argument
        setattr(p.values, u"volsize", v * 1024 * 1024)
        # if mp_size was not explicity given, default it to volsize
        if not getattr(p.values, u'mp_set', False):
            setattr(p.values, u"mp_segment_size", int(config.mp_factor * p.values.volsize))

    parser.add_option(u"--volsize", type=u"int", action=u"callback", metavar=_(u"number"),
                      callback=set_volsize)

    # If set, collect only the file status, not the whole root.
    parser.add_option(u"--file-changed", action=u"callback", type=u"file",
                      metavar=_(u"path"), dest=u"file_changed",
                      callback=lambda o, s, v, p: setattr(p.values, u"file_changed", v.rstrip(u'/')))

    # delay time before next try after a failure of a backend operation
    # TRANSL: Used in usage help. Example:
    # --backend-retry-delay <seconds>
    parser.add_option(u"--backend-retry-delay", type=u"int", metavar=_(u"seconds"))

    # parse the options
    (options, args) = parser.parse_args(arglist)

    # Copy all arguments and their values to the config module.  Don't copy
    # attributes that are 'hidden' (start with an underscore) or whose name is
    # the empty string (used for arguments that don't directly store a value
    # by using dest="")
    for f in [x for x in dir(options) if x and not x.startswith(u"_")]:
        v = getattr(options, f)
        # Only set if v is not None because None is the default for all the
        # variables.  If user didn't set it, we'll use defaults in config.py
        if v is not None:
            setattr(config, f, v)

    # convert file_prefix* string
    if sys.version_info.major >= 3:
        if isinstance(config.file_prefix, str):
            config.file_prefix = bytes(config.file_prefix, u'utf-8')
        if isinstance(config.file_prefix_manifest, str):
            config.file_prefix_manifest = bytes(config.file_prefix_manifest, u'utf-8')
        if isinstance(config.file_prefix_archive, str):
            config.file_prefix_archive = bytes(config.file_prefix_archive, u'utf-8')
        if isinstance(config.file_prefix_signature, str):
            config.file_prefix_signature = bytes(config.file_prefix_signature, u'utf-8')

    # todo: this should really NOT be done here
    socket.setdefaulttimeout(config.timeout)

    # expect no cmd and two positional args
    cmd = u""
    num_expect = 2

    # process first arg as command
    if args:
        cmd = args.pop(0)
        possible = [c for c in commands if c.startswith(cmd)]
        # no unique match, that's an error
        if len(possible) > 1:
            command_line_error(u"command '%s' not unique, could be %s" % (cmd, possible))
        # only one match, that's a keeper
        elif len(possible) == 1:
            cmd = possible[0]
        # no matches, assume no cmd
        elif not possible:
            args.insert(0, cmd)

    if cmd == u"cleanup":
        cleanup = True
        num_expect = 1
    elif cmd == u"collection-status":
        collection_status = True
        num_expect = 1
    elif cmd == u"full":
        full_backup = True
        num_expect = 2
    elif cmd == u"incremental":
        config.incremental = True
        num_expect = 2
    elif cmd == u"list-current-files":
        list_current = True
        num_expect = 1
    elif cmd == u"remove-older-than":
        try:
            arg = args.pop(0)
        except Exception:
            command_line_error(u"Missing time string for remove-older-than")
        config.remove_time = dup_time.genstrtotime(arg)
        num_expect = 1
    elif cmd == u"remove-all-but-n-full" or cmd == u"remove-all-inc-of-but-n-full":
        if cmd == u"remove-all-but-n-full":
            config.remove_all_but_n_full_mode = True
        if cmd == u"remove-all-inc-of-but-n-full":
            config.remove_all_inc_of_but_n_full_mode = True
        try:
            arg = args.pop(0)
        except Exception:
            command_line_error(u"Missing count for " + cmd)
        config.keep_chains = int(arg)
        if not config.keep_chains > 0:
            command_line_error(cmd + u" count must be > 0")
        num_expect = 1
    elif cmd == u"verify":
        verify = True
    elif cmd == u"replicate":
        replicate = True
        num_expect = 2

    if len(args) != num_expect:
        command_line_error(u"Expected %d args, got %d" % (num_expect, len(args)))

    # expand pathname args, but not URL
    for loc in range(len(args)):
        if isinstance(args[loc], bytes):
            args[loc] = args[loc].decode(u'utf8')
        if u'://' not in args[loc]:
            args[loc] = expand_fn(args[loc])

    # Note that ProcessCommandLine depends on us verifying the arg
    # count here; do not remove without fixing it. We must make the
    # checks here in order to make enough sense of args to identify
    # the backend URL/lpath for args_to_path_backend().
    if len(args) < 1:
        command_line_error(u"Too few arguments")
    elif len(args) == 1:
        backend_url = args[0]
    elif len(args) == 2:
        if replicate:
            if not backend.is_backend_url(args[0]) or not backend.is_backend_url(args[1]):
                command_line_error(u"Two URLs expected for replicate.")
            src_backend_url, backend_url = args[0], args[1]
        else:
            lpath, backend_url = args_to_path_backend(args[0], args[1])
    else:
        command_line_error(u"Too many arguments")

    if config.backup_name is None:
        config.backup_name = generate_default_backup_name(backend_url)

    # set and expand archive dir
    set_archive_dir(expand_archive_dir(config.archive_dir,
                                       config.backup_name))

    log.Info(_(u"Using archive dir: %s") % (config.archive_dir_path.uc_name,))
    log.Info(_(u"Using backup name: %s") % (config.backup_name,))

    return args


def command_line_error(message):
    u"""Indicate a command line error and exit"""
    log.FatalError(_(u"Command line error: %s") % (message,) + u"\n" +
                   _(u"Enter 'duplicity --help' for help screen."),
                   log.ErrorCode.command_line)


def usage():
    u"""Returns terse usage info. The code is broken down into pieces for ease of
    translation maintenance. Any comments that look extraneous or redundant should
    be assumed to be for the benefit of translators, since they can get each string
    (paired with its preceding comment, if any) independently of the others."""

    trans = {
        # TRANSL: Used in usage help to represent a Unix-style path name. Example:
        # rsync://user[:password]@other_host[:port]//absolute_path
        u'absolute_path': _(u"absolute_path"),

        # TRANSL: Used in usage help. Example:
        # tahoe://alias/some_dir
        u'alias': _(u"alias"),

        # TRANSL: Used in help to represent a "bucket name" for Amazon Web
        # Services' Simple Storage Service (S3). Example:
        # s3://other.host/bucket_name[/prefix]
        u'bucket_name': _(u"bucket_name"),

        # TRANSL: abbreviation for "character" (noun)
        u'char': _(u"char"),

        # TRANSL: noun
        u'command': _(u"command"),

        # TRANSL: Used in usage help to represent the name of a container in
        # Amazon Web Services' Cloudfront. Example:
        # cf+http://container_name
        u'container_name': _(u"container_name"),

        # TRANSL: noun
        u'count': _(u"count"),

        # TRANSL: Used in usage help to represent the name of a file directory
        u'directory': _(u"directory"),

        # TRANSL: Used in usage help to represent the name of a file. Example:
        # --log-file <filename>
        u'filename': _(u"filename"),

        # TRANSL: Used in usage help to represent an ID for a GnuPG key. Example:
        # --encrypt-key <gpg_key_id>
        u'gpg_key_id': _(u"gpg-key-id"),

        # TRANSL: Used in usage help, e.g. to represent the name of a code
        # module. Example:
        # rsync://user[:password]@other.host[:port]::/module/some_dir
        u'module': _(u"module"),

        # TRANSL: Used in usage help to represent a desired number of
        # something. Example:
        # --num-retries <number>
        u'number': _(u"number"),

        # TRANSL: Used in usage help. (Should be consistent with the "Options:"
        # header.) Example:
        # duplicity [full|incremental] [options] source_dir target_url
        u'options': _(u"options"),

        # TRANSL: Used in usage help to represent an internet hostname. Example:
        # ftp://user[:password]@other.host[:port]/some_dir
        u'other_host': _(u"other.host"),

        # TRANSL: Used in usage help. Example:
        # ftp://user[:password]@other.host[:port]/some_dir
        u'password': _(u"password"),

        # TRANSL: Used in usage help to represent a Unix-style path name. Example:
        # --archive-dir <path>
        u'path': _(u"path"),

        # TRANSL: Used in usage help to represent a TCP port number. Example:
        # ftp://user[:password]@other.host[:port]/some_dir
        u'port': _(u"port"),

        # TRANSL: Used in usage help. This represents a string to be used as a
        # prefix to names for backup files created by Duplicity. Example:
        # s3://other.host/bucket_name[/prefix]
        u'prefix': _(u"prefix"),

        # TRANSL: Used in usage help to represent a Unix-style path name. Example:
        # rsync://user[:password]@other.host[:port]/relative_path
        u'relative_path': _(u"relative_path"),

        # TRANSL: Used in usage help. Example:
        # --timeout <seconds>
        u'seconds': _(u"seconds"),

        # TRANSL: Used in usage help to represent a "glob" style pattern for
        # matching one or more files, as described in the documentation.
        # Example:
        # --exclude <shell_pattern>
        u'shell_pattern': _(u"shell_pattern"),

        # TRANSL: Used in usage help to represent the name of a single file
        # directory or a Unix-style path to a directory. Example:
        # file:///some_dir
        u'some_dir': _(u"some_dir"),

        # TRANSL: Used in usage help to represent the name of a single file
        # directory or a Unix-style path to a directory where files will be
        # coming FROM. Example:
        # duplicity [full|incremental] [options] source_dir target_url
        u'source_dir': _(u"source_dir"),

        # TRANSL: Used in usage help to represent a URL files will be coming
        # FROM. Example:
        # duplicity [restore] [options] source_url target_dir
        u'source_url': _(u"source_url"),

        # TRANSL: Used in usage help to represent the name of a single file
        # directory or a Unix-style path to a directory. where files will be
        # going TO. Example:
        # duplicity [restore] [options] source_url target_dir
        u'target_dir': _(u"target_dir"),

        # TRANSL: Used in usage help to represent a URL files will be going TO.
        # Example:
        # duplicity [full|incremental] [options] source_dir target_url
        u'target_url': _(u"target_url"),

        # TRANSL: Used in usage help to represent a time spec for a previous
        # point in time, as described in the documentation. Example:
        # duplicity remove-older-than time [options] target_url
        u'time': _(u"time"),

        # TRANSL: Used in usage help to represent a user name (i.e. login).
        # Example:
        # ftp://user[:password]@other.host[:port]/some_dir
        u'user': _(u"user"),

        # TRANSL: account id for b2. Example: b2://account_id@bucket/
        u'account_id': _(u"account_id"),

        # TRANSL: application_key for b2.
        # Example: b2://account_id:application_key@bucket/
        u'application_key': _(u"application_key"),

        # TRANSL: remote name for rclone.
        # Example: rclone://remote:/some_dir
        u'remote': _(u"remote"),
    }

    # TRANSL: Header in usage help
    msg = u"""
  duplicity [full|incremental] [%(options)s] %(source_dir)s %(target_url)s
  duplicity [restore] [%(options)s] %(source_url)s %(target_dir)s
  duplicity verify [%(options)s] %(source_url)s %(target_dir)s
  duplicity collection-status [%(options)s] %(target_url)s
  duplicity list-current-files [%(options)s] %(target_url)s
  duplicity cleanup [%(options)s] %(target_url)s
  duplicity remove-older-than %(time)s [%(options)s] %(target_url)s
  duplicity remove-all-but-n-full %(count)s [%(options)s] %(target_url)s
  duplicity remove-all-inc-of-but-n-full %(count)s [%(options)s] %(target_url)s
  duplicity replicate %(source_url)s %(target_url)s

""" % trans

    # TRANSL: Header in usage help
    msg = msg + _(u"Backends and their URL formats:") + u"""
  azure://%(container_name)s
  b2://%(account_id)s[:%(application_key)s]@%(bucket_name)s/[%(some_dir)s/]
  boto3+s3://%(bucket_name)s[/%(prefix)s]
  cf+http://%(container_name)s
  dpbx:///%(some_dir)s
  file:///%(some_dir)s
  ftp://%(user)s[:%(password)s]@%(other_host)s[:%(port)s]/%(some_dir)s
  ftps://%(user)s[:%(password)s]@%(other_host)s[:%(port)s]/%(some_dir)s
  gdocs://%(user)s[:%(password)s]@%(other_host)s/%(some_dir)s
  for gdrive:// a <service-account-url> like the following is required
        <serviceaccount-name>@<serviceaccount-name>.iam.gserviceaccount.com
  gdrive://<service-account-url>/target-folder/?driveID=<SHARED DRIVE ID> (for GOOGLE Shared Drive)
  gdrive://<service-account-url>/target-folder/?myDriveFolderID=<google-myDrive-folder-id> (for GOOGLE MyDrive)
  hsi://%(user)s[:%(password)s]@%(other_host)s[:%(port)s]/%(some_dir)s
  imap://%(user)s[:%(password)s]@%(other_host)s[:%(port)s]/%(some_dir)s
  mega://%(user)s[:%(password)s]@%(other_host)s/%(some_dir)s
  megav2://%(user)s[:%(password)s]@%(other_host)s/%(some_dir)s
  mf://%(user)s[:%(password)s]@%(other_host)s/%(some_dir)s
  onedrive://%(some_dir)s
  pca://%(container_name)s
  pydrive://%(user)s@%(other_host)s/%(some_dir)s
  rclone://%(remote)s:/%(some_dir)s
  rsync://%(user)s[:%(password)s]@%(other_host)s[:%(port)s]/%(relative_path)s
  rsync://%(user)s[:%(password)s]@%(other_host)s[:%(port)s]//%(absolute_path)s
  rsync://%(user)s[:%(password)s]@%(other_host)s[:%(port)s]::/%(module)s/%(some_dir)s
  s3+http://%(bucket_name)s[/%(prefix)s]
  s3://%(other_host)s[:%(port)s]/%(bucket_name)s[/%(prefix)s]
  scp://%(user)s[:%(password)s]@%(other_host)s[:%(port)s]/%(some_dir)s
  ssh://%(user)s[:%(password)s]@%(other_host)s[:%(port)s]/%(some_dir)s
  swift://%(container_name)s
  tahoe://%(alias)s/%(directory)s
  webdav://%(user)s[:%(password)s]@%(other_host)s/%(some_dir)s
  webdavs://%(user)s[:%(password)s]@%(other_host)s/%(some_dir)s

""" % trans

    # TRANSL: Header in usage help
    msg = msg + _(u"Commands:") + u"""
  cleanup <%(target_url)s>
  collection-status <%(target_url)s>
  full <%(source_dir)s> <%(target_url)s>
  incr <%(source_dir)s> <%(target_url)s>
  list-current-files <%(target_url)s>
  remove-all-but-n-full <%(count)s> <%(target_url)s>
  remove-all-inc-of-but-n-full <%(count)s> <%(target_url)s>
  remove-older-than <%(time)s> <%(target_url)s>
  replicate <%(source_url)s> <%(target_url)s>
  restore <%(source_url)s> <%(target_dir)s>
  verify <%(target_url)s> <%(source_dir)s>

""" % trans

    return msg


def set_archive_dir(dirstring):
    u"""Check archive dir and set global"""
    if not os.path.exists(dirstring):
        try:
            os.makedirs(dirstring)
        except Exception:
            pass
    archive_dir_path = path.Path(dirstring)
    if not archive_dir_path.isdir():
        log.FatalError(_(u"Specified archive directory '%s' does not exist, "
                         u"or is not a directory") % (archive_dir_path.uc_name,),
                       log.ErrorCode.bad_archive_dir)
    config.archive_dir_path = archive_dir_path


def set_sign_key(sign_key):
    u"""Set config.sign_key assuming proper key given"""
    if not re.search(u"^(0x)?([0-9A-Fa-f]{8}|[0-9A-Fa-f]{16}|[0-9A-Fa-f]{40})$", sign_key):
        log.FatalError(_(u"Sign key should be an 8, 16 alt. 40 character hex string, like "
                         u"'AA0E73D2'.\nReceived '%s' instead.") % (sign_key,),
                       log.ErrorCode.bad_sign_key)
    config.gpg_profile.sign_key = sign_key


def set_selection():
    u"""Return selection iter starting at filename with arguments applied"""
    global select_opts, select_files
    sel = selection.Select(config.local_path)
    sel.ParseArgs(select_opts, select_files)
    config.select = sel.set_iter()


def args_to_path_backend(arg1, arg2):
    u"""
    Given exactly two arguments, arg1 and arg2, figure out which one
    is the backend URL and which one is a local path, and return
    (local, backend).
    """
    arg1_is_backend, arg2_is_backend = backend.is_backend_url(arg1), backend.is_backend_url(arg2)

    if not arg1_is_backend and not arg2_is_backend:
        command_line_error(u"""\
One of the arguments must be an URL.  Examples of URL strings are
"scp://user@host.net:1234/path" and "file:///usr/local".  See the man
page for more information.""")
    if arg1_is_backend and arg2_is_backend:
        command_line_error(u"Two URLs specified.  "
                           u"One argument should be a path.")
    if arg1_is_backend:
        return (arg2, arg1)
    elif arg2_is_backend:
        return (arg1, arg2)
    else:
        raise AssertionError(u'should not be reached')


def set_backend(arg1, arg2):
    u"""Figure out which arg is url, set backend

    Return value is pair (path_first, path) where is_first is true iff
    path made from arg1.

    """
    path, bend = args_to_path_backend(arg1, arg2)

    config.backend = backend.get_backend(bend)

    if path == arg2:
        return (None, arg2)  # False?
    else:
        return (1, arg1)  # True?


def process_local_dir(action, local_pathname):
    u"""Check local directory, set config.local_path"""
    local_path = path.Path(path.Path(local_pathname).get_canonical())
    if action == u"restore":
        if (local_path.exists() and not local_path.isemptydir()) and not config.force:
            log.FatalError(_(u"Restore destination directory %s already "
                             u"exists.\nWill not overwrite.") % (local_path.uc_name,),
                           log.ErrorCode.restore_dir_exists)
    elif action == u"verify":
        if not local_path.exists():
            log.FatalError(_(u"Verify directory %s does not exist") %
                           (local_path.uc_name,),
                           log.ErrorCode.verify_dir_doesnt_exist)
    else:
        assert action == u"full" or action == u"inc"
        if not local_path.exists():
            log.FatalError(_(u"Backup source directory %s does not exist.")
                           % (local_path.uc_name,),
                           log.ErrorCode.backup_dir_doesnt_exist)

    config.local_path = local_path


def check_consistency(action):
    u"""Final consistency check, see if something wrong with command line"""
    global full_backup, select_opts, list_current, collection_status, cleanup, replicate

    def assert_only_one(arglist):
        u"""Raises error if two or more of the elements of arglist are true"""
        n = 0
        for m in arglist:
            if m:
                n += 1
        assert n <= 1, u"Invalid syntax, two conflicting modes specified"

    if action in [u"list-current", u"collection-status",
                  u"cleanup", u"remove-old", u"remove-all-but-n-full", u"remove-all-inc-of-but-n-full", u"replicate"]:
        assert_only_one([list_current, collection_status, cleanup, replicate,
                         config.remove_time is not None])
    elif action == u"restore" or action == u"verify":
        if full_backup:
            command_line_error(u"--full option cannot be used when "
                               u"restoring or verifying")
        elif config.incremental:
            command_line_error(u"--incremental option cannot be used when "
                               u"restoring or verifying")
        if select_opts and action == u"restore":
            log.Warn(_(u"Command line warning: %s") % _(u"Selection options --exclude/--include\n"
                                                        u"currently work only when backing up,"
                                                        u"not restoring."))
    else:
        assert action == u"inc" or action == u"full"
        if verify:
            command_line_error(u"--verify option cannot be used "
                               u"when backing up")
        if config.restore_dir:
            command_line_error(u"restore option incompatible with %s backup"
                               % (action,))
        if sum([config.s3_use_rrs, config.s3_use_ia, config.s3_use_onezone_ia]) >= 2:
            command_line_error(u"only one of --s3-use-rrs, --s3-use-ia, and --s3-use-onezone-ia may be used")


def ProcessCommandLine(cmdline_list):
    u"""Process command line, set config, return action

    action will be "list-current", "collection-status", "cleanup",
    "remove-old", "restore", "verify", "full", or "inc".

    """
    # build initial gpg_profile
    config.gpg_profile = gpg.GPGProfile()

    # parse command line
    args = parse_cmdline_options(cmdline_list)

    # if we get a different gpg-binary from the commandline then redo gpg_profile
    if config.gpg_binary is not None:
        src = config.gpg_profile
        config.gpg_profile = gpg.GPGProfile(
            passphrase=src.passphrase,
            sign_key=src.sign_key,
            recipients=src.recipients,
            hidden_recipients=src.hidden_recipients)
    log.Debug(_(u"GPG binary is %s, version %s") %
              ((config.gpg_binary or u'gpg'), config.gpg_profile.gpg_version))

    # we can now try to import all the backends
    backend.import_backends()

    # parse_cmdline_options already verified that we got exactly 1 or 2
    # non-options arguments
    assert len(args) >= 1 and len(args) <= 2, u"arg count should have been checked already"

    if len(args) == 1:
        if list_current:
            action = u"list-current"
        elif collection_status:
            action = u"collection-status"
        elif cleanup:
            action = u"cleanup"
        elif config.remove_time is not None:
            action = u"remove-old"
        elif config.remove_all_but_n_full_mode:
            action = u"remove-all-but-n-full"
        elif config.remove_all_inc_of_but_n_full_mode:
            action = u"remove-all-inc-of-but-n-full"
        else:
            command_line_error(u"Too few arguments")
        config.backend = backend.get_backend(args[0])
        if not config.backend:
            log.FatalError(_(u"""Bad URL '%s'.
Examples of URL strings are "scp://user@host.net:1234/path" and
"file:///usr/local".  See the man page for more information.""") % (args[0],),
                           log.ErrorCode.bad_url)
    elif len(args) == 2:
        if replicate:
            config.src_backend = backend.get_backend(args[0])
            config.backend = backend.get_backend(args[1])
            action = u"replicate"
        else:
            # Figure out whether backup or restore
            backup, local_pathname = set_backend(args[0], args[1])
            if backup:
                if full_backup:
                    action = u"full"
                else:
                    action = u"inc"
            else:
                if verify:
                    action = u"verify"
                else:
                    action = u"restore"

            process_local_dir(action, local_pathname)
            if action in [u'full', u'inc', u'verify']:
                set_selection()
    elif len(args) > 2:
        raise AssertionError(u"this code should not be reachable")

    check_consistency(action)
    log.Info(_(u"Main action: ") + action)
    return action
