# -*- Mode:Python; indent-tabs-mode:nil; tab-width:4; encoding:utf8 -*-
#
# duplicity -- Encrypted bandwidth efficient backup
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
#
# See http://www.nongnu.org/duplicity for more information.
# Please send mail to me or the mailing list if you find bugs or have
# any suggestions.

from __future__ import print_function
from future import standard_library
standard_library.install_aliases()
from builtins import map
from builtins import next
from builtins import object
from builtins import range

import copy
import fasteners
import os
import platform
import resource
import sys
import time

from duplicity import __version__
from duplicity import asyncscheduler
from duplicity import commandline
from duplicity import diffdir
from duplicity import dup_collections
from duplicity import dup_temp
from duplicity import dup_time
from duplicity import file_naming
from duplicity import config
from duplicity import gpg
from duplicity import log
from duplicity import manifest
from duplicity import patchdir
from duplicity import path
from duplicity import progress
from duplicity import tempdir
from duplicity import util

from datetime import datetime

# If exit_val is not None, exit with given value at end.
exit_val = None


def getpass_safe(message):
    # getpass() in Python 2.x will call str() on our prompt.  So we can't pass
    # in non-ascii characters.
    import getpass
    import locale
    if sys.version_info.major == 2:
        message = message.encode(locale.getpreferredencoding(), u'replace')
    return getpass.getpass(message)


def get_passphrase(n, action, for_signing=False):
    u"""
    Check to make sure passphrase is indeed needed, then get
    the passphrase from environment, from gpg-agent, or user

    If n=3, a password is requested and verified. If n=2, the current
    password is verified. If n=1, a password is requested without
    verification for the time being.

    @type  n: int
    @param n: verification level for a passphrase being requested
    @type  action: string
    @param action: action to perform
    @type  for_signing: boolean
    @param for_signing: true if the passphrase is for a signing key, false if not
    @rtype: string
    @return: passphrase
    """

    # First try the environment
    try:
        if for_signing:
            return os.environ[u'SIGN_PASSPHRASE']
        else:
            return os.environ[u'PASSPHRASE']
    except KeyError:
        pass

    # check if we can reuse an already set (signing_)passphrase
    # if signing key is also an encryption key assume that the passphrase is identical
    if (for_signing and
            (config.gpg_profile.sign_key in config.gpg_profile.recipients or
             config.gpg_profile.sign_key in config.gpg_profile.hidden_recipients) and
             u'PASSPHRASE' in os.environ):  # noqa
        log.Notice(_(u"Reuse configured PASSPHRASE as SIGN_PASSPHRASE"))
        return os.environ[u'PASSPHRASE']
    # if one encryption key is also the signing key assume that the passphrase is identical
    if (not for_signing and
            (config.gpg_profile.sign_key in config.gpg_profile.recipients or
             config.gpg_profile.sign_key in config.gpg_profile.hidden_recipients) and
             u'SIGN_PASSPHRASE' in os.environ):  # noqa
        log.Notice(_(u"Reuse configured SIGN_PASSPHRASE as PASSPHRASE"))
        return os.environ[u'SIGN_PASSPHRASE']

    # Next, verify we need to ask the user

    # Assumptions:
    #   - encrypt-key has no passphrase
    #   - sign-key requires passphrase
    #   - gpg-agent supplies all, no user interaction

    # no passphrase if --no-encryption or --use-agent
    if not config.encryption or config.use_agent:
        return u""

    # these commands don't need a password
    elif action in [u"collection-status",
                    u"list-current",
                    u"remove-all-but-n-full",
                    u"remove-all-inc-of-but-n-full",
                    u"remove-old",
                    ]:
        return u""

    # for a full backup, we don't need a password if
    # there is no sign_key and there are recipients
    elif (action == u"full" and
          (config.gpg_profile.recipients or config.gpg_profile.hidden_recipients) and not
          config.gpg_profile.sign_key):
        return u""

    # for an inc backup, we don't need a password if
    # there is no sign_key and there are recipients
    elif (action == u"inc" and
          (config.gpg_profile.recipients or config.gpg_profile.hidden_recipients) and not
          config.gpg_profile.sign_key):
        return u""

    # Finally, ask the user for the passphrase
    else:
        log.Info(_(u"PASSPHRASE variable not set, asking user."))
        use_cache = True
        while 1:
            # ask the user to enter a new passphrase to avoid an infinite loop
            # if the user made a typo in the first passphrase
            if use_cache and n == 2:
                if for_signing:
                    pass1 = config.gpg_profile.signing_passphrase
                else:
                    pass1 = config.gpg_profile.passphrase
            else:
                if for_signing:
                    if use_cache and config.gpg_profile.signing_passphrase:
                        pass1 = config.gpg_profile.signing_passphrase
                    else:
                        pass1 = getpass_safe(_(u"GnuPG passphrase for signing key:") + u" ")
                else:
                    if use_cache and config.gpg_profile.passphrase:
                        pass1 = config.gpg_profile.passphrase
                    else:
                        pass1 = getpass_safe(_(u"GnuPG passphrase for decryption:") + u" ")

            if n == 1:
                pass2 = pass1
            elif for_signing:
                pass2 = getpass_safe(_(u"Retype passphrase for signing key to confirm: "))
            else:
                pass2 = getpass_safe(_(u"Retype passphrase for decryption to confirm: "))

            if not pass1 == pass2:
                log.Log(_(u"First and second passphrases do not match!  Please try again."),
                        log.WARNING, force_print=True)
                use_cache = False
                continue

            if not pass1 and not (config.gpg_profile.recipients or
                                  config.gpg_profile.hidden_recipients) and not for_signing:
                log.Log(_(u"Cannot use empty passphrase with symmetric encryption!  Please try again."),
                        log.WARNING, force_print=True)
                use_cache = False
                continue

            return pass1


def dummy_backup(tarblock_iter):
    u"""
    Fake writing to backend, but do go through all the source paths.

    @type tarblock_iter: tarblock_iter
    @param tarblock_iter: iterator for current tar block

    @rtype: int
    @return: constant 0 (zero)
    """
    try:
        # Just spin our wheels
        while next(tarblock_iter):
            pass
    except StopIteration:
        pass
    log.Progress(None, diffdir.stats.SourceFileSize)
    return 0


def restart_position_iterator(tarblock_iter):
    u"""
    Fake writing to backend, but do go through all the source paths.
    Stop when we have processed the last file and block from the
    last backup.  Normal backup will proceed at the start of the
    next volume in the set.

    @type tarblock_iter: tarblock_iter
    @param tarblock_iter: iterator for current tar block

    @rtype: int
    @return: constant 0 (zero)
    """
    last_index = config.restart.last_index
    last_block = config.restart.last_block
    try:
        # Just spin our wheels
        iter_result = next(tarblock_iter)
        while iter_result:
            if (tarblock_iter.previous_index == last_index):
                # If both the previous index and this index are done, exit now
                # before we hit the next index, to prevent skipping its first
                # block.
                if not last_block and not tarblock_iter.previous_block:
                    break
                # Only check block number if last_block is also a number
                if last_block and tarblock_iter.previous_block > last_block:
                    break
            if tarblock_iter.previous_index > last_index:
                log.Warn(_(u"File %s complete in backup set.\n"
                           u"Continuing restart on file %s.") %
                         (util.uindex(last_index), util.uindex(tarblock_iter.previous_index)),
                         log.ErrorCode.restart_file_not_found)
                # We went too far! Stuff the data back into place before restarting
                tarblock_iter.queue_index_data(iter_result)
                break
            iter_result = next(tarblock_iter)
    except StopIteration:
        log.Warn(_(u"File %s missing in backup set.\n"
                   u"Continuing restart on file %s.") %
                 (util.uindex(last_index), util.uindex(tarblock_iter.previous_index)),
                 log.ErrorCode.restart_file_not_found)


def write_multivol(backup_type, tarblock_iter, man_outfp, sig_outfp, backend):
    u"""
    Encrypt volumes of tarblock_iter and write to backend

    backup_type should be "inc" or "full" and only matters here when
    picking the filenames.  The path_prefix will determine the names
    of the files written to backend.  Also writes manifest file.
    Returns number of bytes written.

    @type backup_type: string
    @param backup_type: type of backup to perform, either 'inc' or 'full'
    @type tarblock_iter: tarblock_iter
    @param tarblock_iter: iterator for current tar block
    @type backend: callable backend object
    @param backend: I/O backend for selected protocol

    @rtype: int
    @return: bytes written
    """

    def get_indicies(tarblock_iter):
        u"""Return start_index and end_index of previous volume"""
        start_index, start_block = tarblock_iter.recall_index()
        if start_index is None:
            start_index = ()
            start_block = None
        if start_block:
            start_block -= 1
        end_index, end_block = tarblock_iter.get_previous_index()
        if end_index is None:
            end_index = start_index
            end_block = start_block
        if end_block:
            end_block -= 1
        return start_index, start_block, end_index, end_block

    def validate_block(orig_size, dest_filename):
        info = backend.query_info([dest_filename])[dest_filename]
        size = info[u'size']
        if size is None:
            return  # error querying file
        for attempt in range(1, config.num_retries + 1):
            info = backend.query_info([dest_filename])[dest_filename]
            size = info[u'size']
            if size == orig_size:
                break
            if size is None:
                return
            log.Notice(_(u"%s Remote filesize %d for %s does not match local size %d, retrying.") % (datetime.now(),
                       size, util.escape(dest_filename), orig_size))
            time.sleep(2**attempt)
        if size != orig_size:
            code_extra = u"%s %d %d" % (util.escape(dest_filename), orig_size, size)
            log.FatalError(_(u"File %s was corrupted during upload.") % util.fsdecode(dest_filename),
                           log.ErrorCode.volume_wrong_size, code_extra)

    def put(tdp, dest_filename, vol_num):
        u"""
        Retrieve file size *before* calling backend.put(), which may (at least
        in case of the localbackend) rename the temporary file to the target
        instead of copying.
        """
        putsize = tdp.getsize()
        if config.skip_volume != vol_num:  # for testing purposes only
            backend.put(tdp, dest_filename)
        validate_block(putsize, dest_filename)
        if tdp.stat:
            tdp.delete()
        return putsize

    def validate_encryption_settings(backup_set, manifest):
        u"""
        When restarting a backup, we have no way to verify that the current
        passphrase is the same as the one used for the beginning of the backup.
        This is because the local copy of the manifest is unencrypted and we
        don't need to decrypt the existing volumes on the backend.  To ensure
        that we are using the same passphrase, we manually download volume 1
        and decrypt it with the current passphrase.  We also want to confirm
        that we're using the same encryption settings (i.e. we don't switch
        from encrypted to non in the middle of a backup chain), so we check
        that the vol1 filename on the server matches the settings of this run.
        """
        if ((config.gpg_profile.recipients or config.gpg_profile.hidden_recipients) and
                not config.gpg_profile.sign_key):
            # When using gpg encryption without a signing key, we skip this validation
            # step to ensure that we can still backup without needing the secret key
            # on the machine.
            return

        vol1_filename = file_naming.get(backup_type, 1,
                                        encrypted=config.encryption,
                                        gzipped=config.compression)
        if vol1_filename != backup_set.volume_name_dict[1]:
            log.FatalError(_(u"Restarting backup, but current encryption "
                             u"settings do not match original settings"),
                           log.ErrorCode.enryption_mismatch)

        # Settings are same, let's check passphrase itself if we are encrypted
        if config.encryption:
            fileobj = restore_get_enc_fileobj(config.backend, vol1_filename,
                                              manifest.volume_info_dict[1])
            fileobj.close()

    if not config.restart:
        # normal backup start
        vol_num = 0
        mf = manifest.Manifest(fh=man_outfp)
        mf.set_dirinfo()
    else:
        # restart from last known position
        mf = config.restart.last_backup.get_local_manifest()
        config.restart.checkManifest(mf)
        config.restart.setLastSaved(mf)
        if not (config.s3_use_deep_archive or config.s3_use_glacier):
            validate_encryption_settings(config.restart.last_backup, mf)
        else:
            log.Warn(_(u"Skipping encryption validation due to glacier/deep storage"))
        mf.fh = man_outfp
        last_block = config.restart.last_block
        log.Notice(_(u"Restarting after volume %s, file %s, block %s") %
                   (config.restart.start_vol,
                    util.uindex(config.restart.last_index),
                    config.restart.last_block))
        vol_num = config.restart.start_vol
        restart_position_iterator(tarblock_iter)

    at_end = 0
    bytes_written = 0

    # If --progress option is given, initiate a background thread that will
    # periodically report progress to the Log.
    if config.progress:
        progress.tracker.set_start_volume(vol_num + 1)
        progress.progress_thread.start()

    # This assertion must be kept until we have solved the problem
    # of concurrency at the backend level. Concurrency 1 is fine
    # because the actual I/O concurrency on backends is limited to
    # 1 as usual, but we are allowed to perform local CPU
    # intensive tasks while that single upload is happening. This
    # is an assert put in place to avoid someone accidentally
    # enabling concurrency above 1, before adequate work has been
    # done on the backends to make them support concurrency.
    assert config.async_concurrency <= 1

    io_scheduler = asyncscheduler.AsyncScheduler(config.async_concurrency)
    async_waiters = []

    while not at_end:
        # set up iterator
        tarblock_iter.remember_next_index()  # keep track of start index

        # Create volume
        vol_num += 1
        dest_filename = file_naming.get(backup_type, vol_num,
                                        encrypted=config.encryption,
                                        gzipped=config.compression)
        tdp = dup_temp.new_tempduppath(file_naming.parse(dest_filename))

        # write volume
        if config.encryption:
            at_end = gpg.GPGWriteFile(tarblock_iter, tdp.name, config.gpg_profile,
                                      config.volsize)
        elif config.compression:
            at_end = gpg.GzipWriteFile(tarblock_iter, tdp.name, config.volsize)
        else:
            at_end = gpg.PlainWriteFile(tarblock_iter, tdp.name, config.volsize)
        tdp.setdata()

        # Add volume information to manifest
        vi = manifest.VolumeInfo()
        vi.set_info(vol_num, *get_indicies(tarblock_iter))
        vi.set_hash(u"SHA1", gpg.get_hash(u"SHA1", tdp))
        mf.add_volume_info(vi)

        # Checkpoint after each volume so restart has a place to restart.
        # Note that until after the first volume, all files are temporary.
        if vol_num == 1:
            sig_outfp.to_partial()
            man_outfp.to_partial()
        else:
            sig_outfp.flush()
            man_outfp.flush()

        async_waiters.append(io_scheduler.schedule_task(lambda tdp, dest_filename,
                                                        vol_num: put(tdp, dest_filename, vol_num),
                                                        (tdp, dest_filename, vol_num)))

        # Log human-readable version as well as raw numbers for machine consumers
        log.Progress(_(u'Processed volume %d') % vol_num, diffdir.stats.SourceFileSize)
        # Snapshot (serialize) progress now as a Volume has been completed.
        # This is always the last restore point when it comes to restart a failed backup
        if config.progress:
            progress.tracker.snapshot_progress(vol_num)

        # for testing purposes only - assert on inc or full
        assert config.fail_on_volume != vol_num, u"Forced assertion for testing at volume %d" % vol_num

    # Collect byte count from all asynchronous jobs; also implicitly waits
    # for them all to complete.
    for waiter in async_waiters:
        bytes_written += waiter()

    # Upload the collection summary.
    # bytes_written += write_manifest(mf, backup_type, backend)
    mf.set_files_changed_info(diffdir.stats.get_delta_entries_file())

    return bytes_written


def get_man_fileobj(backup_type):
    u"""
    Return a fileobj opened for writing, save results as manifest

    Save manifest in config.archive_dir_path gzipped.
    Save them on the backend encrypted as needed.

    @type man_type: string
    @param man_type: either "full" or "new"

    @rtype: fileobj
    @return: fileobj opened for writing
    """
    assert backup_type == u"full" or backup_type == u"inc"

    part_man_filename = file_naming.get(backup_type,
                                        manifest=True,
                                        partial=True)
    perm_man_filename = file_naming.get(backup_type,
                                        manifest=True)
    remote_man_filename = file_naming.get(backup_type,
                                          manifest=True,
                                          encrypted=config.encryption)

    fh = dup_temp.get_fileobj_duppath(config.archive_dir_path,
                                      part_man_filename,
                                      perm_man_filename,
                                      remote_man_filename)
    return fh


def get_sig_fileobj(sig_type):
    u"""
    Return a fileobj opened for writing, save results as signature

    Save signatures in config.archive_dir gzipped.
    Save them on the backend encrypted as needed.

    @type sig_type: string
    @param sig_type: either "full-sig" or "new-sig"

    @rtype: fileobj
    @return: fileobj opened for writing
    """
    assert sig_type in [u"full-sig", u"new-sig"]

    part_sig_filename = file_naming.get(sig_type,
                                        gzipped=False,
                                        partial=True)
    perm_sig_filename = file_naming.get(sig_type,
                                        gzipped=True)
    remote_sig_filename = file_naming.get(sig_type, encrypted=config.encryption,
                                          gzipped=config.compression)

    fh = dup_temp.get_fileobj_duppath(config.archive_dir_path,
                                      part_sig_filename,
                                      perm_sig_filename,
                                      remote_sig_filename,
                                      overwrite=True)
    return fh


def full_backup(col_stats):
    u"""
    Do full backup of directory to backend, using archive_dir_path

    @type col_stats: CollectionStatus object
    @param col_stats: collection status

    @rtype: void
    @return: void
    """
    if config.progress:
        progress.tracker = progress.ProgressTracker()
        # Fake a backup to compute total of moving bytes
        tarblock_iter = diffdir.DirFull(config.select)
        dummy_backup(tarblock_iter)
        # Store computed stats to compute progress later
        progress.tracker.set_evidence(diffdir.stats, True)
        # Reinit the config.select iterator, so
        # the core of duplicity can rescan the paths
        commandline.set_selection()
        progress.progress_thread = progress.LogProgressThread()

    if config.dry_run:
        tarblock_iter = diffdir.DirFull(config.select)
        bytes_written = dummy_backup(tarblock_iter)
        col_stats.set_values(sig_chain_warning=None)
    else:
        sig_outfp = get_sig_fileobj(u"full-sig")
        man_outfp = get_man_fileobj(u"full")
        tarblock_iter = diffdir.DirFull_WriteSig(config.select,
                                                 sig_outfp)
        bytes_written = write_multivol(u"full", tarblock_iter,
                                       man_outfp, sig_outfp,
                                       config.backend)

        # close sig file, send to remote, and rename to final
        sig_outfp.close()
        sig_outfp.to_remote()
        sig_outfp.to_final()

        # close manifest, send to remote, and rename to final
        man_outfp.close()
        man_outfp.to_remote()
        man_outfp.to_final()

        if config.progress:
            # Terminate the background thread now, if any
            progress.progress_thread.finished = True
            progress.progress_thread.join()
            log.TransferProgress(100.0, 0, progress.tracker.total_bytecount,
                                 progress.tracker.total_elapsed_seconds(),
                                 progress.tracker.speed, False)

        col_stats.set_values(sig_chain_warning=None)

    print_statistics(diffdir.stats, bytes_written)


def check_sig_chain(col_stats):
    u"""
    Get last signature chain for inc backup, or None if none available

    @type col_stats: CollectionStatus object
    @param col_stats: collection status
    """
    if not col_stats.matched_chain_pair:
        if config.incremental:
            log.FatalError(_(u"Fatal Error: Unable to start incremental backup.  "
                             u"Old signatures not found and incremental specified"),
                           log.ErrorCode.inc_without_sigs)
        else:
            log.Warn(_(u"No signatures found, switching to full backup."))
        return None
    return col_stats.matched_chain_pair[0]


def print_statistics(stats, bytes_written):  # pylint: disable=unused-argument
    u"""
    If config.print_statistics, print stats after adding bytes_written

    @rtype: void
    @return: void
    """
    if config.print_statistics:
        diffdir.stats.TotalDestinationSizeChange = bytes_written
        logstring = diffdir.stats.get_stats_logstring(_(u"Backup Statistics"))
        log.Log(logstring, log.NOTICE, force_print=True)


def incremental_backup(sig_chain):
    u"""
    Do incremental backup of directory to backend, using archive_dir_path

    @rtype: void
    @return: void
    """
    if not config.restart:
        dup_time.setprevtime(sig_chain.end_time)
        if dup_time.curtime == dup_time.prevtime:
            time.sleep(2)
            dup_time.setcurtime()
            assert dup_time.curtime != dup_time.prevtime, \
                u"time not moving forward at appropriate pace - system clock issues?"

    if config.progress:
        progress.tracker = progress.ProgressTracker()
        # Fake a backup to compute total of moving bytes
        tarblock_iter = diffdir.DirDelta(config.select,
                                         sig_chain.get_fileobjs())
        dummy_backup(tarblock_iter)
        # Store computed stats to compute progress later
        progress.tracker.set_evidence(diffdir.stats, False)
        # Reinit the config.select iterator, so
        # the core of duplicity can rescan the paths
        commandline.set_selection()
        progress.progress_thread = progress.LogProgressThread()

    if config.dry_run:
        tarblock_iter = diffdir.DirDelta(config.select,
                                         sig_chain.get_fileobjs())
        bytes_written = dummy_backup(tarblock_iter)
    else:
        new_sig_outfp = get_sig_fileobj(u"new-sig")
        new_man_outfp = get_man_fileobj(u"inc")
        tarblock_iter = diffdir.DirDelta_WriteSig(config.select,
                                                  sig_chain.get_fileobjs(),
                                                  new_sig_outfp)
        bytes_written = write_multivol(u"inc", tarblock_iter,
                                       new_man_outfp, new_sig_outfp,
                                       config.backend)

        # close sig file and rename to final
        new_sig_outfp.close()
        new_sig_outfp.to_remote()
        new_sig_outfp.to_final()

        # close manifest and rename to final
        new_man_outfp.close()
        new_man_outfp.to_remote()
        new_man_outfp.to_final()

        if config.progress:
            # Terminate the background thread now, if any
            progress.progress_thread.finished = True
            progress.progress_thread.join()
            log.TransferProgress(100.0, 0, progress.tracker.total_bytecount,
                                 progress.tracker.total_elapsed_seconds(),
                                 progress.tracker.speed, False)

    print_statistics(diffdir.stats, bytes_written)


def list_current(col_stats):
    u"""
    List the files current in the archive (examining signature only)

    @type col_stats: CollectionStatus object
    @param col_stats: collection status

    @rtype: void
    @return: void
    """
    time = config.restore_time or dup_time.curtime
    sig_chain = col_stats.get_signature_chain_at_time(time)
    path_iter = diffdir.get_combined_path_iter(sig_chain.get_fileobjs(time))
    for path in path_iter:
        if path.difftype != u"deleted":
            user_info = u"%s %s" % (dup_time.timetopretty(path.getmtime()),
                                    util.fsdecode(path.get_relative_path()))
            log_info = u"%s %s %s" % (dup_time.timetostring(path.getmtime()),
                                      util.escape(path.get_relative_path()),
                                      path.type)
            log.Log(user_info, log.INFO, log.InfoCode.file_list,
                    log_info, True)


def restore(col_stats):
    u"""
    Restore archive in config.backend to config.local_path

    @type col_stats: CollectionStatus object
    @param col_stats: collection status

    @rtype: void
    @return: void
    """
    if config.dry_run:
        # Only prints list of required volumes when running dry
        restore_get_patched_rop_iter(col_stats)
        return
    if not patchdir.Write_ROPaths(config.local_path,
                                  restore_get_patched_rop_iter(col_stats)):
        if config.restore_dir:
            log.FatalError(_(u"%s not found in archive - no files restored.")
                           % (util.fsdecode(config.restore_dir)),
                           log.ErrorCode.restore_dir_not_found)
        else:
            log.FatalError(_(u"No files found in archive - nothing restored."),
                           log.ErrorCode.no_restore_files)


def restore_get_patched_rop_iter(col_stats):
    u"""
    Return iterator of patched ROPaths of desired restore data

    @type col_stats: CollectionStatus object
    @param col_stats: collection status
    """
    if config.restore_dir:
        index = tuple(config.restore_dir.split(b"/"))
    else:
        index = ()
    time = config.restore_time or dup_time.curtime
    backup_chain = col_stats.get_backup_chain_at_time(time)
    assert backup_chain, col_stats.all_backup_chains
    backup_setlist = backup_chain.get_sets_at_time(time)
    num_vols = 0
    for s in backup_setlist:
        num_vols += len(s)
    cur_vol = [0]

    def get_fileobj_iter(backup_set):
        u"""Get file object iterator from backup_set contain given index"""
        manifest = backup_set.get_manifest()
        volumes = manifest.get_containing_volumes(index)

        if hasattr(backup_set.backend.backend, u'pre_process_download_batch'):
            backup_set.backend.backend.pre_process_download_batch(backup_set.volume_name_dict.values())

        for vol_num in volumes:
            yield restore_get_enc_fileobj(backup_set.backend,
                                          backup_set.volume_name_dict[vol_num],
                                          manifest.volume_info_dict[vol_num])
            cur_vol[0] += 1
            log.Progress(_(u'Processed volume %d of %d') % (cur_vol[0], num_vols),
                         cur_vol[0], num_vols)

    if hasattr(config.backend, u'pre_process_download') or config.dry_run:
        file_names = []
        for backup_set in backup_setlist:
            manifest = backup_set.get_manifest()
            volumes = manifest.get_containing_volumes(index)
            for vol_num in volumes:
                file_names.append(backup_set.volume_name_dict[vol_num])
        if config.dry_run:
            log.Notice(u"Required volumes to restore:\n\t" +
                       u'\n\t'.join(file_name.decode() for file_name in file_names))
            return None
        else:
            config.backend.pre_process_download(file_names)

    fileobj_iters = list(map(get_fileobj_iter, backup_setlist))
    tarfiles = list(map(patchdir.TarFile_FromFileobjs, fileobj_iters))
    return patchdir.tarfiles2rop_iter(tarfiles, index)


def restore_get_enc_fileobj(backend, filename, volume_info):
    u"""
    Return plaintext fileobj from encrypted filename on backend

    If volume_info is set, the hash of the file will be checked,
    assuming some hash is available.  Also, if config.sign_key is
    set, a fatal error will be raised if file not signed by sign_key.

    """
    parseresults = file_naming.parse(filename)
    tdp = dup_temp.new_tempduppath(parseresults)
    backend.get(filename, tdp)

    u""" verify hash of the remote file """
    verified, hash_pair, calculated_hash = restore_check_hash(volume_info, tdp)
    if not verified:
        log.FatalError(u"%s\n %s\n %s\n %s\n" %
                       (_(u"Invalid data - %s hash mismatch for file:") %
                        hash_pair[0],
                        util.fsdecode(filename),
                        _(u"Calculated hash: %s") % calculated_hash,
                        _(u"Manifest hash: %s") % hash_pair[1]),
                       log.ErrorCode.mismatched_hash)

    fileobj = tdp.filtered_open_with_delete(u"rb")
    if parseresults.encrypted and config.gpg_profile.sign_key:
        restore_add_sig_check(fileobj)
    return fileobj


def restore_check_hash(volume_info, vol_path):
    u"""
    Check the hash of vol_path path against data in volume_info

    @rtype: boolean
    @return: true (verified) / false (failed)
    """
    hash_pair = volume_info.get_best_hash()
    if hash_pair:
        calculated_hash = gpg.get_hash(hash_pair[0], vol_path)
        if calculated_hash != hash_pair[1]:
            return False, hash_pair, calculated_hash
    u""" reached here, verification passed """
    return True, hash_pair, calculated_hash


def restore_add_sig_check(fileobj):
    u"""
    Require signature when closing fileobj matches sig in gpg_profile

    @rtype: void
    @return: void
    """
    assert (isinstance(fileobj, dup_temp.FileobjHooked) and
            isinstance(fileobj.fileobj, gpg.GPGFile)), fileobj

    def check_signature():
        u"""Thunk run when closing volume file"""
        actual_sig = fileobj.fileobj.get_signature()
        actual_sig = u"None" if actual_sig is None else actual_sig
        sign_key = config.gpg_profile.sign_key
        sign_key = u"None" if sign_key is None else sign_key
        ofs = -min(len(actual_sig), len(sign_key))
        if actual_sig[ofs:] != sign_key[ofs:]:
            log.FatalError(_(u"Volume was signed by key %s, not %s") %
                           (actual_sig[ofs:], sign_key[ofs:]),
                           log.ErrorCode.unsigned_volume)

    fileobj.addhook(check_signature)


def verify(col_stats):
    u"""
    Verify files, logging differences

    @type col_stats: CollectionStatus object
    @param col_stats: collection status

    @rtype: void
    @return: void
    """
    global exit_val
    collated = diffdir.collate2iters(restore_get_patched_rop_iter(col_stats),
                                     config.select)
    diff_count = 0
    total_count = 0
    for backup_ropath, current_path in collated:
        if not backup_ropath:
            backup_ropath = path.ROPath(current_path.index)
        if not current_path:
            current_path = path.ROPath(backup_ropath.index)
        if not backup_ropath.compare_verbose(current_path, config.compare_data):
            diff_count += 1
        total_count += 1
    # Unfortunately, ngettext doesn't handle multiple number variables, so we
    # split up the string.
    log.Notice(_(u"Verify complete: %s, %s.") %
               (ngettext(u"%d file compared",
                         u"%d files compared", total_count) % total_count,
                ngettext(u"%d difference found",
                         u"%d differences found", diff_count) % diff_count))
    if diff_count >= 1:
        exit_val = 1


def cleanup(col_stats):
    u"""
    Delete the extraneous files in the current backend

    @type col_stats: CollectionStatus object
    @param col_stats: collection status

    @rtype: void
    @return: void
    """
    ext_local, ext_remote = col_stats.get_extraneous()
    extraneous = ext_local + ext_remote
    if not extraneous:
        log.Warn(_(u"No extraneous files found, nothing deleted in cleanup."))
        return

    filestr = u"\n".join(map(util.fsdecode, extraneous))
    if config.force:
        log.Notice(ngettext(u"Deleting this file from backend:",
                            u"Deleting these files from backend:",
                            len(extraneous)) + u"\n" + filestr)
        if not config.dry_run:
            col_stats.backend.delete(ext_remote)
            for fn in ext_local:
                try:
                    config.archive_dir_path.append(fn).delete()
                except Exception:
                    pass
    else:
        log.Notice(ngettext(u"Found the following file to delete:",
                            u"Found the following files to delete:",
                            len(extraneous)) + u"\n" + filestr + u"\n" +
                   _(u"Run duplicity again with the --force option to actually delete."))


def remove_all_but_n_full(col_stats):
    u"""
    Remove backup files older than the last n full backups.

    @type col_stats: CollectionStatus object
    @param col_stats: collection status

    @rtype: void
    @return: void
    """
    assert config.keep_chains is not None

    config.remove_time = col_stats.get_nth_last_full_backup_time(config.keep_chains)

    remove_old(col_stats)


def remove_old(col_stats):
    u"""
    Remove backup files older than config.remove_time from backend

    @type col_stats: CollectionStatus object
    @param col_stats: collection status

    @rtype: void
    @return: void
    """
    assert config.remove_time is not None

    def set_times_str(setlist):
        u"""Return string listing times of sets in setlist"""
        return u"\n".join([dup_time.timetopretty(s.get_time()) for s in setlist])

    def chain_times_str(chainlist):
        u"""Return string listing times of chains in chainlist"""
        return u"\n".join([dup_time.timetopretty(s.end_time) for s in chainlist])

    req_list = col_stats.get_older_than_required(config.remove_time)
    if req_list:
        log.Warn(u"%s\n%s\n%s" %
                 (_(u"There are backup set(s) at time(s):"),
                  set_times_str(req_list),
                  _(u"Which can't be deleted because newer sets depend on them.")))

    if (col_stats.matched_chain_pair and
            col_stats.matched_chain_pair[1].end_time < config.remove_time):
        log.Warn(_(u"Current active backup chain is older than specified time.  "
                   u"However, it will not be deleted.  To remove all your backups, "
                   u"manually purge the repository."))

    chainlist = col_stats.get_chains_older_than(config.remove_time)

    if config.remove_all_inc_of_but_n_full_mode:
        # ignore chains without incremental backups:
        chainlist = list(x for x in chainlist if
                         (isinstance(x, dup_collections.SignatureChain) and x.inclist) or
                         (isinstance(x, dup_collections.BackupChain) and x.incset_list))

    if not chainlist:
        log.Notice(_(u"No old backup sets found, nothing deleted."))
        return
    if config.force:
        log.Notice(ngettext(u"Deleting backup chain at time:",
                            u"Deleting backup chains at times:",
                            len(chainlist)) +
                   u"\n" + chain_times_str(chainlist))
        # Add signature files too, since they won't be needed anymore
        chainlist += col_stats.get_signature_chains_older_than(config.remove_time)
        chainlist.reverse()  # save oldest for last
        for chain in chainlist:
            # if remove_all_inc_of_but_n_full_mode mode, remove only
            # incrementals one and not full
            if config.remove_all_inc_of_but_n_full_mode:
                if isinstance(chain, dup_collections.SignatureChain):
                    chain_desc = _(u"Deleting any incremental signature chain rooted at %s")
                else:
                    chain_desc = _(u"Deleting any incremental backup chain rooted at %s")
            else:
                if isinstance(chain, dup_collections.SignatureChain):
                    chain_desc = _(u"Deleting complete signature chain %s")
                else:
                    chain_desc = _(u"Deleting complete backup chain %s")
            log.Notice(chain_desc % dup_time.timetopretty(chain.end_time))
            if not config.dry_run:
                chain.delete(keep_full=config.remove_all_inc_of_but_n_full_mode)
        col_stats.set_values(sig_chain_warning=None)
    else:
        log.Notice(ngettext(u"Found old backup chain at the following time:",
                            u"Found old backup chains at the following times:",
                            len(chainlist)) +
                   u"\n" + chain_times_str(chainlist) + u"\n" +
                   _(u"Rerun command with --force option to actually delete."))


def replicate():
    u"""
    Replicate backup files from one remote to another, possibly encrypting or adding parity.

    @rtype: void
    @return: void
    """
    action = u"replicate"
    time = config.restore_time or dup_time.curtime
    src_stats = dup_collections.CollectionsStatus(config.src_backend, None, action).set_values(sig_chain_warning=None)
    tgt_stats = dup_collections.CollectionsStatus(config.backend, None, action).set_values(sig_chain_warning=None)

    src_list = config.src_backend.list()
    tgt_list = config.backend.list()

    src_chainlist = src_stats.get_signature_chains(local=False, filelist=src_list)[0]
    tgt_chainlist = tgt_stats.get_signature_chains(local=False, filelist=tgt_list)[0]
    sorted(src_chainlist, key=lambda chain: chain.start_time)
    sorted(tgt_chainlist, key=lambda chain: chain.start_time)
    if not src_chainlist:
        log.Notice(_(u"No old backup sets found."))
        return
    for src_chain in src_chainlist:
        try:
            tgt_chain = list([chain for chain in tgt_chainlist if chain.start_time == src_chain.start_time])[0]
        except IndexError:
            tgt_chain = None

        tgt_sigs = list(map(file_naming.parse, tgt_chain.get_filenames())) if tgt_chain else []
        for src_sig_filename in src_chain.get_filenames():
            src_sig = file_naming.parse(src_sig_filename)
            if not (src_sig.time or src_sig.end_time) < time:
                continue
            try:
                tgt_sigs.remove(src_sig)
                log.Info(_(u"Signature %s already replicated") % (src_sig_filename,))
                continue
            except ValueError:
                pass
            if src_sig.type == u'new-sig':
                dup_time.setprevtime(src_sig.start_time)
            dup_time.setcurtime(src_sig.time or src_sig.end_time)
            log.Notice(_(u"Replicating %s.") % (src_sig_filename,))
            fileobj = config.src_backend.get_fileobj_read(src_sig_filename)
            filename = file_naming.get(src_sig.type, encrypted=config.encryption, gzipped=config.compression)
            tdp = dup_temp.new_tempduppath(file_naming.parse(filename))
            tmpobj = tdp.filtered_open(mode=u'wb')
            util.copyfileobj(fileobj, tmpobj)  # decrypt, compress, (re)-encrypt
            fileobj.close()
            tmpobj.close()
            config.backend.put(tdp, filename)
            tdp.delete()

    src_chainlist = src_stats.get_backup_chains(filename_list=src_list)[0]
    tgt_chainlist = tgt_stats.get_backup_chains(filename_list=tgt_list)[0]
    sorted(src_chainlist, key=lambda chain: chain.start_time)
    sorted(tgt_chainlist, key=lambda chain: chain.start_time)
    for src_chain in src_chainlist:
        try:
            tgt_chain = list([chain for chain in tgt_chainlist if chain.start_time == src_chain.start_time])[0]
        except IndexError:
            tgt_chain = None

        tgt_sets = tgt_chain.get_all_sets() if tgt_chain else []
        for src_set in src_chain.get_all_sets():
            if not src_set.get_time() < time:
                continue
            try:
                tgt_sets.remove(src_set)
                log.Info(_(u"Backupset %s already replicated") % (src_set.remote_manifest_name,))
                continue
            except ValueError:
                pass
            if src_set.type == u'inc':
                dup_time.setprevtime(src_set.start_time)
            dup_time.setcurtime(src_set.get_time())
            rmf = src_set.get_remote_manifest()
            mf_filename = file_naming.get(src_set.type, manifest=True)
            mf_tdp = dup_temp.new_tempduppath(file_naming.parse(mf_filename))
            mf = manifest.Manifest(fh=mf_tdp.filtered_open(mode=u'wb'))
            for i, filename in list(src_set.volume_name_dict.items()):
                log.Notice(_(u"Replicating %s.") % (filename,))
                fileobj = restore_get_enc_fileobj(config.src_backend, filename, rmf.volume_info_dict[i])
                filename = file_naming.get(src_set.type, i, encrypted=config.encryption, gzipped=config.compression)
                tdp = dup_temp.new_tempduppath(file_naming.parse(filename))
                tmpobj = tdp.filtered_open(mode=u'wb')
                util.copyfileobj(fileobj, tmpobj)  # decrypt, compress, (re)-encrypt
                fileobj.close()
                tmpobj.close()
                config.backend.put(tdp, filename)

                vi = copy.copy(rmf.volume_info_dict[i])
                vi.set_hash(u"SHA1", gpg.get_hash(u"SHA1", tdp))
                mf.add_volume_info(vi)

                tdp.delete()

            mf.fh.close()
            # incremental GPG writes hang on close, so do any encryption here at once
            mf_fileobj = mf_tdp.filtered_open_with_delete(mode=u'rb')
            mf_final_filename = file_naming.get(src_set.type,
                                                manifest=True,
                                                encrypted=config.encryption,
                                                gzipped=config.compression)
            mf_final_tdp = dup_temp.new_tempduppath(file_naming.parse(mf_final_filename))
            mf_final_fileobj = mf_final_tdp.filtered_open(mode=u'wb')
            util.copyfileobj(mf_fileobj, mf_final_fileobj)  # compress, encrypt
            mf_fileobj.close()
            mf_final_fileobj.close()
            config.backend.put(mf_final_tdp, mf_final_filename)
            mf_final_tdp.delete()

    config.src_backend.close()
    config.backend.close()


def sync_archive(col_stats):
    u"""
    Synchronize local archive manifest file and sig chains to remote archives.
    Copy missing files from remote to local as needed to make sure the local
    archive is synchronized to remote storage.

    @rtype: void
    @return: void
    """
    suffixes = [b".g", b".gpg", b".z", b".gz", b".part"]

    def is_needed(filename):
        u"""Indicates if the metadata file should be synced.

        In full sync mode, or if there's a collection misbehavior, all files
        are needed.

        Otherwise, only the metadata for the target chain needs sync.
        """
        if config.metadata_sync_mode == u"full":
            return True
        assert config.metadata_sync_mode == u"partial"
        parsed = file_naming.parse(filename)
        try:
            target_chain = col_stats.get_backup_chain_at_time(
                config.restore_time or dup_time.curtime)
        except dup_collections.CollectionsError:
            # With zero or multiple chains at this time, do a full sync
            return True
        if parsed.start_time is None and parsed.end_time is None:
            start_time = end_time = parsed.time
        else:
            start_time = parsed.start_time
            end_time = parsed.end_time

        return end_time >= target_chain.start_time and \
            start_time <= target_chain.end_time

    def get_metafiles(filelist):
        u"""
        Return metafiles of interest from the file list.
        Files of interest are:
          sigtar - signature files
          manifest - signature files
          duplicity partial versions of the above
        Files excluded are:
          non-duplicity files

        @rtype: list
        @return: list of duplicity metadata files
        """
        metafiles = {}
        partials = {}
        need_passphrase = False
        for fn in filelist:
            pr = file_naming.parse(fn)
            if not pr:
                continue
            if pr.encrypted:
                need_passphrase = True
            if pr.type in [u"full-sig", u"new-sig"] or pr.manifest:
                base, ext = os.path.splitext(fn)
                if ext not in suffixes:
                    base = fn
                if pr.partial:
                    partials[base] = fn
                else:
                    metafiles[base] = fn
        return metafiles, partials, need_passphrase

    def copy_raw(src_iter, filename):
        u"""
        Copy data from src_iter to file at fn
        """
        file = open(filename, u"wb")
        while True:
            try:
                data = src_iter.__next__().data
            except StopIteration:
                break
            file.write(data)
        file.close()

    def resolve_basename(fn):
        u"""
        @return: (parsedresult, local_name, remote_name)
        """
        pr = file_naming.parse(fn)

        base, ext = os.path.splitext(fn)
        if ext not in suffixes:
            base = fn

        suffix = file_naming.get_suffix(False, not pr.manifest)
        loc_name = base + suffix

        return (pr, loc_name, fn)

    def remove_local(fn):
        del_name = config.archive_dir_path.append(fn).name

        log.Notice(_(u"Deleting local %s (not authoritative at backend).") %
                   util.fsdecode(del_name))
        try:
            util.ignore_missing(os.unlink, del_name)
        except Exception as e:
            log.Warn(_(u"Unable to delete %s: %s") % (util.fsdecode(del_name),
                                                      util.uexc(e)))

    def copy_to_local(fn):
        u"""
        Copy remote file fn to local cache.
        """
        class Block(object):
            u"""
            Data block to return from SrcIter
            """

            def __init__(self, data):
                self.data = data

        class SrcIter(object):
            u"""
            Iterate over source and return Block of data.
            """

            def __init__(self, fileobj):
                self.fileobj = fileobj

            def __next__(self):
                try:
                    res = Block(self.fileobj.read(self.get_read_size()))
                except Exception:
                    if hasattr(self.fileobj, u'name'):
                        name = self.fileobj.name
                        # name may be a path
                        if hasattr(name, u'name'):
                            name = name.name
                    else:
                        name = None
                    log.FatalError(_(u"Failed to read %s: %s") %
                                   (util.fsdecode(name), sys.exc_info()),
                                   log.ErrorCode.generic)
                if not res.data:
                    self.fileobj.close()
                    raise StopIteration
                return res

            def get_read_size(self):
                return 128 * 1024

            def get_footer(self):
                return b""

        log.Notice(_(u"Copying %s to local cache.") % util.fsdecode(fn))

        pr, loc_name, rem_name = resolve_basename(fn)

        fileobj = config.backend.get_fileobj_read(fn)
        src_iter = SrcIter(fileobj)
        tdp = dup_temp.new_tempduppath(file_naming.parse(loc_name))
        if pr.manifest:
            copy_raw(src_iter, tdp.name)
        else:
            gpg.GzipWriteFile(src_iter, tdp.name, size=sys.maxsize)
        tdp.setdata()
        tdp.move(config.archive_dir_path.append(loc_name))

    # get remote metafile list
    remlist = config.backend.list()
    remote_metafiles, ignored, rem_needpass = get_metafiles(remlist)

    # get local metafile list
    loclist = config.archive_dir_path.listdir()
    local_metafiles, local_partials, loc_needpass = get_metafiles(loclist)

    # we have the list of metafiles on both sides. remote is always
    # authoritative. figure out which are local spurious (should not
    # be there) and missing (should be there but are not).
    local_keys = list(local_metafiles.keys())
    remote_keys = list(remote_metafiles.keys())

    local_missing = []
    local_spurious = []

    for key in remote_keys:
        # If we lost our cache, re-get the remote file.  But don't do it if we
        # already have a local partial.  The local partial will already be
        # complete in this case (seems we got interrupted before we could move
        # it to its final location).
        if key not in local_keys and key not in local_partials and is_needed(key):
            local_missing.append(remote_metafiles[key])

    for key in local_keys:
        # If we have a file locally that is unnecessary, delete it.  Also
        # delete final versions of partial files because if we have both, it
        # means the write of the final version got interrupted.
        if key not in remote_keys or key in local_partials:
            local_spurious.append(local_metafiles[key])

    # finally finish the process
    if not local_missing and not local_spurious:
        log.Notice(_(u"Local and Remote metadata are synchronized, no sync needed."))
    else:
        local_missing.sort()
        local_spurious.sort()
        if not config.dry_run:
            log.Notice(_(u"Synchronizing remote metadata to local cache..."))
            if local_missing and (rem_needpass or loc_needpass):
                # password for the --encrypt-key
                config.gpg_profile.passphrase = get_passphrase(1, u"sync")
            for fn in local_spurious:
                remove_local(fn)
            if hasattr(config.backend, u'pre_process_download'):
                config.backend.pre_process_download(local_missing)
            for fn in local_missing:
                copy_to_local(fn)
            col_stats.set_values()
        else:
            if local_missing:
                log.Notice(_(u"Sync would copy the following from remote to local:") +
                           u"\n" + u"\n".join(map(util.fsdecode, local_missing)))
            if local_spurious:
                log.Notice(_(u"Sync would remove the following spurious local files:") +
                           u"\n" + u"\n".join(map(util.fsdecode, local_spurious)))


def check_last_manifest(col_stats):
    u"""
    Check consistency and hostname/directory of last manifest

    @type col_stats: CollectionStatus object
    @param col_stats: collection status

    @rtype: void
    @return: void
    """
    assert col_stats.all_backup_chains
    last_backup_set = col_stats.all_backup_chains[-1].get_last()
    # check remote manifest only if we can decrypt it (see #1729796)
    check_remote = not config.encryption or config.gpg_profile.passphrase
    last_backup_set.check_manifests(check_remote=check_remote)


def check_resources(action):
    u"""
    Check for sufficient resources:
      - temp space for volume build
      - enough max open files
    Put out fatal error if not sufficient to run

    @type action: string
    @param action: action in progress

    @rtype: void
    @return: void
    """
    if action in [u"full", u"inc", u"restore"]:
        # Make sure we have enough resouces to run
        # First check disk space in temp area.
        tempfile, tempname = tempdir.default().mkstemp()
        os.close(tempfile)
        # strip off the temp dir and file
        tempfs = os.path.sep.join(tempname.split(os.path.sep)[:-2])
        try:
            stats = os.statvfs(tempfs)
        except Exception:
            log.FatalError(_(u"Unable to get free space on temp."),
                           log.ErrorCode.get_freespace_failed)
        # Calculate space we need for at least 2 volumes of full or inc
        # plus about 30% of one volume for the signature files.
        freespace = stats.f_frsize * stats.f_bavail
        needspace = (((config.async_concurrency + 1) * config.volsize) +
                     int(0.30 * config.volsize))
        if freespace < needspace:
            log.FatalError(_(u"Temp space has %d available, backup needs approx %d.") %
                           (freespace, needspace), log.ErrorCode.not_enough_freespace)
        else:
            log.Info(_(u"Temp has %d available, backup will use approx %d.") %
                     (freespace, needspace))

        # Some environments like Cygwin run with an artificially
        # low value for max open files.  Check for safe number.
        try:
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        except resource.error:
            log.FatalError(_(u"Unable to get max open files."),
                           log.ErrorCode.get_ulimit_failed)
        maxopen = min([l for l in (soft, hard) if l > -1])
        if maxopen < 1024:
            log.FatalError(_(u"Max open files of %s is too low, should be >= 1024.\n"
                             u"Use 'ulimit -n 1024' or higher to correct.\n") % (maxopen,),
                           log.ErrorCode.maxopen_too_low)


def log_startup_parms(verbosity=log.INFO):
    u"""
    log Python, duplicity, and system versions
    """
    log.Log(u'=' * 80, verbosity)
    log.Log(u"duplicity %s" % __version__, verbosity)
    u_args = (util.fsdecode(arg) for arg in sys.argv)
    log.Log(u"Args: %s" % u' '.join(u_args), verbosity)
    log.Log(u' '.join(platform.uname()), verbosity)
    log.Log(u"%s %s" % (sys.executable or sys.platform, sys.version), verbosity)
    log.Log(u'=' * 80, verbosity)


class Restart(object):
    u"""
    Class to aid in restart of inc or full backup.
    Instance in config.restart if restart in progress.
    """

    def __init__(self, last_backup):
        self.type = None
        self.start_time = None
        self.end_time = None
        self.start_vol = None
        self.last_index = None
        self.last_block = None
        self.last_backup = last_backup
        self.setParms(last_backup)

    def setParms(self, last_backup):
        if last_backup.time:
            self.type = u"full"
            self.time = last_backup.time
        else:
            self.type = u"inc"
            self.end_time = last_backup.end_time
            self.start_time = last_backup.start_time
        # We start one volume back in case we weren't able to finish writing
        # the most recent block.  Actually checking if we did (via hash) would
        # involve downloading the block.  Easier to just redo one block.
        self.start_vol = max(len(last_backup) - 1, 0)

    def checkManifest(self, mf):
        mf_len = len(mf.volume_info_dict)
        if (mf_len != self.start_vol) or not (mf_len and self.start_vol):
            if self.start_vol == 0:
                # upload of 1st vol failed, clean and restart
                log.Notice(_(u"RESTART: The first volume failed to upload before termination.\n"
                             u"         Restart is impossible...starting backup from beginning."))
                self.last_backup.delete()
                os.execve(sys.argv[0], sys.argv, os.environ)
            elif mf_len - self.start_vol > 0:
                # upload of N vols failed, fix manifest and restart
                log.Notice(_(u"RESTART: Volumes %d to %d failed to upload before termination.\n"
                             u"         Restarting backup at volume %d.") %
                           (self.start_vol + 1, mf_len, self.start_vol + 1))
                for vol in range(self.start_vol + 1, mf_len + 1):
                    mf.del_volume_info(vol)
            else:
                # this is an 'impossible' state, remove last partial and restart
                log.Notice(_(u"RESTART: Impossible backup state: manifest has %d vols, remote has %d vols.\n"
                             u"         Restart is impossible ... duplicity will clean off the last partial\n"
                             u"         backup then restart the backup from the beginning.") %
                           (mf_len, self.start_vol))
                self.last_backup.delete()
                os.execve(sys.argv[0], sys.argv, os.environ)

    def setLastSaved(self, mf):
        vi = mf.volume_info_dict[self.start_vol]
        self.last_index = vi.end_index
        self.last_block = vi.end_block or 0


def main():
    u"""
    Start/end here
    """
    # per bug https://bugs.launchpad.net/duplicity/+bug/931175
    # duplicity crashes when PYTHONOPTIMIZE is set, so check
    # and refuse to run if it is set.
    if u'PYTHONOPTIMIZE' in os.environ:
        log.FatalError(_(u"""
PYTHONOPTIMIZE in the environment causes duplicity to fail to
recognize its own backups.  Please remove PYTHONOPTIMIZE from
the environment and rerun the backup.

See https://bugs.launchpad.net/duplicity/+bug/931175
"""), log.ErrorCode.pythonoptimize_set)

    # if python is run setuid, it's only partway set,
    # so make sure to run with euid/egid of root
    if os.geteuid() == 0:
        # make sure uid/gid match euid/egid
        os.setuid(os.geteuid())
        os.setgid(os.getegid())

    # set the current time strings (make it available for command line processing)
    dup_time.setcurtime()

    # determine what action we're performing and process command line
    action = commandline.ProcessCommandLine(sys.argv[1:])

    config.lockpath = os.path.join(config.archive_dir_path.name, b"lockfile")
    config.lockfile = fasteners.process_lock.InterProcessLock(config.lockpath)
    log.Debug(_(u"Acquiring lockfile %s") % config.lockpath)
    if not config.lockfile.acquire(blocking=False):
        log.FatalError(
            u"Another duplicity instance is already running with this archive directory\n",
            log.ErrorCode.user_error)
        log.shutdown()
        sys.exit(2)

    try:
        do_backup(action)

    finally:
        util.release_lockfile()


def do_backup(action):
    # set the current time strings again now that we have time separator
    if config.current_time:
        dup_time.setcurtime(config.current_time)
    else:
        dup_time.setcurtime()

    # log some debugging status info
    log_startup_parms(log.INFO)

    # check for disk space and available file handles
    check_resources(action)

    # get current collection status
    col_stats = dup_collections.CollectionsStatus(config.backend,
                                                  config.archive_dir_path,
                                                  action).set_values()

    # check archive synch with remote, fix if needed
    if action not in [u"collection-status",
                      u"remove-all-but-n-full",
                      u"remove-all-inc-of-but-n-full",
                      u"remove-old",
                      u"replicate",
                      ]:
        sync_archive(col_stats)

    while True:
        # if we have to clean up the last partial, then col_stats are invalidated
        # and we have to start the process all over again until clean.
        if action in [u"full", u"inc", u"cleanup"]:
            last_full_chain = col_stats.get_last_backup_chain()
            if not last_full_chain:
                break
            last_backup = last_full_chain.get_last()
            if last_backup.partial:
                if action in [u"full", u"inc"]:
                    # set restart parms from last_backup info
                    config.restart = Restart(last_backup)
                    # (possibly) reset action
                    action = config.restart.type
                    # reset the time strings
                    if action == u"full":
                        dup_time.setcurtime(config.restart.time)
                    else:
                        dup_time.setcurtime(config.restart.end_time)
                        dup_time.setprevtime(config.restart.start_time)
                    # log it -- main restart heavy lifting is done in write_multivol
                    log.Notice(_(u"Last %s backup left a partial set, restarting." % action))
                    break
                else:
                    # remove last partial backup and get new collection status
                    log.Notice(_(u"Cleaning up previous partial %s backup set, restarting." % action))
                    last_backup.delete()
                    col_stats = dup_collections.CollectionsStatus(config.backend,
                                                                  config.archive_dir_path,
                                                                  action).set_values()
                    continue
            break
        break

    # OK, now we have a stable collection
    last_full_time = col_stats.get_last_full_backup_time()
    if last_full_time > 0:
        log.Notice(_(u"Last full backup date:") + u" " + dup_time.timetopretty(last_full_time))
    else:
        log.Notice(_(u"Last full backup date: none"))
    if not config.restart and action == u"inc" and config.full_force_time is not None and \
       last_full_time < config.full_force_time:
        log.Notice(_(u"Last full backup is too old, forcing full backup"))
        action = u"full"
    log.PrintCollectionStatus(col_stats)

    # get the passphrase if we need to based on action/options
    config.gpg_profile.passphrase = get_passphrase(1, action)

    if action == u"restore":
        restore(col_stats)
    elif action == u"verify":
        verify(col_stats)
    elif action == u"list-current":
        list_current(col_stats)
    elif action == u"collection-status":
        if not config.file_changed:
            log.PrintCollectionStatus(col_stats, True)
        else:
            log.PrintCollectionFileChangedStatus(col_stats, config.file_changed, True)
    elif action == u"cleanup":
        cleanup(col_stats)
    elif action == u"remove-old":
        remove_old(col_stats)
    elif action == u"remove-all-but-n-full" or action == u"remove-all-inc-of-but-n-full":
        remove_all_but_n_full(col_stats)
    elif action == u"sync":
        sync_archive(col_stats)
    elif action == u"replicate":
        replicate()
    else:
        assert action == u"inc" or action == u"full", action
        # the passphrase for full and inc is used by --sign-key
        # the sign key can have a different passphrase than the encrypt
        # key, therefore request a passphrase
        if config.gpg_profile.sign_key:
            config.gpg_profile.signing_passphrase = get_passphrase(1, action, True)

        # if there are no recipients (no --encrypt-key), it must be a
        # symmetric key. Therefore, confirm the passphrase
        if not (config.gpg_profile.recipients or config.gpg_profile.hidden_recipients):
            config.gpg_profile.passphrase = get_passphrase(2, action)
            # a limitation in the GPG implementation does not allow for
            # inputting different passphrases, this affects symmetric+sign.
            # Allow an empty passphrase for the key though to allow a non-empty
            # symmetric key
            if (config.gpg_profile.signing_passphrase and
                    config.gpg_profile.passphrase != config.gpg_profile.signing_passphrase):
                log.FatalError(_(
                    u"When using symmetric encryption, the signing passphrase "
                    u"must equal the encryption passphrase."),
                    log.ErrorCode.user_error)

        if action == u"full":
            full_backup(col_stats)
        else:  # attempt incremental
            sig_chain = check_sig_chain(col_stats)
            # action == "inc" was requested, but no full backup is available
            if not sig_chain:
                full_backup(col_stats)
            else:
                if not config.restart:
                    # only ask for a passphrase if there was a previous backup
                    if col_stats.all_backup_chains:
                        config.gpg_profile.passphrase = get_passphrase(1, action)
                        check_last_manifest(col_stats)  # not needed for full backups
                incremental_backup(sig_chain)
    config.backend.close()
    log.shutdown()
    if exit_val is not None:
        sys.exit(exit_val)
