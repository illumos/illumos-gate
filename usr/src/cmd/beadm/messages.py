# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
#

"""
beadm - The Boot Environment Administration tool.

A module containing all of the messages output by beadm.
"""

import sys
from beadm import _

class Msgs:
    """Indices corresponding to message numbers for beadm."""

    (BEADM_ERR_ACTIVATE,
    BEADM_ERR_BE_EXISTS,
    BEADM_ERR_SNAP_EXISTS,
    BEADM_ERR_CREATE,
    BEADM_ERR_DESTROY,
    BEADM_ERR_DESTROY_ACTIVE,
    BEADM_ERR_BE_DOES_NOT_EXIST,
    BEADM_ERR_NO_BES_EXIST,
    BEADM_ERR_MSG_SUB,
    BEADM_ERR_ILL_SUBCOMMAND,
    BEADM_ERR_INVALID_RESPONSE,
    BEADM_ERR_LIST,
    BEADM_ERR_LIST_DATA,
    BEADM_ERR_LOG_CREATE,
    BEADM_ERR_LOG_RM,
    BEADM_ERR_MOUNT,
    BEADM_ERR_MOUNT_EXISTS,
    BEADM_ERR_MOUNTED,
    BEADM_ERR_MOUNTPOINT,
    BEADM_ERR_MUTUALLY_EXCL,
    BEADM_ERR_NO_MSG,
    BEADM_ERR_NO_ZPOOL,
    BEADM_ERR_NOT_SUPPORTED_NGZ,
    BEADM_ERR_OPT_ARGS,
    BEADM_ERR_OS,
    BEADM_ERR_PERMISSIONS,
    BEADM_ERR_RENAME,
    BEADM_ERR_SHARED_FS,
    BEADM_ERR_SNAP_DOES_NOT_EXISTS,
    BEADM_ERR_UNMOUNT,
    BEADM_ERR_UNMOUNT_ACTIVE,
    BEADM_ERR_BENAME,
    BEADM_MSG_ACTIVE_ON_BOOT,
    BEADM_MSG_DESTROY,
    BEADM_MSG_DESTROY_NO,
    BEADM_MSG_BE_CREATE_START,
    BEADM_MSG_BE_CREATE_SUCCESS,
    BEADM_MSG_FREE_FORMAT,
    ) = range(38)

    # Indices corresponding to message numbers for libbe that we are
    # interested in expanding messages.
    (BE_ERR_ACCESS,
    BE_ERR_ACTIVATE_CURR,
    BE_ERR_AUTONAME,
    BE_ERR_BE_NOENT,
    BE_ERR_BUSY,
    BE_ERR_CANCELED,
    BE_ERR_CLONE,
    BE_ERR_COPY,
    BE_ERR_CREATDS,
    BE_ERR_CURR_BE_NOT_FOUND,
    BE_ERR_DESTROY,
    BE_ERR_DEMOTE,
    BE_ERR_DSTYPE,
    BE_ERR_BE_EXISTS,
    BE_ERR_INIT,
    BE_ERR_INTR,
    BE_ERR_INVAL,
    BE_ERR_INVALPROP,
    BE_ERR_INVALMOUNTPOINT,
    BE_ERR_MOUNT,
    BE_ERR_MOUNTED,
    BE_ERR_NAMETOOLONG,
    BE_ERR_NOENT,
    BE_ERR_POOL_NOENT,
    BE_ERR_NODEV,
    BE_ERR_NOTMOUNTED,
    BE_ERR_NOMEM,
    BE_ERR_NONINHERIT,
    BE_ERR_NXIO,
    BE_ERR_NOSPC,
    BE_ERR_NOTSUP,
    BE_ERR_OPEN,
    BE_ERR_PERM,
    BE_ERR_UNAVAIL,
    BE_ERR_PROMOTE,
    BE_ERR_ROFS,
    BE_ERR_READONLYDS,
    BE_ERR_READONLYPROP,
    BE_ERR_SS_EXISTS,
    BE_ERR_SS_NOENT,
    BE_ERR_UMOUNT,
    BE_ERR_UMOUNT_CURR_BE,
    BE_ERR_UMOUNT_SHARED,
    BE_ERR_UNKNOWN,
    BE_ERR_ZFS,
    BE_ERR_DESTROY_CURR_BE,
    BE_ERR_GEN_UUID,
    BE_ERR_PARSE_UUID,
    BE_ERR_NO_UUID,
    BE_ERR_ZONE_NO_PARENTBE,
    BE_ERR_ZONE_MULTIPLE_ACTIVE,
    BE_ERR_ZONE_NO_ACTIVE_ROOT,
    BE_ERR_ZONE_ROOT_NOT_LEGACY,
    BE_ERR_NO_MOUNTED_ZONE,
    BE_ERR_MOUNT_ZONEROOT,
    BE_ERR_UMOUNT_ZONEROOT,
    BE_ERR_ZONES_UNMOUNT,
    BE_ERR_FAULT,
    BE_ERR_RENAME_ACTIVE,
    BE_ERR_NO_MENU,
    BE_ERR_DEV_BUSY,
    BE_ERR_BAD_MENU_PATH,
    BE_ERR_ZONE_SS_EXISTS
    ) = range(4000, 4063)

    # Error message dictionaries.
    mBeadmErr = {}
    mBeadmOut = {}
    mBeadmLog = {}

    # Errors from beadm (to stderr).
    mBeadmErr[BEADM_ERR_ACTIVATE] = _("Unable to activate %(0)s.\n%(1)s")
    mBeadmErr[BEADM_ERR_BE_EXISTS] = _("BE %s already exists. Please choose a different BE name.")
    mBeadmErr[BEADM_ERR_BE_DOES_NOT_EXIST] = _("%s does not exist or appear to be a valid BE.\nPlease check that the name of the BE provided is correct.")
    mBeadmErr[BEADM_ERR_NO_BES_EXIST] = _("No boot environments found on this system.")
    mBeadmErr[BEADM_ERR_CREATE] = _("Unable to create %(0)s.\n%(1)s")
    mBeadmErr[BEADM_ERR_DESTROY] = _("Unable to destroy %(0)s.\n%(1)s")
    mBeadmErr[BEADM_ERR_DESTROY_ACTIVE] = _("%(0)s is the currently active BE and cannot be destroyed.\nYou must boot from another BE in order to destroy %(1)s.")
    mBeadmErr[BEADM_ERR_MSG_SUB] = _("Fatal error. No message associated with index %d")
    mBeadmErr[BEADM_ERR_ILL_SUBCOMMAND] = _("Illegal subcommand %s")
    mBeadmErr[BEADM_ERR_INVALID_RESPONSE] = _("Invalid response. Please enter 'y' or 'n'.")
    mBeadmErr[BEADM_ERR_LIST] = _("Unable to display Boot Environment: %s")
    mBeadmErr[BEADM_ERR_LIST_DATA] = _("Unable to process list data.")
    mBeadmErr[BEADM_ERR_LOG_CREATE] = _("Unable to create log file.")
    mBeadmErr[BEADM_ERR_LOG_RM] = _("Unable to remove %s")
    mBeadmErr[BEADM_ERR_MOUNT] = _("Unable to mount %(0)s.\n%(1)s")
    mBeadmErr[BEADM_ERR_MOUNT_EXISTS] = _("%s is already mounted.\nPlease unmount the BE before mounting it again.")
    mBeadmErr[BEADM_ERR_MOUNTED] = _("Unable to destroy %(0)s.\nIt is currently mounted and must be unmounted before it can be destroyed.\nUse 'beadm unmount %(1)s' to unmount the BE before destroying\nit or 'beadm destroy -fF %(2)s'.")
    mBeadmErr[BEADM_ERR_MOUNTPOINT] = _("Invalid mount point %s. Mount point must start with a /.")
    mBeadmErr[BEADM_ERR_MUTUALLY_EXCL] = _("Invalid options: %s are mutually exclusive.")
    mBeadmErr[BEADM_ERR_NO_MSG] = _("Unable to find message for error code: %d")
    mBeadmErr[BEADM_ERR_NO_ZPOOL] = _("BE: %s was not found in any pool.\n The pool may not exist or the name of the BE is not correct.")
    mBeadmErr[BEADM_ERR_NOT_SUPPORTED_NGZ] = _("beadm is not supported in a non-global zone.")
    mBeadmErr[BEADM_ERR_OPT_ARGS] = _("Invalid options and arguments:")
    mBeadmErr[BEADM_ERR_OS] = _("System error: %s")
    mBeadmErr[BEADM_ERR_RENAME] = _("Rename of BE %(0)s failed.\n%(1)s")
    mBeadmErr[BEADM_ERR_SHARED_FS] = _("%s is a shared file system and it cannot be unmounted.")
    mBeadmErr[BEADM_ERR_SNAP_DOES_NOT_EXISTS] = _("%s does not exist or appear to be a valid snapshot.\nPlease check that the name of the snapshot provided is correct.")
    mBeadmErr[BEADM_ERR_SNAP_EXISTS] = _("Snapshot %s already exists.\n Please choose a different snapshot name.")
    mBeadmErr[BEADM_ERR_UNMOUNT] = _("Unable to unmount %(0)s.\n%(1)s")
    mBeadmErr[BEADM_ERR_UNMOUNT_ACTIVE] = _("%s is the currently active BE.\nIt cannot be unmounted unless another BE is the currently active BE.")
    mBeadmErr[BE_ERR_ZONES_UNMOUNT] = _("Unable to destroy one of %(0)s's zone BE's.\nUse 'beadm destroy -fF %(1)s' or 'zfs -f destroy <dataset>'.")
    mBeadmErr[BEADM_ERR_PERMISSIONS] = _("You have insufficient privileges to execute this command.\nEither use 'pfexec' to execute the command or become superuser.")
    mBeadmErr[BEADM_ERR_BENAME] = _("The BE name provided is invalid.\n Please check it and try again.")

    # Catchall
    mBeadmErr[BEADM_MSG_FREE_FORMAT] = "%s"

    # Messages from beadm (to stdout).
    mBeadmOut[BEADM_MSG_ACTIVE_ON_BOOT] = _("The BE that was just destroyed was the 'active on boot' BE.\n%s is now the 'active on boot' BE. Use 'beadm activate' to change it.\n")
    mBeadmOut[BEADM_MSG_DESTROY] = _("Are you sure you want to destroy %s?  This action cannot be undone(y/[n]):")
    mBeadmOut[BEADM_MSG_DESTROY_NO] = _("%s has not been destroyed.\n")

    # Messages from beadm (to log only).
    mBeadmLog[BEADM_MSG_BE_CREATE_START] = "Attempting to create %s"
    mBeadmLog[BEADM_MSG_BE_CREATE_SUCCESS] = "%s was created successfully"

msgLog, msgOut, msgErr = range(3)

def printLog(string, log_fd):
    """Print log."""

    sendMsg(string, msgLog, log_fd)

def printStdout(string, log_fd):
    """Print standard output."""

    sendMsg(string, msgOut, log_fd)

def printStderr(string, log_fd):
    """Print standard error."""

    sendMsg(string, msgErr, log_fd)

def composeMsg(string, txt=None):
    """
    Compose the message to be dispayed.
    txt can be either a list or string object.
    Return the newly composed string.
    """

    try:
        msg = string % txt
    except TypeError:
        msg = string

    return (msg)

def sendMsg(string, mode, log_fd=-1):
    """Send message."""

    if mode == msgOut: 
        print >> sys.stdout, string,
    if mode == msgErr: 
        print >> sys.stderr, string
    if log_fd != -1 or mode == msgLog: 
        log_fd.write(string + "\n")

def printMsg(msg_idx=-1, txt="", log_fd=-1):
    """Print the message based on the message index."""

    if msg_idx in Msgs.mBeadmErr:
        printStderr(composeMsg(Msgs.mBeadmErr[msg_idx], txt),
            log_fd)
    elif msg_idx in Msgs.mBeadmOut:
        printStdout(composeMsg(Msgs.mBeadmOut[msg_idx], txt),
            log_fd)
    elif msg_idx in Msgs.mBeadmLog:
        printLog(composeMsg(Msgs.mBeadmLog[msg_idx], txt), log_fd)
    else:
        printStderr(composeMsg(Msgs.mLibbe[BEADM_ERR_MSG_SUB],
            msg_idx), -1)
        sys.exit(1)

def getMsg(msg_idx=-1, txt=""):
    """Print the message based on the message index."""

    if msg_idx in  Msgs.mBeadmErr:
        return(composeMsg(Msgs.mBeadmErr[msg_idx], txt))
    elif msg_idx in Msgs.mBeadmOut:
        return(composeMsg(Msgs.mBeadmOut[msg_idx], txt))
    elif msg_idx in Msgs.mBeadmLog:
        return(composeMsg(Msgs.mBeadmLog[msg_idx], txt))
    else:
        return(composeMsg(Msgs.mLibbe[BEADM_ERR_MSG_SUB]))
        sys.exit(1)
