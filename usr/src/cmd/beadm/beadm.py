#!/usr/bin/python2.6
#
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
beadm - The Boot Environment Administration tool. Use this CLI to
manage boot environments.
"""

import getopt
import gettext
import os
import sys
import shutil
import traceback
import time
import subprocess

from beadm import _
from beadm.BootEnvironment import *
import beadm.messages as msg
import libbe_py as lb

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def usage():
    '''Defines parameters and options of the command beadm.'''
    print >> sys.stderr, _("""
Usage:
    beadm subcommand cmd_options

    subcommands:

    beadm activate beName
    beadm create [-a] [-d description]
        [-e non-activeBeName | beName@snapshot]
        [-o property=value] ... [-p zpool] beName
    beadm create beName@snapshot
    beadm destroy [-fF] beName | beName@snapshot
    beadm list [[-a] | [-d] [-s]] [-H] [beName]
    beadm mount beName mountpoint
    beadm rename beName newBeName
    beadm unmount [-f] beName""")
    sys.exit(1)


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Public Command Line functions described in beadm(1)
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def activate(opts):
    """ 
    Function:    activate

            Description: Activate a Boot Environment.The following is the
                         subcommand, options and args that make up the
                         opts object passed in:

            Parameters:
                opts - A string containing the active subcommand

            Returns:
                0 - Success
                1 - Failure
    """

    if len(opts) != 1:
        msg.printMsg(msg.Msgs.BEADM_ERR_OPT_ARGS, None, -1)
        usage()

    be = BootEnvironment()

    if lb.beVerifyBEName(opts[0]) != 0:
        msg.printMsg(msg.Msgs.BEADM_ERR_BENAME, None, -1)
        return 1

    rc = lb.beActivate(opts[0])
    if rc == 0:
        return 0

    be.msg_buf["0"] = opts[0]
    if rc == msg.Msgs.BE_ERR_BE_NOENT:
        be.msg_buf["1"] = \
            msg.getMsg(msg.Msgs.BEADM_ERR_BE_DOES_NOT_EXIST, opts[0])
    elif rc == msg.Msgs.BE_ERR_PERM or rc == msg.Msgs.BE_ERR_ACCESS:
        be.msg_buf["1"] = msg.getMsg(msg.Msgs.BEADM_ERR_PERMISSIONS, rc)
        msg.printMsg(msg.Msgs.BEADM_ERR_ACTIVATE, be.msg_buf, -1)
        return 1
    else:
        be.msg_buf["1"] = lb.beGetErrDesc(rc)
        if be.msg_buf["1"] == None:
            be.msg_buf["1"] = \
                msg.getMsg(msg.Msgs.BEADM_ERR_NO_MSG, rc)

    msg.printMsg(msg.Msgs.BEADM_ERR_ACTIVATE, be.msg_buf, -1)
    return 1


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def create(opts):
    """ 
    Function:    create

            Description: Create a Boot Environment. The following is the
                         subcommand, options and args that make up the
                         opts object passed in:

                         create [-a] [-d description]
                            [-e non-activeBeName | beName@Snapshot]
                            [-o property=value] ... [-p zpool] beName

                         create beName@Snapshot

            Parameters:
                opts - A object containing the create subcommand
                       and all the options and arguments passed in
                       on the command line mentioned above.

            Returns:
                0 - Success
                1 - Failure
    """

    be = BootEnvironment()

    activate = False

    try:
        opts_args, be.trgt_be_name_or_snapshot = getopt.getopt(opts,
            "ad:e:o:p:")
    except getopt.GetoptError:
        msg.printMsg(msg.Msgs.BEADM_ERR_OPT_ARGS, None, -1)
        usage()

    # Counters for detecting multiple options.
    # e.g. beadm create -p rpool -p rpool2 newbe
    num_a_opts = 0
    num_e_opts = 0
    num_p_opts = 0
    num_d_opts = 0

    for opt, arg in opts_args:
        if opt == "-a":
            activate = True
            num_a_opts += 1
        elif opt == "-e":
            be.src_be_name_or_snapshot = arg
            num_e_opts += 1
        elif opt == "-o":
            key, value = arg.split("=")
            be.properties[key] = value
        elif opt == "-p":
            be.trgt_rpool = arg
            num_p_opts += 1
        elif opt == "-d":
            be.description = arg
            num_d_opts += 1

    if num_a_opts > 1 or num_e_opts > 1 or num_p_opts > 1 or num_d_opts > 1:
        msg.printMsg(msg.Msgs.BEADM_ERR_OPT_ARGS, None, -1)
        usage()

    # Check that all info provided from the user is legitimate.
    if (verifyCreateOptionsArgs(be) != 0):
        usage()

    if initBELog("create", be) != 0:
        return 1

    msg.printMsg(msg.Msgs.BEADM_MSG_BE_CREATE_START,
        be.trgt_be_name_or_snapshot[0], be.log_id)

    if '@' in be.trgt_be_name_or_snapshot[0]:
        # Create a snapshot
        rc = createSnapshot(be)
    else:
        if lb.beVerifyBEName(be.trgt_be_name_or_snapshot[0]) != 0:
            msg.printMsg(msg.Msgs.BEADM_ERR_BENAME, None, -1)
            return 1

        # Create a BE based on a snapshot
        if be.src_be_name_or_snapshot is not None and \
            '@' in be.src_be_name_or_snapshot:
            # Create a BE from a snapshot
            rc = createBEFromSnapshot(be)
        else:
            rc = createBE(be)

        # Activate the BE if the user chose to.
        if activate and rc == 0:
            rc = activateBE(be)
    cleanupBELog(be)

    return rc

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def destroy(opts):
    """
    Function:    destroy

            Description: Destroy a Boot Environment. The following is the
                         subcommand, options and args that make up the
                         opts object passed in:

                         destroy [-fF] beName | beName@snapshot

            Parameters:
                opts - A object containing the destroy subcommand
                       and all the options and arguments passed in
                       on the command line mentioned above.

            Returns:
                0 - Success
                1 - Failure
    """

    force_unmount = 0
    suppress_prompt = False
    be_active_on_boot = None
    be = BootEnvironment()

    try:
        opts_args, be.trgt_be_name_or_snapshot = getopt.getopt(opts, "fF")
    except getopt.GetoptError:
        msg.printMsg(msg.Msgs.BEADM_ERR_OPT_ARGS, None, -1)
        usage()

    # Counters for detecting multiple options.
    # e.g. beadm destroy -f -f newbe
    num_f_opts = 0
    num_sf_opts = 0

    for opt, arg in opts_args:
        if opt == "-f":
            force_unmount = 1
            num_sf_opts += 1
        elif opt == "-F":
            suppress_prompt = True
            num_f_opts += 1

    if num_sf_opts > 1 or num_f_opts > 1:
        msg.printMsg(msg.Msgs.BEADM_ERR_OPT_ARGS, None, -1)
        usage()

    if len(be.trgt_be_name_or_snapshot) != 1:
        msg.printMsg(msg.Msgs.BEADM_ERR_OPT_ARGS, None, -1)
        usage()

    is_snapshot = False

    if "@" in be.trgt_be_name_or_snapshot[0]:
        is_snapshot = True
        be_name, snap_name = be.trgt_be_name_or_snapshot[0].split("@")
        if lb.beVerifyBEName(be_name) != 0:
            msg.printMsg(msg.Msgs.BEADM_ERR_BENAME, None, -1)
            return 1
    else:
        if lb.beVerifyBEName(be.trgt_be_name_or_snapshot[0]) != 0:
            msg.printMsg(msg.Msgs.BEADM_ERR_BENAME, None, -1)
            return 1

    # Get the 'active' BE and the 'active on boot' BE.
    be_active, be_active_on_boot = getActiveBEAndActiveOnBootBE()

    # If the user is trying to destroy the 'active' BE then quit now.
    if not is_snapshot and be_active == be.trgt_be_name_or_snapshot[0]:
        be.msg_buf["0"] = be.msg_buf["1"] = be_active
        msg.printMsg(msg.Msgs.BEADM_ERR_DESTROY_ACTIVE, be.msg_buf, -1)
        return 1

    if not suppress_prompt:

        # Display a destruction question and wait for user response.
        # Quit if negative user response.

        if not displayDestructionQuestion(be):
            return 0

    if is_snapshot:

        # Destroy a snapshot.
        rc = lb.beDestroySnapshot(be_name, snap_name)
    else:

        # Destroy a BE.  Passing in 1 for the second arg destroys
        # any snapshots the BE may have as well.

        rc = lb.beDestroy(be.trgt_be_name_or_snapshot[0], 1, force_unmount)

        # Check if the BE that was just destroyed was the
        # 'active on boot' BE. If it was, display a message letting
        # the user know that the 'active' BE is now also the
        # 'active on boot' BE.
        if be_active_on_boot == be.trgt_be_name_or_snapshot[0] and rc == 0:
            msg.printMsg(msg.Msgs.BEADM_MSG_ACTIVE_ON_BOOT,
            be_active, -1)

    if rc == 0:
        try:
            shutil.rmtree("/var/log/beadm/" + \
                          be.trgt_be_name_or_snapshot[0], True)
        except:
            msg.printMsg(msg.Msgs.BEADM_ERR_LOG_RM,
                         "/var/log/beadm/" + be.trgt_be_name_or_snapshot[0], -1)

        return 0

    be.msg_buf["0"] = be.trgt_be_name_or_snapshot[0]
    if rc == msg.Msgs.BE_ERR_MOUNTED:
        be.msg_buf["1"] = be.msg_buf["2"] = be.trgt_be_name_or_snapshot[0]
        msg.printMsg(msg.Msgs.BEADM_ERR_MOUNTED, be.msg_buf, -1)
        return 1
    elif rc == msg.Msgs.BE_ERR_DESTROY_CURR_BE:
        msg.printMsg(msg.Msgs.BEADM_ERR_DESTROY_ACTIVE, \
        be.msg_buf["0"], -1)
        return 1
    elif rc == msg.Msgs.BE_ERR_ZONES_UNMOUNT:
        be.msg_buf["1"] = be.trgt_be_name_or_snapshot[0]
        msg.printMsg(msg.Msgs.BE_ERR_ZONES_UNMOUNT, be.msg_buf, -1)
        return 1
    elif rc == msg.Msgs.BE_ERR_PERM or rc == msg.Msgs.BE_ERR_ACCESS:
        be.msg_buf["1"] = msg.getMsg(msg.Msgs.BEADM_ERR_PERMISSIONS, rc)
        msg.printMsg(msg.Msgs.BEADM_ERR_DESTROY, be.msg_buf, -1)
        return 1
    else:
        be.msg_buf["1"] = lb.beGetErrDesc(rc)
        if be.msg_buf["1"] == None:
            be.msg_buf["1"] = \
                msg.getMsg(msg.Msgs.BEADM_ERR_NO_MSG, rc)

    msg.printMsg(msg.Msgs.BEADM_ERR_DESTROY, be.msg_buf, -1)
    return 1

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def list(opts):
    """ 
            Description: List the attributes of a Boot Environment.
                         The following is the subcommand, options
                         and args that make up the opts object
                         passed in:

                         list [[-a] | [-d] [-s]] [-H] [beName]

                         -a displays all info
                         -d displays BE info plus dataset info
                         -s displays BE info plus snapshot info
                         -H displays info parsable by a computer

            Parameters:
                opts - A object containing the list subcommand
                       and all the options and arguments passed in
                       on the command line mentioned above.

            Returns:
                0 - Success
                1 - Failure
    """

    be = BootEnvironment()

    list_all_attrs = ""
    list_datasets = ""
    list_snapshots = ""
    dont_display_headers = False
    be_name = None
    be_list = None

    # Counters for detecting multiple options.
    # e.g. beadm list -a -a newbe
    num_a_opts = 0
    num_d_opts = 0
    num_s_opts = 0
    num_h_opts = 0

    try:
        opts_args, be.trgt_be_name_or_snapshot = getopt.getopt(opts, "adHs")
    except getopt.GetoptError:
        msg.printMsg(msg.Msgs.BEADM_ERR_OPT_ARGS, None, -1)
        usage()

    for opt, arg in opts_args:
        if opt == "-a":
            list_all_attrs = opt
            num_a_opts += 1
        elif opt == "-d":
            list_datasets = opt
            num_d_opts += 1
        elif opt == "-s":
            list_snapshots = opt
            num_s_opts += 1
        elif opt == "-H":
            dont_display_headers = True
            num_h_opts += 1

    if num_a_opts > 1 or num_d_opts > 1 or num_s_opts > 1 or num_h_opts > 1:
        msg.printMsg(msg.Msgs.BEADM_ERR_OPT_ARGS, None, -1)
        usage()

    if len(be.trgt_be_name_or_snapshot) > 1:
        msg.printMsg(msg.Msgs.BEADM_ERR_OPT_ARGS, None, -1)
        usage()

    if len(be.trgt_be_name_or_snapshot) == 1:
        be_name = be.trgt_be_name_or_snapshot[0]
        if lb.beVerifyBEName(be_name) != 0:
            msg.printMsg(msg.Msgs.BEADM_ERR_BENAME, None, -1)
            return 1

    if (list_all_attrs == "-a" and (list_datasets == "-d" \
        or list_snapshots == "-s")):
        msg.printMsg(msg.Msgs.BEADM_ERR_MUTUALLY_EXCL,
            list_all_attrs + " " + list_datasets + " " +
            list_snapshots, -1)
        usage()

    list_options = ""

    # When zones are implemented add "listZones == "-z" below

    # Coelesce options to pass to displayBEs

    if (list_datasets == "-d" and list_snapshots == "-s" or \
        list_all_attrs == "-a"):
        list_options = "-a"
    elif list_datasets != "" or list_snapshots != "" or list_all_attrs != "":
        list_options = list_datasets + " " + list_snapshots

    rc, be_list = lb.beList()
    if rc != 0:
        if rc == msg.Msgs.BE_ERR_BE_NOENT:
            if be_name == None:
                msg.printMsg(msg.Msgs.BEADM_ERR_NO_BES_EXIST,
                None, -1)
                return 1

            string = \
                msg.getMsg(msg.Msgs.BEADM_ERR_BE_DOES_NOT_EXIST,
                be_name)
        else:
            string = lb.beGetErrDesc(rc)
            if string == None:
                string = \
                    msg.getMsg(msg.Msgs.BEADM_ERR_NO_MSG, rc)

        msg.printMsg(msg.Msgs.BEADM_ERR_LIST, string, -1)
        return 1

    # classify according to command line options
    if list_options.find("-a") != -1 or \
        (list_options.find("-d") != -1 and list_options.find("-s") != -1):
        list_object = CompleteList(dont_display_headers) #all
    elif list_options.find("-d") != -1:
        list_object = DatasetList(dont_display_headers) #dataset
    elif list_options.find("-s") != -1:
        list_object = SnapshotList(dont_display_headers) #snapshot
    else: list_object = BEList(dont_display_headers) #only BE

    # use list method for object
    if list_object.list(be_list, dont_display_headers, be_name) != 0:
        msg.printMsg(msg.Msgs.BEADM_ERR_LIST_DATA, None, -1)
        return 1

    return 0

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def mount(opts):
    """
            Description: Mount a Boot Environment on a directory.
                         The following is the subcommand, options
                         and args that make up the opts object
                         passed in:

                         mount beName [mountpoint]

            Parameters:
                opts - A object containing the mount subcommand
                       and all the options and arguments passed in
                       on the command line mentioned above.

            Returns:
                0 - Success
                1 - Failure
    """

    be = BootEnvironment()

    mountpoint = None

    try:
        be_name_mnt_point = getopt.getopt(opts, "")[1]
    except getopt.GetoptError:
        msg.printMsg(msg.Msgs.BEADM_ERR_OPT_ARGS, None, -1)
        usage()

    mnt_point_len = len(be_name_mnt_point)

    if mnt_point_len != 2:
        msg.printMsg(msg.Msgs.BEADM_ERR_OPT_ARGS, None, -1)
        usage()
    else:
        # Check for leading / in mount point
        mountpoint = be_name_mnt_point[1]
        if not mountpoint.startswith('/'):
            msg.printMsg(msg.Msgs.BEADM_ERR_MOUNTPOINT,
                mountpoint, -1)
            return 1

    if lb.beVerifyBEName(be_name_mnt_point[0]) != 0:
        msg.printMsg(msg.Msgs.BEADM_ERR_BENAME, None, -1)
        return 1

    rc = lb.beMount(be_name_mnt_point[0], mountpoint)
    if rc == 0:
        return 0

    be.msg_buf["0"] = be_name_mnt_point[0]
    if rc == msg.Msgs.BE_ERR_MOUNTED:
        be.msg_buf["1"] = \
            msg.getMsg(msg.Msgs.BEADM_ERR_MOUNT_EXISTS,
            be_name_mnt_point[0])
    elif rc == msg.Msgs.BE_ERR_BE_NOENT:
        be.msg_buf["1"] = \
            msg.getMsg(msg.Msgs.BEADM_ERR_BE_DOES_NOT_EXIST,
            be_name_mnt_point[0])
    elif rc == msg.Msgs.BE_ERR_PERM or rc == msg.Msgs.BE_ERR_ACCESS:
        be.msg_buf["1"] = msg.getMsg(msg.Msgs.BEADM_ERR_PERMISSIONS, rc)
        msg.printMsg(msg.Msgs.BEADM_ERR_MOUNT, be.msg_buf, -1)
        return 1
    else:
        be.msg_buf["1"] = lb.beGetErrDesc(rc)
        if be.msg_buf["1"] == None:
            be.msg_buf["1"] = \
                msg.getMsg(msg.Msgs.BEADM_ERR_NO_MSG, rc)

    msg.printMsg(msg.Msgs.BEADM_ERR_MOUNT, be.msg_buf, -1)
    return 1

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def unmount(opts):
    """
            Description: Unmount a Boot Environment.
                         The following is the subcommand, options
                         and args that make up the opts object
                         passed in:

                         unmount [-f] beName

            Parameters:
                opts - A object containing the unmount subcommand
                       and all the options and arguments passed in
                       on the command line mentioned above.

            Returns:
                0 - Success
                1 - Failure
    """

    be = BootEnvironment()

    force_unmount = 0

    # Counter for detecting multiple options.
    # e.g. beadm unmount -f -f newbe
    num_f_opts = 0

    try:
        optlist, args = getopt.getopt(opts, "f")
    except getopt.GetoptError:
        msg.printMsg(msg.Msgs.BEADM_ERR_OPT_ARGS, None, -1)
        usage()

    for opt, arg in optlist:
        if opt == "-f":
            force_unmount = 1
            num_f_opts += 1

    if num_f_opts > 1:
        msg.printMsg(msg.Msgs.BEADM_ERR_OPT_ARGS, None, -1)
        usage()

    if len(args) != 1:
        msg.printMsg(msg.Msgs.BEADM_ERR_OPT_ARGS, None, -1)
        usage()

    if lb.beVerifyBEName(args[0]) != 0:
        msg.printMsg(msg.Msgs.BEADM_ERR_BENAME, None, -1)
        return 1

    rc = lb.beUnmount(args[0], force_unmount)
    if rc == 0:
        return 0

    be.msg_buf["0"] = args[0]
    if rc == msg.Msgs.BE_ERR_UMOUNT_CURR_BE:
        be.msg_buf["1"] = \
            msg.getMsg(msg.Msgs.BEADM_ERR_UNMOUNT_ACTIVE,
            args[0])
    elif rc == msg.Msgs.BE_ERR_UMOUNT_SHARED:
        be.msg_buf["1"] = \
            msg.getMsg(msg.Msgs.BEADM_ERR_SHARED_FS, args[0])
    elif rc == msg.Msgs.BE_ERR_PERM or rc == msg.Msgs.BE_ERR_ACCESS:
        be.msg_buf["1"] = msg.getMsg(msg.Msgs.BEADM_ERR_PERMISSIONS, rc)
        msg.printMsg(msg.Msgs.BEADM_ERR_UNMOUNT, be.msg_buf, -1)
        return 1
    else:
        be.msg_buf["1"] = lb.beGetErrDesc(rc)
        if be.msg_buf["1"] == None:
            be.msg_buf["1"] = \
                msg.getMsg(msg.Msgs.BEADM_ERR_NO_MSG, rc)

    msg.printMsg(msg.Msgs.BEADM_ERR_UNMOUNT, be.msg_buf, -1)
    return 1

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def rename(opts):
    """
            Description: Rename the name of a Boot Environment.
                         The following is the subcommand, options
                         and args that make up the opts object
                         passed in:

                         rename beName newBeName

            Parameters:
                opts - A object containing the mount subcommand
                       and all the options and arguments passed in
                       on the command line mentioned above.

            Returns:
                0 - Success
                1 - Failure
    """

    be = BootEnvironment()

    try:
        be_names = getopt.getopt(opts, "")[1]
    except getopt.GetoptError:
        msg.printMsg(msg.Msgs.BEADM_ERR_OPT_ARGS, None, -1)
        usage()

    if len(be_names) != 2:
        msg.printMsg(msg.Msgs.BEADM_ERR_OPT_ARGS, None, -1)
        usage()

    if lb.beVerifyBEName(be_names[0]) != 0:
        msg.printMsg(msg.Msgs.BEADM_ERR_BENAME, None, -1)
        return 1

    if lb.beVerifyBEName(be_names[1]) != 0:
        msg.printMsg(msg.Msgs.BEADM_ERR_BENAME, None, -1)
        return 1

    rc = lb.beRename(be_names[0], be_names[1])

    if rc == 0:
        return 0

    be.msg_buf["0"] = be_names[0]
    if rc == msg.Msgs.BE_ERR_BE_NOENT:
        be.msg_buf["1"] = \
            msg.getMsg(msg.Msgs.BEADM_ERR_BE_DOES_NOT_EXIST,
            be_names[0])
    elif rc == msg.Msgs.BE_ERR_PERM or rc == msg.Msgs.BE_ERR_ACCESS:
        be.msg_buf["1"] = msg.getMsg(msg.Msgs.BEADM_ERR_PERMISSIONS, rc)
        msg.printMsg(msg.Msgs.BEADM_ERR_RENAME, be.msg_buf, -1)
        return 1
    else:
        be.msg_buf["1"] = lb.beGetErrDesc(rc)
        if be.msg_buf["1"] == None:
            be.msg_buf["1"] = \
                msg.getMsg(msg.Msgs.BEADM_ERR_NO_MSG, rc)

    msg.printMsg(msg.Msgs.BEADM_ERR_RENAME, be.msg_buf, -1)
    return 1

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# End of CLI public functions
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Verify the options and arguments for the beadm create subcommand

def verifyCreateOptionsArgs(be):
    """Check valid BE names."""

    len_be_args = len(be.trgt_be_name_or_snapshot)
    if len_be_args < 1:
        msg.printMsg(msg.Msgs.BEADM_ERR_OPT_ARGS, None, -1)
        return 1
    if len_be_args > 1:
        msg.printMsg(msg.Msgs.BEADM_ERR_OPT_ARGS, None, -1)
        idx = 0
        while len_be_args > idx:
            msg.printMsg(msg.Msgs.BEADM_MSG_FREE_FORMAT,
                be.trgt_be_name_or_snapshot[idx], -1)
            idx += 1
        return 1

    return 0

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def parseCLI(cli_opts_args):
    """Parse command line interface arguments."""

    gettext.install("beadm", "/usr/lib/locale")

    if len(cli_opts_args) == 0:
        usage()

    subcommand = cli_opts_args[0]
    opts_args = cli_opts_args[1:]

    if subcommand == "activate":
        rc = activate(opts_args)
    elif subcommand == "create":
        rc = create(opts_args)
    elif subcommand == "destroy":
        rc = destroy(opts_args)
    elif subcommand == "list":
        rc = list(opts_args)
    elif subcommand == "mount":
        rc = mount(opts_args)
    elif subcommand == "rename":
        rc = rename(opts_args)
    elif subcommand == "upgrade":
        rc = upgrade(opts_args)
    elif subcommand == "unmount" or \
        subcommand == "umount": #aliased for convenience
        rc = unmount(opts_args)
    elif subcommand == "verify":
        rc = verify()
    else:
        msg.printMsg(msg.Msgs.BEADM_ERR_ILL_SUBCOMMAND,
            subcommand, -1)
        usage()

    return(rc)

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def main():
    """main function."""

    gettext.install("beadm", "/usr/lib/locale")

    if not isBeadmSupported():
        return(1)

    return(parseCLI(sys.argv[1:]))

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def initBELog(log_id, be):
    """
    Initiate the BE log

    Format of the log
    yyyymmdd_hhmmss - 20071130_140558
    yy - year;   2007
    mm - month;  11
    dd - day;    30
    hh - hour;   14
    mm - minute; 05
    ss - second; 58
    """

    # /var/log/beadm/<beName>/<logId>.log.<yyyymmdd_hhmmss>

    date = time.strftime("%Y%m%d_%H%M%S", time.localtime())

    be.log = "/var/log/beadm/" + be.trgt_be_name_or_snapshot[0] + \
        "/" + log_id + ".log" + "." + date

    if not os.path.isfile(be.log) and not os.path.islink(be.log):
        if not os.path.isdir(os.path.dirname(be.log)):
            try:
                os.makedirs(os.path.dirname(be.log), 0644)
            except OSError:
                be.msg_buf["0"] = be.trgt_be_name_or_snapshot[0]
                be.msg_buf["1"] = \
                    msg.getMsg(msg.Msgs.BEADM_ERR_PERMISSIONS,
                    0)
                msg.printMsg(msg.Msgs.BEADM_ERR_CREATE,
                    be.msg_buf, -1)
                return 1
        try:
            be.log_id = open(be.log, "a")
        except IOError:
            msg.printMsg(msg.Msgs.BEADM_ERR_LOG_CREATE,
                None, -1)
            return 1
    else:
        # Should never happen due to new time stamp each call
        msg.printMsg(msg.Msgs.BEADM_ERR_LOG_CREATE, None, -1)
        return 1

    return 0

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def cleanupBELog(be):
    """Clean up BE log."""

    be.log_id.close()

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def displayDestructionQuestion(be):
    """Display a destruction question and wait for user response."""

    msg.printMsg(msg.Msgs.BEADM_MSG_DESTROY, be.trgt_be_name_or_snapshot[0], -1)
    while True:
        try:
            value = raw_input().strip().upper()
        except KeyboardInterrupt:
            return False
        if (value == 'Y' or value == 'YES'):
            return True
        elif len(value) == 0 or value == 'N' or value == 'NO':
            msg.printMsg(msg.Msgs.BEADM_MSG_DESTROY_NO,
                be.trgt_be_name_or_snapshot[0], -1)
            return False
        else:
            msg.printMsg(msg.Msgs.BEADM_ERR_INVALID_RESPONSE,
                -1)

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def setMaxColumnWidths(be_max_w, ds_max_w, ss_max_w, be_list):
    """Figure out max column widths for BE's, Datasets and Snapshots."""

    for be_item in be_list:
        if be_item.get("orig_be_name") is not None:
            determineMaxBEColWidth(be_item, be_max_w)
        if be_item.get("dataset") is not None:
            determineMaxDSColWidth(be_item, ds_max_w)
        if be_item.get("snap_name") is not None:
            determineMaxSSColWidth(be_item, ss_max_w)

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def getActiveBEAndActiveOnBootBE():
    """Return the 'active on boot' BE, the 'active' BE or None."""

    active_be = None
    active_be_on_boot = None

    rc, be_list = lb.beList()

    if rc != 0:
        if rc == msg.Msgs.BE_ERR_BE_NOENT:
            string = \
                msg.getMsg(msg.Msgs.BEADM_ERR_NO_BES_EXIST)
        else:
            string = lb.beGetErrDesc(rc)
            if string == None:
                string = \
                    msg.getMsg(msg.Msgs.BEADM_ERR_NO_MSG, rc)

        msg.printMsg(msg.Msgs.BEADM_ERR_LIST, string, -1)
        return None

    for be_vals in be_list:
        srcBeName = be_vals.get("orig_be_name")
        if be_vals.get("active"):
            active_be = srcBeName
        if be_vals.get("active_boot"):
            active_be_on_boot = srcBeName
        if active_be is not None and active_be_on_boot is not None:
            break

    return active_be, active_be_on_boot

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def createSnapshot(be):
    """Create a snapshot."""

    be_name, snap_name = be.trgt_be_name_or_snapshot[0].split("@")

    rc = lb.beCreateSnapshot(be_name, snap_name)[0]

    if rc == 0:
        return 0

    be.msg_buf["0"] = be.trgt_be_name_or_snapshot[0]
    if rc == msg.Msgs.BE_ERR_BE_NOENT:
        be.msg_buf["1"] = \
            msg.getMsg(msg.Msgs.BEADM_ERR_BE_DOES_NOT_EXIST,
            be_name)
    elif rc == msg.Msgs.BE_ERR_SS_EXISTS:
        be.msg_buf["1"] = msg.getMsg(msg.Msgs.BEADM_ERR_SNAP_EXISTS,
            be.trgt_be_name_or_snapshot[0])
    elif rc == msg.Msgs.BE_ERR_PERM or rc == msg.Msgs.BE_ERR_ACCESS:
        be.msg_buf["1"] = msg.getMsg(msg.Msgs.BEADM_ERR_PERMISSIONS, rc)
        msg.printMsg(msg.Msgs.BEADM_ERR_CREATE, be.msg_buf, -1)
        return 1
    else:
        be.msg_buf["1"] = lb.beGetErrDesc(rc)
        if be.msg_buf["1"] == None:
            be.msg_buf["1"] = \
                msg.getMsg(msg.Msgs.BEADM_ERR_NO_MSG, rc)

    msg.printMsg(msg.Msgs.BEADM_ERR_CREATE, be.msg_buf, -1)

    return 1

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def createBE(be):
    """Create a Boot Environment."""

    rc = lb.beCopy(be.trgt_be_name_or_snapshot[0], be.src_be_name_or_snapshot,
            None, be.trgt_rpool, be.properties, be.description)[0]
    
    if rc == 0:
        msg.printMsg(msg.Msgs.BEADM_MSG_BE_CREATE_SUCCESS,
            be.trgt_be_name_or_snapshot[0], be.log_id)
        return 0

    be.msg_buf["0"] = be.trgt_be_name_or_snapshot[0]
    if rc == msg.Msgs.BE_ERR_BE_NOENT:
        be.msg_buf["1"] = \
            msg.getMsg(msg.Msgs.BEADM_ERR_BE_DOES_NOT_EXIST,
            be.src_be_name_or_snapshot)
    elif rc == msg.Msgs.BE_ERR_BE_EXISTS:
        be.msg_buf["1"] = msg.getMsg(msg.Msgs.BEADM_ERR_BE_EXISTS,
            be.trgt_be_name_or_snapshot[0])
    elif rc == msg.Msgs.BE_ERR_PERM or rc == msg.Msgs.BE_ERR_ACCESS:
        be.msg_buf["1"] = msg.getMsg(msg.Msgs.BEADM_ERR_PERMISSIONS, rc)
        msg.printMsg(msg.Msgs.BEADM_ERR_CREATE, be.msg_buf, -1)
        return 1
    else:
        be.msg_buf["1"] = lb.beGetErrDesc(rc)
        if be.msg_buf["1"] == None:
            be.msg_buf["1"] = \
                msg.getMsg(msg.Msgs.BEADM_ERR_NO_MSG, rc)

    msg.printMsg(msg.Msgs.BEADM_ERR_CREATE, be.msg_buf, be.log_id)

    return 1

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def createBEFromSnapshot(be):
    """Create a BE based off a snapshot."""

    be_name, snap_name = be.src_be_name_or_snapshot.split("@")

    rc = lb.beCopy(be.trgt_be_name_or_snapshot[0], be_name, snap_name, 
        be.trgt_rpool, be.properties, be.description)[0]

    if rc == 0:
        msg.printMsg(msg.Msgs.BEADM_MSG_BE_CREATE_SUCCESS,
            be.trgt_be_name_or_snapshot[0], be.log_id)
        return 0

    be.msg_buf["0"] = be.trgt_be_name_or_snapshot[0]
    if rc == msg.Msgs.BE_ERR_SS_NOENT:
        be.msg_buf["1"] = \
            msg.getMsg(msg.Msgs.BEADM_ERR_SNAP_DOES_NOT_EXISTS,
            be.src_be_name_or_snapshot)
    elif rc == msg.Msgs.BE_ERR_BE_EXISTS:
        be.msg_buf["1"] = msg.getMsg(msg.Msgs.BEADM_ERR_BE_EXISTS, \
            be.trgt_be_name_or_snapshot[0])
    elif rc == msg.Msgs.BE_ERR_BE_NOENT:
        be.msg_buf["1"] = \
            msg.getMsg(msg.Msgs.BEADM_ERR_BE_DOES_NOT_EXIST, \
            be_name)
    elif rc == msg.Msgs.BE_ERR_PERM or rc == msg.Msgs.BE_ERR_ACCESS:
        be.msg_buf["1"] = msg.getMsg(msg.Msgs.BEADM_ERR_PERMISSIONS, rc)
        msg.printMsg(msg.Msgs.BEADM_ERR_CREATE, be.msg_buf, -1)
        return 1
    else:
        be.msg_buf["1"] = lb.beGetErrDesc(rc)
        if be.msg_buf["1"] == None:
            be.msg_buf["1"] = \
                msg.getMsg(msg.Msgs.BEADM_ERR_NO_MSG, rc)

    msg.printMsg(msg.Msgs.BEADM_ERR_CREATE, be.msg_buf, be.log_id)

    return 1

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def activateBE(be):
    """
    Activate a BE. Called from create() when -a is provided as CLI
    Option.
    """

    rc = lb.beActivate(be.trgt_be_name_or_snapshot[0])
    if rc == 0:
        return 0

    be.msg_buf["0"] = be.trgt_be_name_or_snapshot[0]
    if rc == msg.Msgs.BE_ERR_BE_NOENT:
        be.msg_buf["1"] = \
            msg.getMsg(msg.Msgs.BEADM_ERR_BE_DOES_NOT_EXIST, opts[0])
    else:
        be.msg_buf["1"] = lb.beGetErrDesc(rc)
        if be.msg_buf["1"] == None:
            be.msg_buf["1"] = \
                msg.getMsg(msg.Msgs.BEADM_ERR_NO_MSG, rc)

    msg.printMsg(msg.Msgs.BEADM_ERR_ACTIVATE, be.msg_buf, -1)

    return 1

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def isBeadmSupported():
    """
    Currently the only environment that beadm is supported in is
    a global zone. Check that beadm is executing in a
    global zone and not in a non-global zone.
    """

    try:
        proc = subprocess.Popen("/sbin/zonename",
            stdout = subprocess.PIPE,
            stderr = subprocess.STDOUT)
        # Grab stdout.
        zonename = proc.communicate()[0].rstrip('\n')
    except OSError, (errno, strerror):
        msg.printMsg(msg.Msgs.BEADM_ERR_OS, strerror, -1)
        # Ignore a failed attempt to retreive the zonename.
        return True

    if zonename != "global":
        msg.printMsg(msg.Msgs.BEADM_ERR_NOT_SUPPORTED_NGZ, None, -1)
        return False

    return True


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
if __name__ == "__main__":
    try:
        RC = main()
    except SystemExit, e:
        raise e
    except:
        traceback.print_exc()
        sys.exit(99)
    sys.exit(RC)
