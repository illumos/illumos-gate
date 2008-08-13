/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_MESSAGE_H
#define	_MESSAGE_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	CANNOT_BE_USED \
	gettext("Pattern '%s' cannot be used with device '%s:%s'\n")

#define	MUST_BE_ROOT gettext("you must be root to run this program\n")

#define	CANT_FIND_USER gettext("name service cannot find user: %s\n")

#define	CANT_FIND_GROUP gettext("name service cannot find group %s\n")

#define	NO_LINKTAB gettext("no devlink.tab rules loaded from file '%s'\n")

#define	NO_MODULES gettext("no modules loaded from MODPATH '%s'\n")

#define	ABORTING gettext("aborting\n")

#define	MODIFY_PATH gettext("use devfsadm -l to modify\n")

#define	CONFIGURING gettext("Configuring devices.\n")

#define	CHROOT_FAILED gettext("chdir to root failed: %s\n")

#define	DAEMON_RUNNING gettext("daemon pid %d is already running\n")

#define	ALIAS_TOO_LONG \
gettext("alias name is too long; must be %d characters or less: %s\n")

#define	MAJOR_AND_B_FLAG \
gettext("must specify major number and driver name when using the -b flag\n")

#define	MODCTL_ADDMAJBIND \
gettext("modctl failed to add major number binding.\n")

#define	DRIVER_FAILURE gettext("driver failed to attach: %s\n")

#define	IS_EVENTD_RUNNING gettext("check to make sure syseventd is running\n")

#define	UNKNOWN_EVENT gettext("parse_event: unknown event type: %s\n")

#define	DI_INIT_FAILED gettext("di_init failed for %s: %s\n")

#define	CLONE_NOT_FOUND gettext("di_init failed to find clone entry for %s\n")

#define	DLOPEN_FAILED gettext("dlopen failed: %s: %s\n")

#define	REGCOMP_FAILED gettext("regcomp failed for %s: error code: %d\n")

#define	IGNORING_ENTRY \
gettext("ignoring devfsadm_create entry #%d in module %s\n")

#define	CANT_CREATE_THREAD gettext("can not create thread %s: %s\n")

#define	CANT_CREATE_DOOR gettext("can not create event door %s: %s\n")

#define	FAILED_FOR_MODULE gettext("%s failed for module %s\n")

#define	REMOVING_LINK gettext("removing link %s -> %s invalid contents\n")

#define	CREATING_LINK gettext("symlink %s -> %s\n")

#define	SYMLINK_FAILED gettext("symlink failed for %s -> %s: %s\n")

#define	MAX_ATTEMPTS \
gettext("cannot create link: %s -> %s.  max attempts exceeded\n")

#define	PERM_MSG gettext("chown/chmod %s %ul/%ul/%o\n")

#define	NO_DEVFS_NODE gettext("no devfs node or mismatched dev_t for %s\n")

#define	CHMOD_FAILED gettext("chmod failed for %s: %s\n")

#define	CHOWN_FAILED gettext("chown failed for %s: %s\n")

#define	RM_INVALID_MINOR_NODE gettext("removing node %s.  invalid st_rdev\n")

#define	OPENDIR_FAILED gettext("opendir failed for %s: %s\n")

#define	READLINK_FAILED gettext("%s: readlink failed for %s: %s\n")

#define	CANT_LOAD_SYSCALL gettext("cannot load system call for inst_sync\n")

#define	SUPER_TO_SYNC \
gettext("you must be superuser to sync /etc/path_to_inst\n")

#define	INSTSYNC_FAILED gettext("inst_sync failed for %s: %s\n")

#define	RENAME_FAILED gettext("rename failed for %s: %s\n")

#define	CANT_UPDATE gettext("cannot update: %s\n")

#define	FCLOSE_FAILED gettext("fclose failed: %s: %s\n")

#define	FAILED_TO_UPDATE gettext("WARNING: failed to update %s\n")

#define	OPEN_FAILED gettext("open failed for %s: %s\n")

#define	LSEEK_FAILED gettext("lseek failed for %s: %s\n")

#define	LOCK_FAILED gettext("fcntl(F_SETLKW) failed for %s: %s\n")

#define	WRITE_FAILED gettext("write failed for %s: %s\n")

#define	UNLOCK_FAILED gettext("fcntl(F_UNLCK) failed for %s: %s\n")

#define	CLOSE_FAILED gettext("close failed for %s: %s\n")

#define	LSTAT_FAILED gettext("lstat failed for %s: %s\n")

#define	STAT_FAILED gettext("stat failed for %s: %s\n")

#define	GID_FAILED gettext("cannot determine gid for %d: %s\n")

#define	MKNOD_FAILED gettext("mknod failed for %s: %s\n")

#define	MODGETNAME_FAILED gettext("MODGETNAME failed for major number %lu\n")

#define	FIND_MAJOR_FAILED gettext("could not find major number for driver %s\n")

#define	FOPEN_FAILED gettext("fopen failed for %s: %s\n")

#define	IGNORING_LINE_IN gettext("line %d:  malformed in %s\n")

#define	MISSING_TAB \
gettext("line %d: configuration file %s has a missing tab -- ignoring\n")

#define	MISSING_DEVNAME \
gettext("line %d: configuration file %s has a missing dev name field -- \
ignoring\n")

#define	TOO_MANY_FIELDS \
gettext("line %d:  configuration file %s has too many fields -- ignoring\n")

#define	LINE_TOO_LONG \
gettext("Line %d too long in configuration file %s -- should be less \
than %d characters\n")

#define	UNRECOGNIZED_KEY \
gettext("unrecognized keyword '%s' -- ignoring line %d of file %s\n")

#define	BADKEYWORD gettext("bad keyword '%s' on line %d of file %s\n")

#define	MISSING_EQUAL \
	gettext("missing '=' in devfs_spec field line %d from file %s\n")

#define	CONFIG_INCORRECT \
gettext("line %d: configuration file %s incorrect: %s -- ignoring\n")

#define	NO_NODE gettext("no node name found for %s\n")

#define	NO_MINOR gettext("no minor name for %s\n")

#define	DRV_BUT_NO_ALIAS gettext("line %d: driver name with no alias in %s\n")

#define	MALLOC_FAILED gettext("malloc failed for %d bytes\n")

#define	REALLOC_FAILED gettext("realloc failed for %d bytes\n")

#define	CALLOC_FAILED gettext("calloc failed for %d bytes\n")

#define	STRDUP_FAILED gettext("strdup failed for %s\n")

#define	CLOSEDIR_FAILED gettext("closedir failed %s\n")

#define	MKDIR_FAILED gettext("mkdir failed for %s 0x%x: %s\n")

#define	UNLINK_FAILED gettext("unlink failed for %s: %s\n")

#define	DI_DEVFS_PATH_FAILED gettext("di_devfs_path failed: %s\n")

#define	COMPAT_LINK_USAGE gettext("Usage:\n\t\t[ -C ]\n\t\t[ \
-r root_directory ]\n\t\t[ -n ]\n\t\t[ -v ]\n")

#define	DEVLINKS_USAGE gettext("Usage:\n\t\t[ -d ]\n\t\t[ -n ]\n\t\t[ -r \
root_directory ]\n\t\t[ -t table-file ]\n\t\t[ -v ]\n")

#define	DRVCONFIG_USAGE gettext("Usage:\n\t\t[ -a alias_name ]\n\t\t[ -b ]\
\n\t\t[ -c class_name ]\n\t\t[ -d ]\n\t\t[ -i driver_name ]\n\t\t[ -m \
major_number ]\n\t\t[ -n ]\n\t\t[ -r rootdir ]\n\t\t[ -v ]\n")

#define	DEVFSADM_USAGE gettext("Usage:\n\t\t[ -c device_class ]\n\t\t[ -C ]\
\n\t\t[ -i driver_name ]\n\t\t[ -l module_path ]\n\t\t[ -n ]\
\n\t\t[ -r rootdir ]\n\t\t[ -s ]\n\t\t[ -t devlink_table_file ]\n\t\t[ -v ]\n")

#define	DEVFSADM_UNLINK gettext("removing file: %s\n")

#define	INVOKED_WITH gettext("invoked with %s\n")

#define	INVALID_DEVLINK_SPEC gettext("Invalid devlink spec: '%s'\n")

#define	DRV_LOAD_REQD gettext("-n option cannot be used with -i. Ignoring\n")

#define	DPLCY_ONE_DFLT gettext("%s: Only one default entry allowed\n")

#define	DPLCY_FIRST gettext("%s: First entry must be default entry\n")

#define	INVALID_MINOR gettext("%s: invalid minor node specification\n")

#define	MINOR_TOO_LONG gettext("%s:%s: minor node specification too long\n")

#define	UNEXPECTED_EOF gettext("%s: unexpected end of file\n")

#define	BAD_ENTRY gettext("\tin the following entry at line %d\n%s\n")

#define	NO_MEMORY gettext("Out of memory\n")


#define	EVENT_ATTR_LOOKUP_FAILED \
    gettext("failed to lookup event attributes: %s\n")

#define	PROP_ADD_FAILED \
    gettext("failed to add the property %s to event attributes\n")

#define	DEV_NAME_LOOKUP_FAILED \
    gettext("failed to lookup dev name for %s\n")

#define	BUILD_EVENT_ATTR_FAILED \
    gettext("failed to build event attributes: %s\n")

#define	LOG_EVENT_FAILED gettext("failed to log event: %s\n")

#define	ZONE_PATHCHECK \
    gettext("cannot manage root path '%s': path is part of zone '%s'\n")

#define	DEVNAME_CONTACT_FAILED \
    gettext("cannot talk to devname fs %s: %s\n")

#define	NVLIST_ERROR gettext("nvlist interface failed: %s\n")

#define	NOT_DIR gettext("file is not a directory: %s\n")

#define	NO_DEVLINK_CACHE gettext("devlink cache does not exist\n")

#ifdef	__cplusplus
}
#endif

#endif /* _MESSAGE_H */
