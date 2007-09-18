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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_MESSAGE_H
#define	_MESSAGE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <libintl.h>

#define	FILE_MISS gettext("file not found: %s\n")

#define	ARCH_EXEC_MISS gettext("archive creation file not found: %s: %s\n")

#define	DIR_MISS gettext("directory not found: %s\n")

#define	MUST_BE_ROOT gettext("you must be root to run this command\n")

#define	NOT_GRUB_BOOT gettext("%s: not a GRUB boot OS instance\n")

#define	MULT_CMDS gettext("multiple commands specified: -%c\n")

#define	INVALID_SUBCMD gettext("invalid sub-command specified: %s\n")

#define	NEED_SUBCMD gettext("this command requires a sub-command\n")

#define	NEED_CMD gettext("a command option must be specified\n")

#define	CMD_ERR gettext("command failed with errors: %s\n")

#define	DUP_OPT gettext("duplicate options specified: -%c\n")

#define	BAD_OPT gettext("invalid option or missing option argument: -%c\n")

#define	NO_ARG gettext("missing or too many command argument(s)\n")

#define	NO_OPT_REQ gettext("this sub-command (%s) does not take options\n")

#define	MISS_OPT gettext("an option is required for this sub-command: %s\n")

#define	ABS_PATH_REQ gettext("path is not absolute: %s\n")

#define	TOO_LONG gettext("the following line is too long (> %d chars)\n\t%s\n")

#define	NOT_ON_SPARC gettext("this operation is not supported on sparc\n")

#define	NEED_ALT_ROOT gettext("an alternate root must be specified\n")

#define	ALT_ROOT_INVALID \
    gettext("an alternate root (%s) cannot be used with this sub-command\n")

#define	NO_FILE_ENTRY gettext("file not in list: %s\n")

#define	DUP_FILE_ENTRY gettext("file already in list: %s\n")

#define	NO_ENTRY gettext("no %s entry found\n")

#define	NO_MATCH_ENTRY gettext("no matching entry found\n")

#define	NO_BOOTADM_MATCH gettext("no matching bootadm entry found\n")

#define	NO_MEM gettext("could not allocate memory: size = %u\n")

#define	CANNOT_LOCATE_GRUB_MENU gettext("cannot find GRUB menu\n")

#define	GRUB_MENU_DEVICE \
	gettext("The location for the active GRUB menu is: %s (not mounted)\n")

#define	GRUB_MENU_FSTYPE \
    gettext("The filesystem type of the menu device is <%s>\n")

#define	GRUB_MENU_PATH gettext("The location for the active GRUB menu is: %s\n")

#define	STUBBOOT_DIR_NOT_FOUND gettext("cannot find stubboot directory\n")

#define	NO_CMD gettext("no command at line %d\n")

#define	DUP_CMD \
    gettext("duplicate command %s at line %d of %sboot/grub/menu.lst\n")

#define	INVALID_TIMEOUT gettext("invalid timeout value: %s\n")

#define	NO_MENU gettext("menu file not found: %s\n")

#define	LIST_TITLE gettext("%d %s\n")

#define	GLOBAL_CMD gettext("%s %s\n")

#define	REGCOMP_FAIL gettext("regular expression failed to compile\n")

#define	INVALID_ENTRY gettext("invalid boot entry number: %s\n")

#define	DUP_ENTRY gettext("a boot entry with this title already exists: %s\n")

#define	LIST_ENTRY gettext("%s\n")

#define	SUBOPT_VALUE gettext("suboption %s requires a value\n")

#define	INVALID_SUBOPT gettext("invalid suboption: %s\n")

#define	SUBOPT_MISS gettext("missing suboption: %s\n")

#define	INVALID_HDR gettext("invalid entry header: %s\n")

#define	INVALID_TITLE gettext("invalid title entry: %s\n")

#define	INVALID_ROOT gettext("invalid root entry: %s\n")

#define	NO_KERNEL gettext("No kernel line found in entry %d\n")

#define	INVALID_KERNEL gettext("invalid kernel entry: %s\n")

#define	INVALID_MODULE gettext("invalid module entry: %s\n")

#define	INVALID_FOOTER gettext("invalid entry footer: %s\n")

#define	EMPTY_FILE gettext("file is missing or empty: %s\n")

#define	UNLINK_EMPTY gettext("file is empty, deleting file: %s\n")

#define	UNLINK_FAIL gettext("failed to unlink file: %s: %s\n")

#define	NOT_CHR gettext("not a character device: %s\n")

#define	NO_DIR gettext("directory not found: %s\n")

#define	NOT_DIR gettext("not a directory: %s\n")

#define	NO_MATCH gettext("no matching entry found: %s\n")

#define	INVALID_OPT gettext("invalid option: %s\n")

#define	FAILED_SIG gettext("Cannot set SIGCHLD disposition: %s\n")

#define	CANT_UNBLOCK_SIGCHLD gettext("Cannot unblock SIGCHLD: %s\n")

#define	BLOCKED_SIG gettext("SIGCHLD signal blocked. Cannot exec: %s\n")

#define	POPEN_FAIL gettext("popen failed: %s\n")

#define	PCLOSE_FAIL gettext("pclose failed: %s\n")

#define	EXEC_FAIL gettext("command terminated abnormally: %s: %d\n")

#define	INVALID_ARCH_FS \
	gettext("invalid or unsupported archive filesystem: %s\n")

#define	NEED_FORCE \
	gettext("This operation is only supported with the force flag (-f)\n")

#define	REL_PATH_REQ \
	gettext("path (%s) must be relative to root. For example: etc/foo\n")

#define	OPEN_FAIL gettext("failed to open file: %s: %s\n")

#define	LOCK_FAIL gettext("failed to lock file: %s: %s\n")

#define	UNLOCK_FAIL gettext("failed to unlock file: %s: %s\n")

#define	MMAP_FAIL gettext("failed to mmap file: %s: %s\n")

#define	FILE_LOCKED gettext("Another instance of bootadm (pid %u) is running\n")

#define	FLIST_FAIL \
	gettext("failed to open archive filelist: %s: %s\n")

#define	NO_FLIST gettext("archive filelist is empty\n")

#define	CLOSE_FAIL gettext("failed to close file: %s: %s\n")

#define	RENAME_FAIL gettext("rename to file failed: %s: %s\n")

#define	NOT_IN_MNTTAB gettext("alternate root %s not in mnttab\n")

#define	CANT_RESOLVE gettext("cannot resolve path %s: %s\n")

#define	ROOT_ABS gettext("this sub-command doesn't take root arguments: %s\n")

#define	RDONLY_FS gettext("read-only filesystem: %s\n")

#define	ARCHIVE_FAIL gettext("Command '%s' failed to create boot archive\n")

#define	ARCHIVE_NOT_CREATED gettext("couldn't create boot archive: %s\n")

#define	WRITE_FAIL gettext("write to file failed: %s: %s\n")

#define	STAT_FAIL gettext("stat of file failed: %s: %s\n")

#define	PACK_FAIL gettext("failed to pack stat data: %s\n")

#define	NVALLOC_FAIL gettext("failed to create stat data: %s\n")

#define	NVADD_FAIL gettext("failed to update stat data for: %s: %s\n")

#define	NOT_NV gettext("option is not a name=value pair: %s\n")

#define	DISKMAP_FAIL gettext("cannot map disk %s to grub name\n")

#define	DISKMAP_FAIL_NONFATAL \
    gettext("cannot map disk %s to grub name, assume disk 0.\n")

#define	WARN_BOOT \
gettext("WARNING: Incorrect use of this command may make \
the system unbootable\n")

#define	WARN_FAILSAFE_BOOT \
gettext("WARNING: Incorrect use of this command may make \
the failsafe archive unbootable\n")

#define	UPDATE_NO_STAT \
	gettext("%s state file %s not found.\n")

#define	CHECK_NOT_SUPPORTED \
	gettext("the check option is not supported with subcmd: %s\n")

#define	PARSEABLE_NEW_FILE	gettext("    new     %s\n")

#define	PARSEABLE_OUT_DATE	gettext("    changed %s\n")

#define	PARSEABLE_STALE_FILE	gettext("    stale %s\n")

#define	UPDATE_FORCE gettext("forced update of archive requested\n")

#define	NO_NEW_STAT gettext("cannot create new stat data\n")

#define	UPDATE_ARCH_MISS gettext("archive not found: %s\n")

#define	READ_FAIL gettext("read failed for file: %s: %s\n")

#define	UNPACK_FAIL gettext("failed to unpack stat data: %s: %s\n")

#define	NFTW_FAIL gettext("cannot find: %s: %s\n")

#define	NVL_ALLOC_FAIL gettext("failed to alloc nvlist: %s\n")

#define	STATVFS_FAIL gettext("statvfs failed for %s: %s\n")

#define	IS_RAMDISK gettext("%s is on a ramdisk device\n")

#define	SKIP_RAMDISK gettext("Skipping archive creation\n")

#define	PRINT gettext("%s\n")

#define	PRINT_NO_NEWLINE gettext("%s")

#define	PRINT_TITLE gettext("%d %s\n")

#define	INT_ERROR gettext("Internal error: %s\n")

#define	CANT_FIND_USER \
	gettext("getpwnam: uid for %s failed, defaulting to %d\n")

#define	CANT_FIND_GROUP \
	gettext("getgrnam: gid for %s failed, defaulting to %d\n")

#define	CHMOD_FAIL gettext("chmod operation on %s failed - %s\n")

#define	CHOWN_FAIL gettext("chgrp operation on %s failed - %s\n")

#define	MISSING_SLICE_FILE gettext("GRUB slice file %s missing: %s\n")

#define	BAD_SLICE_FILE gettext("Invalid GRUB slice file %s\n")

#define	MKDIR_FAILED gettext("mkdir of %s failed: %s\n")

#define	MOUNT_FAILED gettext("mount of %s (fstype %s) failed\n")

#define	MOUNT_MNTPT_FAILED gettext("mount at %s failed\n")

#define	RMDIR_FAILED gettext("rmdir of %s failed: %s\n")

#define	UMOUNT_FAILED gettext("unmount of %s failed\n")

#define	CANNOT_RESTORE_GRUB_SLICE gettext("cannot restore GRUB slice\n")

#define	RESTORE_GRUB_FAILED gettext("cannot restore GRUB loader\n")

#define	MISSING_BACKUP_MENU gettext("no backup menu %s: %s\n")

#define	RESTORE_MENU_FAILED gettext("cannot restore menu %s\n")

#define	MISSING_ROOT_FILE gettext("file missing: %s: %s\n")

#define	BAD_ROOT_FILE gettext("file is invalid: %s\n")

#define	TRAILING_ARGS gettext("invalid trailing arguments\n")

#define	RESTORING_GRUB \
	gettext("No GRUB installation found. Restoring GRUB from backup\n")

#define	REBOOT_WITH_ARGS_FAILED \
	gettext("Cannot update menu. Cannot reboot with requested arguments\n")

#define	UPDATING_FDISK gettext("Updating fdisk table.\n")

#define	FDISK_UPDATE_FAILED gettext("Update of fdisk table failed.\n")

#define	MISSING_FDISK_FILE \
	gettext("Missing file (%s). Cannot update fdisk table.\n")

#define	FILE_REMOVE_FAILED \
	gettext("Failed to delete one or more of (%s,%s). Remove manually.\n")

#define	UNKNOWN_KERNEL	gettext("Unable to expand %s to a full file path.\n")

#define	UNKNOWN_KERNEL_REBOOT	\
	gettext("Rebooting with default kernel and options.\n")

#define	NOT_DBOOT \
	gettext("bootadm set-menu %s may only be run on directboot kernels.\n")

#define	DEFAULT_NOT_BAM	gettext(	\
"Default /boot/grub/menu.lst entry is not controlled by bootadm.  Exiting\n")

#define	NO_KERNEL_MATCH	\
gettext("Unexpected kernel command on line %d.\n\
** YOU MUST MANUALLY CORRECT /boot/grub/menu.lst BEFORE REBOOT! **\n\
For details, see %s\n")

#define	NO_MODULE_MATCH	\
gettext("Unexpected module command on line %d.\n\
** YOU MUST MANUALLY CORRECT /boot/grub/menu.lst BEFORE REBOOT! **\n\
For details, see %s\n")

#define	NO_KERNELS_FOUND	\
gettext("Could not find any kernel lines to update.  Only entries created by\n\
bootadm(1M) and lu(1M) can be updated.  All other must be manually changed.\n\
** YOU MUST MANUALLY CORRECT /boot/grub/menu.lst BEFORE REBOOT! **\n\
For details on updating entries, see %s\n")

#define	HAND_ADDED_ENTRY	\
gettext("On upgrades, bootadm(1M) will only upgrade entries added by\n\
bootadm(1M) or lu(1M).  The following entry or entries in\n\
/boot/grub/menu.lst will not be upgraded.  For details on updating entries,\n\
see %s\n")

#define	NOT_ELF_FILE gettext("%s is not an ELF file.\n")

#define	WRONG_ELF_CLASS gettext("%s is wrong ELF class 0x%x\n")

#define	FAILSAFE_MISSING \
gettext("bootadm -m upgrade run, but the failsafe archives have not been\n\
updated.  Not updating line %d\n")

#ifdef	__cplusplus
}
#endif

#endif /* _MESSAGE_H */
