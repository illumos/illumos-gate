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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2015 Toomas Soome <tsoome@me.com>
 */

#ifndef	_MESSAGE_H
#define	_MESSAGE_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <libintl.h>

#ifndef	lint
#define	_(x)	gettext(x)
#else
#define	_(x)	(x)
#endif

#define	FILE_MISS _("file not found: %s\n")

#define	ARCH_EXEC_MISS _("archive creation file not found: %s: %s\n")

#define	PATH_EXEC_OWNER _("%s is not owned by %d, skipping\n")

#define	PATH_EXEC_LINK _("%s is not a regular file, skipping\n")

#define	PATH_EXEC_PERMS _("%s is others or group writable, skipping\n")

#define	UPDATE_CACHE_OLD _("archive cache is out of sync. Rebuilding.\n")

#define	MUST_BE_ROOT _("you must be root to run this command\n")

#define	NOT_ARCHIVE_BOOT \
	_("%s: not a boot archive based Solaris instance\n")

#define	MULT_CMDS _("multiple commands specified: -%c\n")

#define	INVALID_SUBCMD _("invalid sub-command specified: %s\n")

#define	NEED_SUBCMD _("this command requires a sub-command\n")

#define	NEED_CMD _("a command option must be specified\n")

#define	DUP_OPT _("duplicate options specified: -%c\n")

#define	BAD_OPT _("invalid option or missing option argument: -%c\n")

#define	NO_OPT_REQ _("this sub-command (%s) does not take options\n")

#define	MISS_OPT _("an option is required for this sub-command: %s\n")

#define	ABS_PATH_REQ _("path is not absolute: %s\n")

#define	PATH_TOO_LONG \
	_("unable to create path on mountpoint %s, path too long\n")

#define	TOO_LONG _("the following line is too long (> %d chars)\n\t%s\n")

#define	NOT_GRUB_BOOT \
    _("not a GRUB 0.97 based Illumos instance. Operation not supported\n")

#define	NOT_GRUB_ROOT _("missing /boot/grub on root: %s\n")

#define	ALT_ROOT_INVALID \
    _("an alternate root (%s) cannot be used with this sub-command\n")

#define	NO_ENTRY _("no %s entry found\n")

#define	NO_MATCH_ENTRY _("no matching entry found\n")

#define	NO_BOOTADM_MATCH _("no matching bootadm entry found\n")

#define	NO_MEM _("could not allocate memory: size = %u\n")

#define	NO_SPARC _("%s operation unsupported on SPARC machines\n")

#define	CANNOT_LOCATE_GRUB_MENU _("cannot find GRUB menu\n")

#define	CANNOT_LOCATE_GRUB_MENU_FILE _("cannot find GRUB menu file: %s\n")

#define	GRUB_MENU_PATH _("the location for the active GRUB menu is: %s\n")

#define	STUBBOOT_DIR_NOT_FOUND _("cannot find stubboot directory\n")

#define	NO_CMD _("no command at line %d\n")

#define	DUP_CMD \
    _("duplicate command %s at line %d of %sboot/grub/menu.lst\n")

#define	NO_MENU _("menu file not found: %s\n")

#define	GLOBAL_CMD _("%s %s\n")

#define	INVALID_ENTRY _("invalid boot entry number: %s\n")

#define	INVALID_OPTION _("invalid option: %s\n")

#define	SUBOPT_MISS _("missing suboption: %s\n")

#define	NO_KERNEL _("no kernel line found in entry %d\n")

#define	EMPTY_MENU _("the GRUB menu is empty\n")

#define	UNLINK_EMPTY _("file is empty, deleting file: %s\n")

#define	UNLINK_FAIL _("failed to unlink file: %s: %s\n")

#define	NO_MATCH _("no matching entry found: %s\n")

#define	INVALID_OPT _("invalid option: %s\n")

#define	FAILED_SIG _("cannot set SIGCHLD disposition: %s\n")

#define	CANT_UNBLOCK_SIGCHLD _("cannot unblock SIGCHLD: %s\n")

#define	NO3264ELF \
    _("WARNING: file %s is neither a 32-bit nor a 64-bit ELF\n")

#define	BLOCKED_SIG _("SIGCHLD signal blocked. Cannot exec: %s\n")

#define	POPEN_FAIL _("popen failed: %s: %s\n")

#define	PCLOSE_FAIL _("pclose failed: %s: %s\n")

#define	EXEC_FAIL _("command terminated abnormally: %s: %d\n")

#define	OPEN_FAIL _("failed to open file: %s: %s\n")

#define	LOCK_FAIL _("failed to lock file: %s: %s\n")

#define	UNLOCK_FAIL _("failed to unlock file: %s: %s\n")

#define	TIMESTAMP_FAIL _("failed to update the timestamp file, next\
    archive update may experience reduced performance\n")

#define	MMAP_FAIL _("failed to mmap file: %s: %s\n")

#define	FILE_LOCKED _("another instance of bootadm (pid %lu) is running\n")

#define	NO_FLIST _("archive filelist is empty\n")

#define	CLOSE_FAIL _("failed to close file: %s: %s\n")

#define	RENAME_FAIL _("rename to file failed: %s: %s\n")

#define	NOT_IN_MNTTAB _("alternate root %s not in mnttab\n")

#define	CANT_RESOLVE _("cannot resolve path %s: %s\n")

#define	ROOT_ABS _("this sub-command doesn't take root arguments: %s\n")

#define	ARCHIVE_FAIL _("boot-archive creation FAILED, command: '%s'\n")

#define	MULTI_FAIL \
    _("Command '%s' failed while generating multisession archive\n")

#define	INFILE_FAIL _("unable to read from %s: %s\n")

#define	ARCHIVE_BAD _("archive file %s not generated correctly\n")

#define	CACHE_FAIL	\
    _("Failed to gather cache files, archives generation aborted\n")

#define	BOOTBLK_FAIL _("unable to access bootblk file : %s\n")

#define	WRITE_FAIL _("write to file failed: %s: %s\n")

#define	GZ_WRITE_FAIL _("failed to write to %s\n")

#define	STAT_FAIL _("stat of file failed: %s: %s\n")

#define	PACK_FAIL _("failed to pack stat data: %s\n")

#define	NVALLOC_FAIL _("failed to create stat data: %s\n")

#define	NVADD_FAIL _("failed to update stat data for: %s: %s\n")

#define	DISKMAP_FAIL \
    _("create_diskmap command failed for OS root: %s.\n")

#define	BIOSDEV_SKIP \
    _("not using biosdev command for disk: %s.\n")

#define	CHECK_NOT_SUPPORTED \
	_("the check option is not supported with subcmd: %s\n")

#define	PARSEABLE_NEW_FILE	_("    new     %s\n")

#define	PARSEABLE_OUT_DATE	_("    changed %s\n")

#define	PARSEABLE_STALE_FILE	_("    stale %s\n")

#define	UPDATE_FORCE _("forced update of archive requested\n")

#define	NO_NEW_STAT _("cannot create new stat data\n")

#define	UPDATE_ARCH_MISS _("archive not found: %s\n")

#define	UPDATE_CDIR_MISS _("archive cache directory not found: %s\n")

#define	MULTI_SIZE \
    _("archive %s is bigger than %d bytes and will be rebuilt\n")

#define	READ_FAIL _("read failed for file: %s: %s\n")

#define	UNPACK_FAIL _("failed to unpack stat data: %s: %s\n")

#define	NFTW_FAIL _("cannot find: %s: %s\n")

#define	SIGN_FAIL _("iso descriptor signature for %s is invalid\n")

#define	STATVFS_FAIL _("statvfs failed for %s: %s\n")

#define	IS_RAMDISK _("%s is on a ramdisk device\n")

#define	PRINT _("%s\n")

#define	PRINT_TITLE _("%d %s\n")

#define	INT_ERROR _("Internal error: %s\n")

#define	CANT_FIND_USER \
	_("getpwnam: uid for %s failed, defaulting to %d\n")

#define	CANT_FIND_GROUP \
	_("getgrnam: gid for %s failed, defaulting to %d\n")

#define	CHMOD_FAIL _("chmod operation on %s failed - %s\n")

#define	CHOWN_FAIL _("chgrp operation on %s failed - %s\n")

#define	MISSING_SLICE_FILE _("GRUB slice file %s missing: %s\n")

#define	MKDIR_FAILED _("mkdir of %s failed: %s\n")

#define	MOUNT_FAILED _("mount of %s (fstype %s) failed\n")

#define	MOUNT_MNTPT_FAILED _("mount at %s failed\n")

#define	UMOUNT_FAILED _("umount of %s failed\n")

#define	CANNOT_RESTORE_GRUB_SLICE _("cannot restore GRUB slice\n")

#define	RESTORE_GRUB_FAILED _("cannot restore GRUB loader\n")

#define	MISSING_BACKUP_MENU _("no backup menu %s: %s\n")

#define	RESTORE_MENU_FAILED _("cannot restore menu %s\n")

#define	MISSING_ROOT_FILE _("file missing: %s: %s\n")

#define	BAD_ROOT_FILE _("file is invalid: %s\n")

#define	TRAILING_ARGS _("invalid trailing arguments\n")

#define	RESTORING_GRUB \
	_("No GRUB installation found. Restoring GRUB from backup\n")

#define	REBOOT_WITH_ARGS_ADD_ENTRY_FAILED \
	_("Cannot update menu. Cannot reboot with requested arguments\n")

#define	FDISK_FILES_FOUND \
	_("Deferred FDISK update file(s) found: %s, %s. Not supported.\n")

#define	UNKNOWN_KERNEL	_("unable to expand %s to a full file path.\n")

#define	UNKNOWN_KERNEL_REBOOT	\
	_("Rebooting with default kernel and options.\n")

#define	NOT_DBOOT \
	_("bootadm set-menu %s may only be run on directboot kernels.\n")

#define	DEFAULT_NOT_BAM	_(	\
"Default /boot/grub/menu.lst entry is not controlled by bootadm.  Exiting\n")

#define	CANT_FIND_DEFAULT	\
_("unable to find default boot entry (%d) in menu.lst file.\n")

#define	UNKNOWN_KERNEL_LINE	\
_("kernel command on line %d not recognized.\n")

#define	UNKNOWN_MODULE_LINE	\
_("module command on line %d not recognized.\n")

#define	FINDROOT_NOT_FOUND	\
_("findroot in default boot entry (%d) missing.\n")

#define	KERNEL_NOT_FOUND	\
_("kernel$ in default boot entry (%d) missing.\n")

#define	KERNEL_NOT_PARSEABLE	\
_("kernel$ in default boot entry (%d) missing or not parseable.\n")

#define	MODULE_NOT_PARSEABLE	\
_("module$ in default boot entry (%d) missing or not parseable.\n")

#define	NOT_ELF_FILE _("%s is not an ELF file.\n")

#define	WRONG_ELF_CLASS _("%s is wrong ELF class 0x%x\n")

#define	FAILSAFE_MISSING \
_("bootadm -m upgrade run, but the failsafe archives have not been\n\
updated.  Not updating line %d\n")

#define	INVALID_PLAT	\
	_("invalid platform %s - must be one of sun4u, sun4v or i86pc\n")

#define	FDISKPART_FAIL _("failed to determine fdisk partition: %s\n")

#define	INVALID_MHASH_KEY _("invalid key for mnttab hash: %s\n")

#define	INVALID_UFS_SIGNATURE _("invalid UFS boot signature: %s\n")

#define	SIGN_LIST_FPUTS_ERR \
	_("failed to write signature %s to signature list: %s\n")

#define	SIGNATURE_LIST_EXISTS _("	- signature list %s exists\n")

#define	OPENDIR_FAILED _("opendir of %s failed: %s\n")

#define	GRUBSIGN_SORT_FAILED _("error sorting GRUB UFS boot signatures\n")

#define	SEARCHING_UFS_SIGN _("	- searching for UFS boot signatures\n")

#define	ERR_FIND_UFS_SIGN _("search for UFS boot signatures failed\n")

#define	UFS_SIGNATURE_LIST_MISS _("missing UFS signature list file: %s\n")

#define	UFS_SIGNATURE_LIST_OPENERR \
	_("error opening UFS boot signature list file %s: %s\n")

#define	UFS_BADSIGN _("bad UFS boot signature: %s\n")

#define	GRUBSIGN_BACKUP_OPENERR \
	_("error opening boot signature backup file %s: %s\n")

#define	GRUBSIGN_BACKUP_WRITEERR \
	_("error writing boot signature backup file %s: %s\n")

#define	GRUBSIGN_BACKUP_UPDATED \
	_("updated boot signature backup file %s\n")

#define	GRUBSIGN_PRIMARY_CREATERR \
	_("error creating primary boot signature %s: %s\n")

#define	GRUBSIGN_PRIMARY_SYNCERR \
	_("error syncing primary boot signature %s: %s\n")

#define	GRUBSIGN_CREATED_PRIMARY \
	_("created primary GRUB boot signature: %s\n")

#define	GRUBSIGN_CREATE_FAIL \
	_("failed to create GRUB boot signature for device: %s\n")

#define	GRUBSIGN_WRITE_FAIL \
	_("failed to write GRUB boot signature for device: %s\n")

#define	GRUBSIGN_UFS_NONE _("	- no existing UFS boot signatures\n")

#define	GRUBSIGN_NOTSUP _("boot signature not supported for fstype: %s\n")

#define	GRUBSIGN_MKDIR_ERR \
	_("error creating boot signature directory %s: %s\n")

#define	NOT_UFS_SLICE _("%s is not a ufs slice: %s\n")

#define	FSTYP_FAILED _("fstyp failed for slice: %s\n")

#define	FSTYP_BAD _("bad output from fstyp for slice: %s\n")

#define	ZFS_MOUNT_FAILED _("mount of ZFS pool %s failed\n")

#define	ZFS_MNTPT_FAILED \
	_("failed to determine mount point of ZFS pool %s\n")

#define	NULL_ZFS_MNTPT _("ZFS pool %s has no mount-point\n")

#define	BAD_ZFS_MNTPT _("ZFS pool %s has bad mount-point %s\n")

#define	NULL_ZFS_MNTPT _("ZFS pool %s has no mount-point\n")

#define	BAD_ZFS_MNTED _("ZFS pool %s has bad mount status\n")

#define	ZFS_MNTED_FAILED \
	_("failed to determine mount status of ZFS pool %s\n")

#define	INT_BAD_MNTSTATE \
	_("Internal error: bad saved mount state for pool %s\n")

#define	FSTYP_A_FAILED _("fstyp -a on device %s failed\n")

#define	NULL_FSTYP_A _("NULL fstyp -a output for device %s\n")

#define	BAD_FSTYP_A _("bad fstyp -a output for device %s\n")

#define	INVALID_UFS_SIGN _("invalid UFS boot signature %s\n")

#define	CANT_FIND_SPECIAL _("cant find special file for mount-point %s\n")

#define	CANT_FIND_POOL _("cant find pool for mount-point %s\n")

#define	NULL_FINDROOT _("can't find argument for findroot command\n")

#define	INVALID_DEV_DSK _("not a /dev/[r]dsk name: %s\n")

#define	CVT_FINDROOT _("converting entries to findroot...\n")

#define	CVT_HV _("adding xVM entries...\n")

#define	CVT_DBOOT _("converting entries to dboot...\n")

#define	DOWNGRADE_NOTSUP \
_("automated downgrade of GRUB menu to older version not supported.\n")

#define	CANT_FIND_GRUBSIGN _("cannot find GRUB signature for %s\n")

#define	CVT_TODO	\
_("one or more GRUB menu entries were not automatically upgraded\n\
For details on manually updating entries, see %s\n")

#define	CVT_ABORT	\
_("error upgrading GRUB menu entries on %s. Aborting.\n\
For details on manually updating entries, see %s\n")

#define	ALREADY_HYPER	\
_("default entry already setup for use with the hypervisor!\n")

#define	HYPER_ABORT	\
_("error converting GRUB menu entry on %s for use with the hypervisor.\n\
Aborting.\n")

#define	ALREADY_METAL	\
_("default entry already setup for use with a metal kernel!\n")

#define	METAL_ABORT	\
_("error converting GRUB menu entry on %s for use with a metal kernel.\n\
Aborting.\n")

#define	HAND_ADDED_ENTRIES	\
_("bootadm(1M) will only upgrade GRUB menu entries added by \n\
bootadm(1M) or lu(1M). The following entries on %s will not be upgraded.\n\
For details on manually updating entries, see %s\n")

#define	SIGN_FSTYPE_MISMATCH	\
_("found mismatched boot signature %s for filesystem type: %s.\n")

#define	REBOOT_FSTYPE_FAILED	\
_("failed to determine filesystem type for \"/\". Reboot with \n\
arguments failed.\n")

#define	REBOOT_SPECIAL_FAILED	\
_("failed to find device special file for \"/\". Reboot with \n\
arguments failed.\n")

#define	REBOOT_SIGN_FAILED	\
_("failed to find boot signature. Reboot with arguments failed.\n")

#define	REBOOT_DIRECT_FAILED	\
_("the root filesystem is not a dboot Solaris instance. \n\
This version of bootadm is not supported on this version of Solaris.\n")

#define	BOOTENV_FSTYPE_FAILED	\
_("cannot determine filesystem type for \"/\".\n\
Cannot generate GRUB menu entry with EEPROM arguments.\n")

#define	BOOTENV_SPECIAL_FAILED	\
_("cannot determine device special file for \"/\".\n\
Cannot generate GRUB menu entry with EEPROM arguments.\n")

#define	BOOTENV_SIGN_FAILED	\
_("cannot determine boot signature for \"/\".\n\
Cannot generate GRUB menu entry with EEPROM arguments.\n")

#define	GRUB_SLICE_FILE_EXISTS \
	_("unsupported GRUB slice file (%s) exists - ignoring.\n")

#define	GRUBSIGN_FOUND_OR_CREATED \
_("found or created GRUB signature %s for %s\n")

#define	GET_FSTYPE_ARGS _("no OS mountpoint. Cannot determine fstype\n")

#define	MNTTAB_MNTPT_NOT_FOUND \
	_("failed to find OS mountpoint %s in %s\n")

#define	MNTTAB_FSTYPE_NULL _("NULL fstype found for OS root %s\n")

#define	MISSING_ARG _("missing argument for sub-command\n")

#define	INVALID_BINARY _("invalid or corrupted binary: %s\n")

#define	PCFS_ROOT_NOTSUP _("root <%s> on PCFS is not supported\n")

#define	NO_O_OSROOT _("OS root not specified with -o option: %s\n")

#define	RDONLY_FS \
	_("%s filesystem is read-only, skipping archives update\n")

#define	RDONLY_TEST_ERROR _("error during read-only test on %s: %s\n")

#define	CANNOT_GRUBROOT_BOOTDISK \
	_("cannot get (hd?,?,?) for menu. menu not on bootdisk: %s\n")

#define	NO_GRUBROOT_FOR_DISK \
	_("cannot determine BIOS disk ID 'hd?' for disk: %s\n")

#define	CACHE_MNTTAB_FAIL _("%s: failed to cache /etc/mnttab\n")

#define	FAILED_ADD_SIGNLIST _("failed to add sign %s to signlist.\n")

#define	GRUBSIGN_BACKUP_MKDIRERR _("mkdirp() of backup dir failed: %s: %s\n")

#define	GET_POOL_FAILED _("failed to get pool name from %s\n")

#define	FAIL_MNT_TOP_DATASET _("failed to mount top dataset for %s\n")

#define	PRIMARY_SIGN_EXISTS _("primary sign %s exists\n")

#define	SET_BACKUP_FAILED _("failed to set backup sign (%s) for %s: %s\n")

#define	SET_PRIMARY_FAILED \
_("failed to set primary sign (%s) for %s: %s\n")

#define	GET_FSTYPE_FAILED _("failed to get fstype for %s\n")

#define	GET_SPECIAL_NULL_MNTPT \
	_("cannot get special file: NULL mount-point\n")

#define	GET_SPECIAL_NULL \
	_("cannot get special file for mount-point: %s\n")

#define	GET_PHYSICAL_MENU_NULL \
	_("cannot get physical device special file for menu root: %s\n")

#define	GET_GRUBSIGN_ERROR \
	_("failed to get grubsign for root: %s, device %s\n")

#define	FAILED_TO_ADD_BOOT_ENTRY \
	_("failed to add boot entry with title=%s, grub signature=%s\n")

#define	SET_DEFAULT_FAILED _("failed to set GRUB menu default to %d\n")

#define	REBOOT_GET_KERNEL_FAILED \
_("reboot with arguments: error querying current boot-file settings\n")

#define	REBOOT_GET_ARGS_FAILED \
_("reboot with arguments: error querying current boot-args settings\n")

#define	REBOOT_SET_DEFAULT_FAILED \
_("reboot with arguments: setting GRUB menu default to %d failed\n")

#define	GET_SET_KERNEL_ADD_BOOT_ENTRY _("failed to add boot entry: %s\n")

#define	GET_SET_KERNEL_SET_GLOBAL _("failed to set default to: %d\n")

#define	NO_OPTION_ARG _("option has no argument: %s\n")

#define	CANT_MOUNT_POOL_DATASET \
	_("cannot mount pool dataset for pool: %s\n")

#define	ZFS_GET_POOL_FAILED _("failed to get pool for device: %s\n")

#define	ZFS_MOUNT_TOP_DATASET_FAILED \
	_("failed to mount top dataset for pool: %s\n")

#define	GET_POOL_OSDEV_NULL _("NULL device: cannot determine pool name\n")

#define	GET_POOL_BAD_OSDEV \
_("invalid device %s: cannot determine pool name\n")

#define	POOL_SIGN_INCOMPAT \
_("pool name %s not present in signature %s\n")

#define	INVALID_ZFS_SPECIAL \
_("invalid device for ZFS filesystem: %s\n")

#define	CANT_FIND_POOL_FROM_SPECIAL \
_("cannot derive ZFS pool from special: %s\n")

#define	ZFS_GET_POOL_STATUS \
_("cannot get zpool status for pool: %s\n")

#define	BAD_ZPOOL_STATUS \
_("bad zpool status for pool=%s\n")

#define	NO_POOL_IN_ZPOOL_STATUS \
_("no pool name %s in zpool status\n")

#define	NO_PHYS_IN_ZPOOL_STATUS \
_("no physical device in zpool status for pool=%s\n")

#define	UFS_GET_PHYS_NOT_SVM \
_("not a SVM metadevice: %s. Cannot derive physical device\n")

#define	UFS_GET_PHYS_INVALID_SVM \
_("invalid SVM metadevice name: %s. Cannot derive physical device\n")

#define	UFS_SVM_METASTAT_ERR \
_("metastat command failed on SVM metadevice: %s\n")

#define	UFS_SVM_METASTAT_SVC_ERR \
_("failed to start service %s for metastat command\n")

#define	BAD_UFS_SVM_METASTAT \
_("bad output from metastat command on SVM metadevice: %s\n")

#define	INVALID_UFS_SVM_METASTAT \
_("invalid fields in metastat output for SVM metadevice: %s\n")

#define	CANNOT_PARSE_UFS_SVM_METASTAT \
_("cannot parse output of metastat command for metadevice: %s\n")

#define	CANNOT_PARSE_UFS_SVM_SUBMIRROR \
_("cannot parse submirror line in metastat output for metadevice: %s\n")

#define	GET_PHYSICAL_NOTSUP_FSTYPE \
_("cannot derive physical device for %s (%s), unsupported filesystem\n")

#define	ERROR_PARSE_UFS_SVM_METASTAT \
_("error parsing metastat output for SVM metadevice: %s\n")

#define	GET_OSROOT_SPECIAL_ERR \
_("failed to get special file for osroot: %s\n")

#define	GET_MENU_ROOT_SPECIAL_ERR \
_("failed to get special file for menu_root: %s\n")

#define	GET_SVC_STATE_ERR _("failed to determine state of service: %s\n")

#define	SVC_IS_ONLINE_FAILED \
	_("failed to determine if service is online: %s\n")

#define	ENABLE_SVC_FAILED _("failed to online service: %s\n")

#define	ERR_SVC_GET_ONLINE \
	_("failed to get online status for service: %s\n")

#define	TIMEOUT_ENABLE_SVC \
	_("timed out waiting for service to online: %s\n")

#define	CANNOT_READ_LU_CKSUM \
	_("failed to read GRUB menu checksum file: %s\n")

#define	MULTIPLE_LU_CKSUM \
	_("multiple checksums for GRUB menu in checksum file: %s\n")

#define	CANNOT_PARSE_LU_CKSUM \
	_("error parsing GRUB menu checksum file: %s\n")

#define	MENU_CKSUM_FAIL \
	_("error generating checksum of GRUB menu\n")

#define	BAD_CKSUM \
	_("bad checksum generated for GRUB menu\n")

#define	BAD_CKSUM_PARSE \
	_("error parsing checksum generated for GRUB menu\n")

#define	MENU_PROP_FAIL \
	_("error propagating updated GRUB menu\n")

#define	MENU_BACKUP_FAIL \
	_("failed to create backup for GRUB menu: %s\n")

#define	BACKUP_PROP_FAIL \
	_("error propagating backup GRUB menu: %s\n")

#define	MENU_CKSUM_WRITE_FAIL \
	_("failed to write GRUB menu checksum file: %s\n")

#define	MENU_CKSUM_PROP_FAIL \
	_("error propagating GRUB menu checksum file: %s\n")

#define	BOOTADM_PROP_FAIL \
	_("error propagating bootadm: %s\n")

#define	PROP_GRUB_MENU \
	_("propagating updated GRUB menu\n")

#define	NEED_DIRPATH	_("need to create directory path for %s\n")

#define	UPDT_CACHE_FAIL	_("directory cache update failed for %s\n")

#define	NEW_BOOT_ENTRY \
    _("unable to modify default entry; creating new boot entry for %s\n")

/*
 * NOTE: The following are debug messages and not I18Ned
 */

#define	D_MATCHED_TITLE "%s: matched title: %s\n"

#define	D_NOMATCH_TITLE "%s: no match title: %s, %s\n"

#define	D_MATCHED_FINDROOT "%s: matched findroot: %s\n"

#define	D_NOMATCH_FINDROOT "%s: no match findroot: %s, %s\n"

#define	D_NOMATCH_FINDROOT_NULL "%s: no match line has findroot, we don't: %s\n"

#define	D_MATCHED_ROOT "%s: matched root: %s\n"

#define	D_NOMATCH_ROOT "%s: no match root: %s, %s\n"

#define	D_NOMATCH_ROOT_NULL "%s: no match, line has root, we don't: %s\n"

#define	D_NO_ROOT_OPT "%s: root NOT optional\n"

#define	D_ROOT_OPT "%s: root IS optional\n"

#define	D_KERNEL_MATCH "%s: kernel match: %s, %s\n"

#define	D_MODULE_MATCH "%s: module match: %s, %s\n"

#define	D_UPGRADE_FROM_MULTIBOOT \
	"%s: upgrading entry from dboot to multiboot: root = %s\n"

#define	D_ENTRY_NOT_FOUND_CREATING \
	"%s: boot entry not found in menu. Creating new entry, findroot = %s\n"

#define	D_CHANGING_TITLE "%s: changing title to: %s\n"

#define	D_ADDING_FINDROOT_LINE "%s: adding findroot line: %s\n"

#define	D_ADDING_KERNEL_DOLLAR "%s: adding new kernel$ line: %s\n"

#define	D_ADDING_MODULE_DOLLAR "%s: adding new module$ line: %s\n"

#define	D_GET_GRUBROOT_SUCCESS \
	"%s: get_grubroot success. osroot=%s, osdev=%s, menu_root=%s\n"

#define	D_GET_GRUBROOT_FAILURE \
	"%s: get_grubroot failed. osroot=%s, osdev=%s, menu_root=%s\n"

#define	D_UPDATED_BOOT_ENTRY \
	"%s: updated boot entry bam_zfs=%d, grubsign = %s\n"

#define	D_UPDATED_HV_ENTRY \
	"%s: updated HV entry bam_zfs=%d, grubsign = %s\n"

#define	D_UPDATED_MULTIBOOT_ENTRY \
	"%s: updated MULTIBOOT entry grubsign = %s\n"

#define	D_UPDATED_FAILSAFE_ENTRY \
	"%s: updated FAILSAFE entry failsafe_kernel = %s\n"

#define	D_GET_GRUBSIGN_SUCCESS "%s: successfully created grubsign %s\n"

#define	D_ADD_LINE_PREV_NEXT "%s: previous next exists\n"

#define	D_ADD_LINE_NOT_PREV_NEXT "%s: previous next does not exist\n"

#define	D_ADD_LINE_LAST_LINE_IN_ENTRY "%s: last line in entry\n"

#define	D_ADD_LINE_LAST_LINE_IN_MENU "%s: last line in menu\n"

#define	D_FOUND_FINDROOT "%s: found entry with matching findroot: %s\n"

#define	D_SAVING_DEFAULT_TO "%s: saving default to: %s\n"

#define	D_SAVED_DEFAULT_TO "%s: saved default to lineNum=%d, entryNum=%d\n"

#define	D_RESTORE_DEFAULT_NULL "%s: NULL saved default\n"

#define	D_RESTORE_DEFAULT_STR "%s: saved default string: %s\n"

#define	D_RESTORED_DEFAULT_TO "%s: restored default to entryNum: %d\n"

#define	D_FUNC_ENTRY0 "%s: entered. No args\n"

#define	D_FUNC_ENTRY1 "%s: entered. arg: %s\n"

#define	D_FUNC_ENTRY2 "%s: entered. args: %s %s\n"

#define	D_FUNC_ENTRY3 "%s: entered. args: %s %s %s\n"

#define	D_FUNC_ENTRY4 "%s: entered. args: %s %s %s %s\n"

#define	D_OPT_NULL "%s: opt is NULL\n"

#define	D_TRANSIENT_NOTFOUND "%s: transient entry not found\n"

#define	D_RESTORED_DEFAULT "%s: restored old default\n"

#define	D_ENTRY_EQUALS "%s: opt has entry=: %s\n"

#define	D_ENTRY_SET_IS "%s: default set to %d, set_default ret=%d\n"

#define	D_REBOOT_RESOLVED_PARTIAL "%s: resolved partial path: %s\n"

#define	D_FOUND_GLOBAL "%s: found matching global command: %s\n"

#define	D_SET_GLOBAL_WROTE_NEW "%s: wrote new global line: %s\n"

#define	D_SET_GLOBAL_REPLACED "%s: replaced global line with: %s\n"

#define	D_ARCHIVE_LINE_NONE "%s: no module/archive line for entry: %d\n"

#define	D_ARCHIVE_LINE_NOCHANGE "%s: no change for line: %s\n"

#define	D_ARCHIVE_LINE_REPLACED "%s: replaced for line: %s\n"

#define	D_GET_SET_KERNEL_NO_RC "%s: no RC entry, nothing to report\n"

#define	D_GET_SET_KERNEL_ALREADY "%s: no reset, already has default\n"

#define	D_GET_SET_KERNEL_RESTORE_DEFAULT "%s: resetting to default\n"

#define	D_GET_SET_KERNEL_RESET_KERNEL_SET_ARG \
"%s: reset kernel to default, but retained old args: %s\n"

#define	D_GET_SET_KERNEL_RESET_ARG_SET_KERNEL \
"%s: reset args to default, but retained old kernel: %s\n"

#define	D_GET_SET_KERNEL_REPLACED_KERNEL_SAME_ARG \
"%s: rc line exists, replaced kernel, same args: %s\n"

#define	D_GET_SET_KERNEL_SAME_KERNEL_REPLACED_ARG \
"%s: rc line exists, same kernel, but new args: %s\n"

#define	D_SET_OPTION "%s: setting %s option to %s\n"

#define	D_EXPAND_PATH "%s: expanded path: %s\n"

#define	D_GET_SET_KERNEL_ARGS "%s: read menu boot-args: %s\n"

#define	D_GET_SET_KERNEL_KERN "%s: read menu boot-file: %s\n"

#define	D_BAM_ROOT "%s: bam_alt_root: %d, bam_root: %s\n"

#define	D_REBOOT_OPTION "%s: reboot with args, option specified: kern=%s\n"

#define	D_REBOOT_ABSPATH "%s: reboot with args, abspath specified: kern=%s\n"

#define	D_GET_SET_KERNEL_NEW_KERN "%s: new kernel=%s\n"

#define	D_GET_SET_KERNEL_NEW_ARG "%s: new args=%s\n"

#define	D_Z_MENU_GET_POOL_FROM_SPECIAL "%s: derived pool=%s from special\n"

#define	D_Z_GET_MENU_MOUNT_TOP_DATASET "%s: top dataset mountpoint=%s\n"

#define	D_Z_GET_MENU_MENU_ROOT "%s: zfs menu_root=%s\n"

#define	D_Z_IS_LEGACY "%s: is legacy, pool=%s\n"

#define	D_Z_IS_NOT_LEGACY "%s: is *NOT* legacy, pool=%s\n"

#define	D_Z_MOUNT_TOP_NONLEG_MOUNTED_ALREADY \
	"%s: non-legacy pool %s mounted already\n"

#define	D_Z_MOUNT_TOP_NONLEG_MOUNTED_NOT_ALREADY \
	"%s: non-legacy pool %s *NOT* already mounted\n"

#define	D_Z_MOUNT_TOP_NONLEG_MOUNTED_NOW \
	"%s: non-legacy pool %s mounted now\n"

#define	D_Z_MOUNT_TOP_NONLEG_MNTPT \
	"%s: non-legacy pool %s is mounted at %s\n"

#define	D_Z_UMOUNT_TOP_ALREADY_NOP \
	"%s: pool %s was already mounted at %s, Nothing to umount\n"

#define	D_Z_UMOUNT_TOP_LEGACY \
	"%s: legacy pool %s was mounted by us, successfully unmounted\n"

#define	D_Z_UMOUNT_TOP_NONLEG \
	"%s: nonleg pool %s was mounted by us, successfully unmounted\n"

#define	D_Z_MOUNT_TOP_LEG_ALREADY \
	"%s: legacy pool %s already mounted\n"

#define	D_Z_MOUNT_TOP_LEG_MNTPT_ABS \
	"%s: legacy pool %s mount-point %s absent\n"

#define	D_Z_MOUNT_TOP_LEG_MNTPT_PRES \
	"%s: legacy pool %s mount-point %s is already present\n"

#define	D_Z_MOUNT_TOP_LEG_MOUNTED \
	"%s: legacy pool %s successfully mounted at %s\n"

#define	D_Z_MOUNT_TOP_LEG_MOUNTED \
	"%s: legacy pool %s successfully mounted at %s\n"

#define	D_GET_MOUNTPOINT_RET \
	"%s: returning mount-point for special %s: %s\n"

#define	D_IS_ZFS "%s: is a ZFS filesystem: %s\n"

#define	D_IS_NOT_ZFS "%s: is *NOT* a ZFS filesystem: %s\n"

#define	D_IS_UFS "%s: is a UFS filesystem: %s\n"

#define	D_IS_NOT_UFS "%s: is *NOT* a UFS filesystem: %s\n"

#define	D_IS_PCFS "%s: is a PCFS filesystem: %s\n"

#define	D_IS_NOT_PCFS "%s: is *NOT* a PCFS filesystem: %s\n"

#define	D_MENU_PATH "%s: menu path is: %s\n"

#define	D_FREEING_LU_SIGNS "%s: feeing LU sign: %s\n"

#define	D_OPEN_FAIL "%s: failed to open %s: %s\n"

#define	D_GET_POOL_OSDEV "%s: osdev arg = %s\n"

#define	D_GET_POOL_RET "%s: got pool. pool = %s\n"

#define	D_GET_GRUBSIGN_NO_EXISTING "%s: no existing grubsign for %s: %s\n"

#define	D_GET_PHYSICAL_ALREADY \
	"%s: got physical device already directly for menu_root=%s special=%s\n"

#define	D_GET_PHYSICAL_RET "%s: returning physical=%s\n"

#define	D_STRTOK_ZPOOL_STATUS "%s: strtok() zpool status line=%s\n"

#define	D_FOUND_POOL_IN_ZPOOL_STATUS "%s: found pool name: %s in zpool status\n"

#define	D_COUNTING_ZFS_PHYS "%s: counting phys slices in zpool status: %d\n"

#define	D_ADDING_ZFS_PHYS "%s: adding phys slice=%s from pool %s status\n"

#define	D_FUNC_ENTRY_N1 "%s: entering args: %d\n"

#define	D_UFS_SVM_SHORT "%s: short SVM name for special=%s is %s\n"

#define	D_UFS_SVM_ONE_COMP "%s: single component %s for metadevice %s\n"

#define	D_CHECK_ON_BOOTDISK "%s: checking if phys-device=%s is on bootdisk\n"

#define	D_IS_ON_BOOTDISK "%s: phys-device=%s *IS* on bootdisk\n"

#define	D_ROOT_OPT_NOT_ZFS "%s: one or more non-ZFS filesystems (%s, %s)\n"

#define	D_ROOT_OPTIONAL_OSPECIAL "%s: ospecial=%s for osroot=%s\n"

#define	D_ROOT_OPTIONAL_MSPECIAL "%s: mspecial=%s for menu_root=%s\n"

#define	D_ROOT_OPTIONAL_FIXED_OSPECIAL "%s: FIXED ospecial=%s for osroot=%s\n"

#define	D_CHECK_CMD_CMD_NOMATCH "%s: command %s does not match %s\n"

#define	D_FINDROOT_ABSENT "%s: findroot capability absent\n"

#define	D_FINDROOT_PRESENT "%s: findroot capability present\n"

#define	D_DBOOT_PRESENT "%s: dboot capability present\n"

#define	D_XVM_PRESENT "%s: xVM capability present\n"

#define	D_IS_SPARC_DBOOT "%s: is sparc - always DBOOT\n"

#define	D_IS_DBOOT "%s: is DBOOT unix\n"

#define	D_IS_MULTIBOOT "%s: is MULTIBOOT unix\n"

#define	D_IS_XVM "%s: is xVM system\n"

#define	D_IS_NOT_XVM "%s: is *NOT* xVM system\n"

#define	D_ALREADY_BFU_TEST "%s: already done bfu test. bfu is %s present\n"

#define	D_UPDATE_LINE_BEFORE "%s: line before update: %s\n"

#define	D_UPDATE_LINE_AFTER "%s: line after update: %s\n"

#define	D_SKIP_WSPACE_PTR_NULL "%s: NULL ptr\n"

#define	D_SKIP_WSPACE_ENTRY_PTR "%s: ptr on entry: %s\n"

#define	D_SKIP_WSPACE_EXIT_PTR "%s: ptr on exit: %s\n"

#define	D_RSKIP_BSPACE_ENTRY "%s: ptr on entry: %s\n"

#define	D_RSKIP_BSPACE_EXIT "%s: ptr on exit: %s\n"

#define	D_RSKIP_BSPACE_EXIT "%s: ptr on exit: %s\n"

#define	D_NOT_MULTIBOOT_CONVERT "%s: not MULTIBOOT, not converting\n"

#define	D_TRYING_FAILSAFE_CVT_TO_DBOOT \
	"%s: trying to convert failsafe to DBOOT\n"

#define	D_NO_FAILSAFE_UNIX_CONVERT "%s: no FAILSAFE unix, not converting\n"

#define	D_CVT_CMD_KERN_DOLLAR "%s: converted kernel cmd to %s\n"

#define	D_CVT_CMD_MOD_DOLLAR "%s: converted module cmd to %s\n"

#define	D_FLAGS1_UNIX_FLAGS2_NULL "%s: NULL flags1, unix, flags2\n"

#define	D_UNIX_PRESENT "%s: unix present\n"

#define	D_UNIX_PRESENT "%s: unix present\n"

#define	D_UNIX_ABSENT "%s: unix ABSENT\n"

#define	D_FLAGS2_PRESENT "%s: flags2 present: %s\n"

#define	D_FLAGS2_ABSENT "%s: flags2 absent\n"

#define	D_FLAGS1_PRESENT "%s: flags1 present: %s\n"

#define	D_FLAGS1_ABSENT "%s: flags1 absent\n"

#define	D_FLAGS1_ONLY "%s: flags1 present: %s, unix, flags2 absent\n"

#define	D_CVTED_UNIX "%s: converted unix: %s\n"

#define	D_CVTED_UNIX_AND_FLAGS "%s: converted unix with flags : %s\n"

#define	D_CVTED_KERNEL_LINE "%s: converted line is: %s\n"

#define	D_FAILSAFE_NO_CVT_NEEDED \
	"%s: failsafe module line needs no conversion: %s\n"

#define	D_CVTED_MODULE "%s: converted module line is: %s\n"

#define	D_FORCE_HAND_CVT "%s: force specified, no warnings about hand entries\n"

#define	D_FOUND_HAND "%s: found hand entry #: %d\n"

#define	D_SKIP_ENTRY "%s: skipping hand entry #: %d\n"

#define	D_SKIP_ROOT_ENTRY "%s: skipping root entry #: %d\n"

#define	D_ENTRY_END "%s: entry has ended\n"

#define	D_SKIP_NULL "%s: skipping NULL line\n"

#define	D_ROOT_MATCH "%s: found matching root line: %s,%s\n"

#define	D_FINDROOT_MATCH "%s: found matching findroot line: %s,%s\n"

#define	D_NO_ROOT_FINDROOT "%s: no root or findroot and root is opt: %d\n"

#define	D_NO_MATCH "%s: no matching entry found\n"

#define	D_ALREADY_FINDROOT "%s: entry %d already converted to findroot\n"

#define	D_ADDED_FINDROOT "%s: added findroot line: %s\n"

#define	D_ADDED_NUMBERING "%s: updating numbering\n"

#define	D_ALREADY_HV "%s: entry %d already converted to xvm HV\n"

#define	D_ADDED_XVM_ENTRY "%s: added xVM HV entry via add_boot_entry()\n"

#define	D_CVT_KERNEL_FAIL "%s: cvt_kernel_line() failed\n"

#define	D_CVT_KERNEL_MSG "%s: BAM_MSG returned from cvt_kernel_line()\n"

#define	D_CVT_MODULE_FAIL "%s: cvt_module_line() failed\n"

#define	D_CVT_MODULE_MSG "%s: BAM_MSG returned from cvt_module_line()\n"

#define	D_UPDATED_NUMBERING "%s: updated numbering\n"

#define	D_FREEING_ROOT "%s: freeing root line: %s\n"

#define	D_MENU_ROOT "%s: menu root is %s\n"

#define	D_CLEAN_MENU_ROOT "%s: cleaned menu root is <%s>\n"

#define	D_BOOT_GET_CAP_FAILED "%s: Failed to get boot capability\n"

#define	D_WRITING_MENU_ROOT "%s: writing menu to clean-menu-root: <%s>\n"

#define	D_WROTE_FILE "%s: wrote file successfully: %s\n"

#define	D_FLIST_FAIL "%s: failed to open archive filelist: %s: %s\n"

#define	D_NOT_ARCHIVE_BOOT "%s: not a boot archive based Solaris instance: %s\n"

#define	D_IS_ARCHIVE_BOOT "%s: *IS* a boot archive based Solaris instance: %s\n"

#define	D_NO_GRUB_DIR "%s: Missing GRUB directory: %s\n"

#define	D_RDONLY_FS "%s: is a READONLY filesystem: %s\n"

#define	D_RDWR_FS "%s: is a RDWR filesystem: %s\n"

#define	D_ENTRY_NEW "%s: new boot entry alloced\n"

#define	D_ENTRY_NEW_FIRST "%s: (first) new boot entry created\n"

#define	D_ENTRY_NEW_LINKED "%s: new boot entry linked in\n"

#define	D_NOT_KERNEL_CMD "%s: not a kernel command: %s\n"

#define	D_SET_DBOOT_32 "%s: setting DBOOT|DBOOT_32 flag: %s\n"

#define	D_SET_DBOOT "%s: setting DBOOT flag: %s\n"

#define	D_SET_DBOOT_64 "%s: setting DBOOT|DBOOT_64 flag: %s\n"

#define	D_SET_DBOOT_FAILSAFE "%s: setting DBOOT|DBOOT_FAILSAFE flag: %s\n"

#define	D_SET_DBOOT_FAILSAFE_32 \
	"%s: setting DBOOT|DBOOT_FAILSAFE|DBOOT_32 flag: %s\n"

#define	D_SET_DBOOT_FAILSAFE_64 \
	"%s: setting DBOOT|DBOOT_FAILSAFE|DBOOT_64 flag: %s\n"

#define	D_SET_MULTIBOOT "%s: setting MULTIBOOT flag: %s\n"

#define	D_SET_MULTIBOOT_FAILSAFE \
	"%s: setting MULTIBOOT|MULTIBOOT_FAILSAFE flag: %s\n"

#define	D_SET_HV "%s: setting XEN HV flag: %s\n"

#define	D_REC_MKDIR "%s: making recursive directory %s\n"

#define	D_SET_HAND_KERNEL "%s: is HAND kernel flag: %s\n"

#define	D_IS_UNKNOWN_KERNEL "%s: is UNKNOWN kernel entry: %s\n"

#define	D_NOT_MODULE_CMD "%s: not module cmd: %s\n"

#define	D_BOOTADM_LU_MODULE "%s: bootadm or LU module cmd: %s\n"

#define	D_IS_HAND_MODULE "%s: is HAND module: %s\n"

#define	D_IS_UNKNOWN_MODULE "%s: is UNKNOWN module: %s\n"

#define	D_IS_BOOTADM_ENTRY "%s: is bootadm(1M) entry: %s\n"

#define	D_IS_LU_ENTRY "%s: is LU entry: %s\n"

#define	D_IS_ROOT_CMD "%s: setting ROOT: %s\n"

#define	D_IS_FINDROOT_CMD "%s: setting FINDROOT: %s\n"

#define	D_CMDLINE  "%s: executing: %s\n"

#define	D_IS_CHAINLOADER_CMD "%s: setting CHAINLOADER: %s\n"

#define	D_NO_BOOTENVRC "could not open %s: %s\n"

#define	D_ADD_FINDROOT_NUM "%s: findroot added: line#: %d: entry#: %d\n"

#define	D_FREEING_LINE "%s: freeing line: %d\n"

#define	D_FREEING_ENTRY "%s: freeing entry: %d\n"

#define	D_CREATED_DISKMAP "%s: created diskmap file: %s\n"

#define	D_CREATE_DISKMAP_FAIL "%s: FAILED to create diskmap file: %s\n"

#define	D_NO_SIGNDIR "%s: no sign dir: %s\n"

#define	D_EXIST_BACKUP_SIGNS \
"%s: found backup signs: zfs=%s ufs=%s lu=%s\n"

#define	D_RETURN_SUCCESS "%s: returning SUCCESS\n"

#define	D_RETURN_FAILURE "%s: returning FAILURE\n"

#define	D_RETURN_RET "%s: returning ret = %d\n"

#define	D_EXIST_PRIMARY_SIGN "%s: existing primary sign: %s\n"

#define	D_EXIST_BACKUP_SIGN "%s: existing backup sign: %s\n"

#define	D_EXIST_PRIMARY_SIGNS \
"%s: found primary signs: zfs=%s ufs=%s lu=%s\n"

#define	D_CHECK_UFS_EXIST_SIGN "%s: checking for existing UFS sign\n"

#define	D_CHECK_ZFS_EXIST_SIGN "%s: checking for existing ZFS sign\n"

#define	D_NO_MNTPT "%s: no mount-point for special=%s and fstype=%s\n"

#define	D_CACHE_MNTS \
"%s: caching mount: special=%s, mntpt=%s, fstype=%s\n"

#define	D_MNTTAB_HASH_NOMATCH "%s: no match in cache for: %s\n"

#define	D_MNTTAB_HASH_MATCH "%s: *MATCH* in cache for: %s\n"

#define	D_NO_SIGN_TO_LIST "%s: no sign on %s to add to signlist\n"

#define	D_SIGN_LIST_PUTS_DONE \
"%s: successfully added sign on %s to signlist\n"

#define	D_SLICE_ENOENT "%s: slice does not exist: %s\n"

#define	D_VTOC_SIZE_ZERO "%s: VTOC: skipping 0-length slice: %s\n"

#define	D_VTOC_NOT_ROOT_TAG "%s: VTOC: unsupported tag, skipping: %s\n"

#define	D_VTOC_ROOT_TAG "%s: VTOC: supported tag, checking: %s\n"

#define	D_VTOC_NOT_RDWR_FLAG "%s: VTOC: non-RDWR flag, skipping: %s\n"

#define	D_VTOC_RDWR_FLAG "%s: VTOC: RDWR flag, checking: %s\n"

#define	D_EFI_SIZE_ZERO "%s: EFI: skipping 0-length slice: %s\n"

#define	D_EFI_NOT_ROOT_TAG "%s: EFI: unsupported tag, skipping: %s\n"

#define	D_EFI_ROOT_TAG "%s: EFI: supported tag, checking: %s\n"

#define	D_EFI_NOT_RDWR_FLAG "%s: EFI: non-RDWR flag, skipping: %s\n"

#define	D_EFI_RDWR_FLAG "%s: EFI: RDWR flag, checking: %s\n"

#define	D_SLICE0_ENOENT "%s: slice 0 does not exist: %s\n"

#define	D_VTOC_READ_FAIL "%s: VTOC: failed to read: %s\n"

#define	D_VTOC_INVALID "%s: VTOC: is INVALID: %s\n"

#define	D_VTOC_UNKNOWN_ERR "%s: VTOC: unknown error while reading: %s\n"

#define	D_VTOC_NOTSUP "%s: VTOC: not supported: %s\n"

#define	D_VTOC_READ_SUCCESS "%s: VTOC: SUCCESS reading: %s\n"

#define	D_VTOC_UNKNOWN_RETCODE "%s: VTOC: READ: unknown return code: %s\n"

#define	D_EFI_READ_FAIL "%s: EFI: failed to read: %s\n"

#define	D_EFI_INVALID "%s: EFI: is INVALID: %s\n"

#define	D_EFI_UNKNOWN_ERR "%s: EFI: unknown error while reading: %s\n"

#define	D_EFI_NOTSUP "%s: EFI: not supported: %s\n"

#define	D_EFI_READ_SUCCESS "%s: EFI: SUCCESS reading: %s\n"

#define	D_EFI_UNKNOWN_RETCODE "%s: EFI: READ: unknown return code: %s\n"

#define	D_NOT_VTOC_OR_EFI "%s: disk has neither VTOC nor EFI: %s\n"

#define	D_SKIP_SLICE_NOTZERO "%s: skipping non-s0 slice: %s\n"

#define	D_FOUND_HOLE_SIGNLIST "%s: found hole %d in sign list.\n"

#define	D_ZERO_LEN_SIGNLIST "%s: generated zero length signlist: %s.\n"

#define	D_CREATED_ZFS_SIGN "%s: created ZFS sign: %s\n"

#define	D_CREATE_NEW_UFS "%s: created new UFS sign\n"

#define	D_CREATE_NEW_ZFS "%s: created new ZFS sign\n"

#define	D_CREATED_NEW_SIGN "%s: created new sign: %s\n"

#define	D_FOUND_IN_BACKUP "%s: found sign (%s) in backup.\n"

#define	D_NOT_FOUND_IN_EXIST_BACKUP \
	"%s: backup exists but sign %s not found\n"

#define	D_BACKUP_NOT_EXIST "%s: no backup file (%s) found.\n"

#define	D_BACKUP_DIR_NOEXIST "%s: backup dir (%s) does not exist.\n"

#define	D_SET_BACKUP_UFS "%s: setting UFS backup sign\n"

#define	D_SET_BACKUP_ZFS "%s: setting ZFS backup sign\n"

#define	D_PRIMARY_NOT_EXIST "%s: primary sign (%s) does not exist\n"

#define	D_PRIMARY_DIR_NOEXIST "%s: primary signdir (%s) does not exist\n"

#define	D_SET_PRIMARY_UFS "%s: setting UFS primary sign\n"

#define	D_SET_PRIMARY_ZFS "%s: setting ZFS primary sign\n"

#define	D_GET_TITLE "%s: got title: %s\n"

#define	D_GET_SPECIAL_NOT_IN_MNTTAB \
	"%s: Cannot get special file:  mount-point %s not in mnttab\n"

#define	D_GET_SPECIAL "%s: returning special: %s\n"

#define	D_MENU_WRITE_ENTER "%s: entered menu_write() for root: <%s>\n"

#define	D_GOT_SVC_STATUS "%s: got status for service: %s\n"

#define	D_SVC_ONLINE "%s: service is online: %s\n"

#define	D_SVC_NOT_ONLINE "%s: service is *NOT* online(%s): %s\n"

#define	D_SVC_ALREADY_ONLINE "%s: service is already online: %s\n"

#define	D_SVC_ONLINE_INITIATED "%s: initiated online of service: %s\n"

#define	D_SVC_NOW_ONLINE "%s: service is NOW online: %s\n"

#define	D_NOT_LU_BE "%s: not a Live Upgrade BE\n"

#define	D_NO_CKSUM_FILE "%s: checksum file absent: %s\n"

#define	D_CKSUM_FILE_OPENED "%s: opened checksum file: %s\n"

#define	D_CKSUM_FILE_READ "%s: read checksum file: %s\n"

#define	D_CKSUM_FILE_PARSED "%s: parsed checksum file: %s\n"

#define	D_CKSUM_GEN_SUCCESS "%s: successfully generated checksum\n"

#define	D_CKSUM_GEN_OUTPUT_VALID "%s: generated checksum output valid\n"

#define	D_CKSUM_GEN_PARSED "%s: successfully parsed generated checksum\n"

#define	D_CKSUM_NO_CHANGE "%s: no change in checksum of GRUB menu\n"

#define	D_CKSUM_HAS_CHANGED "%s: checksum of GRUB menu has changed\n"

#define	D_PROPAGATED_MENU "%s: successfully propagated GRUB menu\n"

#define	D_CREATED_BACKUP "%s: successfully created backup GRUB menu: %s\n"

#define	D_PROPAGATED_BACKUP "%s: successfully propagated backup GRUB menu: %s\n"

#define	D_CREATED_CKSUM_FILE "%s: successfully created checksum file: %s\n"

#define	D_PROPAGATED_CKSUM_FILE \
	"%s: successfully propagated checksum file: %s\n"

#define	D_PROPAGATED_BOOTADM \
	"%s: successfully propagated bootadm: %s\n"

#ifdef	__cplusplus
}
#endif

#endif /* _MESSAGE_H */
