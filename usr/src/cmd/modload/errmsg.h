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
 */

#ifndef	_ERRMSG_H
#define	_ERRMSG_H

#ifdef	__cplusplus
extern "C" {
#endif

/* text for gettext error messages for adddrv.c and remdrv.c */

#define	USAGE	"Usage:\n"\
"	add_drv [ -m '<permission> ','<...>' ]\n"\
"		[ -n ]\n"\
"		[ -f ]\n"\
"		[ -v ]\n"\
"		[ -i '<identify_name  <...>' ] \n"\
"		[ -b <basedir> ]\n"\
"		[ -c <class_name> ]\n"\
"		[ -p <dev_policy> ]\n"\
"		<driver_module>\n"\
"Example:\n"\
"	add_drv -m '* 0666 bin bin' -i 'acme,sd new,sd' sd \n"\
"	Add 'sd' drive with identify names: acme,sd and new,sd.\n"\
"	Every minor node will have the permission 0666,\n"\
"	and be owned by bin with group bin.\n"

#define	BOOT_CLIENT	"Reboot client to install driver.\n"
#define	DRIVER_INSTALLED	"Driver (%s) installed.\n"

#define	ERR_INSTALL_FAIL	"Error: Could not install driver (%s).\n"
#define	ERR_DRVNAME_TOO_LONG	"Error: driver name must not exceed (%d)" \
" characters; driver name too long (%s)\n"
#define	ERR_ALIAS_IN_NAM_MAJ	\
"Alias (\"%s\") already in use as driver name.\n"
#define	ERR_ALIAS_IN_USE	\
"(\"%s\") already in use as a driver or alias.\n"
#define	ERR_CANT_ACCESS_FILE	"Cannot access file (%s).\n"
#define	ERR_BAD_PATH	"Bad syntax for pathname : (%s)\n"
#define	ERR_FORK_FAIL	"Fork failed; cannot exec : %s\n"
#define	ERR_PROG_IN_USE	"add_drv/rem_drv currently busy; try later\n"
#define	ERR_NOT_ROOT	"You must be root to run this program.\n"
#define	ERR_BAD_LINE	"Bad line in file %s : %s\n"
#define	ERR_CANNOT_OPEN	"Cannot open (%s): %s.\n"
#define	ERR_MIS_TOK	"Option (%s) : missing token: (%s)\n"
#define	ERR_BAD_TOK	"Option (%s) : bad token: (%s)\n"
#define	ERR_TOO_MANY_ARGS	"Option (%s) : too many arguments: (%s)\n"
#define	ERR_BAD_MODE	"Bad mode: (%s)\n"
#define	ERR_CANT_OPEN	"Cannot open (%s)\n"
#define	ERR_NO_UPDATE	"Cannot update (%s)\n"
#define	ERR_CANT_RM	"Cannot remove temporary file (%s); remove by hand.\n"
#define	ERR_BAD_LINK	"(%s) exists as (%s); Please rename by hand.\n"
#define	ERR_NO_MEM		"Not enough memory\n"
#define	ERR_DEL_ENTRY	"Cannot delete entry for driver (%s) from file (%s).\n"
#define	ERR_NO_ENTRY	"No entry found for driver (%s) in file (%s).\n"
#define	ERR_INT_UPDATE	"Internal error updating (%s).\n"
#define	ERR_NOMOD	"Cannot find module (%s).\n"
#define	ERR_MAX_MAJOR	"Cannot get major device information.\n"
#define	ERR_NO_FREE_MAJOR	"No available major numbers.\n"
#define	ERR_NOT_UNIQUE	"Driver (%s) is already installed.\n"
#define	ERR_NOT_INSTALLED "Driver (%s) not installed.\n"
#define	ERR_UPDATE	"Cannot update (%s).\n"
#define	ERR_MAX_EXCEEDS "Major number (%d) exceeds maximum (%d).\n"
#define	ERR_NO_CLEAN	"Cannot update; check file %s and rem_drv %s by hand.\n"
#define	ERR_CONFIG	\
"Warning: Driver (%s) successfully added to system but failed to attach\n"
#define	ERR_DEVTREE	\
"Warning: Unable to check for driver configuration conflicts.\n"
#define	ERR_MODPATH	"System error: Could not get module path.\n"
#define	ERR_BAD_MAJNUM	\
"Warning: Major number (%d) inconsistent with /etc/name_to_major file.\n"
#define	ERR_MAJ_TOOBIG	"Warning: Entry '%s %llu' in %s has a major number " \
			"larger\nthan the maximum allowed value %u.\n"

#define	ERR_CREAT_LOCK	"Failed to create lock file(%s): %s\n"
#define	ERR_LOCK	"Failed to lock the lock file(%s): %s\n"
#define	ERR_UNLOCK	"Failed to unlock the lock file(%s): %s\n"

#define	ERR_LOCATION	\
"Warning: %s-bit version of driver found at %s.\n"
#define	ERR_ISA_MISMATCH	"No %s-bit version of (%s) found; %s-bit " \
				"version of this driver exists.\n"
#define	ERR_NOT_LOADABLE	\
"%s-bit driver (%s) not loadable on %s-bit kernel.\n"
#define	ERR_ELF_VERSION "ELF library out of date : %s. \n"
#define	ERR_ELF_KIND	"The file (%s) is not in ELF format.\n"
#define	ERR_KERNEL_ISA	"Could not identify kernel's ISA. \n"
#define	ERR_CONFIG_NOLOAD	\
"System configuration files modified but %s driver not loaded or attached.\n"
#define	ERR_SOL_LOCATION	\
"Place (%s) driver in correct location and run devfsadm -i %s.\n"
#define	ERR_ARCH_NOT_SUPPORTED	"Architecture %s not supported by add_drv.\n"
#define	ERR_SYSINFO_ARCH	"Failed to identify system architecture.\n"
#define	ERR_PATH_SPEC	"Error: driver may not be specified by path (%s)\n"
#define	ERR_CREATE_RECONFIG	"Error: Could not create /reconfigure.\n"

/* update_drv messages */
#define	UPD_DRV_USAGE	\
	"Usage:\tupdate_drv [ -f | -v ] <driver_module>\n" \
	"\tupdate_drv [ -b basedir ] [ -f | -v | -n ] -a\n" \
		"\t\t[-m 'permission'] [-i 'identify_name']\n" \
		"\t\t[-P privilege] [-p 'policy']  <driver_module>\n" \
	"\tupdate_drv [ -b basedir ] [ -f | -v | -n ] -d\n" \
		"\t\t[-m 'permission'] [-i 'identify_name']\n" \
		"\t\t[-P privilege] [-p 'policy']  <driver_module>\n\n"\
	"NOTE: at least one of m/i/P/p must be specified with -a and -d.\n"

#define	FORCE_UPDATE	"Forcing update of %s.conf.\n"
#define	ERR_DRVCONF	"Failed to update %s.conf for driver.\n"
#define	DRVCONF_UPDATED	"%s.conf updated in the kernel.\n"
#define	NOUPDATE	"%s.conf not updated in the kernel\n"

/* remdrv messages */

#define	REM_USAGE1	\
	"Usage:\n\t rem_drv [ -C ] [ -b <basedir> ] [ -n ] driver_name\n"
#define	ERR_NO_MAJ	"Cannot get major number for :  %s\n"
#define	ERR_UNLINK	"Warning: Cannot remove %s from devfs namespace.\n"
#define	ERR_PIPE	"System error : Cannot create pipe\n"
#define	ERR_EXEC	"System error : Exec failed\n"
#define	ERR_DEVFSCLEAN  \
"Warning: Cannot remove entries from devfs namespace for driver : %s.\n"
#define	ERR_DEVFSALCLEAN  \
"Warning: Cannot remove alias entries from devfs namespace for driver : %s .\n"
#define	ERR_MODID	"Cannot get modid for : (%s)\n"
#define	ERR_MODUN	\
	"Cannot unload module: %s\nWill be unloaded upon reboot.\n"
#define	ERR_MODREMMAJ	"Cannot remove major number binding for %d\n"
#define	ERR_NOENTRY	"Cannot find (%s) in file : %s\n"

/* drvsubr messages */
#define	ERR_NOFILE	"Warning: (%s) file missing.\n"
#define	ERR_NO_SPACE	\
"Can't have space within double quote: %s. \
Use octal escape sequence \"\\040\".\n"

#define	ERR_PRIVIMPL	"Cannot get privilege information.\n"
#define	ERR_BAD_MINOR	"Minor device specification cannot include ``:''.\n"
#define	ERR_BAD_TOKEN	"Bad policy token: ``%s''.\n"
#define	ERR_BAD_PRIVS	"Error in privilege set specification: %.*s[HERE->]%s\n"
#define	ERR_INVALID_PLCY	"Invalid policy specification\n"
#define	ERR_ONLY_ONE	"Only one policy entry allowed per invocation\n"
#define	ERR_NO_EQUALS	"Missing equal sign in token ``%s''\n"
#define	ERR_BAD_PRIV	"Cannot allocate privilege ``%s'': %s\n"

#define	ERR_UPDATE_PERM		\
	"kernel update of permissions for driver %s failed (%d)\n"

#define	ERR_REMDRV_CLEANUP	\
	"post-rem_drv devfs cleanup for driver %s failed (%d)\n"

#define	ERR_PATH_ORIENTED_ALIAS	\
	"no device at specified path-oriented alias \"%s\"\n"

#ifdef	__cplusplus
}
#endif

#endif	/* _ERRMSG_H */
