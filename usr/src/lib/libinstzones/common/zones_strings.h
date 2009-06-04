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



#ifndef _ZONES_STRINGS_H
#define	_ZONES_STRINGS_H


/*
 * Module:	zones_strings.h
 * Group:	libinstzones
 * Description:	This header contains strings used in libinstzones
 *		library modules.
 */

#include <libintl.h>

/*
 * C++ prefix
 */

#ifdef __cplusplus
extern "C" {
#endif

/* constants */

#ifndef	TEXT_DOMAIN
#define	TEXT_DOMAIN	"SUNW_INSTALL_LIBZONES"
#endif

#ifndef ILIBSTR
#define	ILIBSTR(x)	dgettext(TEXT_DOMAIN, x)
#endif

/*
 * message strings
 */

/* BEGIN CSTYLED */

/*
 * I18N: these messages are debugging message and are only displayed
 * when special debugging output has been enabled - these messages
 * will never be displayed during normal product usage
 */

#define	DBG_ARG				ILIBSTR("argument <%d> = <%s>")
#define	DBG_LIBRARY_NOT_FOUND		ILIBSTR("unable to dlopen library <%s>: %s")
#define	DBG_MNTPT_NAMES			ILIBSTR("mount point for global zone path <%s> in zone <%s> is global zone mount point <%s> non-global zone mount point <%s>")
#define	DBG_PATHS_ADD_FS		ILIBSTR("add inherited file system entry <%d> path <%s>")
#define	DBG_PATHS_IS_INHERITED		ILIBSTR("path <%s> is inherited from <%s>")
#define	DBG_PATHS_IS_NOT_INHERITED	ILIBSTR("path <%s> in root <%s> not inherited")
#define	DBG_PATHS_NOT_INHERITED		ILIBSTR("path <%s> not inherited: no inherited file systems")
#define	DBG_TO_ZONEHALT			ILIBSTR("halting zone <%s>")
#define	DBG_TO_ZONEREADY		ILIBSTR("readying zone <%s>")
#define	DBG_TO_ZONERUNNING		ILIBSTR("running zone <%s>")
#define	DBG_TO_ZONEUNMOUNT		ILIBSTR("unmounting zone <%s>")
#define	DBG_UNMOUNTING_DEV		ILIBSTR("unmounting package device <%s>")
#define	DBG_ZONES_ADJLCKOBJ_EXIT	ILIBSTR("lock object <%s> adjusted to <%s> for root path <%s> resolved <%s>")
#define	DBG_ZONES_APLK			ILIBSTR("acquire lock zone <%s> lock <%s> pid <%ld>")
#define	DBG_ZONES_APLK_EXIT		ILIBSTR("acquire lock failure zone <%s> lock <%s> pid <%ld>: return <%d> status <%d> <%s>")
#define	DBG_ZONES_APLK_RESULTS		ILIBSTR("acquire lock success zone <%s> lock <%s> key <%s> results <%s>")
#define	DBG_ZONES_ARE_IMPLEMENTED	ILIBSTR("zones are implemented")
#define	DBG_ZONES_CHG_Z_STATE		ILIBSTR("change zone <%s> from state <%d> to state <%d>")
#define	DBG_ZONES_CHG_Z_STATE_ENTRY	ILIBSTR("change zone <%d> to state <%d>")
#define	DBG_ZONES_GET_ZONE_STATE	ILIBSTR("state of zone <%s> is <%ld>")
#define	DBG_ZONES_LCK_OBJ		ILIBSTR("lock zone object <%s> zone <%s> pid <%ld> locks <%s>")
#define	DBG_ZONES_LCK_OBJ_FOUND		ILIBSTR("lock zone examining object <%s> key <%s>: match")
#define	DBG_ZONES_LCK_OBJ_NOTFOUND	ILIBSTR("lock zone examining object <%s> key <%s>: NO MATCH")
#define	DBG_ZONES_LCK_OBJ_NOTHELD	ILIBSTR("object <%s> not locked on zone <%s>")
#define	DBG_ZONES_LCK_THIS		ILIBSTR("lock this zone flags <0x%08lx>")
#define	DBG_ZONES_LCK_ZONE		ILIBSTR("lock zone <%s> flags <0x%08lx>")
#define	DBG_ZONES_LCK_ZONES		ILIBSTR("lock zones flags <0x%08lx>")
#define	DBG_ZONES_LCK_ZONES_EXIST	ILIBSTR("locking all non-global zones defined")
#define	DBG_ZONES_LCK_ZONES_NOZONES	ILIBSTR("no zones locked: no non-global zones exist")
#define	DBG_ZONES_LCK_ZONES_UNIMP	ILIBSTR("no zones locked: zones are not implemented")
#define	DBG_ZONES_LCK_ZONE_PATCHADM	ILIBSTR("locking patch administration: zone <%s> object <%s>")
#define	DBG_ZONES_LCK_ZONE_PKGADM	ILIBSTR("locking package administration: zone <%s> object <%s>")
#define	DBG_ZONES_LCK_ZONE_ZONEADM	ILIBSTR("locking zone administration: zone <%s> object <%s>")
#define	DBG_ZONES_MOUNT_IN_LZ_ENTRY	ILIBSTR("mount in non-global zone: zone <%s> global-zone path <%s>")
#define	DBG_ZONES_NGZ_LIST_STATES	ILIBSTR("non-global zone <%s> current state <%d> kernel status <%d>")
#define	DBG_ZONES_NOT_IMPLEMENTED	ILIBSTR("zones are NOT implemented")
#define	DBG_ZONES_RELK			ILIBSTR("release lock zone <%s> lock <%s> key <%s>")
#define	DBG_ZONES_RELK_EXIT		ILIBSTR("release lock <%s> key <%s> to zone <%s>: return <%d> status <%d> results <%s>")
#define	DBG_ZONES_ULK_OBJ		ILIBSTR("unlock zone object <%s> zone <%s> locks <%s>")
#define	DBG_ZONES_ULK_OBJ_FOUND		ILIBSTR("unlock zone examining object <%s> key <%s>: match")
#define	DBG_ZONES_ULK_OBJ_NONE		ILIBSTR("no objects locked on zone <%s>")
#define	DBG_ZONES_ULK_OBJ_NOTFOUND	ILIBSTR("unlock zone examining object <%s> key <%s>: NO MATCH")
#define	DBG_ZONES_ULK_OBJ_NOTHELD	ILIBSTR("object <%s> not locked on zone <%s>")
#define	DBG_ZONES_ULK_THIS		ILIBSTR("unlock this zone flags <0x%08lx>")
#define	DBG_ZONES_ULK_ZONE		ILIBSTR("unlock zone <%s> flags <0x%08lx>")
#define	DBG_ZONES_ULK_ZONES		ILIBSTR("unlock zones flags <0x%08lx>")
#define	DBG_ZONES_ULK_ZONES_EXIST	ILIBSTR("unlocking all non-global zones defined")
#define	DBG_ZONES_ULK_ZONES_NOZONES	ILIBSTR("no zones unlocked: no non-global zones exist")
#define	DBG_ZONES_ULK_ZONES_UNIMP	ILIBSTR("no zones unlocked: zones are not implemented")
#define	DBG_ZONES_ULK_ZONE_PATCHADM	ILIBSTR("unlocking patch administration: zone <%s> object <%s>")
#define	DBG_ZONES_ULK_ZONE_PKGADM	ILIBSTR("unlocking package administration: zone <%s> object <%s>")
#define	DBG_ZONES_ULK_ZONE_ZONEADM	ILIBSTR("unlocking zone administration: zone <%s> object <%s>")
#define	DBG_ZONES_UNMOUNT_FROM_LZ_ENTRY	ILIBSTR("unmount non-global zone: mount point <%s>")
#define	DBG_ZONE_EXEC_CMD_ENTER		ILIBSTR("execute command <%s> on zone <%s> this zone <%s>")
#define DBG_BRANDS_ARE_IMPLEMENTED	ILIBSTR("brands are implemented")
#define DBG_BRANDS_NOT_IMPLEMENTED	ILIBSTR("brands are NOT implemented")

/*
 * I18N: these messages are error messages that can be displayed
 * during the normal usage of the products
 */

#define	ERR_CANNOT_CREATE_CONTRACT	ILIBSTR("unable to create contract: %s")
#define	ERR_CAPTURE_FILE		ILIBSTR("unable to open command output capture file <%s>: %s")
#define	ERR_FORK			ILIBSTR("unable to create new process: %s")
#define	ERR_GET_ZONEID			ILIBSTR("unable to get id of zone <%s>: %s")
#define	ERR_GZMOUNT_FAILED		ILIBSTR("unable to mount global path <%s> local path <%s> zone <%s>: %s")
#define	ERR_GZMOUNT_RESOLVEPATH		ILIBSTR("unable to determine zone <%s> dev path from <%s>: %s")
#define	ERR_GZMOUNT_SNPRINTFGMP_FAILED	ILIBSTR("unable to create global zone mount point <%s> from <%s> <%s> <%s>: combined path exceeds maximum length of <%ld>")
#define	ERR_GZMOUNT_SNPRINTFLMP_FAILED	ILIBSTR("unable to create local zone mount point <%s> from <%s>: combined path exceeds maximum length of <%ld>")
#define	ERR_GZMOUNT_SNPRINTFUUID_FAILED	ILIBSTR("unable to create uuid <%s>: combined uuid exceeds maximum length of <%ld>")
#define	ERR_GZMOUNT_SNPRINTF_FAILED	ILIBSTR("unable to create path <%s> from <%s>: combined path exceeds maximum length of <%ld>")
#define	ERR_GZPATH_NOT_ABSOLUTE		ILIBSTR("unable to mount global zone path <%s>: path must be absolute")
#define	ERR_GZPATH_NOT_DIR		ILIBSTR("unable to mount global zone path <%s>: %s")
#define	ERR_GZUMOUNT_FAILED		ILIBSTR("unable to unmount <%s>: %s")
#define	ERR_INHERITED_PATH_NOT_ABSOLUTE	ILIBSTR("inherited file system must be absolute path: <%s>")
#define	ERR_INHERITED_PATH_NOT_DIR	ILIBSTR("inherited file system <%s> must be absolute path to directory: %s")
#define	ERR_INHERITED_PATH_NULL		ILIBSTR("empty path specified for inherited file system: must be absolute path")
#define	ERR_LZMNTPT_NOTDIR		ILIBSTR("unable to unmount global zone mount point <%s>: %s")
#define	ERR_LZMNTPT_NOT_ABSOLUTE	ILIBSTR("unable to unmount <%s>: path must be absolute")
#define	ERR_LZROOT_NOTDIR		ILIBSTR("unable to use <%s> as zone root path: %s")
#define	ERR_MALLOC			ILIBSTR("unable to allocate %s memory, errno %d: %s")
#define	ERR_MEM				ILIBSTR("unable to allocate memory.")
#define	ERR_MEMORY	 		ILIBSTR("memory allocation failure, errno=%d")
#define	ERR_MNTPT_MKDIR			ILIBSTR("unable to create temporary mount point <%s> in zone <%s>: %s")
#define	ERR_NO_ZONE_ROOTPATH		ILIBSTR("unable to get root path of zone <%s>: %s")
#define	ERR_PKGDIR_GETHANDLE		ILIBSTR("unable to get inherited directories: zonecfg_get_handle: %s")
#define	ERR_PKGDIR_NOHANDLE		ILIBSTR("unable to get inherited directories: zonecfg_init_handle: %s")
#define	ERR_PKGDIR_SETIPDENT		ILIBSTR("unable to get inherited directories: zonecfg_setipdent: %s")
#define	ERR_ROOTPATH_EMPTY		ILIBSTR("unable to get root path of zone <%s>: empty path returned")
#define	ERR_ZEXEC_ASSEMBLE		ILIBSTR("unable to establish connection with zone <%s>: could not assemble new environment")
#define	ERR_ZEXEC_BADSTATE		ILIBSTR("unable to establish connection with zone <%s>: zone is in state '%s'")
#define	ERR_ZEXEC_BADZONE		ILIBSTR("unable to establish connection with zone <%s>: no such zone")
#define	ERR_ZEXEC_EFAULT		ILIBSTR("one or more file descriptors may be non-local (such as open across nfs): %s")
#define	ERR_ZEXEC_EXECFAILURE		ILIBSTR("unable to establish connection with zone <%s>: exec failure: %s")
#define	ERR_ZEXEC_GETPPRIV		ILIBSTR("unable to establish connection with zone <%s>: getppriv failed: %s")
#define	ERR_ZEXEC_GZUSED		ILIBSTR("unable to establish connection with zone <%s>: global zone specified")
#define	ERR_ZEXEC_NOROOTPATH		ILIBSTR("unable to establish connection with zone <%s>: cannot get root path: %s")
#define	ERR_ZEXEC_NOTRUNNING		ILIBSTR("unable to establish connection with zone <%s>: not running - in state '%s'")
#define	ERR_ZEXEC_NOT_IN_GZ		ILIBSTR("unable to establish connection with zone <%s>: not in the global zone")
#define	ERR_ZEXEC_NOZONEID		ILIBSTR("unable to establish connection with zone <%s>: cannot get zone id: %s")
#define	ERR_ZEXEC_PRIVS			ILIBSTR("unable to establish connection with zone <%s>: you lack sufficient privilege to access the zone")
#define	ERR_ZEXEC_PRIV_ALLOCSET		ILIBSTR("unable to establish connection with zone <%s>o: priv_allocset failed: %s")
#define	ERR_ZEXEC_ZONEENTER		ILIBSTR("unable to establish connection with zone <%s>: could not enter zone: %s")
#define	ERR_ZONEBOOT_CMD_ERROR		ILIBSTR("unable to boot zone: problem running <%s> on zone <%s>: error %d%s%s")
#define	ERR_ZONEBOOT_CMD_SIGNAL		ILIBSTR("unable to boot zone: problem running <%s> on zone <%s>: terminated by signal")
#define	ERR_ZONEBOOT_DIDNT_BOOT		ILIBSTR("unable to boot zone <%s>: zone failed to transition to running state")
#define	ERR_ZONEBOOT_EXEC               ILIBSTR("unable to boot zone: could not execute zone administration command <%s>: %s")
#define	ERR_ZONEHALT_EXEC		ILIBSTR("unable to halt zone: could not execute zone administration command <%s>: %s")
#define	ERR_ZONEINDEX_OPEN		ILIBSTR("unable to open zone index file %s: %s")
#define	ERR_ZONEREADY_CMDFAIL		ILIBSTR("unable to ready zone: problem running <%s> on zone <%s>: %s%s%s")
#define	ERR_ZONEREADY_DIDNT_READY	ILIBSTR("unable to ready zone <%s>: zone failed to transition to ready state")
#define	ERR_ZONEREADY_EXEC		ILIBSTR("unable to ready zone: could not execute zone administration command <%s>: %s")
#define	ERR_ZONEROOT_NOTDIR		ILIBSTR("unable to use temporary mount point <%s> in zone <%s>: %s")
#define	ERR_ZONES_LCK_THIS_PATCHADM	ILIBSTR("Unable to acquire patch administration lock for this system; try again later")
#define	ERR_ZONES_LCK_THIS_PKGADM	ILIBSTR("Unable to acquire package administration lock for this system; try again later")
#define	ERR_ZONES_LCK_THIS_ZONEADM	ILIBSTR("Unable to acquire zone administration lock for this system; please try again later")
#define	ERR_ZONES_LCK_ZONES_FAILED	ILIBSTR("Unable to acquire lock on non-global zone <%s>: releasing all locks")
#define	ERR_ZONES_LCK_ZONE_PATCHADM	ILIBSTR("Unable to acquire patch administration lock for zone <%s>; please try again later")
#define	ERR_ZONES_LCK_ZONE_PKGADM	ILIBSTR("Unable to acquire package administration lock for zone <%s>; please try again later")
#define	ERR_ZONES_LCK_ZONE_ZONEADM	ILIBSTR("Unable to acquire zone administration lock for zone <%s>; please try again later")
#define	ERR_ZONES_NOT_IMPLEMENTED	ILIBSTR("error: zones not implemented")
#define	ERR_ZONES_ULK_THIS_PACKAGE	ILIBSTR("Unable to release package administration lock for this system; try again later")
#define	ERR_ZONES_ULK_THIS_PATCH	ILIBSTR("Unable to release patch administration lock for this system; try again later")
#define	ERR_ZONES_ULK_THIS_ZONES	ILIBSTR("Unable to release zone administration lock for this system; please try again later")
#define	ERR_ZONE_LIST_EMPTY		ILIBSTR("empty zone list specified")
#define	ERR_ZONE_NAME_ILLEGAL		ILIBSTR("illegal zone name %.*s")
#define	ERR_ZONE_NONEXISTENT		ILIBSTR("zone %s does not exist")
#define ERR_INHERITED_PATH_TOO_LONG     ILIBSTR("inherited path too long current length <%d> maximum length <%d> bytes: <%s>")
#define	ERR_OPEN_READ			ILIBSTR("unable to open <%s> for reading: (%d) %s")
#define	ERR_ZONEUNMOUNT_CMD_SIGNAL	ILIBSTR("unable to unmount zone: problem running <%s> on zone <%s>: terminated by signal")
#define	ERR_ZONEUNMOUNT_EXEC		ILIBSTR("unable to unmount zone: could not execute zone administration command <%s>: %s")
#define	ERR_ZONEUNMOUNT_CMD_ERROR	ILIBSTR("unable to unmount zone: problem running <%s> on zone <%s>: error %d%s%s")
#define ERR_BRAND_GETBRAND	ILIBSTR("unable to get zone brand: zonecfg_get_brand: %s")

/*
 * I18N: these are messages that can be displayed during the normal
 * usage of the products
 */

#define	MSG_PROG_ERR			ILIBSTR("ERROR: %s")
#define	MSG_ZONES_LCK_THIS_PATCHADM	ILIBSTR("## Waiting for up to <%ld> seconds for patch administration commands to become available (another user is administering patches)")
#define	MSG_ZONES_LCK_THIS_PKGADM	ILIBSTR("## Waiting for up to <%ld> seconds for package administration commands to become available (another user is administering packages)")
#define	MSG_ZONES_LCK_THIS_ZONEADM	ILIBSTR("## Waiting for up to <%ld> seconds for zone administration commands to become available (another user is administering zones)")
#define	MSG_ZONES_LCK_ZONE_PATCHADM	ILIBSTR("## Waiting for up to <%ld> seconds for patch administration commands to become available (another user is administering patches on zone <%s>)")
#define	MSG_ZONES_LCK_ZONE_PKGADM	ILIBSTR("## Waiting for up to <%ld> seconds for package administration commands to become available (another user is administering packages on zone <%s>)")
#define	MSG_ZONES_LCK_ZONE_ZONEADM	ILIBSTR("## Waiting for up to <%ld> seconds for zone administration commands to become available (another user is administering zones on zone <%s>)")

/*
 * I18N: these messages are warning messages that can be displayed
 * during the normal usage of the products
 */

#define	WRN_ZONES_ULK_ZONE_PATCHADM	ILIBSTR("WARNING: Unable to release patch administration lock for zone <%s>")
#define	WRN_ZONES_ULK_ZONE_PKGADM	ILIBSTR("WARNING: Unable to release package administration lock for zone <%s>")
#define	WRN_ZONES_ULK_ZONE_ZONEADM	ILIBSTR("WARNING: Unable to release zone administration lock for zone <%s>")

/* END CSTYLED */

/*
 * C++ postfix
 */

#ifdef __cplusplus
}
#endif

#endif	/* _ZONES_STRINGS_H */
