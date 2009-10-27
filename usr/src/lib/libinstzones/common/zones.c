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


/*
 * Module:	zones.c
 * Group:	libinstzones
 * Description:	Provide "zones" interface for install consolidation code
 *
 * Public Methods:
 *  z_create_zone_admin_file - Given a location to create the file, and
 *	optionally an existing administration file, generate an
 *	administration file that can be used to perform "non-interactive"
 *	operations in a non-global zone.
 *  z_free_zone_list - free contents of zoneList_t object
 *  z_get_nonglobal_zone_list - return zoneList_t object describing all
 *	non-global native zones
 *  z_get_nonglobal_zone_list_by_brand - return zoneList_t object describing
 *      all non-global zones matching the list of zone brands passed in.
 *  z_free_brand_list - free contents of a zoneBrandList_t object
 *  z_make_brand_list - return a zoneBrandList_t object describing the list
 *	of all zone brands passed in.
 *  z_get_zonename - return the name of the current zone
 *  z_global_only - Determine if the global zone is only zone on the spec list
 *  z_lock_this_zone - lock this zone
 *  z_lock_zones - lock specified zones
 *  z_mount_in_lz - Mount global zone directory in specified zone's root file
 *	system
 *  z_non_global_zones_exist - Determine if any non-global native zones exist
 *  z_on_zone_spec - Determine if named zone is on the zone_spec list
 *  z_running_in_global_zone - Determine if running in the "global" zone
 *  z_set_output_functions - Link program specific output functions
 *  z_set_zone_root - Set root for zones library operations
 *  z_set_zone_spec - Set list of zones on which actions will be performed
 *  z_umount_lz_mount - Unmount directory mounted with z_mount_in_lz
 *  z_unlock_this_zone - unlock this zone
 *  z_unlock_zones - unlock specified zones
 *  z_verify_zone_spec - Verify list of zones on which actions will be performed
 *  z_zlist_change_zone_state - Change the current state of the specified zone
 *  z_zlist_get_current_state - Determine the current kernel state of the
 *	specified zone
 *  z_zlist_get_inherited_pkg_dirs - Determine directories inherited by
 *	specified zone
 *  z_zlist_get_original_state - Return the original kernal state of the
 *	specified zone
 *  z_zlist_get_scratch - Determine name of scratch zone
 *  z_zlist_get_zonename - Determine name of specified zone
 *  z_zlist_get_zonepath - Determine zonepath of specified zone
 *  z_zlist_restore_zone_state - Return the zone to the state it was originally
 *	in
 *  z_zone_exec - Execute a Unix command in a specified zone and return results
 *  z_zones_are_implemented - Determine if any zone operations can be performed
 *  z_is_zone_branded - determine if zone has a non-native brand
 *  z_is_zone_brand_in_list - determine if the zone's brand matches the
 *      brand list passed in.
 *  z_brands_are_implemented - determine if branded zones are implemented on
 *			this system
 */

/*
 * System includes
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <limits.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <stropts.h>
#include <wait.h>
#include <zone.h>
#include <sys/brand.h>
#include <libintl.h>
#include <locale.h>
#include <libzonecfg.h>
#include <libcontract.h>
#include <sys/contract/process.h>
#include <sys/ctfs.h>
#include <assert.h>
#include <dlfcn.h>
#include <link.h>
#include <time.h>

/*
 * local includes
 */

/*
 * When _INSTZONES_LIB_Z_DEFINE_GLOBAL_DATA is defined,
 * instzones_lib.h will define the z_global_data structure.
 * Otherwise an extern to the structure is inserted.
 */

#define	_INSTZONES_LIB_Z_DEFINE_GLOBAL_DATA
#include "instzones_lib.h"
#include "zones_strings.h"

/*
 * Private structures
 */

#define	CLUSTER_BRAND_NAME	"cluster"

/* maximum number of arguments to exec() call */

#define	UUID_FORMAT	"%02d%02d%02d%03d-%02d%02d%02d%d-%016llx"

/*
 * Library Function Prototypes
 */

#define	streq(a, b) (strcmp((a), (b)) == 0)

/*
 * Local Function Prototypes
 */

/*
 * global internal (private) declarations
 */

/*
 * *****************************************************************************
 * global external (public) functions
 * *****************************************************************************
 */

/*
 * Name:	z_create_zone_admin_file
 * Description:	Given a location to create the file, and optionally an existing
 *		administration file, generate an administration file that
 *		can be used to perform "non-interactive" operations in a
 *		non-global zone.
 * Arguments:	a_zoneAdminFilename - pointer to string representing the
 *			full path of zone admin file to create
 *		a_userAdminFilename - pointer to string representing the path
 *			to an existing "user" administration file - the
 *			administration file created will contain the
 *			settings contained in this file, modified as
 *			appropriate to supress any interaction;
 *			If this is == NULL then the administration file
 *			created will not contain any extra settings
 * Returns:	boolean_t
 *			== B_TRUE - admin file created
 *			== B_FALSE - failed to create admin file
 */

boolean_t
z_create_zone_admin_file(char *a_zoneAdminFilename, char *a_userAdminFilename)
{
	FILE	*zFp;
	FILE	*uFp = (FILE *)NULL;

	/* entry assertions */

	assert(a_zoneAdminFilename != NULL);
	assert(*a_zoneAdminFilename != '\0');

	/* create temporary zone admin file */

	zFp = fopen(a_zoneAdminFilename, "w");
	if (zFp == (FILE *)NULL) {
		return (B_FALSE);
	}

	/* open user admin file if specified */

	if (a_userAdminFilename != (char *)NULL) {
		uFp = fopen(a_userAdminFilename, "r");
	}

	/* create default admin file for zone pkg ops if no user admin file */

	if (uFp == (FILE *)NULL) {
		/* create default admin file */
		(void) fprintf(zFp, "action=nocheck\nauthentication=nocheck\n"
		    "basedir=default\nconflict=nocheck\nidepend=nocheck\n"
		    "instance=unique\npartial=nocheck\nrdepend=nocheck\n"
		    "runlevel=nocheck\nsetuid=nocheck\nspace=nocheck\n"
		    "mail=\n");
	} else for (;;) {
		/* copy user admin file substitute/change appropriate entries */
		char	buf[LINE_MAX+1];
		char	*p;

		/* read next line of user admin file */

		p = fgets(buf, sizeof (buf), uFp);
		if (p == (char *)NULL) {
			(void) fclose(uFp);
			break;
		}

		/* modify / replace / accept as appropriate */

		if (strncmp(buf, "instance=quit", 13) == 0) {
			(void) fprintf(zFp, "%s", "instance=unique\n");
			/*LINTED*/
		} else if (strncmp(buf, "keystore=", 9) == 0) {
		} else if (strncmp(buf, "action=", 7) == 0) {
			(void) fprintf(zFp, "action=nocheck\n");
		} else if (strncmp(buf, "authentication=", 15) == 0) {
			(void) fprintf(zFp, "authentication=nocheck\n");
		} else if (strncmp(buf, "conflict=", 9) == 0) {
			(void) fprintf(zFp, "conflict=nocheck\n");
		} else if (strncmp(buf, "idepend=", 8) == 0) {
			(void) fprintf(zFp, "idepend=nocheck\n");
		} else if (strncmp(buf, "mail=", 5) == 0) {
			(void) fprintf(zFp, "mail=\n");
		} else if (strncmp(buf, "partial=", 8) == 0) {
			(void) fprintf(zFp, "partial=nocheck\n");
		} else if (strncmp(buf, "rdepend=", 8) == 0) {
			(void) fprintf(zFp, "rdepend=nocheck\n");
		} else if (strncmp(buf, "runlevel=", 9) == 0) {
			(void) fprintf(zFp, "runlevel=nocheck\n");
		} else if (strncmp(buf, "setuid=", 7) == 0) {
			(void) fprintf(zFp, "setuid=nocheck\n");
		} else if (strncmp(buf, "space=", 6) == 0) {
			(void) fprintf(zFp, "space=nocheck\n");
		} else {
			(void) fprintf(zFp, "%s", buf);
		}
	}

	/* close admin file and return success */

	(void) fclose(zFp);
	return (B_TRUE);
}

/*
 * Name:	z_brands_are_implemented
 * Description:	Determine if any branded zones may be present
 * Arguments:	void
 * Returns:	boolean_t
 *			== B_TRUE - branded zones are supported
 *			== B_FALSE - branded zones are not supported
 */

boolean_t
z_brands_are_implemented(void)
{
static	boolean_t	_brandsImplementedDetermined = B_FALSE;
static	boolean_t	_brandsAreImplemented = B_FALSE;

	/* if availability has not been determined, cache it now */

	if (!_brandsImplementedDetermined) {
		_brandsImplementedDetermined = B_TRUE;
		_brandsAreImplemented = _z_brands_are_implemented();
		if (_brandsAreImplemented) {
			_z_echoDebug(DBG_BRANDS_ARE_IMPLEMENTED);
		} else {
			_z_echoDebug(DBG_BRANDS_NOT_IMPLEMENTED);
		}
	}

	/* return cached answer */

	return (_brandsAreImplemented);
}

/*
 * Name:	z_free_zone_list
 * Description:	free contents of zoneList_t object
 * Arguments:	a_zlst - handle to zoneList_t object to free
 * Returns:	void
 */

void
z_free_zone_list(zoneList_t a_zlst)
{
	int	numzones;

	/* ignore empty list */

	if (a_zlst == (zoneList_t)NULL) {
		return;
	}

	/* free each entry in the zone list */

	for (numzones = 0; a_zlst[numzones]._zlName != (char *)NULL;
	    numzones++) {
		zoneListElement_t *zelm = &a_zlst[numzones];

		/* free zone name string */

		free(zelm->_zlName);

		/* free zonepath string */

		if (zelm->_zlPath != (char *)NULL) {
			free(zelm->_zlPath);
		}

		/* free list of inherited package directories */

		if (zelm->_zlInheritedDirs != (char **)NULL) {
			int	n;

			for (n = 0;
			    (zelm->_zlInheritedDirs)[n] != (char *)NULL;
			    n++) {
				(void) free((zelm->_zlInheritedDirs)[n]);
			}
			(void) free(zelm->_zlInheritedDirs);
		}
	}

	/* free handle to the list */

	free(a_zlst);
}

/*
 * Name:	z_get_nonglobal_zone_list
 * Description: return zoneList_t object describing all non-global
 *              native zones - branded zones are not included in list
 * Arguments:	None.
 * Returns:	zoneList_t
 *			== NULL - error, list could not be generated
 *			!= NULL - success, list returned
 * NOTE:    	Any zoneList_t returned is placed in new storage for the
 *		calling function. The caller must use 'z_free_zone_list' to
 *		dispose of the storage once the list is no longer needed.
 */

zoneList_t
z_get_nonglobal_zone_list(void)
{
	zoneList_t zones;
	zoneBrandList_t *brands = NULL;

	if ((brands = z_make_brand_list("native cluster", " ")) == NULL)
		return (NULL);

	zones = z_get_nonglobal_zone_list_by_brand(brands);

	z_free_brand_list(brands);

	return (zones);
}

/*
 * Name:	z_free_brand_list
 * Description: Free contents of zoneBrandList_t object
 * Arguments:	brands - pointer to zoneBrandList_t object to free
 * Returns: 	void
 */
void
z_free_brand_list(zoneBrandList_t *brands)
{
	while (brands != NULL) {
		zoneBrandList_t *temp = brands;
		free(brands->string_ptr);
		brands = brands->next;
		free(temp);
	}
}

/*
 * Name:	z_make_brand_list
 * Description:	Given a string with a list of brand name delimited by
 *		the delimeter passed in, build a zoneBrandList_t structure
 *		with the list of brand names and return it to the caller.
 * Arguments:
 *		brands - const char pointer to string list of brand names
 *		delim - const char pointer to string representing the
 *			delimeter for brands string.
 * Returns:	zoneBrandList_t *
 *			== NULL - error, list could not be generated
 *			!= NULL - success, list returned
 * NOTE:	Any zoneBrandList_t returned is placed in new storage for the
 *		calling function.  The caller must use 'z_free_brand_list' to
 *		dispose of the storage once the list is no longer needed.
 */
zoneBrandList_t *
z_make_brand_list(const char *brands, const char *delim)
{
	zoneBrandList_t *brand = NULL, *head = NULL;
	char		*blist = NULL;
	char		*str = NULL;

	if ((blist = strdup(brands)) == NULL)
		return (NULL);

	if ((str = strtok(blist, delim)) != NULL) {
		if ((brand = (zoneBrandList_t *)
		    malloc(sizeof (struct _zoneBrandList))) == NULL) {
			return (NULL);
		}

		head = brand;
		brand->string_ptr = strdup(str);
		brand->next = NULL;

		while ((str = strtok(NULL, delim)) != NULL) {
			if ((brand->next = (zoneBrandList_t *)
			    malloc(sizeof (struct _zoneBrandList))) == NULL) {
				return (NULL);
			}

			brand = brand->next;
			brand->string_ptr = strdup(str);
			brand->next = NULL;
		}
	}

	free(blist);
	return (head);
}

/*
 * Name:	z_get_nonglobal_zone_list_by_brand
 * Description: return zoneList_t object describing all non-global
 *              zones matching the list of brands passed in.
 * Arguments:	brands - The list of zone brands to look for.
 * Returns:	zoneList_t
 *			== NULL - error, list could not be generated
 *			!= NULL - success, list returned
 * NOTE:    	Any zoneList_t returned is placed in new storage for the
 *		calling function. The caller must use 'z_free_zone_list' to
 *		dispose of the storage once the list is no longer needed.
 */
zoneList_t
z_get_nonglobal_zone_list_by_brand(zoneBrandList_t *brands)
{
	FILE		*zoneIndexFP;
	int		numzones = 0;
	struct zoneent	*ze;
	zoneList_t	zlst = NULL;
	FILE		*mapFP;
	char		zonename[ZONENAME_MAX];
	zone_spec_t	*zent;

	/* if zones are not implemented, return empty list */

	if (!z_zones_are_implemented()) {
		return ((zoneList_t)NULL);
	}

	/*
	 * Open the zone index file.  Note that getzoneent_private() handles
	 * NULL.
	 */
	zoneIndexFP = setzoneent();

	mapFP = zonecfg_open_scratch("", B_FALSE);

	/* index file open; scan all zones; see if any are at least installed */

	while ((ze = getzoneent_private(zoneIndexFP)) != NULL) {
		zone_state_t	st;

		/* skip the global zone */

		if (strcmp(ze->zone_name, GLOBAL_ZONENAME) == 0) {
			free(ze);
			continue;
		}

		/*
		 * skip any zones with brands not on the brand list
		 */
		if (!z_is_zone_brand_in_list(ze->zone_name, brands)) {
			free(ze);
			continue;
		}

		/*
		 * If the user specified an explicit zone list, then ignore any
		 * zones that aren't on that list.
		 */
		if ((zent = _z_global_data._zone_spec) != NULL) {
			while (zent != NULL) {
				if (strcmp(zent->zl_name, ze->zone_name) == 0)
					break;
				zent = zent->zl_next;
			}
			if (zent == NULL) {
				free(ze);
				continue;
			}
		}

		/* non-global zone: create entry for this zone */

		if (numzones == 0) {
			zlst = (zoneList_t)_z_calloc(
			    sizeof (zoneListElement_t)*2);
		} else {
			zlst = (zoneList_t)_z_realloc(zlst,
			    sizeof (zoneListElement_t)*(numzones+2));
			(void) memset(&zlst[numzones], 0L,
			    sizeof (zoneListElement_t)*2);
		}

		/*
		 * remember the zone name, zonepath and the current
		 * zone state of the zone.
		 */
		zlst[numzones]._zlName = _z_strdup(ze->zone_name);
		zlst[numzones]._zlPath = _z_strdup(ze->zone_path);
		zlst[numzones]._zlOrigInstallState = ze->zone_state;
		zlst[numzones]._zlCurrInstallState = ze->zone_state;

		/* get the zone kernel status */

		if (zone_get_state(ze->zone_name, &st) != Z_OK) {
			st = ZONE_STATE_INCOMPLETE;
		}

		_z_echoDebug(DBG_ZONES_NGZ_LIST_STATES,
		    ze->zone_name, ze->zone_state, st);

		/*
		 * For a scratch zone, we need to know the kernel zone name.
		 */
		if (zonecfg_in_alt_root() && mapFP != NULL &&
		    zonecfg_find_scratch(mapFP, ze->zone_name,
		    zonecfg_get_root(), zonename, sizeof (zonename)) != -1) {
			free(zlst[numzones]._zlScratchName);
			zlst[numzones]._zlScratchName = _z_strdup(zonename);
		}

		/*
		 * remember the current kernel status of the zone.
		 */

		zlst[numzones]._zlOrigKernelStatus = st;
		zlst[numzones]._zlCurrKernelStatus = st;

		zlst[numzones]._zlInheritedDirs =
		    _z_get_inherited_dirs(ze->zone_name);

		numzones++;
		free(ze);
	}

	/* close the index file */
	endzoneent(zoneIndexFP);

	if (mapFP != NULL)
		zonecfg_close_scratch(mapFP);

	/* return generated list */

	return (zlst);
}

/*
 * Name:	z_get_zonename
 * Description:	return the name of the current zone
 * Arguments:	void
 * Returns:	char *
 *			- pointer to string representing the name of the current
 *			zone
 * NOTE:    	Any string returned is placed in new storage for the
 *		calling function. The caller must use 'Free' to dispose
 *		of the storage once the string is no longer needed.
 */

char *
z_get_zonename(void)
{
	ssize_t		zonenameLen;
	char		zonename[ZONENAME_MAX];
	zoneid_t	zoneid = (zoneid_t)-1;

	/* if zones are not implemented, return "" */

	if (!z_zones_are_implemented()) {
		return (_z_strdup(""));
	}

	/* get the zone i.d. of the current zone */

	zoneid = getzoneid();

	/* get the name of the current zone */

	zonenameLen = getzonenamebyid(zoneid, zonename, sizeof (zonename));

	/* return "" if could not get zonename */

	if (zonenameLen < 1) {
		return (_z_strdup(""));
	}

	return (_z_strdup(zonename));
}

/*
 * Name:	z_global_only
 * Description:	Determine if the global zone is only zone on the spec list.
 * Arguments:	None
 * Returns:	B_TRUE if global zone is the only zone on the list,
 *		B_FALSE otherwise.
 */

boolean_t
z_global_only(void)
{
	/* return true if zones are not implemented - treate as global zone */

	if (!z_zones_are_implemented()) {
		return (B_TRUE);
	}

	/* return true if this is the global zone */

	if (_z_global_data._zone_spec != NULL &&
	    _z_global_data._zone_spec->zl_next == NULL &&
	    strcmp(_z_global_data._zone_spec->zl_name, GLOBAL_ZONENAME) == 0) {
		return (B_TRUE);
	}

	/* return false - not the global zone */

	return (B_FALSE);
}

/*
 * Name:	z_lock_this_zone
 * Description:	lock this zone
 * Arguments:	a_lflags - [RO, *RO] - (ZLOCKS_T)
 *			Flags indicating which locks to acquire
 * Returns:	boolean_t
 *			== B_TRUE - success specified locks acquired
 *			== B_FALSE - failure specified locks not acquired
 * NOTE: the lock objects for "this zone" are maintained internally.
 */

boolean_t
z_lock_this_zone(ZLOCKS_T a_lflags)
{
	boolean_t	b;
	char		*zoneName;
	pid_t		pid = (pid_t)0;

	/* entry assertions */

	assert(a_lflags != ZLOCKS_NONE);

	/* entry debugging info */

	_z_echoDebug(DBG_ZONES_LCK_THIS, a_lflags);

	zoneName = z_get_zonename();
	pid = getpid();

	/* lock zone administration */

	if (a_lflags & ZLOCKS_ZONE_ADMIN) {
		b = _z_lock_zone_object(&_z_global_data._z_ObjectLocks,
		    zoneName, LOBJ_ZONEADMIN, pid,
		    MSG_ZONES_LCK_THIS_ZONEADM,
		    ERR_ZONES_LCK_THIS_ZONEADM);
		if (!b) {
			(void) free(zoneName);
			return (B_FALSE);
		}
	}

	/* lock package administration always */

	if (a_lflags & ZLOCKS_PKG_ADMIN) {
		b = _z_lock_zone_object(&_z_global_data._z_ObjectLocks,
		    zoneName, LOBJ_PKGADMIN, pid,
		    MSG_ZONES_LCK_THIS_PKGADM,
		    ERR_ZONES_LCK_THIS_PKGADM);
		if (!b) {
			(void) z_unlock_this_zone(a_lflags);
			(void) free(zoneName);
			return (B_FALSE);
		}
	}

	/* lock patch administration always */

	if (a_lflags & ZLOCKS_PATCH_ADMIN) {
		b = _z_lock_zone_object(&_z_global_data._z_ObjectLocks,
		    zoneName, LOBJ_PATCHADMIN, pid,
		    MSG_ZONES_LCK_THIS_PATCHADM,
		    ERR_ZONES_LCK_THIS_PATCHADM);
		if (!b) {
			(void) z_unlock_this_zone(a_lflags);
			(void) free(zoneName);
			return (B_FALSE);
		}
	}

	(void) free(zoneName);

	return (B_TRUE);
}

/*
 * Name:	z_lock_zones
 * Description:	lock specified zones
 * Arguments:	a_zlst - zoneList_t object describing zones to lock
 *		a_lflags - [RO, *RO] - (ZLOCKS_T)
 *			Flags indicating which locks to acquire
 * Returns:	boolean_t
 *			== B_TRUE - success, zones locked
 *			== B_FALSE - failure, zones not locked
 */

boolean_t
z_lock_zones(zoneList_t a_zlst, ZLOCKS_T a_lflags)
{
	boolean_t	b;
	int		i;

	/* entry assertions */

	assert(a_lflags != ZLOCKS_NONE);

	/* entry debugging info */

	_z_echoDebug(DBG_ZONES_LCK_ZONES, a_lflags);

	/* if zones are not implemented, return TRUE */

	if (z_zones_are_implemented() == B_FALSE) {
		_z_echoDebug(DBG_ZONES_LCK_ZONES_UNIMP);
		return (B_TRUE);
	}

	/* lock this zone first before locking other zones */

	b = z_lock_this_zone(a_lflags);
	if (b == B_FALSE) {
		return (b);
	}

	/* ignore empty list */

	if (a_zlst == (zoneList_t)NULL) {
		_z_echoDebug(DBG_ZONES_LCK_ZONES_NOZONES);
		return (B_FALSE);
	}

	/* zones exist */

	_z_echoDebug(DBG_ZONES_LCK_ZONES_EXIST);

	/*
	 * lock each listed zone that is currently running
	 */

	for (i = 0; (a_zlst[i]._zlName != (char *)NULL); i++) {
		/* ignore zone if already locked */
		if (a_zlst[i]._zlStatus & ZST_LOCKED) {
			continue;
		}

		/* ignore zone if not running */
		if (a_zlst[i]._zlCurrKernelStatus != ZONE_STATE_RUNNING &&
		    a_zlst[i]._zlCurrKernelStatus != ZONE_STATE_MOUNTED) {
			continue;
		}

		/*
		 * mark zone locked - if interrupted out during lock, an attempt
		 * will be made to release the lock
		 */
		a_zlst[i]._zlStatus |= ZST_LOCKED;

		/* lock this zone */
		b = _z_lock_zone(&a_zlst[i], a_lflags);

		/* on failure unlock all zones and return error */
		if (b != B_TRUE) {
			_z_program_error(ERR_ZONES_LCK_ZONES_FAILED,
			    a_zlst[i]._zlName);
			(void) z_unlock_zones(a_zlst, a_lflags);
			return (B_FALSE);
		}
	}

	/* success */

	return (B_TRUE);
}

/*
 * Name:	z_mount_in_lz
 * Description:	Mount global zone directory in specified zone's root file system
 * Arguments:	r_lzMountPoint - pointer to handle to string - on success, the
 *			full path to the mount point relative to the global zone
 *			root file system is returned here - this is needed to
 *			unmount the directory when it is no longer needed
 *		r_lzRootPath - pointer to handle to string - on success, the
 *			full path to the mount point relative to the specified
 *			zone's root file system is returned here - this is
 *			passed to any command executing in the specified zone to
 *			access the directory mounted
 *		a_zoneName - pointer to string representing the name of the zone
 *			to mount the specified global zone directory in
 *		a_gzPath - pointer to string representing the full absolute path
 *			of the global zone directory to LOFS mount inside of the
 *			specified non-global zone
 *		a_mountPointPrefix - pointer to string representing the prefix
 *			to be used when creating the mount point name in the
 *			specified zone's root directory
 * Returns:	boolean_t
 *			== B_TRUE - global zone directory mounted successfully
 *			== B_FALSE - failed to mount directory in specified zone
 * NOTE:    	Any strings returned is placed in new storage for the
 *		calling function. The caller must use 'Free' to dispose
 *		of the storage once the strings are no longer needed.
 */

boolean_t
z_mount_in_lz(char **r_lzMountPoint, char **r_lzRootPath, char *a_zoneName,
	char *a_gzPath, char *a_mountPointPrefix)
{
	char		lzRootPath[MAXPATHLEN] = {'\0'};
	char		uuid[MAXPATHLEN] = {'\0'};
	char		gzMountPoint[MAXPATHLEN] = {'\0'};
	char		lzMountPoint[MAXPATHLEN] = {'\0'};
	hrtime_t	hretime;
	int		err;
	int		slen;
	struct tm	tstruct;
	time_t		thetime;
	zoneid_t	zid;

	/* entry assertions */

	assert(a_zoneName != (char *)NULL);
	assert(*a_zoneName != '\0');
	assert(a_gzPath != (char *)NULL);
	assert(*a_gzPath != '\0');
	assert(r_lzMountPoint != (char **)NULL);
	assert(r_lzRootPath != (char **)NULL);

	/* entry debugging info */

	_z_echoDebug(DBG_ZONES_MOUNT_IN_LZ_ENTRY, a_zoneName, a_gzPath);

	/* reset returned non-global zone mount point path handle */

	*r_lzMountPoint = (char *)NULL;
	*r_lzRootPath = (char *)NULL;

	/* if zones are not implemented, return FALSE */

	if (z_zones_are_implemented() == B_FALSE) {
		return (B_FALSE);
	}

	/* error if global zone path is not absolute */

	if (*a_gzPath != '/') {
		_z_program_error(ERR_GZPATH_NOT_ABSOLUTE, a_gzPath);
		return (B_FALSE);
	}

	/* error if global zone path does not exist */

	if (_z_is_directory(a_gzPath) != 0) {
		_z_program_error(ERR_GZPATH_NOT_DIR, a_gzPath, strerror(errno));
		return (B_FALSE);
	}

	/* verify that specified non-global zone exists */

	err = zone_get_id(a_zoneName, &zid);
	if (err != Z_OK) {
		_z_program_error(ERR_GET_ZONEID, a_zoneName,
		    zonecfg_strerror(err));
		return (B_FALSE);
	}

	/* obtain global zone path to non-global zones root file system */

	err = zone_get_rootpath(a_zoneName, lzRootPath, sizeof (lzRootPath));
	if (err != Z_OK) {
		_z_program_error(ERR_NO_ZONE_ROOTPATH, a_zoneName,
		    zonecfg_strerror(err));
		return (B_FALSE);
	}

	if (lzRootPath[0] == '\0') {
		_z_program_error(ERR_ROOTPATH_EMPTY, a_zoneName);
		return (B_FALSE);
	}

	/*
	 * lofs resolve the non-global zone's root path first in case
	 * its in a path that's been lofs mounted read-only.
	 * (e.g. This happens when we're tyring to patch a zone in an ABE
	 * that lives on a filesystem that the ABE shares with the currently
	 * running BE.)
	 */
	z_resolve_lofs(lzRootPath, sizeof (lzRootPath));

	/* verify that the root path exists */

	if (_z_is_directory(lzRootPath) != 0) {
		_z_program_error(ERR_LZROOT_NOTDIR, lzRootPath,
		    strerror(errno));
		return (B_FALSE);
	}

	/*
	 * generate a unique key - the key is the same length as unique uid
	 * but contains different information that is as unique as can be made;
	 * include current hires time (nanosecond real timer). Such a unique
	 * i.d. will look like:
	 *		0203104092-1145345-0004e94d6af481a0
	 */

	hretime = gethrtime();

	thetime = time((time_t *)NULL);
	(void) localtime_r(&thetime, &tstruct);

	slen = snprintf(uuid, sizeof (uuid),
	    UUID_FORMAT,
	    tstruct.tm_mday, tstruct.tm_mon, tstruct.tm_year,
	    tstruct.tm_yday, tstruct.tm_hour, tstruct.tm_min,
	    tstruct.tm_sec,	tstruct.tm_wday, hretime);
	if (slen > sizeof (uuid)) {
		_z_program_error(ERR_GZMOUNT_SNPRINTFUUID_FAILED,
		    UUID_FORMAT, sizeof (uuid));
		return (B_FALSE);
	}

	/* create the global zone mount point */

	slen = snprintf(gzMountPoint, sizeof (gzMountPoint), "%s/.SUNW_%s_%s",
	    lzRootPath,
	    a_mountPointPrefix ? a_mountPointPrefix : "zones", uuid);
	if (slen > sizeof (gzMountPoint)) {
		_z_program_error(ERR_GZMOUNT_SNPRINTFGMP_FAILED,
		    "%s/.SUNW_%s_%s", lzRootPath,
		    a_mountPointPrefix ? a_mountPointPrefix : "zones",
		    uuid, sizeof (gzMountPoint));
		return (B_FALSE);
	}

	slen = snprintf(lzMountPoint, sizeof (lzMountPoint), "%s",
	    gzMountPoint+strlen(lzRootPath));
	if (slen > sizeof (lzMountPoint)) {
		_z_program_error(ERR_GZMOUNT_SNPRINTFLMP_FAILED,
		    "%s", gzMountPoint+strlen(lzRootPath),
		    sizeof (lzMountPoint));
		return (B_FALSE);
	}

	_z_echoDebug(DBG_MNTPT_NAMES, a_gzPath, a_zoneName, gzMountPoint,
	    lzMountPoint);

	/* error if the mount point already exists */

	if (_z_is_directory(gzMountPoint) == 0) {
		_z_program_error(ERR_ZONEROOT_NOTDIR, gzMountPoint,
		    a_zoneName, strerror(errno));
		return (B_FALSE);
	}

	/* create the temporary mount point */

	if (mkdir(gzMountPoint, 0600) != 0) {
		_z_program_error(ERR_MNTPT_MKDIR, gzMountPoint, a_zoneName,
		    strerror(errno));
		return (B_FALSE);
	}

	/* mount the global zone path on the non-global zone root file system */

	err = mount(a_gzPath, gzMountPoint, MS_RDONLY|MS_DATA, "lofs",
	    (char *)NULL, 0, (char *)NULL, 0);
	if (err != 0) {
		_z_program_error(ERR_GZMOUNT_FAILED, a_gzPath,
		    gzMountPoint, a_zoneName, strerror(errno));
		return (B_FALSE);
	}

	/* success - return both mountpoints to caller */

	*r_lzMountPoint = _z_strdup(gzMountPoint);

	*r_lzRootPath = _z_strdup(lzMountPoint);

	/* return success */

	return (B_TRUE);
}

/*
 * Name:	z_non_global_zones_exist
 * Description:	Determine if any non-global native zones exist
 * Arguments:	None.
 * Returns:	boolean_t
 *	== B_TRUE - at least one non-global native zone exists
 *	== B_FALSE - no non-global native zone exists
 */

boolean_t
z_non_global_zones_exist(void)
{
	FILE		*zoneIndexFP;
	boolean_t	anyExist = B_FALSE;
	struct zoneent	*ze;
	zone_spec_t	*zent;

	/* if zones are not implemented, return FALSE */

	if (z_zones_are_implemented() == B_FALSE) {
		return (B_FALSE);
	}

	/* determine if any zones are configured */
	zoneIndexFP = setzoneent();
	if (zoneIndexFP == NULL) {
		return (B_FALSE);
	}

	/* index file open; scan all zones; see if any are at least installed */

	while ((ze = getzoneent_private(zoneIndexFP)) != NULL) {
		/*
		 * If the user specified an explicit zone list, then ignore any
		 * zones that aren't on that list.
		 */
		if ((zent = _z_global_data._zone_spec) != NULL) {
			while (zent != NULL) {
				if (strcmp(zent->zl_name, ze->zone_name) == 0)
					break;
				zent = zent->zl_next;
			}
			if (zent == NULL) {
				free(ze);
				continue;
			}
		}

		/* skip the global zone */
		if (strcmp(ze->zone_name, GLOBAL_ZONENAME) == 0) {
			free(ze);
			continue;
		}

		/* skip any branded zones */
		if (z_is_zone_branded(ze->zone_name)) {
			free(ze);
			continue;
		}

		/* is this zone installed? */
		if (ze->zone_state >= ZONE_STATE_INSTALLED) {
			free(ze);
			anyExist = B_TRUE;
			break;
		}
		free(ze);
	}

	/* close the index file */

	endzoneent(zoneIndexFP);

	/* return results */

	return (anyExist);
}

/*
 * Name:	z_on_zone_spec
 * Description:	Determine if named zone is on the zone_spec list.
 * Arguments:	Pointer to name to test.
 * Returns:	B_TRUE if named zone is on the list or if the user specified
 *		no list at all (all zones is the default), B_FALSE otherwise.
 */

boolean_t
z_on_zone_spec(const char *zonename)
{
	zone_spec_t	*zent;

	/* entry assertions */

	assert(zonename != NULL);
	assert(*zonename != '\0');

	/* return true if zones not implemented or no zone spec list defined */

	if (!z_zones_are_implemented() || _z_global_data._zone_spec == NULL) {
		return (B_TRUE);
	}

	/* return true if named zone is on the zone spec list */

	for (zent = _z_global_data._zone_spec;
	    zent != NULL; zent = zent->zl_next) {
		if (strcmp(zent->zl_name, zonename) == 0)
			return (B_TRUE);
	}

	/* named zone is not on the zone spec list */

	return (B_FALSE);
}

/*
 * Name:	z_running_in_global_zone
 * Description:	Determine if running in the "global" zone
 * Arguments:	void
 * Returns:	boolean_t
 *			== B_TRUE - running in global zone
 *			== B_FALSE - not running in global zone
 */

boolean_t
z_running_in_global_zone(void)
{
	static	boolean_t	_zoneIdDetermined = B_FALSE;
	static	boolean_t	_zoneIsGlobal = B_FALSE;

	/* if ID has not been determined, cache it now */

	if (!_zoneIdDetermined) {
		_zoneIdDetermined = B_TRUE;
		_zoneIsGlobal = _z_running_in_global_zone();
	}

	return (_zoneIsGlobal);
}

/*
 * Name:	z_set_output_functions
 * Description:	Link program specific output functions to this library.
 * Arguments:	a_echo_fcn - (_z_printf_fcn_t)
 *			Function to call to cause "normal operation" messages
 *			to be output/displayed
 *		a_echo_debug_fcn - (_z_printf_fcn_t)
 *			Function to call to cause "debugging" messages
 *			to be output/displayed
 *		a_progerr_fcn - (_z_printf_fcn_t)
 *			Function to call to cause "program error" messages
 *			to be output/displayed
 * Returns:	void
 * NOTE:	If NULL is specified for any function, then the functionality
 *		associated with that function is disabled.
 * NOTE:	The function pointers provided must call a function that
 *		takes two arguments:
 *			function(char *format, char *message)
 *		Any registered function will be called like:
 *			function("%s", "message")
 */

void
z_set_output_functions(_z_printf_fcn_t a_echo_fcn,
    _z_printf_fcn_t a_echo_debug_fcn,
    _z_printf_fcn_t a_progerr_fcn)
{
	_z_global_data._z_echo = a_echo_fcn;
	_z_global_data._z_echo_debug = a_echo_debug_fcn;
	_z_global_data._z_progerr = a_progerr_fcn;
}

/*
 * Name:	z_set_zone_root
 * Description:	Set root for zones library operations
 * Arguments:	Path to root of boot environment containing zone; must be
 *		absolute.
 * Returns:	None.
 * NOTE:	Must be called before performing any zone-related operations.
 *		(Currently called directly by set_inst_root() during -R
 *		argument handling.)
 */

void
z_set_zone_root(const char *zroot)
{
	char *rootdir;

	/* if zones are not implemented, just return */

	if (!z_zones_are_implemented())
		return;

	/* entry assertions */

	assert(zroot != NULL);

	rootdir = _z_strdup((char *)zroot);
	z_canoninplace(rootdir);

	if (strcmp(rootdir, "/") == 0) {
		rootdir[0] = '\0';
	}

	/* free any existing cached root path */
	if (*_z_global_data._z_root_dir != '\0') {
		free(_z_global_data._z_root_dir);
		_z_global_data._z_root_dir = NULL;
	}

	/* store duplicate of new zone root path */

	if (*rootdir != '\0') {
		_z_global_data._z_root_dir = _z_strdup(rootdir);
	} else {
		_z_global_data._z_root_dir = "";
	}

	/* set zone root path */

	zonecfg_set_root(rootdir);

	free(rootdir);
}

/*
 * Name:	z_set_zone_spec
 * Description:	Set list of zones on which actions will be performed.
 * Arguments:	Whitespace-separated list of zone names.
 * Returns:	0 on success, -1 on error.
 * NOTES:	Will call _z_program_error if argument can't be parsed or
 *		memory not available.
 */

int
z_set_zone_spec(const char *zlist)
{
	const char	*zend;
	ptrdiff_t	zlen;
	zone_spec_t	*zent;
	zone_spec_t	*zhead;
	zone_spec_t	**znextp = &zhead;

	/* entry assertions */

	assert(zlist != NULL);

	/* parse list to zone_spec_t list, store in global data */

	for (;;) {
		while (isspace(*zlist)) {
			zlist++;
		}
		if (*zlist == '\0') {
			break;
		}
		for (zend = zlist; *zend != '\0'; zend++) {
			if (isspace(*zend)) {
				break;
			}
		}
		zlen = ((ptrdiff_t)zend) - ((ptrdiff_t)zlist);
		if (zlen >= ZONENAME_MAX) {
			_z_program_error(ERR_ZONE_NAME_ILLEGAL, zlen, zlist);
			return (-1);
		}
		zent = _z_malloc(sizeof (*zent));
		(void) memcpy(zent->zl_name, zlist, zlen);
		zent->zl_name[zlen] = '\0';
		zent->zl_used = B_FALSE;
		*znextp = zent;
		znextp = &zent->zl_next;
		zlist = zend;
	}
	*znextp = NULL;

	if (zhead == NULL) {
		_z_program_error(ERR_ZONE_LIST_EMPTY);
		return (-1);
	}

	_z_global_data._zone_spec = zhead;
	return (0);
}

/*
 * Name:	z_umount_lz_mount
 * Description:	Unmount directory mounted with z_mount_in_lz
 * Arguments:	a_lzMountPointer - pointer to string returned by z_mount_in_lz
 * Returns:	boolean_t
 *			== B_TRUE - successfully unmounted directory
 *			== B_FALSE - failed to unmount directory
 */

boolean_t
z_umount_lz_mount(char *a_lzMountPoint)
{
	int	err;

	/* entry assertions */

	assert(a_lzMountPoint != (char *)NULL);
	assert(*a_lzMountPoint != '\0');

	/* entry debugging info */

	_z_echoDebug(DBG_ZONES_UNMOUNT_FROM_LZ_ENTRY, a_lzMountPoint);

	/* if zones are not implemented, return TRUE */

	if (z_zones_are_implemented() == B_FALSE) {
		return (B_FALSE);
	}

	/* error if global zone path is not absolute */

	if (*a_lzMountPoint != '/') {
		_z_program_error(ERR_LZMNTPT_NOT_ABSOLUTE, a_lzMountPoint);
		return (B_FALSE);
	}

	/* verify mount point exists */

	if (_z_is_directory(a_lzMountPoint) != 0) {
		_z_program_error(ERR_LZMNTPT_NOTDIR, a_lzMountPoint,
		    strerror(errno));
		return (B_FALSE);
	}

	/* unmount */

	err = umount2(a_lzMountPoint, 0);
	if (err != 0) {
		_z_program_error(ERR_GZUMOUNT_FAILED, a_lzMountPoint,
		    strerror(errno));
		return (B_FALSE);
	}

	/* remove the mount point */

	(void) remove(a_lzMountPoint);

	/* return success */

	return (B_TRUE);
}

/*
 * Name:	z_unlock_this_zone
 * Description:	unlock this zone
 * Arguments:	a_lflags - [RO, *RO] - (ZLOCKS_T)
 *			Flags indicating which locks to release
 * Returns:	boolean_t
 *			== B_TRUE - success specified locks released
 *			== B_FALSE - failure specified locks may not be released
 * NOTE: the lock objects for "this zone" are maintained internally.
 */

boolean_t
z_unlock_this_zone(ZLOCKS_T a_lflags)
{
	boolean_t	b;
	boolean_t	errors = B_FALSE;
	char		*zoneName;

	/* entry assertions */

	assert(a_lflags != ZLOCKS_NONE);

	/* entry debugging info */

	_z_echoDebug(DBG_ZONES_ULK_THIS, a_lflags);

	/* return if no objects locked */

	if ((_z_global_data._z_ObjectLocks == (char *)NULL) ||
	    (*_z_global_data._z_ObjectLocks == '\0')) {
		return (B_TRUE);
	}

	zoneName = z_get_zonename();

	/* unlock patch administration */

	if (a_lflags & ZLOCKS_PATCH_ADMIN) {
		b = _z_unlock_zone_object(&_z_global_data._z_ObjectLocks,
		    zoneName, LOBJ_PATCHADMIN, ERR_ZONES_ULK_THIS_PATCH);
		if (!b) {
			errors = B_TRUE;
		}
	}

	/* unlock package administration */

	if (a_lflags & ZLOCKS_PKG_ADMIN) {
		b = _z_unlock_zone_object(&_z_global_data._z_ObjectLocks,
		    zoneName, LOBJ_PKGADMIN, ERR_ZONES_ULK_THIS_PACKAGE);
		if (!b) {
			errors = B_TRUE;
		}
	}

	/* unlock zone administration */

	if (a_lflags & ZLOCKS_ZONE_ADMIN) {
		b = _z_unlock_zone_object(&_z_global_data._z_ObjectLocks,
		    zoneName, LOBJ_ZONEADMIN, ERR_ZONES_ULK_THIS_ZONES);
		if (!b) {
			errors = B_TRUE;
		}
	}

	(void) free(zoneName);
	return (!errors);
}

/*
 * Name:	z_unlock_zones
 * Description:	unlock specified zones
 * Arguments:	a_zlst - zoneList_t object describing zones to unlock
 *		a_lflags - [RO, *RO] - (ZLOCKS_T)
 *			Flags indicating which locks to release
 * Returns:	boolean_t
 *			== B_TRUE - success, zones unlocked
 *			== B_FALSE - failure, zones not unlocked
 */

boolean_t
z_unlock_zones(zoneList_t a_zlst, ZLOCKS_T a_lflags)
{
	boolean_t	b;
	boolean_t	errors = B_FALSE;
	int		i;

	/* entry assertions */

	assert(a_lflags != ZLOCKS_NONE);

	/* entry debugging info */

	_z_echoDebug(DBG_ZONES_ULK_ZONES, a_lflags);

	/* if zones are not implemented, return TRUE */

	if (z_zones_are_implemented() == B_FALSE) {
		_z_echoDebug(DBG_ZONES_ULK_ZONES_UNIMP);
		return (B_TRUE);
	}

	/* ignore empty list */

	if (a_zlst == (zoneList_t)NULL) {
		_z_echoDebug(DBG_ZONES_ULK_ZONES_NOZONES);
		/* unlock this zone before returning */
		return (z_unlock_this_zone(a_lflags));
	}

	/* zones exist */

	_z_echoDebug(DBG_ZONES_ULK_ZONES_EXIST);

	/*
	 * unlock each listed zone that is currently running
	 */

	for (i = 0; (a_zlst[i]._zlName != (char *)NULL); i++) {
		/* ignore zone if not locked */
		if (!(a_zlst[i]._zlStatus & ZST_LOCKED)) {
			continue;
		}

		/* ignore zone if not running */
		if (a_zlst[i]._zlCurrKernelStatus != ZONE_STATE_RUNNING &&
		    a_zlst[i]._zlCurrKernelStatus != ZONE_STATE_MOUNTED) {
			continue;
		}

		/* unlock this zone */
		b = _z_unlock_zone(&a_zlst[i], a_lflags);

		if (b != B_TRUE) {
			errors = B_TRUE;
		} else {
			/* mark zone as unlocked */
			a_zlst[i]._zlStatus &= ~ZST_LOCKED;
		}
	}

	/* unlock this zone */

	if (z_unlock_this_zone(a_lflags) != B_TRUE) {
		errors = B_TRUE;
	}

	return (errors);
}

/*
 * Name:	z_verify_zone_spec
 * Description:	Verify list of zones on which actions will be performed.
 * Arguments:	None.
 * Returns:	0 on success, -1 on error.
 * NOTES:	Will call _z_program_error if there are zones on the specified
 *		list that don't exist on the system. Requires that
 *		z_set_zone_root is called first (if it is called at all).
 */

int
z_verify_zone_spec(void)
{
	FILE		*zoneIndexFP;
	boolean_t	errors;
	char		zoneIndexPath[MAXPATHLEN];
	struct zoneent	*ze;
	zone_spec_t	*zent;

	if (!z_zones_are_implemented()) {
		_z_program_error(ERR_ZONES_NOT_IMPLEMENTED);
		return (-1);
	}

	zoneIndexFP = setzoneent();
	if (zoneIndexFP == NULL) {
		_z_program_error(ERR_ZONEINDEX_OPEN, zoneIndexPath,
		    strerror(errno));
		return (-1);
	}

	while ((ze = getzoneent_private(zoneIndexFP)) != NULL) {
		for (zent = _z_global_data._zone_spec;
		    zent != NULL; zent = zent->zl_next) {
			if (strcmp(zent->zl_name, ze->zone_name) == 0) {
				zent->zl_used = B_TRUE;
				break;
			}
		}
		free(ze);
	}
	endzoneent(zoneIndexFP);

	errors = B_FALSE;
	for (zent = _z_global_data._zone_spec;
	    zent != NULL; zent = zent->zl_next) {
		if (!zent->zl_used) {
			_z_program_error(ERR_ZONE_NONEXISTENT, zent->zl_name);
			errors = B_TRUE;
		}
	}
	return (errors ? -1 : 0);
}

/*
 * Name:	z_zlist_change_zone_state
 * Description:	Change the current state of the specified zone
 * Arguments:	a_zlst - handle to zoneList_t object describing all zones
 *		a_zoneIndex - index into a_zlst of the zone to return the
 *		a_newState - the state to put the specified zone in
 * Returns:	boolean_t
 *			== B_TRUE - the zone is in the new state
 *			== B_FALSE - unable to transition the zone to the
 *				specified state
 * NOTE:	This changes the "current kernel" state of the specified
 *		zone. For example, to boot the zone, change the state
 *		to "ZONE_STATE_RUNNING". To halt the zone, change the
 *		state to "ZONE_STATE_INSTALLED".
 */

boolean_t
z_zlist_change_zone_state(zoneList_t a_zlst, int a_zoneIndex,
	zone_state_t a_newState)
{
	int	i;

	/* entry debugging info */

	_z_echoDebug(DBG_ZONES_CHG_Z_STATE_ENTRY, a_zoneIndex, a_newState);

	/* ignore empty list */

	if (a_zlst == (zoneList_t)NULL) {
		return (B_FALSE);
	}

	/* find the specified zone in the list */

	for (i = 0; (i != a_zoneIndex) &&
	    (a_zlst[i]._zlName != (char *)NULL); i++)
		;

	/* return error if the specified zone does not exist */

	if (a_zlst[i]._zlName == (char *)NULL) {
		return (B_FALSE);
	}

	/* return success if the zone is already in this state */

	if (a_zlst[i]._zlCurrKernelStatus == a_newState) {
		return (B_TRUE);
	}

	/* take action on new state to set zone to */

	_z_echoDebug(DBG_ZONES_CHG_Z_STATE, a_zlst[i]._zlName,
	    a_zlst[i]._zlCurrKernelStatus, a_newState);

	switch (a_newState) {
	case ZONE_STATE_RUNNING:
	case ZONE_STATE_MOUNTED:
		/* these states mean "boot the zone" */
		return (_z_make_zone_running(&a_zlst[i]));

	case ZONE_STATE_DOWN:
	case ZONE_STATE_INSTALLED:
		/* these states mean "halt the zone" */
		return (_z_make_zone_down(&a_zlst[i]));

	case ZONE_STATE_READY:
		return (_z_make_zone_ready(&a_zlst[i]));

	case ZONE_STATE_CONFIGURED:
	case ZONE_STATE_INCOMPLETE:
	case ZONE_STATE_SHUTTING_DOWN:
	default:
		/* do not know how to change zone to this state */
		return (B_FALSE);
	}
}

/*
 * Name:	z_is_zone_branded
 * Description:	Determine whether zone has a non-native brand
 * Arguments:	a_zoneName - name of the zone to check for branding
 * Returns:	boolean_t
 *			== B_TRUE - zone has a non-native brand
 *			== B_FALSE - zone is native
 */
boolean_t
z_is_zone_branded(char *zoneName)
{
	char			brandname[MAXNAMELEN];
	int			err;

	/* if zones are not implemented, return FALSE */
	if (!z_zones_are_implemented()) {
		return (B_FALSE);
	}

	/* if brands are not implemented, return FALSE */
	if (!z_brands_are_implemented()) {
		return (B_FALSE);
	}

	err = zone_get_brand(zoneName, brandname, sizeof (brandname));
	if (err != Z_OK) {
		_z_program_error(ERR_BRAND_GETBRAND, zonecfg_strerror(err));
		return (B_FALSE);
	}

	/*
	 * Both "native" and "cluster" are native brands
	 * that use the standard facilities in the areas
	 * of packaging/installation/patching/update.
	 */
	if (streq(brandname, NATIVE_BRAND_NAME) ||
	    streq(brandname, CLUSTER_BRAND_NAME)) {
		return (B_FALSE);
	} else {
		return (B_TRUE);
	}
}

/*
 * Name:	z_is_zone_brand_in_list
 * Description:	Determine whether zone's brand has a match in the list
 *              brands passed in.
 * Arguments:	zoneName - name of the zone to check for branding
 *              list - list of brands to check the zone against
 * Returns:	boolean_t
 *			== B_TRUE - zone has a matching brand
 *			== B_FALSE - zone brand is not in list
 */
boolean_t
z_is_zone_brand_in_list(char *zoneName, zoneBrandList_t *list)
{
	char			brandname[MAXNAMELEN];
	int			err;
	zoneBrandList_t		*sp;

	if (zoneName == NULL || list == NULL)
		return (B_FALSE);

	/* if zones are not implemented, return FALSE */
	if (!z_zones_are_implemented()) {
		return (B_FALSE);
	}

	/* if brands are not implemented, return FALSE */
	if (!z_brands_are_implemented()) {
		return (B_FALSE);
	}

	err = zone_get_brand(zoneName, brandname, sizeof (brandname));
	if (err != Z_OK) {
		_z_program_error(ERR_BRAND_GETBRAND, zonecfg_strerror(err));
		return (B_FALSE);
	}

	for (sp = list; sp != NULL; sp = sp->next) {
		if (sp->string_ptr != NULL &&
		    strcmp(sp->string_ptr, brandname) == 0) {
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

/*
 * Name:	z_zlist_get_current_state
 * Description:	Determine the current kernel state of the specified zone
 * Arguments:	a_zlst - handle to zoneList_t object describing all zones
 *		a_zoneIndex - index into a_zlst of the zone to return
 * Returns:	zone_state_t
 *			The current state of the specified zone is returned
 */

zone_state_t
z_zlist_get_current_state(zoneList_t a_zlst, int a_zoneIndex)
{
	int	i;

	/* ignore empty list */

	if (a_zlst == (zoneList_t)NULL) {
		return (ZONE_STATE_INCOMPLETE);
	}

	/* find the specified zone in the list */

	for (i = 0; (i != a_zoneIndex) &&
	    (a_zlst[i]._zlName != (char *)NULL); i++)
		;

	/* return error if the specified zone does not exist */

	if (a_zlst[i]._zlName == (char *)NULL) {
		return (ZONE_STATE_INCOMPLETE);
	}

	/* return selected zone's current kernel state */

	_z_echoDebug(DBG_ZONES_GET_ZONE_STATE,
	    a_zlst[i]._zlName ? a_zlst[i]._zlName : "",
	    a_zlst[i]._zlCurrKernelStatus);

	return (a_zlst[i]._zlCurrKernelStatus);
}

/*
 * Name:	z_zlist_get_inherited_pkg_dirs
 * Description:	Determine directories inherited by specified zone
 * Arguments:	a_zlst - handle to zoneList_t object describing all zones
 *		a_zoneIndex - index into a_zlst of the zone to return the
 *			inherited directories list
 * Returns:	char **
 *			== NULL - zone does not inherit any directories
 *				- zone index is invalid
 *			!= NULL - array of inherited directories
 * NOTE:    	Any directory list returned is located in static storage that
 *		must NEVER be free()ed by the caller.
 */

extern char **
z_zlist_get_inherited_pkg_dirs(zoneList_t a_zlst, int a_zoneIndex)
{
	int	i;

	/* if zones are not implemented, return empty list */

	if (z_zones_are_implemented() == B_FALSE) {
		return (NULL);
	}

	/* ignore empty list */

	if (a_zlst == (zoneList_t)NULL) {
		return (NULL);
	}

	/* find the specified zone in the list */

	for (i = 0; (i != a_zoneIndex) &&
	    (a_zlst[i]._zlName != (char *)NULL); i++)
		;

	/* return error if the specified zone does not exist */

	if (a_zlst[i]._zlName == (char *)NULL) {
		return (NULL);
	}

	/* return selected zone's inherited directories */

	return (a_zlst[i]._zlInheritedDirs);
}

/*
 * Name:	z_zlist_get_original_state
 * Description:	Return the original kernal state of the specified zone
 * Arguments:	a_zlst - handle to zoneList_t object describing all zones
 *		a_zoneIndex - index into a_zlst of the zone to return the
 * Returns:	zone_state_t
 *			The original state of the specified zone is returned.
 *			This is the state of the zone when the zoneList_t
 *			object was first generated.
 */

zone_state_t
z_zlist_get_original_state(zoneList_t a_zlst, int a_zoneIndex)
{
	int	i;

	/* ignore empty list */

	if (a_zlst == (zoneList_t)NULL) {
		return (ZONE_STATE_INCOMPLETE);
	}

	/* find the specified zone in the list */

	for (i = 0; (i != a_zoneIndex) &&
	    (a_zlst[i]._zlName != (char *)NULL); i++)
		;

	/* return error if the specified zone does not exist */

	if (a_zlst[i]._zlName == (char *)NULL) {
		return (ZONE_STATE_INCOMPLETE);
	}

	/* return selected zone's original kernel state */

	return (a_zlst[i]._zlOrigKernelStatus);
}

/*
 * Name:	z_zlist_get_scratch
 * Description:	Determine name of scratch zone
 * Arguments:	a_zlst - handle to zoneList_t object describing all zones
 *		a_zoneIndex - index into a_zlst of the zone to use
 * Return:	char *
 *			== NULL - zone name could not be determined
 *			!= NULL - pointer to string representing scratch zone
 * NOTE:    	Any name returned is placed in static storage that must
 *		NEVER be free()ed by the caller.
 */

char *
z_zlist_get_scratch(zoneList_t a_zlst, int a_zoneIndex)
{
	int	i;

	/* ignore empty list */

	if (a_zlst == NULL)
		return (NULL);

	/* find the specified zone in the list */

	for (i = 0; i != a_zoneIndex; i++) {
		if (a_zlst[i]._zlName == NULL)
			return (NULL);
	}

	/* return selected zone's scratch name */

	return (a_zlst[i]._zlScratchName == NULL ? a_zlst[i]._zlName :
	    a_zlst[i]._zlScratchName);
}

/*
 * Name:	z_zlist_get_zonename
 * Description:	Determine name of specified zone
 * Arguments:	a_zlst - handle to zoneList_t object describing all zones
 *		a_zoneIndex - index into a_zlst of the zone to return the
 * Return:	char *
 *			== NULL - zone name could not be determined
 *			!= NULL - pointer to string representing zone name
 * NOTE:    	Any zoneList_t returned is placed in static storage that must
 *		NEVER be free()ed by the caller.
 */

char *
z_zlist_get_zonename(zoneList_t a_zlst, int a_zoneIndex)
{
	int	i;

	/* ignore empty list */

	if (a_zlst == (zoneList_t)NULL) {
		return ((char *)NULL);
	}

	/* find the specified zone in the list */

	for (i = 0; (i != a_zoneIndex) &&
	    (a_zlst[i]._zlName != (char *)NULL); i++)
		;

	/* return error if the specified zone does not exist */

	if (a_zlst[i]._zlName == (char *)NULL) {
		return (NULL);
	}

	/* return selected zone's name */

	return (a_zlst[i]._zlName);
}

/*
 * Name:	z_zlist_get_zonepath
 * Description:	Determine zonepath of specified zone
 * Arguments:	a_zlst - handle to zoneList_t object describing all zones
 *		a_zoneIndex - index into a_zlst of the zone to return
 * Return:	char *
 *			== NULL - zonepath could not be determined
 *			!= NULL - pointer to string representing zonepath
 * NOTE:    	Any zoneList_t returned is placed in static storage that must
 *		NEVER be free()ed by the caller.
 */

char *
z_zlist_get_zonepath(zoneList_t a_zlst, int a_zoneIndex)
{
	int	i;

	/* ignore empty list */

	if (a_zlst == (zoneList_t)NULL) {
		return ((char *)NULL);
	}

	/* find the specified zone in the list */

	for (i = 0; (i != a_zoneIndex) &&
	    (a_zlst[i]._zlName != (char *)NULL); i++)
		;

	/* return error if the specified zone does not exist */

	if (a_zlst[i]._zlName == (char *)NULL) {
		return (NULL);
	}

	/* return selected zone's zonepath */

	return (a_zlst[i]._zlPath);
}

boolean_t
z_zlist_is_zone_runnable(zoneList_t a_zlst, int a_zoneIndex)
{
	int	i;

	/* if zones are not implemented, return error */

	if (z_zones_are_implemented() == B_FALSE) {
		return (B_FALSE);
	}

	/* ignore empty list */

	if (a_zlst == (zoneList_t)NULL) {
		return (B_FALSE);
	}

	/* find the specified zone in the list */

	for (i = 0; (i != a_zoneIndex) &&
	    (a_zlst[i]._zlName != (char *)NULL); i++)
		;

	/* return error if the specified zone does not exist */

	if (a_zlst[i]._zlName == (char *)NULL) {
		return (B_FALSE);
	}

	/* choose based on current state */

	switch (a_zlst[i]._zlCurrKernelStatus) {
	case ZONE_STATE_RUNNING:
	case ZONE_STATE_MOUNTED:
		/* already running */
		return (B_TRUE);

	case ZONE_STATE_INSTALLED:
	case ZONE_STATE_DOWN:
	case ZONE_STATE_READY:
	case ZONE_STATE_SHUTTING_DOWN:
		/* return false if the zone cannot be booted */

		if (a_zlst[i]._zlStatus & ZST_NOT_BOOTABLE) {
			return (B_FALSE);
		}

		return (B_TRUE);

	case ZONE_STATE_CONFIGURED:
	case ZONE_STATE_INCOMPLETE:
	default:
		/* cannot transition (boot) these states */
		return (B_FALSE);
	}
}

/*
 * Name:	z_zlist_restore_zone_state
 * Description:	Return the zone to the state it was originally in
 * Arguments:	a_zlst - handle to zoneList_t object describing all zones
 *		a_zoneIndex - index into a_zlst of the zone to return the
 * Returns:	boolean_t
 *			== B_TRUE - the zone's state has been restored
 *			== B_FALSE - unable to transition the zone to its
 *				original state
 */

boolean_t
z_zlist_restore_zone_state(zoneList_t a_zlst, int a_zoneIndex)
{
	int		i;

	/* ignore empty list */

	if (a_zlst == (zoneList_t)NULL) {
		return (B_FALSE);
	}

	/* find the specified zone in the list */

	for (i = 0; (i != a_zoneIndex) &&
	    (a_zlst[i]._zlName != (char *)NULL); i++)
		;

	/* return error if the specified zone does not exist */

	if (a_zlst[i]._zlName == (char *)NULL) {
		return (B_FALSE);
	}

	/* transition the zone back to its original state */

	return (z_zlist_change_zone_state(a_zlst,
	    a_zoneIndex, a_zlst[i]._zlOrigKernelStatus));
}

/*
 * Name:	z_zone_exec
 * Description:	Execute a Unix command in a specified zone and return results
 * Arguments:	a_zoneName - pointer to string representing the name of the zone
 *			to execute the specified command in
 *		a_path - pointer to string representing the full path *in the
 *			non-global zone named by a_zoneName* of the Unix command
 *			to be executed
 *		a_argv[] - Pointer to array of character strings representing
 *			the arguments to be passed to the Unix command. The list
 *			must be termianted with an element that is (char *)NULL
 *		NOTE: a_argv[0] is the "command name" passed to the command
 *		a_stdoutPath - Pointer to string representing the path to a file
 *			into which all output to "stdout" from the Unix command
 *			is placed.
 *			== (char *)NULL - leave stdout open and pass through
 *			== "/dev/null" - discard stdout output
 *		a_strerrPath - Pointer to string representing the path to a file
 *			into which all output to "stderr" from the Unix command
 *			is placed.
 *			== (char *)NULL - leave stderr open and pass through
 *			== "/dev/null" - discard stderr output
 *		a_fds - Pointer to array of integers representing file
 *			descriptors to remain open during the call - all
 *			file descriptors above STDERR_FILENO not in this
 *			list will be closed.
 * Returns:	int
 *			The return (exit) code from the specified Unix command
 *			Special return codes:
 *			-1 : failure to exec process
 *			-2 : could not create contract for greenline
 *			-3 : fork() failed
 *			-4 : could not open stdout capture file
 *			-5 : error from 'waitpid' other than EINTR
 *			-6 : zones are not supported
 * NOTE:	All file descriptores other than 0, 1 and 2 are closed except
 *		for those file descriptors listed in the a_fds array.
 */

int
z_zone_exec(const char *a_zoneName, const char *a_path, char *a_argv[],
	char *a_stdoutPath, char *a_stderrPath, int *a_fds)
{
	int			final_status;
	int			lerrno;
	int			status;
	int			tmpl_fd;
	pid_t			child_pid;
	pid_t			result_pid;
	struct sigaction	nact;
	struct sigaction	oact;
	void			(*funcSighup)();
	void			(*funcSigint)();

	/* if zones are not implemented, return TRUE */

	if (z_zones_are_implemented() == B_FALSE) {
		return (-6);	/* -6 : zones are not supported */
	}

	if ((tmpl_fd = _zexec_init_template()) == -1) {
		_z_program_error(ERR_CANNOT_CREATE_CONTRACT, strerror(errno));
		return (-2);	/* -2 : could not create greenline contract */
	}

	/*
	 * hold SIGINT/SIGHUP signals and reset signal received counter;
	 * after the fork1() the parent and child need to setup their respective
	 * interrupt handling and release the hold on the signals
	 */

	(void) sighold(SIGINT);
	(void) sighold(SIGHUP);

	_z_global_data._z_SigReceived = 0;	/* no signals received */

	/*
	 * fork off a new process to execute command in;
	 * fork1() is used instead of vfork() so the child process can
	 * perform operations that would modify the parent process if
	 * vfork() were used
	 */

	child_pid = fork1();

	if (child_pid < 0) {
		/*
		 * *************************************************************
		 * fork failed!
		 * *************************************************************
		 */

		(void) ct_tmpl_clear(tmpl_fd);
		(void) close(tmpl_fd);
		_z_program_error(ERR_FORK, strerror(errno));

		/* release hold on signals */

		(void) sigrelse(SIGHUP);
		(void) sigrelse(SIGINT);

		return (-3);	/* -3 : fork() failed */
	}

	if (child_pid == 0) {
		int	i;

		/*
		 * *************************************************************
		 * This is the forked (child) process
		 * *************************************************************
		 */

		(void) ct_tmpl_clear(tmpl_fd);
		(void) close(tmpl_fd);

		/* reset any signals to default */

		for (i = 0; i < NSIG; i++) {
			(void) sigset(i, SIG_DFL);
		}

		/*
		 * close all file descriptors not in the a_fds list
		 */

		(void) fdwalk(&_z_close_file_descriptors, (void *)a_fds);

		/*
		 * if a file for stdout is present, open the file and use the
		 * file to capture stdout from the _zexec process
		 */

		if (a_stdoutPath != (char *)NULL) {
			int	stdoutfd;

			stdoutfd = open(a_stdoutPath,
			    O_WRONLY|O_CREAT|O_TRUNC, 0600);
			if (stdoutfd < 0) {
				_z_program_error(ERR_CAPTURE_FILE, a_stdoutPath,
				    strerror(errno));
				return (-4);
			}

			(void) dup2(stdoutfd, STDOUT_FILENO);
			(void) close(stdoutfd);
		}

		/*
		 * if a file for stderr is present, open the file and use the
		 * file to capture stderr from the _zexec process
		 */

		if (a_stderrPath != (char *)NULL) {
			int	stderrfd;

			stderrfd = open(a_stderrPath,
			    O_WRONLY|O_CREAT|O_TRUNC, 0600);
			if (stderrfd < 0) {
				_z_program_error(ERR_CAPTURE_FILE, a_stderrPath,
				    strerror(errno));
				return (-4);
			}

			(void) dup2(stderrfd, STDERR_FILENO);
			(void) close(stderrfd);
		}

		/* release all held signals */

		(void) sigrelse(SIGHUP);
		(void) sigrelse(SIGINT);

		/* execute command in the specified non-global zone */

		_exit(_zexec(a_zoneName, a_path, a_argv));
	}

	/*
	 * *********************************************************************
	 * This is the forking (parent) process
	 * *********************************************************************
	 */

	/* register child process i.d. so signal handlers can pass signal on */

	_z_global_data._z_ChildProcessId = child_pid;

	/*
	 * setup signal handlers for SIGINT and SIGHUP and release hold
	 */

	/* hook SIGINT to _z_sig_trap() */

	nact.sa_handler = _z_sig_trap;
	nact.sa_flags = SA_RESTART;
	(void) sigemptyset(&nact.sa_mask);

	if (sigaction(SIGINT, &nact, &oact) < 0) {
		funcSigint = SIG_DFL;
	} else {
		funcSigint = oact.sa_handler;
	}

	/* hook SIGHUP to _z_sig_trap() */

	nact.sa_handler = _z_sig_trap;
	nact.sa_flags = SA_RESTART;
	(void) sigemptyset(&nact.sa_mask);

	if (sigaction(SIGHUP, &nact, &oact) < 0) {
		funcSighup = SIG_DFL;
	} else {
		funcSighup = oact.sa_handler;
	}

	/* release hold on signals */

	(void) sigrelse(SIGHUP);
	(void) sigrelse(SIGINT);

	(void) ct_tmpl_clear(tmpl_fd);
	(void) close(tmpl_fd);

	/*
	 * wait for the process to exit, reap child exit status
	 */

	for (;;) {
		result_pid = waitpid(child_pid, &status, 0L);
		lerrno = (result_pid == -1 ? errno : 0);

		/* break loop if child process status reaped */

		if (result_pid != -1) {
			break;
		}

		/* break loop if not interrupted out of waitpid */

		if (errno != EINTR) {
			break;
		}
	}

	/* reset child process i.d. so signal handlers do not pass signals on */

	_z_global_data._z_ChildProcessId = -1;

	/*
	 * If the child process terminated due to a call to exit(), then
	 * set results equal to the 8-bit exit status of the child process;
	 * otherwise, set the exit status to "-1" indicating that the child
	 * exited via a signal.
	 */

	if (WIFEXITED(status)) {
		final_status = WEXITSTATUS(status);
		if ((_z_global_data._z_SigReceived != 0) &&
		    (final_status == 0)) {
			final_status = 1;
		}
	} else {
		final_status = -1;	/* -1 : failure to exec process */
	}

	/* determine proper exit code */

	if (result_pid == -1) {
		final_status = -5;	/* -5 : error from waitpid not EINTR */
	} else if (_z_global_data._z_SigReceived != 0) {
		final_status = -7;	/* -7 : interrupt received */
	}

	/*
	 * reset signal handlers
	 */

	/* reset SIGINT */

	nact.sa_handler = funcSigint;
	nact.sa_flags = SA_RESTART;
	(void) sigemptyset(&nact.sa_mask);

	(void) sigaction(SIGINT, &nact, (struct sigaction *)NULL);

	/* reset SIGHUP */

	nact.sa_handler = funcSighup;
	nact.sa_flags = SA_RESTART;
	(void) sigemptyset(&nact.sa_mask);

	(void) sigaction(SIGHUP, &nact, (struct sigaction *)NULL);

	/*
	 * if signal received during command execution, interrupt
	 * this process now.
	 */

	if (_z_global_data._z_SigReceived != 0) {
		(void) kill(getpid(), SIGINT);
	}

	/* set errno and return */

	errno = lerrno;

	return (final_status);
}

/*
 * Name:	z_zones_are_implemented
 * Description:	Determine if any zone operations can be performed
 * Arguments:	void
 * Returns:	boolean_t
 *			== B_TRUE - zone operations are available
 *			== B_FALSE - no zone operations can be done
 */

boolean_t
z_zones_are_implemented(void)
{
	static	boolean_t	_zonesImplementedDetermined = B_FALSE;
	static	boolean_t	_zonesAreImplemented = B_FALSE;

	/* if availability has not been determined, cache it now */

	if (!_zonesImplementedDetermined) {
		_zonesImplementedDetermined = B_TRUE;
		_zonesAreImplemented = _z_zones_are_implemented();
		if (!_zonesAreImplemented) {
			_z_echoDebug(DBG_ZONES_NOT_IMPLEMENTED);
		} else {
			_z_echoDebug(DBG_ZONES_ARE_IMPLEMENTED);
		}
	}

	return (_zonesAreImplemented);
}
