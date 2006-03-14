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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <meta.h>
#include <sdssc.h>
#include <mdiox.h>
#include <meta_repartition.h>

#include "volume_dlist.h"
#include "volume_error.h"
#include "volume_output.h"

#include "layout_device_util.h"
#include "layout_discovery.h"
#include "layout_dlist_util.h"
#include "layout_request.h"
#include "layout_svm_util.h"

static int	_max_hsps = 1000;	/* # of HSPs (arbitrary limit) */
static int	_max_devs = 8192;	/* # of SVM volumes allowed */
static int	_max_devs_cfg = 128;	/* # of SVM volumes configured */
static int	_max_sets = 4;		/* # of SVM disk sets */

/* volume name prefixes for generating new names */
static const char	*_hsp_prefix	= "hsp";
static const char	*_dev_prefix	= "d";

/*
 * dynamically allocated arrays to track used HSP (hspXXX) and volume
 * names (dXXX) by number
 */
static	boolean_t	*hsps_by_number	= NULL;
static	boolean_t	*devs_by_number	= NULL;

/*
 * This struct remembers a diskset and the names of
 * the disks in the set
 */
typedef struct {
	char	*name;
	dlist_t	*disknames;
	dlist_t	*hsps;
} diskset_t;

/*
 * list of diskset_t for known disksets
 */
static dlist_t	*_disksets = NULL;

static int add_diskset(
	char *diskset);

static int add_diskset_diskname(
	char *diskset,
	char *diskname);

static int add_diskset_hsp(
	char *diskset,
	char *hspname);

static int add_diskset_hsp_spare(
	char *diskset,
	char *hspname,
	char *spare);

static int is_disk_in_local_diskset(
	dm_descriptor_t	disk,
	boolean_t	*bool);

static int is_disk_in_named_diskset(
	dm_descriptor_t	disk,
	char		*dsname,
	boolean_t	*bool);

/* SVM snapshot stuff */
typedef enum {
	SVM_DISKSET = 0,
	SVM_MDB,
	SVM_STRIPE,
	SVM_MIRROR,
	SVM_RAID,
	SVM_TRANS,
	SVM_SP,
	SVM_HSP,
	SVM_HS,
	SVM_DRIVE
} svm_type_t;

typedef struct svm_snap_entry {
	struct svm_snap_entry	*next;
	char			*diskset;
	svm_type_t		type;
	char			*name;
	char			*slice;
} svm_snap_t;

static svm_snap_t	*svm_snapshot(int *errp);
static void	free_svm_snapshot(svm_snap_t *listp);

static char	*type_name(svm_type_t type);
static int	add_record(
	svm_snap_t **listp,
	char	*setname,
	svm_type_t type,
	char	*mname,
	char	*slice_name);
static int	diskset_info(svm_snap_t **listp, mdsetname_t *sp);
static void	free_names(mdnamelist_t *nlp);
static int	load_svm(svm_snap_t **listp);
static int	new_entry(
	svm_snap_t **listp,
	char	*sname,
	svm_type_t type,
	char	*mname,
	mdsetname_t *sp);

/*
 * FUNCTION:	scan_svm_names(char *diskset)
 *
 * INPUT:	diskset	- a char * disk set name
 *
 * PURPOSE:	Take a snapshot of the current SVM config.
 *
 *		Scan it and remember:
 *		1. all known disk sets
 * 		s. the disks in the named disk set
 *		3. the used device and HSP names in the named disk set
 *		4. the HSPs in the disk set
 *		5. the spares in the HSPs
 */
int
scan_svm_names(
	char	*diskset)
{
	int		ndisks = 0;
	int		nhsps = 0;
	int		ndevices = 0;
	int		nsets = 0;

	int		number = 0;
	int		error = 0;
	svm_snap_t	*headp = NULL;
	svm_snap_t	*listp = NULL;
	char		*tablefmt = "  %-20s %-10s %-20s %-10s\n";

	oprintf(OUTPUT_TERSE,
		gettext("\nScanning system SVM configuration...\n"));

	headp = svm_snapshot(&error);
	if (error != 0) {
	    oprintf(OUTPUT_TERSE,
		    gettext("failed to scan SVM devices\n"));
	    return (error);
	}

	if (error == 0) {
	    if ((error = get_max_number_of_devices(&_max_devs_cfg)) == 0) {
		oprintf(OUTPUT_VERBOSE,
			gettext("  configured maximum number of "
				"volumes: %d\n"),
			_max_devs_cfg);
	    }
	}

	if (error == 0) {
	    if ((error = get_max_number_of_disksets(&_max_sets)) == 0) {
		oprintf(OUTPUT_VERBOSE,
			gettext("  configured maximum number of "
				"disk sets: %d\n"),
			_max_sets);
	    }
	}

	if (error == 0) {
	    /* array is realloc'ed as necessary */
	    if ((hsps_by_number =
		(boolean_t *)calloc(_max_hsps, sizeof (boolean_t))) == NULL) {
		oprintf(OUTPUT_TERSE,
			gettext("failed to allocate HSP name array\n"));
		error = ENOMEM;
	    }
	}

	if (error == 0) {
	    /* array is realloc'ed as necessary */
	    if ((devs_by_number =
		(boolean_t *)calloc(_max_devs, sizeof (boolean_t))) == NULL) {
		oprintf(OUTPUT_TERSE,
			gettext("failed to allocate volume name array\n"));
		error = ENOMEM;
	    }
	}

	if ((error == 0) && (get_max_verbosity() >= OUTPUT_DEBUG)) {
	    (void) oprintf(OUTPUT_DEBUG, "\n");
	    (void) oprintf(OUTPUT_DEBUG,
		    tablefmt,
		    gettext("disk set"),
		    gettext("dev type"),
		    gettext("name"),
		    gettext("slice"));
	    (void) oprintf(OUTPUT_DEBUG,
		    "  -----------------------------------"
		    "-----------------------------------\n");
	}

	for (listp = headp; listp != NULL && error == 0; listp = listp->next) {

	    oprintf(OUTPUT_DEBUG,
		    tablefmt,
		    listp->diskset,
		    type_name(listp->type),
		    listp->name,
		    listp->slice);

	    switch (listp->type) {
	    case SVM_DISKSET:

		error = add_diskset(listp->name);
		++nsets;
		break;

	    case SVM_DRIVE:

		error = add_diskset_diskname(listp->diskset, listp->name);

		/* is this drive in the requested diskset? */
		if (string_case_compare(diskset, listp->diskset) == 0) {
		    ++ndisks;
		}
		break;

	    case SVM_MIRROR:
	    case SVM_RAID:
	    case SVM_TRANS:
	    case SVM_SP:
	    case SVM_STRIPE:

		/* is this SVM volume in the requested diskset? */
		if (string_case_compare(diskset, listp->diskset) == 0) {

		    /* isolate device name from "poolname/dXXXX" */
		    char *cp = strrchr(listp->name, '/');
		    if (cp != NULL) {
			++cp;
		    } else {
			cp = listp->name;
		    }

		    /* BEGIN CSTYLED */
		    /*
		     * names for requested devices and HSPs are remembered
		     * so that the default name generation scheme knows 
		     * which names are already being used 
		     */
		    /* END CSTYLED */
		    /* extract device number from name "dXXXX" */
		    if (sscanf(cp, "d%d", &number) != EOF) {
			oprintf(OUTPUT_DEBUG,
				gettext("  device: %6s   number: %3d\n"),
				cp, number);

			if (number > _max_devs) {
			    /* hit current limit, expand it */
			    boolean_t *tmp =
				(boolean_t *)realloc((void *)_max_devs,
					(number * sizeof (boolean_t)));

			    if (tmp == NULL) {
				error = ENOMEM;
			    } else {
				_max_devs = number;
				devs_by_number = tmp;
			    }
			}

			if ((error == 0) &&
				(devs_by_number[number] == B_FALSE)) {
			    devs_by_number[number] = B_TRUE;
			    ++ndevices;
			}
		    }
		}
		break;

	    case SVM_HSP:

		/* is this HSP in the requested diskset? */
		if (string_case_compare(diskset, listp->diskset) == 0) {

		    /* isolate HSP name from "poolname/hspXXX" */
		    char *cp = strrchr(listp->name, '/');
		    if (cp != NULL) {
			++cp;
		    } else {
			cp = listp->name;
		    }

		    /* extract pool number from name "hspXXX" */
		    if (sscanf(cp, "hsp%03d", &number) != EOF) {
			oprintf(OUTPUT_DEBUG,
				gettext("     HSP: %6s   number: %3d\n"),
				cp, number);

			if (number > _max_hsps) {
			    /* hit our arbitrary limit, double it */
			    boolean_t *tmp =
				(boolean_t *)realloc((void *)hsps_by_number,
					2 * _max_hsps * sizeof (boolean_t));

			    if (tmp != NULL) {
				_max_hsps *= 2;
				hsps_by_number = tmp;
			    } else {
				error = ENOMEM;
			    }
			}

			if ((error == 0) &&
				(hsps_by_number[number] == B_FALSE)) {
			    hsps_by_number[number] = B_TRUE;
			    error = add_diskset_hsp(diskset, cp);
			    ++nhsps;
			}
		    }
		}

		break;

	    case SVM_HS:

		/* is this hot spare in the requested disk set? */
		if (string_case_compare(diskset, listp->diskset) == 0) {

		    /* isolate HSP name from "poolname/hspXXXX" */
		    char *cp = strrchr(listp->name, '/');
		    if (cp != NULL) {
			++cp;
		    } else {
			cp = listp->name;
		    }

		    error = add_diskset_hsp_spare(diskset, cp, listp->slice);
		}
		break;

	    case SVM_MDB:
	    default:
		break;
	    }
	}

	free_svm_snapshot(headp);

	if (error == 0) {
	    /* available diskset?  subtract 1 for the local set */
	    if ((diskset_exists(diskset) != B_TRUE) &&
		(nsets >= _max_sets)) {
		volume_set_error(
			gettext("Disk set \"%s\" cannot be created, the "
				"maximum number of disk sets (%d) already "
				"exists.\n"),
			diskset, _max_sets);
		error = -1;
	    }
	}

	if (error == 0) {
	    oprintf(OUTPUT_VERBOSE,
		    gettext("\n  Disk set \"%s\" has:\n\n"), diskset);
	    oprintf(OUTPUT_VERBOSE,
		    gettext("    %d drives\n"), ndisks);
	    oprintf(OUTPUT_VERBOSE,
		    gettext("    %d volumes\n"), ndevices);
	    oprintf(OUTPUT_VERBOSE,
		    gettext("    %d HSPs\n"), nhsps);
	} else {
	    free(hsps_by_number);
	    free(devs_by_number);
	    hsps_by_number = (boolean_t *)NULL;
	    devs_by_number = (boolean_t *)NULL;
	}

	return (error);
}

/*
 * FUNCTION:	release_svm_names()
 *
 * PURPOSE:	Release snapshot of the current SVM config.
 *
 *		Free memory allocated by scan_svm_names()
 */
void
release_svm_names()
{
	dlist_t *iter;

	for (iter = _disksets; iter != NULL; iter = iter->next) {
	    diskset_t *diskset = (diskset_t *)iter->obj;
	    dlist_free_items(diskset->disknames, free);
	    dlist_free_items(diskset->hsps, free_devconfig);
	    free(diskset->name);
	}
	dlist_free_items(_disksets, free);
	_disksets = NULL;

	if (hsps_by_number != NULL)
	    free(hsps_by_number);
	if (devs_by_number != NULL)
	    free(devs_by_number);

	hsps_by_number = (boolean_t *)NULL;
	devs_by_number = (boolean_t *)NULL;
}

/*
 * FUNCTION:	diskset_exists(char *diskset)
 *
 * INPUT:	dsname	- a char * diskset name
 *
 * RETURNS:	boolean_t - B_TRUE if the named diskset exists
 *			 B_FALSE otherwise
 *
 * PURPOSE:	Checks the list of known disk sets and determines
 *		if the input name is in that list.
 */
boolean_t
diskset_exists(
	char	*dsname)
{
	dlist_t *iter;

	for (iter = _disksets; iter != NULL; iter = iter->next) {
	    diskset_t *diskset = (diskset_t *)iter->obj;
	    if (string_case_compare(dsname, diskset->name) == 0) {
		return (B_TRUE);
	    }
	}

	return (B_FALSE);
}

/*
 * FUNCTION:	add_diskset(char *dsname)
 *
 * INPUT:	dsname	- a char * disk set name
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Add the named disk set to the list of known disk sets.
 */
static int
add_diskset(
	char	*dsname)
{
	dlist_t	*iter;
	int	error = 0;

	for (iter = _disksets; iter != NULL; iter = iter->next) {
	    diskset_t *diskset = (diskset_t *)iter->obj;
	    if (string_case_compare(diskset->name, dsname) == 0) {
		break;
	    }
	}

	if (iter == NULL) {

	    dlist_t *item = NULL;
	    diskset_t *diskset = (diskset_t *)calloc(1, sizeof (diskset_t));

	    if (diskset == NULL) {
		error = ENOMEM;
	    } else {
		diskset->hsps = NULL;
		diskset->name = strdup(dsname);
		if (diskset->name == NULL) {
		    free(diskset);
		    error = ENOMEM;
		} else {
		    if ((item = dlist_new_item(diskset)) == NULL) {
			free(diskset->name);
			free(diskset);
			error = ENOMEM;
		    } else {
			_disksets = dlist_append(item, _disksets, AT_HEAD);
			oprintf(OUTPUT_DEBUG,
				gettext("  added disk set %s \n"), dsname);
		    }
		}
	    }
	}

	return (error);
}

/*
 * FUNCTION:	add_diskset_diskname(char *diskset, char *diskname)
 *
 * INPUT:	dsname	- a char * disk set name
 *		diskname - a char * disk name
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Add the disk name to the named disk set's list of disks.
 *
 *		The input diskname is fully qualified with the path
 *		to the raw disk device (/dev/rdsk/cXtXdXsX) which is
 *		not relevant, so it is removed.
 */
static int
add_diskset_diskname(
	char	*dsname,
	char	*diskname)
{
	dlist_t *iter;
	int error = 0;

	for (iter = _disksets; iter != NULL; iter = iter->next) {

	    diskset_t *diskset = (diskset_t *)iter->obj;
	    if (string_case_compare(diskset->name, dsname) == 0) {

		dlist_t *item = NULL;
		char *name = NULL;
		char *cp = NULL;

		/* trim leading path */
		if ((cp = strrchr(diskname, '/')) != 0) {
		    if ((name = strdup(cp+1)) == NULL) {
			error = ENOMEM;
		    }
		} else if ((name = strdup(diskname)) == NULL) {
		    error = ENOMEM;
		}

		if ((item = dlist_new_item(name)) == NULL) {
		    free(name);
		    error = ENOMEM;
		} else {
		    diskset->disknames =
			dlist_append(item, diskset->disknames, AT_HEAD);
		}

		break;
	    }
	}

	if ((error == 0) && (iter == NULL)) {
	    /* new disk set */
	    if ((error = add_diskset(dsname)) == 0) {
		return (add_diskset_diskname(dsname, diskname));
	    }
	}

	return (error);
}

/*
 * FUNCTION:	add_diskset_hsp(char *dsname, char *hspname)
 *
 * INPUT:	dsname	- a char * disk set name
 *		hspname	- a char * HSP name
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Model a new HSP for the named disk set.
 *
 *		Metassist can use existing HSPs to service new volumes.
 *
 *		It is necessary to have a model of what HSPs currently
 *		exist for each disk set.
 *
 *		This function takes information found during discovery
 *		and turns it into a form usable by the HSP layout code.
 */
static int
add_diskset_hsp(
	char	*dsname,
	char	*hspname)
{
	dlist_t	*iter;
	int	error = 0;

	for (iter = _disksets; iter != NULL; iter = iter->next) {

	    diskset_t	*diskset = (diskset_t *)iter->obj;

	    if (string_case_compare(diskset->name, dsname) == 0) {

		dlist_t		*item = NULL;
		devconfig_t	*hsp = NULL;

		if (((error = new_devconfig(&hsp, TYPE_HSP)) != 0) ||
		    (error = devconfig_set_name(hsp, hspname))) {
		    free_devconfig(hsp);
		} else {
		    if ((item = dlist_new_item(hsp)) == NULL) {
			free_devconfig(hsp);
			error = ENOMEM;
		    } else {
			diskset->hsps =
			    dlist_append(item, diskset->hsps, AT_TAIL);

			oprintf(OUTPUT_DEBUG,
				gettext("  added %s to disk set %s\n"),
				hspname, dsname);
		    }
		}
		break;
	    }
	}

	if ((error == 0) && (iter == NULL)) {
	    if ((error = add_diskset(dsname)) == 0) {
		return (add_diskset_hsp(dsname, hspname));
	    }
	}

	return (error);
}

/*
 * FUNCTION:	add_diskset_hsp_spare(char *dsname, char *hspname,
 *			char *sparename)
 *
 * INPUT:	dsname	- a char * diskset name
 *		hspname	- a char * HSP name
 *		sparename - a char * hot spare (slice) name
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Locate the named hot spare pool in the named disk set and
 *		add the named spare slice to its list of spares.
 *
 *		Metassist can use existing HSPs to service new volumes.
 *
 *		It is necessary to have a model of what HSPs currently
 *		exist for each disk set.
 *
 *		This function takes information found during discovery
 *		and turns it into a form usable by the HSP layout code.
 */
static int
add_diskset_hsp_spare(
	char	*dsname,
	char	*hspname,
	char	*sparename)
{
	dlist_t	*iter;
	int	error = 0;

	for (iter = _disksets; iter != NULL; iter = iter->next) {

	    diskset_t	*diskset = (diskset_t *)iter->obj;

	    if (string_case_compare(diskset->name, dsname) == 0) {

		dlist_t *item =
		    dlist_find(
			    diskset->hsps, hspname,
			    compare_string_to_devconfig_name);

		if (item != NULL) {

		    /* add spare to HSP */
		    devconfig_t	*hsp = (devconfig_t *)item->obj;
		    dm_descriptor_t slice = (dm_descriptor_t)0;

		    (void) slice_get_by_name(sparename, &slice);
		    if (slice == (dm_descriptor_t)0) {
			oprintf(OUTPUT_TERSE,
				gettext("warning: ignoring nonexistent "
					"slice %s defined in %s\n"),
				sparename, hspname);
		    } else {

			uint64_t nbytes = 0;
			uint32_t index = 0;
			devconfig_t *spare = NULL;

			/* build a devconfig_t model of the slice */
			if (((error = slice_get_size(slice, &nbytes)) != 0) ||
			    (error = slice_get_index(slice, &index)) ||
			    (error = new_devconfig(&spare, TYPE_SLICE)) ||
			    (error = devconfig_set_name(spare, sparename)) ||
			    (error = devconfig_set_size(spare, nbytes)) ||
			    (error = devconfig_set_slice_index(spare, index))) {
			    free_devconfig(spare);
			} else {

			    if ((item = dlist_new_item(spare)) == NULL) {
				error = ENOMEM;
				free_devconfig(spare);
			    } else {
				dlist_t	*spares;
				spares = devconfig_get_components(hsp);
				spares = dlist_append(item, spares, AT_TAIL);
				devconfig_set_components(hsp, spares);

				oprintf(OUTPUT_DEBUG,
					gettext("  added %s to %s in "
						"disk set %s\n"),
					sparename, hspname, dsname);
			    }
			}
		    }

		    break;

		} else {
		    if ((error = add_diskset_hsp(dsname, hspname)) == 0) {
			return (add_diskset_hsp_spare(
					dsname, hspname, sparename));
		    }
		}
	    }
	}

	return (error);
}

/*
 * Return a list of disks in the given diskset.
 *
 * @param       dsname
 *              The name of the named disk set, or "" for the local
 *              set.
 *
 * @param       disks
 *              RETURN: pointer to the list of disks in the given disk
 *              set
 *
 * @return      0 if succesful, non-zero otherwise
 */
int
get_disks_in_diskset(
	char *dsname,
	dlist_t **disks)
{
	dlist_t *known_disks;
	int error = 0;

	*disks = NULL;

	if ((error = get_known_disks(&known_disks)) == 0) {
	    dlist_t *iter;

	    /* For each known disk... */
	    for (iter = known_disks;
		iter != NULL && error == 0;
		iter = iter->next) {
		dm_descriptor_t disk = (uintptr_t)iter->obj;
		boolean_t in_diskset = B_FALSE;

		/* If this disk is in the given set... */
		error = is_disk_in_diskset(disk, dsname, &in_diskset);
		if (error == 0 && in_diskset == B_TRUE) {
		    dlist_t *item = dlist_new_item((void *)(uintptr_t)disk);
		    *disks = dlist_append(item, *disks, AT_TAIL);
		}
	    }
	}

	return (error);
}

/*
 * FUNCTION:	is_disk_in_diskset(dm_descriptor_t disk, char *dsname,
 *			boolean_t *bool)
 *
 * INPUT:	disk	- dm_descriptor_t disk handle
 *		dsname	- char * diskset name, or MD_LOCAL_NAME for
 *		the local set.
 *
 * OUTPUT:	bool	- pointer to a boolean_t to hold the result
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Determine if the input disk is known to be in the
 *		given diskset.
 */
int
is_disk_in_diskset(
	dm_descriptor_t	disk,
	char		*dsname,
	boolean_t	*bool)
{
	if (string_case_compare(dsname, MD_LOCAL_NAME) == 0) {
	    return (is_disk_in_local_diskset(disk, bool));
	}

	return (is_disk_in_named_diskset(disk, dsname, bool));
}

static int
is_disk_in_local_diskset(
	dm_descriptor_t	disk,
	boolean_t	*bool)
{
	dlist_t *iter;
	dlist_t *aliases = NULL;
	boolean_t in_named_diskset = B_FALSE;
	char *name = NULL;
	int error = 0;

	*bool = B_FALSE;

	error = get_display_name(disk, &name);
	if (error == 0) {

	    error = get_aliases(disk, &aliases);
	    if (error == 0) {

		/* For each known disk set... */
		for (iter = _disksets;
		    iter != NULL && in_named_diskset == B_FALSE;
		    iter = iter->next) {

		    diskset_t *diskset = (diskset_t *)iter->obj;
		    dlist_t *names = diskset->disknames;

		    /* Check disk name */
		    in_named_diskset = dlist_contains(
			names, name, compare_device_names);

		    /* Check disk aliases */
		    if (in_named_diskset == B_FALSE) {
			dlist_t *iter2;
			for (iter2 = aliases;
			    iter2 != NULL && in_named_diskset == B_FALSE;
			    iter2 = iter2->next) {
			    in_named_diskset = dlist_contains(names,
				(char *)iter2->obj, compare_device_names);
			}
		    }
		}
	    }
	}

	if (error == 0) {
	    *bool = (in_named_diskset == B_TRUE ? B_FALSE : B_TRUE);
	}

	return (error);
}

static int
is_disk_in_named_diskset(
	dm_descriptor_t	disk,
	char		*dsname,
	boolean_t	*bool)
{
	dlist_t		*iter;
	int		error = 0;
	boolean_t 	in_diskset = B_FALSE;

	*bool = B_FALSE;

	for (iter = _disksets;
	    (iter != NULL) && (in_diskset == B_FALSE);
	    iter = iter->next) {

	    diskset_t *diskset = (diskset_t *)iter->obj;

	    if (string_case_compare(diskset->name, dsname) == 0) {

		dlist_t *names = diskset->disknames;
		dlist_t *aliases = NULL;
		char	*name = NULL;

		((error = get_display_name(disk, &name)) != 0) ||
		(error = get_aliases(disk, &aliases));
		if (error != 0) {
		    break;
		}

		/* check disk name */
		in_diskset = dlist_contains(names, name, compare_device_names);

		/* check disk aliases */
		if (in_diskset == B_FALSE) {
		    dlist_t *iter2;
		    for (iter2 = aliases;
			(iter2 != NULL) && (in_diskset == B_FALSE);
			iter2 = iter2->next) {
			in_diskset = dlist_contains(names,
				(char *)iter2->obj, compare_device_names);
		    }
		}
	    }
	}

	*bool = in_diskset;

	return (error);
}

/*
 * FUNCTION:	is_disk_in_other_diskset(dm_descriptor_t disk, char *dsname,
 *			boolean_t *bool)
 *
 * INPUT:	disk	- dm_descriptor_t disk handle
 *		dsname	- char * disk set name
 *
 * OUTPUT:	bool	- pointer to a boolean_t to hold the result.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Determine if the named disk is known to be in a disk set
 *		other than the named disk set.
 */
int
is_disk_in_other_diskset(
	dm_descriptor_t disk,
	char	*dsname,
	boolean_t *bool)
{
	boolean_t in_other = B_FALSE;
	dlist_t	*iter;
	dlist_t *aliases = NULL;
	char	*name = NULL;
	char	*cp = NULL;
	int	error = 0;

	((error = get_display_name(disk, &name)) != 0) ||
	(error = get_aliases(disk, &aliases));
	if (error != 0) {
	    return (error);
	}

	/*
	 * discard the leading path, it is probably /dev/dsk
	 * and the disk set disk names are all /dev/rdsk/...
	 *
	 * aliases do not have leading paths
	 */
	cp = strrchr(name, '/');
	if (cp != NULL) {
	    ++cp;
	} else {
	    cp = name;
	}
	name = cp;

	for (iter = _disksets;
	    (iter != NULL) && (in_other == B_FALSE);
	    iter = iter->next) {

	    diskset_t	*diskset = (diskset_t *)iter->obj;
	    dlist_t	*names = diskset->disknames;

	    if (string_case_compare(diskset->name, dsname) == 0) {
		/* skip named disk set */
		continue;
	    }

	    /* see if disk's name is in disk set's name list */
	    in_other = dlist_contains(names, name, compare_device_names);

	    /* see if any of the disk's aliases is in name list */
	    if (in_other == B_FALSE) {
		dlist_t *iter2;
		for (iter2 = aliases;
		    (iter2 != NULL) && (in_other == B_FALSE);
		    iter2 = iter2->next) {

		    in_other = dlist_contains(names,
			    (char *)iter2->obj, compare_device_names);
		}
	    }
	}

	*bool = in_other;

	return (error);
}

/*
 * FUNCTION:	hsp_get_default_for_diskset(char *diskset,
 *			devconfig_t **hsp)
 *
 * INPUT:	diskset	- char * disk set name
 *
 * RETURNS:	devconfig_t * - pointer to the first HSP in the disk set
 *			NULL if none found
 *
 * PURPOSE:	Locate the first HSP in the named disk set.
 */
int
hsp_get_default_for_diskset(
	char	*diskset,
	devconfig_t **hsp)
{
	dlist_t		*iter = _disksets;

	*hsp = NULL;

	for (; (iter != NULL) && (*hsp == NULL); iter = iter->next) {
	    diskset_t *set = (diskset_t *)iter->obj;
	    if (string_case_compare(set->name, diskset) == 0) {
		dlist_t *item = set->hsps;
		if (item != NULL) {
		    *hsp = item->obj;
		}
	    }
	}

	return (0);
}

/*
 * FUNCTION:	get_n_metadb_replicas(int *nreplicas)
 *
 * OUTPUT:	nreplicas - pointer to int to hold the result
 *
 * RETURNS:	int	- 0 on success
 *			 !0 on failure
 *
 * PURPOSE:	Check the number of replicas configured for the local set.
 */
int
get_n_metadb_replicas(
	int	*nreplicas)
{
	mdsetname_t	*sp;
	md_replicalist_t *rlp = NULL;
	md_error_t	mderror = mdnullerror;
	int		error = 0;

	*nreplicas = 0;

	sp = metasetname(MD_LOCAL_NAME, &mderror);
	if (!mdisok(&mderror)) {
	    volume_set_error(mde_sperror(&mderror, NULL));
	    mdclrerror(&mderror);
	    error = -1;
	} else {
	    *nreplicas = metareplicalist(sp, MD_BASICNAME_OK, &rlp, &mderror);
	    if (!mdisok(&mderror)) {
		volume_set_error(mde_sperror(&mderror, NULL));
		mdclrerror(&mderror);
		error = -1;
	    } else if (rlp != NULL) {
		metafreereplicalist(rlp);
		rlp = NULL;
	    }

	    if (*nreplicas < 0) {
		*nreplicas = 0;
	    }
	}

	return (error);
}

/*
 * FUNCTION:	hsp_get_by_name(char *diskset, char *name,
 *		devconfig_t **hsp)
 *
 * INPUT:	diskset	- char * disk set name
 *		name	- char * HSP name
 *
 * OUTPUT:	hsp	- a devconfig_t * - pointer to hold
 *			  the named HSP if none found
 *
 * PURPOSE:	Locate the named HSP in the named disk set.
 */
int
hsp_get_by_name(
	char		*diskset,
	char		*name,
	devconfig_t	**hsp)
{
	dlist_t		*iter = _disksets;

	*hsp = NULL;

	for (; (iter != NULL) && (*hsp == NULL); iter = iter->next) {
	    diskset_t *set = (diskset_t *)iter->obj;
	    if (string_case_compare(set->name, diskset) == 0) {
		dlist_t *item = dlist_find(
			set->hsps, name, compare_string_to_devconfig_name);
		if (item != NULL) {
		    *hsp = item->obj;
		}
	    }
	}

	return (0);
}

/*
 * FUNCTION:	is_volume_name_valid(char *name)
 *
 * OUTPUT:	name	- pointer to a char * volume name
 *
 * RETURNS:	boolean_t - B_TRUE if the input name is valid
 *			 B_FALSE otherwise
 *
 * PURPOSE:	Wrapper around libmeta volume name validation method.
 */
boolean_t
is_volume_name_valid(
	char		*name)
{
	return (is_metaname(name));
}

/*
 * FUNCTION:	is_hsp_name_valid(char *name)
 *
 * INPUT:	name	- char * HSP name
 *
 * RETURNS:	boolean_t - B_TRUE if the input name is valid
 *			 B_FALSE otherwise
 *
 * PURPOSE:	Wrapper around libmeta HSP name validation method.
 */
boolean_t
is_hsp_name_valid(
	char		*name)
{
	return (is_hspname(name));
}

/*
 * FUNCTION:	extract_index(char *name, char *prefix, char *num_fmt,
 *			int *index)
 *
 * INPUT:	name	- const char * volume name
 *		prefix	- const char * fixed part of format string
 *		num_fmt	- const char * format of number to extract (e.g. %d)
 *
 * OUTPUT:	index	- pointer to int to hold numeric part of name
 *
 * RETURNS:	boolean_t - B_TRUE if the input name is parsed correctly
 *			 B_FALSE otherwise
 *
 * PURPOSE:	Extract the numeric portion of a device name for use
 *		by higher-level functions.
 */
static boolean_t
extract_index(
	const char	*name,
	const char	*prefix,
	const char	*num_fmt,
	int		*index)
{
	char		buf[MAXNAMELEN];
	const char	*cp;
	const char	*fmt = buf;

	if ((cp = strrchr(name, '/')) != NULL) {
	    ++cp;
	} else {
	    cp = name;
	}

	(void) snprintf(buf, sizeof (buf), "%s%s", prefix, num_fmt);
	if (sscanf(cp, fmt, index) == 1)
		return (B_TRUE);
	else
		return (B_FALSE);
}

/*
 * FUNCTION:	is_volume_name_in_range(char *name)
 *
 * INPUT:	name	- char * volume name
 *
 * RETURNS:	boolean_t - B_TRUE if the input name is in the allowed
 *				range of names
 *			 B_FALSE otherwise
 *
 * PURPOSE:	Determine if the input volume name is within the allowed
 *		range of device names (0 <= n < max # of devices configured).
 */
boolean_t
is_volume_name_in_range(
	char		*name)
{
	int		index = -1;

	if (extract_index(name, _dev_prefix, "%d", &index)) {
	    if (index >= 0 && index < _max_devs_cfg) {
		return (B_TRUE);
	    }
	}

	return (B_FALSE);
}

/*
 * FUNCTION:	reserve_volume_name(char *name)
 *
 * INPUT:	name	- a char * volume name
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Mark a volume name/number as used.
 *
 *		Assumes that the input name has been validated.
 *
 *		if the name is not currently available, return -1
 */
int
reserve_volume_name(
	char		*name)
{
	int		index = -1;

	if (extract_index(name, _dev_prefix, "%d", &index)) {
	    if (devs_by_number[index] != B_TRUE) {
		devs_by_number[index] = B_TRUE;
		return (0);
	    }
	}

	return (-1);
}

/*
 * FUNCTION:	reserve_hsp_name(char *name)
 *
 * INPUT:	name	- a char * hsp name
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Mark a HSP name/number as used.
 *
 *		Assumes that the input name has been validated.
 *
 *		if the name is not currently available, return -1
 */
int
reserve_hsp_name(
	char		*name)
{
	int		index = -1;

	if (extract_index(name, _hsp_prefix, "%03d", &index)) {
	    if (hsps_by_number[index] != B_TRUE) {
		hsps_by_number[index] = B_TRUE;
		return (0);
	    }
	}

	return (-1);
}

/*
 * FUNCTION:	release_volume_name(char *name)
 *
 * INPUT:	name	- a char * volume name
 *
 * PURPOSE:	release the input volume name.
 *
 *		Extract volume number from the input name
 *		and use it to index into the array of used
 *		volume numbers.  Make that volume number
 *		available for use again.
 */
void
release_volume_name(
	char		*name)
{
	int		index = -1;

	if (name != NULL && extract_index(name, _dev_prefix, "%d", &index)) {
		oprintf(OUTPUT_DEBUG,
			gettext("released volume name %s%d\n"),
			_dev_prefix, index);
		devs_by_number[index] = B_FALSE;
	}
}

/*
 * FUNCTION:	release_hsp_name(char *name)
 *
 * INPUT:	name	- a char * HSP name
 *
 * PURPOSE:	release the input HSP name.
 *
 *		Extract volume number from the input name
 *		and use it to index into the array of used
 *		hsp numbers.  Make that hsp number available
 *		for use again.
 */
void
release_hsp_name(
	char		*name)
{
	int		index = -1;

	if (name != NULL && extract_index(name, _hsp_prefix, "%d", &index)) {
		oprintf(OUTPUT_DEBUG,
			gettext("released hsp name %s%d\n"),
			_hsp_prefix, index);
		hsps_by_number[index] = B_FALSE;
	}
}

/*
 * FUNCTION:	get_next_volume_name(char **name)
 *
 * OUTPUT:	name	- pointer to a char * to hold volume name
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	generate a new volume name using the standard device
 *		name prefix and the lowest available device number.
 *
 *		if type == MIRROR, determine the next available mirror
 *		name according to the convention that a mirror name is
 *		a multiple of 10.
 *
 *		If such a name is unavailable, use the next available name.
 */
int
get_next_volume_name(
    char		**name,
    component_type_t	type)
{
	int	next = 0;

	for (next = 0; next < _max_devs_cfg; ++next) {
	    if ((type == TYPE_MIRROR && ((next % 10) != 0)) ||
		(type != TYPE_MIRROR && ((next % 10) == 0))) {
		/* use/save multiples of 10 for mirrors */
		continue;
	    }
	    if (devs_by_number[next] != B_TRUE) {
		break;
	    }
	}

	if ((next == _max_devs_cfg) && (type == TYPE_MIRROR)) {
	    /* try next sequentially available name */
	    for (next = 0; next < _max_devs_cfg; ++next) {
		if (devs_by_number[next] != B_TRUE) {
		    break;
		}
	    }
	}

	if (next == _max_devs_cfg) {
	    volume_set_error(
		    gettext("ran out of logical volume names.\n"));
	    return (-1);
	}

	*name = (char *)calloc(MAXNAMELEN, sizeof (char));
	if (*name == NULL) {
	    return (ENOMEM);
	}

	(void) snprintf(*name, MAXNAMELEN-1, "%s%d", _dev_prefix, next);

	devs_by_number[next] = B_TRUE;
	return (0);
}

/*
 * FUNCTION:	get_next_submirror_name(char *mname, char **subname)
 *
 * INPUT:	mname	- pointer to a char * mirror name
 * OUTPUT:	subname	- pointer to a char * to hold submirror name
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Determine the next available submirror name according
 *		to the convention that each submirror name is a sequential
 *		increment of its mirror's name.
 *
 *		If such a name is unavailable, return the next sequentially
 *		available volume name.
 */
int
get_next_submirror_name(
	char	*mname,
	char	**subname)
{
	char	buf[MAXNAMELEN];
	int 	error = 0;
	int	next = 0;
	int	i = 0;

	*subname = NULL;

	/* try next sequential name: mirror + 1... */
	if (extract_index(mname, _dev_prefix, "%d", &next)) {
	    for (i = next + 1; i < _max_devs_cfg; i++) {
		if ((i % 10) == 0) {
		    /* save for mirrors */
		    continue;
		}
		if (devs_by_number[i] == B_FALSE) {
		    (void) snprintf(buf, MAXNAMELEN-1, "%s%d", _dev_prefix, i);
		    if ((*subname = strdup(buf)) != NULL) {
			devs_by_number[i] = B_TRUE;
		    } else {
			error = ENOMEM;
		    }
		    break;
		}
	    }
	}

	if ((error == 0) && (*subname == NULL)) {
	    /* name adhering to convention isn't available, */
	    /* use next sequentially available name */
	    error = get_next_volume_name(subname, TYPE_STRIPE);
	}

	return (error);
}

/*
 * FUNCTION:	get_next_hsp_name(char **name)
 *
 * OUTPUT:	name	- pointer to a char * to hold name
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Helper which generates a new hotsparepool name
 *		using the standard name prefix and the lowest
 *		available hsp number.
 */
int
get_next_hsp_name(
    char	**name)
{
	int	 next = 0;

	for (next = 0; next < _max_hsps; ++next) {
	    if (hsps_by_number[next] != B_TRUE) {
		break;
	    }
	}

	if (next == _max_hsps) {
	    volume_set_error(gettext("ran out of HSP names"));
	    return (-1);
	}

	*name = (char *)calloc(MAXNAMELEN, sizeof (char));
	if (*name == NULL) {
	    oprintf(OUTPUT_TERSE,
		    gettext("failed to allocate volume name string, "
			    "out of memory"));
	    return (ENOMEM);
	}

	(void) snprintf(*name, MAXNAMELEN-1, "%s%03d", _hsp_prefix, next);

	hsps_by_number[next] = B_TRUE;

	return (0);
}

static char *
type_name(
	svm_type_t type)
{
	switch (type) {
	case SVM_DISKSET:	return (gettext("disk set"));
	case SVM_MDB:		return (gettext("metadb"));
	case SVM_STRIPE:	return (gettext("stripe"));
	case SVM_MIRROR:	return (gettext("mirror"));
	case SVM_RAID:		return (gettext("raid"));
	case SVM_TRANS:		return (gettext("trans"));
	case SVM_SP:		return (gettext("soft partition"));
	case SVM_HSP:		return (gettext("hot spare pool"));
	case SVM_HS:		return (gettext("hot spare"));
	case SVM_DRIVE:		return (gettext("drive"));
	default:		return (gettext("unknown"));
	}
}

static svm_snap_t *
svm_snapshot(int *errp)
{
	svm_snap_t	*svm_listp = NULL;

	*errp = 0;

	/* initialize the cluster library entry points */
	if (sdssc_bind_library() == SDSSC_ERROR) {

	    volume_set_error(gettext("sdssc_bin_library() failed\n"));
	    *errp = -1;

	} else {

	    /* load the SVM cache */
	    *errp = load_svm(&svm_listp);

	    if (*errp != 0) {
		free_svm_snapshot(svm_listp);
		svm_listp = NULL;
	    }

	}

	return (svm_listp);
}

static void
free_svm_snapshot(svm_snap_t *listp) {

	svm_snap_t	*nextp;

	while (listp != NULL) {
	    nextp = listp->next;
	    free((void *)listp->diskset);
	    free((void *)listp->name);
	    free((void *)listp->slice);
	    free((void *)listp);
	    listp = nextp;
	}
}

static int
add_record(
	svm_snap_t **listp,
	char *setname,
	svm_type_t type,
	char *mname,
	char *slice_name)
{
	svm_snap_t *sp;

	sp = (svm_snap_t *)malloc(sizeof (svm_snap_t));
	if (sp == NULL) {
	    return (ENOMEM);
	}

	if ((sp->diskset = strdup(setname)) == NULL) {
	    free(sp);
	    return (ENOMEM);
	}

	if ((sp->name = strdup(mname)) == NULL) {
	    free(sp->diskset);
	    free(sp);
	    return (ENOMEM);
	}

	sp->type = type;

	if ((sp->slice = strdup(slice_name)) == NULL) {
	    free(sp->diskset);
	    free(sp->name);
	    free(sp);
	    return (ENOMEM);
	}

	sp->next = *listp;
	*listp = sp;

	return (0);
}

static int
diskset_info(
	svm_snap_t **listp,
	mdsetname_t *sp)
{
	md_error_t		error = mdnullerror;
	md_replicalist_t	*replica_list = NULL;
	md_replicalist_t	*mdbp;
	mdnamelist_t		*nlp;
	mdnamelist_t		*trans_list = NULL;
	mdnamelist_t		*mirror_list = NULL;
	mdnamelist_t		*raid_list = NULL;
	mdnamelist_t		*stripe_list = NULL;
	mdnamelist_t		*sp_list = NULL;
	mdhspnamelist_t		*hsp_list = NULL;

	if (metareplicalist(sp, MD_BASICNAME_OK, &replica_list, &error) < 0) {
	    /* there are no metadb's; that is ok, no need to check the rest */
	    mdclrerror(&error);
	    return (0);
	}
	mdclrerror(&error);

	for (mdbp = replica_list; mdbp != NULL; mdbp = mdbp->rl_next) {
	    char size[MAXPATHLEN];

	    (void) snprintf(size, sizeof (size), "%d",
		    (int)mdbp->rl_repp->r_nblk);

	    if (new_entry(listp, mdbp->rl_repp->r_namep->cname, SVM_MDB, size,
		sp)) {
		metafreereplicalist(replica_list);
		return (ENOMEM);
	    }
	}
	metafreereplicalist(replica_list);

	if (meta_get_trans_names(sp, &trans_list, 0, &error) >= 0) {
	    for (nlp = trans_list; nlp != NULL; nlp = nlp->next) {
		if (new_entry(listp, nlp->namep->cname, SVM_TRANS,
		    nlp->namep->cname, sp)) {
		    free_names(trans_list);
		    return (ENOMEM);
		}
	    }

	    free_names(trans_list);
	}
	mdclrerror(&error);

	if (meta_get_mirror_names(sp, &mirror_list, 0, &error) >= 0) {
	    for (nlp = mirror_list; nlp != NULL; nlp = nlp->next) {
		if (add_record(listp, sp->setname, SVM_MIRROR,
		    nlp->namep->cname, "")) {
		    free_names(mirror_list);
		    return (ENOMEM);
		}
	    }

	    free_names(mirror_list);
	}
	mdclrerror(&error);

	if (meta_get_raid_names(sp, &raid_list, 0, &error) >= 0) {
	    for (nlp = raid_list; nlp != NULL; nlp = nlp->next) {
		mdname_t	*mdn;
		md_raid_t	*raid;

		mdn = metaname(&sp, nlp->namep->cname, META_DEVICE, &error);
		mdclrerror(&error);
		if (mdn == NULL) {
		    continue;
		}

		raid = meta_get_raid(sp, mdn, &error);
		mdclrerror(&error);

		if (raid != NULL) {
		    int i;

		    for (i = 0; i < raid->cols.cols_len; i++) {
			if (new_entry(listp,
			    raid->cols.cols_val[i].colnamep->cname, SVM_RAID,
			    nlp->namep->cname, sp)) {
			    free_names(raid_list);
			    return (ENOMEM);
			}
		    }
		}
	    }

	    free_names(raid_list);
	}
	mdclrerror(&error);

	if (meta_get_stripe_names(sp, &stripe_list, 0, &error) >= 0) {
	    for (nlp = stripe_list; nlp != NULL; nlp = nlp->next) {
		mdname_t	*mdn;
		md_stripe_t	*stripe;

		mdn = metaname(&sp, nlp->namep->cname, META_DEVICE, &error);
		mdclrerror(&error);
		if (mdn == NULL) {
		    continue;
		}

		stripe = meta_get_stripe(sp, mdn, &error);
		mdclrerror(&error);

		if (stripe != NULL) {
		    int i;

		    for (i = 0; i < stripe->rows.rows_len; i++) {
			md_row_t	*rowp;
			int		j;

			rowp = &stripe->rows.rows_val[i];

			for (j = 0; j < rowp->comps.comps_len; j++) {
			    md_comp_t	*component;

			    component = &rowp->comps.comps_val[j];
			    if (new_entry(listp, component->compnamep->cname,
				SVM_STRIPE, nlp->namep->cname, sp)) {
				free_names(stripe_list);
				return (ENOMEM);
			    }
			}
		    }
		}
	    }

	    free_names(stripe_list);
	}
	mdclrerror(&error);

	if (meta_get_sp_names(sp, &sp_list, 0, &error) >= 0) {
	    for (nlp = sp_list; nlp != NULL; nlp = nlp->next) {
		mdname_t	*mdn;
		md_sp_t		*soft_part;

		mdn = metaname(&sp, nlp->namep->cname, META_DEVICE, &error);
		mdclrerror(&error);
		if (mdn == NULL) {
		    continue;
		}

		soft_part = meta_get_sp(sp, mdn, &error);
		mdclrerror(&error);

		if (soft_part != NULL) {
		    if (new_entry(listp, soft_part->compnamep->cname, SVM_SP,
			nlp->namep->cname, sp)) {
			free_names(sp_list);
			return (ENOMEM);
		    }
		}
	    }

	    free_names(sp_list);
	}
	mdclrerror(&error);

	if (meta_get_hsp_names(sp, &hsp_list, 0, &error) >= 0) {
	    mdhspnamelist_t *nlp;

	    for (nlp = hsp_list; nlp != NULL; nlp = nlp->next) {
		md_hsp_t	*hsp;

		hsp = meta_get_hsp(sp, nlp->hspnamep, &error);
		mdclrerror(&error);
		if (hsp != NULL) {
		    int	i;

		    for (i = 0; i < hsp->hotspares.hotspares_len; i++) {
			md_hs_t	*hs;

			hs = &hsp->hotspares.hotspares_val[i];

			if (add_record(listp, sp->setname, SVM_HS,
			    nlp->hspnamep->hspname, hs->hsnamep->bname)) {
			    metafreehspnamelist(hsp_list);
			    return (ENOMEM);
			}
		    }
		}

		if (add_record(listp, sp->setname, SVM_HSP,
		    nlp->hspnamep->hspname, "")) {
		    metafreehspnamelist(hsp_list);
		    return (ENOMEM);
		}
	    }

	    metafreehspnamelist(hsp_list);
	}

	mdclrerror(&error);

	return (0);
}

static void
free_names(
	mdnamelist_t *nlp)
{
	mdnamelist_t *p;

	for (p = nlp; p != NULL; p = p->next) {
	    meta_invalidate_name(p->namep);
	}
	metafreenamelist(nlp);
}

/*
 * Create a list of SVM devices
 */
static int
load_svm(
	svm_snap_t **listp)
{
	int		max_sets;
	md_error_t	error = mdnullerror;
	int		i;

	if ((max_sets = get_max_sets(&error)) == 0) {
	    return (0);
	}

	if (!mdisok(&error)) {
	    volume_set_error(
		    gettext("failed to get maximum number of disk sets.\n"));
	    mdclrerror(&error);
	    return (-1);
	}

	/* for each possible set number, see if we really have a disk set */
	for (i = 0; i < max_sets; i++) {
	    mdsetname_t		*sp;

	    if ((sp = metasetnosetname(i, &error)) == NULL) {
		if (!mdisok(&error) && error.info.errclass == MDEC_RPC) {
		    /* rpc error - no metasets */
		    break;
		}

		mdclrerror(&error);
		continue;
	    }

	    mdclrerror(&error);

	    if (add_record(listp, sp->setname, SVM_DISKSET, sp->setname, "")) {
		metaflushsetname(sp);
		return (ENOMEM);
	    }

	    /* check for drives in disk sets */
	    if (sp->setno != 0) {
		md_drive_desc	*dd;

		dd = metaget_drivedesc(sp, MD_BASICNAME_OK | PRINT_FAST,
		    &error);
		mdclrerror(&error);
		for (; dd != NULL; dd = dd->dd_next) {
		    if (add_record(listp, sp->setname, SVM_DRIVE,
			dd->dd_dnp->rname, "")) {
			metaflushsetname(sp);
			return (ENOMEM);
		    }
		}
	    }

	    if (diskset_info(listp, sp)) {
		metaflushsetname(sp);
		return (ENOMEM);
	    }

	    metaflushsetname(sp);
	}

	mdclrerror(&error);

	return (0);
}

/* determine if 'sp' is built on a slice */
static int
new_entry(
	svm_snap_t **listp,
	char *slice_name,
	svm_type_t type,
	char *mname,
	mdsetname_t *sp)
{
	mdname_t	*mdn;
	md_error_t	 error = mdnullerror;
	meta_device_type_t	uname_type = UNKNOWN;

	/* Determine the appropriate uname type for metaname */
	if (type == SVM_MDB || type == SVM_DRIVE || type == SVM_TRANS)
		uname_type = LOGICAL_DEVICE;

	mdn = metaname(&sp, slice_name, uname_type, &error);
	if (!mdisok(&error)) {
	    mdn = NULL;
	}
	mdclrerror(&error);

	if (mdn != NULL && (
	    mdn->drivenamep->type == MDT_ACCES ||
	    mdn->drivenamep->type == MDT_COMP ||
	    mdn->drivenamep->type == MDT_FAST_COMP)) {

	    return (add_record(listp, sp->setname, type, mname, mdn->bname));
	} else {
	    return (add_record(listp, sp->setname, type, mname, ""));
	}
}

/*
 * FUNCTION:	get_default_stripe_interlace()
 *
 * RETURNS:	uint64_t - default stripe interlace value
 *
 * PURPOSE:	Helper which retrieves the default stripe interlace
 *		from libmeta.
 */
uint64_t
get_default_stripe_interlace()
{
	/* convert back to bytes */
	return ((uint64_t)meta_default_stripe_interlace() * DEV_BSIZE);
}

/*
 * FUNCTION:	get_max_number_of_devices(int *max)
 *
 * OUTPUT:	max	- pointer to int to hold the configured maximum number
 *				of SVM devices
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Helper which determines the maximum number of allowed
 *		SVM devices configured for the system.
 *
 *		Wrapper around libmeta function meta_get_max_nunits().
 */
int
get_max_number_of_devices(
	int	*max)
{
	md_error_t	mderror = mdnullerror;

	*max = meta_get_nunits(&mderror);
	if (!mdisok(&mderror)) {
	    volume_set_error(mde_sperror(&mderror, NULL));
	    mdclrerror(&mderror);
	    return (-1);
	}

	return (0);
}

/*
 * FUNCTION:	get_max_number_of_disksets(int *max)
 *
 * OUTPUT:	max	- pointer to in to hold the configured maximum number
 *				of disk sets
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Helper which determines the maximum number of allowed
 *		disk sets which has been configured for the system.
 *
 *		Wrapper around libmeta function get_max_sets().
 */
int
get_max_number_of_disksets(
	int	*max)
{
	md_error_t	mderror = mdnullerror;

	*max = get_max_sets(&mderror);
	if (!mdisok(&mderror)) {
	    volume_set_error(mde_sperror(&mderror, NULL));
	    mdclrerror(&mderror);
	    return (-1);
	}

	return (0);
}

/*
 * FUNCTION:	is_reserved_replica_slice_index(char *diskset, char *dname,
 *			uint32_t index, boolean_t *bool)
 *
 * INPUT:	diskset	- char * disk set name
 *		dname	- char * disk name
 *		index	- integer index of interest
 *
 * OUTPUT:	bool	- pointer to a boolean_t to hold the result
 *
 * RETURNS:	int	-  0 - success
 *			  !0 - failure
 *
 * PURPOSE:	Helper which determines if the input slice index on
 *		the named disk in the named disk set is the replica
 *		slice that is reserved on disks in disk sets.
 *
 *		The named disk is assumed to be in the named disk set.
 *
 *		Determines if metassist is being run in a simulated
 *		hardware enironment, if not the libmeta function to
 *		determine the replica slice index is called.
 *
 *		If simulation is active, then a local implementation
 *		is used to determine the replica slice index.
 */
int
is_reserved_replica_slice_index(
	char *diskset,
	char *dname,
	uint32_t index,
	boolean_t *bool)
{
	int		error = 0;
	boolean_t	sim = B_FALSE;
	static char	*simfile = "METASSISTSIMFILE";

	sim = ((getenv(simfile) != NULL) && (strlen(getenv(simfile)) > 0));

	if (sim != B_TRUE) {

	    /* sim disabled: use meta_replicaslice() */

	    md_error_t		mderror = mdnullerror;
	    mdsetname_t		*sp;
	    mddrivename_t	*dnp;
	    uint_t		replicaslice;

	    /* slice assumed to be on disk in the named disk set */
	    sp = metasetname(diskset, &mderror);
	    if (!mdisok(&mderror)) {
		volume_set_error(mde_sperror(&mderror, NULL));
		mdclrerror(&mderror);
		return (-1);
	    }

	    dnp = metadrivename(&sp, dname, &mderror);
	    if (!mdisok(&mderror)) {
		volume_set_error(mde_sperror(&mderror, NULL));
		mdclrerror(&mderror);
		return (-1);
	    }

	    if (meta_replicaslice(dnp, &replicaslice, &mderror) != 0) {
		volume_set_error(mde_sperror(&mderror, NULL));
		mdclrerror(&mderror);
		return (-1);
	    }

	    *bool = (replicaslice == (uint_t)index);

	} else {

	    dm_descriptor_t	disk;
	    boolean_t		efi = B_FALSE;

	    /* sim enabled: use same logic as meta_replicaslice() */
	    ((error = disk_get_by_name(dname, &disk)) != 0) ||
	    (error = disk_get_is_efi(disk, &efi));
	    if (error == 0) {

		if (efi == B_FALSE) {
		    *bool = (index == MD_SLICE7);
		} else {
		    *bool = (index == MD_SLICE6);
		}
	    }
	}

	return (error);
}
