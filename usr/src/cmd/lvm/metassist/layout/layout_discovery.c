/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <limits.h>
#include <libdiskmgt.h>
#include <libintl.h>

#include <meta.h>

#define	_LAYOUT_DISCOVERY_C

#include "volume_dlist.h"
#include "volume_error.h"
#include "volume_nvpair.h"
#include "volume_output.h"

#include "layout_device_cache.h"
#include "layout_device_util.h"
#include "layout_dlist_util.h"
#include "layout_discovery.h"
#include "layout_request.h"
#include "layout_slice.h"
#include "layout_svm_util.h"

/*
 * lists of device dm_descriptor_t handles discovered during
 * the initial system probe.  Lists are populated by
 * discover_known_devices.
 *
 * "bad" slices are those that are known to libdiskmgt but
 * cannot be accessed. An example would be a slice that has
 * disappeared due to disk re-slicing: libdiskmgt may have a
 * cached handle for it, but the slice no longer exists.
 *
 * "bad" disks are thoese that are known to libdiskmgt but
 * cannot be accessed.  An example would be a disk that has
 * failed or has gone offline: libdiskmgt may have a cached
 * handle for it, but the disk does not respond.
 */
static dlist_t	*_bad_slices = NULL;
static dlist_t	*_bad_disks = NULL;

static dlist_t	*_known_slices = NULL;
static dlist_t	*_known_disks = NULL;
static dlist_t	*_known_hbas = NULL;

/*
 * helper functions for building known device lists, used by
 * discover_known_devices.
 */
static int generate_known_slices(dlist_t *disks, dlist_t **known,
	dlist_t **bad);
static int generate_known_disks(dlist_t **known, dlist_t **bad);
static int generate_known_hbas(dlist_t *disks, dlist_t **known);
static int generate_known_hba_name(
	dm_descriptor_t hba,
	dm_descriptor_t	alias,
	dm_descriptor_t disk);

static void print_known_devices();
static void print_device_list(dlist_t *devices);

/*
 * lists of device dm_descriptor_t handles that are usable by layout.
 * These devices must still pass the user specified available/unavailable
 * filter before they're actually considered available.
 *
 * Lists are populated by discover_usable_devices.
 */
static dlist_t	*_usable_slices = NULL;
static dlist_t	*_usable_disks = NULL;
static dlist_t	*_usable_hbas = NULL;

/*
 * private flag that remembers if any HBA is known to support MPXIO
 */
static boolean_t _mpxio_enabled = B_FALSE;

/*
 * The slice_class struct is used to group slices by usage class.
 */
typedef struct {
	char	*usage;		/* usage description */
	dlist_t	*sliceinfo;	/* list with info about each slice with usage */
} slice_class_t;

#define	USE_DISKSET	"diskset"

static int check_slice_usage(
	char		*dsname,
	dm_descriptor_t slice,
	dm_descriptor_t disk,
	boolean_t	*avail,
	dlist_t		**bad,
	dlist_t		**classes);

static int check_svm_slice_usage(
	char		*dsname,
	dm_descriptor_t slice,
	dm_descriptor_t disk,
	boolean_t	*avail,
	dlist_t		**classes);

static int save_slice_classification(
	char		*dsname,
	dm_descriptor_t slice,
	dm_descriptor_t disk,
	char		*usage,
	char		*usage_detail,
	dlist_t		**classes);

static int generate_usable_disks_and_slices_in_local_set(
	dlist_t		**classes,
	dlist_t		**bad_disks,
	dlist_t		**usable_disks,
	dlist_t		**usable_slices);

static int generate_usable_disks_and_slices_in_named_set(
	char		*dsname,
	dlist_t		**classes,
	dlist_t		**bad_slices,
	dlist_t		**usable_disks,
	dlist_t		**usable_slices);

static int create_usable_slices(
	dm_descriptor_t disk,
	dlist_t		*used,
	dlist_t		*unused,
	dlist_t 	**usable);

static int add_new_usable(
	dm_descriptor_t disk,
	uint64_t	stblk,
	uint64_t	nblks,
	dlist_t		**next_unused,
	dlist_t		**usable);

static int update_slice_attributes(
	dm_descriptor_t slice,
	uint64_t	stblk,
	uint64_t	nblks,
	uint64_t	nbytes);

static int generate_usable_hbas(
	dlist_t		*disks,
	dlist_t		**usable);

static void print_usable_devices();

static void print_unusable_devices(
	dlist_t		*badslices,
	dlist_t		*baddisks,
	dlist_t		*usedslices);

static char *get_slice_usage_msg(
	char		*usage);

/*
 * virtual slices...
 */
static int generate_virtual_slices(
	dlist_t 	*avail_disks_local_set,
	dlist_t		**usable);

/*
 * multipathed disks have aliases, as do slices on those disks.
 * these need to be tracked since the user may specify them.
 * A multi-pathed disk is one connected to the system thru
 * more than one physical HBA, each connection gets a distinct
 * name in the device tree and they're all more or less equivalent.
 * No indication as to how many possible physical connections a
 * disk may have, so we pick an arbitrary number of aliases to
 * support. There is nothing significant about this number,
 * it just controls the number of alias slots that get allocated.
 */
#define	MAX_ALIASES	8

/*
 * attribute name for layout private information stored in
 * device nvpair attribute lists.
 */
static char *ATTR_DEVICE_ALIASES = "layout_device_aliases";

static int compare_start_blocks(
	void *desc1, void *desc2);

static int compare_desc_display_names(
	void *desc1, void *desc2);

/*
 * FUNCTION:	is_mpxio_enabled()
 *
 * RETURNS:	boolean_t - B_TRUE - if MPXIO appears enabled for the system
 *			    B_FALSE - otherwise
 *
 * PURPOSE:	returns the value of _mpxio_enabled which is set to B_TRUE
 *		during system configuration discovery if any of the knwon
 *		HBAs advertises itself as a "multiplex" controller.
 */
boolean_t
is_mpxio_enabled()
{
	return (_mpxio_enabled);
}

/*
 * FUNCTION:	discover_known_devices()
 *
 * SIDEEFFECT:	populates the module private lists of known devices
 *		(_known_slices, _known_disks, _known_hbas).
 *
 *		All known devices will also have had their CTD
 *		short names inferred and stored.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Load physical devices discovered thru libdiskmgt.
 */
int
discover_known_devices()
{
	int	error = 0;

	oprintf(OUTPUT_TERSE,
		gettext("\nScanning system physical "
			"device configuration...\n"));

	/* initialize layout_device_cache */
	((error = create_device_caches()) != 0) ||

	(error = generate_known_disks(&_known_disks, &_bad_disks)) ||
	(error = generate_known_slices(_known_disks, &_known_slices,
		&_bad_slices)) ||
	(error = generate_known_hbas(_known_disks, &_known_hbas));

	if (error == 0) {
	    print_known_devices();
	}

	return (error);
}

/*
 * FUNCTION:	release_known_devices()
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Unloads all state currently held for known
 *		physical devices.
 */
int
release_known_devices(
	char	*diskset)
{
	/* these lists are module private */
	dlist_free_items(_bad_slices, NULL);
	dlist_free_items(_bad_disks, NULL);
	dlist_free_items(_known_slices, NULL);
	dlist_free_items(_known_disks, NULL);
	dlist_free_items(_known_hbas, NULL);

	_bad_slices = NULL;
	_bad_disks = NULL;
	_known_slices = NULL;
	_known_disks = NULL;
	_known_hbas = NULL;

	/* clean up state kept in layout_device_cache */
	release_device_caches();

	return (0);
}

/*
 * FUNCTION:	discover_usable_devices(char *diskset)
 *
 * INPUT:	diskset	- a char * diskset name.
 *
 * SIDEEFFECT:	Traverses the lists of known devices and populates the
 *		module private lists of usable devices (_usable_slices,
 *		_usable_disks, _usable_hbas), as well as the module
 *		private list of used slices.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Process the known devices and determine which of them are
 *		usable for generating volumes in the specified diskset.
 *
 *		The specified diskset's name cannot be NULL or 0 length.
 */
int
discover_usable_devices(
	char	*diskset)
{
	int	error = 0;

	dlist_t *used_classes = NULL;
	dlist_t *iter = NULL;

	if (diskset == NULL || diskset[0] == '\0') {
	    volume_set_error(
		    gettext("a diskset name must be specified in "
			    "the request\n"));
	    return (-1);
	}

	oprintf(OUTPUT_TERSE,
		gettext("\nDetermining usable physical devices "
			"for disk set \"%s\"...\n"),
		diskset);

	error = generate_usable_disks_and_slices_in_local_set(
	    &used_classes, &_bad_slices, &_usable_disks, &_usable_slices);
	if (error == 0) {

	    error = generate_usable_disks_and_slices_in_named_set(
		diskset, &used_classes, &_bad_slices, &_usable_disks,
		&_usable_slices);
	    if (error == 0) {

		error = generate_usable_hbas(_usable_disks, &_usable_hbas);
		if (error == 0) {

		    print_usable_devices();
		    print_unusable_devices(
			_bad_slices, _bad_disks, used_classes);
		}
	    }
	}

	/*
	 * free slice classification usage and lists, items are char*
	 * the used_classes structure is only filled in if verbose
	 * output was requested.
	 */
	for (iter = used_classes; iter != NULL; iter = iter->next) {
	    slice_class_t *class = (slice_class_t *)iter->obj;
	    free(class->usage);
	    dlist_free_items(class->sliceinfo, free);
	}

	dlist_free_items(used_classes, free);
	return (error);
}

/*
 * FUNCTION:	release_usable_devices()
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Unloads all state currently held for usable
 *		physical devices.
 */
int
release_usable_devices()
{
	/* list items are shared with _known_XXX lists */

	dlist_free_items(_usable_slices, NULL);
	dlist_free_items(_usable_disks, NULL);
	dlist_free_items(_usable_hbas, NULL);

	_usable_slices = NULL;
	_usable_disks = NULL;
	_usable_hbas = NULL;

	/* clean up state kept in layout_device_util */
	release_virtual_slices();

	return (0);
}

/*
 * FUNCTION:	get_known_slices(dlist_t **list)
 *		get_known_disks(dlist_t **list)
 *		get_known_hbas(dlist_t **list)
 *
 * OUTPUT:	list	- a dlist_t pointer to hold the returned list of
 *			devices.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Public accessors for the module private lists of
 *		available devices.
 */
int
get_known_slices(
	dlist_t **list)
{
	*list = _known_slices;

	return (0);
}

int
get_known_disks(
	dlist_t **list)
{
	*list = _known_disks;

	return (0);
}

int
get_known_hbas(
	dlist_t **list)
{
	*list = _known_hbas;

	return (0);
}

/* make fully qualified DID device name */
static char *
make_fully_qualified_did_device_name(
	char	*device)
{
	static char	buf[MAXPATHLEN];

	if (device != NULL && strrchr(device, '/') == NULL) {
	    (void) snprintf(buf, MAXPATHLEN-1, "%s/%s",
		    "/dev/did/dsk", device);
	    return (buf);
	}

	return (device);
}

/*
 * FUNCTION:	generate_known_disks(dlist_t **known,
 *			dlist_t **bad)
 *
 * INPUT:	NONE
 *
 * OUTPUT:	known	- populated list of known disks
 *		bad	- populated list of known bad disks
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Does the system configuration discovery to determine
 *		what disks are known to be attached to the system.
 *
 *		Determines the CTD name for each disk and saves it.
 */
static int
generate_known_disks(
	dlist_t	**known,
	dlist_t **bad)
{
	int	i;
	int	error = 0;
	dm_descriptor_t	*ddp;

	ddp = dm_get_descriptors(DM_DRIVE, NULL, &error);
	(void) add_descriptors_to_free(ddp);

	*known = NULL;

	if (error != 0) {
	    volume_set_error(
		    gettext("Error discovering system hardware configuration,\n"
		    "unable to communicate with libdiskmgt or diskmgtd.\n"));
	    return (-1);
	}

	if ((ddp == NULL) || (ddp[0] == NULL)) {
	    volume_set_error(gettext("there are no known disks\n"));
	    return (-1);
	}

	/* iterate all returned disks and add them to the known list */
	for (i = 0; (ddp[i] != NULL) && (error == 0); i++) {
	    dm_descriptor_t disk = (dm_descriptor_t)ddp[i];
	    dlist_t *aliases = NULL;
	    uint32_t mtype = DM_MT_UNKNOWN;
	    uint32_t dtype = DM_DT_UNKNOWN;
	    boolean_t bad_disk = B_FALSE;
	    boolean_t online = B_TRUE;

#if defined(i386)
	    /* on X86, disks must have a solaris FDISK partition */
	    boolean_t solpart = B_FALSE;
#endif	/* defined(i386) */

	    if (((error = disk_get_is_online(disk, &online)) == 0 &&
		online == B_FALSE) || error == ENODEV) {
		/* if the disk is offline, report it as bad */
		bad_disk = B_TRUE;
		error = 0;
	    } else

	    if (error == 0 &&
		(((error = disk_get_media_type(disk, &mtype)) != 0) ||
		((error = disk_get_drive_type(disk, &dtype)) != 0)) &&
		error == ENODEV) {
		/*
		 * if any disk attribute access fails with ENODEV
		 * report it as bad
		 */
		bad_disk = B_TRUE;
		error = 0;
	    } else {

		/*
		 * Determine whether disk is fixed by checking its
		 * drive type.  If drive type is unknown, check media
		 * type.
		 */
		int isfixed = (dtype == DM_DT_FIXED ||
		    (dtype == DM_DT_UNKNOWN && mtype == DM_MT_FIXED));

		if (!isfixed) {
		    continue;  /* ignore non-fixed disks */
		}

#if defined(i386)
		if (((error = disk_get_has_solaris_partition(disk,
		    &solpart)) != 0) || (solpart != B_TRUE)) {

		    /* X86 drive has no solaris partition, report as bad */
		    oprintf(OUTPUT_DEBUG,
			    gettext("%s has no solaris FDISK partition.\n"));

		    bad_disk = B_TRUE;
		}
#endif	/* defined(i386) */

	    }

	    if (bad_disk) {
		/* remember bad disks and continue */
		if (dlist_contains(*bad, (void *)(uintptr_t)disk,
		    compare_descriptor_names) != B_TRUE) {
		    dlist_t *item = dlist_new_item((void *)(uintptr_t)disk);
		    if (item == NULL) {
			error = ENOMEM;
		    } else {
			*bad = dlist_append(item, *bad, AT_TAIL);
		    }
		}
		continue;
	    }

	    /* get disk name and multipath aliases */
	    if ((error = disk_get_aliases(disk, &aliases)) == 0) {
		dlist_t *iter;
		boolean_t disk_name_set = B_FALSE;

		for (iter = aliases;
		    (iter != NULL) && (error == 0);
		    iter = iter->next) {

		    dm_descriptor_t	ap = (uintptr_t)iter->obj;
		    char		*alias;

		    if ((error = get_name(ap, &alias)) == 0) {
			/* save first alias as display name */
			if (disk_name_set != B_TRUE) {
			    /* make sure DID disk alias is fully qualified */

			    if (is_did_disk_name(alias) == B_TRUE) {
				char *qual_name =
				    make_fully_qualified_did_device_name(alias);

				set_display_name(disk, qual_name);
				oprintf(OUTPUT_DEBUG,
					gettext("DID disk name: %s\n"),
					qual_name);
			    } else {
				set_display_name(disk, alias);
				oprintf(OUTPUT_DEBUG,
					gettext("disk name: %s\n"),
					alias);
			    }
			    disk_name_set = B_TRUE;

			} else {
			    /* save others as aliases */
			    set_alias(disk, alias);
			    oprintf(OUTPUT_DEBUG,
				    gettext("  alias: %s\n"),
				    alias);
			}
		    }
		}

		dlist_free_items(aliases, NULL);
	    }

	    if (error == 0) {
		dlist_t *item = dlist_new_item((void *)(uintptr_t)disk);
		if (item == NULL) {
		    error = ENOMEM;
		} else {
		    *known =
			dlist_insert_ordered(item, *known,
				ASCENDING, compare_desc_display_names);
		}
	    }
	}

	if (ddp != NULL) {
	    free(ddp);
	}

	return (error);
}

/*
 * FUNCTION:	generate_known_slices(dlist_t *disks,
 *		dlist_t **known, dlist_t **bad)
 *
 * OUTPUT:	disks	- a pointer to a list of known disks
 *		known	- a pointer to a dlist_t list to hold the known slices
 *		bad	- a pointer to a dlist_t to hold the bad slices
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Examines input list of known disks and determines the slices
 *		attached to each.
 *
 *		Some slices returned from libdiskmgt may not really exist,
 *		this is detected when trying to get more information about
 *		the slice -- ENODEV is returned.  Any such slices will be
 *		added to the bad slice list.
 */
static int
generate_known_slices(
	dlist_t		*disks,
	dlist_t		**known,
	dlist_t		**bad)
{
	dlist_t		*iter;
	int		error = 0;

	/* iterate list of disks and add their slices to the known list */
	for (iter = disks; (iter != NULL) && (error == 0); iter = iter->next) {

	    dm_descriptor_t disk = (uintptr_t)iter->obj;
	    dlist_t *slices = NULL;
	    dlist_t *iter1;
	    char *dname = NULL;
	    boolean_t disk_ctd_alias_derived = B_FALSE;

	    if (((error = disk_get_slices(disk, &slices)) != 0) ||
		((error = get_display_name(disk, &dname)) != 0)) {
		continue;
	    }

	    for (iter1 = slices;
		(iter1 != NULL) && (error == 0);
		iter1 = iter1->next) {

		dm_descriptor_t slice = (uintptr_t)iter1->obj;
		uint32_t index = 0;
		nvlist_t *attrs = NULL;
		char *sname = NULL;

		if (((error = get_name(slice, &sname)) != 0) ||
		    ((error = slice_get_index(slice, &index)) != 0) ||
		    ((error = get_cached_attributes(slice, &attrs)) != 0)) {

		    if (error == ENODEV) {
			/* bad slice, remember it and continue */
			dlist_t *item =
			    dlist_new_item((void *)(uintptr_t)slice);
			if (item == NULL) {
			    error = ENOMEM;
			} else {
			    *bad = dlist_insert_ordered(
				    item, *bad,
				    ASCENDING, compare_descriptor_names);
			    error = 0;
			}
		    }
		    continue;
		}

		if ((error == 0) && (is_did_slice_name(sname) == B_TRUE) &&
		    (disk_ctd_alias_derived == B_FALSE)) {
		    /* BEGIN CSTYLED */
		    /*
		     * If the slice name is a DID name, get the local CTD
		     * name for slice, extract the disk name and add it as
		     * an alias for the disk.
		     *
		     * This is the only way to derive the CTD alias for the
		     * disk when DID is enabled.
		     *
		     * The disk_ctd_alias_derived flag ensure the disk's
		     * CTD alias is only set once.
		     *
		     * The slice's CTD aliases are then derived from the
		     * disk's CTD alias in the normal, non-DID name processing
		     * which happens below.
		     */
		    /* END CSTYLED */
		    char *local = NULL;
		    if ((error = nvlist_lookup_string(attrs, DM_LOCALNAME,
				&local)) != 0) {
			if (error == ENOENT) {
			    /* no local name -> no DID */
			    error = 0;
			}
		    } else {
			char *localdisk = NULL;
			char *diskonly = NULL;
			if ((error = extract_diskname(local,
			    &localdisk)) == 0) {
			    if ((diskonly = strrchr(localdisk, '/')) != NULL) {
				++diskonly;
			    } else {
				diskonly = localdisk;
			    }
			    oprintf(OUTPUT_DEBUG,
				    gettext("  set DID disk CTD alias: %s\n"),
				    diskonly);
			    error = set_alias(disk, diskonly);
			    free(localdisk);
			    disk_ctd_alias_derived = B_TRUE;
			}
		    }
		}

		/* derive slice display name from disk's display name */
		if (error == 0) {
		    if ((error = make_slicename_for_diskname_and_index(
			dname, index, &sname)) == 0) {
			error = set_display_name(slice, sname);
		    }
		}

		/* set slice aliases using disk aliases */
		if (error == 0) {
		    dlist_t *aliases = NULL;
		    if ((error = get_aliases(disk, &aliases)) == 0) {

			dlist_t *iter2 = aliases;
			for (; (iter2 != NULL) && (error == 0);
			    iter2 = iter2->next) {

			    char *dalias = (char *)iter2->obj;
			    char *salias = NULL;

			    if ((error = make_slicename_for_diskname_and_index(
				dalias, index, &salias)) == 0) {
				error = set_alias(slice, salias);
				free(salias);
			    }
			}
			dlist_free_items(aliases, free);
		    }
		}

		if (error == 0) {
		    dlist_t *item = dlist_new_item((void *)(uintptr_t)slice);
		    if (item == NULL) {
			error = ENOMEM;
		    } else {
			*known =
			    dlist_insert_ordered(
				    item, *known,
				    ASCENDING, compare_desc_display_names);
		    }
		}
	    }

	    dlist_free_items(slices, NULL);
	}

	return (error);
}

/*
 * FUNCTION:	generate_known_hbas(dlist_t *disks, dlist_t **known)
 *
 * INPUT:	diskset	- a char * diskset name.
 *
 * OUTPUT:	populates the list of known HBAs.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Examines known disk list and derives the list of known HBAs.
 *
 *		Determines the CTD name for an HBA and saves it.
 */
static int
generate_known_hbas(
	dlist_t	*disks,
	dlist_t	**known)
{
	dlist_t	*iter;
	int	error = 0;

	/*
	 * for each known disk follow its HBA connections and
	 * assemble the list of known HBAs.
	 */
	for (iter = disks;
	    (iter != NULL) && (error == 0);
	    iter = iter->next) {

	    dm_descriptor_t	disk = (uintptr_t)iter->obj;
	    dlist_t 		*hbas = NULL;
	    dlist_t 		*iter2 = NULL;
	    dlist_t		*iter3 = NULL;
	    dlist_t		*aliases = NULL;
	    char		*dname = NULL;

	    ((error = get_display_name(disk, &dname)) != 0) ||
	    (error = disk_get_aliases(disk, &aliases)) ||
	    (error = disk_get_hbas(disk, &hbas));

	    if (error == 0) {

		if ((hbas == NULL) || (dlist_length(hbas) == 0)) {

		    oprintf(OUTPUT_DEBUG,
			    gettext("Disk %s has no HBA/Controller?!\n"),
			    dname);
		    error = -1;

		    dlist_free_items(hbas, NULL);
		    dlist_free_items(aliases, NULL);

		    continue;
		}

		for (iter2 = hbas, iter3 = aliases;
		    iter2 != NULL && iter3 != NULL;
		    iter2 = iter2->next, iter3 = iter3->next) {

		    dm_descriptor_t	hba = (uintptr_t)iter2->obj;
		    dm_descriptor_t	alias = (uintptr_t)iter3->obj;
		    dlist_t		*item = NULL;

		    /* scan list of known HBAs and see if known */
		    if (dlist_contains(*known, (void*)(uintptr_t)hba,
			compare_descriptor_names) == B_TRUE) {
			/* known HBA */
			continue;
		    }

		    /* see if HBA supports MPXIO */
		    if ((error == 0) && (_mpxio_enabled != B_TRUE)) {
			hba_is_multiplex(hba, &_mpxio_enabled);
		    }

		    /* generate a CTD name for HBA */
		    error = generate_known_hba_name(hba, alias, disk);
		    if (error == 0) {
			/* add to known HBA list */
			if ((item = dlist_new_item((void *)(uintptr_t)hba)) ==
			    NULL) {
			    error = ENOMEM;
			} else {
			    *known =
				dlist_insert_ordered(item, *known,
				    ASCENDING, compare_desc_display_names);
			}
		    }
		}
	    }

	    dlist_free_items(aliases, NULL);
	    dlist_free_items(hbas, NULL);
	}

	return (error);
}

/*
 * FUNCTION:	generate_known_hba_name(dm_descriptor_t hba,
 *		dm_descriptor_t alias, char *diskname)
 *
 * INPUT:	hba	- a dm_descriptor_t HBA handle.
 *		alias	- a dm_descriptor_t disk alias handle.
 *		diskname - a char * disk name
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Sets the CTD name for the input HBA.
 *
 *		The CTD name for the HBA is generated from the input
 *		disk alias (ex: cXdXtXsX) or from the disk name if
 *		the input alias is a DID name (ex: dX).
 */
static int
generate_known_hba_name(
	dm_descriptor_t	hba,
	dm_descriptor_t	alias,
	dm_descriptor_t disk)
{
	char	*hbaname = NULL;
	char	*aliasname = NULL;
	int	error = 0;

	((error = get_name(alias, &aliasname)) != 0) ||
	(error = extract_hbaname(aliasname, &hbaname));
	if (error != 0) {
	    free(hbaname);
	    return (error);
	}

	/* see if the input alias is a DID name... */
	if (is_did_disk_name(aliasname) == B_TRUE) {

	    /* look for a non-DID name in disk's aliases */
	    dlist_t *aliases = NULL;
	    error = get_aliases(disk, &aliases);

	    for (; (error == 0) && (aliases != NULL);
		aliases = aliases->next) {

		aliasname = (char *)aliases->obj;
		if (is_did_disk_name(aliasname) != B_TRUE) {
		    /* this is the "local" CTD name generated by */
		    /* generate_known_disks() above */
		    error = extract_hbaname(aliasname, &hbaname);
		    if ((error == 0) && (hbaname != NULL)) {
			set_display_name(hba, hbaname);
			break;
		    }
		}
	    }
	    dlist_free_items(aliases, free);

	} else {
	    /* use whatever was derived from the alias name */
	    set_display_name(hba, hbaname);
	}

	return (error);
}

/*
 * FUNCTION:	print_known_devices()
 *
 * PURPOSE:	Print out the known devices.
 *
 *		Iterates the lists of known slices, disks and HBAs
 *		and prints out their CTD and device names.
 */
static void
print_known_devices(
	char	*diskset)
{
	int i = 0;
	struct {
		char *msg;
		dlist_t *list;
	}	devs[3];

	devs[0].msg = gettext("HBA/Controllers");
	devs[0].list = _known_hbas;
	devs[1].msg = gettext("disks");
	devs[1].list = _known_disks;
	devs[2].msg = gettext("slices");
	devs[2].list = _known_slices;

	for (i = 0; i < 3; i++) {

	    oprintf(OUTPUT_VERBOSE,
		    gettext("\n  These %s are known:\n\n"),
		    devs[i].msg);

	    print_device_list(devs[i].list);
	}
}

/*
 * FUNCTION:	get_usable_slices(dlist_t **list)
 *
 * OUTPUT:	list	- a dlist_t pointer to hold the returned list of
 *			devices.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Public accessors the the modules private lists of
 *		available devices.
 *
 *		The functions are keyed by diskset name in the event
 *		objects in different disksets are loaded concurrently.
 */
int
get_usable_slices(
	dlist_t **list)
{
	*list = _usable_slices;

	return (0);
}

int
get_usable_disks(
	dlist_t **list)
{
	*list = _usable_disks;

	return (0);
}

int
get_usable_hbas(
	dlist_t **list)
{
	*list = _usable_hbas;

	return (0);
}

/*
 * FUNCTION:	generate_usable_disks_and_slices_in_local_set(dlist_t **classes,
 *			dlist_t **bad_disks, dlist_t **usable_disks,
 *			dlist_t **usable_slices)
 *
 * OUTPUT:	used_classes - a pointer to a list of slice_class_t structs
 *			updated with known slices that have detected uses
 *			added to the correct class'e list of slices.
 *		bad_disks - a pointer to a list of bad/unusable disks updated
 *			with any bad disks that were detected
 *		useable_disks - a pointer to a list of usable disks
 *		useable_slices - a pointer to a list of usable slices
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Scans the disks in the local set to determine which are
 *		usable during layout processing.
 *
 *		Determines which are usable by layout using usages detected
 *		by libdiskmgt.
 */
static int
generate_usable_disks_and_slices_in_local_set(
	dlist_t **classes,
	dlist_t **bad_slices,
	dlist_t **usable_disks,
	dlist_t **usable_slices)
{
	char	*dsname = MD_LOCAL_NAME;
	dlist_t *disks;
	dlist_t *iter;
	int 	error;

	/* Get disks in local set */
	error = get_disks_in_diskset(dsname, &disks);
	if (error != 0) {
	    return (error);
	}

	/* For each disk in this set... */
	for (iter = disks; iter != NULL && error == 0; iter = iter->next) {
	    dm_descriptor_t disk = (uintptr_t)iter->obj;
	    dlist_t *slices;

	    /* Get slices on this disk */
	    error = disk_get_slices(disk, &slices);
	    if (error == 0) {
		dlist_t *iter2;

		/*
		 * Assume disk is available until a bad or unavailable
		 * slice is found
		 */
		boolean_t avail = B_TRUE;
		boolean_t bad_disk = B_FALSE;

		/* For each slice on this disk... */
		for (iter2 = slices;
		    iter2 != NULL && error == 0 &&
			avail == B_TRUE && bad_disk == B_FALSE;
		    iter2 = iter2->next) {

		    dm_descriptor_t slice = (uintptr_t)iter2->obj;
		    dlist_t *bad_slices_on_this_disk = NULL;

		    /* Is this slice available? */
		    error = check_slice_usage(dsname, slice,
			disk, &avail, &bad_slices_on_this_disk, classes);

		    /* Is the slice bad (inaccessible)? */
		    if (error != 0 && bad_slices_on_this_disk != NULL) {
			bad_disk = B_TRUE;
			*bad_slices = dlist_append_list(
			    *bad_slices, bad_slices_on_this_disk);
		    }
		}

		/* Is the disk available? */
		if (error == 0 && bad_disk == B_FALSE && avail == B_TRUE) {
		    error = dlist_append_object(
			(void *)(uintptr_t)disk, usable_disks, AT_TAIL);
		}

		dlist_free_items(slices, NULL);
	    }
	}

	dlist_free_items(disks, NULL);

	if (error == 0) {
	    /* BEGIN CSTYLED */
	    /*
	     * Now reslice usable disks in the local set to
	     * simulate the slices they'll have when they're added
	     * to the named disk set, and add these resulting
	     * virtual slices to the list of available slices.
	     */
	    /* END CSTYLED */
	    error = generate_virtual_slices(*usable_disks, usable_slices);
	}

	return (error);
}

/*
 * FUNCTION:	generate_virtual_slices(dlist_t *unused, dlist_t **usable)
 *
 * INPUT:	slice_classes - a list of unused slice dm_descriptor_t handles.
 *
 * OUTPUT:	usable - pointer to the list of usable slices, updated
 *			with any created virtual slices.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Helper which creates virtual slices for each disk which
 *		could be added to a diskset if necessary...
 *
 *		Search the input list of slice classes for the entry
 *		containing slices known to be available for use by layout.
 *
 *		Iterate the list of unused slices and determine the set
 *		of unique disks.
 *
 *		For each unique disk, create virtual slice descriptors to
 *		represent those that will exist if/when the disk is added
 *		to the diskset.
 *
 *		Add theese virtual slices to the list of usable slices.
 */
static int
generate_virtual_slices(
	dlist_t 	*avail_disks_local_set,
	dlist_t		**usable)
{
	dlist_t	*iter = NULL;
	int	error = 0;

	/* generate virtual slices */
	error = create_virtual_slices(avail_disks_local_set);
	if (error == 0) {

	    get_virtual_slices(&iter);
	    for (; (iter != NULL) && (error == 0); iter = iter->next) {

		dlist_t *item = dlist_new_item((void *) iter->obj);
		if (item == NULL) {
		    error = ENOMEM;
		} else {
		    *usable =
			dlist_insert_ordered(item, *usable,
				ASCENDING, compare_desc_display_names);
		}
	    }
	}

	return (error);
}

/*
 * FUNCTION:	generate_usable_disks_and_slices_in_named_set(char *dsname,
 *			dlist_t **classes, dlist_t **bad_slices,
 *			dlist_t **usable_slices, dlist_t **usable_disks)
 *
 * INPUT:	dsname	- a char * diskset name.
 *
 * OUTPUT:	classes	- pointer to a list of slice_class_t structs,
 *			updated to include slices in the disk set with
 *			known uses.
 * 		bad_slices - pointer to a list of bad/unusable slices,
 *			updated to include slices in the disk set that
 *			are inaccessible or no longer existent.
 *		usable_slices - pointer to a list of usable slices in the
 *			disk set.
 *		usable_disks - pointer to a list of usable disks in the
 *			disk set.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	1. determine the disks in the named disk set
 *		2. determine the used slices on the disks
 *		3. determine the unused slices on the disks
 *		4. look for unused space on the disks and collect it
 *		   into an existing unused slice, or create a new
 *		   virtual slice.
 */
static int
generate_usable_disks_and_slices_in_named_set(
	char		*dsname,
	dlist_t		**classes,
	dlist_t		**bad_slices,
	dlist_t		**usable_disks,
	dlist_t		**usable_slices)
{
	dlist_t		*disks = NULL;
	dlist_t		*iter = NULL;
	int		error = 0;

	error = get_disks_in_diskset(dsname, &disks);
	if (error != 0) {
	    return (error);
	}

	/* For each disk... */
	for (iter = disks;
	    iter != NULL && error == 0;
	    iter = iter->next) {

	    dm_descriptor_t	disk = (uintptr_t)iter->obj;
	    dlist_t		*iter2;
	    dlist_t		*slices = NULL;
	    dlist_t		*bad_slices_on_this_disk = NULL;
	    dlist_t		*used_slices_on_this_disk = NULL;
	    dlist_t		*unused_slices_on_this_disk = NULL;
	    boolean_t		bad_disk = B_FALSE;

	    error = disk_get_slices(disk, &slices);
	    if (error != 0) {
		break;
	    }

	    /* Determine the used, unused, and bad slices on the disk */

	    /* For each slice... */
	    for (iter2 = slices;
		iter2 != NULL && error == 0 && bad_disk == B_FALSE;
		iter2 = iter2->next) {

		dm_descriptor_t slice = (uintptr_t)iter2->obj;

		boolean_t	rsvd = B_FALSE;
		boolean_t	avail = B_FALSE;

		/* Get slice usage */
		if (((error = is_reserved_slice(slice, &rsvd)) == 0) &&
		    ((error = check_slice_usage(dsname, slice, disk, &avail,
			&bad_slices_on_this_disk, classes)) == 0)) {

		    /* Is the slice bad (inaccessible)? */
		    if (bad_slices_on_this_disk != NULL) {
			*bad_slices = dlist_append_list(
			    *bad_slices, bad_slices_on_this_disk);
			/*
			 * Since one slice on this disk is bad, don't
			 * use any slices on this disk
			 */
			bad_disk = B_TRUE;
		    } else {

			dlist_t *item =
			    dlist_new_item((void *)(uintptr_t)slice);
			if (item == NULL) {
			    error = ENOMEM;
			} else {
			    /* Add slice to used/unused list as appropriate */
			    if (avail == B_TRUE && rsvd == B_FALSE) {
				unused_slices_on_this_disk = dlist_append(
				    item, unused_slices_on_this_disk, AT_TAIL);
			    } else {
				used_slices_on_this_disk =
				    dlist_insert_ordered(item,
					used_slices_on_this_disk,
					ASCENDING, compare_start_blocks);
			    }
			}
		    }
		}
	    }

	    /* Done iterating slices */

	    if (error == 0 && bad_disk == B_FALSE) {
		/* For each unused slice... */
		for (iter2 = unused_slices_on_this_disk;
		    iter2 != NULL && error == 0;
		    iter2 = iter2->next) {

		    dm_descriptor_t slice = (uintptr_t)iter2->obj;
		    error = update_slice_attributes(slice, 0, 0, 0);

		    /* Only do this once */
		    if (error == 0 && iter2 == unused_slices_on_this_disk) {
			error = add_modified_disk(NULL, disk);
		    }
		}

		if (error == 0) {
		    /* Create usable slices from the used/unused slice lists */
		    error = create_usable_slices(disk, used_slices_on_this_disk,
			unused_slices_on_this_disk, usable_slices);
		    if (error == 0) {
			error = dlist_append_object((void *)(uintptr_t)disk,
			    usable_disks, AT_TAIL);
		    }
		}
	    }

	    dlist_free_items(slices, NULL);
	    dlist_free_items(used_slices_on_this_disk, NULL);
	    dlist_free_items(unused_slices_on_this_disk, NULL);
	}

	return (error);
}

/*
 * FUNCTION:	create_usable_slices(dm_descriptor_t disk, dlist_t *used,
 *			dlist_t *unused, dlist_t **usable);
 *
 * INPUT:	disk	- a dm_descriptor_t disk handle
 *		used	- pointer to a list of pvt_t structs
 *			  representing existing used slices
 *			  on the input disk.
 *		unused	- pointer to a list of pvt_t structs
 *			  representing existing unused slices
 *			  on the input disk.
 *
 * OUTPUT:	usable	- pointer to a list of pvts representing slices
 *			which can be used for new volume layouts.
 *
 *			Slices in this list have any available space on the
 *			disk collected into the fewest, lowest indexed slices
 *			possible.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	helper for generate_usable_slices_and_disks_in_diskset() which
 *		turns any detected free space on the input disk into one or
 *		more slices.
 */
static int
create_usable_slices(
	dm_descriptor_t disk,
	dlist_t		*used,
	dlist_t		*unused,
	dlist_t		**usable)
{
	dlist_t		*iter;
	int		error = 0;
	boolean_t	first = B_TRUE;
	dlist_t		*next_unused = unused;

	char		*dname = NULL;
	uint64_t 	disk_firstblk = 0;
	uint64_t 	disk_nblks = 0;
	uint64_t 	disk_endblk = 0;

	oprintf(OUTPUT_DEBUG,
		gettext("\n  create_usable_slices for disk\n"));

	/* get necessary info about disk: */
	error = get_display_name(disk, &dname);
	if (error != 0) {
	    return (error);
	}

	/* disk start block is first usable block */
	error = disk_get_start_block(disk, &disk_firstblk);
	if (error != 0) {
	    return (error);
	}

	/* disk size determines last usable disk block */
	error = disk_get_size_in_blocks(disk, &disk_nblks);
	if (error != 0) {
	    return (error);
	}

	disk_endblk = disk_firstblk + disk_nblks - 1;

	/* search for gaps before, between and after used slices */
	for (iter = used; iter != NULL && error == 0; iter = iter->next) {

	    dm_descriptor_t cur = (uintptr_t)iter->obj;

	    uint64_t cur_stblk = 0;
	    uint64_t cur_nblks = 0;
	    uint64_t cur_endblk = 0;
	    uint32_t cur_index = 0;

	    uint64_t new_stblk = 0;
	    uint64_t new_endblk = 0;

	    char *sname = NULL;
	    (void) get_display_name(cur, &sname);

	    if (((error = slice_get_index(cur, &cur_index)) != 0) ||
		((error = slice_get_start_block(cur, &cur_stblk)) != 0) ||
		((error = slice_get_size_in_blocks(cur, &cur_nblks)) != 0)) {
		continue;
	    }

	    cur_endblk = cur_stblk + cur_nblks - 1;

	    oprintf(OUTPUT_DEBUG,
		    gettext("  used slice %d (%10llu to %10llu)\n"),
		    cur_index, cur_stblk, cur_endblk);

	    if (first == B_TRUE) {
		/* first slice: make sure it starts at disk_firstblk */
		first = B_FALSE;
		if (cur_stblk != disk_firstblk) {
		    /* close gap at beginning of disk */
		    new_stblk = disk_firstblk;
		    new_endblk = cur_stblk - 1;

		    oprintf(OUTPUT_DEBUG,
			    gettext("    unused space before first "
				    "used slice\n"));
		}
	    }

	    if (iter->next != NULL) {
		/* check for gap between slices */
		dm_descriptor_t next = (uintptr_t)iter->next->obj;
		uint64_t next_stblk = 0;
		uint32_t next_index = 0;

		if (((error = slice_get_start_block(next, &next_stblk)) == 0) &&
		    ((error = slice_get_index(next, &next_index)) == 0)) {
		    if (cur_endblk != next_stblk - 1) {
			/* close gap between slices */
			new_stblk = cur_endblk + 1;
			new_endblk = next_stblk - 1;

			oprintf(OUTPUT_DEBUG,
				gettext("    unused space between slices "
					"%d and %d\n"), cur_index, next_index);
		    }
		}

	    } else {
		/* last slice: make sure it includes last block on disk */
		if (cur_endblk != disk_endblk) {
		    /* close gap at end of disk */
		    new_stblk = cur_endblk + 1;
		    new_endblk = disk_endblk;

		    oprintf(OUTPUT_DEBUG,
			    gettext("    unused space after last slice "
				    "cur_endblk: %llu disk_endblk: %llu\n"),
			    cur_endblk, disk_endblk);
		}
	    }

	    if ((error == 0) && (new_endblk != 0)) {
		error = add_new_usable(disk, new_stblk,
			new_endblk - new_stblk + 1, &next_unused, usable);
	    }
	}

	if (error != 0) {
	    dlist_free_items(*usable, free);
	    *usable = NULL;
	}

	return (error);
}

/*
 * FUNCTION:	add_new_usable(dm_descriptor_t disk, uint64_t stblk,
 *			uint64_t nblks, dlist_t **next_unused,
 *			dlist_t **usable);
 *
 * INPUT:	disk	- a dm_descriptor_t disk handle
 *		stblk	- start block of the usable space
 *		nblks	- number of usable blocks
 *		next_unused	- pointer to the next unused slice
 *
 * OUTPUT:	next_unused	- updated pointer to the next unused slice
 *		usable	- possibly updated pointer to a list of slices on
 *			the disk with usable space
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	helper for create_usable_slices() which turns free space
 *		on the input disk into a usable slice.
 *
 *		If possible an existing unused slice will be recycled
 *		into a usable slice. If there are none, a new virtual
 *		slice will be created.
 */
static int
add_new_usable(
	dm_descriptor_t disk,
	uint64_t	stblk,
	uint64_t	nblks,
	dlist_t		**next_unused,
	dlist_t		**usable)
{
	dm_descriptor_t new_usable = 0;
	int		error = 0;

	/* try to use an existing unused slice for the usable slice */
	if (*next_unused != NULL) {
	    new_usable = (uintptr_t)((*next_unused)->obj);
	    *next_unused = (*next_unused)->next;

	    oprintf(OUTPUT_DEBUG,
		    gettext("\trecyling used slice into usable slice "
			    "start: %llu, end: %llu\n"),
		    stblk, stblk + nblks + 1);
	}

	if (new_usable == NULL) {
	    /* no unused slices, try to make a new virtual slice */
	    uint32_t index = UINT32_MAX;
	    error = disk_get_available_slice_index(disk, &index);
	    if ((error == 0) && (index != UINT32_MAX)) {

		char *dname = NULL;
		error = get_display_name(disk, &dname);
		if (error == 0) {

		    char buf[MAXNAMELEN];
		    (void) snprintf(buf, MAXNAMELEN-1, "%ss%d", dname, index);
		    error = add_virtual_slice(buf, index, 0, 0, disk);
		    if (error == 0) {
			/* retrieve the virtual slice */
			error = slice_get_by_name(buf, &new_usable);
		    }
		}
	    }
	}

	if ((error == 0) && (new_usable != (dm_descriptor_t)0)) {
	    /* BEGIN CSTYLED */
	    /*
	     * have an unused slice, update its attributes to reflect
	     * the usable space it represents
	     */
	    /* END CSTYLED */
	    uint64_t disk_blksz = 0;
	    error = disk_get_blocksize(disk, &disk_blksz);
	    if (error == 0) {
		error = update_slice_attributes(new_usable, stblk,
		    nblks, nblks * disk_blksz);
		if (error == 0) {
		    error = dlist_append_object(
			(void *)(uintptr_t)new_usable, usable, AT_TAIL);
		}
	    }
	}

	return (error);
}

/*
 * FUNCTION:	update_slice_attributes(dm_descriptor_t slice, uint64_t stblk,
 *			uint64_t nblks, uint64_t nbytes)
 *
 * INPUT:	slice	- a dm_descriptor_t slice handle
 *		stblk	- start block of the usable space
 *		nblks	- size of slice in blocks
 *		nbytes	- size of slice in bytes
 *
 * SIDEEFFECT:	adds a modification record for the slice.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	utility which updates several slice attributes in one call.
 */
static int
update_slice_attributes(
	dm_descriptor_t slice,
	uint64_t	stblk,
	uint64_t	nblks,
	uint64_t	nbytes)
{
	char		*sname = NULL;
	uint32_t	 index = 0;
	int		error = 0;

	if ((error = get_display_name(slice, &sname)) == 0) {
	    if ((error = slice_get_index(slice, &index)) == 0) {
		if ((error = slice_set_start_block(slice, stblk)) == 0) {
		    if ((error = slice_set_size_in_blocks(slice, nblks)) == 0) {
			if (nblks == 0) {
			    error = add_slice_to_remove(sname, index);
			} else {
			    error = assemble_modified_slice((dm_descriptor_t)0,
				    sname, index, stblk, nblks, nbytes, NULL);
			}
		    }
		}
	    }
	}

	return (error);
}

/*
 * FUNCTION:	generate_usable_hbas(dlist_t *slices,
 *			dlist_t **usable)
 *
 * INPUT:	disks	- a list of usable disks.
 *
 * OUTPUT:	usable	- a populated list of usable HBAs.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Examines usable disk list and derives the list of usable HBAs.
 *
 */
static int
generate_usable_hbas(
	dlist_t *disks,
	dlist_t	**usable)
{
	dlist_t	*iter;
	int	error = 0;

	/*
	 * for each usable disk, follow its HBA connections and
	 * add them to the list of usable HBAs.
	 */
	for (iter = disks; (iter != NULL) && (error == 0); iter = iter->next) {

	    dm_descriptor_t	dp = NULL;
	    dlist_t 		*hbas = NULL;
	    dlist_t		*iter2 = NULL;

	    dp = (uintptr_t)iter->obj;

	    error = disk_get_hbas(dp, &hbas);
	    if (error == 0) {

		for (iter2 = hbas;
		    (iter2 != NULL) && (error == 0);
		    iter2 = iter2->next) {

		    dm_descriptor_t	hba = (uintptr_t)iter2->obj;
		    dlist_t		*item = NULL;

		    /* scan list of usable HBAs and see if known */
		    if (dlist_contains(*usable, (void*)(uintptr_t)hba,
			compare_descriptor_names) == B_TRUE) {
			/* known HBA, continue to next HBA/alias */
			continue;
		    }

		    /* add this HBA to the usable list */
		    if ((item = dlist_new_item((void *)(uintptr_t)hba)) ==
			NULL) {
			error = ENOMEM;
		    } else {
			*usable =
			    dlist_insert_ordered(item, *usable,
				    ASCENDING, compare_desc_display_names);
		    }
		}
	    }

	    dlist_free_items(hbas, NULL);
	}

	return (error);
}

/*
 * FUNCTION:	check_slice_usage(char *dsname, dm_descriptor_t slice,
 *			dm_descriptor_t disk, boolean_t *avail,
 *			dlist_t **bad, dlist_t **classes)
 *
 * INPUT:	dsname	- a char * diskset name.
 *		slice	- a dm_descriptor_t handle for a known slices.
 *		disk	- a dm_descriptor_t handle the slice's disk.
 *
 * OUTPUT:	avail	- a boolean_t to hold the slice's availability.
 *		bad	- pointer to a list of bad/unusable slices,
 *				possibly updated if the input slice
 *				was determined to be inaccessible.
 *		classes	- pointer to a list of slice_class_t structs,
 *				possibly updated to include the input slice
 *				if it has a known use.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Handles the details of
 *		determining usage and/or availability of a single slice.
 *
 *		Queries the device library for the input slice's detectable
 *		usage status.
 *
 *		If the slice has a detected usage, its name is added to
 *		the appropriate slice_class_t list in the input list of
 *		slice classes, this is only done if verbose output was
 * 		requested.
 */
static int
check_slice_usage(
	char		*dsname,
	dm_descriptor_t slice,
	dm_descriptor_t disk,
	boolean_t	*avail,
	dlist_t		**bad,
	dlist_t		**classes)
{
	boolean_t	online = B_FALSE;
	boolean_t	used = B_FALSE;
	nvlist_t	*stats = NULL;
	char		*name = NULL;
	char		*used_by = NULL;
	char		*use_detail = NULL;
	int		error = 0;

	*avail = B_FALSE;

	if (((error = get_display_name(slice, &name)) != 0) ||
	    (error = disk_get_is_online(disk, &online))) {
	    return (error);
	}

	/*
	 * if the disk is known to be offline, skip getting status
	 * for the slice since it will just fail and return ENODEV.
	 */
	if (online != B_TRUE) {
	    error = ENODEV;
	} else {
	    stats = dm_get_stats(slice, DM_SLICE_STAT_USE, &error);
	}

	if (error != 0) {
	    if (error == ENODEV) {
		dlist_t *item = dlist_new_item((void *)(uintptr_t)slice);
		oprintf(OUTPUT_TERSE,
			gettext("Warning: unable to get slice information "
				"for %s, it will not be used.\n"), name);

		if (item == NULL) {
		    error = ENOMEM;
		} else {
		    error = 0;
		    *bad = dlist_insert_ordered(item, *bad, ASCENDING,
			    compare_desc_display_names);
		}
	    } else {
		oprintf(OUTPUT_TERSE,
			gettext("check_slice_usage: dm_get_stats for "
				"%s failed %d\n"),
			name, error);
	    }

	    return (error);
	}

	/*
	 * check if/how the slice is currently being used,
	 * device library provides this info in the nvpair_t list:
	 *
	 *   stat_type is DM_SLICE_STAT_USE
	 *	used_by:	string (mount, svm, lu, vxvm, fs)
	 *	used_name:	string
	 *
	 */
	if (stats != NULL) {
	    error = get_string(stats, DM_USED_BY, &used_by);
	    if (error != 0) {
		if (error == ENOENT) {
		    used_by = NULL;
		    error = 0;
		} else {
		    oprintf(OUTPUT_TERSE,
			    gettext("check_slice_usage: dm_get_stats.%s for "
				    "%s failed %d\n"),
			    DM_USED_BY, name, error);
		}
	    }

	    if (error == 0) {
		error = get_string(stats, DM_USED_NAME, &use_detail);
		if (error != 0) {
		    if (error == ENOENT) {
			use_detail = NULL;
			error = 0;
		    } else {
			oprintf(OUTPUT_TERSE,
				gettext("check_slice_usage: "
					"dm_get_stats.%s for "
					"%s failed %d\n"),
					DM_USED_NAME, name, error);
		    }
		}
	    }
	}

	if ((error == 0) && (used_by != NULL) && (used_by[0] != '\0')) {

	    /* was detected usage SVM? */
	    if (string_case_compare(used_by, DM_USE_SVM) == 0) {

		/* check use_detail, it is in the form diskset:name */
		if (strncmp("diskset:", use_detail, 8) == 0) {

		    /* check disk set name */
		    char *str = strrchr(use_detail, ':');
		    if ((str != NULL) &&
			    (string_case_compare(str+1, dsname) == 0)) {

			/* slice in the right diskset */
			error = check_svm_slice_usage(
				dsname, slice, disk, &used, classes);

		    } else {

			/* slice in other diskset */
			save_slice_classification(
				dsname, slice, disk, used_by, use_detail,
				classes);
			used = B_TRUE;
		    }

		} else {

		    /* slice is volume component */
		    save_slice_classification(
			    dsname, slice, disk, used_by, use_detail,
			    classes);
		    used = B_TRUE;
		}

	    } else {

		/* save usage */
		save_slice_classification(
			dsname, slice, disk, used_by, use_detail,
			classes);
		used = B_TRUE;
	    }
	}

	nvlist_free(stats);

	if (error == 0) {
	    if (used == B_TRUE) {
		*avail = B_FALSE;
	    } else {
		*avail = B_TRUE;
	    }
	}

	return (error);
}

/*
 * FUNCTION:	check_svm_slice_usage(char *dsname, dm_descriptor_t slice,
 *			dm_descriptor_t disk, boolean_t *used,
 *			dlist_t **classes)
 *
 * INPUT:	dsname	- a char * diskset name.
 *		slice	- a dm_descriptor_t handle for a known slices.
 *		disk	- a dm_descriptor_t handle the slice's disk.
 *
 * OUTPUT:	used	- a boolean_t to hold the slice usage status.
 *		classes	- pointer to a list of slice_class_t possibly updated
 *				with the input slice's SVM specific usage
 *				classification.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Handles the finer details of
 *		a single slice is being used in the context of SVM.
 *
 *		Currently, one thing is checked:
 *
 *		1. determine if the slice is reserved for metadb replicas.
 *		   The convention for disks in disksets is that a single slice
 *		   (index 6 or 7) is set aside for metadb replicas.
 *
 *		If this condition does not hold, the slice is considered
 *		available for use by layout and 'used' is set to B_FALSE.
 */
static int
check_svm_slice_usage(
	char		*dsname,
	dm_descriptor_t slice,
	dm_descriptor_t disk,
	boolean_t	*used,
	dlist_t		**classes)
{
	boolean_t is_replica = B_FALSE;
	uint32_t index = 0;
	char	*diskname = NULL;
	int	error = 0;

	((error = slice_get_index(slice, &index)) != 0) ||
	(error = get_display_name(disk, &diskname)) ||
	(error = is_reserved_replica_slice_index(
		dsname, diskname, index, &is_replica));

	if (error == 0) {
	    if (is_replica == B_TRUE) {
		/* is replica slice -> used */
		save_slice_classification(dsname, slice, disk, DM_USE_SVM,
			gettext("reserved for metadb replicas"), classes);
		*used = B_TRUE;
	    } else {
		*used = B_FALSE;
	    }
	}

	return (error);
}

/*
 * FUNCTION:	save_slice_classification(char *dsname, dm_descriptor_t slice,
 *			dm_descriptor_t disk, char *used_by, char *usage_detail,
 *			dlist_t **classes)
 *
 * INPUT:	dsname	- a char * disk set name
 *		slice	- a dm_descriptor_t slice handle.
 *		disk	- a dm_descriptor_t handle for the slice's disk.
 *		used_by - a char * usage classification.
 *		usage_detail - a char * usage description for the slice.
 *
 * OUTPUT:	classes	- a list of slice_class_t updated to hold a usage
 *				entry for the input slicexs.
 *
 * SIDEEFFECT:	adds the input slice to the list of known, used slices.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Adds an entry to the
 *		appropriate slice_class_t list of slices.  If there is
 *		not an appropriate slice_class_t entry in the input list
 *		of classes, one is added.
 *
 *		As a performance optimization the slice usage classification
 *		information is only saved if verbose output was requested by
 *		the user.
 */
static int
save_slice_classification(
	char		*dsname,
	dm_descriptor_t	slice,
	dm_descriptor_t	disk,
	char		*usage,
	char		*usage_detail,
	dlist_t		**classes)
{
	int		error = 0;

	error = add_used_slice(slice);

	if ((error == 0) && (get_max_verbosity() >= OUTPUT_VERBOSE)) {

	    dlist_t		*iter;
	    dlist_t		*item;
	    slice_class_t 	*class = NULL;

	    /* locate class struct matching 'usage' */
	    for (iter = *classes; iter != NULL; iter = iter->next) {
		class = (slice_class_t *)iter->obj;
		if (string_case_compare(usage, class->usage) == 0) {
		    break;
		}
	    }

	    if (iter == NULL) {
		/* add a new class to the list of classes */
		class = (slice_class_t *)calloc(1, sizeof (slice_class_t));
		if (class == NULL) {
		    error = ENOMEM;
		} else {
		    class->usage = strdup(usage);
		    if (class->usage == NULL) {
			free(class);
			class = NULL;
			error = ENOMEM;
		    } else {
			item = dlist_new_item((void *)class);
			if (item == NULL) {
			    free(class->usage);
			    free(class);
			    class = NULL;
			    error = ENOMEM;
			} else {
			    *classes = dlist_append(item, *classes, AT_TAIL);
			}
		    }
		}
	    }

	    if ((error == 0) && (class != NULL)) {

		char buf[BUFSIZ];
		char *dup = NULL;
		char *slicename = NULL;

		(void) get_display_name(slice, &slicename);
		(void) snprintf(buf, BUFSIZ-1, "  %s: %s",
			slicename, usage_detail);
		if ((dup = strdup(buf)) == NULL) {
		    error = ENOMEM;
		} else {
		    if ((item = dlist_new_item((void *)dup)) == NULL) {
			free(dup);
			error = ENOMEM;
		    } else {
			class->sliceinfo =
			    dlist_insert_ordered(
				    item, class->sliceinfo,
				    ASCENDING, compare_strings);
		    }
		}
	    }
	}

	return (error);
}

/*
 * FUNCTION:	print_usable_devices()
 *
 * PURPOSE:	Print out the devices determined to be available for
 *		use by layout.
 *
 *		Iterates the lists of usable slices, disks and HBAs
 *		and prints out their CTD and device names.
 */
static void
print_usable_devices()
{
	int	i = 0;

	struct {
		char *msg;
		dlist_t *list;
	}	devs[3];

	devs[0].msg = gettext("HBA/Controllers");
	devs[0].list = _usable_hbas;
	devs[1].msg = gettext("disks");
	devs[1].list = _usable_disks;
	devs[2].msg = gettext("slices");
	devs[2].list = _usable_slices;

	for (i = 0; i < 3; i++) {

	    oprintf(OUTPUT_VERBOSE,
		    gettext("\n  These %s are usable:\n\n"),
		    devs[i].msg);

	    print_device_list(devs[i].list);
	}
}

/*
 * FUNCTION:	print_device_list(dlist_t *devices)
 *
 * INPUT:	devices	- a list of device descriptor handles
 *
 * PURPOSE:	A helper for the print_XXX_devices() routines which iterates
 *		the input list and prints out each device name, CTD name and
 *		alias(es).
 */
static void
print_device_list(
	dlist_t *devices)
{
	dlist_t *iter = NULL;

	for (iter = devices; iter != NULL; iter = iter->next) {

	    dm_descriptor_t device = ((uintptr_t)iter->obj);
	    char	*name = NULL;
	    char	*ctd = NULL;
	    dlist_t	*aliases = NULL;

	    (void) get_display_name(device, &ctd);
	    (void) get_name(device, &name);
	    oprintf(OUTPUT_VERBOSE,
		    "    %-25s %s\n", (ctd != NULL ? ctd : ""), name);

	    (void) get_aliases(device, &aliases);
	    for (; aliases != NULL; aliases = aliases->next) {
		oprintf(OUTPUT_VERBOSE,
			gettext("      (alias: %s)\n"),
			(char *)aliases->obj);
	    }

	    dlist_free_items(aliases, free);
	}
}

/*
 * FUNCTION:	print_unusable_devices(
 *			dlist_t *bad_slices, dlist_t *bad_disks,
 *			dlist_t	*used_classes)
 *
 * INPUT:	used_classes - a list of slice_class_t structs
 *
 * PURPOSE:	Print out the devices determined to be unavailable for
 *		use by layout.
 *
 *		Iterates the input list of slice classifications and prints
 *		out a description of the class and the slices so classified.
 *
 *		Also iterates the lists of bad slices and disks (those that
 *		libdiskmgt returned descriptors for but cannot be accessed)
 *		and notes them as unusable.
 */
static void
print_unusable_devices(
	dlist_t	*bad_slices,
	dlist_t	*bad_disks,
	dlist_t	*used_classes)
{
	dlist_t	*iter = NULL;
	dlist_t	*slices = NULL;
	char	*preamble;

	struct {
		char *msg;
		dlist_t *list;
	}	devs[2];

	/* report bad disks and slices */
	devs[0].msg = gettext("disks");
	devs[0].list = bad_disks;
	devs[1].msg = gettext("slices");
	devs[1].list = bad_slices;

	if (bad_disks != NULL) {
	    oprintf(OUTPUT_VERBOSE,
#if defined(sparc)
		    gettext("\n  These disks are not usable, they may "
			    "may be offline or cannot be accessed:\n\n"));
#elif defined(i386)
		    gettext("\n  These disks are not usable, they may "
			    "may be offline,\n  missing a Solaris FDISK "
			    "partition or cannot be accessed:\n\n"));
#endif
	    print_device_list(bad_disks);
	}

	if (bad_slices != NULL) {
	    oprintf(OUTPUT_VERBOSE, gettext(
		"\n  These slices, and subsequently the disks on which they\n"
		"reside, are not usable, they cannot be accessed:\n\n"));
	    print_device_list(bad_slices);
	}

	/* report used slices and usages */
	preamble = gettext("\n  These slices are not usable, %s:\n\n");
	for (iter = used_classes; iter != NULL; iter = iter->next) {
	    slice_class_t *class = (slice_class_t *)iter->obj;

	    if (class->sliceinfo != NULL) {

		oprintf(OUTPUT_VERBOSE, preamble,
			get_slice_usage_msg(class->usage));

		slices = class->sliceinfo;
		for (; slices != NULL; slices = slices->next) {
		    oprintf(OUTPUT_VERBOSE, "  %s\n", (char *)slices->obj);
		}
	    }
	}

}

/*
 * FUNCTION:	char * get_slice_usage_msg(char *usage)
 *
 * INPUT:	usage - char * string representing a slice usage classification
 *
 * OUTPUT:	char * "friendly" usage message
 *
 * PURPOSE:	the input usage string comes from libdiskmgt and is very terse.
 *
 *		Convert it into a friendlier usage description suitable for user
 *		consumption.
 */
static char *
get_slice_usage_msg(
	char *usage)
{
	char *str = NULL;

	if (string_case_compare(usage, DM_USE_MOUNT) == 0) {
	    str = gettext("they have mounted filesystems");
	} else if (string_case_compare(usage, DM_USE_FS) == 0) {
	    str = gettext("they appear to have unmounted filesystems");
	} else if (string_case_compare(usage, DM_USE_SVM) == 0) {
	    str = gettext("they are utilized by SVM");
	} else if (string_case_compare(usage, DM_USE_VXVM) == 0) {
	    str = gettext("they are utilized by VxVm");
	} else if (string_case_compare(usage, DM_USE_LU) == 0) {
	    str = gettext("they are utilized by LiveUpgrade");
	} else if (string_case_compare(usage, DM_USE_DUMP) == 0) {
	    str = gettext("they are reserved as dump devices");
	} else if (string_case_compare(usage, USE_DISKSET) == 0) {
	    str = gettext("they have disk set issues");
	} else {
	    /* libdiskmgt has detected a usage unknown to layout */
	    str = usage;
	}

	return (str);
}

/*
 * FUNCTION:	set_alias(dm_descriptor_t desc, char *alias)
 *
 * INPUT:	desc	- a dm_descriptor_t handle.
 *		alias	- a char * alias for the device represented
 *				by the descriptor.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Adds the specified alias to the known aliases for the
 *		device associated with the input descriptor.
 */
int
set_alias(
	dm_descriptor_t desc,
	char	*alias)
{
	nvlist_t	*attrs = NULL;
	char		**old_aliases = NULL;
	char		**new_aliases = NULL;
	uint_t		nelem = 0;
	int		error = 0;
	int		i = 0;

	if ((error = get_cached_attributes(desc, &attrs)) != 0) {
	    return (error);
	}

	if ((error = get_string_array(
	    attrs, ATTR_DEVICE_ALIASES, &old_aliases, &nelem)) != 0) {
	    if (error != ENOENT) {
		return (error);
	    }
	    /* no aliases yet */
	    error = 0;
	}

	/* add new alias */
	new_aliases = (char **)calloc(MAX_ALIASES, sizeof (char *));
	if (new_aliases != NULL) {

	    for (i = 0; i < nelem && i < MAX_ALIASES; i++) {
		char *dup = strdup(old_aliases[i]);
		if (dup != NULL) {
		    new_aliases[i] = dup;
		} else {
		    error = ENOMEM;
		}
	    }

	    if (error == 0) {
		if (i == MAX_ALIASES) {
		    volume_set_error(
			    gettext("Maximum number of device aliases "
				    "(8) reached\n"),
			    MAX_ALIASES);
		    error = -1;

		} else {
		    new_aliases[i] = alias;
		    error = set_string_array(attrs, ATTR_DEVICE_ALIASES,
			    new_aliases, i + 1);
		}
	    }

	    free(new_aliases);
	}

	if (error == 0) {
	    /* cache descriptor under this alias */
	    error = add_cached_descriptor(alias, desc);
	}

	return (error);
}

/*
 * FUNCTION:	get_aliases(dm_descriptor_t desc, dlist_t **list)
 *
 * INPUT:	desc	- a dm_descriptor_t handle.
 *
 * OUTPUT:	list	- a dlist_t list pointing to the list of
 *				aliases associated with the device
 *				represented by the descriptor.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Retrieves aliases for the input descriptor and
 *		appends them to the input list.
 *
 *		The list of returned items must be freed by calling
 *		dlist_free_items(list, free)
 */
int
get_aliases(
	dm_descriptor_t desc,
	dlist_t		**list)
{
	nvlist_t	*attrs = NULL;
	char		**aliases = NULL;
	uint_t		nelem = 0;
	int		error = 0;
	int		i;

	if ((error = get_cached_attributes(desc, &attrs)) != 0) {
	    return (error);
	}

	if ((error = get_string_array(
	    attrs, ATTR_DEVICE_ALIASES, &aliases, &nelem)) != 0) {
	    if (error == ENOENT) {
		/* no aliases */
		return (0);
	    }
	}

	for (i = 0; i < nelem; i++) {
	    dlist_t *item;
	    char *dup;

	    if ((dup = strdup(aliases[i])) == NULL) {
		error = ENOMEM;
		break;
	    }

	    if ((item = dlist_new_item(dup)) == NULL) {
		free(dup);
		error = ENOMEM;
		break;
	    }

	    *list = dlist_append(item, *list, AT_TAIL);
	}

	return (error);
}

/*
 * FUNCTION:	compare_start_blocks(
 *			void *obj1, void *obj2)
 *
 * INPUT:	desc1	- opaque pointer to a dm_descriptor_t
 * 		desc2	- opaque pointer to a dm_descriptor_t
 *
 * RETURNS:	int	- <0 - if desc1.stblk < desc2.stblk
 *			   0 - if desc1.stblk == desc2.stblk
 *			  >0 - if desc1.stblk > desc.stblk
 *
 * PURPOSE:	dlist_t helper which compares the start blocks of
 *		the two input dm_descriptor_t slice handles.
 */
static int
compare_start_blocks(
	void	*desc1,
	void	*desc2)
{
	uint64_t stblk1 = 0;
	uint64_t stblk2 = 0;

	assert(desc1 != (dm_descriptor_t)0);
	assert(desc2 != (dm_descriptor_t)0);

	(void) slice_get_start_block((uintptr_t)desc1, &stblk1);
	(void) slice_get_start_block((uintptr_t)desc2, &stblk2);

	return (stblk1 - stblk2);
}

/*
 * FUNCTION:	compare_desc_display_names(
 *			void *desc1, void *desc2)
 *
 * INPUT:	desc1	- opaque pointer to a dm_descriptor_t
 * 		desc2	- opaque pointer to a dm_descriptor_t
 *
 * RETURNS:	int	- <0 - if desc1.name < desc2.name
 *			   0 - if desc1.name == desc2.name
 *			  >0 - if desc1.name > desc.name
 *
 * PURPOSE:	dlist_t helper which compares the CTD names of the
 *		two input dm_descriptor_t objects.
 */
static int
compare_desc_display_names(
	void	*desc1,
	void	*desc2)
{
	char	*name1 = NULL;
	char	*name2 = NULL;

	assert(desc1 != (dm_descriptor_t)0);
	assert(desc2 != (dm_descriptor_t)0);

	(void) get_display_name((uintptr_t)desc1, &name1);
	(void) get_display_name((uintptr_t)desc2, &name2);

	return (string_case_compare(name1, name2));
}
