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

#include <sys/param.h>
#include <meta.h>

#include "volume_string.h"

#include "volume_devconfig.h"
#include "volume_error.h"
#include "volume_dlist.h"
#include "volume_output.h"

#include "layout_device_cache.h"
#include "layout_device_util.h"
#include "layout_discovery.h"
#include "layout_dlist_util.h"
#include "layout_messages.h"
#include "layout_request.h"
#include "layout_slice.h"

#define	_LAYOUT_SLICE_C

static int pick_from_best_hba_and_disk(
	dlist_t   	*list,
	dlist_t   	*used,
	dm_descriptor_t *chosen);

static int slice_has_same_disk_geom(
	dm_descriptor_t slice,
	dlist_t		*used,
	boolean_t	*bool);

static int slice_on_unique_disk(
	dm_descriptor_t slice,
	dlist_t		*used,
	dlist_t		*othervols,
	boolean_t	*bool);

static int slice_on_unique_hba(
	dm_descriptor_t slice,
	dlist_t		*used,
	dlist_t		*othervols,
	boolean_t	*bool);

static int slice_on_similar_bus(
	dm_descriptor_t slice,
	dlist_t		*used,
	boolean_t	*bool);

static int slice_has_n_paths(
	dm_descriptor_t	slice,
	uint16_t	npaths,
	boolean_t	*bool);

static int compare_modslice_names(
	void 		*obj1,
	void		*obj2);

static int compare_string_to_modslice_name(
	void		*str,
	void		*modslice);

static int create_new_slice(
	dm_descriptor_t oslice,
	uint64_t	nbytes,
	boolean_t	add_extra_cyl,
	devconfig_t	**nslice);

static int create_modified_slice(
	dm_descriptor_t	oslice,
	char		*oname,
	uint32_t	oindex,
	uint64_t	ostart,
	uint64_t	osize,
	uint64_t	bps,
	char		*nname,
	uint32_t	nindex,
	uint64_t	nsize,
	devconfig_t	**nslice);

/*
 * list to track resized slices
 */
static  dlist_t	*_modified_slices = NULL;

/*
 * struct to track used slices and their disks...
 */
typedef struct {
	char		*slicename;
	dm_descriptor_t	disk;
} usedslice_t;

/*
 * list to of usedslice_t to track slices that have been
 * used for any reason.
 */
static dlist_t	*_used_slices = NULL;

static int add_used_slice_list_entry(char *slicename, dm_descriptor_t disk);
static int compare_usedslice_name_to_string(void *obj1, void *obj2);
static void free_used_slice(void *obj);

/*
 * list of slices reserved to be used for explicit
 * volume requests
 */
static dlist_t *_rsvd_slices = NULL;

/*
 * list of slices needing to be removed (zeroed out) prior to
 * applying any metassist modifications to the system.
 */
static dlist_t *_rmvd_slices = NULL;

/*
 * FUNCTION:	choose_slice(
 *		uint64_t	nbytes,
 *		uint16_t	npaths,
 *		dlist_t		*slices,
 *		dlist_t		*used,
 *		dlist_t		*used_hbas,
 *		dlist_t		*used_disks,
 *		boolean_t	unused_disk,
 *		boolean_t	nbytes_is_min,
 *		boolean_t	add_extra_cyl,
 *		devconfig_t	**chosen)
 *
 * INPUT:	nbytes -	required size
 *		npaths -	minimum required data paths
 *		*slices -	slices from which to choose
 *		*used -		slices used by the volume under construction
 *		*used_hbas -	hbas used by other volumes relevant to
 *					the volume under construction
 *		*used_disks -	disks used by other volumes relevant to
 *					the volume under construction
 *		unused_disk -	if true, the chosen slice must be from an
 *					unused disk
 *		nbytes_is_min -	if true, the chosen slice may be larger than
 *					nbytes.
 *		add_extra_cyl -	passed to create_new_slice, see comment there.
 *		**chosen -	pointer to hold the chosen slice
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Choosen a slice from the list of those available.
 *
 *		Of those available, choose in order of preference:
 *
 *		- one on a unique HBA and disk that is of the exact size
 *		- one on a unique HBA and disk that is of sufficient size
 *		- one on unique HBA that is of the exact size
 *		- one on unique HBA that is of sufficient size
 *		- one on unique disk that is of the exact size
 *		- one on unique disk that is of sufficient size
 *		- one on any HBA that is of exact size
 *		- one on any HBA that is of sufficient size
 *		- one on a unique HBA that is the largest size
 *		- one on a unique disk that is the largest size
 *		- one on any HBA that is the largest size
 *
 *		The function scans the available slices and builds lists of
 *		those meeting the criteria above.  After the scan is complete,
 *		the lists are examined in order, the first non-empty list is
 *		chosen.  If there are several possibilities in the chosen list,
 *		see if it is possible select the slice from the least used HBA
 *		and/or disk.
 *
 *		If nbytes_is_min is true, the returned slice will be
 *		at least nbytes in capacity.
 *
 *		If unused_disk is true, the returned slice will be from
 *		a disk with no other known uses.
 */
int
choose_slice(
	uint64_t	nbytes,
	uint16_t	npaths,
	dlist_t		*slices,
	dlist_t		*used,
	dlist_t		*used_hbas,
	dlist_t		*used_disks,
	boolean_t	unused_disk,
	boolean_t	nbytes_is_min,
	boolean_t	add_extra_cyl,
	devconfig_t	**chosen)
{
	dlist_t		*iter	= NULL;

	dm_descriptor_t	slice	= NULL;
	boolean_t	resize  = B_FALSE;
	boolean_t	verbose = (get_max_verbosity() == OUTPUT_VERBOSE);

	int		error	= 0;

	/*
	 * indexes into the list array:
	 * i -> unique controller	0 = yes, 1 = no
	 * j -> same bus type		0 = yes, 1 = no
	 * k -> unique disk		0 = yes, 1 = no
	 * l -> same disk geom		0 = yes, 1 = no
	 * m -> size			0 == exact, 1 = larger, 2 = any
	 */
	int		i, j, k, l, m;
	dlist_t		*list[2][2][2][2][3];

	/* output string arrays for each array dimension and index */
	char	*uniqhba[2];
	char	*samebus[2];
	char	*uniqdisk[2];
	char	*samegeom[2];
	char	*sizes[3];

	/* other output strings */
	char	*look_msg = NULL;
	char	*npaths_msg = NULL;
	char	*samegeom_msg = NULL;
	char	*samebus_msg = NULL;
	char	*uniqhba_msg = NULL;
	char	*uniqdisk_msg = NULL;
	char	*exact_msg = NULL;
	char	*larger_msg = NULL;
	char	*smaller_msg = NULL;
	char	*insuff_paths = NULL;
	char	*too_small = NULL;
	char	*useddisk_msg = NULL;

	if (verbose == B_TRUE) {
	    /* only initialize the output strings if needed */

	    /* BEGIN CSTYLED */
	    look_msg = gettext(
		    "\tlooking at slice: %s (%s)\n");
	    npaths_msg = gettext(
		    "\t    has the requested number of data paths (%d)\n");
	    samegeom_msg = gettext(
		    "\t    has the same disk geometry relative to used slices\n");
	    samebus_msg = gettext(
		    "\t    on a similar I/O bus/HBA relative to used slices\n");
	    uniqhba_msg = gettext(
		    "\t    on a unique HBA relative to used slices\n");
	    uniqdisk_msg = gettext(
		    "\t    on a unique disk relative to used slices\n");
	    exact_msg = gettext(
		    "\t    the exact size necessary\n");
	    larger_msg = gettext(
		    "\t    larger than necessary\n");
	    smaller_msg = gettext(
		    "\t    smaller than necessary\n");
	    insuff_paths = gettext(
		    "\t    rejected: not enough paths (%d requested)\n");
	    too_small = gettext(
		    "\t    rejected: too small\n");
	    useddisk_msg = gettext(
		    "\t    rejected: on a disk with other volume component(s)\n");

	    uniqhba[0] = gettext("unique HBA");
	    uniqhba[1] = gettext("non unique HBA");
	    samebus[0] = gettext("same bus type");
	    samebus[1] = gettext("different bus type");
	    uniqdisk[0] = gettext("unique disk");
	    uniqdisk[1] = gettext("non unique disk");
	    samegeom[0] = gettext("same geometry");
	    samegeom[1] = gettext("different geometry");
	    sizes[0] = gettext("an exact size slice");
	    sizes[1] = gettext("a larger slice");
	    sizes[2] = gettext("a smaller slice");

	    /* END CSTYLED */
	}

	/* init list array pointers */
	(void) memset(list, 0,  2*2*2*2*3 * sizeof (dlist_t *));

	for (iter = slices;
	    (iter != NULL) && (error == 0); iter = iter->next) {

	    dm_descriptor_t	slice = (uintptr_t)iter->obj;
	    uint64_t		snbytes = 0;
	    boolean_t		uniqdisk = B_FALSE;
	    boolean_t		uniqhba = B_FALSE;
	    boolean_t		samegeom = B_FALSE;
	    boolean_t		samebus = B_FALSE;
	    boolean_t		paths = B_FALSE;
	    dlist_t		*item = NULL;

	    ((error = slice_get_size(slice, &snbytes)) != 0) ||
	    (error = slice_has_n_paths(slice, npaths, &paths)) ||
	    (error = slice_on_unique_hba(slice, used, used_hbas, &uniqhba)) ||
	    (error = slice_on_unique_disk(slice, used, used_disks,
		    &uniqdisk)) ||
	    (error = slice_on_similar_bus(slice, used, &samebus)) ||
	    (error = slice_has_same_disk_geom(slice, used, &samegeom));
	    if (error != 0) {
		continue;
	    }

	    if (verbose == B_TRUE) {
		char *sname = NULL;
		char *sizestr = NULL;
		(void) get_display_name(slice, &sname);
		if (bytes_to_sizestr(snbytes, &sizestr,
			    universal_units, B_FALSE) == 0) {
		    oprintf(OUTPUT_VERBOSE, look_msg, sname, sizestr);
		    free(sizestr);
		}
	    }

	    if (npaths > 1) {
		if (paths && verbose) {
		    /* specifically asked for more paths, ... */
		    oprintf(OUTPUT_VERBOSE, npaths_msg);
		}
	    } else if (npaths == 1) {
		/* every disk has at least 1 path */
		paths = B_TRUE;
	    }

	    if (verbose == B_TRUE) {
		if (uniqhba) {
		    oprintf(OUTPUT_VERBOSE, uniqhba_msg);
		}
		if (uniqdisk) {
		    oprintf(OUTPUT_VERBOSE, uniqdisk_msg);
		}

		if (used != NULL) {
		    if (samebus) {
			oprintf(OUTPUT_VERBOSE, samebus_msg);
		    }
		    if (samegeom) {
			oprintf(OUTPUT_VERBOSE, samegeom_msg);
		    }
		}

		if (snbytes > nbytes) {
		    oprintf(OUTPUT_VERBOSE, larger_msg);
		} else if (snbytes == nbytes) {
		    oprintf(OUTPUT_VERBOSE, exact_msg);
		} else {
		    oprintf(OUTPUT_VERBOSE, smaller_msg);
		}
	    }

	    /* filter slices not meeting minimum criteria */
	    if (nbytes_is_min && (snbytes < nbytes)) {
		/* not large enough */
		if (verbose == B_TRUE) {
		    oprintf(OUTPUT_VERBOSE, too_small);
		}
		continue;
	    }

	    if (paths == B_FALSE) {
		/* not connected thru enough paths */
		if (verbose == B_TRUE) {
		    oprintf(OUTPUT_VERBOSE, insuff_paths, npaths);
		}
		continue;
	    }

	    if (uniqdisk != B_TRUE && unused_disk == TRUE) {
		/* not on a unique disk */
		if (verbose == B_TRUE) {
		    oprintf(OUTPUT_VERBOSE, useddisk_msg);
		}
		continue;
	    }

	    /* map slice properties into array indices */
	    i = (uniqhba ? 0 : 1);
	    j = (samebus ? 0 : 1);
	    k = (uniqdisk ? 0 : 1);
	    l = (samegeom ? 0 : 1);
	    m = (snbytes == nbytes ? 0 : (snbytes > nbytes ? 1 : 2));

		/*
		 * insert slice into the list array using derived indices.
		 * NB: lists of slices larger than necessary are kept in
		 * ascending order (results in best fit, not worst fit)
		 */
	    if ((item = dlist_new_item((void*)(uintptr_t)slice)) == NULL) {
		error = ENOMEM;
	    } else {
		list[i][j][k][l][m] =
		    dlist_insert_ordered(
			    item,
			    list[i][j][k][l][m],
			    (m == 1 ? ASCENDING : DESCENDING),
			    compare_slice_sizes);
	    }
	}

	/*
	 * Select a slice from one of the lists.
	 *
	 * The list with the combination of lowest indices
	 * is the most preferred list... in rough order:
	 *
	 *   one on a unique HBA and disk that is of the exact size
	 *   one on a unique HBA and disk that is of sufficient size (resize)
	 *   one on unique HBA that is of the exact size
	 *   one on unique HBA that is of sufficient size (resize)
	 *   one on unique disk that is of the exact size
	 *   one on unique disk that is of sufficient size (resize)
	 *   one on any HBA that is of exact size
	 *   one on any HBA that is of sufficient size (resize)
	 *   one on a unique HBA that is the largest size
	 *   one on a unique disk that is the largest size
	 *   one on any HBA that is the largest size
	 */
	slice = NULL;

	for (i = 0; i < 2; i++) {
	    for (j = 0; j < 2; j++) {
		for (k = 0; k < 2; k++) {
		    for (l = 0; l < 2; l++) {
			for (m = 0; m < 3; m++) {
			    if (list[i][j][k][l][m] != NULL) {

				/* pick least used slice from this list */
				error = pick_from_best_hba_and_disk(
					list[i][j][k][l][m],
					used, &slice);

				resize = (m == 1);

				/* terminate all loops */
				goto stop;
			    }
			}
		    }
		}
	    }
	}
stop:

	/*
	 * Slice chosen, is a resize necessary?
	 */
	if ((error == 0) && (slice != NULL)) {

	    if (error == 0) {
		if (verbose == B_TRUE) {
		    uint64_t	snbytes = 0;
		    char	*sname = NULL;
		    char	*sizestr = NULL;

		    (void) get_display_name(slice, &sname);
		    (void) slice_get_size(slice, &snbytes);

		    if (bytes_to_sizestr(snbytes, &sizestr,
				universal_units, B_FALSE) == 0) {
			oprintf(OUTPUT_VERBOSE,
				gettext("      selected %s (%s)\n"
					"        it is %s on a\n"
					"          %s (%s) and a\n"
					"          %s (%s)\n"),
				sname, sizestr,
				sizes[m],
				uniqhba[i], samebus[j],
				uniqdisk[k], samegeom[l]);
			free(sizestr);
		    }
		}

		if (resize) {
		    if (verbose == B_TRUE) {
			oprintf(OUTPUT_VERBOSE,
				gettext("        it has excess space, "
					"resizing...\n"));
		    }

		    error = create_new_slice(slice, nbytes, add_extra_cyl,
			    chosen);
		    if ((error == 0) &&	(*chosen != NULL) && verbose) {
			oprintf(OUTPUT_VERBOSE,
				gettext("        exactly resized\n"));
		    }
		}

		if (error == 0) {
		    /* either no resize was necessary or the resize failed */
		    if (*chosen == NULL) {
			/*
			 * use the original slice as it is.
			 * Make a devconfig_t for it.
			 */
			error = create_devconfig_for_slice(slice, chosen);
		    }
		}
	    }
	} else if (slice == NULL) {
	    oprintf(OUTPUT_DEBUG,
		    gettext("      no possible slice\n"));
	}

	for (i = 0; i < 2; i++) {
	    for (j = 0; j < 2; j++) {
		for (k = 0; k < 2; k++) {
		    for (l = 0; l < 2; l++) {
			for (m = 0; m < 3; m++) {
			    if (list[i][j][k][l][m] != NULL) {
				dlist_free_items(list[i][j][k][l][m], NULL);
			    }
			}
		    }
		}
	    }
	}

	return (error);
}

/*
 * FUNCTION:	create_devconfig_for_slice(dm_descriptor_t slice,
 *			devconfig_t **nslice)
 *
 * INPUT:	slice	- dm_descriptor_t handle to an existing slice
 *		nslice	- devconfig_t pointer to hold the new slice
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Creates a devconfig_t struct representation of the input
 *		slice dm_descriptor.
 */
int
create_devconfig_for_slice(
	dm_descriptor_t slice,
	devconfig_t 	**nslice)
{
	uint64_t 	nbytes = 0;
	uint64_t 	nblks = 0;
	uint64_t 	stblk = 0;
	uint32_t 	index = 0;
	char		*name = NULL;
	int		error = 0;

	((error = get_display_name(slice, &name)) != 0) ||
	(error = slice_get_size(slice, &nbytes)) ||
	(error = slice_get_size_in_blocks(slice, &nblks)) ||
	(error = slice_get_start_block(slice, &stblk)) ||
	(error = slice_get_index(slice, &index));
	if (error != 0) {
	    return (error);
	}

	((error = new_devconfig(nslice, TYPE_SLICE)) != 0) ||
	(error = devconfig_set_name(*nslice, name)) ||
	(error = devconfig_set_slice_index(*nslice, index)) ||
	(error = devconfig_set_slice_start_block(*nslice, stblk)) ||
	(error = devconfig_set_size_in_blocks(*nslice, nblks)) ||
	(error = devconfig_set_size(*nslice, nbytes));
	if (error != 0) {
	    free_devconfig(*nslice);
	}

	return (error);
}

/*
 * FUNCTION:	make_slicename_for_disk_and_index(dm_descriptor_t disk,
 *			uint32_t index, char **slicename)
 *
 * INPUT:	disk	- a dm_descriptor_t disk handle
 *		index	- a slice index
 *
 * OUTPUT	slicename - a char * pointer to hold the resulting slicename
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Utility function to manufacture a new slice name given the
 *		"parent" disk and an available slice index.
 *
 *		The caller should free the returned name when done with it.
 */
static int
make_slicename_for_disk_and_index(
	dm_descriptor_t	disk,
	uint16_t	index,
	char		**slicename)
{
	char *dname;
	int error = 0;

	if ((error = get_display_name(disk, &dname)) == 0) {
	    error = make_slicename_for_diskname_and_index(dname,
		    index, slicename);
	}

	return (error);
}

/*
 * FUNCTION:	make_slicename_for_diskname_and_index(char *diskname,
 *			uint32_t index, char **slicename)
 *
 * INPUT:	diskname - a char * disk name
 *		index	- a slice index
 *
 * OUTPUT	slicename - a char * pointer to hold the resulting slicename
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Utility function to manufacture a new slice name given the
 *		name of a disk and an available slice index.
 *
 *		The caller should free the returned name when done with it.
 */
int
make_slicename_for_diskname_and_index(
	char	*diskname,
	uint16_t index,
	char	**slicename)
{
	int error = 0;
	char buf[MAXNAMELEN+1];

	(void) snprintf(buf, sizeof (buf), "%ss%u", diskname, index);
	if ((*slicename = strdup(buf)) == NULL) {
	    *slicename = NULL;
	    error = ENOMEM;
	}

	return (error);
}

/*
 * FUNCTION:	create_new_slice(dm_descriptor_t oslice, uint64_t nbytes,
 *			boolean_t add_extra_cyl, devconfig_t **nslice)
 *
 * INPUT:	oslice	- dm_descriptor_t handle to an existing slice
 *		nbytes	- desired minimum size of the new slice
 *		add_extra_cyl - boolean indicating whether the resized slice
 *			needs to be oversized by 1 cylinder to account for
 *			interlace rounding done for stripe components.
 *		nslice	- devconfig_t pointer to hold the new slice
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Creates a new slice object using space from the input slice.
 *
 *		If there is an open slice slot in the disk VTOC, it will be
 *		reserved for the new slice.  Space for the new slice will be
 *		taken from the original slice.
 *
 *		If there is no open slice slot, the original slice will be
 *		returned as the usable new slice.
 *
 *		The new slice will be of at least 'nbytes' bytes and possibly
 *		larger due to sector and cylinder boundary alignment.
 *
 *		For EFI labeled disks, nbytes is rounded up to the next block
 *		boundary.
 *
 *		For VTOC labeled disks, nbytes is rounded up to the next
 *		cylinder boundary.
 *
 *		Additionally, if add_extra_cyl is true, the new slice will be
 *		made 1 cylinder larger than necessary. This accounts for the
 *		interlace rounding done within libmeta when computing the
 *		usable size of stripe components on disks with VTOC labels.
 *		Rounding the size up to the next cylinder boundary is not
 *		sufficient because libmeta will round this size down to an
 *		integral multiple of the stripe	interlace and then round that
 *		result down to a cylinder boundary.  This makes the usable
 *		size of the slice one cylinder smaller and possibly less than
 *		nbytes.  Adding an extra cylinder ensures the usable size is
 *		greater than nbytes despite the rounding.
 *
 *		If the resize is successful a pointer to the devconfig_t
 *		representing the new slice will be returned in "newslice".
 *
 *		If the resize cannot be done, the newslice pointer will
 *		be NULL.
 */
static int
create_new_slice(
	dm_descriptor_t	oslice,
	uint64_t	nbytes,
	boolean_t	add_extra_cyl,
	devconfig_t	**nslice)
{
	dm_descriptor_t odisk = NULL;
	boolean_t	efi = B_FALSE;

	char		*oname = NULL;
	uint64_t	osize = 0;	/* orig size (bytes) */
	uint64_t	ostart = 0;	/* orig start (byte) */
	uint64_t	ostblk = 0;	/* orig start (blk) */
	uint64_t	nsize = 0;	/* new size (bytes) */
	uint64_t	bytes_per_sect = 0;

	uint32_t 	oindex = 0;
	uint32_t	nindex = oindex;

	int		error = 0;

	*nslice = NULL;

	((error = slice_get_disk(oslice, &odisk)) != 0) ||
	(error = slice_get_index(oslice, &oindex));
	if (error != 0) {
	    return (error);
	}

	/* find an unused slice number, default to oindex */
	nindex = oindex;
	if ((error = disk_get_available_slice_index(odisk, &nindex)) != 0) {
	    return (error);
	}

	((error = get_display_name(oslice, &oname)) != 0) ||
	(error = slice_get_size(oslice, &osize)) ||
	(error = slice_get_start(oslice, &ostart)) ||
	(error = slice_get_start_block(oslice, &ostblk)) ||
	(error = disk_get_is_efi(odisk, &efi)) ||
	(error = disk_get_blocksize(odisk, &bytes_per_sect));
	if (error != 0) {
	    return (error);
	}

	if (efi) {

	    /* EFI: round size to an integral number of blocks (sectors) */
	    nsize = bytes_per_sect *
		((nbytes + (bytes_per_sect - 1)) / bytes_per_sect);

	    oprintf(OUTPUT_DEBUG,
		    gettext("          "
			    "rounded up to %10.2f blocks\n"),
		    (double)(nsize/bytes_per_sect));

	} else {

	    /* VTOC: round size to an integral number of cylinders */
	    uint64_t	nhead = 0;
	    uint64_t	nsect = 0;
	    uint64_t	ncyls = 0;

	    ((error = disk_get_ncylinders(odisk, &ncyls)) != 0) ||
	    (error = disk_get_nheads(odisk, &nhead)) ||
	    (error = disk_get_nsectors(odisk, &nsect));
	    if (error == 0) {
		uint64_t bytes_per_cyl = nhead * nsect * bytes_per_sect;
		nsize = bytes_per_cyl *
		    ((nbytes + (bytes_per_cyl - 1)) / bytes_per_cyl);

		if (add_extra_cyl == TRUE) {
		    nsize += bytes_per_cyl;
		}

		oprintf(OUTPUT_DEBUG,
			gettext("          "
				"rounded VTOC slice to %10.2f cylinders "
				"(out of %llu)\n"),
			(double)(nsize/bytes_per_cyl), ncyls);
	    }
	}

	/* is sufficient space still available? */
	if (error == 0) {
	    if (osize == nsize) {
		/* use existing slice as is */
		((error = create_devconfig_for_slice(oslice, nslice)) != 0) ||
		(error = disk_reserve_index(odisk, (uint16_t)nindex));
	    } else if (osize > nsize) {

		if (nindex == oindex) {
		    /* no more slices, resize existing slice */
		    ((error = create_devconfig_for_slice(oslice,
			nslice)) != 0) ||
		    (error = devconfig_set_size(*nslice, nsize)) ||
		    (error = devconfig_set_size_in_blocks(*nslice,
			nsize/bytes_per_sect));
		    (error = disk_reserve_index(odisk, (uint16_t)nindex));

		} else {
		    /* make a new slice */
		    char *nname = NULL;

		    ((error = make_slicename_for_disk_and_index(odisk,
			nindex, &nname)) != 0) ||
		    (error = create_modified_slice(oslice, oname, oindex,
			ostart, osize, bytes_per_sect, nname, nindex, nsize,
			nslice)) ||
			/* mark the new slice's index as used */
		    (error = disk_reserve_index(odisk, (uint16_t)nindex));

		    if ((error != 0) && (*nslice == NULL)) {
			free(nname);
		    }
		}
	    }
	}

	return (error);
}

/*
 * FUNCTION:	create_modified_slice(dm_descriptor_t oslice, char *oname,
 *			uint32_t oindex, uint64_t ostart, uint64_t osize,
 *			uint64_t bytes_per_sect, uint64_t nsize,
 *			char *nname, uint32_t nindex, devconfig_t **nslice)
 *
 * INPUT:	oslice	- dm_descriptor_t handle for the original slice
 *		oname - existing source slice name
 *		oindex - existing source slice VTOC index
 *		ostart - existing source slice start byte
 *		osize - existing source slice size in bytes
 *		bytes_per_sect - bytes per block (sector) for the disk
 *		nname - new slice name
 *		nindex - new slice VTOC index
 *		nsize - new slice size in bytes (cylinder and block aligned)
 *
 * SIDEEFFECTS: updates the module private list of modified slices
 *
 * OUTPUT:	nslice - pointer to a devconfig_t to hold the new slice
 *
 * PURPOSE:	create a new VTOC slice by taking space from an
 *		existing slice.
 *
 *		The input size for the new slice is expected to be
 *		cylinder aligned.
 */
static int
create_modified_slice(
	dm_descriptor_t	oslice,
	char		*oname,
	uint32_t	oindex,
	uint64_t	ostart,
	uint64_t	osize,
	uint64_t	bytes_per_sect,
	char		*nname,
	uint32_t	nindex,
	uint64_t	nsize,
	devconfig_t	**nslice)
{
	int		error = 0;

	/* compute start sector and size in sectors for the new slice */

	/* subtract nsize from original slice to get starting byte */
	uint64_t	nstart = (ostart + osize) - nsize;

	/* convert starting byte to a sector */
	uint64_t	nstblk = (uint64_t)(nstart / bytes_per_sect);

	/* convert nsize to an integral number of blocks (sectors) */
	uint64_t	nblks = (uint64_t)(nsize / bytes_per_sect);

	/* create a modified slice record for the new slice */
	error = assemble_modified_slice(oslice, nname, nindex,
		nstblk, nblks, nsize, nslice);
	if (error != 0) {
	    free(nname);
	    return (error);
	}

	/* update the existing source slice's new size */
	osize = osize - nsize;
	(void) slice_set_size(oslice, osize);

	/* update/create the modified slice record gfor the source slice */
	error = assemble_modified_slice((dm_descriptor_t)0,
		oname, oindex, (uint64_t)(ostart / bytes_per_sect),
		(uint64_t)(osize / bytes_per_sect),
		osize, NULL);

	return (error);
}

/*
 * FUNCTION:	assemble_modified_slice(dm_descriptor_t src_slice,
 *			char *mod_name,	uint32_t mod_index,
 *			uint64_t mod_stblk, uint64_t mod_nblks,
 *			uint64_t mod_size, devconfig_t **modslice)
 *
 * INPUT:	src_slice - dm_descriptor_t handle of the slice space
 *			was taken from to create the modified slice
 *		mod_name - name of the modified slice
 *		mod_index - name of the modified slice
 *		mod_stblk - start block of the modified slice
 *		mod_nblks - size in blocks of the modified slice
 *		mod_size - size in bytes of the modified slice
 *
 * OUTPUT:	mod_slice	- if non-NULL, will be populated with a
 *			devconfig_t representing the modified slice.
 *
 * SIDEEFFECTS: adds or updates an entry in the modified slice list
 *		tracking the slices that have been explicitly modified
 *		by the layout code.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Utility function to which updates or creates a devconfig_t
 *		representing a slice that needs to be modified.
 *
 *		If a modified slice record does not exist for the named
 *		slice, a new devconfig_t struct is allocated and added
 *		to the modified slice list.
 *
 *		The existing or created devconfig_t struct is updated with
 *		the input values.
 *
 *		The information about the slices in the modified slice list
 *		will eventually be handed to fmthard.
 */
int
assemble_modified_slice(
	dm_descriptor_t	src_slice,
	char		*mod_name,
	uint32_t	mod_index,
	uint64_t	mod_stblk,
	uint64_t	mod_nblks,
	uint64_t	mod_size,
	devconfig_t	**mod_slice)
{
	devconfig_t	*slice = NULL;
	modslice_t	*mstp = NULL;
	dlist_t		*item = NULL;
	int		error = 0;

	/* see if the slice has been modified before */
	if ((item = dlist_find(_modified_slices, mod_name,
	    compare_string_to_modslice_name)) != NULL) {

	    /* yes, update the resize count and attributes */
	    mstp = (modslice_t *)item->obj;
	    slice = mstp->slice_devcfg;

	    mstp->times_modified += 1;
	    mstp->src_slice_desc = src_slice;

	    ((error = devconfig_set_slice_start_block(slice,
		mod_stblk)) != 0) ||
	    (error = devconfig_set_size(slice, mod_size)) ||
	    (error = devconfig_set_size_in_blocks(slice, mod_nblks));

	} else {

	    /* no, first modification... */
	    /* create a devconfig_t representing the new slice */
	    ((error = new_devconfig(&slice, TYPE_SLICE)) != 0) ||
	    (error = devconfig_set_name(slice, mod_name)) ||
	    (error = devconfig_set_slice_index(slice, mod_index)) ||
	    (error = devconfig_set_slice_start_block(slice, mod_stblk)) ||
	    (error = devconfig_set_size_in_blocks(slice, mod_nblks)) ||
	    (error = devconfig_set_size(slice, mod_size));
	    if (error == 0) {
		/* add to list of modified slices */
		if ((mstp = (modslice_t *)
		    calloc(1, sizeof (modslice_t))) != NULL) {

		    /* count # of times source slice has been modified */
		    if (src_slice != (dm_descriptor_t)0) {
			mstp->times_modified = 0;
		    } else {
			mstp->times_modified = 1;
		    }
		    mstp->src_slice_desc = src_slice;
		    mstp->slice_devcfg = slice;

		    if ((item = dlist_new_item(mstp)) != NULL) {
			_modified_slices =
			    dlist_insert_ordered(
				    item,
				    _modified_slices,
				    ASCENDING,
				    compare_modslice_names);
		    } else {
			error = ENOMEM;
		    }
		} else {
		    error = ENOMEM;
		}
	    }

	    if (error != 0) {
		free_devconfig(mstp);
		free_devconfig(slice);
	    }
	}

	if (error == 0) {
	    oprintf(OUTPUT_DEBUG,
		    "          "
		    "modified %s (start blk: %9llu, nblks: %9llu)\n",
		    mod_name, mod_stblk, mod_nblks);

	    /* return devconfig_t for modified slice */
	    if (mod_slice != NULL) {
		*mod_slice = slice;
		mstp->volume_component = B_TRUE;
	    }
	}

	return (error);
}

/*
 * FUNCTION:	dlist_t *get_modified_slices()
 *
 * RETURNS:	pointer to the list of modslice_t structs representing
 *		modified slices
 *
 * PURPOSE:	public accessor to the list of slices modified while
 *		processing a request.
 */
dlist_t *
get_modified_slices()
{
	return (_modified_slices);
}

/*
 * FUNCTION:	free_modslice_object(void *obj)
 *
 * INPUT:	obj	- opaque pointer
 *
 * PURPOSE:	Frees memory associated with a modslice_t struct.
 */
static void
free_modslice_object(
	void	*obj)
{
	assert(obj != (modslice_t *)NULL);

	if (((modslice_t *)obj)->slice_devcfg != NULL) {
	    if (((modslice_t *)obj)->volume_component != B_TRUE) {
		free_devconfig(((modslice_t *)obj)->slice_devcfg);
	    }
	}

	free(obj);
}

/*
 * FUNCTION:	void release_modified_slices()
 *
 * INPUT:	none   -
 * OUTPUT:	none   -
 *
 * PURPOSE:	cleanup the module global list of slices modified
 *		while processing a request.
 */
int
release_modified_slices()
{
	dlist_free_items(_modified_slices, free_modslice_object);
	_modified_slices = NULL;

	return (0);
}

/*
 * FUNCTION:	destroy_new_slice(devconfig_t *dev)
 *
 * INPUT:	dev	- a devconfig_t pointer to a slice object
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Undoes slice creation done by create_new_slice():
 *
 *		release index
 *		remove from used_slices
 *		remove from modified_slices
 *		return space to source slice
 *		free memory
 */
int
destroy_new_slice(
	devconfig_t	*dev)
{
	dm_descriptor_t disk = NULL;
	uint64_t	size = 0;
	uint16_t	index = 0;
	modslice_t	*modified = NULL;
	dlist_t		*item = NULL;
	char		*name = NULL;
	int		error = 0;

	((error = devconfig_get_name(dev, &name)) != 0) ||
	(error = devconfig_get_slice_index(dev, &index)) ||
	(error = devconfig_get_size(dev, &size)) ||
	(error = get_disk_for_named_slice(name, &disk)) ||
	(error = disk_release_index(disk, index)) ||
	(error = remove_used_slice_by_name(name));
	if (error != 0) {
	    return (error);
	}

	/* remove from the modified_slices list */
	_modified_slices =
	    dlist_remove_equivalent_item(
		    _modified_slices, name,
		    compare_string_to_modslice_name, &item);

	if (item != NULL) {
	    modified = (modslice_t *)item->obj;
	    free((void*) item);
	}

	/* space from an existing slice? if so reclaim it. */
	if (modified != NULL) {

	    dm_descriptor_t src = modified->src_slice_desc;
	    char	*srcname = NULL;
	    dlist_t	*srcitem = NULL;

	    if (src != (dm_descriptor_t)0) {
		if ((error = get_display_name(src, &srcname)) == 0) {
		    srcitem =
			dlist_find(
				_modified_slices,
				srcname,
				compare_string_to_modslice_name);
		}
	    }

	    if ((error == 0) && (srcitem != NULL)) {

		modslice_t	*source = (modslice_t *)srcitem->obj;
		devconfig_t	*srcdevcfg = NULL;
		uint64_t	srcsize = NULL;
		uint64_t	srcsizeblks = NULL;
		uint64_t	inblks = NULL;

		srcdevcfg = source->slice_devcfg;
		source->times_modified -= 1;

		((error = devconfig_get_size(srcdevcfg, &srcsize)) != 0) ||
		(error = devconfig_set_size(srcdevcfg, srcsize + size)) ||
		(error = slice_set_size(src, srcsize + size)) ||
		(error = slice_get_size_in_blocks(src, &srcsizeblks)) ||
		(error = devconfig_get_size_in_blocks(srcdevcfg, &inblks));
		(error = devconfig_set_size_in_blocks(srcdevcfg, srcsizeblks));

		if (error == 0) {

		    /* was only modification undone? */
		    if (source->times_modified == 0) {

			_modified_slices =
			    dlist_remove_equivalent_item(
				    _modified_slices, srcname,
				    compare_string_to_modslice_name,
				    &srcitem);

			free_modslice_object((modslice_t *)srcitem->obj);
			free((void *)srcitem);
		    }
		}
	    }

	    free_modslice_object(modified);
	}

	return (error);
}

/*
 * FUNCTION:	pick_from_best_hba_and_disk(dlist_t *slices,
 *			dlist_t *used, dm_descriptor_t *chosen)
 *
 * INPUT:	slices	- a dlist_t poitner to a list of slices
 *		used	- a dlist_t pointer to a list of used slices
 *		chosen  - a dm_descriptor_t pointer to hold the result
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Examines the input list of slices and chooses the one
 *		that is on the least used HBA and disk.
 *
 *		HBA and disk usage is determined by examining the input
 *		list of used slices and counting the number of slices
 *		each HBA and disk contributes.
 *
 * 		The HBA which contributes the fewest is selected, and
 *		then the disk on that HBA which contributes the fewest
 *		is selected.
 *
 *		The largest slice from that disk is then returned.
 */
static int
pick_from_best_hba_and_disk(
	dlist_t		*slices,
	dlist_t		*used,
	dm_descriptor_t *chosen)
{
	dlist_t		*iter = NULL;
	dlist_t		*iter1 = NULL;
	dlist_t		*iter2 = NULL;
	dlist_t		*item = NULL;

	dlist_t		*used_slice_hbas = NULL;

	int		maxuses = 128;
	int		maxslices = VTOC_SIZE;  /* meta.h */

	int		i = 0;
	int 		error = 0;

	/*
	 * allocate an array to hold lists of slices grouped by
	 * HBA contribution... the list indexed by N is the list
	 * of slices that are on HBAs contributing N slices
	 */
	dlist_t **prefhbas = (dlist_t **)calloc(maxuses, sizeof (dlist_t *));

	/*
	 * allocate an array to hold lists of slices grouped by
	 * disk contribution... the list indexed by N is the list
	 * of slices that are on disks contributing N slices
	 */
	dlist_t **prefdisks = (dlist_t **)calloc(maxslices, sizeof (dlist_t *));

	*chosen = (dm_descriptor_t)0;

	if (prefhbas == NULL || prefdisks == NULL) {
	    free(prefhbas);
	    free(prefdisks);
	    return (ENOMEM);
	}

	/*
	 * precompute the used slices' lists of HBAS: iterate the list
	 * of used slices and determine the HBA(s) each is connected thru.
	 * construct a list of lists containing the HBAs.
	 */
	for (iter = used;
	    (iter != NULL) && (error == 0);
	    iter = iter->next) {

	    devconfig_t	*uslice = (devconfig_t *)iter->obj;
	    dm_descriptor_t udisk = NULL;
	    char	*uname = NULL;
	    dlist_t	*uhbas = NULL;

	    /* need to use disk to get to HBAs because */
	    /* the slice doesn't exist yet */
	    ((error = devconfig_get_name(uslice, &uname)) != 0) ||
	    (error = get_disk_for_named_slice(uname, &udisk)) ||
	    (error = disk_get_hbas(udisk, &uhbas));
	    if (error == 0) {
		if ((item = dlist_new_item((void *)uhbas)) == NULL) {
		    error = ENOMEM;
		} else {
		    used_slice_hbas = dlist_append(
			    item, used_slice_hbas, AT_HEAD);
		}
	    }
	}

	/*
	 * iterate the list of chosen slices and for each,
	 * determine how many other slices from its HBA(s)
	 * are already being used...
	 *
	 * iter steps thru the list of slices
	 * iter1 steps thru each of the slice's HBAs
	 * iter2 steps thru the precomputed list of used slice's HBAs
	 * dlist_contains then searches each used slice's HBAs
	 *   to see if it contains iter1's HBA
	 *
	 * If it does, increment the count for that HBA.
	 */
	for (iter = slices;
	    (iter != NULL) && (error == 0);
	    iter = iter->next) {

	    dm_descriptor_t slice = (uintptr_t)iter->obj;
	    dlist_t	*hbas = NULL;
	    int		n = 0; /* # slices each HBA contributes */

	    if ((error = slice_get_hbas(slice, &hbas)) != 0) {
		continue;
	    }

	    for (iter1 = hbas; iter1 != NULL; iter1 = iter1->next) {
		for (iter2 = used_slice_hbas; iter2 != NULL;
		    iter2 = iter2->next) {

		    dlist_t *uhbas = (dlist_t *)iter2->obj;
		    if (dlist_contains(uhbas, iter1->obj,
				compare_descriptor_names) == B_TRUE) {
			n++;
		    }
		}
	    }

	    dlist_free_items(hbas, NULL);

	    /* group slices from HBAs contributing more than maxuses */
	    if (n >= maxuses) {
		n = maxuses - 1;
	    }

	    /* add slice to list in descending size order */
	    if ((item = dlist_new_item((void*)(uintptr_t)slice)) == NULL) {
		error = ENOMEM;
	    } else {
		prefhbas[n] =
		    dlist_insert_ordered(
			    item,
			    prefhbas[n],
			    DESCENDING,
			    compare_slice_sizes);
	    }
	}

	/* free list of lists of used slices HBAs */
	for (iter = used_slice_hbas; iter != NULL; iter = iter->next) {
	    dlist_free_items((dlist_t *)iter->obj, NULL);
	}
	dlist_free_items(used_slice_hbas, NULL);

	/*
	 * Select the list of slices that are on the HBA(s) contributing
	 * the fewest slices... iterate these slices and for each, detemmine
	 * how many other slices from its disk are already being used...
	 */
	for (i = 0; (i < maxuses) && (error == 0); i++) {

	    for (iter = (dlist_t *)prefhbas[i];
		(iter != NULL) && (error == 0);
		iter = iter->next) {

		dm_descriptor_t slice = (uintptr_t)iter->obj;
		dm_descriptor_t disk;
		int		n = 0;

		(void) slice_get_disk(slice, &disk);

		/*
		 * count how many slices this slice's disk is contributing
		 * by comparing it to the list of used slices
		 */
		for (iter1 = _used_slices; iter1 != NULL; iter1 = iter1->next) {
		    usedslice_t *used = (usedslice_t *)iter1->obj;
		    if (compare_descriptors((void *)(uintptr_t)disk,
			(void *)(uintptr_t)used->disk) == 0) {
			n++;
		    }
		}

		/* add slice to list in descending size order */
		if ((item = dlist_new_item((void *)(uintptr_t)slice)) == NULL) {
		    error = ENOMEM;
		} else {
		    prefdisks[n] =
			dlist_insert_ordered(
				item,
				prefdisks[n],
				DESCENDING,
				compare_slice_sizes);
		}
	    }
	}

	if (error == 0) {
	    /* select largest slice from least used disk */
	    for (i = 0; (i < maxslices) && (*chosen == NULL); i++) {
		if (prefdisks[i] != NULL) {
		    *chosen = (uintptr_t)prefdisks[i]->obj;
		}
	    }
	}

	for (i = 0; i < maxuses; i++) {
	    dlist_free_items(prefhbas[i], NULL);
	}
	for (i = 0; i < maxslices; i++) {
	    dlist_free_items(prefdisks[i], NULL);
	}

	free((void*)prefhbas);
	free((void*)prefdisks);

	return (error);
}

/*
 * FUNCTION:	slice_on_unique_hba(dm_descriptor_t slice,
 *			dlist_t *used, dlist_t *used_hbas,
 *			boolean_t *unique)
 *
 * INPUT:	slice	- a dm_descriptor_t handle for the slice of interest
 *		used	- a dlist_t pointer to a list of used slices
 *		used_hbas - a dlist_t pointer to a list of used_hbas
 *		unique	- a boolean_t pointer to hold the result
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Determines if the input slice is connected thru the same HBA
 *		as a slice in the used list.
 *
 *		Also checks to see if the input slice is connected thru any
 *		HBA in the used_hbas list.
 *
 *		If the slice is found to be on a unique HBA, bool is set
 *		to B_TRUE, B_FALSE otherwise.
 */
static int
slice_on_unique_hba(
	dm_descriptor_t	slice,
	dlist_t		*used,
	dlist_t		*used_hbas,
	boolean_t	*unique)
{
	dlist_t		*iter	= NULL;
	dlist_t		*iter1	= NULL;

	dlist_t		*hbas = NULL;

	int		error	= 0;

	*unique = B_TRUE;

	if ((error = slice_get_hbas(slice, &hbas)) != 0) {
	    return (error);
	}

	/*
	 * check to see if any of slice's HBAs is the same
	 * as the HBA for any of the used
	 */
	for (iter = used;
	    (iter != NULL) && (*unique == B_TRUE) && (error == 0);
	    iter = iter->next) {

	    devconfig_t	*dev = (devconfig_t *)iter->obj;
	    if (devconfig_isA(dev, TYPE_SLICE)) {

		dm_descriptor_t	odisk = NULL;
		char		*oname = NULL;
		dlist_t		*ohbas = NULL;

		/* get HBAs for other slice using its disk */
		/* because the slice doesn't exist yet. */
		((error = devconfig_get_name(dev, &oname)) != 0) ||
		(error = get_disk_for_named_slice(oname, &odisk)) ||
		(error = disk_get_hbas(odisk, &ohbas));

		/* any HBA overlap? */
		for (iter1 = hbas;
		    (iter1 != NULL) && (*unique == B_TRUE) && (error == 0);
		    iter1 = iter1->next) {

		    if (dlist_contains(ohbas, iter1->obj,
				compare_descriptor_names) == B_TRUE) {
			*unique = B_FALSE;
		    }
		}
		dlist_free_items(ohbas, NULL);
	    }
	}

	/*
	 * check to see if any of slice's HBAs is the contained
	 * in the list of used hbas
	 */
	for (iter = hbas;
	    (iter != NULL) && (*unique == B_TRUE) && (error == 0);
	    iter = iter->next) {
	    if (dlist_contains(used_hbas,
		iter->obj, compare_descriptor_names) == B_TRUE) {
		*unique = B_FALSE;
	    }
	}

	dlist_free_items(hbas, NULL);

	return (error);
}

/*
 * FUNCTION:	slice_on_unique_disk(dm_descriptor_t slice,
 *			dlist_t *used, dlist_t *used_disks,
 *			boolean_t *unique)
 *
 * INPUT:	slice	- a dm_descriptor_t handle for the slice of interest
 *		used	- a dlist_t pointer to a list of used slices
 *		othervols - a dlist_t pointer to a list of other volumes
 *		bool	- a boolean_t pointer to hold the result
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Determines if the input slice is on a drive that is not
 *		part of any volume in the othervols list, or on the same
 *		drive as any slice in the used list.
 *
 *		If the slice is found to be on a unique disk, bool is set
 *		to B_TRUE, B_FALSE otherwise.
 */
static int
slice_on_unique_disk(
	dm_descriptor_t	slice,
	dlist_t		*used,
	dlist_t		*used_disks,
	boolean_t	*unique)
{
	dm_descriptor_t	disk = NULL;
	dlist_t		*iter = NULL;
	int		error = 0;

	*unique = B_TRUE;

	if ((error = slice_get_disk(slice, &disk)) != 0) {
	    return (error);
	}

	/*
	 * check to see if this disk is the same as the
	 * disk for any of the used
	 */
	for (iter = used;
	    (iter != NULL) && (*unique == B_TRUE) && (error == 0);
	    iter = iter->next) {

	    devconfig_t	*dev = (devconfig_t *)iter->obj;

	    if (devconfig_isA(dev, TYPE_SLICE)) {

		/* get disk for otherslice */
		dm_descriptor_t	odisk = NULL;
		char		*oname = NULL;

		((error = devconfig_get_name(dev, &oname)) != 0) ||
		(error = get_disk_for_named_slice(oname, &odisk));

		if ((error == 0) &&
			(compare_descriptor_names((void*)(uintptr_t)disk,
			    (void*)(uintptr_t)odisk) == 0)) {
		    /* origslice is on same disk, stop */
		    *unique = B_FALSE;
		}
	    }
	}

	/* check disk against the used disks */
	if ((error == 0) && (*unique == B_TRUE) &&
		dlist_contains(used_disks, (void *)(uintptr_t)disk,
			compare_descriptor_names) == B_TRUE) {
		*unique = B_FALSE;
	}

	return (error);
}

/*
 * FUNCTION:	slice_has_same_disk_geom(dm_descriptor_t slice,
 *			dlist_t *used, boolean_t *has_same_geom)
 *
 * INPUT:	slice	- a dm_descriptor_t handle for the slice of interest
 *		used	- a dlist_t pointer to a list of used slices
 *		bool	- a boolean_t pointer to hold the result
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Determines if the input slice is on a drive with similar
 *		hardware geometry as the slices in the used list.
 *
 *		If the slice is found to be on a disk with similar geometry,
 *		bool is set to B_TRUE, B_FALSE otherwise.
 *
 *		The comparison is based on the available disk geometry
 *		information which may not be relevant or accurate for
 *		EFI labeled disks, so the disk drive type needs to be
 *		checked	as well.
 */
static int
slice_has_same_disk_geom(
	dm_descriptor_t	slice,
	dlist_t		*used,
	boolean_t	*has_same_geom)
{
	dm_descriptor_t	disk = NULL;
	boolean_t	efi = B_FALSE;
	uint64_t	bsize	= 0;
	uint64_t	ncyls	= 0;
	uint64_t	nsects	= 0;
	uint64_t	nheads	= 0;
	dlist_t		*iter	= NULL;
	int		error	= 0;

	*has_same_geom = B_TRUE;

	((error = slice_get_disk(slice, &disk)) != 0) ||
	(error = disk_get_is_efi(disk, &efi)) ||
	(error = disk_get_blocksize(disk, &bsize));

	if ((error == 0) && (efi == B_FALSE)) {
	    ((error = disk_get_ncylinders(disk, &ncyls)) != 0) ||
	    (error = disk_get_nheads(disk, &nheads)) ||
	    (error = disk_get_nsectors(disk, &nsects));
	}

	if (error != 0) {
	    return (error);
	}

	/*
	 * check to see if slice's disk has the same geometry
	 * as the disks for the slices in the used list
	 */
	for (iter = used;
	    (iter != NULL) && (*has_same_geom == B_TRUE) && (error = 0);
	    iter = iter->next) {

	    devconfig_t	*dev = (devconfig_t *)iter->obj;

	    if (devconfig_isA(dev, TYPE_SLICE)) {

		/* get disk info for otherslice */
		dm_descriptor_t	odisk	= NULL;
		char		*oname	= NULL;
		boolean_t	oefi = B_FALSE;
		uint64_t	obsize	= 0;
		uint64_t	oncyls	= 0;
		uint64_t	onsects = 0;
		uint64_t	onheads = 0;

		((error = devconfig_get_name(dev, &oname)) != 0) ||
		(error = get_disk_for_named_slice(oname, &odisk)) ||
		(error = disk_get_is_efi(odisk, &oefi)) ||
		(error = disk_get_blocksize(odisk, &obsize));

		if ((error == 0) && (oefi == B_FALSE)) {
		    ((error = disk_get_ncylinders(odisk, &oncyls)) != 0) ||
		    (error = disk_get_nheads(odisk, &onheads)) ||
		    (error = disk_get_nsectors(odisk, &onsects));
		}

		if (error == 0) {
		    if ((bsize != obsize) || (ncyls != oncyls) ||
			(nsects != onsects) || (nheads != onheads)) {
			/* this disk has a different geometry */
			*has_same_geom = B_FALSE;
		    }
		}
	    }
	}

	return (error);
}

/*
 * FUNCTION:	slice_on_similar_bus(dm_descriptor_t slice,
 *			dlist_t *used, boolean_t *on_smlr_bus)
 *
 * INPUT:	slice	- a dm_descriptor_t handle for the slice of interest
 *		used	- a dlist_t pointer to a list of used slices
 *		bool	- a boolean_t pointer to hold the result
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Determines if the input slice is connected thru a bus with
 *		characteristics similar to the slices in the used list.
 *
 *		If the slice is found to be on a similar bus, bool is set
 *		to B_TRUE, B_FALSE otherwise.
 *
 *		The comparison is actually between any of the HBA/controllers
 *		thru which the slices are connected to the system.
 *		If any are of similar type (e.g., fibre, SCSI) and
 *		protocol (SCSI-2, -3, fast/wide), then the slices are
 *		considered to be on similar busses.
 */
static int
slice_on_similar_bus(
	dm_descriptor_t	slice,
	dlist_t		*used,
	boolean_t	*on_smlr_bus)
{
	dlist_t		*iter	= NULL;
	dlist_t		*iter1	= NULL;
	dlist_t		*hbas = NULL;
	int		error	= 0;

	/* if there are no used slices, then the bus is similar */
	*on_smlr_bus = B_TRUE;
	if (dlist_length(used) == 0) {
	    return (0);
	}

	(error = slice_get_hbas(slice, &hbas));
	if (error != 0) {
	    return (error);
	}

	/* if there are used slices, then make sure the bus is similar */
	*on_smlr_bus = B_FALSE;
	for (iter = hbas;
	    (iter != NULL) && (*on_smlr_bus == B_FALSE) && (error == 0);
	    iter = iter->next) {

	    dm_descriptor_t hba = (uintptr_t)iter->obj;
	    char	*type	= NULL;
	    boolean_t	fast80	= B_FALSE;
	    boolean_t	fast40	= B_FALSE;
	    boolean_t	fast20	= B_FALSE;
	    boolean_t	wide	= B_FALSE;

	    ((error = hba_get_type(hba, &type)) != 0) ||
	    (error = hba_is_fast_80(hba, &fast80)) ||
	    (error = hba_is_fast_40(hba, &fast40)) ||
	    (error = hba_is_fast_20(hba, &fast20)) ||
	    (error = hba_supports_wide(hba, &wide));
	    if (error != 0) {
		continue;
	    }

	    /* check against the HBAs for the used slices */
	    for (iter1 = used;
		(iter1 != NULL) && (*on_smlr_bus == B_FALSE) && (error == 0);
		iter1 = iter1->next) {

		devconfig_t *used = (devconfig_t *)iter1->obj;

		/* get HBAs for otherslice */
		dm_descriptor_t	udisk = NULL;
		char		*uname = NULL;
		dlist_t		*uhbas = NULL;
		dlist_t		*iter2 = NULL;

		((error = devconfig_get_name(used, &uname)) != 0) ||
		(error = get_disk_for_named_slice(uname, &udisk)) ||
		(error = disk_get_hbas(udisk, &uhbas));

		for (iter2 = uhbas;
		    (iter2 != NULL) && (*on_smlr_bus == B_FALSE) &&
			(error == 0);
		    iter2 = iter2 ->next) {

		    dm_descriptor_t uhba = (uintptr_t)iter2->obj;
		    char		*utype	= NULL;
		    boolean_t	ufast80	= B_FALSE;
		    boolean_t	ufast40	= B_FALSE;
		    boolean_t	ufast20	= B_FALSE;
		    boolean_t	uwide	= B_FALSE;

		    ((error = hba_get_type(uhba, &utype)) != 0) ||
		    (error = hba_is_fast_80(uhba, &ufast80)) ||
		    (error = hba_is_fast_40(uhba, &ufast40)) ||
		    (error = hba_is_fast_20(uhba, &ufast20)) ||
		    (error = hba_supports_wide(uhba, &uwide));

		    if (error == 0) {
			/* check sync speed ? */
			if ((fast80 == ufast80) && (fast40 == ufast40) &&
			    (fast20 == ufast20) && (wide == uwide) &&
			    (type == utype)) {
			    *on_smlr_bus = B_TRUE;
			}
		    }
		}
		dlist_free_items(uhbas, NULL);
	    }
	}

	dlist_free_items(hbas, NULL);

	return (error);
}

/*
 * FUNCTION:	slice_has_n_paths(dm_descriptor_t slice,
 *			uint16_t npaths, boolean_t *has_n_paths)
 * INPUT:	slice	- a dm_descriptor_t handle for the slice of interest
 * 		npaths	- the number of paths desired
 *		has_n_paths - a boolean_t pointer to hold the result
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Determines if the input slice is connected via npaths.
 *		has_n_paths is set to B_TRUE if so, B_FALSE otherwise.
 *
 *		In order for a disk to have multiple paths, MPXIO must
 *		be enabled and these conditions should hold:
 *
 *			Slice will have one drive object.
 *			Drive will have one HBA (scsi_vhci)
 *			Drive will have one alias.
 *			Drive will have possibly > 1 paths.
 *
 *		Getting the HBAs and aliases for the disk is relatively
 *		expensive, so they aren't checked.  The actual number of
 *		paths is only checked if MPXIO is known to be enabled on
 *		the system and the input npaths is > 1.
 */
static int
slice_has_n_paths(
	dm_descriptor_t	slice,
	uint16_t	npaths,
	boolean_t	*has_n_paths)
{
	int		error	= 0;

	*has_n_paths = B_FALSE;

	if ((npaths > 1) && (is_mpxio_enabled() == B_TRUE)) {

	    dm_descriptor_t	disk	= NULL;
	    dlist_t		*paths	= NULL;

	    ((error = slice_get_disk(slice, &disk)) != 0) ||
	    (error = disk_get_paths(disk, &paths));

	    if ((error == 0) && (dlist_length(paths) == npaths)) {
		*has_n_paths = B_TRUE;
	    }
	    dlist_free_items(paths, NULL);
	}

	return (error);
}

/*
 * FUNCTION:	compare_string_to_modslice_name(void *str, void *modslice)
 *
 * INPUT:	str	- opaque char * pointer
 * 		modslice - opaque modslice_t pointer
 *
 * RETURNS:	int	- <0 - if str < modslice->slice_devcfg.name
 *			   0 - if str == modslice->slice_devcfg.name
 *			  >0 - if str > modslice->slice_devcfg.name
 *
 * PURPOSE:	dlist_t helper which compares the input string to
 *		the name of a slice represented as modslice_t struct.
 *
 *		Comparison is done via string_case_compare.
 */
static int
compare_string_to_modslice_name(
	void		*str,
	void		*modslice)
{
	char		*name = NULL;

	assert(str != NULL);
	assert(modslice != NULL);

	(void) devconfig_get_name(
		((modslice_t *)modslice)->slice_devcfg, &name);

	return (string_case_compare((char *)str, name));
}

/*
 * FUNCTION:	compare_modslice_names(void *obj1, void *obj2)
 *
 * INPUT:	obj1	- opaque pointer
 * 		obj2	- opaque pointer
 *
 * RETURNS:	int	- <0 - if obj1 name < obj2 name
 *			   0 - if obj1 name == obj2 name
 *			  >0 - if obj1 name > obj2 name
 *
 * PURPOSE:	dlist_t helper which compares the names of two slices
 *		represented as modslice_t structs.
 *
 *		Comparison is done by string_case_compare
 */
static int
compare_modslice_names(
	void		*obj1,
	void		*obj2)
{
	char		*name1 = NULL;
	char		*name2 = NULL;

	assert(obj1 != NULL);
	assert(obj2 != NULL);

	(void) devconfig_get_name(
		((modslice_t *)obj1)->slice_devcfg, &name1);
	(void) devconfig_get_name(
		((modslice_t *)obj2)->slice_devcfg, &name2);

	return (string_case_compare(name1, name2));
}

/*
 * FUNCTION:	release_used_slices()
 *
 * PURPOSE:	Helper which cleans up the module private list of used
 *		slices.
 */
void
release_used_slices()
{
	dlist_free_items(_used_slices, free_used_slice);
	_used_slices = NULL;
}

static void
free_used_slice(
	void *obj)
{
	if (obj != NULL) {
	    usedslice_t *used = (usedslice_t *)obj;
	    free(used->slicename);
	    free(used);
	}
}

/*
 * FUNCTION:	is_used_slice(dm_descriptor_t slice, boolean_t *is_used)
 *
 * INPUT:	slice	- a dm_descriptor_t slice handle
 *
 * OUTPUT:	is_reserved - pointer to a boolean_t to hold the
 *			return result.
 *
 * PURPOSE:	Helper which checks to see if the input slice
 *		is in the used_slice list.
 *
 *		Check the input name against any used slice name or alias.
 *		is_used is set to B_TRUE if the	input slice is already used,
 *		B_FALSE otherwise.
 */
int
is_used_slice(
	dm_descriptor_t	slice,
	boolean_t	*is_used)
{
	char	*name;
	int	error = 0;

	if ((error = get_display_name(slice, &name)) == 0) {
	    *is_used = dlist_contains(_used_slices, (void *)name,
		    compare_usedslice_name_to_string);
	}

	return (error);
}

/*
 * FUNCTIONS:	add_used_slice(dm_descriptor_t slice)
 *		add_used_slice_by_name(char *slicename)
 *		add_used_slice_list_entry(char *slice)
 *		remove_used_slice_by_name(char *slicename)
 *
 * INPUT:	diskset	- a char * diskset name.
 *		slice	- a dm_descriptor_t slice handle
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Access or maintain the list of used slices.
 */
int
add_used_slice(
	dm_descriptor_t	slice)
{
	dm_descriptor_t disk;
	char	*name;
	int	error = 0;

	assert(slice != (dm_descriptor_t)0);

	((error = get_display_name(slice, &name)) != 0) ||
	(error = slice_get_disk(slice, &disk)) ||
	(error = add_used_slice_list_entry(name, disk));

	return (error);
}

int
add_used_slice_by_name(
	char	*slicename)
{
	dm_descriptor_t disk = (dm_descriptor_t)0;
	int	error = 0;

	assert(slicename != NULL);

	/* find disk for slice */
	error = get_disk_for_named_slice(slicename, &disk);
	if (error == 0) {
	    error = add_used_slice_list_entry(slicename, disk);
	}

	return (error);
}

static int
add_used_slice_list_entry(
	char	*slicename,
	dm_descriptor_t	disk)
{
	usedslice_t *used = NULL;
	int	error = 0;

	assert(slicename != NULL);
	assert(disk != (dm_descriptor_t)0);

	used = (usedslice_t *)calloc(1, sizeof (usedslice_t));
	if (used == NULL) {
	    error = ENOMEM;
	} else {

	    used->disk = disk;
	    if ((used->slicename = strdup(slicename)) == NULL) {
		free(used);
		error = ENOMEM;
	    } else {
		dlist_t *item = dlist_new_item((void *) used);
		if (item == NULL) {
		    free(used->slicename);
		    free(used);
		    error = ENOMEM;
		} else {
		    _used_slices =
			dlist_append(item, _used_slices, AT_HEAD);
		}
	    }
	}
	return (error);
}

int
remove_used_slice_by_name(
	char	*slice)
{
	dlist_t *removed = NULL;

	_used_slices =
	    dlist_remove_equivalent_item(_used_slices, (void *)slice,
		    compare_usedslice_name_to_string, &removed);

	if (removed != NULL) {
	    free_used_slice(removed->obj);
	    removed->obj = NULL;
	    free(removed);
	}

	return (0);
}

/*
 * FUNCTION:	compare_usedslice_name_to_string(void *obj1, void *obj2)
 * INPUT:	obj1	- opaque pointer
 * 		obj2	- opaque pointer
 *
 * RETURNS:	int	- <0 - if obj1 name < obj2 name
 *			   0 - if obj1 name == obj2 name
 *			  >0 - if obj1 name > obj2 name
 *
 * PURPOSE:	dlist_t helper which compares the names of a slice
 *		represented as modslice_t struct to a string.
 *
 *		obj1 is assumed to be a char *
 *		obj2 is assumed to be a usedslice_t *
 *
 *		Comparison is done via string_case_compare.
 */
static int
compare_usedslice_name_to_string(
	void		*obj1,
	void		*obj2)
{
	assert(obj1 != NULL);
	assert(obj2 != NULL);

	return (string_case_compare((char *)obj1,
			((usedslice_t *)obj2)->slicename));
}

/*
 * FUNCTION:	disk_has_used_slice(dm_descriptor_t disk, boolean_t *hasused)
 *
 * INPUT:	disk	- a dm_descriptor_t disk handle.
 *		inuse	- a boolean_t pointer to hold the result
 *
 * RETURNS:	int	- 0 on success
 *			 !0 othersize.
 *
 * PURPOSE:	Determines if any of the known used slices is on the
 *		input disk.
 */
int
disk_has_used_slice(
	dm_descriptor_t disk,
	boolean_t	*hasused)
{
	dlist_t		*iter;
	int		error = 0;

	*hasused = B_FALSE;
	for (iter = _used_slices;
	    (iter != NULL) && (*hasused == B_FALSE);
	    iter = iter->next) {

	    usedslice_t *used = (usedslice_t *)iter->obj;

	    /* compare used slice's disk to disk */
	    if (compare_descriptors((void *)(uintptr_t)disk,
		(void *)(uintptr_t)used->disk) == 0) {
		*hasused = B_TRUE;
	    }
	}

	return (error);
}

/*
 * FUNCTION:	add_reserved_slice(dm_descriptor_t slice)
 *
 * INPUT:	slice	- a dm_descriptor_t slice handle
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Helper which remembers specfically requested slices
 *		in a private list to ensure that the same slice isn't
 *		requested more than once.
 *
 *		Does not check to see if the slice already exists
 *		in the list of reserved slices. Assumes that the
 *		caller has checked using is_reserved_slice().
 *
 *		The reserved slice list is used by several functions:
 *
 *		1. layout_validate.validate_slice_components() adds user
 *		   requested slices to the list.
 *
 *		2. After all potentially usable slices have been scanned,
 *		   layout_validate.validate_reserved_slices() checks the
 *		   slices in the reserved and ensures that each slice is
 *		   actually usable as a volume component.
 *
 *		3. layout.disk_get_avail_space(), layout.disk_get_avail_slices()
 *		   exclude slices in the reserved list from being considered
 *		   available for general layout use.
 */
int
add_reserved_slice(
	dm_descriptor_t	slice)
{
	dlist_t	*item = NULL;

	if ((item = dlist_new_item((void *)(uintptr_t)slice)) == NULL) {
	    return (ENOMEM);
	}

	_rsvd_slices = dlist_append(item, _rsvd_slices, AT_HEAD);

	return (0);
}

/*
 * FUNCTION:	is_reserved_slice(dm_descriptor_t slice,
 *			boolean_t *is_reserved)
 *
 * INPUT:	slice	- a dm_descriptor_t slice handle
 *
 * OUTPUT:	is_reserved - pointer to a boolean_t to hold the
 *			return result.
 *
 * PURPOSE:	Helper which checks to see if the input slice
 *		was previously reserved.
 *
 *		Check the input name against any reserved slice
 *		name or alias. is_reserved is set to B_TRUE if the
 *		input slice is already reserved, B_FALSE otherwise.
 */
int
is_reserved_slice(
	dm_descriptor_t	slice,
	boolean_t	*is_reserved)
{
	*is_reserved = dlist_contains(_rsvd_slices,
	    (void *)(uintptr_t)slice, compare_descriptor_names);

	return (0);
}

/*
 * FUNCTION:	release_reserved_slice()
 *
 * PURPOSE:	Helper which cleans up the module private list of reserved
 *		slices.
 */
void
release_reserved_slices()
{
	dlist_free_items(_rsvd_slices, free);
	_rsvd_slices = NULL;
}

/*
 * FUNCTION:	get_reserved_slices(dlist_t **list)
 *
 * OUTPUT:	list	- a dlist_t pointer to hold the returned list of
 *			reserverd slices.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Accessor to retrieve the current list of reserved slice
 *		dm_descriptor_t handles.
 */
int
get_reserved_slices(
	dlist_t **list)
{
	*list = _rsvd_slices;

	return (0);
}

/*
 * FUNCTION:	add_slice_to_remove(char *name, uint32_t index)
 *
 * INPUT:	name	-	name of a slice
 *		index	-	index for the slice
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Utility function to add the named slice to the list of
 *		those that need to be "removed" by having their sizes
 *		set to 0.
 */
int
add_slice_to_remove(
	char		*name,
	uint32_t	index)
{
	rmvdslice_t *rmvd = NULL;
	int	error = 0;

	assert(name != NULL);

	rmvd = (rmvdslice_t *)calloc(1, sizeof (rmvdslice_t));
	if (rmvd == NULL) {
	    error = ENOMEM;
	} else {
	    rmvd->slice_index = index;
	    if ((rmvd->slice_name = strdup(name)) == NULL) {
		free(rmvd);
		error = ENOMEM;
	    } else {
		dlist_t *item = dlist_new_item((void *) rmvd);
		if (item == NULL) {
		    free(rmvd->slice_name);
		    free(rmvd);
		    error = ENOMEM;
		} else {
		    _rmvd_slices =
			dlist_append(item, _rmvd_slices, AT_HEAD);
		}
	    }
	}
	return (error);
}

/*
 * FUNCTION:	get_removed_slices()
 *
 * RETURNS:	dlist_t * - pointer to a list of rmvdslice_t structs
 *
 * PURPOSE:	Accessor to retrieve the current list of names of slices
 *		to be removed.
 */
dlist_t *
get_slices_to_remove(
	dlist_t **list)
{
	return (_rmvd_slices);
}

static void
free_rmvd_slice(
	void *obj)
{
	if (obj != NULL) {
	    rmvdslice_t *rmvd = (rmvdslice_t *)obj;
	    free(rmvd->slice_name);
	    free(rmvd);
	}
}

/*
 * FUNCTION:	release_removed_slices()
 *
 * PURPOSE:	Helper which cleans up the module private list of removed
 *		slices.
 */
void
release_slices_to_remove()
{
	dlist_free_items(_rmvd_slices, free_rmvd_slice);
	_rmvd_slices = NULL;
}
