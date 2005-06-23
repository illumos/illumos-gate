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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/vtoc.h>
#include <sys/dktp/fdisk.h>
#include <errno.h>
#include <meta.h>

#include <libdiskmgt.h>
#include "meta_repartition.h"

#define	_LAYOUT_DEVICE_UTIL_C

#include "volume_dlist.h"
#include "volume_error.h"
#include "volume_output.h"
#include "volume_nvpair.h"

#include "layout_device_cache.h"
#include "layout_device_util.h"
#include "layout_discovery.h"
#include "layout_dlist_util.h"
#include "layout_slice.h"

/*
 *	Macros to produce a quoted string containing the value of a
 *	preprocessor macro. For example, if SIZE is defined to be 256,
 *	VAL2STR(SIZE) is "256". This is used to construct format
 *	strings for scanf-family functions below.
 */
#define	QUOTE(x)	#x
#define	VAL2STR(x)	QUOTE(x)

/* private utilities for disks */
static int disk_get_uint64_attribute(
	dm_descriptor_t disk,
	char		*attr,
	uint64_t 	*val);

static int disk_get_boolean_attribute(
	dm_descriptor_t	disk,
	char		*attr,
	boolean_t	*bool);

static int disk_get_rpm(
	dm_descriptor_t disk,
	uint32_t 	*val);

static int disk_get_sync_speed(
	dm_descriptor_t disk,
	uint32_t 	*val);

static int disk_has_virtual_slices(
	dm_descriptor_t disk,
	boolean_t 	*bool);

static int disk_get_virtual_slices(
	dm_descriptor_t disk,
	dlist_t 	**list);

static int disk_get_reserved_indexes(
	dm_descriptor_t disk,
	uint16_t 	**array);

static int disk_get_associated_desc(
	dm_descriptor_t	disk,
	dm_desc_type_t	assoc_type,
	char		*assoc_type_str,
	dlist_t		**list);

/* utilities for slices */
static int slice_get_uint64_attribute(
	dm_descriptor_t slice,
	char		*attr,
	uint64_t 	*val);

static int slice_set_attribute(
	dm_descriptor_t slice,
	char		*attr,
	uint64_t 	val);

/*
 * Virtual slices are created to represent slices that will be
 * on the system after disks have been added to the destination
 * diskset.  For the purposes of layout, these slices must
 * look & function just as real slices that are currently on
 * the system.
 */
static dlist_t	*_virtual_slices = NULL;

/* temporary implementation */
static int virtual_repartition_drive(
	dm_descriptor_t disk,
	mdvtoc_t	*vtocp);

static int disk_add_virtual_slice(
	dm_descriptor_t disk,
	dm_descriptor_t slice);

static int virtual_slice_get_disk(
	dm_descriptor_t slice,
	dm_descriptor_t *diskp);

/*
 * attribute names for layout private information stored in
 * device nvpair attribute lists.
 */
static char *ATTR_RESERVED_INDEX = "vdu_reserved_index";
static char *ATTR_VIRTUAL_SLICES = "vdu_virtual_slices";
static char *ATTR_DISK_FOR_SLICE = "vdu_disk_for_slice";
static char *ATTR_DEV_CTD_NAME = "vdu_device_ctd_name";
static char *ATTR_HBA_N_DISKS = "vdu_hba_n_usable_disks";

/*
 * FUNCTION:	is_ctd_like_slice_name(char *name)
 * INPUT:	name	- a char *
 *
 * RETURNS:	boolean_t - B_TRUE - if name follows an alternate slice
 *				naming scheme similar to CTD
 *			    B_FALSE - otherwise
 *
 * PURPOSE:	Determines if the input name is of the form XXXsNNN
 *		(e.g., whizzy0s1)
 */
boolean_t
is_ctd_like_slice_name(
	char *name)
{
	uint_t		s = 0;
	uint_t		d = 0;
	int		l = 0;
	boolean_t	is = B_FALSE;

	/* The format strings below match and discard the non-numeric part. */
	if ((sscanf(name, "/dev/dsk/%*[^0-9/]%us%u%n", &d, &s, &l) == 2 ||
	    sscanf(name, "/dev/rdsk/%*[^0-9/]%us%u%n", &d, &s, &l) == 2 ||
	    sscanf(name, "%*[^0-9/]%us%u%n", &d, &s, &l) == 2) &&
		(l == strlen(name))) {
	    is = B_TRUE;
	}

	return (is);
}

/*
 * FUNCTION:	is_bsd_like_slice_name(char *name)
 * INPUT:	name	- a char *
 *
 * RETURNS:	boolean_t - B_TRUE - if name follows an alternate slice
 *				BSD-like naming scheme
 *			    B_FALSE - otherwise
 *
 * PURPOSE:	Determines if the input name is of the form XXXNNN[a-h]
 *			(e.g., whizzy0a)
 */
boolean_t
is_bsd_like_slice_name(
	char *name)
{
	uint_t		d = 0;
	int		l = 0;
	boolean_t	is = B_FALSE;

	/* The format strings below match and discard the non-numeric part. */
	if ((sscanf(name, "/dev/dsk/%*[^0-9/]%u%*[a-h]%n", &d, &l) == 1 ||
	    sscanf(name, "/dev/rdsk/%*[^0-9/]%u%*[a-h]%n", &d, &l) == 1 ||
	    sscanf(name, "%*[^0-9/]%u%*[a-h]%n", &d, &l) == 1) &&
		(l == strlen(name))) {
	    is = B_TRUE;
	}

	return (is);
}

/*
 * FUNCTION:	is_did_name(char *name)
 * INPUT:	name	- a char *
 *
 * RETURNS:	boolean_t - B_TRUE - if name is from the DID namespace
 *			    B_FALSE - otherwise
 *
 * PURPOSE:	Determines if the input name is from the DID namespace.
 */
boolean_t
is_did_name(
	char *name)
{
	return (is_did_slice_name(name) || is_did_disk_name(name));
}

/*
 * FUNCTION:	is_did_slice_name(char *name)
 * INPUT:	name	- a char *
 *
 * RETURNS:	boolean_t - B_TRUE - if name represents a slice from the DID
 *					namespace
 *			    B_FALSE - otherwise
 *
 * PURPOSE:	Determines if the input name is a slice from the DID namespace.
 */
boolean_t
is_did_slice_name(
	char *name)
{
	uint_t		d = 0, s = 0;
	int		l = 0;
	boolean_t	is = B_FALSE;

	if ((sscanf(name, "/dev/did/rdsk/d%us%u%n", &d, &s, &l) == 2 ||
		sscanf(name, "/dev/did/dsk/d%us%u%n", &d, &s, &l) == 2 ||
		sscanf(name, "d%us%u%n", &d, &s, &l) == 2) ||
		(l == strlen(name))) {
	    is = B_TRUE;
	}

	return (is);
}

/*
 * FUNCTION:	is_did_disk_name(char *name)
 * INPUT:	name	- a char *
 *
 * RETURNS:	boolean_t - B_TRUE - if name represents a disk from the DID
 *					namespace
 *			    B_FALSE - otherwise
 *
 * PURPOSE:	Determines if the input name is a disk from the DID namespace.
 */
boolean_t
is_did_disk_name(
	char *name)
{
	uint_t		d = 0;
	int		l = 0;
	boolean_t	is = B_FALSE;

	if ((sscanf(name, "/dev/did/rdsk/d%u%n", &d, &l) == 1 ||
		sscanf(name, "/dev/did/dsk/d%u%n", &d, &l) == 1 ||
		sscanf(name, "d%u%n", &d, &l) == 1) &&
		(l == strlen(name))) {
	    is = B_TRUE;
	}

	return (is);
}

/*
 * FUNCTION:	is_ctd_name(char *name)
 * INPUT:	name	- a char *
 *
 * RETURNS:	boolean_t - B_TRUE - if name is from the CTD namespace
 *			    B_FALSE - otherwise
 *
 * PURPOSE:	Determines if the input name is from the CTD namespace.
 *
 *		{/dev/dsk/, /dev/rdsk/}cXtXdXsX
 *		{/dev/dsk/, /dev/rdsk/}cXtXdX
 *		{/dev/dsk/, /dev/rdsk/}cXdXsX
 *		{/dev/dsk/, /dev/rdsk/}cXdX
 */
boolean_t
is_ctd_name(
	char *name)
{
	return (is_ctd_slice_name(name) || is_ctd_disk_name(name) ||
		is_ctd_target_name(name) || is_ctd_ctrl_name(name));
}

/*
 * FUNCTION:	is_ctd_slice_name(char *name)
 * INPUT:	name	- a char *
 *
 * RETURNS:	boolean_t - B_TRUE - if name represents a slice from the CTD
 *				namespace
 *			    B_FALSE - otherwise
 *
 * PURPOSE:	Determines if the input name is a slice name from the
 *		CTD namespace.
 *
 *		{/dev/dsk/, /dev/rdsk/}cXt<WWN>dXsX
 *		{/dev/dsk/, /dev/rdsk/}cXtXdXsX
 *		{/dev/dsk/, /dev/rdsk/}cXdXsX
 */
boolean_t
is_ctd_slice_name(
    char *name)
{
	uint_t		c = 0, t = 0, d = 0, s = 0;
	char		buf[MAXNAMELEN+1];
	int		l = 0;
	boolean_t	is = B_FALSE;

	if ((sscanf(name, "/dev/dsk/c%ut%ud%us%u%n", &c, &t, &d, &s, &l) == 4 ||
	    sscanf(name, "/dev/rdsk/c%ut%ud%us%u%n", &c, &t, &d, &s, &l) == 4 ||
	    sscanf(name, "c%ut%ud%us%u%n", &c, &t, &d, &s, &l) == 4 ||
	    sscanf(name, "/dev/dsk/c%ud%us%u%n", &c, &d, &s, &l) == 3 ||
	    sscanf(name, "/dev/rdsk/c%ud%us%u%n", &c, &d, &s, &l) == 3 ||
	    sscanf(name, "c%ud%us%u%n", &c, &d, &s, &l) == 3 ||
	    sscanf(name, "c%ud%us%u%n", &c, &d, &s, &l) == 2) &&
		(l == strlen(name))) {
	    is = B_TRUE;
	} else if (
	    (sscanf(name, "/dev/dsk/c%ut%" VAL2STR(MAXNAMELEN) "s%n",
		&c, buf, &l) == 2 ||
	    sscanf(name, "/dev/rdsk/c%ut%" VAL2STR(MAXNAMELEN) "s%n",
		&c, buf, &l) == 2 ||
	    sscanf(name, "c%ut%" VAL2STR(MAXNAMELEN) "s%n",
		&c, buf, &l) == 2) && (l == strlen(name))) {
	    char *dev_pos;

	    /* see if buf ends with "dXsX" */
	    if (((dev_pos = strrchr(buf, 'd')) != NULL) &&
		(sscanf(dev_pos, "d%us%u%n", &d, &s, &l) == 2) &&
		(l == strlen(dev_pos))) {

		char wwn[MAXNAMELEN+2];

		/* buf ends with "dXsX", truncate at the 'd' */
		*dev_pos = '\0';

		/* prepend "0X" to remainder and try to scan as a hex WWN */
		(void) snprintf(wwn, sizeof (wwn), "%s%s", "0X", buf);
		if ((sscanf(wwn, "%x%n", &t, &l) == 1) && (l == strlen(wwn))) {
		    is = B_TRUE;
		}
	    }
	}

	return (is);
}

/*
 * FUNCTION:	is_ctd_disk_name(char *name)
 * INPUT:	name	- a char *
 *
 * RETURNS:	boolean_t - B_TRUE - if name represents a disk from the CTD
 *				namespace
 *			    B_FALSE - otherwise
 *
 * PURPOSE:	Determines if the input name is a disk name from the
 *		CTD namespace.
 *
 *		{/dev/dsk/, /dev/rdsk/}cXt<WWN>dX
 *		{/dev/dsk/, /dev/rdsk/}cXtXdX
 *		{/dev/dsk/, /dev/rdsk/}cXdX
 */
boolean_t
is_ctd_disk_name(
    char *name)
{
	uint_t		c = 0, t = 0, d = 0;
	int		l = 0;
	char		buf[MAXNAMELEN+1];
	boolean_t	is = B_FALSE;

	if ((sscanf(name, "/dev/dsk/c%ut%ud%u%n", &c, &t, &d, &l) == 3 ||
	    sscanf(name, "/dev/rdsk/c%ut%ud%u%n", &c, &t, &d, &l) == 3 ||
	    sscanf(name, "c%ut%ud%u%n", &c, &t, &d, &l) == 3 ||
	    sscanf(name, "/dev/dsk/c%ud%u%n", &c, &d, &l) == 2 ||
	    sscanf(name, "/dev/rdsk/c%ud%n%n", &c, &d, &l) == 2 ||
	    sscanf(name, "c%ud%u%n", &c, &d, &l) == 2) &&
		(l == strlen(name))) {
	    is = B_TRUE;
	} else if ((sscanf(name, "/dev/dsk/c%ut%" VAL2STR(MAXNAMELEN) "s%n",
	    &c, buf, &l) == 2 ||
	    sscanf(name, "/dev/rdsk/c%ut%" VAL2STR(MAXNAMELEN) "s%n",
		&c, buf, &l) == 2 ||
	    sscanf(name, "c%ut%" VAL2STR(MAXNAMELEN) "s%n",
		&c, buf, &l) == 2) && (l == strlen(name))) {
	    char *dev_pos;

	    /* see if buf ends with "dX" */
	    if (((dev_pos = strrchr(buf, 'd')) != NULL) &&
		(sscanf(dev_pos, "d%u%n", &d, &l) == 1) &&
		(l == strlen(dev_pos))) {

		char wwn[MAXNAMELEN+2];

		/* buf ends with "dX", truncate at the 'd' */
		*dev_pos = '\0';

		/* prepend "0X" to remainder and try to scan as a hex WWN */
		(void) snprintf(wwn, sizeof (wwn), "%s%s", "0X", buf);
		if ((sscanf(wwn, "%x%n", &t, &l) == 1) && (l == strlen(wwn))) {
		    is = B_TRUE;
		}
	    }
	}

	return (is);
}

/*
 * FUNCTION:	is_ctd_disk_name(char *name)
 * INPUT:	name	- a char *
 *
 * RETURNS:	boolean_t - B_TRUE - if name represents a target from the CTD
 *				namespace
 *			    B_FALSE - otherwise
 *
 * PURPOSE:	Determines if the input name is a target name from the
 *		CTD namespace.
 *
 *		{/dev/dsk/, /dev/rdsk/}cXt<WWN>
 *		{/dev/dsk/, /dev/rdsk/}cXtX
 */
boolean_t
is_ctd_target_name(
    char *name)
{
	uint_t		c = 0, t = 0;
	int		l = 0;
	char		buf[MAXNAMELEN+1];
	boolean_t	is = B_FALSE;

	if ((sscanf(name, "/dev/dsk/c%ut%u%n", &c, &t, &l) == 2 ||
	    sscanf(name, "/dev/rdsk/c%ut%u%n", &c, &t, &l) == 2 ||
	    sscanf(name, "c%ut%u%n", &c, &t, &l) == 2) &&
		(l == strlen(name))) {
	    is = B_TRUE;
	} else if (
	    (sscanf(name, "/dev/dsk/c%ut%" VAL2STR(MAXNAMELEN) "s%n",
		&c, buf, &l) == 2 ||
	    sscanf(name, "/dev/rdsk/c%ut%" VAL2STR(MAXNAMELEN) "s%n",
		&c, buf, &l) == 2 ||
	    sscanf(name, "c%ut%" VAL2STR(MAXNAMELEN) "s%n",
		&c, &buf, &l) == 2) && (l == strlen(name))) {

	    char wwn[MAXNAMELEN+2];

	    /* prepend "0X" to buf and try to scan as a hex WWN */
	    (void) snprintf(wwn, sizeof (wwn), "%s%s", "0X", buf);
	    if ((sscanf(wwn, "%x%n", &t, &l) == 1) && (l == strlen(wwn))) {
		is = B_TRUE;
	    }
	}

	return (is);
}

/*
 * FUNCTION:	is_ctd_ctrl_name(char *name)
 * INPUT:	name	- a char *
 *
 * RETURNS:	boolean_t - B_TRUE - if name represents a controller/hba
 *				from the CTD namespace
 *			    B_FALSE - otherwise
 *
 * PURPOSE:	Determines if the input name is an HBA name from the
 *		CTD namespace.
 *
 *		{/dev/dsk/, /dev/rdsk/}cX
 */
boolean_t
is_ctd_ctrl_name(
	char	*name)
{
	uint_t		c = 0;
	int		l = 0;
	boolean_t	is = B_FALSE;

	if ((sscanf(name, "/dev/dsk/c%u%n", &c, &l) == 1 ||
	    sscanf(name, "/dev/rdsk/c%u%n", &c, &l) == 1 ||
	    sscanf(name, "c%u%n", &c, &l) == 1) &&
		(l == strlen(name))) {
	    is = B_TRUE;
	}

	return (is);
}

/*
 * FUNCTION:	set_display_name(dm_descriptor_t desc, char *name)
 *		get_display_name(dm_descriptor_t desc, char **name)
 *
 * INPUT:	desc	- a dm_descriptor_t handle for a device
 *		name    - a char * name
 *
 * OUTPUT:	**name	- a pointer to a char * to hold the display
 *			name associated with the input descriptor.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Helpers to set/get the input descriptor's display name.
 *
 *		Only slices, disks and HBAs should have display names.
 *
 *		The attribute is only set in the cached copy of
 *		the device's nvpair attribute list.  This function
 *		does not affect the underlying physical device.
 *
 *		An entry is added in the name->descriptor cache
 *		so the descriptor can be found by name quickly.
 */
int
set_display_name(
	dm_descriptor_t	desc,
	char		*name)
{
	nvlist_t	*attrs	= NULL;
	int		error	= 0;

	((error = add_cached_descriptor(name, desc)) != 0) ||
	(error = get_cached_attributes(desc, &attrs)) ||
	(error = set_string(attrs, ATTR_DEV_CTD_NAME, name));

	return (error);
}

int
get_display_name(
	dm_descriptor_t	desc,
	char		**name)
{
	nvlist_t	*attrs	= NULL;
	int		error	= 0;

	((error = get_cached_attributes(desc, &attrs)) != 0) ||
	(error = get_string(attrs, ATTR_DEV_CTD_NAME, name));

	return (error);
}

/*
 * FUNCTION:	disk_get_slices(dm_descriptor_t disk, dlist_t **list)
 *
 * INPUT:	disk	- a dm_descriptor_t handle for a disk
 *
 * OUTPUT:	*list	- a pointer to list to hold the results.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Collect all of the known slices for the input disk.
 *
 *		These slices may be actual slices which currently exist
 *		on the disk, or virtual slices which will exist when the
 *		disk is added to the destination diskset.
 */
int
disk_get_slices(
	dm_descriptor_t disk,
	dlist_t		**list)
{
	dm_descriptor_t	*media = NULL;
	boolean_t	virtual = B_FALSE;
	int		i = 0;
	int		error = 0;

	*list = 0;

	if ((error = disk_has_virtual_slices(disk, &virtual)) != 0) {
	    return (error);
	}

	if (virtual == B_TRUE) {
	    error = disk_get_virtual_slices(disk, list);
	}

	/* add real slices from disk's media... */
	media = dm_get_associated_descriptors(disk, DM_MEDIA, &error);
	(void) add_descriptors_to_free(media);

	if (error == 0) {
	    /* if there's no media, this is a removeable drive */
	    if (media != NULL && *media != NULL) {

		/* examine media's slices... */
		dm_descriptor_t	*slices = NULL;
		slices = dm_get_associated_descriptors(*media,
			DM_SLICE, &error);
		(void) add_descriptors_to_free(slices);

		if (error != 0) {
		    print_get_assoc_desc_error(disk, gettext("slice"), error);
		} else {
		    for (i = 0; (slices[i] != NULL) && (error == 0); i++) {
			dlist_t *item =
			    dlist_new_item((void *)(uintptr_t)slices[i]);
			if (item == NULL) {
			    error = ENOMEM;
			} else {
			    *list = dlist_append(item, *list, AT_TAIL);
			}
		    }
		    free(slices);
		}
		free(media);
	    }
	} else {
	    print_get_assoc_desc_error(disk, gettext("media"), error);
	}

	return (error);
}

int
get_virtual_slices(
	dlist_t **list)
{
	*list = _virtual_slices;

	return (0);
}

/*
 * FUNCTION:	virtual_repartition_drive(dm_descriptor_t disk,
 *			mdvtoc_t *vtocp)
 *
 * INPUT:	disk	- the disk to be virtually repartitioned
 *
 * OUTPUT:	vtocp	- a poitner to a mdvtoc struct to hold the results
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Helper which emulates the repartitioning that is done
 *		when a disk is added to a diskset.
 *
 *		Modified version of meta_partition_drive which uses info
 * 		from libdiskmgt to accomplish the repartitioning.
 *
 * 		This exists to allow the layout module to run with a
 *		simulated hardware environment.
 *
 *		XXX This method absolutely does not produce the exact
 *		same result as meta_repartition_drive: only information
 *		required by the layout code is returned.  Basically,
 *		a slice 7 (or 6 on EFI labelled disks) is created and
 *		sized, the remained of the available cylinders are put
 *		into slice 0.
 *
 *		XXX2 This method is required until there is resolution
 *		on whether metassist testing will be done using the
 *		hardware simulation mechanism libdiskmgt provides.
 *		Doing so will also require parts of libmeta to be
 *		simulated as well.  Some research has been done into
 *		building an alternate libmeta.so containing
 *		implementations of the functions used by metassist
 *		that are compatible with the simulated hardware.
 *		Actual work is currently on hold.
 */
static int
virtual_repartition_drive(
	dm_descriptor_t	disk,
	mdvtoc_t	*vtocp)
{
	uint_t		replicaslice = 7;
	unsigned long long cylsize;
	unsigned long long drvsize;
	uint_t		reservedcyl;
	ushort_t	resflag;
	unsigned long long ressize;
	diskaddr_t	replica_start;
	diskaddr_t	replica_size;
	diskaddr_t	data_start;
	diskaddr_t	data_size;

	boolean_t	efi = B_FALSE;
	uint64_t	ncyls = 0;
	uint64_t	nheads = 0;
	uint64_t	nsects = 0;
	int		error = 0;

	/*
	 * At this point, ressize is used as a minimum value.  Later it
	 * will be rounded up to a cylinder boundary.  ressize is in
	 * units of disk sectors.
	 */
	ressize = MD_DBSIZE + VTOC_SIZE;
	resflag = V_UNMNT;

	((error = disk_get_is_efi(disk, &efi)) != 0) ||
	(error = disk_get_ncylinders(disk, &ncyls)) ||
	(error = disk_get_nheads(disk, &nheads)) ||
	(error = disk_get_nsectors(disk, &nsects));
	if (error != 0) {
	    return (error);
	}

	if (efi) {
	    replicaslice = 6;
	}

	/*
	 * Both cylsize and drvsize are in units of disk sectors.
	 *
	 * The intended results are of type unsigned long long.  Since
	 * each operand of the first multiplication is of type
	 * unsigned int, we risk overflow by multiplying and then
	 * converting the result.  Therefore we explicitly cast (at
	 * least) one of the operands, forcing conversion BEFORE
	 * multiplication, and avoiding overflow.  The second
	 * assignment is OK, since one of the operands is already of
	 * the desired type.
	 */
	cylsize = ((unsigned long long)nheads) * nsects;
	drvsize = cylsize * ncyls;

	/*
	 * How many cylinders must we reserve for slice seven to
	 * ensure that it meets the previously calculated minimum
	 * size?
	 */
	reservedcyl = (ressize + cylsize - 1) / cylsize;

	/*
	 * It seems unlikely that someone would pass us too small a
	 * disk, but it's still worth checking for...
	 */
	if (reservedcyl >= ncyls) {
	    volume_set_error(
		    gettext("disk is too small to hold a metadb replica"));
	    return (-1);
	}

	replica_start = 0;
	replica_size = reservedcyl * cylsize;
	data_start = reservedcyl * cylsize;
	data_size = drvsize - (reservedcyl * cylsize);

	/*
	 * fill in the proposed VTOC information.
	 */

	/* We need at least replicaslice partitions in the proposed vtoc */
	vtocp->nparts = replicaslice + 1;
	vtocp->parts[MD_SLICE0].start = data_start;
	vtocp->parts[MD_SLICE0].size = data_size;
	vtocp->parts[MD_SLICE0].tag = V_USR;
	vtocp->parts[replicaslice].start = replica_start;
	vtocp->parts[replicaslice].size = replica_size;
	vtocp->parts[replicaslice].flag = resflag;
	vtocp->parts[replicaslice].tag = V_USR;

	return (0);
}

/*
 * FUNCTION:	create_virtual_slices(dlist_t *disks)
 *
 * INPUT:	possibles - a list of dm_descriptor_t disk handles for
 *			disks known to be available for use by layout.
 *
 * SIDEEFFECT:	populates the private of virtual slices.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Helper which creates virtual slices for each disk which
 *		could be added to a diskset if necessary...
 *
 *		Iterate the input list of available disks and see what the
 *		slicing would be if the disk were added to a diskset.
 *
 *		For the resulting slices, create virtual slice descriptors
 *		and attributes for these slices and add them to the list of
 *		available slices.
 */
int
create_virtual_slices(
	dlist_t 	*disks)
{
	int		error = 0;
	dlist_t		*iter;
	boolean_t	sim = B_FALSE;
	static char	*simfile = "METASSISTSIMFILE";

	sim = ((getenv(simfile) != NULL) && (strlen(getenv(simfile)) > 0));

	/* see what slices each of the disks will have when added to a set */
	for (iter = disks; error == 0 && iter != NULL; iter = iter->next) {

	    dm_descriptor_t 	disk = (uintptr_t)iter->obj;
	    dlist_t		*slices = NULL;
	    mdvtoc_t		vtoc;
	    char		*dname;
	    int			i = 0;

	    if ((error = get_display_name(disk, &dname)) != 0) {
		break;
	    }

	    if (sim != B_TRUE) {

		/* sim disabled: use meta_repartition_drive() */

		md_error_t	mderror = mdnullerror;
		int		opts = (MD_REPART_FORCE | MD_REPART_DONT_LABEL);
		mdsetname_t	*sp;
		mddrivename_t	*dnp;

		/* disk is in the local set */
		sp = metasetname(MD_LOCAL_NAME, &mderror);
		if (!mdisok(&mderror)) {
		    volume_set_error(mde_sperror(&mderror, NULL));
		    mdclrerror(&mderror);
		    error = -1;
		    break;
		}

		dnp = metadrivename(&sp, dname, &mderror);
		if (!mdisok(&mderror)) {
		    volume_set_error(mde_sperror(&mderror, NULL));
		    mdclrerror(&mderror);
		    error = -1;
		    break;
		}

		if (meta_repartition_drive(
		    sp, dnp, opts, &vtoc, &mderror) != 0) {
		    volume_set_error(
			    gettext("failed to repartition disk %s\n"),
			    dname);
		    error = -1;
		    break;
		}

	    } else {

		/* sim enabled: use faked repartition code */
		if (virtual_repartition_drive(disk, &vtoc) != 0) {
		    volume_set_error(
			    gettext("failed simulated repartition of %s\n"),
			    dname);
		    error = -1;
		    break;
		}
	    }

	    /* BEGIN CSTYLED */
	    /*
	     * get the existing slices on the disk, if the repartition
	     * was successful, these slices need to have their size, start
	     * blk and size in blks set to 0
	     */
	    /* END CSTYLED */
	    if ((error = disk_get_slices(disk, &slices)) == 0) {
		dlist_t *iter2 = slices;
		for (; iter2 != NULL; iter2 = iter2->next) {
		    dm_descriptor_t sp = (uintptr_t)iter2->obj;
		    ((error = slice_set_start_block(sp, 0)) != 0) ||
		    (error = slice_set_size_in_blocks(sp, 0)) ||
		    (error = slice_set_size(sp, 0));
		}
		dlist_free_items(slices, NULL);
	    }

	    /* scan VTOC, find slice with the free space */
	    for (i = 0; i < vtoc.nparts; i++) {

		if (vtoc.parts[i].tag == V_USR &&
			vtoc.parts[i].flag != V_UNMNT) {

		    /* non-replica slice with free space */
		    char buf[MAXPATHLEN];
		    (void) snprintf(buf, MAXPATHLEN-1, "%ss%d", dname, i);

		    if ((error = add_virtual_slice(buf,
			(uint32_t)i,
			(uint64_t)vtoc.parts[i].start,
			(uint64_t)vtoc.parts[i].size,
			disk)) != 0) {
			break;
		    }

		} else if (vtoc.parts[i].tag == V_RESERVED) {

		    /* skip EFI reserved slice */
		    continue;

		} else if (vtoc.parts[i].tag == V_USR &&
			vtoc.parts[i].flag == V_UNMNT) {

		    /* BEGIN CSTYLED */
		    /*
		     * Make the replica slice 0 sized -- this will
		     * force the disk to be repartitioned by
		     * metaset when it is added to the disk set.
		     *
		     * XXX this is a temporary workaround until
		     * 4712873 is integrated...
		     */
		    /* BEGIN CSTYLED */
		    char buf[MAXPATHLEN];
		    (void) snprintf(buf, MAXPATHLEN-1, "%ss%d", dname, i);
		    add_slice_to_remove(buf, i);

		    /* replica slice, stop here */
		    break;
		}
	    }
	}

	return (error);
}

/*
 * FUNCTION:	add_virtual_slice(char *name, uint32_t index,
 *			uint64_t startblk, uint64_t sizeblks,
 *			dm_descriptor_t disk)
 *
 * INPUT:	name	- the name of the new virtual slice
 *		index	- the VTOC index ...
 *		startblk - the start block ...
 *		sizeblks - the size in blocks ...
 *		disk	- the parent disk ...
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Helper which adds the appropriate data structures to
 *		represent a new virtual slice.
 *
 *		allocates a new descriptor
 *		adds entries to name->desc and desc->name caches
 *		allocates an attribute nvpair list
 *		fills in the relevant attributes for the slice
 *		associates the slice with its parent disk
 *		adds an entry to the list of all virtual slices
 *		generates aliases if the associated disk has aliases.
 */
int
add_virtual_slice(
	char		*name,
	uint32_t	index,
	uint64_t	startblk,
	uint64_t	sizeblks,
	dm_descriptor_t	disk)
{
	dm_descriptor_t sp;
	nvlist_t	*attrs;
	char		*sname;
	dlist_t		*aliases = NULL;
	dlist_t		*item = NULL;
	int 		error = 0;

	if ((error = nvlist_alloc(&attrs, NV_UNIQUE_NAME, 0)) != 0) {
	    return (error);
	}

	/* create descriptor */
	((error = new_descriptor(&sp)) != 0) ||
	/* cache name for the descriptor */
	(error = add_cached_name(sp, name)) ||
	/* cache descriptor for the name */
	(error = add_cached_descriptor(name, sp)) ||

	/* fill in attributes */
	(error = set_string(attrs, ATTR_DEV_CTD_NAME, name)) ||
	(error = set_uint32(attrs, DM_INDEX, index)) ||
	(error = set_uint64(attrs, DM_START, startblk)) ||
	(error = set_uint64(attrs, DM_SIZE, sizeblks)) ||
	(error = set_uint64(attrs, ATTR_DISK_FOR_SLICE, (uint64_t)disk)) ||

	/* add attributes to the cache */
	(error = get_name(sp, &sname)) ||
	(error = add_cached_attributes(sname, attrs)) ||

	/* connect slice to disk */
	(error = disk_add_virtual_slice(disk, sp)) ||
	(error = get_display_name(disk, &name)) ||
	(error = get_aliases(disk, &aliases));

	if (error != 0) {
	    return (error);
	}

	/* generate slice's aliases if the disk has aliases */
	if (aliases != NULL) {
	    char buf[MAXNAMELEN];

	    for (; aliases != NULL; aliases = aliases->next) {
		(void) snprintf(buf, MAXNAMELEN-1, "%ss%d",
			(char *)aliases->obj, index);
		error = set_alias(sp, buf);
	    }
	    dlist_free_items(aliases, free);
	}

	if ((item = dlist_new_item((void *)(uintptr_t)sp)) == NULL) {
	    return (ENOMEM);
	}

	_virtual_slices = dlist_append(item, _virtual_slices, AT_HEAD);

	oprintf(OUTPUT_DEBUG,
		gettext("  created virtual slice %s start: %llu, size: %llu\n"),
		sname, startblk, sizeblks);

	return (error);
}

/*
 * FUNCTION:	release_virtual_slices()
 *
 * PURPOSE:	Helper which cleans up the module private list of virtual
 *		slices.
 *
 *		The descriptors for the virtual slices are cleaned up
 *		in device_cache_util.free_cached_descriptors
 */
void
release_virtual_slices()
{
	dlist_free_items(_virtual_slices, NULL);
	_virtual_slices = NULL;
}

/*
 * FUNCTION:	disk_add_virtual_slice(dm_descriptor_t disk,
 *			dm_descriptor_t slice)
 *
 * INPUT:	disk	- a dm_descriptor_t disk handle
 *		slice	- a dm_descriptor_t virtual slice handle
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Helper which adds a virtual slice to the input disk's
 *		list of virtual slices.
 *
 *		The disk's virtual slice dm_descriptor_t handles are
 *		stored in the disk's nvpair attribute list.
 */
static int
disk_add_virtual_slice(
	dm_descriptor_t	disk,
	dm_descriptor_t slice)
{
	nvlist_t	*attrs = NULL;
	uint64_t	*old_slices = NULL;
	uint64_t	*new_slices = NULL;
	uint_t		nelem = 0;
	int		i = 0;
	int		error = 0;

	if ((error = get_cached_attributes(disk, &attrs)) != 0) {
	    return (error);
	}

	if ((error = get_uint64_array(
	    attrs, ATTR_VIRTUAL_SLICES, &old_slices, &nelem)) != 0) {
	    if (error != ENOENT) {
		return (error);
	    }
	    error = 0;
	}

	/* make a new array */
	new_slices = (uint64_t *)calloc(nelem + 1, sizeof (uint64_t));
	if (new_slices != NULL) {

	    for (i = 0; i < nelem; i++) {
		new_slices[i] = old_slices[i];
	    }
	    new_slices[i] = slice;

	    error = set_uint64_array(
		    attrs, ATTR_VIRTUAL_SLICES, new_slices, nelem);

	    free(new_slices);

	} else {
	    error = ENOMEM;
	}

	return (error);
}

/*
 * FUNCTION:	disk_has_virtual_slices(dm_descriptor_t disk, boolean_t *bool)
 *
 * INPUT:	disk	- a dm_descriptor_t disk handle
 *
 * OUTPUT:	bool	- B_TRUE - if the disk has virtual slices
 *			  B_FALSE - otherwise
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Helper which determines if the input disk has virtual slices.
 *
 *		If a disk has virtual slices, their dm_descriptor_t handles
 *		will be stored in the disk's nvpair attribute list.
 */
static int
disk_has_virtual_slices(
	dm_descriptor_t	disk,
	boolean_t	*bool)
{
	nvlist_t	*attrs = NULL;
	uint64_t	*slices = NULL;
	uint_t		nelem = 0;
	int		error = 0;

	*bool = B_FALSE;

	if ((error = get_cached_attributes(disk, &attrs)) != 0) {
	    return (error);
	}

	if ((error = get_uint64_array(
	    attrs, ATTR_VIRTUAL_SLICES, &slices, &nelem)) != 0) {
	    if (error == ENOENT) {
		error = 0;
		nelem = 0;
	    } else {
		/* count actual number of elements */
		int i = 0;
		while (i < nelem) {
		    if (slices[i] != -1) {
			++i;
		    }
		}
		nelem = i;
	    }
	}

	*bool = (nelem != 0);

	return (error);
}

/*
 * FUNCTION:	disk_get_virtual_slices(dm_descriptor_t disk, boolean_t *bool)
 *
 * INPUT:	disk	- a dm_descriptor_t disk handle
 *
 * OUTPUT:	list	- a dlist_t list of dm_descriptor_t handles for the
 *				disk's virtual slices.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Helper which retrieves a list of the input disk's virtual
 *		slices.
 *
 *		If a disk has virtual slices, their dm_descriptor_t handles
 *		will be stored in the disk's nvpair attribute list.
 */
static int
disk_get_virtual_slices(
	dm_descriptor_t	disk,
	dlist_t		**list)
{
	nvlist_t	*attrs = NULL;
	uint64_t	*slices = NULL;
	uint_t		nelem = 0;
	int		error = 0;
	int		i = 0;

	if ((error = get_cached_attributes(disk, &attrs)) != 0) {
	    return (error);
	}

	if ((error = get_uint64_array(
	    attrs, ATTR_VIRTUAL_SLICES, &slices, &nelem)) != 0) {
	    if (error != ENOENT) {
		return (error);
	    }

	    return (0);
	}

	for (i = 0; i < nelem && slices[i] != -1; i++) {
	    dlist_t *item = NULL;

	    if ((item = dlist_new_item((void*)(uintptr_t)slices[i])) == NULL) {
		error = ENOMEM;
		break;
	    }

	    *list = dlist_append(item, *list, AT_TAIL);
	}

	return (error);
}

/*
 * FUNCTION:	is_virtual_slice(dm_descriptor_t desc)
 *
 * INPUT:	desc	- a dm_descriptor_t handle
 *
 * RETURNS:	boolean_t - B_TRUE if the input descriptor is for
 *				a virtual slice.
 * 			B_FALSE otherwise
 *
 * PURPOSE:	Helper which determines whether the input descriptor
 *		corresponds to a virtual slice.
 *
 *		All virtual slices are stored in a module private list.
 *		This list is iterated to see if it contains the input
 *		descriptor.
 */
boolean_t
is_virtual_slice(
	dm_descriptor_t desc)
{
        return (dlist_contains(_virtual_slices,
			(void*)(uintptr_t)desc, compare_descriptors));
}

/*
 * FUNCTION:	disk_get_available_slice_index(dm_descriptor_t disk,
 *			uint32_t *newindex)
 *
 * INPUT:	disk	- a dm_descriptor_t handle for a disk
 *
 * OUTPUT:	*newindex - a pointer to a uint32_t to hold the available
 *			index.  If no index is available, the value pointed
 *			to is not modified.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	examine the input disk's list of slices and find an unused
 *		slice index.  The replica slice (index 7 or 6) is always
 *		off-limits -- it shows up as in use.  Slice 0 should only
 *		be used as a last resort.
 *
 *		If an available index is found, it is stored into newindex.
 *		Otherwise, newindex is unchanged.  This allows the caller to
 *		pass in an index and check if it has been modified on return.
 *
 *		V_NUMPAR is used as the number of available slices,
 *		SPARC systems have V_NUMPAR == 8, X86 have V_NUMPAR == 16.
 *
 *		EFI disks have only 7.
 */
int
disk_get_available_slice_index(
	dm_descriptor_t	disk,
	uint32_t	*newindex)
{
	dlist_t		*iter	= NULL;
	dlist_t		*slices = NULL;
	uint32_t	index	= 0;
	uint16_t	*reserved = NULL;
	boolean_t 	*used 	= NULL;
	boolean_t 	is_efi	= B_FALSE;
	int		error	= 0;
	int		i	= 0;
	int		nslices = V_NUMPAR;

	if (((error = disk_get_slices(disk, &slices)) != 0) ||
	    (error = disk_get_is_efi(disk, &is_efi)) != 0) {
	    return (error);
	}

	if (is_efi == B_TRUE) {
	    /* limit possible indexes to 7 for EFI */
	    nslices = 7;
	}

	used = (boolean_t *)calloc(nslices, sizeof (boolean_t));
	if (used == NULL) {
	    oprintf(OUTPUT_DEBUG,
		    gettext("failed allocating slice index array\n"),
		    NULL);
	    return (ENOMEM);
	}

	/* eliminate indexes that are reserved */
	if ((error = disk_get_reserved_indexes(disk, &reserved)) != 0) {
	    return (error);
	}

	if (reserved != NULL) {
	    for (i = 0; i < nslices; i++) {
		if (reserved[i] == 1) {
		    used[i] = B_TRUE;
		}
	    }
	}

	/* eliminate slices that are in use (have a size > 0) */
	/* 0 sized slices unused slices */
	for (iter = slices; iter != NULL; iter = iter->next) {
	    dm_descriptor_t sp = (uintptr_t)iter->obj;
	    uint64_t	size = 0;

	    ((error = slice_get_index(sp, &index)) != 0) ||
	    (error = slice_get_size_in_blocks(sp, &size));
	    if (error != 0) {
		return (error);
	    }

	    if (size > 0) {
		used[(int)index] = B_TRUE;
	    }
	}
	dlist_free_items(slices, NULL);

	for (i = 0; i < nslices; i++) {

	    /* skip the index passed in */
	    if (i == *newindex) {
		continue;
	    }

	    if (used[i] != B_TRUE) {
		index = i;
		break;
	    }
	}

	if (i != nslices) {
	    /* return unused slice index */
	    *newindex = index;
	}

	free((void *)used);

	return (0);
}

/*
 * FUNCTION:	disk_get_media_type(dm_descriptor_t slice, uint32_t *type)
 *
 * INPUT:	slice	- a dm_descriptor_t handle for a disk
 *
 * OUTPUT:	*type	- a pointer to a uint32_t to hold the
 *			current type value for the media on which
 *			the input slice resides.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Retrieves the media type for the disk.
 *
 *		Get the media associate with the input disk descriptor
 *		and determine its type.
 */
int
disk_get_media_type(
	dm_descriptor_t	disk,
	uint32_t	*type)
{
	int		error = 0;
	dm_descriptor_t	*mdp = NULL;

	mdp = dm_get_associated_descriptors(disk, DM_MEDIA, &error);
	(void) add_descriptors_to_free(mdp);

	if (error != 0) {
	    print_get_assoc_desc_error(disk, gettext("media"), error);
	} else {
	    /* disk should have exactly 1 media */
	    if ((mdp != NULL) && (*mdp != NULL)) {
		nvlist_t *attrs = dm_get_attributes(*mdp, &error);
		if ((error == 0) && (attrs != NULL)) {
		    error = get_uint32(attrs, DM_MTYPE, type);
		}

		nvlist_free(attrs);
	    }
	    /* no media: removeable drive */
	}

	if (mdp != NULL) {
	    free(mdp);
	}

	return (error);
}

/*
 * FUNCTION:	disk_get_rpm(dm_descriptor_t disk, uint32_t *val)
 *		disk_get_sync_speed(dm_descriptor_t disk, uint32_t *val)
 *		disk_get_size_in_blocks(dm_descriptor_t disk, uint64_t *val)
 *		disk_get_blocksize(dm_descriptor_t disk, uint64_t *val)
 *		disk_get_ncylinders(dm_descriptor_t disk, uint64_t *val)
 *		disk_get_nheads(dm_descriptor_t disk, uint64_t *val)
 *		disk_get_nsectors(dm_descriptor_t disk, uint64_t *val)
 *		disk_get_is_efi(dm_descriptor_t disk, boolean_t *val)
 *		disk_get_is_online(dm_descriptor_t disk, boolean_t *val)
 *		disk_get_media_type(dm_descriptor_t disk, uint32_t *type)
 *		disk_get_has_fdisk(dm_descriptor_t disk, boolean_t *val)
 *		disk_get_start_block(dm_descriptor_t disk, uint64_t *val)
 *
 * INPUT:	disk	- a dm_descriptor_t handle for a disk
 *
 * OUTPUT:	*bool	- a pointer to a variable of the appropriate
 *			type to hold the current value for the attribute
 *			of interest.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Wrappers around disk_get_XXX_attribute that know
 *	        which attribute needs to be retrieved and also handle
 *		any necesasry type or units conversions.
 */
static int
disk_get_rpm(
	dm_descriptor_t	disk,
	uint32_t	*val)
{
	uint64_t	val64 = 0;
	int		error = 0;

	if ((error = disk_get_uint64_attribute(
	    disk, DM_RPM, &val64)) != 0) {
	    return (error);
	}

	*val = (uint32_t)val64;

	return (error);
}

int
disk_get_drive_type(
	dm_descriptor_t	disk,
	uint32_t	*val)
{
	uint64_t	val64 = 0;
	int		error = 0;

	if ((error = disk_get_uint64_attribute(
	    disk, DM_DRVTYPE, &val64)) != 0) {
	    return (error);
	}

	*val = (uint32_t)val64;

	return (error);
}

static int
disk_get_sync_speed(
	dm_descriptor_t	disk,
	uint32_t	*val)
{
	uint64_t	val64 = 0;
	int		error = 0;

	if ((error = disk_get_uint64_attribute(
	    disk, DM_SYNC_SPEED, &val64)) != 0) {
	    return (error);
	}

	*val = (uint32_t)val64;

	return (error);
}

/* returns number of usable blocks */
int
disk_get_size_in_blocks(
	dm_descriptor_t	disk,
	uint64_t	*val)
{
	return (disk_get_uint64_attribute(disk, DM_NACCESSIBLE, val));
}

/* returns first usable block on disk */
int
disk_get_start_block(
	dm_descriptor_t	disk,
	uint64_t	*val)
{
	return (disk_get_uint64_attribute(disk, DM_START, val));
}

int
disk_get_blocksize(
	dm_descriptor_t	disk,
	uint64_t	*val)
{
	return (disk_get_uint64_attribute(disk, DM_BLOCKSIZE, val));
}

int
disk_get_ncylinders(
	dm_descriptor_t	disk,
	uint64_t	*val)
{
	return (disk_get_uint64_attribute(disk, DM_NCYLINDERS, val));
}

int
disk_get_nheads(
	dm_descriptor_t	disk,
	uint64_t	*val)
{
	return (disk_get_uint64_attribute(disk, DM_NHEADS, val));
}

int
disk_get_nsectors(
	dm_descriptor_t	disk,
	uint64_t	*val)
{
	return (disk_get_uint64_attribute(disk, DM_NSECTORS, val));
}

/*
 * FUNCTION:	disk_get_is_online(dm_descriptor_t disk, boolean_t *val)
 *
 * INPUT:	disk	- a dm_descriptor_t handle for a disk
 *
 * OUTPUT:	*bool	- a pointer to a boolean_t to hold the result.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Determine if the input disk is "online".
 *
 *		Check the status bit of the drive, if it is 1 the drive
 *		is online, if it is 0 the drive is offline.
 */
int
disk_get_is_online(
	dm_descriptor_t	disk,
	boolean_t	*val)
{
	uint64_t	status = 0;
	int		error = 0;

	*val = B_FALSE;

	error = disk_get_uint64_attribute(disk, DM_STATUS, &status);
	if (error == 0) {
	    *val = (status == 1) ? B_TRUE : B_FALSE;
	}

	return (error);
}

/*
 * FUNCTION:	disk_get_is_efi(dm_descriptor_t disk, boolean_t *bool)
 *
 * INPUT:	disk	- a dm_descriptor_t handle for a disk
 *
 * OUTPUT:	*bool	- a pointer to a boolean_t to hold the result.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Determine if the input disk is labeled with an EFI label.
 *
 *		The label type is actually a property of the media
 *		associated with the disk, so retrieve the media and
 *		check if it is EFI labeled.
 */
int
disk_get_is_efi(
	dm_descriptor_t	disk,
	boolean_t	*bool)
{
	return (disk_get_boolean_attribute(disk, DM_EFI, bool));
}

/*
 * FUNCTION:	disk_get_has_fdisk(dm_descriptor_t disk, boolean_t *bool)
 *
 * INPUT:	disk	- a dm_descriptor_t handle for a disk
 *
 * OUTPUT:	*bool	- a pointer to a boolean_t to hold the result.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Determine if the input disk has an FDISK partition.
 */
int
disk_get_has_fdisk(
	dm_descriptor_t	disk,
	boolean_t	*bool)
{
	return (disk_get_boolean_attribute(disk, DM_FDISK, bool));
}

/*
 * FUNCTION:	disk_get_has_solaris_partition(dm_descriptor_t disk, boolean_t *bool)
 *
 * INPUT:	disk	- a dm_descriptor_t handle for a disk
 *
 * OUTPUT:	*bool	- a pointer to a boolean_t to hold the result.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Determine if the input disk has a Solaris FDISK partition.
 */
int
disk_get_has_solaris_partition(
	dm_descriptor_t	disk,
	boolean_t	*bool)
{
	boolean_t	has_fdisk = B_FALSE;
	int		error = 0;

	if ((error = disk_get_has_fdisk(disk, &has_fdisk)) != 0) {
	    return (error);
	}

	*bool = B_FALSE;

	if (has_fdisk == B_TRUE) {
	    /* get disk's media */
	    dm_descriptor_t *media;
	    media = dm_get_associated_descriptors(disk, DM_MEDIA, &error);
	    (void) add_descriptors_to_free(media);
	    if (error != 0) {
		print_get_assoc_desc_error(disk, gettext("media"), error);
	    } else if ((media != NULL) && (*media != NULL)) {
		/* get media's partitions */
		dm_descriptor_t *parts;
		parts = dm_get_associated_descriptors(
			media[0], DM_PARTITION, &error);
		(void) add_descriptors_to_free(parts);
		if (error != 0) {
		    print_get_assoc_desc_error(media[0],
			    gettext("partitions"), error);
		} else {
		    /* search partitions for one with type Solaris */
		    int i = 0;
		    for (; (parts != NULL) && (parts[i] != NULL) &&
			(error == 0) && (*bool == B_FALSE); i++) {
			nvlist_t *attrs = dm_get_attributes(parts[i], &error);
			uint32_t ptype = 0;
			if ((error == 0) && (attrs != NULL)) {
			    error = get_uint32(attrs, DM_PTYPE, &ptype);
			    if ((error == 0) &&
			        (ptype == SUNIXOS || ptype == SUNIXOS2)) {
				    *bool = B_TRUE;
			    }
			}
			nvlist_free(attrs);
		    }
		}
		   
		free(parts);
		free(media);
	    }

	    /* if there was no media, it was a removeable drive */
	}

	return (error);
}

static int
disk_get_boolean_attribute(
	dm_descriptor_t	disk,
	char		*attr,
	boolean_t	*bool)
{
	nvlist_t	*attrs	= NULL;
	int		error	= 0;

	*bool = B_FALSE;

	if ((strcmp(attr, DM_EFI) == 0) ||
	    (strcmp(attr, DM_FDISK) == 0)) {

	    /*
	     * these attributes are actually on the media,
	     * not the disk... so get the media descriptor
	     * for this disk
	     */
	    dm_descriptor_t *media;

	    media = dm_get_associated_descriptors(disk, DM_MEDIA, &error);
	    (void) add_descriptors_to_free(media);

	    if (error != 0) {
		print_get_assoc_desc_error(disk, gettext("media"), error);
	    } else if ((media != NULL) && (*media != NULL)) {
		/* if there's no media, it is a removeable drive */
		error = get_cached_attributes(media[0], &attrs);
	    }
	    free(media);

	} else {
	    error = get_cached_attributes(disk, &attrs);
	    if (error != 0) {
		print_get_desc_attr_error(disk, gettext("drive"), attr, error);
	    }
	}

	if (error != 0) {
	    return (error);
	}

	if (nvlist_lookup_boolean(attrs, attr) == 0) {
	    *bool = B_TRUE;
	}

	return (error);
}

static int
disk_get_uint64_attribute(
	dm_descriptor_t	disk,
	char		*attr,
	uint64_t	*val)
{
	nvlist_t	*attrs	= NULL;
	uint32_t	ui32	= 0;
	int		error	= 0;

	/*
	 * these attributes are actually on the media,
	 * not the disk... so get the media descriptor
	 * for this disk
	 */
	if ((strcmp(attr, DM_SIZE) == 0) ||
	    (strcmp(attr, DM_START) == 0) ||
	    (strcmp(attr, DM_NACCESSIBLE) == 0) ||
	    (strcmp(attr, DM_BLOCKSIZE) == 0) ||
	    (strcmp(attr, DM_NCYLINDERS) == 0) ||
	    (strcmp(attr, DM_NHEADS) == 0) ||
	    (strcmp(attr, DM_NSECTORS) == 0)) {

	    dm_descriptor_t *media;

	    media = dm_get_associated_descriptors(disk, DM_MEDIA, &error);
	    (void) add_descriptors_to_free(media);

	    if (error != 0) {
		print_get_assoc_desc_error(disk, gettext("media"), error);
	    } else if ((media == NULL) || (*media == NULL)) {
		print_get_assoc_desc_error(disk, gettext("media"), error);
		error = -1;
	    } else {
		error = get_cached_attributes(media[0], &attrs);
		free(media);
	    }

	} else {
	    error = get_cached_attributes(disk, &attrs);
	    if (error != 0) {
		print_get_desc_attr_error(disk, gettext("drive"), attr, error);
	    }
	}

	if (error != 0) {
	    return (error);
	}

	if (strcmp(attr, DM_SIZE) == 0 ||
	    strcmp(attr, DM_NACCESSIBLE) == 0 ||
	    strcmp(attr, DM_START) == 0) {
	    error = get_uint64(attrs, attr, val);
	} else if (strcmp(attr, DM_BLOCKSIZE) == 0 ||
	    strcmp(attr, DM_NCYLINDERS) == 0 ||
	    strcmp(attr, DM_NHEADS) == 0 ||
	    strcmp(attr, DM_NSECTORS) == 0 ||
	    strcmp(attr, DM_RPM) == 0 ||
	    strcmp(attr, DM_DRVTYPE) == 0 ||
	    strcmp(attr, DM_SYNC_SPEED) == 0 ||
	    strcmp(attr, DM_STATUS) == 0) {
	    error = get_uint32(attrs, attr, &ui32);
	    *val = (uint64_t)ui32;
	}

	return (error);
}

/*
 * FUNCTION:	group_similar_hbas(dlist_t *hbas, dlist_t **list)
 *
 * INPUT:	hbas	- a list of HBA dm_descriptor_t handles.
 *
 * OUTPUT:	**list	- a pointer to a list to hold the lists of HBAs
 *			grouped by characteristics.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Examine the input HBAs and collate them into separate
 *		lists, grouped by their type and the protocols they
 *		support.
 *
 *		The returned list of list is arranged in decreasing order
 *		of preference, "better" HBAs come first.
 *
 *		find all MPXIO controllers
 *		find all similar FC HBAs
 *		find all similar SCSI HBAs
 *		    fast{wide}80
 *		    fast{wide}40
 *		    fast{wide}20
 *		    clock         uint32  ??
 *		find all similar ATA/IDE HBAs
 *		find all similar USB HBAs
 */
int
group_similar_hbas(
	dlist_t	*hbas,
	dlist_t **list)
{
	/* preference order of HBAs */
	enum {
		HBA_FIBRE_MPXIO = 0,
		HBA_SCSI_MPXIO,
		HBA_FIBRE,
		HBA_SCSI_FW80,
		HBA_SCSI_FW40,
		HBA_SCSI_FW20,
		HBA_SCSI_F80,
		HBA_SCSI_F40,
		HBA_SCSI_F20,
		HBA_SCSI,
		HBA_ATA,
		HBA_USB,
		HBA_LAST
	};

	dlist_t		*groups	= NULL;
	dlist_t		*iter = NULL;
	dlist_t		*item = NULL;
	dlist_t		*lists[HBA_LAST];

	int		error = 0;
	int		i = 0;

	(void) memset(lists, '\0', HBA_LAST * sizeof (dlist_t *));

	for (iter = hbas;
	    (iter != NULL) && (error == 0);
	    iter = iter->next) {

	    dm_descriptor_t hba = (uintptr_t)iter->obj;
	    char	*type = NULL;

	    /* if item doesn't go into a list it must be freed */
	    if ((item = dlist_new_item((void *)(uintptr_t)hba)) == NULL) {
		error = ENOMEM;
		continue;
	    }

	    if ((error = hba_get_type(hba, &type)) != 0) {
		free(item);
		continue;
	    }

	    if (strcmp(type, DM_CTYPE_FIBRE) == 0) {

		boolean_t	ismpxio = B_FALSE;

		if ((error = hba_is_multiplex(hba, &ismpxio)) == 0) {
		    if (ismpxio) {
			lists[HBA_FIBRE_MPXIO] =
			    dlist_append(item,
				    lists[HBA_FIBRE_MPXIO], AT_TAIL);
		    } else {
			lists[HBA_FIBRE] =
			    dlist_append(item,
				    lists[HBA_FIBRE], AT_TAIL);
		    }
		} else {
		    free(item);
		}

	    } else if (strcmp(type, DM_CTYPE_SCSI) == 0) {

		/* determine subtype */
		boolean_t	iswide = B_FALSE;
		boolean_t	ismpxio = B_FALSE;
		boolean_t	is80 = B_FALSE;
		boolean_t	is40 = B_FALSE;
		boolean_t	is20 = B_FALSE;

		((error = hba_supports_wide(hba, &iswide)) != 0) ||
		(error = hba_is_multiplex(hba, &ismpxio)) ||
		(error = hba_is_fast_80(hba, &is80)) ||
		(error = hba_is_fast_40(hba, &is40)) ||
		(error = hba_is_fast_20(hba, &is20));

		if (error == 0) {

		    if (ismpxio) {

			lists[HBA_SCSI_MPXIO] =
			    dlist_append(item,
				    lists[HBA_SCSI_MPXIO], AT_TAIL);

		    } else if (is80) {

			if (iswide) {
			    lists[HBA_SCSI_FW80] =
				dlist_append(item,
					lists[HBA_SCSI_FW80], AT_TAIL);
			} else {
			    lists[HBA_SCSI_F80] =
				dlist_append(item,
					lists[HBA_SCSI_F80], AT_TAIL);
			}

		    } else if (is40) {

			if (iswide) {
			    lists[HBA_SCSI_FW40] =
				dlist_append(item,
					lists[HBA_SCSI_FW40], AT_TAIL);
			} else {
			    lists[HBA_SCSI_F40] =
				dlist_append(item,
					lists[HBA_SCSI_F40], AT_TAIL);
			}

		    } else if (is20) {

			if (iswide) {
			    lists[HBA_SCSI_FW20] =
				dlist_append(item,
					lists[HBA_SCSI_FW20], AT_TAIL);
			} else {
			    lists[HBA_SCSI_F20] =
				dlist_append(item,
					lists[HBA_SCSI_F20], AT_TAIL);
			}

		    } else {
			lists[HBA_SCSI] =
			    dlist_append(item, lists[HBA_SCSI], AT_TAIL);
		    }

		} else {
		    free(item);
		}

	    } else if (strcmp(type, DM_CTYPE_ATA) == 0) {
		lists[HBA_ATA] =
		    dlist_append(item, lists[HBA_ATA], AT_TAIL);
	    } else if (strcmp(type, DM_CTYPE_USB) == 0) {
		lists[HBA_USB] =
		    dlist_append(item, lists[HBA_USB], AT_TAIL);
	    } else if (strcmp(type, DM_CTYPE_UNKNOWN) == 0) {
		oprintf(OUTPUT_DEBUG,
			gettext("found an HBA with unknown type\n"));
		free(item);
	    }
	}

	if (error == 0) {
	    /* collect individual lists into a list of lists */
	    for (i = 0; (i < HBA_LAST) && (error == 0); i++) {
		if (lists[i] != NULL) {
		    if ((item = dlist_new_item(lists[i])) == NULL) {
			error = ENOMEM;
		    } else {
			groups = dlist_append(item, groups, AT_TAIL);
		    }
		}
	    }
	}

	if (error != 0) {
	    for (i = 0; i < HBA_LAST; i++) {
		dlist_free_items(lists[i], NULL);
		lists[i] = NULL;
	    }

	    if (groups != NULL) {
		dlist_free_items(groups, NULL);
	    }
	}

	*list = groups;

	return (error);
}

/*
 * FUNCTION:	hba_group_usable_disks(dm_descriptor_t hba, dlist_t **list)
 *
 * INPUT:	hba	- a dm_descriptor_t handle for a slice
 *
 * OUTPUT:	**list	- a pointer to a list to hold the lists of disks
 *			grouped by characteristics.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Examine the disks assocated with the HBA and collates them
 *		into separate lists, grouped by similar characteristics.
 *
 *		get disks on HBA
 *		check disks against _usable_disks list
 *		group disks by similarities:
 *			sync-speed    uint32
 *			wide          boolean
 *			rpm           uint32
 *
 *		XXX this function is currently unused.  At some point,
 *		it may be useful to group disks by performance
 *		characteristics and use "better" disks before others.
 */
int
hba_group_usable_disks(
	dm_descriptor_t	hba,
	dlist_t		**list)
{
	dm_descriptor_t *disk = NULL;
	char 		*name = NULL;
	int		i = 0;
	int		error = 0;

	disk = dm_get_associated_descriptors(hba, DM_DRIVE, &error);
	(void) add_descriptors_to_free(disk);

	if (error != 0) {
	    print_get_assoc_desc_error(hba, gettext("drive"), error);
	    return (error);
	} else if ((disk == NULL) || (*disk == NULL)) {
	    print_get_assoc_desc_error(hba, gettext("drive"), error);
	    error = -1;
	}

	for (i = 0; (disk[i] != NULL) && (error == 0); i++) {

	    uint32_t dtype = DM_DT_UNKNOWN;
	    dlist_t *usable = NULL;

	    /* ignore non fixed media drives */
	    if (((error = disk_get_drive_type(disk[i], &dtype)) != 0) ||
		(dtype != DM_DT_FIXED)) {
		continue;
	    }

	    if (dlist_contains(usable, &disk[i],
		compare_descriptor_names) == B_TRUE) {

		uint64_t bsize	= 0;
		uint64_t ncyls	= 0;
		uint64_t nsects	= 0;
		uint64_t nheads	= 0;
		uint32_t rpm	= 0;
		uint32_t sync	= 0;

		name = NULL;
		((error = get_display_name(disk[i], &name)) != 0) ||
		(error = disk_get_blocksize(disk[i], &bsize)) ||
		(error = disk_get_nheads(disk[i], &nheads)) ||
		(error = disk_get_nsectors(disk[i], &nsects)) ||
		(error = disk_get_ncylinders(disk[i], &ncyls)) ||
		(error = disk_get_rpm(disk[i], &rpm)) ||
		(error = disk_get_sync_speed(disk[i], &sync));
		if (error != 0) {
		    continue;
		}

		oprintf(OUTPUT_VERBOSE,
			gettext("found an available disk: %s\n\t"
			"sync_speed = %u, rpm = %u, "
			"nsect = %llu, blksiz = %llu\n"),
			name, sync, rpm, nsects, bsize);

		/* add to the appropriate list */
	    }
	}

	if (disk != NULL) {
	    free(disk);
	}

	return (error);
}

/*
 * FUNCTION:	hba_get_n_avail_disks(dm_descriptor_t hba, uint16_t *val)
 *		hba_set_n_avail_disks(dm_descriptor_t hba, uint16_t val)
 *
 * INPUT:	hba	- a dm_descriptor_t handle for a slice
 *
 * OUTPUT:	*val	- a pointer to a uint16_t to hold the current number
 *				of available disks for the input HBA.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 */
int
hba_set_n_avail_disks(
	dm_descriptor_t	hba,
	uint16_t	val)
{
	nvlist_t	*attrs;
	int		error = 0;

	((error = get_cached_attributes(hba, &attrs)) != 0) ||
	(error = set_uint16(attrs, ATTR_HBA_N_DISKS, val));

	return (error);
}

int
hba_get_n_avail_disks(
	dm_descriptor_t	hba,
	uint16_t	*val)
{
	nvlist_t	*attrs;
	int		error = 0;

	*val = 0;

	((error = get_cached_attributes(hba, &attrs)) != 0) ||
	(error = get_uint16(attrs, ATTR_HBA_N_DISKS, val));

	return (error);
}

/*
 * FUNCTION:	hba_get_type(dm_descriptor_t hba, char **type)
 *
 * INPUT:	hba	- a dm_descriptor_t handle for a HBA
 *
 * OUTPUT:	**type	- a char * to hold the current type value for
 *			the HBA.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Retrieves the type attribute for the HBA.
 */
int
hba_get_type(
	dm_descriptor_t	hba,
	char		**type)
{
	nvlist_t	*attrs;
	int		error = 0;

	*type = NULL;

	((error = get_cached_attributes(hba, &attrs)) != 0) ||
	(error = get_string(attrs, DM_CTYPE, type));

	return (error);
}

/*
 * FUNCTION:	hba_is_fast(dm_descriptor_t hba, boolean_t *bool)
 *		hba_is_fast20(dm_descriptor_t hba, boolean_t *bool)
 *		hba_is_fast40(dm_descriptor_t hba, boolean_t *bool)
 *		hba_is_fast80(dm_descriptor_t hba, boolean_t *bool)
 *		hba_is_multiplex(dm_descriptor_t hba, boolean_t *bool)
 *		hba_is_wide(dm_descriptor_t hba, boolean_t *bool)
 *
 * INPUT:	hba	- a dm_descriptor_t handle for a HBA
 *
 * OUTPUT:	*bool	- a pointer to a boolean_t to hold the
 *			boolean value of the predicate.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Wrappers around hba_supports_protocol which determines
 *		if the input HBA supports the protocol of interest.
 */
int
hba_is_fast(
	dm_descriptor_t	hba,
	boolean_t	*bool)
{
	return (hba_supports_protocol(hba, DM_FAST, bool));
}

int
hba_is_fast_20(
	dm_descriptor_t	hba,
	boolean_t	*bool)
{
	return (hba_supports_protocol(hba, DM_FAST20, bool));
}

int
hba_is_fast_40(
	dm_descriptor_t	hba,
	boolean_t	*bool)
{
	return (hba_supports_protocol(hba, DM_FAST40, bool));
}

int
hba_is_fast_80(
	dm_descriptor_t	hba,
	boolean_t	*bool)
{
	return (hba_supports_protocol(hba, DM_FAST80, bool));
}

int
hba_is_multiplex(
	dm_descriptor_t	hba,
	boolean_t	*bool)
{
	return (hba_supports_protocol(hba, DM_MULTIPLEX, bool));
}

int
hba_supports_wide(
	dm_descriptor_t	hba,
	boolean_t	*bool)
{
	nvlist_t	*attrs	= NULL;
	int		error	= 0;

	*bool = B_FALSE;

	if ((error = get_cached_attributes(hba, &attrs)) != 0) {
	    return (error);
	}

	*bool = (0 == nvlist_lookup_boolean(attrs, DM_WIDE));

	return (error);
}

/*
 * FUNCTION:	hba_supports_protocol(dm_descriptor_t hba, char *attr,
 *			boolean_t *bool)
 *
 * INPUT:	hba	- a dm_descriptor_t handle for a HBA
 *		attr	- a protocol "name"
 *
 * OUTPUT:	*bool	- a pointer to a boolean_t to hold the
 *			boolean value of the predicate.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Checks the HBAs attributes to see if it is known to
 *		support the protocol of interest.
 *
 *		If the protocol is supported, it will have an entry
 *		in the nvpair attribute list that can be retrieved.
 *
 *		If the entry cannot be retrieved, the protocol is not
 *		supported.
 */
int
hba_supports_protocol(
	dm_descriptor_t	hba,
	char		*attr,
	boolean_t	*bool)
{
	nvlist_t	*attrs	= NULL;
	int		error	= 0;

	*bool = B_FALSE;

	if ((error = get_cached_attributes(hba, &attrs)) != 0) {
	    return (error);
	}

	*bool = (0 == nvlist_lookup_boolean(attrs, attr));

	return (error);
}

/*
 * FUNCTION:	slice_set_size(dm_descriptor_t slice, uint64_t size)
 *
 * INPUT:	slice	- a dm_descriptor_t handle for a slice
 *
 * OUTPUT:	size	- a uint64_t value representing the size of the
 *			slice.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Wrapper around slice_set_uint64_attribute which converts
 *		the input size in bytes to blocks prior to storing it.
 *
 *		This function is used when an existing slice gets resized
 *		to provide space for a new slice. It is necessary to update
 *		the slice's size so that it is accurate.
 */
int
slice_set_size(
	dm_descriptor_t	slice,
	uint64_t	size)
{
	dm_descriptor_t	disk	= NULL;
	uint64_t	blksize	= 0;
	int		error	= 0;

	((error = slice_get_disk(slice, &disk)) != 0) ||
	(error = disk_get_blocksize(disk, &blksize)) ||
	(error = slice_set_size_in_blocks(slice, (uint64_t)(size / blksize)));

	return (error);
}

/*
 * FUNCTION:	slice_set_size_in_blocks(dm_descriptor_t slice, uint64_t size)
 *
 * INPUT:	slice	- a dm_descriptor_t handle for a slice
 *
 * OUTPUT:	size	- a uint64_t value representing the size of the
 *			slice.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Wrapper around slice_set_uint64_attribute to set the slice
 *		size.
 *
 *		This function is used when an existing slice gets resized
 *		to provide space for a new slice. It is necessary to update
 *		the slice's size so that it is accurate.
 */
int
slice_set_size_in_blocks(
	dm_descriptor_t	slice,
	uint64_t	size)
{
	return (slice_set_attribute(slice, DM_SIZE, size));
}

/*
 * FUNCTION:	slice_set_start_block(dm_descriptor_t slice, uint64_t start)
 *
 * INPUT:	slice	- a dm_descriptor_t handle for a slice
 *
 * OUTPUT:	size	- a uint64_t value representing the start block of the
 *			slice.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Wrapper around slice_set_attribute.
 *
 *		This function is used when an existing slice gets adjusted
 *		due to being resized or combined with another slice.
 */
int
slice_set_start_block(
	dm_descriptor_t	slice,
	uint64_t	start)
{
	return (slice_set_attribute(slice, DM_START, start));
}

/*
 * FUNCTION:	slice_get_start_block(dm_descriptor_t slice, uint64_t *val)
 *		slice_get_size_in_blocks(dm_descriptor_t slice, uint64_t *val)
 *		slice_get_start(dm_descriptor_t slice, uint64_t *val)
 *		slice_get_size(dm_descriptor_t slice, uint64_t *val)
 *		slice_get_index(dm_descriptor_t slice, uint64_t *val)
 *
 * INPUT:	slice	- a dm_descriptor_t handle for a slice
 *
 * OUTPUT:	*val	- a pointer to a uint64_t to hold the
 *			current value of the desired attribute.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Wrappers around slice_get_uint64_attribute which retrieve
 *		specific attribute values.
 */
int
slice_get_start_block(
	dm_descriptor_t	slice,
	uint64_t	*val)
{
	return (slice_get_uint64_attribute(slice, DM_START, val));
}

int
slice_get_size_in_blocks(
	dm_descriptor_t	slice,
	uint64_t	*val)
{
	return (slice_get_uint64_attribute(slice, DM_SIZE, val));
}

int
slice_get_start(
	dm_descriptor_t	slice,
	uint64_t	*val)
{
	dm_descriptor_t	disk	= NULL;
	uint64_t	blksize	= 0;
	uint64_t	nblks	= 0;
	int		error	= 0;

	((error = slice_get_disk(slice, &disk)) != 0) ||
	(error = disk_get_blocksize(disk, &blksize)) ||
	(error = slice_get_start_block(slice, &nblks));

	if (error == 0) {
	    *val = (blksize * nblks);
	}

	return (error);
}

int
slice_get_size(
	dm_descriptor_t	slice,
	uint64_t	*val)
{
	dm_descriptor_t	disk	= NULL;
	uint64_t	blksize	= 0;
	uint64_t	nblks	= 0;
	int		error	= 0;

	*val = 0;

	((error = slice_get_disk(slice, &disk)) != 0) ||
	(error = slice_get_size_in_blocks(slice, &nblks)) ||
	(error = disk_get_blocksize(disk, &blksize));

	if (error == 0) {
	    *val = (blksize * nblks);
	}

	return (error);
}

int
slice_get_index(
	dm_descriptor_t	slice,
	uint32_t	*val)
{
	uint64_t	index = 0;
	int		error = 0;

	if ((error = slice_get_uint64_attribute(
	    slice, DM_INDEX, &index)) != 0) {
	    return (error);
	}

	*val = (uint32_t)index;

	return (0);
}

/*
 * FUNCTION:	slice_set_uint64_attribute(dm_descriptor_t slice,
 *			char *attr, uint64_t val)
 * 		slice_get_uint64_attribute(dm_descriptor_t slice,
 *			char *attr, uint64_t *val)
 *
 * INPUT:	slice	- a dm_descriptor_t handle for a slice
 *		attr    - a char * attribute name
 *		val	- auint64_t value
 *
 * OUTPUT:	*val	- a pointer to a uint64_t to hold the
 *			current value of the named attribute.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Helpers to set/get the value for a slice's attribute.
 *
 *		Consolidate the details of getting/setting slice
 *		attributes.  Some attributes are actually stored as
 *		uint32_t or uint16_t values, these functions mask
 *		the type conversions.
 */
static int
slice_get_uint64_attribute(
	dm_descriptor_t	slice,
	char		*attr,
	uint64_t	*val)
{
	nvlist_t	*attrs	= NULL;
	uint32_t	ui32	= 0;
	int		error	= 0;

	if ((error = get_cached_attributes(slice, &attrs)) != 0) {
	    return (error);
	}

	if (strcmp(attr, DM_INDEX) == 0) {
	    error = get_uint32(attrs, attr, &ui32);
	    *val = (uint64_t)ui32;
	} else if (strcmp(attr, DM_START) == 0) {
	    error = get_uint64(attrs, attr, val);
	} else if (strcmp(attr, DM_SIZE) == 0) {
	    error = get_uint64(attrs, attr, val);
	} else if (strcmp(attr, ATTR_DISK_FOR_SLICE) == 0) {
	    error = get_uint64(attrs, attr, val);
	}

	if (error != 0) {
	    print_get_desc_attr_error(slice, "slice", attr, error);
	}

	return (error);
}

/*
 * Set a slice attribute.  The attribute is only set in the cached
 * copy of the slice's nvpair attribute list.  This function does
 * NOT affect the underlying physical device.
 */
static int
slice_set_attribute(
	dm_descriptor_t	slice,
	char		*attr,
	uint64_t	val)
{
	nvlist_t	*attrs = NULL;
	int		error = 0;

	if ((error = get_cached_attributes(slice, &attrs)) != 0) {
	    return (error);
	}

	if (strcmp(attr, DM_INDEX) == 0) {
	    error = set_uint32(attrs, attr, (uint32_t)val);
	} else if (strcmp(attr, DM_START) == 0) {
	    error = set_uint64(attrs, attr, val);
	} else if (strcmp(attr, DM_SIZE) == 0) {
	    error = set_uint64(attrs, attr, val);
	} else if (strcmp(attr, ATTR_DISK_FOR_SLICE) == 0) {
	    error = set_uint64(attrs, attr, val);
	}

	if (error != 0) {
	    print_set_desc_attr_error(slice, "slice", attr, error);
	}

	return (error);
}

/*
 * FUNCTION:	virtual_slice_get_disk(dm_descriptor_t slice,
 *			dm_descriptor_t *diskp)
 *
 * INPUT:	slice	- a dm_descriptor_t virtual slice handle
 *		diskp	- pointer to a dm_descriptor_t disk handle
 *				to return the slice's disk
 *
 * OUTPUT:	the disk associated with the virtual slice.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Helper which determines the disk that the input virtual
 *		slice "belongs" to.
 *
 *		The virtual slice's disk is stored in the slice's nvpair
 *		attribute list when the slice gets created.
 */
static int
virtual_slice_get_disk(
	dm_descriptor_t	slice,
	dm_descriptor_t	*diskp)
{
	uint64_t disk = 0;
	int	error = 0;

	if ((error = slice_get_uint64_attribute(
	    slice, ATTR_DISK_FOR_SLICE, &disk)) != 0) {
	    return (error);
	}

	*diskp = (dm_descriptor_t)disk;

	if (disk == 0) {
	    print_get_desc_attr_error(slice, "virtual slice", "disk", error);
	    return (-1);
	}

	return (0);
}

/*
 * FUNCTION:	slice_get_disk(dm_descriptor_t disk, dm_descriptor_t *diskp)
 *
 * INPUT:	slice	- a dm_descriptor_t handle for a slice
 *
 * OUTPUT:	diskp	- a pointer to a dm_descriptor_t to hold the
 *			disk associated with the input slice
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Helper which retrieves the disk for a slice device.
 *
 *		A slice is actually connected to its disk thru an intermediate
 *		device known as the "media". The media concept exists to
 *		model drives with removeable disk media. For the purposes
 *		of layout, such devices aren't relevant and the intermediate
 *		media can mostly be ignored.
 */
int
slice_get_disk(
	dm_descriptor_t	slice,
	dm_descriptor_t *diskp)
{
	dm_descriptor_t	*media = NULL;

	int	i = 0;
	int	error = 0;

	*diskp = 0;

	if (is_virtual_slice(slice)) {
	    return (virtual_slice_get_disk(slice, diskp));
	}

	media = dm_get_associated_descriptors(slice, DM_MEDIA, &error);
	(void) add_descriptors_to_free(media);

	if (error != 0) {
	    print_get_assoc_desc_error(slice, gettext("media"), error);
	} else if ((media == NULL) || (*media == NULL)) {
	    print_get_assoc_desc_error(slice, gettext("media"), error);
	    error = -1;
	}

	if (error != 0) {
	    return (error);
	}

	/* slice should have exactly 1 media */
	for (i = 0; (media[i] != NULL) && (*diskp == NULL); i++) {
	    /* get disk from media */
	    dm_descriptor_t *disks = NULL;
	    disks = dm_get_associated_descriptors(media[i], DM_DRIVE, &error);
	    (void) add_descriptors_to_free(disks);

	    if ((error == 0) && (disks != NULL) && (disks[0] != NULL)) {
		*diskp = disks[0];
	    }
	    free(disks);
	}

	if (media != NULL) {
	    free(media);
	}

	if (*diskp == 0) {
	    print_get_desc_attr_error(slice,
		    gettext("slice"), gettext("disk"), ENODEV);
	    error = -1;
	}

	return (error);
}

/*
 * FUNCTION:	slice_get_hbas(dm_descriptor_t slice, dlist_t **list)
 *
 * INPUT:	slice	- a dm_descriptor_t handle for a slice
 *
 * OUTPUT:	list	- a pointer to a dlist_t list to hold the
 *			HBAs associated with the input slice
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Helper which retrieves the known HBAs for a slice device.
 *
 */
int
slice_get_hbas(
	dm_descriptor_t	slice,
	dlist_t		**list)
{
	dm_descriptor_t	disk	= NULL;
	int		error	= 0;

	*list = NULL;

	((error = slice_get_disk(slice, &disk)) != 0) ||
	(error = disk_get_hbas(disk, list));

	if (*list == NULL) {
	    print_get_desc_attr_error(slice, "slice", "HBA", ENODEV);
	    error = -1;
	}

	return (error);
}

/*
 * FUNCTION:	disk_get_associated_desc(dm_descriptor_t disk,
 *			dm_desc_type_t assoc_type, char *assoc_type_str,
 *			dlist_t **list)
 *
 * INPUT:	disk	- a dm_descriptor_t handle for a disk
 *		assoc_type - the type of associated object to get
 *		assoc_type_str - a char * string for the associated type
 *
 * OUTPUT:	list	- a pointer to a dlist_t list to hold the
 *			objects associated with the input disk
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Helper which retrieves the associated objects of the
 *		requested type for a disk device.
 */
static int
disk_get_associated_desc(
	dm_descriptor_t	disk,
	dm_desc_type_t 	assoc_type,
	char		*assoc_type_str,
	dlist_t		**list)
{
	int	i = 0;
	int	error = 0;

	dm_descriptor_t	*assoc =
	    dm_get_associated_descriptors(disk, assoc_type, &error);

	(void) add_descriptors_to_free(assoc);

	if (error == 0) {
	    for (i = 0;
		(assoc != NULL) && (assoc[i] != NULL) && (error == 0);
		i++) {
		dlist_t *item = dlist_new_item((void *)(uintptr_t)assoc[i]);
		if (item == NULL) {
		    error = ENOMEM;
		} else {
		    *list = dlist_append(item, *list, AT_TAIL);
		}
	    }
	} else {
	    print_get_assoc_desc_error(disk, assoc_type_str, error);
	}

	if (assoc != NULL) {
	    free(assoc);
	}

	if (error != 0) {
	    dlist_free_items(*list, NULL);
	    *list = NULL;
	}

	return (error);
}

/*
 * FUNCTION:	disk_get_hbas(dm_descriptor_t disk, dlist_t **list)
 *
 * INPUT:	disk	- a dm_descriptor_t handle for a disk
 *
 * OUTPUT:	list	- a pointer to a dlist_t list to hold the
 *			HBAs associated with the input disk
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Helper which retrieves the known HBAs for a disk device.
 *
 */
int
disk_get_hbas(
	dm_descriptor_t	disk,
	dlist_t		**list)
{
	return (disk_get_associated_desc(disk, DM_CONTROLLER,
			gettext("controller"), list));
}

/*
 * FUNCTION:	disk_get_paths(dm_descriptor_t disk, dlist_t **list)
 *
 * INPUT:	disk	- a dm_descriptor_t handle for a disk
 *
 * OUTPUT:	list	- a pointer to a dlist_t list to hold the
 *			paths associated with the input disk
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Helper which retrieves the known paths for a disk device.
 *
 *		Paths are managed by the MPXIO driver, they represent hardware
 *		paths to the disk drive managed by the MPXIO and not visible
 *		externally, unlike aliases which are.
 */
int
disk_get_paths(
	dm_descriptor_t	disk,
	dlist_t		**list)
{
	return (disk_get_associated_desc(disk, DM_PATH,
			gettext("path"), list));
}

/*
 * FUNCTION:	disk_get_aliases(dm_descriptor_t disk, dlist_t **list)
 *
 * INPUT:	disk	- a dm_descriptor_t handle for a disk
 *
 * OUTPUT:	list	- a pointer to a dlist_t list to hold the
 *			alias descriptors associated with the input disk
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Helper which retrieves the known aliases for a disk device.
 *
 *		Aliases are the different CTD names for the disk drive when
 *		MPXIO is not enabled for multipathed drives.
 */
int
disk_get_aliases(
	dm_descriptor_t	disk,
	dlist_t		**list)
{
	return (disk_get_associated_desc(disk, DM_ALIAS,
			gettext("alias"), list));
}

/*
 * FUNCTION:	compare_string_to_desc_name_or_alias(
 *			void *str, void *desc)
 *
 * INPUT:	str	- opaque pointer
 * 		descr	- opaque pointer
 *
 * RETURNS:	int	- <0 - if str < desc.name
 *			   0 - if str == desc.name
 *			  >0 - if str > desc.name
 *
 * PURPOSE:	dlist_t helper which compares a string to the name
 *		and aliases associated with the input dm_descriptor_t
 *		handle.
 *
 *		Comparison is done via compare_device_names.
 */
static int
compare_string_to_desc_name_or_alias(
	void	*str,
	void	*desc)
{
	char	*dname = NULL;
	int	result = -1;

	assert(str != (char *)NULL);
	assert(desc != (dm_descriptor_t)0);

	(void) get_display_name((uintptr_t)desc, &dname);

	/* try name first, then aliases */
	if ((result = compare_device_names(str, dname)) != 0) {
	    dlist_t *aliases = NULL;

	    (void) get_aliases((uintptr_t)desc, &aliases);
	    if ((aliases != NULL) && (dlist_contains(aliases,
			str, compare_device_names) == B_TRUE)) {
		result = 0;
	    }
	    dlist_free_items(aliases, free);
	}

	return (result);
}

/*
 * FUNCTION:	hba_get_by_name(char *name, dm_descriptor_t *hba)
 *
 * INPUT:	name	- a char * disk name
 *
 * OUTPUT:	hba	- a pointer to a dm_descriptor_t to hold the
 *			HBA corresponding to the input name, if found
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Helper which iterates the known HBAs, searching for
 *		the one matching name.
 *
 *		If no HBA matches the name, 0 is returned and the
 *		value of 'hba' will be (dm_descriptor_t)0;
 */
int
hba_get_by_name(
	char		*name,
	dm_descriptor_t *hba)
{
	int		error = 0;
	dlist_t		*list = NULL;
	dlist_t		*item = NULL;

	*hba = (dm_descriptor_t)0;

	if (name == NULL) {
	    return (0);
	}

	if ((error = get_known_hbas(&list)) != 0) {
	    return (error);
	}

	if ((item = dlist_find(list, name,
	    compare_string_to_desc_name_or_alias)) != NULL) {
	    *hba = (uintptr_t)item->obj;
	}

	return (error);
}

/*
 * FUNCTION:	disk_get_by_name(char *name, dm_descriptor_t *disk)
 *
 * INPUT:	name	- a char * disk name
 *
 * OUTPUT:	disk	- a pointer to a dm_descriptor_t to hold the
 *			disk corresponding to the input name, if found
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Helper which retrieves a dm_descriptor_t disk handle
 *		by name.
 *
 *		If no disk is found for the input name, variations of
 *		the name are tried.
 *
 *		If the input name is unqualified, an appropriate leading
 *		path is prepended.
 *
 *		If the input name is qualified, the leading path is
 *		removed.
 *
 *		If no disk is found for the variations, 0 is returned
 *		and the	value of 'disk' will be (dm_descriptor_t)0;
 */
int
disk_get_by_name(
	char		*name,
	dm_descriptor_t *disk)
{
	assert(name != (char *)NULL);

	*disk = find_cached_descriptor(name);
	if (*disk == (dm_descriptor_t)0) {
	    if (name[0] == '/') {
		/* fully qualified, try unqualified */
		char *cp = strrchr(name, '/');
		if (cp != NULL) {
		    *disk = find_cached_descriptor(cp + 1);
		}
	    } else {
		/* unqualified, try fully qualified */
		char buf[MAXNAMELEN+1];
		if (is_ctd_disk_name(name)) {
		    (void) snprintf(buf, MAXNAMELEN, "/dev/dsk/%s", name);
		} else if (is_did_disk_name(name)) {
		    (void) snprintf(buf, MAXNAMELEN, "/dev/did/dsk/%s", name);
		}
		*disk = find_cached_descriptor(buf);
	    }
	}

	/*
	 * since the descriptor cache includes HBAs, disks and slices,
	 * what gets returned may not be a disk... make sure it is
	 */
	if (*disk != (dm_descriptor_t)0) {
	    if (dm_get_type(*disk) != DM_DRIVE) {
		*disk = (dm_descriptor_t)0;
	    }
	}

	return (0);
}

/*
 * FUNCTION:	slice_get_by_name(char *name, dm_descriptor_t *slice)
 *
 * INPUT:	name	- a char * slice name
 *
 * OUTPUT:	slice	- a pointer to a dm_descriptor_t to hold the
 *			slice corresponding to the input name, if found.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Helper which iterates the known slices, searching for
 *		the one matching name.
 *
 *		If no slice is found for the input name, variations of
 *		the name are tried.
 *
 *		If the input name is unqualified, an appropriate leading
 *		path is prepended.
 *
 *		If the input name is qualified, the leading path is
 *		removed.
 *
 *		If no slice matches the variations, 0 is returned and the
 *		value of 'slice' will be (dm_descriptor_t)0;
 */
int
slice_get_by_name(
	char		*name,
	dm_descriptor_t *slice)
{
	assert(name != (char *)NULL);

	*slice = find_cached_descriptor(name);
	if (*slice == (dm_descriptor_t)0) {
	    if (name[0] == '/') {
		/* fully qualified, try unqualified */
		char *cp = strrchr(name, '/');
		if (cp != NULL) {
		    *slice = find_cached_descriptor(cp + 1);
		}
	    } else {
		/* unqualified, try fully qualified */
		char buf[MAXNAMELEN+1];
		if (is_ctd_slice_name(name) || is_ctd_like_slice_name(name) ||
			is_bsd_like_slice_name(name)) {
		    (void) snprintf(buf, MAXNAMELEN, "/dev/dsk/%s", name);
		} else if (is_did_slice_name(name)) {
		    (void) snprintf(buf, MAXNAMELEN, "/dev/did/dsk/%s", name);
		}
		*slice = find_cached_descriptor(buf);
	    }
	}

	/*
	 * since the descriptor cache includes HBAs, disks and slices,
	 * what gets returned may not be a slice... make sure it is
	 */
	if (*slice != (dm_descriptor_t)0) {
	    if (dm_get_type(*slice) != DM_SLICE &&
		is_virtual_slice(*slice) != B_TRUE) {
		*slice = (dm_descriptor_t)0;
	    }
	}

	return (0);
}

/*
 * FUNCTION:	extract_hbaname(char *name, char **hbaname)
 *
 * INPUT:	slicename - a char * device name
 *
 * OUTPUT:	hbaname - a pointer to a char * to hold the hbaname derived
 *			from the input name.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Helper which extracts the HBA name from the input name.
 *
 *		If the input name is in ctd form, extracts just the cX part,
 *		by truncating everything following the last 't'.
 *
 *		Of course on X86, with IDE drives, there is no 't' in the
 *		ctd name, so start by truncating everything following 'd'
 *		and then look for 't'.
 *
 * 		The returned string must be passed to free().
 */
int
extract_hbaname(
	char	*name,
	char	**hbaname)
{
	char	*cp;

	if (is_ctd_name(name)) {
	    if ((*hbaname = strdup(name)) == NULL) {
		return (ENOMEM);
	    }
	    if ((cp = strrchr(*hbaname, 'd')) != NULL) {
		*cp = '\0';
	    }
	    if ((cp = strrchr(*hbaname, 't')) != NULL) {
		*cp = '\0';
	    }
	}

	return (0);
}

/*
 * FUNCTION:	extract_diskname(char *slicename, char **diskname)
 *
 * INPUT:	slicename - a char * slice name
 *
 * OUTPUT:	diskname - a pointer to a char * to hold the diskname derived
 *			from the input slicename.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Helper which extracts the disk's name from a slice name.
 *
 *		Checks to see if the input slicename is in ctd or did form,
 *		and if so, truncates everything following the last 's'.
 *
 *		If the input slicename is BSD-like, truncate the last
 *		character (a-h).
 *
 * 		The returned string must be passed to free().
 */
int
extract_diskname(
	char	*slicename,
	char	**diskname)
{
	char	*cp;

	if (is_ctd_slice_name(slicename) || is_did_slice_name(slicename) ||
	    is_ctd_like_slice_name(slicename)) {

	    if ((*diskname = strdup(slicename)) == NULL) {
		return (ENOMEM);
	    }
	    if ((cp = strrchr(*diskname, 's')) != NULL) {
		*cp = '\0';
	    }

	} else if (is_bsd_like_slice_name(slicename)) {

	    if ((*diskname = strdup(slicename)) == NULL) {
		return (ENOMEM);
	    }
	    (*diskname)[strlen((*diskname)-1)] = '\0';

	}

	return (0);
}

/*
 * FUNCTION:	get_disk_for_named_slice(char *slicename,
 *			dm_descriptor_t disk)
 *
 * INPUT:	slicename - a char * slice name
 *
 * OUTPUT:	disk	- a pointer to a dm_descriptor_t to hold the
 *			disk corresponding to the input name, if found
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Helper which locates the disk dm_descriptor_t handle for
 *		the input slice name.
 *
 *		If no disk matches the name, 0 is returned and the
 *		value of 'disk' will be (dm_descriptor_t)0;
 */
int
get_disk_for_named_slice(
	char		*slicename,
	dm_descriptor_t *disk)
{
	dm_descriptor_t slice = (dm_descriptor_t)0;
	int		error = 0;

	assert(slicename != NULL);

	/* find disk for slice */
	if ((error = slice_get_by_name(slicename, &slice)) == 0) {

	    if (slice != (dm_descriptor_t)0) {
		error = slice_get_disk(slice, disk);
	    } else {
		/* named slice was created by layout: */
		/* need to find disk by name */
		char *dname;

		error = extract_diskname(slicename, &dname);
		if (error == 0) {
		    error = disk_get_by_name(dname, disk);
		}
		free(dname);
	    }
	}

	assert(*disk != (dm_descriptor_t)0);

	return (error);
}

/*
 * FUNCTION:	disk_get_reserved_indexes(dm_descriptor_t disk,
 *			uint16_t **array)
 *
 * INPUT:	disk	- a dm_descriptor_t disk handle
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Retrieves the input disk's list of reserved slice indices.
 *
 *		The list of reserved indices is stored as an array in
 *		the disk's nvpair attribute list.
 */
static int
disk_get_reserved_indexes(
	dm_descriptor_t	disk,
	uint16_t	**array)
{
	nvlist_t	*attrs = NULL;
	uint_t		nelem = 0;
	int		error = 0;

	if ((error = get_cached_attributes(disk, &attrs)) != 0) {
	    return (error);
	}

	if ((error = get_uint16_array(
	    attrs, ATTR_RESERVED_INDEX, array, &nelem)) != 0) {
	    if (error == ENOENT) {
		/* no reserved indices yet */
		error = 0;
	    }
	}

	return (error);
}

/*
 * FUNCTION:	disk_reserve_index(dm_descriptor_t disk, uint16_t index)
 *
 * INPUT:	disk	- a disk dm_descirptor_t handle
 *		undex	- a VTOC slice index
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Reserves the input VTOC slice index for the input disk.
 *
 *		The list of reserved indices is stored as an array in
 *		the disk's nvpair attribute list.
 */
int
disk_reserve_index(
	dm_descriptor_t	disk,
	uint16_t	index)
{
	nvlist_t	*attrs = NULL;
	uint16_t	*oldindexes = NULL;
	uint16_t	*newindexes = NULL;
	uint_t		nelem = 0;
	int		error = 0;
	int		i = 0;

	if ((error = get_cached_attributes(disk, &attrs)) != 0) {
	    return (error);
	}

	if ((error = get_uint16_array(
	    attrs, ATTR_RESERVED_INDEX, &oldindexes, &nelem)) != 0) {
	    if (error != ENOENT) {
		return (error);
	    }
	    /* no reserved indices yet */
	    error = 0;
	}

	/* add new index */
	newindexes = (uint16_t *)calloc(VTOC_SIZE, sizeof (uint16_t));
	if (newindexes != NULL) {
	    for (i = 0; i < nelem; i++) {
		newindexes[i] = oldindexes[i];
	    }
	    newindexes[(int)index] = 1;

	    error = set_uint16_array(attrs, ATTR_RESERVED_INDEX,
		    newindexes, VTOC_SIZE);

	    free(newindexes);
	} else {
	    error = ENOMEM;
	}
	return (error);
}

/*
 * FUNCTION:	disk_release_index(dm_descriptor_t disk, uint16_t index)
 *
 * INPUT:	disk	- a disk dm_descirptor_t handle
 *		undex	- a VTOC slice index
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Releases the input VTOC slice index for the input disk.
 *		The index was previously reserved by disk_reserve_index()
 */
int
disk_release_index(
	dm_descriptor_t	disk,
	uint16_t	index)
{
	nvlist_t	*attrs = NULL;
	uint16_t	*oldindexes = NULL;
	uint16_t	*newindexes = NULL;
	uint_t		nelem = 0;
	int		error = 0;
	int		i = 0;

	if ((error = get_cached_attributes(disk, &attrs)) != 0) {
	    return (error);
	}

	if ((error = get_uint16_array(
	    attrs, ATTR_RESERVED_INDEX, &oldindexes, &nelem)) != 0) {
	    if (error != ENOENT) {
		return (error);
	    }
	    error = 0;
	}

	newindexes = (uint16_t *)calloc(VTOC_SIZE, sizeof (uint16_t));
	if (newindexes != NULL) {
	    for (i = 0; i < nelem; i++) {
		newindexes[i] = oldindexes[i];
	    }

	    /* release index */
	    newindexes[(int)index] = 0;

	    error = set_uint16_array(attrs, ATTR_RESERVED_INDEX,
		    newindexes, VTOC_SIZE);

	    free(newindexes);
	} else {
	    error = ENOMEM;
	}

	return (error);
}

/*
 * FUNCTION:	print_get_assoc_desc_error(dm_descriptor_t desc, char *which,
 *			int error)
 *
 * INPUT:	desc	- a dm_descriptor_t handle
 *		which	- a char * indicating which association
 *		error	- an integer error value
 *
 * PURPOSE:	Utility function to print an error message for a failed
 *		call to dm_get_associated_descriptors().
 *
 *		Extracts the device's CTD name and formats an error message.
 */
void
print_get_assoc_desc_error(
	dm_descriptor_t desc,
	char		*which,
	int		error)
{
	char *name = "";

	(void) get_display_name(desc, &name);
	oprintf(OUTPUT_TERSE,
		gettext("dm_get_associated_descriptors(%s) for "
			"'%s' failed: %d\n"),
		which, name, error);

	volume_set_error(
		gettext("Unexpected error getting associated "
			"descriptors for '%s'"),
			name);
}

/*
 * FUNCTION:	print_get_desc_attr_error(dm_descriptor_t desc,
 *			char *devtype, char *attr, int error)
 *
 * INPUT:	desc	- a dm_descriptor_t handle
 *		devtype	- a char * device type that's being accessed
 *		attr	- a char * attribute name
 *		error	- an integer error value
 *
 * PURPOSE:	Shared utility function to print an error message for a failed
 *		call to retrieve an attribute for a descriptor.
 *
 *		Extracts the device's CTD name and formats an error message.
 */
void
print_get_desc_attr_error(
	dm_descriptor_t desc,
	char		*devtype,
	char		*attr,
	int		error)
{
	char *name = "";

	(void) get_display_name(desc, &name);
	oprintf(OUTPUT_TERSE,
		gettext("'%s' get attribute (%s.%s) error: %d\n"),
		name, devtype, attr, error);

	volume_set_error(
		gettext("Unexpected error getting attribute '%s.%s' for '%s'"),
			devtype, attr, name);
}

/*
 * FUNCTION:	print_set_desc_attr_error(dm_descriptor_t desc,
 *			char *devtype, char *attr, int error)
 *
 * INPUT:	desc	- a dm_descriptor_t handle
 *		devtype	- a char * device type that's being accessed
 *		attr	- a char * attribute name
 *		error	- an integer error value
 *
 * PURPOSE:	Shared utility function to print an error message for a failed
 *		call to set an attribute for a descriptor.
 *
 *		Extracts the device's CTD name and formats an error message.
 */
void
print_set_desc_attr_error(
	dm_descriptor_t desc,
	char		*devtype,
	char		*attr,
	int		error)
{
	char *name = "";

	(void) get_display_name(desc, &name);
	oprintf(OUTPUT_TERSE,
		gettext("'%s' set attribute (%s.%s) error: %d\n"),
		name, devtype, attr, error);

	volume_set_error(
		gettext("Unexpected error setting attribute '%s.%s' for '%s'"),
			devtype, attr, name);
}
