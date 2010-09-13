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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#define	_LAYOUT_DLIST_UTIL_C

#include <assert.h>
#include <string.h>

#include <libintl.h>
#include <libdiskmgt.h>

#include "volume_devconfig.h"
#include "volume_dlist.h"
#include "volume_output.h"

#include "layout_device_cache.h"
#include "layout_dlist_util.h"
#include "layout_request.h"

#include "layout_slice.h"  /* destroy_new_slice */
#include "layout_svm_util.h"

/*
 * FUNCTION:	compare_strings(void *str1, void *str2)
 *
 * INPUT:	str1	- opaque pointer to a char *
 * 		str2	- opaque pointer to a char *
 *
 * RETURNS:	int	- <0 - if str1 < str2
 *			   0 - if str1 == str2
 *			  >0 - if str1 > str2
 *
 * PURPOSE:	dlist_t helper which compares the two input strings.
 *
 *		Comparison is done with string_case_compare()
 */
int
compare_strings(
	void	*str1,
	void	*str2)
{
	assert(str1 != NULL);
	assert(str2 != NULL);

	return (string_case_compare((char *)str1, (char *)str2));
}

/*
 * FUNCTION:	compare_devconfig_sizes(void *devconf1, void *devconf2)
 *
 * INPUT:	devconf1	- opaque pointer
 * 		devconf2	- opaque pointer
 *
 * RETURNS:	int	- <0 - if devconf1.size_in_blks < devconf2.size_in_blks
 *			   0 - if devconf1.size_in_blks == devconf2.size_in_blks
 *			  >0 - if devconf1.size.in_blks > devconf2.size_in_blks
 *
 * PURPOSE:	dlist_t helper which compares the sizes of two devconfig_t
 *		structs.
 *
 *		Both input objects are assumed to be devconfig_t pointers.
 */
int
compare_devconfig_sizes(
	void		*devconf1,
	void		*devconf2)
{
	uint64_t	size1 = 0;
	uint64_t	size2 = 0;

	assert(devconf1 != NULL);
	assert(devconf2 != NULL);

	(void) devconfig_get_size_in_blocks((devconfig_t *)devconf1, &size1);
	(void) devconfig_get_size_in_blocks((devconfig_t *)devconf2, &size2);

	return (size1 - size2);
}

/*
 * FUNCTION:	compare_slice_sizes(void *desc1, void *desc2)
 *
 * INPUT:	desc1	- opaque pointer to a dm_descriptor_t slice handle
 * 		desc2	- opaque pointer to a dm_descriptor_t slice handle
 *
 * RETURNS:	int	- <0 - if desc1.slicesize < desc2.slicesize
 *			   0 - if desc1.slicesize == desc2.slicesize
 *			  >0 - if desc1.slicesize > desc2.slicesize
 *
 * PURPOSE:	dlist_t helper which compares the sizes of two slices
 *		represented as dm_descriptor_t handles.
 */
int
compare_slice_sizes(
	void		*desc1,
	void		*desc2)
{
	uint64_t	size1 = 0;
	uint64_t	size2 = 0;

	assert(desc1 != NULL);
	assert(desc2 != NULL);

	(void) slice_get_size((uintptr_t)desc1, &size1);
	(void) slice_get_size((uintptr_t)desc2, &size2);

	return (size1 - size2);
}

/*
 * FUNCTION:	compare_devconfig_and_descriptor_names(void *devconf,
 *			void *desc)
 *
 * INPUT:	devconf	- opaque pointer to a devconfig_t
 * 		desc	- opaque pointer to a dm_descriptor_t
 *
 * RETURNS:	int	- <0 - if devconf name is "less than" descr name
 *			   0 - if devconf name is "equal to" descr name
 *			  >0 - if devconf name is "greater than" desc name
 *
 * PURPOSE:	dlist_t helper which compares the name of a devconfig_t
 *		struct to the name for a dm_descriptor_t.
 *
 *		Note that the order of the arguments is important.
 *		This function is intended to be passed into the various
 *		dlist_* functions which take a comparison function.
 */
int
compare_devconfig_and_descriptor_names(
	void	*devconf,
	void	*desc)
{
	char	*volname = NULL;
	char	*descname = NULL;

	assert(devconf != NULL);
	assert(desc != NULL);

	(void) devconfig_get_name((devconfig_t *)devconf, &volname);
	(void) get_display_name((uintptr_t)desc, &descname);

	return (string_case_compare(volname, descname));
}

/*
 * FUNCTION:	compare_string_to_devconfig_name(void *str, void *devconf)
 *
 * INPUT:	str	- opaque pointer to a char *str
 *		devconf	- opaque pointer to a devconfig_t
 *
 * RETURNS:	int	- <0 - if devconf name is "less than" str
 *			   0 - if devconf name is "equal to" str
 *			  >0 - if devconf name is "greater than" str
 *
 * PURPOSE:	dlist_t helper which compares a string to the name of
 *		a devconfig_t struct.
 */
int
compare_string_to_devconfig_name(
	void	*str,
	void	*devconf)
{
	char	*volname = NULL;

	assert(str != NULL);
	assert(devconf != NULL);

	(void) devconfig_get_name((devconfig_t *)devconf, &volname);
	if (volname == NULL) {
	    /* no memory for new string(s) */
	    return (-1);
	}

	return (string_case_compare(volname, (char *)str));
}

/*
 * FUNCTION:	free_devconfig_object(void *obj)
 *
 * INPUT:	obj	- an opaque pointer
 *
 * RETURNS:	void
 *
 * PURPOSE:	helper which decomposes a devconfig_t struct after a
 *		failed layout attempt.
 *
 *		reclaims allocated space.
 *		releases reserved volume/HSP names
 *		undoes slicing
 */
void
free_devconfig_object(
	void		*obj)
{
	devconfig_t	*dev = NULL;
	char		*name = NULL;
	dlist_t		*iter = NULL;
	component_type_t	type = TYPE_UNKNOWN;

	if (obj == NULL) {
	    return;
	}

	dev = (devconfig_t *)obj;

	(void) devconfig_get_type(dev, &type);
	(void) devconfig_get_name(dev, &name);

	oprintf(OUTPUT_DEBUG,
		gettext("  -->decomposing %s\n"), name);

	switch (type) {
	case TYPE_MIRROR:
	case TYPE_CONCAT:
	case TYPE_RAID5:
	case TYPE_HSP:
	case TYPE_STRIPE:

	    /* release name */
	    if (devconfig_isA(dev, TYPE_HSP)) {
		release_hsp_name(name);
	    } else {
		release_volume_name(name);
	    }

	    /* decompose volume's components */
	    iter = devconfig_get_components(dev);
	    dlist_free_items(iter, free_devconfig_object);

	    (void) devconfig_set_components(dev, NULL);

	    break;

	case TYPE_SLICE:

	    (void) destroy_new_slice(dev);

	    break;

	default:
	    break;

	}

	free_devconfig(dev);
}

/*
 * FUNCTION:	compare_device_names(
 *			void *str1, void *str2)
 *
 * INPUT:	str1	- opaque pointer
 * 		str2	- opaque pointer
 *
 * RETURNS:	int	- <0 - if str1 < str2
 *			   0 - if str1 == str2
 *			  >0 - if str1 > str2
 *
 * PURPOSE:	dlist_t helper which compares two device name strings.
 *
 *		Both names are assumed to be in CTD form.
 *
 *		Either name may be fully qualified by an absolute
 *		path.  If only one name is fully qualified, the
 *		leading path with be stripped off prior to the
 *		comparison.
 *
 *		Uses string_case_compare() to compare the names.
 */
int
compare_device_names(
	void	*str1,
	void	*str2)
{
	char 	*name1 = (char *)str1;
	char	*name2 = (char *)str2;

	int	val = 0;

	assert(str1 != NULL);
	assert(str2 != NULL);

	/* if one doesn't start with '/', just compare device names */
	if (*name1 != '/' || *name2 != '/') {

	    char *short1 = strrchr(name1, '/');
	    char *short2 = strrchr(name2, '/');

	    if (short1 == NULL) {
		short1 = name1;
	    } else {
		++short1;
	    }

	    if (short2 == NULL) {
		short2 = name2;
	    } else {
		++short2;
	    }

	    val = string_case_compare(short2, short1);

	} else {

	    /* if they both start with '/', assume they're full paths */
	    val = string_case_compare(name2, name1);
	}

	return (val);
}

/*
 * FUNCTION:	compare_descriptors(
 *			void *desc1, void *desc2)
 *
 * INPUT:	desc1	- opaque pointer
 * 		desc2	- opaque pointer
 *
 * RETURNS:	int	- <0 - if desc1 < desc2
 *			   0 - if desc1 == desc2
 *			  >0 - if desc1 > desc2
 *
 * PURPOSE:	dlist_t helper which compares two dm_descriptor_t handles.
 */
int
compare_descriptors(
	void	*desc1,
	void	*desc2)
{
	assert(desc1 != NULL);
	assert(desc2 != NULL);

	return ((uintptr_t)desc1 - (uintptr_t)desc2);
}

/*
 * FUNCTION:	compare_descriptor_names(
 *			void *desc1, void *desc2)
 *
 * INPUT:	desc1	- opaque pointer
 * 		desc2	- opaque pointer
 *
 * RETURNS:	int	- <0 - if desc1.name < desc2.name
 *			   0 - if desc1.name == desc2.name
 *			  >0 - if desc1.name > desc2.name
 *
 * PURPOSE:	dlist_t helper which compares the names associated
 *		with the input dm_descriptor_t handles.
 *
 *		Retrieves the names associated with both descriptors
 *		and compares them using string_case_compare.
 */
int
compare_descriptor_names(
	void	*desc1,
	void	*desc2)
{
	char	*name1 = NULL;
	char	*name2 = NULL;

	assert(desc1 != NULL);
	assert(desc2 != NULL);

	(void) get_name((uintptr_t)desc1, &name1);
	(void) get_name((uintptr_t)desc2, &name2);

	return (string_case_compare(name1, name2));
}

/*
 * FUNCTION:	compare_slices_on_same_hba(
 *			void *slice1, void *slice2)
 *
 * INPUT:	slice1	- opaque pointer
 * 		slice2	- opaque pointer
 *
 * RETURNS:	int -  0 - if slice1 is on the same hba as slice2
 *		      !0 - otherwise
 *
 * PURPOSE:	dlist_t helper which checks whether slice1 is on the
 *		same hba as slice2
 */
int
compare_slices_on_same_hba(
	void	*slice1,
	void	*slice2)
{
	char *name1, *name2;

	/* Retrieve the names of the slices */
	if (devconfig_get_name((devconfig_t *)slice1, &name1) == 0 &&
	    devconfig_get_name((devconfig_t *)slice2, &name2) == 0) {

	    dm_descriptor_t desc1, desc2;

	    /* Retrieve the disk descriptors for the slices */
	    if (get_disk_for_named_slice(name1, &desc1) == 0 &&
		get_disk_for_named_slice(name2, &desc2) == 0) {

		dlist_t *hbas1 = NULL;
		dlist_t *hbas2 = NULL;

		assert(desc1 != (dm_descriptor_t)0);
		assert(desc2 != (dm_descriptor_t)0);

		/* Retrieve list of HBA descriptors for the slices */
		if (disk_get_hbas(desc1, &hbas1) == 0 &&
		    disk_get_hbas(desc2, &hbas2) == 0) {

		    dlist_t *itr1;

		    for (itr1 = hbas1; itr1 != NULL; itr1 = itr1->next) {
			dm_descriptor_t hba1 = (uintptr_t)itr1->obj;
			dlist_t *itr2;

			for (itr2 = hbas2; itr2 != NULL; itr2 = itr2->next) {
			    dm_descriptor_t hba2 = (uintptr_t)itr2->obj;

			    if (hba1 == hba2) {
				return (0);
			    }
			}
		    }
		}
	    }
	}

	return (1);
}
