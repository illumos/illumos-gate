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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _LAYOUT_DLIST_UTIL_H
#define	_LAYOUT_DLIST_UTIL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * A collection of utility functions for manipulating and traversing
 * dlist_t linked lists.
 */

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
 *		Comparison is done with string_compare()
 */
extern int compare_strings(void *str1, void *str2);

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
 *		Uses string_compare() to compare the names.
 */
extern int compare_device_names(void *str1, void *str2);

/*
 * FUNCTION:	compare_devconfig_sizes(void *devconf1, void *devconf2)
 *
 * INPUT:	devconf1	- opaque pointer
 * 		devconf2	- opaque pointer
 *
 * RETURNS:	int	- <0 - if devconf1.size_in_blks < devconf2.size_in_blks
 *			   0 - if devconf1.size_in_blks == devconf2.size_in_blks
 *			  >0 - if devconf1.size_in_blks > devconf2.size_in_blks
 *
 * PURPOSE:	dlist_t helper which compares the sizes of two devconfig_t
 *		structs.
 *
 *		Both input objects are assumed to be devconfig_t pointers.
 */
extern int compare_devconfig_sizes(void *devconf1, void *devconf2);

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
extern int compare_slice_sizes(void *obj1, void *obj2);

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
extern int compare_descriptors(void *desc1, void *desc2);

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
 *		and compares them using string_compare.
 */
extern int compare_descriptor_names(void *desc1, void *desc2);

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
extern int compare_devconfig_and_descriptor_names(void *devconf, void *desc);

/*
 * FUNCTION:	compare_string_to_devconfig_name(void *str, void *devconf)
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
extern int compare_string_to_devconfig_name(void *str, void *devconf);

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
extern int compare_slices_on_same_hba(void *slice1, void *slice2);

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
extern void free_devconfig_object(void *obj);

#ifdef __cplusplus
}
#endif

#endif /* _LAYOUT_DLIST_UTIL_H */
