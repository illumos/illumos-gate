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

#include <libintl.h>

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
#include "layout_svm_util.h"

#define	_LAYOUT_HSP_C

static int layout_explicit_hsp(
	devconfig_t 	*hsprequest,
	dlist_t		*devices,
	devconfig_t 	**hsp);

static int layout_default_hsp(
	devconfig_t 	*request,
	dlist_t		*devices,
	devconfig_t 	**hsp);

static int populate_hsp(
	devconfig_t	*request,
	devconfig_t	*hsp,
	dlist_t		*devices);

static int assemble_hsp(
	devconfig_t 	*hsp,
	dlist_t		*newspares,
	dlist_t		*devices);

static int get_uniquely_sized_slices(
	dlist_t 	*devices,
	dlist_t 	**unique);

static int remove_undersized_slices(
	dlist_t 	*unique,
	dlist_t 	**avail);

static int find_spare_for_component(
	devconfig_t 	*component,
	dlist_t		*all_spares,
	dlist_t		*hbas,
	dlist_t		*disks,
	boolean_t 	*found);

static int choose_spare_for_component(
	devconfig_t 	*comp,
	dlist_t 	**all_spares,
	dlist_t 	**new_spares,
	dlist_t 	**avail,
	dlist_t 	*used_hbas,
	dlist_t 	*used_disks,
	uint16_t	npaths);

/*
 * FUNCTION:	layout_hsp(devconfig_t *request, devconfig_t hsprequest,
 *			dlist_t *devices, dlist_t **results)
 *
 * INPUT:	request	- pointer to the toplevel request devconfig_t
 *		hsp	- pointer to the optional HSP request devconfig_t
 *		devices - pointer to a list of devices to be served by the HSP
 *
 * OUTPUT:	results - pointer to a list result devconfig_t, if the HSP
 *			to service the input list of devices needs to be
 *			created or modified, it will be appended to the list.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Main layout driver for HSP, attempts to build/populate a
 *		single HSP to service the list of devices.
 *
 *		If the input hsprequest is NULL, use the default HSP scheme:
 *		a. use the first HSP in the diskset
 *		b. create an HSP if the diskset has none
 *
 *		If the hsprequest is not NULL:
 *		a. if the request names an HSP and it already exists, use it
 *		b. if the request names an HSP and it does not exist, create it
 *		c. if the request specifies components, use them
 */
int
layout_hsp(
	devconfig_t	*request,
	devconfig_t	*hsprequest,
	dlist_t		*devices,
	dlist_t		**results)
{
	int		error = 0;
	devconfig_t  	*hsp = NULL;

	oprintf(OUTPUT_TERSE,
		gettext("  ->Layout a %s\n"),
		devconfig_type_to_str(TYPE_HSP));

	if (hsprequest == NULL) {
	    error = layout_default_hsp(request, devices, &hsp);
	} else {
	    error = layout_explicit_hsp(hsprequest, devices, &hsp);
	}

	if (error != 0) {
	    print_debug_failure_msg(devconfig_type_to_str(TYPE_HSP),
		    get_error_string(error));
	} else if (hsp != NULL) {

	    if (devconfig_get_components(hsp) == NULL) {
		/* HSP is usable as it is */
		free_devconfig(hsp);
		hsp = NULL;
	    } else {
		dlist_t *item = NULL;
		if ((item = dlist_new_item(hsp)) == NULL) {
		    error = ENOMEM;
		} else {
		    *results = dlist_append(item, *results, AT_TAIL);
		    print_layout_success_msg();
		}
	    }
	}

	return (error);
}

/*
 * FUNCTION:	layout_default_hsp(devconfig_t *request,
 *			dlist_t *devices, devconfig_t **hsp)
 *
 * INPUT:	request	- pointer to the toplevel request devconfig_t
 *		devices - pointer to a list of devices to be served by the HSP
 *
 * OUTPUT:	hsp	- pointer to a devconfig_t to hold the resulting HSP
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Layout driver for default HSP construction.
 *
 *		a. use the first HSP in the diskset
 *		b. create an HSP if the diskset has none
 *		c. add spares to the HSP to service the list of input devices.
 */
static int
layout_default_hsp(
	devconfig_t 	*request,
	dlist_t		*devices,
	devconfig_t 	**hsp)
{
	char		*dsname = get_request_diskset();
	char		*hspname = NULL;
	boolean_t	free_hspname = B_FALSE;
	devconfig_t	*default_hsp = NULL;
	int		error = 0;

	oprintf(OUTPUT_TERSE,
		gettext("  -->Using default HSP scheme...\n"));

	if ((error = get_default_hsp_name(request, &hspname)) != 0) {
	    volume_set_error(
		    gettext("error getting HSP name from defaults\n"));
	    return (error);
	}

	if (hspname != NULL) {
	    if ((error = hsp_get_by_name(dsname, hspname, &default_hsp)) != 0) {
		volume_set_error(
			gettext("error getting default HSP by name\n"));
		return (error);
	    }
	} else {
	    /* no default HSP name, get diskset's default HSP */
	    if ((error = hsp_get_default_for_diskset(dsname,
		&default_hsp)) != 0) {
		volume_set_error(
			gettext("error getting default HSP\n"));
		return (error);
	    }

	    if (default_hsp == NULL) {
		/* no default HSP name, no default HSP, make one */
		if ((error = get_next_hsp_name(&hspname)) != 0) {
		    volume_set_error(
			    gettext("error making default HSP name\n"));
		    return (error);
		}
		free_hspname = B_TRUE;
	    }
	}

	if (default_hsp != NULL) {

	    /* Found existing default HSP, copy it */
	    dlist_t *spares = devconfig_get_components(default_hsp);

	    ((error = devconfig_get_name(default_hsp, &hspname)) != 0) ||
	    (error = new_devconfig(hsp, TYPE_HSP)) ||
	    (error = devconfig_set_name(*hsp, hspname));

	    if (error == 0) {
		devconfig_set_components(*hsp, spares);
		devconfig_set_components(default_hsp, NULL);

		oprintf(OUTPUT_TERSE,
			gettext("  --->Using %s from disk set %s...\n"),
			hspname, dsname);
	    } else {
		free_devconfig(*hsp);
		*hsp = NULL;
	    }

	} else {

	    /* no existing default HSP, make it */
	    ((error = new_devconfig(hsp, TYPE_HSP)) != 0) ||
	    (error = devconfig_set_name(*hsp, hspname));
	    if (error == 0) {
		oprintf(OUTPUT_VERBOSE,
			gettext("  --->Created %s for disk set %s...\n "),
			hspname, dsname);
	    } else {
		free_devconfig(*hsp);
		*hsp = NULL;
	    }

	    if (free_hspname == B_TRUE) {
		free(hspname);
	    }
	}

	if (error == 0) {
	    error = populate_hsp(request, *hsp, devices);
	}

	return (error);
}

/*
 * FUNCTION:	layout_explicit_hsp(devconfig_t *hsprequest,
 *			dlist_t *devices, devconfig_t **hsp)
 *
 * INPUT:	hsprequest - pointer to the explicit HSP request devconfig_t
 *		devices - pointer to a list of devices to be served by the HSP
 *
 * OUTPUT:	hsp	- pointer to a HSP devconfig_t to hold resulting HSP
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Layout driver for an explicit HSP request.
 *
 *		a. if the request names an HSP and it already exists, use it
 *		b. if the request names an HSP and it does not exist, create it
 *		c. if the request specifies components, use them
 *		   otherwise, add new spares to handle the input list
 *		   of devices.
 */
static int
layout_explicit_hsp(
	devconfig_t	*hsprequest,
	dlist_t		*devices,
	devconfig_t 	**hsp)
{
	char		*dsname = get_request_diskset();
	char		*hspname = NULL;
	dlist_t		*rspares = NULL;
	int		error = 0;

	oprintf(OUTPUT_VERBOSE,
		gettext("  --->Explicit HSP request...\n"));

	(void) devconfig_get_name(hsprequest, &hspname);
	if (hspname != NULL) {

	    (void) hsp_get_by_name(dsname, hspname, hsp);
	    if (*hsp != NULL) {

		oprintf(OUTPUT_VERBOSE,
			gettext("  --->Using %s...\n"),
			hspname);
	    } else {

		/* named HSP doesn't exist, create it */
		((error = new_devconfig(hsp, TYPE_HSP)) != 0) ||
		(error = devconfig_set_name(*hsp, hspname));
		if (error == 0) {
		    oprintf(OUTPUT_VERBOSE,
			    gettext("  --->%s does not exist, "
				    "created...\n"), hspname);
		} else {
		    free_devconfig(*hsp);
		    *hsp = NULL;
		}
		free(hspname);
	    }
	}

	if (error == 0) {

	    /* does the hsprequest specify spares? */
	    rspares = devconfig_get_components(hsprequest);
	    if (rspares != NULL) {

		/* put requested spares into HSP */
		dlist_t	*list = NULL;
		dlist_t *iter = NULL;

		for (iter = rspares;
		    (iter != NULL) && (error == 0);
		    iter = iter->next) {

		    dlist_t *item = NULL;
		    if ((dlist_new_item(iter->obj)) == NULL) {
			error = ENOMEM;
		    } else {
			list = dlist_append(item, list, AT_TAIL);
		    }
		}

		if (error == 0) {
		    error = assemble_hsp(*hsp, rspares, devices);
		}

	    } else {

		/* select new spares */
		error = populate_hsp(hsprequest, *hsp, devices);
	    }
	}

	return (error);
}

/*
 * FUNCTION:	populate_hsp(devconfig_t *request, devconfig_t *hsp,
 *			dlist_t *devices)
 *
 * INPUT:	request	- pointer to a request devconfig_t
 *		hsp	- pointer to a HSP devconfig_t
 *		devices - pointer to a list of devices to be served by the HSP
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Processes the input HSP request and add spares sufficient
 *		to service the input list of devices.
 *
 *		Determine the available HBAs, disks, and slices.
 *		Sort thru the input list of devices and determine
 *		    the unique component sizes which need to be spared.
 *		Filter the available slices and remove those that are
 *		    too small to serve as spares.
 *
 *		Iterate each device and its components and see if the
 *		    HSP currently has a sufficient spare, if not, try
 *		    to select one from the available slices.
 *
 *		If a spare cannot be found for any device component,
 *		    the HSP layout process stops.
 *
 *              If spares are found for all device components, add
 *		    any required new ones to the HSP.
 */
static int
populate_hsp(
	devconfig_t	*request,
	devconfig_t	*hsp,
	dlist_t		*devices)
{
	int		error = 0;
	uint16_t	npaths	= 0;

	dlist_t		*usable_hbas = NULL;
	dlist_t		*sel_hbas = NULL;
	dlist_t		*disks = NULL;
	dlist_t		*iter = NULL;

	dlist_t		*avail = NULL;	/* available slices */
	dlist_t		*slices = NULL;	/* avail slices of sufficient size */
	dlist_t		*unique = NULL;	/* volume slices that need spares */
	dlist_t		*curspares = NULL; /* current spares in the HSP */
	dlist_t		*newspares = NULL; /* slices to add to HSP */
	dlist_t		*allspares = NULL; /* current and new spares */

	((error = get_usable_hbas(&usable_hbas)) != 0) ||
	(error = select_hbas_with_n_disks(request, usable_hbas, 1, &sel_hbas,
		&disks)) ||
	(error = disks_get_avail_slices(request, disks, &avail)) ||
	(error = get_volume_npaths(request, &npaths));
	if (error != 0) {
	    dlist_free_items(sel_hbas, NULL);
	    dlist_free_items(disks, NULL);
	    dlist_free_items(avail, NULL);
	    return (error);
	}

	if (disks == NULL || dlist_length(disks) == 0) {
	    /* all disks have been consumed by the devices */
	    volume_set_error(
		    gettext("  no available disks to populate HSP\n"));
	    dlist_free_items(sel_hbas, NULL);
	    dlist_free_items(avail, NULL);
	    return (-1);
	}

	if (avail == NULL || dlist_length(avail) == 0) {
	    /* all slices have been consumed by the devices */
	    volume_set_error(
		    gettext("  no available slices to populate HSP\n"));
	    dlist_free_items(sel_hbas, NULL);
	    dlist_free_items(disks, NULL);
	    return (-1);
	}

	dlist_free_items(sel_hbas, NULL);
	dlist_free_items(disks, NULL);

	/* build list of slices needing to be spared */
	((error = get_uniquely_sized_slices(devices, &unique)) != 0) ||

	/* and list of slices of sufficient size to spare for them */
	(error = remove_undersized_slices(unique, &avail));

	if (error != 0) {
	    dlist_free_items(avail, NULL);
	    dlist_free_items(unique, NULL);
	    dlist_free_items(slices, NULL);
	    return (error);
	}

	/* get spares currently in the HSP */
	curspares = devconfig_get_components(hsp);

	/* clone current spares list */
	for (iter = curspares;
	    (iter != NULL) && (error == 0);
	    iter = iter->next) {
	    dlist_t *item = dlist_new_item(iter->obj);
	    if (item == NULL) {
		error = ENOMEM;
	    } else {
		allspares = dlist_append(item, allspares, AT_TAIL);
	    }
	}

	if (error != 0) {
	    dlist_free_items(avail, NULL);
	    dlist_free_items(unique, NULL);
	    dlist_free_items(slices, NULL);
	    dlist_free_items(allspares, NULL);
	    return (error);
	}

	/*
	 * examine device component slices and see if the HSP already
	 * has a suitable spare. If not, select the best available
	 * of the same (or larger) size
	 */
	for (iter = devices;
	    (iter != NULL) && (error == 0);
	    iter = iter->next) {

	    devconfig_t *device = (devconfig_t *)iter->obj;
	    dlist_t *components = devconfig_get_components(device);
	    dlist_t *hbas = NULL;
	    dlist_t *disks = NULL;
	    dlist_t *iter1;

	    error = get_hbas_and_disks_used_by_volume(device, &hbas, &disks);
	    for (iter1 = components; (iter1 != NULL) && (error == 0);
		iter1 = iter1->next) {

		devconfig_t	*comp = (devconfig_t *)iter1->obj;
		boolean_t	found = B_FALSE;

		if ((error = find_spare_for_component(
		    comp, allspares, hbas, disks, &found)) == 0) {
		    if (found != B_TRUE) {
			error = choose_spare_for_component(
				comp, &allspares, &newspares,
				&avail, hbas, disks, npaths);
		    }
		}
	    }
	    dlist_free_items(disks, NULL);
	    dlist_free_items(hbas, NULL);
	}

	if (error == 0) {
	    /* existing spares are no longer needed */
	    dlist_free_items(curspares, free_devconfig_object);
	    curspares = NULL;

	    error = assemble_hsp(hsp, newspares, devices);
	} else {
	    dlist_free_items(newspares, free_devconfig_object);
	    newspares = NULL;
	}

	dlist_free_items(avail, NULL);
	dlist_free_items(slices, NULL);
	dlist_free_items(unique, NULL);
	dlist_free_items(allspares, NULL);

	return (error);
}

/*
 * FUNCTION:	assemble_hsp(devconfig_t *hsp, dlist_t *newspares,
 *			dlist_t *devices)
 *
 * INPUT:	request	- pointer to a HSP devconfig_t
 *		newspare - pointer to a list of new spares for the HSP
 *		devices - pointer to a list of devices to be served by the HSP
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Final assembly of an HSP. Attach new spare components
 *		and associate the HSP with each device in the input list.
 */
static int
assemble_hsp(
	devconfig_t 	*hsp,
	dlist_t		*newspares,
	dlist_t		*devices)
{
	dlist_t		*iter;
	char		*hspname = NULL;
	int		error = 0;

	/* add new spares to HSP */
	(void) devconfig_set_components(hsp, newspares);
	(void) devconfig_get_name(hsp, &hspname);

	/* associate HSP with each of the devices */
	for (iter = devices;
	    (iter != NULL) && (error == 0);
	    iter = iter->next) {

	    devconfig_t *dev = iter->obj;
	    devconfig_t *hspcomp = NULL;
	    dlist_t	*item = NULL;
	    char	*devname = NULL;

	    ((error = devconfig_get_name(dev, &devname)) != 0) ||
	    (error = new_devconfig(&hspcomp, TYPE_HSP)) ||
	    (error = devconfig_set_name(hspcomp, hspname));

	    if (error != 0) {

		free_devconfig(hspcomp);

	    } else if ((item = dlist_new_item(hspcomp)) == NULL) {

		free_devconfig(hspcomp);
		error = ENOMEM;

	    } else {

		dlist_t	*comps = devconfig_get_components(dev);
		comps = dlist_append(comps, item, AT_TAIL);
		(void) devconfig_set_components(dev, comps);

		oprintf(OUTPUT_VERBOSE,
			gettext("  --->volume %s will use HSP %s\n"),
			devname, hspname);
	    }
	}

	return (error);
}

/*
 * FUNCTION:	get_uniquely_sized_slices(dlist_t *devices,
 *			dlist_t **unique)
 *
 * INPUT:	devices	- pointer to a list of devconfig_t devices
 *
 * OUTPUT:	unique	- pointer to a list of uniquely size slices
 *			from the input list of devices.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Examine each device's slice components and build a list
 *		of uniquely sized slices.
 */
static int
get_uniquely_sized_slices(
	dlist_t 	*devices,
	dlist_t 	**unique)
{
	int		error = 0;
	dlist_t		*iter = NULL;

	for (iter = devices;
	    (iter != NULL) && (error == 0);
	    iter = iter->next) {

	    dlist_t *iter1;
	    for (iter1 = devconfig_get_components((devconfig_t *)iter->obj);
		(iter1 != NULL) && (error == 0);
		iter1 = iter1->next) {

		devconfig_t *comp = (devconfig_t *)iter1->obj;
		if (dlist_contains(*unique, comp,
		    compare_devconfig_sizes) != B_TRUE) {

		    dlist_t *item = NULL;
		    if ((item = dlist_new_item(comp)) == NULL) {
			error = ENOMEM;
		    } else {
			*unique = dlist_insert_ordered(item, *unique,
				ASCENDING, compare_devconfig_sizes);
		    }
		}
	    }
	}

	return (error);
}

/*
 * FUNCTION:	remove_undersized_slices(dlist_t *unique,
 *			dlist_t **avail)
 *
 * INPUT:	avail	- pointer to a list of available slices
 * 		unique	- pointer to a list of uniquely size slices
 *
 * OUTPUT:	avail - pointer to an updated list of available slices
 *			that are at least as large as slices in the
 *			unique list.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	filter available slices and remove those that aren't
 *		large enough for the device components which need spares.
 *
 *		For each uniquely sized slice, find all available slices
 *		that are larger and add them to the filtered list.
 */
static int
remove_undersized_slices(
	dlist_t		*unique,
	dlist_t		**avail)
{
	dlist_t		*filtered = NULL;
	dlist_t		*iter = NULL;
	int		error = 0;

	for (iter = unique;
	    (iter != NULL) && (error == 0);
	    iter = iter->next) {

	    devconfig_t	*uslice = (devconfig_t *)iter->obj;
	    uint64_t	usize = 0;
	    dlist_t	*iter2 = NULL;

	    error = devconfig_get_size(uslice, &usize);

	    for (iter2 = *avail;
		(iter2 != NULL) && (error == 0);
		iter2 = iter2->next) {

		dm_descriptor_t	aslice = (uintptr_t)iter2->obj;
		uint64_t	asize = 0;

		error = slice_get_size(aslice, &asize);
		if (asize >= usize) {

		    /* this slice is large enough */
		    dlist_t *item = NULL;
		    if ((item = dlist_new_item((void *)(uintptr_t)aslice)) ==
			NULL) {
			error = ENOMEM;
		    } else {
			filtered = dlist_insert_ordered(item, filtered,
				ASCENDING, compare_slice_sizes);
		    }

		}
	    }
	}

	if (error == 0) {
	    dlist_free_items(*avail, NULL);
	    *avail = filtered;
	} else {
	    dlist_free_items(filtered, NULL);
	}

	return (error);
}

/*
 * FUNCTION:	find_spare_for_component(devconfig_t *component,
 *			dlist_t *all_spares, dlist_t *hbas, dlist_t *disks,
 *			boolean_t *found)
 *
 * INPUT:	comp	- pointer to a devconfig_t slice compenent that
 *				needs to be spared
 * 		all_spares - pointer to a list of spares currently
 *				in the pool or that will be added
 * 		hbas	- pointer to a list of HBAs the component's
 *				parent device utilizes
 * 		disks	- pointer to a list of disks the component's
 *				parent device utilizes
 *
 * OUTPUT:	found - pointer to a boolean_t to hold the result.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Find a spare for the input component.
 *
 *		Searches the input list of spares to see if one is
 *		sufficient.
 *
 *		A suffcient spare is one that is large enough to spare
 *		for the input component and not on the same disk as any
 *		of the components in the parent device.
 *
 *		The optimal spare would be on a different controller/HBA
 *		as the component and any of the components in the parent
 *		device.  We settle for sufficient.
 */
static int
find_spare_for_component(
	devconfig_t	*component,
	dlist_t		*all_spares,
	dlist_t		*hbas,
	dlist_t		*disks,
	boolean_t	*found)
{
	dlist_t		*iter = NULL;
	uint64_t	csize = 0;
	int		error = 0;

	*found = B_FALSE;

	(void) devconfig_get_size(component, &csize);

	for (iter = all_spares;
	    (iter != NULL) && (*found == B_FALSE) && (error == 0);
	    iter = iter->next) {

	    devconfig_t		*spare = (devconfig_t *)iter->obj;
	    char 		*spname = NULL;
	    uint64_t 		spsize = 0;

	    if (((error = devconfig_get_name(spare, &spname)) != 0) ||
		((error = devconfig_get_size(spare, &spsize)) != 0)) {
		continue;
	    }

	    if (spsize >= csize) {

		dm_descriptor_t	disk = NULL;

		/* see if spare's disk is independent of the volume */
		error = get_disk_for_named_slice(spname, &disk);
		if ((error == 0) && (dlist_contains(disks,
		    (void *)(uintptr_t)disk, compare_descriptor_names) ==
		    B_FALSE)) {
		    *found = B_TRUE;
		}
	    }
	}

	if ((*found == B_TRUE) && (get_max_verbosity() >= OUTPUT_DEBUG)) {
	    char *cname = NULL;
	    (void) devconfig_get_name(component, &cname);
	    oprintf(OUTPUT_DEBUG,
		    gettext("    found existing spare for: %s (%llu)\n"),
		    cname, csize);
	}

	return (error);
}

/*
 * FUNCTION:	choose_spare_for_component(devconfig_t *component,
 *			dlist_t *all_spares, dlist_t **new_spares,
 *			dlist_t avail, uint16_t npaths, dlist_t *used_hbas,
 *			dlist_t *used_disks)
 *
 * INPUT:	comp	- pointer to a devconfig_t slice compenent that
 *				needs to be spared
 * 		all_spares - pointer to a list of spares currently
 *				in the pool and those to be added
 * 		new_spares - pointer to a list of spares that need to
 *				be added to the pool
 *		avail	- list of available slices
 *		npaths	- required number of paths for the spare
 *		used_hbas - list of HBAs used by the component's parent
 *		used_disks - list of disks used by the component's parent
 *
 * OUTPUT:	all_spares - the possibly updated list of all spares
 *		new_spares - the possibly updated list of spares which
 *			need to be added to the pool.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Find a new spare for the input component.
 *
 *		Select a spare from the available slice list and add
 *		it to the new_spares list.
 *
 *		The spare slice chosen should be on a unique HBA and
 *		disk relative to the input lists of used HBAs and disks
 *		and any spares in the pool.
 */
static int
choose_spare_for_component(
	devconfig_t	*component,
	dlist_t		**all_spares,
	dlist_t		**new_spares,
	dlist_t		**avail,
	dlist_t		*used_hbas,
	dlist_t		*used_disks,
	uint16_t	npaths)
{
	devconfig_t	*spare = NULL;
	uint64_t	csize = 0;
	int		error = 0;

	(void) devconfig_get_size(component, &csize);

	if (get_max_verbosity() >= OUTPUT_DEBUG) {
	    char *cname = NULL;
	    (void) devconfig_get_name(component, &cname);
	    oprintf(OUTPUT_DEBUG,
		    gettext("    select new spare for: %s (%llu)\n"),
		    cname, csize);
	}

	/*
	 * find a spare for the input component.
	 * select the best one from the available list that
	 * is on a unique disk.
	 */

	/*
	 * 1st B_TRUE: require a different disk than those used by
	 *		all spares and devices
	 * 2nd B_TRUE: requested size is the minimum acceptable
	 * 1st B_FALSE: do not add an extra cylinder when resizing slice,
	 *		this is only necessary for Stripe components whose
	 *		sizes get rounded down to an interlace multiple and
	 *		then down to a cylinder boundary.
	 */
	error = choose_slice(csize, npaths, *avail, *all_spares,
		used_hbas, used_disks, B_TRUE, B_TRUE, B_FALSE, &spare);

	if ((error == 0) && (spare == NULL)) {
	    /* can't find one on a unique disk, try again on any disk */

	    /* BEGIN CSTYLED */
	    /*
	     * 1st B_FALSE: don't require a different disk than those used
	     *		by all spares and devices
	     * 2nd B_TRUE: requested size is still the minimum acceptable
	     * 2nd B_FALSE: do not add an extra cylinder when resizing slice
	     *		this is only necessary for Stripe components whose
	     *		sizes get rounded down to an interlace multiple and
	     *		then down to a cylinder boundary.
	     */
	    /* END CSTYLED */
	    error = choose_slice(
		    csize, npaths, *avail, *all_spares, used_hbas,
		    used_disks, B_FALSE, B_TRUE, B_FALSE, &spare);
	}

	if ((error == 0) && (spare != NULL)) {

	    dlist_t	*rmvd = NULL;
	    dlist_t	*item = NULL;
	    char	*spname = NULL;

	    if ((item = dlist_new_item(spare)) == NULL) {
		error = ENOMEM;
	    } else {

		/* add spare to the all spares list */
		*all_spares = dlist_append(item, *all_spares, AT_HEAD);

		if ((item = dlist_new_item(spare)) == NULL) {
		    error = ENOMEM;
		} else {

		    /* add spare to the new spares list */
		    *new_spares = dlist_insert_ordered(
			    item, *new_spares, ASCENDING,
			    compare_devconfig_sizes);

		    /* remove it from the available list */
		    *avail = dlist_remove_equivalent_item(*avail, spare,
			    compare_devconfig_and_descriptor_names,
			    &rmvd);

		    if (rmvd != NULL) {
			free(rmvd);
		    }

		    /* add the spare to the used slice list */
		    error = devconfig_get_name(spare, &spname);
		    if (error == 0) {
			error = add_used_slice_by_name(spname);
		    }
		}
	    }

	} else {

	    /* no spare, give up on layout */
	    oprintf(OUTPUT_TERSE,
		    gettext("  <---Failed: insufficient suitable spares\n"));

	    volume_set_error(
		    gettext("failed to find sufficient spares for HSP\n"));

	    error = -1;
	}

	return (error);
}
