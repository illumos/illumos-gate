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

#include <assert.h>
#include <string.h>
#include <libintl.h>

#include "volume_error.h"
#include "volume_defaults.h"
#include "volume_dlist.h"
#include "volume_output.h"
#include "volume_request.h"

#include "layout.h"
#include "layout_request.h"

#include "layout_concat.h"
#include "layout_discovery.h"
#include "layout_device_cache.h"
#include "layout_device_util.h"
#include "layout_dlist_util.h"
#include "layout_hsp.h"
#include "layout_mirror.h"
#include "layout_slice.h"
#include "layout_stripe.h"
#include "layout_svm_util.h"
#include "layout_validate.h"

#define	_LAYOUT_C

static int layout_init(devconfig_t *request, defaults_t *defaults);
static int layout_diskset(request_t *request, dlist_t *results);

static int process_request(devconfig_t *request, dlist_t **results);
static int process_qos_request(devconfig_t *request, dlist_t **results);
static int process_hsp_request(devconfig_t *request, dlist_t **results);

/*
 * stuff for making/updating the HSP to service devices
 * created by the toplevel request
 */
static devconfig_t	*_hsp_request = NULL;
static dlist_t		*_hsp_devices = NULL;
static void set_hsp_request(devconfig_t *request);
static void unset_hsp_request();

/*
 * struct to track which disks have been explicitly modified
 * during the layout process...
 *
 * disk is the dm_descriptor_t of the modified disk
 * accessname is the name to access the disk thru
 * slices is the list of modified slices on the disk
 */
typedef struct {
	dm_descriptor_t	disk;
	char		*accessname;
	dlist_t		*slices;
} moddisk_t;

/*
 * modified_disks is a list of moddisk_t structs
 * tracking disks have been modified during layout.
 */
static dlist_t *_modified_disks = NULL;

static int collect_modified_disks(devconfig_t *request, dlist_t *results);
static int add_modified_disks_to_diskset(
	dlist_t		*devices,
	devconfig_t	*diskset);
static int release_modified_disks();
static int get_removed_slices_for_disks(
	dlist_t		*mod_disks);
static int get_modified_slices_for_disks(
	dlist_t		*moddisks);
static int compare_disk_to_moddisk_disk(
	void		*disk,
	void		*moddisk);

static int convert_device_names(devconfig_t *request, dlist_t *devs);

/*
 * FUNCTION:	get_layout(devconfig_t *request, defaults_t *defaults)
 *
 * INPUT:	request	- a devconfig_t pointer to the toplevel request
 *		defaults - a results_t pointer to the defaults
 *
 * RETURNS:	int	-  0 - on success
 *			  !0 - otherwise
 *
 * PURPOSE:	Public entry point to layout module.
 */
int
get_layout(
	request_t	*request,
	defaults_t	*defaults)
{
	devconfig_t	*diskset_req = NULL;
	dlist_t		*iter = NULL;
	dlist_t		*results = NULL;
	int		error = 0;

	if ((diskset_req = request_get_diskset_req(request)) != NULL) {

	    /* initialize using the the top-level disk set request... */
	    if ((error = layout_init(diskset_req, defaults)) != 0) {
		return (error);
	    }

	    oprintf(OUTPUT_TERSE,
		    gettext("\nProcessing volume request...\n"));

	    iter = devconfig_get_components(diskset_req);
	    for (; (iter != NULL) && (error == 0); iter = iter->next) {

		/* process each volume request, stop on any error */
		devconfig_t	*subreq = (devconfig_t *)iter->obj;
		dlist_t		*subres = NULL;

		((error = process_request(subreq, &subres)) != 0) ||
		(error = collect_modified_disks(subreq, subres)) ||
		(error = convert_device_names(subreq, subres));
		if (error == 0) {
		    results = dlist_append(subres, results, AT_TAIL);
		}
	    }

	    if (error == 0) {
		/* process HSP request */
		dlist_t *subres = NULL;
		error = process_hsp_request(diskset_req, &subres);
		if (error == 0) {
		    results = dlist_append(subres, results, AT_TAIL);
		}
	    }

	    if (error == 0) {
		oprintf(OUTPUT_TERSE,
			gettext("\nAssembling volume specification...\n"));
		/* determine required diskset modifications */
		error = layout_diskset(request, results);
	    }

	    layout_clean_up();

	    if (error == 0) {
		oprintf(OUTPUT_TERSE,
			gettext("\nVolume request completed successfully.\n"));
	    }

	} else {
	    volume_set_error(
		    gettext("Malformed request, missing top level "
			    "disk set request."));
	}

	return (error);
}

/*
 * FUNCTION:	layout_clean_up()
 *
 * PURPOSE:	function which handles the details of cleaning up cached
 *		data and any other memory allocated during the layout
 *		process.
 *
 *		release physical device data structs
 *		release SVM logical device data structs
 *		release validation data structs
 *		release modified device data structs
 *		release request processing data structs
 *
 *		This function is also exported as part of the public
 *		interface to the layout module, clients of layout
 *		are required to call this function if get_layout()
 *		was called and was not allowed to return.  For example,
 *		if SIGINT was received while a layout request was in
 *		process.
 */
void
layout_clean_up()
{
	(void) release_request_caches();
	(void) release_validation_caches();

	(void) release_slices_to_remove();
	(void) release_modified_slices();
	(void) release_modified_disks();

	(void) release_reserved_slices();
	(void) release_used_slices();

	(void) release_usable_devices();
	(void) release_svm_names(get_request_diskset());
	(void) release_known_devices();

	(void) unset_hsp_request(NULL);
	(void) unset_request_defaults(NULL);
	(void) unset_request_diskset(NULL);
	(void) unset_toplevel_request(NULL);
}

/*
 * FUNCTION:	layout_init(devconfig_t *diskset, defaults_t *defaults)
 *
 * INPUT:	diskset	- a devconfig_t pointer to the toplevel request
 *		defaults - a results_t pointer to the defaults
 *
 * RETURNS:	int	-  0 - on success
 *			  !0 - otherwise
 *
 * PURPOSE:	function which handles the details of initializing the layout
 *		module prior to processing a request.
 *
 *		Determines the requested disk set and validates it.
 *
 *		Scans the physical device configuration.
 *		Scans the SVM logical device configuration.
 *
 *		Initializes layout private global data structures and does
 *		semantic validation of the request.
 */
static int
layout_init(
	devconfig_t	*diskset,
	defaults_t	*defaults)
{
	dlist_t		*iter = NULL;
	int		error = 0;
	char		*dsname = NULL;

	((error = validate_basic_svm_config()) != 0) ||

	/* determine & validate requested disk set name */
	(error = devconfig_get_name(diskset, &dsname)) ||
	(error = set_request_diskset(dsname)) ||

	/* discover known physical and logical devices */
	(error = discover_known_devices()) ||
	(error = scan_svm_names(dsname)) ||

	/* validate and remember toplevel request */
	(error = set_toplevel_request(diskset)) ||

	/* validate and remember defaults for this request */
	(error = set_request_defaults(defaults));

	if (error != 0) {
	    return (error);
	}

	oprintf(OUTPUT_TERSE,
		gettext("\nValidating volume request...\n"));

	iter = devconfig_get_components(diskset);
	for (; (iter != NULL) && (error == 0); iter = iter->next) {
	    devconfig_t	*subreq = (devconfig_t *)iter->obj;
	    error = validate_request(subreq);
	}

	if (error == 0) {
	    error = discover_usable_devices(dsname);
	}

	if (error == 0) {
	    /* final validation on explicitly requested components */
	    error = validate_reserved_slices();
	}

	if (error == 0) {
	    /* final validation on request sizes vs. actual avail space */
	    error = validate_request_sizes(diskset);
	}

	return (error);
}

/*
 * FUNCTION:	process_request(devconfig_t *req, dlist_t **results)
 *
 * INPUT:	req	- a devconfig_t pointer to the current request
 *		results	- pointer to a list of resulting volumes
 *
 * RETURNS:	int	-  0 - on success
 *			  !0 - otherwise
 *
 * PURPOSE:	function which handles the details of an explicit
 *		volume request.
 *
 *		Determines the requested volume type, whether the
 *		request	contains specific subcomponents and dispatches
 *		to the appropriate layout function for that type.
 *
 *		Resulting volumes are appended to the results list.
 *
 *		Note that an HSP request is held until all the volumes
 *		in the request have been successfully composed. This
 *		ensures that HSP spare sizing can be appropriate to
 *		those volumes.
 */
static int
process_request(
	devconfig_t	*req,
	dlist_t		**results)
{
	component_type_t	type = TYPE_UNKNOWN;
	uint64_t	nbytes = 0;   /* requested volume size */
	dlist_t		*comps = NULL;
	int		ncomps = 0;
	int		error = 0;

	(void) devconfig_get_type(req, &type);
	(void) devconfig_get_size(req, &nbytes);
	comps = devconfig_get_components(req);

	if (type == TYPE_HSP) {
	    /* HSP processing needs to happen after all other volumes. */
	    /* set the HSP request aside until all other requests have */
	    /* been completed successfully */
	    set_hsp_request(req);
	    return (0);
	}

	oprintf(OUTPUT_TERSE, "\n");
	oprintf(OUTPUT_VERBOSE, "******************\n");

	ncomps = dlist_length(comps);

	if (type == TYPE_STRIPE) {
	    if (ncomps > 0) {
		return (populate_explicit_stripe(req, results));
	    } else {
		return (layout_stripe(req, nbytes, results));
	    }
	}

	if (type == TYPE_CONCAT) {
	    if (ncomps > 0) {
		return (populate_explicit_concat(req, results));
	    } else {
		return (layout_concat(req, nbytes, results));
	    }
	}

	if (type == TYPE_MIRROR) {
	    if (ncomps > 0) {
		return (populate_explicit_mirror(req, results));
	    } else {
		uint16_t nsubs = 0;
		if ((error = get_mirror_nsubs(req, &nsubs)) != 0) {
		    return (error);
		} else {
		    return (layout_mirror(req, nsubs, nbytes, results));
		}
	    }
	}

	if (type == TYPE_VOLUME) {
	    error = process_qos_request(req, results);
	}

	return (error);
}

/*
 * FUNCTION:	process_qos_request(devconfig_t *req, dlist_t **results)
 *
 * INPUT:	req	- a devconfig_t pointer to the current request
 *		results	- pointer to a list of resulting volumes
 *
 * RETURNS:	int	-  0 - on success
 *			  !0 - otherwise
 *
 * PURPOSE:	function which handles the details of mapping an implicit
 *		volume request of QoS attributes into a volume type.
 *
 *		Resulting volumes are appended to the results list.
 */
static int
process_qos_request(
	devconfig_t	*req,
	dlist_t		**results)
{
	int		error = 0;

	uint64_t	nbytes = 0;
	uint16_t	rlevel = 0;

	/* get QoS attributes */
	(void) devconfig_get_size(req, &nbytes);

	if ((error = get_volume_redundancy_level(req, &rlevel)) != 0) {
	    if (error == ERR_ATTR_UNSET) {
		error = 0;
		rlevel = 0;
	    }
	}

	if (error == 0) {
	    if (rlevel == 0) {
		error = layout_stripe(req, nbytes, results);
	    } else {
		error = layout_mirror(req, rlevel, nbytes, results);
	    }
	}

	return (error);
}

/*
 * FUNCTION:	layout_diskset(request_t *req, dlist_t **results)
 *
 * INPUT:	req	- a request_t pointer to the toplevel request
 *		results	- pointer to the list of composed result volumes
 *
 * RETURNS:	int	-  0 - on success
 *			  !0 - otherwise
 *
 * PURPOSE:	function which handles the details of completing an layout
 *		request.
 *
 *		Determines if the disk set specified in the request currently
 *		exists and sets it up for creation if it doesn't.
 *
 *		Adds new disks required by the result volumes to the disk set.
 *
 *		Attaches the result volumes to the disk set result.
 *
 *		Convert slice and disk names to preferred names.
 *
 *		Attaches the disk set result to the toplevel request.
 */
static int
layout_diskset(
	request_t	*request,
	dlist_t		*results)
{
	int		error = 0;
	devconfig_t	*diskset = NULL;
	dlist_t		*comps = NULL;

	((error = new_devconfig(&diskset, TYPE_DISKSET)) != 0) ||
	(error = devconfig_set_name(diskset, get_request_diskset())) ||
	(error = add_modified_disks_to_diskset(results, diskset));
	if (error != 0) {
	    free_devconfig(diskset);
	    return (error);
	}

	/* add resulting volumes */
	if (results != NULL) {
	    comps = devconfig_get_components(diskset);
	    comps = dlist_append(results, comps, AT_TAIL);
	    devconfig_set_components(diskset, comps);
	}

	request_set_diskset_config(request, diskset);

	return (error);
}

/*
 * FUNCTION:	convert_device_names(devconfig_t request, dlist_t *devices)
 *
 * INPUT:	request	- a devconfig_t request pointer
 * 		devices	- a list of devconfig_t devices
 *
 * RETURNS:	int	- 0 - on success
 *			  !0 - on any error
 *
 * PURPOSE:	Utility function to convert any slice or disk drive
 *		names in a result devconfig_t to the preferred name
 *		which should be used to access the device.
 *
 *		This convert the temporary names used by layout to
 *		the proper DID or /dev/dsk alias.
 */
static int
convert_device_names(
	devconfig_t *request,
	dlist_t	*devices)
{
	int	error = 0;
	dlist_t	*iter;

	for (iter = devices;
	    (iter != NULL) && (error == 0);
	    iter = iter->next) {

	    devconfig_t		*dev = (devconfig_t *)iter->obj;
	    component_type_t	type = TYPE_UNKNOWN;
	    dm_descriptor_t	disk = (dm_descriptor_t)0;
	    char		*devname = NULL;
	    char		*diskname = NULL;
	    char		*slicename = NULL;
	    uint16_t		index;

	    if ((error = devconfig_get_type(dev, &type)) == 0) {
		switch (type) {

		case TYPE_MIRROR:
		case TYPE_STRIPE:
		case TYPE_CONCAT:
		case TYPE_HSP:

		    error = convert_device_names(request,
			    devconfig_get_components(dev));

		    break;

		case TYPE_SLICE:

		    ((error = devconfig_get_name(dev, &devname)) != 0) ||
		    (error = devconfig_get_slice_index(dev, &index)) ||
		    (error = get_disk_for_named_slice(devname, &disk)) ||
		    (error = get_device_access_name(request, disk,
			    &diskname)) ||
		    (error = make_slicename_for_diskname_and_index(
			    diskname, index, &slicename));

		    if ((error == 0) && (slicename != NULL)) {
			error = devconfig_set_name(dev, slicename);
			free(slicename);
		    }

		    break;
		}
	    }
	}

	return (error);
}

/*
 * FUNCTION:	add_modified_disk(devconfig_t request, dm_descriptor_t disk);
 *
 * INPUT:	request	- a pointr to a devconfig_t request
 *		disk - dm_descriptor_t handle for a disk that has been modified
 *
 * SIDEEFFECTS: adds an entry to the _modified_disks list which tracks
 *		the disks that have been explicitly modified by
 *		the layout code.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Adds the input disk to the list of those that have been
 *		modified.
 *
 *		Disks are modified during layout for two reasons:
 *
 *		1. any disk that is to be added to the disk set gets
 *		   an explicitly updated label.
 *
 *		2. once a disk is in the disk set, existing slices
 *		   may be resized or new slices can be added.
 */
int
add_modified_disk(
	devconfig_t	*request,
	dm_descriptor_t disk)
{
	dlist_t		*iter = NULL;
	moddisk_t	*moddisk = NULL;
	dlist_t		*item = NULL;
	int		error = 0;

	for (iter = _modified_disks; iter != NULL; iter = iter->next) {
	    moddisk = (moddisk_t *)iter->obj;
	    if (compare_descriptor_names(
		(void *)(uintptr_t)moddisk->disk,
		(void *)(uintptr_t)disk) == 0) {
		/* already in list */
		return (0);
	    }
	}

	moddisk = (moddisk_t *)calloc(1, sizeof (moddisk_t));
	if (moddisk == NULL) {
	    error = ENOMEM;
	} else {
	    char *aname = NULL;
	    error = get_device_access_name(request, disk, &aname);
	    if (error == 0) {

		/* add to list of modified disks */
		moddisk->disk = disk;
		moddisk->accessname = aname;
		moddisk->slices = NULL;

		if ((item = dlist_new_item((void *)moddisk)) == NULL) {
		    free(moddisk);
		    error = ENOMEM;
		} else {
		    _modified_disks =
			dlist_append(item, _modified_disks, AT_HEAD);
		}
	    }
	}

	return (error);
}

/*
 * FUNCTION:	collect_modified_disks(devconfig_t *request, dlist_t* devs)
 *
 * INPUT:	devs	- pointer to a list of composed volumes
 * OUTPUT:	none	-
 * SIDEEFFECT:	updates the module global list _modified_disks
 *
 * RETURNS:	int	-  0 - success
 *			  !0 - failure
 *
 * PURPOSE:	Helper to maintain the list of disks to be added to the
 * 		disk set.
 *
 *		Iterates the input list of devices and determines which
 *		disks they use. If a disk is not in the _modified_disks
 *		list, it is added.
 */
static int
collect_modified_disks(
	devconfig_t *request,
	dlist_t *devs)
{
	int	error = 0;

	char	*sname = NULL;
	dm_descriptor_t	disk = (dm_descriptor_t)0;

	for (; (devs != NULL) && (error == 0); devs = devs->next) {

	    devconfig_t		*dev = (devconfig_t *)devs->obj;
	    component_type_t	type = TYPE_UNKNOWN;

	    if ((error = devconfig_get_type(dev, &type)) == 0) {

		switch (type) {
		case TYPE_MIRROR:
		case TYPE_STRIPE:
		case TYPE_CONCAT:
		case TYPE_HSP:

		    error = collect_modified_disks(request,
			    devconfig_get_components(dev));
		    break;

		case TYPE_SLICE:

		    ((error = devconfig_get_name(dev, &sname)) != 0) ||
		    (error = get_disk_for_named_slice(sname, &disk)) ||
		    (error = add_modified_disk(request, disk));

		    break;
		}
	    }
	}

	return (error);
}

/*
 * FUNCTION:	add_modified_disks_to_diskset(dlist_t *devices,
 *			devconfig_t *diskset)
 *
 * INPUT:	devices	- pointer to a list of devices
 *
 * OUTPUT:	diskset	- pointer to a devconfig_t representing the disk set,
 *			updated to include modified disks and slices as
 *			components.
 *
 * RETURNS:	int	-  0 - success
 *			  !0 - failure
 *
 * PURPOSE:	Helper to add devconfig_t structs for disks and slices
 *	        to the disk set.
 *
 *		Updates the list of _modified_disks by examining the input
 *		list of composed devices.
 *
 *		Iterates _modified_disks and creates a devconfig_t component
 *		for each disk in the list, the list of disks is then attached
 *		to the input disk set.
 *
 *		Modified slices for disks in the disk set are added as well.
 */
static int
add_modified_disks_to_diskset(
	dlist_t		*results,
	devconfig_t	*diskset)
{
	int		error = 0;

	dlist_t		*iter;
	dlist_t		*list = NULL;
	char		*dsname = get_request_diskset();

	/* add modified disks to disk set's component list */
	list = devconfig_get_components(diskset);

	oprintf(OUTPUT_TERSE,
		gettext("  Collecting modified disks...\n"));

	/* collect removed slices for modified disks */
	error = get_removed_slices_for_disks(_modified_disks);

	/* collect modified slices for modified disks */
	error = get_modified_slices_for_disks(_modified_disks);

	for (iter = _modified_disks;
	    (iter != NULL) && (error == 0);
	    iter = iter->next) {

	    moddisk_t	*moddisk = (moddisk_t *)iter->obj;
	    dm_descriptor_t disk = moddisk->disk;
	    devconfig_t	*newdisk = NULL;
	    boolean_t	in_set = B_FALSE;

	    oprintf(OUTPUT_VERBOSE, "      %s\n", moddisk->accessname);

	    error = is_disk_in_diskset(disk, dsname, &in_set);
	    if ((error == 0) && (in_set != B_TRUE)) {
		/* New disk, add it to the disk set */
		((error = new_devconfig(&newdisk, TYPE_DRIVE)) != 0) ||
		(error = devconfig_set_name(newdisk, moddisk->accessname));
		if (error == 0) {
		    dlist_t *item = dlist_new_item(newdisk);
		    if (item == NULL) {
			error = ENOMEM;
		    } else {
			list = dlist_append(item, list, AT_TAIL);
			oprintf(OUTPUT_DEBUG,
				gettext("  must add %s to disk set \"%s\"\n"),
				moddisk->accessname, dsname);
		    }
		} else {
		    free_devconfig(newdisk);
		}
	    }

	    if ((error == 0) && (moddisk->slices != NULL)) {
		/* move moddisk's slice list to disk set comp list */
		list = dlist_append(moddisk->slices, list, AT_TAIL);
		moddisk->slices = NULL;
	    }
	}

	if (error == 0) {
	    devconfig_set_components(diskset, list);
	} else {
	    dlist_free_items(list, NULL);
	}

	return (error);
}

/*
 * FUNCTIONS:	void release_modified_disks()
 *
 * INPUT:	none   -
 * OUTPUT:	none   -
 *
 * PURPOSE:	cleanup the module global list of disks that need
 *		to be added to the disk set to satisfy the request.
 */
static int
release_modified_disks()
{
	dlist_t *iter = _modified_disks;

	for (; iter != NULL; iter = iter->next) {
	    moddisk_t *moddisk = (moddisk_t *)iter->obj;
	    if (moddisk->slices != NULL) {
		dlist_free_items(moddisk->slices, free_devconfig);
		moddisk->slices = NULL;
	    }
	    free(moddisk);
	    iter->obj = NULL;
	}

	dlist_free_items(_modified_disks, NULL);
	_modified_disks = NULL;

	return (0);
}

/*
 * FUNCTION:	get_removed_slices_for_disks(dlist_t *mod_disks)
 *
 * INPUT:	mod_disks - a list of moddisk_t structs
 *
 * OUTPUT:	mod_disks - the list of moddisk_t structs updated with
 *			the slices to be removed for each disk
 *
 * RETURNS:	int	-  0 - success
 *			  !0 - failure
 *
 * PURPOSE:	Helper to create a list of devconfig_t structs
 *		for slices on the input disks which need to be
 *		removed from the system.
 *
 *		Iterates the list of slices to be removed and
 *		creates a devconfig_t component for each slice
 *		in the list that is on any of the input modified
 *		disks.
 *
 *		Slice names are constructed using the modified disk's
 *		access name to ensure that the correct alias is
 *		used to get to the slice.
 */
static int
get_removed_slices_for_disks(
	dlist_t		*mod_disks)
{
	int		error = 0;
	dlist_t		*iter = NULL;

	/* collect slices to be removed for the modified disks */
	for (iter = get_slices_to_remove();
	    (iter != NULL) && (error == 0);
	    iter = iter->next) {

	    rmvdslice_t	*rmvd = (rmvdslice_t *)iter->obj;
	    dm_descriptor_t disk = (dm_descriptor_t)0;
	    moddisk_t	*moddisk = NULL;
	    char	*sname = NULL;
	    devconfig_t	*newslice = NULL;
	    dlist_t	*item = NULL;

	    (void) get_disk_for_named_slice(rmvd->slice_name, &disk);

	    if ((item = dlist_find(mod_disks, (void *)(uintptr_t)disk,
		compare_disk_to_moddisk_disk)) == NULL) {
		/* slice on disk that we don't care about */
		continue;
	    }

	    moddisk = (moddisk_t *)item->obj;

	    /* create output slice struct for the removed slice */
	    ((error = make_slicename_for_diskname_and_index(
		    moddisk->accessname, rmvd->slice_index, &sname)) != 0) ||
	    (error = new_devconfig(&newslice, TYPE_SLICE)) ||
	    (error = devconfig_set_name(newslice, sname)) ||
	    (error = devconfig_set_size_in_blocks(newslice, 0));

	    /* add to the moddisk's list of slices */
	    if (error == 0) {
		if ((item = dlist_new_item(newslice)) == NULL) {
		    free_devconfig(newslice);
		    error = ENOMEM;
		} else {
		    moddisk->slices =
			dlist_append(item, moddisk->slices, AT_TAIL);
		}
	    } else {
		free_devconfig(newslice);
	    }
	}

	return (error);
}

/*
 * FUNCTION:	get_modified_slices_for_disks(dlist_t *mod_disks)
 *
 * INPUT:	mod_disks - a list of moddisk_t structs
 *
 * OUTPUT:	mod_disks - the list of moddisk_t structs updated with
 *			the modified slices for each disk
 *
 * RETURNS:	int	-  0 - success
 *			  !0 - failure
 *
 * PURPOSE:	Helper to create a list of devconfig_t structs
 *		for slices on the input disks which have been
 *		modified for use by layout.
 *
 *		Iterates the list of modified slices and creates a
 *		devconfig_t component for each slice in the list
 *		that is on any of the input modified disks.
 *
 *		Slice names are constructed using the modified disk's
 *		access name to ensure that the correct alias is
 *		used to get to the slice.
 */
int
get_modified_slices_for_disks(
	dlist_t		*mod_disks)
{
	int		error = 0;
	dlist_t		*iter = NULL;

	for (iter = get_modified_slices();
	    (iter != NULL) && (error == 0);
	    iter = iter->next) {

	    modslice_t *mods = (modslice_t *)iter->obj;
	    devconfig_t	*slice = mods->slice_devcfg;
	    devconfig_t	*newslice = NULL;
	    dm_descriptor_t disk;
	    moddisk_t	*moddisk;
	    dlist_t	*item;
	    char	*sname = NULL;
	    uint64_t	stblk = 0;
	    uint64_t	nblks = 0;
	    uint16_t	index;

	    /* only add modified slices that were sources */
	    if ((mods->times_modified == 0) ||
		(mods->src_slice_desc != (dm_descriptor_t)0)) {
		continue;
	    }

	    (void) devconfig_get_name(slice, &sname);
	    (void) get_disk_for_named_slice(sname, &disk);

	    if ((item = dlist_find(mod_disks, (void *)(uintptr_t)disk,
		compare_disk_to_moddisk_disk)) == NULL) {
		/* slice on disk that we don't care about */
		continue;
	    }

	    moddisk = (moddisk_t *)item->obj;

	    /* create output slice struct for the modified slice */
	    ((error = devconfig_get_slice_start_block(slice,
		    &stblk)) != 0) ||
	    (error = devconfig_get_size_in_blocks(slice, &nblks)) ||
	    (error = devconfig_get_slice_index(slice, &index)) ||
	    (error = make_slicename_for_diskname_and_index(
		    moddisk->accessname, index, &sname)) ||
	    (error = new_devconfig(&newslice, TYPE_SLICE)) ||
	    (error = devconfig_set_name(newslice, sname)) ||
	    (error = devconfig_set_slice_start_block(newslice, stblk)) ||
	    (error = devconfig_set_size_in_blocks(newslice, nblks));

	    /* add to the moddisk's list of slices */
	    if (error == 0) {
		if ((item = dlist_new_item(newslice)) == NULL) {
		    free_devconfig(newslice);
		    error = ENOMEM;
		} else {
		    moddisk->slices =
			dlist_append(item, moddisk->slices, AT_TAIL);
		}
	    } else {
		free_devconfig(newslice);
	    }
	}

	return (error);
}

/*
 * FUNCTION:	compare_disk_to_moddisk_disk(void *disk, void *moddisk)
 *
 * INPUT:	disk	- opaque pointer to a dm_descriptor_t
 * 		moddisk - opaque moddisk_t pointer
 *
 * RETURNS:	int	- 0 - if disk == moddisk->disk
 *			 !0 - otherwise
 *
 * PURPOSE:	dlist_t helper which compares the input disk dm_descriptor_t
 *		handle to the disk dm_descriptor_t handle in the input
 *		moddisk_t struct.
 *
 *		Comparison is done via compare_descriptor_names.
 */
static int
compare_disk_to_moddisk_disk(
	void		*disk,
	void		*moddisk)
{
	assert(disk != (dm_descriptor_t)0);
	assert(moddisk != NULL);

	return (compare_descriptor_names((void *)disk,
			(void *)(uintptr_t)((moddisk_t *)moddisk)->disk));
}

/*
 * FUNCTIONS:	void set_hsp_request()
 *
 * INPUT:	none   -
 * OUTPUT:	none   -
 *
 * PURPOSE:	set the module global HSP request struct.
 */
static void
set_hsp_request(
	devconfig_t	*req)
{
	_hsp_request = req;
}

/*
 * FUNCTIONS:	void unset_hsp_request()
 *
 * INPUT:	none   -
 * OUTPUT:	none   -
 *
 * PURPOSE:	unset the module global HSP request struct.
 */
static void
unset_hsp_request()
{
	_hsp_request = NULL;
}

/*
 * FUNCTION:	process_hsp_request(devconfig_t *req, dlist_t **results)
 * INPUT:	req	- pointer to the toplevel disk set devconfig_t request
 * 		results	- pointer to a list of composed results
 *
 * RETURNS:	int	-  0 - success
 *			  !0 - failure
 *
 * PURPOSE:	Helper which determines HSP processing for the
 *		composed volumes which need HSP spares.
 */
static int
process_hsp_request(
	devconfig_t	*req,
	dlist_t		**results)
{
	int error = 0;

	if (_hsp_request != NULL) {
	    oprintf(OUTPUT_TERSE,
		    gettext("\nProcessing HSP...\n"));
	}

	if (_hsp_devices == NULL) {
	    /* no devices -> no HSP */
	    oprintf(OUTPUT_VERBOSE,
		    gettext("  No devices require hot spares...\n"));
	} else {

	    oprintf(OUTPUT_TERSE, "\n");

	    ((error = layout_hsp(req, _hsp_request, _hsp_devices,
		results)) != 0) ||
	    (error = collect_modified_disks(_hsp_request, *results)) ||
	    (error = convert_device_names(_hsp_request, *results));
	}

	return (error);
}

/*
 * FUNCTION:	add_to_hsp_list(dlist_t* list)
 * INPUT:	devs	- pointer to a list of composed volumes
 * OUTPUT:	none	-
 * SIDEEFFECT:	updates the module global list _hsp_devices
 *
 * RETURNS:	int	-  0 - success
 *			  !0 - failure
 *
 * PURPOSE:	Helper to update the list of devices which need HSP spares.
 *
 *		Iterates the input list of devices and adds them them to the
 *		module provate list of devices needing spares.
 */
int
add_to_hsp_list(
	dlist_t	*list)
{
	dlist_t	*iter = NULL;
	int	error = 0;

	for (iter = list; iter != NULL; iter = iter->next) {
	    dlist_t *item = NULL;

	    if ((item = dlist_new_item(iter->obj)) == NULL) {
		error = ENOMEM;
		break;
	    }
	    _hsp_devices = dlist_append(item, _hsp_devices, AT_HEAD);
	}

	return (error);
}

/*
 * FUNCTION:	string_case_compare(
 *			char *str1, char *str2)
 *
 * INPUT:	str1	- char *
 * 		str2	- char *
 *
 * RETURNS:	int	- <0 - if str1 < str2
 *			   0 - if str1 == str2
 *			  >0 - if str1 > str2
 *
 * PURPOSE:	More robust case independent string comparison function.
 *
 *		Assumes str1 and str2 are both char *
 *
 *		Compares the lengths of each and if equivalent compares
 *		the strings using strcasecmp.
 */
int
string_case_compare(
	char	*str1,
	char	*str2)
{
	int	result = 0;

	assert(str1 != NULL);
	assert(str2 != NULL);

	if ((result = (strlen(str1) - strlen(str2))) == 0) {
	    result = strcasecmp(str1, str2);
	}

	return (result);
}
