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

#include "metassist.h"
#include "volume_dlist.h"
#include "volume_error.h"
#include "volume_string.h"
#include "volume_output.h"

#define	_LAYOUT_VALIDATE_C

#include "layout_discovery.h"
#include "layout_dlist_util.h"
#include "layout_device_cache.h"
#include "layout_device_util.h"
#include "layout_request.h"
#include "layout_slice.h"
#include "layout_svm_util.h"
#include "layout_validate.h"

/*
 * This module contains the majority of the validation code which
 * layout applies to input requests. The assumption/agreement with
 * the controller implementation is that requests passed into layout
 * have undergone syntactic validation and that layout is responsible
 * for semantic validation.
 *
 * The semantic validation that is handled:
 *
 * 1. For a toplevel diskset request, validate:
 *
 *	- the number of disksets is not exceeded
 *	- the number of devices is not exceeded
 *
 *	(These items are not directly validated within this module,
 *	but it is useful to document that they are handled somewhere).
 *
 * 2. For any devconfig_t representing a volume request, verify that:
 *
 *	- all HSP names are semantically valid.  The name should conform
 *	  to the HSP naming convention: hspXXX.
 *
 *	- all concat, stripe, mirror, and volume names refer to
 *        unused, semantically valid metadevice names. Examples of
 *        bad data:
 *
 *            - a valid volume name that is already in use (d0, d10)
 *
 *            - a valid volume name that is used two or more times to
 *		refer to new elements in the request.
 *
 *            - a valid volume name that is out of range (d99877,
 *		d44356) or exceeds the maximum number of possible
 *		volumes given the current SVM configuration.
 *
 *	- all available and unavailable	device specifications refer
 *	  to existing controllers, disks, or slices on the system.
 *	  Examples of bad data:
 *
 *            - a valid but non-existent controller (c23, c2)
 *            - a valid but non-existent disk (c0t0d8, c1t0d0)
 *            - a valid slice on a non-existent disk or controller
 *		(c0t0d8s7, c1t0d05)
 *            - a valid slice on an existing disk (c0t0d0s12,
 *          	c0t0d0s9)
 *
 *	- any typed volume request that explicitly specifies components
 *	  requires additional validation to detect syntactically valid
 *	  expressions that are semantically ambiguous:
 *
 *	  a concat request that:
 *	      - specifies size and components is invalid
 *
 *	  a stripe request that:
 *	      - specifies size and components is invalid
 *	      - specifies mincomp and components but not enough
 *		components is invalid
 *	      - specifies maxcomp and components but too many
 *		components is invalid
 *
 *	  a HSP request that:
 *	      - specifies components that are not appropriate for
 *		the volumes the HSP serves is invalid (?)
 *
 *	  a stripe, concat or HSP request that:
 *	      - specifies a component that was used in a prior
 *		request is invalid
 *	      - specifies a component that does not exist in the
 *		diskset is invalid (e.g., c0t0d0s0, but c0t0d0 is
 *		not yet in the diskset)
 *
 *	  a mirror request that:
 *	      - specifies nsubs and components but not enough
 *		components is invalid
 *	      - specifies components and the components specify
 *		different sizes results in a WARNING since the total
 *		usable capacity of the mirror is determined by the
 *		smallest of its submirrors.
 *	      - specifies components and the components specify
 *		components results in a WARNING since the submirrors
 *		may end up with different sizes
 */
static  int validate_request_name(
	devconfig_t	*req,
	component_type_t type);

static  int validate_request_size(
	devconfig_t	*req,
	component_type_t type);

static int validate_minimum_size(
	uint64_t	nbytes);

static uint64_t apply_layout_overhead_factor(
	uint64_t req_size);

static int get_space_available_for_request(
	devconfig_t	*request,
	dlist_t		*usable_slices,
	uint64_t	*avail_space);

static int do_available_space_check(
	uint64_t	req_size,
	uint64_t	raw_avail_space,
	devconfig_t	*request,
	dlist_t		*usable_slices);

static int validate_request_redundancy_level(
	devconfig_t	*req);

static int validate_request_npaths(
	devconfig_t	*req);

static  int validate_request_submirrors(
	devconfig_t	*req);

static  int validate_submirror_types(
	dlist_t		*submirrors);

static  int validate_submirror_number(
	devconfig_t	*req,
	dlist_t		*submirrors);

static  int validate_submirror_sizes(
	devconfig_t	*req,
	dlist_t		*submirrors);

static int validate_submirror_size_and_components(
	devconfig_t	*submir,
	uint64_t	mirror_size,
	uint64_t	*assumed_size,
	dlist_t		**submirs_with_size,
	dlist_t		**submirs_with_comps,
	dlist_t		**submirs_no_size_or_comps);

static  int validate_slice_components(
	devconfig_t	*req,
	component_type_t type);

static char *get_device_aliases_string(
	dm_descriptor_t desc);

static int validate_device_array(
	char	**array,
	char	*which,
	dlist_t	**list);

static int add_reserved_name(char *name);
static boolean_t is_rsvd_name(char *name);
static dlist_t *_rsvd_names = NULL;

/*
 * FUNCTION:	release_validatation_caches()
 *
 * RETURNS:	int	- 0
 *
 * PURPOSE:	Cleanup function.
 *
 *		Purges list of reserved volume names.  Should be called
 *		after all layout requests have been processed.
 */
int
release_validation_caches()
{
	dlist_free_items(_rsvd_names, NULL);
	_rsvd_names = NULL;

	return (0);
}

/*
 * FUNCTION:	validate_basic_svm_config()
 *
 * RETURNS:	int	- 0 on success
 *			 !0 on failure
 *
 * PURPOSE:	Check to see if the local set metadb replicas have been created.
 *
 *		Makes sure at least 1 metadb replica exists for the local set.
 */
int
validate_basic_svm_config()
{
	int error = 0;
	int nreplicas = 0;

	if ((error = get_n_metadb_replicas(&nreplicas)) == 0) {
	    if (nreplicas == 0) {
		volume_set_error(
			gettext("Failed: State database replicas must "
				"exist before using %s.\n"
				"See metadb(1M) and %s(1M)."),
			progname, progname);
		error = -1;
	    } else {
		oprintf(OUTPUT_DEBUG,
			gettext("%d metadb replicas found.\n"),
			nreplicas);
	    }
	}

	return (error);
}

/*
 * FUNCTION:	validate_request_sizes(devconfig_t *req)
 *
 * INPUT:	req:	a devconfig_t pointer to the toplevel request
 *
 * RETURNS:	int	- 0 on success
 *			 !0 on failure
 *
 * PURPOSE:	Check to see if the any of the individual volume request
 *		sizes exceeds the raw available space on the system or
 *		the space available to that specific request.
 *
 *		Check to see if the total space for all requests exceeds
 *		the raw available space.
 *
 *		If any check fails, stop checking, emit an error and
 *		return -1.
 *
 *		Note: this function must be called after the slice
 *		usages have been determined and the list of usable
 *		slices has been generated.
 */
int
validate_request_sizes(
	devconfig_t	*request)
{
	int		error = 0;
	dlist_t		*usable_slices;
	dlist_t		*iter;
	char		bad_rqst_info[BUFSIZ];
	uint64_t	bad_rqst_space = 0;
	uint64_t	total_rqst_space = 0;
	uint64_t	raw_space = 0;

	(void) get_usable_slices(&usable_slices);

	/*
	 * calculate raw available space: space on slices that are
	 * "available" based on the diskset defaults or global defaults
	 */
	if ((error = get_space_available_for_request(request,
	    usable_slices, &raw_space)) != 0) {
	    return (error);
	}

	if (raw_space == 0) {
	    volume_set_error(
		    gettext("Failed: there is no available space.\n"));
	    return (-1);
	}

	/* deduct sizes of reserved components */
	(void) get_reserved_slices(&iter);
	for (; (iter != NULL) && (raw_space != 0) && (error == 0);
	    iter = iter->next) {
	    dm_descriptor_t slice = (uintptr_t)iter->obj;
	    uint64_t	nbytes;
	    if ((error = slice_get_size(slice, &nbytes)) == 0) {
		if (raw_space >= nbytes) {
		    raw_space -= nbytes;
		} else {
		    raw_space = 0;
		}
	    }
	}

	/*
	 * check each volume request's size against raw_space,
	 * if that looks ok, do a closer check with the request's
	 * available devices
	 */
	iter = devconfig_get_components(request);
	for (; (iter != NULL) && (error == 0); iter = iter->next) {

	    devconfig_t		*req = (devconfig_t *)iter->obj;
	    component_type_t	type = TYPE_UNKNOWN;
	    char		*typestr = NULL;
	    uint64_t		nbytes = 0;

	    (void) devconfig_get_type(req, &type);
	    if (type == TYPE_HSP) {
		continue;
	    }

	    typestr = devconfig_type_to_str(type);

	    if ((error = devconfig_get_size(req, &nbytes)) == 0) {

		/* check specified size */

		if (type == TYPE_CONCAT || type == TYPE_STRIPE) {
		    if ((error = do_available_space_check(
			apply_layout_overhead_factor(nbytes),
			raw_space, req, usable_slices)) == 0) {
			total_rqst_space += nbytes;
		    } else if (error == ENOSPC || error == E2BIG) {
			(void) snprintf(bad_rqst_info, BUFSIZ-1,
				"%s", typestr);
			bad_rqst_space = nbytes;
		    }
		} else if (type == TYPE_MIRROR) {
		    uint16_t nsubs = 0;
		    if ((error = get_mirror_nsubs(req, &nsubs)) == 0) {
			if ((error = do_available_space_check(
			    apply_layout_overhead_factor(nbytes * nsubs),
			    raw_space, req, usable_slices)) == 0) {
			    total_rqst_space += (nsubs * nbytes);
			} else {
			    (void) snprintf(bad_rqst_info, BUFSIZ-1,
				    gettext("%s with %d submirrors"),
				    typestr, nsubs);
			    bad_rqst_space = nbytes;
			}
		    }
		}

	    } else if ((error == ERR_ATTR_UNSET) && (type == TYPE_MIRROR)) {

		/* mirror specified no size: find submirror that does */

		dlist_t *subs = devconfig_get_components(req);

		error = 0;
		if (subs != NULL) {
		    dlist_t	*iter2;
		    int		nsubs = dlist_length(subs);
		    for (iter2 = subs;
			(iter2 != NULL) && (error == 0);
			iter2 = iter2->next) {
			devconfig_t *sub = (devconfig_t *)iter2->obj;
			if ((error = devconfig_get_size(sub, &nbytes)) == 0) {
			    if ((error = do_available_space_check(
				apply_layout_overhead_factor(nbytes * nsubs),
				raw_space, req, usable_slices)) == 0) {
				total_rqst_space += (nbytes * nsubs);
			    } else {
				(void) snprintf(bad_rqst_info, BUFSIZ-1,
					gettext("%s with %d submirrors"),
					typestr, nsubs);
				bad_rqst_space = nbytes;
			    }
			    break;
			} else if (error == ERR_ATTR_UNSET) {
			    error = 0;
			}
		    }
		}
	    }
	}

	/*
	 * do_available_space_check may return ENOSPC or E2BIG
	 */
	if (error == ENOSPC) {
	    char *sizestr = NULL;
	    (void) bytes_to_sizestr(bad_rqst_space,
		    &sizestr, universal_units, B_FALSE);

	    volume_set_error(
		    gettext("Failed: the request for a %s %s "
			    "exceeds the available space.\n"),
		    sizestr, bad_rqst_info);

	    free(sizestr);
	    error = -1;

	} else if (error == E2BIG) {
	    char *sizestr = NULL;
	    (void) bytes_to_sizestr(bad_rqst_space,
		    &sizestr, universal_units, B_FALSE);

	    volume_set_error(
		    gettext("Failed: the request for a %s %s "
			    "exceeds the usable space on the device(s) "
			    "specified as available.\n"),
		    sizestr, bad_rqst_info);

	    free(sizestr);
	    error = -1;

	} else if (apply_layout_overhead_factor(total_rqst_space) > raw_space) {
	    char *sizestr = NULL;
	    (void) bytes_to_sizestr(
		    total_rqst_space, &sizestr, universal_units, B_FALSE);

	    volume_set_error(
		    gettext("Failed: the total space requested for the "
			    "volumes (about %s) exceeds the available "
			    "space.\n"),
		    sizestr);

	    free(sizestr);
	    error = -1;
	}

	return (error);
}

/*
 * FUNCTION:	apply_layout_overhead_factor(uint64_t req_size)
 *
 * INPUT:	req_size: a requested volume size
 *
 * RETURNS:	the requested volume size with an overhead factor applied
 *
 * PURPOSE:	The input size size is inflated by a "fudge" factor
 *		to account for some of the expected overhead required for
 *		volumes such as block and cylinder boundary alignment.
 */
static uint64_t
apply_layout_overhead_factor(
	uint64_t req_size)
{
	double	overhead = 1.15;
	double  d_size = req_size;
	uint64_t result = (uint64_t)(d_size * overhead);

	return (result);
}

/*
 * FUNCTION:	get_space_available_for_request(devconfig_t *request,
 *			dlist_t *usable_slices, uint64_t *avail_space)
 *
 * INPUT:	request:	a devconfig_t volume request
 *		usable_slices:	a list of usable slice dm_descriptor_t handles
 *
 * OUTPUT:	avail_space:	the total space on slices in the usable_slice
 *				list that is available for use by the input
 *				request.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 on failure
 *
 * PURPOSE:	Iterate the input list of usable slices, determine which are
 *		available to the input request and accumulate the total space
 *		they represent.
 *
 *		The slices in the usable_slice list are those with no apparent
 *		usage detected.  The slice_is_available() check determines
 *		whether the slice passes the available/unavailable device
 *		specification associated with the input request.
 */
static int
get_space_available_for_request(
	devconfig_t	*request,
	dlist_t		*usable_slices,
	uint64_t	*avail_space)
{
	dlist_t	*iter;
	int	error = 0;

	*avail_space = 0;

	for (iter = usable_slices;
	    (iter != NULL) && (error == 0);
	    iter = iter->next) {
	    dm_descriptor_t slice = (uintptr_t)iter->obj;
	    char	*sname;
	    uint64_t	nbytes;
	    boolean_t	avail = B_FALSE;
	    if ((error = get_display_name(slice, &sname)) == 0) {
		if ((error = slice_is_available(sname, request, &avail)) == 0) {
		    if (avail == B_TRUE) {
			if ((error = slice_get_size(slice, &nbytes)) == 0) {
			    *avail_space += nbytes;
			}
		    }
		}
	    }
	}

	return (error);
}

/*
 * FUNCTION:	do_available_space_check(uint64_t req_size,
 *		uint64_t raw_avail_space, devconfig_t *request,
 *		dlist_t *usable_slices)
 *
 * INPUT:	req_size:	the requested size of a volume
 *		raw_avail_space:the total available space for all volumes
 *		request:	a devconfig_t volume request
 *		usable_slices:	a list of usable slice dm_descriptor_t handles
 *
 * RETURNS:	int	- ENOSPC if the requested size exceeds the raw
 *				available space.
 *
 *			  E2BIG if the requested size exceeds the space
 *				available specifically to the input request,
 *				taking into account its available and
 *				unavailable device specifications.
 *
 *			  0 otherwise
 *
 * PURPOSE:	Check the input request size against different forms of
 *		available space.
 *
 *		If the requested size is less than the raw_avail_space, do the
 *		more expensive check against the space specifically available
 *		to the input request.
 */
static int
do_available_space_check(
	uint64_t	req_size,
	uint64_t	raw_avail_space,
	devconfig_t	*request,
	dlist_t		*usable_slices)
{
	int	error = 0;

	if (req_size > raw_avail_space) {
	    error = ENOSPC;
	} else {
	    uint64_t avail_space = 0;
	    if ((error = get_space_available_for_request(request,
		usable_slices, &avail_space)) == 0) {
		if (req_size > avail_space) {
		    error = E2BIG;
		}
	    }
	}

	return (error);
}

/*
 * FUNCTION:	validate_request(devconfig_t *req)
 *
 * INPUT:	req	- a devconfig_t representing a volume layout request.
 *
 * RETURNS:	int	- 0 if the request passes validation
 *			 !0 otherwise.
 *
 * PURPOSE:	Main entry point into the layout request semantic
 *		validatation.
 *
 *		Determines the type of volume requested and invokes the
 *		appropriate validation functions.
 */
int
validate_request(
	devconfig_t *req)
{
	int 	error = 0;
	component_type_t type = TYPE_UNKNOWN;

	((error = validate_request_avail_unavail(req)) != 0) ||
	(error = devconfig_get_type(req, &type));
	if (error != 0) {
	    return (error);
	}

	if (type == TYPE_MIRROR) {

	    ((error = validate_request_name(req, type)) != 0) ||
	    (error = validate_request_size(req, type)) ||
	    (error = validate_request_submirrors(req));

	} else if (type == TYPE_CONCAT || type == TYPE_STRIPE) {

	    ((error = validate_request_name(req, type)) != 0) ||
	    (error = validate_request_size(req, type)) ||
	    (error = validate_slice_components(req, type));

	} else if (type == TYPE_HSP) {

	    ((error = validate_request_name(req, type)) != 0) ||
	    (error = validate_slice_components(req, type));

	} else if (type == TYPE_VOLUME) {

	    ((error = validate_request_name(req, type)) != 0) ||
	    (error = validate_request_redundancy_level(req)) ||
	    (error = validate_request_npaths(req));

	}

	return (error);
}

/*
 * FUNCTION:	validate_reserved_slices()
 *
 * RETURNS:	int	- 0 if all reserved slices are usable in
 *			    new devices.
 *			 !0 otherwise.
 *
 * PURPOSE:	Ensures that each reserved slice is actually usable
 *		as a volume component.
 *
 *		Retrieves list of reserved slices and list of usable
 *		slices.  Ensures that each reserved slice is in the
 *		usable list, generates an error if it is not.
 *
 *		This is broken out as a separate function because
 *		initial validation is using the lists of all known
 *		devices.  Device "usability" is only determined after
 *		the initial validation has completed successfully.
 */
int
validate_reserved_slices()
{
	dlist_t	*reserved_slices;
	dlist_t	*usable_slices;
	int 	error = 0;

	((error = get_reserved_slices(&reserved_slices)) != 0) ||
	(error = get_usable_slices(&usable_slices));
	if (error == 0) {

	    dlist_t *iter;
	    for (iter = reserved_slices;
		(iter != NULL) && (error == 0);
		iter = iter->next) {

		if (dlist_contains(usable_slices, iter->obj,
			    compare_descriptor_names) != B_TRUE) {

		    dm_descriptor_t slice = (uintptr_t)iter->obj;
		    char *name = NULL;

		    error = get_display_name(slice, &name);
		    if (error == 0) {
			char *aliases = get_device_aliases_string(slice);
			if (aliases[0] != NULL) {
			    volume_set_error(
				    gettext("A requested volume component "
					    "is currently in use: \"%s\" "
					    "(aliases: %s).\n"),
				    name, aliases);
			} else {
			    volume_set_error(
				    gettext("A requested volume component "
					    "is currently in use: \"%s\"\n"),
				    name);
			}
			error = -1;
		    }
		}
	    }
	}

	return (error);
}

/*
 * FUNCTION:	validate_request_avail_unavail(devconfig_t *req)
 *
 * INPUT:	req	- a devconfig_t representing a volume layout request.
 *
 * RETURNS:	int	- 0 if the request passes validation
 *			 !0 otherwise.
 *
 * PURPOSE:	validation function for a request's lists of available
 *		and unavailable devices.
 *
 *		validates that both lists contain names of known devices.
 *
 *		validates that the same name does not appear in both lists.
 */
int
validate_request_avail_unavail(
	devconfig_t *req)
{
	dlist_t	*avail = NULL;
	dlist_t	*unavail = NULL;
	int	error = 0;

	/* check that each array contains valid devices */
	((error = validate_device_array(devconfig_get_available(req),
		gettext("available"), &avail)) != 0) ||
	(error = validate_device_array(devconfig_get_unavailable(req),
		gettext("unavailable"), &unavail));

	/* check that the arrays don't both contain the same device(s) */
	if (error == 0) {
	    dlist_t *iter;
	    for (iter = avail; iter != NULL; iter = iter->next) {
		if (dlist_contains(unavail, iter->obj,
			    compare_descriptor_names) == B_TRUE) {
		    char *name;
		    char *aliases =
			get_device_aliases_string((uintptr_t)iter->obj);

		    (void) get_display_name((uintptr_t)iter->obj, &name);
		    if (aliases[0] != NULL) {
			volume_set_error(
				gettext("\"%s\" specified as both available "
					"and unavailable.\n"
					"It has these aliases: %s\n"),
				name, aliases);
		    } else {
			volume_set_error(
				gettext("\"%s\" specified as both available "
					"and unavailable.\n"),
				name);
		    }
		    error = -1;
		    break;
		}
	    }
	}

	dlist_free_items(avail, NULL);
	dlist_free_items(unavail, NULL);

	return (error);
}

/*
 * FUNCTION:	validate_device_array(char **array, char *which, dlist_t **list)
 *
 * INPUT:	array	- an array of char * device names
 * 		which   - either "available" or "unavailable"
 *			  indicating the array name to use in
 *			  error strings.
 * OUTPUT:	list	- a list of device descriptors corresponding the each
 *			  of the input names.
 *
 * RETURNS:	int	- 0 if the array passes validation
 *			 !0 otherwise.
 *
 * PURPOSE:	validation function for a request's list of available
 *		or unavailable devices.
 *
 *		DID names are converted to CTD names.
 *
 *		The CTD name must be of an available slice, disk or
 *		HBA, or a known used slice, disk or HBA that was
 *		discovered when the system's devices were probed.
 *
 *		Any other name is assumed to refer to a device not
 *		attached to the system and results in a validation
 *		failure.
 *
 *		Descriptors for validated devices are added to the input
 *		list.
 */
int
validate_device_array(
	char	**array,
	char	*which,
	dlist_t	**list)
{
	int	error = 0;
	int	i = 0;

	if (array == NULL || *array == NULL) {
	    return (0);
	}

	for (i = 0; (array[i] != NULL) && (error == 0); i++) {

	    dm_descriptor_t slice = (dm_descriptor_t)0;
	    dm_descriptor_t disk = (dm_descriptor_t)0;
	    dm_descriptor_t hba = (dm_descriptor_t)0;
	    char	*name = array[i];

	    /* name must correspond to a known HBA, disk, or slice */
	    if ((error = hba_get_by_name(name, &hba)) == 0) {
		if (hba == (dm_descriptor_t)0) {
		    if ((error = disk_get_by_name(name, &disk)) == 0) {
			if (disk == (dm_descriptor_t)0) {
			    error = slice_get_by_name(name, &slice);
			}
		    }
		}
	    }

	    if (error != 0) {
		break;
	    }

	    /* 0 sized slices cannot be used as-is, pretend non-existant */
	    if (slice != (dm_descriptor_t)0) {
		uint64_t size = 0;
		if ((error = slice_get_size(slice, &size)) == 0) {
		    if (size == 0) {
			slice = (dm_descriptor_t)0;
		    }
		}
	    }

	    oprintf(OUTPUT_DEBUG,
		    gettext("  validate %s (%s): s=%llu, d=%llu, c=%llu\n"),
		    which, array[i], slice, disk, hba);

	    if ((error == 0) && ((slice != 0) || (disk != 0) || (hba != 0))) {

		/* name represents an individual "device", add it to the list */
		dm_descriptor_t desc = (dm_descriptor_t)0;
		dlist_t *item;

		if (slice != 0) {
		    desc = slice;
		} else if (disk != 0) {
		    desc = disk;
		} else if (hba != 0) {
		    desc = hba;
		}

		if ((item = dlist_new_item((void *)(uintptr_t)desc)) == NULL) {
		    error = ENOMEM;
		} else {
		    *list = dlist_append(item, *list, AT_HEAD);
		}

	    } else if (is_ctd_target_name(name) == B_TRUE) {

		/* expand target to all of its disks */
		dlist_t *disks = NULL;
		if ((error = get_disks_for_target(name, &disks)) == 0) {
		    if ((disks == NULL) || (dlist_length(disks) == 0)) {
			volume_set_error(
				gettext("nonexistent device specified "
					"as %s: \"%s\"."),
				which, array[i]);
			error = -1;
		    } else {
			dlist_t *iter;
			for (iter = disks;
			    (iter != NULL) && (error == 0);
			    iter = iter->next) {

			    dlist_t *item;
			    if ((item = dlist_new_item(iter->obj)) == NULL) {
				error = ENOMEM;
			    } else {
				*list = dlist_append(item, *list, AT_HEAD);
			    }
			}
		    }
		}

	    } else {

		/* not a slice, disk, target or ctrl */
		volume_set_error(
			gettext("nonexistent device specified "
				"as %s: \"%s\"."),
			which, array[i]);
		error = -1;
	    }
	}

	return (error);
}

/*
 * FUNCTION:	validate_request_name(devconfig_t *req, component_type_t type)
 *
 * INPUT:	req	- a devconfig_t volume request
 * 		type	- the volume type being requested
 *
 * SIDEEFFECT:  if the request specifies a name and the name is valid and
 *		not currently in use an attempt is made to reserve it.
 *		if the name has already been reserved by a prior volume
 *		request, validation fails.
 *
 * RETURNS:	int	- 0 if the requested name passes validation
 *				(or there is no name request)
 *			 !0 otherwise.
 *
 * PURPOSE:	Validation function for a request's volume name.
 *
 *		a HSP name must be valid and reservable.
 *
 *		a volume name must be valid and reservable.
 */
static int
validate_request_name(
	devconfig_t	*req,
	component_type_t type)
{
	char	*name = NULL;
	char	*typestr = devconfig_type_to_str(type);
	int	error = 0;

	if ((error = devconfig_get_name(req, &name)) != 0) {
	    if (error != ERR_ATTR_UNSET) {
		volume_set_error(
			gettext("error getting requested name.\n"));
		return (error);
	    }
	    /* no name specified */
	    return (0);
	}

	if (type == TYPE_HSP) {
	    if (is_hsp_name_valid(name) == 0) {
		volume_set_error(
			gettext("requested %s name \"%s\" is not valid.\n"),
			typestr, name);
		error = -1;
	    } else if (reserve_hsp_name(name) != 0) {
		if (is_rsvd_name(name) == B_TRUE) {
		    volume_set_error(
			    gettext("requested %s name \"%s\" used "
				    "previously in this request.\n"),
			    typestr, name);
		} else {
		    volume_set_error(
			    gettext("requested %s name \"%s\" is not "
				    "available.\n"),
			    typestr, name);
		}
		error = -1;
	    } else {
		error = add_reserved_name(name);
	    }
	} else {
	    if (is_volume_name_valid(name) == 0) {
		volume_set_error(
			gettext("requested %s name \"%s\" is not valid.\n"),
			typestr, name);
		error = -1;
	    } else if (is_volume_name_in_range(name) != B_TRUE) {
		int max = 0;
		(void) get_max_number_of_devices(&max);
		volume_set_error(
			gettext("requested %s name \"%s\" is not legal.\n"
				"Use a name less than d%d.\n"),
			typestr, name, max);
		error = -1;
	    } else if (reserve_volume_name(name) != 0) {
		if (is_rsvd_name(name) == B_TRUE) {
		    volume_set_error(
			    gettext("requested %s name \"%s\" used "
				    "previously in this request.\n"),
			    typestr, name);
		} else {
		    volume_set_error(
			    gettext("requested %s name \"%s\" is not "
				    "available, a volume with that name "
				    "already exists.\n"),
			    typestr, name);
		}
		error = -1;
	    } else {
		error = add_reserved_name(name);
	    }
	}

	return (error);
}

/*
 * FUNCTION:	add_reserved_name(char *name)
 *
 * INPUT:	name	- a char * volume name
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Helper which remembers specfically requested names
 *		in a private list to ensure that the same name isn't
 *		requested more than once.
 */
static int
add_reserved_name(
	char	*name)
{
	dlist_t	*item = NULL;

	if ((item = dlist_new_item(name)) == NULL) {
	    return (ENOMEM);
	}

	_rsvd_names = dlist_append(item, _rsvd_names, AT_TAIL);

	return (0);
}

/*
 * FUNCTION:	is_rsvd_name(char *name)
 *
 * INPUT:	name	- a char * volume name
 *
 * RETURNS:	boolean_t - B_TRUE if the requested name is currently
 *				reserved, B_FALSE otherwise.
 *
 * PURPOSE:	Helper which checks to see if the input volume
 *		name was previously reserved.
 */
static boolean_t
is_rsvd_name(
	char	*name)
{
	dlist_t	*iter = NULL;

	for (iter = _rsvd_names; iter != NULL; iter = iter->next) {
	    if ((string_case_compare(name, (char *)iter->obj)) == 0) {
		return (B_TRUE);
	    }
	}

	return (B_FALSE);
}

/*
 * FUNCTION:	validate_request_size(devconfig_t *req, component_type_t type)
 *
 * INPUT:	req	- a devconfig_t volume request
 * 		type	- the volume type being requested
 *
 * RETURNS:	int	- 0 if the requested size passes validation
 *				(or there is no size request)
 *			 !0 otherwise.
 *
 * PURPOSE:	Validation function for a request's volume size.
 *
 *		a HSP request can have no size.
 *
 *		a concat, stripe or mirror request may have a size.
 *		if size is specified, the request cannot also specify
 *		components.  Conversely, if the request does not specify
 *		a size, it must specify components.
 */
static int
validate_request_size(
	devconfig_t	*req,
	component_type_t type)
{
	uint64_t nbytes = 0;
	int	error = 0;

	if (type == TYPE_HSP) {
	    return (0);
	}

	if ((error = devconfig_get_size(req, &nbytes)) != 0) {
	    if (error == ERR_ATTR_UNSET) {
		/* nbytes not specified, request must have subcomponents */
		dlist_t *list = devconfig_get_components(req);
		if (list != NULL && dlist_length(list) > 0) {
		    error = 0;
		} else {
		    volume_set_error(
			    gettext("%s request specifies no size or "
				    "subcomponents.\n"),
			    devconfig_type_to_str(type));
		    error = -1;
		}
	    }
	    return (error);
	}

	return (error);
}

/*
 * FUNCTION:	validate_minimum_size(uint64_t	nbytes)
 *
 * INPUT:	nbytes	- requested volume size in bytes
 *
 * RETURNS:	int	- 0 if the requested size passes validation
 *				(or there is no size request)
 *			 !0 otherwise.
 *
 * PURPOSE:	Validation function for a request's volume size.
 *
 *		an error is issued if the requested size <= 512K.
 */
static int
validate_minimum_size(
	uint64_t	nbytes)
{
	static uint64_t min = (512 * 1024) - 1;
	int	error = 0;

	if (nbytes <= min) {
	    char *sizestr = NULL;
	    char *minstr = NULL;

	    (void) bytes_to_sizestr(
		    nbytes, &sizestr, universal_units, B_FALSE);
	    (void) bytes_to_sizestr(
		    min, &minstr, universal_units, B_FALSE);

	    volume_set_error(
		    gettext("requested volume size (%s) must be "
			    "greater than %s.\n"),
		    sizestr, minstr);

	    free(sizestr);
	    free(minstr);

	    error = -1;
	}

	return (error);
}

/*
 * FUNCTION:	validate_request_redundancy_level(devconfig_t *req)
 *
 * INPUT:	req	- a devconfig_t volume request
 *
 * RETURNS:	int	- 0 if the requested redundancy level
 *			    passes validation (or none was requested)
 *			 !0 otherwise.
 *
 * PURPOSE:	Validation function for a redundant volume request's
 *		redundancy level.
 *
 *		If the request specifies redundancy, the value must be
 *		between 1 and 4.
 */
static int
validate_request_redundancy_level(
	devconfig_t	*req)
{
	uint16_t rlevel = 0;
	int	error = 0;

	if ((error = devconfig_get_volume_redundancy_level(
	    req, &rlevel)) != 0) {
	    if (error == ERR_ATTR_UNSET) {
		error = 0;
	    }
	    return (error);
	}

	if (rlevel > 4) {
	    volume_set_error(gettext(
		"requested redundancy level must be between 0 and 4.\n"));
	    error = -1;
	}

	return (error);
}

/*
 * FUNCTION:	validate_request_npaths(devconfig_t *req)
 *
 * INPUT:	req	- a devconfig_t volume request
 *
 * RETURNS:	int	- 0 if the requested # of redundant data paths
 *				passes validation (or none was requested)
 *			 !0 otherwise.
 *
 * PURPOSE:	Validation function for a volume request's number of
 *		redundant data paths.  This value controls the number
 *		of independent data paths slices components selected
 *		for the volume should have.
 *
 *		If the request specifies npaths, the value must be
 *		between 1 and 4 (4 is an arbitrary upper limit, there
 *		is no known physical limit).
 */
static int
validate_request_npaths(
	devconfig_t	*req)
{
	uint16_t npaths = 0;
	uint16_t minpaths = 1;
	uint16_t maxpaths = 4;

	int	error = 0;

	if ((error = devconfig_get_volume_npaths(req, &npaths)) != 0) {
	    if (error == ERR_ATTR_UNSET) {
		error = 0;
	    }
	    return (error);
	}

	if (npaths < minpaths || npaths > maxpaths) {
	    volume_set_error(
	    gettext("requested number of redundant paths must be "
		    "between %d and %d.\n"), minpaths, maxpaths);
	    error = -1;
	}


	if ((npaths > 1) && (is_mpxio_enabled() != B_TRUE)) {
	    volume_set_error(
		    gettext("requested number of redundant paths (%d) cannot "
			    "be provided, MPXIO is not enabled on this "
			    "system."),
		    npaths);
	    error = -1;
	}

	return (error);
}

/*
 * FUNCTION:	validate_request_submirrors(devconfig_t *req)
 *
 * INPUT:	req	- a devconfig_t volume request
 *
 * RETURNS:	int	- 0 if the requested mirror's submirrors
 *				pass validation
 *			 !0 otherwise.
 *
 * PURPOSE:	Validation function for a mirror volume request's
 *		explicitly specified submirror components.
 *
 * 		Items to check:
 *		a. submirror types
 *		b. submirror number
 *		c. submirror sizes
 */
static int
validate_request_submirrors(
	devconfig_t	*req)
{
	dlist_t	*submirrors = NULL;
	int	error = 0;

	submirrors = devconfig_get_components(req);

	((error = validate_submirror_types(submirrors)) != 0) ||
	(error = validate_submirror_number(req, submirrors)) ||
	(error = validate_submirror_sizes(req, submirrors));

	return (error);
}

/*
 * FUNCTION:	validate_submirror_types(dlist_t *subs)
 *
 * INPUT:	subs	- a list of submirror requests
 *
 * RETURNS:	int	- 0 if the requested submirrors
 *				pass validation
 *			 !0 otherwise.
 *
 * PURPOSE:	Validation function for a mirror volume request's
 *		explicitly specified submirror components.
 *
 * 		Checks that each requested submirror request
 *		is for a concat or stripe.
 */
static int
validate_submirror_types(
	dlist_t	*submirrors)
{
	dlist_t *iter;
	int 	error = 0;

	/* specified submirrors must be stripes or concats */
	for (iter = submirrors;
	    (iter != NULL) && (error == 0);
	    iter = iter->next) {

	    devconfig_t		*submir = (devconfig_t *)iter->obj;
	    component_type_t	submirtype = TYPE_UNKNOWN;

	    if ((error = devconfig_get_type(submir, &submirtype)) != 0) {
		volume_set_error(
			gettext("failed to get requested component type.\n"));
		break;
	    }

	    if (submirtype != TYPE_CONCAT && submirtype != TYPE_STRIPE) {
		volume_set_error(
			gettext("requested submirror type \"%s\" "
				"is not valid.\n"),
			devconfig_type_to_str(submirtype));
		error = -1;
		break;
	    }
	}

	return (error);
}

/*
 * FUNCTION:	validate_submirror_number(devconfig_t *req, dlist_t *subs)
 *
 * INPUT:	req	- the mirror request
 *		subs	- the list of requested submirrors
 *
 * RETURNS:	int	- 0 if the requested submirrors
 *				pass validation
 *			 !0 otherwise.
 *
 * PURPOSE:	Validation function for a mirror volume request's
 *		explicitly specified submirror components.
 *
 * 		Checks that the number of submirror components
 *		that have been specified matches the number of
 *		submirrors specified.
 */
static int
validate_submirror_number(
	devconfig_t	*req,
	dlist_t		*submirrors)
{
	uint16_t	nsubs = 0;
	int 		error = 0;

	if ((error = devconfig_get_mirror_nsubs(req, &nsubs)) != 0) {
	    if (error == ERR_ATTR_UNSET) {
		/* not specified */
		error = 0;
	    }
	} else if ((submirrors != NULL) &&
	    (dlist_length(submirrors) != nsubs)) {
	    volume_set_error(
		    gettext("the requested number of submirrors (%d) differs "
			    "from the number of specified submirrors (%d).\n"),
		    nsubs, dlist_length(submirrors));
	    error = -1;
	}

	return (error);
}

/*
 * FUNCTION:	validate_submirror_sizes(devconfig_t *req,
 *			dlist_t *submirrors)
 *
 * INPUT:	req	- the mirror request
 *		submirrors	- the list of requested submirrors
 *
 * RETURNS:	int	- 0 if the requested submirrors
 *				pass validation
 *			 !0 otherwise.
 *
 * PURPOSE:	Validation function for a mirror volume request's
 *		explicitly specified size.  Assumes that the mirror's size
 *		has been validated by validate_request_size().
 *
 * 		Compares explicitly requested mirror size against specified
 *		component sizes and checks:
 *
 * 		- any submirror request that specifies both size and
 *		  components is invalid
 *		- any submirror request specifying a size different
 *		  than that explictly requested for the mirror is
 *		  invalid
 *		- a submirror request specifying a size < 512K is invalid.
 *
 *		Other validation/warnings:
 *
 *		- submirrors that specify components may end up with
 *		  usable capacity that differs from what was specified
 *		  for the mirror.
 *
 *		- submirrors which specify neither size nor components are
 *		  assumed to be the size requested for the mirror.  If the
 *		  mirror size is not specified, the first explicit size for
 *		  a submirror is assumed as the size for the mirror.
 */
static int
validate_submirror_sizes(
	devconfig_t	*req,
	dlist_t		*submirrors)
{
	dlist_t		*submirs_with_size = NULL;
	dlist_t		*submirs_with_comps = NULL;
	dlist_t		*submirs_with_nothing = NULL;

	dlist_t		*iter = NULL;
	uint64_t	mirror_size = 0;
	uint64_t	assumed_size = 0;
	int		error = 0;

	if (submirrors == NULL || dlist_length(submirrors) == 0) {
	    return (0);
	}

	if ((error = devconfig_get_size(req, &mirror_size)) != 0) {
	    if (error == ERR_ATTR_UNSET) {
		error = 0;
	    } else {
		return (error);
	    }
	}

	/*
	 * check size and component for each submirror,
	 * collect those that specify size, components or neither
	 * into separate lists.
	 */
	for (iter = submirrors;
	    (iter != NULL) && (error == 0);
	    iter = iter->next) {

	    devconfig_t *submir = (devconfig_t *)iter->obj;

	    error = validate_submirror_size_and_components(submir,
		    mirror_size, &assumed_size, &submirs_with_size,
		    &submirs_with_comps, &submirs_with_nothing);

	}

	if (error == 0) {

	    int n_size = dlist_length(submirs_with_size);
	    int n_comp = dlist_length(submirs_with_comps);
	    int n_none = dlist_length(submirs_with_nothing);

	    if ((n_size != 0) && (n_comp != 0)) {
		/* some submirrors specified size, some components */
		oprintf(OUTPUT_TERSE,
			gettext("  *** warning: %d submirrors are specified "
				"by size, %d specified by components.\n"
				"      The resulting mirror capacity will be "
				"that of the smallest submirror.\n"),
			n_size, n_comp);
	    }

	    if (n_none != 0) {
		if (assumed_size != 0) {
		    /* some submirrors specified neither size or components */
		    char *sizestr = NULL;

		    (void) bytes_to_sizestr(
			    assumed_size, &sizestr, universal_units, B_FALSE);

		    oprintf(OUTPUT_TERSE,
			    gettext("  *** warning: %d submirrors specified "
				    "neither size or components,\n"
				    "      the assumed size is %s.\n"),
			    n_none, sizestr);

		    free(sizestr);

		} else if (mirror_size == 0) {
		    volume_set_error(
			    gettext("no size specified for requested "
				    "mirror and no sizes/components "
				    "specified for its submirrors."));

		    error = -1;
		}
	    }

	    dlist_free_items(submirs_with_size, NULL);
	    dlist_free_items(submirs_with_comps, NULL);
	    dlist_free_items(submirs_with_nothing, NULL);

	}

	return (error);
}

/*
 * FUNCTION:	validate_submirror_size_and_components(
 *			devconfig_t *submir,
 *			uint64_t mirror_size,
 *			uint64_t *assumed_size,
 *			dlist_t	**submirs_with_size,
 *			dlist_t	**submirs_with_comps,
 *			dlist_t	**submirs_no_size_or_comps)
 *
 * INPUT:	submir	- a specific submirror request
 *		mirror_size, - the size specified for the mirror
 *
 * OUTPUT:	assumed_size - the assumed size of the mirror,
 *				if none specified.
 *		submirs_with_size - pointer to a list of submirror
 *				requests that specify a size
 *		submirs_with_comps - pointer to a list of submirror
 *				requests that specify components
 *		submirs_no_size_or_comps - pointer to a list of
 *				submirror requests that specify neither
 *				a size or components
 *
 * RETURNS:	int	- 0 if the requested submirrors
 *				pass validation
 *			 !0 otherwise.
 *
 * PURPOSE:	Validation function which checks a specific submirror
 *		request's size and components against the parent mirror's
 *		size.
 *
 * 		- any submirror request that specifies both size and
 *		  components is invalid
 *		- any submirror request specifying a size different
 *		  than that explictly requested for the mirror is
 *		  invalid
 *		- a submirror request specifying a size < 512K is invalid.
 *		- any components specified for a submirror are validated.
 *
 *		If the submirror passes the validation checks, it is added
 *		to the appropriate output list.
 *
 *		If the input mirror_size is 0 and the submirror specifies
 *		a valid size, the submirror size is returned as the
 *		assumed_size for the mirror.
 */
static int
validate_submirror_size_and_components(
	devconfig_t	*submir,
	uint64_t	mirror_size,
	uint64_t	*assumed_size,
	dlist_t		**submirs_with_size,
	dlist_t		**submirs_with_comps,
	dlist_t		**submirs_no_size_or_comps)
{
	uint64_t		submir_size = 0;
	component_type_t	submir_type = TYPE_UNKNOWN;
	char			*submir_typestr = NULL;
	dlist_t			*submir_comps = NULL;
	dlist_t			*item = NULL;
	int			n_submir_comps = 0;
	int			error = 0;

	submir_comps = devconfig_get_components(submir);
	if (submir_comps != NULL) {
	    n_submir_comps = dlist_length(submir_comps);
	}

	if ((error = devconfig_get_size(submir, &submir_size)) != 0) {
	    if (error == ERR_ATTR_UNSET) {
		/* submirror size not specified */
		error = 0;
		submir_size = 0;
	    }
	}

	if (error != 0) {
	    return (error);
	}

	/* submirror type previously validated */
	(void) devconfig_get_type(submir, &submir_type);
	submir_typestr = devconfig_type_to_str(submir_type);

	if (submir_size == 0) {

	    /* submirror has no size, components? */
	    if (n_submir_comps > 0) {

		/* validate components */
		error = validate_slice_components(submir, submir_type);

		item = dlist_new_item((void *)submir);
		if (item == NULL) {
		    error = ENOMEM;
		} else {
		    *submirs_with_comps =
			dlist_append(item, *submirs_with_comps, AT_TAIL);
		}

	    } else {

		/* no size or components */
		item = dlist_new_item((void *)submir);
		if (item == NULL) {
		    error = ENOMEM;
		} else {
		    *submirs_no_size_or_comps =
			dlist_append(item, *submirs_no_size_or_comps, AT_TAIL);
		}

	    }

	} else {

	    /* submirror has size, check it */
	    if (error == 0) {
		error = validate_minimum_size(submir_size);
	    }

	    /* check size against mirror's size */
	    if ((error == 0) && (submir_size != mirror_size)) {

		if (mirror_size != 0) {

		    /* sizes differ */
		    char *sizestr = NULL;
		    char *mstr = NULL;

		    (void) bytes_to_sizestr(
			    submir_size, &sizestr, universal_units, B_FALSE);
		    (void) bytes_to_sizestr(
			    mirror_size, &mstr, universal_units, B_FALSE);

		    volume_set_error(
			    gettext("the requested submirror size (%s) "
				    "differs from the requested mirror "
				    "size (%s).\n"),
			    sizestr, mstr);

		    error = -1;

		    free(sizestr);
		    free(mstr);

		} else if (*assumed_size == 0) {

		    /* first size assumed as mirror size */
		    char *sizestr = NULL;

		    (void) bytes_to_sizestr(
			    submir_size, &sizestr, universal_units, B_FALSE);

		    oprintf(OUTPUT_TERSE,
			    gettext("  *** warning, using first "
				    "explicit submirror size (%s)\n"
				    "      as the mirror size\n"),
			    sizestr);

		    *assumed_size = submir_size;

		    free(sizestr);

		} else if (submir_size != *assumed_size) {

		    /* submirror sizes differ */
		    char *sizestr1 = NULL;
		    char *sizestr2 = NULL;

		    (void) bytes_to_sizestr(
			    submir_size, &sizestr1, universal_units, B_FALSE);
		    (void) bytes_to_sizestr(
			    *assumed_size, &sizestr2, universal_units, B_FALSE);

		    volume_set_error(
			    gettext("submirror specifies different "
				    "size (%s) than a previous "
				    "submirror (%s)\n"),
			    sizestr1, sizestr2);

		    free(sizestr1);
		    free(sizestr2);

		    error = -1;
		}
	    }

	    if ((error == 0) && (n_submir_comps > 0)) {

		/* size and subcomponents specified */
		char *sizestr = NULL;

		(void) bytes_to_sizestr(
			submir_size, &sizestr, universal_units, B_FALSE);

		volume_set_error(
			gettext("%s submirror specifies both an "
				"explicit size (%s) and components.\n"),
			submir_typestr, sizestr);

		free(sizestr);
		error = -1;

	    }

	    if (error == 0) {
		item = dlist_new_item((void *)submir);
		if (item == NULL) {
		    error = ENOMEM;
		} else {
		    *submirs_with_size =
			dlist_append(item, *submirs_with_size, AT_TAIL);
		}
	    }
	}

	return (error);
}


/*
 * FUNCTION:	validate_slice_components(devconfig_t *req,
 *			component_type_t type)
 *
 * INPUT:	req	- the request
 *		type	- the type of volume being requested
 *
 * SIDEEFFECT:	if the slice component is otherwise valid, an attempt is made
 *		to reserve it.
 *
 * RETURNS:	int	- 0 if the request passes slice component validation
 *			 !0 otherwise.
 *
 * PURPOSE:	Validation function for a concat, stripe or HSP request's
 *		explicitly specified slice components.
 *
 *		Is the component slice a known device
 *		Is the component slice available
 *		Is the component slice already reserved
 *
 *		If the request is for a stripe or concat and the
 *		request specifies an explicit size, it cannot also
 *		specify component slices.  This is a validation failure.
 *
 *		If the request is for a stripe, the number of specified
 *		slice components must agree with any expilcit specification
 *		of the minimum or maximum number of components the stripe
 *		should have.
 */
static int
validate_slice_components(
	devconfig_t	*req,
	component_type_t type)
{
	dlist_t	*list = NULL;
	dlist_t	*iter = NULL;
	int	error = 0;
	int	ncomp = 0;

	char	*dsname = get_request_diskset();
	char	*voltype = devconfig_type_to_str(type);

	list = devconfig_get_components(req);

	for (iter = list; (iter != NULL) && (error == 0); iter = iter->next) {

	    devconfig_t		*comp = (devconfig_t *)iter->obj;
	    component_type_t	ctype = TYPE_UNKNOWN;
	    char		*cname = NULL;
	    dm_descriptor_t	slice = (dm_descriptor_t)0;

	    if ((error = devconfig_get_type(comp, &ctype)) != 0) {
		volume_set_error(
			gettext("error getting requested component type."),
			voltype);

		continue;
	    }

	    if ((error = devconfig_get_name(comp, &cname)) != 0) {
		volume_set_error(
		    gettext("error getting requested component name."));

		continue;
	    }

	    if (cname == NULL || cname[0] == '\0') {
		volume_set_error(
			gettext("%s requested component has no name."),
			voltype);

		error = -1;
		continue;
	    }

	    if (ctype == TYPE_SLICE) {

		boolean_t	in_set = B_FALSE;
		boolean_t	is_avail = B_FALSE;
		boolean_t	is_rsvd = B_FALSE;
		dm_descriptor_t	disk = (dm_descriptor_t)0;

		/* is the slice known and explicitly available? */
		if ((error = slice_is_available(cname, req,
		    &is_avail)) != 0) {

		    if (error == ENODEV) {
			volume_set_error(
				gettext("%s requested component does not "
					"exist: \"%s\"."),
				voltype, cname);
			error = -1;
		    }
		    continue;
		}

		if (is_avail != B_TRUE) {
		    volume_set_error(
			    gettext("%s requested component is "
				    "unavailable: \"%s\"."),
			    voltype, cname);

		    error = -1;
		    continue;
		}

		/* get slice and its disk */
		((error = slice_get_by_name(cname, &slice)) != 0) ||
		(error = slice_get_disk(slice, &disk)) ||
		(error = is_reserved_slice(slice, &is_rsvd)) ||
		(error = is_disk_in_diskset(disk, dsname, &in_set));
		if (error != 0) {
		    continue;
		}

		/* is disk in the set? */
		if (in_set != B_TRUE) {
		    volume_set_error(
			    gettext("%s specifies a component not in "
				    "disk set \"%s\": \"%s\"."),
			    voltype, dsname, cname);

		    error = -1;
		    continue;
		}

		/* was slice specified in some other request? */
		if (is_rsvd == B_TRUE) {
		    /* include aliases in the error */
		    char *aliases =
			get_device_aliases_string((dm_descriptor_t)slice);

		    if (aliases[0] != NULL) {
			volume_set_error(
				gettext("%s specifies a previously used "
					"component: \"%s\" "
					"(aliases: %s).\n"),
				voltype, cname, aliases);
		    } else {
			volume_set_error(
				gettext("%s specifies a previously used "
					"component: \"%s\"\n"),
				voltype, cname);
		    }

		    error = -1;
		    continue;
		}

		/* component is ok, reserve it */
		error = add_reserved_slice(slice);

		/*
		 * the reserved slice component still needs to be
		 * checked against slices in use by SVM, but that
		 * information isn't available yet: the usable
		 * slice derivation happens after validation.
		 *
		 * validate_reserved_slices() can be used to check
		 * them once the usable slices are determined.
		 */

	    } else {
		volume_set_error(
			gettext("%s requested component has illegal type."),
			voltype);

		error = -1;
		continue;
	    }
	}

	if (error != 0) {
	    return (error);
	}

	ncomp = dlist_length(list);
	if ((ncomp > 0) && (type == TYPE_CONCAT || type == TYPE_STRIPE)) {
	    /* explicit size requested for the stripe/concat? */
	    uint64_t	size = 0;
	    if ((error = devconfig_get_size(req, &size)) != 0) {
		if (error == ERR_ATTR_UNSET) {
		    error = 0;
		}
	    } else {
		/* size and components both specified */
		char *sizestr = NULL;

		(void) bytes_to_sizestr(
			size, &sizestr, universal_units, B_FALSE);

		volume_set_error(
			gettext("%s specifies both an explicit size (%s) "
				"and components."),
			voltype, sizestr);

		free(sizestr);
		error = -1;
	    }
	}

	if (error != 0) {
	    return (error);
	}

	if ((ncomp > 0) && (type == TYPE_STRIPE)) {
	    /* does # of components agree with min & max comps? */
	    uint16_t min = 0;
	    uint16_t max = 0;
	    if ((error = devconfig_get_stripe_mincomp(req, &min)) != 0) {
		if (error == ERR_ATTR_UNSET) {
		    /* min comp not requested */
		    error = 0;
		} else {
		    /* error getting requested mincomp */
		    return (error);
		}

	    } else if (ncomp < min) {
		/* specified comps < requested mincomp */
		volume_set_error(
			gettext("%s specifies fewer components (%d) than the "
				"minimum number requested (%d).\n"),
			voltype, ncomp, min);

		error = -1;
		return (error);
	    }

	    if ((error = devconfig_get_stripe_maxcomp(req, &max)) != 0) {
		if (error == ERR_ATTR_UNSET) {
		    /* max comp not requested */
		    error = 0;
		} else {
		    /* error getting request maxcomp */
		    return (error);
		}
	    } else if (ncomp > max) {
		/* specified comps > requested maxcomp */
		volume_set_error(
			gettext("%s specifies more components (%d) than the "
				"maximum number requested (%d).\n"),
			voltype, ncomp, max);
		error = -1;
		return (error);
	    }
	}

	return (error);
}

/*
 * Generate a list of known aliases for the input descriptor.
 *
 * The returned string buffer is in the form: "alias1", "alias2"...
 */
static char *
get_device_aliases_string(
	dm_descriptor_t desc)
{
	static char buf[BUFSIZ];
	dlist_t *aliases = NULL;
	dlist_t *iter = NULL;

	buf[0] = '\0';
	(void) get_aliases(desc, &aliases);
	for (iter = aliases; iter != NULL; iter = iter->next) {
	    if (*buf == '\0') {
		(void) snprintf(buf, BUFSIZ-1, "\"%s\"", (char *)iter->obj);
	    } else {
		char tmp[BUFSIZ];
		(void) strcpy(buf, tmp);
		(void) snprintf(buf, BUFSIZ-1, "%s, \"%s\"",
			tmp, (char *)iter->obj);
	    }
	}
	dlist_free_items(aliases, free);

	return (buf);
}
