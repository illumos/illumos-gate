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

#include <string.h>
#include <libintl.h>

#include "libdiskmgt.h"

#include "volume_error.h"
#include "volume_defaults.h"
#include "volume_devconfig.h"
#include "volume_dlist.h"
#include "volume_output.h"
#include "volume_request.h"

#include "layout_concat.h"
#include "layout_device_cache.h"
#include "layout_device_util.h"
#include "layout_discovery.h"
#include "layout_dlist_util.h"
#include "layout_messages.h"
#include "layout_request.h"
#include "layout_slice.h"
#include "layout_svm_util.h"

#define	_LAYOUT_CONCAT_C

static int
compose_concat_within_hba(
	devconfig_t	*request,
	dlist_t		*hbas,
	uint64_t	nbytes,
	devconfig_t	**concat);

static int
assemble_concat(
	devconfig_t	*request,
	dlist_t		*comps,
	devconfig_t	**concat);

/*
 * FUNCTION:	layout_concat(devconfig_t *request, uint64_t nbytes,
 *			dlist_t **results)
 *
 * INPUT:	request	- pointer to a devconfig_t of the current request
 *		nbytes	- the desired capacity of the concat
 *
 * OUPUT:	results	- pointer to a list of composed volumes
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Main layout driver for composing concat volumes.
 *
 *		Attempts to construct a concat of size nbytes.
 *
 *		Several different layout strategies are tried in order
 *		of preference until one succeeds or there are none left.
 *
 *		1 - concat within an HBA
 *		    . requires sufficient space available on the HBA
 *
 *		2 - concat across all available similar HBAs
 *
 *		3 - concat across all available HBAs
 *
 *		get available HBAs
 *
 *		group HBAs by characteristics
 *		for (each HBA grouping) and (concat not composed) {
 *		    select next HBA group
 *		    for (strategy[1,2]) and (concat not composed) {
 *			compose concat using HBAs in group
 *		    }
 *		}
 *
 *		if (concat not composed) {
 *		    for (strategy[3]) and (concat not composed) {
 *			compose concat using all HBAs
 *		    }
 *		}
 *
 *		if (concat composed) {
 *		    append composed concat to results
 *		}
 */
int
layout_concat(
	devconfig_t	*request,
	uint64_t	nbytes,
	dlist_t		**results)
{
	/*
	 * these enums define the # of strategies and the preference order
	 * in which they are tried
	 */
	typedef enum {
		CONCAT_WITHIN_SIMILAR_HBA = 0,
		CONCAT_ACROSS_SIMILAR_HBAS,
		N_SIMILAR_HBA_STRATEGIES
	} similar_hba_strategy_order_t;

	typedef enum {
		CONCAT_ACROSS_ANY_HBAS = 0,
		N_ANY_HBA_STRATEGIES
	} any_hba_strategy_order_t;

	dlist_t		*usable_hbas = NULL;
	dlist_t		*similar_hba_groups = NULL;
	dlist_t		*iter = NULL;
	devconfig_t  	*concat = NULL;

	int		error = 0;

	(error = get_usable_hbas(&usable_hbas));
	if (error != 0) {
	    volume_set_error(gettext("There are no usable HBAs."));
	    return (error);
	}

	print_layout_volume_msg(devconfig_type_to_str(TYPE_CONCAT), nbytes);

	if (dlist_length(usable_hbas) == 0) {
	    print_no_hbas_msg();
	    return (-1);
	}

	error = group_similar_hbas(usable_hbas, &similar_hba_groups);
	if (error != 0) {
	    return (error);
	}

	for (iter = similar_hba_groups;
	    (error == 0) && (concat == NULL) && (iter != NULL);
	    iter = iter->next) {

	    dlist_t *hbas = (dlist_t *)iter->obj;

	    similar_hba_strategy_order_t order;

	    for (order = CONCAT_WITHIN_SIMILAR_HBA;
		(order < N_SIMILAR_HBA_STRATEGIES) &&
			(concat == NULL) && (error == 0);
		order++) {

		dlist_t	*selhbas = NULL;
		dlist_t	*disks = NULL;

		switch (order) {

		case CONCAT_WITHIN_SIMILAR_HBA:

		    error = select_hbas_with_n_disks(
			    request, hbas, 1, &selhbas, &disks);

		    if (error == 0) {

/* BEGIN CSTYLED */
oprintf(OUTPUT_TERSE, 
	gettext("  -->Strategy 1: use disks from a single HBA - concat within HBA\n"));
/* END CSTYLED */

			error = compose_concat_within_hba(
				request, selhbas, nbytes, &concat);
		    }

		    break;

		case CONCAT_ACROSS_SIMILAR_HBAS:

		    error = select_hbas_with_n_disks(
			    request, hbas, 1, &selhbas, &disks);

		    if (error == 0) {

/* BEGIN CSTYLED */
oprintf(OUTPUT_TERSE, 
	gettext("  -->Strategy 2: use disks from all similar HBAs - concat across HBAs\n"));
/* END CSTYLED */

			error = populate_concat(
				request, nbytes, disks,
				NULL, &concat);
		    }

		    break;

		default:
		    break;
		}

		dlist_free_items(disks, NULL);
		dlist_free_items(selhbas, NULL);
	    }
	}

	for (iter = similar_hba_groups; iter != NULL; iter = iter->next) {
	    dlist_free_items((dlist_t *)iter->obj, NULL);
	}
	dlist_free_items(similar_hba_groups, NULL);

	/* try all HBAs */
	if (concat == NULL && error == 0) {

	    any_hba_strategy_order_t order;

	    for (order = CONCAT_ACROSS_ANY_HBAS;
		(order < N_ANY_HBA_STRATEGIES) &&
			(concat == NULL) && (error == 0);
		order++) {

		dlist_t	*selhbas = NULL;
		dlist_t	*disks = NULL;

		switch (order) {

		case CONCAT_ACROSS_ANY_HBAS:

		    error = select_hbas_with_n_disks(
			    request, usable_hbas, 1, &selhbas, &disks);

		    if (error == 0) {

/* BEGIN CSTYLED */
oprintf(OUTPUT_VERBOSE,
	gettext("  -->Strategy 3: use disks from all available HBAs - concat across HBAs\n"));
/* END CSTYLED */

			error = populate_concat(
				request, nbytes, disks,
				NULL, &concat);
		    }

		    break;

		default:
		    break;
		}

		dlist_free_items(disks, NULL);
		dlist_free_items(selhbas, NULL);
	    }
	}

	if (concat != NULL) {

	    dlist_t *item = dlist_new_item(concat);
	    if (item == NULL) {
		error = ENOMEM;
	    } else {

		*results = dlist_append(item, *results, AT_TAIL);

		print_layout_success_msg();
	    }

	} else if (error != 0) {

	    print_debug_failure_msg(
		    devconfig_type_to_str(TYPE_CONCAT),
		    get_error_string(error));

	} else {

	    print_insufficient_resources_msg(
		    devconfig_type_to_str(TYPE_CONCAT));
	    error = -1;
	}

	return (error);
}

static int
compose_concat_within_hba(
	devconfig_t	*request,
	dlist_t		*hbas,
	uint64_t	nbytes,
	devconfig_t	**concat)
{
	int		error = 0;

	dlist_t		*iter = NULL;

	for (iter = hbas;
	    (iter != NULL) && (*concat == NULL) && (error == 0);
	    iter = iter->next) {

	    dm_descriptor_t hba = (uintptr_t)iter->obj;
	    dlist_t	*disks = NULL;
	    uint64_t	space = 0;
	    char	*name;

	    /* check for sufficient space on the HBA */
	    ((error = get_display_name(hba, &name)) != 0) ||
	    (error = hba_get_avail_disks_and_space(request,
		    hba, &disks, &space));

	    if (error == 0) {
		if (space >= nbytes) {
		    error = populate_concat(request, nbytes, disks,
			    NULL, concat);
		} else {
		    print_hba_insufficient_space_msg(name, space);
		}
	    }

	    dlist_free_items(disks, NULL);
	}

	return (error);
}

/*
 * FUNCTION:	populate_concat(devconfig_t *request, uint64_t nbytes,
 *			dlist_t *disks, dlist_t *othervols,
 *			devconfig_t **concat)
 *
 * INPUT:	request	- pointer to a request devconfig_t
 *		nbytes	- desired concat size
 *		disks	- pointer to a list of availalb disks
 *		othervols - pointer to a list of other volumes whose
 *				composition may affect this concat
 *				(e.g., submirrors of the same mirror)
 *
 * OUTPUT:	concat	- pointer to a devconfig_t to hold resulting concat
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Helper to populate a concat with the specified aggregate
 *		capacity using slices on disks in the input list.
 *
 *		If the othervols list is not empty, the slice components
 *		chosen for the concat must not on the same disks as any
 *		of the other volumes.
 *
 *		If sufficient slice components can be found, the concat
 *		is assembled and returned.
 */
int
populate_concat(
	devconfig_t	*request,
	uint64_t	nbytes,
	dlist_t		*disks,
	dlist_t		*othervols,
	devconfig_t	**concat)
{
	dlist_t		*other_hbas = NULL;
	dlist_t		*other_disks = NULL;

	dlist_t		*slices = NULL;
	dlist_t		*comps = NULL;

	uint16_t	npaths	= 0;
	uint64_t	capacity = 0;
	int		error = 0;

	*concat = NULL;

	((error = disks_get_avail_slices(request, disks, &slices)) != 0) ||
	(error = get_volume_npaths(request, &npaths));
	if (error != 0) {
	    dlist_free_items(slices, NULL);
	    return (error);
	}

	print_populate_volume_msg(devconfig_type_to_str(TYPE_CONCAT), nbytes);

	if (slices == NULL) {
	    print_populate_no_slices_msg();
	    return (0);
	}

	/* determine HBAs and disks used by othervols */
	error = get_hbas_and_disks_used_by_volumes(othervols,
		&other_hbas, &other_disks);
	if (error != 0) {
	    dlist_free_items(other_hbas, NULL);
	    dlist_free_items(other_disks, NULL);
	    return (error);
	}

	print_populate_choose_slices_msg();

	while (capacity < nbytes) {

	    devconfig_t	*comp = NULL;
	    dlist_t	*item = NULL;
	    dlist_t	*rmvd = NULL;
	    char	*cname = NULL;
	    uint64_t	csize = 0;

	    /* BEGIN CSTYLED */
	    /*
	     * 1st B_TRUE: require a different disk than those used by
	     *		comps and othervols
	     * 1st B_FALSE: slice with size less that requested is acceptable
	     * 2nd B_FALSE: do not add an extra cylinder when resizing slice,
	     *		this is only necessary for Stripe components whose sizes
	     *		get rounded down to an interlace multiple and then down
	     *		to a cylinder boundary.
	     *
	     */
	    /* END CSTYLED */
	    error = choose_slice((nbytes-capacity), npaths, slices, comps,
		    other_hbas, other_disks, B_TRUE, B_FALSE, B_FALSE, &comp);

	    if ((error == 0) && (comp != NULL)) {

		item = dlist_new_item(comp);
		if (item == NULL) {
		    error = ENOMEM;
		} else  {

		    /* add selected component to comp list */
		    comps = dlist_append(item, comps, AT_HEAD);

		    /* remove it from the available list */
		    slices = dlist_remove_equivalent_item(slices, (void *) comp,
			    compare_devconfig_and_descriptor_names, &rmvd);

		    if (rmvd != NULL) {
			free(rmvd);
		    }

		    /* add the component slice to the used list */
		    if ((error = devconfig_get_name(comp, &cname)) == 0) {
			error = add_used_slice_by_name(cname);
		    }

		    /* increment concat's capacity */
		    if ((error == 0) &&
			(error = devconfig_get_size(comp, &csize)) == 0) {
			capacity += csize;
		    }
		}

	    } else {
		/* no possible slice */
		break;
	    }
	}

	dlist_free_items(slices, NULL);
	dlist_free_items(other_hbas, NULL);
	dlist_free_items(other_disks, NULL);

	if (capacity >= nbytes) {

	    error = assemble_concat(request, comps, concat);

	    if (error == 0) {
		print_populate_success_msg();
	    } else {
		/* undo any slicing done for the concat */
		dlist_free_items(comps, free_devconfig_object);
	    }

	} else if (error == 0) {

	    if (capacity > 0) {
		dlist_free_items(comps, free_devconfig_object);
		print_insufficient_capacity_msg(capacity);
	    } else {
		print_populate_no_slices_msg();
	    }

	}

	return (error);
}

/*
 * FUNCTION:	populate_explicit_concat(devconfig_t *request,
 *			dlist_t **results)
 *
 * INPUT:	request	- pointer to a request devconfig_t
 *
 * OUTPUT:	results	- pointer to a list of volume devconfig_t results
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Processes the input concat request that specifies explicit
 *		slice components.
 *
 *		The components have already been validated and reserved,
 *		all that is required is to create devconfig_t structs
 *		for each requested slice.
 *
 *		The net size of the concat is determined by the slice
 *		components.
 *
 *		The concat devconfig_t is assembled and appended to the
 *		results list.
 *
 *		This function is also called from
 *		    layout_mirror.populate_explicit_mirror()
 */
int
populate_explicit_concat(
	devconfig_t	*request,
	dlist_t		**results)
{
	int		error = 0;

	dlist_t		*comps = NULL;
	dlist_t		*iter = NULL;
	dlist_t		*item = NULL;

	devconfig_t	*concat = NULL;

	print_layout_explicit_msg(devconfig_type_to_str(TYPE_CONCAT));

	/* assemble components */
	iter = devconfig_get_components(request);
	for (; (iter != NULL) && (error == 0); iter = iter->next) {

	    devconfig_t	*rqst = (devconfig_t *)iter->obj;
	    dm_descriptor_t rqst_slice = NULL;
	    char	*rqst_name = NULL;
	    devconfig_t	*comp = NULL;

	    /* slice components have been validated */
	    /* turn each into a devconfig_t */
	    ((error = devconfig_get_name(rqst, &rqst_name)) != 0) ||
	    (error = slice_get_by_name(rqst_name, &rqst_slice)) ||
	    (error = create_devconfig_for_slice(rqst_slice, &comp));

	    if (error == 0) {

		print_layout_explicit_added_msg(rqst_name);

		item = dlist_new_item((void *)comp);
		if (item == NULL) {
		    error = ENOMEM;
		} else {
		    comps = dlist_append(item, comps, AT_TAIL);
		}
	    }
	}

	if (error == 0) {
	    error = assemble_concat(request, comps, &concat);
	}

	if (error == 0) {
	    if ((item = dlist_new_item(concat)) == NULL) {
		error = ENOMEM;
	    } else {
		*results = dlist_append(item, *results, AT_TAIL);
		print_populate_success_msg();
	    }
	} else {
	    dlist_free_items(comps, free_devconfig);
	}

	return (error);
}

/*
 * FUNCTION:	assemble_concat(devconfig_t *request, dlist_t *comps,
 *			devconfig_t **concat)
 *
 * INPUT:	request	- pointer to a devconfig_t of the current request
 *		comps	- pointer to a list of slice components
 *
 * OUPUT:	concat	- pointer to a devconfig_t to hold final concat
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Helper which creates and populates a concat devconfig_t
 *		struct using information from the input request and the
 *		list of slice components.
 *
 *		Determines the name of the concat either from the request
 *		or from the default naming scheme.
 *
 *		Attaches the input list of components to the devconfig.
 */
static int
assemble_concat(
	devconfig_t	*request,
	dlist_t		*comps,
	devconfig_t	**concat)
{
	char		*name = NULL;
	int		error = 0;

	if ((error = new_devconfig(concat, TYPE_CONCAT)) == 0) {
	    /* set concat name, use requested name if specified */
	    if ((error = devconfig_get_name(request, &name)) != 0) {
		if (error != ERR_ATTR_UNSET) {
		    volume_set_error(gettext("error getting requested name\n"));
		} else {
		    error = 0;
		}
	    }

	    if (error == 0) {
		if (name == NULL) {
		    if ((error = get_next_volume_name(&name,
			TYPE_CONCAT)) == 0) {
			error = devconfig_set_name(*concat, name);
			free(name);
		    }
		} else {
		    error = devconfig_set_name(*concat, name);
		}
	    }
	}

	if (error == 0) {

	    /* compute and save true size of concat */
	    if (error == 0) {
		uint64_t nblks = 0;
		dlist_t *iter;

		for (iter = comps;
		    (error == 0) && (iter != NULL);
		    iter = iter->next) {

		    devconfig_t *comp = (devconfig_t *)iter->obj;
		    uint64_t comp_nblks = 0;

		    if ((error = devconfig_get_size_in_blocks(comp,
			&comp_nblks)) == 0) {
			nblks += comp_nblks;
		    }
		}

		if (error == 0) {
		    error = devconfig_set_size_in_blocks(*concat, nblks);
		}
	    }
	}

	if (error == 0) {
	    devconfig_set_components(*concat, comps);
	} else {
	    free_devconfig(*concat);
	    *concat = NULL;
	}

	return (error);
}
