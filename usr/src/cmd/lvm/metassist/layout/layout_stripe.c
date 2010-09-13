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

#include "volume_error.h"
#include "volume_devconfig.h"
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

#define	_LAYOUT_STRIPE_C

static int compose_stripe(
	devconfig_t	*request,
	uint64_t	nbytes,
	dlist_t		*disks,
	int		max,
	int		min,
	dlist_t		*othervols,
	devconfig_t	**stripe);

static int compose_stripe_within_hba(
	devconfig_t	*request,
	dlist_t		*hbas,
	uint64_t	nbytes,
	uint16_t	min,
	uint16_t	max,
	devconfig_t	**stripe);

static int assemble_stripe(
	devconfig_t	*request,
	dlist_t		*comps,
	devconfig_t	**stripe);

static dlist_t *
order_stripe_components_alternate_hbas(
	dlist_t *comps);

static int compute_usable_stripe_capacity(
	dlist_t		*comps,
	uint64_t	ilace,
	uint64_t	*nbytes);

/*
 * FUNCTION:	layout_stripe(devconfig_t *request, uint64_t nbytes,
 *			dlist_t **results)
 *
 * INPUT:	request	- pointer to a devconfig_t of the current request
 *		nbytes	- the desired capacity of the stripe
 *
 * OUPUT:	results	- pointer to a list of composed volumes
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Main layout driver for composing stripe volumes.
 *
 *		Attempts to construct a stripe of size nbytes.
 *
 *		Basic goal of all strategies is to build wide-thin stripes:
 *		build widest stripe possible across as many HBAs as possible.
 *
 *		Several different layout strategies are tried in order
 *		of preference until one succeeds or there are none left.
 *
 *		1 - stripe across similar HBAs
 *		    . number of components is driven by # of HBAs
 *		    . requires mincomp available HBAs
 *
 *		2 - stripe within a single HBA
 *		    . number of components is driven by # of disks
 *		    . requires at least 1 HBA with mincomp disks
 *
 *		3 - stripe across all available disks on similar HBAs
 *		    . number of components is driven by # of disk
 *		    . requires at least mincomp disks
 *
 *		4 - stripe across all available HBAs
 *		    . number of components is driven by # of HBAs
 *		    . requires at least mincomp HBAs
 *
 *		5 - stripe across all available disks on all HBAs
 *		    . number of components is driven by # of disks
 *		    . requires at least mincomp disks
 *
 *		Each strategy tries to compose a stripe with the
 *		maximum number of components first then reduces the
 *		number of components down to mincomp.
 *
 *		get allowed minimum number of stripe components
 *		get allowed maximum number of stripe components
 *		get available HBAs
 *
 *		group HBAs by characteristics
 *		for (each HBA grouping) and (stripe not composed) {
 *		    select next HBA group
 *		    for (strategy[1,2,3]) and (stripe not composed) {
 *			compose stripe using HBAs in group
 *		    }
 *		}
 *
 *		if (stripe not composed) {
 *		    for (strategy[4,5]) and (stripe not composed) {
 *			compose stripe using all HBAs
 *		    }
 *		}
 *
 *		if (stripe composed) {
 *		    append composed stripe to results
 *		}
 *
 */
int
layout_stripe(
	devconfig_t	*request,
	uint64_t	nbytes,
	dlist_t		**results)
{
	/*
	 * these enums define the # of strategies and the preference order
	 * in which they are tried
	 */
	typedef enum {
		STRIPE_ACROSS_SIMILAR_HBAS_DISK_PER = 0,
		STRIPE_WITHIN_SIMILAR_HBA,
		STRIPE_ACROSS_SIMILAR_HBAS,
		N_SIMILAR_HBA_STRATEGIES
	} similar_hba_strategy_order_t;

	typedef enum {
		STRIPE_ACROSS_ANY_HBAS_DISK_PER = 0,
		STRIPE_ACROSS_ANY_HBAS,
		N_ANY_HBA_STRATEGIES
	} any_hba_strategy_order_t;


	dlist_t		*usable_hbas = NULL;
	dlist_t		*similar_hba_groups = NULL;
	dlist_t		*iter = NULL;
	devconfig_t	*stripe = NULL;

	uint16_t	mincomp	= 0;
	uint16_t	maxcomp	= 0;

	int		error = 0;

	(error = get_usable_hbas(&usable_hbas));
	if (error != 0) {
	    return (error);
	}

	print_layout_volume_msg(devconfig_type_to_str(TYPE_STRIPE), nbytes);

	if (dlist_length(usable_hbas) == 0) {
	    print_no_hbas_msg();
	    volume_set_error(gettext("There are no usable HBAs."));
	    return (-1);
	}

	((error = group_similar_hbas(usable_hbas, &similar_hba_groups)) != 0) ||

	/*
	 * determine the min/max number of stripe components
	 * based on the request, the diskset defaults or the
	 * global defaults.  These are absolute limits, the
	 * actual values are determined by the number of HBAs
	 * and/or disks available.
	 */
	(error = get_stripe_min_comp(request, &mincomp)) ||
	(error = get_stripe_max_comp(request, &maxcomp));
	if (error != 0) {
	    return (error);
	}

	for (iter = similar_hba_groups;
	    (error == 0) && (stripe == NULL) && (iter != NULL);
	    iter = iter->next) {

	    dlist_t *hbas = (dlist_t *)iter->obj;

	    similar_hba_strategy_order_t order;

	    for (order = STRIPE_ACROSS_SIMILAR_HBAS_DISK_PER;
		(order < N_SIMILAR_HBA_STRATEGIES) &&
			(stripe == NULL) && (error == 0);
		order++) {

		dlist_t *selhbas = NULL;
		dlist_t	*disks = NULL;
		int	n = 0;

		switch (order) {

		case STRIPE_ACROSS_SIMILAR_HBAS_DISK_PER:

		    error = select_hbas_with_n_disks(
			    request, hbas, 1, &selhbas, &disks);

		    if (error == 0) {

/* BEGIN CSTYLED */
oprintf(OUTPUT_TERSE,
gettext("  -->Strategy 1: use 1 disk from %d-%d similar HBAs - stripe across HBAs\n"),
	mincomp, maxcomp);
/* END CSTYLED */

			if ((n = dlist_length(selhbas)) >= mincomp) {
			    n = ((n > maxcomp) ? maxcomp : n);
			    error = compose_stripe(
				    request, nbytes, disks, n,
				    mincomp, NULL, &stripe);
			} else {
			    print_insufficient_hbas_msg(n);
			}
		    }

		    break;

		case STRIPE_WITHIN_SIMILAR_HBA:

		    error = select_hbas_with_n_disks(
			    request, hbas, mincomp, &selhbas, &disks);

		    if (error == 0) {

/* BEGIN CSTYLED */
oprintf(OUTPUT_TERSE,
gettext("  -->Strategy 2: use %d-%d disks from any single HBA - stripe within HBA\n"),
	mincomp, maxcomp);
/* END CSTYLED */

			if ((n = dlist_length(selhbas)) > 0) {
			    error = compose_stripe_within_hba(
				    request, selhbas, nbytes,
				    mincomp, maxcomp, &stripe);
			} else {
			    print_insufficient_disks_msg(n);
			}
		    }

		    break;

		case STRIPE_ACROSS_SIMILAR_HBAS:

		    error = select_hbas_with_n_disks(
			    request, hbas, 1, &selhbas, &disks);

		    if (error == 0) {

/* BEGIN CSTYLED */
oprintf(OUTPUT_TERSE,
gettext("  -->Strategy 3: use %d-%d disks from %d similar HBAs - stripe across HBAs\n"),
	mincomp, maxcomp, dlist_length(hbas));
/* END CSTYLED */

			if ((n = dlist_length(selhbas)) > 0) {
			    if ((n = dlist_length(disks)) >= mincomp) {
				n = ((n > maxcomp) ? maxcomp : n);
				error = compose_stripe(
					request, nbytes, disks, n,
					mincomp, NULL, &stripe);
			    } else {
				print_insufficient_disks_msg(n);
			    }
			} else {
			    print_insufficient_hbas_msg(n);
			}
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

	/*
	 * if striping within similar HBA groups failed,
	 * try across all available HBAs
	 */
	if ((stripe == NULL) && (error == 0)) {

	    any_hba_strategy_order_t order;

	    for (order = STRIPE_ACROSS_ANY_HBAS_DISK_PER;
		(order < N_ANY_HBA_STRATEGIES) &&
			(stripe == NULL) && (error == 0);
		order++) {

		dlist_t	*selhbas = NULL;
		dlist_t	*disks = NULL;
		int	n = 0;

		switch (order) {

		case STRIPE_ACROSS_ANY_HBAS_DISK_PER:

		    error = select_hbas_with_n_disks(
			    request, usable_hbas, 1, &selhbas, &disks);

		    if (error == 0) {

/* BEGIN CSTYLED */
oprintf(OUTPUT_TERSE,
gettext("  -->Strategy 4: use 1 disk from %d-%d available HBAs - stripe across any HBAs\n"),
	mincomp, maxcomp);
/* END CSTYLED */

			if ((n = dlist_length(selhbas)) >= mincomp) {

			    n = ((n > maxcomp) ? maxcomp : n);
			    error = compose_stripe(
				    request, nbytes, disks, n,
				    mincomp, NULL, &stripe);

			} else {
			    print_insufficient_hbas_msg(n);
			}
		    }

		    break;

		case STRIPE_ACROSS_ANY_HBAS:

		    error = select_hbas_with_n_disks(
			    request, usable_hbas, 1, &selhbas, &disks);

		    if (error == 0) {

/* BEGIN CSTYLED */
oprintf(OUTPUT_TERSE,
gettext("  -->Strategy 5: use %d-%d disks from %d available HBA - stripe across any HBAs\n"),
	mincomp, maxcomp, dlist_length(selhbas));
/* END CSTYLED */

			if ((n = dlist_length(disks)) >= mincomp) {

			    n = ((n > maxcomp) ? maxcomp : n);
			    error = compose_stripe(
				    request, nbytes, disks, n,
				    mincomp, NULL, &stripe);

			} else {
			    print_insufficient_disks_msg(n);
			}
		    }

		    break;
		}

		dlist_free_items(disks, NULL);
		dlist_free_items(selhbas, NULL);
	    }
	}

	if (stripe != NULL) {

	    dlist_t *item = NULL;
	    if ((item = dlist_new_item(stripe)) == NULL) {
		error = ENOMEM;
	    } else {
		*results = dlist_append(item, *results, AT_TAIL);
		print_layout_success_msg();
	    }

	} else if (error != 0) {

	    print_debug_failure_msg(
		    devconfig_type_to_str(TYPE_STRIPE),
		    get_error_string(error));

	} else {

	    print_insufficient_resources_msg(
		    devconfig_type_to_str(TYPE_STRIPE));
	    error = -1;
	}

	return (error);
}

/*
 * FUNCTION:	populate_stripe(devconfig_t *request, uint64_t nbytes,
 *			dlist_t *disks, uint16_t ncomp, dlist_t *othervols,
 *			devconfig_t **stripe)
 *
 * INPUT:	request	- pointer to a request devconfig_t
 *		nbytes	- desired stripe size
 *		disks	- pointer to a list of availalb disks
 *		ncomp	- number of components desired
 *		othervols - pointer to a list of other volumes whose
 *				composition may affect this stripe
 *				(e.g., submirrors of the same mirror)
 *
 * OUTPUT:	stripe	- pointer to a devconfig_t to hold resulting stripe
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Helper to populate a stripe with the specified number of
 *		components and aggregate capacity using slices on disks
 *		in the input list.
 *
 *		If the othervols list is not empty, the slice components
 *		chosen for the stripe must not on the same disks as any
 *		of the other volumes.
 *
 *		If sufficient slice components can be found, the stripe
 *		is assembled and returned.
 */
int
populate_stripe(
	devconfig_t	*request,
	uint64_t	nbytes,
	dlist_t		*disks,
	uint16_t	ncomp,
	dlist_t		*othervols,
	devconfig_t	**stripe)
{
	uint16_t	npaths = 0;
	uint16_t	ncomps = 0;	/* number of components found */
	uint64_t	rsize = 0;	/* reqd component size */

	dlist_t		*other_hbas = NULL;
	dlist_t		*other_disks = NULL;

	dlist_t		*slices = NULL;
	dlist_t		*comps = NULL;

	int		error = 0;

	*stripe = NULL;

	((error = disks_get_avail_slices(request, disks, &slices)) != 0) ||
	(error = get_volume_npaths(request, &npaths));
	if (error != 0) {
	    return (error);
	}

	print_populate_volume_ncomps_msg(
		devconfig_type_to_str(TYPE_STRIPE), nbytes, ncomp);

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

	/*
	 * each stripe component needs to be this size.
	 * Note that the stripe interlace doesn't need to be
	 * taken into account in this computation because any
	 * slice selected as a stripe component will be oversized
	 * to account for interlace and cylinder rounding done
	 * by libmeta.
	 */
	rsize = nbytes / ncomp;

	/*
	 * need to select 'ncomp' slices that are at least 'rsize'
	 * large in order to reach the desired capacity.
	 */
	ncomps = 0;
	while ((ncomps < ncomp) && (error == 0)) {

	    devconfig_t	*comp = NULL;
	    dlist_t	*item = NULL;
	    dlist_t	*rmvd = NULL;
	    char	*cname = NULL;

	    /* BEGIN CSTYLED */
	    /*
	     * 1st B_TRUE: require a different disk than those used by
	     *		comps and othervols
	     * 2nd B_TRUE: requested size is minimum acceptable
	     * 3rd B_TRUE: add an extra cylinder to the resulting slice, this is
	     *		necessary for Stripe components whose sizes get rounded
	     *		down to an interlace multiple and then down to a cylinder
	     *		boundary.
	     */
	    /* END CSTYLED */
	    error = choose_slice(rsize, npaths, slices, comps,
		    other_hbas, other_disks, B_TRUE, B_TRUE, B_TRUE, &comp);

	    if ((error == 0) && (comp != NULL)) {

		++ncomps;

		item = dlist_new_item(comp);
		if (item == NULL) {
		    error = ENOMEM;
		} else {

		    /* add selected component to comp list */
		    comps = dlist_insert_ordered(
			    item,
			    comps,
			    ASCENDING,
			    compare_devconfig_sizes);

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
		}
	    } else if (comp == NULL) {
		/* no possible slice */
		break;
	    }
	}

	dlist_free_items(slices, NULL);
	dlist_free_items(other_hbas, NULL);
	dlist_free_items(other_disks, NULL);

	if (ncomps == ncomp) {

	    if ((error = assemble_stripe(request, comps, stripe)) == 0) {
		print_populate_success_msg();
	    } else {
		dlist_free_items(comps, free_devconfig_object);
	    }

	} else if (error == 0) {

	    if (ncomps > 0) {
		print_insufficient_components_msg(ncomps);
		dlist_free_items(comps, free_devconfig_object);
	    } else {
		print_populate_no_slices_msg();
	    }

	}
	return (error);
}

/*
 * FUNCTION:	populate_explicit_stripe(devconfig_t *request,
 *			dlist_t **results)
 *
 * INPUT:	request	- pointer to a request devconfig_t
 *
 * OUTPUT:	results	- pointer to a list of volume devconfig_t results
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Processes the input stripe request that specifies explicit
 *		slice components.
 *
 *		The components have already been validated and reserved,
 *		all that is required is to create devconfig_t structs
 *		for each requested slice.
 *
 *		The net size of the stripe is determined by the slice
 *		components.
 *
 *		The stripe devconfig_t is assembled and appended to the
 *		results list.
 *
 *		This function is also called from
 *		    layout_mirror.populate_explicit_mirror()
 */
int
populate_explicit_stripe(
	devconfig_t	*request,
	dlist_t		**results)
{
	devconfig_t	*stripe = NULL;
	int		error = 0;

	dlist_t		*comps = NULL;
	dlist_t		*iter = NULL;
	dlist_t		*item = NULL;

	print_layout_explicit_msg(devconfig_type_to_str(TYPE_STRIPE));

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
	    error = assemble_stripe(request, comps, &stripe);
	}

	if (error == 0) {
	    if ((item = dlist_new_item(stripe)) == NULL) {
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
 * FUNCTION:	compose_stripe(devconfig_t *request, uint64_t nbytes,
 *			dlist_t *disks, uint16_t max, uint16_t min,
 *			dlist_t *othervols, devconfig_t **stripe)
 *
 * INPUT:	request	- pointer to a request devconfig_t
 *		nbytes	- desired stripe size
 *		disks	- pointer to a list of availalb disks
 *		max	- maximum number of components allowed
 *		min	- minimum number of components allowed
 *		othervols - pointer to a list of other volumes whose
 *				composition may affect this stripe
 *				(e.g., submirrors of the same mirror)
 *
 * OUTPUT:	stripe	- pointer to a devconfig_t to hold resulting stripe
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Attempt to compose a stripe of capacity nbytes, with
 *		component slices chosen from the input list of disks.
 *		The number of components in the stripe should be in the
 *		range min <= N <= max, more components are preferred.
 *
 *		If a stripe can be composed, a pointer to it will be
 *		returned in the stripe devconfig_t.
 *
 *		This is a loop wrapped around populate_stripe which
 *		varies the number of components between 'max' and 'min'.
 */
static int
compose_stripe(
	devconfig_t	*request,
	uint64_t	nbytes,
	dlist_t		*disks,
	int		max,
	int		min,
	dlist_t		*othervols,
	devconfig_t	**stripe)
{
	int		error = 0;

	*stripe = NULL;

	for (; (error == 0) && (*stripe == NULL) && (max >= min); max--) {
	    error = populate_stripe(
		    request, nbytes, disks, max, othervols, stripe);
	}

	return (error);
}

/*
 * FUNCTION:	compose_stripe_within_hba(devconfig_t *request,
 *			dlist_t *hbas, uint64_t nbytes,
 *			int maxcomp, int mincomp, dlist_t **stripe)
 *
 * INPUT:	request	- pointer to a devconfig_t of the current request
 *		hbas	- pointer to a list of available HBAs
 *		nbytes	- the desired capacity for the stripe
 *		maxcomp - the maximum number of stripe components
 *		mincomp - the minimum number of stripe components
 *
 * OUTPUT:	stripe	- pointer to a stripe devconfig_t result
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Layout function which compose a stripe of the desired size
 *		using available disks within any single HBA from the input list.
 *
 *		The number of components within the composed stripe will be
 *		in the range of min to max, preferring more components
 *		over fewer.
 *
 * 		All input HBAs are expected to have at least mincomp
 *		available disks and total space sufficient for the stripe.
 *
 *		If the stripe can be composed, a pointer to it is returned in
 *		the stripe devconfig_t *.
 *
 *
 *		while (more hbas and stripe not composed) {
 *		    select HBA
 *		    if (not enough available space on this HBA) {
 *			continue;
 *		    }
 *		    get available disks for HBA
 *		    use # disks as max # of stripe components
 *		    try to compose stripe
 *		}
 *
 */
static int
compose_stripe_within_hba(
	devconfig_t	*request,
	dlist_t		*hbas,
	uint64_t	nbytes,
	uint16_t	min,
	uint16_t	max,
	devconfig_t	**stripe)
{
	int		error = 0;

	dlist_t		*iter = NULL;

	*stripe = NULL;

	for (iter = hbas;
	    (iter != NULL) && (error == 0) && (*stripe == NULL);
	    iter = iter->next) {

	    dm_descriptor_t hba = (uintptr_t)iter->obj;
	    dlist_t	*disks = NULL;
	    uint64_t	space = 0;
	    uint16_t	ncomp = 0;
	    char	*name;

	    ((error = get_display_name(hba, &name)) != 0) ||
	    (error = hba_get_avail_disks_and_space(request,
		    hba, &disks, &space));

	    if (error == 0) {
		if (space >= nbytes) {
		    ncomp = dlist_length(disks);
		    ncomp = ((ncomp > max) ? max : ncomp);
		    error = compose_stripe(
			    request, nbytes, disks, ncomp,
			    min, NULL, stripe);
		} else {
		    print_hba_insufficient_space_msg(name, space);
		}
	    }

	    dlist_free_items(disks, NULL);
	}

	return (error);
}

/*
 * FUNCTION:	assemble_stripe(devconfig_t *request, dlist_t *comps,
 *			devconfig_t **stripe)
 *
 * INPUT:	request	- pointer to a devconfig_t of the current request
 *		comps	- pointer to a list of slice components
 *
 * OUPUT:	stripe	- pointer to a devconfig_t to hold final stripe
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Helper which creates and populates a stripe devconfig_t
 *		struct using information from the input request and the
 *		list of slice components.
 *
 *		Determines the name of the stripe either from the request
 *		or from the default naming scheme.
 *
 *		Sets the interlace for the stripe if a value is specified
 *		in the request.
 *
 *		Attaches the input list of components to the devconfig.
 */
static int
assemble_stripe(
	devconfig_t	*request,
	dlist_t		*comps,
	devconfig_t	**stripe)
{
	uint64_t ilace = 0;
	char	*name = NULL;
	int	error = 0;

	if ((error = new_devconfig(stripe, TYPE_STRIPE)) == 0) {
	    /* set stripe name, use requested name if specified */
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
			TYPE_STRIPE)) == 0) {
			error = devconfig_set_name(*stripe, name);
			free(name);
		    }
		} else {
		    error = devconfig_set_name(*stripe, name);
		}
	    }
	}

	if (error == 0) {
	    if ((error = get_stripe_interlace(request, &ilace)) == 0) {
		error = devconfig_set_stripe_interlace(*stripe, ilace);
	    } else if (error == ENOENT) {
		ilace = get_default_stripe_interlace();
		error = 0;
	    }
	}

	if (error == 0) {
	    uint64_t	nbytes = 0;
	    if ((error = compute_usable_stripe_capacity(comps,
		ilace, &nbytes)) == 0) {
		error = devconfig_set_size_in_blocks(*stripe, nbytes/DEV_BSIZE);
	    }
	}

	if (error == 0) {
	    comps = order_stripe_components_alternate_hbas(comps);
	    devconfig_set_components(*stripe, comps);
	} else {
	    free_devconfig(*stripe);
	    *stripe = NULL;
	}

	return (error);
}

/*
 * Order the given stripe component list such that the number of
 * slices on the same hba adjacent to each other in the list are
 * minimized.
 *
 * @param       comps
 *              the slice component list to order
 *
 * @return      the first element of the resulting list
 */
static dlist_t *
order_stripe_components_alternate_hbas(
	dlist_t *comps)
{
	dlist_t *iter;

	oprintf(OUTPUT_DEBUG,
	    gettext("Stripe components before ordering to alternate HBAs:\n"));

	for (iter = comps; iter != NULL; iter = iter->next) {
	    devconfig_t *slice = (devconfig_t *)(iter->obj);
	    char *name;
	    devconfig_get_name(slice, &name);
	    oprintf(OUTPUT_DEBUG, "  %s\n", name);
	}

	return (dlist_separate_similar_elements(
	    comps, compare_slices_on_same_hba));
}

/*
 * FUNCTION:	compute_usable_stripe_capacity(dlist_t *comps, uint64_t ilace,
 *			uint64_t *nbytes)
 *
 * INPUT:	comps	- pointer to a list of stripe components
 *		ilace	- the expected stripe interlace in bytes
 *
 * OUPUT:	nbytes	- pointer to hold the computed capacity
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Helper which computes the usable size of a stripe taking
 *		into account the interlace and cylinder rounding that
 *		libmeta uses: a stripe component's size is rounded down to
 *		an integral multiple of the interlace and then rounded down
 *		to a cylinder boundary on VTOC labeled disks.
 *
 *		(These libmeta computations are in the meta_stripe_attach()
 *		 function of .../lib/lvm/libmeta/common/meta_stripe.c and
 *		 meta_adjust_geom() in .../lib/lvm/libmeta/common/meta_init.c)
 *
 *		This function's implementation iterates the input list of
 *		stripe component slices and determines the smallest usable
 *		component capacity.
 *
 *		The usable stripe capacity is then that component capacity
 *		times the number of components.
 */
static int
compute_usable_stripe_capacity(
	dlist_t		*comps,
	uint64_t	ilace,
	uint64_t	*nbytes)
{
	uint64_t	bytes_per_component = 0;
	dlist_t		*iter;
	int		ncomps = 0;
	int		error = 0;

	for (iter = comps; (iter != NULL) && (error == 0); iter = iter->next) {

	    devconfig_t		*comp = (devconfig_t *)iter->obj;
	    char		*comp_name = NULL;
	    uint64_t 		comp_nbytes = 0;
	    dm_descriptor_t	comp_disk;
	    boolean_t		comp_disk_efi = B_FALSE;
	    uint64_t 		comp_disk_bps = 0; /* disk bytes per sector */

	    ((error = devconfig_get_size(comp, &comp_nbytes)) != 0) ||
	    (error = devconfig_get_name(comp, &comp_name)) ||
	    (error = get_disk_for_named_slice(comp_name, &comp_disk)) ||
	    (error = disk_get_blocksize(comp_disk, &comp_disk_bps)) ||
	    (error = disk_get_is_efi(comp_disk, &comp_disk_efi));
	    if (error == 0) {

		if (comp_disk_efi == B_FALSE) {
		    uint64_t	nhead = 0;
		    uint64_t	nsect = 0;
		    uint64_t	ncyls = 0;

		    /* do cylinder and interlace rounding for non-EFI disks */
		    ((error = disk_get_ncylinders(comp_disk, &ncyls)) != 0) ||
		    (error = disk_get_nheads(comp_disk, &nhead)) ||
		    (error = disk_get_nsectors(comp_disk, &nsect));
		    if (error == 0) {
			/* compute bytes per cyl */
			uint64_t bpc = nhead * nsect * comp_disk_bps;

			/* round nbytes down to a multiple of interlace */
			comp_nbytes = (comp_nbytes / ilace) * ilace;

			/* round nbytes down to a cylinder boundary */
			comp_nbytes = (comp_nbytes / bpc) * bpc;
		    }
		}

		/* save smallest component size */
		if ((bytes_per_component == 0) ||
		    (comp_nbytes < bytes_per_component)) {
		    bytes_per_component = comp_nbytes;
		}

		++ncomps;
	    }
	}

	if (error == 0) {
	    /* size of stripe = smallest component size * n components */
	    *nbytes = (bytes_per_component * ncomps);
	}

	return (error);
}
