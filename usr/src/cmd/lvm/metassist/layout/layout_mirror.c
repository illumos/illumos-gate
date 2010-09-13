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

#include <libintl.h>

#include "volume_error.h"
#include "volume_dlist.h"
#include "volume_output.h"

#include "layout_concat.h"
#include "layout_device_cache.h"
#include "layout_device_util.h"
#include "layout_discovery.h"
#include "layout_dlist_util.h"
#include "layout_messages.h"
#include "layout_request.h"
#include "layout_slice.h"
#include "layout_stripe.h"
#include "layout_svm_util.h"

#define	_LAYOUT_MIRROR_C

static int layout_stripe_submirrors(
	devconfig_t	*request,
	dlist_t		*cursubs,
	uint64_t 	nbytes,
	uint16_t	nsubs,
	dlist_t		**results);

static int layout_concat_submirrors(
	devconfig_t	*request,
	dlist_t		*cursubs,
	uint64_t 	nbytes,
	uint16_t	nsubs,
	dlist_t		**results);

static int compose_stripe_per_hba(
	devconfig_t	*request,
	dlist_t		*cursubs,
	dlist_t		*hbas,
	uint64_t	nbytes,
	uint16_t	nsubs,
	uint16_t	ncomp,
	uint16_t	mincomp,
	dlist_t		**results);

static int compose_stripes_across_hbas(
	devconfig_t	*request,
	dlist_t		*cursubs,
	dlist_t		*hbas,
	dlist_t		*disks,
	uint64_t	nbytes,
	uint16_t	nsubs,
	uint16_t	ncomp,
	uint16_t	mincomp,
	dlist_t		**results);

static int compose_stripes_within_hba(
	devconfig_t	*request,
	dlist_t		*cursubs,
	dlist_t		*hbas,
	uint64_t	nbytes,
	uint16_t	nsubs,
	uint16_t	ncomp,
	uint16_t	mincomp,
	dlist_t		**results);

static int compose_concat_per_hba(
	devconfig_t	*request,
	dlist_t		*cursubs,
	dlist_t		*hbas,
	uint64_t	nbytes,
	uint16_t	nsubs,
	dlist_t		**results);

static int compose_concats_across_hbas(
	devconfig_t	*request,
	dlist_t		*cursubs,
	dlist_t		*hbas,
	dlist_t		*disks,
	uint64_t	nbytes,
	uint16_t	nsubs,
	dlist_t		**results);

static int compose_concats_within_hba(
	devconfig_t	*request,
	dlist_t		*cursubs,
	dlist_t		*hba,
	uint64_t	nbytes,
	uint16_t	nsubs,
	dlist_t		**results);

static int assemble_mirror(
	devconfig_t	*request,
	dlist_t		*subs,
	devconfig_t	**mirror);

static int remove_used_disks(
	dlist_t		**disks,
	devconfig_t	*volume);

static int volume_shares_disk(
	dm_descriptor_t disk,
	devconfig_t	*volume,
	boolean_t	*bool);

static int select_mpxio_hbas(
	dlist_t		*hbas,
	dlist_t		**mpxio_hbas);

static int set_explicit_submirror_names(
	dlist_t		*reqs,
	dlist_t		*subs);

static int set_explicit_submirror_name(
	devconfig_t 	*req,
	devconfig_t 	*sub);

/*
 * FUNCTION:	layout_mirror(devconfig_t *request, nbytes, dlist_t **results)
 *
 * INPUT:	request	- pointer to a request devconfig_t
 *		nsubs	- number of submirrors
 *		nbytes	- desired mirror size
 *
 * OUTPUT:	results	- pointer to a list of volume devconfig_t results
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Main driver to handle a mirror request that does not specify
 *		subcomponents.
 *
 *		Striped submirrors are tried first, then concats.
 */
int
layout_mirror(
	devconfig_t	*request,
	uint16_t	nsubs,
	uint64_t 	nbytes,
	dlist_t		**results)
{
	dlist_t		*subs = NULL;
	dlist_t		*item = NULL;
	boolean_t	usehsp = B_FALSE;
	int		error = 0;

	if ((error = get_volume_faultrecov(request, &usehsp)) != 0) {
	    if (error != ERR_ATTR_UNSET) {
		return (error);
	    }
	    error = 0;
	}

	print_layout_volume_msg(devconfig_type_to_str(TYPE_MIRROR), nbytes);

	/* prefer stripe submirrors */
	if ((error = layout_stripe_submirrors(
	    request, NULL, nbytes, nsubs, &subs)) != 0) {
	    return (error);
	}

	if (subs == NULL) {
	    /* second chance: mirrored concats */
	    if ((error = layout_concat_submirrors(
		request, NULL, nbytes, nsubs, &subs)) != 0) {
		return (error);
	    }
	}

	if (subs != NULL) {

	    devconfig_t	*mirror = NULL;
	    dlist_t	*iter = NULL;

	    /* unset submirror names prior to final assembly */
	    for (iter = subs; iter != NULL; iter = iter->next) {
		devconfig_t *sub = (devconfig_t *)iter->obj;
		char *name = NULL;

		(void) devconfig_get_name(sub, &name);
		release_volume_name(name);
		(void) devconfig_set_name(sub, "");
	    }

	    error = assemble_mirror(request, subs, &mirror);
	    if (error == 0) {

		if ((item = dlist_new_item(mirror)) == NULL) {
		    error = ENOMEM;
		} else {
		    *results = dlist_append(item, *results, AT_TAIL);

		    /* remember submirrors that need HSPs */
		    if (usehsp == B_TRUE) {
			error = add_to_hsp_list(
				devconfig_get_components(mirror));
		    }

		    print_layout_success_msg();
		}
	    } else {
		/* cleanup submirrors */
		dlist_free_items(subs, free_devconfig_object);
		subs = NULL;
	    }

	} else if (error != 0) {

	    print_debug_failure_msg(devconfig_type_to_str(TYPE_MIRROR),
		    get_error_string(error));

	} else {

	    print_insufficient_resources_msg(
		    devconfig_type_to_str(TYPE_MIRROR));
	    error = -1;
	}

	return (error);
}

/*
 * FUNCTION:	populate_explicit_mirror(devconfig_t *request,
 *			dlist_t **results)
 *
 * INPUT:	request	- pointer to a request devconfig_t
 *
 * OUTPUT:	results	- pointer to a list of volume devconfig_t results
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Processes the input mirror request specifying explicit layout
 *		constraints on the submirrors.
 *
 *		Primary submirror constraint is explicit type, either
 *		stripe or concat.  Submirror types may be mixed.
 *
 *		Submirror sizes or components may be specified explicitly.
 *
 *		If the mirror does not specify a size, assume the first explicit
 *		submirror size is the desired size.  If a submirror does not
 *		specify a size or components, use the mirror size.
 *
 *		Scan the submirror requests: those with specific components
 *		get assembled as encountered.  The remainder are grouped by
 *		type and handled by layout_stripe_submirrors() or
 *		layout_concat_submirrors().
 *
 *		If all specified submirrors can be assembled, the final mirror
 *		is assembled and appended to the results list.
 */
int
populate_explicit_mirror(
	devconfig_t	*request,
	dlist_t		**results)
{
	dlist_t		*composed = NULL;
	dlist_t		*list = NULL;
	dlist_t		*iter = NULL;
	dlist_t		*concats_by_size = NULL;
	dlist_t		*stripes_by_size = NULL;
	int		nsubs = 0;
	int		error = 0;
	uint64_t 	msize = 0;
	boolean_t	usehsp = B_FALSE;

	list = devconfig_get_components(request);
	nsubs = dlist_length(list);

	if ((error = get_volume_faultrecov(request, &usehsp)) != 0) {
	    if (error != ERR_ATTR_UNSET) {
		return (error);
	    }
	    error = 0;
	}

	if ((error = devconfig_get_size(request, &msize)) != 0) {
	    if (error == ERR_ATTR_UNSET) {
		error = 0;
		msize = 0;
	    } else {
		return (error);
	    }
	}

	print_layout_explicit_msg(devconfig_type_to_str(TYPE_MIRROR));

	/*
	 * Scan the list of specified submirrors, collect those that only
	 * specify size (or no size).  Process those with explicit components
	 * immediately.
	 */
	composed = NULL;
	for (iter = list; (iter != NULL) && (error == 0); iter = iter->next) {

	    devconfig_t		*comp = (devconfig_t *)iter->obj;
	    component_type_t	ctype = TYPE_UNKNOWN;
	    dlist_t		*clist = NULL;
	    uint64_t 		csize = 0;
	    dlist_t		*item = NULL;

	    (void) devconfig_get_type(comp, &ctype);
	    (void) devconfig_get_size(comp, &csize);
	    clist = devconfig_get_components(comp);

	    if (clist != NULL) {

		/* components specified */

		if (ctype == TYPE_STRIPE) {
		    error = populate_explicit_stripe(comp, &item);
		} else {
		    error = populate_explicit_concat(comp, &item);
		}

		if (error == 0) {
		    set_explicit_submirror_name(
			    comp, (devconfig_t *)item->obj);
		    composed = dlist_append(item, composed, AT_TAIL);
		}

	    } else {

		/* no components specified */

		/* if no size is specified, it needs to be inferred */

		if (msize == 0) {
		    /* mirror specified no size, first explicit submirror */
		    /*  size is assumed to be the desired mirror size */
		    msize = csize;
		}
		if (csize == 0) {
		    /* this submirror specified no size, use mirror size */
		    devconfig_set_size(comp, msize);
		}

		if ((item = dlist_new_item(comp)) == NULL) {
		    error = ENOMEM;
		    break;
		}

		if (ctype == TYPE_STRIPE) {
		    stripes_by_size = dlist_append(
			    item, stripes_by_size, AT_TAIL);
		} else {
		    concats_by_size = dlist_append(
			    item, concats_by_size, AT_TAIL);
		}

	    }
	}

	/* compose stripes specified by size */
	if ((error == 0) && (stripes_by_size != NULL)) {
	    uint16_t n = dlist_length(stripes_by_size);
	    dlist_t *stripes = NULL;
	    if ((error = layout_stripe_submirrors(
		request, composed, msize, n, &stripes)) == 0) {

		/* adjust stripe names */
		set_explicit_submirror_names(stripes_by_size, stripes);
		composed = dlist_append(stripes, composed, AT_TAIL);

	    } else {
		/* these stripes failed, skip concats_by_size */
		dlist_free_items(stripes, free_devconfig_object);
		dlist_free_items(concats_by_size, NULL);
		concats_by_size = NULL;
	    }
	    dlist_free_items(stripes_by_size, NULL);
	}

	/* compose concats specified by size */
	if ((error == 0) && (concats_by_size != NULL)) {
	    uint16_t n = dlist_length(concats_by_size);
	    dlist_t *concats = NULL;
	    if ((error = layout_concat_submirrors(
		request, composed, msize, n, &concats)) == 0) {

		/* adjust concat names */
		set_explicit_submirror_names(concats_by_size, concats);
		composed = dlist_append(concats, composed, AT_TAIL);

	    } else {

		/* these concats failed */
		dlist_free_items(concats, free_devconfig_object);
	    }

	    dlist_free_items(concats_by_size, NULL);
	}

	if ((composed != NULL) && ((dlist_length(composed) == nsubs))) {

	    /* assemble final mirror */

	    devconfig_t	*mirror = NULL;
	    dlist_t	*item = NULL;

	    if ((error = assemble_mirror(request, composed, &mirror)) == 0) {

		if ((item = dlist_new_item(mirror)) == NULL) {
		    error = ENOMEM;
		} else {
		    *results = dlist_append(item, *results, AT_TAIL);
		    if (usehsp == B_TRUE) {
			error = add_to_hsp_list(
				devconfig_get_components(mirror));
		    }
		    print_layout_success_msg();
		}
	    }

	} else if (error != 0) {

	    print_debug_failure_msg(
		    devconfig_type_to_str(TYPE_MIRROR),
		    get_error_string(error));

	} else {

	    dlist_free_items(composed, free_devconfig_object);
	    print_insufficient_resources_msg(
		    devconfig_type_to_str(TYPE_MIRROR));
	    error = -1;
	}

	return (error);
}

/*
 * FUNCTION:	assemble_mirror(devconfig_t *request, dlist_t *subs,
 *			devconfig_t **mirror)
 *
 * INPUT:	request	- pointer to a devconfig_t of the current request
 *		subs	- pointer to a list of composed submirrors
 *
 * OUPUT:	mirror	- pointer to a devconfig_t to hold final mirror
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Helper which creates and populates a mirror devconfig_t
 *		struct using information from the input request and the
 *		list of submirror components.
 *
 *		Determines the name of the mirror either from the request
 *		or from the default naming scheme and assigns names to
 *		unnamed submirrors according to the default naming scheme.
 *
 *		Sets the read and write strategies, and the resync pass
 *		number for the mirror if values are specified in the request.
 *
 *		Attaches the input list of submirrors to the devconfig.
 */
static int
assemble_mirror(
	devconfig_t	*request,
	dlist_t		*subs,
	devconfig_t	**mirror)
{
	dlist_t		*iter = NULL;
	char		*name = NULL;
	int		error = 0;

	if ((error = new_devconfig(mirror, TYPE_MIRROR)) == 0) {
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
			TYPE_MIRROR)) == 0) {
			error = devconfig_set_name(*mirror, name);
			free(name);
			/* get name for generating submirror names below */
			error = devconfig_get_name(*mirror, &name);
		    }
		} else {
		    error = devconfig_set_name(*mirror, name);
		}
	    }
	}

	/* assign name to any unnamed submirror */
	for (iter = subs;
	    (error == 0) && (iter != NULL);
	    iter = iter->next) {

	    devconfig_t *sub = (devconfig_t *)iter->obj;
	    char	*subname = NULL;

	    error = devconfig_get_name(sub, &subname);
	    if ((error == ERR_ATTR_UNSET) || (subname == NULL) ||
		    (*subname == '\0')) {
		((error = get_next_submirror_name(name, &subname)) != 0) ||
		(error = devconfig_set_name(sub, subname));
		free(subname);
	    }
	}

	if (error == 0) {
	    mirror_read_strategy_t read = 0;
	    if ((error = get_mirror_read_strategy(request, &read)) == 0) {
		error = devconfig_set_mirror_read(*mirror, read);
	    } else if (error == ERR_ATTR_UNSET) {
		error = 0;
	    }
	}

	if (error == 0) {
	    mirror_write_strategy_t write = 0;
	    if ((error = get_mirror_write_strategy(request, &write)) == 0) {
		error = devconfig_set_mirror_write(*mirror, write);
	    } else if (error == ERR_ATTR_UNSET) {
		error = 0;
	    }
	}

	if (error == 0) {
	    uint16_t pass = 0;
	    if ((error = get_mirror_pass(request, &pass)) == 0) {
		error = devconfig_set_mirror_pass(*mirror, pass);
	    } else if (error == ERR_ATTR_UNSET) {
		error = 0;
	    }
	}

	/* arrange submirrors in ascending size order */
	if (error == 0) {
	    dlist_t *sorted = NULL;
	    dlist_t *next = NULL;

	    iter = subs;
	    while (iter != NULL) {

		next = iter->next;
		iter->next = NULL;
		iter->prev = NULL;

		sorted = dlist_insert_ordered(iter,
			sorted, ASCENDING, compare_devconfig_sizes);

		iter = next;
	    }
	    subs = sorted;
	}

	if (error == 0) {
	    devconfig_set_components(*mirror, subs);
	} else {
	    free_devconfig(*mirror);
	    *mirror = NULL;
	}

	return (error);
}

/*
 * FUNCTION:	layout_stripe_submirrors(devconfig_t *request, dlist_t *cursubs,
 *			uint64_t nbytes, uint16_t nsubs, dlist_t **results)
 *
 * INPUT:	request	- pointer to a devconfig_t of the current request
 *		cursubs - pointer to a list of already composed submirrors
 *			these may affect disk and HBA choices for new
 *			submirrors being composed and are passed along
 *			into the component selection functions.
 *		nbytes	- the desired capacity for the stripes
 *
 * OUPUT:	results	- pointer to a list of composed volumes
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Main layout driver for composing stripe submirrors.
 *
 *		Attempts to construct nsub submirrors of size nbytes.
 *
 *		Several different layout strategies are tried in order
 *		of preference until one succeeds or there are none left.
 *
 *		1 - mirror with all stripes on the MPXIO "controller"
 *		    . requires MPXIO to be enabled
 *		    . requires nsubs * mincomp available disks on the
 *			MPXIO HBA
 *
 *		2 - mirror with stripes within separate HBAs of same type
 *		    . requires nsubs HBAs with mincomp disks
 *		    . stripe width is driven by number of disks on HBA
 *
 *		3 - mirror with stripes across HBAs of same type
 *		    . requires mincomp HBAs with nsubs disks
 *			(each stripe has a disk per HBA)
 *		    . stripe width is driven by number of HBAs
 *
 *		4 - mirror with stripes within separate HBAs of mixed type
 *		    . requires nsubs HBAs with mincomp disks
 *		    . stripe width is driven by number of disks on HBA
 *
 *		5 - mirror with stripes across HBAs of mixed type
 *		    . requires mincomp HBAs with nsubs disks
 *			(each stripe has a disk per HBA)
 *		    . stripe width is driven by number of HBAs
 *
 *		6 - mirror with all stripes within the same HBA
 *		    . requires an HBA with mincomp * nsubs disks
 *
 *		get available HBAs
 *
 *		group HBAs by characteristics
 *		for (each HBA grouping) and (nsub stripes not composed) {
 *		    select next HBA group
 *		    for (strategy[1,2,3]) and (nsub stripes not composed) {
 *			compose nsub stripes using HBAs in group
 *		    }
 *		}
 *
 *		if (nsub stripes not composed) {
 *		    for (strategy[4,5,6]) and (nsub stripes not composed) {
 *			compose nsub stripes using all HBAs
 *		    }
 *		}
 *
 *		if (all stripes composed) {
 *		    append composed stripes to results
 *		}
 *
 */
static int
layout_stripe_submirrors(
	devconfig_t	*request,
	dlist_t		*cursubs,
	uint64_t 	nbytes,
	uint16_t	nsubs,
	dlist_t		**results)
{
	/*
	 * these enums define the # of strategies and the preference order
	 * in which they are tried
	 */
	typedef enum {
		ALL_STRIPES_ON_MPXIO = 0,
		STRIPE_PER_SIMILAR_HBA,
		STRIPE_ACROSS_SIMILAR_HBAS,
		N_SIMILAR_HBA_STRATEGIES
	} similar_hba_strategy_order_t;

	typedef enum {
		STRIPE_PER_ANY_HBA = 0,
		STRIPE_ACROSS_ANY_HBAS,
		STRIPE_WITHIN_ANY_HBA,
		N_ANY_HBA_STRATEGIES
	} any_hba_strategy_order_t;

	dlist_t		*usable_hbas = NULL;
	dlist_t		*similar_hba_groups = NULL;
	dlist_t		*iter = NULL;
	dlist_t		*subs = NULL;

	boolean_t	usehsp = B_FALSE;
	uint16_t	mincomp	= 0;
	uint16_t	maxcomp	= 0;

	int		error = 0;

	(error = get_usable_hbas(&usable_hbas));
	if (error != 0) {
	    return (error);
	}

	print_layout_submirrors_msg(devconfig_type_to_str(TYPE_STRIPE),
		nbytes, nsubs);

	if (dlist_length(usable_hbas) == 0) {
	    print_no_hbas_msg();
	    volume_set_error(gettext("There are no usable HBAs."));
	    return (-1);
	}

	similar_hba_groups = NULL;
	((error = group_similar_hbas(usable_hbas, &similar_hba_groups)) != 0) ||

	/*
	 * determine the min/max number of stripe components
	 * based on the request, the diskset defaults or the
	 * global defaults.  These are absolute limits, the
	 * actual values are determined by the number of HBAs
	 * and/or disks available.
	 */
	(error = get_stripe_min_comp(request, &mincomp)) ||
	(error = get_stripe_max_comp(request, &maxcomp)) ||
	(error = get_volume_faultrecov(request, &usehsp));
	if (error != 0) {
	    return (error);
	}

	for (iter = similar_hba_groups;
	    (error == 0) && (subs == NULL) && (iter != NULL);
	    iter = iter->next) {

	    dlist_t *hbas = (dlist_t *)iter->obj;

	    similar_hba_strategy_order_t order;

	    for (order = ALL_STRIPES_ON_MPXIO;
		(order < N_SIMILAR_HBA_STRATEGIES) &&
			(subs == NULL) && (error == 0);
		order++) {

		dlist_t *selhbas = NULL;
		dlist_t *disks = NULL;
		int	n = 0;

		switch (order) {

		case ALL_STRIPES_ON_MPXIO:

		    if (is_mpxio_enabled() == B_TRUE) {
			dlist_t *mpxio_hbas = NULL;

			/* see if any HBA supports MPXIO */
			error = select_mpxio_hbas(hbas, &mpxio_hbas);
			if ((error == 0) && (mpxio_hbas != NULL)) {

/* BEGIN CSTYLED */
oprintf(OUTPUT_TERSE,
gettext("  -->Strategy 1: use %d-%d MPXIO disks\n"),
	mincomp * nsubs, maxcomp * nsubs);
/* END CSTYLED */

			    /* see if MPXIO HBA has enough disks */
			    error = select_hbas_with_n_disks(
				    request, mpxio_hbas, (mincomp * nsubs),
				    &selhbas, &disks);

			    if ((error == 0) && (dlist_length(selhbas) > 0)) {
				error = compose_stripes_within_hba(
					request, cursubs, mpxio_hbas, nbytes,
					nsubs, maxcomp, mincomp, &subs);
			    } else {
				print_insufficient_hbas_msg(n);
			    }
			}

			dlist_free_items(mpxio_hbas, NULL);
		    }

		    break;

		case STRIPE_PER_SIMILAR_HBA:

		    error = select_hbas_with_n_disks(
			    request, hbas, mincomp, &selhbas, &disks);

		    if (error == 0) {

/* BEGIN CSTYLED */
oprintf(OUTPUT_TERSE,
	gettext("  -->Strategy 2: use %d-%d disks from %d similar HBAs - stripe per HBA\n"),
	mincomp, maxcomp, nsubs);
/* END CSTYLED */

			if ((n = dlist_length(selhbas)) >= nsubs) {
			    error = compose_stripe_per_hba(
				    request, cursubs, selhbas, nbytes,
				    nsubs, maxcomp, mincomp, &subs);
			} else {
			    print_insufficient_hbas_msg(n);
			}
		    }

		    break;

		case STRIPE_ACROSS_SIMILAR_HBAS:

		    error = select_hbas_with_n_disks(
			    request, hbas, nsubs, &selhbas, &disks);

		    if (error == 0) {

/* BEGIN CSTYLED */
oprintf(OUTPUT_TERSE,
gettext("  -->Strategy 3: use %d disks from %d-%d similar HBAs - stripe across HBAs \n"),
	nsubs, mincomp, maxcomp);
/* END CSTYLED */

			if ((n = dlist_length(selhbas)) >= mincomp) {
			    error = compose_stripes_across_hbas(
				    request, cursubs, selhbas, disks,
				    nbytes, nsubs, maxcomp, mincomp, &subs);
			} else {
			    print_insufficient_hbas_msg(n);
			}
		    }

		    break;

		default:
		    break;
		}

		dlist_free_items(selhbas, NULL);
		dlist_free_items(disks, NULL);
	    }
	}

	for (iter = similar_hba_groups; iter != NULL; iter = iter->next) {
	    dlist_free_items((dlist_t *)iter->obj, NULL);
	}
	dlist_free_items(similar_hba_groups, NULL);

	/* retry using all available HBAs */
	if (subs == NULL) {

	    any_hba_strategy_order_t order;

	    for (order = STRIPE_PER_ANY_HBA;
		(order < N_ANY_HBA_STRATEGIES) &&
			(subs == NULL) && (error == 0);
		order++) {

		dlist_t *selhbas = NULL;
		dlist_t *disks = NULL;
		int	n = 0;

		switch (order) {

		case STRIPE_PER_ANY_HBA:

		    error = select_hbas_with_n_disks(
			    request, usable_hbas, nsubs, &selhbas, &disks);

		    if (error == 0) {

/* BEGIN CSTYLED */
oprintf(OUTPUT_TERSE,
gettext("  -->Strategy 4: use %d-%d disks from any %d HBAs - stripe per HBA\n"),
	mincomp, maxcomp, nsubs);
/* END CSTYLED */

			if ((n = dlist_length(selhbas)) >= nsubs) {
			    error = compose_stripe_per_hba(
				    request, cursubs, selhbas, nbytes,
				    nsubs, maxcomp, mincomp, &subs);
			} else {
			    print_insufficient_hbas_msg(n);
			}
		    }

		    break;

		case STRIPE_ACROSS_ANY_HBAS:

		    error = select_hbas_with_n_disks(
			    request, usable_hbas, nsubs, &selhbas, &disks);

		    if (error == 0) {

/* BEGIN CSTYLED */
oprintf(OUTPUT_TERSE,
gettext("  -->Strategy 5: use %d disks from %d-%d HBAs - stripe across HBAs \n"),
	nsubs, mincomp, maxcomp);
/* END CSTYLED */

			if ((n = dlist_length(selhbas)) >= mincomp) {
			    error = compose_stripes_across_hbas(
				    request, cursubs, selhbas, disks,
				    nbytes, nsubs, maxcomp, mincomp, &subs);
			} else {
			    print_insufficient_hbas_msg(n);
			}
		    }

		    break;

		case STRIPE_WITHIN_ANY_HBA:

		    error = select_hbas_with_n_disks(
			    request, usable_hbas, (mincomp * nsubs),
			    &selhbas, &disks);

		    if (error == 0) {

/* BEGIN CSTYLED */
oprintf(OUTPUT_TERSE,
gettext("  -->Strategy 6: use %d-%d disks from any single HBA - %d stripes within HBA\n"),
	mincomp * nsubs, maxcomp * nsubs, nsubs);
/* END CSTYLED */
			if ((n = dlist_length(selhbas)) > 0) {
			    error = compose_stripes_within_hba(
				    request, cursubs, selhbas, nbytes,
				    nsubs, maxcomp, mincomp, &subs);
			} else {
			    print_insufficient_hbas_msg(n);
			}
		    }

		    break;

		default:
		    break;
		}

		dlist_free_items(selhbas, NULL);
		dlist_free_items(disks, NULL);
	    }
	}

	if (error == 0) {
	    *results = dlist_append(subs, *results, AT_TAIL);
	}
	return (error);
}

/*
 * FUNCTION:	layout_concat_submirrors(devconfig_t *request, dlist_t *cursubs,
 *			uint64_t nbytes, uint16_t nsubs, dlist_t **results)
 *
 * INPUT:	request	- pointer to a devconfig_t of the current request
 *		cursubs - pointer to a list of already composed submirrors
 *		nbytes	- the desired capacity for the concats
 *
 * OUPUT:	results	- pointer to a list of composed volumes
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Main layout driver for composing concat submirrors.
 *
 *		Attempts to construct nsub submirrors of size nbytes.
 *
 *		Several different layout strategies are tried in order
 *		of preference until one succeeds or there are none left.
 *
 *		1 - mirror with all concats on the MPXIO "controller"
 *		    . requires MPXIO to be enabled
 *		    . requires nsubs available disks on the MPXIO HBA
 *
 *		2 - mirror with concats on separate HBAs of same type
 *		    . requires nsubs HBAs with available disks
 *
 *		3 - mirror with concats across HBAs of same type
 *		    . requires an HBA with at least 1 available disk
 *
 *		4 - mirror with concats on separate HBAs of mixed type
 *		    . requires nsubs HBAs with available disks
 *
 *		5 - mirror with concats across HBAs of mixed type
 *		    . requires an HBA with at least 1 available disk
 *
 *		6 - mirror with all concats on the same HBA
 *		    . requires an HBA with at least nsubs available disks
 *
 *		get available HBAs
 *
 *		group HBAs by characteristics
 *		for (each HBA grouping) and (nsub concats not composed) {
 *		    select next HBA group
 *		    for (strategy[1,2,3]) and (nsub concats not composed) {
 *			compose nsub concats, nbytes in size
 *		    }
 *		}
 *
 *		if (nsub concats not composed) {
 *		    for (strategy[4,5,6]) and (nsub concats not composed) {
 *			compose nsub concats, nbytes in size
 *		    }
 *		}
 *
 *		if (all concats composed) {
 *		    append composed concats to results
 *		}
 *
 */
static int
layout_concat_submirrors(
	devconfig_t	*request,
	dlist_t		*cursubs,
	uint64_t 	nbytes,
	uint16_t	nsubs,
	dlist_t		**results)
{
	/*
	 * these enums define the # of strategies and the preference order
	 * in which they are tried
	 */
	typedef enum {
		ALL_CONCATS_ON_MPXIO = 0,
		CONCAT_PER_SIMILAR_HBA,
		CONCAT_ACROSS_SIMILAR_HBAS,
		N_SIMILAR_HBA_STRATEGIES
	} similar_hba_strategy_order_t;

	typedef enum {
		CONCAT_PER_ANY_HBA = 0,
		CONCAT_ACROSS_ANY_HBAS,
		CONCAT_WITHIN_ANY_HBA,
		N_ANY_HBA_STRATEGIES
	} any_hba_strategy_order_t;

	dlist_t		*usable_hbas = NULL;
	dlist_t		*similar_hba_groups = NULL;
	dlist_t		*iter = NULL;
	dlist_t		*subs = NULL;

	boolean_t	usehsp = B_FALSE;

	int		error = 0;

	(error = get_usable_hbas(&usable_hbas));
	if (error != 0) {
	    return (error);
	}

	print_layout_submirrors_msg(devconfig_type_to_str(TYPE_CONCAT),
		nbytes, nsubs);

	if (dlist_length(usable_hbas) == 0) {
	    print_no_hbas_msg();
	    volume_set_error(gettext("There are no usable HBAs."));
	    return (-1);
	}

	similar_hba_groups = NULL;
	((error = group_similar_hbas(usable_hbas, &similar_hba_groups)) != 0) ||
	(error = get_volume_faultrecov(request, &usehsp));
	if (error != 0) {
	    return (error);
	}

	for (iter = similar_hba_groups;
	    (error == 0) && (subs == NULL) && (iter != NULL);
	    iter = iter->next) {

	    dlist_t *hbas = (dlist_t *)iter->obj;

	    similar_hba_strategy_order_t order;

	    for (order = ALL_CONCATS_ON_MPXIO;
		(order < N_SIMILAR_HBA_STRATEGIES) &&
			(subs == NULL) && (error == 0);
		order++) {

		dlist_t *selhbas = NULL;
		dlist_t *disks = NULL;
		int	n = 0;

		switch (order) {

		case ALL_CONCATS_ON_MPXIO:

		    if (is_mpxio_enabled() == B_TRUE) {
			dlist_t *mpxio_hbas = NULL;

			/* see if any HBA supports MPXIO */
			error = select_mpxio_hbas(hbas, &mpxio_hbas);
			if ((error == 0) && (mpxio_hbas != NULL)) {

/* BEGIN CSTYLED */
oprintf(OUTPUT_TERSE,
	gettext("  -->Strategy 1: use at least %d MPXIO disks\n"),
	nsubs);
/* END CSTYLED */

			    /* see if MPXIO HBA has enough disks */
			    error = select_hbas_with_n_disks(
				    request, hbas, nsubs, &selhbas, &disks);

			    if ((error == 0) &&
				    ((n = dlist_length(selhbas)) > 0)) {
				error = compose_concats_within_hba(
					request, cursubs, mpxio_hbas, nbytes,
					nsubs, &subs);
			    } else {
				print_insufficient_hbas_msg(n);
			    }
			}

			dlist_free_items(mpxio_hbas, NULL);
		    }

		    break;

		case CONCAT_PER_SIMILAR_HBA:

		    error = select_hbas_with_n_disks(
			    request, hbas, 1, &selhbas, &disks);

		    if (error == 0) {

/* BEGIN CSTYLED */
oprintf(OUTPUT_TERSE,
	gettext("  -->Strategy 2: use any disks from %d similar HBAs - concat per HBA\n"),
	nsubs);
/* END CSTYLED */

			if ((n = dlist_length(selhbas)) >= nsubs) {
			    error = compose_concat_per_hba(
				    request, cursubs, selhbas,
				    nbytes, nsubs, &subs);
			} else {
			    print_insufficient_hbas_msg(n);
			}
		    }

		    break;

		case CONCAT_ACROSS_SIMILAR_HBAS:

		    error = select_hbas_with_n_disks(
			    request, hbas, 1, &selhbas, &disks);

		    if (error == 0) {

/* BEGIN CSTYLED */
oprintf(OUTPUT_TERSE,
	gettext("  -->Strategy 3: use any disks from any similar HBAs - "
		"%d concats across HBAs\n"),
	nsubs);
/* END CSTYLED */
			error = compose_concats_across_hbas(
				request, cursubs, selhbas, disks,
				nbytes, nsubs, &subs);
		    }

		    break;

		default:
		    break;
		}

		dlist_free_items(selhbas, NULL);
		dlist_free_items(disks, NULL);
	    }
	}

	for (iter = similar_hba_groups; iter != NULL; iter = iter->next) {
	    dlist_free_items((dlist_t *)iter->obj, NULL);
	}
	dlist_free_items(similar_hba_groups, NULL);

	/* retry using all available HBAs */
	if (subs == NULL) {

	    any_hba_strategy_order_t order;

	    for (order = CONCAT_PER_ANY_HBA;
		(order < N_ANY_HBA_STRATEGIES) &&
			(subs == NULL) && (error == 0);
		order++) {

		dlist_t *selhbas = NULL;
		dlist_t *disks = NULL;
		int	n = 0;

		switch (order) {

		case CONCAT_PER_ANY_HBA:

		    error = select_hbas_with_n_disks(
			    request, usable_hbas, 1, &selhbas, &disks);

		    if (error == 0) {

/* BEGIN CSTYLED */
oprintf(OUTPUT_TERSE,
	gettext("  -->Strategy 4: use any disks from %d HBAs - concat per HBA\n"),
	nsubs);
/* END CSTYLED */
			if ((n = dlist_length(selhbas)) >= nsubs) {
			    error = compose_concat_per_hba(
				    request, cursubs, selhbas,
				    nbytes, nsubs, &subs);
			} else {
			    print_insufficient_hbas_msg(n);
			}
		    }
		    break;

		case CONCAT_ACROSS_ANY_HBAS:

		    error = select_hbas_with_n_disks(
			    request, usable_hbas, 1, &selhbas, &disks);

		    if (error == 0) {

/* BEGIN CSTYLED */
oprintf(OUTPUT_TERSE,
	gettext("  -->Strategy 5: use any disks from any HBA - %d concats across HBAs\n"),
	nsubs);
/* END CSTYLED */
			error = compose_concats_across_hbas(
				request, cursubs, selhbas, disks,
				nbytes, nsubs, &subs);
		    }

		    break;

		case CONCAT_WITHIN_ANY_HBA:

		    error = select_hbas_with_n_disks(
			    request, usable_hbas, 1, &selhbas, &disks);

		    if (error == 0) {

/* BEGIN CSTYLED */
oprintf(OUTPUT_TERSE,
gettext("  -->Strategy 6: use any disks from any single HBA - %d concats within an HBA\n"),
	nsubs);
/* END CSTYLED */

			if ((n = dlist_length(selhbas)) > 0) {
			    error = compose_concats_within_hba(
				    request, cursubs, selhbas,
				    nbytes, nsubs, &subs);
			} else {
			    print_insufficient_hbas_msg(n);
			}

		    }
		    break;

		default:
		    break;
		}

		dlist_free_items(selhbas, NULL);
		dlist_free_items(disks, NULL);
	    }
	}

	if (error == 0) {
	    *results = dlist_append(subs, *results, AT_TAIL);
	}

	return (error);
}

/*
 * FUNCTION:	compose_stripe_per_hba(devconfig_t *request,
 *		    dlist_t *cursubs, dlist_t *hbas, uint64_t nbytes,
 *		    uint16_t nsubs, int maxcomp, int mincomp,
 *		    dlist_t **results)
 *
 * INPUT:	request	- pointer to a devconfig_t of the current request
 *		cursubs - pointer to a list of already composed submirrors
 *		hbas	- pointer to a list of available HBAs
 *		nbytes	- the desired capacity for the stripes
 *		nsubs	- the desired number of stripes
 *		maxcomp	- the maximum number of stripe components
 *		mincomp - the minimum number of stripe components
 *
 * OUPUT:	results	- pointer to a list of composed volumes
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Layout function which composes the requested number of stripes
 *		of the desired size using available disks on any of the HBAs
 *		from the input list.
 *
 *		The number of components within the composed stripes will be
 *		in the range of mincomp to ncomp, preferring more components
 *		over fewer.  All stripes composed by a single call to this
 *		function will have the same number of components.
 *
 *		Each stripe will use disks from a single HBA.
 *
 * 		All input HBAs are expected to have at least mincomp available
 *		disks.
 *
 *		If the stripes can be composed, they are appended to the list
 *		of result volumes.
 *
 *		while (more HBAs and more stripes to compose) {
 *		    select next HBA
 *		    get available space for this HBA
 *		    get available disks for this HBA
 *		    if (not enough space or disks) {
 *			continue
 *		    }
 *
 *		    use # disks as # of stripe components - limit to maxcomp
 *		    for ((ncomps downto mincomp) && (more stripes to compose)) {
 *			while (more stripes to compose) {
 *			    if a stripe can be composed using disks {
 *			        save stripe
 *			        increment stripe count
 *			    }
 *			    while (more HBAs and more stripes to compose) {
 *				select next HBA
 *				get available space for this HBA
 *				get available disks for this HBA
 *				if (not enough space or disks) {
 *				    continue
 *				}
 *			        if a stripe can be composed using disks {
 *				    save stripe
 *				    increment stripe count
 *				}
 *			    }
 *
 *			    if (not all stripes composed) {
 *				delete any compose stripes
 *			    }
 *			}
 *		    }
 *
 *		    if (not all stripes composed) {
 *		        delete any stripes composed
 *		    }
 *		}
 *
 *		if (not all stripes composed) {
 *		    delete any stripes composed
 *		}
 *
 *		append composed stripes to results
 */
static int
compose_stripe_per_hba(
	devconfig_t	*request,
	dlist_t		*cursubs,
	dlist_t		*hbas,
	uint64_t	nbytes,
	uint16_t	nsubs,
	uint16_t	maxcomp,
	uint16_t	mincomp,
	dlist_t		**results)
{
	int		error = 0;
	dlist_t		*list = NULL;
	dlist_t		*iter = NULL;

	oprintf(OUTPUT_VERBOSE,
		gettext("  --->Trying to compose %d Stripes with "
			"%d-%d components on separate HBAs.\n"),
		nsubs, mincomp, maxcomp);

	for (iter = hbas;
	    (list == NULL) && (iter != NULL) && (error == 0);
	    iter = iter->next) {

	    dm_descriptor_t hba = (uintptr_t)iter->obj;
	    dlist_t	*disks = NULL;
	    uint64_t	space = 0;
	    int		ncomp = 0;
	    char	*name;

	    ((error = get_display_name(hba, &name)) != 0) ||
	    (error = hba_get_avail_disks_and_space(request,
		    hba, &disks, &space));
	    if (error != 0) {
		continue;
	    }

	    /* check for sufficient space and minimum # of disks */
	    if (space < nbytes) {
		(void) print_hba_insufficient_space_msg(name, space);
		dlist_free_items(disks, NULL);
		continue;
	    }

	    if ((ncomp = dlist_length(disks)) < mincomp) {
		print_insufficient_disks_msg(ncomp);
		dlist_free_items(disks, NULL);
		continue;
	    }

	    /* make the stripe as wide as possible, up to maxcomp */
	    for (ncomp = ((ncomp > maxcomp) ? maxcomp : ncomp);
		(list == NULL) && (ncomp >= mincomp) && (error == 0);
		ncomp--) {

		int count = 0;

		/* try composing nsubs stripes with ncomp components */
		while (count < nsubs) {

		    devconfig_t *stripe = NULL;
		    dlist_t *item = NULL;
		    dlist_t *iter1 = NULL;

		    /* build first stripe using disks on this HBA */
		    if (((error = populate_stripe(request, nbytes,
			disks, ncomp, cursubs, &stripe)) != 0) ||
			    (stripe == NULL)) {
			/* first stripe failed at the current width */
			/* break while loop and try a different width */
			break;
		    }

		    /* composed a stripe */
		    if ((item = dlist_new_item((void*)stripe)) == NULL) {
			error = ENOMEM;
			break;
		    }
		    ++count;
		    list = dlist_append(item, list, AT_TAIL);

		    /* compose stripes on remaining HBAs */
		    for (iter1 = iter->next;
			(count < nsubs) && (iter1 != NULL) && (error == 0);
			iter1 = iter1->next) {

			dm_descriptor_t hba1 = (uintptr_t)iter1->obj;
			uint64_t space1 = 0;
			dlist_t	*disks1 = NULL;

			error = hba_get_avail_disks_and_space(request,
				hba1, &disks1, &space1);
			if (error != 0) {
			    continue;
			}

			/* enough space/disks on this HBA? */
			if ((dlist_length(disks1) < ncomp) ||
			    (space1 < nbytes)) {
			    dlist_free_items(disks1, NULL);
			    continue;
			}

			stripe = NULL;
			error = populate_stripe(
				request, nbytes, disks1,
				ncomp, cursubs, &stripe);

			if (stripe != NULL) {
			    /* prepare to compose another */
			    if ((item = dlist_new_item(
				(void *)stripe)) == NULL) {
				error = ENOMEM;
				break;
			    }
			    list = dlist_append(item, list, AT_TAIL);
			    ++count;
			}

			dlist_free_items(disks1, NULL);
			disks1 = NULL;
		    }

		    if ((iter1 == NULL) && (count < nsubs)) {
			/*
			 * no HBAs remain and haven't composed
			 * enough stripes at the current width.
			 * break while loop and try another width.
			 */
			break;
		    }
		}

		if (count < nsubs) {
		/*
		 * stripe composition at current width failed...
		 * prepare to try a narrower width.
		 * NB: narrower widths may work since some HBA(s)
		 * may have fewer available disks
		 */
		    print_layout_submirrors_failed_msg(
			    devconfig_type_to_str(TYPE_STRIPE),
			    count, nsubs);

		    dlist_free_items(list, free_devconfig_object);
		    list = NULL;
		}
	    }

	    dlist_free_items(disks, NULL);
	    disks = NULL;
	}

	if (error == 0) {
	    *results = dlist_append(list, *results, AT_TAIL);
	} else {
	    dlist_free_items(list, free_devconfig_object);
	}

	return (error);
}

/*
 * FUNCTION:	compose_stripes_across_hbas(devconfig_t *request,
 *			dlist_t *cursubs, dlist_t *hbas, dlist_t *disks,
 *			uint64_t nbytes, uint16_t nsubs, int maxcomp,
 *			int mincomp, dlist_t **results)
 *
 * INPUT:	request	- pointer to a devconfig_t of the current request
 *		cursubs - pointer to a list of already composed submirrors
 *		hbas	- pointer to a list of available HBAs
 *		disks	- pointer to a list of available disks on the HBAs
 *		nbytes	- the desired capacity for the stripes
 *		nsubs	- the desired number of stripes
 *		ncomp	- the maximum number of stripe components
 *		mincomp - the minimum number of stripe components
 *
 * OUPUT:	results	- pointer to a list of composed volumes
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Layout function which composes the requested number of stripes
 *		of the desired size using available disks on any of the HBAs
 *		from the input list.
 *
 *		The number of components within the composed stripes will be
 *		in the range of mincomp to ncomp, preferring more components
 *		over fewer.  All stripes composed by a single call to this
 *		function will have the same number of components.
 *
 *		Each stripe will use a disk from several different HBAs.
 *
 * 		All input HBAs are expected to have at least nsubs available
 *		disks.
 *
 *		If the stripes can be composed, they are appended to the list
 *		of result volumes.
 *
 *		for (ncomps downto mincomp) {
 *
 *		    copy the input disk list
 *		    while (more stripes to compose) {
 *			if a stripe can be composed using disks {
 *			    save stripe
 *			    remove used disks from disk list
 *			    increment stripe count
 *			} else
 *			    end while loop
 *		    }
 *
 *		    free copied disk list
 *		    if (not all stripes composed) {
 *		        delete any stripes composed
 *			decrement ncomps
 *		    }
 *		}
 *
 *		if (not all stripes composed) {
 *		    delete any stripes composed
 *		}
 *
 *		append composed stripes to results
 */
static int
compose_stripes_across_hbas(
	devconfig_t	*request,
	dlist_t		*cursubs,
	dlist_t		*hbas,
	dlist_t		*disks,
	uint64_t	nbytes,
	uint16_t	nsubs,
	uint16_t	ncomp,
	uint16_t	mincomp,
	dlist_t		**results)
{
	int		error = 0;
	int		count = 0;

	dlist_t		*list	= NULL;

	while ((ncomp >= mincomp) && (count < nsubs) && (error == 0)) {

	    dlist_t	*iter;
	    dlist_t	*item;
	    dlist_t	*disks_copy = NULL;

	    oprintf(OUTPUT_VERBOSE,
		gettext("  --->Trying to compose %d Stripes with "
			"%d components across %d HBAs.\n"),
		    nsubs, ncomp, dlist_length(hbas));

	    /* copy disk list, it is modified by the while loop */
	    for (iter = disks; iter != NULL; iter = iter->next) {
		if ((item = dlist_new_item(iter->obj)) == NULL) {
		    error = ENOMEM;
		} else {
		    disks_copy = dlist_append(item, disks_copy, AT_HEAD);
		}
	    }

	    /* compose nsubs stripe submirrors of ncomp components */
	    while ((count < nsubs) && (error == 0)) {

		devconfig_t *stripe = NULL;
		dlist_t	*item = NULL;

		error = populate_stripe(
			request, nbytes, disks_copy, ncomp, cursubs, &stripe);

		if ((error == 0) && (stripe != NULL)) {
		    if ((item = dlist_new_item((void *)stripe)) == NULL) {
			error = ENOMEM;
		    } else {
			++count;
			list = dlist_append(item, list, AT_TAIL);
			error = remove_used_disks(&disks_copy, stripe);
		    }
		} else if (stripe == NULL) {
		    break;
		}
	    }

	    /* free copy of disk list */
	    dlist_free_items(disks_copy, NULL);
	    disks_copy = NULL;

	    if ((error == 0) && (count < nsubs)) {
		/* failed to compose enough stripes at this width, */
		/* prepare to try again with the next narrower width. */
		print_layout_submirrors_failed_msg(
			devconfig_type_to_str(TYPE_STRIPE),
			count, nsubs);

		dlist_free_items(list, free_devconfig_object);
		list = NULL;
		count = 0;
		--ncomp;
	    }
	}

	if (count < nsubs) {
	    dlist_free_items(list, free_devconfig_object);
	    list = NULL;
	} else {
	    *results = dlist_append(list, *results, AT_TAIL);
	}

	return (error);
}

/*
 * FUNCTION:	compose_stripes_within_hba(devconfig_t *request,
 *			dlist_t *cursubs, dlist_t *hbas, uint64_t nbytes,
 *			uint16_t nsubs, int maxcomp, int mincomp,
 *			dlist_t **results)
 *
 * INPUT:	request	- pointer to a devconfig_t of the current request
 *		cursubs - pointer to a list of already composed submirrors
 *		hbas	- pointer to a list of available HBAs
 *		nbytes	- the desired capacity for the stripes
 *		nsubs	- the desired number of stripes
 *		maxcomp - the maximum number of stripe components
 *		mincomp - the minimum number of stripe components
 *		nsubs	- the number of stripes to be composed
 *
 * OUPUT:	results	- pointer to a list of composed volumes
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Layout function which composes the requested number of stripes
 *		of the desired size using available disks within any single
 *		HBA from the input list.
 *
 *		The number of components within the composed stripes will be
 *		in the range of mincomp to maxcomp, preferring more components
 *		over fewer.  All stripes composed by a single call to this
 *		function will have the same number of components.
 *
 *		All stripes will use disks from a single HBA.
 *
 * 		All input HBAs are expected to have at least nsubs * mincomp
 *		available disks and total space sufficient for subs stripes.
 *
 *		If the stripes can be composed, they are appended to the list
 *		of result volumes.
 *
 *		while (more HBAs and more stripes need to be composed) {
 *		    select next HBA
 *		    if (not enough available space on this HBA) {
 *			continue;
 *		    }
 *		    get available disks for HBA
 *		    use # disks as # of stripe components - limit to maxcomp
 *		    for (ncomps downto mincomp) {
 *			if ((ncomps * nsubs) > ndisks) {
 *			    continue;
 *			}
 *			while (more stripes need to be composed) {
 *			    if a stripe can be composed using disks {
 *				save stripe
 *				remove used disks from disk list
 *			    } else
 *				end while loop
 *			}
 *			if (not all stripes composed) {
 *			    delete any stripes composed
 *			}
 *		    }
 *		}
 *
 *		if (not all stripes composed) {
 *		    delete any stripes composed
 *		}
 *
 *		append composed stripes to results
 */
static int
compose_stripes_within_hba(
	devconfig_t	*request,
	dlist_t		*cursubs,
	dlist_t		*hbas,
	uint64_t	nbytes,
	uint16_t	nsubs,
	uint16_t	maxcomp,
	uint16_t	mincomp,
	dlist_t		**results)
{
	int		error = 0;
	int		count = 0;

	dlist_t		*list	= NULL;
	dlist_t		*iter	= NULL;

	for (iter = hbas;
	    (count < nsubs) && (iter != NULL) && (error == 0);
	    iter = iter->next) {

	    dm_descriptor_t hba = (uintptr_t)iter->obj;
	    uint64_t	space = 0;
	    dlist_t	*disks = NULL;
	    int		ndisks = 0;
	    int		ncomp = 0;
	    char	*name = NULL;

	    ((error = get_display_name(hba, &name)) != 0) ||
	    (error = hba_get_avail_disks_and_space(request,
		    hba, &disks, &space));
	    if (error != 0) {
		dlist_free_items(disks, NULL);
		continue;
	    }

	    if (space < (nsubs * nbytes)) {
		(void) print_hba_insufficient_space_msg(name, space);
		dlist_free_items(disks, NULL);
		continue;
	    }

	    ndisks = dlist_length(disks);

		/*
		 * try composing stripes from ncomp down to mincomp.
		 * stop when nsubs stripes have been composed, or when the
		 * minimum stripe width has been tried
		 */
	    for (ncomp = maxcomp;
		(ncomp >= mincomp) && (count != nsubs) && (error == 0);
		ncomp--) {

		oprintf(OUTPUT_VERBOSE,
			gettext("  --->Trying to compose %d Stripes with "
				"%d components on a single HBA.\n"),
			nsubs, ncomp);

		if (ndisks < (ncomp * nsubs)) {
		    print_insufficient_disks_msg(ndisks);
		    continue;
		}

		/* try composing nsubs stripes, each ncomp wide */
		for (count = 0; (count < nsubs) && (error == 0); count++) {

		    devconfig_t *stripe = NULL;

		    error = populate_stripe(
			    request, nbytes, disks, ncomp, cursubs, &stripe);

		    if ((error == 0) && (stripe != NULL)) {

			dlist_t *item = dlist_new_item((void *)stripe);
			if (item == NULL) {
			    error = ENOMEM;
			} else {
			    list = dlist_append(item, list, AT_TAIL);
			    error = remove_used_disks(&disks, stripe);
			}
		    } else if (stripe == NULL) {
			break;
		    }
		}

		if (count < nsubs) {
		    /* failed to compose enough stripes at this width, */
		    /* prepare to try again with fewer components */
		    print_layout_submirrors_failed_msg(
			    devconfig_type_to_str(TYPE_STRIPE),
			    count, nsubs);

		    dlist_free_items(list, free_devconfig_object);
		    list = NULL;
		}
	    }

	    dlist_free_items(disks, NULL);
	}

	if (count < nsubs) {
	    dlist_free_items(list, free_devconfig_object);
	    list = NULL;
	}

	*results = list;

	return (error);
}

/*
 * FUNCTION:	compose_concats_per_hba(devconfig_t *request,
 *			dlist_t *cursubs, dlist_t *hbas, uint64_t nbytes,
 *			uint16_t nsubs, dlist_t	**results)
 *
 * INPUT:	request	- pointer to a devconfig_t of the current request
 *		cursubs - pointer to a list of already composed submirrors
 *		hbas	- pointer to a list of available HBAs
 *		nbytes	- the desired capacity for the concats
 *		nsubs	- the number of concats to be composed
 *
 * OUPUT:	results	- pointer to a list of composed volumes
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Layout function which composes the requested number of concats
 *		of the desired size using available disks within HBAs from the
 *		input list.  Each concat will be composed using disks from a
 *		single HBA.
 *
 *		If the concats can be composed, they are appended to the list
 *		of result volumes.
 *
 *		while (more HBAs AND more concats need to be composed) {
 *		    if (not enough available space on this HBA) {
 *			continue;
 *		    }
 *
 *		    get available disks for HBA
 *		    if (concat can be composed) {
 *			save concat
 *			increment count
 *		    }
 *		}
 *
 *		if (not all stripes composed) {
 *		    delete any concats composed
 *		}
 *
 *		append composed concats to results
 */
static int
compose_concat_per_hba(
	devconfig_t	*request,
	dlist_t		*cursubs,
	dlist_t		*hbas,
	uint64_t	nbytes,
	uint16_t	nsubs,
	dlist_t		**results)
{
	int		error = 0;
	int		count = 0;

	dlist_t		*list = NULL;
	dlist_t		*iter = NULL;

	oprintf(OUTPUT_VERBOSE,
		gettext("  --->Trying to compose %d Concats on "
			"separate HBAs.\n"), nsubs);

	for (iter = hbas;
	    (iter != NULL) && (error == 0) && (count < nsubs);
	    iter = iter->next) {

	    dm_descriptor_t hba = (uintptr_t)iter->obj;
	    uint64_t	space = 0;
	    devconfig_t *concat = NULL;
	    dlist_t	*disks = NULL;

	    error = hba_get_avail_disks_and_space(request, hba, &disks, &space);
	    if ((error == 0) && (space >= nbytes)) {
		error = populate_concat(
			request, nbytes, disks, cursubs, &concat);
	    }

	    if ((error == 0) && (concat != NULL)) {
		dlist_t	*item = dlist_new_item((void *)concat);
		if (item == NULL) {
		    error = ENOMEM;
		} else {
		    ++count;
		    list = dlist_append(item, list, AT_TAIL);
		}
	    }

	    dlist_free_items(disks, NULL);
	}

	if (count != nsubs) {
	    print_layout_submirrors_failed_msg(
		    devconfig_type_to_str(TYPE_CONCAT),
		    count, nsubs);

	    dlist_free_items(list, free_devconfig_object);
	    list = NULL;
	} else {
	    *results = dlist_append(list, *results, AT_TAIL);
	}

	return (error);
}

/*
 * FUNCTION:	compose_concats_across_hbas(devconfig_t *request,
 *			dlist_t *cursubs, dlist_t *hbas, dlist_t *disks,
 *			uint64_t nbytes, uint16_t nsubs, dlist_t **results)
 *
 * INPUT:	request	- pointer to a devconfig_t of the current request
 *		cursubs - pointer to a list of already composed submirrors
 *		hbas	- pointer to a list of available HBAs
 *		disks	- pointer to a list of available disks on the HBAs
 *		nbytes	- the desired capacity for the concats
 *		nsubs	- the number of concats to be composed
 *
 * OUPUT:	results	- pointer to a list of composed volumes
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Layout function which composes the requested number of concats
 *		of the desired size using any available disks from the input
 *		list of available HBAs.
 *
 *		If the concats can be composed, they are appended to the list
 *		of result volumes.
 *
 *		copy the input disk list
 *		while (more concats need to be composed) {
 *		    if (a concat can be composed using remaining disks) {
 *			save concat
 *			remove used disks from disk list
 *			increment count
 *		    } else {
 *			end while loop
 *		    }
 *		}
 *
 *		if (not all concats composed) {
 *		    delete any concats composed
 *		}
 *
 *		append composed concats to results
 */
static int
compose_concats_across_hbas(
	devconfig_t	*request,
	dlist_t		*cursubs,
	dlist_t		*hbas,
	dlist_t		*disks,
	uint64_t	nbytes,
	uint16_t	nsubs,
	dlist_t		**results)
{
	int		error = 0;
	int		count = 0;

	dlist_t		*list	= NULL;
	dlist_t		*item = NULL;
	dlist_t		*iter	= NULL;
	dlist_t		*disks_copy = NULL;

	/* copy disk list, it is modified by the while loop */
	for (iter = disks; iter != NULL; iter = iter->next) {
	    if ((item = dlist_new_item(iter->obj)) == NULL) {
		error = ENOMEM;
	    } else {
		disks_copy = dlist_append(item, disks_copy, AT_HEAD);
	    }
	}

	while ((count < nsubs) && (error == 0)) {

	    devconfig_t *concat = NULL;

	    error = populate_concat(
		    request, nbytes, disks_copy, cursubs, &concat);

	    if ((error == 0) && (concat != NULL)) {

		item = dlist_new_item((void *)concat);
		if (item == NULL) {
		    error = ENOMEM;
		} else {
		    count++;
		    list = dlist_append(item, list, AT_TAIL);
		    error = remove_used_disks(&disks_copy, concat);
		}
	    } else if (concat == NULL) {
		break;
	    }
	}

	/* free copy of disk list */
	dlist_free_items(disks_copy, NULL);
	disks_copy = NULL;

	if (count != nsubs) {
	    print_layout_submirrors_failed_msg(
		    devconfig_type_to_str(TYPE_CONCAT),
		    count, nsubs);

	    dlist_free_items(list, free_devconfig_object);
	    list = NULL;
	} else {
	    *results = dlist_append(list, *results, AT_TAIL);
	}

	return (error);
}

/*
 * FUNCTION:	compose_concats_within_hba(devconfig_t *request,
 *			dlist_t *cursubs, dlist_t *hbas, uint64_t nbytes,
 *			uint16_t nsubs, dlist_t	**results)
 *
 * INPUT:	request	- pointer to a devconfig_t of the current request
 *		cursubs - pointer to a list of already composed submirrors
 *		hbas	- pointer to a list of available HBAs
 *		nbytes	- the desired capacity for the concats
 *		nsubs	- the number of concats to be composed
 *
 * OUPUT:	results	- pointer to a list of composed volumes
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Layout function which composes the requested number of concats
 *		of the desired size using available disks within any single
 *		HBA from the input list.
 *
 *
 *		HBAs in the list are expected to have at least 2 available
 *		disks and total space sufficient for the submirrors.
 *
 *		If the concats can be composed, they are appended to the list
 *		of result volumes.
 *
 *		while (more HBAs) {
 *		    if (not enough available space on this HBA) {
 *			continue;
 *		    }
 *
 *		    get available disks for HBA
 *		    while (more concats need to be composed) {
 *			if a concat can be composed using disks {
 *			    save concat
 *			    remove used disks from disk list
 *			    increment count
 *			} else {
 *			    delete any concats composed
 *			    end while loop
 *			}
 *		    }
 *		}
 *
 *		if (not all concats composed) {
 *		    delete any concats composed
 *		}
 *
 *		append composed concats to results
 */
static int
compose_concats_within_hba(
	devconfig_t	*request,
	dlist_t		*cursubs,
	dlist_t		*hbas,
	uint64_t	nbytes,
	uint16_t	nsubs,
	dlist_t		**results)
{
	int		error = 0;

	dlist_t		*iter	= NULL;
	dlist_t		*list	= NULL;
	int		count = 0;

	oprintf(OUTPUT_VERBOSE,
		gettext("  --->Trying to compose %d Concats within "
			"a single HBA.\n"), nsubs);

	for (iter = hbas;
	    (count < nsubs) && (error == 0) && (iter != NULL);
	    iter = iter->next) {

	    dm_descriptor_t hba = (uintptr_t)iter->obj;
	    dlist_t	*disks	= NULL;
	    uint64_t	space = 0;

	    error = hba_get_avail_disks_and_space(request, hba, &disks, &space);
	    if ((error == 0) && (space >= (nsubs * nbytes))) {

		/* try composing nsubs concats all on this HBA */
		count = 0;
		while ((count < nsubs) && (error == 0)) {
		    devconfig_t *concat = NULL;
		    dlist_t	*item = NULL;

		    error = populate_concat(
			    request, nbytes, disks, cursubs, &concat);

		    if ((error == 0) && (concat != NULL)) {
			item = dlist_new_item((void*)concat);
			if (item == NULL) {
			    error = ENOMEM;
			} else {
			    count++;
			    list = dlist_append(item, list, AT_TAIL);
			    error = remove_used_disks(&disks, concat);
			}
		    } else if (concat == NULL) {
			dlist_free_items(list, free_devconfig_object);
			list = NULL;
			break;
		    }
		}
	    }

	    dlist_free_items(disks, NULL);
	}

	if (count < nsubs) {
	    print_layout_submirrors_failed_msg(
		    devconfig_type_to_str(TYPE_CONCAT),
		    count, nsubs);

	    dlist_free_items(list, free_devconfig_object);
	    list = NULL;
	} else {
	    *results = dlist_append(list, *results, AT_TAIL);
	}

	return (error);
}

/*
 * FUNCTION:	remove_used_disks(dlist_t **disks, devconfig_t *volume)
 *
 * INPUT:	disks	- pointer to a list of disks
 *		volume  - pointer to a devconfig_t volume
 *
 * OUPUT:	disks	- pointer to new list of disks
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Helper which updates the input list of disks by removing
 *		those which have slices	used by the input volume.
 *
 *		Constructs a new list containing only disks not used by
 *		the volume.
 *
 *		The original list is freed.
 */
static int
remove_used_disks(
	dlist_t	**disks,
	devconfig_t *volume)
{
	dlist_t  *list = NULL;
	dlist_t  *iter = NULL;
	dlist_t  *item = NULL;
	int	error = 0;

	for (iter = *disks; (iter != NULL) && (error == 0); iter = iter->next) {

	    dm_descriptor_t diskp = (uintptr_t)iter->obj;
	    boolean_t	shares = B_FALSE;

	    error = volume_shares_disk(diskp, volume, &shares);
	    if ((error == 0) && (shares != B_TRUE)) {
		/* disk is unused */
		if ((item = dlist_new_item((void*)(uintptr_t)diskp)) == NULL) {
		    error = ENOMEM;
		} else {
		    list = dlist_append(item, list, AT_TAIL);
		}
	    }
	}

	if (error != 0) {
	    dlist_free_items(list, NULL);
	} else {

	    /* free original disk list, return new list */
	    dlist_free_items(*disks, NULL);

	    *disks = list;
	}

	return (error);
}

/*
 * FUNCTION:	volume_shares_disk(dm_descriptor_t disk,
 *			devconfig_t *volume, boolean_t *shares)
 *
 * INPUT:	disk	- a dm_descriptor_t handle for the disk of interest
 *		volume	- a devconfig_t pointer to a volume
 *		bool	- a boolean_t pointer to hold the result
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Determines if the input disk has a slice that is used
 *		as a component by the input volume.
 *
 *		If the disk contributes a slice component, bool is set
 *		to B_TRUE, B_FALSE otherwise.
 */
static int
volume_shares_disk(
	dm_descriptor_t disk,
	devconfig_t	*volume,
	boolean_t	*shares)
{
	dlist_t		*iter = NULL;
	int		error = 0;

	*shares = B_FALSE;

	/* look at all slices in the volume */
	for (iter = devconfig_get_components(volume);
	    (iter != NULL) && (*shares == B_FALSE) && (error == 0);
	    iter = iter->next) {

	    devconfig_t	*dev = (devconfig_t *)iter->obj;

	    if (devconfig_isA(dev, TYPE_SLICE)) {

		/* get disk for volume's slice */
		dm_descriptor_t	odisk = NULL;
		char		*oname = NULL;

		((error = devconfig_get_name(dev, &oname)) != 0) ||
		(error = get_disk_for_named_slice(oname, &odisk));

		if (error == 0) {
		    if (compare_descriptor_names(
			(void*)(uintptr_t)disk, (void*)(uintptr_t)odisk) == 0) {
			/* otherslice is on same disk, stop */
			*shares = B_TRUE;
		    }
		}
	    }
	}

	return (error);
}

/*
 * FUNCTION:	select_mpxio_hbas(dlist_t *hbas, dlist_t **mpxio_hbas)
 *
 * INPUT:	hbas	- pointer to a list of dm_descriptor_t HBA handles
 *
 * OUTPUT:	mpxio_hbas - pointer to a new list of containing HBAs that
 *			are multiplex enabled.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Iterates the input list of HBAs and builds a new list
 *		containing those that are multiplex enabled.
 *
 *		The output list should be passed to dlist_free_items()
 *		when no longer needed.
 */
static int
select_mpxio_hbas(
	dlist_t	*hbas,
	dlist_t **mpxio_hbas)
{
	dlist_t *iter;
	int	error = 0;

	for (iter = hbas; (iter != NULL) && (error == 0); iter = iter->next) {
	    dm_descriptor_t hba = (uintptr_t)iter->obj;
	    boolean_t ismpxio = B_FALSE;
	    if ((error = hba_is_multiplex(hba, &ismpxio)) == 0) {
		if (ismpxio == B_TRUE) {
		    dlist_t *item = dlist_new_item((void *)(uintptr_t)hba);
		    if (item != NULL) {
			*mpxio_hbas =
			    dlist_append(item, *mpxio_hbas, AT_TAIL);
		    } else {
			error = ENOMEM;
		    }
		}
	    }
	}

	if (error != 0) {
	    dlist_free_items(*mpxio_hbas, NULL);
	    *mpxio_hbas = NULL;
	}

	return (error);
}

/*
 * FUNCTION:	set_explicit_submirror_names(dlist_t *reqs, dlist_t *subs)
 *
 * INPUT:	reqs	- pointer to a list of request devconfig_ts
 *		subs	- pointer to a list of volume devconfig_ts
 *
 * SIDEEFFECT:	Modifies the volume names.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Iterates the lists of volumes and requests and calls
 *		set_explicit_mirror_name for each pair.
 */
static int
set_explicit_submirror_names(
	dlist_t	*reqs,
	dlist_t	*subs)
{
	int	error = 0;

	while ((reqs != NULL) && (subs != NULL) && (error == 0)) {

	    error = set_explicit_submirror_name(
		(devconfig_t *)reqs->obj,
		(devconfig_t *)subs->obj);

	    reqs = reqs->next;
	    subs = subs->next;
	}

	return (error);
}

/*
 * FUNCTION:	set_explicit_submirror_name(dlist_t *req, dlist_t *sub)
 *
 * INPUT:	req	- pointer to a request devconfig_t
 *		sub	- pointer to a volume devconfig_t
 *
 * SIDEEFFECT:	Modifies the volume name.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Clears the volume's current name and returns the name
 *		to the available pool.
 *
 *		If a name is specified in the request, the name is used
 *		as the volume's name.
 *
 *		(Unnamed submirrors will have default names assigned
 *		during final mirror assembly.)
 */
static int
set_explicit_submirror_name(
	devconfig_t *req,
	devconfig_t *sub)
{
	char *name = NULL;
	int	error = 0;

	/* unset current submirror name */
	(void) devconfig_get_name(sub, &name);
	release_volume_name(name);
	(void) devconfig_set_name(sub, "");

	if (devconfig_get_name(req, &name) != ERR_ATTR_UNSET) {
	    (void) devconfig_set_name(sub, name);
	}

	return (error);
}
