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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <string.h>

#include <sys/cmn_err.h>
#include <sys/wrsm_config.h>

#include "wrsmconf_impl.h"

#define	ROUNDUP(x) (((x) + 0x07) & ~0x07)

/*
 * wrsm_controller
 *	wrsm_routing_data (1)
 *		ncslice (nslices)
 *		wrsm_ncslice_mode (nsclices)
 *		wrsm_wci_data (nwcis)
 *		wrsm_stripe_group (ngroups)
 *		wrsm_routing_policy (npolicy)
 *			wrsm_preferred_route (nroutes)
 *	wrsm_net_member (nmembers)
 *	ncslice_info.incoming_slices
 *	ncslice_info.slice_modes
 */
wrsm_controller_t *
wrsm_cf_unpack(char *data)
{
	wrsm_controller_t *cont;
	wrsm_routing_data_t *routing;
	int size;
	int i, j;

	size = 0;

	/* wrsm_controller */
	/* LINTED */
	cont = (wrsm_controller_t *)data;
	size += ROUNDUP(sizeof (wrsm_controller_t));

	/* wrsm_routing_data */
	/* LINTED */
	cont->WRSM_ALIGN_PTR(routing) = (wrsm_routing_data_t *)(data+size);
	size += ROUNDUP(sizeof (wrsm_routing_data_t));

	routing = cont->WRSM_ALIGN_PTR(routing);
	routing->WRSM_ALIGN_PTR(wcis) = malloc(sizeof (wrsm_wci_data_t *) *
	    routing->nwcis);
	if (!routing->WRSM_ALIGN_PTR(wcis))
		goto err_finish;

	for (i = 0; i < routing->nwcis; ++i) {
		/* LINTED */
		routing->WRSM_ALIGN_PTR(wcis)[i] = (wrsm_wci_data_t *)
		    (data+size);
		size += ROUNDUP(sizeof (wrsm_wci_data_t));
	}

	if (routing->ngroups) {
		routing->WRSM_ALIGN_PTR(stripe_groups) =
		    malloc(sizeof (wrsm_stripe_group_t *) * routing->ngroups);
		if (!routing->WRSM_ALIGN_PTR(stripe_groups))
			goto err_finish;

		for (i = 0; i < routing->ngroups; ++i) {
			routing->WRSM_ALIGN_PTR(stripe_groups)[i] =
			    /* LINTED */
			    (wrsm_stripe_group_t *)(data+size);
			size += ROUNDUP(sizeof (wrsm_stripe_group_t));
		}
	}

	routing->WRSM_ALIGN_PTR(policy) = malloc
	    (sizeof (wrsm_routing_policy_t *) *routing->npolicy);
	if (!routing->WRSM_ALIGN_PTR(policy))
		goto err_finish;

	for (i = 0; i < routing->npolicy; ++i) {
		wrsm_routing_policy_t *policy;

		routing->WRSM_ALIGN_PTR(policy)[i] =
		    /* LINTED */
		    (wrsm_routing_policy_t *)(data+size);
		size += ROUNDUP(sizeof (wrsm_routing_policy_t));

		policy = routing->WRSM_ALIGN_PTR(policy)[i];

		policy->WRSM_ALIGN_PTR(preferred_routes) =
		    malloc(sizeof (wrsm_preferred_route_t *) *
		    policy->nroutes);
		if (!policy->WRSM_ALIGN_PTR(preferred_routes))
			goto err_finish;

		for (j = 0; j < policy->nroutes; ++j) {
			policy->WRSM_ALIGN_PTR(preferred_routes)[j] =
			    /* LINTED */
			    (wrsm_preferred_route_t *)(data+size);
			size += ROUNDUP(sizeof (wrsm_preferred_route_t));
		}
	}

	cont->WRSM_ALIGN_PTR(members) =
	    malloc(sizeof (wrsm_net_member_t *) * cont->nmembers);
	if (!cont->WRSM_ALIGN_PTR(members))
		goto err_finish;

	for (i = 0; i < cont->nmembers; ++i) {
		/* LINTED */
		cont->WRSM_ALIGN_PTR(members)[i] = (wrsm_net_member_t *)
		    (data+size);
		size += ROUNDUP(sizeof (wrsm_net_member_t));
	}

	return (cont);

err_finish:
	/*
	 * Playing a little game here.  The top controller structure
	 * "cont" is allocated before this function is called, so we
	 * shouldn't free it.  Passing a "size" of 0 to wrsm_cf_free()
	 * does what we want be freeing the pointer lists and leaving
	 * the controller struct alone.
	 */
	wrsm_cf_free(cont, 0);
	return (NULL);
}

/*
 * Free all the components of an wrsm_controller_t struct
 */
void
wrsm_cf_free(wrsm_controller_t *cont, size_t size)
{
	wrsm_routing_data_t *routing;
	int i;

	if (!cont)
		return;

	routing = cont->WRSM_ALIGN_PTR(routing);
	if (!routing) {
		/* Already freed, don't bother doing anything else */
		return;
	}

	if (routing->nwcis && routing->WRSM_ALIGN_PTR(wcis))
		free(routing->WRSM_ALIGN_PTR(wcis));

	if (routing->ngroups && routing->WRSM_ALIGN_PTR(stripe_groups))
		free(routing->WRSM_ALIGN_PTR(stripe_groups));

	if (routing->npolicy && routing->WRSM_ALIGN_PTR(policy)) {
		wrsm_routing_policy_t *policy;
		for (i = 0; i < routing->npolicy; ++i) {
			policy = routing->WRSM_ALIGN_PTR(policy)[i];
			if (policy->nroutes &&
			    policy->WRSM_ALIGN_PTR(preferred_routes))
				free(policy->WRSM_ALIGN_PTR(preferred_routes));
		}

		free(routing->WRSM_ALIGN_PTR(policy));
	}

	if (cont->nmembers && cont->WRSM_ALIGN_PTR(members))
		free(cont->WRSM_ALIGN_PTR(members));

	if (size)
		free(cont);
}
