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

/*
 * Configuration parser for the Wildcat RSM driver.  This file parses the
 * configuration data structure passed in by the INITIALCONFIG and
 * REPLACECONFIG ioctls, and constructs a config data structure usable by
 * the Wildcat RSM driver.
 */

#include <sys/param.h>
#include <sys/kmem.h>
#include <sys/wrsm_common.h>

#include <sys/cmn_err.h>
#include <sys/wrsm_config.h>

#define	PACK_DEBUG 1

#ifdef DEBUG
static uint_t wrsm_pack_debug = 0;
#define	DPRINTF(a, b) { if (wrsm_pack_debug & a) wrsmdprintf b; }
#else
#define	DPRINTF(a, b) { }
#endif /* DEBUG */

#define	ROUNDUP(x) (((x) + 0x07) & ~0x07)

void wrsm_cf_free(wrsm_controller_t *cont);

/*
 * wrsm_controller
 *	wrsm_routing_data (1)
 *		wrsm_wci_data (nwcis)
 *		wrsm_stripe_group (ngroups)
 *		wrsm_routing_policy (npolicy)
 *			wrsm_preferred_route (nroutes)
 *	wrsm_net_member (nmembers)
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
	cont = (wrsm_controller_t *)data;
	size += ROUNDUP(sizeof (wrsm_controller_t));

	/* wrsm_routing_data */
	cont->routing = (wrsm_routing_data_t *)(data+size);
	size += ROUNDUP(sizeof (wrsm_routing_data_t));

	routing = cont->routing;
	routing->wcis = kmem_alloc(sizeof (wrsm_wci_data_t *) *
	    routing->nwcis, KM_SLEEP);
	if (!routing->wcis) {
		DPRINTF(PACK_DEBUG, (CE_WARN, "cf_unpack: no wcis"));
		goto err_finish;
	}

	DPRINTF(PACK_DEBUG, (CE_CONT, "cf_unpack: nwcis=%d", routing->nwcis));

	for (i = 0; i < routing->nwcis; ++i) {
		routing->wcis[i] = (wrsm_wci_data_t *)(data+size);
		size += ROUNDUP(sizeof (wrsm_wci_data_t));
		DPRINTF(PACK_DEBUG, (CE_CONT, "cf_unpack: wci %d port=%d", i,
		    routing->wcis[i]->port));
	}

	if (routing->ngroups) {
		DPRINTF(PACK_DEBUG, (CE_CONT, "cf_unpack: ngroups=%d",
		    routing->ngroups));
		routing->stripe_groups =
		    kmem_alloc(sizeof (wrsm_stripe_group_t *) *
		    routing->ngroups, KM_SLEEP);
		if (!routing->stripe_groups) {
			DPRINTF(PACK_DEBUG, (CE_WARN, "cf_unpack: "
			    "no stripe_groups"));
			goto err_finish;
		}

		for (i = 0; i < routing->ngroups; ++i) {
			routing->stripe_groups[i] = (wrsm_stripe_group_t *)
			    (data+size);
			size += ROUNDUP(sizeof (wrsm_stripe_group_t));
		}
	}

	DPRINTF(PACK_DEBUG, (CE_CONT, "cf_unpack: npolicy=%d",
	    routing->npolicy));

	routing->policy = kmem_alloc(sizeof (wrsm_routing_policy_t *) *
	    routing->npolicy, KM_SLEEP);
	if (!routing->policy) {
		DPRINTF(PACK_DEBUG, (CE_WARN, "cf_unpack: no policy"));
		goto err_finish;
	}

	for (i = 0; i < routing->npolicy; ++i) {
		wrsm_routing_policy_t *policy;

		routing->policy[i] = (wrsm_routing_policy_t *)(data+size);
		size += ROUNDUP(sizeof (wrsm_routing_policy_t));

		policy = routing->policy[i];

		DPRINTF(PACK_DEBUG, (CE_CONT, "cf_unpack: policy 0x%p, "
		    "cnodeid=%d", (void *)policy, policy->cnodeid));
		DPRINTF(PACK_DEBUG, (CE_CONT, "cf_unpack: nroutes=%d",
		    policy->nroutes));
		policy->preferred_routes =
		    kmem_alloc(sizeof (wrsm_preferred_route_t *) *
		    policy->nroutes, KM_SLEEP);
		if (!policy->preferred_routes) {
			DPRINTF(PACK_DEBUG, (CE_WARN, "cf_unpack: "
			    "no preferred_routes nroutes=%d",
			    policy->nroutes));
			goto err_finish;
		}

		for (j = 0; j < policy->nroutes; ++j) {
			policy->preferred_routes[j] =
			    (wrsm_preferred_route_t *)(data+size);
			size += ROUNDUP(sizeof (wrsm_preferred_route_t));
		}
	}

	cont->members = kmem_alloc(sizeof (wrsm_net_member_t *) *
	    cont->nmembers, KM_SLEEP);
	if (!cont->members) {
		DPRINTF(PACK_DEBUG, (CE_WARN, "cf_unpack: no members"));
		goto err_finish;
	}

	for (i = 0; i < cont->nmembers; ++i) {
		cont->members[i] = (wrsm_net_member_t *)(data+size);
		size += ROUNDUP(sizeof (wrsm_net_member_t));
	}

	return (cont);

err_finish:
	DPRINTF(PACK_DEBUG, (CE_WARN, "wrsm_cf_unpack failed"));
	wrsm_cf_free(cont);
	return (NULL);
}

/*
 * Free all the components of an wrsm_controller_t struct
 */
void
wrsm_cf_free(wrsm_controller_t *cont)
{
	wrsm_routing_data_t *routing;
	int i;

	if (!cont)
		return;

	routing = cont->routing;

	if (!routing)
		return;

	if (routing->nwcis && routing->wcis)
		kmem_free(routing->wcis, sizeof (wrsm_wci_data_t *)
		    * routing->nwcis);

	if (routing->ngroups && routing->stripe_groups)
		kmem_free(routing->stripe_groups,
		    sizeof (wrsm_stripe_group_t *) * routing->ngroups);

	if (routing->npolicy && routing->policy) {
		wrsm_routing_policy_t *policy;
		for (i = 0; i < routing->npolicy; ++i) {
			policy = routing->policy[i];
			if (policy->nroutes && policy->preferred_routes)
				kmem_free(policy->preferred_routes,
				    sizeof (wrsm_preferred_route_t *) *
				    policy->nroutes);
		}

		kmem_free(routing->policy, sizeof (wrsm_routing_policy_t *) *
		    routing->npolicy);
	}

	if (cont->nmembers && cont->members)
		kmem_free(cont->members, sizeof (wrsm_net_member_t *) *
		    cont->nmembers);
}
