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
 * This file contains functions used to serialize rsm controller
 * data structures in preperation for injecting into the kernel.
 */

#include <stdlib.h>
#include <string.h>
#include <sys/wrsm_config.h>

#define	PACK_SIZE 1
#define	PACK_DATA 2

#define	ROUNDUP(x) (((x) + 0x07) & ~0x07)


static void *
cf_pack_cont(wrsm_controller_t *cont, int flag, int *sizep)
{
	char *data;
	int size;
	int i, j;
	wrsm_routing_data_t *routing;

	if (flag == PACK_DATA) {
		data = (void *)calloc(1, *sizep);
		if (!data)
			return (NULL);
	}
	size = 0;

	/* wrsm_controller */
	if (flag == PACK_DATA)
		(void) memcpy((data+size), cont, sizeof (wrsm_controller_t));
	size += ROUNDUP(sizeof (wrsm_controller_t));

	/* wrsm_routing_data */
	if (flag == PACK_DATA)
		(void) memcpy((data+size), cont->WRSM_ALIGN_PTR(routing),
		    sizeof (wrsm_routing_data_t));
	size += ROUNDUP(sizeof (wrsm_routing_data_t));
	routing = cont->WRSM_ALIGN_PTR(routing);


	for (i = 0; i < routing->nwcis; ++i) {
		wrsm_wci_data_t *wci;
		wci = routing->WRSM_ALIGN_PTR(wcis)[i];
		if (flag == PACK_DATA)
			(void) memcpy((data+size), wci,
			    sizeof (wrsm_wci_data_t));
		size += ROUNDUP(sizeof (wrsm_wci_data_t));
	}

	for (i = 0; i < routing->ngroups; ++i) {
		wrsm_stripe_group_t *group;
		group = routing->WRSM_ALIGN_PTR(stripe_groups)[i];
		if (flag == PACK_DATA)
			(void) memcpy((data+size), group,
			    sizeof (wrsm_stripe_group_t));
		size += ROUNDUP(sizeof (wrsm_stripe_group_t));
	}

	for (i = 0; i < routing->npolicy; ++i) {
		wrsm_routing_policy_t *policy;
		wrsm_preferred_route_t *route;

		policy = routing->WRSM_ALIGN_PTR(policy)[i];
		if (flag == PACK_DATA)
			(void) memcpy((data+size), policy,
			    sizeof (wrsm_routing_policy_t));
		size += ROUNDUP(sizeof (wrsm_routing_policy_t));

		for (j = 0; j < policy->nroutes; ++j) {
			route = policy->
			    WRSM_ALIGN_PTR(preferred_routes)[j];
			if (flag == PACK_DATA)
				(void) memcpy((data+size), route,
				    sizeof (wrsm_preferred_route_t));
			size += ROUNDUP(sizeof (wrsm_preferred_route_t));
		}

	}

	/* wrsm_net_member */
	for (i = 0; i < cont->nmembers; ++i) {
		wrsm_net_member_t *member;
		member = cont->WRSM_ALIGN_PTR(members)[i];
		if (flag == PACK_DATA)
			(void) memcpy((data+size), member,
			    sizeof (wrsm_net_member_t));
		size += ROUNDUP(sizeof (wrsm_net_member_t));
	}

	if (flag == PACK_SIZE) {
		*sizep = size;
		return (NULL);
	}
	return (data);
}

void *
wrsm_cf_pack(wrsm_controller_t *cont, int *sizep)
{
	int block_size;
	void *data;

	(void) cf_pack_cont(cont, PACK_SIZE, &block_size);
	data = cf_pack_cont(cont, PACK_DATA, &block_size);
	if (sizep)
		*sizep = block_size;
	return (data);
}

void
wrsm_free_packed_cont(wrsm_controller_t *cont)
{
	if (cont)
		free(cont);
}
