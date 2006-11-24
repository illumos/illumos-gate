/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/cpu_module_impl.h>

#include "ao.h"

void
ao_mc_register(void *data, const cmi_mc_ops_t *mcops, void *mcdata)
{
	ao_data_t *ao = data;

	ASSERT(ao->ao_mc_ops == NULL);

	ao->ao_mc_ops = mcops;
	ao->ao_mc_data = mcdata;
}

const struct cmi_mc_ops *
ao_mc_getops(void *data)
{
	ao_data_t *ao = data;

	return (ao->ao_mc_ops);
}

int
ao_mc_patounum(ao_data_t *ao, uint64_t pa, uint8_t valid_hi, uint8_t valid_lo,
    uint32_t synd, int syndtype, mc_unum_t *unump)
{
	if (ao->ao_mc_ops == NULL)
		return (0);	/* mc not registered, or failed to load */

	return (ao->ao_mc_ops->cmi_mc_patounum(ao->ao_mc_data, pa,
	    valid_hi, valid_lo, synd, syndtype, unump));
}

int
ao_mc_unumtopa(ao_data_t *ao, mc_unum_t *unump, nvlist_t *nvl, uint64_t *pap)
{
	if (ao->ao_mc_ops == NULL)
		return (0);	/* mc not registered, or failed to load */

	return (ao->ao_mc_ops->cmi_mc_unumtopa(ao->ao_mc_data, unump, nvl,
	    pap));
}
