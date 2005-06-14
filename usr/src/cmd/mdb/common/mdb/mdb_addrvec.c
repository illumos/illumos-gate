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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <mdb/mdb_addrvec.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_modapi.h>

#include <strings.h>

#define	AD_INIT	16	/* initial size of addrvec array */
#define	AD_GROW	2	/* array growth multiplier */

void
mdb_addrvec_create(mdb_addrvec_t *adp)
{
	bzero(adp, sizeof (mdb_addrvec_t));
}

void
mdb_addrvec_destroy(mdb_addrvec_t *adp)
{
	mdb_free(adp->ad_data, sizeof (uintptr_t) * adp->ad_size);
	bzero(adp, sizeof (mdb_addrvec_t));
}

void
mdb_addrvec_unshift(mdb_addrvec_t *adp, uintptr_t value)
{
	if (adp->ad_nelems >= adp->ad_size) {
		size_t size = adp->ad_size ? adp->ad_size * AD_GROW : AD_INIT;
		void *data = mdb_alloc(sizeof (uintptr_t) * size, UM_SLEEP);

		bcopy(adp->ad_data, data, sizeof (uintptr_t) * adp->ad_size);
		mdb_free(adp->ad_data, sizeof (uintptr_t) * adp->ad_size);

		adp->ad_data = data;
		adp->ad_size = size;
	}

	adp->ad_data[adp->ad_nelems++] = value;
}

uintptr_t
mdb_addrvec_shift(mdb_addrvec_t *adp)
{
	if (adp->ad_ndx < adp->ad_nelems)
		return (adp->ad_data[adp->ad_ndx++]);

	return ((uintptr_t)-1L);
}

size_t
mdb_addrvec_length(mdb_addrvec_t *adp)
{
	if (adp != NULL) {
		ASSERT(adp->ad_nelems >= adp->ad_ndx);
		return (adp->ad_nelems - adp->ad_ndx);
	}

	return (0); /* convenience for callers */
}
