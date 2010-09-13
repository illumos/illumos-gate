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

#include <mcamd_api.h>
#include <mcamd_err.h>

static const char *const _mcamd_errlist[] = {
	"Invalid syndrome",			/* EMCAMD_SYNDINVALID */
	"Invalid configuration tree",		/* EMCAMD_TREEINVALID */
	"Address not found",			/* EMCAMD_NOADDR */
	"Operation not supported",		/* EMCAMD_NOTSUP */
	"Too few valid address bits",		/* EMCAMD_INSUFF_RES */
};

static const int _mcamd_nerr = sizeof (_mcamd_errlist) /
    sizeof (_mcamd_errlist[0]);

void *
mcamd_set_errno_ptr(struct mcamd_hdl *mcamd, int err)
{
	(void) mcamd_set_errno(mcamd, err);
	return (NULL);
}

const char *
mcamd_strerror(int err)
{
	const char *str = NULL;

	if (err >= EMCAMD_BASE && (err - EMCAMD_BASE) < _mcamd_nerr)
		str = _mcamd_errlist[err - EMCAMD_BASE];

	return (str == NULL ? "Unknown error" : str);
}

const char *
mcamd_errmsg(struct mcamd_hdl *mcamd)
{
	return (mcamd_strerror(mcamd_errno(mcamd)));
}
