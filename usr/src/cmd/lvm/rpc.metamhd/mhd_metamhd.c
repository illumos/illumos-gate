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
 * Copyright (c) 1994, 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mhd_local.h"

/*
 * list drives
 */
/*ARGSUSED*/
bool_t
mhd_list_1_svc(
	mhd_list_args_t		*argp,
	mhd_list_res_t		*resp,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	mhd_error_t		*mhep = &resp->status;
	int			err;

	/* setup, check permissions */
	(void) memset(resp, 0, sizeof (*resp));
	if ((err = mhd_init(rqstp, R_OK, mhep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	/* doit */
	(void) mhd_list_drives(argp->path, argp->flags, resp, mhep);
	return (TRUE);
}

/*
 * take ownership of drives
 */
/*ARGSUSED*/
bool_t
mhd_tkown_1_svc(
	mhd_tkown_args_t	*argp,
	mhd_error_t		*mhep,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	int			err;

	/* setup, check permissions */
	if ((err = mhd_init(rqstp, W_OK, mhep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	/* doit */
	(void) mhd_reserve_drives(&argp->set, &argp->timeouts, argp->ff_mode,
	    argp->options, mhep);
	return (TRUE);
}

/*
 * release ownership of drives
 */
/*ARGSUSED*/
bool_t
mhd_relown_1_svc(
	mhd_relown_args_t	*argp,
	mhd_error_t		*mhep,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	int			err;

	/* setup, check permissions */
	if ((err = mhd_init(rqstp, W_OK, mhep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	/* doit */
	(void) mhd_release_drives(&argp->set, argp->options, mhep);
	return (TRUE);
}

/*
 * status drives
 */
/*ARGSUSED*/
bool_t
mhd_status_1_svc(
	mhd_status_args_t	*argp,
	mhd_status_res_t	*resp,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	mhd_error_t		*mhep = &resp->status;
	mhd_drive_status_t	*status = NULL;
	int			cnt;
	int			err;

	/* setup, check permissions */
	(void) memset(resp, 0, sizeof (*resp));
	if ((err = mhd_init(rqstp, W_OK, mhep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	/* doit */
	if ((cnt = mhd_status_drives(&argp->set, argp->options,
	    &status, mhep)) < 0) {
		return (TRUE);
	}
	resp->results.results_len = cnt;
	resp->results.results_val = status;
	return (TRUE);
}
