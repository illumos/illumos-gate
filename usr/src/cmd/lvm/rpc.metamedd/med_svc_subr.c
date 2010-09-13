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
 * Copyright (c) 1993, 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "med_local.h"

/*
 * return a response
 */
/*ARGSUSED*/
bool_t
med_null_1_svc(
	void		*argp,
	med_err_t	*res,
	struct svc_req	*rqstp		/* RPC stuff */
)
{
	/* Initialization */
	*res = med_null_err;

	/* do nothing */
	return (TRUE);
}

/*
 * Update the mediator data file.
 */
/*ARGSUSED*/
bool_t
med_upd_data_1_svc(
	med_upd_data_args_t	*argp,
	med_err_t		*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	int			err;

	/* Initialization */
	*res = med_null_err;

	/* setup, check permissions */
	if ((err = med_init(rqstp, W_OK, res)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	/* doit */
	if (med_db_init(res))
		goto out;

	(void) med_db_put_data(&argp->med, &argp->med_data, res);

out:
	return (TRUE);
}

/*
 * Get the mediator data
 */
/*ARGSUSED*/
bool_t
med_get_data_1_svc(
	med_args_t			*argp,
	med_get_data_res_t		*res,
	struct svc_req			*rqstp		/* RPC stuff */
)
{
	int				err;
	med_data_t			*meddp;
	med_err_t			*medep = &res->med_status;

	/* Initialization */
	(void) memset(res, 0, sizeof (*res));
	*medep = med_null_err;

	/* setup, check permissions */
	if ((err = med_init(rqstp, R_OK, medep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	/* doit */
	if (med_db_init(medep))
		goto out;

	if ((meddp = med_db_get_data(&argp->med, medep)) == NULL)
		goto out;

	res->med_data = *meddp;			/* structure assignment */

out:
	return (TRUE);
}

/*
 * Update the mediator record.
 */
/*ARGSUSED*/
bool_t
med_upd_rec_1_svc(
	med_upd_rec_args_t	*argp,
	med_err_t		*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	int			err;

	/* Initialization */
	*res = med_null_err;

	/* setup, check permissions */
	if ((err = med_init(rqstp, W_OK, res)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	/* doit */
	if (med_db_init(res))
		goto out;

	(void) med_db_put_rec(&argp->med, &argp->med_rec, res);

out:
	return (TRUE);
}

/*
 * Get the mediator record
 */
/*ARGSUSED*/
bool_t
med_get_rec_1_svc(
	med_args_t			*argp,
	med_get_rec_res_t		*res,
	struct svc_req			*rqstp		/* RPC stuff */
)
{
	med_rec_t			*medrp;
	int				err;
	med_err_t			*medep = &res->med_status;

	/* Initialization */
	(void) memset(res, 0, sizeof (*res));
	*medep = med_null_err;

	/* setup, check permissions */
	if ((err = med_init(rqstp, R_OK, medep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	/* doit */
	if (med_db_init(medep))
		goto out;

	if ((medrp = med_db_get_rec(&argp->med, medep)) == NULL)
		goto out;

	res->med_rec = *medrp;			/* structure assignment */

out:
	return (TRUE);
}

/*
 * return the official host name for the callee
 */
/*ARGSUSED*/
bool_t
med_hostname_1_svc(
	void 			*argp,
	med_hnm_res_t 		*res,
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	med_err_t		*medep = &res->med_status;
	int			err;

	/* Initialization */
	(void) memset(res, 0, sizeof (*res));
	*medep = med_null_err;

	/* setup, check permissions */
	if ((err = med_init(rqstp, R_OK, medep)) < 0)
		return (FALSE);
	else if (err != 0)
		return (TRUE);

	/* doit */
	res->med_hnm = Strdup(mynode());

	return (TRUE);
}
