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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <postgres.h>
#include <fmgr.h>
PG_MODULE_MAGIC;
#include <string.h>
#include "mms_network.h"
#include "host_ident.h"

/*
 * Postgres server library for MMS client ip address.
 */

PG_FUNCTION_INFO_V1(pg_host_ident);

Datum
pg_host_ident(PG_FUNCTION_ARGS)
{
	void	*pg_host_str;
	void	*pg_ident;
	int32	len;
	char	host_str[MMS_HOST_IDENT_LEN+1];
	char	host[MMS_HOST_IDENT_LEN+1];
	char	ip[MMS_IP_IDENT_LEN+1];
	char	*ident;

	/* test for null arg */
	if (PG_NARGS() != 1 || PG_ARGISNULL(0)) {
		/* LINTED: end-of-loop code not reached */
		PG_RETURN_NULL();
	}

	/* get pointer to arg */
	if ((pg_host_str = (void *) PG_GETARG_TEXT_P(0)) == NULL) {
		/* LINTED: end-of-loop code not reached */
		PG_RETURN_NULL();
	}

	/* check for null pointer */
	if (VARDATA(pg_host_str) == NULL) {
		/* LINTED: end-of-loop code not reached */
		PG_RETURN_NULL();
	}

	/* get string length */
	len = VARSIZE(pg_host_str) - VARHDRSZ;
	if (len < 1 || len >= sizeof (host_str)) {
		/* LINTED: end-of-loop code not reached */
		PG_RETURN_NULL();
	}

	/* must null terminate copy of input string */
	(void) memcpy(host_str, VARDATA(pg_host_str), len);
	host_str[len] = '\0'; /* must do!!! */

	/* find ident (ip address), host_str is a host name or ip address */
	if ((ident = mms_host_ident(host_str, host, ip)) == NULL) {
		/* LINTED: end-of-loop code not reached */
		PG_RETURN_NULL();
	}

	/* ident is what mm uses internally (ip address) */
	len = VARHDRSZ + strlen(ident);
	if ((pg_ident = (void *) palloc(len)) == NULL) {
		/* LINTED: end-of-loop code not reached */
		PG_RETURN_NULL();
	}
	SET_VARSIZE(pg_ident, len);

	/* don't copy string null terminator, pg string struct has length */
	(void) memcpy(VARDATA(pg_ident), ident, strlen(ident));

	PG_RETURN_TEXT_P(pg_ident);
}
