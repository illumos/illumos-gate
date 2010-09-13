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
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Routines to handle tsol_getrhbyaddr calls in nscd
 */

#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <libtsnet.h>
#include "cache.h"

#define	tsol_rh_db	ctx->nsc_db[0]

#define	NSC_NAME_TSOL_RH_BYADDR	"tsol_getrhbyaddr"

static int tsol_rh_compar(const void *, const void *);
static uint_t tsol_rh_gethash(nss_XbyY_key_t *, int);
static void tsol_rh_getlogstr(char *, char *, size_t, nss_XbyY_args_t *);

void
tnrhdb_init_ctx(nsc_ctx_t *ctx) {
	ctx->dbname = NSS_DBNAM_TSOL_RH;
	ctx->db_count = 1;
	ctx->file_name = TNRHDB_PATH;

	tsol_rh_db = make_cache(nsc_key_other,
			NSS_DBOP_TSOL_RH_BYADDR,
			NSC_NAME_TSOL_RH_BYADDR,
			tsol_rh_compar,
			tsol_rh_getlogstr,
			tsol_rh_gethash, nsc_ht_default, -1);
}

static void
tsol_rh_getlogstr(char *name, char *whoami, size_t len,
			nss_XbyY_args_t *argp) {

	(void) snprintf(whoami, len, "%s [key=%s, len=%d, addrtype=%d]",
		name, argp->key.hostaddr.addr, argp->key.hostaddr.len,
		argp->key.hostaddr.type);
}

static int
tsol_rh_compar(const void *n1, const void *n2) {
	nsc_entry_t	*e1, *e2;
	int		res, l1, l2;

	e1 = (nsc_entry_t *)n1;
	e2 = (nsc_entry_t *)n2;

	if (e1->key.hostaddr.type > e2->key.hostaddr.type)
		return (1);
	else if (e1->key.hostaddr.type < e2->key.hostaddr.type)
		return (-1);

	l1 = strlen(e1->key.hostaddr.addr);
	l2 = strlen(e2->key.hostaddr.addr);
	res = strncasecmp(e1->key.hostaddr.addr, e2->key.hostaddr.addr,
		(l1 > l2)?l1:l2);
	return (_NSC_INT_KEY_CMP(res, 0));
}

static uint_t
tsol_rh_gethash(nss_XbyY_key_t *key, int htsize) {
	return (db_gethash(key->hostaddr.addr,
			strlen(key->hostaddr.addr), htsize));
}
