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
 * Routines to handle getproj* calls in nscd
 */

#include <stdlib.h>
#include "cache.h"

#define	nam_db	ctx->nsc_db[0]
#define	pid_db	ctx->nsc_db[1]

#define	NSC_NAME_PROJECT_BYNAME	"getprojbyname"
#define	NSC_NAME_PROJECT_BYID	"getprojbyid"

static void projid_getlogstr(char *, char *, size_t, nss_XbyY_args_t *);
static int projid_compar(const void *, const void *);
static uint_t projid_gethash(nss_XbyY_key_t *, int);

void
project_init_ctx(nsc_ctx_t *ctx) {
	ctx->dbname = NSS_DBNAM_PROJECT;
	ctx->file_name = "/etc/project";
	ctx->db_count = 2;
	nam_db = make_cache(nsc_key_ces,
			NSS_DBOP_PROJECT_BYNAME,
			NSC_NAME_PROJECT_BYNAME,
			NULL, NULL, NULL, nsc_ht_default, -1);

	pid_db = make_cache(nsc_key_other,
			NSS_DBOP_PROJECT_BYID,
			NSC_NAME_PROJECT_BYID,
			projid_compar,
			projid_getlogstr,
			projid_gethash, nsc_ht_default, -1);
}

static int
projid_compar(const void *n1, const void *n2) {
	nsc_entry_t	*e1, *e2;

	e1 = (nsc_entry_t *)n1;
	e2 = (nsc_entry_t *)n2;
	return (_NSC_INT_KEY_CMP(e1->key.projid, e2->key.projid));
}

static uint_t
projid_gethash(nss_XbyY_key_t *key, int htsize) {
	return (db_gethash(&key->projid, sizeof (key->projid), htsize));
}

static void
projid_getlogstr(char *name, char *whoami, size_t len, nss_XbyY_args_t *argp) {
	(void) snprintf(whoami, len, "%s [key=%d]", name, argp->key.projid);
}
