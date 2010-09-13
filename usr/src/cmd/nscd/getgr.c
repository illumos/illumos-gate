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
 * Routines to handle getgr* calls in nscd
 */

#include <stdlib.h>
#include "cache.h"

#define	nam_db	ctx->nsc_db[0]
#define	gid_db	ctx->nsc_db[1]

#define	NSC_NAME_GROUP_BYNAME	"getgrnam"
#define	NSC_NAME_GROUP_BYGID	"getgrgid"

static void grgid_getlogstr(char *, char *, size_t, nss_XbyY_args_t *);
static int grgid_compar(const void *, const void *);
static uint_t grgid_gethash(nss_XbyY_key_t *, int);

void
group_init_ctx(nsc_ctx_t *ctx) {
	ctx->dbname = NSS_DBNAM_GROUP;
	ctx->file_name = "/etc/group";
	ctx->db_count = 2;
	nam_db = make_cache(nsc_key_ces,
			NSS_DBOP_GROUP_BYNAME,
			NSC_NAME_GROUP_BYNAME,
			NULL, NULL, NULL, nsc_ht_default, -1);
	gid_db = make_cache(nsc_key_other,
			NSS_DBOP_GROUP_BYGID,
			NSC_NAME_GROUP_BYGID,
			grgid_compar,
			grgid_getlogstr,
			grgid_gethash, nsc_ht_default, -1);
}

static void
grgid_getlogstr(char *name, char *whoami, size_t len, nss_XbyY_args_t *argp) {
	(void) snprintf(whoami, len, "%s [key=%d]", name, argp->key.gid);
}

static int
grgid_compar(const void *n1, const void *n2) {
	nsc_entry_t	*e1, *e2;

	e1 = (nsc_entry_t *)n1;
	e2 = (nsc_entry_t *)n2;
	return (_NSC_INT_KEY_CMP(e1->key.gid, e2->key.gid));
}

static uint_t
grgid_gethash(nss_XbyY_key_t *key, int htsize) {
	return ((uint_t)key->gid % htsize);
}
