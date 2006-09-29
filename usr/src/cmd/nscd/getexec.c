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
 * Routines to handle getexec* calls in nscd
 */

#include <string.h>
#include <exec_attr.h>
#include "cache.h"

static int execattr_compar(const void *, const void *);
static uint_t execattr_gethash(nss_XbyY_key_t *, int);
static void execattr_getlogstr(char *, char *, size_t, nss_XbyY_args_t *);

#define	nam_db		ctx->nsc_db[0]
#define	id_db		ctx->nsc_db[1]
#define	nam_id_db	ctx->nsc_db[2]
#define	NSC_NAME_EXECATTR_BYNAME	"execattr_byname"
#define	NSC_NAME_EXECATTR_BYID		"execattr_byid"
#define	NSC_NAME_EXECATTR_BYNAMEID	"execattr_bynameid"

void
exec_init_ctx(nsc_ctx_t *ctx) {
	ctx->dbname = NSS_DBNAM_EXECATTR;
	ctx->file_name = "/etc/security/exec_attr";
	ctx->db_count = 3;
	nam_db = make_cache(nsc_key_other,
			NSS_DBOP_EXECATTR_BYNAME,
			NSC_NAME_EXECATTR_BYNAME,
			execattr_compar,
			execattr_getlogstr,
			execattr_gethash, nsc_ht_default, -1);
	id_db = make_cache(nsc_key_other,
			NSS_DBOP_EXECATTR_BYID,
			NSC_NAME_EXECATTR_BYID,
			execattr_compar,
			execattr_getlogstr,
			execattr_gethash, nsc_ht_default, -1);
	nam_id_db = make_cache(nsc_key_other,
			NSS_DBOP_EXECATTR_BYNAMEID,
			NSC_NAME_EXECATTR_BYNAMEID,
			execattr_compar,
			execattr_getlogstr,
			execattr_gethash, nsc_ht_default, -1);
}

#define	EXEC_STR_CMP(s1, s2) \
	if ((a = s1) == NULL) \
		a = z; \
	if ((b = s2) == NULL) \
		b = z; \
	res = strcmp(a, b); \
	if (res != 0) \
		return (res > 0 ? 1 : -1);

static int
execattr_compar(const void *n1, const void *n2) {
	nsc_entry_t	*e1 = (nsc_entry_t *)n1;
	nsc_entry_t	*e2 = (nsc_entry_t *)n2;
	_priv_execattr	*ep1 = (_priv_execattr *)e1->key.attrp;
	_priv_execattr	*ep2 = (_priv_execattr *)e2->key.attrp;
	int		res;
	const char	*a, *b, *z = "";

	/* compare name */
	EXEC_STR_CMP(ep1->name, ep2->name);

	/* compare policy */
	EXEC_STR_CMP(ep1->policy, ep2->policy);

	/* compare type */
	EXEC_STR_CMP(ep1->type, ep2->type);

	/* compare id */
	EXEC_STR_CMP(ep1->id, ep2->id);

	/* compare search flag */
	return (_NSC_INT_KEY_CMP(ep1->search_flag, ep2->search_flag));
}

static uint_t
execattr_gethash(nss_XbyY_key_t *key, int htsize) {
	_priv_execattr	*ep = key->attrp;
	char		keys[1024];
	int		len;

	len = snprintf(keys, sizeof (keys), "%s:%s:%s:%s:%d",
		ep->name ? ep->name : "", ep->type ? ep->type : "",
		ep->id ? ep->id : "", ep->policy ? ep->policy : "",
		ep->search_flag);
	return (db_gethash(keys, len, htsize));
}

static void
execattr_getlogstr(char *name, char *whoami, size_t len,
	nss_XbyY_args_t *argp) {
	_priv_execattr	*ep = argp->key.attrp;

	(void) snprintf(whoami, len,
		"%s [name=%s:type=%s:id=%s:policy=%s:flags=%d]",
		name, check_null(ep->name), check_null(ep->type),
		check_null(ep->id), check_null(ep->policy),
		ep->search_flag);
}
