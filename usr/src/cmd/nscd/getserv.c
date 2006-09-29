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
 * Routines to handle getserv* calls in nscd
 */

#include <strings.h>
#include "cache.h"


#define	name_db	ctx->nsc_db[0]
#define	port_db	ctx->nsc_db[1]

#define	NSC_NAME_SERVICES_BYNAME	"getservbyname"
#define	NSC_NAME_SERVICES_BYPORT	"getservbyport"

static void servname_getlogstr(char *, char *, size_t, nss_XbyY_args_t *);
static int servname_compar(const void *, const void *);
static uint_t servname_gethash(nss_XbyY_key_t *, int);

static void servport_getlogstr(char *, char *, size_t, nss_XbyY_args_t *);
static int servport_compar(const void *, const void *);
static uint_t servport_gethash(nss_XbyY_key_t *, int);

void
serv_init_ctx(nsc_ctx_t *ctx) {
	ctx->dbname = NSS_DBNAM_SERVICES;
	ctx->file_name = "/etc/services";
	ctx->db_count = 2;
	name_db = make_cache(nsc_key_other,
			NSS_DBOP_SERVICES_BYNAME,
			NSC_NAME_SERVICES_BYNAME,
			servname_compar,
			servname_getlogstr,
			servname_gethash, nsc_ht_default, -1);

	port_db = make_cache(nsc_key_other,
			NSS_DBOP_SERVICES_BYPORT,
			NSC_NAME_SERVICES_BYPORT,
			servport_compar,
			servport_getlogstr,
			servport_gethash, nsc_ht_default, -1);
}

static int
servname_compar(const void *n1, const void *n2) {
	nsc_entry_t	*e1, *e2;
	int		res, l1, l2;

	e1 = (nsc_entry_t *)n1;
	e2 = (nsc_entry_t *)n2;

	/* compare protocol */
	if (e1->key.serv.proto == NULL && e2->key.serv.proto)
		return (-1);
	if (e1->key.serv.proto && e2->key.serv.proto == NULL)
		return (1);
	if (e1->key.serv.proto) {
		l1 = strlen(e1->key.serv.proto);
		l2 = strlen(e2->key.serv.proto);
		res = strncmp(e1->key.serv.proto, e2->key.serv.proto,
			(l1 > l2)?l1:l2);
		if (res > 0)
			return (1);
		if (res < 0)
			return (-1);
	}

	/* compare service name */
	l1 = strlen(e1->key.serv.serv.name);
	l2 = strlen(e2->key.serv.serv.name);
	res = strncmp(e1->key.serv.serv.name, e2->key.serv.serv.name,
			(l1 > l2)?l1:l2);
	return (_NSC_INT_KEY_CMP(res, 0));
}

static uint_t
servname_gethash(nss_XbyY_key_t *key, int htsize) {
	return (ces_gethash(key->serv.serv.name, htsize));
}

static void
servname_getlogstr(char *name, char *whoami, size_t len,
			nss_XbyY_args_t *argp) {
	(void) snprintf(whoami, len, "%s [key=%s, %s]",
			name,
			argp->key.serv.serv.name,
			check_null(argp->key.serv.proto));
}

static int
servport_compar(const void *n1, const void *n2) {
	nsc_entry_t	*e1, *e2;
	int		res, l1, l2;

	e1 = (nsc_entry_t *)n1;
	e2 = (nsc_entry_t *)n2;

	/* compare protocol */
	if (e1->key.serv.proto == NULL && e2->key.serv.proto)
		return (-1);
	if (e1->key.serv.proto && e2->key.serv.proto == NULL)
		return (1);
	if (e1->key.serv.proto) {
		l1 = strlen(e1->key.serv.proto);
		l2 = strlen(e2->key.serv.proto);
		res = strncmp(e1->key.serv.proto, e2->key.serv.proto,
				(l1 > l2)?l1:l2);
		if (res > 0)
			return (1);
		if (res < 0)
			return (-1);
	}

	/* compare port */
	return (_NSC_INT_KEY_CMP(e1->key.serv.serv.port,
			e2->key.serv.serv.port));
}

static uint_t
servport_gethash(nss_XbyY_key_t *key, int htsize) {
	return (db_gethash(&key->serv.serv.port,
			sizeof (key->serv.serv.port), htsize));
}

static void
servport_getlogstr(char *name, char *whoami, size_t len,
			nss_XbyY_args_t *argp) {
	(void) snprintf(whoami, len, "%s [key=%d, %s]",
			name,
			argp->key.serv.serv.port,
			check_null(argp->key.serv.proto));
}
