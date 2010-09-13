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

/*
 * Rentrant (MT-safe) getrpcYY interfaces.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mt.h"
#include <ctype.h>
#include <nss_dbdefs.h>
#include <stdlib.h>
#include <string.h>
#include <rpc/rpcent.h>

extern int str2rpcent(const char *, int, void *, char *, int);

static int rpc_stayopen;	/* Unsynchronized, but it affects only	*/
				/*   efficiency, not correctness	*/
static DEFINE_NSS_DB_ROOT(db_root);
static DEFINE_NSS_GETENT(context);

void
_nss_initf_rpc(nss_db_params_t *p)
{
	p->name	= NSS_DBNAM_RPC;
	p->default_config = NSS_DEFCONF_RPC;
}

struct rpcent *
getrpcbyname_r(const char *name, struct rpcent *result, char *buffer,
								int buflen)
{
	nss_XbyY_args_t arg;
	nss_status_t	res;

	if (name == (const char *)NULL) {
		errno = ERANGE;
		return (NULL);
	}
	NSS_XbyY_INIT(&arg, result, buffer, buflen, str2rpcent);
	arg.key.name	= name;
	arg.stayopen	= rpc_stayopen;
	res = nss_search(&db_root, _nss_initf_rpc,
		NSS_DBOP_RPC_BYNAME, &arg);
	arg.status = res;
	return ((struct rpcent *)NSS_XbyY_FINI(&arg));
}

struct rpcent *
getrpcbynumber_r(const int number, struct rpcent *result, char *buffer,
								int buflen)
{
	nss_XbyY_args_t arg;
	nss_status_t	res;

	NSS_XbyY_INIT(&arg, result, buffer, buflen, str2rpcent);
	arg.key.number	= number;
	arg.stayopen	= rpc_stayopen;
	res = nss_search(&db_root, _nss_initf_rpc,
		NSS_DBOP_RPC_BYNUMBER, &arg);
	arg.status = res;
	return ((struct rpcent *)NSS_XbyY_FINI(&arg));
}

void
setrpcent(const int stay)
{
	rpc_stayopen |= stay;
	nss_setent(&db_root, _nss_initf_rpc, &context);
}

void
endrpcent(void)
{
	rpc_stayopen = 0;
	nss_endent(&db_root, _nss_initf_rpc, &context);
	nss_delete(&db_root);
}

struct rpcent *
getrpcent_r(struct rpcent *result, char *buffer, int buflen)
{
	nss_XbyY_args_t arg;
	nss_status_t	res;

	NSS_XbyY_INIT(&arg, result, buffer, buflen, str2rpcent);
	/* No key, no stayopen */
	res = nss_getent(&db_root, _nss_initf_rpc, &context, &arg);
	arg.status = res;
	return ((struct rpcent *)NSS_XbyY_FINI(&arg));
}

int
str2rpcent(const char *instr, int lenstr, void *ent, char *buffer, int buflen)
{
	struct rpcent	*rpc	= (struct rpcent *)ent;
	const char	*p, *numstart, *limit, *namestart;
	ssize_t		numlen, namelen = 0;
	char		numbuf[12];
	char		*numend;

	if ((instr >= buffer && (buffer + buflen) > instr) ||
			(buffer >= instr && (instr + lenstr) > buffer))
		return (NSS_STR_PARSE_PARSE);

	p = instr;
	limit = p + lenstr;

	while (p < limit && isspace(*p)) {
		p++;
	}
	namestart = p;
	while (p < limit && !isspace(*p)) {
		p++;		/* Skip over the canonical name */
	}
	namelen = p - namestart;

	if (buflen <= namelen)		/* not enough buffer */
		return (NSS_STR_PARSE_ERANGE);
	(void) memcpy(buffer, namestart, namelen);
	buffer[namelen] = '\0';
	rpc->r_name = buffer;

	while (p < limit && isspace(*p)) {
		p++;
	}
	if (p >= limit)			/* Syntax error -- no RPC number */
		return (NSS_STR_PARSE_PARSE);
	numstart = p;
	do {
		p++;		/* Find the end of the RPC number */
	} while (p < limit && !isspace(*p));
	numlen = p - numstart;
	if (numlen >= sizeof (numbuf)) {
		/* Syntax error -- supposed number is too long */
		return (NSS_STR_PARSE_PARSE);
	}
	(void) memcpy(numbuf, numstart, numlen);
	numbuf[numlen] = '\0';
	rpc->r_number = (int)strtol(numbuf, &numend, 10);
	if (*numend != '\0')
		return (NSS_STR_PARSE_PARSE);

	while (p < limit && isspace(*p)) {
		p++;
	}
	/*
	 * Although nss_files_XY_all calls us with # stripped,
	 * we should be able to deal with it here in order to
	 * be more useful.
	 */
	if (p >= limit || *p == '#') { /* no aliases, no problem */
		char **ptr;

		ptr = (char **)ROUND_UP(buffer + namelen + 1,
							sizeof (char *));
		if ((char *)ptr >= buffer + buflen) {
			rpc->r_aliases = 0; /* hope they don't try to peek in */
			return (NSS_STR_PARSE_ERANGE);
		}
		*ptr = 0;
		rpc->r_aliases = ptr;
		return (NSS_STR_PARSE_SUCCESS);
	}
	rpc->r_aliases = _nss_netdb_aliases(p, (int)(lenstr - (p - instr)),
			buffer + namelen + 1, (int)(buflen - namelen - 1));
	return (NSS_STR_PARSE_SUCCESS);
}
