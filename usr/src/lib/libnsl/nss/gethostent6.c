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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file defines and implements the re-entrant enumeration routines for
 *   IPv6 hosts: sethostent6(), gethostent6(), and endhostent6().
 *   They consult the switch policy directly and do not "share" their
 *   enumeration state nor the stayopen flag with the implentation of the
 *   more commonly used getipnodebyname()/getipnodebyaddr(). The latter
 *   follows a tortuous route in order to be consistent with netdir_getbyYY()
 *   (see getipnodebyname.c and netdir_inet.c).
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mt.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <nss_dbdefs.h>
#include "nss.h"

static int ipnodes_stayopen;
/*
 * Unsynchronized, but it affects only
 * efficiency, not correctness
 */

static DEFINE_NSS_DB_ROOT(db_root);
static DEFINE_NSS_GETENT(context);

/* IPv6 wrapper for __str2hostent() */
int
str2hostent6(const char *instr, int lenstr, void *ent, char *buffer, int buflen)
{
	return (__str2hostent(AF_INET6, instr, lenstr, ent, buffer, buflen));
}

void
_nss_initf_ipnodes(nss_db_params_t *p)
{
	p->name	= NSS_DBNAM_IPNODES;
	p->default_config = NSS_DEFCONF_IPNODES;
}

int
__sethostent6(int stay)
{
	ipnodes_stayopen |= stay;
	nss_setent(&db_root, _nss_initf_ipnodes, &context);
	return (0);
}

int
__endhostent6(void)
{
	ipnodes_stayopen = 0;
	nss_endent(&db_root, _nss_initf_ipnodes, &context);
	nss_delete(&db_root);
	return (0);
}

struct hostent *
__gethostent6(struct hostent *result, char *buffer, int buflen, int *h_errnop)
{
	nss_XbyY_args_t arg;
	nss_status_t	res;

	NSS_XbyY_INIT(&arg, result, buffer, buflen, str2hostent6);
	res = nss_getent(&db_root, _nss_initf_ipnodes,
	    &context, &arg);
	arg.status = res;
	*h_errnop = arg.h_errno;
	return ((struct hostent *)NSS_XbyY_FINI(&arg));
}
