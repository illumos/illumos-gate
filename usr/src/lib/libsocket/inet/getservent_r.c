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
 *
 * lib/libsocket/inet/getservent_r.c
 *
 * This file defines and implements the re-entrant enumeration routines for
 *   services: setservent(), getservent_r(), and endservent(). They consult
 *   the switch policy directly and do not "share" their enumeration state
 *   nor the stayopen flag with the implentation of the more common
 *   getservbyname_r()/getservbyport_r(). The latter follows a tortuous
 *   route in order to be consistent with netdir_getbyYY() (see
 *   getservbyname_r.c and lib/libnsl/nss/netdir_inet.c).
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <nss_dbdefs.h>

/*
 * str2servent is implemented in libnsl, libnsl/nss/netdir_inet.c, since
 * the "engine" of the new gethost/getserv/netdir lives in libnsl.
 */
int str2servent(const char *, int, void *, char *, int);

/*
 * Unsynchronized, but it affects only
 * efficiency, not correctness.
 */
static int services_stayopen;
static DEFINE_NSS_DB_ROOT(db_root);
static DEFINE_NSS_GETENT(context);

void
_nss_initf_services(nss_db_params_t *p)
{
	p->name	= NSS_DBNAM_SERVICES;
	p->default_config = NSS_DEFCONF_SERVICES;
}

int
setservent(int stay)
{
	services_stayopen |= stay;
	nss_setent(&db_root, _nss_initf_services, &context);
	return (0);
}

int
endservent()
{
	services_stayopen = 0;
	nss_endent(&db_root, _nss_initf_services, &context);
	nss_delete(&db_root);
	return (0);
}

struct servent *
getservent_r(struct servent *result, char *buffer, int buflen)
{
	nss_XbyY_args_t arg;
	nss_status_t	res;

	NSS_XbyY_INIT(&arg, result, buffer, buflen, str2servent);
	/*
	 * Setting proto to NULL here is a bit of a hack since we share
	 * the parsing code in the NIS+ backend with our getservbyYY()
	 * brethren who can search on 1-1/2 key. If they pass a NULL
	 * proto, the parsing code deals with it by picking the protocol
	 * from the first NIS+ matching object and combining all entries
	 * with "that" proto field. NIS+ is the only name service, so far,
	 * that can return multiple entries on a lookup.
	 */
	arg.key.serv.proto	= NULL;
	/* === No stayopen flag;  of course you stay open for iteration */
	res = nss_getent(&db_root, _nss_initf_services, &context, &arg);
	arg.status = res;
	return (struct servent *)NSS_XbyY_FINI(&arg);
}
