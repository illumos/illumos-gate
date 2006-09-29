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
 * gethostbyname_r() is defined in this file.  It is implemented on top of
 *   _get_hostserv_inetnetdir_byname() which is also used to implement
 *   netdir_getbyname() for inet family transports.  In turn the common code
 *   uses the name service switch policy for "hosts" and "services" unless
 *   the administrator chooses to bypass the name service switch by
 *   specifying third-party supplied nametoaddr libs for inet transports
 *   in /etc/netconfig.
 *
 * gethostbyaddr_r() is similarly related to _get_hostserv_inetnetdir_byaddr()
 *   and netdir_getbyaddr();
 *
 * The common code lives in netdir_inet.c.
 *
 * gethostent_r(), sethostent() and endhostent() are *not* implemented on top
 *   of the common interface;  they go straight to the switch and are
 *   defined in gethostent_r.c.
 *
 * There is absolutely no data sharing, not even the stayopen flag or
 *   enumeration state, between gethostbyYY_r() and gethostent_r();
 */

#include "mt.h"
#include <netdb.h>
#include <netdir.h>
#include <sys/types.h>
#include <nss_netdir.h>
#include <string.h>

extern struct netconfig *__rpc_getconfip();

/*
 * h_errno POLICY: The frontends expect the name service
 * backends to modify the h_errno in "arg"; _switch_gethostbyYY_r()
 * will copy that over onto user's h_errnop pointer. This h_errno is
 * never used for "switching" -- status from nss_search serves
 * the purpose. There is no explicit zeroing in the case of success.
 */

extern struct hostent *
_switch_gethostbyname_r(const char *nam, struct hostent *result, char *buffer,
	int buflen, int *h_errnop);

extern struct hostent *
_switch_gethostbyaddr_r(const char *addr, int length, int type,
	struct hostent *result, char *buffer, int buflen, int *h_errnop);

#ifdef PIC
struct hostent *
_uncached_gethostbyname_r(const char *nam, struct hostent *result,
	char *buffer, int buflen, int *h_errnop)
{
	return (_switch_gethostbyname_r(nam, result,
	buffer, buflen, h_errnop));
}

struct hostent *
_uncached_gethostbyaddr_r(const char *addr, int length, int type,
	struct hostent *result, char *buffer, int buflen, int *h_errnop)
{
	return (_switch_gethostbyaddr_r(addr, length, type,
					result, buffer, buflen, h_errnop));
}

#endif

extern struct hostent *
gethostbyname_r(const char *nam, struct hostent *result, char *buffer,
	int buflen, int *h_errnop);

extern struct hostent *
gethostbyaddr_r(const char *addr, int length, int type,
	struct hostent *result, char *buffer, int buflen, int *h_errnop);

struct hostent *
gethostbyname_r(const char *nam, struct hostent *result, char *buffer,
	int buflen, int *h_errnop)
{
	struct netconfig *nconf;
	struct	nss_netdirbyname_in nssin;
	union	nss_netdirbyname_out nssout;
	int neterr, dummy;

	if (h_errnop == NULL)
		h_errnop = &dummy;

	if (strlen(nam) == 0) {
		*h_errnop = HOST_NOT_FOUND;
		return (NULL);
	}

	if ((nconf = __rpc_getconfip("udp")) == NULL &&
	    (nconf = __rpc_getconfip("tcp")) == NULL) {
		*h_errnop = NO_RECOVERY;
		return (NULL);
	}

	nssin.op_t = NSS_HOST;
	nssin.arg.nss.host.name = nam;
	nssin.arg.nss.host.buf = buffer;
	nssin.arg.nss.host.buflen = buflen;

	nssout.nss.host.hent = result;
	nssout.nss.host.herrno_p = h_errnop;

	/*
	 * We pass in nconf and let the implementation of the long-named func
	 * decide whether to use the switch based on nc_nlookups.
	 */
	neterr = _get_hostserv_inetnetdir_byname(nconf, &nssin, &nssout);

	(void) freenetconfigent(nconf);
	if (neterr != ND_OK)
		return (NULL);
	return (nssout.nss.host.hent);
}

struct hostent *
gethostbyaddr_r(const char *addr, int length, int type,
	struct hostent *result, char *buffer, int buflen, int *h_errnop)
{
	struct netconfig *nconf;
	struct	nss_netdirbyaddr_in nssin;
	union	nss_netdirbyaddr_out nssout;
	int neterr, dummy;

	if (h_errnop == NULL)
		h_errnop = &dummy;

	if (type != AF_INET) {
		*h_errnop = HOST_NOT_FOUND;
		return (NULL);
	}

	if ((nconf = __rpc_getconfip("udp")) == NULL &&
	    (nconf = __rpc_getconfip("tcp")) == NULL) {
		*h_errnop = NO_RECOVERY;
		return (NULL);
	}

	nssin.op_t = NSS_HOST;
	nssin.arg.nss.host.addr = addr;
	nssin.arg.nss.host.len = length;
	nssin.arg.nss.host.type = type;
	nssin.arg.nss.host.buf = buffer;
	nssin.arg.nss.host.buflen = buflen;

	nssout.nss.host.hent = result;
	nssout.nss.host.herrno_p = h_errnop;

	/*
	 * We pass in nconf and let the implementation of this long-named func
	 * decide whether to use the switch based on nc_nlookups.
	 */
	neterr = _get_hostserv_inetnetdir_byaddr(nconf, &nssin, &nssout);

	(void) freenetconfigent(nconf);
	if (neterr != ND_OK)
		return (NULL);
	return (nssout.nss.host.hent);
}
