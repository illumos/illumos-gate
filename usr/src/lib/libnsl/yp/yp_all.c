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

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/*	  All Rights Reserved   */

/*
 * Portions of this source code were derived from Berkeley
 * under license from the Regents of the University of
 * California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mt.h"
#include <stdlib.h>
#include <unistd.h>
#include <rpc/rpc.h>
#include <syslog.h>
#include "yp_b.h"
#include <rpcsvc/yp_prot.h>
#include <rpcsvc/ypclnt.h>
#include <netdir.h>
#include <string.h>

extern int __yp_dobind_cflookup(char *, struct dom_binding **, int);

static struct timeval tp_timout = { 120, 0};
static char nullstring[] = "\000";

/*
 * __yp_all_cflookup() is a variant of the yp_all() code,
 * which adds a 'hardlookup' parameter. This parameter is passed
 * to __yp_dobind_cflookup(), and determines whether the server
 * binding attempt is hard (try forever) of soft (retry a compiled-
 * in number of times).
 */
int
__yp_all_cflookup(char *domain, char *map, struct ypall_callback *callback,
								int hardlookup)
{
	size_t domlen;
	size_t maplen;
	struct ypreq_nokey req;
	int reason;
	struct dom_binding *pdomb;
	enum clnt_stat s;
	CLIENT *allc;
	char server_name[MAXHOSTNAMELEN];
	char errbuf[BUFSIZ];

	if ((map == NULL) || (domain == NULL))
		return (YPERR_BADARGS);

	domlen = strlen(domain);
	maplen = strlen(map);

	if ((domlen == 0) || (domlen > YPMAXDOMAIN) ||
	    (maplen == 0) || (maplen > YPMAXMAP) ||
	    (callback == NULL))
		return (YPERR_BADARGS);

	if (reason = __yp_dobind_cflookup(domain, &pdomb, hardlookup))
		return (reason);

	if (pdomb->dom_binding->ypbind_hi_vers < YPVERS) {
		__yp_rel_binding(pdomb);
		return (YPERR_VERS);
	}
	(void) mutex_lock(&pdomb->server_name_lock);
	if (!pdomb->dom_binding->ypbind_servername) {
		(void) mutex_unlock(&pdomb->server_name_lock);
		__yp_rel_binding(pdomb);
		syslog(LOG_ERR, "yp_all: failed to get server's name\n");
		return (YPERR_RPC);
	}
	(void) strcpy(server_name, pdomb->dom_binding->ypbind_servername);
	(void) mutex_unlock(&pdomb->server_name_lock);
	if (strcmp(server_name, nullstring) == 0) {
		/*
		 * This is the case where ypbind is running in broadcast mode,
		 * we have to do the jugglery to get the
		 * ypserv's address on COTS transport based
		 * on the CLTS address ypbind gave us !
		 */

		struct nd_hostservlist *nhs;

		if (netdir_getbyaddr(pdomb->dom_binding->ypbind_nconf,
			&nhs, pdomb->dom_binding->ypbind_svcaddr) != ND_OK) {
			syslog(LOG_ERR,
				"yp_all: failed to get server's name\n");
			__yp_rel_binding(pdomb);
			return (YPERR_RPC);
		}
		/* check server name again, some other thread may have set it */
		(void) mutex_lock(&pdomb->server_name_lock);
		if (strcmp(pdomb->dom_binding->ypbind_servername,
					nullstring) == 0) {
			pdomb->dom_binding->ypbind_servername =
				(char *)strdup(nhs->h_hostservs->h_host);
		}
		(void) strcpy(server_name,
		    pdomb->dom_binding->ypbind_servername);
		(void) mutex_unlock(&pdomb->server_name_lock);
		netdir_free((char *)nhs, ND_HOSTSERVLIST);
	}
	__yp_rel_binding(pdomb);
	if ((allc = clnt_create(server_name, YPPROG,
		YPVERS, "circuit_n")) == NULL) {
			(void) snprintf(errbuf, BUFSIZ, "yp_all \
- transport level create failure for domain %s / map %s", domain, map);
			syslog(LOG_ERR, "%s", clnt_spcreateerror(errbuf));
			return (YPERR_RPC);
	}

	req.domain = domain;
	req.map = map;


	s = clnt_call(allc, YPPROC_ALL,
		(xdrproc_t)xdr_ypreq_nokey, (char *)&req,
	    (xdrproc_t)xdr_ypall, (char *)callback, tp_timout);

	if (s != RPC_SUCCESS && s != RPC_TIMEDOUT) {
		syslog(LOG_ERR, "%s", clnt_sperror(allc,
		    "yp_all - RPC clnt_call (transport level) failure"));
	}

	clnt_destroy(allc);
	switch (s) {
	case RPC_SUCCESS:
		return (0);
	case RPC_TIMEDOUT:
		return (YPERR_YPSERV);
	default:
		return (YPERR_RPC);
	}
}


/*
 * This does the "glommed enumeration" stuff.  callback->foreach is the name
 * of a function which gets called per decoded key-value pair:
 *
 * (*callback->foreach)(status, key, keylen, val, vallen, callback->data);
 *
 * If the server we get back from __yp_dobind speaks the old protocol, this
 * returns YPERR_VERS, and does not attempt to emulate the new functionality
 * by using the old protocol.
 */
int
yp_all(char *domain, char *map, struct ypall_callback *callback)
{
	return (__yp_all_cflookup(domain, map, callback, 1));
}


/*
 * This function is identical to 'yp_all' with the exception that it
 * attempts to use reserve ports.
 */
int
__yp_all_rsvdport(char *domain, char *map, struct ypall_callback *callback)
{
	size_t domlen;
	size_t maplen;
	struct ypreq_nokey req;
	int reason;
	struct dom_binding *pdomb;
	enum clnt_stat s;
	CLIENT *allc;
	char server_name[MAXHOSTNAMELEN];
	char errbuf[BUFSIZ];

	if ((map == NULL) || (domain == NULL))
		return (YPERR_BADARGS);

	domlen =  strlen(domain);
	maplen =  strlen(map);

	if ((domlen == 0) || (domlen > YPMAXDOMAIN) ||
	    (maplen == 0) || (maplen > YPMAXMAP) ||
	    (callback == NULL))
		return (YPERR_BADARGS);

	if (reason = __yp_dobind_rsvdport(domain, &pdomb))
		return (reason);

	if (pdomb->dom_binding->ypbind_hi_vers < YPVERS) {
		/*
		 * Have to free the binding since the reserved
		 * port bindings are not cached.
		 */
		__yp_rel_binding(pdomb);
		free_dom_binding(pdomb);
		return (YPERR_VERS);
	}
	(void) mutex_lock(&pdomb->server_name_lock);
	if (!pdomb->dom_binding->ypbind_servername) {
		(void) mutex_unlock(&pdomb->server_name_lock);
		syslog(LOG_ERR, "yp_all: failed to get server's name\n");
		__yp_rel_binding(pdomb);
		free_dom_binding(pdomb);
		return (YPERR_RPC);
	}
	(void) strcpy(server_name, pdomb->dom_binding->ypbind_servername);
	(void) mutex_unlock(&pdomb->server_name_lock);
	if (strcmp(server_name, nullstring) == 0) {
		/*
		 * This is the case where ypbind is running in broadcast mode,
		 * we have to do the jugglery to get the
		 * ypserv's address on COTS transport based
		 * on the CLTS address ypbind gave us !
		 */

		struct nd_hostservlist *nhs;

		if (netdir_getbyaddr(pdomb->dom_binding->ypbind_nconf,
			&nhs, pdomb->dom_binding->ypbind_svcaddr) != ND_OK) {
			syslog(LOG_ERR,
				"yp_all: failed to get server's name\n");
			__yp_rel_binding(pdomb);
			free_dom_binding(pdomb);
			return (YPERR_RPC);
		}
		/* check server name again, some other thread may have set it */
		(void) mutex_lock(&pdomb->server_name_lock);
		if (strcmp(pdomb->dom_binding->ypbind_servername,
					nullstring) == 0) {
			pdomb->dom_binding->ypbind_servername =
			(char *)strdup(nhs->h_hostservs->h_host);
		}
		(void) strcpy(server_name,
		    pdomb->dom_binding->ypbind_servername);
		(void) mutex_unlock(&pdomb->server_name_lock);
		netdir_free((char *)nhs, ND_HOSTSERVLIST);

	}
	__yp_rel_binding(pdomb);
	if ((allc = __yp_clnt_create_rsvdport(server_name, YPPROG, YPVERS,
	    "tcp6", 0, 0)) == NULL &&
		(allc = __yp_clnt_create_rsvdport(server_name, YPPROG, YPVERS,
	    "tcp", 0, 0)) == NULL) {
		(void) snprintf(errbuf, BUFSIZ, "yp_all \
- transport level create failure for domain %s / map %s", domain, map);
		syslog(LOG_ERR, "%s", clnt_spcreateerror(errbuf));
		free_dom_binding(pdomb);
		return (YPERR_RPC);
	}

	req.domain = domain;
	req.map = map;

	s = clnt_call(allc, YPPROC_ALL,
		(xdrproc_t)xdr_ypreq_nokey, (char *)&req,
	    (xdrproc_t)xdr_ypall, (char *)callback, tp_timout);

	if (s != RPC_SUCCESS && s != RPC_TIMEDOUT) {
		syslog(LOG_ERR, "%s", clnt_sperror(allc,
		    "yp_all - RPC clnt_call (transport level) failure"));
	}

	clnt_destroy(allc);
	free_dom_binding(pdomb);
	switch (s) {
	case RPC_SUCCESS:
		return (0);
	case RPC_TIMEDOUT:
		return (YPERR_YPSERV);
	default:
		return (YPERR_RPC);
	}
}
