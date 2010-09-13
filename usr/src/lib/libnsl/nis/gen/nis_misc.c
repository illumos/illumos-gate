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
 * nis_misc.c
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * nis_misc.c
 *
 * This module contains miscellaneous library functions.
 */

#include "mt.h"
#include <string.h>
#include <syslog.h>
#include <malloc.h>
#include <rpc/rpc.h>
#include <rpcsvc/nis.h>
#include <tiuser.h>
#include <netdir.h>
#include <netinet/in.h>
#include <strings.h>
#include "nis_clnt.h"

/*
 * In the pre-IPv6 code, secure RPC has a bug such that it doesn't look
 * at the endpoint 'family' field when selecting an endpoint to use for
 * time synchronization. In order to protect that broken code from itself,
 * we set the endpoint 'proto' to 'nc_netid' (i.e., "udp6" or "tcp6")
 * rather than 'nc_proto' ("udp"/"tcp") if 'nc_family' is "inet6".
 *
 * The __nis_netconfig2ep() and __nis_netconfig_matches_ep() service
 * functions below simplify endpoint manipulation by implementing the
 * rules above.
 */

void
__nis_netconfig2ep(struct netconfig *nc, endpoint *ep) {

	if (nc == 0 || ep == 0)
		return;

	ep->family = strdup(nc->nc_protofmly);

	if (strcmp(ep->family, "inet6") == 0) {
		ep->proto = strdup(nc->nc_netid);
	} else {
		ep->proto = strdup(nc->nc_proto);
	}
}

bool_t
__nis_netconfig_matches_ep(struct netconfig *nc, endpoint *ep) {

	if (nc == 0 || ep == 0)
		return (FALSE);

	if (strcmp(nc->nc_protofmly, ep->family) != 0)
		return (FALSE);

	if (strcmp(ep->family, "inet6") == 0)
		return (strcmp(nc->nc_netid, ep->proto) == 0 ||
			strcmp(nc->nc_proto, ep->proto) == 0);
	else
		return (strcmp(nc->nc_proto, ep->proto) == 0);

}
