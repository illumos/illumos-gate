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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <libintl.h>
#include <rpcsvc/mount.h>
#include "clnt_subr.h"

/*
 * Common code to create client of MOUNTPROG protocol.
 * Used by dfmounts, dfshares, showmount.
 */
CLIENT *
mountprog_client_create(const char *host, struct timeval *tv)
{
	rpcvers_t versnum;
	CLIENT *cl;

	/*
	 * First try circuit, then drop back to datagram if
	 * circuit is unavailable (an old version of mountd perhaps)
	 * Using circuit is preferred because it can handle
	 * arbitrarily long export lists.
	 */
	cl = clnt_create_vers(host, MOUNTPROG, &versnum,
	    MOUNTVERS, MOUNTVERS3, "circuit_n");
	if (cl == NULL) {
		if (rpc_createerr.cf_stat == RPC_PROGNOTREGISTERED)
			cl = clnt_create_vers(host, MOUNTPROG, &versnum,
			    MOUNTVERS, MOUNTVERS3, "datagram_n");
		if (cl == NULL) {
			pr_err(gettext("can't contact server: %s\n"),
			    clnt_spcreateerror(host));
			(void) __rpc_control(CLCR_SET_RPCB_TIMEOUT, tv);
		}
	}
	return (cl);
}
