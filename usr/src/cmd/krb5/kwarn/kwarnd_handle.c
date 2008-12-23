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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	from kerbd_handle.c	1.3	92/01/29 SMI */

/*
 * kwarnd_handle.c, Interface to kwarnd
 *
 */

#include <unistd.h>
#include <rpc/rpc.h>
#include <rpc/clnt.h>
#include <stdio.h>
#include <string.h>
#include <netconfig.h>
#include <sys/utsname.h>
#include "kwarnd.h"

#ifdef DEBUG
#define	dprt(msg)
#else
#define	dprt(msg)
#endif /* DEBUG */

CLIENT *kwarn_clnt;

/*
 * Keep the handle cached.  This call may be made quite often.
 */

CLIENT *
getkwarnd_handle(void)
{
	void *localhandle;
	struct netconfig *nconf;
	struct netconfig *tpconf;
	struct timeval wait_time;
	struct utsname u;
	static char *hostname;
	static bool_t first_time = TRUE;

/*
 * Total timeout (in seconds) talking to kwarnd.
 */
#define	TOTAL_TIMEOUT	5

	if (kwarn_clnt)
		return (kwarn_clnt);
	if (!(localhandle = setnetconfig()))
		return (NULL);
	tpconf = NULL;
	if (first_time == TRUE) {
		if (uname(&u) == -1) {
			(void) endnetconfig(localhandle);
			return ((CLIENT *)NULL);
		}
		if ((hostname = strdup(u.nodename)) == (char *)NULL) {
			(void) endnetconfig(localhandle);
			return ((CLIENT *)NULL);
		}
		first_time = FALSE;
	}
	while (nconf = getnetconfig(localhandle)) {
		if (strcmp(nconf->nc_protofmly, NC_LOOPBACK) == 0) {
			if (nconf->nc_semantics == NC_TPI_COTS_ORD) {
				kwarn_clnt = clnt_tp_create(hostname,
				    KWARNPROG, KWARNVERS, nconf);
				if (kwarn_clnt) {
					dprt("got COTS_ORD\n");
					break;
				}
			} else {
				tpconf = nconf;
			}
		}
	}
	if ((kwarn_clnt == NULL) && (tpconf)) {

		/* Now, try the connection-oriented loopback transport */

		kwarn_clnt = clnt_tp_create(hostname, KWARNPROG, KWARNVERS,
		    tpconf);
#ifdef DEBUG
		if (kwarn_clnt) {
			dprt("got COTS\n");
		}
#endif	/* DEBUG */
	}
	(void) endnetconfig(localhandle);

	/*
	 * This bit of code uses an as yet unimplemented argument to
	 * clnt_control(). CLSET_SVC_PRIV specifies that the underlying
	 * loopback transport should be checked to ensure it is
	 * connected to a process running as root. If so, the clnt_control()
	 * call returns TRUE. If not, it returns FALSE.
	 */

#ifdef CLSET_SVC_PRIV

	if (clnt_control(kwarn_clnt, CLSET_SVC_PRIV, NULL) != TRUE) {
		clnt_destroy(kwarn_clnt);
		kwarn_clnt = NULL;
		return (NULL);
	{
#endif
	if (kwarn_clnt == NULL)
		return (NULL);

	kwarn_clnt->cl_auth = authsys_create("", getuid(), 0, 0, NULL);
	if (kwarn_clnt->cl_auth == NULL) {
		clnt_destroy(kwarn_clnt);
		kwarn_clnt = NULL;
		return (NULL);
	}
	wait_time.tv_sec = TOTAL_TIMEOUT;
	wait_time.tv_usec = 0;
	(void) clnt_control(kwarn_clnt, CLSET_TIMEOUT, (char *)&wait_time);

	return (kwarn_clnt);
}

void
resetkwarnd_handle(void)
{
	auth_destroy(kwarn_clnt->cl_auth);
	clnt_destroy(kwarn_clnt);
	kwarn_clnt = NULL;
}
