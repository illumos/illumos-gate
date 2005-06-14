/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
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


/*
 * Keep the handle cached.  This call may be made quite often.
 */

CLIENT *
getkwarnd_handle(void)
{
	void *localhandle;
	struct netconfig *nconf;
	struct netconfig *tpconf;
	static CLIENT *clnt;
	struct timeval wait_time;
	struct utsname u;
	static char *hostname;
	static bool_t first_time = TRUE;

#define	TOTAL_TIMEOUT	1000	/* total timeout talking to kwarnd */
#define	TOTAL_TRIES	1	/* Number of tries */

	if (clnt)
		return (clnt);
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
				clnt = clnt_tp_create(hostname,
					KWARNPROG, KWARNVERS, nconf);
				if (clnt) {
					dprt("got COTS_ORD\n");
					break;
				}
			} else {
				tpconf = nconf;
			}
		}
	}
	if ((clnt == NULL) && (tpconf)) {

		/* Now, try the connection-oriented loopback transport */

		clnt = clnt_tp_create(hostname, KWARNPROG, KWARNVERS, tpconf);
#ifdef DEBUG
		if (clnt) {
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

	if (clnt_control(clnt, CLSET_SVC_PRIV, NULL) != TRUE) {
		clnt_destroy(clnt);
		clnt = NULL;
		return (NULL);
	{
#endif
	if (clnt == NULL)
		return (NULL);

	clnt->cl_auth = authsys_create("", getuid(), 0, 0, NULL);
	if (clnt->cl_auth == NULL) {
		clnt_destroy(clnt);
		clnt = NULL;
		return (NULL);
	}
	wait_time.tv_sec = TOTAL_TIMEOUT/TOTAL_TRIES;
	wait_time.tv_usec = 0;
	(void) clnt_control(clnt, CLSET_RETRY_TIMEOUT, (char *)&wait_time);

	return (clnt);
}
