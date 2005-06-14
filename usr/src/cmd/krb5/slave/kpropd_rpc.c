/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <iprop_hdr.h>
#include "iprop.h"
#include <stdio.h>
#include <stdlib.h>

/*
 * Default timeout can be changed using clnt_control()
 */
static struct timeval TIMEOUT = { 25, 0 };

kdb_incr_result_t *
iprop_get_updates_1(argp, clnt)
	kdb_last_t *argp;
	CLIENT *clnt;
{
	static kdb_incr_result_t clnt_res;

	memset((char *)&clnt_res, 0, sizeof (clnt_res));
	if (clnt_call(clnt, IPROP_GET_UPDATES,
		(xdrproc_t)xdr_kdb_last_t, (caddr_t)argp,
		(xdrproc_t)xdr_kdb_incr_result_t, (caddr_t)&clnt_res,
		TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&clnt_res);
}

kdb_fullresync_result_t *
iprop_full_resync_1(argp, clnt)
	void *argp;
	CLIENT *clnt;
{
	static kdb_fullresync_result_t clnt_res;

	memset((char *)&clnt_res, 0, sizeof (clnt_res));
	if (clnt_call(clnt, IPROP_FULL_RESYNC,
		(xdrproc_t)xdr_void, (caddr_t)argp,
		(xdrproc_t)xdr_kdb_fullresync_result_t, (caddr_t)&clnt_res,
		TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&clnt_res);
}
