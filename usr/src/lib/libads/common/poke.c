/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Private API to force DC Rediscovery.
 */

#include <stdlib.h>
#include <string.h>
#include <smb/nterror.h>
#include <arpa/inet.h>
#include "dsgetdc.h"
#include "ads_priv.h"
#include <assert.h>

static struct timeval TIMEOUT = { 15, 0 };

int
_DsForceRediscovery(char *domain, int flags)
{
	DsForceRediscoveryArgs args;
	CLIENT *clnt = NULL;
	enum clnt_stat clstat;
	int res;

	(void) memset(&args, 0, sizeof (args));
	args.Flags = flags;
	args.DomainName = domain;

	/*
	 * Call the ADS deamon.
	 */
	clnt = clnt_door_create(ADSPRIV_PROGRAM, ADSPRIV_V1, ADSPRIV_MAX_XFER);
	if (clnt == NULL)
		return (RPC_S_NOT_LISTENING);

	clstat = clnt_call(clnt, ADSPRIV_ForceRediscovery,
	    (xdrproc_t)xdr_DsForceRediscoveryArgs, (caddr_t)&args,
	    (xdrproc_t)xdr_int, (caddr_t)&res, TIMEOUT);

	clnt_destroy(clnt);
	if (clstat != RPC_SUCCESS)
		return (RPC_S_CALL_FAILED);

	return (res);
}
