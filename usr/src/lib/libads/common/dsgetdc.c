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
 * MS-compatible Directory Server Discovery API, DsGetDC...()
 */

#include <stdlib.h>
#include <string.h>
#include <smb/nterror.h>
#include <smb/ntstatus.h>
#include <arpa/inet.h>
#include "dsgetdc.h"
#include "ads_priv.h"
#include <assert.h>

#define	DSGETDC_VALID_FLAGS ( \
	DS_FORCE_REDISCOVERY | \
	DS_DIRECTORY_SERVICE_REQUIRED | \
	DS_DIRECTORY_SERVICE_PREFERRED | \
	DS_GC_SERVER_REQUIRED | \
	DS_PDC_REQUIRED | \
	DS_BACKGROUND_ONLY | \
	DS_IP_REQUIRED | \
	DS_KDC_REQUIRED | \
	DS_TIMESERV_REQUIRED | \
	DS_WRITABLE_REQUIRED | \
	DS_GOOD_TIMESERV_PREFERRED | \
	DS_AVOID_SELF | \
	DS_ONLY_LDAP_NEEDED | \
	DS_IS_FLAT_NAME | \
	DS_IS_DNS_NAME | \
	DS_RETURN_FLAT_NAME | \
	DS_RETURN_DNS_NAME)

static struct timeval TIMEOUT = { 15, 0 };

/*
 * The Windows version of this would return a single allocation,
 * where any strings pointed to in the returned structure would be
 * stored in space following the top-level returned structure.
 * This allows NetApiBufferFree() to be the same as free().
 *
 * However, we don't have an easy way to do that right now, so
 * the dcinfo returned here will be free'd with DsFreeDcInfo().
 */
uint32_t
_DsGetDcName(const char *ComputerName,
    const char *DomainName, const struct uuid *DomainGuid,
    const char *SiteName, uint32_t Flags,
    DOMAIN_CONTROLLER_INFO **dcinfo)
{
	DsGetDcNameArgs args;
	DsGetDcNameRes res;
	CLIENT *clnt = NULL;
	enum clnt_stat clstat;

	*dcinfo = NULL;
	(void) memset(&args, 0, sizeof (args));
	(void) memset(&res, 0, sizeof (res));

	/*
	 * Later check for over constrained optional args here,
	 * and return (ERROR_INVALID_PARAMETER);
	 */

	if (Flags & ~DSGETDC_VALID_FLAGS)
		return (ERROR_INVALID_FLAGS);

	/*
	 * Call the ADS deamon.
	 */
	clnt = clnt_door_create(ADSPRIV_PROGRAM, ADSPRIV_V1, ADSPRIV_MAX_XFER);
	if (clnt == NULL)
		return (RPC_S_NOT_LISTENING);

	args.ComputerName = (char *)ComputerName;
	args.DomainName = (char *)DomainName;
	if (DomainGuid != NULL)
		(void) memcpy(&args.DomainGuid, DomainGuid,
		    sizeof (args.DomainGuid));
	args.SiteName = (char *)SiteName;
	args.Flags = Flags;

	clstat = clnt_call(clnt, ADSPRIV_GetDcName,
	    (xdrproc_t)xdr_DsGetDcNameArgs, (caddr_t)&args,
	    (xdrproc_t)xdr_DsGetDcNameRes, (caddr_t)&res, TIMEOUT);

	clnt_destroy(clnt);
	if (clstat != RPC_SUCCESS)
		return (RPC_S_CALL_FAILED);
	if (res.status != 0)
		return (res.status);

	*dcinfo = malloc(sizeof (**dcinfo));
	if (*dcinfo == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	/*
	 * We have taken pains to make these two the same.
	 * DOMAIN_CONTROLLER_INFO / struct adspriv_dcinfo
	 */
	/* LINTED E_TRUE_LOGICAL_EXPR */
	assert(sizeof (**dcinfo) == sizeof (res.DsGetDcNameRes_u.res0));
	(void) memcpy(*dcinfo, &res.DsGetDcNameRes_u.res0, sizeof (**dcinfo));

	/*
	 * NB: Do NOT xdr_free the result, because we're
	 * returning a copy of it to the caller.
	 */
	return (0);
}

int
DsGetDcName(const char *ComputerName,
    const char *DomainName, const struct uuid *DomainGuid,
    const char *SiteName, uint32_t Flags,
    DOMAIN_CONTROLLER_INFO **dcinfo)
{
	uint32_t status;
	int rc;

	status = _DsGetDcName(ComputerName, DomainName, DomainGuid,
	    SiteName, Flags, dcinfo);

	switch (status) {
	case 0:
		rc = 0;
		break;
	case NT_STATUS_NO_SUCH_DOMAIN:	/* Specified domain unknown */
	case NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND:
	case NT_STATUS_CANT_WAIT:		/* or gave up waiting. */
	case NT_STATUS_INVALID_SERVER_STATE:	/*  not in domain mode. */
		rc = ERROR_NO_SUCH_DOMAIN;
		break;
	default:
		rc = ERROR_INTERNAL_ERROR;
		break;
	}
	return (rc);
}

void
DsFreeDcInfo(DOMAIN_CONTROLLER_INFO *dci)
{
	if (dci != NULL) {
		xdr_free(xdr_DsGetDcNameRes, (char *)dci);
		free(dci);
	}
}
