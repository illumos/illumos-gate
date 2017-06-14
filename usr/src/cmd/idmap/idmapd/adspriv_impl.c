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


#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include <rpc/rpc.h>
#include <sys/uuid.h>
#include <smb/ntstatus.h>
#include <synch.h>
#include <thread.h>
#include <arpa/inet.h>
#include <uuid/uuid.h>

#include "idmapd.h"
#include "libadutils.h"
#include "dsgetdc.h"
#include "ads_priv.h"

void adspriv_program_1(struct svc_req *, register SVCXPRT *);

SVCXPRT *dcl_xprt = NULL;

void
init_dc_locator(void)
{
	int	connmaxrec = 32 * 1024;

	dcl_xprt = svc_door_create(adspriv_program_1,
	    ADSPRIV_PROGRAM, ADSPRIV_V1, connmaxrec);
	if (dcl_xprt == NULL) {
		syslog(LOG_ERR, "unable to create door RPC service");
		return;
	}

	if (!svc_control(dcl_xprt, SVCSET_CONNMAXREC, &connmaxrec)) {
		syslog(LOG_ERR, "unable to limit RPC request size");
	}
}

void
fini_dc_locator(void)
{
	if (dcl_xprt != NULL)
		svc_destroy(dcl_xprt);
}

/*
 * Functions called by the (generated) adspriv_srv.c
 */

/* ARGSUSED */
bool_t
adspriv_null_1_svc(void *result, struct svc_req *rqstp)
{
	return (TRUE);
}

/* ARGSUSED */
bool_t
adspriv_forcerediscovery_1_svc(
	DsForceRediscoveryArgs args,
	int *res,
	struct svc_req *sreq)
{
	/* Ignoring args for now. */

	idmap_cfg_force_rediscovery();
	*res = 0;

	return (TRUE);
}


/* ARGSUSED */
bool_t
adspriv_getdcname_1_svc(
	DsGetDcNameArgs args,
	DsGetDcNameRes *res,
	struct svc_req *sreq)
{
	uuid_t uuid;
	adspriv_dcinfo *dci;
	idmap_pg_config_t *pgcfg;
	ad_disc_ds_t *ds;
	char *s;

	/* Init */
	(void) memset(res, 0, sizeof (*res));
	res->status = 0;
	dci = &res->DsGetDcNameRes_u.res0;

	if (args.Flags & DS_FORCE_REDISCOVERY)
		idmap_cfg_force_rediscovery();

	/*
	 * We normally should wait if discovery is running.
	 * Sort of mis-using the background flag as a way to
	 * skip the wait, until we really do background disc.
	 */
	if ((args.Flags & DS_BACKGROUND_ONLY) == 0) {
		timespec_t tv = { 15, 0 };
		int rc = 0;
		int waited = 0;

		(void) mutex_lock(&_idmapdstate.addisc_lk);

		if (_idmapdstate.addisc_st != 0)
			idmapdlog(LOG_DEBUG, "getdcname wait begin");

		while (_idmapdstate.addisc_st != 0) {
			waited++;
			rc = cond_reltimedwait(&_idmapdstate.addisc_cv,
			    &_idmapdstate.addisc_lk, &tv);
			if (rc == ETIME)
				break;
		}
		(void) mutex_unlock(&_idmapdstate.addisc_lk);

		if (rc == ETIME) {
			/* Caller will replace this with DC not found. */
			idmapdlog(LOG_ERR, "getdcname timeout");
			res->status = NT_STATUS_CANT_WAIT;
			return (TRUE);
		}
		if (waited) {
			idmapdlog(LOG_DEBUG, "getdcname wait done");
		}
	}

	RDLOCK_CONFIG();
	pgcfg = &_idmapdstate.cfg->pgcfg;

	if (pgcfg->domain_name == NULL) {
		res->status = NT_STATUS_INVALID_SERVER_STATE;
		goto out;
	}

	if (args.DomainName != NULL && args.DomainName[0] != '\0' &&
	    0 != strcasecmp(args.DomainName, pgcfg->domain_name)) {
		/*
		 * They asked for a specific domain not our primary,
		 * which is not supported (and not needed).
		 */
		res->status = NT_STATUS_NO_SUCH_DOMAIN;
		goto out;
	}

	if ((ds = pgcfg->domain_controller) == NULL) {
		res->status = NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
		goto out;
	}

	dci->dci_DcName = strdup(ds->host);

	dci->dci_DcAddr = calloc(1, INET6_ADDRSTRLEN);
	if (dci->dci_DcAddr != NULL &&
	    ad_disc_getnameinfo(dci->dci_DcAddr, INET6_ADDRSTRLEN,
	    &ds->addr) == 0)
		dci->dci_AddrType = DS_INET_ADDRESS;

	if ((s = pgcfg->domain_guid) != NULL &&
	    0 == uuid_parse(s, uuid)) {
		(void) memcpy(dci->dci_guid, uuid, sizeof (uuid));
	}

	if ((s = pgcfg->domain_name) != NULL)
		dci->dci_DomainName = strdup(s);

	if ((s = pgcfg->forest_name) != NULL)
		dci->dci_DnsForestName = strdup(s);

	dci->dci_Flags = ds->flags;
	dci->dci_DcSiteName = strdup(ds->site);

	if ((s = pgcfg->site_name) != NULL)
		dci->dci_ClientSiteName = strdup(s);

	/* Address in binary form too. */
	(void) memcpy(&dci->dci_sockaddr,
	    &ds->addr, ADSPRIV_SOCKADDR_LEN);

out:
	UNLOCK_CONFIG();

	return (TRUE);
}

/* ARGSUSED */
int
adspriv_program_1_freeresult(SVCXPRT *xprt, xdrproc_t fun, caddr_t res)
{
	xdr_free(fun, res);
	return (TRUE);
}
