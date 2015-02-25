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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *  Kernel code to obtain client handle to gssd server
 */

#include <sys/types.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssd_prot.h>
#include <gssapi/kgssapi_defs.h>

#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/uio.h>
#include <sys/pathname.h>

#define	GSSD_RETRY 5

kmutex_t	gssrpcb_lock;
zone_key_t	gss_zone_key;

struct gss_globals {
	enum clnt_stat		gss_last_stat;
	struct netbuf		gss_netaddr;
	struct knetconfig	gss_config;
};

/* ARGSUSED */
void *
gss_zone_init(zoneid_t zoneid)
{
	struct gss_globals *gssg;

	gssg = kmem_zalloc(sizeof (*gssg), KM_SLEEP);
	return (gssg);
}

/* ARGSUSED */
void
gss_zone_fini(zoneid_t zoneid, void *data)
{
	struct gss_globals *gssg = data;
	struct netbuf *netaddrp = &gssg->gss_netaddr;

	if (netaddrp->len != 0)
		kmem_free(netaddrp->buf, netaddrp->maxlen);
	kmem_free(gssg, sizeof (*gssg));
}

void
killgssd_handle(CLIENT *client)
{
	struct rpc_err rpcerr;
	struct gss_globals *gssg;

	gssg = zone_getspecific(gss_zone_key, curproc->p_zone);
	CLNT_GETERR(client, &rpcerr);
	gssg->gss_last_stat = rpcerr.re_status;

	AUTH_DESTROY(client->cl_auth);
	CLNT_DESTROY(client);
}

CLIENT *
getgssd_handle(void)
{
	struct vnode *vp;
	int error;
	CLIENT *clnt;
	enum clnt_stat stat;
	struct netbuf tmpaddr;
	struct gss_globals *gssg;
	struct netbuf *netaddrp;

	gssg = zone_getspecific(gss_zone_key, curproc->p_zone);
	/*
	 * Cribbed from kerb_krpc.c. Really should do the config set up
	 * in the _init routine.
	 */
	if (gssg->gss_config.knc_rdev == 0) {
		if ((error = lookupname("/dev/ticotsord", UIO_SYSSPACE,
		    FOLLOW, NULLVPP, &vp)) != 0) {
			GSSLOG(1, "getgssd_handle: lookupname: %d\n", error);
			return (NULL);
		}
		gssg->gss_config.knc_rdev = vp->v_rdev;
		gssg->gss_config.knc_protofmly = loopback_name;
		VN_RELE(vp);
		gssg->gss_config.knc_semantics = NC_TPI_COTS_ORD;
	}

	/*
	 * Contact rpcbind to get gssd's address only
	 * once and re-use the address.
	 */
	mutex_enter(&gssrpcb_lock);
	netaddrp = &gssg->gss_netaddr;

	if (netaddrp->len == 0 || gssg->gss_last_stat != RPC_SUCCESS) {
		if (netaddrp->buf != NULL)
			kmem_free(netaddrp->buf, netaddrp->maxlen);

		/* Set up netaddr to be "localhost." (strlen is 10) */
		netaddrp->len = netaddrp->maxlen = 10;
		netaddrp->buf = kmem_alloc(netaddrp->len, KM_SLEEP);
		(void) strncpy(netaddrp->buf, "localhost.", netaddrp->len);

		/* Get address of gssd from rpcbind */
		stat = rpcbind_getaddr(&gssg->gss_config, GSSPROG, GSSVERS,
		    netaddrp);
		if (stat != RPC_SUCCESS) {
			kmem_free(netaddrp->buf, netaddrp->maxlen);
			netaddrp->buf = NULL;
			netaddrp->len = netaddrp->maxlen = 0;
			mutex_exit(&gssrpcb_lock);
			return (NULL);
		}
	}

	/*
	 * Copy the netaddr information into a tmp location to
	 * be used by clnt_tli_kcreate.  The purpose of this
	 * is for MT race condition (ie. netaddr being modified
	 * while it is being used.)
	 */
	tmpaddr.buf = kmem_zalloc(netaddrp->maxlen, KM_SLEEP);
	bcopy(netaddrp->buf, tmpaddr.buf, netaddrp->maxlen);
	tmpaddr.maxlen = netaddrp->maxlen;
	tmpaddr.len = netaddrp->len;

	mutex_exit(&gssrpcb_lock);

	error = clnt_tli_kcreate(&gssg->gss_config, &tmpaddr, GSSPROG,
	    GSSVERS, 0, GSSD_RETRY, kcred, &clnt);

	kmem_free(tmpaddr.buf, tmpaddr.maxlen);

	if (error != 0) {
		GSSLOG(1,
		"getgssd_handle: clnt_tli_kcreate: error %d\n", error);
		return (NULL);
	}

	return (clnt);
}
