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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Server side of RPC over RDMA in the kernel.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/sysmacros.h>
#include <sys/proc.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/kstat.h>
#include <sys/vtrace.h>
#include <sys/debug.h>

#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>
#include <rpc/rpc_msg.h>
#include <rpc/svc.h>
#include <rpc/rpc_rdma.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip6.h>

/*
 * RDMA transport specific data associated with SVCMASTERXPRT
 */
struct rdma_data {
	SVCMASTERXPRT 	*rd_xprt;	/* back ptr to SVCMASTERXPRT */
	struct rdma_svc_data rd_data;	/* rdma data */
	rdma_mod_t	*r_mod;		/* RDMA module containing ops ptr */
};

/*
 * Plugin connection specific data stashed away in clone SVCXPRT
 */
struct clone_rdma_data {
	CONN		*conn;		/* RDMA connection */
	rdma_buf_t	rpcbuf;		/* RPC req/resp buffer */
};

#ifdef DEBUG
int rdma_svc_debug = 0;
#endif

#define	MAXADDRLEN	128	/* max length for address mask */

/*
 * Routines exported through ops vector.
 */
static bool_t		svc_rdma_krecv(SVCXPRT *, mblk_t *, struct rpc_msg *);
static bool_t		svc_rdma_ksend(SVCXPRT *, struct rpc_msg *);
static bool_t		svc_rdma_kgetargs(SVCXPRT *, xdrproc_t, caddr_t);
static bool_t		svc_rdma_kfreeargs(SVCXPRT *, xdrproc_t, caddr_t);
void			svc_rdma_kdestroy(SVCMASTERXPRT *);
static int		svc_rdma_kdup(struct svc_req *, caddr_t, int,
				struct dupreq **, bool_t *);
static void		svc_rdma_kdupdone(struct dupreq *, caddr_t,
				void (*)(), int, int);
static int32_t		*svc_rdma_kgetres(SVCXPRT *, int);
static void		svc_rdma_kfreeres(SVCXPRT *);
static void		svc_rdma_kclone_destroy(SVCXPRT *);
static void		svc_rdma_kstart(SVCMASTERXPRT *);
void			svc_rdma_kstop(SVCMASTERXPRT *);

/*
 * Server transport operations vector.
 */
struct svc_ops rdma_svc_ops = {
	svc_rdma_krecv,		/* Get requests */
	svc_rdma_kgetargs,	/* Deserialize arguments */
	svc_rdma_ksend,		/* Send reply */
	svc_rdma_kfreeargs,	/* Free argument data space */
	svc_rdma_kdestroy,	/* Destroy transport handle */
	svc_rdma_kdup,		/* Check entry in dup req cache */
	svc_rdma_kdupdone,	/* Mark entry in dup req cache as done */
	svc_rdma_kgetres,	/* Get pointer to response buffer */
	svc_rdma_kfreeres,	/* Destroy pre-serialized response header */
	svc_rdma_kclone_destroy,	/* Destroy a clone xprt */
	svc_rdma_kstart		/* Tell `ready-to-receive' to rpcmod */
};

/*
 * Server statistics
 * NOTE: This structure type is duplicated in the NFS fast path.
 */
struct {
	kstat_named_t	rscalls;
	kstat_named_t	rsbadcalls;
	kstat_named_t	rsnullrecv;
	kstat_named_t	rsbadlen;
	kstat_named_t	rsxdrcall;
	kstat_named_t	rsdupchecks;
	kstat_named_t	rsdupreqs;
	kstat_named_t	rslongrpcs;
} rdmarsstat = {
	{ "calls",	KSTAT_DATA_UINT64 },
	{ "badcalls",	KSTAT_DATA_UINT64 },
	{ "nullrecv",	KSTAT_DATA_UINT64 },
	{ "badlen",	KSTAT_DATA_UINT64 },
	{ "xdrcall",	KSTAT_DATA_UINT64 },
	{ "dupchecks",	KSTAT_DATA_UINT64 },
	{ "dupreqs",	KSTAT_DATA_UINT64 },
	{ "longrpcs",	KSTAT_DATA_UINT64 }
};

kstat_named_t *rdmarsstat_ptr = (kstat_named_t *)&rdmarsstat;
uint_t rdmarsstat_ndata = sizeof (rdmarsstat) / sizeof (kstat_named_t);

#define	RSSTAT_INCR(x)	rdmarsstat.x.value.ui64++

/*
 * Create a transport record.
 * The transport record, output buffer, and private data structure
 * are allocated.  The output buffer is serialized into using xdrmem.
 * There is one transport record per user process which implements a
 * set of services.
 */
/* ARGSUSED */
int
svc_rdma_kcreate(char *netid, SVC_CALLOUT_TABLE *sct, int id,
	rdma_xprt_group_t *started_xprts)
{
	int error;
	SVCMASTERXPRT *xprt;
	struct rdma_data *rd;
	rdma_registry_t *rmod;
	rdma_xprt_record_t *xprt_rec;
	queue_t	*q;

	/*
	 * modload the RDMA plugins is not already done.
	 */
	if (!rdma_modloaded) {
		mutex_enter(&rdma_modload_lock);
		if (!rdma_modloaded) {
			error = rdma_modload();
		}
		mutex_exit(&rdma_modload_lock);

		if (error)
			return (error);
	}

	/*
	 * master_xprt_count is the count of master transport handles
	 * that were successfully created and are ready to recieve for
	 * RDMA based access.
	 */
	error = 0;
	xprt_rec = NULL;
	rw_enter(&rdma_lock, RW_READER);
	if (rdma_mod_head == NULL) {
		started_xprts->rtg_count = 0;
		rw_exit(&rdma_lock);
		if (rdma_dev_available)
			return (EPROTONOSUPPORT);
		else
			return (ENODEV);
	}

	/*
	 * If we have reached here, then atleast one RDMA plugin has loaded.
	 * Create a master_xprt, make it start listenining on the device,
	 * if an error is generated, record it, we might need to shut
	 * the master_xprt.
	 * SVC_START() calls svc_rdma_kstart which calls plugin binding
	 * routines.
	 */
	for (rmod = rdma_mod_head; rmod != NULL; rmod = rmod->r_next) {

		/*
		 * One SVCMASTERXPRT per RDMA plugin.
		 */
		xprt = kmem_zalloc(sizeof (*xprt), KM_SLEEP);
		xprt->xp_ops = &rdma_svc_ops;
		xprt->xp_sct = sct;
		xprt->xp_type = T_RDMA;
		mutex_init(&xprt->xp_req_lock, NULL, MUTEX_DEFAULT, NULL);
		mutex_init(&xprt->xp_thread_lock, NULL, MUTEX_DEFAULT, NULL);
		xprt->xp_req_head = (mblk_t *)0;
		xprt->xp_req_tail = (mblk_t *)0;
		xprt->xp_threads = 0;
		xprt->xp_detached_threads = 0;

		rd = kmem_zalloc(sizeof (*rd), KM_SLEEP);
		xprt->xp_p2 = (caddr_t)rd;
		rd->rd_xprt = xprt;
		rd->r_mod = rmod->r_mod;

		q = &rd->rd_data.q;
		xprt->xp_wq = q;
		q->q_ptr = &rd->rd_xprt;
		xprt->xp_netid = NULL;

		if (netid != NULL) {
			xprt->xp_netid = kmem_alloc(strlen(netid) + 1,
						KM_SLEEP);
			(void) strcpy(xprt->xp_netid, netid);
		}

		xprt->xp_addrmask.maxlen =
		    xprt->xp_addrmask.len = sizeof (struct sockaddr_in);
		xprt->xp_addrmask.buf =
		    kmem_zalloc(xprt->xp_addrmask.len, KM_SLEEP);
		((struct sockaddr_in *)xprt->xp_addrmask.buf)->sin_addr.s_addr =
		    (uint32_t)~0;
		((struct sockaddr_in *)xprt->xp_addrmask.buf)->sin_family =
		    (ushort_t)~0;

		/*
		 * Each of the plugins will have their own Service ID
		 * to listener specific mapping, like port number for VI
		 * and service name for IB.
		 */
		rd->rd_data.svcid = id;
		error = svc_xprt_register(xprt, id);
		if (error) {
			cmn_err(CE_WARN, "svc_rdma_kcreate: svc_xprt_register"
				"failed");
			goto cleanup;
		}

		SVC_START(xprt);
		if (!rd->rd_data.active) {
			svc_xprt_unregister(xprt);
			error = rd->rd_data.err_code;
			goto cleanup;
		}

		/*
		 * This is set only when there is atleast one or more
		 * transports successfully created. We insert the pointer
		 * to the created RDMA master xprt into a separately maintained
		 * list. This way we can easily reference it later to cleanup,
		 * when NFS kRPC service pool is going away/unregistered.
		 */
		started_xprts->rtg_count ++;
		xprt_rec = kmem_alloc(sizeof (*xprt_rec), KM_SLEEP);
		xprt_rec->rtr_xprt_ptr = xprt;
		xprt_rec->rtr_next = started_xprts->rtg_listhead;
		started_xprts->rtg_listhead = xprt_rec;
		continue;
cleanup:
		SVC_DESTROY(xprt);
		if (error == RDMA_FAILED)
			error = EPROTONOSUPPORT;
	}

	rw_exit(&rdma_lock);

	/*
	 * Don't return any error even if a single plugin was started
	 * successfully.
	 */
	if (started_xprts->rtg_count == 0)
		return (error);
	return (0);
}

/*
 * Cleanup routine for freeing up memory allocated by
 * svc_rdma_kcreate()
 */
void
svc_rdma_kdestroy(SVCMASTERXPRT *xprt)
{
	struct rdma_data *rd = (struct rdma_data *)xprt->xp_p2;


	mutex_destroy(&xprt->xp_req_lock);
	mutex_destroy(&xprt->xp_thread_lock);
	kmem_free(xprt->xp_netid, strlen(xprt->xp_netid) + 1);
	kmem_free(rd, sizeof (*rd));
	kmem_free(xprt->xp_addrmask.buf, xprt->xp_addrmask.maxlen);
	kmem_free(xprt, sizeof (*xprt));
}


static void
svc_rdma_kstart(SVCMASTERXPRT *xprt)
{
	struct rdma_svc_data *svcdata;
	rdma_mod_t *rmod;

	svcdata = &((struct rdma_data *)xprt->xp_p2)->rd_data;
	rmod = ((struct rdma_data *)xprt->xp_p2)->r_mod;

	/*
	 * Create a listener for  module at this port
	 */

	(*rmod->rdma_ops->rdma_svc_listen)(svcdata);
}

void
svc_rdma_kstop(SVCMASTERXPRT *xprt)
{
	struct rdma_svc_data *svcdata;
	rdma_mod_t *rmod;

	svcdata	= &((struct rdma_data *)xprt->xp_p2)->rd_data;
	rmod = ((struct rdma_data *)xprt->xp_p2)->r_mod;

	/*
	 * Call the stop listener routine for each plugin.
	 */
	(*rmod->rdma_ops->rdma_svc_stop)(svcdata);
	if (svcdata->active)
		cmn_err(CE_WARN, "rdma_stop: Failed to shutdown RDMA based kRPC"
			"  listener");
}

/* ARGSUSED */
static void
svc_rdma_kclone_destroy(SVCXPRT *clone_xprt)
{
}

static bool_t
svc_rdma_krecv(SVCXPRT *clone_xprt, mblk_t *mp, struct rpc_msg *msg)
{
	XDR *xdrs;
	rdma_stat status;
	struct recv_data *rdp = (struct recv_data *)mp->b_rptr;
	CONN *conn;
	struct clone_rdma_data *vd;
	struct clist *cl;
	uint_t vers, op, pos;
	uint32_t xid;

	vd = (struct clone_rdma_data *)clone_xprt->xp_p2buf;
	RSSTAT_INCR(rscalls);
	conn = rdp->conn;

	/*
	 * Post a receive descriptor on this
	 * endpoint to ensure all packets are received.
	 */
	status = rdma_svc_postrecv(conn);
	if (status != RDMA_SUCCESS) {
		cmn_err(CE_NOTE,
		    "svc_rdma_krecv: rdma_svc_postrecv failed %d", status);
	}

	if (rdp->status != 0) {
		RDMA_BUF_FREE(conn, &rdp->rpcmsg);
		RDMA_REL_CONN(conn);
		RSSTAT_INCR(rsbadcalls);
		freeb(mp);
		return (FALSE);
	}

	/*
	 * Decode rpc message
	 */
	xdrs = &clone_xprt->xp_xdrin;
	xdrmem_create(xdrs, rdp->rpcmsg.addr, rdp->rpcmsg.len, XDR_DECODE);

	/*
	 * Get the XID
	 */
	/*
	 * Treat xid as opaque (xid is the first entity
	 * in the rpc rdma message).
	 */
	xid = *(uint32_t *)rdp->rpcmsg.addr;
	/* Skip xid and set the xdr position accordingly. */
	XDR_SETPOS(xdrs, sizeof (uint32_t));
	if (! xdr_u_int(xdrs, &vers) ||
	    ! xdr_u_int(xdrs, &op)) {
		cmn_err(CE_WARN, "svc_rdma_krecv: xdr_u_int failed");
		XDR_DESTROY(xdrs);
		RDMA_BUF_FREE(conn, &rdp->rpcmsg);
		RDMA_REL_CONN(conn);
		freeb(mp);
		RSSTAT_INCR(rsbadcalls);
		return (FALSE);
	}
	if (op == RDMA_DONE) {
		/*
		 * Should not get RDMA_DONE
		 */
		freeb(mp);
		XDR_DESTROY(xdrs);
		RDMA_BUF_FREE(conn, &rdp->rpcmsg);
		RDMA_REL_CONN(conn);
		RSSTAT_INCR(rsbadcalls);
		return (FALSE); /* no response */
	}

#ifdef DEBUG
	if (rdma_svc_debug)
		printf("svc_rdma_krecv: recv'd call xid %u\n", xid);
#endif
	/*
	 * Now decode the chunk list
	 */
	cl = NULL;
	if (! xdr_do_clist(xdrs, &cl)) {
		cmn_err(CE_WARN, "svc_rdma_krecv: xdr_do_clist failed");
	}

	/*
	 * A chunk at 0 offset indicates that the RPC call message
	 * is in a chunk. Get the RPC call message chunk.
	 */
	if (cl != NULL && op == RDMA_NOMSG) {
		struct clist *cllong;	/* Long RPC chunk */

		/* Remove RPC call message chunk from chunklist */
		cllong = cl;
		cl = cl->c_next;
		cllong->c_next = NULL;

		/* Allocate and register memory for the RPC call msg chunk */
		cllong->c_daddr = (uint64)(uintptr_t)
		    kmem_alloc(cllong->c_len, KM_SLEEP);
		if (cllong->c_daddr == NULL) {
			cmn_err(CE_WARN,
				"svc_rdma_krecv: no memory for rpc call");
			XDR_DESTROY(xdrs);
			RDMA_BUF_FREE(conn, &rdp->rpcmsg);
			RDMA_REL_CONN(conn);
			freeb(mp);
			RSSTAT_INCR(rsbadcalls);
			clist_free(cl);
			clist_free(cllong);
			return (FALSE);
		}
		status = clist_register(conn, cllong, 0);
		if (status) {
			cmn_err(CE_WARN,
				"svc_rdma_krecv: clist_register failed");
			kmem_free((void *)(uintptr_t)cllong->c_daddr,
			    cllong->c_len);
			XDR_DESTROY(xdrs);
			RDMA_BUF_FREE(conn, &rdp->rpcmsg);
			RDMA_REL_CONN(conn);
			freeb(mp);
			RSSTAT_INCR(rsbadcalls);
			clist_free(cl);
			clist_free(cllong);
			return (FALSE);
		}

		/*
		 * Now read the RPC call message in
		 */
		status = RDMA_READ(conn, cllong, WAIT);
		if (status) {
			cmn_err(CE_WARN,
			    "svc_rdma_krecv: rdma_read failed %d", status);
			(void) clist_deregister(conn, cllong, 0);
			kmem_free((void *)(uintptr_t)cllong->c_daddr,
			    cllong->c_len);
			XDR_DESTROY(xdrs);
			RDMA_BUF_FREE(conn, &rdp->rpcmsg);
			RDMA_REL_CONN(conn);
			freeb(mp);
			RSSTAT_INCR(rsbadcalls);
			clist_free(cl);
			clist_free(cllong);
			return (FALSE);
		}
		/*
		 * Sync memory for CPU after DMA
		 */
		status = clist_syncmem(conn, cllong, 0);

		/*
		 * Deregister the chunk
		 */
		(void) clist_deregister(conn, cllong, 0);

		/*
		 * Setup the XDR for the RPC call message
		 */
		xdrrdma_create(xdrs, (caddr_t)(uintptr_t)cllong->c_daddr,
		    cllong->c_len, 0, cl, XDR_DECODE, conn);
		vd->rpcbuf.type = CHUNK_BUFFER;
		vd->rpcbuf.addr = (caddr_t)(uintptr_t)cllong->c_daddr;
		vd->rpcbuf.len = cllong->c_len;
		vd->rpcbuf.handle.mrc_rmr = 0;

		/*
		 * Free the chunk element with the Long RPC details and
		 * the message received.
		 */
		clist_free(cllong);
		RDMA_BUF_FREE(conn, &rdp->rpcmsg);
	} else {
		pos = XDR_GETPOS(xdrs);

		/*
		 * Now the RPC call message header
		 */
		xdrrdma_create(xdrs, rdp->rpcmsg.addr + pos,
			rdp->rpcmsg.len - pos, 0, cl, XDR_DECODE, conn);
		vd->rpcbuf = rdp->rpcmsg;
	}
	if (! xdr_callmsg(xdrs, msg)) {
		cmn_err(CE_WARN, "svc_rdma_krecv: xdr_callmsg failed");
		if (cl != NULL)
			clist_free(cl);
		XDR_DESTROY(xdrs);
		rdma_buf_free(conn, &vd->rpcbuf);
		RDMA_REL_CONN(conn);
		freeb(mp);
		RSSTAT_INCR(rsxdrcall);
		RSSTAT_INCR(rsbadcalls);
		return (FALSE);
	}

	/*
	 * Point the remote transport address in the service_transport
	 * handle at the address in the request.
	 */
	clone_xprt->xp_rtaddr.buf = conn->c_raddr.buf;
	clone_xprt->xp_rtaddr.len = conn->c_raddr.len;
	clone_xprt->xp_rtaddr.maxlen = conn->c_raddr.len;

#ifdef DEBUG
	if (rdma_svc_debug) {
		struct sockaddr_in *sin4;
		char print_addr[INET_ADDRSTRLEN];

		sin4 = (struct sockaddr_in *)clone_xprt->xp_rtaddr.buf;
		bzero(print_addr, INET_ADDRSTRLEN);
		(void) inet_ntop(AF_INET,
		    &sin4->sin_addr, print_addr, INET_ADDRSTRLEN);
		cmn_err(CE_NOTE,
		    "svc_rdma_krecv: remote clnt_addr: %s", print_addr);
	}
#endif

	clone_xprt->xp_xid = xid;
	vd->conn = conn;
	freeb(mp);
	return (TRUE);
}

/*
 * Send rpc reply.
 */
static bool_t
svc_rdma_ksend(SVCXPRT *clone_xprt, struct rpc_msg *msg)
{
	struct clone_rdma_data *vd;
	XDR *xdrs = &(clone_xprt->xp_xdrout), rxdrs;
	int retval = FALSE;
	xdrproc_t xdr_results;
	caddr_t xdr_location;
	bool_t has_args, reg = FALSE;
	uint_t len, op;
	uint_t vers;
	struct clist *cl = NULL, *cle = NULL;
	struct clist *sendlist = NULL;
	int status;
	int msglen;
	rdma_buf_t clmsg, longreply, rpcreply;

	vd = (struct clone_rdma_data *)clone_xprt->xp_p2buf;

	/*
	 * If there is a result procedure specified in the reply message,
	 * it will be processed in the xdr_replymsg and SVCAUTH_WRAP.
	 * We need to make sure it won't be processed twice, so we null
	 * it for xdr_replymsg here.
	 */
	has_args = FALSE;
	if (msg->rm_reply.rp_stat == MSG_ACCEPTED &&
	    msg->rm_reply.rp_acpt.ar_stat == SUCCESS) {
		if ((xdr_results = msg->acpted_rply.ar_results.proc) != NULL) {
			has_args = TRUE;
			xdr_location = msg->acpted_rply.ar_results.where;
			msg->acpted_rply.ar_results.proc = xdr_void;
			msg->acpted_rply.ar_results.where = NULL;
		}
	}

	/*
	 * Get the size of the rpc reply message. Need this
	 * to determine if the rpc reply message will fit in
	 * the pre-allocated RDMA buffers. If the rpc reply
	 * message length is greater that the pre-allocated
	 * buffers then, a one time use buffer is allocated
	 * and registered for this rpc reply.
	 */
	msglen = xdr_sizeof(xdr_replymsg, msg);
	if (has_args && msg->rm_reply.rp_acpt.ar_verf.oa_flavor != RPCSEC_GSS) {
		msglen += xdrrdma_sizeof(xdr_results, xdr_location,
				rdma_minchunk);
		if (msglen > RPC_MSG_SZ) {

			/*
			 * Allocate chunk buffer for rpc reply
			 */
			rpcreply.type = CHUNK_BUFFER;
			rpcreply.addr = kmem_zalloc(msglen, KM_SLEEP);
			cle = kmem_zalloc(sizeof (*cle), KM_SLEEP);
			cle->c_xdroff = 0;
			cle->c_len  = rpcreply.len = msglen;
			cle->c_saddr = (uint64)(uintptr_t)rpcreply.addr;
			cle->c_next = NULL;
			xdrrdma_create(xdrs, rpcreply.addr, msglen,
			    rdma_minchunk, cle, XDR_ENCODE, NULL);
			op = RDMA_NOMSG;
		} else {
			/*
			 * Get a pre-allocated buffer for rpc reply
			 */
			rpcreply.type = SEND_BUFFER;
			if (RDMA_BUF_ALLOC(vd->conn, &rpcreply)) {
				cmn_err(CE_WARN,
				    "svc_rdma_ksend: no free buffers!");
				return (retval);
			}
			xdrrdma_create(xdrs, rpcreply.addr, rpcreply.len,
			    rdma_minchunk, NULL, XDR_ENCODE, NULL);
			op = RDMA_MSG;
		}

		/*
		 * Initialize the XDR encode stream.
		 */
		msg->rm_xid = clone_xprt->xp_xid;

		if (!(xdr_replymsg(xdrs, msg) &&
		    (!has_args || SVCAUTH_WRAP(&clone_xprt->xp_auth, xdrs,
		    xdr_results, xdr_location)))) {
			rdma_buf_free(vd->conn, &rpcreply);
			if (cle)
				clist_free(cle);
			cmn_err(CE_WARN,
			    "svc_rdma_ksend: xdr_replymsg/SVCAUTH_WRAP "
			    "failed");
			goto out;
		}
		len = XDR_GETPOS(xdrs);
	}
	if (has_args && msg->rm_reply.rp_acpt.ar_verf.oa_flavor == RPCSEC_GSS) {

		/*
		 * For RPCSEC_GSS since we cannot accurately presize the
		 * buffer required for encoding, we assume that its going
		 * to be a Long RPC to start with. We also create the
		 * the XDR stream with min_chunk set to 0 which instructs
		 * the XDR layer to not chunk the incoming byte stream.
		 */
		msglen += 2 * MAX_AUTH_BYTES + 2 * sizeof (struct opaque_auth);
		msglen += xdr_sizeof(xdr_results, xdr_location);

		/*
		 * Long RPC. Allocate one time use custom buffer.
		 */
		longreply.type = CHUNK_BUFFER;
		longreply.addr = kmem_zalloc(msglen, KM_SLEEP);
		cle = kmem_zalloc(sizeof (*cle), KM_SLEEP);
		cle->c_xdroff = 0;
		cle->c_len  = longreply.len = msglen;
		cle->c_saddr = (uint64)(uintptr_t)longreply.addr;
		cle->c_next = NULL;
		xdrrdma_create(xdrs, longreply.addr, msglen, 0, cle,
		    XDR_ENCODE, NULL);
		op = RDMA_NOMSG;
		/*
		 * Initialize the XDR encode stream.
		 */
		msg->rm_xid = clone_xprt->xp_xid;

		if (!(xdr_replymsg(xdrs, msg) &&
		    (!has_args || SVCAUTH_WRAP(&clone_xprt->xp_auth, xdrs,
		    xdr_results, xdr_location)))) {
			if (longreply.addr != xdrs->x_base) {
				longreply.addr = xdrs->x_base;
				longreply.len = xdr_getbufsize(xdrs);
			}
			rdma_buf_free(vd->conn, &longreply);
			if (cle)
				clist_free(cle);
			cmn_err(CE_WARN,
			    "svc_rdma_ksend: xdr_replymsg/SVCAUTH_WRAP "
			    "failed");
			goto out;
		}

		/*
		 * If we had to allocate a new buffer while encoding
		 * then update the addr and len.
		 */
		if (longreply.addr != xdrs->x_base) {
			longreply.addr = xdrs->x_base;
			longreply.len = xdr_getbufsize(xdrs);
		}

		len = XDR_GETPOS(xdrs);

		/*
		 * If it so happens that the encoded message is after all
		 * not long enough to be a Long RPC then allocate a
		 * SEND_BUFFER and copy the encoded message into it.
		 */
		if (len > RPC_MSG_SZ) {
			rpcreply.type = CHUNK_BUFFER;
			rpcreply.addr = longreply.addr;
			rpcreply.len = longreply.len;
		} else {
			clist_free(cle);
			XDR_DESTROY(xdrs);
			/*
			 * Get a pre-allocated buffer for rpc reply
			 */
			rpcreply.type = SEND_BUFFER;
			if (RDMA_BUF_ALLOC(vd->conn, &rpcreply)) {
				cmn_err(CE_WARN,
				    "svc_rdma_ksend: no free buffers!");
				rdma_buf_free(vd->conn, &longreply);
				return (retval);
			}
			bcopy(longreply.addr, rpcreply.addr, len);
			xdrrdma_create(xdrs, rpcreply.addr, len, 0, NULL,
			    XDR_ENCODE, NULL);
			rdma_buf_free(vd->conn, &longreply);
			op = RDMA_MSG;
		}
	}

	if (has_args == FALSE) {

		if (msglen > RPC_MSG_SZ) {

			/*
			 * Allocate chunk buffer for rpc reply
			 */
			rpcreply.type = CHUNK_BUFFER;
			rpcreply.addr = kmem_zalloc(msglen, KM_SLEEP);
			cle = kmem_zalloc(sizeof (*cle), KM_SLEEP);
			cle->c_xdroff = 0;
			cle->c_len  = rpcreply.len = msglen;
			cle->c_saddr = (uint64)(uintptr_t)rpcreply.addr;
			cle->c_next = NULL;
			xdrrdma_create(xdrs, rpcreply.addr, msglen,
			    rdma_minchunk, cle, XDR_ENCODE, NULL);
			op = RDMA_NOMSG;
		} else {
			/*
			 * Get a pre-allocated buffer for rpc reply
			 */
			rpcreply.type = SEND_BUFFER;
			if (RDMA_BUF_ALLOC(vd->conn, &rpcreply)) {
				cmn_err(CE_WARN,
				    "svc_rdma_ksend: no free buffers!");
				return (retval);
			}
			xdrrdma_create(xdrs, rpcreply.addr, rpcreply.len,
			    rdma_minchunk, NULL, XDR_ENCODE, NULL);
			op = RDMA_MSG;
		}

		/*
		 * Initialize the XDR encode stream.
		 */
		msg->rm_xid = clone_xprt->xp_xid;

		if (!xdr_replymsg(xdrs, msg)) {
			rdma_buf_free(vd->conn, &rpcreply);
			if (cle)
				clist_free(cle);
			cmn_err(CE_WARN,
			    "svc_rdma_ksend: xdr_replymsg/SVCAUTH_WRAP "
			    "failed");
			goto out;
		}
		len = XDR_GETPOS(xdrs);
	}

	/*
	 * Get clist and a buffer for sending it across
	 */
	cl = xdrrdma_clist(xdrs);
	clmsg.type = SEND_BUFFER;
	if (RDMA_BUF_ALLOC(vd->conn, &clmsg)) {
		rdma_buf_free(vd->conn, &rpcreply);
		cmn_err(CE_WARN, "svc_rdma_ksend: no free buffers!!");
		goto out;
	}

	/*
	 * Now register the chunks in the list
	 */
	if (cl != NULL) {
		status = clist_register(vd->conn, cl, 1);
		if (status != RDMA_SUCCESS) {
			rdma_buf_free(vd->conn, &clmsg);
			cmn_err(CE_WARN,
				"svc_rdma_ksend: clist register failed");
			goto out;
		}
		reg = TRUE;
	}

	/*
	 * XDR the XID, vers, and op
	 */
	/*
	 * Treat xid as opaque (xid is the first entity
	 * in the rpc rdma message).
	 */
	vers = RPCRDMA_VERS;
	xdrs = &rxdrs;
	xdrmem_create(xdrs, clmsg.addr, clmsg.len, XDR_ENCODE);
	(*(uint32_t *)clmsg.addr) = msg->rm_xid;
	/* Skip xid and set the xdr position accordingly. */
	XDR_SETPOS(xdrs, sizeof (uint32_t));
	if (! xdr_u_int(xdrs, &vers) ||
	    ! xdr_u_int(xdrs, &op)) {
		rdma_buf_free(vd->conn, &rpcreply);
		rdma_buf_free(vd->conn, &clmsg);
		cmn_err(CE_WARN, "svc_rdma_ksend: xdr_u_int failed");
		goto out;
	}

	/*
	 * Now XDR the chunk list
	 */
	(void) xdr_do_clist(xdrs, &cl);

	clist_add(&sendlist, 0, XDR_GETPOS(xdrs), &clmsg.handle, clmsg.addr,
		NULL, NULL);

	if (op == RDMA_MSG) {
		clist_add(&sendlist, 0, len, &rpcreply.handle, rpcreply.addr,
			NULL, NULL);
	} else {
		cl->c_len = len;
		RSSTAT_INCR(rslongrpcs);
	}

	/*
	 * Send the reply message to the client
	 */
	if (cl != NULL) {
		status = clist_syncmem(vd->conn, cl, 1);
		if (status != RDMA_SUCCESS) {
			rdma_buf_free(vd->conn, &rpcreply);
			rdma_buf_free(vd->conn, &clmsg);
			goto out;
		}
#ifdef DEBUG
	if (rdma_svc_debug)
		printf("svc_rdma_ksend: chunk response len %d xid %u\n",
			cl->c_len, msg->rm_xid);
#endif
		/*
		 * Post a receive buffer because we expect a RDMA_DONE
		 * message.
		 */
		status = rdma_svc_postrecv(vd->conn);

		/*
		 * Send the RPC reply message and wait for RDMA_DONE
		 */
		status = RDMA_SEND_RESP(vd->conn, sendlist, msg->rm_xid);
		if (status != RDMA_SUCCESS) {
#ifdef DEBUG
			if (rdma_svc_debug)
				cmn_err(CE_NOTE, "svc_rdma_ksend: "
					"rdma_send_resp failed %d", status);
#endif
			goto out;
		}
#ifdef DEBUG
	if (rdma_svc_debug)
		printf("svc_rdma_ksend: got RDMA_DONE xid %u\n", msg->rm_xid);
#endif
	} else {
#ifdef DEBUG
	if (rdma_svc_debug)
		printf("svc_rdma_ksend: msg response xid %u\n", msg->rm_xid);
#endif
		status = RDMA_SEND(vd->conn, sendlist, msg->rm_xid);
		if (status != RDMA_SUCCESS) {
#ifdef DEBUG
			if (rdma_svc_debug)
				cmn_err(CE_NOTE, "svc_rdma_ksend: "
					"rdma_send failed %d", status);
#endif
			goto out;
		}
	}

	retval = TRUE;
out:
	/*
	 * Deregister the chunks
	 */
	if (cl != NULL) {
		if (reg)
			(void) clist_deregister(vd->conn, cl, 1);
		if (op == RDMA_NOMSG) {
			/*
			 * Long RPC reply in chunk. Free it up.
			 */
			rdma_buf_free(vd->conn, &rpcreply);
		}
		clist_free(cl);
	}

	/*
	 * Free up sendlist chunks
	 */
	if (sendlist != NULL)
		clist_free(sendlist);

	/*
	 * Destroy private data for xdr rdma
	 */
	XDR_DESTROY(&(clone_xprt->xp_xdrout));

	/*
	 * This is completely disgusting.  If public is set it is
	 * a pointer to a structure whose first field is the address
	 * of the function to free that structure and any related
	 * stuff.  (see rrokfree in nfs_xdr.c).
	 */
	if (xdrs->x_public) {
		/* LINTED pointer alignment */
		(**((int (**)())xdrs->x_public))(xdrs->x_public);
	}

	return (retval);
}

/*
 * Deserialize arguments.
 */
static bool_t
svc_rdma_kgetargs(SVCXPRT *clone_xprt, xdrproc_t xdr_args, caddr_t args_ptr)
{
	if ((SVCAUTH_UNWRAP(&clone_xprt->xp_auth, &clone_xprt->xp_xdrin,
	    xdr_args, args_ptr)) != TRUE)
		return (FALSE);
	return (TRUE);
}

static bool_t
svc_rdma_kfreeargs(SVCXPRT *clone_xprt, xdrproc_t xdr_args,
    caddr_t args_ptr)
{
	struct clone_rdma_data *vd;
	bool_t retval;

	vd = (struct clone_rdma_data *)clone_xprt->xp_p2buf;
	if (args_ptr) {
		XDR	*xdrs = &clone_xprt->xp_xdrin;
		struct clist *cl;

		cl = xdrrdma_clist(xdrs);
		if (cl != NULL)
			clist_free(cl);

		xdrs->x_op = XDR_FREE;
		retval = (*xdr_args)(xdrs, args_ptr);
	}
	XDR_DESTROY(&(clone_xprt->xp_xdrin));
	rdma_buf_free(vd->conn, &vd->rpcbuf);
	RDMA_REL_CONN(vd->conn);
	return (retval);
}

/* ARGSUSED */
static int32_t *
svc_rdma_kgetres(SVCXPRT *clone_xprt, int size)
{
	return (NULL);
}

/* ARGSUSED */
static void
svc_rdma_kfreeres(SVCXPRT *clone_xprt)
{
}

/*
 * the dup cacheing routines below provide a cache of non-failure
 * transaction id's.  rpc service routines can use this to detect
 * retransmissions and re-send a non-failure response.
 */

/*
 * MAXDUPREQS is the number of cached items.  It should be adjusted
 * to the service load so that there is likely to be a response entry
 * when the first retransmission comes in.
 */
#define	MAXDUPREQS	1024

/*
 * This should be appropriately scaled to MAXDUPREQS.
 */
#define	DRHASHSZ	257

#if ((DRHASHSZ & (DRHASHSZ - 1)) == 0)
#define	XIDHASH(xid)	((xid) & (DRHASHSZ - 1))
#else
#define	XIDHASH(xid)	((xid) % DRHASHSZ)
#endif
#define	DRHASH(dr)	XIDHASH((dr)->dr_xid)
#define	REQTOXID(req)	((req)->rq_xprt->xp_xid)

static int	rdmandupreqs = 0;
static int	rdmamaxdupreqs = MAXDUPREQS;
static kmutex_t rdmadupreq_lock;
static struct dupreq *rdmadrhashtbl[DRHASHSZ];
static int	rdmadrhashstat[DRHASHSZ];

static void unhash(struct dupreq *);

/*
 * rdmadrmru points to the head of a circular linked list in lru order.
 * rdmadrmru->dr_next == drlru
 */
struct dupreq *rdmadrmru;

/*
 * svc_rdma_kdup searches the request cache and returns 0 if the
 * request is not found in the cache.  If it is found, then it
 * returns the state of the request (in progress or done) and
 * the status or attributes that were part of the original reply.
 */
static int
svc_rdma_kdup(struct svc_req *req, caddr_t res, int size, struct dupreq **drpp,
	bool_t *dupcachedp)
{
	struct dupreq *dr;
	uint32_t xid;
	uint32_t drhash;
	int status;

	xid = REQTOXID(req);
	mutex_enter(&rdmadupreq_lock);
	RSSTAT_INCR(rsdupchecks);
	/*
	 * Check to see whether an entry already exists in the cache.
	 */
	dr = rdmadrhashtbl[XIDHASH(xid)];
	while (dr != NULL) {
		if (dr->dr_xid == xid &&
		    dr->dr_proc == req->rq_proc &&
		    dr->dr_prog == req->rq_prog &&
		    dr->dr_vers == req->rq_vers &&
		    dr->dr_addr.len == req->rq_xprt->xp_rtaddr.len &&
		    bcmp((caddr_t)dr->dr_addr.buf,
		    (caddr_t)req->rq_xprt->xp_rtaddr.buf,
		    dr->dr_addr.len) == 0) {
			status = dr->dr_status;
			if (status == DUP_DONE) {
				bcopy(dr->dr_resp.buf, res, size);
				if (dupcachedp != NULL)
					*dupcachedp = (dr->dr_resfree != NULL);
			} else {
				dr->dr_status = DUP_INPROGRESS;
				*drpp = dr;
			}
			RSSTAT_INCR(rsdupreqs);
			mutex_exit(&rdmadupreq_lock);
			return (status);
		}
		dr = dr->dr_chain;
	}

	/*
	 * There wasn't an entry, either allocate a new one or recycle
	 * an old one.
	 */
	if (rdmandupreqs < rdmamaxdupreqs) {
		dr = kmem_alloc(sizeof (*dr), KM_NOSLEEP);
		if (dr == NULL) {
			mutex_exit(&rdmadupreq_lock);
			return (DUP_ERROR);
		}
		dr->dr_resp.buf = NULL;
		dr->dr_resp.maxlen = 0;
		dr->dr_addr.buf = NULL;
		dr->dr_addr.maxlen = 0;
		if (rdmadrmru) {
			dr->dr_next = rdmadrmru->dr_next;
			rdmadrmru->dr_next = dr;
		} else {
			dr->dr_next = dr;
		}
		rdmandupreqs++;
	} else {
		dr = rdmadrmru->dr_next;
		while (dr->dr_status == DUP_INPROGRESS) {
			dr = dr->dr_next;
			if (dr == rdmadrmru->dr_next) {
				cmn_err(CE_WARN, "svc_rdma_kdup no slots free");
				mutex_exit(&rdmadupreq_lock);
				return (DUP_ERROR);
			}
		}
		unhash(dr);
		if (dr->dr_resfree) {
			(*dr->dr_resfree)(dr->dr_resp.buf);
		}
	}
	dr->dr_resfree = NULL;
	rdmadrmru = dr;

	dr->dr_xid = REQTOXID(req);
	dr->dr_prog = req->rq_prog;
	dr->dr_vers = req->rq_vers;
	dr->dr_proc = req->rq_proc;
	if (dr->dr_addr.maxlen < req->rq_xprt->xp_rtaddr.len) {
		if (dr->dr_addr.buf != NULL)
			kmem_free(dr->dr_addr.buf, dr->dr_addr.maxlen);
		dr->dr_addr.maxlen = req->rq_xprt->xp_rtaddr.len;
		dr->dr_addr.buf = kmem_alloc(dr->dr_addr.maxlen, KM_NOSLEEP);
		if (dr->dr_addr.buf == NULL) {
			dr->dr_addr.maxlen = 0;
			dr->dr_status = DUP_DROP;
			mutex_exit(&rdmadupreq_lock);
			return (DUP_ERROR);
		}
	}
	dr->dr_addr.len = req->rq_xprt->xp_rtaddr.len;
	bcopy(req->rq_xprt->xp_rtaddr.buf, dr->dr_addr.buf, dr->dr_addr.len);
	if (dr->dr_resp.maxlen < size) {
		if (dr->dr_resp.buf != NULL)
			kmem_free(dr->dr_resp.buf, dr->dr_resp.maxlen);
		dr->dr_resp.maxlen = (unsigned int)size;
		dr->dr_resp.buf = kmem_alloc(size, KM_NOSLEEP);
		if (dr->dr_resp.buf == NULL) {
			dr->dr_resp.maxlen = 0;
			dr->dr_status = DUP_DROP;
			mutex_exit(&rdmadupreq_lock);
			return (DUP_ERROR);
		}
	}
	dr->dr_status = DUP_INPROGRESS;

	drhash = (uint32_t)DRHASH(dr);
	dr->dr_chain = rdmadrhashtbl[drhash];
	rdmadrhashtbl[drhash] = dr;
	rdmadrhashstat[drhash]++;
	mutex_exit(&rdmadupreq_lock);
	*drpp = dr;
	return (DUP_NEW);
}

/*
 * svc_rdma_kdupdone marks the request done (DUP_DONE or DUP_DROP)
 * and stores the response.
 */
static void
svc_rdma_kdupdone(struct dupreq *dr, caddr_t res, void (*dis_resfree)(),
	int size, int status)
{
	ASSERT(dr->dr_resfree == NULL);
	if (status == DUP_DONE) {
		bcopy(res, dr->dr_resp.buf, size);
		dr->dr_resfree = dis_resfree;
	}
	dr->dr_status = status;
}

/*
 * This routine expects that the mutex, rdmadupreq_lock, is already held.
 */
static void
unhash(struct dupreq *dr)
{
	struct dupreq *drt;
	struct dupreq *drtprev = NULL;
	uint32_t drhash;

	ASSERT(MUTEX_HELD(&rdmadupreq_lock));

	drhash = (uint32_t)DRHASH(dr);
	drt = rdmadrhashtbl[drhash];
	while (drt != NULL) {
		if (drt == dr) {
			rdmadrhashstat[drhash]--;
			if (drtprev == NULL) {
				rdmadrhashtbl[drhash] = drt->dr_chain;
			} else {
				drtprev->dr_chain = drt->dr_chain;
			}
			return;
		}
		drtprev = drt;
		drt = drt->dr_chain;
	}
}
