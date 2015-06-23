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
 * Copyright (c) 1983, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */
/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

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

#include <nfs/nfs.h>
#include <sys/sdt.h>

#define	SVC_RDMA_SUCCESS 0
#define	SVC_RDMA_FAIL -1

#define	SVC_CREDIT_FACTOR (0.5)

#define	MSG_IS_RPCSEC_GSS(msg)		\
	((msg)->rm_reply.rp_acpt.ar_verf.oa_flavor == RPCSEC_GSS)


uint32_t rdma_bufs_granted = RDMA_BUFS_GRANT;

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
	bool_t		cloned;		/* xprt cloned for thread processing */
	CONN		*conn;		/* RDMA connection */
	rdma_buf_t	rpcbuf;		/* RPC req/resp buffer */
	struct clist	*cl_reply;	/* reply chunk buffer info */
	struct clist	*cl_wlist;		/* write list clist */
};


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
static void		svc_rdma_kclone_xprt(SVCXPRT *, SVCXPRT *);
static void		svc_rdma_ktattrs(SVCXPRT *, int, void **);

static int	svc_process_long_reply(SVCXPRT *, xdrproc_t,
			caddr_t, struct rpc_msg *, bool_t, int *,
			int *, int *, unsigned int *);

static int	svc_compose_rpcmsg(SVCXPRT *, CONN *, xdrproc_t,
			caddr_t, rdma_buf_t *, XDR **, struct rpc_msg *,
			bool_t, uint_t *);
static bool_t rpcmsg_length(xdrproc_t,
		caddr_t,
		struct rpc_msg *, bool_t, int);

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
	svc_rdma_kstart,	/* Tell `ready-to-receive' to rpcmod */
	svc_rdma_kclone_xprt,	/* Transport specific clone xprt */
	svc_rdma_ktattrs	/* Get Transport Attributes */
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
	kstat_named_t	rstotalreplies;
	kstat_named_t	rstotallongreplies;
	kstat_named_t	rstotalinlinereplies;
} rdmarsstat = {
	{ "calls",	KSTAT_DATA_UINT64 },
	{ "badcalls",	KSTAT_DATA_UINT64 },
	{ "nullrecv",	KSTAT_DATA_UINT64 },
	{ "badlen",	KSTAT_DATA_UINT64 },
	{ "xdrcall",	KSTAT_DATA_UINT64 },
	{ "dupchecks",	KSTAT_DATA_UINT64 },
	{ "dupreqs",	KSTAT_DATA_UINT64 },
	{ "longrpcs",	KSTAT_DATA_UINT64 },
	{ "totalreplies",	KSTAT_DATA_UINT64 },
	{ "totallongreplies",	KSTAT_DATA_UINT64 },
	{ "totalinlinereplies",	KSTAT_DATA_UINT64 },
};

kstat_named_t *rdmarsstat_ptr = (kstat_named_t *)&rdmarsstat;
uint_t rdmarsstat_ndata = sizeof (rdmarsstat) / sizeof (kstat_named_t);

#define	RSSTAT_INCR(x)	atomic_inc_64(&rdmarsstat.x.value.ui64)
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
		/*CONSTANTCONDITION*/
		ASSERT(sizeof (struct clone_rdma_data) <= SVC_P2LEN);

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
		xprt->xp_full = FALSE;
		xprt->xp_enable = FALSE;
		xprt->xp_reqs = 0;
		xprt->xp_size = 0;
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

		/*
		 * Each of the plugins will have their own Service ID
		 * to listener specific mapping, like port number for VI
		 * and service name for IB.
		 */
		rd->rd_data.svcid = id;
		error = svc_xprt_register(xprt, id);
		if (error) {
			DTRACE_PROBE(krpc__e__svcrdma__xprt__reg);
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
	kmem_free(rd, sizeof (*rd));
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

	if (rmod->rdma_count != 0)
		(*rmod->rdma_ops->rdma_svc_listen)(svcdata);
	else
		svcdata->err_code = RDMA_FAILED;
}

void
svc_rdma_kstop(SVCMASTERXPRT *xprt)
{
	struct rdma_svc_data *svcdata;
	rdma_mod_t *rmod;

	svcdata	= &((struct rdma_data *)xprt->xp_p2)->rd_data;
	rmod = ((struct rdma_data *)xprt->xp_p2)->r_mod;

	/*
	 * Call the stop listener routine for each plugin. If rdma_count is
	 * already zero set active to zero.
	 */
	if (rmod->rdma_count != 0)
		(*rmod->rdma_ops->rdma_svc_stop)(svcdata);
	else
		svcdata->active = 0;
	if (svcdata->active)
		DTRACE_PROBE(krpc__e__svcrdma__kstop);
}

/* ARGSUSED */
static void
svc_rdma_kclone_destroy(SVCXPRT *clone_xprt)
{

	struct clone_rdma_data *cdrp;
	cdrp = (struct clone_rdma_data *)clone_xprt->xp_p2buf;

	/*
	 * Only free buffers and release connection when cloned is set.
	 */
	if (cdrp->cloned != TRUE)
		return;

	rdma_buf_free(cdrp->conn, &cdrp->rpcbuf);
	if (cdrp->cl_reply) {
		clist_free(cdrp->cl_reply);
		cdrp->cl_reply = NULL;
	}
	RDMA_REL_CONN(cdrp->conn);

	cdrp->cloned = 0;
}

/*
 * Clone the xprt specific information.  It will be freed by
 * SVC_CLONE_DESTROY.
 */
static void
svc_rdma_kclone_xprt(SVCXPRT *src_xprt, SVCXPRT *dst_xprt)
{
	struct clone_rdma_data *srcp2;
	struct clone_rdma_data *dstp2;

	srcp2 = (struct clone_rdma_data *)src_xprt->xp_p2buf;
	dstp2 = (struct clone_rdma_data *)dst_xprt->xp_p2buf;

	if (srcp2->conn != NULL) {
		srcp2->cloned = TRUE;
		*dstp2 = *srcp2;
	}
}

static void
svc_rdma_ktattrs(SVCXPRT *clone_xprt, int attrflag, void **tattr)
{
	CONN	*conn;
	*tattr = NULL;

	switch (attrflag) {
	case SVC_TATTR_ADDRMASK:
		conn = ((struct clone_rdma_data *)clone_xprt->xp_p2buf)->conn;
		ASSERT(conn != NULL);
		if (conn)
			*tattr = (void *)&conn->c_addrmask;
	}
}

static bool_t
svc_rdma_krecv(SVCXPRT *clone_xprt, mblk_t *mp, struct rpc_msg *msg)
{
	XDR	*xdrs;
	CONN	*conn;
	rdma_recv_data_t	*rdp = (rdma_recv_data_t *)mp->b_rptr;
	struct clone_rdma_data *crdp;
	struct clist	*cl = NULL;
	struct clist	*wcl = NULL;
	struct clist	*cllong = NULL;

	rdma_stat	status;
	uint32_t vers, op, pos, xid;
	uint32_t rdma_credit;
	uint32_t wcl_total_length = 0;
	bool_t	wwl = FALSE;

	crdp = (struct clone_rdma_data *)clone_xprt->xp_p2buf;
	RSSTAT_INCR(rscalls);
	conn = rdp->conn;

	status = rdma_svc_postrecv(conn);
	if (status != RDMA_SUCCESS) {
		DTRACE_PROBE(krpc__e__svcrdma__krecv__postrecv);
		goto badrpc_call;
	}

	xdrs = &clone_xprt->xp_xdrin;
	xdrmem_create(xdrs, rdp->rpcmsg.addr, rdp->rpcmsg.len, XDR_DECODE);
	xid = *(uint32_t *)rdp->rpcmsg.addr;
	XDR_SETPOS(xdrs, sizeof (uint32_t));

	if (! xdr_u_int(xdrs, &vers) ||
	    ! xdr_u_int(xdrs, &rdma_credit) ||
	    ! xdr_u_int(xdrs, &op)) {
		DTRACE_PROBE(krpc__e__svcrdma__krecv__uint);
		goto xdr_err;
	}

	/* Checking if the status of the recv operation was normal */
	if (rdp->status != 0) {
		DTRACE_PROBE1(krpc__e__svcrdma__krecv__invalid__status,
		    int, rdp->status);
		goto badrpc_call;
	}

	if (! xdr_do_clist(xdrs, &cl)) {
		DTRACE_PROBE(krpc__e__svcrdma__krecv__do__clist);
		goto xdr_err;
	}

	if (!xdr_decode_wlist_svc(xdrs, &wcl, &wwl, &wcl_total_length, conn)) {
		DTRACE_PROBE(krpc__e__svcrdma__krecv__decode__wlist);
		if (cl)
			clist_free(cl);
		goto xdr_err;
	}
	crdp->cl_wlist = wcl;

	crdp->cl_reply = NULL;
	(void) xdr_decode_reply_wchunk(xdrs, &crdp->cl_reply);

	/*
	 * A chunk at 0 offset indicates that the RPC call message
	 * is in a chunk. Get the RPC call message chunk.
	 */
	if (cl != NULL && op == RDMA_NOMSG) {

		/* Remove RPC call message chunk from chunklist */
		cllong = cl;
		cl = cl->c_next;
		cllong->c_next = NULL;


		/* Allocate and register memory for the RPC call msg chunk */
		cllong->rb_longbuf.type = RDMA_LONG_BUFFER;
		cllong->rb_longbuf.len = cllong->c_len > LONG_REPLY_LEN ?
		    cllong->c_len : LONG_REPLY_LEN;

		if (rdma_buf_alloc(conn, &cllong->rb_longbuf)) {
			clist_free(cllong);
			goto cll_malloc_err;
		}

		cllong->u.c_daddr3 = cllong->rb_longbuf.addr;

		if (cllong->u.c_daddr == NULL) {
			DTRACE_PROBE(krpc__e__svcrdma__krecv__nomem);
			rdma_buf_free(conn, &cllong->rb_longbuf);
			clist_free(cllong);
			goto cll_malloc_err;
		}

		status = clist_register(conn, cllong, CLIST_REG_DST);
		if (status) {
			DTRACE_PROBE(krpc__e__svcrdma__krecv__clist__reg);
			rdma_buf_free(conn, &cllong->rb_longbuf);
			clist_free(cllong);
			goto cll_malloc_err;
		}

		/*
		 * Now read the RPC call message in
		 */
		status = RDMA_READ(conn, cllong, WAIT);
		if (status) {
			DTRACE_PROBE(krpc__e__svcrdma__krecv__read);
			(void) clist_deregister(conn, cllong);
			rdma_buf_free(conn, &cllong->rb_longbuf);
			clist_free(cllong);
			goto cll_malloc_err;
		}

		status = clist_syncmem(conn, cllong, CLIST_REG_DST);
		(void) clist_deregister(conn, cllong);

		xdrrdma_create(xdrs, (caddr_t)(uintptr_t)cllong->u.c_daddr3,
		    cllong->c_len, 0, cl, XDR_DECODE, conn);

		crdp->rpcbuf = cllong->rb_longbuf;
		crdp->rpcbuf.len = cllong->c_len;
		clist_free(cllong);
		RDMA_BUF_FREE(conn, &rdp->rpcmsg);
	} else {
		pos = XDR_GETPOS(xdrs);
		xdrrdma_create(xdrs, rdp->rpcmsg.addr + pos,
		    rdp->rpcmsg.len - pos, 0, cl, XDR_DECODE, conn);
		crdp->rpcbuf = rdp->rpcmsg;

		/* Use xdrrdmablk_ops to indicate there is a read chunk list */
		if (cl != NULL) {
			int32_t flg = XDR_RDMA_RLIST_REG;

			XDR_CONTROL(xdrs, XDR_RDMA_SET_FLAGS, &flg);
			xdrs->x_ops = &xdrrdmablk_ops;
		}
	}

	if (crdp->cl_wlist) {
		int32_t flg = XDR_RDMA_WLIST_REG;

		XDR_CONTROL(xdrs, XDR_RDMA_SET_WLIST, crdp->cl_wlist);
		XDR_CONTROL(xdrs, XDR_RDMA_SET_FLAGS, &flg);
	}

	if (! xdr_callmsg(xdrs, msg)) {
		DTRACE_PROBE(krpc__e__svcrdma__krecv__callmsg);
		RSSTAT_INCR(rsxdrcall);
		goto callmsg_err;
	}

	/*
	 * Point the remote transport address in the service_transport
	 * handle at the address in the request.
	 */
	clone_xprt->xp_rtaddr.buf = conn->c_raddr.buf;
	clone_xprt->xp_rtaddr.len = conn->c_raddr.len;
	clone_xprt->xp_rtaddr.maxlen = conn->c_raddr.len;

	clone_xprt->xp_lcladdr.buf = conn->c_laddr.buf;
	clone_xprt->xp_lcladdr.len = conn->c_laddr.len;
	clone_xprt->xp_lcladdr.maxlen = conn->c_laddr.len;

	/*
	 * In case of RDMA, connection management is
	 * entirely done in rpcib module and netid in the
	 * SVCMASTERXPRT is NULL. Initialize the clone netid
	 * from the connection.
	 */

	clone_xprt->xp_netid = conn->c_netid;

	clone_xprt->xp_xid = xid;
	crdp->conn = conn;

	freeb(mp);

	return (TRUE);

callmsg_err:
	rdma_buf_free(conn, &crdp->rpcbuf);

cll_malloc_err:
	if (cl)
		clist_free(cl);
xdr_err:
	XDR_DESTROY(xdrs);

badrpc_call:
	RDMA_BUF_FREE(conn, &rdp->rpcmsg);
	RDMA_REL_CONN(conn);
	freeb(mp);
	RSSTAT_INCR(rsbadcalls);
	return (FALSE);
}

static int
svc_process_long_reply(SVCXPRT * clone_xprt,
    xdrproc_t xdr_results, caddr_t xdr_location,
    struct rpc_msg *msg, bool_t has_args, int *msglen,
    int *freelen, int *numchunks, unsigned int *final_len)
{
	int status;
	XDR xdrslong;
	struct clist *wcl = NULL;
	int count = 0;
	int alloc_len;
	char  *memp;
	rdma_buf_t long_rpc = {0};
	struct clone_rdma_data *crdp;

	crdp = (struct clone_rdma_data *)clone_xprt->xp_p2buf;

	bzero(&xdrslong, sizeof (xdrslong));

	/* Choose a size for the long rpc response */
	if (MSG_IS_RPCSEC_GSS(msg)) {
		alloc_len = RNDUP(MAX_AUTH_BYTES + *msglen);
	} else {
		alloc_len = RNDUP(*msglen);
	}

	if (alloc_len <= 64 * 1024) {
		if (alloc_len > 32 * 1024) {
			alloc_len = 64 * 1024;
		} else {
			if (alloc_len > 16 * 1024) {
				alloc_len = 32 * 1024;
			} else {
				alloc_len = 16 * 1024;
			}
		}
	}

	long_rpc.type = RDMA_LONG_BUFFER;
	long_rpc.len = alloc_len;
	if (rdma_buf_alloc(crdp->conn, &long_rpc)) {
		return (SVC_RDMA_FAIL);
	}

	memp = long_rpc.addr;
	xdrmem_create(&xdrslong, memp, alloc_len, XDR_ENCODE);

	msg->rm_xid = clone_xprt->xp_xid;

	if (!(xdr_replymsg(&xdrslong, msg) &&
	    (!has_args || SVCAUTH_WRAP(&clone_xprt->xp_auth, &xdrslong,
	    xdr_results, xdr_location)))) {
		rdma_buf_free(crdp->conn, &long_rpc);
		DTRACE_PROBE(krpc__e__svcrdma__longrep__authwrap);
		return (SVC_RDMA_FAIL);
	}

	*final_len = XDR_GETPOS(&xdrslong);

	DTRACE_PROBE1(krpc__i__replylen, uint_t, *final_len);
	*numchunks = 0;
	*freelen = 0;

	wcl = crdp->cl_reply;
	wcl->rb_longbuf = long_rpc;

	count = *final_len;
	while ((wcl != NULL) && (count > 0)) {

		if (wcl->c_dmemhandle.mrc_rmr == 0)
			break;

		DTRACE_PROBE2(krpc__i__write__chunks, uint32_t, count,
		    uint32_t, wcl->c_len);

		if (wcl->c_len > count) {
			wcl->c_len = count;
		}
		wcl->w.c_saddr3 = (caddr_t)memp;

		count -= wcl->c_len;
		*numchunks +=  1;
		memp += wcl->c_len;
		wcl = wcl->c_next;
	}

	/*
	 * Make rest of the chunks 0-len
	 */
	while (wcl != NULL) {
		if (wcl->c_dmemhandle.mrc_rmr == 0)
			break;
		wcl->c_len = 0;
		wcl = wcl->c_next;
	}

	wcl = crdp->cl_reply;

	/*
	 * MUST fail if there are still more data
	 */
	if (count > 0) {
		rdma_buf_free(crdp->conn, &long_rpc);
		DTRACE_PROBE(krpc__e__svcrdma__longrep__dlen__clist);
		return (SVC_RDMA_FAIL);
	}

	if (clist_register(crdp->conn, wcl, CLIST_REG_SOURCE) != RDMA_SUCCESS) {
		rdma_buf_free(crdp->conn, &long_rpc);
		DTRACE_PROBE(krpc__e__svcrdma__longrep__clistreg);
		return (SVC_RDMA_FAIL);
	}

	status = clist_syncmem(crdp->conn, wcl, CLIST_REG_SOURCE);

	if (status) {
		(void) clist_deregister(crdp->conn, wcl);
		rdma_buf_free(crdp->conn, &long_rpc);
		DTRACE_PROBE(krpc__e__svcrdma__longrep__syncmem);
		return (SVC_RDMA_FAIL);
	}

	status = RDMA_WRITE(crdp->conn, wcl, WAIT);

	(void) clist_deregister(crdp->conn, wcl);
	rdma_buf_free(crdp->conn, &wcl->rb_longbuf);

	if (status != RDMA_SUCCESS) {
		DTRACE_PROBE(krpc__e__svcrdma__longrep__write);
		return (SVC_RDMA_FAIL);
	}

	return (SVC_RDMA_SUCCESS);
}


static int
svc_compose_rpcmsg(SVCXPRT * clone_xprt, CONN * conn, xdrproc_t xdr_results,
    caddr_t xdr_location, rdma_buf_t *rpcreply, XDR ** xdrs,
    struct rpc_msg *msg, bool_t has_args, uint_t *len)
{
	/*
	 * Get a pre-allocated buffer for rpc reply
	 */
	rpcreply->type = SEND_BUFFER;
	if (rdma_buf_alloc(conn, rpcreply)) {
		DTRACE_PROBE(krpc__e__svcrdma__rpcmsg__reply__nofreebufs);
		return (SVC_RDMA_FAIL);
	}

	xdrrdma_create(*xdrs, rpcreply->addr, rpcreply->len,
	    0, NULL, XDR_ENCODE, conn);

	msg->rm_xid = clone_xprt->xp_xid;

	if (has_args) {
		if (!(xdr_replymsg(*xdrs, msg) &&
		    (!has_args ||
		    SVCAUTH_WRAP(&clone_xprt->xp_auth, *xdrs,
		    xdr_results, xdr_location)))) {
			rdma_buf_free(conn, rpcreply);
			DTRACE_PROBE(
			    krpc__e__svcrdma__rpcmsg__reply__authwrap1);
			return (SVC_RDMA_FAIL);
		}
	} else {
		if (!xdr_replymsg(*xdrs, msg)) {
			rdma_buf_free(conn, rpcreply);
			DTRACE_PROBE(
			    krpc__e__svcrdma__rpcmsg__reply__authwrap2);
			return (SVC_RDMA_FAIL);
		}
	}

	*len = XDR_GETPOS(*xdrs);

	return (SVC_RDMA_SUCCESS);
}

/*
 * Send rpc reply.
 */
static bool_t
svc_rdma_ksend(SVCXPRT * clone_xprt, struct rpc_msg *msg)
{
	XDR *xdrs_rpc = &(clone_xprt->xp_xdrout);
	XDR xdrs_rhdr;
	CONN *conn = NULL;
	rdma_buf_t rbuf_resp = {0}, rbuf_rpc_resp = {0};

	struct clone_rdma_data *crdp;
	struct clist *cl_read = NULL;
	struct clist *cl_send = NULL;
	struct clist *cl_write = NULL;
	xdrproc_t xdr_results;		/* results XDR encoding function */
	caddr_t xdr_location;		/* response results pointer */

	int retval = FALSE;
	int status, msglen, num_wreply_segments = 0;
	uint32_t rdma_credit = 0;
	int freelen = 0;
	bool_t has_args;
	uint_t  final_resp_len, rdma_response_op, vers;

	bzero(&xdrs_rhdr, sizeof (XDR));
	crdp = (struct clone_rdma_data *)clone_xprt->xp_p2buf;
	conn = crdp->conn;

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
	 * Given the limit on the inline response size (RPC_MSG_SZ),
	 * there is a need to make a guess as to the overall size of
	 * the response.  If the resultant size is beyond the inline
	 * size, then the server needs to use the "reply chunk list"
	 * provided by the client (if the client provided one).  An
	 * example of this type of response would be a READDIR
	 * response (e.g. a small directory read would fit in RPC_MSG_SZ
	 * and that is the preference but it may not fit)
	 *
	 * Combine the encoded size and the size of the true results
	 * and then make the decision about where to encode and send results.
	 *
	 * One important note, this calculation is ignoring the size
	 * of the encoding of the authentication overhead.  The reason
	 * for this is rooted in the complexities of access to the
	 * encoded size of RPCSEC_GSS related authentiation,
	 * integrity, and privacy.
	 *
	 * If it turns out that the encoded authentication bumps the
	 * response over the RPC_MSG_SZ limit, then it may need to
	 * attempt to encode for the reply chunk list.
	 */

	/*
	 * Calculating the "sizeof" the RPC response header and the
	 * encoded results.
	 */
	msglen = xdr_sizeof(xdr_replymsg, msg);

	if (msglen > 0) {
		RSSTAT_INCR(rstotalreplies);
	}
	if (has_args)
		msglen += xdrrdma_sizeof(xdr_results, xdr_location,
		    rdma_minchunk, NULL, NULL);

	DTRACE_PROBE1(krpc__i__svcrdma__ksend__msglen, int, msglen);

	status = SVC_RDMA_SUCCESS;

	if (msglen < RPC_MSG_SZ) {
		/*
		 * Looks like the response will fit in the inline
		 * response; let's try
		 */
		RSSTAT_INCR(rstotalinlinereplies);

		rdma_response_op = RDMA_MSG;

		status = svc_compose_rpcmsg(clone_xprt, conn, xdr_results,
		    xdr_location, &rbuf_rpc_resp, &xdrs_rpc, msg,
		    has_args, &final_resp_len);

		DTRACE_PROBE1(krpc__i__srdma__ksend__compose_status,
		    int, status);
		DTRACE_PROBE1(krpc__i__srdma__ksend__compose_len,
		    int, final_resp_len);

		if (status == SVC_RDMA_SUCCESS && crdp->cl_reply) {
			clist_free(crdp->cl_reply);
			crdp->cl_reply = NULL;
		}
	}

	/*
	 * If the encode failed (size?) or the message really is
	 * larger than what is allowed, try the response chunk list.
	 */
	if (status != SVC_RDMA_SUCCESS || msglen >= RPC_MSG_SZ) {
		/*
		 * attempting to use a reply chunk list when there
		 * isn't one won't get very far...
		 */
		if (crdp->cl_reply == NULL) {
			DTRACE_PROBE(krpc__e__svcrdma__ksend__noreplycl);
			goto out;
		}

		RSSTAT_INCR(rstotallongreplies);

		msglen = xdr_sizeof(xdr_replymsg, msg);
		msglen += xdrrdma_sizeof(xdr_results, xdr_location, 0,
		    NULL, NULL);

		status = svc_process_long_reply(clone_xprt, xdr_results,
		    xdr_location, msg, has_args, &msglen, &freelen,
		    &num_wreply_segments, &final_resp_len);

		DTRACE_PROBE1(krpc__i__svcrdma__ksend__longreplen,
		    int, final_resp_len);

		if (status != SVC_RDMA_SUCCESS) {
			DTRACE_PROBE(krpc__e__svcrdma__ksend__compose__failed);
			goto out;
		}

		rdma_response_op = RDMA_NOMSG;
	}

	DTRACE_PROBE1(krpc__i__svcrdma__ksend__rdmamsg__len,
	    int, final_resp_len);

	rbuf_resp.type = SEND_BUFFER;
	if (rdma_buf_alloc(conn, &rbuf_resp)) {
		rdma_buf_free(conn, &rbuf_rpc_resp);
		DTRACE_PROBE(krpc__e__svcrdma__ksend__nofreebufs);
		goto out;
	}

	rdma_credit = rdma_bufs_granted;

	vers = RPCRDMA_VERS;
	xdrmem_create(&xdrs_rhdr, rbuf_resp.addr, rbuf_resp.len, XDR_ENCODE);
	(*(uint32_t *)rbuf_resp.addr) = msg->rm_xid;
	/* Skip xid and set the xdr position accordingly. */
	XDR_SETPOS(&xdrs_rhdr, sizeof (uint32_t));
	if (!xdr_u_int(&xdrs_rhdr, &vers) ||
	    !xdr_u_int(&xdrs_rhdr, &rdma_credit) ||
	    !xdr_u_int(&xdrs_rhdr, &rdma_response_op)) {
		rdma_buf_free(conn, &rbuf_rpc_resp);
		rdma_buf_free(conn, &rbuf_resp);
		DTRACE_PROBE(krpc__e__svcrdma__ksend__uint);
		goto out;
	}

	/*
	 * Now XDR the read chunk list, actually always NULL
	 */
	(void) xdr_encode_rlist_svc(&xdrs_rhdr, cl_read);

	/*
	 * encode write list -- we already drove RDMA_WRITEs
	 */
	cl_write = crdp->cl_wlist;
	if (!xdr_encode_wlist(&xdrs_rhdr, cl_write)) {
		DTRACE_PROBE(krpc__e__svcrdma__ksend__enc__wlist);
		rdma_buf_free(conn, &rbuf_rpc_resp);
		rdma_buf_free(conn, &rbuf_resp);
		goto out;
	}

	/*
	 * XDR encode the RDMA_REPLY write chunk
	 */
	if (!xdr_encode_reply_wchunk(&xdrs_rhdr, crdp->cl_reply,
	    num_wreply_segments)) {
		rdma_buf_free(conn, &rbuf_rpc_resp);
		rdma_buf_free(conn, &rbuf_resp);
		goto out;
	}

	clist_add(&cl_send, 0, XDR_GETPOS(&xdrs_rhdr), &rbuf_resp.handle,
	    rbuf_resp.addr, NULL, NULL);

	if (rdma_response_op == RDMA_MSG) {
		clist_add(&cl_send, 0, final_resp_len, &rbuf_rpc_resp.handle,
		    rbuf_rpc_resp.addr, NULL, NULL);
	}

	status = RDMA_SEND(conn, cl_send, msg->rm_xid);

	if (status == RDMA_SUCCESS) {
		retval = TRUE;
	}

out:
	/*
	 * Free up sendlist chunks
	 */
	if (cl_send != NULL)
		clist_free(cl_send);

	/*
	 * Destroy private data for xdr rdma
	 */
	if (clone_xprt->xp_xdrout.x_ops != NULL) {
		XDR_DESTROY(&(clone_xprt->xp_xdrout));
	}

	if (crdp->cl_reply) {
		clist_free(crdp->cl_reply);
		crdp->cl_reply = NULL;
	}

	/*
	 * This is completely disgusting.  If public is set it is
	 * a pointer to a structure whose first field is the address
	 * of the function to free that structure and any related
	 * stuff.  (see rrokfree in nfs_xdr.c).
	 */
	if (xdrs_rpc->x_public) {
		/* LINTED pointer alignment */
		(**((int (**)()) xdrs_rpc->x_public)) (xdrs_rpc->x_public);
	}

	if (xdrs_rhdr.x_ops != NULL) {
		XDR_DESTROY(&xdrs_rhdr);
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
	struct clone_rdma_data *crdp;
	bool_t retval;

	/*
	 * If the cloned bit is true, then this transport specific
	 * rmda data has been duplicated into another cloned xprt. Do
	 * not free, or release the connection, it is still in use.  The
	 * buffers will be freed and the connection released later by
	 * SVC_CLONE_DESTROY().
	 */
	crdp = (struct clone_rdma_data *)clone_xprt->xp_p2buf;
	if (crdp->cloned == TRUE) {
		crdp->cloned = 0;
		return (TRUE);
	}

	/*
	 * Free the args if needed then XDR_DESTROY
	 */
	if (args_ptr) {
		XDR	*xdrs = &clone_xprt->xp_xdrin;

		xdrs->x_op = XDR_FREE;
		retval = (*xdr_args)(xdrs, args_ptr);
	}

	XDR_DESTROY(&(clone_xprt->xp_xdrin));
	rdma_buf_free(crdp->conn, &crdp->rpcbuf);
	if (crdp->cl_reply) {
		clist_free(crdp->cl_reply);
		crdp->cl_reply = NULL;
	}
	RDMA_REL_CONN(crdp->conn);

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
int	rdmamaxdupreqs = MAXDUPREQS;
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

bool_t
rdma_get_wchunk(struct svc_req *req, iovec_t *iov, struct clist *wlist)
{
	struct clist	*clist;
	uint32_t	tlen;

	if (req->rq_xprt->xp_type != T_RDMA) {
		return (FALSE);
	}

	tlen = 0;
	clist = wlist;
	while (clist) {
		tlen += clist->c_len;
		clist = clist->c_next;
	}

	/*
	 * set iov to addr+len of first segment of first wchunk of
	 * wlist sent by client.  krecv() already malloc'd a buffer
	 * large enough, but registration is deferred until we write
	 * the buffer back to (NFS) client using RDMA_WRITE.
	 */
	iov->iov_base = (caddr_t)(uintptr_t)wlist->w.c_saddr;
	iov->iov_len = tlen;

	return (TRUE);
}

/*
 * routine to setup the read chunk lists
 */

int
rdma_setup_read_chunks(struct clist *wcl, uint32_t count, int *wcl_len)
{
	int		data_len, avail_len;
	uint_t		round_len;

	data_len = avail_len = 0;

	while (wcl != NULL && count > 0) {
		if (wcl->c_dmemhandle.mrc_rmr == 0)
			break;

		if (wcl->c_len < count) {
			data_len += wcl->c_len;
			avail_len = 0;
		} else {
			data_len += count;
			avail_len = wcl->c_len - count;
			wcl->c_len = count;
		}
		count -= wcl->c_len;

		if (count == 0)
			break;

		wcl = wcl->c_next;
	}

	/*
	 * MUST fail if there are still more data
	 */
	if (count > 0) {
		DTRACE_PROBE2(krpc__e__rdma_setup_read_chunks_clist_len,
		    int, data_len, int, count);
		return (FALSE);
	}

	/*
	 * Round up the last chunk to 4-byte boundary
	 */
	*wcl_len = roundup(data_len, BYTES_PER_XDR_UNIT);
	round_len = *wcl_len - data_len;

	if (round_len) {

		/*
		 * If there is space in the current chunk,
		 * add the roundup to the chunk.
		 */
		if (avail_len >= round_len) {
			wcl->c_len += round_len;
		} else  {
			/*
			 * try the next one.
			 */
			wcl = wcl->c_next;
			if ((wcl == NULL) || (wcl->c_len < round_len)) {
				DTRACE_PROBE1(
				    krpc__e__rdma_setup_read_chunks_rndup,
				    int, round_len);
				return (FALSE);
			}
			wcl->c_len = round_len;
		}
	}

	wcl = wcl->c_next;

	/*
	 * Make rest of the chunks 0-len
	 */

	clist_zero_len(wcl);

	return (TRUE);
}
