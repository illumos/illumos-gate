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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
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

#include <sys/param.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/systm.h>
#include <sys/kstat.h>
#include <sys/t_lock.h>
#include <sys/ddi.h>
#include <sys/cmn_err.h>
#include <sys/time.h>
#include <sys/isa_defs.h>
#include <sys/zone.h>

#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>
#include <rpc/rpc_msg.h>
#include <rpc/rpc_rdma.h>


static enum clnt_stat clnt_rdma_kcallit(CLIENT *, rpcproc_t, xdrproc_t,
    caddr_t, xdrproc_t, caddr_t, struct timeval);
static void	clnt_rdma_kabort(CLIENT *);
static void	clnt_rdma_kerror(CLIENT *, struct rpc_err *);
static bool_t	clnt_rdma_kfreeres(CLIENT *, xdrproc_t, caddr_t);
static void	clnt_rdma_kdestroy(CLIENT *);
static bool_t	clnt_rdma_kcontrol(CLIENT *, int, char *);
static int	clnt_rdma_ksettimers(CLIENT *, struct rpc_timers *,
    struct rpc_timers *, int, void(*)(int, int, caddr_t), caddr_t, uint32_t);

/*
 * Operations vector for RDMA based RPC
 */
static struct clnt_ops rdma_clnt_ops = {
	clnt_rdma_kcallit,	/* do rpc call */
	clnt_rdma_kabort,	/* abort call */
	clnt_rdma_kerror,	/* return error status */
	clnt_rdma_kfreeres,	/* free results */
	clnt_rdma_kdestroy,	/* destroy rpc handle */
	clnt_rdma_kcontrol,	/* the ioctl() of rpc */
	clnt_rdma_ksettimers,	/* set retry timers */
};

/*
 * The size of the preserialized RPC header information.
 */
#define	CKU_HDRSIZE	20

/*
 * Per RPC RDMA endpoint details
 */
typedef struct cku_private {
	CLIENT			cku_client;	/* client handle */
	rdma_mod_t		*cku_rd_mod;	/* underlying RDMA mod */
	void			*cku_rd_handle;	/* underlying RDMA device */
	struct netbuf		cku_addr;	/* remote netbuf address */
	int			cku_addrfmly;	/* for finding addr_type */
	struct rpc_err		cku_err;	/* error status */
	struct cred		*cku_cred;	/* credentials */
	XDR			cku_outxdr;	/* xdr stream for output */
	uint32_t		cku_outsz;
	XDR			cku_inxdr;	/* xdr stream for input */
	char			cku_rpchdr[CKU_HDRSIZE+4]; /* rpc header */
	uint32_t		cku_xid;	/* current XID */
} cku_private_t;

#define	CLNT_RDMA_DELAY	10	/* secs to delay after a connection failure */
static int clnt_rdma_min_delay = CLNT_RDMA_DELAY;

struct {
	kstat_named_t	rccalls;
	kstat_named_t	rcbadcalls;
	kstat_named_t	rcbadxids;
	kstat_named_t	rctimeouts;
	kstat_named_t	rcnewcreds;
	kstat_named_t	rcbadverfs;
	kstat_named_t	rctimers;
	kstat_named_t	rccantconn;
	kstat_named_t	rcnomem;
	kstat_named_t	rcintrs;
	kstat_named_t	rclongrpcs;
} rdmarcstat = {
	{ "calls",	KSTAT_DATA_UINT64 },
	{ "badcalls",	KSTAT_DATA_UINT64 },
	{ "badxids",	KSTAT_DATA_UINT64 },
	{ "timeouts",	KSTAT_DATA_UINT64 },
	{ "newcreds",	KSTAT_DATA_UINT64 },
	{ "badverfs",	KSTAT_DATA_UINT64 },
	{ "timers",	KSTAT_DATA_UINT64 },
	{ "cantconn",	KSTAT_DATA_UINT64 },
	{ "nomem",	KSTAT_DATA_UINT64 },
	{ "interrupts", KSTAT_DATA_UINT64 },
	{ "longrpc", 	KSTAT_DATA_UINT64 }
};

kstat_named_t *rdmarcstat_ptr = (kstat_named_t *)&rdmarcstat;
uint_t rdmarcstat_ndata = sizeof (rdmarcstat) / sizeof (kstat_named_t);

#ifdef DEBUG
int rdma_clnt_debug = 0;
#endif

#ifdef accurate_stats
extern kmutex_t rdmarcstat_lock;    /* mutex for rcstat updates */

#define	RCSTAT_INCR(x)			\
	mutex_enter(&rdmarcstat_lock);	\
	rdmarcstat.x.value.ui64++;	\
	mutex_exit(&rdmarcstat_lock);
#else
#define	RCSTAT_INCR(x)			\
	rdmarcstat.x.value.ui64++;
#endif

#define	ptoh(p)		(&((p)->cku_client))
#define	htop(h)		((cku_private_t *)((h)->cl_private))

int
clnt_rdma_kcreate(char *proto, void *handle, struct netbuf *raddr, int family,
    rpcprog_t pgm, rpcvers_t vers, struct cred *cred, CLIENT **cl)
{
	CLIENT *h;
	struct cku_private *p;
	struct rpc_msg call_msg;
	rdma_registry_t *rp;

	ASSERT(INGLOBALZONE(curproc));

	if (cl == NULL)
		return (EINVAL);
	*cl = NULL;

	p = kmem_zalloc(sizeof (*p), KM_SLEEP);

	/*
	 * Find underlying RDMATF plugin
	 */
	rw_enter(&rdma_lock, RW_READER);
	rp = rdma_mod_head;
	while (rp != NULL) {
		if (strcmp(rp->r_mod->rdma_api, proto))
			rp = rp->r_next;
		else {
			p->cku_rd_mod = rp->r_mod;
			p->cku_rd_handle = handle;
			break;
		}
	}
	rw_exit(&rdma_lock);

	if (p->cku_rd_mod == NULL) {
		/*
		 * Should not happen.
		 * No matching RDMATF plugin.
		 */
		kmem_free(p, sizeof (struct cku_private));
		return (EINVAL);
	}

	h = ptoh(p);
	h->cl_ops = &rdma_clnt_ops;
	h->cl_private = (caddr_t)p;
	h->cl_auth = authkern_create();

	/* call message, just used to pre-serialize below */
	call_msg.rm_xid = 0;
	call_msg.rm_direction = CALL;
	call_msg.rm_call.cb_rpcvers = RPC_MSG_VERSION;
	call_msg.rm_call.cb_prog = pgm;
	call_msg.rm_call.cb_vers = vers;

	xdrmem_create(&p->cku_outxdr, p->cku_rpchdr, CKU_HDRSIZE, XDR_ENCODE);
	/* pre-serialize call message header */
	if (!xdr_callhdr(&p->cku_outxdr, &call_msg)) {
		XDR_DESTROY(&p->cku_outxdr);
		auth_destroy(h->cl_auth);
		kmem_free(p, sizeof (struct cku_private));
		return (EINVAL);
	}

	/*
	 * Set up the rpc information
	 */
	p->cku_cred = cred;
	p->cku_addr.buf = kmem_zalloc(raddr->maxlen, KM_SLEEP);
	p->cku_addr.maxlen = raddr->maxlen;
	p->cku_addr.len = raddr->len;
	bcopy(raddr->buf, p->cku_addr.buf, raddr->len);
	p->cku_addrfmly = family;

	*cl = h;
	return (0);
}

static void
clnt_rdma_kdestroy(CLIENT *h)
{
	struct cku_private *p = htop(h);

	kmem_free(p->cku_addr.buf, p->cku_addr.maxlen);
	kmem_free(p, sizeof (*p));
}

void
clnt_rdma_kinit(CLIENT *h, char *proto, void *handle, struct netbuf *raddr,
    struct cred *cred)
{
	struct cku_private *p = htop(h);
	rdma_registry_t *rp;

	ASSERT(INGLOBALZONE(curproc));
	/*
	 * Find underlying RDMATF plugin
	 */
	p->cku_rd_mod = NULL;
	rw_enter(&rdma_lock, RW_READER);
	rp = rdma_mod_head;
	while (rp != NULL) {
		if (strcmp(rp->r_mod->rdma_api, proto))
			rp = rp->r_next;
		else {
			p->cku_rd_mod = rp->r_mod;
			p->cku_rd_handle = handle;
			break;
		}

	}
	rw_exit(&rdma_lock);

	/*
	 * Set up the rpc information
	 */
	p->cku_cred = cred;
	p->cku_xid = 0;

	if (p->cku_addr.maxlen < raddr->len) {
		if (p->cku_addr.maxlen != 0 && p->cku_addr.buf != NULL)
			kmem_free(p->cku_addr.buf, p->cku_addr.maxlen);
		p->cku_addr.buf = kmem_zalloc(raddr->maxlen, KM_SLEEP);
		p->cku_addr.maxlen = raddr->maxlen;
	}

	p->cku_addr.len = raddr->len;
	bcopy(raddr->buf, p->cku_addr.buf, raddr->len);
	h->cl_ops = &rdma_clnt_ops;
}

/* ARGSUSED */
static enum clnt_stat
clnt_rdma_kcallit(CLIENT *h, rpcproc_t procnum, xdrproc_t xdr_args,
    caddr_t argsp, xdrproc_t xdr_results, caddr_t resultsp, struct timeval wait)
{
	cku_private_t *p = htop(h);
	int 	status;
	XDR 	*xdrs;
	XDR	*cxdrp = NULL, callxdr;	/* for xdrrdma encoding the RPC call */
	XDR	*rxdrp = NULL, replxdr;	/* for xdrrdma decoding the RPC reply */
	struct rpc_msg 	reply_msg;
	struct clist *sendlist, *recvlist = NULL;
	struct clist *cl = NULL, *cle = NULL;
	uint_t vers, op;
	uint_t off;
	uint32_t xid;
	CONN *conn = NULL;
	rdma_buf_t clmsg, rpcmsg, longmsg, rpcreply;
	int msglen;
	clock_t	ticks;

	RCSTAT_INCR(rccalls);
	/*
	 * Get unique xid
	 */
	if (p->cku_xid == 0)
		p->cku_xid = alloc_xid();

	status = RDMA_GET_CONN(p->cku_rd_mod->rdma_ops, &p->cku_addr,
	    p->cku_addrfmly, p->cku_rd_handle, &conn);

	if (conn == NULL) {
		/*
		 * Connect failed to server. Could be because of one
		 * of several things. In some cases we don't want
		 * the caller to retry immediately - delay before
		 * returning to caller.
		 */
		switch (status) {
		case RDMA_TIMEDOUT:
			/*
			 * Already timed out. No need to delay
			 * some more.
			 */
			p->cku_err.re_status = RPC_TIMEDOUT;
			p->cku_err.re_errno = ETIMEDOUT;
			break;
		case RDMA_INTR:
			/*
			 * Failed because of an signal. Very likely
			 * the caller will not retry.
			 */
			p->cku_err.re_status = RPC_INTR;
			p->cku_err.re_errno = EINTR;
			break;
		default:
			/*
			 * All other failures - server down or service
			 * down or temporary resource failure. Delay before
			 * returning to caller.
			 */
			ticks = clnt_rdma_min_delay * drv_usectohz(1000000);
			p->cku_err.re_status = RPC_CANTCONNECT;
			p->cku_err.re_errno = EIO;

			if (h->cl_nosignal == TRUE) {
				delay(ticks);
			} else {
				if (delay_sig(ticks) == EINTR) {
					p->cku_err.re_status = RPC_INTR;
					p->cku_err.re_errno = EINTR;
				}
			}
			break;
		}

		return (p->cku_err.re_status);
	}
	/*
	 * Get the size of the rpc call message. Need this
	 * to determine if the rpc call message will fit in
	 * the pre-allocated RDMA buffers. If the rpc call
	 * message length is greater that the pre-allocated
	 * buffers then, it is a Long RPC. A one time use
	 * buffer is allocated and registered for the Long
	 * RPC call.
	 */
	xdrs = &callxdr;
	msglen = CKU_HDRSIZE + BYTES_PER_XDR_UNIT;
	if (h->cl_auth->ah_cred.oa_flavor != RPCSEC_GSS) {
		msglen += xdrrdma_authsize(h->cl_auth, p->cku_cred,
				rdma_minchunk);
		msglen += xdrrdma_sizeof(xdr_args, argsp, rdma_minchunk);

		if (msglen > RPC_MSG_SZ) {

			/*
			 * Long RPC. Allocate one time use custom buffer.
			 */
			rpcmsg.type = CHUNK_BUFFER;
			rpcmsg.addr = kmem_zalloc(msglen, KM_SLEEP);
			cle = kmem_zalloc(sizeof (*cle), KM_SLEEP);
			cle->c_xdroff = 0;
			cle->c_len  = rpcmsg.len = msglen;
			cle->c_saddr = (uint64)(uintptr_t)rpcmsg.addr;
			cle->c_next = NULL;
			xdrrdma_create(xdrs, rpcmsg.addr, msglen,
			    rdma_minchunk, cle, XDR_ENCODE, NULL);
			cxdrp = xdrs;
			op = RDMA_NOMSG;
		} else {
			/*
			 * Get a pre-allocated buffer for rpc call
			 */
			rpcmsg.type = SEND_BUFFER;
			if (RDMA_BUF_ALLOC(conn, &rpcmsg)) {
				p->cku_err.re_status = RPC_CANTSEND;
				p->cku_err.re_errno = EIO;
				RCSTAT_INCR(rcnomem);
				cmn_err(CE_WARN,
				    "clnt_rdma_kcallit: no buffers!");
				goto done;
			}
			xdrrdma_create(xdrs, rpcmsg.addr, rpcmsg.len,
			    rdma_minchunk, NULL, XDR_ENCODE, NULL);
			cxdrp = xdrs;
			op = RDMA_MSG;
		}
	} else {
		/*
		 * For RPCSEC_GSS since we cannot accurately presize the
		 * buffer required for encoding, we assume that its going
		 * to be a Long RPC to start with. We also create the
		 * the XDR stream with min_chunk set to 0 which instructs
		 * the XDR layer to not chunk the incoming byte stream.
		 */

		msglen += 2 * MAX_AUTH_BYTES + 2 * sizeof (struct opaque_auth);
		msglen += xdr_sizeof(xdr_args, argsp);

		/*
		 * Long RPC. Allocate one time use custom buffer.
		 */
		longmsg.type = CHUNK_BUFFER;
		longmsg.addr = kmem_zalloc(msglen, KM_SLEEP);
		cle = kmem_zalloc(sizeof (*cle), KM_SLEEP);
		cle->c_xdroff = 0;
		cle->c_len  = longmsg.len = msglen;
		cle->c_saddr = (uint64)(uintptr_t)longmsg.addr;
		cle->c_next = NULL;
		xdrrdma_create(xdrs, longmsg.addr, msglen, 0, cle,
		    XDR_ENCODE, NULL);
		cxdrp = xdrs;
		op = RDMA_NOMSG;
	}

	if (h->cl_auth->ah_cred.oa_flavor != RPCSEC_GSS) {
		/*
		 * Copy in the preserialized RPC header
		 * information.
		 */
		bcopy(p->cku_rpchdr, rpcmsg.addr, CKU_HDRSIZE);

		/*
		 * transaction id is the 1st thing in the output
		 * buffer.
		 */
		/* LINTED pointer alignment */
		(*(uint32_t *)(rpcmsg.addr)) = p->cku_xid;

		/* Skip the preserialized stuff. */
		XDR_SETPOS(xdrs, CKU_HDRSIZE);

		/* Serialize dynamic stuff into the output buffer. */
		if ((!XDR_PUTINT32(xdrs, (int32_t *)&procnum)) ||
		    (!AUTH_MARSHALL(h->cl_auth, xdrs, p->cku_cred)) ||
		    (!(*xdr_args)(xdrs, argsp))) {
			rdma_buf_free(conn, &rpcmsg);
			if (cle)
				clist_free(cle);
			p->cku_err.re_status = RPC_CANTENCODEARGS;
			p->cku_err.re_errno = EIO;
			cmn_err(CE_WARN,
	"clnt_rdma_kcallit: XDR_PUTINT32/AUTH_MARSHAL/xdr_args failed");
			goto done;
		}
		p->cku_outsz = XDR_GETPOS(xdrs);
	} else {
		uint32_t *uproc = (uint32_t *)&p->cku_rpchdr[CKU_HDRSIZE];
		IXDR_PUT_U_INT32(uproc, procnum);
		(*(uint32_t *)(&p->cku_rpchdr[0])) = p->cku_xid;
		XDR_SETPOS(xdrs, 0);

		/* Serialize the procedure number and the arguments. */
		if (!AUTH_WRAP(h->cl_auth, (caddr_t)p->cku_rpchdr,
		    CKU_HDRSIZE+4, xdrs, xdr_args, argsp)) {
			if (longmsg.addr != xdrs->x_base) {
				longmsg.addr = xdrs->x_base;
				longmsg.len = xdr_getbufsize(xdrs);
			}
			rdma_buf_free(conn, &longmsg);
			clist_free(cle);
			p->cku_err.re_status = RPC_CANTENCODEARGS;
			p->cku_err.re_errno = EIO;
			cmn_err(CE_WARN,
		"clnt_rdma_kcallit: AUTH_WRAP failed");
			goto done;
		}
		/*
		 * If we had to allocate a new buffer while encoding
		 * then update the addr and len.
		 */
		if (longmsg.addr != xdrs->x_base) {
			longmsg.addr = xdrs->x_base;
			longmsg.len = xdr_getbufsize(xdrs);
		}

		/*
		 * If it so happens that the encoded message is after all
		 * not long enough to be a Long RPC then allocate a
		 * SEND_BUFFER and copy the encoded message into it.
		 */
		p->cku_outsz = XDR_GETPOS(xdrs);
		if (p->cku_outsz > RPC_MSG_SZ) {
			rpcmsg.type = CHUNK_BUFFER;
			rpcmsg.addr = longmsg.addr;
			rpcmsg.len = longmsg.len;
		} else {
			clist_free(cle);
			XDR_DESTROY(cxdrp);
			cxdrp = NULL;
			/*
			 * Get a pre-allocated buffer for rpc call
			 */
			rpcmsg.type = SEND_BUFFER;
			if (RDMA_BUF_ALLOC(conn, &rpcmsg)) {
				p->cku_err.re_status = RPC_CANTSEND;
				p->cku_err.re_errno = EIO;
				RCSTAT_INCR(rcnomem);
				cmn_err(CE_WARN,
				    "clnt_rdma_kcallit: no buffers!");
				rdma_buf_free(conn, &longmsg);
				goto done;
			}
			bcopy(longmsg.addr, rpcmsg.addr, p->cku_outsz);
			xdrrdma_create(xdrs, rpcmsg.addr, p->cku_outsz, 0,
			    NULL, XDR_ENCODE, NULL);
			cxdrp = xdrs;
			rdma_buf_free(conn, &longmsg);
			op = RDMA_MSG;
		}
	}

	cl = xdrrdma_clist(xdrs);

	/*
	 * Update the chunk size information for the Long RPC msg.
	 */
	if (cl && op == RDMA_NOMSG)
		cl->c_len = p->cku_outsz;

	/*
	 * Set up the RDMA chunk message
	 */
	vers = RPCRDMA_VERS;
	clmsg.type = SEND_BUFFER;
	if (RDMA_BUF_ALLOC(conn, &clmsg)) {
		p->cku_err.re_status = RPC_CANTSEND;
		p->cku_err.re_errno = EIO;
		rdma_buf_free(conn, &rpcmsg);
		RCSTAT_INCR(rcnomem);
		cmn_err(CE_WARN, "clnt_rdma_kcallit: no free buffers!!");
		goto done;
	}
	xdrs = &p->cku_outxdr;
	xdrmem_create(xdrs, clmsg.addr, clmsg.len, XDR_ENCODE);
	/*
	 * Treat xid as opaque (xid is the first entity
	 * in the rpc rdma message).
	 */
	(*(uint32_t *)clmsg.addr) = p->cku_xid;
	/* Skip xid and set the xdr position accordingly. */
	XDR_SETPOS(xdrs, sizeof (uint32_t));
	(void) xdr_u_int(xdrs, &vers);
	(void) xdr_u_int(xdrs, &op);

	/*
	 * Now XDR the chunk list
	 */
	if (cl != NULL) {

		/*
		 * Register the chunks in the list
		 */
		status = clist_register(conn, cl, 1);
		if (status != RDMA_SUCCESS) {
			cmn_err(CE_WARN,
		"clnt_rdma_kcallit: clist register failed");
			rdma_buf_free(conn, &clmsg);
			rdma_buf_free(conn, &rpcmsg);
			clist_free(cl);
			p->cku_err.re_status = RPC_CANTSEND;
			p->cku_err.re_errno = EIO;
			goto done;
		}

	}
	(void) xdr_do_clist(xdrs, &cl);

	/*
	 * Start with the RDMA header and clist (if any)
	 */
	sendlist = NULL;
	clist_add(&sendlist, 0, XDR_GETPOS(xdrs), &clmsg.handle,
		clmsg.addr, NULL, NULL);

	/*
	 * Put the RPC call message in the send list if small RPC
	 */
	if (op == RDMA_MSG) {
		clist_add(&sendlist, 0, p->cku_outsz, &rpcmsg.handle,
			rpcmsg.addr, NULL, NULL);
	} else {
		/* Long RPC already in chunk list */
		RCSTAT_INCR(rclongrpcs);
	}

	/*
	 * Set up a reply buffer ready for the reply
	 */
	status = rdma_clnt_postrecv(conn, p->cku_xid);
	if (status != RDMA_SUCCESS) {
		rdma_buf_free(conn, &clmsg);
		rdma_buf_free(conn, &rpcmsg);
		if (cl) {
			(void) clist_deregister(conn, cl, 1);
			clist_free(cl);
		}
		clist_free(sendlist);
		p->cku_err.re_status = RPC_CANTSEND;
		p->cku_err.re_errno = EIO;
		goto done;
	}
	/*
	 * sync the memory for dma
	 */
	if (cl != NULL) {
		status = clist_syncmem(conn, cl, 1);
		if (status != RDMA_SUCCESS) {
			rdma_buf_free(conn, &clmsg);
			rdma_buf_free(conn, &rpcmsg);
			(void) clist_deregister(conn, cl, 1);
			clist_free(cl);
			clist_free(sendlist);
			p->cku_err.re_status = RPC_CANTSEND;
			p->cku_err.re_errno = EIO;
			goto done;
		}
	}

	/*
	 * Send the call message to the server
	 */
	status = RDMA_SEND(conn, sendlist, p->cku_xid);
	if (status != RDMA_SUCCESS) {
		if (cl) {
			(void) clist_deregister(conn, cl, 1);
			clist_free(cl);
			/*
			 * If this was a long RPC message, need
			 * to free that buffer.
			 */
			if (rpcmsg.type == CHUNK_BUFFER)
				rdma_buf_free(conn, &rpcmsg);
		}
		clist_free(sendlist);
		p->cku_err.re_status = RPC_CANTSEND;
		p->cku_err.re_errno = EIO;
		goto done;
	} else {
		/*
		 * RDMA plugin now owns the send msg buffers.
		 * Clear them out and don't free them here.
		 */
		clmsg.addr = NULL;
		if (rpcmsg.type == SEND_BUFFER)
			rpcmsg.addr = NULL;
	}
	clist_free(sendlist);
#ifdef DEBUG
if (rdma_clnt_debug) {
		printf("clnt_rdma_kcallit: send request xid %u\n", p->cku_xid);
	}
#endif

	/*
	 * Recv rpc reply
	 */
	status = RDMA_RECV(conn, &recvlist, p->cku_xid);

	/*
	 * Deregister chunks sent. Do this only after the reply
	 * is received as that is a sure indication that the
	 * remote end has completed RDMA of the chunks.
	 */
	if (cl != NULL) {
		/*
		 * Deregister the chunks
		 */
		(void) clist_deregister(conn, cl, 1);
		clist_free(cl);
		/*
		 * If long RPC free chunk
		 */
		rdma_buf_free(conn, &rpcmsg);
	}

	/*
	 * Now check recv status
	 */
	if (status != 0) {
#ifdef DEBUG
		if (rdma_clnt_debug)
			cmn_err(CE_NOTE,
			    "clnt_rdma_kcallit: reply failed %u status %d",
			    p->cku_xid, status);
#endif
		if (status == RDMA_INTR) {
			p->cku_err.re_status = RPC_INTR;
			p->cku_err.re_errno = EINTR;
			RCSTAT_INCR(rcintrs);
		} else if (status == RPC_TIMEDOUT) {
			p->cku_err.re_status = RPC_TIMEDOUT;
			p->cku_err.re_errno = ETIMEDOUT;
			RCSTAT_INCR(rctimeouts);
		} else {
			p->cku_err.re_status = RPC_CANTRECV;
			p->cku_err.re_errno = EIO;
		}
		goto done;
	}
#ifdef DEBUG
	if (rdma_clnt_debug)
		printf("clnt_rdma_kcallit: got response xid %u\n", p->cku_xid);
#endif
	/*
	 * Process the reply message.
	 *
	 * First the chunk list (if any)
	 */
	xdrs = &(p->cku_inxdr);
	xdrmem_create(xdrs, (caddr_t)(uintptr_t)recvlist->c_saddr,
	    recvlist->c_len, XDR_DECODE);
	/*
	 * Treat xid as opaque (xid is the first entity
	 * in the rpc rdma message).
	 */
	xid = *(uint32_t *)(uintptr_t)recvlist->c_saddr;
	/* Skip xid and set the xdr position accordingly. */
	XDR_SETPOS(xdrs, sizeof (uint32_t));
	(void) xdr_u_int(xdrs, &vers);
	(void) xdr_u_int(xdrs, &op);
	(void) xdr_do_clist(xdrs, &cl);
	off = xdr_getpos(xdrs);

	/*
	 * Now the RPC reply message itself. If the reply
	 * came as a chunk item, then RDMA the reply over.
	 */
	xdrs = &replxdr;
	if (cl && op == RDMA_NOMSG) {
		struct clist		*cle = cl;

		rpcreply.type = CHUNK_BUFFER;
		rpcreply.addr = kmem_alloc(cle->c_len, KM_SLEEP);
		rpcreply.len = cle->c_len;
		cle->c_daddr = (uint64)(uintptr_t)rpcreply.addr;
		cl = cl->c_next;
		cle->c_next = NULL;

		/*
		 * Register the rpc reply chunk destination
		 */
		status = clist_register(conn, cle, 0);
		if (status) {
			rdma_buf_free(conn, &rpcreply);
			clist_free(cle);
			p->cku_err.re_status = RPC_CANTDECODERES;
			p->cku_err.re_errno = EIO;
			cmn_err(CE_WARN,
			    "clnt_rdma_kcallit: clist_register failed");
			goto rdma_done;
		}

		/*
		 * Now read rpc reply in
		 */
#ifdef DEBUG
	if (rdma_clnt_debug)
		printf("clnt_rdma_kcallit: read chunk, len %d, xid %u, \
			reply xid %u\n", cle->c_len, p->cku_xid, xid);
#endif
		status = RDMA_READ(conn, cle, WAIT);
		if (status) {
			(void) clist_deregister(conn, cle, 0);
			rdma_buf_free(conn, &rpcreply);
			clist_free(cle);
			p->cku_err.re_status = RPC_CANTDECODERES;
			p->cku_err.re_errno = EIO;
			cmn_err(CE_WARN,
				"clnt_rdma_kcallit: RDMA_READ failed");
			goto rdma_done;
		}

		/*
		 * sync the memory for dma
		 */
		status = clist_syncmem(conn, cle, 0);
		if (status != RDMA_SUCCESS) {
			(void) clist_deregister(conn, cle, 0);
			rdma_buf_free(conn, &rpcreply);
			clist_free(cle);
			p->cku_err.re_status = RPC_CANTDECODERES;
			p->cku_err.re_errno = EIO;
			goto rdma_done;
		}

		/*
		 * Deregister the Long RPC chunk
		 */
		(void) clist_deregister(conn, cle, 0);
		clist_free(cle);
		xdrrdma_create(xdrs, rpcreply.addr, rpcreply.len, 0, cl,
			XDR_DECODE, conn);
		rxdrp = xdrs;
	} else {
		rpcreply.addr = NULL;
		xdrrdma_create(xdrs,
		    (caddr_t)(uintptr_t)(recvlist->c_saddr + off),
		    recvlist->c_len - off, 0, cl, XDR_DECODE, conn);
		rxdrp = xdrs;
	}

	reply_msg.rm_direction = REPLY;
	reply_msg.rm_reply.rp_stat = MSG_ACCEPTED;
	reply_msg.acpted_rply.ar_stat = SUCCESS;
	reply_msg.acpted_rply.ar_verf = _null_auth;
	/*
	 *  xdr_results will be done in AUTH_UNWRAP.
	 */
	reply_msg.acpted_rply.ar_results.where = NULL;
	reply_msg.acpted_rply.ar_results.proc = xdr_void;

	/*
	 * Decode and validate the response.
	 */
	if (xdr_replymsg(xdrs, &reply_msg)) {
		enum clnt_stat re_status;

		_seterr_reply(&reply_msg, &(p->cku_err));

		re_status = p->cku_err.re_status;
		if (re_status == RPC_SUCCESS) {
			/*
			 * Reply is good, check auth.
			 */
			if (!AUTH_VALIDATE(h->cl_auth,
			    &reply_msg.acpted_rply.ar_verf)) {
				p->cku_err.re_status = RPC_AUTHERROR;
				p->cku_err.re_why = AUTH_INVALIDRESP;
				RCSTAT_INCR(rcbadverfs);
				cmn_err(CE_WARN,
			    "clnt_rdma_kcallit: AUTH_VALIDATE failed");
			} else if (!AUTH_UNWRAP(h->cl_auth, xdrs,
			    xdr_results, resultsp)) {
				p->cku_err.re_status = RPC_CANTDECODERES;
				p->cku_err.re_errno = EIO;
				cmn_err(CE_WARN,
				    "clnt_rdma_kcallit: AUTH_UNWRAP failed");
			}
		} else {
			/* set errno in case we can't recover */
			if (re_status != RPC_VERSMISMATCH &&
			    re_status != RPC_AUTHERROR &&
			    re_status != RPC_PROGVERSMISMATCH)
				p->cku_err.re_errno = EIO;

			if (re_status == RPC_AUTHERROR) {
				/*
				 * Map recoverable and unrecoverable
				 * authentication errors to appropriate
				 * errno
				 */
				switch (p->cku_err.re_why) {
				case AUTH_BADCRED:
				case AUTH_BADVERF:
				case AUTH_INVALIDRESP:
				case AUTH_TOOWEAK:
				case AUTH_FAILED:
				case RPCSEC_GSS_NOCRED:
				case RPCSEC_GSS_FAILED:
					p->cku_err.re_errno = EACCES;
					break;
				case AUTH_REJECTEDCRED:
				case AUTH_REJECTEDVERF:
				default:
					p->cku_err.re_errno = EIO;
					break;
				}
				RPCLOG(1, "clnt_rdma_kcallit : "
				    "authentication failed with "
				    "RPC_AUTHERROR of type %d\n",
				    p->cku_err.re_why);
			}
			cmn_err(CE_WARN,
				    "clnt_rdma_kcallit: RPC failed");

		}
	} else {
		p->cku_err.re_status = RPC_CANTDECODERES;
		p->cku_err.re_errno = EIO;
		cmn_err(CE_WARN, "clnt_rdma_kcallit: xdr_replymsg failed");
	}

	/*
	 * If rpc reply is in a chunk, free it now.
	 */
	if (rpcreply.addr != NULL)
		rdma_buf_free(conn, &rpcreply);

rdma_done:
	if ((cl != NULL) || (op == RDMA_NOMSG)) {
		rdma_buf_t	donemsg;

		/*
		 * Free the list holding the chunk info
		 */
		if (cl) {
			clist_free(cl);
			cl = NULL;
		}

		/*
		 * Tell the server that the reads are done
		 */
		donemsg.type = SEND_BUFFER;
		if (RDMA_BUF_ALLOC(conn, &donemsg)) {
			p->cku_err.re_status = RPC_CANTSEND;
			p->cku_err.re_errno = EIO;
			RCSTAT_INCR(rcnomem);
			cmn_err(CE_WARN, "clnt_rdma_kcallit: no free buffer");
			goto done;
		}
		xdrs = &p->cku_outxdr;
		xdrmem_create(xdrs, donemsg.addr, donemsg.len, XDR_ENCODE);
		vers = RPCRDMA_VERS;
		op = RDMA_DONE;

		/*
		 * Treat xid as opaque (xid is the first entity
		 * in the rpc rdma message).
		 */
		(*(uint32_t *)donemsg.addr) = p->cku_xid;
		/* Skip xid and set the xdr position accordingly. */
		XDR_SETPOS(xdrs, sizeof (uint32_t));
		if (!xdr_u_int(xdrs, &vers) ||
		    !xdr_u_int(xdrs, &op)) {
			cmn_err(CE_WARN,
				"clnt_rdma_kcallit: xdr_u_int failed");
			rdma_buf_free(conn, &donemsg);
			goto done;
		}

		sendlist = NULL;
		clist_add(&sendlist, 0, XDR_GETPOS(xdrs), &donemsg.handle,
			donemsg.addr, NULL, NULL);

		status = RDMA_SEND(conn, sendlist, p->cku_xid);
		if (status != RDMA_SUCCESS) {
			cmn_err(CE_WARN,
				"clnt_rdma_kcallit: RDMA_SEND failed xid %u",
					p->cku_xid);
		}
#ifdef DEBUG
		else {
		if (rdma_clnt_debug)
			printf("clnt_rdma_kcallit: sent RDMA_DONE xid %u\n",
				p->cku_xid);
		}
#endif
		clist_free(sendlist);
	}

done:
	if (cxdrp)
		XDR_DESTROY(cxdrp);
	if (rxdrp) {
		(void) xdr_rpc_free_verifier(rxdrp, &reply_msg);
		XDR_DESTROY(rxdrp);
	}

	if (recvlist) {
		rdma_buf_t	recvmsg;

		recvmsg.addr = (caddr_t)(uintptr_t)recvlist->c_saddr;
		recvmsg.type = RECV_BUFFER;
		RDMA_BUF_FREE(conn, &recvmsg);
		clist_free(recvlist);
	}
	RDMA_REL_CONN(conn);
	if (p->cku_err.re_status != RPC_SUCCESS) {
		RCSTAT_INCR(rcbadcalls);
	}
	return (p->cku_err.re_status);
}

/* ARGSUSED */
static void
clnt_rdma_kabort(CLIENT *h)
{
}

static void
clnt_rdma_kerror(CLIENT *h, struct rpc_err *err)
{
	struct cku_private *p = htop(h);

	*err = p->cku_err;
}

static bool_t
clnt_rdma_kfreeres(CLIENT *h, xdrproc_t xdr_res, caddr_t res_ptr)
{
	struct cku_private *p = htop(h);
	XDR *xdrs;

	xdrs = &(p->cku_outxdr);
	xdrs->x_op = XDR_FREE;
	return ((*xdr_res)(xdrs, res_ptr));
}

/* ARGSUSED */
static bool_t
clnt_rdma_kcontrol(CLIENT *h, int cmd, char *arg)
{
	return (TRUE);
}

/* ARGSUSED */
static int
clnt_rdma_ksettimers(CLIENT *h, struct rpc_timers *t, struct rpc_timers *all,
	int minimum, void(*feedback)(int, int, caddr_t), caddr_t arg,
	uint32_t xid)
{
	RCSTAT_INCR(rctimers);
	return (0);
}

int
rdma_reachable(int addr_type, struct netbuf *addr, struct knetconfig **knconf)
{
	rdma_registry_t	*rp;
	void *handle = NULL;
	struct knetconfig *knc;
	char *pf, *p;
	rdma_stat status;
	int error = 0;

	if (!INGLOBALZONE(curproc))
		return (-1);
	/*
	 * modload the RDMA plugins if not already done.
	 */
	if (!rdma_modloaded) {
		mutex_enter(&rdma_modload_lock);
		if (!rdma_modloaded) {
			error = rdma_modload();
		}
		mutex_exit(&rdma_modload_lock);
		if (error)
			return (-1);
	}

	if (!rdma_dev_available)
		return (-1);

	rw_enter(&rdma_lock, RW_READER);
	rp = rdma_mod_head;
	while (rp != NULL) {
		status = RDMA_REACHABLE(rp->r_mod->rdma_ops, addr_type, addr,
		    &handle);
		if (status == RDMA_SUCCESS) {
			knc = kmem_zalloc(sizeof (struct knetconfig),
				KM_SLEEP);
			knc->knc_semantics = NC_TPI_RDMA;
			pf = kmem_alloc(KNC_STRSIZE, KM_SLEEP);
			p = kmem_alloc(KNC_STRSIZE, KM_SLEEP);
			if (addr_type == AF_INET)
				(void) strncpy(pf, NC_INET, KNC_STRSIZE);
			else if (addr_type == AF_INET6)
				(void) strncpy(pf, NC_INET6, KNC_STRSIZE);
			pf[KNC_STRSIZE - 1] = '\0';

			(void) strncpy(p, rp->r_mod->rdma_api, KNC_STRSIZE);
			p[KNC_STRSIZE - 1] = '\0';

			knc->knc_protofmly = pf;
			knc->knc_proto = p;
			knc->knc_rdev = (dev_t)handle;
			*knconf = knc;
			rw_exit(&rdma_lock);
			return (0);
		}
		rp = rp->r_next;
	}
	rw_exit(&rdma_lock);
	return (-1);
}
