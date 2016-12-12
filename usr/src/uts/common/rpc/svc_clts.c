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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 *  Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012 by Delphix. All rights reserved.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

/*
 * svc_clts.c
 * Server side for RPC in the kernel.
 *
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/file.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/tihdr.h>
#include <sys/tiuser.h>
#include <sys/t_kuser.h>
#include <sys/fcntl.h>
#include <sys/errno.h>
#include <sys/kmem.h>
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
#include <inet/ip.h>

/*
 * Routines exported through ops vector.
 */
static bool_t		svc_clts_krecv(SVCXPRT *, mblk_t *, struct rpc_msg *);
static bool_t		svc_clts_ksend(SVCXPRT *, struct rpc_msg *);
static bool_t		svc_clts_kgetargs(SVCXPRT *, xdrproc_t, caddr_t);
static bool_t		svc_clts_kfreeargs(SVCXPRT *, xdrproc_t, caddr_t);
static void		svc_clts_kdestroy(SVCMASTERXPRT *);
static int		svc_clts_kdup(struct svc_req *, caddr_t, int,
				struct dupreq **, bool_t *);
static void		svc_clts_kdupdone(struct dupreq *, caddr_t,
				void (*)(), int, int);
static int32_t		*svc_clts_kgetres(SVCXPRT *, int);
static void		svc_clts_kclone_destroy(SVCXPRT *);
static void		svc_clts_kfreeres(SVCXPRT *);
static void		svc_clts_kstart(SVCMASTERXPRT *);
static void		svc_clts_kclone_xprt(SVCXPRT *, SVCXPRT *);
static void		svc_clts_ktattrs(SVCXPRT *, int, void **);

/*
 * Server transport operations vector.
 */
struct svc_ops svc_clts_op = {
	svc_clts_krecv,		/* Get requests */
	svc_clts_kgetargs,	/* Deserialize arguments */
	svc_clts_ksend,		/* Send reply */
	svc_clts_kfreeargs,	/* Free argument data space */
	svc_clts_kdestroy,	/* Destroy transport handle */
	svc_clts_kdup,		/* Check entry in dup req cache */
	svc_clts_kdupdone,	/* Mark entry in dup req cache as done */
	svc_clts_kgetres,	/* Get pointer to response buffer */
	svc_clts_kfreeres,	/* Destroy pre-serialized response header */
	svc_clts_kclone_destroy, /* Destroy a clone xprt */
	svc_clts_kstart,	/* Tell `ready-to-receive' to rpcmod */
	svc_clts_kclone_xprt,	/* transport specific clone xprt function */
	svc_clts_ktattrs	/* Transport specific attributes. */
};

/*
 * Transport private data.
 * Kept in xprt->xp_p2buf.
 */
struct udp_data {
	mblk_t	*ud_resp;			/* buffer for response */
	mblk_t	*ud_inmp;			/* mblk chain of request */
};

#define	UD_MAXSIZE	8800
#define	UD_INITSIZE	2048

/*
 * Connectionless server statistics
 */
static const struct rpc_clts_server {
	kstat_named_t	rscalls;
	kstat_named_t	rsbadcalls;
	kstat_named_t	rsnullrecv;
	kstat_named_t	rsbadlen;
	kstat_named_t	rsxdrcall;
	kstat_named_t	rsdupchecks;
	kstat_named_t	rsdupreqs;
} clts_rsstat_tmpl = {
	{ "calls",	KSTAT_DATA_UINT64 },
	{ "badcalls",	KSTAT_DATA_UINT64 },
	{ "nullrecv",	KSTAT_DATA_UINT64 },
	{ "badlen",	KSTAT_DATA_UINT64 },
	{ "xdrcall",	KSTAT_DATA_UINT64 },
	{ "dupchecks",	KSTAT_DATA_UINT64 },
	{ "dupreqs",	KSTAT_DATA_UINT64 }
};

static uint_t clts_rsstat_ndata =
	sizeof (clts_rsstat_tmpl) / sizeof (kstat_named_t);

#define	CLONE2STATS(clone_xprt)	\
	(struct rpc_clts_server *)(clone_xprt)->xp_master->xp_p2

#define	RSSTAT_INCR(stats, x)	\
	atomic_inc_64(&(stats)->x.value.ui64)

/*
 * Create a transport record.
 * The transport record, output buffer, and private data structure
 * are allocated.  The output buffer is serialized into using xdrmem.
 * There is one transport record per user process which implements a
 * set of services.
 */
/* ARGSUSED */
int
svc_clts_kcreate(file_t *fp, uint_t sendsz, struct T_info_ack *tinfo,
    SVCMASTERXPRT **nxprt)
{
	SVCMASTERXPRT *xprt;
	struct rpcstat *rpcstat;

	if (nxprt == NULL)
		return (EINVAL);

	rpcstat = zone_getspecific(rpcstat_zone_key, curproc->p_zone);
	ASSERT(rpcstat != NULL);

	xprt = kmem_zalloc(sizeof (*xprt), KM_SLEEP);
	xprt->xp_lcladdr.buf = kmem_zalloc(sizeof (sin6_t), KM_SLEEP);
	xprt->xp_p2 = (caddr_t)rpcstat->rpc_clts_server;
	xprt->xp_ops = &svc_clts_op;
	xprt->xp_msg_size = tinfo->TSDU_size;

	xprt->xp_rtaddr.buf = NULL;
	xprt->xp_rtaddr.maxlen = tinfo->ADDR_size;
	xprt->xp_rtaddr.len = 0;

	*nxprt = xprt;

	return (0);
}

/*
 * Destroy a transport record.
 * Frees the space allocated for a transport record.
 */
static void
svc_clts_kdestroy(SVCMASTERXPRT *xprt)
{
	if (xprt->xp_netid)
		kmem_free(xprt->xp_netid, strlen(xprt->xp_netid) + 1);
	if (xprt->xp_addrmask.maxlen)
		kmem_free(xprt->xp_addrmask.buf, xprt->xp_addrmask.maxlen);

	mutex_destroy(&xprt->xp_req_lock);
	mutex_destroy(&xprt->xp_thread_lock);

	kmem_free(xprt->xp_lcladdr.buf, sizeof (sin6_t));
	kmem_free(xprt, sizeof (SVCMASTERXPRT));
}

/*
 * Transport-type specific part of svc_xprt_cleanup().
 * Frees the message buffer space allocated for a clone of a transport record
 */
static void
svc_clts_kclone_destroy(SVCXPRT *clone_xprt)
{
	/* LINTED pointer alignment */
	struct udp_data *ud = (struct udp_data *)clone_xprt->xp_p2buf;

	if (ud->ud_resp) {
		/*
		 * There should not be any left over results buffer.
		 */
		ASSERT(ud->ud_resp->b_cont == NULL);

		/*
		 * Free the T_UNITDATA_{REQ/IND} that svc_clts_krecv
		 * saved.
		 */
		freeb(ud->ud_resp);
	}
	if (ud->ud_inmp)
		freemsg(ud->ud_inmp);
}

/*
 * svc_tli_kcreate() calls this function at the end to tell
 * rpcmod that the transport is ready to receive requests.
 */
/* ARGSUSED */
static void
svc_clts_kstart(SVCMASTERXPRT *xprt)
{
}

static void
svc_clts_kclone_xprt(SVCXPRT *src_xprt, SVCXPRT *dst_xprt)
{
	struct udp_data *ud_src =
	    (struct udp_data *)src_xprt->xp_p2buf;
	struct udp_data *ud_dst =
	    (struct udp_data *)dst_xprt->xp_p2buf;

	if (ud_src->ud_resp)
		ud_dst->ud_resp = dupb(ud_src->ud_resp);

}

static void
svc_clts_ktattrs(SVCXPRT *clone_xprt, int attrflag, void **tattr)
{
	*tattr = NULL;

	switch (attrflag) {
	case SVC_TATTR_ADDRMASK:
		*tattr = (void *)&clone_xprt->xp_master->xp_addrmask;
	}
}

/*
 * Receive rpc requests.
 * Pulls a request in off the socket, checks if the packet is intact,
 * and deserializes the call packet.
 */
static bool_t
svc_clts_krecv(SVCXPRT *clone_xprt, mblk_t *mp, struct rpc_msg *msg)
{
	/* LINTED pointer alignment */
	struct udp_data *ud = (struct udp_data *)clone_xprt->xp_p2buf;
	XDR *xdrs = &clone_xprt->xp_xdrin;
	struct rpc_clts_server *stats = CLONE2STATS(clone_xprt);
	union T_primitives *pptr;
	int hdrsz;
	cred_t *cr;

	TRACE_0(TR_FAC_KRPC, TR_SVC_CLTS_KRECV_START,
	    "svc_clts_krecv_start:");

	RSSTAT_INCR(stats, rscalls);

	/*
	 * The incoming request should start with an M_PROTO message.
	 */
	if (mp->b_datap->db_type != M_PROTO) {
		goto bad;
	}

	/*
	 * The incoming request should be an T_UNITDTA_IND.  There
	 * might be other messages coming up the stream, but we can
	 * ignore them.
	 */
	pptr = (union T_primitives *)mp->b_rptr;
	if (pptr->type != T_UNITDATA_IND) {
		goto bad;
	}
	/*
	 * Do some checking to make sure that the header at least looks okay.
	 */
	hdrsz = (int)(mp->b_wptr - mp->b_rptr);
	if (hdrsz < TUNITDATAINDSZ ||
	    hdrsz < (pptr->unitdata_ind.OPT_offset +
	    pptr->unitdata_ind.OPT_length) ||
	    hdrsz < (pptr->unitdata_ind.SRC_offset +
	    pptr->unitdata_ind.SRC_length)) {
		goto bad;
	}

	/*
	 * Make sure that the transport provided a usable address.
	 */
	if (pptr->unitdata_ind.SRC_length <= 0) {
		goto bad;
	}
	/*
	 * Point the remote transport address in the service_transport
	 * handle at the address in the request.
	 */
	clone_xprt->xp_rtaddr.buf = (char *)mp->b_rptr +
	    pptr->unitdata_ind.SRC_offset;
	clone_xprt->xp_rtaddr.len = pptr->unitdata_ind.SRC_length;

	/*
	 * Copy the local transport address in the service_transport
	 * handle at the address in the request. We will have only
	 * the local IP address in options.
	 */
	((sin_t *)(clone_xprt->xp_lcladdr.buf))->sin_family = AF_UNSPEC;
	if (pptr->unitdata_ind.OPT_length && pptr->unitdata_ind.OPT_offset) {
		char *dstopt = (char *)mp->b_rptr +
		    pptr->unitdata_ind.OPT_offset;
		struct T_opthdr *toh = (struct T_opthdr *)dstopt;

		if (toh->level == IPPROTO_IPV6 && toh->status == 0 &&
		    toh->name == IPV6_PKTINFO) {
			struct in6_pktinfo *pkti;

			dstopt += sizeof (struct T_opthdr);
			pkti = (struct in6_pktinfo *)dstopt;
			((sin6_t *)(clone_xprt->xp_lcladdr.buf))->sin6_addr
			    = pkti->ipi6_addr;
			((sin6_t *)(clone_xprt->xp_lcladdr.buf))->sin6_family
			    = AF_INET6;
		} else if (toh->level == IPPROTO_IP && toh->status == 0 &&
		    toh->name == IP_RECVDSTADDR) {
			dstopt += sizeof (struct T_opthdr);
			((sin_t *)(clone_xprt->xp_lcladdr.buf))->sin_addr
			    = *(struct in_addr *)dstopt;
			((sin_t *)(clone_xprt->xp_lcladdr.buf))->sin_family
			    = AF_INET;
		}
	}

	/*
	 * Save the first mblk which contains the T_unidata_ind in
	 * ud_resp.  It will be used to generate the T_unitdata_req
	 * during the reply.
	 * We reuse any options in the T_unitdata_ind for the T_unitdata_req
	 * since we must pass any SCM_UCRED across in order for TX to
	 * work. We also make sure any cred_t is carried across.
	 */
	if (ud->ud_resp) {
		if (ud->ud_resp->b_cont != NULL) {
			cmn_err(CE_WARN, "svc_clts_krecv: ud_resp %p, "
			    "b_cont %p", (void *)ud->ud_resp,
			    (void *)ud->ud_resp->b_cont);
		}
		freeb(ud->ud_resp);
	}
	/* Move any cred_t to the first mblk in the message */
	cr = msg_getcred(mp, NULL);
	if (cr != NULL)
		mblk_setcred(mp, cr, NOPID);

	ud->ud_resp = mp;
	mp = mp->b_cont;
	ud->ud_resp->b_cont = NULL;

	xdrmblk_init(xdrs, mp, XDR_DECODE, 0);

	TRACE_0(TR_FAC_KRPC, TR_XDR_CALLMSG_START,
	    "xdr_callmsg_start:");
	if (! xdr_callmsg(xdrs, msg)) {
		XDR_DESTROY(xdrs);
		TRACE_1(TR_FAC_KRPC, TR_XDR_CALLMSG_END,
		    "xdr_callmsg_end:(%S)", "bad");
		RSSTAT_INCR(stats, rsxdrcall);
		goto bad;
	}
	TRACE_1(TR_FAC_KRPC, TR_XDR_CALLMSG_END,
	    "xdr_callmsg_end:(%S)", "good");

	clone_xprt->xp_xid = msg->rm_xid;
	ud->ud_inmp = mp;

	TRACE_1(TR_FAC_KRPC, TR_SVC_CLTS_KRECV_END,
	    "svc_clts_krecv_end:(%S)", "good");
	return (TRUE);

bad:
	freemsg(mp);
	if (ud->ud_resp) {
		/*
		 * There should not be any left over results buffer.
		 */
		ASSERT(ud->ud_resp->b_cont == NULL);
		freeb(ud->ud_resp);
		ud->ud_resp = NULL;
	}

	RSSTAT_INCR(stats, rsbadcalls);
	TRACE_1(TR_FAC_KRPC, TR_SVC_CLTS_KRECV_END,
	    "svc_clts_krecv_end:(%S)", "bad");
	return (FALSE);
}

/*
 * Send rpc reply.
 * Serialize the reply packet into the output buffer then
 * call t_ksndudata to send it.
 */
static bool_t
svc_clts_ksend(SVCXPRT *clone_xprt, struct rpc_msg *msg)
{
	/* LINTED pointer alignment */
	struct udp_data *ud = (struct udp_data *)clone_xprt->xp_p2buf;
	XDR *xdrs = &clone_xprt->xp_xdrout;
	int stat = FALSE;
	mblk_t *mp;
	int msgsz;
	struct T_unitdata_req *udreq;
	xdrproc_t xdr_results;
	caddr_t xdr_location;
	bool_t has_args;

	TRACE_0(TR_FAC_KRPC, TR_SVC_CLTS_KSEND_START,
	    "svc_clts_ksend_start:");

	ASSERT(ud->ud_resp != NULL);

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

	if (ud->ud_resp->b_cont == NULL) {
		/*
		 * Allocate an initial mblk for the response data.
		 */
		while ((mp = allocb(UD_INITSIZE, BPRI_LO)) == NULL) {
			if (strwaitbuf(UD_INITSIZE, BPRI_LO)) {
				TRACE_1(TR_FAC_KRPC, TR_SVC_CLTS_KSEND_END,
				    "svc_clts_ksend_end:(%S)", "strwaitbuf");
				return (FALSE);
			}
		}

		/*
		 * Initialize the XDR encode stream.  Additional mblks
		 * will be allocated if necessary.  They will be UD_MAXSIZE
		 * sized.
		 */
		xdrmblk_init(xdrs, mp, XDR_ENCODE, UD_MAXSIZE);

		/*
		 * Leave some space for protocol headers.
		 */
		(void) XDR_SETPOS(xdrs, 512);
		mp->b_rptr += 512;

		msg->rm_xid = clone_xprt->xp_xid;

		ud->ud_resp->b_cont = mp;

		TRACE_0(TR_FAC_KRPC, TR_XDR_REPLYMSG_START,
		    "xdr_replymsg_start:");
		if (!(xdr_replymsg(xdrs, msg) &&
		    (!has_args || SVCAUTH_WRAP(&clone_xprt->xp_auth, xdrs,
		    xdr_results, xdr_location)))) {
			XDR_DESTROY(xdrs);
			TRACE_1(TR_FAC_KRPC, TR_XDR_REPLYMSG_END,
			    "xdr_replymsg_end:(%S)", "bad");
			RPCLOG0(1, "xdr_replymsg/SVCAUTH_WRAP failed\n");
			goto out;
		}
		TRACE_1(TR_FAC_KRPC, TR_XDR_REPLYMSG_END,
		    "xdr_replymsg_end:(%S)", "good");

	} else if (!(xdr_replymsg_body(xdrs, msg) &&
	    (!has_args || SVCAUTH_WRAP(&clone_xprt->xp_auth, xdrs,
	    xdr_results, xdr_location)))) {
		XDR_DESTROY(xdrs);
		RPCLOG0(1, "xdr_replymsg_body/SVCAUTH_WRAP failed\n");
		goto out;
	}

	XDR_DESTROY(xdrs);

	msgsz = (int)xmsgsize(ud->ud_resp->b_cont);

	if (msgsz <= 0 || (clone_xprt->xp_msg_size != -1 &&
	    msgsz > clone_xprt->xp_msg_size)) {
#ifdef	DEBUG
		cmn_err(CE_NOTE,
"KRPC: server response message of %d bytes; transport limits are [0, %d]",
		    msgsz, clone_xprt->xp_msg_size);
#endif
		goto out;
	}

	/*
	 * Construct the T_unitdata_req.  We take advantage of the fact that
	 * T_unitdata_ind looks just like T_unitdata_req, except for the
	 * primitive type.  Reusing it means we preserve the SCM_UCRED, and
	 * we must preserve it for TX to work.
	 *
	 * This has the side effect that we can also pass certain receive-side
	 * options like IPV6_PKTINFO back down the send side.  This implies
	 * that we can not ASSERT on a non-NULL db_credp when we have send-side
	 * options in UDP.
	 */
	ASSERT(MBLKL(ud->ud_resp) >= TUNITDATAREQSZ);
	udreq = (struct T_unitdata_req *)ud->ud_resp->b_rptr;
	ASSERT(udreq->PRIM_type == T_UNITDATA_IND);
	udreq->PRIM_type = T_UNITDATA_REQ;

	/*
	 * If the local IPv4 transport address is known use it as a source
	 * address for the outgoing UDP packet.
	 */
	if (((sin_t *)(clone_xprt->xp_lcladdr.buf))->sin_family == AF_INET) {
		struct T_opthdr *opthdr;
		in_pktinfo_t *pktinfo;
		size_t size;

		if (udreq->DEST_length == 0)
			udreq->OPT_offset = _TPI_ALIGN_TOPT(TUNITDATAREQSZ);
		else
			udreq->OPT_offset = _TPI_ALIGN_TOPT(udreq->DEST_offset +
			    udreq->DEST_length);

		udreq->OPT_length = sizeof (struct T_opthdr) +
		    sizeof (in_pktinfo_t);

		size = udreq->OPT_length + udreq->OPT_offset;

		/* make sure we have enough space for the option data */
		mp = reallocb(ud->ud_resp, size, 1);
		if (mp == NULL)
			goto out;
		ud->ud_resp = mp;
		udreq = (struct T_unitdata_req *)mp->b_rptr;

		/* set desired option header */
		opthdr = (struct T_opthdr *)(mp->b_rptr + udreq->OPT_offset);
		opthdr->len = udreq->OPT_length;
		opthdr->level = IPPROTO_IP;
		opthdr->name = IP_PKTINFO;

		/*
		 * 1. set source IP of outbound packet
		 * 2. value '0' for index means IP layer uses this as source
		 *    address
		 */
		pktinfo = (in_pktinfo_t *)(opthdr + 1);
		(void) memset(pktinfo, 0, sizeof (in_pktinfo_t));
		pktinfo->ipi_spec_dst.s_addr =
		    ((sin_t *)(clone_xprt->xp_lcladdr.buf))->sin_addr.s_addr;
		pktinfo->ipi_ifindex = 0;

		/* adjust the end of active data */
		mp->b_wptr = mp->b_rptr + size;
	}

	put(clone_xprt->xp_wq, ud->ud_resp);
	stat = TRUE;
	ud->ud_resp = NULL;

out:
	if (stat == FALSE) {
		freemsg(ud->ud_resp);
		ud->ud_resp = NULL;
	}

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

	TRACE_1(TR_FAC_KRPC, TR_SVC_CLTS_KSEND_END,
	    "svc_clts_ksend_end:(%S)", "done");
	return (stat);
}

/*
 * Deserialize arguments.
 */
static bool_t
svc_clts_kgetargs(SVCXPRT *clone_xprt, xdrproc_t xdr_args,
    caddr_t args_ptr)
{

	/* LINTED pointer alignment */
	return (SVCAUTH_UNWRAP(&clone_xprt->xp_auth, &clone_xprt->xp_xdrin,
	    xdr_args, args_ptr));

}

static bool_t
svc_clts_kfreeargs(SVCXPRT *clone_xprt, xdrproc_t xdr_args,
    caddr_t args_ptr)
{
	/* LINTED pointer alignment */
	struct udp_data *ud = (struct udp_data *)clone_xprt->xp_p2buf;
	XDR *xdrs = &clone_xprt->xp_xdrin;
	bool_t retval;

	if (args_ptr) {
		xdrs->x_op = XDR_FREE;
		retval = (*xdr_args)(xdrs, args_ptr);
	} else
		retval = TRUE;

	XDR_DESTROY(xdrs);

	if (ud->ud_inmp) {
		freemsg(ud->ud_inmp);
		ud->ud_inmp = NULL;
	}

	return (retval);
}

static int32_t *
svc_clts_kgetres(SVCXPRT *clone_xprt, int size)
{
	/* LINTED pointer alignment */
	struct udp_data *ud = (struct udp_data *)clone_xprt->xp_p2buf;
	XDR *xdrs = &clone_xprt->xp_xdrout;
	mblk_t *mp;
	int32_t *buf;
	struct rpc_msg rply;

	/*
	 * Allocate an initial mblk for the response data.
	 */
	while ((mp = allocb(UD_INITSIZE, BPRI_LO)) == NULL) {
		if (strwaitbuf(UD_INITSIZE, BPRI_LO)) {
			return (NULL);
		}
	}

	mp->b_cont = NULL;

	/*
	 * Initialize the XDR encode stream.  Additional mblks
	 * will be allocated if necessary.  They will be UD_MAXSIZE
	 * sized.
	 */
	xdrmblk_init(xdrs, mp, XDR_ENCODE, UD_MAXSIZE);

	/*
	 * Leave some space for protocol headers.
	 */
	(void) XDR_SETPOS(xdrs, 512);
	mp->b_rptr += 512;

	/*
	 * Assume a successful RPC since most of them are.
	 */
	rply.rm_xid = clone_xprt->xp_xid;
	rply.rm_direction = REPLY;
	rply.rm_reply.rp_stat = MSG_ACCEPTED;
	rply.acpted_rply.ar_verf = clone_xprt->xp_verf;
	rply.acpted_rply.ar_stat = SUCCESS;

	if (!xdr_replymsg_hdr(xdrs, &rply)) {
		XDR_DESTROY(xdrs);
		freeb(mp);
		return (NULL);
	}

	buf = XDR_INLINE(xdrs, size);

	if (buf == NULL) {
		XDR_DESTROY(xdrs);
		freeb(mp);
	} else {
		ud->ud_resp->b_cont = mp;
	}

	return (buf);
}

static void
svc_clts_kfreeres(SVCXPRT *clone_xprt)
{
	/* LINTED pointer alignment */
	struct udp_data *ud = (struct udp_data *)clone_xprt->xp_p2buf;

	if (ud->ud_resp == NULL || ud->ud_resp->b_cont == NULL)
		return;

	XDR_DESTROY(&clone_xprt->xp_xdrout);

	/*
	 * SVC_FREERES() is called whenever the server decides not to
	 * send normal reply. Thus, we expect only one mblk to be allocated,
	 * because we have not attempted any XDR encoding.
	 * If we do any XDR encoding and we get an error, then SVC_REPLY()
	 * will freemsg(ud->ud_resp);
	 */
	ASSERT(ud->ud_resp->b_cont->b_cont == NULL);
	freeb(ud->ud_resp->b_cont);
	ud->ud_resp->b_cont = NULL;
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
#define	MAXDUPREQS	8192

/*
 * This should be appropriately scaled to MAXDUPREQS.  To produce as less as
 * possible collisions it is suggested to set this to a prime.
 */
#define	DRHASHSZ	2053

#define	XIDHASH(xid)	((xid) % DRHASHSZ)
#define	DRHASH(dr)	XIDHASH((dr)->dr_xid)
#define	REQTOXID(req)	((req)->rq_xprt->xp_xid)

static int	ndupreqs = 0;
int	maxdupreqs = MAXDUPREQS;
static kmutex_t dupreq_lock;
static struct dupreq *drhashtbl[DRHASHSZ];
static int	drhashstat[DRHASHSZ];

static void unhash(struct dupreq *);

/*
 * drmru points to the head of a circular linked list in lru order.
 * drmru->dr_next == drlru
 */
struct dupreq *drmru;

/*
 * PSARC 2003/523 Contract Private Interface
 * svc_clts_kdup
 * Changes must be reviewed by Solaris File Sharing
 * Changes must be communicated to contract-2003-523@sun.com
 *
 * svc_clts_kdup searches the request cache and returns 0 if the
 * request is not found in the cache.  If it is found, then it
 * returns the state of the request (in progress or done) and
 * the status or attributes that were part of the original reply.
 *
 * If DUP_DONE (there is a duplicate) svc_clts_kdup copies over the
 * value of the response. In that case, also return in *dupcachedp
 * whether the response free routine is cached in the dupreq - in which case
 * the caller should not be freeing it, because it will be done later
 * in the svc_clts_kdup code when the dupreq is reused.
 */
static int
svc_clts_kdup(struct svc_req *req, caddr_t res, int size, struct dupreq **drpp,
    bool_t *dupcachedp)
{
	struct rpc_clts_server *stats = CLONE2STATS(req->rq_xprt);
	struct dupreq *dr;
	uint32_t xid;
	uint32_t drhash;
	int status;

	xid = REQTOXID(req);
	mutex_enter(&dupreq_lock);
	RSSTAT_INCR(stats, rsdupchecks);
	/*
	 * Check to see whether an entry already exists in the cache.
	 */
	dr = drhashtbl[XIDHASH(xid)];
	while (dr != NULL) {
		if (dr->dr_xid == xid &&
		    dr->dr_proc == req->rq_proc &&
		    dr->dr_prog == req->rq_prog &&
		    dr->dr_vers == req->rq_vers &&
		    dr->dr_addr.len == req->rq_xprt->xp_rtaddr.len &&
		    bcmp(dr->dr_addr.buf, req->rq_xprt->xp_rtaddr.buf,
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
			RSSTAT_INCR(stats, rsdupreqs);
			mutex_exit(&dupreq_lock);
			return (status);
		}
		dr = dr->dr_chain;
	}

	/*
	 * There wasn't an entry, either allocate a new one or recycle
	 * an old one.
	 */
	if (ndupreqs < maxdupreqs) {
		dr = kmem_alloc(sizeof (*dr), KM_NOSLEEP);
		if (dr == NULL) {
			mutex_exit(&dupreq_lock);
			return (DUP_ERROR);
		}
		dr->dr_resp.buf = NULL;
		dr->dr_resp.maxlen = 0;
		dr->dr_addr.buf = NULL;
		dr->dr_addr.maxlen = 0;
		if (drmru) {
			dr->dr_next = drmru->dr_next;
			drmru->dr_next = dr;
		} else {
			dr->dr_next = dr;
		}
		ndupreqs++;
	} else {
		dr = drmru->dr_next;
		while (dr->dr_status == DUP_INPROGRESS) {
			dr = dr->dr_next;
			if (dr == drmru->dr_next) {
				cmn_err(CE_WARN, "svc_clts_kdup no slots free");
				mutex_exit(&dupreq_lock);
				return (DUP_ERROR);
			}
		}
		unhash(dr);
		if (dr->dr_resfree) {
			(*dr->dr_resfree)(dr->dr_resp.buf);
		}
	}
	dr->dr_resfree = NULL;
	drmru = dr;

	dr->dr_xid = REQTOXID(req);
	dr->dr_prog = req->rq_prog;
	dr->dr_vers = req->rq_vers;
	dr->dr_proc = req->rq_proc;
	if (dr->dr_addr.maxlen < req->rq_xprt->xp_rtaddr.len) {
		if (dr->dr_addr.buf != NULL)
			kmem_free(dr->dr_addr.buf, dr->dr_addr.maxlen);
		dr->dr_addr.maxlen = req->rq_xprt->xp_rtaddr.len;
		dr->dr_addr.buf = kmem_alloc(dr->dr_addr.maxlen,
		    KM_NOSLEEP);
		if (dr->dr_addr.buf == NULL) {
			dr->dr_addr.maxlen = 0;
			dr->dr_status = DUP_DROP;
			mutex_exit(&dupreq_lock);
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
			mutex_exit(&dupreq_lock);
			return (DUP_ERROR);
		}
	}
	dr->dr_status = DUP_INPROGRESS;

	drhash = (uint32_t)DRHASH(dr);
	dr->dr_chain = drhashtbl[drhash];
	drhashtbl[drhash] = dr;
	drhashstat[drhash]++;
	mutex_exit(&dupreq_lock);
	*drpp = dr;
	return (DUP_NEW);
}

/*
 * PSARC 2003/523 Contract Private Interface
 * svc_clts_kdupdone
 * Changes must be reviewed by Solaris File Sharing
 * Changes must be communicated to contract-2003-523@sun.com
 *
 * svc_clts_kdupdone marks the request done (DUP_DONE or DUP_DROP)
 * and stores the response.
 */
static void
svc_clts_kdupdone(struct dupreq *dr, caddr_t res, void (*dis_resfree)(),
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
 * This routine expects that the mutex, dupreq_lock, is already held.
 */
static void
unhash(struct dupreq *dr)
{
	struct dupreq *drt;
	struct dupreq *drtprev = NULL;
	uint32_t drhash;

	ASSERT(MUTEX_HELD(&dupreq_lock));

	drhash = (uint32_t)DRHASH(dr);
	drt = drhashtbl[drhash];
	while (drt != NULL) {
		if (drt == dr) {
			drhashstat[drhash]--;
			if (drtprev == NULL) {
				drhashtbl[drhash] = drt->dr_chain;
			} else {
				drtprev->dr_chain = drt->dr_chain;
			}
			return;
		}
		drtprev = drt;
		drt = drt->dr_chain;
	}
}

void
svc_clts_stats_init(zoneid_t zoneid, struct rpc_clts_server **statsp)
{
	kstat_t *ksp;
	kstat_named_t *knp;

	knp = rpcstat_zone_init_common(zoneid, "unix", "rpc_clts_server",
	    (const kstat_named_t *)&clts_rsstat_tmpl,
	    sizeof (clts_rsstat_tmpl));
	/*
	 * Backwards compatibility for old kstat clients
	 */
	ksp = kstat_create_zone("unix", 0, "rpc_server", "rpc",
	    KSTAT_TYPE_NAMED, clts_rsstat_ndata,
	    KSTAT_FLAG_VIRTUAL | KSTAT_FLAG_WRITABLE, zoneid);
	if (ksp) {
		ksp->ks_data = knp;
		kstat_install(ksp);
	}
	*statsp = (struct rpc_clts_server *)knp;
}

void
svc_clts_stats_fini(zoneid_t zoneid, struct rpc_clts_server **statsp)
{
	rpcstat_zone_fini_common(zoneid, "unix", "rpc_clts_server");
	kstat_delete_byname_zone("unix", 0, "rpc_server", zoneid);
	kmem_free(*statsp, sizeof (clts_rsstat_tmpl));
}

void
svc_clts_init()
{
	/*
	 * Check to make sure that the clts private data will fit into
	 * the stack buffer allocated by svc_run.  The compiler should
	 * remove this check, but it's a safety net if the udp_data
	 * structure ever changes.
	 */
	/*CONSTANTCONDITION*/
	ASSERT(sizeof (struct udp_data) <= SVC_P2LEN);

	mutex_init(&dupreq_lock, NULL, MUTEX_DEFAULT, NULL);
}
