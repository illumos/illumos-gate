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
 * Copyright 2014 Gary Mills
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Dump memory to NFS swap file after a panic.
 * We have no timeouts, context switches, etc.
 */

#include <rpc/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/vnode.h>
#include <sys/bootconf.h>
#include <nfs/nfs.h>
#include <rpc/auth.h>
#include <rpc/xdr.h>
#include <rpc/rpc_msg.h>
#include <rpc/clnt.h>
#include <netinet/in.h>
#include <sys/tiuser.h>
#include <nfs/nfs_clnt.h>
#include <sys/t_kuser.h>
#include <sys/file.h>
#include <sys/netconfig.h>
#include <sys/utsname.h>
#include <sys/sysmacros.h>
#include <sys/thread.h>
#include <sys/cred.h>
#include <sys/strsubr.h>
#include <nfs/rnode.h>
#include <sys/varargs.h>
#include <sys/cmn_err.h>
#include <sys/systm.h>
#include <sys/dumphdr.h>
#include <sys/debug.h>
#include <sys/sunddi.h>

#define	TIMEOUT		(2 * hz)
#define	RETRIES		(5)
#define	HDR_SIZE	(256)

static struct knetconfig	nfsdump_cf;
static struct netbuf		nfsdump_addr;
static fhandle_t		nfsdump_fhandle2;
static nfs_fh3			nfsdump_fhandle3;
static int			nfsdump_maxcount;
static rpcvers_t		nfsdump_version;

/*
 * nonzero dumplog enables nd_log messages
 */
static int 	dumplog = 0;

static int	nd_init(vnode_t *, TIUSER **);
static int	nd_poll(TIUSER *, int, int *);
static int	nd_send_data(TIUSER *, caddr_t, int, XDR *, uint32_t *);
static int	nd_get_reply(TIUSER *, XDR *, uint32_t, int *);
static int	nd_auth_marshall(XDR *);

static void nd_log(const char *, ...) __KPRINTFLIKE(1);

/*PRINTFLIKE1*/
static void
nd_log(const char *fmt, ...)
{
	if (dumplog) {
		va_list adx;

		va_start(adx, fmt);
		vprintf(fmt, adx);
		va_end(adx);
	}
}

/* ARGSUSED */
int
nfs_dump(vnode_t *dumpvp, caddr_t addr, offset_t bn, offset_t count,
    caller_context_t *ct)
{
	static TIUSER	*tiptr;
	XDR		xdrs;
	int		reply;
	int		badmsg;
	uint32_t	call_xid;
	int		retry = 0;
	int		error;
	int		i;

	nd_log("nfs_dump: addr=%p bn=%lld count=%lld\n",
	    (void *)addr, bn, count);

	if (error = nd_init(dumpvp, &tiptr))
		return (error);

	for (i = 0; i < count; i += ptod(1), addr += ptob(1)) {
		do {
			error = nd_send_data(tiptr, addr, (int)dbtob(bn + i),
			    &xdrs, &call_xid);
			if (error)
				return (error);

			do {
				if (error = nd_poll(tiptr, retry, &reply))
					return (error);

				if (!reply) {
					retry++;
					break;
				}
				retry = 0;

				error = nd_get_reply(tiptr, &xdrs, call_xid,
				    &badmsg);
				if (error)
					return (error);
			} while (badmsg);
		} while (retry);
	}

	return (0);
}

static int
nd_init(vnode_t *dumpvp, TIUSER **tiptr)
{
	int 		error;

	if (*tiptr)
		return (0);

	/*
	 * If dump info hasn't yet been initialized (because dump
	 * device was chosen at user-level, rather than at boot time
	 * in nfs_swapvp) fill it in now.
	 */
	if (nfsdump_maxcount == 0) {
		nfsdump_version = VTOMI(dumpvp)->mi_vers;
		switch (nfsdump_version) {
		case NFS_VERSION:
			nfsdump_fhandle2 = *VTOFH(dumpvp);
			break;
		case NFS_V3:
			nfsdump_fhandle3 = *VTOFH3(dumpvp);
			break;
		default:
			return (EIO);
		}
		nfsdump_maxcount = (int)dumpvp_size;
		nfsdump_addr = VTOMI(dumpvp)->mi_curr_serv->sv_addr;
		nfsdump_cf = *(VTOMI(dumpvp)->mi_curr_serv->sv_knconf);
		if (nfsdump_cf.knc_semantics != NC_TPI_CLTS) {
			int v6 = 1;
			nd_log("nfs_dump: not connectionless!\n");
			if ((strcmp(nfsdump_cf.knc_protofmly, NC_INET) == 0) ||
			    ((v6 = strcmp(nfsdump_cf.knc_protofmly, NC_INET6))\
			    == 0)) {
				major_t clone_maj;

				nfsdump_cf.knc_proto = NC_UDP;
				nfsdump_cf.knc_semantics = NC_TPI_CLTS;
				nd_log("nfs_dump: grabbing UDP major number\n");
				clone_maj = ddi_name_to_major("clone");
				nd_log("nfs_dump: making UDP device\n");
				nfsdump_cf.knc_rdev = makedevice(clone_maj,
				    ddi_name_to_major(v6?"udp":"udp6"));
			} else {
				error = EIO;
				nfs_perror(error, "\nnfs_dump: cannot dump over"
				    " protocol %s: %m\n", nfsdump_cf.knc_proto);
				return (error);
			}
		}
	}

	nd_log("nfs_dump: calling t_kopen\n");

	if (error = t_kopen(NULL, nfsdump_cf.knc_rdev,
	    FREAD|FWRITE|FNDELAY, tiptr, CRED())) {
		nfs_perror(error, "\nnfs_dump: t_kopen failed: %m\n");
		return (EIO);
	}

	if ((strcmp(nfsdump_cf.knc_protofmly, NC_INET) == 0) ||
	    (strcmp(nfsdump_cf.knc_protofmly, NC_INET6) == 0)) {
		nd_log("nfs_dump: calling bindresvport\n");
		if (error = bindresvport(*tiptr, NULL, NULL, FALSE)) {
			nfs_perror(error,
			    "\nnfs_dump: bindresvport failed: %m\n");
			return (EIO);
		}
	} else {
		nd_log("nfs_dump: calling t_kbind\n");
		if ((error = t_kbind(*tiptr, NULL, NULL)) != 0) {
			nfs_perror(error, "\nnfs_dump: t_kbind failed: %m\n");
			return (EIO);
		}
	}
	return (0);
}

static int
nd_send_data(TIUSER *tiptr, caddr_t addr, int offset, XDR *xdrp, uint32_t *xidp)
{
	static struct rpc_msg		call_msg;
	static uchar_t			header[HDR_SIZE];
	static struct t_kunitdata	sudata;
	static uchar_t			*dumpbuf;
	int				procnum;
	stable_how			stable = FILE_SYNC;
	mblk_t				*mblk_p;
	int				error;
	int				tsize = ptob(1);
	uint64				offset3;

	if (!dumpbuf) {
		call_msg.rm_direction = CALL;
		call_msg.rm_call.cb_rpcvers = RPC_MSG_VERSION;
		call_msg.rm_call.cb_prog = NFS_PROGRAM;
		call_msg.rm_call.cb_vers = nfsdump_version;

		if (!(dumpbuf = kmem_alloc(ptob(1), KM_NOSLEEP))) {
		cmn_err(CE_WARN, "\tnfs_dump: cannot allocate dump buffer");
			return (ENOMEM);
		}
	}

	nd_log("nfs_dump: calling esballoc for header\n");

	if (!(mblk_p = esballoc(header, HDR_SIZE, BPRI_HI, &frnop))) {
		cmn_err(CE_WARN, "\tnfs_dump: out of mblks");
		return (ENOBUFS);
	}

	xdrmem_create(xdrp, (caddr_t)header, HDR_SIZE, XDR_ENCODE);

	call_msg.rm_xid = alloc_xid();
	*xidp = call_msg.rm_xid;

	if (!xdr_callhdr(xdrp, &call_msg)) {
		cmn_err(CE_WARN, "\tnfs_dump: cannot serialize header");
		return (EIO);
	}

	if (nfsdump_maxcount) {
		/*
		 * Do not extend the dump file if it is also
		 * the swap file.
		 */
		if (offset >= nfsdump_maxcount) {
			cmn_err(CE_WARN, "\tnfs_dump: end of file");
			return (EIO);
		}
		if (offset + tsize > nfsdump_maxcount)
			tsize = nfsdump_maxcount - offset;
	}
	switch (nfsdump_version) {
	case NFS_VERSION:
		procnum = RFS_WRITE;
		if (!XDR_PUTINT32(xdrp, (int32_t *)&procnum) ||
		    !nd_auth_marshall(xdrp) ||
		    !xdr_fhandle(xdrp, &nfsdump_fhandle2) ||
			/*
			 *  Following four values are:
			 *	beginoffset
			 *	offset
			 *	length
			 *	bytes array length
			 */
		    !XDR_PUTINT32(xdrp, (int32_t *)&offset) ||
		    !XDR_PUTINT32(xdrp, (int32_t *)&offset) ||
		    !XDR_PUTINT32(xdrp, (int32_t *)&tsize) ||
		    !XDR_PUTINT32(xdrp, (int32_t *)&tsize)) {
			cmn_err(CE_WARN, "\tnfs_dump: serialization failed");
			return (EIO);
		}
		break;
	case NFS_V3:
		procnum = NFSPROC3_WRITE;
		offset3 = offset;
		if (!XDR_PUTINT32(xdrp, (int32_t *)&procnum) ||
		    !nd_auth_marshall(xdrp) ||
		    !xdr_nfs_fh3(xdrp, &nfsdump_fhandle3) ||
			/*
			 *  Following four values are:
			 *	offset
			 *	count
			 *	stable
			 *	bytes array length
			 */
		    !xdr_u_longlong_t(xdrp, &offset3) ||
		    !XDR_PUTINT32(xdrp, (int32_t *)&tsize) ||
		    !XDR_PUTINT32(xdrp, (int32_t *)&stable) ||
		    !XDR_PUTINT32(xdrp, (int32_t *)&tsize)) {
			cmn_err(CE_WARN, "\tnfs_dump: serialization failed");
			return (EIO);
		}
		break;
	default:
		return (EIO);
	}

	bcopy(addr, (caddr_t)dumpbuf, tsize);

	mblk_p->b_wptr += (int)XDR_GETPOS(xdrp);

	mblk_p->b_cont = esballoc((uchar_t *)dumpbuf, ptob(1), BPRI_HI, &frnop);

	if (!mblk_p->b_cont) {
		cmn_err(CE_WARN, "\tnfs_dump: out of mblks");
		return (ENOBUFS);
	}
	mblk_p->b_cont->b_wptr += ptob(1);

	sudata.addr = nfsdump_addr;		/* structure copy */
	sudata.udata.buf = (char *)NULL;
	sudata.udata.maxlen = 0;
	sudata.udata.len = 1;			/* needed for t_ksndudata */
	sudata.udata.udata_mp = mblk_p;

	nd_log("nfs_dump: calling t_ksndudata\n");

	if (error = t_ksndudata(tiptr, &sudata, (frtn_t *)NULL)) {
		nfs_perror(error, "\nnfs_dump: t_ksndudata failed: %m\n");
		return (error);
	}
	return (0);
}

static int
nd_get_reply(TIUSER *tiptr, XDR *xdrp, uint32_t call_xid, int *badmsg)
{
	static struct rpc_msg		reply_msg;
	static struct rpc_err		rpc_err;
	static struct nfsattrstat	na;
	static struct WRITE3res		wres;
	static struct t_kunitdata	rudata;
	int				uderr;
	int				type;
	int				error;

	*badmsg = 0;

	rudata.addr.maxlen = 0;
	rudata.opt.maxlen = 0;
	rudata.udata.udata_mp = (mblk_t *)NULL;

	nd_log("nfs_dump: calling t_krcvudata\n");

	if (error = t_krcvudata(tiptr, &rudata, &type, &uderr)) {
		if (error == EBADMSG) {
			cmn_err(CE_WARN, "\tnfs_dump:  received EBADMSG");
			*badmsg = 1;
			return (0);
		}
		nfs_perror(error, "\nnfs_dump: t_krcvudata failed: %m\n");
		return (EIO);
	}
	if (type != T_DATA) {
		cmn_err(CE_WARN, "\tnfs_dump:  received type %d", type);
		*badmsg = 1;
		return (0);
	}
	if (!rudata.udata.udata_mp) {
		cmn_err(CE_WARN, "\tnfs_dump: null receive");
		*badmsg = 1;
		return (0);
	}

	/*
	 * Decode results.
	 */
	xdrmblk_init(xdrp, rudata.udata.udata_mp, XDR_DECODE, 0);

	reply_msg.acpted_rply.ar_verf = _null_auth;
	switch (nfsdump_version) {
	case NFS_VERSION:
		reply_msg.acpted_rply.ar_results.where = (caddr_t)&na;
		reply_msg.acpted_rply.ar_results.proc = xdr_attrstat;
		break;
	case NFS_V3:
		reply_msg.acpted_rply.ar_results.where = (caddr_t)&wres;
		reply_msg.acpted_rply.ar_results.proc = xdr_WRITE3res;
		break;
	default:
		return (EIO);
	}

	if (!xdr_replymsg(xdrp, &reply_msg)) {
		cmn_err(CE_WARN, "\tnfs_dump: xdr_replymsg failed");
		return (EIO);
	}

	if (reply_msg.rm_xid != call_xid) {
		*badmsg = 1;
		return (0);
	}

	_seterr_reply(&reply_msg, &rpc_err);

	if (rpc_err.re_status != RPC_SUCCESS) {
		cmn_err(CE_WARN, "\tnfs_dump: RPC error %d (%s)",
		    rpc_err.re_status, clnt_sperrno(rpc_err.re_status));
		return (EIO);
	}

	switch (nfsdump_version) {
	case NFS_VERSION:
		if (na.ns_status) {
			cmn_err(CE_WARN, "\tnfs_dump: status %d", na.ns_status);
			return (EIO);
		}
		break;
	case NFS_V3:
		if (wres.status != NFS3_OK) {
			cmn_err(CE_WARN, "\tnfs_dump: status %d", wres.status);
			return (EIO);
		}
		break;
	default:
		return (EIO);
	}

	if (reply_msg.acpted_rply.ar_verf.oa_base != NULL) {
		/* free auth handle */
		xdrp->x_op = XDR_FREE;
		(void) xdr_opaque_auth(xdrp, &(reply_msg.acpted_rply.ar_verf));
	}

	freemsg(rudata.udata.udata_mp);

	return (0);
}

static int
nd_poll(TIUSER *tiptr, int retry, int *eventp)
{
	clock_t		start_bolt = ddi_get_lbolt();
	clock_t		timout = TIMEOUT * (retry + 1);
	int		error;

	nd_log("nfs_dump: calling t_kspoll\n");

	*eventp = 0;

	while (!*eventp && ((ddi_get_lbolt() - start_bolt) < timout)) {
		/*
		 * Briefly enable interrupts before checking for a reply;
		 * the network transports do not yet support do_polled_io.
		 */
		int s = spl0();
		splx(s);

		if (error = t_kspoll(tiptr, 0, READWAIT, eventp)) {
			nfs_perror(error,
			    "\nnfs_dump: t_kspoll failed: %m\n");
			return (EIO);
		}
		runqueues();
	}

	if (retry == RETRIES && !*eventp) {
		cmn_err(CE_WARN, "\tnfs_dump: server not responding");
		return (EIO);
	}

	return (0);
}

static int
nd_auth_marshall(XDR *xdrp)
{
	int credsize;
	int32_t *ptr;
	int hostnamelen;

	hostnamelen = (int)strlen(utsname.nodename);
	credsize = 4 + 4 + roundup(hostnamelen, 4) + 4 + 4 + 4;

	ptr = XDR_INLINE(xdrp, 4 + 4 + credsize + 4 + 4);
	if (!ptr) {
		cmn_err(CE_WARN, "\tnfs_dump: auth_marshall failed");
		return (0);
	}
	/*
	 * We can do the fast path.
	 */
	IXDR_PUT_INT32(ptr, AUTH_UNIX);	/* cred flavor */
	IXDR_PUT_INT32(ptr, credsize);	/* cred len */
	IXDR_PUT_INT32(ptr, gethrestime_sec());
	IXDR_PUT_INT32(ptr, hostnamelen);

	bcopy(utsname.nodename, ptr, hostnamelen);
	ptr += roundup(hostnamelen, 4) / 4;

	IXDR_PUT_INT32(ptr, 0);		/* uid */
	IXDR_PUT_INT32(ptr, 0);		/* gid */
	IXDR_PUT_INT32(ptr, 0);		/* gid list length (empty) */
	IXDR_PUT_INT32(ptr, AUTH_NULL);	/* verf flavor */
	IXDR_PUT_INT32(ptr, 0);		/* verf len */

	return (1);
}
