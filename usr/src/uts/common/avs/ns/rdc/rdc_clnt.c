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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Network data replicator Client side */


#include <sys/types.h>
#include <sys/debug.h>
#include <sys/ksynch.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/cred.h>
#include <sys/byteorder.h>
#include <sys/errno.h>

#ifdef _SunOS_2_6
/*
 * on 2.6 both dki_lock.h and rpc/types.h define bool_t so we
 * define enum_t here as it is all we need from rpc/types.h
 * anyway and make it look like we included it. Yuck.
 */
#define	_RPC_TYPES_H
typedef int enum_t;
#else
#ifndef DS_DDICT
#include <rpc/types.h>
#endif
#endif /* _SunOS_2_6 */

#ifndef DS_DDICT
#include <rpc/auth.h>
#include <rpc/svc.h>
#include <rpc/xdr.h>
#endif
#include <sys/ddi.h>

#include <sys/nsc_thread.h>
#ifdef DS_DDICT
#include <sys/nsctl/contract.h>
#endif
#include <sys/nsctl/nsctl.h>

#include <sys/sdt.h>		/* dtrace is S10 or later */

#include "rdc_io.h"
#include "rdc_clnt.h"
#include "rdc_bitmap.h"
#include "rdc_diskq.h"


kmutex_t rdc_clnt_lock;

#ifdef DEBUG
int noflush = 0;
#endif

int rdc_rpc_tmout = RDC_CLNT_TMOUT;
static void rdc_clnt_free(struct chtab *, CLIENT *);
static void _rdc_remote_flush(rdc_aio_t *);

void rdc_flush_memq(int index);
void rdc_flush_diskq(int index);
int rdc_drain_net_queue(int index);
void rdc_flusher_thread(int index);
int  rdc_diskq_enqueue(rdc_k_info_t *krdc, rdc_aio_t *);
void rdc_init_diskq_header(rdc_group_t *grp, dqheader *hd);
void rdc_dump_iohdrs(disk_queue *dq);
rdc_aio_t *rdc_dequeue(rdc_k_info_t *krdc, int *rc);
void rdc_clr_iohdr(rdc_k_info_t *krdc, nsc_off_t qpos);
void rdc_close_diskq(rdc_group_t *krdc);

int rdc_writer(int index);

static struct chtab *rdc_chtable = NULL;
static int rdc_clnt_toomany;
#ifdef DEBUG
static int rdc_ooreply;
#endif

extern void rdc_fail_diskq(rdc_k_info_t *krdc, int wait, int flag);
extern int _rdc_rsrv_diskq(rdc_group_t *group);
extern void _rdc_rlse_diskq(rdc_group_t *group);

static enum clnt_stat
cl_call_sig(struct __client *rh, rpcproc_t proc,
	    xdrproc_t xargs, caddr_t argsp, xdrproc_t xres,
	    caddr_t resp, struct timeval secs)
{
	enum clnt_stat stat;
	k_sigset_t smask;
	sigintr(&smask, 0);
	rh->cl_nosignal = TRUE;
	stat = ((*(rh)->cl_ops->cl_call)\
		(rh, proc, xargs, argsp, xres, resp, secs));
	rh->cl_nosignal = FALSE;
	sigunintr(&smask);
	return (stat);
}

int
rdc_net_getsize(int index, uint64_t *sizeptr)
{
	struct timeval t;
	int err, size;
	rdc_k_info_t *krdc = &rdc_k_info[index];
	int remote_index = krdc->remote_index;

	*sizeptr = 0;
	if (krdc->remote_index < 0)
		return (EINVAL);

	t.tv_sec = rdc_rpc_tmout;
	t.tv_usec = 0;

#ifdef DEBUG
	if (krdc->intf == NULL)
		cmn_err(CE_WARN,
		    "rdc_net_getsize: null intf for index %d", index);
#endif
	if (krdc->rpc_version <= RDC_VERSION5) {
		err = rdc_clnt_call(krdc->lsrv, RDCPROC_GETSIZE,
		    krdc->rpc_version, xdr_int, (char *)&remote_index,
		    xdr_int, (char *)&size, &t);
		if (err == 0)
			*sizeptr = size;
	} else {
		err = rdc_clnt_call(krdc->lsrv, RDCPROC_GETSIZE6,
		    krdc->rpc_version, xdr_int, (char *)&remote_index,
		    xdr_u_longlong_t, (char *)sizeptr, &t);
	}
	return (err);
}


int
rdc_net_state(int index, int options)
{
	struct timeval t;
	int err;
	int remote_index = -1;
	rdc_u_info_t *urdc = &rdc_u_info[index];
	rdc_k_info_t *krdc = &rdc_k_info[index];
	struct set_state s;
	struct set_state4 s4;
	char neta[32], rneta[32];
	unsigned short *sp;

	t.tv_sec = rdc_rpc_tmout;
	t.tv_usec = 0;

	if (krdc->rpc_version < RDC_VERSION7) {
		s4.netaddrlen = urdc->primary.addr.len;
		s4.rnetaddrlen = urdc->secondary.addr.len;
		bcopy(urdc->primary.addr.buf, s4.netaddr, s4.netaddrlen);
		bcopy(urdc->secondary.addr.buf, s4.rnetaddr, s4.rnetaddrlen);
		(void) strncpy(s4.pfile, urdc->primary.file, RDC_MAXNAMLEN);
		(void) strncpy(s4.sfile, urdc->secondary.file, RDC_MAXNAMLEN);
		s4.flag = options;

		err = rdc_clnt_call(krdc->lsrv, RDCPROC_STATE,
		    krdc->rpc_version, xdr_set_state4, (char *)&s4, xdr_int,
		    (char *)&remote_index, &t);
	} else {
		s.netaddrlen = urdc->primary.addr.len;
		s.rnetaddrlen = urdc->secondary.addr.len;
		s.netaddr.buf = neta;
		s.rnetaddr.buf = rneta;
		bcopy(urdc->primary.addr.buf, s.netaddr.buf, s.netaddrlen);
		bcopy(urdc->secondary.addr.buf, s.rnetaddr.buf, s.rnetaddrlen);
		s.netaddr.len = urdc->primary.addr.len;
		s.rnetaddr.len = urdc->secondary.addr.len;
		s.netaddr.maxlen = urdc->primary.addr.len;
		s.rnetaddr.maxlen = urdc->secondary.addr.len;
		sp = (unsigned short *)s.netaddr.buf;
		*sp = htons(*sp);
		sp = (unsigned short *)s.rnetaddr.buf;
		*sp = htons(*sp);
		s.pfile = urdc->primary.file;
		s.sfile = urdc->secondary.file;
		s.flag = options;

		err = rdc_clnt_call(krdc->lsrv, RDCPROC_STATE,
		    krdc->rpc_version, xdr_set_state, (char *)&s, xdr_int,
		    (char *)&remote_index, &t);
	}

	if (err)
		return (-1);
	else
		return (remote_index);
}


/*
 * rdc_net_getbmap
 * gets the bitmaps from remote side and or's them  with remote bitmap
 */
int
rdc_net_getbmap(int index, int size)
{
	struct timeval t;
	int err;
	struct bmap b;
	struct bmap6 b6;
	rdc_k_info_t *krdc;

	krdc = &rdc_k_info[index];

	if (krdc->remote_index < 0)
		return (EINVAL);

	t.tv_sec = rdc_rpc_tmout;
	t.tv_usec = 0;
#ifdef DEBUG
	if (krdc->intf == NULL)
		cmn_err(CE_WARN,
		    "rdc_net_getbmap: null intf for index %d", index);
#endif

	if (krdc->rpc_version <= RDC_VERSION5) {
		b.cd = krdc->remote_index;
		b.dual = index;
		b.size = size;
		err = rdc_clnt_call(krdc->lsrv, RDCPROC_BMAP,
		    krdc->rpc_version, xdr_bmap, (char *)&b, xdr_int,
		    (char *)&err, &t);

	} else {
		b6.cd = krdc->remote_index;
		b6.dual = index;
		b6.size = size;
		err = rdc_clnt_call(krdc->lsrv, RDCPROC_BMAP6,
		    krdc->rpc_version, xdr_bmap6, (char *)&b6, xdr_int,
		    (char *)&err, &t);
	}
	return (err);
}

int sndr_proto = 0;

/*
 * return state corresponding to rdc_host
 */
int
rdc_net_getstate(rdc_k_info_t *krdc, int *serial_mode, int *use_mirror,
    int *mirror_down, int network)
{
	int err;
	struct timeval t;
	int state;
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];
	struct set_state s;
#ifdef sparc
	struct set_state4 s4;
#endif
	char neta[32];
	char rneta[32];
	unsigned short *sp;
	char *setp = (char *)&s;
	xdrproc_t xdr_proc = xdr_set_state;

	if (krdc->lsrv && (krdc->intf == NULL || krdc->intf->if_down) &&
	    network) /* fail fast */
		return (-1);

	s.netaddrlen = urdc->primary.addr.len;
	s.rnetaddrlen = urdc->secondary.addr.len;
	s.pfile = urdc->primary.file;
	s.sfile = urdc->secondary.file;
	s.netaddr.buf = neta;
	s.rnetaddr.buf = rneta;
	bcopy(urdc->primary.addr.buf, s.netaddr.buf, s.netaddrlen);
	bcopy(urdc->secondary.addr.buf, s.rnetaddr.buf, s.rnetaddrlen);
	sp = (unsigned short *) s.netaddr.buf;
	*sp = htons(*sp);
	sp = (unsigned short *) s.rnetaddr.buf;
	*sp = htons(*sp);
	s.netaddr.len = urdc->primary.addr.len;
	s.rnetaddr.len = urdc->secondary.addr.len;
	s.netaddr.maxlen = urdc->primary.addr.maxlen;
	s.rnetaddr.maxlen = urdc->secondary.addr.maxlen;
	s.flag = 0;

	t.tv_sec = rdc_rpc_tmout;
	t.tv_usec = 0;

	if (sndr_proto)
		krdc->rpc_version = sndr_proto;
	else
		krdc->rpc_version = RDC_VERS_MAX;

again:
	err = rdc_clnt_call(krdc->lsrv, RDCPROC_GETSTATE4, krdc->rpc_version,
	    xdr_proc, setp, xdr_int, (char *)&state, &t);

	if (err == RPC_PROGVERSMISMATCH && (krdc->rpc_version !=
		RDC_VERS_MIN)) {
		if (krdc->rpc_version-- == RDC_VERSION7) {
			/* set_state struct changed with v7 of protocol */
#ifdef sparc
			s4.netaddrlen = urdc->primary.addr.len;
			s4.rnetaddrlen = urdc->secondary.addr.len;
			bcopy(urdc->primary.addr.buf, s4.netaddr,
			    s4.netaddrlen);
			bcopy(urdc->secondary.addr.buf, s4.rnetaddr,
			s4.rnetaddrlen);
			(void) strncpy(s4.pfile, urdc->primary.file,
			    RDC_MAXNAMLEN);
			(void) strncpy(s4.sfile, urdc->secondary.file,
			    RDC_MAXNAMLEN);
			s4.flag = 0;
			xdr_proc = xdr_set_state4;
			setp = (char *)&s4;
#else
			/* x64 can not use protocols < 7 */
			return (-1);
#endif
		}
		goto again;
	}
#ifdef DEBUG
	cmn_err(CE_NOTE, "sndr get_state: Protocol ver %d", krdc->rpc_version);
#endif

	if (err) {
		return (-1);
	}

	if (state == -1)
		return (-1);

	if (serial_mode)
		*serial_mode = (state >> 2) & 1;
	if (use_mirror)
		*use_mirror = (state >> 1) & 1;
	if (mirror_down)
		*mirror_down = state & 1;

	return (0);
}


static struct xdr_discrim rdres_discrim[2] = {
	{ (int)RDC_OK, xdr_readok },
	{ __dontcare__, NULL_xdrproc_t }
};


/*
 * Reply from remote read (client side)
 */
static bool_t
xdr_rdresult(XDR *xdrs, readres *rr)
{

	return (xdr_union(xdrs, (enum_t *)&(rr->rr_status),
		(caddr_t)&(rr->rr_ok), rdres_discrim, xdr_void));
}

static int
rdc_rrstatus_decode(int status)
{
	int ret = 0;

	if (status != RDC_OK) {
		switch (status) {
		case RDCERR_NOENT:
			ret = ENOENT;
			break;
		case RDCERR_NOMEM:
			ret = ENOMEM;
			break;
		default:
			ret = EIO;
			break;
		}
	}

	return (ret);
}


int
rdc_net_read(int local_index, int remote_index, nsc_buf_t *handle,
    nsc_off_t fba_pos, nsc_size_t fba_len)
{
	struct rdcrdresult rr;
	rdc_k_info_t *krdc;
	rdc_u_info_t *urdc;
	struct rread list;
	struct rread6 list6;
	struct timeval t;
	uchar_t *sv_addr;
	nsc_vec_t *vec;
	int rpc_flag;
	nsc_size_t sv_len;
	int err;
	int ret;
	nsc_size_t len;
	nsc_size_t maxfbas;
	int transflag;

	if (handle == NULL)
		return (EINVAL);

	if (!RDC_HANDLE_LIMITS(handle, fba_pos, fba_len)) {
#ifdef DEBUG
		cmn_err(CE_NOTE, "rdc_net_read: handle bounds");
#endif
		return (EINVAL);
	}

	krdc = &rdc_k_info[local_index];
	urdc = &rdc_u_info[local_index];

	maxfbas = MAX_RDC_FBAS;

	if (krdc->remote_fd && !(rdc_get_vflags(urdc) & RDC_FCAL_FAILED)) {
		nsc_buf_t *remote_h = NULL;
		int reserved = 0;

		ret = nsc_reserve(krdc->remote_fd, NSC_MULTI);
		if (RDC_SUCCESS(ret)) {
			reserved = 1;
			ret = nsc_alloc_buf(krdc->remote_fd, fba_pos, fba_len,
			    NSC_RDBUF, &remote_h);
		}
		if (RDC_SUCCESS(ret)) {
			ret = nsc_copy(remote_h, handle, fba_pos, fba_pos,
			    fba_len);
			if (RDC_SUCCESS(ret)) {
				(void) nsc_free_buf(remote_h);
				nsc_release(krdc->remote_fd);
				return (0);
			}
		}
		rdc_group_enter(krdc);
		rdc_set_flags(urdc, RDC_FCAL_FAILED);
		rdc_group_exit(krdc);
		if (remote_h)
			(void) nsc_free_buf(remote_h);
		if (reserved)
			nsc_release(krdc->remote_fd);
	}

	t.tv_sec = rdc_rpc_tmout;
	t.tv_usec = 0;

	if (rdc_get_vflags(urdc) & RDC_VOL_FAILED)
		rpc_flag = RDC_RREAD_FAIL;
	else
		rpc_flag = 0;

#ifdef DEBUG
	if (krdc->intf == NULL)
		cmn_err(CE_WARN,
		    "rdc_net_read: null intf for index %d", local_index);
#endif
	/*
	 * switch on proto version.
	 */
	len = fba_len;		/* length (FBAs) still to xfer */
	rr.rr_bufsize = 0;	/* rpc data buffer length (bytes) */
	rr.rr_data = NULL;	/* rpc data buffer */
	transflag = rpc_flag | RDC_RREAD_START;	/* setup rpc */
	if (krdc->rpc_version <= RDC_VERSION5) {
		ASSERT(fba_pos <= INT32_MAX);
		list.pos = (int)fba_pos; /* fba position of start of chunk */
		list.cd = remote_index;	/* remote end cd */
		/* send setup rpc */
		list.flag = transflag;
		ASSERT(len <= INT32_MAX);
		list.len = (int)len;			/* total fba length */
		err = rdc_clnt_call(krdc->lsrv, RDCPROC_READ5,
		    krdc->rpc_version, xdr_rread, (char *)&list, xdr_int,
		    (char *)&ret, &t);

	} else {
		list6.pos = fba_pos;	/* fba position of start of chunk */
		list6.cd = remote_index;	/* remote end cd */
		/* send setup rpc */
		list6.flag = transflag;	/* setup rpc */
		ASSERT(len <= INT32_MAX);
		list6.len = (int)len;			/* total fba length */
		err = rdc_clnt_call(krdc->lsrv, RDCPROC_READ6,
		    krdc->rpc_version, xdr_rread6, (char *)&list6, xdr_int,
		    (char *)&ret, &t);
	}

	if (err) {
#ifdef DEBUG
		cmn_err(CE_NOTE, "rdc_net_read: setup err %d", err);
#endif
		if (err == RPC_INTR)
			ret = EINTR;
		else
			ret = ENOLINK;

		goto remote_rerror;
	}

	if (ret == 0) {		/* No valid index from r_net_read */
#ifdef DEBUG
		cmn_err(CE_NOTE,
		    "rdc_net_read: no valid index from r_net_read");
#endif
		return (ENOBUFS);
	}
	transflag = rpc_flag | RDC_RREAD_DATA;
	if (krdc->rpc_version <= RDC_VERSION5) {
		list.idx = ret;		/* save idx to return to server */
		list.flag = transflag;
					/* move onto to data xfer rpcs */
	} else {
		list6.idx = ret;	/* save idx to return to server */
		list6.flag = transflag;
	}

	/* find starting position in handle */

	vec = handle->sb_vec;

	fba_pos -= handle->sb_pos;

	for (; fba_pos >= FBA_NUM(vec->sv_len); vec++)
		fba_pos -= FBA_NUM(vec->sv_len);

	sv_addr = vec->sv_addr + FBA_SIZE(fba_pos);	/* data in vector */
	sv_len = vec->sv_len - FBA_SIZE(fba_pos);	/* bytes in vector */

	while (len) {
		nsc_size_t translen;
		if (len > maxfbas) {
			translen = maxfbas;
		} else {
			translen = len;
		}

		if (FBA_SIZE(translen) > sv_len) {
			translen = FBA_NUM(sv_len);
		}

		len -= translen;
		if (len == 0) {
			/* last data xfer rpc - tell server to cleanup */
			transflag |= RDC_RREAD_END;
		}

		if (!rr.rr_data || (nsc_size_t)rr.rr_bufsize !=
		    FBA_SIZE(translen)) {
			if (rr.rr_data)
				kmem_free(rr.rr_data, rr.rr_bufsize);

			ASSERT(FBA_SIZE(translen) <= INT32_MAX);
			rr.rr_bufsize = FBA_SIZE(translen);
			rr.rr_data = kmem_alloc(rr.rr_bufsize, KM_NOSLEEP);
		}

		if (!rr.rr_data) {
			/* error */
#ifdef DEBUG
			cmn_err(CE_NOTE, "rdc_net_read: kmem_alloc failed");
#endif
			return (ENOMEM);
		}

		/* get data from remote end */

#ifdef DEBUG
		if (krdc->intf == NULL)
			cmn_err(CE_WARN,
			    "rdc_net_read: null intf for index %d",
			    local_index);
#endif
		if (krdc->io_kstats) {
			mutex_enter(krdc->io_kstats->ks_lock);
			kstat_runq_enter(KSTAT_IO_PTR(krdc->io_kstats));
			mutex_exit(krdc->io_kstats->ks_lock);
		}
		/*CONSTCOND*/
		ASSERT(RDC_MAXDATA <= INT32_MAX);
		ASSERT(translen <= RDC_MAXDATA);
		if (krdc->rpc_version <= RDC_VERSION5) {
			list.len = (int)translen;
			list.flag = transflag;
			err = rdc_clnt_call(krdc->lsrv, RDCPROC_READ5,
			    krdc->rpc_version, xdr_rread, (char *)&list,
			    xdr_rdresult, (char *)&rr, &t);
		} else {
			list6.len = (int)translen;
			list6.flag = transflag;
			err = rdc_clnt_call(krdc->lsrv, RDCPROC_READ6,
			    krdc->rpc_version, xdr_rread6, (char *)&list6,
			    xdr_rdresult, (char *)&rr, &t);
		}

		if (krdc->io_kstats) {
			mutex_enter(krdc->io_kstats->ks_lock);
			kstat_runq_exit(KSTAT_IO_PTR(krdc->io_kstats));
			mutex_exit(krdc->io_kstats->ks_lock);
		}

		if (err) {
#ifdef DEBUG
			cmn_err(CE_NOTE, "rdc_net_read: rpc err %d", err);
#endif
			if (err == RPC_INTR) {
				ret = EINTR;
			} else {
				ret = ENOLINK;
			}

			goto remote_rerror;
		}

		if (rr.rr_status != RDC_OK) {
			ret = rdc_rrstatus_decode(rr.rr_status);
			if (!ret)
				ret = EIO;

			goto remote_rerror;
		}

		/* copy into handle */

		bcopy(rr.rr_data, sv_addr, (size_t)rr.rr_bufsize);

		/* update counters */

		sv_addr += rr.rr_bufsize;
		if (krdc->rpc_version <= RDC_VERSION5) {
			list.pos += translen;
		} else {
			list6.pos += translen;
		}
		if (krdc->io_kstats) {
			KSTAT_IO_PTR(krdc->io_kstats)->reads++;
			KSTAT_IO_PTR(krdc->io_kstats)->nread += rr.rr_bufsize;
		}
		ASSERT(sv_len <= INT32_MAX);
		ASSERT(sv_len >= (nsc_size_t)rr.rr_bufsize);
		sv_len -= rr.rr_bufsize;

		if (sv_len == 0) {
			/* goto next vector */
			vec++;
			sv_addr = vec->sv_addr;
			sv_len = vec->sv_len;
		}
	}

	if (rr.rr_data)
		kmem_free(rr.rr_data, rr.rr_bufsize);

	return (0);

remote_rerror:
	if (rr.rr_data)
		kmem_free(rr.rr_data, rr.rr_bufsize);

	return (ret ? ret : ENOLINK);
}

/*
 * rdc_net_write
 * Main remote write client side
 * Handles protocol selection as well as requests for remote allocation
 * and data transfer
 * Does local IO for FCAL
 * caller must clear bitmap on success
 */

int
rdc_net_write(int local_index, int remote_index, nsc_buf_t *handle,
    nsc_off_t fba_pos, nsc_size_t fba_len, uint_t aseq, int qpos,
    netwriteres *netres)
{
	rdc_k_info_t *krdc;
	rdc_u_info_t *urdc;
	struct timeval t;
	nsc_vec_t *vec;
	int sv_len;
	nsc_off_t fpos;
	int err;
	struct netwriteres netret;
	struct netwriteres *netresptr;
	struct net_data5 dlist5;
	struct net_data6 dlist6;
	int ret;
	nsc_size_t maxfbas;
	int transflag;
	int translen;
	int transendoblk;
	char *transptr;
	int vflags;

	if (handle == NULL)
		return (EINVAL);

	/* if not a diskq buffer */
	if ((qpos == -1) && (!RDC_HANDLE_LIMITS(handle, fba_pos, fba_len))) {
#ifdef DEBUG
		cmn_err(CE_NOTE, "rdc_net_write: handle bounds");
#endif
		return (EINVAL);
	}


	t.tv_sec = rdc_rpc_tmout;
	t.tv_usec = 0;

	krdc = &rdc_k_info[local_index];
	urdc = &rdc_u_info[local_index];

	maxfbas = MAX_RDC_FBAS;

	/* FCAL IO */
	if (krdc->remote_fd && !(rdc_get_vflags(urdc) & RDC_FCAL_FAILED)) {
		nsc_buf_t *remote_h = NULL;
		int reserved = 0;

		ret = nsc_reserve(krdc->remote_fd, NSC_MULTI);
		if (RDC_SUCCESS(ret)) {
			reserved = 1;
			ret = nsc_alloc_buf(krdc->remote_fd, fba_pos, fba_len,
			    NSC_WRBUF, &remote_h);
		}
		if (RDC_SUCCESS(ret)) {
			ret = nsc_copy(handle, remote_h, fba_pos, fba_pos,
			    fba_len);
			if (RDC_SUCCESS(ret))
				ret = nsc_write(remote_h, fba_pos, fba_len, 0);
			if (RDC_SUCCESS(ret)) {
				(void) nsc_free_buf(remote_h);
				nsc_release(krdc->remote_fd);
				return (0);
			}
		}
		rdc_group_enter(krdc);
		rdc_set_flags(urdc, RDC_FCAL_FAILED);
		rdc_group_exit(krdc);
		if (remote_h)
			(void) nsc_free_buf(remote_h);
		if (reserved)
			nsc_release(krdc->remote_fd);
	}

	/*
	 * At this point we must decide which protocol we are using and
	 * do the right thing
	 */
	netret.vecdata.vecdata_val = NULL;
	netret.vecdata.vecdata_len = 0;
	if (netres) {
		netresptr = netres;
	} else {
		netresptr = &netret;
	}

	vflags = rdc_get_vflags(urdc);

	if (vflags & (RDC_VOL_FAILED|RDC_BMP_FAILED))
		transflag = RDC_RWRITE_FAIL;
	else
		transflag = 0;


#ifdef DEBUG
	if (krdc->intf == NULL)
		cmn_err(CE_WARN,
			"rdc_net_write: null intf for index %d",
			local_index);
#endif

	vec = handle->sb_vec;

	/*
	 * find starting position in vector
	 */
	if ((qpos == -1) || (handle->sb_user == RDC_NULLBUFREAD))
		fpos = fba_pos - handle->sb_pos;
	else
		fpos = (qpos + 1) - handle->sb_pos;

	for (; fpos >= FBA_NUM(vec->sv_len); vec++)
		fpos -= FBA_NUM(vec->sv_len);
	sv_len = vec->sv_len - FBA_SIZE(fpos);	/* bytes in vector */
	transptr = (char *)vec->sv_addr + FBA_SIZE(fpos);

	if (krdc->rpc_version <= RDC_VERSION5) {
		dlist5.local_cd = local_index;
		dlist5.cd = remote_index;
		ASSERT(fba_len <= INT32_MAX);
		ASSERT(fba_pos <= INT32_MAX);
		dlist5.len = (int)fba_len;
		dlist5.pos = (int)fba_pos;
		dlist5.idx = -1; /* Starting index */
		dlist5.flag = transflag;
		dlist5.seq = aseq;		/* sequence number */
		dlist5.sfba = (int)fba_pos;	/* starting fba for this xfer */
	} else {
		dlist6.local_cd = local_index;
		dlist6.cd = remote_index;
		ASSERT(fba_len <= INT32_MAX);
		dlist6.len = (int)fba_len;
		dlist6.qpos = qpos;
		dlist6.pos = fba_pos;
		dlist6.idx = -1; /* Starting index */
		dlist6.flag = transflag;
		dlist6.seq = aseq;		/* sequence number */
		dlist6.sfba = fba_pos;		/* starting fba for this xfer */
	}

	transendoblk = 0;
	while (fba_len) {
		if (!transptr) {
#ifdef DEBUG
			cmn_err(CE_WARN,
			    "rdc_net_write: walked off end of handle!");
#endif
			ret = EINVAL;
			goto remote_error;
		}

		if (fba_len > maxfbas) {
			ASSERT(maxfbas <= INT32_MAX);
			translen = (int)maxfbas;
		} else {
			ASSERT(fba_len <= INT32_MAX);
			translen = (int)fba_len;
		}

		if (FBA_SIZE(translen) > sv_len) {
			translen = FBA_NUM(sv_len);
		}

		fba_len -= translen;
		if (fba_len == 0) {
			/* last data xfer - tell server to commit */
			transendoblk = 1;
		}


#ifdef DEBUG
		if (krdc->intf == NULL)
			cmn_err(CE_WARN,
			    "rdc_net_write: null intf for index %d",
			    local_index);
#endif
		DTRACE_PROBE(rdc_netwrite_clntcall_start);

		if (krdc->io_kstats) {
			mutex_enter(krdc->io_kstats->ks_lock);
			kstat_runq_enter(KSTAT_IO_PTR(krdc->io_kstats));
			mutex_exit(krdc->io_kstats->ks_lock);
		}
		if (krdc->rpc_version <= RDC_VERSION5) {
			ret = 0;
			dlist5.nfba = translen;
			dlist5.endoblk = transendoblk;
			dlist5.data.data_len = FBA_SIZE(translen);
			dlist5.data.data_val = transptr;
			err = rdc_clnt_call(krdc->lsrv, RDCPROC_WRITE5,
			    krdc->rpc_version, xdr_net_data5,
			    (char *)&dlist5, xdr_int,
			    (char *)&ret, &t);
			if (ret >= 0) {
				netresptr->result = 0;
				netresptr->index = ret;
			} else {
				netresptr->result = ret;
			}
		} else {
			netresptr->result = 0;
			dlist6.nfba = translen;
			dlist6.endoblk = transendoblk;
			dlist6.data.data_len = FBA_SIZE(translen);
			dlist6.data.data_val = transptr;
			err = rdc_clnt_call(krdc->lsrv, RDCPROC_WRITE6,
			    krdc->rpc_version, xdr_net_data6,
			    (char *)&dlist6, xdr_netwriteres,
			    (char *)netresptr, &t);
		}

		if (krdc->io_kstats) {
			mutex_enter(krdc->io_kstats->ks_lock);
			kstat_runq_exit(KSTAT_IO_PTR(krdc->io_kstats));
			mutex_exit(krdc->io_kstats->ks_lock);
		}

		DTRACE_PROBE(rdc_netwrite_clntcall_end);
		ret = netresptr->result;
		if (err) {
			if (err == RPC_INTR)
				ret = EINTR;
			else if (err && ret != EPROTO)
				ret = ENOLINK;
#ifdef DEBUG
			cmn_err(CE_NOTE,
				"rdc_net_write(5): cd %d err %d ret %d",
				remote_index, err, ret);
#endif
			goto remote_error;
		}
		/* Error from r_net_write5 */
		if (netresptr->result < 0) {
#ifdef DEBUG
			cmn_err(CE_NOTE,
			    "rdc_net_write: r_net_write(5) "
			    "returned: %d",
			    -netresptr->result);
#endif
			ret = -netresptr->result;
			if (netret.vecdata.vecdata_val)
				kmem_free(netret.vecdata.vecdata_val,
				    netret.vecdata.vecdata_len *
				    sizeof (net_pendvec_t));
			goto remote_error;
		} else if (netresptr->index == 0) {
#ifdef DEBUG
			cmn_err(CE_NOTE,
			    "rdc_net_write: no valid index from "
			    "r_net_write(5)");
#endif
			ret = ENOBUFS;
			if (netret.vecdata.vecdata_val)
				kmem_free(netret.vecdata.vecdata_val,
				    netret.vecdata.vecdata_len *
				    sizeof (net_pendvec_t));
			goto remote_error;
		}
		if (krdc->rpc_version <= RDC_VERSION5) {
			dlist5.idx = netresptr->index;
			dlist5.sfba += dlist5.nfba;
		} else {
			dlist6.idx = netresptr->index;
			dlist6.sfba += dlist6.nfba;
		}
		/* update counters */
		if (krdc->io_kstats) {
			KSTAT_IO_PTR(krdc->io_kstats)->writes++;
			KSTAT_IO_PTR(krdc->io_kstats)->nwritten +=
				FBA_SIZE(translen);
		}
		transptr += FBA_SIZE(translen);
		sv_len -= FBA_SIZE(translen);

		if (sv_len <= 0) {
			/* goto next vector */
			vec++;
			transptr = (char *)vec->sv_addr;
			sv_len = vec->sv_len;
		}
	}
	/*
	 * this can't happen.....
	 */
	if (netret.vecdata.vecdata_val)
		kmem_free(netret.vecdata.vecdata_val,
		    netret.vecdata.vecdata_len *
		    sizeof (net_pendvec_t));

	return (0);

remote_error:
	return (ret ? ret : ENOLINK);
}

void
rdc_fixlen(rdc_aio_t *aio)
{
	nsc_vec_t *vecp = aio->qhandle->sb_vec;
	nsc_size_t len = 0;

	while (vecp->sv_addr) {
		len += FBA_NUM(vecp->sv_len);
		vecp++;
	}
	aio->qhandle->sb_len = len;
}

/*
 * rdc_dump_alloc_bufs_cd
 * Dump allocated buffers (rdc_net_hnd's) for the specified cd.
 * this could be the flusher failing, if so, don't do the delay forever
 * Returns: 0 (success), EAGAIN (caller needs to try again).
 */
int
rdc_dump_alloc_bufs_cd(int index)
{
	rdc_k_info_t *krdc;
	rdc_aio_t *aio;
	net_queue *q;
	disk_queue *dq;
	kmutex_t *qlock;

	krdc = &rdc_k_info[index];


	if (!krdc->c_fd) {
		/* cannot do anything! */
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_dump_alloc_bufs_cd(%d): c_fd NULL",
		    index);
#endif
		return (0);
	}
	rdc_dump_dsets(index);

	dq = &krdc->group->diskq;

	if (RDC_IS_DISKQ(krdc->group)) {
		qlock = QLOCK(dq);
		(void) _rdc_rsrv_diskq(krdc->group);
	} else {
		qlock = &krdc->group->ra_queue.net_qlock;
	}

	/*
	 * Now dump the async queue anonymous buffers
	 * if we are a diskq, the we are using the diskq mutex.
	 * However, we are flushing from diskq to memory queue
	 * so we now need to grab the memory lock also
	 */

	q = &krdc->group->ra_queue;

	if (RDC_IS_DISKQ(krdc->group)) {
		mutex_enter(&q->net_qlock);
		if (q->qfill_sleeping == RDC_QFILL_AWAKE) {
			int tries = 5;
#ifdef DEBUG_DISKQ
			cmn_err(CE_NOTE,
			    "dumpalloccd sending diskq->memq flusher to sleep");
#endif
			q->qfflags |= RDC_QFILLSLEEP;
			mutex_exit(&q->net_qlock);

			while (q->qfill_sleeping == RDC_QFILL_AWAKE && tries--)
				delay(5);
			mutex_enter(&q->net_qlock);
		}
	}

	mutex_enter(qlock);

	while ((q->net_qhead != NULL)) {
		rdc_k_info_t *tmpkrdc;
		aio = q->net_qhead;
		tmpkrdc = &rdc_k_info[aio->index];

		if (RDC_IS_DISKQ(krdc->group)) {
			aio->qhandle->sb_user--;
			if (aio->qhandle->sb_user == 0) {
				rdc_fixlen(aio);
				(void) nsc_free_buf(aio->qhandle);
				aio->qhandle = NULL;
				aio->handle = NULL;
			}
		} else {
			if (aio->handle) {
				(void) nsc_free_buf(aio->handle);
				aio->handle = NULL;
			}
		}

		if (tmpkrdc->io_kstats && !RDC_IS_DISKQ(krdc->group)) {
			mutex_enter(tmpkrdc->io_kstats->ks_lock);
			kstat_waitq_exit(KSTAT_IO_PTR(tmpkrdc->io_kstats));
			mutex_exit(tmpkrdc->io_kstats->ks_lock);
		}
		q->net_qhead = q->net_qhead->next;
		q->blocks -= aio->len;
		q->nitems--;

		RDC_CHECK_BIT(tmpkrdc, aio->pos, aio->len);

		kmem_free(aio, sizeof (*aio));
	}
	q->net_qtail = NULL;

	if (krdc->group->asyncstall) {
		krdc->group->asyncdis = 1;
		cv_broadcast(&krdc->group->asyncqcv);
	}
	if (krdc->group->sleepq) {
		rdc_sleepqdiscard(krdc->group);
	}

	krdc->group->seq = RDC_NEWSEQ;
	krdc->group->seqack = RDC_NEWSEQ;
	if (RDC_IS_DISKQ(krdc->group)) {
		rdc_dump_iohdrs(dq);
		SET_QNXTIO(dq, QHEAD(dq));
		SET_QCOALBOUNDS(dq, QHEAD(dq));
	}
	mutex_exit(qlock);

	if (RDC_IS_DISKQ(krdc->group)) {
		mutex_exit(&q->net_qlock);
		_rdc_rlse_diskq(krdc->group);
	}

	return (0);
}


/*
 * rdc_dump_alloc_bufs
 * We have an error on the link
 * Try to dump all of the allocated bufs so we can cleanly recover
 * and not hang
 */
void
rdc_dump_alloc_bufs(rdc_if_t *ip)
{
	rdc_k_info_t *krdc;
	int repeat;
	int index;

	for (index = 0; index < rdc_max_sets; index++) {
		do {
			krdc = &rdc_k_info[index];
			repeat = 0;
			if (krdc->intf == ip) {
				if (rdc_dump_alloc_bufs_cd(index) == EAGAIN) {
					repeat = 1;
					delay(2);
				}
			}
		} while (repeat);
	}
}

/*
 * returns 1 if the the throttle should throttle, 0 if not.
 */
int
_rdc_diskq_isfull(disk_queue *q, long len)
{
	/* ---T----H----N--- */
	mutex_enter(QLOCK(q));

	if (FITSONQ(q, len + 1)) {
		mutex_exit(QLOCK(q));
		return (0);
	}
	mutex_exit(QLOCK(q));
	return (1);
}

void
_rdc_async_throttle(rdc_k_info_t *this, long len)
{
	rdc_k_info_t *krdc;
	rdc_u_info_t *urdc;
	int print_msg = 1;
	int tries = RDC_FUTILE_ATTEMPTS;

	/*
	 * Throttle entries on queue
	 */

	/* Need to take the 1-many case into account, checking all sets */

	/* ADD HANDY HUERISTIC HERE TO SLOW DOWN IO */
	for (krdc = this; /* CSTYLED */; krdc = krdc->many_next) {
		urdc = &rdc_u_info[krdc->index];

		/*
		 * this may be the last set standing in a one to many setup.
		 * we may also be stuck in unintercept, after marking
		 * the volume as not enabled, but have not removed it
		 * from the many list resulting in an endless loop if
		 * we just continue here. Lets jump over this stuff
		 * and check to see if we are the only dude here.
		 */
		if (!IS_ENABLED(urdc))
			goto thischeck;

		if (IS_ASYNC(urdc) && RDC_IS_MEMQ(krdc->group)) {
			net_queue *q = &krdc->group->ra_queue;
			while ((q->blocks + q->inflbls) > urdc->maxqfbas ||
			    (q->nitems + q->inflitems) > urdc->maxqitems) {

				if (!IS_ENABLED(urdc)) /* disable race */
					goto thischeck;

				if (!krdc->group->rdc_writer)
					(void) rdc_writer(krdc->index);
				delay(2);
				q->throttle_delay++;
			}
		}

		/* do a much more aggressive delay, get disk flush going */
		if (IS_ASYNC(urdc) && RDC_IS_DISKQ(krdc->group)) {
			disk_queue *q = &krdc->group->diskq;
			while ((!IS_QSTATE(q, RDC_QNOBLOCK)) &&
			    (_rdc_diskq_isfull(q, len)) &&
			    (!IS_STATE(urdc, RDC_DISKQ_FAILED))) {
				if (print_msg) {
					cmn_err(CE_WARN, "rdc async throttle:"
					    " disk queue %s full",
					    &urdc->disk_queue[0]);

					print_msg = 0;
				}
				if (!IS_ENABLED(urdc)) /* disable race */
					goto thischeck;

				if (!krdc->group->rdc_writer)
					(void) rdc_writer(krdc->index);
				delay(10);
				q->throttle_delay += 10;

				if (!(tries--) && IS_STATE(urdc, RDC_QUEUING)) {
	cmn_err(CE_WARN, "SNDR: disk queue %s full and not flushing. giving up",
	    &urdc->disk_queue[0]);
	cmn_err(CE_WARN, "SNDR: %s:%s entering logging mode",
	    urdc->secondary.intf, urdc->secondary.file);
					rdc_fail_diskq(krdc, RDC_WAIT,
					    RDC_DOLOG | RDC_NOFAIL);
					mutex_enter(QLOCK(q));
					cv_broadcast(&q->qfullcv);
					mutex_exit(QLOCK(q));
				}

			}
			if ((IS_QSTATE(q, RDC_QNOBLOCK)) &&
			    _rdc_diskq_isfull(q, len) &&
			    !IS_STATE(urdc, RDC_DISKQ_FAILED)) {
				if (print_msg) {
					cmn_err(CE_WARN, "disk queue %s full",
					    &urdc->disk_queue[0]);
					print_msg = 0;
				}
				rdc_fail_diskq(krdc, RDC_WAIT,
				    RDC_DOLOG | RDC_NOFAIL);
				mutex_enter(QLOCK(q));
				cv_broadcast(&q->qfullcv);
				mutex_exit(QLOCK(q));
			}
		}

thischeck:
		if (krdc->many_next == this)
			break;
	}
}

int rdc_coalesce = 1;
static int rdc_joins = 0;

int
rdc_aio_coalesce(rdc_aio_t *queued, rdc_aio_t *new)
{
	nsc_buf_t *h = NULL;
	int rc;
	rdc_k_info_t *krdc;
	uint_t bitmask;

	if (rdc_coalesce == 0)
		return (0);		/* don't even try */

	if ((queued == NULL) ||
	    (queued->handle == NULL) ||
	    (new->handle == NULL)) {
		return (0);		/* existing queue is empty */
	}
	if (queued->index != new->index || queued->len + new->len >
	    MAX_RDC_FBAS) {
		return (0);		/* I/O to big */
	}
	if ((queued->pos + queued->len == new->pos) ||
	    (new->pos + new->len == queued->pos)) {
		rc = nsc_alloc_abuf(queued->pos, queued->len + new->len, 0,
		    &h);
		if (!RDC_SUCCESS(rc)) {
			if (h != NULL)
				(void) nsc_free_buf(h);
			return (0);		/* couldn't do coalesce */
		}
		rc = nsc_copy(queued->handle, h, queued->pos, queued->pos,
		    queued->len);
		if (!RDC_SUCCESS(rc)) {
			(void) nsc_free_buf(h);
			return (0);		/* couldn't do coalesce */
		}
		rc = nsc_copy(new->handle, h, new->pos, new->pos,
		    new->len);
		if (!RDC_SUCCESS(rc)) {
			(void) nsc_free_buf(h);
			return (0);		/* couldn't do coalesce */
		}

		krdc = &rdc_k_info[queued->index];

		RDC_SET_BITMASK(queued->pos, queued->len, &bitmask);
		RDC_CLR_BITMAP(krdc, queued->pos, queued->len, \
		    bitmask, RDC_BIT_BUMP);

		RDC_SET_BITMASK(new->pos, new->len, &bitmask);
		RDC_CLR_BITMAP(krdc, new->pos, new->len, \
		    bitmask, RDC_BIT_BUMP);

		(void) nsc_free_buf(queued->handle);
		(void) nsc_free_buf(new->handle);
		queued->handle = h;
		queued->len += new->len;
		bitmask = 0;
		/*
		 * bump the ref count back up
		 */

		RDC_SET_BITMAP(krdc, queued->pos, queued->len, &bitmask);
		return (1);	/* new I/O succeeds last I/O queued */
	}
	return (0);
}

int
rdc_memq_enqueue(rdc_k_info_t *krdc, rdc_aio_t *aio)
{
	net_queue *q;
	rdc_group_t *group;

	group = krdc->group;
	q = &group->ra_queue;

	mutex_enter(&q->net_qlock);

	if (rdc_aio_coalesce(q->net_qtail, aio)) {
		rdc_joins++;
		q->blocks += aio->len;
		kmem_free(aio, sizeof (*aio));
		goto out;
	}
	aio->seq = group->seq++;
	if (group->seq < aio->seq)
		group->seq = RDC_NEWSEQ + 1; /* skip magics */

	if (q->net_qhead == NULL) {
		/* adding to empty q */
		q->net_qhead = q->net_qtail = aio;

#ifdef DEBUG
		if (q->blocks != 0 || q->nitems != 0) {
			cmn_err(CE_PANIC,
			"rdc enqueue: q %p, qhead 0, q blocks %" NSC_SZFMT
			", nitems %" NSC_SZFMT,
				(void *) q, q->blocks, q->nitems);
		}
#endif

	} else {
		/* discontiguous, add aio to q tail */
		q->net_qtail->next = aio;
		q->net_qtail = aio;
	}

	q->blocks += aio->len;
	q->nitems++;

	if (krdc->io_kstats) {
		mutex_enter(krdc->io_kstats->ks_lock);
		kstat_waitq_enter(KSTAT_IO_PTR(krdc->io_kstats));
		mutex_exit(krdc->io_kstats->ks_lock);
	}
out:
#ifdef DEBUG
	/* sum the q and check for sanity */
	{
		nsc_size_t qblocks = 0;
		uint64_t nitems = 0;
		rdc_aio_t *a;

		for (a = q->net_qhead; a != NULL; a = a->next) {
			qblocks += a->len;
			nitems++;
		}

		if (qblocks != q->blocks || nitems != q->nitems) {
			cmn_err(CE_PANIC,
			"rdc enqueue: q %p, q blocks %" NSC_SZFMT " (%"
			NSC_SZFMT "), nitems %" NSC_SZFMT " (%" NSC_SZFMT ")",
				(void *) q, q->blocks, qblocks, q->nitems,
				nitems);
		}
	}
#endif

	mutex_exit(&q->net_qlock);

	if (q->nitems > q->nitems_hwm) {
		q->nitems_hwm = q->nitems;
	}

	if (q->blocks > q->blocks_hwm) {
		q->blocks_hwm = q->blocks;
	}

	if (!krdc->group->rdc_writer)
		(void) rdc_writer(krdc->index);

	return (0);
}

int
_rdc_enqueue_write(rdc_k_info_t *krdc, nsc_off_t pos, nsc_size_t len, int flag,
    nsc_buf_t *h)
{
	rdc_aio_t *aio;
	rdc_group_t *group;
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];
	int rc;

	aio = kmem_zalloc(sizeof (*aio), KM_NOSLEEP);
	if (!aio) {
		return (ENOMEM);
	}

	group = krdc->group;

	aio->pos = pos;
	aio->qpos = -1;
	aio->len = len;
	aio->flag = flag;
	aio->index = krdc->index;
	aio->handle = h;

	if (group->flags & RDC_MEMQUE) {
		return (rdc_memq_enqueue(krdc, aio));
	} else if ((group->flags & RDC_DISKQUE) &&
	    !IS_STATE(urdc, RDC_DISKQ_FAILED)) {
		rc = rdc_diskq_enqueue(krdc, aio);
		kmem_free(aio, sizeof (*aio));
		return (rc);
	}
	return (-1); /* keep lint quiet */
}




/*
 * Async Network RDC flusher
 */

/*
 * don't allow any new writer threads to start if a member of the set
 * is disable pending
 */
int
is_disable_pending(rdc_k_info_t *krdc)
{
	rdc_k_info_t *this = krdc;
	int rc = 0;

	do {
		if (krdc->type_flag & RDC_DISABLEPEND) {
			krdc = this;
			rc = 1;
			break;
		}
		krdc = krdc->group_next;

	} while (krdc != this);

	return (rc);
}

/*
 * rdc_writer -- spawn new writer if not running already
 *	called after enqueing the dirty blocks
 */
int
rdc_writer(int index)
{
	rdc_k_info_t *krdc = &rdc_k_info[index];
	nsthread_t *t;
	rdc_group_t	*group;
	kmutex_t	*qlock;
	int tries;
	const int MAX_TRIES = 16;

	group = krdc->group;

	if (RDC_IS_DISKQ(group))
		qlock = &group->diskq.disk_qlock;
	else
		qlock = &group->ra_queue.net_qlock;

	mutex_enter(qlock);

#ifdef DEBUG
	if (noflush) {
		mutex_exit(qlock);
		return (0);
	}
#endif

	if ((group->rdc_writer) || is_disable_pending(krdc)) {
		mutex_exit(qlock);
		return (0);
	}

	if ((group->rdc_thrnum >= 1) && (group->seqack == RDC_NEWSEQ)) {
		/*
		 * We also need to check if we are starting a new
		 * sequence, and if so don't create a new thread,
		 * as we must ensure that the start of new sequence
		 * requests arrives first to re-init the server.
		 */
		mutex_exit(qlock);
		return (0);
	}
	/*
	 * For version 6,
	 * see if we can fit in another thread.
	 */
	group->rdc_thrnum++;

	if (krdc->intf && (krdc->intf->rpc_version >= RDC_VERSION6)) {
		rdc_u_info_t *urdc = &rdc_u_info[index];
		if (group->rdc_thrnum >= urdc->asyncthr)
			group->rdc_writer = 1;
	} else {
		group->rdc_writer = 1;
	}

	mutex_exit(qlock);


	/*
	 * If we got here, we know that we have not exceeded the allowed
	 * number of async threads for our group.  If we run out of threads
	 * in _rdc_flset, we add a new thread to the set.
	 */
	tries = 0;
	do {
		/* first try to grab a thread from the free list */
		if (t = nst_create(_rdc_flset, rdc_flusher_thread,
		    (blind_t)(unsigned long)index, 0)) {
			break;
		}

		/* that failed; add a thread to the set and try again */
		if (nst_add_thread(_rdc_flset, 1) != 1) {
			cmn_err(CE_WARN, "rdc_writer index %d nst_add_thread "
			    "error, tries: %d", index, tries);
			break;
		}
	} while (++tries < MAX_TRIES);

	if (tries) {
		mutex_enter(&group->addthrnumlk);
		group->rdc_addthrnum += tries;
		mutex_exit(&group->addthrnumlk);
	}

	if (t) {
		return (1);
	}

	cmn_err(CE_WARN, "rdc_writer: index %d nst_create error", index);
	rdc_many_enter(krdc);
	mutex_enter(qlock);
	group->rdc_thrnum--;
	group->rdc_writer = 0;
	if ((group->count == 0) && (group->rdc_thrnum == 0)) {
		mutex_exit(qlock);
		/*
		 * Race with remove_from_group while write thread was
		 * failing to be created.
		 */
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_writer: group being destroyed");
#endif
		rdc_delgroup(group);
		krdc->group = NULL;
		rdc_many_exit(krdc);
		return (-1);
	}
	mutex_exit(qlock);
	rdc_many_exit(krdc);
	return (-1);
}

/*
 * Either we need to flush the
 * kmem (net_queue) queue or the disk (disk_queue)
 * determine which, and do it.
 */
void
rdc_flusher_thread(int index)
{
	rdc_k_info_t *krdc = &rdc_k_info[index];

	if (krdc->group->flags & RDC_MEMQUE) {
		rdc_flush_memq(index);
		return;
	} else if (krdc->group->flags & RDC_DISKQUE) {
		rdc_flush_diskq(index);
		return;
	} else { /* uh-oh, big time */
		cmn_err(CE_PANIC, "flusher trying to flush unknown queue type");
	}

}

void
rdc_flush_memq(int index)
{
	rdc_k_info_t *krdc = &rdc_k_info[index];
	rdc_aio_t *aio;
	net_queue *q;
	int dowork;
	rdc_group_t *group = krdc->group;
	if (!group || group->count == 0) {
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_flush_memq: no group left!");
#endif
		return;
	}

	if (!krdc->c_fd) {
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_flush_memq: no c_fd!");
#endif
		goto thread_death;
	}

#ifdef DEBUG_DISABLE
	if (index < 0 || (krdc->type_flag & RDC_DISABLEPEND)) {
		cmn_err(CE_WARN, "rdc_flush_memq: DISABLE PENDING!");
		/*
		 * Need to continue as we may be trying to flush IO
		 * while trying to disable or suspend
		 */
	}
#endif

	q = &group->ra_queue;

	dowork = 1;
	/* CONSTCOND */
	while (dowork) {
		if (net_exit == ATM_EXIT)
			break;

		group = krdc->group;
		if (!group || group->count == 0) {
#ifdef DEBUG
			cmn_err(CE_WARN, "rdc_flush_memq: no group left!");
#endif
			break;
		}

		mutex_enter(&q->net_qlock);
		aio = q->net_qhead;

		if (aio == NULL) {
#ifdef DEBUG
			if (q->nitems != 0 ||
			    q->blocks != 0 ||
			    q->net_qtail != 0) {
				cmn_err(CE_PANIC,
				    "rdc_flush_memq(1): q %p, q blocks %"
				    NSC_SZFMT ", nitems %" NSC_SZFMT
				    ", qhead %p qtail %p",
				    (void *) q, q->blocks, q->nitems,
				    (void *) aio, (void *) q->net_qtail);
			}
#endif
			mutex_exit(&q->net_qlock);
			break;
		}

		/* aio remove from q */

		q->net_qhead = aio->next;
		aio->next = NULL;

		if (q->net_qtail == aio)
			q->net_qtail = q->net_qhead;

		q->blocks -= aio->len;
		q->nitems--;

		/*
		 * in flight numbers.
		 */
		q->inflbls += aio->len;
		q->inflitems++;

#ifdef DEBUG
		if (q->net_qhead == NULL) {
			if (q->nitems != 0 ||
			    q->blocks != 0 ||
			    q->net_qtail != 0) {
				cmn_err(CE_PANIC,
				    "rdc_flush_memq(2): q %p, q blocks %"
				    NSC_SZFMT ", nitems %" NSC_SZFMT
				    ", qhead %p qtail %p",
				    (void *) q, q->blocks, q->nitems,
				    (void *) q->net_qhead,
				    (void *) q->net_qtail);
			}
		}

#ifndef NSC_MULTI_TERABYTE
		if (q->blocks < 0) {
			cmn_err(CE_PANIC,
			    "rdc_flush_memq(3): q %p, q blocks %" NSC_SZFMT
			    ", nitems %d, qhead %p, qtail %p",
			    (void *) q, q->blocks, q->nitems,
			    (void *) q->net_qhead, (void *) q->net_qtail);
		}
#else
		/* blocks and nitems are unsigned for NSC_MULTI_TERABYTE */
#endif
#endif

		mutex_exit(&q->net_qlock);

		aio->iostatus = RDC_IO_INIT;

		_rdc_remote_flush(aio);

		mutex_enter(&q->net_qlock);
		q->inflbls -= aio->len;
		q->inflitems--;
		if ((group->seqack == RDC_NEWSEQ) &&
		    (group->seq != RDC_NEWSEQ + 1)) {
			if ((q->net_qhead == NULL) ||
			    (q->net_qhead->seq != RDC_NEWSEQ + 1)) {
				/*
				 * We are an old thread, and the
				 * queue sequence has been reset
				 * during the network write above.
				 * As such we mustn't pull another
				 * job from the queue until the
				 * first sequence message has been ack'ed.
				 * Just die instead. Unless this thread
				 * is the first sequence that has just
				 * been ack'ed
				 */
				dowork = 0;
			}
		}
		mutex_exit(&q->net_qlock);

		if ((aio->iostatus != RDC_IO_DONE) && (group->count)) {
			rdc_k_info_t *krdctmp = &rdc_k_info[aio->index];
			if (krdctmp->type_flag & RDC_DISABLEPEND) {
				kmem_free(aio, sizeof (*aio));
				goto thread_death;
			}
			rdc_group_enter(krdc);
			ASSERT(krdc->group);
			rdc_group_log(krdc, RDC_NOFLUSH | RDC_ALLREMOTE,
				"memq flush aio status not RDC_IO_DONE");
			rdc_group_exit(krdc);
			rdc_dump_queue(aio->index);
		}
		kmem_free(aio, sizeof (*aio));

		if (krdc->remote_index < 0 || !krdc->lsrv || !krdc->intf)
			break;
	}

thread_death:
	rdc_many_enter(krdc);
	mutex_enter(&group->ra_queue.net_qlock);
	group->rdc_thrnum--;
	group->rdc_writer = 0;
	/*
	 * all threads must be dead.
	 */
	if ((group->count == 0) && (group->rdc_thrnum == 0)) {
		mutex_exit(&group->ra_queue.net_qlock);
		/*
		 * Group now empty, so destroy
		 * Race with remove_from_group while write thread was running
		 */
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_flush_memq: group being destroyed");
#endif
		rdc_delgroup(group);
		krdc->group = NULL;
		rdc_many_exit(krdc);
		return;
	}
	mutex_exit(&group->ra_queue.net_qlock);
	rdc_many_exit(krdc);
}

/*
 * rdc_flush_diskq
 * disk queue flusher
 */
void
rdc_flush_diskq(int index)
{
	rdc_k_info_t *krdc = &rdc_k_info[index];
	rdc_u_info_t *urdc = &rdc_u_info[index];
	rdc_aio_t *aio = NULL;
	disk_queue *q;
	net_queue *nq;
	int dowork;
	int rc;
	rdc_group_t *group = krdc->group;

	if (!group || group->count == 0) {
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_flush_diskq: no group left!");
#endif
		return;
	}

	if (!krdc->c_fd) {
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_flush_diskq: no c_fd!");
#endif
		return;
	}

#ifdef DEBUG_DISABLE
	if (index < 0 || (krdc->type_flag & RDC_DISABLEPEND)) {
		cmn_err(CE_WARN, "rdc_flush_diskq: DISABLE PENDING!");
		/*
		 * Need to continue as we may be trying to flush IO
		 * while trying to disable or suspend
		 */
	}
#endif
	q = &group->diskq;
	nq = &group->ra_queue;

	if (IS_QSTATE(q, RDC_QDISABLEPEND) || IS_STATE(urdc, RDC_LOGGING)) {
#ifdef DEBUG
		cmn_err(CE_NOTE, "flusher thread death 1 %x", QSTATE(q));
#endif
		goto thread_death;
	}

	dowork = 1;
	/* CONSTCOND */
	while (dowork) {
		if (net_exit == ATM_EXIT)
			break;

		group = krdc->group;
		if (!group || group->count == 0) {
#ifdef DEBUG
			cmn_err(CE_WARN, "rdc_flush_diskq: no group left!");
#endif
			break;
		}

		do {
			rc = 0;
			if ((IS_STATE(urdc, RDC_LOGGING)) ||
			    (IS_STATE(urdc, RDC_SYNCING)) ||
			    (nq->qfflags & RDC_QFILLSLEEP))
				goto thread_death;

			aio = rdc_dequeue(krdc, &rc);

			if ((IS_STATE(urdc, RDC_LOGGING)) ||
			    (IS_STATE(urdc, RDC_SYNCING)) ||
			    (nq->qfflags & RDC_QFILLSLEEP)) {
				goto thread_death;
			}
			if (rc == EAGAIN) {
				delay(40);
			}

		} while (rc == EAGAIN);

		if (aio == NULL) {
			break;
		}

		aio->iostatus = RDC_IO_INIT;

		mutex_enter(QLOCK(q));
		q->inflbls += aio->len;
		q->inflitems++;
		mutex_exit(QLOCK(q));

		_rdc_remote_flush(aio);

		mutex_enter(QLOCK(q));
		q->inflbls -= aio->len;
		q->inflitems--;

		if ((group->seqack == RDC_NEWSEQ) &&
		    (group->seq != RDC_NEWSEQ + 1)) {
			if ((nq->net_qhead == NULL) ||
			    (nq->net_qhead->seq != RDC_NEWSEQ + 1)) {
				/*
				 * We are an old thread, and the
				 * queue sequence has been reset
				 * during the network write above.
				 * As such we mustn't pull another
				 * job from the queue until the
				 * first sequence message has been ack'ed.
				 * Just die instead. Unless of course,
				 * this thread is the first sequence that
				 * has just been ack'ed.
				 */
				dowork = 0;
			}
		}
		mutex_exit(QLOCK(q));

		if (aio->iostatus == RDC_IO_CANCELLED) {
			rdc_dump_queue(aio->index);
			kmem_free(aio, sizeof (*aio));
			aio = NULL;
			if (group) { /* seq gets bumped on dequeue */
				mutex_enter(QLOCK(q));
				rdc_dump_iohdrs(q);
				SET_QNXTIO(q, QHEAD(q));
				SET_QCOALBOUNDS(q, QHEAD(q));
				group->seq = RDC_NEWSEQ;
				group->seqack = RDC_NEWSEQ;
				mutex_exit(QLOCK(q));
			}
			break;
		}

		if ((aio->iostatus != RDC_IO_DONE) && (group->count)) {
			rdc_k_info_t *krdctmp = &rdc_k_info[aio->index];
			if (krdctmp->type_flag & RDC_DISABLEPEND) {
				kmem_free(aio, sizeof (*aio));
				aio = NULL;
				goto thread_death;
			}
			rdc_group_enter(krdc);
			rdc_group_log(krdc,
			    RDC_NOFLUSH | RDC_ALLREMOTE | RDC_QUEUING,
				"diskq flush aio status not RDC_IO_DONE");
			rdc_group_exit(krdc);
			rdc_dump_queue(aio->index);
		}

		kmem_free(aio, sizeof (*aio));
		aio = NULL;

#ifdef DEBUG_DISABLE
		if (krdc->type_flag & RDC_DISABLEPEND) {
			cmn_err(CE_WARN,
				"rdc_flush_diskq: DISABLE PENDING after IO!");
		}
#endif
		if (krdc->remote_index < 0 || !krdc->lsrv || !krdc->intf)
			break;

		if (IS_QSTATE(q, RDC_QDISABLEPEND)) {
#ifdef DEBUG
			cmn_err(CE_NOTE, "flusher thread death 2");
#endif
			break;
		}
	}
thread_death:
	rdc_many_enter(krdc);
	mutex_enter(QLOCK(q));
	group->rdc_thrnum--;
	group->rdc_writer = 0;

	if (aio && aio->qhandle) {
		aio->qhandle->sb_user--;
		if (aio->qhandle->sb_user == 0) {
			(void) _rdc_rsrv_diskq(krdc->group);
			rdc_fixlen(aio);
			(void) nsc_free_buf(aio->qhandle);
			aio->qhandle = NULL;
			aio->handle = NULL;
			_rdc_rlse_diskq(krdc->group);
		}
	}
	if ((group->count == 0) && (group->rdc_thrnum == 0)) {
		mutex_exit(QLOCK(q));
		/*
		 * Group now empty, so destroy
		 * Race with remove_from_group while write thread was running
		 */
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_flush_diskq: group being destroyed");
#endif
		mutex_enter(&group->diskqmutex);
		rdc_close_diskq(group);
		mutex_exit(&group->diskqmutex);
		rdc_delgroup(group);
		krdc->group = NULL;
		rdc_many_exit(krdc);
		return;
	}
	mutex_exit(QLOCK(q));
	rdc_many_exit(krdc);
}

/*
 * _rdc_remote_flush
 * Flush a single block ANON block
 * this function will flush from either the disk queue
 * or the memory queue. The appropriate locks must be
 * taken out etc, etc ...
 */
static void
_rdc_remote_flush(rdc_aio_t *aio)
{
	rdc_k_info_t *krdc = &rdc_k_info[aio->index];
	rdc_u_info_t *urdc = &rdc_u_info[aio->index];
	disk_queue *q = &krdc->group->diskq;
	kmutex_t *qlock;
	rdc_group_t *group;
	nsc_buf_t *h = NULL;
	int reserved = 0;
	int rtype = RDC_RAW;
	int rc;
	uint_t maxseq;
	struct netwriteres netret;
	int waitq = 1;
	int vflags;

	group = krdc->group;
	netret.vecdata.vecdata_val = NULL;
	netret.vecdata.vecdata_len = 0;

	/* Where did we get this aio from anyway? */
	if (RDC_IS_DISKQ(group)) {
		qlock = &group->diskq.disk_qlock;
	} else {
		qlock = &group->ra_queue.net_qlock;
	}

	/*
	 * quench transmission if we are too far ahead of the
	 * server Q, or it will overflow.
	 * Must fail all requests while asyncdis is set.
	 * It will be cleared when the last thread to be discarded
	 * sets the asyncstall counter to zero.
	 * Note the thread within rdc_net_write
	 * also bumps the asyncstall counter.
	 */

	mutex_enter(qlock);
	if (group->asyncdis) {
		aio->iostatus = RDC_IO_CANCELLED;
		mutex_exit(qlock);
		goto failed;
	}
	/* don't go to sleep if we have gone logging! */
	vflags = rdc_get_vflags(urdc);
	if ((vflags & (RDC_BMP_FAILED|RDC_VOL_FAILED|RDC_LOGGING))) {
		if ((vflags & RDC_LOGGING) && RDC_IS_DISKQ(group))
			aio->iostatus = RDC_IO_CANCELLED;

		mutex_exit(qlock);
		goto failed;
	}

	while (maxseq = group->seqack + RDC_MAXPENDQ + 1,
	    maxseq = (maxseq < group->seqack) ? maxseq + RDC_NEWSEQ + 1
	    : maxseq, !RDC_INFRONT(aio->seq, maxseq)) {
		group->asyncstall++;
		ASSERT(!IS_STATE(urdc, RDC_LOGGING));
		cv_wait(&group->asyncqcv, qlock);
		group->asyncstall--;
		ASSERT(group->asyncstall >= 0);
		if (group->asyncdis) {
			if (group->asyncstall == 0) {
				group->asyncdis = 0;
			}
			aio->iostatus = RDC_IO_CANCELLED;
			mutex_exit(qlock);
			goto failed;
		}
		/*
		 * See if we have gone into logging mode
		 * since sleeping.
		 */
		vflags = rdc_get_vflags(urdc);
		if (vflags & (RDC_BMP_FAILED|RDC_VOL_FAILED|RDC_LOGGING)) {
			if ((vflags & RDC_LOGGING) && RDC_IS_DISKQ(group))
				aio->iostatus = RDC_IO_CANCELLED;

			mutex_exit(qlock);
			goto failed;
		}
	}
	mutex_exit(qlock);

	if ((krdc->io_kstats) && (!RDC_IS_DISKQ(krdc->group))) {
		mutex_enter(krdc->io_kstats->ks_lock);
		kstat_waitq_exit(KSTAT_IO_PTR(krdc->io_kstats));
		mutex_exit(krdc->io_kstats->ks_lock);
		waitq = 0;
	}


	rc = _rdc_rsrv_devs(krdc, rtype, RDC_INTERNAL);
	if (rc != 0) {
#ifdef DEBUG
		cmn_err(CE_WARN, "_rdc_remote_flush: reserve, index %d, rc %d",
		    aio->index, rc);
#endif
		goto failed;
	}

	reserved = 1;
	/*
	 * Case where we are multihop and calling with no ANON bufs
	 * Need to do the read to fill the buf.
	 */
	if (!aio->handle) {
		rc = nsc_alloc_buf(RDC_U_FD(krdc), aio->pos, aio->len,
			(aio->flag & ~NSC_WRITE) | NSC_READ, &h);
		if (!RDC_SUCCESS(rc)) {
#ifdef DEBUG
			cmn_err(CE_WARN,
			    "_rdc_remote_flush: alloc_buf, index %d, pos %"
			    NSC_SZFMT ", len %" NSC_SZFMT ", rc %d",
			    aio->index, aio->pos, aio->len, rc);
#endif

			goto failed;
		}
		aio->handle = h;
		aio->handle->sb_user = RDC_NULLBUFREAD;
	}

	mutex_enter(qlock);
	if (group->asyncdis) {
		if (group->asyncstall == 0) {
			group->asyncdis = 0;
		}
		aio->iostatus = RDC_IO_CANCELLED;
		mutex_exit(qlock);
		goto failed;
	}
	group->asyncstall++;
	mutex_exit(qlock);


	if (krdc->remote_index < 0) {
		/*
		 * this should be ok, we are flushing, not rev syncing.
		 * remote_index could be -1 if we lost a race with
		 * resume and the flusher trys to flush an io from
		 * another set that has not resumed
		 */
		krdc->remote_index = rdc_net_state(krdc->index, CCIO_SLAVE);

	}

	/*
	 * double check for logging, no check in net_write()
	 * skip the write if you can, otherwise, if logging
	 * avoid clearing the bit .. you don't know whose bit it may
	 * also be.
	 */
	if (IS_STATE(urdc, RDC_LOGGING) || IS_STATE(urdc, RDC_SYNCING)) {
		aio->iostatus = RDC_IO_CANCELLED;
		mutex_enter(qlock);
		group->asyncstall--;
		mutex_exit(qlock);
		goto failed;
	}

	rc = rdc_net_write(krdc->index, krdc->remote_index,
	    aio->handle, aio->pos, aio->len, aio->seq, aio->qpos, &netret);

	mutex_enter(qlock);
	group->asyncstall--;
	if (group->asyncdis) {
		if (group->asyncstall == 0) {
			group->asyncdis = 0;
		}
		aio->iostatus = RDC_IO_CANCELLED;
		mutex_exit(qlock);
		goto failed;
	}

	if (IS_STATE(urdc, RDC_LOGGING) || IS_STATE(urdc, RDC_SYNCING)) {
		mutex_exit(qlock);
		aio->iostatus = RDC_IO_CANCELLED;
		goto failed;
	}

	ASSERT(aio->handle);
	if (rc != 0) {
#ifdef DEBUG
		cmn_err(CE_WARN,
		    "_rdc_remote_flush: write, index %d, pos %" NSC_SZFMT
		    ", len %" NSC_SZFMT ", "
		    "rc %d seq %u group seq %u seqack %u qpos %" NSC_SZFMT,
		    aio->index, aio->pos, aio->len, rc, aio->seq,
		    group->seq, group->seqack, aio->qpos);
#endif
		if (rc == ENOLINK) {
			cmn_err(CE_WARN,
			    "Hard timeout detected (%d sec) "
			    "on SNDR set %s:%s",
			    rdc_rpc_tmout, urdc->secondary.intf,
			    urdc->secondary.file);
		}
		mutex_exit(qlock);
		goto failed;
	} else {
		aio->iostatus = RDC_IO_DONE;
	}

	if (RDC_IS_DISKQ(group)) {
		/* free locally alloc'd handle */
		if (aio->handle->sb_user == RDC_NULLBUFREAD) {
			(void) nsc_free_buf(aio->handle);
			aio->handle = NULL;
		}
		aio->qhandle->sb_user--;
		if (aio->qhandle->sb_user == 0) {
			(void) _rdc_rsrv_diskq(group);
			rdc_fixlen(aio);
			(void) nsc_free_buf(aio->qhandle);
			aio->qhandle = NULL;
			aio->handle = NULL;
			_rdc_rlse_diskq(group);
		}

	} else {
		(void) nsc_free_buf(aio->handle);
		aio->handle = NULL;
	}

	mutex_exit(qlock);

	_rdc_rlse_devs(krdc, rtype);

	if (netret.result == 0) {
		vflags = rdc_get_vflags(urdc);

		if (!(vflags & (RDC_BMP_FAILED|RDC_VOL_FAILED|RDC_LOGGING))) {
			RDC_CLR_BITMAP(krdc, aio->pos, aio->len, \
			    0xffffffff, RDC_BIT_BUMP);

			if (RDC_IS_DISKQ(krdc->group)) {
				if (!IS_STATE(urdc, RDC_LOGGING)) {
					/* tell queue data has been flushed */
					rdc_clr_iohdr(krdc, aio->qpos);
				} else { /* throw away queue, logging */
					mutex_enter(qlock);
					rdc_dump_iohdrs(q);
					SET_QNXTIO(q, QHEAD(q));
					SET_QCOALBOUNDS(q, QHEAD(q));
					mutex_exit(qlock);
				}
			}
		}

		mutex_enter(qlock);
		/*
		 * Check to see if the reply has arrived out of
		 * order, if so don't update seqack.
		 */
		if (!RDC_INFRONT(aio->seq, group->seqack)) {
			group->seqack = aio->seq;
		}
#ifdef DEBUG
		else {
			rdc_ooreply++;
		}
#endif
		if (group->asyncstall) {
			cv_broadcast(&group->asyncqcv);
		}
		mutex_exit(qlock);
	} else if (netret.result < 0) {
		aio->iostatus = RDC_IO_FAILED;
	}

	/*
	 * see if we have any pending async requests we can mark
	 * as done.
	 */

	if (netret.vecdata.vecdata_len) {
		net_pendvec_t *vecp;
		net_pendvec_t *vecpe;
		vecp = netret.vecdata.vecdata_val;
		vecpe = netret.vecdata.vecdata_val + netret.vecdata.vecdata_len;
		while (vecp < vecpe) {
			rdc_k_info_t *krdcp = &rdc_k_info[vecp->pindex];
			rdc_u_info_t *urdcp = &rdc_u_info[vecp->pindex];
			/*
			 * we must always still be in the same group.
			 */
			ASSERT(krdcp->group == group);
			vflags = rdc_get_vflags(urdcp);

			if (!(vflags &
			    (RDC_BMP_FAILED|RDC_VOL_FAILED|RDC_LOGGING))) {
				RDC_CLR_BITMAP(krdcp, vecp->apos, vecp->alen, \
				    0xffffffff, RDC_BIT_BUMP);
				if (RDC_IS_DISKQ(krdcp->group)) {
					if (!IS_STATE(urdc, RDC_LOGGING)) {
						/* update queue info */
						rdc_clr_iohdr(krdc, vecp->qpos);
					} else { /* we've gone logging */
						mutex_enter(qlock);
						rdc_dump_iohdrs(q);
						SET_QNXTIO(q, QHEAD(q));
						SET_QCOALBOUNDS(q, QHEAD(q));
						mutex_exit(qlock);
					}
				}
			}

			/*
			 * see if we can re-start transmission
			 */
			mutex_enter(qlock);
			if (!RDC_INFRONT(vecp->seq, group->seqack)) {
				group->seqack = vecp->seq;
			}
#ifdef DEBUG
			else {
				rdc_ooreply++;
			}
#endif

			if (group->asyncstall) {
				cv_broadcast(&group->asyncqcv);
			}
			mutex_exit(qlock);
			vecp++;
		}
	}
	if (netret.vecdata.vecdata_val)
		kmem_free(netret.vecdata.vecdata_val,
		    netret.vecdata.vecdata_len * sizeof (net_pendvec_t));
	return;
failed:

	/* perhaps we have a few threads stuck .. */
	if (group->asyncstall) {
		group->asyncdis = 1;
		cv_broadcast(&group->asyncqcv);
	}
	if (netret.vecdata.vecdata_val)
		kmem_free(netret.vecdata.vecdata_val,
		    netret.vecdata.vecdata_len * sizeof (net_pendvec_t));

	mutex_enter(qlock);
	if (RDC_IS_DISKQ(group)) {
		/* free locally alloc'd hanlde */
		if ((aio->handle) &&
		    (aio->handle->sb_user == RDC_NULLBUFREAD)) {
			(void) nsc_free_buf(aio->handle);
			aio->handle = NULL;
		}
		aio->qhandle->sb_user--;
		if (aio->qhandle->sb_user == 0) {
			(void) _rdc_rsrv_diskq(group);
			rdc_fixlen(aio);
			(void) nsc_free_buf(aio->qhandle);
			aio->qhandle = NULL;
			aio->handle = NULL;
			_rdc_rlse_diskq(group);
		}
	} else {
		if (aio->handle) {
			(void) nsc_free_buf(aio->handle);
			aio->handle = NULL;
		}
	}
	mutex_exit(qlock);

	if (reserved) {
		_rdc_rlse_devs(krdc, rtype);
	}

	if ((waitq && krdc->io_kstats) && (!RDC_IS_DISKQ(krdc->group))) {
		mutex_enter(krdc->io_kstats->ks_lock);
		kstat_waitq_exit(KSTAT_IO_PTR(krdc->io_kstats));
		mutex_exit(krdc->io_kstats->ks_lock);
	}

	/* make sure that the bit is still set */
	RDC_CHECK_BIT(krdc, aio->pos, aio->len);

	if (aio->iostatus != RDC_IO_CANCELLED)
		aio->iostatus = RDC_IO_FAILED;
}


/*
 * rdc_drain_disk_queue
 * drain the async network queue for the whole group. Bail out if nothing
 * happens in 20 sec
 * returns -1 if it bails before the queues are drained.
 */
#define	NUM_RETRIES	15	/* Number of retries to wait if no progress */
int
rdc_drain_disk_queue(int index)
{
	rdc_k_info_t *krdc = &rdc_k_info[index];
	volatile rdc_group_t *group;
	volatile disk_queue *diskq;
	int threads, counter;
	long blocks;

	/* Sanity checking */
	if (index > rdc_max_sets)
		return (0);

	/*
	 * If there is no group or diskq configured, we can leave now
	 */
	if (!(group = krdc->group) || !(diskq = &group->diskq))
		return (0);

	/*
	 * No need to wait if EMPTY and threads are gone
	 */
	counter = 0;
	while (!QEMPTY(diskq) || group->rdc_thrnum) {

		/*
		 * Capture counters to determine if progress is being made
		 */
		blocks = QBLOCKS(diskq);
		threads = group->rdc_thrnum;

		/*
		 * Wait
		 */
		delay(HZ);

		/*
		 * Has the group or disk queue gone away while delayed?
		 */
		if (!(group = krdc->group) || !(diskq = &group->diskq))
			return (0);

		/*
		 * Are we still seeing progress?
		 */
		if (blocks == QBLOCKS(diskq) && threads == group->rdc_thrnum) {
			/*
			 * No progress seen, increment retry counter
			 */
			if (counter++ > NUM_RETRIES) {
				return (-1);
			}
		} else {
			/*
			 * Reset counter, as we've made progress
			 */
			counter = 0;
		}
	}

	return (0);
}

/*
 * decide what needs to be drained, disk or core
 * and drain it
 */
int
rdc_drain_queue(int index)
{
	rdc_k_info_t *krdc = &rdc_k_info[index];
	rdc_group_t *group = krdc->group;

	if (!group)
		return (0);

	if (RDC_IS_DISKQ(group))
		return (rdc_drain_disk_queue(index));
	if (RDC_IS_MEMQ(group))
		return (rdc_drain_net_queue(index));
	/* oops.. */
#ifdef DEBUG
	cmn_err(CE_WARN, "rdc_drain_queue: attempting drain of unknown Q type");
#endif
	return (0);
}

/*
 * rdc_drain_net_queue
 * drain the async network queue for the whole group. Bail out if nothing
 * happens in 20 sec
 * returns -1 if it bails before the queues are drained.
 */
int
rdc_drain_net_queue(int index)
{
	rdc_k_info_t *krdc = &rdc_k_info[index];
	volatile net_queue *q;
	int bail = 20;	/* bail out in about 20 secs */
	nsc_size_t blocks;

	/* Sanity checking */
	if (index > rdc_max_sets)
		return (0);
	if (!krdc->group)
		return (0);
	/* LINTED */
	if (!(q = &krdc->group->ra_queue))
		return (0);

	/* CONSTCOND */
	while (1) {

		if (((volatile rdc_aio_t *)q->net_qhead == NULL) &&
		    (krdc->group->rdc_thrnum == 0)) {
			break;
		}

		blocks = q->blocks;

		q = (volatile net_queue *)&krdc->group->ra_queue;

		if ((blocks == q->blocks) &&
		    (--bail <= 0)) {
			break;
		}

		delay(HZ);
	}

	if (bail <= 0)
		return (-1);

	return (0);
}

/*
 * rdc_dump_queue
 * We want to release all the blocks currently on the network flushing queue
 * We already have them logged in the bitmap.
 */
void
rdc_dump_queue(int index)
{
	rdc_k_info_t *krdc = &rdc_k_info[index];
	rdc_aio_t *aio;
	net_queue *q;
	rdc_group_t *group;
	disk_queue *dq;
	kmutex_t *qlock;

	group = krdc->group;

	q = &group->ra_queue;
	dq = &group->diskq;

	/*
	 * gotta have both locks here for diskq
	 */

	if (RDC_IS_DISKQ(group)) {
		mutex_enter(&q->net_qlock);
		if (q->qfill_sleeping == RDC_QFILL_AWAKE) {
			int tries = 3;
#ifdef DEBUG_DISKQ
			cmn_err(CE_NOTE,
			    "dumpq sending diskq->memq flusher to sleep");
#endif
			q->qfflags |= RDC_QFILLSLEEP;
			mutex_exit(&q->net_qlock);
			while (q->qfill_sleeping == RDC_QFILL_AWAKE && tries--)
				delay(5);
			mutex_enter(&q->net_qlock);
		}
	}

	if (RDC_IS_DISKQ(group)) {
		qlock = &dq->disk_qlock;
		(void) _rdc_rsrv_diskq(group);
	} else {
		qlock = &q->net_qlock;
	}

	mutex_enter(qlock);

	group->seq = RDC_NEWSEQ;	/* reset the sequence number */
	group->seqack = RDC_NEWSEQ;

	/* if the q is on disk, dump the q->iohdr chain */
	if (RDC_IS_DISKQ(group)) {
		rdc_dump_iohdrs(dq);

		/* back up the nxtio pointer */
		SET_QNXTIO(dq, QHEAD(dq));
		SET_QCOALBOUNDS(dq, QHEAD(dq));
	}

	while (q->net_qhead) {
		rdc_k_info_t *tmpkrdc;
		aio = q->net_qhead;
		tmpkrdc = &rdc_k_info[aio->index];

		if (RDC_IS_DISKQ(group)) {
			aio->qhandle->sb_user--;
			if (aio->qhandle->sb_user == 0) {
				rdc_fixlen(aio);
				(void) nsc_free_buf(aio->qhandle);
				aio->qhandle = NULL;
				aio->handle = NULL;
			}
		} else {
			if (aio->handle) {
				(void) nsc_free_buf(aio->handle);
				aio->handle = NULL;
			}
		}

		q->net_qhead = aio->next;
		RDC_CHECK_BIT(tmpkrdc, aio->pos, aio->len);

		kmem_free(aio, sizeof (*aio));
		if (tmpkrdc->io_kstats && !RDC_IS_DISKQ(group)) {
			mutex_enter(tmpkrdc->io_kstats->ks_lock);
			kstat_waitq_exit(KSTAT_IO_PTR(tmpkrdc->io_kstats));
			mutex_exit(tmpkrdc->io_kstats->ks_lock);
		}

	}

	q->net_qtail = NULL;
	q->blocks = 0;
	q->nitems = 0;

	/*
	 * See if we have stalled threads.
	 */
done:
	if (group->asyncstall) {
		group->asyncdis = 1;
		cv_broadcast(&group->asyncqcv);
	}
	mutex_exit(qlock);
	if (RDC_IS_DISKQ(group)) {
		mutex_exit(&q->net_qlock);
		_rdc_rlse_diskq(group);
	}

}


/*
 * rdc_clnt_get
 * Get a CLIENT handle and cache it
 */

static int
rdc_clnt_get(rdc_srv_t *svp, rpcvers_t vers, struct chtab **rch, CLIENT **clp)
{
	uint_t	max_msgsize;
	int	retries;
	int ret;
	struct cred		*cred;
	int num_clnts = 0;
	register struct chtab *ch;
	struct chtab **plistp;
	CLIENT *client = 0;

	if (rch) {
		*rch = 0;
	}

	if (clp) {
		*clp = 0;
	}

	retries = 6;	/* Never used for COTS in Solaris */
	cred = ddi_get_cred();
	max_msgsize = RDC_RPC_MAX;

	mutex_enter(&rdc_clnt_lock);

	ch = rdc_chtable;
	plistp = &rdc_chtable;

	/* find the right ch_list chain */

	for (ch = rdc_chtable; ch != NULL; ch = ch->ch_next) {
		if (ch->ch_prog == RDC_PROGRAM &&
		    ch->ch_vers == vers &&
		    ch->ch_dev == svp->ri_knconf->knc_rdev &&
		    ch->ch_protofmly != NULL &&
		    strcmp(ch->ch_protofmly,
			svp->ri_knconf->knc_protofmly) == 0) {
			/* found the correct chain to walk */
			break;
		}
		plistp = &ch->ch_next;
	}

	if (ch != NULL) {
		/* walk the ch_list and try and find a free client */

		for (num_clnts = 0; ch != NULL; ch = ch->ch_list, num_clnts++) {
			if (ch->ch_inuse == FALSE) {
				/* suitable handle to reuse */
				break;
			}
			plistp = &ch->ch_list;
		}
	}

	if (ch == NULL && num_clnts >= MAXCLIENTS) {
		/* alloc a temporary handle and return */

		rdc_clnt_toomany++;
		mutex_exit(&rdc_clnt_lock);

		ret = clnt_tli_kcreate(svp->ri_knconf, &(svp->ri_addr),
				RDC_PROGRAM, vers, max_msgsize, retries,
				cred, &client);

		if (ret != 0) {
			cmn_err(CE_NOTE,
				"rdc_call: tli_kcreate failed %d", ret);
			return (ret);
		}

		*rch = 0;
		*clp = client;
		(void) CLNT_CONTROL(client, CLSET_PROGRESS, NULL);
		return (ret);
	}

	if (ch != NULL) {
		/* reuse a cached handle */

		ch->ch_inuse = TRUE;
		ch->ch_timesused++;
		mutex_exit(&rdc_clnt_lock);

		*rch = ch;

		if (ch->ch_client == NULL) {
			ret = clnt_tli_kcreate(svp->ri_knconf, &(svp->ri_addr),
				RDC_PROGRAM, vers, max_msgsize, retries,
				cred, &ch->ch_client);
			if (ret != 0) {
				ch->ch_inuse = FALSE;
				return (ret);
			}

			(void) CLNT_CONTROL(ch->ch_client, CLSET_PROGRESS,
				NULL);
			*clp = ch->ch_client;

			return (0);
		} else {
		/*
		 * Consecutive calls to CLNT_CALL() on the same client handle
		 * get the same transaction ID.  We want a new xid per call,
		 * so we first reinitialise the handle.
		 */
			(void) clnt_tli_kinit(ch->ch_client, svp->ri_knconf,
				&(svp->ri_addr), max_msgsize, retries, cred);

			*clp = ch->ch_client;
			return (0);
		}
	}

	/* create new handle and cache it */
	ch = (struct chtab *)kmem_zalloc(sizeof (*ch), KM_SLEEP);

	if (ch) {
		ch->ch_inuse = TRUE;
		ch->ch_prog = RDC_PROGRAM;
		ch->ch_vers = vers;
		ch->ch_dev = svp->ri_knconf->knc_rdev;
		ch->ch_protofmly = (char *)kmem_zalloc(
			strlen(svp->ri_knconf->knc_protofmly)+1, KM_SLEEP);
		if (ch->ch_protofmly)
			(void) strcpy(ch->ch_protofmly,
			    svp->ri_knconf->knc_protofmly);
		*plistp = ch;
	}

	mutex_exit(&rdc_clnt_lock);

	ret = clnt_tli_kcreate(svp->ri_knconf, &(svp->ri_addr),
			RDC_PROGRAM, vers, max_msgsize, retries,
			cred, clp);

	if (ret != 0) {
		if (ch)
			ch->ch_inuse = FALSE;
		cmn_err(CE_NOTE, "rdc_call: tli_kcreate failed %d", ret);
		return (ret);
	}

	*rch = ch;
	if (ch)
		ch->ch_client = *clp;

	(void) CLNT_CONTROL(*clp, CLSET_PROGRESS, NULL);

	return (ret);
}


long rdc_clnt_count = 0;

/*
 * rdc_clnt_call
 * Arguments:
 *	rdc_srv_t *svp - rdc servinfo
 *	rpcproc_t proc; - rpcid
 *	rpcvers_t vers; - protocol version
 *	xdrproc_t xargs;- xdr function
 *	caddr_t argsp;- args to xdr function
 *	xdrproc_t xres;- xdr function
 *	caddr_t resp;- args to xdr function
 *	struct timeval timeout;
 * Performs RPC client call using specific protocol and version
 */

int
rdc_clnt_call(rdc_srv_t *svp, rpcproc_t proc, rpcvers_t vers,
		xdrproc_t xargs, caddr_t argsp,
		xdrproc_t xres, caddr_t resp, struct timeval *timeout)
{
	CLIENT *rh = NULL;
	int err;
	int tries = 0;
	struct chtab *ch = NULL;

	err = rdc_clnt_get(svp, vers, &ch, &rh);
	if (err || !rh)
		return (err);

	do {
		DTRACE_PROBE3(rdc_clnt_call_1,
				CLIENT *, rh,
				rpcproc_t, proc,
				xdrproc_t, xargs);

		err = cl_call_sig(rh, proc, xargs, argsp, xres, resp, *timeout);

		DTRACE_PROBE1(rdc_clnt_call_end, int, err);

		switch (err) {
			case RPC_SUCCESS: /* bail now */
				goto done;
			case RPC_INTR:	/* No recovery from this */
				goto done;
			case RPC_PROGVERSMISMATCH:
				goto done;
			case RPC_TLIERROR:
				/* fall thru */
			case RPC_XPRTFAILED:
				/* Delay here to err on side of caution */
				/* fall thru */
			case RPC_VERSMISMATCH:

			default:
				if (IS_UNRECOVERABLE_RPC(err)) {
					goto done;
				}
				tries++;
			/*
			 * The call is in progress (over COTS)
			 * Try the CLNT_CALL again, but don't
			 * print a noisy error message
			 */
				if (err == RPC_INPROGRESS)
					break;
				cmn_err(CE_NOTE, "SNDR client: err %d %s",
					err, clnt_sperrno(err));
			}
	} while (tries && (tries < 2));
done:
	++rdc_clnt_count;
	rdc_clnt_free(ch, rh);
	return (err);
}


/*
 * Call an rpc from the client side, not caring which protocol is used.
 */
int
rdc_clnt_call_any(rdc_srv_t *svp, rdc_if_t *ip, rpcproc_t proc,
		xdrproc_t xargs, caddr_t argsp,
		xdrproc_t xres, caddr_t resp, struct timeval *timeout)
{
	rpcvers_t vers;
	int rc;

	if (ip != NULL) {
		vers = ip->rpc_version;
	} else {
		vers = RDC_VERS_MAX;
	}

	do {
		rc = rdc_clnt_call(svp, proc, vers, xargs, argsp,
				xres, resp, timeout);

		if (rc == RPC_PROGVERSMISMATCH) {
			/*
			 * Downgrade and try again.
			 */
			vers--;
		}
	} while ((vers >= RDC_VERS_MIN) && (rc == RPC_PROGVERSMISMATCH));

	if ((rc == 0) && (ip != NULL) && (vers != ip->rpc_version)) {
		mutex_enter(&rdc_ping_lock);
		ip->rpc_version = vers;
		mutex_exit(&rdc_ping_lock);
	}

	return (rc);
}

/*
 * Call an rpc from the client side, starting with protocol specified
 */
int
rdc_clnt_call_walk(rdc_k_info_t *krdc, rpcproc_t proc, xdrproc_t xargs,
		caddr_t argsp, xdrproc_t xres, caddr_t resp,
		struct timeval *timeout)
{
	int rc;
	rpcvers_t vers;
	rdc_srv_t *svp = krdc->lsrv;
	rdc_if_t *ip = krdc->intf;
	vers = krdc->rpc_version;

	do {
		rc = rdc_clnt_call(svp, proc, vers, xargs, argsp,
				xres, resp, timeout);

		if (rc == RPC_PROGVERSMISMATCH) {
			/*
			 * Downgrade and try again.
			 */
			vers--;
		}
	} while ((vers >= RDC_VERS_MIN) && (rc == RPC_PROGVERSMISMATCH));

	if ((rc == 0) && (ip != NULL) && (vers != ip->rpc_version)) {
		mutex_enter(&rdc_ping_lock);
		ip->rpc_version = vers;
		mutex_exit(&rdc_ping_lock);
	}

	return (rc);
}

/*
 * rdc_clnt_free
 * Free a client structure into the cache, or if this was a temporary
 * handle allocated above MAXCLIENTS, destroy it.
 */
static void
rdc_clnt_free(struct chtab *ch, CLIENT *clp)
{
	if (ch != NULL) {
		/* cached client, just clear inuse flag and return */
		ASSERT(ch->ch_client == clp);
		ch->ch_inuse = FALSE;
		return;
	}

	/* temporary handle allocated above MAXCLIENTS, so destroy it */

	if (clp->cl_auth) {
		AUTH_DESTROY(clp->cl_auth);
		clp->cl_auth = 0;
	}

	CLNT_DESTROY(clp);
}


/*
 * _rdc_clnt_destroy
 * Free a chain (ch_list or ch_next) of cached clients
 */
static int
_rdc_clnt_destroy(struct chtab **p, const int list)
{
	struct chtab *ch;
	int leak = 0;

	if (!p)
		return (0);

	while (*p != NULL) {
		ch = *p;

		/*
		 * unlink from the chain
		 * - this leaks the client if it was inuse
		 */

		*p = list ? ch->ch_list : ch->ch_next;

		if (!ch->ch_inuse) {
			/* unused client - destroy it */

			if (ch->ch_client) {
				if (ch->ch_client->cl_auth) {
					AUTH_DESTROY(ch->ch_client->cl_auth);
					ch->ch_client->cl_auth = 0;
				}

				CLNT_DESTROY(ch->ch_client);
				ch->ch_client = 0;
			}

			if (ch->ch_protofmly)
				kmem_free(ch->ch_protofmly,
					strlen(ch->ch_protofmly)+1);

			kmem_free(ch, sizeof (*ch));
		} else {
			/* remember client leak */
			leak++;
		}
	}

	return (leak);
}


/*
 * rdc_clnt_destroy
 * Free client caching table on unconfigure
 */
void
rdc_clnt_destroy(void)
{
	struct chtab *ch;
	int leak = 0;

	mutex_enter(&rdc_clnt_lock);

	/* destroy each ch_list chain */

	for (ch = rdc_chtable; ch; ch = ch->ch_next) {
		leak += _rdc_clnt_destroy(&ch->ch_list, 1);
	}

	/* destroy the main ch_next chain */
	leak += _rdc_clnt_destroy(&rdc_chtable, 0);

	if (leak) {
		/* we are about to leak clients */
		cmn_err(CE_WARN,
			"rdc_clnt_destroy: leaking %d inuse clients", leak);
	}

	mutex_exit(&rdc_clnt_lock);
}

#ifdef	DEBUG
/*
 * Function to send an asynchronous net_data6 request
 * direct to a server to allow the generation of
 * out of order requests for ZatoIchi tests.
 */
int
rdc_async6(void *arg, int mode, int *rvp)
{
	int			index;
	rdc_async6_t		async6;
	struct net_data6	data6;
	rdc_k_info_t		*krdc;
	rdc_u_info_t		*urdc;
	char			*data;
	int			datasz;
	char			*datap;
	int			rc;
	struct timeval		t;
	struct netwriteres	netret;
	int i;

	rc = 0;
	*rvp = 0;
	/*
	 * copyin the user's arguments.
	 */
	if (ddi_copyin(arg, &async6, sizeof (async6), mode) < 0) {
		return (EFAULT);
	}

	/*
	 * search by the secondary host and file.
	 */
	mutex_enter(&rdc_conf_lock);
	for (index = 0; index < rdc_max_sets; index++) {
		urdc = &rdc_u_info[index];
		krdc = &rdc_k_info[index];

		if (!IS_CONFIGURED(krdc))
			continue;
		if (!IS_ENABLED(urdc))
			continue;
		if (!IS_ASYNC(urdc))
			continue;
		if (krdc->rpc_version < RDC_VERSION6)
			continue;

		if ((strncmp(urdc->secondary.intf, async6.sechost,
		    MAX_RDC_HOST_SIZE) == 0) &&
		    (strncmp(urdc->secondary.file, async6.secfile,
		    NSC_MAXPATH) == 0)) {
			break;
		}
	}
	mutex_exit(&rdc_conf_lock);
	if (index >= rdc_max_sets) {
		return (ENOENT);
	}

	if (async6.spos != -1) {
		if ((async6.spos < async6.pos) ||
		    ((async6.spos + async6.slen) >
		    (async6.pos + async6.len))) {
			cmn_err(CE_WARN, "Sub task not within range "
			    "start %d length %d sub start %d sub length %d",
			    async6.pos, async6.len, async6.spos, async6.slen);
			return (EIO);
		}
	}

	datasz = FBA_SIZE(1);
	data = kmem_alloc(datasz, KM_SLEEP);
	datap = data;
	while (datap < &data[datasz]) {
		/* LINTED */
		*datap++ = async6.pat;
	}

	/*
	 * Fill in the net databuffer prior to transmission.
	 */

	data6.local_cd = krdc->index;
	if (krdc->remote_index == -1) {
		cmn_err(CE_WARN, "Remote index not known");
		kmem_free(data, datasz);
		return (EIO);
	} else {
		data6.cd = krdc->remote_index;
	}
	data6.pos = async6.pos;
	data6.len = async6.len;
	data6.flag = 0;
	data6.idx = async6.idx;
	data6.seq = async6.seq;

	if (async6.spos == -1) {
		data6.sfba = async6.pos;
		data6.nfba = async6.len;
		data6.endoblk = 1;

	} else {
		data6.sfba = async6.spos;
		data6.nfba = async6.slen;
		data6.endoblk = async6.endind;
	}

	data6.data.data_len = datasz;
	data6.data.data_val = data;

	t.tv_sec = rdc_rpc_tmout;
	t.tv_usec = 0;

	netret.vecdata.vecdata_val = NULL;
	netret.vecdata.vecdata_len = 0;


	rc = rdc_clnt_call(krdc->lsrv, RDCPROC_WRITE6, krdc->rpc_version,
	    xdr_net_data6, (char *)&data6, xdr_netwriteres, (char *)&netret,
	    &t);

	kmem_free(data, datasz);
	if (rc == 0) {
		if (netret.result < 0) {
			rc = -netret.result;
		}
		cmn_err(CE_NOTE, "async6: seq %u result %d index %d "
		    "pendcnt %d",
		    netret.seq, netret.result, netret.index,
		    netret.vecdata.vecdata_len);
		for (i = 0; i < netret.vecdata.vecdata_len; i++) {
			net_pendvec_t pvec;
			bcopy(netret.vecdata.vecdata_val + i, &pvec,
			    sizeof (net_pendvec_t));
			cmn_err(CE_NOTE, "Seq %u pos %llu len %llu",
			    pvec.seq, (unsigned long long)pvec.apos,
			    (unsigned long long)pvec.alen);
		}
		if (netret.vecdata.vecdata_val)
			kmem_free(netret.vecdata.vecdata_val,
			    netret.vecdata.vecdata_len *
			    sizeof (net_pendvec_t));
	} else {
		cmn_err(CE_NOTE, "async6: rpc call failed %d", rc);
	}
	*rvp = netret.index;
	return (rc);
}

/*
 * Function to send an net_read6 request
 * direct to a server to allow the generation of
 * read requests.
 */
int
rdc_readgen(void *arg, int mode, int *rvp)
{
	int			index;
	rdc_readgen_t		readgen;
	rdc_readgen32_t		readgen32;
	struct rread6		read6;
	struct rread		read5;
	rdc_k_info_t		*krdc;
	int			ret;
	struct timeval		t;
	struct rdcrdresult	rr;
	int			err;

	*rvp = 0;
	rr.rr_bufsize = 0;	/* rpc data buffer length (bytes) */
	rr.rr_data = NULL;	/* rpc data buffer */
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		if (ddi_copyin(arg, &readgen32, sizeof (readgen32), mode)) {
			return (EFAULT);
		}
		(void) strncpy(readgen.sechost, readgen32.sechost,
		    MAX_RDC_HOST_SIZE);
		(void) strncpy(readgen.secfile, readgen32.secfile, NSC_MAXPATH);
		readgen.len = readgen32.len;
		readgen.pos = readgen32.pos;
		readgen.idx = readgen32.idx;
		readgen.flag = readgen32.flag;
		readgen.data = (void *)(unsigned long)readgen32.data;
		readgen.rpcversion = readgen32.rpcversion;
	} else {
		if (ddi_copyin(arg, &readgen, sizeof (readgen), mode)) {
			return (EFAULT);
		}
	}
	switch (readgen.rpcversion) {
	case 5:
	case 6:
		break;
	default:
		return (EINVAL);
	}

	mutex_enter(&rdc_conf_lock);
	index = rdc_lookup_byhostdev(readgen.sechost, readgen.secfile);
	if (index >= 0) {
		krdc = &rdc_k_info[index];
	}
	if (index < 0 || (krdc->type_flag & RDC_DISABLEPEND)) {
		mutex_exit(&rdc_conf_lock);
		return (ENODEV);
	}
	/*
	 * we should really call setbusy here.
	 */
	mutex_exit(&rdc_conf_lock);

	t.tv_sec = rdc_rpc_tmout;
	t.tv_usec = 0;
	if (krdc->remote_index == -1) {
		cmn_err(CE_WARN, "Remote index not known");
		ret = EIO;
		goto out;
	}
	if (readgen.rpcversion == 6) {
		read6.cd = krdc->remote_index;
		read6.len = readgen.len;
		read6.pos = readgen.pos;
		read6.idx = readgen.idx;
		read6.flag = readgen.flag;
	} else {
		read5.cd = krdc->remote_index;
		read5.len = readgen.len;
		read5.pos = readgen.pos;
		read5.idx = readgen.idx;
		read5.flag = readgen.flag;
	}

	if (readgen.flag & RDC_RREAD_START) {
		if (readgen.rpcversion == 6) {
			err = rdc_clnt_call(krdc->lsrv, RDCPROC_READ6,
			    RDC_VERSION6, xdr_rread6, (char *)&read6,
			    xdr_int, (char *)&ret, &t);
		} else {
			err = rdc_clnt_call(krdc->lsrv, RDCPROC_READ5,
			    RDC_VERSION5, xdr_rread, (char *)&read5,
			    xdr_int, (char *)&ret, &t);
		}
		if (err == 0) {
			*rvp = ret;
			ret = 0;
		} else {
			ret = EPROTO;
		}
	} else {
		if (readgen.rpcversion == 6) {
			err = rdc_clnt_call(krdc->lsrv, RDCPROC_READ6,
			    RDC_VERSION6, xdr_rread6, (char *)&read6,
			    xdr_rdresult, (char *)&rr, &t);
		} else {
			err = rdc_clnt_call(krdc->lsrv, RDCPROC_READ5,
			    RDC_VERSION5, xdr_rread, (char *)&read5,
			    xdr_rdresult, (char *)&rr, &t);
		}
		if (err == 0) {
			if (rr.rr_status != RDC_OK) {
				ret = EIO;
				goto out;
			}
			*rvp = rr.rr_bufsize;
			if (ddi_copyout(rr.rr_data, readgen.data,
			    rr.rr_bufsize, mode) != 0) {
				ret = EFAULT;
				goto out;
			}
			ret = 0;
		} else {
			ret = EPROTO;
			goto out;
		}
	}
out:
	if (rr.rr_data) {
		kmem_free(rr.rr_data, rr.rr_bufsize);
	}
	return (ret);
}


#endif
