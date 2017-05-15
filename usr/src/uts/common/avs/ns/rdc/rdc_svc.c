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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * kRPC Server for sndr
 */

#include <sys/types.h>
#include <sys/ksynch.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/cred.h>
#include <sys/conf.h>
#include <sys/stream.h>
#include <sys/errno.h>

#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_k.h>
#include <sys/unistat/spcs_errors.h>

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
#include <sys/ncall/ncall.h>

#include <sys/sdt.h>		/* dtrace is S10 or later */

#include "rdc_io.h"
#include "rdc_bitmap.h"
#include "rdcsrv.h"

static rdc_sleepq_t *rdc_newsleepq();
static void rdc_delsleepq(rdc_sleepq_t *);
static int rdc_sleepq(rdc_group_t *, rdc_sleepq_t *);
static int rdc_combywrite(rdc_k_info_t *, nsc_buf_t *);
static int rdc_writemaxfba(rdc_k_info_t *, rdc_u_info_t *,
    rdc_net_dataset_t *, uint_t, int);
static void rdc_setbitind(int *, net_pendvec_t *, rdc_net_dataset_t *, uint_t,
    int, int);
static void rdc_dopending(rdc_group_t *, netwriteres *);
static nsc_vec_t *rdc_dset2vec(rdc_net_dataset_t *);
static int rdc_combyread(rdc_k_info_t *, rdc_u_info_t *, nsc_buf_t *);
static int rdc_readmaxfba(int, nsc_off_t, nsc_size_t, int);
static int rdc_dsetcopy(rdc_net_dataset_t *, nsc_vec_t *, nsc_off_t, nsc_size_t,
    char *, int, int);

/* direction for dsetcopy() */
#define	COPY_IN		1	/* copy data into the rpc buffer */
#define	COPY_OUT	2	/* copy data out of the rpc buffer */

#define	MAX_EINTR_COUNT 1000

static int rdc_rread_slow;
static rdcsrv_t rdc_srvtab[];

#ifdef	DEBUG
static int rdc_netwrite6;
static int rdc_stall0;
static int rdc_sleepcnt;
int rdc_datasetcnt;
#endif


int
_rdc_sync_event_notify(int operation, char *volume, char *group)
{
	int ack = 0;
	clock_t time;

	mutex_enter(&rdc_sync_mutex);
	mutex_enter(&rdc_sync_event.mutex);

	if (rdc_sync_event.daemon_waiting) {
		rdc_sync_event.daemon_waiting = 0;
		rdc_sync_event.event = operation;
		(void) strncpy(rdc_sync_event.master, volume, NSC_MAXPATH);
		(void) strncpy(rdc_sync_event.group, group, NSC_MAXPATH);

		cv_signal(&rdc_sync_event.cv);

		rdc_sync_event.kernel_waiting = 1;
		time = cv_reltimedwait_sig(&rdc_sync_event.done_cv,
		    &rdc_sync_event.mutex, rdc_sync_event_timeout,
		    TR_CLOCK_TICK);
		if (time == (clock_t)0 || time == (clock_t)-1) {
			/* signalled or timed out */
			ack = 0;
		} else {
			if (rdc_sync_event.ack)
				ack = 1;
			else
				ack = -1;
		}
	}
	mutex_exit(&rdc_sync_event.mutex);
	mutex_exit(&rdc_sync_mutex);
	return (ack);
}


int
_rdc_sync_event_wait(void *arg0, void *arg1, int mode, spcs_s_info_t kstatus,
    int *rvp)
{
	int rc = 0;
	static char master[NSC_MAXPATH];

	master[0] = '\0';
	*rvp = 0;
	if (ddi_copyin(arg0, master, NSC_MAXPATH, mode))
		return (EFAULT);

	mutex_enter(&rdc_sync_event.mutex);

	if (rdc_sync_event.kernel_waiting &&
	    (rdc_sync_event.lbolt - nsc_lbolt() < rdc_sync_event_timeout)) {
		/* We haven't been away too long */
		if (master[0])
			rdc_sync_event.ack = 1;
		else
			rdc_sync_event.ack = 0;
		rdc_sync_event.kernel_waiting = 0;
		cv_signal(&rdc_sync_event.done_cv);
	}

	rdc_sync_event.daemon_waiting = 1;
	if (cv_wait_sig(&rdc_sync_event.cv, &rdc_sync_event.mutex) == 0) {
		rdc_sync_event.daemon_waiting = 0;
		rc = EAGAIN;
		spcs_s_add(kstatus, rc);
	} else {
		(void) ddi_copyout(rdc_sync_event.master, arg0, NSC_MAXPATH,
		    mode);
		(void) ddi_copyout(rdc_sync_event.group, arg1, NSC_MAXPATH,
		    mode);
		*rvp = rdc_sync_event.event;
	}
	rdc_sync_event.lbolt = nsc_lbolt();
	mutex_exit(&rdc_sync_event.mutex);

	return (rc);
}


static int
rdc_allow_sec_sync(rdc_u_info_t *urdc, int option)
{
	rdc_k_info_t *krdc = &rdc_k_info[urdc->index];
	rdc_k_info_t *ktmp;
	rdc_u_info_t *utmp;

	if (!IS_MULTI(krdc))
		return (0);

	rdc_many_enter(krdc);

	krdc = krdc->multi_next;
	urdc = &rdc_u_info[krdc->index];

	if (!IS_ENABLED(urdc)) {
		rdc_many_exit(krdc);
		return (0);
	}

	if (option == CCIO_RSYNC) {

		/* Reverse sync */

		if (rdc_get_mflags(urdc) & RDC_RSYNC_NEEDED) {
			/*
			 * Reverse sync needed or in progress.
			 */
			rdc_many_exit(krdc);
			return (-1);
		}
	} else {
		ASSERT(option == CCIO_SLAVE);

		/* Forward sync */

		if (rdc_get_mflags(urdc) & RDC_SLAVE) {
			/*
			 * Reverse syncing is bad, as that means that data
			 * is already flowing to the target of the requested
			 * sync operation.
			 */
			rdc_many_exit(krdc);
			return (-1);
		}

		/*
		 * Clear "reverse sync needed" on all 1-many volumes.
		 * The data on them will be updated from the primary of this
		 * requested sync operation, so the aborted reverse sync need
		 * not be completed.
		 */

		if ((rdc_get_mflags(urdc) & RDC_RSYNC_NEEDED) ||
		    (rdc_get_vflags(urdc) & RDC_VOL_FAILED)) {
			rdc_clr_mflags(urdc, RDC_RSYNC_NEEDED);
			rdc_clr_flags(urdc, RDC_VOL_FAILED);
			rdc_write_state(urdc);
		}
		if (IS_MANY(krdc)) {
			for (ktmp = krdc->many_next; ktmp != krdc;
			    ktmp = ktmp->many_next) {
				utmp = &rdc_u_info[ktmp->index];
				if (!IS_ENABLED(utmp))
					continue;
				if (rdc_get_mflags(utmp) & RDC_RSYNC_NEEDED) {
					rdc_clr_mflags(utmp, RDC_RSYNC_NEEDED);
					rdc_write_state(utmp);
				}
			}
		}
	}

	rdc_many_exit(krdc);

	return (0);
}


/*
 * r_net_null
 * Proc 0 Null action
 */
static void
r_net_null(SVCXPRT *xprt)
{
	(void) svc_sendreply(xprt, xdr_void, 0);
}

/*
 * r_net_read
 */
static void
r_net_read(SVCXPRT *xprt)
{
	readres resp;
	rdc_u_info_t *urdc;
	struct rread diskio;
	char *buffer = NULL;
	uchar_t *sv_addr;
	nsc_vec_t *vec;
	int pos, st;
	int nocache;
	int sv_len;
	nsc_vec_t *vector = NULL;
	rdc_net_dataset_t *dset = NULL;
	int vecsz = 0;

	st = SVC_GETARGS(xprt, xdr_rread, (char *)&diskio);
	if (!st) {
		(void) svc_sendreply(xprt, xdr_int, (char *)&st);
		return;
	}
	nocache = (diskio.flag & RDC_RREAD_FAIL) ? 0 : NSC_NOCACHE;

	if ((diskio.cd >= rdc_max_sets) || (diskio.cd < 0)) {
		resp.rr_status = RDCERR_NOENT;
		(void) svc_sendreply(xprt, xdr_readres, (char *)&resp);
#ifdef DEBUG
		cmn_err(CE_NOTE,
		    "!r_net_read: EPROTO cd out or not enabled");
#endif
		return;
	}

	urdc = &rdc_u_info[diskio.cd];

	if (diskio.flag & RDC_RREAD_START) {
		/* setup rpc */
		if (!IS_ENABLED(urdc)) {
			st = 0;
			(void) svc_sendreply(xprt, xdr_int, (char *)&st);
			return;
		}
		st = rdc_readmaxfba(diskio.cd, diskio.pos, diskio.len,
		    nocache);

		if (!svc_sendreply(xprt, xdr_int, (char *)&st)) {
			if (st != 0) {
				rdc_net_dataset_t *dset;
				if (dset = rdc_net_get_set(diskio.cd, st)) {
					rdc_net_del_set(diskio.cd, dset);
				} else {
					cmn_err(CE_NOTE, "!r_net_read: get_set "
					    "has failed in cleanup");
				}
			}
		}
		return;
	}

	/* data rpc */

#ifdef DEBUG
	if ((diskio.flag & RDC_RREAD_DATA) == 0) {
		cmn_err(CE_WARN, "!r_net_read: received non-DATA rpc! flag %x",
		    diskio.flag);
	}
#endif

	dset = rdc_net_get_set(diskio.cd, diskio.idx);
	if (dset) {
		vector = rdc_dset2vec(dset);
	}
	if (vector == NULL) {
		resp.rr_status = RDCERR_NOMEM;
		(void) svc_sendreply(xprt, xdr_readres, (char *)&resp);
		goto cleanup;
	}
	vecsz = (dset->nitems + 1) * sizeof (nsc_vec_t);

	if (!IS_ENABLED(urdc)) {
		resp.rr_status = RDCERR_NOENT;
		(void) svc_sendreply(xprt, xdr_readres, (char *)&resp);
		goto cleanup;
	}
	resp.rr_status = RDC_OK;

	/* find place in vector */
	vec = vector;
	pos = diskio.pos - dset->pos;

	for (; pos >= FBA_NUM(vec->sv_len); vec++)
		pos -= FBA_NUM(vec->sv_len);

	sv_addr = vec->sv_addr + FBA_SIZE(pos);
	sv_len = vec->sv_len - FBA_SIZE(pos);

	/*
	 * IF the data is in a single sb_vec entry
	 * THEN
	 *	we can just point to that
	 * ELSE
	 *	we have to alloc a local buffer,
	 *	copy the data in and the point to
	 *	the local buffer.
	 */

	if (sv_len >= FBA_SIZE(diskio.len)) {
		/* fast */
		resp.rr_data = (char *)sv_addr;
		resp.rr_bufsize = FBA_SIZE(diskio.len);
	} else {
		/* slow */
		rdc_rread_slow++;	/* rough count */
		resp.rr_bufsize = FBA_SIZE(diskio.len);
		buffer = kmem_alloc(resp.rr_bufsize, KM_NOSLEEP);
		if (!buffer) {
			resp.rr_status = RDCERR_NOMEM;
		} else {
			resp.rr_data = buffer;
			if (!rdc_dsetcopy(dset, vector, diskio.pos, diskio.len,
			    resp.rr_data, resp.rr_bufsize, COPY_IN)) {
				resp.rr_status = RDCERR_NOMEM; /* ??? */
			}
		}
	}

	st = svc_sendreply(xprt, xdr_readres, (char *)&resp); /* send data */

cleanup:

	if (dset) {
		if (!st ||
		    (diskio.flag & RDC_RREAD_END) ||
		    (resp.rr_status != RDC_OK)) {
			/*
			 * RPC reply failed, OR
			 * Last RPC for this IO operation, OR
			 * We are failing this IO operation.
			 *
			 * Do cleanup.
			 */
			rdc_net_del_set(diskio.cd, dset);
		} else {
			rdc_net_put_set(diskio.cd, dset);
		}
	}

	if (buffer)
		kmem_free(buffer, resp.rr_bufsize);
	if (vector) {
		kmem_free(vector, vecsz);
		RDC_DSMEMUSE(-vecsz);
	}
}

/*
 * r_net_read (v6)
 */
static void
r_net_read6(SVCXPRT *xprt)
{
	readres resp;
	rdc_u_info_t *urdc;
	struct rread6 diskio;
	char *buffer = NULL;
	uchar_t *sv_addr;
	nsc_vec_t *vec;
	int pos, st;
	int nocache;
	int sv_len;
	nsc_vec_t *vector = NULL;
	rdc_net_dataset_t *dset = NULL;
	int vecsz = 0;

	st = SVC_GETARGS(xprt, xdr_rread6, (char *)&diskio);
	if (!st) {
		(void) svc_sendreply(xprt, xdr_int, (char *)&st);
		return;
	}
	nocache = (diskio.flag & RDC_RREAD_FAIL) ? 0 : NSC_NOCACHE;

	if ((diskio.cd >= rdc_max_sets) || (diskio.cd < 0)) {
		resp.rr_status = RDCERR_NOENT;
		(void) svc_sendreply(xprt, xdr_readres, (char *)&resp);
#ifdef DEBUG
		cmn_err(CE_NOTE, "!r_net_read6: EPROTO cd out or not enabled");
#endif
		return;
	}

	urdc = &rdc_u_info[diskio.cd];

	if (diskio.flag & RDC_RREAD_START) {
		/* setup rpc */
		if (!IS_ENABLED(urdc)) {
			st = 0;
			(void) svc_sendreply(xprt, xdr_int, (char *)&st);
			return;
		}
		st = rdc_readmaxfba(diskio.cd, diskio.pos, diskio.len,
		    nocache);

		if (!svc_sendreply(xprt, xdr_int, (char *)&st)) {
			if (st != 0) {
				rdc_net_dataset_t *dset;
				if (dset = rdc_net_get_set(diskio.cd, st)) {
					rdc_net_del_set(diskio.cd, dset);
				} else {
					cmn_err(CE_NOTE, "!read6: get_set "
					    "has failed in cleanup");
				}
			}
		}
		return;
	}

	/* data rpc */

#ifdef DEBUG
	if ((diskio.flag & RDC_RREAD_DATA) == 0) {
		cmn_err(CE_WARN, "!read6: received non-DATA rpc! flag %x",
		    diskio.flag);
	}
#endif

	dset = rdc_net_get_set(diskio.cd, diskio.idx);
	if (dset) {
		vector = rdc_dset2vec(dset);
	}
	if (vector == NULL) {
		resp.rr_status = RDCERR_NOMEM;
		(void) svc_sendreply(xprt, xdr_readres, (char *)&resp);
		goto cleanup;
	}
	vecsz = (dset->nitems + 1) * sizeof (nsc_vec_t);

	if (!IS_ENABLED(urdc)) {
		resp.rr_status = RDCERR_NOENT;
		(void) svc_sendreply(xprt, xdr_readres, (char *)&resp);
		goto cleanup;
	}
	resp.rr_status = RDC_OK;

	/* find place in vector */
	vec = vector;
	pos = diskio.pos - dset->pos;

	for (; pos >= FBA_NUM(vec->sv_len); vec++)
		pos -= FBA_NUM(vec->sv_len);

	sv_addr = vec->sv_addr + FBA_SIZE(pos);
	sv_len = vec->sv_len - FBA_SIZE(pos);

	/*
	 * IF the data is in a single sb_vec entry
	 * THEN
	 *	we can just point to that
	 * ELSE
	 *	we have to alloc a local buffer,
	 *	copy the data in and the point to
	 *	the local buffer.
	 */

	if (sv_len >= FBA_SIZE(diskio.len)) {
		/* fast */
		resp.rr_data = (char *)sv_addr;
		resp.rr_bufsize = FBA_SIZE(diskio.len);
	} else {
		/* slow */
		rdc_rread_slow++;	/* rough count */
		resp.rr_bufsize = FBA_SIZE(diskio.len);
		buffer = kmem_alloc(resp.rr_bufsize, KM_NOSLEEP);
		if (!buffer) {
			resp.rr_status = RDCERR_NOMEM;
		} else {
			resp.rr_data = buffer;
			if (!rdc_dsetcopy(dset, vector, diskio.pos, diskio.len,
			    resp.rr_data, resp.rr_bufsize, COPY_IN)) {
				resp.rr_status = RDCERR_NOMEM; /* ??? */
			}
		}
	}

	st = svc_sendreply(xprt, xdr_readres, (char *)&resp); /* send data */

cleanup:

	if (dset) {
		if (!st ||
		    (diskio.flag & RDC_RREAD_END) ||
		    (resp.rr_status != RDC_OK)) {
			/*
			 * RPC reply failed, OR
			 * Last RPC for this IO operation, OR
			 * We are failing this IO operation.
			 *
			 * Do cleanup.
			 */
			rdc_net_del_set(diskio.cd, dset);
		} else {
			rdc_net_put_set(diskio.cd, dset);
		}
	}

	if (buffer)
		kmem_free(buffer, resp.rr_bufsize);
	if (vector) {
		kmem_free(vector, vecsz);
		RDC_DSMEMUSE(-vecsz);
	}
}

/*
 * r_net_write (Version 5)
 * 0 reply indicates error
 * >0 reply indicates a net handle index
 * <0 reply indicates errno
 * ret net handle index
 * ret2 general error
 * ret3 multi-hop errors (never returned)
 */
static void
r_net_write5(SVCXPRT *xprt)
{
	rdc_k_info_t *krdc;
	rdc_u_info_t *urdc;
	struct net_data5 diskio;
	rdc_net_dataset_t *dset;
	rdc_net_dataitem_t *ditem;
	int nocache;
	int ret = 0;
	int ret2 = 0;
	int st;

	krdc = NULL;
	diskio.data.data_val = kmem_alloc(RDC_MAXDATA, KM_NOSLEEP);

	if (!diskio.data.data_val) {
		ret2 = ENOMEM;
		goto out;
	}
	RDC_DSMEMUSE(RDC_MAXDATA);
	st = SVC_GETARGS(xprt, xdr_net_data5, (char *)&diskio);
	if (!st) {
		ret2 = ENOMEM;
#ifdef DEBUG
		cmn_err(CE_NOTE, "!r_net_write5:SVC_GETARGS failed: st %d", st);
#endif
		goto out;
	}
	if ((diskio.cd >= rdc_max_sets) || (diskio.cd < 0)) {
		ret2 = EPROTO;
#ifdef DEBUG
		cmn_err(CE_NOTE, "!r_net_write6: EPROTO cd out or not enabled");
#endif
		goto out;
	}

	nocache = (diskio.flag & RDC_RWRITE_FAIL) ? 0 : NSC_NOCACHE;
	krdc = &rdc_k_info[diskio.cd];
	urdc = &rdc_u_info[diskio.cd];

	if (!IS_ENABLED(urdc) || IS_STATE(urdc, RDC_LOGGING)) {
		ret2 = EPROTO;
#ifdef DEBUG
		cmn_err(CE_NOTE, "!r_net_write6: cd logging / not enabled (%x)",
		    rdc_get_vflags(urdc));
#endif
		krdc = NULL; /* so we don't try to unqueue kstat entry */
		goto out;
	}

	if (krdc->io_kstats) {
		mutex_enter(krdc->io_kstats->ks_lock);
		kstat_runq_enter(KSTAT_IO_PTR(krdc->io_kstats));
		mutex_exit(krdc->io_kstats->ks_lock);
	}


	/* -1 index says allocate a buffer */
	if (diskio.idx < 0) {
		dset = rdc_net_add_set(diskio.cd);
		if (dset == NULL) {
#ifdef DEBUG
			cmn_err(CE_NOTE, "!r_net_write5: "
			    "failed to add dataset");
#endif
			ret2 = EIO;
			goto out;
		} else {
			ret = dset->id;
			dset->pos = diskio.pos;
			dset->fbalen = diskio.len;
			diskio.idx = ret;
		}
		ditem = kmem_alloc(sizeof (rdc_net_dataitem_t), KM_NOSLEEP);
		if (ditem == NULL) {
			ret2 = ENOMEM;
			goto out;
		}
		RDC_DSMEMUSE(sizeof (rdc_net_dataitem_t));
		/*
		 * If this is a single transfer, then we don't
		 * need to allocate any memory for the data,
		 * just point the ditem data pointer to the
		 * existing buffer.
		 */
		ditem->next = NULL;
		if (diskio.endoblk) {
			ditem->dptr = diskio.data.data_val;
			/*
			 * So we don't free it twice.
			 */
			diskio.data.data_val = NULL;
			ditem->len = diskio.data.data_len;
			ditem->mlen = RDC_MAXDATA;
		} else {
			/*
			 * Allocate the memory for the complete
			 * transfer.
			 */
			ditem->dptr = kmem_alloc(FBA_SIZE(diskio.len),
			    KM_NOSLEEP);
			if (ditem->dptr == NULL) {
				ret2 = ENOMEM;
				goto out;
			}
			RDC_DSMEMUSE(FBA_SIZE(diskio.len));
			ditem->len = FBA_SIZE(diskio.len);
			ditem->mlen = ditem->len;

			/*
			 * Copy the data to the new buffer.
			 */
			ASSERT(diskio.data.data_len == FBA_SIZE(diskio.nfba));
			bcopy(diskio.data.data_val, ditem->dptr,
			    diskio.data.data_len);
			/*
			 * free the old data buffer.
			 */
			kmem_free(diskio.data.data_val, RDC_MAXDATA);
			RDC_DSMEMUSE(-RDC_MAXDATA);
			diskio.data.data_val = NULL;
		}
		dset->head = ditem;
		dset->tail = ditem;
		dset->nitems++;
	} else {
		ret = diskio.idx;
		dset = rdc_net_get_set(diskio.cd, diskio.idx);
		if (dset == NULL) {
			ret2 = EPROTO;
#ifdef DEBUG
			cmn_err(CE_NOTE,
			    "!r_net_write5: net_get_set failed cd %d idx %d",
			    diskio.cd, diskio.idx);
#endif
			goto out;
		}
		/*
		 * We have to copy the data from the rpc buffer
		 * to the data in ditem.
		 */
		ditem = dset->head;
		bcopy(diskio.data.data_val, (char *)ditem->dptr +
		    FBA_SIZE(diskio.sfba - diskio.pos), diskio.data.data_len);

		kmem_free(diskio.data.data_val, RDC_MAXDATA);
		RDC_DSMEMUSE(-RDC_MAXDATA);
		diskio.data.data_val = NULL;
	}
	ASSERT(dset);

	if (diskio.endoblk) {
		ret2 = rdc_writemaxfba(krdc, urdc, dset, diskio.seq, nocache);
		rdc_net_del_set(diskio.cd, dset);
		dset = NULL;
	}
out:
	if (!RDC_SUCCESS(ret2)) {
		if (ret2 > 0)
			ret2 = -ret2;
		DTRACE_PROBE1(rdc_svcwrite5_err_ret2, int, ret2);
		st = svc_sendreply(xprt, xdr_int, (char *)&ret2);
	} else
		st = svc_sendreply(xprt, xdr_int, (char *)&ret);

	if (krdc && krdc->io_kstats && ret2 != ENOMEM) {
		mutex_enter(krdc->io_kstats->ks_lock);
		kstat_runq_exit(KSTAT_IO_PTR(krdc->io_kstats));
		mutex_exit(krdc->io_kstats->ks_lock);
	}
	/*
	 * On Error we must cleanup.
	 * If we have a handle, free it.
	 * If we have a network handle, free it.
	 */
	if (!st || !RDC_SUCCESS(ret2)) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!r_net_write5 error case? st %x ret %d",
		    st, ret2);
#endif
		if (dset) {
			rdc_net_del_set(diskio.cd, dset);
		}

	} else {
		if (dset) {
			rdc_net_put_set(diskio.cd, dset);
		}
	}
	if (diskio.data.data_val) {
		kmem_free(diskio.data.data_val, RDC_MAXDATA);
		RDC_DSMEMUSE(-RDC_MAXDATA);
	}
}

/*
 * r_net_write (Version 6)
 * index 0 = error, or net handle index.
 * result = 0 , ok.
 * result = 1, pending write.
 * result < 0 error, and is the -errno.
 * ret net handle index.
 * ret2 general error.
 */
static void
r_net_write6(SVCXPRT *xprt)
{
	rdc_k_info_t *krdc;
	rdc_u_info_t *urdc;
	rdc_group_t *group;
	struct net_data6 diskio;
	struct netwriteres netret;
	rdc_net_dataset_t *dset;
	rdc_net_dataitem_t *ditem;
	int ret = 0;
	int ret2 = 0;
	int st;
	int nocache;

	netret.vecdata.vecdata_val = NULL;
	netret.vecdata.vecdata_len = 0;
	dset = NULL;
	krdc = NULL;
	diskio.data.data_val = kmem_alloc(RDC_MAXDATA, KM_NOSLEEP);

	if (!diskio.data.data_val) {
		ret2 = ENOMEM;
		goto out;
	}
	RDC_DSMEMUSE(RDC_MAXDATA);
	st = SVC_GETARGS(xprt, xdr_net_data6, (char *)&diskio);
	if (!st) {
		ret2 = ENOMEM;
#ifdef DEBUG
		cmn_err(CE_NOTE,
		    "!r_net_write6:SVC_GETARGS failed: st  %d", st);
#endif
		goto out;
	}

	if ((diskio.cd >= rdc_max_sets) || (diskio.cd < 0)) {
		ret2 = EPROTO;
#ifdef DEBUG
		cmn_err(CE_NOTE, "!r_net_write6: EPROTO cd out or not enabled");
#endif
		goto out;
	}

	nocache = (diskio.flag & RDC_RWRITE_FAIL) ? 0 : NSC_NOCACHE;
	netret.seq = diskio.seq;

	krdc = &rdc_k_info[diskio.cd];
	urdc = &rdc_u_info[diskio.cd];

	if (!IS_ENABLED(urdc) || IS_STATE(urdc, RDC_LOGGING)) {
		ret2 = EPROTO;
#ifdef DEBUG
		cmn_err(CE_NOTE,
		    "!r_net_write6: cd logging or not enabled (%x)",
		    rdc_get_vflags(urdc));
#endif
		krdc = NULL; /* so we don't try to unqueue kstat entry */
		goto out;
	}

	group = krdc->group;
	if (group == NULL) {
		ret2 = EIO;
#ifdef DEBUG
		cmn_err(CE_NOTE,
		    "!r_net_write6: No group structure for set %s:%s",
		    urdc->secondary.intf, urdc->secondary.file);
#endif
		krdc = NULL; /* so we don't try to unqueue kstat entry */
		goto out;
	}

#ifdef DEBUG
	if (rdc_netwrite6) {
		cmn_err(CE_NOTE,
		    "!r_net_write6: idx %d seq %u current seq %u pos %llu "
		    "len %d sfba %llu nfba %d endoblk %d",
		    diskio.idx, diskio.seq, group->seq,
		    (unsigned long long)diskio.pos, diskio.len,
		    (unsigned long long)diskio.sfba, diskio.nfba,
		    diskio.endoblk);
	}
#endif

	if (krdc->io_kstats) {
		mutex_enter(krdc->io_kstats->ks_lock);
		kstat_runq_enter(KSTAT_IO_PTR(krdc->io_kstats));
		mutex_exit(krdc->io_kstats->ks_lock);
	}

	/* -1 index says allocate a net dataset */
	if (diskio.idx < 0) {
		dset = rdc_net_add_set(diskio.cd);
		if (dset == NULL) {
#ifdef DEBUG
			cmn_err(CE_NOTE,
			    "!r_net_write6: failed to add dataset");
#endif
			ret2 = EIO;
			goto out;
		} else {
			ret = dset->id;
			dset->pos = (nsc_off_t)diskio.pos; /* 64bit! */
			dset->fbalen = diskio.len;
			diskio.idx = ret;
		}
		ditem = kmem_alloc(sizeof (rdc_net_dataitem_t), KM_NOSLEEP);
		if (ditem == NULL) {
			ret2 = ENOMEM;
			goto out;
		}
		RDC_DSMEMUSE(sizeof (rdc_net_dataitem_t));
		/*
		 * If this is a single transfer, then we don't
		 * need to allocate any memory for the data,
		 * just point the ditem data pointer to the
		 * existing buffer.
		 */
		ditem->next = NULL;
		if (diskio.endoblk) {
			ditem->dptr = diskio.data.data_val;
			/*
			 * So we don't free it twice.
			 */
			diskio.data.data_val = NULL;
			ditem->len = diskio.data.data_len;
			ditem->mlen = RDC_MAXDATA;
		} else {
			/*
			 * Allocate the memory for the complete
			 * transfer.
			 */
			ditem->dptr = kmem_alloc(FBA_SIZE(diskio.len),
			    KM_NOSLEEP);
			if (ditem->dptr == NULL) {
				ret2 = ENOMEM;
				goto out;
			}
			RDC_DSMEMUSE(FBA_SIZE(diskio.len));
			ditem->len = FBA_SIZE(diskio.len);
			ditem->mlen = ditem->len;

			/*
			 * Copy the data to the new buffer.
			 */
			ASSERT(diskio.data.data_len == FBA_SIZE(diskio.nfba));
			bcopy(diskio.data.data_val, ditem->dptr,
			    diskio.data.data_len);
			/*
			 * free the old data buffer.
			 */
			kmem_free(diskio.data.data_val, RDC_MAXDATA);
			RDC_DSMEMUSE(-RDC_MAXDATA);
			diskio.data.data_val = NULL;
		}
		dset->head = ditem;
		dset->tail = ditem;
		dset->nitems++;
	} else {
		ret = diskio.idx;
		dset = rdc_net_get_set(diskio.cd, diskio.idx);
		if (dset == NULL) {
			ret2 = EPROTO;
#ifdef DEBUG
			cmn_err(CE_NOTE,
			    "!r_net_write6: net_get_set failed cd %d idx %d "
			    "packet sequence %u expected seq %u",
			    diskio.cd, diskio.idx, diskio.seq, group->seq);
#endif
			goto out;
		}
		/*
		 * We have to copy the data from the rpc buffer
		 * to the data in ditem.
		 */
		ditem = dset->head;
		bcopy(diskio.data.data_val, (char *)ditem->dptr +
		    FBA_SIZE(diskio.sfba - diskio.pos), diskio.data.data_len);

		kmem_free(diskio.data.data_val, RDC_MAXDATA);
		RDC_DSMEMUSE(-RDC_MAXDATA);
		diskio.data.data_val = NULL;
	}
	ASSERT(dset);

	if (diskio.endoblk) {
#ifdef DEBUG
		if (diskio.seq == (RDC_NEWSEQ + 1)) {
			rdc_stallzero(2);
		}
#endif
		if (diskio.seq == RDC_NEWSEQ) {
			/*
			 * magic marker, start of sequence.
			 */
			mutex_enter(&group->ra_queue.net_qlock);
			/*
			 * see if some threads are stuck.
			 */
			if (group->sleepq) {
				rdc_sleepqdiscard(group);
			}
			group->seqack = RDC_NEWSEQ;
			mutex_exit(&group->ra_queue.net_qlock);
		}

		if ((diskio.seq != RDC_NOSEQ) && (diskio.seq != RDC_NEWSEQ)) {
			/*
			 * see if we are allowed through here to
			 * do the write, or if we have to q the
			 * request and send back a pending reply.
			 */
			mutex_enter(&group->ra_queue.net_qlock);
			if (diskio.seq != group->seq) {
				rdc_sleepq_t	*sq;
				int maxseq;

				/*
				 * Check that we have room.
				 */
				maxseq = group->seqack + RDC_MAXPENDQ + 1;
				if (maxseq < group->seqack) {
					/*
					 * skip magic values.
					 */
					maxseq += RDC_NEWSEQ + 1;
				}
				if (!RDC_INFRONT(diskio.seq, maxseq)) {
#ifdef	DEBUG
					cmn_err(CE_WARN, "!net_write6: Queue "
					    "size %d exceeded seqack %u "
					    "this seq %u maxseq %u seq %u",
					    RDC_MAXPENDQ, group->seqack,
					    diskio.seq, maxseq, group->seq);
#endif
				DTRACE_PROBE2(qsize_exceeded, int, diskio.seq,
				    int, maxseq);
					if (!(rdc_get_vflags(urdc) &
					    RDC_VOL_FAILED)) {
						rdc_many_enter(krdc);
						rdc_set_flags(urdc,
						    RDC_VOL_FAILED);
						rdc_many_exit(krdc);
						rdc_write_state(urdc);
					}
					ret2 = EIO;
					rdc_sleepqdiscard(group);
					group->seq = RDC_NEWSEQ;
					group->seqack = RDC_NEWSEQ;
					mutex_exit(&group->ra_queue.net_qlock);
					goto out;
				}

				sq = rdc_newsleepq();
				sq->seq = diskio.seq;
				sq->sindex = diskio.cd;
				sq->pindex = diskio.local_cd;
				sq->idx = diskio.idx;
				sq->qpos = diskio.qpos;
				sq->nocache = nocache;
				if (rdc_sleepq(group, sq)) {
					ret2 = EIO;
					group->seq = RDC_NEWSEQ;
					group->seqack = RDC_NEWSEQ;
					rdc_sleepqdiscard(group);
					mutex_exit(&group->ra_queue.net_qlock);
					goto out;
				}
				rdc_net_put_set(diskio.cd, dset);
				dset = NULL;
				if (krdc->io_kstats) {
					mutex_enter(krdc->io_kstats->ks_lock);
					kstat_waitq_enter(KSTAT_IO_PTR(krdc->
					    io_kstats));
					mutex_exit(krdc->io_kstats->ks_lock);
				}
				mutex_exit(&group->ra_queue.net_qlock);
				/*
				 * pending state.
				 */
				netret.result = 1;
				netret.index = diskio.idx;
				st = svc_sendreply(xprt, xdr_netwriteres,
				    (char *)&netret);
				if (krdc->io_kstats && ret2 != ENOMEM) {
					mutex_enter(krdc->io_kstats->ks_lock);
					kstat_runq_exit(KSTAT_IO_PTR(
					    krdc->io_kstats));
					mutex_exit(krdc->io_kstats->ks_lock);
				}
				return;
			}
			mutex_exit(&group->ra_queue.net_qlock);
		}

		ret2 = rdc_writemaxfba(krdc, urdc, dset, diskio.seq, nocache);
		rdc_net_del_set(diskio.cd, dset);
		dset = NULL;
#ifdef	DEBUG
		if (!RDC_SUCCESS(ret2)) {
			cmn_err(CE_WARN, "!r_net_write6: writemaxfba failed %d",
			    ret2);
		}
#endif
		if (diskio.seq != RDC_NOSEQ) {
			mutex_enter(&group->ra_queue.net_qlock);
			group->seq = diskio.seq + 1;
			if (group->seq < diskio.seq)
				group->seq = RDC_NEWSEQ + 1;
			if (group->sleepq &&
			    (group->sleepq->seq == group->seq)) {
				rdc_dopending(group, &netret);
			}
			group->seqack = group->seq;
			mutex_exit(&group->ra_queue.net_qlock);
		}
	}
out:
	if (!RDC_SUCCESS(ret2)) {
		DTRACE_PROBE1(rdc_svcwrite6_err_ret2, int, ret2);
		netret.result = -ret2;
	} else {
		netret.result = 0;
		netret.index = ret;
	}
	st = svc_sendreply(xprt, xdr_netwriteres, (char *)&netret);
	if (netret.vecdata.vecdata_val) {
		kmem_free(netret.vecdata.vecdata_val,
		    netret.vecdata.vecdata_len * sizeof (net_pendvec_t));
	}
	if (krdc && krdc->io_kstats && ret2 != ENOMEM) {
		mutex_enter(krdc->io_kstats->ks_lock);
		kstat_runq_exit(KSTAT_IO_PTR(krdc->io_kstats));
		mutex_exit(krdc->io_kstats->ks_lock);
	}
	/*
	 * On Error we must cleanup.
	 * If we have a handle, free it.
	 * If we have a network handle, free it.
	 * If we hold the main nsc buffer, free it.
	 */
	if (!st || !RDC_SUCCESS(ret2)) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!r_net_write6 error st %x ret %d seq %u",
		    st, ret2, diskio.seq);
#endif
		if (dset) {
			rdc_net_del_set(diskio.cd, dset);
		}
	} else {
		if (dset) {
			rdc_net_put_set(diskio.cd, dset);
		}
	}
	if (diskio.data.data_val) {
		kmem_free(diskio.data.data_val, RDC_MAXDATA);
		RDC_DSMEMUSE(-RDC_MAXDATA);
	}
}

/*
 * r_net_ping4
 *
 * received on the primary.
 */
static void
r_net_ping4(SVCXPRT *xprt, struct svc_req *req)
{
	struct rdc_ping6 ping;
	int e, ret = 0;
	rdc_if_t *ip;

	e = SVC_GETARGS(xprt, xdr_rdc_ping6, (char *)&ping);
	if (e) {
		mutex_enter(&rdc_ping_lock);

		/* update specified interface */

		for (ip = rdc_if_top; ip; ip = ip->next) {
			if ((bcmp(ping.p_ifaddr, ip->ifaddr.buf,
			    RDC_MAXADDR) == 0) &&
			    (bcmp(ping.s_ifaddr, ip->r_ifaddr.buf,
			    RDC_MAXADDR) == 0)) {
				ip->new_pulse++;
				ip->deadness = 1;

				/* Update the rpc protocol version to use */

				ip->rpc_version = req->rq_vers;
				break;
			}
		}

		mutex_exit(&rdc_ping_lock);
	} else {
		svcerr_decode(xprt);
#ifdef DEBUG
		cmn_err(CE_NOTE, "!SNDR: couldn't get ping4 arguments");
#endif
	}

	(void) svc_sendreply(xprt, xdr_int, (char *)&ret);
}

/*
 * r_net_ping7
 *
 * received on the primary.
 */
static void
r_net_ping7(SVCXPRT *xprt, struct svc_req *req)
{
	struct rdc_ping ping;
	int e, ret = 0;
	rdc_if_t *ip;
	unsigned short *sp;

	bzero(&ping, sizeof (struct rdc_ping));
	e = SVC_GETARGS(xprt, xdr_rdc_ping, (char *)&ping);
	if (e) {
		sp = (unsigned short *)ping.p_ifaddr.buf;
		*sp = ntohs(*sp);
		sp = (unsigned short *)ping.s_ifaddr.buf;
		*sp = ntohs(*sp);
		mutex_enter(&rdc_ping_lock);

		/* update specified interface */

		for (ip = rdc_if_top; ip; ip = ip->next) {
			if ((bcmp(ping.p_ifaddr.buf, ip->ifaddr.buf,
			    ping.p_ifaddr.len) == 0) &&
			    (bcmp(ping.s_ifaddr.buf, ip->r_ifaddr.buf,
			    ping.s_ifaddr.len) == 0)) {
				ip->new_pulse++;
				ip->deadness = 1;

				/* Update the rpc protocol version to use */

				ip->rpc_version = req->rq_vers;
				break;
			}
		}

		mutex_exit(&rdc_ping_lock);
	} else {
		svcerr_decode(xprt);
#ifdef DEBUG
		cmn_err(CE_NOTE, "!SNDR: couldn't get ping7 arguments");
#endif
	}

	(void) svc_sendreply(xprt, xdr_int, (char *)&ret);
}


/*
 * r_net_bmap (v5)
 * WARNING acts as both client and server
 */
static void
r_net_bmap(SVCXPRT *xprt)
{
	int e, ret = EINVAL;
	struct bmap b;
	rdc_k_info_t *krdc;
	rdc_u_info_t *urdc;
	struct bmap6 b6;


	e = SVC_GETARGS(xprt, xdr_bmap, (char *)&b);
	if (e == TRUE) {
		krdc = &rdc_k_info[b.cd];
		urdc = &rdc_u_info[b.cd];
		if (b.cd >= 0 && b.cd < rdc_max_sets && IS_ENABLED(urdc) &&
		    ((krdc->type_flag & RDC_DISABLEPEND) == 0)) {
			krdc->rpc_version = RDC_VERSION5;
			b6.cd = b.cd;
			b6.dual = b.dual;
			b6.size = b.size;
			ret = RDC_SEND_BITMAP(&b6);
		}
	}

	(void) svc_sendreply(xprt, xdr_int, (char *)&ret);
}

/*
 * r_net_bmap (v6)
 * WARNING acts as both client and server
 */
static void
r_net_bmap6(SVCXPRT *xprt)
{
	int e, ret = EINVAL;
	struct bmap6 b;
	rdc_k_info_t *krdc;
	rdc_u_info_t *urdc;

	e = SVC_GETARGS(xprt, xdr_bmap6, (char *)&b);
	if (e == TRUE) {
		krdc = &rdc_k_info[b.cd];
		urdc = &rdc_u_info[b.cd];
		if (b.cd >= 0 && b.cd < rdc_max_sets && IS_ENABLED(urdc) &&
		    ((krdc->type_flag & RDC_DISABLEPEND) == 0)) {
			krdc->rpc_version = RDC_VERSION6;
			ret = RDC_SEND_BITMAP(&b);
		}
	}
	/*
	 * If the bitmap send has succeeded, clear it.
	 */
	if (ret == 0) {
#ifdef DEBUG
		cmn_err(CE_NOTE, "!Bitmap clear in r_net_bmap6");
#endif
		RDC_ZERO_BITMAP(krdc);
		rdc_many_enter(krdc);
		rdc_clr_flags(urdc, RDC_CLR_AFTERSYNC);
		rdc_many_exit(krdc);
	}
	(void) svc_sendreply(xprt, xdr_int, (char *)&ret);
}

/*
 * r_net_bdata
 */
static void
r_net_bdata(SVCXPRT *xprt)
{
	struct net_bdata bd;
	struct net_bdata6 bd6;
	int e, ret = -1;
	rdc_k_info_t *krdc;
	rdc_u_info_t *urdc;

	/*
	 * We have to convert it to the internal form here,
	 * net_data6, when we know that we will have to convert
	 * it back to the v5 variant for transmission.
	 */

	bd.data.data_val = kmem_alloc(BMAP_BLKSIZE, KM_NOSLEEP);
	if (bd.data.data_val == NULL)
		goto out;

	e = SVC_GETARGS(xprt, xdr_net_bdata, (char *)&bd);
	if (e == TRUE) {
		krdc = &rdc_k_info[bd.cd];
		urdc = &rdc_u_info[bd.cd];
		if (bd.cd >= 0 && bd.cd < rdc_max_sets && IS_ENABLED(urdc) &&
		    ((krdc->type_flag & RDC_DISABLEPEND) == 0)) {
			bd6.cd = bd.cd;
			bd6.offset = bd.offset;
			bd6.size = bd.size;
			bd6.data.data_len = bd.data.data_len;
			bd6.data.data_val = bd.data.data_val;
			ret = RDC_OR_BITMAP(&bd6);
		}
	}
	kmem_free(bd.data.data_val, BMAP_BLKSIZE);
out:
	(void) svc_sendreply(xprt, xdr_int, (char *)&ret);
}

/*
 * r_net_bdata v6
 */
static void
r_net_bdata6(SVCXPRT *xprt)
{
	struct net_bdata6 bd;
	int e, ret = -1;
	rdc_k_info_t *krdc;
	rdc_u_info_t *urdc;

	/*
	 * just allocate the bigger block, regardless of < V7
	 * bd.size will dictate how much we lor into our bitmap
	 * the other option would be write r_net_bdata7 that is identical
	 * to this function, but a V7 alloc.
	 */
	bd.data.data_val = kmem_alloc(BMAP_BLKSIZEV7, KM_NOSLEEP);
	if (bd.data.data_val == NULL)
		goto out;

	e = SVC_GETARGS(xprt, xdr_net_bdata6, (char *)&bd);
	if (e == TRUE) {
		krdc = &rdc_k_info[bd.cd];
		urdc = &rdc_u_info[bd.cd];
		if (bd.cd >= 0 && bd.cd < rdc_max_sets && IS_ENABLED(urdc) &&
		    ((krdc->type_flag & RDC_DISABLEPEND) == 0))
			ret = RDC_OR_BITMAP(&bd);
	}
	/*
	 * Write the merged bitmap.
	 */
	if ((ret == 0) && bd.endoblk && (krdc->bitmap_write > 0)) {
#ifdef DEBUG
		cmn_err(CE_NOTE, "!r_net_bdata6: Written bitmap for %s:%s",
		    urdc->secondary.intf, urdc->secondary.file);
#endif
		ret = rdc_write_bitmap(krdc);
	}
	kmem_free(bd.data.data_val, BMAP_BLKSIZEV7);
out:
	(void) svc_sendreply(xprt, xdr_int, (char *)&ret);
}

/*
 * r_net_getsize (v5)
 */
static void
r_net_getsize(SVCXPRT *xprt)
{
	int e, ret = -1, index;
	rdc_k_info_t *krdc;

	e = SVC_GETARGS(xprt, xdr_int, (char *)&index);
	if (e) {
		krdc = &rdc_k_info[index];
		if (IS_VALID_INDEX(index) && ((krdc->type_flag &
		    RDC_DISABLEPEND) == 0))
			ret = mirror_getsize(index);
	}
	(void) svc_sendreply(xprt, xdr_int, (char *)&ret);
}

/*
 * r_net_getsize (v6)
 */
static void
r_net_getsize6(SVCXPRT *xprt)
{
	int e, index;
	rdc_k_info_t *krdc;
	uint64_t ret;

	/*
	 * small change in semantics here, as we can't return
	 * -1 over the wire anymore.
	 */
	ret = 0;

	e = SVC_GETARGS(xprt, xdr_int, (char *)&index);
	if (e) {
		krdc = &rdc_k_info[index];
		if (IS_VALID_INDEX(index) && ((krdc->type_flag &
		    RDC_DISABLEPEND) == 0))
			ret = mirror_getsize(index);
	}
	(void) svc_sendreply(xprt, xdr_u_longlong_t, (char *)&ret);
}


/*
 * r_net_state4
 */
static void
r_net_state4(SVCXPRT *xprt)
{
	rdc_u_info_t *urdc;
	rdc_k_info_t *krdc;
	struct set_state4 state;
	rdc_set_t rdc_set;
	int e, index = -1;
	int options;
	int log = 0;
	int done = 0;
	int slave = 0;
	int rev_sync = 0;

	e = SVC_GETARGS(xprt, xdr_set_state4, (char *)&state);
	if (e) {
		init_rdc_netbuf(&(rdc_set.primary.addr));
		init_rdc_netbuf(&(rdc_set.secondary.addr));
		bcopy(state.netaddr, rdc_set.primary.addr.buf,
		    state.netaddrlen);
		bcopy(state.rnetaddr, rdc_set.secondary.addr.buf,
		    state.rnetaddrlen);
		rdc_set.primary.addr.len = state.netaddrlen;
		rdc_set.secondary.addr.len = state.rnetaddrlen;
		(void) strncpy(rdc_set.primary.file, state.pfile,
		    RDC_MAXNAMLEN);
		(void) strncpy(rdc_set.secondary.file, state.sfile,
		    RDC_MAXNAMLEN);
		options = state.flag;
		index = rdc_lookup_byaddr(&rdc_set);

		krdc = &rdc_k_info[index];

		if (index < 0 || (krdc->type_flag & RDC_DISABLEPEND)) {
#ifdef DEBUG
			cmn_err(CE_WARN,
			    "!r_net_state: no index or disable pending");
#endif
			(void) svc_sendreply(xprt, xdr_int, (char *)&index);
			return;
		}

		urdc = &rdc_u_info[index];

		if (!IS_ENABLED(urdc)) {
			index = -1;
#ifdef DEBUG
			cmn_err(CE_WARN, "!r_net_state: set not enabled ");
#endif
			(void) svc_sendreply(xprt, xdr_int, (char *)&index);
			return;
		}

		if (krdc->lsrv == NULL) {
			cmn_err(CE_NOTE, "!r_net_state: no valid svp\n");
			index = -1;
			(void) svc_sendreply(xprt, xdr_int, (char *)&index);
			return;
		}
		if (!krdc || !krdc->group) {
#ifdef DEBUG
			cmn_err(CE_NOTE,
			    "!r_net_state: no valid krdc %p\n", (void*)krdc);
#endif
			index = -1;
			(void) svc_sendreply(xprt, xdr_int, (char *)&index);
			return;
		}

		mutex_enter(&rdc_conf_lock);
		if (krdc->type_flag & RDC_DISABLEPEND) {
			mutex_exit(&rdc_conf_lock);
			index = -1;
#ifdef DEBUG
			cmn_err(CE_WARN, "!r_net_state: disable pending");
#endif
			(void) svc_sendreply(xprt, xdr_int, (char *)&index);
			return;
		}
		set_busy(krdc);
		mutex_exit(&rdc_conf_lock);

		rdc_group_enter(krdc);

		if (rdc_get_vflags(urdc) & RDC_PRIMARY)
			krdc->intf = rdc_add_to_if(krdc->lsrv,
			    &(urdc->primary.addr), &(urdc->secondary.addr), 1);
		else
			krdc->intf = rdc_add_to_if(krdc->lsrv,
			    &(urdc->secondary.addr), &(urdc->primary.addr), 0);

		if (options & CCIO_SLAVE) {
			/*
			 * mark that the bitmap needs clearing.
			 */
			rdc_many_enter(krdc);
			rdc_set_flags(urdc, RDC_CLR_AFTERSYNC);
			rdc_many_exit(krdc);

			/* Starting forward sync */
			if (urdc->volume_size == 0)
				rdc_get_details(krdc);
			if (urdc->volume_size == 0) {
				index = -1;
				goto out;
			}
			if (krdc->dcio_bitmap == NULL) {
				if (rdc_resume_bitmap(krdc) < 0) {
					index = -1;
					goto out;
				}
			}
			if (rdc_allow_sec_sync(urdc, CCIO_SLAVE) < 0) {
				index = -1;
				goto out;
			}
			rdc_dump_dsets(index);
			slave = 1;
		} else if (options & CCIO_RSYNC) {
			/*
			 * mark that the bitmap needs clearing.
			 */
			rdc_many_enter(krdc);
			rdc_set_flags(urdc, RDC_CLR_AFTERSYNC);
			rdc_many_exit(krdc);

			/* Starting reverse sync */
			if (rdc_get_vflags(urdc) & (RDC_SYNC_NEEDED |
			    RDC_VOL_FAILED | RDC_BMP_FAILED)) {
				index = -1;
				goto out;
			}
			if (rdc_allow_sec_sync(urdc, CCIO_RSYNC) < 0) {
				index = -1;
				goto out;
			}
			rdc_dump_dsets(index);
			rev_sync = 1;
		} else if (options & CCIO_DONE) {
			/* Sync completed OK */
			if (rdc_get_vflags(urdc) & RDC_SYNC_NEEDED)
				done = 1;	/* forward sync complete */
			rdc_many_enter(krdc);
			rdc_clr_flags(urdc, RDC_SYNCING | RDC_SYNC_NEEDED);
			rdc_clr_mflags(urdc, RDC_SLAVE | RDC_RSYNC_NEEDED);
			rdc_many_exit(krdc);
			rdc_write_state(urdc);
			if (rdc_get_vflags(urdc) & RDC_CLR_AFTERSYNC) {
				RDC_ZERO_BITMAP(krdc);
				rdc_many_enter(krdc);
				rdc_clr_flags(urdc, RDC_CLR_AFTERSYNC);
				rdc_many_exit(krdc);
			}
		} else if (options & CCIO_ENABLELOG) {
			/* Sync aborted or logging started */
			if (!(rdc_get_vflags(urdc) & RDC_PRIMARY)) {
				rdc_clr_flags(urdc, RDC_SYNCING);
				rdc_many_enter(krdc);
				rdc_clr_mflags(urdc, RDC_SLAVE);
				rdc_many_exit(krdc);
			}
			log = 1;
		}
out:
		rdc_group_exit(krdc);
		free_rdc_netbuf(&(rdc_set.primary.addr));
		free_rdc_netbuf(&(rdc_set.secondary.addr));

		if (slave) {
			if (_rdc_sync_event_notify(RDC_SYNC_START,
			    urdc->secondary.file, urdc->group_name) >= 0) {
				rdc_group_enter(krdc);
				rdc_clr_flags(urdc, RDC_LOGGING);
				rdc_many_enter(krdc);
				rdc_clr_flags(urdc, RDC_VOL_FAILED);
				rdc_set_flags(urdc,
				    RDC_SYNCING | RDC_SYNC_NEEDED);
				rdc_set_mflags(urdc, RDC_SLAVE);
				rdc_many_exit(krdc);
				rdc_write_state(urdc);
				rdc_group_exit(krdc);
			} else {
				index = -1;
			}
		} else if (rev_sync) {
			/* Check to see if volume is mounted */
			if (_rdc_sync_event_notify(RDC_RSYNC_START,
			    urdc->secondary.file, urdc->group_name) >= 0) {
				rdc_group_enter(krdc);
				rdc_clr_flags(urdc, RDC_LOGGING);
				rdc_set_flags(urdc, RDC_SYNCING);
				rdc_write_state(urdc);
				rdc_group_exit(krdc);
			} else {
				index = -1;
			}
		} else if (done) {

			/*
			 * special case...
			 * if this set is in a group, then sndrsyncd will
			 * make sure that all sets in the group are REP
			 * before updating the config to "update", telling
			 * sndrsyncd that it is ok to take anther snapshot
			 * on a following sync. The important part about
			 * the whole thing is that syncd needs kernel stats.
			 * however, this thread must set the set busy to
			 * avoid disables. since this is the only
			 * sync_event_notify() that will cause a status
			 * call back into the kernel, and we will not be
			 * accessing the group structure, we have to wakeup now
			 */

			mutex_enter(&rdc_conf_lock);
			wakeup_busy(krdc);
			mutex_exit(&rdc_conf_lock);

			(void) _rdc_sync_event_notify(RDC_SYNC_DONE,
			    urdc->secondary.file, urdc->group_name);
		}
	}

	if (!done) {
		mutex_enter(&rdc_conf_lock);
		wakeup_busy(krdc);
		mutex_exit(&rdc_conf_lock);
	}

	(void) svc_sendreply(xprt, xdr_int, (char *)&index);
	if (log) {
		rdc_group_enter(krdc);
		rdc_group_log(krdc, RDC_NOFLUSH | RDC_OTHERREMOTE,
		    "Sync aborted or logging started");
		rdc_group_exit(krdc);
	}
}


/*
 * r_net_state
 */
static void
r_net_state(SVCXPRT *xprt)
{
	rdc_u_info_t *urdc;
	rdc_k_info_t *krdc;
	struct set_state state;
	rdc_set_t rdc_set;
	int e, index = -1;
	int options;
	int log = 0;
	int done = 0;
	int slave = 0;
	int rev_sync = 0;
	unsigned short *sp;

	bzero(&state, sizeof (struct set_state));
	e = SVC_GETARGS(xprt, xdr_set_state, (char *)&state);
	if (e) {
		init_rdc_netbuf(&(rdc_set.primary.addr));
		init_rdc_netbuf(&(rdc_set.secondary.addr));
		sp = (unsigned short *)(state.netaddr.buf);
		*sp = ntohs(*sp);
		bcopy(state.netaddr.buf, rdc_set.primary.addr.buf,
		    state.netaddrlen);
		sp = (unsigned short *)(state.rnetaddr.buf);
		*sp = ntohs(*sp);
		bcopy(state.rnetaddr.buf, rdc_set.secondary.addr.buf,
		    state.rnetaddrlen);
		rdc_set.primary.addr.len = state.netaddrlen;
		rdc_set.secondary.addr.len = state.rnetaddrlen;
		(void) strncpy(rdc_set.primary.file, state.pfile,
		    RDC_MAXNAMLEN);
		(void) strncpy(rdc_set.secondary.file, state.sfile,
		    RDC_MAXNAMLEN);
		options = state.flag;
		index = rdc_lookup_byaddr(&rdc_set);

		krdc = &rdc_k_info[index];

		if (index < 0 || (krdc->type_flag & RDC_DISABLEPEND)) {
#ifdef DEBUG
			cmn_err(CE_WARN,
			    "!r_net_state: no index or disable pending");
#endif
			(void) svc_sendreply(xprt, xdr_int, (char *)&index);
			return;
		}

		urdc = &rdc_u_info[index];

		if (!IS_ENABLED(urdc)) {
			index = -1;
#ifdef DEBUG
			cmn_err(CE_WARN, "!r_net_state: set not enabled ");
#endif
			(void) svc_sendreply(xprt, xdr_int, (char *)&index);
			return;
		}

		if (krdc->lsrv == NULL) {
			cmn_err(CE_NOTE, "!r_net_state: no valid svp\n");
			index = -1;
			(void) svc_sendreply(xprt, xdr_int, (char *)&index);
			return;
		}
		if (!krdc || !krdc->group) {
#ifdef DEBUG
			cmn_err(CE_NOTE,
			    "!r_net_state: no valid krdc %p\n", (void*)krdc);
#endif
			index = -1;
			(void) svc_sendreply(xprt, xdr_int, (char *)&index);
			return;
		}

		mutex_enter(&rdc_conf_lock);
		if (krdc->type_flag & RDC_DISABLEPEND) {
			mutex_exit(&rdc_conf_lock);
			index = -1;
#ifdef DEBUG
			cmn_err(CE_WARN, "!r_net_state: disable pending");
#endif
			(void) svc_sendreply(xprt, xdr_int, (char *)&index);
			return;
		}
		set_busy(krdc);
		mutex_exit(&rdc_conf_lock);

		rdc_group_enter(krdc);

		if (rdc_get_vflags(urdc) & RDC_PRIMARY)
			krdc->intf = rdc_add_to_if(krdc->lsrv,
			    &(urdc->primary.addr), &(urdc->secondary.addr), 1);
		else
			krdc->intf = rdc_add_to_if(krdc->lsrv,
			    &(urdc->secondary.addr), &(urdc->primary.addr), 0);

		if (options & CCIO_SLAVE) {
			/*
			 * mark that the bitmap needs clearing.
			 */
			rdc_many_enter(krdc);
			rdc_set_flags(urdc, RDC_CLR_AFTERSYNC);
			rdc_many_exit(krdc);

			/* Starting forward sync */
			if (urdc->volume_size == 0)
				rdc_get_details(krdc);
			if (urdc->volume_size == 0) {
				index = -1;
				goto out;
			}
			if (krdc->dcio_bitmap == NULL) {
				if (rdc_resume_bitmap(krdc) < 0) {
					index = -1;
					goto out;
				}
			}
			if (rdc_allow_sec_sync(urdc, CCIO_SLAVE) < 0) {
				index = -1;
				goto out;
			}
			rdc_dump_dsets(index);
			slave = 1;
		} else if (options & CCIO_RSYNC) {
			/*
			 * mark that the bitmap needs clearing.
			 */
			rdc_many_enter(krdc);
			rdc_set_flags(urdc, RDC_CLR_AFTERSYNC);
			rdc_many_exit(krdc);

			/* Starting reverse sync */
			if (rdc_get_vflags(urdc) & (RDC_SYNC_NEEDED |
			    RDC_VOL_FAILED | RDC_BMP_FAILED)) {
				index = -1;
				goto out;
			}
			if (rdc_allow_sec_sync(urdc, CCIO_RSYNC) < 0) {
				index = -1;
				goto out;
			}
			rdc_dump_dsets(index);
			rev_sync = 1;
		} else if (options & CCIO_DONE) {
			/* Sync completed OK */
			if (rdc_get_vflags(urdc) & RDC_SYNC_NEEDED)
				done = 1;	/* forward sync complete */
			rdc_many_enter(krdc);
			rdc_clr_flags(urdc, RDC_SYNCING | RDC_SYNC_NEEDED);
			rdc_clr_mflags(urdc, RDC_SLAVE | RDC_RSYNC_NEEDED);
			rdc_many_exit(krdc);
			rdc_write_state(urdc);
			if (rdc_get_vflags(urdc) & RDC_CLR_AFTERSYNC) {
				RDC_ZERO_BITMAP(krdc);
				rdc_many_enter(krdc);
				rdc_clr_flags(urdc, RDC_CLR_AFTERSYNC);
				rdc_many_exit(krdc);
			}
		} else if (options & CCIO_ENABLELOG) {
			/* Sync aborted or logging started */
			if (!(rdc_get_vflags(urdc) & RDC_PRIMARY)) {
				rdc_clr_flags(urdc, RDC_SYNCING);
				rdc_many_enter(krdc);
				rdc_clr_mflags(urdc, RDC_SLAVE);
				rdc_many_exit(krdc);
			}
			log = 1;
		}
out:
		rdc_group_exit(krdc);
		free_rdc_netbuf(&(rdc_set.primary.addr));
		free_rdc_netbuf(&(rdc_set.secondary.addr));

		if (slave) {
			if (_rdc_sync_event_notify(RDC_SYNC_START,
			    urdc->secondary.file, urdc->group_name) >= 0) {
				rdc_group_enter(krdc);
				rdc_clr_flags(urdc, RDC_LOGGING);
				rdc_many_enter(krdc);
				rdc_clr_flags(urdc, RDC_VOL_FAILED);
				rdc_set_flags(urdc,
				    RDC_SYNCING | RDC_SYNC_NEEDED);
				rdc_set_mflags(urdc, RDC_SLAVE);
				rdc_many_exit(krdc);
				rdc_write_state(urdc);
				rdc_group_exit(krdc);
			} else {
				index = -1;
			}
		} else if (rev_sync) {
			/* Check to see if volume is mounted */
			if (_rdc_sync_event_notify(RDC_RSYNC_START,
			    urdc->secondary.file, urdc->group_name) >= 0) {
				rdc_group_enter(krdc);
				rdc_clr_flags(urdc, RDC_LOGGING);
				rdc_set_flags(urdc, RDC_SYNCING);
				rdc_write_state(urdc);
				rdc_group_exit(krdc);
			} else {
				index = -1;
			}
		} else if (done) {

			/*
			 * special case...
			 * if this set is in a group, then sndrsyncd will
			 * make sure that all sets in the group are REP
			 * before updating the config to "update", telling
			 * sndrsyncd that it is ok to take anther snapshot
			 * on a following sync. The important part about
			 * the whole thing is that syncd needs kernel stats.
			 * however, this thread must set the set busy to
			 * avoid disables. since this is the only
			 * sync_event_notify() that will cause a status
			 * call back into the kernel, and we will not be
			 * accessing the group structure, we have to wakeup now
			 */

			mutex_enter(&rdc_conf_lock);
			wakeup_busy(krdc);
			mutex_exit(&rdc_conf_lock);

			(void) _rdc_sync_event_notify(RDC_SYNC_DONE,
			    urdc->secondary.file, urdc->group_name);
		}
	}

	if (!done) {
		mutex_enter(&rdc_conf_lock);
		wakeup_busy(krdc);
		mutex_exit(&rdc_conf_lock);
	}

	(void) svc_sendreply(xprt, xdr_int, (char *)&index);
	if (log) {
		rdc_group_enter(krdc);
		rdc_group_log(krdc, RDC_NOFLUSH | RDC_OTHERREMOTE,
		    "Sync aborted or logging started");
		rdc_group_exit(krdc);
	}
	free_rdc_netbuf(&(state.netaddr));
	free_rdc_netbuf(&(state.rnetaddr));
}

/*
 * r_net_getstate4
 * Return our state to client
 */
static void
r_net_getstate4(SVCXPRT *xprt, struct svc_req *req)
{
	int e, ret = -1, index = -1;
	struct set_state4 state;
	rdc_u_info_t *urdc;
	rdc_set_t rdc_set;

	bzero(&state, sizeof (struct set_state));
	e = SVC_GETARGS(xprt, xdr_set_state4, (char *)&state);
	if (e) {
		init_rdc_netbuf(&(rdc_set.primary.addr));
		init_rdc_netbuf(&(rdc_set.secondary.addr));
		bcopy(state.netaddr, rdc_set.primary.addr.buf,
		    state.netaddrlen);
		bcopy(state.rnetaddr, rdc_set.secondary.addr.buf,
		    state.rnetaddrlen);
		rdc_set.primary.addr.len = state.netaddrlen;
		rdc_set.secondary.addr.len = state.rnetaddrlen;
		(void) strncpy(rdc_set.primary.file, state.pfile,
		    RDC_MAXNAMLEN);
		(void) strncpy(rdc_set.secondary.file, state.sfile,
		    RDC_MAXNAMLEN);
		index = rdc_lookup_byaddr(&rdc_set);
		if (index >= 0) {
			urdc = &rdc_u_info[index];

			ret = 0;
			if (rdc_get_vflags(urdc) & RDC_SYNCING)
				ret |= 4;
			if (rdc_get_vflags(urdc) & RDC_SLAVE)
				ret |= 2;
			if (rdc_get_vflags(urdc) & RDC_LOGGING)
				ret |= 1;
			rdc_set_if_vers(urdc, req->rq_vers);
		}
		free_rdc_netbuf(&(rdc_set.primary.addr));
		free_rdc_netbuf(&(rdc_set.secondary.addr));
	}
	(void) svc_sendreply(xprt, xdr_int, (char *)&ret);
}

/*
 * r_net_getstate7
 * Return our state to client
 */
static void
r_net_getstate7(SVCXPRT *xprt, struct svc_req *req)
{
	int e, ret = -1, index = -1;
	struct set_state state;
	char pstr[RDC_MAXNAMLEN];
	char sstr[RDC_MAXNAMLEN];
	rdc_u_info_t *urdc;
	rdc_set_t rdc_set;
	unsigned short *sp;

	bzero(&state, sizeof (struct set_state));
	state.pfile = pstr;
	state.sfile = sstr;

	e = SVC_GETARGS(xprt, xdr_set_state, (char *)&state);
	if (e) {
		init_rdc_netbuf(&(rdc_set.primary.addr));
		init_rdc_netbuf(&(rdc_set.secondary.addr));
		sp = (unsigned short *)(state.netaddr.buf);
		*sp = ntohs(*sp);
		bcopy(state.netaddr.buf, rdc_set.primary.addr.buf,
		    state.netaddrlen);
		sp = (unsigned short *)(state.rnetaddr.buf);
		*sp = ntohs(*sp);
		bcopy(state.rnetaddr.buf, rdc_set.secondary.addr.buf,
		    state.rnetaddrlen);
		rdc_set.primary.addr.len = state.netaddrlen;
		rdc_set.secondary.addr.len = state.rnetaddrlen;
		/*
		 * strncpy(rdc_set.primary.file, state.pfile, RDC_MAXNAMLEN);
		 * strncpy(rdc_set.secondary.file, state.sfile, RDC_MAXNAMLEN);
		 */
		bcopy(state.pfile, rdc_set.primary.file, RDC_MAXNAMLEN);
		bcopy(state.sfile, rdc_set.secondary.file, RDC_MAXNAMLEN);
		index = rdc_lookup_byaddr(&rdc_set);
		if (index >= 0) {
			urdc = &rdc_u_info[index];

			ret = 0;
			if (rdc_get_vflags(urdc) & RDC_SYNCING)
				ret |= 4;
			if (rdc_get_vflags(urdc) & RDC_SLAVE)
				ret |= 2;
			if (rdc_get_vflags(urdc) & RDC_LOGGING)
				ret |= 1;
			rdc_set_if_vers(urdc, req->rq_vers);
		}
		free_rdc_netbuf(&(rdc_set.primary.addr));
		free_rdc_netbuf(&(rdc_set.secondary.addr));
	}
	(void) svc_sendreply(xprt, xdr_int, (char *)&ret);
}

/*
 * copy from/to a dset/vector combination to a network xdr buffer.
 */
static int
rdc_dsetcopy(rdc_net_dataset_t *dset, nsc_vec_t *invec, nsc_off_t fba_pos,
    nsc_size_t fba_len, char *bdata, int blen, int dir)
{
	nsc_vec_t *vec;
	uchar_t *sv_addr;
	uchar_t *data;
	int sv_len;
	nsc_off_t fpos;
	int len;
	int n;

	if (!bdata || !dset || !invec) {
#ifdef DEBUG
		cmn_err(CE_NOTE,
		    "!rdc: dsetcopy: parameters failed bdata %p, dset %p "
		    "invec %p", (void *)bdata, (void *)dset, (void *)invec);
#endif
		return (FALSE);
	}

	if (fba_len > MAX_RDC_FBAS ||
	    (dir != COPY_IN && dir != COPY_OUT)) {
#ifdef DEBUG
		cmn_err(CE_NOTE,
		    "!rdc: dsetcopy: params failed fba_len %" NSC_SZFMT
		    " fba_pos %" NSC_SZFMT ", dir %d", fba_len, fba_pos, dir);
#endif
		return (FALSE);
	}

	data = (uchar_t *)bdata;	/* pointer to data in rpc */
	len = FBA_SIZE(fba_len);	/* length of this transfer in bytes */
	fpos = fba_pos;			/* start fba offset within buffer */

	if (!len) {
#ifdef DEBUG
		cmn_err(CE_NOTE, "!rdc: dsetcopy: len = 0");
#endif
		return (FALSE);
	}

	if (len != blen) {
#ifdef DEBUG
		cmn_err(CE_NOTE, "!rdc:dsetcopy: len %d != blen %d", len, blen);
#endif
		if (len > blen)
			len = blen;
	}

	if (!RDC_DSET_LIMITS(dset, fba_pos, fba_len)) {
		/* should never happen */
#ifdef DEBUG
		cmn_err(CE_NOTE,
		    "!rdc: dsetcopy: handle limits pos %" NSC_SZFMT " (%"
		    NSC_SZFMT ") len %" NSC_SZFMT " (%" NSC_SZFMT ")",
		    fba_pos, dset->pos, fba_len, dset->fbalen);
#endif
		return (FALSE);	/* Don't overrun handle */
	}

	vec = invec;
	fpos -= dset->pos;

	/* find starting position in vector */

	for (; fpos >= FBA_NUM(vec->sv_len); vec++)
		fpos -= FBA_NUM(vec->sv_len);

	/*
	 * Copy data
	 */

	sv_addr = vec->sv_addr + FBA_SIZE(fpos);
	sv_len = vec->sv_len - FBA_SIZE(fpos);

	while (len) {
		if (!sv_addr)	/* end of vec - how did this happen? */
			break;

		n = min(sv_len, len);

		if (dir == COPY_OUT)
			bcopy(data, sv_addr, (size_t)n);
		else
			bcopy(sv_addr, data, (size_t)n);

		sv_len -= n;
		len -= n;

		sv_addr += n;
		data += n;

		if (sv_len <= 0) {
			/* goto next vector */
			vec++;
			sv_addr = vec->sv_addr;
			sv_len = vec->sv_len;
		}
	}

	return (TRUE);
}


/*
 * rdc_start_server
 * Starts the kRPC server for rdc. Uses tli file descriptor passed down
 * from user level rdc server.
 *
 * Returns: 0 or errno (NOT unistat!).
 */
int
rdc_start_server(struct rdc_svc_args *args, int mode)
{
	file_t *fp;
	int ret;
	struct cred *cred;
	STRUCT_HANDLE(rdc_svc_args, rs);

	STRUCT_SET_HANDLE(rs, mode, args);
	cred = ddi_get_cred();
	if (drv_priv(cred) != 0)
		return (EPERM);
	fp = getf(STRUCT_FGET(rs, fd));
	if (fp == NULL) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!rdc_start_server fd %d, fp %p", args->fd,
		    (void *) fp);
#endif
		return (EBADF);
	}

	ret = rdcsrv_load(fp, rdc_srvtab, args, mode);

	releasef(STRUCT_FGET(rs, fd));
	return (ret);
}

/*
 * Allocate a new sleepq element.
 */

static rdc_sleepq_t *
rdc_newsleepq()
{
	rdc_sleepq_t	*sq;

	sq = kmem_alloc(sizeof (rdc_sleepq_t), KM_SLEEP);
	sq->next = NULL;
#ifdef DEBUG
	mutex_enter(&rdc_cntlock);
	rdc_sleepcnt++;
	mutex_exit(&rdc_cntlock);
#endif
	return (sq);
}

/*
 * free memory/resources used by a sleepq element.
 */
static void
rdc_delsleepq(rdc_sleepq_t *sq)
{
	rdc_net_dataset_t *dset;

	if (sq->idx != -1) {
		dset = rdc_net_get_set(sq->sindex, sq->idx);
		if (dset) {
			rdc_net_del_set(sq->sindex, dset);
		}
	}
	kmem_free(sq, sizeof (rdc_sleepq_t));
#ifdef DEBUG
	mutex_enter(&rdc_cntlock);
	rdc_sleepcnt--;
	mutex_exit(&rdc_cntlock);
#endif
}


/*
 * skip down the sleep q and insert the sleep request
 * in ascending order. Return 0 on success, 1 on failure.
 */
static int
rdc_sleepq(rdc_group_t *group, rdc_sleepq_t *sq)
{
	rdc_sleepq_t *findsq;


	ASSERT(MUTEX_HELD(&group->ra_queue.net_qlock));
	if (group->sleepq == NULL) {
		group->sleepq = sq;
	} else {
		if (sq->seq == group->sleepq->seq) {
			cmn_err(CE_WARN, "!rdc_sleepq: Attempt to "
			    "add duplicate request to queue %d", sq->seq);
			return (1);
		}
		if (RDC_INFRONT(sq->seq, group->sleepq->seq)) {
			sq->next = group->sleepq;
			group->sleepq = sq;
		} else {
			findsq = group->sleepq;

			while (findsq->next) {
				if (sq->seq == findsq->next->seq) {
					cmn_err(CE_WARN, "!rdc_sleepq: "
					    "Attempt to add duplicate "
					    "request to queue %d", sq->seq);
					return (1);
				}
				if (RDC_INFRONT(sq->seq, findsq->next->seq)) {
					sq->next = findsq->next;
					findsq->next = sq;
					break;
				}
				findsq = findsq->next;
			}
			if (findsq->next == NULL)
				findsq->next = sq;
		}
	}
	return (0);
}

/*
 * run down the sleep q and discard all the sleepq elements.
 */
void
rdc_sleepqdiscard(rdc_group_t *group)
{
	rdc_sleepq_t *sq;
	rdc_k_info_t *krdc;

	ASSERT(MUTEX_HELD(&group->ra_queue.net_qlock));
	sq = group->sleepq;

	while (sq) {
		rdc_sleepq_t *dsq;

		dsq = sq;
		krdc = &rdc_k_info[dsq->sindex];
		if (krdc->io_kstats) {
			mutex_enter(krdc->io_kstats->ks_lock);
			kstat_waitq_exit(KSTAT_IO_PTR(krdc->io_kstats));
			mutex_exit(krdc->io_kstats->ks_lock);
		}
		sq = sq->next;
		rdc_delsleepq(dsq);
	}
	group->sleepq = NULL;
}

/*
 * split any write requests down to maxfba sized chunks.
 */
/*ARGSUSED*/
static int
rdc_writemaxfba(rdc_k_info_t *krdc, rdc_u_info_t *urdc,
    rdc_net_dataset_t *dset, uint_t seq, int nocache)
{
	int len;
	int ret;
	nsc_vec_t vector[2];
	nsc_buf_t *handle;
	int reserved;
	int rtype;
	nsc_size_t mfba;
	nsc_size_t wsize;
	nsc_off_t pos;
	int eintr_count;
	unsigned char *daddr;
	int kstat_len;

	kstat_len = len = dset->fbalen;
	ret = 0;
	handle = NULL;
	reserved = 0;
	rtype = RDC_RAW;

	ASSERT(dset->nitems == 1);

	eintr_count = 0;
	do {
		ret = _rdc_rsrv_devs(krdc, rtype, RDC_INTERNAL);
		if (ret == EINTR) {
			++eintr_count;
			delay(2);
		}
	} while ((ret == EINTR) && (eintr_count < MAX_EINTR_COUNT));
	if (ret != 0) {
#ifdef DEBUG
		cmn_err(CE_NOTE, "!rdc_writemaxfba: reserve devs "
		    "failed %d", ret);
#endif
		goto out;

	}
	reserved = 1;
	/*
	 * Perhaps we should cache mfba.
	 */
	ret = nsc_maxfbas(RDC_U_FD(krdc), 0, &mfba);
	if (ret != 0) {
#ifdef DEBUG
		cmn_err(CE_NOTE, "!rdc_writemaxfba: msc_maxfbas failed %d",
		    ret);
#endif
		goto out;
	}

	ASSERT(urdc->volume_size != 0);
	if (dset->pos + len > urdc->volume_size) {
		/* should never happen */
		/*
		 * also need to trim down the vector
		 * sizes.
		 */
		kstat_len = len = urdc->volume_size - dset->pos;
		dset->head->len -= FBA_SIZE(len);
		ASSERT(dset->head->len > 0);
	}
	daddr = dset->head->dptr;
	pos = dset->pos;
	vector[1].sv_addr = NULL;
	vector[1].sv_len = 0;

	while (len > 0) {
		wsize = min((nsc_size_t)len, mfba);
		vector[0].sv_addr = daddr;
		vector[0].sv_len = FBA_SIZE(wsize);

		if (handle) {
			(void) nsc_free_buf(handle);
			handle = NULL;
		}
		ret = nsc_alloc_buf(RDC_U_FD(krdc), pos, wsize,
		    NSC_WRBUF|NSC_NODATA|nocache, &handle);
		if (ret != 0) {
#ifdef DEBUG
			cmn_err(CE_NOTE, "!rdc_writemaxfba: "
			    "nsc_alloc (d1) buf failed %d at "
			    "pos %" NSC_SZFMT " len %" NSC_SZFMT,
			    ret, pos, wsize);
#endif
			goto out;
		}
		handle->sb_vec = &vector[0];
		ret = rdc_combywrite(krdc, handle);
		if (ret != 0) {
#ifdef DEBUG
			cmn_err(CE_NOTE, "!rdc_writemaxfba: "
			    "write failed (d1) %d offset %" NSC_SZFMT " "
			    "length %" NSC_SZFMT, ret, pos, wsize);
#endif
			goto out;
		}
		pos += wsize;
		len -= wsize;
		daddr += FBA_SIZE(wsize);
	}
out:
	if (!RDC_SUCCESS(ret)) {
		if (!(rdc_get_vflags(urdc) & RDC_VOL_FAILED)) {
			ASSERT(!(rdc_get_vflags(urdc) &
			    RDC_PRIMARY));
			rdc_many_enter(krdc);
			rdc_set_flags(urdc, RDC_SYNC_NEEDED);
			rdc_set_flags_log(urdc, RDC_VOL_FAILED,
			    "svc write failed");
			rdc_many_exit(krdc);
			rdc_write_state(urdc);
		}
	} else {
		/* success */
#ifdef	DEBUG
		if (rdc_netwrite6) {
			/*
			 * This string is used in the ZatoIchi MASNDR
			 * tests, if you change this, update the test.
			 */
			cmn_err(CE_NOTE, "!writemaxfba: Write "
			    "sequence %u", seq);
		}
#endif
		if (krdc->io_kstats) {
			KSTAT_IO_PTR(krdc->io_kstats)->writes++;
			KSTAT_IO_PTR(krdc->io_kstats)->nwritten +=
			    FBA_SIZE(kstat_len);
		}
	}
	if (handle)
		(void) nsc_free_buf(handle);
	if (reserved)
		_rdc_rlse_devs(krdc, rtype);
	return (ret);
}

static int
rdc_combywrite(rdc_k_info_t *krdc, nsc_buf_t *handle)
{
	int rsync;
	int ret;
	int multiret;

	rsync = -1;
	ret = 0;
	/* Handle multihop I/O even on error */
	if (IS_MULTI(krdc)) {
		rdc_k_info_t *ktmp;
		rdc_u_info_t *utmp;

		rdc_many_enter(krdc);
		/*
		 * Find a target primary that is enabled,
		 * taking account of the fact that this
		 * could be a multihop secondary
		 * connected to a 1-to-many primary.
		 */
		ktmp = krdc->multi_next;
		if (ktmp == NULL) {
			rdc_many_exit(krdc);
			goto multi_done;
		}
		utmp = &rdc_u_info[ktmp->index];
		do {
			if ((rdc_get_vflags(utmp) & RDC_PRIMARY)
			    /* CSTYLED */
			    && IS_ENABLED(utmp))
				break;

			ktmp = ktmp->many_next;
			utmp = &rdc_u_info[ktmp->index];
		} while (ktmp != krdc->multi_next);

		if (!(rdc_get_vflags(utmp) & RDC_PRIMARY) ||
		    !IS_ENABLED(utmp)) {
			rdc_many_exit(krdc);
			goto multi_done;
		}

		rdc_many_exit(krdc);
		rsync = (rdc_get_mflags(utmp) & RDC_SLAVE);
		if (!rsync) {
			/* normal case - local io first */
			ret = nsc_write(handle, handle->sb_pos, handle->sb_len,
			    0);
		}
		multiret = _rdc_multi_write(handle, handle->sb_pos,
		    handle->sb_len, 0, ktmp);
		if (!RDC_SUCCESS(multiret)) {
#ifdef DEBUG
			cmn_err(CE_NOTE, "!combywrite: "
			    "rdc_multi_write failed "
			    "status %d ret %d",
			    handle->sb_error, multiret);
#endif
			if (!(rdc_get_vflags(utmp) &
			    RDC_VOL_FAILED)) {
				rdc_many_enter(ktmp);
				if (rdc_get_vflags(utmp) &
				    RDC_PRIMARY) {
					rdc_set_mflags(utmp,
					    RDC_RSYNC_NEEDED);
				} else {
					rdc_set_flags(utmp,
					    RDC_SYNC_NEEDED);
				}
				rdc_set_flags(utmp,
				    RDC_VOL_FAILED);
				rdc_many_exit(ktmp);
				rdc_write_state(utmp);
			}
		}
	}

multi_done:
	if (rsync != 0) {
		/*
		 * Either:
		 * reverse sync in progress and so we
		 * need to do the local io after the
		 * (multihop) secondary io.
		 * Or:
		 * no multihop and this is the only io
		 * required.
		 */
		ret = nsc_write(handle, handle->sb_pos, handle->sb_len, 0);

	}
	return (ret);
}
/*
 * set the pos and len values in the piggyback reply.
 */
static void
rdc_setbitind(int *pendcnt, net_pendvec_t *pvec, rdc_net_dataset_t *dset,
    uint_t seq, int pindex, int qpos)
{
	int pc;
	ASSERT(*pendcnt < RDC_MAXPENDQ);

	pc = *pendcnt;
	pvec[pc].seq = seq;
	pvec[pc].apos = dset->pos;
	pvec[pc].qpos = qpos;
	pvec[pc].alen = dset->fbalen;
	pvec[pc].pindex = pindex;
	*pendcnt = pc + 1;
	DTRACE_PROBE1(pvec_reply, int, seq);
}

/*
 * Enters with group->ra_queue.net_qlock held.
 * Tries to construct the return status data for
 * all the pending requests in the sleepq that it can
 * satisfy.
 */
static void
rdc_dopending(rdc_group_t *group, netwriteres *netretp)
{
	int pendcnt;
	net_pendvec_t *pendvec;
	rdc_sleepq_t *sq;
	int ret;
	int pendsz;

	ASSERT(MUTEX_HELD(&group->ra_queue.net_qlock));

	pendcnt = 0;
	pendsz = RDC_MAXPENDQ * sizeof (net_pendvec_t);
	pendvec = kmem_alloc(pendsz, KM_SLEEP);

	/*
	 * now look at the Q of pending tasks, attempt
	 * to write any that have been waiting for
	 * me to complete my write, and piggyback
	 * their results in my reply, by setiing pendcnt
	 * to the number of extra requests sucessfully
	 * processed.
	 */
	while (group->sleepq && group->sleepq->seq == group->seq) {
		rdc_k_info_t		*krdc;
		rdc_u_info_t		*urdc;
		struct rdc_net_dataset	*dset;

		sq = group->sleepq;
		group->sleepq = sq->next;
		mutex_exit(&group->ra_queue.net_qlock);

		krdc = &rdc_k_info[sq->sindex];
		urdc = &rdc_u_info[sq->sindex];
		if (krdc->io_kstats) {
			mutex_enter(krdc->io_kstats->ks_lock);
			kstat_waitq_exit(KSTAT_IO_PTR(krdc->io_kstats));
			mutex_exit(krdc->io_kstats->ks_lock);
		}

		dset = rdc_net_get_set(sq->sindex, sq->idx);
		if (dset == NULL) {
#ifdef	DEBUG
			cmn_err(CE_NOTE, "!pending: %s:%s rdc_net_get_set "
			    "failed", urdc->secondary.intf,
			    urdc->secondary.file);
#endif
			/*
			 * as we failed to get the pointer, there
			 * is no point expecting the cleanup
			 * code in rdc_delsleepq() to get it
			 * either.
			 */
			sq->idx = -1;
			goto cleansq;
		}
		sq->idx = -1;	/* marked as cleaned up */

		ret = rdc_writemaxfba(krdc, urdc, dset, sq->seq, sq->nocache);
		if (RDC_SUCCESS(ret)) {
			rdc_setbitind(&pendcnt, pendvec, dset,
			    sq->seq, sq->pindex, sq->qpos);
		} else {
			cmn_err(CE_WARN, "!dopending: Write of pending "
			    "asynchronous task failed, with "
			    "sequence number %u for SNDR set %s:%s",
			    sq->seq, urdc->secondary.intf,
			    urdc->secondary.file);
		}
		rdc_net_del_set(sq->sindex, dset);
cleansq:
		mutex_enter(&group->ra_queue.net_qlock);
		group->seq = sq->seq + 1;
		if (group->seq < sq->seq)
			group->seq = RDC_NEWSEQ + 1;
		rdc_delsleepq(sq);
	}
	mutex_exit(&group->ra_queue.net_qlock);
	if (pendcnt) {
		int vecsz;
#ifdef DEBUG
		if (rdc_netwrite6) {
			cmn_err(CE_NOTE, "!packing pend, count %d", pendcnt);
		}
#endif
		vecsz = pendcnt * sizeof (net_pendvec_t);
		netretp->vecdata.vecdata_val =
		    kmem_alloc(vecsz, KM_SLEEP);
		netretp->vecdata.vecdata_len = pendcnt;
		bcopy(pendvec, netretp->vecdata.vecdata_val, vecsz);
	}
	kmem_free(pendvec, pendsz);
	mutex_enter(&group->ra_queue.net_qlock);
}

/*
 * Take the dset and allocate and fill in the vector.
 */
static nsc_vec_t *
rdc_dset2vec(rdc_net_dataset_t *dset)
{
	nsc_vec_t *vecret;
	int i;
	rdc_net_dataitem_t *ditem;

	ASSERT(dset->nitems > 0);
	ASSERT(dset->head);
	ASSERT(dset->tail);

	vecret = kmem_alloc((dset->nitems + 1) * sizeof (nsc_vec_t),
	    KM_NOSLEEP);
	if (vecret == NULL) {
		return (NULL);
	}
	RDC_DSMEMUSE((dset->nitems + 1) * sizeof (nsc_vec_t));
	ditem = dset->head;
	for (i = 0; i < dset->nitems; i++) {
		ASSERT(ditem);
		vecret[i].sv_addr = ditem->dptr;
		vecret[i].sv_len = ditem->len;
		ditem = ditem->next;
	}
	/*
	 * Null terminate.
	 */
	vecret[i].sv_addr = NULL;
	vecret[i].sv_len = 0;
	/*
	 * Check the list and count matches.
	 */
	ASSERT(ditem == NULL);
	return (vecret);
}

/*
 * Split the local read into maxfba sized chunks.
 * Returns 0 on an error, or a valid idx on success.
 */
static int
rdc_readmaxfba(int cd, nsc_off_t pos, nsc_size_t fbalen, int nocache)
{
	int idx;
	rdc_k_info_t *krdc;
	rdc_u_info_t *urdc;
	rdc_net_dataset_t *dset;
	rdc_net_dataitem_t *ditem;
	int rtype;
	nsc_buf_t *handle;
	nsc_vec_t veclist[2];
	int ret;
	int reserved;
	nsc_size_t fbaleft;
	nsc_size_t mfba;
	nsc_off_t fba;
	nsc_off_t spos;
	int eintr_count;

	handle = NULL;
	idx = 0; /* error status */
	dset = NULL;
	ditem = NULL;
	reserved = 0;
	ret = 0;
	mfba = 0;

	rtype = RDC_RAW;
	krdc = &rdc_k_info[cd];
	urdc = &rdc_u_info[cd];

	eintr_count = 0;
	do {
		ret = _rdc_rsrv_devs(krdc, rtype, RDC_INTERNAL);
		if (ret == EINTR) {
			++eintr_count;
			delay(2);
		}
	} while ((ret == EINTR) && (eintr_count < MAX_EINTR_COUNT));
	if (ret != 0) {
#ifdef DEBUG
		cmn_err(CE_NOTE, "!readmaxfba: reserve failed on set %s:%s %d",
		    urdc->secondary.intf, urdc->secondary.file,
		    ret);
#endif
		goto out;
	}
	reserved = 1;
	/*
	 * create a dataset that we can hang all the buffers from.
	 */
	dset = rdc_net_add_set(cd);
	if (dset == NULL) {
#ifdef DEBUG
		cmn_err(CE_NOTE, "!readmaxfba: Unable to allocate dset on set "
		    "%s:%s", urdc->secondary.intf, urdc->secondary.file);
#endif
		goto out;
	}
	dset->pos = pos;
	dset->fbalen = fbalen;
	ret = nsc_maxfbas(RDC_U_FD(krdc), 0, &mfba);
	if (ret != 0) {
#ifdef DEBUG
		cmn_err(CE_NOTE, "!readmaxfba: msc_maxfbas failed on set %s:%s "
		    "%d", urdc->secondary.intf,	urdc->secondary.file, ret);
#endif
		goto out;
	}
	spos = pos;
	fbaleft = fbalen;
	veclist[1].sv_addr = NULL;
	veclist[1].sv_len = 0;

	while (fbaleft > 0) {
		fba = min(mfba, fbaleft);
		if (handle) {
			(void) nsc_free_buf(handle);
			handle = NULL;
		}
		ret = nsc_alloc_buf(RDC_U_FD(krdc), spos, fba,
		    nocache|NSC_NODATA, &handle);
		if (ret != 0) {
#ifdef DEBUG
			cmn_err(CE_NOTE, "!readmaxfba: alloc failed on set"
			    "%s:%s %d", urdc->secondary.intf,
			    urdc->secondary.file, ret);
#endif
			goto out;
		}
		ditem = kmem_alloc(sizeof (rdc_net_dataitem_t), KM_NOSLEEP);
		if (ditem == NULL) {
			goto out;
		}
		RDC_DSMEMUSE(sizeof (rdc_net_dataitem_t));
		ditem->len = FBA_SIZE(fba);
		ditem->mlen = ditem->len;
		ditem->dptr = kmem_alloc(ditem->len, KM_SLEEP);
		RDC_DSMEMUSE(ditem->len);
		ditem->next = NULL;
		/*
		 * construct a vector list
		 */
		veclist[0].sv_addr = ditem->dptr;
		veclist[0].sv_len = ditem->len;
		handle->sb_vec = veclist;
		ret = rdc_combyread(krdc, urdc, handle);
		if (ret != 0) {
			goto out;
		}
		/*
		 * place on linked list.
		 */
		dset->nitems++;
		if (dset->head == NULL) {
			dset->head = ditem;
			dset->tail = ditem;
		} else {
			dset->tail->next = ditem;
			dset->tail = ditem;
		}
		/*
		 * now its linked, clear this so its not freed twice.
		 */
		ditem = NULL;
		fbaleft -= fba;
		spos += fba;
	}
	/*
	 * all the reads have worked, store the results.
	 */
	idx = dset->id;
	rdc_net_put_set(cd, dset);
	dset = NULL;
out:
	if (handle)
		(void) nsc_free_buf(handle);
	if (reserved)
		_rdc_rlse_devs(krdc, rtype);
	if (dset)
		rdc_net_del_set(cd, dset);
	if (ditem) {
		kmem_free(ditem->dptr, ditem->mlen);
		RDC_DSMEMUSE(-ditem->mlen);
		kmem_free(ditem, sizeof (*ditem));
		RDC_DSMEMUSE(-sizeof (*ditem));
	}
	return (idx);
}


/*
 * perform both a local read, and if multihop, a remote read.
 * return 0 on success, or errno on failure.
 */
static int
rdc_combyread(rdc_k_info_t *krdc, rdc_u_info_t *urdc, nsc_buf_t *handle)
{
	int ret;
	rdc_k_info_t *ktmp;
	rdc_u_info_t *utmp;

	/*
	 * read it.
	 */
	if (krdc->io_kstats) {
		mutex_enter(krdc->io_kstats->ks_lock);
		kstat_runq_enter(KSTAT_IO_PTR(krdc->io_kstats));
		mutex_exit(krdc->io_kstats->ks_lock);
	}

	ret = nsc_read(handle, handle->sb_pos, handle->sb_len, NSC_READ);

	if (krdc->io_kstats) {
		mutex_enter(krdc->io_kstats->ks_lock);
		kstat_runq_exit(KSTAT_IO_PTR(krdc->io_kstats));
		mutex_exit(krdc->io_kstats->ks_lock);
	}

	if (ret != 0) {
#ifdef DEBUG
		cmn_err(CE_NOTE, "!combyread: read failed on set %s:%s %d",
		    urdc->secondary.intf, urdc->secondary.file, ret);
#endif
		if (!(rdc_get_vflags(urdc) & RDC_VOL_FAILED)) {
			rdc_many_enter(krdc);
			rdc_set_mflags(urdc, RDC_RSYNC_NEEDED);
			rdc_set_flags_log(urdc, RDC_VOL_FAILED,
			    "comby read failed");
			rdc_many_exit(krdc);
			rdc_write_state(urdc);
		}
		goto out;
	}
	if (IS_MULTI(krdc) && (ktmp = krdc->multi_next) &&
	    (utmp = &rdc_u_info[ktmp->index]) &&
	    IS_ENABLED(utmp) &&
	    (rdc_get_mflags(utmp) & RDC_RSYNC_NEEDED)) {
		ret = _rdc_remote_read(ktmp, handle, handle->sb_pos,
		    handle->sb_len, NSC_READ);
		/*
		 * Set NSC_MIXED so
		 * that the cache will throw away this
		 * buffer when we free it since we have
		 * combined data from multiple sources
		 * into a single buffer.
		 * Currently we don't use the cache for
		 * data volumes, so comment this out.
		 * handle->sb_flag |= NSC_MIXED;
		 */
		if (ret != 0) {
#ifdef DEBUG
			cmn_err(CE_NOTE, "!combyread: remote read failed on "
			    "set %s:%s %d", utmp->secondary.intf,
			    utmp->secondary.file, ret);
#endif
			goto out;
		}
	}
	if (krdc->io_kstats) {
		KSTAT_IO_PTR(krdc->io_kstats)->reads++;
		KSTAT_IO_PTR(krdc->io_kstats)->nread +=
		    FBA_SIZE(handle->sb_len);
	}
out:
	return (ret);
}


/*
 * remove and free all the collected dsets for this set.
 */
void
rdc_dump_dsets(int index)
{
	rdc_k_info_t *krdc;
	rdc_net_dataset_t *dset;

	krdc = &rdc_k_info[index];
tloop:
	mutex_enter(&krdc->dc_sleep);
	while ((dset = krdc->net_dataset) != NULL) {
		if (dset->inuse) {
			/*
			 * for the dset to be in use, the
			 * service routine r_net_write6() must
			 * be active with it. It will free
			 * it eventually.
			 */
			mutex_exit(&krdc->dc_sleep);
			delay(5);
			goto tloop;
		}
		/*
		 * free it.
		 */
		rdc_net_free_set(krdc, dset);
	}
	mutex_exit(&krdc->dc_sleep);
}

#ifdef	DEBUG
void
rdc_stallzero(int flag)
{
	static int init = 0;
	static kcondvar_t cv;
	static kmutex_t mu;

	if (init == 0) {
		cv_init(&cv, NULL, CV_DRIVER, NULL);
		mutex_init(&mu, NULL, MUTEX_DRIVER, NULL);
		init = 1;
	}

	mutex_enter(&mu);
	switch (flag) {
	case 0:
		rdc_stall0 = 0;
		cv_signal(&cv);
		break;
	case 1:
		rdc_stall0 = 1;
		break;
	case 2:
		while (rdc_stall0 == 1)
			cv_wait(&cv, &mu);
		break;
	default:
		cmn_err(CE_PANIC, "Bad flag value passed to rdc_stallzero");
		break;
	}
	mutex_exit(&mu);
}
#endif

/*
 * RDC protocol version 5
 */
static rdc_disptab_t rdc_disptab5[] =
{
	/* PROC			Idempotent */
	{ r_net_null,		FALSE },
	{ rdcsrv_noproc,	FALSE },
	{ r_net_getsize,	FALSE },
	{ rdcsrv_noproc,	FALSE },
	{ r_net_write5,		TRUE },
	{ r_net_read,		FALSE },
	{ rdcsrv_noproc,	FALSE },
	{ r_net_state4,		FALSE },
	{ r_net_ping4,		FALSE },
	{ r_net_bmap,		FALSE },
	{ r_net_bdata,		FALSE },
	{ rdcsrv_noproc,	FALSE },
	{ r_net_getstate4,	FALSE }
};

/*
 * RDC protocol version 6
 */
static rdc_disptab_t rdc_disptab6[] =
{
	/* PROC			Idempotent */
	{ r_net_null,		FALSE },
	{ rdcsrv_noproc,	FALSE },
	{ r_net_getsize6,	FALSE },
	{ rdcsrv_noproc,	FALSE },
	{ r_net_write6,		TRUE },
	{ r_net_read6,		FALSE },
	{ rdcsrv_noproc,	FALSE },
	{ r_net_state4,		FALSE },
	{ r_net_ping4,		FALSE },
	{ r_net_bmap6,		FALSE },
	{ r_net_bdata6,		FALSE },
	{ rdcsrv_noproc,	FALSE },
	{ r_net_getstate4,	FALSE }
};

/*
 * RDC protocol version 7
 */
static rdc_disptab_t rdc_disptab7[] =
{
	/* PROC			Idempotent */
	{ r_net_null,		FALSE },
	{ rdcsrv_noproc,	FALSE },
	{ r_net_getsize6,	FALSE },
	{ rdcsrv_noproc,	FALSE },
	{ r_net_write6,		TRUE },
	{ r_net_read6,		FALSE },
	{ rdcsrv_noproc,	FALSE },
	{ r_net_state,		FALSE },
	{ r_net_ping7,		FALSE },
	{ r_net_bmap6,		FALSE },
	{ r_net_bdata6,		FALSE },
	{ rdcsrv_noproc,	FALSE },
	{ r_net_getstate7,	FALSE }
};

static rdcsrv_t rdc_srvtab[] = {
	{ rdc_disptab5, sizeof (rdc_disptab5) / sizeof (*rdc_disptab5) },
	{ rdc_disptab6, sizeof (rdc_disptab6) / sizeof (*rdc_disptab6) },
	{ rdc_disptab7, sizeof (rdc_disptab7) / sizeof (*rdc_disptab7) }
};
