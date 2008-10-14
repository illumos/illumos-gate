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

#include <sys/types.h>
#include <sys/ksynch.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/cred.h>
#include <sys/conf.h>
#include <sys/modctl.h>
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
#else
#include "../contract.h"
#endif

#include <sys/ddi.h>

#include <sys/nsc_thread.h>
#include <sys/nsctl/nsctl.h>

#include <sys/nsctl/nsvers.h>

#include "rdc_io.h"
#include "rdc_stub.h"
#include "rdc_ioctl.h"
#include "rdcsrv.h"

#if defined(_SunOS_5_6) || defined(_SunOS_5_7)
static void rdcsrv_xprtclose(const SVCXPRT *xprt);
#else	/* SunOS 5.8 or later */
/*
 * SunOS 5.8 or later.
 *
 * RDC callout table
 *
 * This table is used by svc_getreq to dispatch a request with a given
 * prog/vers pair to an approriate service provider.
 */

static SVC_CALLOUT rdcsrv_sc[] = {
	{ RDC_PROGRAM, RDC_VERS_MIN, RDC_VERS_MAX, rdcstub_dispatch }
};

static SVC_CALLOUT_TABLE rdcsrv_sct = {
	sizeof (rdcsrv_sc) / sizeof (rdcsrv_sc[0]), FALSE, rdcsrv_sc
};
#endif	/* SunOS 5.8 or later */

static kmutex_t rdcsrv_lock;

static int rdcsrv_dup_error;
static int rdcsrv_registered;
static int rdcsrv_closing;
static int rdcsrv_refcnt;
long rdc_svc_count = 0;
static rdcsrv_t *rdcsrv_disptab;

/*
 * Solaris module setup.
 */

extern struct mod_ops mod_miscops;

static struct modlmisc modlmisc = {
	&mod_miscops,   /* Type of module */
	"nws:Remote Mirror kRPC:" ISS_VERSION_STR
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modlmisc,
	NULL
};


int
_init(void)
{
	int rc;

	mutex_init(&rdcsrv_lock, NULL, MUTEX_DRIVER, NULL);

	if ((rc = mod_install(&modlinkage)) != DDI_SUCCESS)
		mutex_destroy(&rdcsrv_lock);

	return (rc);
}


int
_fini(void)
{
	int rc;

	if ((rc = mod_remove(&modlinkage)) == DDI_SUCCESS)
		mutex_destroy(&rdcsrv_lock);

	return (rc);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*
 * RDC kRPC server stub.
 */

void
rdcsrv_noproc(void)
{
	;
}


static int
rdcsrv_dispdup(struct svc_req *req, SVCXPRT *xprt)
{
	rdc_disptab_t *disp;
	struct dupreq *dr;
	rdcsrv_t *srvp;
	void (*fn)();
	int dupstat;

	srvp = &rdcsrv_disptab[req->rq_vers - RDC_VERS_MIN];
	disp = &srvp->disptab[req->rq_proc];
	fn = disp->dispfn;

	dupstat = SVC_DUP(xprt, req, 0, 0, &dr);

	switch (dupstat) {
	case DUP_ERROR:
		/* svcerr_systemerr does a freeargs */
		svcerr_systemerr(xprt);
		rdcsrv_dup_error++;
		break;

	case DUP_INPROGRESS:
		rdcsrv_dup_error++;
		break;

	case DUP_NEW:
	case DUP_DROP:
		(*fn)(xprt, req);
		SVC_DUPDONE(xprt, dr, 0, 0, DUP_DONE);
		break;

	case DUP_DONE:
		break;
	}

	return (dupstat);
}


/*
 * rdcsrv_dispatch is the dispatcher routine for the RDC RPC protocol
 */
void
rdcsrv_dispatch(struct svc_req *req, SVCXPRT *xprt)
{
	rdc_disptab_t *disp;
	rdcsrv_t *srvp;

	mutex_enter(&rdcsrv_lock);
	rdcsrv_refcnt++;

	if (!rdcsrv_registered || rdcsrv_closing || !rdcsrv_disptab) {
		mutex_exit(&rdcsrv_lock);
		goto outdisp;
	}

	mutex_exit(&rdcsrv_lock);

	if ((req->rq_vers < RDC_VERS_MIN) || (req->rq_vers > RDC_VERS_MAX)) {
		svcerr_noproc(xprt);
		cmn_err(CE_NOTE,
			"rdcsrv_dispatch: unknown version %d",
			req->rq_vers);
		/* svcerr_noproc does a freeargs on xprt */
		goto done;
	}

	srvp = &rdcsrv_disptab[req->rq_vers - RDC_VERS_MIN];
	disp = &srvp->disptab[req->rq_proc];

	if (req->rq_proc >= srvp->nprocs ||
	    disp->dispfn == rdcsrv_noproc) {
		svcerr_noproc(xprt);
		cmn_err(CE_NOTE,
			"rdcsrv_dispatch: bad proc number %d",
			req->rq_proc);
		/* svcerr_noproc does a freeargs on xprt */
		goto done;
	} else if (disp->clone) {
		switch (rdcsrv_dispdup(req, xprt)) {
		case DUP_ERROR:
			goto done;
			/* NOTREACHED */
		case DUP_INPROGRESS:
			goto outdisp;
			/* NOTREACHED */
		default:
			break;
		}
	} else {
		(*disp->dispfn)(xprt, req);
		rdc_svc_count++;
	}

outdisp:
	if (!SVC_FREEARGS(xprt, (xdrproc_t)0, (caddr_t)0))
		cmn_err(CE_NOTE, "rdcsrv_dispatch: bad freeargs");
done:
	mutex_enter(&rdcsrv_lock);
	rdcsrv_refcnt--;
	mutex_exit(&rdcsrv_lock);
}


static int
rdcsrv_create(file_t *fp, rdc_svc_args_t *args, int mode)
{
	/*LINTED*/
	int rc, error = 0;
	/*LINTED*/
	rpcvers_t vers;
	struct netbuf addrmask;

#if defined(_SunOS_5_6) || defined(_SunOS_5_7)
	SVCXPRT *xprt;
#else
	SVCMASTERXPRT *xprt;
#endif
	STRUCT_HANDLE(rdc_svc_args, uap);

	STRUCT_SET_HANDLE(uap, mode, args);

	addrmask.len = STRUCT_FGET(uap, addrmask.len);
	addrmask.maxlen = STRUCT_FGET(uap, addrmask.maxlen);
	addrmask.buf = kmem_alloc(addrmask.maxlen, KM_SLEEP);
	error = ddi_copyin(STRUCT_FGETP(uap, addrmask.buf), addrmask.buf,
			addrmask.len, mode);
	if (error) {
		kmem_free(addrmask.buf, addrmask.maxlen);
#ifdef DEBUG
		cmn_err(CE_WARN, "copyin of addrmask failed %p", (void *) args);
#endif
		return (error);
	}

	/*
	 * Set rdcstub's dispatch handle to rdcsrv_dispatch
	 */
	rdcstub_set_dispatch(rdcsrv_dispatch);

	/*
	 * Create a transport endpoint and create one kernel thread to run the
	 * rdc service loop
	 */
#if defined(_SunOS_5_6) || defined(_SunOS_5_7)
	error = svc_tli_kcreate(fp, RDC_RPC_MAX,
		STRUCT_FGETP(uap, netid), &addrmask,
		STRUCT_FGET(uap, nthr), &xprt);
#else
	{
#if defined(_SunOS_5_8)
		struct svcpool_args p;
		p.id = RDC_SVCPOOL_ID;
		p.maxthreads = STRUCT_FGET(uap, nthr);
		p.redline = 0;
		p.qsize =  0;
		p.timeout = 0;
		p.stksize = 0;
		p.max_same_xprt = 0;

		error = svc_pool_create(&p);
		if (error) {
			cmn_err(CE_NOTE,
				"rdcsrv_create: svc_pool_create failed %d",
				error);
			return (error);
		}
#endif
		error = svc_tli_kcreate(fp, RDC_RPC_MAX,
				STRUCT_FGETP(uap, netid), &addrmask,
				&xprt, &rdcsrv_sct, NULL, RDC_SVCPOOL_ID,
				FALSE);
	}
#endif

	if (error) {
		cmn_err(CE_NOTE,
			"rdcsrv_create: svc_tli_kcreate failed %d",
			error);
		return (error);
	}

#if defined(_SunOS_5_6) || defined(_SunOS_5_7)
	if (xprt == NULL) {
		cmn_err(CE_NOTE, "xprt in rdcsrv_create is NULL");
	} else {
		/*
		 * Register a cleanup routine in case the transport gets
		 * destroyed.  If the registration fails for some reason,
		 * it means that the transport is already being destroyed.
		 * This shouldn't happen, but it's probably not worth a
		 * panic.
		 */
		if (!svc_control(xprt, SVCSET_CLOSEPROC,
			(void *)rdcsrv_xprtclose)) {
			cmn_err(
#ifdef DEBUG
				CE_PANIC,
#else
				CE_WARN,
#endif
				"rdcsrv_create: couldn't set xprt callback");

			error = EBADF;
			goto done;
		}
	}

	for (vers = RDC_VERS_MIN; vers <= RDC_VERS_MAX; vers++) {
		rc = svc_register(xprt, (ulong_t)RDC_PROGRAM, vers,
				rdcstub_dispatch, 0);
		if (!rc) {
			cmn_err(CE_NOTE,
				"rdcsrv_create: svc_register(%d, %lu) failed",
				RDC_PROGRAM, vers);

			if (!error) {
				error = EBADF;
			}
		}
	}
#endif /* 5.6 or 5.7 */

	if (!error) {
		/* mark as registered with the kRPC subsystem */
		rdcsrv_registered = 1;
	}

done:
	return (error);
}


#if defined(_SunOS_5_6) || defined(_SunOS_5_7)
/*
 * Callback routine for when a transport is closed.
 */
static void
rdcsrv_xprtclose(const SVCXPRT *xprt)
{
}
#endif


/*
 * Private interface from the main RDC module.
 */

int
rdcsrv_load(file_t *fp, rdcsrv_t *disptab,  rdc_svc_args_t *args, int mode)
{
	int rc = 0;

	mutex_enter(&rdcsrv_lock);

	rc = rdcsrv_create(fp, args, mode);
	if (rc == 0) {
		rdcsrv_disptab = disptab;
	}

	mutex_exit(&rdcsrv_lock);
	return (rc);
}


void
rdcsrv_unload(void)
{
	mutex_enter(&rdcsrv_lock);

	/* Unset rdcstub's dispatch handle */
	rdcstub_unset_dispatch();

	rdcsrv_closing = 1;

	while (rdcsrv_refcnt > 0) {
		mutex_exit(&rdcsrv_lock);
		delay(drv_usectohz(25));
		mutex_enter(&rdcsrv_lock);
	}

	rdcsrv_closing = 0;
	rdcsrv_disptab = 0;

	mutex_exit(&rdcsrv_lock);
}
