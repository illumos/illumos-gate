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

#define	_RDC_
#include <sys/types.h>
#include <sys/ksynch.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/modctl.h>
#include <sys/cred.h>
#include <sys/ddi.h>
#include <sys/sysmacros.h>
#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_k.h>
#include <sys/unistat/spcs_errors.h>

#include <sys/nsc_thread.h>
#ifdef DS_DDICT
#include "../contract.h"
#endif
#include <sys/nsctl/nsctl.h>
#include <sys/nsctl/nsvers.h>

#include <sys/sdt.h>		/* dtrace is S10 or later */

#include "rdc.h"
#include "rdc_io.h"
#include "rdc_bitmap.h"
#include "rdc_ioctl.h"
#include "rdcsrv.h"
#include "rdc_diskq.h"

#define	DIDINIT		0x01
#define	DIDNODES	0x02
#define	DIDCONFIG	0x04

static int rdcopen(dev_t *devp, int flag, int otyp, cred_t *crp);
static int rdcclose(dev_t dev, int flag, int otyp, cred_t *crp);
static int rdcprint(dev_t dev, char *str);
static int rdcioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *crp,
	int *rvp);
static int rdcattach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int rdcdetach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int rdcgetinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
	void **result);
#ifdef	DEBUG
static int rdc_clrkstat(void *);
#endif

/*
 * kstat interface
 */
static kstat_t *sndr_kstats;

int sndr_info_stats_update(kstat_t *ksp, int rw);

static sndr_m_stats_t sndr_info_stats = {
	{RDC_MKSTAT_MAXSETS,			KSTAT_DATA_ULONG},
	{RDC_MKSTAT_MAXFBAS,			KSTAT_DATA_ULONG},
	{RDC_MKSTAT_RPC_TIMEOUT,		KSTAT_DATA_ULONG},
	{RDC_MKSTAT_HEALTH_THRES,		KSTAT_DATA_ULONG},
	{RDC_MKSTAT_BITMAP_WRITES,		KSTAT_DATA_ULONG},
	{RDC_MKSTAT_CLNT_COTS_CALLS,		KSTAT_DATA_ULONG},
	{RDC_MKSTAT_CLNT_CLTS_CALLS,		KSTAT_DATA_ULONG},
	{RDC_MKSTAT_SVC_COTS_CALLS,		KSTAT_DATA_ULONG},
	{RDC_MKSTAT_SVC_CLTS_CALLS,		KSTAT_DATA_ULONG},
	{RDC_MKSTAT_BITMAP_REF_DELAY,		KSTAT_DATA_ULONG}
};

int rdc_info_stats_update(kstat_t *ksp, int rw);

static rdc_info_stats_t rdc_info_stats = {
	{RDC_IKSTAT_FLAGS,		KSTAT_DATA_ULONG},
	{RDC_IKSTAT_SYNCFLAGS,		KSTAT_DATA_ULONG},
	{RDC_IKSTAT_BMPFLAGS,		KSTAT_DATA_ULONG},
	{RDC_IKSTAT_SYNCPOS,		KSTAT_DATA_ULONG},
	{RDC_IKSTAT_VOLSIZE,		KSTAT_DATA_ULONG},
	{RDC_IKSTAT_BITSSET,		KSTAT_DATA_ULONG},
	{RDC_IKSTAT_AUTOSYNC,		KSTAT_DATA_ULONG},
	{RDC_IKSTAT_MAXQFBAS,		KSTAT_DATA_ULONG},
	{RDC_IKSTAT_MAXQITEMS,		KSTAT_DATA_ULONG},
	{RDC_IKSTAT_FILE,		KSTAT_DATA_STRING},
	{RDC_IKSTAT_SECFILE,		KSTAT_DATA_STRING},
	{RDC_IKSTAT_BITMAP,		KSTAT_DATA_STRING},
	{RDC_IKSTAT_PRIMARY_HOST,	KSTAT_DATA_STRING},
	{RDC_IKSTAT_SECONDARY_HOST,	KSTAT_DATA_STRING},
	{RDC_IKSTAT_TYPE_FLAG,		KSTAT_DATA_ULONG},
	{RDC_IKSTAT_BMP_SIZE,		KSTAT_DATA_ULONG},
	{RDC_IKSTAT_DISK_STATUS,	KSTAT_DATA_ULONG},
	{RDC_IKSTAT_IF_DOWN,		KSTAT_DATA_ULONG},
	{RDC_IKSTAT_IF_RPC_VERSION,	KSTAT_DATA_ULONG},
	{RDC_IKSTAT_ASYNC_BLOCK_HWM,	KSTAT_DATA_ULONG},
	{RDC_IKSTAT_ASYNC_ITEM_HWM,	KSTAT_DATA_ULONG},
	{RDC_IKSTAT_ASYNC_THROTTLE_DELAY,	KSTAT_DATA_ULONG},
	{RDC_IKSTAT_ASYNC_ITEMS,	KSTAT_DATA_ULONG},
	{RDC_IKSTAT_ASYNC_BLOCKS,	KSTAT_DATA_ULONG},
	{RDC_IKSTAT_QUEUE_TYPE,		KSTAT_DATA_CHAR}
};

static struct cb_ops rdc_cb_ops = {
	rdcopen,
	rdcclose,
	nulldev,		/* no strategy */
	rdcprint,
	nodev,			/* no dump */
	nodev,			/* no read */
	nodev,			/* no write */
	rdcioctl,
	nodev,			/* no devmap */
	nodev,			/* no mmap */
	nodev,			/* no segmap */
	nochpoll,
	ddi_prop_op,
	NULL,			/* not STREAMS */
	D_NEW | D_MP | D_64BIT,
	CB_REV,
	nodev,			/* no aread */
	nodev,			/* no awrite */
};

static struct dev_ops rdc_ops = {
	DEVO_REV,
	0,
	rdcgetinfo,
	nulldev,		/* identify */
	nulldev,		/* probe */
	rdcattach,
	rdcdetach,
	nodev,			/* no reset */
	&rdc_cb_ops,
	(struct bus_ops *)NULL
};

static struct modldrv rdc_ldrv = {
	&mod_driverops,
	"nws:Remote Mirror:" ISS_VERSION_STR,
	&rdc_ops
};

static struct modlinkage rdc_modlinkage = {
	MODREV_1,
	&rdc_ldrv,
	NULL
};

const	int sndr_major_rev = ISS_VERSION_MAJ;
const	int sndr_minor_rev = ISS_VERSION_MIN;
const	int sndr_micro_rev = ISS_VERSION_MIC;
const	int sndr_baseline_rev = ISS_VERSION_NUM;
static	char sndr_version[16];

static void *rdc_dip;

extern int _rdc_init_dev();
extern void _rdc_deinit_dev();
extern void rdc_link_down_free();

int rdc_bitmap_mode;
int rdc_auto_sync;
int rdc_max_sets;
extern int rdc_health_thres;

kmutex_t rdc_sync_mutex;
rdc_sync_event_t rdc_sync_event;
clock_t rdc_sync_event_timeout;

static void
rdc_sync_event_init()
{
	mutex_init(&rdc_sync_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&rdc_sync_event.mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&rdc_sync_event.cv, NULL, CV_DRIVER, NULL);
	cv_init(&rdc_sync_event.done_cv, NULL, CV_DRIVER, NULL);
	rdc_sync_event.master[0] = 0;
	rdc_sync_event.lbolt = (clock_t)0;
	rdc_sync_event_timeout = RDC_SYNC_EVENT_TIMEOUT;
}


static void
rdc_sync_event_destroy()
{
	mutex_destroy(&rdc_sync_mutex);
	mutex_destroy(&rdc_sync_event.mutex);
	cv_destroy(&rdc_sync_event.cv);
	cv_destroy(&rdc_sync_event.done_cv);
}



int
_init(void)
{
	return (mod_install(&rdc_modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&rdc_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&rdc_modlinkage, modinfop));
}

static int
rdcattach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	intptr_t flags;
	int instance;
	int i;

	/*CONSTCOND*/
	ASSERT(sizeof (u_longlong_t) == 8);

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	(void) strncpy(sndr_version, _VERSION_, sizeof (sndr_version));

	instance = ddi_get_instance(dip);
	rdc_dip = dip;

	flags = 0;

	rdc_sync_event_init();

	/*
	 * rdc_max_sets must be set before calling _rdc_load().
	 */

	rdc_max_sets = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "rdc_max_sets", 64);

	if (_rdc_init_dev()) {
		cmn_err(CE_WARN, "!rdc: _rdc_init_dev failed");
		goto out;
	}
	flags |= DIDINIT;

	if (_rdc_load() != 0) {
		cmn_err(CE_WARN, "!rdc: _rdc_load failed");
		goto out;
	}

	if (_rdc_configure()) {
		cmn_err(CE_WARN, "!rdc: _rdc_configure failed");
		goto out;
	}
	flags |= DIDCONFIG;

	if (ddi_create_minor_node(dip, "rdc", S_IFCHR, instance, DDI_PSEUDO, 0)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!rdc: could not create node.");
		goto out;
	}
	flags |= DIDNODES;

	rdc_bitmap_mode = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    "rdc_bitmap_mode", 0);

	switch (rdc_bitmap_mode) {
	case RDC_BMP_AUTO:		/* 0 */
		break;
	case RDC_BMP_ALWAYS:		/* 1 */
		break;
	case RDC_BMP_NEVER:		/* 2 */
		cmn_err(CE_NOTE, "!SNDR bitmap mode override");
		cmn_err(CE_CONT,
		    "!SNDR: bitmaps will only be written on shutdown\n");
		break;
	default:			/* unknown */
		cmn_err(CE_NOTE,
		    "!SNDR: unknown bitmap mode %d - autodetecting mode",
		    rdc_bitmap_mode);
		rdc_bitmap_mode = RDC_BMP_AUTO;
		break;
	}

	rdc_bitmap_init();

	rdc_auto_sync = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    "rdc_auto_sync", 0);

	i = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    "rdc_health_thres", RDC_HEALTH_THRESHOLD);
	if (i >= RDC_MIN_HEALTH_THRES)
		rdc_health_thres = i;
	else
		cmn_err(CE_WARN, "!value rdc_heath_thres from rdc.conf ignored "
		    "as it is smaller than the min value of %d",
		    RDC_MIN_HEALTH_THRES);

	ddi_set_driver_private(dip, (caddr_t)flags);
	ddi_report_dev(dip);

	sndr_kstats = kstat_create(RDC_KSTAT_MODULE, 0,
	    RDC_KSTAT_MINFO, RDC_KSTAT_CLASS, KSTAT_TYPE_NAMED,
	    sizeof (sndr_m_stats_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);

	if (sndr_kstats) {
		sndr_kstats->ks_data = &sndr_info_stats;
		sndr_kstats->ks_update = sndr_info_stats_update;
		sndr_kstats->ks_private = &rdc_k_info[0];
		kstat_install(sndr_kstats);
	} else
			cmn_err(CE_WARN, "!SNDR: module kstats failed");

	return (DDI_SUCCESS);

out:
	DTRACE_PROBE(rdc_attach_failed);
	ddi_set_driver_private(dip, (caddr_t)flags);
	(void) rdcdetach(dip, DDI_DETACH);
	return (DDI_FAILURE);
}

static int
rdcdetach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	rdc_k_info_t *krdc;
	rdc_u_info_t *urdc;
	int rdcd;
	intptr_t flags;


	if (cmd != DDI_DETACH) {
		DTRACE_PROBE(rdc_detach_unknown_cmd);
		return (DDI_FAILURE);
	}

	if (rdc_k_info == NULL || rdc_u_info == NULL)
		goto cleanup;

	mutex_enter(&rdc_conf_lock);

	for (rdcd = 0; rdcd < rdc_max_sets; rdcd++) {
		krdc = &rdc_k_info[rdcd];
		urdc = &rdc_u_info[rdcd];

		if (IS_ENABLED(urdc) || krdc->devices) {
#ifdef DEBUG
			cmn_err(CE_WARN,
			    "!rdc: cannot detach, rdcd %d still in use", rdcd);
#endif
			mutex_exit(&rdc_conf_lock);
			DTRACE_PROBE(rdc_detach_err_busy);
			return (DDI_FAILURE);
		}
	}

	mutex_exit(&rdc_conf_lock);

cleanup:
	flags = (intptr_t)ddi_get_driver_private(dip);

	if (flags & DIDNODES)
		ddi_remove_minor_node(dip, NULL);

	if (sndr_kstats) {
		kstat_delete(sndr_kstats);
	}
	if (flags & DIDINIT)
		_rdc_deinit_dev();

	if (flags & DIDCONFIG) {
		(void) _rdc_deconfigure();
		(void) _rdc_unload();
		rdcsrv_unload();
	}

	rdc_sync_event_destroy();
	rdc_link_down_free();

	rdc_dip = NULL;
	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
rdcgetinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int rc = DDI_FAILURE;

	switch (infocmd) {

	case DDI_INFO_DEVT2DEVINFO:
		*result = rdc_dip;
		rc = DDI_SUCCESS;
		break;

	case DDI_INFO_DEVT2INSTANCE:
		/* We only have a single instance */
		*result = 0;
		rc = DDI_SUCCESS;
		break;

	default:
		break;
	}

	return (rc);
}


/* ARGSUSED */

static int
rdcopen(dev_t *devp, int flag, int otyp, cred_t *crp)
{
	return (0);
}


/* ARGSUSED */

static int
rdcclose(dev_t dev, int flag, int otyp, cred_t *crp)
{
	return (0);
}

/* ARGSUSED */

static int
rdcprint(dev_t dev, char *str)
{
	int instance = 0;

	cmn_err(CE_WARN, "!rdc%d: %s", instance, str);
	return (0);
}


static int
convert_ioctl_args(int cmd, intptr_t arg, int mode, _rdc_ioctl_t *args)
{
	_rdc_ioctl32_t args32;

	if (ddi_copyin((void *)arg, &args32, sizeof (_rdc_ioctl32_t), mode))
		return (EFAULT);

	bzero((void *)args, sizeof (_rdc_ioctl_t));

	switch (cmd) {
	case RDC_CONFIG:
		args->arg0 = (uint32_t)args32.arg0; /* _rdc_config_t * */
		args->arg1 = (uint32_t)args32.arg1; /* pointer */
		args->arg2 = (uint32_t)args32.arg2; /* size */
		args->ustatus = (spcs_s_info_t)args32.ustatus;
		break;

	case RDC_STATUS:
		args->arg0 = (uint32_t)args32.arg0; /* pointer */
		args->ustatus = (spcs_s_info_t)args32.ustatus;
		break;

	case RDC_ENABLE_SVR:
		args->arg0 = (uint32_t)args32.arg0; /* _rdc_svc_args *  */
		break;

	case RDC_VERSION:
		args->arg0 = (uint32_t)args32.arg0; /* _rdc_version_t *  */
		args->ustatus = (spcs_s_info_t)args32.ustatus;
		break;

	case RDC_SYNC_EVENT:
		args->arg0 = (uint32_t)args32.arg0; /* char *  */
		args->arg1 = (uint32_t)args32.arg1; /* char *  */
		args->ustatus = (spcs_s_info_t)args32.ustatus;
		break;

	case RDC_LINK_DOWN:
		args->arg0 = (uint32_t)args32.arg0; /* char *  */
		args->ustatus = (spcs_s_info_t)args32.ustatus;
		break;
	case RDC_POOL_CREATE:
		args->arg0 = (uint32_t)args32.arg0; /* svcpool_args *  */
		break;
	case RDC_POOL_WAIT:
		args->arg0 = (uint32_t)args32.arg0; /* int */
		break;
	case RDC_POOL_RUN:
		args->arg0 = (uint32_t)args32.arg0; /* int */
		break;

	default:
		return (EINVAL);
	}

	return (0);
}

/*
 * Build a 32bit rdc_set structure and copyout to the user level.
 */
int
rdc_status_copy32(const void *arg, void *usetp, size_t size, int mode)
{
	rdc_u_info_t *urdc = (rdc_u_info_t *)arg;
	struct rdc_set32 set32;
	size_t tailsize;
#ifdef DEBUG
	size_t tailsize32;
#endif

	bzero(&set32, sizeof (set32));

	tailsize = sizeof (struct rdc_addr32) -
	    offsetof(struct rdc_addr32, intf);

	/* primary address structure, avoiding netbuf */
	bcopy(&urdc->primary.intf[0], &set32.primary.intf[0], tailsize);

	/* secondary address structure, avoiding netbuf */
	bcopy(&urdc->secondary.intf[0], &set32.secondary.intf[0], tailsize);

	/*
	 * the rest, avoiding netconfig
	 * note: the tail must be the same size in both structures
	 */
	tailsize = sizeof (struct rdc_set) - offsetof(struct rdc_set, flags);
#ifdef DEBUG
	/*
	 * ASSERT is calling for debug reason, and tailsize32 is only declared
	 * for ASSERT, put them under debug to avoid lint warning.
	 */
	tailsize32 = sizeof (struct rdc_set32) -
	    offsetof(struct rdc_set32, flags);
	ASSERT(tailsize == tailsize32);
#endif

	bcopy(&urdc->flags, &set32.flags, tailsize);

	/* copyout to user level */
	return (ddi_copyout(&set32, usetp, size, mode));
}


/*
 * Status ioctl.
 */
static int
rdcstatus(_rdc_ioctl_t *args, int mode)
{
	int (*copyout)(const void *, void *, size_t, int);
	rdc_u_info_t *urdc;
	rdc_k_info_t *krdc;
	disk_queue *dqp;
	char *usetp;			/* pointer to user rdc_set structure */
	size_t size;			/* sizeof user rdc_set structure */
	int32_t *maxsetsp;		/* address of status->maxsets; */
	int nset, max, i, j;

	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		struct rdc_status32 status32;

		if (ddi_copyin((void *)args->arg0, &status32,
		    sizeof (status32), mode)) {
			return (EFAULT);
		}

		usetp = ((char *)args->arg0) +
		    offsetof(struct rdc_status32, rdc_set);
		maxsetsp = (int32_t *)((char *)args->arg0 +
		    offsetof(struct rdc_status32, maxsets));
		nset = status32.nset;

		size = sizeof (struct rdc_set32);
		copyout = rdc_status_copy32;
	} else {
		struct rdc_status status;

		if (ddi_copyin((void *)args->arg0, &status,
		    sizeof (status), mode)) {
			return (EFAULT);
		}

		usetp = ((char *)args->arg0) +
		    offsetof(struct rdc_status, rdc_set);
		maxsetsp = (int32_t *)((char *)args->arg0 +
		    offsetof(struct rdc_status, maxsets));
		nset = status.nset;

		size = sizeof (struct rdc_set);
		copyout = ddi_copyout;
	}

	max = min(nset, rdc_max_sets);

	for (i = 0, j = 0; i < max; i++) {
		urdc = &rdc_u_info[i];
		krdc = &rdc_k_info[i];

		if (!IS_ENABLED(urdc))
			continue;

		/*
		 * sneak out qstate in urdc->flags
		 * this is harmless because it's value is not used
		 * in urdc->flags. the real qstate is kept in
		 * group->diskq->disk_hdr.h.state
		 */
		if (RDC_IS_DISKQ(krdc->group)) {
			dqp = &krdc->group->diskq;
			if (IS_QSTATE(dqp, RDC_QNOBLOCK))
				urdc->flags |= RDC_QNOBLOCK;
		}

		j++;
		if ((*copyout)(urdc, usetp, size, mode) != 0)
			return (EFAULT);

		urdc->flags &= ~RDC_QNOBLOCK; /* clear qstate */
		usetp += size;
	}

	/* copyout rdc_max_sets value */

	if (ddi_copyout(&rdc_max_sets, maxsetsp, sizeof (*maxsetsp), mode) != 0)
		return (EFAULT);

	/* copyout number of sets manipulated */

	/*CONSTCOND*/
	ASSERT(offsetof(struct rdc_status32, nset) == 0);
	/*CONSTCOND*/
	ASSERT(offsetof(struct rdc_status, nset) == 0);

	return (ddi_copyout(&j, (void *)args->arg0, sizeof (int), mode));
}


/* ARGSUSED */

static int
rdcioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *crp, int *rvp)
{
	spcs_s_info_t kstatus = NULL;
	_rdc_ioctl_t args;
	int error;
	int rc = 0;

	if (cmd != RDC_STATUS) {
		if ((error = drv_priv(crp)) != 0)
			return (error);
	}
#ifdef	DEBUG
	if (cmd == RDC_ASYNC6) {
		rc = rdc_async6((void *)arg, mode, rvp);
		return (rc);
	}

	if (cmd == RDC_CLRKSTAT) {
		rc = rdc_clrkstat((void *)arg);
		return (rc);
	}

	if (cmd == RDC_STALL0) {
		if (((int)arg > 1) || ((int)arg < 0))
			return (EINVAL);
		rdc_stallzero((int)arg);
		return (0);
	}
	if (cmd == RDC_READGEN) {
		rc = rdc_readgen((void *)arg, mode, rvp);
		return (rc);
	}
#endif
	if (cmd == RDC_BITMAPOP) {
		rdc_bitmap_op_t bmop;
		rdc_bitmap_op32_t bmop32;

		if (ddi_model_convert_from(mode & FMODELS)
		    == DDI_MODEL_ILP32) {
			if (ddi_copyin((void *)arg, &bmop32, sizeof (bmop32),
			    mode))
				return (EFAULT);
			bmop.offset = bmop32.offset;
			bmop.op = bmop32.op;
			(void) strncpy(bmop.sechost, bmop32.sechost,
			    MAX_RDC_HOST_SIZE);
			(void) strncpy(bmop.secfile, bmop32.secfile,
			    NSC_MAXPATH);
			bmop.len = bmop32.len;
			bmop.addr = (unsigned long)bmop32.addr;
		} else {
			if (ddi_copyin((void *)arg, &bmop, sizeof (bmop),
			    mode))
				return (EFAULT);
		}
		rc = rdc_bitmapset(bmop.op, bmop.sechost, bmop.secfile,
		    (void *)bmop.addr, bmop.len, bmop.offset, mode);
		return (rc);
	}

	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		if ((rc = convert_ioctl_args(cmd, arg, mode, &args)) != 0)
			return (rc);
	} else {
		if (ddi_copyin((void *)arg, &args,
		    sizeof (_rdc_ioctl_t), mode)) {
			return (EFAULT);
		}
	}

	kstatus = spcs_s_kcreate();
	if (!kstatus) {
		return (ENOMEM);
	}


	switch (cmd) {

	case RDC_POOL_CREATE: {
		struct svcpool_args p;

		if (ddi_copyin((void *)arg, &p, sizeof (p), mode)) {
			spcs_s_kfree(kstatus);
			return (EFAULT);
		}
		error = svc_pool_create(&p);

		break;
	}
	case RDC_POOL_WAIT: {
		int id;

		if (ddi_copyin((void *)arg, &id, sizeof (id), mode)) {
			spcs_s_kfree(kstatus);
			return (EFAULT);
		}

		error = svc_wait(id);
		break;
	}
	case RDC_POOL_RUN: {
		int id;

		if (ddi_copyin((void *)arg, &id, sizeof (id), mode)) {
			spcs_s_kfree(kstatus);
			return (EFAULT);
		}
		error = svc_do_run(id);
		break;
	}
	case RDC_ENABLE_SVR:
		{
			STRUCT_DECL(rdc_svc_args, parms);

			STRUCT_INIT(parms, mode);
			/* Only used by sndrd which does not use unistat */

			if (ddi_copyin((void *)args.arg0, STRUCT_BUF(parms),
			    STRUCT_SIZE(parms), mode)) {
				spcs_s_kfree(kstatus);
				return (EFAULT);
			}
			rc = rdc_start_server(STRUCT_BUF(parms), mode);
		}
		break;

	case RDC_STATUS:
		rc = rdcstatus(&args, mode);
		break;

	case RDC_CONFIG:
		rc = _rdc_config((void *)args.arg0, mode, kstatus, rvp);
		spcs_s_copyoutf(&kstatus, args.ustatus);
		return (rc);

	case RDC_VERSION:
		{
			STRUCT_DECL(rdc_version, parms);

			STRUCT_INIT(parms, mode);

			STRUCT_FSET(parms, major, sndr_major_rev);
			STRUCT_FSET(parms, minor, sndr_minor_rev);
			STRUCT_FSET(parms, micro, sndr_micro_rev);
			STRUCT_FSET(parms, baseline, sndr_baseline_rev);

			if (ddi_copyout(STRUCT_BUF(parms), (void *)args.arg0,
			    STRUCT_SIZE(parms), mode)) {
				spcs_s_kfree(kstatus);
				return (EFAULT);
			}
			break;
		}

	case RDC_LINK_DOWN:
		/* char *host from user */
		rc = _rdc_link_down((void *)args.arg0, mode, kstatus, rvp);
		spcs_s_copyoutf(&kstatus, args.ustatus);

		return (rc);

	case RDC_SYNC_EVENT:
		rc = _rdc_sync_event_wait((void *)args.arg0, (void *)args.arg1,
		    mode, kstatus, rvp);
		spcs_s_copyoutf(&kstatus, args.ustatus);

		return (rc);


	default:
		rc = EINVAL;
		break;
	}

	spcs_s_kfree(kstatus);
	return (rc);
}

int
sndr_info_stats_update(kstat_t *ksp, int rw)
{
	extern int rdc_rpc_tmout;
	extern int rdc_health_thres;
	extern int rdc_bitmap_delay;
	extern long rdc_clnt_count;
	extern long rdc_svc_count;
	sndr_m_stats_t	*info_stats;
	rdc_k_info_t	*krdc;

	info_stats = (sndr_m_stats_t *)(ksp->ks_data);
	krdc = (rdc_k_info_t *)(ksp->ks_private);

	/* no writes currently allowed */

	if (rw == KSTAT_WRITE) {
		return (EACCES);
	}

	/* default to READ */
	info_stats->m_maxsets.value.ul = rdc_max_sets;
	info_stats->m_maxfbas.value.ul = krdc->maxfbas;
	info_stats->m_rpc_timeout.value.ul = rdc_rpc_tmout;
	info_stats->m_health_thres.value.ul = rdc_health_thres;
	info_stats->m_bitmap_writes.value.ul = krdc->bitmap_write;
	info_stats->m_bitmap_ref_delay.value.ul = rdc_bitmap_delay;

	/* clts counters not implemented yet */
	info_stats->m_clnt_cots_calls.value.ul = rdc_clnt_count;
	info_stats->m_clnt_clts_calls.value.ul = 0;
	info_stats->m_svc_cots_calls.value.ul = rdc_svc_count;
	info_stats->m_svc_clts_calls.value.ul = 0;

	return (0);
}

/*
 * copy tailsize-1 bytes of tail of s to s1.
 */
void
rdc_str_tail_cpy(char *s1, char *s, size_t tailsize)
{
	/* To avoid un-terminated string, max size is 16 - 1 */
	ssize_t offset = strlen(s) - (tailsize - 1);

	offset = (offset > 0) ? offset : 0;

	/* ensure it's null terminated */
	(void) strlcpy(s1, (const char *)(s + offset), tailsize);
}

int
rdc_info_stats_update(kstat_t *ksp, int rw)
{
	rdc_info_stats_t	*rdc_info_stats;
	rdc_k_info_t		*krdc;
	rdc_u_info_t		*urdc;

	rdc_info_stats = (rdc_info_stats_t *)(ksp->ks_data);
	krdc = (rdc_k_info_t *)(ksp->ks_private);
	urdc = &rdc_u_info[krdc->index];

	/* no writes currently allowed */

	if (rw == KSTAT_WRITE) {
		return (EACCES);
	}

	/* default to READ */
	rdc_info_stats->s_flags.value.ul = urdc->flags;
	rdc_info_stats->s_syncflags.value.ul =
	    urdc->sync_flags;
	rdc_info_stats->s_bmpflags.value.ul =
	    urdc->bmap_flags;
	rdc_info_stats->s_syncpos.value.ul =
	    urdc->sync_pos;
	rdc_info_stats->s_volsize.value.ul =
	    urdc->volume_size;
	rdc_info_stats->s_bits_set.value.ul =
	    urdc->bits_set;
	rdc_info_stats->s_autosync.value.ul =
	    urdc->autosync;
	rdc_info_stats->s_maxqfbas.value.ul =
	    urdc->maxqfbas;
	rdc_info_stats->s_maxqitems.value.ul =
	    urdc->maxqitems;

	kstat_named_setstr(&rdc_info_stats->s_primary_vol,
	    urdc->primary.file);

	kstat_named_setstr(&rdc_info_stats->s_secondary_vol,
	    urdc->secondary.file);

	if (rdc_get_vflags(urdc) & RDC_PRIMARY) {
		kstat_named_setstr(&rdc_info_stats->s_bitmap,
		    urdc->primary.bitmap);
	} else {
		kstat_named_setstr(&rdc_info_stats->s_bitmap,
		    urdc->secondary.bitmap);
	}

	kstat_named_setstr(&rdc_info_stats->s_primary_intf,
	    urdc->primary.intf);

	kstat_named_setstr(&rdc_info_stats->s_secondary_intf,
	    urdc->secondary.intf);

	rdc_info_stats->s_type_flag.value.ul = krdc->type_flag;
	rdc_info_stats->s_bitmap_size.value.ul = krdc->bitmap_size;
	rdc_info_stats->s_disk_status.value.ul = krdc->disk_status;

	if (krdc->intf) {
		rdc_info_stats->s_if_if_down.value.ul = krdc->intf->if_down;
		rdc_info_stats->s_if_rpc_version.value.ul =
		    krdc->intf->rpc_version;
	}

	/* the type can change without disable/re-enable so... */
	bzero(rdc_info_stats->s_aqueue_type.value.c, KSTAT_DATA_CHAR_LEN);
	if (RDC_IS_MEMQ(krdc->group)) {
		(void) strcpy(rdc_info_stats->s_aqueue_type.value.c, "memory");
		rdc_info_stats->s_aqueue_blk_hwm.value.ul =
		    krdc->group->ra_queue.blocks_hwm;
		rdc_info_stats->s_aqueue_itm_hwm.value.ul =
		    krdc->group->ra_queue.nitems_hwm;
		rdc_info_stats->s_aqueue_throttle.value.ul =
		    krdc->group->ra_queue.throttle_delay;
		rdc_info_stats->s_aqueue_items.value.ul =
		    krdc->group->ra_queue.nitems;
		rdc_info_stats->s_aqueue_blocks.value.ul =
		    krdc->group->ra_queue.blocks;

	} else if (RDC_IS_DISKQ(krdc->group)) {
		disk_queue *q = &krdc->group->diskq;
		rdc_info_stats->s_aqueue_blk_hwm.value.ul =
		    krdc->group->diskq.blocks_hwm;
		rdc_info_stats->s_aqueue_itm_hwm.value.ul =
		    krdc->group->diskq.nitems_hwm;
		rdc_info_stats->s_aqueue_throttle.value.ul =
		    krdc->group->diskq.throttle_delay;
		rdc_info_stats->s_aqueue_items.value.ul = QNITEMS(q);
		rdc_info_stats->s_aqueue_blocks.value.ul = QBLOCKS(q);
		(void) strcpy(rdc_info_stats->s_aqueue_type.value.c, "disk");
	}

	return (0);
}

void
rdc_kstat_create(int index)
{
	int j = index;
	rdc_k_info_t *krdc = &rdc_k_info[index];
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];
	size_t varsize;

	if (!krdc->set_kstats) {
		krdc->set_kstats = kstat_create(RDC_KSTAT_MODULE, j,
		    RDC_KSTAT_INFO, RDC_KSTAT_CLASS, KSTAT_TYPE_NAMED,
		    sizeof (rdc_info_stats_t) / sizeof (kstat_named_t),
		    KSTAT_FLAG_VIRTUAL);
#ifdef DEBUG
		if (!krdc->set_kstats)
			cmn_err(CE_NOTE, "!krdc:u_kstat null");
#endif

		if (krdc->set_kstats) {
			/* calculate exact size of KSTAT_DATA_STRINGs */
			varsize = strlen(urdc->primary.file) + 1
			    + strlen(urdc->secondary.file) + 1
			    + strlen(urdc->primary.intf) + 1
			    + strlen(urdc->secondary.intf) + 1;
			if (rdc_get_vflags(urdc) & RDC_PRIMARY) {
				varsize += strlen(urdc->primary.bitmap) + 1;
			} else {
				varsize += strlen(urdc->secondary.bitmap) + 1;
			}

			krdc->set_kstats->ks_data_size += varsize;
			krdc->set_kstats->ks_data = &rdc_info_stats;
			krdc->set_kstats->ks_update = rdc_info_stats_update;
			krdc->set_kstats->ks_private = &rdc_k_info[j];
			kstat_install(krdc->set_kstats);
		} else
			cmn_err(CE_WARN, "!SNDR: k-kstats failed");
	}

	krdc->io_kstats = kstat_create(RDC_KSTAT_MODULE, j, NULL,
	    "disk", KSTAT_TYPE_IO, 1, 0);
	if (krdc->io_kstats) {
		krdc->io_kstats->ks_lock = &krdc->kstat_mutex;
		kstat_install(krdc->io_kstats);
	}
	krdc->bmp_kstats = kstat_create("sndrbmp", j, NULL,
	    "disk", KSTAT_TYPE_IO, 1, 0);
	if (krdc->bmp_kstats) {
		krdc->bmp_kstats->ks_lock = &krdc->bmp_kstat_mutex;
		kstat_install(krdc->bmp_kstats);
	}
}

void
rdc_kstat_delete(int index)
{
	rdc_k_info_t *krdc = &rdc_k_info[index];

	if (krdc->set_kstats) {
		kstat_delete(krdc->set_kstats);
		krdc->set_kstats = NULL;
	}

	if (krdc->io_kstats) {
		kstat_delete(krdc->io_kstats);
		krdc->io_kstats = NULL;
	}
	if (krdc->bmp_kstats) {
		kstat_delete(krdc->bmp_kstats);
		krdc->bmp_kstats = NULL;
	}
}

#ifdef	DEBUG
/*
 * Reset the io_kstat structure of the krdc specified
 * by the arg index.
 */
static int
rdc_clrkstat(void *arg)
{
	int index;
	rdc_k_info_t *krdc;

	index = (int)(unsigned long)arg;
	if ((index < 0) || (index >= rdc_max_sets)) {
		return (EINVAL);
	}
	krdc = &rdc_k_info[index];
	if (krdc->io_kstats) {
		kstat_delete(krdc->io_kstats);
		krdc->io_kstats = NULL;
	} else {
		return (EINVAL);
	}
	krdc->io_kstats = kstat_create(RDC_KSTAT_MODULE, index, NULL,
	    "disk", KSTAT_TYPE_IO, 1, 0);
	if (krdc->io_kstats) {
		krdc->io_kstats->ks_lock = &krdc->kstat_mutex;
		kstat_install(krdc->io_kstats);
	} else {
		return (EINVAL);
	}
	/*
	 * clear the high water marks and throttle.
	 */
	if (krdc->group) {
		krdc->group->ra_queue.nitems_hwm = 0;
		krdc->group->ra_queue.blocks_hwm = 0;
		krdc->group->ra_queue.throttle_delay = 0;
	}
	return (0);
}
#endif
