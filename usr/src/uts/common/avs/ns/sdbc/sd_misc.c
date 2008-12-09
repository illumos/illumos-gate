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

#define	_SCM_

#include <sys/types.h>
#include <sys/ksynch.h>
#include <sys/cmn_err.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/kmem.h>
#include <sys/cred.h>
#include <sys/ddi.h>
#include <sys/nsc_thread.h>

#include "sd_bcache.h"
#include "sd_misc.h"
#include "sd_trace.h"
#include "sd_ft.h"
#include "sd_io.h"
#include "sd_bio.h"
#include "sd_pcu.h"
#include "sd_tdaemon.h"
#include "sdbc_ioctl.h"
#include <sys/ncall/ncall.h>
#include <sys/nsctl/nsctl.h>
#include <sys/nsctl/nsvers.h>

#include <sys/sdt.h>		/* dtrace is S10 or later */

#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_k.h>
#include <sys/unistat/spcs_errors.h>
static dev_info_t *dev_dip;
dev_info_t *sdbc_get_dip();


/*
 *  A global variable to set the threshold for large writes to
 *  be in write through mode when NVRAM is present. This should
 *  solve the NVRAM bandwidth problem.
 */

int sdbc_wrthru_len;
nsc_size_t sdbc_max_fbas = _SD_MAX_FBAS;
int sdbc_max_devs = 0;

krwlock_t sdbc_queue_lock;

static int _sd_debug_level = 0;

static kmutex_t _sd_block_lk;

#define	REGISTER_SVC(X, Y) (ncall_register_svc(X, Y))
#define	UNREGISTER_SVC(X) (ncall_unregister_svc(X))

const int sdbc_major_rev = ISS_VERSION_MAJ;
const int sdbc_minor_rev = ISS_VERSION_MIN;
const int sdbc_micro_rev = ISS_VERSION_MIC;
const int sdbc_baseline_rev = ISS_VERSION_NUM;
static char sdbc_version[16];

static int _sdbc_attached = 0;

static int _sdbc_print(dev_t dev, char *s);
static int sdbcunload(void);
static int sdbcload(void);
static int sdbcopen(dev_t *devp, int flag, int otyp, cred_t *crp);
static int sdbcclose(dev_t dev, int flag, int otyp, cred_t *crp);
static int sdbcioctl(dev_t dev, int cmd, void *arg, int mode, cred_t *crp,
    int *rvp);
static int _sdbc_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int _sdbc_probe(dev_info_t *dip);
static int _sdbc_attach(dev_info_t *, ddi_attach_cmd_t);
static int _sdbc_detach(dev_info_t *, ddi_detach_cmd_t);
static int _sdbc_reset(dev_info_t *, ddi_reset_cmd_t);

#ifdef sun
/*
 * Solaris specific driver module interface code.
 */

#ifdef USES_SOFT_STATE
struct	sdbc_state {
	dev_info_t	*dip;		/* everyone would need a devinfo */
};

static	void	*sdbc_statep;		/* for soft state routines */
#endif /* USES_SOFT_STATE */

static	struct	cb_ops sdbc_cb_ops = {
	sdbcopen,	/* open */
	sdbcclose,	/* close */
	nodev,		/* not a block driver, strategy not an entry point */
	_sdbc_print,	/* no print routine */
	nodev,		/* no dump routine */
	nodev,		/* read */
	nodev,		/* write */
	(int (*) ()) sdbcioctl,	/* ioctl */
	nodev,		/* no devmap routine */
	nodev,		/* no mmap routine */
	nodev,		/* no segmap routine */
	nochpoll,	/* no chpoll routine */
	ddi_prop_op,
	0,		/* not a STREAMS driver, no cb_str routine */
	D_NEW | D_MP,	/* safe for multi-thread/multi-processor */
};


static	struct	dev_ops sdbc_ops = {
	DEVO_REV,			/* Driver build version */
	0,				/* device reference count */
	_sdbc_getinfo,
	nulldev,
	_sdbc_probe,
	_sdbc_attach,
	_sdbc_detach,
	_sdbc_reset,
	&sdbc_cb_ops,
	(struct bus_ops *)NULL
};

static struct modldrv sdbc_ldrv = {
	&mod_driverops,
	"nws:Storage Cache:" ISS_VERSION_STR,
	&sdbc_ops
};

static	struct modlinkage sdbc_modlinkage = {
	MODREV_1,
	&sdbc_ldrv,
	NULL
};

/*
 * dynmem interface
 */
static int mutex_and_condvar_flag;

/*
 * Solaris module load time code
 */
int
_init(void)
{

	int err;

	mutex_and_condvar_flag = 0;

#ifdef USES_SOFT_STATE
	ddi_soft_state_init(&sdbc_statep, sizeof (struct sdbc_state),
	    MAX_INSTANCES);
#endif /* USES_SOFT_STATE */

	/*
	 * It is "load" time, call the unixware equivalent.
	 */
	err = sdbcload();
	if (!err)
		err = mod_install(&sdbc_modlinkage);

	if (err) {
		(void) sdbcunload();
#ifdef USES_SOFT_STATE
		ddi_soft_state_fini(&sdbc_statep);
#endif /* USES_SOFT_STATE */
	}

	if (!err) {
		mutex_and_condvar_flag = 1;
		mutex_init(&dynmem_processing_dm.thread_dm_lock, "dynmem",
		    MUTEX_DRIVER, NULL);
		cv_init(&dynmem_processing_dm.thread_dm_cv, "dynmem",
		    CV_DRIVER, NULL);
	}

	return (err);

}
/*
 * Solaris module unload time code
 */

int
_fini(void)
{
	int err;

	if (_sd_cache_initialized) {
		return (EBUSY);
	} else if (_sd_ioset &&
	    (_sd_ioset->set_nlive || _sd_ioset->set_nthread)) {
		cmn_err(CE_WARN, "sdbc:_fini() %d threads still "
		    "active; %d threads in set\n", _sd_ioset->set_nlive,
		    _sd_ioset->set_nthread);
		return (EBUSY);
	}
	if ((err = mod_remove(&sdbc_modlinkage)) == 0) {
		DTRACE_PROBE2(_sdbc_fini_mod_remove_succeeded,
		    int, err,
		    struct modlinkage *, &sdbc_modlinkage);
		err = sdbcunload();
#ifdef USES_SOFT_STATE
		ddi_soft_state_fini(&sdbc_statep);
#endif /* USES_SOFT_STATE */

		if (mutex_and_condvar_flag) {
			cv_destroy(&dynmem_processing_dm.thread_dm_cv);
			mutex_destroy(&dynmem_processing_dm.thread_dm_lock);
			mutex_and_condvar_flag = 0;
		}
	}

	return (err);
}

/*
 * Solaris module info code
 */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&sdbc_modlinkage, modinfop));
}

/*ARGSUSED*/
static int
_sdbc_probe(dev_info_t *dip)
{
	return (DDI_PROBE_SUCCESS);
}

/*
 * Attach an instance of the device. This happens before an open
 * can succeed.
 */
static int
_sdbc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	_dm_process_vars_t local_dm_process_vars;
	struct buf bp;

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	/*
	 *  Get the threshold value for setting large writes in
	 *  write through mode(when NVRAM is present)
	 */

	sdbc_wrthru_len =  ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "sdbc_wrthru_thresh", 64);

	/* Get sdbc_max_fbas from sdbc.conf */
	sdbc_max_fbas =  ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "sdbc_max_fbas",
	    _SD_MAX_FBAS);

	bp.b_bcount = (size_t)FBA_SIZE(sdbc_max_fbas);
	minphys(&bp); /* clamps value to maxphys */

	sdbc_max_fbas = FBA_NUM(bp.b_bcount);

	if (sdbc_max_fbas > _SD_MAX_FBAS) {
		cmn_err(CE_WARN,
		    "_sdbc_attach: sdbc_max_fbas set to %d", _SD_MAX_FBAS);
		sdbc_max_fbas = _SD_MAX_FBAS;
	}

	/*
	 * -get the maximum list length for multipage dynmem
	 * -time between aging
	 * -number of agings before dealloc
	 * -what to report D0=shutdown, D1=thread variables
	 */
	dynmem_processing_dm.max_dyn_list = MAX_DYN_LIST_DEFAULT;
	dynmem_processing_dm.monitor_dynmem_process =
	    MONITOR_DYNMEM_PROCESS_DEFAULT;
	dynmem_processing_dm.cache_aging_ct1 = CACHE_AGING_CT_DEFAULT;
	dynmem_processing_dm.cache_aging_ct2 = CACHE_AGING_CT_DEFAULT;
	dynmem_processing_dm.cache_aging_ct3 = CACHE_AGING_CT_DEFAULT;
	dynmem_processing_dm.cache_aging_sec1 = CACHE_AGING_SEC1_DEFAULT;
	dynmem_processing_dm.cache_aging_sec2 = CACHE_AGING_SEC2_DEFAULT;
	dynmem_processing_dm.cache_aging_sec3 = CACHE_AGING_SEC3_DEFAULT;
	dynmem_processing_dm.cache_aging_pcnt1 = CACHE_AGING_PCNT1_DEFAULT;
	dynmem_processing_dm.cache_aging_pcnt2 = CACHE_AGING_PCNT2_DEFAULT;
	dynmem_processing_dm.max_holds_pcnt = MAX_HOLDS_PCNT_DEFAULT;
	dynmem_processing_dm.process_directive = PROCESS_DIRECTIVE_DEFAULT;

	local_dm_process_vars.max_dyn_list = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dip, DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "sdbc_max_dyn_list",
	    MAX_DYN_LIST_DEFAULT);

	local_dm_process_vars.monitor_dynmem_process =
	    ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "sdbc_monitor_dynmem",
	    MONITOR_DYNMEM_PROCESS_DEFAULT);

	local_dm_process_vars.cache_aging_ct1 = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dip, DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "sdbc_cache_aging_ct1",
	    CACHE_AGING_CT_DEFAULT);

	local_dm_process_vars.cache_aging_ct2 = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dip, DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "sdbc_cache_aging_ct2",
	    CACHE_AGING_CT_DEFAULT);

	local_dm_process_vars.cache_aging_ct3 = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dip, DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "sdbc_cache_aging_ct3",
	    CACHE_AGING_CT_DEFAULT);

	local_dm_process_vars.cache_aging_sec1 = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dip, DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "sdbc_cache_aging_sec1",
	    CACHE_AGING_SEC1_DEFAULT);

	local_dm_process_vars.cache_aging_sec2 = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dip, DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "sdbc_cache_aging_sec2",
	    CACHE_AGING_SEC2_DEFAULT);

	local_dm_process_vars.cache_aging_sec3 = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dip, DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "sdbc_cache_aging_sec3",
	    CACHE_AGING_SEC3_DEFAULT);

	local_dm_process_vars.cache_aging_pcnt1 =
	    ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "sdbc_cache_aging_pcnt1",
	    CACHE_AGING_PCNT1_DEFAULT);

	local_dm_process_vars.cache_aging_pcnt2 =
	    ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "sdbc_cache_aging_pcnt2",
	    CACHE_AGING_PCNT2_DEFAULT);

	local_dm_process_vars.process_directive =
	    ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "sdbc_process_directive",
	    PROCESS_DIRECTIVE_DEFAULT);

	local_dm_process_vars.max_holds_pcnt = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dip, DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "sdbc_max_holds_pcnt",
	    MAX_HOLDS_PCNT_DEFAULT);

	(void) sdbc_edit_xfer_process_vars_dm(&local_dm_process_vars);

#define	MINOR_NAME	"c,sdbc"		/* character device */
#define	MINOR_NUMBER	0
#ifdef MINOR_NAME
	if (ddi_create_minor_node(dip, MINOR_NAME, S_IFCHR,
		MINOR_NUMBER, DDI_PSEUDO, 0)
		    != DDI_SUCCESS) {
			/* free anything we allocated here */
			return (DDI_FAILURE);
		}
#endif /* MINOR_NAME */

	/* Announce presence of the device */
	ddi_report_dev(dip);
	dev_dip = dip;
	/* mark the device as attached, opens may proceed */
	_sdbc_attached = 1;

	rw_init(&sdbc_queue_lock, NULL, RW_DRIVER, NULL);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
_sdbc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd == DDI_DETACH) {
		/*
		 * Check first if the cache is still in use
		 * and if it is, prevent the detach.
		 */
		if (_sd_cache_initialized)
			return (EBUSY);

		_sdbc_attached = 0;

		rw_destroy(&sdbc_queue_lock);
		dev_dip = NULL;

		return (DDI_SUCCESS);
	} else
		return (DDI_FAILURE);
}

/*ARGSUSED*/
static int
_sdbc_reset(dev_info_t *dip, ddi_reset_cmd_t cmd)
{
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
_sdbc_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	dev_t dev;
#ifdef USES_SOFT_STATE
	struct sdbc_state *xsp;
	int instance;
#endif /* USES_SOFT_STATE */
	int rc;

	switch (cmd) {
		case DDI_INFO_DEVT2INSTANCE:
			dev = (dev_t)arg;
			/* The "instance" number is the minor number */
			*result = (void *)(unsigned long)getminor(dev);
			rc = DDI_SUCCESS;
			break;

		case DDI_INFO_DEVT2DEVINFO:
			dev = (dev_t)arg;
#ifdef USES_SOFT_STATE
			/* the instance number is the minor number */
			instance = getminor(dev);
			xsp = ddi_get_soft_state(sdbc_statep, instance);
			if (xsp == NULL)
				return (DDI_FAILURE);
			*result = (void *) xsp->dip;
#else
			*result = (void *) NULL;
#endif /* USES_SOFT_STATE */
			rc = DDI_SUCCESS;
			break;

		default:
			rc = DDI_FAILURE;
			break;
	}
	return (rc);
}

/*ARGSUSED*/
int
_sdbc_print(dev_t dev, char *s)
{
	cmn_err(CE_WARN, "sdbc(_sdbc_print) %s", s);
	return (0);
}
#else
MOD_DRV_WRAPPER(sdbc, sdbcload, sdbcunload, NULL, "Storage Device Block Cache");
#endif /* sun */

static int sdbc_inited;

static int
sdbcinit(void)
{
	int rc;

	sdbc_inited = 0;

	(void) strncpy(sdbc_version, _VERSION_, sizeof (sdbc_version));

	mutex_init(&_sd_cache_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&_sdbc_config_lock, NULL, MUTEX_DRIVER, NULL);

#ifdef m88k
	REGISTER_SVC(SD_DUAL_WRITE,	r_sd_ifs_write);
	REGISTER_SVC(SD_DUAL_READ,	r_sd_ifs_read);
	REGISTER_SVC(SD_SET_CD,		r_sd_set_cd);
	REGISTER_SVC(SD_GETSIZE,	r_sd_getsize);
	REGISTER_SVC(SD_DUAL_OPEN,	r_sd_ifs_open);
	REGISTER_SVC(SD_REMOTE_FLUSH,	r_sd_remote_flush);
	REGISTER_SVC(SD_SGREMOTE_FLUSH,	r_sd_sgremote_flush);
	REGISTER_SVC(SD_DISK_IO,	r_sd_disk_io);
	REGISTER_SVC(SD_GET_BMAP,	r_rem_get_bmap);

	if ((rc = hpf_register_module("SDBC", _sd_hpf_stats)) != 0)
		return (rc);
#endif
	REGISTER_SVC(SD_ENABLE,		r_sd_ifs_cache_enable);
	REGISTER_SVC(SD_DISABLE,	r_sd_ifs_cache_disable);
	REGISTER_SVC(SD_CD_DISCARD,	r_cd_discard);

	cv_init(&_sd_flush_cv, NULL, CV_DRIVER, NULL);

	mutex_init(&_sd_block_lk, NULL, MUTEX_DRIVER, NULL);

	sdbc_max_devs = nsc_max_devices();

	/*
	 * Initialize the bitmap array that would be useful in determining
	 * if the mask is not fragmented, instead of determinig this
	 * at run time. Also initialize a lookup array for each mask, with
	 * the starting position, the length, and the mask subset
	 */
	_sd_init_contig_bmap();
	_sd_init_lookup_map();

	if ((rc = _sdbc_iobuf_load()) != 0)
		return (rc);
	if ((rc = _sdbc_handles_load()) != 0)
		return (rc);
	if ((rc = _sdbc_tr_load()) != 0)
		return (rc);
	if ((rc = _sdbc_ft_load()) != 0)
		return (rc);
	if ((rc = _sdbc_tdaemon_load()) != 0)
		return (rc);
	if ((rc = _sdbc_hash_load()) != 0)
		return (rc);
#ifdef DEBUG
	_sdbc_ioj_load();
#endif
	sdbc_inited = 1;

	return (0);
}

static int
sdbcunload(void)
{
	if (_sd_cache_initialized) {
		cmn_err(CE_WARN,
		    "sdbc(sdbcunload) cannot unload module - cache in use!");
		return (EEXIST);
	}
#ifdef m88k
	UNREGISTER_SVC(SD_DUAL_WRITE);
	UNREGISTER_SVC(SD_DUAL_READ);
	UNREGISTER_SVC(SD_SET_CD);
	UNREGISTER_SVC(SD_GETSIZE);
	UNREGISTER_SVC(SD_DUAL_OPEN);
	UNREGISTER_SVC(SD_REMOTE_FLUSH);
	UNREGISTER_SVC(SD_SGREMOTE_FLUSH);
	UNREGISTER_SVC(SD_DISK_IO);
	UNREGISTER_SVC(SD_GET_BMAP);

	(void) hpf_unregister_module("SDBC");
#endif
	UNREGISTER_SVC(SD_ENABLE);
	UNREGISTER_SVC(SD_DISABLE);
	UNREGISTER_SVC(SD_CD_DISCARD);

	cv_destroy(&_sd_flush_cv);
	mutex_destroy(&_sd_block_lk);

	_sdbc_hash_unload();
	_sdbc_ft_unload();
	_sdbc_tr_unload();
	_sdbc_tdaemon_unload();
	_sdbc_handles_unload();
	_sdbc_iobuf_unload();
#ifdef DEBUG
	_sdbc_ioj_unload();
#endif

	mutex_destroy(&_sd_cache_lock);
	mutex_destroy(&_sdbc_config_lock);

	/*
	 * Normally we would unregister memory at deconfig time.
	 * However when chasing things like memory leaks it is
	 * useful to defer until unload time.
	 */
	if (_sdbc_memtype_deconfigure_delayed)
		_sdbc_memtype_deconfigure();

	return (0);
}


static int
sdbcload(void)
{
	int err;

	if ((err = sdbcinit()) != 0) {
		(void) sdbcunload();
		return (err);
	}
	return (0);
}


/* ARGSUSED */

static int
sdbcopen(dev_t *devp, int flag, int otyp, cred_t *crp)
{
	int nd = nsc_node_id();

	/*
	 * If we were statically linked in then returning an error out
	 * of sdbcinit won't prevent someone from coming thru here.
	 * We must prevent them from getting any further.
	 */
	if (!sdbc_inited)
		return (EINVAL);

	if (nd < nsc_min_nodeid) {
		cmn_err(CE_WARN,
		    "sdbc(sdbcopen) open failed, systemid (%d) must be >= %d",
		    nd, nsc_min_nodeid);
		return (EINVAL);
	}
	if (!_sdbc_attached)
		return (ENXIO);

	return (0);
}


/* ARGSUSED */

static int
sdbcclose(dev_t dev, int flag, int otyp, cred_t *crp)
{
	return (0);
}

#ifdef _MULTI_DATAMODEL
static int
convert_ioctl_args(int cmd, void *arg, int mode, _sdbc_ioctl_t *args)
/*
 * convert_ioctl-args - Do a case by case conversion of a ILP32 ioctl
 * structure to an LP64 structure.
 * The main concern here is whether to sign-extend or not. The rule
 * is that pointers are not sign extended, the rest are obvious.
 * Since most everything is sign-extended the definition of
 * _sdbc_ioctl32_t uses signed fields.
 *
 */
{
	_sdbc_ioctl32_t args32;

	if (ddi_copyin(arg, &args32, sizeof (_sdbc_ioctl32_t), mode))
		return (EFAULT);

	bzero((void *) args, sizeof (_sdbc_ioctl_t));

	switch (cmd) {

	case SDBC_UNUSED_1:
	case SDBC_UNUSED_2:
	case SDBC_UNUSED_3:
		args->sdbc_ustatus = (spcs_s_info_t)args32.sdbc_ustatus;
		cmn_err(CE_WARN,
		    "sdbc(convert_ioctl_args) obsolete sdbc ioctl used");
		return (EINVAL);

	case SDBC_ADUMP:
		args->arg0 = args32.arg0; /* cd */
		args->arg1 = (uint32_t)args32.arg1; /* &tt */
		args->arg2 = (uint32_t)args32.arg2; /* NULL (buf) */
		args->arg3 = args32.arg3; /*  size of buf */
		args->arg4 = args32.arg4; /* flag */
		args->sdbc_ustatus = (spcs_s_info_t)args32.sdbc_ustatus;
		break;

	case SDBC_TEST_INIT:
		args->arg0 = (uint32_t)args32.arg0; /* fname (char *) */
		args->arg1 = args32.arg1; /* index */
		args->arg2 = args32.arg2; /* len */
		args->arg3 = args32.arg3; /* track size */
		args->arg4 = args32.arg4; /* flag */
		break;

	case SDBC_TEST_START:
		args->arg0 = args32.arg0; /* num */
		args->arg1 = args32.arg1; /* type */
		args->arg2 = args32.arg2; /* loops */
		args->arg3 = args32.arg3; /* from */
		args->arg4 = args32.arg4; /* seed */
		break;

	case SDBC_TEST_END:
		break;

	case SDBC_ENABLE:
	case SDBC_VERSION:
		args->arg0 = (uint32_t)args32.arg0; /* pointer */
		args->sdbc_ustatus = (spcs_s_info_t)args32.sdbc_ustatus;
		break;

	case SDBC_DISABLE:
		args->sdbc_ustatus = (spcs_s_info_t)args32.sdbc_ustatus;
		break;

	case SDBC_GET_CLUSTER_SIZE:
		args->arg0 = (uint32_t)args32.arg0; /* (int * ) */
		args->sdbc_ustatus = (spcs_s_info_t)args32.sdbc_ustatus;
		break;

	/* get the gl_file data */
	case SDBC_GET_CLUSTER_DATA:
		/* pointer to array[2*cluster_size] */
		args->arg0 = (uint32_t)args32.arg0;
		args->sdbc_ustatus = (spcs_s_info_t)args32.sdbc_ustatus;
		break;

	/*  get the size of the global info pages for each board */
	case SDBC_GET_GLMUL_SIZES:
		args->arg0 = (uint32_t)args32.arg0; /* int[CACHE_MEM_PAD] * */
		args->sdbc_ustatus = (spcs_s_info_t)args32.sdbc_ustatus;
		break;

	/* get the global info about write blocks */
	case SDBC_GET_GLMUL_INFO:
		/* pointer to array[2*(sum of GLMUL_SIZES)] */
		args->arg0 = (uint32_t)args32.arg0;
		args->sdbc_ustatus = (spcs_s_info_t)args32.sdbc_ustatus;
		break;

	case SDBC_SET_CD_HINT:
		args->arg0 = args32.arg0; /* cd */
		args->arg1 = args32.arg1; /* hint */
		args->arg2 = args32.arg2; /* flag */
		args->sdbc_ustatus = (spcs_s_info_t)args32.sdbc_ustatus;
		break;

	case SDBC_GET_CD_HINT:
		args->arg0 = args32.arg0;
		args->sdbc_ustatus = (spcs_s_info_t)args32.sdbc_ustatus;
		break;

	case SDBC_SET_NODE_HINT:
		args->arg0 = args32.arg0; /* hint */
		args->arg1 = args32.arg1; /* flag */
		args->sdbc_ustatus = (spcs_s_info_t)args32.sdbc_ustatus;
		break;

	case SDBC_GET_NODE_HINT:
		args->sdbc_ustatus = (spcs_s_info_t)args32.sdbc_ustatus;
		break;

	case SDBC_STATS:
		args->arg0 = (uint32_t)args32.arg0; /* (_sd_stats_t *) */
		args->sdbc_ustatus = (spcs_s_info_t)args32.sdbc_ustatus;
		break;

	case SDBC_ZAP_STATS:
		args->sdbc_ustatus = (spcs_s_info_t)args32.sdbc_ustatus;
		break;

	case SDBC_GET_CD_BLK:
		args->arg0 = args32.arg0; /* cd */
		args->arg1 = (uint32_t)args32.arg1; /* blk */
		args->arg2 = (uint32_t)args32.arg2; /* (addr[5] *) */
		break;

	case SDBC_GET_CONFIG:
		args->arg0 = (uint32_t)args32.arg0; /* (_sdbc_config_t *) */
		args->sdbc_ustatus = (spcs_s_info_t)args32.sdbc_ustatus;
		break;

	case SDBC_SET_CONFIG:
		args->arg0 = (uint32_t)args32.arg0; /* (_sdbc_config_t *) */
		args->sdbc_ustatus = (spcs_s_info_t)args32.sdbc_ustatus;
		break;

	case SDBC_MAXFILES:
		args->arg0 = (uint32_t)args32.arg0; /* (int * ) */
		args->sdbc_ustatus = (spcs_s_info_t)args32.sdbc_ustatus;
		break;

#ifdef DEBUG
	/* toggle flusher flag for testing */
	case SDBC_TOGGLE_FLUSH:
		args->sdbc_ustatus = (spcs_s_info_t)args32.sdbc_ustatus;
		break;

	case SDBC_INJ_IOERR: /* cd, errnum */
		args->arg0 = args32.arg0; /* cd */
		args->arg1 = args32.arg1; /* i/o error number */
		args->arg2 = args32.arg2; /* countdown to issuing error */
		break;

	/* clear injected i/o errors */
	case SDBC_CLR_IOERR: /* cd */
		args->arg0 = args32.arg0; /* cd */
		break;
#endif /* DEBUG */
	default:
		return (EINVAL);
	}

	return (0);
}
#endif /* _MULTI_DATAMODEL */

static int
sdbc_get_cd_blk(_sdbc_ioctl_t *args, int mode)
{

	_sd_cctl_t *cc_ent;
	caddr_t data;
	char *taddr;
	intptr_t addr[5];
#ifdef _MULTI_DATAMODEL
	uint32_t addr_32[5];
#endif /* _MULTI_DATAMODEL */
	char *lookup_file = NULL;
	int rc;
	sdbc_info_t info;
	nsc_off_t fba_pos;	/* disk block number */

	if (_sd_cache_initialized == 0) {
		return (EINVAL);
	}

	/* copyin the block number */
	if (ddi_copyin((void *)args->arg1, &fba_pos, sizeof (nsc_off_t),
	    mode)) {
		return (EFAULT);
	}

#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		if (ddi_copyin((void *)args->arg2, addr_32, sizeof (addr_32),
		    mode)) {
			return (EFAULT);
		}
		addr[0] = addr_32[0]; /* (sdbc_info_t *) */
		addr[1] = addr_32[1]; /* (char *) cdata */
		addr[2] = addr_32[2]; /* ( int * ) cblk_size */
		addr[3] = addr_32[3]; /* ( char * ) filename */
		addr[4] = addr_32[4]; /* ( char *) wdata */
	} else {
		if (ddi_copyin((void *)args->arg2, addr, sizeof (addr), mode)) {
			return (EFAULT);
		}
	}
#else /* _MULTI_DATAMODEL */
	if (ddi_copyin((void *)args->arg2, addr, sizeof (addr), mode)) {
		return (EFAULT);
	}
#endif /* _MULTI_DATAMODEL */

	(void) copyout(&CACHE_BLOCK_SIZE, (void *)addr[2], sizeof (int));

	if (_sd_get_cd_blk((int)args->arg0, FBA_TO_BLK_NUM(fba_pos),
	    &cc_ent, &data, &lookup_file)) {
		if (lookup_file != NULL)
			(void) copyout(lookup_file, (void *)addr[3],
			    NSC_MAXPATH);
		return (ENOENT);
	}
	rc = 0;
	taddr = NULL;

	info.ci_write = cc_ent->cc_write ? 1 : 0;
	info.ci_dirty = cc_ent->cc_dirty;
	info.ci_valid = cc_ent->cc_valid;
	info.ci_cd = CENTRY_CD(cc_ent);
	info.ci_dblk = BLK_TO_FBA_NUM(CENTRY_BLK(cc_ent));
	(void) copyout(lookup_file, (void *)addr[3], NSC_MAXPATH);
	(void) copyout(&info, (void *)addr[0], sizeof (sdbc_info_t));

	(void) copyout(data, (void *)addr[1], CACHE_BLOCK_SIZE);

	/* get the write data if any */
	if (cc_ent->cc_write) {

		if (sdbc_safestore) {
			cmn_err(CE_WARN,
			    "sdbc(sdbc_get_cd_blk) cc_write 0x%p sc-res 0x%p",
			    (void *)cc_ent->cc_write,
			    (void *)cc_ent->cc_write->sc_res);

			if ((taddr = kmem_alloc(CACHE_BLOCK_SIZE,
			    KM_NOSLEEP)) == NULL) {
				cmn_err(CE_WARN,
				    "sdbc(sdbc_get_cd_blk) kmem_alloc failed."
				    " cannot get write data");
				info.ci_write = NULL;
				rc = EFAULT;
			} else if (SSOP_READ_CBLOCK(sdbc_safestore,
			    cc_ent->cc_write->sc_res, taddr,
			    CACHE_BLOCK_SIZE, 0) == SS_ERR) {

				cmn_err(CE_WARN, "sdbc(sdbc_get_cd_blk) "
				    "safestore read failed");
				rc = EFAULT;

			} else if (copyout(taddr, (void *)addr[4],
			    CACHE_BLOCK_SIZE)) {
				cmn_err(CE_WARN,
				    "sdbc(sdbc_get_cd_blk) copyout failed."
				    " cannot get write data");
				rc = EFAULT;
			}
		}

	}

	if (taddr)
		kmem_free(taddr, CACHE_BLOCK_SIZE);

	return (rc);
}

/* ARGSUSED */
static int
sdbcioctl(dev_t dev, int cmd, void *arg, int mode, cred_t *crp, int *rvp)
{
	int rc = 0;
	_sdbc_ioctl_t args;
	int convert_32 = 0;
	spcs_s_info_t kstatus;

	*rvp = 0;

#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		int rc;
		convert_32 = 1;
		if ((rc = convert_ioctl_args(cmd, arg, mode, &args)) != 0)
			return (rc);
	} else {
		if (ddi_copyin(arg, &args, sizeof (_sdbc_ioctl_t), mode)) {
			return (EFAULT);
		}
	}
#else /* _MULTI_DATAMODEL */
	if (ddi_copyin(arg, &args, sizeof (_sdbc_ioctl_t), mode)) {
		return (EFAULT);
	}
#endif /* _MULTI_DATAMODEL */

	kstatus = spcs_s_kcreate();
	if (!kstatus)
		return (ENOMEM);

	switch (cmd) {

	case SDBC_UNUSED_1:
	case SDBC_UNUSED_2:
	case SDBC_UNUSED_3:

		return (spcs_s_ocopyoutf(&kstatus, args.sdbc_ustatus,
		    SDBC_EOBSOLETE));

	case SDBC_ADUMP:
		rc = _sd_adump(&args, rvp);
		break;

	case SDBC_TEST_INIT:
		rc = _sd_test_init(&args);
		break;

	case SDBC_TEST_START:
		rc = _sd_test_start(&args, rvp);
		break;

	case SDBC_TEST_END:
		rc = _sd_test_end();
		break;

	case SDBC_ENABLE:
		mutex_enter(&_sdbc_config_lock);
		rc = _sdbc_configure((_sd_cache_param_t *)args.arg0,
			NULL, kstatus);
		if (rc && rc != EALREADY && rc != SDBC_ENONETMEM) {
			(void) _sdbc_deconfigure(kstatus);
			mutex_exit(&_sdbc_config_lock);
			return (spcs_s_ocopyoutf(&kstatus,
				args.sdbc_ustatus, rc));
		}
		mutex_exit(&_sdbc_config_lock);
		return (spcs_s_ocopyoutf(&kstatus, args.sdbc_ustatus, rc));

	case SDBC_DISABLE:
		mutex_enter(&_sdbc_config_lock);
		if (_sd_cache_initialized == 0) {

			mutex_exit(&_sdbc_config_lock);
			return (spcs_s_ocopyoutf(&kstatus, args.sdbc_ustatus,
			    SDBC_EDISABLE));
		}
		rc = _sdbc_deconfigure(kstatus);
		mutex_exit(&_sdbc_config_lock);
		return (spcs_s_ocopyoutf(&kstatus, args.sdbc_ustatus, rc));

	case SDBC_GET_CLUSTER_SIZE:
		if (_sd_cache_initialized == 0) {

			return (spcs_s_ocopyoutf(&kstatus, args.sdbc_ustatus,
			    SDBC_ECLUSTER_SIZE));
		}

		rc = sd_get_file_info_size((void *)args.arg0);
		break;

	/* get the gl_file data */
	case SDBC_GET_CLUSTER_DATA:
		if (_sd_cache_initialized == 0) {

			return (spcs_s_ocopyoutf(&kstatus, args.sdbc_ustatus,
			    SDBC_ECLUSTER_DATA));
		}
		rc = sd_get_file_info_data((void *)args.arg0);
		break;

	/*  get the size of the global info pages for each board */
	case SDBC_GET_GLMUL_SIZES:
		if (_sd_cache_initialized == 0) {
			return (spcs_s_ocopyoutf(&kstatus, args.sdbc_ustatus,
			    SDBC_EGLMUL_SIZE));
		}
		rc = sd_get_glmul_sizes((void *)args.arg0);
		break;

	/* get the global info about write blocks */
	case SDBC_GET_GLMUL_INFO:
		if (_sd_cache_initialized == 0) {

			return (spcs_s_ocopyoutf(&kstatus, args.sdbc_ustatus,
			    SDBC_EGLMUL_INFO));

		}
		rc = sd_get_glmul_info((void *)args.arg0);
		break;

	case SDBC_SET_CD_HINT:
		if (_sd_cache_initialized == 0)
			return (spcs_s_ocopyoutf(&kstatus,
			    args.sdbc_ustatus, EINVAL));
		rc = ((args.arg2) ?
		    _sd_set_hint((int)args.arg0, (uint_t)args.arg1) :
		    _sd_clear_hint((int)args.arg0, (uint_t)args.arg1));
		return (spcs_s_ocopyoutf(&kstatus, args.sdbc_ustatus, rc));

	case SDBC_GET_CD_HINT:
		{
			uint_t hint;

			if (_sd_cache_initialized == 0)
				return (spcs_s_ocopyoutf(&kstatus,
				    args.sdbc_ustatus, EINVAL));
			if ((rc = _sd_get_cd_hint((int)args.arg0, &hint)) == 0)
				*rvp = hint;
			return (spcs_s_ocopyoutf(&kstatus, args.sdbc_ustatus,
			    rc));
		}

	case SDBC_SET_NODE_HINT:
		rc = ((args.arg1) ? _sd_set_node_hint((uint_t)args.arg0) :
		    _sd_clear_node_hint((uint_t)args.arg0));
		if (rc)
			return (spcs_s_ocopyoutf(&kstatus, args.sdbc_ustatus,
			    rc));
		/* FALLTHRU */
	case SDBC_GET_NODE_HINT:
		{
			uint_t hint;
			if ((rc = _sd_get_node_hint(&hint)) == 0)
				*rvp = hint;
			return (spcs_s_ocopyoutf(&kstatus, args.sdbc_ustatus,
			    rc));
		}

	case SDBC_STATS:
		rc = _sd_get_stats((void *)args.arg0, convert_32);
		return (spcs_s_ocopyoutf(&kstatus, args.sdbc_ustatus, rc));

	case SDBC_ZAP_STATS:
		_sd_zap_stats();
		return (spcs_s_ocopyoutf(&kstatus, args.sdbc_ustatus, 0));

	case SDBC_GET_CD_BLK:
		if (_sd_cache_initialized == 0)
			return (spcs_s_ocopyoutf(&kstatus,
			    args.sdbc_ustatus, EINVAL));
		rc = sdbc_get_cd_blk(&args, mode);
		break;

	case SDBC_GET_CONFIG:
		{
		_sdbc_config_t sdbc_config_info;

		if (ddi_copyin((void *)args.arg0,
		    &sdbc_config_info,
		    sizeof (_sdbc_config_t),
		    mode)) {
			spcs_s_kfree(kstatus);
			return (EFAULT);
		}
		rc = _sdbc_get_config(&sdbc_config_info);
		(void) ddi_copyout(&sdbc_config_info,
		    (void *)args.arg0,
		    sizeof (_sdbc_config_t),
		    mode);
		return (spcs_s_ocopyoutf(&kstatus, args.sdbc_ustatus, rc));
		}

	case SDBC_SET_CONFIG:
	{
		_sdbc_config_t mgmt_config_info;

		if (ddi_copyin((void *)args.arg0,
		    &mgmt_config_info,
		    sizeof (_sdbc_config_t),
		    mode)) {
			spcs_s_kfree(kstatus);
			return (EFAULT);
		}

		rc = _sdbc_configure(NULL, &mgmt_config_info, kstatus);
		if (rc && rc != EALREADY) {
			(void) _sdbc_deconfigure(kstatus);
			return (spcs_s_ocopyoutf(&kstatus,
				args.sdbc_ustatus, rc));
		}

		return (spcs_s_ocopyoutf(&kstatus, args.sdbc_ustatus, rc));
	}

	case SDBC_MAXFILES:
		if (copyout(&sdbc_max_devs, (void *)args.arg0,
		    sizeof (sdbc_max_devs)))
			rc = EFAULT;
		else
			rc = 0;

		break;

	case SDBC_VERSION:
	{
		cache_version_t cache_version;

		cache_version.major = sdbc_major_rev;
		cache_version.minor = sdbc_minor_rev;
		cache_version.micro = sdbc_micro_rev;
		cache_version.baseline = sdbc_baseline_rev;

		if (ddi_copyout(&cache_version, (void *)args.arg0,
			sizeof (cache_version_t), mode)) {
			rc = EFAULT;
			break;
		}

		break;
	}


#ifdef DEBUG
	/* toggle flusher flag for testing */
	case SDBC_TOGGLE_FLUSH:
		_sdbc_flush_flag ^= 1;
		*rvp = _sdbc_flush_flag;
		rc = 0;

		return (spcs_s_ocopyoutf(&kstatus, args.sdbc_ustatus,
		    SDBC_ETOGGLE_FLUSH, _sdbc_flush_flag ? "on" : "off"));


	/* inject i/o errors */
	case SDBC_INJ_IOERR: /* cd, errnum */
		if (_sd_cache_initialized == 0)
			return (spcs_s_ocopyoutf(&kstatus,
			    args.sdbc_ustatus, EINVAL));
		rc = _sdbc_inject_ioerr(args.arg0, args.arg1, args.arg2);
		break;

	/* clear injected i/o errors */
	case SDBC_CLR_IOERR: /* cd */
		if (_sd_cache_initialized == 0)
			return (spcs_s_ocopyoutf(&kstatus,
			    args.sdbc_ustatus, EINVAL));
		rc = _sdbc_clear_ioerr(args.arg0);
		break;

#endif /* DEBUG */
	default:
		_sd_print(3, "SDBC unknown ioctl: 0x%x unsupported", cmd);
		rc = EINVAL;
		break;
	}

	spcs_s_kfree(kstatus);
	return (rc);
}


/*
 * _sd_timed_block - sleep waiting for ticks time delay.
 * ticks - # of ticks to sleep
 * cvp - pointer to the cv we wait on while we delay.
 *
 * NO spin locks can be held at entry!
 *
 */
void
_sd_timed_block(clock_t ticks, kcondvar_t *cvp)
{
	clock_t ticker;

	if (drv_getparm(LBOLT, &ticker) != 0)
		cmn_err(CE_WARN, "_sd_timed_block:failed to get current time");

	mutex_enter(&_sd_block_lk);
	(void) cv_timedwait(cvp, &_sd_block_lk, ticks + ticker);
	mutex_exit(&_sd_block_lk);

}


/*
 * _sd_unblock - awake a sleeper waiting on cv pointed to by cvp.
 *
 * NO spin locks can be held at entry as we may sleep.
 *
 */
void
_sd_unblock(kcondvar_t *cvp)
{

	mutex_enter(&_sd_block_lk);
	cv_broadcast(cvp);
	mutex_exit(&_sd_block_lk);
}

/* ARGSUSED */
void
_sd_data_log(int num, _sd_cctl_t *centry, nsc_off_t st, nsc_size_t len)
{
#if defined(_SD_FBA_DATA_LOG)
	nsc_size_t i;
	nsc_off_t blk;

	blk = BLK_TO_FBA_NUM(CENTRY_BLK(centry));
	for (i = st; i < (st + len); i++)
		SDTRACE(num, CENTRY_CD(centry), 1, blk + i,
			*(int *)(centry->cc_data + FBA_SIZE(i)),
			*(int *)(centry->cc_data + FBA_SIZE(i) + 4));
#endif /* _SD_FBA_DATA_LOG */
}

/* ARGSUSED */
void
_sd_data_log_chain(int num, _sd_cctl_t *centry, nsc_off_t fba_pos,
    nsc_size_t fba_len)
{
#if defined(_SD_FBA_DATA_LOG)
	sdbc_cblk_fba_t st_cblk_len;	/* FBA len of starting cache block */
	sdbc_cblk_fba_t end_cblk_len;	/* FBA len of ending cache block */
	sdbc_cblk_fba_t st_cblk_off;	/* FBA offset into starting cblock */

	while (CENTRY_BLK(centry) != FBA_TO_BLK_NUM(fba_pos))
		centry = centry->cc_chain;

	st_cblk_off = BLK_FBA_OFF(fba_pos);
	st_cblk_len = BLK_FBAS - st_cblk_off;
	if (st_cblk_len >= fba_len) {
		end_cblk_len = 0;
		st_cblk_len = fba_len;
	} else {
		end_cblk_len = BLK_FBA_OFF(fba_pos + fba_len);
	}

	DATA_LOG(num, centry, st_cblk_off, st_cblk_len);

	fba_len -= st_cblk_len;
	centry = centry->cc_chain;

	while (fba_len > end_cblk_len) {
		DATA_LOG(num, centry, 0, BLK_FBAS);
		fba_len -= BLK_FBAS;
		centry = centry->cc_chain;
	}
	if (end_cblk_len) DATA_LOG(num, centry, 0, end_cblk_len);
#endif /* _SD_FBA_DATA_LOG */
}


void
_sd_zap_stats(void)
{
	int i;

	if (_sd_cache_stats == NULL)
		return;

	_sd_cache_stats->st_rdhits = 0;
	_sd_cache_stats->st_rdmiss = 0;
	_sd_cache_stats->st_wrhits = 0;
	_sd_cache_stats->st_wrmiss = 0;
	_sd_lru_q.sq_noreq_stat = 0;
	_sd_lru_q.sq_req_stat = 0;

	for (i = 0; i < sdbc_max_devs; i++) {
		_sd_cache_stats->st_shared[i].sh_cache_read  = 0;
		_sd_cache_stats->st_shared[i].sh_cache_write = 0;
		_sd_cache_stats->st_shared[i].sh_disk_read   = 0;
		_sd_cache_stats->st_shared[i].sh_disk_write  = 0;
	}
}


/*
 * Return the cache sizes used by the Sense Subsystem Status CCW
 */
int
_sd_cache_sizes(int *asize, int *wsize)
{
	int	psize;

	*asize = 0;
	*wsize = 0;

	/*
	 * add in the total cache size and the
	 * non-volatile (battery-backed) cache size.
	 */
	if (_sd_net_config.sn_configured) {
		psize = _sd_net_config.sn_psize;
		*asize += (_sd_net_config.sn_cpages * psize);
		*wsize += (safestore_config.ssc_wsize);
	}

	return (0);
}


/*PRINTFLIKE2*/
void
_sd_print(int level, char *fmt, ...)
{
	va_list adx;
	if (level <= _sd_debug_level) {
		va_start(adx, fmt);
		vcmn_err(CE_NOTE, fmt, adx);
		va_end(adx);

	}
}


int
_sd_get_cd_blk(int cd, nsc_off_t cblk, _sd_cctl_t **cc, caddr_t *data,
    char **filename)
{
	_sd_cctl_t *cc_ent;

	if (FILE_OPENED(cd) != 0) {
		*filename = _sd_cache_files[cd].cd_info->sh_filename;
		if (cc_ent = (_sd_cctl_t *)
		    _sd_hash_search(cd, cblk, _sd_htable)) {
			*cc = cc_ent;
			*data = (caddr_t)cc_ent->cc_data;
			return (0);
		}
	}
	return (-1);
}

/*
 * central dyn mem processing vars edit rtn.
 * input a local copy and xfer to global
 *
 * sec0,sec1,sec2
 * range check 1 to 255 (arbitrary but in any case must be <= 2000 due to
 *	32bit signed int limits in later calc)
 * aging_ct
 * range check 1 to 255 (only 8 bits reserved for aging ctr)
 *
 */
int
sdbc_edit_xfer_process_vars_dm(_dm_process_vars_t *process_vars)
{
	if (process_vars->max_dyn_list > 0)
		dynmem_processing_dm.max_dyn_list = process_vars->max_dyn_list;

	/* no edit on monitor_dynmem_process */
	dynmem_processing_dm.monitor_dynmem_process =
	    process_vars->monitor_dynmem_process;
	/* no edit on process_directive */
	dynmem_processing_dm.process_directive =
	    process_vars->process_directive;

	if (process_vars->cache_aging_ct1 > 0 &&
	    process_vars->cache_aging_ct1 <= CACHE_AGING_CT_MAX)
		dynmem_processing_dm.cache_aging_ct1 =
		    process_vars->cache_aging_ct1;
	if (process_vars->cache_aging_ct2 > 0 &&
	    process_vars->cache_aging_ct2 <= CACHE_AGING_CT_MAX)
		dynmem_processing_dm.cache_aging_ct2 =
		    process_vars->cache_aging_ct2;
	if (process_vars->cache_aging_ct3 > 0 &&
	    process_vars->cache_aging_ct3 <= CACHE_AGING_CT_MAX)
		dynmem_processing_dm.cache_aging_ct3 =
		    process_vars->cache_aging_ct3;
	if (process_vars->cache_aging_sec1 > 0 &&
	    process_vars->cache_aging_sec1 <= CACHE_AGING_SEC1_MAX)
		dynmem_processing_dm.cache_aging_sec1 =
		    process_vars->cache_aging_sec1;
	if (process_vars->cache_aging_sec2 > 0 &&
	    process_vars->cache_aging_sec2 <= CACHE_AGING_SEC2_MAX)
		dynmem_processing_dm.cache_aging_sec2 =
		    process_vars->cache_aging_sec2;
	if (process_vars->cache_aging_sec3 > 0 &&
	    process_vars->cache_aging_sec3 <= CACHE_AGING_SEC3_MAX)
		dynmem_processing_dm.cache_aging_sec3 =
		    process_vars->cache_aging_sec3;
	if (process_vars->cache_aging_pcnt1 >= 0 &&
	    process_vars->cache_aging_pcnt1 <= CACHE_AGING_PCNT1_MAX)
		dynmem_processing_dm.cache_aging_pcnt1 =
		    process_vars->cache_aging_pcnt1;
	if (process_vars->cache_aging_pcnt2 >= 0 &&
	    process_vars->cache_aging_pcnt2 <= CACHE_AGING_PCNT2_MAX)
		dynmem_processing_dm.cache_aging_pcnt2 =
		    process_vars->cache_aging_pcnt2;
	if (process_vars->max_holds_pcnt >= 0 &&
	    process_vars->max_holds_pcnt <= MAX_HOLDS_PCNT_MAX)
		dynmem_processing_dm.max_holds_pcnt =
		    process_vars->max_holds_pcnt;
	return (0);
}

dev_info_t *
sdbc_get_dip()
{
	return (dev_dip);
}
