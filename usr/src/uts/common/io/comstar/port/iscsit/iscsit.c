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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright 2013 Nexenta Systems, Inc. All rights reserved.
 */

#include <sys/cpuvar.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/sysmacros.h>
#include <sys/socket.h>
#include <sys/strsubr.h>
#include <sys/nvpair.h>

#include <sys/stmf.h>
#include <sys/stmf_ioctl.h>
#include <sys/portif.h>
#include <sys/idm/idm.h>
#include <sys/idm/idm_conn_sm.h>

#include "iscsit_isns.h"
#include "iscsit.h"

#define	ISCSIT_VERSION		BUILD_DATE "-1.18dev"
#define	ISCSIT_NAME_VERSION	"COMSTAR ISCSIT v" ISCSIT_VERSION

/*
 * DDI entry points.
 */
static int iscsit_drv_attach(dev_info_t *, ddi_attach_cmd_t);
static int iscsit_drv_detach(dev_info_t *, ddi_detach_cmd_t);
static int iscsit_drv_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int iscsit_drv_open(dev_t *, int, int, cred_t *);
static int iscsit_drv_close(dev_t, int, int, cred_t *);
static boolean_t iscsit_drv_busy(void);
static int iscsit_drv_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

extern struct mod_ops mod_miscops;


static struct cb_ops iscsit_cb_ops = {
	iscsit_drv_open,	/* cb_open */
	iscsit_drv_close,	/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	iscsit_drv_ioctl,	/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* cb_streamtab */
	D_MP,			/* cb_flag */
	CB_REV,			/* cb_rev */
	nodev,			/* cb_aread */
	nodev,			/* cb_awrite */
};

static struct dev_ops iscsit_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	iscsit_drv_getinfo,	/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	iscsit_drv_attach,	/* devo_attach */
	iscsit_drv_detach,	/* devo_detach */
	nodev,			/* devo_reset */
	&iscsit_cb_ops,		/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	NULL,			/* devo_power */
	ddi_quiesce_not_needed,	/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,
	"iSCSI Target",
	&iscsit_dev_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL,
};


iscsit_global_t iscsit_global;

kmem_cache_t	*iscsit_status_pdu_cache;

boolean_t	iscsit_sm_logging = B_FALSE;

kmutex_t	login_sm_session_mutex;

static idm_status_t iscsit_init(dev_info_t *dip);
static idm_status_t iscsit_enable_svc(iscsit_hostinfo_t *hostinfo);
static void iscsit_disable_svc(void);

static int
iscsit_check_cmdsn_and_queue(idm_pdu_t *rx_pdu);

static void
iscsit_add_pdu_to_queue(iscsit_sess_t *ist, idm_pdu_t *rx_pdu);

static idm_pdu_t *
iscsit_remove_pdu_from_queue(iscsit_sess_t *ist, uint32_t cmdsn);

static void
iscsit_process_pdu_in_queue(iscsit_sess_t *ist);

static void
iscsit_rxpdu_queue_monitor_session(iscsit_sess_t *ist);

static void
iscsit_rxpdu_queue_monitor(void *arg);

static void
iscsit_post_staged_pdu(idm_pdu_t *rx_pdu);

static void
iscsit_post_scsi_cmd(idm_conn_t *ic, idm_pdu_t *rx_pdu);

static void
iscsit_op_scsi_task_mgmt(iscsit_conn_t *ict, idm_pdu_t *rx_pdu);

static void
iscsit_pdu_op_noop(iscsit_conn_t *ict, idm_pdu_t *rx_pdu);

static void
iscsit_pdu_op_login_cmd(iscsit_conn_t *ict, idm_pdu_t *rx_pdu);

void
iscsit_pdu_op_text_cmd(iscsit_conn_t *ict, idm_pdu_t *rx_pdu);

static void
iscsit_pdu_op_logout_cmd(iscsit_conn_t *ict, idm_pdu_t *rx_pdu);

int iscsit_cmd_window();

static  int
iscsit_sna_lt(uint32_t sn1, uint32_t sn2);

void
iscsit_set_cmdsn(iscsit_conn_t *ict, idm_pdu_t *rx_pdu);

static void
iscsit_deferred_dispatch(idm_pdu_t *rx_pdu);

static void
iscsit_deferred(void *rx_pdu_void);

static idm_status_t
iscsit_conn_accept(idm_conn_t *ic);

static idm_status_t
iscsit_ffp_enabled(idm_conn_t *ic);

static idm_status_t
iscsit_ffp_disabled(idm_conn_t *ic, idm_ffp_disable_t disable_class);

static idm_status_t
iscsit_conn_lost(idm_conn_t *ic);

static idm_status_t
iscsit_conn_destroy(idm_conn_t *ic);

static stmf_data_buf_t *
iscsit_dbuf_alloc(scsi_task_t *task, uint32_t size, uint32_t *pminsize,
    uint32_t flags);

static void
iscsit_dbuf_free(stmf_dbuf_store_t *ds, stmf_data_buf_t *dbuf);

static void
iscsit_buf_xfer_cb(idm_buf_t *idb, idm_status_t status);

static void
iscsit_send_good_status_done(idm_pdu_t *pdu, idm_status_t status);

static void
iscsit_send_status_done(idm_pdu_t *pdu, idm_status_t status);

static stmf_status_t
iscsit_idm_to_stmf(idm_status_t idmrc);

static iscsit_task_t *
iscsit_task_alloc(iscsit_conn_t *ict);

static void
iscsit_task_free(iscsit_task_t *itask);

static iscsit_task_t *
iscsit_tm_task_alloc(iscsit_conn_t *ict);

static void
iscsit_tm_task_free(iscsit_task_t *itask);

static idm_status_t
iscsit_task_start(iscsit_task_t *itask);

static void
iscsit_task_done(iscsit_task_t *itask);

static int
iscsit_status_pdu_constructor(void *pdu_void, void *arg, int flags);

static void
iscsit_pp_cb(struct stmf_port_provider *pp, int cmd, void *arg, uint32_t flags);

static it_cfg_status_t
iscsit_config_merge(it_config_t *cfg);

static idm_status_t
iscsit_login_fail(idm_conn_t *ic);

static boolean_t iscsit_cmdsn_in_window(iscsit_conn_t *ict, uint32_t cmdsn);
static void iscsit_send_direct_scsi_resp(iscsit_conn_t *ict, idm_pdu_t *rx_pdu,
    uint8_t response, uint8_t cmd_status);
static void iscsit_send_task_mgmt_resp(idm_pdu_t *tm_resp_pdu,
    uint8_t tm_status);

/*
 * MC/S: Out-of-order commands are staged on a session-wide wait
 * queue until a system-tunable threshold is reached. A separate
 * thread is used to scan the staging queue on all the session,
 * If a delayed PDU does not arrive within a timeout, the target
 * will advance to the staged PDU that is next in sequence, skipping
 * over the missing PDU(s) to go past a hole in the sequence.
 */
volatile int rxpdu_queue_threshold = ISCSIT_RXPDU_QUEUE_THRESHOLD;

static kmutex_t		iscsit_rxpdu_queue_monitor_mutex;
kthread_t		*iscsit_rxpdu_queue_monitor_thr_id;
static kt_did_t		iscsit_rxpdu_queue_monitor_thr_did;
static boolean_t	iscsit_rxpdu_queue_monitor_thr_running;
static kcondvar_t	iscsit_rxpdu_queue_monitor_cv;

int
_init(void)
{
	int rc;

	rw_init(&iscsit_global.global_rwlock, NULL, RW_DRIVER, NULL);
	mutex_init(&iscsit_global.global_state_mutex, NULL,
	    MUTEX_DRIVER, NULL);
	iscsit_global.global_svc_state = ISE_DETACHED;

	mutex_init(&iscsit_rxpdu_queue_monitor_mutex, NULL,
	    MUTEX_DRIVER, NULL);
	mutex_init(&login_sm_session_mutex, NULL, MUTEX_DRIVER, NULL);
	iscsit_rxpdu_queue_monitor_thr_id = NULL;
	iscsit_rxpdu_queue_monitor_thr_running = B_FALSE;
	cv_init(&iscsit_rxpdu_queue_monitor_cv, NULL, CV_DEFAULT, NULL);

	if ((rc = mod_install(&modlinkage)) != 0) {
		mutex_destroy(&iscsit_global.global_state_mutex);
		rw_destroy(&iscsit_global.global_rwlock);
		return (rc);
	}

	return (rc);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int rc;

	rc = mod_remove(&modlinkage);

	if (rc == 0) {
		mutex_destroy(&iscsit_rxpdu_queue_monitor_mutex);
		mutex_destroy(&login_sm_session_mutex);
		cv_destroy(&iscsit_rxpdu_queue_monitor_cv);
		mutex_destroy(&iscsit_global.global_state_mutex);
		rw_destroy(&iscsit_global.global_rwlock);
	}

	return (rc);
}

/*
 * DDI entry points.
 */

/* ARGSUSED */
static int
iscsit_drv_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
    void **result)
{
	ulong_t instance = getminor((dev_t)arg);

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = iscsit_global.global_dip;
		return (DDI_SUCCESS);

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)instance;
		return (DDI_SUCCESS);

	default:
		break;
	}

	return (DDI_FAILURE);
}

static int
iscsit_drv_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	if (ddi_get_instance(dip) != 0) {
		/* we only allow instance 0 to attach */
		return (DDI_FAILURE);
	}

	/* create the minor node */
	if (ddi_create_minor_node(dip, ISCSIT_MODNAME, S_IFCHR, 0,
	    DDI_PSEUDO, 0) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iscsit_drv_attach: "
		    "failed creating minor node");
		return (DDI_FAILURE);
	}

	if (iscsit_init(dip) != IDM_STATUS_SUCCESS) {
		cmn_err(CE_WARN, "iscsit_drv_attach: "
		    "failed to initialize");
		ddi_remove_minor_node(dip, NULL);
		return (DDI_FAILURE);
	}

	iscsit_global.global_svc_state = ISE_DISABLED;
	iscsit_global.global_dip = dip;

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
iscsit_drv_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	/*
	 * drv_detach is called in a context that owns the
	 * device node for the /dev/pseudo device.  If this thread blocks
	 * for any resource, other threads that need the /dev/pseudo device
	 * may end up in a deadlock with this thread.Hence, we use a
	 * separate lock just for the structures that drv_detach needs
	 * to access.
	 */
	mutex_enter(&iscsit_global.global_state_mutex);
	if (iscsit_drv_busy()) {
		mutex_exit(&iscsit_global.global_state_mutex);
		return (EBUSY);
	}

	iscsit_global.global_dip = NULL;
	ddi_remove_minor_node(dip, NULL);

	ldi_ident_release(iscsit_global.global_li);
	iscsit_global.global_svc_state = ISE_DETACHED;

	mutex_exit(&iscsit_global.global_state_mutex);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
iscsit_drv_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	return (0);
}

/* ARGSUSED */
static int
iscsit_drv_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	return (0);
}

static boolean_t
iscsit_drv_busy(void)
{
	ASSERT(MUTEX_HELD(&iscsit_global.global_state_mutex));

	switch (iscsit_global.global_svc_state) {
	case ISE_DISABLED:
	case ISE_DETACHED:
		return (B_FALSE);
	default:
		return (B_TRUE);
	}
	/* NOTREACHED */
}

/* ARGSUSED */
static int
iscsit_drv_ioctl(dev_t drv, int cmd, intptr_t argp, int flag, cred_t *cred,
    int *retval)
{
	iscsit_ioc_set_config_t		setcfg;
	iscsit_ioc_set_config32_t	setcfg32;
	char				*cfg_pnvlist = NULL;
	nvlist_t			*cfg_nvlist = NULL;
	it_config_t			*cfg = NULL;
	idm_status_t			idmrc;
	int				rc = 0;

	if (drv_priv(cred) != 0) {
		return (EPERM);
	}

	mutex_enter(&iscsit_global.global_state_mutex);

	/*
	 * Validate ioctl requests against global service state
	 */
	switch (iscsit_global.global_svc_state) {
	case ISE_ENABLED:
		if (cmd == ISCSIT_IOC_DISABLE_SVC) {
			iscsit_global.global_svc_state = ISE_DISABLING;
		} else if (cmd == ISCSIT_IOC_ENABLE_SVC) {
			/* Already enabled */
			mutex_exit(&iscsit_global.global_state_mutex);
			return (0);
		} else {
			iscsit_global.global_svc_state = ISE_BUSY;
		}
		break;
	case ISE_DISABLED:
		if (cmd == ISCSIT_IOC_ENABLE_SVC) {
			iscsit_global.global_svc_state = ISE_ENABLING;
		} else if (cmd == ISCSIT_IOC_DISABLE_SVC) {
			/* Already disabled */
			mutex_exit(&iscsit_global.global_state_mutex);
			return (0);
		} else {
			rc = EFAULT;
		}
		break;
	case ISE_BUSY:
	case ISE_ENABLING:
	case ISE_DISABLING:
		rc = EAGAIN;
		break;
	case ISE_DETACHED:
	default:
		rc = EFAULT;
		break;
	}

	mutex_exit(&iscsit_global.global_state_mutex);
	if (rc != 0)
		return (rc);

	/* Handle ioctl request (enable/disable have already been handled) */
	switch (cmd) {
	case ISCSIT_IOC_SET_CONFIG:
		/* Any errors must set state back to ISE_ENABLED */
		switch (ddi_model_convert_from(flag & FMODELS)) {
		case DDI_MODEL_ILP32:
			if (ddi_copyin((void *)argp, &setcfg32,
			    sizeof (iscsit_ioc_set_config32_t), flag) != 0) {
				rc = EFAULT;
				goto cleanup;
			}

			setcfg.set_cfg_pnvlist =
			    (char *)((uintptr_t)setcfg32.set_cfg_pnvlist);
			setcfg.set_cfg_vers = setcfg32.set_cfg_vers;
			setcfg.set_cfg_pnvlist_len =
			    setcfg32.set_cfg_pnvlist_len;
			break;
		case DDI_MODEL_NONE:
			if (ddi_copyin((void *)argp, &setcfg,
			    sizeof (iscsit_ioc_set_config_t), flag) != 0) {
				rc = EFAULT;
				goto cleanup;
			}
			break;
		default:
			rc = EFAULT;
			goto cleanup;
		}

		/* Check API version */
		if (setcfg.set_cfg_vers != ISCSIT_API_VERS0) {
			rc = EINVAL;
			goto cleanup;
		}

		/* Config is in packed nvlist format so unpack it */
		cfg_pnvlist = kmem_alloc(setcfg.set_cfg_pnvlist_len,
		    KM_SLEEP);
		ASSERT(cfg_pnvlist != NULL);

		if (ddi_copyin(setcfg.set_cfg_pnvlist, cfg_pnvlist,
		    setcfg.set_cfg_pnvlist_len, flag) != 0) {
			rc = EFAULT;
			goto cleanup;
		}

		rc = nvlist_unpack(cfg_pnvlist, setcfg.set_cfg_pnvlist_len,
		    &cfg_nvlist, KM_SLEEP);
		if (rc != 0) {
			goto cleanup;
		}

		/* Translate nvlist */
		rc = it_nv_to_config(cfg_nvlist, &cfg);
		if (rc != 0) {
			cmn_err(CE_WARN, "Configuration is invalid");
			goto cleanup;
		}

		/* Update config */
		rc = iscsit_config_merge(cfg);
		/* FALLTHROUGH */

cleanup:
		if (cfg)
			it_config_free_cmn(cfg);
		if (cfg_pnvlist)
			kmem_free(cfg_pnvlist, setcfg.set_cfg_pnvlist_len);
		if (cfg_nvlist)
			nvlist_free(cfg_nvlist);

		/*
		 * Now that the reconfig is complete set our state back to
		 * enabled.
		 */
		mutex_enter(&iscsit_global.global_state_mutex);
		iscsit_global.global_svc_state = ISE_ENABLED;
		mutex_exit(&iscsit_global.global_state_mutex);
		break;
	case ISCSIT_IOC_ENABLE_SVC: {
		iscsit_hostinfo_t hostinfo;

		if (ddi_copyin((void *)argp, &hostinfo.length,
		    sizeof (hostinfo.length), flag) != 0) {
			mutex_enter(&iscsit_global.global_state_mutex);
			iscsit_global.global_svc_state = ISE_DISABLED;
			mutex_exit(&iscsit_global.global_state_mutex);
			return (EFAULT);
		}

		if (hostinfo.length > sizeof (hostinfo.fqhn))
			hostinfo.length = sizeof (hostinfo.fqhn);

		if (ddi_copyin((void *)((caddr_t)argp +
		    sizeof (hostinfo.length)), &hostinfo.fqhn,
		    hostinfo.length, flag) != 0) {
			mutex_enter(&iscsit_global.global_state_mutex);
			iscsit_global.global_svc_state = ISE_DISABLED;
			mutex_exit(&iscsit_global.global_state_mutex);
			return (EFAULT);
		}

		idmrc = iscsit_enable_svc(&hostinfo);
		mutex_enter(&iscsit_global.global_state_mutex);
		if (idmrc == IDM_STATUS_SUCCESS) {
			iscsit_global.global_svc_state = ISE_ENABLED;
		} else {
			rc = EIO;
			iscsit_global.global_svc_state = ISE_DISABLED;
		}
		mutex_exit(&iscsit_global.global_state_mutex);
		break;
	}
	case ISCSIT_IOC_DISABLE_SVC:
		iscsit_disable_svc();
		mutex_enter(&iscsit_global.global_state_mutex);
		iscsit_global.global_svc_state = ISE_DISABLED;
		mutex_exit(&iscsit_global.global_state_mutex);
		break;

	default:
		rc = EINVAL;
		mutex_enter(&iscsit_global.global_state_mutex);
		iscsit_global.global_svc_state = ISE_ENABLED;
		mutex_exit(&iscsit_global.global_state_mutex);
	}

	return (rc);
}

static idm_status_t
iscsit_init(dev_info_t *dip)
{
	int			rc;

	rc = ldi_ident_from_dip(dip, &iscsit_global.global_li);
	ASSERT(rc == 0);  /* Failure indicates invalid argument */

	iscsit_global.global_svc_state = ISE_DISABLED;

	return (IDM_STATUS_SUCCESS);
}

/*
 * iscsit_enable_svc
 *
 * registers all the configured targets and target portals with STMF
 */
static idm_status_t
iscsit_enable_svc(iscsit_hostinfo_t *hostinfo)
{
	stmf_port_provider_t	*pp;
	stmf_dbuf_store_t	*dbuf_store;
	boolean_t		did_iscsit_isns_init;
	idm_status_t		retval = IDM_STATUS_SUCCESS;

	ASSERT(iscsit_global.global_svc_state == ISE_ENABLING);

	/*
	 * Make sure that can tell if we have partially allocated
	 * in case we need to exit and tear down anything allocated.
	 */
	iscsit_global.global_tsih_pool = NULL;
	iscsit_global.global_dbuf_store = NULL;
	iscsit_status_pdu_cache = NULL;
	pp = NULL;
	iscsit_global.global_pp = NULL;
	iscsit_global.global_default_tpg = NULL;
	did_iscsit_isns_init = B_FALSE;
	iscsit_global.global_dispatch_taskq = NULL;

	/* Setup remaining fields in iscsit_global_t */
	idm_refcnt_init(&iscsit_global.global_refcnt,
	    &iscsit_global);

	avl_create(&iscsit_global.global_discovery_sessions,
	    iscsit_sess_avl_compare, sizeof (iscsit_sess_t),
	    offsetof(iscsit_sess_t, ist_tgt_ln));

	avl_create(&iscsit_global.global_target_list,
	    iscsit_tgt_avl_compare, sizeof (iscsit_tgt_t),
	    offsetof(iscsit_tgt_t, target_global_ln));

	list_create(&iscsit_global.global_deleted_target_list,
	    sizeof (iscsit_tgt_t),
	    offsetof(iscsit_tgt_t, target_global_deleted_ln));

	avl_create(&iscsit_global.global_tpg_list,
	    iscsit_tpg_avl_compare, sizeof (iscsit_tpg_t),
	    offsetof(iscsit_tpg_t, tpg_global_ln));

	avl_create(&iscsit_global.global_ini_list,
	    iscsit_ini_avl_compare, sizeof (iscsit_ini_t),
	    offsetof(iscsit_ini_t, ini_global_ln));

	iscsit_global.global_tsih_pool = vmem_create("iscsit_tsih_pool",
	    (void *)1, ISCSI_MAX_TSIH, 1, NULL, NULL, NULL, 0,
	    VM_SLEEP | VMC_IDENTIFIER);

	/*
	 * Setup STMF dbuf store.  Our buffers are bound to a specific
	 * connection so we really can't let STMF cache buffers for us.
	 * Consequently we'll just allocate one global buffer store.
	 */
	dbuf_store = stmf_alloc(STMF_STRUCT_DBUF_STORE, 0, 0);
	if (dbuf_store == NULL) {
		retval = IDM_STATUS_FAIL;
		goto tear_down_and_return;
	}
	dbuf_store->ds_alloc_data_buf = iscsit_dbuf_alloc;
	dbuf_store->ds_free_data_buf = iscsit_dbuf_free;
	dbuf_store->ds_port_private = NULL;
	iscsit_global.global_dbuf_store = dbuf_store;

	/* Status PDU cache */
	iscsit_status_pdu_cache = kmem_cache_create("iscsit_status_pdu_cache",
	    sizeof (idm_pdu_t) + sizeof (iscsi_scsi_rsp_hdr_t), 8,
	    &iscsit_status_pdu_constructor,
	    NULL, NULL, NULL, NULL, KM_SLEEP);

	/* Default TPG and portal */
	iscsit_global.global_default_tpg = iscsit_tpg_createdefault();
	if (iscsit_global.global_default_tpg == NULL) {
		retval = IDM_STATUS_FAIL;
		goto tear_down_and_return;
	}

	/* initialize isns client */
	(void) iscsit_isns_init(hostinfo);
	did_iscsit_isns_init = B_TRUE;

	/* Register port provider */
	pp = stmf_alloc(STMF_STRUCT_PORT_PROVIDER, 0, 0);
	if (pp == NULL) {
		retval = IDM_STATUS_FAIL;
		goto tear_down_and_return;
	}

	pp->pp_portif_rev = PORTIF_REV_1;
	pp->pp_instance = 0;
	pp->pp_name = ISCSIT_MODNAME;
	pp->pp_cb = iscsit_pp_cb;

	iscsit_global.global_pp = pp;


	if (stmf_register_port_provider(pp) != STMF_SUCCESS) {
		retval = IDM_STATUS_FAIL;
		goto tear_down_and_return;
	}

	iscsit_global.global_dispatch_taskq = taskq_create("iscsit_dispatch",
	    1, minclsyspri, 16, 16, TASKQ_PREPOPULATE);

	/* Scan staged PDUs, meaningful in MC/S situations */
	iscsit_rxpdu_queue_monitor_start();

	return (IDM_STATUS_SUCCESS);

tear_down_and_return:

	if (iscsit_global.global_dispatch_taskq) {
		taskq_destroy(iscsit_global.global_dispatch_taskq);
		iscsit_global.global_dispatch_taskq = NULL;
	}

	if (did_iscsit_isns_init)
		iscsit_isns_fini();

	if (iscsit_global.global_default_tpg) {
		iscsit_tpg_destroydefault(iscsit_global.global_default_tpg);
		iscsit_global.global_default_tpg = NULL;
	}

	if (iscsit_global.global_pp)
		iscsit_global.global_pp = NULL;

	if (pp)
		stmf_free(pp);

	if (iscsit_status_pdu_cache) {
		kmem_cache_destroy(iscsit_status_pdu_cache);
		iscsit_status_pdu_cache = NULL;
	}

	if (iscsit_global.global_dbuf_store) {
		stmf_free(iscsit_global.global_dbuf_store);
		iscsit_global.global_dbuf_store = NULL;
	}

	if (iscsit_global.global_tsih_pool) {
		vmem_destroy(iscsit_global.global_tsih_pool);
		iscsit_global.global_tsih_pool = NULL;
	}

	avl_destroy(&iscsit_global.global_ini_list);
	avl_destroy(&iscsit_global.global_tpg_list);
	list_destroy(&iscsit_global.global_deleted_target_list);
	avl_destroy(&iscsit_global.global_target_list);
	avl_destroy(&iscsit_global.global_discovery_sessions);

	idm_refcnt_destroy(&iscsit_global.global_refcnt);

	return (retval);
}

/*
 * iscsit_disable_svc
 *
 * clean up all existing connections and deregister targets from STMF
 */
static void
iscsit_disable_svc(void)
{
	iscsit_sess_t	*sess;

	ASSERT(iscsit_global.global_svc_state == ISE_DISABLING);

	iscsit_rxpdu_queue_monitor_stop();

	/* tear down discovery sessions */
	for (sess = avl_first(&iscsit_global.global_discovery_sessions);
	    sess != NULL;
	    sess = AVL_NEXT(&iscsit_global.global_discovery_sessions, sess))
		iscsit_sess_close(sess);

	/*
	 * Passing NULL to iscsit_config_merge tells it to go to an empty
	 * config.
	 */
	(void) iscsit_config_merge(NULL);

	/*
	 * Wait until there are no more global references
	 */
	idm_refcnt_wait_ref(&iscsit_global.global_refcnt);
	idm_refcnt_destroy(&iscsit_global.global_refcnt);

	/*
	 * Default TPG must be destroyed after global_refcnt is 0.
	 */
	iscsit_tpg_destroydefault(iscsit_global.global_default_tpg);

	avl_destroy(&iscsit_global.global_discovery_sessions);
	list_destroy(&iscsit_global.global_deleted_target_list);
	avl_destroy(&iscsit_global.global_target_list);
	avl_destroy(&iscsit_global.global_tpg_list);
	avl_destroy(&iscsit_global.global_ini_list);

	taskq_destroy(iscsit_global.global_dispatch_taskq);

	iscsit_isns_fini();

	stmf_free(iscsit_global.global_dbuf_store);
	iscsit_global.global_dbuf_store = NULL;

	(void) stmf_deregister_port_provider(iscsit_global.global_pp);
	stmf_free(iscsit_global.global_pp);
	iscsit_global.global_pp = NULL;

	kmem_cache_destroy(iscsit_status_pdu_cache);
	iscsit_status_pdu_cache = NULL;

	vmem_destroy(iscsit_global.global_tsih_pool);
	iscsit_global.global_tsih_pool = NULL;
}

void
iscsit_global_hold()
{
	/*
	 * To take out a global hold, we must either own the global
	 * state mutex or we must be running inside of an ioctl that
	 * has set the global state to ISE_BUSY, ISE_DISABLING, or
	 * ISE_ENABLING.  We don't track the "owner" for these flags,
	 * so just checking if they are set is enough for now.
	 */
	ASSERT((iscsit_global.global_svc_state == ISE_ENABLING) ||
	    (iscsit_global.global_svc_state == ISE_DISABLING) ||
	    (iscsit_global.global_svc_state == ISE_BUSY) ||
	    MUTEX_HELD(&iscsit_global.global_state_mutex));

	idm_refcnt_hold(&iscsit_global.global_refcnt);
}

void
iscsit_global_rele()
{
	idm_refcnt_rele(&iscsit_global.global_refcnt);
}

void
iscsit_global_wait_ref()
{
	idm_refcnt_wait_ref(&iscsit_global.global_refcnt);
}

/*
 * IDM callbacks
 */

/*ARGSUSED*/
void
iscsit_rx_pdu(idm_conn_t *ic, idm_pdu_t *rx_pdu)
{
	iscsit_conn_t *ict = ic->ic_handle;
	switch (IDM_PDU_OPCODE(rx_pdu)) {
	case ISCSI_OP_SCSI_CMD:
		ASSERT(0); /* Shouldn't happen */
		idm_pdu_complete(rx_pdu, IDM_STATUS_SUCCESS);
		break;
	case ISCSI_OP_SNACK_CMD:
		/*
		 * We'll need to handle this when we support ERL1/2.  For
		 * now we treat it as a protocol error.
		 */
		idm_pdu_complete(rx_pdu, IDM_STATUS_SUCCESS);
		idm_conn_event(ic, CE_TRANSPORT_FAIL, NULL);
		break;
	case ISCSI_OP_SCSI_TASK_MGT_MSG:
		if (iscsit_check_cmdsn_and_queue(rx_pdu)) {
			iscsit_set_cmdsn(ict, rx_pdu);
			iscsit_op_scsi_task_mgmt(ict, rx_pdu);
		}
		break;
	case ISCSI_OP_NOOP_OUT:
	case ISCSI_OP_LOGIN_CMD:
	case ISCSI_OP_TEXT_CMD:
	case ISCSI_OP_LOGOUT_CMD:
		/*
		 * If/when we switch to userland processing these PDU's
		 * will be handled by iscsitd.
		 */
		iscsit_deferred_dispatch(rx_pdu);
		break;
	default:
		/* Protocol error */
		idm_pdu_complete(rx_pdu, IDM_STATUS_SUCCESS);
		idm_conn_event(ic, CE_TRANSPORT_FAIL, NULL);
		break;
	}
}

/*ARGSUSED*/
void
iscsit_rx_pdu_error(idm_conn_t *ic, idm_pdu_t *rx_pdu, idm_status_t status)
{
	idm_pdu_complete(rx_pdu, IDM_STATUS_SUCCESS);
}

void
iscsit_task_aborted(idm_task_t *idt, idm_status_t status)
{
	iscsit_task_t *itask = idt->idt_private;

	switch (status) {
	case IDM_STATUS_SUSPENDED:
		break;
	case IDM_STATUS_ABORTED:
		mutex_enter(&itask->it_mutex);
		itask->it_aborted = B_TRUE;
		/*
		 * We rely on the fact that STMF tracks outstanding
		 * buffer transfers and will free all of our buffers
		 * before freeing the task so we don't need to
		 * explicitly free the buffers from iscsit/idm
		 */
		if (itask->it_stmf_abort) {
			mutex_exit(&itask->it_mutex);
			/*
			 * Task is no longer active
			 */
			iscsit_task_done(itask);

			/*
			 * STMF has already asked for this task to be aborted
			 *
			 * STMF specification is wrong... says to return
			 * STMF_ABORTED, the code actually looks for
			 * STMF_ABORT_SUCCESS.
			 */
			stmf_task_lport_aborted(itask->it_stmf_task,
			    STMF_ABORT_SUCCESS, STMF_IOF_LPORT_DONE);
			return;
		} else {
			mutex_exit(&itask->it_mutex);
			/*
			 * Tell STMF to stop processing the task.
			 */
			stmf_abort(STMF_QUEUE_TASK_ABORT, itask->it_stmf_task,
			    STMF_ABORTED, NULL);
			return;
		}
		/*NOTREACHED*/
	default:
		ASSERT(0);
	}
}

/*ARGSUSED*/
idm_status_t
iscsit_client_notify(idm_conn_t *ic, idm_client_notify_t icn,
    uintptr_t data)
{
	idm_status_t rc = IDM_STATUS_SUCCESS;

	/*
	 * IDM client notifications will never occur at interrupt level
	 * since they are generated from the connection state machine which
	 * running on taskq threads.
	 *
	 */
	switch (icn) {
	case CN_CONNECT_ACCEPT:
		rc = iscsit_conn_accept(ic); /* No data */
		break;
	case CN_FFP_ENABLED:
		rc = iscsit_ffp_enabled(ic); /* No data */
		break;
	case CN_FFP_DISABLED:
		/*
		 * Data indicates whether this was the result of an
		 * explicit logout request.
		 */
		rc = iscsit_ffp_disabled(ic, (idm_ffp_disable_t)data);
		break;
	case CN_CONNECT_LOST:
		rc = iscsit_conn_lost(ic);
		break;
	case CN_CONNECT_DESTROY:
		rc = iscsit_conn_destroy(ic);
		break;
	case CN_LOGIN_FAIL:
		/*
		 * Force the login state machine to completion
		 */
		rc = iscsit_login_fail(ic);
		break;
	default:
		rc = IDM_STATUS_REJECT;
		break;
	}

	return (rc);
}

/*
 * iscsit_update_statsn is invoked for all the PDUs which have the StatSN
 * field in the header. The StatSN is incremented if the IDM_PDU_ADVANCE_STATSN
 * flag is set in the pdu flags field. The StatSN is connection-wide and is
 * protected by the mutex ict_statsn_mutex. For Data-In PDUs, if the flag
 * IDM_TASK_PHASECOLLAPSE_REQ is set, the status (phase-collapse) is also filled
 */
void
iscsit_update_statsn(idm_task_t *idm_task, idm_pdu_t *pdu)
{
	iscsi_scsi_rsp_hdr_t *rsp = (iscsi_scsi_rsp_hdr_t *)pdu->isp_hdr;
	iscsit_conn_t *ict = (iscsit_conn_t *)pdu->isp_ic->ic_handle;
	iscsit_task_t *itask = NULL;
	scsi_task_t *task = NULL;

	mutex_enter(&ict->ict_statsn_mutex);
	rsp->statsn = htonl(ict->ict_statsn);
	if (pdu->isp_flags & IDM_PDU_ADVANCE_STATSN)
		ict->ict_statsn++;
	mutex_exit(&ict->ict_statsn_mutex);

	/*
	 * The last SCSI Data PDU passed for a command may also contain the
	 * status if the status indicates termination with no expections, i.e.
	 * no sense data or response involved. If the command completes with
	 * an error, then the response and sense data will be sent in a
	 * separate iSCSI Response PDU.
	 */
	if ((idm_task) && (idm_task->idt_flags & IDM_TASK_PHASECOLLAPSE_REQ)) {
		itask = idm_task->idt_private;
		task = itask->it_stmf_task;

		rsp->cmd_status = task->task_scsi_status;
		rsp->flags	|= ISCSI_FLAG_DATA_STATUS;
		if (task->task_status_ctrl & TASK_SCTRL_OVER) {
			rsp->flags |= ISCSI_FLAG_CMD_OVERFLOW;
		} else if (task->task_status_ctrl & TASK_SCTRL_UNDER) {
			rsp->flags |= ISCSI_FLAG_CMD_UNDERFLOW;
		}
		rsp->residual_count = htonl(task->task_resid);

		/*
		 * Removing the task from the session task list
		 * just before the status is sent in the last
		 * Data PDU transfer
		 */
		iscsit_task_done(itask);
	}
}

void
iscsit_build_hdr(idm_task_t *idm_task, idm_pdu_t *pdu, uint8_t opcode)
{
	iscsit_task_t *itask = idm_task->idt_private;
	iscsi_data_rsp_hdr_t *dh = (iscsi_data_rsp_hdr_t *)pdu->isp_hdr;

	/*
	 * We acquired iscsit_sess_t.ist_sn_mutex in iscsit_xfer_scsi_data
	 */
	ASSERT(MUTEX_HELD(&itask->it_ict->ict_sess->ist_sn_mutex));
	/*
	 * On incoming data, the target transfer tag and Lun is only
	 * provided by the target if the A bit is set, Since the target
	 * does not currently support Error Recovery Level 1, the A
	 * bit is never set.
	 */
	dh->opcode = opcode;
	dh->itt = itask->it_itt;
	dh->ttt = ((opcode & ISCSI_OPCODE_MASK) == ISCSI_OP_SCSI_DATA_RSP) ?
	    ISCSI_RSVD_TASK_TAG : itask->it_ttt;

	dh->expcmdsn = htonl(itask->it_ict->ict_sess->ist_expcmdsn);
	dh->maxcmdsn = htonl(itask->it_ict->ict_sess->ist_maxcmdsn);

	/*
	 * IDM must set:
	 *
	 * data.flags and rtt.flags
	 * data.dlength
	 * data.datasn
	 * data.offset
	 * statsn, residual_count and cmd_status (for phase collapse)
	 * rtt.rttsn
	 * rtt.data_offset
	 * rtt.data_length
	 */
}

void
iscsit_keepalive(idm_conn_t *ic)
{
	idm_pdu_t		*nop_in_pdu;
	iscsi_nop_in_hdr_t	*nop_in;
	iscsit_conn_t		*ict = ic->ic_handle;

	/*
	 * IDM noticed the connection has been idle for too long so it's
	 * time to provoke some activity.  Build and transmit an iSCSI
	 * nop-in PDU -- when the initiator responds it will be counted
	 * as "activity" and keep the connection alive.
	 *
	 * We don't actually care about the response here at the iscsit level
	 * so we will just throw it away without looking at it when it arrives.
	 */
	nop_in_pdu = idm_pdu_alloc(sizeof (*nop_in), 0);
	idm_pdu_init(nop_in_pdu, ic, NULL, NULL);
	nop_in = (iscsi_nop_in_hdr_t *)nop_in_pdu->isp_hdr;
	bzero(nop_in, sizeof (*nop_in));
	nop_in->opcode = ISCSI_OP_NOOP_IN;
	nop_in->flags = ISCSI_FLAG_FINAL;
	nop_in->itt = ISCSI_RSVD_TASK_TAG;
	/*
	 * When the target sends a NOP-In as a Ping, the target transfer tag
	 * is set to a valid (not reserved) value and the initiator task tag
	 * is set to ISCSI_RSVD_TASK_TAG (0xffffffff). In this case the StatSN
	 * will always contain the next sequence number but the StatSN for the
	 * connection is not advanced after this PDU is sent.
	 */
	nop_in_pdu->isp_flags |= IDM_PDU_SET_STATSN;
	/*
	 * This works because we don't currently allocate ttt's anywhere else
	 * in iscsit so as long as we stay out of IDM's range we are safe.
	 * If we need to allocate ttt's for other PDU's in the future this will
	 * need to be improved.
	 */
	mutex_enter(&ict->ict_mutex);
	nop_in->ttt = ict->ict_keepalive_ttt;
	ict->ict_keepalive_ttt++;
	if (ict->ict_keepalive_ttt == ISCSI_RSVD_TASK_TAG)
		ict->ict_keepalive_ttt = IDM_TASKIDS_MAX;
	mutex_exit(&ict->ict_mutex);

	iscsit_pdu_tx(nop_in_pdu);
}

static idm_status_t
iscsit_conn_accept(idm_conn_t *ic)
{
	iscsit_conn_t *ict;

	/*
	 * We need to get a global hold here to ensure that the service
	 * doesn't get shutdown prior to establishing a session. This
	 * gets released in iscsit_conn_destroy().
	 */
	mutex_enter(&iscsit_global.global_state_mutex);
	if (iscsit_global.global_svc_state != ISE_ENABLED) {
		mutex_exit(&iscsit_global.global_state_mutex);
		return (IDM_STATUS_FAIL);
	}
	iscsit_global_hold();
	mutex_exit(&iscsit_global.global_state_mutex);

	/*
	 * Allocate an associated iscsit structure to represent this
	 * connection.  We shouldn't really create a session until we
	 * get the first login PDU.
	 */
	ict = kmem_zalloc(sizeof (*ict), KM_SLEEP);

	ict->ict_ic = ic;
	ict->ict_statsn = 1;
	ict->ict_keepalive_ttt = IDM_TASKIDS_MAX; /* Avoid IDM TT range */
	ic->ic_handle = ict;
	mutex_init(&ict->ict_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ict->ict_statsn_mutex, NULL, MUTEX_DRIVER, NULL);
	idm_refcnt_init(&ict->ict_refcnt, ict);

	/*
	 * Initialize login state machine
	 */
	if (iscsit_login_sm_init(ict) != IDM_STATUS_SUCCESS) {
		iscsit_global_rele();
		/*
		 * Cleanup the ict after idm notifies us about this failure
		 */
		return (IDM_STATUS_FAIL);
	}

	return (IDM_STATUS_SUCCESS);
}

idm_status_t
iscsit_conn_reinstate(iscsit_conn_t *reinstate_ict, iscsit_conn_t *new_ict)
{
	idm_status_t	result;

	/*
	 * Note in new connection state that this connection is
	 * reinstating an existing connection.
	 */
	new_ict->ict_reinstating = B_TRUE;
	new_ict->ict_reinstate_conn = reinstate_ict;
	new_ict->ict_statsn = reinstate_ict->ict_statsn;

	/*
	 * Now generate connection state machine event to existing connection
	 * so that it starts the cleanup process.
	 */
	result = idm_conn_reinstate_event(reinstate_ict->ict_ic,
	    new_ict->ict_ic);

	return (result);
}

void
iscsit_conn_hold(iscsit_conn_t *ict)
{
	idm_refcnt_hold(&ict->ict_refcnt);
}

void
iscsit_conn_rele(iscsit_conn_t *ict)
{
	idm_refcnt_rele(&ict->ict_refcnt);
}

void
iscsit_conn_dispatch_hold(iscsit_conn_t *ict)
{
	idm_refcnt_hold(&ict->ict_dispatch_refcnt);
}

void
iscsit_conn_dispatch_rele(iscsit_conn_t *ict)
{
	idm_refcnt_rele(&ict->ict_dispatch_refcnt);
}

static idm_status_t
iscsit_login_fail(idm_conn_t *ic)
{
	iscsit_conn_t *ict = ic->ic_handle;

	/* Generate login state machine event */
	iscsit_login_sm_event(ict, ILE_LOGIN_CONN_ERROR, NULL);

	return (IDM_STATUS_SUCCESS);
}

static idm_status_t
iscsit_ffp_enabled(idm_conn_t *ic)
{
	iscsit_conn_t *ict = ic->ic_handle;

	/* Generate session state machine event */
	iscsit_sess_sm_event(ict->ict_sess, SE_CONN_LOGGED_IN, ict);

	return (IDM_STATUS_SUCCESS);
}

static idm_status_t
iscsit_ffp_disabled(idm_conn_t *ic, idm_ffp_disable_t disable_class)
{
	iscsit_conn_t *ict = ic->ic_handle;

	/* Generate session state machine event */
	switch (disable_class) {
	case FD_CONN_FAIL:
		iscsit_sess_sm_event(ict->ict_sess, SE_CONN_FFP_FAIL, ict);
		break;
	case FD_CONN_LOGOUT:
		iscsit_sess_sm_event(ict->ict_sess, SE_CONN_FFP_DISABLE, ict);
		break;
	case FD_SESS_LOGOUT:
		iscsit_sess_sm_event(ict->ict_sess, SE_SESSION_CLOSE, ict);
		break;
	default:
		ASSERT(0);
	}

	return (IDM_STATUS_SUCCESS);
}

static idm_status_t
iscsit_conn_lost(idm_conn_t *ic)
{
	iscsit_conn_t	*ict	= ic->ic_handle;
	iscsit_sess_t	*ist	= ict->ict_sess;
	iscsit_cbuf_t	*cbuf;
	idm_pdu_t	*rx_pdu;
	int i;

	mutex_enter(&ict->ict_mutex);
	ict->ict_lost = B_TRUE;
	mutex_exit(&ict->ict_mutex);
	/*
	 * scrub the staging queue for all PDUs on this connection
	 */
	if (ist != NULL) {
		mutex_enter(&ist->ist_sn_mutex);
		for (cbuf = ist->ist_rxpdu_queue, i = 0;
		    ((cbuf->cb_num_elems > 0) && (i < ISCSIT_RXPDU_QUEUE_LEN));
		    i++) {
			if (((rx_pdu = cbuf->cb_buffer[i]) != NULL) &&
			    (rx_pdu->isp_ic == ic)) {
				/* conn is lost, drop the pdu */
				DTRACE_PROBE3(scrubbing__staging__queue,
				    iscsit_sess_t *, ist, idm_conn_t *, ic,
				    idm_pdu_t *, rx_pdu);
				idm_pdu_complete(rx_pdu, IDM_STATUS_FAIL);
				cbuf->cb_buffer[i] = NULL;
				cbuf->cb_num_elems--;
				iscsit_conn_dispatch_rele(ict);
			}
		}
		mutex_exit(&ist->ist_sn_mutex);
	}
	/*
	 * Make sure there aren't any PDU's transitioning from the receive
	 * handler to the dispatch taskq.
	 */
	idm_refcnt_wait_ref(&ict->ict_dispatch_refcnt);

	return (IDM_STATUS_SUCCESS);
}

static idm_status_t
iscsit_conn_destroy(idm_conn_t *ic)
{
	iscsit_conn_t *ict = ic->ic_handle;

	mutex_enter(&ict->ict_mutex);
	ict->ict_destroyed = B_TRUE;
	mutex_exit(&ict->ict_mutex);

	/* Generate session state machine event */
	if (ict->ict_sess != NULL) {
		/*
		 * Session state machine will call iscsit_conn_destroy_done()
		 * when it has removed references to this connection.
		 */
		iscsit_sess_sm_event(ict->ict_sess, SE_CONN_FAIL, ict);
	}

	idm_refcnt_wait_ref(&ict->ict_refcnt);
	/*
	 * The session state machine does not need to post
	 * events to IDM any longer, so it is safe to set
	 * the idm connection reference to NULL
	 */
	ict->ict_ic = NULL;

	/* Reap the login state machine */
	iscsit_login_sm_fini(ict);

	/* Clean up any text command remnants */
	iscsit_text_cmd_fini(ict);

	mutex_destroy(&ict->ict_mutex);
	idm_refcnt_destroy(&ict->ict_refcnt);
	kmem_free(ict, sizeof (*ict));

	iscsit_global_rele();

	return (IDM_STATUS_SUCCESS);
}

void
iscsit_conn_logout(iscsit_conn_t *ict)
{
	/*
	 * If the iscsi connection is active, then
	 * logout the IDM connection by sending a
	 * CE_LOGOUT_SESSION_SUCCESS, else, no action
	 * needs to be taken because the connection
	 * is already in the teardown process.
	 */
	mutex_enter(&ict->ict_mutex);
	if (ict->ict_lost == B_FALSE && ict->ict_destroyed == B_FALSE) {
		idm_conn_event(ict->ict_ic, CE_LOGOUT_SESSION_SUCCESS, NULL);
	}
	mutex_exit(&ict->ict_mutex);
}

/*
 * STMF-related functions
 *
 * iSCSI to STMF mapping
 *
 * Session == ?
 * Connection == bound to local port but not itself a local port
 * Target
 * Target portal (group?) == local port (really but we're not going to do this)
 *	iscsit needs to map connections to local ports (whatever we decide
 * 	they are)
 * Target == ?
 */

/*ARGSUSED*/
static stmf_data_buf_t *
iscsit_dbuf_alloc(scsi_task_t *task, uint32_t size, uint32_t *pminsize,
    uint32_t flags)
{
	iscsit_task_t *itask = task->task_port_private;
	idm_buf_t *idm_buffer;
	iscsit_buf_t	*ibuf;
	stmf_data_buf_t *result;
	uint32_t	bsize;

	/*
	 * If the requested size is larger than MaxBurstLength and the
	 * given pminsize is also larger than MaxBurstLength, then the
	 * allocation fails (dbuf = NULL) and pminsize is modified to
	 * be equal to MaxBurstLength. stmf/sbd then should re-invoke
	 * this function with the corrected values for transfer.
	 */
	ASSERT(pminsize);
	if (size <= itask->it_ict->ict_op.op_max_burst_length) {
		bsize = size;
	} else if (*pminsize <= itask->it_ict->ict_op.op_max_burst_length) {
		bsize = itask->it_ict->ict_op.op_max_burst_length;
	} else {
		*pminsize = itask->it_ict->ict_op.op_max_burst_length;
		return (NULL);
	}

	/* Alloc buffer */
	idm_buffer = idm_buf_alloc(itask->it_ict->ict_ic, NULL, bsize);
	if (idm_buffer != NULL) {
		result = stmf_alloc(STMF_STRUCT_DATA_BUF,
		    sizeof (iscsit_buf_t), 0);
		if (result != NULL) {
			/* Fill in stmf_data_buf_t */
			ibuf = result->db_port_private;
			ibuf->ibuf_idm_buf = idm_buffer;
			ibuf->ibuf_stmf_buf = result;
			ibuf->ibuf_is_immed = B_FALSE;
			result->db_flags = DB_DONT_CACHE;
			result->db_buf_size = bsize;
			result->db_data_size = bsize;
			result->db_sglist_length = 1;
			result->db_sglist[0].seg_addr = idm_buffer->idb_buf;
			result->db_sglist[0].seg_length =
			    idm_buffer->idb_buflen;
			return (result);
		}

		/* Couldn't get the stmf_data_buf_t so free the buffer */
		idm_buf_free(idm_buffer);
	}

	return (NULL);
}

/*ARGSUSED*/
static void
iscsit_dbuf_free(stmf_dbuf_store_t *ds, stmf_data_buf_t *dbuf)
{
	iscsit_buf_t *ibuf = dbuf->db_port_private;

	if (ibuf->ibuf_is_immed) {
		/*
		 * The iscsit_buf_t structure itself will be freed with its
		 * associated task.  Here we just need to free the PDU that
		 * held the immediate data.
		 */
		idm_pdu_complete(ibuf->ibuf_immed_data_pdu, IDM_STATUS_SUCCESS);
		ibuf->ibuf_immed_data_pdu = 0;
	} else {
		idm_buf_free(ibuf->ibuf_idm_buf);
		stmf_free(dbuf);
	}
}

/*ARGSUSED*/
stmf_status_t
iscsit_xfer_scsi_data(scsi_task_t *task, stmf_data_buf_t *dbuf,
    uint32_t ioflags)
{
	iscsit_task_t *iscsit_task = task->task_port_private;
	iscsit_sess_t *ict_sess = iscsit_task->it_ict->ict_sess;
	iscsit_buf_t *ibuf = dbuf->db_port_private;
	int idm_rc;

	/*
	 * If we are aborting then we can ignore this request
	 */
	if (iscsit_task->it_stmf_abort) {
		return (STMF_SUCCESS);
	}

	/*
	 * If it's not immediate data then start the transfer
	 */
	ASSERT(ibuf->ibuf_is_immed == B_FALSE);
	if (dbuf->db_flags & DB_DIRECTION_TO_RPORT) {
		/*
		 * The DB_SEND_STATUS_GOOD flag in the STMF data buffer allows
		 * the port provider to phase-collapse, i.e. send the status
		 * along with the final data PDU for the command. The port
		 * provider passes this request to the transport layer by
		 * setting a flag IDM_TASK_PHASECOLLAPSE_REQ in the task.
		 */
		if (dbuf->db_flags & DB_SEND_STATUS_GOOD)
			iscsit_task->it_idm_task->idt_flags |=
			    IDM_TASK_PHASECOLLAPSE_REQ;
		/*
		 * IDM will call iscsit_build_hdr so lock now to serialize
		 * access to the SN values.  We need to lock here to enforce
		 * lock ordering
		 */
		mutex_enter(&ict_sess->ist_sn_mutex);
		idm_rc = idm_buf_tx_to_ini(iscsit_task->it_idm_task,
		    ibuf->ibuf_idm_buf, dbuf->db_relative_offset,
		    dbuf->db_data_size, &iscsit_buf_xfer_cb, dbuf);
		mutex_exit(&ict_sess->ist_sn_mutex);

		return (iscsit_idm_to_stmf(idm_rc));
	} else if (dbuf->db_flags & DB_DIRECTION_FROM_RPORT) {
		/* Grab the SN lock (see comment above) */
		mutex_enter(&ict_sess->ist_sn_mutex);
		idm_rc = idm_buf_rx_from_ini(iscsit_task->it_idm_task,
		    ibuf->ibuf_idm_buf, dbuf->db_relative_offset,
		    dbuf->db_data_size, &iscsit_buf_xfer_cb, dbuf);
		mutex_exit(&ict_sess->ist_sn_mutex);

		return (iscsit_idm_to_stmf(idm_rc));
	}

	/* What are we supposed to do if there is no direction? */
	return (STMF_INVALID_ARG);
}

static void
iscsit_buf_xfer_cb(idm_buf_t *idb, idm_status_t status)
{
	iscsit_task_t *itask = idb->idb_task_binding->idt_private;
	stmf_data_buf_t *dbuf = idb->idb_cb_arg;

	dbuf->db_xfer_status = iscsit_idm_to_stmf(status);

	/*
	 * If the task has been aborted then we don't need to call STMF
	 */
	if (itask->it_stmf_abort) {
		return;
	}

	/*
	 * For ISCSI over TCP (not iSER), the last SCSI Data PDU passed
	 * for a successful command contains the status as requested by
	 * by COMSTAR (via the DB_SEND_STATUS_GOOD flag). But the iSER
	 * transport does not support phase-collapse. So pretend we are
	 * COMSTAR and send the status in a separate PDU now.
	 */
	if (idb->idb_task_binding->idt_flags & IDM_TASK_PHASECOLLAPSE_SUCCESS) {
		/*
		 * Mark task complete and notify COMSTAR
		 * that the status has been sent.
		 */
		itask->it_idm_task->idt_state = TASK_COMPLETE;
		stmf_send_status_done(itask->it_stmf_task,
		    iscsit_idm_to_stmf(status), STMF_IOF_LPORT_DONE);
	} else if ((dbuf->db_flags & DB_SEND_STATUS_GOOD) &&
	    status == IDM_STATUS_SUCCESS) {

		/*
		 * The iscsi target port provider - for iSER, emulates the
		 * DB_SEND_STATUS_GOOD optimization if requested by STMF;
		 * it sends the status in a separate PDU after the data
		 * transfer. In this case the port provider should first
		 * call stmf_data_xfer_done() to mark the transfer complete
		 * and then send the status. Although STMF will free the
		 * buffer at the time the task is freed, even if the transfer
		 * is not marked complete, this behavior makes statistics
		 * gathering and task state tracking more difficult than it
		 * needs to be.
		 */
		stmf_data_xfer_done(itask->it_stmf_task, dbuf, 0);
		if (iscsit_send_scsi_status(itask->it_stmf_task, 0)
		    != STMF_SUCCESS) {
			stmf_send_status_done(itask->it_stmf_task,
			    STMF_FAILURE, STMF_IOF_LPORT_DONE);
		}
	} else {
		stmf_data_xfer_done(itask->it_stmf_task, dbuf, 0);
		/* don't touch dbuf after stmf_data_xfer_done */
	}
}


/*ARGSUSED*/
stmf_status_t
iscsit_send_scsi_status(scsi_task_t *task, uint32_t ioflags)
{
	iscsit_task_t *itask = task->task_port_private;
	iscsi_scsi_rsp_hdr_t *rsp;
	idm_pdu_t *pdu;
	int resp_datalen;

	/*
	 * If this task is aborted then we don't need to respond.
	 */
	if (itask->it_stmf_abort) {
		return (STMF_SUCCESS);
	}

	/*
	 * If this is a task management status, handle it elsewhere.
	 */
	if (task->task_mgmt_function != TM_NONE) {
		/*
		 * Don't wait for the PDU completion to tell STMF
		 * the task is done -- it doesn't really matter and
		 * it makes life complicated if STMF later asks us to
		 * abort the request and we don't know whether the
		 * status has been sent or not.
		 */
		itask->it_tm_responded = B_TRUE;
		iscsit_send_task_mgmt_resp(itask->it_tm_pdu,
		    (task->task_completion_status == STMF_SUCCESS) ?
		    SCSI_TCP_TM_RESP_COMPLETE : SCSI_TCP_TM_RESP_FUNC_NOT_SUPP);
		stmf_send_status_done(task, STMF_SUCCESS,
		    STMF_IOF_LPORT_DONE);
		return (STMF_SUCCESS);
	}

	/*
	 * Remove the task from the session task list
	 */
	iscsit_task_done(itask);

	/*
	 * Send status
	 */
	mutex_enter(&itask->it_idm_task->idt_mutex);
	if ((itask->it_idm_task->idt_state == TASK_ACTIVE) &&
	    (task->task_completion_status == STMF_SUCCESS) &&
	    (task->task_sense_length == 0) &&
	    (task->task_resid == 0)) {
		itask->it_idm_task->idt_state = TASK_COMPLETE;
		/* PDU callback releases task hold */
		idm_task_hold(itask->it_idm_task);
		mutex_exit(&itask->it_idm_task->idt_mutex);
		/*
		 * Fast path.  Cached status PDU's are already
		 * initialized.  We just need to fill in
		 * connection and task information. StatSN is
		 * incremented by 1 for every status sent a
		 * connection.
		 */
		pdu = kmem_cache_alloc(iscsit_status_pdu_cache, KM_SLEEP);
		pdu->isp_ic = itask->it_ict->ict_ic;
		pdu->isp_private = itask;
		pdu->isp_flags |= IDM_PDU_SET_STATSN | IDM_PDU_ADVANCE_STATSN;

		rsp = (iscsi_scsi_rsp_hdr_t *)pdu->isp_hdr;
		rsp->itt = itask->it_itt;
		/*
		 * ExpDataSN is the number of R2T and Data-In (read)
		 * PDUs the target has sent for the SCSI command.
		 *
		 * Since there is no support for bidirectional transfer
		 * yet, either idt_exp_datasn or idt_exp_rttsn, but not
		 * both is valid at any time
		 */
		rsp->expdatasn = (itask->it_idm_task->idt_exp_datasn != 0) ?
		    htonl(itask->it_idm_task->idt_exp_datasn):
		    htonl(itask->it_idm_task->idt_exp_rttsn);
		rsp->cmd_status = task->task_scsi_status;
		iscsit_pdu_tx(pdu);
		return (STMF_SUCCESS);
	} else {
		if (itask->it_idm_task->idt_state != TASK_ACTIVE) {
			mutex_exit(&itask->it_idm_task->idt_mutex);
			return (STMF_FAILURE);
		}
		itask->it_idm_task->idt_state = TASK_COMPLETE;
		/* PDU callback releases task hold */
		idm_task_hold(itask->it_idm_task);
		mutex_exit(&itask->it_idm_task->idt_mutex);

		resp_datalen = (task->task_sense_length == 0) ? 0 :
		    (task->task_sense_length + sizeof (uint16_t));

		pdu = idm_pdu_alloc(sizeof (iscsi_hdr_t), resp_datalen);
		idm_pdu_init(pdu, itask->it_ict->ict_ic, itask,
		    iscsit_send_status_done);
		pdu->isp_flags |= IDM_PDU_SET_STATSN | IDM_PDU_ADVANCE_STATSN;

		rsp = (iscsi_scsi_rsp_hdr_t *)pdu->isp_hdr;
		bzero(rsp, sizeof (*rsp));
		rsp->opcode = ISCSI_OP_SCSI_RSP;

		rsp->flags = ISCSI_FLAG_FINAL;
		if (task->task_status_ctrl & TASK_SCTRL_OVER) {
			rsp->flags |= ISCSI_FLAG_CMD_OVERFLOW;
		} else if (task->task_status_ctrl & TASK_SCTRL_UNDER) {
			rsp->flags |= ISCSI_FLAG_CMD_UNDERFLOW;
		}

		rsp->bi_residual_count = 0;
		rsp->residual_count = htonl(task->task_resid);
		rsp->itt = itask->it_itt;
		rsp->response = ISCSI_STATUS_CMD_COMPLETED;
		rsp->expdatasn = (itask->it_idm_task->idt_exp_datasn != 0) ?
		    htonl(itask->it_idm_task->idt_exp_datasn):
		    htonl(itask->it_idm_task->idt_exp_rttsn);
		rsp->cmd_status = task->task_scsi_status;
		if (task->task_sense_length != 0) {
			/*
			 * Add a byte to provide the sense length in
			 * the response
			 */
			*(uint16_t *)((void *)pdu->isp_data) =
			    htons(task->task_sense_length);
			bcopy(task->task_sense_data,
			    (uint8_t *)pdu->isp_data +
			    sizeof (uint16_t),
			    task->task_sense_length);
			hton24(rsp->dlength, resp_datalen);
		}

		DTRACE_PROBE5(iscsi__scsi__response,
		    iscsit_conn_t *, itask->it_ict,
		    uint8_t, rsp->response,
		    uint8_t, rsp->cmd_status,
		    idm_pdu_t *, pdu,
		    scsi_task_t *, task);

		iscsit_pdu_tx(pdu);

		return (STMF_SUCCESS);
	}
}

/*ARGSUSED*/
static void
iscsit_send_good_status_done(idm_pdu_t *pdu, idm_status_t status)
{
	iscsit_task_t	*itask;
	boolean_t	aborted;

	itask = pdu->isp_private;
	aborted = itask->it_stmf_abort;

	/*
	 * After releasing the hold the task may be freed at any time so
	 * don't touch it.
	 */
	idm_task_rele(itask->it_idm_task);
	if (!aborted) {
		stmf_send_status_done(itask->it_stmf_task,
		    iscsit_idm_to_stmf(pdu->isp_status), STMF_IOF_LPORT_DONE);
	}
	kmem_cache_free(iscsit_status_pdu_cache, pdu);
}

/*ARGSUSED*/
static void
iscsit_send_status_done(idm_pdu_t *pdu, idm_status_t status)
{
	iscsit_task_t	 *itask;
	boolean_t	aborted;

	itask = pdu->isp_private;
	aborted = itask->it_stmf_abort;

	/*
	 * After releasing the hold the task may be freed at any time so
	 * don't touch it.
	 */
	idm_task_rele(itask->it_idm_task);
	if (!aborted) {
		stmf_send_status_done(itask->it_stmf_task,
		    iscsit_idm_to_stmf(pdu->isp_status), STMF_IOF_LPORT_DONE);
	}
	idm_pdu_free(pdu);
}


void
iscsit_lport_task_free(scsi_task_t *task)
{
	iscsit_task_t *itask = task->task_port_private;

	/* We only call idm_task_start for regular tasks, not task management */
	if (task->task_mgmt_function == TM_NONE) {
		idm_task_done(itask->it_idm_task);
		iscsit_task_free(itask);
		return;
	} else {
		iscsit_tm_task_free(itask);
	}
}

/*ARGSUSED*/
stmf_status_t
iscsit_abort(stmf_local_port_t *lport, int abort_cmd, void *arg, uint32_t flags)
{
	scsi_task_t	*st = (scsi_task_t *)arg;
	iscsit_task_t	*iscsit_task;
	idm_task_t	*idt;

	/*
	 * If this is a task management request then there's really not much to
	 * do.
	 */
	if (st->task_mgmt_function != TM_NONE) {
		return (STMF_ABORT_SUCCESS);
	}

	/*
	 * Regular task, start cleaning up
	 */
	iscsit_task = st->task_port_private;
	idt = iscsit_task->it_idm_task;
	mutex_enter(&iscsit_task->it_mutex);
	iscsit_task->it_stmf_abort = B_TRUE;
	if (iscsit_task->it_aborted) {
		mutex_exit(&iscsit_task->it_mutex);
		/*
		 * Task is no longer active
		 */
		iscsit_task_done(iscsit_task);

		/*
		 * STMF specification is wrong... says to return
		 * STMF_ABORTED, the code actually looks for
		 * STMF_ABORT_SUCCESS.
		 */
		return (STMF_ABORT_SUCCESS);
	} else {
		mutex_exit(&iscsit_task->it_mutex);
		/*
		 * Call IDM to abort the task.  Due to a variety of
		 * circumstances the task may already be in the process of
		 * aborting.
		 * We'll let IDM worry about rationalizing all that except
		 * for one particular instance.  If the state of the task
		 * is TASK_COMPLETE, we need to indicate to the framework
		 * that we are in fact done.  This typically happens with
		 * framework-initiated task management type requests
		 * (e.g. abort task).
		 */
		if (idt->idt_state == TASK_COMPLETE) {
			idm_refcnt_wait_ref(&idt->idt_refcnt);
			return (STMF_ABORT_SUCCESS);
		} else {
			idm_task_abort(idt->idt_ic, idt, AT_TASK_MGMT_ABORT);
			return (STMF_SUCCESS);
		}
	}

	/*NOTREACHED*/
}

/*ARGSUSED*/
void
iscsit_ctl(stmf_local_port_t *lport, int cmd, void *arg)
{
	iscsit_tgt_t		*iscsit_tgt;

	ASSERT((cmd == STMF_CMD_LPORT_ONLINE) ||
	    (cmd == STMF_ACK_LPORT_ONLINE_COMPLETE) ||
	    (cmd == STMF_CMD_LPORT_OFFLINE) ||
	    (cmd == STMF_ACK_LPORT_OFFLINE_COMPLETE));

	iscsit_tgt = (iscsit_tgt_t *)lport->lport_port_private;

	switch (cmd) {
	case STMF_CMD_LPORT_ONLINE:
		iscsit_tgt_sm_event(iscsit_tgt, TE_STMF_ONLINE_REQ);
		break;
	case STMF_CMD_LPORT_OFFLINE:
		iscsit_tgt_sm_event(iscsit_tgt, TE_STMF_OFFLINE_REQ);
		break;
	case STMF_ACK_LPORT_ONLINE_COMPLETE:
		iscsit_tgt_sm_event(iscsit_tgt, TE_STMF_ONLINE_COMPLETE_ACK);
		break;
	case STMF_ACK_LPORT_OFFLINE_COMPLETE:
		iscsit_tgt_sm_event(iscsit_tgt, TE_STMF_OFFLINE_COMPLETE_ACK);
		break;

	default:
		break;
	}
}

static stmf_status_t
iscsit_idm_to_stmf(idm_status_t idmrc)
{
	switch (idmrc) {
	case IDM_STATUS_SUCCESS:
		return (STMF_SUCCESS);
	default:
		return (STMF_FAILURE);
	}
	/*NOTREACHED*/
}

void
iscsit_op_scsi_cmd(idm_conn_t *ic, idm_pdu_t *rx_pdu)
{
	iscsit_conn_t		*ict = ic->ic_handle;

	if (iscsit_check_cmdsn_and_queue(rx_pdu)) {
		iscsit_post_scsi_cmd(ic, rx_pdu);
	}
	iscsit_process_pdu_in_queue(ict->ict_sess);
}

/*
 * ISCSI protocol
 */

void
iscsit_post_scsi_cmd(idm_conn_t *ic, idm_pdu_t *rx_pdu)
{
	iscsit_conn_t		*ict;
	iscsit_task_t		*itask;
	scsi_task_t		*task;
	iscsit_buf_t		*ibuf;
	iscsi_scsi_cmd_hdr_t	*iscsi_scsi =
	    (iscsi_scsi_cmd_hdr_t *)rx_pdu->isp_hdr;
	iscsi_addl_hdr_t	*ahs_hdr;
	uint16_t		addl_cdb_len = 0;

	ict = ic->ic_handle;

	itask = iscsit_task_alloc(ict);
	if (itask == NULL) {
		/* Finish processing request */
		iscsit_set_cmdsn(ict, rx_pdu);

		iscsit_send_direct_scsi_resp(ict, rx_pdu,
		    ISCSI_STATUS_CMD_COMPLETED, STATUS_BUSY);
		idm_pdu_complete(rx_pdu, IDM_STATUS_SUCCESS);
		return;
	}

	/*
	 * Note CmdSN and ITT in task.  IDM will have already validated this
	 * request against the connection state so we don't need to check
	 * that (the connection may have changed state in the meantime but
	 * we will catch that when we try to send a response)
	 */
	itask->it_cmdsn = ntohl(iscsi_scsi->cmdsn);
	itask->it_itt = iscsi_scsi->itt;

	/*
	 * Check for extended CDB AHS
	 */
	if (iscsi_scsi->hlength > 0) {
		ahs_hdr = (iscsi_addl_hdr_t *)iscsi_scsi;
		addl_cdb_len = ((ahs_hdr->ahs_hlen_hi << 8) |
		    ahs_hdr->ahs_hlen_lo) - 1; /* Adjust for reserved byte */
		if (((addl_cdb_len + 4) / sizeof (uint32_t)) >
		    iscsi_scsi->hlength) {
			/* Mangled header info, drop it */
			idm_pdu_complete(rx_pdu, IDM_STATUS_SUCCESS);
			return;
		}
	}

	ict = rx_pdu->isp_ic->ic_handle; /* IDM client private */

	/*
	 * Add task to session list.  This function will also check to
	 * ensure that the task does not already exist.
	 */
	if (iscsit_task_start(itask) != IDM_STATUS_SUCCESS) {
		/*
		 * Task exists, free all resources and reject.  Don't
		 * update expcmdsn in this case because RFC 3720 says
		 * "The CmdSN of the rejected command PDU (if it is a
		 * non-immediate command) MUST NOT be considered received
		 * by the target (i.e., a command sequence gap must be
		 * assumed for the CmdSN), even though the CmdSN of the
		 * rejected command PDU may be reliably ascertained.  Upon
		 * receiving the Reject, the initiator MUST plug the CmdSN
		 * gap in order to continue to use the session.  The gap
		 * may be plugged either by transmitting a command PDU
		 * with the same CmdSN, or by aborting the task (see section
		 * 6.9 on how an abort may plug a CmdSN gap)." (Section 6.3)
		 */
		iscsit_task_free(itask);
		iscsit_send_reject(ict, rx_pdu, ISCSI_REJECT_TASK_IN_PROGRESS);
		idm_pdu_complete(rx_pdu, IDM_STATUS_SUCCESS);
		return;
	}

	/* Update sequence numbers */
	iscsit_set_cmdsn(ict, rx_pdu);

	/*
	 * Allocate STMF task
	 */
	itask->it_stmf_task = stmf_task_alloc(
	    itask->it_ict->ict_sess->ist_lport,
	    itask->it_ict->ict_sess->ist_stmf_sess, iscsi_scsi->lun,
	    16 + addl_cdb_len, 0);
	if (itask->it_stmf_task == NULL) {
		/*
		 * Either stmf really couldn't get memory for a task or,
		 * more likely, the LU is currently in reset.  Either way
		 * we have no choice but to fail the request.
		 */
		iscsit_task_done(itask);
		iscsit_task_free(itask);
		iscsit_send_direct_scsi_resp(ict, rx_pdu,
		    ISCSI_STATUS_CMD_COMPLETED, STATUS_BUSY);
		idm_pdu_complete(rx_pdu, IDM_STATUS_SUCCESS);
		return;
	}

	task = itask->it_stmf_task;
	task->task_port_private = itask;

	bcopy(iscsi_scsi->lun, task->task_lun_no, sizeof (task->task_lun_no));

	/*
	 * iSCSI and Comstar use the same values.  Should we rely on this
	 * or translate them bit-wise?
	 */

	task->task_flags =
	    (((iscsi_scsi->flags & ISCSI_FLAG_CMD_READ) ? TF_READ_DATA : 0) |
	    ((iscsi_scsi->flags & ISCSI_FLAG_CMD_WRITE) ? TF_WRITE_DATA : 0) |
	    ((rx_pdu->isp_datalen == 0) ? 0 : TF_INITIAL_BURST));

	switch (iscsi_scsi->flags & ISCSI_FLAG_CMD_ATTR_MASK) {
	case ISCSI_ATTR_UNTAGGED:
		break;
	case ISCSI_ATTR_SIMPLE:
		task->task_additional_flags |= TF_ATTR_SIMPLE_QUEUE;
		break;
	case ISCSI_ATTR_ORDERED:
		task->task_additional_flags |= TF_ATTR_ORDERED_QUEUE;
		break;
	case ISCSI_ATTR_HEAD_OF_QUEUE:
		task->task_additional_flags |= TF_ATTR_HEAD_OF_QUEUE;
		break;
	case ISCSI_ATTR_ACA:
		task->task_additional_flags |= TF_ATTR_ACA;
		break;
	default:
		/* Protocol error but just take it, treat as untagged */
		break;
	}


	task->task_additional_flags = 0;
	task->task_priority = 0;
	task->task_mgmt_function = TM_NONE;

	/*
	 * This "task_max_nbufs" doesn't map well to BIDI.  We probably need
	 * parameter for each direction.  "MaxOutstandingR2T" may very well
	 * be set to one which could prevent us from doing simultaneous
	 * transfers in each direction.
	 */
	task->task_max_nbufs = (iscsi_scsi->flags & ISCSI_FLAG_CMD_WRITE) ?
	    ict->ict_op.op_max_outstanding_r2t : STMF_BUFS_MAX;
	task->task_cmd_seq_no = ntohl(iscsi_scsi->itt);
	task->task_expected_xfer_length = ntohl(iscsi_scsi->data_length);

	/* Copy CDB */
	bcopy(iscsi_scsi->scb, task->task_cdb, 16);
	if (addl_cdb_len > 0) {
		bcopy(ahs_hdr->ahs_extscb, task->task_cdb + 16, addl_cdb_len);
	}

	DTRACE_ISCSI_3(scsi__command, idm_conn_t *, ic,
	    iscsi_scsi_cmd_hdr_t *, (iscsi_scsi_cmd_hdr_t *)rx_pdu->isp_hdr,
	    scsi_task_t *, task);

	/*
	 * Copy the transport header into the task handle from the PDU
	 * handle. The transport header describes this task's remote tagged
	 * buffer.
	 */
	if (rx_pdu->isp_transport_hdrlen != 0) {
		bcopy(rx_pdu->isp_transport_hdr,
		    itask->it_idm_task->idt_transport_hdr,
		    rx_pdu->isp_transport_hdrlen);
	}

	/*
	 * Tell IDM about our new active task
	 */
	idm_task_start(itask->it_idm_task, (uintptr_t)itask->it_itt);

	/*
	 * If we have any immediate data then setup the immediate buffer
	 * context that comes with the task
	 */
	if (rx_pdu->isp_datalen) {
		ibuf = itask->it_immed_data;
		ibuf->ibuf_immed_data_pdu = rx_pdu;
		ibuf->ibuf_stmf_buf->db_data_size = rx_pdu->isp_datalen;
		ibuf->ibuf_stmf_buf->db_buf_size = rx_pdu->isp_datalen;
		ibuf->ibuf_stmf_buf->db_relative_offset = 0;
		ibuf->ibuf_stmf_buf->db_sglist[0].seg_length =
		    rx_pdu->isp_datalen;
		ibuf->ibuf_stmf_buf->db_sglist[0].seg_addr = rx_pdu->isp_data;

		DTRACE_ISCSI_8(xfer__start, idm_conn_t *, ic,
		    uintptr_t, ibuf->ibuf_stmf_buf->db_sglist[0].seg_addr,
		    uint32_t, ibuf->ibuf_stmf_buf->db_relative_offset,
		    uint64_t, 0, uint32_t, 0, uint32_t, 0, /* no raddr */
		    uint32_t, rx_pdu->isp_datalen, int, XFER_BUF_TX_TO_INI);

		/*
		 * For immediate data transfer, there is no callback from
		 * stmf to indicate that the initial burst of data is
		 * transferred successfully. In some cases, the task can
		 * get freed before execution returns from stmf_post_task.
		 * Although this xfer-start/done probe accurately tracks
		 * the size of the transfer, it does only provide a best
		 * effort on the timing of the transfer.
		 */
		DTRACE_ISCSI_8(xfer__done, idm_conn_t *, ic,
		    uintptr_t, ibuf->ibuf_stmf_buf->db_sglist[0].seg_addr,
		    uint32_t, ibuf->ibuf_stmf_buf->db_relative_offset,
		    uint64_t, 0, uint32_t, 0, uint32_t, 0, /* no raddr */
		    uint32_t, rx_pdu->isp_datalen, int, XFER_BUF_TX_TO_INI);
		stmf_post_task(task, ibuf->ibuf_stmf_buf);
	} else {

		stmf_post_task(task, NULL);
		idm_pdu_complete(rx_pdu, IDM_STATUS_SUCCESS);
	}
}

void
iscsit_deferred_dispatch(idm_pdu_t *rx_pdu)
{
	iscsit_conn_t *ict = rx_pdu->isp_ic->ic_handle;

	/*
	 * If this isn't a login packet, we need a session.  Otherwise
	 * this is a protocol error (perhaps one IDM should've caught?).
	 */
	if (IDM_PDU_OPCODE(rx_pdu) != ISCSI_OP_LOGIN_CMD &&
	    ict->ict_sess == NULL) {
		DTRACE_PROBE2(iscsi__idm__deferred__no__session,
		    iscsit_conn_t *, ict, idm_pdu_t *, rx_pdu);
		idm_pdu_complete(rx_pdu, IDM_STATUS_FAIL);
		return;
	}

	/*
	 * If the connection has been lost then ignore new PDU's
	 */
	mutex_enter(&ict->ict_mutex);
	if (ict->ict_lost) {
		mutex_exit(&ict->ict_mutex);
		idm_pdu_complete(rx_pdu, IDM_STATUS_FAIL);
		return;
	}

	/*
	 * Grab a hold on the connection to prevent it from going away
	 * between now and when the taskq function is called.
	 */
	iscsit_conn_dispatch_hold(ict);
	mutex_exit(&ict->ict_mutex);

	taskq_dispatch_ent(iscsit_global.global_dispatch_taskq,
	    iscsit_deferred, rx_pdu, 0, &rx_pdu->isp_tqent);
}

static void
iscsit_deferred(void *rx_pdu_void)
{
	idm_pdu_t		*rx_pdu = rx_pdu_void;
	idm_conn_t		*ic = rx_pdu->isp_ic;
	iscsit_conn_t		*ict = ic->ic_handle;

	/*
	 * NOP and Task Management Commands can be marked for immediate
	 * delivery. Commands marked as 'Immediate' are to be considered
	 * for execution as soon as they arrive on the target. So these
	 * should not be checked for sequence order and put in a queue.
	 * The CmdSN is not advanced for Immediate Commands.
	 */
	switch (IDM_PDU_OPCODE(rx_pdu)) {
	case ISCSI_OP_NOOP_OUT:
		if (iscsit_check_cmdsn_and_queue(rx_pdu)) {
			iscsit_set_cmdsn(ict, rx_pdu);
			iscsit_pdu_op_noop(ict, rx_pdu);
		}
		break;
	case ISCSI_OP_LOGIN_CMD:
		iscsit_pdu_op_login_cmd(ict, rx_pdu);
		iscsit_conn_dispatch_rele(ict);
		return;
	case ISCSI_OP_TEXT_CMD:
		if (iscsit_check_cmdsn_and_queue(rx_pdu)) {
			iscsit_set_cmdsn(ict, rx_pdu);
			iscsit_pdu_op_text_cmd(ict, rx_pdu);
		}
		break;
	case ISCSI_OP_LOGOUT_CMD:
		if (iscsit_check_cmdsn_and_queue(rx_pdu)) {
			iscsit_set_cmdsn(ict, rx_pdu);
			iscsit_pdu_op_logout_cmd(ict, rx_pdu);
		}
		break;
	default:
		/* Protocol error.  IDM should have caught this */
		idm_pdu_complete(rx_pdu, IDM_STATUS_FAIL);
		ASSERT(0);
		break;
	}
	/*
	 * Check if there are other PDUs in the session staging queue
	 * waiting to be posted to SCSI layer.
	 */
	iscsit_process_pdu_in_queue(ict->ict_sess);

	iscsit_conn_dispatch_rele(ict);
}

static void
iscsit_send_direct_scsi_resp(iscsit_conn_t *ict, idm_pdu_t *rx_pdu,
    uint8_t response, uint8_t cmd_status)
{
	idm_pdu_t			*rsp_pdu;
	idm_conn_t			*ic;
	iscsi_scsi_rsp_hdr_t		*resp;
	iscsi_scsi_cmd_hdr_t		*req =
	    (iscsi_scsi_cmd_hdr_t *)rx_pdu->isp_hdr;

	ic = ict->ict_ic;

	rsp_pdu = idm_pdu_alloc(sizeof (iscsi_scsi_rsp_hdr_t), 0);
	idm_pdu_init(rsp_pdu, ic, NULL, NULL);
	/*
	 * StatSN is incremented by 1 for every response sent on
	 * a connection except for responses sent as a result of
	 * a retry or SNACK
	 */
	rsp_pdu->isp_flags |= IDM_PDU_SET_STATSN | IDM_PDU_ADVANCE_STATSN;

	resp = (iscsi_scsi_rsp_hdr_t *)rsp_pdu->isp_hdr;

	resp->opcode = ISCSI_OP_SCSI_RSP;
	resp->flags = ISCSI_FLAG_FINAL;
	resp->response = response;
	resp->cmd_status = cmd_status;
	resp->itt = req->itt;
	if ((response == ISCSI_STATUS_CMD_COMPLETED) &&
	    (req->data_length != 0) &&
	    ((req->flags & ISCSI_FLAG_CMD_READ) ||
	    (req->flags & ISCSI_FLAG_CMD_WRITE))) {
		resp->flags |= ISCSI_FLAG_CMD_UNDERFLOW;
		resp->residual_count = req->data_length;
	}

	DTRACE_PROBE4(iscsi__scsi__direct__response,
	    iscsit_conn_t *, ict,
	    uint8_t, resp->response,
	    uint8_t, resp->cmd_status,
	    idm_pdu_t *, rsp_pdu);

	iscsit_pdu_tx(rsp_pdu);
}

void
iscsit_send_task_mgmt_resp(idm_pdu_t *tm_resp_pdu, uint8_t tm_status)
{
	iscsi_scsi_task_mgt_rsp_hdr_t	*tm_resp;

	/*
	 * The target must take note of the last-sent StatSN.
	 * The StatSN is to be incremented after sending a
	 * task management response. Digest recovery can only
	 * work if StatSN is incremented.
	 */
	tm_resp_pdu->isp_flags |= IDM_PDU_SET_STATSN | IDM_PDU_ADVANCE_STATSN;
	tm_resp = (iscsi_scsi_task_mgt_rsp_hdr_t *)tm_resp_pdu->isp_hdr;
	tm_resp->response = tm_status;

	DTRACE_PROBE3(iscsi__scsi__tm__response,
	    iscsit_conn_t *, tm_resp_pdu->isp_ic->ic_handle,
	    uint8_t, tm_resp->response,
	    idm_pdu_t *, tm_resp_pdu);
	iscsit_pdu_tx(tm_resp_pdu);
}

void
iscsit_op_scsi_task_mgmt(iscsit_conn_t *ict, idm_pdu_t *rx_pdu)
{
	idm_pdu_t			*tm_resp_pdu;
	iscsit_task_t			*itask;
	iscsit_task_t			*tm_itask;
	scsi_task_t			*task;
	iscsi_scsi_task_mgt_hdr_t 	*iscsi_tm =
	    (iscsi_scsi_task_mgt_hdr_t *)rx_pdu->isp_hdr;
	iscsi_scsi_task_mgt_rsp_hdr_t 	*iscsi_tm_rsp =
	    (iscsi_scsi_task_mgt_rsp_hdr_t *)rx_pdu->isp_hdr;
	uint32_t			rtt, cmdsn, refcmdsn;
	uint8_t				tm_func;

	/*
	 * Setup response PDU (response field will get filled in later)
	 */
	tm_resp_pdu = idm_pdu_alloc(sizeof (iscsi_scsi_task_mgt_rsp_hdr_t), 0);
	if (tm_resp_pdu == NULL) {
		/* Can't respond, just drop it */
		idm_pdu_complete(rx_pdu, IDM_STATUS_SUCCESS);
		return;
	}
	idm_pdu_init(tm_resp_pdu, ict->ict_ic, NULL, NULL);
	iscsi_tm_rsp = (iscsi_scsi_task_mgt_rsp_hdr_t *)tm_resp_pdu->isp_hdr;
	bzero(iscsi_tm_rsp, sizeof (iscsi_scsi_task_mgt_rsp_hdr_t));
	iscsi_tm_rsp->opcode = ISCSI_OP_SCSI_TASK_MGT_RSP;
	iscsi_tm_rsp->flags = ISCSI_FLAG_FINAL;
	iscsi_tm_rsp->itt = rx_pdu->isp_hdr->itt;

	/*
	 * Figure out what we're being asked to do.
	 */
	DTRACE_PROBE4(iscsi__scsi__tm__request,
	    iscsit_conn_t *, ict,
	    uint8_t, (iscsi_tm->function & ISCSI_FLAG_TASK_MGMT_FUNCTION_MASK),
	    uint32_t, iscsi_tm->rtt,
	    idm_pdu_t *, rx_pdu);
	switch (iscsi_tm->function & ISCSI_FLAG_TASK_MGMT_FUNCTION_MASK) {
	case ISCSI_TM_FUNC_ABORT_TASK:
		/*
		 * STMF doesn't currently support the "abort task" task
		 * management command although it does support aborting
		 * an individual task.  We'll get STMF to abort the task
		 * for us but handle the details of the task management
		 * command ourselves.
		 *
		 * Find the task associated with the referenced task tag.
		 */
		rtt = iscsi_tm->rtt;
		itask = (iscsit_task_t *)idm_task_find_by_handle(ict->ict_ic,
		    (uintptr_t)rtt);

		if (itask == NULL) {
			cmdsn = ntohl(iscsi_tm->cmdsn);
			refcmdsn = ntohl(iscsi_tm->refcmdsn);

			/*
			 * Task was not found. But the SCSI command could be
			 * on the rxpdu wait queue. If RefCmdSN is within
			 * the CmdSN window and less than CmdSN of the TM
			 * function, return "Function Complete". Otherwise,
			 * return "Task Does Not Exist".
			 */

			if (iscsit_cmdsn_in_window(ict, refcmdsn) &&
			    iscsit_sna_lt(refcmdsn, cmdsn)) {
				mutex_enter(&ict->ict_sess->ist_sn_mutex);
				(void) iscsit_remove_pdu_from_queue(
				    ict->ict_sess, refcmdsn);
				iscsit_conn_dispatch_rele(ict);
				mutex_exit(&ict->ict_sess->ist_sn_mutex);
				iscsit_send_task_mgmt_resp(tm_resp_pdu,
				    SCSI_TCP_TM_RESP_COMPLETE);
			} else {
				iscsit_send_task_mgmt_resp(tm_resp_pdu,
				    SCSI_TCP_TM_RESP_NO_TASK);
			}
		} else {

			/*
			 * Tell STMF to abort the task.  This will do no harm
			 * if the task is already complete.
			 */
			stmf_abort(STMF_QUEUE_TASK_ABORT, itask->it_stmf_task,
			    STMF_ABORTED, NULL);

			/*
			 * Make sure the task hasn't already completed
			 */
			mutex_enter(&itask->it_idm_task->idt_mutex);
			if ((itask->it_idm_task->idt_state == TASK_COMPLETE) ||
			    (itask->it_idm_task->idt_state == TASK_IDLE)) {
				/*
				 * Task is complete, return "Task Does Not
				 * Exist"
				 */
				mutex_exit(&itask->it_idm_task->idt_mutex);
				iscsit_send_task_mgmt_resp(tm_resp_pdu,
				    SCSI_TCP_TM_RESP_NO_TASK);
			} else {
				/*
				 * STMF is now aborting the task, return
				 * "Function Complete"
				 */
				mutex_exit(&itask->it_idm_task->idt_mutex);
				iscsit_send_task_mgmt_resp(tm_resp_pdu,
				    SCSI_TCP_TM_RESP_COMPLETE);
			}
			idm_task_rele(itask->it_idm_task);
		}
		idm_pdu_complete(rx_pdu, IDM_STATUS_SUCCESS);
		return;

	case ISCSI_TM_FUNC_ABORT_TASK_SET:
		tm_func = TM_ABORT_TASK_SET;
		break;

	case ISCSI_TM_FUNC_CLEAR_ACA:
		tm_func = TM_CLEAR_ACA;
		break;

	case ISCSI_TM_FUNC_CLEAR_TASK_SET:
		tm_func = TM_CLEAR_TASK_SET;
		break;

	case ISCSI_TM_FUNC_LOGICAL_UNIT_RESET:
		tm_func = TM_LUN_RESET;
		break;

	case ISCSI_TM_FUNC_TARGET_WARM_RESET:
		tm_func = TM_TARGET_WARM_RESET;
		break;

	case ISCSI_TM_FUNC_TARGET_COLD_RESET:
		tm_func = TM_TARGET_COLD_RESET;
		break;

	case ISCSI_TM_FUNC_TASK_REASSIGN:
		/*
		 * We do not currently support allegiance reassignment.  When
		 * we start supporting ERL1+, we will need to.
		 */
		iscsit_send_task_mgmt_resp(tm_resp_pdu,
		    SCSI_TCP_TM_RESP_NO_ALLG_REASSN);
		idm_pdu_complete(rx_pdu, IDM_STATUS_SUCCESS);
		return;

	default:
		iscsit_send_task_mgmt_resp(tm_resp_pdu,
		    SCSI_TCP_TM_RESP_REJECTED);
		idm_pdu_complete(rx_pdu, IDM_STATUS_SUCCESS);
		return;
	}

	tm_itask = iscsit_tm_task_alloc(ict);
	if (tm_itask == NULL) {
		iscsit_send_task_mgmt_resp(tm_resp_pdu,
		    SCSI_TCP_TM_RESP_REJECTED);
		idm_pdu_complete(rx_pdu, IDM_STATUS_SUCCESS);
		return;
	}


	task = stmf_task_alloc(ict->ict_sess->ist_lport,
	    ict->ict_sess->ist_stmf_sess, iscsi_tm->lun,
	    0, STMF_TASK_EXT_NONE);
	if (task == NULL) {
		/*
		 * If this happens, either the LU is in reset, couldn't
		 * get memory, or some other condition in which we simply
		 * can't complete this request.  It would be nice to return
		 * an error code like "busy" but the closest we have is
		 * "rejected".
		 */
		iscsit_send_task_mgmt_resp(tm_resp_pdu,
		    SCSI_TCP_TM_RESP_REJECTED);
		iscsit_tm_task_free(tm_itask);
		idm_pdu_complete(rx_pdu, IDM_STATUS_SUCCESS);
		return;
	}

	tm_itask->it_tm_pdu = tm_resp_pdu;
	tm_itask->it_stmf_task = task;
	task->task_port_private = tm_itask;
	task->task_mgmt_function = tm_func;
	task->task_additional_flags = TASK_AF_NO_EXPECTED_XFER_LENGTH;
	task->task_priority = 0;
	task->task_max_nbufs = STMF_BUFS_MAX;
	task->task_cmd_seq_no = iscsi_tm->itt;
	task->task_expected_xfer_length = 0;

	stmf_post_task(task, NULL);
	idm_pdu_complete(rx_pdu, IDM_STATUS_SUCCESS);
}

static void
iscsit_pdu_op_noop(iscsit_conn_t *ict, idm_pdu_t *rx_pdu)
{
	iscsi_nop_out_hdr_t *out = (iscsi_nop_out_hdr_t *)rx_pdu->isp_hdr;
	iscsi_nop_in_hdr_t *in;
	int resp_datalen;
	idm_pdu_t *resp;

	/* Ignore the response from initiator */
	if ((out->itt == ISCSI_RSVD_TASK_TAG) ||
	    (out->ttt != ISCSI_RSVD_TASK_TAG)) {
		idm_pdu_complete(rx_pdu, IDM_STATUS_SUCCESS);
		return;
	}

	/* Allocate a PDU to respond */
	resp_datalen = ntoh24(out->dlength);
	resp = idm_pdu_alloc(sizeof (iscsi_hdr_t), resp_datalen);
	idm_pdu_init(resp, ict->ict_ic, NULL, NULL);
	if (resp_datalen > 0) {
		bcopy(rx_pdu->isp_data, resp->isp_data, resp_datalen);
	}

	/*
	 * When sending a NOP-In as a response to a NOP-Out from the initiator,
	 * the target must respond with the same initiator task tag that was
	 * provided in the NOP-Out request, the target transfer tag must be
	 * ISCSI_RSVD_TASK_TAG (0xffffffff) and StatSN will contain the next
	 * status sequence number. The StatSN for the connection is advanced
	 * after this PDU is sent.
	 */
	in = (iscsi_nop_in_hdr_t *)resp->isp_hdr;
	bzero(in, sizeof (*in));
	in->opcode = ISCSI_OP_NOOP_IN;
	in->flags = ISCSI_FLAG_FINAL;
	bcopy(out->lun, in->lun, 8);
	in->itt		= out->itt;
	in->ttt		= ISCSI_RSVD_TASK_TAG;
	hton24(in->dlength, resp_datalen);
	resp->isp_flags |= IDM_PDU_SET_STATSN | IDM_PDU_ADVANCE_STATSN;
	/* Any other field in resp to be set? */
	iscsit_pdu_tx(resp);
	idm_pdu_complete(rx_pdu, IDM_STATUS_SUCCESS);
}

static void
iscsit_pdu_op_login_cmd(iscsit_conn_t	*ict, idm_pdu_t *rx_pdu)
{

	/*
	 * Submit PDU to login state machine.  State machine will free the
	 * PDU.
	 */
	iscsit_login_sm_event(ict, ILE_LOGIN_RCV, rx_pdu);
}

void
iscsit_pdu_op_logout_cmd(iscsit_conn_t	*ict, idm_pdu_t *rx_pdu)
{
	iscsi_logout_hdr_t 	*logout_req =
	    (iscsi_logout_hdr_t *)rx_pdu->isp_hdr;
	iscsi_logout_rsp_hdr_t	*logout_rsp;
	idm_pdu_t *resp;

	/* Allocate a PDU to respond */
	resp = idm_pdu_alloc(sizeof (iscsi_hdr_t), 0);
	idm_pdu_init(resp, ict->ict_ic, NULL, NULL);
	/*
	 * The StatSN is to be sent to the initiator,
	 * it is not required to increment the number
	 * as the connection is terminating.
	 */
	resp->isp_flags |= IDM_PDU_SET_STATSN;
	/*
	 * Logout results in the immediate termination of all tasks except
	 * if the logout reason is ISCSI_LOGOUT_REASON_RECOVERY.  The
	 * connection state machine will drive this task cleanup automatically
	 * so we don't need to handle that here.
	 */
	logout_rsp = (iscsi_logout_rsp_hdr_t *)resp->isp_hdr;
	bzero(logout_rsp, sizeof (*logout_rsp));
	logout_rsp->opcode = ISCSI_OP_LOGOUT_RSP;
	logout_rsp->flags = ISCSI_FLAG_FINAL;
	logout_rsp->itt = logout_req->itt;
	if ((logout_req->flags & ISCSI_FLAG_LOGOUT_REASON_MASK) >
	    ISCSI_LOGOUT_REASON_RECOVERY) {
		logout_rsp->response = ISCSI_LOGOUT_RECOVERY_UNSUPPORTED;
	} else {
		logout_rsp->response = ISCSI_LOGOUT_SUCCESS;
	}

	iscsit_pdu_tx(resp);
	idm_pdu_complete(rx_pdu, IDM_STATUS_SUCCESS);
}

/*
 * Calculate the number of outstanding commands we can process
 */
int
iscsit_cmd_window()
{
	/*
	 * Instead of using a pre-defined constant for the command window,
	 * it should be made confiurable and dynamic. With MC/S, sequence
	 * numbers will be used up at a much faster rate than with SC/S.
	 */
	return	(ISCSIT_MAX_WINDOW);
}

/*
 * Set local registers based on incoming PDU
 */
void
iscsit_set_cmdsn(iscsit_conn_t *ict, idm_pdu_t *rx_pdu)
{
	iscsit_sess_t *ist;
	iscsi_scsi_cmd_hdr_t *req;

	ist = ict->ict_sess;

	req = (iscsi_scsi_cmd_hdr_t *)rx_pdu->isp_hdr;
	if (req->opcode & ISCSI_OP_IMMEDIATE) {
		/* no cmdsn increment for immediate PDUs */
		return;
	}

	/* Ensure that the ExpCmdSN advances in an orderly manner */
	mutex_enter(&ist->ist_sn_mutex);
	ist->ist_expcmdsn = ntohl(req->cmdsn) + 1;
	ist->ist_maxcmdsn = ntohl(req->cmdsn) + iscsit_cmd_window();
	mutex_exit(&ist->ist_sn_mutex);
}

/*
 * Wrapper funtion, calls iscsi_calc_rspsn and idm_pdu_tx
 */
void
iscsit_pdu_tx(idm_pdu_t *pdu)
{
	iscsit_conn_t *ict = pdu->isp_ic->ic_handle;
	iscsi_scsi_rsp_hdr_t *rsp = (iscsi_scsi_rsp_hdr_t *)pdu->isp_hdr;
	iscsit_sess_t *ist = ict->ict_sess;

	/*
	 * The command sequence numbers are session-wide and must stay
	 * consistent across the transfer, so protect the cmdsn with a
	 * mutex lock on the session. The status sequence number will
	 * be updated just before the transport layer transmits the PDU.
	 */

	mutex_enter(&ict->ict_sess->ist_sn_mutex);
	/* Set ExpCmdSN and MaxCmdSN */
	rsp->maxcmdsn = htonl(ist->ist_maxcmdsn);
	rsp->expcmdsn = htonl(ist->ist_expcmdsn);
	idm_pdu_tx(pdu);
	mutex_exit(&ict->ict_sess->ist_sn_mutex);
}

/*
 * Internal functions
 */

void
iscsit_send_async_event(iscsit_conn_t *ict, uint8_t event)
{
	idm_pdu_t		*abt;
	iscsi_async_evt_hdr_t	*async_abt;

	/*
	 * Get a PDU to build the abort request.
	 */
	abt = idm_pdu_alloc(sizeof (iscsi_hdr_t), 0);
	if (abt == NULL) {
		idm_conn_event(ict->ict_ic, CE_TRANSPORT_FAIL, NULL);
		return;
	}

	/*
	 * A asynchronous message is sent by the target to request a logout.
	 * The StatSN for the connection is advanced after the PDU is sent
	 * to allow for initiator and target state synchronization.
	 */
	idm_pdu_init(abt, ict->ict_ic, NULL, NULL);
	abt->isp_datalen = 0;
	abt->isp_flags |= IDM_PDU_SET_STATSN | IDM_PDU_ADVANCE_STATSN;

	async_abt = (iscsi_async_evt_hdr_t *)abt->isp_hdr;
	bzero(async_abt, sizeof (*async_abt));
	async_abt->opcode = ISCSI_OP_ASYNC_EVENT;
	async_abt->async_event = event;
	async_abt->flags = ISCSI_FLAG_FINAL;
	async_abt->rsvd4[0] = 0xff;
	async_abt->rsvd4[1] = 0xff;
	async_abt->rsvd4[2] = 0xff;
	async_abt->rsvd4[3] = 0xff;

	switch (event) {
	case ISCSI_ASYNC_EVENT_REQUEST_LOGOUT:
		async_abt->param3 = htons(IDM_LOGOUT_SECONDS);
		break;
	case ISCSI_ASYNC_EVENT_SCSI_EVENT:
	case ISCSI_ASYNC_EVENT_DROPPING_CONNECTION:
	case ISCSI_ASYNC_EVENT_DROPPING_ALL_CONNECTIONS:
	case ISCSI_ASYNC_EVENT_PARAM_NEGOTIATION:
	default:
		ASSERT(0);
	}

	iscsit_pdu_tx(abt);
}

void
iscsit_send_reject(iscsit_conn_t *ict, idm_pdu_t *rejected_pdu, uint8_t reason)
{
	idm_pdu_t		*reject_pdu;
	iscsi_reject_rsp_hdr_t	*reject;

	/*
	 * Get a PDU to build the abort request.
	 */
	reject_pdu = idm_pdu_alloc(sizeof (iscsi_hdr_t),
	    rejected_pdu->isp_hdrlen);
	if (reject_pdu == NULL) {
		idm_conn_event(ict->ict_ic, CE_TRANSPORT_FAIL, NULL);
		return;
	}
	idm_pdu_init(reject_pdu, ict->ict_ic, NULL, NULL);
	/* StatSN is advanced after a Reject PDU */
	reject_pdu->isp_flags |= IDM_PDU_SET_STATSN | IDM_PDU_ADVANCE_STATSN;
	reject_pdu->isp_datalen = rejected_pdu->isp_hdrlen;
	bcopy(rejected_pdu->isp_hdr, reject_pdu->isp_data,
	    rejected_pdu->isp_hdrlen);

	reject = (iscsi_reject_rsp_hdr_t *)reject_pdu->isp_hdr;
	bzero(reject, sizeof (*reject));
	reject->opcode = ISCSI_OP_REJECT_MSG;
	reject->reason = reason;
	reject->flags = ISCSI_FLAG_FINAL;
	hton24(reject->dlength, rejected_pdu->isp_hdrlen);
	reject->must_be_ff[0] = 0xff;
	reject->must_be_ff[1] = 0xff;
	reject->must_be_ff[2] = 0xff;
	reject->must_be_ff[3] = 0xff;

	iscsit_pdu_tx(reject_pdu);
}


static iscsit_task_t *
iscsit_task_alloc(iscsit_conn_t *ict)
{
	iscsit_task_t *itask;
	iscsit_buf_t *immed_ibuf;

	/*
	 * Possible items to pre-alloc if we cache iscsit_task_t's:
	 *
	 * Status PDU w/ sense buffer
	 * stmf_data_buf_t for immediate data
	 */
	itask = kmem_alloc(sizeof (iscsit_task_t) + sizeof (iscsit_buf_t) +
	    sizeof (stmf_data_buf_t), KM_NOSLEEP);
	if (itask != NULL) {
		mutex_init(&itask->it_mutex, NULL, MUTEX_DRIVER, NULL);
		itask->it_aborted = itask->it_stmf_abort =
		    itask->it_tm_task = 0;

		immed_ibuf = (iscsit_buf_t *)(itask + 1);
		bzero(immed_ibuf, sizeof (*immed_ibuf));
		immed_ibuf->ibuf_is_immed = B_TRUE;
		immed_ibuf->ibuf_stmf_buf = (stmf_data_buf_t *)(immed_ibuf + 1);

		bzero(immed_ibuf->ibuf_stmf_buf, sizeof (stmf_data_buf_t));
		immed_ibuf->ibuf_stmf_buf->db_port_private = immed_ibuf;
		immed_ibuf->ibuf_stmf_buf->db_sglist_length = 1;
		immed_ibuf->ibuf_stmf_buf->db_flags = DB_DIRECTION_FROM_RPORT |
		    DB_DONT_CACHE;
		itask->it_immed_data = immed_ibuf;
		itask->it_idm_task = idm_task_alloc(ict->ict_ic);
		if (itask->it_idm_task != NULL) {
			itask->it_idm_task->idt_private = itask;
			itask->it_ict = ict;
			itask->it_ttt = itask->it_idm_task->idt_tt;
			return (itask);
		} else {
			kmem_free(itask, sizeof (iscsit_task_t) +
			    sizeof (iscsit_buf_t) + sizeof (stmf_data_buf_t));
		}
	}

	return (NULL);
}

static void
iscsit_task_free(iscsit_task_t *itask)
{
	idm_task_free(itask->it_idm_task);
	mutex_destroy(&itask->it_mutex);
	kmem_free(itask, sizeof (iscsit_task_t) +
	    sizeof (iscsit_buf_t) + sizeof (stmf_data_buf_t));
}

static iscsit_task_t *
iscsit_tm_task_alloc(iscsit_conn_t *ict)
{
	iscsit_task_t *itask;

	itask = kmem_zalloc(sizeof (iscsit_task_t), KM_NOSLEEP);
	if (itask != NULL) {
		idm_conn_hold(ict->ict_ic);
		mutex_init(&itask->it_mutex, NULL, MUTEX_DRIVER, NULL);
		itask->it_aborted = itask->it_stmf_abort =
		    itask->it_tm_responded = 0;
		itask->it_tm_pdu = NULL;
		itask->it_tm_task = 1;
		itask->it_ict = ict;
	}

	return (itask);
}

static void
iscsit_tm_task_free(iscsit_task_t *itask)
{
	/*
	 * If we responded then the call to idm_pdu_complete will free the
	 * PDU.  Otherwise we got aborted before the TM function could
	 * complete and we need to free the PDU explicitly.
	 */
	if (itask->it_tm_pdu != NULL && !itask->it_tm_responded)
		idm_pdu_free(itask->it_tm_pdu);
	idm_conn_rele(itask->it_ict->ict_ic);
	mutex_destroy(&itask->it_mutex);
	kmem_free(itask, sizeof (iscsit_task_t));
}

static idm_status_t
iscsit_task_start(iscsit_task_t *itask)
{
	iscsit_sess_t *ist = itask->it_ict->ict_sess;
	avl_index_t		where;

	/*
	 * Sanity check the ITT and ensure that this task does not already
	 * exist.  If not then add the task to the session task list.
	 */
	mutex_enter(&ist->ist_mutex);
	mutex_enter(&itask->it_mutex);
	itask->it_active = 1;
	if (avl_find(&ist->ist_task_list, itask, &where) == NULL) {
		/* New task, add to AVL */
		avl_insert(&ist->ist_task_list, itask, where);
		mutex_exit(&itask->it_mutex);
		mutex_exit(&ist->ist_mutex);
		return (IDM_STATUS_SUCCESS);
	}
	mutex_exit(&itask->it_mutex);
	mutex_exit(&ist->ist_mutex);

	return (IDM_STATUS_REJECT);
}

static void
iscsit_task_done(iscsit_task_t *itask)
{
	iscsit_sess_t *ist = itask->it_ict->ict_sess;

	mutex_enter(&ist->ist_mutex);
	mutex_enter(&itask->it_mutex);
	if (itask->it_active) {
		avl_remove(&ist->ist_task_list, itask);
		itask->it_active = 0;
	}
	mutex_exit(&itask->it_mutex);
	mutex_exit(&ist->ist_mutex);
}

/*
 * iscsit status PDU cache
 */

/*ARGSUSED*/
static int
iscsit_status_pdu_constructor(void *pdu_void, void *arg, int flags)
{
	idm_pdu_t *pdu = pdu_void;
	iscsi_scsi_rsp_hdr_t *rsp;

	bzero(pdu, sizeof (idm_pdu_t));
	pdu->isp_callback = iscsit_send_good_status_done;
	pdu->isp_magic = IDM_PDU_MAGIC;
	pdu->isp_hdr = (iscsi_hdr_t *)(pdu + 1); /* Ptr arithmetic */
	pdu->isp_hdrlen = sizeof (iscsi_hdr_t);

	/* Setup status response */
	rsp = (iscsi_scsi_rsp_hdr_t *)pdu->isp_hdr;
	bzero(rsp, sizeof (*rsp));
	rsp->opcode = ISCSI_OP_SCSI_RSP;
	rsp->flags = ISCSI_FLAG_FINAL;
	rsp->response = ISCSI_STATUS_CMD_COMPLETED;

	return (0);
}

/*
 * iscsit private data handler
 */

/*ARGSUSED*/
static void
iscsit_pp_cb(struct stmf_port_provider *pp, int cmd, void *arg, uint32_t flags)
{
	it_config_t		*cfg;
	nvlist_t		*nvl;
	iscsit_service_enabled_t	old_state;

	if ((cmd != STMF_PROVIDER_DATA_UPDATED) || (arg == NULL)) {
		return;
	}

	nvl = (nvlist_t *)arg;

	/* Translate nvlist */
	if (it_nv_to_config(nvl, &cfg) != 0) {
		cmn_err(CE_WARN, "Configuration is invalid");
		return;
	}

	/* Check that no iSCSI ioctl is currently running */
	mutex_enter(&iscsit_global.global_state_mutex);
	old_state = iscsit_global.global_svc_state;
	switch (iscsit_global.global_svc_state) {
	case ISE_ENABLED:
	case ISE_DISABLED:
		iscsit_global.global_svc_state = ISE_BUSY;
		break;
	case ISE_ENABLING:
		/*
		 * It is OK for the iscsit_pp_cb to be called from inside of
		 * an iSCSI ioctl only if we are currently executing inside
		 * of stmf_register_port_provider.
		 */
		ASSERT((flags & STMF_PCB_PREG_COMPLETE) != 0);
		break;
	default:
		cmn_err(CE_WARN, "iscsit_pp_cb called when global_svc_state"
		    " is not ENABLED(0x%x) -- ignoring",
		    iscsit_global.global_svc_state);
		mutex_exit(&iscsit_global.global_state_mutex);
		it_config_free_cmn(cfg);
		return;
	}
	mutex_exit(&iscsit_global.global_state_mutex);

	/* Update config */
	(void) iscsit_config_merge(cfg);

	it_config_free_cmn(cfg);

	/* Restore old iSCSI driver global state */
	mutex_enter(&iscsit_global.global_state_mutex);
	ASSERT(iscsit_global.global_svc_state == ISE_BUSY ||
	    iscsit_global.global_svc_state == ISE_ENABLING);
	iscsit_global.global_svc_state = old_state;
	mutex_exit(&iscsit_global.global_state_mutex);
}


static it_cfg_status_t
iscsit_config_merge(it_config_t *in_cfg)
{
	it_cfg_status_t	status;
	it_config_t	*cfg;
	it_config_t	tmp_cfg;
	list_t		tpg_del_list;

	if (in_cfg) {
		cfg = in_cfg;
	} else {
		/* Make empty config */
		bzero(&tmp_cfg, sizeof (tmp_cfg));
		cfg = &tmp_cfg;
	}

	list_create(&tpg_del_list,  sizeof (iscsit_tpg_t),
	    offsetof(iscsit_tpg_t, tpg_delete_ln));

	/*
	 * Update targets, initiator contexts, target portal groups,
	 * and iSNS client
	 */
	ISCSIT_GLOBAL_LOCK(RW_WRITER);
	if (((status = iscsit_config_merge_tpg(cfg, &tpg_del_list))
	    != 0) ||
	    ((status = iscsit_config_merge_tgt(cfg)) != 0) ||
	    ((status = iscsit_config_merge_ini(cfg)) != 0) ||
	    ((status = isnst_config_merge(cfg)) != 0)) {
		ISCSIT_GLOBAL_UNLOCK();
		return (status);
	}

	/* Update other global config parameters */
	if (iscsit_global.global_props) {
		nvlist_free(iscsit_global.global_props);
		iscsit_global.global_props = NULL;
	}
	if (in_cfg) {
		(void) nvlist_dup(cfg->config_global_properties,
		    &iscsit_global.global_props, KM_SLEEP);
	}
	ISCSIT_GLOBAL_UNLOCK();

	iscsit_config_destroy_tpgs(&tpg_del_list);

	list_destroy(&tpg_del_list);

	return (ITCFG_SUCCESS);
}

/*
 * iscsit_sna_lt[e]
 *
 * Compare serial numbers using serial number arithmetic as defined in
 * RFC 1982.
 *
 * NOTE: This code is duplicated in the isns server. It ought to be common.
 */

static int
iscsit_sna_lt(uint32_t sn1, uint32_t sn2)
{
	return ((sn1 != sn2) &&
	    (((sn1 < sn2) && ((sn2 - sn1) < ISCSIT_SNA32_CHECK)) ||
	    ((sn1 > sn2) && ((sn1 - sn2) > ISCSIT_SNA32_CHECK))));
}

static int
iscsit_sna_lte(uint32_t sn1, uint32_t sn2)
{
	return ((sn1 == sn2) ||
	    (((sn1 < sn2) && ((sn2 - sn1) < ISCSIT_SNA32_CHECK)) ||
	    ((sn1 > sn2) && ((sn1 - sn2) > ISCSIT_SNA32_CHECK))));
}


static boolean_t
iscsit_cmdsn_in_window(iscsit_conn_t *ict, uint32_t cmdsn)
{
	iscsit_sess_t	*ist = ict->ict_sess;
	int		rval = B_TRUE;

	ist = ict->ict_sess;

	mutex_enter(&ist->ist_sn_mutex);

	/*
	 * If cmdsn is less than ist_expcmdsn - iscsit_cmd_window() or
	 * greater than ist_expcmdsn, it's not in the window.
	 */

	if (iscsit_sna_lt(cmdsn, (ist->ist_expcmdsn - iscsit_cmd_window())) ||
	    !iscsit_sna_lte(cmdsn, ist->ist_expcmdsn)) {
		rval = B_FALSE;
	}

	mutex_exit(&ist->ist_sn_mutex);

	return (rval);
}

/*
 * iscsit_check_cmdsn_and_queue
 *
 * Independent of the order in which the iSCSI target receives non-immediate
 * command PDU across the entire session and any multiple connections within
 * the session, the target must deliver the commands to the SCSI layer in
 * CmdSN order. So out-of-order non-immediate commands are queued up on a
 * session-wide wait queue. Duplicate commands are ignored.
 *
 */
static int
iscsit_check_cmdsn_and_queue(idm_pdu_t *rx_pdu)
{
	idm_conn_t		*ic = rx_pdu->isp_ic;
	iscsit_conn_t		*ict = ic->ic_handle;
	iscsit_sess_t		*ist = ict->ict_sess;
	iscsi_scsi_cmd_hdr_t	*hdr = (iscsi_scsi_cmd_hdr_t *)rx_pdu->isp_hdr;

	mutex_enter(&ist->ist_sn_mutex);
	if (hdr->opcode & ISCSI_OP_IMMEDIATE) {
		/* do not queue, handle it immediately */
		DTRACE_PROBE2(immediate__cmd, iscsit_sess_t *, ist,
		    idm_pdu_t *, rx_pdu);
		mutex_exit(&ist->ist_sn_mutex);
		return (ISCSIT_CMDSN_EQ_EXPCMDSN);
	}
	if (iscsit_sna_lt(ist->ist_expcmdsn, ntohl(hdr->cmdsn))) {
		/*
		 * Out-of-order commands (cmdSN higher than ExpCmdSN)
		 * are staged on a fixed-size circular buffer until
		 * the missing command is delivered to the SCSI layer.
		 * Irrespective of the order of insertion into the
		 * staging queue, the commands are processed out of the
		 * queue in cmdSN order only.
		 */
		rx_pdu->isp_queue_time = ddi_get_time();
		iscsit_add_pdu_to_queue(ist, rx_pdu);
		mutex_exit(&ist->ist_sn_mutex);
		return (ISCSIT_CMDSN_GT_EXPCMDSN);
	} else if (iscsit_sna_lt(ntohl(hdr->cmdsn), ist->ist_expcmdsn)) {
		DTRACE_PROBE3(cmdsn__lt__expcmdsn, iscsit_sess_t *, ist,
		    iscsit_conn_t *, ict, idm_pdu_t *, rx_pdu);
		mutex_exit(&ist->ist_sn_mutex);
		return (ISCSIT_CMDSN_LT_EXPCMDSN);
	} else {
		mutex_exit(&ist->ist_sn_mutex);
		return (ISCSIT_CMDSN_EQ_EXPCMDSN);
	}
}

/*
 * iscsit_add_pdu_to_queue() adds PDUs into the array indexed by
 * their cmdsn value. The length of the array is kept above the
 * maximum window size. The window keeps the cmdsn within a range
 * such that there are no collisons. e.g. the assumption is that
 * the windowing checks make it impossible to receive PDUs that
 * index into the same location in the array.
 */
static void
iscsit_add_pdu_to_queue(iscsit_sess_t *ist, idm_pdu_t *rx_pdu)
{
	iscsit_cbuf_t	*cbuf	= ist->ist_rxpdu_queue;
	iscsit_conn_t	*ict 	= rx_pdu->isp_ic->ic_handle;
	uint32_t	cmdsn	=
	    ((iscsi_scsi_cmd_hdr_t *)rx_pdu->isp_hdr)->cmdsn;
	uint32_t	index;

	ASSERT(MUTEX_HELD(&ist->ist_sn_mutex));
	/*
	 * If the connection is being torn down, then
	 * don't add the PDU to the staging queue
	 */
	mutex_enter(&ict->ict_mutex);
	if (ict->ict_lost) {
		mutex_exit(&ict->ict_mutex);
		idm_pdu_complete(rx_pdu, IDM_STATUS_FAIL);
		return;
	}
	iscsit_conn_dispatch_hold(ict);
	mutex_exit(&ict->ict_mutex);

	index = ntohl(cmdsn) % ISCSIT_RXPDU_QUEUE_LEN;
	/*
	 * In the normal case, assuming that the Initiator is not
	 * buggy and that we don't have packet duplication occuring,
	 * the entry in the array will be NULL.  However, we may have
	 * received a duplicate PDU with cmdsn > expsn , and in that
	 * case we just ignore this PDU -- the previously received one
	 * remains queued for processing.  We need to be careful not
	 * to leak this one however.
	 */
	if (cbuf->cb_buffer[index] != NULL) {
		idm_pdu_complete(rx_pdu, IDM_STATUS_FAIL);
	} else {
		cbuf->cb_buffer[index] = rx_pdu;
		cbuf->cb_num_elems++;
	}
}

static idm_pdu_t *
iscsit_remove_pdu_from_queue(iscsit_sess_t *ist, uint32_t cmdsn)
{
	iscsit_cbuf_t	*cbuf	= ist->ist_rxpdu_queue;
	idm_pdu_t	*pdu	= NULL;
	uint32_t	index;

	ASSERT(MUTEX_HELD(&ist->ist_sn_mutex));
	index = cmdsn % ISCSIT_RXPDU_QUEUE_LEN;
	if ((pdu = cbuf->cb_buffer[index]) != NULL) {
		ASSERT(cmdsn ==
		    ntohl(((iscsi_scsi_cmd_hdr_t *)pdu->isp_hdr)->cmdsn));
		cbuf->cb_buffer[index] = NULL;
		cbuf->cb_num_elems--;
		return (pdu);
	}
	return (NULL);
}

/*
 * iscsit_process_pdu_in_queue() finds the next pdu in sequence
 * and posts it to the SCSI layer
 */
static void
iscsit_process_pdu_in_queue(iscsit_sess_t *ist)
{
	iscsit_cbuf_t	*cbuf	= ist->ist_rxpdu_queue;
	idm_pdu_t	*pdu = NULL;
	uint32_t	expcmdsn;

	for (;;) {
		mutex_enter(&ist->ist_sn_mutex);
		if (cbuf->cb_num_elems == 0) {
			mutex_exit(&ist->ist_sn_mutex);
			break;
		}
		expcmdsn = ist->ist_expcmdsn;
		if ((pdu = iscsit_remove_pdu_from_queue(ist, expcmdsn))
		    == NULL) {
			mutex_exit(&ist->ist_sn_mutex);
			break;
		}
		mutex_exit(&ist->ist_sn_mutex);
		iscsit_post_staged_pdu(pdu);
	}
}

static void
iscsit_post_staged_pdu(idm_pdu_t *rx_pdu)
{
	iscsit_conn_t	*ict	= rx_pdu->isp_ic->ic_handle;

	/* Post the PDU to the SCSI layer */
	switch (IDM_PDU_OPCODE(rx_pdu)) {
	case ISCSI_OP_NOOP_OUT:
		iscsit_set_cmdsn(ict, rx_pdu);
		iscsit_pdu_op_noop(ict, rx_pdu);
		break;
	case ISCSI_OP_TEXT_CMD:
		iscsit_set_cmdsn(ict, rx_pdu);
		iscsit_pdu_op_text_cmd(ict, rx_pdu);
		break;
	case ISCSI_OP_SCSI_TASK_MGT_MSG:
		iscsit_set_cmdsn(ict, rx_pdu);
		iscsit_op_scsi_task_mgmt(ict, rx_pdu);
		break;
	case ISCSI_OP_SCSI_CMD:
		/* cmdSN will be incremented after creating itask */
		iscsit_post_scsi_cmd(rx_pdu->isp_ic, rx_pdu);
		break;
	case ISCSI_OP_LOGOUT_CMD:
		iscsit_set_cmdsn(ict, rx_pdu);
		iscsit_pdu_op_logout_cmd(ict, rx_pdu);
		break;
	default:
		/* No other PDUs should be placed on the queue */
		ASSERT(0);
	}
	iscsit_conn_dispatch_rele(ict); /* release hold on the conn */
}

/* ARGSUSED */
void
iscsit_rxpdu_queue_monitor_start(void)
{
	mutex_enter(&iscsit_rxpdu_queue_monitor_mutex);
	if (iscsit_rxpdu_queue_monitor_thr_running) {
		mutex_exit(&iscsit_rxpdu_queue_monitor_mutex);
		return;
	}
	iscsit_rxpdu_queue_monitor_thr_id =
	    thread_create(NULL, 0, iscsit_rxpdu_queue_monitor, NULL,
	    0, &p0, TS_RUN, minclsyspri);
	while (!iscsit_rxpdu_queue_monitor_thr_running) {
		cv_wait(&iscsit_rxpdu_queue_monitor_cv,
		    &iscsit_rxpdu_queue_monitor_mutex);
	}
	mutex_exit(&iscsit_rxpdu_queue_monitor_mutex);

}

/* ARGSUSED */
void
iscsit_rxpdu_queue_monitor_stop(void)
{
	mutex_enter(&iscsit_rxpdu_queue_monitor_mutex);
	if (iscsit_rxpdu_queue_monitor_thr_running) {
		iscsit_rxpdu_queue_monitor_thr_running = B_FALSE;
		cv_signal(&iscsit_rxpdu_queue_monitor_cv);
		mutex_exit(&iscsit_rxpdu_queue_monitor_mutex);

		thread_join(iscsit_rxpdu_queue_monitor_thr_did);
		return;
	}
	mutex_exit(&iscsit_rxpdu_queue_monitor_mutex);
}

/*
 * A separate thread is used to scan the staging queue on all the
 * sessions, If a delayed PDU does not arrive within a timeout, the
 * target will advance to the staged PDU that is next in sequence
 * and exceeded the threshold wait time. It is up to the initiator
 * to note that the target has not acknowledged a particular cmdsn
 * and take appropriate action.
 */
/* ARGSUSED */
static void
iscsit_rxpdu_queue_monitor(void *arg)
{
	iscsit_tgt_t	*tgt;
	iscsit_sess_t	*ist;

	mutex_enter(&iscsit_rxpdu_queue_monitor_mutex);
	iscsit_rxpdu_queue_monitor_thr_did = curthread->t_did;
	iscsit_rxpdu_queue_monitor_thr_running = B_TRUE;
	cv_signal(&iscsit_rxpdu_queue_monitor_cv);

	while (iscsit_rxpdu_queue_monitor_thr_running) {
		ISCSIT_GLOBAL_LOCK(RW_READER);
		for (tgt = avl_first(&iscsit_global.global_target_list);
		    tgt != NULL;
		    tgt = AVL_NEXT(&iscsit_global.global_target_list, tgt)) {
			mutex_enter(&tgt->target_mutex);
			for (ist = avl_first(&tgt->target_sess_list);
			    ist != NULL;
			    ist = AVL_NEXT(&tgt->target_sess_list, ist)) {

				iscsit_rxpdu_queue_monitor_session(ist);
			}
			mutex_exit(&tgt->target_mutex);
		}
		ISCSIT_GLOBAL_UNLOCK();
		if (iscsit_rxpdu_queue_monitor_thr_running == B_FALSE) {
			break;
		}
		(void) cv_reltimedwait(&iscsit_rxpdu_queue_monitor_cv,
		    &iscsit_rxpdu_queue_monitor_mutex,
		    ISCSIT_RXPDU_QUEUE_MONITOR_INTERVAL * drv_usectohz(1000000),
		    TR_CLOCK_TICK);
	}
	mutex_exit(&iscsit_rxpdu_queue_monitor_mutex);
	thread_exit();
}

static void
iscsit_rxpdu_queue_monitor_session(iscsit_sess_t *ist)
{
	iscsit_cbuf_t	*cbuf	= ist->ist_rxpdu_queue;
	idm_pdu_t	*next_pdu = NULL;
	uint32_t	index, next_cmdsn, i;

	/*
	 * Assume that all PDUs in the staging queue have a cmdsn >= expcmdsn.
	 * Starting with the expcmdsn, iterate over the staged PDUs to find
	 * the next PDU with a wait time greater than the threshold. If found
	 * advance the staged PDU to the SCSI layer, skipping over the missing
	 * PDU(s) to get past the hole in the command sequence. It is up to
	 * the initiator to note that the target has not acknowledged a cmdsn
	 * and take appropriate action.
	 *
	 * Since the PDU(s) arrive in any random order, it is possible that
	 * that the actual wait time for a particular PDU is much longer than
	 * the defined threshold. e.g. Consider a case where commands are sent
	 * over 4 different connections, and cmdsn = 1004 arrives first, then
	 * 1003, and 1002 and 1001 are lost due to a connection failure.
	 * So now 1003 is waiting for 1002 to be delivered, and although the
	 * wait time of 1004 > wait time of 1003, only 1003 will be considered
	 * by the monitor thread. 1004 will be automatically processed by
	 * iscsit_process_pdu_in_queue() once the scan is complete and the
	 * expcmdsn becomes current.
	 */
	mutex_enter(&ist->ist_sn_mutex);
	cbuf = ist->ist_rxpdu_queue;
	if (cbuf->cb_num_elems == 0) {
		mutex_exit(&ist->ist_sn_mutex);
		return;
	}
	for (next_pdu = NULL, i = 0; ; i++) {
		next_cmdsn = ist->ist_expcmdsn + i; /* start at expcmdsn */
		index = next_cmdsn % ISCSIT_RXPDU_QUEUE_LEN;
		if ((next_pdu = cbuf->cb_buffer[index]) != NULL) {
			/*
			 * If the PDU wait time has not exceeded threshold
			 * stop scanning the staging queue until the timer
			 * fires again
			 */
			if ((ddi_get_time() - next_pdu->isp_queue_time)
			    < rxpdu_queue_threshold) {
				mutex_exit(&ist->ist_sn_mutex);
				return;
			}
			/*
			 * Remove the next PDU from the queue and post it
			 * to the SCSI layer, skipping over the missing
			 * PDU. Stop scanning the staging queue until
			 * the monitor timer fires again
			 */
			(void) iscsit_remove_pdu_from_queue(ist, next_cmdsn);
			mutex_exit(&ist->ist_sn_mutex);
			DTRACE_PROBE3(advanced__to__blocked__cmdsn,
			    iscsit_sess_t *, ist, idm_pdu_t *, next_pdu,
			    uint32_t, next_cmdsn);
			iscsit_post_staged_pdu(next_pdu);
			/* Deliver any subsequent PDUs immediately */
			iscsit_process_pdu_in_queue(ist);
			return;
		}
		/*
		 * Skipping over i PDUs, e.g. a case where commands 1001 and
		 * 1002 are lost in the network, skip over both and post 1003
		 * expcmdsn then becomes 1004 at the end of the scan.
		 */
		DTRACE_PROBE2(skipping__over__cmdsn, iscsit_sess_t *, ist,
		    uint32_t, next_cmdsn);
	}
	/*
	 * following the assumption, staged cmdsn >= expcmdsn, this statement
	 * is never reached.
	 */
}
