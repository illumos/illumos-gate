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
 * fcsm - ULP Module for Fibre Channel SAN Management
 */

#include <sys/types.h>
#include <sys/file.h>
#include <sys/kmem.h>
#include <sys/scsi/scsi.h>
#include <sys/var.h>
#include <sys/byteorder.h>
#include <sys/fibre-channel/fc.h>
#include <sys/fibre-channel/impl/fc_ulpif.h>
#include <sys/fibre-channel/ulp/fcsm.h>

/* Definitions */
#define	FCSM_VERSION		"20090729-1.28"
#define	FCSM_NAME_VERSION	"SunFC FCSM v" FCSM_VERSION

/* Global Variables */
static char		fcsm_name[] = "FCSM";
static void		*fcsm_state = NULL;
static kmutex_t		fcsm_global_mutex;
static uint32_t		fcsm_flag = FCSM_IDLE;
static dev_info_t	*fcsm_dip = NULL;
static fcsm_t		*fcsm_port_head = NULL;
static kmem_cache_t	*fcsm_job_cache = NULL;
static int		fcsm_num_attaching = 0;
static int		fcsm_num_detaching = 0;
static int		fcsm_detached = 0;

static int		fcsm_max_cmd_retries = FCSM_MAX_CMD_RETRIES;
static int		fcsm_retry_interval = FCSM_RETRY_INTERVAL;
static int		fcsm_retry_ticker = FCSM_RETRY_TICKER;
static int		fcsm_offline_ticker = FCSM_OFFLINE_TICKER;
static int		fcsm_max_job_retries = FCSM_MAX_JOB_RETRIES;
static clock_t		fcsm_retry_ticks;
static clock_t		fcsm_offline_ticks;



#ifdef DEBUG
uint32_t		fcsm_debug = 0;
#endif


/* Character/Block entry points */
struct cb_ops	fcsm_cb_ops = {
	fcsm_open,	/* open */
	fcsm_close,	/* close */
	nodev,		/* strategy */
	nodev,		/* print */
	nodev,		/* dump */
	nodev,		/* read */
	nodev,		/* write */
	fcsm_ioctl,	/* ioctl */
	nodev,		/* devmap */
	nodev,		/* mmap */
	nodev,		/* segmap */
	nochpoll,	/* poll */
	ddi_prop_op,
	NULL,		/* streams info */
	D_NEW | D_MP,
	CB_REV,
	nodev,		/* aread */
	nodev		/* awrite */
};

struct dev_ops fcsm_ops = {
	DEVO_REV,
	0,		/* refcnt */
	fcsm_getinfo,	/* get info */
	nulldev,	/* identify (obsolete) */
	nulldev,	/* probe (not required for self-identifying devices) */
	fcsm_attach,	/* attach */
	fcsm_detach,	/* detach */
	nodev,		/* reset */
	&fcsm_cb_ops,	/* char/block entry points structure for leaf drivers */
	NULL,		/* bus operations for nexus driver */
	NULL		/* power management */
};


struct modldrv modldrv = {
	&mod_driverops,
	FCSM_NAME_VERSION,
	&fcsm_ops
};

struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

static fc_ulp_modinfo_t fcsm_modinfo = {
	&fcsm_modinfo,		/* ulp_handle */
	FCTL_ULP_MODREV_4,	/* ulp_rev */
	FC_TYPE_FC_SERVICES,	/* ulp_type */
	fcsm_name,		/* ulp_name */
	0,			/* ulp_statec_mask: get all statec callbacks */
	fcsm_port_attach,	/* ulp_port_attach */
	fcsm_port_detach,	/* ulp_port_detach */
	fcsm_port_ioctl,	/* ulp_port_ioctl */
	fcsm_els_cb,		/* ulp_els_callback */
	fcsm_data_cb,		/* ulp_data_callback */
	fcsm_statec_cb		/* ulp_statec_callback */
};

struct fcsm_xlat_pkt_state {
	uchar_t	xlat_state;
	int	xlat_rval;
} fcsm_xlat_pkt_state [] = {
	{ FC_PKT_SUCCESS,		FC_SUCCESS },
	{ FC_PKT_REMOTE_STOP,		FC_FAILURE },
	{ FC_PKT_LOCAL_RJT,		FC_TRANSPORT_ERROR },
	{ FC_PKT_NPORT_RJT,		FC_PREJECT },
	{ FC_PKT_FABRIC_RJT,		FC_FREJECT },
	{ FC_PKT_LOCAL_BSY,		FC_TRAN_BUSY },
	{ FC_PKT_TRAN_BSY,		FC_TRAN_BUSY },
	{ FC_PKT_NPORT_BSY,		FC_PBUSY },
	{ FC_PKT_FABRIC_BSY,		FC_FBUSY },
	{ FC_PKT_LS_RJT,		FC_PREJECT },
	{ FC_PKT_BA_RJT,		FC_PREJECT },
	{ FC_PKT_TIMEOUT,		FC_FAILURE },
	{ FC_PKT_FS_RJT,		FC_FAILURE },
	{ FC_PKT_TRAN_ERROR,		FC_TRANSPORT_ERROR },
	{ FC_PKT_FAILURE,		FC_FAILURE },
	{ FC_PKT_PORT_OFFLINE,		FC_OFFLINE },
	{ FC_PKT_ELS_IN_PROGRESS,	FC_FAILURE }
};

struct fcsm_xlat_port_state {
	uint32_t	xlat_pstate;
	caddr_t		xlat_state_str;
} fcsm_xlat_port_state [] = {
	{ FC_STATE_OFFLINE,		"OFFLINE" },
	{ FC_STATE_ONLINE,		"ONLINE" },
	{ FC_STATE_LOOP,		"LOOP" },
	{ FC_STATE_NAMESERVICE,		"NAMESERVICE" },
	{ FC_STATE_RESET,		"RESET" },
	{ FC_STATE_RESET_REQUESTED,	"RESET_REQUESTED" },
	{ FC_STATE_LIP,			"LIP" },
	{ FC_STATE_LIP_LBIT_SET,	"LIP_LBIT_SET" },
	{ FC_STATE_DEVICE_CHANGE,	"DEVICE_CHANGE" },
	{ FC_STATE_TARGET_PORT_RESET,	"TARGET_PORT_RESET" }
};

struct fcsm_xlat_topology {
	uint32_t	xlat_top;
	caddr_t		xlat_top_str;
} fcsm_xlat_topology [] = {
	{ FC_TOP_UNKNOWN,	"UNKNOWN" },
	{ FC_TOP_PRIVATE_LOOP,	"Private Loop" },
	{ FC_TOP_PUBLIC_LOOP,	"Public Loop" },
	{ FC_TOP_FABRIC,	"Fabric" },
	{ FC_TOP_PT_PT,		"Point-to-Point" },
	{ FC_TOP_NO_NS,		"NO_NS" }
};

struct fcsm_xlat_dev_type {
	uint32_t	xlat_type;
	caddr_t		xlat_str;
} fcsm_xlat_dev_type [] = {
	{ PORT_DEVICE_NOCHANGE,		"No Change" },
	{ PORT_DEVICE_NEW,		"New" },
	{ PORT_DEVICE_OLD,		"Old" },
	{ PORT_DEVICE_CHANGED,		"Changed" },
	{ PORT_DEVICE_DELETE,		"Delete" },
	{ PORT_DEVICE_USER_LOGIN,	"User Login" },
	{ PORT_DEVICE_USER_LOGOUT,	"User Logout" },
	{ PORT_DEVICE_USER_CREATE,	"User Create" },
	{ PORT_DEVICE_USER_DELETE,	"User Delete" }
};

int
_init(void)
{
	int		rval;

	FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, NULL, NULL, "_init"));

	fcsm_retry_ticks = drv_usectohz(fcsm_retry_ticker * 1000 * 1000);
	fcsm_offline_ticks = drv_usectohz(fcsm_offline_ticker * 1000 * 1000);

	if (rval = ddi_soft_state_init(&fcsm_state, sizeof (fcsm_t),
	    FCSM_INIT_INSTANCES)) {
		fcsm_display(CE_WARN, SM_LOG, NULL, NULL,
		    "_init: ddi_soft_state_init failed");
		return (ENOMEM);
	}

	mutex_init(&fcsm_global_mutex, NULL, MUTEX_DRIVER, NULL);

	fcsm_job_cache = kmem_cache_create("fcsm_job_cache",
	    sizeof (fcsm_job_t), 8, fcsm_job_cache_constructor,
	    fcsm_job_cache_destructor, NULL, NULL, NULL, 0);

	if (fcsm_job_cache == NULL) {
		mutex_destroy(&fcsm_global_mutex);
		ddi_soft_state_fini(&fcsm_state);
		return (ENOMEM);
	}

	/*
	 * Now call fc_ulp_add to add this ULP in the transport layer
	 * database. This will cause 'ulp_port_attach' callback function
	 * to be called.
	 */
	rval = fc_ulp_add(&fcsm_modinfo);
	if (rval != 0) {
		switch (rval) {
		case FC_ULP_SAMEMODULE:
			fcsm_display(CE_WARN, SM_LOG, NULL, NULL,
			    "_init: FC SAN Management module is already "
			    "registered with transport layer");
			rval = EEXIST;
			break;

		case FC_ULP_SAMETYPE:
			fcsm_display(CE_WARN, SM_LOG, NULL, NULL,
			    "_init: Another module with same type 0x%x is "
			    "already registered with transport layer",
			    fcsm_modinfo.ulp_type);
			rval = EEXIST;
			break;

		case FC_BADULP:
			fcsm_display(CE_WARN, SM_LOG, NULL, NULL,
			    "_init: Please upgrade this module. Current "
			    "version 0x%x is not the most recent version",
			    fcsm_modinfo.ulp_rev);
			rval = EIO;
			break;
		default:
			fcsm_display(CE_WARN, SM_LOG, NULL, NULL,
			    "_init: fc_ulp_add failed with status 0x%x", rval);
			rval = EIO;
			break;
		}
		kmem_cache_destroy(fcsm_job_cache);
		mutex_destroy(&fcsm_global_mutex);
		ddi_soft_state_fini(&fcsm_state);
		return (rval);
	}

	if ((rval = mod_install(&modlinkage)) != 0) {
		FCSM_DEBUG(SMDL_ERR, (CE_WARN, SM_LOG, NULL, NULL,
		    "_init: mod_install failed with status 0x%x", rval));
		(void) fc_ulp_remove(&fcsm_modinfo);
		kmem_cache_destroy(fcsm_job_cache);
		mutex_destroy(&fcsm_global_mutex);
		ddi_soft_state_fini(&fcsm_state);
		return (rval);
	}

	return (rval);
}

int
_fini(void)
{
	int	rval;
#ifdef	DEBUG
	int	status;
#endif /* DEBUG */

	FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, NULL, NULL, "_fini"));

	/*
	 * don't start cleaning up until we know that the module remove
	 * has worked  -- if this works, then we know that each instance
	 * has successfully been DDI_DETACHed
	 */
	if ((rval = mod_remove(&modlinkage)) != 0) {
		return (rval);
	}

#ifdef DEBUG
	status = fc_ulp_remove(&fcsm_modinfo);
	if (status != 0) {
		FCSM_DEBUG(SMDL_ERR, (CE_WARN, SM_LOG, NULL, NULL,
		    "_fini: fc_ulp_remove failed with status 0x%x", status));
	}
#else
	(void) fc_ulp_remove(&fcsm_modinfo);
#endif /* DEBUG */

	fcsm_detached = 0;

	/*
	 * It is possible to modunload fcsm manually, which will cause
	 * a bypass of all the port_detach functionality.  We may need
	 * to force that code path to be executed to properly clean up
	 * in that case.
	 */
	fcsm_force_port_detach_all();

	kmem_cache_destroy(fcsm_job_cache);
	mutex_destroy(&fcsm_global_mutex);
	ddi_soft_state_fini(&fcsm_state);

	return (rval);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/* ARGSUSED */
static int
fcsm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int rval = DDI_FAILURE;

	FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, NULL, NULL,
	    "attach: cmd 0x%x", cmd));

	switch (cmd) {
	case DDI_ATTACH:
		mutex_enter(&fcsm_global_mutex);
		if (fcsm_dip != NULL) {
			mutex_exit(&fcsm_global_mutex);
			FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, NULL, NULL,
			    "attach: duplicate attach of fcsm!!"));
			break;
		}

		fcsm_dip = dip;

		/*
		 * The detach routine cleans up all the port instances
		 * i.e. it detaches all ports.
		 * If _fini never got called after detach, then
		 * perform an fc_ulp_remove() followed by fc_ulp_add()
		 * to ensure that port_attach callbacks are called
		 * again.
		 */
		if (fcsm_detached) {
			int status;

			FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, NULL, NULL,
			    "attach: rebinding to transport driver"));

			mutex_exit(&fcsm_global_mutex);

			(void) fc_ulp_remove(&fcsm_modinfo);

			/*
			 * Reset the detached flag, so that ports can attach
			 */
			mutex_enter(&fcsm_global_mutex);
			fcsm_detached = 0;
			mutex_exit(&fcsm_global_mutex);

			status = fc_ulp_add(&fcsm_modinfo);

			if (status != 0) {
				/*
				 * ULP add failed. So set the
				 * detached flag again
				 */
				mutex_enter(&fcsm_global_mutex);
				fcsm_detached = 1;
				mutex_exit(&fcsm_global_mutex);

				switch (status) {
				case FC_ULP_SAMEMODULE:
					fcsm_display(CE_WARN, SM_LOG, NULL,
					    NULL, "attach: FC SAN Management "
					    "module is already "
					    "registered with transport layer");
					break;

				case FC_ULP_SAMETYPE:
					fcsm_display(CE_WARN, SM_LOG, NULL,
					    NULL, "attach: Another module with "
					    "same type 0x%x is already "
					    "registered with transport layer",
					    fcsm_modinfo.ulp_type);
					break;

				case FC_BADULP:
					fcsm_display(CE_WARN, SM_LOG, NULL,
					    NULL, "attach: Please upgrade this "
					    "module. Current version 0x%x is "
					    "not the most recent version",
					    fcsm_modinfo.ulp_rev);
					break;
				default:
					fcsm_display(CE_WARN, SM_LOG, NULL,
					    NULL, "attach: fc_ulp_add failed "
					    "with status 0x%x", status);
					break;
				}

				/* Return failure */
				break;
			}

			mutex_enter(&fcsm_global_mutex);
		}

		/* Create a minor node */
		if (ddi_create_minor_node(fcsm_dip, "fcsm", S_IFCHR,
		    0, DDI_PSEUDO, 0) == DDI_SUCCESS) {
			/* Announce presence of the device */
			mutex_exit(&fcsm_global_mutex);
			ddi_report_dev(dip);
			rval = DDI_SUCCESS;
		} else {
			fcsm_dip = NULL;
			mutex_exit(&fcsm_global_mutex);
			fcsm_display(CE_WARN, SM_LOG_AND_CONSOLE,
			    NULL, NULL, "attach: create minor node failed");
		}
		break;

	case DDI_RESUME:
		rval = DDI_SUCCESS;
		break;

	default:
		FCSM_DEBUG(SMDL_ERR, (CE_NOTE, SM_LOG, NULL, NULL,
		    "attach: unknown cmd 0x%x dip 0x%p", cmd, dip));
		break;
	}

	return (rval);
}

/* ARGSUSED */
static int
fcsm_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	int	instance;
	int	rval = DDI_SUCCESS;

	instance = getminor((dev_t)arg);

	switch (cmd) {
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(long)instance; /* minor number is instance */
		break;

	case DDI_INFO_DEVT2DEVINFO:
		mutex_enter(&fcsm_global_mutex);
		*result = (void *)fcsm_dip;
		mutex_exit(&fcsm_global_mutex);
		break;

	default:
		rval = DDI_FAILURE;
		break;
	}

	return (rval);
}


/* ARGSUSED */
static int
fcsm_port_attach(opaque_t ulph, fc_ulp_port_info_t *pinfo,
    fc_attach_cmd_t cmd, uint32_t s_id)
{
	int	instance;
	int	rval = FC_FAILURE;

	instance = ddi_get_instance(pinfo->port_dip);

	/*
	 * Set the attaching flag, so that fcsm_detach will fail, if
	 * port attach is in progress.
	 */
	mutex_enter(&fcsm_global_mutex);
	if (fcsm_detached) {
		mutex_exit(&fcsm_global_mutex);

		FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, NULL, NULL,
		    "port_attach: end. detach in progress. failing attach "
		    "instance 0x%x", instance));
		return (((cmd == FC_CMD_POWER_UP) || (cmd == FC_CMD_RESUME)) ?
		    FC_FAILURE_SILENT : FC_FAILURE);
	}

	fcsm_num_attaching++;
	mutex_exit(&fcsm_global_mutex);

	switch (cmd) {
	case FC_CMD_ATTACH:
		if (fcsm_handle_port_attach(pinfo, s_id, instance)
		    != DDI_SUCCESS) {
			ASSERT(ddi_get_soft_state(fcsm_state,
			    instance) == NULL);
			break;
		}
		rval = FC_SUCCESS;
		break;

	case FC_CMD_RESUME:
	case FC_CMD_POWER_UP: {
		fcsm_t	*fcsm;
		char fcsm_pathname[MAXPATHLEN];

		FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, NULL, NULL,
		    "port_attach: cmd 0x%x instance 0x%x", cmd, instance));

		/* Get the soft state structure */
		if ((fcsm = ddi_get_soft_state(fcsm_state, instance)) == NULL) {
			FCSM_DEBUG(SMDL_TRACE, (CE_WARN, SM_LOG, NULL, NULL,
			    "port_attach: instance 0x%x, cmd 0x%x "
			    "get softstate failed", instance, cmd));
			break;
		}

		ASSERT(fcsm->sm_instance == instance);

		/* If this instance is not attached, then return failure */
		mutex_enter(&fcsm->sm_mutex);
		if ((fcsm->sm_flags & FCSM_ATTACHED) == 0) {
			mutex_exit(&fcsm->sm_mutex);
			fcsm_display(CE_WARN, SM_LOG, fcsm, NULL,
			    "port_detach: port is not attached");
			break;
		}
		mutex_exit(&fcsm->sm_mutex);

		if (fcsm_handle_port_resume(ulph, pinfo, cmd, s_id, fcsm) !=
		    DDI_SUCCESS) {
			break;
		}

		(void) ddi_pathname(fcsm->sm_port_info.port_dip, fcsm_pathname);
		fcsm_display(CE_NOTE, SM_LOG, fcsm, NULL,
		    "attached to path %s", fcsm_pathname);
		rval = FC_SUCCESS;
		break;
	}

	default:
		FCSM_DEBUG(SMDL_ERR, (CE_NOTE, SM_LOG, NULL, NULL,
		    "port_attach: unknown cmd 0x%x for port 0x%x",
		    cmd, instance));
		break;
	}

	mutex_enter(&fcsm_global_mutex);
	fcsm_num_attaching--;
	mutex_exit(&fcsm_global_mutex);
	return (rval);
}


static int
fcsm_handle_port_attach(fc_ulp_port_info_t *pinfo, uint32_t s_id, int instance)
{
	fcsm_t		*fcsm;
	kthread_t	*thread;
	char		name[32];
	char fcsm_pathname[MAXPATHLEN];

	/* Allocate a soft state structure for the port */
	if (ddi_soft_state_zalloc(fcsm_state, instance) != DDI_SUCCESS) {
		fcsm_display(CE_WARN, SM_LOG, NULL, NULL,
		    "port_attach: instance 0x%x, soft state alloc failed",
		    instance);
		return (DDI_FAILURE);
	}

	if ((fcsm = ddi_get_soft_state(fcsm_state, instance)) == NULL) {
		fcsm_display(CE_WARN, SM_LOG, NULL, NULL,
		    "port_attach: instance 0x%x, get soft state failed",
		    instance);
		ddi_soft_state_free(fcsm_state, instance);
		return (DDI_FAILURE);
	}


	/* Initialize the mutex */
	mutex_init(&fcsm->sm_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&fcsm->sm_job_cv, NULL, CV_DRIVER, NULL);

	mutex_enter(&fcsm->sm_mutex);
	fcsm->sm_flags		|= FCSM_ATTACHING;
	fcsm->sm_sid		= s_id;
	fcsm->sm_instance	= instance;
	fcsm->sm_port_state	= pinfo->port_state;

	/*
	 * Make a copy of the port_information structure, since fctl
	 * uses a temporary structure.
	 */
	fcsm->sm_port_info	= *pinfo;	/* Structure copy !!! */
	mutex_exit(&fcsm->sm_mutex);


	(void) sprintf(name, "fcsm%d_cmd_cache", fcsm->sm_instance);
	fcsm->sm_cmd_cache = kmem_cache_create(name,
	    sizeof (fcsm_cmd_t) + pinfo->port_fca_pkt_size, 8,
	    fcsm_cmd_cache_constructor, fcsm_cmd_cache_destructor,
	    NULL, (void *)fcsm, NULL, 0);
	if (fcsm->sm_cmd_cache == NULL) {
		fcsm_display(CE_WARN, SM_LOG, fcsm, NULL,
		    "port_attach: pkt cache create failed");
		cv_destroy(&fcsm->sm_job_cv);
		mutex_destroy(&fcsm->sm_mutex);
		ddi_soft_state_free(fcsm_state, instance);
		return (DDI_FAILURE);
	}

	thread = thread_create((caddr_t)NULL, 0, fcsm_job_thread,
	    (caddr_t)fcsm, 0, &p0, TS_RUN, v.v_maxsyspri-2);
	if (thread == NULL) {
		fcsm_display(CE_WARN, SM_LOG, fcsm, NULL,
		    "port_attach: job thread create failed");
		kmem_cache_destroy(fcsm->sm_cmd_cache);
		cv_destroy(&fcsm->sm_job_cv);
		mutex_destroy(&fcsm->sm_mutex);
		ddi_soft_state_free(fcsm_state, instance);
		return (DDI_FAILURE);
	}

	fcsm->sm_thread = thread;

	/* Add this structure to fcsm global linked list */
	mutex_enter(&fcsm_global_mutex);
	if (fcsm_port_head == NULL) {
		fcsm_port_head = fcsm;
	} else {
		fcsm->sm_next = fcsm_port_head;
		fcsm_port_head = fcsm;
	}
	mutex_exit(&fcsm_global_mutex);

	mutex_enter(&fcsm->sm_mutex);
	fcsm->sm_flags &= ~FCSM_ATTACHING;
	fcsm->sm_flags |= FCSM_ATTACHED;
	fcsm->sm_port_top = pinfo->port_flags;
	fcsm->sm_port_state = pinfo->port_state;
	if (pinfo->port_acc_attr == NULL) {
		/*
		 * The corresponding FCA doesn't support DMA at all
		 */
		fcsm->sm_flags |= FCSM_USING_NODMA_FCA;
	}
	mutex_exit(&fcsm->sm_mutex);

	(void) ddi_pathname(fcsm->sm_port_info.port_dip, fcsm_pathname);
	fcsm_display(CE_NOTE, SM_LOG, fcsm, NULL,
	    "attached to path %s", fcsm_pathname);

	FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, fcsm, NULL,
	    "port_attach: state <%s>(0x%x) topology <%s>(0x%x)",
	    fcsm_port_state_to_str(FC_PORT_STATE_MASK(pinfo->port_state)),
	    pinfo->port_state,
	    fcsm_topology_to_str(pinfo->port_flags), pinfo->port_flags));

	return (DDI_SUCCESS);
}

static int
fcsm_handle_port_resume(opaque_t ulph, fc_ulp_port_info_t *pinfo,
    fc_attach_cmd_t cmd, uint32_t s_id, fcsm_t *fcsm)
{
	FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, fcsm, NULL,
	    "port_resume: cmd 0x%x", cmd));

	mutex_enter(&fcsm->sm_mutex);

	switch (cmd) {
	case FC_CMD_RESUME:
		ASSERT(!(fcsm->sm_flags & FCSM_POWER_DOWN));
		fcsm->sm_flags &= ~FCSM_SUSPENDED;
		break;

	case FC_CMD_POWER_UP:
		/* If port is suspended, then no need to resume */
		fcsm->sm_flags &= ~FCSM_POWER_DOWN;
		if (fcsm->sm_flags & FCSM_SUSPENDED) {
			mutex_exit(&fcsm->sm_mutex);
			return (DDI_SUCCESS);
		}
		break;
	default:
		mutex_exit(&fcsm->sm_mutex);
		return (DDI_FAILURE);
	}

	fcsm->sm_sid = s_id;

	/*
	 * Make a copy of the new port_information structure
	 */
	fcsm->sm_port_info	= *pinfo;	/* Structure copy !!! */
	mutex_exit(&fcsm->sm_mutex);

	fcsm_resume_port(fcsm);

	/*
	 * Invoke state change processing.
	 * This will ensure that
	 *    - offline timer is started if new port state changed to offline.
	 *    - MGMT_SERVER_LOGIN flag is reset.
	 *    - Port topology is updated.
	 */
	fcsm_statec_cb(ulph, (opaque_t)pinfo->port_handle, pinfo->port_state,
	    pinfo->port_flags, NULL, 0, s_id);

	return (DDI_SUCCESS);
}


/* ARGSUSED */
static int
fcsm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int	rval = DDI_SUCCESS;

	switch (cmd) {
	case DDI_DETACH: {
		fcsm_t	*fcsm;

		FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, NULL, NULL,
		    "detach: start. cmd <DETACH>", cmd));

		mutex_enter(&fcsm_global_mutex);

		/*
		 * If port attach/detach in progress, then wait for 5 seconds
		 * for them to complete.
		 */
		if (fcsm_num_attaching || fcsm_num_detaching) {
			int count;

			FCSM_DEBUG(SMDL_TRACE, (CE_WARN, SM_LOG, NULL, NULL,
			    "detach: wait for port attach/detach to complete"));

			count = 0;
			while ((count++ <= 30) &&
			    (fcsm_num_attaching || fcsm_num_detaching)) {
				mutex_exit(&fcsm_global_mutex);
				delay(drv_usectohz(1000000));
				mutex_enter(&fcsm_global_mutex);
			}

			/* Port attach/detach still in prog, so fail detach */
			if (fcsm_num_attaching || fcsm_num_detaching) {
				mutex_exit(&fcsm_global_mutex);
				FCSM_DEBUG(SMDL_ERR, (CE_WARN, SM_LOG, NULL,
				    NULL, "detach: Failing detach. port "
				    "attach/detach in progress"));
				rval = DDI_FAILURE;
				break;
			}
		}

		if (fcsm_port_head == NULL) {
			/* Not much do, Succeed to detach. */
			ddi_remove_minor_node(fcsm_dip, NULL);
			fcsm_dip = NULL;
			fcsm_detached = 0;
			mutex_exit(&fcsm_global_mutex);
			break;
		}

		/*
		 * Check to see, if any ports are active.
		 * If not, then set the DETACHING flag to indicate
		 * that they are being detached.
		 */
		fcsm = fcsm_port_head;
		while (fcsm != NULL) {

			mutex_enter(&fcsm->sm_mutex);
			if (!(fcsm->sm_flags & FCSM_ATTACHED) ||
			    fcsm->sm_ncmds || fcsm->sm_cb_count) {
				/* port is busy. We can't detach */
				mutex_exit(&fcsm->sm_mutex);
				break;
			}

			fcsm->sm_flags |= FCSM_DETACHING;
			mutex_exit(&fcsm->sm_mutex);

			fcsm = fcsm->sm_next;
		}

		/*
		 * If all ports could not be marked for detaching,
		 * then clear the flags and fail the detach.
		 * Also if a port attach is currently in progress
		 * then fail the detach.
		 */
		if (fcsm != NULL || fcsm_num_attaching || fcsm_num_detaching) {
			/*
			 * Some ports were busy, so can't detach.
			 * Clear the DETACHING flag and return failure
			 */
			fcsm = fcsm_port_head;
			while (fcsm != NULL) {
				mutex_enter(&fcsm->sm_mutex);
				if (fcsm->sm_flags & FCSM_DETACHING) {
					fcsm->sm_flags &= ~FCSM_DETACHING;
				}
				mutex_exit(&fcsm->sm_mutex);

				fcsm = fcsm->sm_next;
			}
			mutex_exit(&fcsm_global_mutex);
			return (DDI_FAILURE);
		} else {
			fcsm_detached = 1;
			/*
			 * Mark all the detaching ports as detached, as we
			 * will be detaching them
			 */
			fcsm = fcsm_port_head;
			while (fcsm != NULL) {
				mutex_enter(&fcsm->sm_mutex);
				fcsm->sm_flags &= ~FCSM_DETACHING;
				fcsm->sm_flags |= FCSM_DETACHED;
				mutex_exit(&fcsm->sm_mutex);

				fcsm = fcsm->sm_next;
			}
		}
		mutex_exit(&fcsm_global_mutex);


		/*
		 * Go ahead and detach the ports
		 */
		mutex_enter(&fcsm_global_mutex);
		while (fcsm_port_head != NULL) {
			fcsm = fcsm_port_head;
			mutex_exit(&fcsm_global_mutex);

			/*
			 * Call fcsm_cleanup_port(). This cleansup and
			 * removes the fcsm structure from global linked list
			 */
			fcsm_cleanup_port(fcsm);

			/*
			 * Soft state cleanup done.
			 * Remember that fcsm struct doesn't exist anymore.
			 */

			mutex_enter(&fcsm_global_mutex);
		}

		ddi_remove_minor_node(fcsm_dip, NULL);
		fcsm_dip = NULL;
		mutex_exit(&fcsm_global_mutex);
		break;
	}

	case DDI_SUSPEND:
		rval = DDI_SUCCESS;
		break;

	default:
		FCSM_DEBUG(SMDL_ERR, (CE_NOTE, SM_LOG, NULL, NULL,
		    "detach: unknown cmd 0x%x", cmd));
		rval = DDI_FAILURE;
		break;
	}

	FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, NULL, NULL,
	    "detach: end. cmd 0x%x, rval 0x%x", cmd, rval));

	return (rval);
}


/* ARGSUSED */
static void
fcsm_force_port_detach_all(void)
{
	fcsm_t	*fcsm;

	fcsm = fcsm_port_head;

	while (fcsm) {
		fcsm_cleanup_port(fcsm);
		/*
		 * fcsm_cleanup_port will remove the current fcsm structure
		 * from the list, which will cause fcsm_port_head to point
		 * to what would have been the next structure on the list.
		 */
		fcsm = fcsm_port_head;
	}
}


/* ARGSUSED */
static int
fcsm_port_detach(opaque_t ulph, fc_ulp_port_info_t *pinfo, fc_detach_cmd_t cmd)
{
	int	instance;
	int	rval = FC_FAILURE;
	fcsm_t	*fcsm;

	instance = ddi_get_instance(pinfo->port_dip);

	mutex_enter(&fcsm_global_mutex);
	if (fcsm_detached) {
		mutex_exit(&fcsm_global_mutex);

		FCSM_DEBUG(SMDL_TRACE, (CE_WARN, SM_LOG, NULL, NULL,
		    "port_detach: end. instance 0x%x, fcsm is detached",
		    instance));
		return (FC_SUCCESS);
	}
	fcsm_num_detaching++;	/* Set the flag */
	mutex_exit(&fcsm_global_mutex);

	/* Get the soft state structure */
	if ((fcsm = ddi_get_soft_state(fcsm_state, instance)) == NULL) {
		FCSM_DEBUG(SMDL_TRACE, (CE_WARN, SM_LOG, NULL, NULL,
		    "port_detach: instance 0x%x, cmd 0x%x get softstate failed",
		    instance, cmd));
		mutex_enter(&fcsm_global_mutex);
		fcsm_num_detaching--;
		mutex_exit(&fcsm_global_mutex);
		return (rval);
	}

	ASSERT(fcsm->sm_instance == instance);

	/* If this instance is not attached, then fail the detach */
	mutex_enter(&fcsm->sm_mutex);
	if ((fcsm->sm_flags & FCSM_ATTACHED) == 0) {
		mutex_exit(&fcsm->sm_mutex);
		fcsm_display(CE_WARN, SM_LOG, fcsm, NULL,
		    "port_detach: port is not attached");
		mutex_enter(&fcsm_global_mutex);
		fcsm_num_detaching--;
		mutex_exit(&fcsm_global_mutex);
		return (rval);
	}
	mutex_exit(&fcsm->sm_mutex);

	/*
	 * If fcsm has been detached, then all instance has already been
	 * detached or are being detached. So succeed this detach.
	 */

	switch (cmd) {
	case FC_CMD_DETACH:
	case FC_CMD_SUSPEND:
	case FC_CMD_POWER_DOWN:
		break;

	default:
		FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, fcsm, NULL,
		    "port_detach: port unknown cmd 0x%x", cmd));
		mutex_enter(&fcsm_global_mutex);
		fcsm_num_detaching--;
		mutex_exit(&fcsm_global_mutex);
		return (rval);
	};

	if (fcsm_handle_port_detach(pinfo, fcsm, cmd) == DDI_SUCCESS) {
		rval = FC_SUCCESS;
	}

	mutex_enter(&fcsm_global_mutex);
	fcsm_num_detaching--;
	mutex_exit(&fcsm_global_mutex);

	/* If it was a detach, then fcsm state structure no longer exists */
	FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, NULL, NULL,
	    "port_detach: end. cmd 0x%x rval 0x%x", cmd, rval));
	return (rval);
}


static int
fcsm_handle_port_detach(fc_ulp_port_info_t *pinfo, fcsm_t *fcsm,
    fc_detach_cmd_t cmd)
{
	uint32_t	flag;
	int		count;
#ifdef DEBUG
	char		pathname[MAXPATHLEN];
#endif /* DEBUG */

	/*
	 * If port is already powered down OR suspended and there is nothing
	 * else to do then just return.
	 * Otherwise, set the flag, so that no more new activity will be
	 * initiated on this port.
	 */
	mutex_enter(&fcsm->sm_mutex);

	switch (cmd) {
	case FC_CMD_DETACH:
		flag = FCSM_DETACHING;
		break;

	case FC_CMD_SUSPEND:
	case FC_CMD_POWER_DOWN:
		((cmd == FC_CMD_SUSPEND) ? (flag = FCSM_SUSPENDED) :
		    (flag = FCSM_POWER_DOWN));
		if (fcsm->sm_flags &
		    (FCSM_POWER_DOWN | FCSM_SUSPENDED)) {
			fcsm->sm_flags |= flag;
			mutex_exit(&fcsm->sm_mutex);
			return (DDI_SUCCESS);
		}
		break;

	default:
		mutex_exit(&fcsm->sm_mutex);
		return (DDI_FAILURE);
	};

	fcsm->sm_flags |= flag;

	/*
	 * If some commands are pending OR callback in progress, then
	 * wait for some finite amount of time for their completion.
	 * TODO: add more checks here to check for cmd timeout, offline
	 * timeout and other (??) threads.
	 */
	count = 0;
	while ((count++ <= 30) && (fcsm->sm_ncmds || fcsm->sm_cb_count)) {
		mutex_exit(&fcsm->sm_mutex);
		delay(drv_usectohz(1000000));
		mutex_enter(&fcsm->sm_mutex);
	}
	if (fcsm->sm_ncmds || fcsm->sm_cb_count) {
		fcsm->sm_flags &= ~flag;
		mutex_exit(&fcsm->sm_mutex);
		fcsm_display(CE_WARN, SM_LOG, fcsm, NULL,
		    "port_detach: Failing suspend, port is busy");
		return (DDI_FAILURE);
	}
	if (flag == FCSM_DETACHING) {
		fcsm->sm_flags &= ~FCSM_DETACHING;
		fcsm->sm_flags |= FCSM_DETACHED;
	}

	mutex_exit(&fcsm->sm_mutex);

	FCSM_DEBUG(SMDL_INFO, (CE_CONT, SM_LOG, fcsm, NULL,
	    "port_detach: cmd 0x%x pathname <%s>",
	    cmd, ddi_pathname(pinfo->port_dip, pathname)));

	if (cmd == FC_CMD_DETACH) {
		fcsm_cleanup_port(fcsm);
		/*
		 * Soft state cleanup done.
		 * Always remember that fcsm struct doesn't exist anymore.
		 */
	} else {
		fcsm_suspend_port(fcsm);
	}

	return (DDI_SUCCESS);
}

static void
fcsm_suspend_port(fcsm_t *fcsm)
{
	mutex_enter(&fcsm->sm_mutex);

	if (fcsm->sm_offline_tid != NULL) {
		timeout_id_t	tid;

		tid = fcsm->sm_offline_tid;
		fcsm->sm_offline_tid = (timeout_id_t)NULL;
		mutex_exit(&fcsm->sm_mutex);
		(void) untimeout(tid);
		mutex_enter(&fcsm->sm_mutex);
		fcsm->sm_flags |= FCSM_RESTORE_OFFLINE_TIMEOUT;
	}

	if (fcsm->sm_retry_tid != NULL) {
		timeout_id_t	tid;

		tid = fcsm->sm_retry_tid;
		fcsm->sm_retry_tid = (timeout_id_t)NULL;
		mutex_exit(&fcsm->sm_mutex);
		(void) untimeout(tid);
		mutex_enter(&fcsm->sm_mutex);
		fcsm->sm_flags |= FCSM_RESTORE_RETRY_TIMEOUT;
	}

	mutex_exit(&fcsm->sm_mutex);
}

static void
fcsm_resume_port(fcsm_t *fcsm)
{
	mutex_enter(&fcsm->sm_mutex);

	if (fcsm->sm_flags & FCSM_RESTORE_OFFLINE_TIMEOUT) {
		fcsm->sm_flags &= ~FCSM_RESTORE_OFFLINE_TIMEOUT;

		/*
		 * If port if offline, link is not marked down and offline
		 * timer is not already running, then restart offline timer.
		 */
		if (!(fcsm->sm_flags & FCSM_LINK_DOWN) &&
		    fcsm->sm_offline_tid == NULL &&
		    (fcsm->sm_flags & FCSM_PORT_OFFLINE)) {
			fcsm->sm_offline_tid = timeout(fcsm_offline_timeout,
			    (caddr_t)fcsm, fcsm_offline_ticks);
		}
	}

	if (fcsm->sm_flags & FCSM_RESTORE_RETRY_TIMEOUT) {
		fcsm->sm_flags &= ~FCSM_RESTORE_RETRY_TIMEOUT;

		/*
		 * If retry queue is not suspended and some cmds are waiting
		 * to be retried, then restart the retry timer
		 */
		if (fcsm->sm_retry_head && fcsm->sm_retry_tid == NULL) {
			fcsm->sm_retry_tid = timeout(fcsm_retry_timeout,
			    (caddr_t)fcsm, fcsm_retry_ticks);
		}
	}
	mutex_exit(&fcsm->sm_mutex);
}

static void
fcsm_cleanup_port(fcsm_t *fcsm)
{
	fcsm_t		*curr, *prev;
	int		status;
	fcsm_job_t	*job;

	FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, fcsm, NULL,
	    "fcsm_cleanup_port: entered"));

	/*
	 * Kill the job thread
	 */
	job = fcsm_alloc_job(KM_SLEEP);
	ASSERT(job != NULL);
	fcsm_init_job(job, fcsm->sm_instance, FCSM_JOB_THREAD_SHUTDOWN,
	    FCSM_JOBFLAG_SYNC, NULL, NULL, NULL, NULL);

	status = fcsm_process_job(job, 0);
	ASSERT(status == FC_SUCCESS);

	ASSERT(job->job_result == FC_SUCCESS);
	fcsm_dealloc_job(job);

	/*
	 * We got here after ensuring the no commands are pending or active.
	 * Therefore retry timeout thread should NOT be running.
	 * Kill the offline timeout thread if currently running.
	 */
	mutex_enter(&fcsm->sm_mutex);

	ASSERT(fcsm->sm_retry_tid == NULL);

	if (fcsm->sm_offline_tid != NULL) {
		timeout_id_t	tid;

		tid = fcsm->sm_offline_tid;
		fcsm->sm_offline_tid = (timeout_id_t)NULL;
		mutex_exit(&fcsm->sm_mutex);
		(void) untimeout(tid);
	} else {
		mutex_exit(&fcsm->sm_mutex);
	}

	/* Remove from the fcsm state structure from global linked list */
	mutex_enter(&fcsm_global_mutex);
	curr = fcsm_port_head;
	prev = NULL;
	while (curr != fcsm && curr != NULL) {
		prev = curr;
		curr = curr->sm_next;
	}
	ASSERT(curr != NULL);

	if (prev == NULL) {
		fcsm_port_head = curr->sm_next;
	} else {
		prev->sm_next = curr->sm_next;
	}
	mutex_exit(&fcsm_global_mutex);

	if (fcsm->sm_cmd_cache != NULL) {
		kmem_cache_destroy(fcsm->sm_cmd_cache);
	}
	cv_destroy(&fcsm->sm_job_cv);
	mutex_destroy(&fcsm->sm_mutex);

	/* Free the fcsm state structure */
	ddi_soft_state_free(fcsm_state, fcsm->sm_instance);
}


/* ARGSUSED */
static void
fcsm_statec_cb(opaque_t ulph, opaque_t port_handle, uint32_t port_state,
    uint32_t port_top, fc_portmap_t *devlist, uint32_t dev_cnt,
    uint32_t port_sid)
{
	fcsm_t		*fcsm;
	timeout_id_t	offline_tid, retry_tid;

	mutex_enter(&fcsm_global_mutex);
	if (fcsm_detached) {
		mutex_exit(&fcsm_global_mutex);
		return;
	}

	fcsm = ddi_get_soft_state(fcsm_state,
	    fc_ulp_get_port_instance(port_handle));
	if (fcsm == NULL) {
		mutex_exit(&fcsm_global_mutex);
		FCSM_DEBUG(SMDL_TRACE, (CE_NOTE, SM_LOG, NULL, NULL,
		    "statec_cb: instance 0x%x not found",
		    fc_ulp_get_port_instance(port_handle)));
		return;
	}
	mutex_enter(&fcsm->sm_mutex);
	ASSERT(fcsm->sm_instance == fc_ulp_get_port_instance(port_handle));
	if ((fcsm->sm_flags & FCSM_ATTACHED) == 0) {
		mutex_exit(&fcsm->sm_mutex);
		mutex_exit(&fcsm_global_mutex);
		FCSM_DEBUG(SMDL_TRACE, (CE_NOTE, SM_LOG, fcsm, NULL,
		    "statec_cb: port not attached"));
		return;
	}

	ASSERT(fcsm->sm_cb_count >= 0);

	fcsm->sm_cb_count++;
	mutex_exit(&fcsm->sm_mutex);
	mutex_exit(&fcsm_global_mutex);

	FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, fcsm, NULL,
	    "statec_cb: state <%s>(0x%x) topology <%s>(0x%x) dev_cnt %d",
	    fcsm_port_state_to_str(FC_PORT_STATE_MASK(port_state)), port_state,
	    fcsm_topology_to_str(port_top), port_top, dev_cnt));

	fcsm_disp_devlist(fcsm, devlist, dev_cnt);

	mutex_enter(&fcsm->sm_mutex);

	/*
	 * Reset the Mgmt server Login flag, so that login is performed again.
	 */
	fcsm->sm_flags &= ~FCSM_MGMT_SERVER_LOGGED_IN;

	fcsm->sm_sid = port_sid;
	fcsm->sm_port_top = port_top;
	fcsm->sm_port_state = port_state;

	switch (port_state) {
	case FC_STATE_OFFLINE:
	case FC_STATE_RESET:
	case FC_STATE_RESET_REQUESTED:
		fcsm->sm_flags |= FCSM_PORT_OFFLINE;
		break;

	case FC_STATE_ONLINE:
	case FC_STATE_LOOP:
	case FC_STATE_LIP:
	case FC_STATE_LIP_LBIT_SET:
		fcsm->sm_flags &= ~FCSM_PORT_OFFLINE;
		fcsm->sm_flags &= ~FCSM_LINK_DOWN;
		break;

	case FC_STATE_NAMESERVICE:
	case FC_STATE_DEVICE_CHANGE:
	case FC_STATE_TARGET_PORT_RESET:
	default:
		/* Do nothing */
		break;
	}

	offline_tid = retry_tid = NULL;
	if (fcsm->sm_flags & FCSM_PORT_OFFLINE) {
		/*
		 * Port is offline.
		 * Suspend cmd processing and start offline timeout thread.
		 */
		if (fcsm->sm_offline_tid == NULL) {
			FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, fcsm, NULL,
			    "statec_cb: schedule offline timeout thread"));
			fcsm->sm_flags |= FCSM_CMD_RETRY_Q_SUSPENDED;
			/* Stop the cmd retry thread */
			retry_tid = fcsm->sm_retry_tid;
			fcsm->sm_retry_tid = (timeout_id_t)NULL;

			fcsm->sm_offline_tid = timeout(fcsm_offline_timeout,
			    (caddr_t)fcsm, fcsm_offline_ticks);
		}

	} else {
		/*
		 * Port is online.
		 * Cancel offline timeout thread and resume command processing.
		 */
		if (fcsm->sm_offline_tid) {
			FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, fcsm, NULL,
			    "statec_cb: cancel offline timeout thread"));
			offline_tid = fcsm->sm_offline_tid;
			fcsm->sm_offline_tid = (timeout_id_t)NULL;
		}

		fcsm->sm_flags &= ~FCSM_CMD_RETRY_Q_SUSPENDED;
		/* Start retry thread if needed */
		if (fcsm->sm_retry_head && fcsm->sm_retry_tid == NULL) {
			fcsm->sm_retry_tid = timeout(fcsm_retry_timeout,
			    (caddr_t)fcsm, fcsm_retry_ticks);
		}
	}

	mutex_exit(&fcsm->sm_mutex);

	if (offline_tid != NULL) {
		(void) untimeout(offline_tid);
	}

	if (retry_tid != NULL) {
		(void) untimeout(retry_tid);
	}

	mutex_enter(&fcsm->sm_mutex);
	fcsm->sm_cb_count--;
	ASSERT(fcsm->sm_cb_count >= 0);
	mutex_exit(&fcsm->sm_mutex);
}


static void
fcsm_offline_timeout(void *handle)
{
	fcsm_t	*fcsm = (fcsm_t *)handle;

	FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, fcsm, NULL,
	    "offline_timeout"));

	mutex_enter(&fcsm->sm_mutex);
	if (fcsm->sm_flags & FCSM_PORT_OFFLINE) {
		fcsm->sm_flags |= FCSM_LINK_DOWN;
	}
	fcsm->sm_offline_tid = (timeout_id_t)NULL;
	fcsm->sm_flags &= ~FCSM_CMD_RETRY_Q_SUSPENDED;

	/* Start the retry thread if needed */
	if (fcsm->sm_retry_head && fcsm->sm_retry_tid == NULL) {
		FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, fcsm, NULL,
		    "offline_timeout: reschedule cmd retry thread"));
		ASSERT(fcsm->sm_retry_tid == NULL);
		fcsm->sm_retry_tid = timeout(fcsm_retry_timeout,
		    (caddr_t)fcsm, fcsm_retry_ticks);
	}
	mutex_exit(&fcsm->sm_mutex);
}

/* ARGSUSED */
static int
fcsm_els_cb(opaque_t ulph, opaque_t port_handle, fc_unsol_buf_t *buf,
    uint32_t claimed)
{
	return (FC_UNCLAIMED);
}


/* ARGSUSED */
static int
fcsm_data_cb(opaque_t ulph, opaque_t port_handle, fc_unsol_buf_t *buf,
    uint32_t claimed)
{
	return (FC_UNCLAIMED);
}


/* ARGSUSED */
static int
fcsm_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rval_p)
{
	int retval = 0;

	FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, NULL, NULL, "ioctl: start"));

	mutex_enter(&fcsm_global_mutex);
	if (!(fcsm_flag & FCSM_OPEN)) {
		mutex_exit(&fcsm_global_mutex);
		return (ENXIO);
	}
	mutex_exit(&fcsm_global_mutex);

	/* Allow only root to talk */
	if (drv_priv(credp)) {
		FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, NULL, NULL,
		    "ioctl: end (disallowing underprivileged user)"));
		return (EPERM);
	}

	switch (cmd) {

	case FCSMIO_CMD: {
		fcio_t	fcio;
		int	status;
#ifdef	_MULTI_DATAMODEL
		switch (ddi_model_convert_from(mode & FMODELS)) {
		case DDI_MODEL_ILP32: {
			struct fcio32 fcio32;

			if (status = ddi_copyin((void *)arg, (void *)&fcio32,
			    sizeof (struct fcio32), mode)) {
				retval = EFAULT;
				break;
			}
			fcio.fcio_xfer = fcio32.fcio_xfer;
			fcio.fcio_cmd = fcio32.fcio_cmd;
			fcio.fcio_flags = fcio32.fcio_flags;
			fcio.fcio_cmd_flags = fcio32.fcio_cmd_flags;
			fcio.fcio_ilen = (size_t)fcio32.fcio_ilen;
			fcio.fcio_ibuf = (caddr_t)(long)fcio32.fcio_ibuf;
			fcio.fcio_olen = (size_t)fcio32.fcio_olen;
			fcio.fcio_obuf = (caddr_t)(long)fcio32.fcio_obuf;
			fcio.fcio_alen = (size_t)fcio32.fcio_alen;
			fcio.fcio_abuf = (caddr_t)(long)fcio32.fcio_abuf;
			fcio.fcio_errno = fcio32.fcio_errno;
			break;
		}

		case DDI_MODEL_NONE:
			if (status = ddi_copyin((void *)arg, (void *)&fcio,
			    sizeof (fcio_t), mode)) {
				retval = EFAULT;
			}
			break;
		}
#else	/* _MULTI_DATAMODEL */
		if (status = ddi_copyin((void *)arg, (void *)&fcio,
		    sizeof (fcio_t), mode)) {
			retval = EFAULT;
			break;
		}
#endif	/* _MULTI_DATAMODEL */
		if (!status) {
			retval = fcsm_fciocmd(arg, mode, credp, &fcio);
		}
		break;
	}

	default:
		retval = ENOTTY;
		break;
	}

	FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, NULL, NULL, "ioctl: end"));
	return (retval);
}

/* ARGSUSED */
static int
fcsm_port_ioctl(opaque_t ulph, opaque_t port_handle, dev_t dev, int cmd,
    intptr_t arg, int mode, cred_t *credp, int *rval, uint32_t claimed)
{
	return (FC_UNCLAIMED);
}


/* ARGSUSED */
static int
fcsm_fciocmd(intptr_t arg, int mode, cred_t *credp, fcio_t *fcio)
{
	int  retval = 0;

	switch (fcio->fcio_cmd) {
	case  FCSMIO_CT_CMD: {
		fcsm_t		*fcsm;
		caddr_t		user_ibuf, user_obuf;
		caddr_t		req_iu, rsp_iu, abuf;
		int		status, instance, count;

		if ((fcio->fcio_xfer != FCIO_XFER_RW) ||
		    (fcio->fcio_ilen == 0) || (fcio->fcio_ibuf == 0) ||
		    (fcio->fcio_olen == 0) || (fcio->fcio_obuf == 0) ||
		    (fcio->fcio_alen == 0) || (fcio->fcio_abuf == 0) ||
		    (fcio->fcio_flags != 0) || (fcio->fcio_cmd_flags != 0) ||
		    (fcio->fcio_ilen > FCSM_MAX_CT_SIZE) ||
		    (fcio->fcio_olen > FCSM_MAX_CT_SIZE) ||
		    (fcio->fcio_alen > MAXPATHLEN)) {
			retval = EINVAL;
			break;
		}

		/*
		 * Get the destination port for which this ioctl
		 * is targeted. The abuf will have the fp_minor
		 * number.
		 */
		abuf = kmem_zalloc(fcio->fcio_alen, KM_SLEEP);
		ASSERT(abuf != NULL);
		if (ddi_copyin(fcio->fcio_abuf, abuf, fcio->fcio_alen, mode)) {
			retval = EFAULT;
			kmem_free(abuf, fcio->fcio_alen);
			break;
		}

		instance = *((int *)abuf);
		kmem_free(abuf, fcio->fcio_alen);

		if (instance < 0) {
			FCSM_DEBUG(SMDL_TRACE, (CE_WARN, SM_LOG, NULL, NULL,
			    "fciocmd: instance 0x%x, invalid instance",
			    instance));
			retval = ENXIO;
			break;
		}

		/*
		 * We confirmed that path corresponds to our port driver
		 * and a valid instance.
		 * If this port instance is not yet attached, then wait
		 * for a finite time for attach to complete
		 */
		fcsm = ddi_get_soft_state(fcsm_state, instance);
		count = 0;
		while (count++ <= 30) {
			if (fcsm != NULL) {
				mutex_enter(&fcsm->sm_mutex);
				if (fcsm->sm_flags & FCSM_ATTACHED) {
					mutex_exit(&fcsm->sm_mutex);
					break;
				}
				mutex_exit(&fcsm->sm_mutex);
			}
			if (count == 1) {
				FCSM_DEBUG(SMDL_TRACE,
				    (CE_WARN, SM_LOG, NULL, NULL,
				    "fciocmd: instance 0x%x, "
				    "wait for port attach", instance));
			}
			delay(drv_usectohz(1000000));
			fcsm = ddi_get_soft_state(fcsm_state, instance);
		}
		if (count > 30) {
			FCSM_DEBUG(SMDL_TRACE, (CE_WARN, SM_LOG, NULL, NULL,
			    "fciocmd: instance 0x%x, port not attached",
			    instance));
			retval = ENXIO;
			break;
		}

		req_iu = kmem_zalloc(fcio->fcio_ilen, KM_SLEEP);
		rsp_iu = kmem_zalloc(fcio->fcio_olen, KM_SLEEP);
		ASSERT((req_iu != NULL) && (rsp_iu != NULL));

		if (ddi_copyin(fcio->fcio_ibuf, req_iu,
		    fcio->fcio_ilen, mode)) {
			retval = EFAULT;
			kmem_free(req_iu, fcio->fcio_ilen);
			kmem_free(rsp_iu, fcio->fcio_olen);
			break;
		}

		user_ibuf = fcio->fcio_ibuf;
		user_obuf = fcio->fcio_obuf;
		fcio->fcio_ibuf = req_iu;
		fcio->fcio_obuf = rsp_iu;

		status = fcsm_ct_passthru(fcsm->sm_instance, fcio, KM_SLEEP,
		    FCSM_JOBFLAG_SYNC, NULL);
		if (status != FC_SUCCESS) {
			retval = EIO;
		}

		FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, fcsm, NULL,
		    "fciocmd: cmd 0x%x completion status 0x%x",
		    fcio->fcio_cmd, status));
		fcio->fcio_errno = status;
		fcio->fcio_ibuf = user_ibuf;
		fcio->fcio_obuf = user_obuf;

		if (ddi_copyout(rsp_iu, fcio->fcio_obuf,
		    fcio->fcio_olen, mode)) {
			retval = EFAULT;
			kmem_free(req_iu, fcio->fcio_ilen);
			kmem_free(rsp_iu, fcio->fcio_olen);
			break;
		}

		kmem_free(req_iu, fcio->fcio_ilen);
		kmem_free(rsp_iu, fcio->fcio_olen);

		if (fcsm_fcio_copyout(fcio, arg, mode)) {
			retval = EFAULT;
		}
		break;
	}

	case  FCSMIO_ADAPTER_LIST: {
		fc_hba_list_t	*list;
		int			count;

		if ((fcio->fcio_xfer != FCIO_XFER_RW) ||
		    (fcio->fcio_olen == 0) || (fcio->fcio_obuf == 0)) {
			retval = EINVAL;
			break;
		}

		list = kmem_zalloc(fcio->fcio_olen, KM_SLEEP);

		if (ddi_copyin(fcio->fcio_obuf, list, fcio->fcio_olen, mode)) {
			retval = EFAULT;
			break;
		}
		list->version = FC_HBA_LIST_VERSION;

		if (fcio->fcio_olen < MAXPATHLEN * list->numAdapters) {
			retval = EFAULT;
			break;
		}

		count = fc_ulp_get_adapter_paths((char *)list->hbaPaths,
		    list->numAdapters);
		if (count < 0) {
			/* Did something go wrong? */
			FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, NULL, NULL,
			    "Error fetching adapter list."));
			retval = ENXIO;
			kmem_free(list, fcio->fcio_olen);
			break;
		}
		/* Sucess (or short buffer) */
		list->numAdapters = count;
		if (ddi_copyout(list, fcio->fcio_obuf,
		    fcio->fcio_olen, mode)) {
			retval = EFAULT;
		}
		kmem_free(list, fcio->fcio_olen);
		break;
	}

	default:
		FCSM_DEBUG(SMDL_TRACE, (CE_NOTE, SM_LOG, NULL, NULL,
		    "fciocmd: unknown cmd <0x%x>", fcio->fcio_cmd));
		retval = ENOTTY;
		break;
	}

	return (retval);
}

static int
fcsm_fcio_copyout(fcio_t *fcio, intptr_t arg, int mode)
{
	int status;

#ifdef	_MULTI_DATAMODEL
	switch (ddi_model_convert_from(mode & FMODELS)) {
	case DDI_MODEL_ILP32: {
		struct fcio32 fcio32;

		fcio32.fcio_xfer = fcio->fcio_xfer;
		fcio32.fcio_cmd = fcio->fcio_cmd;
		fcio32.fcio_flags = fcio->fcio_flags;
		fcio32.fcio_cmd_flags = fcio->fcio_cmd_flags;
		fcio32.fcio_ilen = fcio->fcio_ilen;
		fcio32.fcio_ibuf = (caddr32_t)(long)fcio->fcio_ibuf;
		fcio32.fcio_olen = fcio->fcio_olen;
		fcio32.fcio_obuf = (caddr32_t)(long)fcio->fcio_obuf;
		fcio32.fcio_alen = fcio->fcio_alen;
		fcio32.fcio_abuf = (caddr32_t)(long)fcio->fcio_abuf;
		fcio32.fcio_errno = fcio->fcio_errno;

		status = ddi_copyout((void *)&fcio32, (void *)arg,
		    sizeof (struct fcio32), mode);
		break;
	}
	case DDI_MODEL_NONE:
		status = ddi_copyout((void *)fcio, (void *)arg,
		    sizeof (fcio_t), mode);
		break;
	}
#else	/* _MULTI_DATAMODEL */
	status = ddi_copyout((void *)fcio, (void *)arg, sizeof (fcio_t), mode);
#endif	/* _MULTI_DATAMODEL */

	return (status);
}


/* ARGSUSED */
static int
fcsm_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, NULL, NULL, "open"));

	if (otyp != OTYP_CHR) {
		FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, NULL, NULL,
		    "fcsm_open: failed. open type 0x%x for minor 0x%x is not "
		    "OTYP_CHR", otyp, getminor(*devp)));
		return (EINVAL);
	}

	/*
	 * Allow anybody to open (both root and non-root users).
	 * Previlege level checks are made on the per ioctl basis.
	 */
	mutex_enter(&fcsm_global_mutex);
	if (flags & FEXCL) {
		if (fcsm_flag & FCSM_OPEN) {
			mutex_exit(&fcsm_global_mutex);
			FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, NULL, NULL,
			    "fcsm_open: exclusive open of 0x%x failed",
			    getminor(*devp)));
			return (EBUSY);
		} else {
			ASSERT(fcsm_flag == FCSM_IDLE);
			fcsm_flag |= FCSM_EXCL;
		}
	} else {
		if (fcsm_flag & FCSM_EXCL) {
			mutex_exit(&fcsm_global_mutex);
			FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, NULL, NULL,
			    "fcsm_open: failed. Device minor 0x%x is in "
			    "exclusive open mode", getminor(*devp)));
			return (EBUSY);
		}

	}
	fcsm_flag |= FCSM_OPEN;
	mutex_exit(&fcsm_global_mutex);
	return (0);
}


/* ARGSUSED */
static int
fcsm_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, NULL, NULL, "close"));

	if (otyp != OTYP_CHR) {
		FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, NULL, NULL,
		    "fcsm_close: failed. close type 0x%x for minor 0x%x is not "
		    "OTYP_CHR", otyp, getminor(dev)));
		return (EINVAL);
	}

	mutex_enter(&fcsm_global_mutex);
	if ((fcsm_flag & FCSM_OPEN) == 0) {
		mutex_exit(&fcsm_global_mutex);
		FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, NULL, NULL,
		    "fcsm_close: failed. minor 0x%x is already closed",
		    getminor(dev)));
		return (ENODEV);
	}
	fcsm_flag = FCSM_IDLE;
	mutex_exit(&fcsm_global_mutex);
	return (0);
}


/* ARGSUSED */
static void
fcsm_disp_devlist(fcsm_t *fcsm, fc_portmap_t *devlist, uint32_t dev_cnt)
{
	fc_portmap_t	*map;
	uint32_t	i;

	if (dev_cnt == 0) {
		return;
	}

	ASSERT(devlist != NULL);
	for (i = 0; i < dev_cnt; i++) {
		map = &devlist[i];
		FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, fcsm, NULL,
		    "list[%d]: ID 0x%x WWN %x:%x:%x:%x:%x:%x:%x:%x "
		    "state (0x%x) "
		    "type <%s>(0x%x) "
		    "flags (0x%x)",
		    i, map->map_did.port_id,
		    map->map_pwwn.raw_wwn[0], map->map_pwwn.raw_wwn[1],
		    map->map_pwwn.raw_wwn[2], map->map_pwwn.raw_wwn[3],
		    map->map_pwwn.raw_wwn[4], map->map_pwwn.raw_wwn[5],
		    map->map_pwwn.raw_wwn[6], map->map_pwwn.raw_wwn[7],
		    map->map_state,
		    fcsm_dev_type_to_str(map->map_type), map->map_type,
		    map->map_flags));
	}
}

/* ARGSUSED */
static void
fcsm_display(int level, int flags, fcsm_t *fcsm, fc_packet_t *pkt,
    const char *fmt, ...)
{
	caddr_t	buf;
	va_list	ap;

	buf = kmem_zalloc(256, KM_NOSLEEP);
	if (buf == NULL) {
		return;
	}

	if (fcsm) {
		(void) sprintf(buf + strlen(buf), "fcsm(%d): ",
		    ddi_get_instance(fcsm->sm_port_info.port_dip));
	} else {
		(void) sprintf(buf, "fcsm: ");
	}

	va_start(ap, fmt);
	(void) vsprintf(buf + strlen(buf), fmt, ap);
	va_end(ap);

	if (pkt) {
		caddr_t state, reason, action, expln;

		(void) fc_ulp_pkt_error(pkt, &state, &reason, &action, &expln);

		(void) sprintf(buf + strlen(buf),
		    " state: %s(0x%x); reason: %s(0x%x)",
		    state, pkt->pkt_state, reason, pkt->pkt_reason);
	}

	switch (flags) {
	case SM_LOG:
		cmn_err(level, "!%s", buf);
		break;

	case SM_CONSOLE:
		cmn_err(level, "^%s", buf);
		break;

	default:
		cmn_err(level, "%s", buf);
		break;
	}

	kmem_free(buf, 256);
}


/*
 * Convert FC packet state to FC errno
 */
int
fcsm_pkt_state_to_rval(uchar_t state, uint32_t reason)
{
	int count;

	if (state == FC_PKT_LOCAL_RJT && (reason == FC_REASON_NO_CONNECTION ||
	    reason == FC_REASON_LOGIN_REQUIRED)) {
		return (FC_LOGINREQ);
	} else if (state == FC_PKT_PORT_OFFLINE &&
	    reason == FC_REASON_LOGIN_REQUIRED) {
		return (FC_LOGINREQ);
	}

	for (count = 0; count < sizeof (fcsm_xlat_pkt_state) /
	    sizeof (fcsm_xlat_pkt_state[0]); count++) {
		if (fcsm_xlat_pkt_state[count].xlat_state == state) {
			return (fcsm_xlat_pkt_state[count].xlat_rval);
		}
	}

	return (FC_FAILURE);
}


/*
 * Convert port state state to descriptive string
 */
caddr_t
fcsm_port_state_to_str(uint32_t port_state)
{
	int count;

	for (count = 0; count < sizeof (fcsm_xlat_port_state) /
	    sizeof (fcsm_xlat_port_state[0]); count++) {
		if (fcsm_xlat_port_state[count].xlat_pstate == port_state) {
			return (fcsm_xlat_port_state[count].xlat_state_str);
		}
	}

	return (NULL);
}


/*
 * Convert port topology state to descriptive string
 */
caddr_t
fcsm_topology_to_str(uint32_t topology)
{
	int count;

	for (count = 0; count < sizeof (fcsm_xlat_topology) /
	    sizeof (fcsm_xlat_topology[0]); count++) {
		if (fcsm_xlat_topology[count].xlat_top == topology) {
			return (fcsm_xlat_topology[count].xlat_top_str);
		}
	}

	return (NULL);
}


/*
 * Convert port topology state to descriptive string
 */
static caddr_t
fcsm_dev_type_to_str(uint32_t type)
{
	int count;

	for (count = 0; count < sizeof (fcsm_xlat_dev_type) /
	    sizeof (fcsm_xlat_dev_type[0]); count++) {
		if (fcsm_xlat_dev_type[count].xlat_type == type) {
			return (fcsm_xlat_dev_type[count].xlat_str);
		}
	}

	return (NULL);
}

static int
fcsm_cmd_cache_constructor(void *buf, void *cdarg, int kmflags)
{
	fcsm_cmd_t		*cmd = (fcsm_cmd_t *)buf;
	fcsm_t			*fcsm = (fcsm_t *)cdarg;
	int			(*callback)(caddr_t);
	fc_packet_t		*pkt;
	fc_ulp_port_info_t	*pinfo;

	ASSERT(fcsm != NULL && buf != NULL);
	callback = (kmflags == KM_SLEEP) ? DDI_DMA_SLEEP: DDI_DMA_DONTWAIT;

	cmd->cmd_fp_pkt		= &cmd->cmd_fc_packet;
	cmd->cmd_job		= NULL;
	cmd->cmd_fcsm		= fcsm;
	cmd->cmd_dma_flags	= 0;

	pkt = &cmd->cmd_fc_packet;

	pkt->pkt_ulp_rscn_infop = NULL;
	pkt->pkt_fca_private = (opaque_t)((caddr_t)cmd + sizeof (fcsm_cmd_t));
	pkt->pkt_ulp_private = (opaque_t)cmd;

	if (!(fcsm->sm_flags & FCSM_USING_NODMA_FCA)) {
		pinfo = &fcsm->sm_port_info;
		if (ddi_dma_alloc_handle(pinfo->port_dip,
		    pinfo->port_cmd_dma_attr,
		    callback, NULL, &pkt->pkt_cmd_dma) != DDI_SUCCESS) {
			return (1);
		}

		if (ddi_dma_alloc_handle(pinfo->port_dip,
		    pinfo->port_resp_dma_attr,
		    callback, NULL, &pkt->pkt_resp_dma) != DDI_SUCCESS) {
			ddi_dma_free_handle(&pkt->pkt_cmd_dma);
			return (1);
		}
	} else {
		pkt->pkt_cmd_dma  = NULL;
		pkt->pkt_cmd	  = NULL;
		pkt->pkt_resp_dma = NULL;
		pkt->pkt_resp	  = NULL;
	}

	pkt->pkt_cmd_acc = pkt->pkt_resp_acc = NULL;
	pkt->pkt_cmd_cookie_cnt = pkt->pkt_resp_cookie_cnt =
	    pkt->pkt_data_cookie_cnt = 0;
	pkt->pkt_cmd_cookie = pkt->pkt_resp_cookie =
	    pkt->pkt_data_cookie = NULL;

	return (0);
}


/* ARGSUSED */
static void
fcsm_cmd_cache_destructor(void *buf, void *cdarg)
{
	fcsm_cmd_t	*cmd = (fcsm_cmd_t *)buf;
	fcsm_t		*fcsm = (fcsm_t *)cdarg;
	fc_packet_t	*pkt;

	ASSERT(fcsm == cmd->cmd_fcsm);

	pkt = cmd->cmd_fp_pkt;

	if (pkt->pkt_cmd_dma != NULL) {
		ddi_dma_free_handle(&pkt->pkt_cmd_dma);
	}

	if (pkt->pkt_resp_dma != NULL) {
		ddi_dma_free_handle(&pkt->pkt_resp_dma);
	}
}


static fcsm_cmd_t *
fcsm_alloc_cmd(fcsm_t *fcsm, uint32_t cmd_len, uint32_t resp_len, int sleep)
{
	fcsm_cmd_t	*cmd;
	fc_packet_t	*pkt;
	int		rval;
	ulong_t		real_len;
	int		(*callback)(caddr_t);
	ddi_dma_cookie_t	pkt_cookie;
	ddi_dma_cookie_t	*cp;
	uint32_t		cnt;
	fc_ulp_port_info_t	*pinfo;

	ASSERT(fcsm != NULL);
	pinfo = &fcsm->sm_port_info;

	callback = (sleep == KM_SLEEP) ? DDI_DMA_SLEEP: DDI_DMA_DONTWAIT;

	cmd = (fcsm_cmd_t *)kmem_cache_alloc(fcsm->sm_cmd_cache, sleep);
	if (cmd == NULL) {
		FCSM_DEBUG(SMDL_ERR, (CE_WARN, SM_LOG, fcsm, NULL,
		    "alloc_cmd: kmem_cache_alloc failed"));
		return (NULL);
	}

	cmd->cmd_retry_count	= 0;
	cmd->cmd_max_retries	= 0;
	cmd->cmd_retry_interval	= 0;
	cmd->cmd_transport	= NULL;

	ASSERT(cmd->cmd_dma_flags == 0);
	ASSERT(cmd->cmd_fp_pkt == &cmd->cmd_fc_packet);
	pkt = cmd->cmd_fp_pkt;

	/* Zero out the important fc_packet fields */
	pkt->pkt_pd		= NULL;
	pkt->pkt_datalen	= 0;
	pkt->pkt_data		= NULL;
	pkt->pkt_state		= 0;
	pkt->pkt_action		= 0;
	pkt->pkt_reason		= 0;
	pkt->pkt_expln		= 0;

	/*
	 * Now that pkt_pd is initialized, we can call fc_ulp_init_packet
	 */

	if (fc_ulp_init_packet((opaque_t)pinfo->port_handle, pkt, sleep)
	    != FC_SUCCESS) {
		kmem_cache_free(fcsm->sm_cmd_cache, (void *)cmd);
		return (NULL);
	}

	if ((cmd_len) && !(fcsm->sm_flags & FCSM_USING_NODMA_FCA)) {
		ASSERT(pkt->pkt_cmd_dma != NULL);

		rval = ddi_dma_mem_alloc(pkt->pkt_cmd_dma, cmd_len,
		    fcsm->sm_port_info.port_acc_attr, DDI_DMA_CONSISTENT,
		    callback, NULL, (caddr_t *)&pkt->pkt_cmd, &real_len,
		    &pkt->pkt_cmd_acc);

		if (rval != DDI_SUCCESS) {
			(void) fc_ulp_uninit_packet(
			    (opaque_t)pinfo->port_handle, pkt);
			kmem_cache_free(fcsm->sm_cmd_cache, (void *)cmd);
			fcsm_free_cmd_dma(cmd);
			return (NULL);
		}

		cmd->cmd_dma_flags |= FCSM_CF_CMD_VALID_DMA_MEM;

		if (real_len < cmd_len) {
			(void) fc_ulp_uninit_packet(
			    (opaque_t)pinfo->port_handle, pkt);
			kmem_cache_free(fcsm->sm_cmd_cache, (void *)cmd);
			fcsm_free_cmd_dma(cmd);
			return (NULL);
		}

		rval = ddi_dma_addr_bind_handle(pkt->pkt_cmd_dma, NULL,
		    pkt->pkt_cmd, real_len, DDI_DMA_WRITE | DDI_DMA_CONSISTENT,
		    callback, NULL, &pkt_cookie, &pkt->pkt_cmd_cookie_cnt);

		if (rval != DDI_DMA_MAPPED) {
			(void) fc_ulp_uninit_packet(
			    (opaque_t)pinfo->port_handle, pkt);
			kmem_cache_free(fcsm->sm_cmd_cache, (void *)cmd);
			fcsm_free_cmd_dma(cmd);
			return (NULL);
		}

		cmd->cmd_dma_flags |= FCSM_CF_CMD_VALID_DMA_BIND;

		if (pkt->pkt_cmd_cookie_cnt >
		    pinfo->port_cmd_dma_attr->dma_attr_sgllen) {
			(void) fc_ulp_uninit_packet(
			    (opaque_t)pinfo->port_handle, pkt);
			kmem_cache_free(fcsm->sm_cmd_cache, (void *)cmd);
			fcsm_free_cmd_dma(cmd);
			return (NULL);
		}

		ASSERT(pkt->pkt_cmd_cookie_cnt != 0);

		cp = pkt->pkt_cmd_cookie = (ddi_dma_cookie_t *)kmem_alloc(
		    pkt->pkt_cmd_cookie_cnt * sizeof (pkt_cookie),
		    KM_NOSLEEP);

		if (cp == NULL) {
			(void) fc_ulp_uninit_packet(
			    (opaque_t)pinfo->port_handle, pkt);
			kmem_cache_free(fcsm->sm_cmd_cache, (void *)cmd);
			fcsm_free_cmd_dma(cmd);
			return (NULL);
		}

		*cp = pkt_cookie;
		cp++;
		for (cnt = 1; cnt < pkt->pkt_cmd_cookie_cnt; cnt++, cp++) {
			ddi_dma_nextcookie(pkt->pkt_cmd_dma, &pkt_cookie);
			*cp = pkt_cookie;
		}
	} else if (cmd_len != 0) {
		pkt->pkt_cmd = kmem_zalloc(cmd_len, KM_SLEEP);
	}

	if ((resp_len) && !(fcsm->sm_flags & FCSM_USING_NODMA_FCA)) {
		ASSERT(pkt->pkt_resp_dma != NULL);

		rval = ddi_dma_mem_alloc(pkt->pkt_resp_dma, resp_len,
		    fcsm->sm_port_info.port_acc_attr, DDI_DMA_CONSISTENT,
		    callback, NULL, (caddr_t *)&pkt->pkt_resp, &real_len,
		    &pkt->pkt_resp_acc);

		if (rval != DDI_SUCCESS) {
			(void) fc_ulp_uninit_packet(
			    (opaque_t)pinfo->port_handle, pkt);
			kmem_cache_free(fcsm->sm_cmd_cache, (void *)cmd);
			fcsm_free_cmd_dma(cmd);
			return (NULL);
		}

		cmd->cmd_dma_flags |= FCSM_CF_RESP_VALID_DMA_MEM;

		if (real_len < resp_len) {
			(void) fc_ulp_uninit_packet(
			    (opaque_t)pinfo->port_handle, pkt);
			kmem_cache_free(fcsm->sm_cmd_cache, (void *)cmd);
			fcsm_free_cmd_dma(cmd);
			return (NULL);
		}

		rval = ddi_dma_addr_bind_handle(pkt->pkt_resp_dma, NULL,
		    pkt->pkt_resp, real_len, DDI_DMA_READ | DDI_DMA_CONSISTENT,
		    callback, NULL, &pkt_cookie, &pkt->pkt_resp_cookie_cnt);

		if (rval != DDI_DMA_MAPPED) {
			(void) fc_ulp_uninit_packet(
			    (opaque_t)pinfo->port_handle, pkt);
			kmem_cache_free(fcsm->sm_cmd_cache, (void *)cmd);
			fcsm_free_cmd_dma(cmd);
			return (NULL);
		}

		cmd->cmd_dma_flags |= FCSM_CF_RESP_VALID_DMA_BIND;

		if (pkt->pkt_resp_cookie_cnt >
		    pinfo->port_resp_dma_attr->dma_attr_sgllen) {
			(void) fc_ulp_uninit_packet(
			    (opaque_t)pinfo->port_handle, pkt);
			kmem_cache_free(fcsm->sm_cmd_cache, (void *)cmd);
			fcsm_free_cmd_dma(cmd);
			return (NULL);
		}

		ASSERT(pkt->pkt_resp_cookie_cnt != 0);

		cp = pkt->pkt_resp_cookie = (ddi_dma_cookie_t *)kmem_alloc(
		    pkt->pkt_resp_cookie_cnt * sizeof (pkt_cookie),
		    KM_NOSLEEP);

		if (cp == NULL) {
			(void) fc_ulp_uninit_packet(
			    (opaque_t)pinfo->port_handle, pkt);
			kmem_cache_free(fcsm->sm_cmd_cache, (void *)cmd);
			fcsm_free_cmd_dma(cmd);
			return (NULL);
		}

		*cp = pkt_cookie;
		cp++;
		for (cnt = 1; cnt < pkt->pkt_resp_cookie_cnt; cnt++, cp++) {
			ddi_dma_nextcookie(pkt->pkt_resp_dma, &pkt_cookie);
			*cp = pkt_cookie;
		}
	} else if (resp_len != 0) {
		pkt->pkt_resp = kmem_zalloc(resp_len, KM_SLEEP);
	}

	pkt->pkt_cmdlen = cmd_len;
	pkt->pkt_rsplen = resp_len;

	FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, fcsm, NULL,
	    "alloc_cmd: cmd 0x%p", (void *)cmd));
	return (cmd);
}

static void
fcsm_free_cmd(fcsm_cmd_t *cmd)
{
	fcsm_t		*fcsm;

	fcsm = cmd->cmd_fcsm;
	ASSERT(fcsm != NULL);

	FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, fcsm, NULL,
	    "free_cmd: cmd 0x%p", (void *)cmd));

	fcsm_free_cmd_dma(cmd);

	(void) fc_ulp_uninit_packet((opaque_t)fcsm->sm_port_info.port_handle,
	    cmd->cmd_fp_pkt);
	kmem_cache_free(fcsm->sm_cmd_cache, (void *)cmd);
}

static void
fcsm_free_cmd_dma(fcsm_cmd_t *cmd)
{
	fc_packet_t	*pkt;

	pkt = cmd->cmd_fp_pkt;
	ASSERT(pkt != NULL);

	if (cmd->cmd_fcsm->sm_flags & FCSM_USING_NODMA_FCA) {
		if (pkt->pkt_cmd) {
			kmem_free(pkt->pkt_cmd, pkt->pkt_cmdlen);
			pkt->pkt_cmd = NULL;
		}

		if (pkt->pkt_resp) {
			kmem_free(pkt->pkt_resp, pkt->pkt_rsplen);
			pkt->pkt_resp = NULL;
		}
	}

	pkt->pkt_cmdlen = 0;
	pkt->pkt_rsplen = 0;
	pkt->pkt_tran_type = 0;
	pkt->pkt_tran_flags = 0;

	if (pkt->pkt_cmd_cookie != NULL) {
		kmem_free(pkt->pkt_cmd_cookie, pkt->pkt_cmd_cookie_cnt *
		    sizeof (ddi_dma_cookie_t));
		pkt->pkt_cmd_cookie = NULL;
	}

	if (pkt->pkt_resp_cookie != NULL) {
		kmem_free(pkt->pkt_resp_cookie, pkt->pkt_resp_cookie_cnt *
		    sizeof (ddi_dma_cookie_t));
		pkt->pkt_resp_cookie = NULL;
	}

	if (cmd->cmd_dma_flags & FCSM_CF_CMD_VALID_DMA_BIND) {
		(void) ddi_dma_unbind_handle(pkt->pkt_cmd_dma);
	}

	if (cmd->cmd_dma_flags & FCSM_CF_CMD_VALID_DMA_MEM) {
		if (pkt->pkt_cmd_acc) {
			ddi_dma_mem_free(&pkt->pkt_cmd_acc);
		}
	}

	if (cmd->cmd_dma_flags & FCSM_CF_RESP_VALID_DMA_BIND) {
		(void) ddi_dma_unbind_handle(pkt->pkt_resp_dma);
	}

	if (cmd->cmd_dma_flags & FCSM_CF_RESP_VALID_DMA_MEM) {
		if (pkt->pkt_resp_acc) {
			ddi_dma_mem_free(&pkt->pkt_resp_acc);
		}
	}

	cmd->cmd_dma_flags = 0;
}

/* ARGSUSED */
static int
fcsm_job_cache_constructor(void *buf, void *cdarg, int kmflag)
{
	fcsm_job_t *job = (fcsm_job_t *)buf;

	mutex_init(&job->job_mutex, NULL, MUTEX_DRIVER, NULL);
	sema_init(&job->job_sema, 0, NULL, SEMA_DEFAULT, NULL);

	return (0);
}

/* ARGSUSED */
static void
fcsm_job_cache_destructor(void *buf, void *cdarg)
{
	fcsm_job_t *job = (fcsm_job_t *)buf;

	sema_destroy(&job->job_sema);
	mutex_destroy(&job->job_mutex);
}


static fcsm_job_t *
fcsm_alloc_job(int sleep)
{
	fcsm_job_t	*job;

	job = (fcsm_job_t *)kmem_cache_alloc(fcsm_job_cache, sleep);
	if (job != NULL) {
		job->job_code		= FCSM_JOB_NONE;
		job->job_flags		= 0;
		job->job_port_instance	= -1;
		job->job_result		= -1;
		job->job_arg		= (opaque_t)0;
		job->job_caller_priv	= (opaque_t)0;
		job->job_comp		= NULL;
		job->job_comp_arg	= (opaque_t)0;
		job->job_priv		= (void *)0;
		job->job_priv_flags	= 0;
		job->job_next		= 0;
	}

	return (job);
}

static void
fcsm_dealloc_job(fcsm_job_t *job)
{
	kmem_cache_free(fcsm_job_cache, (void *)job);
}


static void
fcsm_init_job(fcsm_job_t *job, int instance, uint32_t command, uint32_t flags,
    opaque_t arg, opaque_t caller_priv,
    void (*comp)(opaque_t, fcsm_job_t *, int), opaque_t comp_arg)
{
	ASSERT(job != NULL);
	job->job_port_instance	= instance;
	job->job_code		= command;
	job->job_flags		= flags;
	job->job_arg		= arg;
	job->job_caller_priv	= caller_priv;
	job->job_comp		= comp;
	job->job_comp_arg	= comp_arg;
	job->job_retry_count	= 0;
}

static int
fcsm_process_job(fcsm_job_t *job, int priority_flag)
{
	fcsm_t	*fcsm;
	int	sync;

	ASSERT(job != NULL);
	ASSERT(!MUTEX_HELD(&job->job_mutex));

	fcsm = ddi_get_soft_state(fcsm_state, job->job_port_instance);

	if (fcsm == NULL) {
		FCSM_DEBUG(SMDL_ERR, (CE_NOTE, SM_LOG, NULL, NULL,
		    "process_job: port instance 0x%x not found",
		    job->job_port_instance));
		return (FC_BADDEV);
	}

	mutex_enter(&job->job_mutex);
	/* Both SYNC and ASYNC flags should not be set */
	ASSERT(((job->job_flags & (FCSM_JOBFLAG_SYNC | FCSM_JOBFLAG_ASYNC)) ==
	    FCSM_JOBFLAG_SYNC) || ((job->job_flags &
	    (FCSM_JOBFLAG_SYNC | FCSM_JOBFLAG_ASYNC)) == FCSM_JOBFLAG_ASYNC));
	/*
	 * Check if job is a synchronous job. We might not be able to
	 * check it reliably after enque_job(), if job is an ASYNC job.
	 */
	sync = job->job_flags & FCSM_JOBFLAG_SYNC;
	mutex_exit(&job->job_mutex);

	/* Queue the job for processing by job thread */
	fcsm_enque_job(fcsm, job, priority_flag);

	/* Wait for job completion, if it is a synchronous job */
	if (sync) {
		/*
		 * This is a Synchronous Job. So job structure is available.
		 * Caller is responsible for freeing it.
		 */
		FCSM_DEBUG(SMDL_ERR, (CE_CONT, SM_LOG, fcsm, NULL,
		    "process_job: Waiting for sync job <%p> completion",
		    (void *)job));
		sema_p(&job->job_sema);
	}

	return (FC_SUCCESS);
}

static void
fcsm_enque_job(fcsm_t *fcsm, fcsm_job_t *job, int priority_flag)
{
	ASSERT(!MUTEX_HELD(&fcsm->sm_mutex));

	mutex_enter(&fcsm->sm_mutex);
	/* Queue the job at the head or tail depending on the job priority */
	if (priority_flag) {
		FCSM_DEBUG(SMDL_INFO, (CE_CONT, SM_LOG, fcsm, NULL,
		    "enque_job: job 0x%p is high priority", job));
		/* Queue at the head */
		if (fcsm->sm_job_tail == NULL) {
			ASSERT(fcsm->sm_job_head == NULL);
			fcsm->sm_job_head = fcsm->sm_job_tail = job;
		} else {
			ASSERT(fcsm->sm_job_head != NULL);
			job->job_next = fcsm->sm_job_head;
			fcsm->sm_job_head = job;
		}
	} else {
		FCSM_DEBUG(SMDL_INFO, (CE_CONT, SM_LOG, fcsm, NULL,
		    "enque_job: job 0x%p is normal", job));
		/* Queue at the tail */
		if (fcsm->sm_job_tail == NULL) {
			ASSERT(fcsm->sm_job_head == NULL);
			fcsm->sm_job_head = fcsm->sm_job_tail = job;
		} else {
			ASSERT(fcsm->sm_job_head != NULL);
			fcsm->sm_job_tail->job_next = job;
			fcsm->sm_job_tail = job;
		}
		job->job_next = NULL;
	}

	/* Signal the job thread to process the job */
	cv_signal(&fcsm->sm_job_cv);
	mutex_exit(&fcsm->sm_mutex);
}

static int
fcsm_retry_job(fcsm_t *fcsm, fcsm_job_t *job)
{
	/*
	 * If it is a CT passthru job and status is login required, then
	 * retry the job so that login can be performed again.
	 * Ensure that this retry is performed a finite number of times,
	 * so that a faulty fabric does not cause us to retry forever.
	 */

	switch (job->job_code) {
	case FCSM_JOB_CT_PASSTHRU: {
		uint32_t	jobflag;
		fc_ct_header_t	*ct_header;

		if (job->job_result != FC_LOGINREQ) {
			break;
		}

		/*
		 * If it is a management server command
		 * then Reset the Management server login flag, so that login
		 * gets re-established.
		 * If it is a Name server command,
		 * then it is 'fp' responsibility to perform the login.
		 */
		ASSERT(job->job_arg != NULL);
		ct_header =
		    (fc_ct_header_t *)((fcio_t *)job->job_arg)->fcio_ibuf;
		if (ct_header->ct_fcstype == FCSTYPE_MGMTSERVICE) {
			mutex_enter(&fcsm->sm_mutex);
			fcsm->sm_flags &= ~FCSM_MGMT_SERVER_LOGGED_IN;
			mutex_exit(&fcsm->sm_mutex);
		}

		if (job->job_retry_count >= fcsm_max_job_retries) {
			FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, fcsm, NULL,
			    "retry_job: job 0x%p max retries (%d) reached",
			    (void *)job, job->job_retry_count));
			break;
		}

		/*
		 * Login is required again. Retry the command, so that
		 * login will get performed again.
		 */
		mutex_enter(&job->job_mutex);
		job->job_retry_count++;
		jobflag = job->job_flags;
		mutex_exit(&job->job_mutex);

		FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, fcsm, NULL,
		    "retry_job: retry(%d) job 0x%p",
		    job->job_retry_count, (void *)job));
		/*
		 * This job should get picked up before the
		 * other jobs sitting in the queue.
		 * Requeue the command at the head and then
		 * reset the SERIALIZE flag.
		 */
		fcsm_enque_job(fcsm, job, 1);
		if (jobflag & FCSM_JOBFLAG_SERIALIZE) {
			mutex_enter(&fcsm->sm_mutex);
			ASSERT(fcsm->sm_flags & FCSM_SERIALIZE_JOBTHREAD);
			fcsm->sm_flags &= ~FCSM_SERIALIZE_JOBTHREAD;

			/* Signal the job thread to process the job */
			cv_signal(&fcsm->sm_job_cv);
			mutex_exit(&fcsm->sm_mutex);
		}

		/* Command is queued for retrying */
		return (0);
	}

	default:
		break;
	}
	return (1);
}

static void
fcsm_jobdone(fcsm_job_t *job)
{
	fcsm_t	*fcsm;

	fcsm = ddi_get_soft_state(fcsm_state, job->job_port_instance);
	ASSERT(fcsm != NULL);

	if (job->job_result != FC_SUCCESS) {
		if (fcsm_retry_job(fcsm, job) == 0) {
			/* Job retried. so just return from here */
			return;
		}
	}

	if (job->job_comp) {
		job->job_comp(job->job_comp_arg, job, job->job_result);
	}

	mutex_enter(&job->job_mutex);
	if (job->job_flags & FCSM_JOBFLAG_SERIALIZE) {
		mutex_exit(&job->job_mutex);
		mutex_enter(&fcsm->sm_mutex);
		ASSERT(fcsm->sm_flags & FCSM_SERIALIZE_JOBTHREAD);
		fcsm->sm_flags &= ~FCSM_SERIALIZE_JOBTHREAD;

		/* Signal the job thread to process the job */
		cv_signal(&fcsm->sm_job_cv);
		mutex_exit(&fcsm->sm_mutex);
		mutex_enter(&job->job_mutex);
	}

	if (job->job_flags & FCSM_JOBFLAG_SYNC) {
		mutex_exit(&job->job_mutex);
		sema_v(&job->job_sema);
	} else {
		mutex_exit(&job->job_mutex);
		/* Async job, free the job structure */
		fcsm_dealloc_job(job);
	}
}

fcsm_job_t *
fcsm_deque_job(fcsm_t *fcsm)
{
	fcsm_job_t	*job;

	ASSERT(MUTEX_HELD(&fcsm->sm_mutex));

	if (fcsm->sm_job_head == NULL) {
		ASSERT(fcsm->sm_job_tail == NULL);
		job = NULL;
	} else {
		ASSERT(fcsm->sm_job_tail != NULL);
		job = fcsm->sm_job_head;
		if (job->job_next == NULL) {
			ASSERT(fcsm->sm_job_tail == job);
			fcsm->sm_job_tail = NULL;
		}
		fcsm->sm_job_head = job->job_next;
		job->job_next = NULL;
	}

	return (job);
}


/* Dedicated per port thread to process various commands */
static void
fcsm_job_thread(fcsm_t *fcsm)
{
	fcsm_job_t	*job;

	ASSERT(fcsm != NULL);
#ifndef __lock_lint
	CALLB_CPR_INIT(&fcsm->sm_cpr_info, &fcsm->sm_mutex,
	    callb_generic_cpr, "fcsm_job_thread");
#endif /* __lock_lint */

	for (;;) {
		mutex_enter(&fcsm->sm_mutex);

		while (fcsm->sm_job_head == NULL ||
		    fcsm->sm_flags & FCSM_SERIALIZE_JOBTHREAD) {
			CALLB_CPR_SAFE_BEGIN(&fcsm->sm_cpr_info);
			cv_wait(&fcsm->sm_job_cv, &fcsm->sm_mutex);
			CALLB_CPR_SAFE_END(&fcsm->sm_cpr_info, &fcsm->sm_mutex);
		}

		job = fcsm_deque_job(fcsm);

		mutex_exit(&fcsm->sm_mutex);

		mutex_enter(&job->job_mutex);
		if (job->job_flags & FCSM_JOBFLAG_SERIALIZE) {
			mutex_exit(&job->job_mutex);

			mutex_enter(&fcsm->sm_mutex);
			ASSERT(!(fcsm->sm_flags & FCSM_SERIALIZE_JOBTHREAD));
			fcsm->sm_flags |= FCSM_SERIALIZE_JOBTHREAD;
			mutex_exit(&fcsm->sm_mutex);
		} else {
			mutex_exit(&job->job_mutex);
		}

		ASSERT(fcsm->sm_instance == job->job_port_instance);

		switch (job->job_code) {
		case FCSM_JOB_NONE:
			fcsm_display(CE_WARN, SM_LOG, fcsm, NULL,
			    "job_thread: uninitialized job code");
			job->job_result = FC_FAILURE;
			fcsm_jobdone(job);
			break;

		case FCSM_JOB_THREAD_SHUTDOWN:
			FCSM_DEBUG(SMDL_TRACE, (CE_WARN, SM_LOG, fcsm, NULL,
			    "job_thread: job code <JOB PORT SHUTDOWN>"));

			/*
			 * There should not be any pending jobs, when this
			 * is being called.
			 */
			mutex_enter(&fcsm->sm_mutex);
			ASSERT(fcsm->sm_job_head == NULL);
			ASSERT(fcsm->sm_job_tail == NULL);
			ASSERT(fcsm->sm_retry_head == NULL);
			ASSERT(fcsm->sm_retry_tail == NULL);
			job->job_result = FC_SUCCESS;
#ifndef __lock_lint
			CALLB_CPR_EXIT(&fcsm->sm_cpr_info);
#endif
			/* CPR_EXIT has also dropped the fcsm->sm_mutex */

			fcsm_jobdone(job);
			thread_exit();
			/* NOTREACHED */
			break;

		case FCSM_JOB_LOGIN_NAME_SERVER:
			FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, fcsm, NULL,
			    "job_thread: job code <LOGIN_NAME_SERVER>"));
			job->job_result = FC_SUCCESS;
			fcsm_jobdone(job);
			break;

		case FCSM_JOB_LOGIN_MGMT_SERVER:
			FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, fcsm, NULL,
			    "job_thread: job code <LOGIN_MGMT_SERVER>"));
			fcsm_job_login_mgmt_server(job);
			break;

		case FCSM_JOB_CT_PASSTHRU:
			FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, fcsm, NULL,
			    "job_thread: job code <CT_PASSTHRU>"));
			fcsm_job_ct_passthru(job);
			break;

		default:
			FCSM_DEBUG(SMDL_TRACE, (CE_WARN, SM_LOG, fcsm, NULL,
			    "job_thread: job code <UNKNOWN>"));
			job->job_result = FC_FAILURE;
			fcsm_jobdone(job);
			break;
		}
	}

	/* NOTREACHED */
}


static void
fcsm_ct_init(fcsm_t *fcsm, fcsm_cmd_t *cmd, fc_ct_aiu_t *req_iu, size_t req_len,
    void (*comp_func)())
{
	fc_packet_t	*pkt;

	pkt = cmd->cmd_fp_pkt;
	ASSERT(pkt != NULL);

	ASSERT(req_iu->aiu_header.ct_fcstype == FCSTYPE_MGMTSERVICE ||
	    (req_iu->aiu_header.ct_fcstype == FCSTYPE_DIRECTORY &&
	    req_iu->aiu_header.ct_fcssubtype == FCSSUB_DS_NAME_SERVER));


	/* Set the pkt d_id properly */
	if (req_iu->aiu_header.ct_fcstype == FCSTYPE_MGMTSERVICE) {
		pkt->pkt_cmd_fhdr.d_id	= FS_MANAGEMENT_SERVER;
	} else {
		pkt->pkt_cmd_fhdr.d_id	= FS_NAME_SERVER;
	}

	pkt->pkt_cmd_fhdr.r_ctl	= R_CTL_UNSOL_CONTROL;
	pkt->pkt_cmd_fhdr.rsvd	= 0;
	pkt->pkt_cmd_fhdr.s_id	= fcsm->sm_sid;
	pkt->pkt_cmd_fhdr.type	= FC_TYPE_FC_SERVICES;
	pkt->pkt_cmd_fhdr.f_ctl	= F_CTL_SEQ_INITIATIVE |
	    F_CTL_FIRST_SEQ | F_CTL_END_SEQ;
	pkt->pkt_cmd_fhdr.seq_id = 0;
	pkt->pkt_cmd_fhdr.df_ctl = 0;
	pkt->pkt_cmd_fhdr.seq_cnt = 0;
	pkt->pkt_cmd_fhdr.ox_id = 0xffff;
	pkt->pkt_cmd_fhdr.rx_id = 0xffff;
	pkt->pkt_cmd_fhdr.ro	= 0;

	pkt->pkt_timeout	= FCSM_MS_TIMEOUT;
	pkt->pkt_comp		= comp_func;

	FCSM_REP_WR(pkt->pkt_cmd_acc, req_iu, pkt->pkt_cmd, req_len);

	cmd->cmd_transport = fc_ulp_transport;
}

static void
fcsm_ct_intr(fcsm_cmd_t *cmd)
{
	fc_packet_t	*pkt;
	fcsm_job_t	*job;
	fcio_t		*fcio;
	fcsm_t		*fcsm;

	pkt = cmd->cmd_fp_pkt;
	job = cmd->cmd_job;
	ASSERT(job != NULL);

	fcio = job->job_arg;
	ASSERT(fcio != NULL);

	if (pkt->pkt_state != FC_PKT_SUCCESS) {
		FCSM_DEBUG(SMDL_ERR, (CE_NOTE, SM_LOG, cmd->cmd_fcsm, pkt,
		    "ct_intr: CT command <0x%x> to did 0x%x failed",
		    ((fc_ct_aiu_t *)fcio->fcio_ibuf)->aiu_header.ct_cmdrsp,
		    pkt->pkt_cmd_fhdr.d_id));
	} else {
		/* Get the CT response payload */
		fcsm = cmd->cmd_fcsm;
		FCSM_REP_RD(pkt->pkt_resp_acc, fcio->fcio_obuf,
		    pkt->pkt_resp, fcio->fcio_olen);
	}

	job->job_result =
	    fcsm_pkt_state_to_rval(pkt->pkt_state, pkt->pkt_reason);

	fcsm_free_cmd(cmd);

	fcsm_jobdone(job);
}


static void
fcsm_job_ct_passthru(fcsm_job_t *job)
{
	fcsm_t		*fcsm;
	fcio_t		*fcio;
	fcsm_cmd_t	*cmd;
	int		status;
	fc_ct_header_t	*ct_header;

	ASSERT(job != NULL);
	ASSERT(job->job_port_instance != -1);

	job->job_result = FC_FAILURE;
	fcsm = ddi_get_soft_state(fcsm_state, job->job_port_instance);
	if (fcsm == NULL) {
		fcsm_jobdone(job);
		return;
	}

	/*
	 * Process the CT Passthru job only if port is attached
	 * to a FABRIC.
	 */
	if (!FC_TOP_EXTERNAL(fcsm->sm_port_top)) {
		FCSM_DEBUG(SMDL_TRACE, (CE_WARN, SM_LOG, fcsm, NULL,
		    "job_ct_passthru: end (non-fabric port)"));
		job->job_result = FC_BADDEV;
		fcsm_jobdone(job);
		return;
	}

	fcio = job->job_arg;
	ASSERT(fcio != NULL);

	/*
	 * If it is NOT a Management Seriver (MS) or Name Server (NS) command
	 * then complete the command with failure.
	 */
	ct_header = (fc_ct_header_t *)fcio->fcio_ibuf;

	/*
	 * According to libHBAAPI spec, CT header from libHBAAPI would always
	 * be big endian, so we must swap CT header before continue in little
	 * endian platforms.
	 */
	mutex_enter(&job->job_mutex);
	if (!(job->job_flags & FCSM_JOBFLAG_CTHEADER_BE)) {
		job->job_flags |= FCSM_JOBFLAG_CTHEADER_BE;
		*((uint32_t *)((uint32_t *)ct_header + 0)) =
		    BE_32(*((uint32_t *)((uint32_t *)ct_header + 0)));
		*((uint32_t *)((uint32_t *)ct_header + 1)) =
		    BE_32(*((uint32_t *)((uint32_t *)ct_header + 1)));
		*((uint32_t *)((uint32_t *)ct_header + 2)) =
		    BE_32(*((uint32_t *)((uint32_t *)ct_header + 2)));
		*((uint32_t *)((uint32_t *)ct_header + 3)) =
		    BE_32(*((uint32_t *)((uint32_t *)ct_header + 3)));
	}
	mutex_exit(&job->job_mutex);

	if (ct_header->ct_fcstype == FCSTYPE_MGMTSERVICE) {
		FCSM_DEBUG(SMDL_TRACE, (CE_WARN, SM_LOG, fcsm, NULL,
		    "job_ct_passthru: Management Server Cmd"));
	} else if (ct_header->ct_fcstype == FCSTYPE_DIRECTORY) {
		FCSM_DEBUG(SMDL_TRACE, (CE_WARN, SM_LOG, fcsm, NULL,
		    "job_ct_passthru: Name Server Cmd"));
	} else {
		FCSM_DEBUG(SMDL_TRACE, (CE_WARN, SM_LOG, fcsm, NULL,
		    "job_ct_passthru: Unsupported Destination "
		    "gs_type <0x%x> gs_subtype <0x%x>",
		    ct_header->ct_fcstype, ct_header->ct_fcssubtype));
	}

	if (ct_header->ct_fcstype != FCSTYPE_MGMTSERVICE &&
	    (ct_header->ct_fcstype != FCSTYPE_DIRECTORY ||
	    ct_header->ct_fcssubtype != FCSSUB_DS_NAME_SERVER)) {
		FCSM_DEBUG(SMDL_TRACE, (CE_WARN, SM_LOG, fcsm, NULL,
		    "job_ct_passthru: end (Not a Name Server OR "
		    "Mgmt Server Cmd)"));
		job->job_result = FC_BADCMD;
		fcsm_jobdone(job);
		return;
	}

	/*
	 * If it is an MS command and we are not logged in to the management
	 * server, then start the login and requeue the command.
	 * If login to management server is in progress, then reque the
	 * command to wait for login to complete.
	 */
	mutex_enter(&fcsm->sm_mutex);
	if ((ct_header->ct_fcstype == FCSTYPE_MGMTSERVICE) &&
	    !(fcsm->sm_flags & FCSM_MGMT_SERVER_LOGGED_IN)) {
		mutex_exit(&fcsm->sm_mutex);
		if (fcsm_login_and_process_job(fcsm, job) != FC_SUCCESS) {
			FCSM_DEBUG(SMDL_TRACE, (CE_WARN, SM_LOG, fcsm, NULL,
			    "job_ct_passthru: perform login failed"));
			job->job_result = FC_FAILURE;
			fcsm_jobdone(job);
		}
		return;
	}
	mutex_exit(&fcsm->sm_mutex);

	/*
	 * We are already logged in to the management server.
	 * Issue the CT Passthru command
	 */
	cmd = fcsm_alloc_cmd(fcsm, fcio->fcio_ilen, fcio->fcio_olen, KM_SLEEP);
	if (cmd == NULL) {
		job->job_result = FC_NOMEM;
		fcsm_jobdone(job);
		return;
	}

	FCSM_INIT_CMD(cmd, job, FC_TRAN_INTR | FC_TRAN_CLASS3, FC_PKT_EXCHANGE,
	    fcsm_max_cmd_retries, fcsm_ct_intr);

	fcsm_ct_init(fcsm, cmd, (fc_ct_aiu_t *)fcio->fcio_ibuf, fcio->fcio_ilen,
	    fcsm_pkt_common_intr);

	if ((status = fcsm_issue_cmd(cmd)) != FC_SUCCESS) {
		FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, cmd->cmd_fcsm, NULL,
		    "job_ct_passthru: issue CT Passthru failed, status 0x%x",
		    status));
		job->job_result = status;
		fcsm_free_cmd(cmd);
		fcsm_jobdone(job);
		return;
	}
}

static int
fcsm_login_and_process_job(fcsm_t *fcsm, fcsm_job_t *orig_job)
{
	fcsm_job_t	*login_job;
#ifdef DEBUG
	int		status;
#endif /* DEBUG */

	if (orig_job->job_code != FCSM_JOB_CT_PASSTHRU) {
		return (FC_FAILURE);
	}

	FCSM_DEBUG(SMDL_TRACE, (CE_WARN, SM_LOG, fcsm, NULL,
	    "login_and_process_job: start login."));

	mutex_enter(&fcsm->sm_mutex);
	if (fcsm->sm_flags & FCSM_MGMT_SERVER_LOGGED_IN) {
		/*
		 * Directory server login completed just now, while the
		 * mutex was dropped. Just queue the command again for
		 * processing.
		 */
		mutex_exit(&fcsm->sm_mutex);
		FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, fcsm, NULL,
		    "login_and_process_job: got job 0x%p. login just "
		    "completed", (void *)orig_job));
		fcsm_enque_job(fcsm, orig_job, 0);
		return (FC_SUCCESS);
	}

	if (fcsm->sm_flags & FCSM_MGMT_SERVER_LOGIN_IN_PROG) {
		/*
		 * Ideally we shouldn't have come here, since login
		 * job has the serialize flag set.
		 * Anyway, put the command back on the queue.
		 */
		mutex_exit(&fcsm->sm_mutex);
		FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, fcsm, NULL,
		    "login_and_process_job: got job 0x%p while login to "
		    "management server in progress", (void *)orig_job));
		fcsm_enque_job(fcsm, orig_job, 0);
		return (FC_SUCCESS);
	}

	fcsm->sm_flags |= FCSM_MGMT_SERVER_LOGIN_IN_PROG;
	mutex_exit(&fcsm->sm_mutex);

	login_job = fcsm_alloc_job(KM_SLEEP);
	ASSERT(login_job != NULL);

	/*
	 * Mark the login job as SERIALIZE, so that all other jobs will
	 * be processed after completing the login.
	 * Save the original job (CT Passthru job) in the caller private
	 * field in the job structure, so that CT command can be issued
	 * after login has completed.
	 */
	fcsm_init_job(login_job, fcsm->sm_instance, FCSM_JOB_LOGIN_MGMT_SERVER,
	    FCSM_JOBFLAG_ASYNC | FCSM_JOBFLAG_SERIALIZE,
	    (opaque_t)NULL, (opaque_t)orig_job, fcsm_login_ms_comp, NULL);
	orig_job->job_priv = (void *)login_job;

#ifdef DEBUG
	status = fcsm_process_job(login_job, 1);
	ASSERT(status == FC_SUCCESS);
#else /* DEBUG */
	(void) fcsm_process_job(login_job, 1);
#endif /* DEBUG */
	return (FC_SUCCESS);
}


/* ARGSUSED */
static void
fcsm_login_ms_comp(opaque_t comp_arg, fcsm_job_t *login_job, int result)
{
	fcsm_t		*fcsm;
	fcsm_job_t	*orig_job;

	ASSERT(login_job != NULL);

	orig_job = (fcsm_job_t *)login_job->job_caller_priv;

	ASSERT(orig_job != NULL);
	ASSERT(orig_job->job_priv == (void *)login_job);
	orig_job->job_priv = NULL;

	FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, NULL, NULL,
	    "login_ms_comp: result 0x%x", login_job->job_result));

	/* Set the login flag in the per port fcsm structure */
	ASSERT(login_job->job_port_instance == orig_job->job_port_instance);
	fcsm = ddi_get_soft_state(fcsm_state, login_job->job_port_instance);
	ASSERT(fcsm != NULL);

	mutex_enter(&fcsm->sm_mutex);
	ASSERT((fcsm->sm_flags & FCSM_MGMT_SERVER_LOGGED_IN) == 0);
	ASSERT(fcsm->sm_flags & FCSM_MGMT_SERVER_LOGIN_IN_PROG);
	fcsm->sm_flags &= ~FCSM_MGMT_SERVER_LOGIN_IN_PROG;
	if (login_job->job_result != FC_SUCCESS) {
		caddr_t	msg;

		/*
		 * Login failed. Complete the original job with FC_LOGINREQ
		 * status. Retry of that job will cause login to be
		 * retried.
		 */
		mutex_exit(&fcsm->sm_mutex);
		orig_job->job_result = FC_LOGINREQ;
		fcsm_jobdone(orig_job);

		(void) fc_ulp_error(login_job->job_result, &msg);
		fcsm_display(CE_WARN, SM_LOG, fcsm, NULL,
		    "login_ms_comp: Management server login failed: <%s>", msg);
		return;
	}
	fcsm->sm_flags |= FCSM_MGMT_SERVER_LOGGED_IN;
	mutex_exit(&fcsm->sm_mutex);

	/*
	 * Queue the original job at the head of the queue for processing.
	 */
	fcsm_enque_job(fcsm, orig_job, 1);
}


static void
fcsm_els_init(fcsm_cmd_t *cmd, uint32_t d_id)
{
	fc_packet_t	*pkt;
	fcsm_t		*fcsm;

	fcsm = cmd->cmd_fcsm;
	pkt = cmd->cmd_fp_pkt;
	ASSERT(fcsm != NULL && pkt != NULL);

	pkt->pkt_cmd_fhdr.r_ctl	= R_CTL_ELS_REQ;
	pkt->pkt_cmd_fhdr.d_id	= d_id;
	pkt->pkt_cmd_fhdr.rsvd	= 0;
	pkt->pkt_cmd_fhdr.s_id	= fcsm->sm_sid;
	pkt->pkt_cmd_fhdr.type	= FC_TYPE_EXTENDED_LS;
	pkt->pkt_cmd_fhdr.f_ctl	= F_CTL_SEQ_INITIATIVE | F_CTL_FIRST_SEQ;
	pkt->pkt_cmd_fhdr.seq_id = 0;
	pkt->pkt_cmd_fhdr.df_ctl = 0;
	pkt->pkt_cmd_fhdr.seq_cnt = 0;
	pkt->pkt_cmd_fhdr.ox_id = 0xffff;
	pkt->pkt_cmd_fhdr.rx_id = 0xffff;
	pkt->pkt_cmd_fhdr.ro	= 0;

	pkt->pkt_timeout	= FCSM_ELS_TIMEOUT;
}


static int
fcsm_xlogi_init(fcsm_t *fcsm, fcsm_cmd_t *cmd, uint32_t d_id,
    void (*comp_func)(), uchar_t ls_code)
{
	ls_code_t	payload;
	fc_packet_t	*pkt;
	la_els_logi_t	*login_params;
	int		status;

	login_params = (la_els_logi_t *)
	    kmem_zalloc(sizeof (la_els_logi_t), KM_SLEEP);
	if (login_params == NULL) {
		return (FC_NOMEM);
	}

	status = fc_ulp_get_port_login_params(fcsm->sm_port_info.port_handle,
	    login_params);
	if (status != FC_SUCCESS) {
		kmem_free(login_params, sizeof (la_els_logi_t));
		return (status);
	}

	pkt = cmd->cmd_fp_pkt;

	fcsm_els_init(cmd, d_id);
	pkt->pkt_comp = comp_func;

	payload.ls_code = ls_code;
	payload.mbz = 0;

	FCSM_REP_WR(pkt->pkt_cmd_acc, login_params,
	    pkt->pkt_cmd, sizeof (la_els_logi_t));
	FCSM_REP_WR(pkt->pkt_cmd_acc, &payload,
	    pkt->pkt_cmd, sizeof (payload));

	cmd->cmd_transport = fc_ulp_issue_els;

	kmem_free(login_params, sizeof (la_els_logi_t));

	return (FC_SUCCESS);
}

static void
fcsm_xlogi_intr(fcsm_cmd_t *cmd)
{
	fc_packet_t	*pkt;
	fcsm_job_t	*job;
	fcsm_t		*fcsm;

	pkt = cmd->cmd_fp_pkt;
	job = cmd->cmd_job;
	ASSERT(job != NULL);

	fcsm = cmd->cmd_fcsm;
	ASSERT(fcsm != NULL);

	if (pkt->pkt_state != FC_PKT_SUCCESS) {
		fcsm_display(CE_WARN, SM_LOG, fcsm, pkt,
		    "xlogi_intr: login to DID 0x%x failed",
		    pkt->pkt_cmd_fhdr.d_id);
	} else {
		/* Get the Login parameters of the Management Server */
		FCSM_REP_RD(pkt->pkt_resp_acc, &fcsm->sm_ms_service_params,
		    pkt->pkt_resp, sizeof (la_els_logi_t));
	}

	job->job_result =
	    fcsm_pkt_state_to_rval(pkt->pkt_state, pkt->pkt_reason);

	fcsm_free_cmd(cmd);

	fcsm_jobdone(job);
}

static void
fcsm_job_login_mgmt_server(fcsm_job_t *job)
{
	fcsm_t		*fcsm;
	fcsm_cmd_t	*cmd;
	int		status;

	ASSERT(job != NULL);
	ASSERT(job->job_port_instance != -1);

	fcsm = ddi_get_soft_state(fcsm_state, job->job_port_instance);
	if (fcsm == NULL) {
		job->job_result = FC_NOMEM;
		fcsm_jobdone(job);
		return;
	}

	/*
	 * Issue the  Login command to the management server.
	 */
	cmd = fcsm_alloc_cmd(fcsm, sizeof (la_els_logi_t),
	    sizeof (la_els_logi_t), KM_SLEEP);
	if (cmd == NULL) {
		job->job_result = FC_NOMEM;
		fcsm_jobdone(job);
		return;
	}

	FCSM_INIT_CMD(cmd, job, FC_TRAN_INTR | FC_TRAN_CLASS3, FC_PKT_EXCHANGE,
	    fcsm_max_cmd_retries, fcsm_xlogi_intr);

	status = fcsm_xlogi_init(fcsm, cmd, FS_MANAGEMENT_SERVER,
	    fcsm_pkt_common_intr, LA_ELS_PLOGI);

	if (status != FC_SUCCESS) {
		FCSM_DEBUG(SMDL_TRACE, (CE_WARN, SM_LOG, fcsm, NULL,
		    "job_login_mgmt_server: plogi init failed. status 0x%x",
		    status));
		job->job_result = status;
		fcsm_free_cmd(cmd);
		fcsm_jobdone(job);
		return;
	}

	if ((status = fcsm_issue_cmd(cmd)) != FC_SUCCESS) {
		FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, cmd->cmd_fcsm, NULL,
		    "job_ct_passthru: issue login cmd failed, status 0x%x",
		    status));
		job->job_result = status;
		fcsm_free_cmd(cmd);
		fcsm_jobdone(job);
		return;
	}
}


int
fcsm_ct_passthru(int instance, fcio_t *fcio, int sleep, int job_flags,
    void (*func)(fcio_t *))
{
	fcsm_job_t	*job;
	int		status;

	FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, NULL, NULL,
	    "ct_passthru: instance 0x%x fcio 0x%p", instance, fcio));
	job = fcsm_alloc_job(sleep);
	ASSERT(sleep == KM_NOSLEEP || job != NULL);

	fcsm_init_job(job, instance, FCSM_JOB_CT_PASSTHRU, job_flags,
	    (opaque_t)fcio, (opaque_t)func, fcsm_ct_passthru_comp, NULL);
	status = fcsm_process_job(job, 0);
	if (status != FC_SUCCESS) {
		/* Job could not be issued. So free the job and return */
		fcsm_dealloc_job(job);
		return (status);
	}

	if (job_flags & FCSM_JOBFLAG_SYNC) {
		status = job->job_result;
		fcsm_dealloc_job(job);
	}

	return (status);
}


/* ARGSUSED */
static void
fcsm_ct_passthru_comp(opaque_t comp_arg, fcsm_job_t *job, int result)
{
	ASSERT(job != NULL);
	FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, NULL, NULL,
	    "ct_passthru_comp: result 0x%x port 0x%x",
	    job->job_result, job->job_port_instance));
}


static void
fcsm_pkt_common_intr(fc_packet_t *pkt)
{
	fcsm_cmd_t	*cmd;
	int		jobstatus;
	fcsm_t		*fcsm;

	FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, NULL, NULL,
	    "pkt_common_intr"));

	cmd = (fcsm_cmd_t *)pkt->pkt_ulp_private;
	ASSERT(cmd != NULL);

	if (pkt->pkt_state == FC_PKT_SUCCESS) {
		/* Command completed successfully. Just complete the command */
		cmd->cmd_comp(cmd);
		return;
	}

	fcsm = cmd->cmd_fcsm;
	ASSERT(fcsm != NULL);

	FCSM_DEBUG(SMDL_ERR, (CE_NOTE, SM_LOG, cmd->cmd_fcsm, pkt,
	    "fc packet to DID 0x%x failed for pkt 0x%p",
	    pkt->pkt_cmd_fhdr.d_id, pkt));

	mutex_enter(&fcsm->sm_mutex);
	if (fcsm->sm_flags & FCSM_LINK_DOWN) {
		/*
		 * No need to retry the command. The link previously
		 * suffered an offline	timeout.
		 */
		mutex_exit(&fcsm->sm_mutex);
		FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, cmd->cmd_fcsm, NULL,
		    "pkt_common_intr: end. Link is down"));
		cmd->cmd_comp(cmd);
		return;
	}
	mutex_exit(&fcsm->sm_mutex);

	jobstatus = fcsm_pkt_state_to_rval(pkt->pkt_state, pkt->pkt_reason);
	if (jobstatus == FC_LOGINREQ) {
		/*
		 * Login to the destination is required. No need to
		 * retry this cmd again.
		 */
		FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, cmd->cmd_fcsm, NULL,
		    "pkt_common_intr: end. LOGIN required"));
		cmd->cmd_comp(cmd);
		return;
	}

	switch (pkt->pkt_state) {
	case FC_PKT_PORT_OFFLINE:
	case FC_PKT_LOCAL_RJT:
	case FC_PKT_TIMEOUT: {
		uchar_t		pkt_state;

		pkt_state = pkt->pkt_state;
		cmd->cmd_retry_interval = fcsm_retry_interval;
		if (fcsm_retry_cmd(cmd) != 0) {
			FCSM_DEBUG(SMDL_TRACE, (CE_WARN, SM_LOG,
			    cmd->cmd_fcsm, NULL,
			    "common_intr: max retries(%d) reached, status 0x%x",
			    cmd->cmd_retry_count));

			/*
			 * Restore the pkt_state to the actual failure status
			 * received at the time of pkt completion.
			 */
			pkt->pkt_state = pkt_state;
			pkt->pkt_reason = 0;
			cmd->cmd_comp(cmd);
		} else {
			FCSM_DEBUG(SMDL_TRACE, (CE_WARN, SM_LOG,
			    cmd->cmd_fcsm, NULL,
			    "pkt_common_intr: retry(%d) on pkt state (0x%x)",
			    cmd->cmd_retry_count, pkt_state));
		}
		break;
	}
	default:
		cmd->cmd_comp(cmd);
		break;
	}
}

static int
fcsm_issue_cmd(fcsm_cmd_t *cmd)
{
	fc_packet_t	*pkt;
	fcsm_t		*fcsm;
	int		status;

	pkt = cmd->cmd_fp_pkt;
	fcsm = cmd->cmd_fcsm;

	/* Explicitly invalidate this field till fcsm decides to use it */
	pkt->pkt_ulp_rscn_infop = NULL;

	FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, fcsm, NULL,
	    "issue_cmd: entry"));

	ASSERT(!MUTEX_HELD(&fcsm->sm_mutex));
	mutex_enter(&fcsm->sm_mutex);
	if (fcsm->sm_flags & FCSM_LINK_DOWN) {
		/*
		 * Update the pkt_state/pkt_reason appropriately.
		 * Caller of this function can decide whether to call
		 * 'pkt->pkt_comp' or use the 'status' returned by this func.
		 */
		mutex_exit(&fcsm->sm_mutex);
		pkt->pkt_state = FC_PKT_PORT_OFFLINE;
		pkt->pkt_reason = FC_REASON_OFFLINE;
		return (FC_OFFLINE);
	}
	mutex_exit(&fcsm->sm_mutex);

	ASSERT(cmd->cmd_transport != NULL);
	status = cmd->cmd_transport(fcsm->sm_port_info.port_handle, pkt);
	if (status != FC_SUCCESS) {
		switch (status) {
		case FC_LOGINREQ:
			/*
			 * No need to retry. Return the cause of failure.
			 * Also update the pkt_state/pkt_reason. Caller of
			 * this function can decide, whether to call
			 * 'pkt->pkt_comp' or use the 'status' code returned
			 * by this function.
			 */
			pkt->pkt_state = FC_PKT_LOCAL_RJT;
			pkt->pkt_reason = FC_REASON_LOGIN_REQUIRED;
			break;

		case FC_DEVICE_BUSY_NEW_RSCN:
			/*
			 * There was a newer RSCN than what fcsm knows about.
			 * So, just retry again
			 */
			cmd->cmd_retry_count = 0;
			/*FALLTHROUGH*/
		case FC_OFFLINE:
		case FC_STATEC_BUSY:
			/*
			 * TODO: set flag, so that command is retried after
			 * port is back online.
			 * FALL Through for now.
			 */

		case FC_TRAN_BUSY:
		case FC_NOMEM:
		case FC_DEVICE_BUSY:
			cmd->cmd_retry_interval = fcsm_retry_interval;
			if (fcsm_retry_cmd(cmd) != 0) {
				FCSM_DEBUG(SMDL_TRACE,
				    (CE_WARN, SM_LOG, fcsm, NULL,
				    "issue_cmd: max retries (%d) reached",
				    cmd->cmd_retry_count));

				/*
				 * status variable is not changed here.
				 * Return the cause of the original
				 * cmd_transport failure.
				 * Update the pkt_state/pkt_reason. Caller
				 * of this function can decide whether to
				 * call 'pkt->pkt_comp' or use the 'status'
				 * code returned by this function.
				 */
				pkt->pkt_state = FC_PKT_TRAN_BSY;
				pkt->pkt_reason = 0;
			} else {
				FCSM_DEBUG(SMDL_TRACE,
				    (CE_WARN, SM_LOG, fcsm, NULL,
				    "issue_cmd: retry (%d) on fc status (0x%x)",
				    cmd->cmd_retry_count, status));

				status = FC_SUCCESS;
			}
			break;

		default:
			FCSM_DEBUG(SMDL_TRACE, (CE_WARN, SM_LOG, fcsm, NULL,
			    "issue_cmd: failure status 0x%x", status));

			pkt->pkt_state = FC_PKT_TRAN_ERROR;
			pkt->pkt_reason = 0;
			break;


		}
	}

	return (status);
}


static int
fcsm_retry_cmd(fcsm_cmd_t *cmd)
{
	if (cmd->cmd_retry_count < cmd->cmd_max_retries) {
		cmd->cmd_retry_count++;
		fcsm_enque_cmd(cmd->cmd_fcsm, cmd);
		return (0);
	}

	return (1);
}

static void
fcsm_enque_cmd(fcsm_t *fcsm, fcsm_cmd_t *cmd)
{
	ASSERT(!MUTEX_HELD(&fcsm->sm_mutex));

	FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, fcsm, NULL, "enque_cmd"));

	cmd->cmd_next = NULL;
	mutex_enter(&fcsm->sm_mutex);
	if (fcsm->sm_retry_tail) {
		ASSERT(fcsm->sm_retry_head != NULL);
		fcsm->sm_retry_tail->cmd_next = cmd;
		fcsm->sm_retry_tail = cmd;
	} else {
		ASSERT(fcsm->sm_retry_tail == NULL);
		fcsm->sm_retry_head = fcsm->sm_retry_tail = cmd;

		/* Schedule retry thread, if not already running */
		if (fcsm->sm_retry_tid == NULL) {
			FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, fcsm, NULL,
			    "enque_cmd: schedule retry thread"));
			fcsm->sm_retry_tid = timeout(fcsm_retry_timeout,
			    (caddr_t)fcsm, fcsm_retry_ticks);
		}
	}
	mutex_exit(&fcsm->sm_mutex);
}


static fcsm_cmd_t *
fcsm_deque_cmd(fcsm_t *fcsm)
{
	fcsm_cmd_t	*cmd;

	ASSERT(!MUTEX_HELD(&fcsm->sm_mutex));

	FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, fcsm, NULL, "deque_cmd"));

	mutex_enter(&fcsm->sm_mutex);
	if (fcsm->sm_retry_head == NULL) {
		ASSERT(fcsm->sm_retry_tail == NULL);
		cmd = NULL;
	} else {
		cmd = fcsm->sm_retry_head;
		fcsm->sm_retry_head = cmd->cmd_next;
		if (fcsm->sm_retry_head == NULL) {
			fcsm->sm_retry_tail = NULL;
		}
		cmd->cmd_next = NULL;
	}
	mutex_exit(&fcsm->sm_mutex);

	return (cmd);
}

static void
fcsm_retry_timeout(void *handle)
{
	fcsm_t		*fcsm;
	fcsm_cmd_t	*curr_tail;
	fcsm_cmd_t	*cmd;
	int		done = 0;
	int		linkdown;

	fcsm = (fcsm_t *)handle;

	FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, fcsm, NULL, "retry_timeout"));

	/*
	 * If retry cmd queue is suspended, then go away.
	 * This retry thread will be restarted, when cmd queue resumes.
	 */
	mutex_enter(&fcsm->sm_mutex);
	if (fcsm->sm_flags & FCSM_CMD_RETRY_Q_SUSPENDED) {
		/*
		 * Clear the retry_tid, to indicate that this routine is not
		 * currently being rescheduled.
		 */
		fcsm->sm_retry_tid = (timeout_id_t)NULL;
		mutex_exit(&fcsm->sm_mutex);
		FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, fcsm, NULL,
		    "retry_timeout: end. No processing. "
		    "Queue is currently suspended for this instance"));
		return;
	}

	linkdown = (fcsm->sm_flags & FCSM_LINK_DOWN) ? 1 : 0;

	/*
	 * Save the curr_tail, so that we only process the commands
	 * which are in the queue at this time.
	 */
	curr_tail = fcsm->sm_retry_tail;
	mutex_exit(&fcsm->sm_mutex);

	/*
	 * Check for done flag before dequeing the command.
	 * Dequeing before checking the done flag will cause a command
	 * to be lost.
	 */
	while ((!done) && ((cmd = fcsm_deque_cmd(fcsm)) != NULL)) {

		if (cmd == curr_tail) {
			done = 1;
		}

		cmd->cmd_retry_interval -= fcsm_retry_ticker;

		if (linkdown) {
			fc_packet_t *pkt;

			/*
			 * No need to retry the command. The link has
			 * suffered an offline	timeout.
			 */
			pkt = cmd->cmd_fp_pkt;
			pkt->pkt_state = FC_PKT_PORT_OFFLINE;
			pkt->pkt_reason = FC_REASON_OFFLINE;
			pkt->pkt_comp(pkt);
			continue;
		}

		if (cmd->cmd_retry_interval <= 0) {
			/* Retry the command */
			FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, fcsm, NULL,
			    "retry_timeout: issue cmd 0x%p", (void *)cmd));
			if (fcsm_issue_cmd(cmd) != FC_SUCCESS) {
				cmd->cmd_fp_pkt->pkt_comp(cmd->cmd_fp_pkt);
			}
		} else {
			/*
			 * Put the command back on the queue. Retry time
			 * has not yet reached.
			 */
			FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, fcsm, NULL,
			    "retry_timeout: queue cmd 0x%p", (void *)cmd));
			fcsm_enque_cmd(fcsm, cmd);
		}
	}

	mutex_enter(&fcsm->sm_mutex);
	if (fcsm->sm_retry_head) {
		/* Activate timer */
		fcsm->sm_retry_tid = timeout(fcsm_retry_timeout,
		    (caddr_t)fcsm, fcsm_retry_ticks);
		FCSM_DEBUG(SMDL_TRACE, (CE_CONT, SM_LOG, fcsm, NULL,
		    "retry_timeout: retry thread rescheduled"));
	} else {
		/*
		 * Reset the tid variable. The first thread which queues the
		 * command, will restart the timer.
		 */
		fcsm->sm_retry_tid = (timeout_id_t)NULL;
	}
	mutex_exit(&fcsm->sm_mutex);
}
