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
 * NOT a DDI compliant Sun Fibre Channel port driver(fp)
 *
 */

#include <sys/types.h>
#include <sys/varargs.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/uio.h>
#include <sys/buf.h>
#include <sys/modctl.h>
#include <sys/open.h>
#include <sys/file.h>
#include <sys/kmem.h>
#include <sys/poll.h>
#include <sys/conf.h>
#include <sys/thread.h>
#include <sys/var.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/promif.h>
#include <sys/nvpair.h>
#include <sys/byteorder.h>
#include <sys/scsi/scsi.h>
#include <sys/fibre-channel/fc.h>
#include <sys/fibre-channel/impl/fc_ulpif.h>
#include <sys/fibre-channel/impl/fc_fcaif.h>
#include <sys/fibre-channel/impl/fctl_private.h>
#include <sys/fibre-channel/impl/fc_portif.h>
#include <sys/fibre-channel/impl/fp.h>

/* These are defined in fctl.c! */
extern int did_table_size;
extern int pwwn_table_size;

static struct cb_ops fp_cb_ops = {
	fp_open,			/* open */
	fp_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	fp_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* chpoll */
	ddi_prop_op,			/* cb_prop_op */
	0,				/* streamtab */
	D_NEW | D_MP | D_HOTPLUG,	/* cb_flag */
	CB_REV,				/* rev */
	nodev,				/* aread */
	nodev				/* awrite */
};

static struct dev_ops fp_ops = {
	DEVO_REV,			/* build revision */
	0,				/* reference count */
	fp_getinfo,			/* getinfo */
	nulldev,			/* identify - Obsoleted */
	nulldev,			/* probe */
	fp_attach,			/* attach */
	fp_detach,			/* detach */
	nodev,				/* reset */
	&fp_cb_ops,			/* cb_ops */
	NULL,				/* bus_ops */
	fp_power,			/* power */
	ddi_quiesce_not_needed		/* quiesce */
};

#define	FP_VERSION		"20091123-1.101"
#define	FP_NAME_VERSION		"SunFC Port v" FP_VERSION

char *fp_version = FP_NAME_VERSION;

static struct modldrv modldrv = {
	&mod_driverops,			/* Type of Module */
	FP_NAME_VERSION,		/* Name/Version of fp */
	&fp_ops				/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,	/* Rev of the loadable modules system */
	&modldrv,	/* NULL terminated list of */
	NULL		/* Linkage structures */
};



static uint16_t ns_reg_cmds[] = {
	NS_RPN_ID,
	NS_RNN_ID,
	NS_RCS_ID,
	NS_RFT_ID,
	NS_RPT_ID,
	NS_RSPN_ID,
	NS_RSNN_NN
};

struct fp_xlat {
	uchar_t	xlat_state;
	int	xlat_rval;
} fp_xlat [] = {
	{ FC_PKT_SUCCESS,	FC_SUCCESS },
	{ FC_PKT_REMOTE_STOP,	FC_FAILURE },
	{ FC_PKT_LOCAL_RJT,	FC_FAILURE },
	{ FC_PKT_NPORT_RJT,	FC_ELS_PREJECT },
	{ FC_PKT_FABRIC_RJT,	FC_ELS_FREJECT },
	{ FC_PKT_LOCAL_BSY,	FC_TRAN_BUSY },
	{ FC_PKT_TRAN_BSY,	FC_TRAN_BUSY },
	{ FC_PKT_NPORT_BSY,	FC_PBUSY },
	{ FC_PKT_FABRIC_BSY,	FC_FBUSY },
	{ FC_PKT_LS_RJT,	FC_FAILURE },
	{ FC_PKT_BA_RJT,	FC_FAILURE },
	{ FC_PKT_TIMEOUT,	FC_FAILURE },
	{ FC_PKT_TRAN_ERROR,	FC_TRANSPORT_ERROR },
	{ FC_PKT_FAILURE,	FC_FAILURE },
	{ FC_PKT_PORT_OFFLINE,	FC_OFFLINE }
};

static uchar_t fp_valid_alpas[] = {
	0x01, 0x02, 0x04, 0x08, 0x0F, 0x10, 0x17, 0x18, 0x1B,
	0x1D, 0x1E, 0x1F, 0x23, 0x25, 0x26, 0x27, 0x29, 0x2A,
	0x2B, 0x2C, 0x2D, 0x2E, 0x31, 0x32, 0x33, 0x34, 0x35,
	0x36, 0x39, 0x3A, 0x3C, 0x43, 0x45, 0x46, 0x47, 0x49,
	0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x51, 0x52, 0x53, 0x54,
	0x55, 0x56, 0x59, 0x5A, 0x5C, 0x63, 0x65, 0x66, 0x67,
	0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x71, 0x72, 0x73,
	0x74, 0x75, 0x76, 0x79, 0x7A, 0x7C, 0x80, 0x81, 0x82,
	0x84, 0x88, 0x8F, 0x90, 0x97, 0x98, 0x9B, 0x9D, 0x9E,
	0x9F, 0xA3, 0xA5, 0xA6, 0xA7, 0xA9, 0xAA, 0xAB, 0xAC,
	0xAD, 0xAE, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB9,
	0xBA, 0xBC, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB,
	0xCC, 0xCD, 0xCE, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6,
	0xD9, 0xDA, 0xDC, 0xE0, 0xE1, 0xE2, 0xE4, 0xE8, 0xEF
};

static struct fp_perms {
	uint16_t	fp_ioctl_cmd;
	uchar_t		fp_open_flag;
} fp_perm_list [] = {
	{ FCIO_GET_NUM_DEVS,		FP_OPEN },
	{ FCIO_GET_DEV_LIST,		FP_OPEN },
	{ FCIO_GET_SYM_PNAME,		FP_OPEN },
	{ FCIO_GET_SYM_NNAME,		FP_OPEN },
	{ FCIO_SET_SYM_PNAME,		FP_EXCL },
	{ FCIO_SET_SYM_NNAME,		FP_EXCL },
	{ FCIO_GET_LOGI_PARAMS,		FP_OPEN },
	{ FCIO_DEV_LOGIN,		FP_EXCL },
	{ FCIO_DEV_LOGOUT,		FP_EXCL },
	{ FCIO_GET_STATE,		FP_OPEN },
	{ FCIO_DEV_REMOVE,		FP_EXCL },
	{ FCIO_GET_FCODE_REV,		FP_OPEN },
	{ FCIO_GET_FW_REV,		FP_OPEN },
	{ FCIO_GET_DUMP_SIZE,		FP_OPEN },
	{ FCIO_FORCE_DUMP,		FP_EXCL },
	{ FCIO_GET_DUMP,		FP_OPEN },
	{ FCIO_GET_TOPOLOGY,		FP_OPEN },
	{ FCIO_RESET_LINK,		FP_EXCL },
	{ FCIO_RESET_HARD,		FP_EXCL },
	{ FCIO_RESET_HARD_CORE,		FP_EXCL },
	{ FCIO_DIAG,			FP_OPEN },
	{ FCIO_NS,			FP_EXCL },
	{ FCIO_DOWNLOAD_FW,		FP_EXCL },
	{ FCIO_DOWNLOAD_FCODE,		FP_EXCL },
	{ FCIO_LINK_STATUS,		FP_OPEN },
	{ FCIO_GET_HOST_PARAMS,		FP_OPEN },
	{ FCIO_GET_NODE_ID,		FP_OPEN },
	{ FCIO_SET_NODE_ID,		FP_EXCL },
	{ FCIO_SEND_NODE_ID,		FP_OPEN },
	{ FCIO_GET_ADAPTER_ATTRIBUTES,	FP_OPEN },
	{ FCIO_GET_OTHER_ADAPTER_PORTS,	FP_OPEN },
	{ FCIO_GET_ADAPTER_PORT_ATTRIBUTES,	FP_OPEN },
	{ FCIO_GET_DISCOVERED_PORT_ATTRIBUTES,	FP_OPEN },
	{ FCIO_GET_PORT_ATTRIBUTES,	FP_OPEN },
	{ FCIO_GET_ADAPTER_PORT_STATS,	FP_OPEN },
	{ FCIO_GET_ADAPTER_PORT_NPIV_ATTRIBUTES, FP_OPEN },
	{ FCIO_GET_NPIV_PORT_LIST, FP_OPEN },
	{ FCIO_DELETE_NPIV_PORT, FP_OPEN },
	{ FCIO_GET_NPIV_ATTRIBUTES, FP_OPEN },
	{ FCIO_CREATE_NPIV_PORT, FP_OPEN },
	{ FCIO_NPIV_GET_ADAPTER_ATTRIBUTES, FP_OPEN }
};

static char *fp_pm_comps[] = {
	"NAME=FC Port",
	"0=Port Down",
	"1=Port Up"
};


#ifdef	_LITTLE_ENDIAN
#define	MAKE_BE_32(x)	{						\
		uint32_t	*ptr1, i;				\
		ptr1 = (uint32_t *)(x);					\
		for (i = 0; i < sizeof (*(x)) / sizeof (uint32_t); i++) { \
			*ptr1 = BE_32(*ptr1);				\
			ptr1++;						\
		}							\
	}
#else
#define	MAKE_BE_32(x)
#endif

static uchar_t fp_verbosity = (FP_WARNING_MESSAGES | FP_FATAL_MESSAGES);
static uint32_t fp_options = 0;

static int fp_cmd_wait_cnt = FP_CMDWAIT_DELAY;
static int fp_retry_delay = FP_RETRY_DELAY;	/* retry after this delay */
static int fp_retry_count = FP_RETRY_COUNT;	/* number of retries */
unsigned int fp_offline_ticker;			/* seconds */

/*
 * Driver global variable to anchor the list of soft state structs for
 * all fp driver instances.  Used with the Solaris DDI soft state functions.
 */
static void *fp_driver_softstate;

static clock_t	fp_retry_ticks;
static clock_t	fp_offline_ticks;

static int fp_retry_ticker;
static uint32_t fp_unsol_buf_count = FP_UNSOL_BUF_COUNT;
static uint32_t fp_unsol_buf_size = FP_UNSOL_BUF_SIZE;

static int		fp_log_size = FP_LOG_SIZE;
static int		fp_trace = FP_TRACE_DEFAULT;
static fc_trace_logq_t	*fp_logq = NULL;

int fp_get_adapter_paths(char *pathList, int count);
static void fp_log_port_event(fc_local_port_t *port, char *subclass);
static void fp_log_target_event(fc_local_port_t *port, char *subclass,
    la_wwn_t tgt_pwwn, uint32_t port_id);
static uint32_t fp_map_remote_port_state(uint32_t rm_state);
static void fp_init_symbolic_names(fc_local_port_t *port);


/*
 * Perform global initialization
 */
int
_init(void)
{
	int ret;

	if ((ret = ddi_soft_state_init(&fp_driver_softstate,
	    sizeof (struct fc_local_port), 8)) != 0) {
		return (ret);
	}

	if ((ret = scsi_hba_init(&modlinkage)) != 0) {
		ddi_soft_state_fini(&fp_driver_softstate);
		return (ret);
	}

	fp_logq = fc_trace_alloc_logq(fp_log_size);

	if ((ret = mod_install(&modlinkage)) != 0) {
		fc_trace_free_logq(fp_logq);
		ddi_soft_state_fini(&fp_driver_softstate);
		scsi_hba_fini(&modlinkage);
	}

	return (ret);
}


/*
 * Prepare for driver unload
 */
int
_fini(void)
{
	int ret;

	if ((ret = mod_remove(&modlinkage)) == 0) {
		fc_trace_free_logq(fp_logq);
		ddi_soft_state_fini(&fp_driver_softstate);
		scsi_hba_fini(&modlinkage);
	}

	return (ret);
}


/*
 * Request mod_info() to handle all cases
 */
int
_info(struct modinfo *modinfo)
{
	return (mod_info(&modlinkage, modinfo));
}


/*
 * fp_attach:
 *
 * The respective cmd handlers take care of performing
 * ULP related invocations
 */
static int
fp_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int rval;

	/*
	 * We check the value of fp_offline_ticker at this
	 * point. The variable is global for the driver and
	 * not specific to an instance.
	 *
	 * If there is no user-defined value found in /etc/system
	 * or fp.conf, then we use 90 seconds (FP_OFFLINE_TICKER).
	 * The minimum setting for this offline timeout according
	 * to the FC-FS2 standard (Fibre Channel Framing and
	 * Signalling-2, see www.t11.org) is R_T_TOV == 100msec.
	 *
	 * We do not recommend setting the value to less than 10
	 * seconds (RA_TOV) or more than 90 seconds. If this
	 * variable is greater than 90 seconds then drivers above
	 * fp (fcp, sd, scsi_vhci, vxdmp et al) might complain.
	 */

	fp_offline_ticker = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dip, DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "fp_offline_ticker",
	    FP_OFFLINE_TICKER);

	if ((fp_offline_ticker < 10) ||
	    (fp_offline_ticker > 90)) {
		cmn_err(CE_WARN, "Setting fp_offline_ticker to "
		    "%d second(s). This is outside the "
		    "recommended range of 10..90 seconds",
		    fp_offline_ticker);
	}

	/*
	 * Tick every second when there are commands to retry.
	 * It should tick at the least granular value of pkt_timeout
	 * (which is one second)
	 */
	fp_retry_ticker = 1;

	fp_retry_ticks = drv_usectohz(fp_retry_ticker * 1000 * 1000);
	fp_offline_ticks = drv_usectohz(fp_offline_ticker * 1000 * 1000);

	switch (cmd) {
	case DDI_ATTACH:
		rval = fp_attach_handler(dip);
		break;

	case DDI_RESUME:
		rval = fp_resume_handler(dip);
		break;

	default:
		rval = DDI_FAILURE;
		break;
	}
	return (rval);
}


/*
 * fp_detach:
 *
 * If a ULP fails to handle cmd request converse of
 * cmd is invoked for ULPs that previously succeeded
 * cmd request.
 */
static int
fp_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int			rval = DDI_FAILURE;
	fc_local_port_t		*port;
	fc_attach_cmd_t		converse;
	uint8_t			cnt;

	if ((port = ddi_get_soft_state(fp_driver_softstate,
	    ddi_get_instance(dip))) == NULL) {
		return (DDI_FAILURE);
	}

	mutex_enter(&port->fp_mutex);

	if (port->fp_ulp_attach) {
		mutex_exit(&port->fp_mutex);
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_DETACH:
		if (port->fp_task != FP_TASK_IDLE) {
			mutex_exit(&port->fp_mutex);
			return (DDI_FAILURE);
		}

		/* Let's attempt to quit the job handler gracefully */
		port->fp_soft_state |= FP_DETACH_INPROGRESS;

		mutex_exit(&port->fp_mutex);
		converse = FC_CMD_ATTACH;
		if (fctl_detach_ulps(port, FC_CMD_DETACH,
		    &modlinkage) != FC_SUCCESS) {
			mutex_enter(&port->fp_mutex);
			port->fp_soft_state &= ~FP_DETACH_INPROGRESS;
			mutex_exit(&port->fp_mutex);
			rval = DDI_FAILURE;
			break;
		}

		mutex_enter(&port->fp_mutex);
		for (cnt = 0; (port->fp_job_head) && (cnt < fp_cmd_wait_cnt);
		    cnt++) {
			mutex_exit(&port->fp_mutex);
			delay(drv_usectohz(1000000));
			mutex_enter(&port->fp_mutex);
		}

		if (port->fp_job_head) {
			mutex_exit(&port->fp_mutex);
			rval = DDI_FAILURE;
			break;
		}
		mutex_exit(&port->fp_mutex);

		rval = fp_detach_handler(port);
		break;

	case DDI_SUSPEND:
		mutex_exit(&port->fp_mutex);
		converse = FC_CMD_RESUME;
		if (fctl_detach_ulps(port, FC_CMD_SUSPEND,
		    &modlinkage) != FC_SUCCESS) {
			rval = DDI_FAILURE;
			break;
		}
		if ((rval = fp_suspend_handler(port)) != DDI_SUCCESS) {
			(void) callb_generic_cpr(&port->fp_cpr_info,
			    CB_CODE_CPR_RESUME);
		}
		break;

	default:
		mutex_exit(&port->fp_mutex);
		break;
	}

	/*
	 * Use softint to perform reattach.  Mark fp_ulp_attach so we
	 * don't attempt to do this repeatedly on behalf of some persistent
	 * caller.
	 */
	if (rval != DDI_SUCCESS) {
		mutex_enter(&port->fp_mutex);
		port->fp_ulp_attach = 1;

		/*
		 * If the port is in the low power mode then there is
		 * possibility that fca too could be in low power mode.
		 * Try to raise the power before calling attach ulps.
		 */

		if ((port->fp_soft_state & FP_SOFT_POWER_DOWN) &&
		    (!(port->fp_soft_state & FP_SOFT_NO_PMCOMP))) {
			mutex_exit(&port->fp_mutex);
			(void) pm_raise_power(port->fp_port_dip,
			    FP_PM_COMPONENT, FP_PM_PORT_UP);
		} else {
			mutex_exit(&port->fp_mutex);
		}


		fp_attach_ulps(port, converse);

		mutex_enter(&port->fp_mutex);
		while (port->fp_ulp_attach) {
			cv_wait(&port->fp_attach_cv, &port->fp_mutex);
		}

		port->fp_soft_state &= ~FP_DETACH_INPROGRESS;

		/*
		 * Mark state as detach failed so asynchronous ULP attach
		 * events (downstream, not the ones we're initiating with
		 * the call to fp_attach_ulps) are not honored.	 We're
		 * really still in pending detach.
		 */
		port->fp_soft_state |= FP_DETACH_FAILED;

		mutex_exit(&port->fp_mutex);
	}

	return (rval);
}


/*
 * fp_getinfo:
 *   Given the device number, return either the
 *   dev_info_t pointer or the instance number.
 */

/* ARGSUSED */
static int
fp_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	int		rval;
	minor_t		instance;
	fc_local_port_t *port;

	rval = DDI_SUCCESS;
	instance = getminor((dev_t)arg);

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if ((port = ddi_get_soft_state(fp_driver_softstate,
		    instance)) == NULL) {
			rval = DDI_FAILURE;
			break;
		}
		*result = (void *)port->fp_port_dip;
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)instance;
		break;

	default:
		rval = DDI_FAILURE;
		break;
	}

	return (rval);
}


/*
 * Entry point for power up and power down request from kernel
 */
static int
fp_power(dev_info_t *dip, int comp, int level)
{
	int		rval = DDI_FAILURE;
	fc_local_port_t	*port;

	port = ddi_get_soft_state(fp_driver_softstate, ddi_get_instance(dip));
	if (port == NULL || comp != FP_PM_COMPONENT) {
		return (rval);
	}

	switch (level) {
	case FP_PM_PORT_UP:
		rval = DDI_SUCCESS;

		/*
		 * If the port is DDI_SUSPENDed, let the DDI_RESUME
		 * code complete the rediscovery.
		 */
		mutex_enter(&port->fp_mutex);
		if (port->fp_soft_state & FP_SOFT_SUSPEND) {
			port->fp_soft_state &= ~FP_SOFT_POWER_DOWN;
			port->fp_pm_level = FP_PM_PORT_UP;
			mutex_exit(&port->fp_mutex);
			fctl_attach_ulps(port, FC_CMD_POWER_UP, &modlinkage);
			break;
		}

		if (port->fp_soft_state & FP_SOFT_POWER_DOWN) {
			ASSERT(port->fp_pm_level == FP_PM_PORT_DOWN);

			port->fp_pm_level = FP_PM_PORT_UP;
			rval = fp_power_up(port);
			if (rval != DDI_SUCCESS) {
				port->fp_pm_level = FP_PM_PORT_DOWN;
			}
		} else {
			port->fp_pm_level = FP_PM_PORT_UP;
		}
		mutex_exit(&port->fp_mutex);
		break;

	case FP_PM_PORT_DOWN:
		mutex_enter(&port->fp_mutex);

		ASSERT(!(port->fp_soft_state & FP_SOFT_NO_PMCOMP));
		if (port->fp_soft_state & FP_SOFT_NO_PMCOMP) {
			/*
			 * PM framework goofed up. We have don't
			 * have any PM components. Let's never go down.
			 */
			mutex_exit(&port->fp_mutex);
			break;

		}

		if (port->fp_ulp_attach) {
			/* We shouldn't let the power go down */
			mutex_exit(&port->fp_mutex);
			break;
		}

		/*
		 * Not a whole lot to do if we are detaching
		 */
		if (port->fp_soft_state & FP_SOFT_IN_DETACH) {
			port->fp_pm_level = FP_PM_PORT_DOWN;
			mutex_exit(&port->fp_mutex);
			rval = DDI_SUCCESS;
			break;
		}

		if (!port->fp_pm_busy && !port->fp_pm_busy_nocomp) {
			port->fp_pm_level = FP_PM_PORT_DOWN;

			rval = fp_power_down(port);
			if (rval != DDI_SUCCESS) {
				port->fp_pm_level = FP_PM_PORT_UP;
				ASSERT(!(port->fp_soft_state &
				    FP_SOFT_POWER_DOWN));
			} else {
				ASSERT(port->fp_soft_state &
				    FP_SOFT_POWER_DOWN);
			}
		}
		mutex_exit(&port->fp_mutex);
		break;

	default:
		break;
	}

	return (rval);
}


/*
 * Open FC port devctl node
 */
static int
fp_open(dev_t *devp, int flag, int otype, cred_t *credp)
{
	int		instance;
	fc_local_port_t *port;

	if (otype != OTYP_CHR) {
		return (EINVAL);
	}

	/*
	 * This is not a toy to play with. Allow only powerful
	 * users (hopefully knowledgeable) to access the port
	 * (A hacker potentially could download a sick binary
	 * file into FCA)
	 */
	if (drv_priv(credp)) {
		return (EPERM);
	}

	instance = (int)getminor(*devp);

	port = ddi_get_soft_state(fp_driver_softstate, instance);
	if (port == NULL) {
		return (ENXIO);
	}

	mutex_enter(&port->fp_mutex);
	if (port->fp_flag & FP_EXCL) {
		/*
		 * It is already open for exclusive access.
		 * So shut the door on this caller.
		 */
		mutex_exit(&port->fp_mutex);
		return (EBUSY);
	}

	if (flag & FEXCL) {
		if (port->fp_flag & FP_OPEN) {
			/*
			 * Exclusive operation not possible
			 * as it is already opened
			 */
			mutex_exit(&port->fp_mutex);
			return (EBUSY);
		}
		port->fp_flag |= FP_EXCL;
	}
	port->fp_flag |= FP_OPEN;
	mutex_exit(&port->fp_mutex);

	return (0);
}


/*
 * The driver close entry point is called on the last close()
 * of a device. So it is perfectly alright to just clobber the
 * open flag and reset it to idle (instead of having to reset
 * each flag bits). For any confusion, check out close(9E).
 */

/* ARGSUSED */
static int
fp_close(dev_t dev, int flag, int otype, cred_t *credp)
{
	int		instance;
	fc_local_port_t *port;

	if (otype != OTYP_CHR) {
		return (EINVAL);
	}

	instance = (int)getminor(dev);

	port = ddi_get_soft_state(fp_driver_softstate, instance);
	if (port == NULL) {
		return (ENXIO);
	}

	mutex_enter(&port->fp_mutex);
	if ((port->fp_flag & FP_OPEN) == 0) {
		mutex_exit(&port->fp_mutex);
		return (ENODEV);
	}
	port->fp_flag = FP_IDLE;
	mutex_exit(&port->fp_mutex);

	return (0);
}

/*
 * Handle IOCTL requests
 */

/* ARGSUSED */
static int
fp_ioctl(dev_t dev, int cmd, intptr_t data, int mode, cred_t *credp, int *rval)
{
	int		instance;
	int		ret = 0;
	fcio_t		fcio;
	fc_local_port_t *port;

	instance = (int)getminor(dev);

	port = ddi_get_soft_state(fp_driver_softstate, instance);
	if (port == NULL) {
		return (ENXIO);
	}

	mutex_enter(&port->fp_mutex);
	if ((port->fp_flag & FP_OPEN) == 0) {
		mutex_exit(&port->fp_mutex);
		return (ENXIO);
	}

	if (port->fp_soft_state & FP_SOFT_SUSPEND) {
		mutex_exit(&port->fp_mutex);
		return (ENXIO);
	}

	mutex_exit(&port->fp_mutex);

	/* this will raise power if necessary */
	ret = fctl_busy_port(port);
	if (ret != 0) {
		return (ret);
	}

	ASSERT(port->fp_pm_level == FP_PM_PORT_UP);


	switch (cmd) {
	case FCIO_CMD: {
#ifdef	_MULTI_DATAMODEL
		switch (ddi_model_convert_from(mode & FMODELS)) {
		case DDI_MODEL_ILP32: {
			struct fcio32 fcio32;

			if (ddi_copyin((void *)data, (void *)&fcio32,
			    sizeof (struct fcio32), mode)) {
				ret = EFAULT;
				break;
			}
			fcio.fcio_xfer = fcio32.fcio_xfer;
			fcio.fcio_cmd = fcio32.fcio_cmd;
			fcio.fcio_flags = fcio32.fcio_flags;
			fcio.fcio_cmd_flags = fcio32.fcio_cmd_flags;
			fcio.fcio_ilen = (size_t)fcio32.fcio_ilen;
			fcio.fcio_ibuf =
			    (caddr_t)(uintptr_t)fcio32.fcio_ibuf;
			fcio.fcio_olen = (size_t)fcio32.fcio_olen;
			fcio.fcio_obuf =
			    (caddr_t)(uintptr_t)fcio32.fcio_obuf;
			fcio.fcio_alen = (size_t)fcio32.fcio_alen;
			fcio.fcio_abuf =
			    (caddr_t)(uintptr_t)fcio32.fcio_abuf;
			fcio.fcio_errno = fcio32.fcio_errno;
			break;
		}

		case DDI_MODEL_NONE:
			if (ddi_copyin((void *)data, (void *)&fcio,
			    sizeof (fcio_t), mode)) {
				ret = EFAULT;
			}
			break;
		}
#else	/* _MULTI_DATAMODEL */
		if (ddi_copyin((void *)data, (void *)&fcio,
		    sizeof (fcio_t), mode)) {
			ret = EFAULT;
			break;
		}
#endif	/* _MULTI_DATAMODEL */
		if (!ret) {
			ret = fp_fciocmd(port, data, mode, &fcio);
		}
		break;
	}

	default:
		ret = fctl_ulp_port_ioctl(port, dev, cmd, data,
		    mode, credp, rval);
	}

	fctl_idle_port(port);

	return (ret);
}


/*
 * Init Symbolic Port Name and Node Name
 * LV will try to get symbolic names from FCA driver
 * and register these to name server,
 * if LV fails to get these,
 * LV will register its default symbolic names to name server.
 * The Default symbolic node name format is :
 *	<hostname>:<hba driver name>(instance)
 * The Default symbolic port name format is :
 *	<fp path name>
 */
static void
fp_init_symbolic_names(fc_local_port_t *port)
{
	const char *vendorname = ddi_driver_name(port->fp_fca_dip);
	char *sym_name;
	char fcaname[50] = {0};
	int hostnlen, fcanlen;

	if (port->fp_sym_node_namelen == 0) {
		hostnlen = strlen(utsname.nodename);
		(void) snprintf(fcaname, sizeof (fcaname),
		    "%s%d", vendorname, ddi_get_instance(port->fp_fca_dip));
		fcanlen = strlen(fcaname);

		sym_name = kmem_zalloc(hostnlen + fcanlen + 2, KM_SLEEP);
		(void) sprintf(sym_name, "%s:%s", utsname.nodename, fcaname);
		port->fp_sym_node_namelen = strlen(sym_name);
		if (port->fp_sym_node_namelen >= FCHBA_SYMB_NAME_LEN) {
			port->fp_sym_node_namelen = FCHBA_SYMB_NAME_LEN;
		}
		(void) strncpy(port->fp_sym_node_name, sym_name,
		    port->fp_sym_node_namelen);
		kmem_free(sym_name, hostnlen + fcanlen + 2);
	}

	if (port->fp_sym_port_namelen == 0) {
		char *pathname = kmem_zalloc(MAXPATHLEN, KM_SLEEP);

		(void) ddi_pathname(port->fp_port_dip, pathname);
		port->fp_sym_port_namelen = strlen(pathname);
		if (port->fp_sym_port_namelen >= FCHBA_SYMB_NAME_LEN) {
			port->fp_sym_port_namelen = FCHBA_SYMB_NAME_LEN;
		}
		(void) strncpy(port->fp_sym_port_name, pathname,
		    port->fp_sym_port_namelen);
		kmem_free(pathname, MAXPATHLEN);
	}
}


/*
 * Perform port attach
 */
static int
fp_attach_handler(dev_info_t *dip)
{
	int			rval;
	int			instance;
	int			port_num;
	int			port_len;
	char			name[30];
	char			i_pwwn[17];
	fp_cmd_t		*pkt;
	uint32_t		ub_count;
	fc_local_port_t		*port;
	job_request_t		*job;
	fc_local_port_t *phyport = NULL;
	int portpro1;
	char pwwn[17], nwwn[17];

	instance = ddi_get_instance(dip);
	port_len = sizeof (port_num);
	rval = ddi_prop_op(DDI_DEV_T_ANY, dip, PROP_LEN_AND_VAL_BUF,
	    DDI_PROP_DONTPASS | DDI_PROP_CANSLEEP, "port",
	    (caddr_t)&port_num, &port_len);
	if (rval != DDI_SUCCESS) {
		cmn_err(CE_WARN, "fp(%d): No port property in devinfo",
		    instance);
		return (DDI_FAILURE);
	}

	if (ddi_create_minor_node(dip, "devctl", S_IFCHR, instance,
	    DDI_NT_NEXUS, 0) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "fp(%d): failed to create devctl minor node",
		    instance);
		return (DDI_FAILURE);
	}

	if (ddi_create_minor_node(dip, "fc", S_IFCHR, instance,
	    DDI_NT_FC_ATTACHMENT_POINT, 0) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "fp(%d): failed to create fc attachment"
		    " point minor node", instance);
		ddi_remove_minor_node(dip, NULL);
		return (DDI_FAILURE);
	}

	if (ddi_soft_state_zalloc(fp_driver_softstate, instance)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "fp(%d): failed to alloc soft state",
		    instance);
		ddi_remove_minor_node(dip, NULL);
		return (DDI_FAILURE);
	}
	port = ddi_get_soft_state(fp_driver_softstate, instance);

	(void) sprintf(port->fp_ibuf, "fp(%d)", instance);

	port->fp_instance = instance;
	port->fp_ulp_attach = 1;
	port->fp_port_num = port_num;
	port->fp_verbose = fp_verbosity;
	port->fp_options = fp_options;

	port->fp_fca_dip = ddi_get_parent(dip);
	port->fp_port_dip = dip;
	port->fp_fca_tran = (fc_fca_tran_t *)
	    ddi_get_driver_private(port->fp_fca_dip);

	port->fp_task = port->fp_last_task = FP_TASK_IDLE;

	/*
	 * Init the starting value of fp_rscn_count. Note that if
	 * FC_INVALID_RSCN_COUNT is 0 (which is what it currently is), the
	 * actual # of RSCNs will be (fp_rscn_count - 1)
	 */
	port->fp_rscn_count = FC_INVALID_RSCN_COUNT + 1;

	mutex_init(&port->fp_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&port->fp_cv, NULL, CV_DRIVER, NULL);
	cv_init(&port->fp_attach_cv, NULL, CV_DRIVER, NULL);

	(void) sprintf(name, "fp%d_cache", instance);

	if ((portpro1 = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dip, DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    "phyport-instance", -1)) != -1) {
		phyport = ddi_get_soft_state(fp_driver_softstate, portpro1);
		fc_wwn_to_str(&phyport->fp_service_params.nport_ww_name, pwwn);
		fc_wwn_to_str(&phyport->fp_service_params.node_ww_name, nwwn);
		port->fp_npiv_type = FC_NPIV_PORT;
	}

	/*
	 * Allocate the pool of fc_packet_t structs to be used with
	 * this fp instance.
	 */
	port->fp_pkt_cache = kmem_cache_create(name,
	    (port->fp_fca_tran->fca_pkt_size) + sizeof (fp_cmd_t), 8,
	    fp_cache_constructor, fp_cache_destructor, NULL, (void *)port,
	    NULL, 0);
	port->fp_out_fpcmds = 0;
	if (port->fp_pkt_cache == NULL) {
		goto cache_alloc_failed;
	}


	/*
	 * Allocate the d_id and pwwn hash tables for all remote ports
	 * connected to this local port.
	 */
	port->fp_did_table = kmem_zalloc(did_table_size *
	    sizeof (struct d_id_hash), KM_SLEEP);

	port->fp_pwwn_table = kmem_zalloc(pwwn_table_size *
	    sizeof (struct pwwn_hash), KM_SLEEP);

	port->fp_taskq = taskq_create("fp_ulp_callback", 1,
	    MINCLSYSPRI, 1, 16, 0);

	/* Indicate that don't have the pm components yet */
	port->fp_soft_state |=	FP_SOFT_NO_PMCOMP;

	/*
	 * Bind the callbacks with the FCA driver. This will open the gate
	 * for asynchronous callbacks, so after this call the fp_mutex
	 * must be held when updating the fc_local_port_t struct.
	 *
	 * This is done _before_ setting up the job thread so we can avoid
	 * cleaning up after the thread_create() in the error path. This
	 * also means fp will be operating with fp_els_resp_pkt set to NULL.
	 */
	if (fp_bind_callbacks(port) != DDI_SUCCESS) {
		goto bind_callbacks_failed;
	}

	if (phyport) {
		mutex_enter(&phyport->fp_mutex);
		if (phyport->fp_port_next) {
			phyport->fp_port_next->fp_port_prev = port;
			port->fp_port_next =  phyport->fp_port_next;
			phyport->fp_port_next = port;
			port->fp_port_prev = phyport;
		} else {
			phyport->fp_port_next = port;
			phyport->fp_port_prev = port;
			port->fp_port_next =  phyport;
			port->fp_port_prev = phyport;
		}
		mutex_exit(&phyport->fp_mutex);
	}

	/*
	 * Init Symbolic Names
	 */
	fp_init_symbolic_names(port);

	pkt = fp_alloc_pkt(port, sizeof (la_els_logi_t), sizeof (la_els_logi_t),
	    KM_SLEEP, NULL);

	if (pkt == NULL) {
		cmn_err(CE_WARN, "fp(%d): failed to allocate ELS packet",
		    instance);
		goto alloc_els_packet_failed;
	}

	(void) thread_create(NULL, 0, fp_job_handler, port, 0, &p0, TS_RUN,
	    v.v_maxsyspri - 2);

	fc_wwn_to_str(&port->fp_service_params.nport_ww_name, i_pwwn);
	if (ddi_prop_update_string(DDI_DEV_T_NONE, dip, "initiator-port",
	    i_pwwn) != DDI_PROP_SUCCESS) {
		fp_printf(port, CE_NOTE, FP_LOG_ONLY, 0, NULL,
		    "fp(%d): Updating 'initiator-port' property"
		    " on fp dev_info node failed", instance);
	}

	fc_wwn_to_str(&port->fp_service_params.node_ww_name, i_pwwn);
	if (ddi_prop_update_string(DDI_DEV_T_NONE, dip, "initiator-node",
	    i_pwwn) != DDI_PROP_SUCCESS) {
		fp_printf(port, CE_NOTE, FP_LOG_ONLY, 0, NULL,
		    "fp(%d): Updating 'initiator-node' property"
		    " on fp dev_info node failed", instance);
	}

	mutex_enter(&port->fp_mutex);
	port->fp_els_resp_pkt = pkt;
	mutex_exit(&port->fp_mutex);

	/*
	 * Determine the count of unsolicited buffers this FCA can support
	 */
	fp_retrieve_caps(port);

	/*
	 * Allocate unsolicited buffer tokens
	 */
	if (port->fp_ub_count) {
		ub_count = port->fp_ub_count;
		port->fp_ub_tokens = kmem_zalloc(ub_count *
		    sizeof (*port->fp_ub_tokens), KM_SLEEP);
		/*
		 * Do not fail the attach if unsolicited buffer allocation
		 * fails; Just try to get along with whatever the FCA can do.
		 */
		if (fc_ulp_uballoc(port, &ub_count, fp_unsol_buf_size,
		    FC_TYPE_EXTENDED_LS, port->fp_ub_tokens) !=
		    FC_SUCCESS || ub_count != port->fp_ub_count) {
			cmn_err(CE_WARN, "fp(%d): failed to allocate "
			    " Unsolicited buffers. proceeding with attach...",
			    instance);
			kmem_free(port->fp_ub_tokens,
			    sizeof (*port->fp_ub_tokens) * port->fp_ub_count);
			port->fp_ub_tokens = NULL;
		}
	}

	fp_load_ulp_modules(dip, port);

	/*
	 * Enable DDI_SUSPEND and DDI_RESUME for this instance.
	 */
	(void) ddi_prop_create(DDI_DEV_T_NONE, dip, DDI_PROP_CANSLEEP,
	    "pm-hardware-state", "needs-suspend-resume",
	    strlen("needs-suspend-resume") + 1);

	/*
	 * fctl maintains a list of all port handles, so
	 * help fctl add this one to its list now.
	 */
	mutex_enter(&port->fp_mutex);
	fctl_add_port(port);

	/*
	 * If a state change is already in progress, set the bind state t
	 * OFFLINE as well, so further state change callbacks into ULPs
	 * will pass the appropriate states
	 */
	if (FC_PORT_STATE_MASK(port->fp_bind_state) == FC_STATE_OFFLINE ||
	    port->fp_statec_busy) {
		port->fp_bind_state = FC_STATE_OFFLINE;
		mutex_exit(&port->fp_mutex);

		fp_startup_done((opaque_t)port, FC_PKT_SUCCESS);
	} else {
		/*
		 * Without dropping the mutex, ensure that the port
		 * startup happens ahead of state change callback
		 * processing
		 */
		ASSERT(port->fp_job_tail == NULL && port->fp_job_head == NULL);

		port->fp_last_task = port->fp_task;
		port->fp_task = FP_TASK_PORT_STARTUP;

		job = fctl_alloc_job(JOB_PORT_STARTUP, JOB_TYPE_FCTL_ASYNC,
		    fp_startup_done, (opaque_t)port, KM_SLEEP);

		port->fp_job_head = port->fp_job_tail = job;

		cv_signal(&port->fp_cv);

		mutex_exit(&port->fp_mutex);
	}

	mutex_enter(&port->fp_mutex);
	while (port->fp_ulp_attach) {
		cv_wait(&port->fp_attach_cv, &port->fp_mutex);
	}
	mutex_exit(&port->fp_mutex);

	if (ddi_prop_update_string_array(DDI_DEV_T_NONE, dip,
	    "pm-components", fp_pm_comps,
	    sizeof (fp_pm_comps) / sizeof (fp_pm_comps[0])) !=
	    DDI_PROP_SUCCESS) {
		FP_TRACE(FP_NHEAD2(9, 0), "Failed to create PM"
		    " components property, PM disabled on this port.");
		mutex_enter(&port->fp_mutex);
		port->fp_pm_level = FP_PM_PORT_UP;
		mutex_exit(&port->fp_mutex);
	} else {
		if (pm_raise_power(dip, FP_PM_COMPONENT,
		    FP_PM_PORT_UP) != DDI_SUCCESS) {
			FP_TRACE(FP_NHEAD2(9, 0), "Failed to raise"
			    " power level");
			mutex_enter(&port->fp_mutex);
			port->fp_pm_level = FP_PM_PORT_UP;
			mutex_exit(&port->fp_mutex);
		}

		/*
		 * Don't unset the FP_SOFT_NO_PMCOMP flag until after
		 * the call to pm_raise_power.	The PM framework can't
		 * handle multiple threads calling into it during attach.
		 */

		mutex_enter(&port->fp_mutex);
		port->fp_soft_state &=	~FP_SOFT_NO_PMCOMP;
		mutex_exit(&port->fp_mutex);
	}

	ddi_report_dev(dip);

	fp_log_port_event(port, ESC_SUNFC_PORT_ATTACH);

	return (DDI_SUCCESS);

	/*
	 * Unwind any/all preceeding allocations in the event of an error.
	 */

alloc_els_packet_failed:

	if (port->fp_fca_handle != NULL) {
		port->fp_fca_tran->fca_unbind_port(port->fp_fca_handle);
		port->fp_fca_handle = NULL;
	}

	if (port->fp_ub_tokens != NULL) {
		(void) fc_ulp_ubfree(port, port->fp_ub_count,
		    port->fp_ub_tokens);
		kmem_free(port->fp_ub_tokens,
		    port->fp_ub_count * sizeof (*port->fp_ub_tokens));
		port->fp_ub_tokens = NULL;
	}

	if (port->fp_els_resp_pkt != NULL) {
		fp_free_pkt(port->fp_els_resp_pkt);
		port->fp_els_resp_pkt = NULL;
	}

bind_callbacks_failed:

	if (port->fp_taskq != NULL) {
		taskq_destroy(port->fp_taskq);
	}

	if (port->fp_pwwn_table != NULL) {
		kmem_free(port->fp_pwwn_table,
		    pwwn_table_size * sizeof (struct pwwn_hash));
		port->fp_pwwn_table = NULL;
	}

	if (port->fp_did_table != NULL) {
		kmem_free(port->fp_did_table,
		    did_table_size * sizeof (struct d_id_hash));
		port->fp_did_table = NULL;
	}

	if (port->fp_pkt_cache != NULL) {
		kmem_cache_destroy(port->fp_pkt_cache);
		port->fp_pkt_cache = NULL;
	}

cache_alloc_failed:

	cv_destroy(&port->fp_attach_cv);
	cv_destroy(&port->fp_cv);
	mutex_destroy(&port->fp_mutex);
	ddi_remove_minor_node(port->fp_port_dip, NULL);
	ddi_soft_state_free(fp_driver_softstate, instance);
	ddi_prop_remove_all(dip);

	return (DDI_FAILURE);
}


/*
 * Handle DDI_RESUME request
 */
static int
fp_resume_handler(dev_info_t *dip)
{
	int		rval;
	fc_local_port_t *port;

	port = ddi_get_soft_state(fp_driver_softstate, ddi_get_instance(dip));

	ASSERT(port != NULL);

#ifdef	DEBUG
	mutex_enter(&port->fp_mutex);
	ASSERT(port->fp_soft_state & FP_SOFT_SUSPEND);
	mutex_exit(&port->fp_mutex);
#endif

	/*
	 * If the port was power suspended, raise the power level
	 */
	mutex_enter(&port->fp_mutex);
	if ((port->fp_soft_state & FP_SOFT_POWER_DOWN) &&
	    (!(port->fp_soft_state & FP_SOFT_NO_PMCOMP))) {
		ASSERT(port->fp_pm_level == FP_PM_PORT_DOWN);

		mutex_exit(&port->fp_mutex);
		if (pm_raise_power(dip, FP_PM_COMPONENT,
		    FP_PM_PORT_UP) != DDI_SUCCESS) {
			FP_TRACE(FP_NHEAD2(9, 0),
			    "Failed to raise the power level");
			return (DDI_FAILURE);
		}
		mutex_enter(&port->fp_mutex);
	}
	port->fp_soft_state &= ~FP_SOFT_SUSPEND;
	mutex_exit(&port->fp_mutex);

	/*
	 * All the discovery is initiated and handled by per-port thread.
	 * Further all the discovery is done in handled in callback mode
	 * (not polled mode); In a specific case such as this, the discovery
	 * is required to happen in polled mode. The easiest way out is
	 * to bail out port thread and get started. Come back and fix this
	 * to do on demand discovery initiated by ULPs. ULPs such as FCP
	 * will do on-demand discovery during pre-power-up busctl handling
	 * which will only be possible when SCSA provides a new HBA vector
	 * for sending down the PM busctl requests.
	 */
	(void) callb_generic_cpr(&port->fp_cpr_info, CB_CODE_CPR_RESUME);

	rval = fp_resume_all(port, FC_CMD_RESUME);
	if (rval != DDI_SUCCESS) {
		mutex_enter(&port->fp_mutex);
		port->fp_soft_state |= FP_SOFT_SUSPEND;
		mutex_exit(&port->fp_mutex);
		(void) callb_generic_cpr(&port->fp_cpr_info,
		    CB_CODE_CPR_CHKPT);
	}

	return (rval);
}

/*
 * Perform FC Port power on initialization
 */
static int
fp_power_up(fc_local_port_t *port)
{
	int	rval;

	ASSERT(MUTEX_HELD(&port->fp_mutex));

	ASSERT((port->fp_soft_state & FP_SOFT_SUSPEND) == 0);
	ASSERT(port->fp_soft_state & FP_SOFT_POWER_DOWN);

	port->fp_soft_state &= ~FP_SOFT_POWER_DOWN;

	mutex_exit(&port->fp_mutex);

	rval = fp_resume_all(port, FC_CMD_POWER_UP);
	if (rval != DDI_SUCCESS) {
		mutex_enter(&port->fp_mutex);
		port->fp_soft_state |= FP_SOFT_POWER_DOWN;
	} else {
		mutex_enter(&port->fp_mutex);
	}

	return (rval);
}


/*
 * It is important to note that the power may possibly be removed between
 * SUSPEND and the ensuing RESUME operation. In such a context the underlying
 * FC port hardware would have gone through an OFFLINE to ONLINE transition
 * (hardware state). In this case, the port driver may need to rediscover the
 * topology, perform LOGINs, register with the name server again and perform
 * any such port initialization procedures. To perform LOGINs, the driver could
 * use the port device handle to see if a LOGIN needs to be performed and use
 * the D_ID and WWN in it. The LOGINs may fail (if the hardware is reconfigured
 * or removed) which will be reflected in the map the ULPs will see.
 */
static int
fp_resume_all(fc_local_port_t *port, fc_attach_cmd_t cmd)
{

	ASSERT(!MUTEX_HELD(&port->fp_mutex));

	if (fp_bind_callbacks(port) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	mutex_enter(&port->fp_mutex);

	/*
	 * If there are commands queued for delayed retry, instead of
	 * working the hard way to figure out which ones are good for
	 * restart and which ones not (ELSs are definitely not good
	 * as the port will have to go through a new spin of rediscovery
	 * now), so just flush them out.
	 */
	if (port->fp_restore & FP_RESTORE_WAIT_TIMEOUT) {
		fp_cmd_t	*cmd;

		port->fp_restore &= ~FP_RESTORE_WAIT_TIMEOUT;

		mutex_exit(&port->fp_mutex);
		while ((cmd = fp_deque_cmd(port)) != NULL) {
			cmd->cmd_pkt.pkt_state = FC_PKT_TRAN_ERROR;
			fp_iodone(cmd);
		}
		mutex_enter(&port->fp_mutex);
	}

	if (FC_PORT_STATE_MASK(port->fp_bind_state) == FC_STATE_OFFLINE) {
		if ((port->fp_restore & FP_RESTORE_OFFLINE_TIMEOUT) ||
		    port->fp_dev_count) {
			port->fp_restore &= ~FP_RESTORE_OFFLINE_TIMEOUT;
			port->fp_offline_tid = timeout(fp_offline_timeout,
			    (caddr_t)port, fp_offline_ticks);
		}
		if (port->fp_job_head) {
			cv_signal(&port->fp_cv);
		}
		mutex_exit(&port->fp_mutex);
		fctl_attach_ulps(port, cmd, &modlinkage);
	} else {
		struct job_request *job;

		/*
		 * If an OFFLINE timer was running at the time of
		 * suspending, there is no need to restart it as
		 * the port is ONLINE now.
		 */
		port->fp_restore &= ~FP_RESTORE_OFFLINE_TIMEOUT;
		if (port->fp_statec_busy == 0) {
			port->fp_soft_state |= FP_SOFT_IN_STATEC_CB;
		}
		port->fp_statec_busy++;
		mutex_exit(&port->fp_mutex);

		job = fctl_alloc_job(JOB_PORT_ONLINE,
		    JOB_CANCEL_ULP_NOTIFICATION, NULL, NULL, KM_SLEEP);
		fctl_enque_job(port, job);

		fctl_jobwait(job);
		fctl_remove_oldies(port);

		fctl_attach_ulps(port, cmd, &modlinkage);
		fctl_dealloc_job(job);
	}

	return (DDI_SUCCESS);
}


/*
 * At this time, there shouldn't be any I/O requests on this port.
 * But the unsolicited callbacks from the underlying FCA port need
 * to be handled very carefully. The steps followed to handle the
 * DDI_DETACH are:
 *	+	Grab the port driver mutex, check if the unsolicited
 *		callback is currently under processing. If true, fail
 *		the DDI_DETACH request by printing a message; If false
 *		mark the DDI_DETACH as under progress, so that any
 *		further unsolicited callbacks get bounced.
 *	+	Perform PRLO/LOGO if necessary, cleanup all the data
 *		structures.
 *	+	Get the job_handler thread to gracefully exit.
 *	+	Unregister callbacks with the FCA port.
 *	+	Now that some peace is found, notify all the ULPs of
 *		DDI_DETACH request (using ulp_port_detach entry point)
 *	+	Free all mutexes, semaphores, conditional variables.
 *	+	Free the soft state, return success.
 *
 * Important considerations:
 *		Port driver de-registers state change and unsolicited
 *		callbacks before taking up the task of notifying ULPs
 *		and performing PRLO and LOGOs.
 *
 *		A port may go offline at the time PRLO/LOGO is being
 *		requested. It is expected of all FCA drivers to fail
 *		such requests either immediately with a FC_OFFLINE
 *		return code to fc_fca_transport() or return the packet
 *		asynchronously with pkt state set to FC_PKT_PORT_OFFLINE
 */
static int
fp_detach_handler(fc_local_port_t *port)
{
	job_request_t	*job;
	uint32_t	delay_count;
	fc_orphan_t	*orp, *tmporp;

	/*
	 * In a Fabric topology with many host ports connected to
	 * a switch, another detaching instance of fp might have
	 * triggered a LOGO (which is an unsolicited request to
	 * this instance). So in order to be able to successfully
	 * detach by taking care of such cases a delay of about
	 * 30 seconds is introduced.
	 */
	delay_count = 0;
	mutex_enter(&port->fp_mutex);
	if (port->fp_out_fpcmds != 0) {
		/*
		 * At this time we can only check fp internal commands, because
		 * sd/ssd/scsi_vhci should have finsihed all their commands,
		 * fcp/fcip/fcsm should have finished all their commands.
		 *
		 * It seems that all fp internal commands are asynchronous now.
		 */
		port->fp_soft_state &= ~FP_DETACH_INPROGRESS;
		mutex_exit(&port->fp_mutex);

		cmn_err(CE_WARN, "fp(%d): %d fp_cmd(s) is/are in progress"
		    " Failing detach", port->fp_instance, port->fp_out_fpcmds);
		return (DDI_FAILURE);
	}

	while ((port->fp_soft_state &
	    (FP_SOFT_IN_STATEC_CB | FP_SOFT_IN_UNSOL_CB)) &&
	    (delay_count < 30)) {
		mutex_exit(&port->fp_mutex);
		delay_count++;
		delay(drv_usectohz(1000000));
		mutex_enter(&port->fp_mutex);
	}

	if (port->fp_soft_state &
	    (FP_SOFT_IN_STATEC_CB | FP_SOFT_IN_UNSOL_CB)) {
		port->fp_soft_state &= ~FP_DETACH_INPROGRESS;
		mutex_exit(&port->fp_mutex);

		cmn_err(CE_WARN, "fp(%d): FCA callback in progress: "
		    " Failing detach", port->fp_instance);
		return (DDI_FAILURE);
	}

	port->fp_soft_state |= FP_SOFT_IN_DETACH;
	port->fp_soft_state &= ~FP_DETACH_INPROGRESS;
	mutex_exit(&port->fp_mutex);

	/*
	 * If we're powered down, we need to raise power prior to submitting
	 * the JOB_PORT_SHUTDOWN job.  Otherwise, the job handler will never
	 * process the shutdown job.
	 */
	if (fctl_busy_port(port) != 0) {
		cmn_err(CE_WARN, "fp(%d): fctl_busy_port failed",
		    port->fp_instance);
		mutex_enter(&port->fp_mutex);
		port->fp_soft_state &= ~FP_SOFT_IN_DETACH;
		mutex_exit(&port->fp_mutex);
		return (DDI_FAILURE);
	}

	/*
	 * This will deallocate data structs and cause the "job" thread
	 * to exit, in preparation for DDI_DETACH on the instance.
	 * This can sleep for an arbitrary duration, since it waits for
	 * commands over the wire, timeout(9F) callbacks, etc.
	 *
	 * CAUTION: There is still a race here, where the "job" thread
	 * can still be executing code even tho the fctl_jobwait() call
	 * below has returned to us.  In theory the fp driver could even be
	 * modunloaded even tho the job thread isn't done executing.
	 * without creating the race condition.
	 */
	job = fctl_alloc_job(JOB_PORT_SHUTDOWN, 0, NULL,
	    (opaque_t)port, KM_SLEEP);
	fctl_enque_job(port, job);
	fctl_jobwait(job);
	fctl_dealloc_job(job);


	(void) pm_lower_power(port->fp_port_dip, FP_PM_COMPONENT,
	    FP_PM_PORT_DOWN);

	if (port->fp_taskq) {
		taskq_destroy(port->fp_taskq);
	}

	ddi_prop_remove_all(port->fp_port_dip);

	ddi_remove_minor_node(port->fp_port_dip, NULL);

	fctl_remove_port(port);

	fp_free_pkt(port->fp_els_resp_pkt);

	if (port->fp_ub_tokens) {
		if (fc_ulp_ubfree(port, port->fp_ub_count,
		    port->fp_ub_tokens) != FC_SUCCESS) {
			cmn_err(CE_WARN, "fp(%d): couldn't free "
			    " unsolicited buffers", port->fp_instance);
		}
		kmem_free(port->fp_ub_tokens,
		    sizeof (*port->fp_ub_tokens) * port->fp_ub_count);
		port->fp_ub_tokens = NULL;
	}

	if (port->fp_pkt_cache != NULL) {
		kmem_cache_destroy(port->fp_pkt_cache);
	}

	port->fp_fca_tran->fca_unbind_port(port->fp_fca_handle);

	mutex_enter(&port->fp_mutex);
	if (port->fp_did_table) {
		kmem_free(port->fp_did_table, did_table_size *
		    sizeof (struct d_id_hash));
	}

	if (port->fp_pwwn_table) {
		kmem_free(port->fp_pwwn_table, pwwn_table_size *
		    sizeof (struct pwwn_hash));
	}
	orp = port->fp_orphan_list;
	while (orp) {
		tmporp = orp;
		orp = orp->orp_next;
		kmem_free(tmporp, sizeof (*orp));
	}

	mutex_exit(&port->fp_mutex);

	fp_log_port_event(port, ESC_SUNFC_PORT_DETACH);

	mutex_destroy(&port->fp_mutex);
	cv_destroy(&port->fp_attach_cv);
	cv_destroy(&port->fp_cv);
	ddi_soft_state_free(fp_driver_softstate, port->fp_instance);

	return (DDI_SUCCESS);
}


/*
 * Steps to perform DDI_SUSPEND operation on a FC port
 *
 *	- If already suspended return DDI_FAILURE
 *	- If already power-suspended return DDI_SUCCESS
 *	- If an unsolicited callback or state change handling is in
 *	    in progress, throw a warning message, return DDI_FAILURE
 *	- Cancel timeouts
 *	- SUSPEND the job_handler thread (means do nothing as it is
 *	    taken care of by the CPR frame work)
 */
static int
fp_suspend_handler(fc_local_port_t *port)
{
	uint32_t	delay_count;

	mutex_enter(&port->fp_mutex);

	/*
	 * The following should never happen, but
	 * let the driver be more defensive here
	 */
	if (port->fp_soft_state & FP_SOFT_SUSPEND) {
		mutex_exit(&port->fp_mutex);
		return (DDI_FAILURE);
	}

	/*
	 * If the port is already power suspended, there
	 * is nothing else to do, So return DDI_SUCCESS,
	 * but mark the SUSPEND bit in the soft state
	 * before leaving.
	 */
	if (port->fp_soft_state & FP_SOFT_POWER_DOWN) {
		port->fp_soft_state |= FP_SOFT_SUSPEND;
		mutex_exit(&port->fp_mutex);
		return (DDI_SUCCESS);
	}

	/*
	 * Check if an unsolicited callback or state change handling is
	 * in progress. If true, fail the suspend operation; also throw
	 * a warning message notifying the failure. Note that Sun PCI
	 * hotplug spec recommends messages in cases of failure (but
	 * not flooding the console)
	 *
	 * Busy waiting for a short interval (500 millisecond ?) to see
	 * if the callback processing completes may be another idea. Since
	 * most of the callback processing involves a lot of work, it
	 * is safe to just fail the SUSPEND operation. It is definitely
	 * not bad to fail the SUSPEND operation if the driver is busy.
	 */
	delay_count = 0;
	while ((port->fp_soft_state & (FP_SOFT_IN_STATEC_CB |
	    FP_SOFT_IN_UNSOL_CB)) && (delay_count < 30)) {
		mutex_exit(&port->fp_mutex);
		delay_count++;
		delay(drv_usectohz(1000000));
		mutex_enter(&port->fp_mutex);
	}

	if (port->fp_soft_state & (FP_SOFT_IN_STATEC_CB |
	    FP_SOFT_IN_UNSOL_CB)) {
		mutex_exit(&port->fp_mutex);
		cmn_err(CE_WARN, "fp(%d): FCA callback in progress: "
		    " Failing suspend", port->fp_instance);
		return (DDI_FAILURE);
	}

	/*
	 * Check of FC port thread is busy
	 */
	if (port->fp_job_head) {
		mutex_exit(&port->fp_mutex);
		FP_TRACE(FP_NHEAD2(9, 0),
		    "FC port thread is busy: Failing suspend");
		return (DDI_FAILURE);
	}
	port->fp_soft_state |= FP_SOFT_SUSPEND;

	fp_suspend_all(port);
	mutex_exit(&port->fp_mutex);

	return (DDI_SUCCESS);
}


/*
 * Prepare for graceful power down of a FC port
 */
static int
fp_power_down(fc_local_port_t *port)
{
	ASSERT(MUTEX_HELD(&port->fp_mutex));

	/*
	 * Power down request followed by a DDI_SUSPEND should
	 * never happen; If it does return DDI_SUCCESS
	 */
	if (port->fp_soft_state & FP_SOFT_SUSPEND) {
		port->fp_soft_state |= FP_SOFT_POWER_DOWN;
		return (DDI_SUCCESS);
	}

	/*
	 * If the port is already power suspended, there
	 * is nothing else to do, So return DDI_SUCCESS,
	 */
	if (port->fp_soft_state & FP_SOFT_POWER_DOWN) {
		return (DDI_SUCCESS);
	}

	/*
	 * Check if an unsolicited callback or state change handling
	 * is in progress. If true, fail the PM suspend operation.
	 * But don't print a message unless the verbosity of the
	 * driver desires otherwise.
	 */
	if ((port->fp_soft_state & FP_SOFT_IN_STATEC_CB) ||
	    (port->fp_soft_state & FP_SOFT_IN_UNSOL_CB)) {
		FP_TRACE(FP_NHEAD2(9, 0),
		    "Unsolicited callback in progress: Failing power down");
		return (DDI_FAILURE);
	}

	/*
	 * Check of FC port thread is busy
	 */
	if (port->fp_job_head) {
		FP_TRACE(FP_NHEAD2(9, 0),
		    "FC port thread is busy: Failing power down");
		return (DDI_FAILURE);
	}
	port->fp_soft_state |= FP_SOFT_POWER_DOWN;

	/*
	 * check if the ULPs are ready for power down
	 */
	mutex_exit(&port->fp_mutex);
	if (fctl_detach_ulps(port, FC_CMD_POWER_DOWN,
	    &modlinkage) != FC_SUCCESS) {
		mutex_enter(&port->fp_mutex);
		port->fp_soft_state &= ~FP_SOFT_POWER_DOWN;
		mutex_exit(&port->fp_mutex);

		/*
		 * Power back up the obedient ULPs that went down
		 */
		fp_attach_ulps(port, FC_CMD_POWER_UP);

		FP_TRACE(FP_NHEAD2(9, 0),
		    "ULP(s) busy, detach_ulps failed. Failing power down");
		mutex_enter(&port->fp_mutex);
		return (DDI_FAILURE);
	}
	mutex_enter(&port->fp_mutex);

	fp_suspend_all(port);

	return (DDI_SUCCESS);
}


/*
 * Suspend the entire FC port
 */
static void
fp_suspend_all(fc_local_port_t *port)
{
	int			index;
	struct pwwn_hash	*head;
	fc_remote_port_t	*pd;

	ASSERT(MUTEX_HELD(&port->fp_mutex));

	if (port->fp_wait_tid != 0) {
		timeout_id_t	tid;

		tid = port->fp_wait_tid;
		port->fp_wait_tid = (timeout_id_t)NULL;
		mutex_exit(&port->fp_mutex);
		(void) untimeout(tid);
		mutex_enter(&port->fp_mutex);
		port->fp_restore |= FP_RESTORE_WAIT_TIMEOUT;
	}

	if (port->fp_offline_tid) {
		timeout_id_t	tid;

		tid = port->fp_offline_tid;
		port->fp_offline_tid = (timeout_id_t)NULL;
		mutex_exit(&port->fp_mutex);
		(void) untimeout(tid);
		mutex_enter(&port->fp_mutex);
		port->fp_restore |= FP_RESTORE_OFFLINE_TIMEOUT;
	}
	mutex_exit(&port->fp_mutex);
	port->fp_fca_tran->fca_unbind_port(port->fp_fca_handle);
	mutex_enter(&port->fp_mutex);

	/*
	 * Mark all devices as OLD, and reset the LOGIN state as well
	 * (this will force the ULPs to perform a LOGIN after calling
	 * fc_portgetmap() during RESUME/PM_RESUME)
	 */
	for (index = 0; index < pwwn_table_size; index++) {
		head = &port->fp_pwwn_table[index];
		pd = head->pwwn_head;
		while (pd != NULL) {
			mutex_enter(&pd->pd_mutex);
			fp_remote_port_offline(pd);
			fctl_delist_did_table(port, pd);
			pd->pd_state = PORT_DEVICE_VALID;
			pd->pd_login_count = 0;
			mutex_exit(&pd->pd_mutex);
			pd = pd->pd_wwn_hnext;
		}
	}
}


/*
 * fp_cache_constructor: Constructor function for kmem_cache_create(9F).
 * Performs intializations for fc_packet_t structs.
 * Returns 0 for success or -1 for failure.
 *
 * This function allocates DMA handles for both command and responses.
 * Most of the ELSs used have both command and responses so it is strongly
 * desired to move them to cache constructor routine.
 *
 * Context: Can sleep iff called with KM_SLEEP flag.
 */
static int
fp_cache_constructor(void *buf, void *cdarg, int kmflags)
{
	int		(*cb) (caddr_t);
	fc_packet_t	*pkt;
	fp_cmd_t	*cmd = (fp_cmd_t *)buf;
	fc_local_port_t *port = (fc_local_port_t *)cdarg;

	cb = (kmflags == KM_SLEEP) ? DDI_DMA_SLEEP : DDI_DMA_DONTWAIT;

	cmd->cmd_next = NULL;
	cmd->cmd_flags = 0;
	cmd->cmd_dflags = 0;
	cmd->cmd_job = NULL;
	cmd->cmd_port = port;
	pkt = &cmd->cmd_pkt;

	if (!(port->fp_soft_state & FP_SOFT_FCA_IS_NODMA)) {
		if (ddi_dma_alloc_handle(port->fp_fca_dip,
		    port->fp_fca_tran->fca_dma_attr, cb, NULL,
		    &pkt->pkt_cmd_dma) != DDI_SUCCESS) {
			return (-1);
		}

		if (ddi_dma_alloc_handle(port->fp_fca_dip,
		    port->fp_fca_tran->fca_dma_attr, cb, NULL,
		    &pkt->pkt_resp_dma) != DDI_SUCCESS) {
			ddi_dma_free_handle(&pkt->pkt_cmd_dma);
			return (-1);
		}
	} else {
		pkt->pkt_cmd_dma = 0;
		pkt->pkt_resp_dma = 0;
	}

	pkt->pkt_cmd_acc = pkt->pkt_resp_acc = NULL;
	pkt->pkt_cmd_cookie_cnt = pkt->pkt_resp_cookie_cnt =
	    pkt->pkt_data_cookie_cnt = 0;
	pkt->pkt_cmd_cookie = pkt->pkt_resp_cookie =
	    pkt->pkt_data_cookie = NULL;
	pkt->pkt_fca_private = (caddr_t)buf + sizeof (fp_cmd_t);

	return (0);
}


/*
 * fp_cache_destructor: Destructor function for kmem_cache_create().
 * Performs un-intializations for fc_packet_t structs.
 */
/* ARGSUSED */
static void
fp_cache_destructor(void *buf, void *cdarg)
{
	fp_cmd_t	*cmd = (fp_cmd_t *)buf;
	fc_packet_t	*pkt;

	pkt = &cmd->cmd_pkt;
	if (pkt->pkt_cmd_dma) {
		ddi_dma_free_handle(&pkt->pkt_cmd_dma);
	}

	if (pkt->pkt_resp_dma) {
		ddi_dma_free_handle(&pkt->pkt_resp_dma);
	}
}


/*
 * Packet allocation for ELS and any other port driver commands
 *
 * Some ELSs like FLOGI and PLOGI are critical for topology and
 * device discovery and a system's inability to allocate memory
 * or DVMA resources while performing some of these critical ELSs
 * cause a lot of problem. While memory allocation failures are
 * rare, DVMA resource failures are common as the applications
 * are becoming more and more powerful on huge servers.	 So it
 * is desirable to have a framework support to reserve a fragment
 * of DVMA. So until this is fixed the correct way, the suffering
 * is huge whenever a LIP happens at a time DVMA resources are
 * drained out completely - So an attempt needs to be made to
 * KM_SLEEP while requesting for these resources, hoping that
 * the requests won't hang forever.
 *
 * The fc_remote_port_t argument is stored into the pkt_pd field in the
 * fc_packet_t struct prior to the fc_ulp_init_packet() call.  This
 * ensures that the pd_ref_count for the fc_remote_port_t is valid.
 * If there is no fc_remote_port_t associated with the fc_packet_t, then
 * fp_alloc_pkt() must be called with pd set to NULL.
 *
 * fp/fctl will resue fp_cmd_t somewhere, and change pkt_cmdlen/rsplen,
 * actually, it's a design fault. But there's no problem for physical
 * FCAs. But it will cause memory leak or panic for virtual FCAs like fcoei.
 *
 * For FCAs that don't support DMA, such as fcoei, we will use
 * pkt_fctl_rsvd1/rsvd2 to keep the real cmd_len/resp_len.
 */

static fp_cmd_t *
fp_alloc_pkt(fc_local_port_t *port, int cmd_len, int resp_len, int kmflags,
    fc_remote_port_t *pd)
{
	int		rval;
	ulong_t		real_len;
	fp_cmd_t	*cmd;
	fc_packet_t	*pkt;
	int		(*cb) (caddr_t);
	ddi_dma_cookie_t	pkt_cookie;
	ddi_dma_cookie_t	*cp;
	uint32_t		cnt;

	ASSERT(!MUTEX_HELD(&port->fp_mutex));

	cb = (kmflags == KM_SLEEP) ? DDI_DMA_SLEEP : DDI_DMA_DONTWAIT;

	cmd = (fp_cmd_t *)kmem_cache_alloc(port->fp_pkt_cache, kmflags);
	if (cmd == NULL) {
		return (cmd);
	}

	cmd->cmd_ulp_pkt = NULL;
	cmd->cmd_flags = 0;
	pkt = &cmd->cmd_pkt;
	ASSERT(cmd->cmd_dflags == 0);

	pkt->pkt_datalen = 0;
	pkt->pkt_data = NULL;
	pkt->pkt_state = 0;
	pkt->pkt_action = 0;
	pkt->pkt_reason = 0;
	pkt->pkt_expln = 0;
	pkt->pkt_cmd = NULL;
	pkt->pkt_resp = NULL;
	pkt->pkt_fctl_rsvd1 = NULL;
	pkt->pkt_fctl_rsvd2 = NULL;

	/*
	 * Init pkt_pd with the given pointer; this must be done _before_
	 * the call to fc_ulp_init_packet().
	 */
	pkt->pkt_pd = pd;

	/* Now call the FCA driver to init its private, per-packet fields */
	if (fc_ulp_init_packet((opaque_t)port, pkt, kmflags) != FC_SUCCESS) {
		goto alloc_pkt_failed;
	}

	if (cmd_len && !(port->fp_soft_state & FP_SOFT_FCA_IS_NODMA)) {
		ASSERT(pkt->pkt_cmd_dma != NULL);

		rval = ddi_dma_mem_alloc(pkt->pkt_cmd_dma, cmd_len,
		    port->fp_fca_tran->fca_acc_attr, DDI_DMA_CONSISTENT,
		    cb, NULL, (caddr_t *)&pkt->pkt_cmd, &real_len,
		    &pkt->pkt_cmd_acc);

		if (rval != DDI_SUCCESS) {
			goto alloc_pkt_failed;
		}
		cmd->cmd_dflags |= FP_CMD_VALID_DMA_MEM;

		if (real_len < cmd_len) {
			goto alloc_pkt_failed;
		}

		rval = ddi_dma_addr_bind_handle(pkt->pkt_cmd_dma, NULL,
		    pkt->pkt_cmd, real_len, DDI_DMA_WRITE |
		    DDI_DMA_CONSISTENT, cb, NULL,
		    &pkt_cookie, &pkt->pkt_cmd_cookie_cnt);

		if (rval != DDI_DMA_MAPPED) {
			goto alloc_pkt_failed;
		}

		cmd->cmd_dflags |= FP_CMD_VALID_DMA_BIND;

		if (pkt->pkt_cmd_cookie_cnt >
		    port->fp_fca_tran->fca_dma_attr->dma_attr_sgllen) {
			goto alloc_pkt_failed;
		}

		ASSERT(pkt->pkt_cmd_cookie_cnt != 0);

		cp = pkt->pkt_cmd_cookie = (ddi_dma_cookie_t *)kmem_alloc(
		    pkt->pkt_cmd_cookie_cnt * sizeof (pkt_cookie),
		    KM_NOSLEEP);

		if (cp == NULL) {
			goto alloc_pkt_failed;
		}

		*cp = pkt_cookie;
		cp++;
		for (cnt = 1; cnt < pkt->pkt_cmd_cookie_cnt; cnt++, cp++) {
			ddi_dma_nextcookie(pkt->pkt_cmd_dma, &pkt_cookie);
			*cp = pkt_cookie;
		}
	} else if (cmd_len != 0) {
		pkt->pkt_cmd = kmem_alloc(cmd_len, KM_SLEEP);
		pkt->pkt_fctl_rsvd1 = (opaque_t)(uintptr_t)cmd_len;
	}

	if (resp_len && !(port->fp_soft_state & FP_SOFT_FCA_IS_NODMA)) {
		ASSERT(pkt->pkt_resp_dma != NULL);

		rval = ddi_dma_mem_alloc(pkt->pkt_resp_dma, resp_len,
		    port->fp_fca_tran->fca_acc_attr,
		    DDI_DMA_CONSISTENT, cb, NULL,
		    (caddr_t *)&pkt->pkt_resp, &real_len,
		    &pkt->pkt_resp_acc);

		if (rval != DDI_SUCCESS) {
			goto alloc_pkt_failed;
		}
		cmd->cmd_dflags |= FP_RESP_VALID_DMA_MEM;

		if (real_len < resp_len) {
			goto alloc_pkt_failed;
		}

		rval = ddi_dma_addr_bind_handle(pkt->pkt_resp_dma, NULL,
		    pkt->pkt_resp, real_len, DDI_DMA_READ |
		    DDI_DMA_CONSISTENT, cb, NULL,
		    &pkt_cookie, &pkt->pkt_resp_cookie_cnt);

		if (rval != DDI_DMA_MAPPED) {
			goto alloc_pkt_failed;
		}

		cmd->cmd_dflags |= FP_RESP_VALID_DMA_BIND;

		if (pkt->pkt_resp_cookie_cnt >
		    port->fp_fca_tran->fca_dma_attr->dma_attr_sgllen) {
			goto alloc_pkt_failed;
		}

		ASSERT(pkt->pkt_cmd_cookie_cnt != 0);

		cp = pkt->pkt_resp_cookie = (ddi_dma_cookie_t *)kmem_alloc(
		    pkt->pkt_resp_cookie_cnt * sizeof (pkt_cookie),
		    KM_NOSLEEP);

		if (cp == NULL) {
			goto alloc_pkt_failed;
		}

		*cp = pkt_cookie;
		cp++;
		for (cnt = 1; cnt < pkt->pkt_resp_cookie_cnt; cnt++, cp++) {
			ddi_dma_nextcookie(pkt->pkt_resp_dma, &pkt_cookie);
			*cp = pkt_cookie;
		}
	} else if (resp_len != 0) {
		pkt->pkt_resp = kmem_alloc(resp_len, KM_SLEEP);
		pkt->pkt_fctl_rsvd2 = (opaque_t)(uintptr_t)resp_len;
	}

	pkt->pkt_cmdlen = cmd_len;
	pkt->pkt_rsplen = resp_len;
	pkt->pkt_ulp_private = cmd;

	return (cmd);

alloc_pkt_failed:

	fp_free_dma(cmd);

	if (pkt->pkt_cmd_cookie != NULL) {
		kmem_free(pkt->pkt_cmd_cookie,
		    pkt->pkt_cmd_cookie_cnt * sizeof (ddi_dma_cookie_t));
		pkt->pkt_cmd_cookie = NULL;
	}

	if (pkt->pkt_resp_cookie != NULL) {
		kmem_free(pkt->pkt_resp_cookie,
		    pkt->pkt_resp_cookie_cnt * sizeof (ddi_dma_cookie_t));
		pkt->pkt_resp_cookie = NULL;
	}

	if (port->fp_soft_state & FP_SOFT_FCA_IS_NODMA) {
		if (pkt->pkt_cmd) {
			kmem_free(pkt->pkt_cmd, cmd_len);
		}

		if (pkt->pkt_resp) {
			kmem_free(pkt->pkt_resp, resp_len);
		}
	}

	kmem_cache_free(port->fp_pkt_cache, cmd);

	return (NULL);
}


/*
 * Free FC packet
 */
static void
fp_free_pkt(fp_cmd_t *cmd)
{
	fc_local_port_t *port;
	fc_packet_t	*pkt;

	ASSERT(!MUTEX_HELD(&cmd->cmd_port->fp_mutex));

	cmd->cmd_next = NULL;
	cmd->cmd_job = NULL;
	pkt = &cmd->cmd_pkt;
	pkt->pkt_ulp_private = 0;
	pkt->pkt_tran_flags = 0;
	pkt->pkt_tran_type = 0;
	port = cmd->cmd_port;

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

	if (port->fp_soft_state & FP_SOFT_FCA_IS_NODMA) {
		if (pkt->pkt_cmd) {
			kmem_free(pkt->pkt_cmd,
			    (uint32_t)(uintptr_t)pkt->pkt_fctl_rsvd1);
		}

		if (pkt->pkt_resp) {
			kmem_free(pkt->pkt_resp,
			    (uint32_t)(uintptr_t)pkt->pkt_fctl_rsvd2);
		}
	}

	fp_free_dma(cmd);
	(void) fc_ulp_uninit_packet((opaque_t)port, pkt);
	kmem_cache_free(port->fp_pkt_cache, (void *)cmd);
}


/*
 * Release DVMA resources
 */
static void
fp_free_dma(fp_cmd_t *cmd)
{
	fc_packet_t *pkt = &cmd->cmd_pkt;

	pkt->pkt_cmdlen = 0;
	pkt->pkt_rsplen = 0;
	pkt->pkt_tran_type = 0;
	pkt->pkt_tran_flags = 0;

	if (cmd->cmd_dflags & FP_CMD_VALID_DMA_BIND) {
		(void) ddi_dma_unbind_handle(pkt->pkt_cmd_dma);
	}

	if (cmd->cmd_dflags & FP_CMD_VALID_DMA_MEM) {
		if (pkt->pkt_cmd_acc) {
			ddi_dma_mem_free(&pkt->pkt_cmd_acc);
		}
	}

	if (cmd->cmd_dflags & FP_RESP_VALID_DMA_BIND) {
		(void) ddi_dma_unbind_handle(pkt->pkt_resp_dma);
	}

	if (cmd->cmd_dflags & FP_RESP_VALID_DMA_MEM) {
		if (pkt->pkt_resp_acc) {
			ddi_dma_mem_free(&pkt->pkt_resp_acc);
		}
	}
	cmd->cmd_dflags = 0;
}


/*
 * Dedicated thread to perform various activities.  One thread for
 * each fc_local_port_t (driver soft state) instance.
 * Note, this effectively works out to one thread for each local
 * port, but there are also some Solaris taskq threads in use on a per-local
 * port basis; these also need to be taken into consideration.
 */
static void
fp_job_handler(fc_local_port_t *port)
{
	int			rval;
	uint32_t		*d_id;
	fc_remote_port_t	*pd;
	job_request_t		*job;

#ifndef	__lock_lint
	/*
	 * Solaris-internal stuff for proper operation of kernel threads
	 * with Solaris CPR.
	 */
	CALLB_CPR_INIT(&port->fp_cpr_info, &port->fp_mutex,
	    callb_generic_cpr, "fp_job_handler");
#endif


	/* Loop forever waiting for work to do */
	for (;;) {

		mutex_enter(&port->fp_mutex);

		/*
		 * Sleep if no work to do right now, or if we want
		 * to suspend or power-down.
		 */
		while (port->fp_job_head == NULL ||
		    (port->fp_soft_state & (FP_SOFT_POWER_DOWN |
		    FP_SOFT_SUSPEND))) {
			CALLB_CPR_SAFE_BEGIN(&port->fp_cpr_info);
			cv_wait(&port->fp_cv, &port->fp_mutex);
			CALLB_CPR_SAFE_END(&port->fp_cpr_info, &port->fp_mutex);
		}

		/*
		 * OK, we've just been woken up, so retrieve the next entry
		 * from the head of the job queue for this local port.
		 */
		job = fctl_deque_job(port);

		/*
		 * Handle all the fp driver's supported job codes here
		 * in this big honkin' switch.
		 */
		switch (job->job_code) {
		case JOB_PORT_SHUTDOWN:
			/*
			 * fp_port_shutdown() is only called from here. This
			 * will prepare the local port instance (softstate)
			 * for detaching.  This cancels timeout callbacks,
			 * executes LOGOs with remote ports, cleans up tables,
			 * and deallocates data structs.
			 */
			fp_port_shutdown(port, job);

			/*
			 * This will exit the job thread.
			 */
#ifndef __lock_lint
			CALLB_CPR_EXIT(&(port->fp_cpr_info));
#else
			mutex_exit(&port->fp_mutex);
#endif
			fctl_jobdone(job);
			thread_exit();

			/* NOTREACHED */

		case JOB_ATTACH_ULP: {
			/*
			 * This job is spawned in response to a ULP calling
			 * fc_ulp_add().
			 */

			boolean_t do_attach_ulps = B_TRUE;

			/*
			 * If fp is detaching, we don't want to call
			 * fp_startup_done as this asynchronous
			 * notification may interfere with the re-attach.
			 */

			if (port->fp_soft_state & (FP_DETACH_INPROGRESS |
			    FP_SOFT_IN_DETACH | FP_DETACH_FAILED)) {
				do_attach_ulps = B_FALSE;
			} else {
				/*
				 * We are going to force the transport
				 * to attach to the ULPs, so set
				 * fp_ulp_attach.  This will keep any
				 * potential detach from occurring until
				 * we are done.
				 */
				port->fp_ulp_attach = 1;
			}

			mutex_exit(&port->fp_mutex);

			/*
			 * NOTE: Since we just dropped the mutex, there is now
			 * a race window where the fp_soft_state check above
			 * could change here.  This race is covered because an
			 * additional check was added in the functions hidden
			 * under fp_startup_done().
			 */
			if (do_attach_ulps == B_TRUE) {
				/*
				 * This goes thru a bit of a convoluted call
				 * chain before spawning off a DDI taskq
				 * request to perform the actual attach
				 * operations. Blocking can occur at a number
				 * of points.
				 */
				fp_startup_done((opaque_t)port, FC_PKT_SUCCESS);
			}
			job->job_result = FC_SUCCESS;
			fctl_jobdone(job);
			break;
		}

		case JOB_ULP_NOTIFY: {
			/*
			 * Pass state change notifications up to any/all
			 * registered ULPs.
			 */
			uint32_t statec;

			statec = job->job_ulp_listlen;
			if (statec == FC_STATE_RESET_REQUESTED) {
				port->fp_last_task = port->fp_task;
				port->fp_task = FP_TASK_OFFLINE;
				fp_port_offline(port, 0);
				port->fp_task = port->fp_last_task;
				port->fp_last_task = FP_TASK_IDLE;
			}

			if (--port->fp_statec_busy == 0) {
				port->fp_soft_state &= ~FP_SOFT_IN_STATEC_CB;
			}

			mutex_exit(&port->fp_mutex);

			job->job_result = fp_ulp_notify(port, statec, KM_SLEEP);
			fctl_jobdone(job);
			break;
		}

		case JOB_PLOGI_ONE:
			/*
			 * Issue a PLOGI to a single remote port. Multiple
			 * PLOGIs to different remote ports may occur in
			 * parallel.
			 * This can create the fc_remote_port_t if it does not
			 * already exist.
			 */

			mutex_exit(&port->fp_mutex);
			d_id = (uint32_t *)job->job_private;
			pd = fctl_get_remote_port_by_did(port, *d_id);

			if (pd) {
				mutex_enter(&pd->pd_mutex);
				if (pd->pd_state == PORT_DEVICE_LOGGED_IN) {
					pd->pd_login_count++;
					mutex_exit(&pd->pd_mutex);
					job->job_result = FC_SUCCESS;
					fctl_jobdone(job);
					break;
				}
				mutex_exit(&pd->pd_mutex);
			} else {
				mutex_enter(&port->fp_mutex);
				if (FC_IS_TOP_SWITCH(port->fp_topology)) {
					mutex_exit(&port->fp_mutex);
					pd = fp_create_remote_port_by_ns(port,
					    *d_id, KM_SLEEP);
					if (pd == NULL) {
						job->job_result = FC_FAILURE;
						fctl_jobdone(job);
						break;
					}
				} else {
					mutex_exit(&port->fp_mutex);
				}
			}

			job->job_flags |= JOB_TYPE_FP_ASYNC;
			job->job_counter = 1;

			rval = fp_port_login(port, *d_id, job,
			    FP_CMD_PLOGI_RETAIN, KM_SLEEP, pd, NULL);

			if (rval != FC_SUCCESS) {
				job->job_result = rval;
				fctl_jobdone(job);
			}
			break;

		case JOB_LOGO_ONE: {
			/*
			 * Issue a PLOGO to a single remote port. Multiple
			 * PLOGOs to different remote ports may occur in
			 * parallel.
			 */
			fc_remote_port_t *pd;

#ifndef	__lock_lint
			ASSERT(job->job_counter > 0);
#endif

			pd = (fc_remote_port_t *)job->job_ulp_pkts;

			mutex_enter(&pd->pd_mutex);
			if (pd->pd_state != PORT_DEVICE_LOGGED_IN) {
				mutex_exit(&pd->pd_mutex);
				job->job_result = FC_LOGINREQ;
				mutex_exit(&port->fp_mutex);
				fctl_jobdone(job);
				break;
			}
			if (pd->pd_login_count > 1) {
				pd->pd_login_count--;
				mutex_exit(&pd->pd_mutex);
				job->job_result = FC_SUCCESS;
				mutex_exit(&port->fp_mutex);
				fctl_jobdone(job);
				break;
			}
			mutex_exit(&pd->pd_mutex);
			mutex_exit(&port->fp_mutex);
			job->job_flags |= JOB_TYPE_FP_ASYNC;
			(void) fp_logout(port, pd, job);
			break;
		}

		case JOB_FCIO_LOGIN:
			/*
			 * PLOGI initiated at ioctl request.
			 */
			mutex_exit(&port->fp_mutex);
			job->job_result =
			    fp_fcio_login(port, job->job_private, job);
			fctl_jobdone(job);
			break;

		case JOB_FCIO_LOGOUT:
			/*
			 * PLOGO initiated at ioctl request.
			 */
			mutex_exit(&port->fp_mutex);
			job->job_result =
			    fp_fcio_logout(port, job->job_private, job);
			fctl_jobdone(job);
			break;

		case JOB_PORT_GETMAP:
		case JOB_PORT_GETMAP_PLOGI_ALL: {
			port->fp_last_task = port->fp_task;
			port->fp_task = FP_TASK_GETMAP;

			switch (port->fp_topology) {
			case FC_TOP_PRIVATE_LOOP:
				job->job_counter = 1;

				fp_get_loopmap(port, job);
				mutex_exit(&port->fp_mutex);
				fp_jobwait(job);
				fctl_fillout_map(port,
				    (fc_portmap_t **)job->job_private,
				    (uint32_t *)job->job_arg, 1, 0, 0);
				fctl_jobdone(job);
				mutex_enter(&port->fp_mutex);
				break;

			case FC_TOP_PUBLIC_LOOP:
			case FC_TOP_FABRIC:
				mutex_exit(&port->fp_mutex);
				job->job_counter = 1;

				job->job_result = fp_ns_getmap(port,
				    job, (fc_portmap_t **)job->job_private,
				    (uint32_t *)job->job_arg,
				    FCTL_GAN_START_ID);
				fctl_jobdone(job);
				mutex_enter(&port->fp_mutex);
				break;

			case FC_TOP_PT_PT:
				mutex_exit(&port->fp_mutex);
				fctl_fillout_map(port,
				    (fc_portmap_t **)job->job_private,
				    (uint32_t *)job->job_arg, 1, 0, 0);
				fctl_jobdone(job);
				mutex_enter(&port->fp_mutex);
				break;

			default:
				mutex_exit(&port->fp_mutex);
				fctl_jobdone(job);
				mutex_enter(&port->fp_mutex);
				break;
			}
			port->fp_task = port->fp_last_task;
			port->fp_last_task = FP_TASK_IDLE;
			mutex_exit(&port->fp_mutex);
			break;
		}

		case JOB_PORT_OFFLINE: {
			fp_log_port_event(port, ESC_SUNFC_PORT_OFFLINE);

			port->fp_last_task = port->fp_task;
			port->fp_task = FP_TASK_OFFLINE;

			if (port->fp_statec_busy > 2) {
				job->job_flags |= JOB_CANCEL_ULP_NOTIFICATION;
				fp_port_offline(port, 0);
				if (--port->fp_statec_busy == 0) {
					port->fp_soft_state &=
					    ~FP_SOFT_IN_STATEC_CB;
				}
			} else {
				fp_port_offline(port, 1);
			}

			port->fp_task = port->fp_last_task;
			port->fp_last_task = FP_TASK_IDLE;

			mutex_exit(&port->fp_mutex);

			fctl_jobdone(job);
			break;
		}

		case JOB_PORT_STARTUP: {
			if ((rval = fp_port_startup(port, job)) != FC_SUCCESS) {
				if (port->fp_statec_busy > 1) {
					mutex_exit(&port->fp_mutex);
					break;
				}
				mutex_exit(&port->fp_mutex);

				FP_TRACE(FP_NHEAD2(9, rval),
				    "Topology discovery failed");
				break;
			}

			/*
			 * Attempt building device handles in case
			 * of private Loop.
			 */
			if (port->fp_topology == FC_TOP_PRIVATE_LOOP) {
				job->job_counter = 1;

				fp_get_loopmap(port, job);
				mutex_exit(&port->fp_mutex);
				fp_jobwait(job);
				mutex_enter(&port->fp_mutex);
				if (port->fp_lilp_map.lilp_magic < MAGIC_LIRP) {
					ASSERT(port->fp_total_devices == 0);
					port->fp_total_devices =
					    port->fp_dev_count;
				}
			} else if (FC_IS_TOP_SWITCH(port->fp_topology)) {
				/*
				 * Hack to avoid state changes going up early
				 */
				port->fp_statec_busy++;
				port->fp_soft_state |= FP_SOFT_IN_STATEC_CB;

				job->job_flags |= JOB_CANCEL_ULP_NOTIFICATION;
				fp_fabric_online(port, job);
				job->job_flags &= ~JOB_CANCEL_ULP_NOTIFICATION;
			}
			mutex_exit(&port->fp_mutex);
			fctl_jobdone(job);
			break;
		}

		case JOB_PORT_ONLINE: {
			char		*newtop;
			char		*oldtop;
			uint32_t	old_top;

			fp_log_port_event(port, ESC_SUNFC_PORT_ONLINE);

			/*
			 * Bail out early if there are a lot of
			 * state changes in the pipeline
			 */
			if (port->fp_statec_busy > 1) {
				--port->fp_statec_busy;
				mutex_exit(&port->fp_mutex);
				fctl_jobdone(job);
				break;
			}

			switch (old_top = port->fp_topology) {
			case FC_TOP_PRIVATE_LOOP:
				oldtop = "Private Loop";
				break;

			case FC_TOP_PUBLIC_LOOP:
				oldtop = "Public Loop";
				break;

			case FC_TOP_PT_PT:
				oldtop = "Point to Point";
				break;

			case FC_TOP_FABRIC:
				oldtop = "Fabric";
				break;

			default:
				oldtop = NULL;
				break;
			}

			port->fp_last_task = port->fp_task;
			port->fp_task = FP_TASK_ONLINE;

			if ((rval = fp_port_startup(port, job)) != FC_SUCCESS) {

				port->fp_task = port->fp_last_task;
				port->fp_last_task = FP_TASK_IDLE;

				if (port->fp_statec_busy > 1) {
					--port->fp_statec_busy;
					mutex_exit(&port->fp_mutex);
					break;
				}

				port->fp_state = FC_STATE_OFFLINE;

				FP_TRACE(FP_NHEAD2(9, rval),
				    "Topology discovery failed");

				if (--port->fp_statec_busy == 0) {
					port->fp_soft_state &=
					    ~FP_SOFT_IN_STATEC_CB;
				}

				if (port->fp_offline_tid == NULL) {
					port->fp_offline_tid =
					    timeout(fp_offline_timeout,
					    (caddr_t)port, fp_offline_ticks);
				}

				mutex_exit(&port->fp_mutex);
				break;
			}

			switch (port->fp_topology) {
			case FC_TOP_PRIVATE_LOOP:
				newtop = "Private Loop";
				break;

			case FC_TOP_PUBLIC_LOOP:
				newtop = "Public Loop";
				break;

			case FC_TOP_PT_PT:
				newtop = "Point to Point";
				break;

			case FC_TOP_FABRIC:
				newtop = "Fabric";
				break;

			default:
				newtop = NULL;
				break;
			}

			if (oldtop && newtop && strcmp(oldtop, newtop)) {
				fp_printf(port, CE_NOTE, FP_LOG_ONLY, 0, NULL,
				    "Change in FC Topology old = %s new = %s",
				    oldtop, newtop);
			}

			switch (port->fp_topology) {
			case FC_TOP_PRIVATE_LOOP: {
				int orphan = (old_top == FC_TOP_FABRIC ||
				    old_top == FC_TOP_PUBLIC_LOOP) ? 1 : 0;

				mutex_exit(&port->fp_mutex);
				fp_loop_online(port, job, orphan);
				break;
			}

			case FC_TOP_PUBLIC_LOOP:
				/* FALLTHROUGH */
			case FC_TOP_FABRIC:
				fp_fabric_online(port, job);
				mutex_exit(&port->fp_mutex);
				break;

			case FC_TOP_PT_PT:
				fp_p2p_online(port, job);
				mutex_exit(&port->fp_mutex);
				break;

			default:
				if (--port->fp_statec_busy != 0) {
					/*
					 * Watch curiously at what the next
					 * state transition can do.
					 */
					mutex_exit(&port->fp_mutex);
					break;
				}

				FP_TRACE(FP_NHEAD2(9, 0),
				    "Topology Unknown, Offlining the port..");

				port->fp_soft_state &= ~FP_SOFT_IN_STATEC_CB;
				port->fp_state = FC_STATE_OFFLINE;

				if (port->fp_offline_tid == NULL) {
					port->fp_offline_tid =
					    timeout(fp_offline_timeout,
					    (caddr_t)port, fp_offline_ticks);
				}
				mutex_exit(&port->fp_mutex);
				break;
			}

			mutex_enter(&port->fp_mutex);

			port->fp_task = port->fp_last_task;
			port->fp_last_task = FP_TASK_IDLE;

			mutex_exit(&port->fp_mutex);

			fctl_jobdone(job);
			break;
		}

		case JOB_PLOGI_GROUP: {
			mutex_exit(&port->fp_mutex);
			fp_plogi_group(port, job);
			break;
		}

		case JOB_UNSOL_REQUEST: {
			mutex_exit(&port->fp_mutex);
			fp_handle_unsol_buf(port,
			    (fc_unsol_buf_t *)job->job_private, job);
			fctl_dealloc_job(job);
			break;
		}

		case JOB_NS_CMD: {
			fctl_ns_req_t *ns_cmd;

			mutex_exit(&port->fp_mutex);

			job->job_flags |= JOB_TYPE_FP_ASYNC;
			ns_cmd = (fctl_ns_req_t *)job->job_private;
			if (ns_cmd->ns_cmd_code < NS_GA_NXT ||
			    ns_cmd->ns_cmd_code > NS_DA_ID) {
				job->job_result = FC_BADCMD;
				fctl_jobdone(job);
				break;
			}

			if (FC_IS_CMD_A_REG(ns_cmd->ns_cmd_code)) {
				if (ns_cmd->ns_pd != NULL) {
					job->job_result = FC_BADOBJECT;
					fctl_jobdone(job);
					break;
				}

				job->job_counter = 1;

				rval = fp_ns_reg(port, ns_cmd->ns_pd,
				    ns_cmd->ns_cmd_code, job, 0, KM_SLEEP);

				if (rval != FC_SUCCESS) {
					job->job_result = rval;
					fctl_jobdone(job);
				}
				break;
			}
			job->job_result = FC_SUCCESS;
			job->job_counter = 1;

			rval = fp_ns_query(port, ns_cmd, job, 0, KM_SLEEP);
			if (rval != FC_SUCCESS) {
				fctl_jobdone(job);
			}
			break;
		}

		case JOB_LINK_RESET: {
			la_wwn_t *pwwn;
			uint32_t topology;

			pwwn = (la_wwn_t *)job->job_private;
			ASSERT(pwwn != NULL);

			topology = port->fp_topology;
			mutex_exit(&port->fp_mutex);

			if (fctl_is_wwn_zero(pwwn) == FC_SUCCESS ||
			    topology == FC_TOP_PRIVATE_LOOP) {
				job->job_flags |= JOB_TYPE_FP_ASYNC;
				rval = port->fp_fca_tran->fca_reset(
				    port->fp_fca_handle, FC_FCA_LINK_RESET);
				job->job_result = rval;
				fp_jobdone(job);
			} else {
				ASSERT((job->job_flags &
				    JOB_TYPE_FP_ASYNC) == 0);

				if (FC_IS_TOP_SWITCH(topology)) {
					rval = fp_remote_lip(port, pwwn,
					    KM_SLEEP, job);
				} else {
					rval = FC_FAILURE;
				}
				if (rval != FC_SUCCESS) {
					job->job_result = rval;
				}
				fctl_jobdone(job);
			}
			break;
		}

		default:
			mutex_exit(&port->fp_mutex);
			job->job_result = FC_BADCMD;
			fctl_jobdone(job);
			break;
		}
	}
	/* NOTREACHED */
}


/*
 * Perform FC port bring up initialization
 */
static int
fp_port_startup(fc_local_port_t *port, job_request_t *job)
{
	int		rval;
	uint32_t	state;
	uint32_t	src_id;
	fc_lilpmap_t	*lilp_map;

	ASSERT(MUTEX_HELD(&port->fp_mutex));
	ASSERT((job->job_flags & JOB_TYPE_FP_ASYNC) == 0);

	FP_DTRACE(FP_NHEAD1(2, 0), "Entering fp_port_startup;"
	    " port=%p, job=%p", port, job);

	port->fp_topology = FC_TOP_UNKNOWN;
	port->fp_port_id.port_id = 0;
	state = FC_PORT_STATE_MASK(port->fp_state);

	if (state == FC_STATE_OFFLINE) {
		port->fp_port_type.port_type = FC_NS_PORT_UNKNOWN;
		job->job_result = FC_OFFLINE;
		mutex_exit(&port->fp_mutex);
		fctl_jobdone(job);
		mutex_enter(&port->fp_mutex);
		return (FC_OFFLINE);
	}

	if (state == FC_STATE_LOOP) {
		port->fp_port_type.port_type = FC_NS_PORT_NL;
		mutex_exit(&port->fp_mutex);

		lilp_map = &port->fp_lilp_map;
		if ((rval = fp_get_lilpmap(port, lilp_map)) != FC_SUCCESS) {
			job->job_result = FC_FAILURE;
			fctl_jobdone(job);

			FP_TRACE(FP_NHEAD1(9, rval),
			    "LILP map Invalid or not present");
			mutex_enter(&port->fp_mutex);
			return (FC_FAILURE);
		}

		if (lilp_map->lilp_length == 0) {
			job->job_result = FC_NO_MAP;
			fctl_jobdone(job);
			fp_printf(port, CE_NOTE, FP_LOG_ONLY, 0, NULL,
			    "LILP map length zero");
			mutex_enter(&port->fp_mutex);
			return (FC_NO_MAP);
		}
		src_id = lilp_map->lilp_myalpa & 0xFF;
	} else {
		fc_remote_port_t	*pd;
		fc_fca_pm_t		pm;
		fc_fca_p2p_info_t	p2p_info;
		int			pd_recepient;

		/*
		 * Get P2P remote port info if possible
		 */
		bzero((caddr_t)&pm, sizeof (pm));

		pm.pm_cmd_flags = FC_FCA_PM_READ;
		pm.pm_cmd_code = FC_PORT_GET_P2P_INFO;
		pm.pm_data_len = sizeof (fc_fca_p2p_info_t);
		pm.pm_data_buf = (caddr_t)&p2p_info;

		rval = port->fp_fca_tran->fca_port_manage(
		    port->fp_fca_handle, &pm);

		if (rval == FC_SUCCESS) {
			port->fp_port_id.port_id = p2p_info.fca_d_id;
			port->fp_port_type.port_type = FC_NS_PORT_N;
			port->fp_topology = FC_TOP_PT_PT;
			port->fp_total_devices = 1;
			pd_recepient = fctl_wwn_cmp(
			    &port->fp_service_params.nport_ww_name,
			    &p2p_info.pwwn) < 0 ?
			    PD_PLOGI_RECEPIENT : PD_PLOGI_INITIATOR;
			mutex_exit(&port->fp_mutex);
			pd = fctl_create_remote_port(port,
			    &p2p_info.nwwn,
			    &p2p_info.pwwn,
			    p2p_info.d_id,
			    pd_recepient, KM_NOSLEEP);
			FP_DTRACE(FP_NHEAD1(2, 0), "Exiting fp_port_startup;"
			    " P2P port=%p pd=%p fp %x pd %x", port, pd,
			    port->fp_port_id.port_id, p2p_info.d_id);
			mutex_enter(&port->fp_mutex);
			return (FC_SUCCESS);
		}
		port->fp_port_type.port_type = FC_NS_PORT_N;
		mutex_exit(&port->fp_mutex);
		src_id = 0;
	}

	job->job_counter = 1;
	job->job_result = FC_SUCCESS;

	if ((rval = fp_fabric_login(port, src_id, job, FP_CMD_PLOGI_DONT_CARE,
	    KM_SLEEP)) != FC_SUCCESS) {
		port->fp_port_type.port_type = FC_NS_PORT_UNKNOWN;
		job->job_result = FC_FAILURE;
		fctl_jobdone(job);

		mutex_enter(&port->fp_mutex);
		if (port->fp_statec_busy <= 1) {
			mutex_exit(&port->fp_mutex);
			fp_printf(port, CE_NOTE, FP_LOG_ONLY, rval, NULL,
			    "Couldn't transport FLOGI");
			mutex_enter(&port->fp_mutex);
		}
		return (FC_FAILURE);
	}

	fp_jobwait(job);

	mutex_enter(&port->fp_mutex);
	if (job->job_result == FC_SUCCESS) {
		if (FC_IS_TOP_SWITCH(port->fp_topology)) {
			mutex_exit(&port->fp_mutex);
			fp_ns_init(port, job, KM_SLEEP);
			mutex_enter(&port->fp_mutex);
		}
	} else {
		if (state == FC_STATE_LOOP) {
			port->fp_topology = FC_TOP_PRIVATE_LOOP;
			port->fp_port_id.port_id =
			    port->fp_lilp_map.lilp_myalpa & 0xFF;
		}
	}

	FP_DTRACE(FP_NHEAD1(2, 0), "Exiting fp_port_startup; port=%p, job=%p",
	    port, job);

	return (FC_SUCCESS);
}


/*
 * Perform ULP invocations following FC port startup
 */
/* ARGSUSED */
static void
fp_startup_done(opaque_t arg, uchar_t result)
{
	fc_local_port_t *port = arg;

	fp_attach_ulps(port, FC_CMD_ATTACH);

	FP_DTRACE(FP_NHEAD1(2, 0), "fp_startup almost complete; port=%p", port);
}


/*
 * Perform ULP port attach
 */
static void
fp_ulp_port_attach(void *arg)
{
	fp_soft_attach_t *att = (fp_soft_attach_t *)arg;
	fc_local_port_t	 *port = att->att_port;

	FP_DTRACE(FP_NHEAD1(1, 0), "port attach of"
	    " ULPs begin; port=%p, cmd=%x", port, att->att_cmd);

	fctl_attach_ulps(att->att_port, att->att_cmd, &modlinkage);

	if (att->att_need_pm_idle == B_TRUE) {
		fctl_idle_port(port);
	}

	FP_DTRACE(FP_NHEAD1(1, 0), "port attach of"
	    " ULPs end; port=%p, cmd=%x", port, att->att_cmd);

	mutex_enter(&att->att_port->fp_mutex);
	att->att_port->fp_ulp_attach = 0;

	port->fp_task = port->fp_last_task;
	port->fp_last_task = FP_TASK_IDLE;

	cv_signal(&att->att_port->fp_attach_cv);

	mutex_exit(&att->att_port->fp_mutex);

	kmem_free(att, sizeof (fp_soft_attach_t));
}

/*
 * Entry point to funnel all requests down to FCAs
 */
static int
fp_sendcmd(fc_local_port_t *port, fp_cmd_t *cmd, opaque_t fca_handle)
{
	int rval;

	mutex_enter(&port->fp_mutex);
	if (port->fp_statec_busy > 1 || (cmd->cmd_ulp_pkt != NULL &&
	    (port->fp_statec_busy || FC_PORT_STATE_MASK(port->fp_state) ==
	    FC_STATE_OFFLINE))) {
		/*
		 * This means there is more than one state change
		 * at this point of time - Since they are processed
		 * serially, any processing of the current one should
		 * be failed, failed and move up in processing the next
		 */
		cmd->cmd_pkt.pkt_state = FC_PKT_ELS_IN_PROGRESS;
		cmd->cmd_pkt.pkt_reason = FC_REASON_OFFLINE;
		if (cmd->cmd_job) {
			/*
			 * A state change that is going to be invalidated
			 * by another one already in the port driver's queue
			 * need not go up to all ULPs. This will minimize
			 * needless processing and ripples in ULP modules
			 */
			cmd->cmd_job->job_flags |= JOB_CANCEL_ULP_NOTIFICATION;
		}
		mutex_exit(&port->fp_mutex);
		return (FC_STATEC_BUSY);
	}

	if (FC_PORT_STATE_MASK(port->fp_state) == FC_STATE_OFFLINE) {
		cmd->cmd_pkt.pkt_state = FC_PKT_PORT_OFFLINE;
		cmd->cmd_pkt.pkt_reason = FC_REASON_OFFLINE;
		mutex_exit(&port->fp_mutex);

		return (FC_OFFLINE);
	}
	mutex_exit(&port->fp_mutex);

	rval = cmd->cmd_transport(fca_handle, &cmd->cmd_pkt);
	if (rval != FC_SUCCESS) {
		if (rval == FC_TRAN_BUSY) {
			cmd->cmd_retry_interval = fp_retry_delay;
			rval = fp_retry_cmd(&cmd->cmd_pkt);
			if (rval == FC_FAILURE) {
				cmd->cmd_pkt.pkt_state = FC_PKT_TRAN_BSY;
			}
		}
	} else {
		mutex_enter(&port->fp_mutex);
		port->fp_out_fpcmds++;
		mutex_exit(&port->fp_mutex);
	}

	return (rval);
}


/*
 * Each time a timeout kicks in, walk the wait queue, decrement the
 * the retry_interval, when the retry_interval becomes less than
 * or equal to zero, re-transport the command: If the re-transport
 * fails with BUSY, enqueue the command in the wait queue.
 *
 * In order to prevent looping forever because of commands enqueued
 * from within this function itself, save the current tail pointer
 * (in cur_tail) and exit the loop after serving this command.
 */
static void
fp_resendcmd(void *port_handle)
{
	int		rval;
	fc_local_port_t	*port;
	fp_cmd_t	*cmd;
	fp_cmd_t	*cur_tail;

	port = port_handle;
	mutex_enter(&port->fp_mutex);
	cur_tail = port->fp_wait_tail;
	mutex_exit(&port->fp_mutex);

	while ((cmd = fp_deque_cmd(port)) != NULL) {
		cmd->cmd_retry_interval -= fp_retry_ticker;
		/* Check if we are detaching */
		if (port->fp_soft_state &
		    (FP_SOFT_IN_DETACH | FP_DETACH_INPROGRESS)) {
			cmd->cmd_pkt.pkt_state = FC_PKT_TRAN_ERROR;
			cmd->cmd_pkt.pkt_reason = 0;
			fp_iodone(cmd);
		} else if (cmd->cmd_retry_interval <= 0) {
			rval = cmd->cmd_transport(port->fp_fca_handle,
			    &cmd->cmd_pkt);

			if (rval != FC_SUCCESS) {
				if (cmd->cmd_pkt.pkt_state == FC_PKT_TRAN_BSY) {
					if (--cmd->cmd_retry_count) {
						fp_enque_cmd(port, cmd);
						if (cmd == cur_tail) {
							break;
						}
						continue;
					}
					cmd->cmd_pkt.pkt_state =
					    FC_PKT_TRAN_BSY;
				} else {
					cmd->cmd_pkt.pkt_state =
					    FC_PKT_TRAN_ERROR;
				}
				cmd->cmd_pkt.pkt_reason = 0;
				fp_iodone(cmd);
			} else {
				mutex_enter(&port->fp_mutex);
				port->fp_out_fpcmds++;
				mutex_exit(&port->fp_mutex);
			}
		} else {
			fp_enque_cmd(port, cmd);
		}

		if (cmd == cur_tail) {
			break;
		}
	}

	mutex_enter(&port->fp_mutex);
	if (port->fp_wait_head) {
		timeout_id_t tid;

		mutex_exit(&port->fp_mutex);
		tid = timeout(fp_resendcmd, (caddr_t)port,
		    fp_retry_ticks);
		mutex_enter(&port->fp_mutex);
		port->fp_wait_tid = tid;
	} else {
		port->fp_wait_tid = NULL;
	}
	mutex_exit(&port->fp_mutex);
}


/*
 * Handle Local, Fabric, N_Port, Transport (whatever that means) BUSY here.
 *
 * Yes, as you can see below, cmd_retry_count is used here too.	 That means
 * the retries for BUSY are less if there were transport failures (transport
 * failure means fca_transport failure). The goal is not to exceed overall
 * retries set in the cmd_retry_count (whatever may be the reason for retry)
 *
 * Return Values:
 *	FC_SUCCESS
 *	FC_FAILURE
 */
static int
fp_retry_cmd(fc_packet_t *pkt)
{
	fp_cmd_t *cmd;

	cmd = pkt->pkt_ulp_private;

	if (--cmd->cmd_retry_count) {
		fp_enque_cmd(cmd->cmd_port, cmd);
		return (FC_SUCCESS);
	} else {
		return (FC_FAILURE);
	}
}


/*
 * Queue up FC packet for deferred retry
 */
static void
fp_enque_cmd(fc_local_port_t *port, fp_cmd_t *cmd)
{
	timeout_id_t tid;

	ASSERT(!MUTEX_HELD(&port->fp_mutex));

#ifdef	DEBUG
	fp_printf(port, CE_NOTE, FP_LOG_ONLY, 0, &cmd->cmd_pkt,
	    "Retrying ELS for %x", cmd->cmd_pkt.pkt_cmd_fhdr.d_id);
#endif

	mutex_enter(&port->fp_mutex);
	if (port->fp_wait_tail) {
		port->fp_wait_tail->cmd_next = cmd;
		port->fp_wait_tail = cmd;
	} else {
		ASSERT(port->fp_wait_head == NULL);
		port->fp_wait_head = port->fp_wait_tail = cmd;
		if (port->fp_wait_tid == NULL) {
			mutex_exit(&port->fp_mutex);
			tid = timeout(fp_resendcmd, (caddr_t)port,
			    fp_retry_ticks);
			mutex_enter(&port->fp_mutex);
			port->fp_wait_tid = tid;
		}
	}
	mutex_exit(&port->fp_mutex);
}


/*
 * Handle all RJT codes
 */
static int
fp_handle_reject(fc_packet_t *pkt)
{
	int		rval = FC_FAILURE;
	uchar_t		next_class;
	fp_cmd_t	*cmd;
	fc_local_port_t *port;

	cmd = pkt->pkt_ulp_private;
	port = cmd->cmd_port;

	switch (pkt->pkt_state) {
	case FC_PKT_FABRIC_RJT:
	case FC_PKT_NPORT_RJT:
		if (pkt->pkt_reason == FC_REASON_CLASS_NOT_SUPP) {
			next_class = fp_get_nextclass(cmd->cmd_port,
			    FC_TRAN_CLASS(pkt->pkt_tran_flags));

			if (next_class == FC_TRAN_CLASS_INVALID) {
				return (rval);
			}
			pkt->pkt_tran_flags = FC_TRAN_INTR | next_class;
			pkt->pkt_tran_type = FC_PKT_EXCHANGE;

			rval = fp_sendcmd(cmd->cmd_port, cmd,
			    cmd->cmd_port->fp_fca_handle);

			if (rval != FC_SUCCESS) {
				pkt->pkt_state = FC_PKT_TRAN_ERROR;
			}
		}
		break;

	case FC_PKT_LS_RJT:
	case FC_PKT_BA_RJT:
		if ((pkt->pkt_reason == FC_REASON_LOGICAL_ERROR) ||
		    (pkt->pkt_reason == FC_REASON_LOGICAL_BSY)) {
			cmd->cmd_retry_interval = fp_retry_delay;
			rval = fp_retry_cmd(pkt);
		}
		break;

	case FC_PKT_FS_RJT:
		if ((pkt->pkt_reason == FC_REASON_FS_LOGICAL_BUSY) ||
		    ((pkt->pkt_reason == FC_REASON_FS_CMD_UNABLE) &&
		    (pkt->pkt_expln == 0x00))) {
			cmd->cmd_retry_interval = fp_retry_delay;
			rval = fp_retry_cmd(pkt);
		}
		break;

	case FC_PKT_LOCAL_RJT:
		if (pkt->pkt_reason == FC_REASON_QFULL) {
			cmd->cmd_retry_interval = fp_retry_delay;
			rval = fp_retry_cmd(pkt);
		}
		break;

	default:
		FP_TRACE(FP_NHEAD1(1, 0),
		    "fp_handle_reject(): Invalid pkt_state");
		break;
	}

	return (rval);
}


/*
 * Return the next class of service supported by the FCA
 */
static uchar_t
fp_get_nextclass(fc_local_port_t *port, uchar_t cur_class)
{
	uchar_t next_class;

	ASSERT(!MUTEX_HELD(&port->fp_mutex));

	switch (cur_class) {
	case FC_TRAN_CLASS_INVALID:
		if (port->fp_cos & FC_NS_CLASS1) {
			next_class = FC_TRAN_CLASS1;
			break;
		}
		/* FALLTHROUGH */

	case FC_TRAN_CLASS1:
		if (port->fp_cos & FC_NS_CLASS2) {
			next_class = FC_TRAN_CLASS2;
			break;
		}
		/* FALLTHROUGH */

	case FC_TRAN_CLASS2:
		if (port->fp_cos & FC_NS_CLASS3) {
			next_class = FC_TRAN_CLASS3;
			break;
		}
		/* FALLTHROUGH */

	case FC_TRAN_CLASS3:
	default:
		next_class = FC_TRAN_CLASS_INVALID;
		break;
	}

	return (next_class);
}


/*
 * Determine if a class of service is supported by the FCA
 */
static int
fp_is_class_supported(uint32_t cos, uchar_t tran_class)
{
	int rval;

	switch (tran_class) {
	case FC_TRAN_CLASS1:
		if (cos & FC_NS_CLASS1) {
			rval = FC_SUCCESS;
		} else {
			rval = FC_FAILURE;
		}
		break;

	case FC_TRAN_CLASS2:
		if (cos & FC_NS_CLASS2) {
			rval = FC_SUCCESS;
		} else {
			rval = FC_FAILURE;
		}
		break;

	case FC_TRAN_CLASS3:
		if (cos & FC_NS_CLASS3) {
			rval = FC_SUCCESS;
		} else {
			rval = FC_FAILURE;
		}
		break;

	default:
		rval = FC_FAILURE;
		break;
	}

	return (rval);
}


/*
 * Dequeue FC packet for retry
 */
static fp_cmd_t *
fp_deque_cmd(fc_local_port_t *port)
{
	fp_cmd_t *cmd;

	ASSERT(!MUTEX_HELD(&port->fp_mutex));

	mutex_enter(&port->fp_mutex);

	if (port->fp_wait_head == NULL) {
		/*
		 * To avoid races, NULL the fp_wait_tid as
		 * we are about to exit the timeout thread.
		 */
		port->fp_wait_tid = NULL;
		mutex_exit(&port->fp_mutex);
		return (NULL);
	}

	cmd = port->fp_wait_head;
	port->fp_wait_head = cmd->cmd_next;
	cmd->cmd_next = NULL;

	if (port->fp_wait_head == NULL) {
		port->fp_wait_tail = NULL;
	}
	mutex_exit(&port->fp_mutex);

	return (cmd);
}


/*
 * Wait for job completion
 */
static void
fp_jobwait(job_request_t *job)
{
	sema_p(&job->job_port_sema);
}


/*
 * Convert FC packet state to FC errno
 */
int
fp_state_to_rval(uchar_t state)
{
	int count;

	for (count = 0; count < sizeof (fp_xlat) /
	    sizeof (fp_xlat[0]); count++) {
		if (fp_xlat[count].xlat_state == state) {
			return (fp_xlat[count].xlat_rval);
		}
	}

	return (FC_FAILURE);
}


/*
 * For Synchronous I/O requests, the caller is
 * expected to do fctl_jobdone(if necessary)
 *
 * We want to preserve at least one failure in the
 * job_result if it happens.
 *
 */
static void
fp_iodone(fp_cmd_t *cmd)
{
	fc_packet_t		*ulp_pkt = cmd->cmd_ulp_pkt;
	job_request_t		*job = cmd->cmd_job;
	fc_remote_port_t	*pd = cmd->cmd_pkt.pkt_pd;

	ASSERT(job != NULL);
	ASSERT(cmd->cmd_port != NULL);
	ASSERT(&cmd->cmd_pkt != NULL);

	mutex_enter(&job->job_mutex);
	if (job->job_result == FC_SUCCESS) {
		job->job_result = fp_state_to_rval(cmd->cmd_pkt.pkt_state);
	}
	mutex_exit(&job->job_mutex);

	if (pd) {
		mutex_enter(&pd->pd_mutex);
		pd->pd_flags = PD_IDLE;
		mutex_exit(&pd->pd_mutex);
	}

	if (ulp_pkt) {
		if (pd && cmd->cmd_flags & FP_CMD_DELDEV_ON_ERROR &&
		    FP_IS_PKT_ERROR(ulp_pkt)) {
			fc_local_port_t		*port;
			fc_remote_node_t	*node;

			port = cmd->cmd_port;

			mutex_enter(&pd->pd_mutex);
			pd->pd_state = PORT_DEVICE_INVALID;
			pd->pd_ref_count--;
			node = pd->pd_remote_nodep;
			mutex_exit(&pd->pd_mutex);

			ASSERT(node != NULL);
			ASSERT(port != NULL);

			if (fctl_destroy_remote_port(port, pd) == 0) {
				fctl_destroy_remote_node(node);
			}

			ulp_pkt->pkt_pd = NULL;
		}

		ulp_pkt->pkt_comp(ulp_pkt);
	}

	fp_free_pkt(cmd);
	fp_jobdone(job);
}


/*
 * Job completion handler
 */
static void
fp_jobdone(job_request_t *job)
{
	mutex_enter(&job->job_mutex);
	ASSERT(job->job_counter > 0);

	if (--job->job_counter != 0) {
		mutex_exit(&job->job_mutex);
		return;
	}

	if (job->job_ulp_pkts) {
		ASSERT(job->job_ulp_listlen > 0);
		kmem_free(job->job_ulp_pkts,
		    sizeof (fc_packet_t *) * job->job_ulp_listlen);
	}

	if (job->job_flags & JOB_TYPE_FP_ASYNC) {
		mutex_exit(&job->job_mutex);
		fctl_jobdone(job);
	} else {
		mutex_exit(&job->job_mutex);
		sema_v(&job->job_port_sema);
	}
}


/*
 * Try to perform shutdown of a port during a detach. No return
 * value since the detach should not fail because the port shutdown
 * failed.
 */
static void
fp_port_shutdown(fc_local_port_t *port, job_request_t *job)
{
	int			index;
	int			count;
	int			flags;
	fp_cmd_t		*cmd;
	struct pwwn_hash	*head;
	fc_remote_port_t	*pd;

	ASSERT(MUTEX_HELD(&port->fp_mutex));

	job->job_result = FC_SUCCESS;

	if (port->fp_taskq) {
		/*
		 * We must release the mutex here to ensure that other
		 * potential jobs can complete their processing.  Many
		 * also need this mutex.
		 */
		mutex_exit(&port->fp_mutex);
		taskq_wait(port->fp_taskq);
		mutex_enter(&port->fp_mutex);
	}

	if (port->fp_offline_tid) {
		timeout_id_t tid;

		tid = port->fp_offline_tid;
		port->fp_offline_tid = NULL;
		mutex_exit(&port->fp_mutex);
		(void) untimeout(tid);
		mutex_enter(&port->fp_mutex);
	}

	if (port->fp_wait_tid) {
		timeout_id_t tid;

		tid = port->fp_wait_tid;
		port->fp_wait_tid = NULL;
		mutex_exit(&port->fp_mutex);
		(void) untimeout(tid);
	} else {
		mutex_exit(&port->fp_mutex);
	}

	/*
	 * While we cancel the timeout, let's also return the
	 * the outstanding requests back to the callers.
	 */
	while ((cmd = fp_deque_cmd(port)) != NULL) {
		ASSERT(cmd->cmd_job != NULL);
		cmd->cmd_job->job_result = FC_OFFLINE;
		fp_iodone(cmd);
	}

	/*
	 * Gracefully LOGO with all the devices logged in.
	 */
	mutex_enter(&port->fp_mutex);

	for (count = index = 0; index < pwwn_table_size; index++) {
		head = &port->fp_pwwn_table[index];
		pd = head->pwwn_head;
		while (pd != NULL) {
			mutex_enter(&pd->pd_mutex);
			if (pd->pd_state == PORT_DEVICE_LOGGED_IN) {
				count++;
			}
			mutex_exit(&pd->pd_mutex);
			pd = pd->pd_wwn_hnext;
		}
	}

	if (job->job_flags & JOB_TYPE_FP_ASYNC) {
		flags = job->job_flags;
		job->job_flags &= ~JOB_TYPE_FP_ASYNC;
	} else {
		flags = 0;
	}
	if (count) {
		job->job_counter = count;

		for (index = 0; index < pwwn_table_size; index++) {
			head = &port->fp_pwwn_table[index];
			pd = head->pwwn_head;
			while (pd != NULL) {
				mutex_enter(&pd->pd_mutex);
				if (pd->pd_state == PORT_DEVICE_LOGGED_IN) {
					ASSERT(pd->pd_login_count > 0);
					/*
					 * Force the counter to ONE in order
					 * for us to really send LOGO els.
					 */
					pd->pd_login_count = 1;
					mutex_exit(&pd->pd_mutex);
					mutex_exit(&port->fp_mutex);
					(void) fp_logout(port, pd, job);
					mutex_enter(&port->fp_mutex);
				} else {
					mutex_exit(&pd->pd_mutex);
				}
				pd = pd->pd_wwn_hnext;
			}
		}
		mutex_exit(&port->fp_mutex);
		fp_jobwait(job);
	} else {
		mutex_exit(&port->fp_mutex);
	}

	if (job->job_result != FC_SUCCESS) {
		FP_TRACE(FP_NHEAD1(9, 0),
		    "Can't logout all devices. Proceeding with"
		    " port shutdown");
		job->job_result = FC_SUCCESS;
	}

	fctl_destroy_all_remote_ports(port);

	mutex_enter(&port->fp_mutex);
	if (FC_IS_TOP_SWITCH(port->fp_topology)) {
		mutex_exit(&port->fp_mutex);
		fp_ns_fini(port, job);
	} else {
		mutex_exit(&port->fp_mutex);
	}

	if (flags) {
		job->job_flags = flags;
	}

	mutex_enter(&port->fp_mutex);

}


/*
 * Build the port driver's data structures based on the AL_PA list
 */
static void
fp_get_loopmap(fc_local_port_t *port, job_request_t *job)
{
	int			rval;
	int			flag;
	int			count;
	uint32_t		d_id;
	fc_remote_port_t	*pd;
	fc_lilpmap_t		*lilp_map;

	ASSERT(MUTEX_HELD(&port->fp_mutex));

	if (FC_PORT_STATE_MASK(port->fp_state) == FC_STATE_OFFLINE) {
		job->job_result = FC_OFFLINE;
		mutex_exit(&port->fp_mutex);
		fp_jobdone(job);
		mutex_enter(&port->fp_mutex);
		return;
	}

	if (port->fp_lilp_map.lilp_length == 0) {
		mutex_exit(&port->fp_mutex);
		job->job_result = FC_NO_MAP;
		fp_jobdone(job);
		mutex_enter(&port->fp_mutex);
		return;
	}
	mutex_exit(&port->fp_mutex);

	lilp_map = &port->fp_lilp_map;
	job->job_counter = lilp_map->lilp_length;

	if (job->job_code == JOB_PORT_GETMAP_PLOGI_ALL) {
		flag = FP_CMD_PLOGI_RETAIN;
	} else {
		flag = FP_CMD_PLOGI_DONT_CARE;
	}

	for (count = 0; count < lilp_map->lilp_length; count++) {
		d_id = lilp_map->lilp_alpalist[count];

		if (d_id == (lilp_map->lilp_myalpa & 0xFF)) {
			fp_jobdone(job);
			continue;
		}

		pd = fctl_get_remote_port_by_did(port, d_id);
		if (pd) {
			mutex_enter(&pd->pd_mutex);
			if (flag == FP_CMD_PLOGI_DONT_CARE ||
			    pd->pd_state == PORT_DEVICE_LOGGED_IN) {
				mutex_exit(&pd->pd_mutex);
				fp_jobdone(job);
				continue;
			}
			mutex_exit(&pd->pd_mutex);
		}

		rval = fp_port_login(port, d_id, job, flag,
		    KM_SLEEP, pd, NULL);
		if (rval != FC_SUCCESS) {
			fp_jobdone(job);
		}
	}

	mutex_enter(&port->fp_mutex);
}


/*
 * Perform loop ONLINE processing
 */
static void
fp_loop_online(fc_local_port_t *port, job_request_t *job, int orphan)
{
	int			count;
	int			rval;
	uint32_t		d_id;
	uint32_t		listlen;
	fc_lilpmap_t		*lilp_map;
	fc_remote_port_t	*pd;
	fc_portmap_t		*changelist;

	ASSERT(!MUTEX_HELD(&port->fp_mutex));

	FP_TRACE(FP_NHEAD1(1, 0), "fp_loop_online begin; port=%p, job=%p",
	    port, job);

	lilp_map = &port->fp_lilp_map;

	if (lilp_map->lilp_length) {
		mutex_enter(&port->fp_mutex);
		if (port->fp_soft_state & FP_SOFT_IN_FCA_RESET) {
			port->fp_soft_state &= ~FP_SOFT_IN_FCA_RESET;
			mutex_exit(&port->fp_mutex);
			delay(drv_usectohz(PLDA_RR_TOV * 1000 * 1000));
		} else {
			mutex_exit(&port->fp_mutex);
		}

		job->job_counter = lilp_map->lilp_length;

		for (count = 0; count < lilp_map->lilp_length; count++) {
			d_id = lilp_map->lilp_alpalist[count];

			if (d_id == (lilp_map->lilp_myalpa & 0xFF)) {
				fp_jobdone(job);
				continue;
			}

			pd = fctl_get_remote_port_by_did(port, d_id);
			if (pd != NULL) {
#ifdef	DEBUG
				mutex_enter(&pd->pd_mutex);
				if (pd->pd_recepient == PD_PLOGI_INITIATOR) {
					ASSERT(pd->pd_type != PORT_DEVICE_OLD);
				}
				mutex_exit(&pd->pd_mutex);
#endif
				fp_jobdone(job);
				continue;
			}

			rval = fp_port_login(port, d_id, job,
			    FP_CMD_PLOGI_DONT_CARE, KM_SLEEP, pd, NULL);

			if (rval != FC_SUCCESS) {
				fp_jobdone(job);
			}
		}
		fp_jobwait(job);
	}
	listlen = 0;
	changelist = NULL;

	if ((job->job_flags & JOB_CANCEL_ULP_NOTIFICATION) == 0) {
		mutex_enter(&port->fp_mutex);
		ASSERT(port->fp_statec_busy > 0);
		if (port->fp_statec_busy == 1) {
			mutex_exit(&port->fp_mutex);
			fctl_fillout_map(port, &changelist, &listlen,
			    1, 0, orphan);

			mutex_enter(&port->fp_mutex);
			if (port->fp_lilp_map.lilp_magic < MAGIC_LIRP) {
				ASSERT(port->fp_total_devices == 0);
				port->fp_total_devices = port->fp_dev_count;
			}
		} else {
			job->job_flags |= JOB_CANCEL_ULP_NOTIFICATION;
		}
		mutex_exit(&port->fp_mutex);
	}

	if ((job->job_flags & JOB_CANCEL_ULP_NOTIFICATION) == 0) {
		(void) fp_ulp_statec_cb(port, FC_STATE_ONLINE, changelist,
		    listlen, listlen, KM_SLEEP);
	} else {
		mutex_enter(&port->fp_mutex);
		if (--port->fp_statec_busy == 0) {
			port->fp_soft_state &= ~FP_SOFT_IN_STATEC_CB;
		}
		ASSERT(changelist == NULL && listlen == 0);
		mutex_exit(&port->fp_mutex);
	}

	FP_TRACE(FP_NHEAD1(1, 0), "fp_loop_online end; port=%p, job=%p",
	    port, job);
}


/*
 * Get an Arbitrated Loop map from the underlying FCA
 */
static int
fp_get_lilpmap(fc_local_port_t *port, fc_lilpmap_t *lilp_map)
{
	int rval;

	FP_TRACE(FP_NHEAD1(1, 0), "fp_get_lilpmap Begin; port=%p, map=%p",
	    port, lilp_map);

	bzero((caddr_t)lilp_map, sizeof (fc_lilpmap_t));
	rval = port->fp_fca_tran->fca_getmap(port->fp_fca_handle, lilp_map);
	lilp_map->lilp_magic &= 0xFF;	/* Ignore upper byte */

	if (rval != FC_SUCCESS) {
		rval = FC_NO_MAP;
	} else if (lilp_map->lilp_length == 0 &&
	    (lilp_map->lilp_magic >= MAGIC_LISM &&
	    lilp_map->lilp_magic < MAGIC_LIRP)) {
		uchar_t lilp_length;

		/*
		 * Since the map length is zero, provide all
		 * the valid AL_PAs for NL_ports discovery.
		 */
		lilp_length = sizeof (fp_valid_alpas) /
		    sizeof (fp_valid_alpas[0]);
		lilp_map->lilp_length = lilp_length;
		bcopy(fp_valid_alpas, lilp_map->lilp_alpalist,
		    lilp_length);
	} else {
		rval = fp_validate_lilp_map(lilp_map);

		if (rval == FC_SUCCESS) {
			mutex_enter(&port->fp_mutex);
			port->fp_total_devices = lilp_map->lilp_length - 1;
			mutex_exit(&port->fp_mutex);
		}
	}

	mutex_enter(&port->fp_mutex);
	if (rval != FC_SUCCESS && !(port->fp_soft_state & FP_SOFT_BAD_LINK)) {
		port->fp_soft_state |= FP_SOFT_BAD_LINK;
		mutex_exit(&port->fp_mutex);

		if (port->fp_fca_tran->fca_reset(port->fp_fca_handle,
		    FC_FCA_RESET_CORE) != FC_SUCCESS) {
			FP_TRACE(FP_NHEAD1(9, 0),
			    "FCA reset failed after LILP map was found"
			    " to be invalid");
		}
	} else if (rval == FC_SUCCESS) {
		port->fp_soft_state &= ~FP_SOFT_BAD_LINK;
		mutex_exit(&port->fp_mutex);
	} else {
		mutex_exit(&port->fp_mutex);
	}

	FP_TRACE(FP_NHEAD1(1, 0), "fp_get_lilpmap End; port=%p, map=%p", port,
	    lilp_map);

	return (rval);
}


/*
 * Perform Fabric Login:
 *
 * Return Values:
 *		FC_SUCCESS
 *		FC_FAILURE
 *		FC_NOMEM
 *		FC_TRANSPORT_ERROR
 *		and a lot others defined in fc_error.h
 */
static int
fp_fabric_login(fc_local_port_t *port, uint32_t s_id, job_request_t *job,
    int flag, int sleep)
{
	int		rval;
	fp_cmd_t	*cmd;
	uchar_t		class;

	ASSERT(!MUTEX_HELD(&port->fp_mutex));

	FP_TRACE(FP_NHEAD1(1, 0), "fp_fabric_login Begin; port=%p, job=%p",
	    port, job);

	class = fp_get_nextclass(port, FC_TRAN_CLASS_INVALID);
	if (class == FC_TRAN_CLASS_INVALID) {
		return (FC_ELS_BAD);
	}

	cmd = fp_alloc_pkt(port, sizeof (la_els_logi_t),
	    sizeof (la_els_logi_t), sleep, NULL);
	if (cmd == NULL) {
		return (FC_NOMEM);
	}

	cmd->cmd_pkt.pkt_tran_flags = FC_TRAN_INTR | class;
	cmd->cmd_pkt.pkt_tran_type = FC_PKT_EXCHANGE;
	cmd->cmd_flags = flag;
	cmd->cmd_retry_count = fp_retry_count;
	cmd->cmd_ulp_pkt = NULL;

	fp_xlogi_init(port, cmd, s_id, 0xFFFFFE, fp_flogi_intr,
	    job, LA_ELS_FLOGI);

	rval = fp_sendcmd(port, cmd, port->fp_fca_handle);
	if (rval != FC_SUCCESS) {
		fp_free_pkt(cmd);
	}

	FP_TRACE(FP_NHEAD1(1, 0), "fp_fabric_login End; port=%p, job=%p",
	    port, job);

	return (rval);
}


/*
 * In some scenarios such as private loop device discovery period
 * the fc_remote_port_t data structure isn't allocated. The allocation
 * is done when the PLOGI is successful. In some other scenarios
 * such as Fabric topology, the fc_remote_port_t is already created
 * and initialized with appropriate values (as the NS provides
 * them)
 */
static int
fp_port_login(fc_local_port_t *port, uint32_t d_id, job_request_t *job,
    int cmd_flag, int sleep, fc_remote_port_t *pd, fc_packet_t *ulp_pkt)
{
	uchar_t class;
	fp_cmd_t *cmd;
	uint32_t src_id;
	fc_remote_port_t *tmp_pd;
	int relogin;
	int found = 0;

#ifdef	DEBUG
	if (pd == NULL) {
		ASSERT(fctl_get_remote_port_by_did(port, d_id) == NULL);
	}
#endif
	ASSERT(job->job_counter > 0);

	class = fp_get_nextclass(port, FC_TRAN_CLASS_INVALID);
	if (class == FC_TRAN_CLASS_INVALID) {
		return (FC_ELS_BAD);
	}

	mutex_enter(&port->fp_mutex);
	tmp_pd = fctl_lookup_pd_by_did(port, d_id);
	mutex_exit(&port->fp_mutex);

	relogin = 1;
	if (tmp_pd) {
		mutex_enter(&tmp_pd->pd_mutex);
		if ((tmp_pd->pd_aux_flags & PD_DISABLE_RELOGIN) &&
		    !(tmp_pd->pd_aux_flags & PD_LOGGED_OUT)) {
			tmp_pd->pd_state = PORT_DEVICE_LOGGED_IN;
			relogin = 0;
		}
		mutex_exit(&tmp_pd->pd_mutex);
	}

	if (!relogin) {
		mutex_enter(&tmp_pd->pd_mutex);
		if (tmp_pd->pd_state == PORT_DEVICE_LOGGED_IN) {
			cmd_flag |= FP_CMD_PLOGI_RETAIN;
		}
		mutex_exit(&tmp_pd->pd_mutex);

		cmd = fp_alloc_pkt(port, sizeof (la_els_adisc_t),
		    sizeof (la_els_adisc_t), sleep, tmp_pd);
		if (cmd == NULL) {
			return (FC_NOMEM);
		}

		cmd->cmd_pkt.pkt_tran_flags = FC_TRAN_INTR | class;
		cmd->cmd_pkt.pkt_tran_type = FC_PKT_EXCHANGE;
		cmd->cmd_flags = cmd_flag;
		cmd->cmd_retry_count = fp_retry_count;
		cmd->cmd_ulp_pkt = ulp_pkt;

		mutex_enter(&port->fp_mutex);
		mutex_enter(&tmp_pd->pd_mutex);
		fp_adisc_init(cmd, job);
		mutex_exit(&tmp_pd->pd_mutex);
		mutex_exit(&port->fp_mutex);

		cmd->cmd_pkt.pkt_cmdlen = sizeof (la_els_adisc_t);
		cmd->cmd_pkt.pkt_rsplen = sizeof (la_els_adisc_t);

	} else {
		cmd = fp_alloc_pkt(port, sizeof (la_els_logi_t),
		    sizeof (la_els_logi_t), sleep, pd);
		if (cmd == NULL) {
			return (FC_NOMEM);
		}

		cmd->cmd_pkt.pkt_tran_flags = FC_TRAN_INTR | class;
		cmd->cmd_pkt.pkt_tran_type = FC_PKT_EXCHANGE;
		cmd->cmd_flags = cmd_flag;
		cmd->cmd_retry_count = fp_retry_count;
		cmd->cmd_ulp_pkt = ulp_pkt;

		mutex_enter(&port->fp_mutex);
		src_id = port->fp_port_id.port_id;
		mutex_exit(&port->fp_mutex);

		fp_xlogi_init(port, cmd, src_id, d_id, fp_plogi_intr,
		    job, LA_ELS_PLOGI);
	}

	if (pd) {
		mutex_enter(&pd->pd_mutex);
		pd->pd_flags = PD_ELS_IN_PROGRESS;
		mutex_exit(&pd->pd_mutex);
	}

	/* npiv check to make sure we don't log into ourself */
	if (relogin &&
	    ((port->fp_npiv_type == FC_NPIV_PORT) ||
	    (port->fp_npiv_flag == FC_NPIV_ENABLE))) {
		if ((d_id & 0xffff00) ==
		    (port->fp_port_id.port_id & 0xffff00)) {
			found = 1;
		}
	}

	if (found ||
	    (fp_sendcmd(port, cmd, port->fp_fca_handle) != FC_SUCCESS)) {
		if (found) {
			fc_packet_t *pkt = &cmd->cmd_pkt;
			pkt->pkt_state = FC_PKT_NPORT_RJT;
		}
		if (pd) {
			mutex_enter(&pd->pd_mutex);
			pd->pd_flags = PD_IDLE;
			mutex_exit(&pd->pd_mutex);
		}

		if (ulp_pkt) {
			fc_packet_t *pkt = &cmd->cmd_pkt;

			ulp_pkt->pkt_state = pkt->pkt_state;
			ulp_pkt->pkt_reason = pkt->pkt_reason;
			ulp_pkt->pkt_action = pkt->pkt_action;
			ulp_pkt->pkt_expln = pkt->pkt_expln;
		}

		fp_iodone(cmd);
	}

	return (FC_SUCCESS);
}


/*
 * Register the LOGIN parameters with a port device
 */
static void
fp_register_login(ddi_acc_handle_t *handle, fc_remote_port_t *pd,
    la_els_logi_t *acc, uchar_t class)
{
	fc_remote_node_t	*node;

	ASSERT(pd != NULL);

	mutex_enter(&pd->pd_mutex);
	node = pd->pd_remote_nodep;
	if (pd->pd_login_count == 0) {
		pd->pd_login_count++;
	}

	if (handle) {
		FC_GET_RSP(pd->pd_port, *handle, (uint8_t *)&pd->pd_csp,
		    (uint8_t *)&acc->common_service,
		    sizeof (acc->common_service), DDI_DEV_AUTOINCR);
		FC_GET_RSP(pd->pd_port, *handle, (uint8_t *)&pd->pd_clsp1,
		    (uint8_t *)&acc->class_1, sizeof (acc->class_1),
		    DDI_DEV_AUTOINCR);
		FC_GET_RSP(pd->pd_port, *handle, (uint8_t *)&pd->pd_clsp2,
		    (uint8_t *)&acc->class_2, sizeof (acc->class_2),
		    DDI_DEV_AUTOINCR);
		FC_GET_RSP(pd->pd_port, *handle, (uint8_t *)&pd->pd_clsp3,
		    (uint8_t *)&acc->class_3, sizeof (acc->class_3),
		    DDI_DEV_AUTOINCR);
	} else {
		pd->pd_csp = acc->common_service;
		pd->pd_clsp1 = acc->class_1;
		pd->pd_clsp2 = acc->class_2;
		pd->pd_clsp3 = acc->class_3;
	}

	pd->pd_state = PORT_DEVICE_LOGGED_IN;
	pd->pd_login_class = class;
	mutex_exit(&pd->pd_mutex);

#ifndef	__lock_lint
	ASSERT(fctl_get_remote_port_by_did(pd->pd_port,
	    pd->pd_port_id.port_id) == pd);
#endif

	mutex_enter(&node->fd_mutex);
	if (handle) {
		FC_GET_RSP(pd->pd_port, *handle, (uint8_t *)node->fd_vv,
		    (uint8_t *)acc->vendor_version, sizeof (node->fd_vv),
		    DDI_DEV_AUTOINCR);
	} else {
		bcopy(acc->vendor_version, node->fd_vv, sizeof (node->fd_vv));
	}
	mutex_exit(&node->fd_mutex);
}


/*
 * Mark the remote port as OFFLINE
 */
static void
fp_remote_port_offline(fc_remote_port_t *pd)
{
	ASSERT(MUTEX_HELD(&pd->pd_mutex));
	if (pd->pd_login_count &&
	    ((pd->pd_aux_flags & PD_DISABLE_RELOGIN) == 0)) {
		bzero((caddr_t)&pd->pd_csp, sizeof (struct common_service));
		bzero((caddr_t)&pd->pd_clsp1, sizeof (struct service_param));
		bzero((caddr_t)&pd->pd_clsp2, sizeof (struct service_param));
		bzero((caddr_t)&pd->pd_clsp3, sizeof (struct service_param));
		pd->pd_login_class = 0;
	}
	pd->pd_type = PORT_DEVICE_OLD;
	pd->pd_flags = PD_IDLE;
	fctl_tc_reset(&pd->pd_logo_tc);
}


/*
 * Deregistration of a port device
 */
static void
fp_unregister_login(fc_remote_port_t *pd)
{
	fc_remote_node_t *node;

	ASSERT(pd != NULL);

	mutex_enter(&pd->pd_mutex);
	pd->pd_login_count = 0;
	bzero((caddr_t)&pd->pd_csp, sizeof (struct common_service));
	bzero((caddr_t)&pd->pd_clsp1, sizeof (struct service_param));
	bzero((caddr_t)&pd->pd_clsp2, sizeof (struct service_param));
	bzero((caddr_t)&pd->pd_clsp3, sizeof (struct service_param));

	pd->pd_state = PORT_DEVICE_VALID;
	pd->pd_login_class = 0;
	node = pd->pd_remote_nodep;
	mutex_exit(&pd->pd_mutex);

	mutex_enter(&node->fd_mutex);
	bzero(node->fd_vv, sizeof (node->fd_vv));
	mutex_exit(&node->fd_mutex);
}


/*
 * Handle OFFLINE state of an FCA port
 */
static void
fp_port_offline(fc_local_port_t *port, int notify)
{
	int			index;
	int			statec;
	timeout_id_t		tid;
	struct pwwn_hash	*head;
	fc_remote_port_t	*pd;

	ASSERT(MUTEX_HELD(&port->fp_mutex));

	for (index = 0; index < pwwn_table_size; index++) {
		head = &port->fp_pwwn_table[index];
		pd = head->pwwn_head;
		while (pd != NULL) {
			mutex_enter(&pd->pd_mutex);
			fp_remote_port_offline(pd);
			fctl_delist_did_table(port, pd);
			mutex_exit(&pd->pd_mutex);
			pd = pd->pd_wwn_hnext;
		}
	}
	port->fp_total_devices = 0;

	statec = 0;
	if (notify) {
		/*
		 * Decrement the statec busy counter as we
		 * are almost done with handling the state
		 * change
		 */
		ASSERT(port->fp_statec_busy > 0);
		if (--port->fp_statec_busy == 0) {
			port->fp_soft_state &= ~FP_SOFT_IN_STATEC_CB;
		}
		mutex_exit(&port->fp_mutex);
		(void) fp_ulp_statec_cb(port, FC_STATE_OFFLINE, NULL,
		    0, 0, KM_SLEEP);
		mutex_enter(&port->fp_mutex);

		if (port->fp_statec_busy) {
			statec++;
		}
	} else if (port->fp_statec_busy > 1) {
		statec++;
	}

	if ((tid = port->fp_offline_tid) != NULL) {
		mutex_exit(&port->fp_mutex);
		(void) untimeout(tid);
		mutex_enter(&port->fp_mutex);
	}

	if (!statec) {
		port->fp_offline_tid = timeout(fp_offline_timeout,
		    (caddr_t)port, fp_offline_ticks);
	}
}


/*
 * Offline devices and send up a state change notification to ULPs
 */
static void
fp_offline_timeout(void *port_handle)
{
	int		ret;
	fc_local_port_t *port = port_handle;
	uint32_t	listlen = 0;
	fc_portmap_t	*changelist = NULL;

	mutex_enter(&port->fp_mutex);

	if ((FC_PORT_STATE_MASK(port->fp_state) != FC_STATE_OFFLINE) ||
	    (port->fp_soft_state &
	    (FP_SOFT_IN_DETACH | FP_SOFT_SUSPEND | FP_SOFT_POWER_DOWN)) ||
	    port->fp_dev_count == 0 || port->fp_statec_busy) {
		port->fp_offline_tid = NULL;
		mutex_exit(&port->fp_mutex);
		return;
	}

	mutex_exit(&port->fp_mutex);

	FP_TRACE(FP_NHEAD2(9, 0), "OFFLINE timeout");

	if (port->fp_options & FP_CORE_ON_OFFLINE_TIMEOUT) {
		if ((ret = port->fp_fca_tran->fca_reset(port->fp_fca_handle,
		    FC_FCA_CORE)) != FC_SUCCESS) {
			FP_TRACE(FP_NHEAD1(9, ret),
			    "Failed to force adapter dump");
		} else {
			FP_TRACE(FP_NHEAD1(9, 0),
			    "Forced adapter dump successfully");
		}
	} else if (port->fp_options & FP_RESET_CORE_ON_OFFLINE_TIMEOUT) {
		if ((ret = port->fp_fca_tran->fca_reset(port->fp_fca_handle,
		    FC_FCA_RESET_CORE)) != FC_SUCCESS) {
			FP_TRACE(FP_NHEAD1(9, ret),
			    "Failed to force adapter dump and reset");
		} else {
			FP_TRACE(FP_NHEAD1(9, 0),
			    "Forced adapter dump and reset successfully");
		}
	}

	fctl_fillout_map(port, &changelist, &listlen, 1, 0, 0);
	(void) fp_ulp_statec_cb(port, FC_STATE_OFFLINE, changelist,
	    listlen, listlen, KM_SLEEP);

	mutex_enter(&port->fp_mutex);
	port->fp_offline_tid = NULL;
	mutex_exit(&port->fp_mutex);
}


/*
 * Perform general purpose ELS request initialization
 */
static void
fp_els_init(fp_cmd_t *cmd, uint32_t s_id, uint32_t d_id,
    void (*comp) (), job_request_t *job)
{
	fc_packet_t *pkt;

	pkt = &cmd->cmd_pkt;
	cmd->cmd_job = job;

	pkt->pkt_cmd_fhdr.r_ctl = R_CTL_ELS_REQ;
	pkt->pkt_cmd_fhdr.d_id = d_id;
	pkt->pkt_cmd_fhdr.s_id = s_id;
	pkt->pkt_cmd_fhdr.type = FC_TYPE_EXTENDED_LS;
	pkt->pkt_cmd_fhdr.f_ctl = F_CTL_SEQ_INITIATIVE | F_CTL_FIRST_SEQ;
	pkt->pkt_cmd_fhdr.seq_id = 0;
	pkt->pkt_cmd_fhdr.df_ctl  = 0;
	pkt->pkt_cmd_fhdr.seq_cnt = 0;
	pkt->pkt_cmd_fhdr.ox_id = 0xffff;
	pkt->pkt_cmd_fhdr.rx_id = 0xffff;
	pkt->pkt_cmd_fhdr.ro = 0;
	pkt->pkt_cmd_fhdr.rsvd = 0;
	pkt->pkt_comp = comp;
	pkt->pkt_timeout = FP_ELS_TIMEOUT;
}


/*
 * Initialize PLOGI/FLOGI ELS request
 */
static void
fp_xlogi_init(fc_local_port_t *port, fp_cmd_t *cmd, uint32_t s_id,
    uint32_t d_id, void (*intr) (), job_request_t *job, uchar_t ls_code)
{
	ls_code_t	payload;

	fp_els_init(cmd, s_id, d_id, intr, job);
	cmd->cmd_transport = port->fp_fca_tran->fca_els_send;

	payload.ls_code = ls_code;
	payload.mbz = 0;

	FC_SET_CMD(port, cmd->cmd_pkt.pkt_cmd_acc,
	    (uint8_t *)&port->fp_service_params,
	    (uint8_t *)cmd->cmd_pkt.pkt_cmd, sizeof (port->fp_service_params),
	    DDI_DEV_AUTOINCR);

	FC_SET_CMD(port, cmd->cmd_pkt.pkt_cmd_acc, (uint8_t *)&payload,
	    (uint8_t *)cmd->cmd_pkt.pkt_cmd, sizeof (payload),
	    DDI_DEV_AUTOINCR);
}


/*
 * Initialize LOGO ELS request
 */
static void
fp_logo_init(fc_remote_port_t *pd, fp_cmd_t *cmd, job_request_t *job)
{
	fc_local_port_t	*port;
	fc_packet_t	*pkt;
	la_els_logo_t	payload;

	port = pd->pd_port;
	pkt = &cmd->cmd_pkt;
	ASSERT(MUTEX_HELD(&port->fp_mutex));
	ASSERT(MUTEX_HELD(&pd->pd_mutex));

	fp_els_init(cmd, port->fp_port_id.port_id, pd->pd_port_id.port_id,
	    fp_logo_intr, job);

	cmd->cmd_transport = port->fp_fca_tran->fca_els_send;

	pkt->pkt_tran_flags = FC_TRAN_INTR | pd->pd_login_class;
	pkt->pkt_tran_type = FC_PKT_EXCHANGE;

	payload.ls_code.ls_code = LA_ELS_LOGO;
	payload.ls_code.mbz = 0;
	payload.nport_ww_name = port->fp_service_params.nport_ww_name;
	payload.nport_id = port->fp_port_id;

	FC_SET_CMD(port, pkt->pkt_cmd_acc, (uint8_t *)&payload,
	    (uint8_t *)pkt->pkt_cmd, sizeof (payload), DDI_DEV_AUTOINCR);
}

/*
 * Initialize RNID ELS request
 */
static void
fp_rnid_init(fp_cmd_t *cmd, uint16_t flag, job_request_t *job)
{
	fc_local_port_t	*port;
	fc_packet_t	*pkt;
	la_els_rnid_t	payload;
	fc_remote_port_t	*pd;

	pkt = &cmd->cmd_pkt;
	pd = pkt->pkt_pd;
	port = pd->pd_port;

	ASSERT(MUTEX_HELD(&port->fp_mutex));
	ASSERT(MUTEX_HELD(&pd->pd_mutex));

	fp_els_init(cmd, port->fp_port_id.port_id, pd->pd_port_id.port_id,
	    fp_rnid_intr, job);

	cmd->cmd_transport = port->fp_fca_tran->fca_els_send;
	pkt->pkt_tran_flags = FC_TRAN_INTR | pd->pd_login_class;
	pkt->pkt_tran_type = FC_PKT_EXCHANGE;

	payload.ls_code.ls_code = LA_ELS_RNID;
	payload.ls_code.mbz = 0;
	payload.data_format = flag;

	FC_SET_CMD(port, pkt->pkt_cmd_acc, (uint8_t *)&payload,
	    (uint8_t *)pkt->pkt_cmd, sizeof (payload), DDI_DEV_AUTOINCR);
}

/*
 * Initialize RLS ELS request
 */
static void
fp_rls_init(fp_cmd_t *cmd, job_request_t *job)
{
	fc_local_port_t	*port;
	fc_packet_t	*pkt;
	la_els_rls_t	payload;
	fc_remote_port_t	*pd;

	pkt = &cmd->cmd_pkt;
	pd = pkt->pkt_pd;
	port = pd->pd_port;

	ASSERT(MUTEX_HELD(&port->fp_mutex));
	ASSERT(MUTEX_HELD(&pd->pd_mutex));

	fp_els_init(cmd, port->fp_port_id.port_id, pd->pd_port_id.port_id,
	    fp_rls_intr, job);

	cmd->cmd_transport = port->fp_fca_tran->fca_els_send;
	pkt->pkt_tran_flags = FC_TRAN_INTR | pd->pd_login_class;
	pkt->pkt_tran_type = FC_PKT_EXCHANGE;

	payload.ls_code.ls_code = LA_ELS_RLS;
	payload.ls_code.mbz = 0;
	payload.rls_portid = port->fp_port_id;

	FC_SET_CMD(port, pkt->pkt_cmd_acc, (uint8_t *)&payload,
	    (uint8_t *)pkt->pkt_cmd, sizeof (payload), DDI_DEV_AUTOINCR);
}


/*
 * Initialize an ADISC ELS request
 */
static void
fp_adisc_init(fp_cmd_t *cmd, job_request_t *job)
{
	fc_local_port_t *port;
	fc_packet_t	*pkt;
	la_els_adisc_t	payload;
	fc_remote_port_t	*pd;

	pkt = &cmd->cmd_pkt;
	pd = pkt->pkt_pd;
	port = pd->pd_port;

	ASSERT(MUTEX_HELD(&pd->pd_mutex));
	ASSERT(MUTEX_HELD(&pd->pd_port->fp_mutex));

	fp_els_init(cmd, port->fp_port_id.port_id, pd->pd_port_id.port_id,
	    fp_adisc_intr, job);

	cmd->cmd_transport = port->fp_fca_tran->fca_els_send;
	pkt->pkt_tran_flags = FC_TRAN_INTR | pd->pd_login_class;
	pkt->pkt_tran_type = FC_PKT_EXCHANGE;

	payload.ls_code.ls_code = LA_ELS_ADISC;
	payload.ls_code.mbz = 0;
	payload.nport_id = port->fp_port_id;
	payload.port_wwn = port->fp_service_params.nport_ww_name;
	payload.node_wwn = port->fp_service_params.node_ww_name;
	payload.hard_addr = port->fp_hard_addr;

	FC_SET_CMD(port, pkt->pkt_cmd_acc, (uint8_t *)&payload,
	    (uint8_t *)pkt->pkt_cmd, sizeof (payload), DDI_DEV_AUTOINCR);
}


/*
 * Send up a state change notification to ULPs.
 * Spawns a call to fctl_ulp_statec_cb in a taskq thread.
 */
static int
fp_ulp_statec_cb(fc_local_port_t *port, uint32_t state,
    fc_portmap_t *changelist, uint32_t listlen, uint32_t alloc_len, int sleep)
{
	fc_port_clist_t		*clist;
	fc_remote_port_t	*pd;
	int			count;

	ASSERT(!MUTEX_HELD(&port->fp_mutex));

	clist = kmem_zalloc(sizeof (*clist), sleep);
	if (clist == NULL) {
		kmem_free(changelist, alloc_len * sizeof (*changelist));
		return (FC_NOMEM);
	}

	clist->clist_state = state;

	mutex_enter(&port->fp_mutex);
	clist->clist_flags = port->fp_topology;
	mutex_exit(&port->fp_mutex);

	clist->clist_port = (opaque_t)port;
	clist->clist_len = listlen;
	clist->clist_size = alloc_len;
	clist->clist_map = changelist;

	/*
	 * Bump the reference count of each fc_remote_port_t in this changelist.
	 * This is necessary since these devices will be sitting in a taskq
	 * and referenced later.  When the state change notification is
	 * complete, the reference counts will be decremented.
	 */
	for (count = 0; count < clist->clist_len; count++) {
		pd = clist->clist_map[count].map_pd;

		if (pd != NULL) {
			mutex_enter(&pd->pd_mutex);
			ASSERT((pd->pd_ref_count >= 0) ||
			    (pd->pd_aux_flags & PD_GIVEN_TO_ULPS));
			pd->pd_ref_count++;

			if (clist->clist_map[count].map_state !=
			    PORT_DEVICE_INVALID) {
				pd->pd_aux_flags |= PD_GIVEN_TO_ULPS;
			}

			mutex_exit(&pd->pd_mutex);
		}
	}

#ifdef	DEBUG
	/*
	 * Sanity check for presence of OLD devices in the hash lists
	 */
	if (clist->clist_size) {
		ASSERT(clist->clist_map != NULL);
		for (count = 0; count < clist->clist_len; count++) {
			if (clist->clist_map[count].map_state ==
			    PORT_DEVICE_INVALID) {
				la_wwn_t	pwwn;
				fc_portid_t	d_id;

				pd = clist->clist_map[count].map_pd;
				ASSERT(pd != NULL);

				mutex_enter(&pd->pd_mutex);
				pwwn = pd->pd_port_name;
				d_id = pd->pd_port_id;
				mutex_exit(&pd->pd_mutex);

				pd = fctl_get_remote_port_by_pwwn(port, &pwwn);
				ASSERT(pd != clist->clist_map[count].map_pd);

				pd = fctl_get_remote_port_by_did(port,
				    d_id.port_id);
				ASSERT(pd != clist->clist_map[count].map_pd);
			}
		}
	}
#endif

	mutex_enter(&port->fp_mutex);

	if (state == FC_STATE_ONLINE) {
		if (--port->fp_statec_busy == 0) {
			port->fp_soft_state &= ~FP_SOFT_IN_STATEC_CB;
		}
	}
	mutex_exit(&port->fp_mutex);

	(void) taskq_dispatch(port->fp_taskq, fctl_ulp_statec_cb,
	    clist, KM_SLEEP);

	FP_TRACE(FP_NHEAD1(4, 0), "fp_ulp_statec fired; Port=%p,"
	    "state=%x, len=%d", port, state, listlen);

	return (FC_SUCCESS);
}


/*
 * Send up a FC_STATE_DEVICE_CHANGE state notification to ULPs
 */
static int
fp_ulp_devc_cb(fc_local_port_t *port, fc_portmap_t *changelist,
    uint32_t listlen, uint32_t alloc_len, int sleep, int sync)
{
	int		ret;
	fc_port_clist_t *clist;

	ASSERT(!MUTEX_HELD(&port->fp_mutex));

	clist = kmem_zalloc(sizeof (*clist), sleep);
	if (clist == NULL) {
		kmem_free(changelist, alloc_len * sizeof (*changelist));
		return (FC_NOMEM);
	}

	clist->clist_state = FC_STATE_DEVICE_CHANGE;

	mutex_enter(&port->fp_mutex);
	clist->clist_flags = port->fp_topology;
	mutex_exit(&port->fp_mutex);

	clist->clist_port = (opaque_t)port;
	clist->clist_len = listlen;
	clist->clist_size = alloc_len;
	clist->clist_map = changelist;

	/* Send sysevents for target state changes */

	if (clist->clist_size) {
		int			count;
		fc_remote_port_t	*pd;

		ASSERT(clist->clist_map != NULL);
		for (count = 0; count < clist->clist_len; count++) {
			pd = clist->clist_map[count].map_pd;

			/*
			 * Bump reference counts on all fc_remote_port_t
			 * structs in this list.  We don't know when the task
			 * will fire, and we don't need these fc_remote_port_t
			 * structs going away behind our back.
			 */
			if (pd) {
				mutex_enter(&pd->pd_mutex);
				ASSERT((pd->pd_ref_count >= 0) ||
				    (pd->pd_aux_flags & PD_GIVEN_TO_ULPS));
				pd->pd_ref_count++;
				mutex_exit(&pd->pd_mutex);
			}

			if (clist->clist_map[count].map_state ==
			    PORT_DEVICE_VALID) {
				if (clist->clist_map[count].map_type ==
				    PORT_DEVICE_NEW) {
					/* Update our state change counter */
					mutex_enter(&port->fp_mutex);
					port->fp_last_change++;
					mutex_exit(&port->fp_mutex);

					/* Additions */
					fp_log_target_event(port,
					    ESC_SUNFC_TARGET_ADD,
					    clist->clist_map[count].map_pwwn,
					    clist->clist_map[count].map_did.
					    port_id);
				}

			} else if ((clist->clist_map[count].map_type ==
			    PORT_DEVICE_OLD) &&
			    (clist->clist_map[count].map_state ==
			    PORT_DEVICE_INVALID)) {
				/* Update our state change counter */
				mutex_enter(&port->fp_mutex);
				port->fp_last_change++;
				mutex_exit(&port->fp_mutex);

				/*
				 * For removals, we don't decrement
				 * pd_ref_count until after the ULP's
				 * state change callback function has
				 * completed.
				 */

				/* Removals */
				fp_log_target_event(port,
				    ESC_SUNFC_TARGET_REMOVE,
				    clist->clist_map[count].map_pwwn,
				    clist->clist_map[count].map_did.port_id);
			}

			if (clist->clist_map[count].map_state !=
			    PORT_DEVICE_INVALID) {
				/*
				 * Indicate that the ULPs are now aware of
				 * this device.
				 */

				mutex_enter(&pd->pd_mutex);
				pd->pd_aux_flags |= PD_GIVEN_TO_ULPS;
				mutex_exit(&pd->pd_mutex);
			}

#ifdef	DEBUG
			/*
			 * Sanity check for OLD devices in the hash lists
			 */
			if (pd && clist->clist_map[count].map_state ==
			    PORT_DEVICE_INVALID) {
				la_wwn_t	pwwn;
				fc_portid_t	d_id;

				mutex_enter(&pd->pd_mutex);
				pwwn = pd->pd_port_name;
				d_id = pd->pd_port_id;
				mutex_exit(&pd->pd_mutex);

				/*
				 * This overwrites the 'pd' local variable.
				 * Beware of this if 'pd' ever gets
				 * referenced below this block.
				 */
				pd = fctl_get_remote_port_by_pwwn(port, &pwwn);
				ASSERT(pd != clist->clist_map[count].map_pd);

				pd = fctl_get_remote_port_by_did(port,
				    d_id.port_id);
				ASSERT(pd != clist->clist_map[count].map_pd);
			}
#endif
		}
	}

	if (sync) {
		clist->clist_wait = 1;
		mutex_init(&clist->clist_mutex, NULL, MUTEX_DRIVER, NULL);
		cv_init(&clist->clist_cv, NULL, CV_DRIVER, NULL);
	}

	ret = taskq_dispatch(port->fp_taskq, fctl_ulp_statec_cb, clist, sleep);
	if (sync && ret != TASKQID_INVALID) {
		mutex_enter(&clist->clist_mutex);
		while (clist->clist_wait) {
			cv_wait(&clist->clist_cv, &clist->clist_mutex);
		}
		mutex_exit(&clist->clist_mutex);

		mutex_destroy(&clist->clist_mutex);
		cv_destroy(&clist->clist_cv);
		kmem_free(clist, sizeof (*clist));
	}

	if (!ret) {
		FP_TRACE(FP_NHEAD1(4, 0), "fp_ulp_devc dispatch failed; "
		    "port=%p", port);
		kmem_free(clist->clist_map,
		    sizeof (*(clist->clist_map)) * clist->clist_size);
		kmem_free(clist, sizeof (*clist));
	} else {
		FP_TRACE(FP_NHEAD1(4, 0), "fp_ulp_devc fired; port=%p, len=%d",
		    port, listlen);
	}

	return (FC_SUCCESS);
}


/*
 * Perform PLOGI to the group of devices for ULPs
 */
static void
fp_plogi_group(fc_local_port_t *port, job_request_t *job)
{
	int			offline;
	int			count;
	int			rval;
	uint32_t		listlen;
	uint32_t		done;
	uint32_t		d_id;
	fc_remote_node_t	*node;
	fc_remote_port_t	*pd;
	fc_remote_port_t	*tmp_pd;
	fc_packet_t		*ulp_pkt;
	la_els_logi_t		*els_data;
	ls_code_t		ls_code;

	FP_TRACE(FP_NHEAD1(1, 0), "fp_plogi_group begin; port=%p, job=%p",
	    port, job);

	done = 0;
	listlen = job->job_ulp_listlen;
	job->job_counter = job->job_ulp_listlen;

	mutex_enter(&port->fp_mutex);
	offline = (port->fp_statec_busy ||
	    FC_PORT_STATE_MASK(port->fp_state) == FC_STATE_OFFLINE) ? 1 : 0;
	mutex_exit(&port->fp_mutex);

	for (count = 0; count < listlen; count++) {
		ASSERT(job->job_ulp_pkts[count]->pkt_rsplen >=
		    sizeof (la_els_logi_t));

		ulp_pkt = job->job_ulp_pkts[count];
		pd = ulp_pkt->pkt_pd;
		d_id = ulp_pkt->pkt_cmd_fhdr.d_id;

		if (offline) {
			done++;

			ulp_pkt->pkt_state = FC_PKT_PORT_OFFLINE;
			ulp_pkt->pkt_reason = FC_REASON_OFFLINE;
			ulp_pkt->pkt_pd = NULL;
			ulp_pkt->pkt_comp(ulp_pkt);

			job->job_ulp_pkts[count] = NULL;

			fp_jobdone(job);
			continue;
		}

		if (pd == NULL) {
			pd = fctl_get_remote_port_by_did(port, d_id);
			if (pd == NULL) {
				/* reset later */
				ulp_pkt->pkt_state = FC_PKT_FAILURE;
				continue;
			}
			mutex_enter(&pd->pd_mutex);
			if (pd->pd_flags == PD_ELS_IN_PROGRESS) {
				mutex_exit(&pd->pd_mutex);
				ulp_pkt->pkt_state = FC_PKT_ELS_IN_PROGRESS;
				done++;
				ulp_pkt->pkt_comp(ulp_pkt);
				job->job_ulp_pkts[count] = NULL;
				fp_jobdone(job);
			} else {
				ulp_pkt->pkt_state = FC_PKT_FAILURE;
				mutex_exit(&pd->pd_mutex);
			}
			continue;
		}

		switch (ulp_pkt->pkt_state) {
		case FC_PKT_ELS_IN_PROGRESS:
			ulp_pkt->pkt_reason = FC_REASON_OFFLINE;
			/* FALLTHRU */
		case FC_PKT_LOCAL_RJT:
			done++;
			ulp_pkt->pkt_comp(ulp_pkt);
			job->job_ulp_pkts[count] = NULL;
			fp_jobdone(job);
			continue;
		default:
			break;
		}

		/*
		 * Validate the pd corresponding to the d_id passed
		 * by the ULPs
		 */
		tmp_pd = fctl_get_remote_port_by_did(port, d_id);
		if ((tmp_pd == NULL) || (pd != tmp_pd)) {
			done++;
			ulp_pkt->pkt_state = FC_PKT_FAILURE;
			ulp_pkt->pkt_reason = FC_REASON_NO_CONNECTION;
			ulp_pkt->pkt_pd = NULL;
			ulp_pkt->pkt_comp(ulp_pkt);
			job->job_ulp_pkts[count] = NULL;
			fp_jobdone(job);
			continue;
		}

		FP_TRACE(FP_NHEAD1(3, 0), "fp_plogi_group contd; "
		    "port=%p, pd=%p", port, pd);

		mutex_enter(&pd->pd_mutex);

		if (pd->pd_state == PORT_DEVICE_LOGGED_IN) {
			done++;
			els_data = (la_els_logi_t *)ulp_pkt->pkt_resp;

			ls_code.ls_code = LA_ELS_ACC;
			ls_code.mbz = 0;

			FC_SET_CMD(pd->pd_port, ulp_pkt->pkt_resp_acc,
			    (uint8_t *)&ls_code, (uint8_t *)&els_data->ls_code,
			    sizeof (ls_code_t), DDI_DEV_AUTOINCR);

			FC_SET_CMD(pd->pd_port, ulp_pkt->pkt_resp_acc,
			    (uint8_t *)&pd->pd_csp,
			    (uint8_t *)&els_data->common_service,
			    sizeof (pd->pd_csp), DDI_DEV_AUTOINCR);

			FC_SET_CMD(pd->pd_port, ulp_pkt->pkt_resp_acc,
			    (uint8_t *)&pd->pd_port_name,
			    (uint8_t *)&els_data->nport_ww_name,
			    sizeof (pd->pd_port_name), DDI_DEV_AUTOINCR);

			FC_SET_CMD(pd->pd_port, ulp_pkt->pkt_resp_acc,
			    (uint8_t *)&pd->pd_clsp1,
			    (uint8_t *)&els_data->class_1,
			    sizeof (pd->pd_clsp1), DDI_DEV_AUTOINCR);

			FC_SET_CMD(pd->pd_port, ulp_pkt->pkt_resp_acc,
			    (uint8_t *)&pd->pd_clsp2,
			    (uint8_t *)&els_data->class_2,
			    sizeof (pd->pd_clsp2), DDI_DEV_AUTOINCR);

			FC_SET_CMD(pd->pd_port, ulp_pkt->pkt_resp_acc,
			    (uint8_t *)&pd->pd_clsp3,
			    (uint8_t *)&els_data->class_3,
			    sizeof (pd->pd_clsp3), DDI_DEV_AUTOINCR);

			node = pd->pd_remote_nodep;
			pd->pd_login_count++;
			pd->pd_flags = PD_IDLE;
			ulp_pkt->pkt_pd = pd;
			mutex_exit(&pd->pd_mutex);

			mutex_enter(&node->fd_mutex);
			FC_SET_CMD(pd->pd_port, ulp_pkt->pkt_resp_acc,
			    (uint8_t *)&node->fd_node_name,
			    (uint8_t *)(&els_data->node_ww_name),
			    sizeof (node->fd_node_name), DDI_DEV_AUTOINCR);

			FC_SET_CMD(pd->pd_port, ulp_pkt->pkt_resp_acc,
			    (uint8_t *)&node->fd_vv,
			    (uint8_t *)(&els_data->vendor_version),
			    sizeof (node->fd_vv), DDI_DEV_AUTOINCR);

			mutex_exit(&node->fd_mutex);
			ulp_pkt->pkt_state = FC_PKT_SUCCESS;
		} else {

			ulp_pkt->pkt_state = FC_PKT_FAILURE; /* reset later */
			mutex_exit(&pd->pd_mutex);
		}

		if (ulp_pkt->pkt_state != FC_PKT_FAILURE) {
			ulp_pkt->pkt_comp(ulp_pkt);
			job->job_ulp_pkts[count] = NULL;
			fp_jobdone(job);
		}
	}

	if (done == listlen) {
		fp_jobwait(job);
		fctl_jobdone(job);
		return;
	}

	job->job_counter = listlen - done;

	for (count = 0; count < listlen; count++) {
		int cmd_flags;

		if ((ulp_pkt = job->job_ulp_pkts[count]) == NULL) {
			continue;
		}

		ASSERT(ulp_pkt->pkt_state == FC_PKT_FAILURE);

		cmd_flags = FP_CMD_PLOGI_RETAIN;

		d_id = ulp_pkt->pkt_cmd_fhdr.d_id;
		ASSERT(d_id != 0);

		pd = fctl_get_remote_port_by_did(port, d_id);

		/*
		 * We need to properly adjust the port device
		 * reference counter before we assign the pd
		 * to the ULP packets port device pointer.
		 */
		if (pd != NULL && ulp_pkt->pkt_pd == NULL) {
			mutex_enter(&pd->pd_mutex);
			pd->pd_ref_count++;
			mutex_exit(&pd->pd_mutex);
			FP_TRACE(FP_NHEAD1(3, 0),
			    "fp_plogi_group: DID = 0x%x using new pd %p \
			    old pd NULL\n", d_id, pd);
		} else if (pd != NULL && ulp_pkt->pkt_pd != NULL &&
		    ulp_pkt->pkt_pd != pd) {
			mutex_enter(&pd->pd_mutex);
			pd->pd_ref_count++;
			mutex_exit(&pd->pd_mutex);
			mutex_enter(&ulp_pkt->pkt_pd->pd_mutex);
			ulp_pkt->pkt_pd->pd_ref_count--;
			mutex_exit(&ulp_pkt->pkt_pd->pd_mutex);
			FP_TRACE(FP_NHEAD1(3, 0),
			    "fp_plogi_group: DID = 0x%x pkt_pd %p != pd %p\n",
			    d_id, ulp_pkt->pkt_pd, pd);
		} else if (pd == NULL && ulp_pkt->pkt_pd != NULL) {
			mutex_enter(&ulp_pkt->pkt_pd->pd_mutex);
			ulp_pkt->pkt_pd->pd_ref_count--;
			mutex_exit(&ulp_pkt->pkt_pd->pd_mutex);
			FP_TRACE(FP_NHEAD1(3, 0),
			    "fp_plogi_group: DID = 0x%x pd is NULL and \
			    pkt_pd = %p\n", d_id, ulp_pkt->pkt_pd);
		}

		ulp_pkt->pkt_pd = pd;

		if (pd != NULL) {
			mutex_enter(&pd->pd_mutex);
			d_id = pd->pd_port_id.port_id;
			pd->pd_flags = PD_ELS_IN_PROGRESS;
			mutex_exit(&pd->pd_mutex);
		} else {
			d_id = ulp_pkt->pkt_cmd_fhdr.d_id;
#ifdef	DEBUG
			pd = fctl_get_remote_port_by_did(port, d_id);
			ASSERT(pd == NULL);
#endif
			/*
			 * In the Fabric topology, use NS to create
			 * port device, and if that fails still try
			 * with PLOGI - which will make yet another
			 * attempt to create after successful PLOGI
			 */
			mutex_enter(&port->fp_mutex);
			if (FC_IS_TOP_SWITCH(port->fp_topology)) {
				mutex_exit(&port->fp_mutex);
				pd = fp_create_remote_port_by_ns(port,
				    d_id, KM_SLEEP);
				if (pd) {
					cmd_flags |= FP_CMD_DELDEV_ON_ERROR;

					mutex_enter(&pd->pd_mutex);
					pd->pd_flags = PD_ELS_IN_PROGRESS;
					mutex_exit(&pd->pd_mutex);

					FP_TRACE(FP_NHEAD1(3, 0),
					    "fp_plogi_group;"
					    " NS created PD port=%p, job=%p,"
					    " pd=%p", port, job, pd);
				}
			} else {
				mutex_exit(&port->fp_mutex);
			}
			if ((ulp_pkt->pkt_pd == NULL) && (pd != NULL)) {
				FP_TRACE(FP_NHEAD1(3, 0),
				    "fp_plogi_group;"
				    "ulp_pkt's pd is NULL, get a pd %p",
				    pd);
				mutex_enter(&pd->pd_mutex);
				pd->pd_ref_count++;
				mutex_exit(&pd->pd_mutex);
			}
			ulp_pkt->pkt_pd = pd;
		}

		rval = fp_port_login(port, d_id, job, cmd_flags,
		    KM_SLEEP, pd, ulp_pkt);

		if (rval == FC_SUCCESS) {
			continue;
		}

		if (rval == FC_STATEC_BUSY) {
			ulp_pkt->pkt_state = FC_PKT_PORT_OFFLINE;
			ulp_pkt->pkt_reason = FC_REASON_OFFLINE;
		} else {
			ulp_pkt->pkt_state = FC_PKT_FAILURE;
		}

		if (pd) {
			mutex_enter(&pd->pd_mutex);
			pd->pd_flags = PD_IDLE;
			mutex_exit(&pd->pd_mutex);
		}

		if (cmd_flags & FP_CMD_DELDEV_ON_ERROR) {
			ASSERT(pd != NULL);

			FP_TRACE(FP_NHEAD1(3, 0), "fp_plogi_group: NS created,"
			    " PD removed; port=%p, job=%p", port, job);

			mutex_enter(&pd->pd_mutex);
			pd->pd_ref_count--;
			node = pd->pd_remote_nodep;
			mutex_exit(&pd->pd_mutex);

			ASSERT(node != NULL);

			if (fctl_destroy_remote_port(port, pd) == 0) {
				fctl_destroy_remote_node(node);
			}
			ulp_pkt->pkt_pd = NULL;
		}
		ulp_pkt->pkt_comp(ulp_pkt);
		fp_jobdone(job);
	}

	fp_jobwait(job);
	fctl_jobdone(job);

	FP_TRACE(FP_NHEAD1(1, 0), "fp_plogi_group end: port=%p, job=%p",
	    port, job);
}


/*
 * Name server request initialization
 */
static void
fp_ns_init(fc_local_port_t *port, job_request_t *job, int sleep)
{
	int rval;
	int count;
	int size;

	ASSERT((job->job_flags & JOB_TYPE_FP_ASYNC) == 0);

	job->job_counter = 1;
	job->job_result = FC_SUCCESS;

	rval = fp_port_login(port, 0xFFFFFC, job, FP_CMD_PLOGI_RETAIN,
	    KM_SLEEP, NULL, NULL);

	if (rval != FC_SUCCESS) {
		mutex_enter(&port->fp_mutex);
		port->fp_topology = FC_TOP_NO_NS;
		mutex_exit(&port->fp_mutex);
		return;
	}

	fp_jobwait(job);

	if (job->job_result != FC_SUCCESS) {
		mutex_enter(&port->fp_mutex);
		port->fp_topology = FC_TOP_NO_NS;
		mutex_exit(&port->fp_mutex);
		return;
	}

	/*
	 * At this time, we'll do NS registration for objects in the
	 * ns_reg_cmds (see top of this file) array.
	 *
	 * Each time a ULP module registers with the transport, the
	 * appropriate fc4 bit is set fc4 types and registered with
	 * the NS for this support. Also, ULPs and FC admin utilities
	 * may do registration for objects like IP address, symbolic
	 * port/node name, Initial process associator at run time.
	 */
	size = sizeof (ns_reg_cmds) / sizeof (ns_reg_cmds[0]);
	job->job_counter = size;
	job->job_result = FC_SUCCESS;

	for (count = 0; count < size; count++) {
		if (fp_ns_reg(port, NULL, ns_reg_cmds[count],
		    job, 0, sleep) != FC_SUCCESS) {
			fp_jobdone(job);
		}
	}
	if (size) {
		fp_jobwait(job);
	}

	job->job_result = FC_SUCCESS;

	(void) fp_ns_get_devcount(port, job, 0, KM_SLEEP);

	if (port->fp_dev_count < FP_MAX_DEVICES) {
		(void) fp_ns_get_devcount(port, job, 1, KM_SLEEP);
	}

	job->job_counter = 1;

	if (fp_ns_scr(port, job, FC_SCR_FULL_REGISTRATION,
	    sleep) == FC_SUCCESS) {
		fp_jobwait(job);
	}
}


/*
 * Name server finish:
 *	Unregister for RSCNs
 *	Unregister all the host port objects in the Name Server
 *	Perform LOGO with the NS;
 */
static void
fp_ns_fini(fc_local_port_t *port, job_request_t *job)
{
	fp_cmd_t	*cmd;
	uchar_t		class;
	uint32_t	s_id;
	fc_packet_t	*pkt;
	la_els_logo_t	payload;

	ASSERT((job->job_flags & JOB_TYPE_FP_ASYNC) == 0);

	job->job_counter = 1;

	if (fp_ns_scr(port, job, FC_SCR_CLEAR_REGISTRATION, KM_SLEEP) !=
	    FC_SUCCESS) {
		fp_jobdone(job);
	}
	fp_jobwait(job);

	job->job_counter = 1;

	if (fp_ns_reg(port, NULL, NS_DA_ID, job, 0, KM_SLEEP) != FC_SUCCESS) {
		fp_jobdone(job);
	}
	fp_jobwait(job);

	job->job_counter = 1;

	cmd = fp_alloc_pkt(port, sizeof (la_els_logo_t),
	    FP_PORT_IDENTIFIER_LEN, KM_SLEEP, NULL);
	pkt = &cmd->cmd_pkt;

	mutex_enter(&port->fp_mutex);
	class = port->fp_ns_login_class;
	s_id = port->fp_port_id.port_id;
	payload.nport_id = port->fp_port_id;
	mutex_exit(&port->fp_mutex);

	cmd->cmd_pkt.pkt_tran_flags = FC_TRAN_INTR | class;
	cmd->cmd_pkt.pkt_tran_type = FC_PKT_EXCHANGE;
	cmd->cmd_flags = FP_CMD_PLOGI_DONT_CARE;
	cmd->cmd_retry_count = 1;
	cmd->cmd_ulp_pkt = NULL;

	if (port->fp_npiv_type == FC_NPIV_PORT) {
		fp_els_init(cmd, s_id, 0xFFFFFE, fp_logo_intr, job);
	} else {
		fp_els_init(cmd, s_id, 0xFFFFFC, fp_logo_intr, job);
	}

	cmd->cmd_transport = port->fp_fca_tran->fca_els_send;

	payload.ls_code.ls_code = LA_ELS_LOGO;
	payload.ls_code.mbz = 0;
	payload.nport_ww_name = port->fp_service_params.nport_ww_name;

	FC_SET_CMD(port, pkt->pkt_cmd_acc, (uint8_t *)&payload,
	    (uint8_t *)pkt->pkt_cmd, sizeof (payload), DDI_DEV_AUTOINCR);

	if (fp_sendcmd(port, cmd, port->fp_fca_handle) != FC_SUCCESS) {
		fp_iodone(cmd);
	}
	fp_jobwait(job);
}


/*
 * NS Registration function.
 *
 *	It should be seriously noted that FC-GS-2 currently doesn't support
 *	an Object Registration by a D_ID other than the owner of the object.
 *	What we are aiming at currently is to at least allow Symbolic Node/Port
 *	Name registration for any N_Port Identifier by the host software.
 *
 *	Anyway, if the second argument (fc_remote_port_t *) is NULL, this
 *	function treats the request as Host NS Object.
 */
static int
fp_ns_reg(fc_local_port_t *port, fc_remote_port_t *pd, uint16_t cmd_code,
    job_request_t *job, int polled, int sleep)
{
	int		rval;
	fc_portid_t	s_id;
	fc_packet_t	*pkt;
	fp_cmd_t	*cmd;

	if (pd == NULL) {
		mutex_enter(&port->fp_mutex);
		s_id = port->fp_port_id;
		mutex_exit(&port->fp_mutex);
	} else {
		mutex_enter(&pd->pd_mutex);
		s_id = pd->pd_port_id;
		mutex_exit(&pd->pd_mutex);
	}

	if (polled) {
		job->job_counter = 1;
	}

	switch (cmd_code) {
	case NS_RPN_ID:
	case NS_RNN_ID: {
		ns_rxn_req_t rxn;

		cmd = fp_alloc_pkt(port, sizeof (fc_ct_header_t) +
		    sizeof (ns_rxn_req_t), sizeof (fc_reg_resp_t), sleep, NULL);
		if (cmd == NULL) {
			return (FC_NOMEM);
		}
		fp_ct_init(port, cmd, NULL, cmd_code, NULL, 0, 0, job);
		pkt = &cmd->cmd_pkt;

		if (pd == NULL) {
			rxn.rxn_xname = ((cmd_code == NS_RPN_ID) ?
			    (port->fp_service_params.nport_ww_name) :
			    (port->fp_service_params.node_ww_name));
		} else {
			if (cmd_code == NS_RPN_ID) {
				mutex_enter(&pd->pd_mutex);
				rxn.rxn_xname = pd->pd_port_name;
				mutex_exit(&pd->pd_mutex);
			} else {
				fc_remote_node_t *node;

				mutex_enter(&pd->pd_mutex);
				node = pd->pd_remote_nodep;
				mutex_exit(&pd->pd_mutex);

				mutex_enter(&node->fd_mutex);
				rxn.rxn_xname = node->fd_node_name;
				mutex_exit(&node->fd_mutex);
			}
		}
		rxn.rxn_port_id = s_id;

		FC_SET_CMD(port, pkt->pkt_cmd_acc, (uint8_t *)&rxn,
		    (uint8_t *)(pkt->pkt_cmd + sizeof (fc_ct_header_t)),
		    sizeof (rxn), DDI_DEV_AUTOINCR);

		break;
	}

	case NS_RCS_ID: {
		ns_rcos_t rcos;

		cmd = fp_alloc_pkt(port, sizeof (fc_ct_header_t) +
		    sizeof (ns_rcos_t), sizeof (fc_reg_resp_t), sleep, NULL);
		if (cmd == NULL) {
			return (FC_NOMEM);
		}
		fp_ct_init(port, cmd, NULL, cmd_code, NULL, 0, 0, job);
		pkt = &cmd->cmd_pkt;

		if (pd == NULL) {
			rcos.rcos_cos = port->fp_cos;
		} else {
			mutex_enter(&pd->pd_mutex);
			rcos.rcos_cos = pd->pd_cos;
			mutex_exit(&pd->pd_mutex);
		}
		rcos.rcos_port_id = s_id;

		FC_SET_CMD(port, pkt->pkt_cmd_acc, (uint8_t *)&rcos,
		    (uint8_t *)(pkt->pkt_cmd + sizeof (fc_ct_header_t)),
		    sizeof (rcos), DDI_DEV_AUTOINCR);

		break;
	}

	case NS_RFT_ID: {
		ns_rfc_type_t rfc;

		cmd = fp_alloc_pkt(port, sizeof (fc_ct_header_t) +
		    sizeof (ns_rfc_type_t), sizeof (fc_reg_resp_t), sleep,
		    NULL);
		if (cmd == NULL) {
			return (FC_NOMEM);
		}
		fp_ct_init(port, cmd, NULL, cmd_code, NULL, 0, 0, job);
		pkt = &cmd->cmd_pkt;

		if (pd == NULL) {
			mutex_enter(&port->fp_mutex);
			bcopy(port->fp_fc4_types, rfc.rfc_types,
			    sizeof (port->fp_fc4_types));
			mutex_exit(&port->fp_mutex);
		} else {
			mutex_enter(&pd->pd_mutex);
			bcopy(pd->pd_fc4types, rfc.rfc_types,
			    sizeof (pd->pd_fc4types));
			mutex_exit(&pd->pd_mutex);
		}
		rfc.rfc_port_id = s_id;

		FC_SET_CMD(port, pkt->pkt_cmd_acc, (uint8_t *)&rfc,
		    (uint8_t *)(pkt->pkt_cmd + sizeof (fc_ct_header_t)),
		    sizeof (rfc), DDI_DEV_AUTOINCR);

		break;
	}

	case NS_RSPN_ID: {
		uchar_t		name_len;
		int		pl_size;
		fc_portid_t	spn;

		if (pd == NULL) {
			mutex_enter(&port->fp_mutex);
			name_len = port->fp_sym_port_namelen;
			mutex_exit(&port->fp_mutex);
		} else {
			mutex_enter(&pd->pd_mutex);
			name_len = pd->pd_spn_len;
			mutex_exit(&pd->pd_mutex);
		}

		pl_size = sizeof (fc_portid_t) + name_len + 1;

		cmd = fp_alloc_pkt(port, sizeof (fc_ct_header_t) + pl_size,
		    sizeof (fc_reg_resp_t), sleep, NULL);
		if (cmd == NULL) {
			return (FC_NOMEM);
		}

		fp_ct_init(port, cmd, NULL, cmd_code, NULL, 0, 0, job);

		pkt = &cmd->cmd_pkt;

		spn = s_id;

		FC_SET_CMD(port, pkt->pkt_cmd_acc, (uint8_t *)&spn, (uint8_t *)
		    (pkt->pkt_cmd + sizeof (fc_ct_header_t)), sizeof (spn),
		    DDI_DEV_AUTOINCR);
		FC_SET_CMD(port, pkt->pkt_cmd_acc, (uint8_t *)&name_len,
		    (uint8_t *)(pkt->pkt_cmd + sizeof (fc_ct_header_t)
		    + sizeof (fc_portid_t)), 1, DDI_DEV_AUTOINCR);

		if (pd == NULL) {
			mutex_enter(&port->fp_mutex);
			FC_SET_CMD(port, pkt->pkt_cmd_acc,
			    (uint8_t *)port->fp_sym_port_name, (uint8_t *)
			    (pkt->pkt_cmd + sizeof (fc_ct_header_t) +
			    sizeof (spn) + 1), name_len, DDI_DEV_AUTOINCR);
			mutex_exit(&port->fp_mutex);
		} else {
			mutex_enter(&pd->pd_mutex);
			FC_SET_CMD(port, pkt->pkt_cmd_acc,
			    (uint8_t *)pd->pd_spn,
			    (uint8_t *)(pkt->pkt_cmd + sizeof (fc_ct_header_t) +
			    sizeof (spn) + 1), name_len, DDI_DEV_AUTOINCR);
			mutex_exit(&pd->pd_mutex);
		}
		break;
	}

	case NS_RPT_ID: {
		ns_rpt_t rpt;

		cmd = fp_alloc_pkt(port, sizeof (fc_ct_header_t) +
		    sizeof (ns_rpt_t), sizeof (fc_reg_resp_t), sleep, NULL);
		if (cmd == NULL) {
			return (FC_NOMEM);
		}
		fp_ct_init(port, cmd, NULL, cmd_code, NULL, 0, 0, job);
		pkt = &cmd->cmd_pkt;

		if (pd == NULL) {
			rpt.rpt_type = port->fp_port_type;
		} else {
			mutex_enter(&pd->pd_mutex);
			rpt.rpt_type = pd->pd_porttype;
			mutex_exit(&pd->pd_mutex);
		}
		rpt.rpt_port_id = s_id;

		FC_SET_CMD(port, pkt->pkt_cmd_acc, (uint8_t *)&rpt,
		    (uint8_t *)(pkt->pkt_cmd + sizeof (fc_ct_header_t)),
		    sizeof (rpt), DDI_DEV_AUTOINCR);

		break;
	}

	case NS_RIP_NN: {
		ns_rip_t rip;

		cmd = fp_alloc_pkt(port, sizeof (fc_ct_header_t) +
		    sizeof (ns_rip_t), sizeof (fc_reg_resp_t), sleep, NULL);
		if (cmd == NULL) {
			return (FC_NOMEM);
		}
		fp_ct_init(port, cmd, NULL, cmd_code, NULL, 0, 0, job);
		pkt = &cmd->cmd_pkt;

		if (pd == NULL) {
			rip.rip_node_name =
			    port->fp_service_params.node_ww_name;
			bcopy(port->fp_ip_addr, rip.rip_ip_addr,
			    sizeof (port->fp_ip_addr));
		} else {
			fc_remote_node_t *node;

			/*
			 * The most correct implementation should have the IP
			 * address in the fc_remote_node_t structure; I believe
			 * Node WWN and IP address should have one to one
			 * correlation (but guess what this is changing in
			 * FC-GS-2 latest draft)
			 */
			mutex_enter(&pd->pd_mutex);
			node = pd->pd_remote_nodep;
			bcopy(pd->pd_ip_addr, rip.rip_ip_addr,
			    sizeof (pd->pd_ip_addr));
			mutex_exit(&pd->pd_mutex);

			mutex_enter(&node->fd_mutex);
			rip.rip_node_name = node->fd_node_name;
			mutex_exit(&node->fd_mutex);
		}

		FC_SET_CMD(port, pkt->pkt_cmd_acc, (uint8_t *)&rip,
		    (uint8_t *)(pkt->pkt_cmd + sizeof (fc_ct_header_t)),
		    sizeof (rip), DDI_DEV_AUTOINCR);

		break;
	}

	case NS_RIPA_NN: {
		ns_ipa_t ipa;

		cmd = fp_alloc_pkt(port, sizeof (fc_ct_header_t) +
		    sizeof (ns_ipa_t), sizeof (fc_reg_resp_t), sleep, NULL);
		if (cmd == NULL) {
			return (FC_NOMEM);
		}
		fp_ct_init(port, cmd, NULL, cmd_code, NULL, 0, 0, job);
		pkt = &cmd->cmd_pkt;

		if (pd == NULL) {
			ipa.ipa_node_name =
			    port->fp_service_params.node_ww_name;
			bcopy(port->fp_ipa, ipa.ipa_value,
			    sizeof (port->fp_ipa));
		} else {
			fc_remote_node_t *node;

			mutex_enter(&pd->pd_mutex);
			node = pd->pd_remote_nodep;
			mutex_exit(&pd->pd_mutex);

			mutex_enter(&node->fd_mutex);
			ipa.ipa_node_name = node->fd_node_name;
			bcopy(node->fd_ipa, ipa.ipa_value,
			    sizeof (node->fd_ipa));
			mutex_exit(&node->fd_mutex);
		}

		FC_SET_CMD(port, pkt->pkt_cmd_acc, (uint8_t *)&ipa,
		    (uint8_t *)(pkt->pkt_cmd + sizeof (fc_ct_header_t)),
		    sizeof (ipa), DDI_DEV_AUTOINCR);

		break;
	}

	case NS_RSNN_NN: {
		uchar_t			name_len;
		int			pl_size;
		la_wwn_t		snn;
		fc_remote_node_t	*node = NULL;

		if (pd == NULL) {
			mutex_enter(&port->fp_mutex);
			name_len = port->fp_sym_node_namelen;
			mutex_exit(&port->fp_mutex);
		} else {
			mutex_enter(&pd->pd_mutex);
			node = pd->pd_remote_nodep;
			mutex_exit(&pd->pd_mutex);

			mutex_enter(&node->fd_mutex);
			name_len = node->fd_snn_len;
			mutex_exit(&node->fd_mutex);
		}

		pl_size = sizeof (la_wwn_t) + name_len + 1;

		cmd = fp_alloc_pkt(port, sizeof (fc_ct_header_t) +
		    pl_size, sizeof (fc_reg_resp_t), sleep, NULL);
		if (cmd == NULL) {
			return (FC_NOMEM);
		}
		fp_ct_init(port, cmd, NULL, cmd_code, NULL, 0, 0, job);

		pkt = &cmd->cmd_pkt;

		bcopy(&port->fp_service_params.node_ww_name,
		    &snn, sizeof (la_wwn_t));

		if (pd == NULL) {
			mutex_enter(&port->fp_mutex);
			FC_SET_CMD(port, pkt->pkt_cmd_acc,
			    (uint8_t *)port->fp_sym_node_name, (uint8_t *)
			    (pkt->pkt_cmd + sizeof (fc_ct_header_t) +
			    sizeof (snn) + 1), name_len, DDI_DEV_AUTOINCR);
			mutex_exit(&port->fp_mutex);
		} else {
			ASSERT(node != NULL);
			mutex_enter(&node->fd_mutex);
			FC_SET_CMD(port, pkt->pkt_cmd_acc,
			    (uint8_t *)node->fd_snn,
			    (uint8_t *)(pkt->pkt_cmd + sizeof (fc_ct_header_t) +
			    sizeof (snn) + 1), name_len, DDI_DEV_AUTOINCR);
			mutex_exit(&node->fd_mutex);
		}

		FC_SET_CMD(port, pkt->pkt_cmd_acc, (uint8_t *)&snn,
		    (uint8_t *)(pkt->pkt_cmd + sizeof (fc_ct_header_t)),
		    sizeof (snn), DDI_DEV_AUTOINCR);
		FC_SET_CMD(port, pkt->pkt_cmd_acc, (uint8_t *)&name_len,
		    (uint8_t *)(pkt->pkt_cmd
		    + sizeof (fc_ct_header_t) + sizeof (snn)),
		    1, DDI_DEV_AUTOINCR);

		break;
	}

	case NS_DA_ID: {
		ns_remall_t rall;
		char tmp[4] = {0};
		char *ptr;

		cmd = fp_alloc_pkt(port, sizeof (fc_ct_header_t) +
		    sizeof (ns_remall_t), sizeof (fc_reg_resp_t), sleep, NULL);

		if (cmd == NULL) {
			return (FC_NOMEM);
		}

		fp_ct_init(port, cmd, NULL, cmd_code, NULL, 0, 0, job);
		pkt = &cmd->cmd_pkt;

		ptr = (char *)(&s_id);
		tmp[3] = *ptr++;
		tmp[2] = *ptr++;
		tmp[1] = *ptr++;
		tmp[0] = *ptr;
#if defined(_BIT_FIELDS_LTOH)
		bcopy((caddr_t)tmp, (caddr_t)(&rall.rem_port_id), 4);
#else
		rall.rem_port_id = s_id;
#endif
		FC_SET_CMD(port, pkt->pkt_cmd_acc, (uint8_t *)&rall,
		    (uint8_t *)(pkt->pkt_cmd + sizeof (fc_ct_header_t)),
		    sizeof (rall), DDI_DEV_AUTOINCR);

		break;
	}

	default:
		return (FC_FAILURE);
	}

	rval = fp_sendcmd(port, cmd, port->fp_fca_handle);

	if (rval != FC_SUCCESS) {
		job->job_result = rval;
		fp_iodone(cmd);
	}

	if (polled) {
		ASSERT((job->job_flags & JOB_TYPE_FP_ASYNC) == 0);
		fp_jobwait(job);
	} else {
		rval = FC_SUCCESS;
	}

	return (rval);
}


/*
 * Common interrupt handler
 */
static int
fp_common_intr(fc_packet_t *pkt, int iodone)
{
	int		rval = FC_FAILURE;
	fp_cmd_t	*cmd;
	fc_local_port_t	*port;

	cmd = pkt->pkt_ulp_private;
	port = cmd->cmd_port;

	/*
	 * Fail fast the upper layer requests if
	 * a state change has occurred amidst.
	 */
	mutex_enter(&port->fp_mutex);
	if (cmd->cmd_ulp_pkt != NULL && port->fp_statec_busy) {
		mutex_exit(&port->fp_mutex);
		cmd->cmd_ulp_pkt->pkt_state = FC_PKT_PORT_OFFLINE;
		cmd->cmd_ulp_pkt->pkt_reason = FC_REASON_OFFLINE;
	} else if (!(port->fp_soft_state &
	    (FP_SOFT_IN_DETACH | FP_DETACH_INPROGRESS))) {
		mutex_exit(&port->fp_mutex);

		switch (pkt->pkt_state) {
		case FC_PKT_LOCAL_BSY:
		case FC_PKT_FABRIC_BSY:
		case FC_PKT_NPORT_BSY:
		case FC_PKT_TIMEOUT:
			cmd->cmd_retry_interval = (pkt->pkt_state ==
			    FC_PKT_TIMEOUT) ? 0 : fp_retry_delay;
			rval = fp_retry_cmd(pkt);
			break;

		case FC_PKT_FABRIC_RJT:
		case FC_PKT_NPORT_RJT:
		case FC_PKT_LOCAL_RJT:
		case FC_PKT_LS_RJT:
		case FC_PKT_FS_RJT:
		case FC_PKT_BA_RJT:
			rval = fp_handle_reject(pkt);
			break;

		default:
			if (pkt->pkt_resp_resid) {
				cmd->cmd_retry_interval = 0;
				rval = fp_retry_cmd(pkt);
			}
			break;
		}
	} else {
		mutex_exit(&port->fp_mutex);
	}

	if (rval != FC_SUCCESS && iodone) {
		fp_iodone(cmd);
		rval = FC_SUCCESS;
	}

	return (rval);
}


/*
 * Some not so long winding theory on point to point topology:
 *
 *	In the ACC payload, if the D_ID is ZERO and the common service
 *	parameters indicate N_Port, then the topology is POINT TO POINT.
 *
 *	In a point to point topology with an N_Port, during Fabric Login,
 *	the destination N_Port will check with our WWN and decide if it
 *	needs to issue PLOGI or not. That means, FLOGI could potentially
 *	trigger an unsolicited PLOGI from an N_Port. The Unsolicited
 *	PLOGI creates the device handles.
 *
 *	Assuming that the host port WWN is greater than the other N_Port
 *	WWN, then we become the master (be aware that this isn't the word
 *	used in the FC standards) and initiate the PLOGI.
 *
 */
static void
fp_flogi_intr(fc_packet_t *pkt)
{
	int			state;
	int			f_port;
	uint32_t		s_id;
	uint32_t		d_id;
	fp_cmd_t		*cmd;
	fc_local_port_t		*port;
	la_wwn_t		*swwn;
	la_wwn_t		dwwn;
	la_wwn_t		nwwn;
	fc_remote_port_t	*pd;
	la_els_logi_t		*acc;
	com_svc_t		csp;
	ls_code_t		resp;

	cmd = pkt->pkt_ulp_private;
	port = cmd->cmd_port;

	mutex_enter(&port->fp_mutex);
	port->fp_out_fpcmds--;
	mutex_exit(&port->fp_mutex);

	FP_TRACE(FP_NHEAD1(1, 0), "fp_flogi_intr; port=%p, pkt=%p, state=%x",
	    port, pkt, pkt->pkt_state);

	if (FP_IS_PKT_ERROR(pkt)) {
		(void) fp_common_intr(pkt, 1);
		return;
	}

	/*
	 * Currently, we don't need to swap bytes here because qlc is faking the
	 * response for us and so endianness is getting taken care of. But we
	 * have to fix this and generalize this at some point
	 */
	acc = (la_els_logi_t *)pkt->pkt_resp;

	FC_GET_RSP(port, pkt->pkt_resp_acc, (uint8_t *)&resp, (uint8_t *)acc,
	    sizeof (resp), DDI_DEV_AUTOINCR);

	ASSERT(resp.ls_code == LA_ELS_ACC);
	if (resp.ls_code != LA_ELS_ACC) {
		(void) fp_common_intr(pkt, 1);
		return;
	}

	FC_GET_RSP(port, pkt->pkt_resp_acc, (uint8_t *)&csp,
	    (uint8_t *)&acc->common_service, sizeof (csp), DDI_DEV_AUTOINCR);

	f_port = FP_IS_F_PORT(csp.cmn_features) ? 1 : 0;

	ASSERT(!MUTEX_HELD(&port->fp_mutex));

	mutex_enter(&port->fp_mutex);
	state = FC_PORT_STATE_MASK(port->fp_state);
	mutex_exit(&port->fp_mutex);

	if (f_port == 0) {
		if (state != FC_STATE_LOOP) {
			swwn = &port->fp_service_params.nport_ww_name;

			FC_GET_RSP(port, pkt->pkt_resp_acc, (uint8_t *)&dwwn,
			    (uint8_t *)&acc->nport_ww_name, sizeof (la_wwn_t),
			    DDI_DEV_AUTOINCR);

			FC_GET_RSP(port, pkt->pkt_resp_acc, (uint8_t *)&nwwn,
			    (uint8_t *)&acc->node_ww_name, sizeof (la_wwn_t),
			    DDI_DEV_AUTOINCR);

			mutex_enter(&port->fp_mutex);

			port->fp_topology = FC_TOP_PT_PT;
			port->fp_total_devices = 1;
			if (fctl_wwn_cmp(swwn, &dwwn) >= 0) {
				port->fp_ptpt_master = 1;
				/*
				 * Let us choose 'X' as S_ID and 'Y'
				 * as D_ID and that'll work; hopefully
				 * If not, it will get changed.
				 */
				s_id = port->fp_instance + FP_DEFAULT_SID;
				d_id = port->fp_instance + FP_DEFAULT_DID;
				port->fp_port_id.port_id = s_id;
				mutex_exit(&port->fp_mutex);

				FP_TRACE(FP_NHEAD1(1, 0), "fp_flogi_intr: fp %x"
				    "pd %x", port->fp_port_id.port_id, d_id);
				pd = fctl_create_remote_port(port,
				    &nwwn, &dwwn, d_id, PD_PLOGI_INITIATOR,
				    KM_NOSLEEP);
				if (pd == NULL) {
					fp_printf(port, CE_NOTE, FP_LOG_ONLY,
					    0, NULL, "couldn't create device"
					    " d_id=%X", d_id);
					fp_iodone(cmd);
					return;
				}

				cmd->cmd_pkt.pkt_tran_flags =
				    pkt->pkt_tran_flags;
				cmd->cmd_pkt.pkt_tran_type = pkt->pkt_tran_type;
				cmd->cmd_flags = FP_CMD_PLOGI_RETAIN;
				cmd->cmd_retry_count = fp_retry_count;

				fp_xlogi_init(port, cmd, s_id, d_id,
				    fp_plogi_intr, cmd->cmd_job, LA_ELS_PLOGI);

				(&cmd->cmd_pkt)->pkt_pd = pd;

				/*
				 * We've just created this fc_remote_port_t, and
				 * we're about to use it to send a PLOGI, so
				 * bump the reference count right now.	When
				 * the packet is freed, the reference count will
				 * be decremented.  The ULP may also start using
				 * it, so mark it as given away as well.
				 */
				pd->pd_ref_count++;
				pd->pd_aux_flags |= PD_GIVEN_TO_ULPS;

				if (fp_sendcmd(port, cmd,
				    port->fp_fca_handle) == FC_SUCCESS) {
					return;
				}
			} else {
				/*
				 * The device handles will be created when the
				 * unsolicited PLOGI is completed successfully
				 */
				port->fp_ptpt_master = 0;
				mutex_exit(&port->fp_mutex);
			}
		}
		pkt->pkt_state = FC_PKT_FAILURE;
	} else {
		if (f_port) {
			mutex_enter(&port->fp_mutex);
			if (state == FC_STATE_LOOP) {
				port->fp_topology = FC_TOP_PUBLIC_LOOP;
			} else {
				port->fp_topology = FC_TOP_FABRIC;

				FC_GET_RSP(port, pkt->pkt_resp_acc,
				    (uint8_t *)&port->fp_fabric_name,
				    (uint8_t *)&acc->node_ww_name,
				    sizeof (la_wwn_t),
				    DDI_DEV_AUTOINCR);
			}
			port->fp_port_id.port_id = pkt->pkt_resp_fhdr.d_id;
			mutex_exit(&port->fp_mutex);
		} else {
			pkt->pkt_state = FC_PKT_FAILURE;
		}
	}
	fp_iodone(cmd);
}


/*
 * Handle solicited PLOGI response
 */
static void
fp_plogi_intr(fc_packet_t *pkt)
{
	int			nl_port;
	int			bailout;
	uint32_t		d_id;
	fp_cmd_t		*cmd;
	la_els_logi_t		*acc;
	fc_local_port_t		*port;
	fc_remote_port_t	*pd;
	la_wwn_t		nwwn;
	la_wwn_t		pwwn;
	ls_code_t		resp;

	nl_port = 0;
	cmd = pkt->pkt_ulp_private;
	port = cmd->cmd_port;
	d_id = pkt->pkt_cmd_fhdr.d_id;

#ifndef	__lock_lint
	ASSERT(cmd->cmd_job && cmd->cmd_job->job_counter);
#endif

	FP_TRACE(FP_NHEAD1(3, 0), "fp_plogi_intr: port=%p, job=%p, d_id=%x,"
	    " jcount=%d pkt=%p, state=%x", port, cmd->cmd_job, d_id,
	    cmd->cmd_job->job_counter, pkt, pkt->pkt_state);

	/*
	 * Bail out early on ULP initiated requests if the
	 * state change has occurred
	 */
	mutex_enter(&port->fp_mutex);
	port->fp_out_fpcmds--;
	bailout = ((port->fp_statec_busy ||
	    FC_PORT_STATE_MASK(port->fp_state) == FC_STATE_OFFLINE) &&
	    cmd->cmd_ulp_pkt) ? 1 : 0;
	mutex_exit(&port->fp_mutex);

	if (FP_IS_PKT_ERROR(pkt) || bailout) {
		int skip_msg = 0;
		int giveup = 0;

		if (cmd->cmd_ulp_pkt) {
			cmd->cmd_ulp_pkt->pkt_state = pkt->pkt_state;
			cmd->cmd_ulp_pkt->pkt_reason = pkt->pkt_reason;
			cmd->cmd_ulp_pkt->pkt_action = pkt->pkt_action;
			cmd->cmd_ulp_pkt->pkt_expln = pkt->pkt_expln;
		}

		/*
		 * If an unsolicited cross login already created
		 * a device speed up the discovery by not retrying
		 * the command mindlessly.
		 */
		if (pkt->pkt_pd == NULL &&
		    fctl_get_remote_port_by_did(port, d_id) != NULL) {
			fp_iodone(cmd);
			return;
		}

		if (pkt->pkt_pd != NULL) {
			giveup = (pkt->pkt_pd->pd_recepient ==
			    PD_PLOGI_RECEPIENT) ? 1 : 0;
			if (giveup) {
				/*
				 * This pd is marked as plogi
				 * recipient, stop retrying
				 */
				FP_TRACE(FP_NHEAD1(3, 0),
				    "fp_plogi_intr: stop retry as"
				    " a cross login was accepted"
				    " from d_id=%x, port=%p.",
				    d_id, port);
				fp_iodone(cmd);
				return;
			}
		}

		if (fp_common_intr(pkt, 0) == FC_SUCCESS) {
			return;
		}

		if ((pd = fctl_get_remote_port_by_did(port, d_id)) != NULL) {
			mutex_enter(&pd->pd_mutex);
			if (pd->pd_state == PORT_DEVICE_LOGGED_IN) {
				skip_msg++;
			}
			mutex_exit(&pd->pd_mutex);
		}

		mutex_enter(&port->fp_mutex);
		if (!bailout && !(skip_msg && port->fp_statec_busy) &&
		    port->fp_statec_busy <= 1 &&
		    pkt->pkt_reason != FC_REASON_FCAL_OPN_FAIL) {
			mutex_exit(&port->fp_mutex);
			/*
			 * In case of Login Collisions, JNI HBAs returns the
			 * FC pkt back to the Initiator with the state set to
			 * FC_PKT_LS_RJT and reason to FC_REASON_LOGICAL_ERROR.
			 * QLC HBAs handles such cases in the FW and doesnot
			 * return the LS_RJT with Logical error when
			 * login collision happens.
			 */
			if ((pkt->pkt_state != FC_PKT_LS_RJT) ||
			    (pkt->pkt_reason != FC_REASON_LOGICAL_ERROR)) {
				fp_printf(port, CE_NOTE, FP_LOG_ONLY, 0, pkt,
				    "PLOGI to %x failed", d_id);
			}
			FP_TRACE(FP_NHEAD2(9, 0),
			    "PLOGI to %x failed. state=%x reason=%x.",
			    d_id, pkt->pkt_state, pkt->pkt_reason);
		} else {
			mutex_exit(&port->fp_mutex);
		}

		fp_iodone(cmd);
		return;
	}

	acc = (la_els_logi_t *)pkt->pkt_resp;

	FC_GET_RSP(port, pkt->pkt_resp_acc, (uint8_t *)&resp, (uint8_t *)acc,
	    sizeof (resp), DDI_DEV_AUTOINCR);

	ASSERT(resp.ls_code == LA_ELS_ACC);
	if (resp.ls_code != LA_ELS_ACC) {
		(void) fp_common_intr(pkt, 1);
		return;
	}

	if (d_id == FS_NAME_SERVER || d_id == FS_FABRIC_CONTROLLER) {
		mutex_enter(&port->fp_mutex);
		port->fp_ns_login_class = FC_TRAN_CLASS(pkt->pkt_tran_flags);
		mutex_exit(&port->fp_mutex);
		fp_iodone(cmd);
		return;
	}

	ASSERT(acc == (la_els_logi_t *)pkt->pkt_resp);

	FC_GET_RSP(port, pkt->pkt_resp_acc, (uint8_t *)&pwwn,
	    (uint8_t *)&acc->nport_ww_name, sizeof (la_wwn_t),
	    DDI_DEV_AUTOINCR);

	FC_GET_RSP(port, pkt->pkt_resp_acc, (uint8_t *)&nwwn,
	    (uint8_t *)&acc->node_ww_name, sizeof (la_wwn_t),
	    DDI_DEV_AUTOINCR);

	ASSERT(fctl_is_wwn_zero(&pwwn) == FC_FAILURE);
	ASSERT(fctl_is_wwn_zero(&nwwn) == FC_FAILURE);

	if ((pd = pkt->pkt_pd) == NULL) {
		pd = fctl_get_remote_port_by_pwwn(port, &pwwn);
		if (pd == NULL) {
			FP_TRACE(FP_NHEAD2(1, 0), "fp_plogi_intr: fp %x pd %x",
			    port->fp_port_id.port_id, d_id);
			pd = fctl_create_remote_port(port, &nwwn, &pwwn, d_id,
			    PD_PLOGI_INITIATOR, KM_NOSLEEP);
			if (pd == NULL) {
				fp_printf(port, CE_NOTE, FP_LOG_ONLY, 0, NULL,
				    "couldn't create port device handles"
				    " d_id=%x", d_id);
				fp_iodone(cmd);
				return;
			}
		} else {
			fc_remote_port_t *tmp_pd;

			tmp_pd = fctl_get_remote_port_by_did(port, d_id);
			if (tmp_pd != NULL) {
				fp_iodone(cmd);
				return;
			}

			mutex_enter(&port->fp_mutex);
			mutex_enter(&pd->pd_mutex);
			if ((pd->pd_state == PORT_DEVICE_LOGGED_IN) ||
			    (pd->pd_aux_flags & PD_LOGGED_OUT)) {
				cmd->cmd_flags |= FP_CMD_PLOGI_RETAIN;
			}

			if (pd->pd_type == PORT_DEVICE_OLD) {
				if (pd->pd_port_id.port_id != d_id) {
					fctl_delist_did_table(port, pd);
					pd->pd_type = PORT_DEVICE_CHANGED;
					pd->pd_port_id.port_id = d_id;
				} else {
					pd->pd_type = PORT_DEVICE_NOCHANGE;
				}
			}

			if (pd->pd_aux_flags & PD_IN_DID_QUEUE) {
				char ww_name[17];

				fc_wwn_to_str(&pd->pd_port_name, ww_name);

				mutex_exit(&pd->pd_mutex);
				mutex_exit(&port->fp_mutex);
				FP_TRACE(FP_NHEAD2(9, 0),
				    "Possible Duplicate name or address"
				    " identifiers in the PLOGI response"
				    " D_ID=%x, PWWN=%s: Please check the"
				    " configuration", d_id, ww_name);
				fp_iodone(cmd);
				return;
			}
			fctl_enlist_did_table(port, pd);
			pd->pd_aux_flags &= ~PD_LOGGED_OUT;
			mutex_exit(&pd->pd_mutex);
			mutex_exit(&port->fp_mutex);
		}
	} else {
		fc_remote_port_t *tmp_pd, *new_wwn_pd;

		tmp_pd = fctl_get_remote_port_by_did(port, d_id);
		new_wwn_pd = fctl_get_remote_port_by_pwwn(port, &pwwn);

		mutex_enter(&port->fp_mutex);
		mutex_enter(&pd->pd_mutex);
		if (fctl_wwn_cmp(&pd->pd_port_name, &pwwn) == 0) {
			FP_TRACE(FP_NHEAD1(3, 0), "fp_plogi_intr: d_id=%x,"
			    " pd_state=%x pd_type=%x", d_id, pd->pd_state,
			    pd->pd_type);
			if ((pd->pd_state == PORT_DEVICE_LOGGED_IN &&
			    pd->pd_type == PORT_DEVICE_OLD) ||
			    (pd->pd_aux_flags & PD_LOGGED_OUT)) {
				pd->pd_type = PORT_DEVICE_NOCHANGE;
			} else if (pd->pd_state != PORT_DEVICE_LOGGED_IN) {
				pd->pd_type = PORT_DEVICE_NEW;
			}
		} else {
			char	old_name[17];
			char	new_name[17];

			fc_wwn_to_str(&pd->pd_port_name, old_name);
			fc_wwn_to_str(&pwwn, new_name);

			FP_TRACE(FP_NHEAD1(9, 0),
			    "fp_plogi_intr: PWWN of a device with D_ID=%x "
			    "changed. New PWWN = %s, OLD PWWN = %s ; tmp_pd:%p "
			    "pd:%p new_wwn_pd:%p, cmd_ulp_pkt:%p, bailout:0x%x",
			    d_id, new_name, old_name, tmp_pd, pd, new_wwn_pd,
			    cmd->cmd_ulp_pkt, bailout);

			FP_TRACE(FP_NHEAD2(9, 0),
			    "PWWN of a device with D_ID=%x changed."
			    " New PWWN = %s, OLD PWWN = %s", d_id,
			    new_name, old_name);

			if (cmd->cmd_ulp_pkt && !bailout) {
				fc_remote_node_t	*rnodep;
				fc_portmap_t	*changelist;
				fc_portmap_t	*listptr;
				int		len = 1;
				/* # entries in changelist */

				fctl_delist_pwwn_table(port, pd);

				/*
				 * Lets now check if there already is a pd with
				 * this new WWN in the table. If so, we'll mark
				 * it as invalid
				 */

				if (new_wwn_pd) {
					/*
					 * There is another pd with in the pwwn
					 * table with the same WWN that we got
					 * in the PLOGI payload. We have to get
					 * it out of the pwwn table, update the
					 * pd's state (fp_fillout_old_map does
					 * this for us) and add it to the
					 * changelist that goes up to ULPs.
					 *
					 * len is length of changelist and so
					 * increment it.
					 */
					len++;

					if (tmp_pd != pd) {
						/*
						 * Odd case where pwwn and did
						 * tables are out of sync but
						 * we will handle that too. See
						 * more comments below.
						 *
						 * One more device that ULPs
						 * should know about and so len
						 * gets incremented again.
						 */
						len++;
					}

					listptr = changelist = kmem_zalloc(len *
					    sizeof (*changelist), KM_SLEEP);

					mutex_enter(&new_wwn_pd->pd_mutex);
					rnodep = new_wwn_pd->pd_remote_nodep;
					mutex_exit(&new_wwn_pd->pd_mutex);

					/*
					 * Hold the fd_mutex since
					 * fctl_copy_portmap_held expects it.
					 * Preserve lock hierarchy by grabbing
					 * fd_mutex before pd_mutex
					 */
					if (rnodep) {
						mutex_enter(&rnodep->fd_mutex);
					}
					mutex_enter(&new_wwn_pd->pd_mutex);
					fp_fillout_old_map_held(listptr++,
					    new_wwn_pd, 0);
					mutex_exit(&new_wwn_pd->pd_mutex);
					if (rnodep) {
						mutex_exit(&rnodep->fd_mutex);
					}

					/*
					 * Safety check :
					 * Lets ensure that the pwwn and did
					 * tables are in sync. Ideally, we
					 * should not find that these two pd's
					 * are different.
					 */
					if (tmp_pd != pd) {
						mutex_enter(&tmp_pd->pd_mutex);
						rnodep =
						    tmp_pd->pd_remote_nodep;
						mutex_exit(&tmp_pd->pd_mutex);

						/* As above grab fd_mutex */
						if (rnodep) {
							mutex_enter(&rnodep->
							    fd_mutex);
						}
						mutex_enter(&tmp_pd->pd_mutex);

						fp_fillout_old_map_held(
						    listptr++, tmp_pd, 0);

						mutex_exit(&tmp_pd->pd_mutex);
						if (rnodep) {
							mutex_exit(&rnodep->
							    fd_mutex);
						}

						/*
						 * Now add "pd" (not tmp_pd)
						 * to fp_did_table to sync it up
						 * with fp_pwwn_table
						 *
						 * pd->pd_mutex is already held
						 * at this point
						 */
						fctl_enlist_did_table(port, pd);
					}
				} else {
					listptr = changelist = kmem_zalloc(
					    sizeof (*changelist), KM_SLEEP);
				}

				ASSERT(changelist != NULL);

				fp_fillout_changed_map(listptr, pd, &d_id,
				    &pwwn);
				fctl_enlist_pwwn_table(port, pd);

				mutex_exit(&pd->pd_mutex);
				mutex_exit(&port->fp_mutex);

				fp_iodone(cmd);

				(void) fp_ulp_devc_cb(port, changelist, len,
				    len, KM_NOSLEEP, 0);

				return;
			}
		}

		if (pd->pd_porttype.port_type == FC_NS_PORT_NL) {
			nl_port = 1;
		}
		if (pd->pd_aux_flags & PD_DISABLE_RELOGIN) {
			pd->pd_aux_flags &= ~PD_LOGGED_OUT;
		}

		mutex_exit(&pd->pd_mutex);
		mutex_exit(&port->fp_mutex);

		if (tmp_pd == NULL) {
			mutex_enter(&port->fp_mutex);
			mutex_enter(&pd->pd_mutex);
			if (pd->pd_aux_flags & PD_IN_DID_QUEUE) {
				char ww_name[17];

				fc_wwn_to_str(&pd->pd_port_name, ww_name);
				mutex_exit(&pd->pd_mutex);
				mutex_exit(&port->fp_mutex);
				FP_TRACE(FP_NHEAD2(9, 0),
				    "Possible Duplicate name or address"
				    " identifiers in the PLOGI response"
				    " D_ID=%x, PWWN=%s: Please check the"
				    " configuration", d_id, ww_name);
				fp_iodone(cmd);
				return;
			}
			fctl_enlist_did_table(port, pd);
			pd->pd_aux_flags &= ~PD_LOGGED_OUT;
			mutex_exit(&pd->pd_mutex);
			mutex_exit(&port->fp_mutex);
		}
	}
	fp_register_login(&pkt->pkt_resp_acc, pd, acc,
	    FC_TRAN_CLASS(pkt->pkt_tran_flags));

	if (cmd->cmd_ulp_pkt) {
		cmd->cmd_ulp_pkt->pkt_state = pkt->pkt_state;
		cmd->cmd_ulp_pkt->pkt_action = pkt->pkt_action;
		cmd->cmd_ulp_pkt->pkt_expln = pkt->pkt_expln;
		if (cmd->cmd_ulp_pkt->pkt_pd == NULL) {
			if (pd != NULL) {
				FP_TRACE(FP_NHEAD1(9, 0),
				    "fp_plogi_intr;"
				    "ulp_pkt's pd is NULL, get a pd %p",
				    pd);
				mutex_enter(&pd->pd_mutex);
				pd->pd_ref_count++;
				mutex_exit(&pd->pd_mutex);
			}
			cmd->cmd_ulp_pkt->pkt_pd = pd;
		}
		bcopy((caddr_t)&pkt->pkt_resp_fhdr,
		    (caddr_t)&cmd->cmd_ulp_pkt->pkt_resp_fhdr,
		    sizeof (fc_frame_hdr_t));
		bcopy((caddr_t)pkt->pkt_resp,
		    (caddr_t)cmd->cmd_ulp_pkt->pkt_resp,
		    sizeof (la_els_logi_t));
	}

	mutex_enter(&port->fp_mutex);
	if (port->fp_topology == FC_TOP_PRIVATE_LOOP || nl_port) {
		mutex_enter(&pd->pd_mutex);

		cmd->cmd_pkt.pkt_tran_flags = FC_TRAN_INTR | pd->pd_login_class;
		cmd->cmd_pkt.pkt_tran_type = FC_PKT_EXCHANGE;
		cmd->cmd_retry_count = fp_retry_count;

		/*
		 * If the fc_remote_port_t pointer is not set in the given
		 * fc_packet_t, then this fc_remote_port_t must have just
		 * been created.  Save the pointer and also increment the
		 * fc_remote_port_t reference count.
		 */
		if (pkt->pkt_pd == NULL) {
			pkt->pkt_pd = pd;
			pd->pd_ref_count++;	/* It's in use! */
		}

		fp_adisc_init(cmd, cmd->cmd_job);

		pkt->pkt_cmdlen = sizeof (la_els_adisc_t);
		pkt->pkt_rsplen = sizeof (la_els_adisc_t);

		mutex_exit(&pd->pd_mutex);
		mutex_exit(&port->fp_mutex);

		if (fp_sendcmd(port, cmd, port->fp_fca_handle) == FC_SUCCESS) {
			return;
		}
	} else {
		mutex_exit(&port->fp_mutex);
	}

	if ((cmd->cmd_flags & FP_CMD_PLOGI_RETAIN) == 0) {
		mutex_enter(&port->fp_mutex);
		mutex_enter(&pd->pd_mutex);

		cmd->cmd_pkt.pkt_tran_flags = FC_TRAN_INTR | pd->pd_login_class;
		cmd->cmd_pkt.pkt_tran_type = FC_PKT_EXCHANGE;
		cmd->cmd_retry_count = fp_retry_count;

		fp_logo_init(pd, cmd, cmd->cmd_job);

		pkt->pkt_cmdlen = sizeof (la_els_logo_t);
		pkt->pkt_rsplen = FP_PORT_IDENTIFIER_LEN;

		mutex_exit(&pd->pd_mutex);
		mutex_exit(&port->fp_mutex);

		if (fp_sendcmd(port, cmd, port->fp_fca_handle) == FC_SUCCESS) {
			return;
		}

	}
	fp_iodone(cmd);
}


/*
 * Handle solicited ADISC response
 */
static void
fp_adisc_intr(fc_packet_t *pkt)
{
	int			rval;
	int			bailout;
	fp_cmd_t		*cmd, *logi_cmd;
	fc_local_port_t		*port;
	fc_remote_port_t	*pd;
	la_els_adisc_t		*acc;
	ls_code_t		resp;
	fc_hardaddr_t		ha;
	fc_portmap_t		*changelist;
	int			initiator, adiscfail = 0;

	pd = pkt->pkt_pd;
	cmd = pkt->pkt_ulp_private;
	port = cmd->cmd_port;

#ifndef	__lock_lint
	ASSERT(cmd->cmd_job && cmd->cmd_job->job_counter);
#endif

	ASSERT(pd != NULL && port != NULL && cmd != NULL);

	mutex_enter(&port->fp_mutex);
	port->fp_out_fpcmds--;
	bailout = ((port->fp_statec_busy ||
	    FC_PORT_STATE_MASK(port->fp_state) == FC_STATE_OFFLINE) &&
	    cmd->cmd_ulp_pkt) ? 1 : 0;
	mutex_exit(&port->fp_mutex);

	if (bailout) {
		fp_iodone(cmd);
		return;
	}

	if (pkt->pkt_state == FC_PKT_SUCCESS && pkt->pkt_resp_resid == 0) {
		acc = (la_els_adisc_t *)pkt->pkt_resp;

		FC_GET_RSP(port, pkt->pkt_resp_acc, (uint8_t *)&resp,
		    (uint8_t *)acc, sizeof (resp), DDI_DEV_AUTOINCR);

		if (resp.ls_code == LA_ELS_ACC) {
			int	is_private;

			FC_GET_RSP(port, pkt->pkt_resp_acc, (uint8_t *)&ha,
			    (uint8_t *)&acc->hard_addr, sizeof (ha),
			    DDI_DEV_AUTOINCR);

			mutex_enter(&port->fp_mutex);

			is_private =
			    (port->fp_topology == FC_TOP_PRIVATE_LOOP) ? 1 : 0;

			mutex_enter(&pd->pd_mutex);
			if ((pd->pd_aux_flags & PD_IN_DID_QUEUE) == 0) {
				fctl_enlist_did_table(port, pd);
			}
			mutex_exit(&pd->pd_mutex);

			mutex_exit(&port->fp_mutex);

			mutex_enter(&pd->pd_mutex);
			if (pd->pd_type != PORT_DEVICE_NEW) {
				if (is_private && (pd->pd_hard_addr.hard_addr !=
				    ha.hard_addr)) {
					pd->pd_type = PORT_DEVICE_CHANGED;
				} else {
					pd->pd_type = PORT_DEVICE_NOCHANGE;
				}
			}

			if (is_private && (ha.hard_addr &&
			    pd->pd_port_id.port_id != ha.hard_addr)) {
				char ww_name[17];

				fc_wwn_to_str(&pd->pd_port_name, ww_name);

				fp_printf(port, CE_NOTE, FP_LOG_ONLY, 0, NULL,
				    "NL_Port Identifier %x doesn't match"
				    " with Hard Address %x, Will use Port"
				    " WWN %s", pd->pd_port_id.port_id,
				    ha.hard_addr, ww_name);

				pd->pd_hard_addr.hard_addr = 0;
			} else {
				pd->pd_hard_addr.hard_addr = ha.hard_addr;
			}
			mutex_exit(&pd->pd_mutex);
		} else {
			if (fp_common_intr(pkt, 0) == FC_SUCCESS) {
				return;
			}
		}
	} else {
		if (fp_common_intr(pkt, 0) == FC_SUCCESS) {
			return;
		}

		mutex_enter(&port->fp_mutex);
		if (port->fp_statec_busy <= 1) {
			mutex_exit(&port->fp_mutex);
			if (pkt->pkt_state == FC_PKT_LS_RJT &&
			    pkt->pkt_reason == FC_REASON_CMD_UNABLE) {
				uchar_t class;
				int cmd_flag;
				uint32_t src_id;

				class = fp_get_nextclass(port,
				    FC_TRAN_CLASS_INVALID);
				if (class == FC_TRAN_CLASS_INVALID) {
					fp_iodone(cmd);
					return;
				}

				FP_TRACE(FP_NHEAD1(1, 0), "ADISC re-login; "
				    "fp_state=0x%x, pkt_state=0x%x, "
				    "reason=0x%x, class=0x%x",
				    port->fp_state, pkt->pkt_state,
				    pkt->pkt_reason, class);
				cmd_flag = FP_CMD_PLOGI_RETAIN;

				logi_cmd = fp_alloc_pkt(port,
				    sizeof (la_els_logi_t),
				    sizeof (la_els_logi_t), KM_SLEEP, pd);
				if (logi_cmd == NULL) {
					fp_iodone(cmd);
					return;
				}

				logi_cmd->cmd_pkt.pkt_tran_flags =
				    FC_TRAN_INTR | class;
				logi_cmd->cmd_pkt.pkt_tran_type =
				    FC_PKT_EXCHANGE;
				logi_cmd->cmd_flags = cmd_flag;
				logi_cmd->cmd_retry_count = fp_retry_count;
				logi_cmd->cmd_ulp_pkt = NULL;

				mutex_enter(&port->fp_mutex);
				src_id = port->fp_port_id.port_id;
				mutex_exit(&port->fp_mutex);

				fp_xlogi_init(port, logi_cmd, src_id,
				    pkt->pkt_cmd_fhdr.d_id, fp_plogi_intr,
				    cmd->cmd_job, LA_ELS_PLOGI);
				if (pd) {
					mutex_enter(&pd->pd_mutex);
					pd->pd_flags = PD_ELS_IN_PROGRESS;
					mutex_exit(&pd->pd_mutex);
				}

				if (fp_sendcmd(port, logi_cmd,
				    port->fp_fca_handle) == FC_SUCCESS) {
					fp_free_pkt(cmd);
					return;
				} else {
					fp_free_pkt(logi_cmd);
				}
			} else {
				fp_printf(port, CE_NOTE, FP_LOG_ONLY, 0, pkt,
				    "ADISC to %x failed, cmd_flags=%x",
				    pkt->pkt_cmd_fhdr.d_id, cmd->cmd_flags);
				cmd->cmd_flags &= ~FP_CMD_PLOGI_RETAIN;
				adiscfail = 1;
			}
		} else {
			mutex_exit(&port->fp_mutex);
		}
	}

	if (cmd->cmd_ulp_pkt) {
		cmd->cmd_ulp_pkt->pkt_state = pkt->pkt_state;
		cmd->cmd_ulp_pkt->pkt_action = pkt->pkt_action;
		cmd->cmd_ulp_pkt->pkt_expln = pkt->pkt_expln;
		if (cmd->cmd_ulp_pkt->pkt_pd == NULL) {
			cmd->cmd_ulp_pkt->pkt_pd = pd;
			FP_TRACE(FP_NHEAD1(9, 0),
			    "fp_adisc__intr;"
			    "ulp_pkt's pd is NULL, get a pd %p",
			    pd);

		}
		bcopy((caddr_t)&pkt->pkt_resp_fhdr,
		    (caddr_t)&cmd->cmd_ulp_pkt->pkt_resp_fhdr,
		    sizeof (fc_frame_hdr_t));
		bcopy((caddr_t)pkt->pkt_resp,
		    (caddr_t)cmd->cmd_ulp_pkt->pkt_resp,
		    sizeof (la_els_adisc_t));
	}

	if ((cmd->cmd_flags & FP_CMD_PLOGI_RETAIN) == 0) {
		FP_TRACE(FP_NHEAD1(9, 0),
		    "fp_adisc_intr: Perform LOGO.cmd_flags=%x, "
		    "fp_retry_count=%x, ulp_pkt=%p",
		    cmd->cmd_flags, fp_retry_count, cmd->cmd_ulp_pkt);

		mutex_enter(&port->fp_mutex);
		mutex_enter(&pd->pd_mutex);

		cmd->cmd_pkt.pkt_tran_flags = FC_TRAN_INTR | pd->pd_login_class;
		cmd->cmd_pkt.pkt_tran_type = FC_PKT_EXCHANGE;
		cmd->cmd_retry_count = fp_retry_count;

		fp_logo_init(pd, cmd, cmd->cmd_job);

		pkt->pkt_cmdlen = sizeof (la_els_logo_t);
		pkt->pkt_rsplen = FP_PORT_IDENTIFIER_LEN;

		mutex_exit(&pd->pd_mutex);
		mutex_exit(&port->fp_mutex);

		rval = fp_sendcmd(port, cmd, port->fp_fca_handle);
		if (adiscfail) {
			mutex_enter(&pd->pd_mutex);
			initiator =
			    ((pd->pd_recepient == PD_PLOGI_INITIATOR) ? 1 : 0);
			pd->pd_state = PORT_DEVICE_VALID;
			pd->pd_aux_flags |= PD_LOGGED_OUT;
			if (pd->pd_aux_flags & PD_DISABLE_RELOGIN) {
				pd->pd_type = PORT_DEVICE_NEW;
			} else {
				pd->pd_type = PORT_DEVICE_NOCHANGE;
			}
			mutex_exit(&pd->pd_mutex);

			changelist =
			    kmem_zalloc(sizeof (*changelist), KM_SLEEP);

			if (initiator) {
				fp_unregister_login(pd);
				fctl_copy_portmap(changelist, pd);
			} else {
				fp_fillout_old_map(changelist, pd, 0);
			}

			FP_TRACE(FP_NHEAD1(9, 0),
			    "fp_adisc_intr: Dev change notification "
			    "to ULP port=%p, pd=%p, map_type=%x map_state=%x "
			    "map_flags=%x initiator=%d", port, pd,
			    changelist->map_type, changelist->map_state,
			    changelist->map_flags, initiator);

			(void) fp_ulp_devc_cb(port, changelist,
			    1, 1, KM_SLEEP, 0);
		}
		if (rval == FC_SUCCESS) {
			return;
		}
	}
	fp_iodone(cmd);
}


/*
 * Handle solicited LOGO response
 */
static void
fp_logo_intr(fc_packet_t *pkt)
{
	ls_code_t	resp;
	fc_local_port_t *port = ((fp_cmd_t *)pkt->pkt_ulp_private)->cmd_port;

	mutex_enter(&((fp_cmd_t *)pkt->pkt_ulp_private)->cmd_port->fp_mutex);
	((fp_cmd_t *)pkt->pkt_ulp_private)->cmd_port->fp_out_fpcmds--;
	mutex_exit(&((fp_cmd_t *)pkt->pkt_ulp_private)->cmd_port->fp_mutex);

	FC_GET_RSP(port, pkt->pkt_resp_acc, (uint8_t *)&resp,
	    (uint8_t *)pkt->pkt_resp, sizeof (resp), DDI_DEV_AUTOINCR);

	if (FP_IS_PKT_ERROR(pkt)) {
		(void) fp_common_intr(pkt, 1);
		return;
	}

	ASSERT(resp.ls_code == LA_ELS_ACC);
	if (resp.ls_code != LA_ELS_ACC) {
		(void) fp_common_intr(pkt, 1);
		return;
	}

	if (pkt->pkt_pd != NULL) {
		fp_unregister_login(pkt->pkt_pd);
	}

	fp_iodone(pkt->pkt_ulp_private);
}


/*
 * Handle solicited RNID response
 */
static void
fp_rnid_intr(fc_packet_t *pkt)
{
	ls_code_t		resp;
	job_request_t		*job;
	fp_cmd_t		*cmd;
	la_els_rnid_acc_t	*acc;
	fc_local_port_t *port = ((fp_cmd_t *)pkt->pkt_ulp_private)->cmd_port;

	FC_GET_RSP(port, pkt->pkt_resp_acc, (uint8_t *)&resp,
	    (uint8_t *)pkt->pkt_resp, sizeof (resp), DDI_DEV_AUTOINCR);
	cmd = pkt->pkt_ulp_private;

	mutex_enter(&cmd->cmd_port->fp_mutex);
	cmd->cmd_port->fp_out_fpcmds--;
	mutex_exit(&cmd->cmd_port->fp_mutex);

	job = cmd->cmd_job;
	ASSERT(job->job_private != NULL);

	/* If failure or LS_RJT then retry the packet, if needed */
	if (pkt->pkt_state != FC_PKT_SUCCESS || resp.ls_code != LA_ELS_ACC) {
		(void) fp_common_intr(pkt, 1);
		return;
	}

	/* Save node_id memory allocated in ioctl code */
	acc = (la_els_rnid_acc_t *)pkt->pkt_resp;

	FC_GET_RSP(port, pkt->pkt_resp_acc, (uint8_t *)job->job_private,
	    (uint8_t *)acc, sizeof (la_els_rnid_acc_t), DDI_DEV_AUTOINCR);

	/* wakeup the ioctl thread and free the pkt */
	fp_iodone(cmd);
}


/*
 * Handle solicited RLS response
 */
static void
fp_rls_intr(fc_packet_t *pkt)
{
	ls_code_t		resp;
	job_request_t		*job;
	fp_cmd_t		*cmd;
	la_els_rls_acc_t	*acc;
	fc_local_port_t *port = ((fp_cmd_t *)pkt->pkt_ulp_private)->cmd_port;

	FC_GET_RSP(port, pkt->pkt_resp_acc, (uint8_t *)&resp,
	    (uint8_t *)pkt->pkt_resp, sizeof (resp), DDI_DEV_AUTOINCR);
	cmd = pkt->pkt_ulp_private;

	mutex_enter(&cmd->cmd_port->fp_mutex);
	cmd->cmd_port->fp_out_fpcmds--;
	mutex_exit(&cmd->cmd_port->fp_mutex);

	job = cmd->cmd_job;
	ASSERT(job->job_private != NULL);

	/* If failure or LS_RJT then retry the packet, if needed */
	if (FP_IS_PKT_ERROR(pkt) || resp.ls_code != LA_ELS_ACC) {
		(void) fp_common_intr(pkt, 1);
		return;
	}

	/* Save link error status block in memory allocated in ioctl code */
	acc = (la_els_rls_acc_t *)pkt->pkt_resp;

	FC_GET_RSP(port, pkt->pkt_resp_acc, (uint8_t *)job->job_private,
	    (uint8_t *)&acc->rls_link_params, sizeof (fc_rls_acc_t),
	    DDI_DEV_AUTOINCR);

	/* wakeup the ioctl thread and free the pkt */
	fp_iodone(cmd);
}


/*
 * A solicited command completion interrupt (mostly for commands
 * that require almost no post processing such as SCR ELS)
 */
static void
fp_intr(fc_packet_t *pkt)
{
	mutex_enter(&((fp_cmd_t *)pkt->pkt_ulp_private)->cmd_port->fp_mutex);
	((fp_cmd_t *)pkt->pkt_ulp_private)->cmd_port->fp_out_fpcmds--;
	mutex_exit(&((fp_cmd_t *)pkt->pkt_ulp_private)->cmd_port->fp_mutex);

	if (FP_IS_PKT_ERROR(pkt)) {
		(void) fp_common_intr(pkt, 1);
		return;
	}
	fp_iodone(pkt->pkt_ulp_private);
}


/*
 * Handle the underlying port's state change
 */
static void
fp_statec_cb(opaque_t port_handle, uint32_t state)
{
	fc_local_port_t *port = port_handle;
	job_request_t	*job;

	/*
	 * If it is not possible to process the callbacks
	 * just drop the callback on the floor; Don't bother
	 * to do something that isn't safe at this time
	 */
	mutex_enter(&port->fp_mutex);
	if ((port->fp_soft_state &
	    (FP_SOFT_IN_DETACH | FP_SOFT_SUSPEND | FP_SOFT_POWER_DOWN)) ||
	    (FC_PORT_STATE_MASK(port->fp_state) == FC_PORT_STATE_MASK(state))) {
		mutex_exit(&port->fp_mutex);
		return;
	}

	if (port->fp_statec_busy == 0) {
		port->fp_soft_state |= FP_SOFT_IN_STATEC_CB;
#ifdef	DEBUG
	} else {
		ASSERT(port->fp_soft_state & FP_SOFT_IN_STATEC_CB);
#endif
	}

	port->fp_statec_busy++;

	/*
	 * For now, force the trusted method of device authentication (by
	 * PLOGI) when LIPs do not involve OFFLINE to ONLINE transition.
	 */
	if (FC_PORT_STATE_MASK(state) == FC_STATE_LIP ||
	    FC_PORT_STATE_MASK(state) == FC_STATE_LIP_LBIT_SET) {
		state = FC_PORT_SPEED_MASK(port->fp_state) | FC_STATE_LOOP;
		fp_port_offline(port, 0);
	}
	mutex_exit(&port->fp_mutex);

	switch (FC_PORT_STATE_MASK(state)) {
	case FC_STATE_OFFLINE:
		job = fctl_alloc_job(JOB_PORT_OFFLINE,
		    JOB_TYPE_FCTL_ASYNC, NULL, NULL, KM_NOSLEEP);
		if (job == NULL) {
			fp_printf(port, CE_NOTE, FP_LOG_ONLY, 0, NULL,
			    " fp_statec_cb() couldn't submit a job "
			    " to the thread: failing..");
			mutex_enter(&port->fp_mutex);
			if (--port->fp_statec_busy == 0) {
				port->fp_soft_state &= ~FP_SOFT_IN_STATEC_CB;
			}
			mutex_exit(&port->fp_mutex);
			return;
		}
		mutex_enter(&port->fp_mutex);
		/*
		 * Zero out this field so that we do not retain
		 * the fabric name as its no longer valid
		 */
		bzero(&port->fp_fabric_name, sizeof (la_wwn_t));
		port->fp_state = state;
		mutex_exit(&port->fp_mutex);

		fctl_enque_job(port, job);
		break;

	case FC_STATE_ONLINE:
	case FC_STATE_LOOP:
		mutex_enter(&port->fp_mutex);
		port->fp_state = state;

		if (port->fp_offline_tid) {
			timeout_id_t tid;

			tid = port->fp_offline_tid;
			port->fp_offline_tid = NULL;
			mutex_exit(&port->fp_mutex);
			(void) untimeout(tid);
		} else {
			mutex_exit(&port->fp_mutex);
		}

		job = fctl_alloc_job(JOB_PORT_ONLINE,
		    JOB_TYPE_FCTL_ASYNC, NULL, NULL, KM_NOSLEEP);
		if (job == NULL) {
			fp_printf(port, CE_NOTE, FP_LOG_ONLY, 0, NULL,
			    "fp_statec_cb() couldn't submit a job "
			    "to the thread: failing..");

			mutex_enter(&port->fp_mutex);
			if (--port->fp_statec_busy == 0) {
				port->fp_soft_state &= ~FP_SOFT_IN_STATEC_CB;
			}
			mutex_exit(&port->fp_mutex);
			return;
		}
		fctl_enque_job(port, job);
		break;

	case FC_STATE_RESET_REQUESTED:
		mutex_enter(&port->fp_mutex);
		port->fp_state = FC_STATE_OFFLINE;
		port->fp_soft_state |= FP_SOFT_IN_FCA_RESET;
		mutex_exit(&port->fp_mutex);
		/* FALLTHROUGH */

	case FC_STATE_RESET:
		job = fctl_alloc_job(JOB_ULP_NOTIFY,
		    JOB_TYPE_FCTL_ASYNC, NULL, NULL, KM_NOSLEEP);
		if (job == NULL) {
			fp_printf(port, CE_NOTE, FP_LOG_ONLY, 0, NULL,
			    "fp_statec_cb() couldn't submit a job"
			    " to the thread: failing..");

			mutex_enter(&port->fp_mutex);
			if (--port->fp_statec_busy == 0) {
				port->fp_soft_state &= ~FP_SOFT_IN_STATEC_CB;
			}
			mutex_exit(&port->fp_mutex);
			return;
		}

		/* squeeze into some field in the job structure */
		job->job_ulp_listlen = FC_PORT_STATE_MASK(state);
		fctl_enque_job(port, job);
		break;

	case FC_STATE_TARGET_PORT_RESET:
		(void) fp_ulp_notify(port, state, KM_NOSLEEP);
		/* FALLTHROUGH */

	case FC_STATE_NAMESERVICE:
		/* FALLTHROUGH */

	default:
		mutex_enter(&port->fp_mutex);
		if (--port->fp_statec_busy == 0) {
			port->fp_soft_state &= ~FP_SOFT_IN_STATEC_CB;
		}
		mutex_exit(&port->fp_mutex);
		break;
	}
}


/*
 * Register with the Name Server for RSCNs
 */
static int
fp_ns_scr(fc_local_port_t *port, job_request_t *job, uchar_t scr_func,
    int sleep)
{
	uint32_t	s_id;
	uchar_t		class;
	fc_scr_req_t	payload;
	fp_cmd_t	*cmd;
	fc_packet_t	*pkt;

	mutex_enter(&port->fp_mutex);
	s_id = port->fp_port_id.port_id;
	class = port->fp_ns_login_class;
	mutex_exit(&port->fp_mutex);

	cmd = fp_alloc_pkt(port, sizeof (fc_scr_req_t),
	    sizeof (fc_scr_resp_t), sleep, NULL);
	if (cmd == NULL) {
		return (FC_NOMEM);
	}

	cmd->cmd_pkt.pkt_tran_flags = FC_TRAN_INTR | class;
	cmd->cmd_pkt.pkt_tran_type = FC_PKT_EXCHANGE;
	cmd->cmd_flags = FP_CMD_CFLAG_UNDEFINED;
	cmd->cmd_retry_count = fp_retry_count;
	cmd->cmd_ulp_pkt = NULL;

	pkt = &cmd->cmd_pkt;
	cmd->cmd_transport = port->fp_fca_tran->fca_els_send;

	fp_els_init(cmd, s_id, 0xFFFFFD, fp_intr, job);

	payload.ls_code.ls_code = LA_ELS_SCR;
	payload.ls_code.mbz = 0;
	payload.scr_rsvd = 0;
	payload.scr_func = scr_func;

	FC_SET_CMD(port, pkt->pkt_cmd_acc, (uint8_t *)&payload,
	    (uint8_t *)pkt->pkt_cmd, sizeof (payload), DDI_DEV_AUTOINCR);

	job->job_counter = 1;

	if (fp_sendcmd(port, cmd, port->fp_fca_handle) != FC_SUCCESS) {
		fp_iodone(cmd);
	}

	return (FC_SUCCESS);
}


/*
 * There are basically two methods to determine the total number of
 * devices out in the NS database; Reading the details of the two
 * methods described below, it shouldn't be hard to identify which
 * of the two methods is better.
 *
 *	Method 1.
 *		Iteratively issue GANs until all ports identifiers are walked
 *
 *	Method 2.
 *		Issue GID_PT (get port Identifiers) with Maximum residual
 *		field in the request CT HEADER set to accommodate only the
 *		CT HEADER in the response frame. And if FC-GS2 has been
 *		carefully read, the NS here has a chance to FS_ACC the
 *		request and indicate the residual size in the FS_ACC.
 *
 *	Method 2 is wonderful, although it's not mandatory for the NS
 *	to update the Maximum/Residual Field as can be seen in 4.3.1.6
 *	(note with particular care the use of the auxiliary verb 'may')
 *
 */
static int
fp_ns_get_devcount(fc_local_port_t *port, job_request_t *job, int create,
    int sleep)
{
	int		flags;
	int		rval;
	uint32_t	src_id;
	fctl_ns_req_t	*ns_cmd;

	ASSERT(!MUTEX_HELD(&port->fp_mutex));

	mutex_enter(&port->fp_mutex);
	src_id = port->fp_port_id.port_id;
	mutex_exit(&port->fp_mutex);

	if (!create && (port->fp_options & FP_NS_SMART_COUNT)) {
		ns_cmd = fctl_alloc_ns_cmd(sizeof (ns_req_gid_pt_t),
		    sizeof (ns_resp_gid_pt_t), 0,
		    (FCTL_NS_GET_DEV_COUNT | FCTL_NS_NO_DATA_BUF), sleep);

		if (ns_cmd == NULL) {
			return (FC_NOMEM);
		}

		ns_cmd->ns_cmd_code = NS_GID_PT;
		((ns_req_gid_pt_t *)(ns_cmd->ns_cmd_buf))->port_type.port_type
		    = FC_NS_PORT_NX;	/* All port types */
		((ns_req_gid_pt_t *)(ns_cmd->ns_cmd_buf))->port_type.rsvd = 0;

	} else {
		uint32_t ns_flags;

		ns_flags = FCTL_NS_GET_DEV_COUNT | FCTL_NS_NO_DATA_BUF;
		if (create) {
			ns_flags |= FCTL_NS_CREATE_DEVICE;
		}
		ns_cmd = fctl_alloc_ns_cmd(sizeof (ns_req_gan_t),
		    sizeof (ns_resp_gan_t), sizeof (int), ns_flags, sleep);

		if (ns_cmd == NULL) {
			return (FC_NOMEM);
		}
		ns_cmd->ns_gan_index = 0;
		ns_cmd->ns_gan_sid = FCTL_GAN_START_ID;
		ns_cmd->ns_cmd_code = NS_GA_NXT;
		ns_cmd->ns_gan_max = 0xFFFF;

		((ns_req_gan_t *)(ns_cmd->ns_cmd_buf))->pid.port_id = src_id;
		((ns_req_gan_t *)(ns_cmd->ns_cmd_buf))->pid.priv_lilp_posit = 0;
	}

	flags = job->job_flags;
	job->job_flags &= ~JOB_TYPE_FP_ASYNC;
	job->job_counter = 1;

	rval = fp_ns_query(port, ns_cmd, job, 1, sleep);
	job->job_flags = flags;

	if (!create && (port->fp_options & FP_NS_SMART_COUNT)) {
		uint16_t max_resid;

		/*
		 * Revert to scanning the NS if NS_GID_PT isn't
		 * helping us figure out total number of devices.
		 */
		if (job->job_result != FC_SUCCESS ||
		    ns_cmd->ns_resp_hdr.ct_cmdrsp != FS_ACC_IU) {
			mutex_enter(&port->fp_mutex);
			port->fp_options &= ~FP_NS_SMART_COUNT;
			mutex_exit(&port->fp_mutex);

			fctl_free_ns_cmd(ns_cmd);
			return (fp_ns_get_devcount(port, job, create, sleep));
		}

		mutex_enter(&port->fp_mutex);
		port->fp_total_devices = 1;
		max_resid = ns_cmd->ns_resp_hdr.ct_aiusize;
		if (max_resid) {
			/*
			 * Since port identifier is 4 bytes and max_resid
			 * is also in WORDS, max_resid simply indicates
			 * the total number of port identifiers	not
			 * transferred
			 */
			port->fp_total_devices += max_resid;
		}
		mutex_exit(&port->fp_mutex);
	}
	mutex_enter(&port->fp_mutex);
	port->fp_total_devices = *((int *)ns_cmd->ns_data_buf);
	mutex_exit(&port->fp_mutex);
	fctl_free_ns_cmd(ns_cmd);

	return (rval);
}

/*
 * One heck of a function to serve userland.
 */
static int
fp_fciocmd(fc_local_port_t *port, intptr_t data, int mode, fcio_t *fcio)
{
	int		rval = 0;
	int		jcode;
	uint32_t	ret;
	uchar_t		open_flag;
	fcio_t		*kfcio;
	job_request_t	*job;
	boolean_t	use32 = B_FALSE;

#ifdef _MULTI_DATAMODEL
	switch (ddi_model_convert_from(mode & FMODELS)) {
	case DDI_MODEL_ILP32:
		use32 = B_TRUE;
		break;

	case DDI_MODEL_NONE:
	default:
		break;
	}
#endif

	mutex_enter(&port->fp_mutex);
	if (port->fp_soft_state & (FP_SOFT_IN_STATEC_CB |
	    FP_SOFT_IN_UNSOL_CB)) {
		fcio->fcio_errno = FC_STATEC_BUSY;
		mutex_exit(&port->fp_mutex);
		rval = EAGAIN;
		if (fp_fcio_copyout(fcio, data, mode)) {
			rval = EFAULT;
		}
		return (rval);
	}
	open_flag = port->fp_flag;
	mutex_exit(&port->fp_mutex);

	if (fp_check_perms(open_flag, fcio->fcio_cmd) != FC_SUCCESS) {
		fcio->fcio_errno = FC_FAILURE;
		rval = EACCES;
		if (fp_fcio_copyout(fcio, data, mode)) {
			rval = EFAULT;
		}
		return (rval);
	}

	/*
	 * If an exclusive open was demanded during open, don't let
	 * either innocuous or devil threads to share the file
	 * descriptor and fire down exclusive access commands
	 */
	mutex_enter(&port->fp_mutex);
	if (port->fp_flag & FP_EXCL) {
		if (port->fp_flag & FP_EXCL_BUSY) {
			mutex_exit(&port->fp_mutex);
			fcio->fcio_errno = FC_FAILURE;
			return (EBUSY);
		}
		port->fp_flag |= FP_EXCL_BUSY;
	}
	mutex_exit(&port->fp_mutex);

	fcio->fcio_errno = FC_SUCCESS;

	switch (fcio->fcio_cmd) {
	case FCIO_GET_HOST_PARAMS: {
		fc_port_dev_t	*val;
		fc_port_dev32_t	*val32;
		int		index;
		int		lilp_device_count;
		fc_lilpmap_t	*lilp_map;
		uchar_t		*alpa_list;

		if (use32 == B_TRUE) {
			if (fcio->fcio_olen != sizeof (*val32) ||
			    fcio->fcio_xfer != FCIO_XFER_READ) {
				rval = EINVAL;
				break;
			}
		} else {
			if (fcio->fcio_olen != sizeof (*val) ||
			    fcio->fcio_xfer != FCIO_XFER_READ) {
				rval = EINVAL;
				break;
			}
		}

		val = kmem_zalloc(sizeof (*val), KM_SLEEP);

		mutex_enter(&port->fp_mutex);
		val->dev_did = port->fp_port_id;
		val->dev_hard_addr = port->fp_hard_addr;
		val->dev_pwwn = port->fp_service_params.nport_ww_name;
		val->dev_nwwn = port->fp_service_params.node_ww_name;
		val->dev_state = port->fp_state;

		lilp_map = &port->fp_lilp_map;
		alpa_list = &lilp_map->lilp_alpalist[0];
		lilp_device_count = lilp_map->lilp_length;
		for (index = 0; index < lilp_device_count; index++) {
			uint32_t d_id;

			d_id = alpa_list[index];
			if (d_id == port->fp_port_id.port_id) {
				break;
			}
		}
		val->dev_did.priv_lilp_posit = (uint8_t)(index & 0xff);

		bcopy(port->fp_fc4_types, val->dev_type,
		    sizeof (port->fp_fc4_types));
		mutex_exit(&port->fp_mutex);

		if (use32 == B_TRUE) {
			val32 = kmem_zalloc(sizeof (*val32), KM_SLEEP);

			val32->dev_did = val->dev_did;
			val32->dev_hard_addr = val->dev_hard_addr;
			val32->dev_pwwn = val->dev_pwwn;
			val32->dev_nwwn = val->dev_nwwn;
			val32->dev_state = val->dev_state;
			val32->dev_did.priv_lilp_posit =
			    val->dev_did.priv_lilp_posit;

			bcopy(val->dev_type, val32->dev_type,
			    sizeof (port->fp_fc4_types));

			if (fp_copyout((void *)val32, (void *)fcio->fcio_obuf,
			    fcio->fcio_olen, mode) == 0) {
				if (fp_fcio_copyout(fcio, data, mode)) {
					rval = EFAULT;
				}
			} else {
				rval = EFAULT;
			}

			kmem_free(val32, sizeof (*val32));
		} else {
			if (fp_copyout((void *)val, (void *)fcio->fcio_obuf,
			    fcio->fcio_olen, mode) == 0) {
				if (fp_fcio_copyout(fcio, data, mode)) {
					rval = EFAULT;
				}
			} else {
				rval = EFAULT;
			}
		}

		/* need to free "val" here */
		kmem_free(val, sizeof (*val));
		break;
	}

	case FCIO_GET_OTHER_ADAPTER_PORTS: {
		uint32_t    index;
		char	    *tmpPath;
		fc_local_port_t	  *tmpPort;

		if (fcio->fcio_olen < MAXPATHLEN ||
		    fcio->fcio_ilen != sizeof (uint32_t)) {
			rval = EINVAL;
			break;
		}
		if (ddi_copyin(fcio->fcio_ibuf, &index, sizeof (index), mode)) {
			rval = EFAULT;
			break;
		}

		tmpPort = fctl_get_adapter_port_by_index(port, index);
		if (tmpPort == NULL) {
			FP_TRACE(FP_NHEAD1(9, 0),
			    "User supplied index out of range");
			fcio->fcio_errno = FC_BADPORT;
			rval = EFAULT;
			if (fp_fcio_copyout(fcio, data, mode)) {
				rval = EFAULT;
			}
			break;
		}

		tmpPath = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
		(void) ddi_pathname(tmpPort->fp_port_dip, tmpPath);
		if (fp_copyout((void *)tmpPath, (void *)fcio->fcio_obuf,
		    MAXPATHLEN, mode) == 0) {
			if (fp_fcio_copyout(fcio, data, mode)) {
				rval = EFAULT;
			}
		} else {
			rval = EFAULT;
		}
		kmem_free(tmpPath, MAXPATHLEN);
		break;
	}

	case FCIO_NPIV_GET_ADAPTER_ATTRIBUTES:
	case FCIO_GET_ADAPTER_ATTRIBUTES: {
		fc_hba_adapter_attributes_t	*val;
		fc_hba_adapter_attributes32_t	*val32;

		if (use32 == B_TRUE) {
			if (fcio->fcio_olen < sizeof (*val32) ||
			    fcio->fcio_xfer != FCIO_XFER_READ) {
				rval = EINVAL;
				break;
			}
		} else {
			if (fcio->fcio_olen < sizeof (*val) ||
			    fcio->fcio_xfer != FCIO_XFER_READ) {
				rval = EINVAL;
				break;
			}
		}

		val = kmem_zalloc(sizeof (*val), KM_SLEEP);
		val->version = FC_HBA_ADAPTER_ATTRIBUTES_VERSION;
		mutex_enter(&port->fp_mutex);
		bcopy(port->fp_hba_port_attrs.manufacturer,
		    val->Manufacturer,
		    sizeof (val->Manufacturer));
		bcopy(port->fp_hba_port_attrs.serial_number,
		    val->SerialNumber,
		    sizeof (val->SerialNumber));
		bcopy(port->fp_hba_port_attrs.model,
		    val->Model,
		    sizeof (val->Model));
		bcopy(port->fp_hba_port_attrs.model_description,
		    val->ModelDescription,
		    sizeof (val->ModelDescription));
		bcopy(port->fp_sym_node_name, val->NodeSymbolicName,
		    port->fp_sym_node_namelen);
		bcopy(port->fp_hba_port_attrs.hardware_version,
		    val->HardwareVersion,
		    sizeof (val->HardwareVersion));
		bcopy(port->fp_hba_port_attrs.option_rom_version,
		    val->OptionROMVersion,
		    sizeof (val->OptionROMVersion));
		bcopy(port->fp_hba_port_attrs.firmware_version,
		    val->FirmwareVersion,
		    sizeof (val->FirmwareVersion));
		val->VendorSpecificID =
		    port->fp_hba_port_attrs.vendor_specific_id;
		bcopy(&port->fp_service_params.node_ww_name.raw_wwn,
		    &val->NodeWWN.raw_wwn,
		    sizeof (val->NodeWWN.raw_wwn));


		bcopy(port->fp_hba_port_attrs.driver_name,
		    val->DriverName,
		    sizeof (val->DriverName));
		bcopy(port->fp_hba_port_attrs.driver_version,
		    val->DriverVersion,
		    sizeof (val->DriverVersion));
		mutex_exit(&port->fp_mutex);

		if (fcio->fcio_cmd == FCIO_GET_ADAPTER_ATTRIBUTES) {
			val->NumberOfPorts = fctl_count_fru_ports(port, 0);
		} else {
			val->NumberOfPorts = fctl_count_fru_ports(port, 1);
		}

		if (use32 == B_TRUE) {
			val32 = kmem_zalloc(sizeof (*val32), KM_SLEEP);
			val32->version = val->version;
			bcopy(val->Manufacturer, val32->Manufacturer,
			    sizeof (val->Manufacturer));
			bcopy(val->SerialNumber, val32->SerialNumber,
			    sizeof (val->SerialNumber));
			bcopy(val->Model, val32->Model,
			    sizeof (val->Model));
			bcopy(val->ModelDescription, val32->ModelDescription,
			    sizeof (val->ModelDescription));
			bcopy(val->NodeSymbolicName, val32->NodeSymbolicName,
			    sizeof (val->NodeSymbolicName));
			bcopy(val->HardwareVersion, val32->HardwareVersion,
			    sizeof (val->HardwareVersion));
			bcopy(val->OptionROMVersion, val32->OptionROMVersion,
			    sizeof (val->OptionROMVersion));
			bcopy(val->FirmwareVersion, val32->FirmwareVersion,
			    sizeof (val->FirmwareVersion));
			val32->VendorSpecificID = val->VendorSpecificID;
			bcopy(&val->NodeWWN.raw_wwn, &val32->NodeWWN.raw_wwn,
			    sizeof (val->NodeWWN.raw_wwn));
			bcopy(val->DriverName, val32->DriverName,
			    sizeof (val->DriverName));
			bcopy(val->DriverVersion, val32->DriverVersion,
			    sizeof (val->DriverVersion));

			val32->NumberOfPorts = val->NumberOfPorts;

			if (fp_copyout((void *)val32, (void *)fcio->fcio_obuf,
			    fcio->fcio_olen, mode) == 0) {
				if (fp_fcio_copyout(fcio, data, mode)) {
					rval = EFAULT;
				}
			} else {
				rval = EFAULT;
			}

			kmem_free(val32, sizeof (*val32));
		} else {
			if (fp_copyout((void *)val, (void *)fcio->fcio_obuf,
			    fcio->fcio_olen, mode) == 0) {
				if (fp_fcio_copyout(fcio, data, mode)) {
					rval = EFAULT;
				}
			} else {
				rval = EFAULT;
			}
		}

		kmem_free(val, sizeof (*val));
		break;
	}

	case FCIO_GET_NPIV_ATTRIBUTES: {
		fc_hba_npiv_attributes_t *attrs;

		attrs = kmem_zalloc(sizeof (*attrs), KM_SLEEP);
		mutex_enter(&port->fp_mutex);
		bcopy(&port->fp_service_params.node_ww_name.raw_wwn,
		    &attrs->NodeWWN.raw_wwn,
		    sizeof (attrs->NodeWWN.raw_wwn));
		bcopy(&port->fp_service_params.nport_ww_name.raw_wwn,
		    &attrs->PortWWN.raw_wwn,
		    sizeof (attrs->PortWWN.raw_wwn));
		mutex_exit(&port->fp_mutex);
		if (fp_copyout((void *)attrs, (void *)fcio->fcio_obuf,
		    fcio->fcio_olen, mode) == 0) {
			if (fp_fcio_copyout(fcio, data, mode)) {
				rval = EFAULT;
			}
		} else {
			rval = EFAULT;
		}
		kmem_free(attrs, sizeof (*attrs));
		break;
	}

	case FCIO_DELETE_NPIV_PORT: {
		fc_local_port_t *tmpport;
		char	ww_pname[17];
		la_wwn_t	vwwn[1];

		FP_TRACE(FP_NHEAD1(1, 0), "Delete NPIV Port");
		if (ddi_copyin(fcio->fcio_ibuf,
		    &vwwn, sizeof (la_wwn_t), mode)) {
			rval = EFAULT;
			break;
		}

		fc_wwn_to_str(&vwwn[0], ww_pname);
		FP_TRACE(FP_NHEAD1(3, 0),
		    "Delete NPIV Port %s", ww_pname);
		tmpport = fc_delete_npiv_port(port, &vwwn[0]);
		if (tmpport == NULL) {
			FP_TRACE(FP_NHEAD1(3, 0),
			    "Delete NPIV Port : no found");
			rval = EFAULT;
		} else {
			fc_local_port_t *nextport = tmpport->fp_port_next;
			fc_local_port_t *prevport = tmpport->fp_port_prev;
			int portlen, portindex, ret;

			portlen = sizeof (portindex);
			ret = ddi_prop_op(DDI_DEV_T_ANY,
			    tmpport->fp_port_dip, PROP_LEN_AND_VAL_BUF,
			    DDI_PROP_DONTPASS | DDI_PROP_CANSLEEP, "port",
			    (caddr_t)&portindex, &portlen);
			if (ret != DDI_SUCCESS) {
				rval = EFAULT;
				break;
			}
			if (ndi_devi_offline(tmpport->fp_port_dip,
			    NDI_DEVI_REMOVE) != DDI_SUCCESS) {
				FP_TRACE(FP_NHEAD1(1, 0),
				    "Delete NPIV Port failed");
				mutex_enter(&port->fp_mutex);
				tmpport->fp_npiv_state = 0;
				mutex_exit(&port->fp_mutex);
				rval = EFAULT;
			} else {
				mutex_enter(&port->fp_mutex);
				nextport->fp_port_prev = prevport;
				prevport->fp_port_next = nextport;
				if (port == port->fp_port_next) {
					port->fp_port_next =
					    port->fp_port_prev = NULL;
				}
				port->fp_npiv_portnum--;
				FP_TRACE(FP_NHEAD1(3, 0),
				    "Delete NPIV Port %d", portindex);
				port->fp_npiv_portindex[portindex-1] = 0;
				mutex_exit(&port->fp_mutex);
			}
		}
		break;
	}

	case FCIO_CREATE_NPIV_PORT: {
		char ww_nname[17], ww_pname[17];
		la_npiv_create_entry_t entrybuf;
		uint32_t vportindex = 0;
		int npiv_ret = 0;
		char *portname, *fcaname;

		portname = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
		(void) ddi_pathname(port->fp_port_dip, portname);
		fcaname = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
		(void) ddi_pathname(port->fp_fca_dip, fcaname);
		FP_TRACE(FP_NHEAD1(1, 0),
		    "Create NPIV port %s %s %s", portname, fcaname,
		    ddi_driver_name(port->fp_fca_dip));
		kmem_free(portname, MAXPATHLEN);
		kmem_free(fcaname, MAXPATHLEN);
		if (ddi_copyin(fcio->fcio_ibuf,
		    &entrybuf, sizeof (la_npiv_create_entry_t), mode)) {
			rval = EFAULT;
			break;
		}

		fc_wwn_to_str(&entrybuf.VNodeWWN, ww_nname);
		fc_wwn_to_str(&entrybuf.VPortWWN, ww_pname);
		vportindex = entrybuf.vindex;
		FP_TRACE(FP_NHEAD1(3, 0),
		    "Create NPIV Port %s %s %d",
		    ww_nname, ww_pname, vportindex);

		if (fc_get_npiv_port(port, &entrybuf.VPortWWN)) {
			rval = EFAULT;
			break;
		}
		npiv_ret = fctl_fca_create_npivport(port->fp_fca_dip,
		    port->fp_port_dip, ww_nname, ww_pname, &vportindex);
		if (npiv_ret == NDI_SUCCESS) {
			mutex_enter(&port->fp_mutex);
			port->fp_npiv_portnum++;
			mutex_exit(&port->fp_mutex);
			if (fp_copyout((void *)&vportindex,
			    (void *)fcio->fcio_obuf,
			    fcio->fcio_olen, mode) == 0) {
				if (fp_fcio_copyout(fcio, data, mode)) {
					rval = EFAULT;
				}
			} else {
				rval = EFAULT;
			}
		} else {
			rval = EFAULT;
		}
		FP_TRACE(FP_NHEAD1(3, 0),
		    "Create NPIV Port %d %d", npiv_ret, vportindex);
		break;
	}

	case FCIO_GET_NPIV_PORT_LIST: {
		fc_hba_npiv_port_list_t *list;
		int count;

		if ((fcio->fcio_xfer != FCIO_XFER_READ) ||
		    (fcio->fcio_olen == 0) || (fcio->fcio_obuf == 0)) {
			rval = EINVAL;
			break;
		}

		list = kmem_zalloc(fcio->fcio_olen, KM_SLEEP);
		list->version = FC_HBA_LIST_VERSION;

		count = (fcio->fcio_olen -
		    (int)sizeof (fc_hba_npiv_port_list_t))/MAXPATHLEN  + 1;
		if (port->fp_npiv_portnum > count) {
			list->numAdapters = port->fp_npiv_portnum;
		} else {
			/* build npiv port list */
			count = fc_ulp_get_npiv_port_list(port,
			    (char *)list->hbaPaths);
			if (count < 0) {
				rval = ENXIO;
				FP_TRACE(FP_NHEAD1(1, 0),
				    "Build NPIV Port List error");
				kmem_free(list, fcio->fcio_olen);
				break;
			}
			list->numAdapters = count;
		}

		if (fp_copyout((void *)list, (void *)fcio->fcio_obuf,
		    fcio->fcio_olen, mode) == 0) {
			if (fp_fcio_copyout(fcio, data, mode)) {
				FP_TRACE(FP_NHEAD1(1, 0),
				    "Copy NPIV Port data error");
				rval = EFAULT;
			}
		} else {
			FP_TRACE(FP_NHEAD1(1, 0), "Copy NPIV Port List error");
			rval = EFAULT;
		}
		kmem_free(list, fcio->fcio_olen);
		break;
	}

	case FCIO_GET_ADAPTER_PORT_NPIV_ATTRIBUTES: {
		fc_hba_port_npiv_attributes_t	*val;

		val = kmem_zalloc(sizeof (*val), KM_SLEEP);
		val->version = FC_HBA_PORT_NPIV_ATTRIBUTES_VERSION;

		mutex_enter(&port->fp_mutex);
		val->npivflag = port->fp_npiv_flag;
		val->lastChange = port->fp_last_change;
		bcopy(&port->fp_service_params.nport_ww_name.raw_wwn,
		    &val->PortWWN.raw_wwn,
		    sizeof (val->PortWWN.raw_wwn));
		bcopy(&port->fp_service_params.node_ww_name.raw_wwn,
		    &val->NodeWWN.raw_wwn,
		    sizeof (val->NodeWWN.raw_wwn));
		mutex_exit(&port->fp_mutex);

		val->NumberOfNPIVPorts = fc_ulp_get_npiv_port_num(port);
		if (port->fp_npiv_type != FC_NPIV_PORT) {
			val->MaxNumberOfNPIVPorts =
			    port->fp_fca_tran->fca_num_npivports;
		} else {
			val->MaxNumberOfNPIVPorts = 0;
		}

		if (fp_copyout((void *)val, (void *)fcio->fcio_obuf,
		    fcio->fcio_olen, mode) == 0) {
			if (fp_fcio_copyout(fcio, data, mode)) {
				rval = EFAULT;
			}
		} else {
			rval = EFAULT;
		}
		kmem_free(val, sizeof (*val));
		break;
	}

	case FCIO_GET_ADAPTER_PORT_ATTRIBUTES: {
		fc_hba_port_attributes_t	*val;
		fc_hba_port_attributes32_t	*val32;

		if (use32 == B_TRUE) {
			if (fcio->fcio_olen < sizeof (*val32) ||
			    fcio->fcio_xfer != FCIO_XFER_READ) {
				rval = EINVAL;
				break;
			}
		} else {
			if (fcio->fcio_olen < sizeof (*val) ||
			    fcio->fcio_xfer != FCIO_XFER_READ) {
				rval = EINVAL;
				break;
			}
		}

		val = kmem_zalloc(sizeof (*val), KM_SLEEP);
		val->version = FC_HBA_PORT_ATTRIBUTES_VERSION;
		mutex_enter(&port->fp_mutex);
		val->lastChange = port->fp_last_change;
		val->fp_minor = port->fp_instance;

		bcopy(&port->fp_service_params.nport_ww_name.raw_wwn,
		    &val->PortWWN.raw_wwn,
		    sizeof (val->PortWWN.raw_wwn));
		bcopy(&port->fp_service_params.node_ww_name.raw_wwn,
		    &val->NodeWWN.raw_wwn,
		    sizeof (val->NodeWWN.raw_wwn));
		bcopy(&port->fp_fabric_name, &val->FabricName.raw_wwn,
		    sizeof (val->FabricName.raw_wwn));

		val->PortFcId = port->fp_port_id.port_id;

		switch (FC_PORT_STATE_MASK(port->fp_state)) {
		case FC_STATE_OFFLINE:
			val->PortState = FC_HBA_PORTSTATE_OFFLINE;
			break;
		case FC_STATE_ONLINE:
		case FC_STATE_LOOP:
		case FC_STATE_NAMESERVICE:
			val->PortState = FC_HBA_PORTSTATE_ONLINE;
			break;
		default:
			val->PortState = FC_HBA_PORTSTATE_UNKNOWN;
			break;
		}

		/* Translate from LV to FC-HBA port type codes */
		switch (port->fp_port_type.port_type) {
		case FC_NS_PORT_N:
			val->PortType = FC_HBA_PORTTYPE_NPORT;
			break;
		case FC_NS_PORT_NL:
			/* Actually means loop for us */
			val->PortType = FC_HBA_PORTTYPE_LPORT;
			break;
		case FC_NS_PORT_F:
			val->PortType = FC_HBA_PORTTYPE_FPORT;
			break;
		case FC_NS_PORT_FL:
			val->PortType = FC_HBA_PORTTYPE_FLPORT;
			break;
		case FC_NS_PORT_E:
			val->PortType = FC_HBA_PORTTYPE_EPORT;
			break;
		default:
			val->PortType = FC_HBA_PORTTYPE_OTHER;
			break;
		}


		/*
		 * If fp has decided that the topology is public loop,
		 * we will indicate that using the appropriate
		 * FC HBA API constant.
		 */
		switch (port->fp_topology) {
		case FC_TOP_PUBLIC_LOOP:
			val->PortType = FC_HBA_PORTTYPE_NLPORT;
			break;

		case FC_TOP_PT_PT:
			val->PortType = FC_HBA_PORTTYPE_PTP;
			break;

		case FC_TOP_UNKNOWN:
			/*
			 * This should cover the case where nothing is connected
			 * to the port. Crystal+ is p'bly an exception here.
			 * For Crystal+, port 0 will come up as private loop
			 * (i.e fp_bind_state will be FC_STATE_LOOP) even when
			 * nothing is connected to it.
			 * Current plan is to let userland handle this.
			 */
			if (port->fp_bind_state == FC_STATE_OFFLINE) {
				val->PortType = FC_HBA_PORTTYPE_UNKNOWN;
			}
			break;

		default:
			/*
			 * Do Nothing.
			 * Unused:
			 *   val->PortType = FC_HBA_PORTTYPE_GPORT;
			 */
			break;
		}

		val->PortSupportedClassofService =
		    port->fp_hba_port_attrs.supported_cos;
		val->PortSupportedFc4Types[0] = 0;
		bcopy(port->fp_fc4_types, val->PortActiveFc4Types,
		    sizeof (val->PortActiveFc4Types));
		bcopy(port->fp_sym_port_name, val->PortSymbolicName,
		    port->fp_sym_port_namelen);
		val->PortSupportedSpeed =
		    port->fp_hba_port_attrs.supported_speed;

		switch (FC_PORT_SPEED_MASK(port->fp_state)) {
		case FC_STATE_1GBIT_SPEED:
			val->PortSpeed = FC_HBA_PORTSPEED_1GBIT;
			break;
		case FC_STATE_2GBIT_SPEED:
			val->PortSpeed = FC_HBA_PORTSPEED_2GBIT;
			break;
		case FC_STATE_4GBIT_SPEED:
			val->PortSpeed = FC_HBA_PORTSPEED_4GBIT;
			break;
		case FC_STATE_8GBIT_SPEED:
			val->PortSpeed = FC_HBA_PORTSPEED_8GBIT;
			break;
		case FC_STATE_10GBIT_SPEED:
			val->PortSpeed = FC_HBA_PORTSPEED_10GBIT;
			break;
		case FC_STATE_16GBIT_SPEED:
			val->PortSpeed = FC_HBA_PORTSPEED_16GBIT;
			break;
		default:
			val->PortSpeed = FC_HBA_PORTSPEED_UNKNOWN;
			break;
		}
		val->PortMaxFrameSize = port->fp_hba_port_attrs.max_frame_size;
		val->NumberofDiscoveredPorts = port->fp_dev_count;
		mutex_exit(&port->fp_mutex);

		if (use32 == B_TRUE) {
			val32 = kmem_zalloc(sizeof (*val32), KM_SLEEP);
			val32->version = val->version;
			val32->lastChange = val->lastChange;
			val32->fp_minor = val->fp_minor;

			bcopy(&val->PortWWN.raw_wwn, &val32->PortWWN.raw_wwn,
			    sizeof (val->PortWWN.raw_wwn));
			bcopy(&val->NodeWWN.raw_wwn, &val32->NodeWWN.raw_wwn,
			    sizeof (val->NodeWWN.raw_wwn));
			val32->PortFcId = val->PortFcId;
			val32->PortState = val->PortState;
			val32->PortType = val->PortType;

			val32->PortSupportedClassofService =
			    val->PortSupportedClassofService;
			bcopy(val->PortActiveFc4Types,
			    val32->PortActiveFc4Types,
			    sizeof (val->PortActiveFc4Types));
			bcopy(val->PortSymbolicName, val32->PortSymbolicName,
			    sizeof (val->PortSymbolicName));
			bcopy(&val->FabricName, &val32->FabricName,
			    sizeof (val->FabricName.raw_wwn));
			val32->PortSupportedSpeed = val->PortSupportedSpeed;
			val32->PortSpeed = val->PortSpeed;

			val32->PortMaxFrameSize = val->PortMaxFrameSize;
			val32->NumberofDiscoveredPorts =
			    val->NumberofDiscoveredPorts;

			if (fp_copyout((void *)val32, (void *)fcio->fcio_obuf,
			    fcio->fcio_olen, mode) == 0) {
				if (fp_fcio_copyout(fcio, data, mode)) {
					rval = EFAULT;
				}
			} else {
				rval = EFAULT;
			}

			kmem_free(val32, sizeof (*val32));
		} else {
			if (fp_copyout((void *)val, (void *)fcio->fcio_obuf,
			    fcio->fcio_olen, mode) == 0) {
				if (fp_fcio_copyout(fcio, data, mode)) {
					rval = EFAULT;
				}
			} else {
				rval = EFAULT;
			}
		}

		kmem_free(val, sizeof (*val));
		break;
	}

	case FCIO_GET_DISCOVERED_PORT_ATTRIBUTES: {
		fc_hba_port_attributes_t	*val;
		fc_hba_port_attributes32_t	*val32;
		uint32_t	index = 0;
		fc_remote_port_t *tmp_pd;

		if (use32 == B_TRUE) {
			if (fcio->fcio_olen < sizeof (*val32) ||
			    fcio->fcio_xfer != FCIO_XFER_READ) {
				rval = EINVAL;
				break;
			}
		} else {
			if (fcio->fcio_olen < sizeof (*val) ||
			    fcio->fcio_xfer != FCIO_XFER_READ) {
				rval = EINVAL;
				break;
			}
		}

		if (ddi_copyin(fcio->fcio_ibuf, &index, sizeof (index), mode)) {
			rval = EFAULT;
			break;
		}

		if (index >= port->fp_dev_count) {
			FP_TRACE(FP_NHEAD1(9, 0),
			    "User supplied index out of range");
			fcio->fcio_errno = FC_OUTOFBOUNDS;
			rval = EINVAL;
			if (fp_fcio_copyout(fcio, data, mode)) {
				rval = EFAULT;
			}
			break;
		}

		val = kmem_zalloc(sizeof (*val), KM_SLEEP);
		val->version = FC_HBA_PORT_ATTRIBUTES_VERSION;

		mutex_enter(&port->fp_mutex);
		tmp_pd = fctl_lookup_pd_by_index(port, index);

		if (tmp_pd == NULL) {
			fcio->fcio_errno = FC_BADPORT;
			rval = EINVAL;
		} else {
			val->lastChange = port->fp_last_change;
			val->fp_minor = port->fp_instance;

			mutex_enter(&tmp_pd->pd_mutex);
			bcopy(&tmp_pd->pd_port_name.raw_wwn,
			    &val->PortWWN.raw_wwn,
			    sizeof (val->PortWWN.raw_wwn));
			bcopy(&tmp_pd->pd_remote_nodep->fd_node_name.raw_wwn,
			    &val->NodeWWN.raw_wwn,
			    sizeof (val->NodeWWN.raw_wwn));
			val->PortFcId = tmp_pd->pd_port_id.port_id;
			bcopy(tmp_pd->pd_spn, val->PortSymbolicName,
			    tmp_pd->pd_spn_len);
			val->PortSupportedClassofService = tmp_pd->pd_cos;
			/*
			 * we will assume the sizeof these pd_fc4types and
			 * portActiveFc4Types will remain the same.  we could
			 * add in a check for it, but we decided it was unneeded
			 */
			bcopy((caddr_t)tmp_pd->pd_fc4types,
			    val->PortActiveFc4Types,
			    sizeof (tmp_pd->pd_fc4types));
			val->PortState =
			    fp_map_remote_port_state(tmp_pd->pd_state);
			mutex_exit(&tmp_pd->pd_mutex);

			val->PortType = FC_HBA_PORTTYPE_UNKNOWN;
			val->PortSupportedFc4Types[0] = 0;
			val->PortSupportedSpeed = FC_HBA_PORTSPEED_UNKNOWN;
			val->PortSpeed = FC_HBA_PORTSPEED_UNKNOWN;
			val->PortMaxFrameSize = 0;
			val->NumberofDiscoveredPorts = 0;

			if (use32 == B_TRUE) {
				val32 = kmem_zalloc(sizeof (*val32), KM_SLEEP);
				val32->version = val->version;
				val32->lastChange = val->lastChange;
				val32->fp_minor = val->fp_minor;

				bcopy(&val->PortWWN.raw_wwn,
				    &val32->PortWWN.raw_wwn,
				    sizeof (val->PortWWN.raw_wwn));
				bcopy(&val->NodeWWN.raw_wwn,
				    &val32->NodeWWN.raw_wwn,
				    sizeof (val->NodeWWN.raw_wwn));
				val32->PortFcId = val->PortFcId;
				bcopy(val->PortSymbolicName,
				    val32->PortSymbolicName,
				    sizeof (val->PortSymbolicName));
				val32->PortSupportedClassofService =
				    val->PortSupportedClassofService;
				bcopy(val->PortActiveFc4Types,
				    val32->PortActiveFc4Types,
				    sizeof (tmp_pd->pd_fc4types));

				val32->PortType = val->PortType;
				val32->PortState = val->PortState;
				val32->PortSupportedFc4Types[0] =
				    val->PortSupportedFc4Types[0];
				val32->PortSupportedSpeed =
				    val->PortSupportedSpeed;
				val32->PortSpeed = val->PortSpeed;
				val32->PortMaxFrameSize =
				    val->PortMaxFrameSize;
				val32->NumberofDiscoveredPorts =
				    val->NumberofDiscoveredPorts;

				if (fp_copyout((void *)val32,
				    (void *)fcio->fcio_obuf,
				    fcio->fcio_olen, mode) == 0) {
					if (fp_fcio_copyout(fcio,
					    data, mode)) {
						rval = EFAULT;
					}
				} else {
					rval = EFAULT;
				}

				kmem_free(val32, sizeof (*val32));
			} else {
				if (fp_copyout((void *)val,
				    (void *)fcio->fcio_obuf,
				    fcio->fcio_olen, mode) == 0) {
					if (fp_fcio_copyout(fcio, data, mode)) {
						rval = EFAULT;
					}
				} else {
					rval = EFAULT;
				}
			}
		}

		mutex_exit(&port->fp_mutex);
		kmem_free(val, sizeof (*val));
		break;
	}

	case FCIO_GET_PORT_ATTRIBUTES: {
		fc_hba_port_attributes_t    *val;
		fc_hba_port_attributes32_t  *val32;
		la_wwn_t		    wwn;
		fc_remote_port_t	    *tmp_pd;

		if (use32 == B_TRUE) {
			if (fcio->fcio_olen < sizeof (*val32) ||
			    fcio->fcio_xfer != FCIO_XFER_READ) {
				rval = EINVAL;
				break;
			}
		} else {
			if (fcio->fcio_olen < sizeof (*val) ||
			    fcio->fcio_xfer != FCIO_XFER_READ) {
				rval = EINVAL;
				break;
			}
		}

		if (ddi_copyin(fcio->fcio_ibuf, &wwn, sizeof (wwn), mode)) {
			rval = EFAULT;
			break;
		}

		val = kmem_zalloc(sizeof (*val), KM_SLEEP);
		val->version = FC_HBA_PORT_ATTRIBUTES_VERSION;

		mutex_enter(&port->fp_mutex);
		tmp_pd = fctl_lookup_pd_by_wwn(port, wwn);
		val->lastChange = port->fp_last_change;
		val->fp_minor = port->fp_instance;
		mutex_exit(&port->fp_mutex);

		if (tmp_pd == NULL) {
			fcio->fcio_errno = FC_BADWWN;
			rval = EINVAL;
		} else {
			mutex_enter(&tmp_pd->pd_mutex);
			bcopy(&tmp_pd->pd_port_name.raw_wwn,
			    &val->PortWWN.raw_wwn,
			    sizeof (val->PortWWN.raw_wwn));
			bcopy(&tmp_pd->pd_remote_nodep->fd_node_name.raw_wwn,
			    &val->NodeWWN.raw_wwn,
			    sizeof (val->NodeWWN.raw_wwn));
			val->PortFcId = tmp_pd->pd_port_id.port_id;
			bcopy(tmp_pd->pd_spn, val->PortSymbolicName,
			    tmp_pd->pd_spn_len);
			val->PortSupportedClassofService = tmp_pd->pd_cos;
			val->PortType = FC_HBA_PORTTYPE_UNKNOWN;
			val->PortState =
			    fp_map_remote_port_state(tmp_pd->pd_state);
			val->PortSupportedFc4Types[0] = 0;
			/*
			 * we will assume the sizeof these pd_fc4types and
			 * portActiveFc4Types will remain the same.  we could
			 * add in a check for it, but we decided it was unneeded
			 */
			bcopy((caddr_t)tmp_pd->pd_fc4types,
			    val->PortActiveFc4Types,
			    sizeof (tmp_pd->pd_fc4types));
			val->PortSupportedSpeed = FC_HBA_PORTSPEED_UNKNOWN;
			val->PortSpeed = FC_HBA_PORTSPEED_UNKNOWN;
			val->PortMaxFrameSize = 0;
			val->NumberofDiscoveredPorts = 0;
			mutex_exit(&tmp_pd->pd_mutex);

			if (use32 == B_TRUE) {
				val32 = kmem_zalloc(sizeof (*val32), KM_SLEEP);
				val32->version = val->version;
				val32->lastChange = val->lastChange;
				val32->fp_minor = val->fp_minor;
				bcopy(&val->PortWWN.raw_wwn,
				    &val32->PortWWN.raw_wwn,
				    sizeof (val->PortWWN.raw_wwn));
				bcopy(&val->NodeWWN.raw_wwn,
				    &val32->NodeWWN.raw_wwn,
				    sizeof (val->NodeWWN.raw_wwn));
				val32->PortFcId = val->PortFcId;
				bcopy(val->PortSymbolicName,
				    val32->PortSymbolicName,
				    sizeof (val->PortSymbolicName));
				val32->PortSupportedClassofService =
				    val->PortSupportedClassofService;
				val32->PortType = val->PortType;
				val32->PortState = val->PortState;
				val32->PortSupportedFc4Types[0] =
				    val->PortSupportedFc4Types[0];
				bcopy(val->PortActiveFc4Types,
				    val32->PortActiveFc4Types,
				    sizeof (tmp_pd->pd_fc4types));
				val32->PortSupportedSpeed =
				    val->PortSupportedSpeed;
				val32->PortSpeed = val->PortSpeed;
				val32->PortMaxFrameSize = val->PortMaxFrameSize;
				val32->NumberofDiscoveredPorts =
				    val->NumberofDiscoveredPorts;

				if (fp_copyout((void *)val32,
				    (void *)fcio->fcio_obuf,
				    fcio->fcio_olen, mode) == 0) {
					if (fp_fcio_copyout(fcio, data, mode)) {
						rval = EFAULT;
					}
				} else {
					rval = EFAULT;
				}

				kmem_free(val32, sizeof (*val32));
			} else {
				if (fp_copyout((void *)val,
				    (void *)fcio->fcio_obuf,
				    fcio->fcio_olen, mode) == 0) {
					if (fp_fcio_copyout(fcio, data, mode)) {
						rval = EFAULT;
					}
				} else {
					rval = EFAULT;
				}
			}
		}
		kmem_free(val, sizeof (*val));
		break;
	}

	case FCIO_GET_NUM_DEVS: {
		int num_devices;

		if (fcio->fcio_olen != sizeof (num_devices) ||
		    fcio->fcio_xfer != FCIO_XFER_READ) {
			rval = EINVAL;
			break;
		}

		mutex_enter(&port->fp_mutex);
		switch (port->fp_topology) {
		case FC_TOP_PRIVATE_LOOP:
		case FC_TOP_PT_PT:
			num_devices = port->fp_total_devices;
			fcio->fcio_errno = FC_SUCCESS;
			break;

		case FC_TOP_PUBLIC_LOOP:
		case FC_TOP_FABRIC:
			mutex_exit(&port->fp_mutex);
			job = fctl_alloc_job(JOB_NS_CMD, 0, NULL,
			    NULL, KM_SLEEP);
			ASSERT(job != NULL);

			/*
			 * In FC-GS-2 the Name Server doesn't send out
			 * RSCNs for any Name Server Database updates
			 * When it is finally fixed there is no need
			 * to probe as below and should be removed.
			 */
			(void) fp_ns_get_devcount(port, job, 0, KM_SLEEP);
			fctl_dealloc_job(job);

			mutex_enter(&port->fp_mutex);
			num_devices = port->fp_total_devices;
			fcio->fcio_errno = FC_SUCCESS;
			break;

		case FC_TOP_NO_NS:
			/* FALLTHROUGH */
		case FC_TOP_UNKNOWN:
			/* FALLTHROUGH */
		default:
			num_devices = 0;
			fcio->fcio_errno = FC_SUCCESS;
			break;
		}
		mutex_exit(&port->fp_mutex);

		if (fp_copyout((void *)&num_devices,
		    (void *)fcio->fcio_obuf, fcio->fcio_olen,
		    mode) == 0) {
			if (fp_fcio_copyout(fcio, data, mode)) {
				rval = EFAULT;
			}
		} else {
			rval = EFAULT;
		}
		break;
	}

	case FCIO_GET_DEV_LIST: {
		int num_devices;
		int new_count;
		int map_size;

		if (fcio->fcio_xfer != FCIO_XFER_READ ||
		    fcio->fcio_alen != sizeof (new_count)) {
			rval = EINVAL;
			break;
		}

		num_devices = fcio->fcio_olen / sizeof (fc_port_dev_t);

		mutex_enter(&port->fp_mutex);
		if (num_devices < port->fp_total_devices) {
			fcio->fcio_errno = FC_TOOMANY;
			new_count = port->fp_total_devices;
			mutex_exit(&port->fp_mutex);

			if (fp_copyout((void *)&new_count,
			    (void *)fcio->fcio_abuf,
			    sizeof (new_count), mode)) {
				rval = EFAULT;
				break;
			}

			if (fp_fcio_copyout(fcio, data, mode)) {
				rval = EFAULT;
				break;
			}
			rval = EINVAL;
			break;
		}

		if (port->fp_total_devices <= 0) {
			fcio->fcio_errno = FC_NO_MAP;
			new_count = port->fp_total_devices;
			mutex_exit(&port->fp_mutex);

			if (fp_copyout((void *)&new_count,
			    (void *)fcio->fcio_abuf,
			    sizeof (new_count), mode)) {
				rval = EFAULT;
				break;
			}

			if (fp_fcio_copyout(fcio, data, mode)) {
				rval = EFAULT;
				break;
			}
			rval = EINVAL;
			break;
		}

		switch (port->fp_topology) {
		case FC_TOP_PRIVATE_LOOP:
			if (fp_fillout_loopmap(port, fcio,
			    mode) != FC_SUCCESS) {
				rval = EFAULT;
				break;
			}
			if (fp_fcio_copyout(fcio, data, mode)) {
				rval = EFAULT;
			}
			break;

		case FC_TOP_PT_PT:
			if (fp_fillout_p2pmap(port, fcio,
			    mode) != FC_SUCCESS) {
				rval = EFAULT;
				break;
			}
			if (fp_fcio_copyout(fcio, data, mode)) {
				rval = EFAULT;
			}
			break;

		case FC_TOP_PUBLIC_LOOP:
		case FC_TOP_FABRIC: {
			fctl_ns_req_t *ns_cmd;

			map_size =
			    sizeof (fc_port_dev_t) * port->fp_total_devices;

			mutex_exit(&port->fp_mutex);

			ns_cmd = fctl_alloc_ns_cmd(sizeof (ns_req_gan_t),
			    sizeof (ns_resp_gan_t), map_size,
			    (FCTL_NS_FILL_NS_MAP | FCTL_NS_BUF_IS_USERLAND),
			    KM_SLEEP);
			ASSERT(ns_cmd != NULL);

			ns_cmd->ns_gan_index = 0;
			ns_cmd->ns_gan_sid = FCTL_GAN_START_ID;
			ns_cmd->ns_cmd_code = NS_GA_NXT;
			ns_cmd->ns_gan_max = map_size / sizeof (fc_port_dev_t);

			job = fctl_alloc_job(JOB_PORT_GETMAP, 0, NULL,
			    NULL, KM_SLEEP);
			ASSERT(job != NULL);

			ret = fp_ns_query(port, ns_cmd, job, 1, KM_SLEEP);

			if (ret != FC_SUCCESS ||
			    job->job_result != FC_SUCCESS) {
				fctl_free_ns_cmd(ns_cmd);

				fcio->fcio_errno = job->job_result;
				new_count = 0;
				if (fp_copyout((void *)&new_count,
				    (void *)fcio->fcio_abuf,
				    sizeof (new_count), mode)) {
					fctl_dealloc_job(job);
					mutex_enter(&port->fp_mutex);
					rval = EFAULT;
					break;
				}

				if (fp_fcio_copyout(fcio, data, mode)) {
					fctl_dealloc_job(job);
					mutex_enter(&port->fp_mutex);
					rval = EFAULT;
					break;
				}
				rval = EIO;
				mutex_enter(&port->fp_mutex);
				break;
			}
			fctl_dealloc_job(job);

			new_count = ns_cmd->ns_gan_index;
			if (fp_copyout((void *)&new_count,
			    (void *)fcio->fcio_abuf, sizeof (new_count),
			    mode)) {
				rval = EFAULT;
				fctl_free_ns_cmd(ns_cmd);
				mutex_enter(&port->fp_mutex);
				break;
			}

			if (fp_copyout((void *)ns_cmd->ns_data_buf,
			    (void *)fcio->fcio_obuf, sizeof (fc_port_dev_t) *
			    ns_cmd->ns_gan_index, mode)) {
				rval = EFAULT;
				fctl_free_ns_cmd(ns_cmd);
				mutex_enter(&port->fp_mutex);
				break;
			}
			fctl_free_ns_cmd(ns_cmd);

			if (fp_fcio_copyout(fcio, data, mode)) {
				rval = EFAULT;
			}
			mutex_enter(&port->fp_mutex);
			break;
		}

		case FC_TOP_NO_NS:
			/* FALLTHROUGH */
		case FC_TOP_UNKNOWN:
			/* FALLTHROUGH */
		default:
			fcio->fcio_errno = FC_NO_MAP;
			num_devices = port->fp_total_devices;

			if (fp_copyout((void *)&new_count,
			    (void *)fcio->fcio_abuf,
			    sizeof (new_count), mode)) {
				rval = EFAULT;
				break;
			}

			if (fp_fcio_copyout(fcio, data, mode)) {
				rval = EFAULT;
				break;
			}
			rval = EINVAL;
			break;
		}
		mutex_exit(&port->fp_mutex);
		break;
	}

	case FCIO_GET_SYM_PNAME: {
		rval = ENOTSUP;
		break;
	}

	case FCIO_GET_SYM_NNAME: {
		rval = ENOTSUP;
		break;
	}

	case FCIO_SET_SYM_PNAME: {
		rval = ENOTSUP;
		break;
	}

	case FCIO_SET_SYM_NNAME: {
		rval = ENOTSUP;
		break;
	}

	case FCIO_GET_LOGI_PARAMS: {
		la_wwn_t		pwwn;
		la_wwn_t		*my_pwwn;
		la_els_logi_t		*params;
		la_els_logi32_t		*params32;
		fc_remote_node_t	*node;
		fc_remote_port_t	*pd;

		if (fcio->fcio_ilen != sizeof (la_wwn_t) ||
		    (fcio->fcio_xfer & FCIO_XFER_READ) == 0 ||
		    (fcio->fcio_xfer & FCIO_XFER_WRITE) == 0) {
			rval = EINVAL;
			break;
		}

		if (use32 == B_TRUE) {
			if (fcio->fcio_olen != sizeof (la_els_logi32_t)) {
				rval = EINVAL;
				break;
			}
		} else {
			if (fcio->fcio_olen != sizeof (la_els_logi_t)) {
				rval = EINVAL;
				break;
			}
		}

		if (ddi_copyin(fcio->fcio_ibuf, &pwwn, sizeof (pwwn), mode)) {
			rval = EFAULT;
			break;
		}

		pd = fctl_hold_remote_port_by_pwwn(port, &pwwn);
		if (pd == NULL) {
			mutex_enter(&port->fp_mutex);
			my_pwwn = &port->fp_service_params.nport_ww_name;
			mutex_exit(&port->fp_mutex);

			if (fctl_wwn_cmp(&pwwn, my_pwwn) != 0) {
				rval = ENXIO;
				break;
			}

			params = kmem_zalloc(sizeof (*params), KM_SLEEP);
			mutex_enter(&port->fp_mutex);
			*params = port->fp_service_params;
			mutex_exit(&port->fp_mutex);
		} else {
			params = kmem_zalloc(sizeof (*params), KM_SLEEP);

			mutex_enter(&pd->pd_mutex);
			params->ls_code.mbz = params->ls_code.ls_code = 0;
			params->common_service = pd->pd_csp;
			params->nport_ww_name = pd->pd_port_name;
			params->class_1 = pd->pd_clsp1;
			params->class_2 = pd->pd_clsp2;
			params->class_3 = pd->pd_clsp3;
			node = pd->pd_remote_nodep;
			mutex_exit(&pd->pd_mutex);

			bzero(params->reserved, sizeof (params->reserved));

			mutex_enter(&node->fd_mutex);
			bcopy(node->fd_vv, params->vendor_version,
			    sizeof (node->fd_vv));
			params->node_ww_name = node->fd_node_name;
			mutex_exit(&node->fd_mutex);

			fctl_release_remote_port(pd);
		}

		if (use32 == B_TRUE) {
			params32 = kmem_zalloc(sizeof (*params32), KM_SLEEP);

			params32->ls_code.mbz = params->ls_code.mbz;
			params32->common_service = params->common_service;
			params32->nport_ww_name = params->nport_ww_name;
			params32->class_1 = params->class_1;
			params32->class_2 = params->class_2;
			params32->class_3 = params->class_3;
			bzero(params32->reserved, sizeof (params32->reserved));
			bcopy(params->vendor_version, params32->vendor_version,
			    sizeof (node->fd_vv));
			params32->node_ww_name = params->node_ww_name;

			if (ddi_copyout((void *)params32,
			    (void *)fcio->fcio_obuf,
			    sizeof (*params32), mode)) {
				rval = EFAULT;
			}

			kmem_free(params32, sizeof (*params32));
		} else {
			if (ddi_copyout((void *)params, (void *)fcio->fcio_obuf,
			    sizeof (*params), mode)) {
				rval = EFAULT;
			}
		}

		kmem_free(params, sizeof (*params));
		if (fp_fcio_copyout(fcio, data, mode)) {
			rval = EFAULT;
		}
		break;
	}

	case FCIO_DEV_LOGOUT:
	case FCIO_DEV_LOGIN:
		if (fcio->fcio_ilen != sizeof (la_wwn_t) ||
		    fcio->fcio_xfer != FCIO_XFER_WRITE) {
			rval = EINVAL;

			if (fp_fcio_copyout(fcio, data, mode)) {
				rval = EFAULT;
			}
			break;
		}

		if (fcio->fcio_cmd == FCIO_DEV_LOGIN) {
			jcode = JOB_FCIO_LOGIN;
		} else {
			jcode = JOB_FCIO_LOGOUT;
		}

		kfcio = kmem_zalloc(sizeof (*kfcio), KM_SLEEP);
		bcopy(fcio, kfcio, sizeof (*fcio));

		if (kfcio->fcio_ilen) {
			kfcio->fcio_ibuf = kmem_zalloc(kfcio->fcio_ilen,
			    KM_SLEEP);

			if (ddi_copyin((void *)fcio->fcio_ibuf,
			    (void *)kfcio->fcio_ibuf, kfcio->fcio_ilen,
			    mode)) {
				rval = EFAULT;

				kmem_free(kfcio->fcio_ibuf, kfcio->fcio_ilen);
				kmem_free(kfcio, sizeof (*kfcio));
				fcio->fcio_errno = job->job_result;
				if (fp_fcio_copyout(fcio, data, mode)) {
					rval = EFAULT;
				}
				break;
			}
		}

		job = fctl_alloc_job(jcode, 0, NULL, NULL, KM_SLEEP);
		job->job_private = kfcio;

		fctl_enque_job(port, job);
		fctl_jobwait(job);

		rval = job->job_result;

		fcio->fcio_errno = kfcio->fcio_errno;
		if (fp_fcio_copyout(fcio, data, mode)) {
			rval = EFAULT;
		}

		kmem_free(kfcio->fcio_ibuf, kfcio->fcio_ilen);
		kmem_free(kfcio, sizeof (*kfcio));
		fctl_dealloc_job(job);
		break;

	case FCIO_GET_STATE: {
		la_wwn_t		pwwn;
		uint32_t		state;
		fc_remote_port_t	*pd;
		fctl_ns_req_t		*ns_cmd;

		if (fcio->fcio_ilen != sizeof (la_wwn_t) ||
		    fcio->fcio_olen != sizeof (state) ||
		    (fcio->fcio_xfer & FCIO_XFER_WRITE) == 0 ||
		    (fcio->fcio_xfer & FCIO_XFER_READ) == 0) {
			rval = EINVAL;
			break;
		}

		if (ddi_copyin(fcio->fcio_ibuf, &pwwn, sizeof (pwwn), mode)) {
			rval = EFAULT;
			break;
		}
		fcio->fcio_errno = 0;

		pd = fctl_hold_remote_port_by_pwwn(port, &pwwn);
		if (pd == NULL) {
			mutex_enter(&port->fp_mutex);
			if (FC_IS_TOP_SWITCH(port->fp_topology)) {
				mutex_exit(&port->fp_mutex);
				job = fctl_alloc_job(JOB_PLOGI_ONE, 0,
				    NULL, NULL, KM_SLEEP);

				job->job_counter = 1;
				job->job_result = FC_SUCCESS;

				ns_cmd = fctl_alloc_ns_cmd(
				    sizeof (ns_req_gid_pn_t),
				    sizeof (ns_resp_gid_pn_t),
				    sizeof (ns_resp_gid_pn_t),
				    FCTL_NS_BUF_IS_USERLAND, KM_SLEEP);
				ASSERT(ns_cmd != NULL);

				ns_cmd->ns_cmd_code = NS_GID_PN;
				((ns_req_gid_pn_t *)
				    (ns_cmd->ns_cmd_buf))->pwwn = pwwn;

				ret = fp_ns_query(port, ns_cmd, job,
				    1, KM_SLEEP);

				if (ret != FC_SUCCESS || job->job_result !=
				    FC_SUCCESS) {
					if (ret != FC_SUCCESS) {
						fcio->fcio_errno = ret;
					} else {
						fcio->fcio_errno =
						    job->job_result;
					}
					rval = EIO;
				} else {
					state = PORT_DEVICE_INVALID;
				}
				fctl_free_ns_cmd(ns_cmd);
				fctl_dealloc_job(job);
			} else {
				mutex_exit(&port->fp_mutex);
				fcio->fcio_errno = FC_BADWWN;
				rval = ENXIO;
			}
		} else {
			mutex_enter(&pd->pd_mutex);
			state = pd->pd_state;
			mutex_exit(&pd->pd_mutex);

			fctl_release_remote_port(pd);
		}

		if (!rval) {
			if (ddi_copyout((void *)&state,
			    (void *)fcio->fcio_obuf, sizeof (state),
			    mode)) {
				rval = EFAULT;
			}
		}
		if (fp_fcio_copyout(fcio, data, mode)) {
			rval = EFAULT;
		}
		break;
	}

	case FCIO_DEV_REMOVE: {
		la_wwn_t	pwwn;
		fc_portmap_t	*changelist;
		fc_remote_port_t *pd;

		if (fcio->fcio_ilen != sizeof (la_wwn_t) ||
		    fcio->fcio_xfer != FCIO_XFER_WRITE) {
			rval = EINVAL;
			break;
		}

		if (ddi_copyin(fcio->fcio_ibuf, &pwwn, sizeof (pwwn), mode)) {
			rval = EFAULT;
			break;
		}

		pd = fctl_hold_remote_port_by_pwwn(port, &pwwn);
		if (pd == NULL) {
			rval = ENXIO;
			fcio->fcio_errno = FC_BADWWN;
			if (fp_fcio_copyout(fcio, data, mode)) {
				rval = EFAULT;
			}
			break;
		}

		mutex_enter(&pd->pd_mutex);
		if (pd->pd_ref_count > 1) {
			mutex_exit(&pd->pd_mutex);

			rval = EBUSY;
			fcio->fcio_errno = FC_FAILURE;
			fctl_release_remote_port(pd);

			if (fp_fcio_copyout(fcio, data, mode)) {
				rval = EFAULT;
			}
			break;
		}
		mutex_exit(&pd->pd_mutex);

		changelist = kmem_zalloc(sizeof (*changelist), KM_SLEEP);

		fctl_copy_portmap(changelist, pd);
		changelist->map_type = PORT_DEVICE_USER_LOGOUT;
		(void) fp_ulp_devc_cb(port, changelist, 1, 1, KM_SLEEP, 1);

		fctl_release_remote_port(pd);
		break;
	}

	case FCIO_GET_FCODE_REV: {
		caddr_t		fcode_rev;
		fc_fca_pm_t	pm;

		if (fcio->fcio_olen < FC_FCODE_REV_SIZE ||
		    fcio->fcio_xfer != FCIO_XFER_READ) {
			rval = EINVAL;
			break;
		}
		bzero((caddr_t)&pm, sizeof (pm));

		fcode_rev = kmem_zalloc(fcio->fcio_olen, KM_SLEEP);

		pm.pm_cmd_flags = FC_FCA_PM_READ;
		pm.pm_cmd_code = FC_PORT_GET_FCODE_REV;
		pm.pm_data_len = fcio->fcio_olen;
		pm.pm_data_buf = fcode_rev;

		ret = port->fp_fca_tran->fca_port_manage(
		    port->fp_fca_handle, &pm);

		if (ret == FC_SUCCESS) {
			if (ddi_copyout((void *)fcode_rev,
			    (void *)fcio->fcio_obuf,
			    fcio->fcio_olen, mode) == 0) {
				if (fp_fcio_copyout(fcio, data, mode)) {
					rval = EFAULT;
				}
			} else {
				rval = EFAULT;
			}
		} else {
			/*
			 * check if buffer was not large enough to obtain
			 * FCODE version.
			 */
			if (pm.pm_data_len > fcio->fcio_olen) {
				rval = ENOMEM;
			} else {
				rval = EIO;
			}
			fcio->fcio_errno = ret;
			if (fp_fcio_copyout(fcio, data, mode)) {
				rval = EFAULT;
			}
		}
		kmem_free(fcode_rev, fcio->fcio_olen);
		break;
	}

	case FCIO_GET_FW_REV: {
		caddr_t		fw_rev;
		fc_fca_pm_t	pm;

		if (fcio->fcio_olen < FC_FW_REV_SIZE ||
		    fcio->fcio_xfer != FCIO_XFER_READ) {
			rval = EINVAL;
			break;
		}
		bzero((caddr_t)&pm, sizeof (pm));

		fw_rev = kmem_zalloc(fcio->fcio_olen, KM_SLEEP);

		pm.pm_cmd_flags = FC_FCA_PM_READ;
		pm.pm_cmd_code = FC_PORT_GET_FW_REV;
		pm.pm_data_len = fcio->fcio_olen;
		pm.pm_data_buf = fw_rev;

		ret = port->fp_fca_tran->fca_port_manage(
		    port->fp_fca_handle, &pm);

		if (ret == FC_SUCCESS) {
			if (ddi_copyout((void *)fw_rev,
			    (void *)fcio->fcio_obuf,
			    fcio->fcio_olen, mode) == 0) {
				if (fp_fcio_copyout(fcio, data, mode)) {
					rval = EFAULT;
				}
			} else {
				rval = EFAULT;
			}
		} else {
			if (fp_fcio_copyout(fcio, data, mode)) {
				rval = EFAULT;
			}
			rval = EIO;
		}
		kmem_free(fw_rev, fcio->fcio_olen);
		break;
	}

	case FCIO_GET_DUMP_SIZE: {
		uint32_t	dump_size;
		fc_fca_pm_t	pm;

		if (fcio->fcio_olen != sizeof (dump_size) ||
		    fcio->fcio_xfer != FCIO_XFER_READ) {
			rval = EINVAL;
			break;
		}
		bzero((caddr_t)&pm, sizeof (pm));
		pm.pm_cmd_flags = FC_FCA_PM_READ;
		pm.pm_cmd_code = FC_PORT_GET_DUMP_SIZE;
		pm.pm_data_len = sizeof (dump_size);
		pm.pm_data_buf = (caddr_t)&dump_size;

		ret = port->fp_fca_tran->fca_port_manage(
		    port->fp_fca_handle, &pm);

		if (ret == FC_SUCCESS) {
			if (ddi_copyout((void *)&dump_size,
			    (void *)fcio->fcio_obuf, sizeof (dump_size),
			    mode) == 0) {
				if (fp_fcio_copyout(fcio, data, mode)) {
					rval = EFAULT;
				}
			} else {
				rval = EFAULT;
			}
		} else {
			fcio->fcio_errno = ret;
			rval = EIO;
			if (fp_fcio_copyout(fcio, data, mode)) {
				rval = EFAULT;
			}
		}
		break;
	}

	case FCIO_DOWNLOAD_FW: {
		caddr_t		firmware;
		fc_fca_pm_t	pm;

		if (fcio->fcio_ilen <= 0 ||
		    fcio->fcio_xfer != FCIO_XFER_WRITE) {
			rval = EINVAL;
			break;
		}

		firmware = kmem_zalloc(fcio->fcio_ilen, KM_SLEEP);
		if (ddi_copyin(fcio->fcio_ibuf, firmware,
		    fcio->fcio_ilen, mode)) {
			rval = EFAULT;
			kmem_free(firmware, fcio->fcio_ilen);
			break;
		}

		bzero((caddr_t)&pm, sizeof (pm));
		pm.pm_cmd_flags = FC_FCA_PM_WRITE;
		pm.pm_cmd_code = FC_PORT_DOWNLOAD_FW;
		pm.pm_data_len = fcio->fcio_ilen;
		pm.pm_data_buf = firmware;

		ret = port->fp_fca_tran->fca_port_manage(
		    port->fp_fca_handle, &pm);

		kmem_free(firmware, fcio->fcio_ilen);

		if (ret != FC_SUCCESS) {
			fcio->fcio_errno = ret;
			rval = EIO;
			if (fp_fcio_copyout(fcio, data, mode)) {
				rval = EFAULT;
			}
		}
		break;
	}

	case FCIO_DOWNLOAD_FCODE: {
		caddr_t		fcode;
		fc_fca_pm_t	pm;

		if (fcio->fcio_ilen <= 0 ||
		    fcio->fcio_xfer != FCIO_XFER_WRITE) {
			rval = EINVAL;
			break;
		}

		fcode = kmem_zalloc(fcio->fcio_ilen, KM_SLEEP);
		if (ddi_copyin(fcio->fcio_ibuf, fcode,
		    fcio->fcio_ilen, mode)) {
			rval = EFAULT;
			kmem_free(fcode, fcio->fcio_ilen);
			break;
		}

		bzero((caddr_t)&pm, sizeof (pm));
		pm.pm_cmd_flags = FC_FCA_PM_WRITE;
		pm.pm_cmd_code = FC_PORT_DOWNLOAD_FCODE;
		pm.pm_data_len = fcio->fcio_ilen;
		pm.pm_data_buf = fcode;

		ret = port->fp_fca_tran->fca_port_manage(
		    port->fp_fca_handle, &pm);

		kmem_free(fcode, fcio->fcio_ilen);

		if (ret != FC_SUCCESS) {
			fcio->fcio_errno = ret;
			rval = EIO;
			if (fp_fcio_copyout(fcio, data, mode)) {
				rval = EFAULT;
			}
		}
		break;
	}

	case FCIO_FORCE_DUMP:
		ret = port->fp_fca_tran->fca_reset(
		    port->fp_fca_handle, FC_FCA_CORE);

		if (ret != FC_SUCCESS) {
			fcio->fcio_errno = ret;
			rval = EIO;
			if (fp_fcio_copyout(fcio, data, mode)) {
				rval = EFAULT;
			}
		}
		break;

	case FCIO_GET_DUMP: {
		caddr_t		dump;
		uint32_t	dump_size;
		fc_fca_pm_t	pm;

		if (fcio->fcio_xfer != FCIO_XFER_READ) {
			rval = EINVAL;
			break;
		}
		bzero((caddr_t)&pm, sizeof (pm));

		pm.pm_cmd_flags = FC_FCA_PM_READ;
		pm.pm_cmd_code = FC_PORT_GET_DUMP_SIZE;
		pm.pm_data_len = sizeof (dump_size);
		pm.pm_data_buf = (caddr_t)&dump_size;

		ret = port->fp_fca_tran->fca_port_manage(
		    port->fp_fca_handle, &pm);

		if (ret != FC_SUCCESS) {
			fcio->fcio_errno = ret;
			rval = EIO;
			if (fp_fcio_copyout(fcio, data, mode)) {
				rval = EFAULT;
			}
			break;
		}
		if (fcio->fcio_olen != dump_size) {
			fcio->fcio_errno = FC_NOMEM;
			rval = EINVAL;
			if (fp_fcio_copyout(fcio, data, mode)) {
				rval = EFAULT;
			}
			break;
		}

		dump = kmem_zalloc(dump_size, KM_SLEEP);

		bzero((caddr_t)&pm, sizeof (pm));
		pm.pm_cmd_flags = FC_FCA_PM_READ;
		pm.pm_cmd_code = FC_PORT_GET_DUMP;
		pm.pm_data_len = dump_size;
		pm.pm_data_buf = dump;

		ret = port->fp_fca_tran->fca_port_manage(
		    port->fp_fca_handle, &pm);

		if (ret == FC_SUCCESS) {
			if (ddi_copyout((void *)dump, (void *)fcio->fcio_obuf,
			    dump_size, mode) == 0) {
				if (fp_fcio_copyout(fcio, data, mode)) {
					rval = EFAULT;
				}
			} else {
				rval = EFAULT;
			}
		} else {
			fcio->fcio_errno = ret;
			rval = EIO;
			if (fp_fcio_copyout(fcio, data, mode)) {
				rval = EFAULT;
			}
		}
		kmem_free(dump, dump_size);
		break;
	}

	case FCIO_GET_TOPOLOGY: {
		uint32_t user_topology;

		if (fcio->fcio_xfer != FCIO_XFER_READ ||
		    fcio->fcio_olen != sizeof (user_topology)) {
			rval = EINVAL;
			break;
		}

		mutex_enter(&port->fp_mutex);
		if (FC_PORT_STATE_MASK(port->fp_state) == FC_STATE_OFFLINE) {
			user_topology = FC_TOP_UNKNOWN;
		} else {
			user_topology = port->fp_topology;
		}
		mutex_exit(&port->fp_mutex);

		if (ddi_copyout((void *)&user_topology,
		    (void *)fcio->fcio_obuf, sizeof (user_topology),
		    mode)) {
			rval = EFAULT;
		}
		break;
	}

	case FCIO_RESET_LINK: {
		la_wwn_t pwwn;

		/*
		 * Look at the output buffer field; if this field has zero
		 * bytes then attempt to reset the local link/loop. If the
		 * fcio_ibuf field points to a WWN, see if it's an NL_Port,
		 * and if yes, determine the LFA and reset the remote LIP
		 * by LINIT ELS.
		 */

		if (fcio->fcio_xfer != FCIO_XFER_WRITE ||
		    fcio->fcio_ilen != sizeof (pwwn)) {
			rval = EINVAL;
			break;
		}

		if (ddi_copyin(fcio->fcio_ibuf, &pwwn,
		    sizeof (pwwn), mode)) {
			rval = EFAULT;
			break;
		}

		mutex_enter(&port->fp_mutex);
		if (port->fp_soft_state & FP_SOFT_IN_LINK_RESET) {
			mutex_exit(&port->fp_mutex);
			break;
		}
		port->fp_soft_state |= FP_SOFT_IN_LINK_RESET;
		mutex_exit(&port->fp_mutex);

		job = fctl_alloc_job(JOB_LINK_RESET, 0, NULL, NULL, KM_SLEEP);
		if (job == NULL) {
			rval = ENOMEM;
			break;
		}
		job->job_counter = 1;
		job->job_private = (void *)&pwwn;

		fctl_enque_job(port, job);
		fctl_jobwait(job);

		mutex_enter(&port->fp_mutex);
		port->fp_soft_state &= ~FP_SOFT_IN_LINK_RESET;
		mutex_exit(&port->fp_mutex);

		if (job->job_result != FC_SUCCESS) {
			fcio->fcio_errno = job->job_result;
			rval = EIO;
			if (fp_fcio_copyout(fcio, data, mode)) {
				rval = EFAULT;
			}
		}
		fctl_dealloc_job(job);
		break;
	}

	case FCIO_RESET_HARD:
		ret = port->fp_fca_tran->fca_reset(
		    port->fp_fca_handle, FC_FCA_RESET);
		if (ret != FC_SUCCESS) {
			fcio->fcio_errno = ret;
			rval = EIO;
			if (fp_fcio_copyout(fcio, data, mode)) {
				rval = EFAULT;
			}
		}
		break;

	case FCIO_RESET_HARD_CORE:
		ret = port->fp_fca_tran->fca_reset(
		    port->fp_fca_handle, FC_FCA_RESET_CORE);
		if (ret != FC_SUCCESS) {
			rval = EIO;
			fcio->fcio_errno = ret;
			if (fp_fcio_copyout(fcio, data, mode)) {
				rval = EFAULT;
			}
		}
		break;

	case FCIO_DIAG: {
		fc_fca_pm_t pm;

		bzero((caddr_t)&pm, sizeof (fc_fca_pm_t));

		/* Validate user buffer from ioctl call. */
		if (((fcio->fcio_ilen > 0) && (fcio->fcio_ibuf == NULL)) ||
		    ((fcio->fcio_ilen <= 0) && (fcio->fcio_ibuf != NULL)) ||
		    ((fcio->fcio_alen > 0) && (fcio->fcio_abuf == NULL)) ||
		    ((fcio->fcio_alen <= 0) && (fcio->fcio_abuf != NULL)) ||
		    ((fcio->fcio_olen > 0) && (fcio->fcio_obuf == NULL)) ||
		    ((fcio->fcio_olen <= 0) && (fcio->fcio_obuf != NULL))) {
			rval = EFAULT;
			break;
		}

		if ((pm.pm_cmd_len = fcio->fcio_ilen) > 0) {
			pm.pm_cmd_buf = kmem_zalloc(fcio->fcio_ilen, KM_SLEEP);
			if (ddi_copyin(fcio->fcio_ibuf, pm.pm_cmd_buf,
			    fcio->fcio_ilen, mode)) {
				rval = EFAULT;
				goto fp_fcio_diag_cleanup;
			}
		}

		if ((pm.pm_data_len = fcio->fcio_alen) > 0) {
			pm.pm_data_buf = kmem_zalloc(fcio->fcio_alen, KM_SLEEP);
			if (ddi_copyin(fcio->fcio_abuf, pm.pm_data_buf,
			    fcio->fcio_alen, mode)) {
				rval = EFAULT;
				goto fp_fcio_diag_cleanup;
			}
		}

		if ((pm.pm_stat_len = fcio->fcio_olen) > 0) {
			pm.pm_stat_buf = kmem_zalloc(fcio->fcio_olen, KM_SLEEP);
		}

		pm.pm_cmd_code = FC_PORT_DIAG;
		pm.pm_cmd_flags = fcio->fcio_cmd_flags;

		ret = port->fp_fca_tran->fca_port_manage(
		    port->fp_fca_handle, &pm);

		if (ret != FC_SUCCESS) {
			if (ret == FC_INVALID_REQUEST) {
				rval = ENOTTY;
			} else {
				rval = EIO;
			}

			fcio->fcio_errno = ret;
			if (fp_fcio_copyout(fcio, data, mode)) {
				rval = EFAULT;
			}
			goto fp_fcio_diag_cleanup;
		}

		/*
		 * pm_stat_len will contain the number of status bytes
		 * an FCA driver requires to return the complete status
		 * of the requested diag operation. If the user buffer
		 * is not large enough to hold the entire status, We
		 * copy only the portion of data the fits in the buffer and
		 * return a ENOMEM to the user application.
		 */
		if (pm.pm_stat_len > fcio->fcio_olen) {
			fp_printf(port, CE_NOTE, FP_LOG_ONLY, 0, NULL,
			    "fp:FCIO_DIAG:status buffer too small\n");

			rval = ENOMEM;
			if (ddi_copyout(pm.pm_stat_buf, fcio->fcio_obuf,
			    fcio->fcio_olen, mode)) {
				rval = EFAULT;
				goto fp_fcio_diag_cleanup;
			}
		} else {
			/*
			 * Copy only data pm_stat_len bytes of data
			 */
			if (ddi_copyout(pm.pm_stat_buf, fcio->fcio_obuf,
			    pm.pm_stat_len, mode)) {
				rval = EFAULT;
				goto fp_fcio_diag_cleanup;
			}
		}

		if (fp_fcio_copyout(fcio, data, mode)) {
			rval = EFAULT;
		}

		fp_fcio_diag_cleanup:
		if (pm.pm_cmd_buf != NULL) {
			kmem_free(pm.pm_cmd_buf, fcio->fcio_ilen);
		}
		if (pm.pm_data_buf != NULL) {
			kmem_free(pm.pm_data_buf, fcio->fcio_alen);
		}
		if (pm.pm_stat_buf != NULL) {
			kmem_free(pm.pm_stat_buf, fcio->fcio_olen);
		}

		break;
	}

	case FCIO_GET_NODE_ID: {
		/* validate parameters */
		if (fcio->fcio_xfer != FCIO_XFER_READ ||
		    fcio->fcio_olen < sizeof (fc_rnid_t)) {
			rval = EINVAL;
			break;
		}

		rval = fp_get_rnid(port, data, mode, fcio);

		/* ioctl handling is over */
		break;
	}

	case FCIO_SEND_NODE_ID: {
		la_wwn_t		pwwn;

		/* validate parameters */
		if (fcio->fcio_ilen != sizeof (la_wwn_t) ||
		    fcio->fcio_xfer != FCIO_XFER_READ) {
			rval = EINVAL;
			break;
		}

		if (ddi_copyin(fcio->fcio_ibuf, &pwwn,
		    sizeof (la_wwn_t), mode)) {
			rval = EFAULT;
			break;
		}

		rval = fp_send_rnid(port, data, mode, fcio, &pwwn);

		/* ioctl handling is over */
		break;
	}

	case FCIO_SET_NODE_ID: {
		if (fcio->fcio_ilen != sizeof (fc_rnid_t) ||
		    (fcio->fcio_xfer != FCIO_XFER_WRITE)) {
			rval = EINVAL;
			break;
		}

		rval = fp_set_rnid(port, data, mode, fcio);
		break;
	}

	case FCIO_LINK_STATUS: {
		fc_portid_t		rls_req;
		fc_rls_acc_t		*rls_acc;
		fc_fca_pm_t		pm;
		uint32_t		dest, src_id;
		fp_cmd_t		*cmd;
		fc_remote_port_t	*pd;
		uchar_t			pd_flags;

		/* validate parameters */
		if (fcio->fcio_ilen != sizeof (fc_portid_t) ||
		    fcio->fcio_olen != sizeof (fc_rls_acc_t) ||
		    fcio->fcio_xfer != FCIO_XFER_RW) {
			rval = EINVAL;
			break;
		}

		if ((fcio->fcio_cmd_flags != FCIO_CFLAGS_RLS_DEST_FPORT) &&
		    (fcio->fcio_cmd_flags != FCIO_CFLAGS_RLS_DEST_NPORT)) {
			rval = EINVAL;
			break;
		}

		if (ddi_copyin((void *)fcio->fcio_ibuf, (void *)&rls_req,
		    sizeof (fc_portid_t), mode)) {
			rval = EFAULT;
			break;
		}


		/* Determine the destination of the RLS frame */
		if (fcio->fcio_cmd_flags == FCIO_CFLAGS_RLS_DEST_FPORT) {
			dest = FS_FABRIC_F_PORT;
		} else {
			dest = rls_req.port_id;
		}

		mutex_enter(&port->fp_mutex);
		src_id = port->fp_port_id.port_id;
		mutex_exit(&port->fp_mutex);

		/* If dest is zero OR same as FCA ID, then use port_manage() */
		if (dest == 0 || dest == src_id) {

			/* Allocate memory for link error status block */
			rls_acc = kmem_zalloc(sizeof (*rls_acc), KM_SLEEP);
			ASSERT(rls_acc != NULL);

			/* Prepare the port management structure */
			bzero((caddr_t)&pm, sizeof (pm));

			pm.pm_cmd_flags = FC_FCA_PM_READ;
			pm.pm_cmd_code	= FC_PORT_RLS;
			pm.pm_data_len	= sizeof (*rls_acc);
			pm.pm_data_buf	= (caddr_t)rls_acc;

			/* Get the adapter's link error status block */
			ret = port->fp_fca_tran->fca_port_manage(
			    port->fp_fca_handle, &pm);

			if (ret == FC_SUCCESS) {
				/* xfer link status block to userland */
				if (ddi_copyout((void *)rls_acc,
				    (void *)fcio->fcio_obuf,
				    sizeof (*rls_acc), mode) == 0) {
					if (fp_fcio_copyout(fcio, data,
					    mode)) {
						rval = EFAULT;
					}
				} else {
					rval = EFAULT;
				}
			} else {
				rval = EIO;
				fcio->fcio_errno = ret;
				if (fp_fcio_copyout(fcio, data, mode)) {
					rval = EFAULT;
				}
			}

			kmem_free(rls_acc, sizeof (*rls_acc));

			/* ioctl handling is over */
			break;
		}

		/*
		 * Send RLS to the destination port.
		 * Having RLS frame destination is as FPORT is not yet
		 * supported and will be implemented in future, if needed.
		 * Following call to get "pd" will fail if dest is FPORT
		 */
		pd = fctl_hold_remote_port_by_did(port, dest);
		if (pd == NULL) {
			fcio->fcio_errno = FC_BADOBJECT;
			rval = ENXIO;
			if (fp_fcio_copyout(fcio, data, mode)) {
				rval = EFAULT;
			}
			break;
		}

		mutex_enter(&pd->pd_mutex);
		if (pd->pd_state != PORT_DEVICE_LOGGED_IN) {
			mutex_exit(&pd->pd_mutex);
			fctl_release_remote_port(pd);

			fcio->fcio_errno = FC_LOGINREQ;
			rval = EINVAL;
			if (fp_fcio_copyout(fcio, data, mode)) {
				rval = EFAULT;
			}
			break;
		}
		ASSERT(pd->pd_login_count >= 1);
		mutex_exit(&pd->pd_mutex);

		/*
		 * Allocate job structure and set job_code as DUMMY,
		 * because we will not go through the job thread.
		 * Instead fp_sendcmd() is called directly here.
		 */
		job = fctl_alloc_job(JOB_DUMMY, JOB_TYPE_FP_ASYNC,
		    NULL, NULL, KM_SLEEP);
		ASSERT(job != NULL);

		job->job_counter = 1;

		cmd = fp_alloc_pkt(port, sizeof (la_els_rls_t),
		    sizeof (la_els_rls_acc_t), KM_SLEEP, pd);
		if (cmd == NULL) {
			fcio->fcio_errno = FC_NOMEM;
			rval = ENOMEM;

			fctl_release_remote_port(pd);

			fctl_dealloc_job(job);
			if (fp_fcio_copyout(fcio, data, mode)) {
				rval = EFAULT;
			}
			break;
		}

		/* Allocate memory for link error status block */
		rls_acc = kmem_zalloc(sizeof (*rls_acc), KM_SLEEP);

		mutex_enter(&port->fp_mutex);
		mutex_enter(&pd->pd_mutex);

		cmd->cmd_pkt.pkt_tran_flags = FC_TRAN_INTR | pd->pd_login_class;
		cmd->cmd_pkt.pkt_tran_type = FC_PKT_EXCHANGE;
		cmd->cmd_flags = FP_CMD_CFLAG_UNDEFINED;
		cmd->cmd_retry_count = 1;
		cmd->cmd_ulp_pkt = NULL;

		fp_rls_init(cmd, job);

		job->job_private = (void *)rls_acc;

		pd_flags = pd->pd_flags;
		pd->pd_flags = PD_ELS_IN_PROGRESS;

		mutex_exit(&pd->pd_mutex);
		mutex_exit(&port->fp_mutex);

		if (fp_sendcmd(port, cmd, port->fp_fca_handle) == FC_SUCCESS) {
			fctl_jobwait(job);

			fcio->fcio_errno = job->job_result;
			if (job->job_result == FC_SUCCESS) {
				ASSERT(pd != NULL);
				/*
				 * link error status block is now available.
				 * Copy it to userland
				 */
				ASSERT(job->job_private == (void *)rls_acc);
				if (ddi_copyout((void *)rls_acc,
				    (void *)fcio->fcio_obuf,
				    sizeof (*rls_acc), mode) == 0) {
					if (fp_fcio_copyout(fcio, data,
					    mode)) {
						rval = EFAULT;
					}
				} else {
					rval = EFAULT;
				}
			} else {
				rval = EIO;
			}
		} else {
			rval = EIO;
			fp_free_pkt(cmd);
		}

		if (rval) {
			mutex_enter(&port->fp_mutex);
			mutex_enter(&pd->pd_mutex);
			if (pd->pd_flags == PD_ELS_IN_PROGRESS) {
				pd->pd_flags = pd_flags;
			}
			mutex_exit(&pd->pd_mutex);
			mutex_exit(&port->fp_mutex);
		}

		fctl_release_remote_port(pd);
		fctl_dealloc_job(job);
		kmem_free(rls_acc, sizeof (*rls_acc));

		if (fp_fcio_copyout(fcio, data, mode)) {
			rval = EFAULT;
		}
		break;
	}

	case FCIO_NS: {
		fc_ns_cmd_t	*ns_req;
		fc_ns_cmd32_t	*ns_req32;
		fctl_ns_req_t	*ns_cmd;

		if (use32 == B_TRUE) {
			if (fcio->fcio_ilen != sizeof (*ns_req32)) {
				rval = EINVAL;
				break;
			}

			ns_req = kmem_zalloc(sizeof (*ns_req), KM_SLEEP);
			ns_req32 = kmem_zalloc(sizeof (*ns_req32), KM_SLEEP);

			if (ddi_copyin(fcio->fcio_ibuf, ns_req32,
			    sizeof (*ns_req32), mode)) {
				rval = EFAULT;
				kmem_free(ns_req, sizeof (*ns_req));
				kmem_free(ns_req32, sizeof (*ns_req32));
				break;
			}

			ns_req->ns_flags = ns_req32->ns_flags;
			ns_req->ns_cmd = ns_req32->ns_cmd;
			ns_req->ns_req_len = ns_req32->ns_req_len;
			ns_req->ns_req_payload = ns_req32->ns_req_payload;
			ns_req->ns_resp_len = ns_req32->ns_resp_len;
			ns_req->ns_resp_payload = ns_req32->ns_resp_payload;
			ns_req->ns_fctl_private = ns_req32->ns_fctl_private;
			ns_req->ns_resp_hdr = ns_req32->ns_resp_hdr;

			kmem_free(ns_req32, sizeof (*ns_req32));
		} else {
			if (fcio->fcio_ilen != sizeof (*ns_req)) {
				rval = EINVAL;
				break;
			}

			ns_req = kmem_zalloc(sizeof (*ns_req), KM_SLEEP);

			if (ddi_copyin(fcio->fcio_ibuf, ns_req,
			    sizeof (fc_ns_cmd_t), mode)) {
				rval = EFAULT;
				kmem_free(ns_req, sizeof (*ns_req));
				break;
			}
		}

		if (ns_req->ns_req_len <= 0) {
			rval = EINVAL;
			kmem_free(ns_req, sizeof (*ns_req));
			break;
		}

		job = fctl_alloc_job(JOB_NS_CMD, 0, NULL, NULL, KM_SLEEP);
		ASSERT(job != NULL);

		ns_cmd = fctl_alloc_ns_cmd(ns_req->ns_req_len,
		    ns_req->ns_resp_len, ns_req->ns_resp_len,
		    FCTL_NS_FILL_NS_MAP, KM_SLEEP);
		ASSERT(ns_cmd != NULL);
		ns_cmd->ns_cmd_code = ns_req->ns_cmd;

		if (ns_cmd->ns_cmd_code == NS_GA_NXT) {
			ns_cmd->ns_gan_max = 1;
			ns_cmd->ns_gan_index = 0;
			ns_cmd->ns_gan_sid = FCTL_GAN_START_ID;
		}

		if (ddi_copyin(ns_req->ns_req_payload,
		    ns_cmd->ns_cmd_buf, ns_req->ns_req_len, mode)) {
			rval = EFAULT;
			fctl_free_ns_cmd(ns_cmd);
			fctl_dealloc_job(job);
			kmem_free(ns_req, sizeof (*ns_req));
			break;
		}

		job->job_private = (void *)ns_cmd;
		fctl_enque_job(port, job);
		fctl_jobwait(job);
		rval = job->job_result;

		if (rval == FC_SUCCESS) {
			if (ns_req->ns_resp_len) {
				if (ddi_copyout(ns_cmd->ns_data_buf,
				    ns_req->ns_resp_payload,
				    ns_cmd->ns_data_len, mode)) {
					rval = EFAULT;
					fctl_free_ns_cmd(ns_cmd);
					fctl_dealloc_job(job);
					kmem_free(ns_req, sizeof (*ns_req));
					break;
				}
			}
		} else {
			rval = EIO;
		}
		ns_req->ns_resp_hdr = ns_cmd->ns_resp_hdr;
		fctl_free_ns_cmd(ns_cmd);
		fctl_dealloc_job(job);
		kmem_free(ns_req, sizeof (*ns_req));

		if (fp_fcio_copyout(fcio, data, mode)) {
			rval = EFAULT;
		}
		break;
	}

	default:
		rval = ENOTTY;
		break;
	}

	/*
	 * If set, reset the EXCL busy bit to
	 * receive other exclusive access commands
	 */
	mutex_enter(&port->fp_mutex);
	if (port->fp_flag & FP_EXCL_BUSY) {
		port->fp_flag &= ~FP_EXCL_BUSY;
	}
	mutex_exit(&port->fp_mutex);

	return (rval);
}


/*
 * This function assumes that the response length
 * is same regardless of data model (LP32 or LP64)
 * which is true for all the ioctls currently
 * supported.
 */
static int
fp_copyout(void *from, void *to, size_t len, int mode)
{
	return (ddi_copyout(from, to, len, mode));
}

/*
 * This function does the set rnid
 */
static int
fp_set_rnid(fc_local_port_t *port, intptr_t data, int mode, fcio_t *fcio)
{
	int		rval = 0;
	fc_rnid_t	*rnid;
	fc_fca_pm_t	pm;

	/* Allocate memory for node id block */
	rnid = kmem_zalloc(sizeof (fc_rnid_t), KM_SLEEP);

	if (ddi_copyin(fcio->fcio_ibuf, rnid, sizeof (fc_rnid_t), mode)) {
		FP_TRACE(FP_NHEAD1(3, 0), "fp_set_rnid: failed = %d", EFAULT);
		kmem_free(rnid, sizeof (fc_rnid_t));
		return (EFAULT);
	}

	/* Prepare the port management structure */
	bzero((caddr_t)&pm, sizeof (pm));

	pm.pm_cmd_flags = FC_FCA_PM_WRITE;
	pm.pm_cmd_code	= FC_PORT_SET_NODE_ID;
	pm.pm_data_len	= sizeof (*rnid);
	pm.pm_data_buf	= (caddr_t)rnid;

	/* Get the adapter's node data */
	rval = port->fp_fca_tran->fca_port_manage(
	    port->fp_fca_handle, &pm);

	if (rval != FC_SUCCESS) {
		fcio->fcio_errno = rval;
		rval = EIO;
		if (fp_fcio_copyout(fcio, data, mode)) {
			rval = EFAULT;
		}
	} else {
		mutex_enter(&port->fp_mutex);
		/* copy to the port structure */
		bcopy(rnid, &port->fp_rnid_params,
		    sizeof (port->fp_rnid_params));
		mutex_exit(&port->fp_mutex);
	}

	kmem_free(rnid, sizeof (fc_rnid_t));

	if (rval != FC_SUCCESS) {
		FP_TRACE(FP_NHEAD1(3, 0), "fp_set_rnid: failed = %d", rval);
	}

	return (rval);
}

/*
 * This function does the local pwwn get rnid
 */
static int
fp_get_rnid(fc_local_port_t *port, intptr_t data, int mode, fcio_t *fcio)
{
	fc_rnid_t		*rnid;
	fc_fca_pm_t		pm;
	int			rval = 0;
	uint32_t		ret;

	/* Allocate memory for rnid data block */
	rnid = kmem_zalloc(sizeof (fc_rnid_t), KM_SLEEP);

	mutex_enter(&port->fp_mutex);
	if (port->fp_rnid_init == 1) {
		bcopy(&port->fp_rnid_params, rnid, sizeof (fc_rnid_t));
		mutex_exit(&port->fp_mutex);
		/* xfer node info to userland */
		if (ddi_copyout((void *)rnid, (void *)fcio->fcio_obuf,
		    sizeof (*rnid), mode) == 0) {
			if (fp_fcio_copyout(fcio, data, mode)) {
				rval = EFAULT;
			}
		} else {
			rval = EFAULT;
		}

		kmem_free(rnid, sizeof (fc_rnid_t));

		if (rval != FC_SUCCESS) {
			FP_TRACE(FP_NHEAD1(3, 0), "fp_get_rnid: failed = %d",
			    rval);
		}

		return (rval);
	}
	mutex_exit(&port->fp_mutex);

	/* Prepare the port management structure */
	bzero((caddr_t)&pm, sizeof (pm));

	pm.pm_cmd_flags = FC_FCA_PM_READ;
	pm.pm_cmd_code	= FC_PORT_GET_NODE_ID;
	pm.pm_data_len	= sizeof (fc_rnid_t);
	pm.pm_data_buf	= (caddr_t)rnid;

	/* Get the adapter's node data */
	ret = port->fp_fca_tran->fca_port_manage(
	    port->fp_fca_handle,
	    &pm);

	if (ret == FC_SUCCESS) {
		/* initialize in the port_info */
		mutex_enter(&port->fp_mutex);
		port->fp_rnid_init = 1;
		bcopy(rnid, &port->fp_rnid_params, sizeof (*rnid));
		mutex_exit(&port->fp_mutex);

		/* xfer node info to userland */
		if (ddi_copyout((void *)rnid,
		    (void *)fcio->fcio_obuf,
		    sizeof (*rnid), mode) == 0) {
			if (fp_fcio_copyout(fcio, data,
			    mode)) {
				rval = EFAULT;
			}
		} else {
			rval = EFAULT;
		}
	} else {
		rval = EIO;
		fcio->fcio_errno = ret;
		if (fp_fcio_copyout(fcio, data, mode)) {
			rval = EFAULT;
		}
	}

	kmem_free(rnid, sizeof (fc_rnid_t));

	if (rval != FC_SUCCESS) {
		FP_TRACE(FP_NHEAD1(3, 0), "fp_get_rnid: failed = %d", rval);
	}

	return (rval);
}

static int
fp_send_rnid(fc_local_port_t *port, intptr_t data, int mode, fcio_t *fcio,
    la_wwn_t *pwwn)
{
	int			rval = 0;
	fc_remote_port_t	*pd;
	fp_cmd_t		*cmd;
	job_request_t		*job;
	la_els_rnid_acc_t	*rnid_acc;

	pd = fctl_get_remote_port_by_pwwn(port, pwwn);
	if (pd == NULL) {
		/*
		 * We can safely assume that the destination port
		 * is logged in. Either the user land will explicitly
		 * login before issuing RNID ioctl or the device would
		 * have been configured, meaning already logged in.
		 */

		FP_TRACE(FP_NHEAD1(3, 0), "fp_send_rnid: failed = %d", ENXIO);

		return (ENXIO);
	}
	/*
	 * Allocate job structure and set job_code as DUMMY,
	 * because we will not go thorugh the job thread.
	 * Instead fp_sendcmd() is called directly here.
	 */
	job = fctl_alloc_job(JOB_DUMMY, JOB_TYPE_FP_ASYNC,
	    NULL, NULL, KM_SLEEP);

	ASSERT(job != NULL);

	job->job_counter = 1;

	cmd = fp_alloc_pkt(port, sizeof (la_els_rnid_t),
	    sizeof (la_els_rnid_acc_t), KM_SLEEP, pd);
	if (cmd == NULL) {
		fcio->fcio_errno = FC_NOMEM;
		rval = ENOMEM;

		fctl_dealloc_job(job);
		if (fp_fcio_copyout(fcio, data, mode)) {
			rval = EFAULT;
		}

		FP_TRACE(FP_NHEAD1(3, 0), "fp_send_rnid: failed = %d", rval);

		return (rval);
	}

	/* Allocate memory for node id accept block */
	rnid_acc = kmem_zalloc(sizeof (la_els_rnid_acc_t), KM_SLEEP);

	mutex_enter(&port->fp_mutex);
	mutex_enter(&pd->pd_mutex);

	cmd->cmd_pkt.pkt_tran_flags = FC_TRAN_INTR | pd->pd_login_class;
	cmd->cmd_pkt.pkt_tran_type = FC_PKT_EXCHANGE;
	cmd->cmd_flags = FP_CMD_CFLAG_UNDEFINED;
	cmd->cmd_retry_count = 1;
	cmd->cmd_ulp_pkt = NULL;

	fp_rnid_init(cmd, fcio->fcio_cmd_flags, job);

	job->job_private = (void *)rnid_acc;

	pd->pd_flags = PD_ELS_IN_PROGRESS;

	mutex_exit(&pd->pd_mutex);
	mutex_exit(&port->fp_mutex);

	if (fp_sendcmd(port, cmd, port->fp_fca_handle) == FC_SUCCESS) {
		fctl_jobwait(job);
		fcio->fcio_errno = job->job_result;
		if (job->job_result == FC_SUCCESS) {
			int rnid_cnt;
			ASSERT(pd != NULL);
			/*
			 * node id block is now available.
			 * Copy it to userland
			 */
			ASSERT(job->job_private == (void *)rnid_acc);

			/* get the response length */
			rnid_cnt = sizeof (ls_code_t) + sizeof (fc_rnid_hdr_t) +
			    rnid_acc->hdr.cmn_len +
			    rnid_acc->hdr.specific_len;

			if (fcio->fcio_olen < rnid_cnt) {
				rval = EINVAL;
			} else if (ddi_copyout((void *)rnid_acc,
			    (void *)fcio->fcio_obuf,
			    rnid_cnt, mode) == 0) {
				if (fp_fcio_copyout(fcio, data,
				    mode)) {
					rval = EFAULT;
				}
			} else {
				rval = EFAULT;
			}
		} else {
			rval = EIO;
		}
	} else {
		rval = EIO;
		if (pd) {
			mutex_enter(&pd->pd_mutex);
			pd->pd_flags = PD_IDLE;
			mutex_exit(&pd->pd_mutex);
		}
		fp_free_pkt(cmd);
	}

	fctl_dealloc_job(job);
	kmem_free(rnid_acc, sizeof (la_els_rnid_acc_t));

	if (fp_fcio_copyout(fcio, data, mode)) {
		rval = EFAULT;
	}

	if (rval != FC_SUCCESS) {
		FP_TRACE(FP_NHEAD1(3, 0), "fp_send_rnid: failed = %d", rval);
	}

	return (rval);
}

/*
 * Copy out to userland
 */
static int
fp_fcio_copyout(fcio_t *fcio, intptr_t data, int mode)
{
	int rval;

#ifdef	_MULTI_DATAMODEL
	switch (ddi_model_convert_from(mode & FMODELS)) {
	case DDI_MODEL_ILP32: {
		struct fcio32 fcio32;

		fcio32.fcio_xfer = fcio->fcio_xfer;
		fcio32.fcio_cmd = fcio->fcio_cmd;
		fcio32.fcio_flags = fcio->fcio_flags;
		fcio32.fcio_cmd_flags = fcio->fcio_cmd_flags;
		fcio32.fcio_ilen = fcio->fcio_ilen;
		fcio32.fcio_ibuf =
		    (caddr32_t)(uintptr_t)fcio->fcio_ibuf;
		fcio32.fcio_olen = fcio->fcio_olen;
		fcio32.fcio_obuf =
		    (caddr32_t)(uintptr_t)fcio->fcio_obuf;
		fcio32.fcio_alen = fcio->fcio_alen;
		fcio32.fcio_abuf =
		    (caddr32_t)(uintptr_t)fcio->fcio_abuf;
		fcio32.fcio_errno = fcio->fcio_errno;

		rval = ddi_copyout((void *)&fcio32, (void *)data,
		    sizeof (struct fcio32), mode);
		break;
	}
	case DDI_MODEL_NONE:
		rval = ddi_copyout((void *)fcio, (void *)data,
		    sizeof (fcio_t), mode);
		break;
	}
#else
	rval = ddi_copyout((void *)fcio, (void *)data, sizeof (fcio_t), mode);
#endif

	return (rval);
}


static void
fp_p2p_online(fc_local_port_t *port, job_request_t *job)
{
	uint32_t		listlen;
	fc_portmap_t		*changelist;

	ASSERT(MUTEX_HELD(&port->fp_mutex));
	ASSERT(port->fp_topology == FC_TOP_PT_PT);
	ASSERT((job->job_flags & JOB_TYPE_FP_ASYNC) == 0);

	listlen = 0;
	changelist = NULL;

	if ((job->job_flags & JOB_CANCEL_ULP_NOTIFICATION) == 0) {
		if (port->fp_statec_busy > 1) {
			job->job_flags |= JOB_CANCEL_ULP_NOTIFICATION;
		}
	}
	mutex_exit(&port->fp_mutex);

	if ((job->job_flags & JOB_CANCEL_ULP_NOTIFICATION) == 0) {
		fctl_fillout_map(port, &changelist, &listlen, 1, 0, 0);
		(void) fp_ulp_statec_cb(port, FC_STATE_ONLINE, changelist,
		    listlen, listlen, KM_SLEEP);

		mutex_enter(&port->fp_mutex);
	} else {
		ASSERT(changelist == NULL && listlen == 0);
		mutex_enter(&port->fp_mutex);
		if (--port->fp_statec_busy == 0) {
			port->fp_soft_state &= ~FP_SOFT_IN_STATEC_CB;
		}
	}
}

static int
fp_fillout_p2pmap(fc_local_port_t *port, fcio_t *fcio, int mode)
{
	int			rval;
	int			count;
	int			index;
	int			num_devices;
	fc_remote_node_t	*node;
	fc_port_dev_t		*devlist;
	struct pwwn_hash	*head;
	fc_remote_port_t	*pd;

	ASSERT(MUTEX_HELD(&port->fp_mutex));

	num_devices = fcio->fcio_olen / sizeof (fc_port_dev_t);

	devlist = kmem_zalloc(sizeof (fc_port_dev_t) * num_devices, KM_SLEEP);

	for (count = index = 0; index < pwwn_table_size; index++) {
		head = &port->fp_pwwn_table[index];
		pd = head->pwwn_head;
		while (pd != NULL) {
			mutex_enter(&pd->pd_mutex);
			if (pd->pd_state == PORT_DEVICE_INVALID) {
				mutex_exit(&pd->pd_mutex);
				pd = pd->pd_wwn_hnext;
				continue;
			}

			devlist[count].dev_state = pd->pd_state;
			devlist[count].dev_hard_addr = pd->pd_hard_addr;
			devlist[count].dev_did = pd->pd_port_id;
			devlist[count].dev_did.priv_lilp_posit =
			    (uint8_t)(index & 0xff);
			bcopy((caddr_t)pd->pd_fc4types,
			    (caddr_t)devlist[count].dev_type,
			    sizeof (pd->pd_fc4types));

			bcopy((caddr_t)&pd->pd_port_name,
			    (caddr_t)&devlist[count].dev_pwwn,
			    sizeof (la_wwn_t));

			node = pd->pd_remote_nodep;
			mutex_exit(&pd->pd_mutex);

			if (node) {
				mutex_enter(&node->fd_mutex);
				bcopy((caddr_t)&node->fd_node_name,
				    (caddr_t)&devlist[count].dev_nwwn,
				    sizeof (la_wwn_t));
				mutex_exit(&node->fd_mutex);
			}
			count++;
			if (count >= num_devices) {
				goto found;
			}
		}
	}
found:
	if (fp_copyout((void *)&count, (void *)fcio->fcio_abuf,
	    sizeof (count), mode)) {
		rval = FC_FAILURE;
	} else if (fp_copyout((void *)devlist, (void *)fcio->fcio_obuf,
	    sizeof (fc_port_dev_t) * num_devices, mode)) {
		rval = FC_FAILURE;
	} else {
		rval = FC_SUCCESS;
	}

	kmem_free(devlist, sizeof (fc_port_dev_t) * num_devices);

	return (rval);
}


/*
 * Handle Fabric ONLINE
 */
static void
fp_fabric_online(fc_local_port_t *port, job_request_t *job)
{
	int			index;
	int			rval;
	int			dbg_count;
	int			count = 0;
	char			ww_name[17];
	uint32_t		d_id;
	uint32_t		listlen;
	fctl_ns_req_t		*ns_cmd;
	struct pwwn_hash	*head;
	fc_remote_port_t	*pd;
	fc_remote_port_t	*npd;
	fc_portmap_t		*changelist;

	ASSERT(MUTEX_HELD(&port->fp_mutex));
	ASSERT(FC_IS_TOP_SWITCH(port->fp_topology));
	ASSERT((job->job_flags & JOB_TYPE_FP_ASYNC) == 0);

	ns_cmd = fctl_alloc_ns_cmd(sizeof (ns_req_gid_pn_t),
	    sizeof (ns_resp_gid_pn_t), sizeof (ns_resp_gid_pn_t),
	    0, KM_SLEEP);

	ASSERT(ns_cmd != NULL);

	ns_cmd->ns_cmd_code = NS_GID_PN;

	/*
	 * Check if orphans are showing up now
	 */
	if (port->fp_orphan_count) {
		fc_orphan_t	*orp;
		fc_orphan_t	*norp = NULL;
		fc_orphan_t	*prev = NULL;

		for (orp = port->fp_orphan_list; orp; orp = norp) {
			norp = orp->orp_next;
			mutex_exit(&port->fp_mutex);
			orp->orp_nscan++;

			job->job_counter = 1;
			job->job_result = FC_SUCCESS;

			((ns_req_gid_pn_t *)
			    (ns_cmd->ns_cmd_buf))->pwwn = orp->orp_pwwn;
			((ns_resp_gid_pn_t *)
			    ns_cmd->ns_data_buf)->pid.port_id = 0;
			((ns_resp_gid_pn_t *)
			    ns_cmd->ns_data_buf)->pid.priv_lilp_posit = 0;

			rval = fp_ns_query(port, ns_cmd, job, 1, KM_SLEEP);
			if (rval == FC_SUCCESS) {
				d_id =
				    BE_32(*((uint32_t *)ns_cmd->ns_data_buf));
				pd = fp_create_remote_port_by_ns(port,
				    d_id, KM_SLEEP);

				if (pd != NULL) {
					fc_wwn_to_str(&orp->orp_pwwn, ww_name);

					fp_printf(port, CE_WARN, FP_LOG_ONLY,
					    0, NULL, "N_x Port with D_ID=%x,"
					    " PWWN=%s reappeared in fabric",
					    d_id, ww_name);

					mutex_enter(&port->fp_mutex);
					if (prev) {
						prev->orp_next = orp->orp_next;
					} else {
						ASSERT(orp ==
						    port->fp_orphan_list);
						port->fp_orphan_list =
						    orp->orp_next;
					}
					port->fp_orphan_count--;
					mutex_exit(&port->fp_mutex);
					kmem_free(orp, sizeof (*orp));
					count++;

					mutex_enter(&pd->pd_mutex);
					pd->pd_flags = PD_ELS_MARK;

					mutex_exit(&pd->pd_mutex);
				} else {
					prev = orp;
				}
			} else {
				if (orp->orp_nscan == FC_ORPHAN_SCAN_LIMIT) {
					fc_wwn_to_str(&orp->orp_pwwn, ww_name);

					fp_printf(port, CE_NOTE, FP_LOG_ONLY, 0,
					    NULL,
					    " Port WWN %s removed from orphan"
					    " list after %d scans", ww_name,
					    orp->orp_nscan);

					mutex_enter(&port->fp_mutex);
					if (prev) {
						prev->orp_next = orp->orp_next;
					} else {
						ASSERT(orp ==
						    port->fp_orphan_list);
						port->fp_orphan_list =
						    orp->orp_next;
					}
					port->fp_orphan_count--;
					mutex_exit(&port->fp_mutex);

					kmem_free(orp, sizeof (*orp));
				} else {
					prev = orp;
				}
			}
			mutex_enter(&port->fp_mutex);
		}
	}

	/*
	 * Walk the Port WWN hash table, reestablish LOGIN
	 * if a LOGIN is already performed on a particular
	 * device; Any failure to LOGIN should mark the
	 * port device OLD.
	 */
	for (index = 0; index < pwwn_table_size; index++) {
		head = &port->fp_pwwn_table[index];
		npd = head->pwwn_head;

		while ((pd = npd) != NULL) {
			la_wwn_t	*pwwn;

			npd = pd->pd_wwn_hnext;

			/*
			 * Don't count in the port devices that are new
			 * unless the total number of devices visible
			 * through this port is less than FP_MAX_DEVICES
			 */
			mutex_enter(&pd->pd_mutex);
			if (port->fp_dev_count >= FP_MAX_DEVICES ||
			    (port->fp_options & FP_TARGET_MODE)) {
				if (pd->pd_type == PORT_DEVICE_NEW ||
				    pd->pd_flags == PD_ELS_MARK ||
				    pd->pd_recepient != PD_PLOGI_INITIATOR) {
					mutex_exit(&pd->pd_mutex);
					continue;
				}
			} else {
				if (pd->pd_flags == PD_ELS_MARK ||
				    pd->pd_recepient != PD_PLOGI_INITIATOR) {
					mutex_exit(&pd->pd_mutex);
					continue;
				}
				pd->pd_type = PORT_DEVICE_OLD;
			}
			count++;

			/*
			 * Consult with the name server about D_ID changes
			 */
			job->job_counter = 1;
			job->job_result = FC_SUCCESS;

			((ns_req_gid_pn_t *)
			    (ns_cmd->ns_cmd_buf))->pwwn = pd->pd_port_name;
			((ns_resp_gid_pn_t *)
			    ns_cmd->ns_data_buf)->pid.port_id = 0;

			((ns_resp_gid_pn_t *)ns_cmd->ns_data_buf)->
			    pid.priv_lilp_posit = 0;

			pwwn = &pd->pd_port_name;
			pd->pd_flags = PD_ELS_MARK;

			mutex_exit(&pd->pd_mutex);
			mutex_exit(&port->fp_mutex);

			rval = fp_ns_query(port, ns_cmd, job, 1, KM_SLEEP);
			if (rval != FC_SUCCESS) {
				fc_wwn_to_str(pwwn, ww_name);

				mutex_enter(&pd->pd_mutex);
				d_id = pd->pd_port_id.port_id;
				pd->pd_type = PORT_DEVICE_DELETE;
				mutex_exit(&pd->pd_mutex);

				FP_TRACE(FP_NHEAD1(3, 0),
				    "fp_fabric_online: PD "
				    "disappeared; d_id=%x, PWWN=%s",
				    d_id, ww_name);

				FP_TRACE(FP_NHEAD2(9, 0),
				    "N_x Port with D_ID=%x, PWWN=%s"
				    " disappeared from fabric", d_id,
				    ww_name);

				mutex_enter(&port->fp_mutex);
				continue;
			}

			d_id = BE_32(*((uint32_t *)ns_cmd->ns_data_buf));

			mutex_enter(&port->fp_mutex);
			mutex_enter(&pd->pd_mutex);
			if (d_id != pd->pd_port_id.port_id) {
				fctl_delist_did_table(port, pd);
				fc_wwn_to_str(pwwn, ww_name);

				FP_TRACE(FP_NHEAD2(9, 0),
				    "D_ID of a device with PWWN %s changed."
				    " New D_ID = %x, OLD D_ID = %x", ww_name,
				    d_id, pd->pd_port_id.port_id);

				pd->pd_port_id.port_id = BE_32(d_id);
				pd->pd_type = PORT_DEVICE_CHANGED;
				fctl_enlist_did_table(port, pd);
			}
			mutex_exit(&pd->pd_mutex);

		}
	}

	if (ns_cmd) {
		fctl_free_ns_cmd(ns_cmd);
	}

	listlen = 0;
	changelist = NULL;
	if (count) {
		if (port->fp_soft_state & FP_SOFT_IN_FCA_RESET) {
			port->fp_soft_state &= ~FP_SOFT_IN_FCA_RESET;
			mutex_exit(&port->fp_mutex);
			delay(drv_usectohz(FLA_RR_TOV * 1000 * 1000));
			mutex_enter(&port->fp_mutex);
		}

		dbg_count = 0;

		job->job_counter = count;

		for (index = 0; index < pwwn_table_size; index++) {
			head = &port->fp_pwwn_table[index];
			npd = head->pwwn_head;

			while ((pd = npd) != NULL) {
				npd = pd->pd_wwn_hnext;

				mutex_enter(&pd->pd_mutex);
				if (pd->pd_flags != PD_ELS_MARK) {
					mutex_exit(&pd->pd_mutex);
					continue;
				}

				dbg_count++;

				/*
				 * If it is already marked deletion, nothing
				 * else to do.
				 */
				if (pd->pd_type == PORT_DEVICE_DELETE) {
					pd->pd_type = PORT_DEVICE_OLD;

					mutex_exit(&pd->pd_mutex);
					mutex_exit(&port->fp_mutex);
					fp_jobdone(job);
					mutex_enter(&port->fp_mutex);

					continue;
				}

				/*
				 * If it is freshly discovered out of
				 * the orphan list, nothing else to do
				 */
				if (pd->pd_type == PORT_DEVICE_NEW) {
					pd->pd_flags = PD_IDLE;

					mutex_exit(&pd->pd_mutex);
					mutex_exit(&port->fp_mutex);
					fp_jobdone(job);
					mutex_enter(&port->fp_mutex);

					continue;
				}

				pd->pd_flags = PD_IDLE;
				d_id = pd->pd_port_id.port_id;

				/*
				 * Explicitly mark all devices OLD; successful
				 * PLOGI should reset this to either NO_CHANGE
				 * or CHANGED.
				 */
				if (pd->pd_type != PORT_DEVICE_CHANGED) {
					pd->pd_type = PORT_DEVICE_OLD;
				}

				mutex_exit(&pd->pd_mutex);
				mutex_exit(&port->fp_mutex);

				rval = fp_port_login(port, d_id, job,
				    FP_CMD_PLOGI_RETAIN, KM_SLEEP, pd, NULL);

				if (rval != FC_SUCCESS) {
					fp_jobdone(job);
				}
				mutex_enter(&port->fp_mutex);
			}
		}
		mutex_exit(&port->fp_mutex);

		ASSERT(dbg_count == count);
		fp_jobwait(job);

		mutex_enter(&port->fp_mutex);

		ASSERT(port->fp_statec_busy > 0);
		if ((job->job_flags & JOB_CANCEL_ULP_NOTIFICATION) == 0) {
			if (port->fp_statec_busy > 1) {
				job->job_flags |= JOB_CANCEL_ULP_NOTIFICATION;
			}
		}
		mutex_exit(&port->fp_mutex);
	} else {
		ASSERT(port->fp_statec_busy > 0);
		if (port->fp_statec_busy > 1) {
			job->job_flags |= JOB_CANCEL_ULP_NOTIFICATION;
		}
		mutex_exit(&port->fp_mutex);
	}

	if ((job->job_flags & JOB_CANCEL_ULP_NOTIFICATION) == 0) {
		fctl_fillout_map(port, &changelist, &listlen, 1, 0, 0);

		(void) fp_ulp_statec_cb(port, FC_STATE_ONLINE, changelist,
		    listlen, listlen, KM_SLEEP);

		mutex_enter(&port->fp_mutex);
	} else {
		ASSERT(changelist == NULL && listlen == 0);
		mutex_enter(&port->fp_mutex);
		if (--port->fp_statec_busy == 0) {
			port->fp_soft_state &= ~FP_SOFT_IN_STATEC_CB;
		}
	}
}


/*
 * Fill out device list for userland ioctl in private loop
 */
static int
fp_fillout_loopmap(fc_local_port_t *port, fcio_t *fcio, int mode)
{
	int			rval;
	int			count;
	int			index;
	int			num_devices;
	fc_remote_node_t	*node;
	fc_port_dev_t		*devlist;
	int			lilp_device_count;
	fc_lilpmap_t		*lilp_map;
	uchar_t			*alpa_list;

	ASSERT(MUTEX_HELD(&port->fp_mutex));

	num_devices = fcio->fcio_olen / sizeof (fc_port_dev_t);
	if (port->fp_total_devices > port->fp_dev_count &&
	    num_devices >= port->fp_total_devices) {
		job_request_t	*job;

		mutex_exit(&port->fp_mutex);
		job = fctl_alloc_job(JOB_PORT_GETMAP, 0, NULL, NULL, KM_SLEEP);
		job->job_counter = 1;

		mutex_enter(&port->fp_mutex);
		fp_get_loopmap(port, job);
		mutex_exit(&port->fp_mutex);

		fp_jobwait(job);
		fctl_dealloc_job(job);
	} else {
		mutex_exit(&port->fp_mutex);
	}
	devlist = kmem_zalloc(sizeof (*devlist) * num_devices, KM_SLEEP);

	mutex_enter(&port->fp_mutex);

	/*
	 * Applications are accustomed to getting the device list in
	 * LILP map order. The HBA firmware usually returns the device
	 * map in the LILP map order and diagnostic applications would
	 * prefer to receive in the device list in that order too
	 */
	lilp_map = &port->fp_lilp_map;
	alpa_list = &lilp_map->lilp_alpalist[0];

	/*
	 * the length field corresponds to the offset in the LILP frame
	 * which begins with 1. The thing to note here is that the
	 * lilp_device_count is 1 more than fp->fp_total_devices since
	 * the host adapter's alpa also shows up in the lilp map. We
	 * don't however return details of the host adapter since
	 * fctl_get_remote_port_by_did fails for the host adapter's ALPA
	 * and applications are required to issue the FCIO_GET_HOST_PARAMS
	 * ioctl to obtain details about the host adapter port.
	 */
	lilp_device_count = lilp_map->lilp_length;

	for (count = index = 0; index < lilp_device_count &&
	    count < num_devices; index++) {
		uint32_t d_id;
		fc_remote_port_t *pd;

		d_id = alpa_list[index];

		mutex_exit(&port->fp_mutex);
		pd = fctl_get_remote_port_by_did(port, d_id);
		mutex_enter(&port->fp_mutex);

		if (pd != NULL) {
			mutex_enter(&pd->pd_mutex);

			if (pd->pd_state == PORT_DEVICE_INVALID) {
				mutex_exit(&pd->pd_mutex);
				continue;
			}

			devlist[count].dev_state = pd->pd_state;
			devlist[count].dev_hard_addr = pd->pd_hard_addr;
			devlist[count].dev_did = pd->pd_port_id;
			devlist[count].dev_did.priv_lilp_posit =
			    (uint8_t)(index & 0xff);
			bcopy((caddr_t)pd->pd_fc4types,
			    (caddr_t)devlist[count].dev_type,
			    sizeof (pd->pd_fc4types));

			bcopy((caddr_t)&pd->pd_port_name,
			    (caddr_t)&devlist[count].dev_pwwn,
			    sizeof (la_wwn_t));

			node = pd->pd_remote_nodep;
			mutex_exit(&pd->pd_mutex);

			if (node) {
				mutex_enter(&node->fd_mutex);
				bcopy((caddr_t)&node->fd_node_name,
				    (caddr_t)&devlist[count].dev_nwwn,
				    sizeof (la_wwn_t));
				mutex_exit(&node->fd_mutex);
			}
			count++;
		}
	}

	if (fp_copyout((void *)&count, (void *)fcio->fcio_abuf,
	    sizeof (count), mode)) {
		rval = FC_FAILURE;
	}

	if (fp_copyout((void *)devlist, (void *)fcio->fcio_obuf,
	    sizeof (fc_port_dev_t) * num_devices, mode)) {
		rval = FC_FAILURE;
	} else {
		rval = FC_SUCCESS;
	}

	kmem_free(devlist, sizeof (*devlist) * num_devices);
	ASSERT(MUTEX_HELD(&port->fp_mutex));

	return (rval);
}


/*
 * Completion function for responses to unsolicited commands
 */
static void
fp_unsol_intr(fc_packet_t *pkt)
{
	fp_cmd_t	*cmd;
	fc_local_port_t *port;

	cmd = pkt->pkt_ulp_private;
	port = cmd->cmd_port;

	mutex_enter(&port->fp_mutex);
	port->fp_out_fpcmds--;
	mutex_exit(&port->fp_mutex);

	if (pkt->pkt_state != FC_PKT_SUCCESS) {
		fp_printf(port, CE_WARN, FP_LOG_ONLY, 0, pkt,
		    "couldn't post response to unsolicited request;"
		    " ox_id=%x rx_id=%x", pkt->pkt_cmd_fhdr.ox_id,
		    pkt->pkt_resp_fhdr.rx_id);
	}

	if (cmd == port->fp_els_resp_pkt) {
		mutex_enter(&port->fp_mutex);
		port->fp_els_resp_pkt_busy = 0;
		mutex_exit(&port->fp_mutex);
		return;
	}

	fp_free_pkt(cmd);
}


/*
 * solicited LINIT ELS completion function
 */
static void
fp_linit_intr(fc_packet_t *pkt)
{
	fp_cmd_t		*cmd;
	job_request_t		*job;
	fc_linit_resp_t		acc;
	fc_local_port_t *port = ((fp_cmd_t *)pkt->pkt_ulp_private)->cmd_port;

	cmd = (fp_cmd_t *)pkt->pkt_ulp_private;

	mutex_enter(&cmd->cmd_port->fp_mutex);
	cmd->cmd_port->fp_out_fpcmds--;
	mutex_exit(&cmd->cmd_port->fp_mutex);

	if (FP_IS_PKT_ERROR(pkt)) {
		(void) fp_common_intr(pkt, 1);
		return;
	}

	job = cmd->cmd_job;

	FC_GET_RSP(port, pkt->pkt_resp_acc, (uint8_t *)&acc,
	    (uint8_t *)pkt->pkt_resp, sizeof (acc), DDI_DEV_AUTOINCR);
	if (acc.status != FC_LINIT_SUCCESS) {
		job->job_result = FC_FAILURE;
	} else {
		job->job_result = FC_SUCCESS;
	}

	fp_iodone(cmd);
}


/*
 * Decode the unsolicited request; For FC-4 Device and Link data frames
 * notify the registered ULP of this FC-4 type right here. For Unsolicited
 * ELS requests, submit a request to the job_handler thread to work on it.
 * The intent is to act quickly on the FC-4 unsolicited link and data frames
 * and save much of the interrupt time processing of unsolicited ELS requests
 * and hand it off to the job_handler thread.
 */
static void
fp_unsol_cb(opaque_t port_handle, fc_unsol_buf_t *buf, uint32_t type)
{
	uchar_t		r_ctl;
	uchar_t		ls_code;
	uint32_t	s_id;
	uint32_t	rscn_count = FC_INVALID_RSCN_COUNT;
	uint32_t	cb_arg;
	fp_cmd_t	*cmd;
	fc_local_port_t *port;
	job_request_t	*job;
	fc_remote_port_t	*pd;

	port = port_handle;

	FP_TRACE(FP_NHEAD1(1, 0), "fp_unsol_cb: s_id=%x,"
	    " d_id=%x, type=%x, r_ctl=%x, f_ctl=%x"
	    " seq_id=%x, df_ctl=%x, seq_cnt=%x, ox_id=%x, rx_id=%x"
	    " ro=%x, buffer[0]:%x", buf->ub_frame.s_id, buf->ub_frame.d_id,
	    buf->ub_frame.type, buf->ub_frame.r_ctl, buf->ub_frame.f_ctl,
	    buf->ub_frame.seq_id, buf->ub_frame.df_ctl, buf->ub_frame.seq_cnt,
	    buf->ub_frame.ox_id, buf->ub_frame.rx_id, buf->ub_frame.ro,
	    buf->ub_buffer[0]);

	if (type & 0x80000000) {
		/*
		 * Huh ? Nothing much can be done without
		 * a valid buffer. So just exit.
		 */
		return;
	}
	/*
	 * If the unsolicited interrupts arrive while it isn't
	 * safe to handle unsolicited callbacks; Drop them, yes,
	 * drop them on the floor
	 */
	mutex_enter(&port->fp_mutex);
	port->fp_active_ubs++;
	if ((port->fp_soft_state &
	    (FP_SOFT_IN_DETACH | FP_SOFT_SUSPEND | FP_SOFT_POWER_DOWN)) ||
	    FC_PORT_STATE_MASK(port->fp_state) == FC_STATE_OFFLINE) {

		FP_TRACE(FP_NHEAD1(3, 0), "fp_unsol_cb: port state is "
		    "not ONLINE. s_id=%x, d_id=%x, type=%x, "
		    "seq_id=%x, ox_id=%x, rx_id=%x"
		    "ro=%x", buf->ub_frame.s_id, buf->ub_frame.d_id,
		    buf->ub_frame.type, buf->ub_frame.seq_id,
		    buf->ub_frame.ox_id, buf->ub_frame.rx_id, buf->ub_frame.ro);

		ASSERT(port->fp_active_ubs > 0);
		if (--(port->fp_active_ubs) == 0) {
			port->fp_soft_state &= ~FP_SOFT_IN_UNSOL_CB;
		}

		mutex_exit(&port->fp_mutex);

		port->fp_fca_tran->fca_ub_release(port->fp_fca_handle,
		    1, &buf->ub_token);

		return;
	}

	r_ctl = buf->ub_frame.r_ctl;
	s_id = buf->ub_frame.s_id;
	if (port->fp_active_ubs == 1) {
		port->fp_soft_state |= FP_SOFT_IN_UNSOL_CB;
	}

	if (r_ctl == R_CTL_ELS_REQ && buf->ub_buffer[0] == LA_ELS_LOGO &&
	    port->fp_statec_busy) {
		mutex_exit(&port->fp_mutex);
		pd = fctl_get_remote_port_by_did(port, s_id);
		if (pd) {
			mutex_enter(&pd->pd_mutex);
			if (pd->pd_state == PORT_DEVICE_LOGGED_IN) {
				FP_TRACE(FP_NHEAD1(3, 0),
				    "LOGO for LOGGED IN D_ID %x",
				    buf->ub_frame.s_id);
				pd->pd_state = PORT_DEVICE_VALID;
			}
			mutex_exit(&pd->pd_mutex);
		}

		mutex_enter(&port->fp_mutex);
		ASSERT(port->fp_active_ubs > 0);
		if (--(port->fp_active_ubs) == 0) {
			port->fp_soft_state &= ~FP_SOFT_IN_UNSOL_CB;
		}
		mutex_exit(&port->fp_mutex);

		port->fp_fca_tran->fca_ub_release(port->fp_fca_handle,
		    1, &buf->ub_token);

		FP_TRACE(FP_NHEAD1(3, 0),
		    "fp_unsol_cb() bailing out LOGO for D_ID %x",
		    buf->ub_frame.s_id);
		return;
	}

	if (port->fp_els_resp_pkt_busy == 0) {
		if (r_ctl == R_CTL_ELS_REQ) {
			ls_code = buf->ub_buffer[0];

			switch (ls_code) {
			case LA_ELS_PLOGI:
			case LA_ELS_FLOGI:
				port->fp_els_resp_pkt_busy = 1;
				mutex_exit(&port->fp_mutex);
				fp_i_handle_unsol_els(port, buf);

				mutex_enter(&port->fp_mutex);
				ASSERT(port->fp_active_ubs > 0);
				if (--(port->fp_active_ubs) == 0) {
					port->fp_soft_state &=
					    ~FP_SOFT_IN_UNSOL_CB;
				}
				mutex_exit(&port->fp_mutex);
				port->fp_fca_tran->fca_ub_release(
				    port->fp_fca_handle, 1, &buf->ub_token);

				return;
			case LA_ELS_RSCN:
				if (++(port)->fp_rscn_count ==
				    FC_INVALID_RSCN_COUNT) {
					++(port)->fp_rscn_count;
				}
				rscn_count = port->fp_rscn_count;
				break;

			default:
				break;
			}
		}
	} else if ((r_ctl == R_CTL_ELS_REQ) &&
	    (buf->ub_buffer[0] == LA_ELS_RSCN)) {
		if (++port->fp_rscn_count == FC_INVALID_RSCN_COUNT) {
			++port->fp_rscn_count;
		}
		rscn_count = port->fp_rscn_count;
	}

	mutex_exit(&port->fp_mutex);

	switch (r_ctl & R_CTL_ROUTING) {
	case R_CTL_DEVICE_DATA:
		/*
		 * If the unsolicited buffer is a CT IU,
		 * have the job_handler thread work on it.
		 */
		if (buf->ub_frame.type == FC_TYPE_FC_SERVICES) {
			break;
		}
		/* FALLTHROUGH */

	case R_CTL_FC4_SVC: {
		int sendup = 0;

		/*
		 * If a LOGIN isn't performed before this request
		 * shut the door on this port with a reply that a
		 * LOGIN is required. We make an exception however
		 * for IP broadcast packets and pass them through
		 * to the IP ULP(s) to handle broadcast requests.
		 * This is not a problem for private loop devices
		 * but for fabric topologies we don't log into the
		 * remote ports during port initialization and
		 * the ULPs need to log into requesting ports on
		 * demand.
		 */
		pd = fctl_get_remote_port_by_did(port, s_id);
		if (pd) {
			mutex_enter(&pd->pd_mutex);
			if (pd->pd_state == PORT_DEVICE_LOGGED_IN) {
				sendup++;
			}
			mutex_exit(&pd->pd_mutex);
		} else if ((pd == NULL) &&
		    (buf->ub_frame.type == FC_TYPE_IS8802_SNAP) &&
		    (buf->ub_frame.d_id == 0xffffff ||
		    buf->ub_frame.d_id == 0x00)) {
			/* brodacst IP frame - so sendup via job thread */
			break;
		}

		/*
		 * Send all FC4 services via job thread too
		 */
		if ((r_ctl & R_CTL_ROUTING) == R_CTL_FC4_SVC) {
			break;
		}

		if (sendup || !FC_IS_REAL_DEVICE(s_id)) {
			fctl_ulp_unsol_cb(port, buf, buf->ub_frame.type);
			return;
		}

		if (FP_IS_CLASS_1_OR_2(buf->ub_class)) {
			cmd = fp_alloc_pkt(port, sizeof (la_els_rjt_t),
			    0, KM_NOSLEEP, pd);
			if (cmd != NULL) {
				fp_els_rjt_init(port, cmd, buf,
				    FC_ACTION_NON_RETRYABLE,
				    FC_REASON_LOGIN_REQUIRED, NULL);

				if (fp_sendcmd(port, cmd,
				    port->fp_fca_handle) != FC_SUCCESS) {
					fp_free_pkt(cmd);
				}
			}
		}

		mutex_enter(&port->fp_mutex);
		ASSERT(port->fp_active_ubs > 0);
		if (--(port->fp_active_ubs) == 0) {
			port->fp_soft_state &= ~FP_SOFT_IN_UNSOL_CB;
		}
		mutex_exit(&port->fp_mutex);
		port->fp_fca_tran->fca_ub_release(port->fp_fca_handle,
		    1, &buf->ub_token);

		return;
	}

	default:
		break;
	}

	/*
	 * Submit a Request to the job_handler thread to work
	 * on the unsolicited request. The potential side effect
	 * of this is that the unsolicited buffer takes a little
	 * longer to get released but we save interrupt time in
	 * the bargain.
	 */
	cb_arg = (rscn_count == FC_INVALID_RSCN_COUNT) ? 0 : rscn_count;

	/*
	 * One way that the rscn_count will get used is described below :
	 *
	 * 1. fp_unsol_cb() gets an RSCN and updates fp_rscn_count.
	 * 2. Before mutex is released, a copy of it is stored in rscn_count.
	 * 3. The count is passed to job thread as JOB_UNSOL_REQUEST (below)
	 *    by overloading the job_cb_arg to pass the rscn_count
	 * 4. When one of the routines processing the RSCN picks it up (ex:
	 *    fp_validate_rscn_page()), it passes this count in the map
	 *    structure (as part of the map_rscn_info structure member) to the
	 *    ULPs.
	 * 5. When ULPs make calls back to the transport (example interfaces for
	 *    this are fc_ulp_transport(), fc_ulp_login(), fc_issue_els()), they
	 *    can now pass back this count as part of the fc_packet's
	 *    pkt_ulp_rscn_count member. fcp does this currently.
	 * 6. When transport gets a call to transport a command on the wire, it
	 *    will check to see if there is a valid pkt_ulp_rsvd1 field in the
	 *    fc_packet. If there is, it will match that info with the current
	 *    rscn_count on that instance of the port. If they don't match up
	 *    then there was a newer RSCN. The ULP gets back an error code which
	 *    informs it about it - FC_DEVICE_BUSY_NEW_RSCN.
	 * 7. At this point the ULP is free to make up its own mind as to how to
	 *    handle this. Currently, fcp will reset its retry counters and keep
	 *    retrying the operation it was doing in anticipation of getting a
	 *    new state change call back for the new RSCN.
	 */
	job = fctl_alloc_job(JOB_UNSOL_REQUEST, 0, NULL,
	    (opaque_t)(uintptr_t)cb_arg, KM_NOSLEEP);
	if (job == NULL) {
		fp_printf(port, CE_NOTE, FP_LOG_ONLY, 0, NULL, "fp_unsol_cb() "
		    "couldn't submit a job to the thread, failing..");

		mutex_enter(&port->fp_mutex);

		if (--port->fp_rscn_count == FC_INVALID_RSCN_COUNT) {
			--port->fp_rscn_count;
		}

		ASSERT(port->fp_active_ubs > 0);
		if (--(port->fp_active_ubs) == 0) {
			port->fp_soft_state &= ~FP_SOFT_IN_UNSOL_CB;
		}

		mutex_exit(&port->fp_mutex);
		port->fp_fca_tran->fca_ub_release(port->fp_fca_handle,
		    1, &buf->ub_token);

		return;
	}
	job->job_private = (void *)buf;
	fctl_enque_job(port, job);
}


/*
 * Handle unsolicited requests
 */
static void
fp_handle_unsol_buf(fc_local_port_t *port, fc_unsol_buf_t *buf,
    job_request_t *job)
{
	uchar_t			r_ctl;
	uchar_t			ls_code;
	uint32_t		s_id;
	fp_cmd_t		*cmd;
	fc_remote_port_t	*pd;
	fp_unsol_spec_t		*ub_spec;

	r_ctl = buf->ub_frame.r_ctl;
	s_id = buf->ub_frame.s_id;

	switch (r_ctl & R_CTL_ROUTING) {
	case R_CTL_EXTENDED_SVC:
		if (r_ctl != R_CTL_ELS_REQ) {
			break;
		}

		ls_code = buf->ub_buffer[0];
		switch (ls_code) {
		case LA_ELS_LOGO:
		case LA_ELS_ADISC:
		case LA_ELS_PRLO:
			pd = fctl_get_remote_port_by_did(port, s_id);
			if (pd == NULL) {
				if (!FC_IS_REAL_DEVICE(s_id)) {
					break;
				}
				if (!FP_IS_CLASS_1_OR_2(buf->ub_class)) {
					break;
				}
				if ((cmd = fp_alloc_pkt(port,
				    sizeof (la_els_rjt_t), 0, KM_SLEEP,
				    NULL)) == NULL) {
					/*
					 * Can this actually fail when
					 * given KM_SLEEP?  (Could be used
					 * this way in a number of places.)
					 */
					break;
				}

				fp_els_rjt_init(port, cmd, buf,
				    FC_ACTION_NON_RETRYABLE,
				    FC_REASON_INVALID_LINK_CTRL, job);

				if (fp_sendcmd(port, cmd,
				    port->fp_fca_handle) != FC_SUCCESS) {
					fp_free_pkt(cmd);
				}

				break;
			}
			if (ls_code == LA_ELS_LOGO) {
				fp_handle_unsol_logo(port, buf, pd, job);
			} else if (ls_code == LA_ELS_ADISC) {
				fp_handle_unsol_adisc(port, buf, pd, job);
			} else {
				fp_handle_unsol_prlo(port, buf, pd, job);
			}
			break;

		case LA_ELS_PLOGI:
			fp_handle_unsol_plogi(port, buf, job, KM_SLEEP);
			break;

		case LA_ELS_FLOGI:
			fp_handle_unsol_flogi(port, buf, job, KM_SLEEP);
			break;

		case LA_ELS_RSCN:
			fp_handle_unsol_rscn(port, buf, job, KM_SLEEP);
			break;

		default:
			ub_spec = kmem_zalloc(sizeof (*ub_spec), KM_SLEEP);
			ub_spec->port = port;
			ub_spec->buf = buf;

			(void) taskq_dispatch(port->fp_taskq,
			    fp_ulp_unsol_cb, ub_spec, KM_SLEEP);
			return;
		}
		break;

	case R_CTL_BASIC_SVC:
		/*
		 * The unsolicited basic link services could be ABTS
		 * and RMC (Or even a NOP). Just BA_RJT them until
		 * such time there arises a need to handle them more
		 * carefully.
		 */
		if (FP_IS_CLASS_1_OR_2(buf->ub_class)) {
			cmd = fp_alloc_pkt(port, sizeof (la_ba_rjt_t),
			    0, KM_SLEEP, NULL);
			if (cmd != NULL) {
				fp_ba_rjt_init(port, cmd, buf, job);
				if (fp_sendcmd(port, cmd,
				    port->fp_fca_handle) != FC_SUCCESS) {
					fp_free_pkt(cmd);
				}
			}
		}
		break;

	case R_CTL_DEVICE_DATA:
		if (buf->ub_frame.type == FC_TYPE_FC_SERVICES) {
			/*
			 * Mostly this is of type FC_TYPE_FC_SERVICES.
			 * As we don't like any Unsolicited FC services
			 * requests, we would do well to RJT them as
			 * well.
			 */
			if (FP_IS_CLASS_1_OR_2(buf->ub_class)) {
				cmd = fp_alloc_pkt(port, sizeof (la_els_rjt_t),
				    0, KM_SLEEP, NULL);
				if (cmd != NULL) {
					fp_els_rjt_init(port, cmd, buf,
					    FC_ACTION_NON_RETRYABLE,
					    FC_REASON_INVALID_LINK_CTRL, job);

					if (fp_sendcmd(port, cmd,
					    port->fp_fca_handle) !=
					    FC_SUCCESS) {
						fp_free_pkt(cmd);
					}
				}
			}
			break;
		}
		/* FALLTHROUGH */

	case R_CTL_FC4_SVC:
		ub_spec = kmem_zalloc(sizeof (*ub_spec), KM_SLEEP);
		ub_spec->port = port;
		ub_spec->buf = buf;

		(void) taskq_dispatch(port->fp_taskq,
		    fp_ulp_unsol_cb, ub_spec, KM_SLEEP);
		return;

	case R_CTL_LINK_CTL:
		/*
		 * Turn deaf ear on unsolicited link control frames.
		 * Typical unsolicited link control Frame is an LCR
		 * (to reset End to End credit to the default login
		 * value and abort current sequences for all classes)
		 * An intelligent microcode/firmware should handle
		 * this transparently at its level and not pass all
		 * the way up here.
		 *
		 * Possible responses to LCR are R_RDY, F_RJT, P_RJT
		 * or F_BSY. P_RJT is chosen to be the most appropriate
		 * at this time.
		 */
		/* FALLTHROUGH */

	default:
		/*
		 * Just reject everything else as an invalid request.
		 */
		if (FP_IS_CLASS_1_OR_2(buf->ub_class)) {
			cmd = fp_alloc_pkt(port, sizeof (la_els_rjt_t),
			    0, KM_SLEEP, NULL);
			if (cmd != NULL) {
				fp_els_rjt_init(port, cmd, buf,
				    FC_ACTION_NON_RETRYABLE,
				    FC_REASON_INVALID_LINK_CTRL, job);

				if (fp_sendcmd(port, cmd,
				    port->fp_fca_handle) != FC_SUCCESS) {
					fp_free_pkt(cmd);
				}
			}
		}
		break;
	}

	mutex_enter(&port->fp_mutex);
	ASSERT(port->fp_active_ubs > 0);
	if (--(port->fp_active_ubs) == 0) {
		port->fp_soft_state &= ~FP_SOFT_IN_UNSOL_CB;
	}
	mutex_exit(&port->fp_mutex);
	port->fp_fca_tran->fca_ub_release(port->fp_fca_handle,
	    1, &buf->ub_token);
}


/*
 * Prepare a BA_RJT and send it over.
 */
static void
fp_ba_rjt_init(fc_local_port_t *port, fp_cmd_t *cmd, fc_unsol_buf_t *buf,
    job_request_t *job)
{
	fc_packet_t	*pkt;
	la_ba_rjt_t	payload;

	ASSERT(!MUTEX_HELD(&port->fp_mutex));

	cmd->cmd_pkt.pkt_tran_flags = buf->ub_class;
	cmd->cmd_pkt.pkt_tran_type = FC_PKT_OUTBOUND;
	cmd->cmd_flags = FP_CMD_CFLAG_UNDEFINED;
	cmd->cmd_retry_count = 1;
	cmd->cmd_ulp_pkt = NULL;

	cmd->cmd_transport = port->fp_fca_tran->fca_els_send;
	cmd->cmd_job = job;

	pkt = &cmd->cmd_pkt;

	fp_unsol_resp_init(pkt, buf, R_CTL_LS_BA_RJT, FC_TYPE_BASIC_LS);

	payload.reserved = 0;
	payload.reason_code = FC_REASON_CMD_UNSUPPORTED;
	payload.explanation = FC_EXPLN_NONE;
	payload.vendor = 0;

	FC_SET_CMD(port, pkt->pkt_cmd_acc, (uint8_t *)&payload,
	    (uint8_t *)pkt->pkt_cmd, sizeof (payload), DDI_DEV_AUTOINCR);
}


/*
 * Prepare an LS_RJT and send it over
 */
static void
fp_els_rjt_init(fc_local_port_t *port, fp_cmd_t *cmd, fc_unsol_buf_t *buf,
    uchar_t action, uchar_t reason, job_request_t *job)
{
	fc_packet_t	*pkt;
	la_els_rjt_t	payload;

	ASSERT(!MUTEX_HELD(&port->fp_mutex));

	cmd->cmd_pkt.pkt_tran_flags = buf->ub_class;
	cmd->cmd_pkt.pkt_tran_type = FC_PKT_OUTBOUND;
	cmd->cmd_flags = FP_CMD_CFLAG_UNDEFINED;
	cmd->cmd_retry_count = 1;
	cmd->cmd_ulp_pkt = NULL;

	cmd->cmd_transport = port->fp_fca_tran->fca_els_send;
	cmd->cmd_job = job;

	pkt = &cmd->cmd_pkt;

	fp_unsol_resp_init(pkt, buf, R_CTL_ELS_RSP, FC_TYPE_EXTENDED_LS);

	payload.ls_code.ls_code = LA_ELS_RJT;
	payload.ls_code.mbz = 0;
	payload.action = action;
	payload.reason = reason;
	payload.reserved = 0;
	payload.vu = 0;

	FC_SET_CMD(port, pkt->pkt_cmd_acc, (uint8_t *)&payload,
	    (uint8_t *)pkt->pkt_cmd, sizeof (payload), DDI_DEV_AUTOINCR);
}

/*
 *     Function: fp_prlo_acc_init
 *
 *  Description: Initializes an Link Service Accept for a PRLO.
 *
 *    Arguments: *port		Local port through which the PRLO was
 *				received.
 *		 cmd		Command that will carry the accept.
 *		 *buf		Unsolicited buffer containing the PRLO
 *				request.
 *		 job		Job request.
 *		 sleep		Allocation mode.
 *
 * Return Value: *cmd		Command containing the response.
 *
 *	Context: Depends on the parameter sleep.
 */
fp_cmd_t *
fp_prlo_acc_init(fc_local_port_t *port, fc_remote_port_t *pd,
    fc_unsol_buf_t *buf, job_request_t *job, int sleep)
{
	fp_cmd_t	*cmd;
	fc_packet_t	*pkt;
	la_els_prlo_t	*req;
	size_t		len;
	uint16_t	flags;

	req = (la_els_prlo_t *)buf->ub_buffer;
	len = (size_t)ntohs(req->payload_length);

	/*
	 * The payload of the accept to a PRLO has to be the exact match of
	 * the payload of the request (at the exception of the code).
	 */
	cmd = fp_alloc_pkt(port, (int)len, 0, sleep, pd);

	if (cmd) {
		/*
		 * The fp command was successfully allocated.
		 */
		cmd->cmd_pkt.pkt_tran_flags = buf->ub_class;
		cmd->cmd_pkt.pkt_tran_type = FC_PKT_OUTBOUND;
		cmd->cmd_flags = FP_CMD_CFLAG_UNDEFINED;
		cmd->cmd_retry_count = 1;
		cmd->cmd_ulp_pkt = NULL;

		cmd->cmd_transport = port->fp_fca_tran->fca_els_send;
		cmd->cmd_job = job;

		pkt = &cmd->cmd_pkt;

		fp_unsol_resp_init(pkt, buf, R_CTL_ELS_RSP,
		    FC_TYPE_EXTENDED_LS);

		/* The code is overwritten for the copy. */
		req->ls_code = LA_ELS_ACC;
		/* Response code is set. */
		flags = ntohs(req->flags);
		flags &= ~SP_RESP_CODE_MASK;
		flags |= SP_RESP_CODE_REQ_EXECUTED;
		req->flags = htons(flags);

		FC_SET_CMD(port, pkt->pkt_cmd_acc, (uint8_t *)req,
		    (uint8_t *)pkt->pkt_cmd, len, DDI_DEV_AUTOINCR);
	}
	return (cmd);
}

/*
 * Prepare an ACC response to an ELS request
 */
static void
fp_els_acc_init(fc_local_port_t *port, fp_cmd_t *cmd, fc_unsol_buf_t *buf,
    job_request_t *job)
{
	fc_packet_t	*pkt;
	ls_code_t	payload;

	cmd->cmd_pkt.pkt_tran_flags = buf->ub_class;
	cmd->cmd_pkt.pkt_tran_type = FC_PKT_OUTBOUND;
	cmd->cmd_flags = FP_CMD_CFLAG_UNDEFINED;
	cmd->cmd_retry_count = 1;
	cmd->cmd_ulp_pkt = NULL;

	cmd->cmd_transport = port->fp_fca_tran->fca_els_send;
	cmd->cmd_job = job;

	pkt = &cmd->cmd_pkt;

	fp_unsol_resp_init(pkt, buf, R_CTL_ELS_RSP, FC_TYPE_EXTENDED_LS);

	payload.ls_code = LA_ELS_ACC;
	payload.mbz = 0;

	FC_SET_CMD(port, pkt->pkt_cmd_acc, (uint8_t *)&payload,
	    (uint8_t *)pkt->pkt_cmd, sizeof (payload), DDI_DEV_AUTOINCR);
}

/*
 * Unsolicited PRLO handler
 *
 * A Process Logout should be handled by the ULP that established it.  However,
 * some devices send a PRLO to trigger a PLOGI followed by a PRLI.  This happens
 * when a device implicitly logs out an initiator (for whatever reason) and
 * tries to get that initiator to restablish the connection (PLOGI and PRLI).
 * The logical thing to do for the device would be to send a LOGO in response
 * to any FC4 frame sent by the initiator. Some devices choose, however, to send
 * a PRLO instead.
 *
 * From a Fibre Channel standpoint a PRLO calls for a PRLI. There's no reason to
 * think that the Port Login has been lost.  If we follow the Fibre Channel
 * protocol to the letter a PRLI should be sent after accepting the PRLO.  If
 * the Port Login has also been lost, the remote port will reject the PRLI
 * indicating that we must PLOGI first.	 The initiator will then turn around and
 * send a PLOGI.  The way Leadville is layered and the way the ULP interface
 * is defined doesn't allow this scenario to be followed easily.  If FCP were to
 * handle the PRLO and attempt the PRLI, the reject indicating that a PLOGI is
 * needed would be received by FCP. FCP would have, then, to tell the transport
 * (fp) to PLOGI.  The problem is, the transport would still think the Port
 * Login is valid and there is no way for FCP to tell the transport: "PLOGI even
 * if you think it's not necessary".  To work around that difficulty, the PRLO
 * is treated by the transport as a LOGO.  The downside to it is a Port Login
 * may be disrupted (if a PLOGI wasn't actually needed) and another ULP (that
 * has nothing to do with the PRLO) may be impacted.  However, this is a
 * scenario very unlikely to happen.  As of today the only ULP in Leadville
 * using PRLI/PRLOs is FCP.  For a PRLO to disrupt another ULP (that would be
 * FCIP), a SCSI target would have to be running FCP and FCIP (which is very
 * unlikely).
 */
static void
fp_handle_unsol_prlo(fc_local_port_t *port, fc_unsol_buf_t *buf,
    fc_remote_port_t *pd, job_request_t *job)
{
	int		busy;
	int		rval;
	int		retain;
	fp_cmd_t	*cmd;
	fc_portmap_t	*listptr;
	boolean_t	tolerance;
	la_els_prlo_t	*req;

	req = (la_els_prlo_t *)buf->ub_buffer;

	if ((ntohs(req->payload_length) !=
	    (sizeof (service_parameter_page_t) + sizeof (ls_code_t))) ||
	    (req->page_length != sizeof (service_parameter_page_t))) {
		/*
		 * We are being very restrictive.  Only on page per
		 * payload.  If it is not the case we reject the ELS although
		 * we should reply indicating we handle only single page
		 * per PRLO.
		 */
		goto fp_reject_prlo;
	}

	if (ntohs(req->payload_length) > buf->ub_bufsize) {
		/*
		 * This is in case the payload advertizes a size bigger than
		 * what it really is.
		 */
		goto fp_reject_prlo;
	}

	mutex_enter(&port->fp_mutex);
	busy = port->fp_statec_busy;
	mutex_exit(&port->fp_mutex);

	mutex_enter(&pd->pd_mutex);
	tolerance = fctl_tc_increment(&pd->pd_logo_tc);
	if (!busy) {
		if (pd->pd_state != PORT_DEVICE_LOGGED_IN ||
		    pd->pd_state == PORT_DEVICE_INVALID ||
		    pd->pd_flags == PD_ELS_IN_PROGRESS ||
		    pd->pd_type == PORT_DEVICE_OLD) {
			busy++;
		}
	}

	if (busy) {
		mutex_exit(&pd->pd_mutex);

		FP_TRACE(FP_NHEAD1(5, 0), "Logout; D_ID=%x,"
		    "pd=%p - busy",
		    pd->pd_port_id.port_id, pd);

		if (FP_IS_CLASS_1_OR_2(buf->ub_class)) {
			goto fp_reject_prlo;
		}
	} else {
		retain = (pd->pd_recepient == PD_PLOGI_INITIATOR) ? 1 : 0;

		if (tolerance) {
			fctl_tc_reset(&pd->pd_logo_tc);
			retain = 0;
			pd->pd_state = PORT_DEVICE_INVALID;
		}

		FP_TRACE(FP_NHEAD1(5, 0), "Accepting LOGO; d_id=%x, pd=%p,"
		    " tolerance=%d retain=%d", pd->pd_port_id.port_id, pd,
		    tolerance, retain);

		pd->pd_aux_flags |= PD_LOGGED_OUT;
		mutex_exit(&pd->pd_mutex);

		cmd = fp_prlo_acc_init(port, pd, buf, job, KM_SLEEP);
		if (cmd == NULL) {
			return;
		}

		rval = fp_sendcmd(port, cmd, port->fp_fca_handle);
		if (rval != FC_SUCCESS) {
			fp_free_pkt(cmd);
			return;
		}

		listptr = kmem_zalloc(sizeof (fc_portmap_t), KM_SLEEP);

		if (retain) {
			fp_unregister_login(pd);
			fctl_copy_portmap(listptr, pd);
		} else {
			uint32_t	d_id;
			char		ww_name[17];

			mutex_enter(&pd->pd_mutex);
			d_id = pd->pd_port_id.port_id;
			fc_wwn_to_str(&pd->pd_port_name, ww_name);
			mutex_exit(&pd->pd_mutex);

			FP_TRACE(FP_NHEAD2(9, 0),
			    "N_x Port with D_ID=%x, PWWN=%s logged out"
			    " %d times in %d us; Giving up", d_id, ww_name,
			    FC_LOGO_TOLERANCE_LIMIT,
			    FC_LOGO_TOLERANCE_TIME_LIMIT);

			fp_fillout_old_map(listptr, pd, 0);
			listptr->map_type = PORT_DEVICE_OLD;
		}

		(void) fp_ulp_devc_cb(port, listptr, 1, 1, KM_SLEEP, 0);
		return;
	}

fp_reject_prlo:

	cmd = fp_alloc_pkt(port, sizeof (la_els_rjt_t), 0, KM_SLEEP, pd);
	if (cmd != NULL) {
		fp_els_rjt_init(port, cmd, buf, FC_ACTION_NON_RETRYABLE,
		    FC_REASON_INVALID_LINK_CTRL, job);

		if (fp_sendcmd(port, cmd, port->fp_fca_handle) != FC_SUCCESS) {
			fp_free_pkt(cmd);
		}
	}
}

/*
 * Unsolicited LOGO handler
 */
static void
fp_handle_unsol_logo(fc_local_port_t *port, fc_unsol_buf_t *buf,
    fc_remote_port_t *pd, job_request_t *job)
{
	int		busy;
	int		rval;
	int		retain;
	fp_cmd_t	*cmd;
	fc_portmap_t	*listptr;
	boolean_t	tolerance;

	mutex_enter(&port->fp_mutex);
	busy = port->fp_statec_busy;
	mutex_exit(&port->fp_mutex);

	mutex_enter(&pd->pd_mutex);
	tolerance = fctl_tc_increment(&pd->pd_logo_tc);
	if (!busy) {
		if (pd->pd_state != PORT_DEVICE_LOGGED_IN ||
		    pd->pd_state == PORT_DEVICE_INVALID ||
		    pd->pd_flags == PD_ELS_IN_PROGRESS ||
		    pd->pd_type == PORT_DEVICE_OLD) {
			busy++;
		}
	}

	if (busy) {
		mutex_exit(&pd->pd_mutex);

		FP_TRACE(FP_NHEAD1(5, 0), "Logout; D_ID=%x,"
		    "pd=%p - busy",
		    pd->pd_port_id.port_id, pd);

		if (FP_IS_CLASS_1_OR_2(buf->ub_class)) {
			cmd = fp_alloc_pkt(port, sizeof (la_els_rjt_t),
			    0, KM_SLEEP, pd);
			if (cmd != NULL) {
				fp_els_rjt_init(port, cmd, buf,
				    FC_ACTION_NON_RETRYABLE,
				    FC_REASON_INVALID_LINK_CTRL, job);

				if (fp_sendcmd(port, cmd,
				    port->fp_fca_handle) != FC_SUCCESS) {
					fp_free_pkt(cmd);
				}
			}
		}
	} else {
		retain = (pd->pd_recepient == PD_PLOGI_INITIATOR) ? 1 : 0;

		if (tolerance) {
			fctl_tc_reset(&pd->pd_logo_tc);
			retain = 0;
			pd->pd_state = PORT_DEVICE_INVALID;
		}

		FP_TRACE(FP_NHEAD1(5, 0), "Accepting LOGO; d_id=%x, pd=%p,"
		    " tolerance=%d retain=%d", pd->pd_port_id.port_id, pd,
		    tolerance, retain);

		pd->pd_aux_flags |= PD_LOGGED_OUT;
		mutex_exit(&pd->pd_mutex);

		cmd = fp_alloc_pkt(port, FP_PORT_IDENTIFIER_LEN, 0,
		    KM_SLEEP, pd);
		if (cmd == NULL) {
			return;
		}

		fp_els_acc_init(port, cmd, buf, job);

		rval = fp_sendcmd(port, cmd, port->fp_fca_handle);
		if (rval != FC_SUCCESS) {
			fp_free_pkt(cmd);
			return;
		}

		listptr = kmem_zalloc(sizeof (fc_portmap_t), KM_SLEEP);

		if (retain) {
			job_request_t	*job;
			fctl_ns_req_t	*ns_cmd;

			/*
			 * when get LOGO, first try to get PID from nameserver
			 * if failed, then we do not need
			 * send PLOGI to that remote port
			 */
			job = fctl_alloc_job(
			    JOB_NS_CMD, 0, NULL, (opaque_t)port, KM_SLEEP);

			if (job != NULL) {
				ns_cmd = fctl_alloc_ns_cmd(
				    sizeof (ns_req_gid_pn_t),
				    sizeof (ns_resp_gid_pn_t),
				    sizeof (ns_resp_gid_pn_t),
				    0, KM_SLEEP);
				if (ns_cmd != NULL) {
					int ret;
					job->job_result = FC_SUCCESS;
					ns_cmd->ns_cmd_code = NS_GID_PN;
					((ns_req_gid_pn_t *)
					    (ns_cmd->ns_cmd_buf))->pwwn =
					    pd->pd_port_name;
					ret = fp_ns_query(
					    port, ns_cmd, job, 1, KM_SLEEP);
					if ((ret != FC_SUCCESS) ||
					    (job->job_result != FC_SUCCESS)) {
						fctl_free_ns_cmd(ns_cmd);
						fctl_dealloc_job(job);
						FP_TRACE(FP_NHEAD2(9, 0),
						    "NS query failed,",
						    " delete pd");
						goto delete_pd;
					}
					fctl_free_ns_cmd(ns_cmd);
				}
				fctl_dealloc_job(job);
			}
			fp_unregister_login(pd);
			fctl_copy_portmap(listptr, pd);
		} else {
			uint32_t	d_id;
			char		ww_name[17];

		delete_pd:
			mutex_enter(&pd->pd_mutex);
			d_id = pd->pd_port_id.port_id;
			fc_wwn_to_str(&pd->pd_port_name, ww_name);
			mutex_exit(&pd->pd_mutex);

			FP_TRACE(FP_NHEAD2(9, 0),
			    "N_x Port with D_ID=%x, PWWN=%s logged out"
			    " %d times in %d us; Giving up", d_id, ww_name,
			    FC_LOGO_TOLERANCE_LIMIT,
			    FC_LOGO_TOLERANCE_TIME_LIMIT);

			fp_fillout_old_map(listptr, pd, 0);
			listptr->map_type = PORT_DEVICE_OLD;
		}

		(void) fp_ulp_devc_cb(port, listptr, 1, 1, KM_SLEEP, 0);
	}
}


/*
 * Perform general purpose preparation of a response to an unsolicited request
 */
static void
fp_unsol_resp_init(fc_packet_t *pkt, fc_unsol_buf_t *buf,
    uchar_t r_ctl, uchar_t type)
{
	pkt->pkt_cmd_fhdr.r_ctl = r_ctl;
	pkt->pkt_cmd_fhdr.d_id = buf->ub_frame.s_id;
	pkt->pkt_cmd_fhdr.s_id = buf->ub_frame.d_id;
	pkt->pkt_cmd_fhdr.type = type;
	pkt->pkt_cmd_fhdr.f_ctl = F_CTL_LAST_SEQ | F_CTL_XCHG_CONTEXT;
	pkt->pkt_cmd_fhdr.seq_id = buf->ub_frame.seq_id;
	pkt->pkt_cmd_fhdr.df_ctl  = buf->ub_frame.df_ctl;
	pkt->pkt_cmd_fhdr.seq_cnt = buf->ub_frame.seq_cnt;
	pkt->pkt_cmd_fhdr.ox_id = buf->ub_frame.ox_id;
	pkt->pkt_cmd_fhdr.rx_id = buf->ub_frame.rx_id;
	pkt->pkt_cmd_fhdr.ro = 0;
	pkt->pkt_cmd_fhdr.rsvd = 0;
	pkt->pkt_comp = fp_unsol_intr;
	pkt->pkt_timeout = FP_ELS_TIMEOUT;
	pkt->pkt_ub_resp_token = (opaque_t)buf;
}

/*
 * Immediate handling of unsolicited FLOGI and PLOGI requests. In the
 * early development days of public loop soc+ firmware, numerous problems
 * were encountered (the details are undocumented and history now) which
 * led to the birth of this function.
 *
 * If a pre-allocated unsolicited response packet is free, send out an
 * immediate response, otherwise submit the request to the port thread
 * to do the deferred processing.
 */
static void
fp_i_handle_unsol_els(fc_local_port_t *port, fc_unsol_buf_t *buf)
{
	int			sent;
	int			f_port;
	int			do_acc;
	fp_cmd_t		*cmd;
	la_els_logi_t		*payload;
	fc_remote_port_t	*pd;
	char			dww_name[17];

	ASSERT(!MUTEX_HELD(&port->fp_mutex));

	cmd = port->fp_els_resp_pkt;

	mutex_enter(&port->fp_mutex);
	do_acc = (port->fp_statec_busy == 0) ? 1 : 0;
	mutex_exit(&port->fp_mutex);

	switch (buf->ub_buffer[0]) {
	case LA_ELS_PLOGI: {
		int small;

		payload = (la_els_logi_t *)buf->ub_buffer;

		f_port = FP_IS_F_PORT(payload->
		    common_service.cmn_features) ? 1 : 0;

		small = fctl_wwn_cmp(&port->fp_service_params.nport_ww_name,
		    &payload->nport_ww_name);
		pd = fctl_get_remote_port_by_pwwn(port,
		    &payload->nport_ww_name);
		if (pd) {
			mutex_enter(&pd->pd_mutex);
			sent = (pd->pd_flags == PD_ELS_IN_PROGRESS) ? 1 : 0;
			/*
			 * Most likely this means a cross login is in
			 * progress or a device about to be yanked out.
			 * Only accept the plogi if my wwn is smaller.
			 */
			if (pd->pd_type == PORT_DEVICE_OLD) {
				sent = 1;
			}
			/*
			 * Stop plogi request (if any)
			 * attempt from local side to speedup
			 * the discovery progress.
			 * Mark the pd as PD_PLOGI_RECEPIENT.
			 */
			if (f_port == 0 && small < 0) {
				pd->pd_recepient = PD_PLOGI_RECEPIENT;
			}
			fc_wwn_to_str(&pd->pd_port_name, dww_name);

			mutex_exit(&pd->pd_mutex);

			FP_TRACE(FP_NHEAD1(3, 0), "fp_i_handle_unsol_els: "
			    "Unsol PLOGI received. PD still exists in the "
			    "PWWN list. pd=%p PWWN=%s, sent=%x",
			    pd, dww_name, sent);

			if (f_port == 0 && small < 0) {
				FP_TRACE(FP_NHEAD1(3, 0),
				    "fp_i_handle_unsol_els: Mark the pd"
				    " as plogi recipient, pd=%p, PWWN=%s"
				    ", sent=%x",
				    pd, dww_name, sent);
			}
		} else {
			sent = 0;
		}

		/*
		 * To avoid Login collisions, accept only if my WWN
		 * is smaller than the requester (A curious side note
		 * would be that this rule may not satisfy the PLOGIs
		 * initiated by the switch from not-so-well known
		 * ports such as 0xFFFC41)
		 */
		if ((f_port == 0 && small < 0) ||
		    (((small > 0 && do_acc) ||
		    FC_MUST_ACCEPT_D_ID(buf->ub_frame.s_id)) && sent == 0)) {
			if (fp_is_class_supported(port->fp_cos,
			    buf->ub_class) == FC_FAILURE) {
				if (FP_IS_CLASS_1_OR_2(buf->ub_class)) {
					cmd->cmd_pkt.pkt_cmdlen =
					    sizeof (la_els_rjt_t);
					cmd->cmd_pkt.pkt_rsplen = 0;
					fp_els_rjt_init(port, cmd, buf,
					    FC_ACTION_NON_RETRYABLE,
					    FC_REASON_CLASS_NOT_SUPP, NULL);
					FP_TRACE(FP_NHEAD1(3, 0),
					    "fp_i_handle_unsol_els: "
					    "Unsupported class. "
					    "Rejecting PLOGI");

				} else {
					mutex_enter(&port->fp_mutex);
					port->fp_els_resp_pkt_busy = 0;
					mutex_exit(&port->fp_mutex);
					return;
				}
			} else {
				cmd->cmd_pkt.pkt_cmdlen =
				    sizeof (la_els_logi_t);
				cmd->cmd_pkt.pkt_rsplen = 0;

				/*
				 * If fp_port_id is zero and topology is
				 * Point-to-Point, get the local port id from
				 * the d_id in the PLOGI request.
				 * If the outgoing FLOGI hasn't been accepted,
				 * the topology will be unknown here. But it's
				 * still safe to save the d_id to fp_port_id,
				 * just because it will be overwritten later
				 * if the topology is not Point-to-Point.
				 */
				mutex_enter(&port->fp_mutex);
				if ((port->fp_port_id.port_id == 0) &&
				    (port->fp_topology == FC_TOP_PT_PT ||
				    port->fp_topology == FC_TOP_UNKNOWN)) {
					port->fp_port_id.port_id =
					    buf->ub_frame.d_id;
				}
				mutex_exit(&port->fp_mutex);

				/*
				 * Sometime later, we should validate
				 * the service parameters instead of
				 * just accepting it.
				 */
				fp_login_acc_init(port, cmd, buf, NULL,
				    KM_NOSLEEP);
				FP_TRACE(FP_NHEAD1(3, 0),
				    "fp_i_handle_unsol_els: Accepting PLOGI,"
				    " f_port=%d, small=%d, do_acc=%d,"
				    " sent=%d.", f_port, small, do_acc,
				    sent);
			}
		} else {
			if (FP_IS_CLASS_1_OR_2(buf->ub_class) ||
			    port->fp_options & FP_SEND_RJT) {
				cmd->cmd_pkt.pkt_cmdlen = sizeof (la_els_rjt_t);
				cmd->cmd_pkt.pkt_rsplen = 0;
				fp_els_rjt_init(port, cmd, buf,
				    FC_ACTION_NON_RETRYABLE,
				    FC_REASON_LOGICAL_BSY, NULL);
				FP_TRACE(FP_NHEAD1(3, 0),
				    "fp_i_handle_unsol_els: "
				    "Rejecting PLOGI with Logical Busy."
				    "Possible Login collision.");
			} else {
				mutex_enter(&port->fp_mutex);
				port->fp_els_resp_pkt_busy = 0;
				mutex_exit(&port->fp_mutex);
				return;
			}
		}
		break;
	}

	case LA_ELS_FLOGI:
		if (fp_is_class_supported(port->fp_cos,
		    buf->ub_class) == FC_FAILURE) {
			if (FP_IS_CLASS_1_OR_2(buf->ub_class)) {
				cmd->cmd_pkt.pkt_cmdlen = sizeof (la_els_rjt_t);
				cmd->cmd_pkt.pkt_rsplen = 0;
				fp_els_rjt_init(port, cmd, buf,
				    FC_ACTION_NON_RETRYABLE,
				    FC_REASON_CLASS_NOT_SUPP, NULL);
				FP_TRACE(FP_NHEAD1(3, 0),
				    "fp_i_handle_unsol_els: "
				    "Unsupported Class. Rejecting FLOGI.");
			} else {
				mutex_enter(&port->fp_mutex);
				port->fp_els_resp_pkt_busy = 0;
				mutex_exit(&port->fp_mutex);
				return;
			}
		} else {
			mutex_enter(&port->fp_mutex);
			if (FC_PORT_STATE_MASK(port->fp_state) !=
			    FC_STATE_ONLINE || (port->fp_port_id.port_id &&
			    buf->ub_frame.s_id == port->fp_port_id.port_id)) {
				mutex_exit(&port->fp_mutex);
				if (FP_IS_CLASS_1_OR_2(buf->ub_class)) {
					cmd->cmd_pkt.pkt_cmdlen =
					    sizeof (la_els_rjt_t);
					cmd->cmd_pkt.pkt_rsplen = 0;
					fp_els_rjt_init(port, cmd, buf,
					    FC_ACTION_NON_RETRYABLE,
					    FC_REASON_INVALID_LINK_CTRL,
					    NULL);
					FP_TRACE(FP_NHEAD1(3, 0),
					    "fp_i_handle_unsol_els: "
					    "Invalid Link Ctrl. "
					    "Rejecting FLOGI.");
				} else {
					mutex_enter(&port->fp_mutex);
					port->fp_els_resp_pkt_busy = 0;
					mutex_exit(&port->fp_mutex);
					return;
				}
			} else {
				mutex_exit(&port->fp_mutex);
				cmd->cmd_pkt.pkt_cmdlen =
				    sizeof (la_els_logi_t);
				cmd->cmd_pkt.pkt_rsplen = 0;
				/*
				 * Let's not aggressively validate the N_Port's
				 * service parameters until PLOGI. Suffice it
				 * to give a hint that we are an N_Port and we
				 * are game to some serious stuff here.
				 */
				fp_login_acc_init(port, cmd, buf,
				    NULL, KM_NOSLEEP);
				FP_TRACE(FP_NHEAD1(3, 0),
				    "fp_i_handle_unsol_els: "
				    "Accepting FLOGI.");
			}
		}
		break;

	default:
		return;
	}

	if ((fp_sendcmd(port, cmd, port->fp_fca_handle)) != FC_SUCCESS) {
		mutex_enter(&port->fp_mutex);
		port->fp_els_resp_pkt_busy = 0;
		mutex_exit(&port->fp_mutex);
	}
}


/*
 * Handle unsolicited PLOGI request
 */
static void
fp_handle_unsol_plogi(fc_local_port_t *port, fc_unsol_buf_t *buf,
    job_request_t *job, int sleep)
{
	int			sent;
	int			small;
	int			f_port;
	int			do_acc;
	fp_cmd_t		*cmd;
	la_wwn_t		*swwn;
	la_wwn_t		*dwwn;
	la_els_logi_t		*payload;
	fc_remote_port_t	*pd;
	char			dww_name[17];

	payload = (la_els_logi_t *)buf->ub_buffer;
	f_port = FP_IS_F_PORT(payload->common_service.cmn_features) ? 1 : 0;

	mutex_enter(&port->fp_mutex);
	do_acc = (port->fp_statec_busy == 0) ? 1 : 0;
	mutex_exit(&port->fp_mutex);

	FP_TRACE(FP_NHEAD1(3, 0), "fp_handle_unsol_plogi: s_id=%x, d_id=%x,"
	    "type=%x, f_ctl=%x"
	    " seq_id=%x, ox_id=%x, rx_id=%x"
	    " ro=%x", buf->ub_frame.s_id, buf->ub_frame.d_id,
	    buf->ub_frame.type, buf->ub_frame.f_ctl, buf->ub_frame.seq_id,
	    buf->ub_frame.ox_id, buf->ub_frame.rx_id, buf->ub_frame.ro);

	swwn = &port->fp_service_params.nport_ww_name;
	dwwn = &payload->nport_ww_name;
	small = fctl_wwn_cmp(swwn, dwwn);
	pd = fctl_get_remote_port_by_pwwn(port, dwwn);
	if (pd) {
		mutex_enter(&pd->pd_mutex);
		sent = (pd->pd_flags == PD_ELS_IN_PROGRESS) ? 1 : 0;
		/*
		 * Most likely this means a cross login is in
		 * progress or a device about to be yanked out.
		 * Only accept the plogi if my wwn is smaller.
		 */

		if (pd->pd_type == PORT_DEVICE_OLD) {
			sent = 1;
		}
		/*
		 * Stop plogi request (if any)
		 * attempt from local side to speedup
		 * the discovery progress.
		 * Mark the pd as PD_PLOGI_RECEPIENT.
		 */
		if (f_port == 0 && small < 0) {
			pd->pd_recepient = PD_PLOGI_RECEPIENT;
		}
		fc_wwn_to_str(&pd->pd_port_name, dww_name);

		mutex_exit(&pd->pd_mutex);

		FP_TRACE(FP_NHEAD1(3, 0), "fp_handle_unsol_plogi: Unsol PLOGI"
		    " received. PD still exists in the PWWN list. pd=%p "
		    "PWWN=%s, sent=%x", pd, dww_name, sent);

		if (f_port == 0 && small < 0) {
			FP_TRACE(FP_NHEAD1(3, 0),
			    "fp_handle_unsol_plogi: Mark the pd"
			    " as plogi recipient, pd=%p, PWWN=%s"
			    ", sent=%x",
			    pd, dww_name, sent);
		}
	} else {
		sent = 0;
	}

	/*
	 * Avoid Login collisions by accepting only if my WWN is smaller.
	 *
	 * A side note: There is no need to start a PLOGI from this end in
	 *	this context if login isn't going to be accepted for the
	 *	above reason as either a LIP (in private loop), RSCN (in
	 *	fabric topology), or an FLOGI (in point to point - Huh ?
	 *	check FC-PH) would normally drive the PLOGI from this end.
	 *	At this point of time there is no need for an inbound PLOGI
	 *	to kick an outbound PLOGI when it is going to be rejected
	 *	for the reason of WWN being smaller. However it isn't hard
	 *	to do that either (when such a need arises, start a timer
	 *	for a duration that extends beyond a normal device discovery
	 *	time and check if an outbound PLOGI did go before that, if
	 *	none fire one)
	 *
	 *	Unfortunately, as it turned out, during booting, it is possible
	 *	to miss another initiator in the same loop as port driver
	 *	instances are serially attached. While preserving the above
	 *	comments for belly laughs, please kick an outbound PLOGI in
	 *	a non-switch environment (which is a pt pt between N_Ports or
	 *	a private loop)
	 *
	 *	While preserving the above comments for amusement, send an
	 *	ACC if the PLOGI is going to be rejected for WWN being smaller
	 *	when no discovery is in progress at this end. Turn around
	 *	and make the port device as the PLOGI initiator, so that
	 *	during subsequent link/loop initialization, this end drives
	 *	the PLOGI (In fact both ends do in this particular case, but
	 *	only one wins)
	 *
	 * Make sure the PLOGIs initiated by the switch from not-so-well-known
	 * ports (such as 0xFFFC41) are accepted too.
	 */
	if ((f_port == 0 && small < 0) || (((small > 0 && do_acc) ||
	    FC_MUST_ACCEPT_D_ID(buf->ub_frame.s_id)) && sent == 0)) {
		if (fp_is_class_supported(port->fp_cos,
		    buf->ub_class) == FC_FAILURE) {
			if (FP_IS_CLASS_1_OR_2(buf->ub_class)) {
				cmd = fp_alloc_pkt(port,
				    sizeof (la_els_logi_t), 0, sleep, pd);
				if (cmd == NULL) {
					return;
				}
				cmd->cmd_pkt.pkt_cmdlen = sizeof (la_els_rjt_t);
				cmd->cmd_pkt.pkt_rsplen = 0;
				fp_els_rjt_init(port, cmd, buf,
				    FC_ACTION_NON_RETRYABLE,
				    FC_REASON_CLASS_NOT_SUPP, job);
				FP_TRACE(FP_NHEAD1(3, 0),
				    "fp_handle_unsol_plogi: "
				    "Unsupported class. rejecting PLOGI");
			}
		} else {
			cmd = fp_alloc_pkt(port, sizeof (la_els_logi_t),
			    0, sleep, pd);
			if (cmd == NULL) {
				return;
			}
			cmd->cmd_pkt.pkt_cmdlen = sizeof (la_els_logi_t);
			cmd->cmd_pkt.pkt_rsplen = 0;

			/*
			 * Sometime later, we should validate the service
			 * parameters instead of just accepting it.
			 */
			fp_login_acc_init(port, cmd, buf, job, KM_SLEEP);
			FP_TRACE(FP_NHEAD1(3, 0), "fp_handle_unsol_plogi: "
			    "Accepting PLOGI, f_port=%d, small=%d, "
			    "do_acc=%d, sent=%d.", f_port, small, do_acc,
			    sent);

			/*
			 * If fp_port_id is zero and topology is
			 * Point-to-Point, get the local port id from
			 * the d_id in the PLOGI request.
			 * If the outgoing FLOGI hasn't been accepted,
			 * the topology will be unknown here. But it's
			 * still safe to save the d_id to fp_port_id,
			 * just because it will be overwritten later
			 * if the topology is not Point-to-Point.
			 */
			mutex_enter(&port->fp_mutex);
			if ((port->fp_port_id.port_id == 0) &&
			    (port->fp_topology == FC_TOP_PT_PT ||
			    port->fp_topology == FC_TOP_UNKNOWN)) {
				port->fp_port_id.port_id =
				    buf->ub_frame.d_id;
			}
			mutex_exit(&port->fp_mutex);
		}
	} else {
		if (FP_IS_CLASS_1_OR_2(buf->ub_class) ||
		    port->fp_options & FP_SEND_RJT) {
			cmd = fp_alloc_pkt(port, sizeof (la_els_logi_t),
			    0, sleep, pd);
			if (cmd == NULL) {
				return;
			}
			cmd->cmd_pkt.pkt_cmdlen = sizeof (la_els_rjt_t);
			cmd->cmd_pkt.pkt_rsplen = 0;
			/*
			 * Send out Logical busy to indicate
			 * the detection of PLOGI collision
			 */
			fp_els_rjt_init(port, cmd, buf,
			    FC_ACTION_NON_RETRYABLE,
			    FC_REASON_LOGICAL_BSY, job);

			fc_wwn_to_str(dwwn, dww_name);
			FP_TRACE(FP_NHEAD1(3, 0), "fp_handle_unsol_plogi: "
			    "Rejecting Unsol PLOGI with Logical Busy."
			    "possible PLOGI collision. PWWN=%s, sent=%x",
			    dww_name, sent);
		} else {
			return;
		}
	}

	if (fp_sendcmd(port, cmd, port->fp_fca_handle) != FC_SUCCESS) {
		fp_free_pkt(cmd);
	}
}


/*
 * Handle mischievous turning over of our own FLOGI requests back to
 * us by the SOC+ microcode. In other words, look at the class of such
 * bone headed requests, if 1 or 2, bluntly P_RJT them, if 3 drop them
 * on the floor
 */
static void
fp_handle_unsol_flogi(fc_local_port_t *port, fc_unsol_buf_t *buf,
    job_request_t *job, int sleep)
{
	uint32_t	state;
	uint32_t	s_id;
	fp_cmd_t	*cmd;

	if (fp_is_class_supported(port->fp_cos, buf->ub_class) == FC_FAILURE) {
		if (FP_IS_CLASS_1_OR_2(buf->ub_class)) {
			cmd = fp_alloc_pkt(port, sizeof (la_els_rjt_t),
			    0, sleep, NULL);
			if (cmd == NULL) {
				return;
			}
			fp_els_rjt_init(port, cmd, buf,
			    FC_ACTION_NON_RETRYABLE,
			    FC_REASON_CLASS_NOT_SUPP, job);
		} else {
			return;
		}
	} else {

		FP_TRACE(FP_NHEAD1(3, 0), "fp_handle_unsol_flogi:"
		    " s_id=%x, d_id=%x, type=%x, f_ctl=%x"
		    " seq_id=%x, ox_id=%x, rx_id=%x, ro=%x",
		    buf->ub_frame.s_id, buf->ub_frame.d_id,
		    buf->ub_frame.type, buf->ub_frame.f_ctl,
		    buf->ub_frame.seq_id, buf->ub_frame.ox_id,
		    buf->ub_frame.rx_id, buf->ub_frame.ro);

		mutex_enter(&port->fp_mutex);
		state = FC_PORT_STATE_MASK(port->fp_state);
		s_id = port->fp_port_id.port_id;
		mutex_exit(&port->fp_mutex);

		if (state != FC_STATE_ONLINE ||
		    (s_id && buf->ub_frame.s_id == s_id)) {
			if (FP_IS_CLASS_1_OR_2(buf->ub_class)) {
				cmd = fp_alloc_pkt(port, sizeof (la_els_rjt_t),
				    0, sleep, NULL);
				if (cmd == NULL) {
					return;
				}
				fp_els_rjt_init(port, cmd, buf,
				    FC_ACTION_NON_RETRYABLE,
				    FC_REASON_INVALID_LINK_CTRL, job);
				FP_TRACE(FP_NHEAD1(3, 0),
				    "fp_handle_unsol_flogi: "
				    "Rejecting PLOGI. Invalid Link CTRL");
			} else {
				return;
			}
		} else {
			cmd = fp_alloc_pkt(port, sizeof (la_els_logi_t),
			    0, sleep, NULL);
			if (cmd == NULL) {
				return;
			}
			/*
			 * Let's not aggressively validate the N_Port's
			 * service parameters until PLOGI. Suffice it
			 * to give a hint that we are an N_Port and we
			 * are game to some serious stuff here.
			 */
			fp_login_acc_init(port, cmd, buf, job, KM_SLEEP);
			FP_TRACE(FP_NHEAD1(3, 0), "fp_handle_unsol_flogi: "
			    "Accepting PLOGI");
		}
	}

	if (fp_sendcmd(port, cmd, port->fp_fca_handle) != FC_SUCCESS) {
		fp_free_pkt(cmd);
	}
}


/*
 * Perform PLOGI accept
 */
static void
fp_login_acc_init(fc_local_port_t *port, fp_cmd_t *cmd, fc_unsol_buf_t *buf,
    job_request_t *job, int sleep)
{
	fc_packet_t	*pkt;
	fc_portmap_t	*listptr;
	la_els_logi_t	payload;

	ASSERT(buf != NULL);

	/*
	 * If we are sending ACC to PLOGI and we haven't already
	 * create port and node device handles, let's create them
	 * here.
	 */
	if (buf->ub_buffer[0] == LA_ELS_PLOGI &&
	    FC_IS_REAL_DEVICE(buf->ub_frame.s_id)) {
		int			small;
		int			do_acc;
		fc_remote_port_t	*pd;
		la_els_logi_t		*req;

		req = (la_els_logi_t *)buf->ub_buffer;
		small = fctl_wwn_cmp(&port->fp_service_params.nport_ww_name,
		    &req->nport_ww_name);

		mutex_enter(&port->fp_mutex);
		do_acc = (port->fp_statec_busy == 0) ? 1 : 0;
		mutex_exit(&port->fp_mutex);

		FP_TRACE(FP_NHEAD1(3, 0), "fp_plogi_acc_init fp %x, pd %x",
		    port->fp_port_id.port_id, buf->ub_frame.s_id);
		pd = fctl_create_remote_port(port, &req->node_ww_name,
		    &req->nport_ww_name, buf->ub_frame.s_id,
		    PD_PLOGI_RECEPIENT, sleep);
		if (pd == NULL) {
			FP_TRACE(FP_NHEAD1(3, 0), "login_acc_init: "
			    "Couldn't create port device for d_id:0x%x",
			    buf->ub_frame.s_id);

			fp_printf(port, CE_NOTE, FP_LOG_ONLY, 0, NULL,
			    "couldn't create port device d_id=%x",
			    buf->ub_frame.s_id);
		} else {
			/*
			 * usoc currently returns PLOGIs inline and
			 * the maximum buffer size is 60 bytes or so.
			 * So attempt not to look beyond what is in
			 * the unsolicited buffer
			 *
			 * JNI also traverses this path sometimes
			 */
			if (buf->ub_bufsize >= sizeof (la_els_logi_t)) {
				fp_register_login(NULL, pd, req, buf->ub_class);
			} else {
				mutex_enter(&pd->pd_mutex);
				if (pd->pd_login_count == 0) {
					pd->pd_login_count++;
				}
				pd->pd_state = PORT_DEVICE_LOGGED_IN;
				pd->pd_login_class = buf->ub_class;
				mutex_exit(&pd->pd_mutex);
			}

			listptr = kmem_zalloc(sizeof (fc_portmap_t), sleep);
			if (listptr != NULL) {
				fctl_copy_portmap(listptr, pd);
				(void) fp_ulp_devc_cb(port, listptr,
				    1, 1, sleep, 0);
			}

			if (small > 0 && do_acc) {
				mutex_enter(&pd->pd_mutex);
				pd->pd_recepient = PD_PLOGI_INITIATOR;
				mutex_exit(&pd->pd_mutex);
			}
		}
	}

	cmd->cmd_pkt.pkt_tran_flags = buf->ub_class;
	cmd->cmd_pkt.pkt_tran_type = FC_PKT_OUTBOUND;
	cmd->cmd_flags = FP_CMD_CFLAG_UNDEFINED;
	cmd->cmd_retry_count = 1;
	cmd->cmd_ulp_pkt = NULL;

	cmd->cmd_transport = port->fp_fca_tran->fca_els_send;
	cmd->cmd_job = job;

	pkt = &cmd->cmd_pkt;

	fp_unsol_resp_init(pkt, buf, R_CTL_ELS_RSP, FC_TYPE_EXTENDED_LS);

	payload = port->fp_service_params;
	payload.ls_code.ls_code = LA_ELS_ACC;

	FC_SET_CMD(port, pkt->pkt_cmd_acc, (uint8_t *)&payload,
	    (uint8_t *)pkt->pkt_cmd, sizeof (payload), DDI_DEV_AUTOINCR);

	FP_TRACE(FP_NHEAD1(3, 0), "login_acc_init: ELS:0x%x d_id:0x%x "
	    "bufsize:0x%x sizeof (la_els_logi):0x%x "
	    "port's wwn:0x%01x%03x%04x%08x requestor's wwn:0x%01x%03x%04x%08x "
	    "statec_busy:0x%x", buf->ub_buffer[0], buf->ub_frame.s_id,
	    buf->ub_bufsize, sizeof (la_els_logi_t),
	    port->fp_service_params.nport_ww_name.w.naa_id,
	    port->fp_service_params.nport_ww_name.w.nport_id,
	    port->fp_service_params.nport_ww_name.w.wwn_hi,
	    port->fp_service_params.nport_ww_name.w.wwn_lo,
	    ((la_els_logi_t *)buf->ub_buffer)->nport_ww_name.w.naa_id,
	    ((la_els_logi_t *)buf->ub_buffer)->nport_ww_name.w.nport_id,
	    ((la_els_logi_t *)buf->ub_buffer)->nport_ww_name.w.wwn_hi,
	    ((la_els_logi_t *)buf->ub_buffer)->nport_ww_name.w.wwn_lo,
	    port->fp_statec_busy);
}


#define	RSCN_EVENT_NAME_LEN	256

/*
 * Handle RSCNs
 */
static void
fp_handle_unsol_rscn(fc_local_port_t *port, fc_unsol_buf_t *buf,
    job_request_t *job, int sleep)
{
	uint32_t		mask;
	fp_cmd_t		*cmd;
	uint32_t		count;
	int			listindex;
	int16_t			len;
	fc_rscn_t		*payload;
	fc_portmap_t		*listptr;
	fctl_ns_req_t		*ns_cmd;
	fc_affected_id_t	*page;
	caddr_t			nvname;
	nvlist_t		*attr_list = NULL;

	mutex_enter(&port->fp_mutex);
	if (!FC_IS_TOP_SWITCH(port->fp_topology)) {
		if (--port->fp_rscn_count == FC_INVALID_RSCN_COUNT) {
			--port->fp_rscn_count;
		}
		mutex_exit(&port->fp_mutex);
		return;
	}
	mutex_exit(&port->fp_mutex);

	cmd = fp_alloc_pkt(port, FP_PORT_IDENTIFIER_LEN, 0, sleep, NULL);
	if (cmd != NULL) {
		fp_els_acc_init(port, cmd, buf, job);
		if (fp_sendcmd(port, cmd, port->fp_fca_handle) != FC_SUCCESS) {
			fp_free_pkt(cmd);
		}
	}

	payload = (fc_rscn_t *)buf->ub_buffer;
	ASSERT(payload->rscn_code == LA_ELS_RSCN);
	ASSERT(payload->rscn_len == FP_PORT_IDENTIFIER_LEN);

	len = payload->rscn_payload_len - FP_PORT_IDENTIFIER_LEN;

	if (len <= 0) {
		mutex_enter(&port->fp_mutex);
		if (--port->fp_rscn_count == FC_INVALID_RSCN_COUNT) {
			--port->fp_rscn_count;
		}
		mutex_exit(&port->fp_mutex);

		return;
	}

	ASSERT((len & 0x3) == 0);	/* Must be power of 4 */
	count = (len >> 2) << 1;	/* number of pages multiplied by 2 */

	listptr = kmem_zalloc(sizeof (fc_portmap_t) * count, sleep);
	page = (fc_affected_id_t *)(buf->ub_buffer + sizeof (fc_rscn_t));

	ASSERT((job->job_flags & JOB_TYPE_FP_ASYNC) == 0);

	ns_cmd = fctl_alloc_ns_cmd(sizeof (ns_req_gpn_id_t),
	    sizeof (ns_resp_gpn_id_t), sizeof (ns_resp_gpn_id_t),
	    0, sleep);
	if (ns_cmd == NULL) {
		kmem_free(listptr, sizeof (fc_portmap_t) * count);

		mutex_enter(&port->fp_mutex);
		if (--port->fp_rscn_count == FC_INVALID_RSCN_COUNT) {
			--port->fp_rscn_count;
		}
		mutex_exit(&port->fp_mutex);

		return;
	}

	ns_cmd->ns_cmd_code = NS_GPN_ID;

	FP_TRACE(FP_NHEAD1(3, 0), "fp_handle_unsol_rscn: s_id=%x, d_id=%x,"
	    "type=%x, f_ctl=%x seq_id=%x, ox_id=%x, rx_id=%x"
	    " ro=%x", buf->ub_frame.s_id, buf->ub_frame.d_id,
	    buf->ub_frame.type, buf->ub_frame.f_ctl, buf->ub_frame.seq_id,
	    buf->ub_frame.ox_id, buf->ub_frame.rx_id, buf->ub_frame.ro);

	/* Only proceed if we can allocate nvname and the nvlist */
	if ((nvname = kmem_zalloc(RSCN_EVENT_NAME_LEN, KM_NOSLEEP)) != NULL &&
	    nvlist_alloc(&attr_list, NV_UNIQUE_NAME_TYPE,
	    KM_NOSLEEP) == DDI_SUCCESS) {
		if (!(attr_list && nvlist_add_uint32(attr_list, "instance",
		    port->fp_instance) == DDI_SUCCESS &&
		    nvlist_add_byte_array(attr_list, "port-wwn",
		    port->fp_service_params.nport_ww_name.raw_wwn,
		    sizeof (la_wwn_t)) == DDI_SUCCESS)) {
			nvlist_free(attr_list);
			attr_list = NULL;
		}
	}

	for (listindex = 0; len; len -= FP_PORT_IDENTIFIER_LEN, page++) {
		/* Add affected page to the event payload */
		if (attr_list != NULL) {
			(void) snprintf(nvname, RSCN_EVENT_NAME_LEN,
			    "affected_page_%d", listindex);
			if (attr_list && nvlist_add_uint32(attr_list, nvname,
			    ntohl(*(uint32_t *)page)) != DDI_SUCCESS) {
				/* We don't send a partial event, so dump it */
				nvlist_free(attr_list);
				attr_list = NULL;
			}
		}
		/*
		 * Query the NS to get the Port WWN for this
		 * affected D_ID.
		 */
		mask = 0;
		switch (page->aff_format & FC_RSCN_ADDRESS_MASK) {
		case FC_RSCN_PORT_ADDRESS:
			fp_validate_rscn_page(port, page, job, ns_cmd,
			    listptr, &listindex, sleep);

			if (listindex == 0) {
				/*
				 * We essentially did not process this RSCN. So,
				 * ULPs are not going to be called and so we
				 * decrement the rscn_count
				 */
				mutex_enter(&port->fp_mutex);
				if (--port->fp_rscn_count ==
				    FC_INVALID_RSCN_COUNT) {
					--port->fp_rscn_count;
				}
				mutex_exit(&port->fp_mutex);
			}
			break;

		case FC_RSCN_AREA_ADDRESS:
			mask = 0xFFFF00;
			/* FALLTHROUGH */

		case FC_RSCN_DOMAIN_ADDRESS:
			if (!mask) {
				mask = 0xFF0000;
			}
			fp_validate_area_domain(port, page->aff_d_id, mask,
			    job, sleep);
			break;

		case FC_RSCN_FABRIC_ADDRESS:
			/*
			 * We need to discover all the devices on this
			 * port.
			 */
			fp_validate_area_domain(port, 0, 0, job, sleep);
			break;

		default:
			break;
		}
	}
	if (attr_list != NULL) {
		(void) ddi_log_sysevent(port->fp_port_dip, DDI_VENDOR_SUNW,
		    EC_SUNFC, ESC_SUNFC_PORT_RSCN, attr_list,
		    NULL, DDI_SLEEP);
		nvlist_free(attr_list);
	} else {
		FP_TRACE(FP_NHEAD1(9, 0),
		    "RSCN handled, but event not sent to userland");
	}
	if (nvname != NULL) {
		kmem_free(nvname, RSCN_EVENT_NAME_LEN);
	}

	if (ns_cmd) {
		fctl_free_ns_cmd(ns_cmd);
	}

	if (listindex) {
#ifdef	DEBUG
		page = (fc_affected_id_t *)(buf->ub_buffer +
		    sizeof (fc_rscn_t));

		if (listptr->map_did.port_id != page->aff_d_id) {
			FP_TRACE(FP_NHEAD1(9, 0),
			    "PORT RSCN: processed=%x, reporting=%x",
			    listptr->map_did.port_id, page->aff_d_id);
		}
#endif

		(void) fp_ulp_devc_cb(port, listptr, listindex, count,
		    sleep, 0);
	} else {
		kmem_free(listptr, sizeof (fc_portmap_t) * count);
	}
}


/*
 * Fill out old map for ULPs with fp_mutex, fd_mutex and pd_mutex held
 */
static void
fp_fillout_old_map_held(fc_portmap_t *map, fc_remote_port_t *pd, uchar_t flag)
{
	int		is_switch;
	int		initiator;
	fc_local_port_t	*port;

	port = pd->pd_port;

	/* This function has the following bunch of assumptions */
	ASSERT(port != NULL);
	ASSERT(MUTEX_HELD(&port->fp_mutex));
	ASSERT(MUTEX_HELD(&pd->pd_remote_nodep->fd_mutex));
	ASSERT(MUTEX_HELD(&pd->pd_mutex));

	pd->pd_state = PORT_DEVICE_INVALID;
	pd->pd_type = PORT_DEVICE_OLD;
	initiator = (pd->pd_recepient == PD_PLOGI_INITIATOR) ? 1 : 0;
	is_switch = FC_IS_TOP_SWITCH(port->fp_topology);

	fctl_delist_did_table(port, pd);
	fctl_delist_pwwn_table(port, pd);

	FP_TRACE(FP_NHEAD1(6, 0), "fp_fillout_old_map_held: port=%p, d_id=%x"
	    " removed the PD=%p from DID and PWWN tables",
	    port, pd->pd_port_id.port_id, pd);

	if ((!flag) && port && initiator && is_switch) {
		(void) fctl_add_orphan_held(port, pd);
	}
	fctl_copy_portmap_held(map, pd);
	map->map_pd = pd;
}

/*
 * Fill out old map for ULPs
 */
static void
fp_fillout_old_map(fc_portmap_t *map, fc_remote_port_t *pd, uchar_t flag)
{
	int		is_switch;
	int		initiator;
	fc_local_port_t	*port;

	mutex_enter(&pd->pd_mutex);
	port = pd->pd_port;
	mutex_exit(&pd->pd_mutex);

	mutex_enter(&port->fp_mutex);
	mutex_enter(&pd->pd_mutex);

	pd->pd_state = PORT_DEVICE_INVALID;
	pd->pd_type = PORT_DEVICE_OLD;
	initiator = (pd->pd_recepient == PD_PLOGI_INITIATOR) ? 1 : 0;
	is_switch = FC_IS_TOP_SWITCH(port->fp_topology);

	fctl_delist_did_table(port, pd);
	fctl_delist_pwwn_table(port, pd);

	FP_TRACE(FP_NHEAD1(6, 0), "fp_fillout_old_map: port=%p, d_id=%x"
	    " removed the PD=%p from DID and PWWN tables",
	    port, pd->pd_port_id.port_id, pd);

	mutex_exit(&pd->pd_mutex);
	mutex_exit(&port->fp_mutex);

	ASSERT(port != NULL);
	if ((!flag) && port && initiator && is_switch) {
		(void) fctl_add_orphan(port, pd, KM_NOSLEEP);
	}
	fctl_copy_portmap(map, pd);
	map->map_pd = pd;
}


/*
 * Fillout Changed Map for ULPs
 */
static void
fp_fillout_changed_map(fc_portmap_t *map, fc_remote_port_t *pd,
    uint32_t *new_did, la_wwn_t *new_pwwn)
{
	ASSERT(MUTEX_HELD(&pd->pd_mutex));

	pd->pd_type = PORT_DEVICE_CHANGED;
	if (new_did) {
		pd->pd_port_id.port_id = *new_did;
	}
	if (new_pwwn) {
		pd->pd_port_name = *new_pwwn;
	}
	mutex_exit(&pd->pd_mutex);

	fctl_copy_portmap(map, pd);

	mutex_enter(&pd->pd_mutex);
	pd->pd_type = PORT_DEVICE_NOCHANGE;
}


/*
 * Fillout New Name Server map
 */
static void
fp_fillout_new_nsmap(fc_local_port_t *port, ddi_acc_handle_t *handle,
    fc_portmap_t *port_map, ns_resp_gan_t *gan_resp, uint32_t d_id)
{
	ASSERT(!MUTEX_HELD(&port->fp_mutex));

	if (handle) {
		FC_GET_RSP(port, *handle, (uint8_t *)&port_map->map_pwwn,
		    (uint8_t *)&gan_resp->gan_pwwn, sizeof (gan_resp->gan_pwwn),
		    DDI_DEV_AUTOINCR);
		FC_GET_RSP(port, *handle, (uint8_t *)&port_map->map_nwwn,
		    (uint8_t *)&gan_resp->gan_nwwn, sizeof (gan_resp->gan_nwwn),
		    DDI_DEV_AUTOINCR);
		FC_GET_RSP(port, *handle, (uint8_t *)port_map->map_fc4_types,
		    (uint8_t *)gan_resp->gan_fc4types,
		    sizeof (gan_resp->gan_fc4types), DDI_DEV_AUTOINCR);
	} else {
		bcopy(&gan_resp->gan_pwwn, &port_map->map_pwwn,
		    sizeof (gan_resp->gan_pwwn));
		bcopy(&gan_resp->gan_nwwn, &port_map->map_nwwn,
		    sizeof (gan_resp->gan_nwwn));
		bcopy(gan_resp->gan_fc4types, port_map->map_fc4_types,
		    sizeof (gan_resp->gan_fc4types));
	}
	port_map->map_did.port_id = d_id;
	port_map->map_did.priv_lilp_posit = 0;
	port_map->map_hard_addr.hard_addr = 0;
	port_map->map_hard_addr.rsvd = 0;
	port_map->map_state = PORT_DEVICE_INVALID;
	port_map->map_type = PORT_DEVICE_NEW;
	port_map->map_flags = 0;
	port_map->map_pd = NULL;

	(void) fctl_remove_if_orphan(port, &port_map->map_pwwn);

	ASSERT(port != NULL);
}


/*
 * Perform LINIT ELS
 */
static int
fp_remote_lip(fc_local_port_t *port, la_wwn_t *pwwn, int sleep,
    job_request_t *job)
{
	int			rval;
	uint32_t		d_id;
	uint32_t		s_id;
	uint32_t		lfa;
	uchar_t			class;
	uint32_t		ret;
	fp_cmd_t		*cmd;
	fc_porttype_t		ptype;
	fc_packet_t		*pkt;
	fc_linit_req_t		payload;
	fc_remote_port_t	*pd;

	rval = 0;

	ASSERT(job != NULL);
	ASSERT((job->job_flags & JOB_TYPE_FP_ASYNC) == 0);

	pd = fctl_get_remote_port_by_pwwn(port, pwwn);
	if (pd == NULL) {
		fctl_ns_req_t *ns_cmd;

		ns_cmd = fctl_alloc_ns_cmd(sizeof (ns_req_gid_pn_t),
		    sizeof (ns_resp_gid_pn_t), sizeof (ns_resp_gid_pn_t),
		    0, sleep);

		if (ns_cmd == NULL) {
			return (FC_NOMEM);
		}
		job->job_result = FC_SUCCESS;
		ns_cmd->ns_cmd_code = NS_GID_PN;
		((ns_req_gid_pn_t *)(ns_cmd->ns_cmd_buf))->pwwn = *pwwn;

		ret = fp_ns_query(port, ns_cmd, job, 1, sleep);
		if (ret != FC_SUCCESS || job->job_result != FC_SUCCESS) {
			fctl_free_ns_cmd(ns_cmd);
			return (FC_FAILURE);
		}
		bcopy(ns_cmd->ns_data_buf, (caddr_t)&d_id, sizeof (d_id));
		d_id = BE_32(*((uint32_t *)ns_cmd->ns_data_buf));

		fctl_free_ns_cmd(ns_cmd);
		lfa = d_id & 0xFFFF00;

		/*
		 * Given this D_ID, get the port type to see if
		 * we can do LINIT on the LFA
		 */
		ns_cmd = fctl_alloc_ns_cmd(sizeof (ns_req_gpt_id_t),
		    sizeof (ns_resp_gpt_id_t), sizeof (ns_resp_gpt_id_t),
		    0, sleep);

		if (ns_cmd == NULL) {
			return (FC_NOMEM);
		}

		job->job_result = FC_SUCCESS;
		ns_cmd->ns_cmd_code = NS_GPT_ID;

		((ns_req_gpt_id_t *)(ns_cmd->ns_cmd_buf))->pid.port_id = d_id;
		((ns_req_gpt_id_t *)
		    (ns_cmd->ns_cmd_buf))->pid.priv_lilp_posit = 0;

		ret = fp_ns_query(port, ns_cmd, job, 1, sleep);
		if (ret != FC_SUCCESS || job->job_result != FC_SUCCESS) {
			fctl_free_ns_cmd(ns_cmd);
			return (FC_FAILURE);
		}
		bcopy(ns_cmd->ns_data_buf, (caddr_t)&ptype, sizeof (ptype));

		fctl_free_ns_cmd(ns_cmd);

		switch (ptype.port_type) {
		case FC_NS_PORT_NL:
		case FC_NS_PORT_F_NL:
		case FC_NS_PORT_FL:
			break;

		default:
			return (FC_FAILURE);
		}
	} else {
		mutex_enter(&pd->pd_mutex);
		ptype = pd->pd_porttype;

		switch (pd->pd_porttype.port_type) {
		case FC_NS_PORT_NL:
		case FC_NS_PORT_F_NL:
		case FC_NS_PORT_FL:
			lfa = pd->pd_port_id.port_id & 0xFFFF00;
			break;

		default:
			mutex_exit(&pd->pd_mutex);
			return (FC_FAILURE);
		}
		mutex_exit(&pd->pd_mutex);
	}

	mutex_enter(&port->fp_mutex);
	s_id = port->fp_port_id.port_id;
	class = port->fp_ns_login_class;
	mutex_exit(&port->fp_mutex);

	cmd = fp_alloc_pkt(port, sizeof (fc_linit_req_t),
	    sizeof (fc_linit_resp_t), sleep, pd);
	if (cmd == NULL) {
		return (FC_NOMEM);
	}

	cmd->cmd_pkt.pkt_tran_flags = FC_TRAN_INTR | class;
	cmd->cmd_pkt.pkt_tran_type = FC_PKT_EXCHANGE;
	cmd->cmd_flags = FP_CMD_CFLAG_UNDEFINED;
	cmd->cmd_retry_count = fp_retry_count;
	cmd->cmd_ulp_pkt = NULL;

	pkt = &cmd->cmd_pkt;
	cmd->cmd_transport = port->fp_fca_tran->fca_els_send;

	fp_els_init(cmd, s_id, lfa, fp_linit_intr, job);

	/*
	 * How does LIP work by the way ?
	 *	If the L_Port receives three consecutive identical ordered
	 *	sets whose first two characters (fully decoded) are equal to
	 *	the values shown in Table 3 of FC-AL-2 then the L_Port shall
	 *	recognize a Loop Initialization Primitive sequence. The
	 *	character 3 determines the type of lip:
	 *		LIP(F7)		Normal LIP
	 *		LIP(F8)		Loop Failure LIP
	 *
	 * The possible combination for the 3rd and 4th bytes are:
	 *	F7,	F7	Normal Lip	- No valid AL_PA
	 *	F8,	F8	Loop Failure	- No valid AL_PA
	 *	F7,	AL_PS	Normal Lip	- Valid source AL_PA
	 *	F8,	AL_PS	Loop Failure	- Valid source AL_PA
	 *	AL_PD	AL_PS	Loop reset of AL_PD originated by AL_PS
	 *			And Normal Lip for all other loop members
	 *	0xFF	AL_PS	Vendor specific reset of all loop members
	 *
	 * Now, it may not always be that we, at the source, may have an
	 * AL_PS (AL_PA of source) for 4th character slot, so we decide
	 * to do (Normal Lip, No Valid AL_PA), that means, in the LINIT
	 * payload we are going to set:
	 *	lip_b3 = 0xF7;		Normal LIP
	 *	lip_b4 = 0xF7;		No valid source AL_PA
	 */
	payload.ls_code.ls_code = LA_ELS_LINIT;
	payload.ls_code.mbz = 0;
	payload.rsvd = 0;
	payload.func = 0;		/* Let Fabric determine the best way */
	payload.lip_b3 = 0xF7;		/* Normal LIP */
	payload.lip_b4 = 0xF7;		/* No valid source AL_PA */

	FC_SET_CMD(port, pkt->pkt_cmd_acc, (uint8_t *)&payload,
	    (uint8_t *)pkt->pkt_cmd, sizeof (payload), DDI_DEV_AUTOINCR);

	job->job_counter = 1;

	ret = fp_sendcmd(port, cmd, port->fp_fca_handle);
	if (ret == FC_SUCCESS) {
		fp_jobwait(job);
		rval = job->job_result;
	} else {
		rval = FC_FAILURE;
		fp_free_pkt(cmd);
	}

	return (rval);
}


/*
 * Fill out the device handles with GAN response
 */
static void
fp_stuff_device_with_gan(ddi_acc_handle_t *handle, fc_remote_port_t *pd,
    ns_resp_gan_t *gan_resp)
{
	fc_remote_node_t	*node;
	fc_porttype_t		type;
	fc_local_port_t		*port;

	ASSERT(pd != NULL);
	ASSERT(handle != NULL);

	port = pd->pd_port;

	FP_TRACE(FP_NHEAD1(1, 0), "GAN PD stuffing; pd=%p,"
	    " port_id=%x, sym_len=%d fc4-type=%x",
	    pd, gan_resp->gan_type_id.rsvd,
	    gan_resp->gan_spnlen, gan_resp->gan_fc4types[0]);

	mutex_enter(&pd->pd_mutex);

	FC_GET_RSP(port, *handle, (uint8_t *)&type,
	    (uint8_t *)&gan_resp->gan_type_id, sizeof (type), DDI_DEV_AUTOINCR);

	pd->pd_porttype.port_type = type.port_type;
	pd->pd_porttype.rsvd = 0;

	pd->pd_spn_len = gan_resp->gan_spnlen;
	if (pd->pd_spn_len) {
		FC_GET_RSP(port, *handle, (uint8_t *)pd->pd_spn,
		    (uint8_t *)gan_resp->gan_spname, pd->pd_spn_len,
		    DDI_DEV_AUTOINCR);
	}

	FC_GET_RSP(port, *handle, (uint8_t *)pd->pd_ip_addr,
	    (uint8_t *)gan_resp->gan_ip, sizeof (pd->pd_ip_addr),
	    DDI_DEV_AUTOINCR);
	FC_GET_RSP(port, *handle, (uint8_t *)&pd->pd_cos,
	    (uint8_t *)&gan_resp->gan_cos, sizeof (pd->pd_cos),
	    DDI_DEV_AUTOINCR);
	FC_GET_RSP(port, *handle, (uint8_t *)pd->pd_fc4types,
	    (uint8_t *)gan_resp->gan_fc4types, sizeof (pd->pd_fc4types),
	    DDI_DEV_AUTOINCR);

	node = pd->pd_remote_nodep;
	mutex_exit(&pd->pd_mutex);

	mutex_enter(&node->fd_mutex);

	FC_GET_RSP(port, *handle, (uint8_t *)node->fd_ipa,
	    (uint8_t *)gan_resp->gan_ipa, sizeof (node->fd_ipa),
	    DDI_DEV_AUTOINCR);

	node->fd_snn_len = gan_resp->gan_snnlen;
	if (node->fd_snn_len) {
		FC_GET_RSP(port, *handle, (uint8_t *)node->fd_snn,
		    (uint8_t *)gan_resp->gan_snname, node->fd_snn_len,
		    DDI_DEV_AUTOINCR);
	}

	mutex_exit(&node->fd_mutex);
}


/*
 * Handles all NS Queries (also means that this function
 * doesn't handle NS object registration)
 */
static int
fp_ns_query(fc_local_port_t *port, fctl_ns_req_t *ns_cmd, job_request_t *job,
    int polled, int sleep)
{
	int		rval;
	fp_cmd_t	*cmd;

	ASSERT(!MUTEX_HELD(&port->fp_mutex));

	if (ns_cmd->ns_cmd_code == NS_GA_NXT) {
		FP_TRACE(FP_NHEAD1(1, 0), "fp_ns_query GA_NXT fp %x pd %x",
		    port->fp_port_id.port_id, ns_cmd->ns_gan_sid);
	}

	if (ns_cmd->ns_cmd_size == 0) {
		return (FC_FAILURE);
	}

	cmd = fp_alloc_pkt(port, sizeof (fc_ct_header_t) +
	    ns_cmd->ns_cmd_size, sizeof (fc_ct_header_t) +
	    ns_cmd->ns_resp_size, sleep, NULL);
	if (cmd == NULL) {
		return (FC_NOMEM);
	}

	fp_ct_init(port, cmd, ns_cmd, ns_cmd->ns_cmd_code, ns_cmd->ns_cmd_buf,
	    ns_cmd->ns_cmd_size, ns_cmd->ns_resp_size, job);

	if (polled) {
		job->job_counter = 1;
		ASSERT((job->job_flags & JOB_TYPE_FP_ASYNC) == 0);
	}
	rval = fp_sendcmd(port, cmd, port->fp_fca_handle);
	if (rval != FC_SUCCESS) {
		job->job_result = rval;
		fp_iodone(cmd);
		if (polled == 0) {
			/*
			 * Return FC_SUCCESS to indicate that
			 * fp_iodone is performed already.
			 */
			rval = FC_SUCCESS;
		}
	}

	if (polled) {
		fp_jobwait(job);
		rval = job->job_result;
	}

	return (rval);
}


/*
 * Initialize Common Transport request
 */
static void
fp_ct_init(fc_local_port_t *port, fp_cmd_t *cmd, fctl_ns_req_t *ns_cmd,
    uint16_t cmd_code, caddr_t cmd_buf, uint16_t cmd_len,
    uint16_t resp_len, job_request_t *job)
{
	uint32_t	s_id;
	uchar_t		class;
	fc_packet_t	*pkt;
	fc_ct_header_t	ct;

	ASSERT(!MUTEX_HELD(&port->fp_mutex));

	mutex_enter(&port->fp_mutex);
	s_id = port->fp_port_id.port_id;
	class = port->fp_ns_login_class;
	mutex_exit(&port->fp_mutex);

	cmd->cmd_job = job;
	cmd->cmd_private = ns_cmd;
	pkt = &cmd->cmd_pkt;

	ct.ct_rev = CT_REV;
	ct.ct_inid = 0;
	ct.ct_fcstype = FCSTYPE_DIRECTORY;
	ct.ct_fcssubtype = FCSSUB_DS_NAME_SERVER;
	ct.ct_options = 0;
	ct.ct_reserved1 = 0;
	ct.ct_cmdrsp = cmd_code;
	ct.ct_aiusize = resp_len >> 2;
	ct.ct_reserved2 = 0;
	ct.ct_reason = 0;
	ct.ct_expln = 0;
	ct.ct_vendor = 0;

	FC_SET_CMD(port, pkt->pkt_cmd_acc, (uint8_t *)&ct,
	    (uint8_t *)pkt->pkt_cmd, sizeof (ct), DDI_DEV_AUTOINCR);

	pkt->pkt_cmd_fhdr.r_ctl = R_CTL_UNSOL_CONTROL;
	pkt->pkt_cmd_fhdr.d_id = 0xFFFFFC;
	pkt->pkt_cmd_fhdr.s_id = s_id;
	pkt->pkt_cmd_fhdr.type = FC_TYPE_FC_SERVICES;
	pkt->pkt_cmd_fhdr.f_ctl = F_CTL_SEQ_INITIATIVE |
	    F_CTL_FIRST_SEQ | F_CTL_END_SEQ;
	pkt->pkt_cmd_fhdr.seq_id = 0;
	pkt->pkt_cmd_fhdr.df_ctl  = 0;
	pkt->pkt_cmd_fhdr.seq_cnt = 0;
	pkt->pkt_cmd_fhdr.ox_id = 0xffff;
	pkt->pkt_cmd_fhdr.rx_id = 0xffff;
	pkt->pkt_cmd_fhdr.ro = 0;
	pkt->pkt_cmd_fhdr.rsvd = 0;

	pkt->pkt_comp = fp_ns_intr;
	pkt->pkt_ulp_private = (opaque_t)cmd;
	pkt->pkt_timeout = FP_NS_TIMEOUT;

	if (cmd_buf) {
		FC_SET_CMD(port, pkt->pkt_cmd_acc, (uint8_t *)cmd_buf,
		    (uint8_t *)(pkt->pkt_cmd + sizeof (fc_ct_header_t)),
		    cmd_len, DDI_DEV_AUTOINCR);
	}

	cmd->cmd_transport = port->fp_fca_tran->fca_transport;

	cmd->cmd_pkt.pkt_tran_flags = FC_TRAN_INTR | class;
	cmd->cmd_pkt.pkt_tran_type = FC_PKT_EXCHANGE;
	cmd->cmd_flags = FP_CMD_PLOGI_DONT_CARE;
	cmd->cmd_retry_count = fp_retry_count;
	cmd->cmd_ulp_pkt = NULL;
}


/*
 * Name Server request interrupt routine
 */
static void
fp_ns_intr(fc_packet_t *pkt)
{
	fp_cmd_t	*cmd;
	fc_local_port_t	*port;
	fc_ct_header_t	resp_hdr;
	fc_ct_header_t	cmd_hdr;
	fctl_ns_req_t	*ns_cmd;

	cmd = pkt->pkt_ulp_private;
	port = cmd->cmd_port;

	mutex_enter(&port->fp_mutex);
	port->fp_out_fpcmds--;
	mutex_exit(&port->fp_mutex);

	FC_GET_RSP(port, pkt->pkt_cmd_acc, (uint8_t *)&cmd_hdr,
	    (uint8_t *)pkt->pkt_cmd, sizeof (cmd_hdr), DDI_DEV_AUTOINCR);
	ns_cmd = (fctl_ns_req_t *)
	    (((fp_cmd_t *)(pkt->pkt_ulp_private))->cmd_private);
	if (!FP_IS_PKT_ERROR(pkt)) {
		FC_GET_RSP(port, pkt->pkt_resp_acc, (uint8_t *)&resp_hdr,
		    (uint8_t *)pkt->pkt_resp, sizeof (resp_hdr),
		    DDI_DEV_AUTOINCR);

		/*
		 * On x86 architectures, make sure the resp_hdr is big endian.
		 * This macro is a NOP on sparc architectures mainly because
		 * we don't want to end up wasting time since the end result
		 * is going to be the same.
		 */
		MAKE_BE_32(&resp_hdr);

		if (ns_cmd) {
			/*
			 * Always copy out the response CT_HDR
			 */
			bcopy(&resp_hdr, &ns_cmd->ns_resp_hdr,
			    sizeof (resp_hdr));
		}

		if (resp_hdr.ct_cmdrsp == FS_RJT_IU) {
			pkt->pkt_state = FC_PKT_FS_RJT;
			pkt->pkt_reason = resp_hdr.ct_reason;
			pkt->pkt_expln = resp_hdr.ct_expln;
		}
	}

	if (FP_IS_PKT_ERROR(pkt)) {
		if (ns_cmd) {
			if (ns_cmd->ns_flags & FCTL_NS_VALIDATE_PD) {
				ASSERT(ns_cmd->ns_pd != NULL);

				/* Mark it OLD if not already done */
				mutex_enter(&ns_cmd->ns_pd->pd_mutex);
				ns_cmd->ns_pd->pd_type = PORT_DEVICE_OLD;
				mutex_exit(&ns_cmd->ns_pd->pd_mutex);
			}

			if (ns_cmd->ns_flags & FCTL_NS_ASYNC_REQUEST) {
				fctl_free_ns_cmd(ns_cmd);
				((fp_cmd_t *)
				    (pkt->pkt_ulp_private))->cmd_private = NULL;
			}

		}

		FP_TRACE(FP_NHEAD2(1, 0), "%x NS failure pkt state=%x "
		    "reason=%x, expln=%x, NSCMD=%04X, NSRSP=%04X",
		    port->fp_port_id.port_id, pkt->pkt_state,
		    pkt->pkt_reason, pkt->pkt_expln,
		    cmd_hdr.ct_cmdrsp,  resp_hdr.ct_cmdrsp);

		(void) fp_common_intr(pkt, 1);

		return;
	}

	if (resp_hdr.ct_cmdrsp != FS_ACC_IU) {
		uint32_t	d_id;
		fc_local_port_t	*port;
		fp_cmd_t	*cmd;

		d_id = pkt->pkt_cmd_fhdr.d_id;
		cmd = pkt->pkt_ulp_private;
		port = cmd->cmd_port;
		FP_TRACE(FP_NHEAD2(9, 0),
		    "Bogus NS response received for D_ID=%x", d_id);
	}

	if (cmd_hdr.ct_cmdrsp == NS_GA_NXT) {
		fp_gan_handler(pkt, ns_cmd);
		return;
	}

	if (cmd_hdr.ct_cmdrsp >= NS_GPN_ID &&
	    cmd_hdr.ct_cmdrsp <= NS_GID_PT) {
		if (ns_cmd) {
			if ((ns_cmd->ns_flags & FCTL_NS_NO_DATA_BUF) == 0) {
				fp_ns_query_handler(pkt, ns_cmd);
				return;
			}
		}
	}

	fp_iodone(pkt->pkt_ulp_private);
}


/*
 * Process NS_GAN response
 */
static void
fp_gan_handler(fc_packet_t *pkt, fctl_ns_req_t *ns_cmd)
{
	int			my_did;
	fc_portid_t		d_id;
	fp_cmd_t		*cmd;
	fc_local_port_t		*port;
	fc_remote_port_t	*pd;
	ns_req_gan_t		gan_req;
	ns_resp_gan_t		*gan_resp;

	ASSERT(ns_cmd != NULL);

	cmd = pkt->pkt_ulp_private;
	port = cmd->cmd_port;

	gan_resp = (ns_resp_gan_t *)(pkt->pkt_resp + sizeof (fc_ct_header_t));

	FC_GET_RSP(port, pkt->pkt_resp_acc, (uint8_t *)&d_id,
	    (uint8_t *)&gan_resp->gan_type_id, sizeof (d_id), DDI_DEV_AUTOINCR);

	*(uint32_t *)&d_id = BE_32(*(uint32_t *)&d_id);

	/*
	 * In this case the priv_lilp_posit field  in reality
	 * is actually represents the relative position on a private loop.
	 * So zero it while dealing with Port Identifiers.
	 */
	d_id.priv_lilp_posit = 0;
	pd = fctl_get_remote_port_by_did(port, d_id.port_id);
	if (ns_cmd->ns_gan_sid == d_id.port_id) {
		/*
		 * We've come a full circle; time to get out.
		 */
		fp_iodone(cmd);
		return;
	}

	if (ns_cmd->ns_gan_sid == FCTL_GAN_START_ID) {
		ns_cmd->ns_gan_sid = d_id.port_id;
	}

	mutex_enter(&port->fp_mutex);
	my_did = (d_id.port_id == port->fp_port_id.port_id) ? 1 : 0;
	mutex_exit(&port->fp_mutex);

	FP_TRACE(FP_NHEAD1(1, 0), "GAN response; port=%p, fp %x pd %x", port,
	    port->fp_port_id.port_id, d_id.port_id);
	if (my_did == 0) {
		la_wwn_t pwwn;
		la_wwn_t nwwn;

		FP_TRACE(FP_NHEAD1(1, 0), "GAN response details; "
		    "port=%p, d_id=%x, type_id=%x, "
		    "pwwn=%x %x %x %x %x %x %x %x, "
		    "nwwn=%x %x %x %x %x %x %x %x",
		    port, d_id.port_id, gan_resp->gan_type_id,

		    gan_resp->gan_pwwn.raw_wwn[0],
		    gan_resp->gan_pwwn.raw_wwn[1],
		    gan_resp->gan_pwwn.raw_wwn[2],
		    gan_resp->gan_pwwn.raw_wwn[3],
		    gan_resp->gan_pwwn.raw_wwn[4],
		    gan_resp->gan_pwwn.raw_wwn[5],
		    gan_resp->gan_pwwn.raw_wwn[6],
		    gan_resp->gan_pwwn.raw_wwn[7],

		    gan_resp->gan_nwwn.raw_wwn[0],
		    gan_resp->gan_nwwn.raw_wwn[1],
		    gan_resp->gan_nwwn.raw_wwn[2],
		    gan_resp->gan_nwwn.raw_wwn[3],
		    gan_resp->gan_nwwn.raw_wwn[4],
		    gan_resp->gan_nwwn.raw_wwn[5],
		    gan_resp->gan_nwwn.raw_wwn[6],
		    gan_resp->gan_nwwn.raw_wwn[7]);

		FC_GET_RSP(port, pkt->pkt_resp_acc, (uint8_t *)&nwwn,
		    (uint8_t *)&gan_resp->gan_nwwn, sizeof (nwwn),
		    DDI_DEV_AUTOINCR);

		FC_GET_RSP(port, pkt->pkt_resp_acc, (uint8_t *)&pwwn,
		    (uint8_t *)&gan_resp->gan_pwwn, sizeof (pwwn),
		    DDI_DEV_AUTOINCR);

		if (ns_cmd->ns_flags & FCTL_NS_CREATE_DEVICE && pd == NULL) {
			FP_TRACE(FP_NHEAD1(1, 0), "fp %x gan_hander create"
			    "pd %x", port->fp_port_id.port_id, d_id.port_id);
			pd = fctl_create_remote_port(port, &nwwn, &pwwn,
			    d_id.port_id, PD_PLOGI_INITIATOR, KM_NOSLEEP);
		}
		if (pd != NULL) {
			fp_stuff_device_with_gan(&pkt->pkt_resp_acc,
			    pd, gan_resp);
		}

		if (ns_cmd->ns_flags & FCTL_NS_GET_DEV_COUNT) {
			*((int *)ns_cmd->ns_data_buf) += 1;
		}

		if (ns_cmd->ns_flags & FCTL_NS_FILL_NS_MAP) {
			ASSERT((ns_cmd->ns_flags & FCTL_NS_NO_DATA_BUF) == 0);

			if (ns_cmd->ns_flags & FCTL_NS_BUF_IS_USERLAND) {
				fc_port_dev_t *userbuf;

				userbuf = ((fc_port_dev_t *)
				    ns_cmd->ns_data_buf) +
				    ns_cmd->ns_gan_index++;

				userbuf->dev_did = d_id;

				FC_GET_RSP(port, pkt->pkt_resp_acc,
				    (uint8_t *)userbuf->dev_type,
				    (uint8_t *)gan_resp->gan_fc4types,
				    sizeof (userbuf->dev_type),
				    DDI_DEV_AUTOINCR);

				userbuf->dev_nwwn = nwwn;
				userbuf->dev_pwwn = pwwn;

				if (pd != NULL) {
					mutex_enter(&pd->pd_mutex);
					userbuf->dev_state = pd->pd_state;
					userbuf->dev_hard_addr =
					    pd->pd_hard_addr;
					mutex_exit(&pd->pd_mutex);
				} else {
					userbuf->dev_state =
					    PORT_DEVICE_INVALID;
				}
			} else if (ns_cmd->ns_flags &
			    FCTL_NS_BUF_IS_FC_PORTMAP) {
				fc_portmap_t *map;

				map = ((fc_portmap_t *)
				    ns_cmd->ns_data_buf) +
				    ns_cmd->ns_gan_index++;

				/*
				 * First fill it like any new map
				 * and update the port device info
				 * below.
				 */
				fp_fillout_new_nsmap(port, &pkt->pkt_resp_acc,
				    map, gan_resp, d_id.port_id);
				if (pd != NULL) {
					fctl_copy_portmap(map, pd);
				} else {
					map->map_state = PORT_DEVICE_INVALID;
					map->map_type = PORT_DEVICE_NOCHANGE;
				}
			} else {
				caddr_t dst_ptr;

				dst_ptr = ns_cmd->ns_data_buf +
				    (NS_GAN_RESP_LEN) * ns_cmd->ns_gan_index++;

				FC_GET_RSP(port, pkt->pkt_resp_acc,
				    (uint8_t *)dst_ptr, (uint8_t *)gan_resp,
				    NS_GAN_RESP_LEN, DDI_DEV_AUTOINCR);
			}
		} else {
			ns_cmd->ns_gan_index++;
		}
		if (ns_cmd->ns_gan_index >= ns_cmd->ns_gan_max) {
			fp_iodone(cmd);
			return;
		}
	}

	gan_req.pid = d_id;

	FC_SET_CMD(port, pkt->pkt_cmd_acc, (uint8_t *)&gan_req,
	    (uint8_t *)(pkt->pkt_cmd + sizeof (fc_ct_header_t)),
	    sizeof (gan_req), DDI_DEV_AUTOINCR);

	if (cmd->cmd_transport(port->fp_fca_handle, pkt) != FC_SUCCESS) {
		pkt->pkt_state = FC_PKT_TRAN_ERROR;
		fp_iodone(cmd);
	} else {
		mutex_enter(&port->fp_mutex);
		port->fp_out_fpcmds++;
		mutex_exit(&port->fp_mutex);
	}
}


/*
 * Handle NS Query interrupt
 */
static void
fp_ns_query_handler(fc_packet_t *pkt, fctl_ns_req_t *ns_cmd)
{
	fp_cmd_t	*cmd;
	fc_local_port_t	*port;
	caddr_t		src_ptr;
	uint32_t	xfer_len;

	cmd = pkt->pkt_ulp_private;
	port = cmd->cmd_port;

	xfer_len = ns_cmd->ns_resp_size;

	FP_TRACE(FP_NHEAD1(1, 0), "NS Query response, cmd_code=%x, xfer_len=%x",
	    ns_cmd->ns_cmd_code, xfer_len);

	if (ns_cmd->ns_cmd_code == NS_GPN_ID) {
		src_ptr = (caddr_t)pkt->pkt_resp + sizeof (fc_ct_header_t);

		FP_TRACE(FP_NHEAD1(6, 0), "GPN_ID results; %x %x %x %x %x",
		    src_ptr[0], src_ptr[1], src_ptr[2], src_ptr[3], src_ptr[4]);
	}

	if (xfer_len <= ns_cmd->ns_data_len) {
		src_ptr = (caddr_t)pkt->pkt_resp + sizeof (fc_ct_header_t);
		FC_GET_RSP(port, pkt->pkt_resp_acc,
		    (uint8_t *)ns_cmd->ns_data_buf,
		    (uint8_t *)src_ptr, xfer_len, DDI_DEV_AUTOINCR);
	}

	if (ns_cmd->ns_flags & FCTL_NS_VALIDATE_PD) {
		ASSERT(ns_cmd->ns_pd != NULL);

		mutex_enter(&ns_cmd->ns_pd->pd_mutex);
		if (ns_cmd->ns_pd->pd_type == PORT_DEVICE_OLD) {
			ns_cmd->ns_pd->pd_type = PORT_DEVICE_NOCHANGE;
		}
		mutex_exit(&ns_cmd->ns_pd->pd_mutex);
	}

	if (ns_cmd->ns_flags & FCTL_NS_ASYNC_REQUEST) {
		fctl_free_ns_cmd(ns_cmd);
		((fp_cmd_t *)(pkt->pkt_ulp_private))->cmd_private = NULL;
	}
	fp_iodone(cmd);
}


/*
 * Handle unsolicited ADISC ELS request
 */
static void
fp_handle_unsol_adisc(fc_local_port_t *port, fc_unsol_buf_t *buf,
    fc_remote_port_t *pd, job_request_t *job)
{
	int		rval;
	fp_cmd_t	*cmd;

	FP_TRACE(FP_NHEAD1(5, 0), "ADISC; port=%p, D_ID=%x state=%x, pd=%p",
	    port, pd->pd_port_id.port_id, pd->pd_state, pd);
	mutex_enter(&pd->pd_mutex);
	if (pd->pd_state != PORT_DEVICE_LOGGED_IN) {
		mutex_exit(&pd->pd_mutex);
		if (FP_IS_CLASS_1_OR_2(buf->ub_class)) {
			cmd = fp_alloc_pkt(port, sizeof (la_els_rjt_t),
			    0, KM_SLEEP, pd);
			if (cmd != NULL) {
				fp_els_rjt_init(port, cmd, buf,
				    FC_ACTION_NON_RETRYABLE,
				    FC_REASON_INVALID_LINK_CTRL, job);

				if (fp_sendcmd(port, cmd,
				    port->fp_fca_handle) != FC_SUCCESS) {
					fp_free_pkt(cmd);
				}
			}
		}
	} else {
		mutex_exit(&pd->pd_mutex);
		/*
		 * Yes, yes, we don't have a hard address. But we
		 * we should still respond. Huh ? Visit 21.19.2
		 * of FC-PH-2 which essentially says that if an
		 * NL_Port doesn't have a hard address, or if a port
		 * does not have FC-AL capability, it shall report
		 * zeroes in this field.
		 */
		cmd = fp_alloc_pkt(port, sizeof (la_els_adisc_t),
		    0, KM_SLEEP, pd);
		if (cmd == NULL) {
			return;
		}
		fp_adisc_acc_init(port, cmd, buf, job);
		rval = fp_sendcmd(port, cmd, port->fp_fca_handle);
		if (rval != FC_SUCCESS) {
			fp_free_pkt(cmd);
		}
	}
}


/*
 * Initialize ADISC response.
 */
static void
fp_adisc_acc_init(fc_local_port_t *port, fp_cmd_t *cmd, fc_unsol_buf_t *buf,
    job_request_t *job)
{
	fc_packet_t	*pkt;
	la_els_adisc_t	payload;

	cmd->cmd_pkt.pkt_tran_flags = buf->ub_class;
	cmd->cmd_pkt.pkt_tran_type = FC_PKT_OUTBOUND;
	cmd->cmd_flags = FP_CMD_CFLAG_UNDEFINED;
	cmd->cmd_retry_count = 1;
	cmd->cmd_ulp_pkt = NULL;

	cmd->cmd_transport = port->fp_fca_tran->fca_els_send;
	cmd->cmd_job = job;

	pkt = &cmd->cmd_pkt;

	fp_unsol_resp_init(pkt, buf, R_CTL_ELS_RSP, FC_TYPE_EXTENDED_LS);

	payload.ls_code.ls_code = LA_ELS_ACC;
	payload.ls_code.mbz = 0;

	mutex_enter(&port->fp_mutex);
	payload.nport_id = port->fp_port_id;
	payload.hard_addr = port->fp_hard_addr;
	mutex_exit(&port->fp_mutex);

	payload.port_wwn = port->fp_service_params.nport_ww_name;
	payload.node_wwn = port->fp_service_params.node_ww_name;

	FC_SET_CMD(port, pkt->pkt_cmd_acc, (uint8_t *)&payload,
	    (uint8_t *)pkt->pkt_cmd, sizeof (payload), DDI_DEV_AUTOINCR);
}


/*
 * Hold and Install the requested ULP drivers
 */
static void
fp_load_ulp_modules(dev_info_t *dip, fc_local_port_t *port)
{
	int		len;
	int		count;
	int		data_len;
	major_t		ulp_major;
	caddr_t		ulp_name;
	caddr_t		data_ptr;
	caddr_t		data_buf;

	ASSERT(!MUTEX_HELD(&port->fp_mutex));

	data_buf = NULL;
	if (ddi_getlongprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "load-ulp-list",
	    (caddr_t)&data_buf, &data_len) != DDI_PROP_SUCCESS) {
		return;
	}

	len = strlen(data_buf);
	port->fp_ulp_nload = fctl_atoi(data_buf, 10);

	data_ptr = data_buf + len + 1;
	for (count = 0; count < port->fp_ulp_nload; count++) {
		len = strlen(data_ptr) + 1;
		ulp_name = kmem_zalloc(len, KM_SLEEP);
		bcopy(data_ptr, ulp_name, len);

		ulp_major = ddi_name_to_major(ulp_name);

		if (ulp_major != (major_t)-1) {
			if (modload("drv", ulp_name) < 0) {
				fp_printf(port, CE_NOTE, FP_LOG_ONLY,
				    0, NULL, "failed to load %s",
				    ulp_name);
			}
		} else {
			fp_printf(port, CE_NOTE, FP_LOG_ONLY, 0, NULL,
			    "%s isn't a valid driver", ulp_name);
		}

		kmem_free(ulp_name, len);
		data_ptr += len;	/* Skip to next field */
	}

	/*
	 * Free the memory allocated by DDI
	 */
	if (data_buf != NULL) {
		kmem_free(data_buf, data_len);
	}
}


/*
 * Perform LOGO operation
 */
static int
fp_logout(fc_local_port_t *port, fc_remote_port_t *pd, job_request_t *job)
{
	int		rval;
	fp_cmd_t	*cmd;

	ASSERT(!MUTEX_HELD(&port->fp_mutex));
	ASSERT(!MUTEX_HELD(&pd->pd_mutex));

	cmd = fp_alloc_pkt(port, sizeof (la_els_logo_t),
	    FP_PORT_IDENTIFIER_LEN, KM_SLEEP, pd);

	mutex_enter(&port->fp_mutex);
	mutex_enter(&pd->pd_mutex);

	ASSERT(pd->pd_state == PORT_DEVICE_LOGGED_IN);
	ASSERT(pd->pd_login_count == 1);

	cmd->cmd_pkt.pkt_tran_flags = FC_TRAN_INTR | pd->pd_login_class;
	cmd->cmd_pkt.pkt_tran_type = FC_PKT_EXCHANGE;
	cmd->cmd_flags = 0;
	cmd->cmd_retry_count = 1;
	cmd->cmd_ulp_pkt = NULL;

	fp_logo_init(pd, cmd, job);

	mutex_exit(&pd->pd_mutex);
	mutex_exit(&port->fp_mutex);

	rval = fp_sendcmd(port, cmd, port->fp_fca_handle);
	if (rval != FC_SUCCESS) {
		fp_iodone(cmd);
	}

	return (rval);
}


/*
 * Perform Port attach callbacks to registered ULPs
 */
static void
fp_attach_ulps(fc_local_port_t *port, fc_attach_cmd_t cmd)
{
	fp_soft_attach_t *att;

	att = kmem_zalloc(sizeof (*att), KM_SLEEP);
	att->att_cmd = cmd;
	att->att_port = port;

	/*
	 * We need to remember whether or not fctl_busy_port
	 * succeeded so we know whether or not to call
	 * fctl_idle_port when the task is complete.
	 */

	if (fctl_busy_port(port) == 0) {
		att->att_need_pm_idle = B_TRUE;
	} else {
		att->att_need_pm_idle = B_FALSE;
	}

	(void) taskq_dispatch(port->fp_taskq, fp_ulp_port_attach,
	    att, KM_SLEEP);
}


/*
 * Forward state change notifications on to interested ULPs.
 * Spawns a call to fctl_ulp_statec_cb() in a taskq thread to do all the
 * real work.
 */
static int
fp_ulp_notify(fc_local_port_t *port, uint32_t statec, int sleep)
{
	fc_port_clist_t *clist;

	clist = kmem_zalloc(sizeof (*clist), sleep);
	if (clist == NULL) {
		return (FC_NOMEM);
	}

	clist->clist_state = statec;

	mutex_enter(&port->fp_mutex);
	clist->clist_flags = port->fp_topology;
	mutex_exit(&port->fp_mutex);

	clist->clist_port = (opaque_t)port;
	clist->clist_len = 0;
	clist->clist_size = 0;
	clist->clist_map = NULL;

	(void) taskq_dispatch(port->fp_taskq, fctl_ulp_statec_cb,
	    clist, KM_SLEEP);

	return (FC_SUCCESS);
}


/*
 * Get name server map
 */
static int
fp_ns_getmap(fc_local_port_t *port, job_request_t *job, fc_portmap_t **map,
    uint32_t *len, uint32_t sid)
{
	int ret;
	fctl_ns_req_t *ns_cmd;

	/*
	 * Don't let the allocator do anything for response;
	 * we have have buffer ready to fillout.
	 */
	ns_cmd = fctl_alloc_ns_cmd(sizeof (ns_req_gan_t),
	    sizeof (ns_resp_gan_t), 0, (FCTL_NS_FILL_NS_MAP |
	    FCTL_NS_BUF_IS_FC_PORTMAP), KM_SLEEP);

	ns_cmd->ns_data_len = sizeof (**map) * (*len);
	ns_cmd->ns_data_buf = (caddr_t)*map;

	ASSERT(ns_cmd != NULL);

	ns_cmd->ns_gan_index = 0;
	ns_cmd->ns_gan_sid = sid;
	ns_cmd->ns_cmd_code = NS_GA_NXT;
	ns_cmd->ns_gan_max = *len;

	ret = fp_ns_query(port, ns_cmd, job, 1, KM_SLEEP);

	if (ns_cmd->ns_gan_index != *len) {
		*len = ns_cmd->ns_gan_index;
	}
	ns_cmd->ns_data_len = 0;
	ns_cmd->ns_data_buf = NULL;
	fctl_free_ns_cmd(ns_cmd);

	return (ret);
}


/*
 * Create a remote port in Fabric topology by using NS services
 */
static fc_remote_port_t *
fp_create_remote_port_by_ns(fc_local_port_t *port, uint32_t d_id, int sleep)
{
	int			rval;
	job_request_t		*job;
	fctl_ns_req_t		*ns_cmd;
	fc_remote_port_t	*pd;

	ASSERT(!MUTEX_HELD(&port->fp_mutex));

	FP_TRACE(FP_NHEAD1(1, 0), "PD creation begin; port=%p, d_id=%x",
	    port, d_id);

#ifdef	DEBUG
	mutex_enter(&port->fp_mutex);
	ASSERT(FC_IS_TOP_SWITCH(port->fp_topology));
	mutex_exit(&port->fp_mutex);
#endif

	job = fctl_alloc_job(JOB_NS_CMD, 0, NULL, (opaque_t)port, sleep);
	if (job == NULL) {
		return (NULL);
	}

	ns_cmd = fctl_alloc_ns_cmd(sizeof (ns_req_gan_t),
	    sizeof (ns_resp_gan_t), 0, (FCTL_NS_CREATE_DEVICE |
	    FCTL_NS_NO_DATA_BUF), sleep);
	if (ns_cmd == NULL) {
		return (NULL);
	}

	job->job_result = FC_SUCCESS;
	ns_cmd->ns_gan_max = 1;
	ns_cmd->ns_cmd_code = NS_GA_NXT;
	ns_cmd->ns_gan_sid = FCTL_GAN_START_ID;
	((ns_req_gan_t *)(ns_cmd->ns_cmd_buf))->pid.port_id = d_id - 1;
	((ns_req_gan_t *)(ns_cmd->ns_cmd_buf))->pid.priv_lilp_posit = 0;

	ASSERT((job->job_flags & JOB_TYPE_FP_ASYNC) == 0);
	rval = fp_ns_query(port, ns_cmd, job, 1, KM_SLEEP);
	fctl_free_ns_cmd(ns_cmd);

	if (rval != FC_SUCCESS || job->job_result != FC_SUCCESS) {
		fctl_dealloc_job(job);
		return (NULL);
	}
	fctl_dealloc_job(job);

	pd = fctl_get_remote_port_by_did(port, d_id);

	FP_TRACE(FP_NHEAD1(1, 0), "PD creation end; port=%p, d_id=%x, pd=%p",
	    port, d_id, pd);

	return (pd);
}


/*
 * Check for the permissions on an ioctl command. If it is required to have an
 * EXCLUSIVE open performed, return a FAILURE to just shut the door on it. If
 * the ioctl command isn't in one of the list built, shut the door on that too.
 *
 *	Certain ioctls perform hardware accesses in FCA drivers, and it needs
 *	to be made sure that users open the port for an exclusive access while
 *	performing those operations.
 *
 *	This can prevent a casual user from inflicting damage on the port by
 *	sending these ioctls from multiple processes/threads (there is no good
 *	reason why one would need to do that) without actually realizing how
 *	expensive such commands could turn out to be.
 *
 *	It is also important to note that, even with an exclusive access,
 *	multiple threads can share the same file descriptor and fire down
 *	commands in parallel. To prevent that the driver needs to make sure
 *	that such commands aren't in progress already. This is taken care of
 *	in the FP_EXCL_BUSY bit of fp_flag.
 */
static int
fp_check_perms(uchar_t open_flag, uint16_t ioctl_cmd)
{
	int ret = FC_FAILURE;
	int count;

	for (count = 0;
	    count < sizeof (fp_perm_list) / sizeof (fp_perm_list[0]);
	    count++) {
		if (fp_perm_list[count].fp_ioctl_cmd == ioctl_cmd) {
			if (fp_perm_list[count].fp_open_flag & open_flag) {
				ret = FC_SUCCESS;
			}
			break;
		}
	}

	return (ret);
}


/*
 * Bind Port driver's unsolicited, state change callbacks
 */
static int
fp_bind_callbacks(fc_local_port_t *port)
{
	fc_fca_bind_info_t	bind_info = {0};
	fc_fca_port_info_t	*port_info;
	int		rval =	DDI_SUCCESS;
	uint16_t	class;
	int		node_namelen, port_namelen;
	char		*nname = NULL, *pname = NULL;

	ASSERT(!MUTEX_HELD(&port->fp_mutex));

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, port->fp_port_dip,
	    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS,
	    "node-name", &nname) != DDI_PROP_SUCCESS) {
		FP_TRACE(FP_NHEAD1(1, 0),
		    "fp_bind_callback fail to get node-name");
	}
	if (nname) {
		fc_str_to_wwn(nname, &(bind_info.port_nwwn));
	}

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, port->fp_port_dip,
	    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS,
	    "port-name", &pname) != DDI_PROP_SUCCESS) {
		FP_TRACE(FP_NHEAD1(1, 0),
		    "fp_bind_callback fail to get port-name");
	}
	if (pname) {
		fc_str_to_wwn(pname, &(bind_info.port_pwwn));
	}

	if (port->fp_npiv_type == FC_NPIV_PORT) {
		bind_info.port_npiv = 1;
	}

	/*
	 * fca_bind_port returns the FCA driver's handle for the local
	 * port instance. If the port number isn't supported it returns NULL.
	 * It also sets up callback in the FCA for various
	 * things like state change, ELS etc..
	 */
	bind_info.port_statec_cb = fp_statec_cb;
	bind_info.port_unsol_cb = fp_unsol_cb;
	bind_info.port_num = port->fp_port_num;
	bind_info.port_handle = (opaque_t)port;

	port_info = kmem_zalloc(sizeof (*port_info), KM_SLEEP);

	/*
	 * Hold the port driver mutex as the callbacks are bound until the
	 * service parameters are properly filled in (in order to be able to
	 * properly respond to unsolicited ELS requests)
	 */
	mutex_enter(&port->fp_mutex);

	port->fp_fca_handle = port->fp_fca_tran->fca_bind_port(
	    port->fp_fca_dip, port_info, &bind_info);

	if (port->fp_fca_handle == NULL) {
		rval = DDI_FAILURE;
		goto exit;
	}

	/*
	 * Only fcoei will set this bit
	 */
	if (port_info->pi_port_state & FC_STATE_FCA_IS_NODMA) {
		port->fp_soft_state |= FP_SOFT_FCA_IS_NODMA;
		port_info->pi_port_state &= ~(FC_STATE_FCA_IS_NODMA);
	}

	port->fp_bind_state = port->fp_state = port_info->pi_port_state;
	port->fp_service_params = port_info->pi_login_params;
	port->fp_hard_addr = port_info->pi_hard_addr;

	/* Copy from the FCA structure to the FP structure */
	port->fp_hba_port_attrs = port_info->pi_attrs;

	if (port_info->pi_rnid_params.status == FC_SUCCESS) {
		port->fp_rnid_init = 1;
		bcopy(&port_info->pi_rnid_params.params,
		    &port->fp_rnid_params,
		    sizeof (port->fp_rnid_params));
	} else {
		port->fp_rnid_init = 0;
	}

	node_namelen = strlen((char *)&port_info->pi_attrs.sym_node_name);
	if (node_namelen) {
		bcopy(&port_info->pi_attrs.sym_node_name,
		    &port->fp_sym_node_name,
		    node_namelen);
		port->fp_sym_node_namelen = node_namelen;
	}
	port_namelen = strlen((char *)&port_info->pi_attrs.sym_port_name);
	if (port_namelen) {
		bcopy(&port_info->pi_attrs.sym_port_name,
		    &port->fp_sym_port_name,
		    port_namelen);
		port->fp_sym_port_namelen = port_namelen;
	}

	/* zero out the normally unused fields right away */
	port->fp_service_params.ls_code.mbz = 0;
	port->fp_service_params.ls_code.ls_code = 0;
	bzero(&port->fp_service_params.reserved,
	    sizeof (port->fp_service_params.reserved));

	class = port_info->pi_login_params.class_1.class_opt;
	port->fp_cos |= (class & 0x8000) ? FC_NS_CLASS1 : 0;

	class = port_info->pi_login_params.class_2.class_opt;
	port->fp_cos |= (class & 0x8000) ? FC_NS_CLASS2 : 0;

	class = port_info->pi_login_params.class_3.class_opt;
	port->fp_cos |= (class & 0x8000) ? FC_NS_CLASS3 : 0;

exit:
	if (nname) {
		ddi_prop_free(nname);
	}
	if (pname) {
		ddi_prop_free(pname);
	}
	mutex_exit(&port->fp_mutex);
	kmem_free(port_info, sizeof (*port_info));

	return (rval);
}


/*
 * Retrieve FCA capabilities
 */
static void
fp_retrieve_caps(fc_local_port_t *port)
{
	int			rval;
	int			ub_count;
	fc_fcp_dma_t		fcp_dma;
	fc_reset_action_t	action;
	fc_dma_behavior_t	dma_behavior;

	ASSERT(!MUTEX_HELD(&port->fp_mutex));

	rval = port->fp_fca_tran->fca_get_cap(port->fp_fca_handle,
	    FC_CAP_UNSOL_BUF, &ub_count);

	switch (rval) {
	case FC_CAP_FOUND:
	case FC_CAP_SETTABLE:
		switch (ub_count) {
		case 0:
			break;

		case -1:
			ub_count = fp_unsol_buf_count;
			break;

		default:
			/* 1/4th of total buffers is my share */
			ub_count =
			    (ub_count / port->fp_fca_tran->fca_numports) >> 2;
			break;
		}
		break;

	default:
		ub_count = 0;
		break;
	}

	mutex_enter(&port->fp_mutex);
	port->fp_ub_count = ub_count;
	mutex_exit(&port->fp_mutex);

	rval = port->fp_fca_tran->fca_get_cap(port->fp_fca_handle,
	    FC_CAP_POST_RESET_BEHAVIOR, &action);

	switch (rval) {
	case FC_CAP_FOUND:
	case FC_CAP_SETTABLE:
		switch (action) {
		case FC_RESET_RETURN_NONE:
		case FC_RESET_RETURN_ALL:
		case FC_RESET_RETURN_OUTSTANDING:
			break;

		default:
			action = FC_RESET_RETURN_NONE;
			break;
		}
		break;

	default:
		action = FC_RESET_RETURN_NONE;
		break;
	}
	mutex_enter(&port->fp_mutex);
	port->fp_reset_action = action;
	mutex_exit(&port->fp_mutex);

	rval = port->fp_fca_tran->fca_get_cap(port->fp_fca_handle,
	    FC_CAP_NOSTREAM_ON_UNALIGN_BUF, &dma_behavior);

	switch (rval) {
	case FC_CAP_FOUND:
		switch (dma_behavior) {
		case FC_ALLOW_STREAMING:
			/* FALLTHROUGH */
		case FC_NO_STREAMING:
			break;

		default:
			/*
			 * If capability was found and the value
			 * was incorrect assume the worst
			 */
			dma_behavior = FC_NO_STREAMING;
			break;
		}
		break;

	default:
		/*
		 * If capability was not defined - allow streaming; existing
		 * FCAs should not be affected.
		 */
		dma_behavior = FC_ALLOW_STREAMING;
		break;
	}
	mutex_enter(&port->fp_mutex);
	port->fp_dma_behavior = dma_behavior;
	mutex_exit(&port->fp_mutex);

	rval = port->fp_fca_tran->fca_get_cap(port->fp_fca_handle,
	    FC_CAP_FCP_DMA, &fcp_dma);

	if (rval != FC_CAP_FOUND || (fcp_dma != FC_NO_DVMA_SPACE &&
	    fcp_dma != FC_DVMA_SPACE)) {
		fcp_dma = FC_DVMA_SPACE;
	}

	mutex_enter(&port->fp_mutex);
	port->fp_fcp_dma = fcp_dma;
	mutex_exit(&port->fp_mutex);
}


/*
 * Handle Domain, Area changes in the Fabric.
 */
static void
fp_validate_area_domain(fc_local_port_t *port, uint32_t id, uint32_t mask,
    job_request_t *job, int sleep)
{
#ifdef	DEBUG
	uint32_t		dcnt;
#endif
	int			rval;
	int			send;
	int			index;
	int			listindex;
	int			login;
	int			job_flags;
	char			ww_name[17];
	uint32_t		d_id;
	uint32_t		count;
	fctl_ns_req_t		*ns_cmd;
	fc_portmap_t		*list;
	fc_orphan_t		*orp;
	fc_orphan_t		*norp;
	fc_orphan_t		*prev;
	fc_remote_port_t	*pd;
	fc_remote_port_t	*npd;
	struct pwwn_hash	*head;

	ns_cmd = fctl_alloc_ns_cmd(sizeof (ns_req_gid_pn_t),
	    sizeof (ns_resp_gid_pn_t), sizeof (ns_resp_gid_pn_t),
	    0, sleep);
	if (ns_cmd == NULL) {
		mutex_enter(&port->fp_mutex);
		if (--port->fp_rscn_count == FC_INVALID_RSCN_COUNT) {
			--port->fp_rscn_count;
		}
		mutex_exit(&port->fp_mutex);

		return;
	}
	ns_cmd->ns_cmd_code = NS_GID_PN;

	/*
	 * We need to get a new count of devices from the
	 * name server, which will also create any new devices
	 * as needed.
	 */

	(void) fp_ns_get_devcount(port, job, 1, sleep);

	FP_TRACE(FP_NHEAD1(3, 0),
	    "fp_validate_area_domain: get_devcount found %d devices",
	    port->fp_total_devices);

	mutex_enter(&port->fp_mutex);

	for (count = index = 0; index < pwwn_table_size; index++) {
		head = &port->fp_pwwn_table[index];
		pd = head->pwwn_head;
		while (pd != NULL) {
			mutex_enter(&pd->pd_mutex);
			if (pd->pd_flags != PD_ELS_IN_PROGRESS) {
				if ((pd->pd_port_id.port_id & mask) == id &&
				    pd->pd_recepient == PD_PLOGI_INITIATOR) {
					count++;
					pd->pd_type = PORT_DEVICE_OLD;
					pd->pd_flags = PD_ELS_MARK;
				}
			}
			mutex_exit(&pd->pd_mutex);
			pd = pd->pd_wwn_hnext;
		}
	}

#ifdef	DEBUG
	dcnt = count;
#endif /* DEBUG */

	/*
	 * Since port->fp_orphan_count is declared an 'int' it is
	 * theoretically possible that the count could go negative.
	 *
	 * This would be bad and if that happens we really do want
	 * to know.
	 */

	ASSERT(port->fp_orphan_count >= 0);

	count += port->fp_orphan_count;

	/*
	 * We add the port->fp_total_devices value to the count
	 * in the case where our port is newly attached. This is
	 * because we haven't done any discovery and we don't have
	 * any orphans in the port's orphan list. If we do not do
	 * this addition to count then we won't alloc enough kmem
	 * to do discovery with.
	 */

	if (count == 0) {
		count += port->fp_total_devices;
		FP_TRACE(FP_NHEAD1(3, 0), "fp_validate_area_domain: "
		    "0x%x orphans found, using 0x%x",
		    port->fp_orphan_count, count);
	}

	mutex_exit(&port->fp_mutex);

	/*
	 * Allocate the change list
	 */

	list = kmem_zalloc(sizeof (fc_portmap_t) * count, sleep);
	if (list == NULL) {
		fp_printf(port, CE_NOTE, FP_LOG_ONLY, 0, NULL,
		    " Not enough memory to service RSCNs"
		    " for %d ports, continuing...", count);

		fctl_free_ns_cmd(ns_cmd);

		mutex_enter(&port->fp_mutex);
		if (--port->fp_rscn_count == FC_INVALID_RSCN_COUNT) {
			--port->fp_rscn_count;
		}
		mutex_exit(&port->fp_mutex);

		return;
	}

	/*
	 * Attempt to validate or invalidate the devices that were
	 * already in the pwwn hash table.
	 */

	mutex_enter(&port->fp_mutex);
	for (listindex = 0, index = 0; index < pwwn_table_size; index++) {
		head = &port->fp_pwwn_table[index];
		npd = head->pwwn_head;

		while ((pd = npd) != NULL) {
			npd = pd->pd_wwn_hnext;

			mutex_enter(&pd->pd_mutex);
			if ((pd->pd_port_id.port_id & mask) == id &&
			    pd->pd_flags == PD_ELS_MARK) {
				la_wwn_t *pwwn;

				job->job_result = FC_SUCCESS;

				((ns_req_gid_pn_t *)
				    (ns_cmd->ns_cmd_buf))->pwwn =
				    pd->pd_port_name;

				pwwn = &pd->pd_port_name;
				d_id = pd->pd_port_id.port_id;

				mutex_exit(&pd->pd_mutex);
				mutex_exit(&port->fp_mutex);

				rval = fp_ns_query(port, ns_cmd, job, 1,
				    sleep);
				if (rval != FC_SUCCESS) {
					fc_wwn_to_str(pwwn, ww_name);

					FP_TRACE(FP_NHEAD1(3, 0),
					    "AREA RSCN: PD disappeared; "
					    "d_id=%x, PWWN=%s", d_id, ww_name);

					FP_TRACE(FP_NHEAD2(9, 0),
					    "N_x Port with D_ID=%x,"
					    " PWWN=%s disappeared from fabric",
					    d_id, ww_name);

					fp_fillout_old_map(list + listindex++,
					    pd, 1);
				} else {
					fctl_copy_portmap(list + listindex++,
					    pd);

					mutex_enter(&pd->pd_mutex);
					pd->pd_flags = PD_ELS_IN_PROGRESS;
					mutex_exit(&pd->pd_mutex);
				}

				mutex_enter(&port->fp_mutex);
			} else {
				mutex_exit(&pd->pd_mutex);
			}
		}
	}

	mutex_exit(&port->fp_mutex);

	ASSERT(listindex == dcnt);

	job->job_counter = listindex;
	job_flags = job->job_flags;
	job->job_flags |= JOB_TYPE_FP_ASYNC;

	/*
	 * Login (if we were the initiator) or validate devices in the
	 * port map.
	 */

	for (index = 0; index < listindex; index++) {
		pd = list[index].map_pd;

		mutex_enter(&pd->pd_mutex);
		ASSERT((pd->pd_port_id.port_id & mask) == id);

		if (pd->pd_flags != PD_ELS_IN_PROGRESS) {
			ASSERT(pd->pd_type == PORT_DEVICE_OLD);
			mutex_exit(&pd->pd_mutex);
			fp_jobdone(job);
			continue;
		}

		login = (pd->pd_state == PORT_DEVICE_LOGGED_IN) ? 1 : 0;
		send = (pd->pd_recepient == PD_PLOGI_INITIATOR) ? 1 : 0;
		d_id = pd->pd_port_id.port_id;
		mutex_exit(&pd->pd_mutex);

		if ((d_id & mask) == id && send) {
			if (login) {
				FP_TRACE(FP_NHEAD1(6, 0),
				    "RSCN and PLOGI request;"
				    " pd=%p, job=%p d_id=%x, index=%d", pd,
				    job, d_id, index);

				rval = fp_port_login(port, d_id, job,
				    FP_CMD_PLOGI_RETAIN, sleep, pd, NULL);
				if (rval != FC_SUCCESS) {
					mutex_enter(&pd->pd_mutex);
					pd->pd_flags = PD_IDLE;
					mutex_exit(&pd->pd_mutex);

					job->job_result = rval;
					fp_jobdone(job);
				}
				FP_TRACE(FP_NHEAD1(1, 0),
				    "PLOGI succeeded:no skip(1) for "
				    "D_ID %x", d_id);
				list[index].map_flags |=
				    PORT_DEVICE_NO_SKIP_DEVICE_DISCOVERY;
			} else {
				FP_TRACE(FP_NHEAD1(6, 0), "RSCN and NS request;"
				    " pd=%p, job=%p d_id=%x, index=%d", pd,
				    job, d_id, index);

				rval = fp_ns_validate_device(port, pd, job,
				    0, sleep);
				if (rval != FC_SUCCESS) {
					fp_jobdone(job);
				}
				mutex_enter(&pd->pd_mutex);
				pd->pd_flags = PD_IDLE;
				mutex_exit(&pd->pd_mutex);
			}
		} else {
			FP_TRACE(FP_NHEAD1(6, 0),
			    "RSCN and NO request sent; pd=%p,"
			    " d_id=%x, index=%d", pd, d_id, index);

			mutex_enter(&pd->pd_mutex);
			pd->pd_flags = PD_IDLE;
			mutex_exit(&pd->pd_mutex);

			fp_jobdone(job);
		}
	}

	if (listindex) {
		fctl_jobwait(job);
	}
	job->job_flags = job_flags;

	/*
	 * Orphan list validation.
	 */
	mutex_enter(&port->fp_mutex);
	for (prev = NULL, orp = port->fp_orphan_list; port->fp_orphan_count &&
	    orp != NULL; orp = norp) {
		norp = orp->orp_next;
		mutex_exit(&port->fp_mutex);

		job->job_counter = 1;
		job->job_result = FC_SUCCESS;
		ASSERT((job->job_flags & JOB_TYPE_FP_ASYNC) == 0);

		((ns_req_gid_pn_t *)ns_cmd->ns_cmd_buf)->pwwn = orp->orp_pwwn;

		((ns_resp_gid_pn_t *)ns_cmd->ns_data_buf)->pid.port_id = 0;
		((ns_resp_gid_pn_t *)
		    ns_cmd->ns_data_buf)->pid.priv_lilp_posit = 0;

		rval = fp_ns_query(port, ns_cmd, job, 1, KM_SLEEP);
		if (rval == FC_SUCCESS) {
			d_id = BE_32(*((uint32_t *)ns_cmd->ns_data_buf));
			pd = fp_create_remote_port_by_ns(port, d_id, KM_SLEEP);
			if (pd != NULL) {
				fc_wwn_to_str(&orp->orp_pwwn, ww_name);

				FP_TRACE(FP_NHEAD1(6, 0),
				    "RSCN and ORPHAN list "
				    "success; d_id=%x, PWWN=%s", d_id, ww_name);

				FP_TRACE(FP_NHEAD2(6, 0),
				    "N_x Port with D_ID=%x, PWWN=%s reappeared"
				    " in fabric", d_id, ww_name);

				mutex_enter(&port->fp_mutex);
				if (prev) {
					prev->orp_next = orp->orp_next;
				} else {
					ASSERT(orp == port->fp_orphan_list);
					port->fp_orphan_list = orp->orp_next;
				}
				port->fp_orphan_count--;
				mutex_exit(&port->fp_mutex);

				kmem_free(orp, sizeof (*orp));
				fctl_copy_portmap(list + listindex++, pd);
			} else {
				prev = orp;
			}
		} else {
			prev = orp;
		}
		mutex_enter(&port->fp_mutex);
	}
	mutex_exit(&port->fp_mutex);

	/*
	 * One more pass through the list to delist old devices from
	 * the d_id and pwwn tables and possibly add to the orphan list.
	 */

	for (index = 0; index < listindex; index++) {
		pd = list[index].map_pd;
		ASSERT(pd != NULL);

		/*
		 * Update PLOGI results; For NS validation
		 * of orphan list, it is redundant
		 *
		 * Take care to preserve PORT_DEVICE_NO_SKIP_DEVICE_DISCOVERY if
		 * appropriate as fctl_copy_portmap() will clear map_flags.
		 */
		if (list[index].map_flags &
		    PORT_DEVICE_NO_SKIP_DEVICE_DISCOVERY) {
			fctl_copy_portmap(list + index, pd);
			list[index].map_flags |=
			    PORT_DEVICE_NO_SKIP_DEVICE_DISCOVERY;
		} else {
			fctl_copy_portmap(list + index, pd);
		}

		FP_TRACE(FP_NHEAD1(6, 0), "RSCN with Area DOMAIN "
		    "results; pd=%p, d_id=%x pwwn=%x %x %x %x %x %x %x %x",
		    pd, pd->pd_port_id.port_id,
		    pd->pd_port_name.raw_wwn[0],
		    pd->pd_port_name.raw_wwn[1],
		    pd->pd_port_name.raw_wwn[2],
		    pd->pd_port_name.raw_wwn[3],
		    pd->pd_port_name.raw_wwn[4],
		    pd->pd_port_name.raw_wwn[5],
		    pd->pd_port_name.raw_wwn[6],
		    pd->pd_port_name.raw_wwn[7]);

		FP_TRACE(FP_NHEAD1(6, 0), "RSCN with Area DOMAIN "
		    "results continued, pd=%p type=%x, flags=%x, state=%x",
		    pd, pd->pd_type, pd->pd_flags, pd->pd_state);

		mutex_enter(&pd->pd_mutex);
		if (pd->pd_type == PORT_DEVICE_OLD) {
			int initiator;

			pd->pd_flags = PD_IDLE;
			initiator = (pd->pd_recepient ==
			    PD_PLOGI_INITIATOR) ? 1 : 0;

			mutex_exit(&pd->pd_mutex);

			mutex_enter(&port->fp_mutex);
			mutex_enter(&pd->pd_mutex);

			pd->pd_state = PORT_DEVICE_INVALID;
			fctl_delist_did_table(port, pd);
			fctl_delist_pwwn_table(port, pd);

			mutex_exit(&pd->pd_mutex);
			mutex_exit(&port->fp_mutex);

			if (initiator) {
				(void) fctl_add_orphan(port, pd, sleep);
			}
			list[index].map_pd = pd;
		} else {
			ASSERT(pd->pd_flags == PD_IDLE);
			if (pd->pd_state == PORT_DEVICE_LOGGED_IN) {
				/*
				 * Reset LOGO tolerance to zero
				 */
				fctl_tc_reset(&pd->pd_logo_tc);
			}
			mutex_exit(&pd->pd_mutex);
		}
	}

	if (ns_cmd) {
		fctl_free_ns_cmd(ns_cmd);
	}
	if (listindex) {
		(void) fp_ulp_devc_cb(port, list, listindex, count,
		    sleep, 0);
	} else {
		kmem_free(list, sizeof (*list) * count);

		mutex_enter(&port->fp_mutex);
		if (--port->fp_rscn_count == FC_INVALID_RSCN_COUNT) {
			--port->fp_rscn_count;
		}
		mutex_exit(&port->fp_mutex);
	}
}


/*
 * Work hard to make sense out of an RSCN page.
 */
static void
fp_validate_rscn_page(fc_local_port_t *port, fc_affected_id_t *page,
    job_request_t *job, fctl_ns_req_t *ns_cmd, fc_portmap_t *listptr,
    int *listindex, int sleep)
{
	int			rval;
	char			ww_name[17];
	la_wwn_t		*pwwn;
	fc_remote_port_t	*pwwn_pd;
	fc_remote_port_t	*did_pd;

	did_pd = fctl_get_remote_port_by_did(port, page->aff_d_id);

	FP_TRACE(FP_NHEAD1(6, 0), "RSCN with D_ID page; "
	    "port=%p, d_id=%x, pd=%p, rscn_count:0x%x", port, page->aff_d_id,
	    did_pd, (uint32_t)(uintptr_t)job->job_cb_arg);

	if (did_pd != NULL) {
		mutex_enter(&did_pd->pd_mutex);
		if (did_pd->pd_flags != PD_IDLE) {
			mutex_exit(&did_pd->pd_mutex);
			FP_TRACE(FP_NHEAD1(6, 0), "RSCN with D_ID page: "
			    "PD is BUSY; port=%p, d_id=%x, pd=%p",
			    port, page->aff_d_id, did_pd);
			return;
		}
		did_pd->pd_flags = PD_ELS_IN_PROGRESS;
		mutex_exit(&did_pd->pd_mutex);
	}

	job->job_counter = 1;

	pwwn = &((ns_resp_gpn_id_t *)ns_cmd->ns_data_buf)->pwwn;

	((ns_req_gpn_id_t *)ns_cmd->ns_cmd_buf)->pid.port_id = page->aff_d_id;
	((ns_req_gpn_id_t *)ns_cmd->ns_cmd_buf)->pid.priv_lilp_posit = 0;

	bzero(ns_cmd->ns_data_buf, sizeof (la_wwn_t));
	rval = fp_ns_query(port, ns_cmd, job, 1, sleep);

	FP_TRACE(FP_NHEAD1(1, 0), "NS Query Response for D_ID page; rev=%x,"
	    " in_id=%x, cmdrsp=%x, reason=%x, expln=%x",
	    ns_cmd->ns_resp_hdr.ct_rev, ns_cmd->ns_resp_hdr.ct_inid,
	    ns_cmd->ns_resp_hdr.ct_cmdrsp, ns_cmd->ns_resp_hdr.ct_reason,
	    ns_cmd->ns_resp_hdr.ct_expln);

	job->job_counter = 1;

	if (rval != FC_SUCCESS || fctl_is_wwn_zero(pwwn) == FC_SUCCESS) {
		/*
		 * What this means is that the D_ID
		 * disappeared from the Fabric.
		 */
		if (did_pd == NULL) {
			FP_TRACE(FP_NHEAD1(1, 0), "RSCN with D_ID page;"
			    " NULL PD disappeared, rval=%x", rval);
			return;
		}

		fc_wwn_to_str(&did_pd->pd_port_name, ww_name);

		(listptr + *listindex)->map_rscn_info.ulp_rscn_count =
		    (uint32_t)(uintptr_t)job->job_cb_arg;

		fp_fillout_old_map(listptr + (*listindex)++, did_pd, 0);

		FP_TRACE(FP_NHEAD1(3, 0), "RSCN: PD disappeared; "
		    "d_id=%x, PWWN=%s", page->aff_d_id, ww_name);

		FP_TRACE(FP_NHEAD2(9, 0),
		    "GPN_ID for D_ID=%x failed", page->aff_d_id);

		FP_TRACE(FP_NHEAD2(9, 0),
		    "N_x Port with D_ID=%x, PWWN=%s disappeared from"
		    " fabric", page->aff_d_id, ww_name);

		mutex_enter(&did_pd->pd_mutex);
		did_pd->pd_flags = PD_IDLE;
		mutex_exit(&did_pd->pd_mutex);

		FP_TRACE(FP_NHEAD1(3, 0), "RSCN with D_ID (%x) page; "
		    "PD disappeared, pd=%p", page->aff_d_id, did_pd);

		return;
	}

	pwwn_pd = fctl_get_remote_port_by_pwwn(port, pwwn);

	if (did_pd != NULL && pwwn_pd != NULL && did_pd == pwwn_pd) {
		/*
		 * There is no change. Do PLOGI again and add it to
		 * ULP portmap baggage and return. Note: When RSCNs
		 * arrive with per page states, the need for PLOGI
		 * can be determined correctly.
		 */
		mutex_enter(&pwwn_pd->pd_mutex);
		pwwn_pd->pd_type = PORT_DEVICE_NOCHANGE;
		mutex_exit(&pwwn_pd->pd_mutex);

		(listptr + *listindex)->map_rscn_info.ulp_rscn_count =
		    (uint32_t)(uintptr_t)job->job_cb_arg;

		fctl_copy_portmap(listptr + (*listindex)++, pwwn_pd);

		mutex_enter(&pwwn_pd->pd_mutex);
		if ((pwwn_pd->pd_state == PORT_DEVICE_LOGGED_IN) ||
		    (pwwn_pd->pd_aux_flags & PD_LOGGED_OUT)) {
			fc_wwn_to_str(&pwwn_pd->pd_port_name, ww_name);
			mutex_exit(&pwwn_pd->pd_mutex);

			rval = fp_port_login(port, page->aff_d_id, job,
			    FP_CMD_PLOGI_RETAIN, sleep, pwwn_pd, NULL);
			if (rval == FC_SUCCESS) {
				fp_jobwait(job);
				rval = job->job_result;

				/*
				 * Reset LOGO tolerance to zero
				 * Also we are the PLOGI initiator now.
				 */
				mutex_enter(&pwwn_pd->pd_mutex);
				fctl_tc_reset(&pwwn_pd->pd_logo_tc);
				pwwn_pd->pd_recepient = PD_PLOGI_INITIATOR;
				mutex_exit(&pwwn_pd->pd_mutex);
			}

			if (rval == FC_SUCCESS) {
				struct fc_portmap *map =
				    listptr + *listindex - 1;

				FP_TRACE(FP_NHEAD1(1, 0),
				    "PLOGI succeeded: no skip(2)"
				    " for D_ID %x", page->aff_d_id);
				map->map_flags |=
				    PORT_DEVICE_NO_SKIP_DEVICE_DISCOVERY;
			} else {
				FP_TRACE(FP_NHEAD2(9, rval),
				    "PLOGI to D_ID=%x failed", page->aff_d_id);

				FP_TRACE(FP_NHEAD2(9, 0),
				    "N_x Port with D_ID=%x, PWWN=%s"
				    " disappeared from fabric",
				    page->aff_d_id, ww_name);

				fp_fillout_old_map(listptr +
				    *listindex - 1, pwwn_pd, 0);
			}
		} else {
			mutex_exit(&pwwn_pd->pd_mutex);
		}

		mutex_enter(&did_pd->pd_mutex);
		did_pd->pd_flags = PD_IDLE;
		mutex_exit(&did_pd->pd_mutex);

		FP_TRACE(FP_NHEAD1(6, 0), "RSCN with D_ID (0x%x) page; "
		    "Case ONE, rval=%x, result=%x pd=%p", page->aff_d_id, rval,
		    job->job_result, pwwn_pd);

		return;
	}

	if (did_pd == NULL && pwwn_pd == NULL) {

		fc_orphan_t	*orp  = NULL;
		fc_orphan_t	*norp = NULL;
		fc_orphan_t	*prev = NULL;

		/*
		 * Hunt down the orphan list before giving up.
		 */

		mutex_enter(&port->fp_mutex);
		if (port->fp_orphan_count) {

			for (orp = port->fp_orphan_list; orp; orp = norp) {
				norp = orp->orp_next;

				if (fctl_wwn_cmp(&orp->orp_pwwn, pwwn) != 0) {
					prev = orp;
					continue;
				}

				if (prev) {
					prev->orp_next = orp->orp_next;
				} else {
					ASSERT(orp ==
					    port->fp_orphan_list);
					port->fp_orphan_list =
					    orp->orp_next;
				}
				port->fp_orphan_count--;
				break;
			}
		}

		mutex_exit(&port->fp_mutex);
		pwwn_pd = fp_create_remote_port_by_ns(port,
		    page->aff_d_id, sleep);

		if (pwwn_pd != NULL) {

			if (orp) {
				fc_wwn_to_str(&orp->orp_pwwn,
				    ww_name);

				FP_TRACE(FP_NHEAD2(9, 0),
				    "N_x Port with D_ID=%x,"
				    " PWWN=%s reappeared in fabric",
				    page->aff_d_id, ww_name);

				kmem_free(orp, sizeof (*orp));
			}

			(listptr + *listindex)->
			    map_rscn_info.ulp_rscn_count =
			    (uint32_t)(uintptr_t)job->job_cb_arg;

			fctl_copy_portmap(listptr +
			    (*listindex)++, pwwn_pd);
		}

		FP_TRACE(FP_NHEAD1(6, 0), "RSCN with D_ID (0x%x) page; "
		    "Case TWO", page->aff_d_id);

		return;
	}

	if (pwwn_pd != NULL && did_pd == NULL) {
		uint32_t old_d_id;
		uint32_t d_id = page->aff_d_id;

		/*
		 * What this means is there is a new D_ID for this
		 * Port WWN. Take out the port device off D_ID
		 * list and put it back with a new D_ID. Perform
		 * PLOGI if already logged in.
		 */
		mutex_enter(&port->fp_mutex);
		mutex_enter(&pwwn_pd->pd_mutex);

		old_d_id = pwwn_pd->pd_port_id.port_id;

		fctl_delist_did_table(port, pwwn_pd);

		(listptr + *listindex)->map_rscn_info.ulp_rscn_count =
		    (uint32_t)(uintptr_t)job->job_cb_arg;

		fp_fillout_changed_map(listptr + (*listindex)++, pwwn_pd,
		    &d_id, NULL);
		fctl_enlist_did_table(port, pwwn_pd);

		FP_TRACE(FP_NHEAD1(6, 0), "RSCN with D_ID page;"
		    " Case THREE, pd=%p,"
		    " state=%x", pwwn_pd, pwwn_pd->pd_state);

		if ((pwwn_pd->pd_state == PORT_DEVICE_LOGGED_IN) ||
		    (pwwn_pd->pd_aux_flags & PD_LOGGED_OUT)) {
			fc_wwn_to_str(&pwwn_pd->pd_port_name, ww_name);

			mutex_exit(&pwwn_pd->pd_mutex);
			mutex_exit(&port->fp_mutex);

			FP_TRACE(FP_NHEAD2(9, 0),
			    "N_x Port with D_ID=%x, PWWN=%s has a new"
			    " D_ID=%x now", old_d_id, ww_name, d_id);

			rval = fp_port_login(port, page->aff_d_id, job,
			    FP_CMD_PLOGI_RETAIN, sleep, pwwn_pd, NULL);
			if (rval == FC_SUCCESS) {
				fp_jobwait(job);
				rval = job->job_result;
			}

			if (rval != FC_SUCCESS) {
				fp_fillout_old_map(listptr +
				    *listindex - 1, pwwn_pd, 0);
			}
		} else {
			mutex_exit(&pwwn_pd->pd_mutex);
			mutex_exit(&port->fp_mutex);
		}

		return;
	}

	if (pwwn_pd == NULL && did_pd != NULL) {
		fc_portmap_t	*ptr;
		uint32_t	len = 1;
		char		old_ww_name[17];

		mutex_enter(&did_pd->pd_mutex);
		fc_wwn_to_str(&did_pd->pd_port_name, old_ww_name);
		mutex_exit(&did_pd->pd_mutex);

		fc_wwn_to_str(pwwn, ww_name);

		(listptr + *listindex)->map_rscn_info.ulp_rscn_count =
		    (uint32_t)(uintptr_t)job->job_cb_arg;

		/*
		 * What this means is that there is a new Port WWN for
		 * this D_ID; Mark the Port device as old and provide
		 * the new PWWN and D_ID combination as new.
		 */
		fp_fillout_old_map(listptr + (*listindex)++, did_pd, 0);

		FP_TRACE(FP_NHEAD2(9, 0),
		    "N_x Port with D_ID=%x, PWWN=%s has a new PWWN=%s now",
		    page->aff_d_id, old_ww_name, ww_name);

		(listptr + *listindex)->map_rscn_info.ulp_rscn_count =
		    (uint32_t)(uintptr_t)job->job_cb_arg;

		ptr = listptr + (*listindex)++;

		job->job_counter = 1;

		if (fp_ns_getmap(port, job, &ptr, &len,
		    page->aff_d_id - 1) != FC_SUCCESS) {
			(*listindex)--;
		}

		mutex_enter(&did_pd->pd_mutex);
		did_pd->pd_flags = PD_IDLE;
		mutex_exit(&did_pd->pd_mutex);

		return;
	}

	/*
	 * A weird case of Port WWN and D_ID existence but not matching up
	 * between them. Trust your instincts - Take the port device handle
	 * off Port WWN list, fix it with new Port WWN and put it back, In
	 * the mean time mark the port device corresponding to the old port
	 * WWN as OLD.
	 */
	FP_TRACE(FP_NHEAD1(6, 0), "RSCN with D_ID page; Case WEIRD, pwwn_pd=%p,"
	    " did_pd=%p", pwwn_pd, did_pd);

	mutex_enter(&port->fp_mutex);
	mutex_enter(&pwwn_pd->pd_mutex);

	pwwn_pd->pd_type = PORT_DEVICE_OLD;
	pwwn_pd->pd_state = PORT_DEVICE_INVALID;
	fctl_delist_did_table(port, pwwn_pd);
	fctl_delist_pwwn_table(port, pwwn_pd);

	FP_TRACE(FP_NHEAD1(6, 0), "RSCN with D_ID page; case WEIRD continued,"
	    " pwwn-d_id=%x pwwn-wwn=%x %x %x %x %x %x %x %x",
	    pwwn_pd->pd_port_id.port_id,

	    pwwn_pd->pd_port_name.raw_wwn[0],
	    pwwn_pd->pd_port_name.raw_wwn[1],
	    pwwn_pd->pd_port_name.raw_wwn[2],
	    pwwn_pd->pd_port_name.raw_wwn[3],
	    pwwn_pd->pd_port_name.raw_wwn[4],
	    pwwn_pd->pd_port_name.raw_wwn[5],
	    pwwn_pd->pd_port_name.raw_wwn[6],
	    pwwn_pd->pd_port_name.raw_wwn[7]);

	mutex_exit(&pwwn_pd->pd_mutex);
	mutex_exit(&port->fp_mutex);

	(listptr + *listindex)->map_rscn_info.ulp_rscn_count =
	    (uint32_t)(uintptr_t)job->job_cb_arg;

	fctl_copy_portmap(listptr + (*listindex)++, pwwn_pd);

	mutex_enter(&port->fp_mutex);
	mutex_enter(&did_pd->pd_mutex);

	fctl_delist_pwwn_table(port, did_pd);

	(listptr + *listindex)->map_rscn_info.ulp_rscn_count =
	    (uint32_t)(uintptr_t)job->job_cb_arg;

	fp_fillout_changed_map(listptr + (*listindex)++, did_pd, NULL, pwwn);
	fctl_enlist_pwwn_table(port, did_pd);

	FP_TRACE(FP_NHEAD1(6, 0), "RSCN with D_ID page; case WEIRD continued,"
	    " d_id=%x, state=%x, did-wwn=%x %x %x %x %x %x %x %x",
	    did_pd->pd_port_id.port_id, did_pd->pd_state,

	    did_pd->pd_port_name.raw_wwn[0],
	    did_pd->pd_port_name.raw_wwn[1],
	    did_pd->pd_port_name.raw_wwn[2],
	    did_pd->pd_port_name.raw_wwn[3],
	    did_pd->pd_port_name.raw_wwn[4],
	    did_pd->pd_port_name.raw_wwn[5],
	    did_pd->pd_port_name.raw_wwn[6],
	    did_pd->pd_port_name.raw_wwn[7]);

	if ((did_pd->pd_state == PORT_DEVICE_LOGGED_IN) ||
	    (did_pd->pd_aux_flags & PD_LOGGED_OUT)) {
		mutex_exit(&did_pd->pd_mutex);
		mutex_exit(&port->fp_mutex);

		rval = fp_port_login(port, page->aff_d_id, job,
		    FP_CMD_PLOGI_RETAIN, sleep, did_pd, NULL);
		if (rval == FC_SUCCESS) {
			fp_jobwait(job);
			if (job->job_result != FC_SUCCESS) {
				fp_fillout_old_map(listptr +
				    *listindex - 1, did_pd, 0);
			}
		} else {
			fp_fillout_old_map(listptr + *listindex - 1, did_pd, 0);
		}
	} else {
		mutex_exit(&did_pd->pd_mutex);
		mutex_exit(&port->fp_mutex);
	}

	mutex_enter(&did_pd->pd_mutex);
	did_pd->pd_flags = PD_IDLE;
	mutex_exit(&did_pd->pd_mutex);
}


/*
 * Check with NS for the presence of this port WWN
 */
static int
fp_ns_validate_device(fc_local_port_t *port, fc_remote_port_t *pd,
    job_request_t *job, int polled, int sleep)
{
	la_wwn_t	pwwn;
	uint32_t	flags;
	fctl_ns_req_t	*ns_cmd;

	flags = FCTL_NS_VALIDATE_PD | ((polled) ? 0: FCTL_NS_ASYNC_REQUEST);
	ns_cmd = fctl_alloc_ns_cmd(sizeof (ns_req_gid_pn_t),
	    sizeof (ns_resp_gid_pn_t), sizeof (ns_resp_gid_pn_t),
	    flags, sleep);
	if (ns_cmd == NULL) {
		return (FC_NOMEM);
	}

	mutex_enter(&pd->pd_mutex);
	pwwn = pd->pd_port_name;
	mutex_exit(&pd->pd_mutex);

	ns_cmd->ns_cmd_code = NS_GID_PN;
	ns_cmd->ns_pd = pd;
	((ns_req_gid_pn_t *)ns_cmd->ns_cmd_buf)->pwwn = pwwn;
	((ns_resp_gid_pn_t *)ns_cmd->ns_data_buf)->pid.port_id = 0;
	((ns_resp_gid_pn_t *)ns_cmd->ns_data_buf)->pid.priv_lilp_posit = 0;

	return (fp_ns_query(port, ns_cmd, job, polled, sleep));
}


/*
 * Sanity check the LILP map returned by FCA
 */
static int
fp_validate_lilp_map(fc_lilpmap_t *lilp_map)
{
	int	count;

	if (lilp_map->lilp_length == 0) {
		return (FC_FAILURE);
	}

	for (count = 0; count < lilp_map->lilp_length; count++) {
		if (fp_is_valid_alpa(lilp_map->lilp_alpalist[count]) !=
		    FC_SUCCESS) {
			return (FC_FAILURE);
		}
	}

	return (FC_SUCCESS);
}


/*
 * Sanity check if the AL_PA is a valid address
 */
static int
fp_is_valid_alpa(uchar_t al_pa)
{
	int	count;

	for (count = 0; count < sizeof (fp_valid_alpas); count++) {
		if (al_pa == fp_valid_alpas[count] || al_pa == 0) {
			return (FC_SUCCESS);
		}
	}

	return (FC_FAILURE);
}


/*
 * Post unsolicited callbacks to ULPs
 */
static void
fp_ulp_unsol_cb(void *arg)
{
	fp_unsol_spec_t	*ub_spec = (fp_unsol_spec_t *)arg;

	fctl_ulp_unsol_cb(ub_spec->port, ub_spec->buf,
	    ub_spec->buf->ub_frame.type);
	kmem_free(ub_spec, sizeof (*ub_spec));
}


/*
 * Perform message reporting in a consistent manner. Unless there is
 * a strong reason NOT to use this function (which is very very rare)
 * all message reporting should go through this.
 */
static void
fp_printf(fc_local_port_t *port, int level, fp_mesg_dest_t dest, int fc_errno,
    fc_packet_t *pkt, const char *fmt, ...)
{
	caddr_t		buf;
	va_list		ap;

	switch (level) {
	case CE_NOTE:
		if ((port->fp_verbose & FP_WARNING_MESSAGES) == 0) {
			return;
		}
		break;

	case CE_WARN:
		if ((port->fp_verbose & FP_FATAL_MESSAGES) == 0) {
			return;
		}
		break;
	}

	buf = kmem_zalloc(256, KM_NOSLEEP);
	if (buf == NULL) {
		return;
	}

	(void) sprintf(buf, "fp(%d): ", port->fp_instance);

	va_start(ap, fmt);
	(void) vsprintf(buf + strlen(buf), fmt, ap);
	va_end(ap);

	if (fc_errno) {
		char *errmsg;

		(void) fc_ulp_error(fc_errno, &errmsg);
		(void) sprintf(buf + strlen(buf), " FC Error=%s", errmsg);
	} else {
		if (pkt) {
			caddr_t	state, reason, action, expln;

			(void) fc_ulp_pkt_error(pkt, &state, &reason,
			    &action, &expln);

			(void) sprintf(buf + strlen(buf),
			    " state=%s, reason=%s", state, reason);

			if (pkt->pkt_resp_resid) {
				(void) sprintf(buf + strlen(buf),
				    " resp resid=%x\n", pkt->pkt_resp_resid);
			}
		}
	}

	switch (dest) {
	case FP_CONSOLE_ONLY:
		cmn_err(level, "^%s", buf);
		break;

	case FP_LOG_ONLY:
		cmn_err(level, "!%s", buf);
		break;

	default:
		cmn_err(level, "%s", buf);
		break;
	}

	kmem_free(buf, 256);
}

static int
fp_fcio_login(fc_local_port_t *port, fcio_t *fcio, job_request_t *job)
{
	int			ret;
	uint32_t		d_id;
	la_wwn_t		pwwn;
	fc_remote_port_t	*pd = NULL;
	fc_remote_port_t	*held_pd = NULL;
	fctl_ns_req_t		*ns_cmd;
	fc_portmap_t		*changelist;

	bcopy(fcio->fcio_ibuf, &pwwn, sizeof (pwwn));

	mutex_enter(&port->fp_mutex);
	if (FC_IS_TOP_SWITCH(port->fp_topology)) {
		mutex_exit(&port->fp_mutex);
		job->job_counter = 1;

		job->job_result = FC_SUCCESS;

		ns_cmd = fctl_alloc_ns_cmd(sizeof (ns_req_gid_pn_t),
		    sizeof (ns_resp_gid_pn_t), sizeof (ns_resp_gid_pn_t),
		    FCTL_NS_BUF_IS_USERLAND, KM_SLEEP);

		ASSERT(ns_cmd != NULL);

		ns_cmd->ns_cmd_code = NS_GID_PN;
		((ns_req_gid_pn_t *)(ns_cmd->ns_cmd_buf))->pwwn = pwwn;

		ret = fp_ns_query(port, ns_cmd, job, 1, KM_SLEEP);

		if (ret != FC_SUCCESS || job->job_result != FC_SUCCESS) {
			if (ret != FC_SUCCESS) {
				fcio->fcio_errno = ret;
			} else {
				fcio->fcio_errno = job->job_result;
			}
			fctl_free_ns_cmd(ns_cmd);
			return (EIO);
		}
		d_id = BE_32(*((uint32_t *)ns_cmd->ns_data_buf));
		fctl_free_ns_cmd(ns_cmd);
	} else {
		mutex_exit(&port->fp_mutex);

		held_pd = fctl_hold_remote_port_by_pwwn(port, &pwwn);
		if (held_pd == NULL) {
			fcio->fcio_errno = FC_BADWWN;
			return (EIO);
		}
		pd = held_pd;

		mutex_enter(&pd->pd_mutex);
		d_id = pd->pd_port_id.port_id;
		mutex_exit(&pd->pd_mutex);
	}

	job->job_counter = 1;

	pd = fctl_get_remote_port_by_did(port, d_id);

	if (pd) {
		mutex_enter(&pd->pd_mutex);
		if (pd->pd_state == PORT_DEVICE_LOGGED_IN) {
			pd->pd_login_count++;
			mutex_exit(&pd->pd_mutex);

			fcio->fcio_errno = FC_SUCCESS;
			if (held_pd) {
				fctl_release_remote_port(held_pd);
			}

			return (0);
		}
		mutex_exit(&pd->pd_mutex);
	} else {
		mutex_enter(&port->fp_mutex);
		if (FC_IS_TOP_SWITCH(port->fp_topology)) {
			mutex_exit(&port->fp_mutex);
			pd = fp_create_remote_port_by_ns(port, d_id, KM_SLEEP);
			if (pd == NULL) {
				fcio->fcio_errno = FC_FAILURE;
				if (held_pd) {
					fctl_release_remote_port(held_pd);
				}
				return (EIO);
			}
		} else {
			mutex_exit(&port->fp_mutex);
		}
	}

	job->job_flags &= ~JOB_TYPE_FP_ASYNC;
	job->job_counter = 1;

	ret = fp_port_login(port, d_id, job, FP_CMD_PLOGI_RETAIN,
	    KM_SLEEP, pd, NULL);

	if (ret != FC_SUCCESS) {
		fcio->fcio_errno = ret;
		if (held_pd) {
			fctl_release_remote_port(held_pd);
		}
		return (EIO);
	}
	fp_jobwait(job);

	fcio->fcio_errno = job->job_result;

	if (held_pd) {
		fctl_release_remote_port(held_pd);
	}

	if (job->job_result != FC_SUCCESS) {
		return (EIO);
	}

	pd = fctl_hold_remote_port_by_pwwn(port, &pwwn);
	if (pd == NULL) {
		fcio->fcio_errno = FC_BADDEV;
		return (ENODEV);
	}

	changelist = kmem_zalloc(sizeof (*changelist), KM_SLEEP);

	fctl_copy_portmap(changelist, pd);
	changelist->map_type = PORT_DEVICE_USER_LOGIN;

	(void) fp_ulp_devc_cb(port, changelist, 1, 1, KM_SLEEP, 1);

	mutex_enter(&pd->pd_mutex);
	pd->pd_type = PORT_DEVICE_NOCHANGE;
	mutex_exit(&pd->pd_mutex);

	fctl_release_remote_port(pd);

	return (0);
}


static int
fp_fcio_logout(fc_local_port_t *port, fcio_t *fcio, job_request_t *job)
{
	la_wwn_t		pwwn;
	fp_cmd_t		*cmd;
	fc_portmap_t		*changelist;
	fc_remote_port_t	*pd;

	bcopy(fcio->fcio_ibuf, &pwwn, sizeof (pwwn));

	pd = fctl_hold_remote_port_by_pwwn(port, &pwwn);
	if (pd == NULL) {
		fcio->fcio_errno = FC_BADWWN;
		return (ENXIO);
	}

	mutex_enter(&pd->pd_mutex);
	if (pd->pd_state != PORT_DEVICE_LOGGED_IN) {
		fcio->fcio_errno = FC_LOGINREQ;
		mutex_exit(&pd->pd_mutex);

		fctl_release_remote_port(pd);

		return (EINVAL);
	}

	ASSERT(pd->pd_login_count >= 1);

	if (pd->pd_flags == PD_ELS_IN_PROGRESS) {
		fcio->fcio_errno = FC_FAILURE;
		mutex_exit(&pd->pd_mutex);

		fctl_release_remote_port(pd);

		return (EBUSY);
	}

	if (pd->pd_login_count > 1) {
		pd->pd_login_count--;
		fcio->fcio_errno = FC_SUCCESS;
		mutex_exit(&pd->pd_mutex);

		changelist = kmem_zalloc(sizeof (*changelist), KM_SLEEP);

		fctl_copy_portmap(changelist, pd);
		changelist->map_type = PORT_DEVICE_USER_LOGOUT;

		fctl_release_remote_port(pd);

		(void) fp_ulp_devc_cb(port, changelist, 1, 1, KM_SLEEP, 1);

		return (0);
	}

	pd->pd_flags = PD_ELS_IN_PROGRESS;
	mutex_exit(&pd->pd_mutex);

	job->job_counter = 1;

	cmd = fp_alloc_pkt(port, sizeof (la_els_logo_t),
	    FP_PORT_IDENTIFIER_LEN, KM_SLEEP, pd);
	if (cmd == NULL) {
		fcio->fcio_errno = FC_NOMEM;
		fctl_release_remote_port(pd);

		mutex_enter(&pd->pd_mutex);
		pd->pd_flags = PD_IDLE;
		mutex_exit(&pd->pd_mutex);

		return (ENOMEM);
	}

	mutex_enter(&port->fp_mutex);
	mutex_enter(&pd->pd_mutex);

	cmd->cmd_pkt.pkt_tran_flags = FC_TRAN_INTR | pd->pd_login_class;
	cmd->cmd_pkt.pkt_tran_type = FC_PKT_EXCHANGE;
	cmd->cmd_flags = FP_CMD_PLOGI_DONT_CARE;
	cmd->cmd_retry_count = 1;
	cmd->cmd_ulp_pkt = NULL;

	fp_logo_init(pd, cmd, job);

	mutex_exit(&pd->pd_mutex);
	mutex_exit(&port->fp_mutex);

	if (fp_sendcmd(port, cmd, port->fp_fca_handle) != FC_SUCCESS) {
		mutex_enter(&pd->pd_mutex);
		pd->pd_flags = PD_IDLE;
		mutex_exit(&pd->pd_mutex);

		fp_free_pkt(cmd);
		fctl_release_remote_port(pd);

		return (EIO);
	}

	fp_jobwait(job);

	fcio->fcio_errno = job->job_result;
	if (job->job_result != FC_SUCCESS) {
		mutex_enter(&pd->pd_mutex);
		pd->pd_flags = PD_IDLE;
		mutex_exit(&pd->pd_mutex);

		fctl_release_remote_port(pd);

		return (EIO);
	}

	ASSERT(pd != NULL);

	changelist = kmem_zalloc(sizeof (*changelist), KM_SLEEP);

	fctl_copy_portmap(changelist, pd);
	changelist->map_type = PORT_DEVICE_USER_LOGOUT;
	changelist->map_state = PORT_DEVICE_INVALID;

	mutex_enter(&port->fp_mutex);
	mutex_enter(&pd->pd_mutex);

	fctl_delist_did_table(port, pd);
	fctl_delist_pwwn_table(port, pd);
	pd->pd_flags = PD_IDLE;

	mutex_exit(&pd->pd_mutex);
	mutex_exit(&port->fp_mutex);

	(void) fp_ulp_devc_cb(port, changelist, 1, 1, KM_SLEEP, 1);

	fctl_release_remote_port(pd);

	return (0);
}



/*
 * Send a syslog event for adapter port level events.
 */
static void
fp_log_port_event(fc_local_port_t *port, char *subclass)
{
	nvlist_t *attr_list;

	if (nvlist_alloc(&attr_list, NV_UNIQUE_NAME_TYPE,
	    KM_SLEEP) != DDI_SUCCESS) {
		goto alloc_failed;
	}

	if (nvlist_add_uint32(attr_list, "instance",
	    port->fp_instance) != DDI_SUCCESS) {
		goto error;
	}

	if (nvlist_add_byte_array(attr_list, "port-wwn",
	    port->fp_service_params.nport_ww_name.raw_wwn,
	    sizeof (la_wwn_t)) != DDI_SUCCESS) {
		goto error;
	}

	(void) ddi_log_sysevent(port->fp_port_dip, DDI_VENDOR_SUNW, EC_SUNFC,
	    subclass, attr_list, NULL, DDI_SLEEP);

	nvlist_free(attr_list);
	return;

error:
	nvlist_free(attr_list);
alloc_failed:
	FP_TRACE(FP_NHEAD1(9, 0), "Unable to send %s event", subclass);
}


static void
fp_log_target_event(fc_local_port_t *port, char *subclass, la_wwn_t tgt_pwwn,
    uint32_t port_id)
{
	nvlist_t *attr_list;

	if (nvlist_alloc(&attr_list, NV_UNIQUE_NAME_TYPE,
	    KM_SLEEP) != DDI_SUCCESS) {
		goto alloc_failed;
	}

	if (nvlist_add_uint32(attr_list, "instance",
	    port->fp_instance) != DDI_SUCCESS) {
		goto error;
	}

	if (nvlist_add_byte_array(attr_list, "port-wwn",
	    port->fp_service_params.nport_ww_name.raw_wwn,
	    sizeof (la_wwn_t)) != DDI_SUCCESS) {
		goto error;
	}

	if (nvlist_add_byte_array(attr_list, "target-port-wwn",
	    tgt_pwwn.raw_wwn, sizeof (la_wwn_t)) != DDI_SUCCESS) {
		goto error;
	}

	if (nvlist_add_uint32(attr_list, "target-port-id",
	    port_id) != DDI_SUCCESS) {
		goto error;
	}

	(void) ddi_log_sysevent(port->fp_port_dip, DDI_VENDOR_SUNW, EC_SUNFC,
	    subclass, attr_list, NULL, DDI_SLEEP);

	nvlist_free(attr_list);
	return;

error:
	nvlist_free(attr_list);
alloc_failed:
	FP_TRACE(FP_NHEAD1(9, 0), "Unable to send %s event", subclass);
}

static uint32_t
fp_map_remote_port_state(uint32_t rm_state)
{
	switch (rm_state) {
	case PORT_DEVICE_LOGGED_IN:
		return (FC_HBA_PORTSTATE_ONLINE);
	case PORT_DEVICE_VALID:
	case PORT_DEVICE_INVALID:
	default:
		return (FC_HBA_PORTSTATE_UNKNOWN);
	}
}
