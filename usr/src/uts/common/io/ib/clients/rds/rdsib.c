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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <inet/ip.h>
#include <sys/ib/clients/rds/rdsib_ib.h>
#include <sys/ib/clients/rds/rdsib_buf.h>
#include <sys/ib/clients/rds/rdsib_cm.h>
#include <sys/ib/clients/rds/rdsib_protocol.h>
#include <sys/ib/clients/rds/rds_transport.h>
#include <sys/ib/clients/rds/rds_kstat.h>

/*
 * Global Configuration Variables
 * As defined in RDS proposal
 */
uint_t		MaxNodes		= RDS_MAX_NODES;
uint_t		RdsPktSize;
uint_t		NDataRX;
uint_t		MaxDataSendBuffers	= RDS_MAX_DATA_SEND_BUFFERS;
uint_t		MaxDataRecvBuffers	= RDS_MAX_DATA_RECV_BUFFERS;
uint_t		MaxCtrlSendBuffers	= RDS_MAX_CTRL_SEND_BUFFERS;
uint_t		MaxCtrlRecvBuffers	= RDS_MAX_CTRL_RECV_BUFFERS;
uint_t		DataRecvBufferLWM	= RDS_DATA_RECV_BUFFER_LWM;
uint_t		CtrlRecvBufferLWM	= RDS_CTRL_RECV_BUFFER_LWM;
uint_t		PendingRxPktsHWM	= RDS_PENDING_RX_PKTS_HWM;
uint_t		MinRnrRetry		= RDS_IB_RNR_RETRY;
uint8_t		IBPathRetryCount	= RDS_IB_PATH_RETRY;
uint8_t		IBPktLifeTime		= RDS_IB_PKT_LT;

extern int rdsib_open_ib();
extern void rdsib_close_ib();
extern void rds_resume_port(in_port_t port);
extern int rds_sendmsg(uio_t *uiop, ipaddr_t sendip, ipaddr_t recvip,
    in_port_t sendport, in_port_t recvport, zoneid_t zoneid);
extern boolean_t rds_if_lookup_by_name(char *devname);

rds_transport_ops_t rds_ib_transport_ops = {
	rdsib_open_ib,
	rdsib_close_ib,
	rds_sendmsg,
	rds_resume_port,
	rds_if_lookup_by_name
};

/* global */
rds_state_t	*rdsib_statep = NULL;
krwlock_t	rds_loopback_portmap_lock;
uint8_t		rds_loopback_portmap[RDS_PORT_MAP_SIZE];
ddi_taskq_t	*rds_taskq = NULL;
dev_info_t	*rdsib_dev_info = NULL;
uint_t		rds_rx_pkts_pending_hwm;

#ifdef DEBUG
uint32_t	rdsdbglvl = RDS_LOG_L3;
#else
uint32_t	rdsdbglvl = RDS_LOG_L2;
#endif

#define		RDS_NUM_TASKQ_THREADS	4

static int rdsib_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int rdsib_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int rdsib_info(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
    void **result);
static void rds_read_config_values(dev_info_t *dip);

/* Driver entry points */
static struct cb_ops	rdsib_cb_ops = {
	nulldev,		/* open */
	nulldev,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	nodev,			/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* prop_op */
	NULL,			/* stream */
	D_MP,			/* cb_flag */
	CB_REV,			/* rev */
	nodev,			/* int (*cb_aread)() */
	nodev,			/* int (*cb_awrite)() */
};

/* Device options */
static struct dev_ops rdsib_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	rdsib_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	rdsib_attach,		/* attach */
	rdsib_detach,		/* detach */
	nodev,			/* reset */
	&rdsib_cb_ops,		/* driver ops - devctl interfaces */
	NULL,			/* bus operations */
	NULL			/* power */
};

/*
 * Module linkage information.
 */
#define	RDS_DEVDESC	"RDS IB driver %I%"
static struct modldrv rdsib_modldrv = {
	&mod_driverops,		/* Driver module */
	RDS_DEVDESC,		/* Driver name and version */
	&rdsib_ops,		/* Driver ops */
};

static struct modlinkage rdsib_modlinkage = {
	MODREV_1,
	(void *)&rdsib_modldrv,
	NULL
};

/* Called from _init */
int
rdsib_init()
{
	/* RDS supports only one instance */
	rdsib_statep = kmem_zalloc(sizeof (rds_state_t), KM_SLEEP);

	rw_init(&rdsib_statep->rds_sessionlock, NULL, RW_DRIVER, NULL);
	rw_init(&rdsib_statep->rds_hca_lock, NULL, RW_DRIVER, NULL);

	rw_init(&rds_loopback_portmap_lock, NULL, RW_DRIVER, NULL);
	bzero(rds_loopback_portmap, RDS_PORT_MAP_SIZE);

	mutex_init(&rds_dpool.pool_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&rds_dpool.pool_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&rds_cpool.pool_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&rds_cpool.pool_cv, NULL, CV_DRIVER, NULL);

	/* Initialize logging */
	rds_logging_initialization();

	RDS_SET_NPORT(1); /* this should never be 0 */

	ASSERT(rds_transport_ops == NULL);
	rds_transport_ops = &rds_ib_transport_ops;

	return (0);
}

/* Called from _fini */
void
rdsib_fini()
{
	/* Stop logging */
	rds_logging_destroy();

	cv_destroy(&rds_dpool.pool_cv);
	mutex_destroy(&rds_dpool.pool_lock);
	cv_destroy(&rds_cpool.pool_cv);
	mutex_destroy(&rds_cpool.pool_lock);

	rw_destroy(&rds_loopback_portmap_lock);

	rw_destroy(&rdsib_statep->rds_hca_lock);
	rw_destroy(&rdsib_statep->rds_sessionlock);
	kmem_free(rdsib_statep, sizeof (rds_state_t));

	rds_transport_ops = NULL;
}

int
_init(void)
{
	int	ret;

	if (ibt_hw_is_present() == 0) {
		return (ENODEV);
	}

	ret = rdsib_init();
	if (ret != 0) {
		return (ret);
	}

	ret = mod_install(&rdsib_modlinkage);
	if (ret != 0) {
		/*
		 * Could not load module
		 */
		rdsib_fini();
		return (ret);
	}

	return (0);
}

int
_fini()
{
	int	ret;

	/*
	 * Remove module
	 */
	if ((ret = mod_remove(&rdsib_modlinkage)) != 0) {
		return (ret);
	}

	rdsib_fini();

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&rdsib_modlinkage, modinfop));
}

static int
rdsib_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int	ret;

	RDS_DPRINTF2("rdsib_attach", "enter");

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (rdsib_dev_info != NULL) {
		RDS_DPRINTF1("rdsib_attach", "Multiple RDS instances are"
		    " not supported (rds_dev_info: 0x%p)", rdsib_dev_info);
		return (DDI_FAILURE);
	}

	rdsib_dev_info = dip;
	rds_read_config_values(dip);

	rds_taskq = ddi_taskq_create(dip, "rds_taskq", RDS_NUM_TASKQ_THREADS,
	    TASKQ_DEFAULTPRI, 0);
	if (rds_taskq == NULL) {
		RDS_DPRINTF1("rdsib_attach",
		    "ddi_taskq_create failed for rds_taskq");
		rdsib_dev_info = NULL;
		return (DDI_FAILURE);
	}

	ret = ddi_create_minor_node(dip, "rdsib", S_IFCHR, 0, DDI_PSEUDO, 0);
	if (ret != DDI_SUCCESS) {
		RDS_DPRINTF1("rdsib_attach",
		    "ddi_create_minor_node failed: %d", ret);
		ddi_taskq_destroy(rds_taskq);
		rds_taskq = NULL;
		rdsib_dev_info = NULL;
		return (DDI_FAILURE);
	}

	/* Max number of receive buffers on the system */
	NDataRX = (MaxNodes - 1) * MaxDataRecvBuffers * 2;

	/*
	 * High water mark for the receive buffers in the system. If the
	 * number of buffers used crosses this mark then all sockets in
	 * would be stalled. The port quota for the sockets is set based
	 * on this limit.
	 */
	rds_rx_pkts_pending_hwm = (PendingRxPktsHWM * NDataRX)/100;

	ret = rdsib_initialize_ib();
	if (ret != 0) {
		RDS_DPRINTF1("rdsib_attach",
		    "rdsib_initialize_ib failed: %d", ret);
		ddi_taskq_destroy(rds_taskq);
		rds_taskq = NULL;
		rdsib_dev_info = NULL;
		return (DDI_FAILURE);
	}

	RDS_DPRINTF2("rdsib_attach", "return");

	return (DDI_SUCCESS);
}

static int
rdsib_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	RDS_DPRINTF2("rdsib_detach", "enter");

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	rdsib_deinitialize_ib();

	ddi_remove_minor_node(dip, "rdsib");

	/* destroy taskq */
	if (rds_taskq != NULL) {
		ddi_taskq_destroy(rds_taskq);
		rds_taskq = NULL;
	}

	rdsib_dev_info = NULL;

	RDS_DPRINTF2("rdsib_detach", "return");

	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
rdsib_info(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	int ret = DDI_FAILURE;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (rdsib_dev_info != NULL) {
			*result = (void *)rdsib_dev_info;
			ret = DDI_SUCCESS;
		}
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*result = NULL;
		ret = DDI_SUCCESS;
		break;

	default:
		break;
	}

	return (ret);
}

static void
rds_read_config_values(dev_info_t *dip)
{
	MaxNodes = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "MaxNodes", RDS_MAX_NODES);

	UserBufferSize = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "UserBufferSize", RDS_USER_DATA_BUFFER_SIZE);

	MaxDataSendBuffers = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "MaxDataSendBuffers", RDS_MAX_DATA_SEND_BUFFERS);

	MaxDataRecvBuffers = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "MaxDataRecvBuffers", RDS_MAX_DATA_RECV_BUFFERS);

	MaxCtrlSendBuffers = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "MaxCtrlSendBuffers", RDS_MAX_CTRL_SEND_BUFFERS);

	MaxCtrlRecvBuffers = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "MaxCtrlRecvBuffers", RDS_MAX_CTRL_RECV_BUFFERS);

	DataRecvBufferLWM = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "DataRecvBufferLWM", RDS_DATA_RECV_BUFFER_LWM);

	CtrlRecvBufferLWM = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "CtrlRecvBufferLWM", RDS_CTRL_RECV_BUFFER_LWM);

	PendingRxPktsHWM = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "PendingRxPktsHWM", RDS_PENDING_RX_PKTS_HWM);

	MinRnrRetry = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "MinRnrRetry", RDS_IB_RNR_RETRY);

	IBPathRetryCount = (uint8_t)ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "IBPathRetryCount", RDS_IB_PATH_RETRY);

	IBPktLifeTime = (uint8_t)ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "IBPktLifeTime", RDS_IB_PKT_LT);

	rdsdbglvl = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "rdsdbglvl", RDS_LOG_L2);

	if (MaxNodes < 2) {
		cmn_err(CE_WARN, "MaxNodes is set to less than 2");
		MaxNodes = 2;
	}
}
