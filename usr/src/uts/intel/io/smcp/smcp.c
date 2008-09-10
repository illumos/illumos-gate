/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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

/*
 * smcp -- Upper MAC driver for SMC PCI adapters
 * Depends on the Generic LAN Driver utility functions in /kernel/misc/gld
 *
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/ksynch.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/debug.h>

#ifdef	_DDICT
#include "sys/dlpi.h"
#include "sys/ethernet.h"
#include "sys/gld.h"
#else
#include <sys/dlpi.h>
#include <sys/ethernet.h>
#include <sys/gld.h>
#endif

#include <sys/ddi.h>
#include <sys/sunddi.h>

#include SMC_INCLUDE
#include "smcp.h"

char _depends_on[] = "misc/gld";

static ddi_dma_attr_t buf_dma_attr = {
	DMA_ATTR_V0,		/* version of this structure */
	0,			/* lowest usable address */
	0xffffffffU,		/* highest usable address */
	0x0ffffff,		/* maximum DMAable byte count */
	1,			/* alignment in bytes */
	0x7f,			/* bitmap of burst sizes */
	1,			/* minimum transfer */
	0x0ffffffU,		/* maximum transfer */
	0x0ffffffU,		/* maximum segment length */
	1,			/* maximum number of segments */
	1,			/* granularity */
	0,			/* flags (reserved) */
};

static ddi_dma_attr_t txdata_attr = {
	DMA_ATTR_V0,		/* version of this structure */
	0,			/* lowest usable address */
	0xffffffffU,		/* highest usable address */
	0x0ffffff,		/* maximum DMAable byte count */
	1,			/* alignment in bytes */
	0x7f,			/* bitmap of burst sizes */
	1,			/* minimum transfer */
	0x0ffffffU,		/* maximum transfer */
	0x0ffffffU,		/* maximum segment length */
	2,			/* maximum number of segments */
	1,			/* granularity */
	0,			/* flags (reserved) */
};

static ddi_dma_attr_t host_ram_dma_attr = {
	DMA_ATTR_V0,		/* version of this structure */
	0,			/* lowest usable address */
	0xffffffffU,		/* highest usable address */
	0x0ffffff,		/* maximum DMAable byte count */
	HOST_RAM_ALIGNMENT,	/* alignment in bytes */
	0x7f,			/* bitmap of burst sizes */
	1,			/* minimum transfer */
	0x0ffffffU,		/* maximum transfer */
	0x0ffffffU,		/* maximum segment length */
	1,			/* maximum number of segments */
	1,			/* granularity */
	0,			/* flags (reserved) */
};

static ddi_device_acc_attr_t accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};

/*
 * Declarations and Module Linkage
 */

#ifdef	DEBUG
static int	SMCG_debug = 0;
#endif

/* Required system entry points */
static int	SMCG_probe(dev_info_t *);
static int	SMCG_attach(dev_info_t *, ddi_attach_cmd_t);
static int	SMCG_detach(dev_info_t *, ddi_detach_cmd_t);

/* Required driver entry points for GLD */
static int 	SMCG_set_mac_addr(gld_mac_info_t *, unsigned char *);
static int	SMCG_reset(gld_mac_info_t *);
static int	SMCG_start_board(gld_mac_info_t *);
static int	SMCG_stop_board(gld_mac_info_t *);
static int	SMCG_set_multicast(gld_mac_info_t *, unsigned char *, int);
static int	SMCG_set_promiscuous(gld_mac_info_t *, int);
static int	SMCG_get_stats(gld_mac_info_t *, struct gld_stats *);
static int	SMCG_send(gld_mac_info_t *, mblk_t *);
static uint_t	SMCG_intr(gld_mac_info_t *);

/* Internal functions */
static int	SMCG_init_board(gld_mac_info_t *);
static int	SMCG_dma_alloc(smcg_t *);
static void	SMCG_dma_unalloc(smcg_t *);
static void	SMCG_freertn(struct smcg_rx_buffer_desc *);

static unsigned char
    SMCG_broadcastaddr[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

/* Standard Streams initialization */
static struct module_info minfo = {
	0, SMCG_NAME, 0, INFPSZ, SMCGHIWAT, SMCGLOWAT
};

static struct qinit rinit = {	/* read queues */
	0, gld_rsrv, gld_open, gld_close, 0, &minfo, 0
};

static struct qinit winit = {	/* write queues */
	gld_wput, gld_wsrv, 0, 0, 0, &minfo, 0
};

static struct streamtab smcg_info = {&rinit, &winit, NULL, NULL};

/* Standard Module linkage initialization for a Streams driver */

static 	struct cb_ops cb_smcg_ops = {
	nulldev,		/* cb_open */
	nulldev,		/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	nodev,			/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	&smcg_info,		/* cb_stream */
	(int)(D_MP)		/* cb_flag */
};

static struct dev_ops smcg_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	gld_getinfo,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	SMCG_probe,		/* devo_probe */
	SMCG_attach,		/* devo_attach */
	SMCG_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&cb_smcg_ops,		/* devo_cb_ops */
	(struct bus_ops *)NULL	/* devo_bus_ops */
};

static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	SMCG_IDENT,		/* short description */
	&smcg_ops		/* driver specific ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * DDI Entry Points
 */

/* probe(9E) -- Determine if a device is present */
/* ARGSUSED */
static int
SMCG_probe(dev_info_t *devinfo)
{
	return (DDI_PROBE_SUCCESS);
}

/*
 * attach(9E) -- Attach a device to the system
 *
 * Called once for each board successfully probed.
 */
static int
SMCG_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	gld_mac_info_t	*macinfo;
	Adapter_Struc	*pAd;
	smcg_t		*smcg;
	int		rc;
	ddi_acc_handle_t pcihandle;

#ifdef	DEBUG
	if (SMCG_debug & SMCGDDI)
		cmn_err(CE_CONT, SMCG_NAME "_attach(0x%p)", (void *)devinfo);
#endif

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	/*
	 * Allocate gld_mac_info_t and Lower MAC Adapter_Struc structures
	 */
	if ((macinfo = gld_mac_alloc(devinfo)) == NULL)
		return (DDI_FAILURE);
	if ((pAd = kmem_zalloc(sizeof (Adapter_Struc), KM_NOSLEEP)) == NULL) {
		gld_mac_free(macinfo);
		return (DDI_FAILURE);
	}
	if ((smcg = kmem_zalloc(sizeof (smcg_t), KM_NOSLEEP)) == NULL) {
		gld_mac_free(macinfo);
		kmem_free(pAd, sizeof (Adapter_Struc));
		return (DDI_FAILURE);
	}

	pAd->pc_bus = SMCG_PCI_BUS;

	/* create pci handle for UM_PCI_Service */
	if (pci_config_setup(devinfo, (ddi_acc_handle_t *)&pcihandle)
	    != DDI_SUCCESS) {
		goto attach_fail_cleanup;
	}

	/*
	 * Query the LMAC for the device information
	 */
	pAd->pcihandle = (void *) pcihandle;
	rc = LM_GetCnfg(pAd);

	pci_config_teardown((ddi_acc_handle_t *)&pcihandle);
	pAd->pcihandle = NULL;

	if (rc != ADAPTER_AND_CONFIG) {
		cmn_err(CE_WARN,
		    SMCG_NAME "_attach: LM_GetCnfg failed (0x%x)", rc);
		goto attach_fail_cleanup;
	}

	/*
	 * Initialize pointers to device specific functions which will be
	 * used by the generic layer.
	 */
	macinfo->gldm_reset   = SMCG_reset;
	macinfo->gldm_start   = SMCG_start_board;
	macinfo->gldm_stop    = SMCG_stop_board;
	macinfo->gldm_set_mac_addr   = SMCG_set_mac_addr;
	macinfo->gldm_set_multicast = SMCG_set_multicast;
	macinfo->gldm_set_promiscuous = SMCG_set_promiscuous;
	macinfo->gldm_get_stats   = SMCG_get_stats;
	macinfo->gldm_send    = SMCG_send;
	macinfo->gldm_intr    = SMCG_intr;
	macinfo->gldm_ioctl   = NULL;

	/*
	 * Initialize board characteristics needed by the generic layer.
	 */
	macinfo->gldm_ident = SMCG_IDENT;
	macinfo->gldm_type = DL_ETHER;
	macinfo->gldm_minpkt = 0;	/* assumes we pad ourselves */
	macinfo->gldm_maxpkt = SMCGMAXPKT;
	macinfo->gldm_addrlen = ETHERADDRL;
	macinfo->gldm_saplen = -2;
	macinfo->gldm_ppa = ddi_get_instance(devinfo);

	pAd->receive_mask = ACCEPT_BROADCAST;
	pAd->max_packet_size = SMMAXPKT;

	macinfo->gldm_broadcast_addr = SMCG_broadcastaddr;

	/* Get the board's vendor-assigned hardware network address. */
	LM_Get_Addr(pAd);
	macinfo->gldm_vendor_addr = (unsigned char *)pAd->node_address;

	/* Link macinfo, smcg, and LMAC Adapter Structs */
	macinfo->gldm_private = (caddr_t)smcg;
	pAd->sm_private = (void *)smcg;
	smcg->smcg_pAd = pAd;
	smcg->smcg_macinfo = macinfo;

	pAd->ptr_rx_CRC_errors = &smcg->rx_CRC_errors;
	pAd->ptr_rx_too_big = &smcg->rx_too_big;
	pAd->ptr_rx_lost_pkts = &smcg->rx_lost_pkts;
	pAd->ptr_rx_align_errors = &smcg->rx_align_errors;
	pAd->ptr_rx_overruns = &smcg->rx_overruns;
	pAd->ptr_tx_deferred = &smcg->tx_deferred;
	pAd->ptr_tx_total_collisions = &smcg->tx_total_collisions;
	pAd->ptr_tx_max_collisions = &smcg->tx_max_collisions;
	pAd->ptr_tx_one_collision = &smcg->tx_one_collision;
	pAd->ptr_tx_mult_collisions = &smcg->tx_mult_collisions;
	pAd->ptr_tx_ow_collision = &smcg->tx_ow_collision;
	pAd->ptr_tx_CD_heartbeat = &smcg->tx_CD_heartbeat;
	pAd->ptr_tx_carrier_lost = &smcg->tx_carrier_lost;
	pAd->ptr_tx_underruns = &smcg->tx_underruns;
	pAd->ptr_ring_OVW = &smcg->ring_OVW;

	macinfo->gldm_devinfo = smcg->smcg_devinfo = devinfo;

	pAd->num_of_tx_buffs = ddi_getprop(DDI_DEV_T_ANY, devinfo,
	    DDI_PROP_DONTPASS, "num-tx-bufs", SMTRANSMIT_BUFS);
	if (pAd->num_of_tx_buffs > SMCG_MAX_TXDESCS) {
		pAd->num_of_tx_buffs = SMCG_MAX_TXDESCS;
		cmn_err(CE_WARN, SMCG_NAME
		    "Max number_of_tx_buffs is %d", SMCG_MAX_TXDESCS);
	}
	if (pAd->num_of_tx_buffs < 2) {
		pAd->num_of_tx_buffs = 2;
	}
	pAd->num_of_rx_buffs = ddi_getprop(DDI_DEV_T_ANY, devinfo,
	    DDI_PROP_DONTPASS, "num-rx-bufs", SMRECEIVE_BUFS);
	if (pAd->num_of_rx_buffs > SMCG_MAX_RXDESCS) {
		pAd->num_of_rx_buffs = SMCG_MAX_RXDESCS;
		cmn_err(CE_WARN, SMCG_NAME
		    "Max number_of_rx_buffs is %d", SMCG_MAX_RXDESCS);
	}
	if (pAd->num_of_rx_buffs < 2) {
		pAd->num_of_rx_buffs = 2;
	}

	if (ddi_get_iblock_cookie(devinfo, 0, &macinfo->gldm_cookie)
		!= DDI_SUCCESS)
		goto attach_fail_cleanup;

	/*
	 * rbuf_lock	Protects receive data structures
	 * txbuf_lock	Protects transmit data structures
	 * lm_lock	Protects all calls to LMAC layer
	 * rlist_lock	Protects receive buffer list
	 * Note: Locks should be acquired in the above order.
	 */
	mutex_init(&smcg->rbuf_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&smcg->txbuf_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&smcg->lm_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&smcg->rlist_lock, NULL, MUTEX_DRIVER, NULL);

	/*
	 * SMCG_dma_alloc is called before it is possible to get
	 * any interrupts, send or receive packets... Therefore I'm
	 * not going to take rlist_lock for it.
	 */
	if (SMCG_dma_alloc(smcg) != DDI_SUCCESS)
		goto attach_fail_cleanup1;

#ifdef SAFE
	LM_Reset_Adapter(pAd);
#endif
	/* Add the interrupt handler */
	if (ddi_add_intr(devinfo, 0,  NULL, NULL, gld_intr, (caddr_t)macinfo)
	    != DDI_SUCCESS) {
		SMCG_dma_unalloc(smcg);
		goto attach_fail_cleanup1;
	}

	/*
	 * Register ourselves with the GLD interface
	 *
	 * gld_register will:
	 *	link us with the GLD system;
	 *	create the minor node.
	 */
	if (gld_register(devinfo, SMCG_NAME, macinfo) != DDI_SUCCESS) {
		ddi_remove_intr(devinfo, 0, macinfo->gldm_cookie);
		SMCG_dma_unalloc(smcg);
		goto attach_fail_cleanup1;
	}

	return (DDI_SUCCESS);

attach_fail_cleanup1:
	mutex_destroy(&smcg->rbuf_lock);
	mutex_destroy(&smcg->txbuf_lock);
	mutex_destroy(&smcg->lm_lock);
	mutex_destroy(&smcg->rlist_lock);

attach_fail_cleanup:
	kmem_free(pAd, sizeof (Adapter_Struc));
	kmem_free(smcg, sizeof (smcg_t));
	gld_mac_free(macinfo);
	return (DDI_FAILURE);
}

/* detach(9E) -- Detach a device from the system */
static int
SMCG_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{
	gld_mac_info_t	*macinfo;
	Adapter_Struc	*pAd;
	smcg_t		*smcg;
	int		i;

#ifdef	DEBUG
	if (SMCG_debug & SMCGDDI)
		cmn_err(CE_CONT, SMCG_NAME "_detach(0x%p)", (void *)devinfo);
#endif

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	macinfo = ddi_get_driver_private(devinfo);
	smcg = (smcg_t *)macinfo->gldm_private;
	pAd = smcg->smcg_pAd;

	i = 50;

	mutex_enter(&smcg->rlist_lock);
	while (smcg->rx_bufs_outstanding > 0) {
		mutex_exit(&smcg->rlist_lock);
		delay(drv_usectohz(100000));
		if (--i == 0) {
			cmn_err(CE_WARN,
			    SMCG_NAME "%d: %d buffers not reclaimed",
			    macinfo->gldm_ppa, smcg->rx_bufs_outstanding);
			return (DDI_FAILURE);
		}
		mutex_enter(&smcg->rlist_lock);
	}
	smcg->detaching_flag = 1;
	mutex_exit(&smcg->rlist_lock);

	/*
	 * Unregister ourselves from the GLD interface
	 *
	 * gld_unregister will:
	 *	remove the minor node;
	 *	unlink us from the GLD system.
	 */
	if (gld_unregister(macinfo) != DDI_SUCCESS) {
		mutex_enter(&smcg->rlist_lock);
		smcg->detaching_flag = 0;
		mutex_exit(&smcg->rlist_lock);
		return (DDI_FAILURE);
	}

	ddi_remove_intr(devinfo, 0, macinfo->gldm_cookie);

	SMCG_dma_unalloc(smcg);

	mutex_destroy(&smcg->rbuf_lock);
	mutex_destroy(&smcg->txbuf_lock);
	mutex_destroy(&smcg->lm_lock);
	mutex_destroy(&smcg->rlist_lock);

	kmem_free(pAd, sizeof (Adapter_Struc));
	kmem_free(smcg, sizeof (smcg_t));
	gld_mac_free(macinfo);
	return (DDI_SUCCESS);
}

/*
 * GLD Entry Points
 */

/*
 * SMCG_reset() -- reset the board to initial state.
 */
static int
SMCG_reset(gld_mac_info_t *macinfo)
{
	int rc;

#ifdef	DEBUG
	if (SMCG_debug & SMCGTRACE)
		cmn_err(CE_CONT, SMCG_NAME "_reset(0x%p)", (void *)macinfo);
#endif

	rc = SMCG_init_board(macinfo);
	return (rc == SUCCESS ? GLD_SUCCESS : GLD_FAILURE);
}

/*
 * SMCG_init_board() -- initialize the specified network board.
 */
static int
SMCG_init_board(gld_mac_info_t *macinfo)
{
	smcg_t		*smcg = (smcg_t *)macinfo->gldm_private;
	Adapter_Struc	*pAd = smcg->smcg_pAd;
	int		rc;
	int		i;
	Data_Buff_Structure dbuf;

#ifdef	DEBUG
	if (SMCG_debug & SMCGTRACE)
		cmn_err(CE_CONT, SMCG_NAME "_init_board(0x%p)",
		    (void *)macinfo);
#endif

	mutex_enter(&smcg->rbuf_lock);
	mutex_enter(&smcg->lm_lock);
	pAd->receive_mask = ACCEPT_BROADCAST;

	rc = LM_Initialize_Adapter(pAd);

	smcg->rx_ring_index = 0;

	/* Give the buffers on the receive ring to the LMAC */
	for (i = 0; i < pAd->num_of_rx_buffs; i++) {
		dbuf.fragment_count = 1;
		dbuf.fragment_list[0].fragment_length =
		    (ETHERMAX + 4) | (unsigned long)PHYSICAL_ADDR;
		dbuf.fragment_list[0].fragment_ptr =
		    (unsigned char *)smcg->bdesc[i]->physaddr;

		LM_Put_Rx_Frag(&dbuf, pAd);
	}

	/*
	 * The spec says we should wait for UM_Status_Change, but all LMs
	 * we currently support change the status prior to returning from
	 * LM_Initialize_Adapter().
	 */

	mutex_exit(&smcg->lm_lock);
	mutex_exit(&smcg->rbuf_lock);

	if (rc != SUCCESS)
		cmn_err(CE_WARN,
		    SMCG_NAME " LM_Initialize_Adapter failed %d", rc);

	return (rc);
}

/*
 * SMCG_start_board() -- start the board receiving and allow transmits.
 */
static int
SMCG_start_board(gld_mac_info_t *macinfo)
{
	smcg_t		*smcg = (smcg_t *)macinfo->gldm_private;
	Adapter_Struc	*pAd = smcg->smcg_pAd;
	int		rc;

#ifdef	DEBUG
	if (SMCG_debug & SMCGTRACE)
		cmn_err(CE_CONT, SMCG_NAME "_start_board(0x%p)",
		    (void *)macinfo);
#endif

	mutex_enter(&smcg->lm_lock);

	rc = LM_Open_Adapter(pAd);

	/*
	 * The spec says we should wait for UM_Status_Change, but all LMs
	 * we currently support change the status prior to returning from
	 * LM_Open_Adapter().
	 */
	mutex_exit(&smcg->lm_lock);

	if (rc != SUCCESS)
		cmn_err(CE_WARN,
		    SMCG_NAME " LM_Open_Adapter failed %d", rc);

	return (rc == SUCCESS ? GLD_SUCCESS : GLD_FAILURE);
}

/*
 * SMCG_stop_board() -- stop board receiving
 */
static int
SMCG_stop_board(gld_mac_info_t *macinfo)
{
	smcg_t		*smcg = (smcg_t *)macinfo->gldm_private;
	Adapter_Struc	*pAd = smcg->smcg_pAd;
	int		rc, i;

#ifdef	DEBUG
	if (SMCG_debug & SMCGTRACE)
		cmn_err(CE_CONT, SMCG_NAME "_stop_board(0x%p)",
		    (void *)macinfo);
#endif
	mutex_enter(&smcg->txbuf_lock);
	mutex_enter(&smcg->lm_lock);

	if (smcg->tx_ring_head != smcg->tx_ring_tail)
		LM_Reap_Xmits(pAd);

	i = 20;
	while ((smcg->tx_ring_head != smcg->tx_ring_tail) && (i--)) {
		delay(drv_usectohz(10000));
		LM_Reap_Xmits(pAd);
	}

	rc = LM_Close_Adapter(pAd);

	while (smcg->tx_ring_head != smcg->tx_ring_tail) {
		ASSERT(mutex_owned(&smcg->txbuf_lock));
		freemsg(smcg->tx_info[smcg->tx_ring_tail].mptr);
		for (i = 0; i < smcg->tx_info[smcg->tx_ring_tail].handles_bound;
		    i++)
			(void) ddi_dma_unbind_handle(
			    smcg->tx_info[smcg->tx_ring_tail].dmahandle[i]);
		smcg->tx_ring_tail = (smcg->tx_ring_tail+1) %
		    pAd->num_of_tx_buffs;
	}

	/*
	 * The spec says we should wait for UM_Status_Change, but all LMs
	 * we currently support change the status prior to returning from
	 * LM_Close_Adapter().
	 */
	mutex_exit(&smcg->lm_lock);
	mutex_exit(&smcg->txbuf_lock);

#ifdef	DEBUG
	if (rc != SUCCESS)
		cmn_err(CE_WARN,
		    SMCG_NAME " LM_Close_Adapter failed %d", rc);
#endif

	return (rc == SUCCESS ? GLD_SUCCESS : GLD_FAILURE);
}

/*
 * SMCG_set_mac_addr() -- set node MAC address
 */
static int
SMCG_set_mac_addr(gld_mac_info_t *macinfo, unsigned char *macaddr)
{
	smcg_t		*smcg = (smcg_t *)macinfo->gldm_private;
	Adapter_Struc	*pAd = smcg->smcg_pAd;

	mutex_enter(&smcg->lm_lock);
	bcopy(macaddr, pAd->node_address, ETHERADDRL);
	LM_Set_Addr(pAd); /* LM function */
	mutex_exit(&smcg->lm_lock);

	return (GLD_SUCCESS);
}

/*
 * SMCG_set_multicast() -- set (enable) or disable a multicast address
 *
 * Program the hardware to enable/disable the multicast address
 * in "mcast".
 */
static int
SMCG_set_multicast(gld_mac_info_t *macinfo, unsigned char *mcast, int op)
{
	smcg_t		*smcg = (smcg_t *)macinfo->gldm_private;
	Adapter_Struc	*pAd = smcg->smcg_pAd;
	int		rc;
	int i;

	mutex_enter(&smcg->rbuf_lock);
	mutex_enter(&smcg->lm_lock);
#ifdef	DEBUG
	if (SMCG_debug & SMCGTRACE)
		cmn_err(CE_CONT, SMCG_NAME "_set_multicast(0x%p, %s)",
		    (void *)macinfo, (op == GLD_MULTI_ENABLE) ? "ON" : "OFF");
#endif

	for (i = 0; i < ETHERADDRL; i++)
		pAd->multi_address[i] = mcast[i];

	if (op == GLD_MULTI_ENABLE) {
		if ((rc = LM_Add_Multi_Address(pAd)) == SUCCESS)
			if (++smcg->smcg_multicount == 1) {
				pAd->receive_mask |= ACCEPT_MULTICAST;
				rc = LM_Change_Receive_Mask(pAd);
			}
	} else {
		if ((rc = LM_Delete_Multi_Address(pAd)) == SUCCESS)
			if (--smcg->smcg_multicount == 0) {
				pAd->receive_mask &= ~ACCEPT_MULTICAST;
				rc = LM_Change_Receive_Mask(pAd);
			}
	}

#ifdef	DEBUG
	if (rc != SUCCESS)
		cmn_err(CE_WARN,
		    SMCG_NAME "_set_multicast failed %d", rc);
#endif

	mutex_exit(&smcg->lm_lock);
	mutex_exit(&smcg->rbuf_lock);
	return (rc == SUCCESS ? GLD_SUCCESS : GLD_FAILURE);
}


/*
 * SMCG_set_promiscuous() -- set or reset promiscuous mode on the board
 *
 * Program the hardware to enable/disable promiscuous mode.
 */
static int
SMCG_set_promiscuous(gld_mac_info_t *macinfo, int on)
{
	smcg_t		*smcg = (smcg_t *)macinfo->gldm_private;
	Adapter_Struc	*pAd = smcg->smcg_pAd;
	int		rc;

	mutex_enter(&smcg->lm_lock);
#ifdef	DEBUG
	if (SMCG_debug & SMCGTRACE)
		cmn_err(CE_CONT, SMCG_NAME "_promiscuous(0x%p, %s)",
		    (void *)macinfo,
		    (on != GLD_MAC_PROMISC_NONE) ? "ON" : "OFF");
#endif
	if (on != GLD_MAC_PROMISC_NONE) {
		pAd->receive_mask |= PROMISCUOUS_MODE;
	} else {
		pAd->receive_mask &= ~PROMISCUOUS_MODE;
	}

	rc = LM_Change_Receive_Mask(pAd);
	mutex_exit(&smcg->lm_lock);

#ifdef	DEBUG
	if (rc != SUCCESS)
		cmn_err(CE_WARN,
		    SMCG_NAME "_prom: LM_Change_Receive_Mask failed %d", rc);
#endif
	return (rc == SUCCESS ? GLD_SUCCESS : GLD_FAILURE);
}

/*
 * SMCG_get_stats() -- update statistics
 */
static int
SMCG_get_stats(gld_mac_info_t *macinfo, struct gld_stats *g_stats)
{
	smcg_t		*smcg = (smcg_t *)macinfo->gldm_private;
	Adapter_Struc	*pAd = smcg->smcg_pAd;

#ifdef	DEBUG
	if (SMCG_debug & SMCGTRACE)
		cmn_err(CE_CONT, SMCG_NAME "_get_stat(0x%p)", (void *)macinfo);
#endif

/*
 * I am not taking mutexes around the statistics assigments as they could
 * have changed by the time the user application gets them.
 *
 * However not taking the mutex means that statistics may not be self
 * consistant.
 *
 * But if this is changed in the future then take mutexes in the following
 * order rbuf_lock, txbuf_lock, lm_lock.
 */
	g_stats->glds_crc = smcg->rx_CRC_errors;
	g_stats->glds_missed = smcg->rx_lost_pkts;
	g_stats->glds_frame = smcg->rx_align_errors;
	g_stats->glds_overflow = smcg->rx_overruns;
	g_stats->glds_collisions = smcg->tx_total_collisions;
	g_stats->glds_excoll = smcg->tx_max_collisions;
	g_stats->glds_nocarrier = smcg->tx_carrier_lost;
	g_stats->glds_underflow = smcg->tx_underruns;

	/* stats added in conversion to v2 */

	if (pAd->media_type2 & MEDIA_TYPE_MII) smcg->media = GLDM_PHYMII;
	else if (pAd->media_type2 & MEDIA_TYPE_UTP) smcg->media = GLDM_TP;
	else if (pAd->media_type2 & MEDIA_TYPE_BNC) smcg->media = GLDM_BNC;
	else if (pAd->media_type2 & MEDIA_TYPE_AUI) smcg->media = GLDM_AUI;
	else smcg->media = GLDM_UNKNOWN;

	smcg->duplex = (pAd->line_speed & LINE_SPEED_FULL_DUPLEX) ?
		GLD_DUPLEX_FULL: GLD_DUPLEX_HALF;

	if	(pAd->line_speed & LINE_SPEED_100) smcg->speed = 100000000;
	else if (pAd->line_speed & LINE_SPEED_10)  smcg->speed = 10000000;
	else if (pAd->line_speed & LINE_SPEED_16)  smcg->speed = 16000000;
	else if (pAd->line_speed & LINE_SPEED_4)   smcg->speed = 4000000;
	else {
		smcg->speed = 0; /* speed is unknown */
	}

	g_stats->glds_intr = smcg->intr;
	g_stats->glds_defer = smcg->tx_deferred;
	g_stats->glds_short = smcg->short_count;
	g_stats->glds_norcvbuf = smcg->norcvbuf;
	g_stats->glds_dot3_frame_too_long = smcg->rx_too_big;
	g_stats->glds_dot3_first_coll = smcg->tx_one_collision;
	g_stats->glds_dot3_multi_coll = smcg->tx_mult_collisions;
	g_stats->glds_dot3_sqe_error = 0; /* Not implemented by LMAC */
	g_stats->glds_xmtlatecoll = smcg->tx_ow_collision;

	g_stats->glds_speed = smcg->speed;
	g_stats->glds_duplex = smcg->duplex;
	g_stats->glds_media = smcg->media;

	/* Stats which are calculated from other stats */
	g_stats->glds_errxmt =
		smcg->tx_CD_heartbeat + smcg->tx_max_collisions +
		smcg->tx_carrier_lost + smcg->tx_underruns +
		smcg->tx_ow_collision;
	g_stats->glds_errrcv =
		smcg->rx_CRC_errors + smcg->rx_too_big +
		smcg->rx_align_errors + smcg->rx_overruns +
		smcg->short_count;
	g_stats->glds_dot3_mac_xmt_error = smcg->tx_underruns;
	g_stats->glds_dot3_mac_rcv_error =
		smcg->rx_overruns + smcg->short_count;
	return (GLD_SUCCESS);
}

/*
 * SMCG_send() -- send a packet
 */
static int
SMCG_send(gld_mac_info_t *macinfo, mblk_t *mp)
{
	smcg_t			*smcg = (smcg_t *)macinfo->gldm_private;
	Adapter_Struc		*pAd = smcg->smcg_pAd;
	int			i = 0, j = 0, totlen = 0, msglen = 0, rc;
	mblk_t			*mptr = mp;
	Data_Buff_Structure	dbuf;
	ddi_dma_cookie_t	cookie;
	unsigned int		ncookies;

	for (; mptr != NULL; i++, mptr = mptr->b_cont) {
		if (i >= SMCG_MAX_TX_MBLKS) {
			if (pullupmsg(mp, -1) == 0) {
				smcg->smcg_need_gld_sched = 1;
				return (GLD_NORESOURCES); /* retry send */
			}
			msglen = (mp->b_wptr - mp->b_rptr);
			break;
		}
		msglen += (mptr->b_wptr - mptr->b_rptr);
	}

	if (msglen > ETHERMAX) {
		cmn_err(CE_WARN, SMCG_NAME "%d: dropping oversize packet (%d)",
		    macinfo->gldm_ppa, msglen);
		return (GLD_BADARG);
	}


	mutex_enter(&smcg->txbuf_lock);
	mutex_enter(&smcg->lm_lock);
	LM_Reap_Xmits(pAd);
	mutex_exit(&smcg->lm_lock);

	if ((smcg->tx_ring_head + 1) % pAd->num_of_tx_buffs
	    == smcg->tx_ring_tail) {
		smcg->smcg_need_gld_sched = 1;
		mutex_exit(&smcg->txbuf_lock);
		return (GLD_NORESOURCES); /* retry send */
	}

	for (mptr = mp, i = 0; mptr != NULL; mptr = mptr->b_cont) {
		int blocklen = mptr->b_wptr - mptr->b_rptr;

		if (blocklen == 0)
			continue;

		ASSERT(i < SMCG_MAX_TX_MBLKS);
		rc = ddi_dma_addr_bind_handle(
		    smcg->tx_info[smcg->tx_ring_head].dmahandle[i], NULL,
		    (caddr_t)mptr->b_rptr, (size_t)blocklen, DDI_DMA_WRITE,
		    DDI_DMA_DONTWAIT, 0, &cookie, &ncookies);
		if (rc != DDI_DMA_MAPPED) {
			while (--i >= 0)
				(void) ddi_dma_unbind_handle(
				    smcg->tx_info[smcg->tx_ring_head].
				    dmahandle[i]);
			if (rc == DDI_DMA_NORESOURCES) {
				smcg->smcg_need_gld_sched = 1;
				mutex_exit(&smcg->txbuf_lock);
				return (GLD_NORESOURCES);
			}
#ifdef	DEBUG
	if (SMCG_debug & SMCGTRACE)
		cmn_err(CE_WARN, SMCG_NAME
			"Send bind handle failure = 0x%x", rc);
#endif
			mutex_exit(&smcg->txbuf_lock);
			return (GLD_FAILURE);
		}

		/* CONSTANTCONDITION */
		while (1) {
			dbuf.fragment_list[j].fragment_length =
			    cookie.dmac_size | PHYSICAL_ADDR;
			dbuf.fragment_list[j].fragment_ptr =
			    (unsigned char *)(uintptr_t)cookie.dmac_address;
			j++;
			if (--ncookies == 0)
				break;
			ddi_dma_nextcookie(
			    smcg->tx_info[smcg->tx_ring_head].dmahandle[i],
			    &cookie);
		}
		i++;
		totlen += blocklen;
	}
	dbuf.fragment_count = j;
	smcg->tx_info[smcg->tx_ring_head].handles_bound = i;
	smcg->tx_info[smcg->tx_ring_head].mptr = mp;

	if (totlen < ETHERMIN)
		totlen = ETHERMIN;	/* pad if necessary */

	mutex_enter(&smcg->lm_lock);
	pAd->xmit_interrupts = (smcg->smcg_need_gld_sched) ? 1 : 0;
	rc = LM_Send(&dbuf, pAd, totlen);
	mutex_exit(&smcg->lm_lock);

	if (rc != SUCCESS) {
		for (i = 0;
		    i < smcg->tx_info[smcg->tx_ring_head].handles_bound; i++)
			(void) ddi_dma_unbind_handle(
			    smcg->tx_info[smcg->tx_ring_head].dmahandle[i]);
	} else
		smcg->tx_ring_head =
		    (smcg->tx_ring_head+1) % pAd->num_of_tx_buffs;

	mutex_exit(&smcg->txbuf_lock);

#ifdef	DEBUG
	if (rc != SUCCESS && rc != OUT_OF_RESOURCES)
		cmn_err(CE_WARN,
		    SMCG_NAME "_send: LM_Send failed %d", rc);
#endif
	if (rc == SUCCESS) {
		return (GLD_SUCCESS);
	} else if (rc == OUT_OF_RESOURCES) {
		smcg->smcg_need_gld_sched = 1;
		return (GLD_NORESOURCES);
	} else {
		return (GLD_FAILURE);
	}
}

/*
 * SMCG_intr() -- interrupt from board to inform us that a receive or
 * transmit has completed.
 */
static uint_t
SMCG_intr(gld_mac_info_t *macinfo)
{
	smcg_t		*smcg = (smcg_t *)macinfo->gldm_private;
	Adapter_Struc	*pAd = smcg->smcg_pAd;
	mblk_t		*mp;
	int		rc;

#ifdef	DEBUG
	if (SMCG_debug & SMCGINT)
		cmn_err(CE_CONT, SMCG_NAME "_intr(0x%p)", (void *)macinfo);
#endif

	mutex_enter(&smcg->rbuf_lock);
	mutex_enter(&smcg->txbuf_lock);
	mutex_enter(&smcg->lm_lock);
	LM_Disable_Adapter(pAd);
	rc = LM_Service_Events(pAd);
	LM_Enable_Adapter(pAd);
	mutex_exit(&smcg->lm_lock);
	mutex_exit(&smcg->txbuf_lock);

	while (smcg->rq_first) {
		mp = smcg->rq_first;
		smcg->rq_first = smcg->rq_first->b_next;
		mp->b_next = 0;
		mutex_exit(&smcg->rbuf_lock);
		gld_recv(macinfo, mp);
		mutex_enter(&smcg->rbuf_lock);
	}
	smcg->rq_last = 0;
	mutex_exit(&smcg->rbuf_lock);
#ifdef	DEBUG
	if ((rc != SUCCESS) && (SMCG_debug & SMCGINT))
		cmn_err(CE_WARN,
		    SMCG_NAME "_intr: LM_Service_Events error %d", rc);
#endif

	if (rc == NOT_MY_INTERRUPT)
		return (DDI_INTR_UNCLAIMED);

	smcg->intr++; /* Update Statistics */

	if (smcg->smcg_need_gld_sched) {
		smcg->smcg_need_gld_sched = 0;
		gld_sched(macinfo);
	}
	return (DDI_INTR_CLAIMED);
}

/* ARGSUSED */
int
UM_Receive_Packet(char *plkahead, unsigned short length,
	Adapter_Struc *pAd, int status, Data_Buff_Structure **pDataBuff)
{
	mblk_t				*mp;
	smcg_t				*smcg = (smcg_t *)pAd->sm_private;
	struct smcg_rx_buffer_desc	*bdesc;

	ASSERT(mutex_owned(&smcg->rbuf_lock));
	/*
	 * Look for a free data buffer to replace the one we are about
	 * to pass upstream
	 */
	mutex_enter(&smcg->rlist_lock);
	if (((bdesc = smcg->rx_freelist) != NULL) && !smcg->detaching_flag) {
		smcg->rx_freelist = bdesc->next;
		smcg->rx_bufs_outstanding++;
		mp = desballoc((unsigned char *)
		    smcg->bdesc[smcg->rx_ring_index]->buf, (size_t)length,
		    BPRI_MED, (frtn_t *)smcg->bdesc[smcg->rx_ring_index]);
		if (mp == NULL) {
			bdesc->next = smcg->rx_freelist;
			smcg->rx_freelist = bdesc;
			smcg->rx_bufs_outstanding--;
			smcg->norcvbuf++;	/* Update Statistics */
			mutex_exit(&smcg->rlist_lock);
			goto rcv_done;		/* No resources */
		}
		mutex_exit(&smcg->rlist_lock);
		smcg->bdesc[smcg->rx_ring_index] = bdesc;
	} else {
		mutex_exit(&smcg->rlist_lock);
		/* freelist empty, leave buffer intact, and copy out data */
		mp = allocb(length, BPRI_MED);
		if (mp == NULL) {
			smcg->norcvbuf++;	/* Update Statistics */
			goto rcv_done;	/* No resources, drop the packet */
		}
		bcopy(smcg->bdesc[smcg->rx_ring_index]->buf, mp->b_wptr,
		    length);
	}

	mp->b_wptr += length;
	if (length < ETHERMIN)
		smcg->short_count++; /* Update statistics */

	/*
	 * Queue received msgblks to be sent up to GLD with out holding
	 * any mutexes
	 */
	/* Make sure that the last one points to NULL */
	ASSERT(mp->b_next == 0);
	if (!smcg->rq_first) {	/* Add first entry */
		smcg->rq_first = mp;
		smcg->rq_last = mp;
	} else {
		smcg->rq_last->b_next = mp;	/* Link mp's in the queue */
		smcg->rq_last = mp;		/* Move last pointer */
	}

rcv_done:
	smcg->smc_dbuf.fragment_list[0].fragment_ptr = (unsigned char *)
	    smcg->bdesc[smcg->rx_ring_index]->physaddr;
	*pDataBuff = &(smcg->smc_dbuf);

	smcg->rx_ring_index = (smcg->rx_ring_index + 1) % pAd->num_of_rx_buffs;

	return (SUCCESS);
}

/*
 * UM_Status_Change -- LM has completed a driver state change
 */
/* ARGSUSED */
int
UM_Status_Change(Adapter_Struc *pAd)
{
	/*
	 * This function is called by several LMACs but the completion
	 * mechanism is not used by the UMAC to determine if the event
	 * has completed, because all applicable functions complete
	 * prior to returning.
	 */
	return (SUCCESS);
}

/*
 * UM_Receive_Copy_Complete() -- LM has completed a receive copy
 */
/* ARGSUSED */
int
UM_Receive_Copy_Complete(Adapter_Struc *pAd)
{
	/*
	 * This completion mechanism is not used by the UMAC to
	 * determine if the copy has completed, because all LMACs
	 * complete the copy prior to returning.
	 */
	return (SUCCESS);
}

/*
 * UM_Send_Complete() -- LM has completed sending a packet
 */
/* ARGSUSED */
int
UM_Send_Complete(int sstatus, Adapter_Struc *pAd)
{
	int	i;
	smcg_t	*smcg = (smcg_t *)pAd->sm_private;

	ASSERT(mutex_owned(&smcg->txbuf_lock));
	freemsg(smcg->tx_info[smcg->tx_ring_tail].mptr);
	for (i = 0; i < smcg->tx_info[smcg->tx_ring_tail].handles_bound; i++) {
		(void) ddi_dma_unbind_handle(
		    smcg->tx_info[smcg->tx_ring_tail].dmahandle[i]);
	}
	smcg->tx_ring_tail = (smcg->tx_ring_tail+1) % pAd->num_of_tx_buffs;

	return (SUCCESS);
}

/*
 * UM_Interrupt() -- LM has generated an interrupt at our request
 */
/* ARGSUSED */
int
UM_Interrupt(Adapter_Struc *pAd)
{
#ifdef	DEBUG
	cmn_err(CE_WARN, SMCG_NAME " UM_Interrupt called unexpectedly");
#endif
	return (SUCCESS);
}

int
lm_stub()
{
	return (SUCCESS);
}

int
UM_PCI_Services(Adapter_Struc *pAd, union REGS *pregs)
{
	int func = (int)pregs->h.al;
	unsigned long regnum; /* register number */
	unsigned short vendid;
	unsigned short devid;
	unsigned long compval;

	switch (func) {
		case PCI_BIOS_PRESENT:
			/* return PCI present with rev 2.1 */
			pregs->h.ah = 0;
			pregs->h.al = 0;
			pregs->h.bh = 2;
			pregs->h.bl = 1;
			pregs->h.cl = 1;
			pregs->e.edx = 0x20494350;
			pregs->x.cflag = 0;
			break;
		case FIND_PCI_DEVICE:
			vendid = pregs->x.dx;
			devid = pregs->x.cx;
			compval = (((ulong_t)devid) << 16) | ((ulong_t)vendid);
			if (vendid == 0xffff) { /* bad vendor id */
				pregs->x.cflag = 1;
				pregs->h.ah = PCI_BAD_VENDOR_ID;
			} else {
				if (pci_config_get32(
				    (ddi_acc_handle_t)pAd->pcihandle, 0) ==
				    compval) {
					pregs->h.bh = 0; /* put 0 to fake it */
					pregs->h.bl = 0; /* put 0 to fake it */
					pregs->h.ah = PCI_SUCCESSFUL;
					pregs->x.cflag = 0;
				} else {
					pregs->h.ah = PCI_DEVICE_NOT_FOUND;
					pregs->x.cflag = 1;
				}
			}
			break;
		case PCI_READ_CONFIG_BYTE:
			regnum = (unsigned long) pregs->h.di;
			pregs->h.cl = pci_config_get8(
			    (ddi_acc_handle_t)pAd->pcihandle, regnum);
			pregs->x.cflag = 0;
			pregs->h.ah = PCI_SUCCESSFUL;
			break;
		case PCI_READ_CONFIG_WORD:
			regnum = (unsigned long)pregs->h.di;
			if (regnum & 0x1) {
				pregs->x.cflag = 1;
				pregs->h.ah = PCI_BAD_REGISTER_NUMBER;
			} else {
				pregs->x.cx = pci_config_get16(
				    (ddi_acc_handle_t)pAd->pcihandle, regnum);
				pregs->x.cflag = 0;
				pregs->h.ah = PCI_SUCCESSFUL;
			}
			break;
		case PCI_READ_CONFIG_DWORD:
			regnum = (unsigned long)pregs->h.di;
			if (regnum & 0x3) {
				pregs->x.cflag = 1;
				pregs->h.ah = PCI_BAD_REGISTER_NUMBER;
			} else {
				pregs->e.ecx = pci_config_get32(
				    (ddi_acc_handle_t)pAd->pcihandle, regnum);
				pregs->x.cflag = 0;
				pregs->h.ah = PCI_SUCCESSFUL;
			}
			break;
		case PCI_WRITE_CONFIG_BYTE:
			regnum = (unsigned long) pregs->h.di;
			pci_config_put8((ddi_acc_handle_t)pAd->pcihandle,
			    regnum, pregs->h.cl);
			pregs->x.cflag = 0;
			pregs->h.ah = PCI_SUCCESSFUL;
			break;
		case PCI_WRITE_CONFIG_WORD:
			regnum = (unsigned long)pregs->h.di;
			if (regnum & 0x1) {
				pregs->x.cflag = 1;
				pregs->h.ah = PCI_BAD_REGISTER_NUMBER;
			} else {
				pci_config_put16(
				    (ddi_acc_handle_t)pAd->pcihandle,
				    regnum, pregs->x.cx);
				pregs->x.cflag = 0;
				pregs->h.ah = PCI_SUCCESSFUL;
			}
			break;
		case PCI_WRITE_CONFIG_DWORD:
			regnum = (unsigned long)pregs->h.di;
			if (regnum & 0x1) {
				pregs->x.cflag = 1;
				pregs->h.ah = PCI_BAD_REGISTER_NUMBER;
			} else {
				pci_config_put32(
				    (ddi_acc_handle_t)pAd->pcihandle,
				    regnum, pregs->e.ecx);
				pregs->x.cflag = 0;
				pregs->h.ah = PCI_SUCCESSFUL;
			}
			break;
		default:
			pregs->x.cflag = 1;	/* set error */
			pregs->h.ah = PCI_FUNC_NOT_SUPPORTED;
			break;
	}
	return (0);
}

/* Functions that the LMAC doesn't know about */

/*
 * SMCG_dma_alloc assumes that either rlist_lock mutex is held or
 * that it is called from a point where no interrupts, send or receives
 * happen.
 */
static int
SMCG_dma_alloc(smcg_t *smcg)
{
	Adapter_Struc		*pAd = smcg->smcg_pAd;
	unsigned int		ramsize = LM_Get_Host_Ram_Size(pAd);
	uint_t			len, ncookies, i, j;
	ddi_dma_cookie_t	cookie;

	/* Allocate resources for shared memory block */
	if (ddi_dma_alloc_handle(smcg->smcg_devinfo, &host_ram_dma_attr,
	    DDI_DMA_SLEEP, 0, &smcg->hostram_dmahandle) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if (ddi_dma_mem_alloc(smcg->hostram_dmahandle, ramsize, &accattr,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, 0,
	    (caddr_t *)&pAd->host_ram_virt_addr,
	    (size_t *)&len, &smcg->hostram_acchandle) != DDI_SUCCESS) {
		ddi_dma_free_handle(&smcg->hostram_dmahandle);
		return (DDI_FAILURE);
	}

	if (ddi_dma_addr_bind_handle(smcg->hostram_dmahandle, NULL,
	    (caddr_t)pAd->host_ram_virt_addr, ramsize,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, 0,
	    &cookie, &ncookies) != DDI_SUCCESS) {
		ddi_dma_mem_free(&smcg->hostram_acchandle);
		ddi_dma_free_handle(&smcg->hostram_dmahandle);
		return (DDI_FAILURE);
	}

	ASSERT(ncookies == 1 && cookie.dmac_size >= ramsize);
	pAd->host_ram_phy_addr = cookie.dmac_address;

	/* Allocate a list of receive buffers */
	smcg->rxbdesc_mem = kmem_zalloc(sizeof (struct smcg_rx_buffer_desc) *
	    pAd->num_of_rx_buffs*2, KM_SLEEP);
	smcg->rx_freelist = (struct smcg_rx_buffer_desc *)smcg->rxbdesc_mem;

	for (i = 0; i < pAd->num_of_rx_buffs * 2; i++) {
		if (ddi_dma_alloc_handle(smcg->smcg_devinfo, &buf_dma_attr,
		    DDI_DMA_SLEEP, 0, &smcg->rx_freelist[i].dmahandle)
		    != DDI_SUCCESS)
			goto failure;

		if (ddi_dma_mem_alloc(smcg->rx_freelist[i].dmahandle,
		    ETHERMAX + 4, &accattr, DDI_DMA_CONSISTENT, DDI_DMA_SLEEP,
		    0, (caddr_t *)&smcg->rx_freelist[i].buf, (size_t *)&len,
		    &smcg->rx_freelist[i].acchandle) != DDI_SUCCESS) {
			ddi_dma_free_handle(&smcg->rx_freelist[i].dmahandle);
			goto failure;
		}

		if (ddi_dma_addr_bind_handle(smcg->rx_freelist[i].dmahandle,
		    NULL, (caddr_t)smcg->rx_freelist[i].buf, ETHERMAX + 4,
		    DDI_DMA_READ | DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, 0,
		    &cookie, &ncookies) != DDI_SUCCESS) {
			ddi_dma_mem_free(&smcg->rx_freelist[i].acchandle);
			ddi_dma_free_handle(&smcg->rx_freelist[i].dmahandle);
			goto failure;
		}

		ASSERT(ncookies == 1 && cookie.dmac_size >= ETHERMAX+4);
		smcg->rx_freelist[i].physaddr = cookie.dmac_address;
		smcg->rx_freelist[i].smcg = smcg;
		smcg->rx_freelist[i].free_rtn.free_func = SMCG_freertn;
		smcg->rx_freelist[i].free_rtn.free_arg =
		    (char *)&smcg->rx_freelist[i];

		smcg->rx_freelist[i].next = &smcg->rx_freelist[i+1];
	}

	smcg->rx_freelist[i-1].next = NULL;

	/*
	 * Remove one buffer from free list for each receive descriptor,
	 * and associate with an element in the receive ring
	 */
	for (i = 0; i < pAd->num_of_rx_buffs; i++) {
		/* Unlink from free list */
		smcg->bdesc[i] = smcg->rx_freelist;
		smcg->rx_freelist = smcg->bdesc[i]->next;
	}

	smcg->smc_dbuf.fragment_list[0].fragment_length =
	    (ETHERMAX + 4) | (unsigned long)PHYSICAL_ADDR;
	smcg->smc_dbuf.fragment_count = 1;

	/* Allocate the handles to which we bind outgoing data */
	for (i = 0; i < pAd->num_of_tx_buffs; i++)
		for (j = 0; j < SMCG_MAX_TX_MBLKS; j++)
			if (ddi_dma_alloc_handle(smcg->smcg_devinfo,
			    &txdata_attr, DDI_DMA_SLEEP, 0,
			    &smcg->tx_info[i].dmahandle[j]) != DDI_SUCCESS)
				goto failure;

	return (DDI_SUCCESS);

failure:
	SMCG_dma_unalloc(smcg);
	cmn_err(CE_WARN, SMCG_NAME ": could not allocate DMA resources");
	return (DDI_FAILURE);
}

/*
 * SMCG_dma_unalloc assumes that either rlist_lock mutex is held or
 * that it is called from a point where no interrupts, send or receives
 * happen.
 */
/* XXX Bogus to look at the supposedly opaque handles, even to look for NULL */
static void
SMCG_dma_unalloc(smcg_t *smcg)
{
	Adapter_Struc			*pAd = smcg->smcg_pAd;
	struct smcg_rx_buffer_desc	*bdesc;
	int				i, j;

	for (i = 0; i < pAd->num_of_tx_buffs; i++)
		for (j = 0; j < SMCG_MAX_TX_MBLKS; j++) {
			if (smcg->tx_info[i].dmahandle[j] != NULL)
				ddi_dma_free_handle(
				    &smcg->tx_info[i].dmahandle[j]);
			smcg->tx_info[i].dmahandle[j] = NULL;
		}

	ASSERT(smcg->rx_bufs_outstanding == 0);
	/* Free up rx buffers currently on freelist */
	for (bdesc = smcg->rx_freelist; bdesc; bdesc = bdesc->next) {
		if (bdesc->dmahandle != NULL)
			(void) ddi_dma_unbind_handle(bdesc->dmahandle);
		if (bdesc->acchandle != NULL)
			ddi_dma_mem_free(&bdesc->acchandle);
		if (bdesc->dmahandle != NULL)
			ddi_dma_free_handle(&bdesc->dmahandle);
	}

	/* Free up all rx buffers that are associated with rx descriptors */
	for (i = 0; i < pAd->num_of_rx_buffs; i++) {
		if (smcg->bdesc[i] == NULL)
			continue;
		if (smcg->bdesc[i]->dmahandle != NULL)
			(void) ddi_dma_unbind_handle(smcg->bdesc[i]->dmahandle);
		if (smcg->bdesc[i]->acchandle != NULL)
			ddi_dma_mem_free(&smcg->bdesc[i]->acchandle);
		if (smcg->bdesc[i]->dmahandle != NULL)
			ddi_dma_free_handle(&smcg->bdesc[i]->dmahandle);
	}

	kmem_free(smcg->rxbdesc_mem,
	    sizeof (struct smcg_rx_buffer_desc) * pAd->num_of_rx_buffs*2);

	/* Free resources associated with shared ram block */
	if (smcg->hostram_dmahandle != NULL)
		(void) ddi_dma_unbind_handle(smcg->hostram_dmahandle);
	if (smcg->hostram_acchandle != NULL)
		ddi_dma_mem_free(&smcg->hostram_acchandle);
	if (smcg->hostram_dmahandle != NULL)
		ddi_dma_free_handle(&smcg->hostram_dmahandle);
}

/* esballoc() callback - Called when the message we sent up is freed */
static void
SMCG_freertn(struct smcg_rx_buffer_desc *bdesc)
{
	smcg_t	*smcg = bdesc->smcg;

	mutex_enter(&smcg->rlist_lock);
	/* Return the receive buffer to the freelist */
	smcg->rx_bufs_outstanding--;
	bdesc->next = smcg->rx_freelist;
	smcg->rx_freelist = bdesc;
	mutex_exit(&smcg->rlist_lock);
}
