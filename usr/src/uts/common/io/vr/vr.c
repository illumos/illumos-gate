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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/stat.h>
#include <sys/pci.h>
#include <sys/modctl.h>
#include <sys/kstat.h>
#include <sys/ethernet.h>
#include <sys/devops.h>
#include <sys/debug.h>
#include <sys/conf.h>
#include <sys/mac.h>
#include <sys/mac_provider.h>
#include <sys/mac_ether.h>
#include <sys/sysmacros.h>
#include <sys/dditypes.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/miiregs.h>
#include <sys/byteorder.h>
#include <sys/note.h>
#include <sys/vlan.h>

#include "vr.h"
#include "vr_impl.h"

/*
 * VR in a nutshell
 * The card uses two rings of data structures to communicate with the host.
 * These are referred to as "descriptor rings" and there is one for transmit
 * (TX) and one for receive (RX).
 *
 * The driver uses a "DMA buffer" data type for mapping to those descriptor
 * rings. This is a structure with handles and a DMA'able buffer attached to it.
 *
 * Receive
 * The receive ring is filled with DMA buffers. Received packets are copied into
 * a newly allocated mblk's and passed upstream.
 *
 * Transmit
 * Each transmit descriptor has a DMA buffer attached to it. The data of TX
 * packets is copied into the DMA buffer which is then enqueued for
 * transmission.
 *
 * Reclaim of transmitted packets is done as a result of a transmit completion
 * interrupt which is generated 3 times per ring at minimum.
 */

#if defined(DEBUG)
uint32_t	vrdebug = 1;
#define	VR_DEBUG(args)	do {				\
		if (vrdebug > 0)			\
			(*vr_debug()) args;		\
			_NOTE(CONSTANTCONDITION)	\
		} while (0)
static	void	vr_prt(const char *fmt, ...);
	void	(*vr_debug())(const char *fmt, ...);
#else
#define	VR_DEBUG(args)	do ; _NOTE(CONSTANTCONDITION) while (0)
#endif

static char vr_ident[] = "VIA Rhine Ethernet";

/*
 * Attributes for accessing registers and memory descriptors for this device.
 */
static ddi_device_acc_attr_t vr_dev_dma_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

/*
 * Attributes for accessing data.
 */
static ddi_device_acc_attr_t vr_data_dma_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};

/*
 * DMA attributes for descriptors for communication with the device
 * This driver assumes that all descriptors of one ring fit in one consequitive
 * memory area of max 4K (256 descriptors) that does not cross a page boundary.
 * Therefore, we request 4K alignement.
 */
static ddi_dma_attr_t vr_dev_dma_attr = {
	DMA_ATTR_V0,			/* version number */
	0,				/* low DMA address range */
	0xFFFFFFFF,			/* high DMA address range */
	0x7FFFFFFF,			/* DMA counter register */
	0x1000,				/* DMA address alignment */
	0x7F,				/* DMA burstsizes */
	1,				/* min effective DMA size */
	0xFFFFFFFF,			/* max DMA xfer size */
	0xFFFFFFFF,			/* segment boundary */
	1,				/* s/g list length */
	1,				/* granularity of device */
	0				/* DMA transfer flags */
};

/*
 * DMA attributes for the data moved to/from the device
 * Note that the alignement is set to 2K so hat a 1500 byte packet never
 * crosses a page boundary and thus that a DMA transfer is not split up in
 * multiple cookies with a 4K/8K pagesize
 */
static ddi_dma_attr_t vr_data_dma_attr = {
	DMA_ATTR_V0,			/* version number */
	0,				/* low DMA address range */
	0xFFFFFFFF,			/* high DMA address range */
	0x7FFFFFFF,			/* DMA counter register */
	0x800,				/* DMA address alignment */
	0xfff,				/* DMA burstsizes */
	1,				/* min effective DMA size */
	0xFFFFFFFF,			/* max DMA xfer size */
	0xFFFFFFFF,			/* segment boundary */
	1,				/* s/g list length */
	1,				/* granularity of device */
	0				/* DMA transfer flags */
};

static mac_callbacks_t vr_mac_callbacks = {
	MC_SETPROP|MC_GETPROP|MC_PROPINFO, /* Which callbacks are set */
	vr_mac_getstat,		/* Get the value of a statistic */
	vr_mac_start,		/* Start the device */
	vr_mac_stop,		/* Stop the device */
	vr_mac_set_promisc,	/* Enable or disable promiscuous mode */
	vr_mac_set_multicast,	/* Enable or disable a multicast addr */
	vr_mac_set_ether_addr,	/* Set the unicast MAC address */
	vr_mac_tx_enqueue_list,	/* Transmit a packet */
	NULL,
	NULL,			/* Process an unknown ioctl */
	NULL,			/* Get capability information */
	NULL,			/* Open the device */
	NULL,			/* Close the device */
	vr_mac_setprop,		/* Set properties of the device */
	vr_mac_getprop,		/* Get properties of the device */
	vr_mac_propinfo		/* Get properties attributes */
};

/*
 * Table with bugs and features for each incarnation of the card.
 */
static const chip_info_t vr_chip_info [] = {
	{
		0x0, 0x0,
		"VIA Rhine Fast Ethernet",
		(VR_BUG_NO_MEMIO),
		(VR_FEATURE_NONE)
	},
	{
		0x04, 0x21,
		"VIA VT86C100A Fast Ethernet",
		(VR_BUG_NEEDMODE2PCEROPT | VR_BUG_NO_TXQUEUEING |
		    VR_BUG_NEEDMODE10T | VR_BUG_TXALIGN | VR_BUG_NO_MEMIO |
		    VR_BUG_MIIPOLLSTOP),
		(VR_FEATURE_NONE)
	},
	{
		0x40, 0x41,
		"VIA VT6102-A Rhine II Fast Ethernet",
		(VR_BUG_NEEDMODE2PCEROPT),
		(VR_FEATURE_RX_PAUSE_CAP)
	},
	{
		0x42, 0x7f,
		"VIA VT6102-C Rhine II Fast Ethernet",
		(VR_BUG_NEEDMODE2PCEROPT),
		(VR_FEATURE_RX_PAUSE_CAP)
	},
	{
		0x80, 0x82,
		"VIA VT6105-A Rhine III Fast Ethernet",
		(VR_BUG_NONE),
		(VR_FEATURE_RX_PAUSE_CAP | VR_FEATURE_TX_PAUSE_CAP)
	},
	{
		0x83, 0x89,
		"VIA VT6105-B Rhine III Fast Ethernet",
		(VR_BUG_NONE),
		(VR_FEATURE_RX_PAUSE_CAP | VR_FEATURE_TX_PAUSE_CAP)
	},
	{
		0x8a, 0x8b,
		"VIA VT6105-LOM Rhine III Fast Ethernet",
		(VR_BUG_NONE),
		(VR_FEATURE_RX_PAUSE_CAP | VR_FEATURE_TX_PAUSE_CAP)
	},
	{
		0x8c, 0x8c,
		"VIA VT6107-A0 Rhine III Fast Ethernet",
		(VR_BUG_NONE),
		(VR_FEATURE_RX_PAUSE_CAP | VR_FEATURE_TX_PAUSE_CAP)
	},
	{
		0x8d, 0x8f,
		"VIA VT6107-A1 Rhine III Fast Ethernet",
		(VR_BUG_NONE),
		(VR_FEATURE_RX_PAUSE_CAP | VR_FEATURE_TX_PAUSE_CAP |
		    VR_FEATURE_MRDLNMULTIPLE)
	},
	{
		0x90, 0x93,
		"VIA VT6105M-A0 Rhine III Fast Ethernet Management Adapter",
		(VR_BUG_NONE),
		(VR_FEATURE_RX_PAUSE_CAP | VR_FEATURE_TX_PAUSE_CAP |
		    VR_FEATURE_TXCHKSUM | VR_FEATURE_RXCHKSUM |
		    VR_FEATURE_CAMSUPPORT | VR_FEATURE_VLANTAGGING |
		    VR_FEATURE_MIBCOUNTER)
	},
	{
		0x94, 0xff,
		"VIA VT6105M-B1 Rhine III Fast Ethernet Management Adapter",
		(VR_BUG_NONE),
		(VR_FEATURE_RX_PAUSE_CAP | VR_FEATURE_TX_PAUSE_CAP |
		    VR_FEATURE_TXCHKSUM | VR_FEATURE_RXCHKSUM |
		    VR_FEATURE_CAMSUPPORT | VR_FEATURE_VLANTAGGING |
		    VR_FEATURE_MIBCOUNTER)
	}
};

/*
 * Function prototypes
 */
static	vr_result_t	vr_add_intr(vr_t *vrp);
static	void		vr_remove_intr(vr_t *vrp);
static	int32_t		vr_cam_index(vr_t *vrp, const uint8_t *maddr);
static	uint32_t	ether_crc_be(const uint8_t *address);
static	void		vr_tx_enqueue_msg(vr_t *vrp, mblk_t *mp);
static	void		vr_log(vr_t *vrp, int level, const char *fmt, ...);
static	int		vr_resume(dev_info_t *devinfo);
static	int		vr_suspend(dev_info_t *devinfo);
static	vr_result_t	vr_bus_config(vr_t *vrp);
static	void		vr_bus_unconfig(vr_t *vrp);
static	void		vr_reset(vr_t *vrp);
static	int		vr_start(vr_t *vrp);
static	int		vr_stop(vr_t *vrp);
static	vr_result_t	vr_rings_init(vr_t *vrp);
static	void		vr_rings_fini(vr_t *vrp);
static	vr_result_t	vr_alloc_ring(vr_t *vrp, vr_ring_t *r, size_t n);
static	void		vr_free_ring(vr_ring_t *r, size_t n);
static	vr_result_t	vr_rxring_init(vr_t *vrp);
static	void		vr_rxring_fini(vr_t *vrp);
static	vr_result_t	vr_txring_init(vr_t *vrp);
static	void		vr_txring_fini(vr_t *vrp);
static	vr_result_t	vr_alloc_dmabuf(vr_t *vrp, vr_data_dma_t *dmap,
			    uint_t flags);
static	void		vr_free_dmabuf(vr_data_dma_t *dmap);
static	void		vr_param_init(vr_t *vrp);
static	mblk_t		*vr_receive(vr_t *vrp);
static	void		vr_tx_reclaim(vr_t *vrp);
static	void		vr_periodic(void *p);
static	void		vr_error(vr_t *vrp);
static	void		vr_phy_read(vr_t *vrp, int offset, uint16_t *value);
static	void		vr_phy_write(vr_t *vrp, int offset, uint16_t value);
static	void		vr_phy_autopoll_disable(vr_t *vrp);
static	void		vr_phy_autopoll_enable(vr_t *vrp);
static	void		vr_link_init(vr_t *vrp);
static	void		vr_link_state(vr_t *vrp);
static	void		vr_kstats_init(vr_t *vrp);
static	int		vr_update_kstats(kstat_t *ksp, int access);
static	void		vr_remove_kstats(vr_t *vrp);

static int
vr_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	vr_t		*vrp;
	mac_register_t	*macreg;

	if (cmd == DDI_RESUME)
		return (vr_resume(devinfo));
	else if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	/*
	 * Attach.
	 */
	vrp = kmem_zalloc(sizeof (vr_t), KM_SLEEP);
	ddi_set_driver_private(devinfo, vrp);
	vrp->devinfo = devinfo;

	/*
	 * Store the name+instance of the module.
	 */
	(void) snprintf(vrp->ifname, sizeof (vrp->ifname), "%s%d",
	    MODULENAME, ddi_get_instance(devinfo));

	/*
	 * Bus initialization.
	 */
	if (vr_bus_config(vrp) != VR_SUCCESS) {
		vr_log(vrp, CE_WARN, "vr_bus_config failed");
		goto fail0;
	}

	/*
	 * Initialize default parameters.
	 */
	vr_param_init(vrp);

	/*
	 * Setup the descriptor rings.
	 */
	if (vr_rings_init(vrp) != VR_SUCCESS) {
		vr_log(vrp, CE_WARN, "vr_rings_init failed");
		goto fail1;
	}

	/*
	 * Initialize kstats.
	 */
	vr_kstats_init(vrp);

	/*
	 * Add interrupt to the OS.
	 */
	if (vr_add_intr(vrp) != VR_SUCCESS) {
		vr_log(vrp, CE_WARN, "vr_add_intr failed in attach");
		goto fail3;
	}

	/*
	 * Add mutexes.
	 */
	mutex_init(&vrp->intrlock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(vrp->intr_pri));
	mutex_init(&vrp->oplock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&vrp->tx.lock, NULL, MUTEX_DRIVER, NULL);

	/*
	 * Enable interrupt.
	 */
	if (ddi_intr_enable(vrp->intr_hdl) != DDI_SUCCESS) {
		vr_log(vrp, CE_NOTE, "ddi_intr_enable failed");
		goto fail5;
	}

	/*
	 * Register with parent, mac.
	 */
	if ((macreg = mac_alloc(MAC_VERSION)) == NULL) {
		vr_log(vrp, CE_WARN, "mac_alloc failed in attach");
		goto fail6;
	}

	macreg->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macreg->m_driver = vrp;
	macreg->m_dip = devinfo;
	macreg->m_src_addr = vrp->vendor_ether_addr;
	macreg->m_callbacks = &vr_mac_callbacks;
	macreg->m_min_sdu = 0;
	macreg->m_max_sdu = ETHERMTU;
	macreg->m_margin = VLAN_TAGSZ;

	if (mac_register(macreg, &vrp->machdl) != 0) {
		vr_log(vrp, CE_WARN, "mac_register failed in attach");
		goto fail7;
	}
	mac_free(macreg);
	return (DDI_SUCCESS);

fail7:
	mac_free(macreg);
fail6:
	(void) ddi_intr_disable(vrp->intr_hdl);
fail5:
	mutex_destroy(&vrp->tx.lock);
	mutex_destroy(&vrp->oplock);
	mutex_destroy(&vrp->intrlock);
	vr_remove_intr(vrp);
fail3:
	vr_remove_kstats(vrp);
fail2:
	vr_rings_fini(vrp);
fail1:
	vr_bus_unconfig(vrp);
fail0:
	kmem_free(vrp, sizeof (vr_t));
	return (DDI_FAILURE);
}

static int
vr_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{
	vr_t		*vrp;

	vrp = ddi_get_driver_private(devinfo);

	if (cmd == DDI_SUSPEND)
		return (vr_suspend(devinfo));
	else if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	if (vrp->chip.state == CHIPSTATE_RUNNING)
		return (DDI_FAILURE);

	/*
	 * Try to un-register from the MAC layer.
	 */
	if (mac_unregister(vrp->machdl) != 0)
		return (DDI_FAILURE);

	(void) ddi_intr_disable(vrp->intr_hdl);
	vr_remove_intr(vrp);
	mutex_destroy(&vrp->tx.lock);
	mutex_destroy(&vrp->oplock);
	mutex_destroy(&vrp->intrlock);
	vr_remove_kstats(vrp);
	vr_rings_fini(vrp);
	vr_bus_unconfig(vrp);
	kmem_free(vrp, sizeof (vr_t));
	return (DDI_SUCCESS);
}

/*
 * quiesce the card for fast reboot.
 */
int
vr_quiesce(dev_info_t *dev_info)
{
	vr_t	*vrp;

	vrp = (vr_t *)ddi_get_driver_private(dev_info);

	/*
	 * Stop interrupts.
	 */
	VR_PUT16(vrp->acc_reg, VR_ICR0, 0);
	VR_PUT8(vrp->acc_reg, VR_ICR1, 0);

	/*
	 * Stop DMA.
	 */
	VR_PUT8(vrp->acc_reg, VR_CTRL0, VR_CTRL0_DMA_STOP);
	return (DDI_SUCCESS);
}

/*
 * Add an interrupt for our device to the OS.
 */
static vr_result_t
vr_add_intr(vr_t *vrp)
{
	int	nintrs;
	int	rc;

	rc = ddi_intr_alloc(vrp->devinfo, &vrp->intr_hdl,
	    DDI_INTR_TYPE_FIXED,	/* type */
	    0,			/* number */
	    1,			/* count */
	    &nintrs,		/* actualp */
	    DDI_INTR_ALLOC_STRICT);

	if (rc != DDI_SUCCESS) {
		vr_log(vrp, CE_NOTE, "ddi_intr_alloc failed: %d", rc);
		return (VR_FAILURE);
	}

	rc = ddi_intr_add_handler(vrp->intr_hdl, vr_intr, vrp, NULL);
	if (rc != DDI_SUCCESS) {
		vr_log(vrp, CE_NOTE, "ddi_intr_add_handler failed");
		if (ddi_intr_free(vrp->intr_hdl) != DDI_SUCCESS)
			vr_log(vrp, CE_NOTE, "ddi_intr_free failed");
		return (VR_FAILURE);
	}

	rc = ddi_intr_get_pri(vrp->intr_hdl, &vrp->intr_pri);
	if (rc != DDI_SUCCESS) {
		vr_log(vrp, CE_NOTE, "ddi_intr_get_pri failed");
		if (ddi_intr_remove_handler(vrp->intr_hdl) != DDI_SUCCESS)
			vr_log(vrp, CE_NOTE, "ddi_intr_remove_handler failed");

		if (ddi_intr_free(vrp->intr_hdl) != DDI_SUCCESS)
			vr_log(vrp, CE_NOTE, "ddi_intr_free failed");

		return (VR_FAILURE);
	}
	return (VR_SUCCESS);
}

/*
 * Remove our interrupt from the OS.
 */
static void
vr_remove_intr(vr_t *vrp)
{
	if (ddi_intr_remove_handler(vrp->intr_hdl) != DDI_SUCCESS)
		vr_log(vrp, CE_NOTE, "ddi_intr_remove_handler failed");

	if (ddi_intr_free(vrp->intr_hdl) != DDI_SUCCESS)
		vr_log(vrp, CE_NOTE, "ddi_intr_free failed");
}

/*
 * Resume operation after suspend.
 */
static int
vr_resume(dev_info_t *devinfo)
{
	vr_t *vrp;

	vrp = (vr_t *)ddi_get_driver_private(devinfo);
	mutex_enter(&vrp->oplock);
	if (vrp->chip.state == CHIPSTATE_SUSPENDED_RUNNING)
		(void) vr_start(vrp);
	mutex_exit(&vrp->oplock);
	return (DDI_SUCCESS);
}

/*
 * Suspend operation.
 */
static int
vr_suspend(dev_info_t *devinfo)
{
	vr_t *vrp;

	vrp = (vr_t *)ddi_get_driver_private(devinfo);
	mutex_enter(&vrp->oplock);
	if (vrp->chip.state == CHIPSTATE_RUNNING) {
		(void) vr_stop(vrp);
		vrp->chip.state = CHIPSTATE_SUSPENDED_RUNNING;
	}
	mutex_exit(&vrp->oplock);
	return (DDI_SUCCESS);
}

/*
 * Initial bus- and device configuration during attach(9E).
 */
static vr_result_t
vr_bus_config(vr_t *vrp)
{
	uint32_t		addr;
	int			n, nsets, rc;
	uint_t			elem;
	pci_regspec_t		*regs;

	/*
	 * Get the reg property which describes the various access methods.
	 */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, vrp->devinfo,
	    0, "reg", (int **)&regs, &elem) != DDI_PROP_SUCCESS) {
		vr_log(vrp, CE_WARN, "Can't get reg property");
		return (VR_FAILURE);
	}
	nsets = (elem * sizeof (uint_t)) / sizeof (pci_regspec_t);

	/*
	 * Setup access to all available sets.
	 */
	vrp->nsets = nsets;
	vrp->regset = kmem_zalloc(nsets * sizeof (vr_acc_t), KM_SLEEP);
	for (n = 0; n < nsets; n++) {
		rc = ddi_regs_map_setup(vrp->devinfo, n,
		    &vrp->regset[n].addr, 0, 0,
		    &vr_dev_dma_accattr,
		    &vrp->regset[n].hdl);
		if (rc != DDI_SUCCESS) {
			vr_log(vrp, CE_NOTE,
			    "Setup of register set %d failed", n);
			while (--n >= 0)
				ddi_regs_map_free(&vrp->regset[n].hdl);
			kmem_free(vrp->regset, nsets * sizeof (vr_acc_t));
			ddi_prop_free(regs);
			return (VR_FAILURE);
		}
		bcopy(&regs[n], &vrp->regset[n].reg, sizeof (pci_regspec_t));
	}
	ddi_prop_free(regs);

	/*
	 * Assign type-named pointers to the register sets.
	 */
	for (n = 0; n < nsets; n++) {
		addr = vrp->regset[n].reg.pci_phys_hi & PCI_REG_ADDR_M;
		if (addr == PCI_ADDR_CONFIG && vrp->acc_cfg == NULL)
			vrp->acc_cfg = &vrp->regset[n];
		else if (addr == PCI_ADDR_IO && vrp->acc_io == NULL)
			vrp->acc_io = &vrp->regset[n];
		else if (addr == PCI_ADDR_MEM32 && vrp->acc_mem == NULL)
			vrp->acc_mem = &vrp->regset[n];
	}

	/*
	 * Assure there is one of each type.
	 */
	if (vrp->acc_cfg == NULL ||
	    vrp->acc_io == NULL ||
	    vrp->acc_mem == NULL) {
		for (n = 0; n < nsets; n++)
			ddi_regs_map_free(&vrp->regset[n].hdl);
		kmem_free(vrp->regset, nsets * sizeof (vr_acc_t));
		vr_log(vrp, CE_WARN,
		    "Config-, I/O- and memory sets not available");
		return (VR_FAILURE);
	}

	/*
	 * Store vendor/device/revision.
	 */
	vrp->chip.vendor = VR_GET16(vrp->acc_cfg, PCI_CONF_VENID);
	vrp->chip.device = VR_GET16(vrp->acc_cfg, PCI_CONF_DEVID);
	vrp->chip.revision = VR_GET16(vrp->acc_cfg, PCI_CONF_REVID);

	/*
	 * Copy the matching chip_info_t structure.
	 */
	elem = sizeof (vr_chip_info) / sizeof (chip_info_t);
	for (n = 0; n < elem; n++) {
		if (vrp->chip.revision >= vr_chip_info[n].revmin &&
		    vrp->chip.revision <= vr_chip_info[n].revmax) {
			bcopy((void*)&vr_chip_info[n],
			    (void*)&vrp->chip.info,
			    sizeof (chip_info_t));
			break;
		}
	}

	/*
	 * If we didn't find a chip_info_t for this card, copy the first
	 * entry of the info structures. This is a generic Rhine whith no
	 * bugs and no features.
	 */
	if (vrp->chip.info.name == NULL) {
		bcopy((void*)&vr_chip_info[0],
		    (void*) &vrp->chip.info,
		    sizeof (chip_info_t));
	}

	/*
	 * Tell what is found.
	 */
	vr_log(vrp, CE_NOTE, "pci%d,%d,%d: %s, revision 0x%0x",
	    PCI_REG_BUS_G(vrp->acc_cfg->reg.pci_phys_hi),
	    PCI_REG_DEV_G(vrp->acc_cfg->reg.pci_phys_hi),
	    PCI_REG_FUNC_G(vrp->acc_cfg->reg.pci_phys_hi),
	    vrp->chip.info.name,
	    vrp->chip.revision);

	/*
	 * Assure that the device is prepared for memory space accesses
	 * This should be the default as the device advertises memory
	 * access in it's BAR's. However, my VT6102 on a EPIA CL board doesn't
	 * and thus we explicetely enable it.
	 */
	VR_SETBIT8(vrp->acc_io, VR_CFGD, VR_CFGD_MMIOEN);

	/*
	 * Setup a handle for regular usage, prefer memory space accesses.
	 */
	if (vrp->acc_mem != NULL &&
	    (vrp->chip.info.bugs & VR_BUG_NO_MEMIO) == 0)
		vrp->acc_reg = vrp->acc_mem;
	else
		vrp->acc_reg = vrp->acc_io;

	/*
	 * Store the vendor's MAC address.
	 */
	for (n = 0; n < ETHERADDRL; n++) {
		vrp->vendor_ether_addr[n] = VR_GET8(vrp->acc_reg,
		    VR_ETHERADDR + n);
	}
	return (VR_SUCCESS);
}

static void
vr_bus_unconfig(vr_t *vrp)
{
	uint_t	n;

	/*
	 * Free the register access handles.
	 */
	for (n = 0; n < vrp->nsets; n++)
		ddi_regs_map_free(&vrp->regset[n].hdl);
	kmem_free(vrp->regset, vrp->nsets * sizeof (vr_acc_t));
}

/*
 * Initialize parameter structures.
 */
static void
vr_param_init(vr_t *vrp)
{
	/*
	 * Initialize default link configuration parameters.
	 */
	vrp->param.an_en = VR_LINK_AUTONEG_ON;
	vrp->param.anadv_en = 1; /* Select 802.3 autonegotiation */
	vrp->param.anadv_en |= MII_ABILITY_100BASE_T4;
	vrp->param.anadv_en |= MII_ABILITY_100BASE_TX_FD;
	vrp->param.anadv_en |= MII_ABILITY_100BASE_TX;
	vrp->param.anadv_en |= MII_ABILITY_10BASE_T_FD;
	vrp->param.anadv_en |= MII_ABILITY_10BASE_T;
	/* Not a PHY ability, but advertised on behalf of MAC */
	vrp->param.anadv_en |= MII_ABILITY_PAUSE;
	vrp->param.mtu = ETHERMTU;

	/*
	 * Store the PHY identity.
	 */
	vr_phy_read(vrp, MII_PHYIDH, &vrp->chip.mii.identh);
	vr_phy_read(vrp, MII_PHYIDL, &vrp->chip.mii.identl);

	/*
	 * Clear incapabilities imposed by PHY in phymask.
	 */
	vrp->param.an_phymask = vrp->param.anadv_en;
	vr_phy_read(vrp, MII_STATUS, &vrp->chip.mii.status);
	if ((vrp->chip.mii.status & MII_STATUS_10) == 0)
		vrp->param.an_phymask &= ~MII_ABILITY_10BASE_T;

	if ((vrp->chip.mii.status & MII_STATUS_10_FD) == 0)
		vrp->param.an_phymask &= ~MII_ABILITY_10BASE_T_FD;

	if ((vrp->chip.mii.status & MII_STATUS_100_BASEX) == 0)
		vrp->param.an_phymask &= ~MII_ABILITY_100BASE_TX;

	if ((vrp->chip.mii.status & MII_STATUS_100_BASEX_FD) == 0)
		vrp->param.an_phymask &= ~MII_ABILITY_100BASE_TX_FD;

	if ((vrp->chip.mii.status & MII_STATUS_100_BASE_T4) == 0)
		vrp->param.an_phymask &= ~MII_ABILITY_100BASE_T4;

	/*
	 * Clear incapabilities imposed by MAC in macmask
	 * Note that flowcontrol (FCS?) is never masked. All of our adapters
	 * have the ability to honor incoming pause frames. Only the newer can
	 * transmit pause frames. Since there's no asym flowcontrol in 100Mbit
	 * Ethernet, we always advertise (symmetric) pause.
	 */
	vrp->param.an_macmask = vrp->param.anadv_en;

	/*
	 * Advertised capabilities is enabled minus incapable.
	 */
	vrp->chip.mii.anadv = vrp->param.anadv_en &
	    (vrp->param.an_phymask & vrp->param.an_macmask);

	/*
	 * Ensure that autoneg of the PHY matches our default.
	 */
	if (vrp->param.an_en == VR_LINK_AUTONEG_ON)
		vrp->chip.mii.control = MII_CONTROL_ANE;
	else
		vrp->chip.mii.control =
		    (MII_CONTROL_100MB | MII_CONTROL_FDUPLEX);
}

/*
 * Setup the descriptor rings.
 */
static vr_result_t
vr_rings_init(vr_t *vrp)
{

	vrp->rx.ndesc = VR_RX_N_DESC;
	vrp->tx.ndesc = VR_TX_N_DESC;

	/*
	 * Create a ring for receive.
	 */
	if (vr_alloc_ring(vrp, &vrp->rxring, vrp->rx.ndesc) != VR_SUCCESS)
		return (VR_FAILURE);

	/*
	 * Create a ring for transmit.
	 */
	if (vr_alloc_ring(vrp, &vrp->txring, vrp->tx.ndesc) != VR_SUCCESS) {
		vr_free_ring(&vrp->rxring, vrp->rx.ndesc);
		return (VR_FAILURE);
	}

	vrp->rx.ring = vrp->rxring.desc;
	vrp->tx.ring = vrp->txring.desc;
	return (VR_SUCCESS);
}

static void
vr_rings_fini(vr_t *vrp)
{
	vr_free_ring(&vrp->rxring, vrp->rx.ndesc);
	vr_free_ring(&vrp->txring, vrp->tx.ndesc);
}

/*
 * Allocate a descriptor ring
 * The number of descriptor entries must fit in a single page so that the
 * whole ring fits in one consequtive space.
 *  i386:  4K page / 16 byte descriptor = 256 entries
 *  sparc: 8K page / 16 byte descriptor = 512 entries
 */
static vr_result_t
vr_alloc_ring(vr_t *vrp, vr_ring_t *ring, size_t n)
{
	ddi_dma_cookie_t	desc_dma_cookie;
	uint_t			desc_cookiecnt;
	int			i, rc;
	size_t			rbytes;

	/*
	 * Allocate a DMA handle for the chip descriptors.
	 */
	rc = ddi_dma_alloc_handle(vrp->devinfo,
	    &vr_dev_dma_attr,
	    DDI_DMA_SLEEP,
	    NULL,
	    &ring->handle);

	if (rc != DDI_SUCCESS) {
		vr_log(vrp, CE_WARN,
		    "ddi_dma_alloc_handle in vr_alloc_ring failed.");
		return (VR_FAILURE);
	}

	/*
	 * Allocate memory for the chip descriptors.
	 */
	rc = ddi_dma_mem_alloc(ring->handle,
	    n * sizeof (vr_chip_desc_t),
	    &vr_dev_dma_accattr,
	    DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP,
	    NULL,
	    (caddr_t *)&ring->cdesc,
	    &rbytes,
	    &ring->acchdl);

	if (rc != DDI_SUCCESS) {
		vr_log(vrp, CE_WARN,
		    "ddi_dma_mem_alloc in vr_alloc_ring failed.");
		ddi_dma_free_handle(&ring->handle);
		return (VR_FAILURE);
	}

	/*
	 * Map the descriptor memory.
	 */
	rc = ddi_dma_addr_bind_handle(ring->handle,
	    NULL,
	    (caddr_t)ring->cdesc,
	    rbytes,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP,
	    NULL,
	    &desc_dma_cookie,
	    &desc_cookiecnt);

	if (rc != DDI_DMA_MAPPED || desc_cookiecnt > 1) {
		vr_log(vrp, CE_WARN,
		    "ddi_dma_addr_bind_handle in vr_alloc_ring failed: "
		    "rc = %d, cookiecnt = %d", rc, desc_cookiecnt);
		ddi_dma_mem_free(&ring->acchdl);
		ddi_dma_free_handle(&ring->handle);
		return (VR_FAILURE);
	}
	ring->cdesc_paddr = desc_dma_cookie.dmac_address;

	/*
	 * Allocate memory for the host descriptor ring.
	 */
	ring->desc =
	    (vr_desc_t *)kmem_zalloc(n * sizeof (vr_desc_t), KM_SLEEP);

	/*
	 * Interlink the descriptors and connect host- to chip descriptors.
	 */
	for (i = 0; i < n; i++) {
		/*
		 * Connect the host descriptor to a chip descriptor.
		 */
		ring->desc[i].cdesc = &ring->cdesc[i];

		/*
		 * Store the DMA address and offset in the descriptor
		 * Offset is for ddi_dma_sync() and paddr is for ddi_get/-put().
		 */
		ring->desc[i].offset = i * sizeof (vr_chip_desc_t);
		ring->desc[i].paddr = ring->cdesc_paddr + ring->desc[i].offset;

		/*
		 * Link the previous descriptor to this one.
		 */
		if (i > 0) {
			/* Host */
			ring->desc[i-1].next = &ring->desc[i];

			/* Chip */
			ddi_put32(ring->acchdl,
			    &ring->cdesc[i-1].next,
			    ring->desc[i].paddr);
		}
	}

	/*
	 * Make rings out of this list by pointing last to first.
	 */
	i = n - 1;
	ring->desc[i].next = &ring->desc[0];
	ddi_put32(ring->acchdl, &ring->cdesc[i].next, ring->desc[0].paddr);
	return (VR_SUCCESS);
}

/*
 * Free the memory allocated for a ring.
 */
static void
vr_free_ring(vr_ring_t *r, size_t n)
{
	/*
	 * Unmap and free the chip descriptors.
	 */
	(void) ddi_dma_unbind_handle(r->handle);
	ddi_dma_mem_free(&r->acchdl);
	ddi_dma_free_handle(&r->handle);

	/*
	 * Free the memory for storing host descriptors
	 */
	kmem_free(r->desc, n * sizeof (vr_desc_t));
}

/*
 * Initialize the receive ring.
 */
static vr_result_t
vr_rxring_init(vr_t *vrp)
{
	int		i, rc;
	vr_desc_t	*rp;

	/*
	 * Set the read pointer at the start of the ring.
	 */
	vrp->rx.rp = &vrp->rx.ring[0];

	/*
	 * Assign a DMA buffer to each receive descriptor.
	 */
	for (i = 0; i < vrp->rx.ndesc; i++) {
		rp = &vrp->rx.ring[i];
		rc = vr_alloc_dmabuf(vrp,
		    &vrp->rx.ring[i].dmabuf,
		    DDI_DMA_STREAMING | DDI_DMA_READ);

		if (rc != VR_SUCCESS) {
			while (--i >= 0)
				vr_free_dmabuf(&vrp->rx.ring[i].dmabuf);
			return (VR_FAILURE);
		}

		/*
		 * Store the address of the dma buffer in the chip descriptor
		 */
		ddi_put32(vrp->rxring.acchdl,
		    &rp->cdesc->data,
		    rp->dmabuf.paddr);

		/*
		 * Put the buffer length in the chip descriptor. Ensure that
		 * length fits in the 11 bits of stat1 (2047/0x7FF)
		 */
		ddi_put32(vrp->rxring.acchdl, &rp->cdesc->stat1,
		    MIN(VR_MAX_PKTSZ, rp->dmabuf.bufsz));

		/*
		 * Set descriptor ownership to the card
		 */
		ddi_put32(vrp->rxring.acchdl, &rp->cdesc->stat0, VR_RDES0_OWN);

		/*
		 * Sync the descriptor with main memory
		 */
		(void) ddi_dma_sync(vrp->rxring.handle, rp->offset,
		    sizeof (vr_chip_desc_t), DDI_DMA_SYNC_FORDEV);
	}
	return (VR_SUCCESS);
}

/*
 * Free the DMA buffers assigned to the receive ring.
 */
static void
vr_rxring_fini(vr_t *vrp)
{
	int		i;

	for (i = 0; i < vrp->rx.ndesc; i++)
		vr_free_dmabuf(&vrp->rx.ring[i].dmabuf);
}

static vr_result_t
vr_txring_init(vr_t *vrp)
{
	vr_desc_t		*wp;
	int			i, rc;

	/*
	 * Set the write- and claim pointer.
	 */
	vrp->tx.wp = &vrp->tx.ring[0];
	vrp->tx.cp = &vrp->tx.ring[0];

	/*
	 * (Re)set the TX bookkeeping.
	 */
	vrp->tx.stallticks = 0;
	vrp->tx.resched = 0;

	/*
	 * Every transmit decreases nfree. Every reclaim increases nfree.
	 */
	vrp->tx.nfree = vrp->tx.ndesc;

	/*
	 * Attach a DMA buffer to each transmit descriptor.
	 */
	for (i = 0; i < vrp->tx.ndesc; i++) {
		rc = vr_alloc_dmabuf(vrp,
		    &vrp->tx.ring[i].dmabuf,
		    DDI_DMA_STREAMING | DDI_DMA_WRITE);

		if (rc != VR_SUCCESS) {
			while (--i >= 0)
				vr_free_dmabuf(&vrp->tx.ring[i].dmabuf);
			return (VR_FAILURE);
		}
	}

	/*
	 * Init & sync the TX descriptors so the device sees a valid ring.
	 */
	for (i = 0; i < vrp->tx.ndesc; i++) {
		wp = &vrp->tx.ring[i];
		ddi_put32(vrp->txring.acchdl, &wp->cdesc->stat0, 0);
		ddi_put32(vrp->txring.acchdl, &wp->cdesc->stat1, 0);
		ddi_put32(vrp->txring.acchdl, &wp->cdesc->data,
		    wp->dmabuf.paddr);
		(void) ddi_dma_sync(vrp->txring.handle, wp->offset,
		    sizeof (vr_chip_desc_t),
		    DDI_DMA_SYNC_FORDEV);
	}
	return (VR_SUCCESS);
}

/*
 * Free the DMA buffers attached to the TX ring.
 */
static void
vr_txring_fini(vr_t *vrp)
{
	int		i;

	/*
	 * Free the DMA buffers attached to the TX ring
	 */
	for (i = 0; i < vrp->tx.ndesc; i++)
		vr_free_dmabuf(&vrp->tx.ring[i].dmabuf);
}

/*
 * Allocate a DMA buffer.
 */
static vr_result_t
vr_alloc_dmabuf(vr_t *vrp, vr_data_dma_t *dmap, uint_t dmaflags)
{
	ddi_dma_cookie_t	dma_cookie;
	uint_t			cookiecnt;
	int			rc;

	/*
	 * Allocate a DMA handle for the buffer
	 */
	rc = ddi_dma_alloc_handle(vrp->devinfo,
	    &vr_data_dma_attr,
	    DDI_DMA_DONTWAIT, NULL,
	    &dmap->handle);

	if (rc != DDI_SUCCESS) {
		vr_log(vrp, CE_WARN,
		    "ddi_dma_alloc_handle failed in vr_alloc_dmabuf");
		return (VR_FAILURE);
	}

	/*
	 * Allocate the buffer
	 * The allocated buffer is aligned on 2K boundary. This ensures that
	 * a 1500 byte frame never cross a page boundary and thus that the DMA
	 * mapping can be established in 1 fragment.
	 */
	rc = ddi_dma_mem_alloc(dmap->handle,
	    VR_DMABUFSZ,
	    &vr_data_dma_accattr,
	    DDI_DMA_RDWR | DDI_DMA_STREAMING,
	    DDI_DMA_DONTWAIT, NULL,
	    &dmap->buf,
	    &dmap->bufsz,
	    &dmap->acchdl);

	if (rc != DDI_SUCCESS) {
		vr_log(vrp, CE_WARN,
		    "ddi_dma_mem_alloc failed in vr_alloc_dmabuf");
		ddi_dma_free_handle(&dmap->handle);
		return (VR_FAILURE);
	}

	/*
	 * Map the memory
	 */
	rc = ddi_dma_addr_bind_handle(dmap->handle,
	    NULL,
	    (caddr_t)dmap->buf,
	    dmap->bufsz,
	    dmaflags,
	    DDI_DMA_DONTWAIT,
	    NULL,
	    &dma_cookie,
	    &cookiecnt);

	/*
	 * The cookiecount should never > 1 because we requested 2K alignment
	 */
	if (rc != DDI_DMA_MAPPED || cookiecnt > 1) {
		vr_log(vrp, CE_WARN,
		    "dma_addr_bind_handle failed in vr_alloc_dmabuf: "
		    "rc = %d, cookiecnt = %d", rc, cookiecnt);
		ddi_dma_mem_free(&dmap->acchdl);
		ddi_dma_free_handle(&dmap->handle);
		return (VR_FAILURE);
	}
	dmap->paddr = dma_cookie.dmac_address;
	return (VR_SUCCESS);
}

/*
 * Destroy a DMA buffer.
 */
static void
vr_free_dmabuf(vr_data_dma_t *dmap)
{
	(void) ddi_dma_unbind_handle(dmap->handle);
	ddi_dma_mem_free(&dmap->acchdl);
	ddi_dma_free_handle(&dmap->handle);
}

/*
 * Interrupt service routine
 * When our vector is shared with another device, av_dispatch_autovect calls
 * all service routines for the vector until *none* of them return claimed
 * That means that, when sharing vectors, this routine is called at least
 * twice for each interrupt.
 */
uint_t
vr_intr(caddr_t arg1, caddr_t arg2)
{
	vr_t		*vrp;
	uint16_t	status;
	mblk_t		*lp = NULL;
	uint32_t	tx_resched;
	uint32_t	link_change;

	tx_resched = 0;
	link_change = 0;
	vrp = (void *)arg1;
	_NOTE(ARGUNUSED(arg2))

	mutex_enter(&vrp->intrlock);
	/*
	 * If the driver is not in running state it is not our interrupt.
	 * Shared interrupts can end up here without us being started.
	 */
	if (vrp->chip.state != CHIPSTATE_RUNNING) {
		mutex_exit(&vrp->intrlock);
		return (DDI_INTR_UNCLAIMED);
	}

	/*
	 * Read the status register to see if the interrupt is from our device
	 * This read also ensures that posted writes are brought to main memory.
	 */
	status = VR_GET16(vrp->acc_reg, VR_ISR0) & VR_ICR0_CFG;
	if (status == 0) {
		/*
		 * Status contains no configured interrupts
		 * The interrupt was not generated by our device.
		 */
		vrp->stats.intr_unclaimed++;
		mutex_exit(&vrp->intrlock);
		return (DDI_INTR_UNCLAIMED);
	}
	vrp->stats.intr_claimed++;

	/*
	 * Acknowledge the event(s) that caused interruption.
	 */
	VR_PUT16(vrp->acc_reg, VR_ISR0, status);

	/*
	 * Receive completion.
	 */
	if ((status & (VR_ISR0_RX_DONE | VR_ISR_RX_ERR_BITS)) != 0) {
		/*
		 * Received some packets.
		 */
		lp = vr_receive(vrp);

		/*
		 * DMA stops after a conflict in the FIFO.
		 */
		if ((status & VR_ISR_RX_ERR_BITS) != 0)
			VR_PUT8(vrp->acc_reg, VR_CTRL0, VR_CTRL0_DMA_GO);
		status &= ~(VR_ISR0_RX_DONE | VR_ISR_RX_ERR_BITS);
	}

	/*
	 * Transmit completion.
	 */
	if ((status & (VR_ISR0_TX_DONE | VR_ISR_TX_ERR_BITS)) != 0) {
		/*
		 * Card done with transmitting some packets
		 * TX_DONE is generated 3 times per ring but it appears
		 * more often because it is also set when an RX_DONE
		 * interrupt is generated.
		 */
		mutex_enter(&vrp->tx.lock);
		vr_tx_reclaim(vrp);
		tx_resched = vrp->tx.resched;
		vrp->tx.resched = 0;
		mutex_exit(&vrp->tx.lock);
		status &= ~(VR_ISR0_TX_DONE | VR_ISR_TX_ERR_BITS);
	}

	/*
	 * Link status change.
	 */
	if ((status & VR_ICR0_LINKSTATUS) != 0) {
		/*
		 * Get new link state and inform the mac layer.
		 */
		mutex_enter(&vrp->oplock);
		mutex_enter(&vrp->tx.lock);
		vr_link_state(vrp);
		mutex_exit(&vrp->tx.lock);
		mutex_exit(&vrp->oplock);
		status &= ~VR_ICR0_LINKSTATUS;
		vrp->stats.linkchanges++;
		link_change = 1;
	}

	/*
	 * Bus error.
	 */
	if ((status & VR_ISR0_BUSERR) != 0) {
		vr_log(vrp, CE_WARN, "bus error occured");
		vrp->reset = 1;
		status &= ~VR_ISR0_BUSERR;
	}

	/*
	 * We must have handled all things here.
	 */
	ASSERT(status == 0);
	mutex_exit(&vrp->intrlock);

	/*
	 * Reset the device if requested
	 * The request can come from the periodic tx check or from the interrupt
	 * status.
	 */
	if (vrp->reset != 0) {
		vr_error(vrp);
		vrp->reset = 0;
	}

	/*
	 * Pass up the list with received packets.
	 */
	if (lp != NULL)
		mac_rx(vrp->machdl, 0, lp);

	/*
	 * Inform the upper layer on the linkstatus if there was a change.
	 */
	if (link_change != 0)
		mac_link_update(vrp->machdl,
		    (link_state_t)vrp->chip.link.state);
	/*
	 * Restart transmissions if we were waiting for tx descriptors.
	 */
	if (tx_resched == 1)
		mac_tx_update(vrp->machdl);

	/*
	 * Read something from the card to ensure that all of our configuration
	 * writes are delivered to the device before the interrupt is ended.
	 */
	(void) VR_GET8(vrp->acc_reg, VR_ETHERADDR);
	return (DDI_INTR_CLAIMED);
}

/*
 * Respond to an unforseen situation by resetting the card and our bookkeeping.
 */
static void
vr_error(vr_t *vrp)
{
	vr_log(vrp, CE_WARN, "resetting MAC.");
	mutex_enter(&vrp->intrlock);
	mutex_enter(&vrp->oplock);
	mutex_enter(&vrp->tx.lock);
	(void) vr_stop(vrp);
	vr_reset(vrp);
	(void) vr_start(vrp);
	mutex_exit(&vrp->tx.lock);
	mutex_exit(&vrp->oplock);
	mutex_exit(&vrp->intrlock);
	vrp->stats.resets++;
}

/*
 * Collect received packets in a list.
 */
static mblk_t *
vr_receive(vr_t *vrp)
{
	mblk_t			*lp, *mp, *np;
	vr_desc_t		*rxp;
	vr_data_dma_t		*dmap;
	uint32_t		pklen;
	uint32_t		rxstat0;
	uint32_t		n;

	lp = NULL;
	n = 0;
	for (rxp = vrp->rx.rp; ; rxp = rxp->next, n++) {
		/*
		 * Sync the descriptor before looking at it.
		 */
		(void) ddi_dma_sync(vrp->rxring.handle, rxp->offset,
		    sizeof (vr_chip_desc_t), DDI_DMA_SYNC_FORKERNEL);

		/*
		 * Get the status from the descriptor.
		 */
		rxstat0 = ddi_get32(vrp->rxring.acchdl, &rxp->cdesc->stat0);

		/*
		 * We're done if the descriptor is owned by the card.
		 */
		if ((rxstat0 & VR_RDES0_OWN) != 0)
			break;
		else if ((rxstat0 & VR_RDES0_RXOK) != 0) {
			/*
			 * Received a good packet
			 */
			dmap = &rxp->dmabuf;
			pklen = (rxstat0 >> 16) - ETHERFCSL;

			/*
			 * Sync the data.
			 */
			(void) ddi_dma_sync(dmap->handle, 0,
			    pklen, DDI_DMA_SYNC_FORKERNEL);

			/*
			 * Send a new copied message upstream.
			 */
			np = allocb(pklen, 0);
			if (np != NULL) {
				bcopy(dmap->buf, np->b_rptr, pklen);
				np->b_wptr = np->b_rptr + pklen;

				vrp->stats.mac_stat_ipackets++;
				vrp->stats.mac_stat_rbytes += pklen;

				if ((rxstat0 & VR_RDES0_BAR) != 0)
					vrp->stats.mac_stat_brdcstrcv++;
				else if ((rxstat0 & VR_RDES0_MAR) != 0)
					vrp->stats.mac_stat_multircv++;

				/*
				 * Link this packet in the list.
				 */
				np->b_next = NULL;
				if (lp == NULL)
					lp = mp = np;
				else {
					mp->b_next = np;
					mp = np;
				}
			} else {
				vrp->stats.allocbfail++;
				vrp->stats.mac_stat_norcvbuf++;
			}

		} else {
			/*
			 * Received with errors.
			 */
			vrp->stats.mac_stat_ierrors++;
			if ((rxstat0 & VR_RDES0_FAE) != 0)
				vrp->stats.ether_stat_align_errors++;
			if ((rxstat0 & VR_RDES0_CRCERR) != 0)
				vrp->stats.ether_stat_fcs_errors++;
			if ((rxstat0 & VR_RDES0_LONG) != 0)
				vrp->stats.ether_stat_toolong_errors++;
			if ((rxstat0 & VR_RDES0_RUNT) != 0)
				vrp->stats.ether_stat_tooshort_errors++;
			if ((rxstat0 & VR_RDES0_FOV) != 0)
				vrp->stats.mac_stat_overflows++;
		}

		/*
		 * Reset descriptor ownership to the MAC.
		 */
		ddi_put32(vrp->rxring.acchdl,
		    &rxp->cdesc->stat0,
		    VR_RDES0_OWN);
		(void) ddi_dma_sync(vrp->rxring.handle,
		    rxp->offset,
		    sizeof (vr_chip_desc_t),
		    DDI_DMA_SYNC_FORDEV);
	}
	vrp->rx.rp = rxp;

	/*
	 * If we do flowcontrol and if the card can transmit pause frames,
	 * increment the "available receive descriptors" register.
	 */
	if (n > 0 && vrp->chip.link.flowctrl == VR_PAUSE_BIDIRECTIONAL) {
		/*
		 * Whenever the card moves a fragment to host memory it
		 * decrements the RXBUFCOUNT register. If the value in the
		 * register reaches a low watermark, the card transmits a pause
		 * frame. If the value in this register reaches a high
		 * watermark, the card sends a "cancel pause" frame
		 *
		 * Non-zero values written to this byte register are added
		 * by the chip to the register's contents, so we must write
		 * the number of descriptors free'd.
		 */
		VR_PUT8(vrp->acc_reg, VR_FCR0_RXBUFCOUNT, MIN(n, 0xFF));
	}
	return (lp);
}

/*
 * Enqueue a list of packets for transmission
 * Return the packets not transmitted.
 */
mblk_t *
vr_mac_tx_enqueue_list(void *p, mblk_t *mp)
{
	vr_t		*vrp;
	mblk_t		*nextp;

	vrp = (vr_t *)p;
	mutex_enter(&vrp->tx.lock);
	do {
		if (vrp->tx.nfree == 0) {
			vrp->stats.ether_stat_defer_xmts++;
			vrp->tx.resched = 1;
			break;
		}
		nextp = mp->b_next;
		mp->b_next = mp->b_prev = NULL;
		vr_tx_enqueue_msg(vrp, mp);
		mp = nextp;
		vrp->tx.nfree--;
	} while (mp != NULL);
	mutex_exit(&vrp->tx.lock);

	/*
	 * Tell the chip to poll the TX ring.
	 */
	VR_PUT8(vrp->acc_reg, VR_CTRL0, VR_CTRL0_DMA_GO);
	return (mp);
}

/*
 * Enqueue a message for transmission.
 */
static void
vr_tx_enqueue_msg(vr_t *vrp, mblk_t *mp)
{
	vr_desc_t		*wp;
	vr_data_dma_t		*dmap;
	uint32_t		pklen;
	uint32_t		nextp;
	int			padlen;

	if ((uchar_t)mp->b_rptr[0] == 0xff &&
	    (uchar_t)mp->b_rptr[1] == 0xff &&
	    (uchar_t)mp->b_rptr[2] == 0xff &&
	    (uchar_t)mp->b_rptr[3] == 0xff &&
	    (uchar_t)mp->b_rptr[4] == 0xff &&
	    (uchar_t)mp->b_rptr[5] == 0xff)
		vrp->stats.mac_stat_brdcstxmt++;
	else if ((uchar_t)mp->b_rptr[0] == 1)
		vrp->stats.mac_stat_multixmt++;

	pklen = msgsize(mp);
	wp = vrp->tx.wp;
	dmap = &wp->dmabuf;

	/*
	 * Copy the message into the pre-mapped buffer and free mp
	 */
	mcopymsg(mp, dmap->buf);

	/*
	 * Clean padlen bytes of short packet.
	 */
	padlen = ETHERMIN - pklen;
	if (padlen > 0) {
		bzero(dmap->buf + pklen, padlen);
		pklen += padlen;
	}

	/*
	 * Most of the statistics are updated on reclaim, after the actual
	 * transmit. obytes is maintained here because the length is cleared
	 * after transmission
	 */
	vrp->stats.mac_stat_obytes += pklen;

	/*
	 * Sync the data so the device sees the new content too.
	 */
	(void) ddi_dma_sync(dmap->handle, 0, pklen, DDI_DMA_SYNC_FORDEV);

	/*
	 * If we have reached the TX interrupt distance, enable a TX interrupt
	 * for this packet. The Interrupt Control (IC) bit in the transmit
	 * descriptor doesn't have any effect on the interrupt generation
	 * despite the vague statements in the datasheet. Thus, we use the
	 * more obscure interrupt suppress bit which is probably part of the
	 * MAC's bookkeeping for TX interrupts and fragmented packets.
	 */
	vrp->tx.intr_distance++;
	nextp = ddi_get32(vrp->txring.acchdl, &wp->cdesc->next);
	if (vrp->tx.intr_distance >= VR_TX_MAX_INTR_DISTANCE) {
		/*
		 * Don't suppress the interrupt for this packet.
		 */
		vrp->tx.intr_distance = 0;
		nextp &= (~VR_TDES3_SUPPRESS_INTR);
	} else {
		/*
		 * Suppress the interrupt for this packet.
		 */
		nextp |= VR_TDES3_SUPPRESS_INTR;
	}

	/*
	 * Write and sync the chip's descriptor
	 */
	ddi_put32(vrp->txring.acchdl, &wp->cdesc->stat1,
	    pklen | (VR_TDES1_STP | VR_TDES1_EDP | VR_TDES1_CHN));
	ddi_put32(vrp->txring.acchdl, &wp->cdesc->next, nextp);
	ddi_put32(vrp->txring.acchdl, &wp->cdesc->stat0, VR_TDES0_OWN);
	(void) ddi_dma_sync(vrp->txring.handle, wp->offset,
	    sizeof (vr_chip_desc_t), DDI_DMA_SYNC_FORDEV);

	/*
	 * The ticks counter is cleared by reclaim when it reclaimed some
	 * descriptors and incremented by the periodic TX stall check.
	 */
	vrp->tx.stallticks = 1;
	vrp->tx.wp = wp->next;
}

/*
 * Free transmitted descriptors.
 */
static void
vr_tx_reclaim(vr_t *vrp)
{
	vr_desc_t		*cp;
	uint32_t		stat0, stat1, freed, dirty;

	ASSERT(mutex_owned(&vrp->tx.lock));

	freed = 0;
	dirty = vrp->tx.ndesc - vrp->tx.nfree;
	for (cp = vrp->tx.cp; dirty > 0; cp = cp->next) {
		/*
		 * Sync & get descriptor status.
		 */
		(void) ddi_dma_sync(vrp->txring.handle, cp->offset,
		    sizeof (vr_chip_desc_t),
		    DDI_DMA_SYNC_FORKERNEL);
		stat0 = ddi_get32(vrp->txring.acchdl, &cp->cdesc->stat0);

		if ((stat0 & VR_TDES0_OWN) != 0)
			break;

		/*
		 * Do stats for the first descriptor in a chain.
		 */
		stat1 = ddi_get32(vrp->txring.acchdl, &cp->cdesc->stat1);
		if ((stat1 & VR_TDES1_STP) != 0) {
			if ((stat0 & VR_TDES0_TERR) != 0) {
				vrp->stats.ether_stat_macxmt_errors++;
				if ((stat0 & VR_TDES0_UDF) != 0)
					vrp->stats.mac_stat_underflows++;
				if ((stat0 & VR_TDES0_ABT) != 0)
					vrp-> stats.ether_stat_ex_collisions++;
				/*
				 * Abort and FIFO underflow stop the MAC.
				 * Packet queueing must be disabled with HD
				 * links because otherwise the MAC is also lost
				 * after a few of these events.
				 */
				VR_PUT8(vrp->acc_reg, VR_CTRL0,
				    VR_CTRL0_DMA_GO);
			} else
				vrp->stats.mac_stat_opackets++;

			if ((stat0 & VR_TDES0_COL) != 0) {
				if ((stat0 & VR_TDES0_NCR) == 1) {
					vrp->stats.
					    ether_stat_first_collisions++;
				} else {
					vrp->stats.
					    ether_stat_multi_collisions++;
				}
				vrp->stats.mac_stat_collisions +=
				    (stat0 & VR_TDES0_NCR);
			}

			if ((stat0 & VR_TDES0_CRS) != 0)
				vrp->stats.ether_stat_carrier_errors++;

			if ((stat0 & VR_TDES0_OWC) != 0)
				vrp->stats.ether_stat_tx_late_collisions++;
		}
		freed += 1;
		dirty -= 1;
	}
	vrp->tx.cp = cp;

	if (freed > 0) {
		vrp->tx.nfree += freed;
		vrp->tx.stallticks = 0;
		vrp->stats.txreclaims += 1;
	} else
		vrp->stats.txreclaim0 += 1;
}

/*
 * Check TX health every 2 seconds.
 */
static void
vr_periodic(void *p)
{
	vr_t		*vrp;

	vrp = (vr_t *)p;
	if (vrp->chip.state == CHIPSTATE_RUNNING &&
	    vrp->chip.link.state == VR_LINK_STATE_UP && vrp->reset == 0) {
		if (mutex_tryenter(&vrp->intrlock) != 0) {
			mutex_enter(&vrp->tx.lock);
			if (vrp->tx.resched == 1) {
				if (vrp->tx.stallticks >= VR_MAXTXCHECKS) {
					/*
					 * No succesful reclaim in the last n
					 * intervals. Reset the MAC.
					 */
					vrp->reset = 1;
					vr_log(vrp, CE_WARN,
					    "TX stalled, resetting MAC");
				vrp->stats.txstalls++;
				} else {
					/*
					 * Increase until we find that we've
					 * waited long enough.
					 */
					vrp->tx.stallticks += 1;
				}
			}
			mutex_exit(&vrp->tx.lock);
			mutex_exit(&vrp->intrlock);
			vrp->stats.txchecks++;
		}
	}
	vrp->stats.cyclics++;
}

/*
 * Bring the device to our desired initial state.
 */
static void
vr_reset(vr_t *vrp)
{
	uint32_t	time;

	/*
	 * Reset the MAC
	 * If we don't wait long enough for the forced reset to complete,
	 * MAC looses sync with PHY. Result link up, no link change interrupt
	 * and no data transfer.
	 */
	time = 0;
	VR_PUT8(vrp->acc_io, VR_CTRL1, VR_CTRL1_RESET);
	do {
		drv_usecwait(100);
		time += 100;
		if (time >= 100000) {
			VR_PUT8(vrp->acc_io, VR_MISC1, VR_MISC1_RESET);
			delay(drv_usectohz(200000));
		}
	} while ((VR_GET8(vrp->acc_io, VR_CTRL1) & VR_CTRL1_RESET) != 0);
	delay(drv_usectohz(10000));

	/*
	 * Load the PROM contents into the MAC again.
	 */
	VR_SETBIT8(vrp->acc_io, VR_PROMCTL, VR_PROMCTL_RELOAD);
	delay(drv_usectohz(100000));

	/*
	 * Tell the MAC via IO space that we like to use memory space for
	 * accessing registers.
	 */
	VR_SETBIT8(vrp->acc_io, VR_CFGD, VR_CFGD_MMIOEN);
}

/*
 * Prepare and enable the card (MAC + PHY + PCI).
 */
static int
vr_start(vr_t *vrp)
{
	uint8_t		pci_latency, pci_mode;

	ASSERT(mutex_owned(&vrp->oplock));

	/*
	 * Allocate DMA buffers for RX.
	 */
	if (vr_rxring_init(vrp) != VR_SUCCESS) {
		vr_log(vrp, CE_NOTE, "vr_rxring_init() failed");
		return (ENOMEM);
	}

	/*
	 * Allocate DMA buffers for TX.
	 */
	if (vr_txring_init(vrp) != VR_SUCCESS) {
		vr_log(vrp, CE_NOTE, "vr_txring_init() failed");
		vr_rxring_fini(vrp);
		return (ENOMEM);
	}

	/*
	 * Changes of the chip specific registers as done in VIA's fet driver
	 * These bits are not in the datasheet and controlled by vr_chip_info.
	 */
	pci_mode = VR_GET8(vrp->acc_reg, VR_MODE2);
	if ((vrp->chip.info.bugs & VR_BUG_NEEDMODE10T) != 0)
		pci_mode |= VR_MODE2_MODE10T;

	if ((vrp->chip.info.bugs & VR_BUG_NEEDMODE2PCEROPT) != 0)
		pci_mode |= VR_MODE2_PCEROPT;

	if ((vrp->chip.info.features & VR_FEATURE_MRDLNMULTIPLE) != 0)
		pci_mode |= VR_MODE2_MRDPL;
	VR_PUT8(vrp->acc_reg, VR_MODE2, pci_mode);

	pci_mode = VR_GET8(vrp->acc_reg, VR_MODE3);
	if ((vrp->chip.info.bugs & VR_BUG_NEEDMIION) != 0)
		pci_mode |= VR_MODE3_MIION;
	VR_PUT8(vrp->acc_reg, VR_MODE3, pci_mode);

	/*
	 * RX: Accept broadcast packets.
	 */
	VR_SETBIT8(vrp->acc_reg, VR_RXCFG, VR_RXCFG_ACCEPTBROAD);

	/*
	 * RX: Start DMA when there are 256 bytes in the FIFO.
	 */
	VR_SETBITS8(vrp->acc_reg, VR_RXCFG, VR_RXCFG_FIFO_THRESHOLD_BITS,
	    VR_RXCFG_FIFO_THRESHOLD_256);
	VR_SETBITS8(vrp->acc_reg, VR_BCR0, VR_BCR0_RX_FIFO_THRESHOLD_BITS,
	    VR_BCR0_RX_FIFO_THRESHOLD_256);

	/*
	 * TX: Start transmit when there are 256 bytes in the FIFO.
	 */
	VR_SETBITS8(vrp->acc_reg, VR_TXCFG, VR_TXCFG_FIFO_THRESHOLD_BITS,
	    VR_TXCFG_FIFO_THRESHOLD_256);
	VR_SETBITS8(vrp->acc_reg, VR_BCR1, VR_BCR1_TX_FIFO_THRESHOLD_BITS,
	    VR_BCR1_TX_FIFO_THRESHOLD_256);

	/*
	 * Burst transfers up to 256 bytes.
	 */
	VR_SETBITS8(vrp->acc_reg, VR_BCR0, VR_BCR0_DMABITS, VR_BCR0_DMA256);

	/*
	 * Disable TX autopolling as it is bad for RX performance
	 * I assume this is because the RX process finds the bus often occupied
	 * by the polling process.
	 */
	VR_SETBIT8(vrp->acc_reg, VR_CTRL1, VR_CTRL1_NOAUTOPOLL);

	/*
	 * Honor the PCI latency timer if it is reasonable.
	 */
	pci_latency = VR_GET8(vrp->acc_cfg, PCI_CONF_LATENCY_TIMER);
	if (pci_latency != 0 && pci_latency != 0xFF)
		VR_SETBIT8(vrp->acc_reg, VR_CFGB, VR_CFGB_LATENCYTIMER);
	else
		VR_CLRBIT8(vrp->acc_reg, VR_CFGB, VR_CFGB_LATENCYTIMER);

	/*
	 * Ensure that VLAN filtering is off, because this strips the tag.
	 */
	if ((vrp->chip.info.features & VR_FEATURE_VLANTAGGING) != 0) {
		VR_CLRBIT8(vrp->acc_reg, VR_BCR1, VR_BCR1_VLANFILTER);
		VR_CLRBIT8(vrp->acc_reg, VR_TXCFG, VR_TXCFG_8021PQ_EN);
	}

	/*
	 * Clear the CAM filter.
	 */
	if ((vrp->chip.info.features & VR_FEATURE_CAMSUPPORT) != 0) {
		VR_PUT8(vrp->acc_reg, VR_CAM_CTRL, VR_CAM_CTRL_ENABLE);
		VR_PUT32(vrp->acc_reg, VR_CAM_MASK, 0);
		VR_PUT8(vrp->acc_reg, VR_CAM_CTRL, VR_CAM_CTRL_DONE);

		VR_PUT8(vrp->acc_reg, VR_CAM_CTRL,
		    VR_CAM_CTRL_ENABLE|VR_CAM_CTRL_SELECT_VLAN);
		VR_PUT8(vrp->acc_reg, VR_VCAM0, 0);
		VR_PUT8(vrp->acc_reg, VR_VCAM1, 0);
		VR_PUT8(vrp->acc_reg, VR_CAM_CTRL, VR_CAM_CTRL_WRITE);
		VR_PUT32(vrp->acc_reg, VR_CAM_MASK, 1);
		drv_usecwait(2);
		VR_PUT8(vrp->acc_reg, VR_CAM_CTRL, VR_CAM_CTRL_DONE);
	}

	/*
	 * Give the start addresses of the descriptor rings to the DMA
	 * controller on the MAC.
	 */
	VR_PUT32(vrp->acc_reg, VR_RXADDR, vrp->rx.rp->paddr);
	VR_PUT32(vrp->acc_reg, VR_TXADDR, vrp->tx.wp->paddr);

	/*
	 * We don't use the additionally invented interrupt ICR1 register,
	 * so make sure these are disabled.
	 */
	VR_PUT8(vrp->acc_reg, VR_ISR1, 0xFF);
	VR_PUT8(vrp->acc_reg, VR_ICR1, 0);

	/*
	 * Enable interrupts.
	 */
	VR_PUT16(vrp->acc_reg, VR_ISR0, 0xFFFF);
	VR_PUT16(vrp->acc_reg, VR_ICR0, VR_ICR0_CFG);

	/*
	 * Enable the DMA controller.
	 */
	VR_PUT8(vrp->acc_reg, VR_CTRL0, VR_CTRL0_DMA_GO);

	/*
	 * Configure the link. Rely on the link change interrupt for getting
	 * the link state into the driver.
	 */
	vr_link_init(vrp);

	/*
	 * Set the software view on the state to 'running'.
	 */
	vrp->chip.state = CHIPSTATE_RUNNING;
	return (0);
}

/*
 * Stop DMA and interrupts.
 */
static int
vr_stop(vr_t *vrp)
{
	ASSERT(mutex_owned(&vrp->oplock));

	/*
	 * Stop interrupts.
	 */
	VR_PUT16(vrp->acc_reg, VR_ICR0, 0);
	VR_PUT8(vrp->acc_reg, VR_ICR1, 0);

	/*
	 * Stop DMA.
	 */
	VR_PUT8(vrp->acc_reg, VR_CTRL0, VR_CTRL0_DMA_STOP);

	/*
	 * Set the software view on the state to stopped.
	 */
	vrp->chip.state = CHIPSTATE_STOPPED;

	/*
	 * Remove DMA buffers from the rings.
	 */
	vr_rxring_fini(vrp);
	vr_txring_fini(vrp);
	return (0);
}

int
vr_mac_start(void *p)
{
	vr_t	*vrp;
	int	rc;

	vrp = (vr_t *)p;
	mutex_enter(&vrp->oplock);

	/*
	 * Reset the card.
	 */
	vr_reset(vrp);

	/*
	 * Prepare and enable the card.
	 */
	rc = vr_start(vrp);

	/*
	 * Configure a cyclic function to keep the card & driver from diverting.
	 */
	vrp->periodic_id =
	    ddi_periodic_add(vr_periodic, vrp, VR_CHECK_INTERVAL, DDI_IPL_0);

	mutex_exit(&vrp->oplock);
	return (rc);
}

void
vr_mac_stop(void *p)
{
	vr_t	*vrp = p;

	mutex_enter(&vrp->oplock);
	mutex_enter(&vrp->tx.lock);

	/*
	 * Stop the device.
	 */
	(void) vr_stop(vrp);
	mutex_exit(&vrp->tx.lock);

	/*
	 * Remove the cyclic from the system.
	 */
	ddi_periodic_delete(vrp->periodic_id);
	mutex_exit(&vrp->oplock);
}

/*
 * Add or remove a multicast address to/from the filter
 *
 * From the 21143 manual:
 *  The 21143 can store 512 bits serving as hash bucket heads, and one physical
 *  48-bit Ethernet address. Incoming frames with multicast destination
 *  addresses are subjected to imperfect filtering. Frames with physical
 *  destination  addresses are checked against the single physical address.
 *  For any incoming frame with a multicast destination address, the 21143
 *  applies the standard Ethernet cyclic redundancy check (CRC) function to the
 *  first 6 bytes containing the destination address, then it uses the most
 *  significant 9 bits of the result as a bit index into the table. If the
 *  indexed bit is set, the frame is accepted. If the bit is cleared, the frame
 *  is rejected. This filtering mode is called imperfect because multicast
 *  frames not addressed to this station may slip through, but it still
 *  decreases the number of frames that the host can receive.
 * I assume the above is also the way the VIA chips work. There's not a single
 * word about the multicast filter in the datasheet.
 *
 * Another word on the CAM filter on VT6105M controllers:
 *  The VT6105M has content addressable memory which can be used for perfect
 *  filtering of 32 multicast addresses and a few VLAN id's
 *
 *  I think it works like this: When the controller receives a multicast
 *  address, it looks up the address using CAM. When it is found, it takes the
 *  matching cell address (index) and compares this to the bit position in the
 *  cam mask. If the bit is set, the packet is passed up. If CAM lookup does not
 *  result in a match, the packet is filtered using the hash based filter,
 *  if that matches, the packet is passed up and dropped otherwise
 * Also, there's not a single word in the datasheet on how this cam is supposed
 * to work ...
 */
int
vr_mac_set_multicast(void *p, boolean_t add, const uint8_t *mca)
{
	vr_t		*vrp;
	uint32_t	crc_index;
	int32_t		cam_index;
	uint32_t	cam_mask;
	boolean_t	use_hash_filter;
	ether_addr_t	taddr;
	uint32_t	a;

	vrp = (vr_t *)p;
	mutex_enter(&vrp->oplock);
	mutex_enter(&vrp->intrlock);
	use_hash_filter = B_FALSE;

	if ((vrp->chip.info.features & VR_FEATURE_CAMSUPPORT) != 0) {
		/*
		 * Program the perfect filter.
		 */
		cam_mask = VR_GET32(vrp->acc_reg, VR_CAM_MASK);
		if (add == B_TRUE) {
			/*
			 * Get index of first empty slot.
			 */
			bzero(&taddr, sizeof (taddr));
			cam_index = vr_cam_index(vrp, taddr);
			if (cam_index != -1) {
				/*
				 * Add address at cam_index.
				 */
				cam_mask |= (1 << cam_index);
				VR_PUT8(vrp->acc_reg, VR_CAM_CTRL,
				    VR_CAM_CTRL_ENABLE);
				VR_PUT8(vrp->acc_reg, VR_CAM_ADDR, cam_index);
				VR_PUT32(vrp->acc_reg, VR_CAM_MASK, cam_mask);
				for (a = 0; a < ETHERADDRL; a++) {
					VR_PUT8(vrp->acc_reg,
					    VR_MCAM0 + a, mca[a]);
				}
				VR_PUT8(vrp->acc_reg, VR_CAM_CTRL,
				    VR_CAM_CTRL_WRITE);
				drv_usecwait(2);
				VR_PUT8(vrp->acc_reg, VR_CAM_CTRL,
				    VR_CAM_CTRL_DONE);
			} else {
				/*
				 * No free CAM slots available
				 * Add mca to the imperfect filter.
				 */
				use_hash_filter = B_TRUE;
			}
		} else {
			/*
			 * Find the index of the entry to remove
			 * If the entry was not found (-1), the addition was
			 * probably done when the table was full.
			 */
			cam_index = vr_cam_index(vrp, mca);
			if (cam_index != -1) {
				/*
				 * Disable the corresponding mask bit.
				 */
				cam_mask &= ~(1 << cam_index);
				VR_PUT8(vrp->acc_reg, VR_CAM_CTRL,
				    VR_CAM_CTRL_ENABLE);
				VR_PUT32(vrp->acc_reg, VR_CAM_MASK, cam_mask);
				VR_PUT8(vrp->acc_reg, VR_CAM_CTRL,
				    VR_CAM_CTRL_DONE);
			} else {
				/*
				 * The entry to be removed was not found
				 * The likely cause is that the CAM was full
				 * during addition. The entry is added to the
				 * hash filter in that case and needs to be
				 * removed there too.
				 */
				use_hash_filter = B_TRUE;
			}
		}
	} else {
		/*
		 * No CAM in the MAC, thus we need the hash filter.
		 */
		use_hash_filter = B_TRUE;
	}

	if (use_hash_filter == B_TRUE) {
		/*
		 * Get the CRC-32 of the multicast address
		 * The card uses the "MSB first" direction when calculating the
		 * the CRC. This is odd because ethernet is "LSB first"
		 * We have to use that "big endian" approach as well.
		 */
		crc_index = ether_crc_be(mca) >> (32 - 6);
		if (add == B_TRUE) {
			/*
			 * Turn bit[crc_index] on.
			 */
			if (crc_index < 32)
				vrp->mhash0 |= (1 << crc_index);
			else
				vrp->mhash1 |= (1 << (crc_index - 32));
		} else {
			/*
			 * Turn bit[crc_index] off.
			 */
			if (crc_index < 32)
				vrp->mhash0 &= ~(0 << crc_index);
			else
				vrp->mhash1 &= ~(0 << (crc_index - 32));
		}

		/*
		 * When not promiscuous write the filter now. When promiscuous,
		 * the filter is open and will be written when promiscuous ends.
		 */
		if (vrp->promisc == B_FALSE) {
			VR_PUT32(vrp->acc_reg, VR_MAR0, vrp->mhash0);
			VR_PUT32(vrp->acc_reg, VR_MAR1, vrp->mhash1);
		}
	}

	/*
	 * Enable/disable multicast receivements based on mcount.
	 */
	if (add == B_TRUE)
		vrp->mcount++;
	else if (vrp->mcount != 0)
		vrp->mcount --;
	if (vrp->mcount != 0)
		VR_SETBIT8(vrp->acc_reg, VR_RXCFG, VR_RXCFG_ACCEPTMULTI);
	else
		VR_CLRBIT8(vrp->acc_reg, VR_RXCFG, VR_RXCFG_ACCEPTMULTI);

	mutex_exit(&vrp->intrlock);
	mutex_exit(&vrp->oplock);
	return (0);
}

/*
 * Calculate the CRC32 for 6 bytes of multicast address in MSB(it) first order.
 * The MSB first order is a bit odd because Ethernet standard is LSB first
 */
static uint32_t
ether_crc_be(const uint8_t *data)
{
	uint32_t	crc = (uint32_t)0xFFFFFFFFU;
	uint32_t	carry;
	uint32_t	bit;
	uint32_t	length;
	uint8_t		c;

	for (length = 0; length < ETHERADDRL; length++) {
		c = data[length];
		for (bit = 0; bit < 8; bit++) {
			carry = ((crc & 0x80000000U) ? 1 : 0) ^ (c & 0x01);
			crc <<= 1;
			c >>= 1;
			if (carry)
				crc = (crc ^ 0x04C11DB6) | carry;
		}
	}
	return (crc);
}


/*
 * Return the CAM index (base 0) of maddr or -1 if maddr is not found
 * If maddr is 0, return the index of an empty slot in CAM or -1 when no free
 * slots available.
 */
static int32_t
vr_cam_index(vr_t *vrp, const uint8_t *maddr)
{
	ether_addr_t	taddr;
	int32_t		index;
	uint32_t	mask;
	uint32_t	a;

	bzero(&taddr, sizeof (taddr));

	/*
	 * Read the CAM mask from the controller.
	 */
	mask = VR_GET32(vrp->acc_reg, VR_CAM_MASK);

	/*
	 * If maddr is 0, return the first unused slot or -1 for no unused.
	 */
	if (bcmp(maddr, taddr, ETHERADDRL) == 0) {
		/*
		 * Look for the first unused position in mask.
		 */
		for (index = 0; index < VR_CAM_SZ; index++) {
			if (((mask >> index) & 1) == 0)
				return (index);
		}
		return (-1);
	} else {
		/*
		 * Look for maddr in CAM.
		 */
		for (index = 0; index < VR_CAM_SZ; index++) {
			/* Look at enabled entries only */
			if (((mask >> index) & 1) == 0)
				continue;

			VR_PUT8(vrp->acc_reg, VR_CAM_CTRL, VR_CAM_CTRL_ENABLE);
			VR_PUT8(vrp->acc_reg, VR_CAM_ADDR, index);
			VR_PUT8(vrp->acc_reg, VR_CAM_CTRL, VR_CAM_CTRL_READ);
			drv_usecwait(2);
			for (a = 0; a < ETHERADDRL; a++)
				taddr[a] = VR_GET8(vrp->acc_reg, VR_MCAM0 + a);
			VR_PUT8(vrp->acc_reg, VR_CAM_CTRL, VR_CAM_CTRL_DONE);
			if (bcmp(maddr, taddr, ETHERADDRL) == 0)
				return (index);
		}
	}
	return (-1);
}

/*
 * Set promiscuous mode on or off.
 */
int
vr_mac_set_promisc(void *p, boolean_t promiscflag)
{
	vr_t		*vrp;
	uint8_t		rxcfg;

	vrp = (vr_t *)p;

	mutex_enter(&vrp->intrlock);
	mutex_enter(&vrp->oplock);
	mutex_enter(&vrp->tx.lock);

	/*
	 * Get current receive configuration.
	 */
	rxcfg = VR_GET8(vrp->acc_reg, VR_RXCFG);
	vrp->promisc = promiscflag;

	if (promiscflag == B_TRUE) {
		/*
		 * Enable promiscuous mode and open the multicast filter.
		 */
		rxcfg |= (VR_RXCFG_PROMISC | VR_RXCFG_ACCEPTMULTI);
		VR_PUT32(vrp->acc_reg, VR_MAR0, 0xffffffff);
		VR_PUT32(vrp->acc_reg, VR_MAR1, 0xffffffff);
	} else {
		/*
		 * Restore the multicast filter and disable promiscuous mode.
		 */
		VR_PUT32(vrp->acc_reg, VR_MAR0, vrp->mhash0);
		VR_PUT32(vrp->acc_reg, VR_MAR1, vrp->mhash1);
		rxcfg &= ~VR_RXCFG_PROMISC;
		if (vrp->mcount != 0)
			rxcfg |= VR_RXCFG_ACCEPTMULTI;
	}
	VR_PUT8(vrp->acc_reg, VR_RXCFG, rxcfg);
	mutex_exit(&vrp->tx.lock);
	mutex_exit(&vrp->oplock);
	mutex_exit(&vrp->intrlock);
	return (0);
}

int
vr_mac_getstat(void *arg, uint_t stat, uint64_t *val)
{
	vr_t		*vrp;
	uint64_t	v;

	vrp = (void *) arg;

	switch (stat) {
	default:
		return (ENOTSUP);

	case ETHER_STAT_ADV_CAP_100T4:
		v = (vrp->chip.mii.anadv & MII_ABILITY_100BASE_T4) != 0;
		break;

	case ETHER_STAT_ADV_CAP_100FDX:
		v = (vrp->chip.mii.anadv & MII_ABILITY_100BASE_TX_FD) != 0;
		break;

	case ETHER_STAT_ADV_CAP_100HDX:
		v = (vrp->chip.mii.anadv & MII_ABILITY_100BASE_TX) != 0;
		break;

	case ETHER_STAT_ADV_CAP_10FDX:
		v = (vrp->chip.mii.anadv & MII_ABILITY_10BASE_T_FD) != 0;
		break;

	case ETHER_STAT_ADV_CAP_10HDX:
		v = (vrp->chip.mii.anadv & MII_ABILITY_10BASE_T) != 0;
		break;

	case ETHER_STAT_ADV_CAP_ASMPAUSE:
		v = 0;
		break;

	case ETHER_STAT_ADV_CAP_AUTONEG:
		v = (vrp->chip.mii.control & MII_CONTROL_ANE) != 0;
		break;

	case ETHER_STAT_ADV_CAP_PAUSE:
		v = (vrp->chip.mii.anadv & MII_ABILITY_PAUSE) != 0;
		break;

	case ETHER_STAT_ADV_REMFAULT:
		v = (vrp->chip.mii.anadv & MII_AN_ADVERT_REMFAULT) != 0;
		break;

	case ETHER_STAT_ALIGN_ERRORS:
		v = vrp->stats.ether_stat_align_errors;
		break;

	case ETHER_STAT_CAP_100T4:
		v = (vrp->chip.mii.status & MII_STATUS_100_BASE_T4) != 0;
		break;

	case ETHER_STAT_CAP_100FDX:
		v = (vrp->chip.mii.status & MII_STATUS_100_BASEX_FD) != 0;
		break;

	case ETHER_STAT_CAP_100HDX:
		v = (vrp->chip.mii.status & MII_STATUS_100_BASEX) != 0;
		break;

	case ETHER_STAT_CAP_10FDX:
		v = (vrp->chip.mii.status & MII_STATUS_10_FD) != 0;
		break;

	case ETHER_STAT_CAP_10HDX:
		v = (vrp->chip.mii.status & MII_STATUS_10) != 0;
		break;

	case ETHER_STAT_CAP_ASMPAUSE:
		v = 0;
		break;

	case ETHER_STAT_CAP_AUTONEG:
		v = (vrp->chip.mii.status & MII_STATUS_CANAUTONEG) != 0;
		break;

	case ETHER_STAT_CAP_PAUSE:
		v = 1;
		break;

	case ETHER_STAT_CAP_REMFAULT:
		v = (vrp->chip.mii.status & MII_STATUS_REMFAULT) != 0;
		break;

	case ETHER_STAT_CARRIER_ERRORS:
		/*
		 * Number of times carrier was lost or never detected on a
		 * transmission attempt.
		 */
		v = vrp->stats.ether_stat_carrier_errors;
		break;

	case ETHER_STAT_JABBER_ERRORS:
		return (ENOTSUP);

	case ETHER_STAT_DEFER_XMTS:
		/*
		 * Packets without collisions where first transmit attempt was
		 * delayed because the medium was busy.
		 */
		v = vrp->stats.ether_stat_defer_xmts;
		break;

	case ETHER_STAT_EX_COLLISIONS:
		/*
		 * Frames where excess collisions occurred on transmit, causing
		 * transmit failure.
		 */
		v = vrp->stats.ether_stat_ex_collisions;
		break;

	case ETHER_STAT_FCS_ERRORS:
		/*
		 * Packets received with CRC errors.
		 */
		v = vrp->stats.ether_stat_fcs_errors;
		break;

	case ETHER_STAT_FIRST_COLLISIONS:
		/*
		 * Packets successfully transmitted with exactly one collision.
		 */
		v = vrp->stats.ether_stat_first_collisions;
		break;

	case ETHER_STAT_LINK_ASMPAUSE:
		v = 0;
		break;

	case ETHER_STAT_LINK_AUTONEG:
		v = (vrp->chip.mii.control & MII_CONTROL_ANE) != 0 &&
		    (vrp->chip.mii.status & MII_STATUS_ANDONE) != 0;
		break;

	case ETHER_STAT_LINK_DUPLEX:
		v = vrp->chip.link.duplex;
		break;

	case ETHER_STAT_LINK_PAUSE:
		v = vrp->chip.link.flowctrl;
		break;

	case ETHER_STAT_LP_CAP_100T4:
		v = (vrp->chip.mii.lpable & MII_ABILITY_100BASE_T4) != 0;
		break;

	case ETHER_STAT_LP_CAP_1000FDX:
		v = 0;
		break;

	case ETHER_STAT_LP_CAP_1000HDX:
		v = 0;
		break;

	case ETHER_STAT_LP_CAP_100FDX:
		v = (vrp->chip.mii.lpable & MII_ABILITY_100BASE_TX_FD) != 0;
		break;

	case ETHER_STAT_LP_CAP_100HDX:
		v = (vrp->chip.mii.lpable & MII_ABILITY_100BASE_TX) != 0;
		break;

	case ETHER_STAT_LP_CAP_10FDX:
		v = (vrp->chip.mii.lpable & MII_ABILITY_10BASE_T_FD) != 0;
		break;

	case ETHER_STAT_LP_CAP_10HDX:
		v = (vrp->chip.mii.lpable & MII_ABILITY_10BASE_T) != 0;
		break;

	case ETHER_STAT_LP_CAP_ASMPAUSE:
		v = 0;
		break;

	case ETHER_STAT_LP_CAP_AUTONEG:
		v = (vrp->chip.mii.anexp & MII_AN_EXP_LPCANAN) != 0;
		break;

	case ETHER_STAT_LP_CAP_PAUSE:
		v = (vrp->chip.mii.lpable & MII_ABILITY_PAUSE) != 0;
		break;

	case ETHER_STAT_LP_REMFAULT:
		v = (vrp->chip.mii.status & MII_STATUS_REMFAULT) != 0;
		break;

	case ETHER_STAT_MACRCV_ERRORS:
		/*
		 * Packets received with MAC errors, except align_errors,
		 * fcs_errors, and toolong_errors.
		 */
		v = vrp->stats.ether_stat_macrcv_errors;
		break;

	case ETHER_STAT_MACXMT_ERRORS:
		/*
		 * Packets encountering transmit MAC failures, except carrier
		 * and collision failures.
		 */
		v = vrp->stats.ether_stat_macxmt_errors;
		break;

	case ETHER_STAT_MULTI_COLLISIONS:
		/*
		 * Packets successfully transmitted with multiple collisions.
		 */
		v = vrp->stats.ether_stat_multi_collisions;
		break;

	case ETHER_STAT_SQE_ERRORS:
		/*
		 * Number of times signal quality error was reported
		 * This one is reported by the PHY.
		 */
		return (ENOTSUP);

	case ETHER_STAT_TOOLONG_ERRORS:
		/*
		 * Packets received larger than the maximum permitted length.
		 */
		v = vrp->stats.ether_stat_toolong_errors;
		break;

	case ETHER_STAT_TOOSHORT_ERRORS:
		v = vrp->stats.ether_stat_tooshort_errors;
		break;

	case ETHER_STAT_TX_LATE_COLLISIONS:
		/*
		 * Number of times a transmit collision occurred late
		 * (after 512 bit times).
		 */
		v = vrp->stats.ether_stat_tx_late_collisions;
		break;

	case ETHER_STAT_XCVR_ADDR:
		/*
		 * MII address in the 0 to 31 range of the physical layer
		 * device in use for a given Ethernet device.
		 */
		v = vrp->chip.phyaddr;
		break;

	case ETHER_STAT_XCVR_ID:
		/*
		 * MII transceiver manufacturer and device ID.
		 */
		v = (vrp->chip.mii.identh << 16) | vrp->chip.mii.identl;
		break;

	case ETHER_STAT_XCVR_INUSE:
		v = vrp->chip.link.mau;
		break;

	case MAC_STAT_BRDCSTRCV:
		v = vrp->stats.mac_stat_brdcstrcv;
		break;

	case MAC_STAT_BRDCSTXMT:
		v = vrp->stats.mac_stat_brdcstxmt;
		break;

	case MAC_STAT_MULTIXMT:
		v = vrp->stats.mac_stat_multixmt;
		break;

	case MAC_STAT_COLLISIONS:
		v = vrp->stats.mac_stat_collisions;
		break;

	case MAC_STAT_IERRORS:
		v = vrp->stats.mac_stat_ierrors;
		break;

	case MAC_STAT_IFSPEED:
		if (vrp->chip.link.speed == VR_LINK_SPEED_100MBS)
			v = 100 * 1000 * 1000;
		else if (vrp->chip.link.speed == VR_LINK_SPEED_10MBS)
			v = 10 * 1000 * 1000;
		else
			v = 0;
		break;

	case MAC_STAT_IPACKETS:
		v = vrp->stats.mac_stat_ipackets;
		break;

	case MAC_STAT_MULTIRCV:
		v = vrp->stats.mac_stat_multircv;
		break;

	case MAC_STAT_NORCVBUF:
		vrp->stats.mac_stat_norcvbuf +=
		    VR_GET16(vrp->acc_reg, VR_TALLY_MPA);
		VR_PUT16(vrp->acc_reg, VR_TALLY_MPA, 0);
		v = vrp->stats.mac_stat_norcvbuf;
		break;

	case MAC_STAT_NOXMTBUF:
		v = vrp->stats.mac_stat_noxmtbuf;
		break;

	case MAC_STAT_OBYTES:
		v = vrp->stats.mac_stat_obytes;
		break;

	case MAC_STAT_OERRORS:
		v = vrp->stats.ether_stat_macxmt_errors +
		    vrp->stats.mac_stat_underflows +
		    vrp->stats.ether_stat_align_errors +
		    vrp->stats.ether_stat_carrier_errors +
		    vrp->stats.ether_stat_fcs_errors;
		break;

	case MAC_STAT_OPACKETS:
		v = vrp->stats.mac_stat_opackets;
		break;

	case MAC_STAT_RBYTES:
		v = vrp->stats.mac_stat_rbytes;
		break;

	case MAC_STAT_UNKNOWNS:
		/*
		 * Isn't this something for the MAC layer to maintain?
		 */
		return (ENOTSUP);

	case MAC_STAT_UNDERFLOWS:
		v = vrp->stats.mac_stat_underflows;
		break;

	case MAC_STAT_OVERFLOWS:
		v = vrp->stats.mac_stat_overflows;
		break;
	}
	*val = v;
	return (0);
}

int
vr_mac_set_ether_addr(void *p, const uint8_t *ea)
{
	vr_t	*vrp;
	int	i;

	vrp = (vr_t *)p;
	mutex_enter(&vrp->oplock);
	mutex_enter(&vrp->intrlock);

	/*
	 * Set a new station address.
	 */
	for (i = 0; i < ETHERADDRL; i++)
		VR_PUT8(vrp->acc_reg, VR_ETHERADDR + i, ea[i]);

	mutex_exit(&vrp->intrlock);
	mutex_exit(&vrp->oplock);
	return (0);
}

/*
 * Configure the ethernet link according to param and chip.mii.
 */
static void
vr_link_init(vr_t *vrp)
{
	ASSERT(mutex_owned(&vrp->oplock));
	if ((vrp->chip.mii.control & MII_CONTROL_ANE) != 0) {
		/*
		 * If we do autoneg, ensure restart autoneg is ON.
		 */
		vrp->chip.mii.control |= MII_CONTROL_RSAN;

		/*
		 * The advertisements are prepared by param_init.
		 */
		vr_phy_write(vrp, MII_AN_ADVERT, vrp->chip.mii.anadv);
	} else {
		/*
		 * If we don't autoneg, we need speed, duplex and flowcontrol
		 * to configure the link. However, dladm doesn't allow changes
		 * to speed and duplex (readonly). The way this is solved
		 * (ahem) is to select the highest enabled combination
		 * Speed and duplex should be r/w when autoneg is off.
		 */
		if ((vrp->param.anadv_en &
		    MII_ABILITY_100BASE_TX_FD) != 0) {
			vrp->chip.mii.control |= MII_CONTROL_100MB;
			vrp->chip.mii.control |= MII_CONTROL_FDUPLEX;
		} else if ((vrp->param.anadv_en &
		    MII_ABILITY_100BASE_TX) != 0) {
			vrp->chip.mii.control |= MII_CONTROL_100MB;
			vrp->chip.mii.control &= ~MII_CONTROL_FDUPLEX;
		} else if ((vrp->param.anadv_en &
		    MII_ABILITY_10BASE_T_FD) != 0) {
			vrp->chip.mii.control |= MII_CONTROL_FDUPLEX;
			vrp->chip.mii.control &= ~MII_CONTROL_100MB;
		} else {
			vrp->chip.mii.control &= ~MII_CONTROL_100MB;
			vrp->chip.mii.control &= ~MII_CONTROL_FDUPLEX;
		}
	}
	/*
	 * Write the control register.
	 */
	vr_phy_write(vrp, MII_CONTROL, vrp->chip.mii.control);

	/*
	 * With autoneg off we cannot rely on the link_change interrupt for
	 * for getting the status into the driver.
	 */
	if ((vrp->chip.mii.control & MII_CONTROL_ANE) == 0) {
		vr_link_state(vrp);
		mac_link_update(vrp->machdl,
		    (link_state_t)vrp->chip.link.state);
	}
}

/*
 * Get link state in the driver and configure the MAC accordingly.
 */
static void
vr_link_state(vr_t *vrp)
{
	uint16_t		mask;

	ASSERT(mutex_owned(&vrp->oplock));

	vr_phy_read(vrp, MII_STATUS, &vrp->chip.mii.status);
	vr_phy_read(vrp, MII_CONTROL, &vrp->chip.mii.control);
	vr_phy_read(vrp, MII_AN_ADVERT, &vrp->chip.mii.anadv);
	vr_phy_read(vrp, MII_AN_LPABLE, &vrp->chip.mii.lpable);
	vr_phy_read(vrp, MII_AN_EXPANSION, &vrp->chip.mii.anexp);

	/*
	 * If we did autongeg, deduce the link type/speed by selecting the
	 * highest common denominator.
	 */
	if ((vrp->chip.mii.control & MII_CONTROL_ANE) != 0) {
		mask = vrp->chip.mii.anadv & vrp->chip.mii.lpable;
		if ((mask & MII_ABILITY_100BASE_TX_FD) != 0) {
			vrp->chip.link.speed = VR_LINK_SPEED_100MBS;
			vrp->chip.link.duplex = VR_LINK_DUPLEX_FULL;
			vrp->chip.link.mau = VR_MAU_100X;
		} else if ((mask & MII_ABILITY_100BASE_T4) != 0) {
			vrp->chip.link.speed = VR_LINK_SPEED_100MBS;
			vrp->chip.link.duplex = VR_LINK_DUPLEX_HALF;
			vrp->chip.link.mau = VR_MAU_100T4;
		} else if ((mask & MII_ABILITY_100BASE_TX) != 0) {
			vrp->chip.link.speed = VR_LINK_SPEED_100MBS;
			vrp->chip.link.duplex = VR_LINK_DUPLEX_HALF;
			vrp->chip.link.mau = VR_MAU_100X;
		} else if ((mask & MII_ABILITY_10BASE_T_FD) != 0) {
			vrp->chip.link.speed = VR_LINK_SPEED_10MBS;
			vrp->chip.link.duplex = VR_LINK_DUPLEX_FULL;
			vrp->chip.link.mau = VR_MAU_10;
		} else if ((mask & MII_ABILITY_10BASE_T) != 0) {
			vrp->chip.link.speed = VR_LINK_SPEED_10MBS;
			vrp->chip.link.duplex = VR_LINK_DUPLEX_HALF;
			vrp->chip.link.mau = VR_MAU_10;
		} else {
			vrp->chip.link.speed = VR_LINK_SPEED_UNKNOWN;
			vrp->chip.link.duplex = VR_LINK_DUPLEX_UNKNOWN;
			vrp->chip.link.mau = VR_MAU_UNKNOWN;
		}

		/*
		 * Did we negotiate pause?
		 */
		if ((mask & MII_ABILITY_PAUSE) != 0 &&
		    vrp->chip.link.duplex == VR_LINK_DUPLEX_FULL)
			vrp->chip.link.flowctrl = VR_PAUSE_BIDIRECTIONAL;
		else
			vrp->chip.link.flowctrl = VR_PAUSE_NONE;

		/*
		 * Did either one detect a AN fault?
		 */
		if ((vrp->chip.mii.status & MII_STATUS_REMFAULT) != 0)
			vr_log(vrp, CE_WARN,
			    "AN remote fault reported by LP.");

		if ((vrp->chip.mii.lpable & MII_AN_ADVERT_REMFAULT) != 0)
			vr_log(vrp, CE_WARN, "AN remote fault caused for LP.");
	} else {
		/*
		 * We didn't autoneg
		 * The link type is defined by the control register.
		 */
		if ((vrp->chip.mii.control & MII_CONTROL_100MB) != 0) {
			vrp->chip.link.speed = VR_LINK_SPEED_100MBS;
			vrp->chip.link.mau = VR_MAU_100X;
		} else {
			vrp->chip.link.speed = VR_LINK_SPEED_10MBS;
			vrp->chip.link.mau = VR_MAU_10;
		}

		if ((vrp->chip.mii.control & MII_CONTROL_FDUPLEX) != 0)
			vrp->chip.link.duplex = VR_LINK_DUPLEX_FULL;
		else {
			vrp->chip.link.duplex = VR_LINK_DUPLEX_HALF;
			/*
			 * No pause on HDX links.
			 */
			vrp->chip.link.flowctrl = VR_PAUSE_NONE;
		}
	}

	/*
	 * Set the duplex mode on the MAC according to that of the PHY.
	 */
	if (vrp->chip.link.duplex == VR_LINK_DUPLEX_FULL) {
		VR_SETBIT8(vrp->acc_reg, VR_CTRL1, VR_CTRL1_MACFULLDUPLEX);
		/*
		 * Enable packet queueing on FDX links.
		 */
		if ((vrp->chip.info.bugs & VR_BUG_NO_TXQUEUEING) == 0)
			VR_CLRBIT8(vrp->acc_reg, VR_CFGB, VR_CFGB_QPKTDIS);
	} else {
		VR_CLRBIT8(vrp->acc_reg, VR_CTRL1, VR_CTRL1_MACFULLDUPLEX);
		/*
		 * Disable packet queueing on HDX links. With queueing enabled,
		 * this MAC get's lost after a TX abort (too many colisions).
		 */
		VR_SETBIT8(vrp->acc_reg, VR_CFGB, VR_CFGB_QPKTDIS);
	}

	/*
	 * Set pause options on the MAC.
	 */
	if (vrp->chip.link.flowctrl == VR_PAUSE_BIDIRECTIONAL) {
		/*
		 * All of our MAC's can receive pause frames.
		 */
		VR_SETBIT8(vrp->acc_reg, VR_MISC0, VR_MISC0_FDXRFEN);

		/*
		 * VT6105 and above can transmit pause frames.
		 */
		if ((vrp->chip.info.features & VR_FEATURE_TX_PAUSE_CAP) != 0) {
			/*
			 * Set the number of available receive descriptors
			 * Non-zero values written to this register are added
			 * to the register's contents. Careful: Writing zero
			 * clears the register and thus causes a (long) pause
			 * request.
			 */
			VR_PUT8(vrp->acc_reg, VR_FCR0_RXBUFCOUNT,
			    MIN(vrp->rx.ndesc, 0xFF) -
			    VR_GET8(vrp->acc_reg,
			    VR_FCR0_RXBUFCOUNT));

			/*
			 * Request pause when we have 4 descs left.
			 */
			VR_SETBITS8(vrp->acc_reg, VR_FCR1,
			    VR_FCR1_PAUSEONBITS, VR_FCR1_PAUSEON_04);

			/*
			 * Cancel the pause when there are 24 descriptors again.
			 */
			VR_SETBITS8(vrp->acc_reg, VR_FCR1,
			    VR_FCR1_PAUSEOFFBITS, VR_FCR1_PAUSEOFF_24);

			/*
			 * Request a pause of FFFF bit-times. This long pause
			 * is cancelled when the high watermark is reached.
			 */
			VR_PUT16(vrp->acc_reg, VR_FCR2_PAUSE, 0xFFFF);

			/*
			 * Enable flow control on the MAC.
			 */
			VR_SETBIT8(vrp->acc_reg, VR_MISC0, VR_MISC0_FDXTFEN);
			VR_SETBIT8(vrp->acc_reg, VR_FCR1, VR_FCR1_FD_RX_EN |
			    VR_FCR1_FD_TX_EN | VR_FCR1_XONXOFF_EN);
		}
	} else {
		/*
		 * Turn flow control OFF.
		 */
		VR_CLRBIT8(vrp->acc_reg,
		    VR_MISC0, VR_MISC0_FDXRFEN | VR_MISC0_FDXTFEN);
		if ((vrp->chip.info.features & VR_FEATURE_TX_PAUSE_CAP) != 0) {
			VR_CLRBIT8(vrp->acc_reg, VR_FCR1,
			    VR_FCR1_FD_RX_EN | VR_FCR1_FD_TX_EN |
			    VR_FCR1_XONXOFF_EN);
		}
	}

	/*
	 * Set link state.
	 */
	if ((vrp->chip.mii.status & MII_STATUS_LINKUP) != 0)
		vrp->chip.link.state = VR_LINK_STATE_UP;
	else
		vrp->chip.link.state = VR_LINK_STATE_DOWN;
}

/*
 * The PHY is automatically polled by the MAC once per 1024 MD clock cycles
 * MD is clocked once per 960ns so polling happens about every 1M ns, some
 * 1000 times per second
 * This polling process is required for the functionality of the link change
 * interrupt. Polling process must be disabled in order to access PHY registers
 * using MDIO
 *
 * Turn off PHY polling so that the PHY registers can be accessed.
 */
static void
vr_phy_autopoll_disable(vr_t *vrp)
{
	uint32_t	time;
	uint8_t		miicmd, miiaddr;

	/*
	 * Special procedure to stop the autopolling.
	 */
	if ((vrp->chip.info.bugs & VR_BUG_MIIPOLLSTOP) != 0) {
		/*
		 * If polling is enabled.
		 */
		miicmd = VR_GET8(vrp->acc_reg, VR_MIICMD);
		if ((miicmd & VR_MIICMD_MD_AUTO) != 0) {
			/*
			 * Wait for the end of a cycle (mdone set).
			 */
			time = 0;
			do {
				drv_usecwait(10);
				if (time >= VR_MMI_WAITMAX) {
					vr_log(vrp, CE_WARN,
					    "Timeout in "
					    "disable MII polling");
					break;
				}
				time += VR_MMI_WAITINCR;
				miiaddr = VR_GET8(vrp->acc_reg, VR_MIIADDR);
			} while ((miiaddr & VR_MIIADDR_MDONE) == 0);
		}
		/*
		 * Once paused, we can disable autopolling.
		 */
		VR_PUT8(vrp->acc_reg, VR_MIICMD, 0);
	} else {
		/*
		 * Turn off MII polling.
		 */
		VR_PUT8(vrp->acc_reg, VR_MIICMD, 0);

		/*
		 * Wait for MIDLE in MII address register.
		 */
		time = 0;
		do {
			drv_usecwait(VR_MMI_WAITINCR);
			if (time >= VR_MMI_WAITMAX) {
				vr_log(vrp, CE_WARN,
				    "Timeout in disable MII polling");
				break;
			}
			time += VR_MMI_WAITINCR;
			miiaddr = VR_GET8(vrp->acc_reg, VR_MIIADDR);
		} while ((miiaddr & VR_MIIADDR_MIDLE) == 0);
	}
}

/*
 * Turn on PHY polling. PHY's registers cannot be accessed.
 */
static void
vr_phy_autopoll_enable(vr_t *vrp)
{
	uint32_t	time;

	VR_PUT8(vrp->acc_reg, VR_MIICMD, 0);
	VR_PUT8(vrp->acc_reg, VR_MIIADDR, MII_STATUS|VR_MIIADDR_MAUTO);
	VR_PUT8(vrp->acc_reg, VR_MIICMD, VR_MIICMD_MD_AUTO);

	/*
	 * Wait for the polling process to finish.
	 */
	time = 0;
	do {
		drv_usecwait(VR_MMI_WAITINCR);
		if (time >= VR_MMI_WAITMAX) {
			vr_log(vrp, CE_NOTE, "Timeout in enable MII polling");
			break;
		}
		time += VR_MMI_WAITINCR;
	} while ((VR_GET8(vrp->acc_reg, VR_MIIADDR) & VR_MIIADDR_MDONE) == 0);

	/*
	 * Initiate a polling.
	 */
	VR_SETBIT8(vrp->acc_reg, VR_MIIADDR, VR_MIIADDR_MAUTO);
}

/*
 * Read a register from the PHY using MDIO.
 */
static void
vr_phy_read(vr_t *vrp, int offset, uint16_t *value)
{
	uint32_t	time;

	vr_phy_autopoll_disable(vrp);

	/*
	 * Write the register number to the lower 5 bits of the MII address
	 * register.
	 */
	VR_SETBITS8(vrp->acc_reg, VR_MIIADDR, VR_MIIADDR_BITS, offset);

	/*
	 * Write a READ command to the MII control register
	 * This bit will be cleared when the read is finished.
	 */
	VR_SETBIT8(vrp->acc_reg, VR_MIICMD, VR_MIICMD_MD_READ);

	/*
	 * Wait until the read is done.
	 */
	time = 0;
	do {
		drv_usecwait(VR_MMI_WAITINCR);
		if (time >= VR_MMI_WAITMAX) {
			vr_log(vrp, CE_NOTE, "Timeout in MII read command");
			break;
		}
		time += VR_MMI_WAITINCR;
	} while ((VR_GET8(vrp->acc_reg, VR_MIICMD) & VR_MIICMD_MD_READ) != 0);

	*value = VR_GET16(vrp->acc_reg, VR_MIIDATA);
	vr_phy_autopoll_enable(vrp);
}

/*
 * Write to a PHY's register.
 */
static void
vr_phy_write(vr_t *vrp, int offset, uint16_t value)
{
	uint32_t	time;

	vr_phy_autopoll_disable(vrp);

	/*
	 * Write the register number to the MII address register.
	 */
	VR_SETBITS8(vrp->acc_reg, VR_MIIADDR, VR_MIIADDR_BITS, offset);

	/*
	 * Write the value to the data register.
	 */
	VR_PUT16(vrp->acc_reg, VR_MIIDATA, value);

	/*
	 * Issue the WRITE command to the command register.
	 * This bit will be cleared when the write is finished.
	 */
	VR_SETBIT8(vrp->acc_reg, VR_MIICMD, VR_MIICMD_MD_WRITE);

	time = 0;
	do {
		drv_usecwait(VR_MMI_WAITINCR);
		if (time >= VR_MMI_WAITMAX) {
			vr_log(vrp, CE_NOTE, "Timeout in MII write command");
			break;
		}
		time += VR_MMI_WAITINCR;
	} while ((VR_GET8(vrp->acc_reg, VR_MIICMD) & VR_MIICMD_MD_WRITE) != 0);
	vr_phy_autopoll_enable(vrp);
}

/*
 * Initialize and install some private kstats.
 */
typedef struct {
	char		*name;
	uchar_t		type;
} vr_kstat_t;

static const vr_kstat_t vr_driver_stats [] = {
	{"allocbfail",		KSTAT_DATA_INT32},
	{"intr_claimed",	KSTAT_DATA_INT64},
	{"intr_unclaimed",	KSTAT_DATA_INT64},
	{"linkchanges",		KSTAT_DATA_INT64},
	{"txnfree",		KSTAT_DATA_INT32},
	{"txstalls",		KSTAT_DATA_INT32},
	{"resets",		KSTAT_DATA_INT32},
	{"txreclaims",		KSTAT_DATA_INT64},
	{"txreclaim0",		KSTAT_DATA_INT64},
	{"cyclics",		KSTAT_DATA_INT64},
	{"txchecks",		KSTAT_DATA_INT64},
};

static void
vr_kstats_init(vr_t *vrp)
{
	kstat_t			*ksp;
	struct	kstat_named	*knp;
	int			i;
	int			nstats;

	nstats = sizeof (vr_driver_stats) / sizeof (vr_kstat_t);

	ksp = kstat_create(MODULENAME, ddi_get_instance(vrp->devinfo),
	    "driver", "net", KSTAT_TYPE_NAMED, nstats, 0);

	if (ksp == NULL)
		vr_log(vrp, CE_WARN, "kstat_create failed");

	ksp->ks_update = vr_update_kstats;
	ksp->ks_private = (void*) vrp;
	knp = ksp->ks_data;

	for (i = 0; i < nstats; i++, knp++) {
		kstat_named_init(knp, vr_driver_stats[i].name,
		    vr_driver_stats[i].type);
	}
	kstat_install(ksp);
	vrp->ksp = ksp;
}

static int
vr_update_kstats(kstat_t *ksp, int access)
{
	vr_t			*vrp;
	struct kstat_named	*knp;

	vrp = (vr_t *)ksp->ks_private;
	knp = ksp->ks_data;

	if (access != KSTAT_READ)
		return (EACCES);

	(knp++)->value.ui32 = vrp->stats.allocbfail;
	(knp++)->value.ui64 = vrp->stats.intr_claimed;
	(knp++)->value.ui64 = vrp->stats.intr_unclaimed;
	(knp++)->value.ui64 = vrp->stats.linkchanges;
	(knp++)->value.ui32 = vrp->tx.nfree;
	(knp++)->value.ui32 = vrp->stats.txstalls;
	(knp++)->value.ui32 = vrp->stats.resets;
	(knp++)->value.ui64 = vrp->stats.txreclaims;
	(knp++)->value.ui64 = vrp->stats.txreclaim0;
	(knp++)->value.ui64 = vrp->stats.cyclics;
	(knp++)->value.ui64 = vrp->stats.txchecks;
	return (0);
}

/*
 * Remove 'private' kstats.
 */
static void
vr_remove_kstats(vr_t *vrp)
{
	if (vrp->ksp != NULL)
		kstat_delete(vrp->ksp);
}

/*
 * Get a property of the device/driver
 * Remarks:
 * - pr_val is always an integer of size pr_valsize
 * - ENABLED (EN) is what is configured via dladm
 * - ADVERTISED (ADV) is ENABLED minus constraints, like PHY/MAC capabilities
 * - DEFAULT are driver- and hardware defaults (DEFAULT is implemented as a
 *   flag in pr_flags instead of MAC_PROP_DEFAULT_)
 * - perm is the permission printed on ndd -get /.. \?
 */
int
vr_mac_getprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, void *pr_val)
{
	vr_t		*vrp;
	uint32_t	err;
	uint64_t	val;

	/* Since we have no private properties */
	_NOTE(ARGUNUSED(pr_name))

	err = 0;
	vrp = (vr_t *)arg;
	switch (pr_num) {
		case MAC_PROP_ADV_1000FDX_CAP:
		case MAC_PROP_ADV_1000HDX_CAP:
		case MAC_PROP_EN_1000FDX_CAP:
		case MAC_PROP_EN_1000HDX_CAP:
			val = 0;
			break;

		case MAC_PROP_ADV_100FDX_CAP:
			val = (vrp->chip.mii.anadv &
			    MII_ABILITY_100BASE_TX_FD) != 0;
			break;

		case MAC_PROP_ADV_100HDX_CAP:
			val = (vrp->chip.mii.anadv &
			    MII_ABILITY_100BASE_TX) != 0;
			break;

		case MAC_PROP_ADV_100T4_CAP:
			val = (vrp->chip.mii.anadv &
			    MII_ABILITY_100BASE_T4) != 0;
			break;

		case MAC_PROP_ADV_10FDX_CAP:
			val = (vrp->chip.mii.anadv &
			    MII_ABILITY_10BASE_T_FD) != 0;
			break;

		case MAC_PROP_ADV_10HDX_CAP:
			val = (vrp->chip.mii.anadv &
			    MII_ABILITY_10BASE_T) != 0;
			break;

		case MAC_PROP_AUTONEG:
			val = (vrp->chip.mii.control &
			    MII_CONTROL_ANE) != 0;
			break;

		case MAC_PROP_DUPLEX:
			val = vrp->chip.link.duplex;
			break;

		case MAC_PROP_EN_100FDX_CAP:
			val = (vrp->param.anadv_en &
			    MII_ABILITY_100BASE_TX_FD) != 0;
			break;

		case MAC_PROP_EN_100HDX_CAP:
			val = (vrp->param.anadv_en &
			    MII_ABILITY_100BASE_TX) != 0;
			break;

		case MAC_PROP_EN_100T4_CAP:
			val = (vrp->param.anadv_en &
			    MII_ABILITY_100BASE_T4) != 0;
			break;

		case MAC_PROP_EN_10FDX_CAP:
			val = (vrp->param.anadv_en &
			    MII_ABILITY_10BASE_T_FD) != 0;
			break;

		case MAC_PROP_EN_10HDX_CAP:
			val = (vrp->param.anadv_en &
			    MII_ABILITY_10BASE_T) != 0;
			break;

		case MAC_PROP_EN_AUTONEG:
			val = vrp->param.an_en == VR_LINK_AUTONEG_ON;
			break;

		case MAC_PROP_FLOWCTRL:
			val = vrp->chip.link.flowctrl;
			break;

		case MAC_PROP_MTU:
			val = vrp->param.mtu;
			break;

		case MAC_PROP_SPEED:
			if (vrp->chip.link.speed ==
			    VR_LINK_SPEED_100MBS)
				val = 100 * 1000 * 1000;
			else if (vrp->chip.link.speed ==
			    VR_LINK_SPEED_10MBS)
				val = 10 * 1000 * 1000;
			else
				val = 0;
			break;

		case MAC_PROP_STATUS:
			val = vrp->chip.link.state;
			break;

		default:
			err = ENOTSUP;
			break;
	}

	if (err == 0 && pr_num != MAC_PROP_PRIVATE) {
		if (pr_valsize == sizeof (uint64_t))
			*(uint64_t *)pr_val = val;
		else if (pr_valsize == sizeof (uint32_t))
			*(uint32_t *)pr_val = val;
		else if (pr_valsize == sizeof (uint16_t))
			*(uint16_t *)pr_val = val;
		else if (pr_valsize == sizeof (uint8_t))
			*(uint8_t *)pr_val = val;
		else
			err = EINVAL;
	}
	return (err);
}

void
vr_mac_propinfo(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    mac_prop_info_handle_t prh)
{
	vr_t		*vrp = (vr_t *)arg;
	uint8_t		val, perm;

	/* Since we have no private properties */
	_NOTE(ARGUNUSED(pr_name))

	switch (pr_num) {
		case MAC_PROP_ADV_1000FDX_CAP:
		case MAC_PROP_ADV_1000HDX_CAP:
		case MAC_PROP_EN_1000FDX_CAP:
		case MAC_PROP_EN_1000HDX_CAP:
		case MAC_PROP_ADV_100FDX_CAP:
		case MAC_PROP_ADV_100HDX_CAP:
		case MAC_PROP_ADV_100T4_CAP:
		case MAC_PROP_ADV_10FDX_CAP:
		case MAC_PROP_ADV_10HDX_CAP:
			mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
			return;

		case MAC_PROP_EN_100FDX_CAP:
			val = (vrp->chip.mii.status &
			    MII_STATUS_100_BASEX_FD) != 0;
			break;

		case MAC_PROP_EN_100HDX_CAP:
			val = (vrp->chip.mii.status &
			    MII_STATUS_100_BASEX) != 0;
			break;

		case MAC_PROP_EN_100T4_CAP:
			val = (vrp->chip.mii.status &
			    MII_STATUS_100_BASE_T4) != 0;
			break;

		case MAC_PROP_EN_10FDX_CAP:
			val = (vrp->chip.mii.status &
			    MII_STATUS_10_FD) != 0;
			break;

		case MAC_PROP_EN_10HDX_CAP:
			val = (vrp->chip.mii.status &
			    MII_STATUS_10) != 0;
			break;

		case MAC_PROP_AUTONEG:
		case MAC_PROP_EN_AUTONEG:
			val = (vrp->chip.mii.status &
			    MII_STATUS_CANAUTONEG) != 0;
			break;

		case MAC_PROP_FLOWCTRL:
			mac_prop_info_set_default_link_flowctrl(prh,
			    LINK_FLOWCTRL_BI);
			return;

		case MAC_PROP_MTU:
			mac_prop_info_set_range_uint32(prh,
			    ETHERMTU, ETHERMTU);
			return;

		case MAC_PROP_DUPLEX:
			/*
			 * Writability depends on autoneg.
			 */
			perm = ((vrp->chip.mii.control &
			    MII_CONTROL_ANE) == 0) ? MAC_PROP_PERM_RW :
			    MAC_PROP_PERM_READ;
			mac_prop_info_set_perm(prh, perm);

			if (perm == MAC_PROP_PERM_RW) {
				mac_prop_info_set_default_uint8(prh,
				    VR_LINK_DUPLEX_FULL);
			}
			return;

		case MAC_PROP_SPEED:
			perm = ((vrp->chip.mii.control &
			    MII_CONTROL_ANE) == 0) ?
			    MAC_PROP_PERM_RW : MAC_PROP_PERM_READ;
			mac_prop_info_set_perm(prh, perm);

			if (perm == MAC_PROP_PERM_RW) {
				mac_prop_info_set_default_uint64(prh,
				    100 * 1000 * 1000);
			}
			return;

		case MAC_PROP_STATUS:
			mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
			return;

		default:
			return;
		}

		mac_prop_info_set_default_uint8(prh, val);
}

/*
 * Set a property of the device.
 */
int
vr_mac_setprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
	uint_t pr_valsize, const void *pr_val)
{
	vr_t		*vrp;
	uint32_t	err;
	uint64_t	val;

	/* Since we have no private properties */
	_NOTE(ARGUNUSED(pr_name))

	err = 0;
	vrp = (vr_t *)arg;
	mutex_enter(&vrp->oplock);

	/*
	 * The current set of public property values are passed as integers
	 * Private properties are passed as strings in pr_val length pr_valsize.
	 */
	if (pr_num != MAC_PROP_PRIVATE) {
		if (pr_valsize == sizeof (uint64_t))
			val = *(uint64_t *)pr_val;
		else if (pr_valsize == sizeof (uint32_t))
			val = *(uint32_t *)pr_val;
		else if (pr_valsize == sizeof (uint16_t))
			val = *(uint32_t *)pr_val;
		else if (pr_valsize == sizeof (uint8_t))
			val = *(uint8_t *)pr_val;
		else {
			mutex_exit(&vrp->oplock);
			return (EINVAL);
		}
	}

	switch (pr_num) {
		case MAC_PROP_DUPLEX:
			if ((vrp->chip.mii.control & MII_CONTROL_ANE) == 0) {
				if (val == LINK_DUPLEX_FULL)
					vrp->chip.mii.control |=
					    MII_CONTROL_FDUPLEX;
				else if (val == LINK_DUPLEX_HALF)
					vrp->chip.mii.control &=
					    ~MII_CONTROL_FDUPLEX;
				else
					err = EINVAL;
			} else
				err = EINVAL;
			break;

		case MAC_PROP_EN_100FDX_CAP:
			if (val == 0)
				vrp->param.anadv_en &=
				    ~MII_ABILITY_100BASE_TX_FD;
			else
				vrp->param.anadv_en |=
				    MII_ABILITY_100BASE_TX_FD;
			break;

		case MAC_PROP_EN_100HDX_CAP:
			if (val == 0)
				vrp->param.anadv_en &=
				    ~MII_ABILITY_100BASE_TX;
			else
				vrp->param.anadv_en |=
				    MII_ABILITY_100BASE_TX;
			break;

		case MAC_PROP_EN_100T4_CAP:
			if (val == 0)
				vrp->param.anadv_en &=
				    ~MII_ABILITY_100BASE_T4;
			else
				vrp->param.anadv_en |=
				    MII_ABILITY_100BASE_T4;
			break;

		case MAC_PROP_EN_10FDX_CAP:
			if (val == 0)
				vrp->param.anadv_en &=
				    ~MII_ABILITY_10BASE_T_FD;
			else
				vrp->param.anadv_en |=
				    MII_ABILITY_10BASE_T_FD;
			break;

		case MAC_PROP_EN_10HDX_CAP:
			if (val == 0)
				vrp->param.anadv_en &=
				    ~MII_ABILITY_10BASE_T;
			else
				vrp->param.anadv_en |=
				    MII_ABILITY_10BASE_T;
			break;

		case MAC_PROP_AUTONEG:
		case MAC_PROP_EN_AUTONEG:
			if (val == 0) {
				vrp->param.an_en = VR_LINK_AUTONEG_OFF;
				vrp->chip.mii.control &= ~MII_CONTROL_ANE;
			} else {
				vrp->param.an_en = VR_LINK_AUTONEG_ON;
				if ((vrp->chip.mii.status &
				    MII_STATUS_CANAUTONEG) != 0)
					vrp->chip.mii.control |=
					    MII_CONTROL_ANE;
				else
					err = EINVAL;
			}
			break;

		case MAC_PROP_FLOWCTRL:
			if (val == LINK_FLOWCTRL_NONE)
				vrp->param.anadv_en &= ~MII_ABILITY_PAUSE;
			else if (val == LINK_FLOWCTRL_BI)
				vrp->param.anadv_en |= MII_ABILITY_PAUSE;
			else
				err = EINVAL;
			break;

		case MAC_PROP_MTU:
			if (val >= ETHERMIN && val <= ETHERMTU)
				vrp->param.mtu = (uint32_t)val;
			else
				err = EINVAL;
			break;

		case MAC_PROP_SPEED:
			if (val == 10 * 1000 * 1000)
				vrp->chip.link.speed =
				    VR_LINK_SPEED_10MBS;
			else if (val == 100 * 1000 * 1000)
				vrp->chip.link.speed =
				    VR_LINK_SPEED_100MBS;
			else
				err = EINVAL;
			break;

		default:
			err = ENOTSUP;
			break;
	}
	if (err == 0 && pr_num != MAC_PROP_PRIVATE) {
		vrp->chip.mii.anadv = vrp->param.anadv_en &
		    (vrp->param.an_phymask & vrp->param.an_macmask);
		vr_link_init(vrp);
	}
	mutex_exit(&vrp->oplock);
	return (err);
}


/*
 * Logging and debug functions.
 */
static struct {
	kmutex_t mutex[1];
	const char *ifname;
	const char *fmt;
	int level;
} prtdata;

static void
vr_vprt(const char *fmt, va_list args)
{
	char buf[512];

	ASSERT(mutex_owned(prtdata.mutex));
	(void) vsnprintf(buf, sizeof (buf), fmt, args);
	cmn_err(prtdata.level, prtdata.fmt, prtdata.ifname, buf);
}

static void
vr_log(vr_t *vrp, int level, const char *fmt, ...)
{
	va_list args;

	mutex_enter(prtdata.mutex);
	prtdata.ifname = vrp->ifname;
	prtdata.fmt = "!%s: %s";
	prtdata.level = level;

	va_start(args, fmt);
	vr_vprt(fmt, args);
	va_end(args);

	mutex_exit(prtdata.mutex);
}

#if defined(DEBUG)
static void
vr_prt(const char *fmt, ...)
{
	va_list args;

	ASSERT(mutex_owned(prtdata.mutex));

	va_start(args, fmt);
	vr_vprt(fmt, args);
	va_end(args);

	mutex_exit(prtdata.mutex);
}

void
(*vr_debug())(const char *fmt, ...)
{
	mutex_enter(prtdata.mutex);
	prtdata.ifname = MODULENAME;
	prtdata.fmt = "^%s: %s\n";
	prtdata.level = CE_CONT;

	return (vr_prt);
}
#endif	/* DEBUG */

DDI_DEFINE_STREAM_OPS(vr_dev_ops, nulldev, nulldev, vr_attach, vr_detach,
nodev, NULL, D_MP, NULL, vr_quiesce);

static struct modldrv vr_modldrv = {
	&mod_driverops,		/* Type of module. This one is a driver */
	vr_ident,		/* short description */
	&vr_dev_ops		/* driver specific ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&vr_modldrv, NULL
};

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_init(void)
{
	int	status;

	mac_init_ops(&vr_dev_ops, MODULENAME);
	status = mod_install(&modlinkage);
	if (status == DDI_SUCCESS)
		mutex_init(prtdata.mutex, NULL, MUTEX_DRIVER, NULL);
	else
		mac_fini_ops(&vr_dev_ops);
	return (status);
}

int
_fini(void)
{
	int status;

	status = mod_remove(&modlinkage);
	if (status == 0) {
		mac_fini_ops(&vr_dev_ops);
		mutex_destroy(prtdata.mutex);
	}
	return (status);
}
