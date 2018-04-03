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


/*
 * dnet -- DEC 21x4x
 *
 * Currently supports:
 *	21040, 21041, 21140, 21142, 21143
 *	SROM versions 1, 3, 3.03, 4
 *	TP, AUI, BNC, 100BASETX, 100BASET4
 *
 * XXX NEEDSWORK
 *	All media SHOULD work, FX is untested
 *
 * Depends on the Generic LAN Driver utility functions in /kernel/misc/mac
 */

#define	BUG_4010796	/* See 4007871, 4010796 */

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
#include <sys/dlpi.h>
#include <sys/ethernet.h>
#include <sys/vlan.h>
#include <sys/mac.h>
#include <sys/mac_ether.h>
#include <sys/mac_provider.h>
#include <sys/pci.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/strsun.h>

#include "dnet_mii.h"
#include "dnet.h"

/*
 *	Declarations and Module Linkage
 */

#define	IDENT	"DNET 21x4x"

/*
 * #define	DNET_NOISY
 * #define	SROMDEBUG
 * #define	SROMDUMPSTRUCTURES
 */

#ifdef DNETDEBUG
#ifdef DNET_NOISY
int	dnetdebug = -1;
#else
int	dnetdebug = 0;
#endif
#endif

/* used for message allocated using desballoc() */
struct free_ptr {
	struct free_rtn	free_rtn;
	caddr_t buf;
};

struct rbuf_list {
	struct rbuf_list	*rbuf_next;	/* next in the list */
	caddr_t			rbuf_vaddr;	/* virual addr of the buf */
	uint32_t		rbuf_paddr;	/* physical addr of the buf */
	uint32_t		rbuf_endpaddr;	/* physical addr at the end */
	ddi_dma_handle_t	rbuf_dmahdl;	/* dma handle */
	ddi_acc_handle_t	rbuf_acchdl;	/* handle for DDI functions */
};

/* Required system entry points */
static int dnet_probe(dev_info_t *);
static int dnet_attach(dev_info_t *, ddi_attach_cmd_t);
static int dnet_detach(dev_info_t *, ddi_detach_cmd_t);
static int dnet_quiesce(dev_info_t *);

/* Required driver entry points for GLDv3 */
static int dnet_m_start(void *);
static void dnet_m_stop(void *);
static int dnet_m_getstat(void *, uint_t, uint64_t *);
static int dnet_m_setpromisc(void *, boolean_t);
static int dnet_m_multicst(void *, boolean_t, const uint8_t *);
static int dnet_m_unicst(void *, const uint8_t *);
static mblk_t *dnet_m_tx(void *, mblk_t *);

static uint_t dnet_intr(caddr_t);

/* Internal functions used by the above entry points */
static void write_gpr(struct dnetinstance *dnetp, uint32_t val);
static void dnet_reset_board(struct dnetinstance *);
static void dnet_init_board(struct dnetinstance *);
static void dnet_chip_init(struct dnetinstance *);
static uint32_t hashindex(const uint8_t *);
static int dnet_start(struct dnetinstance *);
static int dnet_set_addr(struct dnetinstance *);

static boolean_t dnet_send(struct dnetinstance *, mblk_t *);

static void dnet_getp(struct dnetinstance *);
static void update_rx_stats(struct dnetinstance *, int);
static void update_tx_stats(struct dnetinstance *, int);

/* Media Selection Setup Routines */
static void set_gpr(struct dnetinstance *);
static void set_opr(struct dnetinstance *);
static void set_sia(struct dnetinstance *);

/* Buffer Management Routines */
static int dnet_alloc_bufs(struct dnetinstance *);
static void dnet_free_bufs(struct dnetinstance *);
static void dnet_init_txrx_bufs(struct dnetinstance *);
static int alloc_descriptor(struct dnetinstance *);
static void dnet_reclaim_Tx_desc(struct dnetinstance *);
static int dnet_rbuf_init(dev_info_t *, int);
static int dnet_rbuf_destroy();
static struct rbuf_list *dnet_rbuf_alloc(dev_info_t *, int);
static void dnet_rbuf_free(caddr_t);
static void dnet_freemsg_buf(struct free_ptr *);

static void setup_block(struct dnetinstance *);

/* SROM read functions */
static int dnet_read_srom(dev_info_t *, int, ddi_acc_handle_t, caddr_t,
    uchar_t *, int);
static void dnet_read21040addr(dev_info_t *, ddi_acc_handle_t, caddr_t,
    uchar_t *, int *);
static void dnet_read21140srom(ddi_acc_handle_t, caddr_t, uchar_t *, int);
static int get_alternative_srom_image(dev_info_t *, uchar_t *, int);
static void dnet_print_srom(SROM_FORMAT *sr);
static void dnet_dump_leaf(LEAF_FORMAT *leaf);
static void dnet_dump_block(media_block_t *block);
#ifdef BUG_4010796
static void set_alternative_srom_image(dev_info_t *, uchar_t *, int);
static int dnet_hack(dev_info_t *);
#endif

static int dnet_hack_interrupts(struct dnetinstance *, int);
static int dnet_detach_hacked_interrupt(dev_info_t *devinfo);
static void enable_interrupts(struct dnetinstance *);

/* SROM parsing functions */
static void dnet_parse_srom(struct dnetinstance *dnetp, SROM_FORMAT *sr,
    uchar_t *vi);
static void parse_controller_leaf(struct dnetinstance *dnetp, LEAF_FORMAT *leaf,
    uchar_t *vi);
static uchar_t *parse_media_block(struct dnetinstance *dnetp,
    media_block_t *block, uchar_t *vi);
static int check_srom_valid(uchar_t *);
static void dnet_dumpbin(char *msg, uchar_t *, int size, int len);
static void setup_legacy_blocks();
/* Active Media Determination Routines */
static void find_active_media(struct dnetinstance *);
static int send_test_packet(struct dnetinstance *);
static int dnet_link_sense(struct dnetinstance *);

/* PHY MII Routines */
static ushort_t dnet_mii_read(dev_info_t *dip, int phy_addr, int reg_num);
static void dnet_mii_write(dev_info_t *dip, int phy_addr, int reg_num,
			int reg_dat);
static void write_mii(struct dnetinstance *, uint32_t, int);
static void mii_tristate(struct dnetinstance *);
static void do_phy(struct dnetinstance *);
static void dnet_mii_link_cb(dev_info_t *, int, enum mii_phy_state);
static void set_leaf(SROM_FORMAT *sr, LEAF_FORMAT *leaf);

#ifdef DNETDEBUG
uint32_t dnet_usecelapsed(struct dnetinstance *dnetp);
void dnet_timestamp(struct dnetinstance *, char *);
void dnet_usectimeout(struct dnetinstance *, uint32_t, int, timercb_t);
#endif
static char *media_str[] = {
	"10BaseT",
	"10Base2",
	"10Base5",
	"100BaseTX",
	"10BaseT FD",
	"100BaseTX FD",
	"100BaseT4",
	"100BaseFX",
	"100BaseFX FD",
	"MII"
};

/* default SROM info for cards with no SROMs */
static LEAF_FORMAT leaf_default_100;
static LEAF_FORMAT leaf_asante;
static LEAF_FORMAT leaf_phylegacy;
static LEAF_FORMAT leaf_cogent_100;
static LEAF_FORMAT leaf_21041;
static LEAF_FORMAT leaf_21040;

/* rx buffer size (rounded up to 4) */
int rx_buf_size = (ETHERMAX + ETHERFCSL + VLAN_TAGSZ + 3) & ~3;

int max_rx_desc_21040 = MAX_RX_DESC_21040;
int max_rx_desc_21140 = MAX_RX_DESC_21140;
int max_tx_desc = MAX_TX_DESC;
int dnet_xmit_threshold = MAX_TX_DESC >> 2;	/* XXX need tuning? */

static kmutex_t dnet_rbuf_lock;		/* mutex to protect rbuf_list data */

/* used for buffers allocated by ddi_dma_mem_alloc() */
static ddi_dma_attr_t dma_attr = {
	DMA_ATTR_V0,		/* dma_attr version */
	0,			/* dma_attr_addr_lo */
	(uint64_t)0xFFFFFFFF,	/* dma_attr_addr_hi */
	0x7FFFFFFF,		/* dma_attr_count_max */
	4,			/* dma_attr_align */
	0x3F,			/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	(uint64_t)0xFFFFFFFF,	/* dma_attr_maxxfer */
	(uint64_t)0xFFFFFFFF,	/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0,			/* dma_attr_flags */
};

/* used for buffers allocated for rbuf, allow 2 cookies */
static ddi_dma_attr_t dma_attr_rb = {
	DMA_ATTR_V0,		/* dma_attr version */
	0,			/* dma_attr_addr_lo */
	(uint64_t)0xFFFFFFFF,	/* dma_attr_addr_hi */
	0x7FFFFFFF,		/* dma_attr_count_max */
	4,			/* dma_attr_align */
	0x3F,			/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	(uint64_t)0xFFFFFFFF,	/* dma_attr_maxxfer */
	(uint64_t)0xFFFFFFFF,	/* dma_attr_seg */
	2,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0,			/* dma_attr_flags */
};
/* used for buffers which are NOT from ddi_dma_mem_alloc() - xmit side */
static ddi_dma_attr_t dma_attr_tx = {
	DMA_ATTR_V0,		/* dma_attr version */
	0,			/* dma_attr_addr_lo */
	(uint64_t)0xFFFFFFFF,	/* dma_attr_addr_hi */
	0x7FFFFFFF,		/* dma_attr_count_max */
	1,			/* dma_attr_align */
	0x3F,			/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	(uint64_t)0xFFFFFFFF,	/* dma_attr_maxxfer */
	(uint64_t)0xFFFFFFFF,	/* dma_attr_seg */
	0x7FFF,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0,			/* dma_attr_flags */
};

static ddi_device_acc_attr_t accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC,
};

uchar_t dnet_broadcastaddr[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

/* Standard Module linkage initialization for a Streams driver */
extern struct mod_ops mod_driverops;

DDI_DEFINE_STREAM_OPS(dnet_devops, nulldev, dnet_probe, dnet_attach,
    dnet_detach, nodev, NULL, D_MP, NULL, dnet_quiesce);

static struct modldrv dnet_modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	IDENT,			/* short description */
	&dnet_devops		/* driver specific ops */
};

static struct modlinkage dnet_modlinkage = {
	MODREV_1,		/* ml_rev */
	{ &dnet_modldrv, NULL }	/* ml_linkage */
};

static mac_callbacks_t dnet_m_callbacks = {
	0,			/* mc_callbacks */
	dnet_m_getstat,		/* mc_getstat */
	dnet_m_start,		/* mc_start */
	dnet_m_stop,		/* mc_stop */
	dnet_m_setpromisc,	/* mc_setpromisc */
	dnet_m_multicst,	/* mc_multicst */
	dnet_m_unicst,		/* mc_unicst */
	dnet_m_tx,		/* mc_tx */
	NULL,
	NULL,			/* mc_ioctl */
	NULL,			/* mc_getcapab */
	NULL,			/* mc_open */
	NULL			/* mc_close */
};

/*
 * Passed to the hacked interrupt for multiport Cogent and ZNYX cards with
 * dodgy interrupt routing
 */
#define	MAX_INST 8 /* Maximum instances on a multiport adapter. */
struct hackintr_inf
{
	struct dnetinstance *dnetps[MAX_INST]; /* dnetps for each port */
	dev_info_t *devinfo;		    /* Devinfo of the primary device */
	kmutex_t lock;
		/* Ensures the interrupt doesn't get called while detaching */
};
static char hackintr_propname[] = "InterruptData";
static char macoffset_propname[] = "MAC_offset";
static char speed_propname[] = "speed";
static char ofloprob_propname[] = "dmaworkaround";
static char duplex_propname[] = "full-duplex"; /* Must agree with MII */
static char printsrom_propname[] = "print-srom";

static uint_t dnet_hack_intr(struct hackintr_inf *);

int
_init(void)
{
	int i;

	/* Configure fake sroms for legacy cards */
	mutex_init(&dnet_rbuf_lock, NULL, MUTEX_DRIVER, NULL);
	setup_legacy_blocks();

	mac_init_ops(&dnet_devops, "dnet");

	if ((i = mod_install(&dnet_modlinkage)) != 0) {
		mac_fini_ops(&dnet_devops);
		mutex_destroy(&dnet_rbuf_lock);
	}
	return (i);
}

int
_fini(void)
{
	int i;

	if ((i = mod_remove(&dnet_modlinkage)) == 0) {
		mac_fini_ops(&dnet_devops);

		/* loop until all the receive buffers are freed */
		while (dnet_rbuf_destroy() != 0) {
			delay(drv_usectohz(100000));
#ifdef DNETDEBUG
			if (dnetdebug & DNETDDI)
				cmn_err(CE_WARN, "dnet _fini delay");
#endif
		}
		mutex_destroy(&dnet_rbuf_lock);
	}
	return (i);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&dnet_modlinkage, modinfop));
}

/*
 * probe(9E) -- Determine if a device is present
 */
static int
dnet_probe(dev_info_t *devinfo)
{
	ddi_acc_handle_t handle;
	uint16_t	vendorid;
	uint16_t	deviceid;

	if (pci_config_setup(devinfo, &handle) != DDI_SUCCESS)
		return (DDI_PROBE_FAILURE);

	vendorid = pci_config_get16(handle, PCI_CONF_VENID);

	if (vendorid != DEC_VENDOR_ID) {
		pci_config_teardown(&handle);
		return (DDI_PROBE_FAILURE);
	}

	deviceid = pci_config_get16(handle, PCI_CONF_DEVID);
	switch (deviceid) {
	case DEVICE_ID_21040:
	case DEVICE_ID_21041:
	case DEVICE_ID_21140:
	case DEVICE_ID_21143: /* And 142 */
		break;
	default:
		pci_config_teardown(&handle);
		return (DDI_PROBE_FAILURE);
	}

	pci_config_teardown(&handle);
#ifndef BUG_4010796
	return (DDI_PROBE_SUCCESS);
#else
	return (dnet_hack(devinfo));
#endif
}

#ifdef BUG_4010796
/*
 * If we have a device, but we cannot presently access its SROM data,
 * then we return DDI_PROBE_PARTIAL and hope that sometime later we
 * will be able to get at the SROM data.  This can only happen if we
 * are a secondary port with no SROM, and the bootstrap failed to set
 * our DNET_SROM property, and our primary sibling has not yet probed.
 */
static int
dnet_hack(dev_info_t *devinfo)
{
	uchar_t 	vendor_info[SROM_SIZE];
	uint32_t	csr;
	uint16_t	deviceid;
	ddi_acc_handle_t handle;
	uint32_t	retval;
	int		secondary;
	ddi_acc_handle_t io_handle;
	caddr_t		io_reg;

#define	DNET_PCI_RNUMBER	1

	if (pci_config_setup(devinfo, &handle) != DDI_SUCCESS)
		return (DDI_PROBE_FAILURE);

	deviceid = pci_config_get16(handle, PCI_CONF_DEVID);

	/*
	 * Turn on Master Enable and IO Enable bits.
	 */
	csr = pci_config_get32(handle, PCI_CONF_COMM);
	pci_config_put32(handle, PCI_CONF_COMM, (csr |PCI_COMM_ME|PCI_COMM_IO));

	pci_config_teardown(&handle);

	/* Now map I/O register */
	if (ddi_regs_map_setup(devinfo, DNET_PCI_RNUMBER,
	    &io_reg, 0, 0, &accattr, &io_handle) != DDI_SUCCESS) {
		return (DDI_PROBE_FAILURE);
	}

	/*
	 * Reset the chip
	 */
	ddi_put32(io_handle, REG32(io_reg, BUS_MODE_REG), SW_RESET);
	drv_usecwait(3);
	ddi_put32(io_handle, REG32(io_reg, BUS_MODE_REG), 0);
	drv_usecwait(8);

	secondary = dnet_read_srom(devinfo, deviceid, io_handle,
	    io_reg, vendor_info, sizeof (vendor_info));

	switch (secondary) {
	case -1:
		/* We can't access our SROM data! */
		retval = DDI_PROBE_PARTIAL;
		break;
	case 0:
		retval = DDI_PROBE_SUCCESS;
		break;
	default:
		retval = DDI_PROBE_SUCCESS;
	}

	ddi_regs_map_free(&io_handle);
	return (retval);
}
#endif /* BUG_4010796 */

/*
 * attach(9E) -- Attach a device to the system
 *
 * Called once for each board successfully probed.
 */
static int
dnet_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	uint16_t revid;
	struct dnetinstance 	*dnetp;		/* Our private device info */
	mac_register_t		*macp;
	uchar_t 		vendor_info[SROM_SIZE];
	uint32_t		csr;
	uint16_t		deviceid;
	ddi_acc_handle_t 	handle;
	int			secondary;

#define	DNET_PCI_RNUMBER	1

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		/* Get the driver private (dnetinstance) structure */
		dnetp = ddi_get_driver_private(devinfo);

		mutex_enter(&dnetp->intrlock);
		mutex_enter(&dnetp->txlock);
		dnet_reset_board(dnetp);
		dnet_init_board(dnetp);
		dnetp->suspended = B_FALSE;

		if (dnetp->running) {
			dnetp->need_tx_update = B_FALSE;
			mutex_exit(&dnetp->txlock);
			(void) dnet_start(dnetp);
			mutex_exit(&dnetp->intrlock);
			mac_tx_update(dnetp->mac_handle);
		} else {
			mutex_exit(&dnetp->txlock);
			mutex_exit(&dnetp->intrlock);
		}
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	if (pci_config_setup(devinfo, &handle) != DDI_SUCCESS)
		return (DDI_FAILURE);

	deviceid = pci_config_get16(handle, PCI_CONF_DEVID);
	switch (deviceid) {
	case DEVICE_ID_21040:
	case DEVICE_ID_21041:
	case DEVICE_ID_21140:
	case DEVICE_ID_21143: /* And 142 */
		break;
	default:
		pci_config_teardown(&handle);
		return (DDI_FAILURE);
	}

	/*
	 * Turn on Master Enable and IO Enable bits.
	 */
	csr = pci_config_get32(handle, PCI_CONF_COMM);
	pci_config_put32(handle, PCI_CONF_COMM, (csr |PCI_COMM_ME|PCI_COMM_IO));

	/* Make sure the device is not asleep */
	csr = pci_config_get32(handle, PCI_DNET_CONF_CFDD);
	pci_config_put32(handle, PCI_DNET_CONF_CFDD,
	    csr &  ~(CFDD_SLEEP|CFDD_SNOOZE));

	revid = pci_config_get8(handle, PCI_CONF_REVID);
	pci_config_teardown(&handle);

	dnetp = kmem_zalloc(sizeof (struct dnetinstance), KM_SLEEP);
	ddi_set_driver_private(devinfo, dnetp);

	/* Now map I/O register */
	if (ddi_regs_map_setup(devinfo, DNET_PCI_RNUMBER, &dnetp->io_reg,
	    0, 0, &accattr, &dnetp->io_handle) != DDI_SUCCESS) {
		kmem_free(dnetp, sizeof (struct dnetinstance));
		return (DDI_FAILURE);
	}

	dnetp->devinfo = devinfo;
	dnetp->board_type = deviceid;

	/*
	 * Get the iblock cookie with which to initialize the mutexes.
	 */
	if (ddi_get_iblock_cookie(devinfo, 0, &dnetp->icookie)
	    != DDI_SUCCESS)
		goto fail;

	/*
	 * Initialize mutex's for this device.
	 * Do this before registering the interrupt handler to avoid
	 * condition where interrupt handler can try using uninitialized
	 * mutex.
	 * Lock ordering rules: always lock intrlock first before
	 * txlock if both are required.
	 */
	mutex_init(&dnetp->txlock, NULL, MUTEX_DRIVER, dnetp->icookie);
	mutex_init(&dnetp->intrlock, NULL, MUTEX_DRIVER, dnetp->icookie);

	/*
	 * Get the BNC/TP indicator from the conf file for 21040
	 */
	dnetp->bnc_indicator =
	    ddi_getprop(DDI_DEV_T_ANY, devinfo, DDI_PROP_DONTPASS,
	    "bncaui", -1);

	/*
	 * For 21140 check the data rate set in the conf file. Default is
	 * 100Mb/s. Disallow connections at settings that would conflict
	 * with what's in the conf file
	 */
	dnetp->speed =
	    ddi_getprop(DDI_DEV_T_ANY, devinfo, DDI_PROP_DONTPASS,
	    speed_propname, 0);
	dnetp->full_duplex =
	    ddi_getprop(DDI_DEV_T_ANY, devinfo, DDI_PROP_DONTPASS,
	    duplex_propname, -1);

	if (dnetp->speed == 100) {
		dnetp->disallowed_media |= (1UL<<MEDIA_TP) | (1UL<<MEDIA_TP_FD);
	} else if (dnetp->speed == 10) {
		dnetp->disallowed_media |=
		    (1UL<<MEDIA_SYM_SCR) | (1UL<<MEDIA_SYM_SCR_FD);
	}

	if (dnetp->full_duplex == 1) {
		dnetp->disallowed_media |=
		    (1UL<<MEDIA_TP) | (1UL<<MEDIA_SYM_SCR);
	} else if (dnetp->full_duplex == 0) {
		dnetp->disallowed_media |=
		    (1UL<<MEDIA_TP_FD) | (1UL<<MEDIA_SYM_SCR_FD);
	}

	if (dnetp->bnc_indicator == 0) /* Disable BNC and AUI media */
		dnetp->disallowed_media |= (1UL<<MEDIA_BNC) | (1UL<<MEDIA_AUI);
	else if (dnetp->bnc_indicator == 1) /* Force BNC only */
		dnetp->disallowed_media =  (uint32_t)~(1U<<MEDIA_BNC);
	else if (dnetp->bnc_indicator == 2) /* Force AUI only */
		dnetp->disallowed_media = (uint32_t)~(1U<<MEDIA_AUI);

	dnet_reset_board(dnetp);

	secondary = dnet_read_srom(devinfo, dnetp->board_type, dnetp->io_handle,
	    dnetp->io_reg, vendor_info, sizeof (vendor_info));

	if (secondary == -1) /* ASSERT (vendor_info not big enough) */
		goto fail1;

	dnet_parse_srom(dnetp, &dnetp->sr, vendor_info);

	if (ddi_getprop(DDI_DEV_T_ANY, devinfo, DDI_PROP_DONTPASS,
	    printsrom_propname, 0))
		dnet_print_srom(&dnetp->sr);

	dnetp->sr.netaddr[ETHERADDRL-1] += secondary;	/* unique ether addr */

	BCOPY((caddr_t)dnetp->sr.netaddr,
	    (caddr_t)dnetp->vendor_addr, ETHERADDRL);

	BCOPY((caddr_t)dnetp->sr.netaddr,
	    (caddr_t)dnetp->curr_macaddr, ETHERADDRL);

	/*
	 * determine whether to implement workaround from DEC
	 * for DMA overrun errata.
	 */
	dnetp->overrun_workaround =
	    ((dnetp->board_type == DEVICE_ID_21140 && revid >= 0x20) ||
	    (dnetp->board_type == DEVICE_ID_21143 && revid <= 0x30)) ? 1 : 0;

	dnetp->overrun_workaround =
	    ddi_getprop(DDI_DEV_T_ANY, devinfo, DDI_PROP_DONTPASS,
	    ofloprob_propname, dnetp->overrun_workaround);

	/*
	 * Add the interrupt handler if dnet_hack_interrupts() returns 0.
	 * Otherwise dnet_hack_interrupts() itself adds the handler.
	 */
	if (!dnet_hack_interrupts(dnetp, secondary)) {
		(void) ddi_add_intr(devinfo, 0, NULL,
		    NULL, dnet_intr, (caddr_t)dnetp);
	}

	dnetp->max_tx_desc = max_tx_desc;
	dnetp->max_rx_desc = max_rx_desc_21040;
	if (dnetp->board_type != DEVICE_ID_21040 &&
	    dnetp->board_type != DEVICE_ID_21041 &&
	    dnetp->speed != 10)
		dnetp->max_rx_desc = max_rx_desc_21140;

	/* Allocate the TX and RX descriptors/buffers. */
	if (dnet_alloc_bufs(dnetp) == FAILURE) {
		cmn_err(CE_WARN, "DNET: Not enough DMA memory for buffers.");
		goto fail2;
	}

	/*
	 *	Register ourselves with the GLDv3 interface
	 */
	if ((macp = mac_alloc(MAC_VERSION)) == NULL)
		goto fail2;

	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_driver = dnetp;
	macp->m_dip = devinfo;
	macp->m_src_addr = dnetp->curr_macaddr;
	macp->m_callbacks = &dnet_m_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = ETHERMTU;
	macp->m_margin = VLAN_TAGSZ;

	if (mac_register(macp, &dnetp->mac_handle) == 0) {
		mac_free(macp);

		mutex_enter(&dnetp->intrlock);

		dnetp->phyaddr = -1;
		if (dnetp->board_type == DEVICE_ID_21140 ||
		    dnetp->board_type == DEVICE_ID_21143)
			do_phy(dnetp);	/* Initialize the PHY, if any */
		find_active_media(dnetp);

		/* if the chosen media is non-MII, stop the port monitor */
		if (dnetp->selected_media_block->media_code != MEDIA_MII &&
		    dnetp->mii != NULL) {
			mii_destroy(dnetp->mii);
			dnetp->mii = NULL;
			dnetp->phyaddr = -1;
		}

#ifdef DNETDEBUG
		if (dnetdebug & DNETSENSE)
			cmn_err(CE_NOTE, "dnet: link configured : %s",
			    media_str[dnetp->selected_media_block->media_code]);
#endif
		bzero(dnetp->setup_buf_vaddr, SETUPBUF_SIZE);

		dnet_reset_board(dnetp);
		dnet_init_board(dnetp);

		mutex_exit(&dnetp->intrlock);

		(void) dnet_m_unicst(dnetp, dnetp->curr_macaddr);
		(void) dnet_m_multicst(dnetp, B_TRUE, dnet_broadcastaddr);

		return (DDI_SUCCESS);
	}

	mac_free(macp);
fail2:
	/* XXX function return value ignored */
	/*
	 * dnet_detach_hacked_interrupt() will remove
	 * interrupt for the non-hacked case also.
	 */
	(void) dnet_detach_hacked_interrupt(devinfo);
	dnet_free_bufs(dnetp);
fail1:
	mutex_destroy(&dnetp->txlock);
	mutex_destroy(&dnetp->intrlock);
fail:
	ddi_regs_map_free(&dnetp->io_handle);
	kmem_free(dnetp, sizeof (struct dnetinstance));
	return (DDI_FAILURE);
}

/*
 * detach(9E) -- Detach a device from the system
 */
static int
dnet_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{
	int32_t rc;
	struct dnetinstance *dnetp;		/* Our private device info */
	int32_t		proplen;

	/* Get the driver private (dnetinstance) structure */
	dnetp = ddi_get_driver_private(devinfo);

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_SUSPEND:
		/*
		 * NB: dnetp->suspended can only be modified (marked true)
		 * if both intrlock and txlock are held.  This keeps both
		 * tx and rx code paths excluded.
		 */
		mutex_enter(&dnetp->intrlock);
		mutex_enter(&dnetp->txlock);
		dnetp->suspended = B_TRUE;
		dnet_reset_board(dnetp);
		mutex_exit(&dnetp->txlock);
		mutex_exit(&dnetp->intrlock);
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	/*
	 *	Unregister ourselves from the GLDv3 interface
	 */
	if (mac_unregister(dnetp->mac_handle) != 0)
		return (DDI_FAILURE);

	/* stop the board if it is running */
	dnet_reset_board(dnetp);

	if ((rc = dnet_detach_hacked_interrupt(devinfo)) != DDI_SUCCESS)
		return (rc);

	if (dnetp->mii != NULL)
		mii_destroy(dnetp->mii);

	/* Free leaf information */
	set_leaf(&dnetp->sr, NULL);

	ddi_regs_map_free(&dnetp->io_handle);
	dnet_free_bufs(dnetp);
	mutex_destroy(&dnetp->txlock);
	mutex_destroy(&dnetp->intrlock);
	kmem_free(dnetp, sizeof (struct dnetinstance));

#ifdef BUG_4010796
	if (ddi_getproplen(DDI_DEV_T_ANY, devinfo, 0,
	    "DNET_HACK", &proplen) != DDI_PROP_SUCCESS)
		return (DDI_SUCCESS);

	/*
	 * We must remove the properties we added, because if we leave
	 * them in the devinfo nodes and the driver is unloaded, when
	 * the driver is reloaded the info will still be there, causing
	 * nodes which had returned PROBE_PARTIAL the first time to
	 * instead return PROBE_SUCCESS, in turn causing the nodes to be
	 * attached in a different order, causing their PPA numbers to
	 * be different the second time around, which is undesirable.
	 */
	(void) ddi_prop_remove(DDI_DEV_T_NONE, devinfo, "DNET_HACK");
	(void) ddi_prop_remove(DDI_DEV_T_NONE, ddi_get_parent(devinfo),
	    "DNET_SROM");
	(void) ddi_prop_remove(DDI_DEV_T_NONE, ddi_get_parent(devinfo),
	    "DNET_DEVNUM");
#endif

	return (DDI_SUCCESS);
}

int
dnet_quiesce(dev_info_t *dip)
{
	struct dnetinstance *dnetp = ddi_get_driver_private(dip);

	/*
	 * Reset chip (disables interrupts).
	 */
	ddi_put32(dnetp->io_handle, REG32(dnetp->io_reg, INT_MASK_REG), 0);
	ddi_put32(dnetp->io_handle,
	    REG32(dnetp->io_reg, BUS_MODE_REG), SW_RESET);

	return (DDI_SUCCESS);
}

static void
dnet_reset_board(struct dnetinstance *dnetp)
{
	uint32_t	val;

	/*
	 * before initializing the dnet should be in STOP state
	 */
	val = ddi_get32(dnetp->io_handle, REG32(dnetp->io_reg, OPN_MODE_REG));
	ddi_put32(dnetp->io_handle, REG32(dnetp->io_reg, OPN_MODE_REG),
	    val & ~(START_TRANSMIT | START_RECEIVE));

	/*
	 * Reset the chip
	 */
	ddi_put32(dnetp->io_handle, REG32(dnetp->io_reg, INT_MASK_REG), 0);
	ddi_put32(dnetp->io_handle,
	    REG32(dnetp->io_reg, BUS_MODE_REG), SW_RESET);
	drv_usecwait(5);
}

/*
 * dnet_init_board() -- initialize the specified network board short of
 * actually starting the board.  Call after dnet_reset_board().
 * called with intrlock held.
 */
static void
dnet_init_board(struct dnetinstance *dnetp)
{
	set_opr(dnetp);
	set_gpr(dnetp);
	set_sia(dnetp);
	dnet_chip_init(dnetp);
}

/* dnet_chip_init() - called with intrlock held */
static void
dnet_chip_init(struct dnetinstance *dnetp)
{
	ddi_put32(dnetp->io_handle, REG32(dnetp->io_reg, BUS_MODE_REG),
	    CACHE_ALIGN | BURST_SIZE);		/* CSR0 */

	/*
	 * Initialize the TX and RX descriptors/buffers
	 */
	dnet_init_txrx_bufs(dnetp);

	/*
	 * Set the base address of the Rx descriptor list in CSR3
	 */
	ddi_put32(dnetp->io_handle, REG32(dnetp->io_reg, RX_BASE_ADDR_REG),
	    dnetp->rx_desc_paddr);

	/*
	 * Set the base address of the Tx descrptor list in CSR4
	 */
	ddi_put32(dnetp->io_handle, REG32(dnetp->io_reg, TX_BASE_ADDR_REG),
	    dnetp->tx_desc_paddr);

	dnetp->tx_current_desc = dnetp->rx_current_desc = 0;
	dnetp->transmitted_desc = 0;
	dnetp->free_desc = dnetp->max_tx_desc;
	enable_interrupts(dnetp);
}

/*
 *	dnet_start() -- start the board receiving and allow transmits.
 *  Called with intrlock held.
 */
static int
dnet_start(struct dnetinstance *dnetp)
{
	uint32_t val;

	ASSERT(MUTEX_HELD(&dnetp->intrlock));
	/*
	 * start the board and enable receiving
	 */
	val = ddi_get32(dnetp->io_handle, REG32(dnetp->io_reg, OPN_MODE_REG));
	ddi_put32(dnetp->io_handle, REG32(dnetp->io_reg, OPN_MODE_REG),
	    val | START_TRANSMIT);
	(void) dnet_set_addr(dnetp);
	val = ddi_get32(dnetp->io_handle, REG32(dnetp->io_reg, OPN_MODE_REG));
	ddi_put32(dnetp->io_handle, REG32(dnetp->io_reg, OPN_MODE_REG),
	    val | START_RECEIVE);
	enable_interrupts(dnetp);
	return (0);
}

static int
dnet_m_start(void *arg)
{
	struct dnetinstance *dnetp = arg;

	mutex_enter(&dnetp->intrlock);
	dnetp->running = B_TRUE;
	/*
	 * start the board and enable receiving
	 */
	if (!dnetp->suspended)
		(void) dnet_start(dnetp);
	mutex_exit(&dnetp->intrlock);
	return (0);
}

static void
dnet_m_stop(void *arg)
{
	struct dnetinstance *dnetp = arg;
	uint32_t val;

	/*
	 * stop the board and disable transmit/receive
	 */
	mutex_enter(&dnetp->intrlock);
	if (!dnetp->suspended) {
		val = ddi_get32(dnetp->io_handle,
		    REG32(dnetp->io_reg, OPN_MODE_REG));
		ddi_put32(dnetp->io_handle, REG32(dnetp->io_reg, OPN_MODE_REG),
		    val & ~(START_TRANSMIT | START_RECEIVE));
	}
	mac_link_update(dnetp->mac_handle, LINK_STATE_UNKNOWN);
	dnetp->running = B_FALSE;
	mutex_exit(&dnetp->intrlock);
}

/*
 *	dnet_set_addr() -- set the physical network address on the board
 *  Called with intrlock held.
 */
static int
dnet_set_addr(struct dnetinstance *dnetp)
{
	struct tx_desc_type *desc;
	int 		current_desc;
	uint32_t	val;

	ASSERT(MUTEX_HELD(&dnetp->intrlock));

	val = ddi_get32(dnetp->io_handle, REG32(dnetp->io_reg, OPN_MODE_REG));
	if (!(val & START_TRANSMIT))
		return (0);

	current_desc = dnetp->tx_current_desc;
	desc = &dnetp->tx_desc[current_desc];

	mutex_enter(&dnetp->txlock);
	dnetp->need_saddr = 0;
	mutex_exit(&dnetp->txlock);

	if ((alloc_descriptor(dnetp)) == FAILURE) {
		mutex_enter(&dnetp->txlock);
		dnetp->need_saddr = 1;
		mutex_exit(&dnetp->txlock);
#ifdef DNETDEBUG
		if (dnetdebug & DNETTRACE)
			cmn_err(CE_WARN, "DNET saddr:alloc descriptor failure");
#endif
		return (0);
	}

	desc->buffer1			= dnetp->setup_buf_paddr;
	desc->buffer2			= 0;
	desc->desc1.buffer_size1 	= SETUPBUF_SIZE;
	desc->desc1.buffer_size2 	= 0;
	desc->desc1.setup_packet	= 1;
	desc->desc1.first_desc		= 0;
	desc->desc1.last_desc 		= 0;
	desc->desc1.filter_type0 	= 1;
	desc->desc1.filter_type1 	= 1;
	desc->desc1.int_on_comp		= 1;

	desc->desc0.own = 1;
	ddi_put8(dnetp->io_handle, REG8(dnetp->io_reg, TX_POLL_REG),
	    TX_POLL_DEMAND);
	return (0);
}

static int
dnet_m_unicst(void *arg, const uint8_t *macaddr)
{
	struct dnetinstance *dnetp = arg;
	uint32_t	index;
	uint32_t	*hashp;

	mutex_enter(&dnetp->intrlock);

	bcopy(macaddr, dnetp->curr_macaddr, ETHERADDRL);

	/*
	 * As we are using Imperfect filtering, the broadcast address has to
	 * be set explicitly in the 512 bit hash table.  Hence the index into
	 * the hash table is calculated and the bit set to enable reception
	 * of broadcast packets.
	 *
	 * We also use HASH_ONLY mode, without using the perfect filter for
	 * our station address, because there appears to be a bug in the
	 * 21140 where it fails to receive the specified perfect filter
	 * address.
	 *
	 * Since dlsdmult comes through here, it doesn't matter that the count
	 * is wrong for the two bits that correspond to the cases below. The
	 * worst that could happen is that we'd leave on a bit for an old
	 * macaddr, in the case where the macaddr gets changed, which is rare.
	 * Since filtering is imperfect, it is OK if that happens.
	 */
	hashp = (uint32_t *)dnetp->setup_buf_vaddr;
	index = hashindex((uint8_t *)dnet_broadcastaddr);
	hashp[ index / 16 ] |= 1 << (index % 16);

	index = hashindex((uint8_t *)dnetp->curr_macaddr);
	hashp[ index / 16 ] |= 1 << (index % 16);

	if (!dnetp->suspended)
		(void) dnet_set_addr(dnetp);
	mutex_exit(&dnetp->intrlock);
	return (0);
}

static int
dnet_m_multicst(void *arg, boolean_t add, const uint8_t *macaddr)
{
	struct dnetinstance *dnetp = arg;
	uint32_t	index;
	uint32_t	*hashp;
	uint32_t	retval;

	mutex_enter(&dnetp->intrlock);
	index = hashindex(macaddr);
	hashp = (uint32_t *)dnetp->setup_buf_vaddr;
	if (add) {
		if (dnetp->multicast_cnt[index]++) {
			mutex_exit(&dnetp->intrlock);
			return (0);
		}
		hashp[ index / 16 ] |= 1 << (index % 16);
	} else {
		if (--dnetp->multicast_cnt[index]) {
			mutex_exit(&dnetp->intrlock);
			return (0);
		}
		hashp[ index / 16 ] &= ~ (1 << (index % 16));
	}
	if (!dnetp->suspended)
		retval = dnet_set_addr(dnetp);
	else
		retval = 0;
	mutex_exit(&dnetp->intrlock);
	return (retval);
}

/*
 * A hashing function used for setting the
 * node address or a multicast address
 */
static uint32_t
hashindex(const uint8_t *address)
{
	uint32_t	crc = (uint32_t)HASH_CRC;
	uint32_t const 	POLY = HASH_POLY;
	uint32_t	msb;
	int32_t 	byteslength;
	uint8_t 	currentbyte;
	uint32_t 	index;
	int32_t 	bit;
	int32_t		shift;

	for (byteslength = 0; byteslength < ETHERADDRL; byteslength++) {
		currentbyte = address[byteslength];
		for (bit = 0; bit < 8; bit++) {
			msb = crc >> 31;
			crc <<= 1;
			if (msb ^ (currentbyte & 1)) {
				crc ^= POLY;
				crc |= 0x00000001;
			}
			currentbyte >>= 1;
		}
	}

	for (index = 0, bit = 23, shift = 8; shift >= 0; bit++, shift--) {
		index |= (((crc >> bit) & 1) << shift);
	}
	return (index);
}

static int
dnet_m_setpromisc(void *arg, boolean_t on)
{
	struct dnetinstance *dnetp = arg;
	uint32_t val;

	mutex_enter(&dnetp->intrlock);
	if (dnetp->promisc == on) {
		mutex_exit(&dnetp->intrlock);
		return (0);
	}
	dnetp->promisc = on;

	if (!dnetp->suspended) {
		val = ddi_get32(dnetp->io_handle,
		    REG32(dnetp->io_reg, OPN_MODE_REG));
		if (on)
			ddi_put32(dnetp->io_handle,
			    REG32(dnetp->io_reg, OPN_MODE_REG),
			    val | PROM_MODE);
		else
			ddi_put32(dnetp->io_handle,
			    REG32(dnetp->io_reg, OPN_MODE_REG),
			    val & (~PROM_MODE));
	}
	mutex_exit(&dnetp->intrlock);
	return (0);
}

static int
dnet_m_getstat(void *arg, uint_t stat, uint64_t *val)
{
	struct dnetinstance *dnetp = arg;

	switch (stat) {
	case MAC_STAT_IFSPEED:
		if (!dnetp->running) {
			*val = 0;
		} else {
			*val = (dnetp->mii_up ?
			    dnetp->mii_speed : dnetp->speed) * 1000000;
		}
		break;

	case MAC_STAT_NORCVBUF:
		*val = dnetp->stat_norcvbuf;
		break;

	case MAC_STAT_IERRORS:
		*val = dnetp->stat_errrcv;
		break;

	case MAC_STAT_OERRORS:
		*val = dnetp->stat_errxmt;
		break;

	case MAC_STAT_COLLISIONS:
		*val = dnetp->stat_collisions;
		break;

	case ETHER_STAT_DEFER_XMTS:
		*val = dnetp->stat_defer;
		break;

	case ETHER_STAT_CARRIER_ERRORS:
		*val = dnetp->stat_nocarrier;
		break;

	case ETHER_STAT_TOOSHORT_ERRORS:
		*val = dnetp->stat_short;
		break;

	case ETHER_STAT_LINK_DUPLEX:
		if (!dnetp->running) {
			*val = LINK_DUPLEX_UNKNOWN;

		} else if (dnetp->mii_up) {
			*val = dnetp->mii_duplex ?
			    LINK_DUPLEX_FULL : LINK_DUPLEX_HALF;
		} else {
			*val = dnetp->full_duplex ?
			    LINK_DUPLEX_FULL : LINK_DUPLEX_HALF;
		}
		break;

	case ETHER_STAT_TX_LATE_COLLISIONS:
		*val = dnetp->stat_xmtlatecoll;
		break;

	case ETHER_STAT_EX_COLLISIONS:
		*val = dnetp->stat_excoll;
		break;

	case MAC_STAT_OVERFLOWS:
		*val = dnetp->stat_overflow;
		break;

	case MAC_STAT_UNDERFLOWS:
		*val = dnetp->stat_underflow;
		break;

	default:
		return (ENOTSUP);
	}

	return (0);
}

#define	NextTXIndex(index) (((index)+1) % dnetp->max_tx_desc)
#define	PrevTXIndex(index) (((index)-1) < 0 ? dnetp->max_tx_desc - 1: (index)-1)

static mblk_t *
dnet_m_tx(void *arg, mblk_t *mp)
{
	struct dnetinstance *dnetp = arg;

	mutex_enter(&dnetp->txlock);

	/* if suspended, drop the packet on the floor, we missed it */
	if (dnetp->suspended) {
		mutex_exit(&dnetp->txlock);
		freemsg(mp);
		return (NULL);
	}

	if (dnetp->need_saddr) {
		/* XXX function return value ignored */
		mutex_exit(&dnetp->txlock);
		mutex_enter(&dnetp->intrlock);
		(void) dnet_set_addr(dnetp);
		mutex_exit(&dnetp->intrlock);
		mutex_enter(&dnetp->txlock);
	}

	while (mp != NULL) {
		if (!dnet_send(dnetp, mp)) {
			mutex_exit(&dnetp->txlock);
			return (mp);
		}
		mp = mp->b_next;
	}

	mutex_exit(&dnetp->txlock);

	/*
	 * Enable xmit interrupt in case we are running out of xmit descriptors
	 * or there are more packets on the queue waiting to be transmitted.
	 */
	mutex_enter(&dnetp->intrlock);

	enable_interrupts(dnetp);

	/*
	 * Kick the transmitter
	 */
	ddi_put32(dnetp->io_handle, REG32(dnetp->io_reg, TX_POLL_REG),
	    TX_POLL_DEMAND);

	mutex_exit(&dnetp->intrlock);

	return (NULL);
}

static boolean_t
dnet_send(struct dnetinstance *dnetp, mblk_t *mp)
{
	struct tx_desc_type	*ring = dnetp->tx_desc;
	int		mblen, totlen;
	int		index, end_index, start_index;
	int		avail;
	int		error;
	int		bufn;
	int		retval;
	mblk_t		*bp;

	ASSERT(MUTEX_HELD(&dnetp->txlock));

	/* reclaim any xmit descriptors completed */
	dnet_reclaim_Tx_desc(dnetp);

	/*
	 * Use the data buffers from the message and construct the
	 * scatter/gather list by calling ddi_dma_addr_bind_handle().
	 */
	error = 0;
	totlen = 0;
	bp = mp;
	bufn = 0;
	index = start_index = dnetp->tx_current_desc;
	avail = dnetp->free_desc;
	while (bp != NULL) {
		uint_t ncookies;
		ddi_dma_cookie_t dma_cookie;

		mblen = MBLKL(bp);

		if (!mblen) {	/* skip zero-length message blocks */
			bp = bp->b_cont;
			continue;
		}

		retval = ddi_dma_addr_bind_handle(dnetp->dma_handle_tx, NULL,
		    (caddr_t)bp->b_rptr, mblen,
		    DDI_DMA_WRITE | DDI_DMA_STREAMING, DDI_DMA_SLEEP, 0,
		    &dma_cookie, &ncookies);

		switch (retval) {
		case DDI_DMA_MAPPED:
			break;		/* everything's fine */

		case DDI_DMA_NORESOURCES:
			error = 1;	/* allow retry by gld */
			break;

		case DDI_DMA_NOMAPPING:
		case DDI_DMA_INUSE:
		case DDI_DMA_TOOBIG:
		default:
			error = 2;	/* error, no retry */
			break;
		}

		/*
		 * we can use two cookies per descriptor (i.e buffer1 and
		 * buffer2) so we need at least (ncookies+1)/2 descriptors.
		 */
		if (((ncookies + 1) >> 1) > dnetp->free_desc) {
			(void) ddi_dma_unbind_handle(dnetp->dma_handle_tx);
			error = 1;
			break;
		}

		/* setup the descriptors for this data buffer */
		while (ncookies) {
			end_index = index;
			if (bufn % 2) {
				ring[index].buffer2 =
				    (uint32_t)dma_cookie.dmac_address;
				ring[index].desc1.buffer_size2 =
				    dma_cookie.dmac_size;
				index = NextTXIndex(index); /* goto next desc */
			} else {
				/* initialize the descriptor */
				ASSERT(ring[index].desc0.own == 0);
				*(uint32_t *)&ring[index].desc0 = 0;
				*(uint32_t *)&ring[index].desc1 &=
				    DNET_END_OF_RING;
				ring[index].buffer1 =
				    (uint32_t)dma_cookie.dmac_address;
				ring[index].desc1.buffer_size1 =
				    dma_cookie.dmac_size;
				ring[index].buffer2 = (uint32_t)(0);
				dnetp->free_desc--;
				ASSERT(dnetp->free_desc >= 0);
			}
			totlen += dma_cookie.dmac_size;
			bufn++;
			if (--ncookies)
				ddi_dma_nextcookie(dnetp->dma_handle_tx,
				    &dma_cookie);
		}
		(void) ddi_dma_unbind_handle(dnetp->dma_handle_tx);
		bp = bp->b_cont;
	}

	if (error == 1) {
		dnetp->stat_defer++;
		dnetp->free_desc = avail;
		dnetp->need_tx_update = B_TRUE;
		return (B_FALSE);
	} else if (error) {
		dnetp->free_desc = avail;
		freemsg(mp);
		return (B_TRUE);	/* Drop packet, don't retry */
	}

	if (totlen > ETHERMAX + VLAN_TAGSZ) {
		cmn_err(CE_WARN, "DNET: tried to send large %d packet", totlen);
		dnetp->free_desc = avail;
		freemsg(mp);
		return (B_TRUE);	/* Don't repeat this attempt */
	}

	/*
	 * Remeber the message buffer pointer to do freemsg() at xmit
	 * interrupt time.
	 */
	dnetp->tx_msgbufp[end_index] = mp;

	/*
	 * Now set the first/last buffer and own bits
	 * Since the 21040 looks for these bits set in the
	 * first buffer, work backwards in multiple buffers.
	 */
	ring[end_index].desc1.last_desc = 1;
	ring[end_index].desc1.int_on_comp = 1;
	for (index = end_index; index != start_index;
	    index = PrevTXIndex(index))
		ring[index].desc0.own = 1;
	ring[start_index].desc1.first_desc = 1;
	ring[start_index].desc0.own = 1;

	dnetp->tx_current_desc = NextTXIndex(end_index);

	/*
	 * Safety check: make sure end-of-ring is set in last desc.
	 */
	ASSERT(ring[dnetp->max_tx_desc-1].desc1.end_of_ring != 0);

	return (B_TRUE);
}

/*
 *	dnet_intr() -- interrupt from board to inform us that a receive or
 *	transmit has completed.
 */
static uint_t
dnet_intr(caddr_t arg)
{
	struct dnetinstance *dnetp = (struct dnetinstance *)arg;
	uint32_t int_status;

	mutex_enter(&dnetp->intrlock);

	if (dnetp->suspended) {
		mutex_exit(&dnetp->intrlock);
		return (DDI_INTR_UNCLAIMED);
	}

	int_status = ddi_get32(dnetp->io_handle, REG32(dnetp->io_reg,
	    STATUS_REG));

	/*
	 * If interrupt was not from this board
	 */
	if (!(int_status & (NORMAL_INTR_SUMM | ABNORMAL_INTR_SUMM))) {
		mutex_exit(&dnetp->intrlock);
		return (DDI_INTR_UNCLAIMED);
	}

	dnetp->stat_intr++;

	if (int_status & GPTIMER_INTR) {
		ddi_put32(dnetp->io_handle,
		    REG32(dnetp->io_reg, STATUS_REG), GPTIMER_INTR);
		if (dnetp->timer.cb)
			dnetp->timer.cb(dnetp);
		else
			cmn_err(CE_WARN, "dnet: unhandled timer interrupt");
	}

	if (int_status & TX_INTR) {
		ddi_put32(dnetp->io_handle,
		    REG32(dnetp->io_reg, STATUS_REG), TX_INTR);
		mutex_enter(&dnetp->txlock);
		if (dnetp->need_tx_update) {
			mutex_exit(&dnetp->txlock);
			mutex_exit(&dnetp->intrlock);
			mac_tx_update(dnetp->mac_handle);
			mutex_enter(&dnetp->intrlock);
			mutex_enter(&dnetp->txlock);
			dnetp->need_tx_update = B_FALSE;
		}
		/* reclaim any xmit descriptors that are completed */
		dnet_reclaim_Tx_desc(dnetp);
		mutex_exit(&dnetp->txlock);
	}

	/*
	 * Check if receive interrupt bit is set
	 */
	if (int_status & (RX_INTR | RX_UNAVAIL_INTR)) {
		ddi_put32(dnetp->io_handle,
		    REG32(dnetp->io_reg, STATUS_REG),
		    int_status & (RX_INTR | RX_UNAVAIL_INTR));
		dnet_getp(dnetp);
	}

	if (int_status & ABNORMAL_INTR_SUMM) {
		/*
		 * Check for system error
		 */
		if (int_status & SYS_ERR) {
			if ((int_status & SYS_ERR_BITS) == MASTER_ABORT)
				cmn_err(CE_WARN, "DNET: Bus Master Abort");
			if ((int_status & SYS_ERR_BITS) == TARGET_ABORT)
				cmn_err(CE_WARN, "DNET: Bus Target Abort");
			if ((int_status & SYS_ERR_BITS) == PARITY_ERROR)
				cmn_err(CE_WARN, "DNET: Parity error");
		}

		/*
		 * If the jabber has timed out then reset the chip
		 */
		if (int_status & TX_JABBER_TIMEOUT)
			cmn_err(CE_WARN, "DNET: Jabber timeout.");

		/*
		 * If an underflow has occurred, reset the chip
		 */
		if (int_status & TX_UNDERFLOW)
			cmn_err(CE_WARN, "DNET: Tx Underflow.");

#ifdef DNETDEBUG
		if (dnetdebug & DNETINT)
			cmn_err(CE_NOTE, "Trying to reset...");
#endif
		dnet_reset_board(dnetp);
		dnet_init_board(dnetp);
		/* XXX function return value ignored */
		(void) dnet_start(dnetp);
	}

	/*
	 * Enable the interrupts. Enable xmit interrupt in case we are
	 * running out of free descriptors or if there are packets
	 * in the queue waiting to be transmitted.
	 */
	enable_interrupts(dnetp);
	mutex_exit(&dnetp->intrlock);
	return (DDI_INTR_CLAIMED);	/* Indicate it was our interrupt */
}

static void
dnet_getp(struct dnetinstance *dnetp)
{
	int packet_length, index;
	mblk_t	*mp;
	caddr_t 	virtual_address;
	struct	rx_desc_type *desc = dnetp->rx_desc;
	int marker = dnetp->rx_current_desc;
	int misses;

	if (!dnetp->overrun_workaround) {
		/*
		 * If the workaround is not in place, we must still update
		 * the missed frame statistic from the on-chip counter.
		 */
		misses = ddi_get32(dnetp->io_handle,
		    REG32(dnetp->io_reg, MISSED_FRAME_REG));
		dnetp->stat_missed += (misses & MISSED_FRAME_MASK);
	}

	/* While host owns the current descriptor */
	while (!(desc[dnetp->rx_current_desc].desc0.own)) {
		struct free_ptr *frp;
		caddr_t newbuf;
		struct rbuf_list *rp;

		index = dnetp->rx_current_desc;
		ASSERT(desc[index].desc0.first_desc != 0);

		/*
		 * DMA overrun errata from DEC: avoid possible bus hangs
		 * and data corruption
		 */
		if (dnetp->overrun_workaround &&
		    marker == dnetp->rx_current_desc) {
			int opn;
			do {
				marker = (marker+1) % dnetp->max_rx_desc;
			} while (!(dnetp->rx_desc[marker].desc0.own) &&
			    marker != index);

			misses = ddi_get32(dnetp->io_handle,
			    REG32(dnetp->io_reg, MISSED_FRAME_REG));
			dnetp->stat_missed +=
			    (misses & MISSED_FRAME_MASK);
			if (misses & OVERFLOW_COUNTER_MASK) {
				/*
				 * Overflow(s) have occurred : stop receiver,
				 * and wait until in stopped state
				 */
				opn = ddi_get32(dnetp->io_handle,
				    REG32(dnetp->io_reg, OPN_MODE_REG));
				ddi_put32(dnetp->io_handle,
				    REG32(dnetp->io_reg, OPN_MODE_REG),
				    opn & ~(START_RECEIVE));

				do {
					drv_usecwait(10);
				} while ((ddi_get32(dnetp->io_handle,
				    REG32(dnetp->io_reg, STATUS_REG)) &
				    RECEIVE_PROCESS_STATE) != 0);
#ifdef DNETDEBUG
				if (dnetdebug & DNETRECV)
					cmn_err(CE_CONT, "^*");
#endif
				/* Discard probably corrupt frames */
				while (!(dnetp->rx_desc[index].desc0.own)) {
					dnetp->rx_desc[index].desc0.own = 1;
					index = (index+1) % dnetp->max_rx_desc;
					dnetp->stat_missed++;
				}

				/* restart the receiver */
				opn = ddi_get32(dnetp->io_handle,
				    REG32(dnetp->io_reg, OPN_MODE_REG));
				ddi_put32(dnetp->io_handle,
				    REG32(dnetp->io_reg, OPN_MODE_REG),
				    opn | START_RECEIVE);
				marker = dnetp->rx_current_desc = index;
				continue;
			}
			/*
			 * At this point, we know that all packets before
			 * "marker" were received before a dma overrun occurred
			 */
		}

		/*
		 * If we get an oversized packet it could span multiple
		 * descriptors.  If this happens an error bit should be set.
		 */
		while (desc[index].desc0.last_desc == 0) {
			index = (index + 1) % dnetp->max_rx_desc;
			if (desc[index].desc0.own)
				return;	/* not done receiving large packet */
		}
		while (dnetp->rx_current_desc != index) {
			desc[dnetp->rx_current_desc].desc0.own = 1;
			dnetp->rx_current_desc =
			    (dnetp->rx_current_desc + 1) % dnetp->max_rx_desc;
#ifdef DNETDEBUG
			if (dnetdebug & DNETRECV)
				cmn_err(CE_WARN, "dnet: received large packet");
#endif
		}

		packet_length = desc[index].desc0.frame_len;

		/*
		 * Remove CRC from received data. This is an artefact of the
		 * 21x4x chip and should not be passed higher up the network
		 * stack.
		 */
		packet_length -= ETHERFCSL;

		/* get the virtual address of the packet received */
		virtual_address =
		    dnetp->rx_buf_vaddr[index];

		/*
		 * If no packet errors then do:
		 * 	1. Allocate a new receive buffer so that we can
		 *	   use the current buffer as streams buffer to
		 *	   avoid bcopy.
		 *	2. If we got a new receive buffer then allocate
		 *	   an mblk using desballoc().
		 *	3. Otherwise use the mblk from allocb() and do
		 *	   the bcopy.
		 */
		frp = NULL;
		rp = NULL;
		newbuf = NULL;
		mp = NULL;
		if (!desc[index].desc0.err_summary ||
		    (desc[index].desc0.frame2long &&
		    packet_length < rx_buf_size)) {
			ASSERT(packet_length < rx_buf_size);
			/*
			 * Allocate another receive buffer for this descriptor.
			 * If we fail to allocate then we do the normal bcopy.
			 */
			rp = dnet_rbuf_alloc(dnetp->devinfo, 0);
			if (rp != NULL) {
				newbuf = rp->rbuf_vaddr;
				frp = kmem_zalloc(sizeof (*frp), KM_NOSLEEP);
				if (frp != NULL) {
					frp->free_rtn.free_func =
					    dnet_freemsg_buf;
					frp->free_rtn.free_arg = (char *)frp;
					frp->buf = virtual_address;
					mp = desballoc(
					    (uchar_t *)virtual_address,
					    packet_length, 0, &frp->free_rtn);
					if (mp == NULL) {
						kmem_free(frp, sizeof (*frp));
						dnet_rbuf_free((caddr_t)newbuf);
						frp = NULL;
						newbuf = NULL;
					}
				}
			}
			if (mp == NULL) {
				if (newbuf != NULL)
					dnet_rbuf_free((caddr_t)newbuf);
				mp = allocb(packet_length, 0);
			}
		}

		if ((desc[index].desc0.err_summary &&
		    packet_length >= rx_buf_size) || mp == NULL) {

			/* Update gld statistics */
			if (desc[index].desc0.err_summary)
				update_rx_stats(dnetp, index);
			else
				dnetp->stat_norcvbuf++;

			/*
			 * Reset ownership of the descriptor.
			 */
			desc[index].desc0.own = 1;
			dnetp->rx_current_desc =
			    (dnetp->rx_current_desc+1) % dnetp->max_rx_desc;

			/* Demand receive polling by the chip */
			ddi_put32(dnetp->io_handle,
			    REG32(dnetp->io_reg, RX_POLL_REG), RX_POLL_DEMAND);

			continue;
		}

		if (newbuf != NULL) {
			uint32_t end_paddr;
			/* attach the new buffer to the rx descriptor */
			dnetp->rx_buf_vaddr[index] = newbuf;
			dnetp->rx_buf_paddr[index] = rp->rbuf_paddr;
			desc[index].buffer1 = rp->rbuf_paddr;
			desc[index].desc1.buffer_size1 = rx_buf_size;
			desc[index].desc1.buffer_size2 = 0;
			end_paddr = rp->rbuf_endpaddr;
			if ((desc[index].buffer1 & ~dnetp->pgmask) !=
			    (end_paddr & ~dnetp->pgmask)) {
				/* discontiguous */
				desc[index].buffer2 = end_paddr&~dnetp->pgmask;
				desc[index].desc1.buffer_size2 =
				    (end_paddr & dnetp->pgmask) + 1;
				desc[index].desc1.buffer_size1 =
				    rx_buf_size-desc[index].desc1.buffer_size2;
			}
		} else {
			/* couldn't allocate another buffer; copy the data */
			BCOPY((caddr_t)virtual_address, (caddr_t)mp->b_wptr,
			    packet_length);
		}

		mp->b_wptr += packet_length;

		desc[dnetp->rx_current_desc].desc0.own = 1;

		/*
		 * Increment receive desc index. This is for the scan of
		 * next packet
		 */
		dnetp->rx_current_desc =
		    (dnetp->rx_current_desc+1) % dnetp->max_rx_desc;

		/* Demand polling by chip */
		ddi_put32(dnetp->io_handle,
		    REG32(dnetp->io_reg, RX_POLL_REG), RX_POLL_DEMAND);

		/* send the packet upstream */
		mutex_exit(&dnetp->intrlock);
		mac_rx(dnetp->mac_handle, NULL, mp);
		mutex_enter(&dnetp->intrlock);
	}
}
/*
 * Function to update receive statistics
 */
static void
update_rx_stats(struct dnetinstance *dnetp, int index)
{
	struct rx_desc_type *descp = &(dnetp->rx_desc[index]);

	/*
	 * Update gld statistics
	 */
	dnetp->stat_errrcv++;

	if (descp->desc0.overflow)	{
		/* FIFO Overrun */
		dnetp->stat_overflow++;
	}

	if (descp->desc0.collision) {
		/*EMPTY*/
		/* Late Colllision on receive */
		/* no appropriate counter */
	}

	if (descp->desc0.crc) {
		/* CRC Error */
		dnetp->stat_crc++;
	}

	if (descp->desc0.runt_frame) {
		/* Runt Error */
		dnetp->stat_short++;
	}

	if (descp->desc0.desc_err) {
		/*EMPTY*/
		/* Not enough receive descriptors */
		/* This condition is accounted in dnet_intr() */
	}

	if (descp->desc0.frame2long) {
		dnetp->stat_frame++;
	}
}

/*
 * Function to update transmit statistics
 */
static void
update_tx_stats(struct dnetinstance *dnetp, int index)
{
	struct tx_desc_type *descp = &(dnetp->tx_desc[index]);
	int	fd;
	media_block_t	*block = dnetp->selected_media_block;


	/* Update gld statistics */
	dnetp->stat_errxmt++;

	/* If we're in full-duplex don't count collisions or carrier loss. */
	if (dnetp->mii_up) {
		fd = dnetp->mii_duplex;
	} else {
		/* Rely on media code */
		fd = block->media_code == MEDIA_TP_FD ||
		    block->media_code == MEDIA_SYM_SCR_FD;
	}

	if (descp->desc0.collision_count && !fd) {
		dnetp->stat_collisions += descp->desc0.collision_count;
	}

	if (descp->desc0.late_collision && !fd) {
		dnetp->stat_xmtlatecoll++;
	}

	if (descp->desc0.excess_collision && !fd) {
		dnetp->stat_excoll++;
	}

	if (descp->desc0.underflow) {
		dnetp->stat_underflow++;
	}

#if 0
	if (descp->desc0.tx_jabber_to) {
		/* no appropriate counter */
	}
#endif

	if (descp->desc0.carrier_loss && !fd) {
		dnetp->stat_nocarrier++;
	}

	if (descp->desc0.no_carrier && !fd) {
		dnetp->stat_nocarrier++;
	}
}

/*
 *	========== Media Selection Setup Routines ==========
 */


static void
write_gpr(struct dnetinstance *dnetp, uint32_t val)
{
#ifdef DEBUG
	if (dnetdebug & DNETREGCFG)
		cmn_err(CE_NOTE, "GPR: %x", val);
#endif
	switch (dnetp->board_type) {
	case DEVICE_ID_21143:
		/* Set the correct bit for a control write */
		if (val & GPR_CONTROL_WRITE)
			val |= CWE_21143, val &= ~GPR_CONTROL_WRITE;
		/* Write to upper half of CSR15 */
		dnetp->gprsia = (dnetp->gprsia & 0xffff) | (val << 16);
		ddi_put32(dnetp->io_handle,
		    REG32(dnetp->io_reg, SIA_GENERAL_REG), dnetp->gprsia);
		break;
	default:
		/* Set the correct bit for a control write */
		if (val & GPR_CONTROL_WRITE)
			val |= CWE_21140, val &= ~GPR_CONTROL_WRITE;
		ddi_put32(dnetp->io_handle, REG32(dnetp->io_reg, GP_REG), val);
		break;
	}
}

static uint32_t
read_gpr(struct dnetinstance *dnetp)
{
	switch (dnetp->board_type) {
	case DEVICE_ID_21143:
		/* Read upper half of CSR15 */
		return (ddi_get32(dnetp->io_handle,
		    REG32(dnetp->io_reg, SIA_GENERAL_REG)) >> 16);
	default:
		return (ddi_get32(dnetp->io_handle,
		    REG32(dnetp->io_reg, GP_REG)));
	}
}

static void
set_gpr(struct dnetinstance *dnetp)
{
	uint32_t *sequence;
	int len;
	LEAF_FORMAT *leaf = &dnetp->sr.leaf[dnetp->leaf];
	media_block_t *block = dnetp->selected_media_block;
	int i;

	if (ddi_getlongprop(DDI_DEV_T_ANY, dnetp->devinfo,
	    DDI_PROP_DONTPASS, "gpr-sequence", (caddr_t)&sequence,
	    &len) == DDI_PROP_SUCCESS) {
		for (i = 0; i < len / sizeof (uint32_t); i++)
			write_gpr(dnetp, sequence[i]);
		kmem_free(sequence, len);
	} else {
		/*
		 * Write the reset sequence if this is the first time this
		 * block has been selected.
		 */
		if (block->rstseqlen) {
			for (i = 0; i < block->rstseqlen; i++)
				write_gpr(dnetp, block->rstseq[i]);
			/*
			 * XXX Legacy blocks do not have reset sequences, so the
			 * static blocks will never be modified by this
			 */
			block->rstseqlen = 0;
		}
		if (leaf->gpr)
			write_gpr(dnetp, leaf->gpr | GPR_CONTROL_WRITE);

		/* write GPR sequence each time */
		for (i = 0; i < block->gprseqlen; i++)
			write_gpr(dnetp, block->gprseq[i]);
	}

	/* This has possibly caused a PHY to reset.  Let MII know */
	if (dnetp->phyaddr != -1)
		/* XXX function return value ignored */
		(void) mii_sync(dnetp->mii, dnetp->phyaddr);
	drv_usecwait(5);
}

/* set_opr() - must be called with intrlock held */

static void
set_opr(struct dnetinstance *dnetp)
{
	uint32_t fd, mb1, sf;

	int 		opnmode_len;
	uint32_t val;
	media_block_t *block = dnetp->selected_media_block;

	ASSERT(block);

	/* Check for custom "opnmode_reg" property */
	opnmode_len = sizeof (val);
	if (ddi_prop_op(DDI_DEV_T_ANY, dnetp->devinfo,
	    PROP_LEN_AND_VAL_BUF, DDI_PROP_DONTPASS, "opnmode_reg",
	    (caddr_t)&val, &opnmode_len) != DDI_PROP_SUCCESS)
		opnmode_len = 0;

	/* Some bits exist only on 21140 and greater */
	if (dnetp->board_type != DEVICE_ID_21040 &&
	    dnetp->board_type != DEVICE_ID_21041) {
		mb1 = OPN_REG_MB1;
		sf = STORE_AND_FORWARD;
	} else {
		mb1 = sf = 0;
		mb1 = OPN_REG_MB1; /* Needed for 21040? */
	}

	if (opnmode_len) {
		ddi_put32(dnetp->io_handle,
		    REG32(dnetp->io_reg, OPN_MODE_REG), val);
		dnet_reset_board(dnetp);
		ddi_put32(dnetp->io_handle,
		    REG32(dnetp->io_reg, OPN_MODE_REG), val);
		return;
	}

	/*
	 * Set each bit in CSR6 that we want
	 */

	/* Always want these bits set */
	val = HASH_FILTERING | HASH_ONLY | TX_THRESHOLD_160 | mb1 | sf;

	/* Promiscuous mode */
	val |= dnetp->promisc ? PROM_MODE : 0;

	/* Scrambler for SYM style media */
	val |= ((block->command & CMD_SCR) && !dnetp->disable_scrambler) ?
	    SCRAMBLER_MODE : 0;

	/* Full duplex */
	if (dnetp->mii_up) {
		fd = dnetp->mii_duplex;
	} else {
		/* Rely on media code */
		fd = block->media_code == MEDIA_TP_FD ||
		    block->media_code == MEDIA_SYM_SCR_FD;
	}

	/* Port select (and therefore, heartbeat disable) */
	val |= block->command & CMD_PS ? (PORT_SELECT | HEARTBEAT_DISABLE) : 0;

	/* PCS function */
	val |= (block->command) & CMD_PCS ? PCS_FUNCTION : 0;
	val |= fd ? FULL_DUPLEX : 0;

#ifdef DNETDEBUG
	if (dnetdebug & DNETREGCFG)
		cmn_err(CE_NOTE, "OPN: %x", val);
#endif
	ddi_put32(dnetp->io_handle, REG32(dnetp->io_reg, OPN_MODE_REG), val);
	dnet_reset_board(dnetp);
	ddi_put32(dnetp->io_handle, REG32(dnetp->io_reg, OPN_MODE_REG), val);
}

static void
set_sia(struct dnetinstance *dnetp)
{
	media_block_t *block = dnetp->selected_media_block;

	ASSERT(MUTEX_HELD(&dnetp->intrlock));
	if (block->type == 2) {
		int sia_delay;
#ifdef DNETDEBUG
		if (dnetdebug & DNETREGCFG)
			cmn_err(CE_NOTE,
			    "SIA: CSR13: %x, CSR14: %x, CSR15: %x",
			    block->un.sia.csr13,
			    block->un.sia.csr14,
			    block->un.sia.csr15);
#endif
		sia_delay = ddi_getprop(DDI_DEV_T_ANY, dnetp->devinfo,
		    DDI_PROP_DONTPASS, "sia-delay", 10000);

		ddi_put32(dnetp->io_handle,
		    REG32(dnetp->io_reg, SIA_CONNECT_REG), 0);

		ddi_put32(dnetp->io_handle, REG32(dnetp->io_reg, SIA_TXRX_REG),
		    block->un.sia.csr14);

		/*
		 * For '143, we need to write through a copy of the register
		 * to keep the GP half intact
		 */
		dnetp->gprsia = (dnetp->gprsia&0xffff0000)|block->un.sia.csr15;
		ddi_put32(dnetp->io_handle,
		    REG32(dnetp->io_reg, SIA_GENERAL_REG),
		    dnetp->gprsia);

		ddi_put32(dnetp->io_handle,
		    REG32(dnetp->io_reg, SIA_CONNECT_REG),
		    block->un.sia.csr13);

		drv_usecwait(sia_delay);

	} else if (dnetp->board_type != DEVICE_ID_21140) {
		ddi_put32(dnetp->io_handle,
		    REG32(dnetp->io_reg, SIA_CONNECT_REG), 0);
		ddi_put32(dnetp->io_handle,
		    REG32(dnetp->io_reg, SIA_TXRX_REG), 0);
	}
}

/*
 * This function (re)allocates the receive and transmit buffers and
 * descriptors.  It can be called more than once per instance, though
 * currently it is only called from attach.  It should only be called
 * while the device is reset.
 */
static int
dnet_alloc_bufs(struct dnetinstance *dnetp)
{
	int i;
	size_t len;
	int page_size;
	int realloc = 0;
	int nrecv_desc_old = 0;
	ddi_dma_cookie_t cookie;
	uint_t ncookies;

	/*
	 * check if we are trying to reallocate with different xmit/recv
	 * descriptor ring sizes.
	 */
	if ((dnetp->tx_desc != NULL) &&
	    (dnetp->nxmit_desc != dnetp->max_tx_desc))
		realloc = 1;

	if ((dnetp->rx_desc != NULL) &&
	    (dnetp->nrecv_desc != dnetp->max_rx_desc))
		realloc = 1;

	/* free up the old buffers if we are reallocating them */
	if (realloc) {
		nrecv_desc_old = dnetp->nrecv_desc;
		dnet_free_bufs(dnetp); /* free the old buffers */
	}

	if (dnetp->dma_handle == NULL)
		if (ddi_dma_alloc_handle(dnetp->devinfo, &dma_attr,
		    DDI_DMA_SLEEP, 0, &dnetp->dma_handle) != DDI_SUCCESS)
			return (FAILURE);

	if (dnetp->dma_handle_tx == NULL)
		if (ddi_dma_alloc_handle(dnetp->devinfo, &dma_attr_tx,
		    DDI_DMA_SLEEP, 0, &dnetp->dma_handle_tx) != DDI_SUCCESS)
			return (FAILURE);

	if (dnetp->dma_handle_txdesc == NULL)
		if (ddi_dma_alloc_handle(dnetp->devinfo, &dma_attr,
		    DDI_DMA_SLEEP, 0, &dnetp->dma_handle_txdesc) != DDI_SUCCESS)
			return (FAILURE);

	if (dnetp->dma_handle_setbuf == NULL)
		if (ddi_dma_alloc_handle(dnetp->devinfo, &dma_attr,
		    DDI_DMA_SLEEP, 0, &dnetp->dma_handle_setbuf) != DDI_SUCCESS)
			return (FAILURE);

	page_size = ddi_ptob(dnetp->devinfo, 1);

	dnetp->pgmask = page_size - 1;

	/* allocate setup buffer if necessary */
	if (dnetp->setup_buf_vaddr == NULL) {
		if (ddi_dma_mem_alloc(dnetp->dma_handle_setbuf,
		    SETUPBUF_SIZE, &accattr, DDI_DMA_STREAMING,
		    DDI_DMA_DONTWAIT, 0, (caddr_t *)&dnetp->setup_buf_vaddr,
		    &len, &dnetp->setup_buf_acchdl) != DDI_SUCCESS)
			return (FAILURE);

		if (ddi_dma_addr_bind_handle(dnetp->dma_handle_setbuf,
		    NULL, dnetp->setup_buf_vaddr, SETUPBUF_SIZE,
		    DDI_DMA_RDWR | DDI_DMA_STREAMING, DDI_DMA_SLEEP,
		    NULL, &cookie, &ncookies) != DDI_DMA_MAPPED)
			return (FAILURE);

		dnetp->setup_buf_paddr = cookie.dmac_address;
		bzero(dnetp->setup_buf_vaddr, len);
	}

	/* allocate xmit descriptor array of size dnetp->max_tx_desc */
	if (dnetp->tx_desc == NULL) {
		if (ddi_dma_mem_alloc(dnetp->dma_handle_txdesc,
		    sizeof (struct tx_desc_type) * dnetp->max_tx_desc,
		    &accattr, DDI_DMA_STREAMING, DDI_DMA_DONTWAIT, 0,
		    (caddr_t *)&dnetp->tx_desc, &len,
		    &dnetp->tx_desc_acchdl) != DDI_SUCCESS)
			return (FAILURE);

		if (ddi_dma_addr_bind_handle(dnetp->dma_handle_txdesc,
		    NULL, (caddr_t)dnetp->tx_desc,
		    sizeof (struct tx_desc_type) * dnetp->max_tx_desc,
		    DDI_DMA_RDWR | DDI_DMA_STREAMING, DDI_DMA_SLEEP,
		    NULL, &cookie, &ncookies) != DDI_DMA_MAPPED)
			return (FAILURE);
		dnetp->tx_desc_paddr = cookie.dmac_address;
		bzero(dnetp->tx_desc, len);
		dnetp->nxmit_desc = dnetp->max_tx_desc;

		dnetp->tx_msgbufp =
		    kmem_zalloc(dnetp->max_tx_desc * sizeof (mblk_t **),
		    KM_SLEEP);
	}

	/* allocate receive descriptor array of size dnetp->max_rx_desc */
	if (dnetp->rx_desc == NULL) {
		int ndesc;

		if (ddi_dma_mem_alloc(dnetp->dma_handle,
		    sizeof (struct rx_desc_type) * dnetp->max_rx_desc,
		    &accattr, DDI_DMA_STREAMING, DDI_DMA_DONTWAIT, 0,
		    (caddr_t *)&dnetp->rx_desc, &len,
		    &dnetp->rx_desc_acchdl) != DDI_SUCCESS)
			return (FAILURE);

		if (ddi_dma_addr_bind_handle(dnetp->dma_handle,
		    NULL, (caddr_t)dnetp->rx_desc,
		    sizeof (struct rx_desc_type) * dnetp->max_rx_desc,
		    DDI_DMA_RDWR | DDI_DMA_STREAMING, DDI_DMA_SLEEP,
		    NULL, &cookie, &ncookies) != DDI_DMA_MAPPED)
			return (FAILURE);

		dnetp->rx_desc_paddr = cookie.dmac_address;
		bzero(dnetp->rx_desc, len);
		dnetp->nrecv_desc = dnetp->max_rx_desc;

		dnetp->rx_buf_vaddr =
		    kmem_zalloc(dnetp->max_rx_desc * sizeof (caddr_t),
		    KM_SLEEP);
		dnetp->rx_buf_paddr =
		    kmem_zalloc(dnetp->max_rx_desc * sizeof (uint32_t),
		    KM_SLEEP);
		/*
		 * Allocate or add to the pool of receive buffers.  The pool
		 * is shared among all instances of dnet.
		 *
		 * XXX NEEDSWORK
		 *
		 * We arbitrarily allocate twice as many receive buffers as
		 * receive descriptors because we use the buffers for streams
		 * messages to pass the packets up the stream.  We should
		 * instead have initialized constants reflecting
		 * MAX_RX_BUF_2104x and MAX_RX_BUF_2114x, and we should also
		 * probably have a total maximum for the free pool, so that we
		 * don't get out of hand when someone puts in an 8-port board.
		 * The maximum for the entire pool should be the total number
		 * of descriptors for all attached instances together, plus the
		 * total maximum for the free pool.  This maximum would only be
		 * reached after some number of instances allocate buffers:
		 * each instance would add (max_rx_buf-max_rx_desc) to the free
		 * pool.
		 */
		ndesc = dnetp->max_rx_desc - nrecv_desc_old;
		if ((ndesc > 0) &&
		    (dnet_rbuf_init(dnetp->devinfo, ndesc * 2) != 0))
			return (FAILURE);

		for (i = 0; i < dnetp->max_rx_desc; i++) {
			struct rbuf_list *rp;

			rp = dnet_rbuf_alloc(dnetp->devinfo, 1);
			if (rp == NULL)
				return (FAILURE);
			dnetp->rx_buf_vaddr[i] = rp->rbuf_vaddr;
			dnetp->rx_buf_paddr[i] = rp->rbuf_paddr;
		}
	}

	return (SUCCESS);
}
/*
 * free descriptors/buffers allocated for this device instance.  This routine
 * should only be called while the device is reset.
 */
static void
dnet_free_bufs(struct dnetinstance *dnetp)
{
	int i;
	/* free up any xmit descriptors/buffers */
	if (dnetp->tx_desc != NULL) {
		ddi_dma_mem_free(&dnetp->tx_desc_acchdl);
		dnetp->tx_desc = NULL;
		/* we use streams buffers for DMA in xmit process */
		if (dnetp->tx_msgbufp != NULL) {
			/* free up any streams message buffers unclaimed */
			for (i = 0; i < dnetp->nxmit_desc; i++) {
				if (dnetp->tx_msgbufp[i] != NULL) {
					freemsg(dnetp->tx_msgbufp[i]);
				}
			}
			kmem_free(dnetp->tx_msgbufp,
			    dnetp->nxmit_desc * sizeof (mblk_t **));
			dnetp->tx_msgbufp = NULL;
		}
		dnetp->nxmit_desc = 0;
	}

	/* free up any receive descriptors/buffers */
	if (dnetp->rx_desc != NULL) {
		ddi_dma_mem_free(&dnetp->rx_desc_acchdl);
		dnetp->rx_desc = NULL;
		if (dnetp->rx_buf_vaddr != NULL) {
			/* free up the attached rbufs if any */
			for (i = 0; i < dnetp->nrecv_desc; i++) {
				if (dnetp->rx_buf_vaddr[i])
					dnet_rbuf_free(
					    (caddr_t)dnetp->rx_buf_vaddr[i]);
			}
			kmem_free(dnetp->rx_buf_vaddr,
			    dnetp->nrecv_desc * sizeof (caddr_t));
			kmem_free(dnetp->rx_buf_paddr,
			    dnetp->nrecv_desc * sizeof (uint32_t));
			dnetp->rx_buf_vaddr = NULL;
			dnetp->rx_buf_paddr = NULL;
		}
		dnetp->nrecv_desc = 0;
	}

	if (dnetp->setup_buf_vaddr != NULL) {
		ddi_dma_mem_free(&dnetp->setup_buf_acchdl);
		dnetp->setup_buf_vaddr = NULL;
	}

	if (dnetp->dma_handle != NULL) {
		(void) ddi_dma_unbind_handle(dnetp->dma_handle);
		ddi_dma_free_handle(&dnetp->dma_handle);
		dnetp->dma_handle = NULL;
	}

	if (dnetp->dma_handle_tx != NULL) {
		(void) ddi_dma_unbind_handle(dnetp->dma_handle_tx);
		ddi_dma_free_handle(&dnetp->dma_handle_tx);
		dnetp->dma_handle_tx = NULL;
	}

	if (dnetp->dma_handle_txdesc != NULL) {
		(void) ddi_dma_unbind_handle(dnetp->dma_handle_txdesc);
		ddi_dma_free_handle(&dnetp->dma_handle_txdesc);
		dnetp->dma_handle_txdesc = NULL;
	}

	if (dnetp->dma_handle_setbuf != NULL) {
		(void) ddi_dma_unbind_handle(dnetp->dma_handle_setbuf);
		ddi_dma_free_handle(&dnetp->dma_handle_setbuf);
		dnetp->dma_handle_setbuf = NULL;
	}

}

/*
 * Initialize transmit and receive descriptors.
 */
static void
dnet_init_txrx_bufs(struct dnetinstance *dnetp)
{
	int		i;

	/*
	 * Initilize all the Tx descriptors
	 */
	for (i = 0; i < dnetp->nxmit_desc; i++) {
		/*
		 * We may be resetting the device due to errors,
		 * so free up any streams message buffer unclaimed.
		 */
		if (dnetp->tx_msgbufp[i] != NULL) {
			freemsg(dnetp->tx_msgbufp[i]);
			dnetp->tx_msgbufp[i] = NULL;
		}
		*(uint32_t *)&dnetp->tx_desc[i].desc0 = 0;
		*(uint32_t *)&dnetp->tx_desc[i].desc1 = 0;
		dnetp->tx_desc[i].buffer1 = 0;
		dnetp->tx_desc[i].buffer2 = 0;
	}
	dnetp->tx_desc[i - 1].desc1.end_of_ring = 1;

	/*
	 * Initialize the Rx descriptors
	 */
	for (i = 0; i < dnetp->nrecv_desc; i++) {
		uint32_t end_paddr;
		*(uint32_t *)&dnetp->rx_desc[i].desc0 = 0;
		*(uint32_t *)&dnetp->rx_desc[i].desc1 = 0;
		dnetp->rx_desc[i].desc0.own = 1;
		dnetp->rx_desc[i].desc1.buffer_size1 = rx_buf_size;
		dnetp->rx_desc[i].buffer1 = dnetp->rx_buf_paddr[i];
		dnetp->rx_desc[i].buffer2 = 0;
		end_paddr = dnetp->rx_buf_paddr[i]+rx_buf_size-1;

		if ((dnetp->rx_desc[i].buffer1 & ~dnetp->pgmask) !=
		    (end_paddr & ~dnetp->pgmask)) {
			/* discontiguous */
			dnetp->rx_desc[i].buffer2 = end_paddr&~dnetp->pgmask;
			dnetp->rx_desc[i].desc1.buffer_size2 =
			    (end_paddr & dnetp->pgmask) + 1;
			dnetp->rx_desc[i].desc1.buffer_size1 =
			    rx_buf_size-dnetp->rx_desc[i].desc1.buffer_size2;
		}
	}
	dnetp->rx_desc[i - 1].desc1.end_of_ring = 1;
}

static int
alloc_descriptor(struct dnetinstance *dnetp)
{
	int index;
	struct tx_desc_type    *ring = dnetp->tx_desc;

	ASSERT(MUTEX_HELD(&dnetp->intrlock));
alloctop:
	mutex_enter(&dnetp->txlock);
	index = dnetp->tx_current_desc;

	dnet_reclaim_Tx_desc(dnetp);

	/* we do have free descriptors, right? */
	if (dnetp->free_desc <= 0) {
#ifdef DNETDEBUG
		if (dnetdebug & DNETRECV)
			cmn_err(CE_NOTE, "dnet: Ring buffer is full");
#endif
		mutex_exit(&dnetp->txlock);
		return (FAILURE);
	}

	/* sanity, make sure the next descriptor is free for use (should be) */
	if (ring[index].desc0.own) {
#ifdef DNETDEBUG
		if (dnetdebug & DNETRECV)
			cmn_err(CE_WARN,
			    "dnet: next descriptor is not free for use");
#endif
		mutex_exit(&dnetp->txlock);
		return (FAILURE);
	}
	if (dnetp->need_saddr) {
		mutex_exit(&dnetp->txlock);
		/* XXX function return value ignored */
		if (!dnetp->suspended)
			(void) dnet_set_addr(dnetp);
		goto alloctop;
	}

	*(uint32_t *)&ring[index].desc0 = 0;  /* init descs */
	*(uint32_t *)&ring[index].desc1 &= DNET_END_OF_RING;

	/* hardware will own this descriptor when poll activated */
	dnetp->free_desc--;

	/* point to next free descriptor to be used */
	dnetp->tx_current_desc = NextTXIndex(index);

#ifdef DNET_NOISY
	cmn_err(CE_WARN, "sfree 0x%x, transmitted 0x%x, tx_current 0x%x",
	    dnetp->free_desc, dnetp->transmitted_desc, dnetp->tx_current_desc);
#endif
	mutex_exit(&dnetp->txlock);
	return (SUCCESS);
}

/*
 * dnet_reclaim_Tx_desc() - called with txlock held.
 */
static void
dnet_reclaim_Tx_desc(struct dnetinstance *dnetp)
{
	struct tx_desc_type	*desc = dnetp->tx_desc;
	int index;

	ASSERT(MUTEX_HELD(&dnetp->txlock));

	index = dnetp->transmitted_desc;
	while (((dnetp->free_desc == 0) || (index != dnetp->tx_current_desc)) &&
	    !(desc[index].desc0.own)) {
		/*
		 * Check for Tx Error that gets set
		 * in the last desc.
		 */
		if (desc[index].desc1.setup_packet == 0 &&
		    desc[index].desc1.last_desc &&
		    desc[index].desc0.err_summary)
			update_tx_stats(dnetp, index);

		/*
		 * If we have used the streams message buffer for this
		 * descriptor then free up the message now.
		 */
		if (dnetp->tx_msgbufp[index] != NULL) {
			freemsg(dnetp->tx_msgbufp[index]);
			dnetp->tx_msgbufp[index] = NULL;
		}
		dnetp->free_desc++;
		index = (index+1) % dnetp->max_tx_desc;
	}

	dnetp->transmitted_desc = index;
}

/*
 * Receive buffer allocation/freeing routines.
 *
 * There is a common pool of receive buffers shared by all dnet instances.
 *
 * XXX NEEDSWORK
 *
 * We arbitrarily allocate twice as many receive buffers as
 * receive descriptors because we use the buffers for streams
 * messages to pass the packets up the stream.  We should
 * instead have initialized constants reflecting
 * MAX_RX_BUF_2104x and MAX_RX_BUF_2114x, and we should also
 * probably have a total maximum for the free pool, so that we
 * don't get out of hand when someone puts in an 8-port board.
 * The maximum for the entire pool should be the total number
 * of descriptors for all attached instances together, plus the
 * total maximum for the free pool.  This maximum would only be
 * reached after some number of instances allocate buffers:
 * each instance would add (max_rx_buf-max_rx_desc) to the free
 * pool.
 */

static struct rbuf_list *rbuf_usedlist_head;
static struct rbuf_list *rbuf_freelist_head;
static struct rbuf_list *rbuf_usedlist_end;	/* last buffer allocated */

static int rbuf_freebufs;	/* no. of free buffers in the pool */
static int rbuf_pool_size;	/* total no. of buffers in the pool */

/* initialize/add 'nbufs' buffers to the rbuf pool */
/* ARGSUSED */
static int
dnet_rbuf_init(dev_info_t *dip, int nbufs)
{
	int i;
	struct rbuf_list *rp;
	ddi_dma_cookie_t cookie;
	uint_t ncookies;
	size_t len;

	mutex_enter(&dnet_rbuf_lock);

	/* allocate buffers and add them to the pool */
	for (i = 0; i < nbufs; i++) {
		/* allocate rbuf_list element */
		rp = kmem_zalloc(sizeof (struct rbuf_list), KM_SLEEP);
		if (ddi_dma_alloc_handle(dip, &dma_attr_rb, DDI_DMA_SLEEP,
		    0, &rp->rbuf_dmahdl) != DDI_SUCCESS)
			goto fail_kfree;

		/* allocate dma memory for the buffer */
		if (ddi_dma_mem_alloc(rp->rbuf_dmahdl, rx_buf_size, &accattr,
		    DDI_DMA_STREAMING, DDI_DMA_DONTWAIT, 0,
		    &rp->rbuf_vaddr, &len,
		    &rp->rbuf_acchdl) != DDI_SUCCESS)
			goto fail_freehdl;

		if (ddi_dma_addr_bind_handle(rp->rbuf_dmahdl, NULL,
		    rp->rbuf_vaddr, len, DDI_DMA_RDWR | DDI_DMA_STREAMING,
		    DDI_DMA_SLEEP, NULL, &cookie,
		    &ncookies) != DDI_DMA_MAPPED)
			goto fail_free;

		if (ncookies > 2)
			goto fail_unbind;
		if (ncookies == 1) {
			rp->rbuf_endpaddr =
			    cookie.dmac_address + rx_buf_size - 1;
		} else {
			ddi_dma_nextcookie(rp->rbuf_dmahdl, &cookie);
			rp->rbuf_endpaddr =
			    cookie.dmac_address + cookie.dmac_size - 1;
		}
		rp->rbuf_paddr = cookie.dmac_address;

		rp->rbuf_next = rbuf_freelist_head;
		rbuf_freelist_head = rp;
		rbuf_pool_size++;
		rbuf_freebufs++;
	}

	mutex_exit(&dnet_rbuf_lock);
	return (0);
fail_unbind:
	(void) ddi_dma_unbind_handle(rp->rbuf_dmahdl);
fail_free:
	ddi_dma_mem_free(&rp->rbuf_acchdl);
fail_freehdl:
	ddi_dma_free_handle(&rp->rbuf_dmahdl);
fail_kfree:
	kmem_free(rp, sizeof (struct rbuf_list));

	mutex_exit(&dnet_rbuf_lock);
	return (-1);
}

/*
 * Try to free up all the rbufs in the pool. Returns 0 if it frees up all
 * buffers. The buffers in the used list are considered busy so these
 * buffers are not freed.
 */
static int
dnet_rbuf_destroy()
{
	struct rbuf_list *rp, *next;

	mutex_enter(&dnet_rbuf_lock);

	for (rp = rbuf_freelist_head; rp; rp = next) {
		next = rp->rbuf_next;
		ddi_dma_mem_free(&rp->rbuf_acchdl);
		(void) ddi_dma_unbind_handle(rp->rbuf_dmahdl);
		kmem_free(rp, sizeof (struct rbuf_list));
		rbuf_pool_size--;
		rbuf_freebufs--;
	}
	rbuf_freelist_head = NULL;

	if (rbuf_pool_size) { /* pool is still not empty */
		mutex_exit(&dnet_rbuf_lock);
		return (-1);
	}
	mutex_exit(&dnet_rbuf_lock);
	return (0);
}
static struct rbuf_list *
dnet_rbuf_alloc(dev_info_t *dip, int cansleep)
{
	struct rbuf_list *rp;
	size_t len;
	ddi_dma_cookie_t cookie;
	uint_t ncookies;

	mutex_enter(&dnet_rbuf_lock);

	if (rbuf_freelist_head == NULL) {

		if (!cansleep) {
			mutex_exit(&dnet_rbuf_lock);
			return (NULL);
		}

		/* allocate rbuf_list element */
		rp = kmem_zalloc(sizeof (struct rbuf_list), KM_SLEEP);
		if (ddi_dma_alloc_handle(dip, &dma_attr_rb, DDI_DMA_SLEEP,
		    0, &rp->rbuf_dmahdl) != DDI_SUCCESS)
			goto fail_kfree;

		/* allocate dma memory for the buffer */
		if (ddi_dma_mem_alloc(rp->rbuf_dmahdl, rx_buf_size, &accattr,
		    DDI_DMA_STREAMING, DDI_DMA_DONTWAIT, 0,
		    &rp->rbuf_vaddr, &len,
		    &rp->rbuf_acchdl) != DDI_SUCCESS)
			goto fail_freehdl;

		if (ddi_dma_addr_bind_handle(rp->rbuf_dmahdl, NULL,
		    rp->rbuf_vaddr, len, DDI_DMA_RDWR | DDI_DMA_STREAMING,
		    DDI_DMA_SLEEP, NULL, &cookie,
		    &ncookies) != DDI_DMA_MAPPED)
			goto fail_free;

		if (ncookies > 2)
			goto fail_unbind;
		if (ncookies == 1) {
			rp->rbuf_endpaddr =
			    cookie.dmac_address + rx_buf_size - 1;
		} else {
			ddi_dma_nextcookie(rp->rbuf_dmahdl, &cookie);
			rp->rbuf_endpaddr =
			    cookie.dmac_address + cookie.dmac_size - 1;
		}
		rp->rbuf_paddr = cookie.dmac_address;

		rbuf_freelist_head = rp;
		rbuf_pool_size++;
		rbuf_freebufs++;
	}

	/* take the buffer from the head of the free list */
	rp = rbuf_freelist_head;
	rbuf_freelist_head = rbuf_freelist_head->rbuf_next;

	/* update the used list; put the entry at the end */
	if (rbuf_usedlist_head == NULL)
		rbuf_usedlist_head = rp;
	else
		rbuf_usedlist_end->rbuf_next = rp;
	rp->rbuf_next = NULL;
	rbuf_usedlist_end = rp;
	rbuf_freebufs--;

	mutex_exit(&dnet_rbuf_lock);

	return (rp);
fail_unbind:
	(void) ddi_dma_unbind_handle(rp->rbuf_dmahdl);
fail_free:
	ddi_dma_mem_free(&rp->rbuf_acchdl);
fail_freehdl:
	ddi_dma_free_handle(&rp->rbuf_dmahdl);
fail_kfree:
	kmem_free(rp, sizeof (struct rbuf_list));
	mutex_exit(&dnet_rbuf_lock);
	return (NULL);
}

static void
dnet_rbuf_free(caddr_t vaddr)
{
	struct rbuf_list *rp, *prev;

	ASSERT(vaddr != NULL);
	ASSERT(rbuf_usedlist_head != NULL);

	mutex_enter(&dnet_rbuf_lock);

	/* find the entry in the used list */
	for (prev = rp = rbuf_usedlist_head; rp; rp = rp->rbuf_next) {
		if (rp->rbuf_vaddr == vaddr)
			break;
		prev = rp;
	}

	if (rp == NULL) {
		cmn_err(CE_WARN, "DNET: rbuf_free: bad addr 0x%p",
		    (void *)vaddr);
		mutex_exit(&dnet_rbuf_lock);
		return;
	}

	/* update the used list and put the buffer back in the free list */
	if (rbuf_usedlist_head != rp) {
		prev->rbuf_next = rp->rbuf_next;
		if (rbuf_usedlist_end == rp)
			rbuf_usedlist_end = prev;
	} else {
		rbuf_usedlist_head = rp->rbuf_next;
		if (rbuf_usedlist_end == rp)
			rbuf_usedlist_end = NULL;
	}
	rp->rbuf_next = rbuf_freelist_head;
	rbuf_freelist_head = rp;
	rbuf_freebufs++;

	mutex_exit(&dnet_rbuf_lock);
}

/*
 * Free the receive buffer used in a stream's message block allocated
 * thru desballoc().
 */
static void
dnet_freemsg_buf(struct free_ptr *frp)
{
	dnet_rbuf_free((caddr_t)frp->buf); /* buffer goes back to the pool */
	kmem_free(frp, sizeof (*frp)); /* free up the free_rtn structure */
}

/*
 *	========== SROM Read Routines ==========
 */

/*
 * The following code gets the SROM information, either by reading it
 * from the device or, failing that, by reading a property.
 */
static int
dnet_read_srom(dev_info_t *devinfo, int board_type, ddi_acc_handle_t io_handle,
    caddr_t io_reg, uchar_t *vi, int maxlen)
{
	int all_ones, zerocheck, i;

	/*
	 * Load SROM into vendor_info
	 */
	if (board_type == DEVICE_ID_21040)
		dnet_read21040addr(devinfo, io_handle, io_reg, vi, &maxlen);
	else
		/* 21041/21140 serial rom */
		dnet_read21140srom(io_handle, io_reg, vi, maxlen);
	/*
	 * If the dumpsrom property is present in the conf file, print
	 * the contents of the SROM to the console
	 */
	if (ddi_getprop(DDI_DEV_T_ANY, devinfo, DDI_PROP_DONTPASS,
	    "dumpsrom", 0))
		dnet_dumpbin("SROM", vi, 1, maxlen);

	for (zerocheck = i = 0, all_ones = 0xff; i < maxlen; i++) {
		zerocheck |= vi[i];
		all_ones &= vi[i];
	}
	if (zerocheck == 0 || all_ones == 0xff) {
		return (get_alternative_srom_image(devinfo, vi, maxlen));
	} else {
#ifdef BUG_4010796
		set_alternative_srom_image(devinfo, vi, maxlen);
#endif
		return (0);	/* Primary */
	}
}

/*
 * The function reads the ethernet address of the 21040 adapter
 */
static void
dnet_read21040addr(dev_info_t *dip, ddi_acc_handle_t io_handle, caddr_t io_reg,
    uchar_t *addr, int *len)
{
	uint32_t	val;
	int		i;

	/* No point reading more than the ethernet address */
	*len = ddi_getprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, macoffset_propname, 0) + ETHERADDRL;

	/* Reset ROM pointer */
	ddi_put32(io_handle, REG32(io_reg, ETHER_ROM_REG), 0);
	for (i = 0; i < *len; i++) {
		do {
			val = ddi_get32(io_handle,
			    REG32(io_reg, ETHER_ROM_REG));
		} while (val & 0x80000000);
		addr[i] = val & 0xFF;
	}
}

#define	drv_nsecwait(x)	drv_usecwait(((x)+999)/1000) /* XXX */

/*
 * The function reads the SROM	of the 21140 adapter
 */
static void
dnet_read21140srom(ddi_acc_handle_t io_handle, caddr_t io_reg, uchar_t *addr,
    int maxlen)
{
	uint32_t 	i, j;
	uint32_t	dout;
	uint16_t	word;
	uint8_t		rom_addr;
	uint8_t		bit;


	rom_addr = 0;
	for (i = 0; i <	maxlen; i += 2) {
		ddi_put32(io_handle, REG32(io_reg, ETHER_ROM_REG),
		    READ_OP | SEL_ROM);
		drv_nsecwait(30);
		ddi_put32(io_handle, REG32(io_reg, ETHER_ROM_REG),
		    READ_OP | SEL_ROM | SEL_CHIP);
		drv_nsecwait(50);
		ddi_put32(io_handle, REG32(io_reg, ETHER_ROM_REG),
		    READ_OP | SEL_ROM | SEL_CHIP | SEL_CLK);
		drv_nsecwait(250);
		ddi_put32(io_handle, REG32(io_reg, ETHER_ROM_REG),
		    READ_OP | SEL_ROM | SEL_CHIP);
		drv_nsecwait(100);

		/* command */
		ddi_put32(io_handle, REG32(io_reg, ETHER_ROM_REG),
		    READ_OP | SEL_ROM | SEL_CHIP | DATA_IN);
		drv_nsecwait(150);
		ddi_put32(io_handle, REG32(io_reg, ETHER_ROM_REG),
		    READ_OP | SEL_ROM | SEL_CHIP | DATA_IN | SEL_CLK);
		drv_nsecwait(250);
		ddi_put32(io_handle, REG32(io_reg, ETHER_ROM_REG),
		    READ_OP | SEL_ROM | SEL_CHIP | DATA_IN);
		drv_nsecwait(250);
		ddi_put32(io_handle, REG32(io_reg, ETHER_ROM_REG),
		    READ_OP | SEL_ROM | SEL_CHIP | DATA_IN | SEL_CLK);
		drv_nsecwait(250);
		ddi_put32(io_handle, REG32(io_reg, ETHER_ROM_REG),
		    READ_OP | SEL_ROM | SEL_CHIP | DATA_IN);
		drv_nsecwait(100);
		ddi_put32(io_handle, REG32(io_reg, ETHER_ROM_REG),
		    READ_OP | SEL_ROM | SEL_CHIP);
		drv_nsecwait(150);
		ddi_put32(io_handle, REG32(io_reg, ETHER_ROM_REG),
		    READ_OP | SEL_ROM | SEL_CHIP | SEL_CLK);
		drv_nsecwait(250);
		ddi_put32(io_handle, REG32(io_reg, ETHER_ROM_REG),
		    READ_OP | SEL_ROM | SEL_CHIP);
		drv_nsecwait(100);

		/* Address */
		for (j = HIGH_ADDRESS_BIT; j >= 1; j >>= 1) {
			bit = (rom_addr & j) ? DATA_IN : 0;
			ddi_put32(io_handle, REG32(io_reg, ETHER_ROM_REG),
			    READ_OP | SEL_ROM | SEL_CHIP | bit);
			drv_nsecwait(150);
			ddi_put32(io_handle, REG32(io_reg, ETHER_ROM_REG),
			    READ_OP | SEL_ROM | SEL_CHIP | bit | SEL_CLK);
			drv_nsecwait(250);
			ddi_put32(io_handle, REG32(io_reg, ETHER_ROM_REG),
			    READ_OP | SEL_ROM | SEL_CHIP | bit);
			drv_nsecwait(100);
		}
		drv_nsecwait(150);

		/* Data */
		word = 0;
		for (j = 0x8000; j >= 1; j >>= 1) {
			ddi_put32(io_handle, REG32(io_reg, ETHER_ROM_REG),
			    READ_OP | SEL_ROM | SEL_CHIP | SEL_CLK);
			drv_nsecwait(100);
			dout = ddi_get32(io_handle,
			    REG32(io_reg, ETHER_ROM_REG));
			drv_nsecwait(150);
			if (dout & DATA_OUT)
				word |= j;
			ddi_put32(io_handle,
			    REG32(io_reg, ETHER_ROM_REG),
			    READ_OP | SEL_ROM | SEL_CHIP);
			drv_nsecwait(250);
		}
		addr[i] = (word & 0x0000FF);
		addr[i + 1] = (word >> 8);
		rom_addr++;
		ddi_put32(io_handle, REG32(io_reg, ETHER_ROM_REG),
		    READ_OP | SEL_ROM);
		drv_nsecwait(100);
	}
}


/*
 * XXX NEEDSWORK
 *
 * Some lame multiport cards have only one SROM, which can be accessed
 * only from the "first" 21x4x chip, whichever that one is.  If we can't
 * get at our SROM, we look for its contents in a property instead, which
 * we rely on the bootstrap to have properly set.
 * #ifdef BUG_4010796
 * We also have a hack to try to set it ourselves, when the "first" port
 * attaches, if it has not already been properly set.  However, this method
 * is not reliable, since it makes the unwarrented assumption that the
 * "first" port will attach first.
 * #endif
 */

static int
get_alternative_srom_image(dev_info_t *devinfo, uchar_t *vi, int len)
{
	int	l = len;

	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, devinfo, DDI_PROP_DONTPASS,
	    "DNET_SROM", (caddr_t)vi, &len) != DDI_PROP_SUCCESS &&
	    (len = l) && ddi_getlongprop_buf(DDI_DEV_T_ANY,
	    ddi_get_parent(devinfo), DDI_PROP_DONTPASS, "DNET_SROM",
	    (caddr_t)vi, &len) != DDI_PROP_SUCCESS)
		return (-1);	/* Can't find it! */

	/*
	 * The return value from this routine specifies which port number
	 * we are.  The primary port is denoted port 0.  On a QUAD card we
	 * should return 1, 2, and 3 from this routine.  The return value
	 * is used to modify the ethernet address from the SROM data.
	 */

#ifdef BUG_4010796
	{
	/*
	 * For the present, we remember the device number of our primary
	 * sibling and hope we and our other siblings are consecutively
	 * numbered up from there.  In the future perhaps the bootstrap
	 * will pass us the necessary information telling us which physical
	 * port we really are.
	 */
	pci_regspec_t	*assignp;
	int		assign_len;
	int 		devnum;
	int		primary_devnum;

	primary_devnum = ddi_getprop(DDI_DEV_T_ANY, devinfo, 0,
	    "DNET_DEVNUM", -1);
	if (primary_devnum == -1)
		return (1);	/* XXX NEEDSWORK -- We have no better idea */

	if ((ddi_getlongprop(DDI_DEV_T_ANY, devinfo, DDI_PROP_DONTPASS,
	    "assigned-addresses", (caddr_t)&assignp,
	    &assign_len)) != DDI_PROP_SUCCESS)
		return (1);	/* XXX NEEDSWORK -- We have no better idea */

	devnum = PCI_REG_DEV_G(assignp->pci_phys_hi);
	kmem_free(assignp, assign_len);
	return (devnum - primary_devnum);
	}
#else
	return (1);	/* XXX NEEDSWORK -- We have no better idea */
#endif
}


#ifdef BUG_4010796
static void
set_alternative_srom_image(dev_info_t *devinfo, uchar_t *vi, int len)
{
	int 		proplen;
	pci_regspec_t	*assignp;
	int		assign_len;
	int 		devnum;

	if (ddi_getproplen(DDI_DEV_T_ANY, devinfo, DDI_PROP_DONTPASS,
	    "DNET_SROM", &proplen) == DDI_PROP_SUCCESS ||
	    ddi_getproplen(DDI_DEV_T_ANY, ddi_get_parent(devinfo),
	    DDI_PROP_DONTPASS, "DNET_SROM", &proplen) == DDI_PROP_SUCCESS)
		return;		/* Already done! */

	/* function return value ignored */
	(void) ddi_prop_update_byte_array(DDI_DEV_T_NONE,
	    ddi_get_parent(devinfo), "DNET_SROM", (uchar_t *)vi, len);
	(void) ddi_prop_update_string(DDI_DEV_T_NONE, devinfo,
	    "DNET_HACK", "hack");

	if ((ddi_getlongprop(DDI_DEV_T_ANY, devinfo, DDI_PROP_DONTPASS,
	    "assigned-addresses", (caddr_t)&assignp,
	    &assign_len)) == DDI_PROP_SUCCESS) {
		devnum = PCI_REG_DEV_G(assignp->pci_phys_hi);
		kmem_free(assignp, assign_len);
		/* function return value ignored */
		(void) ddi_prop_update_int(DDI_DEV_T_NONE,
		    ddi_get_parent(devinfo), "DNET_DEVNUM", devnum);
	}
}
#endif

/*
 *	========== SROM Parsing Routines ==========
 */

static int
check_srom_valid(uchar_t *vi)
{
	int		word, bit;
	uint8_t		crc;
	uint16_t	*wvi;		/* word16 pointer to vendor info */
	uint16_t	bitval;

	/* verify that the number of controllers on the card is within range */
	if (vi[SROM_ADAPTER_CNT] < 1 || vi[SROM_ADAPTER_CNT] > MAX_ADAPTERS)
		return (0);

	/*
	 * version 1 and 3 of this card did not check the id block CRC value
	 * and this can't be changed without retesting every supported card
	 *
	 * however version 4 of the SROM can have this test applied
	 * without fear of breaking something that used to work.
	 * the CRC algorithm is taken from the Intel document
	 *	"21x4 Serial ROM Format"
	 *	version 4.09
	 *	3-Mar-1999
	 */

	switch (vi[SROM_VERSION]) {
	case 1:
	    /* fallthru */
	case 3:
		return (vi[SROM_MBZ] == 0 &&	/* must be zero */
		    vi[SROM_MBZ2] == 0 &&	/* must be zero */
		    vi[SROM_MBZ3] == 0);	/* must be zero */

	case 4:
		wvi = (uint16_t *)vi;
		crc = 0xff;
		for (word = 0; word < 9; word++)
			for (bit = 15; bit >= 0; bit--) {
				if (word == 8 && bit == 7)
					return (crc == vi[16]);
				bitval =
				    ((wvi[word] >> bit) & 1) ^ ((crc >> 7) & 1);
				crc <<= 1;
				if (bitval == 1) {
					crc ^= 7;
				}
			}
		/* FALLTHROUGH */

	default:
		return (0);
	}
}

/*
 *	========== Active Media Determination Routines ==========
 */

/* This routine is also called for V3 Compact and extended type 0 SROMs */
static int
is_fdmedia(int media)
{
	if (media == MEDIA_TP_FD || media == MEDIA_SYM_SCR_FD)
		return (1);
	else
		return (0);
}

/*
 * "Linkset" is used to merge media that use the same link test check. So,
 * if the TP link is added to the linkset, so is the TP Full duplex link.
 * Used to avoid checking the same link status twice.
 */
static void
linkset_add(uint32_t *set, int media)
{
	if (media == MEDIA_TP_FD || media == MEDIA_TP)
		*set |= (1UL<<MEDIA_TP_FD) | (1UL<<MEDIA_TP);
	else if (media == MEDIA_SYM_SCR_FD || media == MEDIA_SYM_SCR)
		*set |= (1UL<<MEDIA_SYM_SCR_FD) | (1UL<<MEDIA_SYM_SCR);
	else *set |= 1UL<<media;
}
static int
linkset_isset(uint32_t linkset, int media)
{
	return (((1UL<<media)  & linkset) ? 1:0);
}

/*
 * The following code detects which Media is connected for 21041/21140
 * Expect to change this code to support new 21140 variants.
 * find_active_media() - called with intrlock held.
 */
static void
find_active_media(struct dnetinstance *dnetp)
{
	int i;
	media_block_t *block;
	media_block_t *best_allowed = NULL;
	media_block_t *hd_found = NULL;
	media_block_t *fd_found = NULL;
	LEAF_FORMAT *leaf = &dnetp->sr.leaf[dnetp->leaf];
	uint32_t checked = 0, links_up = 0;

	ASSERT(MUTEX_HELD(&dnetp->intrlock));

	dnetp->selected_media_block = leaf->default_block;

	if (dnetp->phyaddr != -1) {
		dnetp->selected_media_block = leaf->mii_block;
		setup_block(dnetp);

		if (ddi_getprop(DDI_DEV_T_ANY, dnetp->devinfo,
		    DDI_PROP_DONTPASS, "portmon", 1)) {
			/* XXX return value ignored */
			(void) mii_start_portmon(dnetp->mii, dnet_mii_link_cb,
			    &dnetp->intrlock);
			/*
			 * If the port monitor detects the link is already
			 * up, there is no point going through the rest of the
			 * link sense
			 */
			if (dnetp->mii_up) {
				return;
			}
		}
	}

	/*
	 * Media is searched for in order of Precedence. This DEC SROM spec
	 * tells us that the first media entry in the SROM is the lowest
	 * precedence and should be checked last. This is why we go to the last
	 * Media block and work back to the beginning.
	 *
	 * However, some older SROMs (Cogent EM110's etc.) have this the wrong
	 * way around. As a result, following the SROM spec would result in a
	 * 10 link being chosen over a 100 link if both media are available.
	 * So we continue trying the media until we have at least tried the
	 * DEFAULT media.
	 */

	/* Search for an active medium, and select it */
	for (block = leaf->block + leaf->block_count  - 1;
	    block >= leaf->block; block--) {
		int media = block->media_code;

		/* User settings disallow selection of this block */
		if (dnetp->disallowed_media & (1UL<<media))
			continue;

		/* We may not be able to pick the default */
		if (best_allowed == NULL || block == leaf->default_block)
			best_allowed = block;
#ifdef DEBUG
		if (dnetdebug & DNETSENSE)
			cmn_err(CE_NOTE, "Testing %s medium (block type %d)",
			    media_str[media], block->type);
#endif

		dnetp->selected_media_block = block;
		switch (block->type) {

		case 2: /* SIA Media block: Best we can do is send a packet */
			setup_block(dnetp);
			if (send_test_packet(dnetp)) {
				if (!is_fdmedia(media))
					return;
				if (!fd_found)
					fd_found = block;
			}
			break;

		/* SYM/SCR or TP block: Use the link-sense bits */
		case 0:
			if (!linkset_isset(checked, media)) {
				linkset_add(&checked, media);
				if (((media == MEDIA_BNC ||
				    media == MEDIA_AUI) &&
				    send_test_packet(dnetp)) ||
				    dnet_link_sense(dnetp))
					linkset_add(&links_up, media);
			}

			if (linkset_isset(links_up, media)) {
				/*
				 * Half Duplex is *always* the favoured media.
				 * Full Duplex can be set and forced via the
				 * conf file.
				 */
				if (!is_fdmedia(media) &&
				    dnetp->selected_media_block ==
				    leaf->default_block) {
					/*
					 * Cogent cards have the media in
					 * opposite order to the spec.,
					 * this code forces the media test to
					 * keep going until the default media
					 * is tested.
					 *
					 * In Cogent case, 10, 10FD, 100FD, 100
					 * 100 is the default but 10 could have
					 * been detected and would have been
					 * chosen but now we force it through to
					 * 100.
					 */
					setup_block(dnetp);
					return;
				} else if (!is_fdmedia(media)) {
					/*
					 * This allows all the others to work
					 * properly by remembering the media
					 * that works and not defaulting to
					 * a FD link.
					 */
						if (hd_found == NULL)
							hd_found = block;
				} else if (fd_found == NULL) {
					/*
					 * No media have already been found
					 * so far, this is FD, it works so
					 * remember it and if no others are
					 * detected, use it.
					 */
					fd_found = block;
				}
			}
			break;

		/*
		 * MII block: May take up to a second or so to settle if
		 * setup causes a PHY reset
		 */
		case 1: case 3:
			setup_block(dnetp);
			for (i = 0; ; i++) {
				if (mii_linkup(dnetp->mii, dnetp->phyaddr)) {
					/* XXX function return value ignored */
					(void) mii_getspeed(dnetp->mii,
					    dnetp->phyaddr,
					    &dnetp->mii_speed,
					    &dnetp->mii_duplex);
					dnetp->mii_up = 1;
					leaf->mii_block = block;
					return;
				}
				if (i == 10)
					break;
				delay(drv_usectohz(150000));
			}
			dnetp->mii_up = 0;
			break;
		}
	} /* for loop */
	if (hd_found) {
		dnetp->selected_media_block = hd_found;
	} else if (fd_found) {
		dnetp->selected_media_block = fd_found;
	} else {
		if (best_allowed == NULL)
			best_allowed = leaf->default_block;
		dnetp->selected_media_block = best_allowed;
		cmn_err(CE_WARN, "!dnet: Default media selected\n");
	}
	setup_block(dnetp);
}

/*
 * Do anything neccessary to select the selected_media_block.
 * setup_block() - called with intrlock held.
 */
static void
setup_block(struct dnetinstance *dnetp)
{
	dnet_reset_board(dnetp);
	dnet_init_board(dnetp);
	/* XXX function return value ignored */
	(void) dnet_start(dnetp);
}

/* dnet_link_sense() - called with intrlock held */
static int
dnet_link_sense(struct dnetinstance *dnetp)
{
	/*
	 * This routine makes use of the command word from the srom config.
	 * Details of the auto-sensing information contained in this can
	 * be found in the "Digital Semiconductor 21X4 Serial ROM Format v3.03"
	 * spec. Section 4.3.2.1, and 4.5.2.1.3
	 */
	media_block_t *block = dnetp->selected_media_block;
	uint32_t link, status, mask, polarity;
	int settletime, stabletime, waittime, upsamples;
	int delay_100, delay_10;


	ASSERT(MUTEX_HELD(&dnetp->intrlock));
	/* Don't autosense if the medium does not support it */
	if (block->command & (1 << 15)) {
		/* This should be the default block */
		if (block->command & (1UL<<14))
			dnetp->sr.leaf[dnetp->leaf].default_block = block;
		return (0);
	}

	delay_100 = ddi_getprop(DDI_DEV_T_ANY, dnetp->devinfo,
	    DDI_PROP_DONTPASS, "autosense-delay-100", 2000);

	delay_10 = ddi_getprop(DDI_DEV_T_ANY, dnetp->devinfo,
	    DDI_PROP_DONTPASS, "autosense-delay-10", 400);

	/*
	 * Scrambler may need to be disabled for link sensing
	 * to work
	 */
	dnetp->disable_scrambler = 1;
	setup_block(dnetp);
	dnetp->disable_scrambler = 0;

	if (block->media_code == MEDIA_TP || block->media_code == MEDIA_TP_FD)
		settletime = delay_10;
	else
		settletime = delay_100;
	stabletime = settletime / 4;

	mask = 1 << ((block->command & CMD_MEDIABIT_MASK) >> 1);
	polarity = block->command & CMD_POL ? 0xffffffff : 0;

	for (waittime = 0, upsamples = 0;
	    waittime <= settletime + stabletime && upsamples < 8;
	    waittime += stabletime/8) {
		delay(drv_usectohz(stabletime*1000 / 8));
		status = read_gpr(dnetp);
		link = (status^polarity) & mask;
		if (link)
			upsamples++;
		else
			upsamples = 0;
	}
#ifdef DNETDEBUG
	if (dnetdebug & DNETSENSE)
		cmn_err(CE_NOTE, "%s upsamples:%d stat:%x polarity:%x "
		    "mask:%x link:%x",
		    upsamples == 8 ? "UP":"DOWN",
		    upsamples, status, polarity, mask, link);
#endif
	if (upsamples == 8)
		return (1);
	return (0);
}

static int
send_test_packet(struct dnetinstance *dnetp)
{
	int packet_delay;
	struct tx_desc_type *desc;
	int bufindex;
	int media_code = dnetp->selected_media_block->media_code;
	uint32_t del;

	ASSERT(MUTEX_HELD(&dnetp->intrlock));
	/*
	 * For a successful test packet, the card must have settled into
	 * its current setting.  Almost all cards we've tested manage to
	 * do this with all media within 50ms.  However, the SMC 8432
	 * requires 300ms to settle into BNC mode.  We now only do this
	 * from attach, and we do sleeping delay() instead of drv_usecwait()
	 * so we hope this .2 second delay won't cause too much suffering.
	 * ALSO: with an autonegotiating hub, an aditional 1 second delay is
	 * required. This is done if the media type is TP
	 */
	if (media_code == MEDIA_TP || media_code == MEDIA_TP_FD) {
		packet_delay = ddi_getprop(DDI_DEV_T_ANY, dnetp->devinfo,
		    DDI_PROP_DONTPASS, "test_packet_delay_tp", 1300000);
	} else {
		packet_delay = ddi_getprop(DDI_DEV_T_ANY, dnetp->devinfo,
		    DDI_PROP_DONTPASS, "test_packet_delay", 300000);
	}
	delay(drv_usectohz(packet_delay));

	desc = dnetp->tx_desc;

	bufindex = dnetp->tx_current_desc;
	if (alloc_descriptor(dnetp) == FAILURE) {
		cmn_err(CE_WARN, "DNET: send_test_packet: alloc_descriptor"
		    "failed");
		return (0);
	}

	/*
	 * use setup buffer as the buffer for the test packet
	 * instead of allocating one.
	 */

	ASSERT(dnetp->setup_buf_vaddr != NULL);
	/* Put something decent in dest address so we don't annoy other cards */
	BCOPY((caddr_t)dnetp->curr_macaddr,
	    (caddr_t)dnetp->setup_buf_vaddr, ETHERADDRL);
	BCOPY((caddr_t)dnetp->curr_macaddr,
	    (caddr_t)dnetp->setup_buf_vaddr+ETHERADDRL, ETHERADDRL);

	desc[bufindex].buffer1 = dnetp->setup_buf_paddr;
	desc[bufindex].desc1.buffer_size1 = SETUPBUF_SIZE;
	desc[bufindex].buffer2 = (uint32_t)(0);
	desc[bufindex].desc1.first_desc = 1;
	desc[bufindex].desc1.last_desc = 1;
	desc[bufindex].desc1.int_on_comp = 1;
	desc[bufindex].desc0.own = 1;

	ddi_put8(dnetp->io_handle, REG8(dnetp->io_reg, TX_POLL_REG),
	    TX_POLL_DEMAND);

	/*
	 * Give enough time for the chip to transmit the packet
	 */
#if 1
	del = 1000;
	while (desc[bufindex].desc0.own && --del)
		drv_usecwait(10);	/* quickly wait up to 10ms */
	if (desc[bufindex].desc0.own)
		delay(drv_usectohz(200000));	/* nicely wait a longer time */
#else
	del = 0x10000;
	while (desc[bufindex].desc0.own && --del)
		drv_usecwait(10);
#endif

#ifdef DNETDEBUG
	if (dnetdebug & DNETSENSE)
		cmn_err(CE_NOTE, "desc0 bits = %u, %u, %u, %u, %u, %u",
		    desc[bufindex].desc0.own,
		    desc[bufindex].desc0.err_summary,
		    desc[bufindex].desc0.carrier_loss,
		    desc[bufindex].desc0.no_carrier,
		    desc[bufindex].desc0.late_collision,
		    desc[bufindex].desc0.link_fail);
#endif
	if (desc[bufindex].desc0.own) /* it shouldn't take this long, error */
		return (0);

	return (!desc[bufindex].desc0.err_summary);
}

/* enable_interrupts - called with intrlock held */
static void
enable_interrupts(struct dnetinstance *dnetp)
{
	ASSERT(MUTEX_HELD(&dnetp->intrlock));
	/* Don't enable interrupts if they have been forced off */
	if (dnetp->interrupts_disabled)
		return;
	ddi_put32(dnetp->io_handle, REG32(dnetp->io_reg, INT_MASK_REG),
	    ABNORMAL_INTR_MASK | NORMAL_INTR_MASK | SYSTEM_ERROR_MASK |
	    (dnetp->timer.cb ? GPTIMER_INTR : 0) |
	    RX_INTERRUPT_MASK |
	    TX_INTERRUPT_MASK | TX_JABBER_MASK | TX_UNDERFLOW_MASK);
}

/*
 * Some older multiport cards are non-PCI compliant in their interrupt routing.
 * Second and subsequent devices are incorrectly configured by the BIOS
 * (either in their ILINE configuration or the MP Configuration Table for PC+MP
 * systems).
 * The hack stops registering the interrupt routine for the FIRST
 * device on the adapter, and registers its own. It builds up a table
 * of dnetp structures for each device, and the new interrupt routine
 * calls dnet_intr for each of them.
 * Known cards that suffer from this problem are:
 *	All Cogent multiport cards;
 * 	Znyx 314;
 *	Znyx 315.
 *
 * XXX NEEDSWORK -- see comments above get_alternative_srom_image(). This
 * hack relies on the fact that the offending cards will have only one SROM.
 * It uses this fact to identify devices that are on the same multiport
 * adapter, as opposed to multiple devices from the same vendor (as
 * indicated by "secondary")
 */
static int
dnet_hack_interrupts(struct dnetinstance *dnetp, int secondary)
{
	int i;
	struct hackintr_inf *hackintr_inf;
	dev_info_t *devinfo = dnetp->devinfo;
	uint32_t oui = 0;	/* Organizationally Unique ID */

	if (ddi_getprop(DDI_DEV_T_ANY, devinfo, DDI_PROP_DONTPASS,
	    "no_INTA_workaround", 0) != 0)
		return (0);

	for (i = 0; i < 3; i++)
		oui = (oui << 8) | dnetp->vendor_addr[i];

	/* Check wheather or not we need to implement the hack */

	switch (oui) {
	case ZNYX_ETHER:
		/* Znyx multiport 21040 cards <<==>> ZX314 or ZX315 */
		if (dnetp->board_type != DEVICE_ID_21040)
			return (0);
		break;

	case COGENT_ETHER:
		/* All known Cogent multiport cards */
		break;

	case ADAPTEC_ETHER:
		/* Adaptec multiport cards */
		break;

	default:
		/* Other cards work correctly */
		return (0);
	}

	/* card is (probably) non-PCI compliant in its interrupt routing */


	if (!secondary) {

		/*
		 * If we have already registered a hacked interrupt, and
		 * this is also a 'primary' adapter, then this is NOT part of
		 * a multiport card, but a second card on the same PCI bus.
		 * BUGID: 4057747
		 */
		if (ddi_getprop(DDI_DEV_T_ANY, ddi_get_parent(devinfo),
		    DDI_PROP_DONTPASS, hackintr_propname, 0) != 0)
			return (0);
				/* ... Primary not part of a multiport device */

#ifdef DNETDEBUG
		if (dnetdebug & DNETTRACE)
			cmn_err(CE_NOTE, "dnet: Implementing hardware "
			    "interrupt flaw workaround");
#endif
		dnetp->hackintr_inf = hackintr_inf =
		    kmem_zalloc(sizeof (struct hackintr_inf), KM_SLEEP);
		if (hackintr_inf == NULL)
			goto fail;

		hackintr_inf->dnetps[0] = dnetp;
		hackintr_inf->devinfo = devinfo;

		/*
		 * Add a property to allow successive attaches to find the
		 * table
		 */

		if (ddi_prop_update_byte_array(DDI_DEV_T_NONE,
		    ddi_get_parent(devinfo), hackintr_propname,
		    (uchar_t *)&dnetp->hackintr_inf,
		    sizeof (void *)) != DDI_PROP_SUCCESS)
			goto fail;


		/* Register our hacked interrupt routine */
		if (ddi_add_intr(devinfo, 0, &dnetp->icookie, NULL,
		    (uint_t (*)(char *))dnet_hack_intr,
		    (caddr_t)hackintr_inf) != DDI_SUCCESS) {
			/* XXX function return value ignored */
			(void) ddi_prop_remove(DDI_DEV_T_NONE,
			    ddi_get_parent(devinfo),
			    hackintr_propname);
			goto fail;
		}

		/*
		 * Mutex required to ensure interrupt routine has completed
		 * when detaching devices
		 */
		mutex_init(&hackintr_inf->lock, NULL, MUTEX_DRIVER,
		    dnetp->icookie);

		/* Stop GLD registering an interrupt */
		return (-1);
	} else {

		/* Add the dnetp for this secondary device to the table */

		hackintr_inf = (struct hackintr_inf *)(uintptr_t)
		    ddi_getprop(DDI_DEV_T_ANY, ddi_get_parent(devinfo),
		    DDI_PROP_DONTPASS, hackintr_propname, 0);

		if (hackintr_inf == NULL)
			goto fail;

		/* Find an empty slot */
		for (i = 0; i < MAX_INST; i++)
			if (hackintr_inf->dnetps[i] == NULL)
				break;

		/* More than 8 ports on adapter ?! */
		if (i == MAX_INST)
			goto fail;

		hackintr_inf->dnetps[i] = dnetp;

		/*
		 * Allow GLD to register a handler for this
		 * device. If the card is actually broken, as we suspect, this
		 * handler will never get called. However, by registering the
		 * interrupt handler, we can copy gracefully with new multiport
		 * Cogent cards that decide to fix the hardware problem
		 */
		return (0);
	}

fail:
	cmn_err(CE_WARN, "dnet: Could not work around hardware interrupt"
	    " routing problem");
	return (0);
}

/*
 * Call dnet_intr for all adapters on a multiport card
 */
static uint_t
dnet_hack_intr(struct hackintr_inf *hackintr_inf)
{
	int i;
	int claimed = DDI_INTR_UNCLAIMED;

	/* Stop detaches while processing interrupts */
	mutex_enter(&hackintr_inf->lock);

	for (i = 0; i < MAX_INST; i++) {
		if (hackintr_inf->dnetps[i] &&
		    dnet_intr((caddr_t)hackintr_inf->dnetps[i]) ==
		    DDI_INTR_CLAIMED) {
			claimed = DDI_INTR_CLAIMED;
		}
	}
	mutex_exit(&hackintr_inf->lock);
	return (claimed);
}

/*
 * This removes the detaching device from the table procesed by the hacked
 * interrupt routine. Because the interrupts from all devices come in to the
 * same interrupt handler, ALL devices must stop interrupting once the
 * primary device detaches. This isn't a problem at present, because all
 * instances of a device are detached when the driver is unloaded.
 */
static int
dnet_detach_hacked_interrupt(dev_info_t *devinfo)
{
	int i;
	struct hackintr_inf *hackintr_inf;
	struct dnetinstance *altdnetp, *dnetp =
	    ddi_get_driver_private(devinfo);

	hackintr_inf = (struct hackintr_inf *)(uintptr_t)
	    ddi_getprop(DDI_DEV_T_ANY, ddi_get_parent(devinfo),
	    DDI_PROP_DONTPASS, hackintr_propname, 0);

	/*
	 * No hackintr_inf implies hack was not required or the primary has
	 * detached, and our interrupts are already disabled
	 */
	if (!hackintr_inf) {
		/* remove the interrupt for the non-hacked case */
		ddi_remove_intr(devinfo, 0, dnetp->icookie);
		return (DDI_SUCCESS);
	}

	/* Remove this device from the handled table */
	mutex_enter(&hackintr_inf->lock);
	for (i = 0; i < MAX_INST; i++) {
		if (hackintr_inf->dnetps[i] == dnetp) {
			hackintr_inf->dnetps[i] = NULL;
			break;
		}
	}

	mutex_exit(&hackintr_inf->lock);

	/* Not the primary card, we are done */
	if (devinfo != hackintr_inf->devinfo)
		return (DDI_SUCCESS);

	/*
	 * This is the primary card. All remaining adapters on this device
	 * must have their interrupts disabled before we remove the handler
	 */
	for (i = 0; i < MAX_INST; i++) {
		if ((altdnetp = hackintr_inf->dnetps[i]) != NULL) {
			altdnetp->interrupts_disabled = 1;
			ddi_put32(altdnetp->io_handle,
			    REG32(altdnetp->io_reg, INT_MASK_REG), 0);
		}
	}

	/* It should now be safe to remove the interrupt handler */

	ddi_remove_intr(devinfo, 0, dnetp->icookie);
	mutex_destroy(&hackintr_inf->lock);
	/* XXX function return value ignored */
	(void) ddi_prop_remove(DDI_DEV_T_NONE, ddi_get_parent(devinfo),
	    hackintr_propname);
	kmem_free(hackintr_inf, sizeof (struct hackintr_inf));
	return (DDI_SUCCESS);
}

/* do_phy() - called with intrlock held */
static void
do_phy(struct dnetinstance *dnetp)
{
	dev_info_t *dip;
	LEAF_FORMAT *leaf = dnetp->sr.leaf + dnetp->leaf;
	media_block_t *block;
	int phy;

	dip = dnetp->devinfo;

	/*
	 * Find and configure the PHY media block. If NO PHY blocks are
	 * found on the SROM, but a PHY device is present, we assume the card
	 * is a legacy device, and that there is ONLY a PHY interface on the
	 * card (ie, no BNC or AUI, and 10BaseT is implemented by the PHY
	 */

	for (block = leaf->block + leaf->block_count -1;
	    block >= leaf->block; block --) {
		if (block->type == 3 || block->type == 1) {
			leaf->mii_block = block;
			break;
		}
	}

	/*
	 * If no MII block, select default, and hope this configuration will
	 * allow the phy to be read/written if it is present
	 */
	dnetp->selected_media_block = leaf->mii_block ?
	    leaf->mii_block : leaf->default_block;

	setup_block(dnetp);
	/* XXX function return value ignored */
	(void) mii_create(dip, dnet_mii_write, dnet_mii_read, &dnetp->mii);

	/*
	 * We try PHY 0 LAST because it is less likely to be connected
	 */
	for (phy = 1; phy < 33; phy++)
		if (mii_probe_phy(dnetp->mii, phy % 32) == MII_SUCCESS &&
		    mii_init_phy(dnetp->mii, phy % 32) == MII_SUCCESS) {
#ifdef DNETDEBUG
			if (dnetdebug & DNETSENSE)
				cmn_err(CE_NOTE, "dnet: "
				    "PHY at address %d", phy % 32);
#endif
			dnetp->phyaddr = phy % 32;
			if (!leaf->mii_block) {
				/* Legacy card, change the leaf node */
				set_leaf(&dnetp->sr, &leaf_phylegacy);
			}
			return;
		}
#ifdef DNETDEBUG
	if (dnetdebug & DNETSENSE)
		cmn_err(CE_NOTE, "dnet: No PHY found");
#endif
}

static ushort_t
dnet_mii_read(dev_info_t *dip, int phy_addr, int reg_num)
{
	struct dnetinstance *dnetp;

	uint32_t command_word;
	uint32_t tmp;
	uint32_t data = 0;
	int i;
	int bits_in_ushort = ((sizeof (ushort_t))*8);
	int turned_around = 0;

	dnetp = ddi_get_driver_private(dip);

	ASSERT(MUTEX_HELD(&dnetp->intrlock));
	/* Write Preamble */
	write_mii(dnetp, MII_PRE, 2*bits_in_ushort);

	/* Prepare command word */
	command_word = (uint32_t)phy_addr << MII_PHY_ADDR_ALIGN;
	command_word |= (uint32_t)reg_num << MII_REG_ADDR_ALIGN;
	command_word |= MII_READ_FRAME;

	write_mii(dnetp, command_word, bits_in_ushort-2);

	mii_tristate(dnetp);

	/* Check that the PHY generated a zero bit the 2nd clock */
	tmp = ddi_get32(dnetp->io_handle, REG32(dnetp->io_reg, ETHER_ROM_REG));

	turned_around = (tmp & MII_DATA_IN) ? 0 : 1;

	/* read data WORD */
	for (i = 0; i < bits_in_ushort; i++) {
		ddi_put32(dnetp->io_handle,
		    REG32(dnetp->io_reg, ETHER_ROM_REG), MII_READ);
		drv_usecwait(MII_DELAY);
		ddi_put32(dnetp->io_handle,
		    REG32(dnetp->io_reg, ETHER_ROM_REG), MII_READ | MII_CLOCK);
		drv_usecwait(MII_DELAY);
		tmp = ddi_get32(dnetp->io_handle,
		    REG32(dnetp->io_reg, ETHER_ROM_REG));
		drv_usecwait(MII_DELAY);
		data = (data << 1) | (tmp >> MII_DATA_IN_POSITION) & 0x0001;
	}

	mii_tristate(dnetp);
	return (turned_around ? data: -1);
}

static void
dnet_mii_write(dev_info_t *dip, int phy_addr, int reg_num, int reg_dat)
{
	struct dnetinstance *dnetp;
	uint32_t command_word;
	int bits_in_ushort = ((sizeof (ushort_t))*8);

	dnetp = ddi_get_driver_private(dip);

	ASSERT(MUTEX_HELD(&dnetp->intrlock));
	write_mii(dnetp, MII_PRE, 2*bits_in_ushort);

	/* Prepare command word */
	command_word = ((uint32_t)phy_addr << MII_PHY_ADDR_ALIGN);
	command_word |= ((uint32_t)reg_num << MII_REG_ADDR_ALIGN);
	command_word |= (MII_WRITE_FRAME | (uint32_t)reg_dat);

	write_mii(dnetp, command_word, 2*bits_in_ushort);
	mii_tristate(dnetp);
}

/*
 * Write data size bits from mii_data to the MII control lines.
 */
static void
write_mii(struct dnetinstance *dnetp, uint32_t mii_data, int data_size)
{
	int i;
	uint32_t dbit;

	ASSERT(MUTEX_HELD(&dnetp->intrlock));
	for (i = data_size; i > 0; i--) {
		dbit = ((mii_data >>
		    (31 - MII_WRITE_DATA_POSITION)) & MII_WRITE_DATA);
		ddi_put32(dnetp->io_handle,
		    REG32(dnetp->io_reg, ETHER_ROM_REG),
		    MII_WRITE | dbit);
		drv_usecwait(MII_DELAY);
		ddi_put32(dnetp->io_handle,
		    REG32(dnetp->io_reg, ETHER_ROM_REG),
		    MII_WRITE | MII_CLOCK | dbit);
		drv_usecwait(MII_DELAY);
		mii_data <<= 1;
	}
}

/*
 * Put the MDIO port in tri-state for the turn around bits
 * in MII read and at end of MII management sequence.
 */
static void
mii_tristate(struct dnetinstance *dnetp)
{
	ASSERT(MUTEX_HELD(&dnetp->intrlock));
	ddi_put32(dnetp->io_handle, REG32(dnetp->io_reg, ETHER_ROM_REG),
	    MII_WRITE_TS);
	drv_usecwait(MII_DELAY);
	ddi_put32(dnetp->io_handle, REG32(dnetp->io_reg, ETHER_ROM_REG),
	    MII_WRITE_TS | MII_CLOCK);
	drv_usecwait(MII_DELAY);
}


static void
set_leaf(SROM_FORMAT *sr, LEAF_FORMAT *leaf)
{
	if (sr->leaf && !sr->leaf->is_static)
		kmem_free(sr->leaf, sr->adapters * sizeof (LEAF_FORMAT));
	sr->leaf = leaf;
}

/*
 * Callback from MII module. Makes sure that the CSR registers are
 * configured properly if the PHY changes mode.
 */
/* ARGSUSED */
/* dnet_mii_link_cb - called with intrlock held */
static void
dnet_mii_link_cb(dev_info_t *dip, int phy, enum mii_phy_state state)
{
	struct dnetinstance *dnetp = ddi_get_driver_private(dip);
	LEAF_FORMAT *leaf;

	ASSERT(MUTEX_HELD(&dnetp->intrlock));

	leaf = dnetp->sr.leaf + dnetp->leaf;
	if (state == phy_state_linkup) {
		dnetp->mii_up = 1;

		(void) mii_getspeed(dnetp->mii, dnetp->phyaddr,
		    &dnetp->mii_speed, &dnetp->mii_duplex);

		dnetp->selected_media_block = leaf->mii_block;
		setup_block(dnetp);
	} else {
		/* NEEDSWORK: Probably can call find_active_media here */
		dnetp->mii_up = 0;

		if (leaf->default_block->media_code == MEDIA_MII)
			dnetp->selected_media_block = leaf->default_block;
		setup_block(dnetp);
	}

	if (dnetp->running) {
		mac_link_update(dnetp->mac_handle,
		    (dnetp->mii_up ? LINK_STATE_UP : LINK_STATE_DOWN));
	}
}

/*
 * SROM parsing routines.
 * Refer to the Digital 3.03 SROM spec while reading this! (references refer
 * to this document)
 * Where possible ALL vendor specific changes should be localised here. The
 * SROM data should be capable of describing any programmatic irregularities
 * of DNET cards (via SIA or GP registers, in particular), so vendor specific
 * code elsewhere should not be required
 */
static void
dnet_parse_srom(struct dnetinstance *dnetp, SROM_FORMAT *sr, uchar_t *vi)
{
	uint32_t ether_mfg = 0;
	int i;
	uchar_t *p;

	if (!ddi_getprop(DDI_DEV_T_ANY, dnetp->devinfo,
	    DDI_PROP_DONTPASS, "no_sromconfig", 0))
		dnetp->sr.init_from_srom = check_srom_valid(vi);

	if (dnetp->sr.init_from_srom && dnetp->board_type != DEVICE_ID_21040) {
		/* Section 2/3: General SROM Format/ ID Block */
		p = vi+18;
		sr->version = *p++;
		sr->adapters = *p++;

		sr->leaf =
		    kmem_zalloc(sr->adapters * sizeof (LEAF_FORMAT), KM_SLEEP);
		for (i = 0; i < 6; i++)
			sr->netaddr[i] = *p++;

		for (i = 0; i < sr->adapters; i++) {
			uchar_t devno = *p++;
			uint16_t offset = *p++;
			offset |= *p++ << 8;
			sr->leaf[i].device_number = devno;
			parse_controller_leaf(dnetp, sr->leaf+i, vi+offset);
		}
		/*
		 * 'Orrible hack for cogent cards. The 6911A board seems to
		 * have an incorrect SROM. (From the OEMDEMO program
		 * supplied by cogent, it seems that the ROM matches a setup
		 * or a board with a QSI or ICS PHY.
		 */
		for (i = 0; i < 3; i++)
			ether_mfg = (ether_mfg << 8) | sr->netaddr[i];

		if (ether_mfg == ADAPTEC_ETHER) {
			static uint16_t cogent_gprseq[] = {0x821, 0};
			switch (vi[COGENT_SROM_ID]) {
			case COGENT_ANA6911A_C:
			case COGENT_ANA6911AC_C:
#ifdef DNETDEBUG
				if (dnetdebug & DNETTRACE)
					cmn_err(CE_WARN,
					    "Suspected bad GPR sequence."
					    " Making a guess (821,0)");
#endif

				/* XXX function return value ignored */
				(void) ddi_prop_update_byte_array(
				    DDI_DEV_T_NONE, dnetp->devinfo,
				    "gpr-sequence", (uchar_t *)cogent_gprseq,
				    sizeof (cogent_gprseq));
				break;
			}
		}
	} else {
		/*
		 * Adhoc SROM, check for some cards which need special handling
		 * Assume vendor info contains ether address in first six bytes
		 */

		uchar_t *mac = vi + ddi_getprop(DDI_DEV_T_ANY, dnetp->devinfo,
		    DDI_PROP_DONTPASS, macoffset_propname, 0);

		for (i = 0; i < 6; i++)
			sr->netaddr[i] = mac[i];

		if (dnetp->board_type == DEVICE_ID_21140) {
			for (i = 0; i < 3; i++)
				ether_mfg = (ether_mfg << 8) | mac[i];

			switch (ether_mfg) {
			case ASANTE_ETHER:
				dnetp->vendor_21140 = ASANTE_TYPE;
				dnetp->vendor_revision = 0;
				set_leaf(sr, &leaf_asante);
				sr->adapters = 1;
				break;

			case COGENT_ETHER:
			case ADAPTEC_ETHER:
				dnetp->vendor_21140 = COGENT_EM_TYPE;
				dnetp->vendor_revision =
				    vi[VENDOR_REVISION_OFFSET];
				set_leaf(sr, &leaf_cogent_100);
				sr->adapters = 1;
				break;

			default:
				dnetp->vendor_21140 = DEFAULT_TYPE;
				dnetp->vendor_revision = 0;
				set_leaf(sr, &leaf_default_100);
				sr->adapters = 1;
				break;
			}
		} else if (dnetp->board_type == DEVICE_ID_21041) {
			set_leaf(sr, &leaf_21041);
		} else if (dnetp->board_type == DEVICE_ID_21040) {
			set_leaf(sr, &leaf_21040);
		}
	}
}

/* Section 4.2, 4.3, 4.4, 4.5 */
static void
parse_controller_leaf(struct dnetinstance *dnetp, LEAF_FORMAT *leaf,
	uchar_t *vi)
{
	int i;

	leaf->selected_contype = *vi++;
	leaf->selected_contype |= *vi++ << 8;

	if (dnetp->board_type == DEVICE_ID_21140) /* Sect. 4.3 */
		leaf->gpr = *vi++;

	leaf->block_count = *vi++;

	if (leaf->block_count > MAX_MEDIA) {
		cmn_err(CE_WARN, "dnet: Too many media in SROM!");
		leaf->block_count = 1;
	}
	for (i = 0; i <= leaf->block_count; i++) {
		vi = parse_media_block(dnetp, leaf->block + i, vi);
		if (leaf->block[i].command & CMD_DEFAULT_MEDIUM)
			leaf->default_block = leaf->block+i;
	}
	/* No explicit default block: use last in the ROM */
	if (leaf->default_block == NULL)
		leaf->default_block = leaf->block + leaf->block_count -1;

}

static uchar_t *
parse_media_block(struct dnetinstance *dnetp, media_block_t *block, uchar_t *vi)
{
	int i;

	/*
	 * There are three kinds of media block we need to worry about:
	 * The 21041 blocks.
	 * 21140 blocks from a version 1 SROM
	 * 2114[023] block from a version 3 SROM
	 */

	if (dnetp->board_type == DEVICE_ID_21041) {
		/* Section 4.2 */
		block->media_code = *vi & 0x3f;
		block->type = 2;
		if (*vi++ & 0x40) {
			block->un.sia.csr13 = *vi++;
			block->un.sia.csr13 |= *vi++ << 8;
			block->un.sia.csr14 = *vi++;
			block->un.sia.csr14 |= *vi++ << 8;
			block->un.sia.csr15 = *vi++;
			block->un.sia.csr15 |= *vi++ << 8;
		} else {
			/* No media data (csrs 13,14,15). Insert defaults */
			switch (block->media_code) {
			case MEDIA_TP:
				block->un.sia.csr13 = 0xef01;
				block->un.sia.csr14 = 0x7f3f;
				block->un.sia.csr15 = 0x0008;
				break;
			case MEDIA_TP_FD:
				block->un.sia.csr13 = 0xef01;
				block->un.sia.csr14 = 0x7f3d;
				block->un.sia.csr15 = 0x0008;
				break;
			case MEDIA_BNC:
				block->un.sia.csr13 = 0xef09;
				block->un.sia.csr14 = 0x0705;
				block->un.sia.csr15 = 0x0006;
				break;
			case MEDIA_AUI:
				block->un.sia.csr13 = 0xef09;
				block->un.sia.csr14 = 0x0705;
				block->un.sia.csr15 = 0x000e;
				break;
			}
		}
	} else  if (*vi & 0x80) {  /* Extended format: Section 4.3.2.2 */
		int blocklen = *vi++ & 0x7f;
		block->type = *vi++;
		switch (block->type) {
		case 0: /* "non-MII": Section 4.3.2.2.1 */
			block->media_code = (*vi++) & 0x3f;
			block->gprseqlen = 1;
			block->gprseq[0] = *vi++;
			block->command = *vi++;
			block->command |= *vi++ << 8;
			break;

		case 1: /* MII/PHY: Section 4.3.2.2.2 */
			block->command = CMD_PS;
			block->media_code = MEDIA_MII;
				/* This is whats needed in CSR6 */

			block->un.mii.phy_num = *vi++;
			block->gprseqlen = *vi++;

			for (i = 0; i < block->gprseqlen; i++)
				block->gprseq[i] = *vi++;
			block->rstseqlen = *vi++;
			for (i = 0; i < block->rstseqlen; i++)
				block->rstseq[i] = *vi++;

			block->un.mii.mediacaps = *vi++;
			block->un.mii.mediacaps |= *vi++ << 8;
			block->un.mii.nwayadvert = *vi++;
			block->un.mii.nwayadvert |= *vi++ << 8;
			block->un.mii.fdxmask = *vi++;
			block->un.mii.fdxmask |= *vi++ << 8;
			block->un.mii.ttmmask = *vi++;
			block->un.mii.ttmmask |= *vi++ << 8;
			break;

		case 2: /* SIA Media: Section 4.4.2.1.1 */
			block->media_code = *vi & 0x3f;
			if (*vi++ & 0x40) {
				block->un.sia.csr13 = *vi++;
				block->un.sia.csr13 |= *vi++ << 8;
				block->un.sia.csr14 = *vi++;
				block->un.sia.csr14 |= *vi++ << 8;
				block->un.sia.csr15 = *vi++;
				block->un.sia.csr15 |= *vi++ << 8;
			} else {
				/*
				 * SIA values not provided by SROM; provide
				 * defaults. See appendix D of 2114[23] manuals.
				 */
				switch (block->media_code) {
				case MEDIA_BNC:
					block->un.sia.csr13 = 0x0009;
					block->un.sia.csr14 = 0x0705;
					block->un.sia.csr15 = 0x0000;
					break;
				case MEDIA_AUI:
					block->un.sia.csr13 = 0x0009;
					block->un.sia.csr14 = 0x0705;
					block->un.sia.csr15 = 0x0008;
					break;
				case MEDIA_TP:
					block->un.sia.csr13 = 0x0001;
					block->un.sia.csr14 = 0x7f3f;
					block->un.sia.csr15 = 0x0000;
					break;
				case MEDIA_TP_FD:
					block->un.sia.csr13 = 0x0001;
					block->un.sia.csr14 = 0x7f3d;
					block->un.sia.csr15 = 0x0000;
					break;
				default:
					block->un.sia.csr13 = 0x0000;
					block->un.sia.csr14 = 0x0000;
					block->un.sia.csr15 = 0x0000;
				}
			}

			/* Treat GP control/data as a GPR sequence */
			block->gprseqlen = 2;
			block->gprseq[0] = *vi++;
			block->gprseq[0] |= *vi++ << 8;
			block->gprseq[0] |= GPR_CONTROL_WRITE;
			block->gprseq[1] = *vi++;
			block->gprseq[1] |= *vi++ << 8;
			break;

		case 3: /* MII/PHY : Section 4.4.2.1.2 */
			block->command = CMD_PS;
			block->media_code = MEDIA_MII;
			block->un.mii.phy_num = *vi++;

			block->gprseqlen = *vi++;
			for (i = 0; i < block->gprseqlen; i++) {
				block->gprseq[i] = *vi++;
				block->gprseq[i] |= *vi++ << 8;
			}

			block->rstseqlen = *vi++;
			for (i = 0; i < block->rstseqlen; i++) {
				block->rstseq[i] = *vi++;
				block->rstseq[i] |= *vi++ << 8;
			}
			block->un.mii.mediacaps = *vi++;
			block->un.mii.mediacaps |= *vi++ << 8;
			block->un.mii.nwayadvert = *vi++;
			block->un.mii.nwayadvert |= *vi++ << 8;
			block->un.mii.fdxmask = *vi++;
			block->un.mii.fdxmask |= *vi++ << 8;
			block->un.mii.ttmmask = *vi++;
			block->un.mii.ttmmask |= *vi++ << 8;
			block->un.mii.miiintr |= *vi++;
			break;

		case 4: /* SYM Media: 4.5.2.1.3 */
			block->media_code = *vi++ & 0x3f;
			/* Treat GP control and data as a GPR sequence */
			block->gprseqlen = 2;
			block->gprseq[0] = *vi++;
			block->gprseq[0] |= *vi++ << 8;
			block->gprseq[0] |= GPR_CONTROL_WRITE;
			block->gprseq[1]  = *vi++;
			block->gprseq[1] |= *vi++ << 8;
			block->command = *vi++;
			block->command |= *vi++ << 8;
			break;

		case 5: /* GPR reset sequence:  Section 4.5.2.1.4 */
			block->rstseqlen = *vi++;
			for (i = 0; i < block->rstseqlen; i++)
				block->rstseq[i] = *vi++;
			break;

		default: /* Unknown media block. Skip it. */
			cmn_err(CE_WARN, "dnet: Unsupported SROM block.");
			vi += blocklen;
			break;
		}
	} else { /* Compact format (or V1 SROM): Section 4.3.2.1 */
		block->type = 0;
		block->media_code = *vi++ & 0x3f;
		block->gprseqlen = 1;
		block->gprseq[0] = *vi++;
		block->command = *vi++;
		block->command |= (*vi++) << 8;
	}
	return (vi);
}


/*
 * An alternative to doing this would be to store the legacy ROMs in binary
 * format in the conf file, and in read_srom, pick out the data. This would
 * then allow the parser to continue on as normal. This makes it a little
 * easier to read.
 */
static void
setup_legacy_blocks()
{
	LEAF_FORMAT *leaf;
	media_block_t *block;

	/* Default FAKE SROM */
	leaf = &leaf_default_100;
	leaf->is_static = 1;
	leaf->default_block = &leaf->block[3];
	leaf->block_count = 4; /* 100 cards are highly unlikely to have BNC */
	block = leaf->block;
	block->media_code = MEDIA_TP_FD;
	block->type = 0;
	block->command = 0x8e;  /* PCS, PS off, media sense: bit7, pol=1 */
	block++;
	block->media_code = MEDIA_TP;
	block->type = 0;
	block->command = 0x8e;  /* PCS, PS off, media sense: bit7, pol=1 */
	block++;
	block->media_code = MEDIA_SYM_SCR_FD;
	block->type = 0;
	block->command = 0x6d;  /* PCS, PS, SCR on, media sense: bit6, pol=0 */
	block++;
	block->media_code = MEDIA_SYM_SCR;
	block->type = 0;
	block->command = 0x406d; /* PCS, PS, SCR on, media sense: bit6, pol=0 */

	/* COGENT FAKE SROM */
	leaf = &leaf_cogent_100;
	leaf->is_static = 1;
	leaf->default_block = &leaf->block[4];
	leaf->block_count = 5; /* 100TX, 100TX-FD, 10T 10T-FD, BNC */
	block = leaf->block; /* BNC */
	block->media_code = MEDIA_BNC;
	block->type = 0;
	block->command =  0x8000; /* No media sense, PCS, SCR, PS all off */
	block->gprseqlen = 2;
	block->rstseqlen = 0;
	block->gprseq[0] = 0x13f;
	block->gprseq[1] = 1;

	block++;
	block->media_code = MEDIA_TP_FD;
	block->type = 0;
	block->command = 0x8e;  /* PCS, PS off, media sense: bit7, pol=1 */
	block->gprseqlen = 2;
	block->rstseqlen = 0;
	block->gprseq[0] = 0x13f;
	block->gprseq[1] = 0x26;

	block++; /* 10BaseT */
	block->media_code = MEDIA_TP;
	block->type = 0;
	block->command = 0x8e;  /* PCS, PS off, media sense: bit7, pol=1 */
	block->gprseqlen = 2;
	block->rstseqlen = 0;
	block->gprseq[0] = 0x13f;
	block->gprseq[1] = 0x3e;

	block++; /* 100BaseTX-FD */
	block->media_code = MEDIA_SYM_SCR_FD;
	block->type = 0;
	block->command = 0x6d;  /* PCS, PS, SCR on, media sense: bit6, pol=0 */
	block->gprseqlen = 2;
	block->rstseqlen = 0;
	block->gprseq[0] = 0x13f;
	block->gprseq[1] = 1;

	block++; /* 100BaseTX */
	block->media_code = MEDIA_SYM_SCR;
	block->type = 0;
	block->command = 0x406d; /* PCS, PS, SCR on, media sense: bit6, pol=0 */
	block->gprseqlen = 2;
	block->rstseqlen = 0;
	block->gprseq[0] = 0x13f;
	block->gprseq[1] = 1;

	/* Generic legacy card with a PHY. */
	leaf = &leaf_phylegacy;
	leaf->block_count = 1;
	leaf->mii_block = leaf->block;
	leaf->default_block = &leaf->block[0];
	leaf->is_static = 1;
	block = leaf->block;
	block->media_code = MEDIA_MII;
	block->type = 1; /* MII Block type 1 */
	block->command = 1; /* Port select */
	block->gprseqlen = 0;
	block->rstseqlen = 0;

	/* ASANTE FAKE SROM */
	leaf = &leaf_asante;
	leaf->is_static = 1;
	leaf->default_block = &leaf->block[0];
	leaf->block_count = 1;
	block = leaf->block;
	block->media_code = MEDIA_MII;
	block->type = 1; /* MII Block type 1 */
	block->command = 1; /* Port select */
	block->gprseqlen = 3;
	block->rstseqlen = 0;
	block->gprseq[0] = 0x180;
	block->gprseq[1] = 0x80;
	block->gprseq[2] = 0x0;

	/* LEGACY 21041 card FAKE SROM */
	leaf = &leaf_21041;
	leaf->is_static = 1;
	leaf->block_count = 4;  /* SIA Blocks for TP, TPfd, BNC, AUI */
	leaf->default_block = &leaf->block[3];

	block = leaf->block;
	block->media_code = MEDIA_AUI;
	block->type = 2;
	block->un.sia.csr13 = 0xef09;
	block->un.sia.csr14 = 0x0705;
	block->un.sia.csr15 = 0x000e;

	block++;
	block->media_code = MEDIA_TP_FD;
	block->type = 2;
	block->un.sia.csr13 = 0xef01;
	block->un.sia.csr14 = 0x7f3d;
	block->un.sia.csr15 = 0x0008;

	block++;
	block->media_code = MEDIA_BNC;
	block->type = 2;
	block->un.sia.csr13 = 0xef09;
	block->un.sia.csr14 = 0x0705;
	block->un.sia.csr15 = 0x0006;

	block++;
	block->media_code = MEDIA_TP;
	block->type = 2;
	block->un.sia.csr13 = 0xef01;
	block->un.sia.csr14 = 0x7f3f;
	block->un.sia.csr15 = 0x0008;

	/* LEGACY 21040 card FAKE SROM */
	leaf = &leaf_21040;
	leaf->is_static = 1;
	leaf->block_count = 4;  /* SIA Blocks for TP, TPfd, BNC, AUI */
	block = leaf->block;
	block->media_code = MEDIA_AUI;
	block->type = 2;
	block->un.sia.csr13 = 0x8f09;
	block->un.sia.csr14 = 0x0705;
	block->un.sia.csr15 = 0x000e;
	block++;
	block->media_code = MEDIA_TP_FD;
	block->type = 2;
	block->un.sia.csr13 = 0x0f01;
	block->un.sia.csr14 = 0x7f3d;
	block->un.sia.csr15 = 0x0008;
	block++;
	block->media_code = MEDIA_BNC;
	block->type = 2;
	block->un.sia.csr13 = 0xef09;
	block->un.sia.csr14 = 0x0705;
	block->un.sia.csr15 = 0x0006;
	block++;
	block->media_code = MEDIA_TP;
	block->type = 2;
	block->un.sia.csr13 = 0x8f01;
	block->un.sia.csr14 = 0x7f3f;
	block->un.sia.csr15 = 0x0008;
}

static void
dnet_print_srom(SROM_FORMAT *sr)
{
	int i;
	uchar_t *a = sr->netaddr;
	cmn_err(CE_NOTE, "SROM Dump: %d. ver %d, Num adapters %d,"
	    "Addr:%x:%x:%x:%x:%x:%x",
	    sr->init_from_srom, sr->version, sr->adapters,
	    a[0], a[1], a[2], a[3], a[4], a[5]);

	for (i = 0; i < sr->adapters; i++)
		dnet_dump_leaf(sr->leaf+i);
}

static void
dnet_dump_leaf(LEAF_FORMAT *leaf)
{
	int i;
	cmn_err(CE_NOTE, "Leaf: Device %d, block_count %d, gpr: %x",
	    leaf->device_number, leaf->block_count, leaf->gpr);
	for (i = 0; i < leaf->block_count; i++)
		dnet_dump_block(leaf->block+i);
}

static void
dnet_dump_block(media_block_t *block)
{
	cmn_err(CE_NOTE, "Block(%p): type %x, media %s, command: %x ",
	    (void *)block,
	    block->type, media_str[block->media_code], block->command);
	dnet_dumpbin("\tGPR Seq", (uchar_t *)block->gprseq, 2,
	    block->gprseqlen *2);
	dnet_dumpbin("\tGPR Reset", (uchar_t *)block->rstseq, 2,
	    block->rstseqlen *2);
	switch (block->type) {
	case 1: case 3:
		cmn_err(CE_NOTE, "\tMII Info: phy %d, nway %x, fdx"
		    "%x, ttm %x, mediacap %x",
		    block->un.mii.phy_num, block->un.mii.nwayadvert,
		    block->un.mii.fdxmask, block->un.mii.ttmmask,
		    block->un.mii.mediacaps);
		break;
	case 2:
		cmn_err(CE_NOTE, "\tSIA Regs: CSR13:%x, CSR14:%x, CSR15:%x",
		    block->un.sia.csr13, block->un.sia.csr14,
		    block->un.sia.csr15);
		break;
	}
}


/* Utility to print out binary info dumps. Handy for SROMs, etc */

static int
hexcode(unsigned val)
{
	if (val <= 9)
		return (val +'0');
	if (val <= 15)
		return (val + 'a' - 10);
	return (-1);
}

static void
dnet_dumpbin(char *msg, unsigned char *data, int size, int len)
{
	char hex[128], *p = hex;
	char ascii[128], *q = ascii;
	int i, j;

	if (!len)
		return;

	for (i = 0; i < len; i += size) {
		for (j = size - 1; j >= 0; j--) { /* PORTABILITY: byte order */
			*p++ = hexcode(data[i+j] >> 4);
			*p++ = hexcode(data[i+j] & 0xf);
			*q++ = (data[i+j] < 32 || data[i+j] > 127) ?
			    '.' : data[i];
		}
		*p++ = ' ';
		if (q-ascii >= 8) {
			*p = *q = 0;
			cmn_err(CE_NOTE, "%s: %s\t%s", msg, hex, ascii);
			p = hex;
			q = ascii;
		}
	}
	if (p != hex) {
		while ((p - hex) < 8*3)
			*p++ = ' ';
		*p = *q = 0;
		cmn_err(CE_NOTE, "%s: %s\t%s", msg, hex, ascii);
	}
}

#ifdef DNETDEBUG
void
dnet_usectimeout(struct dnetinstance *dnetp, uint32_t usecs, int contin,
    timercb_t cback)
{
	mutex_enter(&dnetp->intrlock);
	dnetp->timer.start_ticks = (usecs * 100) / 8192;
	dnetp->timer.cb = cback;
	ddi_put32(dnetp->io_handle, REG32(dnetp->io_reg, GP_TIMER_REG),
	    dnetp->timer.start_ticks | (contin ? GPTIMER_CONT : 0));
	if (dnetp->timer.cb)
		enable_interrupts(dnetp);
	mutex_exit(&dnetp->intrlock);
}

uint32_t
dnet_usecelapsed(struct dnetinstance *dnetp)
{
	uint32_t ticks = dnetp->timer.start_ticks -
	    (ddi_get32(dnetp->io_handle, REG32(dnetp->io_reg, GP_TIMER_REG)) &
	    0xffff);
	return ((ticks * 8192) / 100);
}

/* ARGSUSED */
void
dnet_timestamp(struct dnetinstance *dnetp,  char *buf)
{
	uint32_t elapsed = dnet_usecelapsed(dnetp);
	char loc[32], *p = loc;
	int firstdigit = 1;
	uint32_t divisor;

	while (*p++ = *buf++)
		;
	p--;

	for (divisor = 1000000000; divisor /= 10; ) {
		int digit = (elapsed / divisor);
		elapsed -= digit * divisor;
		if (!firstdigit || digit) {
			*p++ = digit + '0';
			firstdigit = 0;
		}

	}

	/* Actual zero, output it */
	if (firstdigit)
		*p++ = '0';

	*p++ = '-';
	*p++ = '>';
	*p++ = 0;

	printf(loc);
	dnet_usectimeout(dnetp, 1000000, 0, 0);
}

#endif
