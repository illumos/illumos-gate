/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Intel Pro/100B Ethernet Driver
 */

#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/ksynch.h>
#include <sys/cmn_err.h>
#include <sys/note.h>
#include <sys/pci.h>
#include <sys/pci_cap.h>
#include <sys/ethernet.h>
#include <sys/mii.h>
#include <sys/miiregs.h>
#include <sys/mac.h>
#include <sys/mac_ether.h>
#include <sys/ethernet.h>
#include <sys/vlan.h>
#include <sys/list.h>
#include <sys/sysmacros.h>
#include <sys/varargs.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include "iprb.h"
#include "rcvbundl.h"

/*
 * Intel has openly documented the programming interface for these
 * parts in the "Intel 8255x 10/100 Mbps Ethernet Controller Family
 * Open Source Software Developer Manual".
 *
 * While some open source systems have utilized many of the features
 * of some models in this family (especially scatter gather and IP
 * checksum support), we have elected to offer only the basic
 * functionality.  These are only 10/100 parts, and the additional
 * complexity is not justified by the minimal performance benefit.
 * KISS.  So, we are only supporting the simple 82557 features.
 */

static uint16_t	iprb_mii_read(void *, uint8_t, uint8_t);
static void	iprb_mii_write(void *, uint8_t, uint8_t, uint16_t);
static void	iprb_mii_notify(void *, link_state_t);
static int	iprb_attach(dev_info_t *);
static int	iprb_detach(dev_info_t *);
static int	iprb_quiesce(dev_info_t *);
static int	iprb_suspend(dev_info_t *);
static int	iprb_resume(dev_info_t *);
static int	iprb_m_stat(void *, uint_t, uint64_t *);
static int	iprb_m_start(void *);
static void	iprb_m_stop(void *);
static int	iprb_m_promisc(void *, boolean_t);
static int	iprb_m_multicst(void *, boolean_t, const uint8_t *);
static int	iprb_m_unicst(void *, const uint8_t *);
static mblk_t	*iprb_m_tx(void *, mblk_t *);
static void	iprb_m_ioctl(void *, queue_t *, mblk_t *);
static int	iprb_m_setprop(void *, const char *, mac_prop_id_t, uint_t,
    const void *);
static int	iprb_m_getprop(void *, const char *, mac_prop_id_t, uint_t,
    void *);
static void	iprb_m_propinfo(void *, const char *, mac_prop_id_t,
    mac_prop_info_handle_t);
static void	iprb_destroy(iprb_t *);
static int	iprb_configure(iprb_t *);
static void	iprb_eeprom_sendbits(iprb_t *, uint32_t, uint8_t);
static uint16_t	iprb_eeprom_read(iprb_t *, uint16_t);
static void	iprb_identify(iprb_t *);
static int	iprb_cmd_submit(iprb_t *, uint16_t);
static void	iprb_cmd_reclaim(iprb_t *);
static int	iprb_cmd_ready(iprb_t *);
static int	iprb_cmd_drain(iprb_t *);
static void	iprb_rx_add(iprb_t *);
static void	iprb_rx_init(iprb_t *);
static mblk_t	*iprb_rx(iprb_t *);
static mblk_t	*iprb_send(iprb_t *, mblk_t *);
static uint_t	iprb_intr(caddr_t, caddr_t);
static void	iprb_periodic(void *);
static int	iprb_add_intr(iprb_t *);
static int	iprb_dma_alloc(iprb_t *, iprb_dma_t *, size_t);
static void	iprb_dma_free(iprb_dma_t *);
static iprb_dma_t *iprb_cmd_next(iprb_t *);
static int	iprb_set_config(iprb_t *);
static int	iprb_set_unicast(iprb_t *);
static int	iprb_set_multicast(iprb_t *);
static int	iprb_set_ucode(iprb_t *);
static void	iprb_update_stats(iprb_t *);
static int	iprb_start(iprb_t *);
static void	iprb_stop(iprb_t *);
static int	iprb_ddi_attach(dev_info_t *, ddi_attach_cmd_t);
static int	iprb_ddi_detach(dev_info_t *, ddi_detach_cmd_t);
static void	iprb_error(iprb_t *, const char *, ...);

static mii_ops_t iprb_mii_ops = {
	MII_OPS_VERSION,
	iprb_mii_read,
	iprb_mii_write,
	iprb_mii_notify,
	NULL,		/* reset */
};

static mac_callbacks_t iprb_m_callbacks = {
	MC_IOCTL | MC_SETPROP | MC_GETPROP | MC_PROPINFO,
	iprb_m_stat,
	iprb_m_start,
	iprb_m_stop,
	iprb_m_promisc,
	iprb_m_multicst,
	iprb_m_unicst,
	iprb_m_tx,
	NULL,
	iprb_m_ioctl,	/* mc_ioctl */
	NULL,		/* mc_getcapab */
	NULL,		/* mc_open */
	NULL,		/* mc_close */
	iprb_m_setprop,
	iprb_m_getprop,
	iprb_m_propinfo
};


/*
 * Stream information
 */
DDI_DEFINE_STREAM_OPS(iprb_devops, nulldev, nulldev,
    iprb_ddi_attach, iprb_ddi_detach, nodev, NULL, D_MP, NULL, iprb_quiesce);

static struct modldrv iprb_modldrv = {
	&mod_driverops,			/* drv_modops */
	"Intel 8255x Ethernet",		/* drv_linkinfo */
	&iprb_devops			/* drv_dev_ops */
};

static struct modlinkage iprb_modlinkage = {
	MODREV_1,		/* ml_rev */
	{ &iprb_modldrv, NULL }	/* ml_linkage */
};


static ddi_device_acc_attr_t acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

static ddi_device_acc_attr_t buf_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STORECACHING_OK_ACC
};

/*
 * The 8225x is a 32-bit addressing engine, but it can only address up
 * to 31 bits on a single transaction.  (Far less in reality it turns
 * out.)  Statistics buffers have to be 16-byte aligned, and as we
 * allocate individual data pieces for other things, there is no
 * compelling reason to use another attribute with support for less
 * strict alignment.
 */
static ddi_dma_attr_t dma_attr = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo */
	0xFFFFFFFFU,		/* dma_attr_addr_hi */
	0x7FFFFFFFU,		/* dma_attr_count_max */
	16,			/* dma_attr_align */
	0x100,			/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0xFFFFFFFFU,		/* dma_attr_maxxfer */
	0xFFFFFFFFU,		/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};

#define	DECL_UCODE(x)						\
	static const uint32_t x ## _WORDS[] = x ## _RCVBUNDLE_UCODE
DECL_UCODE(D101_A);
DECL_UCODE(D101_B0);
DECL_UCODE(D101M_B);
DECL_UCODE(D101S);
DECL_UCODE(D102_B);
DECL_UCODE(D102_C);
DECL_UCODE(D102_E);

static uint8_t iprb_bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

/*
 * We don't bother allowing for tuning of the CPU saver algorithm.
 * The ucode has reasonable defaults built-in.  However, some variants
 * apparently have bug fixes delivered via this ucode, so we still
 * need to support the ucode upload.
 */
typedef struct {
	uint8_t		rev;
	uint8_t		length;
	const uint32_t	*ucode;
} iprb_ucode_t;

#define	UCODE(x)						\
	sizeof (x ## _WORDS) / sizeof (uint32_t), x ## _WORDS

static const iprb_ucode_t iprb_ucode[] = {
	{ REV_82558_A4,	UCODE(D101_A) },
	{ REV_82558_B0,	UCODE(D101_B0) },
	{ REV_82559_A0,	UCODE(D101M_B) },
	{ REV_82559S_A,	UCODE(D101S) },
	{ REV_82550,	UCODE(D102_B) },
	{ REV_82550_C,	UCODE(D102_C) },
	{ REV_82551_F,	UCODE(D102_E) },
	{ 0 },
};

int
_init(void)
{
	int	rv;
	mac_init_ops(&iprb_devops, "iprb");
	if ((rv = mod_install(&iprb_modlinkage)) != DDI_SUCCESS) {
		mac_fini_ops(&iprb_devops);
	}
	return (rv);
}

int
_fini(void)
{
	int	rv;
	if ((rv = mod_remove(&iprb_modlinkage)) == DDI_SUCCESS) {
		mac_fini_ops(&iprb_devops);
	}
	return (rv);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&iprb_modlinkage, modinfop));
}

int
iprb_attach(dev_info_t *dip)
{
	iprb_t		*ip;
	uint16_t	w;
	int		i;
	mac_register_t	*macp;

	ip = kmem_zalloc(sizeof (*ip), KM_SLEEP);
	ddi_set_driver_private(dip, ip);
	ip->dip = dip;

	list_create(&ip->mcast, sizeof (struct iprb_mcast),
	    offsetof(struct iprb_mcast, node));

	/* we don't support high level interrupts, so we don't need cookies */
	mutex_init(&ip->culock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ip->rulock, NULL, MUTEX_DRIVER, NULL);

	if (pci_config_setup(dip, &ip->pcih) != DDI_SUCCESS) {
		iprb_error(ip, "unable to map configuration space");
		iprb_destroy(ip);
		return (DDI_FAILURE);
	}

	if (ddi_regs_map_setup(dip, 1, &ip->regs, 0, 0, &acc_attr,
	    &ip->regsh) != DDI_SUCCESS) {
		iprb_error(ip, "unable to map device registers");
		iprb_destroy(ip);
		return (DDI_FAILURE);
	}

	/* Reset, but first go into idle state */
	PUT32(ip, CSR_PORT, PORT_SEL_RESET);
	drv_usecwait(10);
	PUT32(ip, CSR_PORT, PORT_SW_RESET);
	drv_usecwait(10);
	PUT8(ip, CSR_INTCTL, INTCTL_MASK);
	(void) GET8(ip, CSR_INTCTL);

	/*
	 * Precalculate watchdog times.
	 */
	ip->tx_timeout = TX_WATCHDOG;
	ip->rx_timeout = RX_WATCHDOG;

	iprb_identify(ip);

	/* Obtain our factory MAC address */
	w = iprb_eeprom_read(ip, 0);
	ip->factaddr[0] = w & 0xff;
	ip->factaddr[1] = w >> 8;
	w = iprb_eeprom_read(ip, 1);
	ip->factaddr[2] = w & 0xff;
	ip->factaddr[3] = w >> 8;
	w = iprb_eeprom_read(ip, 2);
	ip->factaddr[4] = w & 0xff;
	ip->factaddr[5] = w >> 8;
	bcopy(ip->factaddr, ip->curraddr, 6);

	if (ip->resumebug) {
		/*
		 * Generally, most devices we will ever see will
		 * already have fixed firmware.  Since I can't verify
		 * the validity of the fix (no suitably downrev
		 * hardware), we'll just do our best to avoid it for
		 * devices that exhibit this behavior.
		 */
		if ((iprb_eeprom_read(ip, 10) & 0x02) == 0) {
			/* EEPROM fix was already applied, assume safe. */
			ip->resumebug = B_FALSE;
		}
	}

	if ((iprb_eeprom_read(ip, 3) & 0x3) != 0x3) {
		cmn_err(CE_CONT, "?Enabling RX errata workaround.\n");
		ip->rxhangbug = B_TRUE;
	}

	/* Determine whether we have an MII or a legacy 80c24 */
	w = iprb_eeprom_read(ip, 6);
	if ((w & 0x3f00) != 0x0600) {
		if ((ip->miih = mii_alloc(ip, dip, &iprb_mii_ops)) == NULL) {
			iprb_error(ip, "unable to allocate MII ops vector");
			iprb_destroy(ip);
			return (DDI_FAILURE);
		}
		if (ip->canpause) {
			mii_set_pauseable(ip->miih, B_TRUE, B_FALSE);
		}
	}

	/* Allocate cmds and tx region */
	for (i = 0; i < NUM_TX; i++) {
		/* Command blocks */
		if (iprb_dma_alloc(ip, &ip->cmds[i], CB_SIZE) != DDI_SUCCESS) {
			iprb_destroy(ip);
			return (DDI_FAILURE);
		}
	}

	for (i = 0; i < NUM_TX; i++) {
		iprb_dma_t *cb = &ip->cmds[i];
		/* Link the command blocks into a ring */
		PUTCB32(cb, CB_LNK_OFFSET, (ip->cmds[(i + 1) % NUM_TX].paddr));
	}

	for (i = 0; i < NUM_RX; i++) {
		/* Rx packet buffers */
		if (iprb_dma_alloc(ip, &ip->rxb[i], RFD_SIZE) != DDI_SUCCESS) {
			iprb_destroy(ip);
			return (DDI_FAILURE);
		}
	}
	if (iprb_dma_alloc(ip, &ip->stats, STATS_SIZE) != DDI_SUCCESS) {
		iprb_destroy(ip);
		return (DDI_FAILURE);
	}

	if (iprb_add_intr(ip) != DDI_SUCCESS) {
		iprb_destroy(ip);
		return (DDI_FAILURE);
	}

	if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
		iprb_error(ip, "unable to allocate mac structure");
		iprb_destroy(ip);
		return (DDI_FAILURE);
	}

	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_driver = ip;
	macp->m_dip = dip;
	macp->m_src_addr = ip->curraddr;
	macp->m_callbacks = &iprb_m_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = ETHERMTU;
	macp->m_margin = VLAN_TAGSZ;
	if (mac_register(macp, &ip->mach) != 0) {
		iprb_error(ip, "unable to register mac with framework");
		mac_free(macp);
		iprb_destroy(ip);
		return (DDI_FAILURE);
	}

	mac_free(macp);
	return (DDI_SUCCESS);
}

int
iprb_detach(dev_info_t *dip)
{
	iprb_t *ip;

	ip = ddi_get_driver_private(dip);
	ASSERT(ip != NULL);

	if (mac_disable(ip->mach) != 0)
		return (DDI_FAILURE);

	(void) mac_unregister(ip->mach);
	iprb_destroy(ip);
	return (DDI_SUCCESS);
}

int
iprb_add_intr(iprb_t *ip)
{
	int	actual;

	if (ddi_intr_alloc(ip->dip, &ip->intrh, DDI_INTR_TYPE_FIXED, 0, 1,
	    &actual, DDI_INTR_ALLOC_STRICT) != DDI_SUCCESS) {
		iprb_error(ip, "failed allocating interrupt handle");
		return (DDI_FAILURE);
	}

	if (ddi_intr_add_handler(ip->intrh, iprb_intr, ip, NULL) !=
	    DDI_SUCCESS) {
		(void) ddi_intr_free(ip->intrh);
		ip->intrh = NULL;
		iprb_error(ip, "failed adding interrupt handler");
		return (DDI_FAILURE);
	}
	if (ddi_intr_enable(ip->intrh) != DDI_SUCCESS) {
		(void) ddi_intr_remove_handler(ip->intrh);
		(void) ddi_intr_free(ip->intrh);
		ip->intrh = NULL;
		iprb_error(ip, "failed enabling interrupt");
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

int
iprb_dma_alloc(iprb_t *ip, iprb_dma_t *h, size_t size)
{
	size_t			rlen;
	ddi_dma_cookie_t	dmac;
	uint_t			ndmac;

	if (ddi_dma_alloc_handle(ip->dip, &dma_attr, DDI_DMA_SLEEP, NULL,
	    &h->dmah) != DDI_SUCCESS) {
		iprb_error(ip, "unable to allocate dma handle");
		return (DDI_FAILURE);
	}
	if (ddi_dma_mem_alloc(h->dmah, size, &buf_attr, DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP, NULL, &h->vaddr, &rlen, &h->acch) != DDI_SUCCESS) {
		iprb_error(ip, "unable to allocate dma memory");
		return (DDI_FAILURE);
	}
	bzero(h->vaddr, size);
	if (ddi_dma_addr_bind_handle(h->dmah, NULL, h->vaddr, size,
	    DDI_DMA_CONSISTENT | DDI_DMA_RDWR, DDI_DMA_SLEEP, NULL,
	    &dmac, &ndmac) != DDI_DMA_MAPPED) {
		iprb_error(ip, "unable to map command memory");
		return (DDI_FAILURE);
	}
	h->paddr = dmac.dmac_address;
	return (DDI_SUCCESS);
}

void
iprb_dma_free(iprb_dma_t *h)
{
	if (h->paddr != 0)
		(void) ddi_dma_unbind_handle(h->dmah);
	h->paddr = 0;
	if (h->acch != NULL)
		ddi_dma_mem_free(&h->acch);
	h->acch = NULL;
	if (h->dmah != NULL)
		ddi_dma_free_handle(&h->dmah);
	h->dmah = NULL;
}

void
iprb_destroy(iprb_t *ip)
{
	int i;
	iprb_mcast_t *mc;

	/* shut down interrupts */
	if (ip->intrh != NULL) {
		(void) ddi_intr_disable(ip->intrh);
		(void) ddi_intr_remove_handler(ip->intrh);
		(void) ddi_intr_free(ip->intrh);
	}
	/* release DMA resources */
	for (i = 0; i < NUM_TX; i++) {
		iprb_dma_free(&ip->cmds[i]);
	}
	for (i = 0; i < NUM_RX; i++) {
		iprb_dma_free(&ip->rxb[i]);
	}
	iprb_dma_free(&ip->stats);

	if (ip->miih)
		mii_free(ip->miih);

	/* clean up the multicast list */
	while ((mc = list_head(&ip->mcast)) != NULL) {
		list_remove(&ip->mcast, mc);
		kmem_free(mc, sizeof (*mc));
	}

	/* tear down register mappings */
	if (ip->pcih)
		pci_config_teardown(&ip->pcih);
	if (ip->regsh)
		ddi_regs_map_free(&ip->regsh);

	/* clean the dip */
	ddi_set_driver_private(ip->dip, NULL);

	list_destroy(&ip->mcast);
	mutex_destroy(&ip->culock);
	mutex_destroy(&ip->rulock);

	/* and finally toss the structure itself */
	kmem_free(ip, sizeof (*ip));
}

void
iprb_identify(iprb_t *ip)
{
	ip->devid = pci_config_get16(ip->pcih, PCI_CONF_DEVID);
	ip->revid = pci_config_get8(ip->pcih, PCI_CONF_REVID);

	switch (ip->devid) {
	case 0x1229:	/* 8255x family */
	case 0x1030:	/* Intel InBusiness */

		if (ip->revid >= REV_82558_A4) {
			ip->canpause = B_TRUE;
			ip->canmwi = B_TRUE;
		} else {
			ip->is557 = B_TRUE;
		}
		if (ip->revid >= REV_82559_A0)
			ip->resumebug = B_TRUE;
		break;

	case 0x1209:	/* Embedded 82559ER */
		ip->canpause = B_TRUE;
		ip->resumebug = B_TRUE;
		ip->canmwi = B_TRUE;
		break;

	case 0x2449:	/* ICH2 */
	case 0x1031:	/* Pro/100 VE (ICH3) */
	case 0x1032:	/* Pro/100 VE (ICH3) */
	case 0x1033:	/* Pro/100 VM (ICH3) */
	case 0x1034:	/* Pro/100 VM (ICH3) */
	case 0x1038:	/* Pro/100 VM (ICH3) */
		ip->resumebug = B_TRUE;
		if (ip->revid >= REV_82558_A4)
			ip->canpause = B_TRUE;
		break;

	default:
		if (ip->revid >= REV_82558_A4)
			ip->canpause = B_TRUE;
		break;
	}

	/* Allow property override MWI support - not normally needed. */
	if (ddi_prop_get_int(DDI_DEV_T_ANY, ip->dip, 0, "MWIEnable", 1) == 0) {
		ip->canmwi = B_FALSE;
	}
}

void
iprb_eeprom_sendbits(iprb_t *ip, uint32_t val, uint8_t nbits)
{
	uint32_t	mask;
	uint16_t	x;

	mask = 1U << (nbits - 1);
	while (mask) {
		x = (mask & val) ? EEPROM_EEDI : 0;
		PUT16(ip, CSR_EECTL, x | EEPROM_EECS);
		drv_usecwait(100);
		PUT16(ip, CSR_EECTL, x | EEPROM_EESK | EEPROM_EECS);
		drv_usecwait(100);
		PUT16(ip, CSR_EECTL, x | EEPROM_EECS);
		drv_usecwait(100);
		mask >>= 1;
	}
}

uint16_t
iprb_eeprom_read(iprb_t *ip, uint16_t address)
{
	uint16_t	val;
	int		mask;
	uint16_t	n;
	uint16_t	bits;

	/* if we don't know the address size yet call again to determine it */
	if ((address != 0) && (ip->eeprom_bits == 0))
		(void) iprb_eeprom_read(ip, 0);

	if ((bits = ip->eeprom_bits) == 0) {
		bits = 8;
		ASSERT(address == 0);
	}
	/* enable the EEPROM chip select */
	PUT16(ip, CSR_EECTL, EEPROM_EECS);
	drv_usecwait(100);

	/* send a read command */
	iprb_eeprom_sendbits(ip, 6, 3);
	n = 0;
	for (mask = (1U << (bits - 1)); mask != 0; mask >>= 1) {
		uint16_t x = (mask & address) ? EEPROM_EEDI : 0;
		PUT16(ip, CSR_EECTL, x | EEPROM_EECS);
		drv_usecwait(100);
		PUT16(ip, CSR_EECTL, x | EEPROM_EESK | EEPROM_EECS);
		drv_usecwait(100);
		PUT16(ip, CSR_EECTL, x | EEPROM_EECS);
		drv_usecwait(100);

		n++;
		/* check the dummy 0 bit */
		if ((GET16(ip, CSR_EECTL) & EEPROM_EEDO) == 0) {
			if (ip->eeprom_bits == 0) {
				ip->eeprom_bits = n;
				cmn_err(CE_CONT, "?EEPROM size %d words.\n",
				    1U << ip->eeprom_bits);
			}
			break;
		}
	}
	if (n != ip->eeprom_bits) {
		iprb_error(ip, "cannot determine EEPROM size (%d, %d)",
		    ip->eeprom_bits, n);
	}

	/* shift out a 16-bit word */
	val = 0;
	for (mask = 0x8000; mask; mask >>= 1) {
		PUT16(ip, CSR_EECTL, EEPROM_EECS | EEPROM_EESK);
		drv_usecwait(100);
		if (GET16(ip, CSR_EECTL) & EEPROM_EEDO)
			val |= mask;
		drv_usecwait(100);
		PUT16(ip, CSR_EECTL, EEPROM_EECS);
		drv_usecwait(100);
	}

	/* and disable the eeprom */
	PUT16(ip, CSR_EECTL, 0);
	drv_usecwait(100);

	return (val);
}

int
iprb_cmd_ready(iprb_t *ip)
{
	/* wait for pending SCB commands to be accepted */
	for (int cnt = 1000000; cnt != 0; cnt -= 10) {
		if (GET8(ip, CSR_CMD) == 0) {
			return (DDI_SUCCESS);
		}
		drv_usecwait(10);
	}
	iprb_error(ip, "timeout waiting for chip to become ready");
	return (DDI_FAILURE);
}

void
iprb_cmd_reclaim(iprb_t *ip)
{
	while (ip->cmd_count) {
		iprb_dma_t *cb = &ip->cmds[ip->cmd_tail];

		SYNCCB(cb, CB_STS_OFFSET, 2, DDI_DMA_SYNC_FORKERNEL);
		if ((GETCB16(cb, CB_STS_OFFSET) & CB_STS_C) == 0) {
			break;
		}

		ip->cmd_tail++;
		ip->cmd_tail %= NUM_TX;
		ip->cmd_count--;
		if (ip->cmd_count == 0) {
			ip->tx_wdog = 0;
		} else {
			ip->tx_wdog = gethrtime();
		}
	}
}

int
iprb_cmd_drain(iprb_t *ip)
{
	for (int i = 1000000; i; i -= 10) {
		iprb_cmd_reclaim(ip);
		if (ip->cmd_count == 0)
			return (DDI_SUCCESS);
		drv_usecwait(10);
	}
	iprb_error(ip, "time out waiting for commands to drain");
	return (DDI_FAILURE);
}

int
iprb_cmd_submit(iprb_t *ip, uint16_t cmd)
{
	iprb_dma_t	*ncb = &ip->cmds[ip->cmd_head];
	iprb_dma_t	*lcb = &ip->cmds[ip->cmd_last];

	/* If this command will consume the last CB, interrupt when done */
	ASSERT((ip->cmd_count) < NUM_TX);
	if (ip->cmd_count == (NUM_TX - 1)) {
		cmd |= CB_CMD_I;
	}

	/* clear the status entry */
	PUTCB16(ncb, CB_STS_OFFSET, 0);

	/* suspend upon completion of this new command */
	cmd |= CB_CMD_S;
	PUTCB16(ncb, CB_CMD_OFFSET, cmd);
	SYNCCB(ncb, 0, 0, DDI_DMA_SYNC_FORDEV);

	/* clear the suspend flag from the last submitted command */
	SYNCCB(lcb, CB_CMD_OFFSET, 2, DDI_DMA_SYNC_FORKERNEL);
	PUTCB16(lcb, CB_CMD_OFFSET, GETCB16(lcb, CB_CMD_OFFSET) & ~CB_CMD_S);
	SYNCCB(lcb, CB_CMD_OFFSET, 2, DDI_DMA_SYNC_FORDEV);


	/*
	 * If the chip has a resume bug, then we need to try this as a work
	 * around.  Some anecdotal evidence is that this will help solve
	 * the resume bug.  Its a performance hit, but only if the EEPROM
	 * is not updated.  (In theory we could do this only for 10Mbps HDX,
	 * but since it should just about never get used, we keep it simple.)
	 */
	if (ip->resumebug) {
		if (iprb_cmd_ready(ip) != DDI_SUCCESS)
			return (DDI_FAILURE);
		PUT8(ip, CSR_CMD, CUC_NOP);
		(void) GET8(ip, CSR_CMD);
		drv_usecwait(1);
	}

	/* wait for the SCB to be ready to accept a new command */
	if (iprb_cmd_ready(ip) != DDI_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * Finally we can resume the CU.  Note that if this the first
	 * command in the sequence (i.e. if the CU is IDLE), or if the
	 * CU is already busy working, then this CU resume command
	 * will not have any effect.
	 */
	PUT8(ip, CSR_CMD, CUC_RESUME);
	(void) GET8(ip, CSR_CMD);	/* flush CSR */

	ip->tx_wdog = gethrtime();
	ip->cmd_last = ip->cmd_head;
	ip->cmd_head++;
	ip->cmd_head %= NUM_TX;
	ip->cmd_count++;

	return (DDI_SUCCESS);
}

iprb_dma_t *
iprb_cmd_next(iprb_t *ip)
{
	if (ip->cmd_count == NUM_TX) {
		return (NULL);
	}
	ASSERT(ip->cmd_count < NUM_TX);
	return (&ip->cmds[ip->cmd_head]);
}

int
iprb_set_unicast(iprb_t *ip)
{
	iprb_dma_t	*cb;

	ASSERT(mutex_owned(&ip->culock));

	if ((cb = iprb_cmd_next(ip)) == NULL)
		return (DDI_FAILURE);

	PUTCBEA(cb, CB_IAS_ADR_OFFSET, ip->curraddr);
	return (iprb_cmd_submit(ip, CB_CMD_IAS));
}

int
iprb_set_multicast(iprb_t *ip)
{
	iprb_dma_t	*cb;
	iprb_mcast_t	*mc;
	int		i;
	list_t		*l;

	ASSERT(mutex_owned(&ip->culock));

	if ((ip->nmcast <= 0) || (ip->nmcast > CB_MCS_CNT_MAX)) {
		/*
		 * Only send the list if the total number of multicast
		 * address is nonzero and small enough to fit.  We
		 * don't error out if it is too big, because in that
		 * case we will use the "allmulticast" support
		 * via iprb_set_config instead.
		 */
		return (DDI_SUCCESS);
	}

	if ((cb = iprb_cmd_next(ip)) == NULL) {
		return (DDI_FAILURE);
	}

	l = &ip->mcast;
	for (mc = list_head(l), i = 0; mc; mc = list_next(l, mc), i++) {
		PUTCBEA(cb, CB_MCS_ADR_OFFSET + (i * 6), mc->addr);
	}
	ASSERT(i == ip->nmcast);
	PUTCB16(cb, CB_MCS_CNT_OFFSET, i);
	return (iprb_cmd_submit(ip, CB_CMD_MCS));
}

int
iprb_set_config(iprb_t *ip)
{
	iprb_dma_t *cb;

	ASSERT(mutex_owned(&ip->culock));
	if ((cb = iprb_cmd_next(ip)) == NULL) {
		return (DDI_FAILURE);
	}
	PUTCB8(cb, CB_CONFIG_OFFSET + 0, 0x16);
	PUTCB8(cb, CB_CONFIG_OFFSET + 1, 0x8);
	PUTCB8(cb, CB_CONFIG_OFFSET + 2, 0);
	PUTCB8(cb, CB_CONFIG_OFFSET + 3, (ip->canmwi ? 1 : 0));
	PUTCB8(cb, CB_CONFIG_OFFSET + 4, 0);
	PUTCB8(cb, CB_CONFIG_OFFSET + 5, 0);
	PUTCB8(cb, CB_CONFIG_OFFSET + 6, (ip->promisc ? 0x80 : 0) | 0x3a);
	PUTCB8(cb, CB_CONFIG_OFFSET + 7, (ip->promisc ? 0 : 0x1) | 2);
	PUTCB8(cb, CB_CONFIG_OFFSET + 8, (ip->miih ? 0x1 : 0));
	PUTCB8(cb, CB_CONFIG_OFFSET + 9, 0);
	PUTCB8(cb, CB_CONFIG_OFFSET + 10, 0x2e);
	PUTCB8(cb, CB_CONFIG_OFFSET + 11, 0);
	PUTCB8(cb, CB_CONFIG_OFFSET + 12, (ip->is557 ? 0 : 1) | 0x60);
	PUTCB8(cb, CB_CONFIG_OFFSET + 13, 0);
	PUTCB8(cb, CB_CONFIG_OFFSET + 14, 0xf2);
	PUTCB8(cb, CB_CONFIG_OFFSET + 15,
	    (ip->miih ? 0x80 : 0) | (ip->promisc ? 0x1 : 0) | 0x48);
	PUTCB8(cb, CB_CONFIG_OFFSET + 16, 0);
	PUTCB8(cb, CB_CONFIG_OFFSET + 17, (ip->canpause ? 0x40 : 0));
	PUTCB8(cb, CB_CONFIG_OFFSET + 18, (ip->is557 ? 0 : 0x8) | 0xf2);
	PUTCB8(cb, CB_CONFIG_OFFSET + 19,
	    ((ip->revid < REV_82558_B0) ? 0 : 0x80) |
	    (ip->canpause ? 0x18 : 0));
	PUTCB8(cb, CB_CONFIG_OFFSET + 20, 0x3f);
	PUTCB8(cb, CB_CONFIG_OFFSET + 21,
	    ((ip->nmcast >= CB_MCS_CNT_MAX) ? 0x8 : 0) | 0x5);

	return (iprb_cmd_submit(ip, CB_CMD_CONFIG));
}

int
iprb_set_ucode(iprb_t *ip)
{
	iprb_dma_t *cb;
	const iprb_ucode_t *uc = NULL;
	int i;

	for (i = 0; iprb_ucode[i].length; i++) {
		if (iprb_ucode[i].rev == ip->revid) {
			uc = &iprb_ucode[i];
			break;
		}
	}
	if (uc == NULL) {
		/* no matching firmware found, assume success */
		return (DDI_SUCCESS);
	}

	ASSERT(mutex_owned(&ip->culock));
	if ((cb = iprb_cmd_next(ip)) == NULL) {
		return (DDI_FAILURE);
	}
	for (i = 0; i < uc->length; i++) {
		PUTCB32(cb, (CB_UCODE_OFFSET + i * 4), uc->ucode[i]);
	}
	return (iprb_cmd_submit(ip, CB_CMD_UCODE));
}

int
iprb_configure(iprb_t *ip)
{
	ASSERT(mutex_owned(&ip->culock));

	if (iprb_cmd_drain(ip) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if (iprb_set_config(ip) != DDI_SUCCESS)
		return (DDI_FAILURE);
	if (iprb_set_unicast(ip) != DDI_SUCCESS)
		return (DDI_FAILURE);
	if (iprb_set_multicast(ip) != DDI_SUCCESS)
		return (DDI_FAILURE);

	return (DDI_SUCCESS);
}

void
iprb_stop(iprb_t *ip)
{
	/* go idle */
	PUT32(ip, CSR_PORT, PORT_SEL_RESET);
	(void) GET32(ip, CSR_PORT);
	drv_usecwait(50);

	/* shut off device interrupts */
	PUT8(ip, CSR_INTCTL, INTCTL_MASK);
}

int
iprb_start(iprb_t *ip)
{
	iprb_dma_t *cb;

	ASSERT(mutex_owned(&ip->rulock));
	ASSERT(mutex_owned(&ip->culock));

	/* Reset, but first go into idle state */
	PUT32(ip, CSR_PORT, PORT_SEL_RESET);
	(void) GET32(ip, CSR_PORT);
	drv_usecwait(50);

	PUT32(ip, CSR_PORT, PORT_SW_RESET);
	(void) GET32(ip, CSR_PORT);
	drv_usecwait(10);
	PUT8(ip, CSR_INTCTL, INTCTL_MASK);

	/* Reset pointers */
	ip->cmd_head = ip->cmd_tail = 0;
	ip->cmd_last = NUM_TX - 1;

	if (iprb_cmd_ready(ip) != DDI_SUCCESS)
		return (DDI_FAILURE);
	PUT32(ip, CSR_GEN_PTR, 0);
	PUT8(ip, CSR_CMD, CUC_CUBASE);
	(void) GET8(ip, CSR_CMD);

	if (iprb_cmd_ready(ip) != DDI_SUCCESS)
		return (DDI_FAILURE);
	PUT32(ip, CSR_GEN_PTR, 0);
	PUT8(ip, CSR_CMD, RUC_RUBASE);
	(void) GET8(ip, CSR_CMD);

	/* Send a NOP.  This will be the first command seen by the device. */
	cb = iprb_cmd_next(ip);
	ASSERT(cb);
	if (iprb_cmd_submit(ip, CB_CMD_NOP) != DDI_SUCCESS)
		return (DDI_FAILURE);

	/* as that was the first command, go ahead and submit a CU start */
	if (iprb_cmd_ready(ip) != DDI_SUCCESS)
		return (DDI_FAILURE);
	PUT32(ip, CSR_GEN_PTR, cb->paddr);
	PUT8(ip, CSR_CMD, CUC_START);
	(void) GET8(ip, CSR_CMD);

	/* Upload firmware. */
	if (iprb_set_ucode(ip) != DDI_SUCCESS)
		return (DDI_FAILURE);

	/* Set up RFDs */
	iprb_rx_init(ip);

	PUT32(ip, CSR_GEN_PTR, ip->rxb[0].paddr);
	/* wait for the SCB */
	(void) iprb_cmd_ready(ip);
	PUT8(ip, CSR_CMD, RUC_START);
	(void) GET8(ip, CSR_CMD);	/* flush CSR */

	/* Enable device interrupts */
	PUT8(ip, CSR_INTCTL, 0);
	(void) GET8(ip, CSR_INTCTL);

	return (DDI_SUCCESS);
}

void
iprb_update_stats(iprb_t *ip)
{
	iprb_dma_t	*sp = &ip->stats;
	hrtime_t	tstamp;
	int		i;

	ASSERT(mutex_owned(&ip->culock));

	/* Collect the hardware stats, but don't keep redoing it */
	tstamp = gethrtime();
	if (tstamp / NANOSEC == ip->stats_time / NANOSEC)
		return;

	PUTSTAT(sp, STATS_DONE_OFFSET, 0);
	SYNCSTATS(sp, 0, 0, DDI_DMA_SYNC_FORDEV);

	if (iprb_cmd_ready(ip) != DDI_SUCCESS)
		return;
	PUT32(ip, CSR_GEN_PTR, sp->paddr);
	PUT8(ip, CSR_CMD, CUC_STATSBASE);
	(void) GET8(ip, CSR_CMD);

	if (iprb_cmd_ready(ip) != DDI_SUCCESS)
		return;
	PUT8(ip, CSR_CMD, CUC_STATS_RST);
	(void) GET8(ip, CSR_CMD);	/* flush wb */

	for (i = 10000; i; i -= 10) {
		SYNCSTATS(sp, 0, 0, DDI_DMA_SYNC_FORKERNEL);
		if (GETSTAT(sp, STATS_DONE_OFFSET) == STATS_RST_DONE) {
			/* yay stats are updated */
			break;
		}
		drv_usecwait(10);
	}
	if (i == 0) {
		iprb_error(ip, "time out acquiring hardware statistics");
		return;
	}

	ip->ex_coll += GETSTAT(sp, STATS_TX_MAXCOL_OFFSET);
	ip->late_coll += GETSTAT(sp, STATS_TX_LATECOL_OFFSET);
	ip->uflo += GETSTAT(sp, STATS_TX_UFLO_OFFSET);
	ip->defer_xmt += GETSTAT(sp, STATS_TX_DEFER_OFFSET);
	ip->one_coll += GETSTAT(sp, STATS_TX_ONECOL_OFFSET);
	ip->multi_coll += GETSTAT(sp, STATS_TX_MULTCOL_OFFSET);
	ip->collisions += GETSTAT(sp, STATS_TX_TOTCOL_OFFSET);
	ip->fcs_errs += GETSTAT(sp, STATS_RX_FCS_OFFSET);
	ip->align_errs += GETSTAT(sp, STATS_RX_ALIGN_OFFSET);
	ip->norcvbuf += GETSTAT(sp, STATS_RX_NOBUF_OFFSET);
	ip->oflo += GETSTAT(sp, STATS_RX_OFLO_OFFSET);
	ip->runt += GETSTAT(sp, STATS_RX_SHORT_OFFSET);

	ip->stats_time = tstamp;
}

mblk_t *
iprb_send(iprb_t *ip, mblk_t *mp)
{
	iprb_dma_t	*cb;
	size_t		sz;

	ASSERT(mutex_owned(&ip->culock));

	/* possibly reclaim some CBs */
	iprb_cmd_reclaim(ip);

	cb = iprb_cmd_next(ip);

	if (cb == NULL) {
		/* flow control */
		ip->wantw = B_TRUE;
		return (mp);
	}

	if ((sz = msgsize(mp)) > (ETHERMAX + VLAN_TAGSZ)) {
		/* Generally this should never occur */
		ip->macxmt_errs++;
		freemsg(mp);
		return (NULL);
	}

	ip->opackets++;
	ip->obytes += sz;

	PUTCB32(cb, CB_TX_TBD_OFFSET, 0xffffffffU);
	PUTCB16(cb, CB_TX_COUNT_OFFSET, (sz & 0x3fff) | CB_TX_EOF);
	PUTCB8(cb, CB_TX_THRESH_OFFSET, (sz / 8) & 0xff);
	PUTCB8(cb, CB_TX_NUMBER_OFFSET, 0);
	mcopymsg(mp, cb->vaddr + CB_TX_DATA_OFFSET);
	if (cb->vaddr[CB_TX_DATA_OFFSET] & 0x1) {
		if (bcmp(cb->vaddr + CB_TX_DATA_OFFSET, &iprb_bcast, 6) != 0) {
			ip->multixmt++;
		} else {
			ip->brdcstxmt++;
		}
	}
	SYNCCB(cb, 0, CB_TX_DATA_OFFSET + sz, DDI_DMA_SYNC_FORDEV);

	if (iprb_cmd_submit(ip, CB_CMD_TX) != DDI_SUCCESS) {
		ip->macxmt_errs++;
	}

	return (NULL);
}

void
iprb_rx_add(iprb_t *ip)
{
	uint16_t	last, curr, next;
	iprb_dma_t	*rfd, *nfd, *lfd;

	ASSERT(mutex_owned(&ip->rulock));

	curr = ip->rx_index;
	last = ip->rx_last;
	next = (curr + 1) % NUM_RX;

	ip->rx_last = curr;
	ip->rx_index = next;

	lfd = &ip->rxb[last];
	rfd = &ip->rxb[curr];
	nfd = &ip->rxb[next];

	PUTRFD32(rfd, RFD_LNK_OFFSET, nfd->paddr);
	PUTRFD16(rfd, RFD_CTL_OFFSET, RFD_CTL_EL);
	PUTRFD16(rfd, RFD_SIZ_OFFSET, RFD_SIZE - RFD_PKT_OFFSET);
	PUTRFD16(rfd, RFD_CNT_OFFSET, 0);
	SYNCRFD(rfd, 0, RFD_PKT_OFFSET, DDI_DMA_SYNC_FORDEV);
	/* clear the suspend & EL bits from the previous RFD */
	PUTRFD16(lfd, RFD_CTL_OFFSET, 0);
	SYNCRFD(rfd, RFD_CTL_OFFSET, 2, DDI_DMA_SYNC_FORDEV);
}

void
iprb_rx_init(iprb_t *ip)
{
	ip->rx_index = 0;
	ip->rx_last = NUM_RX - 1;
	for (int i = 0; i < NUM_RX; i++)
		iprb_rx_add(ip);
	ip->rx_index = 0;
	ip->rx_last = NUM_RX - 1;
}

mblk_t *
iprb_rx(iprb_t *ip)
{
	iprb_dma_t	*rfd;
	uint16_t	cnt;
	uint16_t	sts;
	int		i;
	mblk_t		*mplist;
	mblk_t		**mpp;
	mblk_t		*mp;

	mplist = NULL;
	mpp = &mplist;

	for (i = 0; i < NUM_RX; i++) {
		rfd = &ip->rxb[ip->rx_index];
		SYNCRFD(rfd, RFD_STS_OFFSET, 2, DDI_DMA_SYNC_FORKERNEL);
		if ((GETRFD16(rfd, RFD_STS_OFFSET) & RFD_STS_C) == 0) {
			break;
		}

		ip->rx_wdog = gethrtime();

		SYNCRFD(rfd, 0, 0, DDI_DMA_SYNC_FORKERNEL);
		cnt = GETRFD16(rfd, RFD_CNT_OFFSET);
		cnt &= ~(RFD_CNT_EOF | RFD_CNT_F);
		sts = GETRFD16(rfd, RFD_STS_OFFSET);

		if (cnt > (ETHERMAX + VLAN_TAGSZ)) {
			ip->toolong++;
			iprb_rx_add(ip);
			continue;
		}
		if (((sts & RFD_STS_OK) == 0) && (sts & RFD_STS_ERRS)) {
			iprb_rx_add(ip);
			continue;
		}
		if ((mp = allocb(cnt, BPRI_MED)) == NULL) {
			ip->norcvbuf++;
			iprb_rx_add(ip);
			continue;
		}
		bcopy(rfd->vaddr + RFD_PKT_OFFSET, mp->b_wptr, cnt);

		/* return it to the RFD list */
		iprb_rx_add(ip);

		mp->b_wptr += cnt;
		ip->ipackets++;
		ip->rbytes += cnt;
		if (mp->b_rptr[0] & 0x1) {
			if (bcmp(mp->b_rptr, &iprb_bcast, 6) != 0) {
				ip->multircv++;
			} else {
				ip->brdcstrcv++;
			}
		}
		*mpp = mp;
		mpp = &mp->b_next;
	}
	return (mplist);
}

int
iprb_m_promisc(void *arg, boolean_t on)
{
	iprb_t *ip = arg;

	mutex_enter(&ip->culock);
	ip->promisc = on;
	if (ip->running && !ip->suspended)
		(void) iprb_configure(ip);
	mutex_exit(&ip->culock);
	return (0);
}

int
iprb_m_unicst(void *arg, const uint8_t *macaddr)
{
	iprb_t *ip = arg;

	mutex_enter(&ip->culock);
	bcopy(macaddr, ip->curraddr, 6);
	if (ip->running && !ip->suspended)
		(void) iprb_configure(ip);
	mutex_exit(&ip->culock);
	return (0);
}

int
iprb_m_multicst(void *arg, boolean_t add, const uint8_t *macaddr)
{
	iprb_t		*ip = arg;
	list_t		*l = &ip->mcast;
	iprb_mcast_t	*mc;

	if (add) {
		mc = kmem_alloc(sizeof (*mc), KM_NOSLEEP);
		if (mc == NULL) {
			return (ENOMEM);
		}
		bcopy(macaddr, mc->addr, 6);
		mutex_enter(&ip->culock);
		list_insert_head(l, mc);
		ip->nmcast++;
		if (ip->running && !ip->suspended)
			(void) iprb_configure(ip);
		mutex_exit(&ip->culock);
	} else {
		mutex_enter(&ip->culock);
		for (mc = list_head(l); mc != NULL; mc = list_next(l, mc)) {
			if (bcmp(macaddr, mc->addr, 6) == 0) {
				list_remove(&ip->mcast, mc);
				ip->nmcast--;
				if (ip->running && !ip->suspended)
					(void) iprb_configure(ip);
				break;
			}
		}
		mutex_exit(&ip->culock);
		if (mc)
			kmem_free(mc, sizeof (*mc));
	}
	return (0);
}

int
iprb_m_start(void *arg)
{
	int rv;
	iprb_t *ip = arg;

	mutex_enter(&ip->rulock);
	mutex_enter(&ip->culock);
	rv = ip->suspended ? 0 : iprb_start(ip);
	if (rv == 0)
		ip->running = B_TRUE;
	ip->perh = ddi_periodic_add(iprb_periodic, ip, 5000000000, 0);
	mutex_exit(&ip->culock);
	mutex_exit(&ip->rulock);
	if (rv == 0) {
		if (ip->miih)
			mii_start(ip->miih);
		else
			/* might be a lie. */
			mac_link_update(ip->mach, LINK_STATE_UP);
	}
	return (rv ? EIO : 0);
}

void
iprb_m_stop(void *arg)
{
	iprb_t *ip = arg;

	if (ip->miih) {
		mii_stop(ip->miih);
	} else {
		mac_link_update(ip->mach, LINK_STATE_DOWN);
	}

	ddi_periodic_delete(ip->perh);
	ip->perh = 0;

	mutex_enter(&ip->rulock);
	mutex_enter(&ip->culock);

	if (!ip->suspended) {
		iprb_update_stats(ip);
		iprb_stop(ip);
	}
	ip->running = B_FALSE;
	mutex_exit(&ip->culock);
	mutex_exit(&ip->rulock);
}

int
iprb_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	iprb_t		*ip = arg;

	if (ip->miih && (mii_m_getstat(ip->miih, stat, val) == 0)) {
		return (0);
	}

	mutex_enter(&ip->culock);
	if ((!ip->suspended) && (ip->running)) {
		iprb_update_stats(ip);
	}
	mutex_exit(&ip->culock);

	switch (stat) {
	case MAC_STAT_IFSPEED:
		if (ip->miih == NULL) {
			*val = 10000000;	/* 10 Mbps */
		}
		break;
	case ETHER_STAT_LINK_DUPLEX:
		if (ip->miih == NULL) {
			*val = LINK_DUPLEX_UNKNOWN;
		}
		break;
	case MAC_STAT_MULTIRCV:
		*val = ip->multircv;
		break;
	case MAC_STAT_BRDCSTRCV:
		*val = ip->brdcstrcv;
		break;
	case MAC_STAT_MULTIXMT:
		*val = ip->multixmt;
		break;
	case MAC_STAT_BRDCSTXMT:
		*val = ip->brdcstxmt;
		break;
	case MAC_STAT_IPACKETS:
		* val = ip->ipackets;
		break;
	case MAC_STAT_RBYTES:
		*val = ip->rbytes;
		break;
	case MAC_STAT_OPACKETS:
		*val = ip->opackets;
		break;
	case MAC_STAT_OBYTES:
		*val = ip->obytes;
		break;
	case MAC_STAT_NORCVBUF:
		*val = ip->norcvbuf;
		break;
	case MAC_STAT_COLLISIONS:
		*val = ip->collisions;
		break;
	case MAC_STAT_IERRORS:
		*val = ip->align_errs +
		    ip->fcs_errs +
		    ip->norcvbuf +
		    ip->runt +
		    ip->toolong +
		    ip->macrcv_errs;
		break;
	case MAC_STAT_OERRORS:
		*val = ip->ex_coll +
		    ip->late_coll +
		    ip->uflo +
		    ip->macxmt_errs +
		    ip->nocarrier;
		break;
	case ETHER_STAT_ALIGN_ERRORS:
		*val = ip->align_errs;
		break;
	case ETHER_STAT_FCS_ERRORS:
		*val = ip->fcs_errs;
		break;
	case ETHER_STAT_DEFER_XMTS:
		*val = ip->defer_xmt;
		break;
	case ETHER_STAT_FIRST_COLLISIONS:
		*val = ip->one_coll + ip->multi_coll + ip->ex_coll;
		break;
	case ETHER_STAT_MULTI_COLLISIONS:
		*val = ip->multi_coll;
		break;
	case ETHER_STAT_TX_LATE_COLLISIONS:
		*val = ip->late_coll;
		break;
	case ETHER_STAT_EX_COLLISIONS:
		*val = ip->ex_coll;
		break;
	case MAC_STAT_OVERFLOWS:
		*val = ip->oflo;
		break;
	case MAC_STAT_UNDERFLOWS:
		*val = ip->uflo;
		break;
	case ETHER_STAT_TOOSHORT_ERRORS:
		*val = ip->runt;
		break;
	case ETHER_STAT_TOOLONG_ERRORS:
		*val = ip->toolong;
		break;
	case ETHER_STAT_CARRIER_ERRORS:
		*val = ip->nocarrier;	/* reported only for "suspend" */
		break;
	case ETHER_STAT_MACXMT_ERRORS:
		*val = ip->macxmt_errs;
		break;
	case ETHER_STAT_MACRCV_ERRORS:
		*val = ip->macrcv_errs;
		break;
	default:
		return (ENOTSUP);
	}
	return (0);
}

void
iprb_m_propinfo(void *arg, const char *name, mac_prop_id_t id,
    mac_prop_info_handle_t pih)
{
	iprb_t *ip = arg;

	if (ip->miih != NULL) {
		mii_m_propinfo(ip->miih, name, id, pih);
		return;
	}
	switch (id) {
	case MAC_PROP_DUPLEX:
	case MAC_PROP_SPEED:
		mac_prop_info_set_perm(pih, MAC_PROP_PERM_READ);
		break;
	}
}

int
iprb_m_getprop(void *arg, const char *name, mac_prop_id_t id, uint_t sz,
    void *val)
{
	iprb_t *ip = arg;
	uint64_t x;

	if (ip->miih != NULL) {
		return (mii_m_getprop(ip->miih, name, id, sz, val));
	}
	switch (id) {
	case MAC_PROP_SPEED:
		x = 10000000;
		bcopy(&x, val, sizeof (x));
		return (0);

	case MAC_PROP_DUPLEX:
		x = LINK_DUPLEX_UNKNOWN;
		bcopy(&x, val, sizeof (x));
		return (0);
	}

	return (ENOTSUP);
}

int
iprb_m_setprop(void *arg, const char *name, mac_prop_id_t id, uint_t sz,
    const void *val)
{
	iprb_t *ip = arg;

	if (ip->miih != NULL) {
		return (mii_m_setprop(ip->miih, name, id, sz, val));
	}
	return (ENOTSUP);
}

mblk_t *
iprb_m_tx(void *arg, mblk_t *mp)
{
	iprb_t *ip = arg;
	mblk_t *nmp;

	mutex_enter(&ip->culock);

	while (mp != NULL) {
		nmp = mp->b_next;
		mp->b_next = NULL;
		if (ip->suspended) {
			freemsg(mp);
			ip->nocarrier++;
			mp = nmp;
			continue;
		}
		if ((mp = iprb_send(ip, mp)) != NULL) {
			mp->b_next = nmp;
			break;
		}
		mp = nmp;
	}
	mutex_exit(&ip->culock);
	return (mp);
}

void
iprb_m_ioctl(void *arg, queue_t *wq, mblk_t *mp)
{
	iprb_t	*ip = arg;

	if ((ip->miih != NULL) && (mii_m_loop_ioctl(ip->miih, wq, mp)))
		return;

	miocnak(wq, mp, 0, EINVAL);
}

uint16_t
iprb_mii_read(void *arg, uint8_t phy, uint8_t reg)
{
	iprb_t	*ip = arg;
	uint32_t mdi;

	/*
	 * NB: we are guaranteed by the MII layer not to be suspended.
	 * Furthermore, we have an independent MII register.
	 */

	mdi = MDI_OP_RD |
	    ((uint32_t)phy << MDI_PHYAD_SHIFT) |
	    ((uint32_t)reg << MDI_REGAD_SHIFT);

	PUT32(ip, CSR_MDICTL, mdi);
	for (int i = 0; i < 100; i++) {
		mdi = GET32(ip, CSR_MDICTL);
		if (mdi & MDI_R) {
			return (mdi & 0xffff);
		}
		drv_usecwait(1);
	}
	return (0xffff);
}

void
iprb_mii_write(void *arg, uint8_t phy, uint8_t reg, uint16_t data)
{
	iprb_t	*ip = arg;
	uint32_t mdi;

	mdi = MDI_OP_WR |
	    ((uint32_t)phy << MDI_PHYAD_SHIFT) |
	    ((uint32_t)reg << MDI_REGAD_SHIFT) |
	    (data);

	PUT32(ip, CSR_MDICTL, mdi);
	for (int i = 0; i < 100; i++) {
		if (GET32(ip, CSR_MDICTL) & MDI_R)
			break;
	}
}

void
iprb_mii_notify(void *arg, link_state_t link)
{
	iprb_t *ip = arg;

	mac_link_update(ip->mach, link);
}

uint_t
iprb_intr(caddr_t arg1, caddr_t arg2)
{
	iprb_t *ip = (void *)arg1;
	uint8_t	sts;
	mblk_t	*mp = NULL;

	_NOTE(ARGUNUSED(arg2));

	mutex_enter(&ip->rulock);
	if (ip->suspended) {
		mutex_exit(&ip->rulock);
		return (DDI_INTR_UNCLAIMED);
	}
	sts = GET8(ip, CSR_STS);
	if (sts == 0) {
		/* No interrupt status! */
		mutex_exit(&ip->rulock);
		return (DDI_INTR_UNCLAIMED);
	}
	/* acknowledge the interrupts */
	PUT8(ip, CSR_STS, sts);

	if (sts & (STS_RNR | STS_FR)) {
		mp = iprb_rx(ip);

		if ((sts & STS_RNR) &&
		    ((GET8(ip, CSR_STATE) & STATE_RUS) == STATE_RUS_NORES)) {
			iprb_rx_init(ip);

			mutex_enter(&ip->culock);
			PUT32(ip, CSR_GEN_PTR, ip->rxb[0].paddr);
			/* wait for the SCB */
			(void) iprb_cmd_ready(ip);
			PUT8(ip, CSR_CMD, RUC_START);
			(void) GET8(ip, CSR_CMD);	/* flush CSR */
			mutex_exit(&ip->culock);
		}
	}
	mutex_exit(&ip->rulock);

	if (mp) {
		mac_rx(ip->mach, NULL, mp);
	}
	if ((sts & (STS_CNA | STS_CX)) && ip->wantw)  {
		ip->wantw = B_FALSE;
		mac_tx_update(ip->mach);
	}
	return (DDI_INTR_CLAIMED);
}

void
iprb_periodic(void *arg)
{
	iprb_t *ip = arg;
	boolean_t reset = B_FALSE;

	mutex_enter(&ip->rulock);
	if (ip->suspended || !ip->running) {
		mutex_exit(&ip->rulock);
		return;
	}

	/*
	 * If we haven't received a packet in a while, and if the link
	 * is up, then it might be a hung chip.  This problem
	 * reportedly only occurs at 10 Mbps.
	 */
	if (ip->rxhangbug &&
	    ((ip->miih == NULL) || (mii_get_speed(ip->miih) == 10000000)) &&
	    ((gethrtime() - ip->rx_wdog) > ip->rx_timeout)) {
		cmn_err(CE_CONT, "?Possible RU hang, resetting.\n");
		reset = B_TRUE;
	}

	/* update the statistics */
	mutex_enter(&ip->culock);

	if (ip->tx_wdog && ((gethrtime() - ip->tx_wdog) > ip->tx_timeout)) {
		/* transmit/CU hang? */
		cmn_err(CE_CONT, "?CU stalled, resetting.\n");
		reset = B_TRUE;
	}

	if (reset) {
		/* We want to reconfigure */
		iprb_stop(ip);
		if (iprb_start(ip) != DDI_SUCCESS) {
			iprb_error(ip, "unable to restart chip");
		}
	}

	iprb_update_stats(ip);

	mutex_exit(&ip->culock);
	mutex_exit(&ip->rulock);
}

int
iprb_quiesce(dev_info_t *dip)
{
	iprb_t *ip = ddi_get_driver_private(dip);

	/* Reset, but first go into idle state */
	PUT32(ip, CSR_PORT, PORT_SEL_RESET);
	drv_usecwait(50);
	PUT32(ip, CSR_PORT, PORT_SW_RESET);
	drv_usecwait(10);
	PUT8(ip, CSR_INTCTL, INTCTL_MASK);

	return (DDI_SUCCESS);
}

int
iprb_suspend(dev_info_t *dip)
{
	iprb_t *ip = ddi_get_driver_private(dip);

	if (ip->miih)
		mii_suspend(ip->miih);

	mutex_enter(&ip->rulock);
	mutex_enter(&ip->culock);
	if (!ip->suspended) {
		ip->suspended = B_TRUE;
		if (ip->running) {
			iprb_update_stats(ip);
			iprb_stop(ip);
		}
	}
	mutex_exit(&ip->culock);
	mutex_exit(&ip->rulock);
	return (DDI_SUCCESS);
}

int
iprb_resume(dev_info_t *dip)
{
	iprb_t *ip = ddi_get_driver_private(dip);

	mutex_enter(&ip->rulock);
	mutex_enter(&ip->culock);

	ip->suspended = B_FALSE;
	if (ip->running) {
		if (iprb_start(ip) != DDI_SUCCESS) {
			iprb_error(ip, "unable to restart chip!");
			ip->suspended = B_TRUE;
			mutex_exit(&ip->culock);
			mutex_exit(&ip->rulock);
			return (DDI_FAILURE);
		}
	}

	mutex_exit(&ip->culock);
	mutex_exit(&ip->rulock);
	if (ip->miih)
		mii_resume(ip->miih);
	return (DDI_SUCCESS);
}

int
iprb_ddi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		return (iprb_attach(dip));

	case DDI_RESUME:
		return (iprb_resume(dip));

	default:
		return (DDI_FAILURE);
	}
}

int
iprb_ddi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		return (iprb_detach(dip));

	case DDI_SUSPEND:
		return (iprb_suspend(dip));

	default:
		return (DDI_FAILURE);
	}
}

void
iprb_error(iprb_t *ip, const char *fmt, ...)
{
	va_list ap;
	char buf[256];

	va_start(ap, fmt);
	(void) vsnprintf(buf, sizeof (buf), fmt, ap);
	va_end(ap);

	cmn_err(CE_WARN, "%s%d: %s",
	    ddi_driver_name(ip->dip), ddi_get_instance(ip->dip), buf);
}
