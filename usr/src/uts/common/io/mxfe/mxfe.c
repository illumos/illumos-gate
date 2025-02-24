/*
 * Solaris driver for ethernet cards based on the Macronix 98715
 *
 * Copyright (c) 2007 by Garrett D'Amore <garrett@damore.org>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <sys/varargs.h>
#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/cmn_err.h>
#include <sys/dlpi.h>
#include <sys/ethernet.h>
#include <sys/kmem.h>
#include <sys/time.h>
#include <sys/miiregs.h>
#include <sys/strsun.h>
#include <sys/mac.h>
#include <sys/mac_ether.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/vlan.h>

#include "mxfe.h"
#include "mxfeimpl.h"

/*
 * Driver globals.
 */

/* patchable debug flag ... must not be static! */
#ifdef	DEBUG
unsigned		mxfe_debug = DWARN;
#endif

/* table of supported devices */
static mxfe_card_t mxfe_cards[] = {

	/*
	 * Lite-On products
	 */
	{ 0x11ad, 0xc115, 0, 0, "Lite-On LC82C115", MXFE_PNICII },

	/*
	 * Macronix chips
	 */
	{ 0x10d9, 0x0531, 0x25, 0xff, "Macronix MX98715AEC", MXFE_98715AEC },
	{ 0x10d9, 0x0531, 0x20, 0xff, "Macronix MX98715A", MXFE_98715A },
	{ 0x10d9, 0x0531, 0x60, 0xff, "Macronix MX98715B", MXFE_98715B },
	{ 0x10d9, 0x0531, 0x30, 0xff, "Macronix MX98725", MXFE_98725 },
	{ 0x10d9, 0x0531, 0x00, 0xff, "Macronix MX98715", MXFE_98715 },
	{ 0x10d9, 0x0512, 0, 0, "Macronix MX98713", MXFE_98713 },

	/*
	 * Compex (relabeled Macronix products)
	 */
	{ 0x11fc, 0x9881, 0x00, 0x00, "Compex 9881", MXFE_98713 },
	{ 0x11fc, 0x9881, 0x10, 0xff, "Compex 9881A", MXFE_98713A },
	/*
	 * Models listed here
	 */
	{ 0x11ad, 0xc001, 0, 0, "Linksys LNE100TX", MXFE_PNICII },
	{ 0x2646, 0x000b, 0, 0, "Kingston KNE111TX", MXFE_PNICII },
	{ 0x1154, 0x0308, 0, 0, "Buffalo LGY-PCI-TXL", MXFE_98715AEC },
};

#define	ETHERVLANMTU	(ETHERMAX + 4)

/*
 * Function prototypes
 */
static int	mxfe_attach(dev_info_t *, ddi_attach_cmd_t);
static int	mxfe_detach(dev_info_t *, ddi_detach_cmd_t);
static int	mxfe_resume(dev_info_t *);
static int	mxfe_quiesce(dev_info_t *);
static int	mxfe_m_unicst(void *, const uint8_t *);
static int	mxfe_m_multicst(void *, boolean_t, const uint8_t *);
static int	mxfe_m_promisc(void *, boolean_t);
static mblk_t	*mxfe_m_tx(void *, mblk_t *);
static int	mxfe_m_stat(void *, uint_t, uint64_t *);
static int	mxfe_m_start(void *);
static void	mxfe_m_stop(void *);
static int	mxfe_m_getprop(void *, const char *, mac_prop_id_t, uint_t,
    void *);
static int	mxfe_m_setprop(void *, const char *, mac_prop_id_t, uint_t,
    const void *);
static void	mxfe_m_propinfo(void *, const char *, mac_prop_id_t,
    mac_prop_info_handle_t);
static unsigned	mxfe_intr(caddr_t);
static void	mxfe_startmac(mxfe_t *);
static void	mxfe_stopmac(mxfe_t *);
static void	mxfe_resetrings(mxfe_t *);
static boolean_t	mxfe_initialize(mxfe_t *);
static void	mxfe_startall(mxfe_t *);
static void	mxfe_stopall(mxfe_t *);
static void	mxfe_resetall(mxfe_t *);
static mxfe_txbuf_t *mxfe_alloctxbuf(mxfe_t *);
static void	mxfe_destroytxbuf(mxfe_txbuf_t *);
static mxfe_rxbuf_t *mxfe_allocrxbuf(mxfe_t *);
static void	mxfe_destroyrxbuf(mxfe_rxbuf_t *);
static void	mxfe_send_setup(mxfe_t *);
static boolean_t	mxfe_send(mxfe_t *, mblk_t *);
static int	mxfe_allocrxring(mxfe_t *);
static void	mxfe_freerxring(mxfe_t *);
static int	mxfe_alloctxring(mxfe_t *);
static void	mxfe_freetxring(mxfe_t *);
static void	mxfe_error(dev_info_t *, char *, ...);
static uint8_t	mxfe_sromwidth(mxfe_t *);
static uint16_t	mxfe_readsromword(mxfe_t *, unsigned);
static void	mxfe_readsrom(mxfe_t *, unsigned, unsigned, void *);
static void	mxfe_getfactaddr(mxfe_t *, uchar_t *);
static uint8_t	mxfe_miireadbit(mxfe_t *);
static void	mxfe_miiwritebit(mxfe_t *, uint8_t);
static void	mxfe_miitristate(mxfe_t *);
static uint16_t	mxfe_miiread(mxfe_t *, int, int);
static void	mxfe_miiwrite(mxfe_t *, int, int, uint16_t);
static uint16_t	mxfe_miireadgeneral(mxfe_t *, int, int);
static void	mxfe_miiwritegeneral(mxfe_t *, int, int, uint16_t);
static uint16_t	mxfe_miiread98713(mxfe_t *, int, int);
static void	mxfe_miiwrite98713(mxfe_t *, int, int, uint16_t);
static void	mxfe_startphy(mxfe_t *);
static void	mxfe_stopphy(mxfe_t *);
static void	mxfe_startphymii(mxfe_t *);
static void	mxfe_startphynway(mxfe_t *);
static void	mxfe_startnway(mxfe_t *);
static void	mxfe_reportlink(mxfe_t *);
static void	mxfe_checklink(mxfe_t *);
static void	mxfe_checklinkmii(mxfe_t *);
static void	mxfe_checklinknway(mxfe_t *);
static void	mxfe_disableinterrupts(mxfe_t *);
static void	mxfe_enableinterrupts(mxfe_t *);
static void	mxfe_reclaim(mxfe_t *);
static boolean_t	mxfe_receive(mxfe_t *, mblk_t **);

#ifdef	DEBUG
static void	mxfe_dprintf(mxfe_t *, const char *, int, char *, ...);
#endif

#define	KIOIP	KSTAT_INTR_PTR(mxfep->mxfe_intrstat)

static mac_callbacks_t mxfe_m_callbacks = {
	MC_SETPROP | MC_GETPROP | MC_PROPINFO,
	mxfe_m_stat,
	mxfe_m_start,
	mxfe_m_stop,
	mxfe_m_promisc,
	mxfe_m_multicst,
	mxfe_m_unicst,
	mxfe_m_tx,
	NULL,
	NULL,		/* mc_ioctl */
	NULL,		/* mc_getcapab */
	NULL,		/* mc_open */
	NULL,		/* mc_close */
	mxfe_m_setprop,
	mxfe_m_getprop,
	mxfe_m_propinfo
};

/*
 * Stream information
 */
DDI_DEFINE_STREAM_OPS(mxfe_devops, nulldev, nulldev, mxfe_attach, mxfe_detach,
    nodev, NULL, D_MP, NULL, mxfe_quiesce);

/*
 * Module linkage information.
 */

static struct modldrv mxfe_modldrv = {
	&mod_driverops,			/* drv_modops */
	"Macronix Fast Ethernet",	/* drv_linkinfo */
	&mxfe_devops			/* drv_dev_ops */
};

static struct modlinkage mxfe_modlinkage = {
	MODREV_1,		/* ml_rev */
	{ &mxfe_modldrv, NULL } /* ml_linkage */
};

/*
 * Device attributes.
 */
static ddi_device_acc_attr_t mxfe_devattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

static ddi_device_acc_attr_t mxfe_bufattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};

static ddi_dma_attr_t mxfe_dma_attr = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo */
	0xFFFFFFFFU,		/* dma_attr_addr_hi */
	0x7FFFFFFFU,		/* dma_attr_count_max */
	4,			/* dma_attr_align */
	0x3F,			/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0xFFFFFFFFU,		/* dma_attr_maxxfer */
	0xFFFFFFFFU,		/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};

/*
 * Tx buffers can be arbitrarily aligned.  Additionally, they can
 * cross a page boundary, so we use the two buffer addresses of the
 * chip to provide a two-entry scatter-gather list.
 */
static ddi_dma_attr_t mxfe_dma_txattr = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo */
	0xFFFFFFFFU,		/* dma_attr_addr_hi */
	0x7FFFFFFFU,		/* dma_attr_count_max */
	1,			/* dma_attr_align */
	0x3F,			/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0xFFFFFFFFU,		/* dma_attr_maxxfer */
	0xFFFFFFFFU,		/* dma_attr_seg */
	2,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};

/*
 * Ethernet addresses.
 */
static uchar_t mxfe_broadcast[ETHERADDRL] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

/*
 * DDI entry points.
 */
int
_init(void)
{
	int	rv;
	mac_init_ops(&mxfe_devops, "mxfe");
	if ((rv = mod_install(&mxfe_modlinkage)) != DDI_SUCCESS) {
		mac_fini_ops(&mxfe_devops);
	}
	return (rv);
}

int
_fini(void)
{
	int	rv;
	if ((rv = mod_remove(&mxfe_modlinkage)) == DDI_SUCCESS) {
		mac_fini_ops(&mxfe_devops);
	}
	return (rv);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&mxfe_modlinkage, modinfop));
}

int
mxfe_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	mxfe_t			*mxfep;
	mac_register_t		*macp;
	int			inst = ddi_get_instance(dip);
	ddi_acc_handle_t	pci;
	uint16_t		venid;
	uint16_t		devid;
	uint16_t		revid;
	uint16_t		svid;
	uint16_t		ssid;
	uint16_t		cachesize;
	mxfe_card_t		*cardp;
	int			i;

	switch (cmd) {
	case DDI_RESUME:
		return (mxfe_resume(dip));

	case DDI_ATTACH:
		break;

	default:
		return (DDI_FAILURE);
	}

	/* this card is a bus master, reject any slave-only slot */
	if (ddi_slaveonly(dip) == DDI_SUCCESS) {
		mxfe_error(dip, "slot does not support PCI bus-master");
		return (DDI_FAILURE);
	}
	/* PCI devices shouldn't generate hilevel interrupts */
	if (ddi_intr_hilevel(dip, 0) != 0) {
		mxfe_error(dip, "hilevel interrupts not supported");
		return (DDI_FAILURE);
	}
	if (pci_config_setup(dip, &pci) != DDI_SUCCESS) {
		mxfe_error(dip, "unable to setup PCI config handle");
		return (DDI_FAILURE);
	}

	venid = pci_config_get16(pci, PCI_VID);
	devid = pci_config_get16(pci, PCI_DID);
	revid = pci_config_get16(pci, PCI_RID);
	svid = pci_config_get16(pci, PCI_SVID);
	ssid = pci_config_get16(pci, PCI_SSID);

	/*
	 * the last entry in the card table matches every possible
	 * card, so the for-loop always terminates properly.
	 */
	cardp = NULL;
	for (i = 0; i < (sizeof (mxfe_cards) / sizeof (mxfe_card_t)); i++) {
		if ((venid == mxfe_cards[i].card_venid) &&
		    (devid == mxfe_cards[i].card_devid) &&
		    ((revid & mxfe_cards[i].card_revmask) ==
		    mxfe_cards[i].card_revid)) {
			cardp = &mxfe_cards[i];
		}
		if ((svid == mxfe_cards[i].card_venid) &&
		    (ssid == mxfe_cards[i].card_devid) &&
		    ((revid & mxfe_cards[i].card_revmask) ==
		    mxfe_cards[i].card_revid)) {
			cardp = &mxfe_cards[i];
			break;
		}
	}

	if (cardp == NULL) {
		pci_config_teardown(&pci);
		mxfe_error(dip, "Unable to identify PCI card");
		return (DDI_FAILURE);
	}

	if (ddi_prop_update_string(DDI_DEV_T_NONE, dip, "model",
	    cardp->card_cardname) != DDI_PROP_SUCCESS) {
		pci_config_teardown(&pci);
		mxfe_error(dip, "Unable to create model property");
		return (DDI_FAILURE);
	}

	/*
	 * Grab the PCI cachesize -- we use this to program the
	 * cache-optimization bus access bits.
	 */
	cachesize = pci_config_get8(pci, PCI_CLS);

	/* this cannot fail */
	mxfep = kmem_zalloc(sizeof (mxfe_t), KM_SLEEP);
	ddi_set_driver_private(dip, mxfep);

	/* get the interrupt block cookie */
	if (ddi_get_iblock_cookie(dip, 0, &mxfep->mxfe_icookie)
	    != DDI_SUCCESS) {
		mxfe_error(dip, "ddi_get_iblock_cookie failed");
		pci_config_teardown(&pci);
		kmem_free(mxfep, sizeof (mxfe_t));
		return (DDI_FAILURE);
	}

	mxfep->mxfe_dip = dip;
	mxfep->mxfe_cardp = cardp;
	mxfep->mxfe_phyaddr = -1;
	mxfep->mxfe_cachesize = cachesize;

	/* default properties */
	mxfep->mxfe_adv_aneg = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "adv_autoneg_cap", 1);
	mxfep->mxfe_adv_100T4 = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "adv_100T4_cap", 1);
	mxfep->mxfe_adv_100fdx = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "adv_100fdx_cap", 1);
	mxfep->mxfe_adv_100hdx = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "adv_100hdx_cap", 1);
	mxfep->mxfe_adv_10fdx = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "adv_10fdx_cap", 1);
	mxfep->mxfe_adv_10hdx = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "adv_10hdx_cap", 1);

	DBG(DPCI, "PCI vendor id = %x", venid);
	DBG(DPCI, "PCI device id = %x", devid);
	DBG(DPCI, "PCI revision id = %x", revid);
	DBG(DPCI, "PCI cachesize = %d", cachesize);
	DBG(DPCI, "PCI COMM = %x", pci_config_get8(pci, PCI_CMD));
	DBG(DPCI, "PCI STAT = %x", pci_config_get8(pci, PCI_STAT));

	mutex_init(&mxfep->mxfe_xmtlock, NULL, MUTEX_DRIVER,
	    mxfep->mxfe_icookie);
	mutex_init(&mxfep->mxfe_intrlock, NULL, MUTEX_DRIVER,
	    mxfep->mxfe_icookie);

	/*
	 * Enable bus master, IO space, and memory space accesses.
	 */
	pci_config_put16(pci, PCI_CMD,
	    pci_config_get16(pci, PCI_CMD) |
	    PCI_CMD_BME | PCI_CMD_MAE | PCI_CMD_MWIE);

	/* we're done with this now, drop it */
	pci_config_teardown(&pci);

	/*
	 * Initialize interrupt kstat.  This should not normally fail, since
	 * we don't use a persistent stat.  We do it this way to avoid having
	 * to test for it at run time on the hot path.
	 */
	mxfep->mxfe_intrstat = kstat_create("mxfe", inst, "intr", "controller",
	    KSTAT_TYPE_INTR, 1, 0);
	if (mxfep->mxfe_intrstat == NULL) {
		mxfe_error(dip, "kstat_create failed");
		goto failed;
	}
	kstat_install(mxfep->mxfe_intrstat);

	/*
	 * Map in the device registers.
	 */
	if (ddi_regs_map_setup(dip, 1, (caddr_t *)&mxfep->mxfe_regs,
	    0, 0, &mxfe_devattr, &mxfep->mxfe_regshandle)) {
		mxfe_error(dip, "ddi_regs_map_setup failed");
		goto failed;
	}

	/*
	 * Allocate DMA resources (descriptor rings and buffers).
	 */
	if ((mxfe_allocrxring(mxfep) != DDI_SUCCESS) ||
	    (mxfe_alloctxring(mxfep) != DDI_SUCCESS)) {
		mxfe_error(dip, "unable to allocate DMA resources");
		goto failed;
	}

	/* Initialize the chip. */
	mutex_enter(&mxfep->mxfe_intrlock);
	mutex_enter(&mxfep->mxfe_xmtlock);
	if (!mxfe_initialize(mxfep)) {
		mutex_exit(&mxfep->mxfe_xmtlock);
		mutex_exit(&mxfep->mxfe_intrlock);
		goto failed;
	}
	mutex_exit(&mxfep->mxfe_xmtlock);
	mutex_exit(&mxfep->mxfe_intrlock);

	/* Determine the number of address bits to our EEPROM. */
	mxfep->mxfe_sromwidth = mxfe_sromwidth(mxfep);

	/*
	 * Get the factory ethernet address.  This becomes the current
	 * ethernet address (it can be overridden later via ifconfig).
	 */
	mxfe_getfactaddr(mxfep, mxfep->mxfe_curraddr);
	mxfep->mxfe_promisc = B_FALSE;

	/*
	 * Establish interrupt handler.
	 */
	if (ddi_add_intr(dip, 0, NULL, NULL, mxfe_intr, (caddr_t)mxfep) !=
	    DDI_SUCCESS) {
		mxfe_error(dip, "unable to add interrupt");
		goto failed;
	}

	/* TODO: do the power management stuff */

	if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
		mxfe_error(dip, "mac_alloc failed");
		goto failed;
	}

	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_driver = mxfep;
	macp->m_dip = dip;
	macp->m_src_addr = mxfep->mxfe_curraddr;
	macp->m_callbacks = &mxfe_m_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = ETHERMTU;
	macp->m_margin = VLAN_TAGSZ;

	if (mac_register(macp, &mxfep->mxfe_mh) == DDI_SUCCESS) {
		mac_free(macp);
		return (DDI_SUCCESS);
	}

	/* failed to register with MAC */
	mac_free(macp);
failed:
	if (mxfep->mxfe_icookie != NULL) {
		ddi_remove_intr(dip, 0, mxfep->mxfe_icookie);
	}
	if (mxfep->mxfe_intrstat) {
		kstat_delete(mxfep->mxfe_intrstat);
	}
	mutex_destroy(&mxfep->mxfe_intrlock);
	mutex_destroy(&mxfep->mxfe_xmtlock);

	mxfe_freerxring(mxfep);
	mxfe_freetxring(mxfep);

	if (mxfep->mxfe_regshandle != NULL) {
		ddi_regs_map_free(&mxfep->mxfe_regshandle);
	}
	kmem_free(mxfep, sizeof (mxfe_t));
	return (DDI_FAILURE);
}

int
mxfe_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	mxfe_t		*mxfep;

	mxfep = ddi_get_driver_private(dip);
	if (mxfep == NULL) {
		mxfe_error(dip, "no soft state in detach!");
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_DETACH:

		if (mac_unregister(mxfep->mxfe_mh) != 0) {
			return (DDI_FAILURE);
		}

		/* make sure hardware is quiesced */
		mutex_enter(&mxfep->mxfe_intrlock);
		mutex_enter(&mxfep->mxfe_xmtlock);
		mxfep->mxfe_flags &= ~MXFE_RUNNING;
		mxfe_stopall(mxfep);
		mutex_exit(&mxfep->mxfe_xmtlock);
		mutex_exit(&mxfep->mxfe_intrlock);

		/* clean up and shut down device */
		ddi_remove_intr(dip, 0, mxfep->mxfe_icookie);

		/* clean up kstats */
		kstat_delete(mxfep->mxfe_intrstat);

		ddi_prop_remove_all(dip);

		/* free up any left over buffers or DMA resources */
		mxfe_freerxring(mxfep);
		mxfe_freetxring(mxfep);

		ddi_regs_map_free(&mxfep->mxfe_regshandle);
		mutex_destroy(&mxfep->mxfe_intrlock);
		mutex_destroy(&mxfep->mxfe_xmtlock);

		kmem_free(mxfep, sizeof (mxfe_t));
		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		/* quiesce the hardware */
		mutex_enter(&mxfep->mxfe_intrlock);
		mutex_enter(&mxfep->mxfe_xmtlock);
		mxfep->mxfe_flags |= MXFE_SUSPENDED;
		mxfe_stopall(mxfep);
		mutex_exit(&mxfep->mxfe_xmtlock);
		mutex_exit(&mxfep->mxfe_intrlock);
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

int
mxfe_resume(dev_info_t *dip)
{
	mxfe_t		*mxfep;

	if ((mxfep = ddi_get_driver_private(dip)) == NULL) {
		return (DDI_FAILURE);
	}

	mutex_enter(&mxfep->mxfe_intrlock);
	mutex_enter(&mxfep->mxfe_xmtlock);

	mxfep->mxfe_flags &= ~MXFE_SUSPENDED;

	/* re-initialize chip */
	if (!mxfe_initialize(mxfep)) {
		mxfe_error(mxfep->mxfe_dip, "unable to resume chip!");
		mxfep->mxfe_flags |= MXFE_SUSPENDED;
		mutex_exit(&mxfep->mxfe_intrlock);
		mutex_exit(&mxfep->mxfe_xmtlock);
		return (DDI_SUCCESS);
	}

	/* start the chip */
	if (mxfep->mxfe_flags & MXFE_RUNNING) {
		mxfe_startall(mxfep);
	}

	/* drop locks */
	mutex_exit(&mxfep->mxfe_xmtlock);
	mutex_exit(&mxfep->mxfe_intrlock);

	return (DDI_SUCCESS);
}

int
mxfe_quiesce(dev_info_t *dip)
{
	mxfe_t	*mxfep;

	if ((mxfep = ddi_get_driver_private(dip)) == NULL) {
		return (DDI_FAILURE);
	}

	/* just do a hard reset of everything */
	SETBIT(mxfep, CSR_PAR, PAR_RESET);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
mxfe_m_multicst(void *arg, boolean_t add, const uint8_t *macaddr)
{
	/* we already receive all multicast frames */
	return (0);
}

int
mxfe_m_promisc(void *arg, boolean_t on)
{
	mxfe_t		*mxfep = arg;

	/* exclusive access to the card while we reprogram it */
	mutex_enter(&mxfep->mxfe_intrlock);
	mutex_enter(&mxfep->mxfe_xmtlock);
	/* save current promiscuous mode state for replay in resume */
	mxfep->mxfe_promisc = on;

	if ((mxfep->mxfe_flags & (MXFE_RUNNING|MXFE_SUSPENDED)) ==
	    MXFE_RUNNING) {
		if (on)
			SETBIT(mxfep, CSR_NAR, NAR_RX_PROMISC);
		else
			CLRBIT(mxfep, CSR_NAR, NAR_RX_PROMISC);
	}

	mutex_exit(&mxfep->mxfe_xmtlock);
	mutex_exit(&mxfep->mxfe_intrlock);

	return (0);
}

int
mxfe_m_unicst(void *arg, const uint8_t *macaddr)
{
	mxfe_t		*mxfep = arg;

	mutex_enter(&mxfep->mxfe_intrlock);
	mutex_enter(&mxfep->mxfe_xmtlock);
	bcopy(macaddr, mxfep->mxfe_curraddr, ETHERADDRL);

	mxfe_resetall(mxfep);

	mutex_exit(&mxfep->mxfe_intrlock);
	mutex_exit(&mxfep->mxfe_xmtlock);

	return (0);
}

mblk_t *
mxfe_m_tx(void *arg, mblk_t *mp)
{
	mxfe_t	*mxfep = arg;
	mblk_t	*nmp;

	mutex_enter(&mxfep->mxfe_xmtlock);

	if (mxfep->mxfe_flags & MXFE_SUSPENDED) {
		mutex_exit(&mxfep->mxfe_xmtlock);
		return (mp);
	}

	while (mp != NULL) {
		nmp = mp->b_next;
		mp->b_next = NULL;

		if (!mxfe_send(mxfep, mp)) {
			mp->b_next = nmp;
			break;
		}
		mp = nmp;
	}
	mutex_exit(&mxfep->mxfe_xmtlock);

	return (mp);
}

/*
 * Hardware management.
 */
boolean_t
mxfe_initialize(mxfe_t *mxfep)
{
	int		i;
	unsigned	val;
	uint32_t	par, nar;

	ASSERT(mutex_owned(&mxfep->mxfe_intrlock));
	ASSERT(mutex_owned(&mxfep->mxfe_xmtlock));

	DBG(DCHATTY, "resetting!");
	SETBIT(mxfep, CSR_PAR, PAR_RESET);
	for (i = 1; i < 10; i++) {
		drv_usecwait(5);
		val = GETCSR(mxfep, CSR_PAR);
		if (!(val & PAR_RESET)) {
			break;
		}
	}
	if (i == 10) {
		mxfe_error(mxfep->mxfe_dip, "timed out waiting for reset!");
		return (B_FALSE);
	}

	/* initialize busctl register */
	par = PAR_BAR | PAR_MRME | PAR_MRLE | PAR_MWIE;

	/* set the cache alignment if its supported */
	switch (mxfep->mxfe_cachesize) {
	case 8:
		par |= PAR_CALIGN_8;
		break;
	case 16:
		par |= PAR_CALIGN_16;
		break;
	case 32:
		par |= PAR_CALIGN_32;
		break;
	default:
		par &= ~(PAR_MWIE | PAR_MRME | PAR_MRLE);
	}

	/* leave the burst length at zero, indicating infinite burst */
	PUTCSR(mxfep, CSR_PAR, par);

	mxfe_resetrings(mxfep);

	/* clear the lost packet counter (cleared on read) */
	(void) GETCSR(mxfep, CSR_LPC);

	/* a few other NAR bits */
	nar = GETCSR(mxfep, CSR_NAR);
	nar &= ~NAR_RX_HO;	/* disable hash only filtering */
	nar |= NAR_RX_HP;	/* hash perfect forwarding */
	nar |= NAR_RX_MULTI;	/* receive all multicast */
	nar |= NAR_SF;	/* store-and-forward */

	if (mxfep->mxfe_promisc) {
		nar |= NAR_RX_PROMISC;
	} else {
		nar &= ~NAR_RX_PROMISC;
	}
	PUTCSR(mxfep, CSR_NAR, nar);

	mxfe_send_setup(mxfep);

	return (B_TRUE);
}

/*
 * Serial EEPROM access - inspired by the FreeBSD implementation.
 */

uint8_t
mxfe_sromwidth(mxfe_t *mxfep)
{
	int		i;
	int		eeread;
	uint8_t		addrlen = 8;

	eeread = SPR_SROM_READ | SPR_SROM_SEL | SPR_SROM_CHIP;

	PUTCSR(mxfep, CSR_SPR, eeread & ~SPR_SROM_CHIP);
	drv_usecwait(1);
	PUTCSR(mxfep, CSR_SPR, eeread);

	/* command bits first */
	for (i = 4; i != 0; i >>= 1) {
		unsigned val = (SROM_READCMD & i) ? SPR_SROM_DIN : 0;
		PUTCSR(mxfep, CSR_SPR, eeread | val);
		drv_usecwait(1);
		PUTCSR(mxfep, CSR_SPR, eeread | val | SPR_SROM_CLOCK);
		drv_usecwait(1);
	}

	PUTCSR(mxfep, CSR_SPR, eeread);

	for (addrlen = 1; addrlen <= 12; addrlen++) {
		PUTCSR(mxfep, CSR_SPR, eeread | SPR_SROM_CLOCK);
		drv_usecwait(1);
		if (!(GETCSR(mxfep, CSR_SPR) & SPR_SROM_DOUT)) {
			PUTCSR(mxfep, CSR_SPR, eeread);
			drv_usecwait(1);
			break;
		}
		PUTCSR(mxfep, CSR_SPR, eeread);
		drv_usecwait(1);
	}

	/* turn off accesses to the EEPROM */
	PUTCSR(mxfep, CSR_SPR, eeread &~ SPR_SROM_CHIP);

	DBG(DSROM, "detected srom width = %d bits", addrlen);

	return ((addrlen < 4 || addrlen > 12) ? 6 : addrlen);
}

/*
 * The words in EEPROM are stored in little endian order.  We
 * shift bits out in big endian order, though.  This requires
 * a byte swap on some platforms.
 */
uint16_t
mxfe_readsromword(mxfe_t *mxfep, unsigned romaddr)
{
	int		i;
	uint16_t	word = 0;
	uint16_t	retval;
	int		eeread;
	uint8_t		addrlen;
	int		readcmd;
	uchar_t		*ptr;

	eeread = SPR_SROM_READ | SPR_SROM_SEL | SPR_SROM_CHIP;
	addrlen = mxfep->mxfe_sromwidth;
	readcmd = (SROM_READCMD << addrlen) | romaddr;

	if (romaddr >= (1 << addrlen)) {
		/* too big to fit! */
		return (0);
	}

	PUTCSR(mxfep, CSR_SPR, eeread & ~SPR_SROM_CHIP);
	PUTCSR(mxfep, CSR_SPR, eeread);

	/* command and address bits */
	for (i = 4 + addrlen; i >= 0; i--) {
		short val = (readcmd & (1 << i)) ?  SPR_SROM_DIN : 0;
		PUTCSR(mxfep, CSR_SPR, eeread | val);
		drv_usecwait(1);
		PUTCSR(mxfep, CSR_SPR, eeread | val | SPR_SROM_CLOCK);
		drv_usecwait(1);
	}

	PUTCSR(mxfep, CSR_SPR, eeread);

	for (i = 0; i < 16; i++) {
		PUTCSR(mxfep, CSR_SPR, eeread | SPR_SROM_CLOCK);
		drv_usecwait(1);
		word <<= 1;
		if (GETCSR(mxfep, CSR_SPR) & SPR_SROM_DOUT) {
			word |= 1;
		}
		PUTCSR(mxfep, CSR_SPR, eeread);
		drv_usecwait(1);
	}

	/* turn off accesses to the EEPROM */
	PUTCSR(mxfep, CSR_SPR, eeread &~ SPR_SROM_CHIP);

	/*
	 * Fix up the endianness thing.  Note that the values
	 * are stored in little endian format on the SROM.
	 */
	DBG(DSROM, "got value %d from SROM (before swap)", word);
	ptr = (uchar_t *)&word;
	retval = (ptr[1] << 8) | ptr[0];
	return (retval);
}

void
mxfe_readsrom(mxfe_t *mxfep, unsigned romaddr, unsigned len, void *dest)
{
	char		*ptr = dest;
	int		i;
	uint16_t	word;

	for (i = 0; i < len; i++) {
		word = mxfe_readsromword(mxfep, romaddr + i);
		bcopy(&word, ptr, 2);
		ptr += 2;
		DBG(DSROM, "word at %d is 0x%x", romaddr + i, word);
	}
}

void
mxfe_getfactaddr(mxfe_t *mxfep, uchar_t *eaddr)
{
	uint16_t	word;
	uchar_t		*ptr;

	/* first read to get the location of mac address in srom */
	word = mxfe_readsromword(mxfep, SROM_ENADDR / 2);
	ptr = (uchar_t *)&word;
	word = (ptr[1] << 8) | ptr[0];

	/* then read the actual mac address */
	mxfe_readsrom(mxfep, word / 2, ETHERADDRL / 2, eaddr);
	DBG(DMACID,
	    "factory ethernet address = %02x:%02x:%02x:%02x:%02x:%02x",
	    eaddr[0], eaddr[1], eaddr[2], eaddr[3], eaddr[4], eaddr[5]);
}

void
mxfe_startphy(mxfe_t *mxfep)
{
	switch (MXFE_MODEL(mxfep)) {
	case MXFE_98713A:
		mxfe_startphymii(mxfep);
		break;
	default:
		mxfe_startphynway(mxfep);
		break;
	}
}

void
mxfe_stopphy(mxfe_t *mxfep)
{
	uint32_t	nar;
	int		i;

	/* stop the phy timer */
	PUTCSR(mxfep, CSR_TIMER, 0);

	switch (MXFE_MODEL(mxfep)) {
	case MXFE_98713A:
		for (i = 0; i < 32; i++) {
			mxfe_miiwrite(mxfep, mxfep->mxfe_phyaddr, MII_CONTROL,
			    MII_CONTROL_PWRDN | MII_CONTROL_ISOLATE);
		}
		break;
	default:
		DBG(DPHY, "resetting SIA");
		PUTCSR(mxfep, CSR_SIA, SIA_RESET);
		drv_usecwait(500);
		CLRBIT(mxfep, CSR_TCTL, TCTL_PWR | TCTL_ANE);
		nar = GETCSR(mxfep, CSR_NAR);
		nar &= ~(NAR_PORTSEL | NAR_PCS | NAR_SCR | NAR_FDX);
		nar |= NAR_SPEED;
		PUTCSR(mxfep, CSR_NAR, nar);
		break;
	}

	/*
	 * mark the link state unknown
	 */
	if (!mxfep->mxfe_resetting) {
		mxfep->mxfe_linkup = LINK_STATE_UNKNOWN;
		mxfep->mxfe_ifspeed = 0;
		mxfep->mxfe_duplex = LINK_DUPLEX_UNKNOWN;
		if (mxfep->mxfe_flags & MXFE_RUNNING)
			mxfe_reportlink(mxfep);
	}
}

/*
 * NWay support.
 */
void
mxfe_startnway(mxfe_t *mxfep)
{
	unsigned	nar;
	unsigned	tctl;
	unsigned	restart;

	/* this should not happen in a healthy system */
	if (mxfep->mxfe_nwaystate != MXFE_NOLINK) {
		DBG(DWARN, "link start called out of state (%x)",
		    mxfep->mxfe_nwaystate);
		return;
	}

	if (mxfep->mxfe_adv_aneg == 0) {
		/* not done for forced mode */
		return;
	}

	nar = GETCSR(mxfep, CSR_NAR);
	restart = nar & (NAR_TX_ENABLE | NAR_RX_ENABLE);
	nar &= ~restart;

	if (restart != 0)
		mxfe_stopmac(mxfep);

	nar |= NAR_SCR | NAR_PCS | NAR_HBD;
	nar &= ~(NAR_FDX);

	tctl = GETCSR(mxfep, CSR_TCTL);
	tctl &= ~(TCTL_100FDX | TCTL_100HDX | TCTL_HDX);

	if (mxfep->mxfe_adv_100fdx) {
		tctl |= TCTL_100FDX;
	}
	if (mxfep->mxfe_adv_100hdx) {
		tctl |= TCTL_100HDX;
	}
	if (mxfep->mxfe_adv_10fdx) {
		nar |= NAR_FDX;
	}
	if (mxfep->mxfe_adv_10hdx) {
		tctl |= TCTL_HDX;
	}
	tctl |= TCTL_PWR | TCTL_ANE | TCTL_LTE | TCTL_RSQ;

	/* possibly we should add in support for PAUSE frames */
	DBG(DPHY, "writing nar = 0x%x", nar);
	PUTCSR(mxfep, CSR_NAR, nar);

	DBG(DPHY, "writing tctl = 0x%x", tctl);
	PUTCSR(mxfep, CSR_TCTL, tctl);

	/* restart autonegotation */
	DBG(DPHY, "writing tstat = 0x%x", TSTAT_ANS_START);
	PUTCSR(mxfep, CSR_TSTAT, TSTAT_ANS_START);

	/* restart tx/rx processes... */
	if (restart != 0)
		mxfe_startmac(mxfep);

	/* Macronix initializations from Bolo Tsai */
	PUTCSR(mxfep, CSR_MXMAGIC, 0x0b2c0000);
	PUTCSR(mxfep, CSR_ACOMP, 0x11000);

	mxfep->mxfe_nwaystate = MXFE_NWAYCHECK;
}

void
mxfe_checklinknway(mxfe_t *mxfep)
{
	unsigned	tstat;
	uint16_t	lpar;

	DBG(DPHY, "NWay check, state %x", mxfep->mxfe_nwaystate);
	tstat = GETCSR(mxfep, CSR_TSTAT);
	lpar = TSTAT_LPAR(tstat);

	mxfep->mxfe_anlpar = lpar;
	if (tstat & TSTAT_LPN) {
		mxfep->mxfe_aner |= MII_AN_EXP_LPCANAN;
	} else {
		mxfep->mxfe_aner &= ~(MII_AN_EXP_LPCANAN);
	}

	DBG(DPHY, "tstat(CSR12) = 0x%x", tstat);
	DBG(DPHY, "ANEG state = 0x%x", (tstat & TSTAT_ANS) >> 12);

	if ((tstat & TSTAT_ANS) != TSTAT_ANS_OK) {
		/* autoneg did not complete */
		mxfep->mxfe_bmsr &= ~MII_STATUS_ANDONE;
	} else {
		mxfep->mxfe_bmsr |= ~MII_STATUS_ANDONE;
	}

	if ((tstat & TSTAT_100F) && (tstat & TSTAT_10F)) {
		mxfep->mxfe_linkup = LINK_STATE_DOWN;
		mxfep->mxfe_ifspeed = 0;
		mxfep->mxfe_duplex = LINK_DUPLEX_UNKNOWN;
		mxfep->mxfe_nwaystate = MXFE_NOLINK;
		mxfe_reportlink(mxfep);
		mxfe_startnway(mxfep);
		return;
	}

	/*
	 * if the link is newly up, then we might need to set various
	 * mode bits, or negotiate for parameters, etc.
	 */
	if (mxfep->mxfe_adv_aneg) {

		uint16_t	anlpar;

		mxfep->mxfe_linkup = LINK_STATE_UP;
		anlpar = mxfep->mxfe_anlpar;

		if (tstat & TSTAT_LPN) {
			/* partner has NWay */

			if ((anlpar & MII_ABILITY_100BASE_TX_FD) &&
			    mxfep->mxfe_adv_100fdx) {
				mxfep->mxfe_ifspeed = 100000000;
				mxfep->mxfe_duplex = LINK_DUPLEX_FULL;
			} else if ((anlpar & MII_ABILITY_100BASE_TX) &&
			    mxfep->mxfe_adv_100hdx) {
				mxfep->mxfe_ifspeed = 100000000;
				mxfep->mxfe_duplex = LINK_DUPLEX_HALF;
			} else if ((anlpar & MII_ABILITY_10BASE_T_FD) &&
			    mxfep->mxfe_adv_10fdx) {
				mxfep->mxfe_ifspeed = 10000000;
				mxfep->mxfe_duplex = LINK_DUPLEX_FULL;
			} else if ((anlpar & MII_ABILITY_10BASE_T) &&
			    mxfep->mxfe_adv_10hdx) {
				mxfep->mxfe_ifspeed = 10000000;
				mxfep->mxfe_duplex = LINK_DUPLEX_HALF;
			} else {
				mxfep->mxfe_ifspeed = 0;
			}
		} else {
			/* link partner does not have NWay */
			/* just assume half duplex, since we can't detect */
			mxfep->mxfe_duplex = LINK_DUPLEX_HALF;
			if (!(tstat & TSTAT_100F)) {
				DBG(DPHY, "Partner doesn't have NWAY");
				mxfep->mxfe_ifspeed = 100000000;
			} else {
				mxfep->mxfe_ifspeed = 10000000;
			}
		}
	} else {
		/* forced modes */
		mxfep->mxfe_linkup = LINK_STATE_UP;
		if (mxfep->mxfe_adv_100fdx) {
			mxfep->mxfe_ifspeed = 100000000;
			mxfep->mxfe_duplex = LINK_DUPLEX_FULL;
		} else if (mxfep->mxfe_adv_100hdx) {
			mxfep->mxfe_ifspeed = 100000000;
			mxfep->mxfe_duplex = LINK_DUPLEX_HALF;
		} else if (mxfep->mxfe_adv_10fdx) {
			mxfep->mxfe_ifspeed = 10000000;
			mxfep->mxfe_duplex = LINK_DUPLEX_FULL;
		} else if (mxfep->mxfe_adv_10hdx) {
			mxfep->mxfe_ifspeed = 10000000;
			mxfep->mxfe_duplex = LINK_DUPLEX_HALF;
		} else {
			mxfep->mxfe_ifspeed = 0;
		}
	}
	mxfe_reportlink(mxfep);
	mxfep->mxfe_nwaystate = MXFE_GOODLINK;
}

void
mxfe_startphynway(mxfe_t *mxfep)
{
	/* take NWay and PHY out of reset */
	PUTCSR(mxfep, CSR_SIA, SIA_NRESET);
	drv_usecwait(500);

	mxfep->mxfe_nwaystate = MXFE_NOLINK;
	mxfep->mxfe_bmsr = MII_STATUS_CANAUTONEG |
	    MII_STATUS_100_BASEX_FD | MII_STATUS_100_BASEX |
	    MII_STATUS_10_FD | MII_STATUS_10;
	mxfep->mxfe_cap_aneg =
	    mxfep->mxfe_cap_100fdx = mxfep->mxfe_cap_100hdx =
	    mxfep->mxfe_cap_10fdx = mxfep->mxfe_cap_10hdx = 1;

	/* lie about the transceiver... its not really 802.3u compliant */
	mxfep->mxfe_phyaddr = 0;
	mxfep->mxfe_phyinuse = XCVR_100X;
	mxfep->mxfe_phyid = 0;

	/* 100-T4 not supported with NWay */
	mxfep->mxfe_adv_100T4 = 0;
	mxfep->mxfe_cap_100T4 = 0;

	/* make sure at least one valid mode is selected */
	if ((!mxfep->mxfe_adv_100fdx) &&
	    (!mxfep->mxfe_adv_100hdx) &&
	    (!mxfep->mxfe_adv_10fdx) &&
	    (!mxfep->mxfe_adv_10hdx)) {
		mxfe_error(mxfep->mxfe_dip, "No valid link mode selected.");
		mxfe_error(mxfep->mxfe_dip, "Powering down PHY.");
		mxfe_stopphy(mxfep);
		mxfep->mxfe_linkup = LINK_STATE_DOWN;
		if (mxfep->mxfe_flags & MXFE_RUNNING)
			mxfe_reportlink(mxfep);
		return;
	}

	if (mxfep->mxfe_adv_aneg == 0) {
		/* forced mode */
		unsigned	nar;
		unsigned	tctl;

		nar = GETCSR(mxfep, CSR_NAR);
		tctl = GETCSR(mxfep, CSR_TCTL);

		ASSERT((nar & (NAR_TX_ENABLE | NAR_RX_ENABLE)) == 0);

		nar &= ~(NAR_FDX | NAR_PORTSEL | NAR_SCR | NAR_SPEED);
		tctl &= ~TCTL_ANE;
		if (mxfep->mxfe_adv_100fdx) {
			nar |= NAR_PORTSEL | NAR_PCS | NAR_SCR | NAR_FDX;
		} else if (mxfep->mxfe_adv_100hdx) {
			nar |= NAR_PORTSEL | NAR_PCS | NAR_SCR;
		} else if (mxfep->mxfe_adv_10fdx) {
			nar |= NAR_FDX | NAR_SPEED;
		} else { /* mxfep->mxfe_adv_10hdx */
			nar |= NAR_SPEED;
		}

		PUTCSR(mxfep, CSR_NAR, nar);
		PUTCSR(mxfep, CSR_TCTL, tctl);

		/* Macronix initializations from Bolo Tsai */
		PUTCSR(mxfep, CSR_MXMAGIC, 0x0b2c0000);
		PUTCSR(mxfep, CSR_ACOMP, 0x11000);
	} else {
		mxfe_startnway(mxfep);
	}
	PUTCSR(mxfep, CSR_TIMER, TIMER_LOOP |
	    (MXFE_LINKTIMER * 1000 / TIMER_USEC));
}

/*
 * MII management.
 */
void
mxfe_startphymii(mxfe_t *mxfep)
{
	unsigned	phyaddr;
	unsigned	bmcr;
	unsigned	bmsr;
	unsigned	anar;
	unsigned	phyidr1;
	unsigned	phyidr2;
	int		retries;
	int		cnt;

	mxfep->mxfe_phyaddr = -1;

	/* search for first PHY we can find */
	for (phyaddr = 0; phyaddr < 32; phyaddr++) {
		bmsr = mxfe_miiread(mxfep, phyaddr, MII_STATUS);
		if ((bmsr != 0) && (bmsr != 0xffff)) {
			mxfep->mxfe_phyaddr = phyaddr;
			break;
		}
	}

	phyidr1 = mxfe_miiread(mxfep, phyaddr, MII_PHYIDH);
	phyidr2 = mxfe_miiread(mxfep, phyaddr, MII_PHYIDL);
	mxfep->mxfe_phyid = (phyidr1 << 16) | (phyidr2);

	/*
	 * Generally, all Macronix based devices use an internal
	 * 100BASE-TX internal transceiver.  If we ever run into a
	 * variation on this, then the following logic will need to be
	 * enhanced.
	 *
	 * One could question the value of the XCVR_INUSE field in the
	 * MII statistics.
	 */
	if (bmsr & MII_STATUS_100_BASE_T4) {
		mxfep->mxfe_phyinuse = XCVR_100T4;
	} else {
		mxfep->mxfe_phyinuse = XCVR_100X;
	}

	/* assume we support everything to start */
	mxfep->mxfe_cap_aneg = mxfep->mxfe_cap_100T4 =
	    mxfep->mxfe_cap_100fdx = mxfep->mxfe_cap_100hdx =
	    mxfep->mxfe_cap_10fdx = mxfep->mxfe_cap_10hdx = 1;

	DBG(DPHY, "phy at %d: %x,%x", phyaddr, phyidr1, phyidr2);
	DBG(DPHY, "bmsr = %x", mxfe_miiread(mxfep,
	    mxfep->mxfe_phyaddr, MII_STATUS));
	DBG(DPHY, "anar = %x", mxfe_miiread(mxfep,
	    mxfep->mxfe_phyaddr, MII_AN_ADVERT));
	DBG(DPHY, "anlpar = %x", mxfe_miiread(mxfep,
	    mxfep->mxfe_phyaddr, MII_AN_LPABLE));
	DBG(DPHY, "aner = %x", mxfe_miiread(mxfep,
	    mxfep->mxfe_phyaddr, MII_AN_EXPANSION));

	DBG(DPHY, "resetting phy");

	/* we reset the phy block */
	mxfe_miiwrite(mxfep, phyaddr, MII_CONTROL, MII_CONTROL_RESET);
	/*
	 * wait for it to complete -- 500usec is still to short to
	 * bother getting the system clock involved.
	 */
	drv_usecwait(500);
	for (retries = 0; retries < 10; retries++) {
		if (mxfe_miiread(mxfep, phyaddr, MII_CONTROL) &
		    MII_CONTROL_RESET) {
			drv_usecwait(500);
			continue;
		}
		break;
	}
	if (retries == 100) {
		mxfe_error(mxfep->mxfe_dip, "timeout waiting on phy to reset");
		return;
	}

	DBG(DPHY, "phy reset complete");

	bmsr = mxfe_miiread(mxfep, phyaddr, MII_STATUS);
	bmcr = mxfe_miiread(mxfep, phyaddr, MII_CONTROL);
	anar = mxfe_miiread(mxfep, phyaddr, MII_AN_ADVERT);

	anar &= ~(MII_ABILITY_100BASE_T4 |
	    MII_ABILITY_100BASE_TX_FD | MII_ABILITY_100BASE_TX |
	    MII_ABILITY_10BASE_T_FD | MII_ABILITY_10BASE_T);

	/* disable modes not supported in hardware */
	if (!(bmsr & MII_STATUS_100_BASE_T4)) {
		mxfep->mxfe_adv_100T4 = 0;
		mxfep->mxfe_cap_100T4 = 0;
	}
	if (!(bmsr & MII_STATUS_100_BASEX_FD)) {
		mxfep->mxfe_adv_100fdx = 0;
		mxfep->mxfe_cap_100fdx = 0;
	}
	if (!(bmsr & MII_STATUS_100_BASEX)) {
		mxfep->mxfe_adv_100hdx = 0;
		mxfep->mxfe_cap_100hdx = 0;
	}
	if (!(bmsr & MII_STATUS_10_FD)) {
		mxfep->mxfe_adv_10fdx = 0;
		mxfep->mxfe_cap_10fdx = 0;
	}
	if (!(bmsr & MII_STATUS_10)) {
		mxfep->mxfe_adv_10hdx = 0;
		mxfep->mxfe_cap_10hdx = 0;
	}
	if (!(bmsr & MII_STATUS_CANAUTONEG)) {
		mxfep->mxfe_adv_aneg = 0;
		mxfep->mxfe_cap_aneg = 0;
	}

	cnt = 0;
	if (mxfep->mxfe_adv_100T4) {
		anar |= MII_ABILITY_100BASE_T4;
		cnt++;
	}
	if (mxfep->mxfe_adv_100fdx) {
		anar |= MII_ABILITY_100BASE_TX_FD;
		cnt++;
	}
	if (mxfep->mxfe_adv_100hdx) {
		anar |= MII_ABILITY_100BASE_TX;
		cnt++;
	}
	if (mxfep->mxfe_adv_10fdx) {
		anar |= MII_ABILITY_10BASE_T_FD;
		cnt++;
	}
	if (mxfep->mxfe_adv_10hdx) {
		anar |= MII_ABILITY_10BASE_T;
		cnt++;
	}

	/*
	 * Make certain at least one valid link mode is selected.
	 */
	if (!cnt) {
		mxfe_error(mxfep->mxfe_dip, "No valid link mode selected.");
		mxfe_error(mxfep->mxfe_dip, "Powering down PHY.");
		mxfe_stopphy(mxfep);
		mxfep->mxfe_linkup = LINK_STATE_DOWN;
		if (mxfep->mxfe_flags & MXFE_RUNNING)
			mxfe_reportlink(mxfep);
		return;
	}

	if ((mxfep->mxfe_adv_aneg) && (bmsr & MII_STATUS_CANAUTONEG)) {
		DBG(DPHY, "using autoneg mode");
		bmcr = (MII_CONTROL_ANE | MII_CONTROL_RSAN);
	} else {
		DBG(DPHY, "using forced mode");
		if (mxfep->mxfe_adv_100fdx) {
			bmcr = (MII_CONTROL_100MB | MII_CONTROL_FDUPLEX);
		} else if (mxfep->mxfe_adv_100hdx) {
			bmcr = MII_CONTROL_100MB;
		} else if (mxfep->mxfe_adv_10fdx) {
			bmcr = MII_CONTROL_FDUPLEX;
		} else {
			/* 10HDX */
			bmcr = 0;
		}
	}

	DBG(DPHY, "programming anar to 0x%x", anar);
	mxfe_miiwrite(mxfep, phyaddr, MII_AN_ADVERT, anar);
	DBG(DPHY, "programming bmcr to 0x%x", bmcr);
	mxfe_miiwrite(mxfep, phyaddr, MII_CONTROL, bmcr);

	/*
	 * schedule a query of the link status
	 */
	PUTCSR(mxfep, CSR_TIMER, TIMER_LOOP |
	    (MXFE_LINKTIMER * 1000 / TIMER_USEC));
}

void
mxfe_reportlink(mxfe_t *mxfep)
{
	int changed = 0;

	if (mxfep->mxfe_ifspeed != mxfep->mxfe_lastifspeed) {
		mxfep->mxfe_lastifspeed = mxfep->mxfe_ifspeed;
		changed++;
	}
	if (mxfep->mxfe_duplex != mxfep->mxfe_lastduplex) {
		mxfep->mxfe_lastduplex = mxfep->mxfe_duplex;
		changed++;
	}
	if (mxfep->mxfe_linkup != mxfep->mxfe_lastlinkup) {
		mxfep->mxfe_lastlinkup = mxfep->mxfe_linkup;
		changed++;
	}
	if (changed)
		mac_link_update(mxfep->mxfe_mh, mxfep->mxfe_linkup);
}

void
mxfe_checklink(mxfe_t *mxfep)
{
	if ((mxfep->mxfe_flags & MXFE_RUNNING) == 0)
		return;

	if ((mxfep->mxfe_txstall_time != 0) &&
	    (gethrtime() > mxfep->mxfe_txstall_time) &&
	    (mxfep->mxfe_txavail != MXFE_TXRING)) {
		mxfep->mxfe_txstall_time = 0;
		mxfe_error(mxfep->mxfe_dip, "TX stall detected!");
		mxfe_resetall(mxfep);
		return;
	}

	switch (MXFE_MODEL(mxfep)) {
	case MXFE_98713A:
		mxfe_checklinkmii(mxfep);
		break;
	default:
		mxfe_checklinknway(mxfep);
	}
}

void
mxfe_checklinkmii(mxfe_t *mxfep)
{
	/* read MII state registers */
	uint16_t	bmsr;
	uint16_t	bmcr;
	uint16_t	anar;
	uint16_t	anlpar;
	uint16_t	aner;

	/* read this twice, to clear latched link state */
	bmsr = mxfe_miiread(mxfep, mxfep->mxfe_phyaddr, MII_STATUS);
	bmsr = mxfe_miiread(mxfep, mxfep->mxfe_phyaddr, MII_STATUS);
	bmcr = mxfe_miiread(mxfep, mxfep->mxfe_phyaddr, MII_CONTROL);
	anar = mxfe_miiread(mxfep, mxfep->mxfe_phyaddr, MII_AN_ADVERT);
	anlpar = mxfe_miiread(mxfep, mxfep->mxfe_phyaddr, MII_AN_LPABLE);
	aner = mxfe_miiread(mxfep, mxfep->mxfe_phyaddr, MII_AN_EXPANSION);

	mxfep->mxfe_bmsr = bmsr;
	mxfep->mxfe_anlpar = anlpar;
	mxfep->mxfe_aner = aner;

	if (bmsr & MII_STATUS_REMFAULT) {
		mxfe_error(mxfep->mxfe_dip, "Remote fault detected.");
	}
	if (bmsr & MII_STATUS_JABBERING) {
		mxfe_error(mxfep->mxfe_dip, "Jabber condition detected.");
	}
	if ((bmsr & MII_STATUS_LINKUP) == 0) {
		/* no link */
		mxfep->mxfe_ifspeed = 0;
		mxfep->mxfe_duplex = LINK_DUPLEX_UNKNOWN;
		mxfep->mxfe_linkup = LINK_STATE_DOWN;
		mxfe_reportlink(mxfep);
		return;
	}

	DBG(DCHATTY, "link up!");
	mxfep->mxfe_linkup = LINK_STATE_UP;

	if (!(bmcr & MII_CONTROL_ANE)) {
		/* forced mode */
		if (bmcr & MII_CONTROL_100MB) {
			mxfep->mxfe_ifspeed = 100000000;
		} else {
			mxfep->mxfe_ifspeed = 10000000;
		}
		if (bmcr & MII_CONTROL_FDUPLEX) {
			mxfep->mxfe_duplex = LINK_DUPLEX_FULL;
		} else {
			mxfep->mxfe_duplex = LINK_DUPLEX_HALF;
		}
	} else if ((!(bmsr & MII_STATUS_CANAUTONEG)) ||
	    (!(bmsr & MII_STATUS_ANDONE))) {
		mxfep->mxfe_ifspeed = 0;
		mxfep->mxfe_duplex = LINK_DUPLEX_UNKNOWN;
	} else if (anar & anlpar & MII_ABILITY_100BASE_TX_FD) {
		mxfep->mxfe_ifspeed = 100000000;
		mxfep->mxfe_duplex = LINK_DUPLEX_FULL;
	} else if (anar & anlpar & MII_ABILITY_100BASE_T4) {
		mxfep->mxfe_ifspeed = 100000000;
		mxfep->mxfe_duplex = LINK_DUPLEX_HALF;
	} else if (anar & anlpar & MII_ABILITY_100BASE_TX) {
		mxfep->mxfe_ifspeed = 100000000;
		mxfep->mxfe_duplex = LINK_DUPLEX_HALF;
	} else if (anar & anlpar & MII_ABILITY_10BASE_T_FD) {
		mxfep->mxfe_ifspeed = 10000000;
		mxfep->mxfe_duplex = LINK_DUPLEX_FULL;
	} else if (anar & anlpar & MII_ABILITY_10BASE_T) {
		mxfep->mxfe_ifspeed = 10000000;
		mxfep->mxfe_duplex = LINK_DUPLEX_HALF;
	} else {
		mxfep->mxfe_ifspeed = 0;
		mxfep->mxfe_duplex = LINK_DUPLEX_UNKNOWN;
	}

	mxfe_reportlink(mxfep);
}

void
mxfe_miitristate(mxfe_t *mxfep)
{
	unsigned val = SPR_SROM_WRITE | SPR_MII_CTRL;
	PUTCSR(mxfep, CSR_SPR, val);
	drv_usecwait(1);
	PUTCSR(mxfep, CSR_SPR, val | SPR_MII_CLOCK);
	drv_usecwait(1);
}

void
mxfe_miiwritebit(mxfe_t *mxfep, uint8_t bit)
{
	unsigned val = bit ? SPR_MII_DOUT : 0;
	PUTCSR(mxfep, CSR_SPR, val);
	drv_usecwait(1);
	PUTCSR(mxfep, CSR_SPR, val | SPR_MII_CLOCK);
	drv_usecwait(1);
}

uint8_t
mxfe_miireadbit(mxfe_t *mxfep)
{
	unsigned val = SPR_MII_CTRL | SPR_SROM_READ;
	uint8_t bit;
	PUTCSR(mxfep, CSR_SPR, val);
	drv_usecwait(1);
	bit = (GETCSR(mxfep, CSR_SPR) & SPR_MII_DIN) ? 1 : 0;
	PUTCSR(mxfep, CSR_SPR, val | SPR_MII_CLOCK);
	drv_usecwait(1);
	return (bit);
}

uint16_t
mxfe_miiread(mxfe_t *mxfep, int phy, int reg)
{
	switch (MXFE_MODEL(mxfep)) {
	case MXFE_98713A:
		return (mxfe_miiread98713(mxfep, phy, reg));
	default:
		return (0xffff);
	}
}

uint16_t
mxfe_miireadgeneral(mxfe_t *mxfep, int phy, int reg)
{
	uint16_t	value = 0;
	int		i;

	/* send the 32 bit preamble */
	for (i = 0; i < 32; i++) {
		mxfe_miiwritebit(mxfep, 1);
	}

	/* send the start code - 01b */
	mxfe_miiwritebit(mxfep, 0);
	mxfe_miiwritebit(mxfep, 1);

	/* send the opcode for read, - 10b */
	mxfe_miiwritebit(mxfep, 1);
	mxfe_miiwritebit(mxfep, 0);

	/* next we send the 5 bit phy address */
	for (i = 0x10; i > 0; i >>= 1) {
		mxfe_miiwritebit(mxfep, (phy & i) ? 1 : 0);
	}

	/* the 5 bit register address goes next */
	for (i = 0x10; i > 0; i >>= 1) {
		mxfe_miiwritebit(mxfep, (reg & i) ? 1 : 0);
	}

	/* turnaround - tristate followed by logic 0 */
	mxfe_miitristate(mxfep);
	mxfe_miiwritebit(mxfep, 0);

	/* read the 16 bit register value */
	for (i = 0x8000; i > 0; i >>= 1) {
		value <<= 1;
		value |= mxfe_miireadbit(mxfep);
	}
	mxfe_miitristate(mxfep);
	return (value);
}

uint16_t
mxfe_miiread98713(mxfe_t *mxfep, int phy, int reg)
{
	unsigned nar;
	uint16_t retval;
	/*
	 * like an ordinary MII, but we have to turn off portsel while
	 * we read it.
	 */
	nar = GETCSR(mxfep, CSR_NAR);
	PUTCSR(mxfep, CSR_NAR, nar & ~NAR_PORTSEL);
	retval = mxfe_miireadgeneral(mxfep, phy, reg);
	PUTCSR(mxfep, CSR_NAR, nar);
	return (retval);
}

void
mxfe_miiwrite(mxfe_t *mxfep, int phy, int reg, uint16_t val)
{
	switch (MXFE_MODEL(mxfep)) {
	case MXFE_98713A:
		mxfe_miiwrite98713(mxfep, phy, reg, val);
		break;
	default:
		break;
	}
}

void
mxfe_miiwritegeneral(mxfe_t *mxfep, int phy, int reg, uint16_t val)
{
	int i;

	/* send the 32 bit preamble */
	for (i = 0; i < 32; i++) {
		mxfe_miiwritebit(mxfep, 1);
	}

	/* send the start code - 01b */
	mxfe_miiwritebit(mxfep, 0);
	mxfe_miiwritebit(mxfep, 1);

	/* send the opcode for write, - 01b */
	mxfe_miiwritebit(mxfep, 0);
	mxfe_miiwritebit(mxfep, 1);

	/* next we send the 5 bit phy address */
	for (i = 0x10; i > 0; i >>= 1) {
		mxfe_miiwritebit(mxfep, (phy & i) ? 1 : 0);
	}

	/* the 5 bit register address goes next */
	for (i = 0x10; i > 0; i >>= 1) {
		mxfe_miiwritebit(mxfep, (reg & i) ? 1 : 0);
	}

	/* turnaround - tristate followed by logic 0 */
	mxfe_miitristate(mxfep);
	mxfe_miiwritebit(mxfep, 0);

	/* now write out our data (16 bits) */
	for (i = 0x8000; i > 0; i >>= 1) {
		mxfe_miiwritebit(mxfep, (val & i) ? 1 : 0);
	}

	/* idle mode */
	mxfe_miitristate(mxfep);
}

void
mxfe_miiwrite98713(mxfe_t *mxfep, int phy, int reg, uint16_t val)
{
	unsigned nar;
	/*
	 * like an ordinary MII, but we have to turn off portsel while
	 * we read it.
	 */
	nar = GETCSR(mxfep, CSR_NAR);
	PUTCSR(mxfep, CSR_NAR, nar & ~NAR_PORTSEL);
	mxfe_miiwritegeneral(mxfep, phy, reg, val);
	PUTCSR(mxfep, CSR_NAR, nar);
}

int
mxfe_m_start(void *arg)
{
	mxfe_t	*mxfep = arg;

	/* grab exclusive access to the card */
	mutex_enter(&mxfep->mxfe_intrlock);
	mutex_enter(&mxfep->mxfe_xmtlock);

	mxfe_startall(mxfep);
	mxfep->mxfe_flags |= MXFE_RUNNING;

	mutex_exit(&mxfep->mxfe_xmtlock);
	mutex_exit(&mxfep->mxfe_intrlock);
	return (0);
}

void
mxfe_m_stop(void *arg)
{
	mxfe_t	*mxfep = arg;

	/* exclusive access to the hardware! */
	mutex_enter(&mxfep->mxfe_intrlock);
	mutex_enter(&mxfep->mxfe_xmtlock);

	mxfe_stopall(mxfep);
	mxfep->mxfe_flags &= ~MXFE_RUNNING;

	mutex_exit(&mxfep->mxfe_xmtlock);
	mutex_exit(&mxfep->mxfe_intrlock);
}

void
mxfe_startmac(mxfe_t *mxfep)
{
	/* verify exclusive access to the card */
	ASSERT(mutex_owned(&mxfep->mxfe_intrlock));
	ASSERT(mutex_owned(&mxfep->mxfe_xmtlock));

	/* start the card */
	SETBIT(mxfep, CSR_NAR, NAR_TX_ENABLE | NAR_RX_ENABLE);

	if (mxfep->mxfe_txavail != MXFE_TXRING)
		PUTCSR(mxfep, CSR_TDR, 0);

	/* tell the mac that we are ready to go! */
	if (mxfep->mxfe_flags & MXFE_RUNNING)
		mac_tx_update(mxfep->mxfe_mh);
}

void
mxfe_stopmac(mxfe_t *mxfep)
{
	int		i;

	/* exclusive access to the hardware! */
	ASSERT(mutex_owned(&mxfep->mxfe_intrlock));
	ASSERT(mutex_owned(&mxfep->mxfe_xmtlock));

	CLRBIT(mxfep, CSR_NAR, NAR_TX_ENABLE | NAR_RX_ENABLE);

	/*
	 * A 1518 byte frame at 10Mbps takes about 1.2 msec to drain.
	 * We just add up to the nearest msec (2), which should be
	 * plenty to complete.
	 *
	 * Note that some chips never seem to indicate the transition to
	 * the stopped state properly.  Experience shows that we can safely
	 * proceed anyway, after waiting the requisite timeout.
	 */
	for (i = 2000; i != 0; i -= 10) {
		if ((GETCSR(mxfep, CSR_SR) & (SR_TX_STATE | SR_RX_STATE)) == 0)
			break;
		drv_usecwait(10);
	}

	/* prevent an interrupt */
	PUTCSR(mxfep, CSR_SR, INT_RXSTOPPED | INT_TXSTOPPED);
}

void
mxfe_resetrings(mxfe_t *mxfep)
{
	int	i;

	/* now we need to reset the pointers... */
	PUTCSR(mxfep, CSR_RDB, 0);
	PUTCSR(mxfep, CSR_TDB, 0);

	/* reset the descriptor ring pointers */
	mxfep->mxfe_rxhead = 0;
	mxfep->mxfe_txreclaim = 0;
	mxfep->mxfe_txsend = 0;
	mxfep->mxfe_txavail = MXFE_TXRING;

	/* set up transmit descriptor ring */
	for (i = 0; i < MXFE_TXRING; i++) {
		mxfe_desc_t	*tmdp = &mxfep->mxfe_txdescp[i];
		unsigned	control = 0;
		if (i == (MXFE_TXRING - 1)) {
			control |= TXCTL_ENDRING;
		}
		PUTTXDESC(mxfep, tmdp->desc_status, 0);
		PUTTXDESC(mxfep, tmdp->desc_control, control);
		PUTTXDESC(mxfep, tmdp->desc_buffer1, 0);
		PUTTXDESC(mxfep, tmdp->desc_buffer2, 0);
		SYNCTXDESC(mxfep, i, DDI_DMA_SYNC_FORDEV);
	}
	PUTCSR(mxfep, CSR_TDB, mxfep->mxfe_txdesc_paddr);

	/* make the receive buffers available */
	for (i = 0; i < MXFE_RXRING; i++) {
		mxfe_rxbuf_t	*rxb = mxfep->mxfe_rxbufs[i];
		mxfe_desc_t	*rmdp = &mxfep->mxfe_rxdescp[i];
		unsigned	control;

		control = MXFE_BUFSZ & RXCTL_BUFLEN1;
		if (i == (MXFE_RXRING - 1)) {
			control |= RXCTL_ENDRING;
		}
		PUTRXDESC(mxfep, rmdp->desc_buffer1, rxb->rxb_paddr);
		PUTRXDESC(mxfep, rmdp->desc_buffer2, 0);
		PUTRXDESC(mxfep, rmdp->desc_control, control);
		PUTRXDESC(mxfep, rmdp->desc_status, RXSTAT_OWN);
		SYNCRXDESC(mxfep, i, DDI_DMA_SYNC_FORDEV);
	}
	PUTCSR(mxfep, CSR_RDB, mxfep->mxfe_rxdesc_paddr);
}

void
mxfe_stopall(mxfe_t *mxfep)
{
	mxfe_disableinterrupts(mxfep);

	mxfe_stopmac(mxfep);

	/* stop the phy */
	mxfe_stopphy(mxfep);
}

void
mxfe_startall(mxfe_t *mxfep)
{
	ASSERT(mutex_owned(&mxfep->mxfe_intrlock));
	ASSERT(mutex_owned(&mxfep->mxfe_xmtlock));

	/* make sure interrupts are disabled to begin */
	mxfe_disableinterrupts(mxfep);

	/* initialize the chip */
	(void) mxfe_initialize(mxfep);

	/* now we can enable interrupts */
	mxfe_enableinterrupts(mxfep);

	/* start up the phy */
	mxfe_startphy(mxfep);

	/* start up the mac */
	mxfe_startmac(mxfep);
}

void
mxfe_resetall(mxfe_t *mxfep)
{
	mxfep->mxfe_resetting = B_TRUE;
	mxfe_stopall(mxfep);
	mxfep->mxfe_resetting = B_FALSE;
	mxfe_startall(mxfep);
}

mxfe_txbuf_t *
mxfe_alloctxbuf(mxfe_t *mxfep)
{
	ddi_dma_cookie_t	dmac;
	unsigned		ncookies;
	mxfe_txbuf_t		*txb;
	size_t			len;

	txb = kmem_zalloc(sizeof (*txb), KM_SLEEP);

	if (ddi_dma_alloc_handle(mxfep->mxfe_dip, &mxfe_dma_txattr,
	    DDI_DMA_SLEEP, NULL, &txb->txb_dmah) != DDI_SUCCESS) {
		return (NULL);
	}

	if (ddi_dma_mem_alloc(txb->txb_dmah, MXFE_BUFSZ, &mxfe_bufattr,
	    DDI_DMA_STREAMING, DDI_DMA_SLEEP, NULL, &txb->txb_buf,
	    &len, &txb->txb_acch) != DDI_SUCCESS) {
		return (NULL);
	}
	if (ddi_dma_addr_bind_handle(txb->txb_dmah, NULL, txb->txb_buf,
	    len, DDI_DMA_WRITE | DDI_DMA_STREAMING, DDI_DMA_SLEEP, NULL,
	    &dmac, &ncookies) != DDI_DMA_MAPPED) {
		return (NULL);
	}
	txb->txb_paddr = dmac.dmac_address;

	return (txb);
}

void
mxfe_destroytxbuf(mxfe_txbuf_t *txb)
{
	if (txb != NULL) {
		if (txb->txb_paddr)
			(void) ddi_dma_unbind_handle(txb->txb_dmah);
		if (txb->txb_acch)
			ddi_dma_mem_free(&txb->txb_acch);
		if (txb->txb_dmah)
			ddi_dma_free_handle(&txb->txb_dmah);
		kmem_free(txb, sizeof (*txb));
	}
}

mxfe_rxbuf_t *
mxfe_allocrxbuf(mxfe_t *mxfep)
{
	mxfe_rxbuf_t		*rxb;
	size_t			len;
	unsigned		ccnt;
	ddi_dma_cookie_t	dmac;

	rxb = kmem_zalloc(sizeof (*rxb), KM_SLEEP);

	if (ddi_dma_alloc_handle(mxfep->mxfe_dip, &mxfe_dma_attr,
	    DDI_DMA_SLEEP, NULL, &rxb->rxb_dmah) != DDI_SUCCESS) {
		kmem_free(rxb, sizeof (*rxb));
		return (NULL);
	}
	if (ddi_dma_mem_alloc(rxb->rxb_dmah, MXFE_BUFSZ, &mxfe_bufattr,
	    DDI_DMA_STREAMING, DDI_DMA_SLEEP, NULL,
	    &rxb->rxb_buf, &len, &rxb->rxb_acch) != DDI_SUCCESS) {
		ddi_dma_free_handle(&rxb->rxb_dmah);
		kmem_free(rxb, sizeof (*rxb));
		return (NULL);
	}
	if (ddi_dma_addr_bind_handle(rxb->rxb_dmah, NULL, rxb->rxb_buf, len,
	    DDI_DMA_READ | DDI_DMA_STREAMING, DDI_DMA_SLEEP, NULL, &dmac,
	    &ccnt) != DDI_DMA_MAPPED) {
		ddi_dma_mem_free(&rxb->rxb_acch);
		ddi_dma_free_handle(&rxb->rxb_dmah);
		kmem_free(rxb, sizeof (*rxb));
		return (NULL);
	}
	rxb->rxb_paddr = dmac.dmac_address;

	return (rxb);
}

void
mxfe_destroyrxbuf(mxfe_rxbuf_t *rxb)
{
	if (rxb != NULL) {
		(void) ddi_dma_unbind_handle(rxb->rxb_dmah);
		ddi_dma_mem_free(&rxb->rxb_acch);
		ddi_dma_free_handle(&rxb->rxb_dmah);
		kmem_free(rxb, sizeof (*rxb));
	}
}

/*
 * Allocate receive resources.
 */
int
mxfe_allocrxring(mxfe_t *mxfep)
{
	int			rval;
	int			i;
	size_t			size;
	size_t			len;
	ddi_dma_cookie_t	dmac;
	unsigned		ncookies;
	caddr_t			kaddr;

	size = MXFE_RXRING * sizeof (mxfe_desc_t);

	rval = ddi_dma_alloc_handle(mxfep->mxfe_dip, &mxfe_dma_attr,
	    DDI_DMA_SLEEP, NULL, &mxfep->mxfe_rxdesc_dmah);
	if (rval != DDI_SUCCESS) {
		mxfe_error(mxfep->mxfe_dip,
		    "unable to allocate DMA handle for rx descriptors");
		return (DDI_FAILURE);
	}

	rval = ddi_dma_mem_alloc(mxfep->mxfe_rxdesc_dmah, size, &mxfe_devattr,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL, &kaddr, &len,
	    &mxfep->mxfe_rxdesc_acch);
	if (rval != DDI_SUCCESS) {
		mxfe_error(mxfep->mxfe_dip,
		    "unable to allocate DMA memory for rx descriptors");
		return (DDI_FAILURE);
	}

	rval = ddi_dma_addr_bind_handle(mxfep->mxfe_rxdesc_dmah, NULL, kaddr,
	    size, DDI_DMA_RDWR | DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    &dmac, &ncookies);
	if (rval != DDI_DMA_MAPPED) {
		mxfe_error(mxfep->mxfe_dip,
		    "unable to bind DMA for rx descriptors");
		return (DDI_FAILURE);
	}

	/* because of mxfe_dma_attr */
	ASSERT(ncookies == 1);

	/* we take the 32-bit physical address out of the cookie */
	mxfep->mxfe_rxdesc_paddr = dmac.dmac_address;
	mxfep->mxfe_rxdescp = (void *)kaddr;

	/* allocate buffer pointers (not the buffers themselves, yet) */
	mxfep->mxfe_rxbufs = kmem_zalloc(MXFE_RXRING * sizeof (mxfe_rxbuf_t *),
	    KM_SLEEP);

	/* now allocate rx buffers */
	for (i = 0; i < MXFE_RXRING; i++) {
		mxfe_rxbuf_t *rxb = mxfe_allocrxbuf(mxfep);
		if (rxb == NULL)
			return (DDI_FAILURE);
		mxfep->mxfe_rxbufs[i] = rxb;
	}

	return (DDI_SUCCESS);
}

/*
 * Allocate transmit resources.
 */
int
mxfe_alloctxring(mxfe_t *mxfep)
{
	int			rval;
	int			i;
	size_t			size;
	size_t			len;
	ddi_dma_cookie_t	dmac;
	unsigned		ncookies;
	caddr_t			kaddr;

	size = MXFE_TXRING * sizeof (mxfe_desc_t);

	rval = ddi_dma_alloc_handle(mxfep->mxfe_dip, &mxfe_dma_attr,
	    DDI_DMA_SLEEP, NULL, &mxfep->mxfe_txdesc_dmah);
	if (rval != DDI_SUCCESS) {
		mxfe_error(mxfep->mxfe_dip,
		    "unable to allocate DMA handle for tx descriptors");
		return (DDI_FAILURE);
	}

	rval = ddi_dma_mem_alloc(mxfep->mxfe_txdesc_dmah, size, &mxfe_devattr,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL, &kaddr, &len,
	    &mxfep->mxfe_txdesc_acch);
	if (rval != DDI_SUCCESS) {
		mxfe_error(mxfep->mxfe_dip,
		    "unable to allocate DMA memory for tx descriptors");
		return (DDI_FAILURE);
	}

	rval = ddi_dma_addr_bind_handle(mxfep->mxfe_txdesc_dmah, NULL, kaddr,
	    size, DDI_DMA_RDWR | DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    &dmac, &ncookies);
	if (rval != DDI_DMA_MAPPED) {
		mxfe_error(mxfep->mxfe_dip,
		    "unable to bind DMA for tx descriptors");
		return (DDI_FAILURE);
	}

	/* because of mxfe_dma_attr */
	ASSERT(ncookies == 1);

	/* we take the 32-bit physical address out of the cookie */
	mxfep->mxfe_txdesc_paddr = dmac.dmac_address;
	mxfep->mxfe_txdescp = (void *)kaddr;

	/* allocate buffer pointers (not the buffers themselves, yet) */
	mxfep->mxfe_txbufs = kmem_zalloc(MXFE_TXRING * sizeof (mxfe_txbuf_t *),
	    KM_SLEEP);

	/* now allocate tx buffers */
	for (i = 0; i < MXFE_TXRING; i++) {
		mxfe_txbuf_t *txb = mxfe_alloctxbuf(mxfep);
		if (txb == NULL)
			return (DDI_FAILURE);
		/* stick it in the stack */
		mxfep->mxfe_txbufs[i] = txb;
	}

	return (DDI_SUCCESS);
}

void
mxfe_freerxring(mxfe_t *mxfep)
{
	int		i;

	if (mxfep->mxfe_rxbufs) {
		for (i = 0; i < MXFE_RXRING; i++) {
			mxfe_destroyrxbuf(mxfep->mxfe_rxbufs[i]);
		}

		kmem_free(mxfep->mxfe_rxbufs,
		    MXFE_RXRING * sizeof (mxfe_rxbuf_t *));
	}

	if (mxfep->mxfe_rxdesc_paddr)
		(void) ddi_dma_unbind_handle(mxfep->mxfe_rxdesc_dmah);
	if (mxfep->mxfe_rxdesc_acch)
		ddi_dma_mem_free(&mxfep->mxfe_rxdesc_acch);
	if (mxfep->mxfe_rxdesc_dmah)
		ddi_dma_free_handle(&mxfep->mxfe_rxdesc_dmah);
}

void
mxfe_freetxring(mxfe_t *mxfep)
{
	int			i;

	if (mxfep->mxfe_txbufs) {
		for (i = 0; i < MXFE_TXRING; i++) {
			mxfe_destroytxbuf(mxfep->mxfe_txbufs[i]);
		}

		kmem_free(mxfep->mxfe_txbufs,
		    MXFE_TXRING * sizeof (mxfe_txbuf_t *));
	}
	if (mxfep->mxfe_txdesc_paddr)
		(void) ddi_dma_unbind_handle(mxfep->mxfe_txdesc_dmah);
	if (mxfep->mxfe_txdesc_acch)
		ddi_dma_mem_free(&mxfep->mxfe_txdesc_acch);
	if (mxfep->mxfe_txdesc_dmah)
		ddi_dma_free_handle(&mxfep->mxfe_txdesc_dmah);
}

/*
 * Interrupt service routine.
 */
unsigned
mxfe_intr(caddr_t arg)
{
	mxfe_t		*mxfep = (void *)arg;
	uint32_t	status;
	mblk_t		*mp = NULL;
	boolean_t	error = B_FALSE;

	mutex_enter(&mxfep->mxfe_intrlock);

	if (mxfep->mxfe_flags & MXFE_SUSPENDED) {
		/* we cannot receive interrupts! */
		mutex_exit(&mxfep->mxfe_intrlock);
		return (DDI_INTR_UNCLAIMED);
	}

	/* check interrupt status bits, did we interrupt? */
	status = GETCSR(mxfep, CSR_SR) & INT_ALL;

	if (status == 0) {
		KIOIP->intrs[KSTAT_INTR_SPURIOUS]++;
		mutex_exit(&mxfep->mxfe_intrlock);
		return (DDI_INTR_UNCLAIMED);
	}
	/* ack the interrupt */
	PUTCSR(mxfep, CSR_SR, status);
	KIOIP->intrs[KSTAT_INTR_HARD]++;

	if (!(mxfep->mxfe_flags & MXFE_RUNNING)) {
		/* not running, don't touch anything */
		mutex_exit(&mxfep->mxfe_intrlock);
		return (DDI_INTR_CLAIMED);
	}

	if (status & INT_RXOK) {
		/* receive packets */
		if (mxfe_receive(mxfep, &mp)) {
			error = B_TRUE;
		}
	}

	if (status & INT_TXOK) {
		/* transmit completed */
		mutex_enter(&mxfep->mxfe_xmtlock);
		mxfe_reclaim(mxfep);
		mutex_exit(&mxfep->mxfe_xmtlock);
	}

	if (((status & (INT_TIMER|INT_ANEG)) != 0) ||
	    ((mxfep->mxfe_linkup == LINK_STATE_UP) &&
	    ((status & (INT_10LINK|INT_100LINK)) != 0))) {
		/* rescan the link */
		mutex_enter(&mxfep->mxfe_xmtlock);
		mxfe_checklink(mxfep);
		mutex_exit(&mxfep->mxfe_xmtlock);
	}

	if (status & (INT_RXSTOPPED|INT_TXSTOPPED|INT_RXNOBUF|
	    INT_RXJABBER|INT_TXJABBER|INT_TXUNDERFLOW)) {

		if (status & (INT_RXJABBER | INT_TXJABBER)) {
			mxfep->mxfe_jabber++;
		}
		DBG(DWARN, "error interrupt: status %x", status);
		error = B_TRUE;
	}

	if (status & INT_BUSERR) {
		switch (status & SR_BERR_TYPE) {
		case SR_BERR_PARITY:
			mxfe_error(mxfep->mxfe_dip, "PCI parity error");
			break;
		case SR_BERR_TARGET_ABORT:
			mxfe_error(mxfep->mxfe_dip, "PCI target abort");
			break;
		case SR_BERR_MASTER_ABORT:
			mxfe_error(mxfep->mxfe_dip, "PCI master abort");
			break;
		default:
			mxfe_error(mxfep->mxfe_dip, "Unknown PCI error");
			break;
		}

		error = B_TRUE;
	}

	if (error) {
		/* reset the chip in an attempt to fix things */
		mutex_enter(&mxfep->mxfe_xmtlock);
		mxfe_resetall(mxfep);
		mutex_exit(&mxfep->mxfe_xmtlock);
	}

	mutex_exit(&mxfep->mxfe_intrlock);

	/*
	 * Send up packets.  We do this outside of the intrlock.
	 */
	if (mp) {
		mac_rx(mxfep->mxfe_mh, NULL, mp);
	}

	return (DDI_INTR_CLAIMED);
}

void
mxfe_enableinterrupts(mxfe_t *mxfep)
{
	unsigned mask = INT_WANTED;

	if (mxfep->mxfe_wantw)
		mask |= INT_TXOK;

	if (MXFE_MODEL(mxfep) != MXFE_98713A)
		mask |= INT_LINKSTATUS;

	DBG(DINTR, "setting int mask to 0x%x", mask);
	PUTCSR(mxfep, CSR_IER, mask);
}

void
mxfe_disableinterrupts(mxfe_t *mxfep)
{
	/* disable further interrupts */
	PUTCSR(mxfep, CSR_IER, 0);

	/* clear any pending interrupts */
	PUTCSR(mxfep, CSR_SR, INT_ALL);
}

void
mxfe_send_setup(mxfe_t *mxfep)
{
	mxfe_txbuf_t	*txb;
	mxfe_desc_t	*tmdp;

	ASSERT(mutex_owned(&mxfep->mxfe_xmtlock));

	/* setup frame -- must be at head of list -- guaranteed by caller! */
	ASSERT(mxfep->mxfe_txsend == 0);

	txb = mxfep->mxfe_txbufs[0];
	tmdp = &mxfep->mxfe_txdescp[0];

	bzero(txb->txb_buf, MXFE_SETUP_LEN);

	/* program the unicast address */
	txb->txb_buf[156] = mxfep->mxfe_curraddr[0];
	txb->txb_buf[157] = mxfep->mxfe_curraddr[1];
	txb->txb_buf[160] = mxfep->mxfe_curraddr[2];
	txb->txb_buf[161] = mxfep->mxfe_curraddr[3];
	txb->txb_buf[164] = mxfep->mxfe_curraddr[4];
	txb->txb_buf[165] = mxfep->mxfe_curraddr[5];

	/* make sure that the hardware can see it */
	SYNCTXBUF(txb, MXFE_SETUP_LEN, DDI_DMA_SYNC_FORDEV);

	PUTTXDESC(mxfep, tmdp->desc_control,
	    TXCTL_FIRST | TXCTL_LAST | TXCTL_INTCMPLTE | TXCTL_HASHPERF |
	    TXCTL_SETUP | MXFE_SETUP_LEN);

	PUTTXDESC(mxfep, tmdp->desc_buffer1, txb->txb_paddr);
	PUTTXDESC(mxfep, tmdp->desc_buffer2, 0);
	PUTTXDESC(mxfep, tmdp->desc_status, TXSTAT_OWN);

	/* sync the descriptor out to the device */
	SYNCTXDESC(mxfep, 0, DDI_DMA_SYNC_FORDEV);

	/*
	 * wake up the chip ... inside the lock to protect against DR suspend,
	 * etc.
	 */
	PUTCSR(mxfep, CSR_TDR, 0);
	mxfep->mxfe_txsend++;
	mxfep->mxfe_txavail--;

	/*
	 * Program promiscuous mode.
	 */
	if (mxfep->mxfe_promisc) {
		SETBIT(mxfep, CSR_NAR, NAR_RX_PROMISC);
	} else {
		CLRBIT(mxfep, CSR_NAR, NAR_RX_PROMISC);
	}
}

boolean_t
mxfe_send(mxfe_t *mxfep, mblk_t *mp)
{
	size_t			len;
	mxfe_txbuf_t		*txb;
	mxfe_desc_t		*tmd;
	uint32_t		control;
	int			txsend;

	ASSERT(mutex_owned(&mxfep->mxfe_xmtlock));
	ASSERT(mp != NULL);

	len = msgsize(mp);
	if (len > ETHERVLANMTU) {
		DBG(DXMIT, "frame too long: %d", len);
		mxfep->mxfe_macxmt_errors++;
		freemsg(mp);
		return (B_TRUE);
	}

	if (mxfep->mxfe_txavail < MXFE_TXRECLAIM)
		mxfe_reclaim(mxfep);

	if (mxfep->mxfe_txavail == 0) {
		/* no more tmds */
		mxfep->mxfe_wantw = B_TRUE;
		/* enable TX interrupt */
		mxfe_enableinterrupts(mxfep);
		return (B_FALSE);
	}

	txsend = mxfep->mxfe_txsend;

	/*
	 * For simplicity, we just do a copy into a preallocated
	 * DMA buffer.
	 */

	txb = mxfep->mxfe_txbufs[txsend];
	mcopymsg(mp, txb->txb_buf);	/* frees mp! */

	/*
	 * Statistics.
	 */
	mxfep->mxfe_opackets++;
	mxfep->mxfe_obytes += len;
	if (txb->txb_buf[0] & 0x1) {
		if (bcmp(txb->txb_buf, mxfe_broadcast, ETHERADDRL) != 0)
			mxfep->mxfe_multixmt++;
		else
			mxfep->mxfe_brdcstxmt++;
	}

	/* note len is already known to be a small unsigned */
	control = len | TXCTL_FIRST | TXCTL_LAST | TXCTL_INTCMPLTE;

	if (txsend == (MXFE_TXRING - 1))
		control |= TXCTL_ENDRING;

	tmd = &mxfep->mxfe_txdescp[txsend];

	SYNCTXBUF(txb, len, DDI_DMA_SYNC_FORDEV);
	PUTTXDESC(mxfep, tmd->desc_control, control);
	PUTTXDESC(mxfep, tmd->desc_buffer1, txb->txb_paddr);
	PUTTXDESC(mxfep, tmd->desc_buffer2, 0);
	PUTTXDESC(mxfep, tmd->desc_status, TXSTAT_OWN);
	/* sync the descriptor out to the device */
	SYNCTXDESC(mxfep, txsend, DDI_DMA_SYNC_FORDEV);

	/*
	 * Note the new values of txavail and txsend.
	 */
	mxfep->mxfe_txavail--;
	mxfep->mxfe_txsend = (txsend + 1) % MXFE_TXRING;

	/*
	 * It should never, ever take more than 5 seconds to drain
	 * the ring.  If it happens, then we are stuck!
	 */
	mxfep->mxfe_txstall_time = gethrtime() + (5 * 1000000000ULL);

	/*
	 * wake up the chip ... inside the lock to protect against DR suspend,
	 * etc.
	 */
	PUTCSR(mxfep, CSR_TDR, 0);

	return (B_TRUE);
}

/*
 * Reclaim buffers that have completed transmission.
 */
void
mxfe_reclaim(mxfe_t *mxfep)
{
	mxfe_desc_t	*tmdp;

	while (mxfep->mxfe_txavail != MXFE_TXRING) {
		uint32_t	status;
		uint32_t	control;
		int		index = mxfep->mxfe_txreclaim;

		tmdp = &mxfep->mxfe_txdescp[index];

		/* sync it before we read it */
		SYNCTXDESC(mxfep, index, DDI_DMA_SYNC_FORKERNEL);

		control = GETTXDESC(mxfep, tmdp->desc_control);
		status = GETTXDESC(mxfep, tmdp->desc_status);

		if (status & TXSTAT_OWN) {
			/* chip is still working on it, we're done */
			break;
		}

		mxfep->mxfe_txavail++;
		mxfep->mxfe_txreclaim = (index + 1) % MXFE_TXRING;

		/* in the most common successful case, all bits are clear */
		if (status == 0)
			continue;

		if (((control & TXCTL_SETUP) != 0) ||
		    ((control & TXCTL_LAST) == 0)) {
			/* no interesting statistics here */
			continue;
		}

		if (status & TXSTAT_TXERR) {
			mxfep->mxfe_errxmt++;

			if (status & TXSTAT_JABBER) {
				/* transmit jabber timeout */
				mxfep->mxfe_macxmt_errors++;
			}
			if (status & (TXSTAT_CARRLOST | TXSTAT_NOCARR)) {
				mxfep->mxfe_carrier_errors++;
			}
			if (status & TXSTAT_UFLOW) {
				mxfep->mxfe_underflow++;
			}
			if (status & TXSTAT_LATECOL) {
				mxfep->mxfe_tx_late_collisions++;
			}
			if (status & TXSTAT_EXCOLL) {
				mxfep->mxfe_ex_collisions++;
				mxfep->mxfe_collisions += 16;
			}
		}

		if (status & TXSTAT_DEFER) {
			mxfep->mxfe_defer_xmts++;
		}

		/* collision counting */
		if (TXCOLLCNT(status) == 1) {
			mxfep->mxfe_collisions++;
			mxfep->mxfe_first_collisions++;
		} else if (TXCOLLCNT(status)) {
			mxfep->mxfe_collisions += TXCOLLCNT(status);
			mxfep->mxfe_multi_collisions += TXCOLLCNT(status);
		}
	}

	if (mxfep->mxfe_txavail >= MXFE_TXRESCHED) {
		if (mxfep->mxfe_wantw) {
			/*
			 * we were able to reclaim some packets, so
			 * disable tx interrupts
			 */
			mxfep->mxfe_wantw = B_FALSE;
			mxfe_enableinterrupts(mxfep);
			mac_tx_update(mxfep->mxfe_mh);
		}
	}
}

boolean_t
mxfe_receive(mxfe_t *mxfep, mblk_t **rxchain)
{
	unsigned		len;
	mxfe_rxbuf_t		*rxb;
	mxfe_desc_t		*rmd;
	uint32_t		status;
	mblk_t			*mpchain, **mpp, *mp;
	int			head, cnt;
	boolean_t		error = B_FALSE;

	mpchain = NULL;
	mpp = &mpchain;
	head = mxfep->mxfe_rxhead;

	/* limit the number of packets we process to a ring size */
	for (cnt = 0; cnt < MXFE_RXRING; cnt++) {

		DBG(DRECV, "receive at index %d", head);

		rmd = &mxfep->mxfe_rxdescp[head];
		rxb = mxfep->mxfe_rxbufs[head];

		SYNCRXDESC(mxfep, head, DDI_DMA_SYNC_FORKERNEL);
		status = GETRXDESC(mxfep, rmd->desc_status);
		if (status & RXSTAT_OWN) {
			/* chip is still chewing on it */
			break;
		}

		/* discard the ethernet frame checksum */
		len = RXLENGTH(status) - ETHERFCSL;

		DBG(DRECV, "recv length %d, status %x", len, status);

		if ((status & (RXSTAT_ERRS | RXSTAT_FIRST | RXSTAT_LAST)) !=
		    (RXSTAT_FIRST | RXSTAT_LAST)) {

			mxfep->mxfe_errrcv++;

			/*
			 * Abnormal status bits detected, analyze further.
			 */
			if ((status & (RXSTAT_LAST|RXSTAT_FIRST)) !=
			    (RXSTAT_LAST|RXSTAT_FIRST)) {
				/* someone trying to send jumbo frames? */
				DBG(DRECV, "rx packet overspill");
				if (status & RXSTAT_FIRST) {
					mxfep->mxfe_toolong_errors++;
				}
			} else if (status & RXSTAT_DESCERR) {
				/* this should never occur! */
				mxfep->mxfe_macrcv_errors++;
				error = B_TRUE;

			} else if (status & RXSTAT_RUNT) {
				mxfep->mxfe_runt++;

			} else if (status & RXSTAT_COLLSEEN) {
				/* this should really be rx_late_collisions */
				mxfep->mxfe_macrcv_errors++;

			} else if (status & RXSTAT_DRIBBLE) {
				mxfep->mxfe_align_errors++;

			} else if (status & RXSTAT_CRCERR) {
				mxfep->mxfe_fcs_errors++;

			} else if (status & RXSTAT_OFLOW) {
				/* this is a MAC FIFO error, need to reset */
				mxfep->mxfe_overflow++;
				error = B_TRUE;
			}
		}

		else if (len > ETHERVLANMTU) {
			mxfep->mxfe_errrcv++;
			mxfep->mxfe_toolong_errors++;
		}

		/*
		 * At this point, the chip thinks the packet is OK.
		 */
		else {
			mp = allocb(len + MXFE_HEADROOM, 0);
			if (mp == NULL) {
				mxfep->mxfe_errrcv++;
				mxfep->mxfe_norcvbuf++;
				goto skip;
			}

			/* sync the buffer before we look at it */
			SYNCRXBUF(rxb, len, DDI_DMA_SYNC_FORKERNEL);
			mp->b_rptr += MXFE_HEADROOM;
			mp->b_wptr = mp->b_rptr + len;
			bcopy((char *)rxb->rxb_buf, mp->b_rptr, len);

			mxfep->mxfe_ipackets++;
			mxfep->mxfe_rbytes += len;
			if (status & RXSTAT_GROUP) {
				if (bcmp(mp->b_rptr, mxfe_broadcast,
				    ETHERADDRL) == 0)
					mxfep->mxfe_brdcstrcv++;
				else
					mxfep->mxfe_multircv++;
			}
			*mpp = mp;
			mpp = &mp->b_next;
		}

skip:
		/* return ring entry to the hardware */
		PUTRXDESC(mxfep, rmd->desc_status, RXSTAT_OWN);
		SYNCRXDESC(mxfep, head, DDI_DMA_SYNC_FORDEV);

		/* advance to next RMD */
		head = (head + 1) % MXFE_RXRING;
	}

	mxfep->mxfe_rxhead = head;

	*rxchain = mpchain;
	return (error);
}

int
mxfe_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	mxfe_t	*mxfep = arg;

	mutex_enter(&mxfep->mxfe_xmtlock);
	if ((mxfep->mxfe_flags & (MXFE_RUNNING|MXFE_SUSPENDED)) == MXFE_RUNNING)
		mxfe_reclaim(mxfep);
	mutex_exit(&mxfep->mxfe_xmtlock);

	switch (stat) {
	case MAC_STAT_IFSPEED:
		*val = mxfep->mxfe_ifspeed;
		break;

	case MAC_STAT_MULTIRCV:
		*val = mxfep->mxfe_multircv;
		break;

	case MAC_STAT_BRDCSTRCV:
		*val = mxfep->mxfe_brdcstrcv;
		break;

	case MAC_STAT_MULTIXMT:
		*val = mxfep->mxfe_multixmt;
		break;

	case MAC_STAT_BRDCSTXMT:
		*val = mxfep->mxfe_brdcstxmt;
		break;

	case MAC_STAT_IPACKETS:
		*val = mxfep->mxfe_ipackets;
		break;

	case MAC_STAT_RBYTES:
		*val = mxfep->mxfe_rbytes;
		break;

	case MAC_STAT_OPACKETS:
		*val = mxfep->mxfe_opackets;
		break;

	case MAC_STAT_OBYTES:
		*val = mxfep->mxfe_obytes;
		break;

	case MAC_STAT_NORCVBUF:
		*val = mxfep->mxfe_norcvbuf;
		break;

	case MAC_STAT_NOXMTBUF:
		*val = mxfep->mxfe_noxmtbuf;
		break;

	case MAC_STAT_COLLISIONS:
		*val = mxfep->mxfe_collisions;
		break;

	case MAC_STAT_IERRORS:
		*val = mxfep->mxfe_errrcv;
		break;

	case MAC_STAT_OERRORS:
		*val = mxfep->mxfe_errxmt;
		break;

	case ETHER_STAT_LINK_DUPLEX:
		*val = mxfep->mxfe_duplex;
		break;

	case ETHER_STAT_ALIGN_ERRORS:
		*val = mxfep->mxfe_align_errors;
		break;

	case ETHER_STAT_FCS_ERRORS:
		*val = mxfep->mxfe_fcs_errors;
		break;

	case ETHER_STAT_SQE_ERRORS:
		*val = mxfep->mxfe_sqe_errors;
		break;

	case ETHER_STAT_DEFER_XMTS:
		*val = mxfep->mxfe_defer_xmts;
		break;

	case ETHER_STAT_FIRST_COLLISIONS:
		*val  = mxfep->mxfe_first_collisions;
		break;

	case ETHER_STAT_MULTI_COLLISIONS:
		*val = mxfep->mxfe_multi_collisions;
		break;

	case ETHER_STAT_TX_LATE_COLLISIONS:
		*val = mxfep->mxfe_tx_late_collisions;
		break;

	case ETHER_STAT_EX_COLLISIONS:
		*val = mxfep->mxfe_ex_collisions;
		break;

	case ETHER_STAT_MACXMT_ERRORS:
		*val = mxfep->mxfe_macxmt_errors;
		break;

	case ETHER_STAT_CARRIER_ERRORS:
		*val = mxfep->mxfe_carrier_errors;
		break;

	case ETHER_STAT_TOOLONG_ERRORS:
		*val = mxfep->mxfe_toolong_errors;
		break;

	case ETHER_STAT_MACRCV_ERRORS:
		*val = mxfep->mxfe_macrcv_errors;
		break;

	case MAC_STAT_OVERFLOWS:
		*val = mxfep->mxfe_overflow;
		break;

	case MAC_STAT_UNDERFLOWS:
		*val = mxfep->mxfe_underflow;
		break;

	case ETHER_STAT_TOOSHORT_ERRORS:
		*val = mxfep->mxfe_runt;
		break;

	case ETHER_STAT_JABBER_ERRORS:
		*val = mxfep->mxfe_jabber;
		break;

	case ETHER_STAT_ADV_CAP_100T4:
		*val = mxfep->mxfe_adv_100T4;
		break;

	case ETHER_STAT_LP_CAP_100T4:
		*val = (mxfep->mxfe_anlpar & MII_ABILITY_100BASE_T4) ? 1 : 0;
		break;

	case ETHER_STAT_CAP_100T4:
		*val = mxfep->mxfe_cap_100T4;
		break;

	case ETHER_STAT_CAP_100FDX:
		*val = mxfep->mxfe_cap_100fdx;
		break;

	case ETHER_STAT_CAP_100HDX:
		*val = mxfep->mxfe_cap_100hdx;
		break;

	case ETHER_STAT_CAP_10FDX:
		*val = mxfep->mxfe_cap_10fdx;
		break;

	case ETHER_STAT_CAP_10HDX:
		*val = mxfep->mxfe_cap_10hdx;
		break;

	case ETHER_STAT_CAP_AUTONEG:
		*val = mxfep->mxfe_cap_aneg;
		break;

	case ETHER_STAT_LINK_AUTONEG:
		*val = ((mxfep->mxfe_adv_aneg != 0) &&
		    ((mxfep->mxfe_aner & MII_AN_EXP_LPCANAN) != 0));
		break;

	case ETHER_STAT_ADV_CAP_100FDX:
		*val = mxfep->mxfe_adv_100fdx;
		break;

	case ETHER_STAT_ADV_CAP_100HDX:
		*val = mxfep->mxfe_adv_100hdx;
		break;

	case ETHER_STAT_ADV_CAP_10FDX:
		*val = mxfep->mxfe_adv_10fdx;
		break;

	case ETHER_STAT_ADV_CAP_10HDX:
		*val = mxfep->mxfe_adv_10hdx;
		break;

	case ETHER_STAT_ADV_CAP_AUTONEG:
		*val = mxfep->mxfe_adv_aneg;
		break;

	case ETHER_STAT_LP_CAP_100FDX:
		*val = (mxfep->mxfe_anlpar & MII_ABILITY_100BASE_TX_FD) ? 1 : 0;
		break;

	case ETHER_STAT_LP_CAP_100HDX:
		*val = (mxfep->mxfe_anlpar & MII_ABILITY_100BASE_TX) ? 1 : 0;
		break;

	case ETHER_STAT_LP_CAP_10FDX:
		*val = (mxfep->mxfe_anlpar & MII_ABILITY_10BASE_T_FD) ? 1 : 0;
		break;

	case ETHER_STAT_LP_CAP_10HDX:
		*val = (mxfep->mxfe_anlpar & MII_ABILITY_10BASE_T) ? 1 : 0;
		break;

	case ETHER_STAT_LP_CAP_AUTONEG:
		*val = (mxfep->mxfe_aner & MII_AN_EXP_LPCANAN) ? 1 : 0;
		break;

	case ETHER_STAT_XCVR_ADDR:
		*val = mxfep->mxfe_phyaddr;
		break;

	case ETHER_STAT_XCVR_ID:
		*val = mxfep->mxfe_phyid;
		break;

	case ETHER_STAT_XCVR_INUSE:
		*val = mxfep->mxfe_phyinuse;
		break;

	default:
		return (ENOTSUP);
	}
	return (0);
}

/*ARGSUSED*/
int
mxfe_m_getprop(void *arg, const char *name, mac_prop_id_t num, uint_t sz,
    void *val)
{
	mxfe_t		*mxfep = arg;
	int		err = 0;

	switch (num) {
	case MAC_PROP_DUPLEX:
		ASSERT(sz >= sizeof (link_duplex_t));
		bcopy(&mxfep->mxfe_duplex, val, sizeof (link_duplex_t));
		break;

	case MAC_PROP_SPEED:
		ASSERT(sz >= sizeof (uint64_t));
		bcopy(&mxfep->mxfe_ifspeed, val, sizeof (uint64_t));
		break;

	case MAC_PROP_AUTONEG:
		*(uint8_t *)val = mxfep->mxfe_adv_aneg;
		break;

	case MAC_PROP_ADV_100FDX_CAP:
	case MAC_PROP_EN_100FDX_CAP:
		*(uint8_t *)val = mxfep->mxfe_adv_100fdx;
		break;

	case MAC_PROP_ADV_100HDX_CAP:
	case MAC_PROP_EN_100HDX_CAP:
		*(uint8_t *)val = mxfep->mxfe_adv_100hdx;
		break;

	case MAC_PROP_ADV_10FDX_CAP:
	case MAC_PROP_EN_10FDX_CAP:
		*(uint8_t *)val = mxfep->mxfe_adv_10fdx;
		break;

	case MAC_PROP_ADV_10HDX_CAP:
	case MAC_PROP_EN_10HDX_CAP:
		*(uint8_t *)val = mxfep->mxfe_adv_10hdx;
		break;

	case MAC_PROP_ADV_100T4_CAP:
	case MAC_PROP_EN_100T4_CAP:
		*(uint8_t *)val = mxfep->mxfe_adv_100T4;
		break;

	default:
		err = ENOTSUP;
	}

	return (err);
}

/*ARGSUSED*/
int
mxfe_m_setprop(void *arg, const char *name, mac_prop_id_t num, uint_t sz,
    const void *val)
{
	mxfe_t		*mxfep = arg;
	uint8_t		*advp;
	uint8_t		*capp;

	switch (num) {
	case MAC_PROP_EN_100FDX_CAP:
		advp = &mxfep->mxfe_adv_100fdx;
		capp = &mxfep->mxfe_cap_100fdx;
		break;

	case MAC_PROP_EN_100HDX_CAP:
		advp = &mxfep->mxfe_adv_100hdx;
		capp = &mxfep->mxfe_cap_100hdx;
		break;

	case MAC_PROP_EN_10FDX_CAP:
		advp = &mxfep->mxfe_adv_10fdx;
		capp = &mxfep->mxfe_cap_10fdx;
		break;

	case MAC_PROP_EN_10HDX_CAP:
		advp = &mxfep->mxfe_adv_10hdx;
		capp = &mxfep->mxfe_cap_10hdx;
		break;

	case MAC_PROP_EN_100T4_CAP:
		advp = &mxfep->mxfe_adv_100T4;
		capp = &mxfep->mxfe_cap_100T4;
		break;

	case MAC_PROP_AUTONEG:
		advp = &mxfep->mxfe_adv_aneg;
		capp = &mxfep->mxfe_cap_aneg;
		break;

	default:
		return (ENOTSUP);
	}

	if (*capp == 0)		/* ensure phy can support value */
		return (ENOTSUP);

	mutex_enter(&mxfep->mxfe_intrlock);
	mutex_enter(&mxfep->mxfe_xmtlock);

	if (*advp != *(const uint8_t *)val) {
		*advp = *(const uint8_t *)val;

		if ((mxfep->mxfe_flags & (MXFE_RUNNING|MXFE_SUSPENDED)) ==
		    MXFE_RUNNING) {
			/*
			 * This re-initializes the phy, but it also
			 * restarts transmit and receive rings.
			 * Needless to say, changing the link
			 * parameters is destructive to traffic in
			 * progress.
			 */
			mxfe_resetall(mxfep);
		}
	}
	mutex_exit(&mxfep->mxfe_xmtlock);
	mutex_exit(&mxfep->mxfe_intrlock);

	return (0);
}

static void
mxfe_m_propinfo(void *arg, const char *name, mac_prop_id_t num,
    mac_prop_info_handle_t mph)
{
	mxfe_t		*mxfep = arg;

        _NOTE(ARGUNUSED(name));

	switch (num) {
	case MAC_PROP_DUPLEX:
	case MAC_PROP_SPEED:
	case MAC_PROP_ADV_100FDX_CAP:
	case MAC_PROP_ADV_100HDX_CAP:
	case MAC_PROP_ADV_10FDX_CAP:
	case MAC_PROP_ADV_10HDX_CAP:
	case MAC_PROP_ADV_100T4_CAP:
		mac_prop_info_set_perm(mph, MAC_PROP_PERM_READ);
		break;

	case MAC_PROP_AUTONEG:
		mac_prop_info_set_default_uint8(mph, mxfep->mxfe_cap_aneg);
		break;

	case MAC_PROP_EN_100FDX_CAP:
		mac_prop_info_set_default_uint8(mph, mxfep->mxfe_cap_100fdx);
		break;

	case MAC_PROP_EN_100HDX_CAP:
		mac_prop_info_set_default_uint8(mph, mxfep->mxfe_cap_100hdx);
		break;

	case MAC_PROP_EN_10FDX_CAP:
		mac_prop_info_set_default_uint8(mph, mxfep->mxfe_cap_10fdx);
		break;

	case MAC_PROP_EN_10HDX_CAP:
		mac_prop_info_set_default_uint8(mph, mxfep->mxfe_cap_10hdx);
		break;

	case MAC_PROP_EN_100T4_CAP:
		mac_prop_info_set_default_uint8(mph, mxfep->mxfe_cap_100T4);
		break;
	}
}

/*
 * Debugging and error reporting.
 */
void
mxfe_error(dev_info_t *dip, char *fmt, ...)
{
	va_list	ap;
	char	buf[256];

	va_start(ap, fmt);
	(void) vsnprintf(buf, sizeof (buf), fmt, ap);
	va_end(ap);

	if (dip) {
		cmn_err(CE_WARN, "%s%d: %s",
		    ddi_driver_name(dip), ddi_get_instance(dip), buf);
	} else {
		cmn_err(CE_WARN, "mxfe: %s", buf);
	}
}

#ifdef DEBUG

void
mxfe_dprintf(mxfe_t *mxfep, const char *func, int level, char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	if (mxfe_debug & level) {
		char	tag[64];
		char	buf[256];

		if (mxfep && mxfep->mxfe_dip) {
			(void) snprintf(tag, sizeof (tag),
			    "%s%d", ddi_driver_name(mxfep->mxfe_dip),
			    ddi_get_instance(mxfep->mxfe_dip));
		} else {
			(void) snprintf(tag, sizeof (tag), "mxfe");
		}

		(void) snprintf(buf, sizeof (buf), "%s: %s: %s\n", tag,
		    func, fmt);

		vcmn_err(CE_CONT, buf, ap);
	}
	va_end(ap);
}

#endif
