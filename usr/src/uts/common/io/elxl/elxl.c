/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2018 Joyent, Inc.
 */

/*
 * Copyright (c) 1998 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Frank van der Linden.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/varargs.h>
#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/cmn_err.h>
#include <sys/ethernet.h>
#include <sys/pci.h>
#include <sys/kmem.h>
#include <sys/time.h>
#include <sys/mii.h>
#include <sys/miiregs.h>
#include <sys/mac_ether.h>
#include <sys/mac_provider.h>
#include <sys/strsubr.h>
#include <sys/pattr.h>
#include <sys/dlpi.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/vlan.h>

#include "elxl.h"

static boolean_t elxl_add_intr(elxl_t *);
static void elxl_probe_media(elxl_t *);
static void elxl_set_rxfilter(elxl_t *);
static void elxl_set_media(elxl_t *);
static uint16_t elxl_read_eeprom(elxl_t *, int);
static void elxl_init(elxl_t *);
static void elxl_stop(elxl_t *);
static void elxl_reset(elxl_t *);
static void elxl_getstats(elxl_t *);

static int elxl_eeprom_busy(elxl_t *);

static void elxl_setup_tx(elxl_t *);

static uint16_t elxl_mii_read(void *, uint8_t, uint8_t);
static void elxl_mii_write(void *, uint8_t, uint8_t, uint16_t);
static void elxl_mii_notify(void *, link_state_t);

static int elxl_m_stat(void *, uint_t, uint64_t *);
static int elxl_m_start(void *);
static void elxl_m_stop(void *);
static mblk_t *elxl_m_tx(void *, mblk_t *);
static int elxl_m_promisc(void *, boolean_t);
static int elxl_m_multicst(void *, boolean_t, const uint8_t *);
static int elxl_m_unicst(void *, const uint8_t *);
static int elxl_m_getprop(void *, const char *, mac_prop_id_t, uint_t,
    void *);
static int elxl_m_setprop(void *, const char *, mac_prop_id_t, uint_t,
    const void *);
static void elxl_m_propinfo(void *, const char *, mac_prop_id_t,
    mac_prop_info_handle_t);
static boolean_t elxl_m_getcapab(void *, mac_capab_t cap, void *);
static uint_t elxl_intr(caddr_t, caddr_t);
static void elxl_error(elxl_t *, char *, ...);
static void elxl_linkcheck(void *);
static int elxl_attach(dev_info_t *);
static void elxl_detach(elxl_t *);
static void elxl_suspend(elxl_t *);
static void elxl_resume(dev_info_t *);
static int elxl_ddi_attach(dev_info_t *, ddi_attach_cmd_t);
static int elxl_ddi_detach(dev_info_t *, ddi_detach_cmd_t);
static int elxl_ddi_quiesce(dev_info_t *);

static ddi_device_acc_attr_t ex_dev_acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

static ddi_device_acc_attr_t ex_buf_acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STORECACHING_OK_ACC
};

/*
 * In theory buffers can have more flexible DMA attributes, but since
 * we're just using a preallocated region with bcopy, there is little
 * reason to allow for rougher alignment.  (Further, the 8-byte
 * alignment can allow for more efficient bcopy and similar operations
 * from the buffer.)
 */
static ddi_dma_attr_t ex_dma_attr = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo */
	0xFFFFFFFFU,		/* dma_attr_addr_hi */
	0x00FFFFFFU,		/* dma_attr_count_max */
	8,			/* dma_attr_align */
	0x7F,			/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0xFFFFFFFFU,		/* dma_attr_maxxfer */
	0xFFFFFFFFU,		/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};

static uint8_t ex_broadcast[6] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

/*
 * Structure to map media-present bits in boards to ifmedia codes and
 * printable media names.  Used for table-driven ifmedia initialization.
 */
typedef struct ex_media {
	int	exm_mpbit;		/* media present bit */
	int	exm_xcvr;		/* XCVR_SEL_* constant */
} ex_media_t;

/*
 * Media table for 3c90x chips.  Note that chips with MII have no
 * `native' media.  This is sorted in "reverse preference".
 */
static ex_media_t ex_native_media[] = {
	{ MEDIAOPT_AUI,		XCVR_SEL_AUI },
	{ MEDIAOPT_BNC,		XCVR_SEL_BNC },
	{ MEDIAOPT_10T,		XCVR_SEL_10T },
	{ MEDIAOPT_100TX,	XCVR_SEL_AUTO },	/* only 90XB */
	{ MEDIAOPT_100FX,	XCVR_SEL_100FX },
	{ MEDIAOPT_MII,		XCVR_SEL_MII },
	{ MEDIAOPT_100T4,	XCVR_SEL_MII },
	{ 0,			0 },
};


/*
 * NB: There are lots of other models that *could* be supported.
 * Specifically there are cardbus and miniPCI variants that could be
 * easily added here, but they require special hacks and I have no
 * access to the hardware required to verify them.  Especially they
 * seem to require some extra work in another register window, and I
 * have no supporting documentation.
 */
static const struct ex_product {
	uint16_t	epp_prodid;	/* PCI product ID */
	const char	*epp_name;	/* device name */
	unsigned	epp_flags;	/* initial softc flags */
} ex_products[] = {
	{ 0x4500, "3c450-TX",		0 },
	{ 0x7646, "3cSOHO100-TX",	0 },
	{ 0x9000, "3c900-TPO",		0 },
	{ 0x9001, "3c900-COMBO",	0 },
	{ 0x9004, "3c900B-TPO",		0 },
	{ 0x9005, "3c900B-COMBO",	0 },
	{ 0x9006, "3c900B-TPC",		0 },
	{ 0x900a, "3c900B-FL",		0 },
	{ 0x9050, "3c905-TX",		0 },
	{ 0x9051, "3c905-T4",		0 },
	{ 0x9055, "3c905B-TX",		0 },
	{ 0x9056, "3c905B-T4",		0 },
	{ 0x9058, "3c905B-COMBO",	0 },
	{ 0x905a, "3c905B-FX",		0 },
	{ 0x9200, "3c905C-TX",		0 },
	{ 0x9201, "3c920B-EMB",		0 },
	{ 0x9202, "3c920B-EMB-WNM",	0 },
	{ 0x9800, "3c980",		0 },
	{ 0x9805, "3c980C-TXM",		0 },

	{ 0, NULL, 0 },
};

static char *ex_priv_prop[] = {
	"_media",
	"_available_media",
	NULL
};

static mii_ops_t ex_mii_ops = {
	MII_OPS_VERSION,
	elxl_mii_read,
	elxl_mii_write,
	elxl_mii_notify,
};

static mac_callbacks_t elxl_m_callbacks = {
	MC_GETCAPAB | MC_PROPERTIES,
	elxl_m_stat,
	elxl_m_start,
	elxl_m_stop,
	elxl_m_promisc,
	elxl_m_multicst,
	elxl_m_unicst,
	elxl_m_tx,
	NULL,
	NULL,
	elxl_m_getcapab,
	NULL,
	NULL,
	elxl_m_setprop,
	elxl_m_getprop,
	elxl_m_propinfo
};

/*
 * Stream information
 */
DDI_DEFINE_STREAM_OPS(ex_devops, nulldev, nulldev,
    elxl_ddi_attach, elxl_ddi_detach,
    nodev, NULL, D_MP, NULL, elxl_ddi_quiesce);

/*
 * Module linkage information.
 */

static struct modldrv ex_modldrv = {
	&mod_driverops,			/* drv_modops */
	"3Com EtherLink XL",		/* drv_linkinfo */
	&ex_devops			/* drv_dev_ops */
};

static struct modlinkage ex_modlinkage = {
	MODREV_1,		/* ml_rev */
	{ &ex_modldrv, NULL }	/* ml_linkage */
};

int
_init(void)
{
	int	rv;
	mac_init_ops(&ex_devops, "elxl");
	if ((rv = mod_install(&ex_modlinkage)) != DDI_SUCCESS) {
		mac_fini_ops(&ex_devops);
	}
	return (rv);
}

int
_fini(void)
{
	int	rv;
	if ((rv = mod_remove(&ex_modlinkage)) == DDI_SUCCESS) {
		mac_fini_ops(&ex_devops);
	}
	return (rv);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&ex_modlinkage, modinfop));
}

static void
ex_free_ring(ex_ring_t *r)
{
	for (int i = 0; i < r->r_count; i++) {
		ex_desc_t *ed = &r->r_desc[i];
		if (ed->ed_bufaddr)
			(void) ddi_dma_unbind_handle(ed->ed_dmah);
		if (ed->ed_acch)
			ddi_dma_mem_free(&ed->ed_acch);
		if (ed->ed_dmah)
			ddi_dma_free_handle(&ed->ed_dmah);
	}

	if (r->r_paddr)
		(void) ddi_dma_unbind_handle(r->r_dmah);
	if (r->r_acch)
		ddi_dma_mem_free(&r->r_acch);
	if (r->r_dmah)
		ddi_dma_free_handle(&r->r_dmah);

	kmem_free(r->r_desc, sizeof (ex_desc_t) * r->r_count);
	r->r_desc = NULL;
}

static void
elxl_reset_ring(ex_ring_t *r, uint_t dir)
{
	ex_desc_t	*ed;
	ex_pd_t		*pd;

	if (dir == DDI_DMA_WRITE) {
		/* transmit ring, not linked yet */
		for (int i = 0; i < r->r_count; i++) {
			ed = &r->r_desc[i];
			pd = ed->ed_pd;
			PUT_PD(r, pd->pd_link, 0);
			PUT_PD(r, pd->pd_fsh, 0);
			PUT_PD(r, pd->pd_len, EX_FR_LAST);
			PUT_PD(r, pd->pd_addr, ed->ed_bufaddr);
		}
		r->r_head = NULL;
		r->r_tail = NULL;
		r->r_avail = r->r_count;
	} else {
		/* receive is linked into a list */
		for (int i = 0; i < r->r_count; i++) {
			ed = &r->r_desc[i];
			pd = ed->ed_pd;
			PUT_PD(r, pd->pd_link, ed->ed_next->ed_descaddr);
			PUT_PD(r, pd->pd_status, 0);
			PUT_PD(r, pd->pd_len, EX_BUFSZ | EX_FR_LAST);
			PUT_PD(r, pd->pd_addr, ed->ed_bufaddr);
		}
		r->r_head = &r->r_desc[0];
		r->r_tail = NULL;
		r->r_avail = 0;
	}
	(void) ddi_dma_sync(r->r_dmah, 0, 0, DDI_DMA_SYNC_FORDEV);
}

static boolean_t
ex_alloc_ring(elxl_t *sc, int count, ex_ring_t *r, uint_t dir)
{
	dev_info_t		*dip = sc->ex_dip;
	int			i;
	int			rv;
	size_t			len;
	ddi_dma_cookie_t	dmac;
	unsigned		ndmac;

	r->r_count = count;
	r->r_desc = kmem_zalloc(sizeof (ex_desc_t) * count, KM_SLEEP);

	rv = ddi_dma_alloc_handle(dip, &ex_dma_attr, DDI_DMA_DONTWAIT,
	    NULL, &r->r_dmah);
	if (rv != DDI_SUCCESS) {
		elxl_error(sc, "unable to allocate descriptor dma handle");
		return (B_FALSE);
	}

	rv = ddi_dma_mem_alloc(r->r_dmah, count * sizeof (struct ex_pd),
	    &ex_dev_acc_attr, DDI_DMA_CONSISTENT, DDI_DMA_DONTWAIT, NULL,
	    (caddr_t *)&r->r_pd, &len, &r->r_acch);
	if (rv != DDI_SUCCESS) {
		elxl_error(sc, "unable to allocate descriptor memory");
		return (B_FALSE);
	}
	bzero(r->r_pd, len);

	rv = ddi_dma_addr_bind_handle(r->r_dmah, NULL,
	    (caddr_t)r->r_pd, len, DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_DONTWAIT, NULL, &dmac, &ndmac);
	if (rv != DDI_DMA_MAPPED) {
		elxl_error(sc, "unable to map descriptor memory");
		return (B_FALSE);
	}
	r->r_paddr = dmac.dmac_address;

	for (i = 0; i < count; i++) {
		ex_desc_t	*ed = &r->r_desc[i];
		ex_pd_t		*pd = &r->r_pd[i];

		ed->ed_pd = pd;
		ed->ed_off = (i * sizeof (ex_pd_t));
		ed->ed_descaddr = r->r_paddr + (i * sizeof (ex_pd_t));

		/* Link the high level descriptors into a ring. */
		ed->ed_next = &r->r_desc[(i + 1) % count];
		ed->ed_next->ed_prev = ed;

		rv = ddi_dma_alloc_handle(dip, &ex_dma_attr,
		    DDI_DMA_DONTWAIT, NULL, &ed->ed_dmah);
		if (rv != 0) {
			elxl_error(sc, "can't allocate buf dma handle");
			return (B_FALSE);
		}
		rv = ddi_dma_mem_alloc(ed->ed_dmah, EX_BUFSZ, &ex_buf_acc_attr,
		    DDI_DMA_STREAMING, DDI_DMA_DONTWAIT, NULL, &ed->ed_buf,
		    &len, &ed->ed_acch);
		if (rv != DDI_SUCCESS) {
			elxl_error(sc, "unable to allocate buf memory");
			return (B_FALSE);
		}
		bzero(ed->ed_buf, len);

		rv = ddi_dma_addr_bind_handle(ed->ed_dmah, NULL,
		    ed->ed_buf, len, dir | DDI_DMA_STREAMING,
		    DDI_DMA_DONTWAIT, NULL, &dmac, &ndmac);
		if (rv != DDI_DMA_MAPPED) {
			elxl_error(sc, "unable to map buf memory");
			return (B_FALSE);
		}
		ed->ed_bufaddr = dmac.dmac_address;
	}

	elxl_reset_ring(r, dir);

	return (B_TRUE);
}

static boolean_t
elxl_add_intr(elxl_t *sc)
{
	dev_info_t		*dip;
	int			actual;
	uint_t			ipri;

	int			rv;

	dip = sc->ex_dip;

	rv = ddi_intr_alloc(dip, &sc->ex_intrh, DDI_INTR_TYPE_FIXED,
	    0, 1, &actual, DDI_INTR_ALLOC_STRICT);
	if ((rv != DDI_SUCCESS) || (actual != 1)) {
		elxl_error(sc, "Unable to allocate interrupt, %d, count %d",
		    rv, actual);
		return (B_FALSE);
	}

	if (ddi_intr_get_pri(sc->ex_intrh, &ipri) != DDI_SUCCESS) {
		elxl_error(sc, "Unable to get interrupt priority");
		return (B_FALSE);
	}

	if (ddi_intr_add_handler(sc->ex_intrh, elxl_intr, sc, NULL) !=
	    DDI_SUCCESS) {
		elxl_error(sc, "Can't add interrupt handler");
		(void) ddi_intr_free(sc->ex_intrh);
		sc->ex_intrh = NULL;
		return (B_FALSE);
	}
	mutex_init(&sc->ex_intrlock, NULL, MUTEX_DRIVER, DDI_INTR_PRI(ipri));
	mutex_init(&sc->ex_txlock, NULL, MUTEX_DRIVER, DDI_INTR_PRI(ipri));

	return (B_TRUE);
}

static int
elxl_attach(dev_info_t *dip)
{
	elxl_t		*sc;
	mac_register_t	*macp;
	uint16_t	val;
	uint16_t	venid;
	uint16_t	devid;
	int		i;

	sc = kmem_zalloc(sizeof (*sc), KM_SLEEP);
	ddi_set_driver_private(dip, sc);
	sc->ex_dip = dip;

	if (pci_config_setup(dip, &sc->ex_pcih) != DDI_SUCCESS) {
		elxl_error(sc, "unable to setup PCI config handle");
		goto fail;
	}
	venid = pci_config_get16(sc->ex_pcih, PCI_CONF_VENID);
	devid = pci_config_get16(sc->ex_pcih, PCI_CONF_DEVID);

	if (venid != 0x10b7) {
		/* Not a 3Com part! */
		elxl_error(sc, "Unsupported vendor id (0x%x)", venid);
		goto fail;
	}
	for (i = 0; ex_products[i].epp_name; i++) {
		if (devid == ex_products[i].epp_prodid) {
			cmn_err(CE_CONT, "?%s%d: 3Com %s",
			    ddi_driver_name(dip),
			    ddi_get_instance(dip),
			    ex_products[i].epp_name);
			sc->ex_conf = ex_products[i].epp_flags;
			break;
		}
	}
	if (ex_products[i].epp_name == NULL) {
		/* Not a produce we know how to support */
		elxl_error(sc, "Unsupported device id (0x%x)", devid);
		elxl_error(sc, "Driver may or may not function.");
	}

	pci_config_put16(sc->ex_pcih, PCI_CONF_COMM,
	    pci_config_get16(sc->ex_pcih, PCI_CONF_COMM) |
	    PCI_COMM_IO | PCI_COMM_MAE | PCI_COMM_ME);

	if (ddi_regs_map_setup(dip, 1, &sc->ex_regsva, 0, 0, &ex_dev_acc_attr,
	    &sc->ex_regsh) != DDI_SUCCESS) {
		elxl_error(sc, "Unable to map device registers");
		goto fail;
	}

	if (!elxl_add_intr(sc)) {
		goto fail;
	}

	elxl_reset(sc);

	val = elxl_read_eeprom(sc, EE_OEM_ADDR_0);
	sc->ex_factaddr[0] = val >> 8;
	sc->ex_factaddr[1] = val & 0xff;
	val = elxl_read_eeprom(sc, EE_OEM_ADDR_1);
	sc->ex_factaddr[2] = val >> 8;
	sc->ex_factaddr[3] = val & 0xff;
	val = elxl_read_eeprom(sc, EE_OEM_ADDR_2);
	sc->ex_factaddr[4] = val >> 8;
	sc->ex_factaddr[5] = val & 0xff;
	bcopy(sc->ex_factaddr, sc->ex_curraddr, 6);

	sc->ex_capab = elxl_read_eeprom(sc, EE_CAPABILITIES);

	/*
	 * Is this a 90XB?  If bit 2 (supportsLargePackets) is set, or
	 * bit (supportsNoTxLength) is clear, then its a 90X.
	 * Otherwise its a 90XB.
	 */
	if ((sc->ex_capab & (1 << 2)) || !(sc->ex_capab & (1 << 9))) {
		sc->ex_conf &= ~CONF_90XB;
	} else {
		sc->ex_conf |= CONF_90XB;
	}

	if (!ex_alloc_ring(sc, EX_NRX, &sc->ex_rxring, DDI_DMA_READ)) {
		goto fail;
	}

	if (!ex_alloc_ring(sc, EX_NTX, &sc->ex_txring, DDI_DMA_WRITE)) {
		goto fail;
	}

	elxl_probe_media(sc);

	/*
	 * The probe may have indicated MII!
	 */
	if (sc->ex_mediaopt & (MEDIAOPT_MII | MEDIAOPT_100TX)) {
		sc->ex_miih = mii_alloc(sc, sc->ex_dip, &ex_mii_ops);
		if (sc->ex_miih == NULL) {
			goto fail;
		}
		/*
		 * Note: The 90XB models can in theory support pause,
		 * but we're not enabling now due to lack of units for
		 * testing with.  If this is changed, make sure to
		 * update the code in elxl_mii_notify to set the flow
		 * control field in the W3_MAC_CONTROL register.
		 */
		mii_set_pauseable(sc->ex_miih, B_FALSE, B_FALSE);
	}
	if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
		elxl_error(sc, "MAC register allocation failed");
		goto fail;
	}
	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_driver = sc;
	macp->m_dip = dip;
	macp->m_src_addr = sc->ex_curraddr;
	macp->m_callbacks = &elxl_m_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = ETHERMTU;
	macp->m_margin = VLAN_TAGSZ;
	macp->m_priv_props = ex_priv_prop;

	(void) ddi_intr_enable(sc->ex_intrh);

	if (mac_register(macp, &sc->ex_mach) == DDI_SUCCESS) {

			/*
			 * Note: we don't want to start link checking
			 * until *after* we have added the MAC handle.
			 */
		if (sc->ex_mediaopt &
		    (MEDIAOPT_MASK & ~(MEDIAOPT_MII | MEDIAOPT_100TX))) {

			/* Check non-MII link state once per second. */
			sc->ex_linkcheck =
			    ddi_periodic_add(elxl_linkcheck, sc, 10000000, 0);
		}

		mac_free(macp);
		return (DDI_SUCCESS);
	}

	mac_free(macp);

fail:
	elxl_detach(sc);
	return (DDI_FAILURE);
}

/*
 * Find the media present on non-MII chips, and select the one to use.
 */
static void
elxl_probe_media(elxl_t *sc)
{
	ex_media_t	*exm;
	uint32_t	config;
	uint32_t	default_media;
	uint16_t	media_options;

	SET_WIN(3);
	config = GET32(W3_INTERNAL_CONFIG);
	media_options = GET16(W3_MEDIAOPT);

	/*
	 * We modify the media_options field so that we have a
	 * consistent view of the media available, without worrying
	 * about the version of ASIC, etc.
	 */

	/*
	 * 100BASE-TX is handled differently on 90XB from 90X.  Older
	 * parts use the external MII to provide this support.
	 */
	if (sc->ex_conf & CONF_90XB) {
		if (media_options & MEDIAOPT_100TX) {
			/*
			 * 3Com advises that we should only ever use the
			 * auto mode.  Notably, it seems that there should
			 * never be a 90XB board with the MEDIAOPT_10T bit set
			 * without this bit.  If it happens, the driver will
			 * run in compatible 10BASE-T only mode.
			 */
			media_options &= ~MEDIAOPT_10T;
		}
	} else {
		if (media_options & MEDIAOPT_100TX) {
			/*
			 * If this occurs, we really want to use it like
			 * an MII device.  Generally in this situation we
			 * want to use the MII exclusively, and there ought
			 * not be a 10bT transceiver.
			 */
			media_options |= MEDIAOPT_MII;
			media_options &= ~MEDIAOPT_100TX;
			media_options &= ~MEDIAOPT_10T;

			/*
			 * Additionally, some of these devices map all
			 * internal PHY register at *every* address, not
			 * just the "allowed" address 24.
			 */
			sc->ex_conf |= CONF_INTPHY;
		}
		/*
		 * Early versions didn't have 10FL models, and used this
		 * bit for something else (VCO).
		 */
		media_options &= ~MEDIAOPT_10FL;
	}
	if (media_options & MEDIAOPT_100T4) {
		/* 100BASE-T4 units all use the MII bus. */
		media_options |= MEDIAOPT_MII;
		media_options &= ~MEDIAOPT_100T4;
	}

	/* Save our media options. */
	sc->ex_mediaopt = media_options;

#define	APPEND_MEDIA(str, bit, name)					\
	if (media_options & (bit)) {					\
		(void) strlcat(str, *str ? "," : "", sizeof (str));	\
		(void) strlcat(str, name, sizeof (str));		\
	}

	APPEND_MEDIA(sc->ex_medias, (MEDIAOPT_MII|MEDIAOPT_100TX), "mii");
	APPEND_MEDIA(sc->ex_medias, MEDIAOPT_10T, "tp-hdx,tp-fdx");
	APPEND_MEDIA(sc->ex_medias, MEDIAOPT_100FX, "fx-hdx,fx-fdx");
	APPEND_MEDIA(sc->ex_medias, MEDIAOPT_BNC, "bnc");
	APPEND_MEDIA(sc->ex_medias, MEDIAOPT_AUI, "aui");
	APPEND_MEDIA(sc->ex_medias, MEDIAOPT_10FL, "fl-hdx,fl-fdx");

	if (config & XCVR_SEL_100TX) {
		/* Only found on 90XB.  Don't use this, use AUTO instead! */
		config |= XCVR_SEL_AUTO;
		config &= ~XCVR_SEL_100TX;
	}

	default_media = (config & XCVR_SEL_MASK);

	/* Sanity check that there are any media! */
	if ((media_options & MEDIAOPT_MASK) == 0) {
		elxl_error(sc,
		    "No media present?  Attempting to use default.");
		/*
		 * This "default" may be non-sensical.  At worst it should
		 * cause a busted link.
		 */
		sc->ex_xcvr = default_media;
	}

	for (exm = ex_native_media; exm->exm_mpbit != 0; exm++) {
		if (media_options & exm->exm_mpbit) {
			if (exm->exm_xcvr == default_media) {
				/* preferred default is present, just use it */
				sc->ex_xcvr = default_media;
				return;
			}

			sc->ex_xcvr = exm->exm_xcvr;
			/* but keep trying for other more preferred options */
		}
	}
}

/*
 * Setup transmitter parameters.
 */
static void
elxl_setup_tx(elxl_t *sc)
{
	/*
	 * Disable reclaim threshold for 90xB, set free threshold to
	 * 6 * 256 = 1536 for 90x.
	 */
	if (sc->ex_conf & CONF_90XB)
		PUT_CMD(CMD_SET_TXRECLAIM | 255);
	else
		PUT8(REG_TXFREETHRESH, 6);

	/*
	 * We've seen underflows at the root cause of NIC hangs on
	 * older cards.  Use a store-and-forward model to prevent that.
	 */
	PUT_CMD(CMD_SET_TXSTART | EX_BUFSZ >> 2);
}

/*
 * Bring device up.
 */
static void
elxl_init(elxl_t *sc)
{
	if (sc->ex_suspended)
		return;

	WAIT_CMD(sc);
	elxl_stop(sc);

	PUT_CMD(CMD_RX_RESET);
	WAIT_CMD(sc);
	PUT_CMD(CMD_TX_RESET);
	WAIT_CMD(sc);

	/* Load Tx parameters. */
	elxl_setup_tx(sc);

	PUT32(REG_DMACTRL, GET32(REG_DMACTRL) | DMACTRL_UPRXEAREN);

	PUT_CMD(CMD_IND_ENABLE | INT_WATCHED);
	PUT_CMD(CMD_INT_ENABLE | INT_WATCHED);

	PUT_CMD(CMD_INT_ACK | 0xff);

	elxl_set_media(sc);
	elxl_set_rxfilter(sc);

	/* Configure for VLAN tag sizing. */
	SET_WIN(3);
	if (sc->ex_conf & CONF_90XB) {
		PUT16(W3_MAX_PKT_SIZE, EX_BUFSZ);
	} else {
		PUT16(W3_MAC_CONTROL, GET16(W3_MAC_CONTROL) |
		    MAC_CONTROL_ALLOW_LARGE);
	}

	PUT_CMD(CMD_SET_RXEARLY | (EX_BUFSZ >> 2));

	PUT_CMD(CMD_STATS_ENABLE);
	PUT_CMD(CMD_TX_ENABLE);
	PUT32(REG_UPLISTPTR, sc->ex_rxring.r_paddr);
	PUT_CMD(CMD_RX_ENABLE);
	PUT_CMD(CMD_UP_UNSTALL);
}

/*
 * Set multicast receive filter. Also take care of promiscuous mode.
 * Note that *some* of this hardware is fully capable of either a 256
 * or 64 bit multicast hash.  However, we can't determine what the
 * size of the hash table is easily, and so we are expected to be able
 * to resubmit the entire list of addresses each time.  This puts an
 * onerous burden on the driver to maintain its list of multicast
 * addresses.  Since multicast stuff is usually not that performance
 * sensitive, and since we don't usually have much of it, we are just
 * going to skip it.  We allow the upper layers to filter it, as
 * needed, by setting the all-multicast bit if the hardware can do it.
 * This also reduces our test burden.
 */
static void
elxl_set_rxfilter(elxl_t *sc)
{
	uint16_t mask = FILTER_UNICAST | FILTER_ALLBCAST;

	if (sc->ex_suspended)
		return;

	/*
	 * Set the station address and clear the station mask. The latter
	 * is needed for 90x cards, 0 is the default for 90xB cards.
	 */
	SET_WIN(2);
	for (int i = 0; i < ETHERADDRL; i++) {
		PUT8(W2_STATION_ADDRESS + i, sc->ex_curraddr[i]);
		PUT8(W2_STATION_MASK + i, 0);
	}

	if (sc->ex_mccount) {
		mask |= FILTER_ALLMULTI;
	}
	if (sc->ex_promisc) {
		mask |= FILTER_PROMISC;
	}
	PUT_CMD(CMD_SET_FILTER | mask);
}

static void
elxl_set_media(elxl_t *sc)
{
	uint32_t configreg;

	SET_WIN(4);
	PUT16(W4_MEDIASTAT, 0);
	PUT_CMD(CMD_BNC_DISABLE);
	drv_usecwait(800);

	/*
	 * Now turn on the selected media/transceiver.
	 */
	switch (sc->ex_xcvr) {
	case XCVR_SEL_10T:
		sc->ex_mii_active = B_FALSE;
		PUT16(W4_MEDIASTAT,
		    MEDIASTAT_JABGUARD_EN | MEDIASTAT_LINKBEAT_EN);
		drv_usecwait(800);
		break;

	case XCVR_SEL_BNC:
		sc->ex_mii_active = B_FALSE;
		PUT_CMD(CMD_BNC_ENABLE);
		drv_usecwait(800);
		break;

	case XCVR_SEL_100FX:
		sc->ex_mii_active = B_FALSE;	/* Is this really true? */
		PUT16(W4_MEDIASTAT, MEDIASTAT_LINKBEAT_EN);
		drv_usecwait(800);
		break;

	case XCVR_SEL_AUI:
		sc->ex_mii_active = B_FALSE;
		PUT16(W4_MEDIASTAT, MEDIASTAT_SQE_EN);
		drv_usecwait(800);
		break;

	case XCVR_SEL_AUTO:
	case XCVR_SEL_MII:
		/*
		 * This is due to paranoia.  If a card claims
		 * to default to MII, but doesn't have it set in
		 * media options, then we don't want to leave
		 * the MII active or we'll have problems derferencing
		 * the "mii handle".
		 */
		if (sc->ex_miih) {
			sc->ex_mii_active = B_TRUE;
		} else {
			sc->ex_mii_active = B_FALSE;
		}
		break;

	default:
		sc->ex_mii_active = B_FALSE;
		elxl_error(sc, "Impossible media setting!");
		break;
	}

	SET_WIN(3);
	configreg = GET32(W3_INTERNAL_CONFIG);

	configreg &= ~(XCVR_SEL_MASK);
	configreg |= (sc->ex_xcvr);

	PUT32(W3_INTERNAL_CONFIG, configreg);

	/*
	 * If we're not using MII, force the full-duplex setting.  MII
	 * based modes handle the full-duplex setting via the MII
	 * notify callback.
	 */
	if (!sc->ex_mii_active) {
		uint16_t mctl;
		mctl = GET16(W3_MAC_CONTROL);
		if (sc->ex_fdx) {
			mctl |= MAC_CONTROL_FDX;
		} else {
			mctl &= ~MAC_CONTROL_FDX;
		}
		PUT16(W3_MAC_CONTROL, mctl);
	}
}

/*
 * Get currently-selected media from card.
 * (if_media callback, may be called before interface is brought up).
 */
static void
elxl_linkcheck(void *arg)
{
	elxl_t		*sc = arg;
	uint16_t	stat;
	link_state_t	link;

	mutex_enter(&sc->ex_txlock);
	if (sc->ex_mii_active) {
		mutex_exit(&sc->ex_txlock);
		return;
	}
	if (sc->ex_running && !sc->ex_suspended) {
		switch (sc->ex_xcvr) {
		case XCVR_SEL_100FX:
			/* these media we can detect link on */
			SET_WIN(4);
			stat = GET16(W4_MEDIASTAT);
			if (stat & MEDIASTAT_LINKDETECT) {
				sc->ex_link = LINK_STATE_UP;
				sc->ex_speed = 100000000;
			} else {
				sc->ex_link = LINK_STATE_DOWN;
				sc->ex_speed = 0;
			}
			break;

		case XCVR_SEL_10T:
			/* these media we can detect link on */
			SET_WIN(4);
			stat = GET16(W4_MEDIASTAT);
			if (stat & MEDIASTAT_LINKDETECT) {
				sc->ex_link = LINK_STATE_UP;
				sc->ex_speed = 10000000;
			} else {
				sc->ex_link = LINK_STATE_DOWN;
				sc->ex_speed = 0;
			}
			break;

		case XCVR_SEL_BNC:
		case XCVR_SEL_AUI:
		default:
			/*
			 * For these we don't really know the answer,
			 * but if we lie then at least it won't cause
			 * ifconfig to turn off the RUNNING flag.
			 * This is necessary because we might
			 * transition from LINK_STATE_DOWN when
			 * switching media.
			 */
			sc->ex_speed = 10000000;
			sc->ex_link = LINK_STATE_UP;
			break;
		}
		SET_WIN(3);
		sc->ex_duplex = GET16(W3_MAC_CONTROL) & MAC_CONTROL_FDX ?
		    LINK_DUPLEX_FULL : LINK_DUPLEX_HALF;
	} else {
		sc->ex_speed = 0;
		sc->ex_duplex = LINK_DUPLEX_UNKNOWN;
		sc->ex_link = LINK_STATE_UNKNOWN;
	}
	link = sc->ex_link;
	mutex_exit(&sc->ex_txlock);

	mac_link_update(sc->ex_mach, link);
}

static int
elxl_m_promisc(void *arg, boolean_t on)
{
	elxl_t	*sc = arg;

	mutex_enter(&sc->ex_intrlock);
	mutex_enter(&sc->ex_txlock);
	sc->ex_promisc = on;
	elxl_set_rxfilter(sc);
	mutex_exit(&sc->ex_txlock);
	mutex_exit(&sc->ex_intrlock);
	return (0);
}

static int
elxl_m_multicst(void *arg, boolean_t add, const uint8_t *addr)
{
	elxl_t	*sc = arg;

	_NOTE(ARGUNUSED(addr));

	mutex_enter(&sc->ex_intrlock);
	mutex_enter(&sc->ex_txlock);
	if (add) {
		sc->ex_mccount++;
		if (sc->ex_mccount == 1) {
			elxl_set_rxfilter(sc);
		}
	} else {
		sc->ex_mccount--;
		if (sc->ex_mccount == 0) {
			elxl_set_rxfilter(sc);
		}
	}
	mutex_exit(&sc->ex_txlock);
	mutex_exit(&sc->ex_intrlock);
	return (0);
}

static int
elxl_m_unicst(void *arg, const uint8_t *addr)
{
	elxl_t	*sc = arg;

	mutex_enter(&sc->ex_intrlock);
	mutex_enter(&sc->ex_txlock);
	bcopy(addr, sc->ex_curraddr, ETHERADDRL);
	elxl_set_rxfilter(sc);
	mutex_exit(&sc->ex_txlock);
	mutex_exit(&sc->ex_intrlock);

	return (0);
}

static mblk_t *
elxl_m_tx(void *arg, mblk_t *mp)
{
	elxl_t		*sc = arg;
	ex_desc_t	*txd;
	ex_desc_t	*first;
	ex_desc_t	*tail;
	size_t		len;
	ex_ring_t	*r;
	ex_pd_t		*pd;
	uint32_t	cflags;
	mblk_t		*nmp;
	boolean_t	reenable = B_FALSE;
	boolean_t	reset = B_FALSE;
	uint32_t	paddr;

	r = &sc->ex_txring;
	mutex_enter(&sc->ex_txlock);
	if (sc->ex_suspended) {
		while (mp != NULL) {
			sc->ex_nocarrier++;
			nmp = mp->b_next;
			freemsg(mp);
			mp = nmp;
		}
		mutex_exit(&sc->ex_txlock);
		return (NULL);
	}

	for (int limit = (EX_NTX * 2); limit; limit--) {
		uint8_t stat = GET8(REG_TXSTATUS);
		if ((stat & TXSTATUS_COMPLETE) == 0) {
			break;
		}
		if (stat & TXSTATUS_MAXCOLLISIONS) {
			reenable = B_TRUE;
			sc->ex_excoll++;
		}
		if ((stat & TXSTATUS_ERRS) != 0) {
			reset = B_TRUE;
			if (stat & TXSTATUS_JABBER) {
				sc->ex_jabber++;
			}
			if (stat & TXSTATUS_RECLAIM_ERR) {
				sc->ex_txerr++;
			}
			if (stat & TXSTATUS_UNDERRUN) {
				sc->ex_uflo++;
			}
		}
		PUT8(REG_TXSTATUS, 0);
	}

	if (reset || reenable) {
		paddr = GET32(REG_DNLISTPTR);
		if (reset) {
			WAIT_CMD(sc);
			PUT_CMD(CMD_TX_RESET);
			WAIT_CMD(sc);
			elxl_setup_tx(sc);
		}
		PUT_CMD(CMD_TX_ENABLE);
		if (paddr) {
			PUT32(REG_DNLISTPTR, paddr);
		}
	}

	/* first reclaim any free descriptors */
	while (r->r_avail < r->r_count) {

		paddr = GET32(REG_DNLISTPTR);
		txd = r->r_head;
		if (paddr == txd->ed_descaddr) {
			/* still processing this one, we're done */
			break;
		}
		if (paddr == 0) {
			/* done processing the entire list! */
			r->r_head = NULL;
			r->r_tail = NULL;
			r->r_avail = r->r_count;
			break;
		}
		r->r_avail++;
		r->r_head = txd->ed_next;
	}

	if ((r->r_avail < r->r_count) && (GET32(REG_DNLISTPTR) != 0)) {
		PUT_CMD(CMD_DN_STALL);
		WAIT_CMD(sc);
	}

	first = NULL;
	tail = r->r_tail;

	/*
	 * If there is already a tx list, select the next desc on the list.
	 * Otherwise, just pick the first descriptor.
	 */
	txd = tail ? tail->ed_next : &r->r_desc[0];

	while ((mp != NULL) && (r->r_avail)) {

		nmp = mp->b_next;

		len = msgsize(mp);
		if (len > (ETHERMAX + VLAN_TAGSZ)) {
			sc->ex_txerr++;
			freemsg(mp);
			mp = nmp;
			continue;
		}

		cflags = 0;
		if ((sc->ex_conf & CONF_90XB) != 0) {
			uint32_t	pflags;
			mac_hcksum_get(mp, NULL, NULL, NULL, NULL, &pflags);
			if (pflags & HCK_IPV4_HDRCKSUM) {
				cflags |= EX_DPD_IPCKSUM;
			}
			if (pflags & HCK_FULLCKSUM) {
				cflags |= (EX_DPD_TCPCKSUM | EX_DPD_UDPCKSUM);
			}
		}

		/* Mark this descriptor is in use.  We're committed now. */
		mcopymsg(mp, txd->ed_buf);	/* frees the mblk! */
		r->r_avail--;
		mp = nmp;

		/* Accounting stuff. */
		sc->ex_opackets++;
		sc->ex_obytes += len;
		if (txd->ed_buf[0] & 0x1) {
			if (bcmp(txd->ed_buf, ex_broadcast, ETHERADDRL) != 0) {
				sc->ex_multixmt++;
			} else {
				sc->ex_brdcstxmt++;
			}
		}

		pd = txd->ed_pd;


		/*
		 * Zero pad the frame if its too short.  This
		 * also avoids a checksum offload bug.
		 */
		if (len < 30) {
			bzero(txd->ed_buf + len, ETHERMIN - len);
			len = ETHERMIN;
		}

		/*
		 * If this our first packet so far, record the head
		 * of the list.
		 */
		if (first == NULL) {
			first = txd;
		}

		(void) ddi_dma_sync(txd->ed_dmah, 0, 0, DDI_DMA_SYNC_FORDEV);

		PUT_PD(r, pd->pd_link, 0);
		PUT_PD(r, pd->pd_fsh, len | cflags);
		PUT_PD(r, pd->pd_addr, txd->ed_bufaddr);
		PUT_PD(r, pd->pd_len, len | EX_FR_LAST);

		/*
		 * Write the link into the previous descriptor.  Note that
		 * if this is the first packet (so no previous queued), this
		 * will be benign because the previous descriptor won't be
		 * on any tx list.  (Furthermore, we'll clear its link field
		 * when we do later use it.)
		 */
		PUT_PD(r, txd->ed_prev->ed_pd->pd_link, txd->ed_descaddr);
	}

	/*
	 * Are we submitting any packets?
	 */
	if (first != NULL) {
		/* Interrupt on the last packet. */
		PUT_PD(r, pd->pd_fsh, len | cflags | EX_DPD_DNIND);

		if (tail == NULL) {
			/* No packets pending, so its a new list head! */
			r->r_head = first;
		} else {
			pd = tail->ed_pd;
			/* We've added frames, so don't interrupt mid-list. */
			PUT_PD(r, pd->pd_fsh,
			    GET_PD(r, pd->pd_fsh) & ~(EX_DPD_DNIND));
		}
		/* Record the last descriptor. */
		r->r_tail = txd;

		/* flush the entire ring - we're stopped so its safe */
		(void) ddi_dma_sync(r->r_dmah, 0, 0, DDI_DMA_SYNC_FORDEV);
	}

	/* Restart transmitter. */
	if (sc->ex_txring.r_head) {
		PUT32(REG_DNLISTPTR, sc->ex_txring.r_head->ed_descaddr);
	}
	PUT_CMD(CMD_DN_UNSTALL);

	mutex_exit(&sc->ex_txlock);

	return (mp);
}

static mblk_t *
elxl_recv(elxl_t *sc, ex_desc_t *rxd, uint32_t stat)
{
	mblk_t		*mp = NULL;
	uint32_t	len;

	len = stat & EX_UPD_PKTLENMASK;
	if (stat & (EX_UPD_ERR_VLAN | EX_UPD_OVERFLOW)) {
		if (stat & EX_UPD_RUNT) {
			sc->ex_runt++;
		}
		if (stat & EX_UPD_OVERRUN) {
			sc->ex_oflo++;
		}
		if (stat & EX_UPD_CRCERR) {
			sc->ex_fcs++;
		}
		if (stat & EX_UPD_ALIGNERR) {
			sc->ex_align++;
		}
		if (stat & EX_UPD_OVERFLOW) {
			sc->ex_toolong++;
		}
		return (NULL);
	}
	if (len < sizeof (struct ether_header)) {
		sc->ex_runt++;
		return (NULL);
	}
	if (len > (ETHERMAX + VLAN_TAGSZ)) {
		/* Allow four bytes for the VLAN header */
		sc->ex_toolong++;
		return (NULL);
	}
	if ((mp = allocb(len + 14, BPRI_HI)) == NULL) {
		sc->ex_allocbfail++;
		return (NULL);
	}

	(void) ddi_dma_sync(rxd->ed_dmah, 0, 0, DDI_DMA_SYNC_FORKERNEL);
	mp->b_rptr += 14;
	mp->b_wptr = mp->b_rptr + len;
	bcopy(rxd->ed_buf, mp->b_rptr, len);

	sc->ex_ipackets++;
	sc->ex_ibytes += len;
	if (rxd->ed_buf[0] & 0x1) {
		if (bcmp(rxd->ed_buf, ex_broadcast, ETHERADDRL) != 0) {
			sc->ex_multircv++;
		} else {
			sc->ex_brdcstrcv++;
		}
	}

	/*
	 * Set the incoming checksum information for the packet.
	 */
	if (((sc->ex_conf & CONF_90XB) != 0) &&
	    ((stat & EX_UPD_IPCHECKED) != 0) &&
	    ((stat & (EX_UPD_CKSUMERR)) == 0)) {
		uint32_t	pflags = 0;
		if (stat & EX_UPD_IPCHECKED) {
			pflags |= HCK_IPV4_HDRCKSUM;
		}
		if (stat & (EX_UPD_TCPCHECKED | EX_UPD_UDPCHECKED)) {
			pflags |= (HCK_FULLCKSUM | HCK_FULLCKSUM_OK);
		}
		mac_hcksum_set(mp, 0, 0, 0, 0, pflags);
	}

	return (mp);
}

static int
elxl_m_start(void *arg)
{
	elxl_t	*sc = arg;

	mutex_enter(&sc->ex_intrlock);
	mutex_enter(&sc->ex_txlock);

	elxl_init(sc);
	sc->ex_running = B_TRUE;

	mutex_exit(&sc->ex_txlock);
	mutex_exit(&sc->ex_intrlock);

	if (sc->ex_miih) {
		mii_start(sc->ex_miih);
	}
	return (0);
}

static void
elxl_m_stop(void *arg)
{
	elxl_t	*sc = arg;

	if (sc->ex_miih) {
		mii_stop(sc->ex_miih);
	}

	mutex_enter(&sc->ex_intrlock);
	mutex_enter(&sc->ex_txlock);

	elxl_stop(sc);
	sc->ex_running = B_FALSE;

	mutex_exit(&sc->ex_txlock);
	mutex_exit(&sc->ex_intrlock);
}

static boolean_t
elxl_m_getcapab(void *arg, mac_capab_t cap, void *data)
{
	elxl_t		*sc = arg;
	switch (cap) {
	case MAC_CAPAB_HCKSUM: {
		uint32_t	*flags = data;
		if (sc->ex_conf & CONF_90XB) {
			*flags = HCKSUM_IPHDRCKSUM | HCKSUM_INET_FULL_V4;
			return (B_TRUE);
		}
		return (B_FALSE);
	}
	default:
		return (B_FALSE);
	}
}

static int
elxl_m_getprop(void *arg, const char *name, mac_prop_id_t num, uint_t sz,
    void *val)
{
	elxl_t		*sc = arg;
	int		rv;

	if (sc->ex_mii_active) {
		rv = mii_m_getprop(sc->ex_miih, name, num, sz, val);
		if (rv != ENOTSUP)
			return (rv);
	}

	switch (num) {
	case MAC_PROP_DUPLEX:
		*(uint8_t *)val = sc->ex_duplex;
		break;
	case MAC_PROP_SPEED:
		*(uint8_t *)val = sc->ex_speed;
		break;
	case MAC_PROP_STATUS:
		bcopy(&sc->ex_link, val, sizeof (link_state_t));
		break;

	case MAC_PROP_PRIVATE:
		if (strcmp(name, "_media") == 0) {
			char *str;

			switch (sc->ex_xcvr) {
			case XCVR_SEL_AUTO:
			case XCVR_SEL_MII:
				str = "mii";
				break;
			case XCVR_SEL_10T:
				str = sc->ex_fdx ? "tp-fdx" : "tp-hdx";
				break;
			case XCVR_SEL_BNC:
				str = "bnc";
				break;
			case XCVR_SEL_AUI:
				if (sc->ex_mediaopt & MEDIAOPT_10FL) {
					str = sc->ex_fdx ? "fl-fdx" : "fl-hdx";
				} else {
					str = "aui";
				}
				break;
			case XCVR_SEL_100FX:
				str = sc->ex_fdx ? "fx-fdx" : "fx-hdx";
				break;
			default:
				str = "unknown";
				break;
			}
			(void) snprintf(val, sz, "%s", str);
			return (0);
		}
		/*
		 * This available media property is a hack, and should
		 * be removed when we can provide proper support for
		 * querying it as proposed in PSARC 2009/235.  (At the
		 * moment the implementation lacks support for using
		 * MAC_PROP_POSSIBLE with private properties.)
		 */
		if (strcmp(name, "_available_media") == 0) {
			(void) snprintf(val, sz, "%s", sc->ex_medias);
			return (0);
		}
		break;
	}
	return (ENOTSUP);
}

static int
elxl_m_setprop(void *arg, const char *name, mac_prop_id_t num, uint_t sz,
    const void *val)
{
	elxl_t		*sc = arg;
	int		rv;

	if (sc->ex_mii_active) {
		rv = mii_m_setprop(sc->ex_miih, name, num, sz, val);
		if (rv != ENOTSUP) {
			return (rv);
		}
	}
	switch (num) {

	case MAC_PROP_PRIVATE:
		if (strcmp(name, "_media") == 0) {
			uint32_t mopt = sc->ex_mediaopt;

			if (strcmp(val, "mii") == 0) {
				if (mopt & MEDIAOPT_100TX) {
					sc->ex_xcvr = XCVR_SEL_AUTO;
				} else if (mopt & MEDIAOPT_MII)  {
					sc->ex_xcvr = XCVR_SEL_MII;
				} else {
					return (EINVAL);
				}
			} else if (strcmp(val, "tp-fdx") == 0) {
				/* select media option */
				if (mopt & MEDIAOPT_10T) {
					sc->ex_xcvr = XCVR_SEL_10T;
					sc->ex_fdx = B_TRUE;
				} else {
					return (EINVAL);
				}
			} else if (strcmp(val, "tp-hdx") == 0) {
				/* select media option */
				if (mopt & MEDIAOPT_10T) {
					sc->ex_xcvr = XCVR_SEL_10T;
					sc->ex_fdx = B_FALSE;
				} else {
					return (EINVAL);
				}
			} else if (strcmp(val, "fx-fdx") == 0) {
				if (mopt & MEDIAOPT_100FX) {
					sc->ex_xcvr = XCVR_SEL_100FX;
					sc->ex_fdx = B_TRUE;
				} else {
					return (EINVAL);
				}
			} else if (strcmp(val, "fx-hdx") == 0) {
				if (mopt & MEDIAOPT_100FX) {
					sc->ex_xcvr = XCVR_SEL_100FX;
					sc->ex_fdx = B_FALSE;
				} else {
					return (EINVAL);
				}
			} else if (strcmp(val, "bnc") == 0) {
				if (mopt & MEDIAOPT_BNC) {
					sc->ex_xcvr = XCVR_SEL_BNC;
					sc->ex_fdx = B_FALSE;
				} else {
					return (EINVAL);
				}
			} else if (strcmp(val, "aui") == 0) {
				if (mopt & MEDIAOPT_AUI) {
					sc->ex_xcvr = XCVR_SEL_AUI;
					sc->ex_fdx = B_FALSE;
				} else {
					return (EINVAL);
				}
			} else if (strcmp(val, "fl-fdx") == 0) {
				if (mopt & MEDIAOPT_10FL) {
					sc->ex_xcvr = XCVR_SEL_AUI;
					sc->ex_fdx = B_TRUE;
				} else {
					return (EINVAL);
				}
			} else if (strcmp(val, "fl-hdx") == 0) {
				if (mopt & MEDIAOPT_10FL) {
					sc->ex_xcvr = XCVR_SEL_AUI;
					sc->ex_fdx = B_FALSE;
				} else {
					return (EINVAL);
				}

			} else {
				return (EINVAL);
			}
			goto reset;
		}
		break;
	default:
		break;
	}

	return (ENOTSUP);

reset:
	mutex_enter(&sc->ex_intrlock);
	mutex_enter(&sc->ex_txlock);
	if (!sc->ex_suspended) {
		elxl_reset(sc);
		if (sc->ex_running) {
			elxl_init(sc);
		}
	}
	mutex_exit(&sc->ex_txlock);
	mutex_exit(&sc->ex_intrlock);
	return (0);
}

static void
elxl_m_propinfo(void *arg, const char *name, mac_prop_id_t num,
    mac_prop_info_handle_t prh)
{
	elxl_t		*sc = arg;

	if (sc->ex_mii_active)
		mii_m_propinfo(sc->ex_miih, name, num, prh);

	switch (num) {
	case MAC_PROP_DUPLEX:
	case MAC_PROP_SPEED:
	case MAC_PROP_STATUS:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		break;

	case MAC_PROP_PRIVATE:
		if (strcmp(name, "_available_media") == 0)
			mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		break;
	}
}

static int
elxl_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	elxl_t	*sc = arg;

	if (stat == MAC_STAT_IFSPEED) {
		elxl_getstats(sc);
	}

	if ((sc->ex_mii_active) &&
	    (mii_m_getstat(sc->ex_miih, stat, val) == 0)) {
		return (0);
	}

	switch (stat) {
	case MAC_STAT_IFSPEED:
		*val = sc->ex_speed;
		break;

	case ETHER_STAT_LINK_DUPLEX:
		*val = sc->ex_duplex;
		break;

	case MAC_STAT_MULTIRCV:
		*val = sc->ex_multircv;
		break;

	case MAC_STAT_BRDCSTRCV:
		*val = sc->ex_brdcstrcv;
		break;

	case MAC_STAT_MULTIXMT:
		*val = sc->ex_multixmt;
		break;

	case MAC_STAT_BRDCSTXMT:
		*val = sc->ex_brdcstxmt;
		break;

	case MAC_STAT_IPACKETS:
		*val = sc->ex_ipackets;
		break;

	case MAC_STAT_OPACKETS:
		*val = sc->ex_opackets;
		break;

	case MAC_STAT_RBYTES:
		*val = sc->ex_ibytes;
		break;
	case MAC_STAT_OBYTES:
		*val = sc->ex_obytes;
		break;

	case MAC_STAT_COLLISIONS:
	case ETHER_STAT_FIRST_COLLISIONS:
		*val = sc->ex_singlecol + sc->ex_multcol;
		break;

	case ETHER_STAT_MULTI_COLLISIONS:
		*val = sc->ex_multcol;
		break;

	case ETHER_STAT_TX_LATE_COLLISIONS:
		*val = sc->ex_latecol;
		break;

	case ETHER_STAT_ALIGN_ERRORS:
		*val = sc->ex_align;
		break;

	case ETHER_STAT_FCS_ERRORS:
		*val = sc->ex_fcs;
		break;

	case ETHER_STAT_SQE_ERRORS:
		*val = sc->ex_sqe;
		break;

	case ETHER_STAT_DEFER_XMTS:
		*val = sc->ex_defer;
		break;

	case ETHER_STAT_CARRIER_ERRORS:
		*val = sc->ex_nocarrier;
		break;

	case ETHER_STAT_TOOLONG_ERRORS:
		*val = sc->ex_toolong;
		break;

	case ETHER_STAT_EX_COLLISIONS:
		*val = sc->ex_excoll;
		break;

	case MAC_STAT_OVERFLOWS:
		*val = sc->ex_oflo;
		break;

	case MAC_STAT_UNDERFLOWS:
		*val = sc->ex_uflo;
		break;

	case ETHER_STAT_TOOSHORT_ERRORS:
		*val = sc->ex_runt;
		break;

	case ETHER_STAT_JABBER_ERRORS:
		*val = sc->ex_jabber;
		break;

	case MAC_STAT_NORCVBUF:
		*val = sc->ex_allocbfail;
		break;

	case MAC_STAT_OERRORS:
		*val = sc->ex_jabber + sc->ex_latecol + sc->ex_uflo;
		break;

	case MAC_STAT_IERRORS:
		*val = sc->ex_align + sc->ex_fcs + sc->ex_runt +
		    sc->ex_toolong + sc->ex_oflo + sc->ex_allocbfail;
		break;

	default:
		return (ENOTSUP);
	}
	return (0);
}

static uint_t
elxl_intr(caddr_t arg, caddr_t dontcare)
{
	elxl_t		*sc = (void *)arg;
	uint16_t	stat;
	mblk_t		*mphead = NULL;
	mblk_t		**mpp = &mphead;

	_NOTE(ARGUNUSED(dontcare));

	mutex_enter(&sc->ex_intrlock);
	if (sc->ex_suspended) {
		mutex_exit(&sc->ex_intrlock);
		return (DDI_INTR_UNCLAIMED);
	}

	stat = GET16(REG_CMD_STAT);

	if ((stat & INT_LATCH) == 0)  {
		mutex_exit(&sc->ex_intrlock);
		return (DDI_INTR_UNCLAIMED);
	}

	/*
	 * Acknowledge interrupts.
	 */
	PUT_CMD(CMD_INT_ACK | (stat & INT_WATCHED) | INT_LATCH);

	if (stat & INT_HOST_ERROR) {
		/* XXX: Potentially a good spot for FMA */
		elxl_error(sc, "Adapter failure (%x)", stat);
		mutex_enter(&sc->ex_txlock);
		elxl_reset(sc);
		if (sc->ex_running)
			elxl_init(sc);
		mutex_exit(&sc->ex_txlock);
		mutex_exit(&sc->ex_intrlock);
		return (DDI_INTR_CLAIMED);
	}
	if (stat & INT_UP_COMPLETE) {
		ex_ring_t		*r;
		ex_desc_t		*rxd;
		ex_pd_t			*pd;
		mblk_t			*mp;
		uint32_t		pktstat;

		r = &sc->ex_rxring;

		for (;;) {
			rxd = r->r_head;
			pd = rxd->ed_pd;

			(void) ddi_dma_sync(r->r_dmah, rxd->ed_off,
			    sizeof (ex_pd_t), DDI_DMA_SYNC_FORKERNEL);

			pktstat = GET_PD(r, pd->pd_status);

			if ((pktstat & EX_UPD_COMPLETE) == 0) {
				break;
			}

			/* Advance head to next packet. */
			r->r_head = r->r_head->ed_next;

			if ((mp = elxl_recv(sc, rxd, pktstat)) != NULL) {
				*mpp = mp;
				mpp = &mp->b_next;
			}

			/* clear the upComplete status, reset other fields */
			PUT_PD(r, pd->pd_status, 0);
			PUT_PD(r, pd->pd_len, EX_BUFSZ | EX_FR_LAST);
			PUT_PD(r, pd->pd_addr, rxd->ed_bufaddr);
			(void) ddi_dma_sync(r->r_dmah, rxd->ed_off,
			    sizeof (ex_pd_t), DDI_DMA_SYNC_FORDEV);
		}

		/*
		 * If the engine stalled processing (due to
		 * insufficient UPDs usually), restart it.
		 */
		if (GET32(REG_UPLISTPTR) == 0) {
			/*
			 * This seems that it can happen in an RX overrun
			 * situation.
			 */
			mutex_enter(&sc->ex_txlock);
			if (sc->ex_running)
				elxl_init(sc);
			mutex_exit(&sc->ex_txlock);
		}
		PUT_CMD(CMD_UP_UNSTALL);
	}

	mutex_exit(&sc->ex_intrlock);

	if (mphead) {
		mac_rx(sc->ex_mach, NULL, mphead);
	}
	if (stat & INT_STATS) {
		elxl_getstats(sc);
	}
	if (stat & INT_DN_COMPLETE) {
		mac_tx_update(sc->ex_mach);
	}

	return (DDI_INTR_CLAIMED);
}

static void
elxl_getstats(elxl_t *sc)
{
	mutex_enter(&sc->ex_txlock);
	if (sc->ex_suspended) {
		mutex_exit(&sc->ex_txlock);
		return;
	}

	SET_WIN(6);
	/*
	 * We count the packets and bytes elsewhere, but we need to
	 * read the registers to clear them.
	 */
	(void) GET8(W6_RX_FRAMES);
	(void) GET8(W6_TX_FRAMES);
	(void) GET8(W6_UPPER_FRAMES);
	(void) GET8(W6_RX_OVERRUNS);	/* counted by elxl_recv */
	(void) GET16(W6_RX_BYTES);
	(void) GET16(W6_TX_BYTES);

	sc->ex_defer += GET8(W6_DEFER);
	sc->ex_latecol += GET8(W6_TX_LATE_COL);
	sc->ex_singlecol += GET8(W6_SINGLE_COL);
	sc->ex_multcol += GET8(W6_MULT_COL);
	sc->ex_sqe += GET8(W6_SQE_ERRORS);
	sc->ex_nocarrier += GET8(W6_NO_CARRIER);

	SET_WIN(4);
	/* Note: we ought to report this somewhere... */
	(void) GET8(W4_BADSSD);

	mutex_exit(&sc->ex_txlock);
}

static void
elxl_reset(elxl_t *sc)
{
	PUT_CMD(CMD_GLOBAL_RESET);
	/*
	 * Some ASICs need a longer time (20 ms) to come properly out
	 * of reset.  Do not reduce this value.
	 *
	 * Note that this occurs only during attach and failure recovery,
	 * so it should be mostly harmless.
	 */
	drv_usecwait(20000);
	WAIT_CMD(sc);
}

static void
elxl_stop(elxl_t *sc)
{
	ASSERT(mutex_owned(&sc->ex_intrlock));
	ASSERT(mutex_owned(&sc->ex_txlock));

	if (sc->ex_suspended)
		return;

	PUT_CMD(CMD_RX_DISABLE);
	PUT_CMD(CMD_TX_DISABLE);
	PUT_CMD(CMD_BNC_DISABLE);

	elxl_reset_ring(&sc->ex_rxring, DDI_DMA_READ);
	elxl_reset_ring(&sc->ex_txring, DDI_DMA_WRITE);

	PUT_CMD(CMD_INT_ACK | INT_LATCH);
	/* Disable all interrupts. (0 means "none".) */
	PUT_CMD(CMD_INT_ENABLE | 0);
}

static void
elxl_suspend(elxl_t *sc)
{
	if (sc->ex_miih) {
		mii_suspend(sc->ex_miih);
	}

	mutex_enter(&sc->ex_intrlock);
	mutex_enter(&sc->ex_txlock);
	elxl_stop(sc);
	sc->ex_suspended = B_TRUE;
	mutex_exit(&sc->ex_txlock);
	mutex_exit(&sc->ex_intrlock);
}

static void
elxl_resume(dev_info_t *dip)
{
	elxl_t	*sc;

	/* This should always succeed. */
	sc = ddi_get_driver_private(dip);
	ASSERT(sc);

	mutex_enter(&sc->ex_intrlock);
	mutex_enter(&sc->ex_txlock);
	sc->ex_suspended = B_FALSE;
	elxl_reset(sc);
	if (sc->ex_running)
		elxl_init(sc);
	mutex_exit(&sc->ex_txlock);
	mutex_exit(&sc->ex_intrlock);

	if (sc->ex_miih) {
		mii_resume(sc->ex_miih);
	}
}

static void
elxl_detach(elxl_t *sc)
{
	if (sc->ex_miih) {
		/* Detach all PHYs */
		mii_free(sc->ex_miih);
	}
	if (sc->ex_linkcheck) {
		ddi_periodic_delete(sc->ex_linkcheck);
	}

	if (sc->ex_intrh != NULL) {
		(void) ddi_intr_disable(sc->ex_intrh);
		(void) ddi_intr_remove_handler(sc->ex_intrh);
		(void) ddi_intr_free(sc->ex_intrh);
		mutex_destroy(&sc->ex_intrlock);
		mutex_destroy(&sc->ex_txlock);
	}

	if (sc->ex_pcih) {
		pci_config_teardown(&sc->ex_pcih);
	}
	if (sc->ex_regsh) {
		ddi_regs_map_free(&sc->ex_regsh);
	}
	ex_free_ring(&sc->ex_txring);
	ex_free_ring(&sc->ex_rxring);

	kmem_free(sc, sizeof (*sc));
}

/*
 * Read EEPROM data.  If we can't unbusy the EEPROM, then zero will be
 * returned.  This will probably result in a bogus node address.
 */
static uint16_t
elxl_read_eeprom(elxl_t *sc, int offset)
{
	uint16_t data = 0;

	SET_WIN(0);
	if (elxl_eeprom_busy(sc))
		goto out;

	PUT16(W0_EE_CMD, EE_CMD_READ | (offset & 0x3f));
	if (elxl_eeprom_busy(sc))
		goto out;
	data = GET16(W0_EE_DATA);
out:
	return (data);
}

static int
elxl_eeprom_busy(elxl_t *sc)
{
	int i = 2000;

	while (i--) {
		if (!(GET16(W0_EE_CMD) & EE_CMD_BUSY))
			return (0);
		drv_usecwait(100);
	}
	elxl_error(sc, "Eeprom stays busy.");
	return (1);
}

static void
ex_mii_send_bits(struct ex_softc *sc, uint16_t bits, int cnt)
{
	uint16_t val;
	ASSERT(cnt > 0);

	PUT16(W4_PHYSMGMT, PHYSMGMT_DIR);
	drv_usecwait(1);

	for (int i = (1 << (cnt - 1)); i; i >>= 1) {
		if (bits & i) {
			val = PHYSMGMT_DIR | PHYSMGMT_DATA;
		} else {
			val = PHYSMGMT_DIR;
		}
		PUT16(W4_PHYSMGMT, val);
		drv_usecwait(1);
		PUT16(W4_PHYSMGMT, val | PHYSMGMT_CLK);
		drv_usecwait(1);
		PUT16(W4_PHYSMGMT, val);
		drv_usecwait(1);
	}
}

static void
ex_mii_sync(struct ex_softc *sc)
{
	/*
	 * We set the data bit output, and strobe the clock 32 times.
	 */
	PUT16(W4_PHYSMGMT, PHYSMGMT_DATA | PHYSMGMT_DIR);
	drv_usecwait(1);

	for (int i = 0; i < 32; i++) {
		PUT16(W4_PHYSMGMT, PHYSMGMT_DATA | PHYSMGMT_DIR | PHYSMGMT_CLK);
		drv_usecwait(1);
		PUT16(W4_PHYSMGMT, PHYSMGMT_DATA | PHYSMGMT_DIR);
		drv_usecwait(1);
	}
}

static uint16_t
elxl_mii_read(void *arg, uint8_t phy, uint8_t reg)
{
	elxl_t		*sc = arg;
	uint16_t	data;
	int		val;

	if ((sc->ex_conf & CONF_INTPHY) && phy != INTPHY_ID)
		return (0xffff);

	mutex_enter(&sc->ex_txlock);
	SET_WIN(4);

	ex_mii_sync(sc);

	ex_mii_send_bits(sc, 1, 2);	/* start */
	ex_mii_send_bits(sc, 2, 2);	/* read command */
	ex_mii_send_bits(sc, phy, 5);
	ex_mii_send_bits(sc, reg, 5);

	PUT16(W4_PHYSMGMT, 0);			/* switch to input */
	drv_usecwait(1);
	PUT16(W4_PHYSMGMT, PHYSMGMT_CLK);	/* turnaround time */
	drv_usecwait(1);
	PUT16(W4_PHYSMGMT, 0);
	drv_usecwait(1);

	PUT16(W4_PHYSMGMT, PHYSMGMT_CLK);	/* idle time */
	drv_usecwait(1);
	PUT16(W4_PHYSMGMT, 0);
	drv_usecwait(1);

	for (data = 0, val = 0x8000; val; val >>= 1) {
		if (GET16(W4_PHYSMGMT) & PHYSMGMT_DATA) {
			data |= val;
		}
		/* strobe the clock */
		PUT16(W4_PHYSMGMT, PHYSMGMT_CLK);
		drv_usecwait(1);
		PUT16(W4_PHYSMGMT, 0);
		drv_usecwait(1);
	}

	/* return to output mode */
	PUT16(W4_PHYSMGMT, PHYSMGMT_DIR);
	drv_usecwait(1);

	mutex_exit(&sc->ex_txlock);

	return (data);
}

static void
elxl_mii_write(void *arg, uint8_t phy, uint8_t reg, uint16_t data)
{
	elxl_t *sc = arg;

	if ((sc->ex_conf & CONF_INTPHY) && phy != INTPHY_ID)
		return;

	mutex_enter(&sc->ex_txlock);
	SET_WIN(4);

	ex_mii_sync(sc);
	ex_mii_send_bits(sc, 1, 2);	/* start */
	ex_mii_send_bits(sc, 1, 2);	/* write */
	ex_mii_send_bits(sc, phy, 5);
	ex_mii_send_bits(sc, reg, 5);
	ex_mii_send_bits(sc, 2, 2);	/* ack/turnaround */
	ex_mii_send_bits(sc, data, 16);

	/* return to output mode */
	PUT16(W4_PHYSMGMT, PHYSMGMT_DIR);
	drv_usecwait(1);

	mutex_exit(&sc->ex_txlock);
}

static void
elxl_mii_notify(void *arg, link_state_t link)
{
	elxl_t		*sc = arg;
	int		mctl;
	link_duplex_t	duplex;

	duplex = mii_get_duplex(sc->ex_miih);

	mutex_enter(&sc->ex_txlock);
	if (!sc->ex_mii_active) {
		/* If we're using some other legacy media, bail out now */
		mutex_exit(&sc->ex_txlock);
		return;
	}
	if (!sc->ex_suspended) {
		SET_WIN(3);
		mctl = GET16(W3_MAC_CONTROL);
		if (duplex == LINK_DUPLEX_FULL)
			mctl |= MAC_CONTROL_FDX;
		else
			mctl &= ~MAC_CONTROL_FDX;
		PUT16(W3_MAC_CONTROL, mctl);
	}
	mutex_exit(&sc->ex_txlock);

	mac_link_update(sc->ex_mach, link);
}

static int
elxl_ddi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		return (elxl_attach(dip));

	case DDI_RESUME:
		elxl_resume(dip);
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

static int
elxl_ddi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	elxl_t	*sc;

	sc = ddi_get_driver_private(dip);
	ASSERT(sc);

	switch (cmd) {
	case DDI_DETACH:
		if (mac_disable(sc->ex_mach) != 0) {
			return (DDI_FAILURE);
		}
		(void) mac_unregister(sc->ex_mach);
		elxl_detach(sc);
		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		elxl_suspend(sc);
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

static int
elxl_ddi_quiesce(dev_info_t *dip)
{
	elxl_t	*sc;

	sc = ddi_get_driver_private(dip);
	ASSERT(sc);

	if (!sc->ex_suspended)
		elxl_reset(sc);
	return (DDI_SUCCESS);
}

static void
elxl_error(elxl_t *sc, char *fmt, ...)
{
	va_list	ap;
	char	buf[256];

	va_start(ap, fmt);
	(void) vsnprintf(buf, sizeof (buf), fmt, ap);
	va_end(ap);

	cmn_err(CE_WARN, "%s%d: %s",
	    ddi_driver_name(sc->ex_dip), ddi_get_instance(sc->ex_dip), buf);
}
