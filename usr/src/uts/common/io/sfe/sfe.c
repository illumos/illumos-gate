/*
 *  sfe.c : DP83815/DP83816/SiS900 Fast Ethernet MAC driver for Solaris
 *
 * Copyright (c) 2002-2008 Masayuki Murayama.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the author nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/* Avoid undefined symbol for non IA architectures */
#pragma weak	inb
#pragma weak	outb

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * System Header files.
 */
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/modctl.h>
#include <sys/errno.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/byteorder.h>
#include <sys/ethernet.h>
#include <sys/pci.h>

#include "sfe_mii.h"
#include "sfe_util.h"
#include "sfereg.h"

char	ident[] = "sis900/dp83815 driver v" "2.6.1t30os";

/* Debugging support */
#ifdef DEBUG_LEVEL
static int sfe_debug = DEBUG_LEVEL;
#if DEBUG_LEVEL > 4
#define	CONS	"^"
#else
#define	CONS	"!"
#endif
#define	DPRINTF(n, args)	if (sfe_debug > (n)) cmn_err args
#else
#define	CONS	"!"
#define	DPRINTF(n, args)
#endif

/*
 * Useful macros and typedefs
 */
#define	ONESEC		(drv_usectohz(1*1000000))
#define	ROUNDUP2(x, a)	(((x) + (a) - 1) & ~((a) - 1))

/*
 * Our configuration
 */
#define	MAXTXFRAGS	1
#define	MAXRXFRAGS	1

#ifndef	TX_BUF_SIZE
#define	TX_BUF_SIZE	64
#endif
#ifndef	TX_RING_SIZE
#if MAXTXFRAGS == 1
#define	TX_RING_SIZE	TX_BUF_SIZE
#else
#define	TX_RING_SIZE	(TX_BUF_SIZE * 4)
#endif
#endif

#ifndef	RX_BUF_SIZE
#define	RX_BUF_SIZE	256
#endif
#ifndef	RX_RING_SIZE
#define	RX_RING_SIZE	RX_BUF_SIZE
#endif

#define	OUR_INTR_BITS	\
	(ISR_DPERR | ISR_SSERR | ISR_RMABT | ISR_RTABT | ISR_RXSOVR |	\
	ISR_TXURN | ISR_TXDESC | ISR_TXERR |	\
	ISR_RXORN | ISR_RXIDLE | ISR_RXOK | ISR_RXERR)

#define	USE_MULTICAST_HASHTBL

static int	sfe_tx_copy_thresh = 256;
static int	sfe_rx_copy_thresh = 256;

/* special PHY registers for SIS900 */
#define	MII_CONFIG1	0x0010
#define	MII_CONFIG2	0x0011
#define	MII_MASK	0x0013
#define	MII_RESV	0x0014

#define	PHY_MASK		0xfffffff0
#define	PHY_SIS900_INTERNAL	0x001d8000
#define	PHY_ICS1893		0x0015f440


#define	SFE_DESC_SIZE	16	/* including pads rounding up to power of 2 */

/*
 * Supported chips
 */
struct chip_info {
	uint16_t	venid;
	uint16_t	devid;
	char		*chip_name;
	int		chip_type;
#define	CHIPTYPE_DP83815	0
#define	CHIPTYPE_SIS900		1
};

/*
 * Chip dependent MAC state
 */
struct sfe_dev {
	/* misc HW information */
	struct chip_info	*chip;
	uint32_t		our_intr_bits;
	uint32_t		isr_pended;
	uint32_t		cr;
	uint_t			tx_drain_threshold;
	uint_t			tx_fill_threshold;
	uint_t			rx_drain_threshold;
	uint_t			rx_fill_threshold;
	uint8_t			revid;	/* revision from PCI configuration */
	boolean_t		(*get_mac_addr)(struct gem_dev *);
	uint8_t			mac_addr[ETHERADDRL];
	uint8_t			bridge_revid;
};

/*
 * Hardware information
 */
struct chip_info sfe_chiptbl[] = {
	{ 0x1039, 0x0900, "SiS900", CHIPTYPE_SIS900, },
	{ 0x100b, 0x0020, "DP83815/83816", CHIPTYPE_DP83815, },
	{ 0x1039, 0x7016, "SiS7016", CHIPTYPE_SIS900, },
};
#define	CHIPTABLESIZE (sizeof (sfe_chiptbl)/sizeof (struct chip_info))

/* ======================================================== */

/* mii operations */
static void  sfe_mii_sync_dp83815(struct gem_dev *);
static void  sfe_mii_sync_sis900(struct gem_dev *);
static uint16_t  sfe_mii_read_dp83815(struct gem_dev *, uint_t);
static uint16_t  sfe_mii_read_sis900(struct gem_dev *, uint_t);
static void sfe_mii_write_dp83815(struct gem_dev *, uint_t, uint16_t);
static void sfe_mii_write_sis900(struct gem_dev *, uint_t, uint16_t);
static void sfe_set_eq_sis630(struct gem_dev *dp);
/* nic operations */
static int sfe_reset_chip_sis900(struct gem_dev *);
static int sfe_reset_chip_dp83815(struct gem_dev *);
static int sfe_init_chip(struct gem_dev *);
static int sfe_start_chip(struct gem_dev *);
static int sfe_stop_chip(struct gem_dev *);
static int sfe_set_media(struct gem_dev *);
static int sfe_set_rx_filter_dp83815(struct gem_dev *);
static int sfe_set_rx_filter_sis900(struct gem_dev *);
static int sfe_get_stats(struct gem_dev *);
static int sfe_attach_chip(struct gem_dev *);

/* descriptor operations */
static int sfe_tx_desc_write(struct gem_dev *dp, int slot,
		    ddi_dma_cookie_t *dmacookie, int frags, uint64_t flags);
static void sfe_tx_start(struct gem_dev *dp, int startslot, int nslot);
static void sfe_rx_desc_write(struct gem_dev *dp, int slot,
		    ddi_dma_cookie_t *dmacookie, int frags);
static uint_t sfe_tx_desc_stat(struct gem_dev *dp, int slot, int ndesc);
static uint64_t sfe_rx_desc_stat(struct gem_dev *dp, int slot, int ndesc);

static void sfe_tx_desc_init(struct gem_dev *dp, int slot);
static void sfe_rx_desc_init(struct gem_dev *dp, int slot);
static void sfe_tx_desc_clean(struct gem_dev *dp, int slot);
static void sfe_rx_desc_clean(struct gem_dev *dp, int slot);

/* interrupt handler */
static uint_t sfe_interrupt(struct gem_dev *dp);

/* ======================================================== */

/* mapping attributes */
/* Data access requirements. */
static struct ddi_device_acc_attr sfe_dev_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

/* On sparc, Buffers should be native endian for speed */
static struct ddi_device_acc_attr sfe_buf_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,	/* native endianness */
	DDI_STRICTORDER_ACC
};

static ddi_dma_attr_t sfe_dma_attr_buf = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo */
	0xffffffffull,		/* dma_attr_addr_hi */
	0x00000fffull,		/* dma_attr_count_max */
	0, /* patched later */	/* dma_attr_align */
	0x000003fc,		/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0x00000fffull,		/* dma_attr_maxxfer */
	0xffffffffull,		/* dma_attr_seg */
	0, /* patched later */	/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};

static ddi_dma_attr_t sfe_dma_attr_desc = {
	DMA_ATTR_V0,		/* dma_attr_version */
	16,			/* dma_attr_addr_lo */
	0xffffffffull,		/* dma_attr_addr_hi */
	0xffffffffull,		/* dma_attr_count_max */
	16,			/* dma_attr_align */
	0x000003fc,		/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0xffffffffull,		/* dma_attr_maxxfer */
	0xffffffffull,		/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};

uint32_t sfe_use_pcimemspace = 0;

/* ======================================================== */
/*
 * HW manipulation routines
 */
/* ======================================================== */

#define	SFE_EEPROM_DELAY(dp)	\
	{ (void) INL(dp, EROMAR); (void) INL(dp, EROMAR); }
#define	EE_CMD_READ	6
#define	EE_CMD_SHIFT	6

static uint16_t
sfe_read_eeprom(struct gem_dev *dp, uint_t offset)
{
	int		eedi;
	int		i;
	uint16_t	ret;

	/* ensure de-assert chip select */
	OUTL(dp, EROMAR, 0);
	SFE_EEPROM_DELAY(dp);
	OUTL(dp, EROMAR, EROMAR_EESK);
	SFE_EEPROM_DELAY(dp);

	/* assert chip select */
	offset |= EE_CMD_READ << EE_CMD_SHIFT;

	for (i = 8; i >= 0; i--) {
		/* make command */
		eedi = ((offset >> i) & 1) << EROMAR_EEDI_SHIFT;

		/* send 1 bit */
		OUTL(dp, EROMAR, EROMAR_EECS | eedi);
		SFE_EEPROM_DELAY(dp);
		OUTL(dp, EROMAR, EROMAR_EECS | eedi | EROMAR_EESK);
		SFE_EEPROM_DELAY(dp);
	}

	OUTL(dp, EROMAR, EROMAR_EECS);

	ret = 0;
	for (i = 0; i < 16; i++) {
		/* Get 1 bit */
		OUTL(dp, EROMAR, EROMAR_EECS);
		SFE_EEPROM_DELAY(dp);
		OUTL(dp, EROMAR, EROMAR_EECS | EROMAR_EESK);
		SFE_EEPROM_DELAY(dp);

		ret = (ret << 1) | ((INL(dp, EROMAR) >> EROMAR_EEDO_SHIFT) & 1);
	}

	OUTL(dp, EROMAR, 0);
	SFE_EEPROM_DELAY(dp);

	return (ret);
}
#undef SFE_EEPROM_DELAY

static boolean_t
sfe_get_mac_addr_dp83815(struct gem_dev *dp)
{
	uint8_t		*mac;
	uint_t		val;
	int		i;

#define	BITSET(p, ix, v)	(p)[(ix)/8] |= ((v) ? 1 : 0) << ((ix) & 0x7)

	DPRINTF(4, (CE_CONT, CONS "%s: %s: called", dp->name, __func__));

	mac = dp->dev_addr.ether_addr_octet;

	/* first of all, clear MAC address buffer */
	bzero(mac, ETHERADDRL);

	/* get bit 0 */
	val = sfe_read_eeprom(dp, 0x6);
	BITSET(mac, 0, val & 1);

	/* get bit 1 - 16 */
	val = sfe_read_eeprom(dp, 0x7);
	for (i = 0; i < 16; i++) {
		BITSET(mac, 1 + i, val & (1 << (15 - i)));
	}

	/* get bit 17 -  32 */
	val = sfe_read_eeprom(dp, 0x8);
	for (i = 0; i < 16; i++) {
		BITSET(mac, 17 + i, val & (1 << (15 - i)));
	}

	/* get bit 33 -  47 */
	val = sfe_read_eeprom(dp, 0x9);
	for (i = 0; i < 15; i++) {
		BITSET(mac, 33 + i, val & (1 << (15 - i)));
	}

	return (B_TRUE);
#undef BITSET
}

static boolean_t
sfe_get_mac_addr_sis900(struct gem_dev *dp)
{
	uint_t		val;
	int		i;
	uint8_t		*mac;

	mac = dp->dev_addr.ether_addr_octet;

	for (i = 0; i < ETHERADDRL/2; i++) {
		val = sfe_read_eeprom(dp, 0x8 + i);
		*mac++ = (uint8_t)val;
		*mac++ = (uint8_t)(val >> 8);
	}

	return (B_TRUE);
}

static dev_info_t *
sfe_search_pci_dev_subr(dev_info_t *cur_node, int vendor_id, int device_id)
{
	dev_info_t	*child_id;
	dev_info_t	*ret;
	int		vid, did;

	if (cur_node == NULL) {
		return (NULL);
	}

	/* check brothers */
	do {
		vid = ddi_prop_get_int(DDI_DEV_T_ANY, cur_node,
		    DDI_PROP_DONTPASS, "vendor-id", -1);
		did = ddi_prop_get_int(DDI_DEV_T_ANY, cur_node,
		    DDI_PROP_DONTPASS, "device-id", -1);

		if (vid == vendor_id && did == device_id) {
			/* found */
			return (cur_node);
		}

		/* check children */
		if ((child_id = ddi_get_child(cur_node)) != NULL) {
			if ((ret = sfe_search_pci_dev_subr(child_id,
			    vendor_id, device_id)) != NULL) {
				return (ret);
			}
		}

	} while ((cur_node = ddi_get_next_sibling(cur_node)) != NULL);

	/* not found */
	return (NULL);
}

static dev_info_t *
sfe_search_pci_dev(int vendor_id, int device_id)
{
	return (sfe_search_pci_dev_subr(ddi_root_node(), vendor_id, device_id));
}

static boolean_t
sfe_get_mac_addr_sis630e(struct gem_dev *dp)
{
	int		i;
	dev_info_t	*isa_bridge;
	ddi_acc_handle_t isa_handle;
	int		reg;

	if (inb == NULL || outb == NULL) {
		/* this is not IA architecture */
		return (B_FALSE);
	}

	if ((isa_bridge = sfe_search_pci_dev(0x1039, 0x8)) == NULL) {
		cmn_err(CE_WARN, "%s: failed to find isa-bridge pci1039,8",
		    dp->name);
		return (B_FALSE);
	}

	if (pci_config_setup(isa_bridge, &isa_handle) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: ddi_regs_map_setup failed",
		    dp->name);
		return (B_FALSE);
	}

	/* enable to access CMOS RAM */
	reg = pci_config_get8(isa_handle, 0x48);
	pci_config_put8(isa_handle, 0x48, reg | 0x40);

	for (i = 0; i < ETHERADDRL; i++) {
		outb(0x70, 0x09 + i);
		dp->dev_addr.ether_addr_octet[i] = inb(0x71);
	}

	/* disable to access CMOS RAM */
	pci_config_put8(isa_handle, 0x48, reg);
	pci_config_teardown(&isa_handle);

	return (B_TRUE);
}

static boolean_t
sfe_get_mac_addr_sis635(struct gem_dev *dp)
{
	int		i;
	uint32_t	rfcr;
	uint16_t	v;
	struct sfe_dev	*lp = dp->private;

	DPRINTF(2, (CE_CONT, CONS "%s: %s: called", dp->name, __func__));
	rfcr = INL(dp, RFCR);

	OUTL(dp, CR, lp->cr | CR_RELOAD);
	OUTL(dp, CR, lp->cr);

	/* disable packet filtering before reading filter */
	OUTL(dp, RFCR, rfcr & ~RFCR_RFEN);

	/* load MAC addr from filter data register */
	for (i = 0; i < ETHERADDRL; i += 2) {
		OUTL(dp, RFCR,
		    (RFADDR_MAC_SIS900 + (i/2)) << RFCR_RFADDR_SHIFT_SIS900);
		v = INL(dp, RFDR);
		dp->dev_addr.ether_addr_octet[i] = (uint8_t)v;
		dp->dev_addr.ether_addr_octet[i+1] = (uint8_t)(v >> 8);
	}

	/* re-enable packet filtering */
	OUTL(dp, RFCR, rfcr | RFCR_RFEN);

	return (B_TRUE);
}

static boolean_t
sfe_get_mac_addr_sis962(struct gem_dev *dp)
{
	boolean_t	ret;
	int		i;

	ret = B_FALSE;

	/* rise request signal to access EEPROM */
	OUTL(dp, MEAR, EROMAR_EEREQ);
	for (i = 0; (INL(dp, MEAR) & EROMAR_EEGNT) == 0; i++) {
		if (i > 200) {
			/* failed to acquire eeprom */
			cmn_err(CE_NOTE,
			    CONS "%s: failed to access eeprom", dp->name);
			goto x;
		}
		drv_usecwait(10);
	}
	ret = sfe_get_mac_addr_sis900(dp);
x:
	/* release EEPROM */
	OUTL(dp, MEAR, EROMAR_EEDONE);

	return (ret);
}

static int
sfe_reset_chip_sis900(struct gem_dev *dp)
{
	int		i;
	uint32_t	done;
	uint32_t	val;
	struct sfe_dev	*lp = dp->private;

	DPRINTF(4, (CE_CONT, CONS "%s: %s called", dp->name, __func__));

	/* invalidate mac addr cache */
	bzero(lp->mac_addr, sizeof (lp->mac_addr));

	lp->cr = 0;

	/* inhibit interrupt */
	OUTL(dp, IMR, 0);
	lp->isr_pended |= INL(dp, ISR) & lp->our_intr_bits;

	OUTLINL(dp, RFCR, 0);

	OUTL(dp, CR, CR_RST | CR_TXR | CR_RXR);
	drv_usecwait(10);

	done = 0;
	for (i = 0; done != (ISR_TXRCMP | ISR_RXRCMP); i++) {
		if (i > 1000) {
			cmn_err(CE_WARN, "%s: chip reset timeout", dp->name);
			return (GEM_FAILURE);
		}
		done |= INL(dp, ISR) & (ISR_TXRCMP | ISR_RXRCMP);
		drv_usecwait(10);
	}

	if (lp->revid == SIS630ET_900_REV) {
		lp->cr |= CR_ACCESSMODE;
		OUTL(dp, CR, lp->cr | INL(dp, CR));
	}

	/* Configuration register: enable PCI parity */
	DPRINTF(2, (CE_CONT, CONS "%s: cfg:%b",
	    dp->name, INL(dp, CFG), CFG_BITS_SIS900));
	val = 0;
	if (lp->revid >= SIS635A_900_REV ||
	    lp->revid == SIS900B_900_REV) {
		/* what is this ? */
		val |= CFG_RND_CNT;
	}
	OUTL(dp, CFG, val);
	DPRINTF(2, (CE_CONT, CONS "%s: cfg:%b", dp->name,
	    INL(dp, CFG), CFG_BITS_SIS900));

	return (GEM_SUCCESS);
}

static int
sfe_reset_chip_dp83815(struct gem_dev *dp)
{
	int		i;
	uint32_t	val;
	struct sfe_dev	*lp = dp->private;

	DPRINTF(4, (CE_CONT, CONS "%s: %s called", dp->name, __func__));

	/* invalidate mac addr cache */
	bzero(lp->mac_addr, sizeof (lp->mac_addr));

	lp->cr = 0;

	/* inhibit interrupts */
	OUTL(dp, IMR, 0);
	lp->isr_pended |= INL(dp, ISR) & lp->our_intr_bits;

	OUTL(dp, RFCR, 0);

	OUTL(dp, CR, CR_RST);
	drv_usecwait(10);

	for (i = 0; INL(dp, CR) & CR_RST; i++) {
		if (i > 100) {
			cmn_err(CE_WARN, "!%s: chip reset timeout", dp->name);
			return (GEM_FAILURE);
		}
		drv_usecwait(10);
	}
	DPRINTF(0, (CE_CONT, "!%s: chip reset in %duS", dp->name, i*10));

	OUTL(dp, CCSR, CCSR_PMESTS);
	OUTL(dp, CCSR, 0);

	/* Configuration register: enable PCI parity */
	DPRINTF(2, (CE_CONT, CONS "%s: cfg:%b",
	    dp->name, INL(dp, CFG), CFG_BITS_DP83815));
	val = INL(dp, CFG) & (CFG_ANEG_SEL | CFG_PHY_CFG);
	OUTL(dp, CFG, val | CFG_PAUSE_ADV);
	DPRINTF(2, (CE_CONT, CONS "%s: cfg:%b", dp->name,
	    INL(dp, CFG), CFG_BITS_DP83815));

	return (GEM_SUCCESS);
}

static int
sfe_init_chip(struct gem_dev *dp)
{
	/* Configuration register: have been set up in sfe_chip_reset */

	/* PCI test control register: do nothing */

	/* Interrupt status register : do nothing */

	/* Interrupt mask register: clear, but leave lp->our_intr_bits */
	OUTL(dp, IMR, 0);

	/* Enhanced PHY Access register (sis900): do nothing */

	/* Transmit Descriptor Pointer register: base addr of TX ring */
	OUTL(dp, TXDP, dp->tx_ring_dma);

	/* Receive descriptor pointer register: base addr of RX ring */
	OUTL(dp, RXDP, dp->rx_ring_dma);

	return (GEM_SUCCESS);
}

static uint_t
sfe_mcast_hash(struct gem_dev *dp, uint8_t *addr)
{
	return (gem_ether_crc_be(addr, ETHERADDRL));
}

#ifdef DEBUG_LEVEL
static void
sfe_rxfilter_dump(struct gem_dev *dp, int start, int end)
{
	int		i;
	int		j;
	uint16_t	ram[0x10];

	cmn_err(CE_CONT, "!%s: rx filter ram dump:", dp->name);
#define	WORDS_PER_LINE	4
	for (i = start; i < end; i += WORDS_PER_LINE*2) {
		for (j = 0; j < WORDS_PER_LINE; j++) {
			OUTL(dp, RFCR, RFADDR_MAC_DP83815 + i + j*2);
			ram[j] = INL(dp, RFDR);
		}

		cmn_err(CE_CONT, "!0x%02x: 0x%04x 0x%04x 0x%04x 0x%04x",
		    i, ram[0], ram[1], ram[2], ram[3]);
		}

#undef	WORDS_PER_LINE
}
#endif

static uint_t	sfe_rf_perfect_base_dp83815[] = {
	RFADDR_PMATCH0_DP83815,
	RFADDR_PMATCH1_DP83815,
	RFADDR_PMATCH2_DP83815,
	RFADDR_PMATCH3_DP83815,
};

static int
sfe_set_rx_filter_dp83815(struct gem_dev *dp)
{
	int		i;
	int		j;
	uint32_t	mode;
	uint8_t		*mac = dp->cur_addr.ether_addr_octet;
	uint16_t	hash_tbl[32];
	struct sfe_dev	*lp = dp->private;

	DPRINTF(1, (CE_CONT, CONS "%s: %s: called, mc_count:%d, mode:0x%b",
	    dp->name, __func__, dp->mc_count, dp->rxmode, RXMODE_BITS));

#if DEBUG_LEVEL > 0
	for (i = 0; i < dp->mc_count; i++) {
		cmn_err(CE_CONT,
		"!%s: adding mcast(%d) %02x:%02x:%02x:%02x:%02x:%02x",
		    dp->name, i,
		    dp->mc_list[i].addr.ether_addr_octet[0],
		    dp->mc_list[i].addr.ether_addr_octet[1],
		    dp->mc_list[i].addr.ether_addr_octet[2],
		    dp->mc_list[i].addr.ether_addr_octet[3],
		    dp->mc_list[i].addr.ether_addr_octet[4],
		    dp->mc_list[i].addr.ether_addr_octet[5]);
	}
#endif
	if ((dp->rxmode & RXMODE_ENABLE) == 0) {
		/* disable rx filter */
		OUTL(dp, RFCR, 0);
		return (GEM_SUCCESS);
	}

	/*
	 * Set Receive filter control register
	 */
	if (dp->rxmode & RXMODE_PROMISC) {
		/* all broadcast, all multicast, all physical */
		mode = RFCR_AAB | RFCR_AAM | RFCR_AAP;
	} else if ((dp->rxmode & RXMODE_ALLMULTI) || dp->mc_count > 16*32/2) {
		/* all broadcast, all multicast, physical for the chip */
		mode = RFCR_AAB | RFCR_AAM | RFCR_APM_DP83815;
	} else if (dp->mc_count > 4) {
		/*
		 * Use multicast hash table,
		 * accept all broadcast and physical for the chip.
		 */
		mode = RFCR_AAB | RFCR_MHEN_DP83815 | RFCR_APM_DP83815;

		bzero(hash_tbl, sizeof (hash_tbl));
		for (i = 0; i < dp->mc_count; i++) {
			j = dp->mc_list[i].hash >> (32 - 9);
			hash_tbl[j / 16] |= 1 << (j % 16);
		}
	} else {
		/*
		 * Use pattern mach filter for multicast address,
		 * accept all broadcast and physical for the chip
		 */
		/* need to enable corresponding pattern registers */
		mode = RFCR_AAB | RFCR_APM_DP83815 |
		    (((1 << dp->mc_count) - 1) << RFCR_APAT_SHIFT);
	}

#if DEBUG_LEVEL > 1
	cmn_err(CE_CONT,
	    "!%s: mac %02x:%02x:%02x:%02x:%02x:%02x"
	    "  cache %02x:%02x:%02x:%02x:%02x:%02x",
	    dp->name, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
	    lp->mac_addr[0], lp->mac_addr[1],
	    lp->mac_addr[2], lp->mac_addr[3],
	    lp->mac_addr[4], lp->mac_addr[5]);
#endif
	if (bcmp(mac, lp->mac_addr, ETHERADDRL) != 0) {
		/*
		 * XXX - need to *disable* rx filter to load mac address for
		 * the chip. otherwise, we cannot setup rxfilter correctly.
		 */
		/* setup perfect match register for my station address */
		for (i = 0; i < ETHERADDRL; i += 2) {
			OUTL(dp, RFCR, RFADDR_MAC_DP83815 + i);
			OUTL(dp, RFDR, (mac[i+1] << 8) | mac[i]);
		}

		bcopy(mac, lp->mac_addr, ETHERADDRL);
	}

#if DEBUG_LEVEL > 3
	/* clear pattern ram */
	for (j = 0x200; j < 0x380; j += 2) {
		OUTL(dp, RFCR, j);
		OUTL(dp, RFDR, 0);
	}
#endif
	if (mode & RFCR_APAT_DP83815) {
		/* setup multicast address into pattern match registers */
		for (j = 0; j < dp->mc_count; j++) {
			mac = &dp->mc_list[j].addr.ether_addr_octet[0];
			for (i = 0; i < ETHERADDRL; i += 2) {
				OUTL(dp, RFCR,
				    sfe_rf_perfect_base_dp83815[j] + i*2);
				OUTL(dp, RFDR, (mac[i+1] << 8) | mac[i]);
			}
		}

		/* setup pattern count registers */
		OUTL(dp, RFCR, RFADDR_PCOUNT01_DP83815);
		OUTL(dp, RFDR, (ETHERADDRL << 8) | ETHERADDRL);
		OUTL(dp, RFCR, RFADDR_PCOUNT23_DP83815);
		OUTL(dp, RFDR, (ETHERADDRL << 8) | ETHERADDRL);
	}

	if (mode & RFCR_MHEN_DP83815) {
		/* Load Multicast hash table */
		for (i = 0; i < 32; i++) {
			/* for DP83815, index is in byte */
			OUTL(dp, RFCR, RFADDR_MULTICAST_DP83815 + i*2);
			OUTL(dp, RFDR, hash_tbl[i]);
		}
	}
#if DEBUG_LEVEL > 2
	sfe_rxfilter_dump(dp, 0, 0x10);
	sfe_rxfilter_dump(dp, 0x200, 0x380);
#endif
	/* Set rx filter mode and enable rx filter */
	OUTL(dp, RFCR, RFCR_RFEN | mode);

	return (GEM_SUCCESS);
}

static int
sfe_set_rx_filter_sis900(struct gem_dev *dp)
{
	int		i;
	uint32_t	mode;
	uint16_t	hash_tbl[16];
	uint8_t		*mac = dp->cur_addr.ether_addr_octet;
	int		hash_size;
	int		hash_shift;
	struct sfe_dev	*lp = dp->private;

	DPRINTF(4, (CE_CONT, CONS "%s: %s: called", dp->name, __func__));

	if ((dp->rxmode & RXMODE_ENABLE) == 0) {
		/* disable rx filter */
		OUTLINL(dp, RFCR, 0);
		return (GEM_SUCCESS);
	}

	/*
	 * determine hardware hash table size in word.
	 */
	hash_shift = 25;
	if (lp->revid >= SIS635A_900_REV || lp->revid == SIS900B_900_REV) {
		hash_shift = 24;
	}
	hash_size = (1 << (32 - hash_shift)) / 16;
	bzero(hash_tbl, sizeof (hash_tbl));

	/* Set Receive filter control register */

	if (dp->rxmode & RXMODE_PROMISC) {
		/* all broadcast, all multicast, all physical */
		mode = RFCR_AAB | RFCR_AAM | RFCR_AAP;
	} else if ((dp->rxmode & RXMODE_ALLMULTI) ||
	    dp->mc_count > hash_size*16/2) {
		/* all broadcast, all multicast, physical for the chip */
		mode = RFCR_AAB | RFCR_AAM;
	} else {
		/* all broadcast, physical for the chip */
		mode = RFCR_AAB;
	}

	/* make hash table */
	for (i = 0; i < dp->mc_count; i++) {
		uint_t	h;
		h = dp->mc_list[i].hash >> hash_shift;
		hash_tbl[h / 16] |= 1 << (h % 16);
	}

	if (bcmp(mac, lp->mac_addr, ETHERADDRL) != 0) {
		/* Disable Rx filter and load mac address */
		for (i = 0; i < ETHERADDRL/2; i++) {
			/* For sis900, index is in word */
			OUTLINL(dp, RFCR,
			    (RFADDR_MAC_SIS900+i) << RFCR_RFADDR_SHIFT_SIS900);
			OUTLINL(dp, RFDR, (mac[i*2+1] << 8) | mac[i*2]);
		}

		bcopy(mac, lp->mac_addr, ETHERADDRL);
	}

	/* Load Multicast hash table */
	for (i = 0; i < hash_size; i++) {
		/* For sis900, index is in word */
		OUTLINL(dp, RFCR,
		    (RFADDR_MULTICAST_SIS900 + i) << RFCR_RFADDR_SHIFT_SIS900);
		OUTLINL(dp, RFDR, hash_tbl[i]);
	}

	/* Load rx filter mode and enable rx filter */
	OUTLINL(dp, RFCR, RFCR_RFEN | mode);

	return (GEM_SUCCESS);
}

static int
sfe_start_chip(struct gem_dev *dp)
{
	struct sfe_dev	*lp = dp->private;

	DPRINTF(4, (CE_CONT, CONS "%s: %s: called", dp->name, __func__));

	/*
	 * setup interrupt mask, which shouldn't include ISR_TOK
	 * to improve performance.
	 */
	lp->our_intr_bits = OUR_INTR_BITS;

	/* enable interrupt */
	if ((dp->misc_flag & GEM_NOINTR) == 0) {
		OUTL(dp, IER, 1);
		OUTL(dp, IMR, lp->our_intr_bits);
	}

	/* Kick RX */
	OUTL(dp, CR, lp->cr | CR_RXE);

	return (GEM_SUCCESS);
}

/*
 * Stop nic core gracefully.
 */
static int
sfe_stop_chip(struct gem_dev *dp)
{
	struct sfe_dev	*lp = dp->private;
	uint32_t	done;
	int		i;
	uint32_t	val;

	DPRINTF(4, (CE_CONT, CONS "%s: %s: called", dp->name, __func__));

	/*
	 * Although we inhibit interrupt here, we don't clear soft copy of
	 * interrupt mask to avoid bogus interrupts.
	 */
	OUTL(dp, IMR, 0);

	/* stop TX and RX immediately */
	OUTL(dp, CR, lp->cr | CR_TXR | CR_RXR);

	done = 0;
	for (i = 0; done != (ISR_RXRCMP | ISR_TXRCMP); i++) {
		if (i > 1000) {
			/*
			 * As gem layer will call sfe_reset_chip(),
			 * we don't neet to reset futher
			 */
			cmn_err(CE_NOTE, "!%s: %s: Tx/Rx reset timeout",
			    dp->name, __func__);

			return (GEM_FAILURE);
		}
		val = INL(dp, ISR);
		done |= val & (ISR_RXRCMP | ISR_TXRCMP);
		lp->isr_pended |= val & lp->our_intr_bits;
		drv_usecwait(10);
	}

	return (GEM_SUCCESS);
}

#ifndef	__sparc
/*
 * Stop nic core gracefully for quiesce
 */
static int
sfe_stop_chip_quiesce(struct gem_dev *dp)
{
	struct sfe_dev	*lp = dp->private;
	uint32_t	done;
	int		i;
	uint32_t	val;

	/*
	 * Although we inhibit interrupt here, we don't clear soft copy of
	 * interrupt mask to avoid bogus interrupts.
	 */
	OUTL(dp, IMR, 0);

	/* stop TX and RX immediately */
	OUTL(dp, CR, CR_TXR | CR_RXR);

	done = 0;
	for (i = 0; done != (ISR_RXRCMP | ISR_TXRCMP); i++) {
		if (i > 1000) {
			/*
			 * As gem layer will call sfe_reset_chip(),
			 * we don't neet to reset futher
			 */

			return (DDI_FAILURE);
		}
		val = INL(dp, ISR);
		done |= val & (ISR_RXRCMP | ISR_TXRCMP);
		lp->isr_pended |= val & lp->our_intr_bits;
		drv_usecwait(10);
	}
	return (DDI_SUCCESS);
}
#endif

/*
 * Setup media mode
 */
static uint_t
sfe_mxdma_value[] = { 512, 4, 8, 16, 32, 64, 128, 256, };

static uint_t
sfe_encode_mxdma(uint_t burstsize)
{
	int	i;

	if (burstsize > 256) {
		/* choose 512 */
		return (0);
	}

	for (i = 1; i < 8; i++) {
		if (burstsize <= sfe_mxdma_value[i]) {
			break;
		}
	}
	return (i);
}

static int
sfe_set_media(struct gem_dev *dp)
{
	uint32_t	txcfg;
	uint32_t	rxcfg;
	uint32_t	pcr;
	uint32_t	val;
	uint32_t	txmxdma;
	uint32_t	rxmxdma;
	struct sfe_dev	*lp = dp->private;
#ifdef DEBUG_LEVEL
	extern int	gem_speed_value[];
#endif
	DPRINTF(2, (CE_CONT, CONS "%s: %s: %s duplex, %d Mbps",
	    dp->name, __func__,
	    dp->full_duplex ? "full" : "half", gem_speed_value[dp->speed]));

	/* initialize txcfg and rxcfg */
	txcfg = TXCFG_ATP;
	if (dp->full_duplex) {
		txcfg |= (TXCFG_CSI | TXCFG_HBI);
	}
	rxcfg = RXCFG_AEP | RXCFG_ARP;
	if (dp->full_duplex) {
		rxcfg |= RXCFG_ATX;
	}

	/* select txmxdma and rxmxdma, maxmum burst length */
	if (lp->chip->chip_type == CHIPTYPE_SIS900) {
#ifdef DEBUG_SIS900_EDB
		val = CFG_EDB_MASTER;
#else
		val = INL(dp, CFG) & CFG_EDB_MASTER;
#endif
		if (val) {
			/*
			 * sis900 built-in cores:
			 * max burst length must be fixed to 64
			 */
			txmxdma = 64;
			rxmxdma = 64;
		} else {
			/*
			 * sis900 pci chipset:
			 * the vendor recommended to fix max burst length
			 * to 512
			 */
			txmxdma = 512;
			rxmxdma = 512;
		}
	} else {
		/*
		 * NS dp83815/816:
		 * use user defined or default for tx/rx max burst length
		 */
		txmxdma = max(dp->txmaxdma, 256);
		rxmxdma = max(dp->rxmaxdma, 256);
	}


	/* tx high water mark */
	lp->tx_drain_threshold = ROUNDUP2(dp->txthr, TXCFG_FIFO_UNIT);

	/* determine tx_fill_threshold accroding drain threshold */
	lp->tx_fill_threshold =
	    TXFIFOSIZE - lp->tx_drain_threshold - TXCFG_FIFO_UNIT;

	/* tune txmxdma not to exceed tx_fill_threshold */
	for (; ; ) {
		/* normalize txmxdma requested */
		val = sfe_encode_mxdma(txmxdma);
		txmxdma = sfe_mxdma_value[val];

		if (txmxdma <= lp->tx_fill_threshold) {
			break;
		}
		/* select new txmxdma */
		txmxdma = txmxdma / 2;
	}
	txcfg |= val << TXCFG_MXDMA_SHIFT;

	/* encode rxmxdma, maxmum burst length for rx */
	val = sfe_encode_mxdma(rxmxdma);
	rxcfg |= val << RXCFG_MXDMA_SHIFT;
	rxmxdma = sfe_mxdma_value[val];

	/* receive starting threshold - it have only 5bit-wide field */
	val = ROUNDUP2(max(dp->rxthr, ETHERMIN), RXCFG_FIFO_UNIT);
	lp->rx_drain_threshold =
	    min(val, (RXCFG_DRTH >> RXCFG_DRTH_SHIFT) * RXCFG_FIFO_UNIT);

	DPRINTF(0, (CE_CONT,
	    "%s: %s: tx: drain:%d(rest %d) fill:%d mxdma:%d,"
	    " rx: drain:%d mxdma:%d",
	    dp->name, __func__,
	    lp->tx_drain_threshold, TXFIFOSIZE - lp->tx_drain_threshold,
	    lp->tx_fill_threshold, txmxdma,
	    lp->rx_drain_threshold, rxmxdma));

	ASSERT(lp->tx_drain_threshold < 64*TXCFG_FIFO_UNIT);
	ASSERT(lp->tx_fill_threshold < 64*TXCFG_FIFO_UNIT);
	ASSERT(lp->rx_drain_threshold < 32*RXCFG_FIFO_UNIT);

	txcfg |= ((lp->tx_fill_threshold/TXCFG_FIFO_UNIT) << TXCFG_FLTH_SHIFT)
	    | (lp->tx_drain_threshold/TXCFG_FIFO_UNIT);
	OUTL(dp, TXCFG, txcfg);

	rxcfg |= ((lp->rx_drain_threshold/RXCFG_FIFO_UNIT) << RXCFG_DRTH_SHIFT);
	if (lp->chip->chip_type == CHIPTYPE_DP83815) {
		rxcfg |= RXCFG_ALP_DP83815;
	}
	OUTL(dp, RXCFG, rxcfg);

	DPRINTF(0, (CE_CONT, CONS "%s: %s: txcfg:%b rxcfg:%b",
	    dp->name, __func__,
	    txcfg, TXCFG_BITS, rxcfg, RXCFG_BITS));

	/* Flow control */
	if (lp->chip->chip_type == CHIPTYPE_DP83815) {
		pcr = INL(dp, PCR);
		switch (dp->flow_control) {
		case FLOW_CONTROL_SYMMETRIC:
		case FLOW_CONTROL_RX_PAUSE:
			OUTL(dp, PCR, pcr | PCR_PSEN | PCR_PS_MCAST);
			break;

		default:
			OUTL(dp, PCR,
			    pcr & ~(PCR_PSEN | PCR_PS_MCAST | PCR_PS_DA));
			break;
		}
		DPRINTF(2, (CE_CONT, CONS "%s: PCR: %b", dp->name,
		    INL(dp, PCR), PCR_BITS));

	} else if (lp->chip->chip_type == CHIPTYPE_SIS900) {
		switch (dp->flow_control) {
		case FLOW_CONTROL_SYMMETRIC:
		case FLOW_CONTROL_RX_PAUSE:
			OUTL(dp, FLOWCTL, FLOWCTL_FLOWEN);
			break;
		default:
			OUTL(dp, FLOWCTL, 0);
			break;
		}
		DPRINTF(2, (CE_CONT, CONS "%s: FLOWCTL: %b",
		    dp->name, INL(dp, FLOWCTL), FLOWCTL_BITS));
	}
	return (GEM_SUCCESS);
}

static int
sfe_get_stats(struct gem_dev *dp)
{
	/* do nothing */
	return (GEM_SUCCESS);
}

/*
 * descriptor manipulations
 */
static int
sfe_tx_desc_write(struct gem_dev *dp, int slot,
		ddi_dma_cookie_t *dmacookie, int frags, uint64_t flags)
{
	uint32_t		mark;
	struct sfe_desc		*tdp;
	ddi_dma_cookie_t	*dcp;
	uint32_t		tmp0;
#if DEBUG_LEVEL > 2
	int			i;

	cmn_err(CE_CONT,
	    CONS "%s: time:%d %s seqnum: %d, slot %d, frags: %d flags: %llx",
	    dp->name, ddi_get_lbolt(), __func__,
	    dp->tx_desc_tail, slot, frags, flags);

	for (i = 0; i < frags; i++) {
		cmn_err(CE_CONT, CONS "%d: addr: 0x%x, len: 0x%x",
		    i, dmacookie[i].dmac_address, dmacookie[i].dmac_size);
	}
#endif
	/*
	 * write tx descriptor in reversed order.
	 */
#if DEBUG_LEVEL > 3
	flags |= GEM_TXFLAG_INTR;
#endif
	mark = (flags & GEM_TXFLAG_INTR)
	    ? (CMDSTS_OWN | CMDSTS_INTR) : CMDSTS_OWN;

	ASSERT(frags == 1);
	dcp = &dmacookie[0];
	if (flags & GEM_TXFLAG_HEAD) {
		mark &= ~CMDSTS_OWN;
	}

	tdp = (void *)&dp->tx_ring[SFE_DESC_SIZE * slot];
	tmp0 = (uint32_t)dcp->dmac_address;
	mark |= (uint32_t)dcp->dmac_size;
	tdp->d_bufptr = LE_32(tmp0);
	tdp->d_cmdsts = LE_32(mark);

	return (frags);
}

static void
sfe_tx_start(struct gem_dev *dp, int start_slot, int nslot)
{
	uint_t			tx_ring_size = dp->gc.gc_tx_ring_size;
	struct sfe_desc		*tdp;
	struct sfe_dev		*lp = dp->private;

	if (nslot > 1) {
		gem_tx_desc_dma_sync(dp,
		    SLOT(start_slot + 1, tx_ring_size),
		    nslot - 1, DDI_DMA_SYNC_FORDEV);
	}

	tdp = (void *)&dp->tx_ring[SFE_DESC_SIZE * start_slot];
	tdp->d_cmdsts |= LE_32(CMDSTS_OWN);

	gem_tx_desc_dma_sync(dp, start_slot, 1, DDI_DMA_SYNC_FORDEV);

	/*
	 * Let the Transmit Buffer Manager Fill state machine active.
	 */
	if (dp->mac_active) {
		OUTL(dp, CR, lp->cr | CR_TXE);
	}
}

static void
sfe_rx_desc_write(struct gem_dev *dp, int slot,
	    ddi_dma_cookie_t *dmacookie, int frags)
{
	struct sfe_desc		*rdp;
	uint32_t		tmp0;
	uint32_t		tmp1;
#if DEBUG_LEVEL > 2
	int			i;

	ASSERT(frags == 1);

	cmn_err(CE_CONT, CONS
	    "%s: %s seqnum: %d, slot %d, frags: %d",
	    dp->name, __func__, dp->rx_active_tail, slot, frags);
	for (i = 0; i < frags; i++) {
		cmn_err(CE_CONT, CONS "  frag: %d addr: 0x%llx, len: 0x%lx",
		    i, dmacookie[i].dmac_address, dmacookie[i].dmac_size);
	}
#endif
	/* for the last slot of the packet */
	rdp = (void *)&dp->rx_ring[SFE_DESC_SIZE * slot];

	tmp0 = (uint32_t)dmacookie->dmac_address;
	tmp1 = CMDSTS_INTR | (uint32_t)dmacookie->dmac_size;
	rdp->d_bufptr = LE_32(tmp0);
	rdp->d_cmdsts = LE_32(tmp1);
}

static uint_t
sfe_tx_desc_stat(struct gem_dev *dp, int slot, int ndesc)
{
	uint_t			tx_ring_size = dp->gc.gc_tx_ring_size;
	struct sfe_desc		*tdp;
	uint32_t		status;
	int			cols;
	struct sfe_dev		*lp = dp->private;
#ifdef DEBUG_LEVEL
	int			i;
	clock_t			delay;
#endif
	/* check status of the last descriptor */
	tdp = (void *)
	    &dp->tx_ring[SFE_DESC_SIZE * SLOT(slot + ndesc - 1, tx_ring_size)];

	/*
	 * Don't use LE_32() directly to refer tdp->d_cmdsts.
	 * It is not atomic for big endian cpus.
	 */
	status = tdp->d_cmdsts;
	status = LE_32(status);

	DPRINTF(2, (CE_CONT, CONS "%s: time:%ld %s: slot:%d, status:0x%b",
	    dp->name, ddi_get_lbolt(), __func__,
	    slot, status, TXSTAT_BITS));

	if (status & CMDSTS_OWN) {
		/*
		 * not yet transmitted
		 */
		/* workaround for tx hang */
		if (lp->chip->chip_type == CHIPTYPE_DP83815 &&
		    dp->mac_active) {
			OUTL(dp, CR, lp->cr | CR_TXE);
		}
		return (0);
	}

	if (status & CMDSTS_MORE) {
		/* XXX - the hardware problem but don't panic the system */
		/* avoid lint bug for %b format string including 32nd bit */
		cmn_err(CE_NOTE, CONS
		    "%s: tx status bits incorrect:  slot:%d, status:0x%x",
		    dp->name, slot, status);
	}

#if DEBUG_LEVEL > 3
	delay = (ddi_get_lbolt() - dp->tx_buf_head->txb_stime) * 10;
	if (delay >= 50) {
		DPRINTF(0, (CE_NOTE, "%s: tx deferred %d mS: slot %d",
		    dp->name, delay, slot));
	}
#endif

#if DEBUG_LEVEL > 3
	for (i = 0; i < nfrag-1; i++) {
		uint32_t	s;
		int		n;

		n = SLOT(slot + i, tx_ring_size);
		s = LE_32(
		    ((struct sfe_desc *)((void *)
		    &dp->tx_ring[SFE_DESC_SIZE * n]))->d_cmdsts);

		ASSERT(s & CMDSTS_MORE);
		ASSERT((s & CMDSTS_OWN) == 0);
	}
#endif

	/*
	 *  collect statistics
	 */
	if ((status & CMDSTS_OK) == 0) {

		/* failed to transmit the packet */

		DPRINTF(0, (CE_CONT, CONS "%s: Transmit error, Tx status %b",
		    dp->name, status, TXSTAT_BITS));

		dp->stats.errxmt++;

		if (status & CMDSTS_TFU) {
			dp->stats.underflow++;
		} else if (status & CMDSTS_CRS) {
			dp->stats.nocarrier++;
		} else if (status & CMDSTS_OWC) {
			dp->stats.xmtlatecoll++;
		} else if ((!dp->full_duplex) && (status & CMDSTS_EC)) {
			dp->stats.excoll++;
			dp->stats.collisions += 16;
		} else {
			dp->stats.xmit_internal_err++;
		}
	} else if (!dp->full_duplex) {
		cols = (status >> CMDSTS_CCNT_SHIFT) & CCNT_MASK;

		if (cols > 0) {
			if (cols == 1) {
				dp->stats.first_coll++;
			} else /* (cols > 1) */ {
				dp->stats.multi_coll++;
			}
			dp->stats.collisions += cols;
		} else if (status & CMDSTS_TD) {
			dp->stats.defer++;
		}
	}
	return (GEM_TX_DONE);
}

static uint64_t
sfe_rx_desc_stat(struct gem_dev *dp, int slot, int ndesc)
{
	struct sfe_desc		*rdp;
	uint_t			len;
	uint_t			flag;
	uint32_t		status;

	flag = GEM_RX_DONE;

	/* Dont read ISR because we cannot ack only to rx interrupt. */

	rdp = (void *)&dp->rx_ring[SFE_DESC_SIZE * slot];

	/*
	 * Don't use LE_32() directly to refer rdp->d_cmdsts.
	 * It is not atomic for big endian cpus.
	 */
	status = rdp->d_cmdsts;
	status = LE_32(status);

	DPRINTF(2, (CE_CONT, CONS "%s: time:%ld %s: slot:%d, status:0x%b",
	    dp->name, ddi_get_lbolt(), __func__,
	    slot, status, RXSTAT_BITS));

	if ((status & CMDSTS_OWN) == 0) {
		/*
		 * No more received packets because
		 * this buffer is owned by NIC.
		 */
		return (0);
	}

#define	RX_ERR_BITS \
	(CMDSTS_RXA | CMDSTS_RXO | CMDSTS_LONG | CMDSTS_RUNT | \
		CMDSTS_ISE | CMDSTS_CRCE | CMDSTS_FAE | CMDSTS_MORE)

	if (status & RX_ERR_BITS) {
		/*
		 * Packet with error received
		 */
		DPRINTF(0, (CE_CONT, CONS "%s: Corrupted packet "
		    "received, buffer status: %b",
		    dp->name, status, RXSTAT_BITS));

		/* collect statistics information */
		dp->stats.errrcv++;

		if (status & CMDSTS_RXO) {
			dp->stats.overflow++;
		} else if (status & (CMDSTS_LONG | CMDSTS_MORE)) {
			dp->stats.frame_too_long++;
		} else if (status & CMDSTS_RUNT) {
			dp->stats.runt++;
		} else if (status & (CMDSTS_ISE | CMDSTS_FAE)) {
			dp->stats.frame++;
		} else if (status & CMDSTS_CRCE) {
			dp->stats.crc++;
		} else {
			dp->stats.rcv_internal_err++;
		}

		return (flag | GEM_RX_ERR);
	}

	/*
	 * this packet was received without errors
	 */
	if ((len = (status & CMDSTS_SIZE)) >= ETHERFCSL) {
		len -= ETHERFCSL;
	}

#if DEBUG_LEVEL > 10
{
	int	i;
	uint8_t	*bp = dp->rx_buf_head->rxb_buf;

	cmn_err(CE_CONT, CONS "%s: len:%d", dp->name, len);

	for (i = 0; i < 60; i += 10) {
		cmn_err(CE_CONT, CONS
		    "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
		    bp[0], bp[1], bp[2], bp[3], bp[4],
		    bp[5], bp[6], bp[7], bp[8], bp[9]);
	}
	bp += 10;
}
#endif
	return (flag | (len & GEM_RX_LEN));
}

static void
sfe_tx_desc_init(struct gem_dev *dp, int slot)
{
	uint_t			tx_ring_size = dp->gc.gc_tx_ring_size;
	struct sfe_desc		*tdp;
	uint32_t		here;

	tdp = (void *)&dp->tx_ring[SFE_DESC_SIZE * slot];

	/* don't clear d_link field, which have a valid pointer */
	tdp->d_cmdsts = 0;

	/* make a link to this from the previous descriptor */
	here = ((uint32_t)dp->tx_ring_dma) + SFE_DESC_SIZE*slot;

	tdp = (void *)
	    &dp->tx_ring[SFE_DESC_SIZE * SLOT(slot - 1, tx_ring_size)];
	tdp->d_link = LE_32(here);
}

static void
sfe_rx_desc_init(struct gem_dev *dp, int slot)
{
	uint_t			rx_ring_size = dp->gc.gc_rx_ring_size;
	struct sfe_desc		*rdp;
	uint32_t		here;

	rdp = (void *)&dp->rx_ring[SFE_DESC_SIZE * slot];

	/* don't clear d_link field, which have a valid pointer */
	rdp->d_cmdsts = LE_32(CMDSTS_OWN);

	/* make a link to this from the previous descriptor */
	here = ((uint32_t)dp->rx_ring_dma) + SFE_DESC_SIZE*slot;

	rdp = (void *)
	    &dp->rx_ring[SFE_DESC_SIZE * SLOT(slot - 1, rx_ring_size)];
	rdp->d_link = LE_32(here);
}

static void
sfe_tx_desc_clean(struct gem_dev *dp, int slot)
{
	struct sfe_desc		*tdp;

	tdp = (void *)&dp->tx_ring[SFE_DESC_SIZE * slot];
	tdp->d_cmdsts = 0;
}

static void
sfe_rx_desc_clean(struct gem_dev *dp, int slot)
{
	struct sfe_desc		*rdp;

	rdp = (void *)&dp->rx_ring[SFE_DESC_SIZE * slot];
	rdp->d_cmdsts = LE_32(CMDSTS_OWN);
}

/*
 * Device depend interrupt handler
 */
static uint_t
sfe_interrupt(struct gem_dev *dp)
{
	uint_t		rx_ring_size = dp->gc.gc_rx_ring_size;
	uint32_t	isr;
	uint32_t	isr_bogus;
	uint_t		flags = 0;
	boolean_t	need_to_reset = B_FALSE;
	struct sfe_dev	*lp = dp->private;

	/* read reason and clear interrupt */
	isr = INL(dp, ISR);

	isr_bogus = lp->isr_pended;
	lp->isr_pended = 0;

	if (((isr | isr_bogus) & lp->our_intr_bits) == 0) {
		/* we are not the interrupt source */
		return (DDI_INTR_UNCLAIMED);
	}

	DPRINTF(3, (CE_CONT,
	    CONS "%s: time:%ld %s:called: isr:0x%b rx_active_head: %d",
	    dp->name, ddi_get_lbolt(), __func__,
	    isr, INTR_BITS, dp->rx_active_head));

	if (!dp->mac_active) {
		/* the device is going to stop */
		lp->our_intr_bits = 0;
		return (DDI_INTR_CLAIMED);
	}

	isr &= lp->our_intr_bits;

	if (isr & (ISR_RXSOVR | ISR_RXORN | ISR_RXIDLE | ISR_RXERR |
	    ISR_RXDESC | ISR_RXOK)) {
		(void) gem_receive(dp);

		if (isr & (ISR_RXSOVR | ISR_RXORN)) {
			DPRINTF(0, (CE_CONT,
			    CONS "%s: rx fifo overrun: isr %b",
			    dp->name, isr, INTR_BITS));
			/* no need restart rx */
			dp->stats.overflow++;
		}

		if (isr & ISR_RXIDLE) {
			DPRINTF(0, (CE_CONT,
			    CONS "%s: rx buffer ran out: isr %b",
			    dp->name, isr, INTR_BITS));

			dp->stats.norcvbuf++;

			/*
			 * Make RXDP points the head of receive
			 * buffer list.
			 */
			OUTL(dp, RXDP, dp->rx_ring_dma +
			    SFE_DESC_SIZE *
			    SLOT(dp->rx_active_head, rx_ring_size));

			/* Restart the receive engine */
			OUTL(dp, CR, lp->cr | CR_RXE);
		}
	}

	if (isr & (ISR_TXURN | ISR_TXERR | ISR_TXDESC |
	    ISR_TXIDLE | ISR_TXOK)) {
		/* need to reclaim tx buffers */
		if (gem_tx_done(dp)) {
			flags |= INTR_RESTART_TX;
		}
		/*
		 * XXX - tx error statistics will be counted in
		 * sfe_tx_desc_stat() and no need to restart tx on errors.
		 */
	}

	if (isr & (ISR_DPERR | ISR_SSERR | ISR_RMABT | ISR_RTABT)) {
		cmn_err(CE_WARN, "%s: ERROR interrupt: isr %b.",
		    dp->name, isr, INTR_BITS);
		need_to_reset = B_TRUE;
	}
reset:
	if (need_to_reset) {
		(void) gem_restart_nic(dp, GEM_RESTART_KEEP_BUF);
		flags |= INTR_RESTART_TX;
	}

	DPRINTF(5, (CE_CONT, CONS "%s: %s: return: isr: %b",
	    dp->name, __func__, isr, INTR_BITS));

	return (DDI_INTR_CLAIMED | flags);
}

/* ======================================================== */
/*
 * HW depend MII routine
 */
/* ======================================================== */

/*
 * MII routines for NS DP83815
 */
static void
sfe_mii_sync_dp83815(struct gem_dev *dp)
{
	/* do nothing */
}

static uint16_t
sfe_mii_read_dp83815(struct gem_dev *dp, uint_t offset)
{
	DPRINTF(4, (CE_CONT, CONS"%s: %s: offset 0x%x",
	    dp->name, __func__, offset));
	return ((uint16_t)INL(dp, MII_REGS_BASE + offset*4));
}

static void
sfe_mii_write_dp83815(struct gem_dev *dp, uint_t offset, uint16_t val)
{
	DPRINTF(4, (CE_CONT, CONS"%s: %s: offset 0x%x 0x%x",
	    dp->name, __func__, offset, val));
	OUTL(dp, MII_REGS_BASE + offset*4, val);
}

static int
sfe_mii_config_dp83815(struct gem_dev *dp)
{
	uint32_t	srr;

	srr = INL(dp, SRR) & SRR_REV;

	DPRINTF(0, (CE_CONT, CONS "%s: srr:0x%04x %04x %04x %04x %04x %04x",
	    dp->name, srr,
	    INW(dp, 0x00cc),	/* PGSEL */
	    INW(dp, 0x00e4),	/* PMDCSR */
	    INW(dp, 0x00fc),	/* TSTDAT */
	    INW(dp, 0x00f4),	/* DSPCFG */
	    INW(dp, 0x00f8)));	/* SDCFG */

	if (srr == SRR_REV_DP83815CVNG) {
		/*
		 * NS datasheet says that DP83815CVNG needs following
		 * registers to be patched for optimizing its performance.
		 * A report said that CRC errors on RX disappeared
		 * with the patch.
		 */
		OUTW(dp, 0x00cc, 0x0001);	/* PGSEL */
		OUTW(dp, 0x00e4, 0x189c);	/* PMDCSR */
		OUTW(dp, 0x00fc, 0x0000);	/* TSTDAT */
		OUTW(dp, 0x00f4, 0x5040);	/* DSPCFG */
		OUTW(dp, 0x00f8, 0x008c);	/* SDCFG */
		OUTW(dp, 0x00cc, 0x0000);	/* PGSEL */

		DPRINTF(0, (CE_CONT,
		    CONS "%s: PHY patched %04x %04x %04x %04x %04x",
		    dp->name,
		    INW(dp, 0x00cc),	/* PGSEL */
		    INW(dp, 0x00e4),	/* PMDCSR */
		    INW(dp, 0x00fc),	/* TSTDAT */
		    INW(dp, 0x00f4),	/* DSPCFG */
		    INW(dp, 0x00f8)));	/* SDCFG */
	} else if (((srr ^ SRR_REV_DP83815DVNG) & 0xff00) == 0 ||
	    ((srr ^ SRR_REV_DP83816AVNG) & 0xff00) == 0) {
		/*
		 * Additional packets for later chipset
		 */
		OUTW(dp, 0x00cc, 0x0001);	/* PGSEL */
		OUTW(dp, 0x00e4, 0x189c);	/* PMDCSR */
		OUTW(dp, 0x00cc, 0x0000);	/* PGSEL */

		DPRINTF(0, (CE_CONT,
		    CONS "%s: PHY patched %04x %04x",
		    dp->name,
		    INW(dp, 0x00cc),	/* PGSEL */
		    INW(dp, 0x00e4)));	/* PMDCSR */
	}

	return (gem_mii_config_default(dp));
}

static int
sfe_mii_probe_dp83815(struct gem_dev *dp)
{
	uint32_t	val;

	/* try external phy first */
	DPRINTF(0, (CE_CONT, CONS "%s: %s: trying external phy",
	    dp->name, __func__));
	dp->mii_phy_addr = 0;
	dp->gc.gc_mii_sync = &sfe_mii_sync_sis900;
	dp->gc.gc_mii_read = &sfe_mii_read_sis900;
	dp->gc.gc_mii_write = &sfe_mii_write_sis900;

	val = INL(dp, CFG) & (CFG_ANEG_SEL | CFG_PHY_CFG);
	OUTL(dp, CFG, val | CFG_EXT_PHY | CFG_PHY_DIS);

	if (gem_mii_probe_default(dp) == GEM_SUCCESS) {
		return (GEM_SUCCESS);
	}

	/* switch to internal phy */
	DPRINTF(0, (CE_CONT, CONS "%s: %s: switching to internal phy",
	    dp->name, __func__));
	dp->mii_phy_addr = -1;
	dp->gc.gc_mii_sync = &sfe_mii_sync_dp83815;
	dp->gc.gc_mii_read = &sfe_mii_read_dp83815;
	dp->gc.gc_mii_write = &sfe_mii_write_dp83815;

	val = INL(dp, CFG) & (CFG_ANEG_SEL | CFG_PHY_CFG);
	OUTL(dp, CFG, val | CFG_PAUSE_ADV | CFG_PHY_RST);
	drv_usecwait(100);	/* keep to assert RST bit for a while */
	OUTL(dp, CFG, val | CFG_PAUSE_ADV);

	/* wait for PHY reset */
	delay(drv_usectohz(10000));

	return (gem_mii_probe_default(dp));
}

static int
sfe_mii_init_dp83815(struct gem_dev *dp)
{
	uint32_t	val;

	val = INL(dp, CFG) & (CFG_ANEG_SEL | CFG_PHY_CFG);

	if (dp->mii_phy_addr == -1) {
		/* select internal phy */
		OUTL(dp, CFG, val | CFG_PAUSE_ADV);
	} else {
		/* select external phy */
		OUTL(dp, CFG, val | CFG_EXT_PHY | CFG_PHY_DIS);
	}

	return (GEM_SUCCESS);
}

/*
 * MII routines for SiS900
 */
#define	MDIO_DELAY(dp)	{(void) INL(dp, MEAR); (void) INL(dp, MEAR); }
static void
sfe_mii_sync_sis900(struct gem_dev *dp)
{
	int	i;

	/* send 32 ONE's to make MII line idle */
	for (i = 0; i < 32; i++) {
		OUTL(dp, MEAR, MEAR_MDDIR | MEAR_MDIO);
		MDIO_DELAY(dp);
		OUTL(dp, MEAR, MEAR_MDDIR | MEAR_MDIO | MEAR_MDC);
		MDIO_DELAY(dp);
	}
}

static int
sfe_mii_config_sis900(struct gem_dev *dp)
{
	struct sfe_dev	*lp = dp->private;

	/* Do chip depend setup */
	if ((dp->mii_phy_id & PHY_MASK) == PHY_ICS1893) {
		/* workaround for ICS1893 PHY */
		gem_mii_write(dp, 0x0018, 0xD200);
	}

	if (lp->revid == SIS630E_900_REV) {
		/*
		 * SiS 630E has bugs on default values
		 * of PHY registers
		 */
		gem_mii_write(dp, MII_AN_ADVERT, 0x05e1);
		gem_mii_write(dp, MII_CONFIG1, 0x0022);
		gem_mii_write(dp, MII_CONFIG2, 0xff00);
		gem_mii_write(dp, MII_MASK,    0xffc0);
	}
	sfe_set_eq_sis630(dp);

	return (gem_mii_config_default(dp));
}

static uint16_t
sfe_mii_read_sis900(struct gem_dev *dp, uint_t reg)
{
	uint32_t	cmd;
	uint16_t	ret;
	int		i;
	uint32_t	data;

	cmd = MII_READ_CMD(dp->mii_phy_addr, reg);

	for (i = 31; i >= 18; i--) {
		data = ((cmd >> i) & 1) <<  MEAR_MDIO_SHIFT;
		OUTL(dp, MEAR, data | MEAR_MDDIR);
		MDIO_DELAY(dp);
		OUTL(dp, MEAR, data | MEAR_MDDIR | MEAR_MDC);
		MDIO_DELAY(dp);
	}

	/* turn around cycle */
	OUTL(dp, MEAR, 0);
	MDIO_DELAY(dp);

	/* get response from PHY */
	OUTL(dp, MEAR, MEAR_MDC);
	MDIO_DELAY(dp);

	OUTL(dp, MEAR, 0);
#if DEBUG_LEBEL > 0
	(void) INL(dp, MEAR);	/* delay */
	if (INL(dp, MEAR) & MEAR_MDIO) {
		cmn_err(CE_WARN, "%s: PHY@%d not responded",
		    dp->name, dp->mii_phy_addr);
	}
#else
	MDIO_DELAY(dp);
#endif
	/* terminate response cycle */
	OUTL(dp, MEAR, MEAR_MDC);
	MDIO_DELAY(dp);

	ret = 0;	/* to avoid lint errors */
	for (i = 16; i > 0; i--) {
		OUTL(dp, MEAR, 0);
		(void) INL(dp, MEAR);	/* delay */
		ret = (ret << 1) | ((INL(dp, MEAR) >> MEAR_MDIO_SHIFT) & 1);
		OUTL(dp, MEAR, MEAR_MDC);
		MDIO_DELAY(dp);
	}

	/* send two idle(Z) bits to terminate the read cycle */
	for (i = 0; i < 2; i++) {
		OUTL(dp, MEAR, 0);
		MDIO_DELAY(dp);
		OUTL(dp, MEAR, MEAR_MDC);
		MDIO_DELAY(dp);
	}

	return (ret);
}

static void
sfe_mii_write_sis900(struct gem_dev *dp, uint_t reg, uint16_t val)
{
	uint32_t	cmd;
	int		i;
	uint32_t	data;

	cmd = MII_WRITE_CMD(dp->mii_phy_addr, reg, val);

	for (i = 31; i >= 0; i--) {
		data = ((cmd >> i) & 1) << MEAR_MDIO_SHIFT;
		OUTL(dp, MEAR, data | MEAR_MDDIR);
		MDIO_DELAY(dp);
		OUTL(dp, MEAR, data | MEAR_MDDIR | MEAR_MDC);
		MDIO_DELAY(dp);
	}

	/* send two idle(Z) bits to terminate the write cycle. */
	for (i = 0; i < 2; i++) {
		OUTL(dp, MEAR, 0);
		MDIO_DELAY(dp);
		OUTL(dp, MEAR, MEAR_MDC);
		MDIO_DELAY(dp);
	}
}
#undef MDIO_DELAY

static void
sfe_set_eq_sis630(struct gem_dev *dp)
{
	uint16_t	reg14h;
	uint16_t	eq_value;
	uint16_t	max_value;
	uint16_t	min_value;
	int		i;
	uint8_t		rev;
	struct sfe_dev	*lp = dp->private;

	rev = lp->revid;

	if (!(rev == SIS630E_900_REV || rev == SIS630EA1_900_REV ||
	    rev == SIS630A_900_REV || rev == SIS630ET_900_REV)) {
		/* it doesn't have a internal PHY */
		return;
	}

	if (dp->mii_state == MII_STATE_LINKUP) {
		reg14h = gem_mii_read(dp, MII_RESV);
		gem_mii_write(dp, MII_RESV, (0x2200 | reg14h) & 0xBFFF);

		eq_value = (0x00f8 & gem_mii_read(dp, MII_RESV)) >> 3;
		max_value = min_value = eq_value;
		for (i = 1; i < 10; i++) {
			eq_value = (0x00f8 & gem_mii_read(dp, MII_RESV)) >> 3;
			max_value = max(eq_value, max_value);
			min_value = min(eq_value, min_value);
		}

		/* for 630E, rule to determine the equalizer value */
		if (rev == SIS630E_900_REV || rev == SIS630EA1_900_REV ||
		    rev == SIS630ET_900_REV) {
			if (max_value < 5) {
				eq_value = max_value;
			} else if (5 <= max_value && max_value < 15) {
				eq_value =
				    max(max_value + 1,
				    min_value + 2);
			} else if (15 <= max_value) {
				eq_value =
				    max(max_value + 5,
				    min_value + 6);
			}
		}
		/* for 630B0&B1, rule to determine the equalizer value */
		else
		if (rev == SIS630A_900_REV &&
		    (lp->bridge_revid == SIS630B0 ||
		    lp->bridge_revid == SIS630B1)) {

			if (max_value == 0) {
				eq_value = 3;
			} else {
				eq_value = (max_value + min_value + 1)/2;
			}
		}
		/* write equalizer value and setting */
		reg14h = gem_mii_read(dp, MII_RESV) & ~0x02f8;
		reg14h |= 0x6000 | (eq_value << 3);
		gem_mii_write(dp, MII_RESV, reg14h);
	} else {
		reg14h = (gem_mii_read(dp, MII_RESV) & ~0x4000) | 0x2000;
		if (rev == SIS630A_900_REV &&
		    (lp->bridge_revid == SIS630B0 ||
		    lp->bridge_revid == SIS630B1)) {

			reg14h |= 0x0200;
		}
		gem_mii_write(dp, MII_RESV, reg14h);
	}
}

/* ======================================================== */
/*
 * OS depend (device driver) routine
 */
/* ======================================================== */
static void
sfe_chipinfo_init_sis900(struct gem_dev *dp)
{
	int		rev;
	struct sfe_dev	*lp = (struct sfe_dev *)dp->private;

	rev = lp->revid;

	if (rev == SIS630E_900_REV /* 0x81 */) {
		/* sis630E */
		lp->get_mac_addr = &sfe_get_mac_addr_sis630e;
	} else if (rev > 0x81 && rev <= 0x90) {
		/* 630S, 630EA1, 630ET, 635A */
		lp->get_mac_addr = &sfe_get_mac_addr_sis635;
	} else if (rev == SIS962_900_REV /* 0x91 */) {
		/* sis962 or later */
		lp->get_mac_addr = &sfe_get_mac_addr_sis962;
	} else {
		/* sis900 */
		lp->get_mac_addr = &sfe_get_mac_addr_sis900;
	}

	lp->bridge_revid = 0;

	if (rev == SIS630E_900_REV || rev == SIS630EA1_900_REV ||
	    rev == SIS630A_900_REV || rev ==  SIS630ET_900_REV) {
		/*
		 * read host bridge revision
		 */
		dev_info_t	*bridge;
		ddi_acc_handle_t bridge_handle;

		if ((bridge = sfe_search_pci_dev(0x1039, 0x630)) == NULL) {
			cmn_err(CE_WARN,
			    "%s: cannot find host bridge (pci1039,630)",
			    dp->name);
			return;
		}

		if (pci_config_setup(bridge, &bridge_handle) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s: pci_config_setup failed",
			    dp->name);
			return;
		}

		lp->bridge_revid =
		    pci_config_get8(bridge_handle, PCI_CONF_REVID);
		pci_config_teardown(&bridge_handle);
	}
}

static int
sfe_attach_chip(struct gem_dev *dp)
{
	struct sfe_dev		*lp = (struct sfe_dev *)dp->private;

	DPRINTF(4, (CE_CONT, CONS "!%s: %s called", dp->name, __func__));

	/* setup chip-depend get_mac_address function */
	if (lp->chip->chip_type == CHIPTYPE_SIS900) {
		sfe_chipinfo_init_sis900(dp);
	} else {
		lp->get_mac_addr = &sfe_get_mac_addr_dp83815;
	}

	/* read MAC address */
	if (!(lp->get_mac_addr)(dp)) {
		cmn_err(CE_WARN,
		    "!%s: %s: failed to get factory mac address"
		    " please specify a mac address in sfe.conf",
		    dp->name, __func__);
		return (GEM_FAILURE);
	}

	if (lp->chip->chip_type == CHIPTYPE_DP83815) {
		dp->mii_phy_addr = -1;	/* no need to scan PHY */
		dp->misc_flag |= GEM_VLAN_SOFT;
		dp->txthr += 4; /* VTAG_SIZE */
	}
	dp->txthr = min(dp->txthr, TXFIFOSIZE - 2);

	return (GEM_SUCCESS);
}

static int
sfeattach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int			unit;
	const char		*drv_name;
	int			i;
	ddi_acc_handle_t	conf_handle;
	uint16_t		vid;
	uint16_t		did;
	uint8_t			rev;
#ifdef DEBUG_LEVEL
	uint32_t		iline;
	uint8_t			latim;
#endif
	struct chip_info	*p;
	struct gem_dev		*dp;
	struct sfe_dev		*lp;
	caddr_t			base;
	ddi_acc_handle_t	regs_ha;
	struct gem_conf		*gcp;

	unit = ddi_get_instance(dip);
	drv_name = ddi_driver_name(dip);

	DPRINTF(3, (CE_CONT, CONS "%s%d: sfeattach: called", drv_name, unit));

	/*
	 * Common codes after power-up
	 */
	if (pci_config_setup(dip, &conf_handle) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: ddi_regs_map_setup failed",
		    drv_name, unit);
		goto err;
	}

	vid  = pci_config_get16(conf_handle, PCI_CONF_VENID);
	did  = pci_config_get16(conf_handle, PCI_CONF_DEVID);
	rev  = pci_config_get16(conf_handle, PCI_CONF_REVID);
#ifdef DEBUG_LEVEL
	iline = pci_config_get32(conf_handle, PCI_CONF_ILINE);
	latim = pci_config_get8(conf_handle, PCI_CONF_LATENCY_TIMER);
#endif
#ifdef DEBUG_BUILT_IN_SIS900
	rev  = SIS630E_900_REV;
#endif
	for (i = 0, p = sfe_chiptbl; i < CHIPTABLESIZE; i++, p++) {
		if (p->venid == vid && p->devid == did) {
			/* found */
			goto chip_found;
		}
	}

	/* Not found */
	cmn_err(CE_WARN,
	    "%s%d: sfe_attach: wrong PCI venid/devid (0x%x, 0x%x)",
	    drv_name, unit, vid, did);
	pci_config_teardown(&conf_handle);
	goto err;

chip_found:
	pci_config_put16(conf_handle, PCI_CONF_COMM,
	    PCI_COMM_IO | PCI_COMM_MAE | PCI_COMM_ME |
	    pci_config_get16(conf_handle, PCI_CONF_COMM));

	/* ensure D0 mode */
	(void) gem_pci_set_power_state(dip, conf_handle, PCI_PMCSR_D0);

	pci_config_teardown(&conf_handle);

	switch (cmd) {
	case DDI_RESUME:
		return (gem_resume(dip));

	case DDI_ATTACH:

		DPRINTF(0, (CE_CONT,
		    CONS "%s%d: ilr 0x%08x, latency_timer:0x%02x",
		    drv_name, unit, iline, latim));

		/*
		 * Map in the device registers.
		 */
		if (gem_pci_regs_map_setup(dip,
		    (sfe_use_pcimemspace && p->chip_type == CHIPTYPE_DP83815)
		    ? PCI_ADDR_MEM32 : PCI_ADDR_IO, PCI_ADDR_MASK,
		    &sfe_dev_attr, &base, &regs_ha) != DDI_SUCCESS) {
			cmn_err(CE_WARN,
			    "%s%d: ddi_regs_map_setup failed",
			    drv_name, unit);
			goto err;
		}

		/*
		 * construct gem configuration
		 */
		gcp = kmem_zalloc(sizeof (*gcp), KM_SLEEP);

		/* name */
		(void) sprintf(gcp->gc_name, "%s%d", drv_name, unit);

		/* consistency on tx and rx */
		gcp->gc_tx_buf_align = sizeof (uint8_t) - 1;
		gcp->gc_tx_max_frags = MAXTXFRAGS;
		gcp->gc_tx_max_descs_per_pkt = gcp->gc_tx_max_frags;
		gcp->gc_tx_desc_unit_shift = 4;	/* 16 byte */
		gcp->gc_tx_buf_size  = TX_BUF_SIZE;
		gcp->gc_tx_buf_limit = gcp->gc_tx_buf_size;
		gcp->gc_tx_ring_size = TX_RING_SIZE;
		gcp->gc_tx_ring_limit = gcp->gc_tx_ring_size;
		gcp->gc_tx_auto_pad  = B_TRUE;
		gcp->gc_tx_copy_thresh = sfe_tx_copy_thresh;
		gcp->gc_tx_desc_write_oo = B_TRUE;

		gcp->gc_rx_buf_align = sizeof (uint8_t) - 1;
		gcp->gc_rx_max_frags = MAXRXFRAGS;
		gcp->gc_rx_desc_unit_shift = 4;
		gcp->gc_rx_ring_size = RX_RING_SIZE;
		gcp->gc_rx_buf_max   = RX_BUF_SIZE;
		gcp->gc_rx_copy_thresh = sfe_rx_copy_thresh;

		/* map attributes */
		gcp->gc_dev_attr = sfe_dev_attr;
		gcp->gc_buf_attr = sfe_buf_attr;
		gcp->gc_desc_attr = sfe_buf_attr;

		/* dma attributes */
		gcp->gc_dma_attr_desc = sfe_dma_attr_desc;

		gcp->gc_dma_attr_txbuf = sfe_dma_attr_buf;
		gcp->gc_dma_attr_txbuf.dma_attr_align = gcp->gc_tx_buf_align+1;
		gcp->gc_dma_attr_txbuf.dma_attr_sgllen = gcp->gc_tx_max_frags;

		gcp->gc_dma_attr_rxbuf = sfe_dma_attr_buf;
		gcp->gc_dma_attr_rxbuf.dma_attr_align = gcp->gc_rx_buf_align+1;
		gcp->gc_dma_attr_rxbuf.dma_attr_sgllen = gcp->gc_rx_max_frags;

		/* time out parameters */
		gcp->gc_tx_timeout = 3*ONESEC;
		gcp->gc_tx_timeout_interval = ONESEC;
		if (p->chip_type == CHIPTYPE_DP83815) {
			/* workaround for tx hang */
			gcp->gc_tx_timeout_interval = ONESEC/20; /* 50mS */
		}

		/* MII timeout parameters */
		gcp->gc_mii_link_watch_interval = ONESEC;
		gcp->gc_mii_an_watch_interval   = ONESEC/5;
		gcp->gc_mii_reset_timeout = MII_RESET_TIMEOUT;	/* 1 sec */
		gcp->gc_mii_an_timeout = MII_AN_TIMEOUT;	/* 5 sec */
		gcp->gc_mii_an_wait = 0;
		gcp->gc_mii_linkdown_timeout = MII_LINKDOWN_TIMEOUT;

		/* setting for general PHY */
		gcp->gc_mii_an_delay = 0;
		gcp->gc_mii_linkdown_action = MII_ACTION_RSA;
		gcp->gc_mii_linkdown_timeout_action = MII_ACTION_RESET;
		gcp->gc_mii_dont_reset = B_FALSE;


		/* I/O methods */

		/* mac operation */
		gcp->gc_attach_chip = &sfe_attach_chip;
		if (p->chip_type == CHIPTYPE_DP83815) {
			gcp->gc_reset_chip = &sfe_reset_chip_dp83815;
		} else {
			gcp->gc_reset_chip = &sfe_reset_chip_sis900;
		}
		gcp->gc_init_chip  = &sfe_init_chip;
		gcp->gc_start_chip = &sfe_start_chip;
		gcp->gc_stop_chip  = &sfe_stop_chip;
#ifdef USE_MULTICAST_HASHTBL
		gcp->gc_multicast_hash = &sfe_mcast_hash;
#endif
		if (p->chip_type == CHIPTYPE_DP83815) {
			gcp->gc_set_rx_filter = &sfe_set_rx_filter_dp83815;
		} else {
			gcp->gc_set_rx_filter = &sfe_set_rx_filter_sis900;
		}
		gcp->gc_set_media = &sfe_set_media;
		gcp->gc_get_stats = &sfe_get_stats;
		gcp->gc_interrupt = &sfe_interrupt;

		/* descriptor operation */
		gcp->gc_tx_desc_write = &sfe_tx_desc_write;
		gcp->gc_tx_start = &sfe_tx_start;
		gcp->gc_rx_desc_write = &sfe_rx_desc_write;
		gcp->gc_rx_start = NULL;

		gcp->gc_tx_desc_stat = &sfe_tx_desc_stat;
		gcp->gc_rx_desc_stat = &sfe_rx_desc_stat;
		gcp->gc_tx_desc_init = &sfe_tx_desc_init;
		gcp->gc_rx_desc_init = &sfe_rx_desc_init;
		gcp->gc_tx_desc_clean = &sfe_tx_desc_clean;
		gcp->gc_rx_desc_clean = &sfe_rx_desc_clean;

		/* mii operations */
		if (p->chip_type == CHIPTYPE_DP83815) {
			gcp->gc_mii_probe = &sfe_mii_probe_dp83815;
			gcp->gc_mii_init = &sfe_mii_init_dp83815;
			gcp->gc_mii_config = &sfe_mii_config_dp83815;
			gcp->gc_mii_sync = &sfe_mii_sync_dp83815;
			gcp->gc_mii_read = &sfe_mii_read_dp83815;
			gcp->gc_mii_write = &sfe_mii_write_dp83815;
			gcp->gc_mii_tune_phy = NULL;
			gcp->gc_flow_control = FLOW_CONTROL_NONE;
		} else {
			gcp->gc_mii_probe = &gem_mii_probe_default;
			gcp->gc_mii_init = NULL;
			gcp->gc_mii_config = &sfe_mii_config_sis900;
			gcp->gc_mii_sync = &sfe_mii_sync_sis900;
			gcp->gc_mii_read = &sfe_mii_read_sis900;
			gcp->gc_mii_write = &sfe_mii_write_sis900;
			gcp->gc_mii_tune_phy = &sfe_set_eq_sis630;
			gcp->gc_flow_control = FLOW_CONTROL_RX_PAUSE;
		}

		lp = kmem_zalloc(sizeof (*lp), KM_SLEEP);
		lp->chip = p;
		lp->revid = rev;
		lp->our_intr_bits = 0;
		lp->isr_pended = 0;

		cmn_err(CE_CONT, CONS "%s%d: chip:%s rev:0x%02x",
		    drv_name, unit, p->chip_name, rev);

		dp = gem_do_attach(dip, 0, gcp, base, &regs_ha,
		    lp, sizeof (*lp));
		kmem_free(gcp, sizeof (*gcp));

		if (dp == NULL) {
			goto err_freelp;
		}

		return (DDI_SUCCESS);

err_freelp:
		kmem_free(lp, sizeof (struct sfe_dev));
err:
		return (DDI_FAILURE);
	}
	return (DDI_FAILURE);
}

static int
sfedetach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_SUSPEND:
		return (gem_suspend(dip));

	case DDI_DETACH:
		return (gem_do_detach(dip));
	}
	return (DDI_FAILURE);
}

/*
 * quiesce(9E) entry point.
 *
 * This function is called when the system is single-threaded at high
 * PIL with preemption disabled. Therefore, this function must not be
 * blocked.
 *
 * This function returns DDI_SUCCESS on success, or DDI_FAILURE on failure.
 * DDI_FAILURE indicates an error condition and should almost never happen.
 */
#ifdef	__sparc
#define	sfe_quiesce	ddi_quiesce_not_supported
#else
static int
sfe_quiesce(dev_info_t *dip)
{
	struct gem_dev	*dp;
	int	ret = 0;

	dp = GEM_GET_DEV(dip);

	if (dp == NULL)
		return (DDI_FAILURE);

	ret = sfe_stop_chip_quiesce(dp);

	return (ret);
}
#endif

/* ======================================================== */
/*
 * OS depend (loadable streams driver) routine
 */
/* ======================================================== */
DDI_DEFINE_STREAM_OPS(sfe_ops, nulldev, nulldev, sfeattach, sfedetach,
	nodev, NULL, D_MP, NULL, sfe_quiesce);

static struct modldrv modldrv = {
	&mod_driverops,	/* Type of module.  This one is a driver */
	ident,
	&sfe_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};

/* ======================================================== */
/*
 * Loadable module support
 */
/* ======================================================== */
int
_init(void)
{
	int 	status;

	DPRINTF(2, (CE_CONT, CONS "sfe: _init: called"));
	gem_mod_init(&sfe_ops, "sfe");
	status = mod_install(&modlinkage);
	if (status != DDI_SUCCESS) {
		gem_mod_fini(&sfe_ops);
	}
	return (status);
}

/*
 * _fini : done
 */
int
_fini(void)
{
	int	status;

	DPRINTF(2, (CE_CONT, CONS "sfe: _fini: called"));
	status = mod_remove(&modlinkage);
	if (status == DDI_SUCCESS) {
		gem_mod_fini(&sfe_ops);
	}
	return (status);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
