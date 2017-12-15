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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */
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
#include <sys/sysmacros.h>
#include <sys/dditypes.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/miiregs.h>
#include <sys/byteorder.h>
#include <sys/cyclic.h>
#include <sys/note.h>
#include <sys/crc32.h>
#include <sys/mac_provider.h>
#include <sys/mac_ether.h>
#include <sys/vlan.h>
#include <sys/errno.h>
#include <sys/sdt.h>
#include <sys/strsubr.h>

#include "bfe.h"
#include "bfe_hw.h"


/*
 * Broadcom BCM4401 chipsets use two rings :
 *
 * - One TX : For sending packets down the wire.
 * - One RX : For receving packets.
 *
 * Each ring can have any number of descriptors (configured during attach).
 * As of now we configure only 128 descriptor per ring (TX/RX). Each descriptor
 * has address (desc_addr) and control (desc_ctl) which holds a DMA buffer for
 * the packet and control information (like start/end of frame or end of table).
 * The descriptor table is allocated first and then a DMA buffer (for a packet)
 * is allocated and linked to each descriptor.
 *
 * Each descriptor entry is bfe_desc_t structure in bfe. During TX/RX
 * interrupt, the stat register will point to current descriptor being
 * processed.
 *
 * Here's an example of TX and RX ring :
 *
 * TX:
 *
 *   Base of the descriptor table is programmed using BFE_DMATX_CTRL control
 *   register. Each 'addr' points to DMA buffer (or packet data buffer) to
 *   be transmitted and 'ctl' has the length of the packet (usually MTU).
 *
 *  ----------------------|
 *  | addr |Descriptor 0  |
 *  | ctl  |              |
 *  ----------------------|
 *  | addr |Descriptor 1  |    SOF (start of the frame)
 *  | ctl  |              |
 *  ----------------------|
 *  | ...  |Descriptor... |    EOF (end of the frame)
 *  | ...  |              |
 *  ----------------------|
 *  | addr |Descritor 127 |
 *  | ctl  | EOT          |    EOT (End of Table)
 *  ----------------------|
 *
 * 'r_curr_desc'  : pointer to current descriptor which can be used to transmit
 *                  a packet.
 * 'r_avail_desc' : decremented whenever a packet is being sent.
 * 'r_cons_desc'  : incremented whenever a packet is sent down the wire and
 *                  notified by an interrupt to bfe driver.
 *
 * RX:
 *
 *   Base of the descriptor table is programmed using BFE_DMARX_CTRL control
 *   register. Each 'addr' points to DMA buffer (or packet data buffer). 'ctl'
 *   contains the size of the DMA buffer and all the DMA buffers are
 *   pre-allocated during attach and hence the maxmium size of the packet is
 *   also known (r_buf_len from the bfe_rint_t structure). During RX interrupt
 *   the packet length is embedded in bfe_header_t which is added by the
 *   chip in the beginning of the packet.
 *
 *  ----------------------|
 *  | addr |Descriptor 0  |
 *  | ctl  |              |
 *  ----------------------|
 *  | addr |Descriptor 1  |
 *  | ctl  |              |
 *  ----------------------|
 *  | ...  |Descriptor... |
 *  | ...  |              |
 *  ----------------------|
 *  | addr |Descriptor 127|
 *  | ctl  | EOT          |    EOT (End of Table)
 *  ----------------------|
 *
 * 'r_curr_desc'  : pointer to current descriptor while receving a packet.
 *
 */

#define	MODULE_NAME	"bfe"

/*
 * Used for checking PHY (link state, speed)
 */
#define	BFE_TIMEOUT_INTERVAL	(1000 * 1000 * 1000)


/*
 * Chip restart action and reason for restart
 */
#define	BFE_ACTION_RESTART		0x1	/* For restarting the chip */
#define	BFE_ACTION_RESTART_SETPROP	0x2	/* restart due to setprop */
#define	BFE_ACTION_RESTART_FAULT	0x4	/* restart due to fault */
#define	BFE_ACTION_RESTART_PKT		0x8	/* restart due to pkt timeout */

static	char	bfe_ident[] = "bfe driver for Broadcom BCM4401 chipsets";

/*
 * Function Prototypes for bfe driver.
 */
static	int	bfe_check_link(bfe_t *);
static	void	bfe_report_link(bfe_t *);
static	void	bfe_chip_halt(bfe_t *);
static	void	bfe_chip_reset(bfe_t *);
static	void	bfe_tx_desc_init(bfe_ring_t *);
static	void	bfe_rx_desc_init(bfe_ring_t *);
static	void	bfe_set_rx_mode(bfe_t *);
static	void	bfe_enable_chip_intrs(bfe_t *);
static	void	bfe_chip_restart(bfe_t *);
static	void	bfe_init_vars(bfe_t *);
static	void	bfe_clear_stats(bfe_t *);
static	void	bfe_gather_stats(bfe_t *);
static	void	bfe_error(dev_info_t *, char *, ...);
static	int	bfe_mac_getprop(void *, const char *, mac_prop_id_t, uint_t,
    void *);
static	int	bfe_mac_setprop(void *, const char *, mac_prop_id_t, uint_t,
    const void *);
static	int	bfe_tx_reclaim(bfe_ring_t *);
int	bfe_mac_set_ether_addr(void *, const uint8_t *);


/*
 * Macros for ddi_dma_sync().
 */
#define	SYNC_DESC(r, s, l, d)	\
	(void) ddi_dma_sync(r->r_desc_dma_handle, \
	    (off_t)(s * sizeof (bfe_desc_t)), \
	    (size_t)(l * sizeof (bfe_desc_t)), \
	    d)

#define	SYNC_BUF(r, s, b, l, d) \
	(void) ddi_dma_sync(r->r_buf_dma[s].handle, \
	    (off_t)(b), (size_t)(l), d)

/*
 * Supported Broadcom BCM4401 Cards.
 */
static bfe_cards_t bfe_cards[] = {
	{ 0x14e4, 0x170c, "BCM4401 100Base-TX"},
};


/*
 * DMA attributes for device registers, packet data (buffer) and
 * descriptor table.
 */
static struct ddi_device_acc_attr bfe_dev_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

static struct ddi_device_acc_attr bfe_buf_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,	/* native endianness */
	DDI_STRICTORDER_ACC
};

static ddi_dma_attr_t bfe_dma_attr_buf = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo */
	BFE_PCI_DMA - 1,	/* dma_attr_addr_hi */
	0x1fff,			/* dma_attr_count_max */
	8,			/* dma_attr_align */
	0,			/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0x1fff,			/* dma_attr_maxxfer */
	BFE_PCI_DMA - 1,	/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};

static ddi_dma_attr_t bfe_dma_attr_desc = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo */
	BFE_PCI_DMA - 1,	/* dma_attr_addr_hi */
	BFE_PCI_DMA - 1,	/* dma_attr_count_max */
	BFE_DESC_ALIGN,		/* dma_attr_align */
	0,			/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	BFE_PCI_DMA - 1,	/* dma_attr_maxxfer */
	BFE_PCI_DMA - 1,	/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};

/*
 * Ethernet broadcast addresses.
 */
static uchar_t bfe_broadcast[ETHERADDRL] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

#define	ASSERT_ALL_LOCKS(bfe) {	\
	ASSERT(mutex_owned(&bfe->bfe_tx_ring.r_lock));	\
	ASSERT(rw_write_held(&bfe->bfe_rwlock));	\
}

/*
 * Debugging and error reproting code.
 */
static void
bfe_error(dev_info_t *dip, char *fmt, ...)
{
	va_list ap;
	char	buf[256];

	va_start(ap, fmt);
	(void) vsnprintf(buf, sizeof (buf), fmt, ap);
	va_end(ap);

	if (dip) {
		cmn_err(CE_WARN, "%s%d: %s",
		    ddi_driver_name(dip), ddi_get_instance(dip), buf);
	} else {
		cmn_err(CE_WARN, "bfe: %s", buf);
	}
}

/*
 * Grabs all necessary locks to block any other operation on the chip.
 */
static void
bfe_grab_locks(bfe_t *bfe)
{
	bfe_ring_t *tx = &bfe->bfe_tx_ring;

	/*
	 * Grab all the locks.
	 * - bfe_rwlock : locks down whole chip including RX.
	 * - tx's r_lock : locks down only TX side.
	 */
	rw_enter(&bfe->bfe_rwlock, RW_WRITER);
	mutex_enter(&tx->r_lock);

	/*
	 * Note that we don't use RX's r_lock.
	 */
}

/*
 * Release lock on chip/drver.
 */
static void
bfe_release_locks(bfe_t *bfe)
{
	bfe_ring_t *tx = &bfe->bfe_tx_ring;

	/*
	 * Release all the locks in the order in which they were grabbed.
	 */
	mutex_exit(&tx->r_lock);
	rw_exit(&bfe->bfe_rwlock);
}


/*
 * It's used to make sure that the write to device register was successful.
 */
static int
bfe_wait_bit(bfe_t *bfe, uint32_t reg, uint32_t bit,
    ulong_t t, const int clear)
{
	ulong_t i;
	uint32_t v;

	for (i = 0; i < t; i++) {
		v = INL(bfe, reg);

		if (clear && !(v & bit))
			break;

		if (!clear && (v & bit))
			break;

		drv_usecwait(10);
	}

	/* if device still didn't see the value */
	if (i == t)
		return (-1);

	return (0);
}

/*
 * PHY functions (read, write, stop, reset and startup)
 */
static int
bfe_read_phy(bfe_t *bfe, uint32_t reg)
{
	OUTL(bfe, BFE_EMAC_ISTAT, BFE_EMAC_INT_MII);
	OUTL(bfe, BFE_MDIO_DATA, (BFE_MDIO_SB_START |
	    (BFE_MDIO_OP_READ << BFE_MDIO_OP_SHIFT) |
	    (bfe->bfe_phy_addr << BFE_MDIO_PMD_SHIFT) |
	    (reg << BFE_MDIO_RA_SHIFT) |
	    (BFE_MDIO_TA_VALID << BFE_MDIO_TA_SHIFT)));

	(void) bfe_wait_bit(bfe, BFE_EMAC_ISTAT, BFE_EMAC_INT_MII, 10, 0);

	return ((INL(bfe, BFE_MDIO_DATA) & BFE_MDIO_DATA_DATA));
}

static void
bfe_write_phy(bfe_t *bfe, uint32_t reg, uint32_t val)
{
	OUTL(bfe, BFE_EMAC_ISTAT, BFE_EMAC_INT_MII);
	OUTL(bfe,  BFE_MDIO_DATA, (BFE_MDIO_SB_START |
	    (BFE_MDIO_OP_WRITE << BFE_MDIO_OP_SHIFT) |
	    (bfe->bfe_phy_addr << BFE_MDIO_PMD_SHIFT) |
	    (reg << BFE_MDIO_RA_SHIFT) |
	    (BFE_MDIO_TA_VALID << BFE_MDIO_TA_SHIFT) |
	    (val & BFE_MDIO_DATA_DATA)));

	(void) bfe_wait_bit(bfe, BFE_EMAC_ISTAT, BFE_EMAC_INT_MII, 10, 0);
}

/*
 * It resets the PHY layer.
 */
static int
bfe_reset_phy(bfe_t *bfe)
{
	uint32_t i;

	bfe_write_phy(bfe, MII_CONTROL, MII_CONTROL_RESET);
	drv_usecwait(100);
	for (i = 0; i < 10; i++) {
		if (bfe_read_phy(bfe, MII_CONTROL) &
		    MII_CONTROL_RESET) {
			drv_usecwait(500);
			continue;
		}

		break;
	}

	if (i == 10) {
		bfe_error(bfe->bfe_dip, "Timeout waiting for PHY to reset");
		bfe->bfe_phy_state = BFE_PHY_RESET_TIMEOUT;
		return (BFE_FAILURE);
	}

	bfe->bfe_phy_state = BFE_PHY_RESET_DONE;

	return (BFE_SUCCESS);
}

/*
 * Make sure timer function is out of our way and especially during
 * detach.
 */
static void
bfe_stop_timer(bfe_t *bfe)
{
	if (bfe->bfe_periodic_id) {
		ddi_periodic_delete(bfe->bfe_periodic_id);
		bfe->bfe_periodic_id = NULL;
	}
}

/*
 * Stops the PHY
 */
static void
bfe_stop_phy(bfe_t *bfe)
{
	bfe_write_phy(bfe, MII_CONTROL, MII_CONTROL_PWRDN |
	    MII_CONTROL_ISOLATE);

	bfe->bfe_chip.link = LINK_STATE_UNKNOWN;
	bfe->bfe_chip.speed = 0;
	bfe->bfe_chip.duplex = LINK_DUPLEX_UNKNOWN;

	bfe->bfe_phy_state = BFE_PHY_STOPPED;

	/*
	 * Report the link status to MAC layer.
	 */
	if (bfe->bfe_machdl != NULL)
		(void) bfe_report_link(bfe);
}

static int
bfe_probe_phy(bfe_t *bfe)
{
	int phy;
	uint32_t status;

	if (bfe->bfe_phy_addr) {
		status = bfe_read_phy(bfe, MII_STATUS);
		if (status != 0xffff && status != 0) {
			bfe_write_phy(bfe, MII_CONTROL, 0);
			return (BFE_SUCCESS);
		}
	}

	for (phy = 0; phy < 32; phy++) {
		bfe->bfe_phy_addr = phy;
		status = bfe_read_phy(bfe, MII_STATUS);
		if (status != 0xffff && status != 0) {
			bfe_write_phy(bfe, MII_CONTROL, 0);
			return (BFE_SUCCESS);
		}
	}

	return (BFE_FAILURE);
}

/*
 * This timeout function fires at BFE_TIMEOUT_INTERVAL to check the link
 * status.
 */
static void
bfe_timeout(void *arg)
{
	bfe_t *bfe = (bfe_t *)arg;
	int resched = 0;

	/*
	 * We don't grab any lock because bfe can't go away.
	 * untimeout() will wait for this timeout instance to complete.
	 */
	if (bfe->bfe_chip_action & BFE_ACTION_RESTART) {
		/*
		 * Restart the chip.
		 */
		bfe_grab_locks(bfe);
		bfe_chip_restart(bfe);
		bfe->bfe_chip_action &= ~BFE_ACTION_RESTART;
		bfe->bfe_chip_action &= ~BFE_ACTION_RESTART_FAULT;
		bfe->bfe_chip_action &= ~BFE_ACTION_RESTART_PKT;
		bfe_release_locks(bfe);
		mac_tx_update(bfe->bfe_machdl);
		/* Restart will register a new timeout */
		return;
	}

	rw_enter(&bfe->bfe_rwlock, RW_READER);

	if (bfe->bfe_chip_state == BFE_CHIP_ACTIVE) {
		hrtime_t hr;

		hr = gethrtime();
		if (bfe->bfe_tx_stall_time != 0 &&
		    hr > bfe->bfe_tx_stall_time) {
			DTRACE_PROBE2(chip__restart, int, bfe->bfe_unit,
			    char *, "pkt timeout");
			bfe->bfe_chip_action |=
			    (BFE_ACTION_RESTART | BFE_ACTION_RESTART_PKT);
			bfe->bfe_tx_stall_time = 0;
		}
	}

	if (bfe->bfe_phy_state == BFE_PHY_STARTED) {
		/*
		 * Report the link status to MAC layer if link status changed.
		 */
		if (bfe_check_link(bfe)) {
			bfe_report_link(bfe);
			if (bfe->bfe_chip.link == LINK_STATE_UP) {
				uint32_t val, flow;

				val = INL(bfe, BFE_TX_CTRL);
				val &= ~BFE_TX_DUPLEX;
				if (bfe->bfe_chip.duplex == LINK_DUPLEX_FULL) {
					val |= BFE_TX_DUPLEX;
					flow = INL(bfe, BFE_RXCONF);
					flow &= ~BFE_RXCONF_FLOW;
					OUTL(bfe, BFE_RXCONF, flow);

					flow = INL(bfe, BFE_MAC_FLOW);
					flow &= ~(BFE_FLOW_RX_HIWAT);
					OUTL(bfe, BFE_MAC_FLOW, flow);
				}

				resched = 1;

				OUTL(bfe, BFE_TX_CTRL, val);
				DTRACE_PROBE1(link__up,
				    int, bfe->bfe_unit);
			}
		}
	}

	rw_exit(&bfe->bfe_rwlock);

	if (resched)
		mac_tx_update(bfe->bfe_machdl);
}

/*
 * Starts PHY layer.
 */
static int
bfe_startup_phy(bfe_t *bfe)
{
	uint16_t bmsr, bmcr, anar;
	int	prog, s;
	int phyid1, phyid2;

	if (bfe_probe_phy(bfe) == BFE_FAILURE) {
		bfe->bfe_phy_state = BFE_PHY_NOTFOUND;
		return (BFE_FAILURE);
	}

	(void) bfe_reset_phy(bfe);

	phyid1 = bfe_read_phy(bfe, MII_PHYIDH);
	phyid2 = bfe_read_phy(bfe, MII_PHYIDL);
	bfe->bfe_phy_id = (phyid1 << 16) | phyid2;

	bmsr = bfe_read_phy(bfe, MII_STATUS);
	anar = bfe_read_phy(bfe, MII_AN_ADVERT);

again:
	anar &= ~(MII_ABILITY_100BASE_T4 |
	    MII_ABILITY_100BASE_TX_FD | MII_ABILITY_100BASE_TX |
	    MII_ABILITY_10BASE_T_FD | MII_ABILITY_10BASE_T);

	/*
	 * Supported hardware modes are in bmsr.
	 */
	bfe->bfe_chip.bmsr = bmsr;

	/*
	 * Assume no capabilities are supported in the hardware.
	 */
	bfe->bfe_cap_aneg = bfe->bfe_cap_100T4 =
	    bfe->bfe_cap_100fdx = bfe->bfe_cap_100hdx =
	    bfe->bfe_cap_10fdx = bfe->bfe_cap_10hdx = 0;

	/*
	 * Assume property is set.
	 */
	s = 1;
	if (!(bfe->bfe_chip_action & BFE_ACTION_RESTART_SETPROP)) {
		/*
		 * Property is not set which means bfe_mac_setprop()
		 * is not called on us.
		 */
		s = 0;
	}

	bmcr = prog = 0;

	if (bmsr & MII_STATUS_100_BASEX_FD) {
		bfe->bfe_cap_100fdx = 1;
		if (s == 0) {
			anar |= MII_ABILITY_100BASE_TX_FD;
			bfe->bfe_adv_100fdx = 1;
			prog++;
		} else if (bfe->bfe_adv_100fdx) {
			anar |= MII_ABILITY_100BASE_TX_FD;
			prog++;
		}
	}

	if (bmsr & MII_STATUS_100_BASE_T4) {
		bfe->bfe_cap_100T4 = 1;
		if (s == 0) {
			anar |= MII_ABILITY_100BASE_T4;
			bfe->bfe_adv_100T4 = 1;
			prog++;
		} else if (bfe->bfe_adv_100T4) {
			anar |= MII_ABILITY_100BASE_T4;
			prog++;
		}
	}

	if (bmsr & MII_STATUS_100_BASEX) {
		bfe->bfe_cap_100hdx = 1;
		if (s == 0) {
			anar |= MII_ABILITY_100BASE_TX;
			bfe->bfe_adv_100hdx = 1;
			prog++;
		} else if (bfe->bfe_adv_100hdx) {
			anar |= MII_ABILITY_100BASE_TX;
			prog++;
		}
	}

	if (bmsr & MII_STATUS_10_FD) {
		bfe->bfe_cap_10fdx = 1;
		if (s == 0) {
			anar |= MII_ABILITY_10BASE_T_FD;
			bfe->bfe_adv_10fdx = 1;
			prog++;
		} else if (bfe->bfe_adv_10fdx) {
			anar |= MII_ABILITY_10BASE_T_FD;
			prog++;
		}
	}

	if (bmsr & MII_STATUS_10) {
		bfe->bfe_cap_10hdx = 1;
		if (s == 0) {
			anar |= MII_ABILITY_10BASE_T;
			bfe->bfe_adv_10hdx = 1;
			prog++;
		} else if (bfe->bfe_adv_10hdx) {
			anar |= MII_ABILITY_10BASE_T;
			prog++;
		}
	}

	if (bmsr & MII_STATUS_CANAUTONEG) {
		bfe->bfe_cap_aneg = 1;
		if (s == 0) {
			bfe->bfe_adv_aneg = 1;
		}
	}

	if (prog == 0) {
		if (s == 0) {
			bfe_error(bfe->bfe_dip,
			    "No valid link mode selected. Powering down PHY");
			bfe_stop_phy(bfe);
			bfe_report_link(bfe);
			return (BFE_FAILURE);
		}

		/*
		 * If property is set then user would have goofed up. So we
		 * go back to default properties.
		 */
		bfe->bfe_chip_action &= ~BFE_ACTION_RESTART_SETPROP;
		goto again;
	}

	if (bfe->bfe_adv_aneg && (bmsr & MII_STATUS_CANAUTONEG)) {
		bmcr = (MII_CONTROL_ANE | MII_CONTROL_RSAN);
	} else {
		if (bfe->bfe_adv_100fdx)
			bmcr = (MII_CONTROL_100MB | MII_CONTROL_FDUPLEX);
		else if (bfe->bfe_adv_100hdx)
			bmcr = MII_CONTROL_100MB;
		else if (bfe->bfe_adv_10fdx)
			bmcr = MII_CONTROL_FDUPLEX;
		else
			bmcr = 0;		/* 10HDX */
	}

	if (prog)
		bfe_write_phy(bfe, MII_AN_ADVERT, anar);

	if (bmcr)
		bfe_write_phy(bfe, MII_CONTROL, bmcr);

	bfe->bfe_mii_anar = anar;
	bfe->bfe_mii_bmcr = bmcr;
	bfe->bfe_phy_state = BFE_PHY_STARTED;

	if (bfe->bfe_periodic_id == NULL) {
		bfe->bfe_periodic_id = ddi_periodic_add(bfe_timeout,
		    (void *)bfe, BFE_TIMEOUT_INTERVAL, DDI_IPL_0);

		DTRACE_PROBE1(first__timeout, int, bfe->bfe_unit);
	}

	DTRACE_PROBE4(phy_started, int, bfe->bfe_unit,
	    int, bmsr, int, bmcr, int, anar);

	return (BFE_SUCCESS);
}

/*
 * Reports link status back to MAC Layer.
 */
static void
bfe_report_link(bfe_t *bfe)
{
	mac_link_update(bfe->bfe_machdl, bfe->bfe_chip.link);
}

/*
 * Reads PHY/MII registers and get the link status for us.
 */
static int
bfe_check_link(bfe_t *bfe)
{
	uint16_t bmsr, bmcr, anar, anlpar;
	int speed, duplex, link;

	speed = bfe->bfe_chip.speed;
	duplex = bfe->bfe_chip.duplex;
	link = bfe->bfe_chip.link;

	bmsr = bfe_read_phy(bfe, MII_STATUS);
	bfe->bfe_mii_bmsr = bmsr;

	bmcr = bfe_read_phy(bfe, MII_CONTROL);

	anar = bfe_read_phy(bfe, MII_AN_ADVERT);
	bfe->bfe_mii_anar = anar;

	anlpar = bfe_read_phy(bfe, MII_AN_LPABLE);
	bfe->bfe_mii_anlpar = anlpar;

	bfe->bfe_mii_exp = bfe_read_phy(bfe, MII_AN_EXPANSION);

	/*
	 * If exp register is not present in PHY.
	 */
	if (bfe->bfe_mii_exp == 0xffff) {
		bfe->bfe_mii_exp = 0;
	}

	if ((bmsr & MII_STATUS_LINKUP) == 0) {
		bfe->bfe_chip.link = LINK_STATE_DOWN;
		bfe->bfe_chip.speed = 0;
		bfe->bfe_chip.duplex = LINK_DUPLEX_UNKNOWN;
		goto done;
	}

	bfe->bfe_chip.link = LINK_STATE_UP;

	if (!(bmcr & MII_CONTROL_ANE)) {
		/* Forced mode */
		if (bmcr & MII_CONTROL_100MB)
			bfe->bfe_chip.speed = 100000000;
		else
			bfe->bfe_chip.speed = 10000000;

		if (bmcr & MII_CONTROL_FDUPLEX)
			bfe->bfe_chip.duplex = LINK_DUPLEX_FULL;
		else
			bfe->bfe_chip.duplex = LINK_DUPLEX_HALF;

	} else if ((!(bmsr & MII_STATUS_CANAUTONEG)) ||
	    (!(bmsr & MII_STATUS_ANDONE))) {
		bfe->bfe_chip.speed = 0;
		bfe->bfe_chip.duplex = LINK_DUPLEX_UNKNOWN;
	} else if (anar & anlpar & MII_ABILITY_100BASE_TX_FD) {
		bfe->bfe_chip.speed = 100000000;
		bfe->bfe_chip.duplex = LINK_DUPLEX_FULL;
	} else if (anar & anlpar & MII_ABILITY_100BASE_T4) {
		bfe->bfe_chip.speed = 100000000;
		bfe->bfe_chip.duplex = LINK_DUPLEX_HALF;
	} else if (anar & anlpar & MII_ABILITY_100BASE_TX) {
		bfe->bfe_chip.speed = 100000000;
		bfe->bfe_chip.duplex = LINK_DUPLEX_HALF;
	} else if (anar & anlpar & MII_ABILITY_10BASE_T_FD) {
		bfe->bfe_chip.speed = 10000000;
		bfe->bfe_chip.duplex = LINK_DUPLEX_FULL;
	} else if (anar & anlpar & MII_ABILITY_10BASE_T) {
		bfe->bfe_chip.speed = 10000000;
		bfe->bfe_chip.duplex = LINK_DUPLEX_HALF;
	} else {
		bfe->bfe_chip.speed = 0;
		bfe->bfe_chip.duplex = LINK_DUPLEX_UNKNOWN;
	}

done:
	/*
	 * If speed or link status or duplex mode changed then report to
	 * MAC layer which is done by the caller.
	 */
	if (speed != bfe->bfe_chip.speed ||
	    duplex != bfe->bfe_chip.duplex ||
	    link != bfe->bfe_chip.link) {
		return (1);
	}

	return (0);
}

static void
bfe_cam_write(bfe_t *bfe, uchar_t *d, int index)
{
	uint32_t v;

	v = ((uint32_t)d[2] << 24);
	v |= ((uint32_t)d[3] << 16);
	v |= ((uint32_t)d[4] << 8);
	v |= (uint32_t)d[5];

	OUTL(bfe, BFE_CAM_DATA_LO, v);
	v = (BFE_CAM_HI_VALID |
	    (((uint32_t)d[0]) << 8) |
	    (((uint32_t)d[1])));

	OUTL(bfe, BFE_CAM_DATA_HI, v);
	OUTL(bfe, BFE_CAM_CTRL, (BFE_CAM_WRITE |
	    ((uint32_t)index << BFE_CAM_INDEX_SHIFT)));
	(void) bfe_wait_bit(bfe, BFE_CAM_CTRL, BFE_CAM_BUSY, 10, 1);
}

/*
 * Chip related functions (halt, reset, start).
 */
static void
bfe_chip_halt(bfe_t *bfe)
{
	/*
	 * Disables interrupts.
	 */
	OUTL(bfe, BFE_INTR_MASK, 0);
	FLUSH(bfe, BFE_INTR_MASK);

	OUTL(bfe,  BFE_ENET_CTRL, BFE_ENET_DISABLE);

	/*
	 * Wait until TX and RX finish their job.
	 */
	(void) bfe_wait_bit(bfe, BFE_ENET_CTRL, BFE_ENET_DISABLE, 20, 1);

	/*
	 * Disables DMA engine.
	 */
	OUTL(bfe, BFE_DMARX_CTRL, 0);
	OUTL(bfe, BFE_DMATX_CTRL, 0);

	drv_usecwait(10);

	bfe->bfe_chip_state = BFE_CHIP_HALT;
}

static void
bfe_chip_restart(bfe_t *bfe)
{
	DTRACE_PROBE2(chip__restart, int, bfe->bfe_unit,
	    int, bfe->bfe_chip_action);

	/*
	 * Halt chip and PHY.
	 */
	bfe_chip_halt(bfe);
	bfe_stop_phy(bfe);
	bfe->bfe_chip_state = BFE_CHIP_STOPPED;

	/*
	 * Init variables.
	 */
	bfe_init_vars(bfe);

	/*
	 * Reset chip and start PHY.
	 */
	bfe_chip_reset(bfe);

	/*
	 * DMA descriptor rings.
	 */
	bfe_tx_desc_init(&bfe->bfe_tx_ring);
	bfe_rx_desc_init(&bfe->bfe_rx_ring);

	bfe->bfe_chip_state = BFE_CHIP_ACTIVE;
	bfe_set_rx_mode(bfe);
	bfe_enable_chip_intrs(bfe);
}

/*
 * Disables core by stopping the clock.
 */
static void
bfe_core_disable(bfe_t *bfe)
{
	if ((INL(bfe, BFE_SBTMSLOW) & BFE_RESET))
		return;

	OUTL(bfe, BFE_SBTMSLOW, (BFE_REJECT | BFE_CLOCK));
	(void) bfe_wait_bit(bfe, BFE_SBTMSLOW, BFE_REJECT, 100, 0);
	(void) bfe_wait_bit(bfe, BFE_SBTMSHIGH, BFE_BUSY, 100, 1);
	OUTL(bfe, BFE_SBTMSLOW, (BFE_FGC | BFE_CLOCK | BFE_REJECT | BFE_RESET));
	FLUSH(bfe, BFE_SBTMSLOW);
	drv_usecwait(10);
	OUTL(bfe, BFE_SBTMSLOW, (BFE_REJECT | BFE_RESET));
	drv_usecwait(10);
}

/*
 * Resets core.
 */
static void
bfe_core_reset(bfe_t *bfe)
{
	uint32_t val;

	/*
	 * First disable the core.
	 */
	bfe_core_disable(bfe);

	OUTL(bfe, BFE_SBTMSLOW, (BFE_RESET | BFE_CLOCK | BFE_FGC));
	FLUSH(bfe, BFE_SBTMSLOW);
	drv_usecwait(1);

	if (INL(bfe, BFE_SBTMSHIGH) & BFE_SERR)
		OUTL(bfe, BFE_SBTMSHIGH, 0);

	val = INL(bfe, BFE_SBIMSTATE);
	if (val & (BFE_IBE | BFE_TO))
		OUTL(bfe, BFE_SBIMSTATE, val & ~(BFE_IBE | BFE_TO));

	OUTL(bfe, BFE_SBTMSLOW, (BFE_CLOCK | BFE_FGC));
	FLUSH(bfe, BFE_SBTMSLOW);
	drv_usecwait(1);

	OUTL(bfe, BFE_SBTMSLOW, BFE_CLOCK);
	FLUSH(bfe, BFE_SBTMSLOW);
	drv_usecwait(1);
}

static void
bfe_setup_config(bfe_t *bfe, uint32_t cores)
{
	uint32_t bar_orig, val;

	/*
	 * Change bar0 window to map sbtopci registers.
	 */
	bar_orig = pci_config_get32(bfe->bfe_conf_handle, BFE_BAR0_WIN);
	pci_config_put32(bfe->bfe_conf_handle, BFE_BAR0_WIN, BFE_REG_PCI);

	/* Just read it and don't do anything */
	val = INL(bfe, BFE_SBIDHIGH) & BFE_IDH_CORE;

	val = INL(bfe, BFE_SBINTVEC);
	val |= cores;
	OUTL(bfe, BFE_SBINTVEC, val);

	val = INL(bfe, BFE_SSB_PCI_TRANS_2);
	val |= BFE_SSB_PCI_PREF | BFE_SSB_PCI_BURST;
	OUTL(bfe, BFE_SSB_PCI_TRANS_2, val);

	/*
	 * Restore bar0 window mapping.
	 */
	pci_config_put32(bfe->bfe_conf_handle, BFE_BAR0_WIN, bar_orig);
}

/*
 * Resets chip and starts PHY.
 */
static void
bfe_chip_reset(bfe_t *bfe)
{
	uint32_t val;

	/* Set the interrupt vector for the enet core */
	bfe_setup_config(bfe, BFE_INTVEC_ENET0);

	/* check if core is up */
	val = INL(bfe, BFE_SBTMSLOW) &
	    (BFE_RESET | BFE_REJECT | BFE_CLOCK);

	if (val == BFE_CLOCK) {
		OUTL(bfe, BFE_RCV_LAZY, 0);
		OUTL(bfe, BFE_ENET_CTRL, BFE_ENET_DISABLE);
		(void) bfe_wait_bit(bfe, BFE_ENET_CTRL,
		    BFE_ENET_DISABLE, 10, 1);
		OUTL(bfe, BFE_DMATX_CTRL, 0);
		FLUSH(bfe, BFE_DMARX_STAT);
		drv_usecwait(20000);	/* 20 milli seconds */
		if (INL(bfe, BFE_DMARX_STAT) & BFE_STAT_EMASK) {
			(void) bfe_wait_bit(bfe, BFE_DMARX_STAT, BFE_STAT_SIDLE,
			    10, 0);
		}
		OUTL(bfe, BFE_DMARX_CTRL, 0);
	}

	bfe_core_reset(bfe);
	bfe_clear_stats(bfe);

	OUTL(bfe, BFE_MDIO_CTRL, 0x8d);
	val = INL(bfe, BFE_DEVCTRL);
	if (!(val & BFE_IPP))
		OUTL(bfe, BFE_ENET_CTRL, BFE_ENET_EPSEL);
	else if (INL(bfe, BFE_DEVCTRL & BFE_EPR)) {
		OUTL_AND(bfe, BFE_DEVCTRL, ~BFE_EPR);
		drv_usecwait(20000);    /* 20 milli seconds */
	}

	OUTL_OR(bfe, BFE_MAC_CTRL, BFE_CTRL_CRC32_ENAB | BFE_CTRL_LED);

	OUTL_AND(bfe, BFE_MAC_CTRL, ~BFE_CTRL_PDOWN);

	OUTL(bfe, BFE_RCV_LAZY, ((1 << BFE_LAZY_FC_SHIFT) &
	    BFE_LAZY_FC_MASK));

	OUTL_OR(bfe, BFE_RCV_LAZY, 0);

	OUTL(bfe, BFE_RXMAXLEN, bfe->bfe_rx_ring.r_buf_len);
	OUTL(bfe, BFE_TXMAXLEN, bfe->bfe_tx_ring.r_buf_len);

	OUTL(bfe, BFE_TX_WMARK, 56);

	/* Program DMA channels */
	OUTL(bfe, BFE_DMATX_CTRL, BFE_TX_CTRL_ENABLE);

	/*
	 * DMA addresses need to be added to BFE_PCI_DMA
	 */
	OUTL(bfe, BFE_DMATX_ADDR,
	    bfe->bfe_tx_ring.r_desc_cookie.dmac_laddress + BFE_PCI_DMA);

	OUTL(bfe, BFE_DMARX_CTRL, (BFE_RX_OFFSET << BFE_RX_CTRL_ROSHIFT)
	    | BFE_RX_CTRL_ENABLE);

	OUTL(bfe, BFE_DMARX_ADDR,
	    bfe->bfe_rx_ring.r_desc_cookie.dmac_laddress + BFE_PCI_DMA);

	(void) bfe_startup_phy(bfe);

	bfe->bfe_chip_state = BFE_CHIP_INITIALIZED;
}

/*
 * It enables interrupts. Should be the last step while starting chip.
 */
static void
bfe_enable_chip_intrs(bfe_t *bfe)
{
	/* Enable the chip and core */
	OUTL(bfe, BFE_ENET_CTRL, BFE_ENET_ENABLE);

	/* Enable interrupts */
	OUTL(bfe, BFE_INTR_MASK, BFE_IMASK_DEF);
}

/*
 * Common code to take care of setting RX side mode (filter).
 */
static void
bfe_set_rx_mode(bfe_t *bfe)
{
	uint32_t val;
	int i;
	ether_addr_t mac[ETHERADDRL] = {0, 0, 0, 0, 0, 0};

	/*
	 * We don't touch RX filter if we were asked to suspend. It's fine
	 * if chip is not active (no interface is plumbed on us).
	 */
	if (bfe->bfe_chip_state == BFE_CHIP_SUSPENDED)
		return;

	val = INL(bfe, BFE_RXCONF);

	val &= ~BFE_RXCONF_PROMISC;
	val &= ~BFE_RXCONF_DBCAST;

	if ((bfe->bfe_chip_mode & BFE_RX_MODE_ENABLE) == 0) {
		OUTL(bfe, BFE_CAM_CTRL, 0);
		FLUSH(bfe, BFE_CAM_CTRL);
	} else if (bfe->bfe_chip_mode & BFE_RX_MODE_PROMISC) {
		val |= BFE_RXCONF_PROMISC;
		val &= ~BFE_RXCONF_DBCAST;
	} else {
		if (bfe->bfe_chip_state == BFE_CHIP_ACTIVE) {
			/* Flush everything */
			OUTL(bfe, BFE_RXCONF, val |
			    BFE_RXCONF_PROMISC | BFE_RXCONF_ALLMULTI);
			FLUSH(bfe, BFE_RXCONF);
		}

		/* Disable CAM */
		OUTL(bfe, BFE_CAM_CTRL, 0);
		FLUSH(bfe, BFE_CAM_CTRL);

		/*
		 * We receive all multicast packets.
		 */
		val |= BFE_RXCONF_ALLMULTI;

		for (i = 0; i < BFE_MAX_MULTICAST_TABLE - 1; i++) {
			bfe_cam_write(bfe, (uchar_t *)mac, i);
		}

		bfe_cam_write(bfe, bfe->bfe_ether_addr, i);

		/* Enable CAM */
		OUTL_OR(bfe, BFE_CAM_CTRL, BFE_CAM_ENABLE);
		FLUSH(bfe, BFE_CAM_CTRL);
	}

	DTRACE_PROBE2(rx__mode__filter, int, bfe->bfe_unit,
	    int, val);

	OUTL(bfe, BFE_RXCONF, val);
	FLUSH(bfe, BFE_RXCONF);
}

/*
 * Reset various variable values to initial state.
 */
static void
bfe_init_vars(bfe_t *bfe)
{
	bfe->bfe_chip_mode = BFE_RX_MODE_ENABLE;

	/* Initial assumption */
	bfe->bfe_chip.link = LINK_STATE_UNKNOWN;
	bfe->bfe_chip.speed = 0;
	bfe->bfe_chip.duplex = LINK_DUPLEX_UNKNOWN;

	bfe->bfe_periodic_id = NULL;
	bfe->bfe_chip_state = BFE_CHIP_UNINITIALIZED;

	bfe->bfe_tx_stall_time = 0;
}

/*
 * Initializes TX side descriptor entries (bfe_desc_t). Each descriptor entry
 * has control (desc_ctl) and address (desc_addr) member.
 */
static void
bfe_tx_desc_init(bfe_ring_t *r)
{
	int i;
	uint32_t v;

	for (i = 0; i < r->r_ndesc; i++) {
		PUT_DESC(r, (uint32_t *)&(r->r_desc[i].desc_ctl),
		    (r->r_buf_dma[i].len & BFE_DESC_LEN));

		/*
		 * DMA addresses need to be added to BFE_PCI_DMA
		 */
		PUT_DESC(r, (uint32_t *)&(r->r_desc[i].desc_addr),
		    (r->r_buf_dma[i].cookie.dmac_laddress + BFE_PCI_DMA));
	}

	v = GET_DESC(r, (uint32_t *)&(r->r_desc[i - 1].desc_ctl));
	PUT_DESC(r, (uint32_t *)&(r->r_desc[i - 1].desc_ctl),
	    v | BFE_DESC_EOT);

	(void) SYNC_DESC(r, 0, r->r_ndesc, DDI_DMA_SYNC_FORDEV);

	r->r_curr_desc = 0;
	r->r_avail_desc = TX_NUM_DESC;
	r->r_cons_desc = 0;
}

/*
 * Initializes RX side descriptor entries (bfe_desc_t). Each descriptor entry
 * has control (desc_ctl) and address (desc_addr) member.
 */
static void
bfe_rx_desc_init(bfe_ring_t *r)
{
	int i;
	uint32_t v;

	for (i = 0; i < r->r_ndesc; i++) {
		PUT_DESC(r, (uint32_t *)&(r->r_desc[i].desc_ctl),
		    (r->r_buf_dma[i].len& BFE_DESC_LEN));

		PUT_DESC(r, (uint32_t *)&(r->r_desc[i].desc_addr),
		    (r->r_buf_dma[i].cookie.dmac_laddress + BFE_PCI_DMA));

		/* Initialize rx header (len, flags) */
		bzero(r->r_buf_dma[i].addr, sizeof (bfe_rx_header_t));

		(void) SYNC_BUF(r, i, 0, sizeof (bfe_rx_header_t),
		    DDI_DMA_SYNC_FORDEV);
	}

	v = GET_DESC(r, (uint32_t *)&(r->r_desc[i - 1].desc_ctl));
	PUT_DESC(r, (uint32_t *)&(r->r_desc[i - 1].desc_ctl),
	    v | BFE_DESC_EOT);

	(void) SYNC_DESC(r, 0, r->r_ndesc, DDI_DMA_SYNC_FORDEV);

	/* TAIL of RX Descriptor */
	OUTL(r->r_bfe, BFE_DMARX_PTR, ((i) * sizeof (bfe_desc_t)));

	r->r_curr_desc = 0;
	r->r_avail_desc = RX_NUM_DESC;
}

static int
bfe_chip_start(bfe_t *bfe)
{
	ASSERT_ALL_LOCKS(bfe);

	/*
	 * Stop the chip first & then Reset the chip. At last enable interrupts.
	 */
	bfe_chip_halt(bfe);
	bfe_stop_phy(bfe);

	/*
	 * Reset chip and start PHY.
	 */
	bfe_chip_reset(bfe);

	/*
	 * Initailize Descriptor Rings.
	 */
	bfe_tx_desc_init(&bfe->bfe_tx_ring);
	bfe_rx_desc_init(&bfe->bfe_rx_ring);

	bfe->bfe_chip_state = BFE_CHIP_ACTIVE;
	bfe->bfe_chip_mode |= BFE_RX_MODE_ENABLE;
	bfe_set_rx_mode(bfe);
	bfe_enable_chip_intrs(bfe);

	/* Check link, speed and duplex mode */
	(void) bfe_check_link(bfe);

	return (DDI_SUCCESS);
}


/*
 * Clear chip statistics.
 */
static void
bfe_clear_stats(bfe_t *bfe)
{
	ulong_t r;

	OUTL(bfe, BFE_MIB_CTRL, BFE_MIB_CLR_ON_READ);

	/*
	 * Stat registers are cleared by reading.
	 */
	for (r = BFE_TX_GOOD_O; r <= BFE_TX_PAUSE; r += 4)
		(void) INL(bfe, r);

	for (r = BFE_RX_GOOD_O; r <= BFE_RX_NPAUSE; r += 4)
		(void) INL(bfe, r);
}

/*
 * Collect chip statistics.
 */
static void
bfe_gather_stats(bfe_t *bfe)
{
	ulong_t r;
	uint32_t *v;
	uint32_t txerr = 0, rxerr = 0, coll = 0;

	v = &bfe->bfe_hw_stats.tx_good_octets;
	for (r = BFE_TX_GOOD_O; r <= BFE_TX_PAUSE; r += 4) {
		*v += INL(bfe, r);
		v++;
	}

	v = &bfe->bfe_hw_stats.rx_good_octets;
	for (r = BFE_RX_GOOD_O; r <= BFE_RX_NPAUSE; r += 4) {
		*v += INL(bfe, r);
		v++;
	}

	/*
	 * TX :
	 * -------
	 * tx_good_octets, tx_good_pkts, tx_octets
	 * tx_pkts, tx_broadcast_pkts, tx_multicast_pkts
	 * tx_len_64, tx_len_65_to_127, tx_len_128_to_255
	 * tx_len_256_to_511, tx_len_512_to_1023, tx_len_1024_to_max
	 * tx_jabber_pkts, tx_oversize_pkts, tx_fragment_pkts
	 * tx_underruns, tx_total_cols, tx_single_cols
	 * tx_multiple_cols, tx_excessive_cols, tx_late_cols
	 * tx_defered, tx_carrier_lost, tx_pause_pkts
	 *
	 * RX :
	 * -------
	 * rx_good_octets, rx_good_pkts, rx_octets
	 * rx_pkts, rx_broadcast_pkts, rx_multicast_pkts
	 * rx_len_64, rx_len_65_to_127, rx_len_128_to_255
	 * rx_len_256_to_511, rx_len_512_to_1023, rx_len_1024_to_max
	 * rx_jabber_pkts, rx_oversize_pkts, rx_fragment_pkts
	 * rx_missed_pkts, rx_crc_align_errs, rx_undersize
	 * rx_crc_errs, rx_align_errs, rx_symbol_errs
	 * rx_pause_pkts, rx_nonpause_pkts
	 */

	bfe->bfe_stats.ether_stat_carrier_errors =
	    bfe->bfe_hw_stats.tx_carrier_lost;

	/* txerr += bfe->bfe_hw_stats.tx_carrier_lost; */

	bfe->bfe_stats.ether_stat_ex_collisions =
	    bfe->bfe_hw_stats.tx_excessive_cols;
	txerr += bfe->bfe_hw_stats.tx_excessive_cols;
	coll += bfe->bfe_hw_stats.tx_excessive_cols;

	bfe->bfe_stats.ether_stat_fcs_errors =
	    bfe->bfe_hw_stats.rx_crc_errs;
	rxerr += bfe->bfe_hw_stats.rx_crc_errs;

	bfe->bfe_stats.ether_stat_first_collisions =
	    bfe->bfe_hw_stats.tx_single_cols;
	coll += bfe->bfe_hw_stats.tx_single_cols;
	bfe->bfe_stats.ether_stat_multi_collisions =
	    bfe->bfe_hw_stats.tx_multiple_cols;
	coll += bfe->bfe_hw_stats.tx_multiple_cols;

	bfe->bfe_stats.ether_stat_toolong_errors =
	    bfe->bfe_hw_stats.rx_oversize_pkts;
	rxerr += bfe->bfe_hw_stats.rx_oversize_pkts;

	bfe->bfe_stats.ether_stat_tooshort_errors =
	    bfe->bfe_hw_stats.rx_undersize;
	rxerr += bfe->bfe_hw_stats.rx_undersize;

	bfe->bfe_stats.ether_stat_tx_late_collisions +=
	    bfe->bfe_hw_stats.tx_late_cols;

	bfe->bfe_stats.ether_stat_defer_xmts +=
	    bfe->bfe_hw_stats.tx_defered;

	bfe->bfe_stats.ether_stat_macrcv_errors += rxerr;
	bfe->bfe_stats.ether_stat_macxmt_errors += txerr;

	bfe->bfe_stats.collisions += coll;
}

/*
 * Gets the state for dladm command and all.
 */
int
bfe_mac_getstat(void *arg, uint_t stat, uint64_t *val)
{
	bfe_t *bfe = (bfe_t *)arg;
	uint64_t	v;
	int err = 0;

	rw_enter(&bfe->bfe_rwlock, RW_READER);


	switch (stat) {
	default:
		err = ENOTSUP;
		break;

	case MAC_STAT_IFSPEED:
		/*
		 * MAC layer will ask for IFSPEED first and hence we
		 * collect it only once.
		 */
		if (bfe->bfe_chip_state == BFE_CHIP_ACTIVE) {
			/*
			 * Update stats from the hardware.
			 */
			bfe_gather_stats(bfe);
		}
		v = bfe->bfe_chip.speed;
		break;

	case ETHER_STAT_ADV_CAP_100T4:
		v = bfe->bfe_adv_100T4;
		break;

	case ETHER_STAT_ADV_CAP_100FDX:
		v = (bfe->bfe_mii_anar & MII_ABILITY_100BASE_TX_FD) != 0;
		break;

	case ETHER_STAT_ADV_CAP_100HDX:
		v = (bfe->bfe_mii_anar & MII_ABILITY_100BASE_TX) != 0;
		break;

	case ETHER_STAT_ADV_CAP_10FDX:
		v = (bfe->bfe_mii_anar & MII_ABILITY_10BASE_T_FD) != 0;
		break;

	case ETHER_STAT_ADV_CAP_10HDX:
		v = (bfe->bfe_mii_anar & MII_ABILITY_10BASE_T) != 0;
		break;

	case ETHER_STAT_ADV_CAP_ASMPAUSE:
		v = 0;
		break;

	case ETHER_STAT_ADV_CAP_AUTONEG:
		v = bfe->bfe_adv_aneg;
		break;

	case ETHER_STAT_ADV_CAP_PAUSE:
		v = (bfe->bfe_mii_anar & MII_ABILITY_PAUSE) != 0;
		break;

	case ETHER_STAT_ADV_REMFAULT:
		v = (bfe->bfe_mii_anar & MII_AN_ADVERT_REMFAULT) != 0;
		break;

	case ETHER_STAT_ALIGN_ERRORS:
		/* MIB */
		v = bfe->bfe_stats.ether_stat_align_errors;
		break;

	case ETHER_STAT_CAP_100T4:
		v = (bfe->bfe_mii_bmsr & MII_STATUS_100_BASE_T4) != 0;
		break;

	case ETHER_STAT_CAP_100FDX:
		v = (bfe->bfe_mii_bmsr & MII_STATUS_100_BASEX_FD) != 0;
		break;

	case ETHER_STAT_CAP_100HDX:
		v = (bfe->bfe_mii_bmsr & MII_STATUS_100_BASEX) != 0;
		break;

	case ETHER_STAT_CAP_10FDX:
		v = (bfe->bfe_mii_bmsr & MII_STATUS_10_FD) != 0;
		break;

	case ETHER_STAT_CAP_10HDX:
		v = (bfe->bfe_mii_bmsr & MII_STATUS_10) != 0;
		break;

	case ETHER_STAT_CAP_ASMPAUSE:
		v = 0;
		break;

	case ETHER_STAT_CAP_AUTONEG:
		v = ((bfe->bfe_mii_bmsr & MII_STATUS_CANAUTONEG) != 0);
		break;

	case ETHER_STAT_CAP_PAUSE:
		v = 1;
		break;

	case ETHER_STAT_CAP_REMFAULT:
		v = (bfe->bfe_mii_bmsr & MII_STATUS_REMFAULT) != 0;
		break;

	case ETHER_STAT_CARRIER_ERRORS:
		v = bfe->bfe_stats.ether_stat_carrier_errors;
		break;

	case ETHER_STAT_JABBER_ERRORS:
		err = ENOTSUP;
		break;

	case ETHER_STAT_DEFER_XMTS:
		v = bfe->bfe_stats.ether_stat_defer_xmts;
		break;

	case ETHER_STAT_EX_COLLISIONS:
		/* MIB */
		v = bfe->bfe_stats.ether_stat_ex_collisions;
		break;

	case ETHER_STAT_FCS_ERRORS:
		/* MIB */
		v = bfe->bfe_stats.ether_stat_fcs_errors;
		break;

	case ETHER_STAT_FIRST_COLLISIONS:
		/* MIB */
		v = bfe->bfe_stats.ether_stat_first_collisions;
		break;

	case ETHER_STAT_LINK_ASMPAUSE:
		v = 0;
		break;

	case ETHER_STAT_LINK_AUTONEG:
		v = (bfe->bfe_mii_bmcr & MII_CONTROL_ANE) != 0 &&
		    (bfe->bfe_mii_bmsr & MII_STATUS_ANDONE) != 0;
		break;

	case ETHER_STAT_LINK_DUPLEX:
		v = bfe->bfe_chip.duplex;
		break;

	case ETHER_STAT_LP_CAP_100T4:
		v = (bfe->bfe_mii_anlpar & MII_ABILITY_100BASE_T4) != 0;
		break;

	case ETHER_STAT_LP_CAP_100FDX:
		v = (bfe->bfe_mii_anlpar & MII_ABILITY_100BASE_TX_FD) != 0;
		break;

	case ETHER_STAT_LP_CAP_100HDX:
		v = (bfe->bfe_mii_anlpar & MII_ABILITY_100BASE_TX) != 0;
		break;

	case ETHER_STAT_LP_CAP_10FDX:
		v = (bfe->bfe_mii_anlpar & MII_ABILITY_10BASE_T_FD) != 0;
		break;

	case ETHER_STAT_LP_CAP_10HDX:
		v = (bfe->bfe_mii_anlpar & MII_ABILITY_10BASE_T) != 0;
		break;

	case ETHER_STAT_LP_CAP_ASMPAUSE:
		v = 0;
		break;

	case ETHER_STAT_LP_CAP_AUTONEG:
		v = (bfe->bfe_mii_exp & MII_AN_EXP_LPCANAN) != 0;
		break;

	case ETHER_STAT_LP_CAP_PAUSE:
		v = (bfe->bfe_mii_anlpar & MII_ABILITY_PAUSE) != 0;
		break;

	case ETHER_STAT_LP_REMFAULT:
		v = (bfe->bfe_mii_anlpar & MII_STATUS_REMFAULT) != 0;
		break;

	case ETHER_STAT_MACRCV_ERRORS:
		v = bfe->bfe_stats.ether_stat_macrcv_errors;
		break;

	case ETHER_STAT_MACXMT_ERRORS:
		v = bfe->bfe_stats.ether_stat_macxmt_errors;
		break;

	case ETHER_STAT_MULTI_COLLISIONS:
		v = bfe->bfe_stats.ether_stat_multi_collisions;
		break;

	case ETHER_STAT_SQE_ERRORS:
		err = ENOTSUP;
		break;

	case ETHER_STAT_TOOLONG_ERRORS:
		v = bfe->bfe_stats.ether_stat_toolong_errors;
		break;

	case ETHER_STAT_TOOSHORT_ERRORS:
		v = bfe->bfe_stats.ether_stat_tooshort_errors;
		break;

	case ETHER_STAT_TX_LATE_COLLISIONS:
		v = bfe->bfe_stats.ether_stat_tx_late_collisions;
		break;

	case ETHER_STAT_XCVR_ADDR:
		v = bfe->bfe_phy_addr;
		break;

	case ETHER_STAT_XCVR_ID:
		v = bfe->bfe_phy_id;
		break;

	case MAC_STAT_BRDCSTRCV:
		v = bfe->bfe_stats.brdcstrcv;
		break;

	case MAC_STAT_BRDCSTXMT:
		v = bfe->bfe_stats.brdcstxmt;
		break;

	case MAC_STAT_MULTIXMT:
		v = bfe->bfe_stats.multixmt;
		break;

	case MAC_STAT_COLLISIONS:
		v = bfe->bfe_stats.collisions;
		break;

	case MAC_STAT_IERRORS:
		v = bfe->bfe_stats.ierrors;
		break;

	case MAC_STAT_IPACKETS:
		v = bfe->bfe_stats.ipackets;
		break;

	case MAC_STAT_MULTIRCV:
		v = bfe->bfe_stats.multircv;
		break;

	case MAC_STAT_NORCVBUF:
		v = bfe->bfe_stats.norcvbuf;
		break;

	case MAC_STAT_NOXMTBUF:
		v = bfe->bfe_stats.noxmtbuf;
		break;

	case MAC_STAT_OBYTES:
		v = bfe->bfe_stats.obytes;
		break;

	case MAC_STAT_OERRORS:
		/* MIB */
		v = bfe->bfe_stats.ether_stat_macxmt_errors;
		break;

	case MAC_STAT_OPACKETS:
		v = bfe->bfe_stats.opackets;
		break;

	case MAC_STAT_RBYTES:
		v = bfe->bfe_stats.rbytes;
		break;

	case MAC_STAT_UNDERFLOWS:
		v = bfe->bfe_stats.underflows;
		break;

	case MAC_STAT_OVERFLOWS:
		v = bfe->bfe_stats.overflows;
		break;
	}

	rw_exit(&bfe->bfe_rwlock);

	*val = v;
	return (err);
}

int
bfe_mac_getprop(void *arg, const char *name, mac_prop_id_t num, uint_t sz,
    void *val)
{
	bfe_t		*bfe = (bfe_t *)arg;
	int		err = 0;

	switch (num) {
	case MAC_PROP_DUPLEX:
		ASSERT(sz >= sizeof (link_duplex_t));
		bcopy(&bfe->bfe_chip.duplex, val, sizeof (link_duplex_t));
		break;

	case MAC_PROP_SPEED:
		ASSERT(sz >= sizeof (uint64_t));
		bcopy(&bfe->bfe_chip.speed, val, sizeof (uint64_t));
		break;

	case MAC_PROP_AUTONEG:
		*(uint8_t *)val = bfe->bfe_adv_aneg;
		break;

	case MAC_PROP_ADV_100FDX_CAP:
		*(uint8_t *)val = bfe->bfe_adv_100fdx;
		break;

	case MAC_PROP_EN_100FDX_CAP:
		*(uint8_t *)val = bfe->bfe_adv_100fdx;
		break;

	case MAC_PROP_ADV_100HDX_CAP:
		*(uint8_t *)val = bfe->bfe_adv_100hdx;
		break;

	case MAC_PROP_EN_100HDX_CAP:
		*(uint8_t *)val = bfe->bfe_adv_100hdx;
		break;

	case MAC_PROP_ADV_10FDX_CAP:
		*(uint8_t *)val = bfe->bfe_adv_10fdx;
		break;

	case MAC_PROP_EN_10FDX_CAP:
		*(uint8_t *)val = bfe->bfe_adv_10fdx;
		break;

	case MAC_PROP_ADV_10HDX_CAP:
		*(uint8_t *)val = bfe->bfe_adv_10hdx;
		break;

	case MAC_PROP_EN_10HDX_CAP:
		*(uint8_t *)val = bfe->bfe_adv_10hdx;
		break;

	case MAC_PROP_ADV_100T4_CAP:
		*(uint8_t *)val = bfe->bfe_adv_100T4;
		break;

	case MAC_PROP_EN_100T4_CAP:
		*(uint8_t *)val = bfe->bfe_adv_100T4;
		break;

	default:
		err = ENOTSUP;
	}

	return (err);
}


static void
bfe_mac_propinfo(void *arg, const char *name, mac_prop_id_t num,
    mac_prop_info_handle_t prh)
{
	bfe_t		*bfe = (bfe_t *)arg;

	switch (num) {
	case MAC_PROP_DUPLEX:
	case MAC_PROP_SPEED:
	case MAC_PROP_ADV_100FDX_CAP:
	case MAC_PROP_ADV_100HDX_CAP:
	case MAC_PROP_ADV_10FDX_CAP:
	case MAC_PROP_ADV_10HDX_CAP:
	case MAC_PROP_ADV_100T4_CAP:
	case MAC_PROP_EN_100T4_CAP:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		break;

	case MAC_PROP_AUTONEG:
		mac_prop_info_set_default_uint8(prh, bfe->bfe_cap_aneg);
		break;

	case MAC_PROP_EN_100FDX_CAP:
		mac_prop_info_set_default_uint8(prh, bfe->bfe_cap_100fdx);
		break;

	case MAC_PROP_EN_100HDX_CAP:
		mac_prop_info_set_default_uint8(prh, bfe->bfe_cap_100hdx);
		break;

	case MAC_PROP_EN_10FDX_CAP:
		mac_prop_info_set_default_uint8(prh, bfe->bfe_cap_10fdx);
		break;

	case MAC_PROP_EN_10HDX_CAP:
		mac_prop_info_set_default_uint8(prh, bfe->bfe_cap_10hdx);
		break;
	}
}


/*ARGSUSED*/
int
bfe_mac_setprop(void *arg, const char *name, mac_prop_id_t num, uint_t sz,
    const void *val)
{
	bfe_t		*bfe = (bfe_t *)arg;
	uint8_t		*advp;
	uint8_t		*capp;
	int 		r = 0;

	switch (num) {
	case MAC_PROP_EN_100FDX_CAP:
		advp = &bfe->bfe_adv_100fdx;
		capp = &bfe->bfe_cap_100fdx;
		break;

	case MAC_PROP_EN_100HDX_CAP:
		advp = &bfe->bfe_adv_100hdx;
		capp = &bfe->bfe_cap_100hdx;
		break;

	case MAC_PROP_EN_10FDX_CAP:
		advp = &bfe->bfe_adv_10fdx;
		capp = &bfe->bfe_cap_10fdx;
		break;

	case MAC_PROP_EN_10HDX_CAP:
		advp = &bfe->bfe_adv_10hdx;
		capp = &bfe->bfe_cap_10hdx;
		break;

	case MAC_PROP_AUTONEG:
		advp = &bfe->bfe_adv_aneg;
		capp = &bfe->bfe_cap_aneg;
		break;

	default:
		return (ENOTSUP);
	}

	if (*capp == 0)
		return (ENOTSUP);

	bfe_grab_locks(bfe);

	if (*advp != *(const uint8_t *)val) {
		*advp = *(const uint8_t *)val;

		bfe->bfe_chip_action = BFE_ACTION_RESTART_SETPROP;
		if (bfe->bfe_chip_state == BFE_CHIP_ACTIVE) {
			/*
			 * We need to stop the timer before grabbing locks
			 * otherwise we can land-up in deadlock with untimeout.
			 */
			bfe_stop_timer(bfe);

			bfe->bfe_chip_action |= BFE_ACTION_RESTART;

			bfe_chip_restart(bfe);

			/*
			 * We leave SETPROP because properties can be
			 * temporary.
			 */
			bfe->bfe_chip_action &= ~(BFE_ACTION_RESTART);
			r = 1;
		}
	}

	bfe_release_locks(bfe);

	/* kick-off a potential stopped downstream */
	if (r)
		mac_tx_update(bfe->bfe_machdl);

	return (0);
}


int
bfe_mac_set_ether_addr(void *arg, const uint8_t *ea)
{
	bfe_t *bfe = (bfe_t *)arg;

	bfe_grab_locks(bfe);
	bcopy(ea, bfe->bfe_ether_addr, ETHERADDRL);
	bfe_set_rx_mode(bfe);
	bfe_release_locks(bfe);
	return (0);
}

int
bfe_mac_start(void *arg)
{
	bfe_t *bfe = (bfe_t *)arg;

	bfe_grab_locks(bfe);
	if (bfe_chip_start(bfe) == DDI_FAILURE) {
		bfe_release_locks(bfe);
		return (EINVAL);
	}

	bfe_release_locks(bfe);

	mac_tx_update(bfe->bfe_machdl);

	return (0);
}

void
bfe_mac_stop(void *arg)
{
	bfe_t *bfe = (bfe_t *)arg;

	/*
	 * We need to stop the timer before grabbing locks otherwise
	 * we can land-up in deadlock with untimeout.
	 */
	bfe_stop_timer(bfe);

	bfe_grab_locks(bfe);

	/*
	 * First halt the chip by disabling interrupts.
	 */
	bfe_chip_halt(bfe);
	bfe_stop_phy(bfe);

	bfe->bfe_chip_state = BFE_CHIP_STOPPED;

	/*
	 * This will leave the PHY running.
	 */
	bfe_chip_reset(bfe);

	/*
	 * Disable RX register.
	 */
	bfe->bfe_chip_mode &= ~BFE_RX_MODE_ENABLE;
	bfe_set_rx_mode(bfe);

	bfe_release_locks(bfe);
}

/*
 * Send a packet down the wire.
 */
static int
bfe_send_a_packet(bfe_t *bfe, mblk_t *mp)
{
	bfe_ring_t *r = &bfe->bfe_tx_ring;
	uint32_t cur = r->r_curr_desc;
	uint32_t next;
	size_t	pktlen = msgsize(mp);
	uchar_t *buf;
	uint32_t v;

	ASSERT(MUTEX_HELD(&r->r_lock));
	ASSERT(mp != NULL);

	if (pktlen > r->r_buf_len) {
		freemsg(mp);
		return (BFE_SUCCESS);
	}

	/*
	 * There is a big reason why we don't check for '0'. It becomes easy
	 * for us to not roll over the ring since we are based on producer (tx)
	 * and consumer (reclaim by an interrupt) model. Especially when we
	 * run out of TX descriptor, chip will send a single interrupt and
	 * both producer and consumer counter will be same. So we keep a
	 * difference of 1 always.
	 */
	if (r->r_avail_desc <= 1) {
		bfe->bfe_stats.noxmtbuf++;
		bfe->bfe_tx_resched = 1;
		return (BFE_FAILURE);
	}

	/*
	 * Get the DMA buffer to hold packet.
	 */
	buf = (uchar_t *)r->r_buf_dma[cur].addr;

	mcopymsg(mp, buf);	/* it also frees mp */

	/*
	 * Gather statistics.
	 */
	if (buf[0] & 0x1) {
		if (bcmp(buf, bfe_broadcast, ETHERADDRL) != 0)
			bfe->bfe_stats.multixmt++;
		else
			bfe->bfe_stats.brdcstxmt++;
	}
	bfe->bfe_stats.opackets++;
	bfe->bfe_stats.obytes += pktlen;


	/*
	 * Program the DMA descriptor (start and end of frame are same).
	 */
	next = cur;
	v = (pktlen & BFE_DESC_LEN) | BFE_DESC_IOC | BFE_DESC_SOF |
	    BFE_DESC_EOF;

	if (cur == (TX_NUM_DESC - 1))
		v |= BFE_DESC_EOT;

	PUT_DESC(r, (uint32_t *)&(r->r_desc[cur].desc_ctl), v);

	/*
	 * DMA addresses need to be added to BFE_PCI_DMA
	 */
	PUT_DESC(r, (uint32_t *)&(r->r_desc[cur].desc_addr),
	    (r->r_buf_dma[cur].cookie.dmac_laddress + BFE_PCI_DMA));

	/*
	 * Sync the packet data for the device.
	 */
	(void) SYNC_BUF(r, cur, 0, pktlen, DDI_DMA_SYNC_FORDEV);

	/* Move to next descriptor slot */
	BFE_INC_SLOT(next, TX_NUM_DESC);

	(void) SYNC_DESC(r, 0, r->r_ndesc, DDI_DMA_SYNC_FORDEV);

	r->r_curr_desc = next;

	/*
	 * The order should be 1,2,3,... for BFE_DMATX_PTR if 0,1,2,3,...
	 * descriptor slot are being programmed.
	 */
	OUTL(bfe, BFE_DMATX_PTR, next * sizeof (bfe_desc_t));
	FLUSH(bfe, BFE_DMATX_PTR);

	r->r_avail_desc--;

	/*
	 * Let timeout know that it must reset the chip if a
	 * packet is not sent down the wire for more than 5 seconds.
	 */
	bfe->bfe_tx_stall_time = gethrtime() + (5 * 1000000000ULL);

	return (BFE_SUCCESS);
}

mblk_t *
bfe_mac_transmit_packet(void *arg, mblk_t *mp)
{
	bfe_t *bfe = (bfe_t *)arg;
	bfe_ring_t *r = &bfe->bfe_tx_ring;
	mblk_t	*nmp;

	mutex_enter(&r->r_lock);

	if (bfe->bfe_chip_state != BFE_CHIP_ACTIVE) {
		DTRACE_PROBE1(tx__chip__not__active, int, bfe->bfe_unit);

		freemsgchain(mp);
		mutex_exit(&r->r_lock);
		return (NULL);
	}


	while (mp != NULL) {
		nmp = mp->b_next;
		mp->b_next = NULL;

		if (bfe_send_a_packet(bfe, mp) == BFE_FAILURE) {
			mp->b_next = nmp;
			break;
		}
		mp = nmp;
	}

	mutex_exit(&r->r_lock);

	return (mp);
}

int
bfe_mac_set_promisc(void *arg, boolean_t promiscflag)
{
	bfe_t *bfe = (bfe_t *)arg;

	bfe_grab_locks(bfe);
	if (bfe->bfe_chip_state != BFE_CHIP_ACTIVE) {
		bfe_release_locks(bfe);
		return (EIO);
	}

	if (promiscflag) {
		/* Set Promiscous on */
		bfe->bfe_chip_mode |= BFE_RX_MODE_PROMISC;
	} else {
		bfe->bfe_chip_mode &= ~BFE_RX_MODE_PROMISC;
	}

	bfe_set_rx_mode(bfe);
	bfe_release_locks(bfe);

	return (0);
}

int
bfe_mac_set_multicast(void *arg, boolean_t add, const uint8_t *macaddr)
{
	/*
	 * It was too much of pain to implement multicast in CAM. Instead
	 * we never disable multicast filter.
	 */
	return (0);
}

static mac_callbacks_t bfe_mac_callbacks = {
	MC_SETPROP | MC_GETPROP | MC_PROPINFO,
	bfe_mac_getstat,	/* gets stats */
	bfe_mac_start,		/* starts mac */
	bfe_mac_stop,		/* stops mac */
	bfe_mac_set_promisc,	/* sets promisc mode for snoop */
	bfe_mac_set_multicast,	/* multicast implementation */
	bfe_mac_set_ether_addr,	/* sets ethernet address (unicast) */
	bfe_mac_transmit_packet, /* transmits packet */
	NULL,
	NULL,			/* ioctl */
	NULL,			/* getcap */
	NULL,			/* open */
	NULL,			/* close */
	bfe_mac_setprop,
	bfe_mac_getprop,
	bfe_mac_propinfo
};

static void
bfe_error_handler(bfe_t *bfe, int intr_mask)
{
	uint32_t v;

	if (intr_mask & BFE_ISTAT_RFO) {
		bfe->bfe_stats.overflows++;
		bfe->bfe_chip_action |=
		    (BFE_ACTION_RESTART | BFE_ACTION_RESTART_FAULT);
		goto action;
	}

	if (intr_mask & BFE_ISTAT_TFU) {
		bfe->bfe_stats.underflows++;
		return;
	}

	/* Descriptor Protocol Error */
	if (intr_mask & BFE_ISTAT_DPE) {
		bfe_error(bfe->bfe_dip,
		    "Descriptor Protocol Error. Halting Chip");
		bfe->bfe_chip_action |=
		    (BFE_ACTION_RESTART | BFE_ACTION_RESTART_FAULT);
		goto action;
	}

	/* Descriptor Error */
	if (intr_mask & BFE_ISTAT_DSCE) {
		bfe_error(bfe->bfe_dip, "Descriptor Error. Restarting Chip");
		goto action;
	}

	/* Receive Descr. Underflow */
	if (intr_mask & BFE_ISTAT_RDU) {
		bfe_error(bfe->bfe_dip,
		    "Receive Descriptor Underflow. Restarting Chip");
		bfe->bfe_stats.ether_stat_macrcv_errors++;
		bfe->bfe_chip_action |=
		    (BFE_ACTION_RESTART | BFE_ACTION_RESTART_FAULT);
		goto action;
	}

	v = INL(bfe, BFE_DMATX_STAT);

	/* Error while sending a packet */
	if (v & BFE_STAT_EMASK) {
		bfe->bfe_stats.ether_stat_macxmt_errors++;
		bfe_error(bfe->bfe_dip,
		    "Error while sending a packet. Restarting Chip");
	}

	/* Error while receiving a packet */
	v = INL(bfe, BFE_DMARX_STAT);
	if (v & BFE_RX_FLAG_ERRORS) {
		bfe->bfe_stats.ierrors++;
		bfe_error(bfe->bfe_dip,
		    "Error while receiving a packet. Restarting Chip");
	}


	bfe->bfe_chip_action |=
	    (BFE_ACTION_RESTART | BFE_ACTION_RESTART_FAULT);

action:
	bfe_chip_halt(bfe);
}

/*
 * It will recycle a RX descriptor slot.
 */
static void
bfe_rx_desc_buf_reinit(bfe_t *bfe, uint_t slot)
{
	bfe_ring_t *r = &bfe->bfe_rx_ring;
	uint32_t v;

	slot %= RX_NUM_DESC;

	bzero(r->r_buf_dma[slot].addr, sizeof (bfe_rx_header_t));

	(void) SYNC_BUF(r, slot, 0, BFE_RX_OFFSET, DDI_DMA_SYNC_FORDEV);

	v = r->r_buf_dma[slot].len  & BFE_DESC_LEN;
	if (slot == (RX_NUM_DESC - 1))
		v |= BFE_DESC_EOT;

	PUT_DESC(r, (uint32_t *)&(r->r_desc[slot].desc_ctl), v);

	/*
	 * DMA addresses need to be added to BFE_PCI_DMA
	 */
	PUT_DESC(r, (uint32_t *)&(r->r_desc[slot].desc_addr),
	    (r->r_buf_dma[slot].cookie.dmac_laddress + BFE_PCI_DMA));
}

/*
 * Gets called from interrupt context to handle RX interrupt.
 */
static mblk_t *
bfe_receive(bfe_t *bfe, int intr_mask)
{
	int rxstat, current;
	mblk_t	*mp = NULL, *rx_head, *rx_tail;
	uchar_t	*rx_header;
	uint16_t len;
	uchar_t	*bp;
	bfe_ring_t *r = &bfe->bfe_rx_ring;
	int i;

	rxstat = INL(bfe, BFE_DMARX_STAT);
	current = (rxstat & BFE_STAT_CDMASK) / sizeof (bfe_desc_t);
	i = r->r_curr_desc;

	rx_head = rx_tail = NULL;

	DTRACE_PROBE3(receive, int, bfe->bfe_unit,
	    int, r->r_curr_desc,
	    int, current);

	for (i = r->r_curr_desc; i != current;
	    BFE_INC_SLOT(i, RX_NUM_DESC)) {

		/*
		 * Sync the buffer associated with the descriptor table entry.
		 */
		(void) SYNC_BUF(r, i, 0, r->r_buf_dma[i].len,
		    DDI_DMA_SYNC_FORKERNEL);

		rx_header = (void *)r->r_buf_dma[i].addr;

		/*
		 * We do this to make sure we are endian neutral. Chip is
		 * big endian.
		 *
		 * The header looks like :-
		 *
		 *  Offset 0  -> uint16_t len
		 *  Offset 2  -> uint16_t flags
		 *  Offset 4  -> uint16_t pad[12]
		 */
		len = (rx_header[1] << 8) | rx_header[0];
		len -= 4;	/* CRC bytes need to be removed */

		/*
		 * Don't receive this packet if pkt length is greater than
		 * MTU + VLAN_TAGSZ.
		 */
		if (len > r->r_buf_len) {
			/* Recycle slot for later use */
			bfe_rx_desc_buf_reinit(bfe, i);
			continue;
		}

		if ((mp = allocb(len + VLAN_TAGSZ, BPRI_MED)) != NULL) {
			mp->b_rptr += VLAN_TAGSZ;
			bp = mp->b_rptr;
			mp->b_wptr = bp + len;

			/* sizeof (bfe_rx_header_t) + 2 */
			bcopy(r->r_buf_dma[i].addr +
			    BFE_RX_OFFSET, bp, len);

			mp->b_next = NULL;
			if (rx_tail == NULL)
				rx_head = rx_tail = mp;
			else {
				rx_tail->b_next = mp;
				rx_tail = mp;
			}

			/* Number of packets received so far */
			bfe->bfe_stats.ipackets++;

			/* Total bytes of packets received so far */
			bfe->bfe_stats.rbytes += len;

			if (bcmp(mp->b_rptr, bfe_broadcast, ETHERADDRL) == 0)
				bfe->bfe_stats.brdcstrcv++;
			else
				bfe->bfe_stats.multircv++;
		} else {
			bfe->bfe_stats.norcvbuf++;
			/* Recycle the slot for later use */
			bfe_rx_desc_buf_reinit(bfe, i);
			break;
		}

		/*
		 * Reinitialize the current descriptor slot's buffer so that
		 * it can be reused.
		 */
		bfe_rx_desc_buf_reinit(bfe, i);
	}

	r->r_curr_desc = i;

	(void) SYNC_DESC(r, 0, r->r_ndesc, DDI_DMA_SYNC_FORDEV);

	return (rx_head);
}

static int
bfe_tx_reclaim(bfe_ring_t *r)
{
	uint32_t cur, start;
	uint32_t v;

	cur = INL(r->r_bfe, BFE_DMATX_STAT) & BFE_STAT_CDMASK;
	cur = cur / sizeof (bfe_desc_t);

	/*
	 * Start with the last descriptor consumed by the chip.
	 */
	start = r->r_cons_desc;

	DTRACE_PROBE3(tx__reclaim, int, r->r_bfe->bfe_unit,
	    int, start,
	    int, cur);

	/*
	 * There will be at least one descriptor to process.
	 */
	while (start != cur) {
		r->r_avail_desc++;
		v = r->r_buf_dma[start].len  & BFE_DESC_LEN;
		if (start == (TX_NUM_DESC - 1))
			v |= BFE_DESC_EOT;

		PUT_DESC(r, (uint32_t *)&(r->r_desc[start].desc_ctl), v);
		PUT_DESC(r, (uint32_t *)&(r->r_desc[start].desc_addr),
		    (r->r_buf_dma[start].cookie.dmac_laddress + BFE_PCI_DMA));

		/* Move to next descriptor in TX ring */
		BFE_INC_SLOT(start, TX_NUM_DESC);
	}

	(void) ddi_dma_sync(r->r_desc_dma_handle,
	    0, (r->r_ndesc * sizeof (bfe_desc_t)),
	    DDI_DMA_SYNC_FORDEV);

	r->r_cons_desc = start; 	/* consumed pointer */
	r->r_bfe->bfe_tx_stall_time = 0;

	return (cur);
}

static int
bfe_tx_done(bfe_t *bfe, int intr_mask)
{
	bfe_ring_t *r = &bfe->bfe_tx_ring;
	int resched = 0;

	mutex_enter(&r->r_lock);
	(void) bfe_tx_reclaim(r);

	if (bfe->bfe_tx_resched) {
		resched = 1;
		bfe->bfe_tx_resched = 0;
	}
	mutex_exit(&r->r_lock);

	return (resched);
}

/*
 * ISR for interrupt handling
 */
static uint_t
bfe_interrupt(caddr_t arg1, caddr_t arg2)
{
	bfe_t *bfe =  (void *)arg1;
	uint32_t	intr_stat;
	mblk_t *rx_head = NULL;
	int resched = 0;

	/*
	 * Grab the lock to avoid stopping the chip while this interrupt
	 * is handled.
	 */
	rw_enter(&bfe->bfe_rwlock, RW_READER);

	/*
	 * It's necessary to read intr stat again because masking interrupt
	 * register does not really mask interrupts coming from the chip.
	 */
	intr_stat = INL(bfe, BFE_INTR_STAT);
	intr_stat &= BFE_IMASK_DEF;
	OUTL(bfe, BFE_INTR_STAT, intr_stat);
	(void) INL(bfe, BFE_INTR_STAT);

	if (intr_stat == 0) {
		rw_exit(&bfe->bfe_rwlock);
		return (DDI_INTR_UNCLAIMED);
	}

	DTRACE_PROBE2(bfe__interrupt, int, bfe->bfe_unit,
	    int, intr_stat);

	if (bfe->bfe_chip_state != BFE_CHIP_ACTIVE) {
		/*
		 * If chip is suspended then we just return.
		 */
		if (bfe->bfe_chip_state == BFE_CHIP_SUSPENDED) {
			rw_exit(&bfe->bfe_rwlock);
			DTRACE_PROBE1(interrupt__chip__is__suspend, int,
			    bfe->bfe_unit);
			return (DDI_INTR_CLAIMED);
		}

		/*
		 * Halt the chip again i.e basically disable interrupts.
		 */
		bfe_chip_halt(bfe);
		rw_exit(&bfe->bfe_rwlock);
		DTRACE_PROBE1(interrupt__chip__not__active, int,
		    bfe->bfe_unit);
		return (DDI_INTR_CLAIMED);
	}

	/* A packet was received */
	if (intr_stat & BFE_ISTAT_RX) {
		rx_head = bfe_receive(bfe, intr_stat);
	}

	/* A packet was sent down the wire */
	if (intr_stat & BFE_ISTAT_TX) {
		resched = bfe_tx_done(bfe, intr_stat);
	}

	/* There was an error */
	if (intr_stat & BFE_ISTAT_ERRORS) {
		bfe_error_handler(bfe, intr_stat);
	}

	rw_exit(&bfe->bfe_rwlock);

	/*
	 * Pass the list of packets received from chip to MAC layer.
	 */
	if (rx_head) {
		mac_rx(bfe->bfe_machdl, 0, rx_head);
	}

	/*
	 * Let the MAC start sending pkts to a potential stopped stream.
	 */
	if (resched)
		mac_tx_update(bfe->bfe_machdl);

	return (DDI_INTR_CLAIMED);
}

/*
 * Removes registered interrupt handler.
 */
static void
bfe_remove_intr(bfe_t *bfe)
{
	(void) ddi_intr_remove_handler(bfe->bfe_intrhdl);
	(void) ddi_intr_free(bfe->bfe_intrhdl);
}

/*
 * Add an interrupt for the driver.
 */
static int
bfe_add_intr(bfe_t *bfe)
{
	int	nintrs = 1;
	int ret;

	ret = ddi_intr_alloc(bfe->bfe_dip, &bfe->bfe_intrhdl,
	    DDI_INTR_TYPE_FIXED,	/* type */
	    0,	/* inumber */
	    1,	/* count */
	    &nintrs,	/* actual nintrs */
	    DDI_INTR_ALLOC_STRICT);

	if (ret != DDI_SUCCESS) {
		bfe_error(bfe->bfe_dip, "ddi_intr_alloc() failed"
		    " : ret : %d", ret);
		return (DDI_FAILURE);
	}

	ret = ddi_intr_add_handler(bfe->bfe_intrhdl, bfe_interrupt, bfe, NULL);
	if (ret != DDI_SUCCESS) {
		bfe_error(bfe->bfe_dip, "ddi_intr_add_handler() failed");
		(void) ddi_intr_free(bfe->bfe_intrhdl);
		return (DDI_FAILURE);
	}

	ret = ddi_intr_get_pri(bfe->bfe_intrhdl, &bfe->bfe_intrpri);
	if (ret != DDI_SUCCESS) {
		bfe_error(bfe->bfe_dip, "ddi_intr_get_pri() failed");
		bfe_remove_intr(bfe);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


/*
 * Identify chipset family.
 */
static int
bfe_identify_hardware(bfe_t *bfe)
{
	uint16_t	vid, did;
	int i;

	vid = pci_config_get16(bfe->bfe_conf_handle, PCI_CONF_VENID);
	did = pci_config_get16(bfe->bfe_conf_handle, PCI_CONF_DEVID);

	for (i = 0; i < (sizeof (bfe_cards) / sizeof (bfe_cards_t)); i++) {
		if (bfe_cards[i].vendor_id == vid &&
		    bfe_cards[i].device_id == did) {
			return (BFE_SUCCESS);
		}
	}

	bfe_error(bfe->bfe_dip, "bfe driver is attaching to unknown pci%d,%d"
	    " vendor/device-id card", vid, did);

	return (BFE_SUCCESS);
}

/*
 * Maps device registers.
 */
static int
bfe_regs_map(bfe_t *bfe)
{
	dev_info_t *dip = bfe->bfe_dip;
	int ret;

	ret = ddi_regs_map_setup(dip, 1, &bfe->bfe_mem_regset.addr, 0, 0,
	    &bfe_dev_attr, &bfe->bfe_mem_regset.hdl);

	if (ret != DDI_SUCCESS) {
		bfe_error(bfe->bfe_dip, "ddi_regs_map_setup failed");
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static void
bfe_unmap_regs(bfe_t *bfe)
{
	ddi_regs_map_free(&bfe->bfe_mem_regset.hdl);
}

static int
bfe_get_chip_config(bfe_t *bfe)
{

	bfe->bfe_dev_addr[0] = bfe->bfe_ether_addr[0] =
	    INB(bfe, BFE_EEPROM_BASE + 79);

	bfe->bfe_dev_addr[1] = bfe->bfe_ether_addr[1] =
	    INB(bfe, BFE_EEPROM_BASE + 78);

	bfe->bfe_dev_addr[2] = bfe->bfe_ether_addr[2] =
	    INB(bfe, BFE_EEPROM_BASE + 81);

	bfe->bfe_dev_addr[3] = bfe->bfe_ether_addr[3] =
	    INB(bfe, BFE_EEPROM_BASE + 80);

	bfe->bfe_dev_addr[4] = bfe->bfe_ether_addr[4] =
	    INB(bfe, BFE_EEPROM_BASE + 83);

	bfe->bfe_dev_addr[5] = bfe->bfe_ether_addr[5] =
	    INB(bfe, BFE_EEPROM_BASE + 82);

	bfe->bfe_phy_addr = -1;

	return (DDI_SUCCESS);
}

/*
 * Ring Management routines
 */
static int
bfe_ring_buf_alloc(bfe_t *bfe, bfe_ring_t *r, int slot, int d)
{
	int err;
	uint_t count = 0;

	err = ddi_dma_alloc_handle(bfe->bfe_dip,
	    &bfe_dma_attr_buf, DDI_DMA_SLEEP, NULL,
	    &r->r_buf_dma[slot].handle);

	if (err != DDI_SUCCESS) {
		bfe_error(bfe->bfe_dip, " bfe_ring_buf_alloc() :"
		    " alloc_handle failed");
		goto fail0;
	}

	err = ddi_dma_mem_alloc(r->r_buf_dma[slot].handle,
	    r->r_buf_len, &bfe_buf_attr, DDI_DMA_STREAMING,
	    DDI_DMA_SLEEP, NULL, &r->r_buf_dma[slot].addr,
	    &r->r_buf_dma[slot].len,
	    &r->r_buf_dma[slot].acchdl);

	if (err != DDI_SUCCESS) {
		bfe_error(bfe->bfe_dip, " bfe_ring_buf_alloc() :"
		    " mem_alloc failed :%d", err);
		goto fail1;
	}

	err = ddi_dma_addr_bind_handle(r->r_buf_dma[slot].handle,
	    NULL, r->r_buf_dma[slot].addr,
	    r->r_buf_dma[slot].len,
	    (DDI_DMA_RDWR | DDI_DMA_STREAMING),
	    DDI_DMA_SLEEP, NULL,
	    &r->r_buf_dma[slot].cookie,
	    &count);

	if (err != DDI_DMA_MAPPED) {
		bfe_error(bfe->bfe_dip, " bfe_ring_buf_alloc() :"
		    " bind_handle failed");
		goto fail2;
	}

	if (count > 1) {
		bfe_error(bfe->bfe_dip, " bfe_ring_buf_alloc() :"
		    " more than one DMA cookie");
		(void) ddi_dma_unbind_handle(r->r_buf_dma[slot].handle);
		goto fail2;
	}

	return (DDI_SUCCESS);
fail2:
	ddi_dma_mem_free(&r->r_buf_dma[slot].acchdl);
fail1:
	ddi_dma_free_handle(&r->r_buf_dma[slot].handle);
fail0:
	return (DDI_FAILURE);
}

static void
bfe_ring_buf_free(bfe_ring_t *r, int slot)
{
	if (r->r_buf_dma == NULL)
		return;

	(void) ddi_dma_unbind_handle(r->r_buf_dma[slot].handle);
	ddi_dma_mem_free(&r->r_buf_dma[slot].acchdl);
	ddi_dma_free_handle(&r->r_buf_dma[slot].handle);
}

static void
bfe_buffer_free(bfe_ring_t *r)
{
	int i;

	for (i = 0; i < r->r_ndesc; i++) {
		bfe_ring_buf_free(r, i);
	}
}

static void
bfe_ring_desc_free(bfe_ring_t *r)
{
	(void) ddi_dma_unbind_handle(r->r_desc_dma_handle);
	ddi_dma_mem_free(&r->r_desc_acc_handle);
	ddi_dma_free_handle(&r->r_desc_dma_handle);
	kmem_free(r->r_buf_dma, r->r_ndesc * sizeof (bfe_dma_t));

	r->r_buf_dma = NULL;
	r->r_desc = NULL;
}


static int
bfe_ring_desc_alloc(bfe_t *bfe, bfe_ring_t *r, int d)
{
	int err, i, fail = 0;
	caddr_t	ring;
	size_t	size_krnl = 0, size_dma = 0, ring_len = 0;
	ddi_dma_cookie_t cookie;
	uint_t	count = 0;

	ASSERT(bfe != NULL);

	size_krnl = r->r_ndesc * sizeof (bfe_dma_t);
	size_dma = r->r_ndesc * sizeof (bfe_desc_t);
	r->r_buf_dma = kmem_zalloc(size_krnl, KM_SLEEP);


	err = ddi_dma_alloc_handle(bfe->bfe_dip, &bfe_dma_attr_desc,
	    DDI_DMA_SLEEP, NULL, &r->r_desc_dma_handle);

	if (err != DDI_SUCCESS) {
		bfe_error(bfe->bfe_dip, "bfe_ring_desc_alloc() failed on"
		    " ddi_dma_alloc_handle()");
		kmem_free(r->r_buf_dma, size_krnl);
		return (DDI_FAILURE);
	}


	err = ddi_dma_mem_alloc(r->r_desc_dma_handle,
	    size_dma, &bfe_buf_attr,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    &ring, &ring_len, &r->r_desc_acc_handle);

	if (err != DDI_SUCCESS) {
		bfe_error(bfe->bfe_dip, "bfe_ring_desc_alloc() failed on"
		    " ddi_dma_mem_alloc()");
		ddi_dma_free_handle(&r->r_desc_dma_handle);
		kmem_free(r->r_buf_dma, size_krnl);
		return (DDI_FAILURE);
	}

	err = ddi_dma_addr_bind_handle(r->r_desc_dma_handle,
	    NULL, ring, ring_len,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP, NULL,
	    &cookie, &count);

	if (err != DDI_SUCCESS) {
		bfe_error(bfe->bfe_dip, "bfe_ring_desc_alloc() failed on"
		    " ddi_dma_addr_bind_handle()");
		ddi_dma_mem_free(&r->r_desc_acc_handle);
		ddi_dma_free_handle(&r->r_desc_dma_handle);
		kmem_free(r->r_buf_dma, size_krnl);
		return (DDI_FAILURE);
	}

	/*
	 * We don't want to have multiple cookies. Descriptor should be
	 * aligned to PAGESIZE boundary.
	 */
	ASSERT(count == 1);

	/* The actual descriptor for the ring */
	r->r_desc_len = ring_len;
	r->r_desc_cookie = cookie;

	r->r_desc = (void *)ring;

	bzero(r->r_desc, size_dma);
	bzero(r->r_desc, ring_len);

	/* For each descriptor, allocate a DMA buffer */
	fail = 0;
	for (i = 0; i < r->r_ndesc; i++) {
		if (bfe_ring_buf_alloc(bfe, r, i, d) != DDI_SUCCESS) {
			i--;
			fail = 1;
			break;
		}
	}

	if (fail) {
		while (i-- >= 0) {
			bfe_ring_buf_free(r, i);
		}

		/* We don't need the descriptor anymore */
		bfe_ring_desc_free(r);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
bfe_rings_alloc(bfe_t *bfe)
{
	/* TX */
	mutex_init(&bfe->bfe_tx_ring.r_lock, NULL, MUTEX_DRIVER, NULL);
	bfe->bfe_tx_ring.r_lockp = &bfe->bfe_tx_ring.r_lock;
	bfe->bfe_tx_ring.r_buf_len = BFE_MTU + sizeof (struct ether_header) +
	    VLAN_TAGSZ + ETHERFCSL;
	bfe->bfe_tx_ring.r_ndesc = TX_NUM_DESC;
	bfe->bfe_tx_ring.r_bfe = bfe;
	bfe->bfe_tx_ring.r_avail_desc = TX_NUM_DESC;

	/* RX */
	mutex_init(&bfe->bfe_rx_ring.r_lock, NULL, MUTEX_DRIVER, NULL);
	bfe->bfe_rx_ring.r_lockp = &bfe->bfe_rx_ring.r_lock;
	bfe->bfe_rx_ring.r_buf_len = BFE_MTU + sizeof (struct ether_header) +
	    VLAN_TAGSZ + ETHERFCSL + RX_HEAD_ROOM;
	bfe->bfe_rx_ring.r_ndesc = RX_NUM_DESC;
	bfe->bfe_rx_ring.r_bfe = bfe;
	bfe->bfe_rx_ring.r_avail_desc = RX_NUM_DESC;

	/* Allocate TX Ring */
	if (bfe_ring_desc_alloc(bfe, &bfe->bfe_tx_ring,
	    DDI_DMA_WRITE) != DDI_SUCCESS)
		return (DDI_FAILURE);

	/* Allocate RX Ring */
	if (bfe_ring_desc_alloc(bfe, &bfe->bfe_rx_ring,
	    DDI_DMA_READ) != DDI_SUCCESS) {
		cmn_err(CE_NOTE, "RX ring allocation failed");
		bfe_ring_desc_free(&bfe->bfe_tx_ring);
		return (DDI_FAILURE);
	}

	bfe->bfe_tx_ring.r_flags = BFE_RING_ALLOCATED;
	bfe->bfe_rx_ring.r_flags = BFE_RING_ALLOCATED;

	return (DDI_SUCCESS);
}

static int
bfe_resume(dev_info_t *dip)
{
	bfe_t *bfe;
	int err = DDI_SUCCESS;

	if ((bfe = ddi_get_driver_private(dip)) == NULL) {
		bfe_error(dip, "Unexpected error (no driver private data)"
		    " while resume");
		return (DDI_FAILURE);
	}

	/*
	 * Grab all the locks first.
	 */
	bfe_grab_locks(bfe);
	bfe->bfe_chip_state = BFE_CHIP_RESUME;

	bfe_init_vars(bfe);
	/* PHY will also start running */
	bfe_chip_reset(bfe);
	if (bfe_chip_start(bfe) == DDI_FAILURE) {
		bfe_error(dip, "Could not resume chip");
		err = DDI_FAILURE;
	}

	bfe_release_locks(bfe);

	if (err == DDI_SUCCESS)
		mac_tx_update(bfe->bfe_machdl);

	return (err);
}

static int
bfe_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int	unit;
	bfe_t	*bfe;
	mac_register_t	*macreg;
	int	ret;

	switch (cmd) {
	case DDI_RESUME:
		return (bfe_resume(dip));

	case DDI_ATTACH:
		break;

	default:
		return (DDI_FAILURE);
	}


	unit = ddi_get_instance(dip);

	bfe = kmem_zalloc(sizeof (bfe_t), KM_SLEEP);
	bfe->bfe_dip = dip;
	bfe->bfe_unit = unit;

	if (pci_config_setup(dip, &bfe->bfe_conf_handle) != DDI_SUCCESS) {
		bfe_error(dip, "pci_config_setup failed");
		goto fail0;
	}

	/*
	 * Enable IO space, Bus Master and Memory Space accessess.
	 */
	ret = pci_config_get16(bfe->bfe_conf_handle, PCI_CONF_COMM);
	pci_config_put16(bfe->bfe_conf_handle, PCI_CONF_COMM,
	    PCI_COMM_IO | PCI_COMM_MAE | PCI_COMM_ME | ret);

	ddi_set_driver_private(dip, bfe);

	/* Identify hardware */
	if (bfe_identify_hardware(bfe) == BFE_FAILURE) {
		bfe_error(dip, "Could not identify device");
		goto fail1;
	}

	if (bfe_regs_map(bfe) != DDI_SUCCESS) {
		bfe_error(dip, "Could not map device registers");
		goto fail1;
	}

	(void) bfe_get_chip_config(bfe);

	/*
	 * Register with MAC layer
	 */
	if ((macreg = mac_alloc(MAC_VERSION)) == NULL) {
		bfe_error(dip, "mac_alloc() failed");
		goto fail2;
	}

	macreg->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macreg->m_driver = bfe;
	macreg->m_dip = dip;
	macreg->m_instance = unit;
	macreg->m_src_addr = bfe->bfe_ether_addr;
	macreg->m_callbacks = &bfe_mac_callbacks;
	macreg->m_min_sdu = 0;
	macreg->m_max_sdu = ETHERMTU;
	macreg->m_margin = VLAN_TAGSZ;

	if ((ret = mac_register(macreg, &bfe->bfe_machdl)) != 0) {
		bfe_error(dip, "mac_register() failed with %d error", ret);
		mac_free(macreg);
		goto fail2;
	}

	mac_free(macreg);

	rw_init(&bfe->bfe_rwlock, NULL, RW_DRIVER,
	    DDI_INTR_PRI(bfe->bfe_intrpri));

	if (bfe_add_intr(bfe) != DDI_SUCCESS) {
		bfe_error(dip, "Could not add interrupt");
		goto fail3;
	}

	if (bfe_rings_alloc(bfe) != DDI_SUCCESS) {
		bfe_error(dip, "Could not allocate TX/RX Ring");
		goto fail4;
	}

	/* Init and then reset the chip */
	bfe->bfe_chip_action = 0;
	bfe_init_vars(bfe);

	/* PHY will also start running */
	bfe_chip_reset(bfe);

	/*
	 * Even though we enable the interrupts here but chip's interrupt
	 * is not enabled yet. It will be enabled once we plumb the interface.
	 */
	if (ddi_intr_enable(bfe->bfe_intrhdl) != DDI_SUCCESS) {
		bfe_error(dip, "Could not enable interrupt");
		goto fail4;
	}

	return (DDI_SUCCESS);

fail4:
	bfe_remove_intr(bfe);
fail3:
	(void) mac_unregister(bfe->bfe_machdl);
fail2:
	bfe_unmap_regs(bfe);
fail1:
	pci_config_teardown(&bfe->bfe_conf_handle);
fail0:
	kmem_free(bfe, sizeof (bfe_t));
	return (DDI_FAILURE);
}

static int
bfe_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{
	bfe_t *bfe;

	bfe = ddi_get_driver_private(devinfo);

	switch (cmd) {
	case DDI_DETACH:
		/*
		 * We need to stop the timer before grabbing locks otherwise
		 * we can land-up in deadlock with untimeout.
		 */
		bfe_stop_timer(bfe);

		/*
		 * First unregister with MAC layer before stopping DMA
		 * engine.
		 */
		if (mac_unregister(bfe->bfe_machdl) != DDI_SUCCESS)
			return (DDI_FAILURE);

		bfe->bfe_machdl = NULL;

		/*
		 * Quiesce the chip first.
		 */
		bfe_grab_locks(bfe);
		bfe_chip_halt(bfe);
		bfe_stop_phy(bfe);
		bfe_release_locks(bfe);

		(void) ddi_intr_disable(bfe->bfe_intrhdl);

		/* Make sure timer is gone. */
		bfe_stop_timer(bfe);

		/*
		 * Free the DMA resources for buffer and then descriptors
		 */
		if (bfe->bfe_tx_ring.r_flags == BFE_RING_ALLOCATED) {
			/* TX */
			bfe_buffer_free(&bfe->bfe_tx_ring);
			bfe_ring_desc_free(&bfe->bfe_tx_ring);
		}

		if (bfe->bfe_rx_ring.r_flags == BFE_RING_ALLOCATED) {
			/* RX */
			bfe_buffer_free(&bfe->bfe_rx_ring);
			bfe_ring_desc_free(&bfe->bfe_rx_ring);
		}

		bfe_remove_intr(bfe);
		bfe_unmap_regs(bfe);
		pci_config_teardown(&bfe->bfe_conf_handle);

		mutex_destroy(&bfe->bfe_tx_ring.r_lock);
		mutex_destroy(&bfe->bfe_rx_ring.r_lock);
		rw_destroy(&bfe->bfe_rwlock);

		kmem_free(bfe, sizeof (bfe_t));

		ddi_set_driver_private(devinfo, NULL);
		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		/*
		 * We need to stop the timer before grabbing locks otherwise
		 * we can land-up in deadlock with untimeout.
		 */
		bfe_stop_timer(bfe);

		/*
		 * Grab all the locks first.
		 */
		bfe_grab_locks(bfe);
		bfe_chip_halt(bfe);
		bfe_stop_phy(bfe);
		bfe->bfe_chip_state = BFE_CHIP_SUSPENDED;
		bfe_release_locks(bfe);

		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

/*
 * Quiesce the card for fast reboot
 */
int
bfe_quiesce(dev_info_t *dev_info)
{
	bfe_t *bfe;

	bfe = ddi_get_driver_private(dev_info);

	bfe_chip_halt(bfe);
	bfe_stop_phy(bfe);
	bfe->bfe_chip_state = BFE_CHIP_QUIESCED;

	return (DDI_SUCCESS);
}

static struct cb_ops bfe_cb_ops = {
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
	NULL,			/* cb_stream */
	D_MP | D_HOTPLUG,	/* cb_flag */
	CB_REV,			/* cb_rev */
	nodev,			/* cb_aread */
	nodev			/* cb_awrite */
};

static struct dev_ops bfe_dev_ops = {
	DEVO_REV,	/* devo_rev */
	0,		/* devo_refcnt */
	NULL,		/* devo_getinfo */
	nulldev,	/* devo_identify */
	nulldev,	/* devo_probe */
	bfe_attach,	/* devo_attach */
	bfe_detach,	/* devo_detach */
	nodev,		/* devo_reset */
	&bfe_cb_ops,	/* devo_cb_ops */
	NULL,		/* devo_bus_ops */
	ddi_power,	/* devo_power */
	bfe_quiesce	/* devo_quiesce */
};

static struct modldrv bfe_modldrv = {
	&mod_driverops,
	bfe_ident,
	&bfe_dev_ops
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&bfe_modldrv, NULL
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

	mac_init_ops(&bfe_dev_ops, MODULE_NAME);
	status = mod_install(&modlinkage);
	if (status == DDI_FAILURE)
		mac_fini_ops(&bfe_dev_ops);
	return (status);
}

int
_fini(void)
{
	int status;

	status = mod_remove(&modlinkage);
	if (status == 0) {
		mac_fini_ops(&bfe_dev_ops);
	}
	return (status);
}
