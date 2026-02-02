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
 * Copyright (c) 2012 Gary Mills
 *
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright (c) 2018, Joyent, Inc.
 */
/*
 * Copyright (c) 2009, Pyun YongHyeon <yongari@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/kstat.h>
#include <sys/ethernet.h>
#include <sys/devops.h>
#include <sys/debug.h>
#include <sys/conf.h>
#include <sys/mii.h>
#include <sys/miiregs.h>
#include <sys/mac.h>
#include <sys/mac_provider.h>
#include <sys/mac_ether.h>
#include <sys/sysmacros.h>
#include <sys/dditypes.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/byteorder.h>
#include <sys/note.h>
#include <sys/vlan.h>
#include <sys/strsubr.h>
#include <sys/crc32.h>
#include <sys/sdt.h>
#include <sys/pci.h>
#include <sys/pci_cap.h>

#include "atge.h"
#include "atge_cmn_reg.h"
#include "atge_l1c_reg.h"
#include "atge_l1e_reg.h"
#include "atge_l1_reg.h"


/*
 * Atheros/Attansic Ethernet chips are of four types - L1, L2, L1E and L1C.
 * This driver is for L1E/L1/L1C but can be extended to support other chips.
 * L1E comes in 1Gigabit and Fast Ethernet flavors. L1 comes in 1Gigabit
 * flavors only.  L1C comes in both flavours.
 *
 * Atheros/Attansic Ethernet controllers have descriptor based TX and RX
 * with an exception of L1E. L1E's RX side is not descriptor based ring.
 * The L1E's RX uses pages (not to be confused with MMU pages) for
 * receiving pkts. The header has four fields :
 *
 *        uint32_t seqno;    Sequence number of the frame.
 *        uint32_t length;   Length of the frame.
 *        uint32_t flags;    Flags
 *        uint32_t vtag;     We don't use hardware VTAG.
 *
 * We use only one queue for RX (each queue can have two pages) and each
 * page is L1E_RX_PAGE_SZ large in bytes. That's the reason we don't
 * use zero-copy RX because we are limited to two pages and each page
 * accomodates large number of pkts.
 *
 * The TX side on all three chips is descriptor based ring; and all the
 * more reason to have one driver for these chips.
 *
 * We use two locks - atge_intr_lock and atge_tx_lock. Both the locks
 * should be held if the operation has impact on the driver instance.
 *
 * All the three chips have hash-based multicast filter.
 *
 * We use CMB (Coalescing Message Block) for RX but not for TX as there
 * are some issues with TX. RX CMB is used to get the last descriptor
 * posted by the chip. Each CMB is for a RX page (one queue can have two
 * pages) and are uint32_t (4 bytes) long.
 *
 * The descriptor table should have 32-bit physical address limit due to
 * the limitation of having same high address for TX/RX/SMB/CMB. The
 * TX/RX buffers can be 64-bit.
 *
 * Every DMA memory in atge is represented by atge_dma_t be it TX/RX Buffers
 * or TX/RX descriptor table or SMB/CMB. To keep the code simple, we have
 * kept sgl as 1 so that we get contingous pages from root complex.
 *
 * L1 chip (0x1048) uses descriptor based TX and RX ring. Most of registers are
 * common with L1E chip (0x1026).
 */

/*
 * Function Prototypes for debugging.
 */
void	atge_error(dev_info_t *, char *, ...);
void	atge_debug_func(char *, ...);

/*
 * Function Prototypes for driver operations.
 */
static int	atge_resume(dev_info_t *);
static int	atge_add_intr(atge_t *);
static int	atge_alloc_dma(atge_t *);
static void	atge_remove_intr(atge_t *);
static void	atge_free_dma(atge_t *);
static void	atge_device_reset(atge_t *);
static void	atge_device_init(atge_t *);
static void	atge_device_start(atge_t *);
static void	atge_disable_intrs(atge_t *);
atge_dma_t *atge_alloc_a_dma_blk(atge_t *, ddi_dma_attr_t *, int, int);
void	atge_free_a_dma_blk(atge_dma_t *);
static void	atge_rxfilter(atge_t *);
static void	atge_device_reset_l1_l1e(atge_t *);
void	atge_program_ether(atge_t *atgep);
void	atge_device_restart(atge_t *);
void	atge_device_stop(atge_t *);
static int	atge_send_a_packet(atge_t *, mblk_t *);
static uint32_t	atge_ether_crc(const uint8_t *, int);


/*
 * L1E/L2E specific functions.
 */
void	atge_l1e_device_reset(atge_t *);
void	atge_l1e_stop_mac(atge_t *);
int	atge_l1e_alloc_dma(atge_t *);
void	atge_l1e_free_dma(atge_t *);
void	atge_l1e_init_tx_ring(atge_t *);
void	atge_l1e_init_rx_pages(atge_t *);
void	atge_l1e_program_dma(atge_t *);
void	atge_l1e_send_packet(atge_ring_t *);
mblk_t	*atge_l1e_receive(atge_t *);
uint_t	atge_l1e_interrupt(caddr_t, caddr_t);
void	atge_l1e_gather_stats(atge_t *);
void	atge_l1e_clear_stats(atge_t *);

/*
 * L1 specific functions.
 */
int	atge_l1_alloc_dma(atge_t *);
void	atge_l1_free_dma(atge_t *);
void	atge_l1_init_tx_ring(atge_t *);
void	atge_l1_init_rx_ring(atge_t *);
void	atge_l1_init_rr_ring(atge_t *);
void	atge_l1_init_cmb(atge_t *);
void	atge_l1_init_smb(atge_t *);
void	atge_l1_program_dma(atge_t *);
void	atge_l1_stop_tx_mac(atge_t *);
void	atge_l1_stop_rx_mac(atge_t *);
uint_t	atge_l1_interrupt(caddr_t, caddr_t);
void	atge_l1_send_packet(atge_ring_t *);

/*
 * L1C specific functions.
 */
int	atge_l1c_alloc_dma(atge_t *);
void	atge_l1c_free_dma(atge_t *);
void	atge_l1c_init_tx_ring(atge_t *);
void	atge_l1c_init_rx_ring(atge_t *);
void	atge_l1c_init_rr_ring(atge_t *);
void	atge_l1c_init_cmb(atge_t *);
void	atge_l1c_init_smb(atge_t *);
void	atge_l1c_program_dma(atge_t *);
void	atge_l1c_stop_tx_mac(atge_t *);
void	atge_l1c_stop_rx_mac(atge_t *);
uint_t	atge_l1c_interrupt(caddr_t, caddr_t);
void	atge_l1c_send_packet(atge_ring_t *);
void	atge_l1c_gather_stats(atge_t *);
void	atge_l1c_clear_stats(atge_t *);

/*
 * Function prototyps for MII operations.
 */
uint16_t	atge_mii_read(void *, uint8_t, uint8_t);
void	atge_mii_write(void *, uint8_t, uint8_t, uint16_t);
uint16_t	atge_l1c_mii_read(void *, uint8_t, uint8_t);
void	atge_l1c_mii_write(void *, uint8_t, uint8_t, uint16_t);
void	atge_l1e_mii_reset(void *);
void	atge_l1_mii_reset(void *);
void	atge_l1c_mii_reset(void *);
static void	atge_mii_notify(void *, link_state_t);
void	atge_tx_reclaim(atge_t *atgep, int cons);

/*
 * L1E/L2E chip.
 */
static	mii_ops_t atge_l1e_mii_ops = {
	MII_OPS_VERSION,
	atge_mii_read,
	atge_mii_write,
	atge_mii_notify,
	atge_l1e_mii_reset
};

/*
 * L1 chip.
 */
static	mii_ops_t atge_l1_mii_ops = {
	MII_OPS_VERSION,
	atge_mii_read,
	atge_mii_write,
	atge_mii_notify,
	atge_l1_mii_reset
};

/*
 * L1C chip.
 */
static	mii_ops_t atge_l1c_mii_ops = {
	MII_OPS_VERSION,
	atge_l1c_mii_read,
	atge_l1c_mii_write,
	atge_mii_notify,
	atge_l1c_mii_reset
};

/*
 * Function Prototypes for MAC callbacks.
 */
static int	atge_m_stat(void *, uint_t, uint64_t *);
static int	atge_m_start(void *);
static void	atge_m_stop(void *);
static int	atge_m_getprop(void *, const char *, mac_prop_id_t, uint_t,
    void *);
static int	atge_m_setprop(void *, const char *, mac_prop_id_t, uint_t,
    const void *);
static void	atge_m_propinfo(void *, const char *, mac_prop_id_t,
    mac_prop_info_handle_t);
static int	atge_m_unicst(void *, const uint8_t *);
static int	atge_m_multicst(void *, boolean_t, const uint8_t *);
static int	atge_m_promisc(void *, boolean_t);
static mblk_t	*atge_m_tx(void *, mblk_t *);

static	mac_callbacks_t	atge_m_callbacks = {
	MC_SETPROP | MC_GETPROP | MC_PROPINFO,
	atge_m_stat,
	atge_m_start,
	atge_m_stop,
	atge_m_promisc,
	atge_m_multicst,
	atge_m_unicst,
	atge_m_tx,
	NULL,		/* mc_reserved */
	NULL,		/* mc_ioctl */
	NULL,		/* mc_getcapab */
	NULL,		/* mc_open */
	NULL,		/* mc_close */
	atge_m_setprop,
	atge_m_getprop,
	atge_m_propinfo
};

/*
 * DMA Data access requirements.
 */
static struct ddi_device_acc_attr atge_dev_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

/*
 * Buffers should be native endianness.
 */
static struct ddi_device_acc_attr atge_buf_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,	/* native endianness */
	DDI_STRICTORDER_ACC
};

/*
 * DMA device attributes. Buffer can be 64-bit.
 */
static ddi_dma_attr_t atge_dma_attr_buf = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo */
	0x00ffffffffffull,	/* dma_attr_addr_hi */
	0x000000003fffull,	/* dma_attr_count_max */
	8,			/* dma_attr_align */
	0x00003ffc,		/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0x0000000027ffull,	/* dma_attr_maxxfer */
	0x0000ffffffffull,	/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};

/*
 * Table of supported devices.
 */
#define	ATGE_VENDOR_ID	0x1969
#define	ATGE_L1_STR	"Attansic L1"
#define	ATGE_L1CG_STR	"Atheros AR8131 Gigabit Ethernet"
#define	ATGE_L1CF_STR	"Atheros AR8132 Fast Ethernet"
#define	ATGE_L1E_STR	"Atheros AR8121/8113/8114"
#define	ATGE_AR8151V1_STR	"Atheros AR8151 v1.0 Gigabit Ethernet"
#define	ATGE_AR8151V2_STR	"Atheros AR8151 v2.0 Gigabit Ethernet"
#define	ATGE_AR8152V1_STR	"Atheros AR8152 v1.1 Fast Ethernet"
#define	ATGE_AR8152V2_STR	"Atheros AR8152 v2.0 Fast Ethernet"

static atge_cards_t atge_cards[] = {
	{ATGE_VENDOR_ID, ATGE_CHIP_AR8151V2_DEV_ID, ATGE_AR8151V2_STR,
	    ATGE_CHIP_L1C},
	{ATGE_VENDOR_ID, ATGE_CHIP_AR8151V1_DEV_ID, ATGE_AR8151V1_STR,
	    ATGE_CHIP_L1C},
	{ATGE_VENDOR_ID, ATGE_CHIP_AR8152V2_DEV_ID, ATGE_AR8152V2_STR,
	    ATGE_CHIP_L1C},
	{ATGE_VENDOR_ID, ATGE_CHIP_AR8152V1_DEV_ID, ATGE_AR8152V1_STR,
	    ATGE_CHIP_L1C},
	{ATGE_VENDOR_ID, ATGE_CHIP_L1CG_DEV_ID, ATGE_L1CG_STR, ATGE_CHIP_L1C},
	{ATGE_VENDOR_ID, ATGE_CHIP_L1CF_DEV_ID, ATGE_L1CF_STR, ATGE_CHIP_L1C},
	{ATGE_VENDOR_ID, ATGE_CHIP_L1E_DEV_ID, ATGE_L1E_STR, ATGE_CHIP_L1E},
	{ATGE_VENDOR_ID, ATGE_CHIP_L1_DEV_ID, ATGE_L1_STR, ATGE_CHIP_L1},
};

/*
 * Global Debugging flag. Developer level debugging is done only in DEBUG mode.
 */
int	atge_debug = 1;

/*
 * Debugging and error reporting.
 */
void
atge_debug_func(char *fmt, ...)
{
	va_list	ap;
	char	buf[256];

	va_start(ap, fmt);
	(void) vsnprintf(buf, sizeof (buf), fmt, ap);
	va_end(ap);

	DTRACE_PROBE1(atge__debug, char *, buf);
}

static
void
atge_message(dev_info_t *dip, int level, char *fmt, va_list ap)
{
	char	buf[256];
	char	*p = "!%s%d: %s";
	char	*q = "!atge: %s";

	(void) vsnprintf(buf, sizeof (buf), fmt, ap);

	if (level != CE_NOTE) {
		p++;
		q++;
	}

	if (dip) {
		cmn_err(level, p,
		    ddi_driver_name(dip), ddi_get_instance(dip), buf);
	} else {
		cmn_err(level, q, buf);
	}
}

void
atge_notice(dev_info_t *dip, char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	(void) atge_message(dip, CE_NOTE, fmt, ap);
	va_end(ap);
}

void
atge_error(dev_info_t *dip, char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	(void) atge_message(dip, CE_WARN, fmt, ap);
	va_end(ap);
}

void
atge_mac_config(atge_t *atgep)
{
	uint32_t reg;
	int speed;
	link_duplex_t ld;

	/* Re-enable TX/RX MACs */
	reg = INL(atgep, ATGE_MAC_CFG);
	reg &= ~(ATGE_CFG_FULL_DUPLEX | ATGE_CFG_TX_FC | ATGE_CFG_RX_FC |
	    ATGE_CFG_SPEED_MASK);

	switch (ATGE_MODEL(atgep)) {
	case ATGE_CHIP_L1C:
		switch (ATGE_DID(atgep)) {
		case ATGE_CHIP_AR8151V2_DEV_ID:
		case ATGE_CHIP_AR8151V1_DEV_ID:
		case ATGE_CHIP_AR8152V2_DEV_ID:
			reg |= ATGE_CFG_HASH_ALG_CRC32 | ATGE_CFG_SPEED_MODE_SW;
			break;
		}
		break;
	}

	speed = mii_get_speed(atgep->atge_mii);
	switch (speed) {
	case 10:
	case 100:
		reg |= ATGE_CFG_SPEED_10_100;
		break;
	case 1000:
		reg |= ATGE_CFG_SPEED_1000;
		break;
	}

	ld = mii_get_duplex(atgep->atge_mii);
	if (ld == LINK_DUPLEX_FULL)
		reg |= ATGE_CFG_FULL_DUPLEX;

	/* Re-enable TX/RX MACs */
	switch (ATGE_MODEL(atgep)) {
	case ATGE_CHIP_L1E:
		reg |= ATGE_CFG_TX_ENB | ATGE_CFG_RX_ENB | ATGE_CFG_RX_FC;
		break;
	case ATGE_CHIP_L1:
	case ATGE_CHIP_L1C:
		reg |= ATGE_CFG_TX_ENB | ATGE_CFG_RX_ENB;
		break;
	}

	OUTL(atgep, ATGE_MAC_CFG, reg);

	switch (ATGE_MODEL(atgep)) {
	case ATGE_CHIP_L1E:
		reg = ATGE_USECS(ATGE_IM_RX_TIMER_DEFAULT) << IM_TIMER_RX_SHIFT;
		reg |= ATGE_USECS(ATGE_IM_TX_TIMER_DEFAULT) <<
		    IM_TIMER_TX_SHIFT;
		OUTL(atgep, ATGE_IM_TIMER, reg);
		break;
	case ATGE_CHIP_L1:
		break;
	case ATGE_CHIP_L1C:
		/* Configure interrupt moderation timer. */
		reg = ATGE_USECS(atgep->atge_int_rx_mod) << IM_TIMER_RX_SHIFT;
		reg |= ATGE_USECS(atgep->atge_int_tx_mod) << IM_TIMER_TX_SHIFT;
		OUTL(atgep, ATGE_IM_TIMER, reg);
		/*
		 * We don't want to automatic interrupt clear as task queue
		 * for the interrupt should know interrupt status.
		 */
		reg = 0;
		if (ATGE_USECS(atgep->atge_int_rx_mod) != 0)
			reg |= MASTER_IM_RX_TIMER_ENB;
		if (ATGE_USECS(atgep->atge_int_tx_mod) != 0)
			reg |= MASTER_IM_TX_TIMER_ENB;
		OUTL(atgep, ATGE_MASTER_CFG, reg);
		break;
	}

	ATGE_DB(("%s: %s() mac_cfg is : %x",
	    atgep->atge_name, __func__, INL(atgep, ATGE_MAC_CFG)));
}

static void
atge_mii_notify(void *arg, link_state_t link)
{
	atge_t *atgep = arg;

	ATGE_DB(("%s: %s() LINK STATUS CHANGED from %x -> %x",
	    atgep->atge_name, __func__, atgep->atge_link_state, link));

	mac_link_update(atgep->atge_mh, link);

	/*
	 * Reconfigure MAC if link status is UP now.
	 */
	mutex_enter(&atgep->atge_tx_lock);
	if (link == LINK_STATE_UP) {
		atgep->atge_link_state = LINK_STATE_UP;
		atge_mac_config(atgep);
		atgep->atge_tx_resched = 0;
	} else {
		atgep->atge_link_state = LINK_STATE_DOWN;
		atgep->atge_flags |= ATGE_MII_CHECK;
	}

	mutex_exit(&atgep->atge_tx_lock);

	if (link == LINK_STATE_UP)
		mac_tx_update(atgep->atge_mh);
}

void
atge_tx_reclaim(atge_t *atgep, int end)
{
	atge_tx_desc_t  *txd;
	atge_ring_t *r = atgep->atge_tx_ring;
	uchar_t *c;
	int start;

	ASSERT(MUTEX_HELD(&atgep->atge_tx_lock));
	ASSERT(r != NULL);

	start = r->r_consumer;

	if (start == end)
		return;

	while (start != end) {
		r->r_avail_desc++;
		if (r->r_avail_desc > ATGE_TX_RING_CNT) {

			atge_error(atgep->atge_dip,
			    "Reclaim : TX descriptor error");

			if (r->r_avail_desc > (ATGE_TX_RING_CNT + 5)) {
				atge_device_stop(atgep);
				break;
			}
		}

		c = (uchar_t *)r->r_desc_ring->addr;
		c += (sizeof (atge_tx_desc_t) * start);
		txd = (atge_tx_desc_t *)c;

		/*
		 * Clearing TX descriptor helps in debugging some strange
		 * problems.
		 */
		txd->addr = 0;
		txd->len = 0;
		txd->flags = 0;

		ATGE_INC_SLOT(start, ATGE_TX_RING_CNT);
	}

	atgep->atge_tx_ring->r_consumer = start;

	DMA_SYNC(r->r_desc_ring, 0, ATGE_TX_RING_SZ, DDI_DMA_SYNC_FORDEV);
}

/*
 * Adds interrupt handler depending upon the type of interrupt supported by
 * the chip.
 */
static int
atge_add_intr_handler(atge_t *atgep, int intr_type)
{
	int err;
	int count = 0;
	int avail = 0;
	int i;
	int flag;

	if (intr_type != DDI_INTR_TYPE_FIXED) {
		err = ddi_intr_get_nintrs(atgep->atge_dip, intr_type, &count);
		if (err != DDI_SUCCESS) {
			atge_error(atgep->atge_dip,
			    "ddi_intr_get_nintrs failed : %d", err);
			return (DDI_FAILURE);
		}

		ATGE_DB(("%s: %s() count : %d",
		    atgep->atge_name, __func__, count));

		err = ddi_intr_get_navail(atgep->atge_dip, intr_type, &avail);
		if (err != DDI_SUCCESS) {
			atge_error(atgep->atge_dip,
			    "ddi_intr_get_navail failed : %d", err);
			return (DDI_FAILURE);
		}

		if (avail < count) {
			atge_error(atgep->atge_dip, "count :%d,"
			    " avail : %d", count, avail);
		}

		flag = DDI_INTR_ALLOC_STRICT;
	} else {
		/*
		 * DDI_INTR_TYPE_FIXED case.
		 */
		count = 1;
		avail = 1;
		flag = DDI_INTR_ALLOC_NORMAL;
	}

	atgep->atge_intr_size = avail * sizeof (ddi_intr_handle_t);
	atgep->atge_intr_handle = kmem_zalloc(atgep->atge_intr_size, KM_SLEEP);

	ATGE_DB(("%s: %s() avail:%d, count : %d, type : %d",
	    atgep->atge_name, __func__, avail, count,
	    intr_type));

	err = ddi_intr_alloc(atgep->atge_dip, atgep->atge_intr_handle,
	    intr_type, 0, avail, &atgep->atge_intr_cnt, flag);

	if (err != DDI_SUCCESS) {
		atge_error(atgep->atge_dip, "ddi_intr_alloc failed : %d", err);
		kmem_free(atgep->atge_intr_handle, atgep->atge_intr_size);
		return (DDI_FAILURE);
	}

	ATGE_DB(("%s: atge_add_intr_handler() after alloc count"
	    " :%d, avail : %d", atgep->atge_name, count, avail));

	err = ddi_intr_get_pri(atgep->atge_intr_handle[0],
	    &atgep->atge_intr_pri);
	if (err != DDI_SUCCESS) {
		atge_error(atgep->atge_dip, "ddi_intr_get_pri failed:%d", err);
		for (i = 0; i < atgep->atge_intr_cnt; i++) {
			(void) ddi_intr_free(atgep->atge_intr_handle[i]);
		}
		kmem_free(atgep->atge_intr_handle, atgep->atge_intr_size);

		return (DDI_FAILURE);
	}

	/*
	 * Add interrupt handler now.
	 */
	for (i = 0; i < atgep->atge_intr_cnt; i++) {
		switch (ATGE_MODEL(atgep)) {
		case ATGE_CHIP_L1E:
			err = ddi_intr_add_handler(atgep->atge_intr_handle[i],
			    atge_l1e_interrupt, atgep, (caddr_t)(uintptr_t)i);
			break;
		case ATGE_CHIP_L1:
			err = ddi_intr_add_handler(atgep->atge_intr_handle[i],
			    atge_l1_interrupt, atgep, (caddr_t)(uintptr_t)i);
			break;
		case ATGE_CHIP_L1C:
			err = ddi_intr_add_handler(atgep->atge_intr_handle[i],
			    atge_l1c_interrupt, atgep, (caddr_t)(uintptr_t)i);
			break;
		}

		if (err != DDI_SUCCESS) {
			atge_error(atgep->atge_dip,
			    "ddi_intr_add_handler failed : %d", err);

			(void) ddi_intr_free(atgep->atge_intr_handle[i]);
			while (--i >= 0) {
				(void) ddi_intr_remove_handler(
				    atgep->atge_intr_handle[i]);
				(void) ddi_intr_free(
				    atgep->atge_intr_handle[i]);
			}

			kmem_free(atgep->atge_intr_handle,
			    atgep->atge_intr_size);

			return (DDI_FAILURE);
		}
	}

	err = ddi_intr_get_cap(atgep->atge_intr_handle[0],
	    &atgep->atge_intr_cap);

	if (err != DDI_SUCCESS) {
		atge_error(atgep->atge_dip,
		    "ddi_intr_get_cap failed : %d", err);
		atge_remove_intr(atgep);
		return (DDI_FAILURE);
	}

	if (intr_type == DDI_INTR_TYPE_FIXED)
		atgep->atge_flags |= ATGE_FIXED_TYPE;
	else if (intr_type == DDI_INTR_TYPE_MSI)
		atgep->atge_flags |= ATGE_MSI_TYPE;
	else if (intr_type == DDI_INTR_TYPE_MSIX)
		atgep->atge_flags |= ATGE_MSIX_TYPE;

	return (DDI_SUCCESS);
}

void
atge_remove_intr(atge_t *atgep)
{
	int i;
	int cap = 0;

	if (atgep->atge_intr_handle == NULL)
		return;

	if (atgep->atge_intr_cap & DDI_INTR_FLAG_BLOCK) {
		(void) ddi_intr_block_disable(atgep->atge_intr_handle,
		    atgep->atge_intr_cnt);

		cap = 1;
	}

	for (i = 0; i < atgep->atge_intr_cnt; i++) {
		if (cap == 0)
			(void) ddi_intr_disable(atgep->atge_intr_handle[i]);

		(void) ddi_intr_remove_handler(atgep->atge_intr_handle[i]);
		(void) ddi_intr_free(atgep->atge_intr_handle[i]);
	}

	kmem_free(atgep->atge_intr_handle, atgep->atge_intr_size);
}

int
atge_enable_intrs(atge_t *atgep)
{
	int err;
	int i;

	if (atgep->atge_intr_cap & DDI_INTR_FLAG_BLOCK) {
		/*
		 * Do block enable.
		 */
		err = ddi_intr_block_enable(atgep->atge_intr_handle,
		    atgep->atge_intr_cnt);

		if (err != DDI_SUCCESS) {
			atge_error(atgep->atge_dip,
			    "Failed to block enable intrs %d", err);
			err = DDI_FAILURE;
		} else {
			err = DDI_SUCCESS;
		}
	} else {
		/*
		 * Call ddi_intr_enable() for MSI non-block enable.
		 */
		for (i = 0; i < atgep->atge_intr_cnt; i++) {
			err = ddi_intr_enable(atgep->atge_intr_handle[i]);
			if (err != DDI_SUCCESS) {
				atge_error(atgep->atge_dip,
				    "Failed to enable intrs on %d with : %d",
				    i, err);
				break;
			}
		}

		if (err == DDI_SUCCESS)
			err = DDI_SUCCESS;
		else
			err = DDI_FAILURE;
	}

	return (err);
}

/*
 * Adds interrupt handler depending on the supported interrupt type by the
 * chip.
 */
static int
atge_add_intr(atge_t *atgep)
{
	int	err;

	/*
	 * Get the supported interrupt types.
	 */
	err = ddi_intr_get_supported_types(atgep->atge_dip,
	    &atgep->atge_intr_types);
	if (err != DDI_SUCCESS) {
		atge_error(atgep->atge_dip,
		    "ddi_intr_get_supported_types failed : %d", err);
		return (DDI_FAILURE);
	}

	ATGE_DB(("%s: ddi_intr_get_supported_types() returned : %d",
	    atgep->atge_name, atgep->atge_intr_types));


	if (atgep->atge_intr_types & DDI_INTR_TYPE_MSIX) {
		err = atge_add_intr_handler(atgep, DDI_INTR_TYPE_MSIX);
		if (err == DDI_SUCCESS) {
			ATGE_DB(("%s: Using MSIx for interrupt",
			    atgep->atge_name));
			return (err);
		}
	}

	if (atgep->atge_intr_types & DDI_INTR_TYPE_MSI) {
		err = atge_add_intr_handler(atgep, DDI_INTR_TYPE_MSI);
		if (err == DDI_SUCCESS) {
			ATGE_DB(("%s: Using MSI for interrupt",
			    atgep->atge_name));
			return (err);
		}
	}

	err = DDI_FAILURE;
	if (atgep->atge_intr_types & DDI_INTR_TYPE_FIXED) {
		err = atge_add_intr_handler(atgep, DDI_INTR_TYPE_FIXED);
		if (err == DDI_SUCCESS) {
			ATGE_DB(("%s: Using FIXED type for interrupt",
			    atgep->atge_name));
			return (err);
		}
	}

	return (err);
}

int
atge_identify_hardware(atge_t *atgep)
{
	uint16_t vid, did;
	int i;

	vid = pci_config_get16(atgep->atge_conf_handle, PCI_CONF_VENID);
	did = pci_config_get16(atgep->atge_conf_handle, PCI_CONF_DEVID);

	atgep->atge_model = 0;
	for (i = 0; i < (sizeof (atge_cards) / sizeof (atge_cards_t)); i++) {
		if (atge_cards[i].vendor_id == vid &&
		    atge_cards[i].device_id == did) {
			atgep->atge_model = atge_cards[i].model;
			atgep->atge_vid = vid;
			atgep->atge_did = did;
			atgep->atge_revid =
			    pci_config_get8(atgep->atge_conf_handle,
			    PCI_CONF_REVID);
			atge_notice(atgep->atge_dip, "PCI-ID pci%x,%x,%x: %s",
			    vid, did, atgep->atge_revid,
			    atge_cards[i].cardname);
			ATGE_DB(("%s: %s : PCI-ID pci%x,%x and model : %d",
			    atgep->atge_name, __func__, vid, did,
			    atgep->atge_model));

			return (DDI_SUCCESS);
		}
	}

	atge_error(atgep->atge_dip, "atge driver is attaching to unknown"
	    " pci%x,%x vendor/device-id card", vid, did);

	/*
	 * Assume it's L1C chip.
	 */
	atgep->atge_model = ATGE_CHIP_L1C;
	atgep->atge_vid = vid;
	atgep->atge_did = did;
	atgep->atge_revid = pci_config_get8(atgep->atge_conf_handle,
	    PCI_CONF_REVID);

	/*
	 * We will leave the decision to caller.
	 */
	return (DDI_FAILURE);
}

int
atge_get_macaddr(atge_t *atgep)
{
	uint32_t reg;

	reg = INL(atgep, ATGE_SPI_CTRL);
	if ((reg & SPI_VPD_ENB) != 0) {
		/*
		 * Get VPD stored in TWSI EEPROM.
		 */
		reg &= ~SPI_VPD_ENB;
		OUTL(atgep, ATGE_SPI_CTRL, reg);

		ATGE_DB(("%s: %s called Get VPD", atgep->atge_name, __func__));
	}

	atgep->atge_ether_addr[5] = INB(atgep, ATGE_PAR0 + 0);
	atgep->atge_ether_addr[4] = INB(atgep, ATGE_PAR0 + 1);
	atgep->atge_ether_addr[3] = INB(atgep, ATGE_PAR0 + 2);
	atgep->atge_ether_addr[2] = INB(atgep, ATGE_PAR0 + 3);
	atgep->atge_ether_addr[1] = INB(atgep, ATGE_PAR1 + 0);
	atgep->atge_ether_addr[0] = INB(atgep, ATGE_PAR1 + 1);

	ATGE_DB(("%s: %s() Station Address - %x:%x:%x:%x:%x:%x",
	    atgep->atge_name, __func__,
	    atgep->atge_ether_addr[0],
	    atgep->atge_ether_addr[1],
	    atgep->atge_ether_addr[2],
	    atgep->atge_ether_addr[3],
	    atgep->atge_ether_addr[4],
	    atgep->atge_ether_addr[5]));

	bcopy(atgep->atge_ether_addr, atgep->atge_dev_addr, ETHERADDRL);

	return (DDI_SUCCESS);
}

/*
 * Reset functionality for L1, L1E, and L1C. It's same.
 */
static void
atge_device_reset(atge_t *atgep)
{
	switch (ATGE_MODEL(atgep)) {
	case ATGE_CHIP_L1E:
	case ATGE_CHIP_L1:
	case ATGE_CHIP_L1C:
		atge_device_reset_l1_l1e(atgep);
		break;
	}
}

void
atge_device_reset_l1_l1e(atge_t *atgep)
{
	uint32_t reg;
	int t;
	switch (ATGE_MODEL(atgep)) {
	case ATGE_CHIP_L1C:
		OUTL(atgep, ATGE_MASTER_CFG, MASTER_RESET | 0x40);
		break;
	default:
		OUTL(atgep, ATGE_MASTER_CFG, MASTER_RESET);
		break;
	}
	reg = INL(atgep, ATGE_MASTER_CFG);
	for (t = ATGE_RESET_TIMEOUT; t > 0; t--) {
		drv_usecwait(10);
		reg = INL(atgep, ATGE_MASTER_CFG);
		if ((reg & MASTER_RESET) == 0)
			break;
	}

	if (t == 0) {
		atge_error(atgep->atge_dip, " master reset timeout reg : %x",
		    reg);
	}

	for (t = ATGE_RESET_TIMEOUT; t > 0; t--) {
		if ((reg = INL(atgep, ATGE_IDLE_STATUS)) == 0)
			break;

		drv_usecwait(10);
	}

	if (t == 0) {
		atge_error(atgep->atge_dip, "device reset timeout reg : %x",
		    reg);
	}

	switch (ATGE_MODEL(atgep)) {
	case ATGE_CHIP_L1E:
	case ATGE_CHIP_L1:
		/*
		 * Initialize PCIe module. These values came from FreeBSD and
		 * we don't know the meaning of it.
		 */
		OUTL(atgep, ATGE_LTSSM_ID_CFG, 0x6500);
		reg = INL(atgep, 0x1008) | 0x8000;
		OUTL(atgep, 0x1008, reg);
		break;
	case ATGE_CHIP_L1C:
		break;
	}

	/*
	 * Get chip revision.
	 */
	atgep->atge_chip_rev = INL(atgep, ATGE_MASTER_CFG) >>
	    MASTER_CHIP_REV_SHIFT;

	ATGE_DB(("%s: %s reset successfully rev : %x", atgep->atge_name,
	    __func__, atgep->atge_chip_rev));
}

/*
 * DMA allocation for L1 and L1E is bit different since L1E uses RX pages
 * instead of descriptor based RX model.
 */
static int
atge_alloc_dma(atge_t *atgep)
{
	int err = DDI_FAILURE;

	switch (ATGE_MODEL(atgep)) {
	case ATGE_CHIP_L1E:
		err = atge_l1e_alloc_dma(atgep);
		break;
	case ATGE_CHIP_L1:
		err = atge_l1_alloc_dma(atgep);
		break;
	case ATGE_CHIP_L1C:
		err = atge_l1c_alloc_dma(atgep);
		break;
	}

	return (err);
}

static void
atge_free_dma(atge_t *atgep)
{
	switch (ATGE_MODEL(atgep)) {
	case ATGE_CHIP_L1E:
		atge_l1e_free_dma(atgep);
		break;
	case ATGE_CHIP_L1:
		atge_l1_free_dma(atgep);
		break;
	case ATGE_CHIP_L1C:
		atge_l1c_free_dma(atgep);
		break;
	}
}

/*
 * Attach entry point in the driver.
 */
static int
atge_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	atge_t	*atgep;
	mac_register_t	*macreg;
	int	instance;
	uint16_t cap_ptr;
	uint16_t burst;
	int err;
	mii_ops_t *mii_ops;

	instance =  ddi_get_instance(devinfo);

	switch (cmd) {
	case DDI_RESUME:
		return (atge_resume(devinfo));

	case DDI_ATTACH:
		ddi_set_driver_private(devinfo, NULL);
		break;
	default:
		return (DDI_FAILURE);

	}

	atgep = kmem_zalloc(sizeof (atge_t), KM_SLEEP);
	ddi_set_driver_private(devinfo, atgep);
	atgep->atge_dip = devinfo;

	/*
	 * Setup name and instance number to be used for debugging and
	 * error reporting.
	 */
	(void) snprintf(atgep->atge_name, sizeof (atgep->atge_name), "%s%d",
	    "atge", instance);


	/*
	 * Map PCI config space.
	 */
	err = pci_config_setup(devinfo, &atgep->atge_conf_handle);
	if (err != DDI_SUCCESS) {
		atge_error(devinfo, "pci_config_setup() failed");
		goto fail1;
	}

	(void) atge_identify_hardware(atgep);

	/*
	 * Map Device registers.
	 */
	err = ddi_regs_map_setup(devinfo, ATGE_PCI_REG_NUMBER,
	    &atgep->atge_io_regs, 0, 0, &atge_dev_attr, &atgep->atge_io_handle);
	if (err != DDI_SUCCESS) {
		atge_error(devinfo, "ddi_regs_map_setup() failed");
		goto fail2;
	}

	/*
	 * Add interrupt and its associated handler.
	 */
	err = atge_add_intr(atgep);
	if (err != DDI_SUCCESS) {
		atge_error(devinfo, "Failed to add interrupt handler");
		goto fail3;
	}

	mutex_init(&atgep->atge_intr_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(atgep->atge_intr_pri));

	mutex_init(&atgep->atge_tx_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(atgep->atge_intr_pri));

	mutex_init(&atgep->atge_rx_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(atgep->atge_intr_pri));

	mutex_init(&atgep->atge_mii_lock, NULL, MUTEX_DRIVER, NULL);

	/*
	 * Used to lock down MBOX register on L1 chip since RX consumer,
	 * TX producer and RX return ring consumer are shared.
	 */
	mutex_init(&atgep->atge_mbox_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(atgep->atge_intr_pri));

	atgep->atge_link_state = LINK_STATE_DOWN;
	atgep->atge_mtu = ETHERMTU;

	switch (ATGE_MODEL(atgep)) {
	case ATGE_CHIP_L1E:
		if (atgep->atge_revid > 0xF0) {
			/* L2E Rev. B. AR8114 */
			atgep->atge_flags |= ATGE_FLAG_FASTETHER;
		} else {
			if ((INL(atgep, L1E_PHY_STATUS) &
			    PHY_STATUS_100M) != 0) {
				/* L1E AR8121 */
				atgep->atge_flags |= ATGE_FLAG_JUMBO;
			} else {
				/* L2E Rev. A. AR8113 */
				atgep->atge_flags |= ATGE_FLAG_FASTETHER;
			}
		}
		break;
	case ATGE_CHIP_L1:
		break;
	case ATGE_CHIP_L1C:
		/*
		 * One odd thing is AR8132 uses the same PHY hardware(F1
		 * gigabit PHY) of AR8131. So atphy(4) of AR8132 reports
		 * the PHY supports 1000Mbps but that's not true. The PHY
		 * used in AR8132 can't establish gigabit link even if it
		 * shows the same PHY model/revision number of AR8131.
		 *
		 * It seems that AR813x/AR815x has silicon bug for SMB. In
		 * addition, Atheros said that enabling SMB wouldn't improve
		 * performance. However I think it's bad to access lots of
		 * registers to extract MAC statistics.
		 *
		 * Don't use Tx CMB. It is known to have silicon bug.
		 */
		switch (ATGE_DID(atgep)) {
		case ATGE_CHIP_AR8152V2_DEV_ID:
		case ATGE_CHIP_AR8152V1_DEV_ID:
			atgep->atge_flags |= ATGE_FLAG_APS |
			    ATGE_FLAG_FASTETHER |
			    ATGE_FLAG_ASPM_MON | ATGE_FLAG_JUMBO |
			    ATGE_FLAG_SMB_BUG | ATGE_FLAG_CMB_BUG;
			break;
		case ATGE_CHIP_AR8151V2_DEV_ID:
		case ATGE_CHIP_AR8151V1_DEV_ID:
			atgep->atge_flags |= ATGE_FLAG_APS |
			    ATGE_FLAG_ASPM_MON | ATGE_FLAG_JUMBO |
			    ATGE_FLAG_SMB_BUG | ATGE_FLAG_CMB_BUG;
			break;
		case ATGE_CHIP_L1CF_DEV_ID:
			atgep->atge_flags |= ATGE_FLAG_FASTETHER;
			break;
		case ATGE_CHIP_L1CG_DEV_ID:
			break;
		}
		break;
	}

	/*
	 * Get DMA parameters from PCIe device control register.
	 */
	err = PCI_CAP_LOCATE(atgep->atge_conf_handle, PCI_CAP_ID_PCI_E,
	    &cap_ptr);

	if (err == DDI_FAILURE) {
		atgep->atge_dma_rd_burst = DMA_CFG_RD_BURST_128;
		atgep->atge_dma_wr_burst = DMA_CFG_WR_BURST_128;
	} else {
		atgep->atge_flags |= ATGE_FLAG_PCIE;
		burst = pci_config_get16(atgep->atge_conf_handle,
		    cap_ptr + 0x08);

		/*
		 * Max read request size.
		 */
		atgep->atge_dma_rd_burst = ((burst >> 12) & 0x07) <<
		    DMA_CFG_RD_BURST_SHIFT;

		/*
		 * Max Payload Size.
		 */
		atgep->atge_dma_wr_burst = ((burst >> 5) & 0x07) <<
		    DMA_CFG_WR_BURST_SHIFT;

		ATGE_DB(("%s: %s() MRR : %d, MPS : %d",
		    atgep->atge_name, __func__,
		    (128 << ((burst >> 12) & 0x07)),
		    (128 << ((burst >> 5) & 0x07))));
	}

	/* Clear data link and flow-control protocol error. */
	switch (ATGE_MODEL(atgep)) {
	case ATGE_CHIP_L1E:
		break;
	case ATGE_CHIP_L1:
		break;
	case ATGE_CHIP_L1C:
		OUTL_AND(atgep, ATGE_PEX_UNC_ERR_SEV,
		    ~(PEX_UNC_ERR_SEV_UC | PEX_UNC_ERR_SEV_FCP));
		OUTL_AND(atgep, ATGE_LTSSM_ID_CFG, ~LTSSM_ID_WRO_ENB);
		OUTL_OR(atgep, ATGE_PCIE_PHYMISC, PCIE_PHYMISC_FORCE_RCV_DET);
		break;
	}

	/*
	 * Allocate DMA resources.
	 */
	err = atge_alloc_dma(atgep);
	if (err != DDI_SUCCESS) {
		atge_error(devinfo, "Failed to allocate DMA resources");
		goto fail4;
	}

	/*
	 * Get station address.
	 */
	(void) atge_get_macaddr(atgep);

	/*
	 * Setup MII.
	 */
	switch (ATGE_MODEL(atgep)) {
	case ATGE_CHIP_L1E:
		mii_ops = &atge_l1e_mii_ops;
		break;
	case ATGE_CHIP_L1:
		mii_ops = &atge_l1_mii_ops;
		break;
	case ATGE_CHIP_L1C:
		mii_ops = &atge_l1c_mii_ops;
		break;
	}

	if ((atgep->atge_mii = mii_alloc(atgep, devinfo,
	    mii_ops)) == NULL) {
		atge_error(devinfo, "mii_alloc() failed");
		goto fail4;
	}

	/*
	 * Register with MAC layer.
	 */
	if ((macreg = mac_alloc(MAC_VERSION)) == NULL) {
		atge_error(devinfo, "mac_alloc() failed due to version");
		goto fail4;
	}

	macreg->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macreg->m_driver = atgep;
	macreg->m_dip = devinfo;
	macreg->m_instance = instance;
	macreg->m_src_addr = atgep->atge_ether_addr;
	macreg->m_callbacks = &atge_m_callbacks;
	macreg->m_min_sdu = 0;
	macreg->m_max_sdu = atgep->atge_mtu;
	macreg->m_margin = VLAN_TAGSZ;

	if ((err = mac_register(macreg, &atgep->atge_mh)) != 0) {
		atge_error(devinfo, "mac_register() failed with :%d", err);
		mac_free(macreg);
		goto fail4;
	}

	mac_free(macreg);

	ATGE_DB(("%s: %s() driver attached successfully",
	    atgep->atge_name, __func__));

	atge_device_reset(atgep);

	atgep->atge_chip_state = ATGE_CHIP_INITIALIZED;

	/*
	 * At last - enable interrupts.
	 */
	err = atge_enable_intrs(atgep);
	if (err == DDI_FAILURE) {
		goto fail5;
	}

	/*
	 * Reset the PHY before starting.
	 */
	switch (ATGE_MODEL(atgep)) {
	case ATGE_CHIP_L1E:
		atge_l1e_mii_reset(atgep);
		break;
	case ATGE_CHIP_L1:
		atge_l1_mii_reset(atgep);
		break;
	case ATGE_CHIP_L1C:
		atge_l1c_mii_reset(atgep);
		break;
	}

	/*
	 * Let the PHY run.
	 */
	mii_start(atgep->atge_mii);

	return (DDI_SUCCESS);

fail5:
	(void) mac_unregister(atgep->atge_mh);
	atge_device_stop(atgep);
	mii_stop(atgep->atge_mii);
	mii_free(atgep->atge_mii);
fail4:
	atge_free_dma(atgep);
	mutex_destroy(&atgep->atge_intr_lock);
	mutex_destroy(&atgep->atge_tx_lock);
	mutex_destroy(&atgep->atge_rx_lock);
	atge_remove_intr(atgep);
fail3:
	ddi_regs_map_free(&atgep->atge_io_handle);
fail2:
	pci_config_teardown(&atgep->atge_conf_handle);
fail1:
	kmem_free(atgep, sizeof (atge_t));
	return (DDI_FAILURE);
}

static int
atge_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	atge_t	*atgep;

	atgep = ddi_get_driver_private(dip);
	if (atgep == NULL) {
		atge_error(dip, "No soft state in detach");
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_DETACH:

		/*
		 * First unregister with MAC layer before stopping DMA
		 */
		if (mac_disable(atgep->atge_mh) != DDI_SUCCESS)
			return (DDI_FAILURE);

		mii_stop(atgep->atge_mii);

		mutex_enter(&atgep->atge_intr_lock);
		mutex_enter(&atgep->atge_tx_lock);
		atge_device_stop(atgep);
		mutex_exit(&atgep->atge_tx_lock);
		mutex_exit(&atgep->atge_intr_lock);

		mii_free(atgep->atge_mii);
		atge_free_dma(atgep);

		ddi_regs_map_free(&atgep->atge_io_handle);
		atge_remove_intr(atgep);
		pci_config_teardown(&atgep->atge_conf_handle);

		(void) mac_unregister(atgep->atge_mh);
		mutex_destroy(&atgep->atge_intr_lock);
		mutex_destroy(&atgep->atge_tx_lock);
		mutex_destroy(&atgep->atge_rx_lock);
		kmem_free(atgep, sizeof (atge_t));
		ddi_set_driver_private(dip, NULL);

		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		ATGE_DB(("%s: %s() is being suspended",
		    atgep->atge_name, __func__));

		/*
		 * Suspend monitoring MII.
		 */
		mii_suspend(atgep->atge_mii);

		mutex_enter(&atgep->atge_intr_lock);
		mutex_enter(&atgep->atge_tx_lock);
		atgep->atge_chip_state |= ATGE_CHIP_SUSPENDED;
		atge_device_stop(atgep);
		mutex_exit(&atgep->atge_tx_lock);
		mutex_exit(&atgep->atge_intr_lock);

		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

int
atge_alloc_buffers(atge_ring_t *r, size_t rcnt, size_t buflen, int f)
{
	atge_dma_t *dma;
	atge_dma_t **tbl;
	int err = DDI_SUCCESS;
	int i;

	tbl = kmem_zalloc(rcnt * sizeof (atge_dma_t *), KM_SLEEP);
	r->r_buf_tbl = tbl;

	for (i = 0; i < rcnt; i++) {
		dma = atge_buf_alloc(r->r_atge, buflen, f);
		if (dma == NULL) {
			err = DDI_FAILURE;
			break;
		}

		tbl[i] = dma;
	}

	return (err);
}

void
atge_free_buffers(atge_ring_t *r, size_t rcnt)
{
	atge_dma_t **tbl;
	int i;

	if (r == NULL || r->r_buf_tbl == NULL)
		return;

	tbl = r->r_buf_tbl;
	for (i = 0; i < rcnt; i++)  {
		if (tbl[i] != NULL) {
			atge_buf_free(tbl[i]);
		}
	}

	kmem_free(tbl, rcnt * sizeof (atge_dma_t *));
}

atge_dma_t *
atge_alloc_a_dma_blk(atge_t *atgep, ddi_dma_attr_t *attr, int size, int d)
{
	int err;
	atge_dma_t *dma;

	dma = kmem_zalloc(sizeof (atge_dma_t), KM_SLEEP);

	err = ddi_dma_alloc_handle(atgep->atge_dip, attr,
	    DDI_DMA_SLEEP, NULL, &dma->hdl);

	if (err != DDI_SUCCESS) {
		atge_error(atgep->atge_dip, "%s() : failed"
		    " in ddi_dma_alloc_handle() : %d", __func__, err);
		goto fail;
	}

	err = ddi_dma_mem_alloc(dma->hdl,
	    size, &atge_buf_attr, DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    &dma->addr, &dma->len, &dma->acchdl);

	if (err != DDI_SUCCESS) {
		atge_error(atgep->atge_dip, "%s() : failed"
		    " in ddi_dma_mem_alloc() : %d", __func__, err);
		ddi_dma_free_handle(&dma->hdl);
		goto fail;
	}

	err = ddi_dma_addr_bind_handle(dma->hdl, NULL, dma->addr,
	    dma->len, d | DDI_DMA_CONSISTENT, DDI_DMA_SLEEP,
	    NULL, &dma->cookie, &dma->count);

	if (err != DDI_SUCCESS) {
		atge_error(atgep->atge_dip, "%s() : failed"
		    " in ddi_dma_addr_bind_handle() : %d", __func__, err);
		ddi_dma_mem_free(&dma->acchdl);
		ddi_dma_free_handle(&dma->hdl);
		goto fail;
	}

	return (dma);
fail:
	kmem_free(dma, sizeof (atge_dma_t));
	return (NULL);
}

void
atge_free_a_dma_blk(atge_dma_t *dma)
{
	if (dma != NULL) {
		(void) ddi_dma_unbind_handle(dma->hdl);
		ddi_dma_mem_free(&dma->acchdl);
		ddi_dma_free_handle(&dma->hdl);
		kmem_free(dma, sizeof (atge_dma_t));
	}
}

atge_dma_t *
atge_buf_alloc(atge_t *atgep, size_t len, int f)
{
	atge_dma_t *dma = NULL;
	int err;

	dma = kmem_zalloc(sizeof (atge_dma_t), KM_SLEEP);

	err = ddi_dma_alloc_handle(atgep->atge_dip, &atge_dma_attr_buf,
	    DDI_DMA_SLEEP, NULL, &dma->hdl);

	if (err != DDI_SUCCESS) {
		atge_error(atgep->atge_dip, "%s() : failed"
		    " in %s() : %d", __func__, err);
		goto fail;
	}

	err = ddi_dma_mem_alloc(dma->hdl, len, &atge_buf_attr,
	    DDI_DMA_STREAMING, DDI_DMA_SLEEP, NULL, &dma->addr,
	    &dma->len, &dma->acchdl);

	if (err != DDI_SUCCESS) {
		atge_error(atgep->atge_dip, "%s() : failed"
		    " in %s() : %d", __func__, err);
		ddi_dma_free_handle(&dma->hdl);
		goto fail;
	}

	err = ddi_dma_addr_bind_handle(dma->hdl, NULL, dma->addr, dma->len,
	    (f | DDI_DMA_CONSISTENT), DDI_DMA_SLEEP, NULL, &dma->cookie,
	    &dma->count);

	if (err != DDI_SUCCESS) {
		atge_error(atgep->atge_dip, "%s() : failed"
		    " in %s() : %d", __func__, err);
		ddi_dma_mem_free(&dma->acchdl);
		ddi_dma_free_handle(&dma->hdl);
		goto fail;
	}

	/*
	 * Number of return'ed cookie should be one.
	 */
	ASSERT(dma->count == 1);

	return (dma);
fail:
	kmem_free(dma, sizeof (atge_dma_t));
	return (NULL);
}

void
atge_buf_free(atge_dma_t *dma)
{
	ASSERT(dma != NULL);

	(void) ddi_dma_unbind_handle(dma->hdl);
	ddi_dma_mem_free(&dma->acchdl);
	ddi_dma_free_handle(&dma->hdl);
	kmem_free(dma, sizeof (atge_dma_t));
}

static int
atge_resume(dev_info_t *dip)
{
	atge_t	*atgep;

	if ((atgep = ddi_get_driver_private(dip)) == NULL) {
		return (DDI_FAILURE);
	}

	mutex_enter(&atgep->atge_intr_lock);
	mutex_enter(&atgep->atge_tx_lock);

	atgep->atge_chip_state &= ~ATGE_CHIP_SUSPENDED;

	if (atgep->atge_chip_state & ATGE_CHIP_RUNNING) {
		atge_device_restart(atgep);
	} else {
		atge_device_reset(atgep);
	}

	mutex_exit(&atgep->atge_tx_lock);
	mutex_exit(&atgep->atge_intr_lock);

	/*
	 * Reset the PHY before resuming MII.
	 */
	switch (ATGE_MODEL(atgep)) {
	case ATGE_CHIP_L1E:
		atge_l1e_mii_reset(atgep);
		break;
	case ATGE_CHIP_L1:
		break;
	case ATGE_CHIP_L1C:
		break;
	}

	mii_resume(atgep->atge_mii);

	/* kick-off downstream */
	mac_tx_update(atgep->atge_mh);

	return (DDI_SUCCESS);
}

static int
atge_quiesce(dev_info_t *dip)
{
	atge_t	*atgep;

	if ((atgep = ddi_get_driver_private(dip)) == NULL) {
		return (DDI_FAILURE);
	}

	atge_device_stop(atgep);

	return (DDI_SUCCESS);
}

void
atge_add_multicst(atge_t *atgep, uint8_t *macaddr)
{
	uint32_t crc;
	int bit;

	ASSERT(MUTEX_HELD(&atgep->atge_intr_lock));
	ASSERT(MUTEX_HELD(&atgep->atge_tx_lock));

	ATGE_DB(("%s: %s() %x:%x:%x:%x:%x:%x",
	    atgep->atge_name, __func__, macaddr[0], macaddr[1], macaddr[2],
	    macaddr[3], macaddr[4], macaddr[5]));

	crc = atge_ether_crc(macaddr, ETHERADDRL);
	bit = (crc >> 26);
	atgep->atge_mchash_ref_cnt[bit]++;
	atgep->atge_mchash |= (1ULL << (crc >> 26));

	ATGE_DB(("%s: %s() mchash :%llx, bit : %d,"
	    " atge_mchash_ref_cnt[bit] :%d",
	    atgep->atge_name, __func__, atgep->atge_mchash, bit,
	    atgep->atge_mchash_ref_cnt[bit]));
}

void
atge_remove_multicst(atge_t *atgep, uint8_t *macaddr)
{
	uint32_t crc;
	int bit;

	ASSERT(MUTEX_HELD(&atgep->atge_intr_lock));
	ASSERT(MUTEX_HELD(&atgep->atge_tx_lock));

	ATGE_DB(("%s: %s() %x:%x:%x:%x:%x:%x",
	    atgep->atge_name, __func__, macaddr[0], macaddr[1], macaddr[2],
	    macaddr[3], macaddr[4], macaddr[5]));

	crc = atge_ether_crc(macaddr, ETHERADDRL);
	bit = (crc >> 26);
	atgep->atge_mchash_ref_cnt[bit]--;
	if (atgep->atge_mchash_ref_cnt[bit] == 0)
		atgep->atge_mchash &= ~(1ULL << (crc >> 26));

	ATGE_DB(("%s: %s() mchash :%llx, bit : %d,"
	    " atge_mchash_ref_cnt[bit] :%d",
	    atgep->atge_name, __func__, atgep->atge_mchash, bit,
	    atgep->atge_mchash_ref_cnt[bit]));
}

int
atge_m_multicst(void *arg, boolean_t add, const uint8_t *macaddr)
{
	atge_t *atgep = arg;

	mutex_enter(&atgep->atge_intr_lock);
	mutex_enter(&atgep->atge_tx_lock);

	if (add) {
		atge_add_multicst(atgep, (uint8_t *)macaddr);
	} else {
		atge_remove_multicst(atgep, (uint8_t *)macaddr);
	}

	atge_rxfilter(atgep);

	mutex_exit(&atgep->atge_tx_lock);
	mutex_exit(&atgep->atge_intr_lock);

	return (0);
}

int
atge_m_promisc(void *arg, boolean_t on)
{
	atge_t *atgep = arg;

	mutex_enter(&atgep->atge_intr_lock);
	mutex_enter(&atgep->atge_tx_lock);

	if (on) {
		atgep->atge_filter_flags |= ATGE_PROMISC;
	} else {
		atgep->atge_filter_flags &= ~ATGE_PROMISC;
	}

	if (atgep->atge_chip_state & ATGE_CHIP_RUNNING) {
		atge_rxfilter(atgep);
	}

	mutex_exit(&atgep->atge_tx_lock);
	mutex_exit(&atgep->atge_intr_lock);

	return (0);
}

int
atge_m_unicst(void *arg, const uint8_t *macaddr)
{
	atge_t *atgep = arg;

	mutex_enter(&atgep->atge_intr_lock);
	mutex_enter(&atgep->atge_tx_lock);
	bcopy(macaddr, atgep->atge_ether_addr, ETHERADDRL);
	atge_program_ether(atgep);
	atge_rxfilter(atgep);
	mutex_exit(&atgep->atge_tx_lock);
	mutex_exit(&atgep->atge_intr_lock);

	return (0);
}

mblk_t *
atge_m_tx(void *arg, mblk_t *mp)
{
	atge_t *atgep = arg;
	mblk_t	*nmp;

	mutex_enter(&atgep->atge_tx_lock);

	/*
	 * This NIC does not like us to send pkt when link is down.
	 */
	if (!(atgep->atge_link_state & LINK_STATE_UP)) {
		atgep->atge_tx_resched = 1;

		mutex_exit(&atgep->atge_tx_lock);
		return (mp);
	}

	/*
	 * Don't send a pkt if chip isn't running or in suspended state.
	 */
	if ((atgep->atge_chip_state & ATGE_CHIP_RUNNING) == 0 ||
	    atgep->atge_chip_state & ATGE_CHIP_SUSPENDED) {
		atgep->atge_carrier_errors++;
		atgep->atge_tx_resched = 1;

		mutex_exit(&atgep->atge_tx_lock);
		return (mp);
	}

	while (mp != NULL) {
		nmp = mp->b_next;
		mp->b_next = NULL;

		if (atge_send_a_packet(atgep, mp) == DDI_FAILURE) {
			mp->b_next = nmp;
			break;
		}

		mp = nmp;
	}

	mutex_exit(&atgep->atge_tx_lock);
	return (mp);
}

int
atge_m_start(void *arg)
{
	atge_t *atgep = arg;
	int started = 0;

	ASSERT(atgep != NULL);


	mii_stop(atgep->atge_mii);

	mutex_enter(&atgep->atge_intr_lock);
	mutex_enter(&atgep->atge_tx_lock);

	if (!(atgep->atge_chip_state & ATGE_CHIP_SUSPENDED)) {
		atge_device_restart(atgep);
		started = 1;
	}

	mutex_exit(&atgep->atge_tx_lock);
	mutex_exit(&atgep->atge_intr_lock);

	mii_start(atgep->atge_mii);

	/* kick-off downstream */
	if (started)
		mac_tx_update(atgep->atge_mh);

	return (0);
}

void
atge_m_stop(void *arg)
{
	atge_t *atgep = arg;

	mii_stop(atgep->atge_mii);

	/*
	 * Cancel any pending I/O.
	 */
	mutex_enter(&atgep->atge_intr_lock);
	atgep->atge_chip_state &= ~ATGE_CHIP_RUNNING;
	if (!(atgep->atge_chip_state & ATGE_CHIP_SUSPENDED))
		atge_device_stop(atgep);
	mutex_exit(&atgep->atge_intr_lock);
}

int
atge_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	atge_t *atgep = arg;

	if (mii_m_getstat(atgep->atge_mii, stat, val) == 0) {
		return (0);
	}

	switch (stat) {
	case MAC_STAT_MULTIRCV:
		*val = atgep->atge_multircv;
		break;

	case MAC_STAT_BRDCSTRCV:
		*val = atgep->atge_brdcstrcv;
		break;

	case MAC_STAT_MULTIXMT:
		*val = atgep->atge_multixmt;
		break;

	case MAC_STAT_BRDCSTXMT:
		*val = atgep->atge_brdcstxmt;
		break;

	case MAC_STAT_IPACKETS:
		*val = atgep->atge_ipackets;
		break;

	case MAC_STAT_RBYTES:
		*val = atgep->atge_rbytes;
		break;

	case MAC_STAT_OPACKETS:
		*val = atgep->atge_opackets;
		break;

	case MAC_STAT_OBYTES:
		*val = atgep->atge_obytes;
		break;

	case MAC_STAT_NORCVBUF:
		*val = atgep->atge_norcvbuf;
		break;

	case MAC_STAT_NOXMTBUF:
		*val = 0;
		break;

	case MAC_STAT_COLLISIONS:
		*val = atgep->atge_collisions;
		break;

	case MAC_STAT_IERRORS:
		*val = atgep->atge_errrcv;
		break;

	case MAC_STAT_OERRORS:
		*val = atgep->atge_errxmt;
		break;

	case ETHER_STAT_ALIGN_ERRORS:
		*val = atgep->atge_align_errors;
		break;

	case ETHER_STAT_FCS_ERRORS:
		*val = atgep->atge_fcs_errors;
		break;

	case ETHER_STAT_SQE_ERRORS:
		*val = atgep->atge_sqe_errors;
		break;

	case ETHER_STAT_DEFER_XMTS:
		*val = atgep->atge_defer_xmts;
		break;

	case ETHER_STAT_FIRST_COLLISIONS:
		*val = atgep->atge_first_collisions;
		break;

	case ETHER_STAT_MULTI_COLLISIONS:
		*val = atgep->atge_multi_collisions;
		break;

	case ETHER_STAT_TX_LATE_COLLISIONS:
		*val = atgep->atge_tx_late_collisions;
		break;

	case ETHER_STAT_EX_COLLISIONS:
		*val = atgep->atge_ex_collisions;
		break;

	case ETHER_STAT_MACXMT_ERRORS:
		*val = atgep->atge_macxmt_errors;
		break;

	case ETHER_STAT_CARRIER_ERRORS:
		*val = atgep->atge_carrier_errors;
		break;

	case ETHER_STAT_TOOLONG_ERRORS:
		*val = atgep->atge_toolong_errors;
		break;

	case ETHER_STAT_MACRCV_ERRORS:
		*val = atgep->atge_macrcv_errors;
		break;

	case MAC_STAT_OVERFLOWS:
		*val = atgep->atge_overflow;
		break;

	case MAC_STAT_UNDERFLOWS:
		*val = atgep->atge_underflow;
		break;

	case ETHER_STAT_TOOSHORT_ERRORS:
		*val = atgep->atge_runt;
		break;

	case ETHER_STAT_JABBER_ERRORS:
		*val = atgep->atge_jabber;
		break;

	default:
		return (ENOTSUP);
	}

	return (0);
}

int
atge_m_getprop(void *arg, const char *name, mac_prop_id_t num, uint_t sz,
    void *val)
{
	atge_t *atgep = arg;

	return (mii_m_getprop(atgep->atge_mii, name, num, sz, val));
}

int
atge_m_setprop(void *arg, const char *name, mac_prop_id_t num, uint_t sz,
    const void *val)
{
	atge_t *atgep = arg;
	int r;

	r = mii_m_setprop(atgep->atge_mii, name, num, sz, val);

	if (r == 0) {
		mutex_enter(&atgep->atge_intr_lock);
		mutex_enter(&atgep->atge_tx_lock);

		if (atgep->atge_chip_state & ATGE_CHIP_RUNNING) {
			atge_device_restart(atgep);
		}

		mutex_exit(&atgep->atge_tx_lock);
		mutex_exit(&atgep->atge_intr_lock);
	}

	return (r);
}

static void
atge_m_propinfo(void *arg, const char *name, mac_prop_id_t num,
    mac_prop_info_handle_t prh)
{
	atge_t *atgep = arg;

	mii_m_propinfo(atgep->atge_mii, name, num, prh);
}

void
atge_program_ether(atge_t *atgep)
{
	ether_addr_t e;

	/*
	 * Reprogram the Station address.
	 */
	bcopy(atgep->atge_ether_addr, e, ETHERADDRL);
	OUTL(atgep, ATGE_PAR0,
	    ((e[2] << 24) | (e[3] << 16) | (e[4] << 8) | e[5]));
	OUTL(atgep, ATGE_PAR1, (e[0] << 8) | e[1]);
}

/*
 * Device specific operations.
 */
void
atge_device_start(atge_t *atgep)
{
	uint32_t rxf_hi, rxf_lo, rrd_hi, rrd_lo;
	uint32_t reg;
	uint32_t fsize;

	/*
	 * Reprogram the Station address.
	 */
	atge_program_ether(atgep);

	switch (ATGE_MODEL(atgep)) {
	case ATGE_CHIP_L1E:
		atge_l1e_program_dma(atgep);
		break;
	case ATGE_CHIP_L1:
		atge_l1_program_dma(atgep);
		break;
	case ATGE_CHIP_L1C:
		atge_l1c_program_dma(atgep);
		break;
	}

	ATGE_DB(("%s: %s() dma, counters programmed ", atgep->atge_name,
	    __func__));

	switch (ATGE_MODEL(atgep)) {
	case ATGE_CHIP_L1E:
	case ATGE_CHIP_L1:
		OUTW(atgep, ATGE_INTR_CLR_TIMER, 1*1000/2);
		break;
	case ATGE_CHIP_L1C:
		/*
		 * Disable interrupt re-trigger timer. We don't want automatic
		 * re-triggering of un-ACKed interrupts.
		 */
		OUTL(atgep, ATGE_INTR_RETRIG_TIMER, ATGE_USECS(0));
		/* Configure CMB. */
		OUTL(atgep, ATGE_CMB_TX_TIMER, ATGE_USECS(0));
		/*
		 * Hardware can be configured to issue SMB interrupt based
		 * on programmed interval. Since there is a callout that is
		 * invoked for every hz in driver we use that instead of
		 * relying on periodic SMB interrupt.
		 */
		OUTL(atgep, ATGE_SMB_STAT_TIMER, ATGE_USECS(0));
		/* Clear MAC statistics. */
		atge_l1c_clear_stats(atgep);
		break;
	}

	/*
	 * Set Maximum frame size but don't let MTU be less than ETHER_MTU.
	 */
	if (atgep->atge_mtu < ETHERMTU)
		atgep->atge_max_frame_size = ETHERMTU;
	else
		atgep->atge_max_frame_size = atgep->atge_mtu;

	atgep->atge_max_frame_size += sizeof (struct ether_header) +
	    VLAN_TAGSZ + ETHERFCSL;
	OUTL(atgep, ATGE_FRAME_SIZE, atgep->atge_max_frame_size);

	switch (ATGE_MODEL(atgep)) {
	case ATGE_CHIP_L1E:
		break;
	case ATGE_CHIP_L1:
		break;
	case ATGE_CHIP_L1C:
		/* Disable header split(?) */
		OUTL(atgep, ATGE_HDS_CFG, 0);
		break;
	}

	/*
	 * Configure IPG/IFG parameters.
	 */
	OUTL(atgep, ATGE_IPG_IFG_CFG,
	    ((IPG_IFG_IPG2_DEFAULT << IPG_IFG_IPG2_SHIFT) & IPG_IFG_IPG2_MASK) |
	    ((IPG_IFG_IPG1_DEFAULT << IPG_IFG_IPG1_SHIFT) & IPG_IFG_IPG1_MASK) |
	    ((IPG_IFG_MIFG_DEFAULT << IPG_IFG_MIFG_SHIFT) & IPG_IFG_MIFG_MASK) |
	    ((IPG_IFG_IPGT_DEFAULT << IPG_IFG_IPGT_SHIFT) & IPG_IFG_IPGT_MASK));

	/*
	 * Set parameters for half-duplex media.
	 */
	OUTL(atgep, ATGE_HDPX_CFG,
	    ((HDPX_CFG_LCOL_DEFAULT << HDPX_CFG_LCOL_SHIFT) &
	    HDPX_CFG_LCOL_MASK) |
	    ((HDPX_CFG_RETRY_DEFAULT << HDPX_CFG_RETRY_SHIFT) &
	    HDPX_CFG_RETRY_MASK) | HDPX_CFG_EXC_DEF_EN |
	    ((HDPX_CFG_ABEBT_DEFAULT << HDPX_CFG_ABEBT_SHIFT) &
	    HDPX_CFG_ABEBT_MASK) |
	    ((HDPX_CFG_JAMIPG_DEFAULT << HDPX_CFG_JAMIPG_SHIFT) &
	    HDPX_CFG_JAMIPG_MASK));

	/*
	 * Configure jumbo frame.
	 */
	switch (ATGE_MODEL(atgep)) {
	case ATGE_CHIP_L1E:
		if (atgep->atge_flags & ATGE_FLAG_JUMBO) {

			if (atgep->atge_mtu < ETHERMTU)
				reg = atgep->atge_max_frame_size;
			else if (atgep->atge_mtu < 6 * 1024)
				reg = (atgep->atge_max_frame_size * 2) / 3;
			else
				reg = atgep->atge_max_frame_size / 2;

			OUTL(atgep, L1E_TX_JUMBO_THRESH,
			    ROUNDUP(reg, TX_JUMBO_THRESH_UNIT) >>
			    TX_JUMBO_THRESH_UNIT_SHIFT);
		}
		break;
	case ATGE_CHIP_L1:
		fsize = ROUNDUP(atgep->atge_max_frame_size, sizeof (uint64_t));
		OUTL(atgep, ATGE_RXQ_JUMBO_CFG,
		    (((fsize / sizeof (uint64_t)) <<
		    RXQ_JUMBO_CFG_SZ_THRESH_SHIFT) &
		    RXQ_JUMBO_CFG_SZ_THRESH_MASK) |
		    ((RXQ_JUMBO_CFG_LKAH_DEFAULT <<
		    RXQ_JUMBO_CFG_LKAH_SHIFT) & RXQ_JUMBO_CFG_LKAH_MASK) |
		    ((ATGE_USECS(8) << RXQ_JUMBO_CFG_RRD_TIMER_SHIFT) &
		    RXQ_JUMBO_CFG_RRD_TIMER_MASK));
		break;
	case ATGE_CHIP_L1C:
		break;
	}

	/*
	 * Configure flow-control parameters.
	 */
	switch (ATGE_MODEL(atgep)) {
	case ATGE_CHIP_L1E:
	case ATGE_CHIP_L1:
		if ((atgep->atge_flags & ATGE_FLAG_PCIE) != 0) {
		/*
		 * Some hardware version require this magic.
		 */
		OUTL(atgep, ATGE_LTSSM_ID_CFG, 0x6500);
		reg = INL(atgep, 0x1008);
		OUTL(atgep, 0x1008, reg | 0x8000);
		}
		break;
	case ATGE_CHIP_L1C:
		break;
	}

	/*
	 * These are all magic parameters which came from FreeBSD.
	 */
	switch (ATGE_MODEL(atgep)) {
	case ATGE_CHIP_L1E:
		reg = INL(atgep, L1E_SRAM_RX_FIFO_LEN);
		rxf_hi = (reg * 4) / 5;
		rxf_lo = reg/ 5;

		OUTL(atgep, ATGE_RXQ_FIFO_PAUSE_THRESH,
		    ((rxf_lo << RXQ_FIFO_PAUSE_THRESH_LO_SHIFT) &
		    RXQ_FIFO_PAUSE_THRESH_LO_MASK) |
		    ((rxf_hi << RXQ_FIFO_PAUSE_THRESH_HI_SHIFT) &
		    RXQ_FIFO_PAUSE_THRESH_HI_MASK));
		break;
	case ATGE_CHIP_L1:
		switch (atgep->atge_chip_rev) {
		case 0x8001:
		case 0x9001:
		case 0x9002:
		case 0x9003:
			rxf_hi = L1_RX_RING_CNT / 16;
			rxf_lo = (L1_RX_RING_CNT * 7) / 8;
			rrd_hi = (L1_RR_RING_CNT * 7) / 8;
			rrd_lo = L1_RR_RING_CNT / 16;
			break;
		default:
			reg = INL(atgep, L1_SRAM_RX_FIFO_LEN);
			rxf_lo = reg / 16;
			if (rxf_lo > 192)
				rxf_lo = 192;
			rxf_hi = (reg * 7) / 8;
			if (rxf_hi < rxf_lo)
				rxf_hi = rxf_lo + 16;
			reg = INL(atgep, L1_SRAM_RRD_LEN);
			rrd_lo = reg / 8;
			rrd_hi = (reg * 7) / 8;
			if (rrd_lo > 2)
				rrd_lo = 2;
			if (rrd_hi < rrd_lo)
				rrd_hi = rrd_lo + 3;
			break;
		}

		OUTL(atgep, ATGE_RXQ_FIFO_PAUSE_THRESH,
		    ((rxf_lo << RXQ_FIFO_PAUSE_THRESH_LO_SHIFT) &
		    RXQ_FIFO_PAUSE_THRESH_LO_MASK) |
		    ((rxf_hi << RXQ_FIFO_PAUSE_THRESH_HI_SHIFT) &
		    RXQ_FIFO_PAUSE_THRESH_HI_MASK));

		OUTL(atgep, L1_RXQ_RRD_PAUSE_THRESH,
		    ((rrd_lo << RXQ_RRD_PAUSE_THRESH_LO_SHIFT) &
		    RXQ_RRD_PAUSE_THRESH_LO_MASK) |
		    ((rrd_hi << RXQ_RRD_PAUSE_THRESH_HI_SHIFT) &
		    RXQ_RRD_PAUSE_THRESH_HI_MASK));
		break;
	case ATGE_CHIP_L1C:
		switch (ATGE_DID(atgep)) {
		case ATGE_CHIP_AR8151V2_DEV_ID:
		case ATGE_CHIP_AR8152V1_DEV_ID:
			OUTL(atgep, ATGE_SERDES_LOCK,
			    INL(atgep, ATGE_SERDES_LOCK) |
			    SERDES_MAC_CLK_SLOWDOWN |
			    SERDES_PHY_CLK_SLOWDOWN);
			break;
		case ATGE_CHIP_L1CG_DEV_ID:
		case ATGE_CHIP_L1CF_DEV_ID:
			/*
			 * Configure flow control parameters.
			 * XON	: 80% of Rx FIFO
			 * XOFF : 30% of Rx FIFO
			 */
			reg = INL(atgep, L1C_SRAM_RX_FIFO_LEN);
			rxf_hi = (reg * 8) / 10;
			rxf_lo = (reg * 3) / 10;

			OUTL(atgep, ATGE_RXQ_FIFO_PAUSE_THRESH,
			    ((rxf_lo << RXQ_FIFO_PAUSE_THRESH_LO_SHIFT) &
			    RXQ_FIFO_PAUSE_THRESH_LO_MASK) |
			    ((rxf_hi << RXQ_FIFO_PAUSE_THRESH_HI_SHIFT) &
			    RXQ_FIFO_PAUSE_THRESH_HI_MASK));
			break;
		}
		break;
	}

	switch (ATGE_MODEL(atgep)) {
	case ATGE_CHIP_L1E:
		/* Configure RxQ. */
		reg = RXQ_CFG_ALIGN_32 | RXQ_CFG_CUT_THROUGH_ENB |
		    RXQ_CFG_IPV6_CSUM_VERIFY | RXQ_CFG_ENB;
		OUTL(atgep, ATGE_RXQ_CFG, reg);
		/*
		 * Configure TxQ.
		 */
		reg = (128 <<
		    (atgep->atge_dma_rd_burst >> DMA_CFG_RD_BURST_SHIFT)) <<
		    TXQ_CFG_TX_FIFO_BURST_SHIFT;

		reg |= (TXQ_CFG_TPD_BURST_DEFAULT << TXQ_CFG_TPD_BURST_SHIFT) &
		    TXQ_CFG_TPD_BURST_MASK;

		reg |= TXQ_CFG_ENHANCED_MODE | TXQ_CFG_ENB;

		OUTL(atgep, ATGE_TXQ_CFG, reg);
		/* Disable RSS. */
		OUTL(atgep, L1E_RSS_IDT_TABLE0, 0);
		OUTL(atgep, L1E_RSS_CPU, 0);
		/*
		 * Configure DMA parameters.
		 */
		/*
		 * Don't use Tx CMB. It is known to cause RRS update failure
		 * under certain circumstances. Typical phenomenon of the
		 * issue would be unexpected sequence number encountered in
		 * Rx handler. Hence we don't set DMA_CFG_TXCMB_ENB.
		 */
		OUTL(atgep, ATGE_DMA_CFG,
		    DMA_CFG_OUT_ORDER | DMA_CFG_RD_REQ_PRI | DMA_CFG_RCB_64 |
		    atgep->atge_dma_rd_burst | atgep->atge_dma_wr_burst |
		    DMA_CFG_RXCMB_ENB |
		    ((DMA_CFG_RD_DELAY_CNT_DEFAULT <<
		    DMA_CFG_RD_DELAY_CNT_SHIFT) & DMA_CFG_RD_DELAY_CNT_MASK) |
		    ((DMA_CFG_WR_DELAY_CNT_DEFAULT <<
		    DMA_CFG_WR_DELAY_CNT_SHIFT) & DMA_CFG_WR_DELAY_CNT_MASK));
		/*
		 * Enable CMB/SMB timer.
		 */
		OUTL(atgep, L1E_SMB_STAT_TIMER, 100000);
		atge_l1e_clear_stats(atgep);
		break;
	case ATGE_CHIP_L1:
		/* Configure RxQ. */
		reg =
		    ((RXQ_CFG_RD_BURST_DEFAULT << RXQ_CFG_RD_BURST_SHIFT) &
		    RXQ_CFG_RD_BURST_MASK) |
		    ((RXQ_CFG_RRD_BURST_THRESH_DEFAULT <<
		    RXQ_CFG_RRD_BURST_THRESH_SHIFT) &
		    RXQ_CFG_RRD_BURST_THRESH_MASK) |
		    ((RXQ_CFG_RD_PREF_MIN_IPG_DEFAULT <<
		    RXQ_CFG_RD_PREF_MIN_IPG_SHIFT) &
		    RXQ_CFG_RD_PREF_MIN_IPG_MASK) |
		    RXQ_CFG_CUT_THROUGH_ENB | RXQ_CFG_ENB;
		OUTL(atgep, ATGE_RXQ_CFG, reg);
		/*
		 * Configure TxQ.
		 */
		reg =
		    (((TXQ_CFG_TPD_BURST_DEFAULT << TXQ_CFG_TPD_BURST_SHIFT) &
		    TXQ_CFG_TPD_BURST_MASK) |
		    ((TXQ_CFG_TX_FIFO_BURST_DEFAULT <<
		    TXQ_CFG_TX_FIFO_BURST_SHIFT) &
		    TXQ_CFG_TX_FIFO_BURST_MASK) |
		    ((TXQ_CFG_TPD_FETCH_DEFAULT <<
		    TXQ_CFG_TPD_FETCH_THRESH_SHIFT) &
		    TXQ_CFG_TPD_FETCH_THRESH_MASK) |
		    TXQ_CFG_ENB);
		OUTL(atgep, ATGE_TXQ_CFG, reg);
		/* Jumbo frames */
		OUTL(atgep, L1_TX_JUMBO_TPD_TH_IPG,
		    (((fsize / sizeof (uint64_t) << TX_JUMBO_TPD_TH_SHIFT)) &
		    TX_JUMBO_TPD_TH_MASK) |
		    ((TX_JUMBO_TPD_IPG_DEFAULT << TX_JUMBO_TPD_IPG_SHIFT) &
		    TX_JUMBO_TPD_IPG_MASK));
		/*
		 * Configure DMA parameters.
		 */
		OUTL(atgep, ATGE_DMA_CFG,
		    DMA_CFG_ENH_ORDER | DMA_CFG_RCB_64 |
		    atgep->atge_dma_rd_burst | DMA_CFG_RD_ENB |
		    atgep->atge_dma_wr_burst | DMA_CFG_WR_ENB);

		/* Configure CMB DMA write threshold. */
		OUTL(atgep, L1_CMB_WR_THRESH,
		    ((CMB_WR_THRESH_RRD_DEFAULT << CMB_WR_THRESH_RRD_SHIFT) &
		    CMB_WR_THRESH_RRD_MASK) |
		    ((CMB_WR_THRESH_TPD_DEFAULT << CMB_WR_THRESH_TPD_SHIFT) &
		    CMB_WR_THRESH_TPD_MASK));
		/*
		 * Enable CMB/SMB timer.
		 */
		/* Set CMB/SMB timer and enable them. */
		OUTL(atgep, L1_CMB_WR_TIMER,
		    ((ATGE_USECS(2) << CMB_WR_TIMER_TX_SHIFT) &
		    CMB_WR_TIMER_TX_MASK) |
		    ((ATGE_USECS(2) << CMB_WR_TIMER_RX_SHIFT) &
		    CMB_WR_TIMER_RX_MASK));

		/* Request SMB updates for every seconds. */
		OUTL(atgep, L1_SMB_TIMER, ATGE_USECS(1000 * 1000));
		OUTL(atgep, L1_CSMB_CTRL,
		    CSMB_CTRL_SMB_ENB | CSMB_CTRL_CMB_ENB);
		break;
	case ATGE_CHIP_L1C:
		/* Configure RxQ. */
		reg =
		    RXQ_CFG_RD_BURST_DEFAULT << L1C_RXQ_CFG_RD_BURST_SHIFT |
		    RXQ_CFG_IPV6_CSUM_VERIFY | RXQ_CFG_ENB;
		if ((atgep->atge_flags & ATGE_FLAG_ASPM_MON) != 0)
			reg |= RXQ_CFG_ASPM_THROUGHPUT_LIMIT_1M;
		OUTL(atgep, ATGE_RXQ_CFG, reg);
		/*
		 * Configure TxQ.
		 */
		reg = (128 <<
		    (atgep->atge_dma_rd_burst >> DMA_CFG_RD_BURST_SHIFT)) <<
		    TXQ_CFG_TX_FIFO_BURST_SHIFT;

		switch (ATGE_DID(atgep)) {
		case ATGE_CHIP_AR8152V2_DEV_ID:
		case ATGE_CHIP_AR8152V1_DEV_ID:
			reg >>= 1;
			break;
		}

		reg |= (L1C_TXQ_CFG_TPD_BURST_DEFAULT <<
		    TXQ_CFG_TPD_BURST_SHIFT) & TXQ_CFG_TPD_BURST_MASK;

		reg |= TXQ_CFG_ENHANCED_MODE | TXQ_CFG_ENB;

		OUTL(atgep, L1C_TXQ_CFG, reg);
		/* Disable RSS until I understand L1C/L2C's RSS logic. */
		OUTL(atgep, L1C_RSS_IDT_TABLE0, 0xe4e4e4e4);
		OUTL(atgep, L1C_RSS_CPU, 0);
		/*
		 * Configure DMA parameters.
		 */
		OUTL(atgep, ATGE_DMA_CFG,
		    DMA_CFG_SMB_DIS |
		    DMA_CFG_OUT_ORDER | DMA_CFG_RD_REQ_PRI | DMA_CFG_RCB_64 |
		    DMA_CFG_RD_DELAY_CNT_DEFAULT << DMA_CFG_RD_DELAY_CNT_SHIFT |
		    DMA_CFG_WR_DELAY_CNT_DEFAULT << DMA_CFG_WR_DELAY_CNT_SHIFT |

		    atgep->atge_dma_rd_burst | DMA_CFG_RD_ENB |
		    atgep->atge_dma_wr_burst | DMA_CFG_WR_ENB);
		/* Configure CMB DMA write threshold not required. */
		/* Set CMB/SMB timer and enable them not required. */
		break;
	}

	/*
	 * Disable all WOL bits as WOL can interfere normal Rx
	 * operation.
	 */
	OUTL(atgep, ATGE_WOL_CFG, 0);

	/*
	 * Configure Tx/Rx MACs.
	 *  - Auto-padding for short frames.
	 *  - Enable CRC generation.
	 *
	 *  Start with full-duplex/1000Mbps media. Actual reconfiguration
	 *  of MAC is followed after link establishment.
	 */
	reg = (ATGE_CFG_TX_CRC_ENB | ATGE_CFG_TX_AUTO_PAD |
	    ATGE_CFG_FULL_DUPLEX |
	    ((ATGE_CFG_PREAMBLE_DEFAULT << ATGE_CFG_PREAMBLE_SHIFT) &
	    ATGE_CFG_PREAMBLE_MASK));

	/*
	 *  AR813x/AR815x always does checksum computation regardless
	 *  of MAC_CFG_RXCSUM_ENB bit. Also the controller is known to
	 *  have bug in protocol field in Rx return structure so
	 *  these controllers can't handle fragmented frames. Disable
	 *  Rx checksum offloading until there is a newer controller
	 *  that has sane implementation.
	 */
	switch (ATGE_DID(atgep)) {
	case ATGE_CHIP_AR8151V2_DEV_ID:
	case ATGE_CHIP_AR8151V1_DEV_ID:
	case ATGE_CHIP_AR8152V2_DEV_ID:
		reg |= ATGE_CFG_HASH_ALG_CRC32 | ATGE_CFG_SPEED_MODE_SW;
		break;
	}

	if ((atgep->atge_flags & ATGE_FLAG_FASTETHER) != 0) {
		reg |= ATGE_CFG_SPEED_10_100;
		ATGE_DB(("%s: %s() Fast Ethernet", atgep->atge_name, __func__));
	} else {
		reg |= ATGE_CFG_SPEED_1000;
		ATGE_DB(("%s: %s() 1G speed", atgep->atge_name, __func__));
	}
	switch (ATGE_MODEL(atgep)) {
	case ATGE_CHIP_L1C:
		reg |= L1C_CFG_SINGLE_PAUSE_ENB;
		break;
	}

	OUTL(atgep, ATGE_MAC_CFG, reg);

	atgep->atge_chip_state |= ATGE_CHIP_RUNNING;

	/*
	 * Set up the receive filter.
	 */
	atge_rxfilter(atgep);

	/*
	 * Acknowledge all pending interrupts and clear it.
	 */
	switch (ATGE_MODEL(atgep)) {
	case ATGE_CHIP_L1E:
		OUTL(atgep, ATGE_INTR_MASK, L1E_INTRS);
		OUTL(atgep, ATGE_INTR_STATUS, 0xFFFFFFFF);
		OUTL(atgep, ATGE_INTR_STATUS, 0);
		break;
	case ATGE_CHIP_L1:
	case ATGE_CHIP_L1C:
		OUTL(atgep, ATGE_INTR_STATUS, 0);
		OUTL(atgep, ATGE_INTR_MASK, atgep->atge_intrs);
		break;
	}

	atge_mac_config(atgep);

	ATGE_DB(("%s: %s() device started", atgep->atge_name, __func__));
}

/*
 * Generic functions.
 */

#define	CRC32_POLY_BE   0x04c11db7
uint32_t
atge_ether_crc(const uint8_t *addr, int len)
{
	int idx;
	int bit;
	uint_t data;
	uint32_t crc;

	crc = 0xffffffff;
	for (idx = 0; idx < len; idx++) {
		for (data = *addr++, bit = 0; bit < 8; bit++, data >>= 1) {
			crc = (crc << 1)
			    ^ ((((crc >> 31) ^ data) & 1) ? CRC32_POLY_BE : 0);
		}
	}

	return (crc);
}


/*
 * Programs RX filter. We use a link-list to keep track of all multicast
 * addressess.
 */
void
atge_rxfilter(atge_t *atgep)
{
	uint32_t rxcfg;
	uint64_t mchash;

	rxcfg = INL(atgep, ATGE_MAC_CFG);
	rxcfg &= ~(ATGE_CFG_ALLMULTI | ATGE_CFG_PROMISC);

	/*
	 * Accept broadcast frames.
	 */
	rxcfg |= ATGE_CFG_BCAST;

	/*
	 * We don't use Hardware VLAN tagging.
	 */
	rxcfg &= ~ATGE_CFG_VLAN_TAG_STRIP;

	if (atgep->atge_filter_flags & (ATGE_PROMISC | ATGE_ALL_MULTICST)) {
		mchash = ~0ULL;

		if (atgep->atge_filter_flags & ATGE_PROMISC)
			rxcfg |= ATGE_CFG_PROMISC;

		if (atgep->atge_filter_flags & ATGE_ALL_MULTICST)
			rxcfg |= ATGE_CFG_ALLMULTI;
	} else {
		mchash = atgep->atge_mchash;
	}

	atge_program_ether(atgep);

	OUTL(atgep, ATGE_MAR0, (uint32_t)mchash);
	OUTL(atgep, ATGE_MAR1, (uint32_t)(mchash >> 32));
	OUTL(atgep, ATGE_MAC_CFG, rxcfg);

	ATGE_DB(("%s: %s() mac_cfg is : %x, mchash : %llx",
	    atgep->atge_name, __func__, rxcfg, mchash));
}

void
atge_device_stop(atge_t *atgep)
{
	uint32_t reg;
	int t;

	/*
	 * If the chip is being suspended, then don't touch the state. Caller
	 * will take care of setting the correct state.
	 */
	if (!(atgep->atge_chip_state & ATGE_CHIP_SUSPENDED)) {
		atgep->atge_chip_state |= ATGE_CHIP_STOPPED;
		atgep->atge_chip_state &= ~ATGE_CHIP_RUNNING;
	}

	/*
	 * Collect stats for L1E. L1 chip's stats are collected by interrupt.
	 */
	switch (ATGE_MODEL(atgep)) {
	case ATGE_CHIP_L1E:
		atge_l1e_gather_stats(atgep);
		break;
	case ATGE_CHIP_L1:
	case ATGE_CHIP_L1C:
		break;
	}

	/*
	 * Disable interrupts.
	 */
	atge_disable_intrs(atgep);

	switch (ATGE_MODEL(atgep)) {
	case ATGE_CHIP_L1E:
		/* Clear CTRL not required. */
		/* Stop DMA Engine not required. */
		/*
		 * Disable queue processing.
		 */
		/* Stop TxQ */
		reg = INL(atgep, ATGE_TXQ_CFG);
		reg = reg & ~TXQ_CFG_ENB;
		OUTL(atgep, ATGE_TXQ_CFG, reg);
		/* Stop RxQ */
		reg = INL(atgep, ATGE_RXQ_CFG);
		reg = reg & ~RXQ_CFG_ENB;
		OUTL(atgep, ATGE_RXQ_CFG, reg);
		/* Stop DMA */
		reg = INL(atgep, ATGE_DMA_CFG);
		reg = reg & ~(DMA_CFG_TXCMB_ENB | DMA_CFG_RXCMB_ENB);
		OUTL(atgep, ATGE_DMA_CFG, reg);
		drv_usecwait(1000);
		atge_l1e_stop_mac(atgep);
		OUTL(atgep, ATGE_INTR_STATUS, 0xFFFFFFFF);
		break;
	case ATGE_CHIP_L1:
		/* Clear CTRL. */
		OUTL(atgep, L1_CSMB_CTRL, 0);
		/* Stop DMA Engine */
		atge_l1_stop_tx_mac(atgep);
		atge_l1_stop_rx_mac(atgep);
		reg = INL(atgep, ATGE_DMA_CFG);
		reg &= ~(DMA_CFG_RD_ENB | DMA_CFG_WR_ENB);
		OUTL(atgep, ATGE_DMA_CFG, reg);
		/*
		 * Disable queue processing.
		 */
		/* Stop TxQ */
		reg = INL(atgep, ATGE_TXQ_CFG);
		reg = reg & ~TXQ_CFG_ENB;
		OUTL(atgep, ATGE_TXQ_CFG, reg);
		/* Stop RxQ */
		reg = INL(atgep, ATGE_RXQ_CFG);
		reg = reg & ~RXQ_CFG_ENB;
		OUTL(atgep, ATGE_RXQ_CFG, reg);
		break;
	case ATGE_CHIP_L1C:
		/* Clear CTRL not required. */
		/* Stop DMA Engine */
		atge_l1c_stop_tx_mac(atgep);
		atge_l1c_stop_rx_mac(atgep);
		reg = INL(atgep, ATGE_DMA_CFG);
		reg &= ~(DMA_CFG_RD_ENB | DMA_CFG_WR_ENB);
		OUTL(atgep, ATGE_DMA_CFG, reg);
		/*
		 * Disable queue processing.
		 */
		/* Stop TxQ */
		reg = INL(atgep, L1C_TXQ_CFG);
		reg = reg & ~TXQ_CFG_ENB;
		OUTL(atgep, L1C_TXQ_CFG, reg);
		/* Stop RxQ */
		reg = INL(atgep, ATGE_RXQ_CFG);
		reg = reg & ~RXQ_CFG_ENB;
		OUTL(atgep, ATGE_RXQ_CFG, reg);
		break;
	}

	for (t = ATGE_RESET_TIMEOUT; t > 0; t--) {
		if ((reg = INL(atgep, ATGE_IDLE_STATUS)) == 0)
			break;
		drv_usecwait(10);
	}

	if (t == 0) {
		atge_error(atgep->atge_dip, "%s() stopping TX/RX MAC timeout",
		    __func__);
	}
}

void
atge_disable_intrs(atge_t *atgep)
{
	OUTL(atgep, ATGE_INTR_MASK, 0);
	OUTL(atgep, ATGE_INTR_STATUS, 0xFFFFFFFF);
}

void
atge_device_init(atge_t *atgep)
{
	switch (ATGE_MODEL(atgep)) {
	case ATGE_CHIP_L1E:
		atgep->atge_intrs = L1E_INTRS;
		atgep->atge_int_mod = ATGE_IM_TIMER_DEFAULT;

		atge_l1e_init_tx_ring(atgep);
		atge_l1e_init_rx_pages(atgep);
		break;
	case ATGE_CHIP_L1:
		atgep->atge_intrs = L1_INTRS | INTR_GPHY | INTR_PHY_LINK_DOWN |
		    INTR_LINK_CHG;
		atgep->atge_int_mod = ATGE_IM_TIMER_DEFAULT;

		atge_l1_init_tx_ring(atgep);
		atge_l1_init_rx_ring(atgep);
		atge_l1_init_rr_ring(atgep);
		atge_l1_init_cmb(atgep);
		atge_l1_init_smb(atgep);
		break;
	case ATGE_CHIP_L1C:
		atgep->atge_intrs = L1C_INTRS | L1C_INTR_GPHY |
		    L1C_INTR_PHY_LINK_DOWN;
		atgep->atge_int_rx_mod = 400/2;
		atgep->atge_int_tx_mod = 2000/1;

		atge_l1c_init_tx_ring(atgep);
		atge_l1c_init_rx_ring(atgep);
		atge_l1c_init_rr_ring(atgep);
		atge_l1c_init_cmb(atgep);
		atge_l1c_init_smb(atgep);

		/* Enable all clocks. */
		OUTL(atgep, ATGE_CLK_GATING_CFG, 0);
		break;
	}
}

void
atge_device_restart(atge_t *atgep)
{
	ASSERT(MUTEX_HELD(&atgep->atge_intr_lock));
	ASSERT(MUTEX_HELD(&atgep->atge_tx_lock));

	/*
	 * Cancel any pending I/O.
	 */
	atge_device_stop(atgep);

	/*
	 * Reset the chip to a known state.
	 */
	atge_device_reset(atgep);

	/*
	 * Initialize the ring and other descriptor like CMB/SMB/Rx return.
	 */
	atge_device_init(atgep);

	/*
	 * Start the chip.
	 */
	atge_device_start(atgep);

}

static int
atge_send_a_packet(atge_t *atgep, mblk_t *mp)
{
	uchar_t *c;
	uint32_t cflags = 0;
	atge_ring_t *r;
	size_t pktlen;
	uchar_t *buf;
	int	start;

	ASSERT(MUTEX_HELD(&atgep->atge_tx_lock));
	ASSERT(mp != NULL);

	pktlen = msgsize(mp);
	if (pktlen > atgep->atge_tx_buf_len) {
		atgep->atge_macxmt_errors++;

		ATGE_DB(("%s: %s() pktlen (%d) > rx_buf_len (%d)",
		    atgep->atge_name, __func__,
		    pktlen, atgep->atge_rx_buf_len));

		freemsg(mp);
		return (DDI_SUCCESS);
	}

	r = atgep->atge_tx_ring;

	if (r->r_avail_desc <= 1) {
		atgep->atge_noxmtbuf++;
		atgep->atge_tx_resched = 1;

		ATGE_DB(("%s: %s() No transmit buf",
		    atgep->atge_name, __func__));

		return (DDI_FAILURE);
	}

	start = r->r_producer;

	/*
	 * Get the DMA buffer to hold a packet.
	 */
	buf = (uchar_t *)r->r_buf_tbl[start]->addr;

	/*
	 * Copy the msg and free mp
	 */
	mcopymsg(mp, buf);

	r->r_avail_desc--;

	c = (uchar_t *)r->r_desc_ring->addr;
	switch (ATGE_MODEL(atgep)) {
	case ATGE_CHIP_L1C:
		{
		l1c_tx_desc_t	*txd;

		c += (sizeof (l1c_tx_desc_t) * start);
		txd = (l1c_tx_desc_t *)c;

		ATGE_PUT64(r->r_desc_ring, &txd->addr,
		    r->r_buf_tbl[start]->cookie.dmac_laddress);

		ATGE_PUT32(r->r_desc_ring, &txd->len, L1C_TX_BYTES(pktlen));

		cflags |= L1C_TD_EOP;
		ATGE_PUT32(r->r_desc_ring, &txd->flags, cflags);
		break;
		}
	default:
		{
		atge_tx_desc_t	*txd;

		c += (sizeof (atge_tx_desc_t) * start);
		txd = (atge_tx_desc_t *)c;

		ATGE_PUT64(r->r_desc_ring, &txd->addr,
		    r->r_buf_tbl[start]->cookie.dmac_laddress);

		ATGE_PUT32(r->r_desc_ring, &txd->len, ATGE_TX_BYTES(pktlen));

		cflags |= ATGE_TD_EOP;
		ATGE_PUT32(r->r_desc_ring, &txd->flags, cflags);
		break;
		}
	}
	/*
	 * Sync buffer first.
	 */
	DMA_SYNC(r->r_buf_tbl[start], 0, pktlen, DDI_DMA_SYNC_FORDEV);

	/*
	 * Increment TX producer count by one.
	 */
	ATGE_INC_SLOT(r->r_producer, ATGE_TX_RING_CNT);

	/*
	 * Sync descriptor table.
	 */
	DMA_SYNC(r->r_desc_ring, 0, ATGE_TX_RING_SZ, DDI_DMA_SYNC_FORDEV);

	/*
	 * Program TX descriptor to send a packet.
	 */
	switch (ATGE_MODEL(atgep)) {
	case ATGE_CHIP_L1E:
		atge_l1e_send_packet(r);
		break;
	case ATGE_CHIP_L1:
		atge_l1_send_packet(r);
		break;
	case ATGE_CHIP_L1C:
		atge_l1c_send_packet(r);
		break;
	}

	r->r_atge->atge_opackets++;
	r->r_atge->atge_obytes += pktlen;

	ATGE_DB(("%s: %s() pktlen : %d, avail_desc : %d, producer  :%d, "
	    "consumer : %d", atgep->atge_name, __func__, pktlen,
	    r->r_avail_desc, r->r_producer, r->r_consumer));

	return (DDI_SUCCESS);
}

/*
 * Stream Information.
 */
DDI_DEFINE_STREAM_OPS(atge_devops, nulldev, nulldev, atge_attach, atge_detach,
    nodev, NULL, D_MP, NULL, atge_quiesce);

/*
 * Module linkage information.
 */
static	struct	modldrv	atge_modldrv = {
	&mod_driverops,				/* Type of Module */
	"Atheros/Attansic Gb Ethernet",		/* Description */
	&atge_devops				/* drv_dev_ops */
};

static	struct	modlinkage atge_modlinkage = {
	MODREV_1,			/* ml_rev */
	(void *)&atge_modldrv,
	NULL
};

/*
 * DDI Entry points.
 */
int
_init(void)
{
	int	r;
	mac_init_ops(&atge_devops, "atge");
	if ((r = mod_install(&atge_modlinkage)) != DDI_SUCCESS) {
		mac_fini_ops(&atge_devops);
	}

	return (r);
}

int
_fini(void)
{
	int	r;

	if ((r = mod_remove(&atge_modlinkage)) == DDI_SUCCESS) {
		mac_fini_ops(&atge_devops);
	}

	return (r);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&atge_modlinkage, modinfop));
}
