/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * This driver was derived from the FreeBSD if_msk.c driver, which
 * bears the following copyright attributions and licenses.
 */

/*
 *
 *	LICENSE:
 *	Copyright (C) Marvell International Ltd. and/or its affiliates
 *
 *	The computer program files contained in this folder ("Files")
 *	are provided to you under the BSD-type license terms provided
 *	below, and any use of such Files and any derivative works
 *	thereof created by you shall be governed by the following terms
 *	and conditions:
 *
 *	- Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *	- Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials provided
 *	  with the distribution.
 *	- Neither the name of Marvell nor the names of its contributors
 *	  may be used to endorse or promote products derived from this
 *	  software without specific prior written permission.
 *
 *	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *	"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *	LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 *	FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 *	COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 *	INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 *	BUT NOT LIMITED TO, PROCUREMENT OF  SUBSTITUTE GOODS OR SERVICES;
 *	LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *	HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 *	STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *	ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 *	OF THE POSSIBILITY OF SUCH DAMAGE.
 *	/LICENSE
 *
 */
/*
 * Copyright (c) 1997, 1998, 1999, 2000
 *	Bill Paul <wpaul@ctr.columbia.edu>.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by Bill Paul.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY Bill Paul AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL Bill Paul OR THE VOICES IN HIS HEAD
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Copyright (c) 2003 Nathan L. Binkert <binkertn@umich.edu>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
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
#include <sys/kmem.h>
#include <sys/time.h>
#include <sys/pci.h>
#include <sys/mii.h>
#include <sys/miiregs.h>
#include <sys/mac.h>
#include <sys/mac_ether.h>
#include <sys/mac_provider.h>
#include <sys/debug.h>
#include <sys/note.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/vlan.h>

#include "yge.h"

static struct ddi_device_acc_attr yge_regs_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

static struct ddi_device_acc_attr yge_ring_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

static struct ddi_device_acc_attr yge_buf_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};

#define	DESC_ALIGN	0x1000

static ddi_dma_attr_t yge_ring_dma_attr = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo */
	0x00000000ffffffffull,	/* dma_attr_addr_hi */
	0x00000000ffffffffull,	/* dma_attr_count_max */
	DESC_ALIGN,		/* dma_attr_align */
	0x000007fc,		/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0x00000000ffffffffull,	/* dma_attr_maxxfer */
	0x00000000ffffffffull,	/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};

static ddi_dma_attr_t yge_buf_dma_attr = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo */
	0x00000000ffffffffull,	/* dma_attr_addr_hi */
	0x00000000ffffffffull,	/* dma_attr_count_max */
	1,			/* dma_attr_align */
	0x0000fffc,		/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0x000000000000ffffull,	/* dma_attr_maxxfer */
	0x00000000ffffffffull,	/* dma_attr_seg */
	8,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};


static int yge_attach(yge_dev_t *);
static void yge_detach(yge_dev_t *);
static int yge_suspend(yge_dev_t *);
static int yge_resume(yge_dev_t *);

static void yge_reset(yge_dev_t *);
static void yge_setup_rambuffer(yge_dev_t *);

static int yge_init_port(yge_port_t *);
static void yge_uninit_port(yge_port_t *);
static int yge_register_port(yge_port_t *);

static void yge_tick(void *);
static uint_t yge_intr(caddr_t, caddr_t);
static int yge_intr_gmac(yge_port_t *);
static void yge_intr_enable(yge_dev_t *);
static void yge_intr_disable(yge_dev_t *);
static boolean_t yge_handle_events(yge_dev_t *, mblk_t **, mblk_t **, int *);
static void yge_handle_hwerr(yge_port_t *, uint32_t);
static void yge_intr_hwerr(yge_dev_t *);
static mblk_t *yge_rxeof(yge_port_t *, uint32_t, int);
static void yge_txeof(yge_port_t *, int);
static boolean_t yge_send(yge_port_t *, mblk_t *);
static void yge_set_prefetch(yge_dev_t *, int, yge_ring_t *);
static void yge_set_rambuffer(yge_port_t *);
static void yge_start_port(yge_port_t *);
static void yge_stop_port(yge_port_t *);
static void yge_phy_power(yge_dev_t *, boolean_t);
static int yge_alloc_ring(yge_port_t *, yge_dev_t *, yge_ring_t *, uint32_t);
static void yge_free_ring(yge_ring_t *);
static uint8_t yge_find_capability(yge_dev_t *, uint8_t);

static int yge_txrx_dma_alloc(yge_port_t *);
static void yge_txrx_dma_free(yge_port_t *);
static void yge_init_rx_ring(yge_port_t *);
static void yge_init_tx_ring(yge_port_t *);

static uint16_t yge_mii_readreg(yge_port_t *, uint8_t, uint8_t);
static void yge_mii_writereg(yge_port_t *, uint8_t, uint8_t, uint16_t);

static uint16_t yge_mii_read(void *, uint8_t, uint8_t);
static void yge_mii_write(void *, uint8_t, uint8_t, uint16_t);
static void yge_mii_notify(void *, link_state_t);

static void yge_setrxfilt(yge_port_t *);
static void yge_restart_task(yge_dev_t *);
static void yge_task(void *);
static void yge_dispatch(yge_dev_t *, int);

static void yge_stats_clear(yge_port_t *);
static void yge_stats_update(yge_port_t *);
static uint32_t yge_hashbit(const uint8_t *);

static int yge_m_unicst(void *, const uint8_t *);
static int yge_m_multicst(void *, boolean_t, const uint8_t *);
static int yge_m_promisc(void *, boolean_t);
static mblk_t *yge_m_tx(void *, mblk_t *);
static int yge_m_stat(void *, uint_t, uint64_t *);
static int yge_m_start(void *);
static void yge_m_stop(void *);
static int yge_m_getprop(void *, const char *, mac_prop_id_t, uint_t, void *);
static void yge_m_propinfo(void *, const char *, mac_prop_id_t,
    mac_prop_info_handle_t);
static int yge_m_setprop(void *, const char *, mac_prop_id_t, uint_t,
    const void *);
static void yge_m_ioctl(void *, queue_t *, mblk_t *);

void yge_error(yge_dev_t *, yge_port_t *, char *, ...);
extern void yge_phys_update(yge_port_t *);
extern int yge_phys_restart(yge_port_t *, boolean_t);
extern int yge_phys_init(yge_port_t *, phy_readreg_t, phy_writereg_t);

static mac_callbacks_t yge_m_callbacks = {
	MC_IOCTL | MC_SETPROP | MC_GETPROP | MC_PROPINFO,
	yge_m_stat,
	yge_m_start,
	yge_m_stop,
	yge_m_promisc,
	yge_m_multicst,
	yge_m_unicst,
	yge_m_tx,
	NULL,
	yge_m_ioctl,
	NULL,		/* mc_getcapab */
	NULL,		/* mc_open */
	NULL,		/* mc_close */
	yge_m_setprop,
	yge_m_getprop,
	yge_m_propinfo
};

static mii_ops_t yge_mii_ops = {
	MII_OPS_VERSION,
	yge_mii_read,
	yge_mii_write,
	yge_mii_notify,
	NULL	/* reset */
};

/*
 * This is the low level interface routine to read from the PHY
 * MII registers. There is multiple steps to these accesses. First
 * the register number is written to an address register. Then after
 * a specified delay status is checked until the data is present.
 */
static uint16_t
yge_mii_readreg(yge_port_t *port, uint8_t phy, uint8_t reg)
{
	yge_dev_t *dev = port->p_dev;
	int pnum = port->p_port;
	uint16_t val;

	GMAC_WRITE_2(dev, pnum, GM_SMI_CTRL,
	    GM_SMI_CT_PHY_AD(phy) | GM_SMI_CT_REG_AD(reg) | GM_SMI_CT_OP_RD);

	for (int i = 0; i < YGE_TIMEOUT; i += 10) {
		drv_usecwait(10);
		val = GMAC_READ_2(dev, pnum, GM_SMI_CTRL);
		if ((val & GM_SMI_CT_RD_VAL) != 0) {
			val = GMAC_READ_2(dev, pnum, GM_SMI_DATA);
			return (val);
		}
	}

	return (0xffff);
}

/*
 * This is the low level interface routine to write to the PHY
 * MII registers. There is multiple steps to these accesses. The
 * data and the target registers address are written to the PHY.
 * Then the PHY is polled until it is done with the write. Note
 * that the delays are specified and required!
 */
static void
yge_mii_writereg(yge_port_t *port, uint8_t phy, uint8_t reg, uint16_t val)
{
	yge_dev_t *dev = port->p_dev;
	int pnum = port->p_port;

	GMAC_WRITE_2(dev, pnum, GM_SMI_DATA, val);
	GMAC_WRITE_2(dev, pnum, GM_SMI_CTRL,
	    GM_SMI_CT_PHY_AD(phy) | GM_SMI_CT_REG_AD(reg));

	for (int i = 0; i < YGE_TIMEOUT; i += 10) {
		drv_usecwait(10);
		if ((GMAC_READ_2(dev, pnum, GM_SMI_CTRL) & GM_SMI_CT_BUSY) == 0)
			return;
	}

	yge_error(NULL, port, "phy write timeout");
}

static uint16_t
yge_mii_read(void *arg, uint8_t phy, uint8_t reg)
{
	yge_port_t *port = arg;
	uint16_t rv;

	PHY_LOCK(port->p_dev);
	rv = yge_mii_readreg(port, phy, reg);
	PHY_UNLOCK(port->p_dev);
	return (rv);
}

static void
yge_mii_write(void *arg, uint8_t phy, uint8_t reg, uint16_t val)
{
	yge_port_t *port = arg;

	PHY_LOCK(port->p_dev);
	yge_mii_writereg(port, phy, reg, val);
	PHY_UNLOCK(port->p_dev);
}

/*
 * The MII common code calls this function to let the MAC driver
 * know when there has been a change in status.
 */
void
yge_mii_notify(void *arg, link_state_t link)
{
	yge_port_t *port = arg;
	yge_dev_t *dev = port->p_dev;
	uint32_t gmac;
	uint32_t gpcr;
	link_flowctrl_t	fc;
	link_duplex_t duplex;
	int speed;

	fc = mii_get_flowctrl(port->p_mii);
	duplex = mii_get_duplex(port->p_mii);
	speed = mii_get_speed(port->p_mii);

	DEV_LOCK(dev);

	if (link == LINK_STATE_UP) {

		/* Enable Tx FIFO Underrun. */
		CSR_WRITE_1(dev, MR_ADDR(port->p_port, GMAC_IRQ_MSK),
		    GM_IS_TX_FF_UR |	/* TX FIFO underflow */
		    GM_IS_RX_FF_OR);	/* RX FIFO overflow */

		gpcr = GM_GPCR_AU_ALL_DIS;

		switch (fc) {
		case LINK_FLOWCTRL_BI:
			gmac = GMC_PAUSE_ON;
			gpcr &= ~(GM_GPCR_FC_RX_DIS | GM_GPCR_FC_TX_DIS);
			break;
		case LINK_FLOWCTRL_TX:
			gmac = GMC_PAUSE_ON;
			gpcr |= GM_GPCR_FC_RX_DIS;
			break;
		case LINK_FLOWCTRL_RX:
			gmac = GMC_PAUSE_ON;
			gpcr |= GM_GPCR_FC_TX_DIS;
			break;
		case LINK_FLOWCTRL_NONE:
		default:
			gmac = GMC_PAUSE_OFF;
			gpcr |= GM_GPCR_FC_RX_DIS;
			gpcr |= GM_GPCR_FC_TX_DIS;
			break;
		}

		gpcr &= ~((GM_GPCR_SPEED_1000 | GM_GPCR_SPEED_100));
		switch (speed) {
		case 1000:
			gpcr |= GM_GPCR_SPEED_1000;
			break;
		case 100:
			gpcr |= GM_GPCR_SPEED_100;
			break;
		case 10:
		default:
			break;
		}

		if (duplex == LINK_DUPLEX_FULL) {
			gpcr |= GM_GPCR_DUP_FULL;
		} else {
			gpcr &= ~(GM_GPCR_DUP_FULL);
			gmac = GMC_PAUSE_OFF;
			gpcr |= GM_GPCR_FC_RX_DIS;
			gpcr |= GM_GPCR_FC_TX_DIS;
		}

		gpcr |= GM_GPCR_RX_ENA | GM_GPCR_TX_ENA;
		GMAC_WRITE_2(dev, port->p_port, GM_GP_CTRL, gpcr);

		/* Read again to ensure writing. */
		(void) GMAC_READ_2(dev, port->p_port, GM_GP_CTRL);

		/* write out the flow control gmac setting */
		CSR_WRITE_4(dev, MR_ADDR(port->p_port, GMAC_CTRL), gmac);

	} else {
		/* Disable Rx/Tx MAC. */
		gpcr = GMAC_READ_2(dev, port->p_port, GM_GP_CTRL);
		gpcr &= ~(GM_GPCR_RX_ENA | GM_GPCR_TX_ENA);
		GMAC_WRITE_2(dev, port->p_port, GM_GP_CTRL, gpcr);

		/* Read again to ensure writing. */
		(void) GMAC_READ_2(dev, port->p_port, GM_GP_CTRL);
	}

	DEV_UNLOCK(dev);

	mac_link_update(port->p_mh, link);

	if (port->p_running && (link == LINK_STATE_UP)) {
		mac_tx_update(port->p_mh);
	}
}

static void
yge_setrxfilt(yge_port_t *port)
{
	yge_dev_t	*dev;
	uint16_t	mode;
	uint8_t		*ea;
	uint32_t	*mchash;
	int		pnum;

	dev = port->p_dev;
	pnum = port->p_port;
	ea = port->p_curraddr;
	mchash = port->p_mchash;

	if (dev->d_suspended)
		return;

	/* Set station address. */
	for (int i = 0; i < (ETHERADDRL / 2); i++) {
		GMAC_WRITE_2(dev, pnum, GM_SRC_ADDR_1L + i * 4,
		    ((uint16_t)ea[i * 2] | ((uint16_t)ea[(i * 2) + 1] << 8)));
	}
	for (int i = 0; i < (ETHERADDRL / 2); i++) {
		GMAC_WRITE_2(dev, pnum, GM_SRC_ADDR_2L + i * 4,
		    ((uint16_t)ea[i * 2] | ((uint16_t)ea[(i * 2) + 1] << 8)));
	}

	/* Figure out receive filtering mode. */
	mode = GMAC_READ_2(dev, pnum, GM_RX_CTRL);
	if (port->p_promisc) {
		mode &= ~(GM_RXCR_UCF_ENA | GM_RXCR_MCF_ENA);
	} else {
		mode |= (GM_RXCR_UCF_ENA | GM_RXCR_MCF_ENA);
	}
	/* Write the multicast filter. */
	GMAC_WRITE_2(dev, pnum, GM_MC_ADDR_H1, mchash[0] & 0xffff);
	GMAC_WRITE_2(dev, pnum, GM_MC_ADDR_H2, (mchash[0] >> 16) & 0xffff);
	GMAC_WRITE_2(dev, pnum, GM_MC_ADDR_H3, mchash[1] & 0xffff);
	GMAC_WRITE_2(dev, pnum, GM_MC_ADDR_H4, (mchash[1] >> 16) & 0xffff);
	/* Write the receive filtering mode. */
	GMAC_WRITE_2(dev, pnum, GM_RX_CTRL, mode);
}

static void
yge_init_rx_ring(yge_port_t *port)
{
	yge_buf_t *rxb;
	yge_ring_t *ring;
	int prod;

	port->p_rx_cons = 0;
	port->p_rx_putwm = YGE_PUT_WM;
	ring = &port->p_rx_ring;

	/* ala bzero, but uses safer acch access */
	CLEARRING(ring);

	for (prod = 0; prod < YGE_RX_RING_CNT; prod++) {
		/* Hang out receive buffers. */
		rxb = &port->p_rx_buf[prod];

		PUTADDR(ring, prod, rxb->b_paddr);
		PUTCTRL(ring, prod, port->p_framesize | OP_PACKET | HW_OWNER);
	}

	SYNCRING(ring, DDI_DMA_SYNC_FORDEV);

	yge_set_prefetch(port->p_dev, port->p_rxq, ring);

	/* Update prefetch unit. */
	CSR_WRITE_2(port->p_dev,
	    Y2_PREF_Q_ADDR(port->p_rxq, PREF_UNIT_PUT_IDX_REG),
	    YGE_RX_RING_CNT - 1);
}

static void
yge_init_tx_ring(yge_port_t *port)
{
	yge_ring_t *ring = &port->p_tx_ring;

	port->p_tx_prod = 0;
	port->p_tx_cons = 0;
	port->p_tx_cnt = 0;

	CLEARRING(ring);
	SYNCRING(ring, DDI_DMA_SYNC_FORDEV);

	yge_set_prefetch(port->p_dev, port->p_txq, ring);
}

static void
yge_setup_rambuffer(yge_dev_t *dev)
{
	int next;
	int i;

	/* Get adapter SRAM size. */
	dev->d_ramsize = CSR_READ_1(dev, B2_E_0) * 4;
	if (dev->d_ramsize == 0)
		return;

	dev->d_pflags |= PORT_FLAG_RAMBUF;
	/*
	 * Give receiver 2/3 of memory and round down to the multiple
	 * of 1024. Tx/Rx RAM buffer size of Yukon 2 should be multiple
	 * of 1024.
	 */
	dev->d_rxqsize = (((dev->d_ramsize * 1024 * 2) / 3) & ~(1024 - 1));
	dev->d_txqsize = (dev->d_ramsize * 1024) - dev->d_rxqsize;

	for (i = 0, next = 0; i < dev->d_num_port; i++) {
		dev->d_rxqstart[i] = next;
		dev->d_rxqend[i] = next + dev->d_rxqsize - 1;
		next = dev->d_rxqend[i] + 1;
		dev->d_txqstart[i] = next;
		dev->d_txqend[i] = next + dev->d_txqsize - 1;
		next = dev->d_txqend[i] + 1;
	}
}

static void
yge_phy_power(yge_dev_t *dev, boolean_t powerup)
{
	uint32_t val;
	int i;

	if (powerup) {
		/* Switch power to VCC (WA for VAUX problem). */
		CSR_WRITE_1(dev, B0_POWER_CTRL,
		    PC_VAUX_ENA | PC_VCC_ENA | PC_VAUX_OFF | PC_VCC_ON);
		/* Disable Core Clock Division, set Clock Select to 0. */
		CSR_WRITE_4(dev, B2_Y2_CLK_CTRL, Y2_CLK_DIV_DIS);

		val = 0;
		if (dev->d_hw_id == CHIP_ID_YUKON_XL &&
		    dev->d_hw_rev > CHIP_REV_YU_XL_A1) {
			/* Enable bits are inverted. */
			val = Y2_PCI_CLK_LNK1_DIS | Y2_COR_CLK_LNK1_DIS |
			    Y2_CLK_GAT_LNK1_DIS | Y2_PCI_CLK_LNK2_DIS |
			    Y2_COR_CLK_LNK2_DIS | Y2_CLK_GAT_LNK2_DIS;
		}
		/*
		 * Enable PCI & Core Clock, enable clock gating for both Links.
		 */
		CSR_WRITE_1(dev, B2_Y2_CLK_GATE, val);

		val = pci_config_get32(dev->d_pcih, PCI_OUR_REG_1);
		val &= ~(PCI_Y2_PHY1_POWD | PCI_Y2_PHY2_POWD);
		if (dev->d_hw_id == CHIP_ID_YUKON_XL &&
		    dev->d_hw_rev > CHIP_REV_YU_XL_A1) {
			/* Deassert Low Power for 1st PHY. */
			val |= PCI_Y2_PHY1_COMA;
			if (dev->d_num_port > 1)
				val |= PCI_Y2_PHY2_COMA;
		}

		/* Release PHY from PowerDown/COMA mode. */
		pci_config_put32(dev->d_pcih, PCI_OUR_REG_1, val);

		switch (dev->d_hw_id) {
		case CHIP_ID_YUKON_EC_U:
		case CHIP_ID_YUKON_EX:
		case CHIP_ID_YUKON_FE_P: {
			uint32_t our;

			CSR_WRITE_2(dev, B0_CTST, Y2_HW_WOL_OFF);

			/* Enable all clocks. */
			pci_config_put32(dev->d_pcih, PCI_OUR_REG_3, 0);

			our = pci_config_get32(dev->d_pcih, PCI_OUR_REG_4);
			our &= (PCI_FORCE_ASPM_REQUEST|PCI_ASPM_GPHY_LINK_DOWN|
			    PCI_ASPM_INT_FIFO_EMPTY|PCI_ASPM_CLKRUN_REQUEST);
			/* Set all bits to 0 except bits 15..12. */
			pci_config_put32(dev->d_pcih, PCI_OUR_REG_4, our);

			/* Set to default value. */
			our = pci_config_get32(dev->d_pcih, PCI_OUR_REG_5);
			our &= P_CTL_TIM_VMAIN_AV_MSK;
			pci_config_put32(dev->d_pcih, PCI_OUR_REG_5, our);

			pci_config_put32(dev->d_pcih, PCI_OUR_REG_1, 0);

			/*
			 * Enable workaround for dev 4.107 on Yukon-Ultra
			 * and Extreme
			 */
			our = CSR_READ_4(dev, B2_GP_IO);
			our |= GLB_GPIO_STAT_RACE_DIS;
			CSR_WRITE_4(dev, B2_GP_IO, our);

			(void) CSR_READ_4(dev, B2_GP_IO);
			break;
		}
		default:
			break;
		}

		for (i = 0; i < dev->d_num_port; i++) {
			CSR_WRITE_2(dev, MR_ADDR(i, GMAC_LINK_CTRL),
			    GMLC_RST_SET);
			CSR_WRITE_2(dev, MR_ADDR(i, GMAC_LINK_CTRL),
			    GMLC_RST_CLR);
		}
	} else {
		val = pci_config_get32(dev->d_pcih, PCI_OUR_REG_1);
		if (dev->d_hw_id == CHIP_ID_YUKON_XL &&
		    dev->d_hw_rev > CHIP_REV_YU_XL_A1) {
			val &= ~PCI_Y2_PHY1_COMA;
			if (dev->d_num_port > 1)
				val &= ~PCI_Y2_PHY2_COMA;
			val &= ~(PCI_Y2_PHY1_POWD | PCI_Y2_PHY2_POWD);
		} else {
			val |= (PCI_Y2_PHY1_POWD | PCI_Y2_PHY2_POWD);
		}
		pci_config_put32(dev->d_pcih, PCI_OUR_REG_1, val);

		val = Y2_PCI_CLK_LNK1_DIS | Y2_COR_CLK_LNK1_DIS |
		    Y2_CLK_GAT_LNK1_DIS | Y2_PCI_CLK_LNK2_DIS |
		    Y2_COR_CLK_LNK2_DIS | Y2_CLK_GAT_LNK2_DIS;
		if (dev->d_hw_id == CHIP_ID_YUKON_XL &&
		    dev->d_hw_rev > CHIP_REV_YU_XL_A1) {
			/* Enable bits are inverted. */
			val = 0;
		}
		/*
		 * Disable PCI & Core Clock, disable clock gating for
		 * both Links.
		 */
		CSR_WRITE_1(dev, B2_Y2_CLK_GATE, val);
		CSR_WRITE_1(dev, B0_POWER_CTRL,
		    PC_VAUX_ENA | PC_VCC_ENA | PC_VAUX_ON | PC_VCC_OFF);
	}
}

static void
yge_reset(yge_dev_t *dev)
{
	uint64_t addr;
	uint16_t status;
	uint32_t val;
	int i;
	ddi_acc_handle_t	pcih = dev->d_pcih;

	/* Turn off ASF */
	if (dev->d_hw_id == CHIP_ID_YUKON_EX) {
		status = CSR_READ_2(dev, B28_Y2_ASF_STAT_CMD);
		/* Clear AHB bridge & microcontroller reset */
		status &= ~Y2_ASF_CPU_MODE;
		status &= ~Y2_ASF_AHB_RST;
		/* Clear ASF microcontroller state */
		status &= ~Y2_ASF_STAT_MSK;
		CSR_WRITE_2(dev, B28_Y2_ASF_STAT_CMD, status);
	} else {
		CSR_WRITE_1(dev, B28_Y2_ASF_STAT_CMD, Y2_ASF_RESET);
	}
	CSR_WRITE_2(dev, B0_CTST, Y2_ASF_DISABLE);

	/*
	 * Since we disabled ASF, S/W reset is required for Power Management.
	 */
	CSR_WRITE_1(dev, B0_CTST, CS_RST_SET);
	CSR_WRITE_1(dev, B0_CTST, CS_RST_CLR);

	/* Allow writes to PCI config space */
	CSR_WRITE_1(dev, B2_TST_CTRL1, TST_CFG_WRITE_ON);

	/* Clear all error bits in the PCI status register. */
	status = pci_config_get16(pcih, PCI_CONF_STAT);
	CSR_WRITE_1(dev, B2_TST_CTRL1, TST_CFG_WRITE_ON);

	status |= (PCI_STAT_S_PERROR | PCI_STAT_S_SYSERR | PCI_STAT_R_MAST_AB |
	    PCI_STAT_R_TARG_AB | PCI_STAT_PERROR);
	pci_config_put16(pcih, PCI_CONF_STAT, status);

	CSR_WRITE_1(dev, B0_CTST, CS_MRST_CLR);

	switch (dev->d_bustype) {
	case PEX_BUS:
		/* Clear all PEX errors. */
		CSR_PCI_WRITE_4(dev, Y2_CFG_AER + AER_UNCOR_ERR, 0xffffffff);

		/* is error bit status stuck? */
		val = CSR_PCI_READ_4(dev, PEX_UNC_ERR_STAT);
		if ((val & PEX_RX_OV) != 0) {
			dev->d_intrmask &= ~Y2_IS_HW_ERR;
			dev->d_intrhwemask &= ~Y2_IS_PCI_EXP;
		}
		break;
	case PCI_BUS:
		/* Set Cache Line Size to 2 (8 bytes) if configured to 0. */
		if (pci_config_get8(pcih, PCI_CONF_CACHE_LINESZ) == 0)
			pci_config_put16(pcih, PCI_CONF_CACHE_LINESZ, 2);
		break;
	case PCIX_BUS:
		/* Set Cache Line Size to 2 (8 bytes) if configured to 0. */
		if (pci_config_get8(pcih, PCI_CONF_CACHE_LINESZ) == 0)
			pci_config_put16(pcih, PCI_CONF_CACHE_LINESZ, 2);

		/* Set Cache Line Size opt. */
		val = pci_config_get32(pcih, PCI_OUR_REG_1);
		val |= PCI_CLS_OPT;
		pci_config_put32(pcih, PCI_OUR_REG_1, val);
		break;
	}

	/* Set PHY power state. */
	yge_phy_power(dev, B_TRUE);

	/* Reset GPHY/GMAC Control */
	for (i = 0; i < dev->d_num_port; i++) {
		/* GPHY Control reset. */
		CSR_WRITE_4(dev, MR_ADDR(i, GPHY_CTRL), GPC_RST_SET);
		CSR_WRITE_4(dev, MR_ADDR(i, GPHY_CTRL), GPC_RST_CLR);
		/* GMAC Control reset. */
		CSR_WRITE_4(dev, MR_ADDR(i, GMAC_CTRL), GMC_RST_SET);
		CSR_WRITE_4(dev, MR_ADDR(i, GMAC_CTRL), GMC_RST_CLR);
		if (dev->d_hw_id == CHIP_ID_YUKON_EX ||
		    dev->d_hw_id == CHIP_ID_YUKON_SUPR) {
			CSR_WRITE_2(dev, MR_ADDR(i, GMAC_CTRL),
			    (GMC_BYP_RETR_ON | GMC_BYP_MACSECRX_ON |
			    GMC_BYP_MACSECTX_ON));
		}
		CSR_WRITE_2(dev, MR_ADDR(i, GMAC_CTRL), GMC_F_LOOPB_OFF);

	}
	CSR_WRITE_1(dev, B2_TST_CTRL1, TST_CFG_WRITE_OFF);

	/* LED On. */
	CSR_WRITE_2(dev, B0_CTST, Y2_LED_STAT_ON);

	/* Clear TWSI IRQ. */
	CSR_WRITE_4(dev, B2_I2C_IRQ, I2C_CLR_IRQ);

	/* Turn off hardware timer. */
	CSR_WRITE_1(dev, B2_TI_CTRL, TIM_STOP);
	CSR_WRITE_1(dev, B2_TI_CTRL, TIM_CLR_IRQ);

	/* Turn off descriptor polling. */
	CSR_WRITE_1(dev, B28_DPT_CTRL, DPT_STOP);

	/* Turn off time stamps. */
	CSR_WRITE_1(dev, GMAC_TI_ST_CTRL, GMT_ST_STOP);
	CSR_WRITE_1(dev, GMAC_TI_ST_CTRL, GMT_ST_CLR_IRQ);

	/* Don't permit config space writing */
	CSR_WRITE_1(dev, B2_TST_CTRL1, TST_CFG_WRITE_OFF);

	/* enable TX Arbiters */
	for (i = 0; i < dev->d_num_port; i++)
		CSR_WRITE_1(dev, MR_ADDR(i, TXA_CTRL), TXA_ENA_ARB);

	/* Configure timeout values. */
	for (i = 0; i < dev->d_num_port; i++) {
		CSR_WRITE_1(dev, SELECT_RAM_BUFFER(i, B3_RI_CTRL), RI_RST_CLR);

		CSR_WRITE_1(dev, SELECT_RAM_BUFFER(i, B3_RI_WTO_R1), RI_TO_53);
		CSR_WRITE_1(dev, SELECT_RAM_BUFFER(i, B3_RI_WTO_XA1), RI_TO_53);
		CSR_WRITE_1(dev, SELECT_RAM_BUFFER(i, B3_RI_WTO_XS1), RI_TO_53);
		CSR_WRITE_1(dev, SELECT_RAM_BUFFER(i, B3_RI_RTO_R1), RI_TO_53);
		CSR_WRITE_1(dev, SELECT_RAM_BUFFER(i, B3_RI_RTO_XA1), RI_TO_53);
		CSR_WRITE_1(dev, SELECT_RAM_BUFFER(i, B3_RI_RTO_XS1), RI_TO_53);
		CSR_WRITE_1(dev, SELECT_RAM_BUFFER(i, B3_RI_WTO_R2), RI_TO_53);
		CSR_WRITE_1(dev, SELECT_RAM_BUFFER(i, B3_RI_WTO_XA2), RI_TO_53);
		CSR_WRITE_1(dev, SELECT_RAM_BUFFER(i, B3_RI_WTO_XS2), RI_TO_53);
		CSR_WRITE_1(dev, SELECT_RAM_BUFFER(i, B3_RI_RTO_R2), RI_TO_53);
		CSR_WRITE_1(dev, SELECT_RAM_BUFFER(i, B3_RI_RTO_XA2), RI_TO_53);
		CSR_WRITE_1(dev, SELECT_RAM_BUFFER(i, B3_RI_RTO_XS2), RI_TO_53);
	}

	/* Disable all interrupts. */
	CSR_WRITE_4(dev, B0_HWE_IMSK, 0);
	(void) CSR_READ_4(dev, B0_HWE_IMSK);
	CSR_WRITE_4(dev, B0_IMSK, 0);
	(void) CSR_READ_4(dev, B0_IMSK);

	/*
	 * On dual port PCI-X card, there is an problem where status
	 * can be received out of order due to split transactions.
	 */
	if (dev->d_bustype == PCIX_BUS && dev->d_num_port > 1) {
		int pcix;
		uint16_t pcix_cmd;

		if ((pcix = yge_find_capability(dev, PCI_CAP_ID_PCIX)) != 0) {
			pcix_cmd = pci_config_get16(pcih, pcix + 2);
			/* Clear Max Outstanding Split Transactions. */
			pcix_cmd &= ~0x70;
			CSR_WRITE_1(dev, B2_TST_CTRL1, TST_CFG_WRITE_ON);
			pci_config_put16(pcih, pcix + 2, pcix_cmd);
			CSR_WRITE_1(dev, B2_TST_CTRL1, TST_CFG_WRITE_OFF);
		}
	}
	if (dev->d_bustype == PEX_BUS) {
		uint16_t v, width;

		v = pci_config_get16(pcih, PEX_DEV_CTRL);
		/* Change Max. Read Request Size to 4096 bytes. */
		v &= ~PEX_DC_MAX_RRS_MSK;
		v |= PEX_DC_MAX_RD_RQ_SIZE(5);
		pci_config_put16(pcih, PEX_DEV_CTRL, v);
		width = pci_config_get16(pcih, PEX_LNK_STAT);
		width = (width & PEX_LS_LINK_WI_MSK) >> 4;
		v = pci_config_get16(pcih, PEX_LNK_CAP);
		v = (v & PEX_LS_LINK_WI_MSK) >> 4;
		if (v != width)
			yge_error(dev, NULL,
			    "Negotiated width of PCIe link(x%d) != "
			    "max. width of link(x%d)\n", width, v);
	}

	/* Clear status list. */
	CLEARRING(&dev->d_status_ring);
	SYNCRING(&dev->d_status_ring, DDI_DMA_SYNC_FORDEV);

	dev->d_stat_cons = 0;

	CSR_WRITE_4(dev, STAT_CTRL, SC_STAT_RST_SET);
	CSR_WRITE_4(dev, STAT_CTRL, SC_STAT_RST_CLR);

	/* Set the status list base address. */
	addr = dev->d_status_ring.r_paddr;
	CSR_WRITE_4(dev, STAT_LIST_ADDR_LO, YGE_ADDR_LO(addr));
	CSR_WRITE_4(dev, STAT_LIST_ADDR_HI, YGE_ADDR_HI(addr));

	/* Set the status list last index. */
	CSR_WRITE_2(dev, STAT_LAST_IDX, YGE_STAT_RING_CNT - 1);
	CSR_WRITE_2(dev, STAT_PUT_IDX, 0);

	if (dev->d_hw_id == CHIP_ID_YUKON_EC &&
	    dev->d_hw_rev == CHIP_REV_YU_EC_A1) {
		/* WA for dev. #4.3 */
		CSR_WRITE_2(dev, STAT_TX_IDX_TH, ST_TXTH_IDX_MASK);
		/* WA for dev #4.18 */
		CSR_WRITE_1(dev, STAT_FIFO_WM, 0x21);
		CSR_WRITE_1(dev, STAT_FIFO_ISR_WM, 7);
	} else {
		CSR_WRITE_2(dev, STAT_TX_IDX_TH, 10);
		CSR_WRITE_1(dev, STAT_FIFO_WM, 16);

		/* ISR status FIFO watermark */
		if (dev->d_hw_id == CHIP_ID_YUKON_XL &&
		    dev->d_hw_rev == CHIP_REV_YU_XL_A0)
			CSR_WRITE_1(dev, STAT_FIFO_ISR_WM, 4);
		else
			CSR_WRITE_1(dev, STAT_FIFO_ISR_WM, 16);

		CSR_WRITE_4(dev, STAT_ISR_TIMER_INI, 0x0190);
	}

	/*
	 * Use default value for STAT_ISR_TIMER_INI, STAT_LEV_TIMER_INI.
	 */
	CSR_WRITE_4(dev, STAT_TX_TIMER_INI, YGE_USECS(dev, 1000));

	/* Enable status unit. */
	CSR_WRITE_4(dev, STAT_CTRL, SC_STAT_OP_ON);

	CSR_WRITE_1(dev, STAT_TX_TIMER_CTRL, TIM_START);
	CSR_WRITE_1(dev, STAT_LEV_TIMER_CTRL, TIM_START);
	CSR_WRITE_1(dev, STAT_ISR_TIMER_CTRL, TIM_START);
}

static int
yge_init_port(yge_port_t *port)
{
	yge_dev_t *dev = port->p_dev;
	int i;
	mac_register_t *macp;

	port->p_flags = dev->d_pflags;
	port->p_ppa = ddi_get_instance(dev->d_dip) + (port->p_port * 100);

	port->p_tx_buf = kmem_zalloc(sizeof (yge_buf_t) * YGE_TX_RING_CNT,
	    KM_SLEEP);
	port->p_rx_buf = kmem_zalloc(sizeof (yge_buf_t) * YGE_RX_RING_CNT,
	    KM_SLEEP);

	/* Setup Tx/Rx queue register offsets. */
	if (port->p_port == YGE_PORT_A) {
		port->p_txq = Q_XA1;
		port->p_txsq = Q_XS1;
		port->p_rxq = Q_R1;
	} else {
		port->p_txq = Q_XA2;
		port->p_txsq = Q_XS2;
		port->p_rxq = Q_R2;
	}

	/* Disable jumbo frame for Yukon FE. */
	if (dev->d_hw_id == CHIP_ID_YUKON_FE)
		port->p_flags |= PORT_FLAG_NOJUMBO;

	/*
	 * Start out assuming a regular MTU.  Users can change this
	 * with dladm.  The dladm daemon is supposed to issue commands
	 * to change the default MTU using m_setprop during early boot
	 * (before the interface is plumbed) if the user has so
	 * requested.
	 */
	port->p_mtu = ETHERMTU;

	port->p_mii = mii_alloc(port, dev->d_dip, &yge_mii_ops);
	if (port->p_mii == NULL) {
		yge_error(NULL, port, "MII handle allocation failed");
		return (DDI_FAILURE);
	}
	/* We assume all parts support asymmetric pause */
	mii_set_pauseable(port->p_mii, B_TRUE, B_TRUE);

	/*
	 * Get station address for this interface. Note that
	 * dual port cards actually come with three station
	 * addresses: one for each port, plus an extra. The
	 * extra one is used by the SysKonnect driver software
	 * as a 'virtual' station address for when both ports
	 * are operating in failover mode. Currently we don't
	 * use this extra address.
	 */
	for (i = 0; i < ETHERADDRL; i++) {
		port->p_curraddr[i] =
		    CSR_READ_1(dev, B2_MAC_1 + (port->p_port * 8) + i);
	}

	/* Register with Nemo. */
	if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
		yge_error(NULL, port, "MAC handle allocation failed");
		return (DDI_FAILURE);
	}
	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_driver = port;
	macp->m_dip = dev->d_dip;
	macp->m_src_addr = port->p_curraddr;
	macp->m_callbacks = &yge_m_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = port->p_mtu;
	macp->m_instance = port->p_ppa;
	macp->m_margin = VLAN_TAGSZ;

	port->p_mreg = macp;

	return (DDI_SUCCESS);
}

static int
yge_add_intr(yge_dev_t *dev, int intr_type)
{
	dev_info_t		*dip;
	int			count;
	int			actual;
	int			rv;
	int 			i, j;

	dip = dev->d_dip;

	rv = ddi_intr_get_nintrs(dip, intr_type, &count);
	if ((rv != DDI_SUCCESS) || (count == 0)) {
		yge_error(dev, NULL,
		    "ddi_intr_get_nintrs failed, rv %d, count %d", rv, count);
		return (DDI_FAILURE);
	}

	/*
	 * Allocate the interrupt.  Note that we only bother with a single
	 * interrupt.  One could argue that for MSI devices with dual ports,
	 * it would be nice to have a separate interrupt per port.  But right
	 * now I don't know how to configure that, so we'll just settle for
	 * a single interrupt.
	 */
	dev->d_intrcnt = 1;

	dev->d_intrsize = count * sizeof (ddi_intr_handle_t);
	dev->d_intrh = kmem_zalloc(dev->d_intrsize, KM_SLEEP);
	if (dev->d_intrh == NULL) {
		yge_error(dev, NULL, "Unable to allocate interrupt handle");
		return (DDI_FAILURE);
	}

	rv = ddi_intr_alloc(dip, dev->d_intrh, intr_type, 0, dev->d_intrcnt,
	    &actual, DDI_INTR_ALLOC_STRICT);
	if ((rv != DDI_SUCCESS) || (actual == 0)) {
		yge_error(dev, NULL,
		    "Unable to allocate interrupt, %d, count %d",
		    rv, actual);
		kmem_free(dev->d_intrh, dev->d_intrsize);
		return (DDI_FAILURE);
	}

	if ((rv = ddi_intr_get_pri(dev->d_intrh[0], &dev->d_intrpri)) !=
	    DDI_SUCCESS) {
		for (i = 0; i < dev->d_intrcnt; i++)
			(void) ddi_intr_free(dev->d_intrh[i]);
		yge_error(dev, NULL,
		    "Unable to get interrupt priority, %d", rv);
		kmem_free(dev->d_intrh, dev->d_intrsize);
		return (DDI_FAILURE);
	}

	if ((rv = ddi_intr_get_cap(dev->d_intrh[0], &dev->d_intrcap)) !=
	    DDI_SUCCESS) {
		yge_error(dev, NULL,
		    "Unable to get interrupt capabilities, %d", rv);
		for (i = 0; i < dev->d_intrcnt; i++)
			(void) ddi_intr_free(dev->d_intrh[i]);
		kmem_free(dev->d_intrh, dev->d_intrsize);
		return (DDI_FAILURE);
	}

	/* register interrupt handler to kernel */
	for (i = 0; i < dev->d_intrcnt; i++) {
		if ((rv = ddi_intr_add_handler(dev->d_intrh[i], yge_intr,
		    dev, NULL)) != DDI_SUCCESS) {
			yge_error(dev, NULL,
			    "Unable to add interrupt handler, %d", rv);
			for (j = 0; j < i; j++)
				(void) ddi_intr_remove_handler(dev->d_intrh[j]);
			for (i = 0; i < dev->d_intrcnt; i++)
				(void) ddi_intr_free(dev->d_intrh[i]);
			kmem_free(dev->d_intrh, dev->d_intrsize);
			return (DDI_FAILURE);
		}
	}

	mutex_init(&dev->d_rxlock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(dev->d_intrpri));
	mutex_init(&dev->d_txlock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(dev->d_intrpri));
	mutex_init(&dev->d_phylock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(dev->d_intrpri));
	mutex_init(&dev->d_task_mtx, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(dev->d_intrpri));

	return (DDI_SUCCESS);
}

static int
yge_attach_intr(yge_dev_t *dev)
{
	dev_info_t *dip = dev->d_dip;
	int intr_types;
	int rv;

	/* Allocate IRQ resources. */
	rv = ddi_intr_get_supported_types(dip, &intr_types);
	if (rv != DDI_SUCCESS) {
		yge_error(dev, NULL,
		    "Unable to determine supported interrupt types, %d", rv);
		return (DDI_FAILURE);
	}

	/*
	 * We default to not supporting MSI.  We've found some device
	 * and motherboard combinations don't always work well with
	 * MSI interrupts.  Users may override this if they choose.
	 */
	if (ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0, "msi_enable", 0) == 0) {
		/* If msi disable property present, disable both msix/msi. */
		if (intr_types & DDI_INTR_TYPE_FIXED) {
			intr_types &= ~(DDI_INTR_TYPE_MSI | DDI_INTR_TYPE_MSIX);
		}
	}

	if (intr_types & DDI_INTR_TYPE_MSIX) {
		if ((rv = yge_add_intr(dev, DDI_INTR_TYPE_MSIX)) ==
		    DDI_SUCCESS)
			return (DDI_SUCCESS);
	}

	if (intr_types & DDI_INTR_TYPE_MSI) {
		if ((rv = yge_add_intr(dev, DDI_INTR_TYPE_MSI)) ==
		    DDI_SUCCESS)
			return (DDI_SUCCESS);
	}

	if (intr_types & DDI_INTR_TYPE_FIXED) {
		if ((rv = yge_add_intr(dev, DDI_INTR_TYPE_FIXED)) ==
		    DDI_SUCCESS)
			return (DDI_SUCCESS);
	}

	yge_error(dev, NULL, "Unable to configure any interrupts");
	return (DDI_FAILURE);
}

static void
yge_intr_enable(yge_dev_t *dev)
{
	int i;
	if (dev->d_intrcap & DDI_INTR_FLAG_BLOCK) {
		/* Call ddi_intr_block_enable() for MSI interrupts */
		(void) ddi_intr_block_enable(dev->d_intrh, dev->d_intrcnt);
	} else {
		/* Call ddi_intr_enable for FIXED interrupts */
		for (i = 0; i < dev->d_intrcnt; i++)
			(void) ddi_intr_enable(dev->d_intrh[i]);
	}
}

void
yge_intr_disable(yge_dev_t *dev)
{
	int i;

	if (dev->d_intrcap & DDI_INTR_FLAG_BLOCK) {
		(void) ddi_intr_block_disable(dev->d_intrh, dev->d_intrcnt);
	} else {
		for (i = 0; i < dev->d_intrcnt; i++)
			(void) ddi_intr_disable(dev->d_intrh[i]);
	}
}

static uint8_t
yge_find_capability(yge_dev_t *dev, uint8_t cap)
{
	uint8_t ptr;
	uint16_t capit;
	ddi_acc_handle_t pcih = dev->d_pcih;

	if ((pci_config_get16(pcih, PCI_CONF_STAT) & PCI_STAT_CAP) == 0) {
		return (0);
	}
	/* This assumes PCI, and not CardBus. */
	ptr = pci_config_get8(pcih, PCI_CONF_CAP_PTR);
	while (ptr != 0) {
		capit = pci_config_get8(pcih, ptr + PCI_CAP_ID);
		if (capit == cap) {
			return (ptr);
		}
		ptr = pci_config_get8(pcih, ptr + PCI_CAP_NEXT_PTR);
	}
	return (0);
}

static int
yge_attach(yge_dev_t *dev)
{
	dev_info_t	*dip = dev->d_dip;
	int		rv;
	int		nattached;
	uint8_t		pm_cap;

	if (pci_config_setup(dip, &dev->d_pcih) != DDI_SUCCESS) {
		yge_error(dev, NULL, "Unable to map PCI configuration space");
		goto fail;
	}

	/*
	 * Map control/status registers.
	 */

	/* ensure the pmcsr status is D0 state */
	pm_cap = yge_find_capability(dev, PCI_CAP_ID_PM);
	if (pm_cap != 0) {
		uint16_t pmcsr;
		pmcsr = pci_config_get16(dev->d_pcih, pm_cap + PCI_PMCSR);
		pmcsr &= ~PCI_PMCSR_STATE_MASK;
		pci_config_put16(dev->d_pcih, pm_cap + PCI_PMCSR,
		    pmcsr | PCI_PMCSR_D0);
	}

	/* Enable PCI access and bus master. */
	pci_config_put16(dev->d_pcih, PCI_CONF_COMM,
	    pci_config_get16(dev->d_pcih, PCI_CONF_COMM) |
	    PCI_COMM_IO | PCI_COMM_MAE | PCI_COMM_ME);


	/* Allocate I/O resource */
	rv = ddi_regs_map_setup(dip, 1, &dev->d_regs, 0, 0, &yge_regs_attr,
	    &dev->d_regsh);
	if (rv != DDI_SUCCESS) {
		yge_error(dev, NULL, "Unable to map device registers");
		goto fail;
	}


	/* Enable all clocks. */
	CSR_WRITE_1(dev, B2_TST_CTRL1, TST_CFG_WRITE_ON);
	pci_config_put32(dev->d_pcih, PCI_OUR_REG_3, 0);
	CSR_WRITE_1(dev, B2_TST_CTRL1, TST_CFG_WRITE_OFF);

	CSR_WRITE_2(dev, B0_CTST, CS_RST_CLR);
	dev->d_hw_id = CSR_READ_1(dev, B2_CHIP_ID);
	dev->d_hw_rev = (CSR_READ_1(dev, B2_MAC_CFG) >> 4) & 0x0f;


	/*
	 * Bail out if chip is not recognized.  Note that we only enforce
	 * this in production builds.  The Ultra-2 (88e8057) has a problem
	 * right now where TX works fine, but RX seems not to.  So we've
	 * disabled that for now.
	 */
	if (dev->d_hw_id < CHIP_ID_YUKON_XL ||
	    dev->d_hw_id >= CHIP_ID_YUKON_UL_2) {
		yge_error(dev, NULL, "Unknown device: id=0x%02x, rev=0x%02x",
		    dev->d_hw_id, dev->d_hw_rev);
#ifndef	DEBUG
		goto fail;
#endif
	}

	/* Soft reset. */
	CSR_WRITE_2(dev, B0_CTST, CS_RST_SET);
	CSR_WRITE_2(dev, B0_CTST, CS_RST_CLR);
	dev->d_pmd = CSR_READ_1(dev, B2_PMD_TYP);
	if (dev->d_pmd == 'L' || dev->d_pmd == 'S' || dev->d_pmd == 'P')
		dev->d_coppertype = 0;
	else
		dev->d_coppertype = 1;
	/* Check number of MACs. */
	dev->d_num_port = 1;
	if ((CSR_READ_1(dev, B2_Y2_HW_RES) & CFG_DUAL_MAC_MSK) ==
	    CFG_DUAL_MAC_MSK) {
		if (!(CSR_READ_1(dev, B2_Y2_CLK_GATE) & Y2_STATUS_LNK2_INAC))
			dev->d_num_port++;
	}

	/* Check bus type. */
	if (yge_find_capability(dev, PCI_CAP_ID_PCI_E) != 0) {
		dev->d_bustype = PEX_BUS;
	} else if (yge_find_capability(dev, PCI_CAP_ID_PCIX) != 0) {
		dev->d_bustype = PCIX_BUS;
	} else {
		dev->d_bustype = PCI_BUS;
	}

	switch (dev->d_hw_id) {
	case CHIP_ID_YUKON_EC:
		dev->d_clock = 125;	/* 125 Mhz */
		break;
	case CHIP_ID_YUKON_UL_2:
		dev->d_clock = 125;	/* 125 Mhz */
		break;
	case CHIP_ID_YUKON_SUPR:
		dev->d_clock = 125;	/* 125 Mhz */
		break;
	case CHIP_ID_YUKON_EC_U:
		dev->d_clock = 125;	/* 125 Mhz */
		break;
	case CHIP_ID_YUKON_EX:
		dev->d_clock = 125;	/* 125 Mhz */
		break;
	case CHIP_ID_YUKON_FE:
		dev->d_clock = 100;	/* 100 Mhz */
		break;
	case CHIP_ID_YUKON_FE_P:
		dev->d_clock = 50;	/* 50 Mhz */
		break;
	case CHIP_ID_YUKON_XL:
		dev->d_clock = 156;	/* 156 Mhz */
		break;
	default:
		dev->d_clock = 156;	/* 156 Mhz */
		break;
	}

	dev->d_process_limit = YGE_RX_RING_CNT/2;

	rv = yge_alloc_ring(NULL, dev, &dev->d_status_ring, YGE_STAT_RING_CNT);
	if (rv != DDI_SUCCESS)
		goto fail;

	/* Setup event taskq. */
	dev->d_task_q = ddi_taskq_create(dip, "tq", 1, TASKQ_DEFAULTPRI, 0);
	if (dev->d_task_q == NULL) {
		yge_error(dev, NULL, "failed to create taskq");
		goto fail;
	}

	/* Init the condition variable */
	cv_init(&dev->d_task_cv, NULL, CV_DRIVER, NULL);

	/* Allocate IRQ resources. */
	if ((rv = yge_attach_intr(dev)) != DDI_SUCCESS) {
		goto fail;
	}

	/* Set base interrupt mask. */
	dev->d_intrmask = Y2_IS_HW_ERR | Y2_IS_STAT_BMU;
	dev->d_intrhwemask = Y2_IS_TIST_OV | Y2_IS_MST_ERR |
	    Y2_IS_IRQ_STAT | Y2_IS_PCI_EXP | Y2_IS_PCI_NEXP;

	/* Reset the adapter. */
	yge_reset(dev);

	yge_setup_rambuffer(dev);

	nattached = 0;
	for (int i = 0; i < dev->d_num_port; i++) {
		yge_port_t *port = dev->d_port[i];
		if (yge_init_port(port) != DDI_SUCCESS) {
			goto fail;
		}
	}

	yge_intr_enable(dev);

	/* set up the periodic to run once per second */
	dev->d_periodic = ddi_periodic_add(yge_tick, dev, 1000000000, 0);

	for (int i = 0; i < dev->d_num_port; i++) {
		yge_port_t *port = dev->d_port[i];
		if (yge_register_port(port) == DDI_SUCCESS) {
			nattached++;
		}
	}

	if (nattached == 0) {
		goto fail;
	}

	/* Dispatch the taskq */
	if (ddi_taskq_dispatch(dev->d_task_q, yge_task, dev, DDI_SLEEP) !=
	    DDI_SUCCESS) {
		yge_error(dev, NULL, "failed to start taskq");
		goto fail;
	}

	ddi_report_dev(dip);

	return (DDI_SUCCESS);

fail:
	yge_detach(dev);
	return (DDI_FAILURE);
}

static int
yge_register_port(yge_port_t *port)
{
	if (mac_register(port->p_mreg, &port->p_mh) != DDI_SUCCESS) {
		yge_error(NULL, port, "MAC registration failed");
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * Free up port specific resources. This is called only when the
 * port is not registered (and hence not running).
 */
static void
yge_uninit_port(yge_port_t *port)
{
	ASSERT(!port->p_running);

	if (port->p_mreg)
		mac_free(port->p_mreg);

	if (port->p_mii)
		mii_free(port->p_mii);

	yge_txrx_dma_free(port);

	if (port->p_tx_buf)
		kmem_free(port->p_tx_buf,
		    sizeof (yge_buf_t) * YGE_TX_RING_CNT);
	if (port->p_rx_buf)
		kmem_free(port->p_rx_buf,
		    sizeof (yge_buf_t) * YGE_RX_RING_CNT);
}

static void
yge_detach(yge_dev_t *dev)
{
	/*
	 * Turn off the periodic.
	 */
	if (dev->d_periodic)
		ddi_periodic_delete(dev->d_periodic);

	for (int i = 0; i < dev->d_num_port; i++) {
		yge_uninit_port(dev->d_port[i]);
	}

	/*
	 * Make sure all interrupts are disabled.
	 */
	CSR_WRITE_4(dev, B0_IMSK, 0);
	(void) CSR_READ_4(dev, B0_IMSK);
	CSR_WRITE_4(dev, B0_HWE_IMSK, 0);
	(void) CSR_READ_4(dev, B0_HWE_IMSK);

	/* LED Off. */
	CSR_WRITE_2(dev, B0_CTST, Y2_LED_STAT_OFF);

	/* Put hardware reset. */
	CSR_WRITE_2(dev, B0_CTST, CS_RST_SET);

	yge_free_ring(&dev->d_status_ring);

	if (dev->d_task_q != NULL) {
		yge_dispatch(dev, YGE_TASK_EXIT);
		ddi_taskq_destroy(dev->d_task_q);
		dev->d_task_q = NULL;
	}

	cv_destroy(&dev->d_task_cv);

	yge_intr_disable(dev);

	if (dev->d_intrh != NULL) {
		for (int i = 0; i < dev->d_intrcnt; i++) {
			(void) ddi_intr_remove_handler(dev->d_intrh[i]);
			(void) ddi_intr_free(dev->d_intrh[i]);
		}
		kmem_free(dev->d_intrh, dev->d_intrsize);
		mutex_destroy(&dev->d_phylock);
		mutex_destroy(&dev->d_txlock);
		mutex_destroy(&dev->d_rxlock);
		mutex_destroy(&dev->d_task_mtx);
	}
	if (dev->d_regsh != NULL)
		ddi_regs_map_free(&dev->d_regsh);

	if (dev->d_pcih != NULL)
		pci_config_teardown(&dev->d_pcih);
}

static int
yge_alloc_ring(yge_port_t *port, yge_dev_t *dev, yge_ring_t *ring, uint32_t num)
{
	dev_info_t		*dip;
	caddr_t			kaddr;
	size_t			len;
	int			rv;
	ddi_dma_cookie_t	dmac;
	unsigned		ndmac;

	if (port && !dev)
		dev = port->p_dev;
	dip = dev->d_dip;

	ring->r_num = num;

	rv = ddi_dma_alloc_handle(dip, &yge_ring_dma_attr, DDI_DMA_DONTWAIT,
	    NULL, &ring->r_dmah);
	if (rv != DDI_SUCCESS) {
		yge_error(dev, port, "Unable to allocate ring DMA handle");
		return (DDI_FAILURE);
	}

	rv = ddi_dma_mem_alloc(ring->r_dmah, num * sizeof (yge_desc_t),
	    &yge_ring_attr, DDI_DMA_CONSISTENT, DDI_DMA_DONTWAIT, NULL,
	    &kaddr, &len, &ring->r_acch);
	if (rv != DDI_SUCCESS) {
		yge_error(dev, port, "Unable to allocate ring DMA memory");
		return (DDI_FAILURE);
	}
	ring->r_size = len;
	ring->r_kaddr = (void *)kaddr;

	bzero(kaddr, len);

	rv = ddi_dma_addr_bind_handle(ring->r_dmah, NULL, kaddr,
	    len, DDI_DMA_RDWR | DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    &dmac, &ndmac);
	if (rv != DDI_DMA_MAPPED) {
		yge_error(dev, port, "Unable to bind ring DMA handle");
		return (DDI_FAILURE);
	}
	ASSERT(ndmac == 1);
	ring->r_paddr = dmac.dmac_address;

	return (DDI_SUCCESS);
}

static void
yge_free_ring(yge_ring_t *ring)
{
	if (ring->r_paddr)
		(void) ddi_dma_unbind_handle(ring->r_dmah);
	ring->r_paddr = 0;
	if (ring->r_acch)
		ddi_dma_mem_free(&ring->r_acch);
	ring->r_kaddr = NULL;
	ring->r_acch = NULL;
	if (ring->r_dmah)
		ddi_dma_free_handle(&ring->r_dmah);
	ring->r_dmah = NULL;
}

static int
yge_alloc_buf(yge_port_t *port, yge_buf_t *b, size_t bufsz, int flag)
{
	yge_dev_t	*dev = port->p_dev;
	size_t		l;
	int		sflag;
	int 		rv;
	ddi_dma_cookie_t	dmac;
	unsigned		ndmac;

	sflag = flag & (DDI_DMA_STREAMING | DDI_DMA_CONSISTENT);

	/* Now allocate Tx buffers. */
	rv = ddi_dma_alloc_handle(dev->d_dip, &yge_buf_dma_attr,
	    DDI_DMA_DONTWAIT, NULL, &b->b_dmah);
	if (rv != DDI_SUCCESS) {
		yge_error(NULL, port, "Unable to alloc DMA handle for buffer");
		return (DDI_FAILURE);
	}

	rv = ddi_dma_mem_alloc(b->b_dmah, bufsz, &yge_buf_attr,
	    sflag, DDI_DMA_DONTWAIT, NULL, &b->b_buf, &l, &b->b_acch);
	if (rv != DDI_SUCCESS) {
		yge_error(NULL, port, "Unable to alloc DMA memory for buffer");
		return (DDI_FAILURE);
	}

	rv = ddi_dma_addr_bind_handle(b->b_dmah, NULL, b->b_buf, l, flag,
	    DDI_DMA_DONTWAIT, NULL, &dmac, &ndmac);
	if (rv != DDI_DMA_MAPPED) {
		yge_error(NULL, port, "Unable to bind DMA handle for buffer");
		return (DDI_FAILURE);
	}
	ASSERT(ndmac == 1);
	b->b_paddr = dmac.dmac_address;
	return (DDI_SUCCESS);
}

static void
yge_free_buf(yge_buf_t *b)
{
	if (b->b_paddr)
		(void) ddi_dma_unbind_handle(b->b_dmah);
	b->b_paddr = 0;
	if (b->b_acch)
		ddi_dma_mem_free(&b->b_acch);
	b->b_buf = NULL;
	b->b_acch = NULL;
	if (b->b_dmah)
		ddi_dma_free_handle(&b->b_dmah);
	b->b_dmah = NULL;
}

static int
yge_txrx_dma_alloc(yge_port_t *port)
{
	uint32_t		bufsz;
	int			rv;
	int			i;
	yge_buf_t		*b;

	/*
	 * It seems that Yukon II supports full 64 bit DMA operations.
	 * But we limit it to 32 bits only for now.  The 64 bit
	 * operation would require substantially more complex
	 * descriptor handling, since in such a case we would need two
	 * LEs to represent a single physical address.
	 *
	 * If we find that this is limiting us, then we should go back
	 * and re-examine it.
	 */

	/* Note our preferred buffer size. */
	bufsz = port->p_mtu;

	/* Allocate Tx ring. */
	rv = yge_alloc_ring(port, NULL, &port->p_tx_ring, YGE_TX_RING_CNT);
	if (rv != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/* Now allocate Tx buffers. */
	b = port->p_tx_buf;
	for (i = 0; i < YGE_TX_RING_CNT; i++) {
		rv = yge_alloc_buf(port, b, bufsz,
		    DDI_DMA_STREAMING | DDI_DMA_WRITE);
		if (rv != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}
		b++;
	}

	/* Allocate Rx ring. */
	rv = yge_alloc_ring(port, NULL, &port->p_rx_ring, YGE_RX_RING_CNT);
	if (rv != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/* Now allocate Rx buffers. */
	b = port->p_rx_buf;
	for (i = 0; i < YGE_RX_RING_CNT; i++) {
		rv =  yge_alloc_buf(port, b, bufsz,
		    DDI_DMA_STREAMING | DDI_DMA_READ);
		if (rv != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}
		b++;
	}

	return (DDI_SUCCESS);
}

static void
yge_txrx_dma_free(yge_port_t *port)
{
	yge_buf_t	*b;

	/* Tx ring. */
	yge_free_ring(&port->p_tx_ring);

	/* Rx ring. */
	yge_free_ring(&port->p_rx_ring);

	/* Tx buffers. */
	b = port->p_tx_buf;
	for (int i = 0; i < YGE_TX_RING_CNT; i++, b++) {
		yge_free_buf(b);
	}
	/* Rx buffers. */
	b = port->p_rx_buf;
	for (int i = 0; i < YGE_RX_RING_CNT; i++, b++) {
		yge_free_buf(b);
	}
}

boolean_t
yge_send(yge_port_t *port, mblk_t *mp)
{
	yge_ring_t *ring = &port->p_tx_ring;
	yge_buf_t *txb;
	int16_t prod;
	size_t len;

	/*
	 * For now we're not going to support checksum offload or LSO.
	 */

	len = msgsize(mp);
	if (len > port->p_framesize) {
		/* too big! */
		freemsg(mp);
		return (B_TRUE);
	}

	/* Check number of available descriptors. */
	if (port->p_tx_cnt + 1 >=
	    (YGE_TX_RING_CNT - YGE_RESERVED_TX_DESC_CNT)) {
		port->p_wantw = B_TRUE;
		return (B_FALSE);
	}

	prod = port->p_tx_prod;

	txb = &port->p_tx_buf[prod];
	mcopymsg(mp, txb->b_buf);
	SYNCBUF(txb, DDI_DMA_SYNC_FORDEV);

	PUTADDR(ring, prod, txb->b_paddr);
	PUTCTRL(ring, prod, len | OP_PACKET | HW_OWNER | EOP);
	SYNCENTRY(ring, prod, DDI_DMA_SYNC_FORDEV);
	port->p_tx_cnt++;

	YGE_INC(prod, YGE_TX_RING_CNT);

	/* Update producer index. */
	port->p_tx_prod = prod;

	return (B_TRUE);
}

static int
yge_suspend(yge_dev_t *dev)
{
	for (int i = 0; i < dev->d_num_port; i++) {
		yge_port_t *port = dev->d_port[i];
		mii_suspend(port->p_mii);
	}


	DEV_LOCK(dev);

	for (int i = 0; i < dev->d_num_port; i++) {
		yge_port_t *port = dev->d_port[i];

		if (port->p_running) {
			yge_stop_port(port);
		}
	}

	/* Disable all interrupts. */
	CSR_WRITE_4(dev, B0_IMSK, 0);
	(void) CSR_READ_4(dev, B0_IMSK);
	CSR_WRITE_4(dev, B0_HWE_IMSK, 0);
	(void) CSR_READ_4(dev, B0_HWE_IMSK);

	yge_phy_power(dev, B_FALSE);

	/* Put hardware reset. */
	CSR_WRITE_2(dev, B0_CTST, CS_RST_SET);
	dev->d_suspended = B_TRUE;

	DEV_UNLOCK(dev);

	return (DDI_SUCCESS);
}

static int
yge_resume(yge_dev_t *dev)
{
	uint8_t pm_cap;

	DEV_LOCK(dev);

	/* ensure the pmcsr status is D0 state */
	CSR_WRITE_1(dev, B2_TST_CTRL1, TST_CFG_WRITE_ON);

	if ((pm_cap = yge_find_capability(dev, PCI_CAP_ID_PM)) != 0) {
		uint16_t pmcsr;
		pmcsr = pci_config_get16(dev->d_pcih, pm_cap + PCI_PMCSR);
		pmcsr &= ~PCI_PMCSR_STATE_MASK;
		pci_config_put16(dev->d_pcih, pm_cap + PCI_PMCSR,
		    pmcsr | PCI_PMCSR_D0);
	}

	/* Enable PCI access and bus master. */
	pci_config_put16(dev->d_pcih, PCI_CONF_COMM,
	    pci_config_get16(dev->d_pcih, PCI_CONF_COMM) |
	    PCI_COMM_IO | PCI_COMM_MAE | PCI_COMM_ME);

	/* Enable all clocks. */
	switch (dev->d_hw_id) {
	case CHIP_ID_YUKON_EX:
	case CHIP_ID_YUKON_EC_U:
	case CHIP_ID_YUKON_FE_P:
		pci_config_put32(dev->d_pcih, PCI_OUR_REG_3, 0);
		break;
	}

	CSR_WRITE_1(dev, B2_TST_CTRL1, TST_CFG_WRITE_OFF);

	yge_reset(dev);

	/* Make sure interrupts are reenabled */
	CSR_WRITE_4(dev, B0_IMSK, 0);
	CSR_WRITE_4(dev, B0_IMSK, Y2_IS_HW_ERR | Y2_IS_STAT_BMU);
	CSR_WRITE_4(dev, B0_HWE_IMSK,
	    Y2_IS_TIST_OV | Y2_IS_MST_ERR |
	    Y2_IS_IRQ_STAT | Y2_IS_PCI_EXP | Y2_IS_PCI_NEXP);

	for (int i = 0; i < dev->d_num_port; i++) {
		yge_port_t *port = dev->d_port[i];

		if (port != NULL && port->p_running) {
			yge_start_port(port);
		}
	}
	dev->d_suspended = B_FALSE;

	DEV_UNLOCK(dev);

	/* Reset MII layer */
	for (int i = 0; i < dev->d_num_port; i++) {
		yge_port_t *port = dev->d_port[i];

		if (port->p_running) {
			mii_resume(port->p_mii);
			mac_tx_update(port->p_mh);
		}
	}

	return (DDI_SUCCESS);
}

static mblk_t *
yge_rxeof(yge_port_t *port, uint32_t status, int len)
{
	yge_dev_t *dev = port->p_dev;
	mblk_t	*mp;
	int cons, rxlen;
	yge_buf_t *rxb;
	yge_ring_t *ring;

	ASSERT(mutex_owned(&dev->d_rxlock));

	if (!port->p_running)
		return (NULL);

	ring = &port->p_rx_ring;
	cons = port->p_rx_cons;
	rxlen = status >> 16;
	rxb = &port->p_rx_buf[cons];
	mp = NULL;


	if ((dev->d_hw_id == CHIP_ID_YUKON_FE_P) &&
	    (dev->d_hw_rev == CHIP_REV_YU_FE2_A0)) {
		/*
		 * Apparently the status for this chip is not reliable.
		 * Only perform minimal consistency checking; the MAC
		 * and upper protocols will have to filter any garbage.
		 */
		if ((len > port->p_framesize) || (rxlen != len)) {
			goto bad;
		}
	} else {
		if ((len > port->p_framesize) || (rxlen != len) ||
		    ((status & GMR_FS_ANY_ERR) != 0) ||
		    ((status & GMR_FS_RX_OK) == 0)) {
			goto bad;
		}
	}

	if ((mp = allocb(len + YGE_HEADROOM, BPRI_HI)) != NULL) {

		/* good packet - yay */
		mp->b_rptr += YGE_HEADROOM;
		SYNCBUF(rxb, DDI_DMA_SYNC_FORKERNEL);
		bcopy(rxb->b_buf, mp->b_rptr, len);
		mp->b_wptr = mp->b_rptr + len;
	} else {
		port->p_stats.rx_nobuf++;
	}

bad:

	PUTCTRL(ring, cons, port->p_framesize | OP_PACKET | HW_OWNER);
	SYNCENTRY(ring, cons, DDI_DMA_SYNC_FORDEV);

	CSR_WRITE_2(dev,
	    Y2_PREF_Q_ADDR(port->p_rxq, PREF_UNIT_PUT_IDX_REG),
	    cons);

	YGE_INC(port->p_rx_cons, YGE_RX_RING_CNT);

	return (mp);
}

static boolean_t
yge_txeof_locked(yge_port_t *port, int idx)
{
	int prog;
	int16_t cons;
	boolean_t resched;

	if (!port->p_running) {
		return (B_FALSE);
	}

	cons = port->p_tx_cons;
	prog = 0;
	for (; cons != idx; YGE_INC(cons, YGE_TX_RING_CNT)) {
		if (port->p_tx_cnt <= 0)
			break;
		prog++;
		port->p_tx_cnt--;
		/* No need to sync LEs as we didn't update LEs. */
	}

	port->p_tx_cons = cons;

	if (prog > 0) {
		resched = port->p_wantw;
		port->p_tx_wdog = 0;
		port->p_wantw = B_FALSE;
		return (resched);
	} else {
		return (B_FALSE);
	}
}

static void
yge_txeof(yge_port_t *port, int idx)
{
	boolean_t resched;

	TX_LOCK(port->p_dev);

	resched = yge_txeof_locked(port, idx);

	TX_UNLOCK(port->p_dev);

	if (resched && port->p_running) {
		mac_tx_update(port->p_mh);
	}
}

static void
yge_restart_task(yge_dev_t *dev)
{
	yge_port_t *port;

	DEV_LOCK(dev);

	/* Cancel pending I/O and free all Rx/Tx buffers. */
	for (int i = 0; i < dev->d_num_port; i++) {
		port = dev->d_port[i];
		if (port->p_running)
			yge_stop_port(dev->d_port[i]);
	}
	yge_reset(dev);
	for (int i = 0; i < dev->d_num_port; i++) {
		port = dev->d_port[i];

		if (port->p_running)
			yge_start_port(port);
	}

	DEV_UNLOCK(dev);

	for (int i = 0; i < dev->d_num_port; i++) {
		port = dev->d_port[i];

		mii_reset(port->p_mii);
		if (port->p_running)
			mac_tx_update(port->p_mh);
	}
}

static void
yge_tick(void *arg)
{
	yge_dev_t *dev = arg;
	yge_port_t *port;
	boolean_t restart = B_FALSE;
	boolean_t resched = B_FALSE;
	int idx;

	DEV_LOCK(dev);

	if (dev->d_suspended) {
		DEV_UNLOCK(dev);
		return;
	}

	for (int i = 0; i < dev->d_num_port; i++) {
		port = dev->d_port[i];

		if (!port->p_running)
			continue;

		if (port->p_tx_cnt) {
			uint32_t ridx;

			/*
			 * Reclaim first as there is a possibility of losing
			 * Tx completion interrupts.
			 */
			ridx = port->p_port == YGE_PORT_A ?
			    STAT_TXA1_RIDX : STAT_TXA2_RIDX;
			idx = CSR_READ_2(dev, ridx);
			if (port->p_tx_cons != idx) {
				resched = yge_txeof_locked(port, idx);

			} else {

				/* detect TX hang */
				port->p_tx_wdog++;
				if (port->p_tx_wdog > YGE_TX_TIMEOUT) {
					port->p_tx_wdog = 0;
					yge_error(NULL, port,
					    "TX hang detected!");
					restart = B_TRUE;
				}
			}
		}
	}

	DEV_UNLOCK(dev);
	if (restart) {
		yge_dispatch(dev, YGE_TASK_RESTART);
	} else {
		if (resched) {
			for (int i = 0; i < dev->d_num_port; i++) {
				port = dev->d_port[i];

				if (port->p_running)
					mac_tx_update(port->p_mh);
			}
		}
	}
}

static int
yge_intr_gmac(yge_port_t *port)
{
	yge_dev_t *dev = port->p_dev;
	int pnum = port->p_port;
	uint8_t status;
	int dispatch_wrk = 0;

	status = CSR_READ_1(dev, MR_ADDR(pnum, GMAC_IRQ_SRC));

	/* GMAC Rx FIFO overrun. */
	if ((status & GM_IS_RX_FF_OR) != 0) {
		CSR_WRITE_4(dev, MR_ADDR(pnum, RX_GMF_CTRL_T), GMF_CLI_RX_FO);
		yge_error(NULL, port, "Rx FIFO overrun!");
		dispatch_wrk |= YGE_TASK_RESTART;
	}
	/* GMAC Tx FIFO underrun. */
	if ((status & GM_IS_TX_FF_UR) != 0) {
		CSR_WRITE_4(dev, MR_ADDR(pnum, TX_GMF_CTRL_T), GMF_CLI_TX_FU);
		yge_error(NULL, port, "Tx FIFO underrun!");
		/*
		 * In case of Tx underrun, we may need to flush/reset
		 * Tx MAC but that would also require
		 * resynchronization with status LEs. Reinitializing
		 * status LEs would affect the other port in dual MAC
		 * configuration so it should be avoided if we can.
		 * Due to lack of documentation it's all vague guess
		 * but it needs more investigation.
		 */
	}
	return (dispatch_wrk);
}

static void
yge_handle_hwerr(yge_port_t *port, uint32_t status)
{
	yge_dev_t	*dev = port->p_dev;

	if ((status & Y2_IS_PAR_RD1) != 0) {
		yge_error(NULL, port, "RAM buffer read parity error");
		/* Clear IRQ. */
		CSR_WRITE_2(dev, SELECT_RAM_BUFFER(port->p_port, B3_RI_CTRL),
		    RI_CLR_RD_PERR);
	}
	if ((status & Y2_IS_PAR_WR1) != 0) {
		yge_error(NULL, port, "RAM buffer write parity error");
		/* Clear IRQ. */
		CSR_WRITE_2(dev, SELECT_RAM_BUFFER(port->p_port, B3_RI_CTRL),
		    RI_CLR_WR_PERR);
	}
	if ((status & Y2_IS_PAR_MAC1) != 0) {
		yge_error(NULL, port, "Tx MAC parity error");
		/* Clear IRQ. */
		CSR_WRITE_4(dev, MR_ADDR(port->p_port, TX_GMF_CTRL_T),
		    GMF_CLI_TX_PE);
	}
	if ((status & Y2_IS_PAR_RX1) != 0) {
		yge_error(NULL, port, "Rx parity error");
		/* Clear IRQ. */
		CSR_WRITE_4(dev, Q_ADDR(port->p_rxq, Q_CSR), BMU_CLR_IRQ_PAR);
	}
	if ((status & (Y2_IS_TCP_TXS1 | Y2_IS_TCP_TXA1)) != 0) {
		yge_error(NULL, port, "TCP segmentation error");
		/* Clear IRQ. */
		CSR_WRITE_4(dev, Q_ADDR(port->p_txq, Q_CSR), BMU_CLR_IRQ_TCP);
	}
}

static void
yge_intr_hwerr(yge_dev_t *dev)
{
	uint32_t status;
	uint32_t tlphead[4];

	status = CSR_READ_4(dev, B0_HWE_ISRC);
	/* Time Stamp timer overflow. */
	if ((status & Y2_IS_TIST_OV) != 0)
		CSR_WRITE_1(dev, GMAC_TI_ST_CTRL, GMT_ST_CLR_IRQ);
	if ((status & Y2_IS_PCI_NEXP) != 0) {
		/*
		 * PCI Express Error occurred which is not described in PEX
		 * spec.
		 * This error is also mapped either to Master Abort(
		 * Y2_IS_MST_ERR) or Target Abort (Y2_IS_IRQ_STAT) bit and
		 * can only be cleared there.
		 */
		yge_error(dev, NULL, "PCI Express protocol violation error");
	}

	if ((status & (Y2_IS_MST_ERR | Y2_IS_IRQ_STAT)) != 0) {
		uint16_t v16;

		if ((status & Y2_IS_IRQ_STAT) != 0)
			yge_error(dev, NULL, "Unexpected IRQ Status error");
		if ((status & Y2_IS_MST_ERR) != 0)
			yge_error(dev, NULL, "Unexpected IRQ Master error");
		/* Reset all bits in the PCI status register. */
		v16 = pci_config_get16(dev->d_pcih, PCI_CONF_STAT);
		CSR_WRITE_1(dev, B2_TST_CTRL1, TST_CFG_WRITE_ON);
		pci_config_put16(dev->d_pcih, PCI_CONF_STAT, v16 |
		    PCI_STAT_S_PERROR | PCI_STAT_S_SYSERR | PCI_STAT_R_MAST_AB |
		    PCI_STAT_R_TARG_AB | PCI_STAT_PERROR);
		CSR_WRITE_1(dev, B2_TST_CTRL1, TST_CFG_WRITE_OFF);
	}

	/* Check for PCI Express Uncorrectable Error. */
	if ((status & Y2_IS_PCI_EXP) != 0) {
		uint32_t v32;

		/*
		 * On PCI Express bus bridges are called root complexes (RC).
		 * PCI Express errors are recognized by the root complex too,
		 * which requests the system to handle the problem. After
		 * error occurrence it may be that no access to the adapter
		 * may be performed any longer.
		 */

		v32 = CSR_PCI_READ_4(dev, PEX_UNC_ERR_STAT);
		if ((v32 & PEX_UNSUP_REQ) != 0) {
			/* Ignore unsupported request error. */
			yge_error(dev, NULL,
			    "Uncorrectable PCI Express error");
		}
		if ((v32 & (PEX_FATAL_ERRORS | PEX_POIS_TLP)) != 0) {
			int i;

			/* Get TLP header form Log Registers. */
			for (i = 0; i < 4; i++)
				tlphead[i] = CSR_PCI_READ_4(dev,
				    PEX_HEADER_LOG + i * 4);
			/* Check for vendor defined broadcast message. */
			if (!(tlphead[0] == 0x73004001 && tlphead[1] == 0x7f)) {
				dev->d_intrhwemask &= ~Y2_IS_PCI_EXP;
				CSR_WRITE_4(dev, B0_HWE_IMSK,
				    dev->d_intrhwemask);
				(void) CSR_READ_4(dev, B0_HWE_IMSK);
			}
		}
		/* Clear the interrupt. */
		CSR_WRITE_1(dev, B2_TST_CTRL1, TST_CFG_WRITE_ON);
		CSR_PCI_WRITE_4(dev, PEX_UNC_ERR_STAT, 0xffffffff);
		CSR_WRITE_1(dev, B2_TST_CTRL1, TST_CFG_WRITE_OFF);
	}

	if ((status & Y2_HWE_L1_MASK) != 0 && dev->d_port[YGE_PORT_A] != NULL)
		yge_handle_hwerr(dev->d_port[YGE_PORT_A], status);
	if ((status & Y2_HWE_L2_MASK) != 0 && dev->d_port[YGE_PORT_B] != NULL)
		yge_handle_hwerr(dev->d_port[YGE_PORT_B], status >> 8);
}

/*
 * Returns B_TRUE if there is potentially more work to do.
 */
static boolean_t
yge_handle_events(yge_dev_t *dev, mblk_t **heads, mblk_t **tails, int *txindex)
{
	yge_port_t *port;
	yge_ring_t *ring;
	uint32_t control, status;
	int cons, idx, len, pnum;
	mblk_t *mp;
	uint32_t rxprogs[2];

	rxprogs[0] = rxprogs[1] = 0;

	idx = CSR_READ_2(dev, STAT_PUT_IDX);
	if (idx == dev->d_stat_cons) {
		return (B_FALSE);
	}

	ring = &dev->d_status_ring;

	for (cons = dev->d_stat_cons; cons != idx; ) {
		/* Sync status LE. */
		SYNCENTRY(ring, cons, DDI_DMA_SYNC_FORKERNEL);
		control = GETCTRL(ring, cons);
		if ((control & HW_OWNER) == 0) {
			yge_error(dev, NULL, "Status descriptor error: "
			    "index %d, control %x", cons, control);
			break;
		}

		status = GETSTAT(ring, cons);

		control &= ~HW_OWNER;
		len = control & STLE_LEN_MASK;
		pnum = ((control >> 16) & 0x01);
		port = dev->d_port[pnum];
		if (port == NULL) {
			yge_error(dev, NULL, "Invalid port opcode: 0x%08x",
			    control & STLE_OP_MASK);
			goto finish;
		}

		switch (control & STLE_OP_MASK) {
		case OP_RXSTAT:
			mp = yge_rxeof(port, status, len);
			if (mp != NULL) {
				if (heads[pnum] == NULL)
					heads[pnum] = mp;
				else
					tails[pnum]->b_next = mp;
				tails[pnum] = mp;
			}

			rxprogs[pnum]++;
			break;

		case OP_TXINDEXLE:
			txindex[0] = status & STLE_TXA1_MSKL;
			txindex[1] =
			    ((status & STLE_TXA2_MSKL) >> STLE_TXA2_SHIFTL) |
			    ((len & STLE_TXA2_MSKH) << STLE_TXA2_SHIFTH);
			break;
		default:
			yge_error(dev, NULL, "Unhandled opcode: 0x%08x",
			    control & STLE_OP_MASK);
			break;
		}
finish:

		/* Give it back to HW. */
		PUTCTRL(ring, cons, control);
		SYNCENTRY(ring, cons, DDI_DMA_SYNC_FORDEV);

		YGE_INC(cons, YGE_STAT_RING_CNT);
		if (rxprogs[pnum] > dev->d_process_limit) {
			break;
		}
	}

	dev->d_stat_cons = cons;
	if (dev->d_stat_cons != CSR_READ_2(dev, STAT_PUT_IDX))
		return (B_TRUE);
	else
		return (B_FALSE);
}

/*ARGSUSED1*/
static uint_t
yge_intr(caddr_t arg1, caddr_t arg2)
{
	yge_dev_t	*dev;
	yge_port_t	*port1;
	yge_port_t	*port2;
	uint32_t	status;
	mblk_t		*heads[2], *tails[2];
	int		txindex[2];
	int		dispatch_wrk;

	dev = (void *)arg1;

	heads[0] = heads[1] = NULL;
	tails[0] = tails[1] = NULL;
	txindex[0] = txindex[1] = -1;
	dispatch_wrk = 0;

	port1 = dev->d_port[YGE_PORT_A];
	port2 = dev->d_port[YGE_PORT_B];

	RX_LOCK(dev);

	if (dev->d_suspended) {
		RX_UNLOCK(dev);
		return (DDI_INTR_UNCLAIMED);
	}

	/* Get interrupt source. */
	status = CSR_READ_4(dev, B0_Y2_SP_ISRC2);
	if (status == 0 || status == 0xffffffff ||
	    (status & dev->d_intrmask) == 0) { /* Stray interrupt ? */
		/* Reenable interrupts. */
		CSR_WRITE_4(dev, B0_Y2_SP_ICR, 2);
		RX_UNLOCK(dev);
		return (DDI_INTR_UNCLAIMED);
	}

	if ((status & Y2_IS_HW_ERR) != 0) {
		yge_intr_hwerr(dev);
	}

	if (status & Y2_IS_IRQ_MAC1) {
		dispatch_wrk |= yge_intr_gmac(port1);
	}
	if (status & Y2_IS_IRQ_MAC2) {
		dispatch_wrk |= yge_intr_gmac(port2);
	}

	if ((status & (Y2_IS_CHK_RX1 | Y2_IS_CHK_RX2)) != 0) {
		yge_error(NULL, status & Y2_IS_CHK_RX1 ? port1 : port2,
		    "Rx descriptor error");
		dev->d_intrmask &= ~(Y2_IS_CHK_RX1 | Y2_IS_CHK_RX2);
		CSR_WRITE_4(dev, B0_IMSK, dev->d_intrmask);
		(void) CSR_READ_4(dev, B0_IMSK);
	}
	if ((status & (Y2_IS_CHK_TXA1 | Y2_IS_CHK_TXA2)) != 0) {
		yge_error(NULL, status & Y2_IS_CHK_TXA1 ? port1 : port2,
		    "Tx descriptor error");
		dev->d_intrmask &= ~(Y2_IS_CHK_TXA1 | Y2_IS_CHK_TXA2);
		CSR_WRITE_4(dev, B0_IMSK, dev->d_intrmask);
		(void) CSR_READ_4(dev, B0_IMSK);
	}

	/* handle events until it returns false */
	while (yge_handle_events(dev, heads, tails, txindex))
		/* NOP */;

	/* Do receive/transmit events */
	if ((status & Y2_IS_STAT_BMU)) {
		CSR_WRITE_4(dev, STAT_CTRL, SC_STAT_CLR_IRQ);
	}

	/* Reenable interrupts. */
	CSR_WRITE_4(dev, B0_Y2_SP_ICR, 2);

	RX_UNLOCK(dev);

	if (dispatch_wrk) {
		yge_dispatch(dev, dispatch_wrk);
	}

	if (port1->p_running) {
		if (txindex[0] >= 0) {
			yge_txeof(port1, txindex[0]);
		}
		if (heads[0])
			mac_rx(port1->p_mh, NULL, heads[0]);
	} else {
		if (heads[0]) {
			mblk_t *mp;
			while ((mp = heads[0]) != NULL) {
				heads[0] = mp->b_next;
				freemsg(mp);
			}
		}
	}

	if (port2->p_running) {
		if (txindex[1] >= 0) {
			yge_txeof(port2, txindex[1]);
		}
		if (heads[1])
			mac_rx(port2->p_mh, NULL, heads[1]);
	} else {
		if (heads[1]) {
			mblk_t *mp;
			while ((mp = heads[1]) != NULL) {
				heads[1] = mp->b_next;
				freemsg(mp);
			}
		}
	}

	return (DDI_INTR_CLAIMED);
}

static void
yge_set_tx_stfwd(yge_port_t *port)
{
	yge_dev_t *dev = port->p_dev;
	int pnum = port->p_port;

	switch (dev->d_hw_id) {
	case CHIP_ID_YUKON_EX:
		if (dev->d_hw_rev == CHIP_REV_YU_EX_A0)
			goto yukon_ex_workaround;

		if (port->p_mtu > ETHERMTU)
			CSR_WRITE_4(dev, MR_ADDR(pnum, TX_GMF_CTRL_T),
			    TX_JUMBO_ENA | TX_STFW_ENA);
		else
			CSR_WRITE_4(dev, MR_ADDR(pnum, TX_GMF_CTRL_T),
			    TX_JUMBO_DIS | TX_STFW_ENA);
		break;
	default:
yukon_ex_workaround:
		if (port->p_mtu > ETHERMTU) {
			/* Set Tx GMAC FIFO Almost Empty Threshold. */
			CSR_WRITE_4(dev, MR_ADDR(pnum, TX_GMF_AE_THR),
			    MSK_ECU_JUMBO_WM << 16 | MSK_ECU_AE_THR);
			/* Disable Store & Forward mode for Tx. */
			CSR_WRITE_4(dev, MR_ADDR(pnum, TX_GMF_CTRL_T),
			    TX_JUMBO_ENA | TX_STFW_DIS);
		} else {
			/* Enable Store & Forward mode for Tx. */
			CSR_WRITE_4(dev, MR_ADDR(pnum, TX_GMF_CTRL_T),
			    TX_JUMBO_DIS | TX_STFW_ENA);
		}
		break;
	}
}

static void
yge_start_port(yge_port_t *port)
{
	yge_dev_t *dev = port->p_dev;
	uint16_t gmac;
	int32_t pnum;
	int32_t rxq;
	int32_t txq;
	uint32_t reg;

	pnum = port->p_port;
	txq = port->p_txq;
	rxq = port->p_rxq;

	if (port->p_mtu < ETHERMTU)
		port->p_framesize = ETHERMTU;
	else
		port->p_framesize = port->p_mtu;
	port->p_framesize += sizeof (struct ether_vlan_header);

	/*
	 * Note for the future, if we enable offloads:
	 * In Yukon EC Ultra, TSO & checksum offload is not
	 * supported for jumbo frame.
	 */

	/* GMAC Control reset */
	CSR_WRITE_4(dev, MR_ADDR(pnum, GMAC_CTRL), GMC_RST_SET);
	CSR_WRITE_4(dev, MR_ADDR(pnum, GMAC_CTRL), GMC_RST_CLR);
	CSR_WRITE_4(dev, MR_ADDR(pnum, GMAC_CTRL), GMC_F_LOOPB_OFF);
	if (dev->d_hw_id == CHIP_ID_YUKON_EX)
		CSR_WRITE_4(dev, MR_ADDR(pnum, GMAC_CTRL),
		    GMC_BYP_MACSECRX_ON | GMC_BYP_MACSECTX_ON |
		    GMC_BYP_RETR_ON);
	/*
	 * Initialize GMAC first such that speed/duplex/flow-control
	 * parameters are renegotiated with the interface is brought up.
	 */
	GMAC_WRITE_2(dev, pnum, GM_GP_CTRL, 0);

	/* Dummy read the Interrupt Source Register. */
	(void) CSR_READ_1(dev, MR_ADDR(pnum, GMAC_IRQ_SRC));

	/* Clear MIB stats. */
	yge_stats_clear(port);

	/* Disable FCS. */
	GMAC_WRITE_2(dev, pnum, GM_RX_CTRL, GM_RXCR_CRC_DIS);

	/* Setup Transmit Control Register. */
	GMAC_WRITE_2(dev, pnum, GM_TX_CTRL, TX_COL_THR(TX_COL_DEF));

	/* Setup Transmit Flow Control Register. */
	GMAC_WRITE_2(dev, pnum, GM_TX_FLOW_CTRL, 0xffff);

	/* Setup Transmit Parameter Register. */
	GMAC_WRITE_2(dev, pnum, GM_TX_PARAM,
	    TX_JAM_LEN_VAL(TX_JAM_LEN_DEF) | TX_JAM_IPG_VAL(TX_JAM_IPG_DEF) |
	    TX_IPG_JAM_DATA(TX_IPG_JAM_DEF) | TX_BACK_OFF_LIM(TX_BOF_LIM_DEF));

	gmac = DATA_BLIND_VAL(DATA_BLIND_DEF) |
	    GM_SMOD_VLAN_ENA | IPG_DATA_VAL(IPG_DATA_DEF);

	if (port->p_mtu > ETHERMTU)
		gmac |= GM_SMOD_JUMBO_ENA;
	GMAC_WRITE_2(dev, pnum, GM_SERIAL_MODE, gmac);

	/* Disable interrupts for counter overflows. */
	GMAC_WRITE_2(dev, pnum, GM_TX_IRQ_MSK, 0);
	GMAC_WRITE_2(dev, pnum, GM_RX_IRQ_MSK, 0);
	GMAC_WRITE_2(dev, pnum, GM_TR_IRQ_MSK, 0);

	/* Configure Rx MAC FIFO. */
	CSR_WRITE_4(dev, MR_ADDR(pnum, RX_GMF_CTRL_T), GMF_RST_SET);
	CSR_WRITE_4(dev, MR_ADDR(pnum, RX_GMF_CTRL_T), GMF_RST_CLR);
	reg = GMF_OPER_ON | GMF_RX_F_FL_ON;
	if (dev->d_hw_id == CHIP_ID_YUKON_FE_P ||
	    dev->d_hw_id == CHIP_ID_YUKON_EX)
		reg |= GMF_RX_OVER_ON;
	CSR_WRITE_4(dev, MR_ADDR(pnum, RX_GMF_CTRL_T), reg);

	/* Set receive filter. */
	yge_setrxfilt(port);

	/* Flush Rx MAC FIFO on any flow control or error. */
	CSR_WRITE_4(dev, MR_ADDR(pnum, RX_GMF_FL_MSK), GMR_FS_ANY_ERR);

	/*
	 * Set Rx FIFO flush threshold to 64 bytes + 1 FIFO word
	 * due to hardware hang on receipt of pause frames.
	 */
	reg = RX_GMF_FL_THR_DEF + 1;
	/* FE+ magic */
	if ((dev->d_hw_id == CHIP_ID_YUKON_FE_P) &&
	    (dev->d_hw_rev == CHIP_REV_YU_FE2_A0))
		reg = 0x178;

	CSR_WRITE_4(dev, MR_ADDR(pnum, RX_GMF_FL_THR), reg);

	/* Configure Tx MAC FIFO. */
	CSR_WRITE_4(dev, MR_ADDR(pnum, TX_GMF_CTRL_T), GMF_RST_SET);
	CSR_WRITE_4(dev, MR_ADDR(pnum, TX_GMF_CTRL_T), GMF_RST_CLR);
	CSR_WRITE_4(dev, MR_ADDR(pnum, TX_GMF_CTRL_T), GMF_OPER_ON);

	/* Disable hardware VLAN tag insertion/stripping. */
	CSR_WRITE_4(dev, MR_ADDR(pnum, RX_GMF_CTRL_T), RX_VLAN_STRIP_OFF);
	CSR_WRITE_4(dev, MR_ADDR(pnum, TX_GMF_CTRL_T), TX_VLAN_TAG_OFF);

	if ((port->p_flags & PORT_FLAG_RAMBUF) == 0) {
		/* Set Rx Pause threshold. */
		if ((dev->d_hw_id == CHIP_ID_YUKON_FE_P) &&
		    (dev->d_hw_rev == CHIP_REV_YU_FE2_A0)) {
			CSR_WRITE_1(dev, MR_ADDR(pnum, RX_GMF_LP_THR),
			    MSK_ECU_LLPP);
			CSR_WRITE_1(dev, MR_ADDR(pnum, RX_GMF_UP_THR),
			    MSK_FEP_ULPP);
		} else {
			CSR_WRITE_1(dev, MR_ADDR(pnum, RX_GMF_LP_THR),
			    MSK_ECU_LLPP);
			CSR_WRITE_1(dev, MR_ADDR(pnum, RX_GMF_UP_THR),
			    MSK_ECU_ULPP);
		}
		/* Configure store-and-forward for TX */
		yge_set_tx_stfwd(port);
	}

	if ((dev->d_hw_id == CHIP_ID_YUKON_FE_P) &&
	    (dev->d_hw_rev == CHIP_REV_YU_FE2_A0)) {
		/* Disable dynamic watermark */
		reg = CSR_READ_4(dev, MR_ADDR(pnum, TX_GMF_EA));
		reg &= ~TX_DYN_WM_ENA;
		CSR_WRITE_4(dev, MR_ADDR(pnum, TX_GMF_EA), reg);
	}

	/*
	 * Disable Force Sync bit and Alloc bit in Tx RAM interface
	 * arbiter as we don't use Sync Tx queue.
	 */
	CSR_WRITE_1(dev, MR_ADDR(pnum, TXA_CTRL),
	    TXA_DIS_FSYNC | TXA_DIS_ALLOC | TXA_STOP_RC);
	/* Enable the RAM Interface Arbiter. */
	CSR_WRITE_1(dev, MR_ADDR(pnum, TXA_CTRL), TXA_ENA_ARB);

	/* Setup RAM buffer. */
	yge_set_rambuffer(port);

	/* Disable Tx sync Queue. */
	CSR_WRITE_1(dev, RB_ADDR(port->p_txsq, RB_CTRL), RB_RST_SET);

	/* Setup Tx Queue Bus Memory Interface. */
	CSR_WRITE_4(dev, Q_ADDR(txq, Q_CSR), BMU_CLR_RESET);
	CSR_WRITE_4(dev, Q_ADDR(txq, Q_CSR), BMU_OPER_INIT);
	CSR_WRITE_4(dev, Q_ADDR(txq, Q_CSR), BMU_FIFO_OP_ON);
	CSR_WRITE_2(dev, Q_ADDR(txq, Q_WM), MSK_BMU_TX_WM);

	switch (dev->d_hw_id) {
	case CHIP_ID_YUKON_EC_U:
		if (dev->d_hw_rev == CHIP_REV_YU_EC_U_A0) {
			/* Fix for Yukon-EC Ultra: set BMU FIFO level */
			CSR_WRITE_2(dev, Q_ADDR(txq, Q_AL), MSK_ECU_TXFF_LEV);
		}
		break;
	case CHIP_ID_YUKON_EX:
		/*
		 * Yukon Extreme seems to have silicon bug for
		 * automatic Tx checksum calculation capability.
		 */
		if (dev->d_hw_rev == CHIP_REV_YU_EX_B0)
			CSR_WRITE_4(dev, Q_ADDR(txq, Q_F), F_TX_CHK_AUTO_OFF);
		break;
	}

	/* Setup Rx Queue Bus Memory Interface. */
	CSR_WRITE_4(dev, Q_ADDR(rxq, Q_CSR), BMU_CLR_RESET);
	CSR_WRITE_4(dev, Q_ADDR(rxq, Q_CSR), BMU_OPER_INIT);
	CSR_WRITE_4(dev, Q_ADDR(rxq, Q_CSR), BMU_FIFO_OP_ON);
	if (dev->d_bustype == PEX_BUS) {
		CSR_WRITE_2(dev, Q_ADDR(rxq, Q_WM), 0x80);
	} else {
		CSR_WRITE_2(dev, Q_ADDR(rxq, Q_WM), MSK_BMU_RX_WM);
	}
	if (dev->d_hw_id == CHIP_ID_YUKON_EC_U &&
	    dev->d_hw_rev >= CHIP_REV_YU_EC_U_A1) {
		/* MAC Rx RAM Read is controlled by hardware. */
		CSR_WRITE_4(dev, Q_ADDR(rxq, Q_F), F_M_RX_RAM_DIS);
	}

	yge_init_tx_ring(port);

	/* Disable Rx checksum offload and RSS hash. */
	CSR_WRITE_4(dev, Q_ADDR(rxq, Q_CSR),
	    BMU_DIS_RX_CHKSUM | BMU_DIS_RX_RSS_HASH);

	yge_init_rx_ring(port);

	/* Configure interrupt handling. */
	if (port == dev->d_port[YGE_PORT_A]) {
		dev->d_intrmask |= Y2_IS_PORT_A;
		dev->d_intrhwemask |= Y2_HWE_L1_MASK;
	} else if (port == dev->d_port[YGE_PORT_B]) {
		dev->d_intrmask |= Y2_IS_PORT_B;
		dev->d_intrhwemask |= Y2_HWE_L2_MASK;
	}
	CSR_WRITE_4(dev, B0_HWE_IMSK, dev->d_intrhwemask);
	(void) CSR_READ_4(dev, B0_HWE_IMSK);
	CSR_WRITE_4(dev, B0_IMSK, dev->d_intrmask);
	(void) CSR_READ_4(dev, B0_IMSK);

	/* Enable RX/TX GMAC */
	gmac = GMAC_READ_2(dev, pnum, GM_GP_CTRL);
	gmac |= (GM_GPCR_RX_ENA | GM_GPCR_TX_ENA);
	GMAC_WRITE_2(port->p_dev, port->p_port, GM_GP_CTRL, gmac);
	/* Read again to ensure writing. */
	(void) GMAC_READ_2(dev, pnum, GM_GP_CTRL);

	/* Reset TX timer */
	port->p_tx_wdog = 0;
}

static void
yge_set_rambuffer(yge_port_t *port)
{
	yge_dev_t *dev;
	int ltpp, utpp;
	int pnum;
	uint32_t rxq;
	uint32_t txq;

	dev = port->p_dev;
	pnum = port->p_port;
	rxq = port->p_rxq;
	txq = port->p_txq;

	if ((port->p_flags & PORT_FLAG_RAMBUF) == 0)
		return;

	/* Setup Rx Queue. */
	CSR_WRITE_1(dev, RB_ADDR(rxq, RB_CTRL), RB_RST_CLR);
	CSR_WRITE_4(dev, RB_ADDR(rxq, RB_START), dev->d_rxqstart[pnum] / 8);
	CSR_WRITE_4(dev, RB_ADDR(rxq, RB_END), dev->d_rxqend[pnum] / 8);
	CSR_WRITE_4(dev, RB_ADDR(rxq, RB_WP), dev->d_rxqstart[pnum] / 8);
	CSR_WRITE_4(dev, RB_ADDR(rxq, RB_RP), dev->d_rxqstart[pnum] / 8);

	utpp =
	    (dev->d_rxqend[pnum] + 1 - dev->d_rxqstart[pnum] - RB_ULPP) / 8;
	ltpp =
	    (dev->d_rxqend[pnum] + 1 - dev->d_rxqstart[pnum] - RB_LLPP_B) / 8;

	if (dev->d_rxqsize < MSK_MIN_RXQ_SIZE)
		ltpp += (RB_LLPP_B - RB_LLPP_S) / 8;

	CSR_WRITE_4(dev, RB_ADDR(rxq, RB_RX_UTPP), utpp);
	CSR_WRITE_4(dev, RB_ADDR(rxq, RB_RX_LTPP), ltpp);
	/* Set Rx priority(RB_RX_UTHP/RB_RX_LTHP) thresholds? */

	CSR_WRITE_1(dev, RB_ADDR(rxq, RB_CTRL), RB_ENA_OP_MD);
	(void) CSR_READ_1(dev, RB_ADDR(rxq, RB_CTRL));

	/* Setup Tx Queue. */
	CSR_WRITE_1(dev, RB_ADDR(txq, RB_CTRL), RB_RST_CLR);
	CSR_WRITE_4(dev, RB_ADDR(txq, RB_START), dev->d_txqstart[pnum] / 8);
	CSR_WRITE_4(dev, RB_ADDR(txq, RB_END),  dev->d_txqend[pnum] / 8);
	CSR_WRITE_4(dev, RB_ADDR(txq, RB_WP), dev->d_txqstart[pnum] / 8);
	CSR_WRITE_4(dev, RB_ADDR(txq, RB_RP), dev->d_txqstart[pnum] / 8);
	/* Enable Store & Forward for Tx side. */
	CSR_WRITE_1(dev, RB_ADDR(txq, RB_CTRL), RB_ENA_STFWD);
	CSR_WRITE_1(dev, RB_ADDR(txq, RB_CTRL), RB_ENA_OP_MD);
	(void) CSR_READ_1(dev, RB_ADDR(txq, RB_CTRL));
}

static void
yge_set_prefetch(yge_dev_t *dev, int qaddr, yge_ring_t *ring)
{
	/* Reset the prefetch unit. */
	CSR_WRITE_4(dev, Y2_PREF_Q_ADDR(qaddr, PREF_UNIT_CTRL_REG),
	    PREF_UNIT_RST_SET);
	CSR_WRITE_4(dev, Y2_PREF_Q_ADDR(qaddr, PREF_UNIT_CTRL_REG),
	    PREF_UNIT_RST_CLR);
	/* Set LE base address. */
	CSR_WRITE_4(dev, Y2_PREF_Q_ADDR(qaddr, PREF_UNIT_ADDR_LOW_REG),
	    YGE_ADDR_LO(ring->r_paddr));
	CSR_WRITE_4(dev, Y2_PREF_Q_ADDR(qaddr, PREF_UNIT_ADDR_HI_REG),
	    YGE_ADDR_HI(ring->r_paddr));
	/* Set the list last index. */
	CSR_WRITE_2(dev, Y2_PREF_Q_ADDR(qaddr, PREF_UNIT_LAST_IDX_REG),
	    ring->r_num - 1);
	/* Turn on prefetch unit. */
	CSR_WRITE_4(dev, Y2_PREF_Q_ADDR(qaddr, PREF_UNIT_CTRL_REG),
	    PREF_UNIT_OP_ON);
	/* Dummy read to ensure write. */
	(void) CSR_READ_4(dev, Y2_PREF_Q_ADDR(qaddr, PREF_UNIT_CTRL_REG));
}

static void
yge_stop_port(yge_port_t *port)
{
	yge_dev_t *dev = port->p_dev;
	int pnum = port->p_port;
	uint32_t txq = port->p_txq;
	uint32_t rxq = port->p_rxq;
	uint32_t val;
	int i;

	dev = port->p_dev;

	/*
	 * shutdown timeout
	 */
	port->p_tx_wdog = 0;

	/* Disable interrupts. */
	if (pnum == YGE_PORT_A) {
		dev->d_intrmask &= ~Y2_IS_PORT_A;
		dev->d_intrhwemask &= ~Y2_HWE_L1_MASK;
	} else {
		dev->d_intrmask &= ~Y2_IS_PORT_B;
		dev->d_intrhwemask &= ~Y2_HWE_L2_MASK;
	}
	CSR_WRITE_4(dev, B0_HWE_IMSK, dev->d_intrhwemask);
	(void) CSR_READ_4(dev, B0_HWE_IMSK);
	CSR_WRITE_4(dev, B0_IMSK, dev->d_intrmask);
	(void) CSR_READ_4(dev, B0_IMSK);

	/* Disable Tx/Rx MAC. */
	val = GMAC_READ_2(dev, pnum, GM_GP_CTRL);
	val &= ~(GM_GPCR_RX_ENA | GM_GPCR_TX_ENA);
	GMAC_WRITE_2(dev, pnum, GM_GP_CTRL, val);
	/* Read again to ensure writing. */
	(void) GMAC_READ_2(dev, pnum, GM_GP_CTRL);

	/* Update stats and clear counters. */
	yge_stats_update(port);

	/* Stop Tx BMU. */
	CSR_WRITE_4(dev, Q_ADDR(txq, Q_CSR), BMU_STOP);
	val = CSR_READ_4(dev, Q_ADDR(txq, Q_CSR));
	for (i = 0; i < YGE_TIMEOUT; i += 10) {
		if ((val & (BMU_STOP | BMU_IDLE)) == 0) {
			CSR_WRITE_4(dev, Q_ADDR(txq, Q_CSR), BMU_STOP);
			val = CSR_READ_4(dev, Q_ADDR(txq, Q_CSR));
		} else
			break;
		drv_usecwait(10);
	}
	/* This is probably fairly catastrophic. */
	if ((val & (BMU_STOP | BMU_IDLE)) == 0)
		yge_error(NULL, port, "Tx BMU stop failed");

	CSR_WRITE_1(dev, RB_ADDR(txq, RB_CTRL), RB_RST_SET | RB_DIS_OP_MD);

	/* Disable all GMAC interrupt. */
	CSR_WRITE_1(dev, MR_ADDR(pnum, GMAC_IRQ_MSK), 0);

	/* Disable the RAM Interface Arbiter. */
	CSR_WRITE_1(dev, MR_ADDR(pnum, TXA_CTRL), TXA_DIS_ARB);

	/* Reset the PCI FIFO of the async Tx queue */
	CSR_WRITE_4(dev, Q_ADDR(txq, Q_CSR), BMU_RST_SET | BMU_FIFO_RST);

	/* Reset the Tx prefetch units. */
	CSR_WRITE_4(dev, Y2_PREF_Q_ADDR(txq, PREF_UNIT_CTRL_REG),
	    PREF_UNIT_RST_SET);

	/* Reset the RAM Buffer async Tx queue. */
	CSR_WRITE_1(dev, RB_ADDR(txq, RB_CTRL), RB_RST_SET);

	/* Reset Tx MAC FIFO. */
	CSR_WRITE_4(dev, MR_ADDR(pnum, TX_GMF_CTRL_T), GMF_RST_SET);
	/* Set Pause Off. */
	CSR_WRITE_4(dev, MR_ADDR(pnum, GMAC_CTRL), GMC_PAUSE_OFF);

	/*
	 * The Rx Stop command will not work for Yukon-2 if the BMU does not
	 * reach the end of packet and since we can't make sure that we have
	 * incoming data, we must reset the BMU while it is not during a DMA
	 * transfer. Since it is possible that the Rx path is still active,
	 * the Rx RAM buffer will be stopped first, so any possible incoming
	 * data will not trigger a DMA. After the RAM buffer is stopped, the
	 * BMU is polled until any DMA in progress is ended and only then it
	 * will be reset.
	 */

	/* Disable the RAM Buffer receive queue. */
	CSR_WRITE_1(dev, RB_ADDR(rxq, RB_CTRL), RB_DIS_OP_MD);
	for (i = 0; i < YGE_TIMEOUT; i += 10) {
		if (CSR_READ_1(dev, RB_ADDR(rxq, Q_RSL)) ==
		    CSR_READ_1(dev, RB_ADDR(rxq, Q_RL)))
			break;
		drv_usecwait(10);
	}
	/* This is probably nearly a fatal error. */
	if (i == YGE_TIMEOUT)
		yge_error(NULL, port, "Rx BMU stop failed");

	CSR_WRITE_4(dev, Q_ADDR(rxq, Q_CSR), BMU_RST_SET | BMU_FIFO_RST);
	/* Reset the Rx prefetch unit. */
	CSR_WRITE_4(dev, Y2_PREF_Q_ADDR(rxq, PREF_UNIT_CTRL_REG),
	    PREF_UNIT_RST_SET);
	/* Reset the RAM Buffer receive queue. */
	CSR_WRITE_1(dev, RB_ADDR(rxq, RB_CTRL), RB_RST_SET);
	/* Reset Rx MAC FIFO. */
	CSR_WRITE_4(dev, MR_ADDR(pnum, RX_GMF_CTRL_T), GMF_RST_SET);
}

/*
 * When GM_PAR_MIB_CLR bit of GM_PHY_ADDR is set, reading lower
 * counter clears high 16 bits of the counter such that accessing
 * lower 16 bits should be the last operation.
 */
#define	YGE_READ_MIB32(x, y)					\
	GMAC_READ_4(dev, x, y)

#define	YGE_READ_MIB64(x, y)					\
	((((uint64_t)YGE_READ_MIB32(x, (y) + 8)) << 32) +	\
	    (uint64_t)YGE_READ_MIB32(x, y))

static void
yge_stats_clear(yge_port_t *port)
{
	yge_dev_t *dev;
	uint16_t gmac;
	int32_t pnum;

	pnum = port->p_port;
	dev = port->p_dev;

	/* Set MIB Clear Counter Mode. */
	gmac = GMAC_READ_2(dev, pnum, GM_PHY_ADDR);
	GMAC_WRITE_2(dev, pnum, GM_PHY_ADDR, gmac | GM_PAR_MIB_CLR);
	/* Read all MIB Counters with Clear Mode set. */
	for (int i = GM_RXF_UC_OK; i <= GM_TXE_FIFO_UR; i += 4)
		(void) YGE_READ_MIB32(pnum, i);
	/* Clear MIB Clear Counter Mode. */
	gmac &= ~GM_PAR_MIB_CLR;
	GMAC_WRITE_2(dev, pnum, GM_PHY_ADDR, gmac);
}

static void
yge_stats_update(yge_port_t *port)
{
	yge_dev_t *dev;
	struct yge_hw_stats *stats;
	uint16_t gmac;
	int32_t	pnum;

	dev = port->p_dev;
	pnum = port->p_port;

	if (dev->d_suspended || !port->p_running) {
		return;
	}
	stats = &port->p_stats;
	/* Set MIB Clear Counter Mode. */
	gmac = GMAC_READ_2(dev, pnum, GM_PHY_ADDR);
	GMAC_WRITE_2(dev, pnum, GM_PHY_ADDR, gmac | GM_PAR_MIB_CLR);

	/* Rx stats. */
	stats->rx_ucast_frames +=	YGE_READ_MIB32(pnum, GM_RXF_UC_OK);
	stats->rx_bcast_frames +=	YGE_READ_MIB32(pnum, GM_RXF_BC_OK);
	stats->rx_pause_frames +=	YGE_READ_MIB32(pnum, GM_RXF_MPAUSE);
	stats->rx_mcast_frames +=	YGE_READ_MIB32(pnum, GM_RXF_MC_OK);
	stats->rx_crc_errs +=		YGE_READ_MIB32(pnum, GM_RXF_FCS_ERR);
	(void) YGE_READ_MIB32(pnum, GM_RXF_SPARE1);
	stats->rx_good_octets +=	YGE_READ_MIB64(pnum, GM_RXO_OK_LO);
	stats->rx_bad_octets +=		YGE_READ_MIB64(pnum, GM_RXO_ERR_LO);
	stats->rx_runts +=		YGE_READ_MIB32(pnum, GM_RXF_SHT);
	stats->rx_runt_errs +=		YGE_READ_MIB32(pnum, GM_RXE_FRAG);
	stats->rx_pkts_64 +=		YGE_READ_MIB32(pnum, GM_RXF_64B);
	stats->rx_pkts_65_127 +=	YGE_READ_MIB32(pnum, GM_RXF_127B);
	stats->rx_pkts_128_255 +=	YGE_READ_MIB32(pnum, GM_RXF_255B);
	stats->rx_pkts_256_511 +=	YGE_READ_MIB32(pnum, GM_RXF_511B);
	stats->rx_pkts_512_1023 +=	YGE_READ_MIB32(pnum, GM_RXF_1023B);
	stats->rx_pkts_1024_1518 +=	YGE_READ_MIB32(pnum, GM_RXF_1518B);
	stats->rx_pkts_1519_max +=	YGE_READ_MIB32(pnum, GM_RXF_MAX_SZ);
	stats->rx_pkts_too_long +=	YGE_READ_MIB32(pnum, GM_RXF_LNG_ERR);
	stats->rx_pkts_jabbers +=	YGE_READ_MIB32(pnum, GM_RXF_JAB_PKT);
	(void) YGE_READ_MIB32(pnum, GM_RXF_SPARE2);
	stats->rx_fifo_oflows +=	YGE_READ_MIB32(pnum, GM_RXE_FIFO_OV);
	(void) YGE_READ_MIB32(pnum, GM_RXF_SPARE3);

	/* Tx stats. */
	stats->tx_ucast_frames +=	YGE_READ_MIB32(pnum, GM_TXF_UC_OK);
	stats->tx_bcast_frames +=	YGE_READ_MIB32(pnum, GM_TXF_BC_OK);
	stats->tx_pause_frames +=	YGE_READ_MIB32(pnum, GM_TXF_MPAUSE);
	stats->tx_mcast_frames +=	YGE_READ_MIB32(pnum, GM_TXF_MC_OK);
	stats->tx_octets +=		YGE_READ_MIB64(pnum, GM_TXO_OK_LO);
	stats->tx_pkts_64 +=		YGE_READ_MIB32(pnum, GM_TXF_64B);
	stats->tx_pkts_65_127 +=	YGE_READ_MIB32(pnum, GM_TXF_127B);
	stats->tx_pkts_128_255 +=	YGE_READ_MIB32(pnum, GM_TXF_255B);
	stats->tx_pkts_256_511 +=	YGE_READ_MIB32(pnum, GM_TXF_511B);
	stats->tx_pkts_512_1023 +=	YGE_READ_MIB32(pnum, GM_TXF_1023B);
	stats->tx_pkts_1024_1518 +=	YGE_READ_MIB32(pnum, GM_TXF_1518B);
	stats->tx_pkts_1519_max +=	YGE_READ_MIB32(pnum, GM_TXF_MAX_SZ);
	(void) YGE_READ_MIB32(pnum, GM_TXF_SPARE1);
	stats->tx_colls +=		YGE_READ_MIB32(pnum, GM_TXF_COL);
	stats->tx_late_colls +=		YGE_READ_MIB32(pnum, GM_TXF_LAT_COL);
	stats->tx_excess_colls +=	YGE_READ_MIB32(pnum, GM_TXF_ABO_COL);
	stats->tx_multi_colls +=	YGE_READ_MIB32(pnum, GM_TXF_MUL_COL);
	stats->tx_single_colls +=	YGE_READ_MIB32(pnum, GM_TXF_SNG_COL);
	stats->tx_underflows +=		YGE_READ_MIB32(pnum, GM_TXE_FIFO_UR);
	/* Clear MIB Clear Counter Mode. */
	gmac &= ~GM_PAR_MIB_CLR;
	GMAC_WRITE_2(dev, pnum, GM_PHY_ADDR, gmac);
}

#undef YGE_READ_MIB32
#undef YGE_READ_MIB64

uint32_t
yge_hashbit(const uint8_t *addr)
{
	int		idx;
	int		bit;
	uint_t		data;
	uint32_t	crc;
#define	POLY_BE	0x04c11db7

	crc = 0xffffffff;
	for (idx = 0; idx < 6; idx++) {
		for (data = *addr++, bit = 0; bit < 8; bit++, data >>= 1) {
			crc = (crc << 1)
			    ^ ((((crc >> 31) ^ data) & 1) ? POLY_BE : 0);
		}
	}
#undef	POLY_BE

	return (crc % 64);
}

int
yge_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	yge_port_t	*port = arg;
	struct yge_hw_stats *stats = &port->p_stats;

	if (stat == MAC_STAT_IFSPEED) {
		/*
		 * This is the first stat we are asked about.  We update only
		 * for this stat, to avoid paying the hefty cost of the update
		 * once for each stat.
		 */
		DEV_LOCK(port->p_dev);
		yge_stats_update(port);
		DEV_UNLOCK(port->p_dev);
	}

	if (mii_m_getstat(port->p_mii, stat, val) == 0) {
		return (0);
	}

	switch (stat) {
	case MAC_STAT_MULTIRCV:
		*val = stats->rx_mcast_frames;
		break;

	case MAC_STAT_BRDCSTRCV:
		*val = stats->rx_bcast_frames;
		break;

	case MAC_STAT_MULTIXMT:
		*val = stats->tx_mcast_frames;
		break;

	case MAC_STAT_BRDCSTXMT:
		*val = stats->tx_bcast_frames;
		break;

	case MAC_STAT_IPACKETS:
		*val = stats->rx_ucast_frames;
		break;

	case MAC_STAT_RBYTES:
		*val = stats->rx_good_octets;
		break;

	case MAC_STAT_OPACKETS:
		*val = stats->tx_ucast_frames;
		break;

	case MAC_STAT_OBYTES:
		*val = stats->tx_octets;
		break;

	case MAC_STAT_NORCVBUF:
		*val = stats->rx_nobuf;
		break;

	case MAC_STAT_COLLISIONS:
		*val = stats->tx_colls;
		break;

	case ETHER_STAT_ALIGN_ERRORS:
		*val = stats->rx_runt_errs;
		break;

	case ETHER_STAT_FCS_ERRORS:
		*val = stats->rx_crc_errs;
		break;

	case ETHER_STAT_FIRST_COLLISIONS:
		*val  = stats->tx_single_colls;
		break;

	case ETHER_STAT_MULTI_COLLISIONS:
		*val = stats->tx_multi_colls;
		break;

	case ETHER_STAT_TX_LATE_COLLISIONS:
		*val = stats->tx_late_colls;
		break;

	case ETHER_STAT_EX_COLLISIONS:
		*val = stats->tx_excess_colls;
		break;

	case ETHER_STAT_TOOLONG_ERRORS:
		*val = stats->rx_pkts_too_long;
		break;

	case MAC_STAT_OVERFLOWS:
		*val = stats->rx_fifo_oflows;
		break;

	case MAC_STAT_UNDERFLOWS:
		*val = stats->tx_underflows;
		break;

	case ETHER_STAT_TOOSHORT_ERRORS:
		*val = stats->rx_runts;
		break;

	case ETHER_STAT_JABBER_ERRORS:
		*val = stats->rx_pkts_jabbers;
		break;

	default:
		return (ENOTSUP);
	}
	return (0);
}

int
yge_m_start(void *arg)
{
	yge_port_t	*port = arg;

	DEV_LOCK(port->p_dev);

	/*
	 * We defer resource allocation to this point, because we
	 * don't want to waste DMA resources that might better be used
	 * elsewhere, if the port is not actually being used.
	 *
	 * Furthermore, this gives us a more graceful handling of dynamic
	 * MTU modification.
	 */
	if (yge_txrx_dma_alloc(port) != DDI_SUCCESS) {
		/* Make sure we free up partially allocated resources. */
		yge_txrx_dma_free(port);
		DEV_UNLOCK(port->p_dev);
		return (ENOMEM);
	}

	if (!port->p_dev->d_suspended)
		yge_start_port(port);
	port->p_running = B_TRUE;
	DEV_UNLOCK(port->p_dev);

	mii_start(port->p_mii);

	return (0);
}

void
yge_m_stop(void *arg)
{
	yge_port_t	*port = arg;
	yge_dev_t	*dev = port->p_dev;

	DEV_LOCK(dev);
	if (!dev->d_suspended)
		yge_stop_port(port);

	port->p_running = B_FALSE;

	/* Release resources we don't need */
	yge_txrx_dma_free(port);
	DEV_UNLOCK(dev);
}

int
yge_m_promisc(void *arg, boolean_t on)
{
	yge_port_t	*port = arg;

	DEV_LOCK(port->p_dev);

	/* Save current promiscuous mode. */
	port->p_promisc = on;
	yge_setrxfilt(port);

	DEV_UNLOCK(port->p_dev);

	return (0);
}

int
yge_m_multicst(void *arg, boolean_t add, const uint8_t *addr)
{
	yge_port_t	*port = arg;
	int		bit;
	boolean_t	update;

	bit = yge_hashbit(addr);
	ASSERT(bit < 64);

	DEV_LOCK(port->p_dev);
	if (add) {
		if (port->p_mccount[bit] == 0) {
			/* Set the corresponding bit in the hash table. */
			port->p_mchash[bit / 32] |= (1 << (bit % 32));
			update = B_TRUE;
		}
		port->p_mccount[bit]++;
	} else {
		ASSERT(port->p_mccount[bit] > 0);
		port->p_mccount[bit]--;
		if (port->p_mccount[bit] == 0) {
			port->p_mchash[bit / 32] &= ~(1 << (bit % 32));
			update = B_TRUE;
		}
	}

	if (update) {
		yge_setrxfilt(port);
	}
	DEV_UNLOCK(port->p_dev);
	return (0);
}

int
yge_m_unicst(void *arg, const uint8_t *macaddr)
{
	yge_port_t	*port = arg;

	DEV_LOCK(port->p_dev);

	bcopy(macaddr, port->p_curraddr, ETHERADDRL);
	yge_setrxfilt(port);

	DEV_UNLOCK(port->p_dev);

	return (0);
}

mblk_t *
yge_m_tx(void *arg, mblk_t *mp)
{
	yge_port_t	*port = arg;
	mblk_t		*nmp;
	int		enq = 0;
	uint32_t	ridx;
	int		idx;
	boolean_t	resched = B_FALSE;

	TX_LOCK(port->p_dev);

	if (port->p_dev->d_suspended) {

		TX_UNLOCK(port->p_dev);

		while ((nmp = mp) != NULL) {
			/* carrier_errors++; */
			mp = mp->b_next;
			freemsg(nmp);
		}
		return (NULL);
	}

	/* attempt a reclaim */
	ridx = port->p_port == YGE_PORT_A ?
	    STAT_TXA1_RIDX : STAT_TXA2_RIDX;
	idx = CSR_READ_2(port->p_dev, ridx);
	if (port->p_tx_cons != idx)
		resched = yge_txeof_locked(port, idx);

	while (mp != NULL) {
		nmp = mp->b_next;
		mp->b_next = NULL;

		if (!yge_send(port, mp)) {
			mp->b_next = nmp;
			break;
		}
		enq++;
		mp = nmp;

	}
	if (enq > 0) {
		/* Transmit */
		CSR_WRITE_2(port->p_dev,
		    Y2_PREF_Q_ADDR(port->p_txq, PREF_UNIT_PUT_IDX_REG),
		    port->p_tx_prod);
	}

	TX_UNLOCK(port->p_dev);

	if (resched)
		mac_tx_update(port->p_mh);

	return (mp);
}

void
yge_m_ioctl(void *arg, queue_t *wq, mblk_t *mp)
{
#ifdef	YGE_MII_LOOPBACK
	/* LINTED E_FUNC_SET_NOT_USED */
	yge_port_t	*port = arg;

	/*
	 * Right now, the MII common layer does not properly handle
	 * loopback on these PHYs.  Fixing this should be done at some
	 * point in the future.
	 */
	if (mii_m_loop_ioctl(port->p_mii, wq, mp))
		return;
#else
	_NOTE(ARGUNUSED(arg));
#endif

	miocnak(wq, mp, 0, EINVAL);
}

int
yge_m_setprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, const void *pr_val)
{
	yge_port_t	*port = arg;
	uint32_t	new_mtu;
	int err = 0;

	err = mii_m_setprop(port->p_mii, pr_name, pr_num, pr_valsize, pr_val);
	if (err != ENOTSUP) {
		return (err);
	}

	DEV_LOCK(port->p_dev);

	switch (pr_num) {
	case MAC_PROP_MTU:
		if (pr_valsize < sizeof (new_mtu)) {
			err = EINVAL;
			break;
		}
		bcopy(pr_val, &new_mtu, sizeof (new_mtu));
		if (new_mtu == port->p_mtu) {
			/* no change */
			err = 0;
			break;
		}
		if (new_mtu < ETHERMTU) {
			yge_error(NULL, port,
			    "Maximum MTU size too small: %d", new_mtu);
			err = EINVAL;
			break;
		}
		if (new_mtu > (port->p_flags & PORT_FLAG_NOJUMBO ?
		    ETHERMTU : YGE_JUMBO_MTU)) {
			yge_error(NULL, port,
			    "Maximum MTU size too big: %d", new_mtu);
			err = EINVAL;
			break;
		}
		if (port->p_running) {
			yge_error(NULL, port,
			    "Unable to change maximum MTU while running");
			err = EBUSY;
			break;
		}


		/*
		 * NB: It would probably be better not to hold the
		 * DEVLOCK, but releasing it creates a potential race
		 * if m_start is called concurrently.
		 *
		 * It turns out that the MAC layer guarantees safety
		 * for us here by using a cut out for this kind of
		 * notification call back anyway.
		 *
		 * See R8. and R14. in mac.c locking comments, which read
		 * as follows:
		 *
		 * R8. Since it is not guaranteed (see R14) that
		 * drivers won't hold locks across mac driver
		 * interfaces, the MAC layer must provide a cut out
		 * for control interfaces like upcall notifications
		 * and start them in a separate thread.
		 *
		 * R14. It would be preferable if MAC drivers don't
		 * hold any locks across any mac call. However at a
		 * minimum they must not hold any locks across data
		 * upcalls. They must also make sure that all
		 * references to mac data structures are cleaned up
		 * and that it is single threaded at mac_unregister
		 * time.
		 */
		err = mac_maxsdu_update(port->p_mh, new_mtu);
		if (err != 0) {
			/* This should never occur! */
			yge_error(NULL, port,
			    "Failed notifying GLDv3 of new maximum MTU");
		} else {
			port->p_mtu = new_mtu;
		}
		break;

	default:
		err = ENOTSUP;
		break;
	}

err:
	DEV_UNLOCK(port->p_dev);

	return (err);
}

int
yge_m_getprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, void *pr_val)
{
	yge_port_t	*port = arg;

	return (mii_m_getprop(port->p_mii, pr_name, pr_num, pr_valsize,
	    pr_val));
}

static void
yge_m_propinfo(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    mac_prop_info_handle_t prh)
{
	yge_port_t	*port = arg;

	switch (pr_num) {
	case MAC_PROP_MTU:
		mac_prop_info_set_range_uint32(prh, ETHERMTU,
		    port->p_flags & PORT_FLAG_NOJUMBO ?
		    ETHERMTU : YGE_JUMBO_MTU);
		break;
	default:
		mii_m_propinfo(port->p_mii, pr_name, pr_num, prh);
		break;
	}
}

void
yge_dispatch(yge_dev_t *dev, int flag)
{
	TASK_LOCK(dev);
	dev->d_task_flags |= flag;
	TASK_SIGNAL(dev);
	TASK_UNLOCK(dev);
}

void
yge_task(void *arg)
{
	yge_dev_t	*dev = arg;
	int		flags;

	for (;;) {

		TASK_LOCK(dev);
		while ((flags = dev->d_task_flags) == 0)
			TASK_WAIT(dev);

		dev->d_task_flags = 0;
		TASK_UNLOCK(dev);

		/*
		 * This should be the first thing after the sleep so if we are
		 * requested to exit we do that and not waste time doing work
		 * we will then abandone.
		 */
		if (flags & YGE_TASK_EXIT)
			break;

		/* all processing done without holding locks */
		if (flags & YGE_TASK_RESTART)
			yge_restart_task(dev);
	}
}

void
yge_error(yge_dev_t *dev, yge_port_t *port, char *fmt, ...)
{
	va_list		ap;
	char		buf[256];
	int		ppa;

	va_start(ap, fmt);
	(void) vsnprintf(buf, sizeof (buf), fmt, ap);
	va_end(ap);

	if (dev == NULL && port == NULL) {
		cmn_err(CE_WARN, "yge: %s", buf);
	} else {
		if (port != NULL)
			ppa = port->p_ppa;
		else
			ppa = ddi_get_instance(dev->d_dip);
		cmn_err(CE_WARN, "yge%d: %s", ppa, buf);
	}
}

static int
yge_ddi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	yge_dev_t	*dev;
	int		rv;

	switch (cmd) {
	case DDI_ATTACH:
		dev = kmem_zalloc(sizeof (*dev), KM_SLEEP);
		dev->d_port[0] = kmem_zalloc(sizeof (yge_port_t), KM_SLEEP);
		dev->d_port[1] = kmem_zalloc(sizeof (yge_port_t), KM_SLEEP);
		dev->d_dip = dip;
		ddi_set_driver_private(dip, dev);

		dev->d_port[0]->p_port = 0;
		dev->d_port[0]->p_dev = dev;
		dev->d_port[1]->p_port = 0;
		dev->d_port[1]->p_dev = dev;

		rv = yge_attach(dev);
		if (rv != DDI_SUCCESS) {
			ddi_set_driver_private(dip, 0);
			kmem_free(dev->d_port[1], sizeof (yge_port_t));
			kmem_free(dev->d_port[0], sizeof (yge_port_t));
			kmem_free(dev, sizeof (*dev));
		}
		return (rv);

	case DDI_RESUME:
		dev = ddi_get_driver_private(dip);
		ASSERT(dev != NULL);
		return (yge_resume(dev));

	default:
		return (DDI_FAILURE);
	}
}

static int
yge_ddi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	yge_dev_t	*dev;
	mac_handle_t	mh;

	switch (cmd) {
	case DDI_DETACH:

		dev = ddi_get_driver_private(dip);

		/* attempt to unregister MACs from Nemo */
		for (int i = 0; i < dev->d_num_port; i++) {

			if (((mh = dev->d_port[i]->p_mh) != NULL) &&
			    (mac_disable(mh) != 0)) {
				/*
				 * We'd really like a mac_enable to reenable
				 * any MACs that we previously disabled.  Too
				 * bad GLDv3 doesn't have one.
				 */
				return (DDI_FAILURE);
			}
		}

		ASSERT(dip == dev->d_dip);
		yge_detach(dev);
		ddi_set_driver_private(dip, 0);
		for (int i = 0; i < dev->d_num_port; i++) {
			if ((mh = dev->d_port[i]->p_mh) != NULL) {
				/* This can't fail after mac_disable above. */
				(void) mac_unregister(mh);
			}
		}
		kmem_free(dev->d_port[1], sizeof (yge_port_t));
		kmem_free(dev->d_port[0], sizeof (yge_port_t));
		kmem_free(dev, sizeof (*dev));
		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		dev = ddi_get_driver_private(dip);
		ASSERT(dev != NULL);
		return (yge_suspend(dev));

	default:
		return (DDI_FAILURE);
	}
}

static int
yge_quiesce(dev_info_t *dip)
{
	yge_dev_t *dev;

	dev = ddi_get_driver_private(dip);
	ASSERT(dev != NULL);

	/* NB: No locking!  We are called in single threaded context */
	for (int i = 0; i < dev->d_num_port; i++) {
		yge_port_t *port = dev->d_port[i];
		if (port->p_running)
			yge_stop_port(port);
	}

	/* Disable all interrupts. */
	CSR_WRITE_4(dev, B0_IMSK, 0);
	(void) CSR_READ_4(dev, B0_IMSK);
	CSR_WRITE_4(dev, B0_HWE_IMSK, 0);
	(void) CSR_READ_4(dev, B0_HWE_IMSK);

	/* Put hardware into reset. */
	CSR_WRITE_2(dev, B0_CTST, CS_RST_SET);

	return (DDI_SUCCESS);
}

/*
 * Stream information
 */
DDI_DEFINE_STREAM_OPS(yge_devops, nulldev, nulldev, yge_ddi_attach,
    yge_ddi_detach, nodev, NULL, D_MP, NULL, yge_quiesce);

/*
 * Module linkage information.
 */

static struct modldrv yge_modldrv = {
	&mod_driverops,			/* drv_modops */
	"Yukon 2 Ethernet",		/* drv_linkinfo */
	&yge_devops			/* drv_dev_ops */
};

static struct modlinkage yge_modlinkage = {
	MODREV_1,		/* ml_rev */
	&yge_modldrv,		/* ml_linkage */
	NULL
};

/*
 * DDI entry points.
 */
int
_init(void)
{
	int	rv;
	mac_init_ops(&yge_devops, "yge");
	if ((rv = mod_install(&yge_modlinkage)) != DDI_SUCCESS) {
		mac_fini_ops(&yge_devops);
	}
	return (rv);
}

int
_fini(void)
{
	int	rv;
	if ((rv = mod_remove(&yge_modlinkage)) == DDI_SUCCESS) {
		mac_fini_ops(&yge_devops);
	}
	return (rv);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&yge_modlinkage, modinfop));
}
