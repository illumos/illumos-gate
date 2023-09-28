/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2004 David Young.  All rights reserved.
 *
 * This code was written by David Young.
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
 * THIS SOFTWARE IS PROVIDED BY David Young ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL David
 * Young BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */
#include <sys/sysmacros.h>
#include <sys/pci.h>
#include <sys/stat.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/mac_provider.h>
#include <sys/mac_wifi.h>
#include <sys/net80211.h>
#include <sys/byteorder.h>
#include "rtwreg.h"
#include "rtwvar.h"
#include "smc93cx6var.h"
#include "rtwphy.h"
#include "rtwphyio.h"

/*
 * PIO access attributes for registers
 */
static ddi_device_acc_attr_t rtw_reg_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC
};

/*
 * DMA access attributes for descriptors and bufs: NOT to be byte swapped.
 */
static ddi_device_acc_attr_t rtw_desc_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC
};
static ddi_device_acc_attr_t rtw_buf_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC
};

/*
 * Describes the chip's DMA engine
 */
static ddi_dma_attr_t dma_attr_desc = {
	DMA_ATTR_V0,			/* dma_attr version */
	0x0000000000000000ull,		/* dma_attr_addr_lo */
	0xFFFFFFFF,			/* dma_attr_addr_hi */
	0x00000000FFFFFFFFull,		/* dma_attr_count_max */
	0x100,				/* dma_attr_align */
	0xFFFFFFFF,			/* dma_attr_burstsizes */
	0x00000001,			/* dma_attr_minxfer */
	0x00000000FFFFull,		/* dma_attr_maxxfer */
	0xFFFFFFFFFFFFFFFFull,		/* dma_attr_seg */
	1,				/* dma_attr_sgllen */
	1,				/* dma_attr_granular */
	0				/* dma_attr_flags */
};

static ddi_dma_attr_t dma_attr_rxbuf = {
	DMA_ATTR_V0,			/* dma_attr version */
	0x0000000000000000ull,		/* dma_attr_addr_lo */
	0xFFFFFFFF,			/* dma_attr_addr_hi */
	0x00000000FFFFFFFFull,		/* dma_attr_count_max */
	(uint32_t)16,			/* dma_attr_align */
	0xFFFFFFFF,			/* dma_attr_burstsizes */
	0x00000001,			/* dma_attr_minxfer */
	0x00000000FFFFull,		/* dma_attr_maxxfer */
	0xFFFFFFFFFFFFFFFFull,		/* dma_attr_seg */
	1,				/* dma_attr_sgllen */
	1,				/* dma_attr_granular */
	0				/* dma_attr_flags */
};

static ddi_dma_attr_t dma_attr_txbuf = {
	DMA_ATTR_V0,			/* dma_attr version */
	0x0000000000000000ull,		/* dma_attr_addr_lo */
	0xFFFFFFFF,			/* dma_attr_addr_hi */
	0x00000000FFFFFFFFull,		/* dma_attr_count_max */
	(uint32_t)16,			/* dma_attr_align */
	0xFFFFFFFF,			/* dma_attr_burstsizes */
	0x00000001,			/* dma_attr_minxfer */
	0x00000000FFFFull,		/* dma_attr_maxxfer */
	0xFFFFFFFFFFFFFFFFull,		/* dma_attr_seg */
	1,				/* dma_attr_sgllen */
	1,				/* dma_attr_granular */
	0				/* dma_attr_flags */
};


static void *rtw_soft_state_p = NULL;

static void	rtw_stop(void *);
static int	rtw_attach(dev_info_t *, ddi_attach_cmd_t);
static int	rtw_detach(dev_info_t *, ddi_detach_cmd_t);
static int	rtw_quiesce(dev_info_t *);
static int	rtw_m_stat(void *,  uint_t, uint64_t *);
static int	rtw_m_start(void *);
static void	rtw_m_stop(void *);
static int	rtw_m_promisc(void *, boolean_t);
static int	rtw_m_multicst(void *, boolean_t, const uint8_t *);
static int	rtw_m_unicst(void *, const uint8_t *);
static mblk_t	*rtw_m_tx(void *, mblk_t *);
static void	rtw_m_ioctl(void *, queue_t *, mblk_t *);
static int	rtw_m_setprop(void *, const char *, mac_prop_id_t,
    uint_t, const void *);
static int	rtw_m_getprop(void *, const char *, mac_prop_id_t,
    uint_t, void *);
static void	rtw_m_propinfo(void *, const char *, mac_prop_id_t,
    mac_prop_info_handle_t);

static mac_callbacks_t rtw_m_callbacks = {
	MC_IOCTL | MC_SETPROP | MC_GETPROP | MC_PROPINFO,
	rtw_m_stat,
	rtw_m_start,
	rtw_m_stop,
	rtw_m_promisc,
	rtw_m_multicst,
	rtw_m_unicst,
	rtw_m_tx,
	NULL,
	rtw_m_ioctl,
	NULL,		/* mc_getcapab */
	NULL,
	NULL,
	rtw_m_setprop,
	rtw_m_getprop,
	rtw_m_propinfo
};

DDI_DEFINE_STREAM_OPS(rtw_dev_ops, nulldev, nulldev, rtw_attach, rtw_detach,
    nodev, NULL, D_MP, NULL, rtw_quiesce);

static struct modldrv rtw_modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	"realtek 8180L driver 1.7",	/* short description */
	&rtw_dev_ops		/* driver specific ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&rtw_modldrv, NULL
};

static uint32_t rtw_qlen[RTW_NTXPRI] = {
	RTW_TXQLENLO,
	RTW_TXQLENMD,
	RTW_TXQLENHI,
	RTW_TXQLENBCN
};

uint32_t rtw_dbg_flags = 0;
	/*
	 * RTW_DEBUG_ATTACH | RTW_DEBUG_TUNE |
	 * RTW_DEBUG_ACCESS | RTW_DEBUG_INIT | RTW_DEBUG_PKTFILT |
	 * RTW_DEBUG_RECV | RTW_DEBUG_XMIT | RTW_DEBUG_80211 | RTW_DEBUG_INTR |
	 * RTW_DEBUG_PKTDUMP;
	 */

/*
 * Supported rates for 802.11b modes (in 500Kbps unit).
 */
static const struct ieee80211_rateset rtw_rateset_11b =
	{ 4, { 2, 4, 11, 22 } };

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_init(void)
{
	int status;

	status = ddi_soft_state_init(&rtw_soft_state_p,
	    sizeof (rtw_softc_t), 1);
	if (status != 0)
		return (status);

	mac_init_ops(&rtw_dev_ops, "rtw");
	status = mod_install(&modlinkage);
	if (status != 0) {
		mac_fini_ops(&rtw_dev_ops);
		ddi_soft_state_fini(&rtw_soft_state_p);
	}
	return (status);
}

int
_fini(void)
{
	int status;

	status = mod_remove(&modlinkage);
	if (status == 0) {
		mac_fini_ops(&rtw_dev_ops);
		ddi_soft_state_fini(&rtw_soft_state_p);
	}
	return (status);
}

void
rtw_dbg(uint32_t dbg_flags, const int8_t *fmt, ...)
{
	va_list args;

	if (dbg_flags & rtw_dbg_flags) {
		va_start(args, fmt);
		vcmn_err(CE_CONT, fmt, args);
		va_end(args);
	}
}

#ifdef DEBUG
static void
rtw_print_regs(struct rtw_regs *regs, const char *dvname, const char *where)
{
#define	PRINTREG32(sc, reg)				\
	RTW_DPRINTF(RTW_DEBUG_REGDUMP,			\
	    "%s: reg[ " #reg " / %03x ] = %08x\n",	\
	    dvname, reg, RTW_READ(regs, reg))

#define	PRINTREG16(sc, reg)				\
	RTW_DPRINTF(RTW_DEBUG_REGDUMP,			\
	    "%s: reg[ " #reg " / %03x ] = %04x\n",	\
	    dvname, reg, RTW_READ16(regs, reg))

#define	PRINTREG8(sc, reg)				\
	RTW_DPRINTF(RTW_DEBUG_REGDUMP,			\
	    "%s: reg[ " #reg " / %03x ] = %02x\n",	\
	    dvname, reg, RTW_READ8(regs, reg))

	RTW_DPRINTF(RTW_DEBUG_REGDUMP, "%s: %s\n", dvname, where);

	PRINTREG32(regs, RTW_IDR0);
	PRINTREG32(regs, RTW_IDR1);
	PRINTREG32(regs, RTW_MAR0);
	PRINTREG32(regs, RTW_MAR1);
	PRINTREG32(regs, RTW_TSFTRL);
	PRINTREG32(regs, RTW_TSFTRH);
	PRINTREG32(regs, RTW_TLPDA);
	PRINTREG32(regs, RTW_TNPDA);
	PRINTREG32(regs, RTW_THPDA);
	PRINTREG32(regs, RTW_TCR);
	PRINTREG32(regs, RTW_RCR);
	PRINTREG32(regs, RTW_TINT);
	PRINTREG32(regs, RTW_TBDA);
	PRINTREG32(regs, RTW_ANAPARM);
	PRINTREG32(regs, RTW_BB);
	PRINTREG32(regs, RTW_PHYCFG);
	PRINTREG32(regs, RTW_WAKEUP0L);
	PRINTREG32(regs, RTW_WAKEUP0H);
	PRINTREG32(regs, RTW_WAKEUP1L);
	PRINTREG32(regs, RTW_WAKEUP1H);
	PRINTREG32(regs, RTW_WAKEUP2LL);
	PRINTREG32(regs, RTW_WAKEUP2LH);
	PRINTREG32(regs, RTW_WAKEUP2HL);
	PRINTREG32(regs, RTW_WAKEUP2HH);
	PRINTREG32(regs, RTW_WAKEUP3LL);
	PRINTREG32(regs, RTW_WAKEUP3LH);
	PRINTREG32(regs, RTW_WAKEUP3HL);
	PRINTREG32(regs, RTW_WAKEUP3HH);
	PRINTREG32(regs, RTW_WAKEUP4LL);
	PRINTREG32(regs, RTW_WAKEUP4LH);
	PRINTREG32(regs, RTW_WAKEUP4HL);
	PRINTREG32(regs, RTW_WAKEUP4HH);
	PRINTREG32(regs, RTW_DK0);
	PRINTREG32(regs, RTW_DK1);
	PRINTREG32(regs, RTW_DK2);
	PRINTREG32(regs, RTW_DK3);
	PRINTREG32(regs, RTW_RETRYCTR);
	PRINTREG32(regs, RTW_RDSAR);
	PRINTREG32(regs, RTW_FER);
	PRINTREG32(regs, RTW_FEMR);
	PRINTREG32(regs, RTW_FPSR);
	PRINTREG32(regs, RTW_FFER);

	/* 16-bit registers */
	PRINTREG16(regs, RTW_BRSR);
	PRINTREG16(regs, RTW_IMR);
	PRINTREG16(regs, RTW_ISR);
	PRINTREG16(regs, RTW_BCNITV);
	PRINTREG16(regs, RTW_ATIMWND);
	PRINTREG16(regs, RTW_BINTRITV);
	PRINTREG16(regs, RTW_ATIMTRITV);
	PRINTREG16(regs, RTW_CRC16ERR);
	PRINTREG16(regs, RTW_CRC0);
	PRINTREG16(regs, RTW_CRC1);
	PRINTREG16(regs, RTW_CRC2);
	PRINTREG16(regs, RTW_CRC3);
	PRINTREG16(regs, RTW_CRC4);
	PRINTREG16(regs, RTW_CWR);

	/* 8-bit registers */
	PRINTREG8(regs, RTW_CR);
	PRINTREG8(regs, RTW_9346CR);
	PRINTREG8(regs, RTW_CONFIG0);
	PRINTREG8(regs, RTW_CONFIG1);
	PRINTREG8(regs, RTW_CONFIG2);
	PRINTREG8(regs, RTW_MSR);
	PRINTREG8(regs, RTW_CONFIG3);
	PRINTREG8(regs, RTW_CONFIG4);
	PRINTREG8(regs, RTW_TESTR);
	PRINTREG8(regs, RTW_PSR);
	PRINTREG8(regs, RTW_SCR);
	PRINTREG8(regs, RTW_PHYDELAY);
	PRINTREG8(regs, RTW_CRCOUNT);
	PRINTREG8(regs, RTW_PHYADDR);
	PRINTREG8(regs, RTW_PHYDATAW);
	PRINTREG8(regs, RTW_PHYDATAR);
	PRINTREG8(regs, RTW_CONFIG5);
	PRINTREG8(regs, RTW_TPPOLL);

	PRINTREG16(regs, RTW_BSSID16);
	PRINTREG32(regs, RTW_BSSID32);
#undef PRINTREG32
#undef PRINTREG16
#undef PRINTREG8
}

#endif /* DEBUG */
static const char *
rtw_access_string(enum rtw_access access)
{
	switch (access) {
	case RTW_ACCESS_NONE:
		return ("none");
	case RTW_ACCESS_CONFIG:
		return ("config");
	case RTW_ACCESS_ANAPARM:
		return ("anaparm");
	default:
		return ("unknown");
	}
}

/*
 * Enable registers, switch register banks.
 */
void
rtw_config0123_enable(struct rtw_regs *regs, int enable)
{
	uint8_t ecr;
	ecr = RTW_READ8(regs, RTW_9346CR);
	ecr &= ~(RTW_9346CR_EEM_MASK | RTW_9346CR_EECS | RTW_9346CR_EESK);
	if (enable)
		ecr |= RTW_9346CR_EEM_CONFIG;
	else {
		RTW_WBW(regs, RTW_9346CR, MAX(RTW_CONFIG0, RTW_CONFIG3));
		ecr |= RTW_9346CR_EEM_NORMAL;
	}
	RTW_WRITE8(regs, RTW_9346CR, ecr);
	RTW_SYNC(regs, RTW_9346CR, RTW_9346CR);
}

/*
 * requires rtw_config0123_enable(, 1)
 */
void
rtw_anaparm_enable(struct rtw_regs *regs, int enable)
{
	uint8_t cfg3;

	cfg3 = RTW_READ8(regs, RTW_CONFIG3);
	cfg3 |= RTW_CONFIG3_CLKRUNEN;
	if (enable)
		cfg3 |= RTW_CONFIG3_PARMEN;
	else
		cfg3 &= ~RTW_CONFIG3_PARMEN;
	RTW_WRITE8(regs, RTW_CONFIG3, cfg3);
	RTW_SYNC(regs, RTW_CONFIG3, RTW_CONFIG3);
}

/*
 * requires rtw_anaparm_enable(, 1)
 */
void
rtw_txdac_enable(rtw_softc_t *rsc, int enable)
{
	uint32_t anaparm;
	struct rtw_regs *regs = &rsc->sc_regs;

	anaparm = RTW_READ(regs, RTW_ANAPARM);
	if (enable)
		anaparm &= ~RTW_ANAPARM_TXDACOFF;
	else
		anaparm |= RTW_ANAPARM_TXDACOFF;
	RTW_WRITE(regs, RTW_ANAPARM, anaparm);
	RTW_SYNC(regs, RTW_ANAPARM, RTW_ANAPARM);
}

static void
rtw_set_access1(struct rtw_regs *regs, enum rtw_access naccess)
{
	ASSERT(naccess >= RTW_ACCESS_NONE && naccess <= RTW_ACCESS_ANAPARM);
	ASSERT(regs->r_access >= RTW_ACCESS_NONE &&
	    regs->r_access <= RTW_ACCESS_ANAPARM);

	if (naccess == regs->r_access)
		return;

	switch (naccess) {
	case RTW_ACCESS_NONE:
		switch (regs->r_access) {
		case RTW_ACCESS_ANAPARM:
			rtw_anaparm_enable(regs, 0);
			/*FALLTHROUGH*/
		case RTW_ACCESS_CONFIG:
			rtw_config0123_enable(regs, 0);
			/*FALLTHROUGH*/
		case RTW_ACCESS_NONE:
			break;
		}
		break;
	case RTW_ACCESS_CONFIG:
		switch (regs->r_access) {
		case RTW_ACCESS_NONE:
			rtw_config0123_enable(regs, 1);
			/*FALLTHROUGH*/
		case RTW_ACCESS_CONFIG:
			break;
		case RTW_ACCESS_ANAPARM:
			rtw_anaparm_enable(regs, 0);
			break;
		}
		break;
	case RTW_ACCESS_ANAPARM:
		switch (regs->r_access) {
		case RTW_ACCESS_NONE:
			rtw_config0123_enable(regs, 1);
			/*FALLTHROUGH*/
		case RTW_ACCESS_CONFIG:
			rtw_anaparm_enable(regs, 1);
			/*FALLTHROUGH*/
		case RTW_ACCESS_ANAPARM:
			break;
		}
		break;
	}
}

void
rtw_set_access(struct rtw_regs *regs, enum rtw_access access)
{
	rtw_set_access1(regs, access);
	RTW_DPRINTF(RTW_DEBUG_ACCESS,
	    "%s: access %s -> %s\n", __func__,
	    rtw_access_string(regs->r_access),
	    rtw_access_string(access));
	regs->r_access = access;
}


void
rtw_continuous_tx_enable(rtw_softc_t *rsc, int enable)
{
	struct rtw_regs *regs = &rsc->sc_regs;

	uint32_t tcr;
	tcr = RTW_READ(regs, RTW_TCR);
	tcr &= ~RTW_TCR_LBK_MASK;
	if (enable)
		tcr |= RTW_TCR_LBK_CONT;
	else
		tcr |= RTW_TCR_LBK_NORMAL;
	RTW_WRITE(regs, RTW_TCR, tcr);
	RTW_SYNC(regs, RTW_TCR, RTW_TCR);
	rtw_set_access(regs, RTW_ACCESS_ANAPARM);
	rtw_txdac_enable(rsc, !enable);
	rtw_set_access(regs, RTW_ACCESS_ANAPARM);
	rtw_set_access(regs, RTW_ACCESS_NONE);
}

static int
rtw_chip_reset1(struct rtw_regs *regs, const char *dvname)
{
	uint8_t cr;
	int i;

	RTW_WRITE8(regs, RTW_CR, RTW_CR_RST);

	RTW_WBR(regs, RTW_CR, RTW_CR);

	for (i = 0; i < 1000; i++) {
		cr = RTW_READ8(regs, RTW_CR);
		if ((cr & RTW_CR_RST) == 0) {
			RTW_DPRINTF(RTW_DEBUG_RESET,
			    "%s: reset in %dus\n", dvname, i);
			return (0);
		}
		RTW_RBR(regs, RTW_CR, RTW_CR);
		DELAY(10); /* 10us */
	}

	cmn_err(CE_WARN, "%s: reset failed\n", dvname);
	return (ETIMEDOUT);
}

static int
rtw_chip_reset(struct rtw_regs *regs, const char *dvname)
{
	RTW_WBW(regs, RTW_CR, RTW_TCR);
	return (rtw_chip_reset1(regs, dvname));
}

static void
rtw_disable_interrupts(struct rtw_regs *regs)
{
	RTW_WRITE16(regs, RTW_IMR, 0);
	RTW_WRITE16(regs, RTW_ISR, 0xffff);
	(void) RTW_READ16(regs, RTW_IMR);
}

static void
rtw_enable_interrupts(rtw_softc_t *rsc)
{
	struct rtw_regs *regs = &rsc->sc_regs;

	rsc->sc_inten = RTW_INTR_RX | RTW_INTR_TX | RTW_INTR_IOERROR;

	RTW_WRITE16(regs, RTW_IMR, rsc->sc_inten);
	RTW_WRITE16(regs, RTW_ISR, 0xffff);

	/* XXX necessary? */
	if (rsc->sc_intr_ack != NULL)
		(*rsc->sc_intr_ack)(regs);
}

static int
rtw_recall_eeprom(struct rtw_regs *regs, const char *dvname)
{
	int i;
	uint8_t ecr;

	ecr = RTW_READ8(regs, RTW_9346CR);
	ecr = (ecr & ~RTW_9346CR_EEM_MASK) | RTW_9346CR_EEM_AUTOLOAD;
	RTW_WRITE8(regs, RTW_9346CR, ecr);

	RTW_WBR(regs, RTW_9346CR, RTW_9346CR);

	/* wait 25ms for completion */
	for (i = 0; i < 250; i++) {
		ecr = RTW_READ8(regs, RTW_9346CR);
		if ((ecr & RTW_9346CR_EEM_MASK) == RTW_9346CR_EEM_NORMAL) {
			RTW_DPRINTF(RTW_DEBUG_RESET,
			    "%s: recall EEPROM in %dus\n", dvname, i * 100);
			return (0);
		}
		RTW_RBR(regs, RTW_9346CR, RTW_9346CR);
		DELAY(100);
	}
	cmn_err(CE_WARN, "%s: recall EEPROM failed\n", dvname);
	return (ETIMEDOUT);
}

static int
rtw_reset(rtw_softc_t *rsc)
{
	int rc;

	rc = rtw_chip_reset(&rsc->sc_regs, "rtw");
	if (rc != 0)
		return (rc);

	(void) rtw_recall_eeprom(&rsc->sc_regs, "rtw");
	return (0);
}

void
rtw_set_mode(struct rtw_regs *regs, int mode)
{
	uint8_t command;
	command = RTW_READ8(regs, RTW_9346CR);
	command = command &~ RTW_EPROM_CMD_OPERATING_MODE_MASK;
	command = command | (mode<<RTW_EPROM_CMD_OPERATING_MODE_SHIFT);
	command = command &~ (1<<RTW_EPROM_CS_SHIFT);
	command = command &~ (1<<RTW_EPROM_CK_SHIFT);
	RTW_WRITE8(regs, RTW_9346CR, command);
}

void
rtw_dma_start(struct rtw_regs *regs, int priority)
{
	uint8_t check = 0;

	check = RTW_READ8(regs, RTW_TPPOLL);
	switch (priority) {
	case (0):
		RTW_WRITE8(regs, RTW_TPPOLL,
		    (1<< RTW_TX_DMA_POLLING_LOWPRIORITY_SHIFT) | check);
		break;
	case (1):
		RTW_WRITE8(regs, RTW_TPPOLL,
		    (1<< RTW_TX_DMA_POLLING_NORMPRIORITY_SHIFT) | check);
		break;
	case (2):
		RTW_WRITE8(regs, RTW_TPPOLL,
		    (1<< RTW_TX_DMA_POLLING_HIPRIORITY_SHIFT) | check);
		break;
	}
	(void) RTW_READ8(regs, RTW_TPPOLL);
}

void
rtw_beacon_tx_disable(struct rtw_regs *regs)
{
	uint8_t mask = 0;
	mask |= (1 << RTW_TX_DMA_STOP_BEACON_SHIFT);
	rtw_set_mode(regs, RTW_EPROM_CMD_CONFIG);
	RTW_WRITE8(regs, RTW_TPPOLL, mask);
	rtw_set_mode(regs, RTW_EPROM_CMD_NORMAL);
}

static void
rtw_io_enable(rtw_softc_t *rsc, uint8_t flags, int enable);

void
rtw_rtx_disable(rtw_softc_t *rsc)
{
	struct rtw_regs *regs = &rsc->sc_regs;

	rtw_io_enable(rsc, RTW_CR_RE|RTW_CR_TE, 0);
	(void) RTW_READ8(regs, RTW_CR);
}

static void
rtw_srom_free(struct rtw_srom *sr)
{
	if (sr->sr_content == NULL)
		return;
	kmem_free(sr->sr_content, sr->sr_size);
	sr->sr_size = 0;
	sr->sr_content = NULL;
}

/*ARGSUSED*/
static void
rtw_srom_defaults(struct rtw_srom *sr, uint32_t *flags, uint8_t *cs_threshold,
    enum rtw_rfchipid *rfchipid, uint32_t *rcr)
{
	*flags |= (RTW_F_DIGPHY|RTW_F_ANTDIV);
	*cs_threshold = RTW_SR_ENERGYDETTHR_DEFAULT;
	*rcr |= RTW_RCR_ENCS1;
	*rfchipid = RTW_RFCHIPID_PHILIPS;
}

static int
rtw_srom_parse(struct rtw_srom *sr, uint32_t *flags, uint8_t *cs_threshold,
    enum rtw_rfchipid *rfchipid, uint32_t *rcr, enum rtw_locale *locale,
    const char *dvname)
{
	int i;
	const char *rfname, *paname;
	char scratch[sizeof ("unknown 0xXX")];
	uint16_t version;
	uint8_t mac[IEEE80211_ADDR_LEN];

	*flags &= ~(RTW_F_DIGPHY|RTW_F_DFLANTB|RTW_F_ANTDIV);
	*rcr &= ~(RTW_RCR_ENCS1 | RTW_RCR_ENCS2);

	version = RTW_SR_GET16(sr, RTW_SR_VERSION);
	RTW_DPRINTF(RTW_DEBUG_IOSTATE, "%s: SROM version %d.%d", dvname,
	    version >> 8, version & 0xff);

	if (version <= 0x0101) {
		cmn_err(CE_NOTE, " is not understood, limping along "
		    "with defaults\n");
		rtw_srom_defaults(sr, flags, cs_threshold, rfchipid, rcr);
		return (0);
	}

	for (i = 0; i < IEEE80211_ADDR_LEN; i++)
		mac[i] = RTW_SR_GET(sr, RTW_SR_MAC + i);

	RTW_DPRINTF(RTW_DEBUG_ATTACH,
	    "%s: EEPROM MAC %s\n", dvname, mac);

	*cs_threshold = RTW_SR_GET(sr, RTW_SR_ENERGYDETTHR);

	if ((RTW_SR_GET(sr, RTW_SR_CONFIG2) & RTW_CONFIG2_ANT) != 0)
		*flags |= RTW_F_ANTDIV;

	/*
	 * Note well: the sense of the RTW_SR_RFPARM_DIGPHY bit seems
	 * to be reversed.
	 */
	if ((RTW_SR_GET(sr, RTW_SR_RFPARM) & RTW_SR_RFPARM_DIGPHY) == 0)
		*flags |= RTW_F_DIGPHY;
	if ((RTW_SR_GET(sr, RTW_SR_RFPARM) & RTW_SR_RFPARM_DFLANTB) != 0)
		*flags |= RTW_F_DFLANTB;

	*rcr |= LSHIFT(MASK_AND_RSHIFT(RTW_SR_GET(sr, RTW_SR_RFPARM),
	    RTW_SR_RFPARM_CS_MASK), RTW_RCR_ENCS1);

	*rfchipid = RTW_SR_GET(sr, RTW_SR_RFCHIPID);
	switch (*rfchipid) {
	case RTW_RFCHIPID_GCT:		/* this combo seen in the wild */
		rfname = "GCT GRF5101";
		paname = "Winspring WS9901";
		break;
	case RTW_RFCHIPID_MAXIM:
		rfname = "Maxim MAX2820";	/* guess */
		paname = "Maxim MAX2422";	/* guess */
		break;
	case RTW_RFCHIPID_INTERSIL:
		rfname = "Intersil HFA3873";	/* guess */
		paname = "Intersil <unknown>";
		break;
	case RTW_RFCHIPID_PHILIPS:	/* this combo seen in the wild */
		rfname = "Philips SA2400A";
		paname = "Philips SA2411";
		break;
	case RTW_RFCHIPID_RFMD:
		/*
		 * this is the same front-end as an atw(4)!
		 */
		rfname = "RFMD RF2948B, "	/* mentioned in Realtek docs */
		    "LNA: RFMD RF2494, "	/* mentioned in Realtek docs */
		    "SYN: Silicon Labs Si4126";
		paname = "RFMD RF2189";		/* mentioned in Realtek docs */
		break;
	case RTW_RFCHIPID_RESERVED:
		rfname = paname = "reserved";
		break;
	default:
		(void) snprintf(scratch, sizeof (scratch),
		    "unknown 0x%02x", *rfchipid);
		rfname = paname = scratch;
	}
	RTW_DPRINTF(RTW_DEBUG_PHY, "%s: RF: %s, PA: %s\n",
	    dvname, rfname, paname);

	switch (RTW_SR_GET(sr, RTW_SR_CONFIG0) & RTW_CONFIG0_GL_MASK) {
	case RTW_CONFIG0_GL_USA:
		*locale = RTW_LOCALE_USA;
		break;
	case RTW_CONFIG0_GL_EUROPE:
		*locale = RTW_LOCALE_EUROPE;
		break;
	case RTW_CONFIG0_GL_JAPAN:
		*locale = RTW_LOCALE_JAPAN;
		break;
	default:
		*locale = RTW_LOCALE_UNKNOWN;
		break;
	}
	return (0);
}

/*
 * Returns -1 on failure.
 */
static int
rtw_srom_read(struct rtw_regs *regs, uint32_t flags, struct rtw_srom *sr,
    const char *dvname)
{
	int rc;
	struct seeprom_descriptor sd;
	uint8_t ecr;

	(void) memset(&sd, 0, sizeof (sd));

	ecr = RTW_READ8(regs, RTW_9346CR);

	if ((flags & RTW_F_9356SROM) != 0) {
		RTW_DPRINTF(RTW_DEBUG_ATTACH, "%s: 93c56 SROM\n", dvname);
		sr->sr_size = 256;
		sd.sd_chip = C56_66;
	} else {
		RTW_DPRINTF(RTW_DEBUG_ATTACH, "%s: 93c46 SROM\n", dvname);
		sr->sr_size = 128;
		sd.sd_chip = C46;
	}

	ecr &= ~(RTW_9346CR_EEDI | RTW_9346CR_EEDO | RTW_9346CR_EESK |
	    RTW_9346CR_EEM_MASK | RTW_9346CR_EECS);
	ecr |= RTW_9346CR_EEM_PROGRAM;

	RTW_WRITE8(regs, RTW_9346CR, ecr);

	sr->sr_content = kmem_zalloc(sr->sr_size, KM_SLEEP);

	if (sr->sr_content == NULL) {
		cmn_err(CE_WARN, "%s: unable to allocate SROM buffer\n",
		    dvname);
		return (ENOMEM);
	}

	(void) memset(sr->sr_content, 0, sr->sr_size);

	/*
	 * RTL8180 has a single 8-bit register for controlling the
	 * 93cx6 SROM.  There is no "ready" bit. The RTL8180
	 * input/output sense is the reverse of read_seeprom's.
	 */
	sd.sd_handle = regs->r_handle;
	sd.sd_base = regs->r_base;
	sd.sd_regsize = 1;
	sd.sd_control_offset = RTW_9346CR;
	sd.sd_status_offset = RTW_9346CR;
	sd.sd_dataout_offset = RTW_9346CR;
	sd.sd_CK = RTW_9346CR_EESK;
	sd.sd_CS = RTW_9346CR_EECS;
	sd.sd_DI = RTW_9346CR_EEDO;
	sd.sd_DO = RTW_9346CR_EEDI;
	/*
	 * make read_seeprom enter EEPROM read/write mode
	 */
	sd.sd_MS = ecr;
	sd.sd_RDY = 0;

	/*
	 * TBD bus barriers
	 */
	if (!read_seeprom(&sd, sr->sr_content, 0, sr->sr_size/2)) {
		cmn_err(CE_WARN, "%s: could not read SROM\n", dvname);
		kmem_free(sr->sr_content, sr->sr_size);
		sr->sr_content = NULL;
		return (-1);	/* XXX */
	}

	/*
	 * end EEPROM read/write mode
	 */
	RTW_WRITE8(regs, RTW_9346CR,
	    (ecr & ~RTW_9346CR_EEM_MASK) | RTW_9346CR_EEM_NORMAL);
	RTW_WBRW(regs, RTW_9346CR, RTW_9346CR);

	if ((rc = rtw_recall_eeprom(regs, dvname)) != 0)
		return (rc);

#ifdef SROM_DEBUG
	{
		int i;
		RTW_DPRINTF(RTW_DEBUG_ATTACH,
		    "\n%s: serial ROM:\n\t", dvname);
		for (i = 0; i < sr->sr_size/2; i++) {
			RTW_DPRINTF(RTW_DEBUG_ATTACH,
			    "offset-0x%x: %04x", 2*i, sr->sr_content[i]);
		}
	}
#endif /* DEBUG */
	return (0);
}

static void
rtw_set_rfprog(struct rtw_regs *regs, enum rtw_rfchipid rfchipid,
    const char *dvname)
{
	uint8_t cfg4;
	const char *method;

	cfg4 = RTW_READ8(regs, RTW_CONFIG4) & ~RTW_CONFIG4_RFTYPE_MASK;

	switch (rfchipid) {
	default:
		cfg4 |= LSHIFT(0, RTW_CONFIG4_RFTYPE_MASK);
		method = "fallback";
		break;
	case RTW_RFCHIPID_INTERSIL:
		cfg4 |= RTW_CONFIG4_RFTYPE_INTERSIL;
		method = "Intersil";
		break;
	case RTW_RFCHIPID_PHILIPS:
		cfg4 |= RTW_CONFIG4_RFTYPE_PHILIPS;
		method = "Philips";
		break;
	case RTW_RFCHIPID_GCT:	/* XXX a guess */
	case RTW_RFCHIPID_RFMD:
		cfg4 |= RTW_CONFIG4_RFTYPE_RFMD;
		method = "RFMD";
		break;
	}

	RTW_WRITE8(regs, RTW_CONFIG4, cfg4);

	RTW_WBR(regs, RTW_CONFIG4, RTW_CONFIG4);

	RTW_DPRINTF(RTW_DEBUG_INIT,
	    "%s: %s RF programming method, %02x\n", dvname, method,
	    RTW_READ8(regs, RTW_CONFIG4));
}

static void
rtw_init_channels(enum rtw_locale locale,
    struct ieee80211_channel (*chans)[IEEE80211_CHAN_MAX+1],
    const char *dvname)
{
	int i;
	const char *name = NULL;
#define	ADD_CHANNEL(_chans, _chan) {			\
	(*_chans)[_chan].ich_flags = IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_CCK;\
	(*_chans)[_chan].ich_freq =				\
	    ieee80211_ieee2mhz(_chan, (*_chans)[_chan].ich_flags);\
}

	switch (locale) {
	case RTW_LOCALE_USA:	/* 1-11 */
		name = "USA";
		for (i = 1; i <= 11; i++)
			ADD_CHANNEL(chans, i);
		break;
	case RTW_LOCALE_JAPAN:	/* 1-14 */
		name = "Japan";
		ADD_CHANNEL(chans, 14);
		for (i = 1; i <= 14; i++)
			ADD_CHANNEL(chans, i);
		break;
	case RTW_LOCALE_EUROPE:	/* 1-13 */
		name = "Europe";
		for (i = 1; i <= 13; i++)
			ADD_CHANNEL(chans, i);
		break;
	default:			/* 10-11 allowed by most countries */
		name = "<unknown>";
		for (i = 10; i <= 11; i++)
			ADD_CHANNEL(chans, i);
		break;
	}
	RTW_DPRINTF(RTW_DEBUG_ATTACH, "%s: Geographic Location %s\n",
	    dvname, name);
#undef ADD_CHANNEL
}

static void
rtw_set80211props(struct ieee80211com *ic)
{
	ic->ic_phytype = IEEE80211_T_DS;
	ic->ic_opmode = IEEE80211_M_STA;
	ic->ic_caps = IEEE80211_C_PMGT | IEEE80211_C_IBSS |
	    IEEE80211_C_SHPREAMBLE;
	/* IEEE80211_C_HOSTAP | IEEE80211_C_MONITOR | IEEE80211_C_WEP */

	ic->ic_sup_rates[IEEE80211_MODE_11B] = rtw_rateset_11b;
}

/*ARGSUSED*/
static void
rtw_identify_country(struct rtw_regs *regs, enum rtw_locale *locale,
    const char *dvname)
{
	uint8_t cfg0 = RTW_READ8(regs, RTW_CONFIG0);

	switch (cfg0 & RTW_CONFIG0_GL_MASK) {
	case RTW_CONFIG0_GL_USA:
		*locale = RTW_LOCALE_USA;
		break;
	case RTW_CONFIG0_GL_JAPAN:
		*locale = RTW_LOCALE_JAPAN;
		break;
	case RTW_CONFIG0_GL_EUROPE:
		*locale = RTW_LOCALE_EUROPE;
		break;
	default:
		*locale = RTW_LOCALE_UNKNOWN;
		break;
	}
}

static int
rtw_identify_sta(struct rtw_regs *regs, uint8_t *addr,
    const char *dvname)
{
	uint32_t idr0 = RTW_READ(regs, RTW_IDR0),
	    idr1 = RTW_READ(regs, RTW_IDR1);

	*addr = MASK_AND_RSHIFT(idr0, BITS(0,  7));
	*(addr + 1) = MASK_AND_RSHIFT(idr0, BITS(8,  15));
	*(addr + 2) = MASK_AND_RSHIFT(idr0, BITS(16, 23));
	*(addr + 3) = MASK_AND_RSHIFT(idr0, BITS(24, 31));

	*(addr + 4) = MASK_AND_RSHIFT(idr1, BITS(0,  7));
	*(addr + 5) = MASK_AND_RSHIFT(idr1, BITS(8, 15));

	RTW_DPRINTF(RTW_DEBUG_ATTACH,
	    "%s: 802.11mac address %x:%x:%x:%x:%x:%x\n", dvname,
	    *addr, *(addr+1), *(addr+2), *(addr+3), *(addr+4), *(addr+5));

	return (0);
}

static uint8_t
rtw_chan2txpower(struct rtw_srom *sr, struct ieee80211com *ic,
    struct ieee80211_channel *chan)
{
	uint32_t idx = RTW_SR_TXPOWER1 + ieee80211_chan2ieee(ic, chan) - 1;
	return (RTW_SR_GET(sr, idx));
}

static void
rtw_rxdesc_init(rtw_softc_t *rsc, struct rtw_rxbuf *rbf, int idx, int is_last)
{
	uint32_t ctl = 0;
	uint8_t *buf = (uint8_t *)rbf->bf_dma.mem_va;

	ASSERT(rbf != NULL);
	rbf->rxdesc->rd_buf = (rbf->bf_dma.cookie.dmac_address);
	bzero(buf, rbf->bf_dma.alength);
	RTW_DMA_SYNC(rbf->bf_dma, DDI_DMA_SYNC_FORDEV);

	ctl = (rbf->bf_dma.alength & 0xfff) | RTW_RXCTL_OWN;

	if (is_last)
		ctl |= RTW_RXCTL_EOR;

	rbf->rxdesc->rd_ctl = (ctl);
	/* sync the mbuf */

	/* sync the descriptor */
	RTW_DMA_SYNC_DESC(rsc->sc_desc_dma,
	    RTW_DESC_OFFSET(hd_rx, idx),
	    sizeof (struct rtw_rxdesc),
	    DDI_DMA_SYNC_FORDEV);
}

static void
rtw_idle(struct rtw_regs *regs)
{
	int active;

	/* request stop DMA; wait for packets to stop transmitting. */

	RTW_WRITE8(regs, RTW_TPPOLL, RTW_TPPOLL_SALL);

	for (active = 0; active < 300 &&
	    (RTW_READ8(regs, RTW_TPPOLL) & RTW_TPPOLL_ALL) != 0; active++)
		drv_usecwait(10);
}

static void
rtw_io_enable(rtw_softc_t *rsc, uint8_t flags, int enable)
{
	uint8_t cr;
	struct rtw_regs *regs = &rsc->sc_regs;

	RTW_DPRINTF(RTW_DEBUG_IOSTATE, "%s: %s 0x%02x\n", __func__,
	    enable ? "enable" : "disable", flags);

	cr = RTW_READ8(regs, RTW_CR);

	/* The receive engine will always start at RDSAR.  */
	if (enable && (flags & ~cr & RTW_CR_RE)) {
		RTW_DMA_SYNC_DESC(rsc->sc_desc_dma,
		    RTW_DESC_OFFSET(hd_rx, 0),
		    sizeof (struct rtw_rxdesc),
		    DDI_DMA_SYNC_FORCPU);
		rsc->rx_next = 0;
		rtw_rxdesc_init(rsc, rsc->rxbuf_h, 0, 0);
	}

	if (enable)
		cr |= flags;
	else
		cr &= ~flags;
	RTW_WRITE8(regs, RTW_CR, cr);
	(void) RTW_READ8(regs, RTW_CR);
}

/*
 * Allocate an area of memory and a DMA handle for accessing it
 */
static int
rtw_alloc_dma_mem(dev_info_t *devinfo, ddi_dma_attr_t *dma_attr,
	size_t memsize, ddi_device_acc_attr_t *attr_p, uint_t alloc_flags,
	uint_t bind_flags, dma_area_t *dma_p)
{
	int err;

	/*
	 * Allocate handle
	 */
	err = ddi_dma_alloc_handle(devinfo, dma_attr,
	    DDI_DMA_SLEEP, NULL, &dma_p->dma_hdl);
	if (err != DDI_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * Allocate memory
	 */
	err = ddi_dma_mem_alloc(dma_p->dma_hdl, memsize, attr_p,
	    alloc_flags, DDI_DMA_SLEEP, NULL, &dma_p->mem_va,
	    &dma_p->alength, &dma_p->acc_hdl);
	if (err != DDI_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * Bind the two together
	 */
	err = ddi_dma_addr_bind_handle(dma_p->dma_hdl, NULL,
	    dma_p->mem_va, dma_p->alength, bind_flags,
	    DDI_DMA_SLEEP, NULL, &dma_p->cookie, &dma_p->ncookies);
	if ((dma_p->ncookies != 1) || (err != DDI_DMA_MAPPED))
		return (DDI_FAILURE);

	dma_p->nslots = ~0U;
	dma_p->size = ~0U;
	dma_p->token = ~0U;
	dma_p->offset = 0;
	return (DDI_SUCCESS);
}

/*
 * Free one allocated area of DMAable memory
 */
static void
rtw_free_dma_mem(dma_area_t *dma_p)
{
	if (dma_p->dma_hdl != NULL) {
		(void) ddi_dma_unbind_handle(dma_p->dma_hdl);
		if (dma_p->acc_hdl != NULL) {
			ddi_dma_mem_free(&dma_p->acc_hdl);
			dma_p->acc_hdl = NULL;
		}
		ddi_dma_free_handle(&dma_p->dma_hdl);
		dma_p->ncookies = 0;
		dma_p->dma_hdl = NULL;
	}
}

static void
rtw_dma_free(rtw_softc_t *rsc)
{
	struct rtw_txbuf *txbf;
	struct rtw_rxbuf *rxbf;
	int i, j;

	/* Free TX DMA buffer */
	for (i = 0; i < RTW_NTXPRI; i++) {
		txbf = list_head(&rsc->sc_txq[i].tx_free_list);
		while (txbf != NULL) {
			rtw_free_dma_mem(&txbf->bf_dma);
			list_remove(&rsc->sc_txq[i].tx_free_list, txbf);
			txbf = list_head(&rsc->sc_txq[i].tx_free_list);
		}
		list_destroy(&rsc->sc_txq[i].tx_free_list);
		txbf = list_head(&rsc->sc_txq[i].tx_dirty_list);
		while (txbf != NULL) {
			rtw_free_dma_mem(&txbf->bf_dma);
			list_remove(&rsc->sc_txq[i].tx_dirty_list, txbf);
			txbf = list_head(&rsc->sc_txq[i].tx_dirty_list);
		}
		list_destroy(&rsc->sc_txq[i].tx_dirty_list);

		if (rsc->sc_txq[i].txbuf_h != NULL) {
			kmem_free(rsc->sc_txq[i].txbuf_h,
			    sizeof (struct rtw_txbuf) * rtw_qlen[i]);
			rsc->sc_txq[i].txbuf_h = NULL;
		}
	}

	/* Free RX DMA buffer */
	rxbf = rsc->rxbuf_h;
	for (j = 0; j < RTW_RXQLEN; j++) {
		rtw_free_dma_mem(&rxbf->bf_dma);
		rxbf++;
	}

	if (rsc->rxbuf_h != NULL) {
		kmem_free(rsc->rxbuf_h,
		    sizeof (struct rtw_rxbuf) * RTW_RXQLEN);
		rsc->rxbuf_h = NULL;
	}

	rtw_free_dma_mem(&rsc->sc_desc_dma);
}

static int
rtw_dma_init(dev_info_t *devinfo, rtw_softc_t *rsc)
{
	int i, j, err;
	size_t size;
	uint32_t buflen;
	struct rtw_txdesc *txds;
	struct rtw_rxdesc *rxds;
	struct rtw_txbuf *txbf;
	struct rtw_rxbuf *rxbf;
	uint32_t phybaseaddr, ptx[RTW_NTXPRI], prx;
	caddr_t virbaseaddr, vtx[RTW_NTXPRI], vrx;

	/* DMA buffer size for each TX/RX packet */
	rsc->sc_dmabuf_size = roundup(sizeof (struct ieee80211_frame) + 0x100 +
	    IEEE80211_MTU + IEEE80211_CRC_LEN + sizeof (struct ieee80211_llc) +
	    (IEEE80211_WEP_IVLEN + IEEE80211_WEP_KIDLEN +
	    IEEE80211_WEP_CRCLEN), rsc->sc_cachelsz);
	size = sizeof (struct rtw_descs);
	err = rtw_alloc_dma_mem(devinfo, &dma_attr_desc, size,
	    &rtw_desc_accattr,
	    DDI_DMA_CONSISTENT, DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &rsc->sc_desc_dma);
	if (err != DDI_SUCCESS)
		goto error;
	phybaseaddr = rsc->sc_desc_dma.cookie.dmac_address;
	virbaseaddr = rsc->sc_desc_dma.mem_va;
	ptx[0] = RTW_RING_BASE(phybaseaddr, hd_txlo);
	ptx[1] = RTW_RING_BASE(phybaseaddr, hd_txmd);
	ptx[2] = RTW_RING_BASE(phybaseaddr, hd_txhi);
	ptx[3] = RTW_RING_BASE(phybaseaddr, hd_bcn);
	vtx[0] = (caddr_t)(RTW_RING_BASE(virbaseaddr, hd_txlo));
	vtx[1] = (caddr_t)(RTW_RING_BASE(virbaseaddr, hd_txmd));
	vtx[2] = (caddr_t)(RTW_RING_BASE(virbaseaddr, hd_txhi));
	vtx[3] = (caddr_t)(RTW_RING_BASE(virbaseaddr, hd_bcn));
	for (i = 0; i < RTW_NTXPRI; i++) {
		RTW_DPRINTF(RTW_DEBUG_DMA, "p[%d]=%x, v[%d]=%x", i, ptx[i],
		    i, vtx[i]);
		RTW_DPRINTF(RTW_DEBUG_DMA, "ring%d:", i);
		list_create(&rsc->sc_txq[i].tx_free_list,
		    sizeof (struct rtw_txbuf),
		    offsetof(struct rtw_txbuf, bf_node));
		list_create(&rsc->sc_txq[i].tx_dirty_list,
		    sizeof (struct rtw_txbuf),
		    offsetof(struct rtw_txbuf, bf_node));
		/* virtual address of the first descriptor */
		rsc->sc_txq[i].txdesc_h =
		    (struct rtw_txdesc *)(uintptr_t)vtx[i];

		txds = rsc->sc_txq[i].txdesc_h;
		/* allocate data structures to describe TX DMA buffers */
		buflen = sizeof (struct rtw_txbuf) * rtw_qlen[i];
		txbf = (struct rtw_txbuf *)kmem_zalloc(buflen, KM_SLEEP);
		rsc->sc_txq[i].txbuf_h = txbf;
		for (j = 0; j < rtw_qlen[i]; j++, txbf++, txds++) {
			txbf->txdesc = txds;
			txbf->bf_daddr = ptx[i] + ((uintptr_t)txds -
			    (uintptr_t)rsc->sc_txq[i].txdesc_h);
			list_insert_tail(&rsc->sc_txq[i].tx_free_list, txbf);

			/* alloc DMA memory */
			err = rtw_alloc_dma_mem(devinfo, &dma_attr_txbuf,
			    rsc->sc_dmabuf_size,
			    &rtw_buf_accattr,
			    DDI_DMA_STREAMING,
			    DDI_DMA_WRITE | DDI_DMA_STREAMING,
			    &txbf->bf_dma);
			if (err != DDI_SUCCESS)
				goto error;
			RTW_DPRINTF(RTW_DEBUG_DMA, "pbufaddr[%d]=%x",
			    j, txbf->bf_dma.cookie.dmac_address);
		}
	}
	prx = RTW_RING_BASE(phybaseaddr, hd_rx);
	vrx = (caddr_t)(RTW_RING_BASE(virbaseaddr, hd_rx));
	/* virtual address of the first descriptor */
	rsc->rxdesc_h = (struct rtw_rxdesc *)(uintptr_t)vrx;
	rxds = rsc->rxdesc_h;

	/* allocate data structures to describe RX DMA buffers */
	buflen = sizeof (struct rtw_rxbuf) * RTW_RXQLEN;
	rxbf = (struct rtw_rxbuf *)kmem_zalloc(buflen, KM_SLEEP);
	rsc->rxbuf_h = rxbf;

	for (j = 0; j < RTW_RXQLEN; j++, rxbf++, rxds++) {
		rxbf->rxdesc = rxds;
		rxbf->bf_daddr =
		    prx + ((uintptr_t)rxds - (uintptr_t)rsc->rxdesc_h);

		/* alloc DMA memory */
		err = rtw_alloc_dma_mem(devinfo, &dma_attr_rxbuf,
		    rsc->sc_dmabuf_size,
		    &rtw_buf_accattr,
		    DDI_DMA_STREAMING, DDI_DMA_READ | DDI_DMA_STREAMING,
		    &rxbf->bf_dma);
		if (err != DDI_SUCCESS)
			goto error;
	}

	return (DDI_SUCCESS);
error:
	return (DDI_FAILURE);
}

static void
rtw_hwring_setup(rtw_softc_t *rsc)
{
	struct rtw_regs *regs = &rsc->sc_regs;
	uint32_t phybaseaddr;

	phybaseaddr = rsc->sc_desc_dma.cookie.dmac_address;

	RTW_WRITE(regs, RTW_RDSAR, RTW_RING_BASE(phybaseaddr, hd_rx));
	RTW_WRITE(regs, RTW_TLPDA, RTW_RING_BASE(phybaseaddr, hd_txlo));
	RTW_WRITE(regs, RTW_TNPDA, RTW_RING_BASE(phybaseaddr, hd_txmd));
	RTW_WRITE(regs, RTW_THPDA, RTW_RING_BASE(phybaseaddr, hd_txhi));
	RTW_WRITE(regs, RTW_TBDA, RTW_RING_BASE(phybaseaddr, hd_bcn));
	rsc->hw_start = RTW_READ(regs, RTW_TNPDA);
	rsc->hw_go = RTW_READ(regs, RTW_TNPDA);
}

static void
rtw_swring_setup(rtw_softc_t *rsc, int flag)
{
	int i, j;
	int is_last;
	struct rtw_txbuf *txbf;
	struct rtw_rxbuf *rxbf;
	uint32_t phybaseaddr, ptx[RTW_NTXPRI], baddr_desc, taddr_desc;

	phybaseaddr = rsc->sc_desc_dma.cookie.dmac_address;
	ptx[0] = RTW_RING_BASE(phybaseaddr, hd_txlo);
	ptx[1] = RTW_RING_BASE(phybaseaddr, hd_txmd);
	ptx[2] = RTW_RING_BASE(phybaseaddr, hd_txhi);
	ptx[3] = RTW_RING_BASE(phybaseaddr, hd_bcn);
	RTW_DMA_SYNC(rsc->sc_desc_dma, DDI_DMA_SYNC_FORDEV);
	/* sync tx desc and tx buf */
	for (i = 0; i < RTW_NTXPRI; i++) {
		rsc->sc_txq[i].tx_prod = rsc->sc_txq[i].tx_cons = 0;
		rsc->sc_txq[i].tx_nfree = rtw_qlen[i];
		txbf = list_head(&rsc->sc_txq[i].tx_free_list);
		while (txbf != NULL) {
			list_remove(&rsc->sc_txq[i].tx_free_list, txbf);
			txbf = list_head(&rsc->sc_txq[i].tx_free_list);
		}
		txbf = list_head(&rsc->sc_txq[i].tx_dirty_list);
		while (txbf != NULL) {
			list_remove(&rsc->sc_txq[i].tx_dirty_list, txbf);
			txbf = list_head(&rsc->sc_txq[i].tx_dirty_list);
		}
		txbf = rsc->sc_txq[i].txbuf_h;
		baddr_desc = ptx[i];
		taddr_desc = baddr_desc + sizeof (struct rtw_txdesc);
		for (j = 0; j < rtw_qlen[i]; j++) {
			list_insert_tail(&rsc->sc_txq[i].tx_free_list, txbf);
			if (j == (rtw_qlen[i] - 1)) {
				is_last = 1;
			} else {
				is_last = 0;
			}

			if (is_last) {
				txbf->txdesc->td_next = baddr_desc;
			} else {
				txbf->txdesc->td_next = taddr_desc;
			}
			txbf->next_bf_daddr = txbf->txdesc->td_next;
			RTW_DMA_SYNC(txbf->bf_dma, DDI_DMA_SYNC_FORDEV);
			txbf->order = j;
			txbf++;
			taddr_desc += sizeof (struct rtw_txdesc);
		}
	}
	if (!flag)
		return;

	/* sync rx desc and rx buf */
	rsc->rx_next = 0;
	rxbf = rsc->rxbuf_h;
	for (j = 0; j < RTW_RXQLEN; j++) {
		RTW_DMA_SYNC(rxbf->bf_dma, DDI_DMA_SYNC_FORCPU);
		if (j == (RTW_RXQLEN - 1))
			is_last = 1;
		else
			is_last = 0;
		rtw_rxdesc_init(rsc, rxbf, j, is_last);
		rxbf++;
	}
}

static void
rtw_resume_ticks(rtw_softc_t *rsc)
{
	RTW_WRITE(&rsc->sc_regs, RTW_TINT, 0xffffffff);
}

const char *
rtw_pwrstate_string(enum rtw_pwrstate power)
{
	switch (power) {
	case RTW_ON:
		return ("on");
	case RTW_SLEEP:
		return ("sleep");
	case RTW_OFF:
		return ("off");
	default:
		return ("unknown");
	}
}

/*
 * XXX For Maxim, I am using the RFMD settings gleaned from the
 * reference driver, plus a magic Maxim "ON" value that comes from
 * the Realtek document "Windows PG for Rtl8180."
 */
/*ARGSUSED*/
static void
rtw_maxim_pwrstate(struct rtw_regs *regs, enum rtw_pwrstate power,
    int before_rf, int digphy)
{
	uint32_t anaparm;

	anaparm = RTW_READ(regs, RTW_ANAPARM);
	anaparm &= ~(RTW_ANAPARM_RFPOW_MASK | RTW_ANAPARM_TXDACOFF);

	switch (power) {
	case RTW_OFF:
		if (before_rf)
			return;
		anaparm |= RTW_ANAPARM_RFPOW_MAXIM_OFF;
		anaparm |= RTW_ANAPARM_TXDACOFF;
		break;
	case RTW_SLEEP:
		if (!before_rf)
			return;
		anaparm |= RTW_ANAPARM_RFPOW_MAXIM_SLEEP;
		anaparm |= RTW_ANAPARM_TXDACOFF;
		break;
	case RTW_ON:
		if (!before_rf)
			return;
		anaparm |= RTW_ANAPARM_RFPOW_MAXIM_ON;
		break;
	}
	RTW_DPRINTF(RTW_DEBUG_PWR,
	    "%s: power state %s, %s RF, reg[ANAPARM] <- %08x\n",
	    __func__, rtw_pwrstate_string(power),
	    (before_rf) ? "before" : "after", anaparm);

	RTW_WRITE(regs, RTW_ANAPARM, anaparm);
	RTW_SYNC(regs, RTW_ANAPARM, RTW_ANAPARM);
}

/*
 * XXX I am using the RFMD settings gleaned from the reference
 * driver.  They agree
 */
/*ARGSUSED*/
static void
rtw_rfmd_pwrstate(struct rtw_regs *regs, enum rtw_pwrstate power,
    int before_rf, int digphy)
{
	uint32_t anaparm;

	anaparm = RTW_READ(regs, RTW_ANAPARM);
	anaparm &= ~(RTW_ANAPARM_RFPOW_MASK | RTW_ANAPARM_TXDACOFF);

	switch (power) {
	case RTW_OFF:
		if (before_rf)
			return;
		anaparm |= RTW_ANAPARM_RFPOW_RFMD_OFF;
		anaparm |= RTW_ANAPARM_TXDACOFF;
		break;
	case RTW_SLEEP:
		if (!before_rf)
			return;
		anaparm |= RTW_ANAPARM_RFPOW_RFMD_SLEEP;
		anaparm |= RTW_ANAPARM_TXDACOFF;
		break;
	case RTW_ON:
		if (!before_rf)
			return;
		anaparm |= RTW_ANAPARM_RFPOW_RFMD_ON;
		break;
	}
	RTW_DPRINTF(RTW_DEBUG_PWR,
	    "%s: power state %s, %s RF, reg[ANAPARM] <- %08x\n",
	    __func__, rtw_pwrstate_string(power),
	    (before_rf) ? "before" : "after", anaparm);

	RTW_WRITE(regs, RTW_ANAPARM, anaparm);
	RTW_SYNC(regs, RTW_ANAPARM, RTW_ANAPARM);
}

static void
rtw_philips_pwrstate(struct rtw_regs *regs, enum rtw_pwrstate power,
    int before_rf, int digphy)
{
	uint32_t anaparm;

	anaparm = RTW_READ(regs, RTW_ANAPARM);
	anaparm &= ~(RTW_ANAPARM_RFPOW_MASK | RTW_ANAPARM_TXDACOFF);

	switch (power) {
	case RTW_OFF:
		if (before_rf)
			return;
		anaparm |= RTW_ANAPARM_RFPOW_PHILIPS_OFF;
		anaparm |= RTW_ANAPARM_TXDACOFF;
		break;
	case RTW_SLEEP:
		if (!before_rf)
			return;
		anaparm |= RTW_ANAPARM_RFPOW_PHILIPS_SLEEP;
		anaparm |= RTW_ANAPARM_TXDACOFF;
		break;
	case RTW_ON:
		if (!before_rf)
			return;
		if (digphy) {
			anaparm |= RTW_ANAPARM_RFPOW_DIG_PHILIPS_ON;
			/* XXX guess */
			anaparm |= RTW_ANAPARM_TXDACOFF;
		} else
			anaparm |= RTW_ANAPARM_RFPOW_ANA_PHILIPS_ON;
		break;
	}
	RTW_DPRINTF(RTW_DEBUG_PWR,
	    "%s: power state %s, %s RF, reg[ANAPARM] <- %08x\n",
	    __func__, rtw_pwrstate_string(power),
	    (before_rf) ? "before" : "after", anaparm);

	RTW_WRITE(regs, RTW_ANAPARM, anaparm);
	RTW_SYNC(regs, RTW_ANAPARM, RTW_ANAPARM);
}

static void
rtw_pwrstate0(rtw_softc_t *rsc, enum rtw_pwrstate power, int before_rf,
    int digphy)
{
	struct rtw_regs *regs = &rsc->sc_regs;

	rtw_set_access(regs, RTW_ACCESS_ANAPARM);

	(*rsc->sc_pwrstate_cb)(regs, power, before_rf, digphy);

	rtw_set_access(regs, RTW_ACCESS_NONE);
}

static void
rtw_rf_destroy(struct rtw_rf *rf)
{
	(*rf->rf_destroy)(rf);
}

static int
rtw_rf_pwrstate(struct rtw_rf *rf, enum rtw_pwrstate power)
{
	return (*rf->rf_pwrstate)(rf, power);
}

static int
rtw_pwrstate(rtw_softc_t *rsc, enum rtw_pwrstate power)
{
	int rc;

	RTW_DPRINTF(RTW_DEBUG_PWR,
	    "%s: %s->%s\n", __func__,
	    rtw_pwrstate_string(rsc->sc_pwrstate), rtw_pwrstate_string(power));

	if (rsc->sc_pwrstate == power)
		return (0);

	rtw_pwrstate0(rsc, power, 1, rsc->sc_flags & RTW_F_DIGPHY);
	rc = rtw_rf_pwrstate(rsc->sc_rf, power);
	rtw_pwrstate0(rsc, power, 0, rsc->sc_flags & RTW_F_DIGPHY);

	switch (power) {
	case RTW_ON:
		/* TBD set LEDs */
		break;
	case RTW_SLEEP:
		/* TBD */
		break;
	case RTW_OFF:
		/* TBD */
		break;
	}
	if (rc == 0)
		rsc->sc_pwrstate = power;
	else
		rsc->sc_pwrstate = RTW_OFF;
	return (rc);
}

void
rtw_disable(rtw_softc_t *rsc)
{
	int rc;

	if ((rsc->sc_flags & RTW_F_ENABLED) == 0)
		return;

	/* turn off PHY */
	if ((rsc->sc_flags & RTW_F_INVALID) == 0 &&
	    (rc = rtw_pwrstate(rsc, RTW_OFF)) != 0) {
		cmn_err(CE_WARN, "failed to turn off PHY (%d)\n", rc);
	}

	if (rsc->sc_disable != NULL)
		(*rsc->sc_disable)(rsc);

	rsc->sc_flags &= ~RTW_F_ENABLED;
}

int
rtw_enable(rtw_softc_t *rsc)
{
	if ((rsc->sc_flags & RTW_F_ENABLED) == 0) {
		if (rsc->sc_enable != NULL && (*rsc->sc_enable)(rsc) != 0) {
			cmn_err(CE_WARN, "device enable failed\n");
			return (EIO);
		}
		rsc->sc_flags |= RTW_F_ENABLED;
		if (rtw_pwrstate(rsc, RTW_ON) != 0)
			cmn_err(CE_WARN, "PHY turn on failed\n");
	}
	return (0);
}

static void
rtw_set_nettype(rtw_softc_t *rsc, enum ieee80211_opmode opmode)
{
	uint8_t msr;

	/* I'm guessing that MSR is protected as CONFIG[0123] are. */
	rtw_set_access(&rsc->sc_regs, RTW_ACCESS_CONFIG);

	msr = RTW_READ8(&rsc->sc_regs, RTW_MSR) & ~RTW_MSR_NETYPE_MASK;

	switch (opmode) {
	case IEEE80211_M_AHDEMO:
	case IEEE80211_M_IBSS:
		msr |= RTW_MSR_NETYPE_ADHOC_OK;
		break;
	case IEEE80211_M_HOSTAP:
		msr |= RTW_MSR_NETYPE_AP_OK;
		break;
	case IEEE80211_M_STA:
		msr |= RTW_MSR_NETYPE_INFRA_OK;
		break;
	}
	RTW_WRITE8(&rsc->sc_regs, RTW_MSR, msr);

	rtw_set_access(&rsc->sc_regs, RTW_ACCESS_NONE);
}

static void
rtw_pktfilt_load(rtw_softc_t *rsc)
{
	struct rtw_regs *regs = &rsc->sc_regs;
	struct ieee80211com *ic = &rsc->sc_ic;

	/* XXX might be necessary to stop Rx/Tx engines while setting filters */
	rsc->sc_rcr &= ~RTW_RCR_PKTFILTER_MASK;
	rsc->sc_rcr &= ~(RTW_RCR_MXDMA_MASK | RTW_RCR_RXFTH_MASK);

	rsc->sc_rcr |= RTW_RCR_PKTFILTER_DEFAULT;
	/* MAC auto-reset PHY (huh?) */
	rsc->sc_rcr |= RTW_RCR_ENMARP;
	/* DMA whole Rx packets, only.  Set Tx DMA burst size to 1024 bytes. */
	rsc->sc_rcr |= RTW_RCR_RXFTH_WHOLE |RTW_RCR_MXDMA_1024;

	switch (ic->ic_opmode) {
	case IEEE80211_M_AHDEMO:
	case IEEE80211_M_IBSS:
		/* receive broadcasts in our BSS */
		rsc->sc_rcr |= RTW_RCR_ADD3;
		break;
	default:
		break;
	}
#if 0
	/* XXX accept all broadcast if scanning */
	rsc->sc_rcr |= RTW_RCR_AB;	/* accept all broadcast */
#endif
	RTW_WRITE(regs, RTW_MAR0, 0xffffffff);
	RTW_WRITE(regs, RTW_MAR1, 0xffffffff);
	rsc->sc_rcr |= RTW_RCR_AM;
	RTW_WRITE(regs, RTW_RCR, rsc->sc_rcr);
	RTW_SYNC(regs, RTW_MAR0, RTW_RCR); /* RTW_MAR0 < RTW_MAR1 < RTW_RCR */

	RTW_DPRINTF(RTW_DEBUG_PKTFILT,
	    "RTW_MAR0 %08x RTW_MAR1 %08x RTW_RCR %08x\n",
	    RTW_READ(regs, RTW_MAR0),
	    RTW_READ(regs, RTW_MAR1), RTW_READ(regs, RTW_RCR));
	RTW_WRITE(regs, RTW_RCR, rsc->sc_rcr);
}

static void
rtw_transmit_config(struct rtw_regs *regs)
{
	uint32_t tcr;

	tcr = RTW_READ(regs, RTW_TCR);

	tcr |= RTW_TCR_CWMIN;
	tcr &= ~RTW_TCR_MXDMA_MASK;
	tcr |= RTW_TCR_MXDMA_1024;
	tcr |= RTW_TCR_SAT;		/* send ACK as fast as possible */
	tcr &= ~RTW_TCR_LBK_MASK;
	tcr |= RTW_TCR_LBK_NORMAL;	/* normal operating mode */

	/* set short/long retry limits */
	tcr &= ~(RTW_TCR_SRL_MASK|RTW_TCR_LRL_MASK);
	tcr |= LSHIFT(0x4, RTW_TCR_SRL_MASK) | LSHIFT(0x4, RTW_TCR_LRL_MASK);

	tcr &= ~RTW_TCR_CRC;	/* NIC appends CRC32 */
	RTW_WRITE(regs, RTW_TCR, tcr);
	RTW_SYNC(regs, RTW_TCR, RTW_TCR);
}

int
rtw_refine_setting(rtw_softc_t *rsc)
{
	struct rtw_regs *regs;
	int rc = 0;

	regs = &rsc->sc_regs;
	rc = rtw_reset(rsc);
	if (rc != 0)
		return (-1);

	rtw_beacon_tx_disable(regs);
	rtw_io_enable(rsc, RTW_CR_RE|RTW_CR_TE, 1);
	rtw_set_mode(regs, RTW_EPROM_CMD_CONFIG);

	rtw_transmit_config(regs);
	rtw_pktfilt_load(rsc);
	rtw_set_access(regs, RTW_ACCESS_CONFIG);
	RTW_WRITE(regs, RTW_TINT, 0xffffffff);
	RTW_WRITE8(regs, RTW_MSR, 0x0);	/* no link */
	RTW_WRITE16(regs, RTW_BRSR, 0);

	rtw_set_access(regs, RTW_ACCESS_ANAPARM);
	rtw_set_access(regs, RTW_ACCESS_NONE);
	RTW_WRITE(regs, RTW_FEMR, 0xffff);
	RTW_SYNC(regs, RTW_FEMR, RTW_FEMR);
	rtw_set_rfprog(regs, rsc->sc_rfchipid, "rtw");

	RTW_WRITE8(regs, RTW_PHYDELAY, rsc->sc_phydelay);
	RTW_WRITE8(regs, RTW_CRCOUNT, RTW_CRCOUNT_MAGIC);
	rtw_set_mode(regs, RTW_EPROM_CMD_NORMAL);
	return (0);
}

static int
rtw_tune(rtw_softc_t *rsc)
{
	struct ieee80211com *ic = &rsc->sc_ic;
	uint32_t chan;
	int rc;
	int antdiv = rsc->sc_flags & RTW_F_ANTDIV,
	    dflantb = rsc->sc_flags & RTW_F_DFLANTB;

	ASSERT(ic->ic_curchan != NULL);

	chan = ieee80211_chan2ieee(ic, ic->ic_curchan);
	RTW_DPRINTF(RTW_DEBUG_TUNE, "rtw: chan no = %x", chan);

	if (chan == IEEE80211_CHAN_ANY) {
		cmn_err(CE_WARN, "%s: chan == IEEE80211_CHAN_ANY\n", __func__);
		return (-1);
	}

	if (chan == rsc->sc_cur_chan) {
		RTW_DPRINTF(RTW_DEBUG_TUNE,
		    "%s: already tuned chan %d\n", __func__, chan);
		return (0);
	}
	rtw_idle(&rsc->sc_regs);
	rtw_io_enable(rsc, RTW_CR_RE | RTW_CR_TE, 0);
	ASSERT((rsc->sc_flags & RTW_F_ENABLED) != 0);

	if ((rc = rtw_phy_init(&rsc->sc_regs, rsc->sc_rf,
	    rtw_chan2txpower(&rsc->sc_srom, ic, ic->ic_curchan),
	    rsc->sc_csthr, ic->ic_curchan->ich_freq, antdiv,
	    dflantb, RTW_ON)) != 0) {
		/* XXX condition on powersaving */
		cmn_err(CE_NOTE, "phy init failed\n");
	}
	rtw_io_enable(rsc, RTW_CR_RE | RTW_CR_TE, 1);
	rtw_resume_ticks(rsc);
	rsc->sc_cur_chan = chan;
	return (rc);
}

static int
rtw_init(rtw_softc_t *rsc)
{
	struct ieee80211com *ic = &rsc->sc_ic;
	int rc = 0;

	rtw_stop(rsc);
	mutex_enter(&rsc->sc_genlock);
	if ((rc = rtw_enable(rsc)) != 0)
		goto out;
	rc = rtw_refine_setting(rsc);
	if (rc != 0) {
		mutex_exit(&rsc->sc_genlock);
		return (rc);
	}
	rtw_swring_setup(rsc, 1);
	rtw_hwring_setup(rsc);
	RTW_WRITE16(&rsc->sc_regs, RTW_BSSID16, 0x0);
	RTW_WRITE(&rsc->sc_regs, RTW_BSSID32, 0x0);
	rtw_enable_interrupts(rsc);

	ic->ic_ibss_chan = &ic->ic_sup_channels[1];
	ic->ic_curchan = ic->ic_ibss_chan;
	RTW_DPRINTF(RTW_DEBUG_TUNE, "%s: channel %d freq %d flags 0x%04x\n",
	    __func__, ieee80211_chan2ieee(ic, ic->ic_curchan),
	    ic->ic_curchan->ich_freq, ic->ic_curchan->ich_flags);
	rsc->sc_invalid = 0;
out:
	mutex_exit(&rsc->sc_genlock);
	return (rc);
}

static struct rtw_rf *
rtw_rf_attach(rtw_softc_t *rsc, enum rtw_rfchipid rfchipid, int digphy)
{
	rtw_rf_write_t rf_write;
	struct rtw_rf *rf;
	int rtw_host_rfio;

	switch (rfchipid) {
	default:
		rf_write = rtw_rf_hostwrite;
		break;
	case RTW_RFCHIPID_INTERSIL:
	case RTW_RFCHIPID_PHILIPS:
	case RTW_RFCHIPID_GCT:	/* XXX a guess */
	case RTW_RFCHIPID_RFMD:
		rtw_host_rfio = 1;
		rf_write = (rtw_host_rfio) ? rtw_rf_hostwrite : rtw_rf_macwrite;
		break;
	}

	switch (rfchipid) {
	case RTW_RFCHIPID_MAXIM:
		rf = rtw_max2820_create(&rsc->sc_regs, rf_write, 0);
		rsc->sc_pwrstate_cb = rtw_maxim_pwrstate;
		break;
	case RTW_RFCHIPID_PHILIPS:
		rf = rtw_sa2400_create(&rsc->sc_regs, rf_write, digphy);
		rsc->sc_pwrstate_cb = rtw_philips_pwrstate;
		break;
	case RTW_RFCHIPID_RFMD:
		/* XXX RFMD has no RF constructor */
		rsc->sc_pwrstate_cb = rtw_rfmd_pwrstate;
		/*FALLTHROUGH*/
	default:
		return (NULL);
	}
	if (rf != NULL) {
		rf->rf_continuous_tx_cb =
		    (rtw_continuous_tx_cb_t)rtw_continuous_tx_enable;
		rf->rf_continuous_tx_arg = (void *)rsc;
	}
	return (rf);
}

/*
 * Revision C and later use a different PHY delay setting than
 * revisions A and B.
 */
static uint8_t
rtw_check_phydelay(struct rtw_regs *regs, uint32_t rcr0)
{
#define	REVAB (RTW_RCR_MXDMA_UNLIMITED | RTW_RCR_AICV)
#define	REVC (REVAB | RTW_RCR_RXFTH_WHOLE)

	uint8_t phydelay = LSHIFT(0x6, RTW_PHYDELAY_PHYDELAY);

	RTW_WRITE(regs, RTW_RCR, REVAB);
	RTW_WBW(regs, RTW_RCR, RTW_RCR);
	RTW_WRITE(regs, RTW_RCR, REVC);

	RTW_WBR(regs, RTW_RCR, RTW_RCR);
	if ((RTW_READ(regs, RTW_RCR) & REVC) == REVC)
		phydelay |= RTW_PHYDELAY_REVC_MAGIC;

	RTW_WRITE(regs, RTW_RCR, rcr0);	/* restore RCR */
	RTW_SYNC(regs, RTW_RCR, RTW_RCR);

	return (phydelay);
#undef REVC
}

static void rtw_intr_rx(rtw_softc_t *rsc);
static void rtw_ring_recycling(rtw_softc_t *rsc, uint16_t isr, uint32_t pri);

static int
rtw_get_rate(struct ieee80211com *ic)
{
	uint8_t (*rates)[IEEE80211_RATE_MAXSIZE];
	int rate;

	rates = &ic->ic_bss->in_rates.ir_rates;

	if (ic->ic_fixed_rate != IEEE80211_FIXED_RATE_NONE)
		rate = ic->ic_fixed_rate;
	else if (ic->ic_state == IEEE80211_S_RUN)
		rate = (*rates)[ic->ic_bss->in_txrate];
	else
		rate = 0;
	return (rate & IEEE80211_RATE_VAL);
}

/*
 * Arguments in:
 *
 * paylen:  payload length (no FCS, no WEP header)
 *
 * hdrlen:  header length
 *
 * rate:    MSDU speed, units 500kb/s
 *
 * flags:   IEEE80211_F_SHPREAMBLE (use short preamble),
 *          IEEE80211_F_SHSLOT (use short slot length)
 *
 * Arguments out:
 *
 * d:       802.11 Duration field for RTS,
 *          802.11 Duration field for data frame,
 *          PLCP Length for data frame,
 *          residual octets at end of data slot
 */
static int
rtw_compute_duration1(int len, int use_ack, uint32_t flags, int rate,
    struct rtw_ieee80211_duration *d)
{
	int pre, ctsrate;
	uint16_t ack, bitlen, data_dur, remainder;

	/*
	 * RTS reserves medium for SIFS | CTS | SIFS | (DATA) | SIFS | ACK
	 * DATA reserves medium for SIFS | ACK
	 *
	 * XXXMYC: no ACK on multicast/broadcast or control packets
	 */

	bitlen = len * 8;

	pre = IEEE80211_DUR_DS_SIFS;
	if ((flags & IEEE80211_F_SHPREAMBLE) != 0)
		pre += IEEE80211_DUR_DS_SHORT_PREAMBLE +
		    IEEE80211_DUR_DS_FAST_PLCPHDR;
	else
		pre += IEEE80211_DUR_DS_LONG_PREAMBLE +
		    IEEE80211_DUR_DS_SLOW_PLCPHDR;

	d->d_residue = 0;
	data_dur = (bitlen * 2) / rate;
	remainder = (bitlen * 2) % rate;
	if (remainder != 0) {
		if (rate == 22)
			d->d_residue = (rate - remainder) / 16;
		data_dur++;
	}

	switch (rate) {
	case 2:		/* 1 Mb/s */
	case 4:		/* 2 Mb/s */
		/* 1 - 2 Mb/s WLAN: send ACK/CTS at 1 Mb/s */
		ctsrate = 2;
		break;
	case 11:	/* 5.5 Mb/s */
	case 22:	/* 11  Mb/s */
	case 44:	/* 22  Mb/s */
		/* 5.5 - 11 Mb/s WLAN: send ACK/CTS at 2 Mb/s */
		ctsrate = 4;
		break;
	default:
		/* TBD */
		return (-1);
	}

	d->d_plcp_len = data_dur;

	ack = (use_ack) ? pre + (IEEE80211_DUR_DS_SLOW_ACK * 2) / ctsrate : 0;

	d->d_rts_dur =
	    pre + (IEEE80211_DUR_DS_SLOW_CTS * 2) / ctsrate +
	    pre + data_dur +
	    ack;

	d->d_data_dur = ack;

	return (0);
}

/*
 * Arguments in:
 *
 * wh:      802.11 header
 *
 * paylen:  payload length (no FCS, no WEP header)
 *
 * rate:    MSDU speed, units 500kb/s
 *
 * fraglen: fragment length, set to maximum (or higher) for no
 *          fragmentation
 *
 * flags:   IEEE80211_F_PRIVACY (hardware adds WEP),
 *          IEEE80211_F_SHPREAMBLE (use short preamble),
 *          IEEE80211_F_SHSLOT (use short slot length)
 *
 * Arguments out:
 *
 * d0: 802.11 Duration fields (RTS/Data), PLCP Length, Service fields
 *     of first/only fragment
 *
 * dn: 802.11 Duration fields (RTS/Data), PLCP Length, Service fields
 *     of first/only fragment
 */
static int
rtw_compute_duration(struct ieee80211_frame *wh, int len,
    uint32_t flags, int fraglen, int rate, struct rtw_ieee80211_duration *d0,
    struct rtw_ieee80211_duration *dn, int *npktp)
{
	int ack, rc;
	int firstlen, hdrlen, lastlen, lastlen0, npkt, overlen, paylen;

	/* don't think about addr4 here */
	hdrlen = sizeof (struct ieee80211_frame);

	paylen = len - hdrlen;

	if ((wh->i_fc[1] & IEEE80211_FC1_WEP) != 0) {
		overlen = 8 + IEEE80211_CRC_LEN;
		paylen -= 8;
	} else
		overlen = IEEE80211_CRC_LEN;

	npkt = paylen / fraglen;
	lastlen0 = paylen % fraglen;

	if (npkt == 0)			/* no fragments */
		lastlen = paylen + overlen;
	else if (lastlen0 != 0) {	/* a short "tail" fragment */
		lastlen = lastlen0 + overlen;
		npkt++;
	} else			/* full-length "tail" fragment */
		lastlen = fraglen + overlen;

	if (npktp != NULL)
		*npktp = npkt;

	if (npkt > 1)
		firstlen = fraglen + overlen;
	else
		firstlen = paylen + overlen;

	ack = !IEEE80211_IS_MULTICAST(wh->i_addr1) &&
	    (wh->i_fc[1] & IEEE80211_FC0_TYPE_MASK) !=
	    IEEE80211_FC0_TYPE_CTL;

	rc = rtw_compute_duration1(firstlen + hdrlen,
	    ack, flags, rate, d0);
	if (rc == -1)
		return (rc);

	if (npkt <= 1) {
		*dn = *d0;
		return (0);
	}
	return (rtw_compute_duration1(lastlen + hdrlen, ack, flags,
	    rate, dn));
}

static int
rtw_assembly_80211(rtw_softc_t *rsc, struct rtw_txbuf *bf,
    mblk_t *mp)
{
	ieee80211com_t *ic;
	struct rtw_txdesc *ds;
	struct ieee80211_frame *wh;
	uint8_t *buf;
	uint32_t ctl0 = 0, ctl1 = 0;
	int npkt, rate;
	struct rtw_ieee80211_duration d0, dn;
	int32_t iswep, pktlen, mblen;
	mblk_t *mp0;

	ic = &rsc->sc_ic;
	ds = bf->txdesc;
	buf = (uint8_t *)bf->bf_dma.mem_va;
	bzero(buf, bf->bf_dma.alength);
	bzero((uint8_t *)ds, sizeof (struct rtw_txdesc));
	wh = (struct ieee80211_frame *)mp->b_rptr;
	iswep = wh->i_fc[1] & IEEE80211_FC1_WEP;

	/* ieee80211_crypto_encap() needs a single mblk */
	mp0 = allocb(bf->bf_dma.alength, BPRI_MED);
	if (mp0 == NULL) {
		cmn_err(CE_WARN, "%s: allocb(mp) error", __func__);
		return (-1);
	}
	for (; mp != NULL; mp = mp->b_cont) {
			mblen = (uintptr_t)mp->b_wptr - (uintptr_t)mp->b_rptr;
			bcopy(mp->b_rptr, mp0->b_wptr, mblen);
			mp0->b_wptr += mblen;
	}

	if (iswep) {
		struct ieee80211_key *k;

		k = ieee80211_crypto_encap(ic, mp0);
		if (k == NULL) {
			cmn_err(CE_WARN, "%s: ieee80211_crypto_encap() error",
			    __func__);
			freemsg(mp0);
			return (-1);
		}
	}
	pktlen = msgdsize(mp0);

#if 0
	RTW_DPRINTF(RTW_DEBUG_XMIT, "-----------send------begin--------");
	ieee80211_dump_pkt((uint8_t *)(mp0->b_rptr), pktlen, 0, 0);
	RTW_DPRINTF(RTW_DEBUG_XMIT, "-----------send------end--------");
#endif
	/* RTW_DMA_SYNC(bf->bf_dma, DDI_DMA_SYNC_FORDEV); */
	if (pktlen > bf->bf_dma.alength) {
		cmn_err(CE_WARN, "%s: overlength packet pktlen = %d\n",
		    __func__, pktlen);
		freemsg(mp0);
		return (-1);
	}
	bcopy(mp0->b_rptr, buf, pktlen);
	RTW_DMA_SYNC(bf->bf_dma, DDI_DMA_SYNC_FORDEV);

	/* setup descriptor */
	ctl0 = RTW_TXCTL0_RTSRATE_1MBPS;

	if (((ic->ic_flags & IEEE80211_F_SHPREAMBLE) != 0) &&
	    (ic->ic_bss->in_capinfo & IEEE80211_CAPINFO_SHORT_PREAMBLE)) {
		ctl0 |= RTW_TXCTL0_SPLCP;
	}
	/* XXX do real rate control */
	if ((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) ==
	    IEEE80211_FC0_TYPE_MGT)
		rate = 2;
	else {
		rate = MAX(2, rtw_get_rate(ic));
	}
	ctl0 = ctl0 |
	    LSHIFT(pktlen, RTW_TXCTL0_TPKTSIZE_MASK);

	RTW_DPRINTF(RTW_DEBUG_XMIT, "%s: rate = %d", __func__, rate);

	switch (rate) {
	default:
	case 2:
		ctl0 |= RTW_TXCTL0_RATE_1MBPS;
		break;
	case 4:
		ctl0 |= RTW_TXCTL0_RATE_2MBPS;
		break;
	case 11:
		ctl0 |= RTW_TXCTL0_RATE_5MBPS;
		break;
	case 22:
		ctl0 |= RTW_TXCTL0_RATE_11MBPS;
		break;
	}

	/* XXX >= ? Compare after fragmentation? */
	if (pktlen > ic->ic_rtsthreshold) {
		ctl0 |= RTW_TXCTL0_RTSEN;
		cmn_err(CE_NOTE, "%s: fragmentation: pktlen = %d",
		    __func__, pktlen);
	}

	if ((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) ==
	    IEEE80211_FC0_TYPE_MGT) {
		ctl0 &= ~(RTW_TXCTL0_SPLCP | RTW_TXCTL0_RTSEN);
		if ((wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) ==
		    IEEE80211_FC0_SUBTYPE_BEACON)
			ctl0 |= RTW_TXCTL0_BEACON;
	}

	if (rtw_compute_duration(wh, pktlen,
	    ic->ic_flags, ic->ic_fragthreshold,
	    rate, &d0, &dn, &npkt) == -1) {
		RTW_DPRINTF(RTW_DEBUG_XMIT,
		    "%s: fail compute duration\n", __func__);
		freemsg(mp0);
		return (-1);
	}
	*(uint16_t *)(uintptr_t)wh->i_dur = (d0.d_data_dur);

	ctl1 = LSHIFT(d0.d_plcp_len, RTW_TXCTL1_LENGTH_MASK) |
	    LSHIFT(d0.d_rts_dur, RTW_TXCTL1_RTSDUR_MASK);

	if (d0.d_residue)
		ctl1 |= RTW_TXCTL1_LENGEXT;

	RTW_DPRINTF(RTW_DEBUG_XMIT, "%s: duration=%x, ctl1=%x", __func__,
	    *(uint16_t *)(uintptr_t)wh->i_dur, ctl1);

	if (bf->bf_dma.alength > RTW_TXLEN_LENGTH_MASK) {
		RTW_DPRINTF(RTW_DEBUG_XMIT,
		    "%s: seg too long\n", __func__);
		freemsg(mp0);
		return (-1);
	}
	ds->td_ctl0 = ctl0;
	ds->td_ctl0 |= RTW_TXCTL0_OWN | RTW_TXCTL0_LS | RTW_TXCTL0_FS;
	ds->td_ctl1 = ctl1;
	ds->td_buf = bf->bf_dma.cookie.dmac_address;
	ds->td_len = pktlen & 0xfff;
	ds->td_next = bf->next_bf_daddr;

	RTW_DMA_SYNC_DESC(rsc->sc_desc_dma,
	    RTW_DESC_OFFSET(hd_txmd, bf->order),
	    sizeof (struct rtw_txdesc),
	    DDI_DMA_SYNC_FORDEV);

	RTW_DPRINTF(RTW_DEBUG_XMIT,
	    "descriptor: order = %d, phy_addr=%x, ctl0=%x,"
	    " ctl1=%x, buf=%x, len=%x, next=%x", bf->order,
	    bf->bf_daddr, ds->td_ctl0, ds->td_ctl1,
	    ds->td_buf, ds->td_len, ds->td_next);
	rsc->sc_pktxmt64++;
	rsc->sc_bytexmt64 += pktlen;

	freemsg(mp0);
	return (0);
}

static int
rtw_send(ieee80211com_t *ic, mblk_t *mp, uint8_t type)
{
	rtw_softc_t *rsc = (rtw_softc_t *)ic;
	struct ieee80211_node *in = ic->ic_bss;
	struct rtw_txbuf *bf = NULL;
	int ret, i = RTW_TXPRIMD;

	mutex_enter(&rsc->sc_txlock);
	mutex_enter(&rsc->sc_txq[i].txbuf_lock);
	bf = list_head(&rsc->sc_txq[i].tx_free_list);

	if ((bf == NULL) || (rsc->sc_txq[i].tx_nfree <= 4)) {
		RTW_DPRINTF(RTW_DEBUG_XMIT, "%s: no tx buf\n", __func__);
		rsc->sc_noxmtbuf++;
		if ((type & IEEE80211_FC0_TYPE_MASK) ==
		    IEEE80211_FC0_TYPE_DATA) {
			RTW_DPRINTF(RTW_DEBUG_XMIT, "%s: need reschedule\n",
			    __func__);
			rsc->sc_need_reschedule = 1;
		} else {
			freemsg(mp);
		}
		mutex_exit(&rsc->sc_txq[i].txbuf_lock);
		mutex_exit(&rsc->sc_txlock);
		return (1);
	}
	list_remove(&rsc->sc_txq[i].tx_free_list, bf);
	rsc->sc_txq[i].tx_nfree--;

	/* assemble 802.11 frame here */
	ret = rtw_assembly_80211(rsc, bf, mp);
	if (ret != 0) {
		cmn_err(CE_WARN, "%s assembly frame error\n", __func__);
		mutex_exit(&rsc->sc_txq[i].txbuf_lock);
		mutex_exit(&rsc->sc_txlock);
		if ((type & IEEE80211_FC0_TYPE_MASK) !=
		    IEEE80211_FC0_TYPE_DATA) {
			freemsg(mp);
		}
		return (1);
	}
	list_insert_tail(&rsc->sc_txq[i].tx_dirty_list, bf);
	bf->bf_in = in;
	rtw_dma_start(&rsc->sc_regs, i);

	mutex_exit(&rsc->sc_txq[i].txbuf_lock);
	mutex_exit(&rsc->sc_txlock);

	freemsg(mp);
	return (0);
}

static mblk_t *
rtw_m_tx(void *arg, mblk_t *mp)
{
	rtw_softc_t *rsc = arg;
	ieee80211com_t *ic = (ieee80211com_t *)rsc;
	mblk_t *next;

	if (ic->ic_state != IEEE80211_S_RUN) {
		freemsgchain(mp);
		return (NULL);
	}

	while (mp != NULL) {
		next = mp->b_next;
		mp->b_next = NULL;

		if (rtw_send(ic, mp, IEEE80211_FC0_TYPE_DATA)) {
			mp->b_next = next;
			break;
		}
		mp = next;
	}

	return (mp);

}

static void
rtw_next_scan(void *arg)
{
	ieee80211com_t *ic = arg;
	rtw_softc_t *rsc = (rtw_softc_t *)arg;

	rsc->sc_scan_id = 0;
	if (ic->ic_state == IEEE80211_S_SCAN) {
		RTW_DPRINTF(RTW_DEBUG_TUNE, "rtw_next_scan\n");
		(void) ieee80211_next_scan(ic);
	}

}

static void
rtw_join_bss(rtw_softc_t *rsc, uint8_t *bssid, uint16_t intval0)
{
	uint16_t bcnitv, intval;
	int i;
	struct rtw_regs *regs = &rsc->sc_regs;

	for (i = 0; i < IEEE80211_ADDR_LEN; i++)
		RTW_WRITE8(regs, RTW_BSSID + i, bssid[i]);

	RTW_SYNC(regs, RTW_BSSID16, RTW_BSSID32);
	rtw_set_access(regs, RTW_ACCESS_CONFIG);

	RTW_WRITE8(regs, RTW_MSR, 0x8);	/* sta mode link ok */
	intval = MIN(intval0, PRESHIFT(RTW_BCNITV_BCNITV_MASK));

	bcnitv = RTW_READ16(regs, RTW_BCNITV) & ~RTW_BCNITV_BCNITV_MASK;
	bcnitv |= LSHIFT(intval, RTW_BCNITV_BCNITV_MASK);
	RTW_WRITE16(regs, RTW_BCNITV, bcnitv);
	RTW_WRITE16(regs, RTW_ATIMWND, LSHIFT(1, RTW_ATIMWND_ATIMWND));
	RTW_WRITE16(regs, RTW_ATIMTRITV, LSHIFT(2, RTW_ATIMTRITV_ATIMTRITV));

	rtw_set_access(regs, RTW_ACCESS_NONE);

	/* TBD WEP */
	/* RTW_WRITE8(regs, RTW_SCR, 0); */

	rtw_io_enable(rsc, RTW_CR_RE | RTW_CR_TE, 1);
}

/*
 * Set the starting transmit rate for a node.
 */
static void
rtw_rate_ctl_start(rtw_softc_t *rsc, struct ieee80211_node *in)
{
	ieee80211com_t *ic = (ieee80211com_t *)rsc;
	int32_t srate;

	if (ic->ic_fixed_rate == IEEE80211_FIXED_RATE_NONE) {
		/*
		 * No fixed rate is requested. For 11b start with
		 * the highest negotiated rate; otherwise, for 11g
		 * and 11a, we start "in the middle" at 24Mb or 36Mb.
		 */
		srate = in->in_rates.ir_nrates - 1;
		if (ic->ic_curmode != IEEE80211_MODE_11B) {
			/*
			 * Scan the negotiated rate set to find the
			 * closest rate.
			 */
			/* NB: the rate set is assumed sorted */
			for (; srate >= 0 && IEEE80211_RATE(srate) > 72;
			    srate--)
				;
		}
	} else {
		/*
		 * A fixed rate is to be used;  We know the rate is
		 * there because the rate set is checked when the
		 * station associates.
		 */
		/* NB: the rate set is assumed sorted */
		srate = in->in_rates.ir_nrates - 1;
		for (; srate >= 0 && IEEE80211_RATE(srate) != ic->ic_fixed_rate;
		    srate--)
			;
	}
	in->in_txrate = srate;
}


/*
 * Reset the rate control state for each 802.11 state transition.
 */
static void
rtw_rate_ctl_reset(rtw_softc_t *rsc, enum ieee80211_state state)
{
	ieee80211com_t *ic = &rsc->sc_ic;
	ieee80211_node_t *in;

	if (ic->ic_opmode == IEEE80211_M_STA) {
		/*
		 * Reset local xmit state; this is really only
		 * meaningful when operating in station mode.
		 */
		in = (struct ieee80211_node *)ic->ic_bss;

		if (state == IEEE80211_S_RUN) {
			rtw_rate_ctl_start(rsc, in);
		} else {
			in->in_txrate = 0;
		}
	}
}

/*
 * Examine and potentially adjust the transmit rate.
 */
static void
rtw_rate_ctl(void *arg)
{
	ieee80211com_t	*ic = (ieee80211com_t *)arg;
	rtw_softc_t *rsc = (rtw_softc_t *)ic;
	struct ieee80211_node *in = ic->ic_bss;
	struct ieee80211_rateset *rs = &in->in_rates;
	int32_t mod = 1, nrate, enough;

	mutex_enter(&rsc->sc_genlock);
	enough = (rsc->sc_tx_ok + rsc->sc_tx_err) >= 600? 1 : 0;

	/* err ratio is high -> down */
	if (enough && rsc->sc_tx_ok < rsc->sc_tx_err)
		mod = -1;

	nrate = in->in_txrate;
	switch (mod) {
	case -1:
		if (nrate > 0) {
			nrate--;
		}
		break;
	case 1:
		if (nrate + 1 < rs->ir_nrates) {
			nrate++;
		}
		break;
	}

	if (nrate != in->in_txrate)
		in->in_txrate = nrate;
	rsc->sc_tx_ok = rsc->sc_tx_err = rsc->sc_tx_retr = 0;
	mutex_exit(&rsc->sc_genlock);
	if (ic->ic_state == IEEE80211_S_RUN)
		rsc->sc_ratectl_id = timeout(rtw_rate_ctl, ic,
		    drv_usectohz(1000000));
}

static int32_t
rtw_new_state(ieee80211com_t *ic, enum ieee80211_state nstate, int arg)
{
	rtw_softc_t *rsc = (rtw_softc_t *)ic;
	int error;
	enum ieee80211_state ostate;

	ostate = ic->ic_state;

	RTW_DPRINTF(RTW_DEBUG_ATTACH,
	    "rtw_new_state: ostate:0x%x, nstate:0x%x, opmode:0x%x\n",
	    ostate, nstate, ic->ic_opmode);


	mutex_enter(&rsc->sc_genlock);
	if (rsc->sc_scan_id != 0) {
		(void) untimeout(rsc->sc_scan_id);
		rsc->sc_scan_id = 0;
	}
	if (rsc->sc_ratectl_id != 0) {
		(void) untimeout(rsc->sc_ratectl_id);
		rsc->sc_ratectl_id = 0;
	}
	rtw_rate_ctl_reset(rsc, nstate);
	if (ostate == IEEE80211_S_INIT && nstate != IEEE80211_S_INIT)
		(void) rtw_pwrstate(rsc, RTW_ON);
	if (nstate != IEEE80211_S_INIT) {
		if ((error = rtw_tune(rsc)) != 0) {
			mutex_exit(&rsc->sc_genlock);
			return (error);
		}
	}
	switch (nstate) {
	case IEEE80211_S_INIT:
		RTW_DPRINTF(RTW_DEBUG_ATTACH, "rtw_new_state: S_INIT\n");
		break;
	case IEEE80211_S_SCAN:
		RTW_DPRINTF(RTW_DEBUG_ATTACH, "rtw_new_state: S_SCAN\n");
		rsc->sc_scan_id = timeout(rtw_next_scan, ic,
		    drv_usectohz(200000));
		rtw_set_nettype(rsc, IEEE80211_M_MONITOR);
		break;
	case IEEE80211_S_RUN:
		RTW_DPRINTF(RTW_DEBUG_ATTACH, "rtw_new_state: S_RUN\n");
		switch (ic->ic_opmode) {
		case IEEE80211_M_HOSTAP:
		case IEEE80211_M_IBSS:
			rtw_set_nettype(rsc, IEEE80211_M_MONITOR);
			/* TBD */
			/*FALLTHROUGH*/
		case IEEE80211_M_AHDEMO:
		case IEEE80211_M_STA:
			RTW_DPRINTF(RTW_DEBUG_ATTACH,
			    "rtw_new_state: sta\n");
			rtw_join_bss(rsc, ic->ic_bss->in_bssid, 0);
			rsc->sc_ratectl_id = timeout(rtw_rate_ctl, ic,
			    drv_usectohz(1000000));
			break;
		case IEEE80211_M_MONITOR:
			break;
		}
		rtw_set_nettype(rsc, ic->ic_opmode);
		break;
	case IEEE80211_S_ASSOC:
	case IEEE80211_S_AUTH:
		break;
	}

	mutex_exit(&rsc->sc_genlock);
	/*
	 * Invoke the parent method to complete the work.
	 */
	error = rsc->sc_newstate(ic, nstate, arg);

	return (error);
}

static void
rtw_intr_rx(rtw_softc_t *rsc)
{
#define	IS_BEACON(__fc0)						\
	((__fc0 & (IEEE80211_FC0_TYPE_MASK | IEEE80211_FC0_SUBTYPE_MASK)) ==\
	(IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_BEACON))
	/*
	 * ratetbl[4] = {2, 4, 11, 22};
	 */
	struct rtw_rxbuf *bf;
	struct rtw_rxdesc *ds;
	int hwrate, len, rssi;
	uint32_t hstat, hrssi, htsftl;
	int is_last, next, n = 0, i;
	struct ieee80211_frame *wh;
	ieee80211com_t *ic = (ieee80211com_t *)rsc;
	mblk_t *mp;

	RTW_DPRINTF(RTW_DEBUG_RECV, "%s rtw_intr_rx: enter ic_state=%x\n",
	    __func__, rsc->sc_ic.ic_state);
	mutex_enter(&rsc->rxbuf_lock);
	next = rsc->rx_next;
	mutex_exit(&rsc->rxbuf_lock);
	for (i = 0; i < RTW_RXQLEN; i++) {
		RTW_DMA_SYNC_DESC(rsc->sc_desc_dma,
		    RTW_DESC_OFFSET(hd_rx, next),
		    sizeof (struct rtw_rxdesc),
		    DDI_DMA_SYNC_FORKERNEL);
		n++;
		bf = rsc->rxbuf_h + next;
		ds = bf->rxdesc;
		hstat = (ds->rd_stat);
		hrssi = ds->rd_rssi;
		htsftl = ds->rd_tsftl;
		/* htsfth = ds->rd_tsfth; */
		RTW_DPRINTF(RTW_DEBUG_RECV, "%s: stat=%x\n", __func__, hstat);
		/* still belongs to NIC */
		if ((hstat & RTW_RXSTAT_OWN) != 0) {
			if (n > 1) {
				RTW_DPRINTF(RTW_DEBUG_RECV,
				    "%s: n > 1\n", __func__);
				break;
			}
			RTW_DMA_SYNC_DESC(rsc->sc_desc_dma,
			    RTW_DESC_OFFSET(hd_rx, 0),
			    sizeof (struct rtw_rxdesc),
			    DDI_DMA_SYNC_FORCPU);
			bf = rsc->rxbuf_h;
			ds = bf->rxdesc;
			hstat = (ds->rd_stat);
			if ((hstat & RTW_RXSTAT_OWN) != 0)
				break;
			next = 0 /* RTW_RXQLEN - 1 */;
			continue;
		}

		rsc->sc_pktrcv64++;
		if ((hstat & RTW_RXSTAT_IOERROR) != 0) {
			RTW_DPRINTF(RTW_DEBUG_RECV,
			    "rtw: DMA error/FIFO overflow %08x, "
			    "rx descriptor %d\n",
			    hstat & RTW_RXSTAT_IOERROR, next);
			goto next;
		}

		len = MASK_AND_RSHIFT(hstat, RTW_RXSTAT_LENGTH_MASK);
		rsc->sc_bytercv64 += len;

		/* CRC is included with the packet; trim it off. */
		/* len -= IEEE80211_CRC_LEN; */

		hwrate = MASK_AND_RSHIFT(hstat, RTW_RXSTAT_RATE_MASK);
		if (hwrate >= 4) {
			goto next;
		}

		if ((hstat & RTW_RXSTAT_RES) != 0 &&
		    rsc->sc_ic.ic_opmode != IEEE80211_M_MONITOR) {
			goto next;
		}

		/* if bad flags, skip descriptor */
		if ((hstat & RTW_RXSTAT_ONESEG) != RTW_RXSTAT_ONESEG) {
			RTW_DPRINTF(RTW_DEBUG_RECV,
			    "rtw too many rx segments\n");
			goto next;
		}

		if (rsc->sc_rfchipid == RTW_RFCHIPID_PHILIPS)
			rssi = MASK_AND_RSHIFT(hrssi, RTW_RXRSSI_RSSI);
		else {
			rssi = MASK_AND_RSHIFT(hrssi, RTW_RXRSSI_IMR_RSSI);
			/*
			 * TBD find out each front-end's LNA gain in the
			 * front-end's units
			 */
			if ((hrssi & RTW_RXRSSI_IMR_LNA) == 0)
				rssi |= 0x80;
		}
		/* sq = MASK_AND_RSHIFT(hrssi, RTW_RXRSSI_SQ); */


		/* deal with the frame itself here */
		mp = allocb(rsc->sc_dmabuf_size, BPRI_MED);
		if (mp == NULL) {
			cmn_err(CE_WARN, "rtw: alloc mblk error");
			rsc->sc_norcvbuf++;
			return;
		}
		len -= IEEE80211_CRC_LEN;
		RTW_DMA_SYNC(bf->bf_dma, DDI_DMA_SYNC_FORKERNEL);
		bcopy(bf->bf_dma.mem_va, mp->b_rptr, len);
		mp->b_wptr += len;
		wh = (struct ieee80211_frame *)mp->b_rptr;
		if ((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) ==
		    IEEE80211_FC0_TYPE_CTL) {
			cmn_err(CE_WARN, "TYPE CTL !!\n");
			freemsg(mp);
			goto next;
		}
		(void) ieee80211_input(ic, mp, ic->ic_bss, rssi, htsftl);
next:
		if (next == 63)
			is_last = 1;
		else
			is_last = 0;
		rtw_rxdesc_init(rsc, bf, next, is_last);

		next = (next + 1)%RTW_RXQLEN;
		RTW_DPRINTF(RTW_DEBUG_RECV, "%s: next = %d\n", __func__, next);
	}
	mutex_enter(&rsc->rxbuf_lock);
	rsc->rx_next = next;
	mutex_exit(&rsc->rxbuf_lock);
}

static void
rtw_ring_recycling(rtw_softc_t *rsc, uint16_t isr, uint32_t pri)
{
	struct rtw_txbuf *bf;
	struct rtw_txdesc *ds;
	uint32_t hstat;
	uint32_t  head = 0;
	uint32_t  cnt = 0, idx = 0;

	mutex_enter(&rsc->sc_txq[pri].txbuf_lock);
	head = RTW_READ(&rsc->sc_regs, RTW_TNPDA);
	if (head == rsc->hw_go) {
		mutex_exit(&rsc->sc_txq[pri].txbuf_lock);
		return;
	}
	RTW_DPRINTF(RTW_DEBUG_XMIT, "rtw_ring_recycling: enter ic_state=%x\n",
	    rsc->sc_ic.ic_state);

	bf = list_head(&rsc->sc_txq[pri].tx_dirty_list);
	if (bf == NULL) {
		RTW_DPRINTF(RTW_DEBUG_XMIT,
		    "rtw_ring_recycling: dirty bf[%d] NULL\n", pri);
		mutex_exit(&rsc->sc_txq[pri].txbuf_lock);
		return;
	}

	while ((bf != NULL) && (rsc->hw_go != head)) {
		cnt++;
		idx = (rsc->hw_go - rsc->hw_start) / sizeof (struct rtw_txdesc);
		if (idx == 63)
			rsc->hw_go = rsc->hw_start;
		else
			rsc->hw_go += sizeof (struct rtw_txdesc);
		RTW_DMA_SYNC_DESC(rsc->sc_desc_dma,
		    RTW_DESC_OFFSET(hd_txmd, idx),
		    sizeof (struct rtw_txdesc),
		    DDI_DMA_SYNC_FORCPU);

		RTW_DPRINTF(RTW_DEBUG_XMIT, "Head = 0x%x\n", head);
		ds = bf->txdesc;
		hstat = (ds->td_stat);
		ds->td_len = ds->td_len & 0xfff;
		RTW_DPRINTF(RTW_DEBUG_XMIT,
		    "%s rtw_ring_recycling: stat=%x, pri=%x\n",
		    __func__, hstat, pri);
		if (hstat & RTW_TXSTAT_TOK)
			rsc->sc_tx_ok++;
		else {
			RTW_DPRINTF(RTW_DEBUG_XMIT,
			    "TX err @%d, o %d, retry[%d], isr[0x%x], cnt %d\n",
			    idx, (hstat & RTW_TXSTAT_OWN)?1:0,
			    (hstat & RTW_TXSTAT_DRC_MASK), isr, cnt);
			if ((hstat & RTW_TXSTAT_DRC_MASK) <= 4) {
				rsc->sc_tx_ok++;
			} else {
				rsc->sc_tx_err++;
			}
		}
		rsc->sc_tx_retr +=
		    (hstat & RTW_TXSTAT_DRC_MASK);
		rsc->sc_xmtretry +=
		    (hstat & RTW_TXSTAT_DRC_MASK);
		list_remove(&rsc->sc_txq[pri].tx_dirty_list, bf);
		list_insert_tail(&rsc->sc_txq[pri].tx_free_list,
		    bf);
		(rsc->sc_txq[pri].tx_nfree)++;
		if (rsc->sc_need_reschedule == 1) {
			mac_tx_update(rsc->sc_ic.ic_mach);
			rsc->sc_need_reschedule = 0;
		}
		RTW_DPRINTF(RTW_DEBUG_XMIT,
		    "rtw_ring_recycling: nfree[%d]=%d\n",
		    pri, rsc->sc_txq[pri].tx_nfree);
		bzero((uint8_t *)ds, sizeof (struct rtw_txdesc));
		RTW_DMA_SYNC_DESC(rsc->sc_desc_dma,
		    RTW_DESC_OFFSET(hd_txmd, idx),
		    sizeof (struct rtw_txdesc),
		    DDI_DMA_SYNC_FORDEV);
		bf = list_head(&rsc->sc_txq[pri].tx_dirty_list);
	}
	mutex_exit(&rsc->sc_txq[pri].txbuf_lock);
}

static void
rtw_intr_timeout(rtw_softc_t *rsc)
{
	rtw_resume_ticks(rsc);
}

static uint_t
rtw_intr(caddr_t arg)
{
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	rtw_softc_t *rsc = (rtw_softc_t *)arg;
	struct rtw_regs *regs = &rsc->sc_regs;
	uint16_t isr = 0;

	mutex_enter(&rsc->sc_genlock);
	isr = RTW_READ16(regs, RTW_ISR);
	RTW_WRITE16(regs, RTW_ISR, isr);

	if (isr == 0) {
		mutex_exit(&rsc->sc_genlock);
		return (DDI_INTR_UNCLAIMED);
	}

#ifdef DEBUG
#define	PRINTINTR(flag) { \
	if ((isr & flag) != 0) { \
		RTW_DPRINTF(RTW_DEBUG_INTR, "|" #flag); \
	} \
}

	if ((rtw_dbg_flags & RTW_DEBUG_INTR) != 0 && isr != 0) {

		RTW_DPRINTF(RTW_DEBUG_INTR, "rtw: reg[ISR] = %x", isr);

		PRINTINTR(RTW_INTR_TXFOVW);
		PRINTINTR(RTW_INTR_TIMEOUT);
		PRINTINTR(RTW_INTR_BCNINT);
		PRINTINTR(RTW_INTR_ATIMINT);
		PRINTINTR(RTW_INTR_TBDER);
		PRINTINTR(RTW_INTR_TBDOK);
		PRINTINTR(RTW_INTR_THPDER);
		PRINTINTR(RTW_INTR_THPDOK);
		PRINTINTR(RTW_INTR_TNPDER);
		PRINTINTR(RTW_INTR_TNPDOK);
		PRINTINTR(RTW_INTR_RXFOVW);
		PRINTINTR(RTW_INTR_RDU);
		PRINTINTR(RTW_INTR_TLPDER);
		PRINTINTR(RTW_INTR_TLPDOK);
		PRINTINTR(RTW_INTR_RER);
		PRINTINTR(RTW_INTR_ROK);
	}
#undef PRINTINTR
#endif /* DEBUG */

	rsc->sc_intr++;

	if ((isr & RTW_INTR_RX) != 0) {
		mutex_exit(&rsc->sc_genlock);
		rtw_intr_rx(rsc);
		mutex_enter(&rsc->sc_genlock);
	}
	if ((isr & RTW_INTR_TIMEOUT) != 0)
		rtw_intr_timeout(rsc);

	if ((isr & RTW_INTR_TX) != 0)
		rtw_ring_recycling(rsc, isr, 1);
	mutex_exit(&rsc->sc_genlock);
	return (DDI_INTR_CLAIMED);
}

static void
rtw_stop(void *arg)
{
	rtw_softc_t *rsc = (rtw_softc_t *)arg;
	struct rtw_regs *regs = &rsc->sc_regs;

	mutex_enter(&rsc->sc_genlock);
	rtw_disable_interrupts(regs);
	rtw_io_enable(rsc, RTW_CR_RE | RTW_CR_TE, 0);
	RTW_WRITE8(regs, RTW_TPPOLL, RTW_TPPOLL_SALL);
	rsc->sc_invalid = 1;
	mutex_exit(&rsc->sc_genlock);
}

static void
rtw_m_stop(void *arg)
{
	rtw_softc_t *rsc = (rtw_softc_t *)arg;

	(void) ieee80211_new_state(&rsc->sc_ic, IEEE80211_S_INIT, -1);
	rtw_stop(rsc);
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
int
rtw_quiesce(dev_info_t *dip)
{
	rtw_softc_t  *rsc = NULL;
	struct rtw_regs *regs;

	rsc = ddi_get_soft_state(rtw_soft_state_p, ddi_get_instance(dip));
	ASSERT(rsc != NULL);
	regs = &rsc->sc_regs;

	rtw_dbg_flags = 0;
	rtw_disable_interrupts(regs);
	rtw_io_enable(rsc, RTW_CR_RE | RTW_CR_TE, 0);
	RTW_WRITE8(regs, RTW_TPPOLL, RTW_TPPOLL_SALL);

	return (DDI_SUCCESS);
}

/*
 * callback functions for /get/set properties
 */
static int
rtw_m_setprop(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    uint_t wldp_length, const void *wldp_buf)
{
	rtw_softc_t *rsc = (rtw_softc_t *)arg;
	struct ieee80211com *ic = &rsc->sc_ic;
	int err;

	err = ieee80211_setprop(ic, pr_name, wldp_pr_num,
	    wldp_length, wldp_buf);
	if (err == ENETRESET) {
		if (ic->ic_des_esslen && (rsc->sc_invalid == 0)) {
			(void) rtw_init(rsc);
			(void) ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
		}
		err = 0;
	}
	return (err);
}

static int
rtw_m_getprop(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    uint_t wldp_length, void *wldp_buf)
{
	rtw_softc_t *rsc = arg;
	int err;

	err = ieee80211_getprop(&rsc->sc_ic, pr_name, wldp_pr_num,
	    wldp_length, wldp_buf);

	return (err);
}

static void
rtw_m_propinfo(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    mac_prop_info_handle_t prh)
{
	rtw_softc_t *rsc = arg;

	ieee80211_propinfo(&rsc->sc_ic, pr_name, wldp_pr_num, prh);
}

static int
rtw_m_start(void *arg)
{
	rtw_softc_t *rsc = (rtw_softc_t *)arg;
	ieee80211com_t *ic = (ieee80211com_t *)rsc;
	int ret;
#ifdef DEBUG
	rtw_print_regs(&rsc->sc_regs, "rtw", "rtw_start");
#endif

	ret = rtw_init(rsc);
	if (ret) {
		cmn_err(CE_WARN, "rtw: failed to do rtw_init\n");
		return (EIO);
	}
	(void) ieee80211_new_state(ic, IEEE80211_S_INIT, -1);
	return (0);
}


static int
rtw_m_unicst(void *arg, const uint8_t *macaddr)
{
	rtw_softc_t *rsc = (rtw_softc_t *)arg;
	ieee80211com_t *ic = (ieee80211com_t *)rsc;
	struct rtw_regs *regs = &rsc->sc_regs;
	uint32_t t;

	mutex_enter(&rsc->sc_genlock);
	bcopy(macaddr, ic->ic_macaddr, 6);
	t = ((*macaddr)<<24) | ((*(macaddr + 1))<<16) |
	    ((*(macaddr + 2))<<8) | (*(macaddr + 3));
	RTW_WRITE(regs, RTW_IDR0, ntohl(t));
	t = ((*(macaddr + 4))<<24) | ((*(macaddr + 5))<<16);
	RTW_WRITE(regs, RTW_IDR1, ntohl(t));
	mutex_exit(&rsc->sc_genlock);
	return (0);
}

static int
rtw_m_promisc(void *arg, boolean_t on)
{
	rtw_softc_t *rsc = (rtw_softc_t *)arg;
	struct rtw_regs *regs = &rsc->sc_regs;

	mutex_enter(&rsc->sc_genlock);

	if (on)
		rsc->sc_rcr |= RTW_RCR_PROMIC;
	else
		rsc->sc_rcr &= ~RTW_RCR_PROMIC;

	RTW_WRITE(regs, RTW_RCR, rsc->sc_rcr);

	mutex_exit(&rsc->sc_genlock);
	return (0);
}

static int
rtw_m_multicst(void *arg, boolean_t add, const uint8_t *macaddr)
{
	rtw_softc_t *rsc = (rtw_softc_t *)arg;
	struct rtw_regs *regs = &rsc->sc_regs;
	uint32_t t;

	mutex_enter(&rsc->sc_genlock);
	if (add) {
		rsc->sc_rcr |= RTW_RCR_AM;
		t = ((*macaddr)<<24) | ((*(macaddr + 1))<<16) |
		    ((*(macaddr + 2))<<8) | (*(macaddr + 3));
		RTW_WRITE(regs, RTW_MAR0, ntohl(t));
		t = ((*(macaddr + 4))<<24) | ((*(macaddr + 5))<<16);
		RTW_WRITE(regs, RTW_MAR1, ntohl(t));
		RTW_WRITE(regs, RTW_RCR, rsc->sc_rcr);
		RTW_SYNC(regs, RTW_MAR0, RTW_RCR);
	} else {
		rsc->sc_rcr &= ~RTW_RCR_AM;
		RTW_WRITE(regs, RTW_MAR0, 0);
		RTW_WRITE(regs, RTW_MAR1, 0);
		RTW_WRITE(regs, RTW_RCR, rsc->sc_rcr);
		RTW_SYNC(regs, RTW_MAR0, RTW_RCR);
	}
	mutex_exit(&rsc->sc_genlock);
	return (0);
}

static void
rtw_m_ioctl(void* arg, queue_t *wq, mblk_t *mp)
{
	rtw_softc_t *rsc = arg;
	struct ieee80211com *ic = &rsc->sc_ic;
	int err;

	err = ieee80211_ioctl(ic, wq, mp);
	if (err == ENETRESET) {
		if (ic->ic_des_esslen && (rsc->sc_invalid == 0)) {
			(void) rtw_init(rsc);
			(void) ieee80211_new_state(ic,
			    IEEE80211_S_SCAN, -1);
		}
	}
}

static int
rtw_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	rtw_softc_t *rsc = (rtw_softc_t *)arg;
	ieee80211com_t *ic = &rsc->sc_ic;
	struct ieee80211_node *in = 0;
	struct ieee80211_rateset *rs = 0;

	mutex_enter(&rsc->sc_genlock);
	switch (stat) {
	case MAC_STAT_IFSPEED:
		in = ic->ic_bss;
		rs = &in->in_rates;
		*val = ((ic->ic_fixed_rate == IEEE80211_FIXED_RATE_NONE) ?
		    (rs->ir_rates[in->in_txrate] & IEEE80211_RATE_VAL)
		    : ic->ic_fixed_rate) / 2 * 1000000;
		break;
	case MAC_STAT_NOXMTBUF:
		*val = rsc->sc_noxmtbuf;
		break;
	case MAC_STAT_NORCVBUF:
		*val = rsc->sc_norcvbuf;
		break;
	case MAC_STAT_RBYTES:
		*val = rsc->sc_bytercv64;
		break;
	case MAC_STAT_IPACKETS:
		*val = rsc->sc_pktrcv64;
		break;
	case MAC_STAT_OBYTES:
		*val = rsc->sc_bytexmt64;
		break;
	case MAC_STAT_OPACKETS:
		*val = rsc->sc_pktxmt64;
		break;
	case WIFI_STAT_TX_RETRANS:
		*val = rsc->sc_xmtretry;
		break;
	case WIFI_STAT_TX_FRAGS:
	case WIFI_STAT_MCAST_TX:
	case WIFI_STAT_RTS_SUCCESS:
	case WIFI_STAT_RTS_FAILURE:
	case WIFI_STAT_ACK_FAILURE:
	case WIFI_STAT_RX_FRAGS:
	case WIFI_STAT_MCAST_RX:
	case WIFI_STAT_RX_DUPS:
		mutex_exit(&rsc->sc_genlock);
		return (ieee80211_stat(ic, stat, val));
	default:
		*val = 0;
		break;
	}
	mutex_exit(&rsc->sc_genlock);

	return (0);
}


static void
rtw_mutex_destroy(rtw_softc_t *rsc)
{
	int i;

	mutex_destroy(&rsc->rxbuf_lock);
	mutex_destroy(&rsc->sc_txlock);
	for (i = 0; i < RTW_NTXPRI; i++) {
		mutex_destroy(&rsc->sc_txq[RTW_NTXPRI - 1 - i].txbuf_lock);
	}
	mutex_destroy(&rsc->sc_genlock);
}

static int
rtw_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	rtw_softc_t *rsc;
	ieee80211com_t *ic;
	uint8_t csz;
	uint32_t i;
	uint16_t vendor_id, device_id, command;
	int32_t err;
	char strbuf[32];
	wifi_data_t wd = { 0 };
	mac_register_t *macp;
	int instance = ddi_get_instance(devinfo);

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		rsc = ddi_get_soft_state(rtw_soft_state_p,
		    ddi_get_instance(devinfo));
		ASSERT(rsc != NULL);
		mutex_enter(&rsc->sc_genlock);
		rsc->sc_flags &= ~RTW_F_SUSPEND;
		mutex_exit(&rsc->sc_genlock);
		if ((rsc->sc_flags & RTW_F_PLUMBED)) {
			err = rtw_init(rsc);
			if (err == 0) {
				mutex_enter(&rsc->sc_genlock);
				rsc->sc_flags &= ~RTW_F_PLUMBED;
				mutex_exit(&rsc->sc_genlock);
			}
		}
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	if (ddi_soft_state_zalloc(rtw_soft_state_p,
	    ddi_get_instance(devinfo)) != DDI_SUCCESS) {
		RTW_DPRINTF(RTW_DEBUG_ATTACH, "rtw: rtw_attach(): "
		    "Unable to alloc softstate\n");
		return (DDI_FAILURE);
	}

	rsc = ddi_get_soft_state(rtw_soft_state_p, ddi_get_instance(devinfo));
	ic = &rsc->sc_ic;
	rsc->sc_dev = devinfo;

	err = ddi_regs_map_setup(devinfo, 0, (caddr_t *)&rsc->sc_cfg_base, 0, 0,
	    &rtw_reg_accattr, &rsc->sc_cfg_handle);
	if (err != DDI_SUCCESS) {
		RTW_DPRINTF(RTW_DEBUG_ATTACH, "rtw: rtw_attach(): "
		    "ddi_regs_map_setup() failed");
		goto attach_fail0;
	}
	csz = ddi_get8(rsc->sc_cfg_handle,
	    (uint8_t *)(rsc->sc_cfg_base + PCI_CONF_CACHE_LINESZ));
	if (!csz)
		csz = 16;
	rsc->sc_cachelsz = csz << 2;
	vendor_id = ddi_get16(rsc->sc_cfg_handle,
	    (uint16_t *)((uintptr_t)rsc->sc_cfg_base + PCI_CONF_VENID));
	device_id = ddi_get16(rsc->sc_cfg_handle,
	    (uint16_t *)((uintptr_t)rsc->sc_cfg_base + PCI_CONF_DEVID));
	RTW_DPRINTF(RTW_DEBUG_ATTACH, "rtw: rtw_attach(): vendor 0x%x, "
	    "device id 0x%x, cache size %d\n", vendor_id, device_id, csz);

	/*
	 * Enable response to memory space accesses,
	 * and enabe bus master.
	 */
	command = PCI_COMM_MAE | PCI_COMM_ME;
	ddi_put16(rsc->sc_cfg_handle,
	    (uint16_t *)((uintptr_t)rsc->sc_cfg_base + PCI_CONF_COMM), command);
	RTW_DPRINTF(RTW_DEBUG_ATTACH, "rtw: rtw_attach(): "
	    "set command reg to 0x%x \n", command);

	ddi_put8(rsc->sc_cfg_handle,
	    (uint8_t *)(rsc->sc_cfg_base + PCI_CONF_LATENCY_TIMER), 0xa8);

	ddi_regs_map_free(&rsc->sc_cfg_handle);

	err = ddi_regs_map_setup(devinfo, 2, (caddr_t *)&rsc->sc_regs.r_base,
	    0, 0, &rtw_reg_accattr, &rsc->sc_regs.r_handle);
	if (err != DDI_SUCCESS) {
		RTW_DPRINTF(RTW_DEBUG_ATTACH, "rtw: rtw_attach(): "
		    "ddi_regs_map_setup() failed");
		goto attach_fail0;
	}
	RTW_DPRINTF(RTW_DEBUG_ATTACH, "rtw: r_base=%x, r_handle=%x\n",
	    rsc->sc_regs.r_base, rsc->sc_regs.r_handle);

	err = rtw_dma_init(devinfo, rsc);
	if (err != DDI_SUCCESS) {
		RTW_DPRINTF(RTW_DEBUG_ATTACH, "rtw: rtw_attach(): "
		    "failed to init dma: %d\n", err);
		goto attach_fail1;
	}

	/*
	 * Stop the transmit and receive processes. First stop DMA,
	 * then disable receiver and transmitter.
	 */
	RTW_WRITE8(&rsc->sc_regs, RTW_TPPOLL, RTW_TPPOLL_SALL);
	rtw_io_enable(rsc, RTW_CR_RE | RTW_CR_TE, 0);

	/* Reset the chip to a known state. */
	if (rtw_reset(rsc) != 0) {
		RTW_DPRINTF(RTW_DEBUG_ATTACH, "rtw: rtw_attach(): "
		    "failed to reset\n");
		goto attach_fail2;
	}
	rsc->sc_rcr = RTW_READ(&rsc->sc_regs, RTW_RCR);

	if ((rsc->sc_rcr & RTW_RCR_9356SEL) != 0)
		rsc->sc_flags |= RTW_F_9356SROM;

	if (rtw_srom_read(&rsc->sc_regs, rsc->sc_flags, &rsc->sc_srom,
	    "rtw") != 0) {
		RTW_DPRINTF(RTW_DEBUG_ATTACH, "rtw: rtw_attach(): "
		    "failed to read srom\n");
		goto attach_fail2;
	}

	if (rtw_srom_parse(&rsc->sc_srom, &rsc->sc_flags, &rsc->sc_csthr,
	    &rsc->sc_rfchipid, &rsc->sc_rcr, &rsc->sc_locale,
	    "rtw") != 0) {
		RTW_DPRINTF(RTW_DEBUG_ATTACH, "rtw_attach():"
		    " malformed serial ROM\n");
		goto attach_fail3;
	}

	RTW_DPRINTF(RTW_DEBUG_PHY, "rtw: %s PHY\n",
	    ((rsc->sc_flags & RTW_F_DIGPHY) != 0) ? "digital" : "analog");


	rsc->sc_rf = rtw_rf_attach(rsc, rsc->sc_rfchipid,
	    rsc->sc_flags & RTW_F_DIGPHY);

	if (rsc->sc_rf == NULL) {
		cmn_err(CE_WARN, "rtw: rtw_attach(): could not attach RF\n");
		goto attach_fail3;
	}
	rsc->sc_phydelay = rtw_check_phydelay(&rsc->sc_regs, rsc->sc_rcr);

	RTW_DPRINTF(RTW_DEBUG_ATTACH,
	    "rtw: PHY delay %d\n", rsc->sc_phydelay);

	if (rsc->sc_locale == RTW_LOCALE_UNKNOWN)
		rtw_identify_country(&rsc->sc_regs, &rsc->sc_locale,
		    "rtw");

	rtw_init_channels(rsc->sc_locale, &rsc->sc_ic.ic_sup_channels,
	    "rtw");

	rtw_set80211props(ic);

	if (rtw_identify_sta(&rsc->sc_regs, ic->ic_macaddr,
	    "rtw") != 0)
		goto attach_fail4;

	ic->ic_xmit = rtw_send;
	ieee80211_attach(ic);

	rsc->sc_newstate = ic->ic_newstate;
	ic->ic_newstate = rtw_new_state;
	ieee80211_media_init(ic);
	ic->ic_def_txkey = 0;

	if (ddi_get_iblock_cookie(devinfo, 0, &(rsc->sc_iblock))
	    != DDI_SUCCESS) {
		RTW_DPRINTF(RTW_DEBUG_ATTACH, "rtw: rtw_attach(): "
		    "Can not get iblock cookie for INT\n");
		goto attach_fail5;
	}

	mutex_init(&rsc->sc_genlock, NULL, MUTEX_DRIVER, rsc->sc_iblock);
	for (i = 0; i < RTW_NTXPRI; i++) {
		mutex_init(&rsc->sc_txq[i].txbuf_lock, NULL, MUTEX_DRIVER,
		    rsc->sc_iblock);
	}
	mutex_init(&rsc->rxbuf_lock, NULL, MUTEX_DRIVER, rsc->sc_iblock);
	mutex_init(&rsc->sc_txlock, NULL, MUTEX_DRIVER, rsc->sc_iblock);

	if (ddi_add_intr(devinfo, 0, &rsc->sc_iblock, NULL, rtw_intr,
	    (caddr_t)(rsc)) != DDI_SUCCESS) {
		RTW_DPRINTF(RTW_DEBUG_ATTACH, "rtw: rtw_attach(): "
		    "Can not add intr for rtw driver\n");
		goto attach_fail7;
	}

	/*
	 * Provide initial settings for the WiFi plugin; whenever this
	 * information changes, we need to call mac_plugindata_update()
	 */
	wd.wd_opmode = ic->ic_opmode;
	wd.wd_secalloc = WIFI_SEC_NONE;
	IEEE80211_ADDR_COPY(wd.wd_bssid, ic->ic_bss->in_bssid);

	if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
		RTW_DPRINTF(RTW_DEBUG_ATTACH, "rtw: rtw_attach(): "
		    "MAC version mismatch\n");
		goto attach_fail8;
	}

	macp->m_type_ident	= MAC_PLUGIN_IDENT_WIFI;
	macp->m_driver		= rsc;
	macp->m_dip		= devinfo;
	macp->m_src_addr	= ic->ic_macaddr;
	macp->m_callbacks	= &rtw_m_callbacks;
	macp->m_min_sdu		= 0;
	macp->m_max_sdu		= IEEE80211_MTU;
	macp->m_pdata		= &wd;
	macp->m_pdata_size	= sizeof (wd);

	err = mac_register(macp, &ic->ic_mach);
	mac_free(macp);
	if (err != 0) {
		RTW_DPRINTF(RTW_DEBUG_ATTACH, "rtw: rtw_attach(): "
		    "mac_register err %x\n", err);
		goto attach_fail8;
	}

	/* Create minor node of type DDI_NT_NET_WIFI */
	(void) snprintf(strbuf, sizeof (strbuf), "%s%d",
	    "rtw", instance);
	err = ddi_create_minor_node(devinfo, strbuf, S_IFCHR,
	    instance + 1, DDI_NT_NET_WIFI, 0);
	if (err != DDI_SUCCESS) {
		RTW_DPRINTF(RTW_DEBUG_ATTACH, "WARN: rtw: rtw_attach(): "
		    "Create minor node failed - %d\n", err);
		goto attach_fail9;
	}
	mac_link_update(ic->ic_mach, LINK_STATE_DOWN);
	rsc->sc_flags |= RTW_F_ATTACHED;
	rsc->sc_need_reschedule = 0;
	rsc->sc_invalid = 1;
	return (DDI_SUCCESS);
attach_fail9:
	(void) mac_disable(ic->ic_mach);
	(void) mac_unregister(ic->ic_mach);
attach_fail8:
	ddi_remove_intr(devinfo, 0, rsc->sc_iblock);
attach_fail7:
	rtw_mutex_destroy(rsc);
attach_fail5:
	ieee80211_detach(ic);
attach_fail4:
	rtw_rf_destroy(rsc->sc_rf);
attach_fail3:
	rtw_srom_free(&rsc->sc_srom);
attach_fail2:
	rtw_dma_free(rsc);
attach_fail1:
	ddi_regs_map_free(&rsc->sc_regs.r_handle);
attach_fail0:
	ddi_soft_state_free(rtw_soft_state_p, ddi_get_instance(devinfo));
	return (DDI_FAILURE);
}

static int32_t
rtw_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{
	rtw_softc_t *rsc;

	rsc = ddi_get_soft_state(rtw_soft_state_p, ddi_get_instance(devinfo));
	ASSERT(rsc != NULL);

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		ieee80211_new_state(&rsc->sc_ic, IEEE80211_S_INIT, -1);
		mutex_enter(&rsc->sc_genlock);
		rsc->sc_flags |= RTW_F_SUSPEND;
		mutex_exit(&rsc->sc_genlock);
		if (rsc->sc_invalid == 0) {
			rtw_stop(rsc);
			mutex_enter(&rsc->sc_genlock);
			rsc->sc_flags |= RTW_F_PLUMBED;
			mutex_exit(&rsc->sc_genlock);
		}
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
	if (!(rsc->sc_flags & RTW_F_ATTACHED))
		return (DDI_FAILURE);

	if (mac_disable(rsc->sc_ic.ic_mach) != 0)
		return (DDI_FAILURE);

	/* free intterrupt resources */
	ddi_remove_intr(devinfo, 0, rsc->sc_iblock);

	rtw_mutex_destroy(rsc);
	ieee80211_detach((ieee80211com_t *)rsc);
	/*
	 * Unregister from the MAC layer subsystem
	 */
	(void) mac_unregister(rsc->sc_ic.ic_mach);

	rtw_rf_destroy(rsc->sc_rf);
	rtw_srom_free(&rsc->sc_srom);
	rtw_dma_free(rsc);
	ddi_remove_minor_node(devinfo, NULL);
	ddi_regs_map_free(&rsc->sc_regs.r_handle);

	ddi_soft_state_free(rtw_soft_state_p, ddi_get_instance(devinfo));

	return (DDI_SUCCESS);
}
