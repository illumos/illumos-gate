/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2008 Weongyo Jeong
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    similar to the "NO WARRANTY" disclaimer below ("Disclaimer") and any
 *    redistribution must be conditioned upon including a substantially
 *    similar Disclaimer requirement for further binary redistribution.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF NONINFRINGEMENT, MERCHANTIBILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGES.
 */
#include <sys/sysmacros.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/mac_provider.h>
#include <sys/mac_wifi.h>
#include <sys/net80211.h>
#define	USBDRV_MAJOR_VER	2
#define	USBDRV_MINOR_VER	0
#include <sys/usb/usba.h>
#include <sys/usb/usba/usba_types.h>

#include "urtw_reg.h"
#include "urtw_var.h"

static void *urtw_soft_state_p = NULL;

#define	URTW_TXBUF_SIZE  	(IEEE80211_MAX_LEN)
#define	URTW_RXBUF_SIZE  	(URTW_TXBUF_SIZE)
/*
 * device operations
 */
static int urtw_attach(dev_info_t *, ddi_attach_cmd_t);
static int urtw_detach(dev_info_t *, ddi_detach_cmd_t);

/*
 * Module Loading Data & Entry Points
 */
DDI_DEFINE_STREAM_OPS(urtw_dev_ops, nulldev, nulldev, urtw_attach,
    urtw_detach, nodev, NULL, D_MP, NULL, ddi_quiesce_not_needed);

static struct modldrv urtw_modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	"RTL8187L driver v1.1",	/* short description */
	&urtw_dev_ops		/* driver specific ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&urtw_modldrv,
	NULL
};

static int	urtw_m_stat(void *,  uint_t, uint64_t *);
static int	urtw_m_start(void *);
static void	urtw_m_stop(void *);
static int	urtw_m_promisc(void *, boolean_t);
static int	urtw_m_multicst(void *, boolean_t, const uint8_t *);
static int	urtw_m_unicst(void *, const uint8_t *);
static mblk_t	*urtw_m_tx(void *, mblk_t *);
static void	urtw_m_ioctl(void *, queue_t *, mblk_t *);
static int	urtw_m_setprop(void *, const char *, mac_prop_id_t,
    uint_t, const void *);

static mac_callbacks_t urtw_m_callbacks = {
	MC_IOCTL | MC_SETPROP | MC_GETPROP,
	urtw_m_stat,
	urtw_m_start,
	urtw_m_stop,
	urtw_m_promisc,
	urtw_m_multicst,
	urtw_m_unicst,
	urtw_m_tx,
	urtw_m_ioctl,
	NULL,
	NULL,
	NULL,
	urtw_m_setprop,
	ieee80211_getprop
};

static int  urtw_tx_start(struct urtw_softc *, mblk_t *, int);
static int  urtw_rx_start(struct urtw_softc *);


/*
 * Supported rates for 802.11a/b/g modes (in 500Kbps unit).
 */
static const struct ieee80211_rateset urtw_rateset_11b =
	{ 4, { 2, 4, 11, 22 } };

static const struct ieee80211_rateset urtw_rateset_11g =
	{ 12, { 2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108 } };


struct urtw_pair {
	uint32_t	reg;
	uint32_t	val;
};

static uint8_t urtw_8225_agc[] = {
	0x9e, 0x9e, 0x9e, 0x9e, 0x9e, 0x9e, 0x9e, 0x9e, 0x9d, 0x9c, 0x9b,
	0x9a, 0x99, 0x98, 0x97, 0x96, 0x95, 0x94, 0x93, 0x92, 0x91, 0x90,
	0x8f, 0x8e, 0x8d, 0x8c, 0x8b, 0x8a, 0x89, 0x88, 0x87, 0x86, 0x85,
	0x84, 0x83, 0x82, 0x81, 0x80, 0x3f, 0x3e, 0x3d, 0x3c, 0x3b, 0x3a,
	0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30, 0x2f,
	0x2e, 0x2d, 0x2c, 0x2b, 0x2a, 0x29, 0x28, 0x27, 0x26, 0x25, 0x24,
	0x23, 0x22, 0x21, 0x20, 0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19,
	0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10, 0x0f, 0x0e,
	0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03,
	0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
};

static uint32_t urtw_8225_channel[] = {
	0x0000,		/* dummy channel 0  */
	0x085c,		/* 1  */
	0x08dc,		/* 2  */
	0x095c,		/* 3  */
	0x09dc,		/* 4  */
	0x0a5c,		/* 5  */
	0x0adc,		/* 6  */
	0x0b5c,		/* 7  */
	0x0bdc,		/* 8  */
	0x0c5c,		/* 9  */
	0x0cdc,		/* 10  */
	0x0d5c,		/* 11  */
	0x0ddc,		/* 12  */
	0x0e5c,		/* 13  */
	0x0f72,		/* 14  */
};

static uint8_t urtw_8225_gain[] = {
	0x23, 0x88, 0x7c, 0xa5,		/* -82dbm  */
	0x23, 0x88, 0x7c, 0xb5,		/* -82dbm  */
	0x23, 0x88, 0x7c, 0xc5,		/* -82dbm  */
	0x33, 0x80, 0x79, 0xc5,		/* -78dbm  */
	0x43, 0x78, 0x76, 0xc5,		/* -74dbm  */
	0x53, 0x60, 0x73, 0xc5,		/* -70dbm  */
	0x63, 0x58, 0x70, 0xc5,		/* -66dbm  */
};

static struct urtw_pair urtw_8225_rf_part1[] = {
	{ 0x00, 0x0067 }, { 0x01, 0x0fe0 }, { 0x02, 0x044d }, { 0x03, 0x0441 },
	{ 0x04, 0x0486 }, { 0x05, 0x0bc0 }, { 0x06, 0x0ae6 }, { 0x07, 0x082a },
	{ 0x08, 0x001f }, { 0x09, 0x0334 }, { 0x0a, 0x0fd4 }, { 0x0b, 0x0391 },
	{ 0x0c, 0x0050 }, { 0x0d, 0x06db }, { 0x0e, 0x0029 }, { 0x0f, 0x0914 },
};

static struct urtw_pair urtw_8225_rf_part2[] = {
	{ 0x00, 0x01 }, { 0x01, 0x02 }, { 0x02, 0x42 }, { 0x03, 0x00 },
	{ 0x04, 0x00 }, { 0x05, 0x00 }, { 0x06, 0x40 }, { 0x07, 0x00 },
	{ 0x08, 0x40 }, { 0x09, 0xfe }, { 0x0a, 0x09 }, { 0x0b, 0x80 },
	{ 0x0c, 0x01 }, { 0x0e, 0xd3 }, { 0x0f, 0x38 }, { 0x10, 0x84 },
	{ 0x11, 0x06 }, { 0x12, 0x20 }, { 0x13, 0x20 }, { 0x14, 0x00 },
	{ 0x15, 0x40 }, { 0x16, 0x00 }, { 0x17, 0x40 }, { 0x18, 0xef },
	{ 0x19, 0x19 }, { 0x1a, 0x20 }, { 0x1b, 0x76 }, { 0x1c, 0x04 },
	{ 0x1e, 0x95 }, { 0x1f, 0x75 }, { 0x20, 0x1f }, { 0x21, 0x27 },
	{ 0x22, 0x16 }, { 0x24, 0x46 }, { 0x25, 0x20 }, { 0x26, 0x90 },
	{ 0x27, 0x88 }
};

static struct urtw_pair urtw_8225_rf_part3[] = {
	{ 0x00, 0x98 }, { 0x03, 0x20 }, { 0x04, 0x7e }, { 0x05, 0x12 },
	{ 0x06, 0xfc }, { 0x07, 0x78 }, { 0x08, 0x2e }, { 0x10, 0x9b },
	{ 0x11, 0x88 }, { 0x12, 0x47 }, { 0x13, 0xd0 }, { 0x19, 0x00 },
	{ 0x1a, 0xa0 }, { 0x1b, 0x08 }, { 0x40, 0x86 }, { 0x41, 0x8d },
	{ 0x42, 0x15 }, { 0x43, 0x18 }, { 0x44, 0x1f }, { 0x45, 0x1e },
	{ 0x46, 0x1a }, { 0x47, 0x15 }, { 0x48, 0x10 }, { 0x49, 0x0a },
	{ 0x4a, 0x05 }, { 0x4b, 0x02 }, { 0x4c, 0x05 }
};

static uint16_t urtw_8225_rxgain[] = {
	0x0400, 0x0401, 0x0402, 0x0403, 0x0404, 0x0405, 0x0408, 0x0409,
	0x040a, 0x040b, 0x0502, 0x0503, 0x0504, 0x0505, 0x0540, 0x0541,
	0x0542, 0x0543, 0x0544, 0x0545, 0x0580, 0x0581, 0x0582, 0x0583,
	0x0584, 0x0585, 0x0588, 0x0589, 0x058a, 0x058b, 0x0643, 0x0644,
	0x0645, 0x0680, 0x0681, 0x0682, 0x0683, 0x0684, 0x0685, 0x0688,
	0x0689, 0x068a, 0x068b, 0x068c, 0x0742, 0x0743, 0x0744, 0x0745,
	0x0780, 0x0781, 0x0782, 0x0783, 0x0784, 0x0785, 0x0788, 0x0789,
	0x078a, 0x078b, 0x078c, 0x078d, 0x0790, 0x0791, 0x0792, 0x0793,
	0x0794, 0x0795, 0x0798, 0x0799, 0x079a, 0x079b, 0x079c, 0x079d,
	0x07a0, 0x07a1, 0x07a2, 0x07a3, 0x07a4, 0x07a5, 0x07a8, 0x07a9,
	0x07aa, 0x07ab, 0x07ac, 0x07ad, 0x07b0, 0x07b1, 0x07b2, 0x07b3,
	0x07b4, 0x07b5, 0x07b8, 0x07b9, 0x07ba, 0x07bb, 0x07bb
};

static uint8_t urtw_8225_threshold[] = {
	0x8d, 0x8d, 0x8d, 0x8d, 0x9d, 0xad, 0xbd,
};

static uint8_t urtw_8225_tx_gain_cck_ofdm[] = {
	0x02, 0x06, 0x0e, 0x1e, 0x3e, 0x7e
};

static uint8_t urtw_8225_txpwr_cck[] = {
	0x18, 0x17, 0x15, 0x11, 0x0c, 0x08, 0x04, 0x02,
	0x1b, 0x1a, 0x17, 0x13, 0x0e, 0x09, 0x04, 0x02,
	0x1f, 0x1e, 0x1a, 0x15, 0x10, 0x0a, 0x05, 0x02,
	0x22, 0x21, 0x1d, 0x18, 0x11, 0x0b, 0x06, 0x02,
	0x26, 0x25, 0x21, 0x1b, 0x14, 0x0d, 0x06, 0x03,
	0x2b, 0x2a, 0x25, 0x1e, 0x16, 0x0e, 0x07, 0x03
};

static uint8_t urtw_8225_txpwr_cck_ch14[] = {
	0x18, 0x17, 0x15, 0x0c, 0x00, 0x00, 0x00, 0x00,
	0x1b, 0x1a, 0x17, 0x0e, 0x00, 0x00, 0x00, 0x00,
	0x1f, 0x1e, 0x1a, 0x0f, 0x00, 0x00, 0x00, 0x00,
	0x22, 0x21, 0x1d, 0x11, 0x00, 0x00, 0x00, 0x00,
	0x26, 0x25, 0x21, 0x13, 0x00, 0x00, 0x00, 0x00,
	0x2b, 0x2a, 0x25, 0x15, 0x00, 0x00, 0x00, 0x00
};

static uint8_t urtw_8225_txpwr_ofdm[] = {
	0x80, 0x90, 0xa2, 0xb5, 0xcb, 0xe4
};

static uint8_t urtw_8225v2_gain_bg[] = {
	0x23, 0x15, 0xa5,		/* -82-1dbm  */
	0x23, 0x15, 0xb5,		/* -82-2dbm  */
	0x23, 0x15, 0xc5,		/* -82-3dbm  */
	0x33, 0x15, 0xc5,		/* -78dbm  */
	0x43, 0x15, 0xc5,		/* -74dbm  */
	0x53, 0x15, 0xc5,		/* -70dbm  */
	0x63, 0x15, 0xc5,		/* -66dbm  */
};

static struct urtw_pair urtw_8225v2_rf_part1[] = {
	{ 0x00, 0x02bf }, { 0x01, 0x0ee0 }, { 0x02, 0x044d }, { 0x03, 0x0441 },
	{ 0x04, 0x08c3 }, { 0x05, 0x0c72 }, { 0x06, 0x00e6 }, { 0x07, 0x082a },
	{ 0x08, 0x003f }, { 0x09, 0x0335 }, { 0x0a, 0x09d4 }, { 0x0b, 0x07bb },
	{ 0x0c, 0x0850 }, { 0x0d, 0x0cdf }, { 0x0e, 0x002b }, { 0x0f, 0x0114 }
};

static struct urtw_pair urtw_8225v2_rf_part2[] = {
	{ 0x00, 0x01 }, { 0x01, 0x02 }, { 0x02, 0x42 }, { 0x03, 0x00 },
	{ 0x04, 0x00 },	{ 0x05, 0x00 }, { 0x06, 0x40 }, { 0x07, 0x00 },
	{ 0x08, 0x40 }, { 0x09, 0xfe }, { 0x0a, 0x08 }, { 0x0b, 0x80 },
	{ 0x0c, 0x01 }, { 0x0d, 0x43 }, { 0x0e, 0xd3 }, { 0x0f, 0x38 },
	{ 0x10, 0x84 }, { 0x11, 0x07 }, { 0x12, 0x20 }, { 0x13, 0x20 },
	{ 0x14, 0x00 }, { 0x15, 0x40 }, { 0x16, 0x00 }, { 0x17, 0x40 },
	{ 0x18, 0xef }, { 0x19, 0x19 }, { 0x1a, 0x20 }, { 0x1b, 0x15 },
	{ 0x1c, 0x04 }, { 0x1d, 0xc5 }, { 0x1e, 0x95 }, { 0x1f, 0x75 },
	{ 0x20, 0x1f }, { 0x21, 0x17 }, { 0x22, 0x16 }, { 0x23, 0x80 },
	{ 0x24, 0x46 }, { 0x25, 0x00 }, { 0x26, 0x90 }, { 0x27, 0x88 }
};

static struct urtw_pair urtw_8225v2_rf_part3[] = {
	{ 0x00, 0x98 }, { 0x03, 0x20 }, { 0x04, 0x7e }, { 0x05, 0x12 },
	{ 0x06, 0xfc }, { 0x07, 0x78 }, { 0x08, 0x2e }, { 0x09, 0x11 },
	{ 0x0a, 0x17 }, { 0x0b, 0x11 }, { 0x10, 0x9b }, { 0x11, 0x88 },
	{ 0x12, 0x47 }, { 0x13, 0xd0 }, { 0x19, 0x00 }, { 0x1a, 0xa0 },
	{ 0x1b, 0x08 }, { 0x1d, 0x00 }, { 0x40, 0x86 }, { 0x41, 0x9d },
	{ 0x42, 0x15 }, { 0x43, 0x18 }, { 0x44, 0x36 }, { 0x45, 0x35 },
	{ 0x46, 0x2e }, { 0x47, 0x25 }, { 0x48, 0x1c }, { 0x49, 0x12 },
	{ 0x4a, 0x09 }, { 0x4b, 0x04 }, { 0x4c, 0x05 }
};

static uint16_t urtw_8225v2_rxgain[] = {
	0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0008, 0x0009,
	0x000a,	0x000b, 0x0102, 0x0103, 0x0104, 0x0105, 0x0140, 0x0141,
	0x0142,	0x0143, 0x0144, 0x0145, 0x0180, 0x0181, 0x0182, 0x0183,
	0x0184,	0x0185, 0x0188, 0x0189, 0x018a, 0x018b, 0x0243, 0x0244,
	0x0245,	0x0280, 0x0281, 0x0282, 0x0283, 0x0284, 0x0285, 0x0288,
	0x0289, 0x028a, 0x028b, 0x028c, 0x0342, 0x0343, 0x0344, 0x0345,
	0x0380, 0x0381, 0x0382, 0x0383, 0x0384, 0x0385, 0x0388, 0x0389,
	0x038a, 0x038b, 0x038c, 0x038d, 0x0390, 0x0391, 0x0392, 0x0393,
	0x0394, 0x0395, 0x0398, 0x0399, 0x039a, 0x039b, 0x039c, 0x039d,
	0x03a0, 0x03a1, 0x03a2, 0x03a3, 0x03a4, 0x03a5, 0x03a8, 0x03a9,
	0x03aa, 0x03ab, 0x03ac, 0x03ad, 0x03b0, 0x03b1, 0x03b2, 0x03b3,
	0x03b4, 0x03b5, 0x03b8, 0x03b9, 0x03ba, 0x03bb, 0x03bb
};

static uint8_t urtw_8225v2_tx_gain_cck_ofdm[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
	0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
	0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
	0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
	0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
};

static uint8_t urtw_8225v2_txpwr_cck[] = {
	0x36, 0x35, 0x2e, 0x25, 0x1c, 0x12, 0x09, 0x04
};

static uint8_t urtw_8225v2_txpwr_cck_ch14[] = {
	0x36, 0x35, 0x2e, 0x1b, 0x00, 0x00, 0x00, 0x00
};

static struct urtw_pair urtw_ratetable[] = {
	{  2,  0 }, {   4,  1 }, { 11, 2 }, { 12, 4 }, { 18, 5 },
	{ 22,  3 }, {  24,  6 }, { 36, 7 }, { 48, 8 }, { 72, 9 },
	{ 96, 10 }, { 108, 11 }
};

static int		urtw_init(void *);
static void		urtw_stop(struct urtw_softc *);
static int		urtw_set_channel(struct urtw_softc *);
static void
urtw_rxeof(usb_pipe_handle_t, usb_bulk_req_t *);
static int
urtw_newstate(struct ieee80211com *, enum ieee80211_state, int);
static usbd_status	urtw_read8_c(struct urtw_softc *, int, uint8_t *);
static usbd_status	urtw_read16_c(struct urtw_softc *, int, uint16_t *);
static usbd_status	urtw_read32_c(struct urtw_softc *, int, uint32_t *);
static usbd_status	urtw_write8_c(struct urtw_softc *, int, uint8_t);
static usbd_status	urtw_write16_c(struct urtw_softc *, int, uint16_t);
static usbd_status	urtw_write32_c(struct urtw_softc *, int, uint32_t);
static usbd_status	urtw_eprom_cs(struct urtw_softc *, int);
static usbd_status	urtw_eprom_ck(struct urtw_softc *);
static usbd_status	urtw_eprom_sendbits(struct urtw_softc *, int16_t *,
			    int);
static usbd_status	urtw_eprom_read32(struct urtw_softc *, uint32_t,
			    uint32_t *);
static usbd_status	urtw_eprom_readbit(struct urtw_softc *, int16_t *);
static usbd_status	urtw_eprom_writebit(struct urtw_softc *, int16_t);
static usbd_status	urtw_get_macaddr(struct urtw_softc *);
static usbd_status	urtw_get_txpwr(struct urtw_softc *);
static usbd_status	urtw_get_rfchip(struct urtw_softc *);
static usbd_status	urtw_led_init(struct urtw_softc *);
static usbd_status
urtw_8225_read(struct urtw_softc *, uint8_t, uint32_t *);
static usbd_status	urtw_8225_rf_init(struct urtw_softc *);
static usbd_status	urtw_8225_rf_set_chan(struct urtw_softc *, int);
static usbd_status	urtw_8225_rf_set_sens(struct urtw_softc *, int);
static usbd_status	urtw_8225v2_rf_init(struct urtw_softc *);
static usbd_status	urtw_8225v2_rf_set_chan(struct urtw_softc *, int);
static usbd_status	urtw_open_pipes(struct urtw_softc *);
static void urtw_close_pipes(struct urtw_softc *);
static void urtw_led_launch(void *);

#ifdef DEBUG

#define	URTW_DEBUG_XMIT		0x00000001
#define	URTW_DEBUG_RECV		0x00000002
#define	URTW_DEBUG_LED 		0x00000004
#define	URTW_DEBUG_GLD 		0x00000008
#define	URTW_DEBUG_RF		0x00000010
#define	URTW_DEBUG_ATTACH 	0x00000020
#define	URTW_DEBUG_ACTIVE 	0x00000040
#define	URTW_DEBUG_HWTYPE	0x00000080
#define	URTW_DEBUG_STATE	0x00000100
#define	URTW_DEBUG_HOTPLUG	0x00000200
#define	URTW_DEBUG_STAT		0x00000400
#define	URTW_DEBUG_TX_PROC	0x00000800
#define	URTW_DEBUG_RX_PROC 	0x00001000
#define	URTW_DEBUG_EEPROM	0x00002000
#define	URTW_DEBUG_RESET	0x00004000
#define	URTW_DEBUG_DEVREQ	0x00010000
#define	URTW_DEBUG_ANY		0xffffffff

uint32_t urtw8187_dbg_flags = 0;
static void
urtw8187_dbg(dev_info_t *dip, int level, const char *fmt, ...)
{
	char		msg_buffer[255];
	va_list	ap;

	if (dip == NULL) {
		return;
	}

	va_start(ap, fmt);
	(void) vsprintf(msg_buffer, fmt, ap);
	cmn_err(level, "%s%d: %s", ddi_get_name(dip),
	    ddi_get_instance(dip), msg_buffer);
	va_end(ap);
}

#define	URTW8187_DBG(l, x) do {\
	_NOTE(CONSTANTCONDITION) \
	if ((l) & urtw8187_dbg_flags) \
		urtw8187_dbg x;\
	_NOTE(CONSTANTCONDITION) \
} while (0)
#else
#define	URTW8187_DBG(l, x)
#endif

static usbd_status
urtw_led_init(struct urtw_softc *sc)
{
	uint32_t rev;
	usbd_status error;

	if (error = urtw_read8_c(sc, URTW_PSR, &sc->sc_psr))
		goto fail;
	error = urtw_eprom_read32(sc, URTW_EPROM_SWREV, &rev);
	if (error != 0)
		goto fail;

	switch (rev & URTW_EPROM_CID_MASK) {
	case URTW_EPROM_CID_ALPHA0:
		sc->sc_strategy = URTW_SW_LED_MODE1;
		break;
	case URTW_EPROM_CID_SERCOMM_PS:
		sc->sc_strategy = URTW_SW_LED_MODE3;
		break;
	case URTW_EPROM_CID_HW_LED:
		sc->sc_strategy = URTW_HW_LED;
		break;
	case URTW_EPROM_CID_RSVD0:
	case URTW_EPROM_CID_RSVD1:
	default:
		sc->sc_strategy = URTW_SW_LED_MODE0;
		break;
	}

	sc->sc_gpio_ledpin = URTW_LED_PIN_GPIO0;

fail:
	return (error);
}

static usbd_status
urtw_8225_write_s16(struct urtw_softc *sc, uint8_t addr, int index,
    uint16_t *data)
{
	usb_ctrl_setup_t req;
	usb_cr_t cr;
	usb_cb_flags_t cf;
	mblk_t *mp = 0;
	uint16_t data16;
	usbd_status error;

	data16 = *data;
	bzero(&req, sizeof (req));
	req.bmRequestType = UT_WRITE_VENDOR_DEVICE;
	req.bRequest = URTW_8187_SETREGS_REQ;
	req.wValue = addr;
	req.wIndex = (uint16_t)index;
	req.wLength = sizeof (uint16_t);
	req.attrs = USB_ATTRS_NONE;

	mp = allocb(sizeof (uint16_t), BPRI_MED);
	if (mp == 0) {
		cmn_err(CE_WARN, "urtw_8225_write_s16: allocb failed\n");
		return (-1);
	}
	*(mp->b_rptr) = (data16 & 0x00ff);
	*(mp->b_rptr + 1) = (data16 & 0xff00) >> 8;
	mp->b_wptr += sizeof (uint16_t);
	error = usb_pipe_ctrl_xfer_wait(sc->sc_udev->dev_default_ph, &req, &mp,
	    &cr, &cf, 0);
	if (error != USB_SUCCESS) {
		URTW8187_DBG(URTW_DEBUG_DEVREQ, (sc->sc_dev, CE_CONT,
		    "urtw_8225_write_s16: could not set regs:"
		    "cr:%s(%d), cf:(%x)\n", usb_str_cr(cr), cr, cf));
	}
	if (mp)
		freemsg(mp);
	return (error);

}

static usbd_status
urtw_8225_read(struct urtw_softc *sc, uint8_t addr, uint32_t *data)
{
	int i;
	int16_t bit;
	uint8_t rlen = 12, wlen = 6;
	uint16_t o1, o2, o3, tmp;
	uint32_t d2w = ((uint32_t)(addr & 0x1f)) << 27;
	uint32_t mask = 0x80000000, value = 0;
	usbd_status error;

	if (error = urtw_read16_c(sc, URTW_RF_PINS_OUTPUT, &o1))
		goto fail;
	if (error = urtw_read16_c(sc, URTW_RF_PINS_ENABLE, &o2))
		goto fail;
	if (error = urtw_read16_c(sc, URTW_RF_PINS_SELECT, &o3))
		goto fail;
	if (error = urtw_write16_c(sc, URTW_RF_PINS_ENABLE, o2 | 0xf))
		goto fail;
	if (error = urtw_write16_c(sc, URTW_RF_PINS_SELECT, o3 | 0xf))
		goto fail;
	o1 &= ~0xf;
	if (error = urtw_write16_c(sc, URTW_RF_PINS_OUTPUT,
	    o1 | URTW_BB_HOST_BANG_EN))
		goto fail;
	DELAY(5);
	if (error = urtw_write16_c(sc, URTW_RF_PINS_OUTPUT, o1))
		goto fail;
	DELAY(5);

	for (i = 0; i < (wlen / 2); i++, mask = mask >> 1) {
		bit = ((d2w & mask) != 0) ? 1 : 0;

		if (error = urtw_write16_c(sc, URTW_RF_PINS_OUTPUT, bit | o1))
			goto fail;
		DELAY(2);
		if (error = urtw_write16_c(sc, URTW_RF_PINS_OUTPUT, bit | o1 |
		    URTW_BB_HOST_BANG_CLK))
			goto fail;
		DELAY(2);
		if (error = urtw_write16_c(sc, URTW_RF_PINS_OUTPUT, bit | o1 |
		    URTW_BB_HOST_BANG_CLK))
			goto fail;
		DELAY(2);
		mask = mask >> 1;
		if (i == 2)
			break;
		bit = ((d2w & mask) != 0) ? 1 : 0;
		if (error = urtw_write16_c(sc, URTW_RF_PINS_OUTPUT, bit | o1 |
		    URTW_BB_HOST_BANG_CLK))
			goto fail;
		DELAY(2);
		if (error = urtw_write16_c(sc, URTW_RF_PINS_OUTPUT, bit | o1 |
		    URTW_BB_HOST_BANG_CLK))
			goto fail;
		DELAY(2);
		if (error = urtw_write16_c(sc, URTW_RF_PINS_OUTPUT, bit | o1))
			goto fail;
		DELAY(1);
	}
	if (error = urtw_write16_c(sc, URTW_RF_PINS_OUTPUT,
	    bit | o1 | URTW_BB_HOST_BANG_RW | URTW_BB_HOST_BANG_CLK))
		goto fail;
	DELAY(2);
	if (error = urtw_write16_c(sc, URTW_RF_PINS_OUTPUT,
	    bit | o1 | URTW_BB_HOST_BANG_RW))
		goto fail;
	DELAY(2);
	if (error = urtw_write16_c(sc, URTW_RF_PINS_OUTPUT,
	    o1 | URTW_BB_HOST_BANG_RW))
		goto fail;
	DELAY(2);

	mask = 0x800;
	for (i = 0; i < rlen; i++, mask = mask >> 1) {
		if (error = urtw_write16_c(sc, URTW_RF_PINS_OUTPUT,
		    o1 | URTW_BB_HOST_BANG_RW))
			goto fail;
		DELAY(2);
		if (error = urtw_write16_c(sc, URTW_RF_PINS_OUTPUT,
		    o1 | URTW_BB_HOST_BANG_RW | URTW_BB_HOST_BANG_CLK))
			goto fail;
		DELAY(2);
		if (error = urtw_write16_c(sc, URTW_RF_PINS_OUTPUT,
		    o1 | URTW_BB_HOST_BANG_RW | URTW_BB_HOST_BANG_CLK))
			goto fail;
		DELAY(2);
		if (error = urtw_write16_c(sc, URTW_RF_PINS_OUTPUT,
		    o1 | URTW_BB_HOST_BANG_RW | URTW_BB_HOST_BANG_CLK))
			goto fail;
		DELAY(2);

		if (error = urtw_read16_c(sc, URTW_RF_PINS_INPUT, &tmp))
			goto fail;
		value |= ((tmp & URTW_BB_HOST_BANG_CLK) ? mask : 0);
		if (error = urtw_write16_c(sc, URTW_RF_PINS_OUTPUT,
		    o1 | URTW_BB_HOST_BANG_RW))
			goto fail;
		DELAY(2);
	}

	if (error = urtw_write16_c(sc, URTW_RF_PINS_OUTPUT,
	    o1 | URTW_BB_HOST_BANG_EN |
	    URTW_BB_HOST_BANG_RW))
		goto fail;
	DELAY(2);

	if (error = urtw_write16_c(sc, URTW_RF_PINS_ENABLE, o2))
		goto fail;
	if (error = urtw_write16_c(sc, URTW_RF_PINS_SELECT, o3))
		goto fail;
	error = urtw_write16_c(sc, URTW_RF_PINS_OUTPUT, 0x3a0);

	if (data != NULL)
		*data = value;
fail:
	return (error);
}

static void
urtw_delay_ms(int t)
{
	DELAY(t * 1000);
}

static usbd_status
urtw_8225_write_c(struct urtw_softc *sc, uint8_t addr, uint16_t data)
{
	uint16_t d80, d82, d84;
	usbd_status error;

	if (error = urtw_read16_c(sc, URTW_RF_PINS_OUTPUT, &d80))
		goto fail;
	d80 &= 0xfff3;
	if (error = urtw_read16_c(sc, URTW_RF_PINS_ENABLE, &d82))
		goto fail;
	if (error = urtw_read16_c(sc, URTW_RF_PINS_SELECT, &d84))
		goto fail;
	d84 &= 0xfff0;
	if (error = urtw_write16_c(sc, URTW_RF_PINS_ENABLE,
	    d82 | 0x0007))
		goto fail;
	if (error = urtw_write16_c(sc, URTW_RF_PINS_SELECT,
	    d84 | 0x0007))
		goto fail;
	DELAY(10);

	if (error = urtw_write16_c(sc, URTW_RF_PINS_OUTPUT,
	    d80 | URTW_BB_HOST_BANG_EN))
		goto fail;
	DELAY(2);
	if (error = urtw_write16_c(sc, URTW_RF_PINS_OUTPUT, d80))
		goto fail;
	DELAY(10);

	error = urtw_8225_write_s16(sc, addr, 0x8225, &data);
	if (error != 0)
		goto fail;

	if (error = urtw_write16_c(sc, URTW_RF_PINS_OUTPUT,
	    d80 | URTW_BB_HOST_BANG_EN))
		goto fail;
	DELAY(10);
	if (error = urtw_write16_c(sc, URTW_RF_PINS_OUTPUT,
	    d80 | URTW_BB_HOST_BANG_EN))
		goto fail;
	error = urtw_write16_c(sc, URTW_RF_PINS_SELECT, d84);
	urtw_delay_ms(2);
fail:
	return (error);
}

static usbd_status
urtw_8225_isv2(struct urtw_softc *sc, int *ret)
{
	uint32_t data;
	usbd_status error;

	*ret = 1;

	if (error = urtw_write16_c(sc, URTW_RF_PINS_OUTPUT, 0x0080))
		goto fail;
	if (error = urtw_write16_c(sc, URTW_RF_PINS_SELECT, 0x0080))
		goto fail;
	if (error = urtw_write16_c(sc, URTW_RF_PINS_ENABLE, 0x0080))
		goto fail;
	urtw_delay_ms(300);

	if (error = urtw_8225_write_c(sc, 0x0, 0x1b7))
		goto fail;

	error = urtw_8225_read(sc, 0x8, &data);
	if (error != 0)
		goto fail;
	if (data != 0x588)
		*ret = 0;
	else {
		error = urtw_8225_read(sc, 0x9, &data);
		if (error != 0)
			goto fail;
		if (data != 0x700)
			*ret = 0;
	}

	error = urtw_8225_write_c(sc, 0x0, 0xb7);
fail:
	return (error);
}

static usbd_status
urtw_get_rfchip(struct urtw_softc *sc)
{
	int ret;
	uint32_t data;
	usbd_status error;

	error = urtw_eprom_read32(sc, URTW_EPROM_RFCHIPID, &data);
	if (error != 0)
		goto fail;
	switch (data & 0xff) {
	case URTW_EPROM_RFCHIPID_RTL8225U:
		error = urtw_8225_isv2(sc, &ret);
		if (error != 0)
			goto fail;
		if (ret == 0) {
			URTW8187_DBG(URTW_DEBUG_HWTYPE,
			    (sc->sc_dev, CE_CONT, "8225 RF chip detected\n"));
			sc->sc_rf_init = urtw_8225_rf_init;
			sc->sc_rf_set_sens = urtw_8225_rf_set_sens;
			sc->sc_rf_set_chan = urtw_8225_rf_set_chan;
		} else {
			URTW8187_DBG(URTW_DEBUG_HWTYPE,
			    (sc->sc_dev, CE_CONT,
			    "8225 v2 RF chip detected\n"));
			sc->sc_rf_init = urtw_8225v2_rf_init;
			sc->sc_rf_set_chan = urtw_8225v2_rf_set_chan;
		}
		sc->sc_max_sens = URTW_8225_RF_MAX_SENS;
		sc->sc_sens = URTW_8225_RF_DEF_SENS;
		break;
	default:
		cmn_err(CE_WARN, "unsupported RF chip %d\n", data & 0xff);
		error = -1;
	}

fail:
	return (error);
}

static usbd_status
urtw_get_txpwr(struct urtw_softc *sc)
{
	int i, j;
	uint32_t data;
	usbd_status error;

	error = urtw_eprom_read32(sc, URTW_EPROM_TXPW_BASE, &data);
	if (error != 0)
		goto fail;
	sc->sc_txpwr_cck_base = data & 0xf;
	sc->sc_txpwr_ofdm_base = (data >> 4) & 0xf;

	for (i = 1, j = 0; i < 6; i += 2, j++) {
		error = urtw_eprom_read32(sc, URTW_EPROM_TXPW0 + j, &data);
		if (error != 0)
			goto fail;
		sc->sc_txpwr_cck[i] = data & 0xf;
		sc->sc_txpwr_cck[i + 1] = (data & 0xf00) >> 8;
		sc->sc_txpwr_ofdm[i] = (data & 0xf0) >> 4;
		sc->sc_txpwr_ofdm[i + 1] = (data & 0xf000) >> 12;
	}
	for (i = 1, j = 0; i < 4; i += 2, j++) {
		error = urtw_eprom_read32(sc, URTW_EPROM_TXPW1 + j, &data);
		if (error != 0)
			goto fail;
		sc->sc_txpwr_cck[i + 6] = data & 0xf;
		sc->sc_txpwr_cck[i + 6 + 1] = (data & 0xf00) >> 8;
		sc->sc_txpwr_ofdm[i + 6] = (data & 0xf0) >> 4;
		sc->sc_txpwr_ofdm[i + 6 + 1] = (data & 0xf000) >> 12;
	}
	for (i = 1, j = 0; i < 4; i += 2, j++) {
		error = urtw_eprom_read32(sc, URTW_EPROM_TXPW2 + j, &data);
		if (error != 0)
			goto fail;
		sc->sc_txpwr_cck[i + 6 + 4] = data & 0xf;
		sc->sc_txpwr_cck[i + 6 + 4 + 1] = (data & 0xf00) >> 8;
		sc->sc_txpwr_ofdm[i + 6 + 4] = (data & 0xf0) >> 4;
		sc->sc_txpwr_ofdm[i + 6 + 4 + 1] = (data & 0xf000) >> 12;
	}
fail:
	return (error);
}

static usbd_status
urtw_get_macaddr(struct urtw_softc *sc)
{
	uint32_t data;
	usbd_status error;
	uint8_t *m = 0;

	error = urtw_eprom_read32(sc, URTW_EPROM_MACADDR, &data);
	if (error != 0)
		goto fail;
	sc->sc_bssid[0] = data & 0xff;
	sc->sc_bssid[1] = (data & 0xff00) >> 8;
	error = urtw_eprom_read32(sc, URTW_EPROM_MACADDR + 1, &data);
	if (error != 0)
		goto fail;
	sc->sc_bssid[2] = data & 0xff;
	sc->sc_bssid[3] = (data & 0xff00) >> 8;
	error = urtw_eprom_read32(sc, URTW_EPROM_MACADDR + 2, &data);
	if (error != 0)
		goto fail;
	sc->sc_bssid[4] = data & 0xff;
	sc->sc_bssid[5] = (data & 0xff00) >> 8;
	bcopy(sc->sc_bssid, sc->sc_ic.ic_macaddr, IEEE80211_ADDR_LEN);
	m = sc->sc_bssid;
	URTW8187_DBG(URTW_DEBUG_HWTYPE, (sc->sc_dev, CE_CONT,
	    "MAC: %x:%x:%x:%x:%x:%x\n",
	    m[0], m[1], m[2], m[3], m[4], m[5]));
fail:
	return (error);
}

static usbd_status
urtw_eprom_read32(struct urtw_softc *sc, uint32_t addr, uint32_t *data)
{
#define	URTW_READCMD_LEN	3
	int addrlen, i;
	int16_t addrstr[8], data16, readcmd[] = { 1, 1, 0 };
	usbd_status error;

	/* NB: make sure the buffer is initialized  */
	*data = 0;

	/* enable EPROM programming */
	if (error = urtw_write8_c(sc, URTW_EPROM_CMD,
	    URTW_EPROM_CMD_PROGRAM_MODE))
		goto fail;
	DELAY(URTW_EPROM_DELAY);

	error = urtw_eprom_cs(sc, URTW_EPROM_ENABLE);
	if (error != 0)
		goto fail;
	error = urtw_eprom_ck(sc);
	if (error != 0)
		goto fail;
	error = urtw_eprom_sendbits(sc, readcmd, URTW_READCMD_LEN);
	if (error != 0)
		goto fail;
	if (sc->sc_epromtype == URTW_EEPROM_93C56) {
		addrlen = 8;
		addrstr[0] = addr & (1 << 7);
		addrstr[1] = addr & (1 << 6);
		addrstr[2] = addr & (1 << 5);
		addrstr[3] = addr & (1 << 4);
		addrstr[4] = addr & (1 << 3);
		addrstr[5] = addr & (1 << 2);
		addrstr[6] = addr & (1 << 1);
		addrstr[7] = addr & (1 << 0);
	} else {
		addrlen = 6;
		addrstr[0] = addr & (1 << 5);
		addrstr[1] = addr & (1 << 4);
		addrstr[2] = addr & (1 << 3);
		addrstr[3] = addr & (1 << 2);
		addrstr[4] = addr & (1 << 1);
		addrstr[5] = addr & (1 << 0);
	}
	error = urtw_eprom_sendbits(sc, addrstr, addrlen);
	if (error != 0)
		goto fail;

	error = urtw_eprom_writebit(sc, 0);
	if (error != 0)
		goto fail;

	for (i = 0; i < 16; i++) {
		error = urtw_eprom_ck(sc);
		if (error != 0)
			goto fail;
		error = urtw_eprom_readbit(sc, &data16);
		if (error != 0)
			goto fail;

		(*data) |= (data16 << (15 - i));
	}

	error = urtw_eprom_cs(sc, URTW_EPROM_DISABLE);
	if (error != 0)
		goto fail;
	error = urtw_eprom_ck(sc);
	if (error != 0)
		goto fail;

	/* now disable EPROM programming */
	error = urtw_write8_c(sc, URTW_EPROM_CMD, URTW_EPROM_CMD_NORMAL_MODE);
fail:
	return (error);
#undef URTW_READCMD_LEN
}

static usbd_status
urtw_eprom_readbit(struct urtw_softc *sc, int16_t *data)
{
	uint8_t data8;
	usbd_status error;

	error = urtw_read8_c(sc, URTW_EPROM_CMD, &data8);
	*data = (data8 & URTW_EPROM_READBIT) ? 1 : 0;
	DELAY(URTW_EPROM_DELAY);
	return (error);
}

static usbd_status
urtw_eprom_sendbits(struct urtw_softc *sc, int16_t *buf, int buflen)
{
	int i = 0;
	usbd_status error;

	for (i = 0; i < buflen; i++) {
		error = urtw_eprom_writebit(sc, buf[i]);
		if (error != 0)
			goto fail;
		error = urtw_eprom_ck(sc);
		if (error != 0)
			goto fail;
	}
fail:
	return (error);
}

static usbd_status
urtw_eprom_writebit(struct urtw_softc *sc, int16_t bit)
{
	uint8_t data;
	usbd_status error;

	if (error = urtw_read8_c(sc, URTW_EPROM_CMD, &data))
		goto fail;
	if (bit != 0)
		error = urtw_write8_c(sc, URTW_EPROM_CMD,
		    data | URTW_EPROM_WRITEBIT);
	else
		error = urtw_write8_c(sc, URTW_EPROM_CMD,
		    data & ~URTW_EPROM_WRITEBIT);
	DELAY(URTW_EPROM_DELAY);
fail:
	return (error);
}

static usbd_status
urtw_eprom_ck(struct urtw_softc *sc)
{
	uint8_t data;
	usbd_status error;

	/* masking  */
	if (error = urtw_read8_c(sc, URTW_EPROM_CMD, &data))
		goto fail;
	if (error = urtw_write8_c(sc, URTW_EPROM_CMD, data | URTW_EPROM_CK))
		goto fail;
	DELAY(URTW_EPROM_DELAY);
	/* unmasking  */
	if (error = urtw_read8_c(sc, URTW_EPROM_CMD, &data))
		goto fail;
	error = urtw_write8_c(sc, URTW_EPROM_CMD, data & ~URTW_EPROM_CK);
	DELAY(URTW_EPROM_DELAY);
fail:
	return (error);
}

static usbd_status
urtw_eprom_cs(struct urtw_softc *sc, int able)
{
	uint8_t data;
	usbd_status error;

	if (error = urtw_read8_c(sc, URTW_EPROM_CMD, &data))
		goto fail;
	if (able == URTW_EPROM_ENABLE)
		error = urtw_write8_c(sc, URTW_EPROM_CMD,
		    data | URTW_EPROM_CS);
	else
		error = urtw_write8_c(sc, URTW_EPROM_CMD,
		    data & ~URTW_EPROM_CS);
	DELAY(URTW_EPROM_DELAY);
fail:
	return (error);
}

static usbd_status
urtw_read8_c(struct urtw_softc *sc, int val, uint8_t *data)
{
	usb_ctrl_setup_t req;
	usb_cr_t cr;
	usb_cb_flags_t cf;
	mblk_t *mp = NULL;
	usbd_status error;

	bzero(&req, sizeof (req));
	req.bmRequestType = UT_READ_VENDOR_DEVICE;
	req.bRequest = URTW_8187_GETREGS_REQ;
	req.wValue = val | 0xff00;
	req.wIndex = 0;
	req.wLength = sizeof (uint8_t);

	error = usb_pipe_ctrl_xfer_wait(sc->sc_udev->dev_default_ph, &req, &mp,
	    &cr, &cf, 0);

	if (error != USB_SUCCESS) {
		URTW8187_DBG(URTW_DEBUG_DEVREQ, (sc->sc_dev, CE_CONT,
		    "urtw_read8_c: get regs req failed :"
		    " cr:%s(%d), cf:(%x)\n", usb_str_cr(cr), cr, cf));
		return (error);
	}
	bcopy(mp->b_rptr, data, sizeof (uint8_t));
	URTW8187_DBG(URTW_DEBUG_DEVREQ, (sc->sc_dev, CE_CONT,
	    "urtw_read8_c: get regs data1 ok :0x%x", *data));
	if (mp)
		freemsg(mp);
	return (error);
}

static usbd_status
urtw_read8e(struct urtw_softc *sc, int val, uint8_t *data)
{
	usb_ctrl_setup_t req;
	usb_cr_t cr;
	usb_cb_flags_t cf;
	mblk_t *mp = NULL;
	usbd_status error;

	bzero(&req, sizeof (req));
	req.bmRequestType = UT_READ_VENDOR_DEVICE;
	req.bRequest = URTW_8187_GETREGS_REQ;
	req.wValue = val | 0xfe00;
	req.wIndex = 0;
	req.wLength = sizeof (uint8_t);
	req.attrs = USB_ATTRS_AUTOCLEARING;
	error = usb_pipe_ctrl_xfer_wait(sc->sc_udev->dev_default_ph, &req, &mp,
	    &cr, &cf, 0);

	if (error != USB_SUCCESS) {
		URTW8187_DBG(URTW_DEBUG_DEVREQ, (sc->sc_dev, CE_CONT,
		    "urtw_read8e: get regs req failed :"
		    " cr:%s(%d), cf:(%x)\n", usb_str_cr(cr), cr, cf));
		return (error);
	}

	if (mp) {
		bcopy(mp->b_rptr, data, sizeof (uint8_t));
		URTW8187_DBG(URTW_DEBUG_DEVREQ, (sc->sc_dev, CE_CONT,
		    "urtw_read8e: get regs data1 ok :0x%x", *data));
		freemsg(mp);
	}
	return (error);
}

static usbd_status
urtw_read16_c(struct urtw_softc *sc, int val, uint16_t *data)
{
	usb_ctrl_setup_t req;
	usb_cr_t cr;
	usb_cb_flags_t cf;
	mblk_t *mp = NULL;
	usbd_status error;

	bzero(&req, sizeof (req));
	req.bmRequestType = UT_READ_VENDOR_DEVICE;
	req.bRequest = URTW_8187_GETREGS_REQ;
	req.wValue = val | 0xff00;
	req.wIndex = 0;
	req.wLength = sizeof (uint16_t);
	req.attrs = USB_ATTRS_AUTOCLEARING;
	error = usb_pipe_ctrl_xfer_wait(sc->sc_udev->dev_default_ph, &req, &mp,
	    &cr, &cf, 0);

	if (error != USB_SUCCESS) {
		URTW8187_DBG(URTW_DEBUG_DEVREQ, (sc->sc_dev, CE_CONT,
		    "urtw_read16_c: get regs req failed :"
		    " cr:%s(%d), cf:(%x)\n",
		    usb_str_cr(cr), cr, cf));
		return (error);
	}
	if (mp) {
		bcopy(mp->b_rptr, data, sizeof (uint16_t));
		URTW8187_DBG(URTW_DEBUG_DEVREQ, (sc->sc_dev, CE_CONT,
		    "urtw_read16_c: get regs data2 ok :0x%x", *data));
		freemsg(mp);
	}
	return (error);
}

static usbd_status
urtw_read32_c(struct urtw_softc *sc, int val, uint32_t *data)
{
	usb_ctrl_setup_t req;
	usb_cr_t cr;
	usb_cb_flags_t cf;
	mblk_t *mp = NULL;
	usbd_status error;

	bzero(&req, sizeof (req));
	req.bmRequestType = UT_READ_VENDOR_DEVICE;
	req.bRequest = URTW_8187_GETREGS_REQ;
	req.wValue = val | 0xff00;
	req.wIndex = 0;
	req.wLength = sizeof (uint32_t);
	req.attrs = USB_ATTRS_AUTOCLEARING;

	error = usb_pipe_ctrl_xfer_wait(sc->sc_udev->dev_default_ph, &req, &mp,
	    &cr, &cf, 0);

	if (error != USB_SUCCESS) {
		URTW8187_DBG(URTW_DEBUG_DEVREQ, (sc->sc_dev, CE_CONT,
		    "urtw_read32_c: get regs req failed :"
		    " cr:%s(%d), cf:(%x)\n", usb_str_cr(cr), cr, cf));
		return (error);
	}

	if (mp) {
		bcopy(mp->b_rptr, data, sizeof (uint32_t));
		URTW8187_DBG(URTW_DEBUG_DEVREQ, (sc->sc_dev, CE_CONT,
		    "urtw_read32_c: get regs data4 ok :0x%x", *data));
		freemsg(mp);
	}
	return (error);
}

static usbd_status
urtw_write8_c(struct urtw_softc *sc, int val, uint8_t data)
{
	usb_ctrl_setup_t req;
	usb_cr_t cr;
	usb_cb_flags_t cf;
	mblk_t *mp = 0;
	int error;

	bzero(&req, sizeof (req));
	req.bmRequestType = UT_WRITE_VENDOR_DEVICE;
	req.bRequest = URTW_8187_SETREGS_REQ;
	req.wValue = val | 0xff00;
	req.wIndex = 0;
	req.wLength = sizeof (uint8_t);
	req.attrs = USB_ATTRS_NONE;

	mp = allocb(sizeof (uint32_t), BPRI_MED);
	if (mp == NULL) {
		cmn_err(CE_CONT, "urtw_write8_c: failed alloc mblk.");
		return (-1);
	}
	*(uint8_t *)(mp->b_rptr) = data;
	mp->b_wptr += sizeof (uint8_t);
	error = usb_pipe_ctrl_xfer_wait(sc->sc_udev->dev_default_ph, &req, &mp,
	    &cr, &cf, 0);
	if (error != USB_SUCCESS) {
		URTW8187_DBG(URTW_DEBUG_DEVREQ, (sc->sc_dev, CE_CONT,
		    "urtw_write8_c: could not set regs:"
		    "cr:%s(%d), cf:(%x)\n", usb_str_cr(cr), cr, cf));
	}
	if (mp)
		freemsg(mp);
	return (error);
}

static usbd_status
urtw_write8e(struct urtw_softc *sc, int val, uint8_t data)
{
	usb_ctrl_setup_t req;
	usb_cr_t cr;
	usb_cb_flags_t cf;
	mblk_t *mp = 0;
	int error;

	bzero(&req, sizeof (req));
	req.bmRequestType = UT_WRITE_VENDOR_DEVICE;
	req.bRequest = URTW_8187_SETREGS_REQ;
	req.wValue = val | 0xfe00;
	req.wIndex = 0;
	req.wLength = sizeof (uint8_t);
	req.attrs = USB_ATTRS_NONE;

	mp = allocb(sizeof (uint8_t), BPRI_MED);
	if (mp == NULL) {
		cmn_err(CE_CONT, "urtw_write8e: failed alloc mblk.");
		return (-1);
	}
	*(mp->b_rptr) = data;
	mp->b_wptr += sizeof (uint8_t);

	error = usb_pipe_ctrl_xfer_wait(sc->sc_udev->dev_default_ph, &req, &mp,
	    &cr, &cf, 0);
	if (error != USB_SUCCESS) {
		URTW8187_DBG(URTW_DEBUG_DEVREQ, (sc->sc_dev, CE_CONT,
		    "urtw_write8e: could not set regs:"
		    "cr:%s(%d), cf:(%x)\n",
		    usb_str_cr(cr), cr, cf));
	}
	if (mp)
		freemsg(mp);
	return (error);
}

static usbd_status
urtw_write16_c(struct urtw_softc *sc, int val, uint16_t data)
{
	usb_ctrl_setup_t req;
	usb_cr_t cr;
	usb_cb_flags_t cf;
	mblk_t *mp = 0;
	int error;

	bzero(&req, sizeof (req));
	req.bmRequestType = UT_WRITE_VENDOR_DEVICE;
	req.bRequest = URTW_8187_SETREGS_REQ;
	req.wValue = val | 0xff00;
	req.wIndex = 0;
	req.wLength = sizeof (uint16_t);
	req.attrs = USB_ATTRS_NONE;

	mp = allocb(sizeof (uint16_t), BPRI_MED);
	if (mp == NULL) {
		cmn_err(CE_CONT, "urtw_write16_c: failed alloc mblk.");
		return (-1);
	}
	*(uint16_t *)(uintptr_t)(mp->b_rptr) = data;
	mp->b_wptr += sizeof (uint16_t);
	error = usb_pipe_ctrl_xfer_wait(sc->sc_udev->dev_default_ph, &req, &mp,
	    &cr, &cf, 0);
	if (error != USB_SUCCESS) {
		URTW8187_DBG(URTW_DEBUG_DEVREQ, (sc->sc_dev, CE_CONT,
		    "urtw_write16_c: could not set regs:"
		    "cr:%s(%d), cf:(%x)\n",
		    usb_str_cr(cr), cr, cf));
	}
	if (mp)
		freemsg(mp);
	return (error);
}

static usbd_status
urtw_write32_c(struct urtw_softc *sc, int val, uint32_t data)
{
	usb_ctrl_setup_t req;
	usb_cr_t cr;
	usb_cb_flags_t cf;
	mblk_t *mp = 0;
	int error;

	bzero(&req, sizeof (req));
	req.bmRequestType = UT_WRITE_VENDOR_DEVICE;
	req.bRequest = URTW_8187_SETREGS_REQ;
	req.wValue = val | 0xff00;
	req.wIndex = 0;
	req.wLength = sizeof (uint32_t);
	req.attrs = USB_ATTRS_NONE;

	mp = allocb(sizeof (uint32_t), BPRI_MED);
	if (mp == NULL) {
		cmn_err(CE_CONT, "urtw_write32_c: failed alloc mblk.");
		return (-1);
	}
	*(uint32_t *)(uintptr_t)(mp->b_rptr) = data;
	mp->b_wptr += sizeof (uint32_t);
	error = usb_pipe_ctrl_xfer_wait(sc->sc_udev->dev_default_ph, &req, &mp,
	    &cr, &cf, 0);
	if (error != USB_SUCCESS) {
		URTW8187_DBG(URTW_DEBUG_DEVREQ, (sc->sc_dev, CE_CONT,
		    "urtw_write32_c: could not set regs:"
		    "cr:%s(%d), cf:(%x)\n",
		    usb_str_cr(cr), cr, cf));
	}

	if (mp)
		freemsg(mp);
	return (error);
}

static usbd_status
urtw_set_mode(struct urtw_softc *sc, uint32_t mode)
{
	uint8_t data;
	usbd_status error;

	if (error = urtw_read8_c(sc, URTW_EPROM_CMD, &data))
		goto fail;
	data = (data & ~URTW_EPROM_CMD_MASK) | (mode << URTW_EPROM_CMD_SHIFT);
	data = data & ~(URTW_EPROM_CS | URTW_EPROM_CK);
	error = urtw_write8_c(sc, URTW_EPROM_CMD, data);
fail:
	return (error);
}

static usbd_status
urtw_8180_set_anaparam(struct urtw_softc *sc, uint32_t val)
{
	uint8_t data;
	usbd_status error;

	error = urtw_set_mode(sc, URTW_EPROM_CMD_CONFIG);
	if (error)
		goto fail;

	if (error = urtw_read8_c(sc, URTW_CONFIG3, &data))
		goto fail;
	if (error = urtw_write8_c(sc, URTW_CONFIG3,
	    data | URTW_CONFIG3_ANAPARAM_WRITE))
		goto fail;
	if (error = urtw_write32_c(sc, URTW_ANAPARAM, val))
		goto fail;
	if (error = urtw_read8_c(sc, URTW_CONFIG3, &data))
		goto fail;
	if (error = urtw_write8_c(sc, URTW_CONFIG3,
	    data & ~URTW_CONFIG3_ANAPARAM_WRITE))
		goto fail;

	error = urtw_set_mode(sc, URTW_EPROM_CMD_NORMAL);
	if (error)
		goto fail;
fail:
	return (error);
}

static usbd_status
urtw_8185_set_anaparam2(struct urtw_softc *sc, uint32_t val)
{
	uint8_t data;
	usbd_status error;

	error = urtw_set_mode(sc, URTW_EPROM_CMD_CONFIG);
	if (error)
		goto fail;

	if (error = urtw_read8_c(sc, URTW_CONFIG3, &data))
		goto fail;
	if (error = urtw_write8_c(sc, URTW_CONFIG3,
	    data | URTW_CONFIG3_ANAPARAM_WRITE))
		goto fail;
	if (error = urtw_write32_c(sc, URTW_ANAPARAM2, val))
		goto fail;
	if (error = urtw_read8_c(sc, URTW_CONFIG3, &data))
		goto fail;
	if (error = urtw_write8_c(sc, URTW_CONFIG3,
	    data & ~URTW_CONFIG3_ANAPARAM_WRITE))
		goto fail;

	error = urtw_set_mode(sc, URTW_EPROM_CMD_NORMAL);
	if (error)
		goto fail;
fail:
	return (error);
}

static usbd_status
urtw_intr_disable(struct urtw_softc *sc)
{
	usbd_status error;

	error = urtw_write16_c(sc, URTW_INTR_MASK, 0);
	return (error);
}

static usbd_status
urtw_reset(struct urtw_softc *sc)
{
	uint8_t data;
	usbd_status error;

	error = urtw_8180_set_anaparam(sc, URTW_8225_ANAPARAM_ON);
	if (error)
		goto fail;
	error = urtw_8185_set_anaparam2(sc, URTW_8225_ANAPARAM2_ON);
	if (error)
		goto fail;

	error = urtw_intr_disable(sc);
	if (error)
		goto fail;
	urtw_delay_ms(50);

	error = urtw_write8e(sc, 0x18, 0x10);
	if (error != 0)
		goto fail;
	error = urtw_write8e(sc, 0x18, 0x11);
	if (error != 0)
		goto fail;
	error = urtw_write8e(sc, 0x18, 0x00);
	if (error != 0)
		goto fail;
	urtw_delay_ms(50);

	if (error = urtw_read8_c(sc, URTW_CMD, &data))
		goto fail;
	data = (data & 2) | URTW_CMD_RST;
	if (error = urtw_write8_c(sc, URTW_CMD, data))
		goto fail;
	urtw_delay_ms(50);

	if (error = urtw_read8_c(sc, URTW_CMD, &data))
		goto fail;
	if (data & URTW_CMD_RST) {
		cmn_err(CE_CONT, "urtw reset timeout\n");
		goto fail;
	}
	error = urtw_set_mode(sc, URTW_EPROM_CMD_LOAD);
	if (error)
		goto fail;
	urtw_delay_ms(50);

	error = urtw_8180_set_anaparam(sc, URTW_8225_ANAPARAM_ON);
	if (error)
		goto fail;
	error = urtw_8185_set_anaparam2(sc, URTW_8225_ANAPARAM2_ON);
	if (error)
		goto fail;
fail:
	return (error);
}

static usbd_status
urtw_led_on(struct urtw_softc *sc, int type)
{
	if (type == URTW_LED_GPIO) {
		switch (sc->sc_gpio_ledpin) {
		case URTW_LED_PIN_GPIO0:
			(void) urtw_write8_c(sc, URTW_GPIO, 0x01);
			(void) urtw_write8_c(sc, URTW_GP_ENABLE, 0x00);
			break;
		default:
			cmn_err(CE_WARN, "unsupported LED PIN type 0x%x",
			    sc->sc_gpio_ledpin);
			/* never reach  */
		}
	} else {
		cmn_err(CE_WARN, "unsupported LED type 0x%x", type);
		/* never reach  */
	}

	sc->sc_gpio_ledon = 1;
	return (0);
}

static usbd_status
urtw_led_off(struct urtw_softc *sc, int type)
{
	if (type == URTW_LED_GPIO) {
		switch (sc->sc_gpio_ledpin) {
		case URTW_LED_PIN_GPIO0:
			(void) urtw_write8_c(sc, URTW_GPIO, 0x01);
			(void) urtw_write8_c(sc, URTW_GP_ENABLE, 0x01);
			break;
		default:
			cmn_err(CE_WARN, "unsupported LED PIN type 0x%x",
			    sc->sc_gpio_ledpin);
			/* never reach  */
		}
	} else {
		cmn_err(CE_WARN, "unsupported LED type 0x%x", type);
		/* never reach  */
	}

	sc->sc_gpio_ledon = 0;
	return (0);
}

static usbd_status
urtw_led_mode0(struct urtw_softc *sc, int mode)
{
	URTW8187_DBG(URTW_DEBUG_LED, (sc->sc_dev, CE_CONT,
	    "urtw_led_mode0: mode = %d\n", mode));
	switch (mode) {
	case URTW_LED_CTL_POWER_ON:
		sc->sc_gpio_ledstate = URTW_LED_POWER_ON_BLINK;
		break;
	case URTW_LED_CTL_TX:
		if (sc->sc_gpio_ledinprogress == 1)
			return (0);
		sc->sc_gpio_ledstate = URTW_LED_BLINK_NORMAL;
		sc->sc_gpio_blinktime =
		    (sc->sc_ic.ic_state == IEEE80211_S_RUN ? 4:2);
		break;
	case URTW_LED_CTL_LINK:
		sc->sc_gpio_ledstate = URTW_LED_ON;
		break;
	default:
		cmn_err(CE_CONT, "unsupported LED mode 0x%x", mode);
		/* never reach  */
	}

	switch (sc->sc_gpio_ledstate) {
	case URTW_LED_ON:
		if (sc->sc_gpio_ledinprogress != 0)
			break;
		(void) urtw_led_on(sc, URTW_LED_GPIO);
		break;
	case URTW_LED_BLINK_NORMAL:
		if (sc->sc_gpio_ledinprogress != 0)
			break;
		sc->sc_gpio_ledinprogress = 1;
		sc->sc_gpio_blinkstate = (sc->sc_gpio_ledon != 0) ?
		    URTW_LED_OFF : URTW_LED_ON;
		URTW_LEDLOCK(sc);
		if (sc->sc_led_ch == 0) {
			URTW8187_DBG(URTW_DEBUG_LED, (sc->sc_dev, CE_CONT,
			    "urtw_led_mode0: restart led timer\n"));
			sc->sc_led_ch = timeout(urtw_led_launch,
			    (void *)sc,
			    drv_usectohz((sc->sc_ic.ic_state ==
			    IEEE80211_S_RUN) ?
			    URTW_LED_LINKON_BLINK :
			    URTW_LED_LINKOFF_BLINK));
			sc->sc_gpio_ledinprogress = 0;
		}
		URTW_LEDUNLOCK(sc);
		break;
	case URTW_LED_POWER_ON_BLINK:
		(void) urtw_led_on(sc, URTW_LED_GPIO);
		urtw_delay_ms(100);
		(void) urtw_led_off(sc, URTW_LED_GPIO);
		break;
	default:
		URTW8187_DBG(URTW_DEBUG_LED, (sc->sc_dev, CE_CONT,
		    "urtw_led_mode0: unknown LED status 0x%x",
		    sc->sc_gpio_ledstate));
	}
	return (0);
}

static usbd_status
urtw_led_mode1(struct urtw_softc *sc, int mode)
{
	cmn_err(CE_WARN, "urtw sc %p, mode %d not supported", (void *)sc, mode);
	return (USBD_INVAL);
}

static usbd_status
urtw_led_mode2(struct urtw_softc *sc, int mode)
{
	cmn_err(CE_WARN, "urtw sc %p, mode %d not supported", (void *)sc, mode);
	return (USBD_INVAL);
}

static usbd_status
urtw_led_mode3(struct urtw_softc *sc, int mode)
{
	cmn_err(CE_WARN, "urtw sc %p, mode %d not supported", (void *)sc, mode);
	return (USBD_INVAL);
}

static usbd_status
urtw_led_blink(struct urtw_softc *sc)
{
	uint8_t ing = 0;

	URTW8187_DBG(URTW_DEBUG_LED, (sc->sc_dev, CE_CONT,
	    "urtw_led_blink: gpio_blinkstate %d\n",
	    sc->sc_gpio_blinkstate));
	if (sc->sc_gpio_blinkstate == URTW_LED_ON)
		(void) urtw_led_on(sc, URTW_LED_GPIO);
	else
		(void) urtw_led_off(sc, URTW_LED_GPIO);
	sc->sc_gpio_blinktime--;
	if (sc->sc_gpio_blinktime == 0)
		ing = 1;
	else {
		if (sc->sc_gpio_ledstate != URTW_LED_BLINK_NORMAL &&
		    sc->sc_gpio_ledstate != URTW_LED_BLINK_SLOWLY &&
		    sc->sc_gpio_ledstate != URTW_LED_BLINK_CM3)
			ing = 1;
	}
	if (ing == 1) {
		if (sc->sc_gpio_ledstate == URTW_LED_ON &&
		    sc->sc_gpio_ledon == 0)
			(void) urtw_led_on(sc, URTW_LED_GPIO);
		else if (sc->sc_gpio_ledstate == URTW_LED_OFF &&
		    sc->sc_gpio_ledon == 1)
			(void) urtw_led_off(sc, URTW_LED_GPIO);

		sc->sc_gpio_blinktime = 0;
		sc->sc_gpio_ledinprogress = 0;
		return (0);
	}

	sc->sc_gpio_blinkstate = (sc->sc_gpio_blinkstate != URTW_LED_ON) ?
	    URTW_LED_ON : URTW_LED_OFF;

	switch (sc->sc_gpio_ledstate) {
	case URTW_LED_BLINK_NORMAL:
		URTW8187_DBG(URTW_DEBUG_LED, (sc->sc_dev, CE_CONT,
		    "URTW_LED_BLINK_NORMAL\n"));
		return (1);
	default:
		URTW8187_DBG(URTW_DEBUG_LED, (sc->sc_dev, CE_CONT,
		    "unknown LED status 0x%x", sc->sc_gpio_ledstate));
	}
	return (0);
}

static usbd_status
urtw_led_ctl(struct urtw_softc *sc, int mode)
{
	usbd_status error = 0;

	switch (sc->sc_strategy) {
	case URTW_SW_LED_MODE0:
		error = urtw_led_mode0(sc, mode);
		break;
	case URTW_SW_LED_MODE1:
		error = urtw_led_mode1(sc, mode);
		break;
	case URTW_SW_LED_MODE2:
		error = urtw_led_mode2(sc, mode);
		break;
	case URTW_SW_LED_MODE3:
		error = urtw_led_mode3(sc, mode);
		break;
	default:
		cmn_err(CE_CONT, "unsupported LED mode %d\n", sc->sc_strategy);
		/* never reach  */
		return (-1);
	}

	return (error);
}

static usbd_status
urtw_update_msr(struct urtw_softc *sc, int nstate)
{
	struct ieee80211com *ic = &sc->sc_ic;
	uint8_t data;
	usbd_status error;

	if (error = urtw_read8_c(sc, URTW_MSR, &data))
		goto fail;
	data &= ~URTW_MSR_LINK_MASK;

	if (nstate == IEEE80211_S_RUN) {
		switch (ic->ic_opmode) {
		case IEEE80211_M_STA:
		case IEEE80211_M_MONITOR:
			data |= URTW_MSR_LINK_STA;
			break;
		case IEEE80211_M_IBSS:
			data |= URTW_MSR_LINK_ADHOC;
			break;
		case IEEE80211_M_HOSTAP:
			data |= URTW_MSR_LINK_HOSTAP;
			break;
		default:
			cmn_err(CE_CONT, "unsupported operation mode 0x%x\n",
			    ic->ic_opmode);
			return (-1);
		}
	} else
		data |= URTW_MSR_LINK_NONE;

	error = urtw_write8_c(sc, URTW_MSR, data);
	drv_usecwait(10000);
fail:
	return (error);
}

static uint16_t
urtw_rate2rtl(int rate)
{
#define	N(a)	(sizeof (a) / sizeof ((a)[0]))
	int i;

	for (i = 0; i < N(urtw_ratetable); i++) {
		if (rate == urtw_ratetable[i].reg)
			return (urtw_ratetable[i].val);
	}
	return (3);
#undef N
}

static uint16_t
urtw_rtl2rate(int rate)
{
#define	N(a)	(sizeof (a) / sizeof ((a)[0]))
	int i;

	for (i = 0; i < N(urtw_ratetable); i++) {
		if (rate == urtw_ratetable[i].val)
			return (urtw_ratetable[i].reg);
	}

	return (0);
#undef N
}

static usbd_status
urtw_set_rate(struct urtw_softc *sc)
{
	int i, basic_rate, min_rr_rate, max_rr_rate;
	uint16_t data;
	usbd_status error;

	basic_rate = urtw_rate2rtl(48);
	min_rr_rate = urtw_rate2rtl(12);
	max_rr_rate = urtw_rate2rtl(48);
	if (error = urtw_write8_c(sc, URTW_RESP_RATE,
	    max_rr_rate << URTW_RESP_MAX_RATE_SHIFT |
	    min_rr_rate << URTW_RESP_MIN_RATE_SHIFT))
		goto fail;

	if (error = urtw_read16_c(sc, URTW_BRSR, &data))
		goto fail;
	data &= ~URTW_BRSR_MBR_8185;

	for (i = 0; i <= basic_rate; i++)
		data |= (1 << i);

	error = urtw_write16_c(sc, URTW_BRSR, data);
fail:
	return (error);
}

static usbd_status
urtw_intr_enable(struct urtw_softc *sc)
{
	usbd_status error;

	error = urtw_write16_c(sc, URTW_INTR_MASK, 0xffff);
	return (error);
}

static usbd_status
urtw_adapter_start(struct urtw_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	usbd_status error;
	int i = 0;

	error = urtw_reset(sc);
	if (error)
		goto fail;

	if (error = urtw_write8_c(sc, 0x85, 0))
		goto fail;
	if (error = urtw_write8_c(sc, URTW_GPIO, 0))
		goto fail;

	/* for led  */
	if (error = urtw_write8_c(sc, 0x85, 4))
		goto fail;
	error = urtw_led_ctl(sc, URTW_LED_CTL_POWER_ON);
	if (error != 0)
		goto fail;

	error = urtw_set_mode(sc, URTW_EPROM_CMD_CONFIG);
	if (error)
		goto fail;
	/* applying MAC address again.  */
	for (i = 0; i < IEEE80211_ADDR_LEN; i++)
		(void) urtw_write8_c(sc, URTW_MAC0 + i,
		    ic->ic_macaddr[i]);
	error = urtw_set_mode(sc, URTW_EPROM_CMD_NORMAL);
	if (error)
		goto fail;

	error = urtw_update_msr(sc, IEEE80211_S_INIT);
	if (error)
		goto fail;

	if (error = urtw_write32_c(sc, URTW_INT_TIMEOUT, 0))
		goto fail;
	if (error = urtw_write8_c(sc, URTW_WPA_CONFIG, 0))
		goto fail;
	if (error = urtw_write8_c(sc, URTW_RATE_FALLBACK, 0x81))
		goto fail;
	error = urtw_set_rate(sc);
	if (error != 0)
		goto fail;

	error = sc->sc_rf_init(sc);
	if (error != 0)
		goto fail;
	if (sc->sc_rf_set_sens != NULL)
		sc->sc_rf_set_sens(sc, sc->sc_sens);

	if (error = urtw_write16_c(sc, 0x5e, 1))
		goto fail;
	if (error = urtw_write16_c(sc, 0xfe, 0x10))
		goto fail;
	if (error = urtw_write8_c(sc, URTW_TALLY_SEL, 0x80))
		goto fail;
	if (error = urtw_write8_c(sc, 0xff, 0x60))
		goto fail;
	if (error = urtw_write16_c(sc, 0x5e, 0))
		goto fail;
	if (error = urtw_write8_c(sc, 0x85, 4))
		goto fail;
	ic->ic_curchan = &ic->ic_sup_channels[1];
	error = urtw_intr_enable(sc);
	if (error != 0)
		goto fail;

fail:
	return (error);
}

static usbd_status
urtw_rx_setconf(struct urtw_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	uint32_t data, a, b;
	usbd_status error;

	if (urtw_read32_c(sc, URTW_RX, &data))
		goto fail;
	data = data &~ URTW_RX_FILTER_MASK;
	data = data | URTW_RX_FILTER_MNG | URTW_RX_FILTER_DATA;
	data = data | URTW_RX_FILTER_BCAST | URTW_RX_FILTER_MCAST;

	if (ic->ic_opmode == IEEE80211_M_MONITOR) {
		data = data | URTW_RX_FILTER_ICVERR;
		data = data | URTW_RX_FILTER_PWR;
	}
	if (sc->sc_crcmon == 1 && ic->ic_opmode == IEEE80211_M_MONITOR)
		data = data | URTW_RX_FILTER_CRCERR;
	data = data | URTW_RX_FILTER_NICMAC;
	data = data | URTW_RX_CHECK_BSSID;
	data = data &~ URTW_RX_FIFO_THRESHOLD_MASK;
	data = data | URTW_RX_FIFO_THRESHOLD_NONE | URTW_RX_AUTORESETPHY;
	data = data &~ URTW_MAX_RX_DMA_MASK;
	a = URTW_MAX_RX_DMA_2048;
	b = 0x80000000;
	data = data | a | b;

	error = urtw_write32_c(sc, URTW_RX, data);
fail:
	return (error);
}

static usbd_status
urtw_rx_enable(struct urtw_softc *sc)
{
	int i;
	usbd_status error;
	uint8_t data;

	sc->rx_queued = 0;
	for (i = 0; i < URTW_RX_DATA_LIST_COUNT; i++) {
		if (urtw_rx_start(sc) != 0) {
			return (USB_FAILURE);
		}
	}

	error = urtw_rx_setconf(sc);
	if (error != 0)
		goto fail;

	if (error = urtw_read8_c(sc, URTW_CMD, &data))
		goto fail;
	error = urtw_write8_c(sc, URTW_CMD, data | URTW_CMD_RX_ENABLE);
fail:
	return (error);
}

static usbd_status
urtw_tx_enable(struct urtw_softc *sc)
{
	uint8_t data8;
	uint32_t data;
	usbd_status error;

	if (error = urtw_read8_c(sc, URTW_CW_CONF, &data8))
		goto fail;
	data8 &= ~(URTW_CW_CONF_PERPACKET_CW | URTW_CW_CONF_PERPACKET_RETRY);
	if (error = urtw_write8_c(sc, URTW_CW_CONF, data8))
		goto fail;

	if (error = urtw_read8_c(sc, URTW_TX_AGC_CTL, &data8))
		goto fail;
	data8 &= ~URTW_TX_AGC_CTL_PERPACKET_GAIN;
	data8 &= ~URTW_TX_AGC_CTL_PERPACKET_ANTSEL;
	data8 &= ~URTW_TX_AGC_CTL_FEEDBACK_ANT;
	if (error = urtw_write8_c(sc, URTW_TX_AGC_CTL, data8))
		goto fail;

	if (error = urtw_read32_c(sc, URTW_TX_CONF, &data))
		goto fail;
	data &= ~URTW_TX_LOOPBACK_MASK;
	data |= URTW_TX_LOOPBACK_NONE;
	data &= ~(URTW_TX_DPRETRY_MASK | URTW_TX_RTSRETRY_MASK);
	data |= sc->sc_tx_retry << URTW_TX_DPRETRY_SHIFT;
	data |= sc->sc_rts_retry << URTW_TX_RTSRETRY_SHIFT;
	data &= ~(URTW_TX_NOCRC | URTW_TX_MXDMA_MASK);
	data |= URTW_TX_MXDMA_2048 | 0x80000000 | URTW_TX_DISCW;
	data &= ~URTW_TX_SWPLCPLEN;
	data |= URTW_TX_NOICV;
	if (error = urtw_write32_c(sc, URTW_TX_CONF, data))
		goto fail;
	if (error = urtw_read8_c(sc, URTW_CMD, &data8))
		goto fail;
	error = urtw_write8_c(sc, URTW_CMD, data8 | URTW_CMD_TX_ENABLE);
fail:
	return (error);
}

static int
urtw_init(void *arg)
{
	struct urtw_softc *sc = arg;
	usbd_status error;

	urtw_stop(sc);
	URTW_LOCK(sc);
	error = urtw_open_pipes(sc);
	if (error != 0)
		goto fail;
	error = urtw_adapter_start(sc);
	if (error != 0)
		goto fail;
	sc->sc_tx_low_queued = 0;
	sc->sc_tx_normal_queued = 0;
	error = urtw_rx_enable(sc);
	if (error != 0)
		goto fail;
	error = urtw_tx_enable(sc);
	if (error != 0)
		goto fail;

	if (error == 0) {
		URTW8187_DBG(URTW_DEBUG_ACTIVE, (sc->sc_dev,
		    CE_CONT, "urtw_init: succesfully done\n"));
		sc->sc_flags |= URTW_FLAG_RUNNING;
		URTW_UNLOCK(sc);
		return (error);
	}

fail:
	URTW_UNLOCK(sc);
	urtw_stop(sc);
	return (error);
}


static usbd_status
urtw_8225_usb_init(struct urtw_softc *sc)
{
	uint8_t data;
	usbd_status error;

	if (error = urtw_write8_c(sc, URTW_RF_PINS_SELECT + 1, 0))
		goto fail;
	if (error = urtw_write8_c(sc, URTW_GPIO, 0))
		goto fail;
	if (error = urtw_read8e(sc, 0x53, &data))
		goto fail;
	if (error = urtw_write8e(sc, 0x53, data | (1 << 7)))
		goto fail;
	if (error = urtw_write8_c(sc, URTW_RF_PINS_SELECT + 1, 4))
		goto fail;
	if (error = urtw_write8_c(sc, URTW_GPIO, 0x20))
		goto fail;
	if (error = urtw_write8_c(sc, URTW_GP_ENABLE, 0))
		goto fail;
	if (error = urtw_write16_c(sc, URTW_RF_PINS_OUTPUT, 0x80))
		goto fail;
	if (error = urtw_write16_c(sc, URTW_RF_PINS_SELECT, 0x80))
		goto fail;
	error = urtw_write16_c(sc, URTW_RF_PINS_ENABLE, 0x80);

	urtw_delay_ms(100);
fail:
	return (error);
}

static usbd_status
urtw_8185_rf_pins_enable(struct urtw_softc *sc)
{
	usbd_status error = 0;

	error = urtw_write16_c(sc, URTW_RF_PINS_ENABLE, 0x1ff7);
	return (error);
}

static usbd_status
urtw_8187_write_phy(struct urtw_softc *sc, uint8_t addr, uint32_t data)
{
	uint32_t phyw;
	usbd_status error;

	phyw = ((data << 8) | (addr | 0x80));
	if (error = urtw_write8_c(sc, 0x7f, ((phyw & 0xff000000) >> 24)))
		goto fail;
	if (error = urtw_write8_c(sc, 0x7e, ((phyw & 0x00ff0000) >> 16)))
		goto fail;
	if (error = urtw_write8_c(sc, 0x7d, ((phyw & 0x0000ff00) >> 8)))
		goto fail;
	error = urtw_write8_c(sc, 0x7c, ((phyw & 0x000000ff)));
	urtw_delay_ms(1);
fail:
	return (error);
}

static usbd_status
urtw_8187_write_phy_ofdm_c(struct urtw_softc *sc, uint8_t addr, uint32_t data)
{
	data = data & 0xff;
	return (urtw_8187_write_phy(sc, addr, data));
}

static usbd_status
urtw_8187_write_phy_cck_c(struct urtw_softc *sc, uint8_t addr, uint32_t data)
{
	data = data & 0xff;
	return (urtw_8187_write_phy(sc, addr, (data | 0x10000)));
}

static usbd_status
urtw_8225_setgain(struct urtw_softc *sc, int16_t gain)
{
	usbd_status error;

	if (error = urtw_8187_write_phy_ofdm_c(sc, 0x0d,
	    urtw_8225_gain[gain * 4]))
		goto fail;
	if (error = urtw_8187_write_phy_ofdm_c(sc, 0x1b,
	    urtw_8225_gain[gain * 4 + 2]))
		goto fail;
	if (error = urtw_8187_write_phy_ofdm_c(sc, 0x1d,
	    urtw_8225_gain[gain * 4 + 3]))
		goto fail;
	error = urtw_8187_write_phy_ofdm_c(sc, 0x23,
	    urtw_8225_gain[gain * 4 + 1]);
fail:
	return (error);
}

static usbd_status
urtw_8225_set_txpwrlvl(struct urtw_softc *sc, int chan)
{
	int i, idx, set;
	uint8_t *cck_pwltable;
	uint8_t cck_pwrlvl_max, ofdm_pwrlvl_min, ofdm_pwrlvl_max;
	uint8_t cck_pwrlvl = sc->sc_txpwr_cck[chan] & 0xff;
	uint8_t ofdm_pwrlvl = sc->sc_txpwr_ofdm[chan] & 0xff;
	usbd_status error;

	cck_pwrlvl_max = 11;
	ofdm_pwrlvl_max = 25;	/* 12 -> 25  */
	ofdm_pwrlvl_min = 10;

	/* CCK power setting */
	cck_pwrlvl = (cck_pwrlvl > cck_pwrlvl_max) ?
	    cck_pwrlvl_max : cck_pwrlvl;
	idx = cck_pwrlvl % 6;
	set = cck_pwrlvl / 6;
	cck_pwltable = (chan == 14) ? urtw_8225_txpwr_cck_ch14 :
	    urtw_8225_txpwr_cck;

	if (error = urtw_write8_c(sc, URTW_TX_GAIN_CCK,
	    urtw_8225_tx_gain_cck_ofdm[set] >> 1))
		goto fail;
	for (i = 0; i < 8; i++) {
		if (error = urtw_8187_write_phy_cck_c(sc, 0x44 + i,
		    cck_pwltable[idx * 8 + i]))
			goto fail;
	}
	urtw_delay_ms(1);
	/* OFDM power setting */
	ofdm_pwrlvl = (ofdm_pwrlvl > (ofdm_pwrlvl_max - ofdm_pwrlvl_min)) ?
	    ofdm_pwrlvl_max : ofdm_pwrlvl + ofdm_pwrlvl_min;
	ofdm_pwrlvl = (ofdm_pwrlvl > 35) ? 35 : ofdm_pwrlvl;
	idx = ofdm_pwrlvl % 6;
	set = ofdm_pwrlvl / 6;

	error = urtw_8185_set_anaparam2(sc, URTW_8225_ANAPARAM2_ON);
	if (error)
		goto fail;
	if (error = urtw_8187_write_phy_ofdm_c(sc, 2, 0x42))
		goto fail;
	if (error = urtw_8187_write_phy_ofdm_c(sc, 6, 0))
		goto fail;
	if (error = urtw_8187_write_phy_ofdm_c(sc, 8, 0))
		goto fail;

	if (error = urtw_write8_c(sc, URTW_TX_GAIN_OFDM,
	    urtw_8225_tx_gain_cck_ofdm[set] >> 1))
		goto fail;
	if (error = urtw_8187_write_phy_ofdm_c(sc, 0x5,
	    urtw_8225_txpwr_ofdm[idx]))
		goto fail;
	error = urtw_8187_write_phy_ofdm_c(sc, 0x7,
	    urtw_8225_txpwr_ofdm[idx]);
	urtw_delay_ms(1);
fail:
	return (error);
}

static usbd_status
urtw_8185_tx_antenna(struct urtw_softc *sc, uint8_t ant)
{
	usbd_status error;

	error = urtw_write8_c(sc, URTW_TX_ANTENNA, ant);
	urtw_delay_ms(1);
	return (error);
}

static usbd_status
urtw_8225_rf_init(struct urtw_softc *sc)
{
#define	N(a)	(sizeof (a) / sizeof ((a)[0]))
	int i;
	uint16_t data;
	usbd_status error;

	error = urtw_8180_set_anaparam(sc, URTW_8225_ANAPARAM_ON);
	if (error)
		goto fail;

	if (error = urtw_8225_usb_init(sc))
		goto fail;
	if (error = urtw_write32_c(sc, URTW_RF_TIMING, 0x000a8008))
		goto fail;
	if (error = urtw_read16_c(sc, URTW_BRSR, &data))
		goto fail;
	if (error = urtw_write16_c(sc, URTW_BRSR, 0xffff))
		goto fail;
	if (error = urtw_write32_c(sc, URTW_RF_PARA, 0x100044))
		goto fail;

	if (error = urtw_set_mode(sc, URTW_EPROM_CMD_CONFIG))
		goto fail;
	if (error = urtw_write8_c(sc, URTW_CONFIG3, 0x44))
		goto fail;
	if (error = urtw_set_mode(sc, URTW_EPROM_CMD_NORMAL))
		goto fail;
	if (error = urtw_8185_rf_pins_enable(sc))
		goto fail;
	urtw_delay_ms(100);

	for (i = 0; i < N(urtw_8225_rf_part1); i++) {
		if (error = urtw_8225_write_c(sc, urtw_8225_rf_part1[i].reg,
		    urtw_8225_rf_part1[i].val))
			goto fail;
		urtw_delay_ms(1);
	}
	urtw_delay_ms(50);
	if (error = urtw_8225_write_c(sc, 0x2, 0xc4d))
		goto fail;
	urtw_delay_ms(50);
	if (error = urtw_8225_write_c(sc, 0x2, 0x44d))
		goto fail;
	urtw_delay_ms(50);
	if (error = urtw_8225_write_c(sc, 0x0, 0x127))
		goto fail;

	for (i = 0; i < 95; i++) {
		if (error = urtw_8225_write_c(sc, 0x1, (uint8_t)(i + 1)))
			goto fail;
		if (error = urtw_8225_write_c(sc, 0x2, urtw_8225_rxgain[i]))
			goto fail;
	}

	if (error = urtw_8225_write_c(sc, 0x0, 0x27))
		goto fail;
	if (error = urtw_8225_write_c(sc, 0x0, 0x22f))
		goto fail;

	for (i = 0; i < 128; i++) {
		if (error = urtw_8187_write_phy_ofdm_c(sc, 0xb,
		    urtw_8225_agc[i]))
			goto fail;
		urtw_delay_ms(1);
		if (error = urtw_8187_write_phy_ofdm_c(sc, 0xa,
		    (uint8_t)i + 0x80))
			goto fail;
		urtw_delay_ms(1);
	}

	for (i = 0; i < N(urtw_8225_rf_part2); i++) {
		if (error = urtw_8187_write_phy_ofdm_c(sc,
		    urtw_8225_rf_part2[i].reg,
		    urtw_8225_rf_part2[i].val))
			goto fail;
		urtw_delay_ms(1);
	}
	error = urtw_8225_setgain(sc, 4);
	if (error)
		goto fail;

	for (i = 0; i < N(urtw_8225_rf_part3); i++) {
		if (error = urtw_8187_write_phy_cck_c(sc,
		    urtw_8225_rf_part3[i].reg,
		    urtw_8225_rf_part3[i].val))
			goto fail;
		urtw_delay_ms(1);
	}

	if (error = urtw_write8_c(sc, 0x5b, 0x0d))
		goto fail;
	if (error = urtw_8225_set_txpwrlvl(sc, 1))
		goto fail;
	if (error = urtw_8187_write_phy_cck_c(sc, 0x10, 0x9b))
		goto fail;
	urtw_delay_ms(1);
	if (error = urtw_8187_write_phy_ofdm_c(sc, 0x26, 0x90))
		goto fail;
	urtw_delay_ms(1);

	/* TX ant A, 0x0 for B */
	if (error = urtw_8185_tx_antenna(sc, 0x3))
		goto fail;
	if (error = urtw_write32_c(sc, 0x94, 0x3dc00002))
		goto fail;

	error = urtw_8225_rf_set_chan(sc, 1);
fail:
	return (error);
#undef N
}

static usbd_status
urtw_8225_rf_set_chan(struct urtw_softc *sc, int chan)
{
#define	IEEE80211_CHAN_G	\
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_DYN)
#define	IEEE80211_IS_CHAN_G(_c)		\
	(((_c)->ich_flags & IEEE80211_CHAN_G) == IEEE80211_CHAN_G)

	struct ieee80211com *ic = &sc->sc_ic;
	struct ieee80211_channel *c = ic->ic_curchan;
	short gset = (IEEE80211_IS_CHAN_G(c)) ? 1 : 0;
	usbd_status error;

	if (error = urtw_8225_set_txpwrlvl(sc, chan))
		goto fail;
	if (urtw_8225_write_c(sc, 0x7, urtw_8225_channel[chan]))
		goto fail;
	urtw_delay_ms(10);

	if (error = urtw_write8_c(sc, URTW_SIFS, 0x22))
		goto fail;

	if (ic->ic_state == IEEE80211_S_ASSOC &&
	    ic->ic_flags & IEEE80211_F_SHSLOT)
		if (error = urtw_write8_c(sc, URTW_SLOT, 0x9))
			goto fail;
	else
		if (error = urtw_write8_c(sc, URTW_SLOT, 0x14))
			goto fail;
	if (gset) {
		/* for G */
		if (error = urtw_write8_c(sc, URTW_DIFS, 0x14))
			goto fail;
		if (error = urtw_write8_c(sc, URTW_EIFS, 0x5b - 0x14))
			goto fail;
		error = urtw_write8_c(sc, URTW_CW_VAL, 0x73);
	} else {
		/* for B */
		if (error = urtw_write8_c(sc, URTW_DIFS, 0x24))
			goto fail;
		if (error = urtw_write8_c(sc, URTW_EIFS, 0x5b - 0x24))
			goto fail;
		error = urtw_write8_c(sc, URTW_CW_VAL, 0xa5);
	}

fail:
	return (error);
}

static usbd_status
urtw_8225_rf_set_sens(struct urtw_softc *sc, int sens)
{
	usbd_status error;

	if (sens < 0 || sens > 6)
		return (-1);

	if (sens > 4)
		if (error = urtw_8225_write_c(sc, 0x0c, 0x850))
			goto fail;
	else
		if (error = urtw_8225_write_c(sc, 0x0c, 0x50))
			goto fail;

	sens = 6 - sens;
	if (error = urtw_8225_setgain(sc, sens))
		goto fail;
	error = urtw_8187_write_phy_cck_c(sc, 0x41, urtw_8225_threshold[sens]);
fail:
	return (error);
}

static void
urtw_stop(struct urtw_softc *sc)
{
	URTW_LOCK(sc);
	sc->sc_flags &= ~URTW_FLAG_RUNNING;
	URTW_UNLOCK(sc);
	urtw_close_pipes(sc);
}

static int
urtw_isbmode(uint16_t rate)
{

	rate = urtw_rtl2rate(rate);

	return ((rate <= 22 && rate != 12 && rate != 18)?(1) : (0));
}

/* ARGSUSED */
static void
urtw_rxeof(usb_pipe_handle_t pipe, usb_bulk_req_t *req)
{
	struct urtw_softc *sc = (struct urtw_softc *)req->bulk_client_private;
	struct ieee80211com *ic = &sc->sc_ic;
	int actlen, len,  flen,  rssi;
	uint8_t *desc, rate;
	struct ieee80211_frame *wh;
	struct ieee80211_node *ni = 0;
	mblk_t *mp = 0;
	uint8_t *rxbuf;

	mp = req->bulk_data;
	req->bulk_data = NULL;
	if (req->bulk_completion_reason != USB_CR_OK ||
	    mp == NULL) {
		sc->sc_rx_err++;
		URTW8187_DBG(URTW_DEBUG_RX_PROC, (sc->sc_dev, CE_CONT,
		    "urtw_rxeof failed! %d\n",
		    req->bulk_completion_reason));
		req->bulk_data = mp;
		goto fail;
	}

	actlen = MBLKL(mp);
	rxbuf = (uint8_t *)mp->b_rptr;

	/* 4 dword and 4 byte CRC  */
	len = actlen - (4 * 4);
	desc = rxbuf + len;
	flen = ((desc[1] & 0x0f) << 8) + (desc[0] & 0xff);
	if (flen > actlen) {
		cmn_err(CE_CONT, "urtw_rxeof: impossible: flen %d, actlen %d\n",
		    flen, actlen);
		sc->sc_rx_err++;
		req->bulk_data = mp;
		goto fail;
	}

	rate = (desc[2] & 0xf0) >> 4;
	URTW8187_DBG(URTW_DEBUG_RX_PROC, (sc->sc_dev, CE_CONT,
	    "urtw_rxeof: rate is %u\n", rate));
	/* XXX correct?  */
	rssi = (desc[6] & 0xfe) >> 1;
	if (!urtw_isbmode(rate)) {
		rssi = (rssi > 90) ? 90 : ((rssi < 25) ? 25 : rssi);
		rssi = ((90 - rssi) * 100) / 65;
	} else {
		rssi = (rssi > 90) ? 95 : ((rssi < 30) ? 30 : rssi);
		rssi = ((95 - rssi) * 100) / 65;
	}

	mp->b_wptr = mp->b_rptr + flen - 4;

	wh = (struct ieee80211_frame *)mp->b_rptr;
	if ((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK)
	    == IEEE80211_FC0_TYPE_DATA) {
		sc->sc_currate = (rate > 0) ? rate : sc->sc_currate;
		URTW8187_DBG(URTW_DEBUG_RX_PROC, (sc->sc_dev, CE_CONT,
		    "urtw_rxeof: update sc_currate to %u\n",
		    sc->sc_currate));
	}
	ni = ieee80211_find_rxnode(ic, wh);

	/* send the frame to the 802.11 layer */
	(void) ieee80211_input(ic, mp, ni, rssi, 0);

	/* node is no longer needed */
	ieee80211_free_node(ni);
fail:
	mutex_enter(&sc->rx_lock);
	sc->rx_queued--;
	mutex_exit(&sc->rx_lock);
	usb_free_bulk_req(req);
	if (URTW_IS_RUNNING(sc) && !URTW_IS_SUSPENDING(sc))
		(void) urtw_rx_start(sc);
}

static usbd_status
urtw_8225v2_setgain(struct urtw_softc *sc, int16_t gain)
{
	uint8_t *gainp;
	usbd_status error;

	/* XXX for A?  */
	gainp = urtw_8225v2_gain_bg;
	if (error = urtw_8187_write_phy_ofdm_c(sc, 0x0d, gainp[gain * 3]))
		goto fail;
	urtw_delay_ms(1);
	if (error = urtw_8187_write_phy_ofdm_c(sc, 0x1b, gainp[gain * 3 + 1]))
	urtw_delay_ms(1);
	if (error = urtw_8187_write_phy_ofdm_c(sc, 0x1d, gainp[gain * 3 + 2]))
		goto fail;
	urtw_delay_ms(1);
	if (error = urtw_8187_write_phy_ofdm_c(sc, 0x21, 0x17))
		goto fail;
	urtw_delay_ms(1);
fail:
	return (error);
}

static usbd_status
urtw_8225v2_set_txpwrlvl(struct urtw_softc *sc, int chan)
{
	int i;
	uint8_t *cck_pwrtable;
	uint8_t cck_pwrlvl_max = 15, ofdm_pwrlvl_max = 25, ofdm_pwrlvl_min = 10;
	uint8_t cck_pwrlvl = sc->sc_txpwr_cck[chan] & 0xff;
	uint8_t ofdm_pwrlvl = sc->sc_txpwr_ofdm[chan] & 0xff;
	usbd_status error;

	/* CCK power setting */
	cck_pwrlvl = (cck_pwrlvl > cck_pwrlvl_max) ?
	    cck_pwrlvl_max : cck_pwrlvl;
	cck_pwrlvl += sc->sc_txpwr_cck_base;
	cck_pwrlvl = (cck_pwrlvl > 35) ? 35 : cck_pwrlvl;
	cck_pwrtable = (chan == 14) ? urtw_8225v2_txpwr_cck_ch14 :
	    urtw_8225v2_txpwr_cck;

	for (i = 0; i < 8; i++) {
		if (error = urtw_8187_write_phy_cck_c(sc, 0x44 + i,
		    cck_pwrtable[i]))
			goto fail;
	}
	if (error = urtw_write8_c(sc, URTW_TX_GAIN_CCK,
	    urtw_8225v2_tx_gain_cck_ofdm[cck_pwrlvl]))
		goto fail;
	urtw_delay_ms(1);

	/* OFDM power setting */
	ofdm_pwrlvl = (ofdm_pwrlvl > (ofdm_pwrlvl_max - ofdm_pwrlvl_min)) ?
	    ofdm_pwrlvl_max : ofdm_pwrlvl + ofdm_pwrlvl_min;
	ofdm_pwrlvl += sc->sc_txpwr_ofdm_base;
	ofdm_pwrlvl = (ofdm_pwrlvl > 35) ? 35 : ofdm_pwrlvl;

	error = urtw_8185_set_anaparam2(sc, URTW_8225_ANAPARAM2_ON);
	if (error)
		goto fail;

	if (error = urtw_8187_write_phy_ofdm_c(sc, 2, 0x42))
		goto fail;
	if (error = urtw_8187_write_phy_ofdm_c(sc, 5, 0x0))
		goto fail;
	if (error = urtw_8187_write_phy_ofdm_c(sc, 6, 0x40))
		goto fail;
	if (error = urtw_8187_write_phy_ofdm_c(sc, 7, 0x0))
		goto fail;
	if (error = urtw_8187_write_phy_ofdm_c(sc, 8, 0x40))
		goto fail;

	error = urtw_write8_c(sc, URTW_TX_GAIN_OFDM,
	    urtw_8225v2_tx_gain_cck_ofdm[ofdm_pwrlvl]);
	urtw_delay_ms(1);
fail:
	return (error);
}

static usbd_status
urtw_8225v2_rf_init(struct urtw_softc *sc)
{
#define	N(a)	(sizeof (a)/ sizeof ((a)[0]))
	int i;
	uint16_t data;
	uint32_t data32;
	usbd_status error;

	if (error = urtw_8180_set_anaparam(sc, URTW_8225_ANAPARAM_ON))
		goto fail;
	if (error = urtw_8225_usb_init(sc))
		goto fail;
	if (error = urtw_write32_c(sc, URTW_RF_TIMING, 0x000a8008))
		goto fail;
	if (error = urtw_read16_c(sc, URTW_BRSR, &data))
		goto fail;
	if (error = urtw_write16_c(sc, URTW_BRSR, 0xffff))
		goto fail;
	if (error = urtw_write32_c(sc, URTW_RF_PARA, 0x100044))
		goto fail;
	if (error = urtw_set_mode(sc, URTW_EPROM_CMD_CONFIG))
		goto fail;
	if (error = urtw_write8_c(sc, URTW_CONFIG3, 0x44))
		goto fail;
	if (error = urtw_set_mode(sc, URTW_EPROM_CMD_NORMAL))
		goto fail;
	if (error = urtw_8185_rf_pins_enable(sc))
		goto fail;

	urtw_delay_ms(500);

	for (i = 0; i < N(urtw_8225v2_rf_part1); i++) {
		if (error = urtw_8225_write_c(sc, urtw_8225v2_rf_part1[i].reg,
		    urtw_8225v2_rf_part1[i].val))
			goto fail;
		urtw_delay_ms(1);
	}
	urtw_delay_ms(100);

	if (error = urtw_8225_write_c(sc, 0x0, 0x1b7))
		goto fail;

	for (i = 0; i < 95; i++) {
		if (error = urtw_8225_write_c(sc, 0x1, (uint8_t)(i + 1)))
			goto fail;
		urtw_delay_ms(1);
		if (error = urtw_8225_write_c(sc, 0x2, urtw_8225v2_rxgain[i]))
			goto fail;
		urtw_delay_ms(1);
	}

	if (error = urtw_8225_write_c(sc, 0x3, 0x2))
		goto fail;
	urtw_delay_ms(1);
	if (error = urtw_8225_write_c(sc, 0x5, 0x4))
		goto fail;
	urtw_delay_ms(1);
	if (error = urtw_8225_write_c(sc, 0x0, 0xb7))
		goto fail;
	urtw_delay_ms(1);
	if (error = urtw_8225_write_c(sc, 0x2, 0xc4d))
		goto fail;
	urtw_delay_ms(100);
	if (error = urtw_8225_write_c(sc, 0x2, 0x44d))
		goto fail;
	urtw_delay_ms(100);

	if (error = urtw_8225_read(sc, 0x6, &data32))
		goto fail;
	if (data32 != 0xe6) {
		error = (-1);
		cmn_err(CE_WARN, "expect 0xe6!! (0x%x)\n", data32);
		goto fail;
	}
	if (!(data32 & 0x80)) {
		if (error = urtw_8225_write_c(sc, 0x02, 0x0c4d))
			goto fail;
		urtw_delay_ms(200);
		if (error = urtw_8225_write_c(sc, 0x02, 0x044d))
			goto fail;
		urtw_delay_ms(100);
		if (error = urtw_8225_read(sc, 0x6, &data32))
			goto fail;
		if (!(data32 & 0x80))
			cmn_err(CE_CONT, "RF calibration failed\n");
	}
	urtw_delay_ms(200);

	if (error = urtw_8225_write_c(sc, 0x0, 0x2bf))
		goto fail;
	for (i = 0; i < 128; i++) {
		if (error = urtw_8187_write_phy_ofdm_c(sc, 0xb,
		    urtw_8225_agc[i]))
			goto fail;
		urtw_delay_ms(1);
		if (error = urtw_8187_write_phy_ofdm_c(sc, 0xa,
		    (uint8_t)i + 0x80))
			goto fail;
		urtw_delay_ms(1);
	}
	urtw_delay_ms(1);

	for (i = 0; i < N(urtw_8225v2_rf_part2); i++) {
		if (error = urtw_8187_write_phy_ofdm_c(sc,
		    urtw_8225v2_rf_part2[i].reg,
		    urtw_8225v2_rf_part2[i].val))
			goto fail;
		urtw_delay_ms(1);
	}
	error = urtw_8225v2_setgain(sc, 4);
	if (error)
		goto fail;

	for (i = 0; i < N(urtw_8225v2_rf_part3); i++) {
		if (error = urtw_8187_write_phy_cck_c(sc,
		    urtw_8225v2_rf_part3[i].reg,
		    urtw_8225v2_rf_part3[i].val))
			goto fail;
		urtw_delay_ms(1);
	}

	if (error = urtw_write8_c(sc, 0x5b, 0x0d))
		goto fail;
	if (error = urtw_8225v2_set_txpwrlvl(sc, 1))
		goto fail;
	if (error = urtw_8187_write_phy_cck_c(sc, 0x10, 0x9b))
		goto fail;
	urtw_delay_ms(1);
	if (error = urtw_8187_write_phy_ofdm_c(sc, 0x26, 0x90))
		goto fail;
	urtw_delay_ms(1);

	/* TX ant A, 0x0 for B */
	if (error = urtw_8185_tx_antenna(sc, 0x3))
		goto fail;
	if (error = urtw_write32_c(sc, 0x94, 0x3dc00002))
		goto fail;

	error = urtw_8225_rf_set_chan(sc, 1);
fail:
	return (error);
#undef N
}

static usbd_status
urtw_8225v2_rf_set_chan(struct urtw_softc *sc, int chan)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct ieee80211_channel *c = ic->ic_curchan;
	short gset = (IEEE80211_IS_CHAN_G(c)) ? 1 : 0;
	usbd_status error;

	if (error = urtw_8225v2_set_txpwrlvl(sc, chan))
		goto fail;

	if (error = urtw_8225_write_c(sc, 0x7, urtw_8225_channel[chan]))
		goto fail;

	urtw_delay_ms(10);

	if (error = urtw_write8_c(sc, URTW_SIFS, 0x22))
		goto fail;

	if (ic->ic_state == IEEE80211_S_ASSOC &&
	    ic->ic_flags & IEEE80211_F_SHSLOT) {
		if (error = urtw_write8_c(sc, URTW_SLOT, 0x9))
			goto fail;
	} else
		if (error = urtw_write8_c(sc, URTW_SLOT, 0x14))
			goto fail;
	if (gset) {
		/* for G */
		if (error = urtw_write8_c(sc, URTW_DIFS, 0x14))
			goto fail;
		if (error = urtw_write8_c(sc, URTW_EIFS, 0x5b - 0x14))
			goto fail;
		if (error = urtw_write8_c(sc, URTW_CW_VAL, 0x73))
			goto fail;
	} else {
		/* for B */
		if (error = urtw_write8_c(sc, URTW_DIFS, 0x24))
			goto fail;
		if (error = urtw_write8_c(sc, URTW_EIFS, 0x5b - 0x24))
			goto fail;
		if (error = urtw_write8_c(sc, URTW_CW_VAL, 0xa5))
			goto fail;
	}

fail:
	return (error);
}

static int
urtw_set_channel(struct urtw_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	uint32_t data;
	usbd_status error;

	if (error = urtw_read32_c(sc, URTW_TX_CONF, &data))
		goto fail;
	data &= ~URTW_TX_LOOPBACK_MASK;
	if (error = urtw_write32_c(sc, URTW_TX_CONF,
	    data | URTW_TX_LOOPBACK_MAC))
		goto fail;
	error = sc->sc_rf_set_chan(sc,
	    ieee80211_chan2ieee(ic, ic->ic_curchan));
	if (error)
		goto fail;
	urtw_delay_ms(10);
	error = urtw_write32_c(sc, URTW_TX_CONF, data | URTW_TX_LOOPBACK_NONE);
fail:
	return (error);
}

/* ARGSUSED */
static void
urtw_txeof_low(usb_pipe_handle_t pipe, usb_bulk_req_t *req)
{
	struct urtw_softc *sc = (struct urtw_softc *)req->bulk_client_private;
	struct ieee80211com *ic = &sc->sc_ic;

	URTW8187_DBG(URTW_DEBUG_TX_PROC, (sc->sc_dev, CE_CONT,
	    "urtw_txeof_low(): cr:%s(%d), flags:0x%x, tx_queued:%d",
	    usb_str_cr(req->bulk_completion_reason),
	    req->bulk_completion_reason,
	    req->bulk_cb_flags,
	    sc->sc_tx_low_queued));
	mutex_enter(&sc->tx_lock);
	if (req->bulk_completion_reason != USB_CR_OK) {
		ic->ic_stats.is_tx_failed++;
		goto fail;
	}

	if (sc->sc_need_sched) {
		sc->sc_need_sched = 0;
		mac_tx_update(ic->ic_mach);
	}
fail:
	sc->sc_tx_low_queued--;
	mutex_exit(&sc->tx_lock);
	usb_free_bulk_req(req);
}

/* ARGSUSED */
static void
urtw_txeof_normal(usb_pipe_handle_t pipe, usb_bulk_req_t *req)
{
	struct urtw_softc *sc = (struct urtw_softc *)req->bulk_client_private;
	struct ieee80211com *ic = &sc->sc_ic;

	URTW8187_DBG(URTW_DEBUG_ACTIVE, (sc->sc_dev, CE_CONT,
	    "urtw_txeof_normal(): cr:%s(%d), flags:0x%x, tx_queued:%d",
	    usb_str_cr(req->bulk_completion_reason),
	    req->bulk_completion_reason,
	    req->bulk_cb_flags,
	    sc->sc_tx_normal_queued));

	mutex_enter(&sc->tx_lock);
	if (req->bulk_completion_reason != USB_CR_OK) {
		ic->ic_stats.is_tx_failed++;
		goto fail;
	}

	if (sc->sc_need_sched) {
		sc->sc_need_sched = 0;
		mac_tx_update(ic->ic_mach);
	}
fail:
	sc->sc_tx_normal_queued--;
	mutex_exit(&sc->tx_lock);
	usb_free_bulk_req(req);
}


static int
urtw_get_rate(struct ieee80211com *ic)
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

static int
urtw_send(ieee80211com_t *ic, mblk_t *mp, uint8_t type)
{
	struct urtw_softc *sc = (struct urtw_softc *)ic;
	struct ieee80211_frame *wh;
	struct ieee80211_key *k;
	struct ieee80211_node *ni = NULL;
	uint8_t *buf;
	mblk_t *m = 0, *m0, *mtx;
	int off, mblen, xferlen, err = 0, priority = 0;

	mutex_enter(&sc->tx_lock);
	priority = (type == IEEE80211_FC0_TYPE_DATA) ?
	    LOW_PRIORITY_PIPE: NORMAL_PRIORITY_PIPE;

	if (URTW_IS_SUSPENDING(sc)) {
		err = 0;
		goto failed;
	}

	if (((priority)? sc->sc_tx_normal_queued : sc->sc_tx_low_queued) >=
	    URTW_TX_DATA_LIST_COUNT) {
		URTW8187_DBG(URTW_DEBUG_XMIT, (sc->sc_dev, CE_CONT,
		    "urtw_send(): no TX buffer!\n"));
		sc->sc_tx_nobuf++;
		err = ENOMEM;
		goto failed;
	}

	m = allocb(URTW_TXBUF_SIZE, BPRI_MED);
	if (m == NULL) {
		cmn_err(CE_WARN, "urtw_send(): can't alloc mblk.\n");
		err = ENOMEM;
		goto failed;
	}

	for (off = 0, m0 = mp; m0 != NULL; m0 = m0->b_cont) {
		mblen = (uintptr_t)m0->b_wptr - (uintptr_t)m0->b_rptr;
		(void) bcopy(m0->b_rptr, m->b_rptr + off, mblen);
		off += mblen;
	}
	m->b_wptr += off;

	wh = (struct ieee80211_frame *)m->b_rptr;

	ni = ieee80211_find_txnode(ic, wh->i_addr1);
	if (ni == NULL) {
		err = ENXIO;
		ic->ic_stats.is_tx_failed++;
		goto failed;
	}

	if ((type & IEEE80211_FC0_TYPE_MASK) ==
	    IEEE80211_FC0_TYPE_DATA) {
		(void) ieee80211_encap(ic, m, ni);
	}

	if (wh->i_fc[1] & IEEE80211_FC1_WEP) {
		k = ieee80211_crypto_encap(ic, m);
		if (k == NULL) {
			ic->ic_stats.is_tx_failed++;
			err = ENXIO;
			goto failed;
		}
		/* packet header may have moved, reset our local pointer */
		wh = (struct ieee80211_frame *)m->b_rptr;
	}

	xferlen = MBLKL(m) + 4 * 3;
	if ((0 == xferlen % 64) || (0 == xferlen % 512))
		xferlen += 1;

	mtx = allocb(xferlen, BPRI_MED);
	buf = mtx->b_rptr;

	bzero(buf, xferlen);
	buf[0] = MBLKL(m) & 0xff;
	buf[1] = (MBLKL(m) & 0x0f00) >> 8;
	buf[1] |= (1 << 7);

	/* XXX sc_preamble_mode is always 2.  */
	if (wh->i_fc[1] & IEEE80211_FC1_MORE_FRAG)
		buf[2] |= (1 << 1);
	/* RTS rate - 10 means we use a basic rate.  */
	buf[2] |= (urtw_rate2rtl(2) << 3);
	/*
	 * XXX currently TX rate control depends on the rate value of
	 * RX descriptor because I don't know how to we can control TX rate
	 * in more smart way.  Please fix me you find a thing.
	 */
	if ((type & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_DATA) {
		buf[3] = urtw_rate2rtl(MAX(2, urtw_get_rate(ic)));
	} else
		buf[3] = sc->sc_currate;
	buf[8] = 3;		/* CW minimum  */
	buf[8] |= (7 << 4);	/* CW maximum  */
	buf[9] |= 11;		/* retry limitation  */

	bcopy(m->b_rptr, &buf[12], MBLKL(m));

	(void) urtw_led_ctl(sc, URTW_LED_CTL_TX);
	mtx->b_wptr = mtx->b_rptr + xferlen;

	URTW8187_DBG(URTW_DEBUG_XMIT, (sc->sc_dev, CE_CONT,
	    "sending data frame len=%u rate=%u xfer len=%u\n",
	    MBLKL(m), buf[3], xferlen));

	err = urtw_tx_start(sc, mtx, priority);
	if (!err) {
		ic->ic_stats.is_tx_frags++;
		ic->ic_stats.is_tx_bytes += MBLKL(m);
	} else {
		ic->ic_stats.is_tx_failed++;
	}

failed:
	if (ni != NULL)
		ieee80211_free_node(ni);

	if ((mp) &&
	    ((type & IEEE80211_FC0_TYPE_MASK) != IEEE80211_FC0_TYPE_DATA ||
	    err == DDI_SUCCESS)) {
		freemsg(mp);
	}
	if (m) freemsg(m);

	if (((type & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_DATA) &&
	    (err != 0)) {
		sc->sc_need_sched = 1;
	}
	mutex_exit(&sc->tx_lock);
	return (err);
}

static void
urtw_next_scan(void *arg)
{
	ieee80211com_t *ic = arg;
	struct urtw_softc *sc = (struct urtw_softc *)arg;

	if (URTW_IS_NOT_RUNNING(sc)) {
		sc->sc_scan_id = 0;
		return;
	}

	if (ic->ic_state == IEEE80211_S_SCAN) {
		(void) ieee80211_next_scan(ic);
	}
	sc->sc_scan_id = 0;
}

static void
urtw_led_launch(void *arg)
{
	struct urtw_softc *sc = arg;
	ieee80211com_t *ic = &sc->sc_ic;
	int error = 0;

	URTW_LEDLOCK(sc);
	if ((sc->sc_strategy != URTW_SW_LED_MODE0) ||
	    URTW_IS_NOT_RUNNING(sc) ||
	    URTW_IS_SUSPENDING(sc)) {
		URTW8187_DBG(URTW_DEBUG_LED, (sc->sc_dev, CE_CONT,
		    "failed process LED strategy 0x%x, run?%d",
		    sc->sc_strategy,
		    sc->sc_flags));
		sc->sc_led_ch = 0;
		sc->sc_gpio_ledinprogress = 0;
		URTW_LEDUNLOCK(sc);
		return;
	}
	error = urtw_led_blink(sc);
	if (error) {
		sc->sc_led_ch = timeout(urtw_led_launch, (void *)sc,
		    drv_usectohz((ic->ic_state == IEEE80211_S_RUN) ?
		    URTW_LED_LINKON_BLINK: URTW_LED_LINKOFF_BLINK));
		URTW8187_DBG(URTW_DEBUG_LED, (sc->sc_dev, CE_CONT,
		    "try again led launch"));
	} else {
		sc->sc_led_ch = 0;
		URTW8187_DBG(URTW_DEBUG_LED, (sc->sc_dev, CE_CONT,
		    "exit led launch"));
	}
	URTW_LEDUNLOCK(sc);
}

static int
urtw_newstate(struct ieee80211com *ic, enum ieee80211_state nstate, int arg)
{
	struct urtw_softc *sc = (struct urtw_softc *)ic;
	struct ieee80211_node *ni;
	int error = 0;

	if (sc->sc_scan_id != 0) {
		(void) untimeout(sc->sc_scan_id);
		sc->sc_scan_id = 0;
	}
	URTW_LOCK(sc);
	switch (nstate) {
	case IEEE80211_S_INIT:
		URTW8187_DBG(URTW_DEBUG_STATE,
		    (sc->sc_dev, CE_CONT, "-> IEEE80211_S_INIT...arg(%d)\n",
		    arg));
		(void) urtw_update_msr(sc, nstate);
		(void) urtw_led_off(sc, URTW_LED_GPIO);
		break;

	case IEEE80211_S_SCAN:
		URTW8187_DBG(URTW_DEBUG_STATE,
		    (sc->sc_dev, CE_CONT,
		    "-> IEEE80211_S_SCAN...arg(%d)...[%d]\n",
		    arg, ieee80211_chan2ieee(ic, ic->ic_curchan)));
		error = urtw_set_channel(sc);
		if (error) {
			URTW8187_DBG(URTW_DEBUG_STATE,
			    (sc->sc_dev, CE_CONT, "scan setchan failed"));
			break;
		}
		sc->sc_scan_id = timeout(urtw_next_scan, (void *)sc,
		    drv_usectohz(sc->dwelltime * 1000));
		break;

	case IEEE80211_S_AUTH:
		URTW8187_DBG(URTW_DEBUG_STATE, (sc->sc_dev, CE_CONT,
		    "-> IEEE80211_S_AUTH ...arg(%d)\n", arg));
		error = urtw_set_channel(sc);
		if (error) {
			URTW8187_DBG(URTW_DEBUG_STATE,
			    (sc->sc_dev,  CE_CONT, "auth setchan failed"));
		}
		break;

	case IEEE80211_S_ASSOC:
		URTW8187_DBG(URTW_DEBUG_STATE, (sc->sc_dev, CE_CONT,
		    "-> IEEE80211_S_ASSOC ...arg(%d)\n", arg));
		error = urtw_set_channel(sc);
		if (error) {
			URTW8187_DBG(URTW_DEBUG_STATE,
			    (sc->sc_dev, CE_CONT, "assoc setchan failed"));
		}
		break;

	case IEEE80211_S_RUN:
		URTW8187_DBG(URTW_DEBUG_STATE,
		    (sc->sc_dev, CE_CONT, "-> IEEE80211_S_RUN ...arg(%d)\n",
		    arg));
		error = urtw_set_channel(sc);
		if (error) {
			URTW8187_DBG(URTW_DEBUG_STATE,
			    (sc->sc_dev, CE_CONT, "run setchan failed"));
			goto fail;
		}
		ni = ic->ic_bss;
		/* setting bssid.  */
		(void) urtw_write32_c(sc, URTW_BSSID,
		    ((uint32_t *)(uintptr_t)ni->in_bssid)[0]);
		(void) urtw_write16_c(sc, URTW_BSSID + 4,
		    ((uint16_t *)(uintptr_t)ni->in_bssid)[2]);
		(void) urtw_update_msr(sc, nstate);

		ni->in_txrate = ni->in_rates.ir_nrates - 1;
		break;
	}
fail:
	URTW_UNLOCK(sc);

	if (error)
		return (EIO);
	error = sc->sc_newstate(ic, nstate, arg);
	return (error);
}

static void
urtw_close_pipes(struct urtw_softc *sc)
{
	usb_flags_t flags = USB_FLAGS_SLEEP;

	if (sc->sc_rxpipe != NULL) {
		usb_pipe_reset(sc->sc_dev,
		    sc->sc_rxpipe, flags, NULL, 0);
		usb_pipe_close(sc->sc_dev,
		    sc->sc_rxpipe, flags, NULL, 0);
		sc->sc_rxpipe = NULL;
	}

	if (sc->sc_txpipe_low != NULL) {
		usb_pipe_reset(sc->sc_dev,
		    sc->sc_txpipe_low, flags, NULL, 0);
		usb_pipe_close(sc->sc_dev,
		    sc->sc_txpipe_low, flags, NULL, 0);
		sc->sc_txpipe_low = NULL;
	}

	if (sc->sc_txpipe_normal != NULL) {
		usb_pipe_reset(sc->sc_dev,
		    sc->sc_txpipe_normal, flags, NULL, 0);
		usb_pipe_close(sc->sc_dev,
		    sc->sc_txpipe_normal, flags, NULL, 0);
		sc->sc_txpipe_normal = NULL;
	}
}

static int
urtw_open_pipes(struct urtw_softc *sc)
{
	usb_ep_data_t *ep_node;
	usb_pipe_policy_t policy;
	int err;

	if (sc->sc_rxpipe || sc->sc_txpipe_low || sc->sc_txpipe_normal)
		return (USB_SUCCESS);

	ep_node = usb_lookup_ep_data(sc->sc_dev, sc->sc_udev, 0, 0,
	    LOW_PRIORITY_PIPE, USB_EP_ATTR_BULK, USB_EP_DIR_OUT);

	bzero(&policy, sizeof (usb_pipe_policy_t));
	policy.pp_max_async_reqs = URTW_TX_DATA_LIST_COUNT;

	if ((err = usb_pipe_open(sc->sc_dev,
	    &ep_node->ep_descr, &policy, USB_FLAGS_SLEEP,
	    &sc->sc_txpipe_low)) != USB_SUCCESS) {
		URTW8187_DBG(URTW_DEBUG_ACTIVE, (sc->sc_dev, CE_CONT,
		    "urtw_open_pipes(): %x low priority pipe open failed\n",
		    err));
		goto fail;
	}

	ep_node = usb_lookup_ep_data(sc->sc_dev, sc->sc_udev, 0, 0,
	    NORMAL_PRIORITY_PIPE, USB_EP_ATTR_BULK, USB_EP_DIR_OUT);

	bzero(&policy, sizeof (usb_pipe_policy_t));
	policy.pp_max_async_reqs = URTW_TX_DATA_LIST_COUNT;

	if ((err = usb_pipe_open(sc->sc_dev,
	    &ep_node->ep_descr, &policy, USB_FLAGS_SLEEP,
	    &sc->sc_txpipe_normal)) != USB_SUCCESS) {
		URTW8187_DBG(URTW_DEBUG_ACTIVE, (sc->sc_dev, CE_CONT,
		    "urtw_open_pipes(): %x failed to open high tx pipe\n",
		    err));
		goto fail;
	}

	ep_node = usb_lookup_ep_data(sc->sc_dev, sc->sc_udev, 0, 0, 0,
	    USB_EP_ATTR_BULK, USB_EP_DIR_IN);

	bzero(&policy, sizeof (usb_pipe_policy_t));
	policy.pp_max_async_reqs = URTW_RX_DATA_LIST_COUNT;

	if ((err = usb_pipe_open(sc->sc_dev,
	    &ep_node->ep_descr, &policy, USB_FLAGS_SLEEP,
	    &sc->sc_rxpipe)) != USB_SUCCESS) {
		URTW8187_DBG(URTW_DEBUG_ACTIVE, (sc->sc_dev, CE_CONT,
		    "urtw_open_pipes(): %x failed to open rx pipe\n", err));
		goto fail;
	}

	return (USB_SUCCESS);

fail:
	urtw_close_pipes(sc);
	return (USB_FAILURE);
}

static int
urtw_tx_start(struct urtw_softc *sc, mblk_t *mp, int priority)
{
	usb_bulk_req_t *req;
	int err;

	req = usb_alloc_bulk_req(sc->sc_dev, 0, USB_FLAGS_SLEEP);
	if (req == NULL) {
		URTW8187_DBG(URTW_DEBUG_TX_PROC, (sc->sc_dev, CE_CONT,
		    "urtw_tx_start(): failed to allocate req"));
		freemsg(mp);
		return (-1);
	}

	req->bulk_len = MBLKL(mp);
	req->bulk_data = mp;
	req->bulk_client_private = (usb_opaque_t)sc;
	req->bulk_timeout = URTW_TX_TIMEOUT;
	req->bulk_attributes = USB_ATTRS_AUTOCLEARING;
	req->bulk_cb = (priority)?urtw_txeof_normal : urtw_txeof_low;
	req->bulk_exc_cb = (priority)?urtw_txeof_normal: urtw_txeof_low;
	req->bulk_completion_reason = 0;
	req->bulk_cb_flags = 0;

	if ((err = usb_pipe_bulk_xfer(
	    (priority)?sc->sc_txpipe_normal:sc->sc_txpipe_low, req, 0))
	    != USB_SUCCESS) {
		sc->sc_ic.ic_stats.is_tx_failed++;
		URTW8187_DBG(URTW_DEBUG_TX_PROC, (sc->sc_dev, CE_CONT,
		    "urtw_tx_start: failed to do tx xfer, %d", err));
		usb_free_bulk_req(req);
		return (EIO);
	}

	if (priority) {
		sc->sc_tx_normal_queued++;
	} else {
		sc->sc_tx_low_queued++;
	}

	return (0);
}

static int
urtw_rx_start(struct urtw_softc *sc)
{
	usb_bulk_req_t *req;
	int err;

	req = usb_alloc_bulk_req(sc->sc_dev, URTW_RXBUF_SIZE, USB_FLAGS_SLEEP);
	if (req == NULL) {
		URTW8187_DBG(URTW_DEBUG_RECV, (sc->sc_dev, CE_CONT,
		    "urtw_rx_start(): failed to allocate req"));
		return (-1);
	}

	req->bulk_len		= URTW_RXBUF_SIZE;
	req->bulk_client_private = (usb_opaque_t)sc;
	req->bulk_timeout	= 0;
	req->bulk_attributes	= USB_ATTRS_SHORT_XFER_OK |
	    USB_ATTRS_AUTOCLEARING;
	req->bulk_cb		= urtw_rxeof;
	req->bulk_exc_cb	= urtw_rxeof;
	req->bulk_completion_reason = 0;
	req->bulk_cb_flags	= 0;

	err = usb_pipe_bulk_xfer(sc->sc_rxpipe, req, 0);

	if (err != USB_SUCCESS) {
		URTW8187_DBG(URTW_DEBUG_RECV, (sc->sc_dev, CE_CONT,
		    "urtw_rx_start: failed to do rx xfer, %d", err));
		usb_free_bulk_req(req);
		return (-1);
	}

	mutex_enter(&sc->rx_lock);
	sc->rx_queued++;
	mutex_exit(&sc->rx_lock);

	return (0);
}

static int
urtw_disconnect(dev_info_t *devinfo)
{
	struct urtw_softc *sc;

	sc = ddi_get_soft_state(urtw_soft_state_p, ddi_get_instance(devinfo));
	URTW8187_DBG(URTW_DEBUG_HOTPLUG,
	    (sc->sc_dev, CE_CONT, "urtw_offline()\n"));

	ieee80211_new_state(&sc->sc_ic, IEEE80211_S_INIT, -1);
	ieee80211_stop_watchdog(&sc->sc_ic);
	if (URTW_IS_RUNNING(sc)) {
		urtw_stop(sc);
		URTW_LOCK(sc);
		sc->sc_flags |= URTW_FLAG_PLUGIN_ONLINE;
		URTW_UNLOCK(sc);
	}
	return (DDI_SUCCESS);
}

static int
urtw_reconnect(dev_info_t *devinfo)
{
	struct urtw_softc *sc;
	int error = 0;
	sc = ddi_get_soft_state(urtw_soft_state_p, ddi_get_instance(devinfo));
	if (usb_check_same_device(sc->sc_dev, NULL, USB_LOG_L2, -1,
	    USB_CHK_ALL, NULL) != USB_SUCCESS)
		return (DDI_FAILURE);
	URTW8187_DBG(URTW_DEBUG_HOTPLUG, (sc->sc_dev, CE_CONT,
	    "urtw_online()\n"));
	if (URTW_IS_PLUGIN_ONLINE(sc)) {
		error = urtw_init(sc);
		if (!error) {
			URTW_LOCK(sc);
			sc->sc_flags &= ~URTW_FLAG_PLUGIN_ONLINE;
			URTW_UNLOCK(sc);
		}
	}
	return (error);
}

static mblk_t *
urtw_m_tx(void *arg, mblk_t *mp)
{
	struct urtw_softc *sc = (struct urtw_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;
	mblk_t *next;

	if ((ic->ic_state != IEEE80211_S_RUN) ||
	    URTW_IS_SUSPENDING(sc)) {
		freemsgchain(mp);
		return (NULL);
	}

	while (mp != NULL) {
		next = mp->b_next;
		mp->b_next = NULL;
		if (urtw_send(ic, mp, IEEE80211_FC0_TYPE_DATA) != DDI_SUCCESS) {
			mp->b_next = next;
			break;
		}
		mp = next;
	}
	return (mp);
}

static int
urtw_m_start(void *arg)
{
	struct urtw_softc *sc = (struct urtw_softc *)arg;
	int error = 0;

	URTW8187_DBG(URTW_DEBUG_ACTIVE,
	    (sc->sc_dev, CE_CONT, "urtw_m_start)\n"));
	error = urtw_init(sc);
	return (error);
}

static void
urtw_m_stop(void *arg)
{
	struct urtw_softc *sc = (struct urtw_softc *)arg;

	URTW8187_DBG(URTW_DEBUG_ACTIVE, (sc->sc_dev, CE_CONT,
	    "urtw_m_stop()\n"));
	ieee80211_new_state(&sc->sc_ic, IEEE80211_S_INIT, -1);
	ieee80211_stop_watchdog(&sc->sc_ic);
	(void) urtw_stop(sc);
}

/*ARGSUSED*/
static int
urtw_m_unicst(void *arg, const uint8_t *macaddr)
{
	return (ENOTSUP);
}

/*ARGSUSED*/
static int
urtw_m_multicst(void *arg, boolean_t add, const uint8_t *macaddr)
{
	return (ENOTSUP);
}

/*ARGSUSED*/
static int
urtw_m_promisc(void *arg, boolean_t on)
{
	return (0);
}

static int
urtw_m_setprop(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    uint_t wldp_length, const void *wldp_buf)
{
	struct urtw_softc *sc = (struct urtw_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;
	int err;

	err = ieee80211_setprop(ic, pr_name, wldp_pr_num,
	    wldp_length, wldp_buf);
	if (err == ENETRESET) {
		if (ic->ic_des_esslen && URTW_IS_RUNNING(sc)) {
			(void) urtw_init(sc);
			(void) ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
		}
		err = 0;
	}
	return (err);
}

static void
urtw_m_ioctl(void* arg, queue_t *wq, mblk_t *mp)
{
	struct urtw_softc *sc = (struct urtw_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;
	int err;

	err = ieee80211_ioctl(ic, wq, mp);
	if (err == ENETRESET) {
		if (ic->ic_des_esslen && URTW_IS_RUNNING(sc)) {
			(void) urtw_init(sc);
			(void) ieee80211_new_state(ic,
			    IEEE80211_S_SCAN, -1);
		}
	}
}

static int
urtw_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	struct urtw_softc *sc  = (struct urtw_softc *)arg;
	ieee80211com_t	*ic = &sc->sc_ic;
	ieee80211_node_t *ni = 0;
	struct ieee80211_rateset *rs = 0;

	URTW_LOCK(sc);
	switch (stat) {
	case MAC_STAT_IFSPEED:
		ni = ic->ic_bss;
		rs = &ni->in_rates;
		*val = ((ic->ic_fixed_rate == IEEE80211_FIXED_RATE_NONE) ?
		    (rs->ir_rates[ni->in_txrate] & IEEE80211_RATE_VAL)
		    : ic->ic_fixed_rate) / 2 * 1000000;
		break;
	case MAC_STAT_NOXMTBUF:
		*val = sc->sc_tx_nobuf;
		break;
	case MAC_STAT_NORCVBUF:
		*val = sc->sc_rx_nobuf;
		break;
	case MAC_STAT_IERRORS:
		*val = sc->sc_rx_err;
		break;
	case MAC_STAT_RBYTES:
		*val = ic->ic_stats.is_rx_bytes;
		break;
	case MAC_STAT_IPACKETS:
		*val = ic->ic_stats.is_rx_frags;
		break;
	case MAC_STAT_OBYTES:
		*val = ic->ic_stats.is_tx_bytes;
		break;
	case MAC_STAT_OPACKETS:
		*val = ic->ic_stats.is_tx_frags;
		break;
	case MAC_STAT_OERRORS:
		*val = ic->ic_stats.is_tx_failed;
		break;
	case WIFI_STAT_TX_FRAGS:
	case WIFI_STAT_MCAST_TX:
	case WIFI_STAT_TX_FAILED:
	case WIFI_STAT_TX_RETRANS:
	case WIFI_STAT_RTS_SUCCESS:
	case WIFI_STAT_RTS_FAILURE:
	case WIFI_STAT_ACK_FAILURE:
	case WIFI_STAT_RX_FRAGS:
	case WIFI_STAT_MCAST_RX:
	case WIFI_STAT_FCS_ERRORS:
	case WIFI_STAT_WEP_ERRORS:
	case WIFI_STAT_RX_DUPS:
		URTW_UNLOCK(sc);
		return (ieee80211_stat(ic, stat, val));
	default:
		URTW_UNLOCK(sc);
		return (ENOTSUP);
	}
	URTW_UNLOCK(sc);

	return (0);
}

static void
urtw_watchdog(void *arg)
{
	struct urtw_softc *sc = arg;
	struct ieee80211com *ic = &sc->sc_ic;

	ieee80211_stop_watchdog(ic);

	URTW_LOCK(sc);
	if (URTW_IS_NOT_RUNNING(sc)) {
		URTW_UNLOCK(sc);
		return;
	}

	URTW_UNLOCK(sc);
	switch (ic->ic_state) {
		case IEEE80211_S_AUTH:
		case IEEE80211_S_ASSOC:
			if (ic->ic_bss->in_fails > 0)
				ieee80211_new_state(ic, IEEE80211_S_INIT, -1);
			else
				ieee80211_watchdog(ic);
			break;
	}
}


static int
urtw_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	struct urtw_softc *sc;
	struct ieee80211com *ic;
	int error, i, instance;
	uint32_t data = 0;
	char strbuf[32];
	wifi_data_t wd = { 0 };
	mac_register_t *macp;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		sc = ddi_get_soft_state(urtw_soft_state_p,
		    ddi_get_instance(devinfo));
		ASSERT(sc != NULL);
		URTW8187_DBG(URTW_DEBUG_ACTIVE,
		    (sc->sc_dev, CE_CONT, "urtw: resume\n"));
		URTW_LOCK(sc);
		sc->sc_flags &= ~URTW_FLAG_SUSPEND;
		URTW_UNLOCK(sc);
		if (URTW_IS_PLUGIN_ONLINE(sc)) {
			error = urtw_init(sc);
			if (error == 0) {
				URTW_LOCK(sc);
				sc->sc_flags &= ~URTW_FLAG_PLUGIN_ONLINE;
				URTW_UNLOCK(sc);
			}
		}
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(devinfo);

	if (ddi_soft_state_zalloc(urtw_soft_state_p, instance) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "urtw_attach:unable to alloc soft_state_p\n");
		return (DDI_FAILURE);
	}

	sc = ddi_get_soft_state(urtw_soft_state_p, instance);
	ic = (ieee80211com_t *)&sc->sc_ic;
	sc->sc_dev = devinfo;

	if (usb_client_attach(devinfo, USBDRV_VERSION, 0) != USB_SUCCESS) {
		cmn_err(CE_WARN, "urtw_attach: usb_client_attach failed\n");
		goto fail1;
	}

	if (usb_get_dev_data(devinfo, &sc->sc_udev,
	    USB_PARSE_LVL_ALL, 0) != USB_SUCCESS) {
		sc->sc_udev = NULL;
		goto fail2;
	}

	mutex_init(&sc->sc_genlock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sc->tx_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sc->rx_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sc->sc_ledlock, NULL, MUTEX_DRIVER, NULL);

	if (urtw_read32_c(sc, URTW_RX, &data))
		goto fail3;
	sc->sc_epromtype = (data & URTW_RX_9356SEL) ? URTW_EEPROM_93C56 :
	    URTW_EEPROM_93C46;
	if (sc->sc_epromtype == URTW_EEPROM_93C56)
		URTW8187_DBG(URTW_DEBUG_HWTYPE, (sc->sc_dev, CE_CONT,
		    "urtw_attach: eprom is 93C56\n"));
	else
		URTW8187_DBG(URTW_DEBUG_HWTYPE, (sc->sc_dev, CE_CONT,
		    "urtw_attach: eprom is 93C46\n"));
	error = urtw_get_rfchip(sc);
	if (error != 0)
		goto fail3;
	error = urtw_get_macaddr(sc);
	if (error != 0)
		goto fail3;
	error = urtw_get_txpwr(sc);
	if (error != 0)
		goto fail3;
	error = urtw_led_init(sc);		/* XXX incompleted  */
	if (error != 0)
		goto fail3;

	sc->sc_rts_retry = URTW_DEFAULT_RTS_RETRY;
	sc->sc_tx_retry = URTW_DEFAULT_TX_RETRY;
	sc->sc_currate = 3;
	/* XXX for what?  */
	sc->sc_preamble_mode = 2;

	ic->ic_phytype = IEEE80211_T_OFDM;	/* not only, but not used */
	ic->ic_opmode = IEEE80211_M_STA;	/* default to BSS mode */
	ic->ic_state = IEEE80211_S_INIT;

	ic->ic_maxrssi = 95;
	ic->ic_xmit = urtw_send;

	ic->ic_caps |= IEEE80211_C_WPA | /* Support WPA/WPA2 */
	    IEEE80211_C_TXPMGT |	/* tx power management */
	    IEEE80211_C_SHPREAMBLE |	/* short preamble supported */
	    IEEE80211_C_SHSLOT;	/* short slot time supported */
	/* set supported .11b and .11g rates */
	ic->ic_sup_rates[IEEE80211_MODE_11B] = urtw_rateset_11b;
	ic->ic_sup_rates[IEEE80211_MODE_11G] = urtw_rateset_11g;

	/* set supported .11b and .11g channels (1 through 11) */
	for (i = 1; i <= 11; i++) {
		ic->ic_sup_channels[i].ich_freq =
		    ieee80211_ieee2mhz(i, IEEE80211_CHAN_2GHZ);
		ic->ic_sup_channels[i].ich_flags =
		    IEEE80211_CHAN_CCK | IEEE80211_CHAN_DYN |
		    IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_OFDM;
	}

	ieee80211_attach(ic);

	/* register WPA door */
	ieee80211_register_door(ic, ddi_driver_name(devinfo),
	    ddi_get_instance(devinfo));

	/* override state transition machine */
	sc->sc_newstate = ic->ic_newstate;
	ic->ic_newstate = urtw_newstate;
	ic->ic_watchdog = urtw_watchdog;
	ieee80211_media_init(ic);
	ic->ic_def_txkey = 0;

	sc->dwelltime = 400;
	sc->sc_flags = 0;

	/*
	 * Provide initial settings for the WiFi plugin; whenever this
	 * information changes, we need to call mac_plugindata_update()
	 */
	wd.wd_opmode = ic->ic_opmode;
	wd.wd_secalloc = WIFI_SEC_NONE;
	IEEE80211_ADDR_COPY(wd.wd_bssid, ic->ic_bss->in_bssid);

	if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
		URTW8187_DBG(URTW_DEBUG_ATTACH, (sc->sc_dev, CE_CONT,
		    "MAC version alloc failed\n"));
		goto fail4;
	}

	macp->m_type_ident = MAC_PLUGIN_IDENT_WIFI;
	macp->m_driver = sc;
	macp->m_dip = devinfo;
	macp->m_src_addr = ic->ic_macaddr;
	macp->m_callbacks = &urtw_m_callbacks;
	macp->m_min_sdu	= 0;
	macp->m_max_sdu	= IEEE80211_MTU;
	macp->m_pdata = &wd;
	macp->m_pdata_size = sizeof (wd);

	error = mac_register(macp, &ic->ic_mach);
	mac_free(macp);
	if (error != 0) {
		cmn_err(CE_WARN, "urtw_attach: mac_register() err %x\n", error);
		goto fail4;
	}

	if (usb_register_hotplug_cbs(devinfo, urtw_disconnect,
	    urtw_reconnect) != USB_SUCCESS) {
		cmn_err(CE_WARN, "urtw_attach: failed to register events");
		goto fail5;
	}

	/*
	 * Create minor node of type DDI_NT_NET_WIFI
	 */
	(void) snprintf(strbuf, sizeof (strbuf), "%s%d",
	    "urtw", instance);
	error = ddi_create_minor_node(devinfo, strbuf, S_IFCHR,
	    instance + 1, DDI_NT_NET_WIFI, 0);

	if (error != DDI_SUCCESS)
		cmn_err(CE_WARN, "urtw: ddi_create_minor_node() failed\n");

	/*
	 * Notify link is down now
	 */
	mac_link_update(ic->ic_mach, LINK_STATE_DOWN);

	URTW8187_DBG(URTW_DEBUG_ATTACH, (sc->sc_dev, CE_CONT,
	    "urtw_attach: successfully.\n"));
	return (DDI_SUCCESS);
fail5:
	(void) mac_unregister(ic->ic_mach);
fail4:
	ieee80211_detach(ic);
fail3:
	mutex_destroy(&sc->sc_genlock);
	mutex_destroy(&sc->tx_lock);
	mutex_destroy(&sc->rx_lock);
	mutex_destroy(&sc->sc_ledlock);
fail2:
	usb_client_detach(sc->sc_dev, sc->sc_udev);
fail1:
	ddi_soft_state_free(urtw_soft_state_p, ddi_get_instance(devinfo));

	return (DDI_FAILURE);
}

static int
urtw_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{
	struct urtw_softc *sc;

	sc = ddi_get_soft_state(urtw_soft_state_p, ddi_get_instance(devinfo));
	URTW8187_DBG(URTW_DEBUG_ATTACH, (sc->sc_dev,
	    CE_CONT, "urtw_detach()\n"));

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		URTW8187_DBG(URTW_DEBUG_ATTACH,
		    (sc->sc_dev, CE_CONT, "urtw: suspend\n"));

		ieee80211_new_state(&sc->sc_ic, IEEE80211_S_INIT, -1);
		ieee80211_stop_watchdog(&sc->sc_ic);

		URTW_LOCK(sc);
		sc->sc_flags |= URTW_FLAG_SUSPEND;
		URTW_UNLOCK(sc);
		if (URTW_IS_RUNNING(sc)) {
			urtw_stop(sc);
			URTW_LOCK(sc);
			sc->sc_flags |= URTW_FLAG_PLUGIN_ONLINE;
			URTW_UNLOCK(sc);
		}
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	if (mac_disable(sc->sc_ic.ic_mach) != 0)
		return (DDI_FAILURE);
	urtw_stop(sc);
	/*
	 * Unregister from the MAC layer subsystem
	 */
	(void) mac_unregister(sc->sc_ic.ic_mach);

	ieee80211_detach(&sc->sc_ic);
	usb_unregister_hotplug_cbs(devinfo);
	usb_client_detach(devinfo, sc->sc_udev);
	mutex_destroy(&sc->sc_genlock);
	mutex_destroy(&sc->tx_lock);
	mutex_destroy(&sc->rx_lock);
	mutex_destroy(&sc->sc_ledlock);
	sc->sc_udev = NULL;

	ddi_remove_minor_node(devinfo, NULL);
	ddi_soft_state_free(urtw_soft_state_p, ddi_get_instance(devinfo));

	return (DDI_SUCCESS);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_init(void)
{
	int status;

	status = ddi_soft_state_init(&urtw_soft_state_p,
	    sizeof (struct urtw_softc), 1);
	if (status != 0)
		return (status);

	mac_init_ops(&urtw_dev_ops, "urtw");
	status = mod_install(&modlinkage);
	if (status != 0) {
		mac_fini_ops(&urtw_dev_ops);
		ddi_soft_state_fini(&urtw_soft_state_p);
	}
	return (status);
}

int
_fini(void)
{
	int status;

	status = mod_remove(&modlinkage);
	if (status == 0) {
		mac_fini_ops(&urtw_dev_ops);
		ddi_soft_state_fini(&urtw_soft_state_p);
	}
	return (status);
}
