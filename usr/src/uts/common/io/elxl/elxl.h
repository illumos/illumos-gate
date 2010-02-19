/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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


#ifndef ELXL_H
#define	ELXL_H

/*
 * This file defines the registers specific to the EtherLink XL family
 * of NICs.
 */

#define	REG_CMD_STAT		0x0e	/* Write command, read status */

#define	CMD_GLOBAL_RESET	0x0000
#define	CMD_SELECT_WINDOW	0x0800
#define	CMD_BNC_ENABLE		0x1000	/* enable 10BASE2 DC-DC converter */
#define	CMD_RX_DISABLE		0x1800
#define	CMD_RX_ENABLE		0x2000
#define	CMD_RX_RESET		0x2800
#define	CMD_UP_STALL		0x3000
#define	CMD_UP_UNSTALL		0x3001
#define	CMD_DN_STALL		0x3002
#define	CMD_DN_UNSTALL		0x3003
#define	CMD_TX_ENABLE		0x4800
#define	CMD_TX_DISABLE		0x5000
#define	CMD_TX_RESET		0x5800
#define	CMD_INT_REQ		0x6000
#define	CMD_INT_ACK		0x6800
#define	CMD_INT_ENABLE		0x7000
#define	CMD_IND_ENABLE		0x7800
#define	CMD_SET_FILTER		0x8000
#define	CMD_SET_RXEARLY		0x8800
#define	CMD_SET_TXSTART		0x9800
#define	CMD_STATS_ENABLE	0xa800
#define	CMD_STATS_DISABLE	0xb000
#define	CMD_BNC_DISABLE		0xb800	/* disable 10BASE2 DC-DC converter */
#define	CMD_SET_TXRECLAIM	0xc000
#define	CMD_CLEAR_HASHBIT	0xc800
#define	CMD_SET_HASHBIT		0xcc00

/*
 * Defines for the interrupt status register
 */
#define	INT_LATCH		0x0001
#define	INT_HOST_ERROR		0x0002
#define	INT_TX_COMPLETE		0x0004
#define	INT_RX_COMPLETE		0x0010
#define	INT_RX_EARLY		0x0020
#define	INT_REQUESTED		0x0040
#define	INT_STATS		0x0080
#define	INT_LINK		0x0100	/* NB: most NICs don't implement it! */
#define	INT_DN_COMPLETE		0x0200
#define	INT_UP_COMPLETE		0x0400
#define	STAT_CMD_IN_PROGRESS	0x1000

#define	INT_WATCHED							\
	(INT_HOST_ERROR | INT_STATS | INT_DN_COMPLETE | INT_UP_COMPLETE)


/*
 * Flat address space registers (outside the windows)
 */

#define	REG_TXPKTID		0x18	/* 90xB only */
#define	REG_TIMER		0x1a
#define	REG_TXSTATUS		0x1b
#define	TXSTATUS_RECLAIM_ERR	0x02
#define	TXSTATUS_STATUS_OFLOW	0x04	/* bad news! */
#define	TXSTATUS_MAXCOLLISIONS	0x08
#define	TXSTATUS_UNDERRUN	0x10
#define	TXSTATUS_JABBER		0x20
#define	TXSTATUS_INT_REQ	0x40
#define	TXSTATUS_COMPLETE	0x80
#define	TXSTATUS_ERRS		0x32

#define	REG_INTSTATUSAUTO	0x1e
#define	REG_DMACTRL		0x20
#define	DMACTRL_DNCMPLREQ	0x00000002
#define	DMACTRL_DNSTALLED	0x00000004
#define	DMACTRL_UPCOMPLETE	0x00000008
#define	DMACTRL_DNCOMPLETE	0x00000010
#define	DMACTRL_UPRXEAREN	0x00000020
#define	DMACTRL_ARNCNTDN	0x00000040
#define	DMACTRL_DNINPROG	0x00000080
#define	DMACTRL_CNTSPEED	0x00000100
#define	DMACTRL_CNTDNMODE	0x00000200
#define	DMACTRL_ALTSEQDIS	0x00010000
#define	DMACTRL_DEFEATMWI	0x00100000
#define	DMACTRL_DEFEATMRL	0x00200000
#define	DMACTRL_UPOVERDIS	0x00400000
#define	DMACTRL_TARGABORT	0x40000000
#define	DMACTRL_MSTRABORT	0x80000000
#define	REG_DNLISTPTR		0x24
#define	REG_DNBURSTTHRESH	0x2a	/* 90xB only */
#define	REG_DNPRIOTHRESH	0x2c	/* 90xB only */
#define	REG_DNPOLL		0x2d	/* 90xB only */
#define	REG_TXFREETHRESH	0x2f	/* 90x only */
#define	REG_UPPKTSTATUS		0x30
#define	REG_FREETIMER		0x34
#define	REG_COUNTDOWN		0x36
#define	REG_UPLISTPTR		0x38
#define	REG_UPPRIOTHRESH	0x3c	/* 90xB only */
#define	REG_UPPOLL		0x3d	/* 90xB only */
#define	REG_UPBURSTTHRESH	0x3e	/* 90xB only */
#define	REG_REALTIMECNT		0x40	/* 90xB only */
#define	REG_DNMAXBURST		0x78	/* 90xB only */
#define	REG_UPMAXBURST		0x7a	/* 90xB only */

/*
 * Window 0.  Eeprom access.
 */
#define	W0_MFG_ID		0x00
#define	W0_EE_CMD		0x0a
#define	EE_CMD_ADDR		0x001f
#define	EE_CMD_WRITE_EN		0x0000
#define	EE_CMD_READ		0x0080
#define	EE_CMD_READ8		0x0200
#define	EE_CMD_BUSY		0x8000
#define	W0_EE_DATA		0x0c
/*
 * Window 2.
 */
#define	W2_STATION_ADDRESS	0x00
#define	W2_STATION_MASK		0x06
#define	W2_RESET_OPTIONS	0x0c		/* Reset options (90xB only) */
#define	W2_RESET_OPT_LEDPOLAR	0x0010	/* invert LED polarity */
#define	W2_RESET_OPT_PHYPOWER	0x4000	/* turn on PHY power */


/*
 * Window 3.
 */
#define	W3_INTERNAL_CONFIG	0x00	/* 32 bits */
#define	W3_MAX_PKT_SIZE		0x04	/* 90xB only */
#define	W3_MAC_CONTROL		0x06
#define	MAC_CONTROL_FDX		0x0020
#define	MAC_CONTROL_ALLOW_LARGE	0x0040
#define	MAC_CONTROL_FLOW_EN	0x0100	/* 90xB only */
#define	MAC_CONTROL_VLT_EN	0x0200	/* 90xB only */

/*
 * This is reset options for the other cards, media options for
 * the 90xB NICs. Reset options are in a separate register for
 * the 90xB.
 *
 * Note that these bit values are also the same as the
 * W3_RESET_OPTIONS media selection bits on 90x NICs, which
 * conviently occupies the same register, and pretty much is
 * the same thing.  There are some differences in the upper bits,
 * but we don't care about those.
 */
#define	W3_MEDIAOPT		0x08
#define	MEDIAOPT_100T4		0x0001
#define	MEDIAOPT_100TX		0x0002
#define	MEDIAOPT_100FX		0x0004
#define	MEDIAOPT_10T		0x0008
#define	MEDIAOPT_BNC		0x0010
#define	MEDIAOPT_AUI		0x0020
#define	MEDIAOPT_MII		0x0040
#define	MEDIAOPT_10FL		0x0080
#define	MEDIAOPT_MASK		0x00ff	/* excludes 10BASEFL */

/*
 * Window 4 registers.
 */
#define	W4_MEDIASTAT		0xa
#define	MEDIASTAT_SQE_EN	0x0008
#define	MEDIASTAT_JABGUARD_EN	0x0040
#define	MEDIASTAT_LINKBEAT_EN	0x0080
#define	MEDIASTAT_LINKDETECT	0x0800
#define	MEDIASTAT_AUI_DIS	0x8000

/*
 * Window 4, offset 8 is defined for MII/PHY access for EtherLink XL
 * cards.
 */
#define	W4_PHYSMGMT		0x08
#define	PHYSMGMT_CLK		0x0001
#define	PHYSMGMT_DATA		0x0002
#define	PHYSMGMT_DIR		0x0004

/*
 * Counter in window 4 for packets with a bad start-of-stream delimiter/
 */
#define	W4_BADSSD		0x0c

/*
 * Upper bits of 20-bit byte counters.
 */
#define	W4_UBYTESOK		0x0d

/*
 * W6 registers, used for statistics
 */
#define	W6_TX_BYTES		0x0c
#define	W6_RX_BYTES		0x0a
#define	W6_UPPER_FRAMES		0x09
#define	W6_DEFER		0x08
#define	W6_RX_FRAMES		0x07
#define	W6_TX_FRAMES		0x06
#define	W6_RX_OVERRUNS		0x05
#define	W6_TX_LATE_COL		0x04
#define	W6_SINGLE_COL		0x03
#define	W6_MULT_COL		0x02
#define	W6_SQE_ERRORS		0x01
#define	W6_NO_CARRIER		0x00

/*
 * Receive filter bits for use with CMD_SET_FILTER.
 */
#define	FILTER_UNICAST		0x01
#define	FILTER_ALLMULTI		0x02
#define	FILTER_ALLBCAST		0x04
#define	FILTER_PROMISC		0x08
#define	FILTER_MULTIHASH	0x10	/* only on 90xB */

/*
 * Window 7 registers. These are different for 90x and 90xB than
 * for the EtherLink III / Fast EtherLink cards.
 */

#define	W7_VLANMASK	0x00	/* 90xB only */
#define	W7_VLANTYPE	0x04	/* 90xB only */
#define	W7_TIMER	0x0a	/* 90x only */
#define	W7_TX_STATUS	0x0b	/* 90x only */
#define	W7_POWEREVENT	0x0c	/* 90xB only */
#define	W7_INTSTATUS	0x0e

/*
 * The Internal Config register is different on 90xB cards. The
 * different masks / shifts are defined here.
 */

/*
 * Lower 16 bits.
 */
#define	CONFIG_TXLARGE		0x4000
#define	CONFIG_TXLARGE_SHIFT	14

#define	CONFIG_RXLARGE		0x8000
#define	CONFIG_RXLARGE_SHIFT	15

/*
 * Upper 16 bits.
 */
#define	XCVR_SEL_10T		0x00000000U
#define	XCVR_SEL_AUI		0x00100000U
#define	XCVR_SEL_BNC		0x00300000U
#define	XCVR_SEL_100TX		0x00400000U	/* 3com says don't use this! */
#define	XCVR_SEL_100FX		0x00500000U
#define	XCVR_SEL_MII		0x00600000U
#define	XCVR_SEL_AUTO		0x00800000U
#define	XCVR_SEL_MASK		0x00f00000U

#define	RAM_PARTITION_5_3	0x00000000U
#define	RAM_PARTITION_3_1	0x00010000U
#define	RAM_PARTITION_1_1	0x00020000U
#define	RAM_PARTITION_3_5	0x00030000U
#define	RAM_PARTITION_MASK	0x00030000U

#define	CONFIG_AUTOSEL		0x0100
#define	CONFIG_AUTOSEL_SHIFT	8

#define	CONFIG_DISABLEROM	0x0200
#define	CONFIG_DISABLEROM_SHIFT	9

/*
 * ID of internal PHY.
 */

#define	INTPHY_ID		24

/*
 * Fragment header as laid out in memory for DMA access.
 */

#define	EX_FR_LENMASK	0x00001fff	/* mask for length in fr_len field */
#define	EX_FR_LAST	0x80000000	/* indicates last fragment */

/*
 * 3Com NICs have separate structures for packet upload (receive) and
 * download (transmit) descriptors.  However, the structures for the
 * "legacy" transmit format are nearly identical except for the fact
 * that the third field is named differently and the bit fields are
 * different.  To maximize code reuse, we use a single type to cover
 * both uses.  Note that for receive we can arrange these in a loop,
 * but not for transmit.  Note also that for simplicity, we only use
 * the "type 0" legacy DPD format -- the features offered by the newer
 * type 1 format are not something we need.
 */
typedef struct ex_pd {
	uint32_t	pd_link;
	uint32_t	pd_shared;
	uint32_t	pd_addr;
	uint32_t	pd_len;
} ex_pd_t;
#define	pd_fsh		pd_shared
#define	pd_status	pd_shared

/*
 * Type 0 Download Packet Descriptor (DPD).  We don't use the other
 * type, since it isn't supported by older 90x ASICs.
 */
struct ex_dpd {
	uint32_t dpd_nextptr;		/* prt to next fragheader */
	uint32_t dpd_fsh;		/* frame start header */
	uint32_t dpd_addr;
	uint32_t dpd_len;
};

struct ex_upd {
	uint32_t upd_nextptr;
	uint32_t upd_pktstatus;
	uint32_t upd_addr;	/* phys addr of frag */
	uint32_t upd_len;	/* length of frag */
};

#define	DPD_DMADDR(s, t) \
	((s)->sc_dpddma + ((char *)((t)->tx_dpd) - (char *)((s)->sc_dpd)))

/*
 * Frame Start Header bitfields.
 */

#define	EX_DPD_DNIND	0x80000000	/* intr on download done */
#define	EX_DPD_TXIND	0x00008000	/* intr on tx done */
#define	EX_DPD_NOCRC	0x00002000	/* no CRC append */

/*
 * Lower 12 bits are the tx length for the 90x family. The 90xB
 * assumes that the tx length is the sum of all frame lengths,
 * and uses the bits as below. It also defines some more bits in
 * the upper part.
 */
#define	EX_DPD_EMPTY	0x20000000	/* no data in this DPD */
#define	EX_DPD_UPDEFEAT	0x10000000	/* don't round tx lengths up */
#define	EX_DPD_UDPCKSUM	0x08000000	/* do hardware UDP checksum */
#define	EX_DPD_TCPCKSUM	0x04000000	/* do hardware TCP checksum */
#define	EX_DPD_IPCKSUM	0x02000000	/* do hardware IP checksum */
#define	EX_DPD_DNCMPLT	0x01000000	/* packet has been downloaded */
#define	EX_DPD_IDMASK	0x000003fc	/* mask for packet id */
#define	EX_DPD_IDSHIFT	2
#define	EX_DPD_RNDMASK	0x00000003	/* mask for rounding */
					/* 0 -> dword, 2 -> word, 1,3 -> none */
/*
 * upd_pktstatus bitfields.
 * The *CKSUMERR fields are only valid if the matching *CHECKED field
 * is set.
 */
#define	EX_UPD_PKTLENMASK	0x00001fff	/* 12:0 -> packet length */
#define	EX_UPD_ERROR		0x00004000	/* rcv error */
#define	EX_UPD_COMPLETE		0x00008000	/* rcv complete */
#define	EX_UPD_OVERRUN		0x00010000	/* rcv overrun */
#define	EX_UPD_RUNT		0x00020000	/* pkt < 60 bytes */
#define	EX_UPD_ALIGNERR		0x00040000	/* alignment error */
#define	EX_UPD_CRCERR		0x00080000	/* CRC error */
#define	EX_UPD_OVERSIZED	0x00100000	/* oversize frame */
#define	EX_UPD_DRIBBLEBITS	0x00800000	/* pkt had dribble bits */
#define	EX_UPD_OVERFLOW		0x01000000	/* insufficient space for pkt */
#define	EX_UPD_IPCKSUMERR	0x02000000	/* IP cksum error (90xB) */
#define	EX_UPD_TCPCKSUMERR	0x04000000	/* TCP cksum error (90xB) */
#define	EX_UPD_UDPCKSUMERR	0x08000000	/* UDP cksum error (90xB) */
#define	EX_UPD_IPCHECKED	0x20000000	/* IP cksum done */
#define	EX_UPD_TCPCHECKED	0x40000000	/* TCP cksum done */
#define	EX_UPD_UDPCHECKED	0x80000000	/* UDP cksum done */

#define	EX_UPD_ERR		0x001f4000	/* Errors we check for */
#define	EX_UPD_ERR_VLAN		0x000f0000	/* same for 802.1q */

#define	EX_UPD_CKSUMERR		0x0e000000	/* any IP checksum error */

/*
 * EEPROM offsets.  These are 16-bit word addresses.  There are a lot of
 * other things in here, but we only care about the OEM address.
 */
#define	EE_3COM_ADDR_0		0x00
#define	EE_3COM_ADDR_1		0x01
#define	EE_3COM_ADDR_2		0x02
#define	EE_OEM_ADDR_0		0x0a
#define	EE_OEM_ADDR_1		0x0b
#define	EE_OEM_ADDR_2		0x0c
#define	EE_CAPABILITIES		0x10

#define	EX_NTX		256
#define	EX_NRX		128
#define	EX_BUFSZ	1536

typedef struct ex_desc {
	struct ex_desc		*ed_next;
	struct ex_desc		*ed_prev;
	ddi_dma_handle_t	ed_dmah;
	ddi_acc_handle_t	ed_acch;
	caddr_t			ed_buf;
	uint32_t		ed_bufaddr;
	uint32_t		ed_descaddr;
	uint32_t		ed_off;		/* offset of pd */
	ex_pd_t			*ed_pd;
} ex_desc_t;

typedef struct ex_ring {
	int			r_count;
	int			r_avail;
	ddi_dma_handle_t	r_dmah;
	ddi_acc_handle_t	r_acch;
	uint32_t		r_paddr;
	ex_pd_t			*r_pd;
	ex_desc_t		*r_desc;
	ex_desc_t		*r_head;
	ex_desc_t		*r_tail;
} ex_ring_t;

/*
 * Higher level linked list of upload packet descriptors.
 */
struct ex_rxdesc {
	ddi_dma_handle_t	rx_dmah;
	ddi_acc_handle_t	rx_acch;
	caddr_t			rx_buf;
	uint32_t		rx_paddr;
	struct ex_upd		*rx_upd;
};

/*
 * Ethernet software status per interface.
 */
typedef struct ex_softc {
	dev_info_t		*ex_dip;
	mac_handle_t		ex_mach;
	mii_handle_t		ex_miih;
	ddi_periodic_t		ex_linkcheck;

	ddi_acc_handle_t	ex_pcih;
	ddi_acc_handle_t	ex_regsh;
	caddr_t			ex_regsva;

	kmutex_t		ex_txlock;
	kmutex_t		ex_intrlock;

	ddi_intr_handle_t	ex_intrh;

	uint8_t			ex_curraddr[6];
	uint8_t			ex_factaddr[6];
	boolean_t		ex_promisc;
	unsigned		ex_mccount;

	boolean_t		ex_running;
	boolean_t		ex_suspended;

	ex_ring_t		ex_rxring;
	ex_ring_t		ex_txring;

	uint32_t		ex_xcvr;
	uint32_t		ex_speed;
	link_duplex_t		ex_duplex;
	boolean_t		ex_fdx;
	link_state_t		ex_link;
	boolean_t		ex_mii_active;
	uint32_t		ex_mediaopt;
	char			ex_medias[128];
	uint16_t		ex_capab;

	/*
	 * Kstats.
	 */
	uint64_t		ex_ipackets;
	uint64_t		ex_opackets;
	uint64_t		ex_ibytes;
	uint64_t		ex_obytes;
	uint64_t		ex_brdcstrcv;
	uint64_t		ex_multircv;
	uint64_t		ex_brdcstxmt;
	uint64_t		ex_multixmt;
	unsigned		ex_toolong;
	unsigned		ex_runt;
	unsigned		ex_oflo;
	unsigned		ex_fcs;
	unsigned		ex_align;
	unsigned		ex_allocbfail;
	unsigned		ex_txerr;
	unsigned		ex_uflo;
	unsigned		ex_jabber;
	unsigned		ex_excoll;
	unsigned		ex_sqe;
	unsigned		ex_nocarrier;
	unsigned		ex_multcol;
	unsigned		ex_defer;
	unsigned		ex_latecol;
	unsigned		ex_singlecol;

	uint_t			ex_conf;	/* config flags */

#define	CONF_INTPHY		0x0001	/* has internal PHY at address 24 */
#define	CONF_90XB		0x0002	/* is 90xB */

} elxl_t;

#define	WAIT_CMD(sc) \
	{ \
		int stat; \
		do { \
			stat = GET16(REG_CMD_STAT); \
		} while ((stat & STAT_CMD_IN_PROGRESS) && (stat != 0xffff)); \
	}

#define	GET8(off)	\
	ddi_get8(sc->ex_regsh, (void *)(sc->ex_regsva + (off)))
#define	GET16(off)	\
	ddi_get16(sc->ex_regsh, (void *)(sc->ex_regsva + (off)))
#define	GET32(off)	\
	ddi_get32(sc->ex_regsh, (void *)(sc->ex_regsva + (off)))
#define	PUT8(off, val)	\
	ddi_put8(sc->ex_regsh, (void *)(sc->ex_regsva + (off)), val)
#define	PUT16(off, val)	\
	ddi_put16(sc->ex_regsh, (void *)(sc->ex_regsva + (off)), val)
#define	PUT32(off, val)	\
	ddi_put32(sc->ex_regsh, (void *)(sc->ex_regsva + (off)), val)

#define	SET16(off, val)	PUT16(off, GET16(off) | val)
#define	CLR16(off, val)	PUT16(off, GET16(off) & ~(val))

#define	PUT_CMD(x)	PUT16(REG_CMD_STAT, (x))
#define	SET_WIN(x)	PUT16(REG_CMD_STAT, CMD_SELECT_WINDOW | (x))

#define	PUT_PD(ring, member, val)	ddi_put32(ring->r_acch, &member, (val))
#define	GET_PD(ring, member)		ddi_get32(ring->r_acch, &member)

#endif	/* ELXL_H */
