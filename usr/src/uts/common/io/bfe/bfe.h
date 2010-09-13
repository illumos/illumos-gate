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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _BFE_H
#define	_BFE_H

#include "bfe_hw.h"

#ifdef __cplusplus
	extern "C" {
#endif

#define	BFE_SUCCESS	DDI_SUCCESS
#define	BFE_FAILURE	DDI_FAILURE

#define	BFE_MAX_MULTICAST_TABLE	64

#define	BFE_LINK_SPEED_10MBS	1
#define	BFE_LINK_SPEED_100MBS	2

#define	VTAG_SIZE	4

#define	BFE_MTU		ETHERMTU

/*
 * Use to increment descriptor slot number.
 */
#define	BFE_INC_SLOT(i, p2) \
	(i = ((i + 1) & (p2 - 1)))

#define	BFE_DEC_SLOT(i, p2) \
	(i = ((i + p2 - 1) % p2))

/*
 * I/O instructions
 */
#define	OUTB(bfe, p, v)  \
	ddi_put8((bfe)->bfe_mem_regset.hdl, \
		(void *)((caddr_t)((bfe)->bfe_mem_regset.addr) + (p)), v)

#define	OUTW(bfe, p, v)  \
	ddi_put16((bfe)->bfe_mem_regset.hdl, \
		(void *)((caddr_t)((bfe)->bfe_mem_regset.addr) + (p)), v)

#define	OUTL(bfe, p, v)  \
	ddi_put32((bfe)->bfe_mem_regset.hdl, \
		(void *)((caddr_t)((bfe)->bfe_mem_regset.addr) + (p)), v)

#define	INB(bfe, p)      \
	ddi_get8((bfe)->bfe_mem_regset.hdl, \
		(void *)(((caddr_t)(bfe)->bfe_mem_regset.addr) + (p)))
#define	INW(bfe, p)      \
	ddi_get16((bfe)->bfe_mem_regset.hdl, \
		(void *)(((caddr_t)(bfe)->bfe_mem_regset.addr) + (p)))

#define	INL(bfe, p)      \
	ddi_get32((bfe)->bfe_mem_regset.hdl, \
		(void *)(((caddr_t)(bfe)->bfe_mem_regset.addr) + (p)))

#define	FLUSH(bfe, reg) \
	(void) INL(bfe, reg)

#define	OUTL_OR(bfe, reg, v) \
	OUTL(bfe, reg, (INL(bfe, reg) | v))

#define	OUTL_AND(bfe, reg, v) \
	OUTL(bfe, reg, (INL(bfe, reg) & v))

/*
 * These macros allows use to write to descriptor memory.
 */
#define	PUT_DESC(r, member, val)	\
	ddi_put32(r->r_desc_acc_handle, (member), (val))

#define	GET_DESC(r, member)	\
	ddi_get32(r->r_desc_acc_handle, (member))

typedef struct bfe_cards {
	uint16_t	vendor_id;
	uint16_t	device_id;
	char		*cardname;
} bfe_cards_t;


/*
 * Chip's state.
 */
typedef	enum {
	BFE_CHIP_UNINITIALIZED = 0,
	BFE_CHIP_INITIALIZED,
	BFE_CHIP_ACTIVE,
	BFE_CHIP_STOPPED,
	BFE_CHIP_HALT,
	BFE_CHIP_RESUME,
	BFE_CHIP_SUSPENDED,
	BFE_CHIP_QUIESCED
} bfe_chip_state_t;

/*
 * PHY state.
 */
typedef	enum {
	BFE_PHY_STARTED = 1,
	BFE_PHY_STOPPED,
	BFE_PHY_RESET_DONE,
	BFE_PHY_RESET_TIMEOUT,
	BFE_PHY_NOTFOUND
} bfe_phy_state_t;

/*
 * Chip's mode
 */
#define	BFE_RX_MODE_ENABLE	0x1
#define	BFE_RX_MODE_PROMISC	0x2
#define	BFE_RX_MODE_BROADCAST	0x4
#define	BFE_RX_MODE_ALLMULTI	0x8

/*
 * Every packet has this header which is put by the card.
 */
typedef	struct	bfe_rx_header {
	uint16_t len;
	uint16_t flags;
	uint16_t pad[12];
} bfe_rx_header_t;

typedef	struct bfe_stats {
	uint64_t	ether_stat_align_errors;
	uint64_t	ether_stat_carrier_errors;
	uint64_t	ether_stat_ex_collisions;
	uint64_t	ether_stat_fcs_errors;
	uint64_t	ether_stat_first_collisions;
	uint64_t	ether_stat_macrcv_errors;
	uint64_t	ether_stat_macxmt_errors;
	uint64_t	ether_stat_multi_collisions;
	uint64_t	ether_stat_toolong_errors;
	uint64_t	ether_stat_tooshort_errors;
	uint64_t	ether_stat_tx_late_collisions;
	uint64_t	ether_stat_defer_xmts;
	uint64_t	brdcstrcv;
	uint64_t	brdcstxmt;
	uint64_t	multixmt;
	uint64_t	collisions;
	uint64_t	ierrors;
	uint64_t	ipackets;
	uint64_t	multircv;
	uint64_t	norcvbuf;
	uint64_t	noxmtbuf;
	uint64_t	obytes;
	uint64_t	opackets;
	uint64_t	rbytes;
	uint64_t	underflows;
	uint64_t	overflows;
	uint64_t	txchecks;
	uint64_t	intr_claimed;
	uint64_t	intr_unclaimed;
	uint64_t	linkchanges;
	uint64_t	txcpybytes;
	uint64_t	txmapbytes;
	uint64_t	rxcpybytes;
	uint64_t	rxmapbytes;
	uint64_t	txreclaim0;
	uint64_t	txreclaims;
	uint32_t	txstalls;
	uint32_t	resets;
} bfe_stats_t;

typedef struct {
	int	state;
	int	speed;
	int	duplex;
	int	flowctrl;
	int	mau;
} bfe_link_t;

/*
 * Device registers handle
 */
typedef struct {
	ddi_acc_handle_t	hdl;
	caddr_t			addr;
} bfe_acc_t;

/*
 * BCM4401 Chip state
 */
typedef struct bfe_chip {
	int		link;
	int		state;
	int		speed;
	int		duplex;
	uint32_t	bmsr;
	uint32_t	phyaddr;
} bfe_chip_t;


/*
 * Ring Management framework.
 */

/*
 * TX and RX descriptor format in the hardware.
 */
typedef	struct bfe_desc {
	volatile uint32_t	desc_ctl;
	volatile uint32_t	desc_addr;
} bfe_desc_t;

/*
 * DMA handle for each descriptor
 */
typedef struct bfe_dma {
	ddi_dma_handle_t	handle;
	ddi_acc_handle_t	acchdl;
	ddi_dma_cookie_t	cookie;
	caddr_t			addr;
	size_t			len;
} bfe_dma_t;

/* Keep it power of 2 */
#define	TX_NUM_DESC	128
#define	RX_NUM_DESC	128


#define	BFE_RING_UNALLOCATED	0
#define	BFE_RING_ALLOCATED	1

struct	bfe;

typedef	struct bfe_ring {
	/* Lock for the ring */
	kmutex_t	r_lock;

	/* Actual lock pointer. It may point to global lock */
	kmutex_t	*r_lockp;

	/* DMA handle for all buffers in descriptor table */
	bfe_dma_t	*r_buf_dma;

	/* DMA buffer holding descriptor table */
	bfe_desc_t	*r_desc;

	/* DMA handle for the descriptor table */
	ddi_dma_handle_t r_desc_dma_handle;
	ddi_acc_handle_t r_desc_acc_handle;
	ddi_dma_cookie_t r_desc_cookie;
	uint32_t	r_ndesc;	/* number of descriptors for the ring */
	size_t		r_desc_len;	/* Actual descriptor size */

	/* DMA buffer length */
	size_t		r_buf_len;

	/* Flags associated to the ring */
	int		r_flags;

	/* Pointer back to bfe instance */
	struct	bfe	*r_bfe;

	/* Current slot number (or descriptor number) in the ring */
	uint_t		r_curr_desc;
	/* Consumed descriptor if got the interrupt (only used for TX) */
	uint_t		r_cons_desc;

	uint_t		r_avail_desc;
} bfe_ring_t;

/*
 * Device driver's private data per instance.
 */
typedef struct bfe {
	/* devinfo stuff */
	dev_info_t	*bfe_dip;
	int		bfe_unit;

	/* PCI Configuration handle */
	ddi_acc_handle_t	bfe_conf_handle;

	/* Device registers handle and regset */
	bfe_acc_t	bfe_mem_regset;

	/* Ethernet addr */
	ether_addr_t	bfe_ether_addr;
	ether_addr_t	bfe_dev_addr;

	/* MAC layer handle */
	mac_handle_t	bfe_machdl;

	/* Interrupt management */
	ddi_intr_handle_t	bfe_intrhdl;
	uint_t			bfe_intrpri;

	/* Ring Management */
	bfe_ring_t	bfe_tx_ring;
	bfe_ring_t	bfe_rx_ring;
	int		bfe_tx_resched;

	/* Chip details */
	bfe_chip_t	bfe_chip;
	bfe_stats_t	bfe_stats;
	bfe_chip_state_t	bfe_chip_state;
	uint_t		bfe_chip_mode;
	int32_t		bfe_phy_addr;
	uchar_t		bfe_chip_action;
	bfe_hw_stats_t	bfe_hw_stats;

	/* rw lock for chip */
	krwlock_t	bfe_rwlock;

	/* Multicast table */
	uint32_t	bfe_mcast_cnt;

	/* Timeout and PHY state */
	ddi_periodic_t	bfe_periodic_id;
	hrtime_t	bfe_tx_stall_time;
	bfe_phy_state_t	bfe_phy_state;
	int		bfe_phy_id;

	/* MII register set */
	uint16_t	bfe_mii_exp;
	uint16_t	bfe_mii_bmsr;
	uint16_t	bfe_mii_anar;
	uint16_t	bfe_mii_anlpar;
	uint16_t	bfe_mii_bmcr;

	/* Transceiver fields */
	uint8_t		bfe_adv_aneg;
	uint8_t		bfe_adv_100T4;
	uint8_t		bfe_adv_100fdx;
	uint8_t		bfe_adv_100hdx;
	uint8_t		bfe_adv_10fdx;
	uint8_t		bfe_adv_10hdx;
	uint8_t		bfe_cap_aneg;
	uint8_t		bfe_cap_100T4;
	uint8_t		bfe_cap_100fdx;
	uint8_t		bfe_cap_100hdx;
	uint8_t		bfe_cap_10fdx;
	uint8_t		bfe_cap_10hdx;
} bfe_t;

static int bfe_identify_hardware(bfe_t *);

#ifdef __cplusplus
}
#endif
#endif	/* _BFE_H */
