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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _ATGE_H
#define	_ATGE_H

#ifdef __cplusplus
	extern "C" {
#endif

#include <sys/ethernet.h>
#include <sys/mac_provider.h>
#include "atge_l1e_reg.h"
#include "atge_l1c_reg.h"

#define	ATGE_PCI_REG_NUMBER	1

#define	ROUNDUP(x, a)		(((x) + (a) - 1) & ~((a) - 1))

/*
 * Flags.
 */
#define	ATGE_FLAG_PCIE		0x0001
#define	ATGE_FIXED_TYPE		0x0002
#define	ATGE_MSI_TYPE		0x0004
#define	ATGE_MSIX_TYPE		0x0008
#define	ATGE_FLAG_FASTETHER	0x0010
#define	ATGE_FLAG_JUMBO		0x0020
#define	ATGE_MII_CHECK		0x0040
#define	ATGE_FLAG_ASPM_MON	0x0080
#define	ATGE_FLAG_CMB_BUG	0x0100
#define	ATGE_FLAG_SMB_BUG	0x0200
#define	ATGE_FLAG_APS		0x1000

#define	ATGE_CHIP_L1_DEV_ID	0x1048
#define	ATGE_CHIP_L2_DEV_ID	0x2048
#define	ATGE_CHIP_L1E_DEV_ID	0x1026
#define	ATGE_CHIP_L1CG_DEV_ID	0x1063
#define	ATGE_CHIP_L1CF_DEV_ID	0x1062
#define	ATGE_CHIP_AR8151V1_DEV_ID	0x1073
#define	ATGE_CHIP_AR8151V2_DEV_ID	0x1083
#define	ATGE_CHIP_AR8152V1_DEV_ID	0x2060
#define	ATGE_CHIP_AR8152V2_DEV_ID	0x2062

#define	ATGE_PROMISC		0x001
#define	ATGE_ALL_MULTICST	0x002

/*
 * Timer for one second interval.
 */
#define	ATGE_TIMER_INTERVAL	(1000 * 1000 * 1000)

/*
 * Chip state.
 */
#define	ATGE_CHIP_INITIALIZED	0x0001
#define	ATGE_CHIP_RUNNING	0x0002
#define	ATGE_CHIP_STOPPED	0x0004
#define	ATGE_CHIP_SUSPENDED	0x0008

#define	ETHER_CRC_LEN		0x4

/*
 * Descriptor increment and decrment operation.
 */
#define	ATGE_INC_SLOT(x, y)	\
	((x) = ((x) + 1) % (y))

#define	ATGE_DEC_SLOT(x, y)	\
	(x = ((x + y - 1) % y))

/*
 * I/O instructions
 */
#define	OUTB(atge, p, v)  \
	ddi_put8((atge)->atge_io_handle, \
		(void *)((caddr_t)((atge)->atge_io_regs) + (p)), v)

#define	OUTW(atge, p, v)  \
	ddi_put16((atge)->atge_io_handle, \
		(void *)((caddr_t)((atge)->atge_io_regs) + (p)), v)

#define	OUTL(atge, p, v)  \
	ddi_put32((atge)->atge_io_handle, \
		(void *)((caddr_t)((atge)->atge_io_regs) + (p)), v)

#define	INB(atge, p)      \
	ddi_get8((atge)->atge_io_handle, \
		(void *)(((caddr_t)(atge)->atge_io_regs) + (p)))
#define	INW(atge, p)      \
	ddi_get16((atge)->atge_io_handle, \
		(void *)(((caddr_t)(atge)->atge_io_regs) + (p)))

#define	INL(atge, p)      \
	ddi_get32((atge)->atge_io_handle, \
		(void *)(((caddr_t)(atge)->atge_io_regs) + (p)))

#define	FLUSH(atge, reg) \
	(void) INL(atge, reg)

#define	OUTL_OR(atge, reg, v) \
	OUTL(atge, reg, (INL(atge, reg) | v))

#define	OUTL_AND(atge, reg, v) \
	OUTL(atge, reg, (INL(atge, reg) & v))

/*
 * Descriptor and other endianess aware access.
 */
#define	ATGE_PUT64(dma, addr, v) \
	ddi_put64(dma->acchdl, (addr), (v))

#define	ATGE_PUT32(dma, addr, v) \
	ddi_put32(dma->acchdl, (addr), (v))

#define	ATGE_GET32(dma, addr) \
	ddi_get32(dma->acchdl, (addr))

#define	ATGE_GET64(dma, addr) \
	ddi_get64(dma->acchdl, (addr))

#define	DMA_SYNC(dma, s, l, d)	\
	(void) ddi_dma_sync(dma->hdl, (off_t)(s), (l), d)


#define	ATGE_ADDR_LO(x)		((uint64_t)(x) & 0xFFFFFFFF)
#define	ATGE_ADDR_HI(x)		((uint64_t)(x) >> 32)


/*
 * General purpose macros.
 */
#define	ATGE_MODEL(atgep)	atgep->atge_model
#define	ATGE_VID(atgep)		atgep->atge_vid
#define	ATGE_DID(atgep)		atgep->atge_did

/*
 * Different type of chip models.
 */
typedef	enum {
	ATGE_CHIP_L1 = 1,
	ATGE_CHIP_L2,
	ATGE_CHIP_L1E,
	ATGE_CHIP_L1C,
} atge_model_t;

typedef	struct	atge_cards {
	uint16_t	vendor_id;	/* PCI vendor id */
	uint16_t	device_id;	/* PCI device id */
	char		*cardname;	/* Description of the card */
	atge_model_t	model;		/* Model of the card */
} atge_cards_t;

/*
 * Number of Descriptors for TX and RX Ring.
 */
#define	ATGE_TX_NUM_DESC	256
#define	ATGE_RX_NUM_DESC	256

/*
 * DMA Handle for all DMA work.
 */
typedef	struct	atge_dma_data {
	ddi_dma_handle_t	hdl;
	ddi_acc_handle_t	acchdl;
	ddi_dma_cookie_t	cookie;
	caddr_t			addr;
	size_t			len;
	uint_t			count;
} atge_dma_t;

struct	atge;

/*
 * Structure for ring data (TX/RX).
 */
typedef	struct	atge_ring {
	struct	atge	*r_atge;
	atge_dma_t	**r_buf_tbl;
	atge_dma_t	*r_desc_ring;
	int		r_ndesc;
	int		r_consumer;
	int		r_producer;
	int		r_avail_desc;
} atge_ring_t;

/*
 * L1E specific private data.
 */
typedef	struct	atge_l1e_data {
	atge_dma_t	**atge_l1e_rx_page;
	atge_dma_t	*atge_l1e_rx_cmb;
	int		atge_l1e_pagesize;
	int		atge_l1e_rx_curp;
	uint16_t	atge_l1e_rx_seqno;
	uint32_t	atge_l1e_proc_max;
	uint32_t	atge_l1e_rx_page_cons;
	uint32_t	atge_l1e_rx_page_prods[L1E_RX_PAGES];
} atge_l1e_data_t;

/*
 * L1 specific private data.
 */
typedef	struct	atge_l1_data {
	atge_ring_t		*atge_rx_ring;
	atge_dma_t		*atge_l1_cmb;
	atge_dma_t		*atge_l1_rr;
	atge_dma_t		*atge_l1_smb;
	int			atge_l1_rr_consumers;
	uint32_t		atge_l1_intr_status;
	uint32_t		atge_l1_rx_prod_cons;
	uint32_t		atge_l1_tx_prod_cons;
} atge_l1_data_t;

/*
 * L1C specific private data.
 */
typedef	struct	atge_l1c_data {
	atge_ring_t		*atge_rx_ring;
	atge_dma_t		*atge_l1c_cmb;
	atge_dma_t		*atge_l1c_rr;
	atge_dma_t		*atge_l1c_smb;
	int			atge_l1c_rr_consumers;
	uint32_t		atge_l1c_intr_status;
	uint32_t		atge_l1c_rx_prod_cons;
	uint32_t		atge_l1c_tx_prod_cons;
} atge_l1c_data_t;

/*
 * TX descriptor table is same with L1, L1E and L2E chips.
 */
#pragma pack(1)
typedef struct  atge_tx_desc {
	uint64_t	addr;
	uint32_t	len;
	uint32_t	flags;
} atge_tx_desc_t;
#pragma pack()

#define	ATGE_TX_RING_CNT		256
#define	ATGE_TX_RING_SZ	\
	(sizeof (struct atge_tx_desc) * ATGE_TX_RING_CNT)

/*
 * Private instance data structure (per-instance soft-state).
 */
typedef	struct	atge {
	/*
	 * Lock for the TX ring, RX ring and interrupt. In order to align
	 * these locks at 8-byte boundary, we have kept it at the beginning
	 * of atge_t.
	 */
	kmutex_t		atge_tx_lock;
	kmutex_t		atge_rx_lock;
	kmutex_t		atge_intr_lock;
	kmutex_t		atge_mii_lock;
	kmutex_t		atge_mbox_lock;

	/*
	 * Instance number and devinfo pointer.
	 */
	int			atge_unit;
	dev_info_t		*atge_dip;
	char			atge_name[8];
	atge_model_t		atge_model;
	uint16_t		atge_vid;
	uint16_t		atge_did;
	int			atge_chip_rev;
	uint8_t			atge_revid;

	/*
	 * Mac handle.
	 */
	mac_handle_t		atge_mh;

	/*
	 * MII layer handle.
	 */
	mii_handle_t		atge_mii;
	link_state_t		atge_link_state;

	/*
	 * Config Space Handle.
	 */
	ddi_acc_handle_t	atge_conf_handle;

	/*
	 * IO registers mapped by DDI.
	 */
	ddi_acc_handle_t	atge_io_handle;
	caddr_t			atge_io_regs;
	uint_t			atge_intrs;

	/*
	 * Interrupt management structures.
	 */
	ddi_intr_handle_t	*atge_intr_handle;
	int			atge_intr_types;
	int			atge_intr_cnt;
	uint_t			atge_intr_pri;
	int			atge_intr_size;
	int			atge_intr_cap;

	/*
	 * Common structures.
	 */
	atge_ring_t		*atge_tx_ring;
	int			atge_tx_resched;
	int			atge_mtu;
	int			atge_int_mod;
	int			atge_int_rx_mod; /* L1C */
	int			atge_int_tx_mod; /* L1C */
	int			atge_max_frame_size;


	/*
	 * Ethernet addresses.
	 */
	ether_addr_t		atge_ether_addr;
	ether_addr_t		atge_dev_addr;
	uint64_t		atge_mchash;
	uint32_t		atge_mchash_ref_cnt[64];

	/*
	 * PHY register.
	 */
	int			atge_phyaddr;

	/*
	 * Flags.
	 */
	int			atge_flags;
	uint32_t		atge_dma_rd_burst;
	uint32_t		atge_dma_wr_burst;
	int			atge_filter_flags;
	int			atge_chip_state;

	/*
	 * Private data for the chip.
	 */
	void			*atge_private_data;

	/*
	 * Buffer length.
	 */
	int			atge_rx_buf_len;
	int			atge_tx_buf_len;

	/*
	 * Common stats.
	 */
	void			*atge_hw_stats;
	uint64_t		atge_ipackets;
	uint64_t		atge_opackets;
	uint64_t		atge_rbytes;
	uint64_t		atge_obytes;
	uint64_t		atge_brdcstxmt;
	uint64_t		atge_multixmt;
	uint64_t		atge_brdcstrcv;
	uint64_t		atge_multircv;
	unsigned		atge_norcvbuf;
	unsigned		atge_errrcv;
	unsigned		atge_errxmt;
	unsigned		atge_missed;
	unsigned		atge_underflow;
	unsigned		atge_overflow;
	unsigned		atge_align_errors;
	unsigned		atge_fcs_errors;
	unsigned		atge_carrier_errors;
	unsigned		atge_collisions;
	unsigned		atge_ex_collisions;
	unsigned		atge_tx_late_collisions;
	unsigned		atge_defer_xmts;
	unsigned		atge_first_collisions;
	unsigned		atge_multi_collisions;
	unsigned		atge_sqe_errors;
	unsigned		atge_macxmt_errors;
	unsigned		atge_macrcv_errors;
	unsigned		atge_toolong_errors;
	unsigned		atge_runt;
	unsigned		atge_jabber;
	unsigned		atge_noxmtbuf;
} atge_t;

/*
 * extern functions.
 */
extern	void	atge_error(dev_info_t *, char *, ...);

/*
 * Debugging Support.
 */
#ifdef	DEBUG
#define	ATGE_DB(arg)	atge_debug_func arg
#else
#define	ATGE_DB(arg)
#endif

extern	int	atge_debug;
extern	void	atge_debug_func(char *, ...);
extern	atge_dma_t	*atge_alloc_a_dma_blk(atge_t *, ddi_dma_attr_t *,
    int, int);
extern	void	atge_free_a_dma_blk(atge_dma_t *);
extern	atge_dma_t *atge_buf_alloc(atge_t *, size_t, int);
extern	void	atge_buf_free(atge_dma_t *);
extern	mblk_t *atge_get_mblk(int);
extern	void	atge_device_restart(atge_t *);
extern	int	atge_alloc_buffers(atge_ring_t *, size_t, size_t, int);
extern	void	atge_free_buffers(atge_ring_t *, size_t);
extern	void	atge_stop_timer(atge_t *);
extern	void	atge_start_timer(atge_t *);
extern	void	atge_mii_write(void *, uint8_t, uint8_t, uint16_t);
extern	uint16_t	atge_mii_read(void *, uint8_t, uint8_t);
extern	void	atge_device_stop(atge_t *);
extern	void	atge_tx_reclaim(atge_t *, int);


#ifdef __cplusplus
}
#endif

#endif	/* _ATGE_H */
