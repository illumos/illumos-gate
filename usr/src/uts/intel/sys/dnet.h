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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_DNET_H
#define	_SYS_DNET_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/* debug flags */
#define	DNETTRACE		0x01
#define	DNETERRS		0x02
#define	DNETRECV		0x04
#define	DNETDDI			0x08
#define	DNETSEND		0x10
#define	DNETINT			0x20
#define	DNETSENSE		0x40
#define	DNETREGCFG		0x80

#ifdef DEBUG
#define	DNETDEBUG 1
#endif

/* Misc */
#define	DNETHIWAT		32768	/* driver flow control high water */
#define	DNETLOWAT		4096	/* driver flow control low water */
#define	DNETMAXPKT		1500	/* maximum media frame size */
#define	DNETIDNUM		0	/* DNET Id; zero works */
#define	DNET_MAX_FRAG		6	/* max mblk in msg before we pullup */

/* board state */
#define	DNET_IDLE		0
#define	DNET_WAITRCV		1
#define	DNET_XMTBUSY		2
#define	DNET_ERROR		3

#define	SUCCESS			0
#define	FAILURE			1

#define	DEC_VENDOR_ID		0x1011
#define	DEVICE_ID_21040		0x0002
#define	DEVICE_ID_21041		0x0014
#define	DEVICE_ID_21140		0x0009

/* Apparently, the 21143 and 142 are distinguished by revision ID */
#define	DEVICE_ID_21142		0x0019
#define	DEVICE_ID_21143		0x0019
#define	COGENT_EM100		0x12
#define	COGENT_QUARTET400	0x13
#define	COGENT_EM110TX		0x14
#define	VENDOR_ID_OFFSET	32
#define	VENDOR_REVISION_OFFSET	33	/* Cogent */
#define	ASANTE_ETHER		0x000094
#define	COGENT_ETHER		0x000092
#define	ADAPTEC_ETHER		0x0000d1
#define	ZNYX_ETHER		0x00c095
#define	COGENT_SROM_ID		0x7c
#define	COGENT_ANA6911A_C	0x2a
#define	COGENT_ANA6911AC_C	0x2b
enum	{ DEFAULT_TYPE, COGENT_EM_TYPE, ASANTE_TYPE};

#define	GLD_TX_RESEND		1 	/* return code for GLD resend */
#define	GLD_TX_OK		0	/* return code for GLD Tx ok */

#ifndef GLD_INTR_WAIT
/* Temporary until this makes it into the build environment's gld.h */
#define	GLD_INTR_WAIT 0x0002	/* waiting for interrupt to do scheduling */
#endif

#define	MAX_TX_DESC		128	/* Should be a multiple of 4 <= 256 */
#define	MAX_RX_DESC_21040	16	/* Should be a multiple of 4 <= 256 */
#define	MAX_RX_DESC_21140	32	/* Should be a multiple of 4 <= 256 */

#define	SROM_SIZE		128
#define	SETUPBUF_SIZE		192	/* Setup buffer size */
#define	MCASTBUF_SIZE		512	/* multicast hash table size in bits */
#define	PRIORITY_LEVEL		5
#define	HASH_POLY		0x04C11DB6
#define	HASH_CRC		0xFFFFFFFFU

#define	DNET_100MBPS		100	/* 21140 chip speeds */
#define	DNET_10MBPS		10


/* User defined PCI config space registers */
#define	PCI_DNET_CONF_CFDD	0x40
#define	CFDD_SLEEP		(1UL<<31)
#define	CFDD_SNOOZE		(1UL<<30)
/* CSR  Description */
#define	BUS_MODE_REG		0x00
#define	TX_POLL_REG		0x08
#define	RX_POLL_REG		0x10
#define	RX_BASE_ADDR_REG	0x18
#define	TX_BASE_ADDR_REG	0x20
#define	STATUS_REG		0x28
#define	OPN_MODE_REG		0x30
#define	INT_MASK_REG		0x38
#define	MISSED_FRAME_REG	0x40
#define	ETHER_ROM_REG		0x48
#define	BOOT_ROM_REG		0x50 /* 041, 140A, 142 */
#define	FULL_DUPLEX_REG		0x58 /* 040 */
#define	GP_TIMER_REG		0x58 /* 140-143 */
#define	SIA_STATUS_REG		0x60 /* 040, 041, 142 */
#define	SIA_CONNECT_REG		0x68 /* 040, 041, 142 */
#define	SIA_TXRX_REG		0x70 /* 041, 041, 142 */
#define	SIA_GENERAL_REG		0x78 /* 040, 041, 142 */
#define	GP_REG			0x60 /* 140, 140A */

/* Helpful defines for register access */
#define	REG32(reg, off)		((uint32_t *)((uintptr_t)(reg) + off))
#define	REG16(reg, off)		((uint16_t *)((uintptr_t)(reg) + off))
#define	REG8(reg, off)		((uint8_t *)((uintptr_t)(reg) + off))

/* Bit descriptions of CSR registers */

/* BUS_MODE_REG, CSR0 */
#define	SW_RESET		0x01UL
#define	BURST_SIZE		0x2000UL
#define	CACHE_ALIGN		0x04000UL /* 8 long word boundary align */

/* TX_POLL_REG, CSR1 */
#define	TX_POLL_DEMAND  	0x01

/* RX_POLL_REG, CSR2 */
#define	RX_POLL_DEMAND  	0x01

/* STATUS_REG, CSR5 */
#define	TX_INTR			0x01UL
#define	TX_STOPPED		0x02UL
#define	TX_BUFFER_UNAVAILABLE	0x04UL
#define	TX_JABBER_TIMEOUT	0x08UL
#define	TX_UNDERFLOW		0x20UL
#define	RX_INTR			0x40UL
#define	RX_UNAVAIL_INTR		0x80UL
#define	RX_STOP_INTR		0x0100UL
#define	LINK_INTR		0x1000UL
#define	SYS_ERR			0x2000UL
#define	ABNORMAL_INTR_SUMM	0x8000UL
#define	NORMAL_INTR_SUMM	0x10000UL
#define	RECEIVE_PROCESS_STATE	0xe0000UL
#define	SYS_ERR_BITS		0x3800000UL
#define	PARITY_ERROR		0x00000000UL
#define	MASTER_ABORT		0x00800000UL
#define	TARGET_ABORT		0x01000000UL

/* OPN_REG , CSR6  */
#define	HASH_FILTERING		(1UL<<0)
#define	START_RECEIVE		(1UL<<1)
#define	HASH_ONLY		(1UL<<2)
#define	PASSBAD			(1UL<<3)
#define	INV_FILTER		(1UL<<4)
#define	START_BACKOFF		(1UL<<5)
#define	PROM_MODE		(1UL<<6)
#define	PASS_MULTICAST		(1UL<<7)
#define	FULL_DUPLEX		(1UL<<9)
#define	OPERATING_MODE		(3UL<<10)		/* 143 */
#define	FORCE_COLLISION		(1UL<<12)
#define	START_TRANSMIT 		(1UL<<13)
#define	TX_THRESHOLD_160	(3UL<<14)
#define	CAPTURE_ENABLE		(1UL<<17)
#define	PORT_SELECT		(1UL<<18)		/* 140, 140A, 142 */
#define	HEARTBEAT_DISABLE	(1UL<<19)		/* 140, 140A, 142 */
#define	STORE_AND_FORWARD	(1UL<<21)		/* 140, 140A, 142 */
#define	TX_THRESHOLD_MODE	(1UL<<22)		/* 140, 140A, 142 */
#define	PCS_FUNCTION		(1UL<<23)		/* 140, 140A */
#define	SCRAMBLER_MODE		(1UL<<24)		/* 140, 140A */
#define	OPN_REG_MB1		(1UL<<25)
#define	RECEIVEALL		(1UL<<30)
#define	SPECIAL_CAPTURE		(1UL<<31)

/* INT_MASK_REG , CSR7  */
#define	TX_INTERRUPT_MASK	0x01UL
#define	TX_STOPPED_MASK		0x02UL
#define	TX_BUFFER_UNAVAIL_MASK	0x04UL
#define	TX_JABBER_MASK		0x08UL
#define	TX_UNDERFLOW_MASK	0x20UL
#define	RX_INTERRUPT_MASK	0x40UL
#define	RX_UNAVAIL_MASK 	0x80UL
#define	RX_STOP_MASK		0x00100UL
#define	GPTIMER_INTR		0x800UL
#define	LINK_INTR_MASK   	0x01000UL
#define	SYSTEM_ERROR_MASK   	0x02000UL
#define	ABNORMAL_INTR_MASK	0x08000UL
#define	NORMAL_INTR_MASK	0x10000UL

/* MISSED_FRAME_REG, CSR8 */
#define	MISSED_FRAME_MASK	0x0ffffUL
#define	OVERFLOW_COUNTER_MASK	0xffe0000UL

/* Serial ROM Register CSR9 */
#define	SROM_MAX_CYCLES		5UL
#define	SEL_CHIP		0x01UL
#define	SEL_CLK			0x02UL
#define	DATA_IN			0x04UL
#define	DATA_OUT		0x08UL
#define	HIGH_ADDRESS_BIT	0x20UL
#define	SEL_ROM			0x800UL
#define	READ_OP			0x4000UL

#define	MII_WRITE		((uint32_t)(0x00002000))
#define	MII_CLOCK		((uint32_t)(0x00010000))
#define	MII_WRITE_DATA		((uint32_t)(0x00020000))
#define	MII_DATA_IN		((uint32_t)(0x00080000))
#define	MII_PHY_ADDR_ALIGN	23
#define	MII_REG_ADDR_ALIGN	18
#define	MII_WRITE_DATA_POSITION	17
#define	MII_DATA_IN_POSITION	19
#define	MII_DELAY		1  /* 1 microsecond */
#define	MII_PRE			((uint32_t)(0xFFFFFFFF))
#define	MII_READ_FRAME		((uint32_t)(0x60000000))
#define	MII_WRITE_FRAME		((uint32_t)(0x50020000))
#define	MII_READ		((uint32_t)(0x00044000))
#define	MII_WRITE_TS		((uint32_t)(0x00042000))


/* GPR Timer reg, CSR11 */
#define	GPTIMER_CONT		(1UL<<16)
/* SIA Connectivity reg, CSR13 (040, 041, 142) */
#define	AUTO_CONFIG		0x05UL
#define	BNC_CONFIG		0x0DUL
#define	SIA_CONNECT_MASK	0xFFFF0000UL
#define	SIA_TXRX_MASK		0xFFFFFFFFUL
#define	SIA_GENERAL_MASK	0xFFFF0000UL

#define	SIA_TXRX_MASK_TP	0xFFFFFFFFUL
#define	SIA_GENRL_MASK_TP	0x00UL
#define	SIA_CONN_MASK_AUI	0xEF09UL
#define	SIA_TXRX_MASK_AUI	0x0000F73DUL
#define	SIA_GENRL_MASK_AUI	0x0000000EUL

#define	CWE_21140		0x00000100UL /* This is moved in the 21143 */
#define	CSR15_C
#define	MEDIA_TP		0
#define	MEDIA_BNC		1
#define	MEDIA_AUI		2
#define	MEDIA_SYM_SCR		3
#define	MEDIA_TP_FD		4
#define	MEDIA_SYM_SCR_FD	5
#define	MEDIA_100T4		6
#define	MEDIA_100FX		7
#define	MEDIA_100FX_FD		8
#define	MEDIA_MII		9


/* CSR15 */
#define	CWE_21143		(1UL<<11)

#define	MEDIA_CAP_100T4		0x8000UL
#define	MEDIA_CAP_100FDX	0x4000UL
#define	MEDIA_CAP_100HDX	0x2000UL
#define	MEDIA_CAP_10FDX		0x1000UL
#define	MEDIA_CAP_10HDX		0x800UL

/*
 * In GPR and reset sequences in the ROM this is used to decide wheather the
 * CWE bit should be set when writing to the GPR. However, the CWE bit is
 * different on the 143 and 140, so we pick a bit where we can safely store
 * this information in the ROM structure before writing it out to the GPR
 * register itself
 */
#define	GPR_CONTROL_WRITE	(1UL<<31)

/* command block bit flags from SROM */
#define	CMD_PS			(1<<0)
#define	CMD_TTM			(1<<4)
#define	CMD_PCS			(1<<5)
#define	CMD_SCR			(1<<6)
#define	CMD_POL			(1<<7)
#define	CMD_DEFAULT_MEDIUM	(1<<14)
#define	CMD_ACTIVE_INVALID	(1<<15)
#define	CMD_MEDIABIT_MASK	0xE

#define	MAX_SEQ			8
#define	MAX_ADAPTERS		8
#define	MAX_MEDIA		8



struct dnetinstance;

typedef void (*timercb_t)(struct dnetinstance *);


typedef struct _media_block_t {
	int type;
	uint16_t command;
	int gprseqlen;
	int rstseqlen;
	int media_code;
	uint16_t gprseq[8];
	uint16_t rstseq[8];
	unsigned int hassia:1;
	union {
		struct {
			int phy_num;
			uint16_t nwayadvert;
			uint16_t fdxmask;
			uint16_t ttmmask;
			uint16_t miiintr;
			uint16_t mediacaps;
		} mii;
		struct {
			uint32_t csr13;
			uint32_t csr14;
			uint32_t csr15;
		} sia;
	} un;
} media_block_t;

typedef struct leaf_format {
	uint16_t device_number;
	uint16_t gpr;
	uint16_t selected_contype;
	int block_count;
	media_block_t *default_block;
	media_block_t *mii_block;
	media_block_t block[MAX_MEDIA];
	int is_static;
} LEAF_FORMAT;


typedef struct srom_format {
	int	init_from_srom;
	/* elements used to store Version 1,3 and proprietary formats */
	uchar_t version;
	uchar_t adapters;
	uchar_t netaddr[ETHERADDRL];
	LEAF_FORMAT *leaf;
} SROM_FORMAT;

#define	SROM_VERSION		18
#define	SROM_ADAPTER_CNT	19
#define	SROM_NETADDR		20
#define	SROM_LEAF_OFFSET	26
#define	SROM_MBZ		 6
#define	SROM_MBZ2		15
#define	SROM_MBZ3		17

#define	MEDIA_CODE_MASK		0x3F
#define	EXT_BIT			0x40

struct dnetinstance {
	caddr_t			io_reg;		/* mapped register */
	int 			board_type;	/* board type: 21040 or 21140 */
	int			full_duplex;
	int 			bnc_indicator; 	/* Flag for BNC connector */
	uint64_t		speed;		/* data rate: 10 or 100 */
	int			secondary;	/* SROM read as all zero */
	SROM_FORMAT		sr;
	int			leaf;
	int			vendor_21140;
	int			vendor_revision;
	int			promisc;
	int			need_saddr;
	int			max_tx_desc;	/* max xmit descriptors */
	caddr_t 		setup_buf_vaddr; /* setup buffer (virt) */
	uint32_t 		setup_buf_paddr; /* setup buffer (phys) */
	struct tx_desc_type	*tx_desc;	/* virtual addr of xmit desc */
	uint32_t		tx_desc_paddr;	/* physical addr of xmit desc */
	struct rx_desc_type	*rx_desc;	/* virtual addr of recv desc */
	uint32_t		rx_desc_paddr;	/* physical addr of recv desc */
	char			multicast_cnt[MCASTBUF_SIZE];
	ddi_acc_handle_t	io_handle;	/* ddi I/O handle */
	dev_info_t		*devinfo;
	int			max_rx_desc;	/* max recv descriptors */
	ddi_dma_handle_t	dma_handle;
	ddi_dma_handle_t	dma_handle_tx;
	ddi_dma_handle_t	dma_handle_txdesc;
	ddi_dma_handle_t	dma_handle_setbuf;
	int			pgmask;
	ddi_acc_handle_t	setup_buf_acchdl;
	int			nxmit_desc;	/* #of xmit descriptors */
	int			nrecv_desc;	/* #of recv descriptors */
	ddi_acc_handle_t	tx_desc_acchdl;
	ddi_acc_handle_t	rx_desc_acchdl;
	mblk_t			**tx_msgbufp;	/* streams message buffers */
						/* used for xmit */
	caddr_t			*rx_buf_vaddr;	/* recv buf addresses (virt) */
	uint32_t		*rx_buf_paddr;	/* recv buf addresses (phys) */
	kmutex_t		txlock;
	kmutex_t		intrlock;
	boolean_t		suspended;
	boolean_t		running;
	int	need_gld_sched;

	uint32_t	stat_errrcv;
	uint32_t	stat_overflow;
	uint32_t	stat_intr;
	uint32_t	stat_defer;
	uint32_t	stat_missed;
	uint32_t	stat_norcvbuf;
	uint32_t	stat_crc;
	uint32_t	stat_short;
	uint32_t	stat_frame;
	uint32_t	stat_errxmt;
	uint32_t	stat_collisions;
	uint32_t	stat_xmtlatecoll;
	uint32_t	stat_excoll;
	uint32_t	stat_underflow;
	uint32_t	stat_nocarrier;
	int			tx_current_desc; /* Current Tx descriptor */
	int 			rx_current_desc; /* Current descriptor of Rx  */
	int			transmitted_desc; /* Descriptor count xmitted */
	int 			free_desc;	/* Descriptors available */
	mii_handle_t		mii;
	int			mii_speed;
	int			mii_duplex;
	int			phyaddr;
	uchar_t		vendor_addr[ETHERADDRL];
	uchar_t		curr_macaddr[ETHERADDRL];
	media_block_t		*selected_media_block;
	uint32_t		disallowed_media;
	int			disable_scrambler;
	int			overrun_workaround;
	int			interrupts_disabled;
	int			mii_up;
	uint32_t		gprsia; /* Write-through for 143's gprsia reg */
	struct hackintr_inf	*hackintr_inf;
	struct {
		timercb_t	cb;
		uint32_t	start_ticks;
	} timer;
};

#pragma pack(1)

#define	BCOPY(from, to, len) bcopy(from, to, len)

/*
 * Receive descriptor description
 */
struct rx_desc_type {
	struct {
		volatile uint32_t
				overflow	: 01,
				crc 		: 01,
				dribbling	: 01,
				mii_err		: 01,
				rcv_watchdog 	: 01,
				frame_type	: 01,
				collision	: 01,
				frame2long   	: 01,
				last_desc	: 01,
				first_desc	: 01,
				multi_frame  	: 01,
				runt_frame	: 01,
				u_data_type	: 02,
				desc_err	: 01,
				err_summary  	: 01,
				frame_len	: 14,
				filter_fail	: 01,
				own		: 01;
	} desc0;
	struct {
		volatile uint32_t
				buffer_size1 	: 11,
				buffer_size2 	: 11,
				not_used	: 02,
				chaining	: 01,
				end_of_ring	: 01,
				rsvd1		: 06;
	} desc1;
	volatile uint32_t	buffer1;
	volatile uint32_t	buffer2;
};

/*
 * Receive descriptor description
 */
struct tx_desc_type {
	struct {
		volatile uint32_t
				deferred	: 1,
				underflow	: 1,
				link_fail	: 1,
				collision_count : 4,
				heartbeat_fail	: 1,
				excess_collision : 1,
				late_collision	: 1,
				no_carrier	: 1,
				carrier_loss	: 1,
				rsvd1		: 2,
				tx_jabber_to	: 1,
				err_summary	: 1,
				rsvd		: 15,
				own		: 1;
	} desc0;
	struct {
		volatile uint32_t
				buffer_size1 	: 11,
				buffer_size2 	: 11,
				filter_type0 	: 1,
				disable_padding : 1,
				chaining 	: 1,
				end_of_ring  	: 1,
				crc_disable  	: 1,
				setup_packet 	: 1,
				filter_type1 	: 1,
				first_desc   	: 1,
				last_desc    	: 1,
				int_on_comp  	: 1;
	} desc1;
	volatile uint32_t	buffer1;
	volatile uint32_t	buffer2;
};


#define	DNET_END_OF_RING	0x2000000

#pragma pack()

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_DNET_H */
