/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1998, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SMCP_H
#define	_SMCP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Driver declarations for the SMC Generic UMAC	driver
 */

#ifdef	__cplusplus
extern "C" {
#endif


/* debug flags */
#define	SMCGTRACE	0x01
#define	SMCGERRS	0x02
#define	SMCGRECV	0x04
#define	SMCGDDI		0x08
#define	SMCGSEND	0x10
#define	SMCGINT		0x20
#define	SMCGALAN	0x40

/* Misc	*/
#define	SMCGHIWAT	65536		/* driver flow control high water */
#define	SMCGLOWAT	16384		/* driver flow control low water */
#define	SMCGMAXPKT	1500		/* maximum media frame size */

/* Definitions for the field bus_type */
#define	SMCG_AT_BUS	0x00
#define	SMCG_EISA_BUS	0x02
#define	SMCG_PCI_BUS	0x03

/* Function declarations */
int LM_Nextcard(Adapter_Struc *);
void LM_Get_Addr(Adapter_Struc *);
void LM_Set_Addr(Adapter_Struc *);
void LM_Reset_Adapter(Adapter_Struc *);
int LM_GetCnfg(Adapter_Struc *);
int LM_Initialize_Adapter(Adapter_Struc *);
int LM_Open_Adapter(Adapter_Struc *);
int LM_Close_Adapter(Adapter_Struc *);
int LM_Add_Multi_Address(Adapter_Struc *);
int LM_Delete_Multi_Address(Adapter_Struc *);
int LM_Change_Receive_Mask(Adapter_Struc *);
int LM_Send(Data_Buff_Structure *, Adapter_Struc *, int);
int LM_Service_Events(Adapter_Struc *);
int LM_Disable_Adapter(Adapter_Struc *);
int LM_Enable_Adapter(Adapter_Struc *);
int LM_Receive_Copy(int, int, Data_Buff_Structure *, Adapter_Struc *, int);
int LM_Put_Rx_Frag(Data_Buff_Structure *, Adapter_Struc *);
int LM_Get_Host_Ram_Size(Adapter_Struc *);
void LM_Reap_Xmits(Adapter_Struc *);

int UM_Receive_Packet(char *, unsigned short, Adapter_Struc *, int,
	Data_Buff_Structure **);
int UM_PCI_Services(Adapter_Struc *pAd, union REGS *pregs);
int UM_Status_Change(Adapter_Struc *);
int UM_Receive_Copy_Complete(Adapter_Struc *);
int UM_Send_Complete(int, Adapter_Struc *);
int UM_Interrupt(Adapter_Struc *);

#define	SMCG_MAX_TX_MBLKS	(SMCG_MAX_TX_FRAGS/2)

struct smcg_rx_buffer_desc {
	frtn_t			free_rtn; /* Must be first element */
	struct smcg_info	*smcg;
	caddr_t			buf;	/* Pointer to dma-able data buffer */
	ulong_t			physaddr;	/* Physical address of data */
	struct smcg_rx_buffer_desc	*next;
	ddi_dma_handle_t		dmahandle;
	ddi_acc_handle_t		acchandle;
};

struct txpkt_info {
	ddi_dma_handle_t		dmahandle[SMCG_MAX_TX_MBLKS];
	int				handles_bound;
	mblk_t				*mptr;
};

/* SMC Generic UMAC structure */

typedef
struct smcg_info {
	gld_mac_info_t		*smcg_macinfo;
	dev_info_t		*smcg_devinfo;
	Adapter_Struc		*smcg_pAd;
	int			smcg_multicount; /* current multicast count */
	int			smcg_need_gld_sched; /* flag */
	ddi_dma_handle_t	hostram_dmahandle;
	ddi_acc_handle_t	hostram_acchandle;

	/* Stuff for keeping track of receive buffers */
	caddr_t				rxbdesc_mem;
	struct smcg_rx_buffer_desc	*rx_freelist;
	struct smcg_rx_buffer_desc	*bdesc[SMCG_MAX_RXDESCS];
	int				rx_ring_index;
	kmutex_t			rbuf_lock;
	kmutex_t			rlist_lock;
	int				rx_bufs_outstanding;
	Data_Buff_Structure		smc_dbuf;
	int				detaching_flag;

	/* Stuff for keeping track of transmit packets */
	int				tx_ring_head;
	int				tx_ring_tail;
	struct txpkt_info		tx_info[SMCG_MAX_TXDESCS];
	kmutex_t			txbuf_lock;

	/* Stuff for keeping track of LMAC */
	kmutex_t			lm_lock;
	mblk_t				*rq_first;
	mblk_t				*rq_last;

	/* Storage for statistics */
	ulong_t			rx_CRC_errors;
	ulong_t			rx_too_big;
	ulong_t			rx_lost_pkts;
	ulong_t			rx_align_errors;
	ulong_t			rx_overruns;
	ulong_t			tx_deferred;
	ulong_t			tx_total_collisions;
	ulong_t			tx_max_collisions;
	ulong_t			tx_one_collision;
	ulong_t			tx_mult_collisions;
	ulong_t			tx_ow_collision;
	ulong_t			tx_CD_heartbeat;
	ulong_t			tx_carrier_lost;
	ulong_t			tx_underruns;
	ulong_t			ring_OVW;
	/* Stats added in conversion to v2 */
	uint32_t		intr;
	uint32_t		norcvbuf;
	uint32_t		short_count;
	uint64_t		speed;
	uint32_t		media;
	uint32_t		duplex;
} smcg_t;

/*
 * **************************************************************************
 * Definitions for the field:
 * line_speed
 * Note: copied from lmstruct.h
 */
#define	LINE_SPEED_UNKNOWN	0x0000
#define	LINE_SPEED_4		0x0001
#define	LINE_SPEED_10		0x0002
#define	LINE_SPEED_16		0x0004
#define	LINE_SPEED_100		0x0008
#define	LINE_SPEED_T4		0x0008  /* 100BaseT4 aliased for 9332BVT */
#define	LINE_SPEED_FULL_DUPLEX	0x8000

/*
 * **************************************************************************
 * Definitions for the field:
 * media_type2
 * Note: copied from lmstruct.h
 */
#define	MEDIA_TYPE_MII			0x0001
#define	MEDIA_TYPE_UTP			0x0002
#define	MEDIA_TYPE_BNC			0x0004
#define	MEDIA_TYPE_AUI			0x0008
#define	MEDIA_TYPE_S10			0x0010
#define	MEDIA_TYPE_AUTO_SENSE		0x1000
#define	MEDIA_TYPE_AUTO_DETECT		0x4000
#define	MEDIA_TYPE_AUTO_NEGOTIATE	0x8000


#ifdef	__cplusplus
}
#endif

#endif	/* _SMCP_H */
