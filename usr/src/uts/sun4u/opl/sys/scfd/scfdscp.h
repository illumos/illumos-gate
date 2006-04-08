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
 * All Rights Reserved, Copyright (c) FUJITSU LIMITED 2006
 */

#ifndef	_SCFDSCP_H
#define	_SCFDSCP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/scfd/scfdscpif.h>
/*
 * Discriptor define
 */
#define	SCF_TOTAL_BUFFSIZE	0x00010000	/* Total buff size (64KB) */
#define	SCF_MB_MAXDATALEN	0x00000600	/* Message data max length */
#define	SCF_TXBUFFSIZE		SCF_MB_MAXDATALEN /* Tx buff size (1.5KB) */
#define	SCF_RXBUFFSIZE		SCF_MB_MAXDATALEN /* Rx buff size (1.5KB) */
#define	SCF_TX_SRAM_MAXCOUNT	16		/* Tx SRAM max count (0x6000) */
#define	SCF_RX_SRAM_MAXCOUNT	26		/* Rx SRAM max count (0x6000) */

#define	SCF_TXDSC_CNTROLCOUNT	(2 * MBIF_MAX)	/* TxDSC control count */
#define	SCF_TXDSC_LOCALCOUNT	1 /* TxDSC local count (DSCP_PATH/CONN_CHK) */

#define	SCF_TXDSC_MAXCOUNT	(SCF_TX_SRAM_MAXCOUNT + SCF_TXDSC_CNTROLCOUNT)
						/* TxDSC max count (0x6000) */
#define	SCF_RXDSC_MAXCOUNT	SCF_RX_SRAM_MAXCOUNT
						/* RxDSC max count (0x9c00) */

#define	SCF_TXDSC_BUSYCOUNT	SCF_TX_SRAM_MAXCOUNT	/* TxDSC busy count */
#define	SCF_RXDSC_BUSYCOUNT	SCF_RX_SRAM_MAXCOUNT	/* RxDSC busy count */

/*
 * Re-try max count define
 */
#define	SCF_TX_ACKTO_MAXRETRAYCOUNT	1	/* TxACK timeout */
#define	SCF_TX_ENDTO_MAXRETRAYCOUNT	1	/* TxEND timeout */

#define	SCF_TX_BUSY_MAXRETRAYCOUNT	10	/* TxEND Busy */
#define	SCF_TX_IF_MAXRETRAYCOUNT	1	/* TxEND Interface error */
#define	SCF_TX_NAK_MAXRETRAYCOUNT	1	/* TxEND Connection refusal */
#define	SCF_TX_NOTSUP_MAXRETRAYCOUNT	1	/* TxEND Not support */
#define	SCF_TX_PRMERR_MAXRETRAYCOUNT	1	/* TxEND Parameter error */
#define	SCF_TX_SEQERR_MAXRETRAYCOUNT	1	/* TxEND Sequence error */
#define	SCF_TX_OTHER_MAXRETRAYCOUNT	1	/* TxEND other error */
#define	SCF_TX_SEND_MAXRETRAYCOUNT	3	/* TxEND send */

/*
 * Que max count define
 */
#define	SCF_RDQUE_MAXCOUNT	SCF_RXDSC_MAXCOUNT	/* Recv data */
#define	SCF_RDQUE_BUSYCOUNT	SCF_RDQUE_MAXCOUNT	/* Recv data */

#define	SCF_MB_EVQUE_MAXCOUNT	(SCF_RDQUE_MAXCOUNT + 4) /* Event */

/*
 * Mailbox interface code
 */
typedef enum {
	MBIF_DSCP,			/* DSCP mailbox interface code */
	MBIF_DKMD,			/* DKMD mailbox interface code */
					/* Add mailbox interface code */
	MBIF_MAX			/* Max interface code */
} scf_mbif_t;

/*
 * Callback event queue
 */
typedef struct scf_event_que {
	scf_event_t	mevent;			/* Event types */
} scf_event_que_t;

/*
 * Recv data queue
 */
typedef struct scf_rdata_que {
	caddr_t		rdatap;			/* Recv data address */
	uint32_t	length;			/* Recv data length */
} scf_rdata_que_t;

/*
 * DSCP main control table
 */
typedef struct scf_dscp_main {
	/* main status */
	uint16_t	status;			/* Main status */
	uint16_t	old_status;		/* Old main status */
	uint8_t		id;			/* Table No. */
	uint8_t		rsv[3];			/* reserved */

	/* flag/code */
	uint_t		conn_chk_flag;		/* DSCP connect check flag */

	/* init() parameter */
	target_id_t	target_id;	/* Target ID specifying the peer */
	mkey_t		mkey;			/* Data type for mailbox key */
	void		(*event_handler)(scf_event_t, void *);
					/* event handler function */
	scf_event_t	mevent;			/* Event types */
	void		*arg;			/* Callback argument */

	/* cv_init() condition */
	uint_t		cv_init_flag;		/* cv_init call flag */
	kcondvar_t	fini_cv;		/* fint() condition variables */
	uint_t		fini_wait_flag;		/* fini wait flag */

	/* flag */
	uint_t		putmsg_busy_flag;	/* putmsg busy flag */

	/* memo counter */
	uint_t		memo_tx_data_req_cnt;	/* Tx DATA_REQ counter */
	uint_t		memo_tx_data_req_ok_cnt; /* Tx DATA_REQ ok counter */
	uint_t		memo_rx_data_req_cnt;	/* Rx DATA_REQ counter */
	uint_t		memo_rx_data_req_ok_cnt; /* Rx DATA_REQ ok counter */
	uint_t		memo_putmsg_busy_cnt;	/* putmsg busy counter */
	uint_t		memo_putmsg_enospc_cnt;	/* putmsg ENOSPC counter */

	/* Event/Recv data regulation counter */
	uint_t		ev_maxcount;		/* Event max count */
	uint_t		rd_maxcount;		/* Recv data max count */
	uint_t		rd_busycount;		/* Recv data busy count */

	/* Event/Recv data working counter */
	uint_t		ev_count;		/* Use event count */
	uint_t		rd_count;		/* Use recv data count */

	/* Event/Recv data table address and size */
	scf_event_que_t	*ev_quep;		/* Event table pointer */
	uint_t		ev_quesize;		/* Event table size */
	scf_rdata_que_t	*rd_datap;		/* Recv data table pointer */
	uint_t		rd_datasize;		/* Recv data table size */

	/* Event/Recv data offset */
	uint16_t	ev_first;		/* Event first */
	uint16_t	ev_last;		/* Event last */
	uint16_t	ev_put;			/* Event put */
	uint16_t	ev_get;			/* Event get */
	uint16_t	rd_first;		/* Recv data first */
	uint16_t	rd_last;		/* Recv data last */
	uint16_t	rd_put;			/* Recv data put */
	uint16_t	rd_get;			/* Recv data get */
} scf_dscp_main_t;

/*
 * DCR/DSR register table
 */
typedef union scf_dscreg {
	/* Basic code format */
	struct {
		uint16_t	c_flag;		/* Control flag (DCR/DSR) */
		uint16_t	offset;		/* SRAM offset (DCR/DSR) */
		uint32_t	length;		/* Data length (DCR) */
		caddr_t		dscp_datap;	/* KMEM data address */
	} base;
	/* TxDCR/RxDCR bit format */
	struct {				/* DCR bit format */
		unsigned	id		: 4;	/* control id */
		unsigned	code		: 4;	/* control code */

		unsigned	emergency	: 1;	/* emergency flag */
		unsigned	interrupt	: 1;	/* interrupt flag */
		unsigned			: 2;
		unsigned	first		: 1;	/* first data flag */
		unsigned	last		: 1;	/* last data flag */
		unsigned			: 2;
	} bdcr;
	/* TxDSR/RxDSR bit format */
	struct {				/* DSR bit format */
		unsigned	id		: 4;	/* control id */
		unsigned	code		: 4;	/* control code */

		unsigned	status		: 8;	/* complete status */
	} bdsr;
} scf_dscreg_t;

/*
 * DSCP Tx/Rx discriptor table
 */
typedef struct scf_dscp_dsc {
	/* TxDSC/RxDSC status */
	uint16_t	status;			/* Tx/Rx status */
	uint16_t	old_status;		/* Old Tx/Rx status */

	/* DCR/DSR interface area */
	scf_dscreg_t	dinfo;			/* DCR/DSR register table */
} scf_dscp_dsc_t;

/*
 * DSCP Tx SRAM table
 */
typedef struct scf_tx_sram {
	uint16_t	use_flag;		/* Tx SRAM use flag */
	uint16_t	offset;			/* Tx SRAM offset */
} scf_tx_sram_t;

/*
 * DSCP common table
 */
typedef struct scf_dscp_comtbl {
	/* DSCP main control table */
	scf_dscp_main_t	scf_dscp_main[MBIF_MAX]; /* DSCP main table */

	/* flag/code */
	uint_t		dscp_init_flag;		/* DSCP interface init flag */
	uint_t		tx_exec_flag;		/* TxREQ exec flag */
	uint_t		rx_exec_flag;		/* RxREQ exec flag */
	uint_t		callback_exec_flag;	/* Callback exec flag */
	uint_t		dscp_path_flag;		/* DSCP path change flag */
	uint_t		tx_local_use_flag; /* Use local control TxDSC flag */

	/* size */
	uint_t		maxdatalen;		/* Message data max length */
	uint_t		total_buffsize;		/* Total buff size */
	uint_t		txbuffsize;		/* Tx buff size */
	uint_t		rxbuffsize;		/* Rx buff size */

	/* TxDSC/RxDSC/Event regulation counter */
	uint_t		txsram_maxcount;	/* TxDSC SRAM max count */
	uint_t		rxsram_maxcount;	/* RxDSC SRAM max count */
	uint_t		txdsc_maxcount;		/* TxDSC max count */
	uint_t		rxdsc_maxcount;		/* RxDSC max count */
	uint_t		txdsc_busycount;	/* TxDSC busy count */
	uint_t		rxdsc_busycount;	/* RxDSC busy count */

	/* TxDSC re-try max count */
	uint_t		tx_ackto_maxretry_cnt;	/* TxACK timeout */
	uint_t		tx_endto_maxretry_cnt;	/* TxEND timeout */

	uint_t		tx_busy_maxretry_cnt;	/* TxEND busy */
	uint_t		tx_interface_maxretry_cnt; /* TxEND Interface error */
	uint_t		tx_nak_maxretry_cnt;	/* TxEND Connection refusal */
	uint_t		tx_notsup_maxretry_cnt;	/* TxEND Not support */
	uint_t		tx_prmerr_maxretry_cnt;	/* TxEND Parameter error */
	uint_t		tx_seqerr_maxretry_cnt;	/* TxEND Sequence erro */
	uint_t		tx_other_maxretry_cnt;	/* TxEND other error */
	uint_t		tx_send_maxretry_cnt;	/* TxEND send */

	/* TxDSC/RxDSC working counter */
	uint_t		tx_dsc_count;		/* Use TxDSC count */
	uint_t		rx_dsc_count;		/* Use RxDSC count */
	uint_t		tx_sram_count;		/* Use Tx SRAM count */

	/* TxDSC/RxDSC working re-try counter */
	uint_t		tx_ackto_retry_cnt;	/* TxACK timeout */
	uint_t		tx_endto_retry_cnt;	/* TxEND timeout */

	uint_t		tx_busy_retry_cnt;	/* TxEND busy */
	uint_t		tx_interface_retry_cnt;	/* TxEND Interface error */
	uint_t		tx_nak_retry_cnt;	/* TxEND Connection refusal */
	uint_t		tx_notsuop_retry_cnt;	/* TxEND Not support */
	uint_t		tx_prmerr_retry_cnt;	/* TxEND Parameter error */
	uint_t		tx_seqerr_retry_cnt;	/* TxEND Sequence error */
	uint_t		tx_other_retry_cnt;	/* TxEND other error */
	uint_t		tx_send_retry_cnt;	/* TxEND send */

	/* TxDSC/RxDSC memo counter */
	uint_t		tx_ackto_memo_cnt;	/* TxACK timeout */
	uint_t		tx_endto_memo_cnt;	/* TxEND timeout */
	uint_t		tx_busy_memo_cnt;	/* TxEND busy */
	uint_t		tx_interface_memo_cnt;	/* TxEND Interface error */
	uint_t		tx_nak_memo_cnt;	/* TxEND Connection refusal */
	uint_t		tx_notsuop_memo_cnt;	/* TxEND Not support */
	uint_t		tx_prmerr_memo_cnt;	/* TxEND Parameter error */
	uint_t		tx_seqerr_memo_cnt;	/* TxEND Sequence error */
	uint_t		tx_other_memo_cnt;	/* TxEND other error */
	uint_t		scf_stop_memo_cnt;	/* SCF path stop */

	/* TxDSC table address and size */
	scf_dscp_dsc_t	*tx_dscp;		/* TxDSC table pointer */
	uint_t		tx_dscsize;		/* TxDSC table size */
	/* RxDSC table address and size */
	scf_dscp_dsc_t	*rx_dscp;		/* RxDSC table pointer */
	uint_t		rx_dscsize;		/* RxDSC table size */
	/* Tx SRAM table address and size */
	scf_tx_sram_t	*tx_sramp;		/* Tx SRAM table pointer */
	uint_t		tx_sramsize;		/* Tx SRAM table size */

	/* TxDSC offset */
	uint16_t	tx_first;		/* TxDSC first offset */
	uint16_t	tx_last;		/* TxDSC last offset */
	uint16_t	tx_put;			/* TxDSC put offset */
	uint16_t	tx_get;			/* TxDSC get offset */
	uint16_t	tx_local;		/* Local control TxDSC offset */

	/* TxDSC/RxDSC offset */
	uint16_t	rx_first;		/* RxDSC first offset */
	uint16_t	rx_last;		/* RxDSC last offset */
	uint16_t	rx_put;			/* RxDSC put offset */
	uint16_t	rx_get;			/* RxDSC get offset */

	/* Tx SRAM offset */
	uint16_t	tx_sram_first;		/* Tx SRAM first offset */
	uint16_t	tx_sram_last;		/* Tx SRAM last offset */
	uint16_t	tx_sram_put;		/* Tx SRAM put offset */

} scf_dscp_comtbl_t;

/*
 * DSCP main status (scf_dscp_main_t : status)
 */
	/* (A0) Cconnection idle state */
#define	SCF_ST_IDLE			0x0000

#ifdef	_SCF_SP_SIDE
	/* (A1) init() after, INIT_REQ recv state */
#define	SCF_ST_EST_INIT_REQ_RECV_WAIT	0x0001
#else	/* _SCF_SP_SIDE */
	/* (B0) Send INIT_REQ, TxEND recv wait state */
#define	SCF_ST_EST_TXEND_RECV_WAIT	0x0010
#endif	/* _SCF_SP_SIDE */

	/* (C0) Connection establishment state */
#define	SCF_ST_ESTABLISHED		0x0020
	/* (C1) Recv FINI_REQ, fini() wait state */
#define	SCF_ST_EST_FINI_WAIT		0x0021
	/* (D0) Send FINI_REQ, TxEND recv wait state */
#define	SCF_ST_CLOSE_TXEND_RECV_WAIT	0x0030

/*
 * DSCP Tx discriptor status (scf_dscp_dsc_t : status)
 */
	/* (SA0) Idle state */
#define	SCF_TX_ST_IDLE			0x0000
	/* (SB0) TxREQ send wait & SRAM trans wait state */
#define	SCF_TX_ST_SRAM_TRANS_WAIT	0x0010

#ifdef	_SCF_SP_SIDE
	/* (SB1) TxREQ send wait & SRAM trans comp wait state */
#define	SCF_TX_ST_SRAM_COMP_WAIT	0x0011
#endif	/* _SCF_SP_SIDE */

	/* (SB2) TxREQ send wait & TxREQ send wait state */
#define	SCF_TX_ST_TXREQ_SEND_WAIT	0x0012
	/* (SC0) Send TxREQ, TxACK recv wait state */
#define	SCF_TX_ST_TXACK_RECV_WAIT	0x0020
	/* (SC1) Send TxREQ, TxEND recv wait state */
#define	SCF_TX_ST_TXEND_RECV_WAIT	0x0021

/*
 * DSCP Rx discriptor status (scf_dscp_dsc_t : status)
 */
	/* (RA0) Idle state */
#define	SCF_RX_ST_IDLE			0x0000
	/* (RB0) Recv RxREQ, RxACK send wait state */
#define	SCF_RX_ST_RXACK_SEND_WAIT	0x0010
	/* (RB1) Recv RxREQ, SRAM trans wait state */
#define	SCF_RX_ST_SRAM_TRANS_WAIT	0x0011

#ifdef	_SCF_SP_SIDE
	/* (RB2) Recv RxREQ, SRAM comp wait state */
#define	SCF_RX_ST_SRAM_COMP_WAIT	0x0012
#endif	/* _SCF_SP_SIDE */

	/* (RB3) Recv RxREQ, RxEND send wait state */
#define	SCF_RX_ST_RXEND_SEND_WAIT	0x0013

/*
 * DSC controlflag (scf_dscreg_t : c_flag)
 */
#define	DSC_FLAG_DEFAULT	0x004c		/* Default flag */
				/* emergency=0, interrupt=1, first=1, last=0 */
/*
 * DSC controlflag (scf_dscreg_t : id)
 */
#define	DSC_CNTL_MASK_ID	0x0f		/* Mask id */

#define	DSC_CNTL_DSCP		0x0		/* DSCP mailbox interface */
#define	DSC_CNTL_DKMD		0x1		/* DKMD mailbox interface */
#define	DSC_CNTL_LOCAL		0xe		/* Local interface */
#define	DSC_CNTL_POST		0xf	/* Post diag interface (not use) */

/*
 * DSC controlflag (scf_dscreg_t : code)
 */
#define	DSC_CNTL_MASK_CODE	0x0f		/* Mask code */

#define	DSC_CNTL_DATA_REQ	0x0		/* DATA REQ */
#define	DSC_CNTL_INIT_REQ	0x1		/* INIT_REQ */
#define	DSC_CNTL_FINI_REQ	0x2		/* FINI_REQ */
#define	DSC_CNTL_FLUSH_REQ	0x3		/* FLUSH_REQ */
#define	DSC_CNTL_CONN_CHK	0xf		/* CONN_CHK */

/*
 * DSC controlflag (scf_dscreg_t : code) id = DSC_CNTL_LOCAL
 */
#define	DSC_CNTL_DSCP_PATH	0x0		/* DSCP_PATH */

/*
 * DSC controlflag (scf_dscreg_t : status)
 */
#define	DSC_STATUS_NORMAL		0x00	/* Normal end */
#define	DSC_STATUS_BUF_BUSY		0x01	/* Buffer busy */
#define	DSC_STATUS_INTERFACE		0x03	/* Interface error */
#define	DSC_STATUS_CONN_NAK		0x04	/* Connection refusal */
#define	DSC_STATUS_E_NOT_SUPPORT	0x08	/* Not support */
#define	DSC_STATUS_E_PARAM		0x09	/* Parameter error */
#define	DSC_STATUS_E_SEQUENCE		0x0d	/* Sequence error */

/*
 * DSC controlflag (scf_dscreg_t : offset)
 */
#define	DSC_OFFSET_NOTHING	0xffff		/* DSC offset nothing value */
#define	DSC_OFFSET_CONVERT	16		/* DSC offset convert size */

/*
 * scf_dscp_sram_get() return value
 */
#define	TX_SRAM_GET_ERROR	0xffff		/* Tx SRAM get error value */

/*
 * Main status change macro
 */
#define	SCF_SET_STATUS(p, st)						\
	p->old_status = p->status;					\
	p->status = st;							\
	SCFDBGMSG2(SCF_DBGFLAG_DSCP,					\
		"main status change = 0x%04x 0x%04x",			\
		p->status, p->old_status)
/*
 * TxDSC/RxDSC status change macro
 */
#define	SCF_SET_DSC_STATUS(p, st)					\
	p->old_status = p->status;					\
	p->status = st;							\
	SCFDBGMSG2(SCF_DBGFLAG_DSCP,					\
		"DSC status change = 0x%04x 0x%04x",			\
		p->status, p->old_status)

/*
 * Use scf_dscp_tx_mat_notice() code
 */
#define	TxEND			(uint8_t)0x80	/* TxEND */
#define	TxREL_BUSY		(uint8_t)0xf0	/* Relese busy */

/*
 * Use scf_dscp_rx_mat_notice() code
 */
#define	RxREQ			(uint8_t)0x80	/* RxREQ */
#define	RxDATA			(uint8_t)0xf0	/* RxDATA */

#ifdef	__cplusplus
}
#endif

#endif	/* _SCFDSCP_H */
