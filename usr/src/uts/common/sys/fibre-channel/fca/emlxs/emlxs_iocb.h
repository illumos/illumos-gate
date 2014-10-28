/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at
 * http://www.opensource.org/licenses/cddl1.txt.
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
 * Copyright (c) 2004-2011 Emulex. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _EMLXS_IOCB_H
#define	_EMLXS_IOCB_H

#ifdef	__cplusplus
extern "C" {
#endif

/* ==== IOCB Commands ==== */

#define	CMD_RCV_SEQUENCE_CX	0x01
#define	CMD_XMIT_SEQUENCE_CR	0x02
#define	CMD_XMIT_SEQUENCE_CX	0x03
#define	CMD_XMIT_BCAST_CN	0x04
#define	CMD_XMIT_BCAST_CX	0x05
#define	CMD_QUE_RING_BUF_CN	0x06
#define	CMD_QUE_XRI_BUF_CX	0x07
#define	CMD_IOCB_CONTINUE_CN	0x08
#define	CMD_RET_XRI_BUF_CX	0x09
#define	CMD_ELS_REQUEST_CR	0x0A
#define	CMD_ELS_REQUEST_CX	0x0B
#define	CMD_RCV_ELS_REQ_CX	0x0D
#define	CMD_ABORT_XRI_CN	0x0E
#define	CMD_ABORT_XRI_CX	0x0F
#define	CMD_CLOSE_XRI_CN	0x10
#define	CMD_CLOSE_XRI_CX	0x11
#define	CMD_CREATE_XRI_CR	0x12
#define	CMD_CREATE_XRI_CX	0x13
#define	CMD_GET_RPI_CN		0x14
#define	CMD_XMIT_ELS_RSP_CX	0x15
#define	CMD_GET_RPI_CR		0x16
#define	CMD_XRI_ABORTED_CX	0x17
#define	CMD_FCP_IWRITE_CR	0x18
#define	CMD_FCP_IWRITE_CX	0x19
#define	CMD_FCP_IREAD_CR	0x1A
#define	CMD_FCP_IREAD_CX	0x1B
#define	CMD_FCP_ICMND_CR	0x1C
#define	CMD_FCP_ICMND_CX	0x1D
#define	CMD_FCP_TSEND_CX	0x1F	/* FCP_TARGET_MODE */
#define	CMD_ADAPTER_MSG		0x20
#define	CMD_FCP_TRECEIVE_CX	0x21	/* FCP_TARGET_MODE */
#define	CMD_ADAPTER_DUMP	0x22
#define	CMD_FCP_TRSP_CX		0x23	/* FCP_TARGET_MODE */
#define	CMD_FCP_AUTO_TRSP_CX	0x29	/* FCP_TARGET_MODE */

/* LP3000 gasket IOCB Command Set */

#define	CMD_BPL_IWRITE_CR	0x48
#define	CMD_BPL_IWRITE_CX	0x49
#define	CMD_BPL_IREAD_CR	0x4A
#define	CMD_BPL_IREAD_CX	0x4B
#define	CMD_BPL_ICMND_CR	0x4C
#define	CMD_BPL_ICMND_CX	0x4D

#define	CMD_ASYNC_STATUS	0x7C

/* SLI_2 IOCB Command Set */
#define	CMD_RCV_SEQUENCE64_CX	0x81
#define	CMD_XMIT_SEQUENCE64_CR	0x82
#define	CMD_XMIT_SEQUENCE64_CX	0x83
#define	CMD_XMIT_BCAST64_CN	0x84
#define	CMD_XMIT_BCAST64_CX	0x85
#define	CMD_QUE_RING_BUF64_CN	0x86
#define	CMD_QUE_XRI_BUF64_CX	0x87
#define	CMD_IOCB_CONTINUE64_CN	0x88
#define	CMD_RET_XRI_BUF64_CX	0x89
#define	CMD_ELS_REQUEST64_CR	0x8A
#define	CMD_ELS_REQUEST64_CX	0x8B
#define	CMD_RCV_ELS_REQ64_CX	0x8D
#define	CMD_XMIT_ELS_RSP64_CX	0x95
#define	CMD_XMIT_BLS_RSP64_CX	0x97
#define	CMD_FCP_IWRITE64_CR	0x98
#define	CMD_FCP_IWRITE64_CX	0x99
#define	CMD_FCP_IREAD64_CR	0x9A
#define	CMD_FCP_IREAD64_CX	0x9B
#define	CMD_FCP_ICMND64_CR	0x9C
#define	CMD_FCP_ICMND64_CX	0x9D
#define	CMD_FCP_TSEND64_CX	0x9F	/* FCP_TARGET_MODE */
#define	CMD_FCP_TRECEIVE64_CX	0xA1	/* FCP_TARGET_MODE */
#define	CMD_FCP_TRSP64_CX	0xA3	/* FCP_TARGET_MODE */
#define	CMD_RCV_SEQ64_CX	0xB5	/* SLI3 */
#define	CMD_RCV_ELS64_CX	0xB7	/* SLI3 */
#define	CMD_RCV_CONT64_CX	0xBB	/* SLI3 */
#define	CMD_RCV_SEQ_LIST64_CX	0xC1
#define	CMD_GEN_REQUEST64_CR	0xC2
#define	CMD_GEN_REQUEST64_CX	0xC3
#define	CMD_QUE_RING_LIST64_CN	0xC6


/*
 * Begin Structure Definitions for IOCB Commands
 */

typedef struct
{
#ifdef EMLXS_BIG_ENDIAN
	uint8_t		statAction;
	uint8_t		statRsn;
	uint8_t		statBaExp;
	uint8_t		statLocalError;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint8_t		statLocalError;
	uint8_t		statBaExp;
	uint8_t		statRsn;
	uint8_t		statAction;
#endif
	/* statAction  FBSY reason codes */
#define	FBSY_RSN_MASK	0xF0	/* Rsn stored in upper nibble */
#define	FBSY_FABRIC_BSY	0x10	/* F_bsy due to Fabric BSY */
#define	FBSY_NPORT_BSY	0x30	/* F_bsy due to N_port BSY */

	/* statAction  PBSY action codes */
#define	PBSY_ACTION1	0x01	/* Sequence terminated - retry */
#define	PBSY_ACTION2	0x02	/* Sequence active - retry */

	/* statAction  P/FRJT action codes */
#define	RJT_RETRYABLE	0x01	/* Retryable class of error */
#define	RJT_NO_RETRY	0x02	/* Non-Retryable class of error */

	/* statRsn  LS_RJT reason codes defined in LS_RJT structure */

	/* statRsn  P_BSY reason codes */
#define	PBSY_NPORT_BSY	0x01	/* Physical N_port BSY */
#define	PBSY_RESRCE_BSY	0x03	/* N_port resource BSY */
#define	PBSY_VU_BSY	0xFF	/* See VU field for rsn */

	/* statRsn  P/F_RJT reason codes */
#define	RJT_BAD_D_ID		0x01	/* Invalid D_ID field */
#define	RJT_BAD_S_ID		0x02	/* Invalid S_ID field */
#define	RJT_UNAVAIL_TEMP	0x03	/* N_Port unavailable temp. */
#define	RJT_UNAVAIL_PERM	0x04	/* N_Port unavailable perm. */
#define	RJT_UNSUP_CLASS		0x05	/* Class not supported */
#define	RJT_DELIM_ERR		0x06	/* Delimiter usage error */
#define	RJT_UNSUP_TYPE		0x07	/* Type not supported */
#define	RJT_BAD_CONTROL		0x08	/* Invalid link conrtol */
#define	RJT_BAD_RCTL		0x09	/* R_CTL invalid */
#define	RJT_BAD_FCTL		0x0A	/* F_CTL invalid */
#define	RJT_BAD_OXID		0x0B	/* OX_ID invalid */
#define	RJT_BAD_RXID		0x0C	/* RX_ID invalid */
#define	RJT_BAD_SEQID		0x0D	/* SEQ_ID invalid */
#define	RJT_BAD_DFCTL		0x0E	/* DF_CTL invalid */
#define	RJT_BAD_SEQCNT		0x0F	/* SEQ_CNT invalid */
#define	RJT_BAD_PARM		0x10	/* Param. field invalid */
#define	RJT_XCHG_ERR		0x11	/* Exchange error */
#define	RJT_PROT_ERR		0x12	/* Protocol error */
#define	RJT_BAD_LENGTH		0x13	/* Invalid Length */
#define	RJT_UNEXPECTED_ACK	0x14	/* Unexpected ACK */
#define	RJT_LOGIN_REQUIRED	0x16	/* Login required */
#define	RJT_TOO_MANY_SEQ	0x17	/* Excessive sequences */
#define	RJT_XCHG_NOT_STRT	0x18	/* Exchange not started */
#define	RJT_UNSUP_SEC_HDR	0x19	/* Security hdr not supported */
#define	RJT_UNAVAIL_PATH	0x1A	/* Fabric Path not available */
#define	RJT_VENDOR_UNIQUE	0xFF	/* Vendor unique error */

	/* statRsn  BA_RJT reason codes */
#define	BARJT_BAD_CMD_CODE	0x01	/* Invalid command code */
#define	BARJT_LOGICAL_ERR	0x03	/* Logical error */
#define	BARJT_LOGICAL_BSY	0x05	/* Logical busy */
#define	BARJT_PROTOCOL_ERR	0x07	/* Protocol error */
#define	BARJT_VU_ERR		0xFF	/* Vendor unique error */

	/* LS_RJT reason explanation defined in LS_RJT structure */

	/* BA_RJT reason explanation */
#define	BARJT_EXP_INVALID_ID	0x01	/* Invalid OX_ID/RX_ID */
#define	BARJT_EXP_ABORT_SEQ	0x05	/* Abort SEQ, no more info */

	/* Local Reject errors */
#define	IOERR_SUCCESS			0x00
#define	IOERR_MISSING_CONTINUE		0x01
#define	IOERR_SEQUENCE_TIMEOUT		0x02
#define	IOERR_INTERNAL_ERROR		0x03
#define	IOERR_INVALID_RPI		0x04
#define	IOERR_NO_XRI			0x05
#define	IOERR_ILLEGAL_COMMAND		0x06
#define	IOERR_XCHG_DROPPED		0x07
#define	IOERR_ILLEGAL_FIELD		0x08
/* RESERVED 0x09 */
/* RESERVED 0x0A */
#define	IOERR_RCV_BUFFER_WAITING	0x0B
/* RESERVED 0x0C */
#define	IOERR_TX_DMA_FAILED		0x0D
#define	IOERR_RX_DMA_FAILED		0x0E
#define	IOERR_ILLEGAL_FRAME		0x0F

/* RESERVED 0x10 */
#define	IOERR_NO_RESOURCES		0x11
/* RESERVED 0x12 */
#define	IOERR_ILLEGAL_LENGTH		0x13
#define	IOERR_UNSUPPORTED_FEATURE	0x14
#define	IOERR_ABORT_IN_PROGRESS		0x15
#define	IOERR_ABORT_REQUESTED		0x16
#define	IOERR_RCV_BUFFER_TIMEOUT	0x17
#define	IOERR_LOOP_OPEN_FAILURE		0x18
#define	IOERR_RING_RESET		0x19
#define	IOERR_LINK_DOWN			0x1A
#define	IOERR_CORRUPTED_DATA		0x1B
#define	IOERR_CORRUPTED_RPI		0x1C
#define	IOERR_OUT_OF_ORDER_DATA		0x1D
#define	IOERR_OUT_OF_ORDER_ACK		0x1E
#define	IOERR_DUP_FRAME			0x1F

#define	IOERR_LINK_CONTROL_FRAME	0x20	/* ACK_N received */
#define	IOERR_BAD_HOST_ADDRESS		0x21
#define	IOERR_RCV_HDRBUF_WAITING	0x22
#define	IOERR_MISSING_HDR_BUFFER	0x23
#define	IOERR_MSEQ_CHAIN_CORRUPTED	0x24
#define	IOERR_ABORTMULT_REQUESTED	0x25
/* RESERVED 0x26 */
/* RESERVED 0x27 */
#define	IOERR_BUFFER_SHORTAGE		0x28
#define	IOERR_XRIBUF_WAITING		0x29
/* RESERVED 0x2A */
#define	IOERR_MISSING_HBQ_ENTRY		0x2B
#define	IOERR_ABORT_EXT_REQ		0x2C
#define	IOERR_CLOSE_EXT_REQ		0x2D
#define	IOERR_INVALID_VPI		0x2E
/* RESERVED 0x2F */

#define	IOERR_XRIBUF_MISSING		0x30
#define	IOERR_ASSI_RSP_SUPPRESSED	0x31
/* RESERVED 0x32 - 0x3F */

#define	IOERR_ROFFSET_INVAL		0x40
#define	IOERR_ROFFSET_MISSING		0x41
#define	IOERR_INSUF_BUFFER		0x42
#define	IOERR_MISSING_SI		0x43
#define	IOERR_MISSING_ES		0x44
#define	IOERR_INCOMP_XFER		0x45
/* RESERVED 0x46 - 0xFF */

	/* Driver defined */
#define	IOERR_ABORT_TIMEOUT		0xF0
} PARM_ERR;

typedef union
{
	struct
	{
#ifdef EMLXS_BIG_ENDIAN
		uint8_t		Rctl;	/* R_CTL field */
		uint8_t		Type;	/* TYPE field */
		uint8_t		Dfctl;	/* DF_CTL field */
		uint8_t		Fctl;	/* Bits 0-7 of IOCB word 5 */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
		uint8_t		Fctl;	/* Bits 0-7 of IOCB word 5 */
		uint8_t		Dfctl;	/* DF_CTL field */
		uint8_t		Type;	/* TYPE field */
		uint8_t		Rctl;	/* R_CTL field */
#endif
#define	FCP_RTYPE	0x08	/* FCP_TARGET_MODE Type - Rctl */

#define	BC		0x02	/* Broadcast Received  - Fctl */
#define	SI		0x04	/* Sequence Initiative */
#define	LA		0x08	/* Ignore Link Attention state */
#define	FSEQ		0x40	/* First Sequence */
#define	LSEQ		0x80	/* Last Sequence */
	} hcsw;
	uint32_t	reserved;
} WORD5;


/* IOCB Command template for a generic response */
typedef struct
{
	uint32_t	reserved[4];
	PARM_ERR	perr;
} GENERIC_RSP;


/* IOCB Command template for XMIT / XMIT_BCAST / RCV_SEQUENCE / XMIT_ELS */
typedef struct
{
	ULP_BDE		xrsqbde[2];
	uint32_t	xrsqRo;		/* Starting Relative Offset */
	WORD5		w5;		/* Header control/status word */
} XR_SEQ_FIELDS;

/* IOCB Command template for ELS_REQUEST */
typedef struct
{
	ULP_BDE		elsReq;
	ULP_BDE		elsRsp;
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	word4Rsvd:7;
	uint32_t	fl:1;
	uint32_t	myID:24;

	uint32_t	word5Rsvd:8;
	uint32_t	remoteID:24;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	myID:24;
	uint32_t	fl:1;
	uint32_t	word4Rsvd:7;

	uint32_t	remoteID:24;
	uint32_t	word5Rsvd:8;
#endif
} ELS_REQUEST;

/* IOCB Command template for RCV_ELS_REQ */
typedef struct
{
	ULP_BDE		elsReq[2];
	uint32_t	parmRo;
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	word5Rsvd:8;
	uint32_t	remoteID:24;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	remoteID:24;
	uint32_t	word5Rsvd:8;
#endif
} RCV_ELS_REQ;

/* IOCB Command template for ABORT / CLOSE_XRI */
typedef struct
{
	uint32_t	rsvd[3];
	uint32_t	abortType;
#define	ABORT_TYPE_ABTX		0x00000000
#define	ABORT_TYPE_ABTS		0x00000001
	uint32_t	parm;
#ifdef EMLXS_BIG_ENDIAN
	uint16_t	abortContextTag;	/* ulpContext from command to */
						/* abort/close */
	uint16_t	abortIoTag;		/* ulpIoTag from command to */
						/* abort/close */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t	abortIoTag;		/* ulpIoTag from command to */
						/* abort/close */
	uint16_t	abortContextTag;	/* ulpContext from command to */
						/* abort/close */
#endif
} AC_XRI;

/* IOCB Command template for GET_RPI */
typedef struct
{
	uint32_t	rsvd[4];
	uint32_t	parmRo;
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	word5Rsvd:8;
	uint32_t	remoteID:24;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	remoteID:24;
	uint32_t	word5Rsvd:8;
#endif
} GET_RPI;

/* IOCB Command template for all FCP Initiator commands */
typedef struct
{
	ULP_BDE		fcpi_cmnd;	/* FCP_CMND payload descriptor */
	ULP_BDE		fcpi_rsp;	/* Rcv buffer */
	uint32_t	fcpi_parm;
	uint32_t	fcpi_XRdy;	/* transfer ready for IWRITE */
} FCPI_FIELDS;

/* IOCB Command template for all FCP Target commands */
typedef struct
{
	ULP_BDE		fcpt_Buffer[2];	/* FCP_CMND payload descriptor */
	uint32_t	fcpt_Offset;
	uint32_t	fcpt_Length;	/* transfer ready for IWRITE */
} FCPT_FIELDS;

/* SLI-2 IOCB structure definitions */

/* IOCB Command template for 64 bit XMIT / XMIT_BCAST / XMIT_ELS */
typedef struct
{
	ULP_BDL		bdl;
	uint32_t	xrsqRo;	/* Starting Relative Offset */
	WORD5		w5;	/* Header control/status word */
} XMT_SEQ_FIELDS64;


/* IOCB Command template for 64 bit RCV_SEQUENCE64 */
typedef struct
{
	ULP_BDE64	rcvBde;
	uint32_t	rsvd1;
	uint32_t	xrsqRo;	/* Starting Relative Offset */
	WORD5		w5;	/* Header control/status word */
} RCV_SEQ_FIELDS64;

/* IOCB Command template for ELS_REQUEST64 */
typedef struct
{
	ULP_BDL		bdl;
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	word4Rsvd:7;
	uint32_t	fl:1;
	uint32_t	myID:24;

	uint32_t	word5Rsvd:8;
	uint32_t	remoteID:24;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	myID:24;
	uint32_t	fl:1;
	uint32_t	word4Rsvd:7;

	uint32_t	remoteID:24;
	uint32_t	word5Rsvd:8;
#endif
} ELS_REQUEST64;


/* IOCB Command template for ASYNC_STATUS */
typedef struct
{
	ULP_BDL		resv;
	uint32_t	parameter;
#ifdef EMLXS_BIG_ENDIAN
	uint16_t	EventCode;
	uint16_t	SubContext;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t	SubContext;
	uint16_t	EventCode;
#endif
} ASYNC_STATUS;


/* IOCB Command template for QUE_RING_LIST64 */
typedef struct
{
	ULP_BDL		bdl;
	uint32_t	rsvd1;
	uint32_t	rsvd2;
} QUE_RING_LIST64;


/* IOCB Command template for GEN_REQUEST64 */
typedef struct
{
	ULP_BDL		bdl;
	uint32_t	param;	/* Starting Relative Offset */
	WORD5		w5;	/* Header control/status word */
} GEN_REQUEST64;

/* IOCB Command template for RCV_ELS_REQ64 */
typedef struct
{
	ULP_BDE64	elsReq;
	uint32_t	rsvd1;
	uint32_t	parmRo;
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	word5Rsvd:8;
	uint32_t	remoteID:24;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	remoteID:24;
	uint32_t	word5Rsvd:8;
#endif
} RCV_ELS_REQ64;

/* IOCB Command template for all 64 bit FCP Initiator commands */
typedef struct
{
	ULP_BDL		bdl;
	uint32_t	fcpi_parm;
	uint32_t	fcpi_XRdy;	/* transfer ready for IWRITE */
} FCPI_FIELDS64;

/* IOCB Command template for all 64 bit FCP Target commands */
typedef struct
{
	ULP_BDL		bdl;
	uint32_t	fcpt_Offset;
	uint32_t	fcpt_Length;	/* transfer ready for IWRITE */
} FCPT_FIELDS64;

/* IOCB Command template for all 64 bit FCP Target commands */
typedef struct
{
	uint32_t	rsp_length;
	uint32_t	rsvd1;
	uint32_t	rsvd2;
	uint32_t	iotag32;
	uint32_t	status;
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	rsvd:30;
	uint32_t	lnk:1;
#endif /* EMLXS_BIG_ENDIAN */

#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	lnk:1;
	uint32_t	rsvd:30;
#endif /* EMLXS_LITTLE_ENDIAN */
} AUTO_TRSP;


typedef struct
{
	uint32_t	io_tag64_low;	/* Word 8 */
	uint32_t	io_tag64_high;	/* Word 9 */
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	cs_ctl:8;	/* Word 10, bit 31:24 */
	uint32_t	cs_en:1;	/* Word 10, bit 23 */
	uint32_t	rsv:15;		/* Word 10, bit 22:8 */
	uint32_t	ebde_count:8;	/* Word 10, bit 7:0 */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	ebde_count:8;	/* Word 10, bit 7:0 */
	uint32_t	rsv:15;		/* Word 10, bit 22:8 */
	uint32_t	cs_en:1;	/* Word 10, bit 23 */
	uint32_t	cs_ctl:8;	/* Word 10, bit 31:24 */
#endif
	uint32_t	rsplen;		/* Word 11 */
	ULP_BDE64	ebde1;		/* Word 12:14 */
	ULP_BDE64	ebde2;		/* Word 15:17 */
	ULP_BDE64	ebde3;		/* Word 18:20 */
	ULP_BDE64	ebde4;		/* Word 21:23 */
	ULP_BDE64	ebde5;		/* Word 24:26 */
	ULP_BDE64	ebde6;		/* Word 27:29 */
} GENERIC_EXT_IOCB;

/*
 * IOCB Command Extension template for
 * CMD_RCV_ELS64_CX (0xB7) or CMD_RCV_SEQ64_CX (0xB5)
 */

typedef struct
{
#ifdef EMLXS_BIG_ENDIAN
	uint16_t	oxid;		/* word 8 */
	uint16_t	seq_cnt;

	uint16_t	vpi;		/* word 9 */
	uint16_t	buddy_xri;

	uint32_t	ccp:8;		/* word 10 */
	uint32_t	ccpe:1;
	uint32_t	rsvd:23;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t	seq_cnt;	/* word 8 */
	uint16_t	oxid;

	uint16_t	buddy_xri;	/* word 9 */
	uint16_t	vpi;

	uint32_t	rsvd:23;	/* word 10 */
	uint32_t	ccpe:1;
	uint32_t	ccp:8;
#endif
	uint32_t	seq_len;	/* received sequence length */
	ULP_BDL		bde2;		/* total 4 words */
} RCV_SEQ_ELS_64_SLI3_EXT;


typedef volatile struct emlxs_iocb
{ /* IOCB structure */
	union
	{
		GENERIC_RSP		grsp;		/* Generic response */
		XR_SEQ_FIELDS		xrseq;		/* XMIT/BCAST/RCV_SEQ */
		ULP_BDE			cont[3];	/* up to 3 cont BDEs */
		ELS_REQUEST		elsreq;		/* ELS_REQ template */
		RCV_ELS_REQ		rcvels;		/* RCV_ELS_REQ */
							/* template */
		AC_XRI			acxri;		/* ABORT/CLOSE_XRI */
							/* template */
		GET_RPI			getrpi;		/* GET_RPI template */
		FCPI_FIELDS		fcpi;		/* FCP Initiator */
							/* template */
		FCPT_FIELDS		fcpt;		/* FCP target */
							/* template */

		/* SLI-2 structures */

		ULP_BDE64		cont64[2];	/* up to 2 64 bit */
							/* cont BDE_64s */
		ELS_REQUEST64		elsreq64;	/* ELS_REQ64 template */
		QUE_RING_LIST64		qringlist64;	/* QUE RING LIST64 */
							/* template */
		GEN_REQUEST64		genreq64;	/* GEN_REQUEST64 */
							/* template */
		RCV_ELS_REQ64		rcvels64;	/* RCV_ELS_REQ */
							/* template */
		XMT_SEQ_FIELDS64	xseq64;		/* XMIT / BCAST cmd */
		FCPI_FIELDS64		fcpi64;		/* FCP 64 bit */
							/* Initiator template */
		FCPT_FIELDS64		fcpt64;		/* FCP 64 bit target */
							/* template */
		AUTO_TRSP		atrsp;		/* FCP 64 bit target */
							/* template */

		RCV_SEQ_FIELDS64	rcvseq64;
		ASYNC_STATUS		astat;

		uint32_t		ulpWord[6];	/* generic 6 'words' */
	} un;
	union
	{
		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint16_t	ulpContext;	/* High order bits */
							/* word6 */
			uint16_t	ulpIoTag;	/* Low order bits */
							/* word6 */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint16_t	ulpIoTag;	/* Low order bits */
							/* word6 */
			uint16_t	ulpContext;	/* High order bits */
							/* word6 */
#endif
		} t1;
		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint16_t	ulpContext;	/* High order bits */
							/* word6 */
			uint16_t	ulpIoTag1:2;	/* Low order bits */
							/* word6 */
			uint16_t	ulpIoTag0:14;	/* Low order bits */
							/* word6 */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint16_t	ulpIoTag0:14;	/* Low order bits */
							/* word6 */
			uint16_t	ulpIoTag1:2;	/* Low order bits */
							/* word6 */
			uint16_t	ulpContext;	/* High order bits */
							/* word6 */
#endif
		} t2;

		uint32_t	ulpWord;
	} un1;
#define	ULPCONTEXT	un1.t1.ulpContext
#define	ULPIOTAG	un1.t1.ulpIoTag
#define	ULPIOTAG0	un1.t2.ulpIoTag0
#define	ULPDELAYXMIT	un1.t2.ulpIoTag1

#define	IOCB_DELAYXMIT_MSK 0x3000


	union
	{
		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint32_t	ulpRsvdByte:8;
			uint32_t	ulpXS:1;
			uint32_t	ulpFCP2Rcvy:1;
			uint32_t	ulpPU:2;
			uint32_t	ulpIr:1;
			uint32_t	ulpClass:3;
			uint32_t	ulpCommand:8;
			uint32_t	ulpStatus:4;
			uint32_t	ulpBdeCount:2;
			uint32_t	ulpLe:1;
			uint32_t	ulpOwner:1;	/* Low order bit */
							/* word 7 */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t	ulpOwner:1;	/* Low order bit */
							/* word 7 */
			uint32_t	ulpLe:1;
			uint32_t	ulpBdeCount:2;
			uint32_t	ulpStatus:4;
			uint32_t	ulpCommand:8;
			uint32_t	ulpClass:3;
			uint32_t	ulpIr:1;
			uint32_t	ulpPU:2;
			uint32_t	ulpFCP2Rcvy:1;
			uint32_t	ulpXS:1;
			uint32_t	ulpRsvdByte:8;
#endif
		} t1;

		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint32_t	ulpRsvdByte:8;
			uint32_t	ulpCT:2;
			uint32_t	ulpPU:2;
			uint32_t	ulpIr:1;
			uint32_t	ulpClass:3;
			uint32_t	ulpCommand:8;
			uint32_t	ulpStatus:4;
			uint32_t	ulpBdeCount:2;
			uint32_t	ulpLe:1;
			uint32_t	ulpOwner:1;	/* Low order bit */
							/* word 7 */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t	ulpOwner:1;	/* Low order bit */
							/* word 7 */
			uint32_t	ulpLe:1;
			uint32_t	ulpBdeCount:2;
			uint32_t	ulpStatus:4;
			uint32_t	ulpCommand:8;
			uint32_t	ulpClass:3;
			uint32_t	ulpIr:1;
			uint32_t	ulpPU:2;
			uint32_t	ulpCT:2;
			uint32_t	ulpRsvdByte:8;
#endif
		} t2;

		uint32_t	ulpWord;
	} un2;

#define	ULPCT		un2.t2.ulpCT
#define	ULPRSVDBYTE	un2.t1.ulpRsvdByte
#define	ULPXS		un2.t1.ulpXS
#define	ULPFCP2RCVY	un2.t1.ulpFCP2Rcvy
#define	ULPPU		un2.t1.ulpPU
#define	ULPIR		un2.t1.ulpIr
#define	ULPCLASS	un2.t1.ulpClass
#define	ULPCOMMAND	un2.t1.ulpCommand
#define	ULPSTATUS	un2.t1.ulpStatus
#define	ULPBDECOUNT	un2.t1.ulpBdeCount
#define	ULPLE		un2.t1.ulpLe
#define	ULPOWNER	un2.t1.ulpOwner
	/* 32 bytes at this point */

/* SLI4 */
#define	RXFCHDR		un.ulpWord
#define	RXSEQCNT	un1.ulpWord
#define	RXSEQLEN	un2.ulpWord

	union
	{
		GENERIC_EXT_IOCB	ext_iocb;
		RCV_SEQ_ELS_64_SLI3_EXT	ext_rcv;
		uint32_t		sli3Words[24];	/* 96 extra bytes */
							/* for SLI-3 */
	} unsli3;
	/* 128 bytes at this point */

#define	IOCB_FCP		1	/* IOCB is used for */
					/* FCP ELS cmds - ulpRsvByte */
#define	IOCB_IP			2	/* IOCB is used for IP ELS cmds */
#define	PARM_UNUSED		0	/* PU field (Word 4) not used */
#define	PARM_REL_OFF		1	/* PU field (Word 4) = R. O. */
#define	PARM_XFER_CHECK		2	/* PU field (Word 4) = Data Xfer Len */
#define	CLASS1			0	/* Class 1 */
#define	CLASS2			1	/* Class 2 */
#define	CLASS3			2	/* Class 3 */
#define	CLASS_FCP_INTERMIX	7	/* FCP Data->Cls 1, all else->Cls 2 */

#define	IOSTAT_SUCCESS			0x0	/* ulpStatus */
#define	IOSTAT_FCP_RSP_ERROR		0x1
#define	IOSTAT_REMOTE_STOP		0x2
#define	IOSTAT_LOCAL_REJECT		0x3
#define	IOSTAT_NPORT_RJT		0x4
#define	IOSTAT_FABRIC_RJT		0x5
#define	IOSTAT_NPORT_BSY		0x6
#define	IOSTAT_FABRIC_BSY		0x7
#define	IOSTAT_INTERMED_RSP		0x8
#define	IOSTAT_LS_RJT			0x9
#define	IOSTAT_RESERVED_A		0xA
#define	IOSTAT_CMD_REJECT		0xB
#define	IOSTAT_FCP_TGT_LENCHK		0xC
#define	IOSTAT_RESERVED_D		0xD
#define	IOSTAT_RESERVED_E		0xE
#define	IOSTAT_NEED_BUFF_ENTRY		0xF

/* Special error codes */
#define	IOSTAT_DATA_OVERRUN		0x10	/* Added for resid handling */
#define	IOSTAT_DATA_UNDERRUN		0x11	/* Added for resid handling */
#define	IOSTAT_RSP_INVALID		0x12	/* Added for resp checking */
} emlxs_iocb_t;
typedef emlxs_iocb_t IOCB;


typedef struct emlxs_iocbq
{
	emlxs_iocb_t		iocb;
	emlxs_wqe_t		wqe; /* SLI4 */

	struct emlxs_iocbq	*next;

	void			*bp;	/* ptr to data buffer structure */
	void			*port;	/* Board info pointer */
	void			*channel; /* IO Channel pointer */
	void			*node;	/* Node pointer */
	void			*sbp;	/* Pkt pointer */
	uint32_t		flag;

#define	IOCB_POOL_ALLOCATED	0x00000001
#define	IOCB_PRIORITY		0x00000002
#define	IOCB_SPECIAL		0x00000004
#define	IOCB_FCP_CMD		0x00000008
#define	IOCB_FCT_DATA		0x00000020	/* tgt-mode */

} emlxs_iocbq_t;
typedef emlxs_iocbq_t IOCBQ;


#ifdef	__cplusplus
}
#endif

#endif	/* _EMLXS_IOCB_H */
