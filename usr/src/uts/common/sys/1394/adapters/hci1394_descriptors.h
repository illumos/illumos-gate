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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_1394_ADAPTERS_HCI1394_DESCRIPTORS_H
#define	_SYS_1394_ADAPTERS_HCI1394_DESCRIPTORS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * hci1394_descriptors.h
 *    1394 Open HCI command descriptors.
 *    These are DMA commands chained together to form packets.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/note.h>

/*
 * There are 2 different 1394 Open HCI entities defined in this file.
 * The HCI DMA descriptors (aka context descriptors or descriptor
 * commands), and the packet formats.
 *
 * Packet formats are used within descriptors for transmit and
 * are available in buffers for receive.  EACH PACKET TYPE
 * (such as read_quadlet_request) may have a different format
 * depending on whether it is to be transmitted or whether it
 * is being received.
 *
 * In general, fields within a packet remain in the same location
 * within a quadlet either way.  However, the location of the
 * quadlets themselves may be different.
 *
 * In an attempt to clarify what is used for what, Macros used
 * for setting up packets within a descriptor (an "Immediate" command)
 * shall have "DESC" in their name.  Macros used for reading packets
 * from an input buffer shall have "PKT" in their name.
 *
 * For more information, see OpenHCI 1.00 chapters 7 (Asynch Transmit),
 * 8 (Asynch Receive), 9 (Isoch Transmit) and 10 (Isoch Receive).
 * Each chapter shows the DMA descriptors at the beginning, and
 * the packet formats at the end.
 * Also see chapter 11 (Self ID).
 */


/*
 * hci1394_desc is the basic format used for the following descriptor commands:
 * OUTPUT_MORE, OUTPUT_LAST, INPUT_MORE and INPUT_LAST
 */
typedef struct hci1394_desc_s {
	uint32_t	hdr;
	uint32_t	data_addr;
	uint32_t	branch;	    /* branch or skip address (& Z) */
	uint32_t	status;	    /* status and/or (timestamp or rescount) */
} hci1394_desc_t;

_NOTE(SCHEME_PROTECTS_DATA("Single thread modifies", hci1394_desc_s))

/*
 * hci1394_desc_imm is the basic format used for the "immediate" descriptor
 * commands: OUTPUT_MORE_IMMEDIATE and OUTPUT_LAST_IMMEDIATE.
 */
typedef struct hci1394_desc_imm_s {
    uint32_t	hdr;
    uint32_t	data_addr;
    uint32_t	branch;
    uint32_t	status;
    uint32_t	q1;
    uint32_t	q2;
    uint32_t	q3;
    uint32_t	q4;
} hci1394_desc_imm_t;

_NOTE(SCHEME_PROTECTS_DATA("Single thread modifies", hci1394_desc_imm_s))

/*
 * hci1394_desc_hdr contains the immediate packet header quadlets
 * for OUTPUT_MORE_IMMEDIATE and OUTPUT_LAST_IMMEDIATE.  A packet header
 * has up to 4 quadlets of data which are specific to the individual operation
 * and operation type (i.e. this data would be different between a quadlet read
 * and quadlet write).
 */
typedef struct hci1394_desc_hdr_s {
    uint32_t	q1;
    uint32_t	q2;
    uint32_t	q3;
    uint32_t	q4;
} hci1394_desc_hdr_t;


/* typedefs for each descriptor command */
typedef hci1394_desc_imm_t	hci1394_output_more_imm_t;
typedef hci1394_desc_t		hci1394_output_more_t;
typedef hci1394_desc_imm_t	hci1394_output_last_imm_t;
typedef hci1394_desc_t		hci1394_output_last_t;
typedef hci1394_desc_t		hci1394_input_more_t;
typedef hci1394_desc_t		hci1394_input_last_t;

/*
 * maximum number of 16-byte components comprising a descriptor block.
 * Note that "immediate" descriptors take up 32-bytes and therefore are
 * 2 Z counts.  Refer to OHCI 1.00 sections 3.1.2, 7.1.5.1, 8.3.1, 9.2.1,
 * and table 10-2 for context specific info about Z.
 */
#define	HCI1394_DESC_MAX_Z	8


/*
 * There are two sets of defines below.  The first set includes
 * definitions for the descriptor header.  Namely hdr, branch, and stat.
 * The second set includes definitions for the different packet header
 * formats that have to be placed in the immediate q1-q4 fields
 * of a descriptor.
 */


/* General descriptor HDR quadlet defs */
#define	DESC_HDR_STAT_ENBL	0x08000000	/* AR, IT & IR only */
#define	DESC_HDR_STAT_DSABL	0x00000000	/* AR, IT & IR only */
#define	DESC_HDR_PING_ENBL	0x00800000	/* AT only */
#define	DESC_HDR_REQCOUNT_MASK	0x0000FFFF	/* IR only */
#define	DESC_HDR_REQCOUNT_SHIFT	0
#define	DESC_HDR_STVAL_MASK	0x0000FFFF	/* IT STORE only */
#define	DESC_HDR_STVAL_SHIFT	0
#define	DESC_GET_HDR_REQCOUNT(DESCP) \
	(((DESCP)->hdr & DESC_HDR_REQCOUNT_MASK) >> DESC_HDR_REQCOUNT_SHIFT)

/* CMD_TYPE values */
#define	DESC_TY_OUTPUT_MORE	0x00000000	/* AT & IT */
#define	DESC_TY_OUTPUT_LAST	0x10000000	/* AT & IT */
#define	DESC_TY_INPUT_MORE	0x20000000	/* AR & IR */
#define	DESC_TY_INPUT_LAST	0x30000000	/* IR only */
#define	DESC_TY_STORE		0x80000000	/* IT only */

/* CMD_KEY values */
#define	DESC_KEY_REF		0x00000000	/* reference ptr to data */
#define	DESC_KEY_IMMED		0x02000000	/* immediate data */
#define	DESC_KEY_STORE		0x06000000	/* store data */

/* CMD_BR and CMD_INT values  - two bits */
#define	DESC_INTR_DSABL		0x00000000
#define	DESC_INTR_ENBL		0x00300000
#define	DESC_BR_DSABL		0x00000000
#define	DESC_BR_ENBL		0x000C0000
#define	DESC_W_DSABL		0x00000000
#define	DESC_W_ENBL		0x00030000

/*
 * Shortcuts for AT Descriptor types. We will always interrupt upon command
 * completion for AT OL, OLI, and IM.
 */
#define	DESC_AT_OM  DESC_TY_OUTPUT_MORE
#define	DESC_AT_OMI (DESC_TY_OUTPUT_MORE | DESC_KEY_IMMED)
#define	DESC_AT_OL  (DESC_TY_OUTPUT_LAST | DESC_INTR_ENBL | DESC_BR_ENBL)
#define	DESC_AT_OLI (DESC_AT_OL | DESC_KEY_IMMED)
#define	DESC_AR_IM  (DESC_TY_INPUT_MORE | DESC_HDR_STAT_ENBL | \
    DESC_INTR_ENBL | DESC_BR_ENBL)

/*
 * descriptor BRANCH field defs
 * Branch addresses are 16-byte aligned. the low order 4-bits are
 * used for the Z value.
 */
#define	DESC_BRANCH_MASK	0xFFFFFFF0
#define	DESC_Z_MASK		0x0000000F

#define	HCI1394_SET_BRANCH(DESCP, ADDR, Z)  ((DESCP)->branch = 0 |	\
	((ADDR) & DESC_BRANCH_MASK) | ((Z) & DESC_Z_MASK))

#define	HCI1394_GET_BRANCH_ADDR(DESCP)	    ((DESCP)->branch & ~DESC_Z_MASK)
#define	HCI1394_GET_BRANCH_Z(DESCP)	    ((DESCP)->branch & DESC_Z_MASK)

/*
 * descriptor STATUS field defs.  comprised of xfer status and either
 * a timestamp or a residual count (rescount)
 */
#define	DESC_ST_XFER_STAT_MASK	0xFFFF0000
#define	DESC_ST_XFER_STAT_SHIFT	16
#define	DESC_ST_RESCOUNT_MASK	0x0000FFFF	/* AR, IR only */
#define	DESC_ST_RESCOUNT_SHIFT	0
#define	DESC_ST_TIMESTAMP_MASK	0x0000FFFF	/* AT, IT only */
#define	DESC_ST_TIMESTAMP_SHIFT	0

#define	HCI1394_DESC_RESCOUNT_GET(data)	    ((data) & DESC_ST_RESCOUNT_MASK)
#define	HCI1394_DESC_TIMESTAMP_GET(data)    ((data) & DESC_ST_TIMESTAMP_MASK)

/*
 * XFER status fields are the same as the context control fields.
 * but in the high 16 bits
 */
#define	DESC_XFER_RUN_MASK	(OHCI_CC_RUN_MASK << DESC_ST_XFER_STAT_SHIFT)
#define	DESC_XFER_WAKE_MASK	(OHCI_CC_WAKE_MASK << DESC_ST_XFER_STAT_SHIFT)
#define	DESC_XFER_DEAD_MASK	(OHCI_CC_DEAD_MASK << DESC_ST_XFER_STAT_SHIFT)
#define	DESC_XFER_ACTIVE_MASK	(OHCI_CC_ACTIVE_MASK << DESC_ST_XFER_STAT_SHIFT)

#define	DESC_AT_SPD_MASK	0x7
#define	DESC_AT_SPD_SHIFT	16
#define	DESC_AR_SPD_MASK	0x00E00000
#define	DESC_AR_SPD_SHIFT	21
#define	DESC_AR_EVT_MASK	0x001F0000
#define	DESC_AR_EVT_SHIFT	16

#define	HCI1394_DESC_EVT_GET(data) \
	(((data) & DESC_AR_EVT_MASK) >> DESC_AR_EVT_SHIFT)
#define	HCI1394_DESC_AR_SPD_GET(data) \
	(((data) & DESC_AR_SPD_MASK) >> DESC_AR_SPD_SHIFT)
#define	HCI1394_DESC_AT_SPD_SET(data) \
	(((data) & DESC_AT_SPD_MASK) << DESC_AT_SPD_SHIFT)


/*
 * XferStatus events are as follows
 */
#define	DESC_EVT_NO_STATUS	0x00		/* AT, AR, IT, IR */
#define	DESC_EVT_LONG_PKT	0x02		/* IR */
#define	DESC_EVT_MISSING_ACK	0x03		/* AT */
#define	DESC_EVT_UNDERRUN	0x04		/* AT, IT */
#define	DESC_EVT_OVERRUN	0x05		/* IR */
#define	DESC_EVT_DESC_READ	0x06		/* AT, AR, IT, IR */
#define	DESC_EVT_DATA_READ	0x07		/* AT, IT */
#define	DESC_EVT_DATA_WRITE	0x08		/* AR, IR */
#define	DESC_EVT_BUS_RESET	0x09		/* AR */
#define	DESC_EVT_TIMEOUT	0x0A		/* AT */
#define	DESC_EVT_TCODE_ERR	0x0B		/* AT, IT */

#define	DESC_ACK_COMPLETE	0x11		/* AT, AR, IT, IR */
#define	DESC_ACK_PENDING	0x12		/* AT, AR */
#define	DESC_ACK_BUSY_X		0x14		/* AT */
#define	DESC_ACK_BUSY_A		0x15		/* AT */
#define	DESC_ACK_BUSY_B		0x16		/* AT */
#define	DESC_ACK_TARDY		0x1B		/* AT */
#define	DESC_ACK_DATA_ERR	0x1D		/* AT IR */
#define	DESC_ACK_TYPE_ERR	0x1E		/* AT, AR */

/*
 * Response packet response codes
 */
#define	DESC_RESP_COMPLETE	0x0
#define	DESC_RESP_CONFLICT_ERR	0x4
#define	DESC_RESP_DATA_ERR	0x5
#define	DESC_RESP_TYPE_ERR	0x6
#define	DESC_RESP_ADDR_ERR	0x7


/*
 * Context dependent MACROs used to set up the command headers and
 * Caller provides only the necessary variables.
 */

/*
 * Isochronous Transmit  Descriptors
 */
#define	HCI1394_INIT_IT_OMORE(DESCP, REQCOUNT)	((DESCP)->hdr = 0 | \
	(DESC_TY_OUTPUT_MORE | DESC_KEY_REF | DESC_BR_DSABL | \
	    ((REQCOUNT) << DESC_HDR_REQCOUNT_SHIFT)))

#define	HCI1394_INIT_IT_OMORE_IMM(DESCP)	((DESCP)->hdr = 0 | \
	(DESC_TY_OUTPUT_MORE | DESC_KEY_IMMED | DESC_BR_DSABL | \
	    (8 << DESC_HDR_REQCOUNT_SHIFT)))

#define	HCI1394_INIT_IT_OLAST(DESCP, STAT, INTR, REQCOUNT) ((DESCP)->hdr = 0 |\
	(DESC_TY_OUTPUT_LAST | (STAT) | DESC_KEY_REF | (INTR) | \
	    DESC_BR_ENBL | ((REQCOUNT) << DESC_HDR_REQCOUNT_SHIFT)))

#define	HCI1394_INIT_IT_OLAST_IMM(DESCP, STAT, INTR)	((DESCP)->hdr = 0 | \
	(DESC_TY_OUTPUT_LAST | (STAT) | DESC_KEY_IMMED | (INTR) | \
	    DESC_BR_ENBL | (8 << DESC_HDR_REQCOUNT_SHIFT)))

#define	HCI1394_INIT_IT_STORE(DESCP, VAL)	((DESCP)->hdr = 0 | \
	(DESC_TY_STORE | DESC_KEY_STORE | ((VAL) << DESC_HDR_STVAL_SHIFT)))

/*
 * Isochronous Receive  Descriptors
 * PPB is Packet-Per-Buffer mode, BF is Buffer-Fill mode
 */
#define	HCI1394_INIT_IR_PPB_IMORE(DESCP, WAIT, REQCOUNT)    (DESCP)->hdr = 0 | \
	(DESC_TY_INPUT_MORE | DESC_HDR_STAT_DSABL | DESC_KEY_REF | \
	    DESC_INTR_DSABL | DESC_BR_DSABL | (WAIT) |	\
	    ((REQCOUNT) << DESC_HDR_REQCOUNT_SHIFT));	\
	(DESCP)->status = 0 | (((REQCOUNT) << DESC_ST_RESCOUNT_SHIFT) &	    \
	    DESC_ST_RESCOUNT_MASK);

#define	HCI1394_INIT_IR_PPB_ILAST(DESCP, STAT, INTR, WAIT, REQCOUNT)	    \
	(DESCP)->hdr = 0 | (DESC_TY_INPUT_LAST | (STAT) | DESC_KEY_REF |    \
	    (INTR) | DESC_BR_ENBL | (WAIT) |				    \
	    ((REQCOUNT) << DESC_HDR_REQCOUNT_SHIFT));			    \
	(DESCP)->status = 0 | (((REQCOUNT) << DESC_ST_RESCOUNT_SHIFT) &	    \
	    DESC_ST_RESCOUNT_MASK);

#define	HCI1394_INIT_IR_BF_IMORE(DESCP, INT, WAIT, REQCOUNT)		    \
	(DESCP)->hdr = 0 | (DESC_TY_INPUT_MORE | DESC_HDR_STAT_ENBL |	    \
	    DESC_KEY_REF | (INT) | DESC_BR_ENBL | (WAIT) |		    \
	    ((REQCOUNT) << DESC_HDR_REQCOUNT_SHIFT));			    \
	(DESCP)->status = 0 | (((REQCOUNT) << DESC_ST_RESCOUNT_SHIFT) &	    \
	    DESC_ST_RESCOUNT_MASK);

/*
 * Packet Formats
 *
 * HCI packet formats typically comprise 2-4 quadlets for transmit
 * and 3-5 quadlets for receive.  Although particular quadlets
 * may be in different parts of the 1394 header, the fields within
 * the quadlets remain in a consistent location.
 */
typedef struct hci1394_basic_packet {
	uint32_t	q1;		/* (HCI format) packet header w/tcode */
	uint32_t	q2;
	uint32_t	q3;
	uint32_t	q4;
	uint32_t	q5;		/* xferstatus/rescount for AR/IR */
} hci1394_basic_pkt_t;


/* defs for the # of bytes are used in building the immediate descriptors */
/* These are used to set REQCOUNT in the HDR etc... */
#define	DESC_FIVE_QUADS			20
#define	DESC_FOUR_QUADS			16
#define	DESC_THREE_QUADS  		12
#define	DESC_TWO_QUADS    		8
#define	DESC_ONE_QUAD			4
#define	DESC_ONE_OCTLET			8
#define	DESC_TWO_OCTLETS		16

#define	DESC_PKT_HDRLEN_AT_READQUAD		DESC_THREE_QUADS
#define	DESC_PKT_HDRLEN_AT_WRITEQUAD		DESC_FOUR_QUADS
#define	DESC_PKT_HDRLEN_AT_READBLOCK		DESC_FOUR_QUADS
#define	DESC_PKT_HDRLEN_AT_WRITEBLOCK		DESC_FOUR_QUADS
#define	DESC_PKT_HDRLEN_AT_LOCK			DESC_FOUR_QUADS
#define	DESC_PKT_HDRLEN_AT_PHY			DESC_THREE_QUADS
#define	DESC_PKT_HDRLEN_AT_WRITE_RESP		DESC_THREE_QUADS
#define	DESC_PKT_HDRLEN_AT_READQUAD_RESP	DESC_FOUR_QUADS
#define	DESC_PKT_HDRLEN_AT_READBLOCK_RESP	DESC_FOUR_QUADS
#define	DESC_PKT_HDRLEN_AT_LOCK_RESP		DESC_FOUR_QUADS
#define	DESC_PKT_HDRLEN_AT_STREAM		DESC_TWO_QUADS
#define	DESC_PKT_HDRLEN_AT_ISOCH		DESC_PKT_HDRLEN_AT_STREAM

/* q1 shortcuts for ASYNC processing */
#define	DESC_AT_SRCBUSID	0x00800000
#define	DESC_ATREQ_Q1_PHY	0x000000E0
#define	DESC_ATREQ_Q1_QWR	0x00000100
#define	DESC_ATREQ_Q1_BWR	0x00000110
#define	DESC_ATREQ_Q1_QRD	0x00000140
#define	DESC_ATREQ_Q1_BRD	0x00000150
#define	DESC_ATREQ_Q1_LCK	0x00000190
#define	DESC_ATRESP_Q1_WR	0x00000120
#define	DESC_ATRESP_Q1_QRD	0x00000160
#define	DESC_ATRESP_Q1_BRD	0x00000170
#define	DESC_ATRESP_Q1_LCK	0x000001B0

/* q1 - definitions for the asynch packet first quadlet */
#define	DESC_PKT_SRCBUSID_SHIFT	23
#define	DESC_PKT_SRCBUSID_MASK	0x00800000
#define	DESC_PKT_SPD_SHIFT	16		/* asynch and isoch */
#define	DESC_PKT_SPD_MASK	0x00070000
#define	DESC_PKT_TLABEL_SHIFT	10		/* asynch and isoch */
#define	DESC_PKT_TLABEL_MASK	0x0000FC00
#define	DESC_PKT_RT_SHIFT	8
#define	DESC_PKT_RT_MASK	0x00000300
#define	DESC_PKT_TCODE_SHIFT	4		/* asynch and isoch */
#define	DESC_PKT_TCODE_MASK	0x000000F0
#define	DESC_RT_RETRYX		0x1

/* q1 - definitions for the isoch first quadlet (see q1 async above for spd) */
#define	DESC_PKT_TAG_SHIFT	14
#define	DESC_PKT_TAG_MASK	0x0000C000
#define	DESC_PKT_CHAN_SHIFT	8
#define	DESC_PKT_CHAN_MASK	0x00003F00
#define	DESC_PKT_SY_SHIFT	0
#define	DESC_PKT_SY_MASK	0x0000000F

/* q2 - definitions for the asynch second quadlet */
#define	DESC_PKT_DESTID_SHIFT	16		/* 1st quadlet for AR */
#define	DESC_PKT_DESTID_MASK	0xFFFF0000
#define	DESC_PKT_SRCID_SHIFT	16		/* asynch recv only */
#define	DESC_PKT_SRCID_MASK	0xFFFF0000
#define	DESC_PKT_DESTOFFHI_SHIFT 0
#define	DESC_PKT_DESTOFFHI_MASK	0x0000FFFF

#define	DESC_PKT_BUSID_SHIFT	22		/* in srcid or destid */
#define	DESC_PKT_BUSID_MASK	0xFFC00000	/* in srcid or destid */
#define	DESC_PKT_NODENUM_SHIFT	16		/* in srcid or destid */
#define	DESC_PKT_NODENUM_MASK	0x003F0000	/* in srcid or destid */
#define	DESC_PKT_RC_SHIFT	12		/* AT/AR read respnse */
#define	DESC_PKT_RC_MASK	0x0000F000	/* AT/AR read respnse */

/* q3 - definitions for the asynch third quadlet */
#define	DESC_PKT_DESTOFFLO_SHIFT	0
#define	DESC_PKT_DESTOFFLO_MASK		0xFFFFFFFF
#define	DESC_PKT_PHYGEN_SHIFT		16
#define	DESC_PKT_PHYGEN_MASK		0x00FF0000

/* q4 - definitions for the fourth quadlet */
#define	DESC_PKT_QDATA_SHIFT	0	/* at_wr_quad, at_rd_resp_quad */
#define	DESC_PKT_QDATA_MASK	0xFFFFFFFF
#define	DESC_PKT_DATALEN_SHIFT	16	/* at_rd_blk, at_wr_blk, isoch (q2), */
#define	DESC_PKT_DATALEN_MASK	0xFFFF0000 /* at_rd_resp_blk, at_lock_resp, */
					/* ar_rd_blk, ar_wr_blk, ar_lock, */
					/* ar_rd_resp, ar_lock_resp */
#define	DESC_PKT_EXTTCODE_MASK	0x0000FFFF

/*
 * MACROS for getting and setting HCI packet fields
 */

/* ASYNCHRONOUS */
#define	HCI1394_DESC_TCODE_GET(data) \
	(((data) & DESC_PKT_TCODE_MASK) >> DESC_PKT_TCODE_SHIFT)
#define	HCI1394_DESC_TLABEL_GET(data) \
	(((data) & DESC_PKT_TLABEL_MASK) >> DESC_PKT_TLABEL_SHIFT)
#define	HCI1394_DESC_RCODE_GET(data) \
	(((data) & DESC_PKT_RC_MASK) >> DESC_PKT_RC_SHIFT)
#define	HCI1394_DESC_DESTID_GET(data) \
	(((data) & DESC_PKT_DESTID_MASK) >> DESC_PKT_DESTID_SHIFT)
#define	HCI1394_DESC_SRCID_GET(data) \
	(((data) & DESC_PKT_SRCID_MASK) >> DESC_PKT_SRCID_SHIFT)
#define	HCI1394_DESC_DATALEN_GET(data) \
	(((data) & DESC_PKT_DATALEN_MASK) >> DESC_PKT_DATALEN_SHIFT)
#define	HCI1394_DESC_EXTTCODE_GET(data) \
	((data) & DESC_PKT_EXTTCODE_MASK)
#define	HCI1394_DESC_PHYGEN_GET(data) \
	(((data) & DESC_PKT_PHYGEN_MASK) >> DESC_PKT_PHYGEN_SHIFT)

#define	HCI1394_DESC_TLABEL_SET(data) \
	(((data) << DESC_PKT_TLABEL_SHIFT) & DESC_PKT_TLABEL_MASK)
#define	HCI1394_DESC_RCODE_SET(data) \
	(((data) << DESC_PKT_RC_SHIFT) & DESC_PKT_RC_MASK)
#define	HCI1394_DESC_DESTID_SET(data) \
	(((data) << DESC_PKT_DESTID_SHIFT) & DESC_PKT_DESTID_MASK)
#define	HCI1394_DESC_DATALEN_SET(data) \
	(((data) << DESC_PKT_DATALEN_SHIFT) & DESC_PKT_DATALEN_MASK)
#define	HCI1394_DESC_EXTTCODE_SET(data) \
	((data) & DESC_PKT_EXTTCODE_MASK)


/* ISOCHRONOUS */
/*
 * note: the GET macros for isoch take the actual quadlet as an arg because
 * the location of the IR header quadlet varies depending on the mode.
 * SETs are expected to be done only for isochronous transmit.
 */
#define	HCI1394_GETTAG(Q)	    (((Q) & DESC_TAG_MASK) >> DESC_TAG_SHIFT)

#define	HCI1394_SETTAG(PKT, VAL)    ((PKT)->q1 = (((PKT)->q1) &	\
	~DESC_PKT_TAG_MASK) | (((VAL) << DESC_PKT_TAG_SHIFT) & \
	DESC_PKT_TAG_MASK))

#define	HCI1394_GETCHAN(Q)	    (((Q) & PKT_CHAN_MASK) >>	\
	DESC_PKT_CHAN_SHIFT)

#define	HCI1394_SETCHAN(PKT, VAL)   ((PKT)->q1 = ((PKT)->q1) &	\
	~DESC_PKT_CHAN_MASK) | (((VAL) << DESC_PKT_CHAN_SHIFT) &	\
	DESC_PKT_CHAN_MASK))

#define	HCI1394_GETSY(Q)	    (((Q) & DESC_PKT_SY_MASK) >> \
	DESC_PKT_SY_SHIFT)

#define	HCI1394_SETSY(PKT, VAL)	    ((PKT)->q1 = ((PKT)->q1) & \
	~DESC_PKT_SY_MASK) | (((VAL) << DESC_PKT_SY_SHIFT) & DESC_PKT_SY_MASK))

#define	HCI1394_GET_ILEN(Q)	    (((Q) & DESC_DATALEN_MASK) >> \
	DESC_DATALEN_SHIFT)

#define	HCI1394_SET_ILEN(PKT, VAL)  ((PKT)->q2 = (((PKT)->q1) & \
	~DESC_PKT_DATALEN_MASK) | (((VAL) << DESC_PKT_DATALEN_SHIFT) & \
	DESC_PKT_DATALEN_MASK))

#define	HCI1394_IT_SET_HDR_Q1(PKT, SPD, TAG, CH, TC, SY)    ((PKT)->q1 = 0 |  \
	(((SPD) << DESC_PKT_SPD_SHIFT) & DESC_PKT_SPD_MASK) |		\
	(((TAG) << DESC_PKT_TAG_SHIFT) & DESC_PKT_TAG_MASK) |		\
	(((CH) << DESC_PKT_CH_SHIFT) & DESC_PKT_CH_MASK) |		\
	(((TC) << DESC_PKT_TCODE_SHIFT) & DESC_PKT_TCODE_MASK) |	\
	(((SY) << DESC_PKT_SY_SHIFT) & DESC_PKT_SY_MASK))

/*
 * OpenHCI Packet format sizes (header only)
 */
#define	DESC_SZ_AR_WRITEQUAD_REQ    DESC_FIVE_QUADS
#define	DESC_SZ_AR_WRITEBLOCK_REQ   DESC_FIVE_QUADS	/* add data_len */
#define	DESC_SZ_AR_WRITE_RESP	    DESC_FOUR_QUADS
#define	DESC_SZ_AR_READQUAD_REQ	    DESC_FOUR_QUADS
#define	DESC_SZ_AR_READBLOCK_REQ    DESC_FIVE_QUADS
#define	DESC_SZ_AR_READQUAD_RESP    DESC_FIVE_QUADS
#define	DESC_SZ_AR_READ_BLOCK_RESP  DESC_FIVE_QUADS	/* add data_len */
#define	DESC_SZ_AR_PHY		    DESC_FOUR_QUADS
#define	DESC_SZ_AR_LOCK_REQ	    DESC_FIVE_QUADS	/* add data_len */
#define	DESC_SZ_AR_LOCK_RESP	    DESC_FIVE_QUADS	/* add data_len */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_1394_ADAPTERS_HCI1394_DESCRIPTORS_H */
