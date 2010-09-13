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

#ifndef _ISER_XFER_H
#define	_ISER_XFER_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/ib/ibtl/ibti.h>
#include <sys/ib/ibtl/ibtl_types.h>
#include <sys/iscsi_protocol.h>

/*
 * iser_xfer.h
 *	Definitions and functions related to data transfer across the RC channel
 * This includes the posting of the Hello Message, the HelloReply Message, the
 * RC Send Message for the iSCSI Control PDU.
 */

/*
 * iser_private_data_s contains parameters relating to the iSER connection and
 * IB options support status. This data conforms to the 'iSER CM REQ Message
 * Private Data Format' from the Annex A12 - Support for iSCSI Extensions for
 * RDMA.
 */
#pragma pack(1)
typedef struct iser_private_data_s {
	uint8_t		ip_pvt[IBT_IP_HDR_PRIV_DATA_SZ];
#if defined(_BIT_FIELDS_LTOH)
	uint32_t	rsvd1	:30,
			sie	:1,
			zbvae	:1;
#elif defined(_BIT_FIELDS_HTOL)
	uint32_t	zbvae	:1,
			sie	:1,
			rsvd1	:30;
#else
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif /* _BIT_FIELDS_LTOH */
	uint8_t		rsvd2[52];
} iser_private_data_t;

/* iSER Message Opcodes */
#define	ISER_OPCODE_CTRL_TYPE_PDU	1
#define	ISER_OPCODE_HELLO_MSG		2
#define	ISER_OPCODE_HELLOREPLY_MSG	3

/*
 * When ZBVA is not supported, both the initiator and the target shall use the
 * expanded iSER header as defined in the IB Spec Table 540 for iSCSI control-
 * type PDUs in the connection
 */
typedef struct iser_ctrl_hdr_s {
#if defined(_BIT_FIELDS_LTOH)
	uint8_t		rsvd1:	  2,
			rsv_flag: 1, /* RStag valid bit */
			wsv_flag: 1, /* WStag valid bit */
			opcode:	  4; /* iSER opcode */
	uint8_t		rsvd[3];
#elif defined(_BIT_FIELDS_HTOL)
	uint8_t		opcode:	  4,
			wsv_flag: 1,
			rsv_flag: 1,
			rsvd1:	  2;
	uint8_t		rsvd[3];
#else
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif /* _BIT_FIELDS_LTOH */
	uint32_t	wstag;		/* IB R-key for SCSI Write */
	uint64_t	wva;		/* IB VA for SCSI Write */
	uint32_t	rstag;		/* IB R-key for SCSI Read */
	uint64_t	rva;		/* IB VA for SCSI Read */
} iser_ctrl_hdr_t;

/* iSER Header Format for the iSER Hello Message */
typedef struct iser_hello_hdr_s {
#if defined(_BIT_FIELDS_LTOH)
	uint8_t		rsvd1	: 4,
			opcode	: 4;
	uint8_t		minver	: 4,
			maxver	: 4;
#elif defined(_BIT_FIELDS_HTOL)
	uint8_t		opcode	: 4,
			rsvd1	: 4;
	uint8_t		maxver	: 4,
			minver	: 4;
#else
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif /* _BIT_FIELDS_LTOH */
	uint16_t	iser_ird;
	uint32_t	rsvd2[2];
} iser_hello_hdr_t;

/* iSER Header Format for the iSER HelloReply Message */
typedef struct iser_helloreply_hdr_s {
#if defined(_BIT_FIELDS_LTOH)
	uint8_t		flag	: 1,
			rsvd1	: 3,
			opcode	: 4;
	uint8_t		curver	: 4,
			maxver	: 4;
#elif defined(_BIT_FIELDS_HTOL)
	uint8_t		opcode	: 4,
			rsvd1	: 3,
			flag	: 1;
	uint8_t		maxver	: 4,
			curver	: 4;
#else
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif /* _BIT_FIELDS_LTOH */
	uint16_t	iser_ord;
	uint32_t	rsvd2[2];
} iser_helloreply_hdr_t;
#pragma pack()

struct iser_state_s;

int iser_xfer_hello_msg(iser_chan_t *chan);

int iser_xfer_helloreply_msg(iser_chan_t *chan);

int iser_xfer_ctrlpdu(iser_chan_t *chan, idm_pdu_t *pdu);

int iser_xfer_buf_to_ini(idm_task_t *idt, idm_buf_t *buf);

int iser_xfer_buf_from_ini(idm_task_t *idt, idm_buf_t *buf);

#ifdef	__cplusplus
}
#endif

#endif /* _ISER_XFER_H */
