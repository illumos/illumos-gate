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
 * Copyright 1998 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_SOCAL_CQ_DEFS_H
#define	_SYS_SOCAL_CQ_DEFS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#define	SOC_CQE_PAYLOAD 60

/*
 * define the CQ_HEADER for the soc command queue.
 */

typedef struct	cq_hdr {
	uchar_t	cq_hdr_count;
	uchar_t	cq_hdr_type;
	uchar_t	cq_hdr_flags;
	uchar_t	cq_hdr_seqno;
} cq_hdr_t;

/*
 * Command Queue entry description.
 */

typedef struct cqe {
	uchar_t		cqe_payload[SOC_CQE_PAYLOAD];
	cq_hdr_t	cqe_hdr;
} cqe_t;

/*
 * CQ Entry types.
 */

#define	CQ_TYPE_NOP		0x00
#define	CQ_TYPE_OUTBOUND	0x01
#define	CQ_TYPE_INBOUND		0x02
#define	CQ_TYPE_SIMPLE		0x03
#define	CQ_TYPE_IO_WRITE	0x04
#define	CQ_TYPE_IO_READ		0x05
#define	CQ_TYPE_UNSOLICITED	0x06
#define	CQ_TYPE_BYPASS_DEV	0x06	/* supercedes unsolicited in SOC+ */
#define	CQ_TYPE_DIAGNOSTIC	0x07
#define	CQ_TYPE_OFFLINE		0x08
#define	CQ_TYPE_ADD_POOL	0x09	/* SOC+ enhancement */
#define	CQ_TYPE_DELETE_POOL	0x0a	/* SOC+ enhancement */
#define	CQ_TYPE_ADD_BUFFER	0x0b	/* SOC+ enhancement */
#define	CQ_TYPE_ADD_POOL_BUFFER	0x0c	/* SOC+ enhancement */
#define	CQ_TYPE_REQUEST_ABORT	0x0d	/* SOC+ enhnacement */
#define	CQ_TYPE_REQUEST_LIP	0x0e	/* SOC+ enhancement */
#define	CQ_TYPE_REPORT_MAP	0x0f	/* SOC+ enhancement */
#define	CQ_TYPE_RESPONSE	0x10
#define	CQ_TYPE_INLINE		0x20

/*
 * CQ Entry Flags
 */

#define	CQ_FLAG_CONTINUATION	0x01
#define	CQ_FLAG_FULL		0x02
#define	CQ_FLAG_BADHEADER	0x04
#define	CQ_FLAG_BADPACKET	0x08

/*
 * CQ Descriptor Definition.
 */

typedef	struct cq {
	uint32_t	cq_address;
	uchar_t		cq_in;
	uchar_t		cq_out;
	uchar_t		cq_last_index;
	uchar_t		cq_seqno;
} soc_cq_t;

/*
 * SOC header definition.
 */

typedef struct soc_hdr {
	uint_t		sh_request_token;
	ushort_t	sh_flags;
	uchar_t		sh_class;
	uchar_t		sh_seg_cnt;
	uint_t		sh_byte_cnt;
} soc_header_t;

/*
 * SOC header request packet definition.
 */

typedef struct soc_request {
	soc_header_t		sr_soc_hdr;
	fc_dataseg_t		sr_dataseg[3];
	fc_frame_header_t	sr_fc_frame_hdr;
	cq_hdr_t		sr_cqhdr;
} soc_request_t;

typedef	soc_request_t soc_header_request_t;

/*
 * SOC header response packet definition.
 */

typedef struct soc_response {
	soc_header_t		sr_soc_hdr;
	uint_t			sr_soc_status;
	fc_dataseg_t		sr_dataseg;
	uchar_t			sr_reserved[10];
	ushort_t 		sr_ncmds;
	fc_frame_header_t	sr_fc_frame_hdr;
	cq_hdr_t		sr_cqhdr;
} soc_response_t;

/*
 * SOC data request packet definition.
 */

typedef struct soc_data_request {
	soc_header_t		sdr_soc_hdr;
	fc_dataseg_t		sdr_dataseg[6];
	cq_hdr_t		sdr_cqhdr;
} soc_data_request_t;

/*
 * SOC+ (only) command-only packet definitiion
 */

typedef	struct soc_cmdonly_request {
	soc_header_t	scr_soc_hdr;
	uchar_t		reserved[48];
	cq_hdr_t	scr_cqhdr;
} soc_cmdonly_request_t;

/*
 * SOC+ (only) diagnostic request packet definition
 */

typedef	struct soc_diag_request {
	soc_header_t	sdr_soc_hdr;
	uint_t		sdr_diag_cmd;
	uchar_t		reserved[44];
	cq_hdr_t	sdr_cqhdr;
} soc_diag_request_t;

#define	SOC_DIAG_NOP		0x00
#define	SOC_DIAG_INT_LOOP	0x01
#define	SOC_DIAG_EXT_LOOP	0x02
#define	SOC_DIAG_REM_LOOP	0x03
#define	SOC_DIAG_XRAM_TEST	0x04
#define	SOC_DIAG_SOC_TEST	0x05
#define	SOC_DIAG_HCB_TEST	0x06
#define	SOC_DIAG_SOCLB_TEST	0x07
#define	SOC_DIAG_SRDSLB_TEST	0x08
#define	SOC_DIAG_EXTOE_TEST	0x09

/*
 * SOC+ (only) pool request packet definition
 */

typedef	struct soc_pool_request {
	soc_header_t		spr_soc_hdr;
	uint_t		spr_pool_id;
	uint_t		spr_header_mask;
	uint_t		spr_buf_size;
	uint_t		spr_n_entries;
	uchar_t			reserved[8];
	fc_frame_header_t	spr_fc_frame_hdr;
	cq_hdr_t		spr_cqhdr;
} soc_pool_request_t;

#define	SOCPR_MASK_RCTL		0x800000
#define	SOCPR_MASK_DID		0x700000
#define	SOCPR_MASK_SID		0x070000
#define	SOCPR_MASK_TYPE		0x008000
#define	SOCPR_MASK_F_CTL	0x007000
#define	SOCPR_MASK_SEQ_ID	0x000800
#define	SOCPR_MASK_D_CTL	0x000400
#define	SOCPR_MASK_SEQ_CNT	0x000300
#define	SOCPR_MASK_OX_ID	0x0000f0
#define	SOCPR_MASK_PARAMETER	0x0000f0


/*
 * Macros for flags field
 *
 * values used in both RSP's and REQ's
 */
#define	SOC_PORT_B	0x0001	/* entry to/from SOC Port B */
#define	SOC_FC_HEADER	0x0002	/* this entry contains an FC_HEADER */
/*
 *	REQ: this request is supplying buffers
 *	RSP: this pkt is unsolicited
 */
#define	SOC_UNSOLICITED	0x0080

/*
 * values used only for REQ's
 */
#define	SOC_NO_RESPONSE	0x0004 /* generate niether RSP nor INT */
#define	SOC_NO_INTR	0x0008 /* generate RSP only */
#define	SOC_XFER_RDY	0x0010 /* issue a XFRRDY packet for this cmd */
#define	SOC_IGNORE_RO	0x0020 /* ignore FC_HEADER relative offset */
#define	SOC_RESP_HEADER	0x0200	/* return frame header regardless of status */

/*
 * values used only for RSP's
 */
#define	SOC_COMPLETE	0x0040 /* previous CMD completed. */
#define	SOC_STATUS	0x0100 /* a SOC status change has occurred */

#define	CQ_SUCCESS	0x0
#define	CQ_FAILURE	0x1
#define	CQ_FULL		0x2

#define	CQ_REQUEST_0	0
#define	CQ_REQUEST_1	1
#define	CQ_REQUEST_2	2
#define	CQ_REQUEST_3	3

#define	CQ_RESPONSE_0	0
#define	CQ_RESPONSE_1	1
#define	CQ_RESPONSE_2	2
#define	CQ_RESPONSE_3	3

#define	CQ_SOLICITED_OK		CQ_RESPONSE_0
#define	CQ_SOLICITED_BAD	CQ_RESPONSE_1
#define	CQ_UNSOLICITED		CQ_RESPONSE_2


typedef struct soc_request_descriptor {
	soc_request_t	*srd_sp;
	uint_t		srd_sp_count;

	caddr_t		srd_cmd;
	uint_t		srd_cmd_count;

	caddr_t		srd_data;
	uint_t		srd_data_count;
} soc_request_desc_t;


#ifdef __cplusplus
}
#endif

#endif /* !_SYS_SOCAL_CQ_DEFS_H */
