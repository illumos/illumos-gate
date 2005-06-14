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
 * Copyright (c) 1995-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_FC4_FCAL_H
#define	_SYS_FC4_FCAL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Fibre Channel Physical and Signaling Interface (FC-PH) definitions.
 *
 * NOTE: modifications of this file affect drivers, mpsas models, PLUTO
 *	firmware, SOC assembly code. Please be communicative.
 */

#define	FC_PH_VERSION	0x06	/* 0x06 means 4.0 ! */
#define	MAX_FRAME_SIZE	2112	/* maximum size of frame payload */

/*
 * This is the standard frame header for FC-PH frames.
 */

typedef struct FC2_FRAME_HDR {
	uint_t	r_ctl:8,	d_id:24;
	uint_t	reserved1:8,	s_id:24;
	uint_t	type:8,		f_ctl:24;
	uint_t	seq_id:8,	df_ctl:8,	seq_cnt:16;
	uint16_t	ox_id, rx_id;
	uint32_t	ro;
}aFC2_FRAME_HDR, *FC2_FRAME_HDRptr, fc_frame_header_t;

#define	WE_ARE_ORIGINATOR(fh)		(fh->f_ctl & F_CTL_XCHG_CONTEXT)
#define	UNSOLICITED_FRAME(fh)		(fh->rx_id == 0xffff)
#define	FIRST_SEQUENCE(fh)		(fh->f_ctl & F_CTL_FIRST_SEQ)
#define	LAST_FRAME_OF_SEQUENCE(fh)	(fh->f_ctl & F_CTL_END_SEQ)
#define	LAST_SEQUENCE_OF_EXCHANGE(fh)	(fh->f_ctl & F_CTL_LAST_SEQ)
#define	TRANSFER_INITIATIVE(fh)		(fh->f_ctl & F_CTL_SEQ_INITIATIVE)


/* legal values for r_ctl */
#define	R_CTL_ROUTING		0xf0 /* mask for routing bits */
#define	R_CTL_INFO		0x0f /* mask for information bits */

#define	R_CTL_DEVICE_DATA	0x00 /* all I/O related frames */
#define	R_CTL_EXTENDED_SVC	0x20 /* extended link services (PLOGI) */
#define	R_CTL_FC4_SVC		0x30 /* FC-4 link services (FCP_LOGI) */
#define	R_CTL_VIDEO_BUFF	0x40 /* not yet defined */
#define	R_CTL_BASIC_SVC		0x80 /* basic link services (NOP) */
#define	R_CTL_LINK_CTL		0xc0 /* ACKs, etc. */

/* legal values for r_ctl: Device Data */
#define	R_CTL_UNCATEGORIZED	0x00
#define	R_CTL_SOLICITED_DATA	0x01
#define	R_CTL_UNSOL_CONTROL	0x02
#define	R_CTL_SOLICITED_CONTROL	0x03
#define	R_CTL_UNSOL_DATA	0x04
#define	R_CTL_XFER_RDY		0x05
#define	R_CTL_COMMAND		0x06
#define	R_CTL_STATUS		0x07

/* legal values for r_ctl: Basic Link Services, type 0 */
#define	R_CTL_LS_NOP		0x80
#define	R_CTL_LS_ABTS		0x81
#define	R_CTL_LS_RMC		0x82
#define	R_CTL_LS_BA_ACC		0x84
#define	R_CTL_LS_BA_RJT		0x85

/* legal values for r_ctl: Extended Link Services, type 1 */
#define	R_CTL_ELS_REQ		0x22
#define	R_CTL_ELS_RSP		0x23

/* legal values for r_ctl: Link Control */
#define	R_CTL_ACK_1		0xc0
#define	R_CTL_ACK_N		0xc1
#define	R_CTL_P_RJT		0xc2
#define	R_CTL_F_RJT		0xc3
#define	R_CTL_P_BSY		0xc4
#define	R_CTL_F_BSY_DF		0xc5
#define	R_CTL_F_BSY_LC		0xc6
#define	R_CTL_LCR		0xc7

/* type field definitions for Link Data frames: */
#define	TYPE_BASIC_LS		0x00
#define	TYPE_EXTENDED_LS	0x01

/* type field definitions for Device Data frames (from FC-PH 4.1): */
#define	TYPE_IS8802		0x04
#define	TYPE_IS8802_SNAP	0x05
#define	TYPE_SCSI_FCP		0x08 /* we use this one */
#define	TYPE_SCSI_GPP		0x09
#define	TYPE_HIPP_FP		0x0a
#define	TYPE_IPI3_MASTER	0x11
#define	TYPE_IPI3_SLAVE		0x12
#define	TYPE_IPI3_PEER		0x13

#define	F_CTL_XCHG_CONTEXT	0x800000 /* 0 if SID is XCHG originator */
#define	F_CTL_SEQ_CONTEXT	0x400000 /* 0 if SID is SEQ initiator */
#define	F_CTL_FIRST_SEQ		0x200000 /* 1 if first sequence of XCHG */
#define	F_CTL_LAST_SEQ		0x100000 /* 1 if last SEQ of XCHG */
#define	F_CTL_END_SEQ		0x080000 /* 1 if last frame of a SEQ */
#define	F_CTL_END_CONNECT	0x040000 /* always 0 */
#define	F_CTL_CHAINED_SEQ	0x020000 /* always 0 */
#define	F_CTL_SEQ_INITIATIVE	0x010000 /* when 1 xfrs SEQ initiative */
#define	F_CTL_XID_REASSIGNED	0x008000 /* always 0 */
#define	F_CTL_INVALIDATE_XID	0x004000 /* always 0 */
#define	F_CTL_CONTINUE_SEQ	0x0000C0 /* always 0 */
#define	F_CTL_ABORT_SEQ		0x000030 /* always 0 */
#define	F_CTL_RO_PRESENT	0x000008 /* 1 if param field == RO */
#define	F_CTL_XCHG_REASSEMBLE	0x000004 /* always 0 */
#define	F_CTL_FILL_BYTES	0x000003 /* # of fill bytes in this frame */
#define	F_CTL_RESERVED		0x003F00
#define	F_CTL_ALWAYS_ZERO	(F_CTL_RESERVED | F_CTL_XCHG_REASSEMBLE | \
	F_CTL_ABORT_SEQ | F_CTL_CONTINUE_SEQ| F_CTL_INVALIDATE_XID | \
	F_CTL_XID_REASSIGNED | F_CTL_CHAINED_SEQ | F_CTL_END_CONNECT)

/* Well known addresses ... */
#define	FS_GENERAL_MULTICAST	0xfffff7
#define	FS_WELL_KNOWN_MULTICAST	0xfffff8
#define	FS_HUNT_GROUP		0xfffff9
#define	FS_MANAGEMENT_SERVER	0xfffffa
#define	FS_TIME_SERVER		0xfffffb
#define	FS_NAME_SERVER		0xfffffc
#define	FS_FABRIC_CONTROLLER	0xfffffd
#define	FS_FABRIC_F_PORT	0xfffffe
#define	FS_BROADCAST		0xffffff

/* Fabric Busy Reason Codes */
#define	FABRIC_BUSY		0x01
#define	NPORT_BUSY		0x03

/* NPort Busy Reason Codes */
#define	PHYSICAL_BUSY		0x01
#define	RESOURSE_BUSY		0x03

/* Reject Reason Codes */

typedef struct FC2_RJT_PARAM {
	uchar_t	rjt_action;
	uchar_t	rjt_reason;
	uchar_t	reserved[2];
} aFC2_RJT_PARAM;

#define	INVALID_D_ID		0x01
#define	INVALID_S_ID		0x02
#define	NPORT_NOT_AVAIL_TEMP	0x03
#define	NPORT_NOT_AVAIL_PERM	0x04
#define	CLASS_NOT_SUPPORTED	0x05
#define	DELIMITER_ERROR		0x06
#define	TYPE_NOT_SUPPORTED	0x07
#define	INVALID_LINK_CONTROL	0x08
#define	INVALID_R_CTL		0x09
#define	INVALID_F_CTL		0x0a
#define	INVALID_OX_ID		0x0b
#define	INVALID_RX_ID		0x0c
#define	INVALID_SEQ_ID		0x0d
#define	INVALID_DF_CTL		0x0e
#define	INVALID_SEQ_CNT		0x0f
#define	INVALID_PARAMETER	0x10
#define	EXCHANGE_ERROR		0x11
#define	PROTOCOL_ERROR		0x12
#define	INCORRECT_LENGTH	0x13
#define	UNEXPECTED_ACK		0x14
#define	UNEXPECTED_LINK_RESP	0x15
#define	LOGIN_REQUIRED		0x16
#define	EXCESSIVE_SEQUENCES	0x17
#define	CANT_ESTABLISH_EXCHANGE	0x18
#define	SECURITY_NOT_SUPPORTED	0x19

/* BA_RJT and LS_RJT reason codes */
#define	RJT_INVALID_CMD_CODE	0x01
#define	RJT_LOGICAL_ERROR	0x03
#define	RJT_LOGICAL_BUSY	0x05
#define	RJT_PROTOCOL_ERR	0x07
#define	RJT_CANT_PERFORM_RQST	0x09
#define	RJT_CMD_NOT_SUPPORTED	0x0b


/*
 * Frame Payloads that the SOC understands
 * Transfer Ready:
 */

typedef struct Xfer_Rdy {
	int32_t	seq_ro;
	int32_t	burst_len;
	int32_t	reserved;
} aXFER_RDY, *XFER_RDYptr;

/*
 * Extended Link Service Payload
 */

/* Arbitrary upper limit for now... */
#define	FC_MAX_ELS	(60-4)

typedef struct ELS_payload {
	union els_cmd_u {
	    struct {
		uchar_t	ls_command;
		uchar_t	reserved[3];
	    } c;
	    uint32_t i;
	} els_cmd;
	uchar_t	els_data[FC_MAX_ELS];
} els_payload_t;


/*
 * Data segment definition
 */
typedef struct fc_dataseg {
	uint32_t	fc_base;	/* Address of buffer. */
	uint32_t	fc_count;	/* Length of buffer. */
} fc_dataseg_t;

#ifdef	__cplusplus
}
#endif

#endif	/* !_SYS_FC4_FCAL_H */
