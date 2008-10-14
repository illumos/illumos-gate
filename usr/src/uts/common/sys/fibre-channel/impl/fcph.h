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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_FIBRE_CHANNEL_IMPL_FCPH_H
#define	_SYS_FIBRE_CHANNEL_IMPL_FCPH_H


#include <sys/note.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if !defined(_BIT_FIELDS_LTOH) && !defined(_BIT_FIELDS_HTOL)
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif	/* _BIT_FIELDS_LTOH */

/* legal values for r_ctl */
#define	R_CTL_ROUTING		0xF0 /* mask for routing bits */
#define	R_CTL_INFO		0x0F /* mask for information bits */

#define	R_CTL_DEVICE_DATA	0x00 /* all I/O related frames */
#define	R_CTL_EXTENDED_SVC	0x20 /* extended link services (PLOGI) */
#define	R_CTL_FC4_SVC		0x30 /* FC-4 link services (FCP_LOGI) */
#define	R_CTL_VIDEO_BUFF	0x40 /* not yet defined */
#define	R_CTL_BASIC_SVC		0x80 /* basic link services (NOP) */
#define	R_CTL_LINK_CTL		0xC0 /* ACKs, etc. */

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
#define	R_CTL_ACK_1		0xC0
#define	R_CTL_ACK_N		0xC1
#define	R_CTL_P_RJT		0xC2
#define	R_CTL_F_RJT		0xC3
#define	R_CTL_P_BSY		0xC4
#define	R_CTL_F_BSY_DF		0xC5
#define	R_CTL_F_BSY_LC		0xC6
#define	R_CTL_LCR		0xC7

/* type field definitions for Link Data frames: */
#define	FC_TYPE_BASIC_LS	0x00
#define	FC_TYPE_EXTENDED_LS	0x01

/* type field definitions for Device Data frames (from FC-PH 4.1): */
#define	FC_TYPE_IS8802		0x04
#define	FC_TYPE_IS8802_SNAP	0x05
#define	FC_TYPE_SCSI_FCP	0x08
#define	FC_TYPE_SCSI_GPP	0x09
#define	FC_TYPE_HIPP_FP		0x0a
#define	FC_TYPE_IPI3_MASTER	0x11
#define	FC_TYPE_IPI3_SLAVE	0x12
#define	FC_TYPE_IPI3_PEER	0x13
#define	FC_TYPE_FC_SERVICES	0x20

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

/* values for DF_CTL */
#define	DF_CTL_EXT_FR_HDR	0x80
#define	DF_CTL_EXP_SEC_HDR	0x40
#define	DF_CTL_NET_HDR		0x20
#define	DF_CTL_ASSOC_HDR	0x10
#define	DF_CTL_RESERVED		0x0C
#define	DF_CTL_DEV_HDR_16	0x01
#define	DF_CTL_DEV_HDR_32	0x02
#define	DF_CTL_DEV_HDR_64	0x03
#define	DF_CTL_NO_DEV_HDR	0x00

/* Well known addresses ... */
#define	NPORT_ID_DOM_CTLR_START	0xFFFC01 /* N_Port IDs for domain controller */
#define	NPORT_ID_DOM_CTLR_END	0xFFFCFE

#define	FS_GENERAL_MULTICAST	0xFFFFF7
#define	FS_WELL_KNOWN_MULTICAST	0xFFFFF8
#define	FS_HUNT_GROUP		0xFFFFF9
#define	FS_MANAGEMENT_SERVER	0xFFFFFA
#define	FS_TIME_SERVER		0xFFFFFB
#define	FS_NAME_SERVER		0xFFFFFC
#define	FS_FABRIC_CONTROLLER	0xFFFFFD
#define	FS_FABRIC_F_PORT	0xFFFFFE
#define	FS_BROADCAST		0xFFFFFF

#define	FC_WELL_KNOWN_START	0xFFFFF0
#define	FC_WELL_KNOWN_END	0xFFFFFF
#define	FC_WELL_KNOWN_ADDR(x)	(((x) >= FC_WELL_KNOWN_START &&\
				(x) <= FC_WELL_KNOWN_END) || \
				((x) >= NPORT_ID_DOM_CTLR_START && \
				(x) <= NPORT_ID_DOM_CTLR_END))

/*
 * frame header
 */
typedef struct frame_header {

#if defined(_BIT_FIELDS_LTOH)
	uint32_t	d_id	: 24,
			r_ctl	: 8;
	uint32_t	s_id	: 24,
			rsvd	: 8;
	uint32_t	f_ctl	: 24,
			type	: 8;
	uint32_t	seq_cnt	: 16,
			df_ctl	: 8,
			seq_id 	: 8;
	uint32_t	rx_id	: 16,
			ox_id	: 16;
	uint32_t	ro;

#else
	uint32_t	r_ctl 	: 8,
			d_id 	: 24;
	uint32_t	rsvd 	: 8,
			s_id	: 24;
	uint32_t	type	: 8,
			f_ctl	: 24;
	uint32_t	seq_id	: 8,
			df_ctl	: 8,
			seq_cnt	: 16;
	uint32_t	ox_id	: 16,
			rx_id	: 16;
	uint32_t	ro;
#endif	/* _BIT_FIELDS_LTOH */
} fc_frame_hdr_t;

#if	!defined(__lint)
_NOTE(SCHEME_PROTECTS_DATA("unique per request", frame_header))
#endif	/* __lint */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FIBRE_CHANNEL_IMPL_FCPH_H */
