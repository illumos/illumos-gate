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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_IB_MGT_IBMF_IBMF_RMPP_H
#define	_SYS_IB_MGT_IBMF_IBMF_RMPP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains the IBMF RMPP implementation dependent structures
 * and defines.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* The RMPP context */
typedef struct _ibmf_rmpp_ctx_t {
	uint32_t		rmpp_wf;  /* first segment in window (send) */
	uint32_t		rmpp_wl;  /* last segment in window (send) */
	uint32_t		rmpp_ns;  /* next segment in window (send) */
	uint32_t		rmpp_es;  /* expected segment num (receive) */
	uint32_t		rmpp_is_ds;	/* direction change indicator */
	uint32_t		rmpp_nwl;	/* new window last */
	uint32_t		rmpp_pyld_len;	/* payload length */
	uint32_t		rmpp_state;	/* rmpp protocol state */
	uint32_t		rmpp_retry_cnt; /* retry count */
	uint32_t		rmpp_pkt_data_sz; /* data size in packet */
	uint32_t		rmpp_last_pkt_sz; /* data size in last packet */
	uint32_t		rmpp_num_pkts;	/* number of packets needed */
	size_t			rmpp_data_offset; /* offset in data buffer */
	uint32_t		rmpp_word3;	/* 3rd word of RMPP hdr */
	uint32_t		rmpp_word4;	/* 4th word of RMPP hdr */
	uint8_t			rmpp_type;	/* type of RMPP packet */
	uint8_t			rmpp_respt;	/* resp time for RMPP packet */
	uint8_t			rmpp_flags;	/* rmpp flags */
	uint8_t			rmpp_status;	/* status for RMPP packet */
} ibmf_rmpp_ctx_t;

/* RMPP state definitions */
#define	IBMF_RMPP_STATE_UNDEFINED		0
#define	IBMF_RMPP_STATE_SENDER_ACTIVE		1
#define	IBMF_RMPP_STATE_SENDER_SWITCH		2
#define	IBMF_RMPP_STATE_RECEVR_ACTIVE		3
#define	IBMF_RMPP_STATE_RECEVR_TERMINATE	4
#define	IBMF_RMPP_STATE_ABORT			5
#define	IBMF_RMPP_STATE_DONE			6

/* RMPP context flags definition */
#define	IBMF_CTX_RMPP_FLAGS_DYN_PYLD		8

#define	IBMF_RMPP_DEFAULT_RRESPT		0x1F
#define	IBMF_RMPP_TERM_RRESPT			0xE

#define	IBMF_RMPP_METHOD_RESP_BIT		0x80

/* RMPP header (IB Architecture Specification 1.1, Section 13.6.2) */
#if defined(_BIT_FIELDS_HTOL)
typedef struct _ibmf_rmpp_hdr_t {
	uint8_t			rmpp_version;		/* RMPP version = 1 */
	uint8_t			rmpp_type;		/* RMPP packet type */
	uint8_t			rmpp_resp_time	:5;	/* response time val */
	uint8_t			rmpp_flags	:3;	/* RMPP flags */
	uint8_t			rmpp_status;		/* RMPP status */

	uint32_t		rmpp_segnum;		/* packet ID */

	/* Payload len for data or, NewWindowLast for ack packets */
	uint32_t		rmpp_pyldlen_nwl;
} ibmf_rmpp_hdr_t;
#else
typedef struct _ibmf_rmpp_hdr_t {
	uint8_t			rmpp_version;		/* RMPP version = 1 */
	uint8_t			rmpp_type;		/* RMPP packet type */
	uint8_t			rmpp_flags	:3;	/* RMPP flags */
	uint8_t			rmpp_resp_time	:5;	/* response time val */
	uint8_t			rmpp_status;		/* RMPP status */

	uint32_t		rmpp_segnum;		/* packet ID */

	/* Payload len for data or, NewWindowLast for ack packets */
	uint32_t		rmpp_pyldlen_nwl;
} ibmf_rmpp_hdr_t;
#endif

_NOTE(READ_ONLY_DATA(ibmf_rmpp_hdr_t))

/* RMPP header type definitions */
#define	IBMF_RMPP_TYPE_NONE		0
#define	IBMF_RMPP_TYPE_DATA		1
#define	IBMF_RMPP_TYPE_ACK		2
#define	IBMF_RMPP_TYPE_STOP		3
#define	IBMF_RMPP_TYPE_ABORT		4

/* RMPP header flags definitions */
#define	IBMF_RMPP_FLAGS_ACTIVE		0x1
#define	IBMF_RMPP_FLAGS_FIRST_PKT	0x2
#define	IBMF_RMPP_FLAGS_LAST_PKT	0x4

/* RMPP_header status definitions */
#define	IBMF_RMPP_STATUS_NORMAL		0	/* Normal */
#define	IBMF_RMPP_STATUS_RESX		1	/* Resources exhausted */
#define	IBMF_RMPP_STATUS_T2L		118	/* Total time too long */

/* Inconsistent last and payload length */
#define	IBMF_RMPP_STATUS_ILPL		119

/* Inconsistent first and segment number */
#define	IBMF_RMPP_STATUS_IFSN		120

#define	IBMF_RMPP_STATUS_BADT		121	/* Bad RMPP type */
#define	IBMF_RMPP_STATUS_W2S		122	/* New window last too small */
#define	IBMF_RMPP_STATUS_S2B		123	/* Segment number too big */
#define	IBMF_RMPP_STATUS_IS		124	/* Illegal status */
#define	IBMF_RMPP_STATUS_UNV		125	/* Unsupported version */
#define	IBMF_RMPP_STATUS_TMR		126	/* Too many retries */
#define	IBMF_RMPP_STATUS_USP		127	/* Unspecified error */

#define	IBMF_RMPP_VERSION		1
#define	IBMF_RMPP_DEFAULT_WIN_SZ	5
#define	IBMF_NO_BLOCK			0

#ifdef __cplusplus
}
#endif

#endif /* _SYS_IB_MGT_IBMF_IBMF_RMPP_H */
