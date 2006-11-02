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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * etm_etm_proto.h	FMA ETM-to-ETM Protocol header
 *			for sun4v/Ontario
 *
 * const/type defns for protocol used between two event transport
 * modules (ETMs)
 */

#ifndef _ETM_ETM_PROTO_H
#define	_ETM_ETM_PROTO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * --------------------------------- includes --------------------------------
 */

#include <sys/types.h>

/*
 * ------------------------ etm protocol all versions ------------------------
 */

/* magic number for ETM protocol (start of msg hdr) */

#define	ETM_PROTO_MAGIC_NUM (0xADB8A5A0)

/* protocol version numbers 1, 2, ... */

#define	ETM_PROTO_V1 (1)
#define	ETM_PROTO_V2 (2)
#define	ETM_PROTO_V3 (3)

/*
 * Design_Note:	Protocol V2 uses the same headers and constants as V1.
 *		The V1 and V2 protocols differ from each other only in the
 *		support of response messages for FMA event messages with
 *		non-NONE timeout fields. In V1 it is invalid to supply a
 *		timeout value that is non-NONE when sending an ETM message
 *		containing an FMA event; in V2 it is valid. In both V1 and
 *		V2 it is valid to supply a non-NONE timeout when sending an
 *		ETM control message. V1 is the initial bootup protocol version;
 *		from there version is negotiated upward.
 */

/*
 * Design_Note: Protocol V3 introduces a new message type for
 * syslog alerting.  It uses the same protocols and preambles.
 */

/*
 * Design_Note:	Care should be taken for any future V4 protocol, particularly
 *		if the size of the protocol preamble shrinks vs the current
 *		size, so that if ETM is implemented to receive each message
 *		header as a whole, it won't pend indefinitely when sent a
 *		[tiny] V4 message.
 */

/*
 * ------------------------ etm protocol versions 1,2 ----------------------
 */

typedef enum {

	ETM_MSG_TYPE_TOO_LOW = 0,	/* range check place holder */
	ETM_MSG_TYPE_FMA_EVENT,		/* pp_msg_type: FMA event */
	ETM_MSG_TYPE_CONTROL,		/* pp_msg_type: ETM control */
	ETM_MSG_TYPE_RESPONSE,		/* pp_msg_type: ETM response */
	ETM_MSG_TYPE_ALERT,		/* pp_msg_type: Syslog alert */
	ETM_MSG_TYPE_TOO_BIG		/* range check place holder */

} etm_proto_v3_msg_type_t;	/* 8-bit pp_msg_type ETM message types */

#define	ETM_PROTO_V1_TIMEOUT_NONE	((uint32_t)(-1))
#define	ETM_PROTO_V1_TIMEOUT_FOREVER	((uint32_t)(-2))

typedef struct etm_proto_v1_pp {

	uint32_t	pp_magic_num;	/* magic number */
	uint8_t		pp_proto_ver;	/* version of ETM protocol */
	uint8_t		pp_msg_type;	/* type of ETM msg */
	uint8_t		pp_sub_type;	/* sub type within pp_msg_type */
	uint8_t		pp_rsvd_pad;	/* reserved/padding/alignment */
	uint32_t	pp_xid;		/* transaction id */
	uint32_t	pp_timeout;	/* timeout (in sec) for response */

} etm_proto_v1_pp_t;	/* protocol preamble for all v1 msg hdrs */

typedef struct etm_proto_v1_ev_hdr {

	etm_proto_v1_pp_t	ev_pp;		/* protocol preamble */
	uint32_t		ev_lens[1];	/* 0-termed lengths vector */

	/* uint8_t ev_bodies[];		contig packed FMA events */

} etm_proto_v1_ev_hdr_t;	/* header for FMA_EVENT msgs */

/*
 * V3 addition: Syslog Alert.  Uses the same protocol preamble as V1/V2
 */

typedef struct etm_proto_v3_sa_hdr {

	etm_proto_v1_pp_t	sa_pp;		/* protocol preamble */
	uint32_t		sa_priority;	/* priority for syslog */
	uint32_t		sa_len;		/* message string length */

	/* uint8_t sa_message[];		contig message string */

} etm_proto_v3_sa_hdr_t;	/* header for ALERT msgs */

typedef enum {

	ETM_CTL_SEL_TOO_LOW = 16,	/* range check place holder */
	ETM_CTL_SEL_PING_REQ,		/* ping request */
	ETM_CTL_SEL_VER_NEGOT_REQ,	/* negotiate proto version request */
	ETM_CTL_SEL_TOO_BIG		/* range check place holder */

} etm_proto_v1_ctl_sel_t;	/* 8-bit pp_sub_type control selectors */

typedef struct etm_proto_v1_ctl_hdr {

	etm_proto_v1_pp_t	ctl_pp;		/* protocol preamble */
	uint32_t  		ctl_len;	/* length of control body */

	/* uint8_t ctl_body[];	   contig accompanying control data */

} etm_proto_v1_ctl_hdr_t;	/* header for CONTROL msgs */

typedef struct etm_proto_v1_resp_hdr {

	etm_proto_v1_pp_t	resp_pp;	/* protocol preamble */
	int32_t   		resp_code;	/* -errno or success code */
	uint32_t  		resp_len;	/* length of response body */

	/* uint8_t resp_body[];	   contig accompanying response data */

} etm_proto_v1_resp_hdr_t;

/*
 * --------------------------------- prolog ----------------------------------
 */

#ifdef __cplusplus
}
#endif

#endif /* _ETM_ETM_PROTO_H */
