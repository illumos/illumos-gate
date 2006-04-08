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
 * FMA ETM-to-ETM Protocol header
 *
 * const/type defns for protocol used between two event transport
 * modules (ETMs)
 */

#ifndef _ETM_PROTO_H
#define	_ETM_PROTO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

#define	ETM_DELIM	"\177ETM"	/* Start of header delimiter */
#define	ETM_DELIMLEN	4		/* Length of header deimiter */

typedef struct etm_proto_header {
	char hdr_delim[ETM_DELIMLEN];	/* Start of header delimiter */
	uint8_t hdr_ver;		/* ETM protocol version */
	uint8_t hdr_type;		/* Header type */
	uint8_t hdr_pad1;		/* reserved/padding/alignment */
	uint8_t hdr_pad2;		/* reserved/padding/alignment */
	uint32_t hdr_msglen;		/* Length of following message */
} etm_proto_hdr_t;

typedef enum etm_proto_header_type {
	ETM_HDR_TYPE_TOO_LOW = 0,	/* Range check place holder */
	ETM_HDR_MSG,			/* FMA event to follow */
	ETM_HDR_S_RESTART,		/* Server re-start indication */
	ETM_HDR_C_HELLO,		/* Client startup indication */
	ETM_HDR_S_HELLO,		/* Server response to C_HELLO */
	ETM_HDR_ACK,			/* Acknowledgement */
	ETM_HDR_NAK,			/* Negative acknowledgement */
	ETM_HDR_SHUTDOWN,		/* Notify remote ETM of shutdown */
	ETM_HDR_TYPE_TOO_HIGH		/* Range check place holder */
} etm_proto_hdr_type_t;

#define	ETM_HDRLEN sizeof (etm_proto_hdr_t)
#define	ETM_PROTO_V1 1

#ifdef __cplusplus
}
#endif

#endif /* _ETM_PROTO_H */
