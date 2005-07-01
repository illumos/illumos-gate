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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PCP_COMMON_H
#define	_PCP_COMMON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This file is shared by both ALOM and Solaris sides of
 * Platform Channel Protocol users. So this file should
 * include only common shared things.
 */

/*
 * Platform Channel Request Message Header.
 */
typedef struct pcp_req_msg_hdr {
	uint32_t	magic_num;	/* magic number */
	uint8_t		proto_ver;	/* version info for */
					/* backward compatibility */
	uint8_t		msg_type;	/* provided by user apps */
	uint8_t		sub_type;	/* provided by user apps */
	uint8_t		rsvd_pad;	/* padding bits */
	uint32_t	xid;		/* transaction id */
	uint32_t	timeout;	/* timeout in seconds */
	uint32_t	msg_len;	/* length of request or response data */
	uint16_t	msg_cksum;	/* 16-bit checksum of req msg data */
	uint16_t	hdr_cksum;	/* 16-bit checksum of req hdr */
} pcp_req_msg_hdr_t;


/*
 * Platform Channel Response Message Header.
 */
typedef struct pcp_resp_msg_hdr {
	uint32_t 	magic_num;	/* magic number */
	uint8_t		proto_ver;	/* version info for */
					/* backward compatibility */
	uint8_t		msg_type;	/* passed to user apps */
	uint8_t		sub_type;	/* passed to user apps */
	uint8_t		rsvd_pad;	/* for padding */
	uint32_t	xid;		/* transaction id */
	uint32_t	timeout;	/* timeout in seconds */
	uint32_t	msg_len;	/* length of request or response data */
	uint32_t	status;		/* response status */
	uint16_t	msg_cksum;	/* 16-bit checksum of resp msg data */
	uint16_t	hdr_cksum;	/* 16-bit checksum of resp hdr */
} pcp_resp_msg_hdr_t;

/*
 * magic number for Platform Channel Protocol (PCP)
 * ~(rot13("PCP_") = 0xAFBCAFA0
 * rot13 is a simple Caesar-cypher encryption that replaces each English letter
 * with the one 13 places forward or back along the alphabet.
 */
#define	PCP_MAGIC_NUM		(0xAFBCAFA0)


/* Platform channel protocol versions. */
#define	PCP_PROT_VER_1		1


/* Error codes for 'status' field in response message header */

#define	PCP_OK			(0)	/* message received okay */
#define	PCP_ERROR		(1)	/* generic error */
#define	PCP_HDR_CKSUM_ERROR	(2)	/* header checksum error */
#define	PCP_MSG_CKSUM_ERROR	(3)	/* message checksum error */
#define	PCP_XPORT_ERROR		(4)	/* message in complete error */

/* defines for 'timeout' */
#define	PCP_TO_NO_RESPONSE	(0xFFFFFFFF)	/* no response required */
#define	PCP_TO_WAIT_FOREVER	(0)	/* wait forever..(in reality, */
					/* it waits until glvc driver */
					/* call returns; curently glvc */
					/* calls are blocking calls. */

#ifdef	__cplusplus
}
#endif

#endif /* _PCP_COMMON_H */
