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
 * PPPoE Protocol definitions.
 *
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * See also:
 *	RFC 2516, A Method for Transmitting PPP Over Ethernet (PPPoE)
 */

#ifndef _NETINET_PPPOE_H
#define	_NETINET_PPPOE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Protocol description and well-known constants used by Informational
 * RFC 2516, "A Method for Transmitting PPP Over Ethernet (PPPoE)."
 *
 * Caution:  Note that, contrary to standard practice, length counts
 * used in PPPoE do not include the applicable header length.
 */

/* Aligned PPPoE packet header; both discovery and session stages */
typedef struct poep_s {
	uint8_t		poep_version_type;	/* Use POE_VERSION */
	uint8_t		poep_code;	/* POECODE_* below */
	uint16_t	poep_session_id;	/* POESESS_* below */
	uint16_t	poep_length;	/* NOT including this header */
} poep_t;
#define	POE_HDR_ALIGN	(sizeof (ushort_t))

#define	PPPOE_MSGMAX	1500	/* Maximum possible message length */
#define	PPPOE_MTU	1492	/* Maximum PPP MTU/MRU with PPPoE */
#define	PPPOE_MAXPADI	1484	/* Max from RFC 2516 */

#define	POE_VERSION	0x11	/* RFC 2516 version/type fields */

/* poep_t.poep_code numbers from RFC 2516 */
#define	POECODE_DATA	0x00	/* Data packet (uses other Ethertype) */
#define	POECODE_PADO	0x07	/* Active Discovery Offer */
#define	POECODE_PADI	0x09	/* Active Discovery Initiation (bcast) */
#define	POECODE_PADR	0x19	/* Active Discovery Request */
#define	POECODE_PADS	0x65	/* Active Discovery Session-confirmation */
#define	POECODE_PADT	0xA7	/* Active Discovery Terminate */

/* poep_t.poep_code numbers from draft-carrel-info-pppoe-ext. */
#define	POECODE_PADM	0xD3	/* Active Discovery Message */
#define	POECODE_PADN	0xD4	/* Active Discovery Network */

/* Special values for poep_t.poep_session_id */
#define	POESESS_NONE	0x0000	/* PADI, PADO, and PADR only */
#define	POESESS_ALL	0xFFFF	/* For multicast data */

/*
 * Tag parsing macros (unaligned) for discovery stage packets.
 * These assume that the pointer to the data is a uint8_t *.
 */
#define	POET_GET_TYPE(x)	(((x)[0]<<8) | (x)[1])
#define	POET_SET_TYPE(x, t)	(void)((x)[0] = (t)>>8, (x)[1] = (t)&0xFF)
#define	POET_GET_LENG(x)	(((x)[2]<<8) | (x)[3])
#define	POET_SET_LENG(x, l)	(void)((x)[2] = (l)>>8, (x)[3] = (l)&0xFF)
#define	POET_HDRLEN		4
#define	POET_DATA(x)		((x)+POET_HDRLEN)
#define	POET_NEXT(x)		(POET_DATA(x) + POET_GET_LENG(x))

/* Tag types for discovery stage packets from RFC 2516. */
#define	POETT_END	0x0000	/* End-Of-List; not required */
#define	POETT_SERVICE	0x0101	/* Service-Name; UTF-8 string follows */
#define	POETT_ACCESS	0x0102	/* AC-Name; UTF-8 */
#define	POETT_UNIQ	0x0103	/* Host-Uniq; arbitrary binary */
#define	POETT_COOKIE	0x0104	/* AC-Cookie; DoS reducer */
#define	POETT_VENDOR	0x0105	/* Vendor-Specific; 0+enterprise+data */
#define	POETT_RELAY	0x0110	/* Relay-Session-Id; opaque data */
#define	POETT_NAMERR	0x0201	/* Service-Name-Error; no data */
#define	POETT_SYSERR	0x0202	/* AC-System-Error; may have UTF-8 */
#define	POETT_GENERR	0x0203	/* Generic-Error; may have UTF-8 */

/* Tag types from draft-carrel-info-pppoe-ext. */
#define	POETT_MULTI	0x0106	/* Multicast-Capable; one byte version */
#define	POETT_HURL	0x0111	/* Host-URL; UTF-8 for browser */
#define	POETT_MOTM	0x0112	/* Message-Of-The-Minute; UTF-8 for human */
#define	POETT_RTEADD	0x0121	/* IP-Route-Add; single poer_t below */

/* Data byte in POETT_MULTI (Multicast-Capable) tag. */
#define	POET_MULTI_VER	0x00	/* Current version is zero */

/* POETT_RTEADD tag contents */
typedef struct poer_s {
	uint32_t	poer_dest_network;
	uint32_t	poer_subnet_mask;
	uint32_t	poer_gateway;
	uint32_t	poer_metric;
} poer_t;

#ifdef __cplusplus
}
#endif

#endif /* _NETINET_PPPOE_H */
