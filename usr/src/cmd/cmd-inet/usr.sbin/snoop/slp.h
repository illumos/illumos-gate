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
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SNOOP_SLP_H
#define	_SNOOP_SLP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Structs and definitions for the snoop SLP interpreter only
 * (This code is not used by the SLP library).
 */

#ifdef __cplusplus
extern "C" {
#endif

struct slpv1_hdr {
	unsigned char	vers;
	unsigned char	function;
	unsigned short	length;
	unsigned char	flags;
	unsigned char	dialect;
	unsigned char	language[2];
	unsigned short	charset;
	unsigned short	xid;
};

struct slpv2_hdr {
	unsigned char	vers;
	unsigned char	function;
	unsigned char	l1, l2, l3;
	unsigned char	flags;
	unsigned char	reserved;
	unsigned char	o1, o2, o3;
	unsigned short	xid;
};

/*
 *  flags
 */
#define	V1_OVERFLOW	0x80
#define	V1_MONOLINGUAL	0x40
#define	V1_URL_AUTH	0x20
#define	V1_ATTR_AUTH	0x10
#define	V1_FRESH_REG	0x08

#define	V2_OVERFLOW	0x80
#define	V2_FRESH	0x40
#define	V2_MCAST	0x20

/*
 * packet types
 */

#define	V1_SRVREQ 1
#define	V1_SRVRPLY 2
#define	V1_SRVREG 3
#define	V1_SRVDEREG 4
#define	V1_SRVACK 5
#define	V1_ATTRRQST 6
#define	V1_ATTRRPLY 7
#define	V1_DAADVERT 8
#define	V1_SRVTYPERQST 9
#define	V1_SRVTYPERPLY 10

#define	V2_SRVRQST	1
#define	V2_SRVRPLY	2
#define	V2_SRVREG	3
#define	V2_SRVDEREG	4
#define	V2_SRVACK	5
#define	V2_ATTRRQST	6
#define	V2_ATTRRPLY	7
#define	V2_DAADVERT	8
#define	V2_SRVTYPERQST	9
#define	V2_SRVTYPERPLY	10
#define	V2_SAADVERT	11

/*
 * extended packet types
 */
#define	SCOPERQST 65
#define	SCOPERPLY 66
#define	DARQST	  67
#define	DARPLY	  68
#define	DASTRIKE  69


/*
 * error codes
 */

#define	OK				0x0000
#define	LANG_NOT_SUPPORTED		0x0001
#define	PROTOCOL_PARSE_ERR		0x0002
#define	INVALID_REGISTRATION		0x0003
#define	SCOPE_NOT_SUPPORTED		0x0004
#define	CHARSET_NOT_UNDERSTOOD		0x0005
#define	AUTHENTICATION_UNKNOWN		0x0005
#define	AUTHENTICATION_INVALID		0x0006
#define	V2_AUTHENTICATION_ABSENT	0x0006
#define	V2_AUTHENTICATION_FAILED	0x0007
#define	V2_VER_NOT_SUPPORTED		0x0009
#define	NOT_SUPPORTED_YET		0x000a
#define	V2_INTERNAL_ERROR		0x000a
#define	REQUEST_TIMED_OUT		0x000b
#define	V2_DA_BUSY_NOW			0x000b
#define	COULD_NOT_INIT_NET_RESOURCES	0x000c
#define	V2_OPTION_NOT_UNDERSTOOD	0x000c
#define	COULD_NOT_ALLOCATE_MEMORY	0x000d
#define	V2_INVALID_UPDATE		0x000d
#define	PARAMETER_BAD			0x000e
#define	V2_RQST_NOT_SUPPORTED		0x000e
#define	INVALID_LIFETIME		0x000f

#define	INTERNAL_NET_ERROR		0x000f
#define	INTERNAL_SYSTEM_ERROR		0x0010

#ifdef __cplusplus
}
#endif

#endif	/* _SNOOP_SLP_H */
