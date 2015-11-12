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

#ifndef _SMBSRV_NETBIOS_H
#define	_SMBSRV_NETBIOS_H

/*
 * NetBIOS over TCP/IP interface definitions. NetBIOS over TCP/IP is
 * documented in the following RFC documents:
 *
 * RFC 1001: Protocol Standard for a NetBIOS Service on a TCP/UDP
 *           Transport: Concepts and Methods
 *
 * RFC 1002: Protocol Standard for a NetBIOS Service on a TCP/UDP
 *           Transport: Detailed Specifications
 *
 * These documents reference RCF883.
 * RFC 883:  Domain Names - Implementation and Specification
 */

#ifdef __cplusplus
extern "C" {
#endif


/*
 * NetBIOS names in NetBIOS packets are valid domain names as defined in
 * RFC 883. Each label is limited to 63 bytes with an overall length of
 * 255 bytes as described in RFC 1002 section 4.1. This is known as
 * second-level encoding. In first-level encoding the label lengths are
 * represented as dots (.).
 *
 * RFC 1001 section 14.1 describes first-level encoding of the NetBIOS
 * name (hostname) and scope. The ASCII name is padded to 15 bytes using
 * spaces and a one byte type or suffix is written to the 16th byte.
 * This is then encoded as a 32 byte string.
 *
 * NetBIOS Name:  NetBIOS
 * NetBIOS Scope: DOMAIN.COM
 * First Level:   EOGFHEECEJEPFDCACACACACACACACACA.DOMAIN.COM
 * Second Level:  <32>EOGFHEECEJEPFDCACACACACACACACACA<6>DOMAIN<3>COM<0>
 */
#define	NETBIOS_NAME_SZ			16
#define	NETBIOS_ENCODED_NAME_SZ		32
#define	NETBIOS_LABEL_MAX		63
#define	NETBIOS_DOMAIN_NAME_MAX		255
#define	NETBIOS_DOMAIN_NAME_BUFLEN	(NETBIOS_DOMAIN_NAME_MAX + 1)
#define	NETBIOS_SESSION_REQUEST_DATA_LENGTH \
	((NETBIOS_ENCODED_NAME_SZ + 2) * 2)

#define	NETBIOS_HDR_SZ			4	/* bytes */

/*
 * NetBIOS name type/suffix: 16th byte of the NetBIOS name.
 * The NetBIOS suffix is used by to identify computer services.
 */
#define	NBT_WKSTA			0x00	/* Workstation Service */
#define	NBT_CLIENT			0x03	/* Messenger Service */
#define	NBT_RASSRVR			0x06	/* RAS Server Service */
#define	NBT_DMB				0x1B	/* Domain Master Browser */
#define	NBT_IP				0x1C	/* Domain Controller */
#define	NBT_MB				0x1D	/* Master Browser */
#define	NBT_BS				0x1E	/* Browser Elections */
#define	NBT_NETDDE			0x1F	/* NetDDE Service */
#define	NBT_SERVER			0x20	/* Server Service */
#define	NBT_RASCLNT			0x21	/* RAS Client Service */

/*
 * Session Packet Types (RFC 1002 4.3.1).
 */
#define	SESSION_MESSAGE			0x00
#define	SESSION_REQUEST			0x81
#define	POSITIVE_SESSION_RESPONSE	0x82
#define	NEGATIVE_SESSION_RESPONSE	0x83
#define	RETARGET_SESSION_RESPONSE	0x84
#define	SESSION_KEEP_ALIVE		0x85

/*
 * NEGATIVE SESSION RESPONSE packet error code values (RFC 1002 4.3.4).
 */
#define	SESSION_NOT_LISTENING_ON_CALLED_NAME	0x80
#define	SESSION_NOT_LISTENING_FOR_CALLING_NAME	0x81
#define	SESSION_CALLED_NAME_NOT_PRESENT		0x82
#define	SESSION_INSUFFICIENT_RESOURCES		0x83
#define	SESSION_UNSPECIFIED_ERROR		0x8F

/*
 * Time conversions
 */
#define	MILLISECONDS	1
#define	SECONDS		(1000 * MILLISECONDS)
#define	MINUTES		(60 * SECONDS)
#define	HOURS		(60 * MINUTES)
#define	TO_SECONDS(x)		((x) / 1000)
#define	TO_MILLISECONDS(x)	((x) * 1000)

/*
 * DATAGRAM service definitions
 */
#define	DATAGRAM_DESTINATION_NAME_NOT_PRESENT		0x82
#define	DATAGRAM_INVALID_SOURCE_NAME_FORMAT		0x83
#define	DATAGRAM_INVALID_DESTINATION_NAME_FORMAT	0x84

#define	MAX_DATAGRAM_LENGTH		576
#define	DATAGRAM_HEADER_LENGTH		14
#define	DATAGRAM_ERR_HEADER_LENGTH	11
#define	MAX_NAME_LENGTH			256
#define	BCAST_REQ_RETRY_COUNT		2
#define	UCAST_REQ_RETRY_COUNT		2
#define	BCAST_REQ_RETRY_TIMEOUT		(500 * MILLISECONDS)
#define	UCAST_REQ_RETRY_TIMEOUT		(500 * MILLISECONDS)
#define	CONFLICT_TIMER			(1 * SECONDS)
#define	INFINITE_TTL			0
#define	DEFAULT_TTL			(600 * SECONDS)
#define	SSN_RETRY_COUNT			4
#define	SSN_CLOSE_TIMEOUT		(30 * SECONDS)
#define	FRAGMENT_TIMEOUT	(2 * SECONDS)

/* smb_netbios_util.c */
extern int netbios_first_level_name_decode(char *in, char *name, char *scope);
extern int netbios_first_level_name_encode(unsigned char *name,
    unsigned char *scope, unsigned char *out, int max_out);
extern int netbios_name_isvalid(char *in, char *out);

#ifdef __cplusplus
}
#endif

#endif /* _SMBSRV_NETBIOS_H */
