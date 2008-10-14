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

#ifndef	_RADIUS_PROTOCOL_H
#define	_RADIUS_PROTOCOL_H

#ifdef __cplusplus
extern "C" {
#endif

/* Packet type. RFC 2865 section 4. */
#define	RAD_ACCESS_REQ		1	/* Authentication Request */
#define	RAD_ACCESS_ACPT		2	/* Authentication Accepted */
#define	RAD_ACCESS_REJ		3	/* Authentication Rejected */

/* RADIUS Attribute Types. RFC 2865 section 5. */
#define	RAD_USER_NAME		1
#define	RAD_CHAP_PASSWORD	3
#define	RAD_CHAP_CHALLENGE	60

/* RFC 2865 Section 3. The Identifier field is one octet. */
#define	RAD_IDENTIFIER_LEN	1

/* RFC 2865 Section 5.3. The String field is 16 octets. */
#define	RAD_CHAP_PASSWD_STR_LEN	16

/* RFC 2865 Section 3. Authenticator field is 16 octets. */
#define	RAD_AUTHENTICATOR_LEN	16

/* RFC 2865 Section 5: 1-253 octets */
#define	MAX_RAD_ATTR_VALUE_LEN	253

/* RFC 2865 Section 3. Minimum length 20 octets. */
#define	MIN_RAD_PACKET_LEN	20

/* RFC 2865 Section 3. Maximum length 4096 octets. */
#define	MAX_RAD_PACKET_LEN	4096

/* Maximum RADIUS shared secret length (in fact there is no defined limit) */
#define	MAX_RAD_SHARED_SECRET_LEN	128

/* RFC 2865 Section 3. Minimum RADIUS shared secret length */
#define	MIN_RAD_SHARED_SECRET_LEN	16

/* Raw RADIUS packet. RFC 2865 section 3. */
typedef struct radius_packet {
	uint8_t	code;		/* RADIUS code, section 3, RFC 2865 */
	uint8_t	identifier;	/* 1 octet in length. RFC 2865 section 3 */
	uint8_t	length[2];	/* 2 octets, or sizeof (u_short) */
	uint8_t	authenticator[RAD_AUTHENTICATOR_LEN];
	uint8_t	data[1];
} radius_packet_t;

/* Length of a RADIUS packet minus the payload */
#define	RAD_PACKET_HDR_LEN		20

#ifdef __cplusplus
}
#endif

#endif /* _RADIUS_PROTOCOL_H */
