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

#ifndef	_INET_IPSEC_INFO_H
#define	_INET_IPSEC_INFO_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/crypto/common.h>

/*
 * IPsec informational messages.  These are M_CTL STREAMS messages, which
 * convey IPsec information between various IP and related modules.  Most
 * have been deprecated by the de-STREAMS-ing of TCP/IP.  What remains is:
 *
 *	* Keysock consumer interface  -  These messages are wrappers for
 *	  PF_KEY messages.  They flow between AH/ESP and keysock.
 *
 */

/*
 * The IPsec M_CTL value MUST be something that will not be even close
 * to an IPv4 or IPv6 header.  This means the first byte must not be
 * 0x40 - 0x4f or 0x60-0x6f.  For big-endian machines, this is fixable with
 * the IPSEC_M_CTL prefix.  For little-endian machines, the actual M_CTL
 * _type_ must not be in the aforementioned ranges.
 *
 * The reason for this avoidance is because M_CTL's with a real IPv4/IPv6
 * datagram get sent from to TCP or UDP when an ICMP datagram affects a
 * TCP/UDP session.
 */
#define	IPSEC_M_CTL	0x73706900

/*
 * M_CTL types for IPsec messages.  Remember, the values 0x40 - 0x4f and 0x60
 * - 0x6f are not to be used because of potential little-endian confusion.
 *
 * Offsets 3-7 (decimal) are in use, spread through this file.
 * Check for duplicates through the whole file before adding.
 */

/*
 * Keysock consumer interface.
 *
 * The driver/module keysock (which is a driver to PF_KEY sockets, but is
 * a module to 'consumers' like AH and ESP) uses keysock consumer interface
 * messages to pass on PF_KEY messages to consumers who process and act upon
 * them.
 */
#define	KEYSOCK_IN		(IPSEC_M_CTL + 3)
#define	KEYSOCK_OUT		(IPSEC_M_CTL + 4)
#define	KEYSOCK_OUT_ERR		(IPSEC_M_CTL + 5)
#define	KEYSOCK_HELLO		(IPSEC_M_CTL + 6)
#define	KEYSOCK_HELLO_ACK	(IPSEC_M_CTL + 7)

/*
 * KEYSOCK_HELLO is sent by keysock to a consumer when it is pushed on top
 * of one (i.e. opened as a module).
 *
 * NOTE: Keysock_hello is simply an ipsec_info_t
 */

/*
 * KEYSOCK_HELLO_ACK is sent by a consumer to acknowledge a KEYSOCK_HELLO.
 * It contains the PF_KEYv2 sa_type, so keysock can redirect PF_KEY messages
 * to the right consumer.
 */
typedef struct keysock_hello_ack_s {
	uint32_t ks_hello_type;
	uint32_t ks_hello_len;
	uint8_t ks_hello_satype;	/* PF_KEYv2 sa_type of ks client */
} keysock_hello_ack_t;

#define	KS_IN_ADDR_UNKNOWN 0
#define	KS_IN_ADDR_NOTTHERE 1
#define	KS_IN_ADDR_UNSPEC 2
#define	KS_IN_ADDR_ME 3
#define	KS_IN_ADDR_NOTME 4
#define	KS_IN_ADDR_MBCAST 5
#define	KS_IN_ADDR_DONTCARE 6

/*
 * KEYSOCK_IN is a PF_KEY message from a PF_KEY socket destined for a consumer.
 */
typedef struct keysock_in_s {
	uint32_t ks_in_type;
	uint32_t ks_in_len;
	/*
	 * NOTE:	These pointers MUST be into the M_DATA that follows
	 *		this M_CTL message.  If they aren't, weirdness
	 *		results.
	 */
	struct sadb_ext *ks_in_extv[SADB_EXT_MAX + 1];
	int ks_in_srctype;	/* Source address type. */
	int ks_in_dsttype;	/* Dest address type. */
	minor_t ks_in_serial;	/* Serial # of sending socket. */
} keysock_in_t;

/*
 * KEYSOCK_OUT is a PF_KEY message from a consumer destined for a PF_KEY
 * socket.
 */
typedef struct keysock_out_s {
	uint32_t ks_out_type;
	uint32_t ks_out_len;
	minor_t ks_out_serial;	/* Serial # of sending socket. */
} keysock_out_t;

/*
 * KEYSOCK_OUT_ERR is sent to a consumer from keysock if for some reason
 * keysock could not find a PF_KEY socket to deliver a consumer-originated
 * message (e.g. SADB_ACQUIRE).
 */
typedef struct keysock_out_err_s {
	uint32_t ks_err_type;
	uint32_t ks_err_len;
	minor_t ks_err_serial;
	int ks_err_errno;
	/*
	 * Other, richer error information may end up going here eventually.
	 */
} keysock_out_err_t;

/*
 * All IPsec informational messages are placed into the ipsec_info_t
 * union, so that allocation can be done once, and IPsec informational
 * messages can be recycled.
 */
typedef union ipsec_info_u {
	struct {
		uint32_t ipsec_allu_type;
		uint32_t ipsec_allu_len;	/* In bytes */
	} ipsec_allu;
	keysock_hello_ack_t keysock_hello_ack;
	keysock_in_t keysock_in;
	keysock_out_t keysock_out;
	keysock_out_err_t keysock_out_err;
} ipsec_info_t;
#define	ipsec_info_type ipsec_allu.ipsec_allu_type
#define	ipsec_info_len ipsec_allu.ipsec_allu_len

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_IPSEC_INFO_H */
