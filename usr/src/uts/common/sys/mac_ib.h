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

#ifndef	_SYS_MAC_ETHER_H
#define	_SYS_MAC_ETHER_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Ethernet MAC Plugin
 */

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

#define	MAC_PLUGIN_IDENT_IB	"mac_ib"

#define	MAC_IB_MAX_802_SAP	255
#define	MAC_IB_ETHERTYPE_MAX	65535
#define	MAC_IB_GID_SIZE		10
#define	MAC_IB_BROADCAST_GID	0xFFFFFFFF

/*
 * In order to transmit the datagram to correct destination, an extra
 * header including destination address is required. IB does not provide an
 * interface for sending a link layer header directly to the IB link and the
 * link layer header received from the IB link is missing information that
 * GLDv3 requires. So mac_ib plugin defines a "soft" header as below.
 */
typedef struct ib_addrs {
	ipoib_mac_t	ipib_src;
	ipoib_mac_t	ipib_dst;
} ib_addrs_t;

typedef struct ib_header_info {
	union {
		ipoib_pgrh_t	ipib_grh;
		ib_addrs_t	ipib_addrs;
	} ipib_prefix;
	ipoib_hdr_t	ipib_rhdr;
} ib_header_info_t;

#define	ib_dst	ipib_prefix.ipib_addrs.ipib_dst
#define	ib_src	ipib_prefix.ipib_addrs.ipib_src
#define	ib_grh	ipib_prefix.ipib_grh

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_MAC_ETHER_H */
