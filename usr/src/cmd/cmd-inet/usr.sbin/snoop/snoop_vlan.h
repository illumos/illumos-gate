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

#ifndef _SNOOP_VLAN_H
#define	_SNOOP_VLAN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/ethernet.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The offset in bytes, in a VLAN tagged packet, from the
 * ethernet header ethertype (which is ETHERTYPE_VLAN) to
 * the encapsulated ethertype.
 */
#define	ENCAP_ETHERTYPE_OFF (offsetof(struct ether_vlan_header, ether_type) -\
	    offsetof(struct ether_vlan_header, ether_tpid))

/*
 * The offset in bytes, from the beginning of an ethernet header,
 * to the VLAN ID.
 */
#define	VLAN_ID_OFFSET (offsetof(struct ether_vlan_header, ether_tci) -\
	    offsetof(struct ether_vlan_header, ether_dhost))

#ifdef __cplusplus
}
#endif

#endif /* _SNOOP_VLAN_H */
