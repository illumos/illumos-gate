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

#ifndef	_VSW_FDB_H
#define	_VSW_FDB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Convert ethernet (mac) address to hash table key.
 */
#define	KEY_HASH(key, addr) \
	(key = ((((uint64_t)(addr)->ether_addr_octet[0]) << 40) | \
	(((uint64_t)(addr)->ether_addr_octet[1]) << 32) | \
	(((uint64_t)(addr)->ether_addr_octet[2]) << 24) | \
	(((uint64_t)(addr)->ether_addr_octet[3]) << 16) | \
	(((uint64_t)(addr)->ether_addr_octet[4]) << 8) | \
	((uint64_t)(addr)->ether_addr_octet[5])));

#define	VLAN_ID_KEY(key)	((mod_hash_key_t)(uintptr_t)(key))

/*
 * Multicast forwarding database (mFDB) is a hashtable
 * keyed off the mac address, with the value being a linked
 * list of mfdb_ent_t structures, each of which is a destination
 * (either a vsw_port or the vsw instance itself when plumbed as
 * a network device) to which the multicast pkt should be forwarded.
 */
typedef struct mfdb_ent {
	struct mfdb_ent		*nextp;		/* next entry in list */
	void			*d_addr;	/* address of dest */
	uint8_t			d_type;		/* destination type */
} mfdb_ent_t;

/*
 * Forwarding database entry. Each member port of a vsw will have an entry in
 * the vsw's fdb. Ref count is bumped up while sending a packet destined to a
 * port corresponding to the fdb entry.
 */
typedef struct vsw_fdbe {
	void		*portp;	/* pointer to the vnet_port */
	uint32_t	refcnt;	/* reference count */
} vsw_fdbe_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _VSW_FDB_H */
