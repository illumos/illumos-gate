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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _IPP_IPGPC_TRIE_H
#define	_IPP_IPGPC_TRIE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <ipp/ipgpc/classifier-objects.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Header file for trie data structure used to hold keys of non-exact match
 * selectors
 */

#ifdef	_LITTLE_ENDIAN
/*
 * given the length of a key, and the desired bit position, compute the
 * correct bit position assuming and NBO key on a _LITTLE_ENDIAN machine
 */
#define	COMPUTE_BIT_POS(len, pos) \
	(((len - pos - 1) & 0xf8) | (pos & 0x7))
#endif /* _LITTLE_ENDIAN */

/*
 * extracts a single bit at position pos from a given value, val, for an
 * unsigned integer of length len.  len will be equal to either 16 or 32
 */
#define	EXTRACTBIT_CMN(val, pos)	((val >> pos) & 1)
#ifdef	_BIG_ENDIAN
#define	EXTRACTBIT(val, pos, len)	(EXTRACTBIT_CMN(val, pos))
#else  /* _LITTLE_ENDIAN */
#define	EXTRACTBIT(val, pos, len) \
	(EXTRACTBIT_CMN(val, (COMPUTE_BIT_POS(len, pos))))
#endif /* _BIG_ENDIAN */

/* sets the bit at position pos of num to 1 if val == 1 */
#define	SETBIT_CMN(num, pos, val)	(num |= (val << pos))
#ifdef	_BIG_ENDIAN
#define	SETBIT(num, pos, val, len)	(SETBIT_CMN(num, pos, val))
#else  /* _LITTLE_ENDIAN */
#define	SETBIT(num, pos, val, len) \
	(SETBIT_CMN(num, (COMPUTE_BIT_POS(len, pos)), val))
#endif /* _BIG_ENDIAN */

/* sets the bit at position pos of num to 0 */
#define	UNSETBIT_CMN(num, pos)	(num &= (~(1 << pos)))
#ifdef	_BIG_ENDIAN
#define	UNSETBIT(num, pos, len)	(UNSETBIT_CMN(num, pos))
#else  /* _LITTLE_ENDIAN */
#define	UNSETBIT(num, pos, len) \
	(UNSETBIT_CMN(num, (COMPUTE_BIT_POS(len, pos))))
#endif /* _BIG_ENDIAN */

extern node_t *create_node(int);
extern int t_insert(trie_id_t *, key_t, uint32_t, uint32_t);
extern int t_insert6(trie_id_t *, key_t, in6_addr_t, in6_addr_t);
extern void t_remove(trie_id_t *, key_t, uint32_t, uint32_t);
extern void t_remove6(trie_id_t *, key_t, in6_addr_t, in6_addr_t);
extern int t_retrieve(trie_id_t *, uint32_t, ht_match_t *);
extern int t_retrieve6(trie_id_t *, in6_addr_t, ht_match_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _IPP_IPGPC_TRIE_H */
