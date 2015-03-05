/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 Joyent, Inc.
 */

#ifndef _INET_INET_HASH_H
#define	_INET_INET_HASH_H

/*
 * Common packet hashing routines shared across MAC, UDP, and others.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	INET_PKT_HASH_L2	0x01
#define	INET_PKT_HASH_L3	0x02
#define	INET_PKT_HASH_L4	0x04

extern uint64_t inet_pkt_hash(uint_t, mblk_t *, uint8_t);

#ifdef __cplusplus
}
#endif

#endif /* _INET_INET_HASH_H */
