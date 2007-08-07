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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _POOL_H
#define	_POOL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * pool.h : Data structures and prototypes used by a Mobile IP agent
 *          to support Address Pools.
 */


#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
	enum {
		    POOL_FREE = 0,
		    POOL_TAKEN
	} poolStatus;
	ipaddr_t    poolHomeAddress;
	char	    poolMnNAI[MAX_NAI_LENGTH];
} PoolEntry;

typedef struct {
	rwlock_t  poolNodeLock;
	uint32_t  poolIdentifier;
	ipaddr_t  poolBaseAddress;
	uint32_t  poolLength;
	PoolEntry poolEntry[1];
} Pool;


Pool *CreateAddressPool(uint32_t, ipaddr_t, uint32_t);

uint32_t GetAddressFromPool(uint32_t);

boolean_t freeAddressFromPool(uint32_t, ipaddr_t);


#ifdef __cplusplus
}
#endif

#endif /* _POOL_H */
