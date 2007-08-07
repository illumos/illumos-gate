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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * file: pool.c
 *
 * This file contains all of the routines that manage
 * the Home Agent's Home Address pools. This is used
 * when a Mobile Node requests a Home Address by including
 * a Home Address of zero (0) in the Registration
 * request.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <syslog.h>
#include <stdlib.h>

#include "mip.h"
#include "agent.h"
#include "pool.h"

/*
 * This table has one entry for each pool defined in the config file
 */
extern HashTable mipPoolHash;

extern int  logVerbosity;
extern char *ntoa(uint32_t, char *);

/*
 * Function: CreateAddressPool
 *
 * Arguments:	poolIdentifier - Numerical Pool Identifier
 *		baseAddress - The base IP address of the pool
 *		length - The number of addresses in the pool
 *
 * Description: This function will create a Pool structure
 *		and add it to the Hash Table. Pools are used
 *		to allocate Home Agent addresses to Mobile
 *		Nodes that request one by inserting a zero (0)
 *		Home Address in the Registration Request.
 *
 *		The Pool entry will be locked upon return.
 *		The caller is responsible for unlocking the
 *		node when it is finished with it.
 *
 * Returns:	if successful a pointer to a Pool structure
 *		is returned, otherwise NULL
 */
Pool *
CreateAddressPool(uint32_t poolIdentifier, ipaddr_t baseAddress,
    uint32_t length)
{
	Pool *pool;
	int poolSize;
	int i;

	/*
	 * First, let's see if we already have this pool.
	 */
	if (findHashTableEntryUint(&mipPoolHash, poolIdentifier,
		LOCK_NONE, NULL, 0, 0, 0) != NULL) {
		syslog(LOG_ERR, "Pool %d already defined\n", poolIdentifier);
		return (NULL);
	}

	/*
	 * First we allocate the memory
	 */
	poolSize = sizeof (Pool) + (sizeof (PoolEntry) * length);
	pool = (Pool *)calloc(1, poolSize);

	if (pool == NULL) {
		syslog(LOG_CRIT, "FATAL: Unable to allocate address pool");
		return (NULL);
	}

	/*
	 * Initialize the pool's parameters.
	 */
	if (rwlock_init(&pool->poolNodeLock, USYNC_THREAD, NULL)) {
		syslog(LOG_ERR, "Unable to initialize read/write lock");
		free(pool);
		return (NULL);
	}

	pool->poolIdentifier = poolIdentifier;
	pool->poolBaseAddress = baseAddress;
	pool->poolLength = length;

	/*
	 * Setup each Pool Entry within the Pool structure (one
	 * per address).
	 */
	for (i = 0; i < length; i++) {
		/* Setup the entry's address. */
		pool->poolEntry[i].poolStatus = POOL_FREE;
		pool->poolEntry[i].poolHomeAddress = baseAddress + htonl(i);
	}

	/*
	 * Add it to the Hash Table.
	 */
	if (linkHashTableEntryUint(&mipPoolHash, poolIdentifier, pool,
		LOCK_WRITE)) {
		syslog(LOG_ERR, "FATAL: Unable to add pool to hash table");
		free(pool);
		return (NULL);
	}

	return (pool);
}

/*
 * Function: GetAddressFromPool
 *
 * Arguments:	poolIdentifier - Pool Identifier
 *
 * Description: This function will step through the Pool
 *		entry identified via the Pool Identifier
 *		and will return the first available
 *		Home Address.
 *
 * Returns:	int, Home Address if successful, otherwise
 *		zero (0).
 */
uint32_t
GetAddressFromPool(uint32_t poolIdentifier)
{

	Pool *pool;
	int i;
	ipaddr_t homeAddress = 0;
	char buffer[INET_ADDRSTRLEN];

	/*
	 * Let's get the pool entry, using the pool identifier.
	 */
	if ((pool = findHashTableEntryUint(&mipPoolHash,
	    poolIdentifier, LOCK_WRITE, NULL, 0, 0, 0)) == NULL) {
		mipverbose(("Pool %d not found\n", poolIdentifier));
		return (0);
	}

	for (i = 0; i < pool->poolLength; i++) {
		if (pool->poolEntry[i].poolStatus == POOL_FREE) {
			/*
			 * This one is free, let's allocate it.
			 */
			pool->poolEntry[i].poolStatus = POOL_TAKEN;
			mipverbose(("allocated %s from pool %d\n",
			    ntoa(pool->poolEntry[i].poolHomeAddress, buffer),
			    poolIdentifier));
			homeAddress = pool->poolEntry[i].poolHomeAddress;
			break;
		}
	}

	/*
	 * And now we unlock the node...
	 */
	(void) rw_unlock(&pool->poolNodeLock);

	return (homeAddress);
}

/*
 * Function: freeAddressFromPool
 *
 * Arguments:	poolIdentifier - Pool Identifier
 *		homeAddr - Home Address
 *
 * Description: This function will put a Home Address
 *		back into the address pool by marking
 *		the entry as being free.
 *
 * Returns: boolean, _B_TRUE if the Home Address was freed.
 */
boolean_t
freeAddressFromPool(uint32_t poolIdentifier, ipaddr_t homeAddr)
{
	Pool *pool;
	int i;
	boolean_t found = _B_FALSE;
	char buffer[INET_ADDRSTRLEN];

	/*
	 * First, let's see if we already have this pool.
	 */
	if ((pool = findHashTableEntryUint(&mipPoolHash,
	    poolIdentifier, LOCK_WRITE, NULL, 0, 0, 0)) == NULL) {
		mipverbose(("Pool %d not found\n", poolIdentifier));
		return (found);
	}

	for (i = 0; i < pool->poolLength; i++) {
		if (pool->poolEntry[i].poolStatus == POOL_TAKEN &&
			pool->poolEntry[i].poolHomeAddress == homeAddr) {
			mipverbose(("Freed %s from pool %d\n",
			    ntoa(homeAddr, buffer), poolIdentifier));
			pool->poolEntry[i].poolStatus = POOL_FREE;
			found = _B_TRUE;
			break;
		}
	}

	/*
	 * And now we unlock the node...
	 */
	(void) rw_unlock(&pool->poolNodeLock);

	return (found);
}
