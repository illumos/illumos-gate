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
 * file: mipagentsnmp_haCounterEntry.c
 *
 * This file contains the SNMP routines used to retrieve
 * the Home Agent's Mobile Node Counter Information.
 */

#include <sys/types.h>
#include <netinet/in.h>
#include <stdlib.h>

#include <impl.h>
#include <snmp.h>

#include "snmp_stub.h"
#include "agent.h"

extern HashTable haMobileNodeHash;


/*
 * Function: get_haCounterEntry
 *
 * Arguments:	search_type - The type of search (first, next, exact)
 *		haCounterEntry_data - Pointer to a pointer which
 *			will contain the Mobile Node counter entry
 *			upon successful completion.
 *		index - Pointer to the current index
 *
 * Description: This function will allocate the memory required for
 *		the Mobile Node counter entry, and will find the
 *		appropriate Mobile Node counter based on the index
 *		provided. If the search type is set to FIRST_ENTRY,
 *		we will return the first Mobile Node counter in the
 *		Hash Table, otherwise the index is used.
 *
 *		The Mobile Node counter entry is then setup with the
 *		values found in the entry from the hash table and
 *		returned to the caller.
 *
 *		Note, the caller is responsible for either freeing the
 *		memory, or calling free_haCounterEntry()
 *
 * Returns: int, 0 if successful
 */
extern int
get_haCounterEntry(int search_type,
    HaCounterEntry_t **haCounterEntry_data, IndexType *index)
{

	Integer *integer;
	HaMobileNodeEntry *haMobileNodeEntry = NULL;
	HashEntry *hashEntry;
	int i;
	int j;
	int return_code = SNMP_ERR_NOERROR;
	boolean_t found = _B_FALSE;

	*haCounterEntry_data =
	    (HaCounterEntry_t *)calloc(1, sizeof (HaCounterEntry_t));

	if (haCounterEntry_data == NULL) {
		return (SNMP_ERR_GENERR);
	}

	/*
	 * In the case, the search_type is FIRST_ENTRY or NEXT_ENTRY
	 * this function should modify the index argument to the
	 * appropriate value
	 */
	switch (search_type) {
	case FIRST_ENTRY:
		/*
		 * We are looking for the first entry in the list.
		 */
		index->value[0] = 1;
		index->len = 1;
		break;
	case NEXT_ENTRY:
		/*
		 * Increment the index value.
		 */
		index->value[0]++;
		break;
	case EXACT_ENTRY:
		/*
		 * We don't need to play around with the
		 * index for this search type.
		 */
		break;
	default:
		return_code = SNMP_ERR_GENERR;
		goto the_end;
	}

	/*
	 * Now search for the entry...
	 */
	for (i = 0, j = 1; i < HASH_TBL_SIZE && found == _B_FALSE; i++) {
		if (haMobileNodeHash.buckets[i]) {
			/*
			 * Lock the bucket
			 */
			(void) rw_rdlock(&haMobileNodeHash.bucketLock[i]);

			hashEntry = haMobileNodeHash.buckets[i];
			while (hashEntry != NULL) {
				if (j == index->value[0]) {
					haMobileNodeEntry = hashEntry->data;
					found = _B_TRUE;

					/*
					 * Lock the node
					 */
					(void) rw_rdlock(&haMobileNodeEntry->
					    haMnNodeLock);

					break;
				}
				hashEntry = hashEntry->next;
				j++;
			}

			/*
			 * Unlock the bucket
			 */
			(void) rw_unlock(&haMobileNodeHash.bucketLock[i]);
		}
	}

	if (haMobileNodeEntry == NULL) {
		return_code =  END_OF_TABLE;
		goto the_end;
	}

	/*
	 * And now we return the number of times service was accepted for the
	 * Mobile Node.
	 */
	integer = &((*haCounterEntry_data)->haServiceRequestsAccepted);
	*integer = (int)haMobileNodeEntry->haServiceRequestsAcceptedCnt;

	/*
	 * And now we return the number of times service was denied for the
	 * Mobile Node.
	 */
	integer = &((*haCounterEntry_data)->haServiceRequestsDenied);
	*integer = (int)haMobileNodeEntry->haServiceRequestsDeniedCnt;

	/*
	 * And now we return the total amount of time (in seconds) that
	 * service was provided to the Mobile Node.
	 */
	integer = &((*haCounterEntry_data)->haOverallServiceTime);
	*integer = (int)haMobileNodeEntry->haOverallServiceTime;

	/*
	 * And now we return the last time service was accepted.
	 */
	integer = &((*haCounterEntry_data)->haRecentServiceAcceptedTime);
	*integer = (int)haMobileNodeEntry->haRecentServiceAcceptedTime;

	/*
	 * And now we return the last time service was denied.
	 */
	integer = &((*haCounterEntry_data)->haRecentServiceDeniedTime);
	*integer = (int)haMobileNodeEntry->haRecentServiceDeniedTime;

	/*
	 * And now we return the reason for the last denial of service.
	 */
	integer = &((*haCounterEntry_data)->haRecentServiceDeniedCode);
	*integer = (int)haMobileNodeEntry->haRecentServiceDeniedCode;

the_end:
	if (haMobileNodeEntry != NULL) {
		/*
		 * Unlock the node
		 */
		(void) rw_unlock(&haMobileNodeEntry->haMnNodeLock);
	}

	if (return_code != SNMP_ERR_NOERROR) {
		free_haCounterEntry(*haCounterEntry_data);
		*haCounterEntry_data = NULL;
	}

	return (return_code);
}


/*
 * Function: free_haCounterEntry
 *
 * Arguments:	haCounterEntry - Pointer to a previously
 *			allocated SNMP Mobile Node counter
 *			entry
 *
 * Description: This function is called to free a previously
 *		allocated SNMP Mobile Node counter entry.
 *
 * Returns:
 */
void
free_haCounterEntry(HaCounterEntry_t *haCounterEntry)
{
	if (haCounterEntry) {
		free(haCounterEntry);
		haCounterEntry = NULL;
	}
}
