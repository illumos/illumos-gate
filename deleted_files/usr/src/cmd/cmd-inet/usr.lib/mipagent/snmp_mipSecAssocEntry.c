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
 * file: mipagentsnmp_mipSecAssocEntry.c
 *
 * This file contains the SNMP routines used to retrieve
 * the Mobility Agent's Security Association Information.
 */

#include <sys/types.h>
#include <netinet/in.h>
#include <stdlib.h>

#include <impl.h>
#include <snmp.h>

#include "snmp_stub.h"
#include "agent.h"

/*
 * This table has one entry for each mobile node for which a mobility
 * agent offers Home Agent services.
 */
extern HashTable mipSecAssocHash;

/*
 * Function: get_mipSecAssocEntry
 *
 * Arguments:	search_type - The type of search (first, next, exact)
 *		mipSecAssocEntry_data - Pointer to a pointer which
 *			will contain the Security Association entry
 *			upon successful completion.
 *		index - Pointer to the current index
 *
 * Description: This function will allocate the memory required for
 *		the Security Association entry, and will find the
 *		appropriate Security Association based on the index
 *		provided. If the search type is set to FIRST_ENTRY,
 *		we will return the first Security Association in the
 *		Hash Table, otherwise the index is used.
 *
 *		The Security Association entry is then setup with the
 *		values found in the entry from the hash table and
 *		returned to the caller.
 *
 *		Note, the caller is responsible for either freeing the
 *		memory, or calling free_mipSecAssocEntry()
 *
 * Returns: int, 0 if successful
 */
extern int
get_mipSecAssocEntry(int search_type,
    MipSecAssocEntry_t **mipSecAssocEntry_data, IndexType *index)
{
	Integer *integer;
	String  *string;
	MipSecAssocEntry *mipSecAssocEntry = NULL;
	HashEntry *hashEntry;
	int i;
	int j;
	boolean_t found = _B_FALSE;

	/*
	 * Allocate some memory to handle the request.
	 */
	*mipSecAssocEntry_data =
	    (MipSecAssocEntry_t *)calloc(1, sizeof (MipSecAssocEntry_t));

	if (mipSecAssocEntry_data == NULL) {
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
		free_mipSecAssocEntry(*mipSecAssocEntry_data);
		return (SNMP_ERR_GENERR);
	}

	/*
	 * Now search for the entry... the problem here is that
	 * the Security Association Information spans three different
	 * tables, so we need to look through each one.
	 */
	for (i = 0, j = 1; i < HASH_TBL_SIZE && found == _B_FALSE; i++) {
		if (mipSecAssocHash.buckets[i]) {
			/*
			 * Lock the bucket
			 */
			(void) rw_rdlock(&mipSecAssocHash.bucketLock[i]);

			hashEntry = mipSecAssocHash.buckets[i];
			while (hashEntry != NULL) {
				if (j == index->value[0]) {
					mipSecAssocEntry = hashEntry->data;
					found = _B_TRUE;

					/*
					 * Lock the node
					 */
					(void) rw_rdlock(&mipSecAssocEntry->
					    mipSecNodeLock);

					break;
				}
				hashEntry = hashEntry->next;
				j++;
			}

			/*
			 * Unlock the bucket
			 */
			(void) rw_unlock(&mipSecAssocHash.bucketLock[i]);
		}
	}

	if (mipSecAssocEntry == NULL) {
		free_mipSecAssocEntry(*mipSecAssocEntry_data);
		*mipSecAssocEntry_data = NULL;
		return (END_OF_TABLE);
	}

	/*
	 * And now we return the Algorithm type.
	 */
	integer = &((*mipSecAssocEntry_data)->mipSecAlgorithmType);
	*integer = (int)mipSecAssocEntry->mipSecAlgorithmType;

	/*
	 * And now we return the Algorithm mode.
	 */
	integer = &((*mipSecAssocEntry_data)->mipSecAlgorithmMode);
	*integer = (int)mipSecAssocEntry->mipSecAlgorithmMode;

	/*
	 * And now we return the Key. Note that RFC2006 clearly states
	 * that this will always return 0 (then why does it exist in
	 * the MIB?!?).
	 */
	string = &((*mipSecAssocEntry_data)->mipSecKey);
	string->len = 0;

	/*
	 * And now we return the Replay Method.
	 */
	integer = &((*mipSecAssocEntry_data)->mipSecReplayMethod);
	*integer = (int)mipSecAssocEntry->mipSecReplayMethod;

	/*
	 * Unlock the node
	 */
	(void) rw_unlock(&mipSecAssocEntry->mipSecNodeLock);

	return (SNMP_ERR_NOERROR);
}


/*
 * Function: free_mipSecAssocEntry
 *
 * Arguments:	mipSecAssocEntry - Pointer to a previously
 *			allocated SNMP Security Association
 *			entry
 *
 * Description: This function is called to free a previously
 *		allocated SNMP Security Association entry.
 *
 * Returns:
 */
void
free_mipSecAssocEntry(MipSecAssocEntry_t *mipSecAssocEntry)
{
	if (mipSecAssocEntry) {
		free(mipSecAssocEntry);
		mipSecAssocEntry = NULL;
	}
}
