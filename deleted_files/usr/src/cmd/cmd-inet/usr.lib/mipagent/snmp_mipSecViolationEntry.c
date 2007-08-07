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
 * Copyright 1999-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * file: mipagentsnmp_mipSecViolationEntry.c
 *
 * This file contains the SNMP routines used to retrieve
 * the Mobility Agent's Security Violation Information.
 */

#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>

#include <impl.h>
#include <snmp.h>

#include "snmp_stub.h"
#include "agent.h"

extern char *ntoa(uint32_t, char *);

/*
 * This table stores all of the Security Violations
 */
HashTable mipSecViolationHash;

/*
 * Function: get_mipSecViolationEntry
 *
 * Arguments:	search_type - The type of search (first, next, exact)
 *		mipSecViolationEntry_data - Pointer to a pointer which
 *			will contain the Security Violation entry
 *			upon successful completion.
 *		index - Pointer to the current index
 *
 * Description: This function will allocate the memory required for
 *		the Security Violation entry, and will find the
 *		appropriate Security Violation based on the index
 *		provided. If the search type is set to FIRST_ENTRY,
 *		we will return the first Security Assocication in the
 *		Hash Table, otherwise the index is used.
 *
 *		The Security Violation entry is then setup with the
 *		values found in the entry from the hash table and
 *		returned to the caller.
 *
 *		Note, the caller is responsible for either freeing the
 *		memory, or calling free_mipSecViolationEntry()
 *
 * Returns: int, 0 if successful
 */
extern int
get_mipSecViolationEntry(int search_type,
    MipSecViolationEntry_t **mipSecViolationEntry_data, IndexType *index)
{
	Integer *integer;
	String  *string;
	MipSecViolationEntry *mipSecViolationEntry = NULL;
	HashEntry *hashEntry;
	int i;
	int j;
	int return_code = SNMP_ERR_NOERROR;
	char buffer[258];
	boolean_t found = _B_FALSE;

	/*
	 * Allocate some memory to handle the request.
	 */
	*mipSecViolationEntry_data = (MipSecViolationEntry_t *)calloc(1,
	    sizeof (MipSecViolationEntry_t));

	if (mipSecViolationEntry_data == NULL) {
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
	 * Now search for the entry... the problem here is that
	 * the Security Association Information spans three different
	 * tables, so we need to look through each one.
	 */
	for (i = 0, j = 1; i < HASH_TBL_SIZE && found == _B_FALSE; i++) {
		if (mipSecViolationHash.buckets[i]) {
			/*
			 * Lock the bucket
			 */
			(void) rw_rdlock(&mipSecViolationHash.bucketLock[i]);

			hashEntry = mipSecViolationHash.buckets[i];
			while (hashEntry != NULL) {
				if (j == index->value[0]) {
					mipSecViolationEntry = hashEntry->data;
					found = _B_TRUE;

					/*
					 * Lock the node
					 */
					(void) rw_rdlock(
					    &mipSecViolationEntry->
						mipSecNodeLock);

					break;
				}
				hashEntry = hashEntry->next;
				j++;
			}

			/*
			 * Unlock the bucket
			 */
			(void) rw_unlock(&mipSecViolationHash.bucketLock[i]);
		}
	}

	if (mipSecViolationEntry == NULL) {
		return_code = END_OF_TABLE;
		goto the_end;
	}

	/*
	 * Return the address of the offender.
	 */
	(void) ntoa(mipSecViolationEntry->mipSecViolatorAddr, buffer);

	string = &((*mipSecViolationEntry_data)->mipSecViolatorAddress);

	string->chars = (unsigned char *)malloc(strlen(buffer) + 1);
	if (string->chars == NULL) {
		return_code = SNMP_ERR_GENERR;
		goto the_end;
	}
	(void) strcpy((char *)string->chars, buffer);
	string->len = strlen(buffer);

	/*
	 * And now we return the number of security violations
	 * for this entry.
	 */
	integer = &((*mipSecViolationEntry_data)->mipSecViolationCounter);
	*integer = (int)mipSecViolationEntry->mipSecViolationCounter;

	/*
	 * And now we return the SPI used.
	 */
	integer = &((*mipSecViolationEntry_data)->mipSecRecentViolationSPI);
	*integer = (int)mipSecViolationEntry->mipSecRecentViolationSPI;

	/*
	 * And now we return time of the last violation.
	 */
	integer =
	    &((*mipSecViolationEntry_data)->mipSecRecentViolationTime);
	*integer = (int)mipSecViolationEntry->mipSecRecentViolationTime;

	/*
	 * And now we return the low order bits of the Identifier used.
	 */
	integer =
	    &((*mipSecViolationEntry_data)->mipSecRecentViolationIDLow);
	*integer = (int)mipSecViolationEntry->mipSecRecentViolationIDLow;

	/*
	 * And now we return the high order bits of the Identifier used.
	 */
	integer =
	    &((*mipSecViolationEntry_data)->mipSecRecentViolationIDHigh);
	*integer = (int)mipSecViolationEntry->mipSecRecentViolationIDHigh;

	/*
	 * And finally, the reason for the violation.
	 */
	integer =
	    &((*mipSecViolationEntry_data)->mipSecRecentViolationReason);
	*integer = (int)mipSecViolationEntry->mipSecRecentViolationReason;

the_end:
	if (mipSecViolationEntry != NULL) {
		/*
		 * Unlock the node
		 */
		(void) rw_unlock(&mipSecViolationEntry->mipSecNodeLock);
	}

	if (return_code != SNMP_ERR_NOERROR) {
		free_mipSecViolationEntry(*mipSecViolationEntry_data);
		*mipSecViolationEntry_data = NULL;
	}

	return (return_code);
}


/*
 * Function: free_mipSecViolationEntry
 *
 * Arguments:	mipSecViolationEntry - Pointer to a previously
 *			allocated SNMP Security Violation
 *			entry
 *
 * Description: This function is called to free a previously
 *		allocated SNMP Security Violation entry.
 *
 * Returns:
 */
void
free_mipSecViolationEntry(MipSecViolationEntry_t *mipSecViolationEntry)
{
	String  *string;

	if (mipSecViolationEntry) {
		string =
		    &(mipSecViolationEntry->mipSecViolatorAddress);
		if (string->chars != NULL && string->len != 0) {
			free(string->chars);
			string->len = 0;
		}

		free(mipSecViolationEntry);
		mipSecViolationEntry = NULL;
	}
}
