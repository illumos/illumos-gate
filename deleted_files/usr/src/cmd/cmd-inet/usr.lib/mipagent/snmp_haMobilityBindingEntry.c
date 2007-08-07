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
 * file: mipagentsnmp_haMobilityBindingEntry.c
 *
 * This file contains the SNMP routines used to retrieve
 * the Home Agent's Mobile Node Binding Information.
 */

#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>

#include <impl.h>
#include <snmp.h>

#include "snmp_stub.h"
#include "agent.h"

extern HashTable haMobileNodeHash;
extern char *ntoa(uint32_t, char *);

/*
 * Function: get_haMobilityBindingEntry
 *
 * Arguments:	search_type - The type of search (first, next, exact)
 *		haMobilityBindingEntry_data - Pointer to a pointer
 *			which will contain the binding entry upon
 *			successful completion.
 *		index - Pointer to the current index
 *
 * Description: This function will allocate the memory required for
 *		the binding entry, and will find the appropriate
 *		binding entry based on the index provided. If the
 *		search type is set to FIRST_ENTRY, we will return
 *		the first binding entry in the Hash Table, otherwise
 *		the index is used.
 *
 *		The binding entry is then setup with the values found
 *		in the entry from the hash table and returned to the
 *		caller.
 *
 *		Note, the caller is responsible for either freeing the
 *		memory, or calling free_haMobilityBindingEntry()
 *
 * Returns: int, 0 if successful
 */
extern int
get_haMobilityBindingEntry(int search_type,
    HaMobilityBindingEntry_t **haMobilityBindingEntry_data,
    IndexType *index)
{
	Integer *integer;
	String  *string;
	HaMobileNodeEntry *haMobileNodeEntry = NULL;
	HaBindingEntry *haBindingEntry = NULL;
	HashEntry *hashEntry;
	int i;
	int j;
	int return_code = SNMP_ERR_NOERROR;
	time_t currentTime;
	char buffer[258];
	boolean_t found = _B_FALSE;

	*haMobilityBindingEntry_data =
	    (HaMobilityBindingEntry_t *)calloc(1,
	    sizeof (HaMobilityBindingEntry_t));

	if (haMobilityBindingEntry_data == NULL) {
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
		return_code = END_OF_TABLE;
		goto the_end;
	}

	haBindingEntry = haMobileNodeEntry->bindingEntries;

	if (haBindingEntry != NULL) {
		/*
		 * Get the Mobile Node's IP Address.
		 */
		(void) ntoa(haBindingEntry->haBindingMN, buffer);

		string =
		    &((*haMobilityBindingEntry_data)->haMobilityBindingMN);
		string->chars = (unsigned char *)malloc(strlen(buffer) + 1);
		if (string->chars == NULL) {
			return_code = SNMP_ERR_GENERR;
			goto the_end;
		}
		(void) strcpy((char *)string->chars, buffer);
		string->len = strlen(buffer);

		/*
		 * Get the Care of Address.
		 */
		(void) ntoa(haBindingEntry->haBindingCOA, buffer);
		string =
		    &((*haMobilityBindingEntry_data)->haMobilityBindingCOA);

		string->chars = (unsigned char *)malloc(strlen(buffer) + 1);
		if (string->chars == NULL) {
			return_code = SNMP_ERR_GENERR;
			goto the_end;
		}
		(void) strcpy((char *)string->chars, buffer);
		string->len = strlen(buffer);

		/*
		 * Get the Binding Source Address.
		 */
		(void) ntoa(haBindingEntry->haBindingSrcAddr, buffer);

		string =
		    &((*haMobilityBindingEntry_data)->
		    haMobilityBindingSourceAddress);

		string->chars = (unsigned char *)malloc(strlen(buffer) + 1);
		if (string->chars == NULL) {
			return_code = SNMP_ERR_GENERR;
			goto the_end;
		}
		(void) strcpy((char *)string->chars, buffer);
		string->len = strlen(buffer);

		/*
		 * And now we return the Registration Flags.
		 */
		integer =
		    &((*haMobilityBindingEntry_data)->
		    haMobilityBindingRegFlags);
		*integer = (int)haBindingEntry->haBindingRegFlags;

		/*
		 * And now we return the Low order Registration ID.
		 */
		integer = &((*haMobilityBindingEntry_data)->
		    haMobilityBindingRegIDLow);
		*integer = (int)haMobileNodeEntry->haMnRegIDLow;

		/*
		 * And now we return the High order Registration ID.
		 */
		integer =
		    &((*haMobilityBindingEntry_data)->
		    haMobilityBindingRegIDHigh);
		*integer = (int)haMobileNodeEntry->haMnRegIDHigh;

		/*
		 * And now we return the Registration Time Granted.
		 */
		integer =
		    &((*haMobilityBindingEntry_data)->
		    haMobilityBindingTimeGranted);
		*integer = (int)haBindingEntry->haBindingTimeGranted;

		/*
		 * And now we return the Registration Time Remaining.
		 */
		integer =
		    &((*haMobilityBindingEntry_data)->
		    haMobilityBindingTimeRemaining);
		GET_TIME(currentTime);
		*integer = currentTime -
			(int)haBindingEntry->haBindingTimeExpires;
	}

the_end:
	if (haMobileNodeEntry != NULL) {
		/*
		 * Unlock the node
		 */
		(void) rw_unlock(&haMobileNodeEntry->haMnNodeLock);
	}

	if (return_code != SNMP_ERR_NOERROR) {
		free_haMobilityBindingEntry(*haMobilityBindingEntry_data);
		*haMobilityBindingEntry_data = NULL;
	}

	return (return_code);
}


/*
 * Function: free_haMobilityBindingEntry
 *
 * Arguments:	haMobilityBindingEntry - Pointer to a previously
 *			allocated SNMP binding entry
 *
 * Description: This function is called to free a previously
 *		allocated SNMP binding entry.
 *
 * Returns:
 */
void
free_haMobilityBindingEntry(HaMobilityBindingEntry_t *haMobilityBindingEntry)
{
	String *string;

	if (haMobilityBindingEntry) {
		/*
		 * The template generates code that checks both
		 * the pointer, and the length. I am not sure
		 * if this is excessive, so I will leave it as is.
		 */
		string = &(haMobilityBindingEntry->haMobilityBindingMN);
		if (string->chars != NULL && string->len != 0) {
			free(string->chars);
			string->len = 0;
		}

		string = &(haMobilityBindingEntry->haMobilityBindingCOA);
		if (string->chars != NULL && string->len != 0) {
			free(string->chars);
			string->len = 0;
		}

		string =
		    &(haMobilityBindingEntry->haMobilityBindingSourceAddress);
		if (string->chars != NULL && string->len != 0) {
			free(string->chars);
			string->len = 0;
		}
		free(haMobilityBindingEntry);
		haMobilityBindingEntry = NULL;
	}
}
