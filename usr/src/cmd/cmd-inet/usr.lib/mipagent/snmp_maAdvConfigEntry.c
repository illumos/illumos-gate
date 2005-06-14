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
 * file: mipagentsnmp_maAdvConfigEntry.c
 *
 * This file contains the SNMP routines used to retrieve
 * the Mobility Agent's Interface Information.
 */

#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <impl.h>
#include <snmp.h>

#include "snmp_stub.h"
#include "agent.h"

extern HashTable maAdvConfigHash;
extern char *ntoa(uint32_t, char *);

/*
 * Function: get_maAdvConfigEntry
 *
 * Arguments:	search_type - The type of search (first, next, exact)
 *		maAdvConfigEntry_data - Pointer to a pointer which
 *			will contain the interface entry upon
 *			successful completion.
 *		index - Pointer to the current index
 *
 * Description: This function will allocate the memory required for
 *		the interface entry, and will find the appropriate
 *		interface entry based on the index provided. If the
 *		search type is set to FIRST_ENTRY, we will return
 *		the first interface entry in the Hash Table, otherwise
 *		the index is used.
 *
 *		The interface entry is then setup with the values found
 *		in the entry from the hash table and returned to the
 *		caller.
 *
 *		Note, the caller is responsible for either freeing the
 *		memory, or calling free_maAdvConfigEntry()
 *
 * Returns: int, 0 if successful
 */
extern int
get_maAdvConfigEntry(int search_type,
    MaAdvConfigEntry_t **maAdvConfigEntry_data,
    IndexType *index)
{
	Integer *integer;
	String  *string;
	MaAdvConfigEntry *maAdvConfigEntry = NULL;
	HashEntry *hashEntry;
	int i;
	int j;
	int len;
	int return_code = SNMP_ERR_NOERROR;
	char buffer[258];
	boolean_t found = _B_FALSE;

	*maAdvConfigEntry_data =
	    (MaAdvConfigEntry_t *)calloc(1, sizeof (MaAdvConfigEntry_t));

	if (maAdvConfigEntry_data == NULL) {
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
		if (maAdvConfigHash.buckets[i]) {
			/*
			 * Lock the bucket
			 */
			(void) rw_rdlock(&maAdvConfigHash.bucketLock[i]);

			hashEntry = maAdvConfigHash.buckets[i];
			while (hashEntry != NULL) {
				if (j == index->value[0]) {
					maAdvConfigEntry = hashEntry->data;
					found = _B_TRUE;

					/*
					 * Lock the node
					 */
					(void) rw_rdlock(&maAdvConfigEntry->
					    maIfaceNodeLock);

					break;
				}
				hashEntry = hashEntry->next;
				j++;
			}

			/*
			 * Unlock the bucket
			 */
			(void) rw_unlock(&maAdvConfigHash.bucketLock[i]);
		}
	}

	if (maAdvConfigEntry == NULL) {
		return_code = END_OF_TABLE;
		goto the_end;
	}

	/*
	 * And now we return the Maximum Registration Lifetime.
	 */
	integer = &((*maAdvConfigEntry_data)->maAdvMaxRegLifetime);
	*integer = (int)maAdvConfigEntry->maAdvMaxRegLifetime;

	/*
	 * And now we return the Prefix Length Inclusion.
	 */
	integer = &((*maAdvConfigEntry_data)->maAdvPrefixLengthInclusion);
	if (maAdvConfigEntry->maAdvPrefixLenInclusion) {
		*integer = 1;
	} else {
		/* I need to validate this one. Should this be 2 or 0 ? */
		*integer = 2;
	}

	/*
	 * Get the Advertised Address.
	 */
	(void) ntoa(maAdvConfigEntry->maAdvAddr, buffer);
	len = strlen(buffer);
	string = &((*maAdvConfigEntry_data)->maAdvAddress);
	string->chars = (unsigned char *)calloc(1, len);
	if (string == NULL) {
		return_code = SNMP_ERR_GENERR;
		goto the_end;
	}
	(void) memcpy(string->chars, buffer, len);
	string->len = len;

	/*
	 * And now we return the Maximum Advertisement Interval.
	 */
	integer = &((*maAdvConfigEntry_data)->maAdvMaxInterval);
	*integer = (int)maAdvConfigEntry->maAdvMaxInterval;

	/*
	 * And now we return the Minimum Advertisement Interval.
	 */
	integer = &((*maAdvConfigEntry_data)->maAdvMinInterval);
	*integer = (int)maAdvConfigEntry->maAdvMinInterval;

#if 0
	/*
	 * And now we return whether we only advertise if we receive
	 * a soliciation.
	 */
	integer = &((*maAdvConfigEntry_data)->maAdvResponseSolicitationOnly);

	if (maAdvConfigEntry->maAdvResponseSolicitationOnly) {
		*integer = 1;
	} else {
		/* I need to validate this one. Should this be 2 or 0 ? */
		*integer = 2;
	}
#endif

	/*
	 * And now we return whether the entry is active. In our case,
	 * all entries are active, so we can hardcode the value.
	 */
	integer = &((*maAdvConfigEntry_data)->maAdvStatus);
	*integer = 1;

the_end:
	if (maAdvConfigEntry != NULL) {
		/*
		 * Unlock the node
		 */
		(void) rw_unlock(&maAdvConfigEntry->maIfaceNodeLock);
	}

	if (return_code != SNMP_ERR_NOERROR) {
		free_maAdvConfigEntry(*maAdvConfigEntry_data);
		*maAdvConfigEntry_data = NULL;
	}

	(void) fprintf(stderr, "get_maAdvConfigEntry: returning %d (%p)\n",
	    return_code, (void *)*maAdvConfigEntry_data);

	return (return_code);
}


/*
 * Function: free_maAdvConfigEntry
 *
 * Arguments:	maAdvConfigEntry - Pointer to a previously
 *			allocated SNMP interface entry
 *
 * Description: This function is called to free a previously
 *		allocated SNMP interface entry.
 *
 * Returns:
 */
void
free_maAdvConfigEntry(MaAdvConfigEntry_t *maAdvConfigEntry)
{
	String  *string;

	if (maAdvConfigEntry) {
		/*
		 * The template generates code that checks both
		 * the pointer, and the length. I am not sure
		 * if this is excessive, so I will leave it as is.
		 */
		string = &(maAdvConfigEntry->maAdvAddress);
		if (string->chars != NULL && string->len != 0) {
			free(string->chars);
			string->len = 0;
		}

		free(maAdvConfigEntry);
		maAdvConfigEntry = NULL;
	}
}
