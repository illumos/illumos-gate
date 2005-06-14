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
 * file: mipagentsnmp_faVisitorEntry.c
 *
 * This file contains the SNMP routines used to retrieve
 * the Foreign Agent's Visitor Entry.
 */

#include <sys/types.h>
#include <netinet/in.h>
#include <memory.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <impl.h>
#include <snmp.h>

#include "snmp_stub.h"
#include "agent.h"

extern HashTable faVisitorHash;
extern char *ntoa(uint32_t, char *);

/* faVisitorEntry */

/*
 * Function: get_faVisitorEntry
 *
 * Arguments:	search_type - The type of search (first, next, exact)
 *		faVisitorEntry_data - Pointer to a pointer which
 *			will contain the visitor entry upon
 *			successful completion.
 *		index - Pointer to the current index
 *
 * Description: This function will allocate the memory required for
 *		the visitor entry, and will find the appropriate
 *		visitor entry based on the index provided. If the
 *		search type is set to FIRST_ENTRY, we will return
 *		the first visitor entry in the Hash Table, otherwise
 *		the index is used.
 *
 *		The visitor entry is then setup with the values found
 *		in the entry from the hash table and returned to the
 *		caller.
 *
 *		Note, the caller is responsible for either freeing the
 *		memory, or calling free_faVisitorEntry()
 *
 * Returns: int, 0 if successful
 */
int
get_faVisitorEntry(int search_type, FaVisitorEntry_t **faVisitorEntry_data,
    IndexType *index)
{
	Integer *integer;
	String  *string;
	FaVisitorEntry *faVisitorEntry = NULL;
	HashEntry *hashEntry;
	int i;
	int j;
	int return_code = SNMP_ERR_NOERROR;
	time_t currentTime;
	char buffer[258];
	boolean_t found = _B_FALSE;
	struct ether_addr	ether;
	char	*tmp_buf;

	/*
	 * Allocate some memory to handle the request.
	 */
	*faVisitorEntry_data =
	    (FaVisitorEntry_t *)calloc(1, sizeof (FaVisitorEntry_t));

	if (faVisitorEntry_data == NULL) {
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
		if (faVisitorHash.buckets[i]) {
			/*
			 * Lock the bucket
			 */
			(void) rw_rdlock(&faVisitorHash.bucketLock[i]);

			/*
			 * Look for the entry we need
			 */
			hashEntry = faVisitorHash.buckets[i];
			while (hashEntry != NULL) {
				if (j == index->value[0]) {
					faVisitorEntry = hashEntry->data;
					found = _B_TRUE;

					/*
					 * Lock the node
					 */
					(void) rw_rdlock(&faVisitorEntry->
					    faVisitorNodeLock);

					break;
				}
				hashEntry = hashEntry->next;
				j++;
			}

			/*
			 * Unlock the bucket
			 */
			(void) rw_unlock(&faVisitorHash.bucketLock[i]);
		}
	}

	if (faVisitorEntry == NULL) {
		return_code = END_OF_TABLE;
		goto the_end;
	}

	/*
	 * Get the visitor entry's IP Address.
	 */
	(void)  ntoa(faVisitorEntry->faVisitorAddr, buffer);
	string = &((*faVisitorEntry_data)->faVisitorIPAddress);
	string->chars = (unsigned char *)strdup(buffer);
	if (string->chars == NULL) {
		return_code = SNMP_ERR_GENERR;
		goto the_end;
	}
	string->len = strlen(buffer);

	/*
	 * Get the visitor entry's link layer address.
	 */
	(void) memcpy(ether.ether_addr_octet,
	    faVisitorEntry->faVisitorSlla.sdl_data, ETHERADDRL);
	tmp_buf = ether_ntoa(&ether);
	if (tmp_buf == NULL) {
		return_code = SNMP_ERR_GENERR;
		goto the_end;
	}
	string = &((*faVisitorEntry_data)->faVisitorSlla);
	string->chars = (unsigned char *)strdup(tmp_buf);
	if (string->chars == NULL) {
		return_code = SNMP_ERR_GENERR;
		goto the_end;
	}
	string->len = strlen(tmp_buf);

	/*
	 * Let's get the visitor entry's Home Agent Address
	 */
	(void)  ntoa(faVisitorEntry->faVisitorHomeAgentAddr, buffer);
	string = &((*faVisitorEntry_data)->faVisitorHomeAgentAddress);
	string->chars = (unsigned char *)strdup(buffer);
	if (string->chars == NULL) {
		return_code = SNMP_ERR_GENERR;
		goto the_end;
	}
	string->len = strlen(buffer);

	/*
	 * Let's get the visitor entry's Home Address
	 */
	(void) ntoa(faVisitorEntry->faVisitorHomeAddr, buffer);
	string = &((*faVisitorEntry_data)->faVisitorHomeAddress);

	string->chars = (unsigned char *)strdup(buffer);
	if (string->chars == NULL) {
		return_code = SNMP_ERR_GENERR;
		goto the_end;
	}
	string->len = strlen(buffer);

	/*
	 * And now we return the amount of time that was granted to
	 * the visitor.
	 */
	integer = &((*faVisitorEntry_data)->faVisitorTimeGranted);
	*integer = faVisitorEntry->faVisitorTimeGranted;

	/*
	 * And now we return the amount of time remaining for
	 * the visitor.
	 */
	integer = &((*faVisitorEntry_data)->faVisitorTimeRemaining);
	GET_TIME(currentTime);
	*integer = currentTime -
	    faVisitorEntry->faVisitorTimeExpires;

	/*
	 * And now we return the Registration Flags.
	 */
	integer = &((*faVisitorEntry_data)->faVisitorRegFlags);
	*integer = (int)faVisitorEntry->faVisitorRegFlags;

	/*
	 * And now we return the lower 32-bits of the visitor's ID.
	 */
	integer = &((*faVisitorEntry_data)->faVisitorRegIDLow);
	*integer = (int)faVisitorEntry->faVisitorRegIDLow;

	/*
	 * And now we return the high 32-bits of the visitor's ID.
	 */
	integer = &((*faVisitorEntry_data)->faVisitorRegIDHigh);
	*integer = (int)faVisitorEntry->faVisitorRegIDHigh;


	/*
	 * And now we return the high 32-bits of the visitor's ID.
	 */
	integer = &((*faVisitorEntry_data)->faVisitorRegIsAccepted);
	if (faVisitorEntry->faVisitorRegIsAccepted == _B_TRUE) {
		*integer = 1;
	} else {
		*integer = 2;
	}

	/*
	 * And now we return the inbound interface index on which the
	 * registration request was received
	 */
	integer = &((*faVisitorEntry_data)->faVisitorInIfindex);
	*integer = (int)faVisitorEntry->faVisitorInIfindex;

the_end:
	if (faVisitorEntry != NULL) {
		/*
		 * Unlock the bucket
		 */
		(void) rw_unlock(&faVisitorEntry->faVisitorNodeLock);
	}

	if (return_code != SNMP_ERR_NOERROR) {
		free_faVisitorEntry(*faVisitorEntry_data);
		*faVisitorEntry_data = NULL;
	}

	return (return_code);
}


/*
 * Function: free_faVisitorEntry
 *
 * Arguments:	faVisitorEntry - Pointer to a previously
 *			allocated SNMP visitor entry
 *
 * Description: This function is called to free a previously
 *		allocated SNMP visitor entry.
 *
 * Returns:
 */
void
free_faVisitorEntry(FaVisitorEntry_t *faVisitorEntry)
{
	String *string;

	if (faVisitorEntry) {
		/*
		 * The template generates code that checks both
		 * the pointer, and the length. I am not sure
		 * if this is excessive, so I will leave it as is.
		 */
		string = &(faVisitorEntry->faVisitorIPAddress);
		if (string->chars != NULL && string->len != 0) {
			free(string->chars);
			string->len = 0;
		}

		string = &(faVisitorEntry->faVisitorHomeAddress);
		if (string->chars != NULL && string->len != 0) {
			free(string->chars);
			string->len = 0;
		}

		string = &(faVisitorEntry->faVisitorHomeAgentAddress);
		if (string->chars != NULL && string->len != 0) {
			free(string->chars);
			string->len = 0;
		}

		string = &(faVisitorEntry->faVisitorSlla);
		if (string->chars != NULL && string->len != 0) {
			free(string->chars);
			string->len = 0;
		}

		free(faVisitorEntry);
		faVisitorEntry = NULL;
	}
}
