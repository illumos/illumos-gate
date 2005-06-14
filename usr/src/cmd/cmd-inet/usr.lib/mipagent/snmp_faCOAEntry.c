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
 * file: mipagentsnmp_faCOAEntry.c
 *
 * This file contains the SNMP routines used to retrieve
 * the Foreign Agent's Care of Address Information.
 */

#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>

#include <impl.h>

#include "snmp_stub.h"
#include "agent.h"

/* faCOAEntry */

/*
 * Function: get_faCOAEntry
 *
 * Arguments:	search_type - The type of search (first, next, exact)
 *		faCOAEntry_data - Pointer to a pointer
 *			which will contain the COA entry upon
 *			successful completion.
 *		index - Pointer to the current index
 *
 * Description: Since we currently do not support this, we will
 *		simply return and end of table SNMP error code.
 *
 * Returns:	END_OF_TABLE, meaning there are no more entries
 *		in our table.
 */
/* ARGSUSED */
extern int
get_faCOAEntry(int search_type, FaCOAEntry_t **faCOAEntry_data,
    IndexType *index)
{
	/*
	 * Perhaps one day we will support Care of Addresses, but
	 * for now we will return an end of table error.
	 */
	return (END_OF_TABLE);

}


/*
 * Function: free_faCOAEntry
 *
 * Arguments:	faCOAEntry - Pointer to a previously
 *			allocated SNMP COA entry
 *
 * Description: This function is called to free a previously
 *		allocated SNMP COA entry.
 *
 * Returns:
 */
void
free_faCOAEntry(FaCOAEntry_t *faCOAEntry)
{
	if (faCOAEntry) {
		free(faCOAEntry);
		faCOAEntry = NULL;
	}
}
