/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2019 Joyent, Inc.
 */

#include    "sun_sas.h"

/*
 * Returns the text string which describes this adapter and which is used to
 * open the adapter with the library.
 *
 * Arguments:
 *	    index	the index to which adapter to retrieve the name
 *	    name	buffer to which the adapter name will be placed
 */
HBA_STATUS
Sun_sasGetAdapterName(HBA_UINT32 index, char *name)
{
	const char		ROUTINE[] = "Sun_sasGetAdapterName";
	struct sun_sas_hba	*hba_ptr;

	if (name == NULL) {
		log(LOG_DEBUG, ROUTINE, "NULL adapter name");
		return (HBA_STATUS_ERROR_ARG);
	}
	lock(&all_hbas_lock);
	for (hba_ptr = global_hba_head; hba_ptr != NULL;
	    hba_ptr = hba_ptr->next) {
		if (hba_ptr->index == index) {
			if (hba_ptr->handle_name[0] == '\0') {
				hba_ptr = NULL;
				break;
			}
			/*
			 * Flaw in the spec!  How do we know the size of name?
			 */
			(void) strlcpy(name, hba_ptr->handle_name,
			    strlen(hba_ptr->handle_name)+1);
			break;
		}
	}
	unlock(&all_hbas_lock);
	if (hba_ptr == NULL) {
		log(LOG_DEBUG, ROUTINE,
		    "Unable to find adapter index %d.", index);
		return (HBA_STATUS_ERROR_ILLEGAL_INDEX);
	}

	return (HBA_STATUS_OK);
}
