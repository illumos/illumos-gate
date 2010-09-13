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

#include <sun_sas.h>

/*
 * Returns the number of HBAs supported by the library.  This returns the
 * current number of HBAs, even if this changes
 *
 */
HBA_UINT32 Sun_sasGetNumberOfPorts(
    HBA_HANDLE handle, HBA_UINT32 *numberofports)
{
	const char		    ROUTINE[] = "Sun_sasGetNumberOfPorts";
	int			    count, index;
	struct  sun_sas_hba	    *hba_ptr;
	struct  sun_sas_port	    *hba_port_ptr;

	if (numberofports == NULL) {
		log(LOG_DEBUG, ROUTINE, "NULL numberofPorts pointer");
		return (HBA_STATUS_ERROR_ARG);
	}

	lock(&all_hbas_lock);
	index = RetrieveIndex(handle);
	lock(&open_handles_lock);
	hba_ptr = RetrieveHandle(index);
	if (hba_ptr == NULL) {
		log(LOG_DEBUG, ROUTINE, "Invalid handle %08lx.", handle);
		/* on error, need to set NumberOfEntries to 0 */
		unlock(&open_handles_lock);
		unlock(&all_hbas_lock);
		return (HBA_STATUS_ERROR_INVALID_HANDLE);
	}
	/* goes through hba list counting all the hbas found */
	if (hba_ptr->first_port == NULL) {
		log(LOG_DEBUG, ROUTINE, "No HBA Port found on handle %08lx.",
		    handle);
		/* on error, need to set NumberOfPorts to 0 */
		*numberofports = 0;
		unlock(&open_handles_lock);
		unlock(&all_hbas_lock);
		return (HBA_STATUS_OK);
	}

	for (count = 0, hba_port_ptr = hba_ptr->first_port;
	    hba_port_ptr != NULL; hba_port_ptr = hba_port_ptr->next, count++) {}

	*numberofports = count;

	unlock(&open_handles_lock);
	unlock(&all_hbas_lock);

	return (HBA_STATUS_OK);

}
