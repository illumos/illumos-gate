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

#include    <sun_sas.h>
/*
 * Retrieves the attribues for an adapter
 */
HBA_STATUS
Sun_sasGetAdapterAttributes(HBA_HANDLE handle,
    PSMHBA_ADAPTERATTRIBUTES attributes)
{
	const char		ROUTINE[] = "Sun_sasGetAdapterAttributes";
	struct sun_sas_hba	*hba_ptr;
	int			index = 0;

	if (attributes == NULL) {
		log(LOG_DEBUG, ROUTINE, "NULL attributes pointer");
		return (HBA_STATUS_ERROR_ARG);
	}

	lock(&all_hbas_lock);
	index = RetrieveIndex(handle);
	lock(&open_handles_lock);
	hba_ptr = RetrieveHandle(index);
	if (hba_ptr == NULL) {
		log(LOG_DEBUG, ROUTINE, "Invalid handle %08lx", handle);
		unlock(&open_handles_lock);
		unlock(&all_hbas_lock);
		return (HBA_STATUS_ERROR_INVALID_HANDLE);
	}

	(void) memcpy(attributes, &hba_ptr->adapter_attributes,
	    sizeof (SMHBA_ADAPTERATTRIBUTES));

	unlock(&open_handles_lock);
	unlock(&all_hbas_lock);

	return (HBA_STATUS_OK);
}
