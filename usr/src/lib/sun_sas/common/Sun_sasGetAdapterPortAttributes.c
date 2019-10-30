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
 * Retrieves the attributes for a specified port of an adapter
 */
HBA_STATUS
Sun_sasGetAdapterPortAttributes(HBA_HANDLE handle, HBA_UINT32 port,
    PSMHBA_PORTATTRIBUTES attributes)
{
	const char		ROUTINE[] = "Sun_sasGetAdapterPortAttributes";
	HBA_STATUS		status;
	struct sun_sas_hba	*hba_ptr;
	struct sun_sas_port	*hba_port_ptr;
	int			index;

	/* Validate the arguments */
	if ((attributes == NULL) ||
	    (attributes->PortSpecificAttribute.SASPort == NULL)) {
		log(LOG_DEBUG, ROUTINE, "NULL attributes");
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

	/* Check for stale data */
	status = verifyAdapter(hba_ptr);
	if (status != HBA_STATUS_OK) {
		log(LOG_DEBUG, ROUTINE, "Verify Adapter failed");
		unlock(&open_handles_lock);
		unlock(&all_hbas_lock);
		return (status);
	}

	if (hba_ptr->first_port == NULL) {
		/* This is probably an internal failure of the library */
		if (hba_ptr->device_path[0] != '\0') {
			log(LOG_DEBUG, ROUTINE, "Internal failure:  Adapter "
			    "%s contains no port data", hba_ptr->device_path);
		} else {
			log(LOG_DEBUG, ROUTINE, "Internal failure:  Adapter at"
			    " index %d contains no port data", hba_ptr->index);
		}
		unlock(&open_handles_lock);
		unlock(&all_hbas_lock);
		return (HBA_STATUS_ERROR);
	}
	for (hba_port_ptr = hba_ptr->first_port;
	    hba_port_ptr != NULL; hba_port_ptr = hba_port_ptr->next) {
		if (hba_port_ptr->index == port) {
			break;
		}
	}
	if (hba_port_ptr == NULL || hba_port_ptr->index != port) {
		log(LOG_DEBUG, ROUTINE,
		    "Invalid port index %d for handle %08lx.",
		    port, handle);
		unlock(&open_handles_lock);
		unlock(&all_hbas_lock);
		return (HBA_STATUS_ERROR_ILLEGAL_INDEX);
	}

	attributes->PortType =  hba_port_ptr->port_attributes.PortType;
	attributes->PortState =  hba_port_ptr->port_attributes.PortState;
	(void) strlcpy(attributes->OSDeviceName,
	    hba_port_ptr->port_attributes.OSDeviceName,
	    sizeof (attributes->OSDeviceName));
	(void) memcpy(attributes->PortSpecificAttribute.SASPort,
	    hba_port_ptr->port_attributes.PortSpecificAttribute.SASPort,
	    sizeof (struct SMHBA_SAS_Port));

	unlock(&open_handles_lock);
	unlock(&all_hbas_lock);

	return (HBA_STATUS_OK);
}
