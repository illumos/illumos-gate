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
 * Retrieves the attributes for a specific discovered port by WWN
 */
HBA_STATUS
Sun_sasGetPortAttributesByWWN(HBA_HANDLE handle, HBA_WWN portWWN,
    HBA_WWN domainPortWWN, PSMHBA_PORTATTRIBUTES attributes)
{
	const char		ROUTINE[] = "Sun_sasGetPortAttributesByWWN";
	HBA_STATUS		status;
	struct sun_sas_hba	*hba_ptr;
	struct sun_sas_port	*hba_port_ptr, *hba_disco_port;
	int			index, chkDomainPort = 0, domainFound = 0;

	/* Validate the arguments */
	if (attributes == NULL) {
		log(LOG_DEBUG, ROUTINE, "NULL port attributes");
		return (HBA_STATUS_ERROR_ARG);
	}

	if (wwnConversion(domainPortWWN.wwn) != 0) {
		chkDomainPort = 1;
	}

	lock(&all_hbas_lock);
	index = RetrieveIndex(handle);
	lock(&open_handles_lock);
	hba_ptr = RetrieveHandle(index);
	if (hba_ptr == NULL) {
		log(LOG_DEBUG, ROUTINE, "Invalid handle %08lx.", handle);
		unlock(&open_handles_lock);
		unlock(&all_hbas_lock);
		return (HBA_STATUS_ERROR_INVALID_HANDLE);
	}

	/* Check for stale data */
	status = verifyAdapter(hba_ptr);
	if (status != HBA_STATUS_OK) {
		log(LOG_DEBUG, ROUTINE, "Verify adapter failed");
		unlock(&open_handles_lock);
		unlock(&all_hbas_lock);
		return (status);
	}

	if (hba_ptr->first_port == NULL) {
		/* This is probably an internal failure of the library */
		if (hba_ptr->device_path[0] != '\0') {
			log(LOG_DEBUG, ROUTINE,
			    "Internal failure:  Adapter %s contains "
			    "no port data", hba_ptr->device_path);
		} else {
			log(LOG_DEBUG, ROUTINE,
			    "Internal failure:  Adapter at index %d contains "
			    "no port data", hba_ptr->index);
		}
		unlock(&open_handles_lock);
		unlock(&all_hbas_lock);
		return (HBA_STATUS_ERROR);
	}

	/* Loop over all Adapter ports */
	for (hba_port_ptr = hba_ptr->first_port;
	    hba_port_ptr != NULL;
	    hba_port_ptr = hba_port_ptr->next) {
		if (chkDomainPort) {
			if (validateDomainAddress(hba_port_ptr,
			    domainPortWWN) != HBA_STATUS_OK) {
				continue;
			} else
				domainFound = 1;
		}

		if (wwnConversion(hba_port_ptr->port_attributes.
		    PortSpecificAttribute.SASPort->LocalSASAddress.wwn) ==
		    wwnConversion(portWWN.wwn)) {
			/*
			 * We should indicate an error if we enter here
			 * without domainPortWWN set.
			 */
			if (chkDomainPort == 0) {
				log(LOG_DEBUG, ROUTINE,
				    "Domain Port WWN should be set when "
				    "querying HBA port %016llx for "
				    "handle %08lx",
				    wwnConversion(portWWN.wwn), handle);
				unlock(&open_handles_lock);
				unlock(&all_hbas_lock);
				return (HBA_STATUS_ERROR_ARG);
			}
			attributes->PortType =
			    hba_port_ptr->port_attributes.PortType;
			attributes->PortState =
			    hba_port_ptr->port_attributes.PortState;
			(void) strlcpy(attributes->OSDeviceName,
			    hba_port_ptr->port_attributes.OSDeviceName,
			    sizeof (attributes->OSDeviceName));
			(void) memcpy(attributes->PortSpecificAttribute.SASPort,
			    hba_port_ptr->port_attributes.PortSpecificAttribute.
			    SASPort, sizeof (struct SMHBA_SAS_Port));

			unlock(&open_handles_lock);
			unlock(&all_hbas_lock);
			return (HBA_STATUS_OK);
		}

		/* check to make sure there are devices attached to this port */
		if (hba_port_ptr->first_attached_port != NULL) {

			/* Loop over all discovered ports */
			for (hba_disco_port = hba_port_ptr->first_attached_port;
			    hba_disco_port != NULL;
			    hba_disco_port = hba_disco_port->next) {
				if (wwnConversion(hba_disco_port->
				    port_attributes.PortSpecificAttribute.
				    SASPort->LocalSASAddress.wwn) ==
				    wwnConversion(portWWN.wwn)) {
					attributes->PortType =
					    hba_disco_port->port_attributes.
					    PortType;
					attributes->PortState =
					    hba_disco_port->port_attributes.
					    PortState;
					(void) strlcpy(attributes->OSDeviceName,
					    hba_disco_port->port_attributes.
					    OSDeviceName,
					    sizeof (attributes->OSDeviceName));
					(void) memcpy(attributes->
					    PortSpecificAttribute.SASPort,
					    hba_disco_port->port_attributes.
					    PortSpecificAttribute.SASPort,
					    sizeof (struct SMHBA_SAS_Port));
					unlock(&open_handles_lock);
					unlock(&all_hbas_lock);
					return (HBA_STATUS_OK);
				}
			}
		}
		if (chkDomainPort) {
			log(LOG_DEBUG, ROUTINE,
			    "Invalid Port WWN %016llx for handle %08lx",
			    wwnConversion(portWWN.wwn), handle);
			unlock(&open_handles_lock);
			unlock(&all_hbas_lock);
			return (HBA_STATUS_ERROR_ILLEGAL_WWN);
		}
	}
	if (chkDomainPort && domainFound == 0) {
		log(LOG_DEBUG, ROUTINE, "No Matching domain port"
		    " (%16llx) for port (%16llx) for handle %08lx",
		    wwnConversion(domainPortWWN.wwn),
		    wwnConversion(portWWN.wwn),
		    handle);
	} else {
		/* We enter here only when chkDomainPort == 0 */
		log(LOG_DEBUG, ROUTINE,
		    "Invalid Port WWN %016llx for handle %08lx",
		    wwnConversion(portWWN.wwn), handle);
	}
	unlock(&open_handles_lock);
	unlock(&all_hbas_lock);
	return (HBA_STATUS_ERROR_ILLEGAL_WWN);
}
