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

#include    <sun_sas.h>

/*
 * Retrieves the statistics for a specified port on an adapter
 */
HBA_STATUS Sun_sasGetSASPhyAttributes(HBA_HANDLE handle,
    HBA_UINT32 port, HBA_UINT32 phy, SMHBA_SAS_PHY *pAttributes)
{
	const char	ROUTINE[] = "Sun_sasGetSASPhyAttributes";
	HBA_STATUS		status = HBA_STATUS_OK;
	struct sun_sas_hba	*hba_ptr;
	struct sun_sas_port	*hba_port_ptr;
	struct phy_info		*phy_ptr;

	/* Validate the arguments */
	if (pAttributes == NULL) {
		log(LOG_DEBUG, ROUTINE, "NULL response buffer");
		return (HBA_STATUS_ERROR_ARG);
	}
	lock(&all_hbas_lock);

	if ((hba_ptr = Retrieve_Sun_sasHandle(handle)) == NULL) {
		log(LOG_DEBUG, ROUTINE, "Invalid handle %08lx", handle);
		unlock(&all_hbas_lock);
		return (HBA_STATUS_ERROR_INVALID_HANDLE);
	}

	/* Check for stale data */
	status = verifyAdapter(hba_ptr);
	if (status != HBA_STATUS_OK) {
		log(LOG_DEBUG, ROUTINE, "Verify adapter failed");
		unlock(&all_hbas_lock);
		return (status);
	}

	for (hba_port_ptr = hba_ptr->first_port;
	    hba_port_ptr != NULL;
	    hba_port_ptr = hba_port_ptr->next) {
		if (hba_port_ptr->index == port) {
			break;
		}
	}

	if (hba_port_ptr == NULL) {
		log(LOG_DEBUG, ROUTINE, "Invalid port index");
		unlock(&all_hbas_lock);
		return (HBA_STATUS_ERROR_ILLEGAL_INDEX);
	}

	/* match phy index. */
	if (phy >= hba_port_ptr->port_attributes.PortSpecificAttribute.
	    SASPort->NumberofPhys) {
		log(LOG_DEBUG, ROUTINE, "Invalid phy index %d", phy);
		unlock(&all_hbas_lock);
		return (HBA_STATUS_ERROR_ILLEGAL_INDEX);
	} else {
		for (phy_ptr = hba_port_ptr->first_phy; phy_ptr != NULL;
		    phy_ptr = phy_ptr->next) {
			if (phy == phy_ptr->index) {
				(void) memset(pAttributes, 0,
				    sizeof (SMHBA_SAS_PHY));
				(void) memcpy(pAttributes, &phy_ptr->phy,
				    sizeof (SMHBA_SAS_PHY));
				unlock(&all_hbas_lock);
				return (HBA_STATUS_OK);
			}
		}
	}

	unlock(&all_hbas_lock);
	log(LOG_DEBUG, ROUTINE, "Illegal phy index %d", phy);
	return (HBA_STATUS_ERROR_ILLEGAL_INDEX);
}
