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
 * Retrieves the mapping between targets and OS SCSI information
 */
HBA_STATUS
Sun_sasGetTargetMapping(HBA_HANDLE handle, HBA_WWN hbaPortWWN,
    HBA_WWN domainPortWWN, SMHBA_TARGETMAPPING *mapping)
{
	const char		ROUTINE[] = "Sun_sasGetTargetMapping";
	int			i, index;
	int			hbaPortFound = 0;
	int			domainPortFound = 0;
	uint_t			total_entries = 0;
	struct  sun_sas_hba	*hba_ptr;
	struct  sun_sas_port	*hba_port_ptr, *hba_disco_port;
	struct	ScsiEntryList	*mapping_ptr;

	if (mapping == NULL) {
		log(LOG_DEBUG, ROUTINE, "NULL mapping buffer");
		return (HBA_STATUS_ERROR_ARG);
	}

	lock(&all_hbas_lock);
	index = RetrieveIndex(handle);
	lock(&open_handles_lock);
	hba_ptr = RetrieveHandle(index);
	if (hba_ptr == NULL) {
		log(LOG_DEBUG, ROUTINE, "Invalid handle %08lx.", handle);
		/* on error, need to set NumberOfEntries to 0 */
		mapping->NumberOfEntries = 0;
		unlock(&open_handles_lock);
		unlock(&all_hbas_lock);
		return (HBA_STATUS_ERROR_INVALID_HANDLE);
	}

	/*
	 * We should indicate an error if no domainPortWWN passed in.
	 */
	if (wwnConversion(domainPortWWN.wwn) == 0) {
		log(LOG_DEBUG, ROUTINE, "domainPortWWN must be provided");
		mapping->NumberOfEntries = 0;
		unlock(&open_handles_lock);
		unlock(&all_hbas_lock);
		return (HBA_STATUS_ERROR_ARG);
	}
	/*
	 * walk through the list of ports for this hba and count up the number
	 * of discovered ports on each hba port
	 */
	i = 0;
	for (hba_port_ptr = hba_ptr->first_port; hba_port_ptr != NULL;
	    hba_port_ptr = hba_port_ptr->next) {
		if (hbaPortFound == 0) {
			if (wwnConversion(hba_port_ptr->port_attributes.
			    PortSpecificAttribute.SASPort->LocalSASAddress.wwn)
			    != wwnConversion(hbaPortWWN.wwn)) {
				/*
				 * Since all the ports under the same HBA have
				 * the same LocalSASAddress, we should break
				 * the loop once we find it dosn't match.
				 */
				break;
			} else {
				hbaPortFound = 1;
			}
		}

		/*
		 * Check whether the domainPortWWN matches.
		 */
		if ((validateDomainAddress(hba_port_ptr, domainPortWWN))
		    != HBA_STATUS_OK) {
			continue;
		}
		domainPortFound = 1;

		for (hba_disco_port = hba_port_ptr->first_attached_port;
		    hba_disco_port != NULL;
		    hba_disco_port = hba_disco_port->next) {
			for (mapping_ptr = hba_disco_port->scsiInfo;
			    mapping_ptr != NULL;
			    mapping_ptr = mapping_ptr->next) {
				/*
				 * Add the information as much as mapping
				 * can hold.
				 */
				if (wwnConversion(domainPortWWN.wwn) !=
				    wwnConversion(mapping_ptr->entry.
				    PortLun.domainPortWWN.wwn)) {
					continue;
				}

				if (total_entries < mapping->NumberOfEntries) {
					(void) memcpy(&mapping->entry[i].ScsiId,
					    &mapping_ptr->entry.ScsiId,
					    sizeof (SMHBA_SCSIID));
					(void) memcpy(&mapping->entry[i].
					    PortLun, &mapping_ptr->entry.
					    PortLun, sizeof (SMHBA_PORTLUN));
					(void) memcpy(&mapping->entry[i].LUID,
					    &mapping_ptr->entry.LUID,
					    sizeof (SMHBA_LUID));
					i++;
				}
				total_entries++;
			}
		}
	}

	/*
	 * check to make sure user has passed in an acceptable PortWWN for
	 * the given handle
	 */
	if (hbaPortFound == 0) {
		log(LOG_DEBUG, ROUTINE, "Unable to locate requested "
		    "HBA Port WWN %016llx on handle %08lx",
		    wwnConversion(hbaPortWWN.wwn), handle);
		unlock(&open_handles_lock);
		unlock(&all_hbas_lock);
		return (HBA_STATUS_ERROR_ILLEGAL_WWN);
	}

	if (domainPortFound == 0) {
		log(LOG_DEBUG, ROUTINE, "No matching domain "
		    "port %016llx for port %016llx on handle "
		    "%08lx", wwnConversion(domainPortWWN.wwn),
		    wwnConversion(hbaPortWWN.wwn), handle);
		unlock(&open_handles_lock);
		unlock(&all_hbas_lock);
		return (HBA_STATUS_ERROR_ILLEGAL_WWN);
	}

	if (total_entries > mapping->NumberOfEntries) {
		log(LOG_DEBUG, ROUTINE,
		    "total entries: %d: mapping->NumberofEntries: %d.",
		    total_entries, mapping->NumberOfEntries);
		mapping->NumberOfEntries = total_entries;
		unlock(&open_handles_lock);
		unlock(&all_hbas_lock);
		return (HBA_STATUS_ERROR_MORE_DATA);
	}

	mapping->NumberOfEntries = total_entries;

	/* convert devpath to dev link */
	convertDevpathToDevlink(mapping);

	unlock(&open_handles_lock);
	unlock(&all_hbas_lock);

	return (HBA_STATUS_OK);
}
