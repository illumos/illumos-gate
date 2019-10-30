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

#include <sun_sas.h>

/*
 * Frees the HBA Library.  Must be called after all HBA library functions
 * to free all resources
 */
HBA_STATUS
Sun_sasFreeLibrary(void)
{
	HBA_STATUS status;

	lock(&all_hbas_lock);

	status = FreeHBA(global_hba_head);

	/* re-initialize all global variables */
	global_hba_head = NULL;
	hba_count = 0;
	open_handle_index = 1;
	unlock(&all_hbas_lock);
	(void) mutex_destroy(&all_hbas_lock);

	/* free sysevent handle. */
	if (gSysEventHandle != NULL)
		sysevent_unbind_handle(gSysEventHandle);

	/* Reset our load count so we can be reloaded now */
	loadCount = 0;

	return (status);
}

/*
 * Internal routine to free up hba_ptr's (and all sub-structures)
 */
HBA_STATUS
FreeHBA(struct sun_sas_hba *hba)
{
	struct sun_sas_hba	*hba_ptr = NULL;
	struct sun_sas_hba	*last_hba_ptr = NULL;
	struct sun_sas_port	*hba_port = NULL;
	struct sun_sas_port	*last_hba_port = NULL;
	struct sun_sas_port	*tgt_port = NULL;
	struct sun_sas_port	*last_tgt_port = NULL;
	struct ScsiEntryList	*scsi_info = NULL;
	struct ScsiEntryList	*last_scsi_info = NULL;
	struct phy_info		*phy_ptr = NULL;
	struct phy_info		*last_phy = NULL;
	struct open_handle	*open_handle = NULL;
	struct open_handle	*last_open_handle = NULL;

	last_hba_ptr = NULL;
	/* walk through global_hba_head list freeing each handle */
	for (hba_ptr = hba; hba_ptr != NULL; hba_ptr = hba_ptr->next) {
		/* Free the nested structures (port and attached port) */
		hba_port = hba_ptr->first_port;
		while (hba_port != NULL) {
			/* Free discovered port structure list. */
			tgt_port = hba_port->first_attached_port;
			while (tgt_port != NULL) {
				/* Free target mapping data list first. */
				scsi_info = tgt_port->scsiInfo;
				while (scsi_info != NULL) {
					last_scsi_info = scsi_info;
					scsi_info = scsi_info->next;
					free(last_scsi_info);
				}
				last_tgt_port = tgt_port;
				tgt_port = tgt_port->next;
				free(last_tgt_port->port_attributes.\
				    PortSpecificAttribute.SASPort);
				free(last_tgt_port);
			}

			phy_ptr = hba_port->first_phy;
			while (phy_ptr != NULL) {
				last_phy = phy_ptr;
				phy_ptr = phy_ptr->next;
				free(last_phy);
			}

			last_hba_port = hba_port;
			hba_port = hba_port->next;
			free(last_hba_port->port_attributes.\
			    PortSpecificAttribute.SASPort);
			free(last_hba_port);
		}

		open_handle = hba_ptr->open_handles;
		while (open_handle != NULL) {
			last_open_handle = open_handle;
			open_handle = open_handle->next;
			free(last_open_handle);
		}
		/* Free up the top level HBA structure from the last spin */
		if (last_hba_ptr != NULL) {
			free(last_hba_ptr);
		}
		last_hba_ptr = hba_ptr;
	}
	if (last_hba_ptr != NULL) {
		free(last_hba_ptr);
	}

	return (HBA_STATUS_OK);
}
