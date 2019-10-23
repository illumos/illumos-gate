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
#include <kstat.h>
#include <sun_sas.h>

/*
 * Retrieves the statistics for a specified port.phy on an adapter
 */
HBA_STATUS
Sun_sasGetPhyStatistics(HBA_HANDLE handle, HBA_UINT32 port, HBA_UINT32 phy,
    SMHBA_PHYSTATISTICS *pStatistics)
{
	const char	ROUTINE[] = "Sun_sasGetPhyStatistics";
	HBA_STATUS		status = HBA_STATUS_OK;
	struct sun_sas_hba	*hba_ptr;
	struct sun_sas_port	*hba_port_ptr;
	struct phy_info		*phy_ptr;
	PSMHBA_SASPHYSTATISTICS	psas;
	kstat_ctl_t		*kc;
	kstat_t			*ksp;
	kstat_named_t		*kname;
	char			*charptr, path[MAXPATHLEN + 1];
	char			*driver_name, kstat_name[256];
	di_node_t		node;
	int			instance = 0;
	int			i;
	uint64_t		iport_wwn;

	/* Validate the arguments */
	if (pStatistics == NULL) {
		log(LOG_DEBUG, ROUTINE,
		    "NULL Phy Statistics buffer of phyIndex: %08lx", phy);
		return (HBA_STATUS_ERROR_ARG);
	}
	psas = pStatistics->SASPhyStatistics;
	if (psas == NULL) {
		log(LOG_DEBUG, ROUTINE,
		    "NULL SAS Phy Statistics buffer of phyIndex: %08lx", phy);
		return (HBA_STATUS_ERROR_ARG);
	}

	lock(&all_hbas_lock);

	if ((hba_ptr = Retrieve_Sun_sasHandle(handle)) == NULL) {
		log(LOG_DEBUG, ROUTINE,
		    "Invalid HBA handler %08lx of phyIndex: %08lx",
		    handle, phy);
		unlock(&all_hbas_lock);
		return (HBA_STATUS_ERROR_INVALID_HANDLE);
	}

	/* Check for stale data */
	status = verifyAdapter(hba_ptr);
	if (status != HBA_STATUS_OK) {
		log(LOG_DEBUG, ROUTINE,
		    "Verify Adapter failed for phyIndex: %08lx", phy);
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
		log(LOG_DEBUG, ROUTINE,
		    "Invalid port index of phyIndex: %08lx", phy);
		unlock(&all_hbas_lock);
		return (HBA_STATUS_ERROR_ILLEGAL_INDEX);
	}

	if (phy >= hba_port_ptr->port_attributes.PortSpecificAttribute.
	    SASPort->NumberofPhys) {
		log(LOG_DEBUG, ROUTINE, "Invalid phy index %08lx", phy);
		unlock(&all_hbas_lock);
		return (HBA_STATUS_ERROR_ILLEGAL_INDEX);
	}

	/* We need to find out the phy identifier. */
	for (phy_ptr = hba_port_ptr->first_phy;
	    phy_ptr != NULL;
	    phy_ptr = phy_ptr->next) {
		if (phy == phy_ptr->index)
			break;
	}

	if (phy_ptr == NULL) {
		log(LOG_DEBUG, ROUTINE, "Invalid phy index %08lx", phy);
		unlock(&all_hbas_lock);
		return (HBA_STATUS_ERROR_ILLEGAL_INDEX);
	}

	/*
	 * for statistics that are not supported, its bits should all be
	 * set to -1
	 */
	(void) memset(pStatistics->SASPhyStatistics, 0xff,
	    sizeof (SMHBA_SASPHYSTATISTICS));


	/* First, we need the deivce path to locate the devinfo node. */
	(void) strlcpy(path, hba_port_ptr->device_path,
	    sizeof (path));
	charptr = strrchr(path, ':');
	if (charptr) {
		*charptr = '\0';
	}

	errno = 0;

	(void *) memset(kstat_name, 0, sizeof (kstat_name));
	node = di_init(path, DINFOCPYONE);
	if (node == DI_NODE_NIL) {
		di_fini(node);
		log(LOG_DEBUG, ROUTINE,
		    "Unable to take devinfo snapshot on HBA \"%s\" "
		    "for phyIndex: %08lx due to %s",
		    path, phy, strerror(errno));
		unlock(&all_hbas_lock);
		return (HBA_STATUS_ERROR);
	}

	/*
	 * Then we could fetch the instance number and driver name of this
	 * device.
	 */
	instance = di_instance(node);
	if (instance == -1) {
		di_fini(node);
		log(LOG_DEBUG, ROUTINE,
		    "An instance number has not been assigned to the "
		    "device \"%s\" when get phyIndex: %08lx", path, phy);
		unlock(&all_hbas_lock);
		return (HBA_STATUS_ERROR);
	}

	driver_name = di_driver_name(node);
	if (driver_name == NULL) {
		di_fini(node);
		log(LOG_DEBUG, ROUTINE,
		    "No driver bound to this device \"%s\" "
		    "when get phyIndex: %08lx",
		    path, phy);
		unlock(&all_hbas_lock);
		return (HBA_STATUS_ERROR);
	}

	di_fini(node);

	iport_wwn = wwnConversion(hba_port_ptr->port_attributes.\
	    PortSpecificAttribute.SASPort->LocalSASAddress.wwn);

	/*
	 * Construct the kstat name here.
	 */
	(void) snprintf(kstat_name, sizeof (kstat_name), "%s.%016llx.%u.%u",
	    driver_name, iport_wwn, instance, phy_ptr->phy.PhyIdentifier);

	/* retrieve all the statistics from kstat. */
	kc = kstat_open();
	if (kc == NULL) {
		log(LOG_DEBUG, ROUTINE,
		    "kstat_open failed due to \"%s\" of phyIndex: %08lx",
		    strerror(errno), phy);
		unlock(&all_hbas_lock);
		return (HBA_STATUS_ERROR);
	}
	ksp = kstat_lookup(kc, NULL, -1, kstat_name);
	if (ksp == NULL) {
		log(LOG_DEBUG, ROUTINE,
		    "No matching kstat name found for \"%s\" "
		    "of phyIndex: %08lx",
		    kstat_name, phy);
		unlock(&all_hbas_lock);
		(void) kstat_close(kc);
		return (HBA_STATUS_ERROR);
	}
	/* Found the phy we're looking for. */
	if (kstat_read(kc, ksp, NULL) == -1) {
		log(LOG_DEBUG, ROUTINE,
		    "error reading kstat data due to \"%s\" "
		    "of phyIndex: %08lx",
		    strerror(errno), phy);
		unlock(&all_hbas_lock);
		(void) kstat_close(kc);
		return (HBA_STATUS_ERROR);
	}

	kname = (kstat_named_t *)ksp->ks_data;
	for (i = 0; i < ksp->ks_ndata; i++, kname++) {
		if (strcmp(kname->name,
		    "SecondsSinceLastReset") == 0) {
			psas->SecondsSinceLastReset = kname->value.ull;
			continue;
		}
		if (strcmp(kname->name, "TxFrames") == 0) {
			psas->TxFrames = kname->value.ull;
			continue;
		}
		if (strcmp(kname->name, "RxFrames") == 0) {
			psas->RxFrames = kname->value.ull;
			continue;
		}
		if (strcmp(kname->name, "TxWords") == 0) {
			psas->TxWords = kname->value.ull;
			continue;
		}
		if (strcmp(kname->name, "RxWords") == 0) {
			psas->RxWords = kname->value.ull;
			continue;
		}
		if (strcmp(kname->name, "InvalidDwordCount") == 0) {
			psas->InvalidDwordCount = kname->value.ull;
			continue;
		}
		if (strcmp(kname->name, "RunningDisparityErrorCount") == 0) {
			psas->RunningDisparityErrorCount = kname->value.ull;
			continue;
		}
		if (strcmp(kname->name, "LossofDwordSyncCount") == 0) {
			psas->LossofDwordSyncCount = kname->value.ull;
			continue;
		}
		if (strcmp(kname->name, "PhyResetProblemCount") == 0) {
			psas->PhyResetProblemCount = kname->value.ull;
		}
	}
	unlock(&all_hbas_lock);
	(void) kstat_close(kc);

	return (HBA_STATUS_OK);
}
