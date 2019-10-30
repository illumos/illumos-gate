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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright 2019 Joyent, Inc.
 */

#include	<sun_sas.h>
#include	<sys/modctl.h>
#include	<sys/types.h>
#include	<netinet/in.h>
#include	<inttypes.h>
#include	<ctype.h>

/* free hba port info for the given hba */
static void
free_hba_port(struct sun_sas_hba *hba_ptr)
{
	struct sun_sas_port	*hba_port = NULL;
	struct sun_sas_port	*last_hba_port = NULL;
	struct sun_sas_port	*tgt_port = NULL;
	struct sun_sas_port	*last_tgt_port = NULL;
	struct ScsiEntryList	*scsi_info = NULL;
	struct ScsiEntryList	*last_scsi_info = NULL;
	struct phy_info		*phy_ptr = NULL;
	struct phy_info		*last_phy = NULL;

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
		hba_port->first_attached_port = NULL;

		phy_ptr = hba_port->first_phy;
		while (phy_ptr != NULL) {
			last_phy = phy_ptr;
			phy_ptr = phy_ptr->next;
			free(last_phy);
		}
		hba_port->first_phy = NULL;

		last_hba_port = hba_port;
		hba_port = hba_port->next;
		free(last_hba_port->port_attributes.\
		    PortSpecificAttribute.SASPort);
		free(last_hba_port);
	}

	hba_ptr->first_port = NULL;
}

/*
 * Internal routine for adding an HBA port
 */
static HBA_STATUS
add_hba_port_info(di_node_t portNode, struct sun_sas_hba *hba_ptr, int protocol)
{
	const char		    ROUTINE[] = "add_hba_port_info";
	struct sun_sas_port	    *port_ptr;
	char			    *portDevpath;
	int			    *propIntData;
	char			    *propStringData;
	uint64_t		    tmpAddr;
	char			    *charptr, cntlLink[MAXPATHLEN] = {'\0'};
	int			    rval;
	di_node_t		    branchNode;
	uint_t			    state = HBA_PORTSTATE_UNKNOWN;

	if (hba_ptr == NULL) {
		log(LOG_DEBUG, ROUTINE,
		    "Sun_sas handle ptr set to NULL.");
		return (HBA_STATUS_ERROR_ARG);
	}

	if ((port_ptr = (struct sun_sas_port *)calloc(1,
	    sizeof (struct sun_sas_port))) == NULL) {
		OUT_OF_MEMORY(ROUTINE);
		return (HBA_STATUS_ERROR);
	}

	if ((port_ptr->port_attributes.PortSpecificAttribute.SASPort =
	    (struct SMHBA_SAS_Port *)calloc(1, sizeof (struct SMHBA_SAS_Port)))
	    == NULL) {
		OUT_OF_MEMORY(ROUTINE);
		return (HBA_STATUS_ERROR);
	}

	if ((portDevpath = di_devfs_path(portNode)) == NULL) {
		log(LOG_DEBUG, ROUTINE,
		    "Unable to get device path from HBA Port Node.");
		S_FREE(port_ptr->port_attributes.PortSpecificAttribute.SASPort);
		S_FREE(port_ptr);
		return (HBA_STATUS_ERROR);
	}

	/*
	 * Let's take a branch snap shot for pulling attributes.
	 * The attribute change doesn't invalidate devinfo cache snapshot.
	 * Phy info prop and num-phys can be obsolate when the same hba
	 * connected to the same expander(SIM) thus phy numbers are increased.
	 * Also the phy number may get decreased when a connection is removed
	 * while the iport still exist through another connection.
	 */
	branchNode = di_init(portDevpath, DINFOPROP);
	if (branchNode == DI_NODE_NIL) {
		/* something is wrong here. */
		di_fini(branchNode);
		log(LOG_DEBUG, ROUTINE,
		    "Unable to take devinfoi branch snapshot on HBA port \"%s\""
		    " due to %s", portDevpath, strerror(errno));
		S_FREE(port_ptr->port_attributes.PortSpecificAttribute.SASPort);
		S_FREE(port_ptr);
		return (HBA_STATUS_ERROR);
	}

	state = di_state(portNode);
	if (((state & DI_DRIVER_DETACHED) == DI_DRIVER_DETACHED) ||
	    ((state & DI_DEVICE_OFFLINE) == DI_DEVICE_OFFLINE)) {
		log(LOG_DEBUG, ROUTINE,
		    "HBA port node %s is either OFFLINE or DETACHED",
		    portDevpath);
		port_ptr->port_attributes.PortState = HBA_PORTSTATE_OFFLINE;
	} else {
		port_ptr->port_attributes.PortState = HBA_PORTSTATE_ONLINE;
	}

	port_ptr->port_attributes.PortType = HBA_PORTTYPE_SASDEVICE;

	(void) strlcpy(port_ptr->device_path, portDevpath, MAXPATHLEN + 1);

	if (lookupControllerLink(portDevpath, (char *)cntlLink) ==
	    HBA_STATUS_OK) {
		(void) strlcpy(port_ptr->port_attributes.OSDeviceName, cntlLink,
		    sizeof (port_ptr->port_attributes.OSDeviceName));
		if ((charptr = strrchr(cntlLink, '/')) != NULL) {
			charptr++;
		}
		if (charptr[0] ==  'c') {
			port_ptr->cntlNumber = atoi(++charptr);
		} else {
			port_ptr->cntlNumber = -1;
		}
	} else {
		(void) snprintf(port_ptr->port_attributes.OSDeviceName,
		    sizeof (port_ptr->port_attributes.OSDeviceName),
		    "%s%s%s", DEVICES_DIR, portDevpath, SCSI_SUFFIX);
	}

	di_devfs_path_free(portDevpath);

	port_ptr->port_attributes.PortSpecificAttribute.
	    SASPort->PortProtocol = protocol;

	rval = di_prop_lookup_strings(DDI_DEV_T_ANY, branchNode,
	    "initiator-port", &propStringData);
	if (rval < 0) {
		log(LOG_DEBUG, ROUTINE,
		    "Unable to get initiator-port from HBA port node %s.",
		    port_ptr->port_attributes.OSDeviceName);
		di_fini(branchNode);
		S_FREE(port_ptr->port_attributes.PortSpecificAttribute.SASPort);
		S_FREE(port_ptr);
		return (HBA_STATUS_ERROR);
	} else {
		for (charptr = propStringData; *charptr != '\0'; charptr++) {
			if (isxdigit(*charptr)) {
				break;
			}
		}
		if (*charptr != '\0') {
			tmpAddr = htonll(strtoll(charptr, NULL, 16));
			(void) memcpy(port_ptr->port_attributes.
			    PortSpecificAttribute.SASPort->LocalSASAddress.wwn,
			    &tmpAddr, 8);
		} else {
			log(LOG_DEBUG, ROUTINE,
			    "No proper intiator-port prop value on HBA port %s",
			    port_ptr->port_attributes.OSDeviceName);
		}
	}

	rval = di_prop_lookup_strings(DDI_DEV_T_ANY, branchNode,
	    "attached-port", &propStringData);
	if (rval < 0) {
		log(LOG_DEBUG, ROUTINE,
		    "Unable to get attached-port from HBA port node %s.",
		    port_ptr->port_attributes.OSDeviceName);
		di_fini(branchNode);
		S_FREE(port_ptr->port_attributes.PortSpecificAttribute.SASPort);
		S_FREE(port_ptr);
		return (HBA_STATUS_ERROR);
	} else {
		for (charptr = propStringData; *charptr != '\0'; charptr++) {
			if (isxdigit(*charptr)) {
				break;
			}
		}
		if (*charptr != '\0') {
			tmpAddr = htonll(strtoll(charptr, NULL, 16));
			(void) memcpy(port_ptr->port_attributes.
			    PortSpecificAttribute.SASPort->
			    AttachedSASAddress.wwn, &tmpAddr, 8);
		} else {
			/* continue even if the attached port is NULL. */
			log(LOG_DEBUG, ROUTINE,
			    "No proper attached-port prop value: "
			    "HBA port Local SAS Address(%016llx)",
			    wwnConversion(port_ptr->port_attributes.
			    PortSpecificAttribute.
			    SASPort->LocalSASAddress.wwn));
		}
	}

	rval = di_prop_lookup_ints(DDI_DEV_T_ANY, branchNode,
	    "num-phys", &propIntData);
	if (rval < 0) {
		log(LOG_DEBUG, ROUTINE,
		    "Unable to get NumberofPhys from HBA port %s.",
		    port_ptr->port_attributes.OSDeviceName);
		di_fini(branchNode);
		S_FREE(port_ptr->port_attributes.PortSpecificAttribute.SASPort);
		S_FREE(port_ptr);
		return (HBA_STATUS_ERROR);
	} else {
		port_ptr->port_attributes.PortSpecificAttribute.\
		    SASPort->NumberofPhys = *propIntData;
	}

	if (port_ptr->port_attributes.PortSpecificAttribute.\
	    SASPort->NumberofPhys > 0) {
		if (get_phy_info(branchNode, port_ptr) != HBA_STATUS_OK) {
			log(LOG_DEBUG, ROUTINE,
			    "Failed to get phy info on HBA port %s.",
			    port_ptr->port_attributes.OSDeviceName);
			di_fini(branchNode);
			S_FREE(port_ptr->port_attributes.
			    PortSpecificAttribute.SASPort);
			S_FREE(port_ptr);
			return (HBA_STATUS_ERROR);
		}
	}

	/* now done with prop checking. remove branchNode. */
	di_fini(branchNode);

	/* Construct discovered target port. */
	if (devtree_attached_devices(portNode, port_ptr) != HBA_STATUS_OK) {
		log(LOG_DEBUG, ROUTINE,
		    "Failed to get attached device info HBA port %s.",
		    port_ptr->port_attributes.OSDeviceName);
		S_FREE(port_ptr->port_attributes.PortSpecificAttribute.SASPort);
		S_FREE(port_ptr);
		return (HBA_STATUS_ERROR);
	}

	fillDomainPortWWN(port_ptr);

	/* add new port onto hba handle list */
	if (hba_ptr->first_port == NULL) {
		port_ptr->index = 0;
		hba_ptr->first_port = port_ptr;
	} else {
		port_ptr->index = hba_ptr->first_port->index + 1;
		port_ptr->next = hba_ptr->first_port;
		hba_ptr->first_port = port_ptr;
	}

	return (HBA_STATUS_OK);
}

HBA_STATUS
refresh_hba(di_node_t hbaNode, struct sun_sas_hba *hba_ptr)
{
	const char	ROUTINE[] = "refresh_hba";
	di_node_t	portNode;
	int		protocol = 0;
	int		*propIntData;

	/*
	 * clean up existing hba port, discovered target, phy info.
	 * leave open handles intact.
	 */
	free_hba_port(hba_ptr);

	if ((portNode = di_child_node(hbaNode)) == NULL) {
		log(LOG_DEBUG, ROUTINE,
		    "HBA node doesn't have iport child.");
		return (HBA_STATUS_ERROR);
	}

	if ((di_prop_lookup_ints(DDI_DEV_T_ANY, hbaNode,
	    "supported-protocol", &propIntData)) == -1) {
		log(LOG_DEBUG, ROUTINE,
		    "Unable to get supported-protocol from HBA node.");
	} else {
		protocol = *propIntData;
	}

	while (portNode != DI_NODE_NIL) {
		if (di_prop_lookup_ints(DDI_DEV_T_ANY, portNode,
		    "virtual-port", &propIntData) >= 0) {
			if (*propIntData) {
				/* ignore a virtual port. */
				portNode = di_sibling_node(portNode);
				continue;
			}
		}
		if (add_hba_port_info(portNode, hba_ptr, protocol)
		    == HBA_STATUS_ERROR) {
			S_FREE(hba_ptr->first_port);
			S_FREE(hba_ptr);
			return (HBA_STATUS_ERROR);
		}
		portNode = di_sibling_node(portNode);
	}

	return (HBA_STATUS_OK);
}

/*
 * Discover information for one HBA in the device tree.
 * The di_node_t argument should be a node with smhba-supported prop set
 * to true.
 * Without iport support, the devinfo node will represent one port hba.
 * This routine assumes the locks have been taken.
 */
HBA_STATUS
devtree_get_one_hba(di_node_t hbaNode)
{
	const char		ROUTINE[] = "devtree_get_one_hba";
	char			*propdata = NULL;
	int			*propIntData = NULL;
	struct sun_sas_hba	*new_hba, *hba_ptr;
	char			*hbaDevpath, *hba_driver;
	int			protocol = 0;
	di_node_t		portNode;
	int			hba_instance = -1;

	hba_instance = di_instance(hbaNode);
	if (hba_instance == -1) {
		log(LOG_DEBUG, ROUTINE,
		    "portNode has instance of -1");
		return (DI_WALK_CONTINUE);
	}

	if ((hbaDevpath = di_devfs_path(hbaNode)) == NULL) {
		log(LOG_DEBUG, ROUTINE, "Unable to get "
		    "device path from hbaNode");
		return (HBA_STATUS_ERROR);
	}

	/* check to see if this is a repeat HBA */
	if (global_hba_head) {
		for (hba_ptr = global_hba_head;
		    hba_ptr != NULL;
		    hba_ptr = hba_ptr->next) {
			if ((strncmp(hba_ptr->device_path, hbaDevpath,
			    strlen(hbaDevpath))) == 0) {
				if (refresh_hba(hbaNode, hba_ptr) !=
				    HBA_STATUS_OK) {
					log(LOG_DEBUG, ROUTINE, "Refresh failed"
					    " on hbaNode %s", hbaDevpath);
				}
				di_devfs_path_free(hbaDevpath);
				return (HBA_STATUS_OK);
			}
		}
	}

	/* this is a new hba */
	if ((new_hba = (struct sun_sas_hba *)calloc(1,
	    sizeof (struct sun_sas_hba))) == NULL) {
		OUT_OF_MEMORY(ROUTINE);
		di_devfs_path_free(hbaDevpath);
		return (HBA_STATUS_ERROR);
	}

	(void) strlcpy(new_hba->device_path, hbaDevpath,
	    sizeof (new_hba->device_path));
	di_devfs_path_free(hbaDevpath);

	(void) snprintf(new_hba->adapter_attributes.HBASymbolicName,
	    sizeof (new_hba->adapter_attributes.HBASymbolicName),
	    "%s%s", DEVICES_DIR, new_hba->device_path);

	/* Manufacturer */
	if ((di_prop_lookup_strings(DDI_DEV_T_ANY, hbaNode,
	    "Manufacturer", (char **)&propdata)) == -1) {
		(void) strlcpy(new_hba->adapter_attributes.Manufacturer,
		    SUN_MICROSYSTEMS,
		    sizeof (new_hba->adapter_attributes.Manufacturer));
	} else {
		(void) strlcpy(new_hba->adapter_attributes.Manufacturer,
		    propdata,
		    sizeof (new_hba->adapter_attributes.Manufacturer));
	}

	/* SerialNumber */
	if ((di_prop_lookup_strings(DDI_DEV_T_ANY, hbaNode,
	    "SerialNumber", (char **)&propdata)) == -1) {
		new_hba->adapter_attributes.SerialNumber[0] = '\0';
	} else {
		(void) strlcpy(new_hba->adapter_attributes.SerialNumber,
		    propdata,
		    sizeof (new_hba->adapter_attributes.SerialNumber));
	}

	/* Model */
	if ((di_prop_lookup_strings(DDI_DEV_T_ANY, hbaNode,
	    "ModelName", (char **)&propdata)) == -1) {
		new_hba->adapter_attributes.Model[0] = '\0';
	} else {
		(void) strlcpy(new_hba->adapter_attributes.Model,
		    propdata,
		    sizeof (new_hba->adapter_attributes.Model));
	}

	/* FirmwareVersion */
	if ((di_prop_lookup_strings(DDI_DEV_T_ANY, hbaNode,
	    "firmware-version", (char **)&propdata)) == -1) {
		log(LOG_DEBUG, ROUTINE,
		    "Property \"%s\" not found for device \"%s\"",
		    "firmware-version", new_hba->device_path);
	} else {
		(void) strlcpy(new_hba->adapter_attributes.FirmwareVersion,
		    propdata,
		    sizeof (new_hba->adapter_attributes.FirmwareVersion));
	}

	/* HardwareVersion */
	if ((di_prop_lookup_strings(DDI_DEV_T_ANY, hbaNode,
	    "hardware-version", (char **)&propdata)) == -1) {
		log(LOG_DEBUG, ROUTINE,
		    "Property \"%s\" not found for device \"%s\"",
		    "hardware-version", new_hba->device_path);
	} else {
		(void) strlcpy(new_hba->adapter_attributes.HardwareVersion,
		    propdata,
		    sizeof (new_hba->adapter_attributes.HardwareVersion));
	}

	/* DriverVersion */
	if ((di_prop_lookup_strings(DDI_DEV_T_ANY, hbaNode,
	    "driver-version", (char **)&propdata)) == -1) {
		log(LOG_DEBUG, ROUTINE,
		    "Property \"%s\" not found for device \"%s\"",
		    "driver-version", new_hba->device_path);
	} else {
		(void) strlcpy(new_hba->adapter_attributes.DriverVersion,
		    propdata,
		    sizeof (new_hba->adapter_attributes.DriverVersion));
	}

	if ((di_prop_lookup_ints(DDI_DEV_T_ANY, hbaNode,
	    "supported-protocol", &propIntData)) == -1) {
		log(LOG_DEBUG, ROUTINE,
		    "Unable to get supported-protocol from HBA node.");
	} else {
		protocol = *propIntData;
	}

	/* We don't use these */
	new_hba->adapter_attributes.OptionROMVersion[0] = '\0';
	new_hba->adapter_attributes.RedundantOptionROMVersion[0] = '\0';
	new_hba->adapter_attributes.RedundantFirmwareVersion[0] = '\0';
	new_hba->adapter_attributes.VendorSpecificID = 0;

	if ((hba_driver = di_driver_name(hbaNode)) != NULL) {
		(void) strlcpy(new_hba->adapter_attributes.DriverName,
		    hba_driver,
		    sizeof (new_hba->adapter_attributes.DriverName));
	} else {
		log(LOG_DEBUG, ROUTINE,
		    "HBA driver name not found for device \"%s\"",
		    new_hba->device_path);
	}

	/*
	 * Name the adapter: like SUNW-pmcs-1
	 * Using di_instance number as the suffix for the name for persistent
	 * among rebooting.
	 */
	(void) snprintf(new_hba->handle_name, HANDLE_NAME_LENGTH, "%s-%s-%d",
	    "SUNW", new_hba->adapter_attributes.DriverName, hba_instance);

	if ((portNode = di_child_node(hbaNode)) == NULL) {
		log(LOG_DEBUG, ROUTINE,
		    "HBA driver doesn't have iport child. \"%s\"",
		    new_hba->device_path);
		/* continue on with an hba without any port. */
		new_hba->index = hba_count++;

		/*
		 * add newly created handle into global_hba_head list
		 */
		if (global_hba_head != NULL) {
			/*
			 * Make sure to move the open_handles list to back to
			 * the head if it's there (for refresh scenario)
			 */
			if (global_hba_head->open_handles) {
				new_hba->open_handles =
				    global_hba_head->open_handles;
				global_hba_head->open_handles = NULL;
			}
			/* Now bump the new one to the head of the list */
			new_hba->next = global_hba_head;
			global_hba_head = new_hba;
		} else {
			global_hba_head = new_hba;
		}
		return (HBA_STATUS_OK);
	}

	while (portNode != DI_NODE_NIL) {
		if (di_prop_lookup_ints(DDI_DEV_T_ANY, portNode,
		    "virtual-port", &propIntData) >= 0) {
			if (*propIntData) {
				/* ignore a virtual port. */
				portNode = di_sibling_node(portNode);
				continue;
			}
		}
		if (add_hba_port_info(portNode, new_hba, protocol)
		    == HBA_STATUS_ERROR) {
			S_FREE(new_hba->first_port);
			S_FREE(new_hba);
			return (HBA_STATUS_ERROR);
		}
		portNode = di_sibling_node(portNode);
	}

	new_hba->index = hba_count++;

	/*
	 * add newly created handle into global_hba_head list
	 */
	if (global_hba_head != NULL) {
		/*
		 * Make sure to move the open_handles list to back to the
		 * head if it's there (for refresh scenario)
		 */
		if (global_hba_head->open_handles) {
			new_hba->open_handles = global_hba_head->open_handles;
			global_hba_head->open_handles = NULL;
		}
		/* Now bump the new one to the head of the list */
		new_hba->next = global_hba_head;
		global_hba_head = new_hba;
	} else {
		global_hba_head = new_hba;
	}

	return (HBA_STATUS_OK);
}

/*
 * Discover information for all HBAs found on the system.
 * The di_node_t argument should be the root of the device tree.
 * This routine assumes the locks have been taken
 */
static int
lookup_smhba_sas_hba(di_node_t node, void *arg)
{
	const char ROUTINE[] = "lookup_smhba_sas_hba";
	int *propData, rval;
	walkarg_t *wa = (walkarg_t *)arg;

	/* Skip stub(instance -1) nodes */
	if (IS_STUB_NODE(node)) {
		log(LOG_DEBUG, ROUTINE, "Walk continue");
		return (DI_WALK_CONTINUE);
	}

	rval = di_prop_lookup_ints(DDI_DEV_T_ANY, node,
	    "sm-hba-supported", &propData);
	if (rval >= 0) {
		if (*propData) {
			/* add the hba to the hba list */
			if (devtree_get_one_hba(node) != HBA_STATUS_OK) {
				*(wa->flag) = B_TRUE;
			}
			/* Found a node. No need to walk the child. */
			log(LOG_DEBUG, ROUTINE, "Walk prunechild");
			return (DI_WALK_PRUNECHILD);
		}
	}

	return (DI_WALK_CONTINUE);
}

/*
 * Discover information for all HBAs found on the system.
 * The di_node_t argument should be the root of the device tree.
 * This routine assumes the locks have been taken
 */
HBA_STATUS
devtree_get_all_hbas(di_node_t root)
{
	const char	ROUTINE[] = "devtree_get_all_hbas";
	int		rv, ret = HBA_STATUS_ERROR;
	walkarg_t	wa;

	wa.devpath = NULL;
	if ((wa.flag = (boolean_t *)calloc(1,
	    sizeof (boolean_t))) == NULL) {
		OUT_OF_MEMORY(ROUTINE);
		return (HBA_STATUS_ERROR);
	}
	*wa.flag = B_FALSE;
	rv = di_walk_node(root, DI_WALK_SIBFIRST, &wa, lookup_smhba_sas_hba);

	if (rv == 0) {
		/*
		 * Now determine what status code to return, taking
		 * partial failure scenarios into consideration.
		 *
		 * If we have at least one working HBA, then we return an
		 * OK status.  If we have no good HBAs, but at least one
		 * failed HBA, we return an ERROR status.  If we have
		 * no HBAs and no failures, we return OK.
		 */
		if (global_hba_head) {
			/*
			 * We've got at least one HBA and possibly some
			 * failures.
			 */
			ret = HBA_STATUS_OK;
		} else if (*(wa.flag)) {
			/* We have no HBAs but have failures */
			ret = HBA_STATUS_ERROR;
		} else {
			/* We have no HBAs and no failures */
			ret = HBA_STATUS_OK;
		}
	}


	S_FREE(wa.flag);

	if (ret == HBA_STATUS_OK)
		(void) registerSysevent();

	return (ret);
}
