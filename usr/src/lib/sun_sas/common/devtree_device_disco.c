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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

#include	<sun_sas.h>
#include	<sys/types.h>
#include	<netinet/in.h>
#include	<inttypes.h>
#include	<ctype.h>
#include	<sys/scsi/scsi_address.h>
#include	<libdevid.h>

/*
 * Get the preferred minor node for the given path.
 * ":n" for tapes, ":c,raw" for disks,
 * and ":0" for enclosures.
 */
static void
get_minor(char *devpath, char *minor)
{
	const char	ROUTINE[] = "get_minor";
	char	fullpath[MAXPATHLEN];
	int	fd;

	if ((strstr(devpath, "/st@")) || (strstr(devpath, "/tape@"))) {
		(void) strcpy(minor, ":n");
	} else if (strstr(devpath, "/smp@")) {
		(void) strcpy(minor, ":smp");
	} else if ((strstr(devpath, "/ssd@")) || (strstr(devpath, "/sd@")) ||
	    (strstr(devpath, "/disk@"))) {
		(void) strcpy(minor, ":c,raw");
	} else if ((strstr(devpath, "/ses@")) || (strstr(devpath,
	    "/enclosure@"))) {
		(void) snprintf(fullpath, MAXPATHLEN, "%s%s%s", DEVICES_DIR,
		    devpath, ":0");
		/* reset errno to 0 */
		errno = 0;
		if ((fd = open(fullpath, O_RDONLY)) == -1) {
			/*
			 * :0 minor doesn't exist. assume bound to sgen driver
			 * and :ses minor exist.
			 */
			if (errno == ENOENT) {
				(void) strcpy(minor, ":ses");
			}
		} else {
			(void) strcpy(minor, ":0");
			(void) close(fd);
		}
	} else {
		log(LOG_DEBUG, ROUTINE, "Unrecognized target (%s)",
		    devpath);
		minor[0] = '\0';
	}

}

/*
 * Free the attached port allocation.
 */
static void
free_attached_port(struct sun_sas_port *port_ptr)
{
	struct sun_sas_port 	*tgt_port, *last_tgt_port;
	struct ScsiEntryList	*scsi_info = NULL, *last_scsi_info = NULL;

	tgt_port = port_ptr->first_attached_port;
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

	port_ptr->first_attached_port = NULL;
	port_ptr->port_attributes.PortSpecificAttribute.\
	    SASPort->NumberofDiscoveredPorts = 0;
}

/*
 * Fill domainPortWWN.
 * should be called after completing discovered port discovery.
 */
void
fillDomainPortWWN(struct sun_sas_port *port_ptr)
{
	const char    ROUTINE[] = "fillDomainPortWWN";
	struct sun_sas_port *disco_port_ptr;
	struct phy_info *phy_ptr;
	uint64_t    domainPort = 0;
	struct ScsiEntryList	    *mapping_ptr;

	for (disco_port_ptr = port_ptr->first_attached_port;
	    disco_port_ptr != NULL; disco_port_ptr = disco_port_ptr->next) {
		if (disco_port_ptr->port_attributes.PortType ==
		    HBA_PORTTYPE_SASEXPANDER &&
		    wwnConversion(disco_port_ptr->port_attributes.
		    PortSpecificAttribute.SASPort->
		    AttachedSASAddress.wwn) ==
		    wwnConversion(port_ptr->port_attributes.
		    PortSpecificAttribute.SASPort->
		    LocalSASAddress.wwn)) {
			(void) memcpy(&domainPort,
			    disco_port_ptr->port_attributes.
			    PortSpecificAttribute.
			    SASPort->LocalSASAddress.wwn, 8);
			break;
		}
	}

	if (domainPort == 0) {
		if (port_ptr->first_attached_port) {
			/*
			 * there is no expander device attached on an HBA port
			 * domainPortWWN should not stay to 0 since multiple
			 * hba ports can have the same LocalSASAddres within
			 * the same HBA.
			 * Set the SAS address of direct attached target.
			 */
			if (wwnConversion(port_ptr->port_attributes.
			    PortSpecificAttribute.SASPort->
			    LocalSASAddress.wwn) ==
			    wwnConversion(port_ptr->first_attached_port->
			    port_attributes.PortSpecificAttribute.
			    SASPort->AttachedSASAddress.wwn)) {
				(void) memcpy(&domainPort,
				    port_ptr->first_attached_port->
				    port_attributes.PortSpecificAttribute.
				    SASPort->LocalSASAddress.wwn, 8);
			} else {
				/*
				 * SAS address is not upstream connected.
				 * domainPortWWN stays as 0.
				 */
				log(LOG_DEBUG, ROUTINE,
				    "DomainPortWWN is not set. "
				    "Device(s) are visible on the HBA port "
				    "but there is no expander or directly "
				    "attached port with matching upsteam "
				    "attached SAS address for "
				    "HBA port (Local SAS Address: %016llx).",
				    wwnConversion(port_ptr->port_attributes.
				    PortSpecificAttribute.
				    SASPort->LocalSASAddress.wwn));
				return;
			}
		} else {
			/*
			 * There existss an iport without properly configured
			 * child smp ndoes or  child node or pathinfo.
			 * domainPortWWN stays as 0.
			 */
			log(LOG_DEBUG, ROUTINE,
			    "DomainPortWWN is not set.  No properly "
			    "configured smp or directly attached port "
			    "found on HBA port(Local SAS Address: %016llx).",
			    wwnConversion(port_ptr->port_attributes.
			    PortSpecificAttribute.
			    SASPort->LocalSASAddress.wwn));
			return;
		}
	}

	/* fill up phy info */
	for (phy_ptr = port_ptr->first_phy; phy_ptr != NULL;
	    phy_ptr = phy_ptr->next) {
		(void) memcpy(phy_ptr->phy.domainPortWWN.wwn, &domainPort, 8);
	}

	/* fill up target mapping */
	for (disco_port_ptr = port_ptr->first_attached_port;
	    disco_port_ptr != NULL; disco_port_ptr = disco_port_ptr->next) {
		for (mapping_ptr = disco_port_ptr->scsiInfo;
		    mapping_ptr != NULL;
		    mapping_ptr = mapping_ptr->next) {
			(void) memcpy(mapping_ptr->entry.PortLun.
			    domainPortWWN.wwn, &domainPort, 8);
		}
	}
}

/*
 * Finds attached device(target) from devinfo node.
 */
static HBA_STATUS
get_attached_devices_info(di_node_t node, struct sun_sas_port *port_ptr)
{
	const char		    ROUTINE[] = "get_attached_devices_info";
	char			    *propStringData = NULL;
	int			    *propIntData = NULL;
	int64_t			    *propInt64Data = NULL;
	scsi_lun_t		    samLun;
	ddi_devid_t		    devid;
	char			    *guidStr;
	char			    *unit_address;
	char			    *charptr;
	char			    *devpath, link[MAXNAMELEN];
	char			    fullpath[MAXPATHLEN+1];
	char			    minorname[MAXNAMELEN+1];
	struct ScsiEntryList	    *mapping_ptr;
	HBA_WWN			    SASAddress, AttachedSASAddress;
	struct sun_sas_port	    *disco_port_ptr;
	uint_t			    state = 0;
	int			    portfound, rval, size;
	int			    port_state = HBA_PORTSTATE_ONLINE;
	uint64_t		    tmpAddr;

	if (port_ptr == NULL) {
		log(LOG_DEBUG, ROUTINE, "NULL port_ptr argument");
		return (HBA_STATUS_ERROR);
	}

	if ((devpath = di_devfs_path(node)) == NULL) {
		log(LOG_DEBUG, ROUTINE,
		    "Device in device tree has no path. Skipping.");
		return (HBA_STATUS_ERROR);
	}

	if ((di_instance(node) == -1) || di_retired(node)) {
		log(LOG_DEBUG, ROUTINE,
		    "dev node (%s) returned instance of -1 or is retired. "
		    " Skipping.", devpath);
		di_devfs_path_free(devpath);
		return (HBA_STATUS_OK);
	}
	state = di_state(node);
	/* when node is not attached and online, set the state to offline. */
	if (((state & DI_DRIVER_DETACHED) == DI_DRIVER_DETACHED) ||
	    ((state & DI_DEVICE_OFFLINE) == DI_DEVICE_OFFLINE)) {
		log(LOG_DEBUG, ROUTINE,
		    "dev node (%s) is either OFFLINE or DETACHED",
		    devpath);
		port_state = HBA_PORTSTATE_OFFLINE;
	}

	/* add the "/devices" in the begining at the end */
	(void) snprintf(fullpath, sizeof (fullpath), "%s%s",
	    DEVICES_DIR, devpath);

	(void) memset(&SASAddress, 0, sizeof (SASAddress));
	if ((unit_address = di_bus_addr(node)) != NULL) {
		if ((charptr = strchr(unit_address, ',')) != NULL) {
			*charptr = '\0';
		}
		for (charptr = unit_address; *charptr != '\0'; charptr++) {
			if (isxdigit(*charptr)) {
				break;
			}
		}
		if (*charptr != '\0') {
			tmpAddr = htonll(strtoll(charptr, NULL, 16));
			(void) memcpy(&SASAddress.wwn[0], &tmpAddr, 8);
		} else {
			log(LOG_DEBUG, ROUTINE,
			    "No proper target port info on unit address of %s",
			    fullpath);
			di_devfs_path_free(devpath);
			return (HBA_STATUS_ERROR);
		}
	} else {
		log(LOG_DEBUG, ROUTINE,
		    "Fail to get unit address of %s.",
		    fullpath);
		di_devfs_path_free(devpath);
		return (HBA_STATUS_ERROR);
	}

	(void) memset(&AttachedSASAddress, 0, sizeof (AttachedSASAddress));
	if (di_prop_lookup_strings(DDI_DEV_T_ANY, node, "attached-port",
	    &propStringData) != -1) {
		for (charptr = propStringData; *charptr != '\0'; charptr++) {
			if (isxdigit(*charptr)) {
				break;
			}
		}
		if (*charptr != '\0') {
			tmpAddr = htonll(strtoll(charptr, NULL, 16));
			(void) memcpy(AttachedSASAddress.wwn, &tmpAddr, 8);
			/* check the attached address of hba port. */
			if (memcmp(port_ptr->port_attributes.
			    PortSpecificAttribute.SASPort->LocalSASAddress.wwn,
			    &tmpAddr, 8) == 0) {
				/*
				 * When attached-port is set from iport
				 * attached-port prop, we do the cross check
				 * with device's own SAS address.
				 *
				 * If not set, we store device's own SAS
				 * address to iport attached SAS address.
				 */
				if (wwnConversion(port_ptr->port_attributes.
				    PortSpecificAttribute.SASPort->
				    AttachedSASAddress.wwn)) {
					/* verify the Attaached SAS Addr. */
					if (memcmp(port_ptr->port_attributes.
					    PortSpecificAttribute.SASPort->
					    AttachedSASAddress.wwn,
					    SASAddress.wwn, 8) != 0) {
				/* indentation move begin. */
				log(LOG_DEBUG, ROUTINE,
				    "iport attached-port(%016llx) do not"
				    " match with level 1 Local"
				    " SAS address(%016llx).",
				    wwnConversion(port_ptr->port_attributes.
				    PortSpecificAttribute.
				    SASPort->AttachedSASAddress.wwn),
				    wwnConversion(SASAddress.wwn));
				di_devfs_path_free(devpath);
				free_attached_port(port_ptr);
				return (HBA_STATUS_ERROR);
				/* indentation move ends. */
					}
				} else {
					(void) memcpy(port_ptr->port_attributes.
					    PortSpecificAttribute.
					    SASPort->AttachedSASAddress.wwn,
					    &SASAddress.wwn[0], 8);
				}
			}
		} else {
			log(LOG_DEBUG, ROUTINE,
			    "No proper attached SAS address value on device %s",
			    fullpath);
			di_devfs_path_free(devpath);
			free_attached_port(port_ptr);
			return (HBA_STATUS_ERROR);
		}
	} else {
		log(LOG_DEBUG, ROUTINE,
		    "Property AttachedSASAddress not found for device \"%s\"",
		    fullpath);
		di_devfs_path_free(devpath);
		free_attached_port(port_ptr);
		return (HBA_STATUS_ERROR);
	}

	/*
	 * walk the disco list to make sure that there isn't a matching
	 * port and node wwn or a matching device path
	 */
	portfound = 0;
	for (disco_port_ptr = port_ptr->first_attached_port;
	    disco_port_ptr != NULL;
	    disco_port_ptr = disco_port_ptr->next) {
		if ((disco_port_ptr->port_attributes.PortState !=
		    HBA_PORTSTATE_ERROR) && (memcmp(disco_port_ptr->
		    port_attributes.PortSpecificAttribute.
		    SASPort->LocalSASAddress.wwn, SASAddress.wwn, 8) == 0)) {
			/*
			 * found matching disco_port
			 * look for matching device path
			 */
			portfound = 1;
			for (mapping_ptr = disco_port_ptr->scsiInfo;
			    mapping_ptr != NULL;
			    mapping_ptr = mapping_ptr->next) {
				if (strstr(mapping_ptr-> entry.ScsiId.
				    OSDeviceName, devpath) != 0) {
					log(LOG_DEBUG, ROUTINE,
					    "Found an already discovered "
					    "device %s.", fullpath);
					di_devfs_path_free(devpath);
					return (HBA_STATUS_OK);
				}
			}
			if (portfound == 1) {
				break;
			}
		}
	}

	if (portfound == 0) {
		/*
		 * there are no matching SAS address.
		 * this must be a new device
		 */
		if ((disco_port_ptr = (struct sun_sas_port *)calloc(1,
		    sizeof (struct sun_sas_port))) == NULL)  {
			OUT_OF_MEMORY(ROUTINE);
			di_devfs_path_free(devpath);
			free_attached_port(port_ptr);
			return (HBA_STATUS_ERROR);
		}

		if ((disco_port_ptr->port_attributes.PortSpecificAttribute.\
		    SASPort = (struct SMHBA_SAS_Port *)calloc(1,
		    sizeof (struct SMHBA_SAS_Port))) == NULL) {
			OUT_OF_MEMORY("add_hba_port_info");
			di_devfs_path_free(devpath);
			free_attached_port(port_ptr);
			return (HBA_STATUS_ERROR);
		}

		(void) memcpy(disco_port_ptr->port_attributes.
		    PortSpecificAttribute.SASPort->LocalSASAddress.wwn,
		    SASAddress.wwn, 8);
		(void) memcpy(disco_port_ptr->port_attributes.
		    PortSpecificAttribute.SASPort->AttachedSASAddress.wwn,
		    AttachedSASAddress.wwn, 8);

		/* Default to unknown until we figure out otherwise */
		rval = di_prop_lookup_strings(DDI_DEV_T_ANY, node,
		    "variant", &propStringData);
		if (rval < 0) {
			/* check if it is SMP target */
			charptr = di_driver_name(node);
			if (charptr != NULL && (strncmp(charptr, "smp",
			    strlen(charptr)) == 0)) {
				disco_port_ptr->port_attributes.PortType =
				    HBA_PORTTYPE_SASEXPANDER;
				disco_port_ptr->port_attributes.
				    PortSpecificAttribute.
				    SASPort->PortProtocol =
				    HBA_SASPORTPROTOCOL_SMP;
				if (lookupSMPLink(devpath, (char *)link) ==
				    HBA_STATUS_OK) {
		/* indentation changed here. */
		(void) strlcpy(disco_port_ptr->port_attributes.
		    OSDeviceName, link,
		    sizeof (disco_port_ptr->port_attributes.OSDeviceName));
		/* indentation change ends here. */
				} else {
		/* indentation changed here. */
		get_minor(devpath, minorname);
		(void) snprintf(fullpath, sizeof (fullpath), "%s%s%s",
		    DEVICES_DIR, devpath, minorname);
		(void) strlcpy(disco_port_ptr->port_attributes.
		    OSDeviceName, fullpath,
		    sizeof (disco_port_ptr->port_attributes.OSDeviceName));
		/* indentation change ends here. */
				}
			} else {
				disco_port_ptr->port_attributes.PortType =
				    HBA_PORTTYPE_SASDEVICE;
				disco_port_ptr->port_attributes.\
				    PortSpecificAttribute.\
				    SASPort->PortProtocol =
				    HBA_SASPORTPROTOCOL_SSP;
			}
		} else {
			if ((strcmp(propStringData, "sata") == 0) ||
			    (strcmp(propStringData, "atapi") == 0)) {
				disco_port_ptr->port_attributes.PortType =
				    HBA_PORTTYPE_SATADEVICE;
				disco_port_ptr->port_attributes.\
				    PortSpecificAttribute.SASPort->PortProtocol
				    = HBA_SASPORTPROTOCOL_SATA;
			} else {
				log(LOG_DEBUG, ROUTINE,
				    "Unexpected variant prop value %s found on",
				    " device %s", propStringData, fullpath);
				/*
				 * Port type will be 0
				 * which is not valid type.
				 */
			}
		}

		/* SMP device was handled already */
		if (disco_port_ptr->port_attributes.OSDeviceName[0] == '\0') {
		/* indentation change due to ctysle check on sizeof. */
		size = sizeof (disco_port_ptr->port_attributes.OSDeviceName);
			(void) strlcpy(disco_port_ptr->port_attributes.
			    OSDeviceName, fullpath, size);
		}

		/* add new discovered port into the list */

		if (port_ptr->first_attached_port == NULL) {
			port_ptr->first_attached_port = disco_port_ptr;
			disco_port_ptr->index = 0;
			port_ptr->port_attributes.PortSpecificAttribute.\
			    SASPort->NumberofDiscoveredPorts = 1;
		} else {
			disco_port_ptr->next = port_ptr->first_attached_port;
			port_ptr->first_attached_port = disco_port_ptr;
			disco_port_ptr->index = port_ptr->port_attributes.\
			    PortSpecificAttribute.\
			    SASPort->NumberofDiscoveredPorts;
			port_ptr->port_attributes.PortSpecificAttribute.\
			    SASPort->NumberofDiscoveredPorts++;
		}
		disco_port_ptr->port_attributes.PortState = port_state;
	}

	if (disco_port_ptr->port_attributes.PortType ==
	    HBA_PORTTYPE_SASEXPANDER) {
	    /* No mapping data for expander device.  return ok here. */
		di_devfs_path_free(devpath);
		return (HBA_STATUS_OK);
	}

	if ((mapping_ptr = (struct ScsiEntryList *)calloc
		    (1, sizeof (struct ScsiEntryList))) == NULL) {
		OUT_OF_MEMORY(ROUTINE);
		di_devfs_path_free(devpath);
		free_attached_port(port_ptr);
		return (HBA_STATUS_ERROR);
	}

	if (di_prop_lookup_ints(DDI_DEV_T_ANY, node, "lun",
	    &propIntData) != -1) {
		mapping_ptr->entry.ScsiId.ScsiOSLun = *propIntData;
	} else {
		if ((charptr = strchr(unit_address, ',')) != NULL) {
			charptr++;
			mapping_ptr->entry.ScsiId.ScsiOSLun =
			    strtoull(charptr, NULL, 10);
		} else {
			log(LOG_DEBUG, ROUTINE,
			    "Failed to get LUN from the unit address of device "
			    " %s.", fullpath);
			di_devfs_path_free(devpath);
			free_attached_port(port_ptr);
			return (HBA_STATUS_ERROR);
		}
	}

	/* get TargetLun(SAM-LUN). */
	if (di_prop_lookup_int64(DDI_DEV_T_ANY, node, "lun64",
	    &propInt64Data) != -1) {
		samLun = scsi_lun64_to_lun(*propInt64Data);
		(void) memcpy(&mapping_ptr->entry.PortLun.TargetLun,
		    &samLun, 8);
	} else {
		log(LOG_DEBUG, "get_attached_devices_info",
		    "No lun64 prop found on device %s.", fullpath);
		di_devfs_path_free(devpath);
		free_attached_port(port_ptr);
		return (HBA_STATUS_ERROR);
	}

	if (di_prop_lookup_ints(DDI_DEV_T_ANY, node,
	    "target", &propIntData) != -1) {
		mapping_ptr->entry.ScsiId.ScsiTargetNumber = *propIntData;
	} else {
		mapping_ptr->entry.ScsiId.ScsiTargetNumber = di_instance(node);
	}

	/* get ScsiBusNumber */
	mapping_ptr->entry.ScsiId.ScsiBusNumber = port_ptr->cntlNumber;

	(void) memcpy(mapping_ptr->entry.PortLun.PortWWN.wwn,
	    SASAddress.wwn, 8);

	/* Store the devices path for now.  We'll convert to /dev later */
	get_minor(devpath, minorname);
	(void) snprintf(mapping_ptr->entry.ScsiId.OSDeviceName,
	    sizeof (mapping_ptr->entry.ScsiId.OSDeviceName),
	    "%s%s%s", DEVICES_DIR, devpath, minorname);

	/* reset errno to 0 */
	errno = 0;
	if (di_prop_lookup_strings(DDI_DEV_T_ANY, node, "devid",
	    &propStringData) != -1) {
		if (devid_str_decode(propStringData, &devid, NULL) != -1) {
			guidStr = devid_to_guid(devid);
			if (guidStr != NULL) {
				(void) strlcpy(mapping_ptr->entry.LUID.buffer,
				    guidStr,
				    sizeof (mapping_ptr->entry.LUID.buffer));
				devid_free_guid(guidStr);
			} else {
				/*
				 * Note:
				 * if logical unit associated page 83 id
				 * descriptor is not avaialble for the device
				 * devid_to_guid returns NULL with errno 0.
				 */
				log(LOG_DEBUG, ROUTINE,
				    "failed to get devid guid on (%s) : %s",
				    devpath, strerror(errno));
			}

			devid_free(devid);
		} else {
			/*
			 * device may not support proper page 83 id descriptor.
			 * leave LUID attribute to NULL and continue.
			 */
			log(LOG_DEBUG, ROUTINE,
			    "failed to decode devid prop on (%s) : %s",
			    devpath, strerror(errno));
		}
	} else {
		/* leave LUID attribute to NULL and continue. */
		log(LOG_DEBUG, ROUTINE,
		    "failed to get devid prop on (%s) : %s",
		    devpath, strerror(errno));
	}

	if (disco_port_ptr->scsiInfo == NULL) {
		disco_port_ptr->scsiInfo = mapping_ptr;
	} else {
		mapping_ptr->next = disco_port_ptr->scsiInfo;
		disco_port_ptr->scsiInfo = mapping_ptr;
	}

	di_devfs_path_free(devpath);

	return (HBA_STATUS_OK);
}

/*
 * Finds attached device(target) from pathinfo node.
 */
static HBA_STATUS
get_attached_paths_info(di_path_t path, struct sun_sas_port *port_ptr)
{
	char			    ROUTINE[] = "get_attached_paths_info";
	char			    *propStringData = NULL;
	int			    *propIntData = NULL;
	int64_t			    *propInt64Data = NULL;
	scsi_lun_t		    samLun;
	ddi_devid_t		    devid;
	char			    *guidStr;
	char			    *unit_address;
	char			    *charptr;
	char			    *clientdevpath = NULL;
	char			    *pathdevpath = NULL;
	char			    fullpath[MAXPATHLEN+1];
	char			    minorname[MAXNAMELEN+1];
	struct ScsiEntryList	    *mapping_ptr;
	HBA_WWN			    SASAddress, AttachedSASAddress;
	struct sun_sas_port	    *disco_port_ptr;
	di_path_state_t		    state = 0;
	di_node_t		    clientnode;
	int			    portfound, size;
	int			    port_state = HBA_PORTSTATE_ONLINE;
	uint64_t		    tmpAddr;

	if (port_ptr == NULL) {
		log(LOG_DEBUG, ROUTINE, "NULL port_ptr argument");
		return (HBA_STATUS_ERROR);
	}

	/* if not null, free before return. */
	pathdevpath = di_path_devfs_path(path);

	state = di_path_state(path);
	/* when node is not attached and online, set the state to offline. */
	if ((state == DI_PATH_STATE_OFFLINE) ||
	    (state == DI_PATH_STATE_FAULT)) {
		log(LOG_DEBUG, ROUTINE,
		    "path node (%s) is either OFFLINE or FAULT state",
		    pathdevpath ?  pathdevpath : "(missing device path)");
		port_state = HBA_PORTSTATE_OFFLINE;
	}

	if (clientnode = di_path_client_node(path)) {
		if (di_retired(clientnode)) {
			log(LOG_DEBUG, ROUTINE,
			    "client node of path (%s) is retired. Skipping.",
			    pathdevpath ?  pathdevpath :
			    "(missing device path)");
			if (pathdevpath) di_devfs_path_free(pathdevpath);
			return (HBA_STATUS_OK);
		}
		if ((clientdevpath = di_devfs_path(clientnode)) == NULL) {
			log(LOG_DEBUG, ROUTINE,
			    "Client device of path (%s) has no path. Skipping.",
			    pathdevpath ?  pathdevpath :
			    "(missing device path)");
			if (pathdevpath) di_devfs_path_free(pathdevpath);
			return (HBA_STATUS_ERROR);
		}
	} else {
		log(LOG_DEBUG, ROUTINE,
		    "Failed to get client device from a path (%s).",
		    pathdevpath ?  pathdevpath :
		    "(missing device path)");
		if (pathdevpath) di_devfs_path_free(pathdevpath);
		return (HBA_STATUS_ERROR);
	}

	/* add the "/devices" in the begining and the :devctl at the end */
	(void) snprintf(fullpath, sizeof (fullpath), "%s%s", DEVICES_DIR,
	    clientdevpath);

	(void) memset(&SASAddress, 0, sizeof (SASAddress));
	if ((unit_address = di_path_bus_addr(path)) != NULL) {
		if ((charptr = strchr(unit_address, ',')) != NULL) {
			*charptr = '\0';
		}
		for (charptr = unit_address; *charptr != '\0'; charptr++) {
			if (isxdigit(*charptr)) {
				break;
			}
		}
		if (*charptr != '\0') {
			tmpAddr = htonll(strtoll(charptr, NULL, 16));
			(void) memcpy(&SASAddress.wwn[0], &tmpAddr, 8);
		} else {
			log(LOG_DEBUG, ROUTINE,
			    "No proper target port info on unit address of "
			    "path (%s).", pathdevpath ?  pathdevpath :
			    "(missing device path)");
			if (pathdevpath) di_devfs_path_free(pathdevpath);
			di_devfs_path_free(clientdevpath);
			return (HBA_STATUS_ERROR);
		}
	} else {
		log(LOG_DEBUG, ROUTINE, "Fail to get unit address of path(%s).",
		    "path (%s).", pathdevpath ?  pathdevpath :
		    "(missing device path)");
		if (pathdevpath) di_devfs_path_free(pathdevpath);
		di_devfs_path_free(clientdevpath);
		return (HBA_STATUS_ERROR);
	}

	(void) memset(&AttachedSASAddress, 0, sizeof (AttachedSASAddress));
	if (di_path_prop_lookup_strings(path, "attached-port",
	    &propStringData) != -1) {
		for (charptr = propStringData; *charptr != '\0'; charptr++) {
			if (isxdigit(*charptr)) {
				break;
			}
		}
		if (*charptr != '\0') {
			tmpAddr = htonll(strtoll(charptr, NULL, 16));
			(void) memcpy(AttachedSASAddress.wwn, &tmpAddr, 8);
			/*  check the attached address of hba port. */
			if (memcmp(port_ptr->port_attributes.
			    PortSpecificAttribute.SASPort->
			    LocalSASAddress.wwn, &tmpAddr, 8) == 0) {
				if (wwnConversion(port_ptr->port_attributes.
				    PortSpecificAttribute.SASPort->
				    AttachedSASAddress.wwn)) {
					/* verify the attaached SAS Addr. */
					if (memcmp(port_ptr->port_attributes.
					    PortSpecificAttribute.SASPort->
					    AttachedSASAddress.wwn,
					    SASAddress.wwn, 8) != 0) {
				/* indentation move begin. */
				log(LOG_DEBUG, ROUTINE,
				    "iport attached-port(%016llx) do not"
				    " match with level 1 Local"
				    " SAS address(%016llx).",
				    wwnConversion(port_ptr->port_attributes.
				    PortSpecificAttribute.
				    SASPort->AttachedSASAddress.wwn),
				    wwnConversion(SASAddress.wwn));
				if (pathdevpath)
					di_devfs_path_free(pathdevpath);
				di_devfs_path_free(clientdevpath);
				free_attached_port(port_ptr);
				return (HBA_STATUS_ERROR);
				/* indentation move ends. */
					}
				} else {
					/* store the Attaached SAS Addr. */
					(void) memcpy(port_ptr->port_attributes.
					    PortSpecificAttribute.
					    SASPort->AttachedSASAddress.wwn,
					    &SASAddress.wwn[0], 8);
				}
			}
		} else {
			log(LOG_DEBUG, ROUTINE,
			    "No proper attached SAS address value of path (%s)",
			    pathdevpath ?  pathdevpath :
			    "(missing device path)");
			if (pathdevpath) di_devfs_path_free(pathdevpath);
			di_devfs_path_free(clientdevpath);
			free_attached_port(port_ptr);
			return (HBA_STATUS_ERROR);
		}
	} else {
		log(LOG_DEBUG, ROUTINE,
		    "Property attached-port not found for path (%s)",
		    pathdevpath ?  pathdevpath :
		    "(missing device path)");
		if (pathdevpath) di_devfs_path_free(pathdevpath);
		di_devfs_path_free(clientdevpath);
		free_attached_port(port_ptr);
		return (HBA_STATUS_ERROR);
	}

	/*
	 * walk the disco list to make sure that there isn't a matching
	 * port and node wwn or a matching device path
	 */
	portfound = 0;
	for (disco_port_ptr = port_ptr->first_attached_port;
	    disco_port_ptr != NULL;
	    disco_port_ptr = disco_port_ptr->next) {
		if ((disco_port_ptr->port_attributes.PortState !=
		    HBA_PORTSTATE_ERROR) &&
		    (memcmp(disco_port_ptr->port_attributes.
		    PortSpecificAttribute.SASPort->LocalSASAddress.wwn,
		    SASAddress.wwn, 8) == 0)) {
			/*
			 * found matching disco_port
			 * look for matching device path
			 */
			portfound = 1;
			for (mapping_ptr = disco_port_ptr->scsiInfo;
			    mapping_ptr != NULL;
			    mapping_ptr = mapping_ptr->next) {
				if (strstr(mapping_ptr-> entry.ScsiId.
				    OSDeviceName, clientdevpath) != 0) {
					log(LOG_DEBUG, ROUTINE,
					    "Found an already discovered "
					    "device %s.", clientdevpath);
					if (pathdevpath)
						di_devfs_path_free(pathdevpath);
					di_devfs_path_free(clientdevpath);
					return (HBA_STATUS_OK);
				}
			}
			if (portfound == 1) {
				break;
			}
		}
	}

	if (portfound == 0) {
		/*
		 * there are no matching SAS address.
		 * this must be a new device
		 */
		if ((disco_port_ptr = (struct sun_sas_port *)calloc(1,
				    sizeof (struct sun_sas_port))) == NULL)  {
			OUT_OF_MEMORY(ROUTINE);
			if (pathdevpath) di_devfs_path_free(pathdevpath);
			di_devfs_path_free(clientdevpath);
			free_attached_port(port_ptr);
			return (HBA_STATUS_ERROR);
		}

		if ((disco_port_ptr->port_attributes.PortSpecificAttribute.\
		    SASPort = (struct SMHBA_SAS_Port *)calloc(1,
		    sizeof (struct SMHBA_SAS_Port))) == NULL) {
			OUT_OF_MEMORY("add_hba_port_info");
			if (pathdevpath) di_devfs_path_free(pathdevpath);
			di_devfs_path_free(clientdevpath);
			free_attached_port(port_ptr);
			return (HBA_STATUS_ERROR);
		}

		(void) memcpy(disco_port_ptr->port_attributes.
		    PortSpecificAttribute.
		    SASPort->LocalSASAddress.wwn, SASAddress.wwn, 8);
		(void) memcpy(disco_port_ptr->port_attributes.
		    PortSpecificAttribute.
		    SASPort->AttachedSASAddress.wwn, AttachedSASAddress.wwn, 8);

		/* Default to unknown until we figure out otherwise */
		if (di_path_prop_lookup_strings(path, "variant",
		    &propStringData) != -1) {
			if ((strcmp(propStringData, "sata") == 0) ||
			    (strcmp(propStringData, "atapi") == 0)) {
				disco_port_ptr->port_attributes.PortType =
				    HBA_PORTTYPE_SATADEVICE;
				disco_port_ptr->port_attributes.\
				    PortSpecificAttribute.SASPort->PortProtocol
				    = HBA_SASPORTPROTOCOL_SATA;
			} else {
				log(LOG_DEBUG, ROUTINE,
				    "Unexpected variant prop value %s found on",
				    " path (%s)", propStringData,
				    pathdevpath ?  pathdevpath :
				    "(missing device path)");
				/*
				 * Port type will be 0
				 * which is not valid type.
				 */
			}
		} else {
			disco_port_ptr->port_attributes.PortType =
			    HBA_PORTTYPE_SASDEVICE;
			disco_port_ptr->port_attributes.PortSpecificAttribute.\
			    SASPort->PortProtocol = HBA_SASPORTPROTOCOL_SSP;
		}

		if (disco_port_ptr->port_attributes.OSDeviceName[0] == '\0') {
		/* indentation change due to ctysle check on sizeof. */
		size = sizeof (disco_port_ptr->port_attributes.OSDeviceName);
			if (pathdevpath != NULL) {
				(void) strlcpy(disco_port_ptr->port_attributes.
				    OSDeviceName, pathdevpath, size);
			}
		}

		/* add new discovered port into the list */
		if (port_ptr->first_attached_port == NULL) {
			port_ptr->first_attached_port = disco_port_ptr;
			disco_port_ptr->index = 0;
			port_ptr->port_attributes.PortSpecificAttribute.\
			    SASPort->NumberofDiscoveredPorts = 1;
		} else {
			disco_port_ptr->next = port_ptr->first_attached_port;
			port_ptr->first_attached_port = disco_port_ptr;
			disco_port_ptr->index = port_ptr->port_attributes.\
			    PortSpecificAttribute.\
			    SASPort->NumberofDiscoveredPorts;
			port_ptr->port_attributes.PortSpecificAttribute.\
			    SASPort->NumberofDiscoveredPorts++;
		}
		disco_port_ptr->port_attributes.PortState = port_state;
	}

	if ((mapping_ptr = (struct ScsiEntryList *)calloc
		    (1, sizeof (struct ScsiEntryList))) == NULL) {
		OUT_OF_MEMORY(ROUTINE);
		if (pathdevpath) di_devfs_path_free(pathdevpath);
		di_devfs_path_free(clientdevpath);
		free_attached_port(port_ptr);
		return (HBA_STATUS_ERROR);
	}

	if (di_path_prop_lookup_ints(path, "lun", &propIntData) != -1) {
		mapping_ptr->entry.ScsiId.ScsiOSLun = *propIntData;
	} else {
		if ((charptr = strchr(unit_address, ',')) != NULL) {
			charptr++;
			mapping_ptr->entry.ScsiId.ScsiOSLun =
			    strtoull(charptr, NULL, 10);
		} else {
			log(LOG_DEBUG, ROUTINE,
			    "Failed to get LUN from unit address of path(%s).",
			    pathdevpath ?  pathdevpath :
			    "(missing device path)");
			if (pathdevpath) di_devfs_path_free(pathdevpath);
			di_devfs_path_free(clientdevpath);
			free_attached_port(port_ptr);
			return (HBA_STATUS_ERROR);
		}
	}

	/* Get TargetLun(SAM LUN). */
	if (di_path_prop_lookup_int64s(path, "lun64", &propInt64Data) != -1) {
		samLun = scsi_lun64_to_lun(*propInt64Data);
		(void) memcpy(&mapping_ptr->entry.PortLun.TargetLun,
		    &samLun, 8);
	} else {
		log(LOG_DEBUG, ROUTINE, "No lun64 prop found on path (%s)",
		    pathdevpath ?  pathdevpath :
		    "(missing device path)");
		if (pathdevpath) di_devfs_path_free(pathdevpath);
		di_devfs_path_free(clientdevpath);
		free_attached_port(port_ptr);
		return (HBA_STATUS_ERROR);
	}

	if (di_path_prop_lookup_ints(path, "target", &propIntData) != -1) {
		mapping_ptr->entry.ScsiId.ScsiTargetNumber = *propIntData;
	} else {
		mapping_ptr->entry.ScsiId.ScsiTargetNumber =
		    di_path_instance(path);
	}

	/* get ScsiBusNumber */
	mapping_ptr->entry.ScsiId.ScsiBusNumber = port_ptr->cntlNumber;

	(void) memcpy(mapping_ptr->entry.PortLun.PortWWN.wwn,
	    SASAddress.wwn, 8);

	/* Store the devices path for now.  We'll convert to /dev later */
	get_minor(clientdevpath, minorname);
	(void) snprintf(mapping_ptr->entry.ScsiId.OSDeviceName,
	    sizeof (mapping_ptr->entry.ScsiId.OSDeviceName),
	    "%s%s%s", DEVICES_DIR, clientdevpath, minorname);

	/* get luid. */
	errno = 0; /* reset errno to 0 */
	if (di_prop_lookup_strings(DDI_DEV_T_ANY, clientnode, "devid",
	    &propStringData) != -1) {
		if (devid_str_decode(propStringData, &devid, NULL) != -1) {
			guidStr = devid_to_guid(devid);
			if (guidStr != NULL) {
				(void) strlcpy(mapping_ptr->entry.LUID.buffer,
				    guidStr,
				    sizeof (mapping_ptr->entry.LUID.buffer));
				devid_free_guid(guidStr);
			} else {
				/*
				 * Note:
				 * if logical unit associated page 83 id
				 * descriptor is not avaialble for the device
				 * devid_to_guid returns NULL with errno 0.
				 */
				log(LOG_DEBUG, ROUTINE,
				    "failed to get devid guid on (%s)",
				    " associated with path(%s) : %s",
				    clientdevpath,
				    pathdevpath ?  pathdevpath :
				    "(missing device path)",
				    strerror(errno));
			}

			devid_free(devid);
		} else {
			/*
			 * device may not support proper page 83 id descriptor.
			 * leave LUID attribute to NULL and continue.
			 */
			log(LOG_DEBUG, ROUTINE,
			    "failed to decode devid prop on (%s)",
			    " associated with path(%s) : %s",
			    clientdevpath,
			    pathdevpath ?  pathdevpath :
			    "(missing device path)",
			    strerror(errno));
		}
	} else {
		/* leave LUID attribute to NULL and continue. */
		log(LOG_DEBUG, ROUTINE, "Failed to get devid on %s"
		    " associated with path(%s) : %s", clientdevpath,
		    pathdevpath ?  pathdevpath : "(missing device path)",
		    strerror(errno));
	}

	if (disco_port_ptr->scsiInfo == NULL) {
		disco_port_ptr->scsiInfo = mapping_ptr;
	} else {
		mapping_ptr->next = disco_port_ptr->scsiInfo;
		disco_port_ptr->scsiInfo = mapping_ptr;
	}

	if (pathdevpath) di_devfs_path_free(pathdevpath);
	di_devfs_path_free(clientdevpath);

	return (HBA_STATUS_OK);
}

/*
 * walks the devinfo tree retrieving all hba information
 */
extern HBA_STATUS
devtree_attached_devices(di_node_t node, struct sun_sas_port *port_ptr)
{
	const char		ROUTINE[] = "devtree_attached_devices";
	di_node_t		nodechild = DI_NODE_NIL;
	di_path_t		path = DI_PATH_NIL;

	/* child should be device */
	if ((nodechild = di_child_node(node)) == DI_NODE_NIL) {
		log(LOG_DEBUG, ROUTINE,
		    "No devinfo child on the HBA port node.");
	}

	if ((path = di_path_phci_next_path(node, path)) ==
	    DI_PATH_NIL) {
		log(LOG_DEBUG, ROUTINE,
		    "No pathinfo node on the HBA port node.");
	}

	if ((nodechild == DI_NODE_NIL) && (path == DI_PATH_NIL)) {
		return (HBA_STATUS_OK);
	}

	while (nodechild != DI_NODE_NIL) {
		if (get_attached_devices_info(nodechild, port_ptr)
		    != HBA_STATUS_OK) {
			break;
		}
		nodechild = di_sibling_node(nodechild);
	}


	while (path != DI_PATH_NIL) {
		if (get_attached_paths_info(path, port_ptr)
		    != HBA_STATUS_OK) {
			break;
		}
		path = di_path_phci_next_path(node, path);
	}

	return (HBA_STATUS_OK);
}
