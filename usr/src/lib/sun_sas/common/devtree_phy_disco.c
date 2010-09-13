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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <libdevinfo.h>
#include <netinet/in.h>
#include <inttypes.h>

/*
 * structure for di_devlink_walk
 */
typedef struct walk_devlink {
	char *path;
	size_t len;
	char **linkpp;
} walk_devlink_t;

/*
 * Free the phy allocation.
 */
static void
free_phy_info(struct sun_sas_port *port_ptr)
{
	struct phy_info *phy_ptr, *last_phy;

	phy_ptr = port_ptr->first_phy;
	while (phy_ptr != NULL) {
		last_phy = phy_ptr;
		phy_ptr = phy_ptr->next;
		free(last_phy);
	}

	port_ptr->first_phy = NULL;

}

/*
 * callback funtion for di_devlink_walk
 * Find matching /dev link for the given path argument.
 * devlink element and callback function argument.
 * The input path is expected to not have "/devices".
 */
extern HBA_STATUS
get_phy_info(di_node_t node, struct sun_sas_port *port_ptr)
{
	const char ROUTINE[] = "get_phy_info";
	char *portDevpath = NULL;
	uchar_t	*propByteData = NULL;
	struct phy_info *phy_ptr;
	uint_t nvcount;
	int rval, count, i;
	nvlist_t *nvl, **phyInfoVal;
	uint8_t phyId;
	int8_t negoRate, prgmMinRate, prgmMaxRate, hwMinRate, hwMaxRate;

	/*
	 * When path is specified, it doesn't have minor
	 * name. Therefore, the ../.. prefixes needs to be stripped.
	 */
	if ((portDevpath = di_devfs_path(node)) == NULL) {
		log(LOG_DEBUG, ROUTINE,
		"Unable to get device path from portNode.");
	}

	count = di_prop_lookup_bytes(DDI_DEV_T_ANY, node, "phy-info",
	    (uchar_t **)&propByteData);
	if (count < 0) {
		if (portDevpath) {
			log(LOG_DEBUG, ROUTINE,
			    "Property phy-info not found on port %s%s",
			    DEVICES_DIR, portDevpath);
			di_devfs_path_free(portDevpath);
		} else {
			log(LOG_DEBUG, ROUTINE, "Property phy-info not found.");
		}
		return (HBA_STATUS_ERROR);
	} else {
		rval = nvlist_unpack((char *)propByteData, count, &nvl, 0);
		if (rval != 0) {
			if (portDevpath) {
				log(LOG_DEBUG, ROUTINE,
				    "nvlist_unpack failed on port %s%s",
				    DEVICES_DIR, portDevpath);
				di_devfs_path_free(portDevpath);
			} else {
				log(LOG_DEBUG, ROUTINE,
				    "nvlist_unpack failed.");
			}
			return (HBA_STATUS_ERROR);
		} else {
			rval = nvlist_lookup_nvlist_array(nvl, "phy-info-nvl",
			    &phyInfoVal, &nvcount);
			if (rval != 0) {
				if (portDevpath) {
					log(LOG_DEBUG, ROUTINE,
					    "nvlist array phy-info-nvl not\
					    found on port %s%s", DEVICES_DIR,
					    portDevpath);
					di_devfs_path_free(portDevpath);
				} else {
					log(LOG_DEBUG, ROUTINE,
					    "nvlist array phy-info-nvl not\
					    found");
				}
				nvlist_free(nvl);
				return (HBA_STATUS_ERROR);
			} else {
		/* indentation moved */
		for (i = 0; i < nvcount; i++) {
			if (nvlist_lookup_uint8(phyInfoVal[i],
			    "PhyIdentifier", &phyId) != 0) {
				/* Indicate a failure : no better way to set */
				phyId = 0xff;
			}
			if (nvlist_lookup_int8(phyInfoVal[i],
			    "NegotiatedLinkRate", &negoRate) != 0) {
				negoRate = HBA_SASSTATE_UNKNOWN;
			}
			if (nvlist_lookup_int8(phyInfoVal[i],
			    "ProgrammedMinLinkRate", &prgmMinRate) != 0) {
				prgmMinRate = HBA_SASSTATE_UNKNOWN;
			}
			if (nvlist_lookup_int8(phyInfoVal[i],
			    "ProgrammedMaxLinkRate", &prgmMaxRate) != 0) {
				prgmMaxRate = HBA_SASSTATE_UNKNOWN;
			}
			if (nvlist_lookup_int8(phyInfoVal[i],
			    "HardwareMinLinkRate", &hwMinRate) != 0) {
				hwMinRate = HBA_SASSTATE_UNKNOWN;
			}
			if (nvlist_lookup_int8(phyInfoVal[i],
			    "HardwareMaxLinkRate", &hwMaxRate) != 0) {
				hwMaxRate = HBA_SASSTATE_UNKNOWN;
			}

			if ((phy_ptr = (struct phy_info *)calloc(1,
			    sizeof (struct phy_info))) == NULL)  {
				OUT_OF_MEMORY(ROUTINE);
				if (portDevpath)
					di_devfs_path_free(portDevpath);
				free_phy_info(port_ptr);
				nvlist_free(nvl);
				return (HBA_STATUS_ERROR);
			}
			phy_ptr->phy.PhyIdentifier = phyId;
			phy_ptr->phy.NegotiatedLinkRate = negoRate;
			phy_ptr->phy.ProgrammedMinLinkRate = prgmMinRate;
			phy_ptr->phy.ProgrammedMaxLinkRate = prgmMaxRate;
			phy_ptr->phy.HardwareMinLinkRate = hwMinRate;
			phy_ptr->phy.HardwareMaxLinkRate = hwMaxRate;
			/*
			 * we will fill domain port later.
			 */
			(void) memset(phy_ptr->phy.domainPortWWN.wwn, 0, 8);
			phy_ptr->index = i;
			if (port_ptr->first_phy == NULL) {
				port_ptr->first_phy = phy_ptr;
			} else {
				phy_ptr->next = port_ptr->first_phy;
				port_ptr->first_phy = phy_ptr;
			}

		}
		nvlist_free(nvl);
		/* end of indentation move */
			}
		}
	}

	if (portDevpath) {
		di_devfs_path_free(portDevpath);
	}

	return (HBA_STATUS_OK);
}
