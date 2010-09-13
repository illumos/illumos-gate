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

#include "fcinfo.h"
#include <libintl.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>
#include <sys/list.h>
#include <stddef.h>
#include <strings.h>
#include <libfcoe.h>
#include <syslog.h>

static const char *FCOE_DRIVER_PATH	= "/devices/fcoe:admin";

static int
isValidWWN(char *wwn)
{
	int index;

	if (wwn == NULL) {
		return (0);
	}

	if (strlen(wwn) != 16) {
		return (0);
	}

	for (index = 0; index < 16; index++) {
		if (isxdigit(wwn[index])) {
			continue;
		}
		return (0);
	}
	return (1);
}

static uint64_t wwnconvert(uchar_t *wwn)
{
	uint64_t tmp;
	memcpy(&tmp, wwn, sizeof (uint64_t));
	return (ntohll(tmp));
}

/*
 * prints out all the HBA port information
 */
void
printFCOEPortInfo(FCOE_PORT_ATTRIBUTE *attr)
{
	int i;
	if (attr == NULL) {
		return;
	}
	fprintf(stdout, gettext("HBA Port WWN: %016llx\n"),
	    wwnconvert((unsigned char *)&attr->port_wwn));

	fprintf(stdout, gettext("\tPort Type: %s\n"),
	    (attr->port_type == 0) ? "Initiator" : "Target");

	fprintf(stdout, gettext("\tMAC Name: %s\n"), attr->mac_link_name);

	fprintf(stdout, gettext("\tMTU Size: %d\n"), attr->mtu_size);

	fprintf(stdout, gettext("\tPrimary MAC Address: "));
	for (i = 0; i < 6; i++) {
		fprintf(stdout, gettext("%02x"), attr->mac_factory_addr[i]);
	}
	fprintf(stdout, gettext("\n\tCurrent MAC Address: "));
	for (i = 0; i < 6; i++) {
		fprintf(stdout, gettext("%02x"), attr->mac_current_addr[i]);
	}
	fprintf(stdout, gettext("\n\tPromiscuous Mode: %s\n"),
	    attr->mac_promisc == 1 ? "On" : "Off");
}


int
fcoe_adm_create_port(int objects, char *argv[],
    cmdOptions_t *options)
{
	FCOE_STATUS status = FCOE_STATUS_OK;
	uint64_t	nodeWWN, portWWN;
	FCOE_PORT_WWN	pwwn, nwwn;
	FCOE_UINT8	macLinkName[FCOE_MAX_MAC_NAME_LEN];
	FCOE_UINT8	promiscuous = 0;
	int		createini = 0, createtgt = 0;

	/* check the mac name operand */
	assert(objects == 1);

	strcpy((char *)macLinkName, argv[0]);
	bzero(&pwwn, 8);
	bzero(&nwwn, 8);

	for (; options->optval; options++) {
		switch (options->optval) {
		case 'i':
			createini = 1;
			break;

		case 't':
			createtgt = 1;
			break;
		case 'p':
			if (!isValidWWN(options->optarg)) {
				fprintf(stderr,
				    gettext("Error: Invalid Port WWN\n"));
				return (1);
			}
			sscanf(options->optarg, "%016llx", &portWWN);
			portWWN = htonll(portWWN);
			memcpy(&pwwn, &portWWN, sizeof (portWWN));
			break;

		case 'n':
			if (!isValidWWN(options->optarg)) {
				fprintf(stderr,
				    gettext("Error: Invalid Node WWN\n"));
				return (1);
			}
			sscanf(options->optarg, "%016llx", &nodeWWN);
			nodeWWN = htonll(nodeWWN);
			memcpy(&nwwn, &nodeWWN, sizeof (nodeWWN));
			break;
		case 'f':
			promiscuous = 1;
			break;

		default:
			fprintf(stderr, gettext("Error: Illegal option: %c\n"),
			    options->optval);
			return (1);
		}
	}

	if (createini == 1 && createtgt == 1) {
		fprintf(stderr, "Error: Option -i and -t should "
		    "not be both specified\n");
		return (1);
	}
	status = FCOE_CreatePort(macLinkName,
	    createtgt == 1 ? FCOE_PORTTYPE_TARGET :
	    FCOE_PORTTYPE_INITIATOR, pwwn, nwwn, promiscuous);

	if (status != FCOE_STATUS_OK) {
		switch (status) {
		case  FCOE_STATUS_ERROR_BUSY:
			fprintf(stderr,
			    gettext("Error: fcoe driver is busy\n"));
			break;

		case  FCOE_STATUS_ERROR_ALREADY:
			fprintf(stderr,
			    gettext("Error: Existing FCoE port "
			    "found on the specified MAC link\n"));
			break;

		case  FCOE_STATUS_ERROR_PERM:
			fprintf(stderr,
			    gettext("Error: Not enough permission to "
			    "open fcoe device\n"));
			break;

		case  FCOE_STATUS_ERROR_OPEN_DEV:
			fprintf(stderr,
			    gettext("Error: Failed to open fcoe device\n"));
			break;

		case  FCOE_STATUS_ERROR_WWN_SAME:
			fprintf(stderr,
			    gettext("Error: Port WWN is same as Node "
			    "WWN\n"));
			break;

		case  FCOE_STATUS_ERROR_MAC_LEN:
			fprintf(stderr,
			    gettext("Error: MAC name exceeds maximum "
			    "length\n"));
			break;

		case  FCOE_STATUS_ERROR_PWWN_CONFLICTED:
			fprintf(stderr,
			    gettext("Error: The specified Port WWN "
			    "is already in use\n"));
			break;

		case  FCOE_STATUS_ERROR_NWWN_CONFLICTED:
			fprintf(stderr,
			    gettext("Error: The specified Node WWN "
			    "is already in use\n"));
			break;

		case  FCOE_STATUS_ERROR_NEED_JUMBO_FRAME:
			fprintf(stderr,
			    gettext("Error: MTU size of the specified "
			    "MAC link needs to be increased to 2500 "
			    "or above\n"));
			break;

		case  FCOE_STATUS_ERROR_CREATE_MAC:
			fprintf(stderr,
			    gettext("Error: Out of memory\n"));
			break;


		case  FCOE_STATUS_ERROR_OPEN_MAC:
			fprintf(stderr,
			    gettext("Error: Failed to open the "
			    "specified MAC link\n"));
			break;

		case  FCOE_STATUS_ERROR_CREATE_PORT:
			fprintf(stderr,
			    gettext("Error: Failed to create FCoE "
			    "port on the specified MAC link\n"));
			break;

		case  FCOE_STATUS_ERROR_CLASS_UNSUPPORT:
			fprintf(stderr,
			    gettext("Error: Link class other than physical "
			    "link is not supported\n"));
			break;

		case FCOE_STATUS_ERROR_GET_LINKINFO:
			fprintf(stderr,
			    gettext("Error: Failed to get link information "
			    "for %s\n"), macLinkName);
			break;

		case FCOE_STATUS_ERROR:
		default:
			fprintf(stderr,
			    gettext("Error: Due to reason code %d\n"), status);
		}
		return (1);
	} else {
		return (0);
	}
}

int
fcoe_adm_delete_port(int objects, char *argv[])
{
	FCOE_STATUS status;
	FCOE_UINT8	*macLinkName;
	FCOE_UINT32		port_num;
	FCOE_PORT_ATTRIBUTE	*portlist = NULL;
	int			i;

	/* check the mac name operand */
	assert(objects == 1);

	macLinkName = (FCOE_UINT8 *) argv[0];

	status = FCOE_DeletePort(macLinkName);
	if (status != FCOE_STATUS_OK) {
		switch (status) {
		case  FCOE_STATUS_ERROR_BUSY:
			fprintf(stderr,
			    gettext("Error: fcoe driver is busy\n"));
			break;

		case  FCOE_STATUS_ERROR_ALREADY:
			fprintf(stderr,
			    gettext("Error: FCoE port not found on the "
			    "specified MAC link\n"));
			break;

		case  FCOE_STATUS_ERROR_PERM:
			fprintf(stderr,
			    gettext("Error: Not enough permission to "
			    "open fcoe device\n"));
			break;

		case  FCOE_STATUS_ERROR_MAC_LEN:
			fprintf(stderr,
			    gettext("Failed: MAC name exceeds maximum "
			    "length 32\n"));
			break;

		case  FCOE_STATUS_ERROR_OPEN_DEV:
			fprintf(stderr,
			    gettext("Error: Failed to open fcoe device\n"));
			break;

		case  FCOE_STATUS_ERROR_MAC_NOT_FOUND:
			fprintf(stderr,
			    gettext("Error: FCoE port not found on the "
			    "specified MAC link\n"));
			break;

		case  FCOE_STATUS_ERROR_OFFLINE_DEV:
			status = FCOE_GetPortList(&port_num, &portlist);
			if (status != FCOE_STATUS_OK || port_num == 0) {
				fprintf(stderr,
				    gettext("Error: FCoE port not found on the "
				    "specified MAC link\n"));
				break;
			}
			for (i = 0; i < port_num; i++) {
				if (strcmp(
				    (char *)portlist[i].mac_link_name,
				    (char *)macLinkName) == 0) {
					if (portlist[i].port_type ==
					    FCOE_PORTTYPE_TARGET) {
						fprintf(stderr,
						    gettext("Error: Please use "
						    "stmfadm to offline the "
						    "FCoE target first\n"));
					} else {
						fprintf(stderr,
						    gettext("Error: Failed to "
						    "delete FCoE port because "
						    "unable to offline the "
						    "device\n"));
					}
					break;
				}
			}
			free(portlist);
			if (i == port_num) {
				fprintf(stderr,
				    gettext("Error: FCoE port not found on the "
				    "specified MAC link\n"));
			}
			break;

		case FCOE_STATUS_ERROR_GET_LINKINFO:
			fprintf(stderr,
			    gettext("Error: Failed to get link information "
			    "for %s\n"), macLinkName);
			break;

		case FCOE_STATUS_ERROR:
		default:
			fprintf(stderr,
			    gettext("Error: Due to reason code %d\n"), status);
		}
		return (1);
	} else {
		return (0);
	}
}

int
fcoe_adm_list_ports(cmdOptions_t *options)
{
	FCOE_STATUS	status;
	int	showini = 0, showtgt = 0;
	FCOE_UINT32	port_num;
	FCOE_PORT_ATTRIBUTE	*portlist = NULL;
	int i;
	int ret;

	for (; options->optval; options++) {
		switch (options->optval) {
		case 'i':
			showini = 1;
			break;

		case 't':
			showtgt = 1;
			break;

		default:
			fprintf(stderr, gettext("Error: Illegal option: %c\n"),
			    options->optval);
			return (1);
		}
	}
	if (showini == 0 && showtgt == 0) {
		showini = 1;
		showtgt = 1;
	}

	status = FCOE_GetPortList(&port_num, &portlist);

	if (status != FCOE_STATUS_OK) {
		switch (status) {
		case  FCOE_STATUS_ERROR_BUSY:
			fprintf(stderr,
			    gettext("Error: fcoe driver is busy\n"));
			break;

		case  FCOE_STATUS_ERROR_PERM:
			fprintf(stderr,
			    gettext("Error: Not enough permission to "
			    "open fcoe device\n"));
			break;

		case  FCOE_STATUS_ERROR_OPEN_DEV:
			fprintf(stderr,
			    gettext("Error: Failed to open fcoe device\n"));
			break;

		case  FCOE_STATUS_ERROR_INVAL_ARG:
			fprintf(stderr,
			    gettext("Error: Invalid argument\n"));
			break;

		case  FCOE_STATUS_ERROR_MORE_DATA:
			fprintf(stderr,
			    gettext("Error: More data\n"));
			break;

		case FCOE_STATUS_ERROR:
		default:
			fprintf(stderr,
			    gettext("Error: Due to reason code %d\n"), status);
		}
		ret = 1;
	} else {
		if (port_num == 0) {
			fprintf(stdout, gettext("No FCoE Ports Found!\n"));
		} else {
			for (i = 0; i < port_num; i++) {
				if ((portlist[i].port_type ==
				    FCOE_PORTTYPE_INITIATOR &&
				    showini == 1) || (showtgt == 1 &&
				    portlist[i].port_type ==
				    FCOE_PORTTYPE_TARGET)) {
					printFCOEPortInfo(&portlist[i]);
				}
			}
		}
		ret = 0;
	}

	if (portlist != NULL) {
		free(portlist);
	}
	return (ret);

}
