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
#include <libscf.h>
#include <syslog.h>

static const char *FCOE_DRIVER_PATH	= "/devices/fcoe:admin";

static char *
WWN2str(char *buf, FCOE_PORT_WWN *wwn) {
	int j;
	unsigned char *pc = (unsigned char *)&(wwn->wwn[0]);
	buf[0] = '\0';
	for (j = 0; j < 16; j += 2) {
		sprintf(&buf[j], "%02X", (int)*pc++);
	}
	return (buf);
}

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

	fprintf(stdout, gettext("\tMAC Factory Address: "));
	for (i = 0; i < 6; i++) {
		fprintf(stdout, gettext("%02x"), attr->mac_factory_addr[i]);
	}
	fprintf(stdout, gettext("\n\tMAC Current Address: "));
	for (i = 0; i < 6; i++) {
		fprintf(stdout, gettext("%02x"), attr->mac_current_addr[i]);
	}
	fprintf(stdout, gettext("\n\tPromiscuous Mode: %s\n"),
	    attr->mac_promisc == 1 ? "On" : "Off");
}

/*
 * Initialize scf fcoe service access
 * handle - returned handle
 * service - returned service handle
 */
static int
fcoe_cfg_scf_init(scf_handle_t **handle, scf_service_t **service)
{
	scf_scope_t	*scope = NULL;
	int		ret;

	if ((*handle = scf_handle_create(SCF_VERSION)) == NULL) {
		syslog(LOG_ERR, "scf_handle_create failed - %s",
		    scf_strerror(scf_error()));
		ret = FCOE_ERROR;
		goto err;
	}

	if (scf_handle_bind(*handle) == -1) {
		syslog(LOG_ERR, "scf_handle_bind failed - %s",
		    scf_strerror(scf_error()));
		ret = FCOE_ERROR;
		goto err;
	}

	if ((*service = scf_service_create(*handle)) == NULL) {
		syslog(LOG_ERR, "scf_service_create failed - %s",
		    scf_strerror(scf_error()));
		ret = FCOE_ERROR;
		goto err;
	}

	if ((scope = scf_scope_create(*handle)) == NULL) {
		syslog(LOG_ERR, "scf_scope_create failed - %s",
		    scf_strerror(scf_error()));
		ret = FCOE_ERROR;
		goto err;
	}

	if (scf_handle_get_scope(*handle, SCF_SCOPE_LOCAL, scope) == -1) {
		syslog(LOG_ERR, "scf_handle_get_scope failed - %s",
		    scf_strerror(scf_error()));
		ret = FCOE_ERROR;
		goto err;
	}

	if (scf_scope_get_service(scope, FCOE_SERVICE, *service) == -1) {
		syslog(LOG_ERR, "scf_scope_get_service failed - %s",
		    scf_strerror(scf_error()));
		ret = FCOE_ERROR_SERVICE_NOT_FOUND;
		goto err;
	}

	scf_scope_destroy(scope);

	return (FCOE_SUCCESS);

err:
	if (*handle != NULL) {
		scf_handle_destroy(*handle);
	}
	if (*service != NULL) {
		scf_service_destroy(*service);
		*service = NULL;
	}
	if (scope != NULL) {
		scf_scope_destroy(scope);
	}
	return (ret);
}


static int
fcoe_adm_add_remove_scf_entry(char *mac_name,
    char *pwwn, char *nwwn,
    int is_target, int is_promiscuous, int addRemoveFlag)
{
	scf_handle_t	*handle = NULL;
	scf_service_t	*svc = NULL;
	scf_propertygroup_t	*pg = NULL;
	scf_transaction_t	*tran = NULL;
	scf_transaction_entry_t	*entry = NULL;
	scf_property_t	*prop = NULL;
	scf_value_t	*valueLookup = NULL;
	scf_iter_t	*valueIter = NULL;
	scf_value_t	**valueSet = NULL;
	int	ret = FCOE_SUCCESS;
	boolean_t	createProp = B_FALSE;
	int	lastAlloc = 0;
	char	buf[FCOE_PORT_LIST_LENGTH] = {0};
	char	memberName[FCOE_PORT_LIST_LENGTH] = {0};
	boolean_t	found = B_FALSE;
	int	i = 0;
	int	valueArraySize = 0;
	int	commitRet;

	sprintf(memberName, "%s:%s:%s:%d:%d", mac_name, pwwn, nwwn,
	    is_target, is_promiscuous);

	ret = fcoe_cfg_scf_init(&handle, &svc);
	if (ret != FCOE_SUCCESS) {
		goto out;
	}

	if (((pg = scf_pg_create(handle)) == NULL) ||
	    ((tran = scf_transaction_create(handle)) == NULL) ||
	    ((entry = scf_entry_create(handle)) == NULL) ||
	    ((prop = scf_property_create(handle)) == NULL) ||
	    ((valueIter = scf_iter_create(handle)) == NULL)) {
		ret = FCOE_ERROR;
		goto out;
	}

	/* get property group or create it */
	if (scf_service_get_pg(svc, FCOE_PG_NAME, pg) == -1) {
		if ((scf_error() == SCF_ERROR_NOT_FOUND)) {
			if (scf_service_add_pg(svc, FCOE_PG_NAME,
			    SCF_GROUP_APPLICATION, 0, pg) == -1) {
				syslog(LOG_ERR, "add pg failed - %s",
				    scf_strerror(scf_error()));
				ret = FCOE_ERROR;
			} else {
				createProp = B_TRUE;
			}
		} else {
			syslog(LOG_ERR, "get pg failed - %s",
			    scf_strerror(scf_error()));
			ret = FCOE_ERROR;
		}
		if (ret != FCOE_SUCCESS) {
			goto out;
		}
	}

	/* to make sure property exists */
	if (createProp == B_FALSE) {
		if (scf_pg_get_property(pg, FCOE_PORT_LIST, prop) == -1) {
			if ((scf_error() == SCF_ERROR_NOT_FOUND)) {
				createProp = B_TRUE;
			} else {
				syslog(LOG_ERR, "get property failed - %s",
				    scf_strerror(scf_error()));
				ret = FCOE_ERROR;
				goto out;
			}
		}
	}

	/* Begin the transaction */
	if (scf_transaction_start(tran, pg) == -1) {
		syslog(LOG_ERR, "start transaction failed - %s",
		    scf_strerror(scf_error()));
		ret = FCOE_ERROR;
		goto out;
	}

	valueSet = (scf_value_t **)calloc(1, sizeof (*valueSet)
	    * (lastAlloc = PORT_LIST_ALLOC));
	if (valueSet == NULL) {
		ret = FCOE_ERROR_NOMEM;
		goto out;
	}

	if (createProp) {
		if (scf_transaction_property_new(tran, entry, FCOE_PORT_LIST,
		    SCF_TYPE_USTRING) == -1) {
			if (scf_error() == SCF_ERROR_EXISTS) {
				ret = FCOE_ERROR_EXISTS;
			} else {
				syslog(LOG_ERR,
				    "transaction property new failed - %s",
				    scf_strerror(scf_error()));
				ret = FCOE_ERROR;
			}
			goto out;
		}
	} else {
		if (scf_transaction_property_change(tran, entry,
		    FCOE_PORT_LIST, SCF_TYPE_USTRING) == -1) {
			syslog(LOG_ERR,
			    "transaction property change failed - %s",
			    scf_strerror(scf_error()));
			ret = FCOE_ERROR;
			goto out;
		}

		if (scf_pg_get_property(pg, FCOE_PORT_LIST, prop) == -1) {
			syslog(LOG_ERR, "get property failed - %s",
			    scf_strerror(scf_error()));
			ret = FCOE_ERROR;
			goto out;
		}

		valueLookup = scf_value_create(handle);
		if (valueLookup == NULL) {
			syslog(LOG_ERR, "scf value alloc failed - %s",
			    scf_strerror(scf_error()));
			ret = FCOE_ERROR;
			goto out;
		}

		if (scf_iter_property_values(valueIter, prop) == -1) {
			syslog(LOG_ERR, "iter value failed - %s",
			    scf_strerror(scf_error()));
			ret = FCOE_ERROR;
			goto out;
		}

		while (scf_iter_next_value(valueIter, valueLookup) == 1) {
			char *macnameIter = NULL;
			char buftmp[FCOE_PORT_LIST_LENGTH] = {0};

			bzero(buf, sizeof (buf));
			if (scf_value_get_ustring(valueLookup,
			    buf, MAXNAMELEN) == -1) {
				syslog(LOG_ERR, "iter value failed- %s",
				    scf_strerror(scf_error()));
				ret = FCOE_ERROR;
				break;
			}
			strcpy(buftmp, buf);
			macnameIter = strtok(buftmp, ":");
			if (bcmp(macnameIter, mac_name,
			    strlen(mac_name)) == 0) {
				if (addRemoveFlag == FCOE_SCF_ADD) {
					ret = FCOE_ERROR_EXISTS;
					break;
				} else {
					found = B_TRUE;
					continue;
				}
			}

			valueSet[i] = scf_value_create(handle);
			if (valueSet[i] == NULL) {
				syslog(LOG_ERR, "scf value alloc failed - %s",
				    scf_strerror(scf_error()));
				ret = FCOE_ERROR;
				break;
			}

			if (scf_value_set_ustring(valueSet[i], buf) == -1) {
				syslog(LOG_ERR, "set value failed 1- %s",
				    scf_strerror(scf_error()));
				ret = FCOE_ERROR;
				break;
			}

			if (scf_entry_add_value(entry, valueSet[i]) == -1) {
				syslog(LOG_ERR, "add value failed - %s",
				    scf_strerror(scf_error()));
				ret = FCOE_ERROR;
				break;
			}

			i++;

			if (i >= lastAlloc) {
				lastAlloc += PORT_LIST_ALLOC;
				valueSet = realloc(valueSet,
				    sizeof (*valueSet) * lastAlloc);
				if (valueSet == NULL) {
					ret = FCOE_ERROR;
					break;
				}
			}
		}
	}

	valueArraySize = i;
	if (!found && (addRemoveFlag == FCOE_SCF_REMOVE)) {
		ret = FCOE_ERROR_MEMBER_NOT_FOUND;
	}
	if (ret != FCOE_SUCCESS) {
		goto out;
	}

	if (addRemoveFlag == FCOE_SCF_ADD) {
		/*
		 * Now create the new entry
		 */
		valueSet[i] = scf_value_create(handle);
		if (valueSet[i] == NULL) {
			syslog(LOG_ERR, "scf value alloc failed - %s",
			    scf_strerror(scf_error()));
			ret = FCOE_ERROR;
			goto out;
		} else {
			valueArraySize++;
		}

		/*
		 * Set the new member name
		 */
		if (scf_value_set_ustring(valueSet[i], memberName) == -1) {
			syslog(LOG_ERR, "set value failed 2- %s",
			    scf_strerror(scf_error()));
			ret = FCOE_ERROR;
			goto out;
		}

		/*
		 * Add the new member
		 */
		if (scf_entry_add_value(entry, valueSet[i]) == -1) {
			syslog(LOG_ERR, "add value failed - %s",
			    scf_strerror(scf_error()));
			ret = FCOE_ERROR;
			goto out;
		}
	}

	if ((commitRet = scf_transaction_commit(tran)) != 1) {
		syslog(LOG_ERR, "transaction commit failed - %s",
		    scf_strerror(scf_error()));
		if (commitRet == 0) {
			ret = FCOE_ERROR_BUSY;
		} else {
			ret = FCOE_ERROR;
		}
		goto out;
	}

out:
	/*
	 * Free resources
	 */
	if (handle != NULL) {
		scf_handle_destroy(handle);
	}
	if (svc != NULL) {
		scf_service_destroy(svc);
	}
	if (pg != NULL) {
		scf_pg_destroy(pg);
	}
	if (tran != NULL) {
		scf_transaction_destroy(tran);
	}
	if (entry != NULL) {
		scf_entry_destroy(entry);
	}
	if (prop != NULL) {
		scf_property_destroy(prop);
	}
	if (valueIter != NULL) {
		scf_iter_destroy(valueIter);
	}
	if (valueLookup != NULL) {
		scf_value_destroy(valueLookup);
	}

	/*
	 * Free valueSet scf resources
	 */
	if (valueArraySize > 0) {
		for (i = 0; i < valueArraySize; i++) {
			scf_value_destroy(valueSet[i]);
		}
	}
	/*
	 * Now free the pointer array to the resources
	 */
	if (valueSet != NULL) {
		free(valueSet);
	}

	return (ret);
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
			    gettext("Error: Failed to get link infomation "
			    "for %s\n"), macLinkName);
			break;

		case FCOE_STATUS_ERROR:
		default:
			fprintf(stderr,
			    gettext("Error: Due to reason code %d\n"), status);
		}
		return (1);
	} else {
		char cpwwn[17], cnwwn[17];

		WWN2str(cpwwn, &pwwn);
		WWN2str(cnwwn, &nwwn);

		fcoe_adm_add_remove_scf_entry((char *)macLinkName,
		    cpwwn,
		    cnwwn,
		    createtgt,
		    promiscuous,
		    FCOE_SCF_ADD);
		return (0);
	}
}

int
fcoe_adm_delete_port(int objects, char *argv[])
{
	FCOE_STATUS status;
	FCOE_UINT8	*macLinkName;

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
			fprintf(stderr,
			    gettext("Error: Please use stmfadm to offline "
			    "the FCoE target first\n"));
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
		fcoe_adm_add_remove_scf_entry((char *)macLinkName,
		    "",
		    "",
		    0,
		    0,
		    FCOE_SCF_REMOVE);
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

int
fcoe_adm_create_portlist(cmdOptions_t *options)
{
	scf_handle_t	*handle = NULL;
	scf_service_t	*svc = NULL;
	scf_propertygroup_t	*pg = NULL;
	scf_transaction_t	*tran = NULL;
	scf_transaction_entry_t	*entry = NULL;
	scf_property_t		*prop = NULL;
	scf_value_t	*valueLookup = NULL;
	scf_iter_t	*valueIter = NULL;
	char		buf[FCOE_PORT_LIST_LENGTH] = {0};
	int		commitRet;
	int		create_target = 0, create_initiator = 0;

	/* Check what type of port list will be created */
	for (; options->optval; options++) {
		switch (options->optval) {
		case 'i':
			create_initiator = 1;
			break;
		case 't':
			create_target = 1;
			break;
		default:
			fprintf(stderr, gettext("Error: Illegal option: %c\n"),
			    options->optval);
			return (1);
		}
	}

	if (create_initiator == 0 && create_target == 0) {
		create_initiator = 1;
		create_target = 1;
	}

	commitRet = fcoe_cfg_scf_init(&handle, &svc);
	if (commitRet != FCOE_SUCCESS) {
		goto out;
	}

	if (((pg = scf_pg_create(handle)) == NULL) ||
	    ((tran = scf_transaction_create(handle)) == NULL) ||
	    ((entry = scf_entry_create(handle)) == NULL) ||
	    ((prop = scf_property_create(handle)) == NULL) ||
	    ((valueIter = scf_iter_create(handle)) == NULL)) {
		goto out;
	}

	/* get property group or create it */
	if (scf_service_get_pg(svc, FCOE_PG_NAME, pg) == -1) {
		goto out;
	}

	if (scf_pg_get_property(pg, FCOE_PORT_LIST, prop) == -1) {
		syslog(LOG_ERR, "get property failed - %s",
		    scf_strerror(scf_error()));
		goto out;
	}

	valueLookup = scf_value_create(handle);
	if (valueLookup == NULL) {
		syslog(LOG_ERR, "scf value alloc failed - %s",
		    scf_strerror(scf_error()));
		goto out;
	}

	if (scf_iter_property_values(valueIter, prop) == -1) {
		syslog(LOG_ERR, "iter value failed - %s",
		    scf_strerror(scf_error()));
		goto out;
	}
	while (scf_iter_next_value(valueIter, valueLookup) == 1) {
		uint8_t *macLinkName = NULL;
		char *remainder = NULL;
		FCOE_PORT_WWN pwwn, nwwn;
		uint64_t	nodeWWN, portWWN;
		int is_target, is_promiscuous;

		bzero(buf, sizeof (buf));
		bzero(&pwwn, sizeof (pwwn));
		bzero(&nwwn, sizeof (nwwn));
		if (scf_value_get_ustring(valueLookup, buf, MAXNAMELEN) == -1) {
			syslog(LOG_ERR, "iter value failed - %s",
			    scf_strerror(scf_error()));
			break;
		}
		macLinkName = (uint8_t *)strtok(buf, ":");
		remainder = strtok(NULL, "#");
		sscanf(remainder, "%016llx:%016llx:%d:%d",
		    &portWWN, &nodeWWN, &is_target, &is_promiscuous);
		if ((!create_target && is_target) ||
		    (!create_initiator && !is_target)) {
			continue;
		}

		nodeWWN = htonll(nodeWWN);
		memcpy(&nwwn, &nodeWWN, sizeof (nodeWWN));
		portWWN = htonll(portWWN);
		memcpy(&pwwn, &portWWN, sizeof (portWWN));

		FCOE_CreatePort(macLinkName,
		    is_target ? FCOE_PORTTYPE_TARGET : FCOE_PORTTYPE_INITIATOR,
		    pwwn, nwwn, is_promiscuous);
	}

out:
	/*
	 * Free resources
	 */
	if (handle != NULL) {
		scf_handle_destroy(handle);
	}
	if (svc != NULL) {
		scf_service_destroy(svc);
	}
	if (pg != NULL) {
		scf_pg_destroy(pg);
	}
	if (tran != NULL) {
		scf_transaction_destroy(tran);
	}
	if (entry != NULL) {
		scf_entry_destroy(entry);
	}
	if (prop != NULL) {
		scf_property_destroy(prop);
	}
	if (valueIter != NULL) {
		scf_iter_destroy(valueIter);
	}
	if (valueLookup != NULL) {
		scf_value_destroy(valueLookup);
	}

	return (0);
}
