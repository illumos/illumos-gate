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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <libscf.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>
#include <strings.h>
#include <ctype.h>
#include <fcinfo.h>


#define	FCADM_RETRY_TIMES	10
#define	FCADM_SLEEP_TIME	1

static char *
WWN2str(char *buf, HBA_WWN *wwn) {
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


/*
 * Initialize scf stmf service access
 * handle - returned handle
 * service - returned service handle
 */
static int
cfgInit(scf_handle_t **handle, scf_service_t **service)
{
	scf_scope_t	*scope = NULL;
	int		ret;

	if ((*handle = scf_handle_create(SCF_VERSION)) == NULL) {
		/* log error */
		ret = NPIV_ERROR;
		goto err;
	}

	if (scf_handle_bind(*handle) == -1) {
		/* log error */
		ret = NPIV_ERROR;
		goto err;
	}

	if ((*service = scf_service_create(*handle)) == NULL) {
		/* log error */
		ret = NPIV_ERROR;
		goto err;
	}

	if ((scope = scf_scope_create(*handle)) == NULL) {
		/* log error */
		ret = NPIV_ERROR;
		goto err;
	}

	if (scf_handle_get_scope(*handle, SCF_SCOPE_LOCAL, scope) == -1) {
		/* log error */
		ret = NPIV_ERROR;
		goto err;
	}

	if (scf_scope_get_service(scope, NPIV_SERVICE, *service) == -1) {
		/* log error */
		ret = NPIV_ERROR_SERVICE_NOT_FOUND;
		goto err;
	}

	scf_scope_destroy(scope);

	return (NPIV_SUCCESS);

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
npivAddRemoveNPIVEntry(char *ppwwn, char *vnwwn,
    char *vpwwn, int vindex, int addRemoveFlag) {
	scf_handle_t	*handle = NULL;
	scf_service_t	*svc = NULL;
	scf_propertygroup_t	*pg = NULL;
	scf_transaction_t	*tran = NULL;
	scf_transaction_entry_t	*entry = NULL;
	scf_property_t	*prop = NULL;
	scf_value_t	*valueLookup = NULL;
	scf_iter_t	*valueIter = NULL;
	scf_value_t	**valueSet = NULL;
	int	ret = NPIV_SUCCESS;
	boolean_t	createProp = B_FALSE;
	int	lastAlloc = 0;
	char	buf[NPIV_PORT_LIST_LENGTH] = {0};
	char	memberName[NPIV_PORT_LIST_LENGTH] = {0};
	boolean_t	found = B_FALSE;
	int	i = 0;
	int	valueArraySize = 0;
	int	commitRet;

	if (vnwwn) {
		sprintf(memberName, "%s:%s:%s:%d", ppwwn, vpwwn, vnwwn, vindex);
	} else {
		sprintf(memberName, "%s:%s", ppwwn, vpwwn);
	}

	ret = cfgInit(&handle, &svc);
	if (ret != NPIV_SUCCESS) {
		goto out;
	}

	if (((pg = scf_pg_create(handle)) == NULL) ||
	    ((tran = scf_transaction_create(handle)) == NULL) ||
	    ((entry = scf_entry_create(handle)) == NULL) ||
	    ((prop = scf_property_create(handle)) == NULL) ||
	    ((valueIter = scf_iter_create(handle)) == NULL)) {
		ret = NPIV_ERROR;
		goto out;
	}

	/* get property group or create it */
	if (scf_service_get_pg(svc, NPIV_PG_NAME, pg) == -1) {
		if ((scf_error() == SCF_ERROR_NOT_FOUND) &&
		    (addRemoveFlag == NPIV_ADD)) {
			if (scf_service_add_pg(svc, NPIV_PG_NAME,
			    SCF_GROUP_APPLICATION, 0, pg) == -1) {
				syslog(LOG_ERR, "add pg failed - %s",
				    scf_strerror(scf_error()));
				ret = NPIV_ERROR;
			} else {
				createProp = B_TRUE;
			}
		} else if (scf_error() == SCF_ERROR_NOT_FOUND) {
			ret = NPIV_ERROR_NOT_FOUND;
		} else {
			syslog(LOG_ERR, "get pg failed - %s",
			    scf_strerror(scf_error()));
			ret = NPIV_ERROR;
		}
		if (ret != NPIV_SUCCESS) {
			goto out;
		}
	}

	/* Begin the transaction */
	if (scf_transaction_start(tran, pg) == -1) {
		syslog(LOG_ERR, "start transaction failed - %s",
		    scf_strerror(scf_error()));
		ret = NPIV_ERROR;
		goto out;
	}

	valueSet = (scf_value_t **)calloc(1, sizeof (*valueSet)
	    * (lastAlloc = PORT_LIST_ALLOC));
	if (valueSet == NULL) {
		ret = NPIV_ERROR_NOMEM;
		goto out;
	}

	if (createProp) {
		if (scf_transaction_property_new(tran, entry, NPIV_PORT_LIST,
		    SCF_TYPE_USTRING) == -1) {
			if (scf_error() == SCF_ERROR_EXISTS) {
				ret = NPIV_ERROR_EXISTS;
			} else {
				syslog(LOG_ERR,
				    "transaction property new failed - %s",
				    scf_strerror(scf_error()));
				ret = NPIV_ERROR;
			}
			goto out;
		}
	} else {
		if (scf_transaction_property_change(tran, entry,
		    NPIV_PORT_LIST, SCF_TYPE_USTRING) == -1) {
			syslog(LOG_ERR,
			    "transaction property change failed - %s",
			    scf_strerror(scf_error()));
			ret = NPIV_ERROR;
			goto out;
		}

		if (scf_pg_get_property(pg, NPIV_PORT_LIST, prop) == -1) {
			syslog(LOG_ERR, "get property failed - %s",
			    scf_strerror(scf_error()));
			ret = NPIV_ERROR;
			goto out;
		}

		valueLookup = scf_value_create(handle);
		if (valueLookup == NULL) {
			syslog(LOG_ERR, "scf value alloc failed - %s",
			    scf_strerror(scf_error()));
			ret = NPIV_ERROR;
			goto out;
		}

		if (scf_iter_property_values(valueIter, prop) == -1) {
			syslog(LOG_ERR, "iter value failed - %s",
			    scf_strerror(scf_error()));
			ret = NPIV_ERROR;
			goto out;
		}

		while (scf_iter_next_value(valueIter, valueLookup) == 1) {
			bzero(buf, sizeof (buf));
			if (scf_value_get_ustring(valueLookup,
			    buf, MAXNAMELEN) == -1) {
				syslog(LOG_ERR, "iter value failed - %s",
				    scf_strerror(scf_error()));
				ret = NPIV_ERROR;
				break;
			}

			if ((strlen(buf) >= strlen(memberName)) &&
			    bcmp(buf, memberName, strlen(memberName)) == 0) {
				if (addRemoveFlag == NPIV_ADD) {
					ret = NPIV_ERROR_EXISTS;
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
				ret = NPIV_ERROR;
				break;
			}

			if (scf_value_set_ustring(valueSet[i], buf) == -1) {
				syslog(LOG_ERR, "set value failed - %s",
				    scf_strerror(scf_error()));
				ret = NPIV_ERROR;
				break;
			}

			if (scf_entry_add_value(entry, valueSet[i]) == -1) {
				syslog(LOG_ERR, "add value failed - %s",
				    scf_strerror(scf_error()));
				ret = NPIV_ERROR;
				break;
			}

			i++;

			if (i >= lastAlloc) {
				lastAlloc += PORT_LIST_ALLOC;
				valueSet = realloc(valueSet,
				    sizeof (*valueSet) * lastAlloc);
				if (valueSet == NULL) {
					ret = NPIV_ERROR;
					break;
				}
			}
		}
	}

	valueArraySize = i;
	if (!found && (addRemoveFlag == NPIV_REMOVE)) {
		ret = NPIV_ERROR_MEMBER_NOT_FOUND;
	}
	if (ret != NPIV_SUCCESS) {
		goto out;
	}

	if (addRemoveFlag == NPIV_ADD) {
		/*
		 * Now create the new entry
		 */
		valueSet[i] = scf_value_create(handle);
		if (valueSet[i] == NULL) {
			syslog(LOG_ERR, "scf value alloc failed - %s",
			    scf_strerror(scf_error()));
			ret = NPIV_ERROR;
			goto out;
		} else {
			valueArraySize++;
		}

		/*
		 * Set the new member name
		 */
		if (scf_value_set_ustring(valueSet[i], memberName) == -1) {
			syslog(LOG_ERR, "set value failed - %s",
			    scf_strerror(scf_error()));
			ret = NPIV_ERROR;
			goto out;
		}

		/*
		 * Add the new member
		 */
		if (scf_entry_add_value(entry, valueSet[i]) == -1) {
			syslog(LOG_ERR, "add value failed - %s",
			    scf_strerror(scf_error()));
			ret = NPIV_ERROR;
			goto out;
		}
	}

	if ((commitRet = scf_transaction_commit(tran)) != 1) {
		syslog(LOG_ERR, "transaction commit failed - %s",
		    scf_strerror(scf_error()));
		if (commitRet == 0) {
			ret = NPIV_ERROR_BUSY;
		} else {
			ret = NPIV_ERROR;
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

static int
retrieveNPIVAttrs(HBA_HANDLE handle, HBA_WWN portWWN,
    HBA_PORTNPIVATTRIBUTES *npivattrs, HBA_UINT32 *portIndex) {
	HBA_STATUS		status;
	HBA_ADAPTERATTRIBUTES	attrs;
	HBA_PORTATTRIBUTES	portattrs;
	int			portCtr;
	int			times = 0;

	/* argument checking */
	if (npivattrs == NULL || portIndex == NULL) {
		return (1);
	}

	memset(&attrs, 0, sizeof (HBA_ADAPTERATTRIBUTES));
	status = HBA_GetAdapterAttributes(handle, &attrs);
	while ((status == HBA_STATUS_ERROR_TRY_AGAIN ||
	    status == HBA_STATUS_ERROR_BUSY) &&
	    times++ < 130) {
		status = HBA_GetAdapterAttributes(handle, &attrs);
		if (status == HBA_STATUS_OK) {
			break;
		}
		(void) sleep(1);
	}
	if (status != HBA_STATUS_OK) {
		return (1);
	}

	memset(&portattrs, 0, sizeof (HBA_PORTATTRIBUTES));
	for (portCtr = 0; portCtr < attrs.NumberOfPorts; portCtr++) {
		status = HBA_GetAdapterPortAttributes(handle,
		    portCtr, &portattrs);
		times = 0;
		while ((status == HBA_STATUS_ERROR_TRY_AGAIN ||
		    status == HBA_STATUS_ERROR_BUSY) &&
		    times++ < HBA_MAX_RETRIES) {
			status = HBA_GetAdapterPortAttributes(handle,
			    portCtr, &portattrs);
			if (status == HBA_STATUS_OK) {
				break;
			}
			(void) sleep(1);
		}

		if (status != HBA_STATUS_OK) {
			return (1);
		}

		if (memcmp(portWWN.wwn, portattrs.PortWWN.wwn,
		    sizeof (portattrs.PortWWN.wwn)) == 0) {
			break;
		}
	}
	if (portCtr >= attrs.NumberOfPorts) {
		*portIndex = 0;
		return (1);
	}
	*portIndex = portCtr;

	status = Sun_HBA_GetPortNPIVAttributes(handle, portCtr, npivattrs);
	times = 0;
	while ((status == HBA_STATUS_ERROR_TRY_AGAIN ||
	    status == HBA_STATUS_ERROR_BUSY) &&
	    times++ < HBA_MAX_RETRIES) {
		status = Sun_HBA_GetPortNPIVAttributes(handle,
		    portCtr, npivattrs);
		if (status == HBA_STATUS_OK) {
			break;
		}
		(void) sleep(1);
	}
	if (status != HBA_STATUS_OK) {
		return (1);
	}

	return (0);
}


int
fc_util_delete_npivport(int wwnCount, char **wwn_argv,
    cmdOptions_t *options)
{
	uint64_t	physicalportWWN, virtualportWWN;
	HBA_WWN		portWWN, vportWWN;
	HBA_STATUS	status;
	HBA_HANDLE	handle;
	HBA_PORTNPIVATTRIBUTES	npivattrs;
	HBA_UINT32	portIndex;
	char		pwwn[17];
	int		times;

	if (wwnCount != 1) {
		fprintf(stderr,
		    gettext("Invalid Parameter\n"));
		return (1);
	}

	for (; options->optval; options++) {
		switch (options->optval) {
		case 'p':
			if (!isValidWWN(options->optarg)) {
				fprintf(stderr,
				    gettext("Invalid Port WWN\n"));
				return (1);
			}
			sscanf(options->optarg, "%016llx", &virtualportWWN);
			break;
		default:
			return (1);
		}
	}

	if (!isValidWWN(wwn_argv[0])) {
		fprintf(stderr,
		    gettext("Invalid Physical Port WWN\n"));
		return (1);
	}

	if ((status = HBA_LoadLibrary()) != HBA_STATUS_OK) {
		fprintf(stderr,
		    gettext("Failed to load FC-HBA common library\n"));
		printStatus(status);
		fprintf(stderr, "\n");
		return (1);
	}
	sscanf(wwn_argv[0], "%016llx", &physicalportWWN);
	physicalportWWN = htonll(physicalportWWN);
	memcpy(portWWN.wwn, &physicalportWWN, sizeof (physicalportWWN));

	virtualportWWN = htonll(virtualportWWN);
	memcpy(vportWWN.wwn, &virtualportWWN, sizeof (virtualportWWN));

	status = HBA_OpenAdapterByWWN(&handle, portWWN);
	if (status != HBA_STATUS_OK) {
		fprintf(stderr,
		    gettext("Error: HBA port %s: not found\n"),
		    wwn_argv[0]);
		HBA_FreeLibrary();
		return (1);
	}

	/* Get physical port NPIV attributes */
	if (retrieveNPIVAttrs(handle, portWWN, &npivattrs, &portIndex) == 0) {
		/* Check port NPIV attributes */
		if (npivattrs.MaxNumberOfNPIVPorts == 0) {
			fprintf(stderr,
			    gettext("Error: NPIV not Supported\n"));
			HBA_CloseAdapter(handle);
			HBA_FreeLibrary();
			return (1);
		}

		/* Delete a virtual port */
		status = Sun_HBA_DeleteNPIVPort(handle, portIndex,
		    vportWWN);
		times = 0;
		while ((status == HBA_STATUS_ERROR_TRY_AGAIN ||
		    status == HBA_STATUS_ERROR_BUSY) &&
		    times++ < HBA_MAX_RETRIES) {
			(void) sleep(1);
			status = Sun_HBA_DeleteNPIVPort(handle, portIndex,
			    vportWWN);
			if (status == HBA_STATUS_OK) {
				break;
			}
		}
		if (status != HBA_STATUS_OK) {
			fprintf(stderr,
			    gettext("Error: failed to delete a npiv port\n"));
			HBA_CloseAdapter(handle);
			HBA_FreeLibrary();
			return (1);
		}
	} else {
		fprintf(stderr,
		    gettext("Error: failed to get port NPIV attributes\n"));
		HBA_CloseAdapter(handle);
		HBA_FreeLibrary();
		return (1);
	}

	HBA_CloseAdapter(handle);
	HBA_FreeLibrary();

	WWN2str(pwwn, &vportWWN);
	npivAddRemoveNPIVEntry(wwn_argv[0],
	    NULL, pwwn, 0, NPIV_REMOVE);

	return (0);
}

int
fc_util_create_npivport(int wwnCount,
    char **wwn_argv, cmdOptions_t *options)
{
	uint64_t	physicalportWWN, virtualnodeWWN, virtualportWWN;
	HBA_WWN		portWWN, vnodeWWN, vportWWN;
	HBA_STATUS	status;
	HBA_HANDLE	handle;
	HBA_PORTNPIVATTRIBUTES	npivattrs;
	HBA_UINT32	portIndex;
	HBA_UINT32	npivportIndex = 0;
	char		nwwn[17], pwwn[17];
	int		randomflag = 0;
	int		times;

	if (wwnCount != 1) {
		fprintf(stderr,
		    gettext("Invalid Parameter\n"));
		return (1);
	}

	for (; options->optval; options++) {
		switch (options->optval) {
		case 'p':
			if (!isValidWWN(options->optarg)) {
				fprintf(stderr,
				    gettext("Invalid Port WWN\n"));
				return (1);
			}
			sscanf(options->optarg, "%016llx", &virtualportWWN);
			randomflag++;
			break;
		case 'n':
			if (!isValidWWN(options->optarg)) {
				fprintf(stderr,
				    gettext("Invalid Node WWN\n"));
				return (1);
			}
			sscanf(options->optarg, "%016llx", &virtualnodeWWN);
			randomflag++;
			break;
		default:
			return (1);
		}
	}

	if (!isValidWWN(wwn_argv[0])) {
		fprintf(stderr,
		    gettext("Invalid Physical Port WWN\n"));
		wwnCount = 0;
		return (1);
	}

	if ((status = HBA_LoadLibrary()) != HBA_STATUS_OK) {
		fprintf(stderr,
		    gettext("Failed to load FC-HBA common library\n"));
		printStatus(status);
		fprintf(stderr, "\n");
		return (1);
	}

	sscanf(wwn_argv[0], "%016llx", &physicalportWWN);
	physicalportWWN = htonll(physicalportWWN);
	memcpy(portWWN.wwn, &physicalportWWN, sizeof (physicalportWWN));

	status = HBA_OpenAdapterByWWN(&handle, portWWN);
	if (status != HBA_STATUS_OK) {
		fprintf(stderr,
		    gettext("Error: HBA port %s: not found\n"),
		    wwn_argv[0]);
		HBA_FreeLibrary();
		return (1);
	}

	if (randomflag != 2) {
		status = Sun_HBA_AdapterCreateWWN(handle, 0,
		    &vnodeWWN, &vportWWN, NULL, HBA_CREATE_WWN_RANDOM);
		if (status != HBA_STATUS_OK) {
			fprintf(stderr,
			    gettext("Error: Fail to get Random WWN\n"));
			HBA_CloseAdapter(handle);
			HBA_FreeLibrary();
			return (1);
		}
	} else {
		virtualnodeWWN = htonll(virtualnodeWWN);
		memcpy(vnodeWWN.wwn, &virtualnodeWWN, sizeof (virtualnodeWWN));
		virtualportWWN = htonll(virtualportWWN);
		memcpy(vportWWN.wwn, &virtualportWWN, sizeof (virtualportWWN));
	}

	if (memcmp(vnodeWWN.wwn, vportWWN.wwn, 8) == 0) {
		fprintf(stderr,
		    gettext("Error: Port WWN is same as Node WWN\n"));
		HBA_CloseAdapter(handle);
		HBA_FreeLibrary();
		return (1);
	}

	/* Get physical port NPIV attributes */
	if (retrieveNPIVAttrs(handle, portWWN, &npivattrs, &portIndex) == 0) {
		/* Check port NPIV attributes */
		if (npivattrs.MaxNumberOfNPIVPorts == 0) {
			fprintf(stderr,
			    gettext("Error: NPIV not Supported\n"));
			HBA_CloseAdapter(handle);
			HBA_FreeLibrary();
			return (1);
		}
		if (npivattrs.MaxNumberOfNPIVPorts ==
		    npivattrs.NumberOfNPIVPorts) {
			fprintf(stderr,
			    gettext("Error: Can not create more NPIV port\n"));
			HBA_CloseAdapter(handle);
			HBA_FreeLibrary();
			return (1);
		}

		/* Create a virtual port */
		status = Sun_HBA_CreateNPIVPort(handle, portIndex,
		    vnodeWWN, vportWWN, &npivportIndex);
		times = 0;
		while ((status == HBA_STATUS_ERROR_TRY_AGAIN ||
		    status == HBA_STATUS_ERROR_BUSY) &&
		    times++ < HBA_MAX_RETRIES) {
			(void) sleep(1);
			status = Sun_HBA_CreateNPIVPort(handle, portIndex,
			    vnodeWWN, vportWWN, &npivportIndex);
			if (status == HBA_STATUS_OK) {
				break;
			}
		}

		if (status != HBA_STATUS_OK) {
			fprintf(stderr,
			    gettext("Error: failed to create a npiv port\n"));
			HBA_CloseAdapter(handle);
			HBA_FreeLibrary();
			return (1);
		}
	} else {
		fprintf(stderr,
		    gettext("Error: failed to get port NPIV attributes\n"));
		HBA_CloseAdapter(handle);
		HBA_FreeLibrary();
		return (1);
	}

	HBA_CloseAdapter(handle);
	HBA_FreeLibrary();

	WWN2str(nwwn, &vnodeWWN);
	WWN2str(pwwn, &vportWWN);
	npivAddRemoveNPIVEntry(wwn_argv[0],
	    nwwn, pwwn, npivportIndex, NPIV_ADD);

	return (0);
}

int
create_npivport(char *ppwwn_str, char *vnwwn_str,
    char *vpwwn_str, int vindex)
{
	uint64_t	physicalportWWN, virtualnodeWWN, virtualportWWN;
	HBA_WWN		portWWN, vnodeWWN, vportWWN;
	HBA_STATUS	status;
	HBA_HANDLE	handle;
	HBA_PORTNPIVATTRIBUTES	npivattrs;
	HBA_UINT32	portIndex;
	HBA_UINT32	npivportIndex;
	int		times = 0;

	sscanf(ppwwn_str, "%016llx", &physicalportWWN);
	physicalportWWN = htonll(physicalportWWN);
	memcpy(portWWN.wwn, &physicalportWWN, sizeof (physicalportWWN));
	sscanf(vnwwn_str, "%016llx", &virtualnodeWWN);
	virtualnodeWWN = htonll(virtualnodeWWN);
	memcpy(vnodeWWN.wwn, &virtualnodeWWN, sizeof (virtualnodeWWN));
	sscanf(vpwwn_str, "%016llx", &virtualportWWN);
	virtualportWWN = htonll(virtualportWWN);
	memcpy(vportWWN.wwn, &virtualportWWN, sizeof (virtualportWWN));
	npivportIndex = vindex;

	status = HBA_OpenAdapterByWWN(&handle, portWWN);
	while (status == HBA_STATUS_ERROR_TRY_AGAIN ||
	    status == HBA_STATUS_ERROR_BUSY) {
		(void) sleep(FCADM_SLEEP_TIME);
		status = HBA_OpenAdapterByWWN(&handle, portWWN);
		if (times++ > FCADM_RETRY_TIMES) {
			return (1);
		}
	}

	/* Get physical port NPIV attributes */
	if (retrieveNPIVAttrs(handle, portWWN,
	    &npivattrs, &portIndex) == 0) {
		/* Check port NPIV attributes */
		if (npivattrs.MaxNumberOfNPIVPorts == 0) {
			goto failed;
		}
		if (npivattrs.MaxNumberOfNPIVPorts ==
		    npivattrs.NumberOfNPIVPorts) {
			goto failed;
		}

		/* Create a virtual port */
		status = Sun_HBA_CreateNPIVPort(handle, portIndex,
		    vnodeWWN, vportWWN, &npivportIndex);
		times = 0;
		while (status == HBA_STATUS_ERROR_TRY_AGAIN ||
		    status == HBA_STATUS_ERROR_BUSY) {
			(void) sleep(FCADM_SLEEP_TIME);
			status = Sun_HBA_CreateNPIVPort(handle, portIndex,
			    vnodeWWN, vportWWN, &npivportIndex);
			if (times++ > FCADM_RETRY_TIMES) {
				goto failed;
			}
		}
	}

failed:
	HBA_CloseAdapter(handle);

	return (0);
}

int
fc_util_create_portlist()
{
	scf_handle_t	*handle = NULL;
	scf_service_t	*svc = NULL;
	scf_propertygroup_t	*pg = NULL;
	scf_transaction_t	*tran = NULL;
	scf_transaction_entry_t	*entry = NULL;
	scf_property_t		*prop = NULL;
	scf_value_t	*valueLookup = NULL;
	scf_iter_t	*valueIter = NULL;
	char		buf[NPIV_PORT_LIST_LENGTH] = {0};
	int		commitRet;

	commitRet = cfgInit(&handle, &svc);
	if (commitRet != NPIV_SUCCESS) {
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
	if (scf_service_get_pg(svc, NPIV_PG_NAME, pg) == -1) {
		goto out;
	}

	if (scf_pg_get_property(pg, NPIV_PORT_LIST, prop) == -1) {
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

	if (HBA_LoadLibrary() != HBA_STATUS_OK) {
		goto out;
	}
	HBA_GetNumberOfAdapters();

	while (scf_iter_next_value(valueIter, valueLookup) == 1) {
		char ppwwn[17] = {0};
		char vnwwn[17] = {0};
		char vpwwn[17] = {0};
		int vindex = 0;

		bzero(buf, sizeof (buf));
		if (scf_value_get_ustring(valueLookup, buf, MAXNAMELEN) == -1) {
			syslog(LOG_ERR, "iter value failed - %s",
			    scf_strerror(scf_error()));
			break;
		}

		sscanf(buf, "%16s:%16s:%16s:%d", ppwwn, vpwwn, vnwwn, &vindex);
		create_npivport(ppwwn, vnwwn, vpwwn, vindex);
	}

	HBA_FreeLibrary();
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
