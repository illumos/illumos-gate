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

#include <stdlib.h>
#include <stdio.h>
#include <wchar.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <libintl.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <syslog.h>
#include <libfcoe.h>
#include <libdllink.h>
#include <fcoeio.h>
#include <libscf.h>
#include <inttypes.h>

#define	FCOE_DEV_PATH	 "/devices/fcoe:admin"

#define	OPEN_FCOE 0
#define	OPEN_EXCL_FCOE O_EXCL

/*
 * Open for fcoe module
 *
 * flag - open flag (OPEN_FCOE, OPEN_EXCL_FCOE)
 * fd - pointer to integer. On success, contains the fcoe file descriptor
 */
static int
openFcoe(int flag, int *fd)
{
	int ret = FCOE_STATUS_ERROR;

	if ((*fd = open(FCOE_DEV_PATH, O_NDELAY | O_RDONLY | flag)) != -1) {
		ret = FCOE_STATUS_OK;
	} else {
		if (errno == EPERM || errno == EACCES) {
			ret = FCOE_STATUS_ERROR_PERM;
		} else {
			ret = FCOE_STATUS_ERROR_OPEN_DEV;
		}
		syslog(LOG_DEBUG, "openFcoe:open failure:%s:errno(%d)",
		    FCOE_DEV_PATH, errno);
	}

	return (ret);
}

static void
WWN2str(char *buf, FCOE_PORT_WWN *wwn)
{
	int j;
	unsigned char *pc = (unsigned char *)&(wwn->wwn[0]);
	buf[0] = '\0';
	for (j = 0; j < 16; j += 2) {
		(void) sprintf(&buf[j], "%02X", (int)*pc++);
	}
}

static int
isWWNZero(FCOE_PORT_WWN portwwn)
{
	int i;
	int size = sizeof (FCOE_PORT_WWN);

	for (i = 0; i < size; i++) {
		if (portwwn.wwn[i] != 0) {
			return (0);
		}
	}
	return (1);
}

/*
 * Initialize scf fcoe service access
 * handle - returned handle
 * service - returned service handle
 */
static int
fcoe_cfg_scf_init(scf_handle_t **handle, scf_service_t **service, int is_target)
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

	if (scf_scope_get_service(scope,
	    is_target ? FCOE_TARGET_SERVICE: FCOE_INITIATOR_SERVICE,
	    *service) == -1) {
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
fcoe_add_remove_scf_entry(char *mac_name,
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
	int portListAlloc = 100;

	(void) snprintf(memberName, FCOE_PORT_LIST_LENGTH,
	    "%s:%s:%s:%d:%d", mac_name, pwwn, nwwn,
	    is_target, is_promiscuous);

	ret = fcoe_cfg_scf_init(&handle, &svc, is_target);
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
	    * (lastAlloc = portListAlloc));
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
			(void) strcpy(buftmp, buf);
			macnameIter = strtok(buftmp, ":");
			if (strcmp(macnameIter, mac_name) == 0) {
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
				lastAlloc += portListAlloc;
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

FCOE_STATUS
FCOE_CreatePort(
	const FCOE_UINT8		*macLinkName,
	FCOE_UINT8		portType,
	FCOE_PORT_WWN		pwwn,
	FCOE_PORT_WWN		nwwn,
	FCOE_UINT8		promiscuous)
{
	FCOE_STATUS		status;
	int			fcoe_fd;
	fcoeio_t		fcoeio;
	fcoeio_create_port_param_t	param;
	dladm_handle_t		handle;
	datalink_id_t		linkid;
	datalink_class_t	class;

	bzero(&param, sizeof (fcoeio_create_port_param_t));

	if (macLinkName == NULL) {
		return (FCOE_STATUS_ERROR_INVAL_ARG);
	}

	if (strlen((char *)macLinkName) > MAXLINKNAMELEN-1) {
		return (FCOE_STATUS_ERROR_MAC_LEN);
	}

	if (dladm_open(&handle) != DLADM_STATUS_OK) {
		return (FCOE_STATUS_ERROR);
	}

	if (dladm_name2info(handle, (const char *)macLinkName,
	    &linkid, NULL, &class, NULL) != DLADM_STATUS_OK) {
		dladm_close(handle);
		(void) fcoe_add_remove_scf_entry((char *)macLinkName,
		    "",
		    "",
		    portType,
		    0,
		    FCOE_SCF_REMOVE);
		return (FCOE_STATUS_ERROR_GET_LINKINFO);
	}
	dladm_close(handle);

	if (class != DATALINK_CLASS_PHYS) {
		return (FCOE_STATUS_ERROR_CLASS_UNSUPPORT);
	}

	if (portType != FCOE_PORTTYPE_INITIATOR &&
	    portType != FCOE_PORTTYPE_TARGET) {
		return (FCOE_STATUS_ERROR_INVAL_ARG);
	}

	if (!isWWNZero(pwwn)) {
		param.fcp_pwwn_provided = 1;
		bcopy(pwwn.wwn, param.fcp_pwwn, 8);
	}

	if (!isWWNZero(nwwn)) {
		param.fcp_nwwn_provided = 1;
		bcopy(nwwn.wwn, param.fcp_nwwn, 8);
	}

	if (param.fcp_pwwn_provided == 1 &&
	    param.fcp_nwwn_provided == 1 &&
	    bcmp(&pwwn, &nwwn, 8) == 0) {
		return (FCOE_STATUS_ERROR_WWN_SAME);
	}

	param.fcp_force_promisc = promiscuous;
	param.fcp_mac_linkid = linkid;
	param.fcp_port_type = (fcoe_cli_type_t)portType;

	if ((status = openFcoe(OPEN_FCOE, &fcoe_fd)) != FCOE_STATUS_OK) {
		return (status);
	}

	(void) memset(&fcoeio, 0, sizeof (fcoeio));
	fcoeio.fcoeio_cmd = FCOEIO_CREATE_FCOE_PORT;

	fcoeio.fcoeio_ilen = sizeof (param);
	fcoeio.fcoeio_xfer = FCOEIO_XFER_WRITE;
	fcoeio.fcoeio_ibuf = (uintptr_t)&param;

	if (ioctl(fcoe_fd, FCOEIO_CMD, &fcoeio) != 0) {
		switch (fcoeio.fcoeio_status) {
		case FCOEIOE_INVAL_ARG:
			status = FCOE_STATUS_ERROR_INVAL_ARG;
			break;

		case FCOEIOE_BUSY:
			status = FCOE_STATUS_ERROR_BUSY;
			break;

		case FCOEIOE_ALREADY:
			status = FCOE_STATUS_ERROR_ALREADY;
			break;

		case FCOEIOE_PWWN_CONFLICTED:
			status = FCOE_STATUS_ERROR_PWWN_CONFLICTED;
			break;

		case FCOEIOE_NWWN_CONFLICTED:
			status = FCOE_STATUS_ERROR_NWWN_CONFLICTED;
			break;

		case FCOEIOE_CREATE_MAC:
			status = FCOE_STATUS_ERROR_CREATE_MAC;
			break;

		case FCOEIOE_OPEN_MAC:
			status = FCOE_STATUS_ERROR_OPEN_MAC;
			break;

		case FCOEIOE_CREATE_PORT:
			status = FCOE_STATUS_ERROR_CREATE_PORT;
			break;

		case FCOEIOE_NEED_JUMBO_FRAME:
			status = FCOE_STATUS_ERROR_NEED_JUMBO_FRAME;
			break;

		default:
			status = FCOE_STATUS_ERROR;
		}
	} else {
		char cpwwn[17], cnwwn[17];

		WWN2str(cpwwn, &pwwn);
		WWN2str(cnwwn, &nwwn);

		(void) fcoe_add_remove_scf_entry((char *)macLinkName,
		    cpwwn,
		    cnwwn,
		    portType,
		    promiscuous,
		    FCOE_SCF_ADD);
		status = FCOE_STATUS_OK;
	}
	(void) close(fcoe_fd);
	return (status);
}

FCOE_STATUS
FCOE_DeletePort(const FCOE_UINT8 *macLinkName)
{
	FCOE_STATUS status = FCOE_STATUS_OK;
	int fcoe_fd;
	fcoeio_t	fcoeio;
	dladm_handle_t		handle;
	datalink_id_t		linkid;
	fcoeio_delete_port_param_t fc_del_port;
	uint64_t	is_target = 0;
	int		io_ret = 0;

	if (macLinkName == NULL) {
		return (FCOE_STATUS_ERROR_INVAL_ARG);
	}

	if (strlen((char *)macLinkName) > MAXLINKNAMELEN-1) {
		return (FCOE_STATUS_ERROR_MAC_LEN);
	}
	if (dladm_open(&handle) != DLADM_STATUS_OK) {
		return (FCOE_STATUS_ERROR);
	}

	if (dladm_name2info(handle, (const char *)macLinkName,
	    &linkid, NULL, NULL, NULL) != DLADM_STATUS_OK) {
		dladm_close(handle);
		return (FCOE_STATUS_ERROR_GET_LINKINFO);
	}
	dladm_close(handle);

	if ((status = openFcoe(OPEN_FCOE, &fcoe_fd)) != FCOE_STATUS_OK) {
		return (status);
	}

	fc_del_port.fdp_mac_linkid = linkid;

	(void) memset(&fcoeio, 0, sizeof (fcoeio));
	fcoeio.fcoeio_cmd = FCOEIO_DELETE_FCOE_PORT;

	/* only 4 bytes here, need to change */
	fcoeio.fcoeio_ilen = sizeof (fcoeio_delete_port_param_t);
	fcoeio.fcoeio_olen = sizeof (uint64_t);
	fcoeio.fcoeio_xfer = FCOEIO_XFER_RW;
	fcoeio.fcoeio_ibuf = (uintptr_t)&fc_del_port;
	fcoeio.fcoeio_obuf = (uintptr_t)&is_target;

	io_ret = ioctl(fcoe_fd, FCOEIO_CMD, &fcoeio);
	if (io_ret != 0) {
		switch (fcoeio.fcoeio_status) {
		case FCOEIOE_INVAL_ARG:
			status = FCOE_STATUS_ERROR_INVAL_ARG;
			break;

		case FCOEIOE_BUSY:
			status = FCOE_STATUS_ERROR_BUSY;
			break;

		case FCOEIOE_ALREADY:
			status = FCOE_STATUS_ERROR_ALREADY;
			break;

		case FCOEIOE_MAC_NOT_FOUND:
			status = FCOE_STATUS_ERROR_MAC_NOT_FOUND;
			break;

		case FCOEIOE_OFFLINE_FAILURE:
			status = FCOE_STATUS_ERROR_OFFLINE_DEV;
			break;

		default:
			status = FCOE_STATUS_ERROR;
		}
	} else {
		(void) fcoe_add_remove_scf_entry((char *)macLinkName,
		    "",
		    "",
		    is_target,
		    0,
		    FCOE_SCF_REMOVE);
		status = FCOE_STATUS_OK;
	}

	if (io_ret == FCOEIOE_MAC_NOT_FOUND) {
		(void) fcoe_add_remove_scf_entry((char *)macLinkName,
		    "",
		    "",
		    0,
		    0,
		    FCOE_SCF_REMOVE);
		(void) fcoe_add_remove_scf_entry((char *)macLinkName,
		    "",
		    "",
		    1,
		    0,
		    FCOE_SCF_REMOVE);
	}
	(void) close(fcoe_fd);
	return (status);
}

FCOE_STATUS
FCOE_GetPortList(
	FCOE_UINT32		*port_num,
	FCOE_PORT_ATTRIBUTE	**portlist)
{
	FCOE_STATUS	status = FCOE_STATUS_OK;
	int		fcoe_fd;
	fcoeio_t	fcoeio;
	fcoe_port_list_t	*inportlist = NULL;
	FCOE_PORT_ATTRIBUTE	*outportlist = NULL;
	int		i;
	int		size = 64; /* default first attempt */
	int		retry = 0;
	int		bufsize;
	dladm_handle_t	handle;
	char		mac_name[MAXLINKNAMELEN];

	if (port_num == NULL || portlist == NULL) {
		return (FCOE_STATUS_ERROR_INVAL_ARG);
	}
	*port_num = 0;

	if ((status = openFcoe(OPEN_FCOE, &fcoe_fd)) != FCOE_STATUS_OK) {
		return (status);
	}

	/* Get fcoe port list */
	(void) memset(&fcoeio, 0, sizeof (fcoeio));
	retry = 0;

	do {
		bufsize = sizeof (fcoe_port_instance_t) * (size - 1) +
		    sizeof (fcoe_port_list_t);
		inportlist = (fcoe_port_list_t *)malloc(bufsize);
		fcoeio.fcoeio_cmd = FCOEIO_GET_FCOE_PORT_LIST;
		fcoeio.fcoeio_olen = bufsize;
		fcoeio.fcoeio_xfer = FCOEIO_XFER_READ;
		fcoeio.fcoeio_obuf = (uintptr_t)inportlist;

		if (ioctl(fcoe_fd, FCOEIO_CMD, &fcoeio) != 0) {
			if (fcoeio.fcoeio_status == FCOEIOE_MORE_DATA) {
				size = inportlist->numPorts;
			}
			free(inportlist);
			switch (fcoeio.fcoeio_status) {
			case FCOEIOE_INVAL_ARG:
				status = FCOE_STATUS_ERROR_INVAL_ARG;
				(void) close(fcoe_fd);
				return (status);

			case FCOEIOE_BUSY:
				status = FCOE_STATUS_ERROR_BUSY;
				retry++;
				break;

			case FCOEIOE_MORE_DATA:
				status = FCOE_STATUS_ERROR_MORE_DATA;
				retry++;
				break;

			default:
				status = FCOE_STATUS_ERROR;
				(void) close(fcoe_fd);
				return (status);
			}
		} else {
			status = FCOE_STATUS_OK;
			break;
		}
	} while (retry <= 3 && status != FCOE_STATUS_OK);

	if (status == FCOE_STATUS_OK && inportlist->numPorts > 0) {
		if (dladm_open(&handle) != DLADM_STATUS_OK) {
			handle = NULL;
		}

		outportlist = (PFCOE_PORT_ATTRIBUTE)
		    malloc(sizeof (FCOE_PORT_ATTRIBUTE) * inportlist->numPorts);

		for (i = 0; i < inportlist->numPorts; i++) {
			fcoe_port_instance_t *pi = &inportlist->ports[i];
			FCOE_PORT_ATTRIBUTE *po = &outportlist[i];
			bcopy(pi->fpi_pwwn, &po->port_wwn, 8);

			if (handle == NULL ||
			    dladm_datalink_id2info(handle, pi->fpi_mac_linkid,
			    NULL, NULL, NULL, mac_name, sizeof (mac_name))
			    != DLADM_STATUS_OK) {
				(void) strcpy((char *)po->mac_link_name,
				    "<unknown>");
			} else {
				(void) strcpy((char *)po->mac_link_name,
				    mac_name);
			}
			bcopy(pi->fpi_mac_factory_addr,
			    po->mac_factory_addr, 6);
			bcopy(pi->fpi_mac_current_addr,
			    po->mac_current_addr, 6);
			po->port_type = (FCOE_UINT8)pi->fpi_port_type;
			po->mtu_size = pi->fpi_mtu_size;
			po->mac_promisc = pi->fpi_mac_promisc;
		}

		if (handle != NULL) {
			dladm_close(handle);
		}
		*port_num = inportlist->numPorts;
		*portlist = outportlist;
		free(inportlist);
	} else {
		*port_num = 0;
		*portlist = NULL;
	}
	(void) close(fcoe_fd);
	return (status);
}

FCOE_STATUS FCOE_LoadConfig(
	FCOE_UINT8		portType,
    FCOE_SMF_PORT_LIST **portlist)
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
	FCOE_UINT32	portIndex;
	int		bufsize, retry;
	int		size = 10; /* default first attempt */
	int		pg_or_prop_not_found = 0;

	commitRet = fcoe_cfg_scf_init(&handle, &svc, portType);
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

	if (scf_service_get_pg(svc, FCOE_PG_NAME, pg) == -1) {
		pg_or_prop_not_found = 1;
		goto out;
	}

	if (scf_pg_get_property(pg, FCOE_PORT_LIST, prop) == -1) {
		pg_or_prop_not_found = 1;
		goto out;
	}

	valueLookup = scf_value_create(handle);
	if (valueLookup == NULL) {
		syslog(LOG_ERR, "scf value alloc failed - %s",
		    scf_strerror(scf_error()));
		goto out;
	}

	portIndex = 0;

	do {
		if (scf_iter_property_values(valueIter, prop) == -1) {
			syslog(LOG_ERR, "iter value failed - %s",
			    scf_strerror(scf_error()));
			goto out;
		}

		retry = 0;
		bufsize = sizeof (FCOE_SMF_PORT_INSTANCE) * (size - 1) +
		    sizeof (FCOE_SMF_PORT_LIST);
		*portlist = (PFCOE_SMF_PORT_LIST)malloc(bufsize);

		while (scf_iter_next_value(valueIter, valueLookup) == 1) {
			uint8_t *macLinkName = NULL;
			char *remainder = NULL;
			uint64_t	nodeWWN, portWWN;
			int is_target, is_promiscuous;

			bzero(buf, sizeof (buf));
			if (scf_value_get_ustring(valueLookup, buf,
			    MAXNAMELEN) == -1) {
				syslog(LOG_ERR, "iter value failed - %s",
				    scf_strerror(scf_error()));
				break;
			}
			macLinkName = (uint8_t *)strtok(buf, ":");
			remainder = strtok(NULL, "#");
			(void) sscanf(remainder,
			    "%016" PRIx64 ":%016" PRIx64 ":%d:%d",
			    &portWWN, &nodeWWN, &is_target, &is_promiscuous);

			if (portIndex >= size) {
				free(*portlist);
				retry = 1;
				size *= 2;
				break;
			} else {
				PFCOE_SMF_PORT_INSTANCE pi =
				    &(*portlist)->ports[portIndex++];
				(void) strcpy((char *)pi->mac_link_name,
				    (char *)macLinkName);
				pi->port_type = is_target ?
				    FCOE_PORTTYPE_TARGET:
				    FCOE_PORTTYPE_INITIATOR;
				portWWN = htonll(portWWN);
				nodeWWN = htonll(nodeWWN);
				(void) memcpy(&pi->port_pwwn, &portWWN,
				    sizeof (FCOE_PORT_WWN));
				(void) memcpy(&pi->port_nwwn, &nodeWWN,
				    sizeof (FCOE_PORT_WWN));
				pi->mac_promisc = is_promiscuous;
			}
		}

		(*portlist)->port_num = portIndex;
	} while (retry == 1);

	return (FCOE_STATUS_OK);
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

	if (pg_or_prop_not_found == 1) {
		return (FCOE_STATUS_OK);
	} else {
		return (FCOE_STATUS_ERROR);
	}
}
