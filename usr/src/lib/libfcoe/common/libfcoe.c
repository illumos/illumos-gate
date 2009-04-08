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

FCOE_STATUS
FCOE_CreatePort(
	const FCOE_UINT8		*macLinkName,
	FCOE_UINT8		portType,
	FCOE_PORT_WWN		pwwn,
	FCOE_PORT_WWN		nwwn,
	FCOE_UINT8		promiscuous)
{
	FCOE_STATUS		status = FCOE_STATUS_OK;
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
	fcoeio.fcoeio_xfer = FCOEIO_XFER_WRITE;
	fcoeio.fcoeio_ibuf = (uintptr_t)&fc_del_port;

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
		status = FCOE_STATUS_OK;
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
			default:
				status = FCOE_STATUS_ERROR;
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
