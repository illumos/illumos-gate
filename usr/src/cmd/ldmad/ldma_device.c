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
 * Logical Domains Device Agent
 */

#include <errno.h>
#include <fcntl.h>
#include <libdladm.h>
#include <libdllink.h>
#include <libds.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "ldma.h"

#define	LDMA_MODULE	LDMA_NAME_DEVICE

#define	LDMA_NVERSIONS	(sizeof (ldma_versions) / sizeof (ds_ver_t))
#define	LDMA_NHANDLERS	(sizeof (ldma_handlers) / sizeof (ldma_msg_handler_t))

static ldm_msg_func_t ldma_dev_validate_path;
static ldm_msg_func_t ldma_dev_validate_nic;

static ds_ver_t ldma_versions[] = { { 1, 0 } };

static ldma_msg_handler_t ldma_handlers[] = {
	{ LDMA_MSGDEV_VALIDATE_PATH,	ldma_dev_validate_path },
	{ LDMA_MSGDEV_VALIDATE_NIC,	ldma_dev_validate_nic }
};

ldma_agent_info_t ldma_device_info = {
	LDMA_NAME_DEVICE,
	ldma_versions, LDMA_NVERSIONS,
	ldma_handlers, LDMA_NHANDLERS
};

/*ARGSUSED*/
static ldma_request_status_t
ldma_dev_validate_path(ds_ver_t *ver, ldma_message_header_t *request,
    size_t request_dlen, ldma_message_header_t **replyp, size_t *reply_dlenp)
{
	ldma_message_header_t *reply = NULL;
	ldma_request_status_t status;
	struct stat st;
	char *path = NULL;
	uint32_t *path_type, reply_dlen;
	uint32_t plen;
	int fd;

	plen = request->msg_info;
	if (plen == 0 || plen > MAXPATHLEN || plen > request_dlen) {
		status = LDMA_REQ_INVALID;
		goto done;
	}

	path = malloc(plen + 1);
	if (path == NULL) {
		status = LDMA_REQ_FAILED;
		goto done;
	}

	(void) strncpy(path, LDMA_HDR2DATA(request), plen);
	path[plen] = '\0';

	LDMA_DBG("VALIDATE_PATH(%s)", path);

	reply_dlen = sizeof (uint32_t);
	reply = ldma_alloc_result_msg(request, reply_dlen);
	if (reply == NULL) {
		status = LDMA_REQ_FAILED;
		goto done;
	}

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	path_type = (uint32_t *)(LDMA_HDR2DATA(reply));

	reply->msg_info = 0x0;

	/* check if path exists */
	if (stat(path, &st) != 0) {

		LDMA_DBG("VALIDATE_PATH(%s): stat failed with error %d",
		    path, errno);

		switch (errno) {

		case EACCES:
		case ELOOP:
		case ENOENT:
		case ENOLINK:
		case ENOTDIR:
			/* path is inaccessible, the request is completed */
			status = LDMA_REQ_COMPLETED;
			break;

		case ENAMETOOLONG:
			status = LDMA_REQ_INVALID;
			break;

		default:
			/* request has failed */
			status = LDMA_REQ_FAILED;
			break;
		}

		goto done;
	}

	status = LDMA_REQ_COMPLETED;

	reply->msg_info |= LDMA_DEVPATH_EXIST;

	LDMA_DBG("VALIDATE_PATH(%s): file mode = 0x%lx", path, st.st_mode);

	switch (st.st_mode & S_IFMT) {

	case S_IFREG:
		*path_type = LDMA_DEVPATH_TYPE_FILE;
		break;

	case S_IFCHR:
	case S_IFBLK:
		*path_type = LDMA_DEVPATH_TYPE_DEVICE;
		break;

	default:
		/* we don't advertise other types (fifo, directory...) */
		*path_type = 0;
	}

	/* check if path can be opened read/write */
	if ((fd = open(path, O_RDWR)) != -1) {
		reply->msg_info |= LDMA_DEVPATH_OPENRW | LDMA_DEVPATH_OPENRO;
		(void) close(fd);
	} else {
		LDMA_DBG("VALIDATE_PATH(%s): open RDWR failed with error %d",
		    path, errno);

		/* check if path can be opened read only */
		if ((fd = open(path, O_RDONLY)) != -1) {
			reply->msg_info |= LDMA_DEVPATH_OPENRO;
			(void) close(fd);
		} else {
			LDMA_DBG("VALIDATE_PATH(%s): open RDONLY failed "
			    "with error %d", path, errno);
		}
	}

done:
	if (status != LDMA_REQ_COMPLETED) {
		/*
		 * We don't provide a reply message if the request has not
		 * been completed. The LDoms agent daemon will send an
		 * appropriate reply based on the return code of this function.
		 */
		free(reply);
		reply = NULL;
		reply_dlen = 0;

		LDMA_DBG("VALIDATE_PATH(%s): return error %d",
		    (path)? path : "<none>", status);
	} else {
		LDMA_DBG("VALIDATE_PATH(%s): return status=0x%x type=0x%x",
		    path, reply->msg_info, *path_type);
	}

	free(path);
	*replyp = reply;
	*reply_dlenp = reply_dlen;

	return (status);
}

/*
 * We check that the device is a network interface (NIC) using libdladm.
 */
/*ARGSUSED*/
static ldma_request_status_t
ldma_dev_validate_nic(ds_ver_t *ver, ldma_message_header_t *request,
    size_t request_dlen, ldma_message_header_t **replyp, size_t *reply_dlenp)
{
	dladm_handle_t dlhandle;
	datalink_id_t linkid;
	uint32_t flag, media;
	datalink_class_t class;
	ldma_message_header_t *reply = NULL;
	ldma_request_status_t status;
	char *nic = NULL;
	uint32_t nlen, reply_dlen;

	nlen = request->msg_info;
	if (nlen == 0 || nlen > MAXPATHLEN || nlen > request_dlen) {
		status = LDMA_REQ_INVALID;
		goto done;
	}

	nic = malloc(nlen + 1);
	if (nic == NULL) {
		status = LDMA_REQ_FAILED;
		goto done;
	}

	(void) strncpy(nic, LDMA_HDR2DATA(request), nlen);
	nic[nlen] = '\0';

	LDMA_DBG("VALIDATE_NIC(%s)", nic);

	reply_dlen = 0;
	reply = ldma_alloc_result_msg(request, reply_dlen);
	if (reply == NULL) {
		status = LDMA_REQ_FAILED;
		goto done;
	}

	reply->msg_info = 0x0;

	if (dladm_open(&dlhandle) != DLADM_STATUS_OK) {
		status = LDMA_REQ_FAILED;
		goto done;
	}

	if (dladm_name2info(dlhandle, nic, &linkid, &flag, &class,
	    &media) != DLADM_STATUS_OK) {
		LDMA_DBG("VALIDATE_NIC(%s): name2info failed", nic);
	} else {
		LDMA_DBG("VALIDATE_NIC(%s): media=0x%x", nic, media);
		reply->msg_info = LDMA_DEVNIC_EXIST;
	}

	dladm_close(dlhandle);

	status = LDMA_REQ_COMPLETED;

done:
	if (status != LDMA_REQ_COMPLETED) {
		/*
		 * We don't provide a reply message if the request has not
		 * been completed. The LDoms agent daemon will send an
		 * appropriate reply based on the return code of this function.
		 */
		free(reply);
		reply = NULL;
		reply_dlen = 0;

		LDMA_DBG("VALIDATE_NIC(%s): return error %d",
		    (nic)? nic : "<none>", status);
	} else {
		LDMA_DBG("VALIDATE_NIC(%s): return status=0x%x",
		    nic, reply->msg_info);
	}

	free(nic);
	*replyp = reply;
	*reply_dlenp = reply_dlen;

	return (status);
}
