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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <door.h>
#include <errno.h>
#include <strings.h>
#include <sys/mman.h>
#include <libdladm.h>
#include <libdlib.h>
#include <libdllink.h>

extern dladm_status_t	dladm_door_fd(dladm_handle_t, int *);

static dladm_status_t
ibd_dladm_door_call(dladm_handle_t handle, void *arg, size_t asize, void *rbuf,
    size_t rsize)
{
	door_arg_t	darg;
	int		door_fd;
	dladm_status_t	status = DLADM_STATUS_OK;

	darg.data_ptr	= arg;
	darg.data_size	= asize;
	darg.desc_ptr	= NULL;
	darg.desc_num	= 0;
	darg.rbuf	= rbuf;
	darg.rsize	= rsize;

	/* The door descriptor is opened if it isn't already */
	if ((status = dladm_door_fd(handle, &door_fd)) != DLADM_STATUS_OK)
		return (status);

	if (door_call(door_fd, &darg) == -1)
		return (DLADM_STATUS_FAILED);

	if (darg.rbuf != rbuf) {
		/*
		 * The size of the input rbuf is not big enough so that
		 * the door allocate the rbuf itself. In this case, simply
		 * think something wrong with the door call.
		 */
		(void) munmap(darg.rbuf, darg.rsize);
		return (DLADM_STATUS_TOOSMALL);
	}

	if (darg.rsize != rsize)
		return (DLADM_STATUS_FAILED);

	if ((((dlmgmt_retval_t *)rbuf)->lr_err) == 0)
		return (DLADM_STATUS_OK);
	else
		return (DLADM_STATUS_FAILED);
}

static int
ibd_delete_link(dladm_handle_t dlh, char *link)
{
	dlmgmt_door_getlinkid_t		getlinkid;
	dlmgmt_getlinkid_retval_t	retval;
	datalink_id_t			linkid;
	dladm_status_t			status;
	char				errmsg[DLADM_STRSIZE];

	getlinkid.ld_cmd = DLMGMT_CMD_GETLINKID;
	(void) strlcpy(getlinkid.ld_link, link, MAXLINKNAMELEN);

	if ((status = ibd_dladm_door_call(dlh, &getlinkid, sizeof (getlinkid),
	    &retval, sizeof (retval))) != DLADM_STATUS_OK) {
		(void) fprintf(stderr,
		    "dladm_door_call failed: %s; linkname = %s\n",
		    dladm_status2str(status, errmsg), link);
		return (status);
	}

	if (retval.lr_class != DATALINK_CLASS_PHYS) {
		(void) fprintf(stderr,
		    "Not a physical link: linkname = %s, class = 0x%x\n",
		    link, (uint_t)retval.lr_class);
		return (status);
	}

	linkid = retval.lr_linkid;

	if ((status = dladm_remove_conf(dlh, linkid)) != DLADM_STATUS_OK) {
		(void) fprintf(stderr, "dladm_remove_conf failed: %s\n",
		    dladm_status2str(status, errmsg));
		return (status);
	}

	if ((status = dladm_destroy_datalink_id(dlh, linkid,
	    DLADM_OPT_ACTIVE | DLADM_OPT_PERSIST)) != DLADM_STATUS_OK) {
		(void) fprintf(stderr, "dladm_destroy_datalink_id failed: %s\n",
		    dladm_status2str(status, errmsg));
	}

	return (status);
}

int
main(int argc, char *argv[])
{
	dladm_handle_t	dlh;
	int		i;
	dladm_status_t	status;
	char		errmsg[DLADM_STRSIZE];

	if (argc < 2) {
		(void) fprintf(stderr,
		    "Usage: ibd_delete_link linkname ...\n");
		return (2);
	}

	if ((status = dladm_open(&dlh)) != DLADM_STATUS_OK) {
		(void) fprintf(stderr, "Failed to open dladm handle: %s\n",
		    dladm_status2str(status, errmsg));
		return (1);
	}

	for (i = 1; i < argc; i++) {
		if (ibd_delete_link(dlh, argv[i]) != DLADM_STATUS_OK) {
			dladm_close(dlh);
			return (1);
		}
	}

	dladm_close(dlh);
	return (0);
}
