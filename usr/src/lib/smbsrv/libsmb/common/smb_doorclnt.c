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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * User-space door client routines for both SMB daemon and CLIs.
 */

#include <fcntl.h>
#include <syslog.h>
#include <door.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>
#include <smbsrv/libsmb.h>
#include <smbsrv/wintypes.h>
#include <smbsrv/smb_door_svc.h>
#include <smbsrv/smb_common_door.h>

/*
 * Returns 0 on success. Otherwise, -1.
 */
int
smb_dr_clnt_open(int *fd, char *path, char *op_desc)
{
	int rc = 0;

	if (!op_desc)
		op_desc = "unknown operation";

	if (!path || !fd)
		return (-1);

	if ((*fd = open(path, O_RDONLY)) < 0) {
		syslog(LOG_ERR, "%s: open %s failed %s", op_desc,
		    path, strerror(errno));
		rc = -1;
	}

	return (rc);
}

/*
 * smb_dr_clnt_call
 *
 * This function will make a door call to the server function
 * associated with the door descriptor fd. The specified door
 * request buffer (i.e. argp) will be passed as the argument to the
 * door_call(). Upon success, the result buffer is returned. Otherwise,
 * NULL pointer is returned. The size of the result buffer is returned
 * via rbufsize.
 */
char *
smb_dr_clnt_call(int fd, char *argp, size_t arg_size, size_t *rbufsize,
    char *op_desc)
{
	door_arg_t arg;

	if (!argp) {
		syslog(LOG_ERR, "smb_dr_clnt_call: invalid parameter");
		return (NULL);
	}

	arg.data_ptr = argp;
	arg.data_size = arg_size;
	arg.desc_ptr = NULL;
	arg.desc_num = 0;
	arg.rbuf = argp;
	arg.rsize = arg_size;

	if (!op_desc)
		op_desc = "unknown operation";

	if (door_call(fd, &arg) < 0) {
		syslog(LOG_ERR, "%s: Door call failed %s", op_desc,
		    strerror(errno));
		free(argp);
		argp = NULL;
		return (NULL);
	}

	if (smb_dr_get_res_stat(arg.data_ptr, arg.rsize)
	    != SMB_DR_OP_SUCCESS) {
		smb_dr_clnt_free(argp, arg_size, arg.rbuf, arg.rsize);
		*rbufsize = 0;
		return (NULL);
	}
	*rbufsize = arg.rsize;
	return (arg.data_ptr);
}

/*
 * smb_dr_clnt_free
 *
 * This function should be invoked to free both the argument/result door buffer
 * regardless of the status of the door call.
 *
 * The doorfs allocates a new buffer if the result buffer passed by the client
 * is too small. This function will munmap if that happens.
 */
/*ARGSUSED*/
void
smb_dr_clnt_free(char *argp, size_t arg_size, char *rbufp, size_t rbuf_size)
{
	if (argp) {
		if (argp == rbufp) {
			free(argp);
			argp = NULL;
		} else if (rbufp) {
			free(argp);
			argp = NULL;
			if (munmap(rbufp, rbuf_size) != 0) {
				syslog(LOG_ERR, "munmap failed");
			}
		}
	} else {
		if (rbufp) {
			if (munmap(rbufp, rbuf_size) != 0) {
				syslog(LOG_ERR, "munmap failed");
			}
		}
	}
}
