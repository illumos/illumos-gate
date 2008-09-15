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

/*
 * User-space door client routines for both SMB daemon and CLIs.
 */

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

#define	SMB_DOOR_CALL_RETRIES		3

void
smb_dr_clnt_setup(door_arg_t *arg, char *buf, size_t buflen)
{
	arg->data_ptr = buf;
	arg->data_size = buflen;
	arg->desc_ptr = NULL;
	arg->desc_num = 0;
	arg->rbuf = buf;
	arg->rsize = buflen;
}

/*
 * Free resources allocated for a door call.  If the result buffer provided
 * by the client is too small, the doorfs will have allocated a new buffer,
 * which must be unmapped here.
 *
 * This function must be called to free both the argument and result door
 * buffers regardless of the status of the door call.
 */
void
smb_dr_clnt_cleanup(door_arg_t *arg)
{
	if (arg->rbuf && (arg->rbuf != arg->data_ptr))
		(void) munmap(arg->rbuf, arg->rsize);

	free(arg->data_ptr);
}

/*
 * Make a door call to the server function associated with the door
 * descriptor fd.
 *
 * After a successful door call the local door_arg->data_ptr is assigned
 * to the caller's arg->rbuf so that arg has references to both input and
 * response buffers, which is required by smb_dr_clnt_free.
 *
 * On success, 0 will be returned and the call results can be referenced
 * via arg->rbuf and arg->rsize.  Otherwise -1 will be returned.
 */
int
smb_dr_clnt_call(int fd, door_arg_t *arg)
{
	door_arg_t door_arg;
	int rc;
	int i;

	if (fd < 0 || arg == NULL)
		return (-1);

	bcopy(arg, &door_arg, sizeof (door_arg_t));

	for (i = 0; i < SMB_DOOR_CALL_RETRIES; ++i) {
		errno = 0;

		if ((rc = door_call(fd, &door_arg)) == 0)
			break;

		if (errno != EAGAIN && errno != EINTR)
			return (-1);
	}

	if (rc != 0)
		return (-1);

	if ((rc = smb_dr_get_res_stat(door_arg.data_ptr, door_arg.rsize)) != 0)
		rc = -1;

	arg->rbuf = door_arg.data_ptr;
	arg->rsize = door_arg.rsize;
	return (rc);
}
