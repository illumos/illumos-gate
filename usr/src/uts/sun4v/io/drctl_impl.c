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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/door.h>
#include <sys/note.h>
#include <sys/drctl.h>
#include <sys/drctl_impl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/dr_util.h>

static door_handle_t drctl_dh;	/* Door for upcalls */


int
i_drctl_ioctl(int cmd, intptr_t arg)
{
	int rv;
	drctl_setup_t setup_rqst;

	switch (cmd) {
	case DRCTL_IOCTL_CONNECT_SERVER:
		if (ddi_copyin((caddr_t)arg,
		    &setup_rqst, sizeof (setup_rqst), 0) != 0) {
			cmn_err(CE_WARN, "i_drctl_ioctl: ddi_copyin failed "
			    "for DRCTL_IOCTL_CONNECT_SERVER");
			rv = EFAULT;
			break;
		}

		drctl_dh = door_ki_lookup(setup_rqst.did);
		rv = 0;
		break;

	default:
		rv = EIO;
	}

	return (rv);
}

int
i_drctl_send(void *msg, size_t size, void **obufp, size_t *osize)
{
	int up_err;
	int rv = 0;
	door_arg_t door_args;
	door_handle_t dh = drctl_dh;
	static const char me[] = "i_drctl_send";

retry:
	if (dh)
		door_ki_hold(dh);
	else
		return (EIO);

	door_args.data_ptr = (char *)msg;
	door_args.data_size = size;
	door_args.desc_ptr = NULL;
	door_args.desc_num = 0;

	/*
	 * We don't know the size of the message the daemon
	 * will pass back to us.  By setting rbuf to NULL,
	 * we force the door code to allocate a buf of the
	 * appropriate size.  We must set rsize > 0, however,
	 * else the door code acts as if no response was
	 * expected and doesn't pass the data to us.
	 */
	door_args.rbuf = NULL;
	door_args.rsize = 1;
	DR_DBG_CTL("%s: msg %p size %ld obufp %p osize %p\n",
	    me, msg, size, (void *)obufp, (void *)osize);

	up_err = door_ki_upcall_limited(dh, &door_args, NULL, SIZE_MAX, 0);
	if (up_err == 0) {
		if (door_args.rbuf == NULL)
			goto done;

		DR_DBG_CTL("%s: rbuf %p rsize %ld\n", me,
		    (void *)door_args.rbuf, door_args.rsize);

		if (obufp != NULL) {
			*obufp = door_args.rbuf;
			*osize = door_args.rsize;
		} else {
			/*
			 * No output buffer pointer was passed in,
			 * so the response buffer allocated by the
			 * door code must be deallocated.
			 */
			kmem_free(door_args.rbuf, door_args.rsize);
		}
	} else {
		switch (up_err) {
		case EINTR:
			DR_DBG_CTL("%s: door call returned EINTR\n", me);
			_NOTE(FALLTHROUGH)
		case EAGAIN:
			/*
			 * Server process may be forking, try again.
			 */
			door_ki_rele(dh);
			delay(hz);
			goto retry;
		case EBADF:
		case EINVAL:
			drctl_dh = NULL;
			DR_DBG_CTL(
			    "%s: door call failed with %d\n", me, up_err);
			rv = EIO;
			break;
		default:
			DR_DBG_CTL("%s: unexpected return "
			    "code %d from door_ki_upcall\n", me, up_err);
			rv = EIO;
			break;
		}
	}

done:
	door_ki_rele(dh);
	return (rv);
}
