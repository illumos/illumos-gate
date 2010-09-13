
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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * sendfilev is the native interface : 32 bit app on 32 bit kernel
 * and 64 bit app on 64 bit kernel. sendfilev64() is used by
 * 32 bit apps on a 64 bit kernel or 32 bit kernel for large
 * file offsets. Similar things apply to sendfile.
 */

#pragma weak sendfilev = _sendfilev
#pragma weak sendfile = _sendfile

#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/sendfile.h>
#include <errno.h>

ssize_t
_sendfilev(int sock, const struct sendfilevec *vec, int sfvcnt, size_t *xferred)
{
	sysret_t rval;
	int error;

	error = __systemcall(&rval, SYS_sendfilev, SENDFILEV, sock, vec,
	    sfvcnt, xferred);
	if (error != 0) {
		if (error == EINTR && *xferred != 0) {
			rval.sys_rval1 = *xferred;
		} else {
			(void) __set_errno(error);
		}
	}
	return ((ssize_t)rval.sys_rval1);
}

ssize_t
_sendfile(int sock, int fd, off_t *off, size_t len)
{
	sysret_t rval;
	int error;
	struct sendfilevec sfv;
	size_t xferred;

	sfv.sfv_fd = fd;
	sfv.sfv_flag = 0;
	sfv.sfv_off = *off;
	sfv.sfv_len = len;
	error = __systemcall(&rval, SYS_sendfilev, SENDFILEV, sock, &sfv,
	    1, &xferred);
	*off += xferred;
	if (error != 0) {
		if (error == EINTR && xferred != 0) {
			rval.sys_rval1 = xferred;
		} else {
			(void) __set_errno(error);
		}
	}
	return ((ssize_t)rval.sys_rval1);
}

#if (!defined(_LP64))

#pragma weak sendfilev64 = _sendfilev64
#pragma weak sendfile64 = _sendfile64

ssize_t
_sendfilev64(int sock, const struct sendfilevec64 *vec, int sfvcnt,
    size_t *xferred)
{
	sysret_t rval;
	int error;

	error = __systemcall(&rval, SYS_sendfilev, SENDFILEV64, sock, vec,
	    sfvcnt, xferred);
	if (error != 0) {
		if (error == EINTR && *xferred != 0) {
			rval.sys_rval1 = *xferred;
		} else {
			(void) __set_errno(error);
		}
	}
	return ((ssize_t)rval.sys_rval1);
}

ssize_t
_sendfile64(int sock, int fd, off64_t *off, size_t len)
{
	sysret_t rval;
	int error;
	struct sendfilevec64 sfv;
	size_t xferred;

	sfv.sfv_fd = fd;
	sfv.sfv_flag = 0;
	sfv.sfv_off = *off;
	sfv.sfv_len = len;
	error = __systemcall(&rval, SYS_sendfilev, SENDFILEV64, sock, &sfv,
	    1, &xferred);
	*off += xferred;
	if (error != 0) {
		if (error == EINTR && xferred != 0) {
			rval.sys_rval1 = xferred;
		} else {
			(void) __set_errno(error);
		}
	}
	return ((ssize_t)rval.sys_rval1);
}
#endif
