#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

function	aiocancel
include		<sys/asynch.h>, <aio.h>
declaration	int aiocancel(aio_result_t *resultp)
version		SUNW_1.23
errno		EACCES EFAULT EINVAL  
exception	$return == -1
end

function	aioread
include		<sys/types.h>, <sys/asynch.h>, <aio.h>
declaration	int aioread(int fildes, char *bufp, int bufs, \
			off_t offset, int whence, aio_result_t *resultp)
version		SUNW_1.23
errno		EAGAIN EBADF EFAULT EINVAL ENOMEM  
exception	$return == -1
end

function	aioread64
declaration	int aioread64(int fd, caddr_t buf, int bufsz, off64_t offset, \
			int whence, aio_result_t *resultp)
arch		i386 sparc
version		SUNW_1.23
end

function	aiowait
include		<sys/asynch.h>, <aio.h>, <sys/time.h>
declaration	aio_result_t *aiowait(struct timeval *timeout)
version		SUNW_1.23
errno		EFAULT EINTR EINVAL  
exception	$return == (aio_result_t *)-1
end

function	aiowrite
include		<sys/types.h>, <sys/asynch.h>, <aio.h>
declaration	int aiowrite(int fildes, char *bufp, int bufs, \
			off_t offset, int whence, aio_result_t *resultp)
version		SUNW_1.23
errno		EAGAIN EBADF EFAULT EINVAL ENOMEM
exception	$return == -1
end

function	aiowrite64
include		<sys/types.h>, <sys/asynch.h>, <aio.h>
declaration	int aiowrite64(int fildes, char *bufp, int bufs, \
			off64_t offset, int whence, aio_result_t *resultp)
arch		sparc i386
version		SUNW_1.23
errno		EAGAIN EBADF EFAULT EINVAL ENOMEM
exception	$return == -1
end

function	assfail
declaration	int assfail(char *a, char *f, int l)
version		SUNW_1.23
end

