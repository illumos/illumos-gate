#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#

function        sendfilev
include         <sys/sendfile.h>
declaration     ssize_t sendfilev(int sock, const struct sendfilevec *vec, \
			int sfvcnt, size_t *xferred)
version         SUNW_1.1
errno           EAFNOSUPPORT EPROTONOSUPPORT EPROTOTYPE EBADF EACCES \
			ENOBUFS ENOMEM EPIPE EIO EFAULT EINVAL
exception       $return == -1
end

function        sendfile
include         <sys/sendfile.h>
declaration     ssize_t sendfile(int sock, int fd, off_t *off, size_t len)
version         SUNW_1.1
errno           EAFNOSUPPORT EOPNOTSUPP EBADF EAGAIN EPIPE \
			EIO EFAULT EINVAL
exception       $return == -1
end

function        sendfilev64
include         <sys/sendfile.h>
declaration     ssize_t sendfilev64(int sock, const struct sendfilevec64 *vec, \
			int sfvcnt, size_t *xferred)
arch		sparc i386
version         SUNW_1.1
errno           EAFNOSUPPORT EPROTONOSUPPORT EPROTOTYPE EBADF EACCES \
			ENOBUFS ENOMEM EPIPE EIO EFAULT EINVAL
exception       $return == -1
end

function        sendfile64
include         <sys/sendfile.h>
declaration     ssize_t sendfile64(int sock, int fd, off64_t *off, size_t len)
arch		sparc i386
version         SUNW_1.1
errno           EAFNOSUPPORT EOPNOTSUPP EBADF EAGAIN EPIPE \
			EIO EFAULT EINVAL
exception       $return == -1
end

