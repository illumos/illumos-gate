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
version		sparc=SISCD_2.3 sparcv9=SUNW_0.7 i386=SUNW_0.7 amd64=SUNW_0.7
errno		EACCES EFAULT EINVAL  
exception	$return == -1
end

function	aioread
include		<sys/types.h>, <sys/asynch.h>, <aio.h>
declaration	int aioread(int fildes, char *bufp, int bufs, \
			off_t offset, int whence, aio_result_t *resultp)
version		sparc=SISCD_2.3 sparcv9=SUNW_0.7 i386=SUNW_0.7 amd64=SUNW_0.7
errno		EAGAIN EBADF EFAULT EINVAL ENOMEM  
exception	$return == -1
end

function	aioread64
declaration	int aioread64(int fd, caddr_t buf, int bufsz, off64_t offset, \
			int whence, aio_result_t *resultp)
arch		i386 sparc
version		i386=SUNW_1.0 sparc=SUNW_1.0
end

function	aiowait
include		<sys/asynch.h>, <aio.h>, <sys/time.h>
declaration	aio_result_t *aiowait(struct timeval *timeout)
version		sparc=SISCD_2.3 sparcv9=SUNW_0.7 i386=SUNW_0.7 amd64=SUNW_0.7
errno		EFAULT EINTR EINVAL  
exception	$return == (aio_result_t *)-1
end

function	aiowrite
include		<sys/types.h>, <sys/asynch.h>, <aio.h>
declaration	int aiowrite(int fildes, char *bufp, int bufs, \
			off_t offset, int whence, aio_result_t *resultp)
version		sparc=SISCD_2.3 sparcv9=SUNW_0.7 i386=SUNW_0.7 amd64=SUNW_0.7
errno		EAGAIN EBADF EFAULT EINVAL ENOMEM
exception	$return == -1
end

function	aiowrite64
include		<sys/types.h>, <sys/asynch.h>, <aio.h>
declaration	int aiowrite64(int fildes, char *bufp, int bufs, \
			off64_t offset, int whence, aio_result_t *resultp)
arch		sparc i386
version		sparc=SUNW_1.0 i386=SUNW_1.0
errno		EAGAIN EBADF EFAULT EINVAL ENOMEM
exception	$return == -1
end

function	assfail
declaration	int assfail(char *a, char *f, int l)
version		SUNW_1.1
end

function	close
include		<unistd.h>
declaration	int close(int fildes)
version		SUNW_0.7
errno		EBADF EINTR ENOLINK EIO
exception	$return == -1
binding		nodirect
end

function	fork
version		SUNW_0.7
filter		libc.so.1
end

function	sigaction extends libc/spec/sys.spec sigaction
version		SUNW_0.7
binding		nodirect
end

function	_sigaction
weak		sigaction
version		SUNWprivate_1.1
binding		nodirect
end

function	__lio_listio
declaration	int __lio_listio(int mode, aiocb_t * const list[], int nent, \
			struct sigevent *sig)
version		SUNWprivate_1.1
end

function	__aio_suspend
declaration	int __aio_suspend(void **list, int nent, \
			const timespec_t *timo, int largefile)
version		SUNWprivate_1.1
end

function	__aio_error
declaration	int __aio_error(aiocb_t *cb)
version		SUNWprivate_1.1
end

function	__aio_return
declaration	ssize_t __aio_return(aiocb_t *cb)
version		SUNWprivate_1.1
end

function	__aio_read
declaration	int __aio_read(aiocb_t *cb)
version		SUNWprivate_1.1
end

function	__aio_write
declaration	int __aio_write(aiocb_t *cb)
version		SUNWprivate_1.1
end

function	__aio_fsync
declaration	int __aio_fsync(int op, aiocb_t *aiocbp)
version		SUNWprivate_1.1
end

function	__aio_cancel
declaration	int __aio_cancel(int fd, aiocb_t *aiocbp)
version		SUNWprivate_1.1
end

function	__aio_waitn
declaration	int __aio_waitn(void **list, uint_t nent, uint_t *nwait, \
			const struct timespec *timeout, int mode)
version		SUNWprivate_1.1
end

function	__lio_listio64
declaration	int __lio_listio64(int mode, aiocb64_t * const list[], \
			int nent, struct sigevent *sig)
arch		sparc i386
version		sparc=SUNWprivate_1.1 i386=SUNWprivate_1.1
end

function	__aio_error64
declaration	int __aio_error64(aiocb64_t *cb)
arch		sparc i386
version		sparc=SUNWprivate_1.1 i386=SUNWprivate_1.1
end

function	__aio_return64
declaration	ssize_t __aio_return64(aiocb64_t *cb)
arch		sparc i386
version		sparc=SUNWprivate_1.1 i386=SUNWprivate_1.1
end

function	__aio_read64
declaration	int __aio_read64(aiocb64_t *cb)
arch		sparc i386
version		sparc=SUNWprivate_1.1 i386=SUNWprivate_1.1
end

function	__aio_write64
declaration	int __aio_write64(aiocb64_t *cb)
arch		sparc i386
version		sparc=SUNWprivate_1.1 i386=SUNWprivate_1.1
end

function	__aio_fsync64
declaration	int __aio_fsync64(int op, aiocb64_t *aiocbp)
arch		sparc i386
version		sparc=SUNWprivate_1.1 i386=SUNWprivate_1.1
end

function	__aio_cancel64
declaration	int __aio_cancel64(int fd, aiocb64_t *aiocbp)
arch		sparc i386
version		sparc=SUNWprivate_1.1 i386=SUNWprivate_1.1
end

function	_libaio_close
version		SUNWprivate_1.1
end
