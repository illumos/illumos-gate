/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2013 Pluribus Networks Inc.
 */

#ifndef _COMPAT_FREEBSD_SYS_UIO_H_
#define	_COMPAT_FREEBSD_SYS_UIO_H_

#include_next <sys/uio.h>

#ifndef	_KERNEL
ssize_t preadv(int, const struct iovec *, int, off_t);
ssize_t pwritev(int, const struct iovec *, int, off_t);
#endif

#endif	/* _COMPAT_FREEBSD_SYS_UIO_H_ */
