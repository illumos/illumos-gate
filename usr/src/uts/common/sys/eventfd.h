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
 * Copyright (c) 2014 Joyent, Inc.  All rights reserved.
 */

/*
 * Header file to support for the eventfd facility.  Note that this facility
 * is designed to be binary compatible with the Linux eventfd facility; values
 * for constants here should therefore exactly match those found in Linux, and
 * this facility shouldn't be extended independently of Linux.
 */

#ifndef _SYS_EVENTFD_H
#define	_SYS_EVENTFD_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef uint64_t eventfd_t;

/*
 * To assure binary compatibility with Linux, these values are fixed at their
 * Linux equivalents, not their native ones.
 */
#define	EFD_CLOEXEC		02000000		/* LX_O_CLOEXEC */
#define	EFD_NONBLOCK		04000			/* LX_O_NONBLOCK */
#define	EFD_SEMAPHORE		1

/*
 * These ioctl values are specific to the native implementation; applications
 * shouldn't be using them directly, and they should therefore be safe to
 * change without breaking apps.
 */
#define	EVENTFDIOC		(('e' << 24) | ('f' << 16) | ('d' << 8))
#define	EVENTFDIOC_SEMAPHORE	(EVENTFDIOC | 1)	/* toggle sem state */

#ifndef _KERNEL

extern int eventfd(unsigned int, int);
extern int eventfd_read(int, eventfd_t *);
extern int eventfd_write(int, eventfd_t);

#else

#define	EVENTFDMNRN_INOTIFY	0
#define	EVENTFDMNRN_CLONE	1
#define	EVENTFD_VALMAX		(ULLONG_MAX - 1ULL)

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_EVENTFD_H */
