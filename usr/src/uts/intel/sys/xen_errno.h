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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_XEN_ERRNO_H
#define	_SYS_XEN_ERRNO_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Xen errno's for HYPERVISOR calls
 *
 * XXPV	This is maintained by hand :(
 *
 * Unfortunately native Xen currently uses the same namespace as the Solaris
 * errno namespace but with (some) different numeric values.
 *
 * This set of errno values match Xen 3.0.3; sigh.
 *
 * In a better world, Xen would make its namespace explicitly different
 * e.g. something like below.
 */

#define	X_EPERM		1
#define	X_ENOENT	2
#define	X_ESRCH		3
#define	X_EINTR		4
#define	X_EIO		5
#define	X_ENXIO		6
#define	X_E2BIG		7

#define	X_EAGAIN	11
#define	X_ENOMEM	12
#define	X_EACCES	13
#define	X_EFAULT	14

#define	X_EBUSY		16
#define	X_EEXIST	17

#define	X_ENODEV	19
#define	X_EISDIR	21
#define	X_EINVAL	22

#define	X_ENOSPC	28
#define	X_ESPIPE	29
#define	X_EROFS		30

#define	X_ENOSYS	38
#define	X_ENOTEMPTY	39

#define	X_ENODATA	61

#define	X_EISCONN	106

#ifndef	_ASM
#if defined(_KERNEL)
/*
 * Error code translation routine to translate xen error codes to
 * Solaris error codes.  Xen returns negative error codes which this
 * routine will translate to a positive one.
 */
extern int xen_xlate_errcode(int);
#endif	/* _KERNEL */
#endif	/* _ASM */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_XEN_ERRNO_H */
