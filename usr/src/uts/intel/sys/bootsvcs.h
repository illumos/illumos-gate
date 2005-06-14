/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_BOOTSVCS_H
#define	_SYS_BOOTSVCS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Boot time configuration information objects
 *
 * The BS_VERSION version number should be incremented when adding
 * new boot_syscalls entry points.  The kernel can check the boot_syscalls
 * version number by looking up the BS_VERSION_PROP property in the
 * device tree.  This version number allows the kernel to detect if the
 * version of boot.bin that loaded it supports newer boot_syscalls entry
 * points.  This in turn allows the kernel to potentially support
 * backward compatibility with older versions of boot.bin that don't
 * support newer entry points.
 *
 * (Before we get too carried away with extending this interface,
 * realize how broken it is.  Even with a cleaner namespace than
 * we used to have prior to S10, it is -extremely- difficult to
 * interpose upon because the method pointer is NOT passed to the
 * methods.  We would do well to extend the bootops and EOL this
 * interface as fast as possible, rather than to add more to it.)
 */
#define	BS_VERSION 4
#define	BS_VERSION_PROP "bs-version"

typedef struct boot_syscalls {			/* offset */
	int	(*bsvc_getchar)();		/*  7 - getchar */
	void	(*bsvc_putchar)(int);		/*  8 - putchar */
	int	(*bsvc_ischar)();		/*  9 - ischar */
} boot_syscalls_t;

#ifdef _KMDB
extern boot_syscalls_t *kmdb_sysp;
#define	SYSP	kmdb_sysp
#else /* !_KMDB */
extern boot_syscalls_t *sysp;
#define	SYSP	sysp
#endif

#define	BSVC_GETCHAR(sysp)		(((sysp)->bsvc_getchar)())
#define	BSVC_PUTCHAR(sysp, c)		(((sysp)->bsvc_putchar)(c))
#define	BSVC_ISCHAR(sysp)		(((sysp)->bsvc_ischar)())

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_BOOTSVCS_H */
