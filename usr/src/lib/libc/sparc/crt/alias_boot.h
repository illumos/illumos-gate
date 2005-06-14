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
 * Copyright (c) 1991 Sun Microsystems, Inc.
 */

#ifndef	_ALIAS_BOOT_H
#define	_ALIAS_BOOT_H

#ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Offsets for string constants used in alias bootstrap.
 */
#define	LDSO_S		0		/* "/usr/lib/ld.so.n" */
#define	ZERO_S		1		/* "/dev/zero" */
#define	EMPTY_S		2		/* "(null)" */
#define	S_MAX		3		/* count of strings */

/*
 * Offsets for function pointers used in alias bootstrap.
 */
#define	PANIC_F		0		/* panic() */
#define	OPEN_F		1		/* open() */
#define	MMAP_F		2		/* mmap() */
#define	FSTAT_F		3		/* fstat() */
#define	SYSCONFIG_F	4		/* sysconfig() */
#define	CLOSE_F		5		/* close() */
#define	MUNMAP_F	6		/* munmap() */
#define	F_MAX		7		/* count of functions */

#endif	/* _ALIAS_BOOT_H */
