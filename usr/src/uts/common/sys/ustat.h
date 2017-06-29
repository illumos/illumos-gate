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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/


/*
 * WARNING: The ustat system call will become obsolete in the
 * next major release following SVR4. Application code should
 * migrate to the replacement system call statvfs(2).
 */

/*
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_USTAT_H
#define	_SYS_USTAT_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if !defined(_LP64) && _FILE_OFFSET_BITS == 64
#error	"Cannot use ustat in the large files compilation environment"
#endif

struct  ustat {
	daddr_t	f_tfree;	/* total free */
	ino_t	f_tinode;	/* total inodes free */
	char	f_fname[6];	/* filsys name */
	char	f_fpack[6];	/* filsys pack name */
};

#if defined(_SYSCALL32)

struct	ustat32 {
	daddr32_t	f_tfree;	/* total free */
	ino32_t		f_tinode;	/* total inodes free */
	char		f_fname[6];	/* filsys name */
	char		f_fpack[6];	/* filsys pack name */
};

#endif	/* _SYSCALL32 */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_USTAT_H */
