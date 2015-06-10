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
 *
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef _SYS_MODE_H
#define	_SYS_MODE_H

#if defined(_KERNEL) || defined(_FAKE_KERNEL)

#include <sys/stat.h>
#include <sys/vnode.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Conversion between vnode types/modes and encoded type/mode as
 * seen by stat(2) and mknod(2).
 */
extern enum vtype	iftovt_tab[];
extern ushort_t		vttoif_tab[];
#define	IFTOVT(M)	(iftovt_tab[((M) & S_IFMT) >> 12])
#define	VTTOIF(T)	(vttoif_tab[(int)(T)])
#define	MAKEIMODE(T, M)	(VTTOIF(T) | ((M) & ~S_IFMT))

#ifdef	__cplusplus
}
#endif

#endif  /* _KERNEL */

#endif	/* _SYS_MODE_H */
