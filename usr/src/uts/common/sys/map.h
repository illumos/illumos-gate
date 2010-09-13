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
 * Copyright 2001 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/*	  All Rights Reserved	*/

#ifndef _SYS_MAP_H
#define	_SYS_MAP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/t_lock.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct map;

#ifdef _KERNEL

extern	void	*rmallocmap(size_t);
extern	void	*rmallocmap_wait(size_t);
extern	void	rmfreemap(void *);

extern	ulong_t	rmalloc(void *, size_t);
extern	ulong_t	rmalloc_wait(void *, size_t);
extern	void	rmfree(void *, size_t, ulong_t);

#endif /* KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_MAP_H */
