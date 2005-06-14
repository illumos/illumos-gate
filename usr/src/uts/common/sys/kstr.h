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
 * Copyright (c) 1991-1997, 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_KSTR_H
#define	_SYS_KSTR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/stream.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Autopush operation numbers.
 */
#define	SET_AUTOPUSH	0
#define	GET_AUTOPUSH	1
#define	CLR_AUTOPUSH	2

extern int	kstr_open(major_t, minor_t, vnode_t **, int *);
extern int	kstr_plink(vnode_t *, int, int *);
extern int	kstr_unplink(vnode_t *, int);
extern int	kstr_push(vnode_t *, char *);
extern int	kstr_pop(vnode_t *);
extern int	kstr_close(vnode_t *, int);
extern int	kstr_ioctl(vnode_t *, int, intptr_t);
extern int	kstr_msg(vnode_t *, mblk_t *, mblk_t **, timestruc_t *);
extern int	kstr_autopush(int, major_t *, minor_t *, minor_t *, uint_t *,
		    char *[]);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_KSTR_H */
