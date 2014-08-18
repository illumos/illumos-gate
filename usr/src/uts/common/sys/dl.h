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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#ifndef _SYS_DL_H
#define	_SYS_DL_H

#include <sys/isa_defs.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef	struct dl {
#ifdef _LONG_LONG_LTOH
	uint_t	dl_lop;
	int	dl_hop;
#else
	int	dl_hop;
	uint_t	dl_lop;
#endif
} dl_t;

extern dl_t	ladd(dl_t, dl_t);
extern dl_t	lsub(dl_t, dl_t);
extern dl_t	lmul(dl_t, dl_t);
extern dl_t	ldivide(dl_t, dl_t);
extern dl_t	lshiftl(dl_t, int);
extern dl_t	llog10(dl_t);
extern dl_t	lexp10(dl_t);

extern dl_t	lzero;
extern dl_t	lone;
extern dl_t	lten;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DL_H */
