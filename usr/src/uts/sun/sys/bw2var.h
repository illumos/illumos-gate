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
 * Copyright (c) 1986, 1990 by Sun Microsystems, Inc.
 *	All rights reserved.
 */

#ifndef	_SYS_BW2VAR_H
#define	_SYS_BW2VAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SunOS-4.0 1.13 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * bw2 -- monochrome frame buffer
 */

/* standard resolution */
#define	BW2SIZEX 1152
#define	BW2SIZEY 900
#define	BW2BYTES (BW2SIZEX*BW2SIZEY/8)

#define	BW2SQUARESIZEX 1024
#define	BW2SQUARESIZEY 1024
#define	BW2SQUAREBYTES (BW2SQUARESIZEX*BW2SQUARESIZEY/8)

/* high resolution (bw2h) */
#define	BW2HSIZEX	1600
#define	BW2HSIZEY	1280
#define	BW2HBYTES	(BW2HSIZEX*BW2HSIZEY/8)

#define	BW2HSQUARESIZEX 1440
#define	BW2HSQUARESIZEY 1440
#define	BW2HSQUAREBYTES (BW2HSQUARESIZEX*BW2HSQUARESIZEY/8)


extern	struct pixrectops bw2_ops;

#ifndef _KERNEL
struct	pixrect *bw2_make();
int	bw2_destroy();
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_BW2VAR_H */
