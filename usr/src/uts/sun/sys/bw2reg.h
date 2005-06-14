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
 * Copyright 1985, 1987, 1990 by Sun Microsystems, Inc.
 *	All rights reserved.
 */

#ifndef	_SYS_BW2REG_H
#define	_SYS_BW2REG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SunOS-4.0 1.14 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Monochrome memory frame buffer hardware definitions
 */

#define	BW2_FBSIZE		(128*1024)	/* size of frame buffer */
#define	BW2_FBSIZE_HIRES	(256*1024)	/* hi-res frame buffer size */

#define	BW2_USECOPYMEM		0x1	/* config flag to use copy memory */

#ifdef _KERNEL

#define	BW2_COPY_MEM_AVAIL	(defined(sun2) || defined(SUN3_160))

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_BW2REG_H */
