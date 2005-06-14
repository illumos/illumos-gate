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

#ifndef _SYS_MSIO_H
#define	_SYS_MSIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SunOS4.0 1.6 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Mouse related ioctls
 */
typedef struct {
	int	jitter_thresh;
	int	speed_law;
	int	speed_limit;
} Ms_parms;

typedef struct {
	int	height;			/* height of the screen */
	int	width;			/* width of the screen */
}Ms_screen_resolution;

#define	MSIOC		('m'<<8)	/* same as mtio.h - change ? */
#define	MSIOGETPARMS	(MSIOC|1)	/* get / set jitter, speed  */
#define	MSIOSETPARMS	(MSIOC|2)	/* law, or speed limit */
#define	MSIOBUTTONS	(MSIOC|3)	/* get number of buttons */
#define	MSIOSRESOLUTION	(MSIOC|4)	/* Set screen resolution for mouse */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MSIO_H */
