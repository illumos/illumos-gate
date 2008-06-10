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
 * Copyright (c) 1983, by Sun Microsystems, Inc.
 */

#ifndef _SYS_CURSOR_IMPL_H
#define	_SYS_CURSOR_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	DONT_SHOW_CURSOR	0x00000001
#define	SHOW_CROSSHAIRS		0x00000002
#define	SHOW_HORIZ_HAIR		0x00000004
#define	SHOW_VERT_HAIR		0x00000008
#define	FULLSCREEN		0x00000010
#define	HORIZ_BORDER_GRAVITY	0x00000020
#define	VERT_BORDER_GRAVITY	0x00000040
#define	FREE_SHAPE		0x00000080
#define	NOT_IN_HW		0x00000100  /* Don't use cursor hw for this */
					    /* cursor */
#define	CLIENT_OWNS_IMAGE	0x00000200  /* Hw cursor only: client will  */
					    /* set shape and not SunWindows */

#define	show_cursor(cursor)		(!((cursor)->flags & DONT_SHOW_CURSOR))
#define	show_crosshairs(cursor)		((cursor)->flags & SHOW_CROSSHAIRS)
#define	show_horiz_hair(cursor)		((cursor)->flags & SHOW_HORIZ_HAIR)
#define	show_vert_hair(cursor)		((cursor)->flags & SHOW_VERT_HAIR)
#define	fullscreen(cursor)		((cursor)->flags & FULLSCREEN)
#define	horiz_border_gravity(cursor)	((cursor)->flags & HORIZ_BORDER_GRAVITY)
#define	vert_border_gravity(cursor)	((cursor)->flags & VERT_BORDER_GRAVITY)
#define	free_shape(cursor)		((cursor)->flags & FREE_SHAPE)
#define	not_in_hw(cursor)		((cursor)->flags & NOT_IN_HW)
#define	client_owns_image(cursor)	((cursor)->flags & CLIENT_OWNS_IMAGE)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CURSOR_IMPL_H */
