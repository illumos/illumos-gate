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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * The structures header and dispatch define the format of a font file.
 *
 * A font file contains one struct 'header', an array of NUM_DISPATCH struct
 * 'dispatch'es, then an array of bytes containing bit maps.
 *
 * See vfont(5) for more details.
 */

#ifndef _vfont_h
#define	_vfont_h

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

struct header {
	short		magic;		/* Magic number VFONT_MAGIC */
	unsigned short	size;		/* Total # bytes of bitmaps */
	short		maxx;		/* Maximum horizontal glyph size */
	short		maxy;		/* Maximum vertical   glyph size */
	short		xtend;		/* (unused?) */
};
#define	VFONT_MAGIC	0436

struct dispatch {
	unsigned short	addr;		/* &(glyph) - &(start of bitmaps) */
	short		nbytes;		/* # bytes of glyphs (0 if no glyph) */
	char		up, down, left, right;	/* Widths from baseline point */
	short		width;		/* Logical width, used by troff */
};
#define	NUM_DISPATCH	256

#ifdef __cplusplus
}
#endif

#endif /* !_vfont_h */
