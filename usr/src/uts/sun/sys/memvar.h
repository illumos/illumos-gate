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
 * Copyright 1986-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_MEMVAR_H
#define	_SYS_MEMVAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SunOS4.1.2 1.45 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * A memory pixrect is a special type of pixrect.  Its image resides in
 * memory, in a publicly known format permitting more direct access to the
 * image than possible with the general pixrectops.
 *
 * In the memory pixrect the image is stored in consecutive memory locations,
 * across the row from left to right, and then from top to bottom.  Each row
 * is padded to a 16-bit or 32-bit boundary (for details refer to the Pixrect
 * Reference Manual).
 *
 * The depth of a pixel is the number of bits required to represent it.
 * Pixels are placed in consecutive fields of width the depth of each pixel,
 * with placement being independent of word or byte boundaries.
 */
struct mpr_data {
	int	md_linebytes;	/* number of bytes from one line to next */
	short	*md_image;	/* word address */
	struct	pr_pos md_offset;
	short	md_primary;
	short	md_flags;	/* Flag bits, see below */
};

/* pixrect data for memory pixrect with plane mask (MP_PLANEMASK set) */
struct mprp_data {
	struct mpr_data mpr;
	int		planes;
};

#define	mpr_d(pr)	((struct mpr_data *)(pr)->pr_data)
#define	mprp_d(pr)	((struct mprp_data *)(pr)->pr_data)

/* md_flags bits definitions */

#define	MP_REVERSEVIDEO 1	/* Pixrect is reverse video */
				/* (should only be set if pr_depth = 1) */
#define	MP_DISPLAY	2	/* Pixrect is a frame buffer device */
#define	MP_PLANEMASK	4	/* Pixrect has a plane mask */
				/* (should only be set if pr_depth > 1) */
#if defined(__i386)
#define	MP_I386		8	/* Pixrect is for 386 architecture */
#define	MP_STATIC	16	/* Pixrect is a static pixrect */
#endif
#define	MP_FONT		32	/* Pixrect is a part of a Pixfont */
				/* (hint to pr_batchrop) */

/*
 * Each line (row) of the pixrect is padded to be a multiple
 * of this many bits
 */
#define	MPR_LINEBITPAD	16

#define	mpr_linebytes(x, depth)						\
	(((pr_product(x, depth) + (MPR_LINEBITPAD-1)) >> 3) &~ 1)
#define	mpr_prlinebytes(mpr)						\
	mpr_linebytes((mpr)->pr_size.x, (mpr)->pr_depth)
#define	mpr_mdlinebytes(mpr)						\
	(mpr_d(mpr)->md_linebytes)

#define	mprd_addr(mprd, xo, yo)						\
	((short *)(\
	    (int)(mprd)->md_image					\
	    + pr_product((mprd)->md_linebytes, (mprd)->md_offset.y+(yo)) \
	    + (((mprd)->md_offset.x+(xo)) >> 3) &~ 1))

#define	mprd8_addr(mprd, xo, yo, d)					\
	((uchar_t *)(\
	(int)(mprd)->md_image						\
	    + pr_product((mprd)->md_linebytes, (mprd)->md_offset.y+(yo)) \
	    + (pr_product((mprd)->md_offset.x+(xo), (d)) >> 3)))

#define	mprd_skew(mprd, xo, yo)						\
	(((mprd)->md_offset.x + (xo)) & 15)

#define	mprs_addr(mprs)		_mprs_addr((struct pr_prpos *)&(mprs))
#define	mprs8_addr(mprs)	_mprs8_addr((struct pr_prpos *)&(mprs))
#define	mprs_skew(mprs)		_mprs_skew((struct pr_prpos *)&(mprs))

#if !defined __lint || !defined _KERNEL || defined(sun2)
short	*_mprs_addr();
uchar_t	*_mprs8_addr();
int	_mprs_skew();
#endif

/*
 * Static pixrects.  A pixrect may be created at compile time using the
 * mpr_static macro as part of the static declarations of a program.  Thus
 * mpr_static(cursor, 16, 16, 1, rawcursordata);
 * will declare and initialize (using rawcursordata) the storage needed
 * for a pixrect that may be referred to as 'cursor' subsequently in the
 * same file, or as &cursor if a pointer to that pixrect is called for rather
 * than the pixrect itself.
 */

/*
 * First a pair of utility macros that allow concatenation in a fashion that
 * won't annoy lint (These belong in a standard header file!):
 */
#if defined(__STDC__) && !defined(__LIBCPP__)

#ifndef CAT
#define	CAT(a, b)	a##b
#endif

#else	/* __STDC__ */

#ifndef CAT
#undef	IDENT
#define	IDENT(x)	x
#define	CAT(a, b)	IDENT(a)b
#endif

#endif	/* __STDC__ */

#define	mpr_static(name, w, h, d, image) \
	struct mpr_data CAT(name, _data) = \
	    {mpr_linebytes(w, d), (short *)(image), {0, 0}, 0, 0}; \
	Pixrect name = {&mem_ops, w, h, d, (caddr_t)&CAT(name, _data)}

/* static pixrect with variables declared "static" */
#define	mpr_static_static(name, w, h, d, image) \
	static struct mpr_data CAT(name, _data) = \
	    {mpr_linebytes(w, d), (short *)(image), {0, 0}, 0, 0}; \
	static Pixrect name = {&mem_ops, w, h, d, (caddr_t)&CAT(name, _data)}

/*
 * During rop calls need to determine if dst/src is something that
 * mem_rop() can handle.  Use the following macro to find out.
 */
#define	MP_NOTMPR(pr)	((pr)->pr_ops->pro_rop != mem_rop)

extern struct pixrectops mem_ops;

int	mem_rop();
#ifndef _KERNEL
int	mem_stencil();
int	mem_batchrop();
Pixrect *mem_create();		/* General mpr create routine */
Pixrect *mem_point();		/* Even more general mpr create */
int	mem_destroy();
int	mem_get();
int	mem_put();
int	mem_vector();
Pixrect *mem_region();
#endif	/* _KERNEL */
int	mem_putcolormap();
int	mem_putattributes();
#ifndef _KERNEL
int	mem_getcolormap();
int	mem_getattributes();
#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MEMVAR_H */
