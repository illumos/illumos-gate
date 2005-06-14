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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_PIXRECT_H
#define	_SYS_PIXRECT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SunOS4.1.2 1.51 */

#include <sys/types.h>	/* system type defs */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This file defines the programmer interface to the pixrect abstraction.
 * A pixrect is a rectangular array of pixels on which a number of
 * operations are defined.
 *
 * Each pixrect has as visible attributes its height and width in
 * pixels and the number of bits stored for each pixel.	 It also supports
 * several operations.	The proper way to think of the operations is
 * that they are messages sent to the pixrect.	The operations are:
 *
 *	pr_destroy	Destroy a pixrect.
 *	pr_rop		Raster operation from another pixrect to the
 *			destination pixrect.  The case where the source
 *			and destination overlap is properly handled.
 *	pr_stencil	Raster operation from source pixrect to the
 *			dest pixrect using a stencil pixrect as a 'cookie
 *			cutter' to perform a spatial write enable.
 *	pr_batchrop	Like pr_rop, but source is an array of pixrects,
 *			and an offset to be applied before each pixrect.
 *			This is specifically designed for operations like
 *			putting up text, which consists of a number of
 *			characters from a font, each given by a pixrect.
 *	pr_get		Get the value of a single pixel from a pixrect.
 *	pr_put		Change a single pixel value in a pixrect.
 *	pr_vector	Draw a vector in a pixrect
 *	pr_region	Create a new pixrect which describes a rectangular
 *			sub-region of an existing pixrect.
 *	pr_putcolormap	Write a portion of the colormap.
 *	pr_getcolormap	Read a portion of the colormap.
 *	pr_putattributes Set the plane mask.
 *	pr_getattributes Get the plane mask.
 */

/*
 * There are a number of structures used in the arguments to pixrects:
 *
 *	struct pr_pos		A position within a pixrect is a pair of
 *				integers giving the offset from the upper
 *				left corner.  The pixels within a pixrect
 *				are numbered with (0, 0) at the upper left
 *				and (width-1, height-1) at the lower right.
 *	struct pr_prpos		A pixrect and a position within it.
 *	struct pr_size		A pair of integers representing the
 *				size of a rectangle within a pixrect.
 *	struct pr_subregion	A pixrect, a position and a size,
 *				specifying a rectangular sub-region.
 */

struct pr_size {
	int	x, y;
};

typedef struct pixrect {
	struct	pixrectops *pr_ops;	/* operations appropriate to this pr */
	struct	pr_size pr_size;	/* pixels per dimension */
	int	pr_depth;		/* bits per pixel */
	caddr_t pr_data;		/* device-dependent data */
} Pixrect;
#define	pr_width	pr_size.x
#define	pr_height	pr_size.y

struct pr_pos {
	int	x, y;
};

struct pr_prpos {
	Pixrect *pr;
	struct	pr_pos pos;
};

struct pr_subregion {
	Pixrect *pr;
	struct	pr_pos pos;
	struct	pr_size size;
};

/*
 * Pr_product is used when doing multiplications involving pixrects,
 * and casts its arguments to that the compiler will use 16 by 16 multiplies.
 */
#ifndef pr_product
#if defined(__sun) && !defined(__sparc)
#define	pr_product(a, b)	((short)(a) * (short)(b))
#else
#define	pr_product(a, b)	((a) * (b))
#endif
#endif

#ifndef _KERNEL
/*
 * Takes device file name.  This is how a screen pixrect is created.
 */
extern Pixrect *pr_open();
#endif	/* !_KERNEL */

/*
 * Pixrect ops vector, used by pr_ macros below to call the appropriate
 * device dependent function for the destination pixrect.
 */
struct pixrectops {
	int	(*pro_rop)();
#ifndef _KERNEL
	int	(*pro_stencil)();
	int	(*pro_batchrop)();
	int	(*pro_nop)();		/* place holder */
	int	(*pro_destroy)();
	int	(*pro_get)();
	int	(*pro_put)();
	int	(*pro_vector)();
	Pixrect * (*pro_region)();
#endif	/* !_KERNEL */
	int	(*pro_putcolormap)();
#ifndef _KERNEL
	int	(*pro_getcolormap)();
#endif	/* !_KERNEL */
	int	(*pro_putattributes)();
#ifndef _KERNEL
	int	(*pro_getattributes)();
#endif	/* !_KERNEL */
#ifdef _KERNEL
	int	(*pro_nop)();		/* place holder */
#endif	/* _KERNEL */
};

#if !defined(__lint) || defined(_KERNEL)

#define	pr_rop(dpr, dx, dy, w, h, op, spr, sx, sy) \
	(*(dpr)->pr_ops->pro_rop)((dpr), (dx), (dy), (w), (h), (op), \
		(spr), (sx), (sy))
#define	pr_putcolormap(pr, ind, cnt, red, grn, blu) \
	(*(pr)->pr_ops->pro_putcolormap)((pr), (ind), (cnt), \
		(red), (grn), (blu))
#define	pr_putattributes(pr, planes) \
	(*(pr)->pr_ops->pro_putattributes)((pr), (planes))
#define	_PR_IOCTL_KERNEL_DEFINED
#define	pr_ioctl(pr, cmd, data) \
	((pr)->pr_ops->pro_nop ? \
	(*(pr)->pr_ops->pro_nop)((pr), (cmd), (data)) : -1)

#ifndef _KERNEL

#define	pr_stencil(dpr, dx, dy, w, h, op, stpr, stx, sty, spr, sx, sy) \
	(*(dpr)->pr_ops->pro_stencil)((dpr), (dx), (dy), (w), (h), (op), \
		(stpr), (stx), (sty), (spr), (sx), (sy))
#define	pr_batchrop(dpr, x, y, op, sbp, n) \
	(*(dpr)->pr_ops->pro_batchrop)((dpr), (x), (y), (op), (sbp), (n))
#define	pr_destroy(pr) \
	(*(pr)->pr_ops->pro_destroy)(pr)
#define	pr_get(pr, x, y) \
	(*(pr)->pr_ops->pro_get)((pr), (x), (y))
#define	pr_put(pr, x, y, val) \
	(*(pr)->pr_ops->pro_put)((pr), (x), (y), (val))
#define	pr_vector(pr, x0, y0, x1, y1, op, color) \
	(*(pr)->pr_ops->pro_vector)((pr), (x0), (y0), (x1), (y1), (op), \
		(color))
#define	pr_region(pr, x, y, w, h) \
	(*(pr)->pr_ops->pro_region)((pr), (x), (y), (w), (h))
#define	pr_getcolormap(pr, ind, cnt, red, grn, blu) \
	(*(pr)->pr_ops->pro_getcolormap)((pr), (ind), (cnt), \
		(red), (grn), (blu))
#define	pr_getattributes(pr, planes) \
	(*(pr)->pr_ops->pro_getattributes)((pr), (planes))

#endif	/* !_KERNEL */

#else	/* !__lint || _KERNEL */

extern pr_rop();
extern pr_stencil();
extern pr_batchrop();
extern pr_destroy();
extern pr_get();
extern pr_put();
extern pr_vector();
extern Pixrect *pr_region();
extern pr_putcolormap();
extern pr_getcolormap();
extern pr_putattributes();
extern pr_getattributes();

#endif	/* __lint */

/*
 * Several of the above operations return a common, distinguished value when
 * an error arises.  That value is defined as follows:
 */
#define	PIX_ERR -1

/*
 * Operations.	The 'op' in 'rasterop' may be any binary Boolean function,
 * encoded as an integer from 0 to 15 (the op code) shifted left by one bit.
 * The function is applied per-pixel.
 *
 * The following permit the op to be expressed as Boolean combinations
 * of the two inputs 'src' and 'dst'.  Thus oring the source and destination
 * together is written as PIX_SRC|PIX_DST, while xoring the source with the
 * destination is PIX_SRC^PIX_DST.  Since ~op would set the color and clip
 * bits, the macro PIX_NOT is provided for use in place of ~.
 */
#define	PIX_SRC		(0xC << 1)
#define	PIX_DST		(0xA << 1)
#define	PIX_NOT(op)	((op) ^ 0x1E)
#define	PIX_CLR		(0x0 << 1)
#define	PIX_SET		(0xF << 1)

/* macros which tell whether a rasterop needs SRC or DST values */
#define	PIXOP_NEEDS_DST(op)	((((op)>>1)^(op)) & PIX_NOT(PIX_DST))
#define	PIXOP_NEEDS_SRC(op)	((((op)>>2)^(op)) & PIX_NOT(PIX_SRC))

/* macros for encoding and extracting color field */
#define	PIX_COLOR(c)	((c)<<5)
#define	PIX_OPCOLOR(op) ((op)>>5)
#define	PIX_OP_CLIP(op) ((op)&0x1f)
#define	PIX_OP(op)	((op)&0x1e)

/*
 * The pseudo-operation PIX_DONTCLIP specifies that clipping should not
 * be performed.  PIX_CLIP is also provided, although unnecessary.
 */
#define	PIX_DONTCLIP		0x1
#define	PIX_CLIP		0x0

/*
 * The following structured definitions, all prefixed with prs_, correspond
 * to the unstructured definitions above prefixed with pr_.
 */

#if !defined(__lint) || defined(_KERNEL)

#define	prs_rop(dstreg, op, srcprpos) \
	pr_rop((dstreg).pr, (dstreg).pos.x, (dstreg).pos.y, \
		(dstreg).size.x, (dstreg).size.y, (op), \
		(srcprpos).pr, (srcprpos).pos.x, (srcprpos).pos.y)
#define	prs_stencil(dstreg, op, stenprpos, srcprpos) \
	pr_stencil((dstreg).pr, (dstreg).pos.x, (dstreg).pos.y, \
		(dstreg).size.x, (dstreg).size.y, (op), \
		(stenprpos).pr, (stenprpos).pos.x, (stenprpos).pos.y, \
		(srcprpos).pr, (srcprpos).pos.x, (srcprpos).pos.y)
#define	prs_batchrop(dstprpos, op, items, n) \
	pr_batchrop((dstprpos).pr, (dstprpos).pos.x, (dstprpos).pos.y, \
		(op), (items), (n))
#define	prs_destroy(pr)		pr_destroy(pr)
#define	prs_get(srcprpos) \
	pr_get((srcprpos).pr, (srcprpos).pos.x, (srcprpos).pos.y)
#define	prs_put(dstprpos, val) \
	pr_put((dstprpos).pr, (dstprpos).pos.x, (dstprpos).pos.y, (val))
#define	prs_vector(pr, pos0, pos1, op, color) \
	pr_vector((pr), (pos0).x, (pos0).y, (pos1).x, (pos1).y, (op), (color))
#define	prs_region(dstreg) \
	pr_region((dstreg).pr, (dstreg).pos.x, (dstreg).pos.y, \
		(dstreg).size.x, (dstreg).size.y)
#define	prs_putcolormap(pr, ind, cnt, red, grn, blu) \
	pr_putcolormap((pr), (ind), (cnt), (red), (grn), (blu))
#define	prs_getcolormap(pr, ind, cnt, red, grn, blu) \
	pr_getcolormap((pr), (ind), (cnt), (red), (grn), (blu))
#define	prs_putattributes(pr, planes)	pr_putattributes((pr), (planes))
#define	prs_getattributes(pr, planes)	pr_getattributes((pr), (planes))

/* pr_replrop is not currently in the ops vector */
#define	prs_replrop(dstreg, op, srcprpos) \
	pr_replrop((dstreg).pr, (dstreg).pos.x, (dstreg).pos.y, \
		(dstreg).size.x, (dstreg).size.y, (op), \
		(srcprpos).pr, (srcprpos).pos.x,  (srcprpos).pos.y)

/* pr_close is a synonym for pr_destroy */
#define	pr_close(pr)	pr_destroy(pr)

/* textured line macro */
#define	pr_line(pr, x0, y0, x1, y1, brush, tex, op) \
	pro_line((pr), (x0), (y0), (x1), (y1), (brush), (tex), (op), 0)

#else	/* !__lint || _KERNEL */

extern prs_rop();
extern prs_stencil();
extern prs_batchrop();
extern prs_destroy();
extern prs_get();
extern prs_put();
extern prs_vector();
extern Pixrect *prs_region();
extern prs_putcolormap();
extern prs_getcolormap();
extern prs_putattributes();
extern prs_getattributes();

extern prs_replrop();
extern pr_close();
extern pr_line();

#endif	/* !__lint || _KERNEL */



/*
 * magic flag passed to true color frame buffer to force updating the
 * colormap.  Yes, a kludge.
 * Value defined to be the same as PIX_DONT_SET_PLANES purposedly
 */
#define	PR_FORCE_UPDATE (1 << 24)
/*
 * Yet another magic flag - to explicitly not use the
 * inverse gamma table.
 */
#define	PR_DONT_DEGAMMA (1 << 23)
#define	PR_DEGAMMA	(1 << 22)

#ifdef	ROUNDUP
#undef	ROUNDUP
#endif
#define	ROUNDUP(val, gran)	(((val) - 1 | (gran) - 1) + 1)

/* structure used to specify fields in a 32-bit pixel */
union fbunit {
    unsigned int    packed;		/* whole-sale deal */
    struct {
	unsigned int	A:8;		/* unused, for now */
	unsigned int	B:8;		/* blue channel */
	unsigned int	G:8;		/* green channel */
	unsigned int	R:8;		/* red channel */
	}	    channel;		/* access per channel */
};

#define	pr_putlut(pr, ind, cnt, red, grn, blu) \
	(*(pr)->pr_ops->pro_putcolormap)((pr), PR_FORCE_UPDATE | (ind), \
		(cnt), (red), (grn), (blu))

#ifndef _KERNEL
#define	pr_getlut(pr, ind, cnt, red, grn, blu) \
	(*(pr)->pr_ops->pro_getcolormap)((pr), PR_FORCE_UPDATE | (ind), \
		(cnt), (red), (grn), (blu))
#endif	/* !_KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PIXRECT_H */
