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
 * Copyright 1990 by Sun Microsystems, Inc.
 */

#ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Memory pixrect (non)creation in kernel
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/pixrect.h>
/* #include "/usr/include/pixrect/pixrect.h" */

int	mem_rop();
int	mem_putcolormap();
int	mem_putattributes();

struct	pixrectops mem_ops = {
	mem_rop,
	mem_putcolormap,
	mem_putattributes,
#ifdef _PR_IOCTL_KERNEL_DEFINED
	0
#endif
};

/*ARGSUSED*/
int
mem_rop(dpr, dx, dy, dw, dh, op, spr, sx, sy)
Pixrect *dpr;
int dx, dy, dw, dh;
int op;
Pixrect *spr;
int sx, sy;
{
#ifdef DEBUG
	cmn_err(CE_PANIC, "mem_rop: pixrects not supported.");
#endif
	return (PIX_ERR); /* fail */
}

/*ARGSUSED*/
int
mem_putcolormap(pr, index, count, red, green, blue)
Pixrect *pr;
int index, count;
u_char red[], green[], blue[];
{
#ifdef DEBUG
	cmn_err(CE_PANIC,
	    "mem_putcolormap: pixrects not supported.");
#endif
	return (PIX_ERR); /* fail */
}

/*ARGSUSED*/
int
mem_putattributes(pr, planes)
Pixrect *pr;
int *planes;
{
#ifdef DEBUG
	cmn_err(CE_PANIC,
	    "mem_putattributes: pixrects not supported.");
#endif
	return (PIX_ERR);
}
