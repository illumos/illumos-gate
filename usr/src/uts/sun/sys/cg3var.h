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
 * Copyright 1989 by Sun Microsystems, Inc.
 */

#ifndef	_SYS_CG3VAR_H
#define	_SYS_CG3VAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * cg3 -- color memory frame buffer
 */

/*
 * On architectures where cg4s have been implemented we need a nice big
 * mmap offset to avoid the cg4 compatible simulated overlay/enable planes.
 */
#define	CG3_MMAP_OFFSET	0x04000000	/* 8K x 8K */

/*
 * In the kernel we just use a memory pixrect so we don't
 * need any of this stuff.
 */
#ifndef _KERNEL
#include <sys/memvar.h>

/* pixrect private data */
struct cg3_data {
	struct mprp_data mprp;		/* memory pixrect simulator */
	int fd;				/* file descriptor */
};

#define	cg3_d(pr)	((struct cg3_data *) (pr)->pr_data)

/* pixrect ops vector */
extern struct pixrectops cg3_ops;

Pixrect	*cg3_make();
int cg3_destroy();
Pixrect *cg3_region();
int cg3_putcolormap();
int cg3_getcolormap();
#endif /* !_KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_CG3VAR_H */
