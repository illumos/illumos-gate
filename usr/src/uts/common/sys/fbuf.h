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
 * Copyright (c) 1997-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef _SYS_FBUF_H
#define	_SYS_FBUF_H

#include <sys/vnode.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * A struct fbuf is used to get a mapping to part of a file using the
 * segkmap facilities.  After you get a mapping, you can fbrelse() it
 * (giving a seg code to pass back to segmap_release), you can fbwrite()
 * it (causes a synchronous write back using the file mapping information),
 * or you can fbiwrite it (causing indirect synchronous write back to
 * the block number given without using the file mapping information).
 */

struct fbuf {
	caddr_t	fb_addr;
	uint_t	fb_count;
};

extern int fbread(struct vnode *, offset_t, uint_t, enum seg_rw,
    struct fbuf **);
extern void fbzero(struct vnode *, offset_t, uint_t, struct fbuf **);
extern int fbwrite(struct fbuf *);
extern int fbdwrite(struct fbuf *);
extern int fbiwrite(struct fbuf *, struct vnode *, daddr_t bn, int bsize);
extern void fbrelse(struct fbuf *, enum seg_rw);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FBUF_H */
