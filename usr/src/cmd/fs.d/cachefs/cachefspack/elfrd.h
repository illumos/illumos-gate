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
 * Copyright (c) 1996, by Sun Microsystems, Inc.
 * All Rights Reserved.
 */

#ifndef	_ELFRD_H
#define	_ELFRD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

struct libpath *add_libpath(struct libpath *, char *, int);
struct libpath *stk_libpath(struct libpath *, char *, int);
struct libpath *pop_libpath(struct libpath *);


struct sobj {
	char *so_name;
	struct sobj *so_next;
};

struct libpath {
	char *lp_path;
	struct libpath *lp_next;
	int lp_level;
};


#define	ERR_NOERROR	0
#define	ERR_NOFILE	-1
#define	ERR_NOELFVER	-2
#define	ERR_NOELFBEG	-3
#define	ERR_NOELFEHD	-4
#define	ERR_NOELFSHD	-5
#define	ERR_NOELFSDT	-6
#define	ERR_NOELFNAM	-7
#define	ERR_HASHFULL	-8


#define	GSO_ADDEXCLD	1

#ifdef MAIN
#define	EXTERN
#else
#define	EXTERN	extern
#endif

EXTERN struct libpath *libp, libp_hd;

#undef EXTERN

#endif /* _ELFRD_H */
