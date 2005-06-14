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
 * Copyright 1990-1998, 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_BYTEORDER_H
#define	_BYTEORDER_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <sys/fs/ufs_fsdir.h>
#include <sys/fs/ufs_acl.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	SUPPORTS_MTB_TAPE_FORMAT
#include <protocols/dumprestore.h>
#include <assert.h>

struct byteorder_ctx {
	int initialized;
	int Bcvt;
};

#ifdef __STDC__
extern struct byteorder_ctx *byteorder_create(void);
extern void byteorder_destroy(struct byteorder_ctx *);
extern void byteorder_banner(struct byteorder_ctx *, FILE *);
extern void swabst(char *, uchar_t *);
extern uint32_t swabl(uint32_t);
extern int normspcl(struct byteorder_ctx *, struct s_spcl *, int *, int, int);
extern void normdirect(struct byteorder_ctx *, struct direct *);
extern void normacls(struct byteorder_ctx *, ufs_acl_t *, int);
#else /* __STDC__ */
extern struct byteorder_ctx *byteorder_create();
extern void byteorder_destroy();
extern void byteorder_banner();
extern void swabst();
extern uint32_t swabl();
extern int normspcl();
extern void normdirect();
extern void normacls();
#endif /* __STDC__ */

#ifdef	__cplusplus
}
#endif

#endif /* _BYTEORDER_H */
