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
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * This header file defines the internal interfaces for the default audio
 * mixer sample rate converted. It is NOT to be distributed with Solaris.
 */

#ifndef	_SYS_AM_SRC1_IMPL_H
#define	_SYS_AM_SRC1_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/note.h>
#include <sys/types.h>
#include <sys/audio/am_src1.h>

/*
 * am_src1_data_t	- sample rate conversion algorithm #1 data
 */
#define	AM_SRC1_MUPSIZE1	4		/* max up/down conversions */
struct am_src1_data {
	kmutex_t	src1_lock;		/* protects this structure */
	uint_t		src1_inFs;		/* input sample rate */
	uint_t		src1_outFs;		/* device sample rate */
	int		src1_k;			/* filter parameter */
	int		src1_up[AM_SRC1_MUPSIZE1];	/* up sample steps */
	int		src1_down[AM_SRC1_MUPSIZE1];	/* down sample steps */
	int		src1_ustart1[AM_SRC1_MUPSIZE1];
						/* up smpl saved samps, L */
	int		src1_ustart2[AM_SRC1_MUPSIZE1];
						/* up smpl saved samps, R */
	int		src1_dstart[AM_SRC1_MUPSIZE1];
						/* dwn sample saved samples */
	int		src1_out1[AM_SRC1_MUPSIZE1];
						/* down sample saved samples */
	int		src1_out2[AM_SRC1_MUPSIZE1];
						/* down sample saved samples */
	int		(*src1_up0)(struct am_src1_data *, int, int,
				int *, int *, int);
	int		(*src1_up1)(struct am_src1_data *, int, int,
				int *, int *, int);
	int		(*src1_up2)(struct am_src1_data *, int, int,
				int *, int *, int);
	int		(*src1_up3)(struct am_src1_data *, int, int,
				int *, int *, int);
	int		src1_up_factor;		/* total up conversions */
	int		src1_down_factor;	/* total down conversions */
	int		src1_count;		/* number of up conversions */
};
typedef struct am_src1_data am_src1_data_t;

_NOTE(MUTEX_PROTECTS_DATA(am_src1_data::src1_lock, am_src1_data))

/* fudge factor to make sure we've got enough memory */
#define	AM_SRC1_BUFFER		(8 * sizeof (int))

/* misc. defines */
#define	AM_SRC1_SHIFT1		1
#define	AM_SRC1_SHIFT2		2
#define	AM_SRC1_SHIFT3		3
#define	AM_SRC1_SHIFT8		8
#define	AM_INT32_SHIFT		2
#define	SRC_MAX(a, b)		((a) > (b) ? (a) : (b))
#define	SRC_MAX4(w, x, y, z)	SRC_MAX(SRC_MAX(w, x), SRC_MAX(y, z))

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_AM_SRC1_IMPL_H */
