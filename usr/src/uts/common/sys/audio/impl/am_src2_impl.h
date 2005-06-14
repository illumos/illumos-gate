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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * This header file defines the internal interfaces for the alternative audio
 * mixer sample rate converter. It is NOT to be distributed with Solaris.
 */

#ifndef	_SYS_AM_SRC2_IMPL_H
#define	_SYS_AM_SRC2_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/note.h>
#include <sys/types.h>
#include <sys/audio/am_src2.h>

/* misc. defines */
#define	AM_SRC2_NZCS		(10)		/* number of zero crossings */
#define	AM_SRC2_CPZC		(256)		/* coeffs per zero crossing */
#define	AM_SRC2_CPZC_SHIFT	(8)		/* 1 << CPZC_SHIFT = CPZC */
#define	AM_SRC2_CPZC_MASK	(0xFF)		/* for modulo arithmetic */
#define	AM_SRC2_STEREO_MASK	(0x1)		/* for modulo arithmetic */
#define	AM_SRC2_COFF_SHIFT	(16)		/* for scaling output */
#define	AM_SRC2_COFFS		((2 * AM_SRC2_NZCS) + 1) /* coefficients */
#define	AM_SRC2_SHIFT1		(1)
#define	AM_SRC2_SHIFT2		(2)

/* We define the location of the first, middle and last coefficients */
#define	AM_SRC2_START		(AM_SRC2_NZCS)
#define	AM_SRC2_MIDDLE		((AM_SRC2_NZCS * AM_SRC2_CPZC) + AM_SRC2_CPZC)
#define	AM_SRC2_END		((2 * AM_SRC2_NZCS * AM_SRC2_CPZC) + \
				AM_SRC2_CPZC)

/*
 * We define the maximum amount of prebuffer room required.
 * If playing, it is assumed we are increasing the sample rate
 * in which case the amount of room required is given by
 * 2 * max_channels * nzcs.
 */
#define	AM_SRC2_PBUFFER		(2 * 2 * AM_SRC2_NZCS)

/*
 * When down sampling the amount of prebuffer room required
 * depends on the conversion factor. Here we assume that this
 * factor will never be greater than 12 (i.e. 48kHz -> 4kHz)
 * and we allocate enough memory to cope with that. A little
 * wasteful but worth it for the simplicity achieved. Here
 * the room required is 2 * max_channels * max_factor * nzcs.
 */
#define	AM_SRC2_RBUFFER		(2 * 2 * 12 * AM_SRC2_NZCS)

/*
 * am_src2_data_t	- sample rate conversion algorithm #2 data
 */
struct am_src2_data {
	kmutex_t	src2_lock;	/* protects this structure */
	int		src2_inFs;	/* input sample rate */
	int		src2_outFs;	/* device sample rate */
	int		(*src2_resample)(struct am_src2_data *, int *, int *,
				int);	/* resampling function */
	int		src2_pbsize;	/* room in front of samples */
	int		src2_delta_c;	/* distance to nearest input sample */
	int		src2_delta_n;	/* normalised delta_c */
	int		src2_i_index;	/* start point in input */
	int		src2_csteps;	/* step size through input */
	int		src2_cmod;	/* fraction of csteps left over */
	int		src2_cover;	/* fraction of csteps counter */
	int		src2_tsteps;	/* step size through filter */
	int		*src2_table;	/* filter coefficients */
	int		**src2_tables;  /* individual tables */
};

typedef struct am_src2_data am_src2_data_t;

_NOTE(MUTEX_PROTECTS_DATA(am_src2_data::src2_lock, am_src2_data))

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_AM_SRC2_IMPL_H */
