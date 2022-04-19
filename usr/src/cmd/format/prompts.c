/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file contains functions to prompt the user for various
 * disk characteristics.  By isolating these into functions,
 * we can guarantee that prompts, defaults, etc are identical.
 */
#include "global.h"
#include "prompts.h"
#include "io.h"
#include "param.h"
#include "startup.h"

#ifdef sparc
#include <sys/hdio.h>
#endif


/*
 * Prompt for max number of LBA
 */
uint64_t
get_mlba(void)
{
	u_ioparam_t	ioparam;

	ioparam.io_bounds.lower = (1024 * 16) + 68;
	ioparam.io_bounds.upper = UINT_MAX64;

	return (input(FIO_INT64, "Enter maximum number of LBAs",
	    ':', &ioparam, NULL, DATA_INPUT));
}

/*
 * Prompt for number of cylinders
 */
int
get_ncyl(void)
{
	u_ioparam_t	ioparam;

	ioparam.io_bounds.lower = 1;
	ioparam.io_bounds.upper = MAX_CYLS;
	return (input(FIO_INT, "Enter number of data cylinders",
	    ':', &ioparam, NULL, DATA_INPUT));
}

/*
 * Prompt for number of alternate cylinders
 */
int
get_acyl(int n_cyls)
{
	u_ioparam_t	ioparam;
	int		deflt;

	ioparam.io_bounds.lower = 2;
	ioparam.io_bounds.upper = MAX_CYLS - n_cyls;
	deflt = 2;
	return (input(FIO_INT, "Enter number of alternate cylinders", ':',
	    &ioparam, &deflt, DATA_INPUT));
}

/*
 * Prompt for number of physical cylinders
 */
int
get_pcyl(int n_cyls, int a_cyls)
{
	u_ioparam_t	ioparam;
	int		deflt;

	ioparam.io_bounds.lower = n_cyls + a_cyls;
	ioparam.io_bounds.upper = MAX_CYLS;
	deflt = n_cyls + a_cyls;
	return (input(FIO_INT, "Enter number of physical cylinders", ':',
	    &ioparam, &deflt, DATA_INPUT));
}

/*
 * Prompt for number of heads
 */
int
get_nhead(void)
{
	u_ioparam_t	ioparam;

	ioparam.io_bounds.lower = 1;
	ioparam.io_bounds.upper = MAX_HEADS;
	return (input(FIO_INT, "Enter number of heads", ':',
	    &ioparam, NULL, DATA_INPUT));
}

/*
 * Prompt for number of physical heads
 */
int
get_phead(int n_heads, ulong_t *options)
{
	u_ioparam_t	ioparam;
	int		deflt;

	if (SCSI) {
		ioparam.io_bounds.lower = n_heads;
		ioparam.io_bounds.upper = INFINITY;
		if (input(FIO_OPINT, "Enter physical number of heads",
		    ':', &ioparam, &deflt, DATA_INPUT)) {
			*options |= SUP_PHEAD;
			return (deflt);
		}
	}
	return (0);
}


/*
 * Prompt for number of sectors per track
 */
int
get_nsect(void)
{
	u_ioparam_t	ioparam;

	ioparam.io_bounds.lower = 1;
	ioparam.io_bounds.upper = MAX_SECTS;
	return (input(FIO_INT,
	    "Enter number of data sectors/track", ':',
	    &ioparam, NULL, DATA_INPUT));
}

/*
 * Prompt for number of physical sectors per track
 */
int
get_psect(ulong_t *options)
{
	u_ioparam_t	ioparam;
	int		deflt;

	if (SCSI) {
		ioparam.io_bounds.lower = 0;
		ioparam.io_bounds.upper = INFINITY;
		if (input(FIO_OPINT, "Enter number of physical sectors/track",
		    ':', &ioparam, &deflt, DATA_INPUT)) {
			*options |= SUP_PSECT;
			return (deflt);
		}
	}
	return (0);
}

/*
 * Prompt for bytes per track
 */
int
get_bpt(int n_sects, ulong_t *options)
{
	u_ioparam_t	ioparam;
	int		deflt;

	if (SMD) {
		*options |= SUP_BPT;
		ioparam.io_bounds.lower = 1;
		ioparam.io_bounds.upper = INFINITY;
		deflt = n_sects * cur_blksz;
		return (input(FIO_INT, "Enter number of bytes/track",
		    ':', &ioparam, &deflt, DATA_INPUT));
	}

	return (0);
}

/*
 * Prompt for rpm
 */
int
get_rpm(void)
{
	u_ioparam_t	ioparam;
	int		deflt;

	ioparam.io_bounds.lower = MIN_RPM;
	ioparam.io_bounds.upper = MAX_RPM;
	deflt = AVG_RPM;
	return (input(FIO_INT, "Enter rpm of drive", ':',
	    &ioparam, &deflt, DATA_INPUT));
}

/*
 * Prompt for formatting time
 */
int
get_fmt_time(ulong_t *options)
{
	u_ioparam_t	ioparam;
	int		deflt;

	ioparam.io_bounds.lower = 0;
	ioparam.io_bounds.upper = INFINITY;
	if (input(FIO_OPINT, "Enter format time", ':',
	    &ioparam, &deflt, DATA_INPUT)) {
		*options |= SUP_FMTTIME;
		return (deflt);
	}
	return (0);
}

/*
 * Prompt for cylinder skew
 */
int
get_cyl_skew(ulong_t *options)
{
	u_ioparam_t	ioparam;
	int		deflt;

	ioparam.io_bounds.lower = 0;
	ioparam.io_bounds.upper = INFINITY;
	if (input(FIO_OPINT, "Enter cylinder skew", ':',
	    &ioparam, &deflt, DATA_INPUT)) {
		*options |= SUP_CYLSKEW;
		return (deflt);
	}
	return (0);
}

/*
 * Prompt for track skew
 */
int
get_trk_skew(ulong_t *options)
{
	u_ioparam_t	ioparam;
	int		deflt;

	ioparam.io_bounds.lower = 0;
	ioparam.io_bounds.upper = INFINITY;
	if (input(FIO_OPINT, "Enter track skew", ':',
	    &ioparam, &deflt, DATA_INPUT)) {
		*options |= SUP_TRKSKEW;
		return (deflt);
	}
	return (0);
}

/*
 * Prompt for tracks per zone
 */
int
get_trks_zone(ulong_t *options)
{
	u_ioparam_t	ioparam;
	int		deflt;

	ioparam.io_bounds.lower = 0;
	ioparam.io_bounds.upper = INFINITY;
	if (input(FIO_OPINT, "Enter tracks per zone", ':',
	    &ioparam, &deflt, DATA_INPUT)) {
		*options |= SUP_TRKS_ZONE;
		return (deflt);
	}
	return (0);
}

/*
 * Prompt for alternate tracks
 */
int
get_atrks(ulong_t *options)
{
	u_ioparam_t	ioparam;
	int		deflt;

	ioparam.io_bounds.lower = 0;
	ioparam.io_bounds.upper = INFINITY;
	if (input(FIO_OPINT, "Enter alternate tracks", ':',
	    &ioparam, &deflt, DATA_INPUT)) {
		*options |= SUP_ATRKS;
		return (deflt);
	}
	return (0);
}

/*
 * Prompt for alternate sectors
 */
int
get_asect(ulong_t *options)
{
	u_ioparam_t	ioparam;
	int		deflt;

	ioparam.io_bounds.lower = 0;
	ioparam.io_bounds.upper = INFINITY;
	if (input(FIO_OPINT, "Enter alternate sectors", ':',
	    &ioparam, &deflt, DATA_INPUT)) {
		*options |= SUP_ASECT;
		return (deflt);
	}
	return (0);
}

/*
 * Prompt for cache setting
 */
int
get_cache(ulong_t *options)
{
	u_ioparam_t	ioparam;
	int		deflt;

	ioparam.io_bounds.lower = 0;
	ioparam.io_bounds.upper = 0xff;
	if (input(FIO_OPINT, "Enter cache control", ':',
	    &ioparam, &deflt, DATA_INPUT)) {
		*options |= SUP_CACHE;
		return (deflt);
	}
	return (0);
}

/*
 * Prompt for prefetch threshold
 */
int
get_threshold(ulong_t *options)
{
	u_ioparam_t	ioparam;
	int		deflt;

	ioparam.io_bounds.lower = 0;
	ioparam.io_bounds.upper = INFINITY;
	if (input(FIO_OPINT, "Enter prefetch threshold",
	    ':', &ioparam, &deflt, DATA_INPUT)) {
		*options |= SUP_PREFETCH;
		return (deflt);
	}
	return (0);
}

/*
 * Prompt for minimum prefetch
 */
int
get_min_prefetch(ulong_t *options)
{
	u_ioparam_t	ioparam;
	int		deflt;

	ioparam.io_bounds.lower = 0;
	ioparam.io_bounds.upper = INFINITY;
	if (input(FIO_OPINT, "Enter minimum prefetch",
	    ':', &ioparam, &deflt, DATA_INPUT)) {
		*options |= SUP_CACHE_MIN;
		return (deflt);
	}
	return (0);
}

/*
 * Prompt for maximum prefetch
 */
int
get_max_prefetch(int min_prefetch, ulong_t *options)
{
	u_ioparam_t	ioparam;
	int		deflt;

	ioparam.io_bounds.lower = min_prefetch;
	ioparam.io_bounds.upper = INFINITY;
	if (input(FIO_OPINT, "Enter maximum prefetch",
	    ':', &ioparam, &deflt, DATA_INPUT)) {
		*options |= SUP_CACHE_MAX;
		return (deflt);
	}
	return (0);
}

/*
 * Prompt for bytes per sector
 */
int
get_bps(void)
{
	u_ioparam_t	ioparam;
	int		deflt;

	if (cur_ctype->ctype_flags & CF_SMD_DEFS) {
		ioparam.io_bounds.lower = MIN_BPS;
		ioparam.io_bounds.upper = MAX_BPS;
		deflt = AVG_BPS;
		return (input(FIO_INT, "Enter bytes per sector",
		    ':', &ioparam, &deflt, DATA_INPUT));
	}

	return (0);
}

/*
 * Prompt for ascii label
 */
char *
get_asciilabel(void)
{
	return ((char *)(uintptr_t)input(FIO_OSTR,
	    "Enter disk type name (remember quotes)", ':',
	    NULL, NULL, DATA_INPUT));
}
