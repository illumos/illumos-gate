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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_FB_STATS_H
#define	_FB_STATS_H

#include "config.h"
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

var_t *stats_findvar(var_t *var, char *name);
void stats_init(void);
void stats_clear(void);
void stats_snap(void);
void stats_dump(char *filename);
void stats_xmldump(char *filename);
void stats_multidump(char *filename);

#ifndef HAVE_HRTIME
/* typedef uint64_t hrtime_t; */
#define	hrtime_t uint64_t
#endif

#define	STATS_VAR "stats."

#define	FLOW_MSTATES 4
#define	FLOW_MSTATE_LAT 0	/* Total service time of op */
#define	FLOW_MSTATE_CPU 1	/* On-cpu time of op */
#define	FLOW_MSTATE_WAIT 2	/* Wait-time, excluding waiting for CPU */
#define	FLOW_MSTATE_OHEAD 3	/* overhead time, around op */

typedef struct flowstats {
	int		fs_children;	/* Number of contributors */
	int		fs_active;	/* Number of active contributors */
	int		fs_count;	/* Number of ops */
	uint64_t	fs_rbytes;	/* Number of bytes  */
	uint64_t	fs_wbytes;	/* Number of bytes  */
	uint64_t	fs_bytes;	/* Number of bytes  */
	uint64_t	fs_rcount;	/* Number of ops */
	uint64_t	fs_wcount;	/* Number of ops */
	hrtime_t	fs_stime;	/* Time stats for flow started */
	hrtime_t	fs_etime;	/* Time stats for flow ended */
	hrtime_t	fs_mstate[FLOW_MSTATES]; /* Microstate breakdown */
	hrtime_t	fs_syscpu;	/* System wide cpu, global only */
} flowstat_t;


#define	IS_FLOW_IOP(x) (x->fo_stats.fs_rcount + x->fo_stats.fs_wcount)
#define	STAT_IOPS(x)   ((x->fs_rcount) + (x->fs_wcount))
#define	IS_FLOW_ACTIVE(x) (x->fo_stats.fs_count)
#define	STAT_CPUTIME(x) (x->fs_cpu_op)
#define	STAT_OHEADTIME(x) (x->fs_cpu_ohead)

#ifdef	__cplusplus
}
#endif

#endif	/* _FB_STATS_H */
