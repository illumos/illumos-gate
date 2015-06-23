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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Joyent, Inc.  All rights reserved.
 */

#ifndef	_SYS_FSS_H
#define	_SYS_FSS_H

#include <sys/types.h>
#include <sys/thread.h>
#include <sys/project.h>
#include <sys/cpucaps.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

typedef uint64_t fsspri_t;
typedef	uint64_t fssusage_t;
struct cpupart;
struct zone;

/*
 * Valid arg1's for fss_allocbuf()
 */
#define	FSS_NPSET_BUF	1
#define	FSS_NPROJ_BUF	2
#define	FSS_ONE_BUF	3

/*
 * Valid arg2's for fss_allocbuf()
 */
#define	FSS_ALLOC_PROJ	1
#define	FSS_ALLOC_ZONE	2

#define	FSS_MAXSHARES	65535

typedef struct fssbuf {
	int	fssb_size;
	void	**fssb_list;
} fssbuf_t;

void *fss_allocbuf(int, int);
void fss_freebuf(fssbuf_t *, int);
void fss_changeproj(kthread_id_t, void *, void *, fssbuf_t *, fssbuf_t *);
void fss_changepset(kthread_id_t, void *, fssbuf_t *, fssbuf_t *);

/*
 * Fair share scheduling class specific cpu partition structure
 */
typedef struct fsspset {
	kmutex_t	fssps_lock;	/* lock to protect per-pset	*/
					/* list of fssproj structures	*/
	disp_lock_t	fssps_displock;	/* lock for fsps_maxfsspri	*/
	struct cpupart	*fssps_cpupart;	/* ptr to our cpu partition	*/
					/* protected by fsspsets_lock	*/
	fsspri_t	fssps_maxfsspri; /* maximum fsspri value among	*/
					/* all projects on this pset	*/
	uint32_t	fssps_shares;	/* number of active shares	*/
	uint32_t	fssps_nproj;	/* number of fssproj structures */
					/* on the list			*/
	struct fssproj	*fssps_list;	/* list of project parts	*/
	struct fsszone	*fssps_zones;	/* list of fsszone_t's in pset	*/
	uint32_t	fssps_gen;	/* generation for zone's kstats */
} fsspset_t;

/*
 * One of these structures is allocated to each project running within each
 * active cpu partition.
 */
typedef struct fssproj {
	kproject_t	*fssp_proj;	/* ptr to our project structure	*/
	fsspset_t	*fssp_pset;	/* ptr to our fsspset structure	*/
	uint32_t	fssp_threads;	/* total number of threads here */
					/* protected by fssps_lock	*/
	uint32_t	fssp_runnable;	/* number of runnable threads	*/
					/* protected by fssps_lock	*/
	uint32_t	fssp_shares;	/* copy of our kpj_shares	*/
					/* protected by fssps_displock	*/
	uint32_t	fssp_ticks;	/* total of nice tick values	*/
					/* protected by fssps_displock	*/
	uint32_t	fssp_tick_cnt;	/* cnt of all ticks in this sec	*/
	uint32_t	fssp_shr_pct;	/* active shr % in this sec	*/
					/* protected by fssps_displock	*/
	fssusage_t	fssp_usage;	/* this project's decayed usage */
	fssusage_t	fssp_shusage;	/* normalized usage		*/
	struct fssproj	*fssp_next;	/* next project on this pset	*/
	struct fssproj	*fssp_prev;	/* prev project on this pset	*/
	struct fsszone	*fssp_fsszone;	/* fsszone_t for this fssproj	*/
} fssproj_t;

/*
 * Fair share scheduling class specific thread structure
 */
typedef struct fssproc {
	kthread_t *fss_tp;	/* pointer back to our thread		*/
	fssproj_t *fss_proj;	/* pointer to our project FSS data	*/
	uchar_t fss_flags;	/* flags defined below			*/
	int	fss_timeleft;	/* time remaining in procs quantum	*/
	uint32_t fss_ticks;	/* ticks accumulated by this thread	*/
	pri_t	fss_upri;	/* user supplied priority (to priocntl)	*/
	pri_t	fss_uprilim;	/* user priority limit			*/
	pri_t	fss_umdpri;	/* user mode priority within fs class	*/
	pri_t	fss_scpri;	/* remembered priority, for schedctl	*/
	int	fss_nice;	/* nice value for compatibility with ts	*/
	fsspri_t fss_fsspri;	/* internal fair share priority		*/
	int	fss_runnable;	/* to indicate runnable/sleeping thread	*/
	struct fssproc *fss_next; /* pointer to next fssproc_t struct	*/
	struct fssproc *fss_prev; /* pointer to prev fssproc_t sturct	*/
	caps_sc_t fss_caps;	/* CPU caps specific data		*/
} fssproc_t;

/*
 * One of these structures is allocated to each zone running within
 * each active cpu partition.  This means that if a zone spans more
 * than one cpu partition then it will have a few of these structures.
 */
typedef struct fsszone {
	struct zone 	*fssz_zone;	/* ptr to our zone structure	*/
	struct fsszone	*fssz_next;	/* next fsszone_t in fsspset_t	*/
	struct fsszone	*fssz_prev;	/* prev fsszone_t in fsspset_t	*/
	uint32_t	fssz_shares;	/* sum of all project shares	*/
	uint32_t	fssz_nproj;	/* # of projects		*/
	uint32_t	fssz_rshares;	/* "real" shares given to zone	*/
	uint32_t	fssz_runnable;	/* # of runnable projects	*/
} fsszone_t;

#define	FSSPROC(tx)		((fssproc_t *)(tx->t_cldata))
#define	FSSPROC2FSSPROJ(fssx)	((fssx)->fss_proj);
#define	FSSPROC2FSSPSET(fssx)	(FSSPROC2FSSPROJ(fssx)->fssp_pset)
#define	FSSPROJ(tx)		(FSSPROC(tx)->fss_proj)
#define	FSSPROJ2FSSPSET(fssx)	((fssx)->fssp_pset)
#define	FSSPROJ2KPROJ(fssx)	((fssx)->fssp_proj)
#define	FSSPROJ2FSSZONE(fssx)	((fssx)->fssp_fsszone)

/*
 * fss_flags
 */
#define	FSSKPRI		0x01	/* the thread is in kernel mode	*/
#define	FSSBACKQ	0x02	/* thread should be placed at the back of */
				/* the dispatch queue if preempted */
#define	FSSRESTORE	0x04	/* thread was not preempted, due to schedctl */
				/* restore priority from fss_scpri */

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FSS_H */
