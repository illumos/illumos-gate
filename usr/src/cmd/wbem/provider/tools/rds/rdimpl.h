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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_RDIMPL_H
#define	_RDIMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/types.h>
#include <procfs.h>
#include <setjmp.h>
#include <time.h>
#include <inttypes.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern int monitor_start();
extern void monitor_stop();
extern int monitor_update();
extern void list_clear();
extern char *ltdb_file;
extern int mo; /* option flag for microstate accounting	*/

/*
 * FRC2PCT macro is used to convert 16-bit binary fractions in the range
 * 0.0 to 1.0 with binary point to the right of the high order bit
 * (i.e. 1.0 == 0x8000) to percentage value.
 */

#define	FRC2PCT(pp)	(((float)(pp))/0x8000*100)

#define	TIME2NSEC(__t)\
(hrtime_t)(((hrtime_t)__t.tv_sec * (hrtime_t)NANOSEC) + (hrtime_t)__t.tv_nsec)
#define	TIME2SEC(__t)\
(hrtime_t)(__t.tv_sec)

/*
 * Possible list types
 */
#define	LT_LWPS		0x0001
#define	LT_USERS	0x0002
#define	LT_TASKS	0x0004
#define	LT_PROJECTS	0x0008
#define	LT_PSETS	0x0010
#define	LT_SYS		0x0020
#define	LT_PROCESS	0x0040

/*
 * Default list sizes
 */
#define	LS_LWPS		1024
#define	LS_PROCESSES	512
#define	LS_USERS	32
#define	LS_PROJECTS	16
#define	LS_PSETS	8
#define	LS_SYS		1

/*
 * Linked list of per-process or per-lwp statistics
 */
typedef struct lwp_info {
	psinfo_t	*li_psinfo;	/* data read from psinfo file	*/
	lwpsinfo_t	*li_lwpsinfo;
	prusage_t	li_usage;	/* data read from usage file	*/
	int		li_alive;	/* flag for alive lwps	*/
	int		rlwpid;		/* id of the representative lwp	*/

	double	li_usr;		/* user level CPU time		*/
	double	li_sys;		/* system call CPU time		*/
	double	li_ttime;	/* SystemTrapTime		*/
	double	li_tpftime;	/* TextPageFaultSleepTime	*/
	double	li_dpftime;	/* DataPageFaultSleepTime	*/
	double	li_kpftime;	/* SystemPageFaultSleepTime	*/
	double	li_lck;		/* user lock wait sleep time	*/
	double	li_slp;		/* all other sleep time		*/
	double	li_lat;		/* wait-cpu (latency) time	*/
	double	li_stime;	/* StoppedTime			*/
	ulong_t	li_minf;	/* MinorPageFaults		*/
	ulong_t	li_majf;	/* MajorPageFaults		*/
	ulong_t	li_nswap;	/* SwapOperations		*/
	ulong_t	li_inblk;	/* BlocksRead			*/
	ulong_t	li_oublk;	/* BlocksWritten		*/
	ulong_t	li_msnd;	/* MessagesSent			*/
	ulong_t	li_mrcv;	/* MessagesReceived		*/
	ulong_t	li_sigs;	/* SignalsReceived		*/
	ulong_t	li_vctx;	/* VoluntaryContextSwitches	*/
	ulong_t	li_ictx;	/* InvoluntaryContextSwitches 	*/
	ulong_t	li_scl;		/* SystemCallsMade		*/
	ulong_t	li_ioch;	/* CharacterIOUsage		*/
	ulong_t	li_hpsize;	/* process heap in byte		*/
	ulong_t	li_timestamp;   /* system clock time od this snapshot	*/
	struct lwp_info *li_next;	/* pointer to next lwp		*/
	struct lwp_info *li_prev;	/* pointer to previous lwp	*/
} lwp_info_t;

typedef struct {
	char *nodename;
	char *name;
} sys_info_t;

typedef struct {
	int  id;
	void *id_next;	/* pointer to next entry */
	void *id_prev;	/* pointer to previous entry */
} info_head_t;

/*
 * Linked list of collective per-uid, per-set, or per-projid statistics
 */
typedef struct id_info {

	int	id_alive;	/* flag for alive id	*/
	uint_t	id_pid;		/* user process id	*/
	uint_t	id_uid;		/* user id */
	uint_t	id_taskid;	/* task id */
	uint_t	id_projid;	/* project id */
	uint_t	id_psetid;	/* processor set to which lwp is bound */

	double	id_usr;		/* UserModeTime */
	double	id_sys;		/* SystemModeTime */
	double	id_ttime;	/* SystemTrapTime */
	double	id_tpftime;	/* TextPageFaultSleepTime */
	double	id_dpftime;	/* DataPageFaultSleepTime */
	double	id_kpftime;	/* SystemPageFaultSleepTime */
	double	id_lck;		/* UserLockWaitSleepTime */
	double	id_slp;		/* OtherSleepTime */
	double	id_lat;		/* WaitCPUTime */
	double	id_stime;	/* StoppedTime */
	int64_t id_minf;	/* MinorPageFaults */
	int64_t id_majf;	/* MajorPageFaults */
	int64_t id_nswap;	/* SwapOperations */
	int64_t id_inblk;	/* BlocksRead */
	int64_t id_oublk;	/* BlocksWritten */
	int64_t id_msnd;	/* MessagesSent */
	int64_t id_mrcv;	/* MessagesReceived */
	int64_t id_sigs;	/* SignalsReceived */
	int64_t id_vctx;	/* VoluntaryContextSwitches */
	int64_t id_ictx;	/* InvoluntaryContextSwitches */
	int64_t id_scl;		/* SystemCallsMade */
	int64_t id_ioch;	/* CharacterIOUsage */
	int64_t id_hpsize;	/* ProcessHeapSize # pstatus */
	int64_t id_size;	/* ProcessVMSize	*/
	int64_t id_rssize;	/* ProcessResidentSetSize # psinfo */
	float	id_pctcpu;	/* PercentCPUTime # psinfo	*/
	float	id_pctmem;	/* PercentMemorySize # psinfo	*/
	int64_t id_time;	/* UserSystemModeTime		*/
	uint_t	id_nlwps;	/* NumThreads	# psinfo	*/
	uint_t	id_nproc;	/* number of processes		*/
	int64_t id_timestamp;

	char	*id_name;
	int64_t	id_inpkg;	/* net input packets		*/
	int64_t	id_oupkg;	/* net output packets		*/
	uint_t		id_key;		/* sort key value 		*/
	struct id_info *id_next;	/* pointer to next entry	*/
	struct id_info *id_prev;	/* pointer to previous entry 	*/
} id_info_t;

/*
 * Per-list structure
 */
typedef struct list {
	int		l_type;		/* list type */
	int		l_count;	/* number of entries in the list   */
	void		*l_head;	/* pointer to the head of the list */
	void		*l_tail;	/* pointer to the tail of the list */
	int		l_size;		/* number of allocated pointers */
	int		l_used;		/* number of used pointers	*/
	void		**l_ptrs;	/* pointer to an array of pointers */
} list_t;

typedef struct swap_info {
	size_t	allocated; /* not free swap memory		*/
	size_t	reserved;  /* reserved  but not allocated swap memory in KB */
	size_t  available; /* available swap memory in KB	*/
	float   pctswap;   /* percentage of used swap		*/
} swap_info_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _RDIMPL_H */
