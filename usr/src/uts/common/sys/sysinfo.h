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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/


/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_SYSINFO_H
#define	_SYS_SYSINFO_H

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/kstat.h>
#include <sys/machlock.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 *	System Information.
 */
#define	CPU_IDLE	0
#define	CPU_USER	1
#define	CPU_KERNEL	2
#define	CPU_WAIT	3
#define	CPU_STATES	4

#define	W_IO		0
#define	W_SWAP		1
#define	W_PIO		2
#define	W_STATES	3

typedef struct cpu_sysinfo {
	uint_t	cpu[CPU_STATES]; /* CPU utilization			*/
	uint_t	wait[W_STATES];	/* CPU wait time breakdown		*/
	/*
	 * The two stats lwrite and bwrite are used by sar(1) to
	 * generate the write cache hit percentage (%wcache value).
	 *
	 * The value is calculated as follows (unless lwrite < 0.5 and
	 * then %wcache is coded to 100%):
	 *
	 *	(lwrite - bwrite)/lwrite * 100.0
	 *
	 * This calculation assumes that when a physical write occurs
	 * (bwrite incremented), that a logical write (lwrite
	 * incremented) has also occured. Note that a logical write
	 * (lwrite incremented) my occur on its own.
	 *
	 * Similar for lread/bread and %rcache.
	 */
	uint_t	bread;		/* physical block reads			*/
	uint_t	bwrite;		/* physical block writes (sync+async)	*/
	uint_t	lread;		/* logical block reads			*/
	uint_t	lwrite;		/* logical block writes			*/
	uint_t	phread;		/* raw I/O reads			*/
	uint_t	phwrite;	/* raw I/O writes			*/
	uint_t	pswitch;	/* context switches			*/
	uint_t	trap;		/* traps				*/
	uint_t	intr;		/* device interrupts			*/
	uint_t	syscall;	/* system calls				*/
	uint_t	sysread;	/* read() + readv() system calls	*/
	uint_t	syswrite;	/* write() + writev() system calls	*/
	uint_t	sysfork;	/* forks				*/
	uint_t	sysvfork;	/* vforks				*/
	uint_t	sysexec;	/* execs				*/
	uint_t	readch;		/* bytes read by rdwr()			*/
	uint_t	writech;	/* bytes written by rdwr()		*/
	uint_t	rcvint;		/* XXX: UNUSED				*/
	uint_t	xmtint;		/* XXX: UNUSED				*/
	uint_t	mdmint;		/* XXX: UNUSED				*/
	uint_t	rawch;		/* terminal input characters		*/
	uint_t	canch;		/* chars handled in canonical mode	*/
	uint_t	outch;		/* terminal output characters		*/
	uint_t	msg;		/* msg count (msgrcv()+msgsnd() calls)	*/
	uint_t	sema;		/* semaphore ops count (semop() calls)	*/
	uint_t	namei;		/* pathname lookups			*/
	uint_t	ufsiget;	/* ufs_iget() calls			*/
	uint_t	ufsdirblk;	/* directory blocks read		*/
	uint_t	ufsipage;	/* inodes taken with attached pages	*/
	uint_t	ufsinopage;	/* inodes taked with no attached pages	*/
	uint_t	inodeovf;	/* inode table overflows		*/
	uint_t	fileovf;	/* file table overflows			*/
	uint_t	procovf;	/* proc table overflows			*/
	uint_t	intrthread;	/* interrupts as threads (below clock)	*/
	uint_t	intrblk;	/* intrs blkd/prempted/released (swtch)	*/
	uint_t	idlethread;	/* times idle thread scheduled		*/
	uint_t	inv_swtch;	/* involuntary context switches		*/
	uint_t	nthreads;	/* thread_create()s			*/
	uint_t	cpumigrate;	/* cpu migrations by threads 		*/
	uint_t	xcalls;		/* xcalls to other cpus 		*/
	uint_t	mutex_adenters;	/* failed mutex enters (adaptive)	*/
	uint_t	rw_rdfails;	/* rw reader failures			*/
	uint_t	rw_wrfails;	/* rw writer failures			*/
	uint_t	modload;	/* times loadable module loaded		*/
	uint_t	modunload;	/* times loadable module unloaded 	*/
	uint_t	bawrite;	/* physical block writes (async)	*/
/* Following are gathered only under #ifdef STATISTICS in source 	*/
	uint_t	rw_enters;	/* tries to acquire rw lock		*/
	uint_t	win_uo_cnt;	/* reg window user overflows		*/
	uint_t	win_uu_cnt;	/* reg window user underflows		*/
	uint_t	win_so_cnt;	/* reg window system overflows		*/
	uint_t	win_su_cnt;	/* reg window system underflows		*/
	uint_t	win_suo_cnt;	/* reg window system user overflows	*/
} cpu_sysinfo_t;

typedef struct sysinfo {	/* (update freq) update action		*/
	uint_t	updates;	/* (1 sec) ++				*/
	uint_t	runque;		/* (1 sec) += num runnable procs	*/
	uint_t	runocc;		/* (1 sec) ++ if num runnable procs > 0	*/
	uint_t	swpque;		/* (1 sec) += num swapped procs		*/
	uint_t	swpocc;		/* (1 sec) ++ if num swapped procs > 0	*/
	uint_t	waiting;	/* (1 sec) += jobs waiting for I/O	*/
} sysinfo_t;

typedef struct cpu_syswait {
	int	iowait;		/* procs waiting for block I/O		*/
	int	swap;		/* XXX: UNUSED				*/
	int	physio;		/* XXX: UNUSED 				*/
} cpu_syswait_t;

typedef struct cpu_vminfo {
	uint_t	pgrec;		/* page reclaims (includes pageout)	*/
	uint_t	pgfrec;		/* page reclaims from free list		*/
	uint_t	pgin;		/* pageins				*/
	uint_t	pgpgin;		/* pages paged in			*/
	uint_t	pgout;		/* pageouts				*/
	uint_t	pgpgout;	/* pages paged out			*/
	uint_t	swapin;		/* swapins				*/
	uint_t	pgswapin;	/* pages swapped in			*/
	uint_t	swapout;	/* swapouts				*/
	uint_t	pgswapout;	/* pages swapped out			*/
	uint_t	zfod;		/* pages zero filled on demand		*/
	uint_t	dfree;		/* pages freed by daemon or auto	*/
	uint_t	scan;		/* pages examined by pageout daemon	*/
	uint_t	rev;		/* revolutions of the page daemon hand	*/
	uint_t	hat_fault;	/* minor page faults via hat_fault()	*/
	uint_t	as_fault;	/* minor page faults via as_fault()	*/
	uint_t	maj_fault;	/* major page faults			*/
	uint_t	cow_fault;	/* copy-on-write faults			*/
	uint_t	prot_fault;	/* protection faults			*/
	uint_t	softlock;	/* faults due to software locking req	*/
	uint_t	kernel_asflt;	/* as_fault()s in kernel addr space	*/
	uint_t	pgrrun;		/* times pager scheduled		*/
	uint_t  execpgin;	/* executable pages paged in		*/
	uint_t  execpgout;	/* executable pages paged out		*/
	uint_t  execfree;	/* executable pages freed		*/
	uint_t  anonpgin;	/* anon pages paged in			*/
	uint_t  anonpgout;	/* anon pages paged out			*/
	uint_t  anonfree;	/* anon pages freed			*/
	uint_t  fspgin;		/* fs pages paged in			*/
	uint_t  fspgout;	/* fs pages paged out			*/
	uint_t  fsfree;		/* fs pages free			*/
} cpu_vminfo_t;

typedef struct vminfo {		/* (update freq) update action		*/
	uint64_t freemem; 	/* (1 sec) += freemem in pages		*/
	uint64_t swap_resv;	/* (1 sec) += reserved swap in pages	*/
	uint64_t swap_alloc;	/* (1 sec) += allocated swap in pages	*/
	uint64_t swap_avail;	/* (1 sec) += unreserved swap in pages	*/
	uint64_t swap_free;	/* (1 sec) += unallocated swap in pages	*/
	uint64_t updates;	/* (1 sec) ++				*/
} vminfo_t;

typedef struct cpu_stat {
	uint_t		__cpu_stat_lock[2];	/* 32-bit kstat compat. */
	cpu_sysinfo_t	cpu_sysinfo;
	cpu_syswait_t	cpu_syswait;
	cpu_vminfo_t	cpu_vminfo;
} cpu_stat_t;

typedef struct cpu_sys_stats {
	uint64_t cpu_ticks_idle; 	/* CPU utilization */
	uint64_t cpu_ticks_user;
	uint64_t cpu_ticks_kernel;
	uint64_t cpu_ticks_wait;
	uint64_t wait_ticks_io;		/* CPU wait time breakdown */
	uint64_t bread;			/* physical block reads */
	uint64_t bwrite;		/* physical block writes (sync+async) */
	uint64_t lread;			/* logical block reads */
	uint64_t lwrite;		/* logical block writes */
	uint64_t phread;		/* raw I/O Reads */
	uint64_t phwrite;		/* raw I/O writes */
	uint64_t pswitch;		/* context switches */
	uint64_t trap;			/* traps */
	uint64_t intr[PIL_MAX];		/* device interrupts per PIL */
	uint64_t syscall;		/* system calls */
	uint64_t sysread;		/* read() + readv() system calls */
	uint64_t syswrite;		/* write() + writev() system calls */
	uint64_t sysfork;		/* forks */
	uint64_t sysvfork;		/* vforks */
	uint64_t sysexec;		/* execs */
	uint64_t readch;		/* bytes read by rdwr() */
	uint64_t writech;		/* bytes written by rdwr() */
	uint64_t rcvint;		/* XXX: unused (mostly) */
	uint64_t xmtint;		/* XXX: unused */
	uint64_t mdmint;		/* XXX: unused */
	uint64_t rawch;			/* terminal input characters */
	uint64_t canch;			/* chars handled in canonical mode */
	uint64_t outch;			/* terminal output characters */
	uint64_t msg;			/* msg count (msgrcv() + msgsnd()) */
	uint64_t sema;			/* semaphore ops count (semop()) */
	uint64_t namei;			/* pathname lookups */
	uint64_t ufsiget;		/* ufs_iget() calls */
	uint64_t ufsdirblk;		/* directory blocks read */
	uint64_t ufsipage;		/* inodes taken with attached pages */
	uint64_t ufsinopage;		/* inodes taken with no attached pgs */
	uint64_t procovf;		/* failed forks */
	uint64_t intrblk;		/* ints blkd/prempted/rel'd (swtch) */
	uint64_t intrunpin;		/* intr thread unpins pinned thread */
	uint64_t idlethread;		/* times idle thread scheduled */
	uint64_t inv_swtch;		/* involuntary context switches */
	uint64_t nthreads;		/* thread_create()s */
	uint64_t cpumigrate;		/* cpu migrations by threads */
	uint64_t xcalls;		/* xcalls to other cpus */
	uint64_t mutex_adenters;	/* failed mutex enters (adaptive) */
	uint64_t rw_rdfails;		/* rw reader failures */
	uint64_t rw_wrfails;		/* rw writer failures */
	uint64_t modload;		/* times loadable module loaded */
	uint64_t modunload; 		/* times loadable module unloaded */
	uint64_t bawrite;		/* physical block writes (async) */
	uint64_t iowait; 		/* count of waiters for block I/O */
} cpu_sys_stats_t;

typedef struct cpu_vm_stats {
	uint64_t pgrec;			/* page reclaims (includes pageout) */
	uint64_t pgfrec;		/* page reclaims from free list */
	uint64_t pgin;			/* pageins */
	uint64_t pgpgin;		/* pages paged in */
	uint64_t pgout;			/* pageouts */
	uint64_t pgpgout;		/* pages paged out */
	uint64_t swapin;		/* swapins */
	uint64_t pgswapin;		/* pages swapped in */
	uint64_t swapout;		/* swapouts */
	uint64_t pgswapout;		/* pages swapped out */
	uint64_t zfod;			/* pages zero filled on demand */
	uint64_t dfree;			/* pages freed by daemon or auto */
	uint64_t scan;			/* pages examined by pageout daemon */
	uint64_t rev;			/* revolutions of page daemon hand */
	uint64_t hat_fault;		/* minor page faults via hat_fault() */
	uint64_t as_fault;		/* minor page faults via as_fault() */
	uint64_t maj_fault;		/* major page faults */
	uint64_t cow_fault;		/* copy-on-write faults */
	uint64_t prot_fault;		/* protection faults */
	uint64_t softlock;		/* faults due to software locking req */
	uint64_t kernel_asflt;		/* as_fault()s in kernel addr space */
	uint64_t pgrrun;		/* times pager scheduled */
	uint64_t execpgin;		/* executable pages paged in */
	uint64_t execpgout;		/* executable pages paged out */
	uint64_t execfree;		/* executable pages freed */
	uint64_t anonpgin;		/* anon pages paged in */
	uint64_t anonpgout;		/* anon pages paged out */
	uint64_t anonfree;		/* anon pages freed */
	uint64_t fspgin;		/* fs pages paged in */
	uint64_t fspgout;		/* fs pages paged out */
	uint64_t fsfree;		/* fs pages free */
} cpu_vm_stats_t;

typedef struct cpu_stats {
	cpu_sys_stats_t	sys;
	cpu_vm_stats_t	vm;
} cpu_stats_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SYSINFO_H */
