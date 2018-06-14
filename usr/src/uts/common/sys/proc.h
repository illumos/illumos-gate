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
 * Copyright (c) 1988, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2018 Joyent, Inc.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#ifndef _SYS_PROC_H
#define	_SYS_PROC_H

#include <sys/time.h>
#include <sys/thread.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/watchpoint.h>
#include <sys/timer.h>
#if defined(__x86)
#include <sys/tss.h>
#include <sys/segments.h>
#endif
#include <sys/utrap.h>
#include <sys/model.h>
#include <sys/refstr.h>
#include <sys/avl.h>
#include <sys/rctl.h>
#include <sys/list.h>
#include <sys/avl.h>
#include <sys/door_impl.h>
#include <sys/signalfd.h>
#include <sys/secflags.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Profile arguments.
 */
struct prof {
	void		*pr_base;	/* buffer base */
	uintptr_t	pr_off;		/* pc offset */
	size_t		pr_size;	/* buffer size */
	uint32_t	pr_scale;	/* pc scaling */
	long		pr_samples;	/* sample count */
};

/*
 * An lwp directory entry.
 * If le_thread != NULL, this is an active lwp.
 * If le_thread == NULL, this is an unreaped zombie lwp.
 */
typedef struct lwpent {
	kthread_t	*le_thread;	/* the active lwp, NULL if zombie */
	id_t		le_lwpid;	/* its lwpid (t->t_tid) */
	uint16_t	le_waiters;	/* total number of lwp_wait()ers */
	uint16_t	le_dwaiters;	/* number that are daemons */
	clock_t		le_start;	/* start time of this lwp */
	struct vnode	*le_trace;	/* pointer to /proc lwp vnode */
} lwpent_t;

typedef struct pctxop {
	void	(*save_op)(void *);	/* function to invoke to save ctx */
	void	(*restore_op)(void *);	/* function to invoke to restore ctx */
	void	(*fork_op)(void *, void *); /* invoke to fork context */
	void	(*exit_op)(void *);	/* invoked during process exit */
	void	(*free_op)(void *, int); /* function which frees the context */
	void	*arg;			/* argument to above functions */
	struct pctxop *next;		/* next pcontext ops */
} pctxop_t;

/*
 * Elements of the lwp directory, p->p_lwpdir[].
 *
 * We allocate lwp directory entries separately from lwp directory
 * elements because the lwp directory must be allocated as an array.
 * The number of lwps can grow quite large and we want to keep the
 * size of the kmem_alloc()d directory as small as possible.
 *
 * If ld_entry == NULL, the entry is free and is on the free list,
 * p->p_lwpfree, linked through ld_next.  If ld_entry != NULL, the
 * entry is used and ld_next is the thread-id hash link pointer.
 */
typedef struct lwpdir {
	struct lwpdir	*ld_next;	/* hash chain or free list */
	struct lwpent	*ld_entry;	/* lwp directory entry */
} lwpdir_t;

/*
 * Element of the p_tidhash thread-id (lwpid) hash table.
 */
typedef struct tidhash {
	kmutex_t	th_lock;
	lwpdir_t	*th_list;
} tidhash_t;

/*
 * Retired tidhash hash tables.
 */
typedef struct ret_tidhash {
	struct ret_tidhash	*rth_next;
	tidhash_t		*rth_tidhash;
	uint_t			rth_tidhash_sz;
} ret_tidhash_t;

struct pool;
struct task;
struct zone;
struct brand;
struct corectl_path;
struct corectl_content;

/*
 * One structure allocated per active process.  It contains all
 * data needed about the process while the process may be swapped
 * out.  Other per-process data (user.h) is also inside the proc structure.
 * Lightweight-process data (lwp.h) and the kernel stack may be swapped out.
 */
typedef struct	proc {
	/*
	 * Fields requiring no explicit locking
	 */
	struct	vnode *p_exec;		/* pointer to a.out vnode */
	struct	as *p_as;		/* process address space pointer */
	struct	plock *p_lockp;		/* ptr to proc struct's mutex lock */
	kmutex_t p_crlock;		/* lock for p_cred */
	struct	cred	*p_cred;	/* process credentials */
	/*
	 * Fields protected by pidlock
	 */
	int	p_swapcnt;		/* number of swapped out lwps */
	char	p_stat;			/* status of process */
	char	p_wcode;		/* current wait code */
	ushort_t p_pidflag;		/* flags protected only by pidlock */
	int 	p_wdata;		/* current wait return value */
	pid_t	p_ppid;			/* process id of parent */
	struct	proc	*p_link;	/* forward link */
	struct	proc	*p_parent;	/* ptr to parent process */
	struct	proc	*p_child;	/* ptr to first child process */
	struct	proc	*p_sibling;	/* ptr to next sibling proc on chain */
	struct	proc	*p_psibling;	/* ptr to prev sibling proc on chain */
	struct	proc	*p_sibling_ns;	/* prt to siblings with new state */
	struct	proc	*p_child_ns;	/* prt to children with new state */
	struct	proc 	*p_next;	/* active chain link next */
	struct	proc 	*p_prev;	/* active chain link prev */
	struct	proc 	*p_nextofkin;	/* gets accounting info at exit */
	struct	proc 	*p_orphan;
	struct	proc 	*p_nextorph;
	struct	proc	*p_pglink;	/* process group hash chain link next */
	struct	proc	*p_ppglink;	/* process group hash chain link prev */
	struct	sess	*p_sessp;	/* session information */
	struct	pid 	*p_pidp;	/* process ID info */
	struct	pid 	*p_pgidp;	/* process group ID info */
	/*
	 * Fields protected by p_lock
	 */
	kcondvar_t p_cv;		/* proc struct's condition variable */
	kcondvar_t p_flag_cv;
	kcondvar_t p_lwpexit;		/* waiting for some lwp to exit */
	kcondvar_t p_holdlwps;		/* process is waiting for its lwps */
					/* to to be held.  */
	uint_t	p_proc_flag;		/* /proc-related flags */
	uint_t	p_flag;			/* protected while set. */
					/* flags defined below */
	clock_t	p_utime;		/* user time, this process */
	clock_t	p_stime;		/* system time, this process */
	clock_t	p_cutime;		/* sum of children's user time */
	clock_t	p_cstime;		/* sum of children's system time */
	avl_tree_t *p_segacct;		/* System V shared segment list */
	avl_tree_t *p_semacct;		/* System V semaphore undo list */
	caddr_t	p_bssbase;		/* base addr of last bss below heap */
	caddr_t	p_brkbase;		/* base addr of heap */
	size_t	p_brksize;		/* heap size in bytes */
	uint_t	p_brkpageszc;		/* preferred heap max page size code */
	/*
	 * Per process signal stuff.
	 */
	k_sigset_t p_sig;		/* signals pending to this process */
	k_sigset_t p_extsig;		/* signals sent from another contract */
	k_sigset_t p_ignore;		/* ignore when generated */
	k_sigset_t p_siginfo;		/* gets signal info with signal */
	void *p_sigfd;			/* signalfd support state */
	struct sigqueue *p_sigqueue;	/* queued siginfo structures */
	struct sigqhdr *p_sigqhdr;	/* hdr to sigqueue structure pool */
	struct sigqhdr *p_signhdr;	/* hdr to signotify structure pool */
	uchar_t	p_stopsig;		/* jobcontrol stop signal */

	/*
	 * Special per-process flag when set will fix misaligned memory
	 * references.
	 */
	char    p_fixalignment;

	/*
	 * Per process lwp and kernel thread stuff
	 */
	id_t	p_lwpid;		/* most recently allocated lwpid */
	int 	p_lwpcnt;		/* number of lwps in this process */
	int	p_lwprcnt;		/* number of not stopped lwps */
	int	p_lwpdaemon;		/* number of TP_DAEMON lwps */
	int	p_lwpwait;		/* number of lwps in lwp_wait() */
	int	p_lwpdwait;		/* number of daemons in lwp_wait() */
	int	p_zombcnt;		/* number of zombie lwps */
	kthread_t *p_tlist;		/* circular list of threads */
	lwpdir_t *p_lwpdir;		/* thread (lwp) directory */
	lwpdir_t *p_lwpfree;		/* p_lwpdir free list */
	tidhash_t *p_tidhash;		/* tid (lwpid) lookup hash table */
	uint_t	p_lwpdir_sz;		/* number of p_lwpdir[] entries */
	uint_t	p_tidhash_sz;		/* number of p_tidhash[] entries */
	ret_tidhash_t *p_ret_tidhash;	/* retired tidhash hash tables */
	uint64_t p_lgrpset;		/* unprotected hint of set of lgrps */
					/* on which process has threads */
	volatile lgrp_id_t  p_t1_lgrpid; /* main's thread lgroup id */
	volatile lgrp_id_t  p_tr_lgrpid; /* text replica's lgroup id */
#if defined(_LP64)
	uintptr_t  p_lgrpres2;		/* reserved for lgrp migration */
#endif
	/*
	 * /proc (process filesystem) debugger interface stuff.
	 */
	k_sigset_t p_sigmask;		/* mask of traced signals (/proc) */
	k_fltset_t p_fltmask;		/* mask of traced faults (/proc) */
	struct vnode *p_trace;		/* pointer to primary /proc vnode */
	struct vnode *p_plist;		/* list of /proc vnodes for process */
	kthread_t *p_agenttp;		/* thread ptr for /proc agent lwp */
	avl_tree_t p_warea;		/* list of watched areas */
	avl_tree_t p_wpage;		/* remembered watched pages (vfork) */
	watched_page_t *p_wprot;	/* pages that need to have prot set */
	int	p_mapcnt;		/* number of active pr_mappage()s */
	kmutex_t p_maplock;		/* lock for pr_mappage() */
	struct	proc  *p_rlink;		/* linked list for server */
	kcondvar_t p_srwchan_cv;
	size_t	p_stksize;		/* process stack size in bytes */
	uint_t	p_stkpageszc;		/* preferred stack max page size code */

	/*
	 * Microstate accounting, resource usage, and real-time profiling
	 */
	hrtime_t p_mstart;		/* hi-res process start time */
	hrtime_t p_mterm;		/* hi-res process termination time */
	hrtime_t p_mlreal;		/* elapsed time sum over defunct lwps */
	hrtime_t p_acct[NMSTATES];	/* microstate sum over defunct lwps */
	hrtime_t p_cacct[NMSTATES];	/* microstate sum over child procs */
	struct lrusage p_ru;		/* lrusage sum over defunct lwps */
	struct lrusage p_cru;		/* lrusage sum over child procs */
	struct itimerval p_rprof_timer; /* ITIMER_REALPROF interval timer */
	uintptr_t p_rprof_cyclic;	/* ITIMER_REALPROF cyclic */
	uint_t	p_defunct;		/* number of defunct lwps */
	/*
	 * profiling. A lock is used in the event of multiple lwp's
	 * using the same profiling base/size.
	 */
	kmutex_t p_pflock;		/* protects user profile arguments */
	struct prof p_prof;		/* profile arguments */

	/*
	 * Doors.
	 */
	door_pool_t		p_server_threads; /* common thread pool */
	struct door_node	*p_door_list;	/* active doors */
	struct door_node	*p_unref_list;
	kcondvar_t		p_unref_cv;
	char			p_unref_thread;	/* unref thread created */

	/*
	 * Kernel probes
	 */
	uchar_t			p_tnf_flags;

	/*
	 * Solaris Audit
	 */
	struct p_audit_data	*p_audit_data; /* per process audit structure */

	pctxop_t	*p_pctx;

#if defined(__x86)
	/*
	 * LDT support.
	 */
	kmutex_t	p_ldtlock;	/* protects the following fields */
	user_desc_t	*p_ldt;		/* Pointer to private LDT */
	uint64_t	p_unused1;	/* no longer used */
	uint64_t	p_unused2;	/* no longer used */
	ushort_t	p_ldtlimit;	/* highest selector used */
#endif
	size_t p_swrss;			/* resident set size before last swap */
	struct aio	*p_aio;		/* pointer to async I/O struct */
	struct itimer	**p_itimer;	/* interval timers */
	timeout_id_t	p_alarmid;	/* alarm's timeout id */
	caddr_t		p_usrstack;	/* top of the process stack */
	uint_t		p_stkprot;	/* stack memory protection */
	uint_t		p_datprot;	/* data memory protection */
	model_t		p_model;	/* data model determined at exec time */
	struct lwpchan_data *p_lcp;	/* lwpchan cache */
	kmutex_t	p_lcp_lock;	/* protects assignments to p_lcp */
	utrap_handler_t	*p_utraps;	/* pointer to user trap handlers */
	struct corectl_path	*p_corefile;	/* pattern for core file */
	struct task	*p_task;	/* our containing task */
	struct proc	*p_taskprev;	/* ptr to previous process in task */
	struct proc	*p_tasknext;	/* ptr to next process in task */
	kmutex_t	p_sc_lock;	/* protects p_pagep */
	struct sc_page_ctl *p_pagep;	/* list of process's shared pages */
	struct rctl_set	*p_rctls;	/* resource controls for this process */
	rlim64_t	p_stk_ctl;	/* currently enforced stack size */
	rlim64_t	p_fsz_ctl;	/* currently enforced file size */
	rlim64_t	p_vmem_ctl;	/* currently enforced addr-space size */
	rlim64_t	p_fno_ctl;	/* currently enforced file-desc limit */
	pid_t		p_ancpid;	/* ancestor pid, used by exacct */
	struct itimerval p_realitimer;	/* real interval timer */
	timeout_id_t	p_itimerid;	/* real interval timer's timeout id */
	struct corectl_content *p_content;	/* content of core file */

	avl_tree_t	p_ct_held;	/* held contracts */
	struct ct_equeue **p_ct_equeue;	/* process-type event queues */

	struct cont_process *p_ct_process; /* process contract */
	list_node_t	p_ct_member;	/* process contract membership */
	sigqueue_t	*p_killsqp;	/* sigqueue pointer for SIGKILL */

	int		p_dtrace_probes; /* are there probes for this proc? */
	uint64_t	p_dtrace_count;	/* number of DTrace tracepoints */
					/* (protected by P_PR_LOCK) */
	void		*p_dtrace_helpers; /* DTrace helpers, if any */
	struct pool	*p_pool;	/* pointer to containing pool */
	kcondvar_t	p_poolcv;	/* synchronization with pools */
	uint_t		p_poolcnt;	/* # threads inside pool barrier */
	uint_t		p_poolflag;	/* pool-related flags (see below) */
	uintptr_t	p_portcnt;	/* event ports counter */
	struct zone	*p_zone;	/* zone in which process lives */
	struct vnode	*p_execdir;	/* directory that p_exec came from */
	struct brand	*p_brand;	/* process's brand  */
	void		*p_brand_data;	/* per-process brand state */
	psecflags_t	p_secflags;	/* per-process security flags */

	/* additional lock to protect p_sessp (but not its contents) */
	kmutex_t p_splock;
	rctl_qty_t	p_locked_mem;	/* locked memory charged to proc */
					/* protected by p_lock */
	rctl_qty_t	p_crypto_mem;	/* /dev/crypto memory charged to proc */
					/* protected by p_lock */
	clock_t	p_ttime;		/* buffered task time */

	/*
	 * The user structure
	 */
	struct user p_user;		/* (see sys/user.h) */
} proc_t;

#define	PROC_T				/* headers relying on proc_t are OK */

#ifdef _KERNEL

/* active process chain */

extern proc_t *practive;

/* Well known processes */

extern proc_t *proc_sched;		/* memory scheduler */
extern proc_t *proc_init;		/* init */
extern proc_t *proc_pageout;		/* pageout daemon */
extern proc_t *proc_fsflush;		/* filesystem sync-er */

#endif /* _KERNEL */

/*
 * Stuff to keep track of the number of processes each uid has.
 * It is tracked on a per-zone basis; that is, if users in different
 * zones have the same uid, they are tracked separately.
 *
 * A structure is allocated when a new <uid,zoneid> pair shows up
 * There is a hash to find each structure.
 */
struct	upcount	{
	struct	upcount	*up_next;
	uid_t		up_uid;
	zoneid_t	up_zoneid;
	uint_t		up_count;
};

/* process ID info */

struct pid {
	unsigned int pid_prinactive :1;
	unsigned int pid_pgorphaned :1;
	unsigned int pid_padding :6;	/* used to be pid_ref, now an int */
	unsigned int pid_prslot :24;
	pid_t pid_id;
	struct proc *pid_pglink;
	struct proc *pid_pgtail;
	struct pid *pid_link;
	uint_t pid_ref;
};

#define	p_pgrp p_pgidp->pid_id
#define	p_pid  p_pidp->pid_id
#define	p_slot p_pidp->pid_prslot
#define	p_detached p_pgidp->pid_pgorphaned

#define	PID_HOLD(pidp)	ASSERT(MUTEX_HELD(&pidlock)); \
			++(pidp)->pid_ref;
#define	PID_RELE(pidp)	ASSERT(MUTEX_HELD(&pidlock)); \
			(pidp)->pid_ref > 1 ? \
				--(pidp)->pid_ref : pid_rele(pidp);

/*
 * Structure containing persistent process lock.  The structure and
 * macro allow "mutex_enter(&p->p_lock)" to continue working.
 */
struct plock {
	kmutex_t pl_lock;
};
#define	p_lock	p_lockp->pl_lock

#ifdef _KERNEL
extern proc_t p0;		/* process 0 */
extern struct plock p0lock;	/* p0's plock */
extern struct pid pid0;		/* p0's pid */

/* pid_allocate() flags */
#define	PID_ALLOC_PROC	0x0001	/* assign a /proc slot as well */

#endif /* _KERNEL */

/* stat codes */

#define	SSLEEP	1		/* awaiting an event */
#define	SRUN	2		/* runnable */
#define	SZOMB	3		/* process terminated but not waited for */
#define	SSTOP	4		/* process stopped by debugger */
#define	SIDL	5		/* intermediate state in process creation */
#define	SONPROC	6		/* process is being run on a processor */
#define	SWAIT	7		/* process is waiting to become runnable */

/* p_pidflag codes */
#define	CLDPEND		0x0001	/* have yet to post a SIGCHLD to the parent */
#define	CLDCONT		0x0002	/* child has notified parent of CLD_CONTINUED */
#define	CLDNOSIGCHLD	0x0004	/* do not post SIGCHLD when child terminates */
#define	CLDWAITPID	0x0008	/* only waitid(P_PID, pid) can reap the child */

/* p_proc_flag codes -- these flags are mostly private to /proc */
#define	P_PR_TRACE	0x0001	/* signal, fault or syscall tracing via /proc */
#define	P_PR_PTRACE	0x0002	/* ptrace() compatibility mode */
#define	P_PR_FORK	0x0004	/* child inherits tracing flags */
#define	P_PR_LOCK	0x0008	/* process locked by /proc */
#define	P_PR_ASYNC	0x0010	/* asynchronous stopping via /proc */
#define	P_PR_EXEC	0x0020	/* process is in exec() */
#define	P_PR_BPTADJ	0x0040	/* adjust pc on breakpoint trap */
#define	P_PR_RUNLCL	0x0080	/* set process running on last /proc close */
#define	P_PR_KILLCL	0x0100	/* kill process on last /proc close */

/*
 * p_flag codes
 *
 * note that two of these flags, SMSACCT and SSYS, are exported to /proc's
 * psinfo_t.p_flag field.  Historically, all were, but since they are
 * implementation dependant, we only export the ones people have come to
 * rely upon.  Hence, the bit positions of SSYS and SMSACCT should not be
 * altered.
 */
#define	SSYS	   0x00000001	/* system (resident) process */
#define	SEXITING   0x00000002	/* process is exiting */
#define	SITBUSY	   0x00000004	/* setitimer(ITIMER_REAL) in progress */
#define	SFORKING   0x00000008	/* tells called functions that we're forking */
#define	SWATCHOK   0x00000010	/* proc in acceptable state for watchpoints */
#define	SKILLED    0x00000100	/* SIGKILL has been posted to the process */
#define	SSCONT	   0x00000200	/* SIGCONT has been posted to the process */
#define	SZONETOP   0x00000400	/* process has no valid PPID in its zone */
#define	SEXTKILLED 0x00000800	/* SKILLED is from another contract */
#define	SUGID	   0x00002000	/* process was result of set[ug]id exec */
#define	SEXECED	   0x00004000	/* this process has execed */
#define	SJCTL	   0x00010000	/* SIGCHLD sent when children stop/continue */
#define	SNOWAIT    0x00020000	/* children never become zombies */
#define	SVFORK	   0x00040000	/* child of vfork that has not yet exec'd */
#define	SVFWAIT	   0x00080000	/* parent of vfork waiting for child to exec */
#define	SEXITLWPS  0x00100000	/* have lwps exit within the process */
#define	SHOLDFORK  0x00200000	/* hold lwps where they're cloneable */
#define	SHOLDFORK1 0x00800000	/* hold lwps in place (not cloning) */
#define	SCOREDUMP  0x01000000	/* process is dumping core */
#define	SMSACCT    0x02000000	/* process is keeping micro-state accounting */
#define	SLWPWRAP   0x04000000	/* process has wrapped its lwp ids */
#define	SAUTOLPG   0x08000000	/* kernel controls page sizes */
#define	SNOCD	   0x10000000	/* new creds from VSxID, do not coredump */
#define	SHOLDWATCH 0x20000000	/* hold lwps for watchpoint operation */
#define	SMSFORK	   0x40000000	/* child inherits micro-state accounting */
#define	SDOCORE	   0x80000000	/* process will attempt to dump core */

/*
 * p_poolflag codes
 *
 * These flags are used to synchronize with the pool subsystem to allow
 * re-binding of processes to new pools.
 */
#define	PBWAIT		0x0001  /* process should wait outside fork/exec/exit */
#define	PEXITED		0x0002  /* process exited and about to become zombie */

/* Macro to convert proc pointer to a user block pointer */
#define	PTOU(p)		(&(p)->p_user)

#define	tracing(p, sig)	(sigismember(&(p)->p_sigmask, sig))

/* Macro to reduce unnecessary calls to issig() */

#define	ISSIG(t, why)	ISSIG_FAST(t, ttolwp(t), ttoproc(t), why)

/*
 * Fast version of ISSIG.
 *	1. uses register pointers to lwp and proc instead of reloading them.
 *	2. uses bit-wise OR of tests, since the usual case is that none of them
 *	   are true, this saves orcc's and branches.
 *	3. load the signal flags instead of using sigisempty() macro which does
 *	   a branch to convert to boolean.
 */
#define	ISSIG_FAST(t, lwp, p, why)		\
	(ISSIG_PENDING(t, lwp, p) && issig(why))

#define	ISSIG_PENDING(t, lwp, p)		\
	((lwp)->lwp_cursig |			\
	    sigcheck((p), (t)) |		\
	    (p)->p_stopsig |			\
	    (t)->t_dtrace_stop |		\
	    (t)->t_dtrace_sig |			\
	    ((t)->t_proc_flag & (TP_PRSTOP|TP_HOLDLWP|TP_CHKPT|TP_PAUSE)) | \
	    ((p)->p_flag & (SEXITLWPS|SKILLED|SHOLDFORK1|SHOLDWATCH)))

#define	ISSTOP(sig)	 (u.u_signal[sig-1] == SIG_DFL && \
				sigismember(&stopdefault, sig))

#define	ISHOLD(p)	((p)->p_flag & SHOLDFORK)

#define	MUSTRETURN(p, t)	(ISHOLD(p) | (t)->t_activefd.a_stale)

/*
 * Determine if there are any watchpoints active in the process.
 */
#define	pr_watch_active(p)	(avl_numnodes(&(p)->p_warea) != 0)

/* Reasons for calling issig() */

#define	FORREAL		0	/* Usual side-effects */
#define	JUSTLOOKING	1	/* Don't stop the process */

/* 'what' values for stop(PR_SUSPENDED, what) */
#define	SUSPEND_NORMAL	0
#define	SUSPEND_PAUSE	1

/* pseudo-flag to lwp_create() */
#define	NOCLASS	(-1)

/* unused scheduling class ID */
#define	CLASS_UNUSED	(-2)

/* LWP stats updated via lwp_stats_update() */
typedef enum {
	LWP_STAT_INBLK,
	LWP_STAT_OUBLK,
	LWP_STAT_MSGRCV,
	LWP_STAT_MSGSND
} lwp_stat_id_t;

typedef struct prkillinfo {
	int32_t prk_error;		/* errno */
	int32_t prk_pad;		/* pad */
	siginfo_t prk_info;		/* siginfo of killing signal */
} prkillinfo_t;

#ifdef _KERNEL

/* user profiling functions */

extern void profil_tick(uintptr_t);

/* process management functions */

extern int newproc(void (*)(), caddr_t, id_t, int, struct contract **, pid_t);
extern void vfwait(pid_t);
extern void proc_detach(proc_t *);
extern void freeproc(proc_t *);
extern void setrun(kthread_t *);
extern void setrun_locked(kthread_t *);
extern void exit(int, int);
extern int proc_exit(int, int);
extern void proc_is_exiting(proc_t *);
extern void relvm(void);
extern void add_ns(proc_t *, proc_t *);
extern void delete_ns(proc_t *, proc_t *);
extern void upcount_inc(uid_t, zoneid_t);
extern void upcount_dec(uid_t, zoneid_t);
extern int upcount_get(uid_t, zoneid_t);
#if defined(__x86)
extern selector_t setup_thrptr(proc_t *, uintptr_t);
extern void deferred_singlestep_trap(caddr_t);
#endif

extern void sigcld(proc_t *, sigqueue_t *);
extern void sigcld_delete(k_siginfo_t *);
extern void sigcld_repost(void);
extern int fsig(k_sigset_t *, kthread_t *);
extern void psig(void);
extern void stop(int, int);
extern int stop_on_fault(uint_t, k_siginfo_t *);
extern int issig(int);
extern int jobstopped(proc_t *);
extern void psignal(proc_t *, int);
extern void tsignal(kthread_t *, int);
extern void sigtoproc(proc_t *, kthread_t *, int);
extern void trapsig(k_siginfo_t *, int);
extern void realsigprof(int, int, int);
extern int eat_signal(kthread_t *, int);
extern int signal_is_blocked(kthread_t *, int);
extern int sigcheck(proc_t *, kthread_t *);
extern void sigdefault(proc_t *);

extern void pid_setmin(void);
extern pid_t pid_allocate(proc_t *, pid_t, int);
extern int pid_rele(struct pid *);
extern void pid_exit(proc_t *, struct task *);
extern void proc_entry_free(struct pid *);
extern proc_t *prfind(pid_t);
extern proc_t *prfind_zone(pid_t, zoneid_t);
extern proc_t *pgfind(pid_t);
extern proc_t *pgfind_zone(pid_t, zoneid_t);
extern proc_t *sprlock(pid_t);
extern proc_t *sprlock_zone(pid_t, zoneid_t);
extern int sprtrylock_proc(proc_t *);
extern void sprwaitlock_proc(proc_t *);
extern void sprlock_proc(proc_t *);
extern void sprunlock(proc_t *);
extern void pid_init(void);
extern proc_t *pid_entry(int);
extern int pid_slot(proc_t *);
extern void signal(pid_t, int);
extern void prsignal(struct pid *, int);
extern int uread(proc_t *, void *, size_t, uintptr_t);
extern int uwrite(proc_t *, void *, size_t, uintptr_t);

extern void pgsignal(struct pid *, int);
extern void pgjoin(proc_t *, struct pid *);
extern void pgcreate(proc_t *);
extern void pgexit(proc_t *);
extern void pgdetach(proc_t *);
extern int pgmembers(pid_t);

extern	void	init_mstate(kthread_t *, int);
extern	int	new_mstate(kthread_t *, int);
extern	void	restore_mstate(kthread_t *);
extern	void	term_mstate(kthread_t *);
extern	void	estimate_msacct(kthread_t *, hrtime_t);
extern	void	disable_msacct(proc_t *);
extern	hrtime_t mstate_aggr_state(proc_t *, int);
extern	hrtime_t mstate_thread_onproc_time(kthread_t *);
extern	void	mstate_systhread_times(kthread_t *, hrtime_t *, hrtime_t *);
extern	void	syscall_mstate(int, int);

extern	uint_t	cpu_update_pct(kthread_t *, hrtime_t);

extern void	set_proc_pre_sys(proc_t *p);
extern void	set_proc_post_sys(proc_t *p);
extern void	set_proc_sys(proc_t *p);
extern void	set_proc_ast(proc_t *p);
extern void	set_all_proc_sys(void);
extern void	set_all_zone_usr_proc_sys(zoneid_t);

/* thread function prototypes */

extern	kthread_t	*thread_create(
	caddr_t		stk,
	size_t		stksize,
	void		(*proc)(),
	void		*arg,
	size_t		len,
	proc_t 		*pp,
	int		state,
	pri_t		pri);
extern	void	thread_exit(void) __NORETURN;
extern	void	thread_free(kthread_t *);
extern	void	thread_rele(kthread_t *);
extern	void	thread_join(kt_did_t);
extern	int	reaper(void);
extern	void	installctx(kthread_t *, void *, void (*)(), void (*)(),
    void (*)(), void (*)(), void (*)(), void (*)());
extern	int	removectx(kthread_t *, void *, void (*)(), void (*)(),
    void (*)(), void (*)(), void (*)(), void (*)());
extern	void	savectx(kthread_t *);
extern	void	restorectx(kthread_t *);
extern	void	forkctx(kthread_t *, kthread_t *);
extern	void	lwp_createctx(kthread_t *, kthread_t *);
extern	void	exitctx(kthread_t *);
extern	void	freectx(kthread_t *, int);
extern	void	installpctx(proc_t *, void *, void (*)(), void (*)(),
    void (*)(), void (*)(), void (*)());
extern	int	removepctx(proc_t *, void *, void (*)(), void (*)(),
    void (*)(), void (*)(), void (*)());
extern	void	savepctx(proc_t *);
extern	void	restorepctx(proc_t *);
extern	void	forkpctx(proc_t *, proc_t *);
extern	void	exitpctx(proc_t *);
extern	void	freepctx(proc_t *, int);
extern	kthread_t *thread_unpin(void);
extern	void	thread_init(void);
extern	void	thread_load(kthread_t *, void (*)(), caddr_t, size_t);

extern	void	tsd_create(uint_t *, void (*)(void *));
extern	void	tsd_destroy(uint_t *);
extern	void	*tsd_getcreate(uint_t *, void (*)(void *), void *(*)(void));
extern	void	*tsd_get(uint_t);
extern	int	tsd_set(uint_t, void *);
extern	void	tsd_exit(void);
extern	void	*tsd_agent_get(kthread_t *, uint_t);
extern	int	tsd_agent_set(kthread_t *, uint_t, void *);

/* lwp function prototypes */

extern kthread_t *lwp_kernel_create(proc_t *, void (*)(), void *, int, pri_t);
extern	klwp_t 		*lwp_create(
	void		(*proc)(),
	caddr_t		arg,
	size_t		len,
	proc_t		*p,
	int		state,
	int		pri,
	const k_sigset_t *smask,
	int		cid,
	id_t		lwpid);
extern	kthread_t *idtot(proc_t *, id_t);
extern	void	lwp_hash_in(proc_t *, lwpent_t *, tidhash_t *, uint_t, int);
extern	void	lwp_hash_out(proc_t *, id_t);
extern	lwpdir_t *lwp_hash_lookup(proc_t *, id_t);
extern	lwpdir_t *lwp_hash_lookup_and_lock(proc_t *, id_t, kmutex_t **);
extern	void	lwp_create_done(kthread_t *);
extern	void	lwp_exit(void);
extern	void	lwp_pcb_exit(void);
extern	void	lwp_cleanup(void);
extern	int	lwp_suspend(kthread_t *);
extern	void	lwp_continue(kthread_t *);
extern	void	holdlwp(void);
extern	void	stoplwp(void);
extern	int	holdlwps(int);
extern	int	holdwatch(void);
extern	void	pokelwps(proc_t *);
extern	void	continuelwps(proc_t *);
extern	int	exitlwps(int);
extern	void	lwp_ctmpl_copy(klwp_t *, klwp_t *);
extern	void	lwp_ctmpl_clear(klwp_t *);
extern	klwp_t	*forklwp(klwp_t *, proc_t *, id_t);
extern	void	lwp_load(klwp_t *, gregset_t, uintptr_t);
extern	void	lwp_setrval(klwp_t *, int, int);
extern	void	lwp_forkregs(klwp_t *, klwp_t *);
extern	void	lwp_freeregs(klwp_t *, int);
extern	caddr_t	lwp_stk_init(klwp_t *, caddr_t);
extern	void	lwp_stk_cache_init(void);
extern	void	lwp_stk_fini(klwp_t *);
extern	void	lwp_fp_init(klwp_t *);
extern	void	lwp_installctx(klwp_t *);
extern	void	lwp_rtt(void);
extern	void	lwp_rtt_initial(void);
extern	int	lwp_setprivate(klwp_t *, int, uintptr_t);
extern	void	lwp_stat_update(lwp_stat_id_t, long);
extern	void	lwp_attach_brand_hdlrs(klwp_t *);
extern	void	lwp_detach_brand_hdlrs(klwp_t *);

#if defined(__sparcv9)
extern	void	lwp_mmodel_newlwp(void);
extern	void	lwp_mmodel_shared_as(caddr_t, size_t);
#define	LWP_MMODEL_NEWLWP()		lwp_mmodel_newlwp()
#define	LWP_MMODEL_SHARED_AS(addr, sz)	lwp_mmodel_shared_as((addr), (sz))
#else
#define	LWP_MMODEL_NEWLWP()
#define	LWP_MMODEL_SHARED_AS(addr, sz)
#endif

/*
 * Signal queue function prototypes. Must be here due to header ordering
 * dependencies.
 */
extern void sigqfree(proc_t *);
extern void siginfofree(sigqueue_t *);
extern void sigdeq(proc_t *, kthread_t *, int, sigqueue_t **);
extern void sigdelq(proc_t *, kthread_t *, int);
extern void sigaddq(proc_t *, kthread_t *, k_siginfo_t *, int);
extern void sigaddqa(proc_t *, kthread_t *, sigqueue_t *);
extern void sigqsend(int, proc_t *, kthread_t *, sigqueue_t *);
extern void sigdupq(proc_t *, proc_t *);
extern int sigwillqueue(int, int);
extern sigqhdr_t *sigqhdralloc(size_t, uint_t);
extern sigqueue_t *sigqalloc(sigqhdr_t *);
extern void sigqhdrfree(sigqhdr_t *);
extern sigqueue_t *sigappend(k_sigset_t *, sigqueue_t *,
	k_sigset_t *, sigqueue_t *);
extern sigqueue_t *sigprepend(k_sigset_t *, sigqueue_t *,
	k_sigset_t *, sigqueue_t *);
extern void winfo(proc_t *, k_siginfo_t *, int);
extern int wstat(int, int);
extern int sendsig(int, k_siginfo_t *, void (*)());
#if defined(_SYSCALL32_IMPL)
extern int sendsig32(int, k_siginfo_t *, void (*)());
#endif

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PROC_H */
