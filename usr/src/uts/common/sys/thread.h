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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_THREAD_H
#define	_SYS_THREAD_H


#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/klwp.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <sys/kcpc.h>
#if defined(__GNUC__) && defined(_ASM_INLINES) && defined(_KERNEL)
#include <asm/thread.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The thread object, its states, and the methods by which it
 * is accessed.
 */

/*
 * Values that t_state may assume. Note that t_state cannot have more
 * than one of these flags set at a time.
 */
#define	TS_FREE		0x00	/* Thread at loose ends */
#define	TS_SLEEP	0x01	/* Awaiting an event */
#define	TS_RUN		0x02	/* Runnable, but not yet on a processor */
#define	TS_ONPROC	0x04	/* Thread is being run on a processor */
#define	TS_ZOMB		0x08	/* Thread has died but hasn't been reaped */
#define	TS_STOPPED	0x10	/* Stopped, initial state */
#define	TS_WAIT		0x20	/* Waiting to become runnable */

typedef struct ctxop {
	void	(*save_op)(void *);	/* function to invoke to save context */
	void	(*restore_op)(void *);	/* function to invoke to restore ctx */
	void	(*fork_op)(void *, void *);	/* invoke to fork context */
	void	(*lwp_create_op)(void *, void *);	/* lwp_create context */
	void	(*exit_op)(void *);	/* invoked during {thread,lwp}_exit() */
	void	(*free_op)(void *, int); /* function which frees the context */
	void	*arg;		/* argument to above functions, ctx pointer */
	struct ctxop *next;	/* next context ops */
} ctxop_t;

/*
 * The active file descriptor table.
 * Each member of a_fd[] not equalling -1 represents an active fd.
 * The structure is initialized on first use; all zeros means uninitialized.
 */
typedef struct {
	kmutex_t a_fdlock;	/* protects a_fd and a_nfd */
	int	*a_fd;		/* pointer to list of fds */
	int	a_nfd;		/* number of entries in *a_fd */
	int	a_stale;	/* one of the active fds is being closed */
	int	a_buf[2];	/* buffer to which a_fd initially refers */
} afd_t;

/*
 * An lwpchan provides uniqueness when sleeping on user-level
 * synchronization primitives.  The lc_wchan member is used
 * for sleeping on kernel synchronization primitives.
 */
typedef struct {
	caddr_t lc_wchan0;
	caddr_t lc_wchan;
} lwpchan_t;

typedef struct _kthread	*kthread_id_t;

struct turnstile;
struct panic_trap_info;
struct upimutex;
struct kproject;
struct on_trap_data;
struct waitq;
struct _kcpc_ctx;
struct _kcpc_set;

/* Definition for kernel thread identifier type */
typedef uint64_t kt_did_t;

typedef struct _kthread {
	struct _kthread	*t_link; /* dispq, sleepq, and free queue link */

	caddr_t	t_stk;		/* base of stack (kernel sp value to use) */
	void	(*t_startpc)(void);	/* PC where thread started */
	struct cpu *t_bound_cpu; /* cpu bound to, or NULL if not bound */
	short	t_affinitycnt;	/* nesting level of kernel affinity-setting */
	short	t_bind_cpu;	/* user-specified CPU binding (-1 if none) */
	ushort_t t_flag;		/* modified only by current thread */
	ushort_t t_proc_flag;	/* modified holding ttproc(t)->p_lock */
	ushort_t t_schedflag;	/* modified holding thread_lock(t) */
	volatile char t_preempt;	/* don't preempt thread if set */
	volatile char t_preempt_lk;
	uint_t	t_state;	/* thread state	(protected by thread_lock) */
	pri_t	t_pri;		/* assigned thread priority */
	pri_t	t_epri;		/* inherited thread priority */
	pri_t	t_cpri;		/* thread scheduling class priority */
	char	t_writer;	/* sleeping in lwp_rwlock_lock(RW_WRITE_LOCK) */
	uchar_t	t_bindflag;	/* CPU and pset binding type */
	label_t	t_pcb;		/* pcb, save area when switching */
	lwpchan_t t_lwpchan;	/* reason for blocking */
#define	t_wchan0	t_lwpchan.lc_wchan0
#define	t_wchan		t_lwpchan.lc_wchan
	struct _sobj_ops *t_sobj_ops;
	id_t	t_cid;		/* scheduling class id */
	struct thread_ops *t_clfuncs;	/* scheduling class ops vector */
	void	*t_cldata;	/* per scheduling class specific data */
	ctxop_t	*t_ctx;		/* thread context */
	uintptr_t t_lofault;	/* ret pc for failed page faults */
	label_t	*t_onfault;	/* on_fault() setjmp buf */
	struct on_trap_data *t_ontrap;	/* on_trap() protection data */
	caddr_t t_swap;		/* the bottom of the stack, if from segkp */
	lock_t	t_lock;		/* used to resume() a thread */
	uint8_t	t_lockstat;	/* set while thread is in lockstat code */
	uint8_t	t_pil;		/* interrupt thread PIL */
	disp_lock_t	t_pi_lock;	/* lock protecting t_prioinv list */
	char	t_nomigrate;	/* do not migrate if set */
	struct cpu	*t_cpu;	/* CPU that thread last ran on */
	struct cpu	*t_weakbound_cpu;	/* cpu weakly bound to */
	struct lgrp_ld	*t_lpl;	/* load average for home lgroup */
	void		*t_lgrp_reserv[2];	/* reserved for future */
	struct _kthread	*t_intr; /* interrupted (pinned) thread */
	uint64_t	t_intr_start;	/* timestamp when time slice began */
	kt_did_t	t_did;	/* thread id for kernel debuggers */
	caddr_t t_tnf_tpdp;	/* Trace facility data pointer */
	struct _kcpc_ctx *t_cpc_ctx;	/* performance counter context */
	struct _kcpc_set *t_cpc_set;	/* set this thread has bound */

	/*
	 * non swappable part of the lwp state.
	 */
	id_t		t_tid;		/* lwp's id */
	id_t		t_waitfor;	/* target lwp id in lwp_wait() */
	struct sigqueue	*t_sigqueue;	/* queue of siginfo structs */
	k_sigset_t	t_sig;		/* signals pending to this process */
	k_sigset_t	t_extsig;	/* signals sent from another contract */
	k_sigset_t	t_hold;		/* hold signal bit mask */
	k_sigset_t	t_sigwait;	/* sigtimedwait/sigfd accepting these */
	struct	_kthread *t_forw;	/* process's forward thread link */
	struct	_kthread *t_back;	/* process's backward thread link */
	struct	_kthread *t_thlink;	/* tid (lwpid) lookup hash link */
	klwp_t	*t_lwp;			/* thread's lwp pointer */
	struct	proc	*t_procp;	/* proc pointer */
	struct	t_audit_data *t_audit_data;	/* per thread audit data */
	struct	_kthread *t_next;	/* doubly linked list of all threads */
	struct	_kthread *t_prev;
	ushort_t t_whystop;		/* reason for stopping */
	ushort_t t_whatstop;		/* more detailed reason */
	int	t_dslot;		/* index in proc's thread directory */
	struct	pollstate *t_pollstate;	/* state used during poll(2) */
	struct	pollcache *t_pollcache;	/* to pass a pcache ptr by /dev/poll */
	struct	cred	*t_cred;	/* pointer to current cred */
	time_t	t_start;		/* start time, seconds since epoch */
	clock_t	t_lbolt;		/* lbolt at last clock_tick() */
	hrtime_t t_stoptime;		/* timestamp at stop() */
	uint_t	t_pctcpu;		/* %cpu at last clock_tick(), binary */
					/* point at right of high-order bit */
	short	t_sysnum;		/* system call number */
	kcondvar_t	t_delay_cv;
	kmutex_t	t_delay_lock;

	/*
	 * Pointer to the dispatcher lock protecting t_state and state-related
	 * flags.  This pointer can change during waits on the lock, so
	 * it should be grabbed only by thread_lock().
	 */
	disp_lock_t	*t_lockp;	/* pointer to the dispatcher lock */
	ushort_t 	t_oldspl;	/* spl level before dispatcher locked */
	volatile char	t_pre_sys;	/* pre-syscall work needed */
	lock_t		t_lock_flush;	/* for lock_mutex_flush() impl */
	struct _disp	*t_disp_queue;	/* run queue for chosen CPU */
	clock_t		t_disp_time;	/* last time this thread was running */
	uint_t		t_kpri_req;	/* kernel priority required */

	/*
	 * Post-syscall / post-trap flags.
	 * 	No lock is required to set these.
	 *	These must be cleared only by the thread itself.
	 *
	 *	t_astflag indicates that some post-trap processing is required,
	 *		possibly a signal or a preemption.  The thread will not
	 *		return to user with this set.
	 *	t_post_sys indicates that some unusualy post-system call
	 *		handling is required, such as an error or tracing.
	 *	t_sig_check indicates that some condition in ISSIG() must be
	 * 		checked, but doesn't prevent returning to user.
	 *	t_post_sys_ast is a way of checking whether any of these three
	 *		flags are set.
	 */
	union __tu {
		struct __ts {
			volatile char	_t_astflag;	/* AST requested */
			volatile char	_t_sig_check;	/* ISSIG required */
			volatile char	_t_post_sys;	/* post_syscall req */
			volatile char	_t_trapret;	/* call CL_TRAPRET */
		} _ts;
		volatile int	_t_post_sys_ast;	/* OR of these flags */
	} _tu;
#define	t_astflag	_tu._ts._t_astflag
#define	t_sig_check	_tu._ts._t_sig_check
#define	t_post_sys	_tu._ts._t_post_sys
#define	t_trapret	_tu._ts._t_trapret
#define	t_post_sys_ast	_tu._t_post_sys_ast

	/*
	 * Real time microstate profiling.
	 */
					/* possible 4-byte filler */
	hrtime_t t_waitrq;		/* timestamp for run queue wait time */
	int	t_mstate;		/* current microstate */
	struct rprof {
		int	rp_anystate;		/* set if any state non-zero */
		uint_t	rp_state[NMSTATES];	/* mstate profiling counts */
	} *t_rprof;

	/*
	 * There is a turnstile inserted into the list below for
	 * every priority inverted synchronization object that
	 * this thread holds.
	 */

	struct turnstile *t_prioinv;

	/*
	 * Pointer to the turnstile attached to the synchronization
	 * object where this thread is blocked.
	 */

	struct turnstile *t_ts;

	/*
	 * kernel thread specific data
	 *	Borrowed from userland implementation of POSIX tsd
	 */
	struct tsd_thread {
		struct tsd_thread *ts_next;	/* threads with TSD */
		struct tsd_thread *ts_prev;	/* threads with TSD */
		uint_t		  ts_nkeys;	/* entries in value array */
		void		  **ts_value;	/* array of value/key */
	} *t_tsd;

	clock_t		t_stime;	/* time stamp used by the swapper */
	struct door_data *t_door;	/* door invocation data */
	kmutex_t	*t_plockp;	/* pointer to process's p_lock */

	struct sc_shared *t_schedctl;	/* scheduler activations shared data */
	uintptr_t	t_sc_uaddr;	/* user-level address of shared data */

	struct cpupart	*t_cpupart;	/* partition containing thread */
	int		t_bind_pset;	/* processor set binding */

	struct copyops	*t_copyops;	/* copy in/out ops vector */

	caddr_t		t_stkbase;	/* base of the the stack */
	struct page	*t_red_pp;	/* if non-NULL, redzone is mapped */

	afd_t		t_activefd;	/* active file descriptor table */

	struct _kthread	*t_priforw;	/* sleepq per-priority sublist */
	struct _kthread	*t_priback;

	struct sleepq	*t_sleepq;	/* sleep queue thread is waiting on */
	struct panic_trap_info *t_panic_trap;	/* saved data from fatal trap */
	int		*t_lgrp_affinity;	/* lgroup affinity */
	struct upimutex	*t_upimutex;	/* list of upimutexes owned by thread */
	uint32_t	t_nupinest;	/* number of nested held upi mutexes */
	struct kproject *t_proj;	/* project containing this thread */
	uint8_t		t_unpark;	/* modified holding t_delay_lock */
	uint8_t		t_release;	/* lwp_release() waked up the thread */
	uint8_t		t_hatdepth;	/* depth of recursive hat_memloads */
	uint8_t		t_xpvcntr;	/* see xen_block_migrate() */
	kcondvar_t	t_joincv;	/* cv used to wait for thread exit */
	void		*t_taskq;	/* for threads belonging to taskq */
	hrtime_t	t_anttime;	/* most recent time anticipatory load */
					/*	was added to an lgroup's load */
					/*	on this thread's behalf */
	char		*t_pdmsg;	/* privilege debugging message */

	uint_t		t_predcache;	/* DTrace predicate cache */
	hrtime_t	t_dtrace_vtime;	/* DTrace virtual time */
	hrtime_t	t_dtrace_start;	/* DTrace slice start time */

	uint8_t		t_dtrace_stop;	/* indicates a DTrace-desired stop */
	uint8_t		t_dtrace_sig;	/* signal sent via DTrace's raise() */

	union __tdu {
		struct __tds {
			uint8_t	_t_dtrace_on;	/* hit a fasttrap tracepoint */
			uint8_t	_t_dtrace_step;	/* about to return to kernel */
			uint8_t	_t_dtrace_ret;	/* handling a return probe */
			uint8_t	_t_dtrace_ast;	/* saved ast flag */
#ifdef __amd64
			uint8_t	_t_dtrace_reg;	/* modified register */
#endif
		} _tds;
		ulong_t	_t_dtrace_ft;		/* bitwise or of these flags */
	} _tdu;
#define	t_dtrace_ft	_tdu._t_dtrace_ft
#define	t_dtrace_on	_tdu._tds._t_dtrace_on
#define	t_dtrace_step	_tdu._tds._t_dtrace_step
#define	t_dtrace_ret	_tdu._tds._t_dtrace_ret
#define	t_dtrace_ast	_tdu._tds._t_dtrace_ast
#ifdef __amd64
#define	t_dtrace_reg	_tdu._tds._t_dtrace_reg
#endif

	uintptr_t	t_dtrace_pc;	/* DTrace saved pc from fasttrap */
	uintptr_t	t_dtrace_npc;	/* DTrace next pc from fasttrap */
	uintptr_t	t_dtrace_scrpc;	/* DTrace per-thread scratch location */
	uintptr_t	t_dtrace_astpc;	/* DTrace return sequence location */
#ifdef __amd64
	uint64_t	t_dtrace_regv;	/* DTrace saved reg from fasttrap */
#endif
	hrtime_t	t_hrtime;	/* high-res last time on cpu */
	kmutex_t	t_ctx_lock;	/* protects t_ctx in removectx() */
	struct waitq	*t_waitq;	/* wait queue */
	kmutex_t	t_wait_mutex;	/* used in CV wait functions */
} kthread_t;

/*
 * Thread flag (t_flag) definitions.
 *	These flags must be changed only for the current thread,
 * 	and not during preemption code, since the code being
 *	preempted could be modifying the flags.
 *
 *	For the most part these flags do not need locking.
 *	The following flags will only be changed while the thread_lock is held,
 *	to give assurrance that they are consistent with t_state:
 *		T_WAKEABLE
 */
#define	T_INTR_THREAD	0x0001	/* thread is an interrupt thread */
#define	T_WAKEABLE	0x0002	/* thread is blocked, signals enabled */
#define	T_TOMASK	0x0004	/* use lwp_sigoldmask on return from signal */
#define	T_TALLOCSTK	0x0008  /* thread structure allocated from stk */
#define	T_FORKALL	0x0010	/* thread was cloned by forkall() */
#define	T_WOULDBLOCK	0x0020	/* for lockfs */
#define	T_DONTBLOCK	0x0040	/* for lockfs */
#define	T_DONTPEND	0x0080	/* for lockfs */
#define	T_SYS_PROF	0x0100	/* profiling on for duration of system call */
#define	T_WAITCVSEM	0x0200	/* waiting for a lwp_cv or lwp_sema on sleepq */
#define	T_WATCHPT	0x0400	/* thread undergoing a watchpoint emulation */
#define	T_PANIC		0x0800	/* thread initiated a system panic */
#define	T_LWPREUSE	0x1000	/* stack and LWP can be reused */
#define	T_CAPTURING	0x2000	/* thread is in page capture logic */
#define	T_VFPARENT	0x4000	/* thread is vfork parent, must call vfwait */
#define	T_DONTDTRACE	0x8000  /* disable DTrace probes */

/*
 * Flags in t_proc_flag.
 *	These flags must be modified only when holding the p_lock
 *	for the associated process.
 */
#define	TP_DAEMON	0x0001	/* this is an LWP_DAEMON lwp */
#define	TP_HOLDLWP	0x0002	/* hold thread's lwp */
#define	TP_TWAIT	0x0004	/* wait to be freed by lwp_wait() */
#define	TP_LWPEXIT	0x0008	/* lwp has exited */
#define	TP_PRSTOP	0x0010	/* thread is being stopped via /proc */
#define	TP_CHKPT	0x0020	/* thread is being stopped via CPR checkpoint */
#define	TP_EXITLWP	0x0040	/* terminate this lwp */
#define	TP_PRVSTOP	0x0080	/* thread is virtually stopped via /proc */
#define	TP_MSACCT	0x0100	/* collect micro-state accounting information */
#define	TP_STOPPING	0x0200	/* thread is executing stop() */
#define	TP_WATCHPT	0x0400	/* process has watchpoints in effect */
#define	TP_PAUSE	0x0800	/* process is being stopped via pauselwps() */
#define	TP_CHANGEBIND	0x1000	/* thread has a new cpu/cpupart binding */
#define	TP_ZTHREAD	0x2000	/* this is a kernel thread for a zone */
#define	TP_WATCHSTOP	0x4000	/* thread is stopping via holdwatch() */

/*
 * Thread scheduler flag (t_schedflag) definitions.
 *	The thread must be locked via thread_lock() or equiv. to change these.
 */
#define	TS_LOAD		0x0001	/* thread is in memory */
#define	TS_DONT_SWAP	0x0002	/* thread/lwp should not be swapped */
#define	TS_SWAPENQ	0x0004	/* swap thread when it reaches a safe point */
#define	TS_ON_SWAPQ	0x0008	/* thread is on the swap queue */
#define	TS_SIGNALLED	0x0010	/* thread was awakened by cv_signal() */
#define	TS_PROJWAITQ	0x0020	/* thread is on its project's waitq */
#define	TS_ZONEWAITQ	0x0040	/* thread is on its zone's waitq */
#define	TS_CSTART	0x0100	/* setrun() by continuelwps() */
#define	TS_UNPAUSE	0x0200	/* setrun() by unpauselwps() */
#define	TS_XSTART	0x0400	/* setrun() by SIGCONT */
#define	TS_PSTART	0x0800	/* setrun() by /proc */
#define	TS_RESUME	0x1000	/* setrun() by CPR resume process */
#define	TS_CREATE	0x2000	/* setrun() by syslwp_create() */
#define	TS_RUNQMATCH	0x4000	/* exact run queue balancing by setbackdq() */
#define	TS_ALLSTART	\
	(TS_CSTART|TS_UNPAUSE|TS_XSTART|TS_PSTART|TS_RESUME|TS_CREATE)
#define	TS_ANYWAITQ	(TS_PROJWAITQ|TS_ZONEWAITQ)

/*
 * Thread binding types
 */
#define	TB_ALLHARD	0
#define	TB_CPU_SOFT	0x01		/* soft binding to CPU */
#define	TB_PSET_SOFT	0x02		/* soft binding to pset */

#define	TB_CPU_SOFT_SET(t)		((t)->t_bindflag |= TB_CPU_SOFT)
#define	TB_CPU_HARD_SET(t)		((t)->t_bindflag &= ~TB_CPU_SOFT)
#define	TB_PSET_SOFT_SET(t)		((t)->t_bindflag |= TB_PSET_SOFT)
#define	TB_PSET_HARD_SET(t)		((t)->t_bindflag &= ~TB_PSET_SOFT)
#define	TB_CPU_IS_SOFT(t)		((t)->t_bindflag & TB_CPU_SOFT)
#define	TB_CPU_IS_HARD(t)		(!TB_CPU_IS_SOFT(t))
#define	TB_PSET_IS_SOFT(t)		((t)->t_bindflag & TB_PSET_SOFT)

/*
 * No locking needed for AST field.
 */
#define	aston(t)		((t)->t_astflag = 1)
#define	astoff(t)		((t)->t_astflag = 0)

/* True if thread is stopped on an event of interest */
#define	ISTOPPED(t) ((t)->t_state == TS_STOPPED && \
			!((t)->t_schedflag & TS_PSTART))

/* True if thread is asleep and wakeable */
#define	ISWAKEABLE(t) (((t)->t_state == TS_SLEEP && \
			((t)->t_flag & T_WAKEABLE)))

/* True if thread is on the wait queue */
#define	ISWAITING(t) ((t)->t_state == TS_WAIT)

/* similar to ISTOPPED except the event of interest is CPR */
#define	CPR_ISTOPPED(t) ((t)->t_state == TS_STOPPED && \
			!((t)->t_schedflag & TS_RESUME))

/*
 * True if thread is virtually stopped (is or was asleep in
 * one of the lwp_*() system calls and marked to stop by /proc.)
 */
#define	VSTOPPED(t)	((t)->t_proc_flag & TP_PRVSTOP)

/* similar to VSTOPPED except the point of interest is CPR */
#define	CPR_VSTOPPED(t)				\
	((t)->t_state == TS_SLEEP &&		\
	(t)->t_wchan0 != NULL &&		\
	((t)->t_flag & T_WAKEABLE) &&		\
	((t)->t_proc_flag & TP_CHKPT))

/* True if thread has been stopped by hold*() or was created stopped */
#define	SUSPENDED(t) ((t)->t_state == TS_STOPPED && \
	((t)->t_schedflag & (TS_CSTART|TS_UNPAUSE)) != (TS_CSTART|TS_UNPAUSE))

/* True if thread possesses an inherited priority */
#define	INHERITED(t)	((t)->t_epri != 0)

/* The dispatch priority of a thread */
#define	DISP_PRIO(t) ((t)->t_epri > (t)->t_pri ? (t)->t_epri : (t)->t_pri)

/* The assigned priority of a thread */
#define	ASSIGNED_PRIO(t)	((t)->t_pri)

/*
 * Macros to determine whether a thread can be swapped.
 * If t_lock is held, the thread is either on a processor or being swapped.
 */
#define	SWAP_OK(t)	(!LOCK_HELD(&(t)->t_lock))

/*
 * proctot(x)
 *	convert a proc pointer to a thread pointer. this only works with
 *	procs that have only one lwp.
 *
 * proctolwp(x)
 *	convert a proc pointer to a lwp pointer. this only works with
 *	procs that have only one lwp.
 *
 * ttolwp(x)
 *	convert a thread pointer to its lwp pointer.
 *
 * ttoproc(x)
 *	convert a thread pointer to its proc pointer.
 *
 * ttoproj(x)
 * 	convert a thread pointer to its project pointer.
 *
 * ttozone(x)
 * 	convert a thread pointer to its zone pointer.
 *
 * lwptot(x)
 *	convert a lwp pointer to its thread pointer.
 *
 * lwptoproc(x)
 *	convert a lwp to its proc pointer.
 */
#define	proctot(x)	((x)->p_tlist)
#define	proctolwp(x)	((x)->p_tlist->t_lwp)
#define	ttolwp(x)	((x)->t_lwp)
#define	ttoproc(x)	((x)->t_procp)
#define	ttoproj(x)	((x)->t_proj)
#define	ttozone(x)	((x)->t_procp->p_zone)
#define	lwptot(x)	((x)->lwp_thread)
#define	lwptoproc(x)	((x)->lwp_procp)

#define	t_pc		t_pcb.val[0]
#define	t_sp		t_pcb.val[1]

#ifdef	_KERNEL

extern	kthread_t	*threadp(void);	/* inline, returns thread pointer */
#define	curthread	(threadp())		/* current thread pointer */
#define	curproc		(ttoproc(curthread))	/* current process pointer */
#define	curproj		(ttoproj(curthread))	/* current project pointer */
#define	curzone		(curproc->p_zone)	/* current zone pointer */

extern	struct _kthread	t0;		/* the scheduler thread */
extern	kmutex_t	pidlock;	/* global process lock */

/*
 * thread_free_lock is used by the tick accounting thread to keep a thread
 * from being freed while it is being examined.
 *
 * Thread structures are 32-byte aligned structures. That is why we use the
 * following formula.
 */
#define	THREAD_FREE_BITS	10
#define	THREAD_FREE_NUM		(1 << THREAD_FREE_BITS)
#define	THREAD_FREE_MASK	(THREAD_FREE_NUM - 1)
#define	THREAD_FREE_1		PTR24_LSB
#define	THREAD_FREE_2		(PTR24_LSB + THREAD_FREE_BITS)
#define	THREAD_FREE_SHIFT(t)	\
	(((ulong_t)(t) >> THREAD_FREE_1) ^ ((ulong_t)(t) >> THREAD_FREE_2))
#define	THREAD_FREE_HASH(t)	(THREAD_FREE_SHIFT(t) & THREAD_FREE_MASK)

typedef struct thread_free_lock {
	kmutex_t	tf_lock;
	uchar_t		tf_pad[64 - sizeof (kmutex_t)];
} thread_free_lock_t;

extern void	thread_free_prevent(kthread_t *);
extern void	thread_free_allow(kthread_t *);

/*
 * Routines to change the priority and effective priority
 * of a thread-locked thread, whatever its state.
 */
extern int	thread_change_pri(kthread_t *t, pri_t disp_pri, int front);
extern void	thread_change_epri(kthread_t *t, pri_t disp_pri);

/*
 * Routines that manipulate the dispatcher lock for the thread.
 * The locking heirarchy is as follows:
 *	cpu_lock > sleepq locks > run queue locks
 */
void	thread_transition(kthread_t *); /* move to transition lock */
void	thread_stop(kthread_t *);	/* move to stop lock */
void	thread_lock(kthread_t *);	/* lock thread and its queue */
void	thread_lock_high(kthread_t *);	/* lock thread and its queue */
void	thread_onproc(kthread_t *, struct cpu *); /* set onproc state lock */

#define	thread_unlock(t)		disp_lock_exit((t)->t_lockp)
#define	thread_unlock_high(t)		disp_lock_exit_high((t)->t_lockp)
#define	thread_unlock_nopreempt(t)	disp_lock_exit_nopreempt((t)->t_lockp)

#define	THREAD_LOCK_HELD(t)	(DISP_LOCK_HELD((t)->t_lockp))

extern disp_lock_t transition_lock;	/* lock protecting transiting threads */
extern disp_lock_t stop_lock;		/* lock protecting stopped threads */

caddr_t	thread_stk_init(caddr_t);	/* init thread stack */

extern int default_binding_mode;

#endif	/* _KERNEL */

/*
 * Macros to indicate that the thread holds resources that could be critical
 * to other kernel threads, so this thread needs to have kernel priority
 * if it blocks or is preempted.  Note that this is not necessary if the
 * resource is a mutex or a writer lock because of priority inheritance.
 *
 * The only way one thread may legally manipulate another thread's t_kpri_req
 * is to hold the target thread's thread lock while that thread is asleep.
 * (The rwlock code does this to implement direct handoff to waiting readers.)
 */
#define	THREAD_KPRI_REQUEST()	(curthread->t_kpri_req++)
#define	THREAD_KPRI_RELEASE()	(curthread->t_kpri_req--)
#define	THREAD_KPRI_RELEASE_N(n) (curthread->t_kpri_req -= (n))

/*
 * Macro to change a thread's priority.
 */
#define	THREAD_CHANGE_PRI(t, pri) {					\
	pri_t __new_pri = (pri);					\
	DTRACE_SCHED2(change__pri, kthread_t *, (t), pri_t, __new_pri);	\
	(t)->t_pri = __new_pri;						\
	schedctl_set_cidpri(t);						\
}

/*
 * Macro to indicate that a thread's priority is about to be changed.
 */
#define	THREAD_WILLCHANGE_PRI(t, pri) {					\
	DTRACE_SCHED2(change__pri, kthread_t *, (t), pri_t, (pri));	\
}

/*
 * Macros to change thread state and the associated lock.
 */
#define	THREAD_SET_STATE(tp, state, lp) \
		((tp)->t_state = state, (tp)->t_lockp = lp)

/*
 * Point it at the transition lock, which is always held.
 * The previosly held lock is dropped.
 */
#define	THREAD_TRANSITION(tp) 	thread_transition(tp);
/*
 * Set the thread's lock to be the transition lock, without dropping
 * previosly held lock.
 */
#define	THREAD_TRANSITION_NOLOCK(tp) 	((tp)->t_lockp = &transition_lock)

/*
 * Put thread in run state, and set the lock pointer to the dispatcher queue
 * lock pointer provided.  This lock should be held.
 */
#define	THREAD_RUN(tp, lp)	THREAD_SET_STATE(tp, TS_RUN, lp)

/*
 * Put thread in wait state, and set the lock pointer to the wait queue
 * lock pointer provided.  This lock should be held.
 */
#define	THREAD_WAIT(tp, lp)	THREAD_SET_STATE(tp, TS_WAIT, lp)

/*
 * Put thread in run state, and set the lock pointer to the dispatcher queue
 * lock pointer provided (i.e., the "swapped_lock").  This lock should be held.
 */
#define	THREAD_SWAP(tp, lp)	THREAD_SET_STATE(tp, TS_RUN, lp)

/*
 * Put the thread in zombie state and set the lock pointer to NULL.
 * The NULL will catch anything that tries to lock a zombie.
 */
#define	THREAD_ZOMB(tp)		THREAD_SET_STATE(tp, TS_ZOMB, NULL)

/*
 * Set the thread into ONPROC state, and point the lock at the CPUs
 * lock for the onproc thread(s).  This lock should be held, so the
 * thread deoes not become unlocked, since these stores can be reordered.
 */
#define	THREAD_ONPROC(tp, cpu)	\
		THREAD_SET_STATE(tp, TS_ONPROC, &(cpu)->cpu_thread_lock)

/*
 * Set the thread into the TS_SLEEP state, and set the lock pointer to
 * to some sleep queue's lock.  The new lock should already be held.
 */
#define	THREAD_SLEEP(tp, lp)	{				\
			disp_lock_t	*tlp;			\
			tlp = (tp)->t_lockp;			\
			THREAD_SET_STATE(tp, TS_SLEEP, lp);	\
			disp_lock_exit_high(tlp);		\
			}

/*
 * Interrupt threads are created in TS_FREE state, and their lock
 * points at the associated CPU's lock.
 */
#define	THREAD_FREEINTR(tp, cpu)	\
		THREAD_SET_STATE(tp, TS_FREE, &(cpu)->cpu_thread_lock)

/* if tunable kmem_stackinfo is set, fill kthread stack with a pattern */
#define	KMEM_STKINFO_PATTERN	0xbadcbadcbadcbadcULL

/*
 * If tunable kmem_stackinfo is set, log the latest KMEM_LOG_STK_USAGE_SIZE
 * dead kthreads that used their kernel stack the most.
 */
#define	KMEM_STKINFO_LOG_SIZE	16

/* kthread name (cmd/lwpid) string size in the stackinfo log */
#define	KMEM_STKINFO_STR_SIZE	64

/*
 * stackinfo logged data.
 */
typedef struct kmem_stkinfo {
	caddr_t	kthread;	/* kthread pointer */
	caddr_t	t_startpc;	/* where kthread started */
	caddr_t	start;		/* kthread stack start address */
	size_t	stksz;		/* kthread stack size */
	size_t	percent;	/* kthread stack high water mark */
	id_t	t_tid;		/* kthread id */
	char	cmd[KMEM_STKINFO_STR_SIZE];	/* kthread name (cmd/lwpid) */
} kmem_stkinfo_t;

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_THREAD_H */
