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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright 2015, Joyent, Inc.
 */

#ifndef _SYS_PROC_PRDATA_H
#define	_SYS_PROC_PRDATA_H

#include <sys/isa_defs.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/prsystm.h>
#include <sys/model.h>
#include <sys/poll.h>
#include <sys/list.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Test for thread being stopped, not on an event of interest,
 * but with a directed stop in effect.
 */
#define	DSTOPPED(t)	\
	((t)->t_state == TS_STOPPED && \
	((t)->t_proc_flag & TP_PRSTOP))

#define	round4(r)	(((r) + 3) & (~3))
#define	round8(r)	(((r) + 7) & (~7))
#define	round16(r)	(((r) + 15) & (~15))
#define	roundlong(r)	(((r) + sizeof (long) - 1) & (~(sizeof (long) - 1)))

#define	PNSIZ	10			/* max size of /proc name entries */
#define	PLNSIZ	10			/* max size of /proc lwp name entries */

/*
 * Common file object to which all /proc vnodes for a specific process
 * or lwp refer.  One for the process, one for each lwp.
 */
typedef struct prcommon {
	kmutex_t	prc_mutex;	/* to wait for the proc/lwp to stop */
	kcondvar_t	prc_wait;	/* to wait for the proc/lwp to stop */
	ushort_t	prc_flags;	/* flags */
	uint_t		prc_writers;	/* number of write opens of prnodes */
	uint_t		prc_selfopens;	/* number of write opens by self */
	pid_t		prc_pid;	/* process id */
	model_t		prc_datamodel;	/* data model of the process */
	proc_t		*prc_proc;	/* process being traced */
	kthread_t	*prc_thread;	/* thread (lwp) being traced */
	int		prc_slot;	/* procdir slot number */
	id_t		prc_tid;	/* thread (lwp) id */
	int		prc_tslot;	/* lwpdir slot number, -1 if reaped */
	int		prc_refcnt;	/* this structure's reference count */
	struct pollhead	prc_pollhead;	/* list of all pollers */
} prcommon_t;

/* prc_flags */
#define	PRC_DESTROY	0x01	/* process or lwp is being destroyed */
#define	PRC_LWP		0x02	/* structure refers to an lwp */
#define	PRC_SYS		0x04	/* process is a system process */
#define	PRC_POLL	0x08	/* poll() in progress on this process/lwp */
#define	PRC_EXCL	0x10	/* exclusive access granted (old /proc) */

/*
 * Macros for mapping between i-numbers and pids.
 */
#define	pmkino(tslot, pslot, nodetype)		\
	(((((ino_t)(tslot) << nproc_highbit) |	\
	(ino_t)(pslot)) << 6) |			\
	(nodetype) + 2)

/* for old /proc interface */
#define	PRBIAS	64
#define	ptoi(n) ((int)(((n) + PRBIAS)))		/* pid to i-number */

/*
 * Node types for /proc files (directories and files contained therein).
 */
typedef enum prnodetype {
	PR_PROCDIR,		/* /proc				*/
	PR_SELF,		/* /proc/self				*/
	PR_PIDDIR,		/* /proc/<pid>				*/
	PR_AS,			/* /proc/<pid>/as			*/
	PR_CTL,			/* /proc/<pid>/ctl			*/
	PR_STATUS,		/* /proc/<pid>/status			*/
	PR_LSTATUS,		/* /proc/<pid>/lstatus			*/
	PR_PSINFO,		/* /proc/<pid>/psinfo			*/
	PR_LPSINFO,		/* /proc/<pid>/lpsinfo			*/
	PR_MAP,			/* /proc/<pid>/map			*/
	PR_RMAP,		/* /proc/<pid>/rmap			*/
	PR_XMAP,		/* /proc/<pid>/xmap			*/
	PR_CRED,		/* /proc/<pid>/cred			*/
	PR_SIGACT,		/* /proc/<pid>/sigact			*/
	PR_AUXV,		/* /proc/<pid>/auxv			*/
#if defined(__i386) || defined(__amd64)
	PR_LDT,			/* /proc/<pid>/ldt			*/
#endif
	PR_ARGV,		/* /proc/<pid>/argv			*/
	PR_USAGE,		/* /proc/<pid>/usage			*/
	PR_LUSAGE,		/* /proc/<pid>/lusage			*/
	PR_PAGEDATA,		/* /proc/<pid>/pagedata			*/
	PR_WATCH,		/* /proc/<pid>/watch			*/
	PR_CURDIR,		/* /proc/<pid>/cwd			*/
	PR_ROOTDIR,		/* /proc/<pid>/root			*/
	PR_FDDIR,		/* /proc/<pid>/fd			*/
	PR_FD,			/* /proc/<pid>/fd/nn			*/
	PR_OBJECTDIR,		/* /proc/<pid>/object			*/
	PR_OBJECT,		/* /proc/<pid>/object/xxx		*/
	PR_LWPDIR,		/* /proc/<pid>/lwp			*/
	PR_LWPIDDIR,		/* /proc/<pid>/lwp/<lwpid>		*/
	PR_LWPCTL,		/* /proc/<pid>/lwp/<lwpid>/lwpctl	*/
	PR_LWPSTATUS,		/* /proc/<pid>/lwp/<lwpid>/lwpstatus	*/
	PR_LWPSINFO,		/* /proc/<pid>/lwp/<lwpid>/lwpsinfo	*/
	PR_LWPUSAGE,		/* /proc/<pid>/lwp/<lwpid>/lwpusage	*/
	PR_XREGS,		/* /proc/<pid>/lwp/<lwpid>/xregs	*/
	PR_TMPLDIR,		/* /proc/<pid>/lwp/<lwpid>/templates	*/
	PR_TMPL,		/* /proc/<pid>/lwp/<lwpid>/templates/<id> */
	PR_SPYMASTER,		/* /proc/<pid>/lwp/<lwpid>/spymaster	*/
#if defined(__sparc)
	PR_GWINDOWS,		/* /proc/<pid>/lwp/<lwpid>/gwindows	*/
	PR_ASRS,		/* /proc/<pid>/lwp/<lwpid>/asrs		*/
#endif
	PR_PRIV,		/* /proc/<pid>/priv			*/
	PR_PATHDIR,		/* /proc/<pid>/path			*/
	PR_PATH,		/* /proc/<pid>/path/xxx			*/
	PR_CTDIR,		/* /proc/<pid>/contracts		*/
	PR_CT,			/* /proc/<pid>/contracts/<ctid>		*/
	PR_PIDFILE,		/* old process file			*/
	PR_LWPIDFILE,		/* old lwp file				*/
	PR_OPAGEDATA,		/* old page data file			*/
	PR_NFILES		/* number of /proc node types		*/
} prnodetype_t;

typedef struct prnode {
	vnode_t		*pr_next;	/* list of all vnodes for process */
	uint_t		pr_flags;	/* private flags */
	kmutex_t	pr_mutex;	/* locks pr_files and child pr_flags */
	prnodetype_t	pr_type;	/* node type */
	mode_t		pr_mode;	/* file mode */
	ino_t		pr_ino;		/* node id (for stat(2)) */
	uint_t		pr_hatid;	/* hat layer id for page data files */
	prcommon_t	*pr_common;	/* common data structure */
	prcommon_t	*pr_pcommon;	/* process common data structure */
	vnode_t		*pr_parent;	/* parent directory */
	vnode_t		**pr_files;	/* contained files array (directory) */
	uint_t		pr_index;	/* position within parent */
	vnode_t		*pr_pidfile;	/* substitute vnode for old /proc */
	vnode_t		*pr_realvp;	/* real vnode, file in object,fd dirs */
	proc_t		*pr_owner;	/* the process that created this node */
	vnode_t		*pr_vnode;	/* pointer to vnode */
	struct contract *pr_contract;	/* contract pointer */
	int		pr_cttype;	/* active template type */
} prnode_t;

/*
 * Values for pr_flags.
 */
#define	PR_INVAL	0x01		/* vnode is invalidated */
#define	PR_ISSELF	0x02		/* vnode is a self-open */
#define	PR_AOUT		0x04		/* vnode is for an a.out path */
#define	PR_OFFMAX	0x08		/* vnode is a large file open */

/*
 * Conversion macros.
 */
#define	VTOP(vp)	((struct prnode *)(vp)->v_data)
#define	PTOV(pnp)	((pnp)->pr_vnode)

/*
 * Flags to prlock().
 */
#define	ZNO	0	/* Fail on encountering a zombie process. */
#define	ZYES	1	/* Allow zombies. */

/*
 * Assign one set to another (possible different sizes).
 *
 * Assigning to a smaller set causes members to be lost.
 * Assigning to a larger set causes extra members to be cleared.
 */
#define	prassignset(ap, sp)					\
{								\
	register int _i_ = sizeof (*(ap))/sizeof (uint32_t);	\
	while (--_i_ >= 0)					\
		((uint32_t *)(ap))[_i_] =			\
		    (_i_ >= sizeof (*(sp))/sizeof (uint32_t)) ?	\
		    0 : ((uint32_t *)(sp))[_i_];		\
}

/*
 * Determine whether or not a set (of arbitrary size) is empty.
 */
#define	prisempty(sp) \
	setisempty((uint32_t *)(sp), \
		(uint_t)(sizeof (*(sp)) / sizeof (uint32_t)))

/*
 * Resource usage with times as hrtime_t rather than timestruc_t.
 * Each member exactly matches the corresponding member in prusage_t.
 * This is for convenience of internal computation.
 */
typedef struct prhusage {
	id_t		pr_lwpid;	/* lwp id.  0: process or defunct */
	int		pr_count;	/* number of contributing lwps */
	hrtime_t	pr_tstamp;	/* current time stamp */
	hrtime_t	pr_create;	/* process/lwp creation time stamp */
	hrtime_t	pr_term;	/* process/lwp termination time stamp */
	hrtime_t	pr_rtime;	/* total lwp real (elapsed) time */
	hrtime_t	pr_utime;	/* user level CPU time */
	hrtime_t	pr_stime;	/* system call CPU time */
	hrtime_t	pr_ttime;	/* other system trap CPU time */
	hrtime_t	pr_tftime;	/* text page fault sleep time */
	hrtime_t	pr_dftime;	/* data page fault sleep time */
	hrtime_t	pr_kftime;	/* kernel page fault sleep time */
	hrtime_t	pr_ltime;	/* user lock wait sleep time */
	hrtime_t	pr_slptime;	/* all other sleep time */
	hrtime_t	pr_wtime;	/* wait-cpu (latency) time */
	hrtime_t	pr_stoptime;	/* stopped time */
	hrtime_t	filltime[6];	/* filler for future expansion */
	uint64_t	pr_minf;	/* minor page faults */
	uint64_t	pr_majf;	/* major page faults */
	uint64_t	pr_nswap;	/* swaps */
	uint64_t	pr_inblk;	/* input blocks */
	uint64_t	pr_oublk;	/* output blocks */
	uint64_t	pr_msnd;	/* messages sent */
	uint64_t	pr_mrcv;	/* messages received */
	uint64_t	pr_sigs;	/* signals received */
	uint64_t	pr_vctx;	/* voluntary context switches */
	uint64_t	pr_ictx;	/* involuntary context switches */
	uint64_t	pr_sysc;	/* system calls */
	uint64_t	pr_ioch;	/* chars read and written */
	uint64_t	filler[10];	/* filler for future expansion */
} prhusage_t;

#if defined(_KERNEL)

/* Exclude system processes from this test */
#define	PROCESS_NOT_32BIT(p)	\
	(!((p)->p_flag & SSYS) && (p)->p_as != &kas && \
	(p)->p_model != DATAMODEL_ILP32)

extern	int	prnwatch;	/* number of supported watchpoints */
extern	int	nproc_highbit;	/* highbit(v.v_nproc) */

extern	struct vnodeops	*prvnodeops;

/*
 * Generic chained copyout buffers for procfs use.
 * In order to prevent procfs from making huge oversize kmem_alloc calls,
 * a list of smaller buffers can be concatenated and copied to userspace in
 * sequence.
 *
 * The implementation is opaque.
 *
 * A user of this will perform the following steps:
 *
 *	list_t	listhead;
 *	struct my *mp;
 *
 *	pr_iol_initlist(&listhead, sizeof (*mp), n);
 *	while (whatever) {
 *		mp = pr_iol_newbuf(&listhead, sizeof (*mp);
 *		...
 *		error = ...
 *	}
 *
 * When done, depending on whether copyout() or uiomove() is supposed to
 * be used for transferring the buffered data to userspace, call either:
 *
 *	error = pr_iol_copyout_and_free(&listhead, &cmaddr, error);
 *
 * or else:
 *
 *	error = pr_iol_uiomove_and_free(&listhead, uiop, error);
 *
 * These two functions will in any case kmem_free() all list items, but
 * if an error occurred before they will not perform the copyout/uiomove.
 * If copyout/uiomove are done, the passed target address / uio_t
 * are updated. The error returned will either be the one passed in, or
 * the error that occurred during copyout/uiomove.
 */

extern	void	pr_iol_initlist(list_t *head, size_t itemsize, int nitems);
extern	void *	pr_iol_newbuf(list_t *head, size_t itemsize);
extern	int	pr_iol_copyout_and_free(list_t *head, caddr_t *tgt, int errin);
extern	int	pr_iol_uiomove_and_free(list_t *head, uio_t *uiop, int errin);

#if defined(_SYSCALL32_IMPL)

extern	int	prwritectl32(vnode_t *, struct uio *, cred_t *);
extern	void	prgetaction32(proc_t *, user_t *, uint_t, struct sigaction32 *);
extern	void	prcvtusage32(struct prhusage *, prusage32_t *);

#endif	/* _SYSCALL32_IMPL */

/* kludge to support old /proc interface */
#if !defined(_SYS_OLD_PROCFS_H)
extern	int	prgetmap(proc_t *, int, list_t *);
extern	int	prgetxmap(proc_t *, list_t *);
#if defined(_SYSCALL32_IMPL)
extern	int	prgetmap32(proc_t *, int, list_t *);
extern	int	prgetxmap32(proc_t *, list_t *);
#endif	/* _SYSCALL32_IMPL */
#endif /* !_SYS_OLD_PROCFS_H */

extern	proc_t	*pr_p_lock(prnode_t *);
extern	kthread_t *pr_thread(prnode_t *);
extern	void	pr_stop(prnode_t *);
extern	int	pr_wait_stop(prnode_t *, time_t);
extern	int	pr_setrun(prnode_t *, ulong_t);
extern	int	pr_wait(prcommon_t *, timestruc_t *, int);
extern	void	pr_wait_die(prnode_t *);
extern	int	pr_setsig(prnode_t *, siginfo_t *);
extern	int	pr_kill(prnode_t *, int, cred_t *);
extern	int	pr_unkill(prnode_t *, int);
extern	int	pr_nice(proc_t *, int, cred_t *);
extern	void	pr_setentryexit(proc_t *, sysset_t *, int);
extern	int	pr_set(proc_t *, long);
extern	int	pr_unset(proc_t *, long);
extern	void	pr_sethold(prnode_t *, sigset_t *);
extern	void	pr_setfault(proc_t *, fltset_t *);
extern	int	prusrio(proc_t *, enum uio_rw, struct uio *, int);
extern	int	prreadargv(proc_t *, char *, size_t, size_t *);
extern	int	prwritectl(vnode_t *, struct uio *, cred_t *);
extern	int	prlock(prnode_t *, int);
extern	void	prunmark(proc_t *);
extern	void	prunlock(prnode_t *);
extern	size_t	prpdsize(struct as *);
extern	int	prpdread(proc_t *, uint_t, struct uio *);
extern	size_t	oprpdsize(struct as *);
extern	int	oprpdread(struct as *, uint_t, struct uio *);
extern	void	prgetaction(proc_t *, user_t *, uint_t, struct sigaction *);
extern	void	prgetusage(kthread_t *, struct prhusage *);
extern	void	praddusage(kthread_t *, struct prhusage *);
extern	void	prcvtusage(struct prhusage *, prusage_t *);
extern	void 	prscaleusage(prhusage_t *);
extern	kthread_t *prchoose(proc_t *);
extern	void	allsetrun(proc_t *);
extern	int	setisempty(uint32_t *, uint_t);
extern	int	pr_u32tos(uint32_t, char *, int);
extern	vnode_t	*prlwpnode(prnode_t *, uint_t);
extern	prnode_t *prgetnode(vnode_t *, prnodetype_t);
extern	void	prfreenode(prnode_t *);
extern	void	pr_object_name(char *, vnode_t *, struct vattr *);
extern	int	set_watched_area(proc_t *, struct watched_area *);
extern	int	clear_watched_area(proc_t *, struct watched_area *);
extern	void	pr_free_watchpoints(proc_t *);
extern	proc_t	*pr_cancel_watch(prnode_t *);
extern	struct seg *break_seg(proc_t *);

/*
 * Machine-dependent routines (defined in prmachdep.c).
 */
extern	void	prgetprregs(klwp_t *, prgregset_t);
extern	void	prsetprregs(klwp_t *, prgregset_t, int);

#if defined(_SYSCALL32_IMPL)
extern	void	prgetprregs32(klwp_t *, prgregset32_t);
extern	void	prgregset_32ton(klwp_t *, prgregset32_t, prgregset_t);
extern	void	prgetprfpregs32(klwp_t *, prfpregset32_t *);
extern	void	prsetprfpregs32(klwp_t *, prfpregset32_t *);
extern	size_t	prpdsize32(struct as *);
extern	int	prpdread32(proc_t *, uint_t, struct uio *);
extern	size_t	oprpdsize32(struct as *);
extern	int	oprpdread32(struct as *, uint_t, struct uio *);
#endif	/* _SYSCALL32_IMPL */

extern	void	prpokethread(kthread_t *t);
extern	int	prgetrvals(klwp_t *, long *, long *);
extern	void	prgetprfpregs(klwp_t *, prfpregset_t *);
extern	void	prsetprfpregs(klwp_t *, prfpregset_t *);
extern	void	prgetprxregs(klwp_t *, caddr_t);
extern	void	prsetprxregs(klwp_t *, caddr_t);
extern	int	prgetprxregsize(proc_t *);
extern	int	prhasfp(void);
extern	int	prhasx(proc_t *);
extern	caddr_t	prgetstackbase(proc_t *);
extern	caddr_t	prgetpsaddr(proc_t *);
extern	int	prisstep(klwp_t *);
extern	void	prsvaddr(klwp_t *, caddr_t);
extern	int	prfetchinstr(klwp_t *, ulong_t *);
extern	ushort_t prgetpctcpu(uint64_t);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PROC_PRDATA_H */
