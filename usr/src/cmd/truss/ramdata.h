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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#ifndef _RAMDATA_H
#define	_RAMDATA_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * ramdata.h -- read/write data declarations.
 */

#include <errno.h>
#include <signal.h>
#include <synch.h>
#include <thread.h>
#include <thread_db.h>
#include "htbl.h"

/*
 * Set type for possible filedescriptors.
 */
#define	NOFILES_MAX	(64 * 1024)
typedef struct {
	uint32_t word[(NOFILES_MAX+31)/32];
} fileset_t;

/*
 * Previous stop state enumeration (used by signalled() and requested()).
 */
#define	SLEEPING	1
#define	JOBSIG		2
#define	JOBSTOP		3

/*
 * Simple convenience.
 */
#ifdef	TRUE
#undef	TRUE
#endif
#ifdef	FALSE
#undef	FALSE
#endif
#define	TRUE	1
#define	FALSE	0

/*
 * Definition of private data.  See get_private().
 */

#define	IOBSIZE	12		/* number of bytes shown by prt_iob() */

#define	CACHE_LN_SZ 64

typedef struct private {
	struct ps_lwphandle *Lwp;	/* non-NULL for each lwp controller */
	const lwpstatus_t *lwpstat; /* lwp status information while stopped */
	int	length;		/* length of printf() output so far */
	pid_t	child;		/* pid of fork()ed child process */
	char	pname[32];	/* formatted pid/tid of controlled lwp */
	struct {		/* remembered parameters for make_pname() */
		int	ff;
		int	lf;
		pid_t	pid;
		id_t	lwpid;
		id_t	tid;
	} pparam;
	int	Errno;		/* errno for controlled process's syscall */
	int	ErrPriv;	/* privilege missing for last syscall */
	long	Rval1;		/* rval1 (%r0) for syscall */
	long	Rval2;		/* rval2 (%r1) for syscall */
	timestruc_t syslast;	/* most recent value of stime */
	timestruc_t usrlast;	/* most recent value of utime */
	long	sys_args[9];	/* the arguments to the last syscall */
	int	sys_nargs;	/* number of arguments to the last syscall */
	int	sys_indirect;	/* if TRUE, this is an indirect system call */
	char	sys_name[12];	/* name of unknown system call */
	char	raw_sig_name[SIG2STR_MAX+4]; /* name of known signal */
	char	sig_name[12];	/* name of unknown signal */
	char	flt_name[12];	/* name of unknown fault */
	char	*sys_path;	/* first pathname given to syscall */
	size_t	sys_psize;	/* sizeof(*sys_path) */
	int	sys_valid;	/* pathname was fetched and is valid */
	char	*sys_string;	/* buffer for formatted syscall string */
	size_t	sys_ssize;	/* sizeof(*sys_string) */
	size_t	sys_leng;	/* strlen(sys_string) */
	char	*exec_string;	/* copy of sys_string for exec() only */
	char	exec_pname[32];	/* formatted pid for exec() only */
	id_t	exec_lwpid;	/* lwpid that performed the exec */
	char	*str_buffer;	/* fetchstring() buffer */
	size_t	str_bsize;	/* sizeof(*str_buffer) */
	char	iob_buf[2*IOBSIZE+8];	/* where prt_iob() leaves its stuff */
	char	code_buf[160];	/* for symbolic arguments, e.g., ioctl codes */
	int	recur;		/* show_strioctl() -- to prevent recursion */
	int	seconds;	/* seconds, fraction for timestamps */
	int	fraction;	/* fraction in 1/10 milliseconds */
} private_t;

extern	thread_key_t	private_key;	/* set by thr_keycreate() */

extern	char	*command;	/* name of command ("truss") */
extern	int	interrupt;	/* interrupt signal was received */
extern	int	sigusr1;	/* received SIGUSR1 (release process) */
extern	int	sfd;		/* file descriptor to shared tmp file */
extern	pid_t	created;	/* if process was created, its process id */
extern	uid_t	Euid;		/* truss's effective uid */
extern	uid_t	Egid;		/* truss's effective gid */
extern	uid_t	Ruid;		/* truss's real uid */
extern	uid_t	Rgid;		/* truss's real gid */
extern	prcred_t credentials;	/* traced process credentials */
extern	int	istty;		/* TRUE iff output is a tty */
extern	time_t	starttime;	/* start time */

extern	int	Fflag;		/* option flags from getopt() */
extern	int	fflag;
extern	int	cflag;
extern	int	aflag;
extern	int	eflag;
extern	int	iflag;
extern	int	lflag;
extern	int	tflag;
extern	int	pflag;
extern	int	sflag;
extern	int	mflag;
extern	int	oflag;
extern	int	vflag;
extern	int	xflag;
extern	int	hflag;

extern	int	dflag;
extern	int	Dflag;
extern	int	Eflag;
extern	int	Tflag;
extern	int	Sflag;
extern	int	Mflag;

extern	sysset_t trace;		/* sys calls to trace */
extern	sysset_t traceeven;	/* sys calls to trace even if not reported */
extern	sysset_t verbose;	/* sys calls to be verbose about */
extern	sysset_t rawout;	/* sys calls to show in raw mode */
extern	sigset_t signals;	/* signals to trace */
extern	fltset_t faults;	/* faults to trace */
extern	fileset_t readfd;	/* read() file descriptors to dump */
extern	fileset_t writefd;	/* write() file descriptors to dump */

#pragma align CACHE_LN_SZ(truss_lock, count_lock)
extern	mutex_t	truss_lock;	/* protects almost everything */
extern	cond_t	truss_cv;	/* condition variable associated w truss_lock */
extern	mutex_t count_lock;	/* lock protecting count struct Cp */

extern	htbl_t	*fcall_tbl;	/* function call hash table (per-proc) */

extern	int	truss_nlwp;	/* number of truss lwps */
extern	int	truss_maxlwp;	/* number of entries in truss_lwpid */
extern	lwpid_t	*truss_lwpid;	/* array of truss lwpid's */


struct syscount {
	long count;		/* system call count */
	long error;		/* system call errors */
	timestruc_t stime;	/* time spent in system call */
};

struct counts {		/* structure for keeping counts */
	long sigcount[PRMAXSIG+1];	/* signals count [0..PRMAXSIG] */
	long fltcount[PRMAXFAULT+1];	/* faults count [0..MAXFAULT] */
	struct syscount *syscount[PRMAXSYS+1];
	timestruc_t systotal;		/* total time spent in kernel */
	timestruc_t usrtotal;		/* total time spent in user mode */
	timestruc_t basetime;		/* base time for timestamps */
};

struct global_psinfo {
	mutex_t	fork_lock;		/* protects list of truss pids */
	cond_t	fork_cv;
	char p1[CACHE_LN_SZ - (sizeof (mutex_t) + sizeof (cond_t))];
	mutex_t ps_mutex0;		/* see ipc.c:Ecritical */
	char p2[CACHE_LN_SZ - sizeof (mutex_t)];
	mutex_t	ps_mutex1;		/* see ipc.c:Ecritical */
	char p3[CACHE_LN_SZ - sizeof (mutex_t)];
	pid_t	fork_pid;
	pid_t tpid[1000];	/* truss process pid */
	pid_t spid[1000];	/* subject process pid */
	const char *lwps[1000];	/* optional lwp list */
};

extern	struct counts *Cp;	/* for counting: malloc() or shared memory */
extern	struct global_psinfo *gps;	/* ptr to global_psinfo struct */

struct bkpt {		/* to describe one function's entry point */
	struct bkpt *next;	/* hash table linked list */
	char	*sym_name;	/* function name */
	struct dynlib *dyn;	/* enclosing library */
	uintptr_t addr;		/* function address, breakpointed */
	ulong_t	instr;		/* original instruction at addr */
	int	flags;		/* see below */
};
#define	BPT_HANG	0x01	/* leave stopped and abandoned when called */
#define	BPT_EXCLUDE	0x02	/* function found but is being excluded */
#define	BPT_INTERNAL	0x04	/* trace internal calls on this function */
#define	BPT_ACTIVE	0x08	/* function breakpoint is set in process */
#define	BPT_PREINIT	0x10	/* PREINIT event in ld.so.1 */
#define	BPT_POSTINIT	0x20	/* POSTINIT event in ld.so.1 */
#define	BPT_DLACTIVITY	0x40	/* DLACTIVITY event in ld.so.1 */
#define	BPT_TD_CREATE	0x80	/* TD_CREATE threading event */

struct dynlib {		/* structure for tracing functions */
	struct dynlib *next;
	char	*lib_name;	/* full library name */
	char	*match_name;	/* library name used in name matching */
	char	*prt_name;	/* library name for printing */
	int	built;		/* if true, bkpt list has been built */
	int	present;	/* true if library is still present */
	uintptr_t base;		/* library's mapping base */
	size_t	size;		/* library's mapping size */
};

struct dynpat {		/* structure specifying patterns for dynlib's */
	struct dynpat *next;
	const char **libpat;	/* array of patterns for library names */
	const char **sympat;	/* array of patterns for symbol names */
	int	nlibpat;	/* number of library patterns */
	int	nsympat;	/* number of symbol patterns */
	char	flag;		/* 0 or BPT_HANG */
	char	exclude_lib;	/* if true, exclude these libraries */
	char	exclude;	/* if true, exclude these functions */
	char	internal;	/* if true, trace internal calls */
	struct dynlib *Dp;	/* set to the dynlib instance when searching */
};

extern	struct dynlib *Dynlib;	/* for tracing functions in shared libraries */
extern	struct dynpat *Dynpat;
extern	struct dynpat *Lastpat;
extern	struct bkpt **bpt_hashtable;	/* breakpoint hash table */
extern	uint_t	nthr_create;	/* number of thr_create() calls seen so far */

struct callstack {
	struct callstack *next;
	uintptr_t stkbase;	/* stkbase < stkend */
	uintptr_t stkend;	/* stkend == base + size */
	prgreg_t tref;		/* %g7 (sparc) or %gs (intel) */
	id_t	tid;		/* thread-id */
	uint_t	nthr_create;	/* value of nthr_create last time we looked */
	uint_t	ncall;		/* number of elements in stack */
	uint_t	maxcall;	/* max elements in stack (malloc'd) */
	struct {
		uintptr_t sp;		/* %sp for function call */
		uintptr_t pc;		/* value of the return %pc */
		struct bkpt *fcn;	/* name of function called */
	} *stack;		/* pointer to the call stack info */
};

extern	struct callstack *callstack;	/* the callstack list */
extern	uint_t	nstack;			/* number of detected stacks */
extern	rd_agent_t *Rdb_agent;		/* run-time linker debug handle */
extern	td_thragent_t *Thr_agent;	/* thread debug handle */
extern	int	not_consist;	/* used while rebuilding breakpoint table */
extern	int	delete_library;	/* used while rebuilding breakpoint table */

extern	pid_t	ancestor;	/* top-level parent process id */
extern	int	descendent;	/* TRUE iff descendent of top level */
extern	int	is_vfork_child;	/* TRUE iff process is a vfork()ed child */

extern	int	ngrab;		/* number of pid's that were grabbed */

extern	struct ps_prochandle *Proc;	/* global reference to process */
extern	int	data_model;	/* PR_MODEL_LP64 or PR_MODEL_ILP32 */

extern	long	pagesize;	/* bytes per page; should be per-process */

extern	int	exit_called;	/* _exit() syscall was seen */

extern	lwpid_t	primary_lwp;	/* representative lwp on process grab */

extern	sysset_t syshang;	/* sys calls to make process hang */
extern	sigset_t sighang;	/* signals to make process hang */
extern	fltset_t flthang;	/* faults to make process hang */

extern	sigset_t emptyset;	/* no signals, for thr_sigsetmask() */
extern	sigset_t fillset;	/* all signals, for thr_sigsetmask() */

extern	int	leave_hung;	/* if TRUE, leave the process hung */


#ifdef	__cplusplus
}
#endif

#endif /* _RAMDATA_H */
