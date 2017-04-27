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
 * Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#ifndef _PRB_PROC_H
#define	_PRB_PROC_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Header file that gives the interfaces to the proc layer.  These are the
 * interfaces for "native" /proc i.e. when libtnfctl uses /proc directly
 * on the target process (tnfctl_exec_open() and tnfctl_pid_open())
 */

/*
 * Includes
 */

#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/procfs.h>
#include <sys/errno.h>
#include <signal.h>
#include <note.h>

#include <tnf/probe.h>

/*
 * Typedefs
 */

typedef enum prb_status {
	/* successful status */
	PRB_STATUS_OK = 0,

	/* errors */
	/*
	 * Status values in the range 1 to -1023 are reserved for mapping
	 * standard errno values.
	 */
	PRB_STATUS_MINERRNO = 1,	/* minimum errno value */
	PRB_STATUS_EAGAIN = EAGAIN,
	PRB_STATUS_MAXERRNO = 1023,	/* maximum errno value */

	PRB_STATUS_ALLOCFAIL,		/* memory allocation failed */
	PRB_STATUS_BADARG,		/* bad input argument */
	PRB_STATUS_BADSYNC,		/* couldn't sync with rtld */
	PRB_STATUS_BADLMAPSTATE		/* inconsistent link map */
} prb_status_t;

typedef enum prb_syscall_op {
	PRB_SYS_ALL,		/* turn on all system calls	 */
	PRB_SYS_NONE,		/* clears all system calls	 */
	PRB_SYS_ADD,		/* add a system call		 */
	PRB_SYS_DEL		/* delete a system call		 */
} prb_syscall_op_t;

/*
 * status of /proc file descriptor
 */
typedef struct prb_proc_state {
	boolean_t	ps_isstopped;
	boolean_t	ps_isinsys;
	boolean_t	ps_isrequested;
	boolean_t	ps_issysexit;
	boolean_t	ps_issysentry;
	boolean_t	ps_isbptfault;
	long		ps_syscallnum;
} prb_proc_state_t;

NOTE(SCHEME_PROTECTS_DATA("one thread per handle", prb_proc_state))

/*
 * Opaque /proc handle
 */
typedef struct prb_proc_ctl prb_proc_ctl_t;

/*
 * prb_dbgaddr() has to be called with the address of DT_DEBUG before
 * most other interfaces in the prb layer can be used.
 */
void		prb_dbgaddr(prb_proc_ctl_t *proc_p, uintptr_t dbgaddr);

/*
 * loadobject iteration callback specification
 * WARNING: keep this structure in sync with tnfctl_ind_obj_info_t
 */
typedef struct prb_loadobj {
	int			objfd;
	uintptr_t		text_base;
	uintptr_t		data_base;
	const char		*objname;
} prb_loadobj_t;

typedef int prb_loadobj_f(prb_proc_ctl_t *proc_p, const prb_loadobj_t *obj,
				void *calldata);
prb_status_t	prb_loadobj_iter(prb_proc_ctl_t *, prb_loadobj_f *, void *);
prb_status_t	prb_mainobj_get(prb_proc_ctl_t *proc_p, int *objfd,
						uintptr_t *baseaddr);

const char	*prb_status_str(prb_status_t prbstat);

pid_t		prb_proc_pid_get(prb_proc_ctl_t *proc_p);

/* rtld interfaces */
prb_status_t	prb_rtld_sync_if_needed(prb_proc_ctl_t *proc_p);
prb_status_t	prb_rtld_stalk(prb_proc_ctl_t *proc_p);
prb_status_t	prb_rtld_unstalk(prb_proc_ctl_t *proc_p);
prb_status_t	prb_rtld_advance(prb_proc_ctl_t *proc_p);

/* generic /proc wrapper interfaces */
prb_status_t	prb_proc_open(pid_t pid, prb_proc_ctl_t **proc_pp);
prb_status_t	prb_proc_reopen(pid_t pid, prb_proc_ctl_t **proc_pp);
prb_status_t	prb_proc_close(prb_proc_ctl_t *proc_p);
prb_status_t	prb_proc_stop(prb_proc_ctl_t *proc_p);
prb_status_t	prb_proc_wait(prb_proc_ctl_t *proc_p, boolean_t use_sigmask,
					sigset_t *oldmask);
prb_status_t	prb_proc_cont(prb_proc_ctl_t *proc_p);
prb_status_t	prb_proc_state(prb_proc_ctl_t *proc_p,
					prb_proc_state_t *state_p);
prb_status_t	prb_proc_setrlc(prb_proc_ctl_t *proc_p, boolean_t rlc);
prb_status_t	prb_proc_setklc(prb_proc_ctl_t *proc_p, boolean_t klc);
prb_status_t	prb_proc_exit(prb_proc_ctl_t *proc_p, uint_t syscall,
					prb_syscall_op_t op);
prb_status_t	prb_proc_entry(prb_proc_ctl_t *proc_p, uint_t syscall,
					prb_syscall_op_t op);
prb_status_t	prb_proc_read(prb_proc_ctl_t *proc_p, uintptr_t addr,
	void *buf, size_t size);
prb_status_t	prb_proc_write(prb_proc_ctl_t *proc_p, uintptr_t addr,
	void *buf, size_t size);
prb_status_t    prb_proc_setfork(prb_proc_ctl_t *proc_p, boolean_t inhfork);
prb_status_t	prb_proc_get_r0_r1(prb_proc_ctl_t *proc_p,
    prgreg_t *r0, prgreg_t *r1);

/* exec a child */
prb_status_t	prb_child_create(const char *cmdname, char * const *cmdargs,
	const char *loption, const char *libtnfprobe_path,
	char * const *envp, prb_proc_ctl_t **ret_val);

#ifdef __cplusplus
}
#endif

#endif	/* _PRB_PROC_H */
