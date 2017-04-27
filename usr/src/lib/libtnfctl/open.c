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

/*
 * Interfaces that return a tnfctl handle back to client (except for
 * tnfctl_internal_open()) and helper functions for these interfaces.
 * Also has buffer alloc, buffer dealloc, and trace attributes retrieval
 * interfaces.
 */

#include "tnfctl_int.h"
#include "kernel_int.h"
#include "dbg.h"

#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

static tnfctl_errcode_t attach_pid(pid_t pid, prb_proc_ctl_t **proc_pp);
static tnfctl_errcode_t step_to_end_of_exec(tnfctl_handle_t *hndl);

/*
 * invokes the target program and executes it till the run time linker (rtld)
 * has loaded in the shared objects (but before any .init sections are
 * executed).  Returns a pointer to a tnfctl handle.
 */
tnfctl_errcode_t
tnfctl_exec_open(const char *pgm_name, char * const *args,  char * const *envp,
    const char *ld_preload,
    const char *libtnfprobe_path,
    tnfctl_handle_t **ret_val)
{
	tnfctl_handle_t	*hdl;
	prb_proc_ctl_t	*proc_p = NULL;
	prb_status_t	prbstat;
	uintptr_t	dbgaddr;
	tnfctl_errcode_t	prexstat;

	prbstat = prb_child_create(pgm_name, args, ld_preload, libtnfprobe_path,
	    envp, &proc_p);
	if (prbstat) {
		return (_tnfctl_map_to_errcode(prbstat));
	}

	/* allocate hdl and zero fill */
	hdl = calloc(1, sizeof (*hdl));
	if (hdl == NULL) {
		(void) prb_proc_close(proc_p);
		return (TNFCTL_ERR_ALLOCFAIL);
	}

	hdl->proc_p = proc_p;
	hdl->mode = DIRECT_MODE;
	hdl->called_exit = B_FALSE;

	/* use native /proc on this target */
	hdl->p_read = _tnfctl_read_targ;
	hdl->p_write = _tnfctl_write_targ;
	hdl->p_obj_iter = _tnfctl_loadobj_iter;
	hdl->p_getpid = _tnfctl_pid_get;

	/*
	 * get the address of DT_DEBUG and send it in to prb_ layer.
	 * This is needed before before prb_rtld_sync() can be called.
	 */
	prexstat = _tnfctl_elf_dbgent(hdl, &dbgaddr);
	if (prexstat)
		goto failure_ret;

	prb_dbgaddr(proc_p, dbgaddr);

	/* sync up to rtld sync point */
	prbstat = prb_rtld_sync_if_needed(proc_p);
	if (prbstat) {
		prexstat = _tnfctl_map_to_errcode(prbstat);
		goto failure_ret;
	}

	/* initialize state in handle */
	prexstat = _tnfctl_set_state(hdl);
	if (prexstat)
		goto failure_ret;

	prexstat = _tnfctl_external_getlock(hdl);
	if (prexstat)
		goto failure_ret;

	*ret_val = hdl;
	/* Successful return */
	return (TNFCTL_ERR_NONE);

failure_ret:
	(void) prb_proc_close(proc_p);
	free(hdl);
	return (prexstat);
}


/*
 * attaches to a running process.  If the process is in the beginning
 * of an exec(2) system call (which is how tnfctl_continue() returns on exec),
 * it steps the process till the end of the the exec. If the process hasn't
 * reached the rtld sync point, the process is continued until it does
 * reach it.  Returns a pointer to a tnfctl handle.
 */
tnfctl_errcode_t
tnfctl_pid_open(pid_t pid, tnfctl_handle_t **ret_val)
{
	tnfctl_handle_t	*hdl;
	prb_proc_ctl_t	*proc_p = NULL;
	uintptr_t	dbgaddr;
	prb_status_t	prbstat;
	tnfctl_errcode_t	prexstat;

	prexstat = attach_pid(pid, &proc_p);
	if (prexstat) {
		return (prexstat);
	}

	/* allocate hdl and zero fill */
	hdl = calloc(1, sizeof (*hdl));
	if (hdl == NULL) {
		(void) prb_proc_close(proc_p);
		return (TNFCTL_ERR_ALLOCFAIL);
	}

	hdl->proc_p = proc_p;
	hdl->mode = DIRECT_MODE;
	hdl->called_exit = B_FALSE;

	/* use native /proc on this target */
	hdl->p_read = _tnfctl_read_targ;
	hdl->p_write = _tnfctl_write_targ;
	hdl->p_obj_iter = _tnfctl_loadobj_iter;
	hdl->p_getpid = _tnfctl_pid_get;

	/*
	 * Since tnfctl_continue() returns when a process does an exec
	 * and leaves the process stopped at the beginning of exec, we
	 * have to be sure to catch this case.
	 */
	prexstat = step_to_end_of_exec(hdl);
	/* proc_p could be side effected by step_to_end_of_exec() */
	proc_p = hdl->proc_p;
	if (prexstat)
		goto failure_ret;

	/*
	 * get the address of DT_DEBUG and send it in to prb_ layer.
	 */
	prexstat = _tnfctl_elf_dbgent(hdl, &dbgaddr);
	if (prexstat)
		goto failure_ret;

	prb_dbgaddr(proc_p, dbgaddr);

	/* sync up to rtld sync point if target is not there yet */
	prbstat = prb_rtld_sync_if_needed(proc_p);
	if (prbstat) {
		prexstat = _tnfctl_map_to_errcode(prbstat);
		goto failure_ret;
	}

	/* initialize state in handle */
	prexstat = _tnfctl_set_state(hdl);
	if (prexstat)
		goto failure_ret;

	/* set state in target indicating we're tracing externally */
	prexstat = _tnfctl_external_getlock(hdl);
	if (prexstat)
		goto failure_ret;

	*ret_val = hdl;

	/* Sucessful return */
	return (TNFCTL_ERR_NONE);

failure_ret:
	(void) prb_proc_close(proc_p);
	free(hdl);
	return (prexstat);
}

/*
 * open a process for tracing without using native /proc on it.  The client
 * provides a set of callback functions which encapsulate the /proc
 * functionality we need.  Returns a pointer to a tnfctl handle.
 */
tnfctl_errcode_t
tnfctl_indirect_open(void *prochandle, tnfctl_ind_config_t *config,
    tnfctl_handle_t **ret_val)
{
	tnfctl_handle_t	*hdl;
	tnfctl_errcode_t	prexstat;

	/* allocate hdl and zero fill */
	hdl = calloc(1, sizeof (*hdl));
	if (hdl == NULL) {
		return (TNFCTL_ERR_ALLOCFAIL);
	}

	hdl->proc_p = prochandle;
	hdl->mode = INDIRECT_MODE;
	hdl->called_exit = B_FALSE;

	/* initialize callback functions */
	hdl->p_read = config->p_read;
	hdl->p_write = config->p_write;
	hdl->p_obj_iter = config->p_obj_iter;
	hdl->p_getpid = config->p_getpid;

	/* initialize state in handle */
	prexstat = _tnfctl_set_state(hdl);
	if (prexstat) {
		free(hdl);
		return (prexstat);
	}
	/* set state in target indicating we're tracing externally */
	prexstat = _tnfctl_external_getlock(hdl);
	if (prexstat) {
		free(hdl);
		return (prexstat);
	}
	*ret_val = hdl;
	return (TNFCTL_ERR_NONE);
}

/*
 * Returns a pointer to a tnfctl handle that can do kernel trace control
 * and kernel probe control.
 */
tnfctl_errcode_t
tnfctl_kernel_open(tnfctl_handle_t **ret_val)
{
	tnfctl_handle_t	*hdl;
	tnfctl_errcode_t	prexstat;

	/* allocate hdl and zero fill */
	hdl = calloc(1, sizeof (*hdl));
	if (hdl == NULL) {
		return (TNFCTL_ERR_ALLOCFAIL);
	}

	/* initialize kernel tracing */
	prexstat = _tnfctl_prbk_init(hdl);
	if (prexstat)
		return (prexstat);

	hdl->mode = KERNEL_MODE;
	hdl->targ_pid = 0;

	/* initialize function pointers that can be stuffed into a probe */
	_tnfctl_prbk_get_other_funcs(&hdl->allocfunc, &hdl->commitfunc,
	    &hdl->rollbackfunc, &hdl->endfunc);
	_tnfctl_prbk_test_func(&hdl->testfunc);

	/* find the probes in the kernel */
	prexstat = _tnfctl_refresh_kernel(hdl);
	if (prexstat)
		return (prexstat);

	*ret_val = hdl;
	return (TNFCTL_ERR_NONE);
}

/*
 * Returns the trace attributes to the client.  Since there can be
 * only one controlling agent on a target at a time, our cached information
 * is correct and we don't have to actually retrieve any information
 * from the target.
 */
tnfctl_errcode_t
tnfctl_trace_attrs_get(tnfctl_handle_t *hdl, tnfctl_trace_attrs_t *attrs)
{
	boolean_t		release_lock;
	tnfctl_errcode_t	prexstat;

	/*LINTED statement has no consequent: else*/
	LOCK_SYNC(hdl, prexstat, release_lock);

	attrs->targ_pid = hdl->targ_pid;
	attrs->trace_file_name = hdl->trace_file_name;
	attrs->trace_buf_size = hdl->trace_buf_size;
	attrs->trace_min_size = hdl->trace_min_size;
	attrs->trace_buf_state = hdl->trace_buf_state;
	attrs->trace_state = hdl->trace_state;
	attrs->filter_state = hdl->kpidfilter_state;

	/*LINTED statement has no consequent: else*/
	UNLOCK(hdl, release_lock);

	return (TNFCTL_ERR_NONE);
}


/*
 * Allocate a trace buffer of the specified name and size.
 */
tnfctl_errcode_t
tnfctl_buffer_alloc(tnfctl_handle_t *hdl, const char *trace_file_name,
    uint_t trace_file_size)
{
	tnfctl_errcode_t prexstat;

	if (hdl->mode == KERNEL_MODE) {
		/* trace_file_name is ignored in kernel mode */
		prexstat = _tnfctl_prbk_buffer_alloc(hdl, trace_file_size);
		if (prexstat)
			return (prexstat);
		return (TNFCTL_ERR_NONE);
	}

	/* Not KERNEL_MODE */
	if (hdl->trace_file_name != NULL) {
		/* buffer already allocated */
		return (TNFCTL_ERR_BUFEXISTS);
	}

	prexstat = _tnfctl_create_tracefile(hdl, trace_file_name,
	    trace_file_size);
	if (prexstat) {
		return (prexstat);
	}

	return (TNFCTL_ERR_NONE);
}

/*
 * Deallocate the trace buffer - only works for kernel mode
 */
tnfctl_errcode_t
tnfctl_buffer_dealloc(tnfctl_handle_t *hdl)
{
	tnfctl_errcode_t prexstat;

	if (hdl->mode != KERNEL_MODE)
		return (TNFCTL_ERR_BADARG);

	/* KERNEL_MODE */
	prexstat = _tnfctl_prbk_buffer_dealloc(hdl);
	if (prexstat)
		return (prexstat);
	return (TNFCTL_ERR_NONE);
}


/*
 * Helper function for attaching to a target process
 */
static tnfctl_errcode_t
attach_pid(pid_t pid, prb_proc_ctl_t **proc_pp)
{
	prb_status_t	prbstat;
	prb_proc_ctl_t	*proc_p;

	if (getpid() == pid)
		return (TNFCTL_ERR_BADARG);

	/* check if pid is valid */
	if ((kill(pid, 0) == -1) && errno == ESRCH) {
		return (TNFCTL_ERR_NOPROCESS);
	}
	/* open up /proc fd */
	prbstat = prb_proc_open(pid, proc_pp);
	if (prbstat)
		return (_tnfctl_map_to_errcode(prbstat));

	proc_p = *proc_pp;
	/*
	 * default is to run-on-last-close.  In case we cannot sync with
	 * target, we don't want to kill the target.
	 */
	prbstat = prb_proc_setrlc(proc_p, B_TRUE);
	if (prbstat)
		goto failure_ret;
	prbstat = prb_proc_setklc(proc_p, B_FALSE);
	if (prbstat)
		goto failure_ret;

	/* stop process */
	prbstat = prb_proc_stop(proc_p);
	if (prbstat)
		goto failure_ret;

	/* Sucessful return */
	return (TNFCTL_ERR_NONE);

failure_ret:
	(void) prb_proc_close(proc_p);
	return (_tnfctl_map_to_errcode(prbstat));
}

/*
 * Checks if target is at the beginning of an exec system call.  If so,
 * it runs it till the end of the exec system call.  It takes care of
 * the case where you're about to exec a setuid program.
 * CAUTION: could side effect hndl->proc_p
 */
static tnfctl_errcode_t
step_to_end_of_exec(tnfctl_handle_t *hndl)
{
	prb_proc_ctl_t	*proc_p, *oldproc_p;
	prb_status_t	prbstat, tempstat;
	int		pid;
	prb_proc_state_t	pstate;

	proc_p = hndl->proc_p;
	pid = hndl->p_getpid(proc_p);

	prbstat = prb_proc_state(proc_p, &pstate);
	if (prbstat)
		return (_tnfctl_map_to_errcode(prbstat));
	if (!(pstate.ps_issysentry && pstate.ps_syscallnum == SYS_execve)) {
		/* not stopped at beginning of exec system call */
		return (TNFCTL_ERR_NONE);
	}

	/* we are stopped at beginning of exec system call */

	prbstat = prb_proc_exit(proc_p, SYS_execve, PRB_SYS_ADD);
	if (prbstat)
		return (_tnfctl_map_to_errcode(prbstat));

	prbstat = prb_proc_cont(proc_p);
	if (prbstat)
		return (_tnfctl_map_to_errcode(prbstat));

	prbstat = prb_proc_wait(proc_p, B_FALSE, NULL);
	switch (prbstat) {
	case PRB_STATUS_OK:
		break;
	case PRB_STATUS_EAGAIN:
		/*
		 * If we had exec'ed a setuid/setgid program PIOCWSTOP
		 * will return EAGAIN.  Reopen the 'fd' and try again.
		 * Read the last section of /proc man page - we reopen first
		 * and then close the old fd.
		 */
		oldproc_p = proc_p;
		tempstat = prb_proc_reopen(pid, &proc_p);
		if (tempstat) {
			/* here EACCES means exec'ed a setuid/setgid program */
			return (_tnfctl_map_to_errcode(tempstat));
		}

		prb_proc_close(oldproc_p);
		hndl->proc_p = proc_p;
		break;
	default:
		return (_tnfctl_map_to_errcode(prbstat));
	}

	prbstat = prb_proc_state(proc_p, &pstate);
	if (prbstat)
		return (_tnfctl_map_to_errcode(prbstat));

	if (!(pstate.ps_issysexit && pstate.ps_syscallnum == SYS_execve)) {
		/* unexpected condition */
		return (tnfctl_status_map(ENOENT));
	}

	/* clear old interest mask */
	prbstat = prb_proc_exit(proc_p, SYS_execve, PRB_SYS_DEL);
	if (prbstat)
		return (_tnfctl_map_to_errcode(prbstat));
	return (TNFCTL_ERR_NONE);
}


tnfctl_errcode_t
_tnfctl_external_getlock(tnfctl_handle_t *hdl)
{

	tnfctl_errcode_t	prexstat;
	prb_status_t		prbstat;
	uintptr_t		targ_symbol_ptr;
	int			internal_tracing_on;

	prexstat = _tnfctl_sym_find(hdl, TNFCTL_INTERNAL_TRACEFLAG,
	    &targ_symbol_ptr);
	if (prexstat) {
	/* no libtnfctl in target: success */
	return (TNFCTL_ERR_NONE);
	}
	prbstat = hdl->p_read(hdl->proc_p, targ_symbol_ptr,
	    &internal_tracing_on, sizeof (internal_tracing_on));

	if (prbstat) {
	prexstat = _tnfctl_map_to_errcode(prbstat);
	goto failure_ret;
	}
	if (internal_tracing_on) {
	/* target process being traced internally */
	prexstat = TNFCTL_ERR_BUSY;
	goto failure_ret;
	}
	prexstat = _tnfctl_sym_find(hdl, TNFCTL_EXTERNAL_TRACEDPID,
	    &targ_symbol_ptr);
	if (prexstat) {
	/* this shouldn't happen. we know we have libtnfctl */
	goto failure_ret;
	}
	prbstat = hdl->p_write(hdl->proc_p, targ_symbol_ptr,
	    &(hdl->targ_pid), sizeof (hdl->targ_pid));
	if (prbstat) {
	prexstat = _tnfctl_map_to_errcode(prbstat);
	goto failure_ret;
	}
	/* success */
	DBG((void) fprintf(stderr, "_tnfctl_external_getlock: ok to trace %d\n",
	    hdl->targ_pid));
	return (TNFCTL_ERR_NONE);

failure_ret:
	return (prexstat);
}
