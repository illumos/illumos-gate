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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Utility functions to initialize tnfctl handle, find functions that
 * can be plugged into probes, find trace file information, and create
 * a trace file for process tracing.
 */

#ifndef DEBUG
#define	NDEBUG	1
#endif

#include "tnfctl_int.h"
#include "dbg.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/param.h>

#include "tnf_buf.h"
/*
 * Defines - Project private interfaces in libtnfprobe.so
 */

#define	TRACEFILE_NAME		"tnf_trace_file_name"
#define	TRACEFILE_SIZE		"tnf_trace_file_size"
#define	TRACEFILE_MIN		"tnf_trace_file_min"
#define	TRACE_ERROR		"_tnfw_b_control"

#define	TRACE_ALLOC		"tnf_trace_alloc"
#define	TRACE_COMMIT		"tnf_trace_commit"
#define	TRACE_ROLLBACK		"tnf_trace_rollback"
#define	DEBUG_ENTRY		"tnf_probe_debug"

#define	PROBE_LIST_HEAD		"__tnf_probe_list_head"
#define	PROBE_LIST_VALID	"__tnf_probe_list_valid"

#define	NONTHREAD_TEST		"tnf_non_threaded_test_addr"
#define	THREAD_TEST		"tnf_threaded_test_addr"
#define	PROBE_THR_SYNC		"__tnf_probe_thr_sync"

#define	MEMSEG_PTR		"__tnf_probe_memseg_p"

/* Project private interfaces in libthread.so */
#define	LIBTHREAD_PRESENT	"thr_probe_getfunc_addr"

/*
 * Local declarations
 */

static tnfctl_errcode_t find_test_func(tnfctl_handle_t *hndl);
static tnfctl_errcode_t find_target_syms(tnfctl_handle_t *hndl);
static tnfctl_errcode_t find_trace_file_info(tnfctl_handle_t *hndl);
static tnfctl_errcode_t check_trace_error(tnfctl_handle_t *hndl);

/*
 * _tnfctl_refresh_process() - search for new shared objects.  If any
 * found, discover probes in new shared objects.
 *	NOT to be called in kernel mode.
 */

tnfctl_errcode_t
_tnfctl_refresh_process(tnfctl_handle_t *hndl, boolean_t *lmap_ok,
			enum event_op_t *dl_evt)
{
	tnfctl_errcode_t	prexstat = TNFCTL_ERR_NONE;
	boolean_t	release_lock;

	assert(hndl->mode != KERNEL_MODE);

	/*LINTED statement has no consequent: else*/
	LOCK(hndl, prexstat, release_lock);

	prexstat = check_trace_error(hndl);
	if (prexstat)
		goto finish_func;

	/*
	 * update the link map. caller decides what to do on
	 * inconsistent link map
	 */
	prexstat = _tnfctl_lmap_update(hndl, lmap_ok, dl_evt);
	if (prexstat)
		goto finish_func;

	/* link map is ok now */
	prexstat = find_test_func(hndl);
	if (prexstat)
		goto finish_func;
	if (*dl_evt != EVT_NONE) {
		prexstat = _tnfctl_find_all_probes(hndl);
		if (prexstat)
			goto finish_func;
	}

finish_func:
	/*LINTED statement has no consequent: else*/
	UNLOCK(hndl, release_lock);

	return (prexstat);
}

/*
 * initialize tnfctl handle for a new target
 */
tnfctl_errcode_t
_tnfctl_set_state(tnfctl_handle_t *hndl)
{
	tnfctl_errcode_t	prexstat = TNFCTL_ERR_NONE;
	boolean_t	lmap_ok;
	enum event_op_t	dl_evt;
	boolean_t	release_lock;

	hndl->targ_pid = hndl->p_getpid(hndl->proc_p);

	/*LINTED statement has no consequent: else*/
	LOCK(hndl, prexstat, release_lock);

	/*
	 * initialize the link map table. If link map is not ok, it is an
	 * error.
	 */
	prexstat = _tnfctl_lmap_update(hndl, &lmap_ok, &dl_evt);
	if (prexstat)
		goto end_func;

	/* find the needed target symbols */
	prexstat = find_target_syms(hndl);
	if (prexstat) {
		/* is libtnfprobe.so loaded in target ? */
		goto end_func;
	}

	prexstat = find_trace_file_info(hndl);
	if (prexstat)
		goto end_func;

	prexstat = find_test_func(hndl);
	if (prexstat)
		goto end_func;

	prexstat = _tnfctl_find_all_probes(hndl);
	if (prexstat)
		goto end_func;

	prexstat = check_trace_error(hndl);
	/* fall into end_func */

end_func:
	/*LINTED statement has no consequent: else*/
	UNLOCK(hndl, release_lock);

	return (prexstat);
}

/*
 * find the test function for a probe.  The test function could change
 * with time, so we have to repeatedly check for the test function to use
 */
static tnfctl_errcode_t
find_test_func(tnfctl_handle_t *hndl)
{
	long		thr_sync;
	int		miscstat;

	if (hndl->mt_target == B_FALSE) {
		/* no libthread linked in */
		hndl->testfunc = hndl->nonthread_test;
	} else {
		/*
		 * check whether libthread/libtnfw have synced up.
		 * If not yet synced up, use non-threaded test function
		 */

		/* assume we are going to use threaded test */
		hndl->testfunc = hndl->thread_test;
		miscstat = hndl->p_read(hndl->proc_p, hndl->thread_sync,
			&thr_sync, sizeof (thr_sync));
		if (miscstat != 0)
			return (TNFCTL_ERR_INTERNAL);
		/* if not yet synced up, change test func to non-threaded one */
		if (thr_sync == 0) {
			hndl->testfunc = hndl->nonthread_test;
		}
	}

	/*
	 * Note: the testfunc in the target can change underneath us because
	 * in an MT program the init section of libthread changes all the
	 * test functions from the non-threaded one to the threaded one.
	 * So, every time we write out a probe, we have to make sure that
	 * we are using the correct test function by not trusting the test
	 * function in our copy of the probe.  A more fool-proof solution
	 * which will allow other fields in the probe to change internally
	 * is to refresh every probe on a _tnfctl_refresh_process()
	 */
	return (TNFCTL_ERR_NONE);
}

/*
 * check_trace_error() - checks whether there was an error in tracing
 *	side effects trace_buf_state and trace_state in hndl
 *	note: call this function only after trace_file_name is set up
 *	in hndl
 */
tnfctl_errcode_t
check_trace_error(tnfctl_handle_t *hndl)
{
	int		miscstat;
	uintptr_t	trace_error_ptr;
	TNFW_B_CONTROL	trace_error_rec;

	/* read in the value of the control structure pointer */
	miscstat = hndl->p_read(hndl->proc_p, hndl->trace_error,
		&trace_error_ptr, sizeof (trace_error_ptr));
	if (miscstat != 0)
		return (TNFCTL_ERR_INTERNAL);

	/* read in the value of the control structure */
	miscstat = hndl->p_read(hndl->proc_p, trace_error_ptr, &trace_error_rec,
		sizeof (trace_error_rec));
	if (miscstat != 0)
		return (TNFCTL_ERR_INTERNAL);

	if (trace_error_rec.tnf_state == TNFW_B_NOBUFFER) {
		/*
		 * massage into correct state for caller - the target might
		 * not have hit the first probe and hence we got "no buffer".
		 * So, if the user had given a file name, return BUF_OK.
		 */
		if (hndl->trace_file_name == NULL)
			hndl->trace_buf_state = TNFCTL_BUF_NONE;
		else
			hndl->trace_buf_state = TNFCTL_BUF_OK;
	} else if (trace_error_rec.tnf_state == TNFW_B_BROKEN) {
		hndl->trace_buf_state = TNFCTL_BUF_BROKEN;
	} else {
		hndl->trace_buf_state = TNFCTL_BUF_OK;
	}

	if (TNFW_B_IS_STOPPED(trace_error_rec.tnf_state))
		hndl->trace_state = B_FALSE;
	else
		hndl->trace_state = B_TRUE;

	return (TNFCTL_ERR_NONE);

}				/* end find_alloc_func */

/*
 * find_target_syms() - finds needed target functions
 * 	sideffects allocfunc, commitfunc, endfunc, rollbackfunc in hndl
 */
static tnfctl_errcode_t
find_target_syms(tnfctl_handle_t *hndl)
{
	tnfctl_errcode_t	prexstat;
	uintptr_t		temp_addr;
	int			miscstat;

	prexstat = _tnfctl_sym_find(hndl, TRACE_ALLOC, &hndl->allocfunc);
	if (prexstat)
		goto end_of_func;

	prexstat = _tnfctl_sym_find(hndl, TRACE_COMMIT, &hndl->commitfunc);
	if (prexstat)
		goto end_of_func;

	prexstat = _tnfctl_sym_find(hndl, TRACE_END_FUNC, &hndl->endfunc);
	if (prexstat)
		goto end_of_func;

	prexstat = _tnfctl_sym_find(hndl, TRACE_ROLLBACK, &hndl->rollbackfunc);
	if (prexstat)
		goto end_of_func;

	prexstat = _tnfctl_sym_find(hndl, PROBE_LIST_HEAD,
					&hndl->probelist_head);
	if (prexstat)
		goto end_of_func;

	prexstat = _tnfctl_sym_find(hndl, TRACE_ERROR, &hndl->trace_error);
	if (prexstat)
		goto end_of_func;

	prexstat = _tnfctl_sym_find(hndl, MEMSEG_PTR, &temp_addr);
	if (prexstat)
		goto end_of_func;

	/* dereference to get the actual address of structure */
	miscstat = hndl->p_read(hndl->proc_p, temp_addr, &hndl->memseg_p,
			sizeof (hndl->memseg_p));
	if (miscstat != 0)
		return (TNFCTL_ERR_INTERNAL);

	prexstat = _tnfctl_sym_find(hndl, PROBE_LIST_VALID,
					&hndl->probelist_valid);
	if (prexstat)
		goto end_of_func;

	prexstat = _tnfctl_sym_find(hndl, NONTHREAD_TEST, &temp_addr);
	if (prexstat)
		goto end_of_func;

	/* dereference to get the actual function address */
	miscstat = hndl->p_read(hndl->proc_p, temp_addr, &hndl->nonthread_test,
			sizeof (hndl->nonthread_test));
	if (miscstat != 0)
		return (TNFCTL_ERR_INTERNAL);

	prexstat = _tnfctl_sym_find(hndl, THREAD_TEST, &temp_addr);
	if (prexstat)
		goto end_of_func;

	/* dereference to get the actual function address */
	miscstat = hndl->p_read(hndl->proc_p, temp_addr, &hndl->thread_test,
			sizeof (hndl->thread_test));
	if (miscstat != 0)
		return (TNFCTL_ERR_INTERNAL);

	prexstat = _tnfctl_sym_find(hndl, PROBE_THR_SYNC, &hndl->thread_sync);
	if (prexstat)
		goto end_of_func;

	prexstat = _tnfctl_sym_find(hndl, LIBTHREAD_PRESENT, &temp_addr);
	if (prexstat) {
		if (prexstat == TNFCTL_ERR_BADARG) {
			/* no libthread linked in */
			hndl->mt_target = B_FALSE;
			/* this is not an error condition */
			prexstat = TNFCTL_ERR_NONE;
		} else {
			return (prexstat);
		}
	} else {
		hndl->mt_target = B_TRUE;
	}

end_of_func:
	if (prexstat == TNFCTL_ERR_BADARG)
		prexstat = TNFCTL_ERR_NOLIBTNFPROBE;

	return (prexstat);
}

/*
 * _tnfctl_create_tracefile() - initializes tracefile, sets the tracefile name
 *	and size
 *	side effects trace_file_name and trace_buf_size in hndl
 */

#define	ZBUFSZ		(64 * 1024)

tnfctl_errcode_t
_tnfctl_create_tracefile(tnfctl_handle_t *hndl, const char *trace_file_name,
			uint_t trace_file_size)
{
	char		*preexisting;
	tnfctl_errcode_t	prexstat;
	int		miscstat;
	char		path[MAXPATHLEN];
	uintptr_t	name_addr, size_addr;
	uint_t		outsize;
	char		zerobuf[ZBUFSZ];
	int		fd, sz, i;

	/* find the neccessary symbols in the target */
	prexstat = _tnfctl_sym_find(hndl, TRACEFILE_NAME, &name_addr);
	if (prexstat) {
		if (prexstat == TNFCTL_ERR_BADARG)
			prexstat = TNFCTL_ERR_INTERNAL;
		return (prexstat);
	}
	prexstat = _tnfctl_sym_find(hndl, TRACEFILE_SIZE, &size_addr);
	if (prexstat) {
		if (prexstat == TNFCTL_ERR_BADARG)
			prexstat = TNFCTL_ERR_INTERNAL;
		return (prexstat);
	}

	/* Double check that a file name doesn't already exist */
	preexisting = NULL;
	prexstat = _tnfctl_readstr_targ(hndl, name_addr, &preexisting);
	if (prexstat) {
		if (preexisting)
			free(preexisting);
		return (prexstat);
	}

	/* There better not be a file name there yet */
	assert(preexisting[0] == '\0');

	/* paranoia - for optimized compilation */
	if (preexisting[0] != '\0')
		return (TNFCTL_ERR_BUFEXISTS);

	/* free memory in preexisting string */
	if (preexisting)
		free(preexisting);

	if (trace_file_size < hndl->trace_min_size) {
		return (TNFCTL_ERR_SIZETOOSMALL);
	}

	/* do we have an absolute, relative or no pathname specified? */
	if (trace_file_name == NULL) {
		return (TNFCTL_ERR_BADARG);
	}
	if (trace_file_name[0] == '/') {
		/* absolute path to tracefile specified */
		if ((strlen(trace_file_name) + 1) > (size_t) MAXPATHLEN) {
			/* directory specification too long */
			return (TNFCTL_ERR_BADARG);
		}
		(void) strcpy(path, trace_file_name);
	} else {
		char		   *cwd;

		/* relative path to tracefile specified */
		cwd = getcwd(NULL, MAXPATHLEN);
		if (!cwd) {
			return (tnfctl_status_map(errno));
		}
		if ((strlen(cwd) + 1 + strlen(trace_file_name) + 1) >
			(size_t) MAXPATHLEN) {
			/* path name too long */
			return (TNFCTL_ERR_BADARG);
		}
		(void) sprintf(path, "%s/%s", cwd, trace_file_name);

		free(cwd);
	}

	outsize = trace_file_size;

	DBG_TNF_PROBE_2(_tnfctl_create_tracefile_1, "libtnfctl",
		"sunw%verbosity 1; sunw%debug 'setting trace file name'",
		tnf_string, tracefile_name, path,
		tnf_long, tracefile_size, outsize);

	/* unlink a previous tracefile (if one exists) */
	(void) unlink(path);

	/* create the new tracefile */
	fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0)	{
		return (tnfctl_status_map(errno));
	}

	/* zero fill the file */
	(void) memset(zerobuf, 0, ZBUFSZ);
	sz = ZBUFSZ;
	for (i = 0; i < outsize; i += sz) {
		ulong_t		retval;

		sz = ((outsize - i) > ZBUFSZ) ? ZBUFSZ : (outsize - i);
		retval = write(fd, zerobuf, sz);
		if (retval != sz) {
			/* trouble zeroing tracefile */
			return (tnfctl_status_map(errno));
		}
	}

	/* close the file */
	(void) close(fd);

	/* write the tracefile name and size into the target process */
	miscstat = hndl->p_write(hndl->proc_p, name_addr, path,
					strlen(path) + 1);
	if (miscstat != 0)
		return (TNFCTL_ERR_INTERNAL);
	miscstat = hndl->p_write(hndl->proc_p, size_addr, &outsize,
					sizeof (outsize));
	if (miscstat != 0)
		return (TNFCTL_ERR_INTERNAL);

	hndl->trace_file_name = strdup(path);
	if (hndl->trace_file_name == NULL)
		return (TNFCTL_ERR_ALLOCFAIL);
	hndl->trace_buf_size = outsize;
	hndl->trace_buf_state = TNFCTL_BUF_OK;
	return (TNFCTL_ERR_NONE);
}				/* end _tnfctl_create_tracefile */

/*
 * find_trace_file_info()
 *	finds out information about the trace file.
 *	side effects trace_buf_size, trace_min_size, trace_file_name in hndl
 */

static tnfctl_errcode_t
find_trace_file_info(tnfctl_handle_t *hndl)
{
	tnfctl_errcode_t	prexstat;
	int		miscstat;
	char		*preexisting;
	uintptr_t	name_addr, size_addr, min_addr;
	uint_t		outsize, minoutsize;

	/* find the neccessary symbols in the target */
	prexstat = _tnfctl_sym_find(hndl, TRACEFILE_NAME, &name_addr);
	if (prexstat) {
		if (prexstat == TNFCTL_ERR_BADARG)
			prexstat = TNFCTL_ERR_INTERNAL;
		return (prexstat);
	}
	prexstat = _tnfctl_sym_find(hndl, TRACEFILE_SIZE, &size_addr);
	if (prexstat) {
		if (prexstat == TNFCTL_ERR_BADARG)
			prexstat = TNFCTL_ERR_INTERNAL;
		return (prexstat);
	}
	prexstat = _tnfctl_sym_find(hndl, TRACEFILE_MIN, &min_addr);
	if (prexstat) {
		if (prexstat == TNFCTL_ERR_BADARG)
			prexstat = TNFCTL_ERR_INTERNAL;
		return (prexstat);
	}

	/* read file name */
	preexisting = NULL;
	prexstat = _tnfctl_readstr_targ(hndl, name_addr, &preexisting);
	if (prexstat) {
		if (preexisting)
			free(preexisting);
		return (prexstat);
	}

	/* read the minimum file size from the target */
	miscstat = hndl->p_read(hndl->proc_p, min_addr, &minoutsize,
							sizeof (minoutsize));
	if (miscstat != 0)
		return (TNFCTL_ERR_INTERNAL);
	hndl->trace_min_size = minoutsize;

	/* if there is no filename, we are done */
	if (preexisting[0] == '\0') {
		hndl->trace_file_name = NULL;
		hndl->trace_buf_size = 0;
	} else {
		hndl->trace_file_name = preexisting;
		/* read size of file */
		miscstat = hndl->p_read(hndl->proc_p, size_addr,
				&outsize, sizeof (outsize));
		if (miscstat != 0)
			return (TNFCTL_ERR_INTERNAL);
		hndl->trace_buf_size = outsize;
	}

	return (TNFCTL_ERR_NONE);
}				/* end find_trace_file_info */

/*
 * wrapper functions over native /proc functions implemented by proc
 * layer
 */
int
_tnfctl_read_targ(void *proc_p, uintptr_t addr, void *buf, size_t size)
{
	return (prb_proc_read(proc_p, addr, buf, size));
}

int
_tnfctl_write_targ(void *proc_p, uintptr_t addr, void *buf, size_t size)
{
	return (prb_proc_write(proc_p, addr, buf, size));
}

int
_tnfctl_loadobj_iter(void *proc_p, tnfctl_ind_obj_f *func, void *client_data)
{
	prb_loadobj_f *same_func = (prb_loadobj_f *) func;

	return (prb_loadobj_iter(proc_p, same_func, client_data));
}

pid_t
_tnfctl_pid_get(void *proc_p)
{
	return (prb_proc_pid_get(proc_p));
}

/*
 * _tnfctl_readstr_targ() - dereferences a string in the target
 * 	NOTE: There is a similar routine called prb_proc_readstr()
 *	      used by proc layer.  It would be better if there was only
 *	      one of these functions defined.
 */

#define	BUFSZ	256

tnfctl_errcode_t
_tnfctl_readstr_targ(tnfctl_handle_t *hndl, uintptr_t addr, char **outstr_pp)
{
	int		retstat;
	int		bufsz = BUFSZ;
	char		buffer[BUFSZ + 1];
	offset_t	offset;
	char		*ptr, *orig_ptr;

	*outstr_pp = NULL;
	offset = 0;

	/* allocate an inital return buffer */
	ptr = (char *) malloc(BUFSZ);
	if (!ptr) {
		DBG((void) fprintf(stderr,
			"_tnfctl_readstr_targ: malloc failed\n"));
		return (TNFCTL_ERR_ALLOCFAIL);
	}
	/*LINTED constant in conditional context*/
	while (1) {
		int			 i;

		/* read a chunk into our buffer */
		retstat = hndl->p_read(hndl->proc_p, addr + offset, buffer,
								bufsz);
		if (retstat != 0) {

			/*
			 * if we get into trouble with a large read, try again
			 * with a single byte.  Subsequent failiure is real ...
			 */
			if (bufsz > 1) {
				bufsz = 1;
				continue;
			}

			DBG((void) fprintf(stderr,
			    "_tnfctl_readstr_targ: target read failed: \n"));
			free(ptr);
			return (TNFCTL_ERR_INTERNAL);
		}
		/* copy the chracters into the return buffer */
		for (i = 0; i < bufsz; i++) {
			char			c = buffer[i];

			ptr[offset + i] = c;
			if (c == '\0') {
				/* hooray! we saw the end of the string */
				*outstr_pp = ptr;
				return (TNFCTL_ERR_NONE);
			}
		}

		/* bummer, need to grab another bufsz characters */
		offset += bufsz;
		orig_ptr = ptr;
		ptr = (char *) realloc(ptr, offset + bufsz);
		if (!ptr) {
			free(orig_ptr);
			DBG((void) fprintf(stderr,
				"_tnfctl_readstr_targ: realloc failed\n"));
			return (TNFCTL_ERR_ALLOCFAIL);
		}
	}

#if defined(lint)
	return (TNFCTL_ERR_NONE);
#endif

}
