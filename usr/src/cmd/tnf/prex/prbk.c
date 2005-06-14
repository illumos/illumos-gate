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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>	/* for strerror() */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/tnf.h>
#include <fcntl.h>
#include <errno.h>
#include <locale.h>

#include "prbk.h"

#include <tnf/tnfctl.h>

extern tnfctl_handle_t *g_hndl;

typedef struct _pidlist {
	pid_t pid;
	struct _pidlist *next;
} pidlist_t;

static boolean_t check_kernelmode(tnfctl_trace_attrs_t *attrs_p);

static boolean_t
check_kernelmode(tnfctl_trace_attrs_t *attrs_p)
{
	extern int g_kernelmode;
	tnfctl_errcode_t err;

	if (!g_kernelmode) {
		(void) fprintf(stderr, gettext(
			"This command is only available "
			"in kernel mode (prex invoked with the -k flag)\n"));
		return (B_TRUE);
	}
	if (attrs_p) {
		err = tnfctl_trace_attrs_get(g_hndl, attrs_p);
		if (err) {
			(void) fprintf(stderr, gettext(
				"error on checking trace attributes : %s\n"),
				tnfctl_strerror(err));
			return (B_TRUE);
		}
	}
	return (B_FALSE);
}

/*
 * Print trace buffer status (is one allocated, and if so, how big is it.
 */
void
prbk_buffer_list()
{
	tnfctl_trace_attrs_t	attrs;

	if (check_kernelmode(&attrs))
		return;
	if (attrs.trace_buf_state == TNFCTL_BUF_NONE) {
		(void) printf(gettext("No trace buffer allocated\n"));
	} else {
		(void) printf(gettext("Trace buffer size is %d bytes\n"),
			attrs.trace_buf_size);
		if (attrs.trace_buf_state == TNFCTL_BUF_BROKEN) {
			(void) printf(gettext("Tracing system has failed -- "
				"tracing suspended\n"));
		}
	}
}


/*
 * Allocate a trace buffer.  Check for reasonable size; reject if there's
 * already a buffer.
 */
void
prbk_buffer_alloc(int size)
{
	tnfctl_errcode_t	err;
	tnfctl_trace_attrs_t	attrs;

	if (check_kernelmode(&attrs))
		return;

	if (attrs.trace_buf_state != TNFCTL_BUF_NONE) {
		(void) fprintf(stderr,
			gettext("There is already a buffer allocated\n"));
		return;
	}
	if (size < attrs.trace_min_size) {
		(void) fprintf(stderr, gettext(
			"Size %d is less than the minimum buffer size of %d -- "
			"buffer size set to %d bytes\n"),
			size, attrs.trace_min_size, attrs.trace_min_size);
		size = attrs.trace_min_size;
	}

	err = tnfctl_buffer_alloc(g_hndl, NULL, size);
	if (err) {
		(void) fprintf(stderr,
			gettext("error in allocating buffer: %s\n"),
			tnfctl_strerror(err));
		return;
	}

	/* get the trace attributes again */
	if (check_kernelmode(&attrs))
		return;
	(void) printf(gettext("Buffer of size %d bytes allocated\n"),
			attrs.trace_buf_size);
}


/*
 * Deallocate the kernel's trace buffer.
 */
void
prbk_buffer_dealloc()
{
	tnfctl_errcode_t	err;

	if (check_kernelmode(NULL))
		return;

	err = tnfctl_buffer_dealloc(g_hndl);
	switch (err) {
	case (TNFCTL_ERR_NONE):
		(void) printf(gettext("buffer deallocated\n"));
		break;
	case (TNFCTL_ERR_NOBUF):
		(void) fprintf(stderr,
			gettext("There is no buffer to deallocate\n"));
		break;
	case (TNFCTL_ERR_BADDEALLOC):
		(void) fprintf(stderr,
			gettext("Can't deallocate the buffer when "
			"tracing is active\n"));
		break;
	default:
		(void) fprintf(stderr,
			gettext("error in deleting buffer: %s\n"),
			tnfctl_strerror(err));
		break;
	}
}


/*
 * Process filter routines.
 *
 * Process id sets are encoded as "pidlists":  a linked list of pids.
 * In a feeble attempt at encapsulation, the pidlist_t type is private
 * to this file; prexgram.y manipulates pidlists only as opaque handles.
 */

/*
 * Add the given pid (new) to the pidlist (pl).
 */
void *
prbk_pidlist_add(void *pl, int new)

{
	pidlist_t *npl = (pidlist_t *) malloc(sizeof (*npl));

	if (npl == NULL) {
		(void) fprintf(stderr,
			gettext("Out of memory -- can't process pid %d\n"),
			new);
		return (pl);
	}
	npl->next = pl;
	npl->pid = new;
	return (npl);
}

/*
 * Add the pids in the given pidlist to the process filter list.
 * For each pid, check whether it's already in the filter list,
 * and whether the process exists.
 */
void
prbk_pfilter_add(void *pl)
{
	pidlist_t *ppl = (pidlist_t *) pl;
	pidlist_t *tmp;
	tnfctl_errcode_t err;

	if (check_kernelmode(NULL))
		return;
	while (ppl != NULL) {
		err = tnfctl_filter_list_add(g_hndl, ppl->pid);
		if (err) {
			(void) fprintf(stderr, gettext("Process %ld: %s\n"),
				ppl->pid, tnfctl_strerror(err));
		}
		tmp = ppl;
		ppl = ppl->next;
		free(tmp);
	}
}

/*
 * Drop the pids in the given pidlist from the process filter list.
 * For each pid, complain if it's not in the process filter list;
 * and if the process no longer exists (and hence has already implicitly
 * been dropped from the process filter list), say so.
 */
void
prbk_pfilter_drop(void *pl)
{
	pidlist_t *ppl = (pidlist_t *) pl;
	pidlist_t *tmp;
	tnfctl_errcode_t err;

	if (check_kernelmode(NULL))
		return;

	while (ppl != NULL) {
		tmp = ppl;
		err = tnfctl_filter_list_delete(g_hndl, tmp->pid);
		switch (err) {
		case (TNFCTL_ERR_NONE):
			break;
		case (TNFCTL_ERR_BADARG):
			(void) fprintf(stderr,
				gettext("Process %ld is not being traced\n"),
				tmp->pid);
			break;
		case (TNFCTL_ERR_NOPROCESS):
			(void) printf(gettext("Process %ld has exited\n"),
					tmp->pid);
			break;
		default:
			(void) fprintf(stderr, gettext("Process %ld: %s\n"),
				tmp->pid, tnfctl_strerror(err));
			break;
		}
		ppl = ppl->next;
		free(tmp);
	}
}

/*
 * Turn process filter mode on or off.  The process filter is maintained
 * even when process filtering is off, but has no effect:  all processes
 * are traced.
 */
void
prbk_set_pfilter_mode(boolean_t onoff)
{
	tnfctl_errcode_t	err;

	if (check_kernelmode(NULL))
		return;
	err = tnfctl_filter_state_set(g_hndl, onoff);
	if (err) {
		(void) fprintf(stderr, gettext("pfilter: %s\n"),
			tnfctl_strerror(err));
	}
}


/*
 * Report whether process filter mode is currently on or off, and
 * dump the current process filter set.
 */
void
prbk_show_pfilter_mode()
{
	tnfctl_errcode_t	err;
	tnfctl_trace_attrs_t	attrs;
	pid_t			*pids_p;
	int			i, pid_count;
	pid_t			*cur_pid;

	if (check_kernelmode(&attrs))
		return;
	(void) printf(gettext("Process filtering is %s\n"),
		attrs.filter_state ? "on" : "off");
	err = tnfctl_filter_list_get(g_hndl, &pids_p, &pid_count);
	if (err) {
		(void) fprintf(stderr,
			gettext("error in getting process filter list: %s\n"),
			tnfctl_strerror(err));
		return;
	}
	(void) printf(gettext("Process filter set is "));
	if (pid_count == 0)
		(void) printf("empty.\n");
	else {
		(void) printf("{");
		cur_pid = pids_p;
		for (i = 0; i < pid_count; i++, cur_pid++) {
			(void) printf("%ld%s", *cur_pid,
			    (i != (pid_count - 1)) ? ", " : "}\n");
		}
	}
}

/*
 * Check for process filtering on with empty pid filter.
 */
void
prbk_warn_pfilter_empty(void)
{
	tnfctl_errcode_t	err;
	pid_t		*pids_p;
	int			pid_count;
	tnfctl_trace_attrs_t	attrs;

	if (check_kernelmode(&attrs))
		return;
	if (attrs.filter_state) {
		err = tnfctl_filter_list_get(g_hndl, &pids_p, &pid_count);
		if (err) {
		    (void) fprintf(stderr,
			gettext("error in getting process filter list: %s\n"),
			tnfctl_strerror(err));
		    return;
		}
		if (!pid_count)
		    (void) fprintf(stderr,
			gettext("Warning: Process filtering on, \
but pid filter list is empty\n"));
	}
}


/*
 * Turn kernel tracing on or off.
 */
void
prbk_set_tracing(boolean_t onoff)
{
	tnfctl_errcode_t	err;

	if (check_kernelmode(NULL))
	    return;

	err = tnfctl_trace_state_set(g_hndl, onoff);
	if (err) {
	    (void) fprintf(stderr,
		gettext("error in setting tracing state: %s\n"),
		tnfctl_strerror(err));
	}
}

/*
 * Show whether kernel tracing is currently on or off.
 */
void
prbk_show_tracing()
{
	tnfctl_trace_attrs_t	attrs;

	if (check_kernelmode(&attrs))
		return;
	(void) printf(gettext("Tracing is %s\n"),
		attrs.trace_state ? "on" : "off");
}
