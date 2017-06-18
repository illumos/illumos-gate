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

/*
 * Interfaces to control kernel tracing and kernel probes
 */

#ifndef DEBUG
#define	NDEBUG	1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>	/* for strerror() */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/tnf.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <assert.h>

#include "tnfctl_int.h"
#include "kernel_int.h"

/* The TNF pseudo-device */
#define	TNFDRIVER	"/dev/tnfctl"

/* Dummy "test" function  -- just used to flag enabled probes */
#define	PRBK_DUMMY_TEST	((tnf_probe_test_func_t) 4)

/* Dummy "commit" function -- just used to flag trace enabled */
#define	PRBK_DUMMY_COMMIT ((tnf_probe_func_t) 8)

/* Dummy "rollback" function -- just used to flag trace disabled */
#define	PRBK_DUMMY_ROLLBACK ((tnf_probe_func_t) 12)

/* Dummy "end" function */
#define	PRBK_DUMMY_END ((uintptr_t) 16)

/* Dummy "alloc" function */
#define	PRBK_DUMMY_ALLOC ((uintptr_t) 20)

/* Minimum and maximum allowed buffer sizes. */
/* XXX -- maximum should be some function of physmem. */
#define	KERNEL_MINBUF_SIZE	(128 * 1024)
#define	KERNEL_MAXBUF_SIZE	(128 * 1024 * 1024)

static tnfctl_errcode_t prbk_get_buf_attrs(tnfctl_handle_t *hdl);
static tnfctl_errcode_t alloc_probe_space(tnfctl_handle_t *hndl, int maxprobe);

/*
 * Initialize the kernel interface:  Open the TNF control device,
 * and determine the current kernel probes state, including the
 * current pidfilter list.
 */
tnfctl_errcode_t
_tnfctl_prbk_init(tnfctl_handle_t *hdl)
{
	tnfctl_errcode_t prexstat;
	tifiocstate_t kstate;
	int kfd;

	kfd = open(TNFDRIVER, O_RDWR);
	if (kfd < 0) {
		return (tnfctl_status_map(errno));
	}
	if (ioctl(kfd, TIFIOCGSTATE, &kstate) < 0)
		return (tnfctl_status_map(errno));

	hdl->kfd = kfd;
	hdl->kpidfilter_state = kstate.pidfilter_mode;
	hdl->trace_state = !kstate.trace_stopped;
	hdl->trace_min_size = KERNEL_MINBUF_SIZE;
	prexstat = prbk_get_buf_attrs(hdl);
	if (prexstat)
		return (prexstat);

	return (TNFCTL_ERR_NONE);
}

/*
 * Close the TNF control device.
 */
tnfctl_errcode_t
_tnfctl_prbk_close(tnfctl_handle_t *hdl)
{
	if (hdl == NULL)
		return (TNFCTL_ERR_NONE);

	if (close(hdl->kfd) == -1) {
		return (tnfctl_status_map(errno));
	}
	return (TNFCTL_ERR_NONE);
}

/*
 * Returns function addresses that can be plugged into function pointers
 * in kernel probes.  These are actually dummy values that get
 * interpreted by a routine in this file when a probe is flushed.
 */
void
_tnfctl_prbk_get_other_funcs(uintptr_t *allocp, uintptr_t *commitp,
	uintptr_t *rollbackp, uintptr_t *endp)
{
	*allocp = PRBK_DUMMY_ALLOC;
	*commitp = (uintptr_t) PRBK_DUMMY_COMMIT;
	*rollbackp = (uintptr_t) PRBK_DUMMY_ROLLBACK;
	*endp = PRBK_DUMMY_END;
}


/*
 * Returns test function address
 */
void
_tnfctl_prbk_test_func(uintptr_t *outp)
{
	*outp = (uintptr_t) PRBK_DUMMY_TEST;
}

/*
 * Allocate a trace buffer.  Check for reasonable size; reject if there's
 * already a buffer.
 */
tnfctl_errcode_t
_tnfctl_prbk_buffer_alloc(tnfctl_handle_t *hdl, int size)
{
	tifiocstate_t bufstat;
	tnfctl_errcode_t prexstat;
	int saved_val;

	if (ioctl(hdl->kfd, TIFIOCGSTATE, &bufstat) < 0) {
		return (tnfctl_status_map(errno));
	}
	if (bufstat.buffer_state != TIFIOCBUF_NONE) {
		return (TNFCTL_ERR_BUFEXISTS);
	}
	if (size < KERNEL_MINBUF_SIZE) {
		return (TNFCTL_ERR_SIZETOOSMALL);
	} else if (size > KERNEL_MAXBUF_SIZE) {
		/* REMIND: make this an error ? */
		size = KERNEL_MAXBUF_SIZE;
	}
	if (ioctl(hdl->kfd, TIFIOCALLOCBUF, size) < 0) {
		saved_val = errno;
		(void) prbk_get_buf_attrs(hdl);
		return (tnfctl_status_map(saved_val));
	}

	prexstat = prbk_get_buf_attrs(hdl);
	if (prexstat)
		return (prexstat);

	return (TNFCTL_ERR_NONE);
}

/*
 * Deallocate the kernel's trace buffer.
 */
tnfctl_errcode_t
_tnfctl_prbk_buffer_dealloc(tnfctl_handle_t *hdl)
{
	tifiocstate_t bufstat;
	tnfctl_errcode_t prexstat;
	int saved_val;

	if (ioctl(hdl->kfd, TIFIOCGSTATE, &bufstat) < 0) {
		return (tnfctl_status_map(errno));
	}
	if (bufstat.buffer_state == TIFIOCBUF_NONE) {
		return (TNFCTL_ERR_NOBUF);
	}

	if (bufstat.buffer_state == TIFIOCBUF_OK && !bufstat.trace_stopped) {
		return (TNFCTL_ERR_BADDEALLOC);
	}
	if (ioctl(hdl->kfd, TIFIOCDEALLOCBUF) < 0) {
		saved_val = errno;
		(void) prbk_get_buf_attrs(hdl);
		return (tnfctl_status_map(saved_val));
	}

	prexstat = prbk_get_buf_attrs(hdl);
	if (prexstat)
		return (prexstat);

	return (TNFCTL_ERR_NONE);
}

/*
 * Turns kernel global tracing on or off.
 */
tnfctl_errcode_t
_tnfctl_prbk_set_tracing(tnfctl_handle_t *hdl, boolean_t onoff)
{
	if (hdl->trace_state != onoff &&
	    ioctl(hdl->kfd, TIFIOCSTRACING, onoff) < 0) {
		if (errno == ENOMEM && onoff)
			return (TNFCTL_ERR_NOBUF);
		else
			return (tnfctl_status_map(errno));
	}
	hdl->trace_state = onoff;
	return (TNFCTL_ERR_NONE);
}

/*
 * Turn process filter mode on or off.  The process filter is maintained
 * even when process filtering is off, but has no effect:  all processes
 * are traced.
 */
tnfctl_errcode_t
_tnfctl_prbk_set_pfilter_mode(tnfctl_handle_t *hdl, boolean_t onoff)
{
	if (hdl->kpidfilter_state != onoff &&
	    ioctl(hdl->kfd, TIFIOCSPIDFILTER, onoff) < 0) {
		return (tnfctl_status_map(errno));
	}
	hdl->kpidfilter_state = onoff;
	return (TNFCTL_ERR_NONE);
}

/*
 * Return the process filter list.
 */
tnfctl_errcode_t
_tnfctl_prbk_get_pfilter_list(tnfctl_handle_t *hdl, pid_t **ret_list_p,
				int *ret_count)
{
	tifiocstate_t kstate;
	int *filterset;
	int i;
	pid_t *ret_list;

	if (ioctl(hdl->kfd, TIFIOCGSTATE, &kstate) < 0)
		return (tnfctl_status_map(errno));

	if (kstate.pidfilter_size == 0) {
		*ret_count = 0;
		*ret_list_p = NULL;
		return (TNFCTL_ERR_NONE);
	}

	filterset = (int *) malloc((kstate.pidfilter_size + 1) *
					sizeof (pid_t));
	if (filterset == NULL)
		return (TNFCTL_ERR_ALLOCFAIL);
	if (ioctl(hdl->kfd, TIFIOCPIDFILTERGET, filterset) < 0)
		return (tnfctl_status_map(errno));

	/* filterset[0] contains size of array */
	ret_list = malloc(filterset[0] * sizeof (pid_t));
	if (ret_list == NULL)
		return (TNFCTL_ERR_ALLOCFAIL);

	for (i = 1; i <= filterset[0]; ++i)
		ret_list[i - 1] = filterset[i];

	*ret_count = filterset[0];
	(void) free(filterset);
	*ret_list_p = ret_list;
	return (TNFCTL_ERR_NONE);
}

/*
 * Add the pid to the process filter list.
 * check whether it's already in the filter list,
 * and whether the process exists.
 */
tnfctl_errcode_t
_tnfctl_prbk_pfilter_add(tnfctl_handle_t *hdl, pid_t pid_to_add)
{
	if (ioctl(hdl->kfd, TIFIOCSPIDON, pid_to_add) < 0) {
		return (tnfctl_status_map(errno));
	}
	return (TNFCTL_ERR_NONE);
}

/*
 * Drop the pid from the process filter list.
 */
tnfctl_errcode_t
_tnfctl_prbk_pfilter_delete(tnfctl_handle_t *hdl, pid_t pid_to_del)
{
	if (ioctl(hdl->kfd, TIFIOCSPIDOFF, pid_to_del) < 0) {
		if (errno == ESRCH) {
			return (TNFCTL_ERR_NOPROCESS);
		} else {
			return (tnfctl_status_map(errno));
		}
	}
	return (TNFCTL_ERR_NONE);
}

/*
 * get the buffer attributes - side effect tnfctl handle
 */
static tnfctl_errcode_t
prbk_get_buf_attrs(tnfctl_handle_t *hdl)
{
	tifiocstate_t bufstat;

	if (ioctl(hdl->kfd, TIFIOCGSTATE, &bufstat) < 0) {
		return (tnfctl_status_map(errno));
	}

	hdl->trace_file_name = NULL;
	hdl->trace_buf_size = bufstat.buffer_size;
	if (bufstat.buffer_state == TIFIOCBUF_NONE)
		hdl->trace_buf_state = TNFCTL_BUF_NONE;
	else if (bufstat.buffer_state == TIFIOCBUF_BROKEN)
		hdl->trace_buf_state = TNFCTL_BUF_BROKEN;
	else
		hdl->trace_buf_state = TNFCTL_BUF_OK;
	return (TNFCTL_ERR_NONE);
}

/*
 * "Flush" a probe:  i.e., sync up the kernel state with the
 * (desired) state stored in our data structure.
 */
tnfctl_errcode_t
_tnfctl_prbk_flush(tnfctl_handle_t *hndl, prbctlref_t *p)
{
	tnf_probevals_t probebuf;

	probebuf.probenum = p->probe_id;
	probebuf.enabled = (p->wrkprbctl.test_func != NULL);
	probebuf.traced = (p->wrkprbctl.commit_func == PRBK_DUMMY_COMMIT);
	if (ioctl(hndl->kfd, TIFIOCSPROBEVALS, &probebuf) < 0)
		return (tnfctl_status_map(errno));
	return (TNFCTL_ERR_NONE);
}

/*
 * Refresh our understanding of the existing probes in the kernel.
 */
tnfctl_errcode_t
_tnfctl_refresh_kernel(tnfctl_handle_t *hndl)
{
	int maxprobe, i;
	int pos;
	tnfctl_errcode_t prexstat;
	tnf_probevals_t probebuf;
	objlist_t *obj_p;
	prbctlref_t *p = NULL;

	prexstat = prbk_get_buf_attrs(hndl);
	if (prexstat)
		return (prexstat);
	/*
	 * Here is where you'd set obj_p->new to B_FALSE and obj_p->old to
	 * B_TRUE for all existing objects.  We currently don't need
	 * it until we get modload/unload working correctly with probes
	 */
	if (ioctl(hndl->kfd, TIFIOCGMAXPROBE, &maxprobe) < 0)
		return (tnfctl_status_map(errno));
	if (maxprobe == hndl->num_probes) {
		/* XXX Inadequate in the presence of module unloading */
		return (TNFCTL_ERR_NONE);
	}

	prexstat = alloc_probe_space(hndl, maxprobe);
	if (prexstat)
		return (prexstat);

	obj_p = hndl->objlist;
	assert((obj_p != NULL) && (obj_p->probes != NULL));

	for (i = 1; i <= maxprobe; ++i) {

		if (i >= (obj_p->min_probe_num + obj_p->probecnt)) {
			obj_p = obj_p->next;
		}

		/* make sure we are in the correct object */
		assert(obj_p != NULL);
		assert((i >= obj_p->min_probe_num) &&
			(i < (obj_p->min_probe_num + obj_p->probecnt)));

		/* get a pointer to correct probe */
		pos = i - obj_p->min_probe_num;
		p = &(obj_p->probes[pos]);
		assert((p != NULL) && (p->probe_id == i) && (p->probe_handle));

		probebuf.probenum = i;
		if (ioctl(hndl->kfd, TIFIOCGPROBEVALS, &probebuf) < 0) {
			if (errno == ENOENT) {
				/*
				 * This probe has vanished due to a module
				 * unload.
				 */
				p->probe_handle->valid = B_FALSE;
			} else {
				return (tnfctl_status_map(errno));
			}
		} else {
			if (p->probe_handle->valid == B_FALSE) {
				/*
				 * seeing this probe for the first time
				 * (alloc_probe_space() initialized this
				 * "valid" field to B_FALSE)
				 */
				/* Update our info about this probe */
				p->wrkprbctl.test_func = (probebuf.enabled) ?
					PRBK_DUMMY_TEST : NULL;
				p->wrkprbctl.commit_func = (probebuf.traced) ?
					PRBK_DUMMY_COMMIT : PRBK_DUMMY_ROLLBACK;
				p->probe_handle->valid = B_TRUE;
				if (probebuf.attrsize < sizeof (probebuf))
					probebuf.attrsize = sizeof (probebuf);
				p->attr_string = malloc(probebuf.attrsize);
				if (p->attr_string == NULL)
					return (TNFCTL_ERR_ALLOCFAIL);
				/*
				 * NOTE: the next statement is a structure
				 * copy and *not* a pointer assignment
				 */
/* LINTED pointer cast may result in improper alignment */
				*(tnf_probevals_t *) p->attr_string = probebuf;
				if (ioctl(hndl->kfd, TIFIOCGPROBESTRING,
						p->attr_string) < 0)
					return (tnfctl_status_map(errno));
				if (hndl->create_func) {
				    p->probe_handle->client_registered_data =
					hndl->create_func(hndl,
						p->probe_handle);
				}
			}
		}
	}
	hndl->num_probes = maxprobe;
	return (TNFCTL_ERR_NONE);
}

/*
 * check if there are any new probes in the kernel that we aren't aware of.
 * If so, allocate space for those probes in our data structure.
 */
static tnfctl_errcode_t
alloc_probe_space(tnfctl_handle_t *hndl, int maxprobe)
{
	objlist_t **o_pp;
	objlist_t *obj_p, *nobj_p;
	int min_probe_num, i;
	prbctlref_t *probe_p;

	/* we know that: hndl->maxprobe != maxprobe */
	obj_p = hndl->objlist;
	if (obj_p == NULL) {
		/* no objects allocated */
		o_pp = &(hndl->objlist);
		min_probe_num = 1;
	} else {
		/* find last object */
		while (obj_p->next != NULL) {
			/* reset new_probe field on modload/unload */
			obj_p->new_probe = B_FALSE;
			obj_p = obj_p->next;
		}
		o_pp = &(obj_p->next);
		min_probe_num = obj_p->min_probe_num + obj_p->probecnt;
	}

	nobj_p = calloc(1, sizeof (objlist_t));
	if (nobj_p == NULL)
		return (TNFCTL_ERR_ALLOCFAIL);
	/* add to the linked list */
	*o_pp = nobj_p;
	/* NULL, B_FALSE, or 0's not explicitly initialized */
	nobj_p->new_probe = B_TRUE;
	nobj_p->new = B_TRUE;
	nobj_p->objfd = -1;
	nobj_p->min_probe_num = min_probe_num;
	nobj_p->probecnt = maxprobe - min_probe_num + 1;
	nobj_p->probes = calloc(nobj_p->probecnt,  sizeof (prbctlref_t));
	if (nobj_p->probes == NULL) {
		free(nobj_p);
		return (TNFCTL_ERR_ALLOCFAIL);
	}

	probe_p = &(nobj_p->probes[0]);
	for (i = min_probe_num; i <= maxprobe; i++) {
		probe_p->obj = nobj_p;
		probe_p->probe_id = i;
		probe_p->probe_handle = calloc(1, sizeof (tnfctl_probe_t));
		if (probe_p->probe_handle == NULL) {
			if (nobj_p->probes)
				free(nobj_p->probes);
			free(nobj_p);
			return (TNFCTL_ERR_ALLOCFAIL);
		}
		probe_p->probe_handle->valid = B_FALSE;
		probe_p->probe_handle->probe_p = probe_p;
		/* link in probe handle into chain off tnfctl_handle_t */
		probe_p->probe_handle->next = hndl->probe_handle_list_head;
		hndl->probe_handle_list_head = probe_p->probe_handle;

		probe_p++;
	}

	hndl->num_probes = maxprobe;
	return (TNFCTL_ERR_NONE);
}
