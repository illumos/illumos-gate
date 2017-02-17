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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#include <libcpc.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <strings.h>
#include <unistd.h>
#include <stropts.h>
#include <libintl.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/processor.h>
#include <sys/procset.h>

#include "libcpc_impl.h"

#define	MASK32 0xFFFFFFFF

/*
 * The library uses the cpc_lock field of the cpc_t struct to protect access to
 * the linked lists inside the cpc_t, and only the linked lists. It is NOT used
 * to protect against users shooting themselves in the foot (such as, for
 * instance, destroying the same set at the same time from different threads.).
 *
 * SIGEMT needs to be blocked while holding the lock, to prevent deadlock among
 * an app holding the lock and a signal handler attempting to sample or bind.
 */

static char *cpc_get_list(int which, int arg);
static void cpc_err(cpc_t *cpc, const char *fn, int subcode, ...);
static int cpc_set_valid(cpc_t *cpc, cpc_set_t *set);
static int cpc_lock(cpc_t *cpc);
static void cpc_unlock(cpc_t *cpc, int blocked);
static int cpc_valid_event(cpc_t *cpc, uint_t pic, const char *ev);
static int cpc_valid_attr(cpc_t *cpc, char *attr);
static void cpc_invalidate_pctx(cpc_t *cpc, pctx_t *pctx);

cpc_t *
cpc_open(int ver)
{
	cpc_t	*cpc;
	void	(*sigsaved)();
	int	error = 0;
	int	i;
	int	j;

	if (ver != CPC_VER_CURRENT) {
		/*
		 * v1 clients must stick to the v1 interface: cpc_version()
		 */
		errno = EINVAL;
		return (NULL);
	}

	/*
	 * Call the syscall with invalid parameters.  If we get ENOSYS this CPU
	 * has no CPC support.  We need to block SIGSYS because the syscall code
	 * will send the signal if the system call fails to load.
	 */
	sigsaved = signal(SIGSYS, SIG_IGN);
	if (syscall(SYS_cpc, -1, -1, -1, -1, -1) != -1) {
		(void) signal(SIGSYS, sigsaved);
		errno = EINVAL;
		return (NULL);
	}
	error = errno;
	(void) signal(SIGSYS, sigsaved);

	if (error != EINVAL) {
		errno = error;
		return (NULL);
	}

	if ((cpc = malloc(sizeof (cpc_t))) == NULL) {
		errno = ENOMEM;
		return (NULL);
	}

	cpc->cpc_npic = syscall(SYS_cpc, CPC_NPIC, -1, 0, 0, 0);
	cpc->cpc_caps = syscall(SYS_cpc, CPC_CAPS, -1, 0, 0, 0);

	if (syscall(SYS_cpc, CPC_IMPL_NAME, -1, &cpc->cpc_cciname, 0, 0) != 0)
		return (NULL);
	if (syscall(SYS_cpc, CPC_CPUREF, -1, &cpc->cpc_cpuref, 0, 0) != 0)
		return (NULL);


	if ((cpc->cpc_attrlist = cpc_get_list(CPC_LIST_ATTRS, 0)) == NULL) {
		free(cpc);
		return (NULL);
	}

	if ((cpc->cpc_evlist = malloc(cpc->cpc_npic * sizeof (char *))) ==
	    NULL) {
		free(cpc->cpc_attrlist);
		free(cpc);
		return (NULL);
	}

	for (i = 0; i < cpc->cpc_npic; i++) {
		if ((cpc->cpc_evlist[i] = cpc_get_list(CPC_LIST_EVENTS, i)) ==
		    NULL)
			break;
	}
	if (i != cpc->cpc_npic) {
		for (j = 0; j < i; j++)
			free(cpc->cpc_evlist[j]);
		free(cpc->cpc_evlist);
		free(cpc->cpc_attrlist);
		free(cpc);
		return (NULL);
	}

	cpc->cpc_sets = NULL;
	cpc->cpc_bufs = NULL;
	cpc->cpc_errfn = NULL;
	(void) mutex_init(&cpc->cpc_lock, USYNC_THREAD, NULL);
	__pctx_cpc_register_callback(cpc_invalidate_pctx);

	return (cpc);
}

/*
 * Ensure state is cleaned up:
 *
 * - Hardware is unbound
 * - Sets are all destroyed
 * - Bufs are all freed
 */
int
cpc_close(cpc_t *cpc)
{
	while (cpc->cpc_sets != NULL) {
		if (cpc->cpc_sets->cs_state != CS_UNBOUND)
			(void) cpc_unbind(cpc, cpc->cpc_sets);
		(void) cpc_set_destroy(cpc, cpc->cpc_sets);
	}

	while (cpc->cpc_bufs != NULL)
		(void) cpc_buf_destroy(cpc, cpc->cpc_bufs);

	free(cpc);
	return (0);
}

/*
 * Terminate everything that runs in pctx_run
 */
void
cpc_terminate(cpc_t *cpc)
{
	cpc_set_t	*csp;
	int		sigblocked;

	sigblocked = cpc_lock(cpc);
	for (csp = cpc->cpc_sets; csp != NULL; csp = csp->cs_next) {
		if (csp->cs_pctx != NULL)
			pctx_terminate(csp->cs_pctx);
	}
	cpc_unlock(cpc, sigblocked);
}

cpc_set_t *
cpc_set_create(cpc_t *cpc)
{
	cpc_set_t	*set;
	int		sigblocked;

	if ((set = malloc(sizeof (*set))) == NULL) {
		errno = ENOMEM;
		return (NULL);
	}

	set->cs_request = NULL;
	set->cs_nreqs	= 0;
	set->cs_state	= CS_UNBOUND;
	set->cs_fd	= -1;
	set->cs_pctx	= NULL;
	set->cs_id	= -1;
	set->cs_thr	= NULL;

	sigblocked = cpc_lock(cpc);
	set->cs_next = cpc->cpc_sets;
	cpc->cpc_sets = set;
	cpc_unlock(cpc, sigblocked);

	return (set);
}

int
cpc_set_destroy(cpc_t *cpc, cpc_set_t *set)
{
	cpc_set_t	*csp, *prev;
	cpc_request_t	*req, *next;
	int		sigblocked;

	/*
	 * Remove this set from the cpc handle's list of sets.
	 */
	sigblocked = cpc_lock(cpc);
	for (csp = prev = cpc->cpc_sets; csp != NULL; csp = csp->cs_next) {
		if (csp == set)
			break;
		prev = csp;
	}
	if (csp == NULL) {
		cpc_unlock(cpc, sigblocked);
		errno = EINVAL;
		return (-1);
	}
	if (csp == cpc->cpc_sets)
		cpc->cpc_sets = csp->cs_next;
	prev->cs_next = csp->cs_next;
	cpc_unlock(cpc, sigblocked);

	if (csp->cs_state != CS_UNBOUND)
		(void) cpc_unbind(cpc, csp);

	/*
	 * Detach from the process
	 */
	if (csp->cs_pctx != NULL) {
		pctx_release(csp->cs_pctx);
		csp->cs_pctx = NULL;
	}

	for (req = csp->cs_request; req != NULL; req = next) {
		next = req->cr_next;

		if (req->cr_nattrs != 0)
			free(req->cr_attr);

		free(req);
	}


	free(set);

	return (0);
}

/*ARGSUSED*/
int
cpc_set_add_request(cpc_t *cpc, cpc_set_t *set, const char *event,
    uint64_t preset, uint_t flags, uint_t nattrs, const cpc_attr_t *attrs)
{
	cpc_request_t	*req;
	const char	*fn = "cpc_set_add_request";
	int		i;
	int		npics = cpc_npic(cpc);

	if (cpc_set_valid(cpc, set) != 0 || set->cs_state != CS_UNBOUND) {
		errno = EINVAL;
		return (-1);
	}

	for (i = 0; i < npics; i++)
		if (cpc_valid_event(cpc, i, event))
			break;
	if (i == npics) {
		cpc_err(cpc, fn, CPC_INVALID_EVENT);
		errno = EINVAL;
		return (-1);
	}

	if ((req = malloc(sizeof (*req))) == NULL) {
		errno = ENOMEM;
		return (-1);
	}

	(void) strncpy(req->cr_event, event, CPC_MAX_EVENT_LEN);
	req->cr_preset = preset;
	req->cr_flags = flags;
	req->cr_nattrs = nattrs;
	req->cr_index = set->cs_nreqs;
	req->cr_attr = NULL;

	if (nattrs != 0) {
		for (i = 0; i < nattrs; i++) {
			/*
			 * Verify that each attribute name is legal and valid.
			 */
			if (attrs[i].ca_name[0] == '\0' ||
			    cpc_valid_attr(cpc, attrs[i].ca_name) == 0) {
				cpc_err(cpc, fn, CPC_INVALID_ATTRIBUTE);
				goto inval;
			}

			/*
			 * If the user requested a specific picnum, ensure that
			 * the pic can count the requested event.
			 */
			if (strncmp("picnum", attrs[i].ca_name, 8) == 0) {
				if (attrs[i].ca_val >= npics) {
					cpc_err(cpc, fn, CPC_INVALID_PICNUM);
					goto inval;
				}

				if (cpc_valid_event(cpc, attrs[i].ca_val,
				    req->cr_event) == 0) {
					cpc_err(cpc, fn, CPC_PIC_NOT_CAPABLE);
					goto inval;
				}
			}
		}

		if ((req->cr_attr = malloc(nattrs * sizeof (kcpc_attr_t)))
		    == NULL) {
			free(req);
			return (-1);
		}

		for (i = 0; i < nattrs; i++) {
			req->cr_attr[i].ka_val = attrs[i].ca_val;
			(void) strncpy(req->cr_attr[i].ka_name,
			    attrs[i].ca_name, CPC_MAX_ATTR_LEN);
		}
	} else
		req->cr_attr = NULL;

	req->cr_next = set->cs_request;
	set->cs_request = req;
	set->cs_nreqs++;

	return (req->cr_index);

inval:
	free(req);
	errno = EINVAL;
	return (-1);
}

cpc_buf_t *
cpc_buf_create(cpc_t *cpc, cpc_set_t *set)
{
	cpc_buf_t	*buf;
	int		sigblocked;

	if (cpc_set_valid(cpc, set) != 0) {
		errno = EINVAL;
		return (NULL);
	}

	if ((buf = malloc(sizeof (*buf))) == NULL)
		return (NULL);

	buf->cb_size = set->cs_nreqs * sizeof (uint64_t);
	if ((buf->cb_data = malloc(buf->cb_size)) == NULL) {
		free(buf);
		return (NULL);
	}

	bzero(buf->cb_data, buf->cb_size);

	buf->cb_hrtime = 0;
	buf->cb_tick = 0;

	sigblocked = cpc_lock(cpc);
	buf->cb_next = cpc->cpc_bufs;
	cpc->cpc_bufs = buf;
	cpc_unlock(cpc, sigblocked);

	return (buf);
}

int
cpc_buf_destroy(cpc_t *cpc, cpc_buf_t *buf)
{
	cpc_buf_t	*cbp, *prev;
	int		sigblocked;

	/*
	 * Remove this buf from the cpc handle's list of bufs.
	 */
	sigblocked = cpc_lock(cpc);
	for (cbp = prev = cpc->cpc_bufs; cbp != NULL; cbp = cbp->cb_next) {
		if (cbp == buf)
			break;
		prev = cbp;
	}
	if (cbp == NULL) {
		cpc_unlock(cpc, sigblocked);
		errno = EINVAL;
		return (-1);
	}
	if (cbp == cpc->cpc_bufs)
		cpc->cpc_bufs = cbp->cb_next;
	prev->cb_next = cbp->cb_next;

	cpc_unlock(cpc, sigblocked);
	free(cbp->cb_data);
	free(cbp);

	return (0);
}

/*ARGSUSED*/
int
cpc_bind_curlwp(cpc_t *cpc, cpc_set_t *set, uint_t flags)
{
	char		*packed_set;
	size_t		packsize;
	int		ret;
	int		subcode = -1;

	/*
	 * We don't bother checking cpc_set_valid() here, because this is in the
	 * fast path of an app doing SIGEMT-based profiling as they restart the
	 * counters from their signal handler.
	 */
	if (CPC_SET_VALID_FLAGS(flags) == 0 || set->cs_nreqs <= 0) {
		errno = EINVAL;
		return (-1);
	}

	if ((packed_set = __cpc_pack_set(set, flags, &packsize)) == NULL) {
		errno = ENOMEM;
		return (-1);
	}

	ret = syscall(SYS_cpc, CPC_BIND, -1, packed_set, packsize, &subcode);
	free(packed_set);

	if (ret != 0) {
		if (subcode != -1)
			cpc_err(cpc, "cpc_bind_curlwp", subcode);
		return (-1);
	}

	set->cs_thr = thr_self();
	set->cs_state = CS_BOUND_CURLWP;
	return (ret);
}

/*ARGSUSED*/
int
cpc_bind_pctx(cpc_t *cpc, pctx_t *pctx, id_t id, cpc_set_t *set, uint_t flags)
{
	char		*packed_set;
	size_t		packsize;
	int		ret;
	int		subcode = -1;

	/*
	 * cpc_bind_pctx() currently has no valid flags.
	 */
	if (flags != 0 || cpc_set_valid(cpc, set) != 0 || set->cs_nreqs <= 0) {
		errno = EINVAL;
		return (-1);
	}

	if ((packed_set = __cpc_pack_set(set, flags, &packsize)) == NULL) {
		errno = ENOMEM;
		return (-1);
	}

	ret = __pctx_cpc(pctx, cpc, CPC_BIND, id, packed_set, (void *)packsize,
	    (void *)&subcode, -1);

	free(packed_set);

	if (ret == 0) {
		set->cs_pctx = pctx;
		set->cs_id = id;
		set->cs_state = CS_BOUND_PCTX;
	} else if (subcode != -1)
		cpc_err(cpc, "cpc_bind_pctx", subcode);

	return (ret);
}

/*ARGSUSED*/
int
cpc_bind_cpu(cpc_t *cpc, processorid_t id, cpc_set_t *set, uint_t flags)
{
	int		fd;
	char		*packed_set;
	size_t		packsize;
	__cpc_args_t	cpc_args;
	int		error;
	const char	*fn = "cpc_bind_cpu";
	int		subcode = -1;

	/*
	 * cpc_bind_cpu() currently has no valid flags.
	 */
	if (flags != 0 || cpc_set_valid(cpc, set) != 0 || set->cs_nreqs <= 0) {
		errno = EINVAL;
		return (-1);
	}

	if (processor_bind(P_LWPID, P_MYID, id, &set->cs_obind) == -1) {
		cpc_err(cpc, fn, CPC_PBIND_FAILED);
		return (-1);
	}

	if ((fd = open(CPUDRV_SHARED, O_RDWR)) < 0) {
		error = errno;
		(void) processor_bind(P_LWPID, P_MYID, set->cs_obind, NULL);
		errno = error;
		return (-1);
	}

	/*
	 * To avoid leaking file descriptors, if we find an existing fd here we
	 * just close it. This is only a problem if a user attempts to bind the
	 * same set to different CPUs without first unbinding it.
	 */
	if (set->cs_fd != -1)
		(void) close(set->cs_fd);
	set->cs_fd = fd;

	if ((packed_set = __cpc_pack_set(set, flags, &packsize)) == NULL) {
		(void) close(fd);
		(void) processor_bind(P_LWPID, P_MYID, set->cs_obind, NULL);
		errno = ENOMEM;
		return (-1);
	}

	cpc_args.udata1 = packed_set;
	cpc_args.udata2 = (void *)packsize;
	cpc_args.udata3 = (void *)&subcode;

	if (ioctl(fd, CPCIO_BIND, &cpc_args) != 0) {
		error = errno;
		free(packed_set);
		(void) close(fd);
		(void) processor_bind(P_LWPID, P_MYID, set->cs_obind, NULL);
		if (subcode != -1)
			cpc_err(cpc, fn, subcode);
		errno = error;
		return (-1);
	}

	free(packed_set);

	set->cs_thr = thr_self();
	set->cs_state = CS_BOUND_CPU;

	return (0);
}

/*ARGSUSED*/
int
cpc_request_preset(cpc_t *cpc, int index, uint64_t preset)
{
	return (syscall(SYS_cpc, CPC_PRESET, -1, index,
	    (uint32_t)(preset >> 32), (uint32_t)(preset & MASK32)));
}

/*ARGSUSED*/
int
cpc_set_restart(cpc_t *cpc, cpc_set_t *set)
{
	return (syscall(SYS_cpc, CPC_RESTART, -1, 0, 0, 0));
}

/*ARGSUSED*/
int
cpc_unbind(cpc_t *cpc, cpc_set_t *set)
{
	int		ret = 0;
	int		error;

	if (cpc_set_valid(cpc, set) != 0) {
		errno = EINVAL;
		return (-1);
	}

	switch (set->cs_state) {
	case CS_UNBOUND:
		errno = EINVAL;
		return (-1);
	case CS_BOUND_CURLWP:
		ret = syscall(SYS_cpc, CPC_RELE, -1, 0, 0, 0);
		error = errno;
		break;
	case CS_BOUND_CPU:
		ret = ioctl(set->cs_fd, CPCIO_RELE, NULL);
		error = errno;
		(void) close(set->cs_fd);
		set->cs_fd = -1;
		(void) processor_bind(P_LWPID, P_MYID, set->cs_obind, NULL);
		break;
	case CS_BOUND_PCTX:
		if (set->cs_pctx != NULL) {
			ret = __pctx_cpc(set->cs_pctx, cpc, CPC_RELE,
			    set->cs_id, 0, 0, 0, 0);
			error = errno;
		}
		break;
	}

	set->cs_thr = NULL;
	set->cs_id = -1;
	set->cs_state = CS_UNBOUND;
	if (ret != 0)
		errno = error;
	return (ret);
}

/*ARGSUSED*/
int
cpc_set_sample(cpc_t *cpc, cpc_set_t *set, cpc_buf_t *buf)
{
	__cpc_args_t args;

	/*
	 * The following check ensures that only the most recently bound set
	 * can be sampled, as binding a set invalidates all other sets in the
	 * cpc_t.
	 */
	if (set->cs_state == CS_UNBOUND ||
	    buf->cb_size != set->cs_nreqs * sizeof (uint64_t)) {
		errno = EINVAL;
		return (-1);
	}

	switch (set->cs_state) {
	case CS_BOUND_CURLWP:
		return (syscall(SYS_cpc, CPC_SAMPLE, -1, buf->cb_data,
		    &buf->cb_hrtime, &buf->cb_tick));
	case CS_BOUND_CPU:
		args.udata1 = buf->cb_data;
		args.udata2 = &buf->cb_hrtime;
		args.udata3 = &buf->cb_tick;
		return (ioctl(set->cs_fd, CPCIO_SAMPLE, &args));
	case CS_BOUND_PCTX:
		return (__pctx_cpc(set->cs_pctx, cpc, CPC_SAMPLE, set->cs_id,
		    buf->cb_data, &buf->cb_hrtime, &buf->cb_tick,
		    buf->cb_size));
	}

	errno = EINVAL;
	return (-1);
}

/*ARGSUSED*/
void
cpc_buf_sub(cpc_t *cpc, cpc_buf_t *ds, cpc_buf_t *a, cpc_buf_t *b)
{
	int i;

	if (a->cb_size != ds->cb_size || b->cb_size != ds->cb_size)
		return;

	ds->cb_hrtime = (a->cb_hrtime > b->cb_hrtime) ?
	    a->cb_hrtime : b->cb_hrtime;
	ds->cb_tick = a->cb_tick - b->cb_tick;

	for (i = 0; i < ds->cb_size / sizeof (uint64_t); i++)
		ds->cb_data[i] = a->cb_data[i] - b->cb_data[i];
}

/*ARGSUSED*/
void
cpc_buf_add(cpc_t *cpc, cpc_buf_t *ds, cpc_buf_t *a, cpc_buf_t *b)
{
	int i;

	if (a->cb_size != ds->cb_size || b->cb_size != ds->cb_size)
		return;

	ds->cb_hrtime = (a->cb_hrtime > b->cb_hrtime) ?
	    a->cb_hrtime : b->cb_hrtime;
	ds->cb_tick = a->cb_tick + b->cb_tick;

	for (i = 0; i < ds->cb_size / sizeof (uint64_t); i++)
		ds->cb_data[i] = a->cb_data[i] + b->cb_data[i];
}

/*ARGSUSED*/
void
cpc_buf_copy(cpc_t *cpc, cpc_buf_t *ds, cpc_buf_t *src)
{
	if (ds->cb_size != src->cb_size)
		return;

	bcopy(src->cb_data, ds->cb_data, ds->cb_size);
	ds->cb_hrtime = src->cb_hrtime;
	ds->cb_tick = src->cb_tick;
}

/*ARGSUSED*/
void
cpc_buf_zero(cpc_t *cpc, cpc_buf_t *buf)
{
	bzero(buf->cb_data, buf->cb_size);
	buf->cb_hrtime = 0;
	buf->cb_tick = 0;
}

/*
 * Gets or sets the value of the request specified by index.
 */
/*ARGSUSED*/
int
cpc_buf_get(cpc_t *cpc, cpc_buf_t *buf, int index, uint64_t *val)
{
	*val = buf->cb_data[index];

	return (0);
}

/*ARGSUSED*/
int
cpc_buf_set(cpc_t *cpc, cpc_buf_t *buf, int index, uint64_t val)
{
	buf->cb_data[index] = val;

	return (0);
}

/*ARGSUSED*/
hrtime_t
cpc_buf_hrtime(cpc_t *cpc, cpc_buf_t *buf)
{
	return (buf->cb_hrtime);
}

/*ARGSUSED*/
uint64_t
cpc_buf_tick(cpc_t *cpc, cpc_buf_t *buf)
{
	return (buf->cb_tick);
}

static char *
cpc_get_list(int which, int arg)
{
	int	szcmd;
	int	size;
	char	*list;

	if (which == CPC_LIST_ATTRS)
		szcmd = CPC_ATTRLIST_SIZE;
	else
		szcmd = CPC_EVLIST_SIZE;

	if (syscall(SYS_cpc, szcmd, -1, &size, arg, 0) != 0)
		return (NULL);

	if ((list = malloc(size)) == NULL)
		return (NULL);

	if (syscall(SYS_cpc, which, -1, list, arg, 0) != 0) {
		free(list);
		return (NULL);
	}

	return (list);
}

/*ARGSUSED*/
void
cpc_walk_requests(cpc_t *cpc, cpc_set_t *set, void *arg,
    void (*action)(void *arg, int index, const char *event, uint64_t preset,
	uint_t flags, int nattrs, const cpc_attr_t *attrs))
{
	cpc_request_t	*rp;
	cpc_attr_t	*attrs = NULL;
	int		i;

	for (rp = set->cs_request; rp != NULL; rp = rp->cr_next) {
		/*
		 * Need to reconstruct a temporary cpc_attr_t array for req.
		 */
		if (rp->cr_nattrs != 0)
			if ((attrs = malloc(rp->cr_nattrs *
			    sizeof (cpc_attr_t))) == NULL)
				return;
		for (i = 0; i < rp->cr_nattrs; i++) {
			attrs[i].ca_name = rp->cr_attr[i].ka_name;
			attrs[i].ca_val = rp->cr_attr[i].ka_val;
		}

		action(arg, rp->cr_index, rp->cr_event, rp->cr_preset,
		    rp->cr_flags, rp->cr_nattrs, attrs);

		if (rp->cr_nattrs != 0)
			free(attrs);
	}
}

/*ARGSUSED*/
static void
cpc_walk_events_impl(cpc_t *cpc, void *arg,
    void (*action)(void *arg, const char *event), int is_generic)
{
	char		**list;
	char		*p, *e;
	int		i;
	int		is_papi;
	int		ncounters = cpc_npic(cpc);
	cpc_strhash_t	*hash;

	if ((list = malloc(ncounters * sizeof (char *))) == NULL)
		return;

	if ((hash = __cpc_strhash_alloc()) == NULL) {
		free(list);
		return;
	}

	for (i = 0; i < ncounters; i++) {
		if ((list[i] = strdup(cpc->cpc_evlist[i])) == NULL)
			goto err;
		p = list[i];
		while ((e = strchr(p, ',')) != NULL) {
			*e = '\0';

			/*
			 * Based on is_generic flag, skip appropriate
			 * event names.
			 */
			is_papi = (strncmp(p, "PAPI", 4) == 0);
			if (is_generic != is_papi) {
				p = e + 1;
				continue;
			}

			if (__cpc_strhash_add(hash, p) == -1)
				goto err;

			p = e + 1;
		}

		is_papi = (strncmp(p, "PAPI", 4) == 0);
		if (is_generic == is_papi) {
			if (__cpc_strhash_add(hash, p) == -1)
				goto err;
		}
	}

	while ((p = __cpc_strhash_next(hash)) != NULL)
		action(arg, p);

err:
	__cpc_strhash_free(hash);
	for (i = 0; i < ncounters; i++)
		free(list[i]);
	free(list);
}

/*ARGSUSED*/
void
cpc_walk_events_all(cpc_t *cpc, void *arg,
		    void (*action)(void *arg, const char *event))
{
	cpc_walk_events_impl(cpc, arg, action, 0);
}


/*ARGSUSED*/
void
cpc_walk_generic_events_all(cpc_t *cpc, void *arg,
			    void (*action)(void *arg, const char *event))
{
	cpc_walk_events_impl(cpc, arg, action, 1);
}

/*ARGSUSED*/
static void
cpc_walk_events_pic_impl(cpc_t *cpc, uint_t picno, void *arg,
    void (*action)(void *arg, uint_t picno, const char *event), int is_generic)
{
	char	*p;
	char	*e;
	char	*list;
	int	is_papi;

	if (picno >= cpc->cpc_npic) {
		errno = EINVAL;
		return;
	}

	if ((list = strdup(cpc->cpc_evlist[picno])) == NULL)
		return;

	/*
	 * List now points to a comma-separated list of events supported by
	 * the designated pic.
	 */
	p = list;
	while ((e = strchr(p, ',')) != NULL) {
		*e = '\0';

		/*
		 * Based on is_generic flag, skip appropriate
		 * event names.
		 */
		is_papi = (strncmp(p, "PAPI", 4) == 0);
		if (is_generic != is_papi) {
			p = e + 1;
			continue;
		}

		action(arg, picno, p);
		p = e + 1;
	}

	is_papi = (strncmp(p, "PAPI", 4) == 0);
	if (is_generic == is_papi)
		action(arg, picno, p);

	free(list);
}

/*ARGSUSED*/
void
cpc_walk_events_pic(cpc_t *cpc, uint_t picno, void *arg,
    void (*action)(void *arg, uint_t picno, const char *event))
{
	cpc_walk_events_pic_impl(cpc, picno, arg, action, 0);
}

/*ARGSUSED*/
void
cpc_walk_generic_events_pic(cpc_t *cpc, uint_t picno, void *arg,
    void (*action)(void *arg, uint_t picno, const char *event))
{
	cpc_walk_events_pic_impl(cpc, picno, arg, action, 1);
}

/*ARGSUSED*/
void
cpc_walk_attrs(cpc_t *cpc, void *arg,
    void (*action)(void *arg, const char *attr))
{
	char	*p;
	char	*e;
	char	*list;

	if ((list = strdup(cpc->cpc_attrlist)) == NULL)
		return;

	/*
	 * Platforms with no attributes will return an empty string.
	 */
	if (*list == '\0')
		return;

	/*
	 * List now points to a comma-separated list of attributes supported by
	 * the underlying platform.
	 */
	p = list;
	while ((e = strchr(p, ',')) != NULL) {
		*e = '\0';
		action(arg, p);
		p = e + 1;
	}
	action(arg, p);

	free(list);
}

/*ARGSUSED*/
int
cpc_enable(cpc_t *cpc)
{
	return (syscall(SYS_cpc, CPC_ENABLE, -1, 0, 0, 0));
}

/*ARGSUSED*/
int
cpc_disable(cpc_t *cpc)
{
	return (syscall(SYS_cpc, CPC_DISABLE, -1, 0, 0, 0));
}

/*ARGSUSED*/
uint_t
cpc_npic(cpc_t *cpc)
{
	return (cpc->cpc_npic);
}

/*ARGSUSED*/
uint_t
cpc_caps(cpc_t *cpc)
{
	return (cpc->cpc_caps);
}

const char *
cpc_cciname(cpc_t *cpc)
{
	return (cpc->cpc_cciname);
}

const char *
cpc_cpuref(cpc_t *cpc)
{
	return (cpc->cpc_cpuref);
}

int
cpc_seterrhndlr(cpc_t *cpc, cpc_errhndlr_t *fn)
{
	cpc->cpc_errfn = fn;
	return (0);
}

/*
 * These strings may contain printf() conversion specifiers.
 */
static const char *errstr[] = {
"",						/* zero slot filler */
"Unknown event\n",				/* CPC_INVALID_EVENT */
"Invalid counter number\n",			/* CPC_INVALID_PICNUM */
"Unknown attribute\n",				/* CPC_INVALID_ATTRIBUTE */
"Attribute out of range\n",			/* CPC_ATTRIBUTE_OUT_OF_RANGE */
"Hardware resource unavailable\n",		/* CPC_RESOURCE_UNAVAIL */
"Counter cannot count requested event\n",	/* CPC_PIC_NOT_CAPABLE */
"Invalid flags in a request\n",			/* CPC_REQ_INVALID_FLAGS */
"Requests conflict with each other\n",		/* CPC_CONFLICTING_REQS */
"Attribute requires the cpc_cpu privilege\n",  /* CPC_ATTR_REQUIRES_PRIVILEGE */
"Couldn't bind LWP to requested processor\n",	/* CPC_PBIND_FAILED */
"Hypervisor event access denied\n"		/* CPC_HV_NO_ACCESS */
};

/*VARARGS3*/
static void
cpc_err(cpc_t *cpc, const char *fn, int subcode, ...)
{
	va_list		ap;
	const char	*str;
	int		error;

	/*
	 * If subcode is -1, there is no specific description for this error.
	 */
	if (subcode == -1)
		return;

	/*
	 * We need to preserve errno across calls to this function to prevent it
	 * from being clobbered while here, or in the user's error handler.
	 */
	error = errno;

	str = dgettext(TEXT_DOMAIN, errstr[subcode]);

	va_start(ap, subcode);
	if (cpc->cpc_errfn != NULL)
		cpc->cpc_errfn(fn, subcode, str, ap);
	else {
		/*
		 * If printf() conversion specifiers are added to the errstr[]
		 * table, this call needs to be changed to vfprintf().
		 */
		(void) fprintf(stderr, "libcpc: %s: %s", fn, str);
	}
	va_end(ap);

	errno = error;
}

/*
 * Hook used by libpctx to alert libcpc when a pctx handle is going away.
 * This is necessary to prevent libcpc from attempting a libpctx operation on a
 * stale and invalid pctx_t handle. Since pctx_t's are cached by libcpc, we need
 * to be notified when they go away.
 */
static void
cpc_invalidate_pctx(cpc_t *cpc, pctx_t *pctx)
{
	cpc_set_t	*set;
	int		sigblocked;

	sigblocked = cpc_lock(cpc);
	for (set = cpc->cpc_sets; set != NULL; set = set->cs_next)
		if (set->cs_pctx == pctx)
			set->cs_pctx = NULL;
	cpc_unlock(cpc, sigblocked);
}

/*
 * Check that the set is valid; if so it will be in the cpc handle's
 * list of sets. The lock protects the list of sets, but not the set
 * itself.
 */
static int
cpc_set_valid(cpc_t *cpc, cpc_set_t *set)
{
	cpc_set_t	*csp;
	int		sigblocked;

	sigblocked = cpc_lock(cpc);
	for (csp = cpc->cpc_sets; csp != NULL; csp = csp->cs_next)
		if (csp == set)
			break;
	cpc_unlock(cpc, sigblocked);
	if (csp == NULL)
		return (-1);
	return (0);
}

static int
cpc_lock(cpc_t *cpc)
{
	int ret = (sigset(SIGEMT, SIG_HOLD) == SIG_HOLD);
	(void) mutex_lock(&cpc->cpc_lock);
	return (ret);
}

static void
cpc_unlock(cpc_t *cpc, int sigblocked)
{
	(void) mutex_unlock(&cpc->cpc_lock);
	if (sigblocked == 0)
		(void) sigrelse(SIGEMT);
}

struct priv {
	const char *name;
	int found;
};

/*ARGSUSED*/
static void
ev_walker(void *arg, uint_t picno, const char *ev)
{
	if (strcmp(((struct priv *)arg)->name, ev) == 0)
		((struct priv *)arg)->found = 1;
}

static void
at_walker(void *arg, const char *at)
{
	if (strcmp(((struct priv *)arg)->name, at) == 0)
		((struct priv *)arg)->found = 1;
}

static int
cpc_valid_event(cpc_t *cpc, uint_t pic, const char *ev)
{
	struct priv pr = { NULL, 0 };
	char *end_ev;
	int err;

	pr.name = ev;
	cpc_walk_events_pic(cpc, pic, &pr, ev_walker);
	if (pr.found)
		return (1);

	cpc_walk_generic_events_pic(cpc, pic, &pr, ev_walker);
	if (pr.found)
		return (1);

	/*
	 * Before assuming this is an invalid event, see if we have been given
	 * a raw event code.
	 * Check the second argument of strtol() to ensure invalid events
	 * beginning with number do not go through.
	 */
	err = errno;
	errno = 0;
	(void) strtol(ev, &end_ev, 0);
	if ((errno == 0) && (*end_ev == '\0')) {
		/*
		 * Success - this is a valid raw code in hex, decimal, or octal.
		 */
		errno = err;
		return (1);
	}

	errno = err;
	return (0);
}

static int
cpc_valid_attr(cpc_t *cpc, char *attr)
{
	struct priv pr = { NULL, 0 };

	pr.name = attr;
	cpc_walk_attrs(cpc, &pr, at_walker);
	return (pr.found);
}
