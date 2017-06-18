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

/*
 * Implements the routines that are needed only for internal process
 * control.
 */

#ifndef DEBUG
#define	NDEBUG	1
#endif

#include "tnfctl_int.h"
#include "kernel_int.h"
#include "dbg.h"

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <link.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/procfs.h>
#include <assert.h>
#include <dlfcn.h>

static int inprocess_read(void *ignore,
    uintptr_t addr, void *buf, size_t size);
static int inprocess_write(void *ignore,
    uintptr_t addr, void *buf, size_t size);
static pid_t inprocess_getpid(void *ignore);
static tnfctl_errcode_t inprocess_get_dtdebug(void *hndl, uintptr_t *ret_val);
static int inprocess_loadobj_iter(void *opq, tnfctl_ind_obj_f *obj_func,
					void *cd);

/*
 * Cause interposition on dlclose() and dlopen()
 */
#pragma weak dlclose = _tnfctl_dlclose

#pragma weak dlopen = _tnfctl_dlopen

/*
 * The lock used to protect the _tnfctl_internal_tracing_flag variable.
 *
 */
mutex_t		_tnfctl_internalguard_lock = DEFAULTMUTEX;
boolean_t	_tnfctl_internal_tracing_flag = 0;
pid_t		_tnfctl_externally_traced_pid = NOPID;

/*
 * Returns a pointer to a tnfctl handle that can do in process probe control.
 */
tnfctl_errcode_t
tnfctl_internal_open(tnfctl_handle_t **ret_val)
{
	tnfctl_handle_t	*hdl;
	tnfctl_errcode_t	prexstat;
	uintptr_t		dbgaddr;

	/* allocate hdl and zero fill */
	hdl = calloc(1, sizeof (*hdl));
	if (hdl == NULL) {
		return (TNFCTL_ERR_ALLOCFAIL);
	}

	hdl->mode = INTERNAL_MODE;
	hdl->called_exit = B_FALSE;

	/* plug in inprocess call back functions */
	hdl->p_read = inprocess_read;
	hdl->p_write = inprocess_write;
	hdl->p_obj_iter = inprocess_loadobj_iter;
	hdl->p_getpid = inprocess_getpid;

	/*
	 * get the address of DT_DEBUG and store it in proc_p
	 * (the handle on the same process is the dbg address)
	 */
	prexstat = inprocess_get_dtdebug(hdl, &dbgaddr);
	if (prexstat) {
		free(hdl);
		return (prexstat);
	}
	hdl->proc_p = (void *) dbgaddr;

	/* initialize state in handle */
	prexstat = _tnfctl_set_state(hdl);
	if (prexstat) {
		free(hdl);
		return (prexstat);
	}
	/* see if process is already being traced */
	prexstat = _tnfctl_internal_getlock();
	if (prexstat) {
		free(hdl);
		return (prexstat);
	}
	*ret_val = hdl;
	return (TNFCTL_ERR_NONE);
}

/*
 * reads a block of memory from the same address space.
 */
static int
inprocess_read(void *ignore, uintptr_t addr, void *buf, size_t size)
{

	DBG_TNF_PROBE_2(inprocess_read_1, "libtnfctl", "sunw%verbosity 3;",
		tnf_long, num_bytes, size,
		tnf_opaque, from_address, addr);

	(void) memcpy(buf, (void *) addr, size);
	return (0);
}

/*
 * writes a block of memory to the same address space.
 */
static int
inprocess_write(void *ignore, uintptr_t addr, void *buf, size_t size)
{

	DBG_TNF_PROBE_2(inprocess_write_1, "libtnfctl", "sunw%verbosity 3;",
		tnf_long, num_bytes, size,
		tnf_opaque, to_address, addr);

	(void) memcpy((void *)addr, buf, size);
	return (0);
}

/*
 * returns the pid of the process.
 */
static pid_t
inprocess_getpid(void *ignore)
{
	return (getpid());
}
extern Elf3264_Dyn _DYNAMIC;

/*
 * returns the address of the DT_DEBUG field in the _DYNAMIC array
 * of the same address space.
 */
static tnfctl_errcode_t
inprocess_get_dtdebug(void *hndl, uintptr_t *ret_val)
{
	Elf3264_Dyn 	*dyn = &_DYNAMIC;
	Elf3264_Dyn	*dp;

	for (dp = dyn; dp->d_tag != DT_NULL; dp++) {
		if (dp->d_tag == DT_DEBUG) {
			*ret_val = (uintptr_t) dp;
			return (TNFCTL_ERR_NONE);
		}
	}
	return (TNFCTL_ERR_INTERNAL);
}

#define	PROCFORMAT	"/proc/%d"

/*
 * iterate over all loadobjects in the same address space calling the
 * callback function "obj_func".
 */
static int
inprocess_loadobj_iter(void *opq, tnfctl_ind_obj_f *obj_func, void *cd)
{
	Elf3264_Dyn	*dtdebug = opq;
	struct r_debug	*r_dbg;
	struct link_map *lmap;
	char		path[MAXPATHLEN];
	int		procfd;
	tnfctl_ind_obj_info_t	loadobj;
	int		retval = 0;	/* sucessful return */

	DBG_TNF_PROBE_0(inprocess_loadobj_iter_start, "libtnfctl",
			"start inprocess_loadobj_iter; sunw%verbosity 1");

	r_dbg = (struct r_debug *)dtdebug->d_un.d_ptr;

	DBG_TNF_PROBE_1(inprocess_loadobj_iter_1, "libtnfctl",
		"sunw%verbosity 1",
		tnf_string, link_map_state,
		(r_dbg->r_state == RT_CONSISTENT) ? "RT_CONSISTENT" :
			(r_dbg->r_state == RT_ADD) ? "RT_ADD" : "RT_DELETE");

	/* bail if link map is not consistent */
	if (r_dbg->r_state != RT_CONSISTENT)
		return (1);

	(void) sprintf(path, PROCFORMAT, (int) getpid());

	/*
	 * opening /proc readonly, so debuggers can still run
	 * We use /proc in order to get fd on the object.
	 */
	procfd = open(path, O_RDONLY);
	if (procfd == -1)
		return (1);

	for (lmap = r_dbg->r_map; lmap; lmap = lmap->l_next) {
		loadobj.text_base = lmap->l_addr;
		loadobj.data_base = lmap->l_addr;
		loadobj.objname = lmap->l_name;
		/*
		 * client of this interface should deal with -1 for objfd,
		 * so no error checking is needed on this ioctl
		 */
		loadobj.objfd = ioctl(procfd, PIOCOPENM, &(lmap->l_addr));

		retval = obj_func(opq, &loadobj, cd);

		/* close the fd */
		if (loadobj.objfd != -1)
			close(loadobj.objfd);

		/* check for error */
		if (retval == 1)
			goto end_of_func;
	}

end_of_func:
	close(procfd);

	DBG_TNF_PROBE_0(inprocess_loadobj_iter_end, "libtnfctl",
			"end inprocess_loadobj_iter; sunw%verbosity 1");
	return (retval);
}

/*
 * The lock that prevents a thread from accessing our cached library list
 * and a dlopen or dlclose happening at the same time in another thread.
 */
mutex_t		_tnfctl_lmap_lock = DEFAULTMUTEX;

/*
 * The flag that indicates that the library list has changed via a
 * dlopen or dlclose.
 */
boolean_t	_tnfctl_libs_changed = B_FALSE;

/*
 * Thread id of the owner of the lock in order to implement a
 * recursive lock i.e. no deadlock if the same thread tries to lock
 * a lock it already holds.
 */
static thread_t	lock_holder = 0;	/* XXX - no tid with 0 */

#define	LMAP_LOCK	(&_tnfctl_lmap_lock)

/*
 * dlclose interposition with a recursive lock so that a .fini section
 * can recursively call dlopen or dlclose while holding _tnfctl_lmap_lock
 * This interposition serializes access to rtld's loadobject list and
 * also updates the flag _tnfctl_libs_changed to indicate a change in
 * the library list.  This flag is checked by operations that update
 * probes so that it can sync up with the new library list and potential
 * new/deleted probes.
 */
int
_tnfctl_dlclose(void *handle)
{
	static int (*real_dlclose)(void *handle) = NULL;
	int retval;
	thread_t tid;

	if (real_dlclose == NULL) {
		real_dlclose = (int (*)(void *)) dlsym(RTLD_NEXT, "dlclose");
	}
	assert(real_dlclose);

	if (mutex_trylock(LMAP_LOCK) != 0) {
		/* don't have lock */
		tid = thr_self();
		if (tid == lock_holder) {
			/* recursive dlopen/dlclose by same thread */
			return ((*real_dlclose)(handle));
		}
		/* not a recursive dlopen/dlclose - wait on lock */
		mutex_lock(LMAP_LOCK);
	}

	/* lock is held now */
	lock_holder = thr_self();
	retval = (*real_dlclose)(handle);

	/*
	 * reset lock_holder so that if _tnfctl_lmap_lock is held by some
	 * other part of the code, we don't assume it is a recursive
	 * dlopen/dlclose
	 */
	lock_holder = 0;
	_tnfctl_libs_changed = B_TRUE;
	mutex_unlock(LMAP_LOCK);

	return (retval);
}

/*
 * dlopen interposition with a recursive lock so that a .init section
 * can recursively call dlopen or dlclose while holding _tnfctl_lmap_lock
 * This interposition serializes access to rtld's loadobject list and
 * also updates the flag _tnfctl_libs_changed to indicate a change in
 * the library list.  This flag is checked by operations that update
 * probes so that it can sync up with the new library list and potential
 * new/deleted probes.
 */
void *
_tnfctl_dlopen(const char *pathname, int mode)
{
	static void * (*real_dlopen)(const char *, int) = NULL;
	void *retval;
	thread_t tid;

	if (real_dlopen == NULL) {
		real_dlopen = (void * (*)(const char *, int))
					dlsym(RTLD_NEXT, "dlopen");
	}
	assert(real_dlopen);

	if (mutex_trylock(LMAP_LOCK) != 0) {
		/* don't have lock */
		tid = thr_self();
		if (tid == lock_holder) {
			/* recursive dlopen/dlclose by same thread */
			return ((*real_dlopen)(pathname, mode));
		}
		/* not a recursive dlopen/dlclose - wait on lock */
		mutex_lock(LMAP_LOCK);
	}

	/* lock is held now */
	lock_holder = thr_self();
	retval = (*real_dlopen)(pathname, mode);

	/*
	 * reset lock_holder so that if _tnfctl_lmap_lock is held by some
	 * other part of the code, we don't assume it is a recursive
	 * dlopen/dlclose
	 */
	lock_holder = 0;
	_tnfctl_libs_changed = B_TRUE;
	mutex_unlock(LMAP_LOCK);

	return (retval);
}

tnfctl_errcode_t
_tnfctl_internal_getlock()
{
	mutex_lock(&_tnfctl_internalguard_lock);
	if (_tnfctl_internal_tracing_flag == 1) {
	/* internal trace control active */
	mutex_unlock(&_tnfctl_internalguard_lock);
	return (TNFCTL_ERR_BUSY);
	}
	_tnfctl_internal_tracing_flag = 1;
	if (_tnfctl_externally_traced_pid == getpid()) {
	/* external trace control is active */
	_tnfctl_internal_tracing_flag = 0;
	mutex_unlock(&_tnfctl_internalguard_lock);
	return (TNFCTL_ERR_BUSY);
	}
	DBG((void) fprintf(stderr, "_tnfctl_internal_getlock: ok to trace %d\n",
	getpid()));
	mutex_unlock(&_tnfctl_internalguard_lock);
	return (TNFCTL_ERR_NONE);
}
