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
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * libthread_db (tdb) cache
 *
 * In order to properly debug multi-threaded programs, the proc target must be
 * able to query and modify information such as a thread's register set using
 * either the native LWP services provided by libproc (if the process is not
 * linked with libthread), or using the services provided by libthread_db (if
 * the process is linked with libthread).  Additionally, a process may begin
 * life as a single-threaded process and then later dlopen() libthread, so we
 * must be prepared to switch modes on-the-fly.  There are also two possible
 * libthread implementations (one in /usr/lib and one in /usr/lib/lwp) so we
 * cannot link mdb against libthread_db directly; instead, we must dlopen the
 * appropriate libthread_db on-the-fly based on which libthread.so the victim
 * process has open.  Finally, mdb is designed so that multiple targets can be
 * active simultaneously, so we could even have *both* libthread_db's open at
 * the same time.  This might happen if you were looking at two multi-threaded
 * user processes inside of a crash dump, one using /usr/lib/libthread.so and
 * the other using /usr/lib/lwp/libthread.so.  To meet these requirements, we
 * implement a libthread_db "cache" in this file.  The proc target calls
 * mdb_tdb_load() with the pathname of a libthread_db to load, and if it is
 * not already open, we dlopen() it, look up the symbols we need to reference,
 * and fill in an ops vector which we return to the caller.  Once an object is
 * loaded, we don't bother unloading it unless the entire cache is explicitly
 * flushed.  This mechanism also has the nice property that we don't bother
 * loading libthread_db until we need it, so the debugger starts up faster.
 */

#include <mdb/mdb_tdb.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_err.h>

#include <strings.h>
#include <unistd.h>
#include <dlfcn.h>
#include <link.h>

static mdb_tdb_lib_t *tdb_list;

static td_err_e
tdb_notsup()
{
	return (TD_NOCAPAB); /* return thread_db code for not supported */
}

const mdb_tdb_ops_t *
mdb_tdb_load(const char *path)
{
	td_err_e (*tdb_init)(void);
	mdb_tdb_lib_t *t;
	td_err_e err;
	void *hdl;

	/*
	 * Search through the existing cache of thread_db libraries and see if
	 * we have this one loaded already.  If so, just return its ops vector.
	 */
	for (t = tdb_list; t != NULL; t = t->tdb_next) {
		if (strcmp(path, t->tdb_pathname) == 0)
			break;
	}

	if (t != NULL)
		return (&t->tdb_ops);

	/*
	 * Otherwise dlmopen the new library, look up its td_init() function,
	 * and call it.  If any of this fails, we return NULL for failure.
	 */
	if (access(path, F_OK) == -1)
		return (NULL);

	if ((hdl = dlmopen(LM_ID_BASE, path, RTLD_LAZY | RTLD_LOCAL)) == NULL) {
		(void) set_errno(EMDB_RTLD);
		return (NULL);
	}

	if ((tdb_init = (td_err_e (*)(void))dlsym(hdl, "td_init")) == NULL) {
		(void) dlclose(hdl);
		(void) set_errno(tdb_to_errno(TD_NOCAPAB));
		return (NULL);
	}

	if ((err = tdb_init()) != TD_OK) {
		(void) dlclose(hdl);
		(void) set_errno(tdb_to_errno(err));
		return (NULL);
	}

	/*
	 * If td_init() succeeds, we can't fail from here on.  Allocate a new
	 * library entry and add it to our linked list.
	 */
	t = mdb_alloc(sizeof (mdb_tdb_lib_t), UM_SLEEP);

	(void) strncpy(t->tdb_pathname, path, MAXPATHLEN);
	t->tdb_pathname[MAXPATHLEN - 1] = '\0';
	t->tdb_handle = hdl;
	t->tdb_next = tdb_list;
	tdb_list = t;

	/*
	 * For each function we need to call in the thread_db library, look it
	 * up using dlsym().  If we find it, add it to the ops vector.  If not,
	 * put the address of our default function (see above) in that slot.
	 */

	t->tdb_ops.td_ta_new = (td_err_e (*)())dlsym(hdl, "td_ta_new");
	if (t->tdb_ops.td_ta_new == NULL)
		t->tdb_ops.td_ta_new = (td_err_e (*)())tdb_notsup;

	t->tdb_ops.td_ta_delete = (td_err_e (*)())dlsym(hdl, "td_ta_delete");
	if (t->tdb_ops.td_ta_delete == NULL)
		t->tdb_ops.td_ta_delete = (td_err_e (*)())tdb_notsup;

	t->tdb_ops.td_ta_thr_iter = (td_err_e (*)())
	    dlsym(hdl, "td_ta_thr_iter");
	if (t->tdb_ops.td_ta_thr_iter == NULL)
		t->tdb_ops.td_ta_thr_iter = (td_err_e (*)())tdb_notsup;

	t->tdb_ops.td_ta_map_id2thr = (td_err_e (*)())
	    dlsym(hdl, "td_ta_map_id2thr");
	if (t->tdb_ops.td_ta_map_id2thr == NULL)
		t->tdb_ops.td_ta_map_id2thr = (td_err_e (*)())tdb_notsup;

	t->tdb_ops.td_ta_map_lwp2thr = (td_err_e (*)())
	    dlsym(hdl, "td_ta_map_lwp2thr");
	if (t->tdb_ops.td_ta_map_lwp2thr == NULL)
		t->tdb_ops.td_ta_map_lwp2thr = (td_err_e (*)())tdb_notsup;

	t->tdb_ops.td_thr_get_info = (td_err_e (*)())
	    dlsym(hdl, "td_thr_get_info");
	if (t->tdb_ops.td_thr_get_info == NULL)
		t->tdb_ops.td_thr_get_info = (td_err_e (*)())tdb_notsup;

	t->tdb_ops.td_thr_getgregs = (td_err_e (*)())
	    dlsym(hdl, "td_thr_getgregs");
	if (t->tdb_ops.td_thr_getgregs == NULL)
		t->tdb_ops.td_thr_getgregs = (td_err_e (*)())tdb_notsup;

	t->tdb_ops.td_thr_setgregs = (td_err_e (*)())
	    dlsym(hdl, "td_thr_setgregs");
	if (t->tdb_ops.td_thr_setgregs == NULL)
		t->tdb_ops.td_thr_setgregs = (td_err_e (*)())tdb_notsup;

	t->tdb_ops.td_thr_getfpregs = (td_err_e (*)())
	    dlsym(hdl, "td_thr_getfpregs");
	if (t->tdb_ops.td_thr_getfpregs == NULL)
		t->tdb_ops.td_thr_getfpregs = (td_err_e (*)())tdb_notsup;

	t->tdb_ops.td_thr_setfpregs = (td_err_e (*)())
	    dlsym(hdl, "td_thr_setfpregs");
	if (t->tdb_ops.td_thr_setfpregs == NULL)
		t->tdb_ops.td_thr_setfpregs = (td_err_e (*)())tdb_notsup;

	t->tdb_ops.td_thr_tlsbase = (td_err_e (*)())
	    dlsym(hdl, "td_thr_tlsbase");
	if (t->tdb_ops.td_thr_tlsbase == NULL)
		t->tdb_ops.td_thr_tlsbase = (td_err_e (*)())tdb_notsup;

	t->tdb_ops.td_thr_getxregsize = (td_err_e (*)())
	    dlsym(hdl, "td_thr_getxregsize");
	if (t->tdb_ops.td_thr_getxregsize == NULL)
		t->tdb_ops.td_thr_getxregsize = (td_err_e (*)())tdb_notsup;

	t->tdb_ops.td_thr_getxregs = (td_err_e (*)())
	    dlsym(hdl, "td_thr_getxregs");
	if (t->tdb_ops.td_thr_getxregs == NULL)
		t->tdb_ops.td_thr_getxregs = (td_err_e (*)())tdb_notsup;

	t->tdb_ops.td_thr_setxregs = (td_err_e (*)())
	    dlsym(hdl, "td_thr_setxregs");
	if (t->tdb_ops.td_thr_setxregs == NULL)
		t->tdb_ops.td_thr_setxregs = (td_err_e (*)())tdb_notsup;

	return (&t->tdb_ops);
}

void
mdb_tdb_flush(void)
{
	mdb_tdb_lib_t *t, *u;

	for (t = tdb_list; t != NULL; t = u) {
		u = t->tdb_next;
		(void) dlclose(t->tdb_handle);
		mdb_free(t, sizeof (mdb_tdb_lib_t));
	}

	tdb_list = NULL;
}
