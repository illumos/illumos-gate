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

#ifndef	_MDB_TDB_H
#define	_MDB_TDB_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _MDB

#include <sys/types.h>
#include <sys/param.h>
#include <thread_db.h>

typedef struct mdb_tdb_ops {
	td_err_e (*td_ta_new)(struct ps_prochandle *, td_thragent_t **);
	td_err_e (*td_ta_delete)(td_thragent_t *);
	td_err_e (*td_ta_thr_iter)(const td_thragent_t *, td_thr_iter_f *,
	    void *, td_thr_state_e, int, sigset_t *, uint_t);
	td_err_e (*td_ta_map_id2thr)(const td_thragent_t *,
	    thread_t, td_thrhandle_t *);
	td_err_e (*td_ta_map_lwp2thr)(const td_thragent_t *,
	    lwpid_t, td_thrhandle_t *);
	td_err_e (*td_thr_get_info)(const td_thrhandle_t *, td_thrinfo_t *);
	td_err_e (*td_thr_getgregs)(const td_thrhandle_t *, prgregset_t);
	td_err_e (*td_thr_setgregs)(const td_thrhandle_t *, const prgregset_t);
	td_err_e (*td_thr_getfpregs)(const td_thrhandle_t *, prfpregset_t *);
	td_err_e (*td_thr_setfpregs)(const td_thrhandle_t *,
	    const prfpregset_t *);
	td_err_e (*td_thr_tlsbase)(const td_thrhandle_t *, ulong_t, psaddr_t *);
	td_err_e (*td_thr_getxregsize)(const td_thrhandle_t *, int *);
	td_err_e (*td_thr_getxregs)(const td_thrhandle_t *, void *);
	td_err_e (*td_thr_setxregs)(const td_thrhandle_t *, const void *);
} mdb_tdb_ops_t;

typedef struct mdb_tdb_lib {
	char tdb_pathname[MAXPATHLEN];	/* Absolute pathname of library */
	mdb_tdb_ops_t tdb_ops;		/* Ops vector for this library */
	void *tdb_handle;		/* Library rtld object handle */
	struct mdb_tdb_lib *tdb_next;	/* Pointer to next library in cache */
} mdb_tdb_lib_t;

extern const mdb_tdb_ops_t *mdb_tdb_load(const char *);
extern void mdb_tdb_flush(void);

#endif	/* _MDB */

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_TDB_H */
