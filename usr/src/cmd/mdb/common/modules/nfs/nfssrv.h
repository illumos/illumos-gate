/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */
/*
 * Copyright 2021 Tintri by DDN, Inc. All rights reserved.
 */

#ifndef _NFSSRV_H
#define	_NFSSRV_H

#include <sys/mdb_modapi.h>

extern int nfs_expvis_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int nfs_expinfo_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int nfs_exptable_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int nfs_exptable_path_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int nfs_nstree_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
extern void nfs_nstree_help(void);
extern int nfs_fid_hashdist_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int nfs_path_hashdist_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
extern void nfs_hashdist_help(void);

struct exp_walk_arg {
	const char *name;	/* variable name with the exportinfo array */
	int size;		/* size of the exportinfo array */
	size_t offset;		/* offset for the walker */
};

extern struct exp_walk_arg nfs_expinfo_arg;
extern struct exp_walk_arg nfs_expinfo_path_arg;
extern int nfs_expinfo_walk_init(mdb_walk_state_t *);
extern void nfs_expinfo_walk_fini(mdb_walk_state_t *);
extern int nfs_expvis_walk_init(mdb_walk_state_t *);
extern int nfs_expvis_walk_step(mdb_walk_state_t *);

extern int nfssrv_globals_walk_init(mdb_walk_state_t *);
extern int nfssrv_globals_walk_step(mdb_walk_state_t *);

#endif	/* _NFSSRV_H */
