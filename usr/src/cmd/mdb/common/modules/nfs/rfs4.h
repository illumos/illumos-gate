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

#ifndef _RFS4_H
#define	_RFS4_H

#include <sys/mdb_modapi.h>

extern int rfs4_db_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int rfs4_tbl_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
extern void rfs4_tbl_help(void);
extern int rfs4_idx_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
extern void rfs4_idx_help(void);
extern int rfs4_bkt_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int rfs4_oo_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int rfs4_osid_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int rfs4_file_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int rfs4_deleg_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int rfs4_lo_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int rfs4_lsid_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int rfs4_client_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
extern void rfs4_client_help(void);

extern int rfs4_db_tbl_walk_init(mdb_walk_state_t *);
extern int rfs4_db_tbl_walk_step(mdb_walk_state_t *);
extern int rfs4_db_idx_walk_init(mdb_walk_state_t *);
extern int rfs4_db_idx_walk_step(mdb_walk_state_t *);
extern int rfs4_db_bkt_walk_init(mdb_walk_state_t *);
extern int rfs4_db_bkt_walk_step(mdb_walk_state_t *);
extern void rfs4_db_bkt_walk_fini(mdb_walk_state_t *);

#endif	/* _RFS4_H */
