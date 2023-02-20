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

#ifndef _NFS_CLNT_H
#define	_NFS_CLNT_H

#include <sys/mdb_modapi.h>

#include "common.h"

extern int nfs_mntinfo_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
extern void nfs_mntinfo_help(void);
extern int nfs_servinfo_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
extern void nfs_servinfo_help(void);
extern int nfs4_mntinfo_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
extern void nfs4_mntinfo_help(void);
extern int nfs4_servinfo_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
extern void nfs4_servinfo_help(void);
extern int nfs4_server_info_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
extern void nfs4_server_info_help(void);
extern int nfs4_mimsg_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
extern void nfs4_mimsg_help(void);
extern int nfs4_fname_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int nfs4_foo_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int nfs4_oob_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int nfs4_os_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int nfs4_svnode_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);

extern hash_table_walk_arg_t nfs_rtable_arg;
extern int nfs_rtable_walk_init(mdb_walk_state_t *);
extern hash_table_walk_arg_t nfs_rtable4_arg;
extern int nfs_rtable4_walk_init(mdb_walk_state_t *);
extern int nfs_vfs_walk_init(mdb_walk_state_t *);
extern int nfs_vfs_walk_step(mdb_walk_state_t *);
extern void nfs_vfs_walk_fini(mdb_walk_state_t *);
extern int nfs_mnt_walk_init(mdb_walk_state_t *);
extern int nfs_mnt_walk_step(mdb_walk_state_t *);
extern void nfs_mnt_walk_fini(mdb_walk_state_t *);
extern int nfs4_mnt_walk_init(mdb_walk_state_t *);
extern int nfs4_mnt_walk_step(mdb_walk_state_t *);
extern void nfs4_mnt_walk_fini(mdb_walk_state_t *);
extern int nfs_serv_walk_init(mdb_walk_state_t *);
extern int nfs_serv_walk_step(mdb_walk_state_t *);
extern int nfs4_serv_walk_init(mdb_walk_state_t *);
extern int nfs4_serv_walk_step(mdb_walk_state_t *);
extern int nfs4_svnode_walk_init(mdb_walk_state_t *);
extern int nfs4_svnode_walk_step(mdb_walk_state_t *);
extern int nfs4_server_walk_init(mdb_walk_state_t *);
extern int nfs4_server_walk_step(mdb_walk_state_t *);
extern int nfs_async_walk_init(mdb_walk_state_t *);
extern int nfs_async_walk_step(mdb_walk_state_t *);
extern int nfs4_async_walk_init(mdb_walk_state_t *);
extern int nfs4_async_walk_step(mdb_walk_state_t *);
extern int nfs_acache_walk_init(mdb_walk_state_t *);
extern void nfs_acache_walk_fini(mdb_walk_state_t *);
extern int nfs_acache_rnode_walk_init(mdb_walk_state_t *);
extern int nfs_acache_rnode_walk_step(mdb_walk_state_t *);
extern int nfs_acache4_walk_init(mdb_walk_state_t *);
extern void nfs_acache4_walk_fini(mdb_walk_state_t *);
extern int nfs_acache4_rnode_walk_init(mdb_walk_state_t *);
extern int nfs_acache4_rnode_walk_step(mdb_walk_state_t *);

#endif	/* _NFS_CLNT_H */
