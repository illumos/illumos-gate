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

#ifndef _SVC_H
#define	_SVC_H

#include <mdb/mdb_modapi.h>

extern int svc_pool_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
extern void svc_pool_help(void);
extern int svc_mxprt_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
extern void svc_mxprt_help(void);

extern int svc_pool_walk_init(mdb_walk_state_t *);
extern int svc_pool_walk_step(mdb_walk_state_t *);
extern int svc_mxprt_walk_init(mdb_walk_state_t *);
extern int svc_mxprt_walk_step(mdb_walk_state_t *);

#endif	/* _SVC_H */
