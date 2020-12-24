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
 * Copyright 2021 Joyent, Inc.
 */

#ifndef _MDB_LINKERSET_H
#define	_MDB_LINKERSET_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _MDB

extern int ldsets_walk_init(mdb_walk_state_t *);
extern int ldsets_walk_step(mdb_walk_state_t *);

extern int ldset_walk_init(mdb_walk_state_t *);
extern int ldset_walk_step(mdb_walk_state_t *);

extern int cmd_linkerset(uintptr_t, uint_t, int, const mdb_arg_t *);
extern void linkerset_help(void);
extern int cmd_linkerset_tab(mdb_tab_cookie_t *, uint_t, int,
    const mdb_arg_t *);

#endif /* _MDB */

#ifdef __cplusplus
}
#endif

#endif /* _MDB_LINKERSET_H */
