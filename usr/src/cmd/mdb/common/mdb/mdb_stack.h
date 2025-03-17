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
 * Copyright 2025 Oxide Computer Company
 */

#ifndef	_MDB_STACK_H
#define	_MDB_STACK_H

#include <sys/types.h>
#include <mdb/mdb_target.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef void mdb_stack_frame_hdl_t;

typedef enum {
	MSF_VERBOSE		= 1 << 0,
	MSF_TYPES		= 1 << 1,
	MSF_SIZES		= 1 << 2
} mdb_stack_frame_flags_t;

#define	MSF_ALL	(MSF_VERBOSE|MSF_TYPES|MSF_SIZES)

extern mdb_stack_frame_hdl_t *mdb_stack_frame_init(mdb_tgt_t *, uint_t,
    mdb_stack_frame_flags_t);
extern void mdb_stack_frame(mdb_stack_frame_hdl_t *, uintptr_t, uintptr_t,
    uint_t, const long *);
extern uint_t mdb_stack_frame_arglim(mdb_stack_frame_hdl_t *);
extern void mdb_stack_frame_flags_set(mdb_stack_frame_hdl_t *,
    mdb_stack_frame_flags_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_STACK_H */
