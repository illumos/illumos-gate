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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_MDB_WCB_H
#define	_MDB_WCB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <mdb/mdb_module.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Values for w_buftag, used as a guard to ensure that the walk state hasn't
 * overflowed into the wcb.  w_buftag is INITIAL when the wcb is first
 * allocated, ACTIVE when added to a frame, and PASSIVE when removed.
 */
#define	WCB_TAG_INITIAL	0xcbbabecb	/* Magic tag for initialized wcb */
#define	WCB_TAG_ACTIVE	0xcba1cba1	/* Magic tag for active wcb */
#define	WCB_TAG_PASSIVE	0xcbdeadcb	/* Magic tag for inactive wcb */

struct mdb_frame;			/* Forward declaration */

typedef struct mdb_wcb {
	mdb_walk_state_t w_state;	/* Walk soft state */
	uint32_t w_buftag;		/* WCB_TAG_* */
	int w_inited;			/* Set if we've called walk_init */
	struct mdb_wcb *w_lyr_head;	/* Link to head wcb in layer chain */
	struct mdb_wcb *w_lyr_link;	/* Link to next wcb in layer chain */
	struct mdb_wcb *w_link;		/* Link to next wcb in global chain */
	const mdb_iwalker_t *w_walker;	/* Walker corresponding to this wcb */
} mdb_wcb_t;

extern mdb_wcb_t *mdb_wcb_create(mdb_iwalker_t *, mdb_walk_cb_t,
    void *, uintptr_t);

extern void mdb_wcb_destroy(mdb_wcb_t *);
extern mdb_wcb_t *mdb_wcb_from_state(mdb_walk_state_t *);

extern void mdb_wcb_insert(mdb_wcb_t *, struct mdb_frame *);
extern void mdb_wcb_delete(mdb_wcb_t *, struct mdb_frame *);
extern void mdb_wcb_purge(mdb_wcb_t **);

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_WCB_H */
