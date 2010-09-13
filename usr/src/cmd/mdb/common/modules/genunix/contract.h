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

#ifndef	_CONTRACT_H
#define	_CONTRACT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <mdb/mdb_modapi.h>

#ifdef	__cplusplus
extern "C" {
#endif

int ct_walk_init(mdb_walk_state_t *);
int ct_event_walk_init(mdb_walk_state_t *);
int ct_listener_walk_init(mdb_walk_state_t *);

int ct_common_walk_step(mdb_walk_state_t *);

int cmd_contract(uintptr_t, uint_t, int, const mdb_arg_t *);
int cmd_ctevent(uintptr_t, uint_t, int, const mdb_arg_t *);
int cmd_ctid(uintptr_t, uint_t, int, const mdb_arg_t *);
int cmd_ctmpl(uintptr_t, uint_t, int, const mdb_arg_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _CONTRACT_H */
