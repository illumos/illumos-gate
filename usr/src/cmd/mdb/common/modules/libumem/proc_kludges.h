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
 * Copyright 2000-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PROC_KLUDGES_H
#define	_PROC_KLUDGES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	KLUDGE_MAPWALK_NAME "__prockludge_mappings"

extern int prockludge_mappings_walk_init(mdb_walk_state_t *);
extern int prockludge_mappings_walk_step(mdb_walk_state_t *);
extern void prockludge_mappings_walk_fini(mdb_walk_state_t *);

extern void prockludge_add_walkers(void);
extern void prockludge_remove_walkers(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _PROC_KLUDGES_H */
