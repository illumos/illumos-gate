/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_TSOL_H
#define	_TSOL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

extern int tnrh_walk_init(mdb_walk_state_t *);
extern int tnrh_walk_step(mdb_walk_state_t *);
extern void tnrh_walk_fini(mdb_walk_state_t *);

extern int tnrhtp_walk_init(mdb_walk_state_t *);
extern int tnrhtp_walk_step(mdb_walk_state_t *);
extern void tnrhtp_walk_fini(mdb_walk_state_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _TSOL_H */
