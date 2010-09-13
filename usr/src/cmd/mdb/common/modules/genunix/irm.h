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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_IRM_H
#define	_IRM_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/mdb_modapi.h>

extern int	irmpools_walk_init(mdb_walk_state_t *);
extern int	irmreqs_walk_init(mdb_walk_state_t *);
extern int	irmpools_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int	irmreqs_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int	irmreq_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _IRM_H */
