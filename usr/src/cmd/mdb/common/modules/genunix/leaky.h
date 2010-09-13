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

#ifndef	_LEAKY_H
#define	_LEAKY_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/systm.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern int leaky_walk_init(mdb_walk_state_t *);
extern int leaky_walk_step(mdb_walk_state_t *);
extern int leaky_buf_walk_step(mdb_walk_state_t *);
extern void leaky_walk_fini(mdb_walk_state_t *);

#define	FINDLEAKS_USAGE	"?[-dfv]"
extern int findleaks(uintptr_t, uint_t, int, const mdb_arg_t *);
extern void findleaks_help(void);

extern void leaky_cleanup(int);

#ifdef	__cplusplus
}
#endif

#endif	/* _LEAKY_H */
