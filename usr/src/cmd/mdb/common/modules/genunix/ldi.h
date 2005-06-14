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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef	_MDB_LDI_H
#define	_MDB_LDI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* ldi handle walker routines */
extern int ldi_handle_walk_init(mdb_walk_state_t *);
extern int ldi_handle_walk_step(mdb_walk_state_t *);

/* ldi ident walker routines */
extern int ldi_ident_walk_init(mdb_walk_state_t *);
extern int ldi_ident_walk_step(mdb_walk_state_t *);

/* ::ldi_handle dcmd */
extern int ldi_handle(uintptr_t, uint_t, int, const mdb_arg_t *);
extern void ldi_handle_help(void);

/* ::ldi_identifier dcmd */
extern int ldi_ident(uintptr_t, uint_t, int, const mdb_arg_t *);
extern void ldi_ident_help(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_LDI_H */
