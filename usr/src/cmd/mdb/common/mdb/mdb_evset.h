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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_MDB_EVSET_H
#define	_MDB_EVSET_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_MDB

extern void cmd_event(mdb_tgt_t *, int, void *);
extern int cmd_evset(uintptr_t, uint_t, int, const mdb_arg_t *);

extern int cmd_bp(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int cmd_sigbp(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int cmd_sysbp(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int cmd_fltbp(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int cmd_wp(uintptr_t, uint_t, int, const mdb_arg_t *);

extern int cmd_oldbp(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int cmd_oldwpr(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int cmd_oldwpw(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int cmd_oldwpx(uintptr_t, uint_t, int, const mdb_arg_t *);

extern void bp_help(void);
extern void evset_help(void);
extern void fltbp_help(void);
extern void sigbp_help(void);
extern void sysbp_help(void);
extern void wp_help(void);

#endif	/* _MDB */

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_EVSET_H */
