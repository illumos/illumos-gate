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

#ifndef	_NVPAIR_H
#define	_NVPAIR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	NVPAIR_DCMD_NAME    "nvpair"
#define	NVPAIR_DCMD_USAGE   ":[-rq]"
#define	NVPAIR_DCMD_DESCR   "print out an nvpair"

#define	NVLIST_DCMD_NAME	"nvlist"
#define	NVLIST_DCMD_USAGE	":[-v]"
#define	NVLIST_DCMD_DESCR	"print out an nvlist"

#define	NVPAIR_WALKER_NAME  "nvpair"
#define	NVPAIR_WALKER_DESCR "walk through the nvpairs in an unpacked nvlist"

#ifdef _KERNEL
#define	NVPAIR_MODULE	"genunix"
#else /* _KERNEL */
#define	NVPAIR_MODULE	"libnvpair"
#endif /* _KERNEL */

#define	NVPAIR_DCMD_FQNAME	NVPAIR_MODULE"`"NVPAIR_DCMD_NAME
#define	NVPAIR_WALKER_FQNAME	NVPAIR_MODULE"`"NVPAIR_WALKER_NAME

extern int nvpair_walk_init(mdb_walk_state_t *wsp);
extern int nvpair_walk_step(mdb_walk_state_t *wsp);
extern int nvpair_print(uintptr_t addr, uint_t flags,
    int argc, const mdb_arg_t *argv);
extern int print_nvlist(uintptr_t addr, uint_t flags,
    int argc, const mdb_arg_t *argv);

#ifdef	__cplusplus
}
#endif

#endif	/* _NVPAIR_H */
