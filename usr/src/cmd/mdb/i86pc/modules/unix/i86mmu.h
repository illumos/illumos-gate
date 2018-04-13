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
 *
 * Copyright 2018 Joyent, Inc.
 */

#ifndef	_I86MMU_H
#define	_I86MMU_H

#ifdef	__cplusplus
extern "C" {
#endif

extern int pte_dcmd(uintptr_t addr, uint_t flags, int argc,
	const mdb_arg_t *argv);

extern int report_maps_dcmd(uintptr_t addr, uint_t flags, int argc,
	const mdb_arg_t *argv);

extern int htables_dcmd(uintptr_t addr, uint_t flags, int argc,
	const mdb_arg_t *argv);

extern int ptable_dcmd(uintptr_t addr, uint_t flags, int argc,
	const mdb_arg_t *argv);

extern int ptmap_dcmd(uintptr_t addr, uint_t flags, int argc,
	const mdb_arg_t *argv);

extern int va2pfn_dcmd(uintptr_t addr, uint_t flags, int argc,
	const mdb_arg_t *argv);

extern int mfntopfn_dcmd(uintptr_t addr, uint_t flags, int argc,
	const mdb_arg_t *argv);

extern int pfntomfn_dcmd(uintptr_t addr, uint_t flags, int argc,
	const mdb_arg_t *argv);

extern int memseg_list(uintptr_t addr, uint_t flags, int argc,
	const mdb_arg_t *argv);

extern int memseg_walk_init(mdb_walk_state_t *);
extern int memseg_walk_step(mdb_walk_state_t *);
extern void memseg_walk_fini(mdb_walk_state_t *);

extern void free_mmu(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _I86MMU_H */
