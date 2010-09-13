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

#ifndef	_MDB_DISASM_IMPL_H
#define	_MDB_DISASM_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Disassembler Implementation
 *
 * Each disassembler provides a string name (for selection with $V or -V),
 * a brief description, and the set of operations defined in mdb_dis_ops_t.
 * Currently the interface defined here is very primitive, but we hope to
 * greatly enhance it in the future if we have a two-pass disassembler.
 */

#include <mdb/mdb_disasm.h>
#include <mdb/mdb_module.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct mdb_dis_ops {
	void (*dis_destroy)(mdb_disasm_t *);
	mdb_tgt_addr_t (*dis_ins2str)(mdb_disasm_t *, mdb_tgt_t *,
	    mdb_tgt_as_t, char *, size_t, mdb_tgt_addr_t);
	mdb_tgt_addr_t (*dis_previns)(mdb_disasm_t *, mdb_tgt_t *,
	    mdb_tgt_as_t, mdb_tgt_addr_t, uint_t);
	mdb_tgt_addr_t (*dis_nextins)(mdb_disasm_t *, mdb_tgt_t *,
	    mdb_tgt_as_t, mdb_tgt_addr_t);
} mdb_dis_ops_t;

struct mdb_disasm {
	const char *dis_name;		/* Disassembler name */
	const char *dis_desc;		/* Brief description */
	mdb_module_t *dis_module;	/* Backpointer to containing module */
	const mdb_dis_ops_t *dis_ops;	/* Pointer to ops vector */
	void *dis_data;			/* Private storage */
};

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_DISASM_IMPL_H */
