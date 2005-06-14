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

#ifndef	_MDB_DISASM_H
#define	_MDB_DISASM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <mdb/mdb_target.h>
#include <mdb/mdb_modapi.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _MDB

/*
 * Forward declaration of the disassembler structure: the internals are defined
 * in mdb_disasm_impl.h and is opaque with respect to callers of this interface.
 */

struct mdb_disasm;
typedef struct mdb_disasm mdb_disasm_t;

/*
 * Disassemblers are created by calling mdb_dis_create() with a disassembler
 * constructor function.  A constructed disassembler can be selected (made
 * the current disassembler) by invoking mdb_dis_select().
 */

typedef int mdb_dis_ctor_f(mdb_disasm_t *);

extern int mdb_dis_select(const char *);
extern mdb_disasm_t *mdb_dis_create(mdb_dis_ctor_f *);
extern void mdb_dis_destroy(mdb_disasm_t *);

/*
 * Disassembler operations - instruction-to-string and backstep.
 */
extern mdb_tgt_addr_t mdb_dis_ins2str(mdb_disasm_t *, mdb_tgt_t *,
    mdb_tgt_as_t, char *, size_t, mdb_tgt_addr_t);
extern mdb_tgt_addr_t mdb_dis_previns(mdb_disasm_t *, mdb_tgt_t *,
    mdb_tgt_as_t, mdb_tgt_addr_t, uint_t);
extern mdb_tgt_addr_t mdb_dis_nextins(mdb_disasm_t *, mdb_tgt_t *,
    mdb_tgt_as_t, mdb_tgt_addr_t);

/*
 * Builtin dcmds for selecting and listing disassemblers:
 */
extern int cmd_dismode(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int cmd_disasms(uintptr_t, uint_t, int, const mdb_arg_t *);

#endif	/* _MDB */

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_DISASM_H */
