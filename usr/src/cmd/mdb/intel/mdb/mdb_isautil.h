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
/*
 * Copyright (c) 2018, Joyent, Inc.  All rights reserved.
 * Copyright 2025 Oxide Computer Company
 */

#ifndef _MDB_ISAUTIL_H
#define	_MDB_ISAUTIL_H

#ifdef __cplusplus
extern "C" {
#endif

typedef uchar_t mdb_instr_t;

#ifdef __amd64
#include <mdb/mdb_amd64util.h>

#define	mdb_isa_printregs	mdb_amd64_printregs
#define	mdb_isa_kregs		mdb_amd64_kregs

#define	mdb_isa_step_out	mdb_amd64_step_out
#define	mdb_isa_next		mdb_amd64_next

#define	mdb_isa_kvm_stack_iter	mdb_amd64_kvm_stack_iter

#define	mdb_isa_kvm_frame	mdb_amd64_kvm_frame

#else
#include <mdb/mdb_ia32util.h>

#define	mdb_isa_printregs	mdb_ia32_printregs
#define	mdb_isa_kregs		mdb_ia32_kregs

#define	mdb_isa_step_out	mdb_ia32_step_out
#define	mdb_isa_next		mdb_ia32_next

#define	mdb_isa_kvm_stack_iter	mdb_ia32_kvm_stack_iter

#define	mdb_isa_kvm_frame	mdb_ia32_kvm_frame

#endif

#ifdef __cplusplus
}
#endif

#endif /* _MDB_ISAUTIL_H */
