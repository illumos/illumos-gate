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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_MDB_KB_H
#define	_MDB_KB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * A KVM backend is used by the KVM target to interrogate the address space of
 * the subject binary.  This is almost always via direct calls into libkvm,
 * except for hypervisor core dumps, which implement its own backend via the
 * mdb_kb support module.
 */

#include <sys/types.h>
#include <mdb/mdb_io.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _MDB

struct as;
struct privmregs;

typedef struct mdb_kb_ops {
	void *(*kb_open)(const char *, const char *, const char *, int,
	    const char *);

	int (*kb_close)(void *);

	mdb_io_t *(*kb_sym_io)(void *, const char *);

	ssize_t (*kb_kread)(void *, uintptr_t, void *, size_t);
	ssize_t (*kb_kwrite)(void *, uintptr_t, const void *, size_t);
	ssize_t (*kb_aread)(void *, uintptr_t, void *, size_t, struct as *);
	ssize_t (*kb_awrite)(void *, uintptr_t, const void *,
	    size_t, struct as *);
	ssize_t (*kb_pread)(void *, uint64_t, void *, size_t);
	ssize_t (*kb_pwrite)(void *, uint64_t, const void *, size_t);

	uint64_t (*kb_vtop)(void *, struct as *, uintptr_t);

	int (*kb_getmregs)(void *, uint_t, struct privmregs *);
} mdb_kb_ops_t;

extern mdb_kb_ops_t *libkvm_kb_ops(void);

#endif	/* _MDB */

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_KB_H */
