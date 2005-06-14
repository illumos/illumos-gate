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

#ifndef	_AMD64_AMD64_H
#define	_AMD64_AMD64_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/link.h>

#include <amd64/types.h>
#include <amd64/boothooks.h>

struct amd64_machregs;

extern void amd64_system_reset(void);

extern const char *amd64_getmmulist(void);
extern int amd64_config_cpu(void);

extern struct bootops64 *init_bootops64(struct bootops *);
extern struct boot_syscalls64 *init_boot_syscalls64(struct boot_syscalls *);

/*
 * These routines probably belong in machregs.h
 * Or we need to type the arguments as void * ..
 */
struct amd64_machregs;

extern void amd64_vtrap(struct amd64_machregs *);
extern void amd64_dump_amd64_machregs(struct amd64_machregs *);
extern void amd64_dump_memlist(const char *);

struct i386_machregs;
extern void amd64_dump_i386_machregs(struct i386_machregs *);

extern struct amd64_machregs *amd64_makectx64(uint64_t);

extern void amd64_exitto(struct amd64_machregs *);
extern void amd64_i386_clrtss(struct i386_machregs *);

#ifdef	__cplusplus
}
#endif

#endif	/* _AMD64_AMD64_H */
