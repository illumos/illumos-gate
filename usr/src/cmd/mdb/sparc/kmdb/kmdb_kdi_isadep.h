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

#ifndef _KMDB_KDI_ISADEP_H
#define	_KMDB_KDI_ISADEP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/pte.h>

#ifdef __cplusplus
extern "C" {
#endif

struct regs;

extern int kmdb_kdi_get_stick(uint64_t *);
extern caddr_t kmdb_kdi_get_trap_vatotte(void);
extern void kmdb_kdi_kernpanic(struct regs *, uint_t);

#ifdef __cplusplus
}
#endif

#endif /* _KMDB_KDI_ISADEP_H */
