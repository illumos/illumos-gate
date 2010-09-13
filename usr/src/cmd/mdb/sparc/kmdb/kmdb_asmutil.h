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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _KMDB_ASMUTIL_H
#define	_KMDB_ASMUTIL_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int get_nwin(void);
extern uintptr_t get_fp(void);
extern void flush_windows(void);
extern uintptr_t cas(uintptr_t *, uintptr_t, uintptr_t);
extern void membar_producer(void);
extern void interrupts_on(void);
extern void interrupts_off(void);
extern caddr_t get_tba(void);
extern void *set_tba(void *);
extern uint64_t rdasi(uint32_t, uintptr_t);
extern void wrasi(uint32_t, uintptr_t, uint64_t);

#ifdef __cplusplus
}
#endif

#endif /* _KMDB_ASMUTIL_H */
