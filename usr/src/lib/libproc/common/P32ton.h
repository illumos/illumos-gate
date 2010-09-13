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

#ifndef	_P32TON_H
#define	_P32TON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/types32.h>
#include <sys/time_impl.h>
#include <sys/regset.h>
#include <sys/signal.h>
#include <sys/auxv.h>
#include <procfs.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern dev_t prexpldev(dev32_t);
extern dev32_t prcmpldev(dev_t);

#ifdef _LP64

extern void timestruc_32_to_n(const timestruc32_t *, timestruc_t *);
extern void stack_32_to_n(const stack32_t *, stack_t *);
extern void sigaction_32_to_n(const struct sigaction32 *, struct sigaction *);
extern void siginfo_32_to_n(const siginfo32_t *, siginfo_t *);
extern void auxv_32_to_n(const auxv32_t *, auxv_t *);

#if defined(__sparc)
extern void rwindow_32_to_n(const struct rwindow32 *, struct rwindow *);
extern void gwindows_32_to_n(const gwindows32_t *, gwindows_t *);
#endif

extern void prgregset_32_to_n(const prgreg32_t *, prgreg_t *);
extern void prfpregset_32_to_n(const prfpregset32_t *, prfpregset_t *);
extern void lwpstatus_32_to_n(const lwpstatus32_t *, lwpstatus_t *);
extern void pstatus_32_to_n(const pstatus32_t *, pstatus_t *);
extern void lwpsinfo_32_to_n(const lwpsinfo32_t *, lwpsinfo_t *);
extern void psinfo_32_to_n(const psinfo32_t *, psinfo_t *);

extern void timestruc_n_to_32(const timestruc_t *, timestruc32_t *);
extern void stack_n_to_32(const stack_t *, stack32_t *);
extern void sigaction_n_to_32(const struct sigaction *, struct sigaction32 *);
extern void siginfo_n_to_32(const siginfo_t *, siginfo32_t *);
extern void auxv_n_to_32(const auxv_t *, auxv32_t *);

extern void prgregset_n_to_32(const prgreg_t *, prgreg32_t *);
extern void prfpregset_n_to_32(const prfpregset_t *, prfpregset32_t *);
extern void lwpstatus_n_to_32(const lwpstatus_t *, lwpstatus32_t *);
extern void pstatus_n_to_32(const pstatus_t *, pstatus32_t *);
extern void lwpsinfo_n_to_32(const lwpsinfo_t *, lwpsinfo32_t *);
extern void psinfo_n_to_32(const psinfo_t *, psinfo32_t *);

#endif /* _LP64 */

#ifdef	__cplusplus
}
#endif

#endif	/* _P32TON_H */
