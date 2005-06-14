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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/fault.h>
#include <sys/signal.h>
#include <sys/siginfo.h>
#include <sys/debug.h>

int
sigaltstack(struct sigaltstack *ssp, struct sigaltstack *oss)
{
	klwp_t *lwp = ttolwp(curthread);
	struct sigaltstack ss;

	/*
	 * User's oss and ss might be the same address, so copyin first and
	 * save before copying out.
	 */
	if (ssp) {
		if (lwp->lwp_sigaltstack.ss_flags & SS_ONSTACK)
			return (set_errno(EPERM));
		if (copyin(ssp, &ss, sizeof (ss)))
			return (set_errno(EFAULT));
		if (ss.ss_flags & ~SS_DISABLE)
			return (set_errno(EINVAL));
		if (!(ss.ss_flags & SS_DISABLE) && ss.ss_size < MINSIGSTKSZ)
			return (set_errno(ENOMEM));
	}

	if (oss) {
		if (copyout(&lwp->lwp_sigaltstack,
		    oss, sizeof (struct sigaltstack)))
			return (set_errno(EFAULT));
	}

	if (ssp)
		lwp->lwp_sigaltstack = ss;

	return (0);
}

#ifdef _LP64
int
sigaltstack32(struct sigaltstack32 *ssp, struct sigaltstack32 *oss)
{
	klwp_t *lwp = ttolwp(curthread);
	struct sigaltstack   *ss;
	struct sigaltstack32 ss32, oss32;

	/*
	 * User's oss and ss might be the same address, so copyin first and
	 * save before copying out.
	 */
	if (ssp) {
		if (lwp->lwp_sigaltstack.ss_flags & SS_ONSTACK)
			return (set_errno(EPERM));
		if (copyin(ssp, &ss32, sizeof (ss32)))
			return (set_errno(EFAULT));
		if (ss32.ss_flags & ~SS_DISABLE)
			return (set_errno(EINVAL));
		if (!(ss32.ss_flags & SS_DISABLE) && ss32.ss_size < MINSIGSTKSZ)
			return (set_errno(ENOMEM));
	}

	if (oss) {
		/*
		 * copy to ILP32 struct before copyout.
		 */
		ss = &lwp->lwp_sigaltstack;
		oss32.ss_sp    = (caddr32_t)(uintptr_t)ss->ss_sp;
		oss32.ss_size  = (size32_t)ss->ss_size;
		oss32.ss_flags = ss->ss_flags;

		if (copyout(&oss32, oss, sizeof (oss32)))
			return (set_errno(EFAULT));
	}

	if (ssp) {
		ss = &lwp->lwp_sigaltstack;
		ss->ss_sp = (void *)(uintptr_t)ss32.ss_sp;
		ss->ss_size = (size_t)ss32.ss_size;
		ss->ss_flags = ss32.ss_flags;
	}

	return (0);
}
#endif /* _LP64 */
