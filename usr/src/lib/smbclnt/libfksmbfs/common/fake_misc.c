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
 * Copyright (c) 1994, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012, 2017 by Delphix. All rights reserved.
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/cred.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>

volatile int ncsize = 500;	/* dnlc.h */

static major_t devcnt = 0x280;
static kmutex_t udevlock;

/* os/subr.c */
major_t
getudev()
{
	static major_t next = 0;
	major_t ret;

	mutex_enter(&udevlock);
	if (next == 0)
		next = devcnt;
	if (next <= L_MAXMAJ32 && next >= devcnt)
		ret = next++;
	else {
		cmn_err(CE_WARN, "out of major numbers");
		ret = ((major_t)-1);
	}
	mutex_exit(&udevlock);
	return (ret);
}

/*
 * Compress 'long' device number encoding to 32-bit device number
 * encoding.  If it won't fit, we return failure, but set the
 * device number to 32-bit NODEV for the sake of our callers.
 */
int
cmpldev(dev32_t *dst, dev_t dev)
{
#if defined(_LP64)
	if (dev == NODEV) {
		*dst = (dev32_t)(-1);
	} else {
		major_t major = dev >> L_BITSMINOR;
		minor_t minor = dev & L_MAXMIN;

		if (major > L_MAXMAJ32 || minor > L_MAXMIN32) {
			*dst = (dev32_t)(-1);
			return (0);
		}

		*dst = (dev32_t)((major << L_BITSMINOR32) | minor);
	}
#else
	*dst = (dev32_t)dev;
#endif
	return (1);
}

/* os/cred.c */
int
groupmember(gid_t gid, const cred_t *cr)
{
	if (gid == 0 || gid == 1)
		return (1);
	return (0);
}

/* os/sig.c */

/* ARGSUSED */
void
sigintr(k_sigset_t *smask, int intable)
{
}

/* ARGSUSED */
void
sigunintr(k_sigset_t *smask)
{
}
