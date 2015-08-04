/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 Joyent, Inc.
 */

#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/lx_brand.h>

/* 'which' values. */
#define	LX_IOPRIO_WHO_PROCESS	1
#define	LX_IOPRIO_WHO_PGRP	2
#define	LX_IOPRIO_WHO_USER	3

/*
 * The possible values for the class. We report best effort (BE) as the class
 * in use.
 */
#define	LX_IOPRIO_CLASS_RT	1
#define	LX_IOPRIO_CLASS_BE	2
#define	LX_IOPRIO_CLASS_IDLE	3

/* Macro to determine the class from the input mask */
#define	LX_IOPRIO_PRIO_CLASS(m)	((m) >> 13)

/* ARGSUSED */
long
lx_ioprio_get(int which, int who)
{
	if (which < LX_IOPRIO_WHO_PROCESS || which > LX_IOPRIO_WHO_USER)
		return (set_errno(EINVAL));

	return (LX_IOPRIO_CLASS_BE);
}

/*
 * We allow setting any valid class, even though it's ignored.
 * We ignore the 'who' parameter which means that we're not searching for
 * the specified target in order to return a specific errno in the case that
 * the target does not exist.
 */
/* ARGSUSED */
long
lx_ioprio_set(int which, int who, int mask)
{
	int class;

	if (which < LX_IOPRIO_WHO_PROCESS || which > LX_IOPRIO_WHO_USER)
		return (set_errno(EINVAL));

	class = LX_IOPRIO_PRIO_CLASS(mask);
	if (class < LX_IOPRIO_CLASS_RT || class > LX_IOPRIO_CLASS_IDLE)
		return (set_errno(EINVAL));

	return (0);
}
