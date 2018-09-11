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
 * Copyright 2014 Pluribus Networks Inc.
 */

#ifndef _COMPAT_FREEBSD_PTHREAD_NP_H_
#define	_COMPAT_FREEBSD_PTHREAD_NP_H_

#include <sys/param.h>
#include <sys/cpuset.h>

#include <synch.h>

#define	pthread_set_name_np(thread, name)

#define	pthread_mutex_isowned_np(x)	_mutex_held(x)

#endif	/* _COMPAT_FREEBSD_PTHREAD_NP_H_ */
