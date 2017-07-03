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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

#ifndef	_POLL_H
#define	_POLL_H

/*
 * Poll system call interface definitions.
 */

#include <sys/feature_tests.h>
#include <sys/poll.h>
#if defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX)
#include <time.h>
#include <signal.h>
#endif	/* defined(__EXTENSIONS__) ... */

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX)

extern int ppoll(struct pollfd *_RESTRICT_KYWD, nfds_t,
    const struct timespec *_RESTRICT_KYWD, const sigset_t *_RESTRICT_KYWD);

#endif	/* defined(__EXTENSIONS__) ... */

#ifdef __cplusplus
}
#endif

#endif	/* _POLL_H */
