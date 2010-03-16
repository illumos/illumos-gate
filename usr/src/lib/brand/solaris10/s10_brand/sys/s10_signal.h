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

#ifndef _S10_SIGNAL_H
#define	_S10_SIGNAL_H

#ifdef	__cplusplus
extern "C" {
#endif

#if !defined(_ASM)

#include <sys/types.h>
#include <sys/signal.h>

extern pid_t zone_init_pid;

typedef void (*s10_sighandler_t)(int, siginfo_t *, void *);

#endif	/* !_ASM */

/*
 * Configurable in native Solaris, stick with the values assigned
 * by default as _SIGRTMIN and _SIGRTMAX in S10.
 */
#define	S10_SIGRTMIN	41
#define	S10_SIGRTMAX	48

#ifdef	__cplusplus
}
#endif

#endif	/* _S10_SIGNAL_H */
