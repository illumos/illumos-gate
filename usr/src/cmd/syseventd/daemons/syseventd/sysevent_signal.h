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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_DEVFSEVENT_SIGNAL_H
#define	_DEVFSEVENT_SIGNAL_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <ucontext.h>
#include <signal.h>

typedef void se_signal_f(int, siginfo_t *, ucontext_t *, void *);

#define	SE_SIG_DFL	(se_signal_f *)0
#define	SE_SIG_IGN	(se_signal_f *)1

extern int se_signal_sethandler(int, se_signal_f *, void *);
extern se_signal_f *se_signal_gethandler(int, void **);

extern int se_signal_raise(int);
extern int se_signal_pgrp(int);

extern int se_signal_block(int);
extern int se_signal_unblock(int);

extern int se_signal_blockall(void);
extern int se_signal_unblockall(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _DEVFSEVENT_SIGNAL_H */
