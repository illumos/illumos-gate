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
 * Copyright (c) 1997-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_MDB_SIGNAL_H
#define	_MDB_SIGNAL_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <ucontext.h>
#include <signal.h>

typedef void mdb_signal_f(int, siginfo_t *, ucontext_t *, void *);

#ifdef _MDB

#define	MDB_SIG_DFL	(mdb_signal_f *)0
#define	MDB_SIG_IGN	(mdb_signal_f *)1

extern int mdb_signal_sethandler(int, mdb_signal_f *, void *);
extern mdb_signal_f *mdb_signal_gethandler(int, void **);

extern int mdb_signal_raise(int);
extern int mdb_signal_pgrp(int);

extern int mdb_signal_block(int);
extern int mdb_signal_unblock(int);

extern int mdb_signal_blockall(void);
extern int mdb_signal_unblockall(void);

#endif /* _MDB */

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_SIGNAL_H */
