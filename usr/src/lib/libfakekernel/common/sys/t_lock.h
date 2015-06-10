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
 * Copyright (c) 1991-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * t_lock.h:	Prototypes for disp_locks, plus include files
 *		that describe the interfaces to kernel synch.
 *		objects.
 */

#ifndef _SYS_T_LOCK_H
#define	_SYS_T_LOCK_H

/* these two are real */
#include <sys/machlock.h>
#include <sys/param.h>

/* the rest are fake */
#include <sys/mutex.h>
#include <sys/rwlock.h>
#include <sys/semaphore.h>
#include <sys/condvar.h>

/*
 * The real sys/semaphore.h pulls in sys/thread and some headers
 * using sys/t_lock.h rely on that, so let's pull it in here too.
 * Note that sys/thread.h includes sys/t_lock.h too (a cycle) but
 * that's OK thanks to the multi-include guards.
 */
#if defined(_KERNEL) || defined(_FAKE_KERNEL)
#include <sys/thread.h>
#endif

#endif	/* _SYS_T_LOCK_H */
