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
 *	Copyright (c) 1991, Sun Microsystems, Inc.
 */
/*
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * DKI/DDI MT synchronization primitives.
 */

#ifndef _SYS_KSYNCH_H
#define	_SYS_KSYNCH_H

/*
 * Include the _real_ sys/sync.h to get the _lwp_... types
 */
#include <sys/synch.h>

/*
 * Lots of kernel headers we might want to use may
 * directly include sys/t_lock.h so provide a fake
 * that redirects to our shim.
 */
#include <sys/t_lock.h>

#endif	/* _SYS_KSYNCH_H */
