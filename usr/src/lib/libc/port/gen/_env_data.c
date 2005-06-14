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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	Copyright (c) 1988 AT&T
 *	All Rights Reserved.
 *
 */

#include "lint.h"
#include <synch.h>

/*
 * NOTE: This symbol definition may occur in crt1.o.  This duplication is
 * required for building ABI compliant applications (see bugid 1181124).
 * To avoid any possible incompatibility with crt1.o the initialization of
 * this variable must not change.  If change is required a new mutex variable
 * should be created.
 */

mutex_t __environ_lock = DEFAULTMUTEX;
