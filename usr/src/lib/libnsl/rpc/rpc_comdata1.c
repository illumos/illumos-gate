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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * FD_SETSIZE definition must precede any save isa_defs.h since that
 * is where _LP64 is defined....
 */
#include "mt.h"
#include <sys/isa_defs.h>
#if !defined(_LP64)
#ifdef FD_SETSIZE
#undef FD_SETSIZE
#endif
#define	FD_SETSIZE 65536

#include <sys/select.h>

/*
 * This file should only contain common data (global data) that is exported
 * by public interfaces
 */

/*
 * Definition of alternate fd_set for svc_fdset to be used when
 * someone redefine SVC_FDSETSIZE. This is here solely to
 * protect against someone doing a svc_fdset = a_larger_fd_set.
 * If we're not a 64 bit app and someone defines fd_setsize > 1024
 * then svc_fdset is redefined to be _new_svc_fdset (in <rpc/svc.h>)
 * which we size here at the maximum size.
 */

fd_set _new_svc_fdset;
#else

#include <sys/select.h>

extern fd_set svc_fdset;	/* to avoid "empty translation unit" */
#endif
