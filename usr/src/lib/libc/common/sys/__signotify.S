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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

	.file	"__signotify.s"

#include "SYS.h"

/*
 * Unpublished system call for POSIX message queues.
 * int __signotify(int cmd, siginfo_t *siginfo, signotify_id_t *sn_id);
 */
	SYSCALL2_RVAL1(__signotify,signotify)
	RET
	SET_SIZE(__signotify)

/*
 * Unpublished system call to support deferred signals in libc.
 * int __sigresend(int sig, siginfo_t *siginfo, sigset_t *mask);
 */
	ENTRY(__sigresend)
	SYSTRAP_RVAL1(sigresend)
	SYSLWPERR
	RET
	SET_SIZE(__sigresend)
