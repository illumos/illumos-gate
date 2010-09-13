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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

	.file	"sparc_utrap_install.s"

#include "SYS.h"

/*
 * int
 * __sparc_utrap_install(utrap_entry_t type,
 *       utrap_handler_t new_precise, utrap_handler_t new_deferred,
 *       utrap_handler_t *old_precise, utrap_handler_t *old_deferred)
 */
	SYSCALL2_RVAL1(__sparc_utrap_install,sparc_utrap_install)
	RET
	SET_SIZE(__sparc_utrap_install)
