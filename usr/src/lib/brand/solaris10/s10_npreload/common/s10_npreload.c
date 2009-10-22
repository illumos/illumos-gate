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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma init(init)

#include <s10_brand.h>
#include <sys/syscall.h>

/*
 * This is a library that is LD_PRELOADed into native binaries.
 * All it does is one brand operation.  B_S10_NATIVE.  This brand
 * operation checks that this is actually a native binary, and then
 * if so changes the executable name so that it is no longer ld.sol.1.
 * Instead it changes it to be the name of the real native executable
 * that we're runnning.  This allows things like pgrep to work as
 * expected.  Note, that this brand opration only changes the process
 * name wrt the kernel.  From the processes perspective, the first
 * argument and AT_SUN_EXECNAME are still ld.so.1.
 */

void
init(void)
{
	sysret_t rval;
	(void) __systemcall(&rval, SYS_brand, B_S10_NATIVE);
}
