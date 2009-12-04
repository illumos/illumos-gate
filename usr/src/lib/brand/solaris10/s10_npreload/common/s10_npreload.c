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
#include <stdlib.h>
#include <sys/syscall.h>

/*
 * This is a library that is LD_PRELOADed into native processes.
 * Its primary function is to perform one brand operation, B_S10_NATIVE,
 * which checks that this is actually a native process.  If it is, then
 * the operation changes the executable name so that it is no longer
 * ld.sol.1.  Instead it changes it to be the name of the real native
 * executable that we're runnning.  This allows things like pgrep to work
 * as expected.  Note that this brand operation only changes the process
 * name wrt the kernel.  From the process' perspective, the first
 * argument and AT_SUN_EXECNAME are still ld.so.1.
 *
 * The library also unsets the LD_LIBRARY_PATH_* and LD_PRELOAD_*
 * environment variables created by the brand's native wrapper scripts
 * (e.g., s10_isaexec_wrapper) in order to ensure that execve(2) and its
 * ilk, which brand the calling process, do not cause ld.so.1 to link native
 * libraries to the resulting process.  The native wrapper scripts make
 * LD_LIBRARY_PATH_* point to library directories (e.g., /usr/lib) prefixed
 * with "/.SUNWnative" in order to make native processes link with native
 * libraries.  However, if a native process running within a branded zone
 * executes exec(2), then the new process becomes branded.  Therefore, if this
 * library were to not unset the LD_LIBRARY_PATH_* environment variables, then
 * if a native process were to invoke an exec(2) function, then the resulting
 * process would be branded and linked with native libraries.
 * LD_PRELOAD_*, which the native wrapper scripts set to "s10_npreload.so.1"
 * (the name of this library), must be cleared as well because
 * s10_npreload.so.1 is only preloaded into native processes and can only be
 * accessed via the /.SUNWnative library paths.
 *
 * NOTE: This trick won't work if another library that invokes an exec(2)
 * function in its initialization function is initialized before this library.
 * Such a problem won't happen if the brand only replaces binaries shipped with
 * Solaris (e.g., ifconfig(1M)) with their native counterparts because most (if
 * not all) Solaris system libraries don't exec(2) within their initialization
 * functions.
 */
void
init(void)
{
	sysret_t rval;

	(void) __systemcall(&rval, SYS_brand, B_S10_NATIVE);

	/*
	 * We can safely use unsetenv(3C) to clear LD_LIBRARY_PATH_* and
	 * LD_PRELOAD_* because ld.so.1 caches their values before this
	 * library is initialized.
	 */
	(void) unsetenv("LD_LIBRARY_PATH_32");
	(void) unsetenv("LD_LIBRARY_PATH_64");
	(void) unsetenv("LD_PRELOAD_32");
	(void) unsetenv("LD_PRELOAD_64");
}
