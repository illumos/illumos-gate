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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#pragma init(init)

#include <s10_brand.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <dlfcn.h>
#include <link.h>
#include <limits.h>
#include <sys/mman.h>
#include <strings.h>

/* MAXCOMLEN is only defined in user.h in the kernel. */
#define	MAXCOMLEN	16

/*
 * This is a library that is LD_PRELOADed into native processes.
 * Its primary function is to perform one brand operation, B_S10_NATIVE,
 * which checks that this is actually a native process.  If it is, then
 * the operation changes the executable name so that it is no longer
 * ld.so.1.  Instead it changes it to be the name of the real native
 * executable that we're runnning.  This allows things like pgrep to work
 * as expected.  Note that this brand operation only changes the process
 * name wrt the kernel.  From the process' perspective, AT_SUN_EXECNAME is
 * still ld.so.1. ld.so.1 removes itself and its arguments from the argv list.
 */
void
init(void)
{
	int i;
	Dl_argsinfo_t argsinfo;
	sysret_t rval;
	char	*pcomm;
	char	cmd_buf[MAXCOMLEN + 1];
	char	arg_buf[PSARGSZ];

	if (dlinfo(RTLD_SELF, RTLD_DI_ARGSINFO, &argsinfo) == -1)
		return;

	/* get the base cmd name */
	if ((pcomm = strrchr(argsinfo.dla_argv[0], '/')) != NULL)
		pcomm = pcomm + 1;
	else
		pcomm = argsinfo.dla_argv[0];
	(void) strlcpy(cmd_buf, pcomm, sizeof (cmd_buf));

	(void) strlcpy(arg_buf, argsinfo.dla_argv[0], sizeof (arg_buf));

	for (i = 1; i < argsinfo.dla_argc; i++) {
		(void) strlcat(arg_buf, " ", sizeof (arg_buf));
		if (strlcat(arg_buf, argsinfo.dla_argv[i], sizeof (arg_buf))
		    >= sizeof (arg_buf))
			break;
	}

	(void) __systemcall(&rval, SYS_brand, B_S10_NATIVE, cmd_buf, arg_buf);
}
