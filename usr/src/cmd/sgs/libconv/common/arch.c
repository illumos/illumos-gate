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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<unistd.h>
#include	<string.h>
#include	<sys/systeminfo.h>
#include	"_conv.h"
#include	"arch_msg.h"

/*
 * Determine if the 32-bit or 64-bit kernel is running.
 * Return the corresponding EI_CLASS constant.
 */
int
conv_sys_eclass(void)
{
	char buf[BUFSIZ];

	/*
	 * SI_ISALIST will return -1 on pre-2.6 machines,
	 * which is fine - it can't be a 64-bit kernel.
	 */
	if (sysinfo(SI_ISALIST, buf, BUFSIZ) == -1)
		return (ELFCLASS32);

	if ((strstr(buf, MSG_ORIG(MSG_ARCH_SPARCV9)) != NULL) ||
	    (strstr(buf, MSG_ORIG(MSG_ARCH_AMD64)) != NULL))
		return (ELFCLASS64);

	return (ELFCLASS32);
}

#if	defined(_LP64)
/* ARGSUSED */
uchar_t
conv_check_native(char **argv, char **envp)
{
	/* 64-bit version does nothing */
	return (ELFCLASS64);
}

#else

/*
 * Wrapper for isaexec(3c) that allows disabling 64-bit counterpart execution
 * via setting LD_NOEXEC64=yes.
 *
 * The only callers are 32-bit sgs applications.  These applications determine
 * whether a 64-bit counterpart is available via this routine, and if not,
 * control is passed back to the caller, who will then complete execution.
 * Note, isaexec() will eventually fall through to looking for a 32-bit
 * counterpart (ie. sparcv7, or sparc), but as none of the callers provide these
 * counterparts, we simply return to the caller.
 */
uchar_t
conv_check_native(char **argv, char **envp)
{
	const char	*str;

	/*
	 * LD_NOEXEC_64 defined in the environment prevents the isaexec() call.
	 * This is used by the test suite to test 32-bit support libraries.
	 */
	if (((str = getenv(MSG_ORIG(MSG_LD_NOEXEC64))) != NULL) && *str)
		return (ELFCLASS32);

	if ((str = getexecname()) != NULL)
		(void) isaexec(str, argv, envp);
	return (ELFCLASS32);
}
#endif
