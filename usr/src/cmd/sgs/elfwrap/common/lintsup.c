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
/* LINTLIBRARY */
/* PROTOLIB1 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Supplemental Pseudo-code to get lint to consider these symbols used.
 */
#include	<msg.h>
#include	<_elfwrap.h>

void
foo()
{
	(void) _elfwrap_msg((Msg)&__elfwrap_msg[0]);
}

#if	defined(_ELF64)
int
input32(int argc, char **argv, const char *prog, const char *ofile,
    ObjDesc_t *odp)
{
	return (input64(argc, argv, prog, ofile, odp));
}

int
output32(const char *prog, int fd, const char *ofile, ushort_t mach,
    ObjDesc_t *odp)
{
	return (output64(prog, fd, ofile, mach, odp));
}
#else
int
input64(int argc, char **argv, const char *prog, const char *ofile,
    ObjDesc_t *odp)
{
	return (input32(argc, argv, prog, ofile, odp));
}
int
output64(const char *prog, int fd, const char *ofile, ushort_t mach,
    ObjDesc_t *odp)
{
	return (output32(prog, fd, ofile, mach, odp));
}
#endif
