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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/* LINTLIBRARY */
/* PROTOLIB1 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Supplemental Pseudo-code to get lint to consider these symbols used.
 */
#include	<sys/types.h>
#include	<libelf.h>
#include	<conv.h>
#include	<msg.h>
#include	<_elfdump.h>

void
foo()
{
	(void) _elfdump_msg((Msg)&__elfdump_msg[0]);
}

#if	defined(_ELF64)
void
regular32(const char *file, Elf *elf, uint32_t flags, char *Nname, int wfd)
{
	regular64(file, elf, flags, Nname, wfd);
}
#else
void
regular64(const char *file, Elf *elf, uint32_t flags, char *Nname, int wfd)
{
	regular32(file, elf, flags, Nname, wfd);
}
#endif
