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

/* LINTLIBRARY */
/* PROTOLIB1 */

/*
 * Supplemental definitions for lint that help us avoid options like `-x' that
 * filter out things we want to know about as well as things we don't.
 */
#include <libelf.h>
#include <link.h>
#include <sgs.h>
#include <libld.h>
#include <rtld.h>
#include <conv.h>
#include <msg.h>
#include <sys/debug.h>

/*
 * Get the Elf32 side to think that the _ELF64 side
 * is defined, and vice versa.
 */
#if	defined(_ELF64)
#undef	_ELF64
#include <debug.h>
#define	_ELF64
#else
#define	_ELF64
#include <debug.h>
#undef	_ELF64
#endif

void	Dbg_reloc_doactiverel(void);

void
foo()
{
	assfail3(NULL, 0, NULL, 0, NULL, 0);
}
