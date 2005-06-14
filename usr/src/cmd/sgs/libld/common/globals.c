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
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 *
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Global variables
 */
#include	<sys/elf.h>
#include	"msg.h"
#include	"_libld.h"

Ofl_desc	Ofl;		/* provided for signal handler */
Ld_heap *	ld_heap;	/* list of allocated blocks for */
				/* 	link-edit dynamic allocations */
List		lib_support;	/* List of support libraries specified */
				/*	(-S option) */

uint_t		dbg_mask = 0;	/* liblddbg enabled */

/*
 * Paths and directories for library searches.  These are used to set up
 * linked lists of directories which are maintained in the ofl structure.
 */
char		*Plibpath;	/* User specified -YP or defaults to LIBPATH */
char		*Llibdir;	/* User specified -YL */
char		*Ulibdir;	/* User specified -YU */
Listnode	*insert_lib;	/* insertion point for -L libraries */

/*
 * liblddbg sometimes takes an ehdr in order to figure out the elf class or
 * machine type.  Symbols that are added by ld, such as _etext, don't have a
 * corresponding ehdr, so we pass this instead.
 */
Ehdr		def_ehdr = { { ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3,
			M_CLASS, M_DATA }, 0, M_MACH };

/*
 * For backward compatibility provide a /dev/zero file descriptor.
 */
int		dz_fd = -1;

/*
 * Rejected file error messages (indexed to match FLG_RJC_ values).
 */
const Msg
reject[] = {
		MSG_STR_EMPTY,
		MSG_REJ_MACH,		/* MSG_INTL(MSG_REJ_MACH) */
		MSG_REJ_CLASS,		/* MSG_INTL(MSG_REJ_CLASS) */
		MSG_REJ_DATA,		/* MSG_INTL(MSG_REJ_DATA) */
		MSG_REJ_TYPE,		/* MSG_INTL(MSG_REJ_TYPE) */
		MSG_REJ_BADFLAG,	/* MSG_INTL(MSG_REJ_BADFLAG) */
		MSG_REJ_MISFLAG,	/* MSG_INTL(MSG_REJ_MISFLAG) */
		MSG_REJ_VERSION,	/* MSG_INTL(MSG_REJ_VERSION) */
		MSG_REJ_HAL,		/* MSG_INTL(MSG_REJ_HAL) */
		MSG_REJ_US3,		/* MSG_INTL(MSG_REJ_US3) */
		MSG_REJ_STR,		/* MSG_INTL(MSG_REJ_STR) */
		MSG_REJ_UNKFILE,	/* MSG_INTL(MSG_REJ_UNKFILE) */
		MSG_REJ_HWCAP_1,	/* MSG_INTL(MSG_REJ_HWCAP_1) */
	};
