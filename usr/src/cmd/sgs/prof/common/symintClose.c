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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <unistd.h>
#include "symint.h"
#include "debug.h"

/*
 * symintFcns.c -- symbol information interface routines.
 *
 * these routines form a symbol information access
 * interface, for the profilers to get at object file
 * information.  this interface was designed to aid
 * in the COFF to ELF conversion of prof, lprof and friends.
 *
 */


/*
 * _symintClose(profPtr)
 * profPtr	- structure allocated by _symintOpen(),
 *		indicating structures to free and
 *		object file to close.
 *
 * specifically, elf_end() and fclose() are called for the object file,
 * and the PROF_SYMBOL and section hdr arrays are freed.
 *
 *
 * No Returns.
 */

void
_symintClose(PROF_FILE *profPtr)
{
	DEBUG_LOC("_symintClose: top");
	if (profPtr) {
		(void) elf_end(profPtr->pf_elf_p);
		(void) close(profPtr->pf_fildes);

		(void) free(profPtr->pf_shdarr_p);
		(void) free(profPtr->pf_symarr_p);
	}
	DEBUG_LOC("_symintClose: bottom");
}
