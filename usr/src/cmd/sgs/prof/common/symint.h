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


	/* protect against multiple inclusion */
#ifndef _SYMINT_H
#define	_SYMINT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "symintHdr.h"

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * symint.c -- symbol information interface routines,
 *		interface definition.
 *
 * these routines form a symbol information access
 * interface, for the profilers to get at object file
 * information.  this interface was designed to aid
 * in the COFF to ELF conversion of prof, lprof and friends.
 *
 * this file includes all declarative information required
 * by a user of this interface.
 *
 * ASSUMPTIONS
 * ===========
 *
 * 1.	that there exists a routine _Malloc, with the following
 * 	(effective) prototype:
 * 		char * _Malloc (int item_count, int item_size);
 * 	which does NOT (necessarily) initialize the allocated storage,
 * 	and which issues an error message and calls exit() if
 * 	the storage could not be allocated.
 *
 */


/*
 * the interface routines:
 *
 * 	1. open an object file, set up PROF_FILE et al. (_symintOpen).
 * 	1. close an object file, clean up PROF_FILE et al. (_symintClose).
 *
 * the data:
 *
 * 	(none yet.)
 *
 */

PROF_FILE *_symintOpen(char *aout_name);	/* NULL or ptr */
void _symintClose(PROF_FILE *profPtr);		/* nuttin */
PROF_SYMBOL *_symintLoad(PROF_FILE *proffilePtr);

/*
 * required to be provided by the user of the interface...
 */

void *_Malloc(uint_t item_count, uint_t item_size);
void _err_exit(char *format_s, ...);

#ifdef  __cplusplus
}
#endif

#endif	/* _SYMINT_H */
