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
 * Copyright (c) 1997-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _PRINTFUNCS_H
#define	_PRINTFUNCS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#ifdef	__cplusplus
extern "C" {
#endif

/* Types */
enum { CHAR, SHORT, UNSIGNED_SHORT, INT, UNSIGNED, LONG, UNSIGNED_LONG,
	CHAR_P, POINTER, FLOAT, LONG_LONG, UNSIGNED_LONG_LONG, VOID_,
	NONPRIMITIVE};

void generate_printf(ENTRY *);

/* Define, declare, initialize and use pointers to printfuncs. */
void generate_print_definitions(FILE *);
void generate_print_declarations(FILE *);
void generate_print_initializations(void);
void generate_printfunc_calls(ENTRY *); /* Use. */

int is_void(ENTRY *);

#ifdef	__cplusplus
}
#endif

#endif	/* _PRINTFUNCS_H */
