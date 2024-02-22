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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "ndrgen.h"

ndr_typeinfo_t	*typeinfo_list;
struct node	*construct_list;

int
main(void)
{
	set_lex_input(stdin, "(stdin)");

	if (yyparse() == 0) {
		analyze();
		generate();
		if (n_compile_error) {
			(void) printf("\n\n\n\n================\n\n\n\n");
			tdata_dump();
			show_typeinfo_list();
		}
	}

	if (n_compile_error)
		exit(1);

	return (0);
}

int
yyerror(const char *msg)
{
	compile_error("%s", msg);
	return (0);
}
