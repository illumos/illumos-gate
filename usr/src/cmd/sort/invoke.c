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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * invoke
 *	display the field series resulting from a potentially complex sort
 *	invocation
 */

#include "main.h"

static void
display_field_defns(field_t *F)
{
	int i;

	for (i = 0; F != NULL; F = F->f_next, i++) {
		(void) fprintf(stderr, "%d. ", i);
		field_print(F);
		(void) fprintf(stderr, "\n");
	}
}

static void
display_global_defns(sort_t *S)
{
	if (S->m_field_separator.sc)
		(void) fprintf(stderr, "Delimiter: %c\n\n",
		    S->m_field_separator.sc);

}

int
main(int argc, char **argv)
{
	sort_t S;

	initialize_pre(&S);

	if (options(&S, argc, argv))
		return (E_ERROR);

	display_global_defns(&S);
	display_field_defns(S.m_fields_head);

	return (E_SUCCESS);
}
