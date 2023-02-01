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
 * Copyright 1998-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Overview of sort(1)
 *
 * sort(1) implements a robust sorting program, compliant with the POSIX
 * specifications for sort, that is capable of handling large sorts and merges
 * in single byte and multibyte locales.  Like most sort(1) implementations,
 * this implementation uses an internal algorithm for sorting subsets of the
 * requested data set and an external algorithm for sorting the subsets into the
 * final output.  In the current implementation, the internal algorithm is a
 * ternary radix quicksort, modified from the algorithm described in Bentley and
 * Sedgewick [1], while the external algorithm is a priority-queue based
 * heapsort, as outlined in Sedgewick [2].
 *
 * We use three major datatypes, defined in ./types.h: the line record,
 * line_rec_t; the stream, stream_t; and the field definition, field_t.
 * Because sort supports efficient code paths for each of the C, single-byte,
 * and wide character/multibyte locales, each of these types contains unions
 * and/or function pointers to describe appropriate properties or operations for
 * each locale type.
 *
 * To utilize the radix quicksort algorithm with the potentially complex sort
 * keys definable via the POSIX standard, we convert each line to a collatable
 * string based on the key definition.  This approach is somewhat different from
 * historical implementations of sort(1), which have built a complex
 * field-by-field comparison function.  There are, of course, tradeoffs that
 * accompany this decision, particularly when the duration of use of a given
 * collated form is short.  However, the maintenance costs of parallel
 * conversion and collation functions are estimated to be high, and the
 * performance costs of a shared set of functions were found to be excessive in
 * prototype.
 *
 * [1]	J. Bentley and R. Sedgewick, Fast Algorithms for Sorting and Searching
 *	Strings, in Eighth Annual ACM-SIAM Symposium on Discrete Algorithms,
 *	1997 (SODA 1997),
 * [2]	R. Sedgewick, Algorithms in C, 3rd ed., vol. 1, Addison-Wesley, 1998.
 */

#include "main.h"

static sort_t S;

int
main(int argc, char *argv[])
{
	initialize_pre(&S);

	if (options(&S, argc, argv))
		return (2);

	initialize_post(&S);

	if (S.m_check_if_sorted_only)
		check_if_sorted(&S);

	if (!S.m_merge_only)
		internal_sort(&S);

	merge(&S);

	return (0);
}
