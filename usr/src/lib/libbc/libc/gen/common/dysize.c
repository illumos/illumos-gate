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
#pragma ident	"%Z%%M%	%I%	%E% SMI"
	 /* from Arthur Olson's 3.1 */

/*LINTLIBRARY*/

#include <tzfile.h>

dysize(y)
{
	/*
	** The 4.[0123]BSD version of dysize behaves as if the return statement
	** below read
	**	return ((y % 4) == 0) ? DAYS_PER_LYEAR : DAYS_PER_NYEAR;
	** but since we'd rather be right than (strictly) compatible. . .
	*/
	return isleap(y) ? DAYS_PER_LYEAR : DAYS_PER_NYEAR;
}
