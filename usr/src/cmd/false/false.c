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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2024 Oxide Computer Company
 */

#include <unistd.h>

/*
 * Exit with a non-zero value as quickly as possible.
 *
 * POSIX.1-2024 specifies an exit value between 1 and 125, inclusive, but a
 * survey of various shell builtin versions and other operating systems shows
 * that 1 is universally used, and some software erroneously expects exactly
 * that. For best compatibility and least surprise, we elect to do the same.
 */

int
main(void)
{
	_exit(1);
	/*NOTREACHED*/
	return (0);
}
