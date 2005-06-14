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
 * Copyright (c) 1996, by Sun Microsystems, Inc.
 * All rights reserved.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Define any exported data items.  These have to be described within an object
 * rather than a mapfile so that they are assigned to a valid section (and thus
 * do not result in absolute symbols). 
 *
 * Both of these symbols originate from libnsl.  h_error is an uninitialized
 * data item where as t_errno is initialized - the value provided here is
 * irrelevant but necessary to generate an appropriate copy relocation should
 * an application reference this symbol.
 */
int	h_errno;
int	t_errno = 0;
