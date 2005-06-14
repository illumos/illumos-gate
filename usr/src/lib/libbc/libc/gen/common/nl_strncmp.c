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
 * Copyright 1988 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>

#define MAXSTR	256		/* use same value as used in strcoll */

int
nl_strncmp(s1, s2, n)
	char *s1;
	char *s2;
	int n;
{
	char ns1[MAXSTR+1];
	char ns2[MAXSTR+1];
	register int i;
	register char *p1, *p2;

	p1 = ns1;
	p2 = ns2;

	for (i = 0; i < n && i < MAXSTR; i++) {
		*p1++ = *s1++;
		*p2++ = *s2++;
	}
	*p1 = *p2 = '\0';

	return (strcoll(ns1, ns2));
}
