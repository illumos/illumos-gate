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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2018 Joyent, Inc.
 */

#include "lint.h"
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/types.h>

/*
 * Create a copy of string s, but only duplicate the first n bytes.
 * Return NULL if the new string can't be allocated.
 */
char *
strndup(const char *s1, size_t n)
{
	char *s2;

	n = strnlen(s1, n);
	if ((s2 = malloc(n + 1)) != NULL) {
		bcopy(s1, s2, n);
		s2[n] = '\0';
	}

	return (s2);
}
