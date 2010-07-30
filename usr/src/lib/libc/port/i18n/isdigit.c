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
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file contains the implementation of various functional forms
 * of the ctype tests, specifically the required by ISO C.  These are defined
 * in the "C" (POSIX) locale.
 */

#include "lint.h"
#include <ctype.h>

/*
 * We are supplying functional forms, so make sure to suppress any macros
 * we might have imported.
 */

#ifdef isblank
#undef isblank
#endif

int
isblank(int c)
{
	return (((unsigned)c > 255) ? 0 : (__ctype_mask[c] & _ISBLANK));
}

#ifdef isupper
#undef isupper
#endif

int
isupper(int c)
{
	return (((unsigned)c > 255) ? 0 : (__ctype_mask[c] & _ISUPPER));
}

#ifdef islower
#undef islower
#endif

int
islower(int c)
{
	return (((unsigned)c > 255) ? 0 : (__ctype_mask[c] & _ISLOWER));
}

#ifdef isdigit
#undef isdigit
#endif

int
isdigit(int c)
{
	return (((unsigned)c > 255) ? 0 : (__ctype_mask[c] & _ISDIGIT));
}

#ifdef isxdigit
#undef isxdigit
#endif

int
isxdigit(int c)
{
	return (((unsigned)c > 255) ? 0 : (__ctype_mask[c] & _ISXDIGIT));
}

#ifdef isalpha
#undef isalpha
#endif

int
isalpha(int c)
{
	return (((unsigned)c > 255) ? 0 : (__ctype_mask[c] & _ISALPHA));
}

#ifdef isalnum
#undef isalnum
#endif

int
isalnum(int c)
{
	return (((unsigned)c > 255) ? 0 : (__ctype_mask[c] & _ISALNUM));
}

#ifdef isspace
#undef isspace
#endif

int
isspace(int c)
{
	return (((unsigned)c > 255) ? 0 : (__ctype_mask[c] & _ISSPACE));
}

#ifdef iscntrl
#undef iscntrl
#endif

int
iscntrl(int c)
{
	return (((unsigned)c > 255) ? 0 : (__ctype_mask[c] & _ISCNTRL));
}

#ifdef isgraph
#undef isgraph
#endif

int
isgraph(int c)
{
	return (((unsigned)c > 255) ? 0 : (__ctype_mask[c] & _ISGRAPH));
}

#ifdef ispunct
#undef ispunct
#endif

int
ispunct(int c)
{
	return (((unsigned)c > 255) ? 0 : (__ctype_mask[c] & _ISPUNCT));
}

#ifdef isprint
#undef isprint
#endif

int
isprint(int c)
{
	return (((unsigned)c > 255) ? 0 : (__ctype_mask[c] & _ISPRINT));
}
