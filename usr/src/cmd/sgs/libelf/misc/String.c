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
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * C++ Demangler Source Code
 * @(#)master	1.5
 * 7/27/88 13:54:37
 */
#include <stdio.h>
#include <setjmp.h>
#include <assert.h>
#include <string.h>
#include <malloc.h>
#include "elf_dem.h"
#include "String.h"

/*
 * This code emulates the C++ String package
 * in a crude way.
 */

jmp_buf jbuf;

/*
 * This function will expand the space
 * available to a String so that more data
 * can be appended to it
 */
static String *
grow(s)
String *s;
{
	String *ns;
	int sz = s->sg.max * 2;
	assert(sz > 0);
#ifdef ELF
	if ((ns = (String *)malloc(sz + sizeof (StringGuts) + 1)) == NULL)
		longjmp(jbuf, 1);
	(void) memcpy(ns, s, s->sg.max + sizeof (StringGuts) + 1);
	free(s);
#else
	if ((ns = (String *)realloc(s, sz + sizeof (StringGuts) + 1)) == NULL)
		longjmp(jbuf, 1);
#endif
	ns->sg.max = sz;
	return (ns);
}

/*
 * This function will expand the space
 * available to a String so that more data
 * can be prepended to it.
 */
static String *
ror(s, n)
String *s;
int n;
{
	assert(s != 0);
	while (s->sg.end + n > s->sg.max)
		s = grow(s);
#ifdef __STDC__
	assert(n >= 0);
	assert(s->sg.end >= s->sg.start);
	(void) memmove(s->data + n, s->data, s->sg.end - s->sg.start);
#else
	{
		int i;
		for (i = s->sg.end - 1; i >= s->sg.start; i--)
			s->data[i+n] = s->data[i];
	}
#endif
	s->sg.end += n;
	s->sg.start += n;
	s->data[s->sg.end] = 0;
	return (s);
}

/*
 * This function will prepend c
 * to s
 */
String *
prep_String(c, s)
char *c;
String *s;
{
	return (nprep_String(c, s, ID_NAME_MAX));
}

/*
 * This function will prepend the
 * first n characters of c to s
 */
String *
nprep_String(c, s, n)
const char *c;
String *s;
int n;
{
	int len = strlen(c);
	assert(s != 0);
	if (len > n)
		len = n;
	if (len > s->sg.start)
		s = ror(s, len - s->sg.start);
	s->sg.start -= len;
	(void) memcpy(s->data + s->sg.start, c, len);
	return (s);
}

/*
 * This function will append
 * c to s.
 */
String *
app_String(s, c)
String *s;
const char *c;
{
	return (napp_String(s, c, ID_NAME_MAX));
}

/*
 * This function will append the
 * first n characters of c to s
 */
String *
napp_String(String *s, const char *c, int n)
{
	int len = strlen(c);
	int catlen;
	assert(s != 0);
	if (n < len)
		len = n;
	catlen = s->sg.end + len;
	while (catlen > s->sg.max)
		s = grow(s);
	(void) memcpy(s->data + s->sg.end, c, len);
	s->sg.end += len;
	s->data[s->sg.end] = '\0';
	return (s);
}

/*
 * This function initializes a
 * String.  It returns its argument if
 * its argument is non-zero.
 * This prevents the same string
 * from being re-initialized.
 */
String *
mk_String(s)
String *s;
{
	if (s)
		return (s);
	s = (String *)malloc(STRING_START + sizeof (StringGuts) + 1);
	if (s == NULL)
		longjmp(jbuf, 1);
	s->sg.start = s->sg.end = STRING_START/2;
	s->sg.max = STRING_START;
	s->data[s->sg.end] = '\0';
	return (s);
}

void
free_String(s)
String *s;
{
	if (s)
		free(s);
}

/*
 * This function copies
 * c into s.
 * Used for initialization.
 */
String *
set_String(s, c)
String *s;
char *c;
{
	int len = strlen(c)*2;
	while (len > s->sg.max)
		s = grow(s);
	s->sg.start = s->sg.end = s->sg.max / 2;
	s = app_String(s, c);
	return (s);
}

/*
 * Chop n characters off the end of a string.
 * Return the truncated string.
 */
String *
trunc_String(String *s, int n)
{
	assert(n <= s->sg.end - s->sg.start);
	s->sg.end -= n;
	s->data[s->sg.end] = '\0';
	return (s);
}
