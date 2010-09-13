/*
 * Copyright (c) 1992, 1993, 1994 Henry Spencer.
 * Copyright (c) 1992, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Henry Spencer.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "lint.h"
#include "file64.h"
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <regex.h>

#include "utils.h"

static struct rerr {
	int code;
	char *name;
	char *explain;
} rerrs[] = {
	{REG_NOMATCH,	"REG_NOMATCH",	"regexec() failed to match"},
	{REG_BADPAT,	"REG_BADPAT",	"invalid regular expression"},
	{REG_ECOLLATE,	"REG_ECOLLATE",	"invalid collating element"},
	{REG_ECTYPE,	"REG_ECTYPE",	"invalid character class"},
	{REG_EESCAPE,	"REG_EESCAPE",	"trailing backslash (\\)"},
	{REG_ESUBREG,	"REG_ESUBREG",	"invalid backreference number"},
	{REG_EBRACK,	"REG_EBRACK",	"brackets ([ ]) not balanced"},
	{REG_EPAREN,	"REG_EPAREN",	"parentheses not balanced"},
	{REG_EBRACE,	"REG_EBRACE",	"braces not balanced"},
	{REG_BADBR,	"REG_BADBR",	"invalid repetition count(s)"},
	{REG_ERANGE,	"REG_ERANGE",	"invalid character range"},
	{REG_ESPACE,	"REG_ESPACE",	"out of memory"},
	{REG_BADRPT,	"REG_BADRPT",	"repetition-operator operand invalid"},
#ifdef	REG_EMPTY
	{REG_EMPTY,	"REG_EMPTY",	"empty (sub)expression"},
#endif
	{REG_EFATAL,	"REG_EFATAL",	"\"can't happen\" -- you found a bug"},
#ifdef	REG_INVARG
	{REG_INVARG,	"REG_INVARG",	"invalid argument to regex routine"},
#endif
	{REG_ECHAR,	"REG_ECHAR",	"illegal byte sequence"},
	{REG_ENOSYS,	"REG_ENOSYS",	"function not supported"},
	{REG_STACK,	"REG_STACK",	"backtrack stack overflow"},
	{REG_ENSUB,	"REG_ENSUB",	"more than 9 \\( \\) pairs"},
	{REG_ENEWLINE,	"REG_ENEWLINE",	"\n found before end of pattern"},
	{0,		"",		"*** unknown regexp error code ***"}
};


/*
 * regerror - the interface to error numbers
 */
/* ARGSUSED */
size_t
regerror(int errcode, const regex_t *_RESTRICT_KYWD preg,
    char *_RESTRICT_KYWD errbuf, size_t errbuf_size)
{
	struct rerr *r;
	size_t len;
	char *s;

	for (r = rerrs; r->code != 0; r++)
		if (r->code == errcode)
			break;

	s = r->explain;

	len = strlen(s) + 1;
	if (errbuf_size > 0) {
		if (errbuf_size > len)
			(void) strcpy(errbuf, s);
		else {
			(void) strncpy(errbuf, s, errbuf_size-1);
			errbuf[errbuf_size-1] = '\0';
		}
	}

	return (len);
}
