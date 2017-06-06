/*
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
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
 * 3. Neither the name of the University nor the names of its contributors
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

#include "lint.h"
#include "file64.h"
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <regex.h>

#include "utils.h"
#include "../gen/_libc_gettext.h"

static const char *regatoi(const regex_t *preg, char *localbuf);

#define	RERR(x, msg)	{ x, #x, msg }

static struct rerr {
	int code;
	const char *name;
	const char *explain;
} rerrs[] = {
	RERR(REG_NOMATCH,	"regexec() failed to match"),
	RERR(REG_BADPAT,	"invalid regular expression"),
	RERR(REG_ECOLLATE,	"invalid collating element"),
	RERR(REG_ECTYPE,	"invalid character class"),
	RERR(REG_EESCAPE,	"trailing backslash (\\)"),
	RERR(REG_ESUBREG,	"invalid backreference number"),
	RERR(REG_EBRACK,	"brackets ([ ]) not balanced"),
	RERR(REG_EPAREN,	"parentheses not balanced"),
	RERR(REG_EBRACE,	"braces not balanced"),
	RERR(REG_BADBR,		"invalid repetition count(s)"),
	RERR(REG_ERANGE,	"invalid character range"),
	RERR(REG_ESPACE,	"out of memory"),
	RERR(REG_BADRPT,	"repetition-operator operand invalid"),
#ifdef	REG_EMPTY
	RERR(REG_EMPTY,		"empty (sub)expression"),
#endif
	RERR(REG_EFATAL,	"fatal internal error"),
#ifdef	REG_INVARG
	RERR(REG_INVARG,	"invalid argument to regex routine"),
#endif
	RERR(REG_ECHAR,		"illegal byte sequence"),
	RERR(REG_ENOSYS,	"function not supported"),
	RERR(REG_STACK,		"backtrack stack overflow"),
	RERR(REG_ENSUB,		"more than 9 \\( \\) pairs"),
	RERR(REG_ENEWLINE,	"\n found before end of pattern"),
	{0,	"",		"*** unknown regexp error code ***"}
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
	int target = errcode &~ REG_ITOA;
	const char *s;
	char convbuf[50];

	if (errcode == REG_ATOI) {
		s = regatoi(preg, convbuf);
	} else {
		for (r = rerrs; r->code != 0; r++) {
			if (r->code == target)
				break;
		}

		if (errcode&REG_ITOA) {
			if (r->code != 0)
				(void) strcpy(convbuf, r->name);
			else
				(void) sprintf(convbuf, "REG_0x%x", target);
			assert(strlen(convbuf) < sizeof (convbuf));
			s = convbuf;
		} else {
			s = _libc_gettext(r->explain);
		}
	}

	len = strlen(s) + 1;
	if (errbuf_size > 0) {
		if (errbuf_size > len) {
			(void) strcpy(errbuf, s);
		} else {
			(void) strncpy(errbuf, s, errbuf_size-1);
			errbuf[errbuf_size-1] = '\0';
		}
	}

	return (len);
}

/*
 * regatoi - internal routine to implement REG_ATOI
 */
static const char *
regatoi(const regex_t *preg, char *localbuf)
{
	struct rerr *r;

	for (r = rerrs; r->code != 0; r++) {
		if (strcmp(r->name, preg->re_endp) == 0)
			break;
	}
	if (r->code == 0)
		return ("0");

	(void) sprintf(localbuf, "%d", r->code);
	return (localbuf);
}
