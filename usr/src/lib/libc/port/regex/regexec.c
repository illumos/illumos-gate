/*
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
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

/*
 * the outer shell of regexec()
 *
 * This file includes engine.c three times, after muchos fiddling with the
 * macros that code uses.  This lets the same code operate on two different
 * representations for state sets and characters.
 */
#include "lint.h"
#include "file64.h"
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <regex.h>
#include <wchar.h>
#include <wctype.h>
#include <note.h>
#include <assert.h>

#include "utils.h"
#include "regex2.h"

/* we want _NOTE, but not NOTE (which collides with our own use) */
#undef	NOTE

static size_t
xmbrtowc(wint_t *wi, const char *s, size_t n, mbstate_t *mbs, wint_t dummy)
{
	size_t nr;
	wchar_t wc;

	nr = mbrtowc(&wc, s, n, mbs);
	if (wi != NULL)
		*wi = wc;
	if (nr == 0)
		return (1);
	else if (nr == (size_t)-1 || nr == (size_t)-2) {
		(void) memset(mbs, 0, sizeof (*mbs));
		if (wi != NULL)
			*wi = dummy;
		return (1);
	} else
		return (nr);
}

static size_t
xmbrtowc_dummy(wint_t *wi, const char *s, size_t n, mbstate_t *mbs,
    wint_t dummy)
{
	_NOTE(ARGUNUSED(n));
	_NOTE(ARGUNUSED(mbs));
	_NOTE(ARGUNUSED(dummy));

	if (wi != NULL)
		*wi = (unsigned char)*s;
	return (1);
}

/* macros for manipulating states, small version */
#define	states	long
#define	states1	states		/* for later use in regexec() decision */
#define	CLEAR(v)	((v) = 0)
#define	SET0(v, n)	((v) &= ~((unsigned long)1 << (n)))
#define	SET1(v, n)	((v) |= (unsigned long)1 << (n))
#define	ISSET(v, n)	(((v) & ((unsigned long)1 << (n))) != 0)
#define	ASSIGN(d, s)	((d) = (s))
#define	EQ(a, b)	((a) == (b))
#define	STATEVARS	long dummy	/* dummy version */
#define	STATESETUP(m, n)	/* nothing */
#define	STATETEARDOWN(m)	/* nothing */
#define	SETUP(v)	((v) = 0)
#define	onestate	long
#define	INIT(o, n)	((o) = (unsigned long)1 << (n))
#define	INC(o)	((o) <<= 1)
#define	ISSTATEIN(v, o)	(((v) & (o)) != 0)
/* some abbreviations; note that some of these know variable names! */
/* do "if I'm here, I can also be there" etc without branches */
#define	FWD(dst, src, n)	((dst) |= ((unsigned long)(src)&(here)) << (n))
#define	BACK(dst, src, n)	((dst) |= ((unsigned long)(src)&(here)) >> (n))
#define	ISSETBACK(v, n)	(((v) & ((unsigned long)here >> (n))) != 0)
/* no multibyte support */
#define	XMBRTOWC	xmbrtowc_dummy
#define	ZAPSTATE(mbs)	((void)(mbs))
/* function names */
#define	SNAMES			/* engine.c looks after details */

#include "engine.c"

/* now undo things */
#undef	states
#undef	CLEAR
#undef	SET0
#undef	SET1
#undef	ISSET
#undef	ASSIGN
#undef	EQ
#undef	STATEVARS
#undef	STATESETUP
#undef	STATETEARDOWN
#undef	SETUP
#undef	onestate
#undef	INIT
#undef	INC
#undef	ISSTATEIN
#undef	FWD
#undef	BACK
#undef	ISSETBACK
#undef	SNAMES
#undef	XMBRTOWC
#undef	ZAPSTATE

/* macros for manipulating states, large version */
#define	states	char *
#define	CLEAR(v)	(void) memset(v, 0, m->g->nstates)
#define	SET0(v, n)	((v)[n] = 0)
#define	SET1(v, n)	((v)[n] = 1)
#define	ISSET(v, n)	((v)[n])
#define	ASSIGN(d, s)	(void) memcpy(d, s, m->g->nstates)
#define	EQ(a, b)	(memcmp(a, b, m->g->nstates) == 0)
#define	STATEVARS	long vn; char *space
#define	STATESETUP(m, nv) { (m)->space = malloc((nv)*(m)->g->nstates); \
	if ((m)->space == NULL) \
		return (REG_ESPACE); \
	(m)->vn = 0; }
#define	STATETEARDOWN(m)	{ free((m)->space); }
#define	SETUP(v)	((v) = &m->space[m->vn++ * m->g->nstates])
#define	onestate	long
#define	INIT(o, n)	((o) = (n))
#define	INC(o)	((o)++)
#define	ISSTATEIN(v, o)	((v)[o])
/* some abbreviations; note that some of these know variable names! */
/* do "if I'm here, I can also be there" etc without branches */
#define	FWD(dst, src, n)	((dst)[here+(n)] |= (src)[here])
#define	BACK(dst, src, n)	((dst)[here-(n)] |= (src)[here])
#define	ISSETBACK(v, n)	((v)[here - (n)])
/* no multibyte support */
#define	XMBRTOWC	xmbrtowc_dummy
#define	ZAPSTATE(mbs)	((void)(mbs))
/* function names */
#define	LNAMES			/* flag */

#include "engine.c"

/* multibyte character & large states version */
#undef	LNAMES
#undef	XMBRTOWC
#undef	ZAPSTATE
#define	XMBRTOWC	xmbrtowc
#define	ZAPSTATE(mbs)	(void) memset((mbs), 0, sizeof (*(mbs)))
#define	MNAMES

#include "engine.c"

/*
 * regexec - interface for matching
 *
 * We put this here so we can exploit knowledge of the state representation
 * when choosing which matcher to call.  Also, by this point the matchers
 * have been prototyped.
 */
int				/* 0 success, REG_NOMATCH failure */
regexec(const regex_t *_RESTRICT_KYWD preg, const char *_RESTRICT_KYWD string,
    size_t nmatch, regmatch_t pmatch[_RESTRICT_KYWD], int eflags)
{
	struct re_guts *g = preg->re_g;
#ifdef REDEBUG
#define	GOODFLAGS(f)	(f)
#else
#ifdef	REG_STARTEND
#define	GOODFLAGS(f)	((f)&(REG_NOTBOL|REG_NOTEOL|REG_STARTEND))
#else
#define	GOODFLAGS(f)	((f)&(REG_NOTBOL|REG_NOTEOL))
#endif
#endif

	if (preg->re_magic != MAGIC1 || g->magic != MAGIC2)
		return (REG_BADPAT);
	assert(!(g->iflags&BAD));
	if (g->iflags&BAD)		/* backstop for no-debug case */
		return (REG_BADPAT);
	eflags = GOODFLAGS(eflags);

	if (MB_CUR_MAX > 1)
		return (mmatcher(g, string, nmatch, pmatch, eflags));
#ifdef	REG_LARGE
	else if (g->nstates <= CHAR_BIT*sizeof (states1) && !(eflags&REG_LARGE))
#else
	else if (g->nstates <= CHAR_BIT*sizeof (states1))
#endif
		return (smatcher(g, string, nmatch, pmatch, eflags));
	else
		return (lmatcher(g, string, nmatch, pmatch, eflags));
}
