/*
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Guido van Rossum.
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
 * Copyright (c) 2013 Gary Mills
 */

/*
 * glob(3) -- a superset of the one defined in POSIX 1003.2.
 *
 * The [!...] convention to negate a range is supported (SysV, Posix, ksh).
 *
 * Optional extra services, controlled by flags not defined by POSIX:
 *
 * GLOB_QUOTE:
 *	Escaping convention: \ inhibits any special meaning the following
 *	character might have (except \ at end of string is retained).
 * GLOB_MAGCHAR:
 *	Set in gl_flags if pattern contained a globbing character.
 * GLOB_NOMAGIC:
 *	Same as GLOB_NOCHECK, but it will only append pattern if it did
 *	not contain any magic characters.  [Used in csh style globbing]
 * GLOB_ALTDIRFUNC:
 *	Use alternately specified directory access functions.
 * GLOB_TILDE:
 *	expand ~user/foo to the /home/dir/of/user/foo
 * GLOB_BRACE:
 *	expand {1,2}{a,b} to 1a 1b 2a 2b
 * gl_matchc:
 *	Number of matches in the current invocation of glob.
 */

#include "lint.h"

#include <sys/param.h>
#include <sys/stat.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <glob.h>
#include <limits.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wchar.h>
#include <wctype.h>

/*
 * This is the legacy glob_t prior to illumos enhancement 1097,
 * used when old programs call the old libc glob functions.
 * (New programs call the _glob_ext, _globfree_ext functions.)
 * This struct should be considered "carved in stone".
 */
typedef	struct	old_glob	{
	size_t	gl_pathc;		/* Count of paths matched by pattern */
	char	**gl_pathv;		/* List of matched pathnames */
	size_t	gl_offs;		/* # of slots reserved in gl_pathv */
	/* following are internal to the implementation */
	char	**gl_pathp;		/* gl_pathv + gl_offs */
	int	gl_pathn;		/* # of elements allocated */
}	old_glob_t;

/*
 * For old programs, the external names need to be the old names:
 * glob() and globfree() .  We've redefined those already to
 *  _glob_ext() and _globfree_ext() .  Now redefine old_glob()
 * and old_globfree() to glob() and globfree() .
 */
#ifdef __PRAGMA_REDEFINE_EXTNAME
#pragma	redefine_extname	old_glob	glob
#pragma	redefine_extname	old_globfree	globfree
#endif /* __PRAGMA_REDEFINE_EXTNAME */
extern int old_glob(const char *, int, int (*)(const char *, int),
    old_glob_t *);
extern void old_globfree(old_glob_t *);

/*
 * The various extensions to glob(3C) allow for stat and dirent structures to
 * show up whose size may change in a largefile environment. If libc defines
 * _FILE_OFFSET_BITS to be 64 that is the key to indicate that we're building
 * the LFS version of this file. As such, we rename the public functions here,
 * _glob_ext() and _globfree_ext() to have a 64 suffix. When building the LFS
 * version, we do not include the old versions.
 */
#if !defined(_LP64) && _FILE_OFFSET_BITS == 64
#define	_glob_ext	_glob_ext64
#define	_globfree_ext	_globfree_ext64
#endif	/* !_LP64 && _FILE_OFFSET_BITS == 64 */

#define	DOLLAR		'$'
#define	DOT		'.'
#define	EOS		'\0'
#define	LBRACKET	'['
#define	NOT		'!'
#define	QUESTION	'?'
#define	QUOTE		'\\'
#define	RANGE		'-'
#define	RBRACKET	']'
#define	SEP		'/'
#define	STAR		'*'
#define	TILDE		'~'
#define	UNDERSCORE	'_'
#define	LBRACE		'{'
#define	RBRACE		'}'
#define	SLASH		'/'
#define	COMMA		','
#define	COLON		':'

#define	M_QUOTE		0x800000
#define	M_PROTECT	0x400000

typedef struct wcat {
	wchar_t w_wc;
	uint_t w_at;
} wcat_t;

#define	M_ALL		'*'	/* Plus M_QUOTE */
#define	M_END		']'	/* Plus M_QUOTE */
#define	M_NOT		'!'	/* Plus M_QUOTE */
#define	M_ONE		'?'	/* Plus M_QUOTE */
#define	M_RNG		'-'	/* Plus M_QUOTE */
#define	M_SET		'['	/* Plus M_QUOTE */
#define	M_CLASS		':'	/* Plus M_QUOTE */
#define	ismeta(c)	(((c).w_at&M_QUOTE) != 0)

#define	INITIAL			8	/* initial pathv allocation */

#define	GLOB_LIMIT_MALLOC	65536
#define	GLOB_LIMIT_STAT		2048
#define	GLOB_LIMIT_READDIR	16384

struct glob_lim {
	size_t	glim_malloc;
	size_t	glim_stat;
	size_t	glim_readdir;
};

struct glob_path_stat {
	char		*gps_path;
	struct stat	*gps_stat;
};

static int	 compare(const void *, const void *);
static int	 compare_gps(const void *, const void *);
static int	 g_Ctoc(const wcat_t *, char *, uint_t);
static int	 g_lstat(wcat_t *, struct stat *, glob_t *);
static DIR	*g_opendir(wcat_t *, glob_t *);
static wcat_t	*g_strchr(const wcat_t *, wchar_t);
static int	 g_stat(wcat_t *, struct stat *, glob_t *);
static int	 glob0(const wcat_t *, glob_t *, struct glob_lim *,
			int (*)(const char *, int));
static int	 glob1(wcat_t *, wcat_t *, glob_t *, struct glob_lim *,
			int (*)(const char *, int));
static int	 glob2(wcat_t *, wcat_t *, wcat_t *, wcat_t *, wcat_t *,
			wcat_t *, glob_t *, struct glob_lim *,
			int (*)(const char *, int));
static int	 glob3(wcat_t *, wcat_t *, wcat_t *, wcat_t *, wcat_t *,
			wcat_t *, wcat_t *, glob_t *, struct glob_lim *,
			int (*)(const char *, int));
static int	 globextend(const wcat_t *, glob_t *, struct glob_lim *,
		    struct stat *);
static
const wcat_t	*globtilde(const wcat_t *, wcat_t *, size_t, glob_t *);
static int	 globexp1(const wcat_t *, glob_t *, struct glob_lim *,
		    int (*)(const char *, int));
static int	 globexp2(const wcat_t *, const wcat_t *, glob_t *,
		    struct glob_lim *, int (*)(const char *, int));
static int	 match(wcat_t *, wcat_t *, wcat_t *);

/*
 * Extended glob() function, selected by #pragma redefine_extname
 * in glob.h with the external name _glob_ext() .
 */
int
_glob_ext(const char *pattern, int flags, int (*errfunc)(const char *, int),
    glob_t *pglob)
{
	const char *patnext;
	int n;
	size_t patlen;
	wchar_t c;
	wcat_t *bufnext, *bufend, patbuf[PATH_MAX];
	struct glob_lim limit = { 0, 0, 0 };

	patnext = pattern;
	if (!(flags & GLOB_APPEND)) {
		pglob->gl_pathc = 0;
		pglob->gl_pathn = 0;
		pglob->gl_pathv = NULL;
		if ((flags & GLOB_KEEPSTAT) != 0)
			pglob->gl_statv = NULL;
		if (!(flags & GLOB_DOOFFS))
			pglob->gl_offs = 0;
	}
	pglob->gl_flags = flags & ~GLOB_MAGCHAR;
	pglob->gl_matchc = 0;

	if ((patlen = strnlen(pattern, PATH_MAX)) == PATH_MAX)
		return (GLOB_NOMATCH);

	if (pglob->gl_offs >= INT_MAX || pglob->gl_pathc >= INT_MAX ||
	    pglob->gl_pathc >= INT_MAX - pglob->gl_offs - 1)
		return (GLOB_NOSPACE);

	bufnext = patbuf;
	bufend = bufnext + PATH_MAX - 1;
	patlen += 1;
	if (flags & GLOB_NOESCAPE) {
		while (bufnext < bufend) {
			if ((n = mbtowc(&c, patnext, patlen)) > 0) {
				patnext += n;
				patlen -= n;
				bufnext->w_at = 0;
				(bufnext++)->w_wc = c;
			} else if (n == 0) {
				break;
			} else {
				return (GLOB_NOMATCH);
			}
		}
	} else {
		/* Protect the quoted characters. */
		while (bufnext < bufend) {
			if ((n = mbtowc(&c, patnext, patlen)) > 0) {
				patnext += n;
				patlen -= n;
				if (c == QUOTE) {
					n = mbtowc(&c, patnext, patlen);
					if (n < 0)
						return (GLOB_NOMATCH);
					if (n > 0) {
						patnext += n;
						patlen -= n;
					}
					if (n == 0)
						c = QUOTE;
					bufnext->w_at = M_PROTECT;
					(bufnext++)->w_wc = c;
				} else {
					bufnext->w_at = 0;
					(bufnext++)->w_wc = c;
				}
			} else if (n == 0) {
				break;
			} else {
				return (GLOB_NOMATCH);
			}
		}
	}
	bufnext->w_at = 0;
	bufnext->w_wc = EOS;

	if (flags & GLOB_BRACE)
		return (globexp1(patbuf, pglob, &limit, errfunc));
	else
		return (glob0(patbuf, pglob, &limit, errfunc));
}

/*
 * Expand recursively a glob {} pattern. When there is no more expansion
 * invoke the standard globbing routine to glob the rest of the magic
 * characters
 */
static int
globexp1(const wcat_t *pattern, glob_t *pglob, struct glob_lim *limitp,
    int (*errfunc)(const char *, int))
{
	const wcat_t *ptr = pattern;

	/* Protect a single {}, for find(1), like csh */
	if (pattern[0].w_wc == LBRACE && pattern[1].w_wc == RBRACE &&
	    pattern[2].w_wc == EOS)
		return (glob0(pattern, pglob, limitp, errfunc));

	if ((ptr = (const wcat_t *) g_strchr(ptr, LBRACE)) != NULL)
		return (globexp2(ptr, pattern, pglob, limitp, errfunc));

	return (glob0(pattern, pglob, limitp, errfunc));
}


/*
 * Recursive brace globbing helper. Tries to expand a single brace.
 * If it succeeds then it invokes globexp1 with the new pattern.
 * If it fails then it tries to glob the rest of the pattern and returns.
 */
static int
globexp2(const wcat_t *ptr, const wcat_t *pattern, glob_t *pglob,
    struct glob_lim *limitp, int (*errfunc)(const char *, int))
{
	int	i, rv;
	wcat_t   *lm, *ls;
	const wcat_t *pe, *pm, *pl;
	wcat_t    patbuf[PATH_MAX];

	/* copy part up to the brace */
	for (lm = patbuf, pm = pattern; pm != ptr; *lm++ = *pm++)
		;
	lm->w_at = 0;
	lm->w_wc = EOS;
	ls = lm;

	/* Find the balanced brace */
	for (i = 0, pe = ++ptr; pe->w_wc != EOS; pe++)
		if (pe->w_wc == LBRACKET) {
			/* Ignore everything between [] */
			for (pm = pe++; pe->w_wc != RBRACKET &&
			    pe->w_wc != EOS; pe++)
				;
			if (pe->w_wc == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pe = pm;
			}
		} else if (pe->w_wc == LBRACE) {
			i++;
		} else if (pe->w_wc == RBRACE) {
			if (i == 0)
				break;
			i--;
		}

	/* Non matching braces; just glob the pattern */
	if (i != 0 || pe->w_wc == EOS)
		return (glob0(patbuf, pglob, limitp, errfunc));

	for (i = 0, pl = pm = ptr; pm <= pe; pm++) {
		switch (pm->w_wc) {
		case LBRACKET:
			/* Ignore everything between [] */
			for (pl = pm++; pm->w_wc != RBRACKET && pm->w_wc != EOS;
			    pm++)
				;
			if (pm->w_wc == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pm = pl;
			}
			break;

		case LBRACE:
			i++;
			break;

		case RBRACE:
			if (i) {
				i--;
				break;
			}
			/* FALLTHROUGH */
		case COMMA:
			if (i && pm->w_wc == COMMA)
				break;
			else {
				/* Append the current string */
				for (lm = ls; (pl < pm); *lm++ = *pl++)
					;

				/*
				 * Append the rest of the pattern after the
				 * closing brace
				 */
				for (pl = pe + 1;
				    (*lm++ = *pl++).w_wc != EOS; /* */)
					;

				/* Expand the current pattern */
				rv = globexp1(patbuf, pglob, limitp, errfunc);
				if (rv && rv != GLOB_NOMATCH)
					return (rv);

				/* move after the comma, to the next string */
				pl = pm + 1;
			}
			break;

		default:
			break;
		}
	}
	return (0);
}



/*
 * expand tilde from the passwd file.
 */
static const wcat_t *
globtilde(const wcat_t *pattern, wcat_t *patbuf, size_t patbuf_len,
    glob_t *pglob)
{
	struct passwd *pwd;
	char *h;
	const wcat_t *p;
	wcat_t *b, *eb, *q;
	int n;
	size_t lenh;
	wchar_t c;

	if (pattern->w_wc != TILDE || !(pglob->gl_flags & GLOB_TILDE))
		return (pattern);

	/* Copy up to the end of the string or / */
	eb = &patbuf[patbuf_len - 1];
	for (p = pattern + 1, q = patbuf;
	    q < eb && p->w_wc != EOS && p->w_wc != SLASH; *q++ = *p++)
		;

	q->w_at = 0;
	q->w_wc = EOS;

	/* What to do if patbuf is full? */

	if (patbuf[0].w_wc == EOS) {
		/*
		 * handle a plain ~ or ~/ by expanding $HOME
		 * first and then trying the password file
		 */
		if (issetugid() != 0)
			return (pattern);
		if ((h = getenv("HOME")) == NULL) {
			if ((pwd = getpwuid(getuid())) == NULL)
				return (pattern);
			else
				h = pwd->pw_dir;
		}
	} else {
		/*
		 * Expand a ~user
		 */
		if ((pwd = getpwnam((char *)patbuf)) == NULL)
			return (pattern);
		else
			h = pwd->pw_dir;
	}

	/* Copy the home directory */
	lenh = strlen(h) + 1;
	for (b = patbuf; b < eb && *h != EOS; b++) {
		if ((n = mbtowc(&c, h, lenh)) > 0) {
			h += n;
			lenh -= n;
			b->w_at = 0;
			b->w_wc = c;
		} else if (n < 0) {
			return (pattern);
		} else {
			break;
		}
	}

	/* Append the rest of the pattern */
	while (b < eb && (*b++ = *p++).w_wc != EOS)
		;
	b->w_at = 0;
	b->w_wc = EOS;

	return (patbuf);
}

static int
g_charclass(const wcat_t **patternp, wcat_t **bufnextp)
{
	const wcat_t *pattern = *patternp + 1;
	wcat_t *bufnext = *bufnextp;
	const wcat_t *colon;
	char cbuf[MB_LEN_MAX + 32];
	wctype_t cc;
	size_t len;

	if ((colon = g_strchr(pattern, COLON)) == NULL ||
	    colon[1].w_wc != RBRACKET)
		return (1);	/* not a character class */

	len = (size_t)(colon - pattern);
	if (len + MB_LEN_MAX + 1 > sizeof (cbuf))
		return (-1);	/* invalid character class */
	{
		wchar_t w;
		const wcat_t *s1 = pattern;
		char *s2 = cbuf;
		size_t n = len;

		/* Copy the string. */
		while (n > 0) {
			w = (s1++)->w_wc;
			/* Character class names must be ASCII. */
			if (iswascii(w)) {
				n--;
				*s2++ = w;
			} else {
				return (-1);	/* invalid character class */
			}
		}
		*s2 = EOS;
	}
	if ((cc = wctype(cbuf)) == 0)
		return (-1);	/* invalid character class */
	bufnext->w_at = M_QUOTE;
	(bufnext++)->w_wc = M_CLASS;
	bufnext->w_at = 0;
	(bufnext++)->w_wc = cc;
	*bufnextp = bufnext;
	*patternp += len + 3;

	return (0);
}

/*
 * The main glob() routine: compiles the pattern (optionally processing
 * quotes), calls glob1() to do the real pattern matching, and finally
 * sorts the list (unless unsorted operation is requested).  Returns 0
 * if things went well, nonzero if errors occurred.  It is not an error
 * to find no matches.
 */
static int
glob0(const wcat_t *pattern, glob_t *pglob, struct glob_lim *limitp,
    int (*errfunc)(const char *, int))
{
	const wcat_t *qpatnext;
	int err, oldpathc;
	wchar_t c;
	int a;
	wcat_t *bufnext, patbuf[PATH_MAX];

	qpatnext = globtilde(pattern, patbuf, PATH_MAX, pglob);
	oldpathc = pglob->gl_pathc;
	bufnext = patbuf;

	/*
	 * We don't need to check for buffer overflow any more.
	 * The pattern has already been copied to an internal buffer.
	 */
	while ((a = qpatnext->w_at), (c = (qpatnext++)->w_wc) != EOS) {
		switch (c) {
		case LBRACKET:
			if (a != 0) {
				bufnext->w_at = a;
				(bufnext++)->w_wc = c;
				break;
			}
			a = qpatnext->w_at;
			c = qpatnext->w_wc;
			if (a == 0 && c == NOT)
				++qpatnext;
			if (qpatnext->w_wc == EOS ||
			    g_strchr(qpatnext+1, RBRACKET) == NULL) {
				bufnext->w_at = 0;
				(bufnext++)->w_wc = LBRACKET;
				if (a == 0 && c == NOT)
					--qpatnext;
				break;
			}
			bufnext->w_at = M_QUOTE;
			(bufnext++)->w_wc = M_SET;
			if (a == 0 && c == NOT) {
				bufnext->w_at = M_QUOTE;
				(bufnext++)->w_wc = M_NOT;
			}
			a = qpatnext->w_at;
			c = (qpatnext++)->w_wc;
			do {
				if (a == 0 && c == LBRACKET &&
				    qpatnext->w_wc == COLON) {
					do {
						err = g_charclass(&qpatnext,
						    &bufnext);
						if (err)
							break;
						a = qpatnext->w_at;
						c = (qpatnext++)->w_wc;
					} while (a == 0 && c == LBRACKET &&
					    qpatnext->w_wc == COLON);
					if (err == -1 &&
					    !(pglob->gl_flags & GLOB_NOCHECK))
						return (GLOB_NOMATCH);
					if (a == 0 && c == RBRACKET)
						break;
				}
				bufnext->w_at = a;
				(bufnext++)->w_wc = c;
				if (qpatnext->w_at == 0 &&
				    qpatnext->w_wc == RANGE) {
					a = qpatnext[1].w_at;
					c = qpatnext[1].w_wc;
					if (qpatnext[1].w_at != 0 ||
					    qpatnext[1].w_wc != RBRACKET) {
						bufnext->w_at = M_QUOTE;
						(bufnext++)->w_wc = M_RNG;
						bufnext->w_at = a;
						(bufnext++)->w_wc = c;
						qpatnext += 2;
					}
				}
				a = qpatnext->w_at;
				c = (qpatnext++)->w_wc;
			} while (a != 0 || c != RBRACKET);
			pglob->gl_flags |= GLOB_MAGCHAR;
			bufnext->w_at = M_QUOTE;
			(bufnext++)->w_wc = M_END;
			break;
		case QUESTION:
			if (a != 0) {
				bufnext->w_at = a;
				(bufnext++)->w_wc = c;
				break;
			}
			pglob->gl_flags |= GLOB_MAGCHAR;
			bufnext->w_at = M_QUOTE;
			(bufnext++)->w_wc = M_ONE;
			break;
		case STAR:
			if (a != 0) {
				bufnext->w_at = a;
				(bufnext++)->w_wc = c;
				break;
			}
			pglob->gl_flags |= GLOB_MAGCHAR;
			/*
			 * collapse adjacent stars to one,
			 * to avoid exponential behavior
			 */
			if (bufnext == patbuf ||
			    bufnext[-1].w_at != M_QUOTE ||
			    bufnext[-1].w_wc != M_ALL) {
				bufnext->w_at = M_QUOTE;
				(bufnext++)->w_wc = M_ALL;
			}
			break;
		default:
			bufnext->w_at = a;
			(bufnext++)->w_wc = c;
			break;
		}
	}
	bufnext->w_at = 0;
	bufnext->w_wc = EOS;

	if ((err = glob1(patbuf, patbuf+PATH_MAX-1, pglob, limitp, errfunc))
	    != 0)
		return (err);

	/*
	 * If there was no match we are going to append the pattern
	 * if GLOB_NOCHECK was specified or if GLOB_NOMAGIC was specified
	 * and the pattern did not contain any magic characters
	 * GLOB_NOMAGIC is there just for compatibility with csh.
	 */
	if (pglob->gl_pathc == oldpathc) {
		if ((pglob->gl_flags & GLOB_NOCHECK) ||
		    ((pglob->gl_flags & GLOB_NOMAGIC) &&
		    !(pglob->gl_flags & GLOB_MAGCHAR)))
			return (globextend(pattern, pglob, limitp, NULL));
		else
			return (GLOB_NOMATCH);
	}
	if (!(pglob->gl_flags & GLOB_NOSORT)) {
		if ((pglob->gl_flags & GLOB_KEEPSTAT)) {
			/* Keep the paths and stat info synced during sort */
			struct glob_path_stat *path_stat;
			int i;
			int n = pglob->gl_pathc - oldpathc;
			int o = pglob->gl_offs + oldpathc;

			if ((path_stat = calloc(n, sizeof (*path_stat))) ==
			    NULL)
				return (GLOB_NOSPACE);
			for (i = 0; i < n; i++) {
				path_stat[i].gps_path = pglob->gl_pathv[o + i];
				path_stat[i].gps_stat = pglob->gl_statv[o + i];
			}
			qsort(path_stat, n, sizeof (*path_stat), compare_gps);
			for (i = 0; i < n; i++) {
				pglob->gl_pathv[o + i] = path_stat[i].gps_path;
				pglob->gl_statv[o + i] = path_stat[i].gps_stat;
			}
			free(path_stat);
		} else {
			qsort(pglob->gl_pathv + pglob->gl_offs + oldpathc,
			    pglob->gl_pathc - oldpathc, sizeof (char *),
			    compare);
		}
	}
	return (0);
}

static int
compare(const void *p, const void *q)
{
	return (strcmp(*(char **)p, *(char **)q));
}

static int
compare_gps(const void *_p, const void *_q)
{
	const struct glob_path_stat *p = (const struct glob_path_stat *)_p;
	const struct glob_path_stat *q = (const struct glob_path_stat *)_q;

	return (strcmp(p->gps_path, q->gps_path));
}

static int
glob1(wcat_t *pattern, wcat_t *pattern_last, glob_t *pglob,
    struct glob_lim *limitp, int (*errfunc)(const char *, int))
{
	wcat_t pathbuf[PATH_MAX];

	/* A null pathname is invalid -- POSIX 1003.1 sect. 2.4. */
	if (pattern->w_wc == EOS)
		return (0);
	return (glob2(pathbuf, pathbuf+PATH_MAX-1,
	    pathbuf, pathbuf+PATH_MAX-1,
	    pattern, pattern_last, pglob, limitp, errfunc));
}

/*
 * The functions glob2 and glob3 are mutually recursive; there is one level
 * of recursion for each segment in the pattern that contains one or more
 * meta characters.
 */
static int
glob2(wcat_t *pathbuf, wcat_t *pathbuf_last, wcat_t *pathend,
    wcat_t *pathend_last, wcat_t *pattern, wcat_t *pattern_last,
    glob_t *pglob, struct glob_lim *limitp, int (*errfunc)(const char *, int))
{
	struct stat sb;
	wcat_t *p, *q;
	int anymeta;

	/*
	 * Loop over pattern segments until end of pattern or until
	 * segment with meta character found.
	 */
	for (anymeta = 0; ; ) {
		if (pattern->w_wc == EOS) {		/* End of pattern? */
			pathend->w_at = 0;
			pathend->w_wc = EOS;

			if ((pglob->gl_flags & GLOB_LIMIT) &&
			    limitp->glim_stat++ >= GLOB_LIMIT_STAT) {
				errno = 0;
				pathend->w_at = 0;
				(pathend++)->w_wc = SEP;
				pathend->w_at = 0;
				pathend->w_wc = EOS;
				return (GLOB_NOSPACE);
			}
			if (g_lstat(pathbuf, &sb, pglob))
				return (0);

			if (((pglob->gl_flags & GLOB_MARK) &&
			    (pathend[-1].w_at != 0 ||
			    pathend[-1].w_wc != SEP)) &&
			    (S_ISDIR(sb.st_mode) ||
			    (S_ISLNK(sb.st_mode) &&
			    (g_stat(pathbuf, &sb, pglob) == 0) &&
			    S_ISDIR(sb.st_mode)))) {
				if (pathend+1 > pathend_last)
					return (GLOB_NOSPACE);
				pathend->w_at = 0;
				(pathend++)->w_wc = SEP;
				pathend->w_at = 0;
				pathend->w_wc = EOS;
			}
			++pglob->gl_matchc;
			return (globextend(pathbuf, pglob, limitp, &sb));
		}

		/* Find end of next segment, copy tentatively to pathend. */
		q = pathend;
		p = pattern;
		while (p->w_wc != EOS && p->w_wc != SEP) {
			if (ismeta(*p))
				anymeta = 1;
			if (q+1 > pathend_last)
				return (GLOB_NOSPACE);
			*q++ = *p++;
		}

		if (!anymeta) {		/* No expansion, do next segment. */
			pathend = q;
			pattern = p;
			while (pattern->w_wc == SEP) {
				if (pathend+1 > pathend_last)
					return (GLOB_NOSPACE);
				*pathend++ = *pattern++;
			}
		} else  {
			/* Need expansion, recurse. */
			return (glob3(pathbuf, pathbuf_last, pathend,
			    pathend_last, pattern, p, pattern_last,
			    pglob, limitp, errfunc));
		}
	}
	/* NOTREACHED */
}

static int
glob3(wcat_t *pathbuf, wcat_t *pathbuf_last, wcat_t *pathend,
    wcat_t *pathend_last, wcat_t *pattern, wcat_t *restpattern,
    wcat_t *restpattern_last, glob_t *pglob, struct glob_lim *limitp,
    int (*errfunc)(const char *, int))
{
	struct dirent *dp;
	DIR *dirp;
	int err;
	char buf[PATH_MAX];

	/*
	 * The readdirfunc declaration can't be prototyped, because it is
	 * assigned, below, to two functions which are prototyped in glob.h
	 * and dirent.h as taking pointers to differently typed opaque
	 * structures.
	 */
	struct dirent *(*readdirfunc)(void *);

	if (pathend > pathend_last)
		return (GLOB_NOSPACE);
	pathend->w_at = 0;
	pathend->w_wc = EOS;
	errno = 0;

	if ((dirp = g_opendir(pathbuf, pglob)) == NULL) {
		/* TODO: don't call for ENOENT or ENOTDIR? */
		if (errfunc) {
			if (g_Ctoc(pathbuf, buf, sizeof (buf)))
				return (GLOB_ABORTED);
			if (errfunc(buf, errno) ||
			    pglob->gl_flags & GLOB_ERR)
				return (GLOB_ABORTED);
		}
		return (0);
	}

	err = 0;

	/* Search directory for matching names. */
	if (pglob->gl_flags & GLOB_ALTDIRFUNC)
		readdirfunc = pglob->gl_readdir;
	else
		readdirfunc = (struct dirent *(*)(void *))readdir;
	while ((dp = (*readdirfunc)(dirp))) {
		char *sc;
		wcat_t *dc;
		int n;
		int lensc;
		wchar_t w;

		if ((pglob->gl_flags & GLOB_LIMIT) &&
		    limitp->glim_readdir++ >= GLOB_LIMIT_READDIR) {
			errno = 0;
			pathend->w_at = 0;
			(pathend++)->w_wc = SEP;
			pathend->w_at = 0;
			pathend->w_wc = EOS;
			err = GLOB_NOSPACE;
			break;
		}

		/* Initial DOT must be matched literally. */
		if (dp->d_name[0] == DOT && pattern->w_wc != DOT)
			continue;
		dc = pathend;
		sc = dp->d_name;
		lensc = strlen(sc) + 1;
		while (dc < pathend_last) {
			if ((n = mbtowc(&w, sc, lensc)) <= 0) {
				sc += 1;
				lensc -= 1;
				dc->w_at = 0;
				dc->w_wc = EOS;
			} else {
				sc += n;
				lensc -= n;
				dc->w_at = 0;
				dc->w_wc = w;
			}
			dc++;
			if (n <= 0)
				break;
		}
		if (dc >= pathend_last) {
			dc->w_at = 0;
			dc->w_wc = EOS;
			err = GLOB_NOSPACE;
			break;
		}
		if (n < 0) {
			err = GLOB_NOMATCH;
			break;
		}

		if (!match(pathend, pattern, restpattern)) {
			pathend->w_at = 0;
			pathend->w_wc = EOS;
			continue;
		}
		err = glob2(pathbuf, pathbuf_last, --dc, pathend_last,
		    restpattern, restpattern_last, pglob, limitp,
		    errfunc);
		if (err)
			break;
	}

	if (pglob->gl_flags & GLOB_ALTDIRFUNC)
		(*pglob->gl_closedir)(dirp);
	else
		(void) closedir(dirp);
	return (err);
}


/*
 * Extend the gl_pathv member of a glob_t structure to accommodate a new item,
 * add the new item, and update gl_pathc.  Avoids excessive reallocation
 * by doubling the number of elements each time.  Uses gl_pathn to contain
 * the number.
 *
 * Return 0 if new item added, error code if memory couldn't be allocated.
 *
 * Invariant of the glob_t structure:
 *	Either gl_pathc is zero and gl_pathv is NULL; or gl_pathc > 0 and
 *	gl_pathv points to (gl_offs + gl_pathc + 1) items.
 */
static int
globextend(const wcat_t *path, glob_t *pglob, struct glob_lim *limitp,
    struct stat *sb)
{
	char **pathv;
	ssize_t i;
	size_t allocn, newn, len;
	char *copy = NULL;
	const wcat_t *p;
	struct stat **statv;
	char junk[MB_LEN_MAX];
	int n;

	allocn = pglob->gl_pathn;
	newn = 2 + pglob->gl_pathc + pglob->gl_offs;

	if (newn <= allocn) {
		pathv = pglob->gl_pathv;
		if ((pglob->gl_flags & GLOB_KEEPSTAT) != 0)
			statv = pglob->gl_statv;
	} else {
		if (allocn == 0)
			allocn = pglob->gl_offs + INITIAL;
		allocn *= 2;
		if (pglob->gl_offs >= INT_MAX ||
		    pglob->gl_pathc >= INT_MAX ||
		    allocn >= INT_MAX ||
		    SIZE_MAX / sizeof (*pathv) <= allocn ||
		    SIZE_MAX / sizeof (*statv) <= allocn) {
		nospace:
			for (i = pglob->gl_offs; i < (ssize_t)(newn - 2);
			    i++) {
				if (pglob->gl_pathv && pglob->gl_pathv[i])
					free(pglob->gl_pathv[i]);
				if ((pglob->gl_flags & GLOB_KEEPSTAT) != 0 &&
				    pglob->gl_statv && pglob->gl_statv[i])
					free(pglob->gl_statv[i]);
			}
			free(pglob->gl_pathv);
			pglob->gl_pathv = NULL;
			if ((pglob->gl_flags & GLOB_KEEPSTAT) != 0) {
				free(pglob->gl_statv);
				pglob->gl_statv = NULL;
			}
			return (GLOB_NOSPACE);
		}
		limitp->glim_malloc += allocn * sizeof (*pathv);
		pathv = reallocarray(pglob->gl_pathv, allocn, sizeof (*pathv));
		if (pathv == NULL)
			goto nospace;
		if ((pglob->gl_flags & GLOB_KEEPSTAT) != 0) {
			limitp->glim_malloc += allocn * sizeof (*statv);
			statv = reallocarray(pglob->gl_statv, allocn,
			    sizeof (*statv));
			if (statv == NULL)
				goto nospace;
		}
	}
	pglob->gl_pathn = allocn;

	if (pglob->gl_pathv == NULL && pglob->gl_offs > 0) {
		/* first time around -- clear initial gl_offs items */
		pathv += pglob->gl_offs;
		for (i = pglob->gl_offs; --i >= 0; )
			*--pathv = NULL;
	}
	pglob->gl_pathv = pathv;

	if ((pglob->gl_flags & GLOB_KEEPSTAT) != 0) {
		if (pglob->gl_statv == NULL && pglob->gl_offs > 0) {
			/* first time around -- clear initial gl_offs items */
			statv += pglob->gl_offs;
			for (i = pglob->gl_offs; --i >= 0; )
				*--statv = NULL;
		}
		pglob->gl_statv = statv;
		if (sb == NULL)
			statv[pglob->gl_offs + pglob->gl_pathc] = NULL;
		else {
			limitp->glim_malloc += sizeof (**statv);
			if ((statv[pglob->gl_offs + pglob->gl_pathc] =
			    malloc(sizeof (**statv))) == NULL)
				goto copy_error;
			(void) memcpy(statv[pglob->gl_offs + pglob->gl_pathc],
			    sb, sizeof (*sb));
		}
		statv[pglob->gl_offs + pglob->gl_pathc + 1] = NULL;
	}

	len = MB_LEN_MAX;
	p = path;
	while ((n = wctomb(junk, p->w_wc)) > 0) {
		len += n;
		if ((p++)->w_wc == EOS)
			break;
	}
	if (n < 0)
		return (GLOB_NOMATCH);

	limitp->glim_malloc += len;
	if ((copy = malloc(len)) != NULL) {
		if (g_Ctoc(path, copy, len)) {
			free(copy);
			return (GLOB_NOSPACE);
		}
		pathv[pglob->gl_offs + pglob->gl_pathc++] = copy;
	}
	pathv[pglob->gl_offs + pglob->gl_pathc] = NULL;

	if ((pglob->gl_flags & GLOB_LIMIT) &&
	    limitp->glim_malloc >= GLOB_LIMIT_MALLOC) {
		errno = 0;
		return (GLOB_NOSPACE);
	}
	copy_error:
	return (copy == NULL ? GLOB_NOSPACE : 0);
}


/*
 * pattern matching function for filenames.  Each occurrence of the *
 * pattern causes an iteration.
 *
 * Note, this function differs from the original as per the discussion
 * here: https://research.swtch.com/glob
 *
 * Basically we removed the recursion and made it use the algorithm
 * from Russ Cox to not go quadratic on cases like a file called
 * ("a" x 100) . "x" matched against a pattern like "a*a*a*a*a*a*a*y".
 */
static int
match(wcat_t *name, wcat_t *pat, wcat_t *patend)
{
	int ok, negate_range;
	wcat_t c, k;
	wcat_t *nextp = NULL;
	wcat_t *nextn = NULL;

loop:
	while (pat < patend) {
		c = *pat++;
		switch (c.w_wc) {
		case M_ALL:
			if (c.w_at != M_QUOTE) {
				k = *name++;
				if (k.w_at != c.w_at || k.w_wc != c.w_wc)
					return (0);
				break;
			}
			while (pat < patend && pat->w_at == M_QUOTE &&
			    pat->w_wc == M_ALL)
				pat++;	/* eat consecutive '*' */
			if (pat == patend)
				return (1);
			if (name->w_wc == EOS)
				return (0);
			nextn = name + 1;
			nextp = pat - 1;
			break;
		case M_ONE:
			if (c.w_at != M_QUOTE) {
				k = *name++;
				if (k.w_at != c.w_at || k.w_wc != c.w_wc)
					goto fail;
				break;
			}
			if ((name++)->w_wc == EOS)
				goto fail;
			break;
		case M_SET:
			if (c.w_at != M_QUOTE) {
				k = *name++;
				if (k.w_at != c.w_at || k.w_wc != c.w_wc)
					goto fail;
				break;
			}
			ok = 0;
			if ((k = *name++).w_wc == EOS)
				goto fail;
			if ((negate_range = (pat->w_at == M_QUOTE &&
			    pat->w_wc == M_NOT)) != 0)
				++pat;
			while (((c = *pat++).w_at != M_QUOTE) ||
			    c.w_wc != M_END) {
				if (c.w_at == M_QUOTE && c.w_wc == M_CLASS) {
					wcat_t cc;

					cc.w_at = pat->w_at;
					cc.w_wc = pat->w_wc;
					if (iswctype(k.w_wc, cc.w_wc))
						ok = 1;
					++pat;
				}
				if (pat->w_at == M_QUOTE &&
				    pat->w_wc == M_RNG) {
					if (c.w_wc <= k.w_wc &&
					    k.w_wc <= pat[1].w_wc)
						ok = 1;
					pat += 2;
				} else if (c.w_wc == k.w_wc)
					ok = 1;
			}
			if (ok == negate_range)
				goto fail;
			break;
		default:
			k = *name++;
			if (k.w_at != c.w_at || k.w_wc != c.w_wc)
				goto fail;
			break;
		}
	}
	if (name->w_wc == EOS)
		return (1);

fail:
	if (nextn) {
		pat = nextp;
		name = nextn;
		goto loop;
	}
	return (0);
}

/*
 * Extended globfree() function, selected by #pragma redefine_extname
 * in glob.h with the external name _globfree_ext() .
 */
void
_globfree_ext(glob_t *pglob)
{
	int i;
	char **pp;

	if (pglob->gl_pathv != NULL) {
		pp = pglob->gl_pathv + pglob->gl_offs;
		for (i = pglob->gl_pathc; i--; ++pp)
			free(*pp);
		free(pglob->gl_pathv);
		pglob->gl_pathv = NULL;
	}
	if ((pglob->gl_flags & GLOB_KEEPSTAT) != 0 &&
	    pglob->gl_statv != NULL) {
		for (i = 0; i < pglob->gl_pathc; i++) {
			free(pglob->gl_statv[i]);
		}
		free(pglob->gl_statv);
		pglob->gl_statv = NULL;
	}
}

static DIR *
g_opendir(wcat_t *str, glob_t *pglob)
{
	char buf[PATH_MAX];

	if (str->w_wc == EOS)
		(void) strlcpy(buf, ".", sizeof (buf));
	else {
		if (g_Ctoc(str, buf, sizeof (buf)))
			return (NULL);
	}

	if (pglob->gl_flags & GLOB_ALTDIRFUNC)
		return ((*pglob->gl_opendir)(buf));

	return (opendir(buf));
}

static int
g_lstat(wcat_t *fn, struct stat *sb, glob_t *pglob)
{
	char buf[PATH_MAX];

	if (g_Ctoc(fn, buf, sizeof (buf)))
		return (-1);
	if (pglob->gl_flags & GLOB_ALTDIRFUNC)
		return ((*pglob->gl_lstat)(buf, sb));
	return (lstat(buf, sb));
}

static int
g_stat(wcat_t *fn, struct stat *sb, glob_t *pglob)
{
	char buf[PATH_MAX];

	if (g_Ctoc(fn, buf, sizeof (buf)))
		return (-1);
	if (pglob->gl_flags & GLOB_ALTDIRFUNC)
		return ((*pglob->gl_stat)(buf, sb));
	return (stat(buf, sb));
}

static wcat_t *
g_strchr(const wcat_t *str, wchar_t ch)
{
	do {
		if (str->w_at == 0 && str->w_wc == ch)
			return ((wcat_t *)str);
	} while ((str++)->w_wc != EOS);
	return (NULL);
}

static int
g_Ctoc(const wcat_t *str, char *buf, uint_t len)
{
	int n;
	wchar_t w;

	while (len >= MB_LEN_MAX) {
		w = (str++)->w_wc;
		if ((n = wctomb(buf, w)) > 0) {
			len -= n;
			buf += n;
		}
		if (n < 0)
			break;
		if (w == EOS)
			return (0);
	}
	return (1);
}

#if defined(_LP64) || _FILE_OFFSET_BITS != 64

/* glob() function with legacy glob structure */
int
old_glob(const char *pattern, int flags, int (*errfunc)(const char *, int),
    old_glob_t *pglob)
{

	glob_t gl;
	int rv;

	flags &= GLOB_POSIX;

	(void) memset(&gl, 0, sizeof (gl));

	/*
	 * Copy all the members, old to new.  There's
	 * really no point in micro-optimizing the copying.
	 * Other members are set to zero.
	 */
	gl.gl_pathc = pglob->gl_pathc;
	gl.gl_pathv = pglob->gl_pathv;
	gl.gl_offs = pglob->gl_offs;
	gl.gl_pathp = pglob->gl_pathp;
	gl.gl_pathn = pglob->gl_pathn;

	rv = _glob_ext(pattern, flags, errfunc, &gl);

	/*
	 * Copy all the members, new to old.  There's
	 * really no point in micro-optimizing the copying.
	 */
	pglob->gl_pathc = gl.gl_pathc;
	pglob->gl_pathv = gl.gl_pathv;
	pglob->gl_offs = gl.gl_offs;
	pglob->gl_pathp = gl.gl_pathp;
	pglob->gl_pathn = gl.gl_pathn;

	return (rv);
}

/* globfree() function with legacy glob structure */
void
old_globfree(old_glob_t *pglob)
{
	glob_t gl;

	(void) memset(&gl, 0, sizeof (gl));

	/*
	 * Copy all the members, old to new.  There's
	 * really no point in micro-optimizing the copying.
	 * Other members are set to zero.
	 */
	gl.gl_pathc = pglob->gl_pathc;
	gl.gl_pathv = pglob->gl_pathv;
	gl.gl_offs = pglob->gl_offs;
	gl.gl_pathp = pglob->gl_pathp;
	gl.gl_pathn = pglob->gl_pathn;

	_globfree_ext(&gl);

	/*
	 * Copy all the members, new to old.  There's
	 * really no point in micro-optimizing the copying.
	 */
	pglob->gl_pathc = gl.gl_pathc;
	pglob->gl_pathv = gl.gl_pathv;
	pglob->gl_offs = gl.gl_offs;
	pglob->gl_pathp = gl.gl_pathp;
	pglob->gl_pathn = gl.gl_pathn;

}

#endif	/* _LP64 || _FILE_OFFSET_BITS != 64 */
