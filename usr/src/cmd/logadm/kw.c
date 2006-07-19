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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * logadm/kw.c -- manage keywords table
 *
 * this module expands things like $file.$n in "templates".
 * calling kw_init() sets the current "filename" used for
 * $file, $dirname, and $basename.
 *
 * any time-based expansions, like $secs, or all the strftime()
 * percent sequences, are based on the exact same point in time.
 * so calling kw_expand() on something like "file-%T" will return
 * the same thing when called multiple times during the same logadm run.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <libintl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/systeminfo.h>
#include <strings.h>
#include <time.h>
#include <ctype.h>
#include <zone.h>
#include "err.h"
#include "lut.h"
#include "fn.h"
#include "kw.h"

/* forward declarations for functions used internally by this module */
static void kw_printer(const char *lhs, void *rhs, void *arg);

/*
 * absurdly long length to hold sprintf of a %d,
 * or strftime() expansion of a *single* percent sequence
 */
#define	MAXDIGITS 100

static struct lut *Keywords;	/* lookup table for keywords */

extern time_t Now;		/* time used for keyword expansions */

/*
 * kw_init -- initialize keywords based on given filename
 */
void
kw_init(struct fn *fnp, struct fn *nfnp)
{
	static char *fullpath;
	static char *nfullpath;
	static char *splitpath;
	static char secs[MAXDIGITS];
	static struct utsname un;
	static char platform[SYS_NMLN];
	static char isa[SYS_NMLN];
	static char domain[256];
	static char *home;
	static char *user;
	static char *logname;
	static char zonename[ZONENAME_MAX];
	static zoneid_t zoneid;
	static int initialized;
	char *ptr;

	/* make a copy of the string for $file */
	if (fullpath)
		FREE(fullpath);
	fullpath = STRDUP(fn_s(fnp));
	Keywords = lut_add(Keywords, "file", fullpath);

	/* make a copy of the string for $nfile */
	if (nfullpath)
		FREE(nfullpath);
	if (nfnp == NULL) {
		nfullpath = NULL;
		Keywords = lut_add(Keywords, "nfile", "");
	} else {
		nfullpath = STRDUP(fn_s(nfnp));
		Keywords = lut_add(Keywords, "nfile", nfullpath);
	}

	/* make a copy of the string for $dirname/$basename */
	if (splitpath)
		FREE(splitpath);
	splitpath = STRDUP(fn_s(fnp));

	if ((ptr = strrchr(splitpath, '/')) == NULL) {
		Keywords = lut_add(Keywords, "basename", splitpath);
		Keywords = lut_add(Keywords, "dirname", ".");
	} else {
		*ptr++ = '\0';
		Keywords = lut_add(Keywords, "basename", ptr);
		Keywords = lut_add(Keywords, "dirname", splitpath);
	}

	if (initialized)
		return;		/* rest of the keywords don't change */

	(void) snprintf(secs, MAXDIGITS, "%d", (int)Now);
	Keywords = lut_add(Keywords, "secs", secs);

	if (uname(&un) < 0)
		err(EF_SYS, "uname");

	Keywords = lut_add(Keywords, "nodename", un.nodename);
	Keywords = lut_add(Keywords, "release", un.release);
	Keywords = lut_add(Keywords, "machine", un.machine);

	if (sysinfo(SI_ARCHITECTURE, isa, sizeof (isa)) == -1)
		err(EF_WARN|EF_SYS, "sysinfo(SI_ARCHITECTURE) failed.");
	else
		Keywords = lut_add(Keywords, "isa", isa);

	if (sysinfo(SI_PLATFORM, platform, sizeof (platform)) == -1)
		err(EF_WARN|EF_SYS, "sysinfo(SI_PLATFORM) failed.");
	else
		Keywords = lut_add(Keywords, "platform", platform);

	if (sysinfo(SI_SRPC_DOMAIN, domain, sizeof (domain)) == -1)
		err(EF_WARN|EF_SYS, "sysinfo(SI_SRPC_DOMAIN) failed.");
	else
		Keywords = lut_add(Keywords, "domain", domain);

	if ((home = getenv("HOME")) != NULL)
		Keywords = lut_add(Keywords, "home", STRDUP(home));

	if ((user = getenv("USER")) != NULL)
		Keywords = lut_add(Keywords, "user", STRDUP(user));

	if ((logname = getenv("LOGNAME")) != NULL)
		Keywords = lut_add(Keywords, "logname", STRDUP(logname));

	zoneid = getzoneid();
	if ((getzonenamebyid(zoneid, zonename, sizeof (zonename))) == -1)
		err(EF_WARN|EF_SYS, "getzonenamebyid() failed.");
	else
		Keywords = lut_add(Keywords, "zonename", STRDUP(zonename));

	initialized = 1;
}

/* helper function for kw_print() */
static void
kw_printer(const char *lhs, void *rhs, void *arg)
{
	FILE *stream = (FILE *)arg;

	(void) fprintf(stream, "%20.20s %s\n", lhs, (char *)rhs);
}

/*
 * kw_print -- spew the entire keywords table to stream
 *
 * this routine is used to dump the keywords table for debugging.
 */
void
kw_print(FILE *stream)
{
	lut_walk(Keywords, kw_printer, stream);
}

/*
 * kw_expand -- expand src into dst with given n value for $n (or $N)
 *
 * n == -1 means expand src into a reglob
 * if gz is true, include ".gz" extension
 *
 * returns true if template contains $n or $N (implying rotation of files)
 */
boolean_t
kw_expand(struct fn *src, struct fn *dst, int n, boolean_t gz)
{
	int c;
	char buf[MAXDIGITS];
	boolean_t hasn = B_FALSE;
	struct fn *kw = fn_new(NULL);
	char *ptr;
	struct tm *gmt_tm = localtime(&Now);

	while ((c = fn_getc(src)) != '\0')
		switch (c) {
		case '.':
		case '(':
		case ')':
		case '^':
		case '+':
		case '{':
		case '}':
			/* when building an re, escape with a backslash */
			if (n < 0)
				fn_putc(dst, '\\');
			fn_putc(dst, c);
			break;
		case '?':
			/* when building an re, change '?' to a single dot */
			if (n < 0)
				fn_putc(dst, '.');
			break;
		case '*':
			/* when building an re, change '*' to ".*" */
			if (n < 0)
				fn_putc(dst, '.');
			fn_putc(dst, '*');
			break;
		case '$':
			/* '$' marks the start of a keyword */
			switch (c = fn_getc(src)) {
			case '$':
				/* double '$' stands for a single '$' */
				if (n < 0)
					fn_putc(dst, '\\');
				fn_putc(dst, '$');
				break;
			case '#':
				/*
				 * $# expands to nothing, but forces an end
				 * of keyword, allow juxtaposition of a
				 * keyword with lower-case characters
				 */
				break;
			case 'n':
			case 'N':
				if (c == 'N' || !islower(fn_peekc(src))) {
					/*
					 * we've found $n or $N, if we're
					 * building an re, build one that
					 * matches a number, otherwise
					 * expand the keyword to the n
					 * passed in to this function
					 */
					hasn = B_TRUE;
					if (n < 0)
						fn_puts(dst, "([0-9]+)$0");
					else {
						(void) snprintf(buf,
						    MAXDIGITS, "%d",
						    (c == 'n') ? n : n + 1);
						fn_puts(dst, buf);
					}
					break;
				}
				/*FALLTHROUGH*/
			default:
				/* gather up the keyword name */
				fn_renew(kw, NULL);
				fn_putc(kw, c);
				while (islower(fn_peekc(src)))
					fn_putc(kw, fn_getc(src));

				/* lookup keyword */
				if ((ptr = (char *)lut_lookup(Keywords,
				    fn_s(kw))) == NULL) {
					/* nope, copy it unexpanded */
					if (n < 0)
						fn_putc(dst, '\\');
					fn_putc(dst, '$');
					fn_putfn(dst, kw);
				} else
					fn_puts(dst, ptr);
			}
			break;
		case '%':
			/*
			 * % sequence for strftime(), if we're building
			 * an re, we take our best guess at the re for
			 * this sequence, otherwise we pass it to strftime()
			 */
			if (n < 0) {
				/*
				 * the regex for a percent sequence is
				 * usually just ".*" unless it is one
				 * of the common cases we know about
				 * that are numeric.  in those  cases, we
				 * tighten up the regex to just match digits.
				 *
				 * while it is gross that we embed knowledge
				 * of strftime() sequences here, they are
				 * specified in a standard so aren't
				 * expected to change often, and it *really*
				 * cuts down on the possibility that we'll
				 * expire a file that isn't an old log file.
				 */
				if ((c = fn_getc(src)) == 'E' || c == 'O') {
					c = fn_getc(src);
					fn_puts(dst, ".*");
				} else
					switch (c) {
					case 'd':
					case 'g':
					case 'G':
					case 'H':
					case 'I':
					case 'j':
					case 'm':
					case 'M':
					case 'S':
					case 'u':
					case 'U':
					case 'V':
					case 'w':
					case 'W':
					case 'y':
					case 'Y':
						/* pure numeric cases */
						fn_puts(dst, "[0-9]+");
						break;
					case 'e':
					case 'k':
					case 'l':
						/* possible space then num */
						fn_puts(dst, " *[0-9]+");
						break;
					case 'D':	/* %m/%d/%y */
						/* adds slashes! */
						fn_puts(dst,
						    "[0-9]+/[0-9]+/[0-9]+");
						break;
					case 'R':	/* %H:%M */
						fn_puts(dst, "[0-9]+:[0-9]+");
						break;
					case 'T':	/* %H:%M:%S */
						fn_puts(dst,
						    "[0-9]+:[0-9]+:[0-9]+");
						break;
					default:
						fn_puts(dst, ".*");
					}
			} else {
				char tbuf[4];

				/* copy % sequence to tbuf */
				tbuf[0] = '%';
				tbuf[1] = fn_getc(src);
				if (tbuf[1] == 'E' || tbuf[1] == 'O') {
					/* "extended" sequence */
					tbuf[2] = fn_getc(src);
					tbuf[3] = '\0';
				} else
					tbuf[2] = '\0';

				if (strftime(buf, MAXDIGITS, tbuf, gmt_tm) == 0)
					/* just copy %x */
					fn_puts(dst, tbuf);
				else
					fn_puts(dst, buf);
			}
			break;
		default:
			/* nothing special, just copy it */
			fn_putc(dst, c);
		}

	if (gz) {
		if (n < 0)
			fn_puts(dst, "(\\.gz){0,1}");
		else
			fn_puts(dst, ".gz");
	}

	fn_free(kw);
	return (hasn);
}

#ifdef	TESTMODULE

time_t Now;

/*
 * test main for kw module, usage: a.out fname [template...]
 */
int
main(int argc, char *argv[])
{
	int i;
	struct fn *src = fn_new(NULL);
	struct fn *dst = fn_new(NULL);

	err_init(argv[0]);
	setbuf(stdout, NULL);

	Now = time(0);

	if (argc < 2)
		err(0, "first arg must be fname");

	kw_init(fn_new(argv[1]), NULL);

	kw_print(stdout);

	for (i = 2; i < argc; i++) {
		int n;

		for (n = -1; n < 2; n++) {
			fn_renew(src, argv[i]);
			fn_renew(dst, NULL);
			printf("expand<%s> n %d hasn %d ",
			    argv[i], n, kw_expand(src, dst, n, B_FALSE));
			printf("result <%s>\n", fn_s(dst));
		}
	}

	err_done(0);
	/* NOTREACHED */
	return (0);
}

#endif	/* TESTMODULE */
