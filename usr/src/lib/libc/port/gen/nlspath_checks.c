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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "lint.h"
#include "mtlib.h"
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <thread.h>
#include <synch.h>
#include <ctype.h>
#include <errno.h>
#include "libc.h"
#include "nlspath_checks.h"

extern const char **_environ;

/*
 * We want to prevent the use of NLSPATH by setugid applications but
 * not completely.  CDE depends on this very much.
 * Yes, this is ugly.
 */

struct trusted_systemdirs {
	const char	*dir;
	size_t	dirlen;
};

#define	_USRLIB	"/usr/lib/"
#define	_USRDT	"/usr/dt/"
#define	_USROW	"/usr/openwin/"

static const struct trusted_systemdirs	prefix[] = {
	{ _USRLIB,	sizeof (_USRLIB) - 1 },
	{ _USRDT,	sizeof (_USRDT) - 1 },
	{ _USROW,	sizeof (_USROW) - 1 },
	{ NULL,		0 }
};

static int8_t nlspath_safe;

/*
 * Routine to check the safety of a messages file.
 * When the program specifies a pathname and doesn't
 * use NLSPATH, it should specify the "safe" flag as 1.
 * Most checks will be disabled then.
 * fstat64 is done here and the stat structure is returned
 * to prevent duplication of system calls.
 *
 * The trust return value contains an indication of
 * trustworthiness (i.e., does check_format need to be called or
 * not)
 */

int
nls_safe_open(const char *path, struct stat64 *statbuf, int *trust, int safe)
{
	int	fd;
	int	trust_path;
	int	systemdir = 0;
	int	abs_path = 0;
	int	trust_owner = 0;
	int	trust_group = 0;
	const struct trusted_systemdirs	*p;

	/*
	 * If SAFE_F has been specified or NLSPATH is safe (or not set),
	 * set trust_path and trust the file as an initial value.
	 */
	trust_path = *trust = safe || nlspath_safe;

	fd = open(path, O_RDONLY);

	if (fd < 0)
		return (-1);

	if (fstat64(fd, statbuf) == -1) {
		(void) close(fd);
		return (-1);
	}

	/*
	 * Trust only files owned by root or bin (uid 2), except
	 * when specified as full path or when NLSPATH is known to
	 * be safe.
	 * Don't trust files writable by other or writable
	 * by non-bin, non-root system group.
	 * Don't trust these files even if the path is correct.
	 * Since we don't support changing uids/gids on our files,
	 * we hardcode them here for now.
	 */

	/*
	 * if the path is absolute and does not contain "/../",
	 * set abs_path.
	 */
	if (*path == '/' && strstr(path, "/../") == NULL) {
		abs_path = 1;
		/*
		 * if the path belongs to the trusted system directory,
		 * set systemdir.
		 */
		for (p = prefix; p->dir; p++) {
			if (strncmp(p->dir, path, p->dirlen) == 0) {
				systemdir = 1;
				break;
			}
		}
	}

	/*
	 * If the owner is root or bin, set trust_owner.
	 */
	if (statbuf->st_uid == 0 || statbuf->st_uid == 2) {
		trust_owner = 1;
	}
	/*
	 * If the file is neither other-writable nor group-writable by
	 * non-bin and non-root system group, set trust_group.
	 */
	if ((statbuf->st_mode & (S_IWOTH)) == 0 &&
	    ((statbuf->st_mode & (S_IWGRP)) == 0 ||
	    (statbuf->st_gid < 4 && statbuf->st_gid != 1))) {
		trust_group = 1;
	}

	/*
	 * Even if UNSAFE_F has been specified and unsafe-NLSPATH
	 * has been set, trust the file as long as it belongs to
	 * the trusted system directory.
	 */
	if (!*trust && systemdir) {
		*trust = 1;
	}

	/*
	 * If:
	 *	file is not a full pathname,
	 * or
	 *	neither trust_owner nor trust_path is set,
	 * or
	 *	trust_group is not set,
	 * untrust it.
	 */
	if (*trust &&
	    (!abs_path || (!trust_owner && !trust_path) || !trust_group)) {
		*trust = 0;
	}

	/*
	 * If set[ug]id process, open for the untrusted file should fail.
	 * Otherwise, the message extracted from the untrusted file
	 * will have to be checked by check_format().
	 */
	if (issetugid()) {
		if (!*trust) {
			/*
			 * Open should fail
			 */
			(void) close(fd);
			return (-1);
		}

		/*
		 * if the path does not belong to the trusted system directory
		 * or if the owner is neither root nor bin, untrust it.
		 */
		if (!systemdir || !trust_owner) {
			*trust = 0;
		}
	}

	return (fd);
}

/*
 * Extract a format into a normalized format string.
 * Returns the number of arguments converted, -1 on error.
 * The string norm should contain 2N bytes; an upperbound is the
 * length of the format string.
 * The canonical format consists of two chars: one is the conversion
 * character (s, c, d, x, etc), the second one is the option flag.
 * L, ll, l, w as defined below.
 * A special conversion character, '*', indicates that the argument
 * is used as a precision specifier.
 */

#define	OPT_L		0x01
#define	OPT_l		0x02
#define	OPT_ll		0x04
#define	OPT_w		0x08
#define	OPT_h		0x10
#define	OPT_hh		0x20
#define	OPT_j		0x40

/* Number of bytes per canonical format entry */
#define	FORMAT_SIZE	2

/*
 * Check and store the argument; allow each argument to be used only as
 * one type even though printf allows multiple uses.  The specification only
 * allows one use, but we don't want to break existing functional code,
 * even if it's buggy.
 */
#define	STORE(buf, size, arg, val) 	if (arg * FORMAT_SIZE + 1 >= size ||\
					    (strict ? \
					    (buf[arg*FORMAT_SIZE] != '\0' && \
					    buf[arg*FORMAT_SIZE] != val) \
						: \
					    (buf[arg*FORMAT_SIZE] == 'n'))) \
						return (-1); \
					else {\
						if (arg >= maxarg) \
							maxarg = arg + 1; \
						narg++; \
						buf[arg*FORMAT_SIZE] = val; \
					}

/*
 * This function extracts sprintf format into a canonical
 * sprintf form.  It's not as easy as just removing everything
 * that isn't a format specifier, because of "%n$" specifiers.
 * Ideally, this should be compatible with printf and not
 * fail on bad formats.
 * However, that makes writing a proper check_format that
 * doesn't cause crashes a lot harder.
 */

static int
extract_format(const char *fmt, char *norm, size_t sz, int strict)
{
	int narg = 0;
	int t, arg, argp;
	int dotseen;
	char flag;
	char conv;
	int lastarg = -1;
	int prevarg;
	int maxarg = 0;		/* Highest index seen + 1 */
	int lflag;

	(void) memset(norm, '\0', sz);

#ifdef DEBUG
	printf("Format \"%s\" canonical form: ", fmt);
#endif

	for (; *fmt; fmt++) {
		if (*fmt == '%') {
			if (*++fmt == '%')
				continue;

			if (*fmt == '\0')
				break;

			prevarg = lastarg;
			arg = ++lastarg;

			t = 0;
			while (*fmt && isdigit(*fmt))
				t = t * 10 + *fmt++ - '0';

			if (*fmt == '$') {
				lastarg = arg = t - 1;
				fmt++;
			}

			if (*fmt == '\0')
				goto end;

			dotseen = 0;
			flag = 0;
			lflag = 0;
again:
			/* Skip flags */
			while (*fmt) {
				switch (*fmt) {
				case '\'':
				case '+':
				case '-':
				case ' ':
				case '#':
				case '0':
					fmt++;
					continue;
				}
				break;
			}

			while (*fmt && isdigit(*fmt))
				fmt++;

			if (*fmt == '*') {
				if (isdigit(fmt[1])) {
					fmt++;
					t = 0;
					while (*fmt && isdigit(*fmt))
						t = t * 10 + *fmt++ - '0';

					if (*fmt == '$') {
						argp = t - 1;
						STORE(norm, sz, argp, '*');
					}
					/*
					 * If digits follow a '*', it is
					 * not loaded as an argument, the
					 * digits are used instead.
					 */
				} else {
					/*
					 * Weird as it may seem, if we
					 * use an numbered argument, we
					 * get the next one if we have
					 * an unnumbered '*'
					 */
					if (fmt[1] == '$')
						fmt++;
					else {
						argp = arg;
						prevarg = arg;
						lastarg = ++arg;
						STORE(norm, sz, argp, '*');
					}
				}
				fmt++;
			}

			/* Fail on two or more dots if we do strict checking */
			if (*fmt == '.' || *fmt == '*') {
				if (dotseen && strict)
					return (-1);
				dotseen = 1;
				fmt++;
				goto again;
			}

			if (*fmt == '\0')
				goto end;

			while (*fmt) {
				switch (*fmt) {
				case 'l':
					if (!(flag & OPT_ll)) {
						if (lflag) {
							flag &= ~OPT_l;
							flag |= OPT_ll;
						} else {
							flag |= OPT_l;
						}
					}
					lflag++;
					break;
				case 'L':
					flag |= OPT_L;
					break;
				case 'w':
					flag |= OPT_w;
					break;
				case 'h':
					if (flag & (OPT_h|OPT_hh))
						flag |= OPT_hh;
					else
						flag |= OPT_h;
					break;
				case 'j':
					flag |= OPT_j;
					break;
				case 'z':
				case 't':
					if (!(flag & OPT_ll)) {
						flag |= OPT_l;
					}
					break;
				case '\'':
				case '+':
				case '-':
				case ' ':
				case '#':
				case '.':
				case '*':
					goto again;
				default:
					if (isdigit(*fmt))
						goto again;
					else
						goto done;
				}
				fmt++;
			}
done:
			if (*fmt == '\0')
				goto end;

			switch (*fmt) {
			case 'C':
				flag |= OPT_l;
				/* FALLTHROUGH */
			case 'd':
			case 'i':
			case 'o':
			case 'u':
			case 'c':
			case 'x':
			case 'X':
				conv = 'I';
				break;
			case 'e':
			case 'E':
			case 'f':
			case 'F':
			case 'a':
			case 'A':
			case 'g':
			case 'G':
				conv = 'D';
				break;
			case 'S':
				flag |= OPT_l;
				/* FALLTHROUGH */
			case 's':
				conv = 's';
				break;
			case 'p':
			case 'n':
				conv = *fmt;
				break;
			default:
				lastarg = prevarg;
				continue;
			}

			STORE(norm, sz, arg, conv);
			norm[arg*FORMAT_SIZE + 1] = flag;
		}
	}
#ifdef DEBUG
	for (t = 0; t < maxarg * FORMAT_SIZE; t += FORMAT_SIZE) {
		printf("%c(%d)", norm[t], norm[t+1]);
	}
	putchar('\n');
#endif
end:
	if (strict)
		for (arg = 0; arg < maxarg; arg++)
			if (norm[arg*FORMAT_SIZE] == '\0')
				return (-1);

	return (maxarg);
}

char *
check_format(const char *org, const char *new, int strict)
{
	char *ofmt, *nfmt, *torg;
	size_t osz, nsz;
	int olen, nlen;

	if (!org) {
		/*
		 * Default message is NULL.
		 * dtmail uses NULL for default message.
		 */
		torg = "(NULL)";
	} else {
		torg = (char *)org;
	}

	/* Short cut */
	if (org == new || strcmp(torg, new) == 0 ||
	    strchr(new, '%') == NULL)
		return ((char *)new);

	osz = strlen(torg) * FORMAT_SIZE;
	ofmt = malloc(osz);
	if (ofmt == NULL)
		return ((char *)org);

	olen = extract_format(torg, ofmt, osz, 0);

	if (olen == -1)
		syslog(LOG_AUTH|LOG_INFO,
		    "invalid format in gettext argument: \"%s\"", torg);

	nsz = strlen(new) * FORMAT_SIZE;
	nfmt = malloc(nsz);
	if (nfmt == NULL) {
		free(ofmt);
		return ((char *)org);
	}

	nlen = extract_format(new, nfmt, nsz, strict);

	if (nlen == -1) {
		free(ofmt);
		free(nfmt);
		syslog(LOG_AUTH|LOG_NOTICE,
		    "invalid format in message file \"%.100s\" -> \"%s\"",
		    torg, new);
		errno = EBADMSG;
		return ((char *)org);
	}

	if (strict && (olen != nlen || olen == -1)) {
		free(ofmt);
		free(nfmt);
		syslog(LOG_AUTH|LOG_NOTICE,
		    "incompatible format in message file: \"%.100s\" != \"%s\"",
		    torg, new);
		errno = EBADMSG;
		return ((char *)org);
	}

	if (strict && memcmp(ofmt, nfmt, nlen * FORMAT_SIZE) == 0) {
		free(ofmt);
		free(nfmt);
		return ((char *)new);
	} else {
		if (!strict) {
			char *n;

			nlen *= FORMAT_SIZE;

			for (n = nfmt; n = memchr(n, 'n', nfmt + nlen - n);
			    n++) {
				int off = (n - nfmt);

				if (off >= olen * FORMAT_SIZE ||
				    ofmt[off] != 'n' ||
				    ofmt[off+1] != nfmt[off+1]) {
					free(ofmt);
					free(nfmt);
					syslog(LOG_AUTH|LOG_NOTICE,
					    "dangerous format in message file: "
					    "\"%.100s\" -> \"%s\"", torg, new);
					errno = EBADMSG;
					return ((char *)org);
				}
			}
			free(ofmt);
			free(nfmt);
			return ((char *)new);
		}
		free(ofmt);
		free(nfmt);
		syslog(LOG_AUTH|LOG_NOTICE,
		    "incompatible format in message file \"%.100s\" != \"%s\"",
		    torg, new);
		errno = EBADMSG;
		return ((char *)org);
	}
}

/*
 * s1 is either name, or name=value
 * s2 is name=value
 * if names match, return value of s2, else NULL
 * used for environment searching: see getenv
 */
const char *
nvmatch(const char *s1, const char *s2)
{
	while (*s1 == *s2++)
		if (*s1++ == '=')
			return (s2);
	if (*s1 == '\0' && *(s2-1) == '=')
		return (s2);
	return (NULL);
}

/*
 * Handle NLSPATH environment variables in the environment.
 * This routine is hooked into getenv/putenv at first call.
 *
 * The intention is to ignore NLSPATH in set-uid applications,
 * and determine whether the NLSPATH in an application was set
 * by the applications or derived from the user's environment.
 */

void
clean_env(void)
{
	const char **p;

	if (_environ == NULL) {
		/* can happen when processing a SunOS 4.x AOUT file */
		nlspath_safe = 1;
		return;
	}

	/* Find the first NLSPATH occurrence */
	for (p = _environ; *p; p++)
		if (**p == 'N' && nvmatch("NLSPATH", *p) != NULL)
			break;

	if (!*p)				/* None found, we're safe */
		nlspath_safe = 1;
	else if (issetugid()) {			/* Found and set-uid, clean */
		int off = 1;

		for (p++; (p[-off] = p[0]) != NULL; p++)
			if (**p == 'N' && nvmatch("NLSPATH", *p) != NULL)
				off++;

		nlspath_safe = 1;
	}
}
