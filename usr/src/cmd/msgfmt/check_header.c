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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "sun_msgfmt.h"

static const char	*mandatory_fields[] = {
	"Project-Id-Version",
	"PO-Revision-Date",
	"Last-Translator",
	"Language-Team",
	"Content-Type",
	"Content-Transfer-Encoding",
	NULL
};

static const char	*mandatory_fields_new[] = {
	"POT-Creation-Date",
	"Plural-Forms",
	NULL
};

extern int	verbose;

extern void	invoke_gnu_msgfmt(void);

static size_t
get_one_line(char **bufhead, char **mbuf, size_t *fsize)
{
	size_t	len;
	char	*p = *mbuf;
	char	*q, *tmp;

	if (*bufhead) {
		free(*bufhead);
		*bufhead = NULL;
	}

	if (*fsize == 0) {
		/* eof */
		return (0);
	}

	q = p;
	while (((*fsize) != 0) && (*p++ != '\n')) {
		(*fsize)--;
	}
	len = p - q;
	if (len == 0) {
		return (0);
	}
	tmp = (char *)Xmalloc(len + 1);
	(void) memcpy(tmp, q, len);
	tmp[len] = '\0';
	*bufhead = tmp;
	*mbuf = p;
	return (len);
}

void
check_gnu(char *addr, size_t fsize)
{
	int	i;
	char	c, mc;
	char	*linebuf;
	char	*mbuf, *p, *buf;
	unsigned int	n;
	size_t	ln_size;
	size_t	bufsize, index;
	size_t	size = fsize;
	int	quotefound = 0;
	const char	*field;

	buf = NULL;
	linebuf = NULL;
	mbuf = addr;

loop:
	ln_size = get_one_line(&linebuf, &mbuf, &size);
	if ((ln_size == (size_t)-1) ||
		(ln_size == 0)) {
		goto no_gnu;
	}
	p = linebuf;

	while ((*p == '#') || (*p == '\n')) {
		ln_size = get_one_line(&linebuf, &mbuf, &size);
		if ((ln_size == (size_t)-1) ||
			(ln_size == 0)) {
			goto no_gnu;
		}
		p = linebuf;
	}

	if (strncmp(p, "domain", 6) == 0)
		goto loop;

	if (strncmp(p, "msgid", 5) != 0) {
		/* error */
		goto no_gnu;
	}

	p += 5;
	if ((*p != ' ') && (*p != '\t') &&
		(*p != '\n') && (*p != '\0')) {
		/* no space after msgid */
		goto no_gnu;
	}
	/* skip spaces */
	while ((*p == ' ') || (*p == '\t'))
		p++;

	/* check if this entry is an empty string */
	if ((*p != '\"') || (*(p + 1) != '\"')) {
		/* this is not an empty string */
		goto no_gnu;
	}
	p += 2;
	while (*p && ((*p == ' ') || (*p == '\t'))) {
		p++;
	}
	if ((*p != '\n') && (*p != '\0')) {
		/* other characters than '\n' and '\0' found */
		goto no_gnu;
	}

	for (; ; ) {
		ln_size = get_one_line(&linebuf, &mbuf, &size);
		if ((ln_size == (size_t)-1) ||
			(ln_size == 0)) {
			goto no_gnu;
		}
		p = linebuf;
		/* skip leading spaces */
		while ((*p == ' ') || (*p == '\t'))
			p++;

		if (*p != '\"') {
			if (strncmp(p, "msgstr", 6) == 0) {
				break;
			}
			/* not a valid entry */
			goto no_gnu;
		}
		if (*(p + 1) != '\"') {
			/* not an empty string */
			goto no_gnu;
		}
		p += 2;
		while ((*p == ' ') || (*p == '\t'))
			p++;

		if ((*p != '\n') && (*p != '\0')) {
			/* other characters than '\n' and '\0' found */
			goto no_gnu;
		}
	}

	/*
	 * msgid for the header entry found
	 * Now p points to "msgstr"
	 */
	p += 6;
	if ((*p != ' ') && (*p != '\t') &&
		(*p != '\n') && (*p != '\0')) {
		/* no space after msgid */
		goto no_gnu;
	}

	/* skip spaces */
	while ((*p == ' ') || (*p == '\t'))
		p++;

	if (*p != '\"') {
		/* no quote */
		goto no_gnu;
	}

	bufsize = ln_size + 1;
	index = 0;
	buf = (char *)Xmalloc(bufsize);

	for (; ; ) {
		if (*p != '\"') {
			/* msgstr entry ends */
			buf[index] = '\0';
			break;
		}

		if (*p++ != '\"') {
			/* no beginning quote */
			goto no_gnu;
		}
		while (*p) {
			switch (mc = *p++) {
			case '\n':
				if (!quotefound) {
					/* error */
					goto no_gnu;
				}
				break;
			case '\"':
				quotefound = 1;
				break;
			case '\\':
				if (!*p)
					break;
				switch (c = *p++) {
				case 'b':
					buf[index++] = '\b';
					break;
				case 'f':
					buf[index++] = '\f';
					break;
				case 'n':
					buf[index++] = '\n';
					break;
				case 'r':
					buf[index++] = '\r';
					break;
				case 't':
					buf[index++] = '\t';
					break;
				case 'v':
					buf[index++] = '\v';
					break;
				case 'a':
					buf[index++] = '\a';
					break;
				case '\"':
				case '\\':
				case '\'':
				case '?':
					buf[index++] = c;
					break;
				default:
					if (isdigit((unsigned char)c)) {
						unsigned int	x;
						unsigned char	*up =
							(unsigned char *)p;
						n = c - '0';
						if (isdigit(*up)) {
							x = *up++ - '0';
							n = 8 * n + x;
							if (isdigit(*up)) {
								x = *up++ - '0';
								n = 8 * n + x;
							}
						}
						p = (char *)up;
						buf[index++] = n;
					}
					break;
				}
				break;
			default:
				buf[index++] = mc;
				break;
			}
			if (quotefound) {
				while (*p && ((*p == ' ') || (*p == '\t'))) {
					p++;
				}
				if ((*p != '\n') && (*p != '\0')) {
					goto no_gnu;
				}
				quotefound = 0;
				break;
			}
		}
		ln_size = get_one_line(&linebuf, &mbuf, &size);
		if ((ln_size == (size_t)-1) ||
			(ln_size == 0)) {
			goto no_gnu;
		}
		p = linebuf;
		/* skip spaces */
		while ((*p == ' ') || (*p == '\t'))
			p++;
		bufsize += ln_size;
		buf = (char *)Xrealloc(buf, bufsize);
	}

	for (i = 0; (field = mandatory_fields[i]) != NULL; i++) {
		if (strstr(buf, field) == NULL)
			continue;
		/* one of mandatory fields found */
		free(linebuf);
		free(buf);
		(void) munmap(addr, fsize);
		if (verbose)
			diag(gettext(DIAG_GNU_FOUND));
		invoke_gnu_msgfmt();
		/* NOTREACHED */
	}
	for (i = 0; (field = mandatory_fields_new[i]) != NULL; i++) {
		if (strstr(buf, field) == NULL)
			continue;
		/* one of mandatory fields found */
		free(linebuf);
		free(buf);
		(void) munmap(addr, fsize);
		if (verbose)
			diag(gettext(DIAG_GNU_FOUND));
		invoke_gnu_msgfmt();
		/* NOTREACHED */
	}

no_gnu:
	free(linebuf);
	if (buf)
		free(buf);
}
