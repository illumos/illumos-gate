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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2019 Joyent, Inc.
 */

#include <strings.h>
#include <ctype.h>
#include <fm/libtopo.h>
#include <fm/topo_mod.h>
#include <topo_alloc.h>

char *
topo_hdl_strdup(topo_hdl_t *thp, const char *s)
{
	char *p;

	if (s != NULL)
		p = topo_hdl_alloc(thp, strlen(s) + 1);
	else
		p = NULL;

	if (p != NULL)
		(void) strcpy(p, s);

	return (p);
}

void
topo_hdl_strfree(topo_hdl_t *thp, char *s)
{
	if (s != NULL)
		topo_hdl_free(thp, s, strlen(s) + 1);
}

void
topo_hdl_strfreev(topo_hdl_t *thp, char **strarr, uint_t nelem)
{
	for (int i = 0; i < nelem; i++)
		topo_hdl_strfree(thp, strarr[i]);

	topo_hdl_free(thp, strarr, (nelem * sizeof (char *)));
}

char *
topo_hdl_strsplit(topo_hdl_t *hdl, const char *input, const char *sep,
    char **lastp)
{
	size_t seplen = strlen(sep);
	const char *scanstart;
	char *token;
	char *ret;

	if (input != NULL) {
		/*
		 * Start scanning at beginning of input:
		 */
		scanstart = input;
	} else if (*lastp == NULL) {
		/*
		 * If we have already finished scanning, return NULL.
		 */
		return (NULL);
	} else {
		/*
		 * Otherwise, start scanning where we left off:
		 */
		scanstart = *lastp;
	}

	token = strstr(scanstart, sep);
	if (token != NULL) {
		/*
		 * We still have a separator, so advance the next-start
		 * pointer past it:
		 */
		*lastp = token + seplen;
		/*
		 * Copy out this element.  The buffer must fit the string
		 * exactly, so that topo_hdl_strfree() can determine its
		 * size with strlen().
		 */
		ret = topo_hdl_alloc(hdl, token - scanstart + 1);
		(void) strncpy(ret, scanstart, token - scanstart);
		ret[token - scanstart] = '\0';
	} else {
		/*
		 * We have no separator, so this is the last element:
		 */
		*lastp = NULL;
		ret = topo_hdl_strdup(hdl, scanstart);
	}

	return (ret);
}

char *
topo_mod_strdup(topo_mod_t *mod, const char *s)
{
	return (topo_hdl_strdup(mod->tm_hdl, s));
}

void
topo_mod_strfree(topo_mod_t *mod, char *s)
{
	topo_hdl_strfree(mod->tm_hdl, s);
}

void
topo_mod_strfreev(topo_mod_t *mod, char **strarr, uint_t nelem)
{
	topo_hdl_strfreev(mod->tm_hdl, strarr, nelem);
}

char *
topo_mod_strsplit(topo_mod_t *mod, const char *input, const char *sep,
    char **lastp)
{
	return (topo_hdl_strsplit(mod->tm_hdl, input, sep, lastp));
}

const char *
topo_strbasename(const char *s)
{
	const char *p = strrchr(s, '/');

	if (p == NULL)
		return (s);

	return (++p);
}

char *
topo_strdirname(char *s)
{
	static char slash[] = "/";
	static char dot[] = ".";
	char *p;

	if (s == NULL || *s == '\0')
		return (dot);

	for (p = s + strlen(s); p != s && *--p == '/'; )
		continue;

	if (p == s && *p == '/')
		return (slash);

	while (p != s) {
		if (*--p == '/') {
			while (*p == '/' && p != s)
				p--;
			*++p = '\0';
			return (s);
		}
	}

	return (dot);
}

ulong_t
topo_strhash(const char *key)
{
	ulong_t g, h = 0;
	const char *p;

	for (p = key; *p != '\0'; p++) {
		h = (h << 4) + *p;

		if ((g = (h & 0xf0000000)) != 0) {
			h ^= (g >> 24);
			h ^= g;
		}
	}

	return (h);
}

/*
 * Transform string s inline, converting each embedded C escape sequence string
 * to the corresponding character.  For example, the substring "\n" is replaced
 * by an inline '\n' character.  The length of the resulting string is returned.
 */
size_t
topo_stresc2chr(char *s)
{
	char *p, *q, c;
	int esc = 0;
	int x;

	for (p = q = s; (c = *p) != '\0'; p++) {
		if (esc) {
			switch (c) {
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
				c -= '0';
				p++;

				if (*p >= '0' && *p <= '7') {
					c = c * 8 + *p++ - '0';

					if (*p >= '0' && *p <= '7')
						c = c * 8 + *p - '0';
					else
						p--;
				} else
					p--;

				*q++ = c;
				break;

			case 'a':
				*q++ = '\a';
				break;
			case 'b':
				*q++ = '\b';
				break;
			case 'f':
				*q++ = '\f';
				break;
			case 'n':
				*q++ = '\n';
				break;
			case 'r':
				*q++ = '\r';
				break;
			case 't':
				*q++ = '\t';
				break;
			case 'v':
				*q++ = '\v';
				break;

			case 'x':
				for (x = 0; (c = *++p) != '\0'; ) {
					if (c >= '0' && c <= '9')
						x = x * 16 + c - '0';
					else if (c >= 'a' && c <= 'f')
						x = x * 16 + c - 'a' + 10;
					else if (c >= 'A' && c <= 'F')
						x = x * 16 + c - 'A' + 10;
					else
						break;
				}
				*q++ = (char)x;
				p--;
				break;

			case '"':
			case '\\':
				*q++ = c;
				break;
			default:
				*q++ = '\\';
				*q++ = c;
			}

			esc = 0;

		} else {
			if ((esc = c == '\\') == 0)
				*q++ = c;
		}
	}

	*q = '\0';
	return ((size_t)(q - s));
}

int
topo_strmatch(const char *s, const char *p)
{
	char c;

	if (p == NULL)
		return (0);

	if (s == NULL)
		s = ""; /* treat NULL string as the empty string */

	do {
		if ((c = *p++) == '\0')
			return (*s == '\0');

		if (c == '*') {
			while (*p == '*')
				p++; /* consecutive *'s can be collapsed */

			if (*p == '\0')
				return (1);

			while (*s != '\0') {
				if (topo_strmatch(s++, p) != 0)
					return (1);
			}

			return (0);
		}
	} while (c == *s++);

	return (0);
}
