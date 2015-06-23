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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc. All rights reserved.
 */

#if !defined(_KERNEL) && !defined(_FAKE_KERNEL)
#include <stdlib.h>
#include <string.h>
#else
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/sunddi.h>
#endif
#include <smbsrv/string.h>
#include <smbsrv/smb.h>

/*
 * Maximum recursion depth for the wildcard match functions.
 * These functions may recurse when processing a '*'.
 */
#define	SMB_MATCH_DEPTH_MAX	32

struct match_priv {
	int depth;
	boolean_t ci;
};

static int smb_match_private(const char *, const char *, struct match_priv *);

static const char smb_wildcards[] = "*?<>\"";

/*
 * Return B_TRUE if pattern contains wildcards
 */
boolean_t
smb_contains_wildcards(const char *pattern)
{

	return (strpbrk(pattern, smb_wildcards) != NULL);
}

/*
 * NT-compatible file name match function.  [MS-FSA 3.1.4.4]
 * Returns TRUE if there is a match.
 */
boolean_t
smb_match(const char *p, const char *s, boolean_t ci)
{
	struct match_priv priv;
	int rc;

	/*
	 * Optimize common patterns that match everything:
	 * ("*", "<\"*")  That second one is the converted
	 * form of "*.*" after smb_convert_wildcards() does
	 * its work on it for an old LM client. Note that a
	 * plain "*.*" never gets this far.
	 */
	if (p[0] == '*' && p[1] == '\0')
		return (B_TRUE);
	if (p[0] == '<' && p[1] == '\"' && p[2] == '*' && p[3] == '\0')
		return (B_TRUE);

	/*
	 * Match string ".." as if "."  This is Windows behavior
	 * (not mentioned in MS-FSA) that was determined using
	 * the Samba masktest program.
	 */
	if (s[0] == '.' && s[1] == '.' && s[2] == '\0')
		s++;

	/*
	 * Optimize simple patterns (no wildcards)
	 */
	if (NULL == strpbrk(p, smb_wildcards)) {
		if (ci)
			rc = smb_strcasecmp(p, s, 0);
		else
			rc = strcmp(p, s);
		return (rc == 0);
	}

	/*
	 * Do real wildcard match.
	 */
	priv.depth = 0;
	priv.ci = ci;
	rc = smb_match_private(p, s, &priv);
	return (rc == 1);
}

/*
 * Internal file name match function.  [MS-FSA 3.1.4.4]
 * This does the full expression evaluation.
 *
 * '*' matches zero of more of any characters.
 * '?' matches exactly one of any character.
 * '<' matches any string up through the last dot or EOS.
 * '>' matches any one char not a dot, dot at EOS, or EOS.
 * '"' matches a dot, or EOS.
 *
 * Returns:
 *  1	match
 *  0	no-match
 * -1	no-match, error (illseq, too many wildcards in pattern, ...)
 *
 * Note that both the pattern and the string are in multi-byte form.
 *
 * The implementation of this is quite tricky.  First note that it
 * can call itself recursively, though it limits the recursion depth.
 * Each switch case in the while loop can basically do one of three
 * things: (a) return "Yes, match", (b) return "not a match", or
 * continue processing the match pattern.  The cases for wildcards
 * that may match a variable number of characters ('*' and '<') do
 * recursive calls, looking for a match of the remaining pattern,
 * starting at the current and later positions in the string.
 */
static int
smb_match_private(const char *pat, const char *str, struct match_priv *priv)
{
	const char	*limit;
	char		pc;		/* current pattern char */
	int		rc;
	smb_wchar_t	wcpat, wcstr;	/* current wchar in pat, str */
	int		nbpat, nbstr;	/* multi-byte length of it */

	if (priv->depth >= SMB_MATCH_DEPTH_MAX)
		return (-1);

	/*
	 * Advance over one multi-byte char, used in cases like
	 * '?' or '>' where "match one character" needs to be
	 * interpreted as "match one multi-byte sequence".
	 *
	 * This	macro needs to consume the semicolon following
	 * each place it appears, so this is carefully written
	 * as an if/else with a missing semicolon at the end.
	 */
#define	ADVANCE(str) \
	if ((nbstr = smb_mbtowc(NULL, str, MTS_MB_CHAR_MAX)) < 1) \
		return (-1); \
	else \
		str += nbstr	/* no ; */

	/*
	 * We move pat forward in each switch case so that the
	 * default case can move it by a whole multi-byte seq.
	 */
	while ((pc = *pat) != '\0') {
		switch (pc) {

		case '?':	/* exactly one of any character */
			pat++;
			if (*str != '\0') {
				ADVANCE(str);
				continue;
			}
			/* EOS: no-match */
			return (0);

		case '*':	/* zero or more of any characters */
			pat++;
			/* Optimize '*' at end of pattern. */
			if (*pat == '\0')
				return (1); /* match */
			while (*str != '\0') {
				priv->depth++;
				rc = smb_match_private(pat, str, priv);
				priv->depth--;
				if (rc != 0)
					return (rc); /* match */
				ADVANCE(str);
			}
			continue;

		case '<':	/* any string up through the last dot or EOS */
			pat++;
			if ((limit = strrchr(str, '.')) != NULL)
				limit++;
			while (*str != '\0' && str != limit) {
				priv->depth++;
				rc = smb_match_private(pat, str, priv);
				priv->depth--;
				if (rc != 0)
					return (rc); /* match */
				ADVANCE(str);
			}
			continue;

		case '>':	/* anything not a dot, dot at EOS, or EOS */
			pat++;
			if (*str == '.') {
				if (str[1] == '\0') {
					/* dot at EOS */
					str++;	/* ADVANCE over '.' */
					continue;
				}
				/* dot NOT at EOS: no-match */
				return (0);
			}
			if (*str != '\0') {
				/* something not a dot */
				ADVANCE(str);
				continue;
			}
			continue;

		case '\"':	/* dot, or EOS */
			pat++;
			if (*str == '.') {
				str++;	/* ADVANCE over '.' */
				continue;
			}
			if (*str == '\0') {
				continue;
			}
			/* something else: no-match */
			return (0);

		default:	/* not a wildcard */
			nbpat = smb_mbtowc(&wcpat, pat, MTS_MB_CHAR_MAX);
			nbstr = smb_mbtowc(&wcstr, str, MTS_MB_CHAR_MAX);
			/* make sure we advance */
			if (nbpat < 1 || nbstr < 1)
				return (-1);
			if (wcpat == wcstr) {
				pat += nbpat;
				str += nbstr;
				continue;
			}
			if (priv->ci) {
				wcpat = smb_tolower(wcpat);
				wcstr = smb_tolower(wcstr);
				if (wcpat == wcstr) {
					pat += nbpat;
					str += nbstr;
					continue;
				}
			}
			return (0); /* no-match */
		}
	}
	return (*str == '\0');
}
