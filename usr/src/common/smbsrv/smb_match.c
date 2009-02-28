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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _KERNEL
#include <stdlib.h>
#include <string.h>
#else
#include <sys/types.h>
#include <sys/sunddi.h>
#endif
#include <smbsrv/ctype.h>

/*
 * Maximum recursion depth for the wildcard match functions.
 * These functions may recurse when processing a '*'.
 */
#define	SMB_MATCH_DEPTH_MAX	32

#define	SMB_CRC_POLYNOMIAL	0xD8B5D8B5

static int smb_match_private(const char *, const char *, int *);
static int smb_match_ci_private(const char *, const char *, int *);

/*
 * Returns:
 * 1	match
 * 0	no-match
 */
int
smb_match(char *patn, char *str)
{
	int depth = 0;
	int rc;

	if ((rc = smb_match_private(patn, str, &depth)) == -1)
		rc = 0;

	return (rc);
}

/*
 * The '*' character matches multiple characters.
 * The '?' character matches a single character.
 *
 * If the pattern has trailing '?'s then it matches the specified number
 * of characters or less.  For example, "x??" matches "xab", "xa" and "x",
 * but not "xabc".
 *
 * Returns:
 * 1	match
 * 0	no-match
 * -1	no-match, too many wildcards in pattern
 */
static int
smb_match_private(const char *patn, const char *str, int *depth)
{
	int rc;

	for (;;) {
		switch (*patn) {
		case 0:
			return (*str == 0);

		case '?':
			if (*str != 0) {
				str++;
				patn++;
				continue;
			} else {
				return (0);
			}
			/*NOTREACHED*/

		case '*':
			patn += strspn(patn, "*");
			if (*patn == 0)
				return (1);

			if ((*depth)++ >= SMB_MATCH_DEPTH_MAX)
				return (-1);

			while (*str) {
				rc = smb_match_private(patn, str, depth);
				if (rc != 0)
					return (rc);
				str++;
			}
			return (0);

		default:
			if (*str != *patn)
				return (0);
			str++;
			patn++;
			continue;
		}
	}
	/*NOTREACHED*/
}

int
smb_match83(char *patn, char *str83)
{
	int	avail;
	char	*ptr;
	char	name83[14];

	ptr = name83;
	for (avail = 8; (avail > 0) && (*patn != '.') && (*patn != 0);
	    avail--) {
		*(ptr++) = *(patn++);
	}
	while (avail--)
		*(ptr++) = ' ';
	*(ptr++) = '.';

	if (*patn == '.')
		patn++;
	else if (*patn != 0)
		return (0);

	for (avail = 3; (avail > 0) && (*patn != 0); avail--) {
		*(ptr++) = *(patn++);
	}
	if (*patn != 0)
		return (0);

	while (avail--)
		*(ptr++) = ' ';
	*ptr = 0;

	return (smb_match_ci(name83, str83));
}

/*
 * Returns:
 * 1	match
 * 0	no-match
 */
int
smb_match_ci(char *patn, char *str)
{
	int depth = 0;
	int rc;

	if ((rc = smb_match_ci_private(patn, str, &depth)) == -1)
		rc = 0;

	return (rc);
}

/*
 * The '*' character matches multiple characters.
 * The '?' character matches a single character.
 *
 * If the pattern has trailing '?'s then it matches the specified number
 * of characters or less.  For example, "x??" matches "xab", "xa" and "x",
 * but not "xabc".
 *
 * Returns:
 * 1	match
 * 0	no-match
 * -1	no-match, too many wildcards in pattern
 */
static int
smb_match_ci_private(const char *patn, const char *str, int *depth)
{
	const char *p;
	int rc;

	/*
	 * "<" is a special pattern that matches only those names that do
	 * NOT have an extension. "." and ".." are ok.
	 */
	if (strcmp(patn, "<") == 0) {
		if ((strcmp(str, ".") == 0) || (strcmp(str, "..") == 0))
			return (1);
		if (strchr(str, '.') == 0)
			return (1);
		return (0);
	}

	for (;;) {
		switch (*patn) {
		case 0:
			return (*str == 0);

		case '?':
			if (*str != 0) {
				str++;
				patn++;
				continue;
			} else {
				p = patn;
				p += strspn(p, "?");
				return ((*p == '\0') ? 1 : 0);
			}
			/*NOTREACHED*/

		case '*':
			patn += strspn(patn, "*");
			if (*patn == 0)
				return (1);

			if ((*depth)++ >= SMB_MATCH_DEPTH_MAX)
				return (-1);

			while (*str) {
				rc = smb_match_ci_private(patn, str, depth);
				if (rc != 0)
					return (rc);
				str++;
			}
			return (0);

		default:
			if (*str != *patn) {
				int	c1 = *str;
				int	c2 = *patn;

				c1 = mts_tolower(c1);
				c2 = mts_tolower(c2);
				if (c1 != c2)
					return (0);
			}
			str++;
			patn++;
			continue;
		}
	}
	/*NOTREACHED*/
}

uint32_t
smb_crc_gen(uint8_t *buf, size_t len)
{
	uint32_t crc = SMB_CRC_POLYNOMIAL;
	uint8_t *p;
	int i;

	for (p = buf, i = 0; i < len; ++i, ++p) {
		crc = (crc ^ (uint32_t)*p) + (crc << 12);

		if (crc == 0 || crc == 0xFFFFFFFF)
			crc = SMB_CRC_POLYNOMIAL;
	}

	return (crc);
}
