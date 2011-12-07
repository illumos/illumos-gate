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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifdef _KERNEL
#include <sys/types.h>
#include <sys/sunddi.h>
#else
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#endif
#include <sys/u8_textprep.h>
#include <smbsrv/alloc.h>
#include <sys/errno.h>
#include <smbsrv/string.h>
#include <smbsrv/cp_usascii.h>
#include <smbsrv/cp_unicode.h>

#define	UNICODE_N_ENTRIES	(sizeof (a_unicode) / sizeof (a_unicode[0]))

/*
 * Global pointer to the current codepage: defaults to ASCII,
 * and a flag indicating whether the codepage is Unicode or ASCII.
 */
static const smb_codepage_t *current_codepage = usascii_codepage;
static boolean_t is_unicode = B_FALSE;

static smb_codepage_t *smb_unicode_init(void);

/*
 * strsubst
 *
 * Scan a string replacing all occurrences of orgchar with newchar.
 * Returns a pointer to s, or null of s is null.
 */
char *
strsubst(char *s, char orgchar, char newchar)
{
	char *p = s;

	if (p == 0)
		return (0);

	while (*p) {
		if (*p == orgchar)
			*p = newchar;
		++p;
	}

	return (s);
}

/*
 * strcanon
 *
 * Normalize a string by reducing all the repeated characters in
 * buf as defined by class. For example;
 *
 *		char *buf = strdup("/d1//d2//d3\\\\d4\\\\f1.txt");
 *		strcanon(buf, "/\\");
 *
 * Would result in buf containing the following string:
 *
 *		/d1/d2/d3\d4\f1.txt
 *
 * This function modifies the contents of buf in place and returns
 * a pointer to buf.
 */
char *
strcanon(char *buf, const char *class)
{
	char *p = buf;
	char *q = buf;
	char *r;

	while (*p) {
		*q++ = *p;

		if ((r = strchr(class, *p)) != 0) {
			while (*p == *r)
				++p;
		} else
			++p;
	}

	*q = '\0';
	return (buf);
}

void
smb_codepage_init(void)
{
	const smb_codepage_t *cp;

	if (is_unicode)
		return;

	if ((cp = smb_unicode_init()) != NULL) {
		current_codepage = cp;
		is_unicode = B_TRUE;
	} else {
		current_codepage = usascii_codepage;
		is_unicode = B_FALSE;
	}
}

/*
 * Determine whether or not a character is an uppercase character.
 * This function operates on the current codepage table. Returns
 * non-zero if the character is uppercase. Otherwise returns zero.
 */
int
smb_isupper(int c)
{
	uint16_t mask = is_unicode ? 0xffff : 0xff;

	return (current_codepage[c & mask].ctype & CODEPAGE_ISUPPER);
}

/*
 * Determine whether or not a character is an lowercase character.
 * This function operates on the current codepage table. Returns
 * non-zero if the character is lowercase. Otherwise returns zero.
 */
int
smb_islower(int c)
{
	uint16_t mask = is_unicode ? 0xffff : 0xff;

	return (current_codepage[c & mask].ctype & CODEPAGE_ISLOWER);
}

/*
 * Convert individual characters to their uppercase equivalent value.
 * If the specified character is lowercase, the uppercase value will
 * be returned. Otherwise the original value will be returned.
 */
int
smb_toupper(int c)
{
	uint16_t mask = is_unicode ? 0xffff : 0xff;

	return (current_codepage[c & mask].upper);
}

/*
 * Convert individual characters to their lowercase equivalent value.
 * If the specified character is uppercase, the lowercase value will
 * be returned. Otherwise the original value will be returned.
 */
int
smb_tolower(int c)
{
	uint16_t mask = is_unicode ? 0xffff : 0xff;

	return (current_codepage[c & mask].lower);
}

/*
 * Convert a string to uppercase using the appropriate codepage. The
 * string is converted in place. A pointer to the string is returned.
 * There is an assumption here that uppercase and lowercase values
 * always result encode to the same length.
 */
char *
smb_strupr(char *s)
{
	smb_wchar_t c;
	char *p = s;

	while (*p) {
		if (smb_isascii(*p)) {
			*p = smb_toupper(*p);
			p++;
		} else {
			if (smb_mbtowc(&c, p, MTS_MB_CHAR_MAX) < 0)
				return (0);

			if (c == 0)
				break;

			c = smb_toupper(c);
			p += smb_wctomb(p, c);
		}
	}

	return (s);
}

/*
 * Convert a string to lowercase using the appropriate codepage. The
 * string is converted in place. A pointer to the string is returned.
 * There is an assumption here that uppercase and lowercase values
 * always result encode to the same length.
 */
char *
smb_strlwr(char *s)
{
	smb_wchar_t c;
	char *p = s;

	while (*p) {
		if (smb_isascii(*p)) {
			*p = smb_tolower(*p);
			p++;
		} else {
			if (smb_mbtowc(&c, p, MTS_MB_CHAR_MAX) < 0)
				return (0);

			if (c == 0)
				break;

			c = smb_tolower(c);
			p += smb_wctomb(p, c);
		}
	}

	return (s);
}

/*
 * Returns 1 if string contains NO uppercase chars 0 otherwise. However,
 * -1 is returned if "s" is not a valid multi-byte string.
 */
int
smb_isstrlwr(const char *s)
{
	smb_wchar_t c;
	int n;
	const char *p = s;

	while (*p) {
		if (smb_isascii(*p) && smb_isupper(*p))
			return (0);
		else {
			if ((n = smb_mbtowc(&c, p, MTS_MB_CHAR_MAX)) < 0)
				return (-1);

			if (c == 0)
				break;

			if (smb_isupper(c))
				return (0);

			p += n;
		}
	}

	return (1);
}

/*
 * Returns 1 if string contains NO lowercase chars 0 otherwise. However,
 * -1 is returned if "s" is not a valid multi-byte string.
 */
int
smb_isstrupr(const char *s)
{
	smb_wchar_t c;
	int n;
	const char *p = s;

	while (*p) {
		if (smb_isascii(*p) && smb_islower(*p))
			return (0);
		else {
			if ((n = smb_mbtowc(&c, p, MTS_MB_CHAR_MAX)) < 0)
				return (-1);

			if (c == 0)
				break;

			if (smb_islower(c))
				return (0);

			p += n;
		}
	}

	return (1);
}

/*
 * Compare the null-terminated strings s1 and s2 and return an integer
 * greater than, equal to or less than 0 dependent on whether s1 is
 * lexicographically greater than, equal to or less than s2 after
 * translation of each character to lowercase.  The original strings
 * are not modified.
 *
 * If n is non-zero, at most n bytes are compared.  Otherwise, the strings
 * are compared until a null terminator is encountered.
 *
 * Out:    0 if strings are equal
 *       < 0 if first string < second string
 *       > 0 if first string > second string
 */
int
smb_strcasecmp(const char *s1, const char *s2, size_t n)
{
	int	err = 0;
	int	rc;

	rc = u8_strcmp(s1, s2, n, U8_STRCMP_CI_LOWER, U8_UNICODE_LATEST, &err);
	if (err != 0)
		return (-1);
	return (rc);
}

/*
 * First build a codepage based on cp_unicode.h.  Then build the unicode
 * codepage from this interim codepage by copying the entries over while
 * fixing them and filling in the gaps.
 */
static smb_codepage_t *
smb_unicode_init(void)
{
	smb_codepage_t	*unicode;
	uint32_t	a = 0;
	uint32_t	b = 0;

	unicode = MEM_ZALLOC("unicode", sizeof (smb_codepage_t) << 16);
	if (unicode == NULL)
		return (NULL);

	while (b != 0xffff) {
		/*
		 * If there is a gap in the standard,
		 * fill in the gap with no-case entries.
		 */
		if (UNICODE_N_ENTRIES <= a || a_unicode[a].val > b) {
			unicode[b].ctype = CODEPAGE_ISNONE;
			unicode[b].upper = (smb_wchar_t)b;
			unicode[b].lower = (smb_wchar_t)b;
			b++;
			continue;
		}

		/*
		 * Copy the entry and fixup as required.
		 */
		switch (a_unicode[a].ctype) {
		case CODEPAGE_ISNONE:
			/*
			 * Replace 0xffff in upper/lower fields with its val.
			 */
			unicode[b].ctype = CODEPAGE_ISNONE;
			unicode[b].upper = (smb_wchar_t)b;
			unicode[b].lower = (smb_wchar_t)b;
			break;
		case CODEPAGE_ISUPPER:
			/*
			 * Some characters may have case yet not have
			 * case conversion.  Treat them as no-case.
			 */
			if (a_unicode[a].lower == 0xffff) {
				unicode[b].ctype = CODEPAGE_ISNONE;
				unicode[b].upper = (smb_wchar_t)b;
				unicode[b].lower = (smb_wchar_t)b;
			} else {
				unicode[b].ctype = CODEPAGE_ISUPPER;
				unicode[b].upper = (smb_wchar_t)b;
				unicode[b].lower = a_unicode[a].lower;
			}
			break;
		case CODEPAGE_ISLOWER:
			/*
			 * Some characters may have case yet not have
			 * case conversion.  Treat them as no-case.
			 */
			if (a_unicode[a].upper == 0xffff) {
				unicode[b].ctype = CODEPAGE_ISNONE;
				unicode[b].upper = (smb_wchar_t)b;
				unicode[b].lower = (smb_wchar_t)b;
			} else {
				unicode[b].ctype = CODEPAGE_ISLOWER;
				unicode[b].upper = a_unicode[a].upper;
				unicode[b].lower = (smb_wchar_t)b;
			}
			break;
		default:
			MEM_FREE("unicode", unicode);
			return (NULL);
		}

		a++;
		b++;
	};

	return (unicode);
}

/*
 * Parse a UNC path (\\server\share\path) into its components.
 * Although a standard UNC path starts with two '\', in DFS
 * all UNC paths start with one '\'. So, this function only
 * checks for one.
 *
 * A valid UNC must at least contain two components i.e. server
 * and share. The path is parsed to:
 *
 * unc_server	server or domain name with no leading/trailing '\'
 * unc_share	share name with no leading/trailing '\'
 * unc_path	relative path to the share with no leading/trailing '\'
 * 		it is valid for unc_path to be NULL.
 *
 * Upon successful return of this function, smb_unc_free()
 * MUST be called when returned 'unc' is no longer needed.
 *
 * Returns 0 on success, otherwise returns an errno code.
 */
int
smb_unc_init(const char *path, smb_unc_t *unc)
{
	char *p;

	if (path == NULL || unc == NULL || (*path != '\\' && *path != '/'))
		return (EINVAL);

	bzero(unc, sizeof (smb_unc_t));

#ifdef _KERNEL
	unc->unc_buf = smb_mem_strdup(path);
#else
	if ((unc->unc_buf = strdup(path)) == NULL)
		return (ENOMEM);
#endif

	(void) strsubst(unc->unc_buf, '\\', '/');
	(void) strcanon(unc->unc_buf, "/");

	unc->unc_server = unc->unc_buf + 1;
	if (*unc->unc_server == '\0') {
		smb_unc_free(unc);
		return (EINVAL);
	}

	if ((p = strchr(unc->unc_server, '/')) == NULL) {
		smb_unc_free(unc);
		return (EINVAL);
	}

	*p++ = '\0';
	unc->unc_share = p;

	if (*unc->unc_share == '\0') {
		smb_unc_free(unc);
		return (EINVAL);
	}

	unc->unc_path = strchr(unc->unc_share, '/');
	if ((p = unc->unc_path) == NULL)
		return (0);

	unc->unc_path++;
	*p = '\0';

	/* remove the last '/' if any */
	if ((p = strchr(unc->unc_path, '\0')) != NULL) {
		if (*(--p) == '/')
			*p = '\0';
	}

	return (0);
}

void
smb_unc_free(smb_unc_t *unc)
{
	if (unc == NULL)
		return;

#ifdef _KERNEL
	smb_mem_free(unc->unc_buf);
#else
	free(unc->unc_buf);
#endif
	unc->unc_buf = NULL;
}
