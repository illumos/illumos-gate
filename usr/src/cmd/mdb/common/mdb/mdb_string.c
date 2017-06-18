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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <netinet/in.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <mdb/mdb_string.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_lex.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb.h>

/*
 * Convert the specified integer value to a string represented in the given
 * base.  The flags parameter is a bitfield of the formatting flags defined in
 * mdb_string.h.  A pointer to a static conversion buffer is returned.
 */
const char *
numtostr(uintmax_t uvalue, int base, uint_t flags)
{
	static const char ldigits[] = "0123456789abcdef";
	static const char udigits[] = "0123456789ABCDEF";

	static char buf[68]; /* Enough for ULLONG_MAX in binary plus prefixes */

	const char *digits = (flags & NTOS_UPCASE) ? udigits : ldigits;
	int i = sizeof (buf);

	intmax_t value = (intmax_t)uvalue;
	int neg = (flags & NTOS_UNSIGNED) == 0 && value < 0;
	uintmax_t rem = neg ? -value : value;

	buf[--i] = 0;

	do {
		buf[--i] = digits[rem % base];
		rem /= base;
	} while (rem != 0);

	if (flags & NTOS_SHOWBASE) {
		uintmax_t lim;
		char c = 0;

		switch (base) {
		case 2:
			lim = 1;
			c = 'i';
			break;
		case 8:
			lim = 7;
			c = 'o';
			break;
		case 10:
			lim = 9;
			c = 't';
			break;
		case 16:
			lim = 9;
			c = 'x';
			break;
		}

		if (c != 0 && uvalue > lim) {
			buf[--i] = c;
			buf[--i] = '0';
		}
	}

	if (neg)
		buf[--i] = '-';
	else if (flags & NTOS_SIGNPOS)
		buf[--i] = '+';

	return ((const char *)(&buf[i]));
}

#define	CTOI(x)	(((x) >= '0' && (x) <= '9') ? (x) - '0' : \
	((x) >= 'a' && (x) <= 'z') ? (x) + 10 - 'a' : (x) + 10 - 'A')

/*
 * Convert a string to an unsigned integer value using the specified base.
 * In the event of overflow or an invalid character, we generate an
 * error message and longjmp back to the main loop using yyerror().
 */
uintmax_t
mdb_strtonum(const char *s, int base)
{
	uintmax_t multmax = (uintmax_t)ULLONG_MAX / (uintmax_t)(uint_t)base;
	uintmax_t val = 0;
	int c, i, neg = 0;

	switch (c = *s) {
	case '-':
		neg++;
		/*FALLTHRU*/
	case '+':
		c = *++s;
	}

	if (c == '\0')
		goto done;

	if ((val = CTOI(c)) >= base)
		yyerror("digit '%c' is invalid in current base\n", c);

	for (c = *++s; c != '\0'; c = *++s) {
		if (val > multmax)
			goto oflow;

		if ((i = CTOI(c)) >= base)
			yyerror("digit '%c' is invalid in current base\n", c);

		val *= base;

		if ((uintmax_t)ULLONG_MAX - val < (uintmax_t)i)
			goto oflow;

		val += i;
	}
done:
	return (neg ? -val : val);
oflow:
	yyerror("specified value exceeds maximum immediate value\n");
	return ((uintmax_t)ULLONG_MAX);
}

/*
 * Quick string to unsigned long conversion function.  This function performs
 * no overflow checking and is only meant for internal mdb use.  It allows
 * the caller to specify the length of the string in bytes and a base.
 */
ulong_t
strntoul(const char *s, size_t nbytes, int base)
{
	ulong_t n;
	int c;

	for (n = 0; nbytes != 0 && (c = *s) != '\0'; s++, nbytes--)
		n = n * base + CTOI(c);

	return (n);
}

/*
 * Return a boolean value indicating whether or not a string consists
 * solely of characters which are digits 0..9.
 */
int
strisnum(const char *s)
{
	for (; *s != '\0'; s++) {
		if (*s < '0' || *s > '9')
			return (0);
	}

	return (1);
}

/*
 * Return a boolean value indicating whether or not a string contains a
 * number.  The number may be in the current radix, or it may have an
 * explicit radix qualifier.  The number will be validated against the
 * legal characters for the given radix.
 */
int
strisbasenum(const char *s)
{
	char valid[] = "0123456789aAbBcCdDeEfF";
	int radix = mdb.m_radix;

	if (s[0] == '0') {
		switch (s[1]) {
		case 'I':
		case 'i':
			radix = 2;
			s += 2;
			break;
		case 'O':
		case 'o':
			radix = 8;
			s += 2;
			break;
		case 'T':
		case 't':
			radix = 10;
			s += 2;
			break;
		case 'x':
		case 'X':
			radix = 16;
			s += 2;
			break;
		}
	}

	/* limit `valid' to the digits valid for this base */
	valid[radix > 10 ? 10 + (radix - 10) * 2 : radix] = '\0';

	do {
		if (!strchr(valid, *s))
			return (0);
	} while (*++s != '\0');

	return (1);
}

/*
 * Quick string to integer (base 10) conversion function.  This performs
 * no overflow checking and is only meant for internal mdb use.
 */
int
strtoi(const char *s)
{
	int c, n;

	for (n = 0; (c = *s) >= '0' && c <= '9'; s++)
		n = n * 10 + c - '0';

	return (n);
}

/*
 * Create a copy of string s using the mdb allocator interface.
 */
char *
strdup(const char *s)
{
	char *s1 = mdb_alloc(strlen(s) + 1, UM_SLEEP);

	(void) strcpy(s1, s);
	return (s1);
}

/*
 * Create a copy of string s, but only duplicate the first n bytes.
 */
char *
strndup(const char *s, size_t n)
{
	char *s2 = mdb_alloc(n + 1, UM_SLEEP);

	(void) strncpy(s2, s, n);
	s2[n] = '\0';
	return (s2);
}

/*
 * Convenience routine for freeing strings.
 */
void
strfree(char *s)
{
	mdb_free(s, strlen(s) + 1);
}

/*
 * Transform string s inline, converting each embedded C escape sequence string
 * to the corresponding character.  For example, the substring "\n" is replaced
 * by an inline '\n' character.  The length of the resulting string is returned.
 */
size_t
stresc2chr(char *s)
{
	char *p, *q, c;
	int esc = 0;

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

/*
 * Create a copy of string s in which certain unprintable or special characters
 * have been converted to the string representation of their C escape sequence.
 * For example, the newline character is expanded to the string "\n".
 */
char *
strchr2esc(const char *s, size_t n)
{
	const char *p;
	char *q, *s2, c;
	size_t addl = 0;

	for (p = s; p < s + n; p++) {
		switch (c = *p) {
		case '\0':
		case '\a':
		case '\b':
		case '\f':
		case '\n':
		case '\r':
		case '\t':
		case '\v':
		case '"':
		case '\\':
			addl++;		/* 1 add'l char needed to follow \ */
			break;
		case ' ':
			break;
		default:
			if (c < '!' || c > '~')
				addl += 3; /* 3 add'l chars following \ */
		}
	}

	s2 = mdb_alloc(n + addl + 1, UM_SLEEP);

	for (p = s, q = s2; p < s + n; p++) {
		switch (c = *p) {
		case '\0':
			*q++ = '\\';
			*q++ = '0';
			break;
		case '\a':
			*q++ = '\\';
			*q++ = 'a';
			break;
		case '\b':
			*q++ = '\\';
			*q++ = 'b';
			break;
		case '\f':
			*q++ = '\\';
			*q++ = 'f';
			break;
		case '\n':
			*q++ = '\\';
			*q++ = 'n';
			break;
		case '\r':
			*q++ = '\\';
			*q++ = 'r';
			break;
		case '\t':
			*q++ = '\\';
			*q++ = 't';
			break;
		case '\v':
			*q++ = '\\';
			*q++ = 'v';
			break;
		case '"':
			*q++ = '\\';
			*q++ = '"';
			break;
		case '\\':
			*q++ = '\\';
			*q++ = '\\';
			break;
		case ' ':
			*q++ = c;
			break;
		default:
			if (c < '!' || c > '~') {
				*q++ = '\\';
				*q++ = ((c >> 6) & 3) + '0';
				*q++ = ((c >> 3) & 7) + '0';
				*q++ = (c & 7) + '0';
			} else
				*q++ = c;
		}
	}

	*q = '\0';
	return (s2);
}

/*
 * Create a copy of string s in which certain unprintable or special characters
 * have been converted to an odd representation of their escape sequence.
 * This algorithm is the old adb convention for representing such sequences.
 */
char *
strchr2adb(const char *s, size_t n)
{
	size_t addl = 0;
	const char *p;
	char *q, *s2;

	for (p = s; p < s + n; p++) {
		char c = *p & CHAR_MAX;

		if (c < ' ' || c == CHAR_MAX)
			addl++; /* 1 add'l char needed for "^" */
	}

	s2 = mdb_alloc(n + addl + 1, UM_SLEEP);

	for (p = s, q = s2; p < s + n; p++) {
		char c = *p & CHAR_MAX;

		if (c == CHAR_MAX) {
			*q++ = '^';
			*q++ = '?';
		} else if (c < ' ') {
			*q++ = '^';
			*q++ = c + '@';
		} else
			*q++ = c;
	}

	*q = '\0';
	return (s2);
}

/*
 * Same as strchr, but we only search the first n characters
 */
char *
strnchr(const char *s, int c, size_t n)
{
	int i = 0;

	for (i = 0; i < n; i++) {
		if (*(s + i) == (char)c)
			return ((char *)(s + i));
	}

	return (NULL);
}

/*
 * Split the string s at the first occurrence of character c.  This character
 * is replaced by \0, and a pointer to the remainder of the string is returned.
 */
char *
strsplit(char *s, char c)
{
	char *p;

	if ((p = strchr(s, c)) == NULL)
		return (NULL);

	*p++ = '\0';
	return (p);
}

/*
 * Same as strsplit, but split from the last occurrence of character c.
 */
char *
strrsplit(char *s, char c)
{
	char *p;

	if ((p = strrchr(s, c)) == NULL)
		return (NULL);

	*p++ = '\0';
	return (p);
}

/*
 * Return the address of the first occurrence of any character from s2
 * in the string s1, or NULL if none exists.  This is similar to libc's
 * strpbrk, but we add a third parameter to limit the search to the
 * specified number of bytes in s1, or a \0 character, whichever is
 * encountered first.
 */
const char *
strnpbrk(const char *s1, const char *s2, size_t nbytes)
{
	const char *p;

	if (nbytes == 0)
		return (NULL);

	do {
		for (p = s2; *p != '\0' && *p != *s1; p++)
			continue;

		if (*p != '\0')
			return (s1);

	} while (--nbytes != 0 && *s1++ != '\0');

	return (NULL);
}

/*
 * Abbreviate a string if it meets or exceeds the specified length, including
 * the terminating null character.  The string is abbreviated by replacing the
 * last four characters with " ...".  strabbr is useful in constructs such as
 * this one, where nbytes = sizeof (buf):
 *
 * if (mdb_snprintf(buf, nbytes, "%s %d %c", ...) >= nbytes)
 *         (void) strabbr(buf, nbytes);
 *
 * No modifications are made if nbytes is too small to hold the suffix itself.
 */
char *
strabbr(char *s, size_t nbytes)
{
	static const char suffix[] = " ...";

	if (nbytes > sizeof (suffix) && strlen(s) >= nbytes - 1)
		(void) strcpy(&s[nbytes - sizeof (suffix)], suffix);

	return (s);
}

/*
 * Return the basename (name after final /) of the given string.  We use
 * strbasename rather than basename to avoid conflicting with libgen.h's
 * non-const function prototype.
 */
const char *
strbasename(const char *s)
{
	const char *p = strrchr(s, '/');

	if (p == NULL)
		return (s);

	return (++p);
}

/*
 * Return the directory name (name prior to the final /) of the given string.
 * The string itself is modified.
 */
char *
strdirname(char *s)
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

/*
 * Return a pointer to the first character in the string that makes it an
 * invalid identifer (i.e. incompatible with the mdb syntax), or NULL if
 * the string is a valid identifier.
 */
const char *
strbadid(const char *s)
{
	return (strpbrk(s, "#%^&*-+=,:$/\\?<>;|!`'\"[]\n\t() {}"));
}

/*
 * Return a boolean value indicating if the given string consists solely
 * of printable ASCII characters terminated by \0.
 */
int
strisprint(const char *s)
{
	for (; *s != '\0'; s++) {
		if (*s < ' ' || *s > '~')
			return (0);
	}

	return (1);
}

/*
 * This is a near direct copy of the inet_ntop() code in
 * uts/common/inet/ip/ipv6.c, duplicated here for kmdb's sake.
 */
static void
convert2ascii(char *buf, const in6_addr_t *addr)
{
	int		hexdigits;
	int		head_zero = 0;
	int		tail_zero = 0;
	/* tempbuf must be big enough to hold ffff:\0 */
	char		tempbuf[6];
	char		*ptr;
	uint16_t	*addr_component, host_component;
	size_t		len;
	int		first = FALSE;
	int		med_zero = FALSE;
	int		end_zero = FALSE;

	addr_component = (uint16_t *)addr;
	ptr = buf;

	/* First count if trailing zeroes higher in number */
	for (hexdigits = 0; hexdigits < 8; hexdigits++) {
		if (*addr_component == 0) {
			if (hexdigits < 4)
				head_zero++;
			else
				tail_zero++;
		}
		addr_component++;
	}
	addr_component = (uint16_t *)addr;
	if (tail_zero > head_zero && (head_zero + tail_zero) != 7)
		end_zero = TRUE;

	for (hexdigits = 0; hexdigits < 8; hexdigits++) {
		/* if entry is a 0 */
		if (*addr_component == 0) {
			if (!first && *(addr_component + 1) == 0) {
				if (end_zero && (hexdigits < 4)) {
					*ptr++ = '0';
					*ptr++ = ':';
				} else {
					if (hexdigits == 0)
						*ptr++ = ':';
					/* add another */
					*ptr++ = ':';
					first = TRUE;
					med_zero = TRUE;
				}
			} else if (first && med_zero) {
				if (hexdigits == 7)
					*ptr++ = ':';
				addr_component++;
				continue;
			} else {
				*ptr++ = '0';
				*ptr++ = ':';
			}
			addr_component++;
			continue;
		}
		if (med_zero)
			med_zero = FALSE;

		tempbuf[0] = '\0';
		mdb_nhconvert(&host_component, addr_component,
		    sizeof (uint16_t));
		(void) mdb_snprintf(tempbuf, sizeof (tempbuf), "%x:",
		    host_component & 0xffff);
		len = strlen(tempbuf);
		bcopy(tempbuf, ptr, len);
		ptr = ptr + len;
		addr_component++;
	}
	*--ptr = '\0';
}

char *
mdb_inet_ntop(int af, const void *addr, char *buf, size_t buflen)
{
	in6_addr_t	*v6addr;
	uchar_t		*v4addr;
	char		*caddr;

#define	UC(b)	(((int)b) & 0xff)
	switch (af) {
	case AF_INET:
		ASSERT(buflen >= INET_ADDRSTRLEN);
		v4addr = (uchar_t *)addr;
		(void) mdb_snprintf(buf, buflen, "%d.%d.%d.%d",
		    UC(v4addr[0]), UC(v4addr[1]), UC(v4addr[2]), UC(v4addr[3]));
		return (buf);

	case AF_INET6:
		ASSERT(buflen >= INET6_ADDRSTRLEN);
		v6addr = (in6_addr_t *)addr;
		if (IN6_IS_ADDR_V4MAPPED(v6addr)) {
			caddr = (char *)addr;
			(void) mdb_snprintf(buf, buflen, "::ffff:%d.%d.%d.%d",
			    UC(caddr[12]), UC(caddr[13]),
			    UC(caddr[14]), UC(caddr[15]));
		} else if (IN6_IS_ADDR_V4COMPAT(v6addr)) {
			caddr = (char *)addr;
			(void) mdb_snprintf(buf, buflen, "::%d.%d.%d.%d",
			    UC(caddr[12]), UC(caddr[13]), UC(caddr[14]),
			    UC(caddr[15]));
		} else if (IN6_IS_ADDR_UNSPECIFIED(v6addr)) {
			(void) mdb_snprintf(buf, buflen, "::");
		} else {
			convert2ascii(buf, v6addr);
		}
		return (buf);
	}
#undef UC

	return (NULL);
}
