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
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

/*
 * Implementations of the functions described in vsnprintf(3C) and string(3C),
 * for use by the kernel, the standalone, and kmdb.  Unless otherwise specified,
 * these functions match the section 3C manpages.
 */

#include <sys/types.h>
#include <sys/varargs.h>

#if defined(_KERNEL)
#include <sys/systm.h>
#include <sys/debug.h>
#elif !defined(_BOOT)
#include <string.h>
#endif

#ifndef	NULL
#define	NULL	0l
#endif

#include "memcpy.h"
#include "string.h"

/*
 * We don't need these for x86 boot or kmdb.
 */
#if !defined(_KMDB) && (!defined(_BOOT) || defined(__sparc))

#define	ADDCHAR(c)	if (bufp++ - buf < buflen) bufp[-1] = (c)

/*
 * Given a buffer 'buf' of size 'buflen', render as much of the string
 * described by <fmt, args> as possible.  The string will always be
 * null-terminated, so the maximum string length is 'buflen - 1'.
 * Returns the number of bytes that would be necessary to render the
 * entire string, not including null terminator (just like vsnprintf(3S)).
 * To determine buffer size in advance, use vsnprintf(NULL, 0, fmt, args) + 1.
 *
 * There is no support for floating point, and the C locale is assumed.
 */
size_t
vsnprintf(char *buf, size_t buflen, const char *fmt, va_list aargs)
{
	uint64_t ul, tmp;
	char *bufp = buf;	/* current buffer pointer */
	int pad, width, base, sign, c, num;
	int prec, h_count, l_count, dot_count;
	int pad_count, transfer_count, left_align;
	char *digits, *sp, *bs;
	char numbuf[65];	/* sufficient for a 64-bit binary value */
	va_list args;

	/*
	 * Make a copy so that all our callers don't have to make a copy
	 */
	va_copy(args, aargs);

	if ((ssize_t)buflen < 0)
		buflen = 0;

	while ((c = *fmt++) != '\0') {
		if (c != '%') {
			ADDCHAR(c);
			continue;
		}

		width = prec = 0;
		left_align = base = sign = 0;
		h_count = l_count = dot_count = 0;
		pad = ' ';
		digits = "0123456789abcdef";
next_fmt:
		if ((c = *fmt++) == '\0')
			break;

		if (c >= 'A' && c <= 'Z') {
			c += 'a' - 'A';
			digits = "0123456789ABCDEF";
		}

		switch (c) {
		case '-':
			left_align++;
			goto next_fmt;
		case '0':
			if (dot_count == 0)
				pad = '0';
			/*FALLTHROUGH*/
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			num = 0;
			for (;;) {
				num = 10 * num + c - '0';
				c = *fmt;
				if (c < '0' || c > '9')
					break;
				else
					fmt++;
			}
			if (dot_count > 0)
				prec = num;
			else
				width = num;

			goto next_fmt;
		case '.':
			dot_count++;
			goto next_fmt;
		case '*':
			if (dot_count > 0)
				prec = (int)va_arg(args, int);
			else
				width = (int)va_arg(args, int);
			goto next_fmt;
		case 'l':
			l_count++;
			goto next_fmt;
		case 'h':
			h_count++;
			goto next_fmt;
		case 'd':
			sign = 1;
			/*FALLTHROUGH*/
		case 'u':
			base = 10;
			break;
		case 'p':
			l_count = 1;
			/*FALLTHROUGH*/
		case 'x':
			base = 16;
			break;
		case 'o':
			base = 8;
			break;
		case 'b':
			l_count = 0;
			base = 1;
			break;
		case 'c':
			c = (char)va_arg(args, int);
			ADDCHAR(c);
			break;
		case 's':
			sp = va_arg(args, char *);
			if (sp == NULL) {
				sp = "<null string>";
				/* avoid truncation */
				prec = strlen(sp);
			}
			/*
			 * Handle simple case specially to avoid
			 * performance hit of strlen()
			 */
			if (prec == 0 && width == 0) {
				while ((c = *sp++) != 0)
					ADDCHAR(c);
				break;
			}
			if (prec > 0) {
				transfer_count = strnlen(sp, prec);
				/* widen field if too narrow */
				if (prec > width)
					width = prec;
			} else
				transfer_count = strlen(sp);
			if (width > transfer_count)
				pad_count = width - transfer_count;
			else
				pad_count = 0;
			while ((!left_align) && (pad_count-- > 0))
				ADDCHAR(' ');
			/* ADDCHAR() evaluates arg at most once */
			while (transfer_count-- > 0)
				ADDCHAR(*sp++);
			while ((left_align) && (pad_count-- > 0))
				ADDCHAR(' ');
			break;
		case '%':
			ADDCHAR('%');
			break;
		}

		if (base == 0)
			continue;

		if (h_count == 0 && l_count == 0)
			if (sign)
				ul = (int64_t)va_arg(args, int);
			else
				ul = (int64_t)va_arg(args, unsigned int);
		else if (l_count > 1)
			if (sign)
				ul = (int64_t)va_arg(args, int64_t);
			else
				ul = (int64_t)va_arg(args, uint64_t);
		else if (l_count > 0)
			if (sign)
				ul = (int64_t)va_arg(args, long);
			else
				ul = (int64_t)va_arg(args, unsigned long);
		else if (h_count > 1)
			if (sign)
				ul = (int64_t)((char)va_arg(args, int));
			else
				ul = (int64_t)((unsigned char)va_arg(args,
				    int));
		else if (h_count > 0)
			if (sign)
				ul = (int64_t)((short)va_arg(args, int));
			else
				ul = (int64_t)((unsigned short)va_arg(args,
				    int));

		if (sign && (int64_t)ul < 0)
			ul = -ul;
		else
			sign = 0;

		if (c == 'b') {
			bs = va_arg(args, char *);
			base = *bs++;
		}

		/* avoid repeated division if width is 0 */
		if (width > 0) {
			tmp = ul;
			do {
				width--;
			} while ((tmp /= base) != 0);
		}

		if (sign && pad == '0')
			ADDCHAR('-');
		while ((!left_align) && (width-- > sign))
			ADDCHAR(pad);
		if (sign && pad == ' ')
			ADDCHAR('-');

		sp = numbuf;
		tmp = ul;
		do {
			*sp++ = digits[tmp % base];
		} while ((tmp /= base) != 0);

		while (sp > numbuf) {
			sp--;
			ADDCHAR(*sp);
		}

		/* add left-alignment padding */
		while (width-- > sign)
			ADDCHAR(' ');

		if (c == 'b' && ul != 0) {
			int any = 0;
			c = *bs++;
			while (c != 0) {
				if (ul & (1 << (c - 1))) {
					if (any++ == 0)
						ADDCHAR('<');
					while ((c = *bs++) >= 32)
						ADDCHAR(c);
					ADDCHAR(',');
				} else {
					while ((c = *bs++) >= 32)
						continue;
				}
			}
			if (any) {
				bufp--;
				ADDCHAR('>');
			}
		}
	}
	if (bufp - buf < buflen)
		bufp[0] = c;
	else if (buflen != 0)
		buf[buflen - 1] = c;

	va_end(args);

	return (bufp - buf);
}

/*PRINTFLIKE1*/
size_t
snprintf(char *buf, size_t buflen, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	buflen = vsnprintf(buf, buflen, fmt, args);
	va_end(args);

	return (buflen);
}

#if defined(_BOOT) && defined(__sparc)
/*
 * The sprintf() and vsprintf() routines aren't shared with the kernel because
 * the DDI mandates that they return the buffer rather than its length.
 */
/*PRINTFLIKE2*/
int
sprintf(char *buf, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	(void) vsnprintf(buf, INT_MAX, fmt, args);
	va_end(args);

	return (strlen(buf));
}

int
vsprintf(char *buf, const char *fmt, va_list args)
{
	(void) vsnprintf(buf, INT_MAX, fmt, args);
	return (strlen(buf));
}
#endif /* _BOOT && __sparc */

#endif /* !_KMDB && (!_BOOT || __sparc) */

char *
strcat(char *s1, const char *s2)
{
	char *os1 = s1;

	while (*s1++ != '\0')
		;
	s1--;
	while ((*s1++ = *s2++) != '\0')
		;
	return (os1);
}

char *
strchr(const char *sp, int c)
{
	do {
		if (*sp == (char)c)
			return ((char *)sp);
	} while (*sp++);
	return (NULL);
}

int
strcmp(const char *s1, const char *s2)
{
	while (*s1 == *s2++)
		if (*s1++ == '\0')
			return (0);
	return (*(unsigned char *)s1 - *(unsigned char *)--s2);
}

int
strncmp(const char *s1, const char *s2, size_t n)
{
	if (s1 == s2)
		return (0);
	n++;
	while (--n != 0 && *s1 == *s2++)
		if (*s1++ == '\0')
			return (0);
	return ((n == 0) ? 0 : *(unsigned char *)s1 - *(unsigned char *)--s2);
}

static const char charmap[] = {
	'\000', '\001', '\002', '\003', '\004', '\005', '\006', '\007',
	'\010', '\011', '\012', '\013', '\014', '\015', '\016', '\017',
	'\020', '\021', '\022', '\023', '\024', '\025', '\026', '\027',
	'\030', '\031', '\032', '\033', '\034', '\035', '\036', '\037',
	'\040', '\041', '\042', '\043', '\044', '\045', '\046', '\047',
	'\050', '\051', '\052', '\053', '\054', '\055', '\056', '\057',
	'\060', '\061', '\062', '\063', '\064', '\065', '\066', '\067',
	'\070', '\071', '\072', '\073', '\074', '\075', '\076', '\077',
	'\100', '\141', '\142', '\143', '\144', '\145', '\146', '\147',
	'\150', '\151', '\152', '\153', '\154', '\155', '\156', '\157',
	'\160', '\161', '\162', '\163', '\164', '\165', '\166', '\167',
	'\170', '\171', '\172', '\133', '\134', '\135', '\136', '\137',
	'\140', '\141', '\142', '\143', '\144', '\145', '\146', '\147',
	'\150', '\151', '\152', '\153', '\154', '\155', '\156', '\157',
	'\160', '\161', '\162', '\163', '\164', '\165', '\166', '\167',
	'\170', '\171', '\172', '\173', '\174', '\175', '\176', '\177',
	'\200', '\201', '\202', '\203', '\204', '\205', '\206', '\207',
	'\210', '\211', '\212', '\213', '\214', '\215', '\216', '\217',
	'\220', '\221', '\222', '\223', '\224', '\225', '\226', '\227',
	'\230', '\231', '\232', '\233', '\234', '\235', '\236', '\237',
	'\240', '\241', '\242', '\243', '\244', '\245', '\246', '\247',
	'\250', '\251', '\252', '\253', '\254', '\255', '\256', '\257',
	'\260', '\261', '\262', '\263', '\264', '\265', '\266', '\267',
	'\270', '\271', '\272', '\273', '\274', '\275', '\276', '\277',
	'\300', '\301', '\302', '\303', '\304', '\305', '\306', '\307',
	'\310', '\311', '\312', '\313', '\314', '\315', '\316', '\317',
	'\320', '\321', '\322', '\323', '\324', '\325', '\326', '\327',
	'\330', '\331', '\332', '\333', '\334', '\335', '\336', '\337',
	'\340', '\341', '\342', '\343', '\344', '\345', '\346', '\347',
	'\350', '\351', '\352', '\353', '\354', '\355', '\356', '\357',
	'\360', '\361', '\362', '\363', '\364', '\365', '\366', '\367',
	'\370', '\371', '\372', '\373', '\374', '\375', '\376', '\377',
};

int
strcasecmp(const char *s1, const char *s2)
{
	const unsigned char *cm = (const unsigned char *)charmap;
	const unsigned char *us1 = (const unsigned char *)s1;
	const unsigned char *us2 = (const unsigned char *)s2;

	while (cm[*us1] == cm[*us2++])
		if (*us1++ == '\0')
			return (0);
	return (cm[*us1] - cm[*(us2 - 1)]);
}

int
strncasecmp(const char *s1, const char *s2, size_t n)
{
	const unsigned char *cm = (const unsigned char *)charmap;
	const unsigned char *us1 = (const unsigned char *)s1;
	const unsigned char *us2 = (const unsigned char *)s2;

	while (n != 0 && cm[*us1] == cm[*us2++]) {
		if (*us1++ == '\0')
			return (0);
		n--;
	}
	return (n == 0 ? 0 : cm[*us1] - cm[*(us2 - 1)]);
}

char *
strcpy(char *s1, const char *s2)
{
	char *os1 = s1;

	while ((*s1++ = *s2++) != '\0')
		;
	return (os1);
}

char *
strncpy(char *s1, const char *s2, size_t n)
{
	char *os1 = s1;

	n++;
	while (--n != 0 && (*s1++ = *s2++) != '\0')
		;
	if (n != 0)
		while (--n != 0)
			*s1++ = '\0';
	return (os1);
}

char *
strrchr(const char *sp, int c)
{
	char *r = NULL;

	do {
		if (*sp == (char)c)
			r = (char *)sp;
	} while (*sp++);

	return (r);
}

char *
strstr(const char *as1, const char *as2)
{
	const char *s1, *s2;
	const char *tptr;
	char c;

	s1 = as1;
	s2 = as2;

	if (s2 == NULL || *s2 == '\0')
		return ((char *)s1);
	c = *s2;

	while (*s1)
		if (*s1++ == c) {
			tptr = s1;
			while ((c = *++s2) == *s1++ && c)
				;
			if (c == 0)
				return ((char *)tptr - 1);
			s1 = tptr;
			s2 = as2;
			c = *s2;
		}

	return (NULL);
}

char *
strpbrk(const char *string, const char *brkset)
{
	const char *p;

	do {
		for (p = brkset; *p != '\0' && *p != *string; ++p)
			;
		if (*p != '\0')
			return ((char *)string);
	} while (*string++);

	return (NULL);
}

char *
strncat(char *s1, const char *s2, size_t n)
{
	char *os1 = s1;

	n++;
	while (*s1++ != '\0')
		;
	--s1;
	while ((*s1++ = *s2++) != '\0') {
		if (--n == 0) {
			s1[-1] = '\0';
			break;
		}
	}
	return (os1);
}

#if defined(_BOOT) || defined(_KMDB)
#define	bcopy(src, dst, n)	(void) memcpy((dst), (src), (n))
#endif

size_t
strlcat(char *dst, const char *src, size_t dstsize)
{
	char *df = dst;
	size_t left = dstsize;
	size_t l1;
	size_t l2 = strlen(src);
	size_t copied;

	while (left-- != 0 && *df != '\0')
		df++;
	/*LINTED: possible ptrdiff_t overflow*/
	l1 = (size_t)(df - dst);
	if (dstsize == l1)
		return (l1 + l2);

	copied = l1 + l2 >= dstsize ? dstsize - l1 - 1 : l2;
	bcopy(src, dst + l1, copied);
	dst[l1+copied] = '\0';
	return (l1 + l2);
}

size_t
strlcpy(char *dst, const char *src, size_t len)
{
	size_t slen = strlen(src);
	size_t copied;

	if (len == 0)
		return (slen);

	if (slen >= len)
		copied = len - 1;
	else
		copied = slen;
	bcopy(src, dst, copied);
	dst[copied] = '\0';
	return (slen);
}

size_t
strspn(const char *string, const char *charset)
{
	const char *p, *q;

	for (q = string; *q != '\0'; ++q) {
		for (p = charset; *p != '\0' && *p != *q; ++p)
			;
		if (*p == '\0')
			break;
	}

	/*LINTED: possible ptrdiff_t overflow*/
	return ((size_t)(q - string));
}

size_t
strcspn(const char *string, const char *charset)
{
	const char *p, *q;

	for (q = string; *q != '\0'; ++q) {
		for (p = charset; *p != '\0' && *p != *q; ++p)
			;
		if (*p != '\0')
			break;
	}

	/*LINTED E_PTRDIFF_OVERFLOW*/
	return ((size_t)(q - string));
}

/*
 * strsep
 *
 * The strsep() function locates, in the string referenced by *stringp, the
 * first occurrence of any character in the string delim (or the terminating
 * `\0' character) and replaces it with a `\0'.  The location of the next
 * character after the delimiter character (or NULL, if the end of the
 * string was reached) is stored in *stringp.  The original value of
 * *stringp is returned.
 *
 * If *stringp is initially NULL, strsep() returns NULL.
 *
 * NOTE: This instance is left for in-kernel use. Libraries and programs
 *       should use strsep from libc.
 */
char *
strsep(char **stringp, const char *delim)
{
	char *s;
	const char *spanp;
	int c, sc;
	char *tok;

	if ((s = *stringp) == NULL)
		return (NULL);

	for (tok = s; ; ) {
		c = *s++;
		spanp = delim;
		do {
			if ((sc = *spanp++) == c) {
				if (c == 0)
					s = NULL;
				else
					s[-1] = 0;
				*stringp = s;
				return (tok);
			}
		} while (sc != 0);
	}
	/* NOTREACHED */
}

/*
 * Unless mentioned otherwise, all of the routines below should be added to
 * the Solaris DDI as necessary.  For now, only provide them to standalone.
 */
#if defined(_BOOT) || defined(_KMDB)
char *
strtok(char *string, const char *sepset)
{
	char		*p, *q, *r;
	static char	*savept;

	/*
	 * Set `p' to our current location in the string.
	 */
	p = (string == NULL) ? savept : string;
	if (p == NULL)
		return (NULL);

	/*
	 * Skip leading separators; bail if no tokens remain.
	 */
	q = p + strspn(p, sepset);
	if (*q == '\0')
		return (NULL);

	/*
	 * Mark the end of the token and set `savept' for the next iteration.
	 */
	if ((r = strpbrk(q, sepset)) == NULL)
		savept = NULL;
	else {
		*r = '\0';
		savept = ++r;
	}

	return (q);
}

/*
 * The strlen() routine isn't shared with the kernel because it has its own
 * hand-tuned assembly version.
 */
size_t
strlen(const char *s)
{
	size_t n = 0;

	while (*s++)
		n++;
	return (n);
}

#endif /* _BOOT || _KMDB */

/*
 * Returns the number of non-NULL bytes in string argument,
 * but not more than maxlen.  Does not look past str + maxlen.
 */
size_t
strnlen(const char *s, size_t maxlen)
{
	size_t n = 0;

	while (maxlen != 0 && *s != 0) {
		s++;
		maxlen--;
		n++;
	}

	return (n);
}


#ifdef _KERNEL
/*
 * Check for a valid C identifier:
 *	a letter or underscore, followed by
 *	zero or more letters, digits and underscores.
 */

#define	IS_DIGIT(c)	((c) >= '0' && (c) <= '9')

#define	IS_ALPHA(c)	\
	(((c) >= 'a' && (c) <= 'z') || ((c) >= 'A' && (c) <= 'Z'))

int
strident_valid(const char *id)
{
	int c = *id++;

	if (!IS_ALPHA(c) && c != '_')
		return (0);
	while ((c = *id++) != 0) {
		if (!IS_ALPHA(c) && !IS_DIGIT(c) && c != '_')
			return (0);
	}
	return (1);
}

/*
 * Convert a string into a valid C identifier by replacing invalid
 * characters with '_'.  Also makes sure the string is nul-terminated
 * and takes up at most n bytes.
 */
void
strident_canon(char *s, size_t n)
{
	char c;
	char *end = s + n - 1;

	ASSERT(n > 0);

	if ((c = *s) == 0)
		return;

	if (!IS_ALPHA(c) && c != '_')
		*s = '_';

	while (s < end && ((c = *(++s)) != 0)) {
		if (!IS_ALPHA(c) && !IS_DIGIT(c) && c != '_')
			*s = '_';
	}
	*s = 0;
}

#endif	/* _KERNEL */
