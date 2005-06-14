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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1	*/

#include	"uucp.h"
#include <rpc/trace.h> 

#ifdef TLI

#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <malloc.h>
#include <sys/tiuser.h>
#include <ctype.h>
#define OCT	0
#define HEX	1
/* #include <nsaddr.h>
*/
#define	toupper(c)	(islower(c) ? _toupper(c) : (c))
#define	todigit(c)	((int)((c) - '0'))	/* char to digit */
#define	toxdigit(c)	((isdigit(c))?todigit(c):(toupper(c)-(int)'A'+10))
#define	isodigit(c)	(isdigit(c) && ((c) != '9') && ((c) != '8'))
#define	itoac(i)	(((i) > 9) ? ((char)((i)-10) + 'A'):((char)(i) + '0'))	
#define	MASK(n)		((1 << (n)) - 1)

#define	SBUFSIZE	128

/* #define	TRUE	1;
 * #define	FALSE	0;
 */

/*	local static functions	*/
static int dobase();
static void memcp();
static char *xfer();

/*
	stoa - convert string to address

	If a string begins in \o or \O, the following address is octal
	"  "   "       "    " \x or \X, the following address is hex

	If ok, return pointer to netbuf structure.
	A  NULL is returned on any error(s).
*/

GLOBAL struct netbuf *
stoa(str, addr)			/* Return netbuf ptr if success */
char	*str;			/* Return NULL if error		*/
struct netbuf	*addr;
{
	int	myadr;		/* was netbuf struct allocated here ? */
	static	char *sbuf;

	trace1(TR_stoa, 0);
	myadr = FALSE;

	if (!str) {
		trace1(TR_stoa, 1);
		return (NULL);
	}
	while (*str && isspace(*str))	/* leading whites are OK */
		++str;

	if (!str || !*str) {	/* Nothing to convert */
		trace1(TR_stoa, 1);
		return (NULL);
	}

	if (!addr) {
		if ((addr = (struct netbuf *)malloc(sizeof(struct netbuf))) == NULL) {
			trace1(TR_stoa, 1);
			return (NULL);
		}
				
		myadr = TRUE;
		addr->buf = NULL;
		addr->maxlen = 0;
		addr->len = 0;
	}

	if (sbuf == NULL) {
		sbuf = (char *)malloc(SBUFSIZE);
		if (sbuf == NULL)
			return (NULL);
	}

	/* Now process the address */
	if (*str == '\\') {
		++str;
		switch (*str) {

		case 'X':	/* hex */
		case 'x':
			addr->len = dobase(++str, sbuf, HEX);
			break;

		case 'o':	/* octal */
		case 'O':
			addr->len = dobase(++str, sbuf, OCT);
			break;

		default:	/* error */
			addr->len = 0;
			break;
		}
	}

	if (addr->len == 0) {	/* Error in conversion */
		if (myadr)
			free(addr);
		trace1(TR_stoa, 1);
		return (NULL);
	}
	if ((addr->buf = xfer(addr->buf, sbuf, addr->len, addr->maxlen)) == NULL) {
		trace1(TR_stoa, 1);
		return (NULL);
	} else {
		trace1(TR_stoa, 1);
		return addr;
	}
}

/*
	dobase :	converts a hex or octal ASCII string
		to a binary address. Only HEX or OCT may be used
		for type.
	return length of binary string (in bytes), 0 if error.
	The binary result is placed at buf.
*/

static int
dobase(s, buf, type)	/* read in an address */
char	*s, *buf;	/* source ASCII, result binary string */
int	type;
{
	int	bp = SBUFSIZE - 1;
	int	shift = 0;
	char	*end;

	trace2(TR_dobase, 0, type);
	for (end = s; *end && ((type == OCT) ? isodigit(*end) :
		isxdigit(*end)); ++end) ;

	/* any non-white, non-digits cause address to be rejected,
	   other fields are ignored */

	if ((*s == 0) || (end == s) || (!isspace(*end) && *end)) {
		fprintf(stderr, "dobase: Illegal trailer on address string\n");
		buf[0] = '\0';
		trace1(TR_dobase, 1);
		return (0);
	}
	--end;

	buf[bp] = '\0';

	while (bp > 0 && end >= s) {
		buf[bp] |= toxdigit(*end) << shift;
		if (type == OCT) {
			if (shift > 5) {
				buf[--bp] = (todigit(*end) >> (8 - shift))
					& MASK(shift-5);
			}
			if ((shift = (shift + 3) % 8) == 0)
				buf[--bp] = 0;
		}
		else	/* hex */
			if ((shift = (shift) ? 0 : 4) == 0)
				buf[--bp] = 0;;
		--end;
	}
	if (bp == 0) {
		fprintf(stderr, "stoa: dobase: number to long\n");
		trace1(TR_dobase, 1);
		return (0);
	}

	/* need to catch end case to avoid extra 0's in front	*/
	if (!shift)
		bp++;
	memcp(buf, &buf[bp], (SBUFSIZE - bp));
	trace1(TR_dobase, 1);
	return (SBUFSIZE - bp);
}

static void
memcp(d, s, n)	/* safe memcpy for overlapping regions */
char	*d, *s;
int	n;
{
	trace2(TR_memcp, 0, n);
	while (n--)
		*d++ = *s++;
	trace1(TR_memcp, 1);
	return;
}

/* transfer block to a given destination or allocate one of the
    right size 
    if max = 0 : ignore max
*/

static char *
xfer(dest, src, len, max)
char	*dest, *src;
unsigned	len, max;
{
	trace3(TR_xfer, 0, len, max);
	if (max && dest && max < len) {		/* No room */
		fprintf(stderr, "xfer: destination not long enough\n");
		trace1(TR_xfer, 1);
		return (NULL);
	}
	if (!dest)
		if ((dest = malloc(len)) == NULL) {
			fprintf(stderr, "xfer: malloc failed\n");
			trace1(TR_xfer, 1);
			return (NULL);
		}

	memcpy(dest, src, (int)len);
	trace1(TR_xfer, 1);
	return (dest);
}

#endif /* TLI */
