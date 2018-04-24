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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
	stoa - convert string to address

	If a string begins in \o or \O, the following address is octal
	"  "   "       "    " \x or \X, the following address is hex
	Otherwise, a string is considered text. Text may be quoted
	with double quotes and the C-like escapes \n, \b, \t, \v, \r, and \nnn
	(nnn = octal char) are recognized.
	A \ followed by a newline causes the newline
	to vanish. A \ followed by any other char causes any "magic" of
	any other char to disappear.

	Other escape sequences recognized are:
		\!cmd args [ \! || EOL ]
	which is replaced by the raw output of the execution of cmd.
	This may only be used in a string.

		\$cmd args [ \$ || EOL ]
	which is replaced by the output of the execution of cmd and
	is then reprocessed.

	A  NULL is returned on any error(s).
*/

#include <stdio.h>
#include <memory.h>
#include <ctype.h>
#include "nsaddr.h"


#define	toupper(c)	(islower(c) ? _toupper(c) : (c))
#define	todigit(c)	((int)((c) - '0'))	/* char to digit */
#define	toxdigit(c)	((isdigit(c))?todigit(c):(toupper(c)-(int)'A'+10))
#define	isodigit(c)	(isdigit(c) && ((c) != '9') && ((c) != '8'))
#define	itoac(i)	(((i) > 9) ? ((char)((i)-10) + 'A'):((char)(i) + '0'))	
#define	MASK(n)		((1 << (n)) - 1)

#define	MAXRLEVEL	10	/* maximum recursion level */

#define	TRUE	1;
#define	FALSE	0;

char	scanbuf[SBUFSIZE];
int	sbp = 0;
int	rec = 0;	/* Recursion level */

char	sbuf[SBUFSIZE];

extern void free();

struct netbuf *
stoa(str, addr)			/* Return 0 for success, -1 for error */
char	*str;
struct netbuf	*addr;
{
	char	*xfer(), *prescan();

	int	myadr;		/* was netbuf struct allocated here ? */
	int	quote;		/* quoted string ? */

	myadr = FALSE;

	if (!str)
		return NULL;
	while (*str && isspace(*str))	/* leading whites are OK */
		++str;

	str = prescan(str);		/* Do all \$ ... \$ */

	if (!str || !*str) return NULL;		/* Nothing to convert */

	if (!addr) {
		if ((addr = (struct netbuf *)malloc(sizeof(struct netbuf))) == NULL)
			return NULL;
		myadr = TRUE;
		addr->buf = NULL;
		addr->maxlen = 0;
		addr->len = 0;
	}

	/* Now process the address */
	quote = 0;

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

		case '\0':	/* No address given!, length is 0 */
			addr->len = dostring(str, sbuf, 0);
			break;

		default:	/* \ is handled by dostring */
			addr->len = dostring(--str, sbuf, quote);
			break;
		}
	}
	else {
		if (*str == '"') {	/* quoted string */
			quote = 1;
			++str;
		}
		addr->len = dostring(str, sbuf, quote);
	}

	if (addr->len == 0) {	/* Error in conversion */
		if (myadr)
			free(addr);
		return NULL;
	}
	if ((addr->buf = xfer(addr->buf, sbuf, addr->len, addr->maxlen)) == NULL)
		return NULL;
	else
		return addr;
}


/*
	dostring:	Copy string at s to buf translating
		escaped characters and shell escapes.
	return length of string.
*/

int
dostring(s, buf, quote)		/* read in a raw address */
char	*s, *buf;
int	quote;
{
	char	*xcmd();

	int	oc, ch, len = 0;
	int	l = 0;
	char	*rout;

	while (*s) {
		if (len >= SBUFSIZE) {
			fprintf(stderr, "dostring: string too long\n");
			break;
		}
		else if (*s == '\\')
			switch(*++s) {

			case '!':	/* raw shell escape */
				if (rout = xcmd(s+1, '!', &s, &l)) {
					if (len + l < SBUFSIZE)
						memcpy(buf+len, rout, l);
					len += l;
					free(rout);
				}
				break;

			case '\n':	/* ignore newline */
				++s;
				break;

			case 'b':	/* backspace */
				buf[len++] = '\b'; s++;
				break;

			case 'n':	/* newline */
				buf[len++] = '\n'; s++;
				break;

			case 'r':	/* return */
				buf[len++] = '\r'; s++;
				break;

			case 't':	/* horiz. tab */
				buf[len++] = '\t'; s++;
				break;

			case 'v':	/* vert. tab */
				buf[len++] = '\v'; s++;
				/* FALLTHROUGH */

			case '0':
			case '1':
			case '2':
			case '3':
				for(oc=ch=0; (*s >= '0' && *s <= '7') && oc++ < 3; ++s) 
					ch = (ch << 3) | (*s - '0');
				buf[len++] = ch;
				break;

			case 0:		/* end of string -- terminate */
				break;

			default:	/* take the character blindly */
				buf[len++] = *s++;
				break;
			}
		else if ((quote && (*s == '"')) || (!quote && isspace(*s)))
			break;

		else
			buf[len++] = *s++;
	}
	return (len >= SBUFSIZE) ? 0 : len;
}


/*
	dobase :	converts a hex or octal ASCII string
		to a binary address. Only HEX or OCT may be used
		for type.
	return length of binary string (in bytes), 0 if error.
	The binary result is placed at buf.
*/

int
dobase(s, buf, type)	/* read in an address */
char	*s, *buf;	/* source ASCII, result binary string */
int	type;
{
	void	memcp();
	int	bp = SBUFSIZE - 1;
	int	shift = 0;
	char	*end;

	for (end = s; *end && ((type == OCT) ? isodigit(*end) :
		isxdigit(*end)); ++end) ;

	/* any non-white, non-digits cause address to be rejected,
	   other fields are ignored */

	if ((*s == 0) || (end == s) || (!isspace(*end) && *end)) {
		fprintf(stderr, "dobase: Illegal trailer on address string\n");
		buf[0] = '\0';
		return 0;
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
		return 0;
	}

	/* need to catch end case to avoid extra 0's in front	*/
	if (!shift)
		bp++;
	memcp(buf, &buf[bp], (SBUFSIZE - bp));
	return (SBUFSIZE - bp);
}

#ifdef NOTUSED


/*

	atos(str, addr, type)

	convert address to ASCII form with address in hex, octal,
	or character form.
	return pointer to buffer (NULL on failure).
*/


char *
atos(str, addr, type)
char	*str;
struct netbuf	*addr;
int	type;
{
	char	*xfer();
	int	mystr = 0;	/* was str allocated here ? */
	unsigned	x_atos(), o_atos();
	void	memcp();

	char	*base;

	if (addr == NULL)
		return NULL;

	if (str == NULL)
		if ((str = malloc(SBUFSIZE)) == NULL)
			return NULL;
		else
			mystr = 1;

	switch (type) {

	case OCT:
		/* first add \o */	
		sbuf[0] = '\\';
		sbuf[1] = 'o';

		return xfer(str, sbuf, o_atos(sbuf+2, addr->buf, addr->len) + 2,
			mystr ? SBUFSIZE : 0);

	case HEX:
		/* first add \x */	
		sbuf[0] = '\\';
		sbuf[1] = 'x';

		return xfer(str, sbuf, x_atos(sbuf+2, addr->buf, addr->len) + 2,
			mystr ? SBUFSIZE : 0);

	case RAW:
		base = xfer(str, addr->buf,
			 addr->len + 1, mystr ? SBUFSIZE : 0);
		if (base)
			base[addr->len] = '\0';	/* terminate*/ 
		return base;

	default:
		return NULL;
	}
}


/*
	x_atos, o_atos
	return the number of bytes occupied by string + NULL*/ 

/*
	x_atos :	convert an address string a, length s
		to hex ASCII in s */


unsigned
x_atos(s, a, l)
char	*s, *a;
unsigned	l;
{
	char	*b;

	b = s;
	while (l--) {
		*s++ = itoac(((*a >> 4) & MASK (4)));
		*s++ = itoac((*a & MASK(4)));
		++a;
	}
	*s = '\0';
	return (s - b + 1);
}


/*
	o_atos :	convert an address a, length l
		to octal ASCII in s   */


unsigned
o_atos(s, a, l)
char	*s, *a;
unsigned	l;
{
	int	i, shift;
	char	*b;

	b = s;
	if (l == 0) {
		*s = '\0';
		return 0;
	}

	/* take care of partial bits and set shift factor for next 3  */

	i = l % 3;
	*s++ = itoac((*a>>(i+5)) & MASK(3-i));
	shift = 2 + i;

	while (l)
		if (shift <= 5) {
			*s++ = itoac((*a >> shift) & MASK(3));
			if (shift == 0) {
				++a;
				--l;
			}
			shift += (shift < 3) ? 5 : -3;
		}
		else {
			i = (*a & MASK(shift-5)) << (8-shift);
			i |= (*++a >> shift) & MASK(8-shift);
			*s++ = itoac(i);
			shift -= 3;
			--l;
		}
	*s++ = '\0';
	return (s - b + 1);
}

#endif /* NOTUSED */

void
memcp(d, s, n)	/* safe memcpy for overlapping regions */
char	*d, *s;
int	n;
{
	while (n--)
		*d++ = *s++;
}


/* transfer block to a given destination or allocate one of the
    right size 
    if max = 0 : ignore max
*/

char *
xfer(dest, src, len, max)
char	*dest, *src;
unsigned	len, max;
{
	if (max && dest && max < len) {		/* No room */
		fprintf(stderr, "xfer: destination not long enough\n");
		return NULL;
	}
	if (!dest)
		if ((dest = (char *)malloc(len)) == NULL) {
			fprintf(stderr, "xfer: malloc failed\n");
			return NULL;
		}

	memcpy(dest, src, (int)len);
	return dest;
}

/*
	prescan:	scan through string s, expanding all \$...\$
		as shell escapes.
	Return pointer to string of expanded text.
*/

char *
prescan(s)
char	*s;
{
	int	scan();

	rec = sbp = 0;
	if (!s || !*s || !scan(s))
		return NULL;
	scanbuf[sbp] = '\0';
	return scanbuf;
}


/*
	scan:	scan through string s, expanding all \$...\$.
	(Part II of prescan)
	Return 0 if anything failed, else 1.
*/

int
scan(s)
char	*s;
{
	char	*xcmd();
	char	*cmd;
	int	len;
	int	esc = 0;		/* Keep lookout for \\$ */

	while (*s) {
		if (!esc && (*s == '\\' && *(s+1) == '$')) {
			if (rec++ == MAXRLEVEL) {
				fprintf(stderr, "scan: Recursion \
level past %d on shell escape\n", rec);
				return 0;
			}
			if ((cmd = xcmd(s+2, '$', &s, &len)) != NULL) {
				cmd[len] = '\0';
 				if (*cmd != '\0')
					scan(cmd);
				free(cmd);
			}
			else
				return 0;
		}

		else if (sbp == SBUFSIZE) {
			fprintf(stderr, "Overflow on shell esc expansion\n");
			return 0;
		}
		else if (sbp < SBUFSIZE)
			esc = ((scanbuf[sbp++] = *s++) == '\\');
	}
	return 1;
}


/*
	xcmd :	extract command line for shell escape and execute it
		return pointer to output of command
*/

char *
xcmd(s, ec, ps, len)
char	*s;		/* input string */
char	ec;		/* escape char ( $ or ! ) */
char	**ps;		/* address of input string pointer */
int	*len;		/* Number of bytes of output from command */
{
	FILE	*popen();
	int	pclose();

	FILE	*pfp;		/* pipe for process */
	char	*cmd;		/* command buffer */
	char	*cmdp;		/* pointer along cmd */
	char	*ocmd;		/* output of command buffer */
	int	esc = 0;	/* escaped escape shell */

	*len = 0;

	if ((cmd = cmdp = (char *)malloc(SBUFSIZE)) == NULL) {
		fprintf(stderr, "xcmd: malloc failed\n");
		return NULL;
	}

	if ((ocmd = (char *)malloc(SBUFSIZE)) == NULL) {
		fprintf(stderr, "xcmd: malloc failed\n");
		free(cmd);
		return NULL;
	}
	while (*s) {
		if (!esc && *s == '\\' && *(s+1) == ec) {
			s += 2;
			break;
		}
		else
			esc = (*cmdp++ = *s++) == '\\';
	}
	*cmdp = '\0';
	*ps = s;

	if ((pfp = popen(cmd, "r")) == NULL)
		fprintf(stderr, "xcmd: popen failed\n");
	while (fread(&ocmd[*len], 1, 1, pfp))
		if ((*len += 1) >= SBUFSIZE) {
			fprintf(stderr, "xcmd: command output too long\n");
			break;
		}
	pclose(pfp);
	free(cmd);

	return ocmd;
}
