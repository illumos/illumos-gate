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
 * Copyright 2001, 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "gnu_msgfmt.h"
#include "gnu_lex.h"
#include "y.tab.h"

int	cur_line = 1;

static char	backbuf[MB_LEN_MAX];
static int	backlen = 0;

/*
 * get_mb() returns one multibyte character.
 *
 * This function uses the iconv() function to find out one
 * multibyte character from a sequence of bytes in the file stream.
 * The conversion from the codeset specified in the PO file to UTF-8
 * is performed.  The funcition reads another byte and calls iconv(),
 * until iconv() successfully returns as a valid UTF-8 character has
 * been converted or returns EILSEQ.  If iconv() successfully returned,
 * the function returns the read bytes as one character.  Otherwise,
 * returns error.  The string converted to UTF-8 in outbuf won't be
 * used at all.
 */
static size_t
get_mb(unsigned char *tmpbuf, unsigned char fc)
{
	int	c;
	char	outbuf[8];			/* max size of a UTF-8 char */
	const char	*inptr;
	char	*outptr;
	size_t	insize = 0, inlen, outlen, ret;

	tmpbuf[insize++] = fc;		/* size of tmpbuf is MB_LEN_MAX+1 */

	if (cd == (iconv_t)-1) {
		/* no conversion */
		tmpbuf[insize] = '\0';
		return (insize);
	}

	for (; ; ) {
		inptr = (const char *)tmpbuf;
		outptr = &outbuf[0];
		inlen = insize;
		outlen = sizeof (outbuf);

		errno = 0;
		ret = iconv(cd, &inptr, &inlen, &outptr, &outlen);
		if (ret == (size_t)-1) {
			/* iconv failed */
			switch (errno) {
			case EILSEQ:
				/* invalid character found */
				error(gettext(ERR_INVALID_CHAR),
					cur_line, cur_po);
				/* NOTREACHED */
			case EINVAL:
				/* not enough input */
				if (insize == MB_LEN_MAX) {
					/* invalid character found */
					error(gettext(ERR_INVALID_CHAR),
						cur_line, cur_po);
					/* NOTREACHED */
				}
				c = getc(fp);
				if (c == EOF) {
					error(gettext(ERR_UNEXP_EOF),
						cur_line, cur_po);
					/* NOTREACHED */
				}
				tmpbuf[insize++] = (unsigned char)c;

				/* initialize the conversion */
				outptr = &outbuf[0];
				outlen = sizeof (outbuf);
				(void) iconv(cd, NULL, NULL, &outptr, &outlen);

				continue;
				/* NOTREACHED */
			default:
				/* should never happen */
				error(ERR_INTERNAL,
					cur_line, cur_po);
				/* NOTREACHED */
			}
			/* NOTREACHED */
		}
		tmpbuf[insize] = '\0';
		return (insize);
		/* NOTRECHED */
	}
}

static void
po_uninput(int c)
{
	(void) ungetc(c, fp);
	if (c == '\n')
		cur_line--;
}

static void
po_ungetc(struct ch *pch)
{
	if (backlen) {
		error(gettext(ERR_INTERNAL), cur_line, cur_po);
		/* NOTREACHED */
	}
	if (!pch->eof) {
		backlen = pch->len;
		(void) memcpy(backbuf, pch->buf, backlen);
	}
}

static struct ch *
po_getc(void)
{
	static struct ch	och;
	int	c;

	if (backlen) {
		och.len = backlen;
		(void) memcpy(och.buf, backbuf, backlen);
		backlen = 0;
		return (&och);
	}

	for (; ; ) {
		c = getc(fp);
		if (c == EOF) {
			if (ferror(fp)) {
				/* error happend */
				error(gettext(ERR_READ_FAILED), cur_po);
				/* NOTREACHED */
			}
			och.len = 0;
			och.eof = 1;
			return (&och);
		}
		if (c == '\\') {
			c = getc(fp);
			if (c == '\n') {
				/* this newline should be escaped */
				cur_line++;
				continue;
			} else {
				po_uninput(c);
				och.len = 1;
				och.eof = 0;
				och.buf[0] = '\\';
				return (&och);
			}
			/* NOTREACHED */
		}
		if (c == '\n') {
			cur_line++;
			och.len = 1;
			och.eof = 0;
			och.buf[0] = '\n';
			return (&och);
		}
		if (isascii((unsigned char)c)) {
			/* single byte ascii */
			och.len = 1;
			och.eof = 0;
			och.buf[0] = (unsigned char)c;
			return (&och);
		}

		och.len = get_mb(&och.buf[0], (unsigned char)c);
		och.eof = 0;
		return (&och);
	}
	/* NOTREACHED */
}

static void
extend_buf(char **buf, size_t *size, size_t add)
{
	char	*tmp;

	*size += add;
	tmp = (char *)Xrealloc(*buf, *size);
	*buf = tmp;
}

static struct ch	*
expand_es(void)
{
	int	c, n, loop;
	static struct ch	och;
	struct ch	*pch;

	pch = po_getc();
	if (pch->eof) {
		error(gettext(ERR_UNEXP_EOF),
			cur_line, cur_po);
		/* NOTREACHED */
	}
	if (pch->len > 1) {
		/* not a valid escape sequence */
		return (pch);
	}

	och.len = 1;
	och.eof = 0;
	switch (pch->buf[0]) {
	case '"':
	case '\\':
		och.buf[0] = pch->buf[0];
		break;
	case 'b':
		och.buf[0] = '\b';
		break;
	case 'f':
		och.buf[0] = '\f';
		break;
	case 'n':
		och.buf[0] = '\n';
		break;
	case 'r':
		och.buf[0] = '\r';
		break;
	case 't':
		och.buf[0] = '\t';
		break;
	case 'v':
		och.buf[0] = '\v';
		break;
	case 'a':
		och.buf[0] = '\a';
		break;
	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
		/* octal */
		c = pch->buf[0];
		for (n = 0, loop = 0; ; ) {
			n = n * 8 + c - '0';
			loop++;
			if (loop >= 3)
				break;
			pch = po_getc();
			if (pch->eof) {
				error(gettext(ERR_UNEXP_EOF),
					cur_line, cur_po);
				/* NOTREACHED */
			}
			if ((pch->len > 1) || (pch->buf[0] < '0') ||
				(pch->buf[0] > '7'))
				break;
			c = pch->buf[0];
		}
		po_ungetc(pch);
		och.buf[0] = (unsigned char)n;
		break;
	case 'x':
		/* hex */
		pch = po_getc();
		if (pch->eof) {
			error(gettext(ERR_UNEXP_EOF),
				cur_line, cur_po);
			/* NOTREACHED */
		}
		if (pch->len > 1) {
			po_ungetc(pch);
			och.buf[0] = 'x';
			break;
		}
		c = pch->buf[0];
		if (!isxdigit((unsigned char)c)) {
			po_ungetc(pch);
			och.buf[0] = 'x';
			break;
		}
		if (isdigit((unsigned char)c)) {
			n = c - '0';
		} else if (isupper((unsigned char)c)) {
			n = c - 'A' + 10;
		} else {
			n = c - 'a' + 10;
		}

		pch = po_getc();
		if (pch->eof) {
			error(gettext(ERR_UNEXP_EOF),
				cur_line, cur_po);
			/* NOTREACHED */
		}
		if (pch->len > 1) {
			po_ungetc(pch);
			och.buf[0] = (unsigned char)n;
			break;
		}
		c = pch->buf[0];
		if (!isxdigit((unsigned char)c)) {
			po_ungetc(pch);
			och.buf[0] = (unsigned char)n;
			break;
		}
		n *= 16;
		if (isdigit((unsigned char)c)) {
			n += c - '0';
		} else if (isupper((unsigned char)c)) {
			n += c - 'A' + 10;
		} else {
			n += c - 'a' + 10;
		}
		och.buf[0] = (unsigned char)n;
		break;

	default:
		och.buf[0] = pch->buf[0];
		break;
	}
	return (&och);
}

int
yylex(void)
{
	unsigned int	uc;
	struct ch	*pch;
	char	*buf;
	size_t	buf_size, buf_pos;

	for (; ; ) {
		pch = po_getc();

		if (pch->eof) {
			/* EOF */
			return (0);
		}

		if (pch->len > 1) {
			/* multi byte */
			yylval.c.len = pch->len;
			(void) memcpy(yylval.c.buf, pch->buf, pch->len);
			return (CHR);
		}
		/* single byte */
		switch (pch->buf[0]) {
		case ' ':
		case '\t':
		case '\n':
			break;

		case '#':
			/* comment start */
			buf_size = CBUFSIZE;
			buf = (char *)Xmalloc(buf_size);
			buf_pos = 0;
			pch = po_getc();
			while (!pch->eof &&
				((pch->len != 1) || (pch->buf[0] != '\n'))) {
				if (buf_pos + pch->len + 1 > buf_size)
					extend_buf(&buf, &buf_size, CBUFSIZE);
				(void) memcpy(buf + buf_pos,
					pch->buf, pch->len);
				buf_pos += pch->len;
				pch = po_getc();
			}
			buf[buf_pos] = '\0';
			yylval.str = buf;
			return (COMMENT);
			/* NOTREACHED */

		case '[':
		case ']':
			return (pch->buf[0]);
			/* NOTREACHED */

		case '"':
			buf_size = MBUFSIZE;
			buf = (char *)Xmalloc(buf_size);
			buf_pos = 0;
			for (; ; ) {
				pch = po_getc();

				if (pch->eof) {
					/* EOF */
					error(gettext(ERR_UNEXP_EOF),
						cur_line, cur_po);
					/* NOTREACHED */
				}

				if (pch->len == 1) {
					uc = pch->buf[0];

					if (uc == '\n') {
						error(gettext(ERR_UNEXP_EOL),
							cur_line, cur_po);
						/* NOTREACHED */
					}
					if (uc == '"')
						break;
					if (uc == '\\')
						pch = expand_es();
				}
				if (buf_pos + pch->len + 1 > buf_size)
					extend_buf(&buf, &buf_size,
						MBUFSIZE);
				(void) memcpy(buf + buf_pos,
					pch->buf, pch->len);
				buf_pos += pch->len;
			}

			buf[buf_pos] = '\0';
			yylval.str = buf;
			return (STR);
			/* NOTREACHED */

		default:
			uc = pch->buf[0];

			if (isalpha(uc) || (uc == '_')) {
				buf_size = KBUFSIZE;
				buf = (char *)Xmalloc(buf_size);
				buf_pos = 0;
				buf[buf_pos++] = (char)uc;
				pch = po_getc();
				while (!pch->eof &&
					(pch->len == 1) &&
					(isalpha(uc = pch->buf[0]) ||
					isdigit(uc) || (uc == '_'))) {
					if (buf_pos + 1 + 1 > buf_size)
						extend_buf(&buf, &buf_size,
							KBUFSIZE);
					buf[buf_pos++] = (char)uc;
					pch = po_getc();
				}
				/* push back the last char */
				po_ungetc(pch);
				buf[buf_pos] = '\0';
				yylval.str = buf;
				if (buf_pos > MAX_KW_LEN) {
					/* kbuf is longer than any keywords */
					return (SYMBOL);
				}
				yylval.num = cur_line;
				if (strcmp(buf, KW_DOMAIN) == 0) {
					free(buf);
					return (DOMAIN);
				} else if (strcmp(buf, KW_MSGID) == 0) {
					free(buf);
					return (MSGID);
				} else if (strcmp(buf, KW_MSGID_PLURAL) == 0) {
					free(buf);
					return (MSGID_PLURAL);
				} else if (strcmp(buf, KW_MSGSTR) == 0) {
					free(buf);
					return (MSGSTR);
				} else {
					free(buf);
					return (SYMBOL);
				}
				/* NOTREACHED */
			}
			if (isdigit(uc)) {
				buf_size = NBUFSIZE;
				buf = (char *)Xmalloc(buf_size);
				buf_pos = 0;
				buf[buf_pos++] = (char)uc;
				pch = po_getc();
				while (!pch->eof &&
					(pch->len == 1) &&
					isdigit(uc = pch->buf[0])) {
					if (buf_pos + 1 + 1 > buf_size)
						extend_buf(&buf, &buf_size,
							NBUFSIZE);
					buf[buf_pos++] = (char)uc;
					pch = po_getc();
				}
				/* push back the last char */
				po_ungetc(pch);
				buf[buf_pos] = '\0';
				yylval.num = atoi(buf);
				free(buf);
				return (NUM);
			}
			/* just a char */
			yylval.c.len = 1;
			yylval.c.buf[0] = uc;
			return (CHR);
			/* NOTREACHED */
		}
	}
}
