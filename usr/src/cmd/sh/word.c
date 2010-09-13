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
 * Copyright 2000 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * UNIX shell
 */

#include	"defs.h"
#include	"sym.h"
#include	<errno.h>
#include	<fcntl.h>

static int	readb(struct fileblk *, int, int);

/* ========	character handling for command lines	======== */

int
word(void)
{
	unsigned int	c, d, cc;
	struct argnod	*arg = (struct argnod *)locstak();
	unsigned char	*argp = arg->argval;
	unsigned char	*oldargp;
	int		alpha = 1;
	unsigned char *pc;

	wdnum = 0;
	wdset = 0;

	while (1)
	{
		while (c = nextwc(), space(c))		/* skipc() */
			;

		if (c == COMCHAR)
		{
			while ((c = readwc()) != NL && c != EOF);
			peekc = c;
		}
		else
		{
			break;	/* out of comment - white space loop */
		}
	}
	if (!eofmeta(c))
	{
		do
		{
			if (c == LITERAL)
			{
				oldargp = argp;
				while ((c = readwc()) && c != LITERAL){
					/*
					 * quote each character within
					 * single quotes
					 */
					pc = readw(c);
					if (argp >= brkend)
						growstak(argp);
					*argp++='\\';
				/* Pick up rest of multibyte character */
					if (c == NL)
						chkpr();
					while (c = *pc++) {
						if (argp >= brkend)
							growstak(argp);
						*argp++ = (unsigned char)c;
					}
				}
				if (argp == oldargp) { /* null argument - '' */
				/*
				 * Word will be represented by quoted null
				 * in macro.c if necessary
				 */
					if (argp >= brkend)
						growstak(argp);
					*argp++ = '"';
					if (argp >= brkend)
						growstak(argp);
					*argp++ = '"';
				}
			}
			else
			{
				if (c == 0) {
					if (argp >= brkend)
						growstak(argp);
					*argp++ = 0;
				} else {
					pc = readw(c);
					while (*pc) {
						if (argp >= brkend)
							growstak(argp);
						*argp++ = *pc++;
					}
				}
				if (c == '\\') {
					if ((cc = readwc()) == 0) {
						if (argp >= brkend)
							growstak(argp);
						*argp++ = 0;
					} else {
						pc = readw(cc);
						while (*pc) {
							if (argp >= brkend)
								growstak(argp);
							*argp++ = *pc++;
						}
					}
				}
				if (c == '=')
					wdset |= alpha;
				if (!alphanum(c))
					alpha = 0;
				if (qotchar(c))
				{
					d = c;
					for (;;)
					{
						if ((c = nextwc()) == 0) {
							if (argp >= brkend)
								growstak(argp);
							*argp++ = 0;
						} else {
							pc = readw(c);
							while (*pc) {
								if (argp >= brkend)
									growstak(argp);
								*argp++ = *pc++;
							}
						}
						if (c == 0 || c == d)
							break;
						if (c == NL)
							chkpr();
						/*
						 * don't interpret quoted
						 * characters
						 */
						if (c == '\\') {
							if ((cc = readwc()) == 0) {
								if (argp >= brkend)
									growstak(argp);
								*argp++ = 0;
							} else {
								pc = readw(cc);
								while (*pc) {
									if (argp >= brkend)
										growstak(argp);
									*argp++ = *pc++;
								}
							}
						}
					}
				}
			}
		} while ((c = nextwc(), !eofmeta(c)));
		argp = endstak(argp);
		if (!letter(arg->argval[0]))
			wdset = 0;

		peekn = c | MARK;
		if (arg->argval[1] == 0 &&
		    (d = arg->argval[0], digit(d)) &&
		    (c == '>' || c == '<'))
		{
			word();
			wdnum = d - '0';
		}else{ /* check for reserved words */
			if (reserv == FALSE ||
			    (wdval = syslook(arg->argval,
					reserved, no_reserved)) == 0) {
				wdval = 0;
			}
			/* set arg for reserved words too */
			wdarg = arg;
		}
	}else if (dipchar(c)){
		if ((d = nextwc()) == c)
		{
			wdval = c | SYMREP;
			if (c == '<')
			{
				if ((d = nextwc()) == '-')
					wdnum |= IOSTRIP;
				else
					peekn = d | MARK;
			}
		}
		else
		{
			peekn = d | MARK;
			wdval = c;
		}
	}
	else
	{
		if ((wdval = c) == EOF)
			wdval = EOFSYM;
		if (iopend && eolchar(c))
		{
			struct ionod *tmp_iopend;
			tmp_iopend = iopend;
			iopend = 0;
			copy(tmp_iopend);
		}
	}
	reserv = FALSE;
	return (wdval);
}

unsigned int skipwc()
{
	unsigned int c;

	while (c = nextwc(), space(c))
		;
	return (c);
}

unsigned int nextwc()
{
	unsigned int	c, d;

retry:
	if ((d = readwc()) == ESCAPE) {
		if ((c = readwc()) == NL) {
			chkpr();
			goto retry;
		}
		peekc = c | MARK;
	}
	return (d);
}

unsigned char *readw(d)
wchar_t	d;
{
	static unsigned char c[MULTI_BYTE_MAX + 1];
	int length;
	wchar_t l;
	if (isascii(d)) {
		c[0] = d;
		c[1] = '\0';
		return (c);
	}

	length = wctomb((char *)c, d);
	if (length <= 0) {
		c[0] = (unsigned char)d;
		length = 1;
	}
	c[length] = '\0';
	return (c);
}

unsigned int
readwc()
{
	wchar_t	c;
	int	len;
	struct fileblk	*f;
	int	mbmax = MB_CUR_MAX;
	int	i, mlen;

	if (peekn) {
		c = peekn & 0x7fffffff;
		peekn = 0;
		return (c);
	}
	if (peekc) {
		c = peekc & 0x7fffffff;
		peekc = 0;
		return (c);
	}
	f = standin;

retry:
	if (f->fend > f->fnxt) {
		/*
		 * something in buffer
		 */
		if (*f->fnxt == 0) {
			f->fnxt++;
			f->nxtoff++;
			if (f->feval == 0)
				goto retry;	/* = c = readc(); */
			if (estabf(*f->feval++))
				c = EOF;
			else
				c = SPACE;
			if (flags & readpr && standin->fstak == 0)
				prc(c);
			if (c == NL)
				f->flin++;
			return (c);
		}

		if (isascii(c = (unsigned char)*f->fnxt)) {
			f->fnxt++;
			f->nxtoff++;
			if (flags & readpr && standin->fstak == 0)
				prc(c);
			if (c == NL)
				f->flin++;
			return (c);
		}

		for (i = 1; i <= mbmax; i++) {
			int	rest;
			if ((rest = f->fend - f->fnxt) < i) {
				/*
				 * not enough bytes available
				 * f->fsiz could be BUFFERSIZE or 1
				 * since mbmax is enough smaller than BUFFERSIZE,
				 * this loop won't overrun the f->fbuf buffer.
				 */
				len = readb(f,
					(f->fsiz == 1) ? 1 : (f->fsiz - rest),
					rest);
				if (len == 0)
					break;
			}
			mlen = mbtowc(&c, (char *)f->fnxt, i);
			if (mlen > 0)
				break;
		}

		if (i > mbmax) {
			/*
			 * enough bytes available but cannot be converted to
			 * a valid wchar.
			 */
			c = (unsigned char)*f->fnxt;
			mlen = 1;
		}
		
		f->fnxt += mlen;
		f->nxtoff += mlen;
		if (flags & readpr && standin->fstak == 0)
			prwc(c);
		if (c == NL)
			f->flin++;
		return (c);
	}

	if (f->feof || f->fdes < 0){
		c = EOF;
		f->feof++;
		return (c);
	}

	if (readb(f, f->fsiz, 0) <= 0){
		if (f->fdes != input || !isatty(input)) {
			close(f->fdes);
			f->fdes = -1;
		}
		f->feof++;
		c = EOF;
		return (c);
	}
	goto retry;
}

static int
readb(struct fileblk *f, int toread, int rest)
{
	int	len;
	int	fflags;

	if (rest) {
		/*
		 * copies the remaining 'rest' bytes from f->fnxt
		 * to f->fbuf
		 */
		(void) memcpy(f->fbuf, f->fnxt, rest);
		f->fnxt = f->fbuf;
		f->fend = f->fnxt + rest;
		f->nxtoff = 0;
		f->endoff = rest;
		if (f->fbuf[rest - 1] == '\n') {
			/*
			 * if '\n' found, it should be
			 * a bondary of multibyte char.
			 */
			return (rest);
		}
	}
		
retry:
	do {
		if (trapnote & SIGSET) {
			newline();
			sigchk();
		} else if ((trapnote & TRAPSET) && (rwait > 0)) {
			newline();
			chktrap();
			clearup();
		}
	} while ((len = read(f->fdes, f->fbuf + rest, toread)) < 0 && trapnote);
	/*
	 * if child sets O_NDELAY or O_NONBLOCK on stdin
	 * and exited then turn the modes off and retry
	 */
	if (len == 0) {
		if (((flags & intflg) ||
		    ((flags & oneflg) == 0 && isatty(input) &&
		    (flags & stdflg))) &&
		    ((fflags = fcntl(f->fdes, F_GETFL, 0)) & O_NDELAY)) {
			fflags &= ~O_NDELAY;
			fcntl(f->fdes, F_SETFL, fflags);
			goto retry;
		}
	} else if (len < 0) {
		if (errno == EAGAIN) {
			fflags = fcntl(f->fdes, F_GETFL, 0);
			fflags &= ~O_NONBLOCK;
			fcntl(f->fdes, F_SETFL, fflags);
			goto retry;
		}
		len = 0;
	}
	f->fnxt = f->fbuf;
	f->fend = f->fnxt + (len + rest);
	f->nxtoff = 0;
	f->endoff = len + rest;
	return (len + rest);
}
