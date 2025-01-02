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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * UNIX shell
 */

#include	"defs.h"
#include	"sym.h"
#include	<wait.h>

static unsigned char	quote;	/* used locally */
static unsigned char	quoted;	/* used locally */
static int getch();
static void comsubst(int);
static void flush(int);

static void
copyto(unsigned char endch, int trimflag)
/* trimflag - flag to check if argument will be trimmed */
{
	unsigned int	c;
	unsigned int 	d;
	unsigned char *pc;

	while ((c = getch(endch, trimflag)) != endch && c)
		if (quote) {
			if(c == '\\') { /* don't interpret next character */
				if (staktop >= brkend)
					growstak(staktop);
				pushstak(c);
				d = readwc();
				if(!escchar(d)) { /* both \ and following
						     character are quoted if next
						     character is not $, `, ", or \*/
					if (staktop >= brkend)
						growstak(staktop);
					pushstak('\\');
					if (staktop >= brkend)
						growstak(staktop);
					pushstak('\\');
					pc = readw(d);
					/* push entire multibyte char */
					while(*pc) {
						if (staktop >= brkend)
							growstak(staktop);
						pushstak(*pc++);
					}
				} else {
					pc = readw(d);
					/* d might be NULL */
					/* Evenif d is NULL, we have to save it */
					if (*pc) {
						while (*pc) {
							if (staktop >= brkend)
								growstak(staktop);
							pushstak(*pc++);
						}
					} else {
						if (staktop >= brkend)
							growstak(staktop);
						pushstak(*pc);
					}
				}
			} else { /* push escapes onto stack to quote characters */
				pc = readw(c);
				if (staktop >= brkend)
					growstak(staktop);
				pushstak('\\');
				while(*pc) {
					if (staktop >= brkend)
						growstak(staktop);
					pushstak(*pc++);
				}
			}
		} else if(c == '\\') {
			c = readwc(); /* get character to be escaped */
			if (staktop >= brkend)
				growstak(staktop);
			pushstak('\\');
			pc = readw(c);
			/* c might be NULL */
			/* Evenif c is NULL, we have to save it */
			if (*pc) {
				while (*pc) {
					if (staktop >= brkend)
						growstak(staktop);
					pushstak(*pc++);
				}
			} else {
				if (staktop >= brkend)
					growstak(staktop);
				pushstak(*pc);
			}
		} else {
			pc = readw(c);
			while (*pc) {
				if (staktop >= brkend)
					growstak(staktop);
				pushstak(*pc++);
			}
		}
	if (staktop >= brkend)
			growstak(staktop);
	zerostak();
	if (c != endch)
		error(badsub);
}

static void
skipto(unsigned char endch)
{
	/*
	 * skip chars up to }
	 */
	unsigned int	c;

	while ((c = readwc()) && c != endch)
	{
		switch (c)
		{
		case SQUOTE:
			skipto(SQUOTE);
			break;

		case DQUOTE:
			skipto(DQUOTE);
			break;

		case DOLLAR:
			if (readwc() == BRACE)
				skipto('}');
		}
	}
	if (c != endch)
		error(badsub);
}

static
int getch(endch, trimflag)
unsigned char	endch;
int trimflag; /* flag to check if an argument is going to be trimmed, here document
		 output is never trimmed
	 */
{
	unsigned int	d;
	int atflag;  /* flag to check if $@ has already been seen within double
		        quotes */
retry:
	d = readwc();
	if (!subchar(d))
		return(d);

	if (d == DOLLAR)
	{
		unsigned int c;

		if ((c = readwc(), dolchar(c)))
		{
			struct namnod *n = (struct namnod *)NIL;
			int		dolg = 0;
			BOOL		bra;
			BOOL		nulflg;
			unsigned char	*argp, *v;
			unsigned char		idb[2];
			unsigned char		*id = idb;

			if (bra = (c == BRACE))
				c = readwc();
			if (letter(c))
			{
				argp = (unsigned char *)relstak();
				while (alphanum(c))
				{
					if (staktop >= brkend)
						growstak(staktop);
					pushstak(c);
					c = readwc();
				}
				if (staktop >= brkend)
					growstak(staktop);
				zerostak();
				n = lookup(absstak(argp));
				setstak(argp);
				if (n->namflg & N_FUNCTN)
					error(badsub);
				v = n->namval;
				id = (unsigned char *)n->namid;
				peekc = c | MARK;
			}
			else if (digchar(c))
			{
				*id = c;
				idb[1] = 0;
				if (astchar(c))
				{
					if(c == '@' && !atflag && quote) {
						quoted--;
						atflag = 1;
					}
					dolg = 1;
					c = '1';
				}
				c -= '0';
				v = ((c == 0) ? cmdadr : ((int)c <= dolc) ? dolv[c] : (unsigned char *)(dolg = 0));
			}
			else if (c == '$')
				v = pidadr;
			else if (c == '!')
				v = pcsadr;
			else if (c == '#')
			{
				itos(dolc);
				v = numbuf;
			}
			else if (c == '?')
			{
				itos(retval);
				v = numbuf;
			}
			else if (c == '-')
				v = flagadr;
			else if (bra)
				error(badsub);
			else
				goto retry;
			c = readwc();
			if (c == ':' && bra)	/* null and unset fix */
			{
				nulflg = 1;
				c = readwc();
			}
			else
				nulflg = 0;
			if (!defchar(c) && bra)
				error(badsub);
			argp = 0;
			if (bra)
			{
				if (c != '}')
				{
					argp = (unsigned char *)relstak();
					if ((v == 0 || (nulflg && *v == 0)) ^ (setchar(c)))
						copyto('}', trimflag);
					else
						skipto('}');
					argp = absstak(argp);
				}
			}
			else
			{
				peekc = c | MARK;
				c = 0;
			}
			if (v && (!nulflg || *v))
			{

				if (c != '+')
				{
					for (;;)
					{
						if (*v == 0 && quote) {
							if (staktop >= brkend)
								growstak(staktop);
							pushstak('\\');
							if (staktop >= brkend)
								growstak(staktop);
							pushstak('\0');
						} else {
							while (c = *v) {
								wchar_t 	wc;
								int 	length;
								if ((length = mbtowc(&wc, (char *)v, MB_LEN_MAX)) <= 0)
									length = 1;

								if(quote || (c == '\\' && trimflag)) {
									if (staktop >= brkend)
										growstak(staktop);
									pushstak('\\');
								}
								while(length-- > 0) {
									if (staktop >= brkend)
										growstak(staktop);
									pushstak(*v++);
								}
							}
						}

						if (dolg == 0 || (++dolg > dolc))
							break;
						else /* $* and $@ expansion */
						{
							v = dolv[dolg];
							if(*id == '*' && quote) {
/* push quoted space so that " $* " will not be broken into separate arguments */
								if (staktop >= brkend)
									growstak(staktop);
								pushstak('\\');
							}
							if (staktop >= brkend)
								growstak(staktop);
							pushstak(' ');
						}
					}
				}
			}
			else if (argp)
			{
				if (c == '?') {
					if(trimflag)
						trim(argp);
					failed(id, *argp ? (const char *)argp :
					    badparam);
				}
				else if (c == '=')
				{
					if (n)
					{
						int strlngth = staktop - stakbot;
						unsigned char *savptr = fixstak();
						unsigned char *newargp;
					/*
					 * copy word onto stack, trim it, and then
					 * do assignment
					 */
						usestak();
						while(c = *argp) {
							wchar_t 	wc;
							int 		len;

							if ((len = mbtowc(&wc, (char *)argp, MB_LEN_MAX)) <= 0)
								len = 1;

							if(c == '\\' && trimflag) {
								argp++;
								if (*argp == 0) {
									argp++;
									continue;
								}
								if ((len = mbtowc(&wc, (char *)argp, MB_LEN_MAX)) <= 0)
									len = 1;
							}
							while(len-- > 0) {
								if (staktop >= brkend)
									growstak(staktop);
								pushstak(*argp++);
							}
						}
						newargp = fixstak();
						assign(n, newargp);
						tdystak(savptr);
						(void) memcpystak(stakbot, savptr, strlngth);
						staktop = stakbot + strlngth;
					}
					else
						error(badsub);
				}
			}
			else if (flags & setflg)
				failed(id, unset);
			goto retry;
		}
		else
			peekc = c | MARK;
	}
	else if (d == endch)
		return(d);
	else if (d == SQUOTE)
	{
		comsubst(trimflag);
		goto retry;
	}
	else if (d == DQUOTE && trimflag)
	{
		if(!quote) {
			atflag = 0;
			quoted++;
		}
		quote ^= QUOTE;
		goto retry;
	}
	return(d);
}

unsigned char *
macro(as)
unsigned char	*as;
{
	/*
	 * Strip "" and do $ substitution
	 * Leaves result on top of stack
	 */
	BOOL	savqu = quoted;
	unsigned char	savq = quote;
	struct filehdr	fb;

	push(&fb);
	estabf(as);
	usestak();
	quote = 0;
	quoted = 0;
	copyto(0, 1);
	pop();
	if (quoted && (stakbot == staktop)) {
		if (staktop >= brkend)
			growstak(staktop);
		pushstak('\\');
		if (staktop >= brkend)
			growstak(staktop);
		pushstak('\0');
/*
 * above is the fix for *'.c' bug
 */
	}
	quote = savq;
	quoted = savqu;
	return(fixstak());
}
/* Save file descriptor for command substitution */
int savpipe = -1;

static void
comsubst(int trimflag)
/* trimflag - used to determine if argument will later be trimmed */
{
	/*
	 * command substn
	 */
	struct fileblk	cb;
	unsigned int	d;
	int strlngth = staktop - stakbot;
	unsigned char *oldstaktop;
	unsigned char *savptr = fixstak();
	unsigned char	*pc;

	usestak();
	while ((d = readwc()) != SQUOTE && d) {
		if(d == '\\') {
			d = readwc();
			if(!escchar(d) || (d == '"' && !quote)) {
		/* trim quotes for `, \, or " if command substitution is within
		   double quotes */
				if (staktop >= brkend)
					growstak(staktop);
				pushstak('\\');
			}
		}
		pc = readw(d);
		/* d might be NULL */
		if (*pc) {
			while (*pc) {
				if (staktop >= brkend)
					growstak(staktop);
				pushstak(*pc++);
			}
		} else {
			if (staktop >= brkend)
				growstak(staktop);
			pushstak(*pc);
		}
	}
	{
		unsigned char	*argc;

		argc = fixstak();
		push(&cb);
		estabf(argc);  /* read from string */
	}
	{
		struct trenod	*t;
		int		pv[2];

		/*
		 * this is done like this so that the pipe
		 * is open only when needed
		 */
	 	t = makefork(FPOU, cmd(EOFSYM, MTFLG | NLFLG ));
		chkpipe(pv);
		savpipe = pv[OTPIPE];
		initf(pv[INPIPE]); /* read from pipe */
		execute(t, XEC_NOSTOP, (int)(flags & errflg), 0, pv);
		close(pv[OTPIPE]);
		savpipe = -1;
	}
	tdystak(savptr);
	(void) memcpystak(stakbot, savptr, strlngth);
	oldstaktop = staktop = stakbot + strlngth;
	while (d = readwc()) {
		if(quote || (d == '\\' && trimflag)) {
			unsigned char *rest;
			/* quote output from command subst. if within double
			   quotes or backslash part of output */
			rest = readw(d);
			if (staktop >= brkend)
				growstak(staktop);
			pushstak('\\');
			while(d = *rest++) {
			/* Pick up all of multibyte character */
				if (staktop >= brkend)
					growstak(staktop);
				pushstak(d);
			}
		}
		else {
			pc = readw(d);
			while (*pc) {
				if (staktop >= brkend)
					growstak(staktop);
				pushstak(*pc++);
			}
		}
	}
	{
		extern pid_t parent;
		int stat;
		int rc;
		int	ret = 0;

		while ((ret = waitpid(parent,&stat,0)) != parent) {
			/* break out if waitpid(3C) has failed */
			if (ret == -1)
				break;
		}
		if (WIFEXITED(stat))
			rc = WEXITSTATUS(stat);
		else
			rc = (WTERMSIG(stat) | SIGFLG);
		if (rc && (flags & errflg))
			exitsh(rc);
		exitval = rc;
		flags |= eflag;
		exitset();
	}
	while (oldstaktop != staktop)
	{ /* strip off trailing newlines from command substitution only */
		if ((*--staktop) != NL)
		{
			++staktop;
			break;
		} else if(quote)
			staktop--; /* skip past backslashes if quoting */
	}
	pop();
}

#define CPYSIZ	512

void
subst(int in, int ot)
{
	unsigned int	c;
	struct fileblk	fb;
	int	count = CPYSIZ;
	unsigned char	*pc;

	push(&fb);
	initf(in);
	/*
	 * DQUOTE used to stop it from quoting
	 */
	while (c = (getch(DQUOTE, 0))) /* read characters from here document
				       and interpret them */
	{
		if(c == '\\') {
			c = readwc(); /* check if character in here document is
					escaped */
			if(!escchar(c) || c == '"') {
				if (staktop >= brkend)
					growstak(staktop);
				pushstak('\\');
			}
		}
		pc = readw(c);
		/* c might be NULL */
		if (*pc) {
			while (*pc) {
				if (staktop >= brkend)
					growstak(staktop);
				pushstak(*pc++);
			}
		} else {
			if (staktop >= brkend)
				growstak(staktop);
			pushstak(*pc);
		}
		if (--count == 0)
		{
			flush(ot);
			count = CPYSIZ;
		}
	}
	flush(ot);
	pop();
}

static void
flush(int ot)
{
	write(ot, stakbot, staktop - stakbot);
	if (flags & execpr)
		write(output, stakbot, staktop - stakbot);
	staktop = stakbot;
}
