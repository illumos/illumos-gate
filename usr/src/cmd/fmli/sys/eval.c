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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef CACA
#define _DEBUG2	1
int	_Debug=4;
#endif

#include	<stdio.h>
#include	<ctype.h>
#include	"wish.h"
#include	"eval.h"
#include	"terror.h"
#include	"message.h"
#include	"moremacros.h"
#include	"interrupt.h"

#define MAXARGS		64

/* NOTE!!! the following flags compete for bits with
 *         the EV_**** flags in inc/eval.h  Make sure
 *	   there is no overlap.
 */
#define IN_DQ		1
#define IN_SQ		2
#define IN_BQ		4
#define IN_SQUIG	8
#define FROM_BQ		16

/*
 * list of "special" characters, and flags in which they are not
 * treated as special. NOTE that EV_SQUIG  flag is opposite all 
 * others. set it in nflags if {} ARE to be treated as special.
 */
static char	spchars[] = "\"'\\`$\n \t{}|&;<>2";
/*static char	spchars[] = "\"'\\`$\n \t{}|&;<>";
abs */
static int	nflags[] = {
	FROM_BQ | IN_SQ,		/* double quote */
	FROM_BQ | IN_DQ,		/* single quote */
	FROM_BQ,			/* backslash    */
	FROM_BQ | IN_SQ,		/* back quote   */
	FROM_BQ | IN_SQ,		/* dollar sign  */
	IN_SQUIG | IN_SQ | IN_DQ,	/* new line     */
	FROM_BQ | IN_SQ | IN_DQ | EV_GROUP,		/* space        */
	FROM_BQ | IN_SQ | IN_DQ | EV_GROUP,		/* tab          */
	FROM_BQ | IN_SQUIG | IN_SQ | IN_DQ | IN_BQ | EV_SQUIG,	/* open squig   */
	FROM_BQ | IN_SQ | IN_DQ | IN_BQ | EV_SQUIG,		/* close squig  */
	FROM_BQ | IN_SQ | IN_DQ | EV_GROUP,	/* pipe symbol  */
	FROM_BQ | IN_SQ | IN_DQ | EV_GROUP,	/* ampersand    */
	FROM_BQ | IN_SQ | IN_DQ | EV_GROUP,	/* semicolon    */
	FROM_BQ | IN_SQ | IN_DQ | EV_GROUP,	/* less than    */
	FROM_BQ | IN_SQ | IN_DQ | EV_GROUP     /* greater than */
	,FROM_BQ | IN_SQ | IN_DQ | EV_GROUP 	 /* digit two    */
};

/* return code from most recently executed command */
int	EV_retcode;
int	EV_backquotes;
int	Lasttok;

extern int in_an_if;	/* (in an if statement) see evfuncs.c */

static int eval_dollar();
static void eval_backquote();

char *
special_char(c, instr)
register int c;
IOSTRUCT *instr;
{
    char	*strchr();
    int c2;

    if ((char)c == '2')
    {
	c2 = getac(instr);
	if(c2 || instr->flags & EV_USE_FP) /* the other case: EV_USE_STRING */
	   ungetac(c2, instr);	/* and c2 = EndOfString. don't unget cause */
				/* it would unget c not c2.   abs */
	if ((char)c2 != '>')
	    return(NULL);
    }
    return(strchr(spchars, c));
}
    

int
eval(instr, outstr, flags)
IOSTRUCT	*instr;
IOSTRUCT	*outstr;
int	flags;
{
	register int	c;
	register int	tok;
	bool	done;

	flags ^= EV_SQUIG;	/* flip flag so only have to set it
				 when special (one case) instead of
				 in all other cases.  abs */
	if (!(flags & IN_BQ))
		EV_retcode = 0;
	EV_backquotes = FALSE;
	c = getac(instr);
	/* skip leading white space */
	if (flags & (EV_TOKEN | EV_GROUP)) {
		while (isspace(c))
			c = getac(instr);
		if (c == '#') {
			/*
			 * skip everything until end of line
			 */
			while ((c = getac(instr)) && c != '\n' && c != EOF)
				;
		}
	}
	/* handler `` at beginning of line if in GROUP mode */
	if ((flags & EV_GROUP) && c == '`') {
		eval_backquote(instr, outstr, flags);
		io_flags(instr, io_flags(instr, 0) & ~FROM_BQ);
		c = getac(instr);
	}
#ifdef _DEBUG2
/*
	if ((flags & EV_TOKEN) && (instr->flags & EV_USE_STRING)) {
		_debug2(stderr, "input is '%.*s'\n", instr->mu.str.count - instr->mu.str.pos, instr->mu.str.val +  instr->mu.str.pos);
	}
*/
#endif

	Lasttok = tok = ET_EOF;
	for (done = FALSE; c; c = getac(instr)) {
		register char	*p;
		char	*strchr();

/*		while (!(p = strchr(spchars, c))) {
abs */
		while(!(p = special_char(c, instr)))  {
			Lasttok = ET_WORD;
			putac(c, outstr);
			if (!(c = getac(instr))) {
				done = TRUE;
				break;
			}
		}
		if (done)
			break;
		/* single | and & are correct here */
		if ((instr->flags | flags) & nflags[tok = p - spchars])
			tok = !!c;
		else {
			tok += ET_DQUOTE;
#ifdef _DEBUG2
			_debug2(stderr, "eval: got special char 0x%x\n", tok);
#endif
		}
		switch (tok) {
		case ET_EOF:
			done = TRUE;
			break;
		case ET_WORD:
			Lasttok = tok;
			putac(c, outstr);
			break;
		case ET_DQUOTE:
			flags ^= IN_DQ;
			if (!(flags & EV_TOKEN))
				putac(c, outstr);
			break;
		case ET_SQUOTE:
			flags ^= IN_SQ;
			if (!(flags & EV_TOKEN))
				putac(c, outstr);
			break;
		case ET_BSLASH:
			c = getac(instr);
			/*
			 * if (not tokenizing or if we're in quotes and the
			 *	next character is not special, leave backslash
			 *	there
			 * else
			 *	remove it (don't copy to output)
			 */
			if (!(flags & EV_TOKEN) || (flags & (IN_SQ | IN_DQ)) && (!(p = strchr(spchars, c)) || (instr->flags | flags) & nflags[p - spchars]))
				putac('\\', outstr);
			putac(c, outstr);
			break;
		case ET_BQUOTE:
			if (flags & EV_TOKEN) {
				if (flags & IN_BQ) {
					if (Lasttok == ET_EOF) {
						putac(c, outstr);
						c = getac(instr);
						Lasttok = tok;
					}
					done = TRUE;
				}
				else
					eval_backquote(instr, outstr, flags);
			}
			else {
				flags ^= IN_BQ;
				putac(c, outstr);
			}
			EV_backquotes = TRUE;
			break;
		case ET_DOLLAR:
			if (flags & EV_TOKEN)
				eval_dollar(instr, outstr, flags);
			else
				putac(c, outstr);
			break;
		case ET_NEWLINE:
		case ET_SPACE:
		case ET_TAB:
			Lasttok = ET_WORD;
			if ((flags & EV_GROUP) && (flags & IN_BQ))
				putac(c, outstr);
			else
				done = TRUE;
			break;
		case ET_OSQUIG:
		case ET_CSQUIG:
			putac(c, outstr);
			if (flags & EV_GROUP)
				flags ^= IN_SQUIG;
			else if (flags & EV_TOKEN) {
				if (Lasttok == ET_EOF) {
					c = getac(instr);
					Lasttok = tok;
				}
				done = TRUE;
			}
			break;
		case ET_PIPE:
		case ET_AMPERSAND:
		case ET_SEMI:
		case ET_LTHAN:
		case ET_GTHAN:
			if (flags & IN_BQ) {
				if (Lasttok == ET_EOF) {
					register int	oldc;

					putac(c, outstr);
					oldc = c;
					if ((c = getac(instr)) == oldc) {
						putac(c, outstr);
						c = getac(instr);
						tok += DOUBLE;
					}
					Lasttok = tok;
				}
				done = TRUE;
			}
			else
				putac(c, outstr);
			break;
		case ET_TWO:
			if (flags & IN_BQ) {
			    if (Lasttok == ET_EOF) {
				putac(c, outstr);
				c = getac(instr); /* gets > known to follow 2 */
				putac(c, outstr);
				if ((c = getac(instr)) == '>') {
				    putac(c, outstr);
				    c = getac(instr);
				    tok += DOUBLE;
				}
				Lasttok = tok;
			    }
			    done = TRUE;
			}
			else
			    putac(c, outstr);
			break;
		}
		if (done)
			break;
		Lasttok = ET_WORD;
	}
	if (c)
		ungetac(c, instr);
#ifdef _DEBUG2
	if (flags & EV_TOKEN) {
		_debug2(stderr, "eval -> '%s'\n", io_ret_string(outstr));
		_debug2(stderr, "eval returning 0x%x\n", Lasttok);
	}
#endif

	return Lasttok;
}

/*
 * NOTE:
 *
 * In pre-4.0 releases of FMLI, the contents of environment variables
 * (after expansion) were put back into the input string for further
 * evaluation (lets call it "double evaluation").
 *
 * To remain backwards compatable, the global variable "Doublevars"
 * will be set to TRUE if double evaluation should be performed on
 * ALL environment variables. 
 *
 * If Doublevars == FALSE, then only evaluate the "contents" of the
 * variable if a "!" follows "$" (i.e., the "new" convention for double
 * evaluation is "$!VARNAME").
 *
 */
/*ARGSUSED*/
static int
eval_dollar(instr, outstr, flags)
IOSTRUCT	*instr;
IOSTRUCT	*outstr;
int	flags;
{
	register char	*p;
	register int	c;
	register IOSTRUCT	*iop;
	char	*expand();
	int	evalagain;
	extern  bool Doublevars;

	iop = io_open(EV_USE_STRING, NULL);
	putac('$', iop);
	if (Doublevars == TRUE)
		evalagain = TRUE;
	else {
		if ((c = getac(instr)) == '!') {
			evalagain = TRUE;
		}
		else {
			evalagain = FALSE;
			ungetac(c, instr);
		}
	}
	if ((c = getac(instr)) == '{') {
		while (c != '}') {
			putac(c, iop);
			c = getac(instr);
		}
		putac(c, iop);
	}
	else {
		while (isalpha(c) || isdigit(c) || c == '_') {
			putac(c, iop);
			c = getac(instr);
		}
		if (c)
			ungetac(c, instr);
	}
	if (p = expand(io_ret_string(iop))) {
		io_clear(iop);
		if (evalagain) {
			/*
			 * if the "contents" of the variable should
			 * be evaluated before passing it to outstr ...
			 */
			putastr(p, iop);
			free(p);
			p = (char *)NULL;
			io_seek(iop, 0);
			io_push(instr, iop);	/* push it back in instr */
		}
		else {
			/*
			 * simply put the variable's contents into outstr 
			 */
			putastr(p, outstr);
			free(p);
			p = (char *)NULL;
			io_close(iop);
		}
		return SUCCESS;
	}
	return FAIL;
}

static char *
eval_token(instr, flags)
IOSTRUCT	*instr;
int	flags;
{
	register char	*p;
	static IOSTRUCT	*tmp;

	if (instr == NULL) {
		io_close(tmp);
		return NULL;
	}
	if (tmp == NULL)
		tmp = io_open(EV_USE_STRING, NULL);
	(void) eval(instr, tmp, flags);
	p = io_string(tmp);
	io_seek(tmp, 0);
	return p;
}

static void
eval_backquote(instr, outstr, flags)
IOSTRUCT	*instr;
IOSTRUCT	*outstr;
int	flags;
{
    int	argc;
    char	*argv[MAXARGS];
    bool	doit;
    int	conditional = 0;
    int	if_elif = 0;
    bool	skip;
    bool	piped;
    bool	special;
    IOSTRUCT	*mystdin;
    IOSTRUCT	*mystdout;
    IOSTRUCT	*altstdout;
    IOSTRUCT	*altstderr;

#ifdef _DEBUG2
    _debug2(stderr, "eval_backquote\n");
#endif
    mystdin = io_open(EV_USE_STRING, NULL);
    mystdout = io_open(EV_USE_STRING, NULL);
    altstdout = NULL;
    altstderr = NULL;
    doit = skip = piped = special = FALSE;

    for (argc = 0; ; ) {
	conditional = 0;
	argv[argc++] = eval_token(instr, EV_TOKEN | IN_BQ);

	if (argc == 1) {
	    /*
	     * determine whether we've found an 
	     * if/then/else/elif statement
	     */ 
	    if_elif = 0;

#ifdef _DEBUG2
	    _debug2(stderr, "argv[0]=\"%s\"\n\r", argv[0]);
#endif

	    switch(argv[0][0]) {
	    case 'e':	/* else, elif */
		if (!strcmp(argv[0], "else")) 
		    conditional = 1;
		else if (!strcmp(argv[0], "elif")) {
		    conditional = 1;
		    if_elif = 1;
		}
		break;
	    case 'i':	/* if */
		if (argv[0][1] == 'f' && argv[0][2] == '\0') {
		    conditional = 1;
		    if_elif = 1;
		}
		break;
	    case 't':	/* then */
		if (!strcmp(argv[0], "then")) 
		    conditional = 1;
		break;
	    }

	    if (conditional) {
		int	a, nonwhite, start_look;
		char	*cp;
		char	ch;

		/*
		 * Force call to if/then/else/elif built-in
		 * (no arguments) ... Don't modify the input
		 * string here, just put a semi-colon in the
		 * "argv" array and set Lasttok (last token
		 * received) to ET_SEMI (semi-colon).
		 */
		argv[argc++] = strsave(";");
		Lasttok = ET_SEMI;


		/*
		 * Though the implementation of if/then/else
		 * is done via built-ins ... don't allow
		 * semi-colons after if/then/else/elif !!
		 */
		start_look = instr->mu.str.pos;
		cp = instr->mu.str.val + start_look; 
		nonwhite = 1;
		for (a = 0; a < instr->mu.str.count - start_look + 1; a++) {
		    ch = *(cp + a);

		    if (ch == '\n' )  
			break;
		    else if (ch == ';') {
			/*
			 * If all you've seen is
			 * white-space then produce
			 * an error message
			 */ 
			if (nonwhite) {
			    char errbuf[100];

			    sprintf(errbuf, "Syntax error - \";\" found after \"%s\"", argv[0]);
			    mess_temp(errbuf);
			    mess_lock();
			    Lasttok = ET_EOF;
			    in_an_if = 0;
			}
			break;
		    }
		    else if (ch != '\t' && ch != ' ') {
			/*
			 * not a space, tab, new-line
			 * or semi-colon ......
			 */
			nonwhite = 0;
		    }
		}
	    }
	}

	switch (Lasttok) {
	case ET_EOF:
	case ET_BQUOTE:
	    special = doit = TRUE;
	    break;
	case ET_PIPE:
	{
	    register FILE	*fp;
	    FILE	*tempfile();

	    if (altstdout) {
#ifdef _DEBUG2
		_debug2(stderr, "PIPE and > in same eval command\n");
#endif
		io_close(altstdout);
		altstdout = NULL;
	    }
	    if (fp = tempfile(NULL, "w+"))
		altstdout = io_open(EV_USE_FP, fp);
	    special = doit = piped = TRUE;
	}
	    break;
	case ET_AMPERSAND:
	    break;
	case ET_SEMI:
	    special = doit = TRUE;
	    break;
	case ET_LTHAN:
	{
	    register FILE	*fp;
	    register char	*p;

	    special = TRUE;
	    p = eval_token(instr, EV_TOKEN | IN_BQ);
	    if (fp = fopen(p, "r")) {
		io_close(mystdin);
		mystdin = io_open(EV_USE_FP, fp);
	    }
	    else
		warn(NOPEN, p);
	    free(p);
	    p = (char *)NULL;
	}
	    break;
	case ET_GTHAN:
	case ET_GTHAN + DOUBLE:	/* append symbol */
	{
	    register FILE	*fp;
	    register char	*p;
	    int savetok=Lasttok;
	    special = TRUE;
	    if (altstdout) {
#ifdef _DEBUG2
		_debug2(stderr, "2 >'s in eval command\n");
#endif
		io_close(altstdout);
	    }
	    p = eval_token(instr, EV_TOKEN | IN_BQ);
	    if (fp = fopen(p, (savetok & DOUBLE)?"a":"w"))
		altstdout = io_open(EV_USE_FP, fp);
	    else
		warn(NOPEN, p);
	    free(p);
	    p = (char *)NULL;
	}
	    break;
	case ET_TWO:
	case ET_TWO + DOUBLE:	/* append stderr symbol (2>>)*/
	{
	    register FILE	*fp;
	    register char	*p;
	    int savetok=Lasttok;

	    special = TRUE;
	    if (altstderr) {
#ifdef _DEBUG2
		_debug2(stderr, "2 >'s in eval command\n");
#endif
		io_close(altstderr);
		altstderr = NULL;
	    }
	    p = eval_token(instr, EV_TOKEN | IN_BQ);
	    if (fp = fopen(p, (savetok & DOUBLE) ?"a":"w"))
		altstderr = io_open(EV_USE_FP, fp);
	    else
		warn(NOPEN, p);
	    free(p);
	    p = (char *)NULL;
	}
	    break;
	    /* OR symbol */
	case ET_PIPE + DOUBLE:
	    special = doit = TRUE;
	    break;
	    /* AND symbol */
	case ET_AMPERSAND + DOUBLE:
	    special = doit = TRUE;
	    break;
	    /* semicolon (twice in a row) */
	case ET_SEMI + DOUBLE:
	    special = doit = TRUE;
	    break;
	    /* here document */
	case ET_LTHAN + DOUBLE:
	    break;

	}
	if (special) {
	    free(argv[--argc]);
	    argv[argc] = (char *)NULL;
	    special = FALSE;
	}
	if (doit || argc >= MAXARGS - 1) {
	    register int	n;

	    doit = FALSE;
	    if (!skip && !Cur_intr.skip_eval && argc > 0) /* abs */
	    {
		argv[argc] = NULL;
		EV_retcode = evalargv(argc, argv, mystdin,
				      altstdout ? altstdout : mystdout,
				      altstderr);
		/*
		 * if there is a syntax error in the
		 * conditional statement then terminate
		 * evaluation
		 */ 
		if (conditional && (EV_retcode == FAIL))
		    Lasttok = ET_EOF;
	    }
	    skip = (EV_retcode && Lasttok == ET_AMPERSAND + DOUBLE)
		|| (!EV_retcode && Lasttok == ET_PIPE + DOUBLE);
	    for (n = 0; n < argc; n++)
		if (argv[n]) {	/* ehr3 */
		    free(argv[n]);
		    argv[n] = (char *)NULL;
		}
	    argc = 0;
	    io_close(mystdin);
	    if (piped) {
		mystdin = altstdout;
		io_seek(mystdin, 0);
		piped = FALSE;
	    }
	    else {
		mystdin = io_open(EV_USE_STRING, NULL);
		if (altstdout)
		    io_close(altstdout);
	    }
	    if (altstderr)
	    {
		io_close(altstderr);
		altstderr = NULL;
	    }
	    altstdout = NULL;
	    if (Lasttok == ET_EOF || Lasttok == ET_BQUOTE)
		break;
	}
    }
    if ((argc = unputac(mystdout)) && argc != '\n')
	putac(argc, mystdout);
    if (flags & EV_GROUP)
	putac('\n', mystdout);
    io_seek(mystdout, 0);
    io_flags(mystdout, io_flags(mystdout, 0) | FROM_BQ);
    io_push(instr, mystdout);
}
