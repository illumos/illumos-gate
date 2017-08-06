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
 * Copyright 2015 Gary Mills
 * Copyright (c) 1996-1997 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

/* Copyright (c) 1979 Regents of the University of California */

/*LINTLIBRARY*/

#include	"curses_inc.h"
#include	"curshdr.h"
#include	"term.h"
#include	<string.h>
#include	<setjmp.h>
#include	<stdlib.h>
#include	<stdio.h>

#ifndef	_CHCTRL
#define	_CHCTRL(c)	((c) & 037)
#endif	/* _CHCTRL */

char	*_branchto(char *, char);

/*
 * Routine to perform parameter substitution.
 * instring is a string containing printf type escapes.
 * The whole thing uses a stack, much like an HP 35.
 * The following escapes are defined for substituting row/column:
 *
 *	%[:[-+ #0]][0-9][.][0-9][dsoxX]
 *		print pop() as in printf(3), as defined in the local
 *		sprintf(3), except that a leading + or - must be preceded
 *		with a colon (:) to distinguish from the plus/minus operators.
 *
 *	%c	print pop() like %c in printf(3)
 *	%l	pop() a string address and push its length.
 *	%P[a-z] set dynamic variable a-z
 *	%g[a-z] get dynamic variable a-z
 *	%P[A-Z] set static variable A-Z
 *	%g[A-Z] get static variable A-Z
 *
 *	%p[1-0]	push ith parm
 *	%'c'	char constant c
 *	%{nn}	integer constant nn
 *
 *	%+ %- %* %/ %m		arithmetic (%m is mod): push(pop() op pop())
 *	%& %| %^		bit operations:		push(pop() op pop())
 *	%= %> %<		logical operations:	push(pop() op pop())
 *	%A %O			logical AND, OR		push(pop() op pop())
 *	%! %~			unary operations	push(op pop())
 *	%%			output %
 *	%? expr %t thenpart %e elsepart %;
 *				if-then-else, %e elsepart is optional.
 *				else-if's are possible ala Algol 68:
 *				%? c1 %t %e c2 %t %e c3 %t %e c4 %t %e %;
 *	% followed by anything else
 *				is not defined, it may output the character,
 *				and it may not. This is done so that further
 *				enhancements to the format capabilities may
 *				be made without worrying about being upwardly
 *				compatible from buggy code.
 *
 * all other characters are ``self-inserting''.  %% gets % output.
 *
 * The stack structure used here is based on an idea by Joseph Yao.
 */

#define	MAX		10
#define	MEM_ALLOC_FAIL	1
#define	STACK_UNDERFLOW	2

typedef struct {
	long	top;
	int	stacksize;
	long	*stack;

}STACK;

static jmp_buf env;

static long
tops(STACK *st)
{

	if (st->top < 0) {
		longjmp(env, STACK_UNDERFLOW);
	}
	return (st->stack[st->top]);
}

static void
push(STACK *st, long i)
{
	if (st->top >= (st->stacksize - 1)) {
		st->stacksize += MAX;
		if ((st->stack = (void *)realloc(st->stack,
		    (st->stacksize * sizeof (long)))) == NULL) {
			longjmp(env, MEM_ALLOC_FAIL);
		}
	}
	st->stack[++st->top] = (i);
}

static long
pop(STACK *st)
{
	if (st->top < 0) {
		longjmp(env, STACK_UNDERFLOW);
	}
	return (st->stack[st->top--]);
}

/*
 * The following routine was added to make lint shut up about converting from
 * a long to a char *.  It is identical to the pop routine, except for the
 * cast on the return statement.
 */
static char *
pop_char_p(STACK *st)
{
	if (st->top < 0) {
		longjmp(env, STACK_UNDERFLOW);
	}
	return ((char *)(st->stack[st->top--]));
}

static void
init_stack(STACK *st)
{
	st->top = -1;
	st->stacksize = MAX;
	if ((st->stack = (void *)malloc(MAX * sizeof (long))) == NULL) {
		longjmp(env, MEM_ALLOC_FAIL);
	}
}

static void
free_stack(STACK *st)
{
	free(st->stack);
}


char *
tparm_p0(char *instring)
{
	long	p[] = {0, 0, 0, 0, 0, 0, 0, 0, 0};

	return (tparm(instring, p[0], p[1], p[2], p[3], p[4], p[5], p[6],
	    p[7], p[8]));
}

char *
tparm_p1(char *instring, long l1)
{
	long	p[] = {0, 0, 0, 0, 0, 0, 0, 0, 0};

	p[0] = l1;

	return (tparm(instring, p[0], p[1], p[2], p[3], p[4], p[5], p[6],
	    p[7], p[8]));
}

char *
tparm_p2(char *instring, long l1, long l2)
{
	long	p[] = {0, 0, 0, 0, 0, 0, 0, 0, 0};

	p[0] = l1;
	p[1] = l2;

	return (tparm(instring, p[0], p[1], p[2], p[3], p[4], p[5], p[6],
	    p[7], p[8]));
}

char *
tparm_p3(char *instring, long l1, long l2, long l3)
{
	long	p[] = {0, 0, 0, 0, 0, 0, 0, 0, 0};

	p[0] = l1;
	p[1] = l2;
	p[2] = l3;

	return (tparm(instring, p[0], p[1], p[2], p[3], p[4], p[5], p[6],
	    p[7], p[8]));
}

char *
tparm_p4(char *instring, long l1, long l2, long l3, long l4)
{
	long	p[] = {0, 0, 0, 0, 0, 0, 0, 0, 0};

	p[0] = l1;
	p[1] = l2;
	p[2] = l3;
	p[3] = l4;

	return (tparm(instring, p[0], p[1], p[2], p[3], p[4], p[5], p[6],
	    p[7], p[8]));
}

char *
tparm_p7(char *instring, long l1, long l2, long l3, long l4, long l5, long l6,
    long l7)
{
	long	p[] = {0, 0, 0, 0, 0, 0, 0, 0, 0};

	p[0] = l1;
	p[1] = l2;
	p[2] = l3;
	p[3] = l4;
	p[4] = l5;
	p[5] = l6;
	p[6] = l7;

	return (tparm(instring, p[0], p[1], p[2], p[3], p[4], p[5], p[6],
	    p[7], p[8]));
}

/* VARARGS */
char *
tparm(char *instring, long fp1, long fp2, long p3, long p4,
    long p5, long p6, long p7, long p8, long p9)
{
	static	char	result[512];
	static	char	added[100];
	long		vars[26];
	STACK		stk;
	char		*cp = instring;
	char		*outp = result;
	char		c;
	long		op;
	long		op2;
	int		sign;
	volatile int	onrow = 0;
	volatile long	p1 = fp1, p2 = fp2; /* copy in case < 2 actual parms */
	char		*xp;
	char		formatbuffer[100];
	char		*format;
	int		looping;
	short		*regs = cur_term->_regs;
	int		val;


	if ((val = setjmp(env)) != 0) {
#ifdef DEBUG
		switch (val) {
			case MEM_ALLOC_FAIL:
				fprintf(outf, "TPARM: Memory allocation"
				    " failure.");
				break;
			case STACK_UNDERFLOW:
				fprintf(outf, "TPARM: Stack underflow.");
				break;
		}
#endif  /* DEBUG */

		if (val == STACK_UNDERFLOW)
			free_stack(&stk);
		return (NULL);
	}

	init_stack(&stk);
	push(&stk, 0);

	if (instring == 0) {
#ifdef	DEBUG
		if (outf)
			fprintf(outf, "TPARM: null arg\n");
#endif	/* DEBUG */
		free_stack(&stk);
		return (NULL);
	}

	added[0] = 0;

	while ((c = *cp++) != 0) {
		if (c != '%') {
			*outp++ = c;
			continue;
		}
		op = tops(&stk);
		switch (c = *cp++) {
			/* PRINTING CASES */
			case ':':
			case ' ':
			case '#':
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
			case '.':
			case 'd':
			case 's':
			case 'o':
			case 'x':
			case 'X':
				format = formatbuffer;
				*format++ = '%';

			/* leading ':' to allow +/- in format */
			if (c == ':')
				c = *cp++;

			/* take care of flags, width and precision */
			looping = 1;
			while (c && looping)
				switch (c) {
					case '-':
					case '+':
					case ' ':
					case '#':
					case '0':
					case '1':
					case '2':
					case '3':
					case '4':
					case '5':
					case '6':
					case '7':
					case '8':
					case '9':
					case '.':
						*format++ = c;
						c = *cp++;
						break;
					default:
						looping = 0;
				}

			/* add in the conversion type */
			switch (c) {
				case 'd':
				case 's':
				case 'o':
				case 'x':
				case 'X':
					*format++ = c;
					break;
				default:
#ifdef	DEBUG
				if (outf)
					fprintf(outf, "TPARM: invalid "
					    "conversion type\n");
#endif	/* DEBUG */
				free_stack(&stk);
				return (NULL);
			}
			*format = '\0';

			/*
			 * Pass off the dirty work to sprintf.
			 * It's debatable whether we should just pull in
			 * the appropriate code here. I decided not to for
			 * now.
			 */
			if (c == 's')
				(void) sprintf(outp, formatbuffer, (char *)op);
			else
				(void) sprintf(outp, formatbuffer, op);
			/*
			 * Advance outp past what sprintf just did.
			 * sprintf returns an indication of its length on some
			 * systems, others the first char, and there's
			 * no easy way to tell which. The Sys V on
			 * BSD emulations are particularly confusing.
			 */
				while (*outp)
					outp++;
				(void) pop(&stk);

				continue;

			case 'c':
			/*
			 * This code is worth scratching your head at for a
			 * while.  The idea is that various weird things can
			 * happen to nulls, EOT's, tabs, and newlines by the
			 * tty driver, arpanet, and so on, so we don't send
			 * them if we can help it.  So we instead alter the
			 * place being addessed and then move the cursor
			 * locally using UP or RIGHT.
			 *
			 * This is a kludge, clearly.  It loses if the
			 * parameterized string isn't addressing the cursor
			 * (but hopefully that is all that %c terminals do
			 * with parms).  Also, since tab and newline happen
			 * to be next to each other in ASCII, if tab were
			 * included a loop would be needed.  Finally, note
			 * that lots of other processing is done here, so
			 * this hack won't always work (e.g. the Ann Arbor
			 * 4080, which uses %B and then %c.)
			 */
				switch (op) {
				/*
				 * Null.  Problem is that our
				 * output is, by convention, null terminated.
				 */
					case 0:
						op = 0200; /* Parity should */
							/* be ignored. */
						break;
				/*
				 * Control D.  Problem is that certain very
				 * ancient hardware hangs up on this, so the
				 * current(!) UNIX tty driver doesn't xmit
				 * control D's.
				 */
					case _CHCTRL('d'):
				/*
				 * Newline.  Problem is that UNIX will expand
				 * this to CRLF.
				 */
					case '\n':
						xp = (onrow ? cursor_down :
						    cursor_right);
					if (onrow && xp && op < lines-1 &&
					    cursor_up) {
						op += 2;
						xp = cursor_up;
					}
					if (xp && instring ==
					    cursor_address) {
						(void) strcat(added, xp);
						op--;
					}
					break;
				/*
				 * Tab used to be in this group too,
				 * because UNIX might expand it to blanks.
				 * We now require that this tab mode be turned
				 * off by any program using this routine,
				 * or using termcap in general, since some
				 * terminals use tab for other stuff, like
				 * nondestructive space.  (Filters like ul
				 * or vcrt will lose, since they can't stty.)
				 * Tab was taken out to get the Ann Arbor
				 * 4080 to work.
				 */
				}

				/* LINTED */
				*outp++ = (char)op;
				(void) pop(&stk);
				break;

			case 'l':
				xp = pop_char_p(&stk);
				push(&stk, strlen(xp));
				break;

			case '%':
				*outp++ = c;
				break;

			/*
			 * %i: shorthand for increment first two parms.
			 * Useful for terminals that start numbering from
			 * one instead of zero(like ANSI terminals).
			 */
			case 'i':
				p1++;
				p2++;
				break;

			/* %pi: push the ith parameter */
			case 'p':
				switch (c = *cp++) {
					case '1':
						push(&stk, p1);
						break;
					case '2':
						push(&stk, p2);
						break;
					case '3':
						push(&stk, p3);
						break;
					case '4':
						push(&stk, p4);
						break;
					case '5':
						push(&stk, p5);
						break;
					case '6':
						push(&stk, p6);
						break;
					case '7':
						push(&stk, p7);
						break;
					case '8':
						push(&stk, p8);
						break;
					case '9':
						push(&stk, p9);
						break;
					default:
#ifdef	DEBUG
						if (outf)
							fprintf(outf, "TPARM:"
							    " bad parm"
							    " number\n");
#endif	/* DEBUG */
						free_stack(&stk);
						return (NULL);
				}
			onrow = (c == '1');
			break;

			/* %Pi: pop from stack into variable i (a-z) */
			case 'P':
				if (*cp >= 'a' && *cp <= 'z') {
					vars[*cp++ - 'a'] = pop(&stk);
				} else {
					if (*cp >= 'A' && *cp <= 'Z') {
						regs[*cp++ - 'A'] =
						    /* LINTED */
						    (short)pop(&stk);
					}
#ifdef	DEBUG
					else if (outf) {
						fprintf(outf, "TPARM: bad"
						    " register name\n");
					}
#endif	/* DEBUG */
				}
				break;

			/* %gi: push variable i (a-z) */
			case 'g':
				if (*cp >= 'a' && *cp <= 'z') {
					push(&stk, vars[*cp++ - 'a']);
				} else {
					if (*cp >= 'A' && *cp <= 'Z') {
						push(&stk, regs[*cp++ - 'A']);
					}
#ifdef	DEBUG
					else if (outf) {
						fprintf(outf, "TPARM: bad"
						    " register name\n");

					}
#endif	/* DEBUG */
				}
				break;

			/* %'c' : character constant */
			case '\'':
				push(&stk, *cp++);
				if (*cp++ != '\'') {
#ifdef	DEBUG
					if (outf)
						fprintf(outf, "TPARM: missing"
						    " closing quote\n");
#endif	/* DEBUG */
					free_stack(&stk);
					return (NULL);
				}
				break;

			/* %{nn} : integer constant.  */
			case '{':
				op = 0;
				sign = 1;
				if (*cp == '-') {
					sign = -1;
					cp++;
				} else
					if (*cp == '+')
						cp++;
				while ((c = *cp++) >= '0' && c <= '9') {
					op = 10 * op + c - '0';
				}
				if (c != '}') {
#ifdef	DEBUG
					if (outf)
						fprintf(outf, "TPARM: missing "
						    "closing brace\n");
#endif	/* DEBUG */
					free_stack(&stk);
					return (NULL);
				}
				push(&stk, (sign * op));
				break;

			/* binary operators */
			case '+':
				op2 = pop(&stk);
				op = pop(&stk);
				push(&stk, (op + op2));
				break;
			case '-':
				op2 = pop(&stk);
				op = pop(&stk);
				push(&stk, (op - op2));
				break;
			case '*':
				op2 = pop(&stk);
				op = pop(&stk);
				push(&stk, (op * op2));
				break;
			case '/':
				op2 = pop(&stk);
				op = pop(&stk);
				push(&stk, (op / op2));
				break;
			case 'm':
				op2 = pop(&stk);
				op = pop(&stk);
				push(&stk, (op % op2));
				break; /* %m: mod */
			case '&':
				op2 = pop(&stk);
				op = pop(&stk);
				push(&stk, (op & op2));
				break;
			case '|':
				op2 = pop(&stk);
				op = pop(&stk);
				push(&stk, (op | op2));
				break;
			case '^':
				op2 = pop(&stk);
				op = pop(&stk);
				push(&stk, (op ^ op2));
				break;
			case '=':
				op2 = pop(&stk);
				op = pop(&stk);
				push(&stk, (op == op2));
				break;
			case '>':
				op2 = pop(&stk);
				op = pop(&stk);
				push(&stk, (op > op2));
				break;
			case '<':
				op2 = pop(&stk);
				op = pop(&stk);
				push(&stk, (op < op2));
				break;
			case 'A':
				op2 = pop(&stk);
				op = pop(&stk);
				push(&stk, (op && op2));
				break; /* AND */
			case 'O':
				op2 = pop(&stk);
				op = pop(&stk);
				push(&stk, (op || op2));
				break; /* OR */

			/* Unary operators. */
			case '!':
				push(&stk, !pop(&stk));
				break;
			case '~':
				push(&stk, ~pop(&stk));
				break;

			/* Sorry, no unary minus, because minus is binary. */

			/*
			 * If-then-else.  Implemented by a low level hack of
			 * skipping forward until the match is found, counting
			 * nested if-then-elses.
			 */
			case '?':	/* IF - just a marker */
				break;

			case 't':	/* THEN - branch if false */
				if (!pop(&stk))
					cp = _branchto(cp, 'e');
				break;

			case 'e':	/* ELSE - branch to ENDIF */
				cp = _branchto(cp, ';');
				break;

			case ';':	/* ENDIF - just a marker */
				break;

			default:
#ifdef	DEBUG
				if (outf)
					fprintf(outf, "TPARM: bad % "
					    "sequence\n");
#endif	/* DEBUG */
				free_stack(&stk);
				return (NULL);
		}
	}
	(void) strcpy(outp, added);
	free_stack(&stk);
	return (result);
}

char	*
_branchto(register char *cp, char to)
{
	register	int	level = 0;
	register	char	c;

	while (c = *cp++) {
		if (c == '%') {
			if ((c = *cp++) == to || c == ';') {
				if (level == 0) {
					return (cp);
				}
			}
			if (c == '?')
				level++;
			if (c == ';')
				level--;
		}
	}
#ifdef	DEBUG
	if (outf)
		fprintf(outf, "TPARM: no matching ENDIF");
#endif	/* DEBUG */
	return (NULL);
}
