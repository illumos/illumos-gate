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
 * Copyright (c) 1995-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * tparm.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mrotice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/tparm.c 1.2 1995/08/31 19:44:03 danv Exp $";
#endif
#endif

/*l
 * Substitute the given parameters into the given string by the
 * following rules (taken from terminfo(5)):
 *
 * Cursor addressing and other strings  requiring  parameters
 * in the terminal are described by a parameterized string
 * capability, with like escapes %x in  it.   For  example,  to
 * address  the  cursor, the cup capability is given, using two
 * parameters: the row and column to  address  to.   (Rows  and
 * columns  are  numbered  from  zero and refer to the physical
 * screen visible to the user, not to any  unseen  memory.)  If
 * the terminal has memory relative cursor addressing, that can
 * be indicated by
 *
 * The parameter mechanism uses  a  stack  and  special  %
 * codes  to manipulate it.  Typically a sequence will push one
 * of the parameters onto the stack and then print it  in  some
 * format.  Often more complex operations are necessary.
 *
 *      The % encodings have the following meanings:
 *
 *      %%        outputs `%'
 *      %d        print pop() like %d in printf()
 *      %2d       print pop() like %2d in printf()
 *      %02d      print pop() like %02d in printf()
 *      %3d       print pop() like %3d in printf()
 *      %03d      print pop() like %03d in printf()
 *      %c        print pop() like %c in printf()
 *      %s        print pop() like %s in printf()
 *
 *      %p[1-9]   push ith parm
 *      %P[a-z]   set variable [a-z] to pop()
 *      %g[a-z]   get variable [a-z] and push it
 *      %'c'      push char constant c
 *      %{nn}     push integer constant nn
 *
 *      %+ %- %* %/ %m
 *                arithmetic (%m is mod): push(pop() op pop())
 *      %& %| %^  bit operations: push(pop() op pop())
 *      %= %> %<  logical operations: push(pop() op pop())
 *      %! %~     unary operations push(op pop())
 *      %i        add 1 to first two parms (for ANSI terminals)
 *
 *      %? expr %t thenpart %e elsepart %;
 *                if-then-else, %e elsepart is optional.
 *                else-if's are possible ala Algol 68:
 *                %? c1 %t b1 %e c2 %t b2 %e c3 %t b3 %e c4 %t b4 %e b5 %;
 *
 * For those of the above operators which are binary and not commutative,
 * the stack works in the usual way, with
 * 		%gx %gy %m
 * resulting in x mod y, not the reverse.
 */

#include <private.h>
#include <ctype.h>
#include <stdarg.h>
#include <string.h>
#include <m_ord.h>

#define STACKSIZE	20
#define npush(x)	if (stack_ptr < STACKSIZE) {\
				stack[stack_ptr].num = x; stack_ptr++; }
#define npop()	   	(stack_ptr > 0 ? stack[--stack_ptr].num : 0)
#define spop()	   	(stack_ptr > 0 ? stack[--stack_ptr].str : (char *) 0)

typedef union {
	unsigned int num;
	char* str;
} stack_frame;

static char buffer[256];

/*f
 * Do parameter substitution.
 */
const char *
#ifdef STDARG_VERSION
tparm(const char *string, ...)
#else
tparm(string, p1, p2, p3, p4, p5, p6, p7, p8, p9)
const char *string;
long p1, p2, p3, p4, p5, p6, p7, p8, p9;
#endif /* STDARG_VERSION */
{
	char len;
	long parm[9];
	va_list vparm;
	int varyable[26];
	int number, level, x, y;
	int stack_ptr = 0;
	stack_frame stack[STACKSIZE];
	char *bufptr = buffer;

#ifdef STDARG_VERSION
	/* We've had too many problems porting this particular module
	 * to different compilers and machines, in particular RISC,
	 * that we can't make clever assumptions about how variable
	 * arguments might be handled.  The best solution is the
	 * slow and simple one.
	 *
	 * We read the va_args into an array, since the tparm format
	 * string may want to address parameters in arbitrary order.
	 */
	va_start(vparm, string);
	for (x = 0; x < 9; ++x)
		parm[x] = va_arg(vparm, long);
	va_end(vparm);
#else
	parm[0] = p1;
	parm[1] = p2;
	parm[2] = p3;
	parm[3] = p4;
	parm[4] = p5;
	parm[5] = p6;
	parm[6] = p7;
	parm[7] = p8;
	parm[8] = p9;
#endif /* STDARG_VERSION */

#ifdef M_CURSES_TRACE
	__m_trace(
		"tparm(\"%s\", %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld)",
		string, parm[0],
		parm[1], parm[2], parm[3], parm[4],
		parm[5], parm[6], parm[7], parm[8]
	);
#endif

	while (*string) {
		if (*string != '%')
			*(bufptr++) = *string;
		else {
			string++;
			switch (*string) {
			default:
				break;
			case '%':
				*(bufptr++) = '%';
				break;
			case 'd':
				bufptr += sprintf(bufptr, "%ld", npop());
				break;
			case '0':
				len = -(*++string - '0');
				if ((len == (char)-2 || len == (char)-3)
				&& *++string == 'd')
					bufptr += sprintf(
						bufptr, "%0*ld", len, npop()
					);
				break;
			case '2':
			case '3':
				len = *string++ - '0';
				if (*string == 'd')
					bufptr += sprintf(
						bufptr, "%*ld", len, npop()
					);
				break;
			case 'c':
				*(bufptr++) = (char) npop();
				break;
			case 's':
				strcpy(bufptr, spop());
				bufptr += strlen(bufptr);
				break;
			case 'p':
				string++;
				if ('1' <= *string && *string <= '9')
					npush(parm[*string - '1']);
				break;
			case 'P': {
				int i;
				int	c;
				++string;
				c = (int)*string;
				i = m_ord(c);
				if (0 < i)
					varyable[i-1] = npop();
				break;
			}
			case 'g': {
				int i;
				int	c;
				++string;
				c = (int)*string;
				i = m_ord(c);
				if (0 < i)
					npush(varyable[i-1]);
				break;
			}
			case '\'':
				string++;
				npush(*string);
				string++;
				break;
			case '{':
				number = 0;
				string++;
				while ('0' <= *string && *string <= '9') {
					number = number * 10 + *string - '0';
					string++;
				}
				npush(number);
				break;
			case '+':
				y = npop();
				x = npop();
				npush(x + y);
				break;
			case '-':
				y = npop();
				x = npop();
				npush(x - y);
				break;
			case '*':
				y = npop();
				x = npop();
				npush(x * y);
				break;
			case '/':
				y = npop();
				x = npop();
				npush(x / y);
				break;
			case 'm':
				y = npop();
				x = npop();
				npush(x % y);
				break;
			case '&':
				y = npop();
				x = npop();
				npush(x & y);
				break;
			case '|':
				y = npop();
				x = npop();
				npush(x | y);
				break;
			case '^':
				y = npop();
				x = npop();
				npush(x ^ y);
				break;
			case '=':
				y = npop();
				x = npop();
				npush(x == y);
				break;
			case '<':
				y = npop();
				x = npop();
				npush(x < y);
				break;
			case '>':
				y = npop();
				x = npop();
				npush(x > y);
				break;
			case '!':
				x = npop();
				npush(!x);
				break;

			case '~':
				x = npop();
				npush(~x);
				break;
			case 'i':
				parm[0]++;
				parm[1]++;
				break;
			case '?':
				break;
			case 't':
			    x = npop();
			    if (x) {
				/* do nothing; keep executing */
			    } else {
				/* scan forward for %e or %; at
				 * level zero */
				string++;
				level = 0;
				while (*string) {
		 		    if (*string == '%') {
					string++;
					if (*string == '?')
					    level++;
					else if (*string == ';') {
					    if (level <= 0)
						break;
					    level--;
					} else if (*string == 'e' && level == 0)
					    break;
				    }
				    if (*string)
					string++;
				}
			    }
			    break;
			case 'e':
				/* scan forward for a %; at level zero */
				string++;
				level = 0;
				while (*string) {
					if (*string == '%') {
						string++;
						if (*string == '?')
							level++;
						else if (*string == ';') {
							if (level <= 0)
								break;
							level--;
						}
					}
					if (*string)
						string++;
				}
				break;
			case ';':
				break;

			} /* endswitch (*string) */
		} /* endelse (*string == '%') */
		if (*string == '\0')
			break;
		string++;
	} /* endwhile (*string) */
	*bufptr = '\0';

	return __m_return_pointer("tparm", buffer);
}
