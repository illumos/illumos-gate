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
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 *
 *
 *	Copyright (c) 1998 by Sun Microsystems, Inc.
 *	All rights reserved.
 */

#include <ctype.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <thread.h>
#include "elf_dem.h"
#include "String.h"
#include "msg.h"

/*
 * The variable "hold" contains the pointer to the array initially
 * handed to demangle.  It is returned if it is not possible to
 * demangle the string.  NULL is returned if a memory allocation
 * problem is encountered.  Thus one can do the following:
 *
 * char *mn = "Some mangled name";
 * char *dm = mangle(mn);
 * if (dm == NULL)
 *	printf("allocation error\n");
 * else if (dm == mn)
 * 	printf("name could not be demangled\n");
 * else
 *	printf("demangled name is: %s\n",dm);
 */
static char *hold;

/*
 * this String is the working buffer for the demangle
 * routine.  A pointer into this String is returned
 * from demangle when it is possible to demangle the
 * String.  For this reason, the pointer should not
 * be saved between calls of demangle(), nor freed.
 */
static String *s = 0;

static int
getint(char **c)
{
	return (strtol(*c, c, 10));
}

/*
 * If a mangled name has a __
 * that is not at the very beginning
 * of the string, then this routine
 * is called to demangle that part
 * of the name.  All overloaded functions,
 * and class members fall into this category.
 *
 * c should start with two underscores followed by a non-zero digit or an F.
 */
static char *
second(char *c)
{
	int n;
	if (strncmp(c, MSG_ORIG(MSG_STR_DBLUNDBAR), 2))
		return (hold);
	c += 2;

	if (!(isdigit(*c) || *c == 'F'))
		return (hold);

	if (isdigit(*c)) {
		/* a member */
		n = getint(&c);
		if (n == 0 || (int)strlen(c) < n)
			return (hold);
		s = prep_String(MSG_ORIG(MSG_STR_DBLCOL), s);
		s = nprep_String(c, s, n);
		c += n;
	}
	if (*c == 'F') {
		/* an overloaded function */
		switch (*++c) {
		case '\0':
			return (hold);
		case 'v':
			s = app_String(s, MSG_ORIG(MSG_STR_OPENCLOSEPAR));
			break;
		default:
			if (demangle_doargs(&s, c) < 0)
				return (hold);
		}
	}
	return (PTR(s));
}

char *
demangle(char *c)
{
	volatile int i = 0;
	extern jmp_buf jbuf;
	static mutex_t	mlock = DEFAULTMUTEX;

	(void) mutex_lock(&mlock);

	if (setjmp(jbuf)) {
		(void) mutex_unlock(&mlock);
		return (0);
	}

	hold = c;
	s = mk_String(s);
	s = set_String(s, MSG_ORIG(MSG_STR_EMPTY));

	if (c == 0 || *c == 0) {
		c = hold;
		(void) mutex_unlock(&mlock);
		return (c);
	}

	if (strncmp(c, MSG_ORIG(MSG_STR_DBLUNDBAR), 2) != 0) {
		/*
		 * If a name does not begin with a __
		 * but it does contain one, it is either
		 * a member or an overloaded function.
		 */
		while (c[i] && strncmp(c+i, MSG_ORIG(MSG_STR_DBLUNDBAR), 2))
			i++;
		if (c[i]) {
			/* Advance to first non-underscore */
			while (c[i+2] == '_')
				i++;
		}
		if (strncmp(c+i, MSG_ORIG(MSG_STR_DBLUNDBAR), 2) == 0) {
			/* Copy the simple name */
			s = napp_String(s, c, i);
			/* Process the signature */
			c = second(c+i);
			(void) mutex_unlock(&mlock);
			return (c);
		} else {
			c = hold;
			(void) mutex_unlock(&mlock);
			return (c);
		}
	} else {
		const char	*x;
		int		oplen;

		c += 2;

		/*
		 * For automatic variables, or internal static
		 * variables, a __(number) is prepended to the
		 * name.  If this is encountered, strip this off
		 * and return.
		 */
		if (isdigit(*c)) {
			while (isdigit(*c))
				c++;
			(void) mutex_unlock(&mlock);
			return (c);
		}

		/*
		 * Handle operator functions -- this
		 * automatically calls second, since
		 * all operator functions are overloaded.
		 */
		if (x = findop(c, &oplen)) {
			s = app_String(s, MSG_ORIG(MSG_STR_OPERATOR_1));
			s = app_String(s, x);
			c += oplen;
			c = second(c);
			(void) mutex_unlock(&mlock);
			return (c);
		}

		/*
		 * Operator cast does not fit the mould
		 * of the other operators.  Its type name
		 * is encoded.  The cast function must
		 * take a void as an argument.
		 */
		if (strncmp(c, MSG_ORIG(MSG_STR_OP), 2) == 0) {
			int r;
			s = app_String(s, MSG_ORIG(MSG_STR_OPERATOR_2));
			c += 2;
			r = demangle_doarg(&s, c);
			if (r < 0) {
				c = hold;
				(void) mutex_unlock(&mlock);
				return (c);
			}
			c += r;
			c = second(c);
			(void) mutex_unlock(&mlock);
			return (c);
		}

		/*
		 * Constructors and Destructors are also
		 * a special case of operator name.  Note
		 * that the destructor, while overloaded,
		 * must always take the same arguments --
		 * none.
		 */
		if ((*c == 'c' || *c == 'd') &&
		    strncmp(c+1, MSG_ORIG(MSG_STR_TDBLUNDBAR), 3) == 0) {
			int n;
			char *c2 = c+2;
			char cx = c[0];
			c += 4;
			n = getint(&c);
			if (n == 0) {
				c = hold;
				(void) mutex_unlock(&mlock);
				return (c);
			}
			s = napp_String(s, c, n);
			if (cx == 'd')
				s = prep_String(MSG_ORIG(MSG_STR_TILDE), s);
			c = second(c2);
			(void) mutex_unlock(&mlock);
			return (c);
		}
		c = hold;
		(void) mutex_unlock(&mlock);
		return (c);
	}
}
