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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

/* Copyright (c) 1979 Regents of the University of California */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include	<sys/types.h>
#include	<ctype.h>
#include	"curses_inc.h"

/*
 * Put the character string cp out, with padding.
 * The number of affected lines is affcnt, and the routine
 * used to output one character is outc.
 */
static	char	*ocp;

static	char	*
_tpad(char *, int, int (*)(char));

static	char	*
_tpad(char *cp, int affcnt, int (*outc)(char x))
{
	int	delay = 0;
	char	*icp = cp;
	int	ignorexon = 0, doaffcnt = 0;

#ifdef	_VR2_COMPAT_CODE
	/*
	 * Why is this here?
	 * Because mandatory padding must be used for flash_screen
	 * and bell. We cannot force users to code mandatory padding
	 * in their terminfo entries, as that would break compatibility.
	 * We therefore, do it here.
	 *
	 * When compatibility is to be broken, it will go away
	 * and users will be informed that they MUST use mandatory
	 * padding for flash and bell.
	 */
	if (ocp == bell || ocp == flash_screen)
		ignorexon = TRUE;
#endif	/* _VR2_COMPAT_CODE */

	/* Eat initial $< */
	cp += 2;

	/* Convert the number representing the delay. */
	if (isdigit(*cp)) {
		do
			delay = delay * 10 + *cp++ - '0';
		while (isdigit(*cp));
	}
	delay *= 10;
	if (*cp == '.') {
		cp++;
		if (isdigit(*cp))
			delay += *cp - '0';
	/* Only one digit to the right of the decimal point. */
		while (isdigit(*cp))
			cp++;
	}

	/*
	 * If the delay is followed by a `*', then
	 * multiply by the affected lines count.
	 * If the delay is followed by a '/', then
	 * the delay is done irregardless of xon/xoff.
	 */
	/*CONSTCOND*/
	while (TRUE) {
		if (*cp == '/')
			ignorexon = TRUE;
		else
			if (*cp == '*')
				doaffcnt = TRUE;
			else
				break;
		cp++;
	}
	if (doaffcnt)
		delay *= affcnt;
	if (*cp == '>')
		cp++;	/* Eat trailing '>' */
	else {
	/*
	 * We got a "$<" with no ">".  This is usually caused by
	 * a cursor addressing sequence that happened to generate
	 * $ < .  To avoid an infinite loop, we output the $ here
	 * and pass back the rest.
	 */
		(*outc)(*icp++);
		return (icp);
	}

	/*
	 * If no delay needed, or output speed is
	 * not comprehensible, then don't try to delay.
	 */
	if (delay == 0)
		return (cp);
	/*
	 * Let handshaking take care of it - no extra cpu load from pads.
	 * Also, this will be more optimal since the pad info is usually
	 * worst case.  We only use padding info for such terminals to
	 * estimate the cost of a capability in choosing the cheapest one.
	 * Some capabilities, such as flash_screen, really want the
	 * padding irregardless.
	 */
	if (xon_xoff && !ignorexon)
		return (cp);
	(void) _delay(delay, outc);
	return (cp);
}

int
tputs(char *cp, int affcnt, int (*outc)(char))
{
	if (cp != 0) {
		ocp = cp;

		/* The guts of the string. */
		while (*cp)
			if (*cp == '$' && cp[1] == '<')
				cp = _tpad(cp, affcnt, outc);
			else
				(*outc)(*cp++);
	}
	return (OK);
}
