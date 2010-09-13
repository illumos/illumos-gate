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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	Routines to print and adjust options on
 *	error messages.
 */

#include	"errmsg.h"
#include	<stdio.h>
#include	<stdarg.h>
#include	<string.h>
#include	<errno.h>
#include	<stdlib.h>

/*
 *	Internal form, to handle both errtext() and _errmsg()
 */
/* PRINTFLIKE2 */
void
__errtext(int severity, char *format, va_list ap)
{
	int	puterrno = 0;		/* true if an errno msg was printed */

	Err.severity = severity;
	errverb(getenv("ERRVERB"));
	errbefore(Err.severity, format, ap);

	if (Err.severity == EIGNORE)
		goto after;

	if (Err.vbell)
		(void) fputc('\07', stderr);
	if (Err.vprefix && Err.prefix) {
		(void) fputs(Err.prefix, stderr);
		(void) fputc(' ', stderr);
	}
	if (Err.vsource) {
		if (Err.envsource ||
			(Err.envsource = getenv("ERRSOURCE"))) {
			(void) fprintf(stderr, "%s: ", Err.envsource);
		}
	}
	if (Err.vsource && Err.source) {
		(void) fprintf(stderr, "%s: ", Err.source);
	}
	if (Err.vsevmsg) {
		char	**e;

		for (e = Err.sevmsg; *e; e++)
			;
		if (Err.severity < (e - Err.sevmsg))
			(void) fputs(Err.sevmsg[Err.severity], stderr);
		else
			(void) fputs("<UNKNOWN>", stderr);
	}

	if (Err.vtext) {
		if (Err.vsyserr && ((int)format == EERRNO)) {
			(void) fflush(stderr);
			perror("");
			puterrno = 1;
		} else {
			(void) vfprintf(stderr, format, ap);
			(void) fputs("\n", stderr);
		}
	}

	if ((errno && ((int)format != EERRNO)) &&
	    (Err.vsyserr == EYES || (Err.vsyserr ==  EDEF &&
	    (Err.severity == EHALT || Err.severity == EERROR)))) {
		(void) fputc('\t', stderr);
		(void) fflush(stderr);
		perror("");
		puterrno = 1;
	}

	if (Err.vtag) {
		if (Err.tagnum)
			(void) fputc('\t', stderr);
		else
			(void) fputs("HELP FACILITY KEY: ", stderr);
		if (Err.tagstr)
			(void) fputs(Err.tagstr, stderr);
		if (Err.tagnum)
			(void) fprintf(stderr, ", line %d", Err.tagnum);
		if (puterrno)
			(void) fprintf(stderr, "\tUXerrno%d", errno);
		(void) fputc('\n', stderr);
	}

	if ((Err.vtext || Err.vtag) &&
	    Err.vfix && Err.tofix && !Err.tagnum)
		(void) fprintf(stderr, "To Fix:\t%s\n", Err.tofix);
	after:
	erraction(errafter(Err.severity, format, ap));
}


/*
 *	external form, used by errmsg() macro, when tag is not permanently
 *	assigned.
 */
void
errtext(int severity, char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	__errtext(severity, format, ap);
	va_end(ap);
}


/*
 *	external form, used when tag is permanently assigned.
 */
void
_errmsg(char *tag, int severity, char *format, ...)
{
	va_list ap;

	Err.tagstr = tag;
	Err.tagnum = 0;
	va_start(ap, format);
	__errtext(severity, format, ap);
	va_end(ap);
}

void
errverb(char *s)
{
	char	buf[ BUFSIZ ];
	char   *token;
	static char   space[] = ",\t\n";

	if (!s)
		return;
	(void) strcpy(buf, s);
	for (token = errstrtok(buf, space);  token;
		token = errstrtok((char *)0, space)) {
		if (strcmp(token, "nochange") == 0) {
			Err.vbell   =  ENO;
			Err.vtext   =  EYES;
			Err.vsource =  EYES;
			Err.vsyserr =  EYES;
			Err.vtag    =  ENO;
			Err.vsevmsg =  ENO;
			Err.vfix	 =  ENO;
		} else if (strcmp(token, "silent") == 0) {
			Err.vbell   =  ENO;
			Err.vprefix =  ENO;
			Err.vtext   =  ENO;
			Err.vsource =  ENO;
			Err.vsyserr =  ENO;
			Err.vtag    =  ENO;
			Err.vsevmsg =  ENO;
			Err.vfix	 =  ENO;
		} else if (strcmp(token, "verbose") == 0) {
			Err.vbell   =  EYES;
			Err.vprefix =  EYES;
			Err.vtext   =  EYES;
			Err.vsource =  EYES;
			Err.vsyserr =  EYES;
			Err.vtag    =  EYES;
			Err.vsevmsg =  EYES;
			Err.vfix	 =  EYES;
		} else if (strcmp(token, "expert") == 0) {
			Err.vbell   =  ENO;
			Err.vprefix =  ENO;
			Err.vtext   =  EYES;
			Err.vsource =  EYES;
			Err.vsyserr =  EYES;
			Err.vtag    =  ENO;
			Err.vsevmsg =  EYES;
			Err.vfix	 =  ENO;
		} else if (strcmp(token, "bell") == 0) {
			Err.vbell = EYES;
		} else if (strcmp(token, "nobell") == 0) {
			Err.vbell = ENO;
		} else if (strcmp(token, "tag") == 0) {
			Err.vtag = EYES;
		} else if (strcmp(token, "notag") == 0) {
			Err.vtag = ENO;
		} else if (strcmp(token, "text") == 0) {
			Err.vtext = EYES;
		} else if (strcmp(token, "notext") == 0) {
			Err.vtext = ENO;
		} else if (strcmp(token, "tofix") == 0) {
			Err.vfix = EYES;
		} else if (strcmp(token, "notofix") == 0) {
			Err.vfix = ENO;
		} else if (strcmp(token, "syserr") == 0) {
			Err.vsyserr = EYES;
		} else if (strcmp(token, "nosyserr") == 0) {
			Err.vsyserr = ENO;
		} else if (strcmp(token, "defsyserr") == 0) {
			Err.vsyserr = EDEF;
		} else if (strcmp(token, "source")) {
			Err.vsource = EYES;
		} else if (strcmp(token, "nosource")  == 0) {
			Err.vsource = ENO;
		} else if (strcmp(token, "sevmsg") == 0) {
			Err.vsevmsg = EYES;
		} else if (strcmp(token, "nosevmsg") == 0) {
			Err.vsevmsg = ENO;
		} else if (strcmp(token, "prefix") == 0) {
			Err.vprefix = EYES;
		} else if (strcmp(token, "noprefix") == 0) {
			Err.vprefix = ENO;
		}
	}
}
