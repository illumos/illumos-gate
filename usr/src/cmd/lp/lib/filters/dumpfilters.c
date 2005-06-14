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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "unistd.h"

#include "lp.h"
#include "filters.h"

static void		q_print ( int , char * );

static char *fw_zDblQte (char *zBuf);

/**
 ** dumpfilters() - WRITE FILTERS FROM INTERNAL STRUCTURE TO FILTER TABLE
 **/

int
dumpfilters(char *file)
{
	register _FILTER	*pf;
	register TEMPLATE	*pt;
	register TYPE		*pty;
	register char		*p,
				*sep;
	register int		fld;
	int fd;

	if ((fd = open_filtertable(file, "w")) < 0)
		return (-1);

	printlist_setup ("", "", LP_SEP, "");
	if (filters) for (pf = filters; pf->name; pf++) {

		for (fld = 0; fld < FL_MAX; fld++) switch (fld) {
		case FL_IGN:
			break;
		case FL_NAME:
			p = pf->name;
			goto String;
		case FL_CMD:
			if ((p = fw_zDblQte (pf->command)) != NULL) {
				(void)fdprintf (fd, "%s%s", FL_SEP, p);
				free (p);
				break;
			}
			/* zDblQte failed so go without quotes */
			p = pf->command;
String:			(void)fdprintf (fd, "%s%s", FL_SEP, (p? p : ""));
			break;
		case FL_TYPE:
			(void)fdprintf(fd, "%s%s", FL_SEP,
				(pf->type == fl_fast? FL_FAST : FL_SLOW));
			break;
		case FL_PTYPS:
			pty = pf->printer_types;
			goto Types;
		case FL_ITYPS:
			pty = pf->input_types;
			goto Types;
		case FL_OTYPS:
			pty = pf->output_types;
Types:			(void)fdprintf(fd, "%s", FL_SEP);
			sep = "";
			if (pty) {
				for (; pty->name; pty++) {
					(void)fdprintf(fd, "%s%s", sep,
						pty->name);
					sep = ",";
				}
			} else
				(void)fdprintf(fd, "%s", NAME_ANY);
			break;
		case FL_PRTRS:
			(void)fdprintf(fd, "%s", FL_SEP);
			if (pf->printers)
				fdprintlist (fd, pf->printers);
			else
				(void)fdprintf(fd, "%s", NAME_ANY);
			break;
		case FL_TMPS:
			(void)fdprintf(fd, "%s", FL_SEP);
			sep = "";
			if ((pt = pf->templates))
				for(; pt->keyword; pt++) {
					(void)fdprintf(fd, "%s%s ", sep,
						pt->keyword);
					q_print(fd, pt->pattern);
					(void)fdprintf(fd, " = ");
					q_print(fd, pt->result);
					sep = ",";
				}
			break;
		}
		(void)fdprintf(fd, FL_END);
	}

	close(fd);
	return (0);
}

/**
 ** q_print() - PRINT STRING, QUOTING SEPARATOR CHARACTERS
 **/

static void
q_print(int fd, char *str)
{
	/*
	 * There are four reasons to quote a character: It is
	 * a quote (backslash) character, it is a field separator,
	 * it is a list separator, or it is a template separator.
	 * "loadfilters()" strips the quote (backslash), but not
	 * in one place.
	 */
	if (!str)
		return;
	while (*str) {
		if (
			*str == '\\'		/* quote reason #1 */
		     || strchr(FL_SEP, *str)	/* quote reason #2 */
		     || strchr(LP_SEP, *str)	/* quote reason #3 */
		     || strchr("=", *str)	/* quote reason #4 */
		)
			fdputc ('\\', fd);
		fdputc (*str, fd);
		str++;
	}
	return;
}

/*********************************************************

	fw_zDblQte	

	Duplicates the given string allocating memory
	using malloc.

	Double quotes are used to encase the string
	and a backslash s put infront of any embedded
	quotes. 

	returns a pointer to the string provided.

	It the function runs out of memory it returns
	NULL.


*/
static char *fw_zDblQte (char *zBuf)
{
	char *zT;
	int i;
	int j;
	int iNewSize;

	/* count the embedded double quotes */
	for (i = j = 0; zBuf[i]; i++) {
		if (zBuf[i] == '"') {
			j++;
		}
	}

	/* 
		Allocate a new buffer 
		add 3 extra bytes for:
			the new leading double quote
			the new trailing double quote
			and the NULL
		add an extra byte for each embedded double quote
	*/
	iNewSize = (strlen (zBuf) + 3 + j);
	if ((zT = malloc (iNewSize)) == NULL) {
		return (NULL); /* buffer overflow */
	}

	j = 0;
	zT[j++] = '"'; /* start with a leading double quote */
	for (i = 0; zBuf[i]; i++) {
		if (zBuf[i] == '"') {
			zT[j++] = '\\';
		} 
		zT[j++] = zBuf[i];
	}
				
	zT[j++] = '"'; /* add a trailing double quote */
	zT[j] = '\0';

	return (zT);
}

