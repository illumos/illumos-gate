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


#ifndef _ERRMSG_H
#define	_ERRMSG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * errmsg.h
 *	Include file for error message interface.
 *	Command and library version.
 */

#define	errmsg	errtag(__FILE__, __LINE__), errtext

void erraction(int action);
int errafter(int severity, char *format, ...);
void errbefore(int severity, char *format, ...);
int errexit(int e);
void _errmsg(char *tag, int severity, char *format, ...);
void errprefix(char *str);
void errsource(char *str);
void errtag(char *str, int num);
void errtext(int severity, char *format, ...);
void errtofix(char *str);
void errusage(char *format, ...);
char *errstrtok(char *string, char *sepset);
void errverb(char *s);

/* severities  first argument to errbefore(), errafter(), errtext() */
#define	EIGNORE	-1	/* special severity, no message, no action, returns */
#define	EINFO	0
#define	EWARN	1
#define	EERROR	2
#define	EHALT	3

/* special errtext() argument that prints a standard message based on errno */
#define	EERRNO	1

/*
 * actions : returned by errafter() used as an argument to erraction()
 */
#define	EEXIT	100
#define	EABORT  200
#define	ERETURN 300

/* used to set verbosity */
#define	ENO	0
#define	EYES	1
#define	EDEF	2   /* default value -- setting ersyserr */

struct Err {
			/* flags to adjust verbosity */
	char	vbell;	/* ring bell before message */
	char	vprefix;
	char	vsource;	/* source information, including prefix */
	char	vsevmsg;	/* severity message */
	char	vsyserr;	/* system error message, perror() */
	char	vfix;	/* to fix msg */
	char	vtag;
	char	vtext;
			/* message content and context */
	char	*prefix;	/* usually unique per manufacturer */
	char	*envsource;	/* source from ERRSOURCE environment variable */
	char	*source;	/* usually command name */
	int	severity;
	char	**sevmsg;	/* error messages that depend on severity */
	char	*tofix;  /* set by errtofix()  */
	int	tagnum;
	char	*tagstr;
	int	exit;	/* exit(2) code to use if error causes exit */
};

extern struct Err	Err;

#include	<stdio.h>
#include	<sys/types.h>

extern void *zmalloc(int severity, size_t n);
FILE *zfopen(int severity, char *path, char *type);

#endif /* _ERRMSG_H */
