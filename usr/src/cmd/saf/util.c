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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <ctype.h>
#include <sys/types.h>
#include <unistd.h>
#include "extern.h"
#include "misc.h"
#include <sac.h>
#include "structs.h"
#ifdef SAC
#include "msgs.h"
#endif

char	Comment[SIZE];	/* place holder for comments */


/*
 * nexttok - return next token, essentially a strtok, but it can
 *	deal with null fields and strtok can not
 *
 *	args:	str - the string to be examined, NULL if we should
 *		      examine the remembered string
 *		delim - the list of valid delimiters
 *		ros - rest of string flag (1 for rest of string, 0 for
 *		      normal processing)
 */


char *
nexttok(str, delim, ros)
char *str;
register char *delim;
int ros;
{
	static char *savep;	/* the remembered string */
	register char *p;	/* pointer to start of token */
	register char *ep;	/* pointer to end of token */

	p = (str == NULL) ? savep : str ;
	if (ros)
		return(p);
	if (p == NULL)
		return(NULL);
	ep = strpbrk(p, delim);
	if (ep == NULL) {
		savep = NULL;
		return(p);
	}
	savep = ep + 1;
	*ep = '\0';
	return(p);
}


/*
 * parse - parse a line from _sactab.  This routine will return if the parse
 *		was successful, otherwise it will output an error and exit.
 *
 *	args:	p - pointer to the data read from the file
 *		sp - pointer to a structure in which the separated fields
 *		     are placed
 *
 *	A line in the file has the following format:
 *
 *	tag:type:flags:restart_count:command_string	#comment
 */


void
parse(p, sp)
register char *p;
register struct sactab *sp;
{
	char scratch[SIZE];	/* a scratch buffer */

/*
 * get the PM tag
 */

	p = nexttok(p, DELIM, FALSE);
	if (p == NULL) {
# ifdef SAC
		error(E_BADFILE, EXIT);
# else
		Saferrno = E_SAFERR;
		error("_sactab file is corrupt");
# endif
	}
	if (strlen(p) > PMTAGSIZE) {
		p[PMTAGSIZE] = '\0';
# ifdef SAC
		(void) sprintf(scratch, "tag too long, truncated to <%s>", p);
		log(scratch);
# else
		(void) fprintf(stderr, "tag too long, truncated to <%s>", p);
# endif
	}
	(void) strcpy(sp->sc_tag, p);

/*
 * get the PM type
 */

	p = nexttok(NULL, DELIM, FALSE);
	if (p == NULL) {
# ifdef SAC
		error(E_BADFILE, EXIT);
# else
		Saferrno = E_SAFERR;
		error("_sactab file is corrupt");
# endif
	}
	if (strlen(p) > PMTYPESIZE) {
		p[PMTYPESIZE] = '\0';
# ifdef SAC
		(void) sprintf(scratch, "type too long, truncated to <%s>", p);
		log(scratch);
# else
		(void) fprintf(stderr, "type too long, truncated to <%s>", p);
# endif
	}
	(void) strcpy(sp->sc_type, p);

/*
 * get the flags
 */

	p = nexttok(NULL, DELIM, FALSE);
	if (p == NULL) {
# ifdef SAC
		error(E_BADFILE, EXIT);
# else
		Saferrno = E_SAFERR;
		error("_sactab file is corrupt");
# endif
	}
	sp->sc_flags = 0;
	while (*p) {
		switch (*p++) {
		case 'd':
			sp->sc_flags |= D_FLAG;
			break;
		case 'x':
			sp->sc_flags |= X_FLAG;
			break;
		default:
			(void) sprintf(scratch, "Unrecognized flag <%c>", *(p - 1));
# ifdef SAC
			log(scratch);
# else
			Saferrno = E_SAFERR;
			error(scratch);
# endif
			break;
		}
	}

/*
 * get the restart count
 */

	p = nexttok(NULL, DELIM, FALSE);
	if (p == NULL) {
# ifdef SAC
		error(E_BADFILE, EXIT);
# else
		Saferrno = E_SAFERR;
		error("_sactab file is corrupt");
# endif
	}
	sp->sc_rsmax = atoi(p);

/*
 * get the command string
 */

	p = nexttok(NULL, DELIM, FALSE);
	if (p == NULL) {
# ifdef SAC
		error(E_BADFILE, EXIT);
# else
		Saferrno = E_SAFERR;
		error("_sactab file is corrupt");
# endif
	}
	if ((sp->sc_cmd = malloc((unsigned) (strlen(p) + 1))) == NULL) {
# ifdef SAC
		error(E_MALLOC, EXIT);
# else
		Saferrno = E_SAFERR;
		error("malloc failed");
# endif
	}
	(void) strcpy(sp->sc_cmd, p);

/*
 * remember the comment string
 */

	if ((sp->sc_comment = malloc((unsigned) (strlen(Comment) + 1))) == NULL) {
# ifdef SAC
		error(E_MALLOC, EXIT);
# else
		Saferrno = E_SAFERR;
		error("malloc failed");
# endif
	}
	(void) strcpy(sp->sc_comment, Comment);
}


/*
 * trim - remove comments, trim off trailing white space, done in place
 *	args:	p - string to be acted upon
 */

char *
trim(p)
register char *p;
{
	register char *tp;	/* temp pointer */

/*
 * remove comments, if any, but remember them for later
 */

	tp = strchr(p, COMMENT);
	Comment[0] = '\0';
	if (tp) {
		(void) strcpy(Comment, tp + 1);	/* skip the '#' */
		*tp = '\0';
		tp = strchr(Comment, '\n');
		if (tp)
			*tp ='\0';
	}

/*
 * remove trailing whitespace, if any
 */

	for (tp = p + strlen(p) - 1; tp >= p && isspace(*tp); --tp)
		*tp = '\0';
	return(p);
}


/*
 * pstate - put port monitor state into intelligible form for output
 *	SSTATE is only used by sacadm
 *
 *	args:	state - binary representation of state
 */

char *
pstate(unchar state)
{
	switch (state) {
	case NOTRUNNING:
		return("NOTRUNNING");
	case STARTING:
		return("STARTING");
	case ENABLED:
		return("ENABLED");
	case DISABLED:
		return("DISABLED");
	case STOPPING:
		return("STOPPING");
	case FAILED:
		return("FAILED");
	case UNKNOWN:
		return("UNKNOWN");
# ifndef SAC
	case SSTATE:
		return("NO_SAC");
# endif
	default:
# ifdef SAC
		error(E_BADSTATE, EXIT);
# else
		Saferrno = E_SAFERR;
		error("Improper message from SAC\n");
# endif
	}
	/* NOTREACHED */
	return (NULL);
}
