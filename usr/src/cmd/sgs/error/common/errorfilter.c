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

#include <stdio.h>
#include <ctype.h>
#include <pwd.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "error.h"

char	*lint_libs[] = {
	IG_FILE1,
	IG_FILE2,
	0
};

extern	char	*processname;

static int lexsort(const void *arg1, const void *arg2);

/*
 *	Read the file ERRORNAME of the names of functions in lint
 *	to ignore complaints about.
 */
void
getignored(char *auxname)
{
	int	i;
	FILE	*fyle;
	char	inbuffer[256];
	int	uid;
	char	filename[128];
	char	*username;
	struct	passwd *passwdentry;

	nignored = 0;
	if (auxname == 0) {	/* use the default */
		if ((username = (char *)getlogin()) == NULL) {
			username = "Unknown";
			uid = getuid();
			if ((passwdentry = getpwuid(uid)) == NULL) {
				return;
			}
		} else {
			if ((passwdentry = getpwnam(username)) == NULL)
				return;
		}
		(void) strcpy(filename, passwdentry->pw_dir);
		(void) strcat(filename, ERRORNAME);
	} else
		(void) strcpy(filename, auxname);
#ifdef FULLDEBUG
	printf("Opening file \"%s\" to read names to ignore.\n",
	    filename);
#endif
	if ((fyle = fopen(filename, "r")) == NULL) {
#ifdef FULLDEBUG
		fprintf(stderr, "%s: Can't open file \"%s\"\n",
		    processname, filename);
#endif
		return;
	}
	/*
	 *	Make the first pass through the file, counting lines
	 */
	for (nignored = 0; fgets(inbuffer, 255, fyle) != NULL; nignored++)
		continue;
	names_ignored = Calloc(nignored+1, sizeof (char *));
	(void) fclose(fyle);
	if (freopen(filename, "r", fyle) == NULL) {
#ifdef FULLDEBUG
		fprintf(stderr, "%s: Failure to open \"%s\" for second read.\n",
		    processname, filename);
#endif
		nignored = 0;
		return;
	}
	for (i = 0; i < nignored && (fgets(inbuffer, 255, fyle) != NULL);
	    i++) {
		names_ignored[i] = strsave(inbuffer);
		(void) substitute(names_ignored[i], '\n', '\0');
	}
	qsort(names_ignored, nignored, sizeof (*names_ignored), lexsort);
#ifdef FULLDEBUG
	printf("Names to ignore follow.\n");
	for (i = 0; i < nignored; i++) {
		printf("\tIgnore: %s\n", names_ignored[i]);
	}
#endif
}

static int
lexsort(const void *arg1, const void *arg2)
{
	char **cpp1 = (char **)arg1;
	char **cpp2 = (char **)arg2;

	return (strcmp(*cpp1, *cpp2));
}

int
search_ignore(char *key)
{
	int	ub, lb;
	int	halfway;
	int	order;

	if (nignored == 0)
		return (-1);
	for (lb = 0, ub = nignored - 1; ub >= lb; /* NULL */) {
		halfway = (ub + lb)/2;
		if ((order = strcmp(key, names_ignored[halfway])) == 0)
			return (halfway);
		if (order < 0)	/* key is less than probe, throw away above */
			ub = halfway - 1;
		else
			lb = halfway + 1;
	}
	return (-1);
}

/*
 *	Tell if the error text is to be ignored.
 *	The error must have been canonicalized, with
 *	the file name the zeroth entry in the errorv,
 *	and the linenumber the second.
 *	Return the new categorization of the error class.
 */
Errorclass
discardit(Eptr errorp)
{
	int	language;
	int	i;
	Errorclass	errorclass = errorp->error_e_class;

	switch (errorclass) {
	case C_SYNC:
	case C_NONSPEC:
	case C_UNKNOWN:
		return (errorclass);
	default:
		break;
	}
	if (errorp->error_lgtext < 2) {
		return (C_NONSPEC);
	}
	language = errorp->error_language;
	if (language == INLINT) {
		if (errorclass != C_NONSPEC) {	/* no file */
			for (i = 0; lint_libs[i] != 0; i++) {
				if (strcmp(errorp->error_text[0],
				    lint_libs[i]) == 0) {
					return (C_DISCARD);
				}
			}
		}
		/*
		 * check if the argument to the error message
		 * is to be ignored
		 */
		if (ispunct(lastchar(errorp->error_text[2])))
			clob_last(errorp->error_text[2], '\0');
		if (search_ignore(
		    errorp->error_text[errorclass == C_NONSPEC ? 0 : 2]) >= 0) {
			return (C_NULLED);
		}
	}
	return (errorclass);
}
