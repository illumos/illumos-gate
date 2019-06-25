/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */



#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

/* 0 = both upper and lower case */
/* 1 = initial lower case only (build variables) */
/* 2 = initial upper case only (install variables) */
#define	mode(flag, pt)	(!flag || ((flag == 1) && islower(pt[1])) || \
			((flag == 2) && isupper(pt[1])))

/*
 * For next and last functions below, values indicate whether resolution
 * was possible.
 *
 *	0 = all OK - the variable resolved within the established parameters
 *		or it wasn't time for the variable to bind.
 *	1 = parameter did not resolve because there was no value in the
 *		environment or because it was a build variable at install
 *		time.
 */

/*
 * This gets a raw path which may contain shell variables and returns in path
 * a pathname with all appropriate parameters resolved. If it comes in
 * relative, it goes out relative.
 */
int
mappath(int flag, char *path)
{
	char buffer[PATH_MAX];
	char varname[64];
	char *npt, *pt, *pt2, *copy;
	char *token;
	int retvalue = 0;

	copy = buffer;

	/*
	 * For each "/" separated token. If the token contains an environment
	 * variable, then evaluate the variable and insert it into path.
	 */
	for (pt = path; *pt; /* void */) {
		/*
		 * If this is a token and it's an environment variable
		 * properly situated in the path...
		 */
		if ((*pt == '$') && isalpha(pt[1]) &&
		    ((pt == path) || (pt[-1] == '/'))) {
			/* ... and it's the right time to evaluate it... */
			if (mode(flag, pt)) {
				/* replace the parameter with its value. */
				pt2 = varname;
				for (npt = pt+1; *npt && (*npt != '/');
				    /* void */)
					*pt2++ = *npt++;
				*pt2 = '\0';
				/*
				 * At this point EVERY token should evaluate
				 * to a value. If it doesn't, there's an
				 * error.
				 */
				if ((token = getenv(varname)) != NULL &&
				    *token != '\0') {
					/* copy in parameter value */
					while (*token)
						*copy++ = *token++;
					pt = npt;
				} else {
					retvalue = 1;
					*copy++ = *pt++;
				}
			/*
			 * If evaluate time is wrong, determine of this is an
			 * error.
			 */
			} else {
				if (flag == 2) {	/* install-time. */
					/*
					 * ALL variables MUST evaluate at
					 * install time.
					 */
					*copy++ = *pt++;
					retvalue = 1;
				} else if (flag == 1 &&	/* build-time */
				    islower(pt[1])) {
					/*
					 * All build-time variables must
					 * evaluate at build time.
					 */
					retvalue = 1;
					*copy++ = *pt++;
				} else	/* no problem. */
					*copy++ = *pt++;
			}
		/*
		 * If it's a separator, copy it over to the target buffer and
		 * move to the start of the next token.
		 */
		} else if (*pt == '/') {
			while (pt[1] == '/')
				pt++;
			if ((pt[1] == '\0') && (pt > path))
				break;
			*copy++ = *pt++;
		/*
		 * If we're in the middle of a non-parametric token, copy
		 * that character over and try the next character.
		 */
		} else
			*copy++ = *pt++;
	}
	*copy = '\0';
	(void) strcpy(path, buffer);
	return (retvalue);
}

/*
 * This function resolves the path into an absolute path referred to
 * an install root of ir.
 */
void
basepath(char *path, char *basedir, char *ir)
{
	char buffer[PATH_MAX];

	/* For a relative path, prepend the basedir */
	if (*path != '/') {
		(void) strcpy(buffer, path);
		if (ir && *ir) {
			while (*ir)
				*path++ = *ir++;
			if (path[-1] == '/')
				path--;
		}
		if (basedir && *basedir) {
			if (ir && *ir && *basedir != '/')
				*path++ = '/';
			while (*basedir)
				*path++ = *basedir++;
			if (path[-1] == '/')
				path--;
		}
		*path++ = '/';
		(void) strcpy(path, buffer);

	/* For an absolute path, just prepend the install root */
	} else {
		if (ir && *ir) {
			(void) strcpy(buffer, path);
			while (*ir)
				*path++ = *ir++;
			if (path[-1] == '/')
				path--;
			(void) strcpy(path, buffer);
		}
	}
}

/*
 * Evaluate varname and return with environment variables resolved.
 * NOTE: This assumes that varname is a buffer long enough to hold the
 * evaluated string.
 */
int
mapvar(int flag, char *varname)
{
	char	*token;
	int retvalue = 0;

	/* If its a parametric entry beginning with an alpha character. */
	if (*varname == '$' && isalpha(varname[1])) {
		/* ...and it's the right time to evaluate it... */
		if (mode(flag, varname)) {
			/*
			 * then it MUST be possible to evaluate it. If not,
			 * there's an error.
			 */
			if (((token = getenv(&varname[1])) != NULL) &&
			    *token) {
				/* copy token into varname */
				while (*token)
					*varname++ = *token++;
				*varname = '\0';
			} else
				retvalue = 1;
		} else {
			if (flag == 2) /* install-time. */
				/*
				 * ALL variables MUST evaluate at install
				 * time.
				 */
				retvalue = 1;
			else if (flag == 1 &&	/* build-time */
			    islower(varname[1]))
				/*
				 * all build-time variables must evaluate at
				 * build time.
				 */
				retvalue = 1;
		}
	}
	return (retvalue);
}
