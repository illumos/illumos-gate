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
 * Copyright (c) 1997-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>
#include "parser.h"
#include "errlog.h"

static int find_fun(char *key, char *value, char *parentfun);

/*
 * handles the extends clause of the 'function' keyword
 * Returns the number of errors encountered
 * This function is recursive.
 */
int
do_extends(const Meta_info parentM, const Translator_info *T_info, char *value)
{
	static int extends_count = 0;
	char funname[BUFSIZ], filename[MAXPATHLEN], parentfun[BUFSIZ],
	    buf[BUFSIZ], key[20];
	char *ifilename, *f, *p;
	char *localvalue = NULL, *buf2 = NULL;
	FILE *efp;
	Meta_info M;
	int found = 0, errors = 0, ki = 0;
	int retval;
	int scan;

	++extends_count;

	if (extends_count > MAX_EXTENDS) {
		errlog(ERROR, "\"%s\", line %d: Error: Too many levels of "
		    "extends\n", parentM.mi_filename, parentM.mi_line_number);
		++errors;
		goto ret;
	}

	scan = sscanf(value, "%s %s %s %s", funname, buf, filename, parentfun);
	switch (scan) {
	case 0: /* funname not set */
	case 1: /* buf not set, though ignored */
	case 2: /* filename not set */
		errlog(ERROR, "\"%s\", line %d: Error: Couldn't parse "
		    "'data' or 'function' line\n",
		    parentM.mi_filename, parentM.mi_line_number);
		++errors;
		goto ret;
		break;
	case 3:
		(void) strncpy(parentfun, funname, BUFSIZ);
		parentfun[BUFSIZ-1] = '\0';
		break;
	default:
		break;
	}

	/* All info is from parent file - extends */
	M.mi_ext_cnt = extends_count;

	if (T_info->ti_verbosity >= TRACING) {
		errlog(TRACING, "Extending file %s\nExtending function %s\n"
		    "SPEC's from %s\n", filename, parentfun,
		    T_info->ti_dash_I);
	}

	f = pathfind(T_info->ti_dash_I, filename, "f");
	if (f == NULL) {
		errlog(ERROR, "\"%s\", line %d: Error: Unable to find spec "
		    "file \"%s\"\n", parentM.mi_filename,
		    parentM.mi_line_number, filename);
		++errors;
		goto ret;
	}
	ifilename = strdup(f);
	if (ifilename == NULL) {
		errlog(ERROR | FATAL, "Error: strdup() of filename failed\n");
	}
	efp = fopen(ifilename, "r");
	if (efp == NULL) {
		errlog(ERROR, "\"%s\", line %d: Error: Unable to open "
		    "file \"%s\"\n", parentM.mi_filename,
		    parentM.mi_line_number, ifilename);
		free(ifilename);
		++errors;
		goto ret;
	}

	(void) strncpy(M.mi_filename, ifilename, MAXPATHLEN);
	M.mi_line_number = 0;

	/* search for begin function */
	while (M.mi_nlines = readline(&buf2, efp)) {
		M.mi_line_number += M.mi_nlines;

		if (!non_empty(buf2)) {	 /* is line non empty */
			free(buf2);
			buf2 = NULL;
			continue;
		}
		p = realloc(localvalue, sizeof (char)*(strlen(buf2)+1));
		if (p == NULL) {
			errlog(ERROR | FATAL, "Error (do_extends): "
			    "Unable to allocate memory\n");
		}
		localvalue = p;
		split(buf2, key, localvalue);
		if ((found = find_fun(key, localvalue, parentfun))) {
			/* check if architecture matches */
			if (found = arch_match(efp, T_info->ti_archtoken))
				break;
		}
		free(buf2);
		buf2 = NULL;
	}

	if (found) {
		int extends_err = 0;
		static int extends_warn = 0;
		extends_err = check4extends(ifilename, localvalue,
		T_info->ti_archtoken, efp);
		switch (extends_err) {
		case -1:	/* Error */
			errlog(ERROR, "\"%s\", line %d: Error occurred while "
			    "checking for extends clause\n",
			    M.mi_filename, M.mi_line_number);
			++errors;
			/*FALLTHRU*/
		case 0:		/* No Extends */
			break;
		case 1:		/* Extends */
			/*
			 * Warning on more then one level of extends
			 * but only warn once.
			 */
			if (extends_count == 1) {
				extends_warn = 1;
			}
			if ((extends_err = do_extends(M, T_info, localvalue))
			    != 0) {
				if (extends_count == 1) {
					errlog(ERROR, "\"%s\", line %d: "
					    "Error occurred while "
					    "processing 'extends'\n",
					    parentM.mi_filename,
					    parentM.mi_line_number);
				}
				errors += extends_err;
			}
			if (extends_warn == 1 && extends_count == 1) {
				errlog(ERROR, "\"%s\", line %d: "
				    "Warning: \"%s\" does not extend "
				    "a base specification",
				    parentM.mi_filename,
				    parentM.mi_line_number,
				    funname);
			}
			break;
		default:	/* Programmer Error */
			errlog(ERROR | FATAL,
			    "Error: invalid return from "
			    "check4extends: %d\n", extends_err);
		}

		free(buf2);
		buf2 = NULL;

		while (M.mi_nlines = readline(&buf2, efp)) {
			M.mi_line_number += M.mi_nlines;

			if (!non_empty(buf2)) { /* is line non empty */
				free(buf2);
				buf2 = NULL;
				continue;
			}
			p = realloc(localvalue, sizeof (char)*(strlen(buf2)+1));
			if (p == NULL) {
				p = realloc(NULL,
				    sizeof (char)*(strlen(buf2)+1));
				if (p == NULL) {
					errlog(ERROR | FATAL,
					    "Error: unable to "
					    "allocate memory\n");
				}
			}
			localvalue = p;
			split(buf2, key, localvalue);
			ki = interesting_keyword(keywordlist, key);
			switch (ki) {
			case XLATOR_KW_END:
				goto end;
				break;
			case XLATOR_KW_FUNC:
			case XLATOR_KW_DATA:
				errlog(ERROR, "\"%s\", line %d: "
				    "Error: Interface is missing \"end\"\n"
				    "\"%s\", line %d: Error while processing "
				    "%s\n", M.mi_filename, M.mi_line_number,
				    parentM.mi_filename,
				    parentM.mi_line_number, ifilename);
				++errors;
				goto end;
				break;
			case XLATOR_KW_NOTFOUND:
				if (T_info->ti_verbosity >= TRACING)
					errlog(STATUS,
					    "uninteresting keyword: %s\n", key);
				break;
			default:
				retval = xlator_take_kvpair(M, ki, localvalue);
				if (retval) {
					if (T_info->ti_verbosity >= STATUS)
						errlog(STATUS,
						    "Error in "
						    "xlator_take_kvpair\n");
					++errors;
				}
			}
			free(buf2);
			buf2 = NULL;
		}
	} else {
		errlog(ERROR, "\"%s\", line %d: Error: Unable to find "
		    "function %s in %s\n", parentM.mi_filename,
		    parentM.mi_line_number, parentfun, ifilename);
		++errors;
	}
end:
	(void) fclose(efp);
	free(localvalue);
	free(ifilename);
	free(buf2);
ret:
	extends_count--;
	return (errors);
}

/*
 * find_fun()
 *    given a key value pair, and the name of the function you are
 *    searching for in the SPEC source file, this function returns 1
 *    if the beginning of the function in the SPEC source file is found.
 *    returns 0 otherwise.
 */
static int
find_fun(char *key, char *value, char *parentfun)
{
	char pfun[BUFSIZ];

	if (strcasecmp(key, "function") != 0 &&
		strcasecmp(key, "data") != 0) {
		return (0);
	}

	(void) sscanf(value, "%1023s", pfun);

	if (strcmp(pfun, parentfun) == 0) {
		return (1);
	}

	return (0);
}

/*
 * arch_match(FILE *fp, int arch)
 * This function takes a FILE pointer, and an architecture token
 * The FILE pointer is assumed to point at the beginning of a Function
 * or Data specification (specifically at the first line of spec AFTER
 * the Function or Data line)
 * It reads all the way to the "End" line.
 * If it finds an "arch" keyword along the way, it is checked to see if
 * it matches the architecture currently being generated and returns
 * 1 if a match is found.  If a match is not found, it returns a
 * 0. If no "arch" keyword is found, it returns 1.
 *
 * XXX - the algorithm in arch_match is very inefficient. it read through
 * the file to find "arch" and rewinds before returning.
 * Later all the data that was skipped while searching for "arch" may
 * be needed and it is re-read from the disk. It would be nice to just
 * read the data once.
 */
int
arch_match(FILE *fp, int arch)
{
	off_t offset;
	char key[20], buf[BUFSIZ], *buf2 = NULL, *localvalue = NULL, *p;
	int len;
	int has_arch = 0;
	int archset = 0;

	offset = ftello(fp);
	if (offset == -1) {
		errlog(ERROR|FATAL, "Unable to determine file position\n");
	}

	while (fgets(buf, BUFSIZ, fp)) {
		/* replace comments with single whitespace */
		remcomment(buf);

		/* get complete line */
		buf2 = line_to_buf(buf2, buf); /* append buf to buf2 */
		len = strlen(buf);
		if (len > 1) {
			while (buf[len-2] == '\\') {
				if (!fgets(buf, BUFSIZ, fp)) {
					buf2 = line_to_buf(buf2, buf);
					break;
				}
				len = strlen(buf);
				buf2 = line_to_buf(buf2, buf);
			}
		} /* end of 'get complete line' */

		if (!non_empty(buf2)) { /* is line non empty */
			free(buf2);
			buf2 = NULL;
			continue;
		}
		p = realloc(localvalue, sizeof (char)*(strlen(buf2)+1));
		if (p == NULL) {
			p = realloc(NULL,
				sizeof (char)*(strlen(buf2)+1));
			if (p == NULL) {
				errlog(ERROR | FATAL,
					"Error: unable to "
					"allocate memory\n");
			}
		}
		localvalue = p;
		split(buf2, key, localvalue);
		if (strcasecmp(key, "arch") == 0) {
			char *alist = localvalue, *a;
			has_arch = 1;
			while ((a = strtok(alist, " ,\n")) != NULL) {
				archset = arch_strtoi(a);
				if (arch & archset) {
					free(buf2);
					free(p);
					if (fseeko(fp, offset, SEEK_SET) < 0) {
						errlog(ERROR|FATAL,
						    "%s", strerror(errno));
					}
					return (1);
				}
				alist = NULL;
			}
		} else if (strcasecmp(key, "end") == 0) {
			break;
		}
		free(buf2);
		buf2 = NULL;
	}

	free(buf2);
	free(p);

	if (fseeko(fp, offset, SEEK_SET) < 0) {
		errlog(ERROR|FATAL, "%s", strerror(errno));
	}
	if (has_arch == 0)
		return (1);

	return (0);
}
