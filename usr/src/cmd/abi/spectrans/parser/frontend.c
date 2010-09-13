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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>
#include <dirent.h>
#include <libgen.h>
#include <sys/param.h>
#include <errno.h>

#include "parser.h"
#include "errlog.h"

static char const *ARCH_I386 = "i386";
static char const *ARCH_SPARC = "sparc";
static char const *ARCH_SPARCV9 = "sparcv9";
static char const *ARCH_IA64 = "ia64";
static char const *ARCH_AMD64 = "amd64";
static char const *ARCH_ALL = "all";

static int dofiles(const Translator_info *);
static int read_spec(const Translator_info *, char *);

static int Curlineno;

xlator_keyword_t *keywordlist;

/*
 * frontend entry point
 * returns the number of errors encountered
 */
int
frontend(const Translator_info *T_info)
{
	int retval, i = 0, errors = 0;

	keywordlist = xlator_init(T_info);
	if (keywordlist == NULL) {
		errlog(ERROR, "Error: Unable to get keywordlist\n");
		return (1);
	}

	if (T_info->ti_verbosity >= STATUS) {
		errlog(STATUS, "interesting keywords:\n");
		while (keywordlist[i].key != NULL) {
			errlog(STATUS,  "\t%s\n", keywordlist[i].key);
			++i;
		};
	}

	retval = xlator_startlib(T_info->ti_liblist);
	switch (retval) {
	case XLATOR_SKIP:
		if (T_info->ti_verbosity >= STATUS)
			errlog(STATUS,  "Skipping %s\n", T_info->ti_liblist);
		retval = 0;
		break;

	case XLATOR_NONFATAL:
		++errors;
		retval = 0;
		break;

	case XLATOR_SUCCESS:
		retval = dofiles(T_info);
		errors += retval;
		if ((retval = xlator_endlib()) != XLATOR_SUCCESS)
			++errors;
		retval = 0;
		break;

	default:
		errlog(ERROR | FATAL,
		    "Error: Invalid return code from xlator_startlib()\n");
		exit(1);
	}

	if ((retval = xlator_end()) != XLATOR_SUCCESS)
		++errors;

	return (errors);
}

/*
 * dofiles(const Translator_info *T_info);
 *    iterate through files specified in the command line and process
 *    them one by one
 * requires spec files to have a ".spec" suffix
 * returns the number of errors;
 */
static int
dofiles(const Translator_info *T_info)
{
	int nfiles, flen, findex, retval = 0, errors = 0;

	nfiles = T_info->ti_nfiles;

	for (findex = 0; findex < nfiles; ++findex) {
		flen = strlen(filelist[findex]);
		if ((flen <= 5) ||
			strcmp(&filelist[findex][flen-5], ".spec") != 0) {
			errlog(ERROR,
			    "Error: File specified does not have the "
			    ".spec extension: %s\n", filelist[findex]);
			++errors;
			continue;
		};
		retval = read_spec(T_info, filelist[findex]);
		errors += retval;
	}
	return (errors);
}

/*
 * read_spec -
 *   Given a filename, this function will reads the spec file to
 *   recognize keywords which it passes along with the corresponding
 *   value to the back-end translator to process. The following
 *   back-end interfaces are called:
 *	xlator_startfile
 *	xlator_start_if
 *	xlator_take_kvpair
 *	xlator_end_if
 *	xlator_endfile
 */
static int
read_spec(const Translator_info *T_info, char *spec_filename)
{
	FILE *spec_fp;
	Meta_info meta_info;
	char key[BUFSIZ], *value = NULL, *p = NULL;
	char *buf2 = NULL;
	int retval = 0, errors = 0, ki = 0;	/* keyword indicator */
	int start_if_fail = 0, skip_if = 0;
	int extends_err = 0;

	meta_info.mi_ext_cnt = 0; /* All info is non-extends */
	meta_info.mi_flags = 0;

	retval = xlator_startfile(spec_filename);

	switch (retval) {
	case XLATOR_SKIP:
		if (T_info->ti_verbosity >= WARNING)
			errlog(WARNING, "Warning: Skipping %s\n",
			    spec_filename);
		return (errors);

	case XLATOR_NONFATAL:
		errlog(ERROR, "Error in xlator_startfile\n");
		++errors;
		return (errors);

	case XLATOR_SUCCESS:
		break;

	default:
		errlog(ERROR,
		    "Error: Invalid return code from xlator_startfile()\n");
		++errors;
		return (errors);
	};

	/* file processing */
	spec_fp = fopen(spec_filename, "r");
	if (spec_fp == NULL) {
		errlog(ERROR,  "Error: Unable to open spec file %s: %s\n",
		    spec_filename, strerror(errno));
		++errors;
		return (errors);
	}

	(void) strncpy(meta_info.mi_filename, spec_filename, BUFSIZ);
	meta_info.mi_line_number = 0;
	Curlineno = meta_info.mi_line_number;
	while (meta_info.mi_nlines = readline(&buf2, spec_fp)) {
		meta_info.mi_line_number += meta_info.mi_nlines;
		Curlineno = meta_info.mi_line_number;
		if (!non_empty(buf2)) {
			free(buf2);
			buf2 = NULL;
			continue;
		}
		p = realloc(value, sizeof (char)*(strlen(buf2)+1));
		if (p == NULL) {
			errlog(ERROR | FATAL,
			    "Error: Unable to allocate memory for "
			    "value: %d\n", errno);
		}
		value = p;
		split(buf2, key, value);
		ki = interesting_keyword(keywordlist, key);
		switch (ki) {
		case XLATOR_KW_FUNC:	 /* Function keyword */
		case XLATOR_KW_DATA:	 /* Data keyword */
			meta_info.mi_extended = 0;
			retval = xlator_start_if(meta_info, ki, value);
			switch (retval) {
			case XLATOR_FATAL: /* FATAL ERROR */
				if (T_info->ti_verbosity >= STATUS) {
					errlog(STATUS,
					    "Error in xlator_start_if: ");
				}
				++errors;
				return (errors);
			case XLATOR_NONFATAL: /* NON-FATAL ERROR */
				if (T_info->ti_verbosity >= STATUS)
					errlog(STATUS,
					    "Error in xlator_start_if\n");
				++errors;
				start_if_fail = 1;
				break;
			case XLATOR_SUCCESS: /* OK */
				start_if_fail = 0;
				extends_err = check4extends(spec_filename,
				    value, T_info->ti_archtoken, spec_fp);
				switch (extends_err) {
				case -1:	/* Error */
					errlog(ERROR, "\"%s\", line %d: "
					    "Error occurred while "
					    "checking for extends clause\n",
					    spec_filename, Curlineno);
					++errors;
					/*FALLTHRU*/
				case 0:		/* No Extends */
					break;
				case 1:		/* Extends */
					meta_info.mi_extended = 1;
					extends_err = do_extends(meta_info,
					    T_info, value);
					if (extends_err) {
						errors += extends_err;
					}
					break;
				default:	/* Programmer Error */
					errlog(ERROR | FATAL,
					    "Error: invalid return from "
					    "check4extends %d\n", extends_err);
				}
				break;
			case XLATOR_SKIP: /* SKIP */
				if (T_info->ti_verbosity >= WARNING)
					errlog(WARNING, "Warning: Skipping "
					    "interface %s\n", value);
				skip_if = 1;
				start_if_fail = 0;
				break;
			default:
				/* Invalid Return */
				errlog(ERROR | FATAL,
				    "Error:  Invalid return code "
				    "from xlator_start_if (): %d\n", retval);
			}
			break;
		case XLATOR_KW_END: /* END keyword */
			if (start_if_fail == 0 && skip_if == 0) {
				retval = xlator_end_if(meta_info, value);
				if (retval)
					++errors;
			}
			skip_if = 0;
			break;
		case XLATOR_KW_NOTFOUND:
			if (T_info->ti_verbosity >= TRACING)
				errlog(TRACING, "uninteresting keyword: %s\n",
				    key);
			break;
		default:
			if (skip_if == 0 && start_if_fail == 0) {
				retval = xlator_take_kvpair(meta_info,
				    ki, value);
				if (retval) {
					if (T_info->ti_verbosity >= STATUS)
						errlog(STATUS, "Error in "
						    "xlator_take_kvpair\n");
					++errors;
				}
			}
		}
		free(buf2);
		buf2 = NULL;
	}

	if ((retval = xlator_endfile()) != XLATOR_SUCCESS) {
		if (T_info->ti_verbosity >= STATUS)
			errlog(STATUS, "Error in xlator_endfile\n");
		++errors;
	}
	free(p);
	(void) fclose(spec_fp);
	return (errors);
}

/*
 * interesting_keyword(char **keywordlist, const char *key) {
 *   returns the token associated with key if key is found in keywordlist
 *   returns XLATOR_KW_NOTFOUND if key is NOT found in keywordlist
 *   "Function" and "End" are always interesting, return XLATOR_KW_FUNC
 *   and XLATOR_KW_DATA respectively;
 *   "End" is always interesting, return XLATOR_KW_END;
 *
 */
int
interesting_keyword(xlator_keyword_t *keywordlist, const char *key)
{
	int i = 0;

	if (strcasecmp(key, "data") == 0) {
		return (XLATOR_KW_DATA);
	}
	if (strcasecmp(key, "function") == 0) {
		return (XLATOR_KW_FUNC);
	}

	if (strcasecmp(key, "end") == 0)
		return (XLATOR_KW_END);

	while (keywordlist[i].key != NULL) {
		if (strcasecmp(keywordlist[i].key, key) == 0)
			return (keywordlist[i].token);
		++i;
	}
	return (XLATOR_KW_NOTFOUND);
}

/*
 * line_to_buf(char *dest, const char *src) {
 *    appends src to dest, dynamically increasing the size of dest.
 *    replaces the trailing '\' continuation character with a space.
 *
 * if src is continuation of dest, dest != NULL, and
 * the last character in dest before the newline must be a `\'
 * if src is not continuation of dest, then dest must be NULL
 */
char *
line_to_buf(char *dest, const char *src)
{
	int slen = strlen(src);
	int dlen;

	if (dest == NULL) {
		/* We're being called for the first time */
		dest = malloc(sizeof (char) * (slen + 1));
		if (dest == NULL) {
			errlog(ERROR | FATAL,
			    "Error: Unable to allocate memory for dest\n");
		}
		(void) strcpy(dest, src);
		return (dest);
	}

	dlen = strlen(dest);

	dest = realloc(dest, (size_t)(sizeof (char) * (dlen+slen+1)));
	if (dest == NULL) {
		errlog(ERROR | FATAL,
		    "Error: Unable to allocate memory for dest\n");
	}

	if (dlen > 1) {
		/*
		 * remove continuation character
		 * we replace the '\' from the previous line with a space
		 */
		if (dest[dlen-2] == '\\') {
			dest[dlen-2] = ' ';
		}
	}

	/* join the two strings */
	(void) strcat(dest, src);

	return (dest);
}

/*
 * non_empty(const char *str)
 * assumes str is non null
 * checks if str is a non empty string
 * returns 1 if string contains non whitespace
 * returns 0 if string contains only whitespace
 */
int
non_empty(const char *str)
{
	while (*str != '\0') {
		if (!isspace(*str))
			return (1);
		++str;
	};
	return (0);
}

/*
 * split(const char *line, char *key, char *value);
 * splits the line into keyword (key) and value pair
 */
void
split(const char *line, char *key, char *value)
{
	char *p;

	p = (char *)line;

	/* skip leading whitespace */
	while (isspace(*p)&& *p != '\0')
		++p;

	/* copy keyword from line into key */
	while (!isspace(*p) && *p != '\0')
		*key++ = *p++;

	*key = '\0';

	/* skip whitespace */
	while (isspace(*p) && *p != '\0')
		p++;

	(void) strcpy(value, p);

}

/*
 * check4extends(char *filename, char *value, int arch, FILE *fp)
 * if no arch keyword is found or there is a MATCHING arch keyword
 *     returns 1 if value is of the form "data|function name extends"
 *          -1 for error
 *          0  no other keyword after the function name
 * else
 *     return 0
 *
 * filename is used only for error reporting
 */
int
check4extends(const char *filename, const char *value, int arch, FILE *fp)
{
	char fun[BUFSIZ];
	char extends[BUFSIZ];
	int n;

	if (arch_match(fp, arch)) {
		split(value, fun, extends);
		n = strlen(extends);
		if (extends[n-1] == '\n')
			extends[n-1] = '\0';
		if (strncasecmp("extends", extends, 7) == 0) {
			return (1);
		} else {
			if (*extends != '\0') {
				errlog(ERROR, "\"%s\", line %d: Error: "
				    "Trailing garbage after function name\n",
				    filename, Curlineno);
				return (-1);
			}
		}
	}
	return (0);
}

/*
 * remcomment (char *buf)
 * replace comments with single whitespace
 */
/* XXX: There is currently no way to escape a comment character */
void
remcomment(char const *buf)
{
	char *p;
	p = strchr(buf, '#');
	if (p) {
		*p = ' ';
		*(p+1) = '\0';
	}
}

/*
 * arch_strtoi()
 *
 * input: string
 * return: XLATOR_I386 if string == ARCH_I386
 *         XLATOR_SPARC if string == ARCH_SPARC
 *         XLATOR_SPARCV9 if string == ARCH_SPARCV9
 *         XLATOR_IA64 if string == ARCH_IA64
 *         XLATOR_AMD64 if string == ARCH_AMD64
 *         XLATOR_ALLARCH if string == ARCH_ALL
 *         0 if outside the known set {i386, sparc, sparcv9, ia64, amd64}.
 */
int
arch_strtoi(const char *arch_str)
{
	if (arch_str != NULL) {
		if (strcmp(arch_str, ARCH_I386) == 0)
			return (XLATOR_I386);
		else if (strcmp(arch_str, ARCH_SPARC) == 0)
			return (XLATOR_SPARC);
		else if (strcmp(arch_str, ARCH_SPARCV9) == 0)
			return (XLATOR_SPARCV9);
		else if (strcmp(arch_str, ARCH_IA64) == 0)
			return (XLATOR_IA64);
		else if (strcmp(arch_str, ARCH_AMD64) == 0)
			return (XLATOR_AMD64);
		else if (strcmp(arch_str, ARCH_ALL) == 0)
			return (XLATOR_ALLARCH);
	} else {
		errlog(ERROR, "\"%s\", line %d: Error: "
		    "arch keyword with no value");
	}
	return (0);
}

int
readline(char **buffer, FILE *fp)
{
	int nlines = 0;
	int len;
	char buf[BUFSIZ];

	if (fgets(buf, BUFSIZ, fp)) {
		nlines++;
		/* replace comments with single whitespace */
		remcomment(buf);

		/* get complete line */
		*buffer = line_to_buf(*buffer, buf); /* append buf to buffer */
		len = strlen(buf);
		if (len > 1) {
			/* handle continuation lines */
			while (buf[len-2] == '\\') {
				if (!fgets(buf, BUFSIZ, fp)) {
					*buffer = line_to_buf(*buffer, buf);
					break;
				}
				nlines++;
				len = strlen(buf);
				*buffer = line_to_buf(*buffer, buf);
			}
		} /* end of 'get complete line' */
	}
	return (nlines);
}
