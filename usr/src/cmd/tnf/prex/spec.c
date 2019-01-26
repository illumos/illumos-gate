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
 * Copyright (c) 1994, by Sun Microsytems, Inc.
 */

/*
 * Includes
 */

/* we need to define this to get strtok_r from string.h */
/* SEEMS LIKE A BUG TO ME */
#define	_REENTRANT

#ifndef DEBUG
#define	NDEBUG	1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libintl.h>
#include <regexpr.h>
#include <assert.h>
#include <sys/types.h>
#include "spec.h"
#include "new.h"
#include "source.h"


static boolean_t spec_match(spec_t * spec_p, char *str);

/*
 * Globals
 */



/*
 * spec() - builds a spec
 */

spec_t		 *
spec(char *str_p,
	spec_type_t type)
{
	spec_t		 *new_p;

	new_p = new(spec_t);
	queue_init(&new_p->qn);
	new_p->str = str_p;
	new_p->type = type;
	new_p->regexp_p = NULL;

	if (type == SPEC_REGEXP) {
		new_p->regexp_p = compile(str_p, NULL, NULL);
		if (!new_p->regexp_p) {
			semantic_err(gettext("invalid regular expression"));
			free(new_p);
			return (NULL);
		}
	}
	return (new_p);

}				/* end spec */


/*
 * spec_dup() - duplicates a spec, NOT A SPEC LIST!
 */

spec_t		 *
spec_dup(spec_t * spec_p)
{
	spec_t		 *new_p;

	new_p = spec(strdup(spec_p->str), spec_p->type);

	return (new_p);

}				/* end spec_dup */


/*
 * spec_destroy() - destroys a spec list
 */

void
spec_destroy(spec_t * list_p)
{
	spec_t		 *spec_p;

	while ((spec_p = (spec_t *) queue_next(&list_p->qn, &list_p->qn))) {
		(void) queue_remove(&spec_p->qn);

		if (spec_p->str)
			free(spec_p->str);
		if (spec_p->regexp_p)
			free(spec_p->regexp_p);
		free(spec_p);
	}

	if (list_p->str)
		free(list_p->str);
	if (list_p->regexp_p)
		free(list_p->regexp_p);
	free(list_p);

}				/* end spec_destroy */


/*
 * spec_list() - append a spec_t to a list
 */

spec_t		 *
spec_list(spec_t * h,
	spec_t * f)
{
	/* queue append handles the NULL cases OK */
	return ((spec_t *) queue_append(&h->qn, &f->qn));

}				/* end spec_list */


/*
 * spec_print() - pretty prints a speclist
 */

void
spec_print(FILE * stream,
	spec_t * list_p)
{
	spec_t		 *spec_p = NULL;

	while ((spec_p = (spec_t *) queue_next(&list_p->qn, &spec_p->qn))) {
		switch (spec_p->type) {
		case SPEC_EXACT:
			(void) fprintf(stream, "'%s'", spec_p->str);
			break;
		case SPEC_REGEXP:
			(void) fprintf(stream, "/%s/", spec_p->str);
			break;
		}
	}

}				/* end spec_print */


/*
 * spec_match() - called with a spec and a string, returns whether they
 * match.
 */

static boolean_t
spec_match(spec_t * spec_p,
	char *str)
{
	if (!spec_p)
		return (B_FALSE);

	switch (spec_p->type) {
	case SPEC_EXACT:
		return ((strcmp(spec_p->str, str) == 0));

	case SPEC_REGEXP:
		return ((step(str, spec_p->regexp_p) != 0));
	}

	return (B_FALSE);

}				/* end spec_match */


/*
 * spec_attrtrav() - traverse an attribute list, calling the supplied
 * function on each matching attribute.
 */

void
spec_attrtrav(spec_t * spec_p,
	char *attrs,
	spec_attr_fun_t fun,
	void *calldatap)
{
	char		   *lasts;
	char		   *refptr = NULL;
	char		   *escptr = NULL;
	char		   *pair;
	char		   *s;
	boolean_t	   inquote = B_FALSE;

	/*
	 * * STRATEGY - we make two copies of the attr string.  In one *
	 * string we escape (translate) all relevant quoted characters to * a
	 * non-significant character.  We use this string to feed to * strtok
	 * to do the parsing. * Once strtok has parsed the string, we use the
	 * same fragement * positions from the unescaped string to pass to
	 * the next level.
	 */

	/* make two copies of the string */
	refptr = strdup(attrs);
	escptr = strdup(attrs);

	/* escape any quoted ';'s in the escptr string */
	for (s = escptr; *s; s++) {
		switch (*s) {
		case ';':
			if (inquote)
				*s = '#';
			break;

		case '\'':
			inquote = (inquote) ? B_FALSE : B_TRUE;
			break;

		default:
			/* nothing on purpose */
			break;
		}
	}

	/* loop over each attribute section separated by ';' */
	for (pair = strtok_r(escptr, ";", &lasts); pair;
		pair = strtok_r(NULL, ";", &lasts)) {
		char		   *escattr;
		char		   *escvals;
		char		   *refattr;
		char		   *refvals;
		char			emptystr[1];

		escattr = strtok_r(pair, " \t", &escvals);

		/*
		 * setup the ref pointers to the same locations as the esc
		 * ptrs
		 */
		/*
		 * null the reference string in the same spots as the esc
		 * string
		 */
		refattr = (refptr + (escattr - escptr));
		refattr[strlen(escattr)] = '\0';

		if (escvals && *escvals) {
			refvals = (refptr + (escvals - escptr));
			refvals[strlen(escvals)] = '\0';
		} else {
			refvals = NULL;
			emptystr[0] = '\0';
		}

		if (spec_match(spec_p, refattr)) {
			if (refvals)
				(*fun) (spec_p, refattr, refvals, calldatap);
			else
				(*fun) (spec_p, refattr, emptystr, calldatap);
		}
	}

alldone:
	if (refptr)
		free(refptr);
	if (escptr)
		free(escptr);

}				/* end spec_attrtrav */


/*
 * spec_valtrav() - traverse an value list, calling the supplied function on
 * each matching value.
 */

void
spec_valtrav(spec_t * spec_p,
	char *valstr,
	spec_val_fun_t fun,
	void *calldatap)
{
	char		   *s0;
	char		   *s;
	boolean_t	   intoken = B_FALSE;
	boolean_t	   inquote = B_FALSE;

	/* return immeadiatly on null pointers */
	if (!valstr)
		return;

	/* special case, match once on empty string */
	if (!*valstr) {
		if (spec_match(spec_p, valstr))
			(*fun) (spec_p, valstr, calldatap);
		return;
	}
	for (s = s0 = valstr; ; s++) {
		switch (*s) {
		case '\0':
			if (intoken) {
				if (spec_match(spec_p, s0))
					(*fun) (spec_p, s0, calldatap);
			}
			return;	/* ALL DONE */

		case '\'':
			if (inquote) {
				/* end a quoted string */
				inquote = B_FALSE;
				intoken = B_FALSE;
				*s = '\0';
				if (spec_match(spec_p, s0))
					(*fun) (spec_p, s0, calldatap);
				/* next string starts past the quote */
				s0 = s + 1;
			} else {
				/* start a quoted string */
				inquote = B_TRUE;
				intoken = B_TRUE;
				s0 = s + 1;	/* point past the quote */
			}
			break;

		case ' ':
		case '\t':
			/* ignore whitespace in quoted strings */
			if (inquote)
				break;

			if (intoken) {
				/* whitespace ended this token */
				intoken = B_FALSE;
				*s = '\0';
				if (spec_match(spec_p, s0))
					(*fun) (spec_p, s0, calldatap);
				/* next string starts past the whitespace */
				s0 = s + 1;
			}
			break;

		default:
			/* characters all OK inside quoted string */
			if (inquote)
				break;

			if (!intoken) {
				/* start of unquoted token */
				intoken = B_TRUE;
				s0 = s;	/* token starts here */
			}
			break;
		}
	}


#ifdef TOOSIMPLE
	char		   *v;
	char		   *ls;

	/*
	 * #### MISSING - need to handle quoted value strings * containing
	 * whitespace.
	 */

	for (v = strtok_r(valstr, " \t", &ls); v;
		v = strtok_r(NULL, " \t", &ls)) {
		if (spec_match(spec_p, v)) {
			(*fun) (spec_p, v, calldatap);
		}
	}
#endif

}				/* end spec_valtrav */
