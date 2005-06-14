/*
 *  Copyright 1993 Open Software Foundation, Inc., Cambridge, Massachusetts.
 *  All rights reserved.
 */
/*
#pragma ident	"%Z%%M%	%I%	%E% SMI"
 * Copyright (c) 1994  
 * Open Software Foundation, Inc. 
 *  
 * Permission is hereby granted to use, copy, modify and freely distribute 
 * the software in this file and its documentation for any purpose without 
 * fee, provided that the above copyright notice appears in all copies and 
 * that both the copyright notice and this permission notice appear in 
 * supporting documentation.  Further, provided that the name of Open 
 * Software Foundation, Inc. ("OSF") not be used in advertising or 
 * publicity pertaining to distribution of the software without prior 
 * written permission from OSF.  OSF makes no representations about the 
 * suitability of this software for any purpose.  It is provided "as is" 
 * without express or implied warranty. 
 */
/*
 * Copyright (c) 1996 X Consortium
 * Copyright (c) 1995, 1996 Dalrymple Consulting
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 * X CONSORTIUM OR DALRYMPLE CONSULTING BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 * 
 * Except as contained in this notice, the names of the X Consortium and
 * Dalrymple Consulting shall not be used in advertising or otherwise to
 * promote the sale, use or other dealings in this Software without prior
 * written authorization.
 */
/* ________________________________________________________________________
 *
 *  Program to manipulate SGML instances.
 *
 *  This module contains the initialization routines for translation module.
 *  They mostly deal with reading data files (translation specs, SDATA
 *  mappings, character mappings).
 *
 *  Entry points:
 *	ReadTransSpec(transfile)	read/store translation spec from file
 *	ReadSDATA(sdatafile)		read/store SDATA mappings from file
 *	ReadMapping(mapfile)		read/store char mappings from file
 * ________________________________________________________________________
 */

#ifndef lint
static char *RCSid =
  "$Header: /usr/src/docbook-to-man/Instant/RCS/traninit.c,v 1.6 1998/06/28 19:15:41 fld Exp fld $";
#endif

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <memory.h>
#include <sys/types.h>
#include <errno.h>

#include <tptregexp.h>
#include "general.h"
#include "translate.h"

#ifndef TRUE
#define TRUE	(1 == 1)
#endif

/* forward references */
void	RememberTransSpec(Trans_t *, int);

/* ______________________________________________________________________ */
/*  Read the translation specs from the input file, storing in memory.
 *  Arguments:
 *	Name of translation spec file.
 */

void
ReadTransSpec(
    char *transfile
)
{
    FILE	*fp;
    char	buf[LINESIZE], *cp, *fn, *cp2;
    int		lineno=0, c, i;
    Trans_t	T;

    if ((fp=OpenFile(transfile)) == NULL) {
	fprintf(stderr, "Can not open translation spec file '%s'.\n%s\n",
		transfile, strerror(errno));
	return;
    }

    memset(&T, 0, sizeof T);		/* initialize/clear structure */
    while (fgets(buf, LINESIZE, fp))	/* read line from .ts file */
    {
	lineno++;
	/* skip comment and blank lines */
	if (buf[0] == '#' || buf[0] == NL) continue;

	/* '-' indicates end of a spec.  When we hit one, remember what we've
	 * accumulated so far, and null-out the accumulating structure. */
	if (buf[0] == '-') {
	    T.lineno = lineno;
	    RememberTransSpec(&T, lineno);
	    memset(&T, 0, sizeof T);
	    continue;
	}

	stripNL(buf);

	/*  See if next line is continued from this one -- ie. it starts with
	 *  whitespace.  If so, append to current line.  (This is similar to
	 *  how e-mail headers work...) */
	while (1) {
	    c = getc(fp);		/* 1st char of next line */
	    if (IsWhite(c)) {		/* space or tab? */
		/* keep getting characters until it's a non-whitespace */
		c = getc(fp);
		while (IsWhite(c)) c = getc(fp);
		ungetc(c, fp);		/* put back non-whitespace */
		i = strlen(buf);
		buf[i++] = ' ';
		fn = buf + i;		/* point to end of string in buffer */
		fgets(fn, LINESIZE-i, fp);	/* read and append to buf */
		lineno++;
		stripNL(buf);
	    }
	    else {
		ungetc(c, fp);		/* put back non-whitespace */
		break;
	    }
	}
	/* Isolate field value */
	if ((cp=strchr(buf, ':'))) {
	    cp++;				/* point past colon */
	    while (*cp && IsWhite(*cp)) cp++;	/* point to content */
	}
	else {
	    fprintf(stderr,
		"Trans spec error, missing colon (skipping line):\n  %s\n", fn);
	    continue;
	}
	fn = buf;		/* fn is name of the field, cp the value. */

	/* Check field names in order that they're likely to occur. */
	if (!strncmp("GI:",          fn, 3)) {
	    /* if we are folding the case of GIs, make all upper (unless
	       it's an internal pseudo-GI name, which starts with '_') */
	    if (fold_case && cp[0] != '_' && cp[0] != '#') {
		for (cp2=cp; *cp2; cp2++)
		    if (islower(*cp2)) *cp2 = toupper(*cp2);
	    }
	    T.gi = AddElemName(cp);
	}
	else if (!strncmp("StartText:",   fn, 10)) T.starttext	= strdup(cp);
	else if (!strncmp("EndText:",     fn, 8))  T.endtext	= strdup(cp);
	else if (!strncmp("Relation:",    fn, 9))  {
	    if (!T.relations) T.relations = NewMap(IMS_relations);
	    SetMapping(T.relations, cp);
	}
	else if (!strncmp("Replace:",     fn, 8))  T.replace	= strdup(cp);
	else if (!strncmp("AttValue:",    fn, 9)) {
	    if (!T.nattpairs) {
		Malloc(1, T.attpair, AttPair_t);
	    }
	    else
		Realloc((T.nattpairs+1), T.attpair, AttPair_t);
	    /* we'll split name/value pairs later */
	    T.attpair[T.nattpairs].name = strdup(cp);
	    T.nattpairs++;
	}
	/* If there's only one item in context, it's the parent.  Treat
	 * it specially, since it's easier to just check parent gi.
	 */
	else if (!strncmp("Context:",     fn, 8))  T.context	= strdup(cp);
	else if (!strncmp("Message:",     fn, 8))  T.message	= strdup(cp);
	else if (!strncmp("SpecID:",      fn, 7))  T.my_id	= atoi(cp);
	else if (!strncmp("Action:",      fn, 7))  T.use_id	= atoi(cp);
	else if (!strncmp("Content:",     fn, 8))  T.content	= strdup(cp);
	else if (!strncmp("PAttSet:",     fn, 8))  T.pattrset	= strdup(cp);
	else if (!strncmp("Verbatim:",    fn, 9))  T.verbatim	= TRUE;
	else if (!strncmp("Ignore:",      fn, 7)) {
	    if (!strcmp(cp, "all"))		T.ignore = IGN_ALL;
	    else if (!strcmp(cp, "data"))	T.ignore = IGN_DATA;
	    else if (!strcmp(cp, "children"))	T.ignore = IGN_CHILDREN;
	    else
		fprintf(stderr, "Bad 'Ignore:' arg in transpec (line %d): %s\n",
			lineno, cp);
	}
	else if (!strncmp("VarValue:",    fn, 9)) {
	    char	**tok;
	    i = 2;
	    tok = Split(cp, &i, S_STRDUP);
	    T.var_name	= tok[0];
	    T.var_value	= tok[1];
	}
	else if (!strncmp("VarREValue:",    fn, 11)) {
	    char	**tok;
	    i = 2;
	    tok = Split(cp, &i, S_STRDUP);
	    T.var_RE_name = tok[0];
	    ExpandVariables(tok[1], buf, 0);
	    if (!(T.var_RE_value=tpt_regcomp(buf)))	{
	    	fprintf(stderr, "Regex error in VarREValue Content: %s\n",
					tok[1]);
	    }
	}
	else if (!strncmp("Set:", fn, 4)) {
	    if (!T.set_var) T.set_var = NewMap(IMS_setvar);
	    SetMapping(T.set_var, cp);
	}
	else if (!strncmp("Increment:",   fn, 10)) {
	    if (!T.incr_var) T.incr_var = NewMap(IMS_incvar);
	    SetMapping(T.incr_var, cp);
	}
	else if (!strncmp("Substitute:",   fn, 11)) {
	    if (!T.incr_var) T.substitute = NewMap(IMS_incvar);
	    SetMapping(T.substitute, cp);
	}
	else if (!strncmp("NthChild:",    fn, 9))  T.nth_child	= atoi(cp);
	else if (!strncmp("Var:", fn, 4)) SetMapping(Variables, cp);
	else if (!strncmp("Quit:",        fn, 5))  T.quit	= strdup(cp);
	else if (!strncmp("Trim:",        fn, 5))  T.trim	= strdup(cp);
	else
	    fprintf(stderr, "Unknown translation spec (skipping it): %s\n", fn);
    }
    fclose(fp);
}

/* ______________________________________________________________________ */
/*  Store translation spec 't' in memory.
 *  Arguments:
 *	Pointer to translation spec to remember.
 *	Line number where translation spec ends.
 */
void
RememberTransSpec(
    Trans_t	*t,
    int		lineno
)
{
    char	*cp;
    int		i, do_regex;
    static Trans_t *last_t;
    char buf[1000];

    /* If context testing, check some details and set things up for later. */
    if (t->context) {
	/* See if the context specified is a regular expression.
	 * If so, compile the reg expr.  It is assumed to be a regex if
	 * it contains a character other than what's allowed for GIs in the
	 * OSF sgml declaration (alphas, nums, '-', and '.').
	 */
	for (do_regex=0,cp=t->context; *cp; cp++) {
	    if (!isalnum(*cp) && *cp != '-' && *cp != '.' && *cp != ' ') {
		do_regex = 1;
		break;
	    }
	}

	if (do_regex) {
	    t->depth = MAX_DEPTH;
	    if (!(t->context_re=tpt_regcomp(t->context))) {
		fprintf(stderr, "Regex error in Context: %s\n", t->context);
	    }
	}
	else {
	    /* If there's only one item in context, it's the parent.  Treat
	     * it specially, since it's faster to just check parent gi.
	     */
	    cp = t->context;
	    if (!strchr(cp, ' ')) {
		t->parent  = t->context;
		t->context = NULL;
	    }
	    else {
		/* Figure out depth of context string */
		t->depth = 0;
		while (*cp) {
		    if (*cp) t->depth++;
		    while (*cp && !IsWhite(*cp)) cp++;	/* find end of gi */
		    while (*cp && IsWhite(*cp)) cp++;	/* skip space */
		}
	    }
	}
    }

    /* Compile regular expressions for each attribute */
    for (i=0; i<t->nattpairs; i++) {
	/* Initially, name points to "name value".  Split them... */
	cp = t->attpair[i].name;
	while (*cp && !IsWhite(*cp)) cp++;	/* point past end of name */
	if (*cp) {	/* value found */
	    *cp++ = EOS;			/* terminate name */
	    while (*cp && IsWhite(*cp)) cp++;	/* point to value */
	    ExpandVariables(cp, buf, 0);	/* expand any variables */
	    t->attpair[i].val = strdup(buf);
	}
	else {		/* value not found */
	    t->attpair[i].val = ".";
	}
	if (!(t->attpair[i].rex=tpt_regcomp(t->attpair[i].val))) {
	    fprintf(stderr, "Regex error in AttValue: %s %s\n",
		    t->attpair[i].name, t->attpair[i].val);
	}
    }

    /* Compile regular expression for content */
    t->content_re = 0;
    if (t->content) {
	ExpandVariables(t->content, buf, 0);
	if (!(t->content_re=tpt_regcomp(buf)))
	    fprintf(stderr, "Regex error in Content: %s\n",
		    t->content);
    }

    /* If multiple GIs, break up into a vector, then remember it.  We either
     * sture the individual, or the list - not both. */
    if (t->gi && strchr(t->gi, ' ')) {
	t->gilist = Split(t->gi, 0, S_ALVEC);
	t->gi = NULL;
    }

    /* Now, store structure in linked list. */
    if (!TrSpecs) {
	Malloc(1, TrSpecs, Trans_t);
	last_t = TrSpecs;
    }
    else {
	Malloc(1, last_t->next, Trans_t);
	last_t = last_t->next;
    }
    *last_t = *t;
}


/* ______________________________________________________________________ */
/*  Read mapping file, filling in structure slots (just name-value pairs).
 *  Arguments:
 *	Name of character mapping file.
 */

void
ReadCharMap(
    char *filename
)
{
    FILE	*fp;
    char	buf[LINESIZE], *name, *val;
    int		lineno=0;
    int		n_alloc=0;	/* number of slots allocated so far */

    if ((fp=OpenFile(filename)) == NULL) {
	fprintf(stderr, "Can not open character mapping file '%s'.\n%s\n",
		filename, strerror(errno));
	return;
    }

    /* We allocate slots in blocks of N, so we don't have to call
     * malloc so many times. */
    n_alloc  = 32;
    Calloc(n_alloc, CharMap, Mapping_t);

    nCharMap = 0;
    while (fgets(buf, LINESIZE, fp))
    {
	lineno++;
	/* skip comment and blank lines */
	if (buf[0] == '#' || buf[0] == NL) continue;
	stripNL(buf);

	/* Need more slots for mapping structures? */
	if (nCharMap >= n_alloc) {
	    n_alloc += 32;
	    Realloc(n_alloc, CharMap, Mapping_t);
	}
	name = val = buf;
	while (*val && !IsWhite(*val)) val++;	/* point past end of name */
	if (*val) {
	    *val++ = EOS;				/* terminate name */
	    while (*val && IsWhite(*val)) val++;	/* point to value */
	}
	if (name) {
	    CharMap[nCharMap].name = strdup(name);
	    if (val) CharMap[nCharMap].sval = strdup(val);
	    if (CharMap[nCharMap].name[0] == '\\') CharMap[nCharMap].name++;
	    nCharMap++;
	}
    }
    fclose(fp);
}

/* ______________________________________________________________________ */
/* Read SDATA mapping file, remembering the mappings in memory.
 * Input file format is 2 columns, name and value, separated by one or
 * more tabs (not spaces).
 * This can be called multuple times, reading several files.
 *  Arguments:
 *	Name of SDATA entity mapping file.
 */

void
ReadSDATA(
    char *filename
)
{
    FILE	*fp;
    char	buf[LINESIZE], *name, *val;
    int		lineno=0;

    if ((fp=OpenFile(filename)) == NULL) {
	fprintf(stderr, "Can not open SDATA file '%s': %s", filename,
		strerror(errno));
	return;
    }

    if (!SDATAmap) SDATAmap = NewMap(IMS_sdata);

    while (fgets(buf, LINESIZE, fp))
    {
	lineno++;
	/* skip comment and blank lines */
	if (buf[0] == '#' || buf[0] == NL) continue;
	stripNL(buf);

	name = val = buf;
	while (*val && *val != TAB) val++;	/* point past end of name */
	if (*val) {
	    *val++ = EOS;			/* terminate name */
	    while (*val && *val == TAB) val++;	/* point to value */
	}

	SetMappingNV(SDATAmap, name, val);
    }
    fclose(fp);
}

/* ______________________________________________________________________ */
