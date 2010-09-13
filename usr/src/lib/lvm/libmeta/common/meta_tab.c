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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Just in case we're not in a build environment, make sure that
 * TEXT_DOMAIN gets set to something.
 */
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif

#include <meta.h>

#include <ctype.h>

/*
 * free md.tab struct
 */
void
meta_tab_free(
	md_tab_t	*tabp
)
{
	size_t		line;

	Free(tabp->filename);
	Free(tabp->data);
	if (tabp->lines != NULL) {
		assert(tabp->alloc > 0);
		for (line = 0; (line < tabp->nlines); ++line) {
			md_tab_line_t	*linep = &tabp->lines[line];

			if (linep->context != NULL)
				Free(linep->context);
			if (linep->cname != NULL)
				Free(linep->cname);
			if (linep->argv != NULL) {
				assert(linep->alloc > 0);
				Free(linep->argv);
			}
		}
		Free(tabp->lines);
	}
	Free(tabp);
}

/*
 * (re)allocate argv array
 */
static void
realloc_argv(
	md_tab_line_t	*linep,
	size_t		argc
)
{
	/* allocate in chunks */
	argc = roundup(argc, TAB_ARG_ALLOC);
	if (argc < linep->alloc)
		return;

	/* (re)allocate */
	if (linep->alloc == 0) {
		linep->argv = Malloc(argc * sizeof (*linep->argv));
	} else {
		assert(linep->argv != NULL);
		linep->argv =
		    Realloc(linep->argv, (argc * sizeof (*linep->argv)));
	}

	/* zero out new stuff */
	(void) memset(&linep->argv[linep->alloc], 0,
	    ((argc - linep->alloc) * sizeof (*linep->argv)));

	/* adjust for new size */
	linep->alloc = argc;
}

/*
 * (re)allocate line array
 */
static void
realloc_lines(
	md_tab_t	*tabp,
	size_t		nlines
)
{
	/* allocate in chunks */
	nlines = roundup(nlines, TAB_LINE_ALLOC);
	if (nlines < tabp->alloc)
		return;

	/* (re)allocate */
	if (tabp->alloc == 0) {
		assert(tabp->lines == NULL);
		tabp->lines = Malloc(nlines * sizeof (*tabp->lines));
	} else {
		assert(tabp->lines != NULL);
		tabp->lines =
		    Realloc(tabp->lines, (nlines * sizeof (*tabp->lines)));
	}

	/* zero out new stuff */
	(void) memset(&tabp->lines[tabp->alloc], 0,
	    ((nlines - tabp->alloc) * sizeof (*tabp->lines)));

	/* adjust for new size */
	tabp->alloc = nlines;
}

/*
 * parse up md.tab struct
 */
static void
parse_tab(
	md_tab_t	*tabp,
	char		*metatab_name,
	md_error_t	*ep
)
{
	uint_t		lineno = 1;
	char		*p = tabp->data;
	char		*e = tabp->data + tabp->total - 1;
	char		*context;
	size_t		len;

	/* we can count on '\n\0' as the last characters */
	assert(tabp->total >= 2);
	assert(tabp->data[tabp->total - 2] == '\n');
	assert(tabp->data[tabp->total - 1] == '\0');

	/* allocate context buffer "file line XXX" */
	assert(tabp->filename != NULL);
	len = strlen(tabp->filename) +
	    strlen(dgettext(TEXT_DOMAIN, "%s line %u")) + 20 + 1;
	context = Malloc(len);

	/* parse lines */
	while (p < e && *p != '\0') {
		md_tab_line_t	*linep;
		char		*t;

		/* allocate new line */
		realloc_lines(tabp, (tabp->nlines + 1));
		linep = &tabp->lines[tabp->nlines];
		(void) snprintf(context, len,
		    dgettext(TEXT_DOMAIN, "%s line %u"), tabp->filename,
		    lineno);

		/* comments */
		if (*p == '#') {
			while (*p != '\n')
				++p;
		}

		/* coalesce \ continuations */
		t = p;
		while (*t != '\n') {
			if ((*t == '\\') && (*(t + 1) == '\n')) {
				*t++ = ' ';
				*t = ' ';
				++lineno;
			}
			++t;
		}

		/* leading whitespace */
		while ((*p != '\n') && (isspace(*p)))
			++p;

		/* count lines */
		if (*p == '\n') {
			++p;
			++lineno;
			continue;
		}

		/* tokenize line */
		while ((p < e) && (*p != '\n')) {
			char	**argvp;

			/* allocate new token */
			realloc_argv(linep, (linep->argc + 1));
			argvp = &linep->argv[linep->argc++];

			/* find end of token */
			*argvp = p;
			while ((*p != '\n') && (! isspace(*p)))
				++p;

			/* terminate */
			if (*p == '\n') {
				*p++ = '\0';
				++lineno;
				break;
			}

			/* eat white space */
			*p++ = '\0';
			while ((p < e) && (*p != '\n') && (isspace(*p)))
				++p;
		}
		tabp->nlines++;

		/* fill in the rest */
		assert((linep->argc > 0) && (linep->argv != NULL) &&
		    (linep->argv[0][0] != '\0') &&
		    (! isspace(linep->argv[0][0])));
		linep->context = Strdup(context);
		linep->type = meta_get_init_type(linep->argc, linep->argv);
		linep->cname = meta_canonicalize(NULL, linep->argv[0]);
		/* if cname is NULL then the meta/hsp name is invalid */
		if (linep->cname == NULL) {
			(void) mderror(ep, MDE_SYNTAX, metatab_name);
			break;
		}
	}

	/* cleanup */
	Free(context);
}

/*
 * read in md.tab file and return struct
 */
md_tab_t *
meta_tab_parse(
	char		*filename,
	md_error_t	*ep
)
{
	md_tab_t	*tabp = NULL;
	int		fd = -1;
	struct stat	statbuf;
	size_t		sofar;
	char		*p;

	/* open tab file */
	if (filename == NULL)
		filename = METATAB;
	if ((fd = open(filename, O_RDONLY, 0)) < 0) {
		(void) mdsyserror(ep, errno, filename);
		goto out;
	}
	if (fstat(fd, &statbuf) != 0) {
		(void) mdsyserror(ep, errno, filename);
		goto out;
	}

	/* allocate table */
	tabp = Zalloc(sizeof (*tabp));
	tabp->filename = Strdup(filename);
	tabp->total = statbuf.st_size + 2;	/* terminating "\n\0" */
	tabp->data = Malloc(tabp->total);

	/* read in data */
	sofar = 0;
	p = tabp->data;
	while (sofar < statbuf.st_size) {
		int	cnt;

		if ((cnt = read(fd, p, 8192)) < 0) {
			(void) mdsyserror(ep, errno, filename);
			goto out;
		} else if (cnt == 0) {
			(void) mderror(ep, MDE_SYNTAX, filename);
			goto out;
		}
		sofar += cnt;
		p += cnt;
	}
	tabp->data[tabp->total - 2] = '\n';
	tabp->data[tabp->total - 1] = '\0';

	/* close file */
	if (close(fd) != 0) {
		(void) mdsyserror(ep, errno, filename);
		fd = -1;
		goto out;
	}
	fd = -1;

	/* parse it up */
	parse_tab(tabp, filename, ep);

	/* return success if file was correctly parsed */
	if (mdisok(ep))
		return (tabp);

	/* cleanup, return error */
out:
	if (fd >= 0)
		(void) close(fd);
	if (tabp != NULL)
		meta_tab_free(tabp);
	return (NULL);
}

/*
 * find line in md.tab
 */
md_tab_line_t *
meta_tab_find(
	mdsetname_t	*sp,
	md_tab_t	*tabp,
	char		*name,
	mdinittypes_t	type
)
{
	char		*cname = meta_canonicalize(sp, name);
	size_t		line;

	/* if name is not legal meta name then return NULL */
	if (cname == NULL)
		return (NULL);

	for (line = 0; (line < tabp->nlines); ++line) {
		md_tab_line_t	*linep = &tabp->lines[line];

		assert((linep->argc > 0) && (linep->argv[0] != NULL));
		if (((linep->type & type) != 0) &&
		    (strcmp(linep->cname, cname) == 0)) {
			Free(cname);
			return (linep);
		}
	}
	Free(cname);
	return (NULL);
}
