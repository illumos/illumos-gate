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
 * logadm/opts.c -- options handling routines
 */

#include <stdio.h>
#include <libintl.h>
#include <stdlib.h>
#include <ctype.h>
#include <strings.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include "err.h"
#include "lut.h"
#include "fn.h"
#include "opts.h"

/* forward declarations for private functions */
static struct optinfo *opt_info(int c);
static void opts_setcmdarg(struct opts *opts, const char *cmdarg);

/* info created by opts_parse(), private to this module */
struct opts {
	struct lut *op_raw;		/* the raw text for the options */
	struct lut *op_ints;		/* the int values for the options */
	struct fn_list *op_cmdargs;	/* the op_cmdargs */
};

static struct lut *Info;		/* table driving parsing */

/*
 * opts_init -- set current options parsing table
 */
void
opts_init(struct optinfo *table, int numentries)
{
	while (numentries-- > 0) {
		Info = lut_add(Info, table->oi_o, table);
		table++;
	}
}

/*
 * opt_info -- fetch the optinfo struct for the given option
 */
static struct optinfo *
opt_info(int c)
{
	char lhs[2];
	lhs[0] = c;
	lhs[1] = '\0';
	return ((struct optinfo *)lut_lookup(Info, lhs));
}

/*
 * opts_parse -- parse an argv-style list of options
 *
 * prints a message to stderr and calls err(EF_FILE|EF_JMP, ...) on error
 */
struct opts *
opts_parse(char **argv, int flags)
{
	struct opts *ret = MALLOC(sizeof (*ret));
	int dashdash = 0;
	char *ptr;

	ret->op_raw = ret->op_ints = NULL;
	ret->op_cmdargs = fn_list_new(NULL);

	/* no words to process, just return empty opts struct */
	if (argv == NULL)
		return (ret);

	/* foreach word... */
	for (; (ptr = *argv) != NULL; argv++) {
		if (dashdash || *ptr != '-') {
			/* found a cmdarg */
			opts_setcmdarg(ret, ptr);
			continue;
		}
		if (*++ptr == '\0')
			err(EF_FILE|EF_JMP, "Illegal option: dash by itself");
		if (*ptr == '-') {
			/* (here's where support for --longname would go) */
			if (*(ptr + 1) != '\0')
				err(EF_FILE|EF_JMP, "Illegal option: -%s", ptr);
			dashdash++;
			continue;
		}
		for (; *ptr; ptr++) {
			struct optinfo *info = opt_info(*ptr);

			/* see if option was in our parsing table */
			if (info == NULL)
				err(EF_FILE|EF_JMP, "Illegal option: %c", *ptr);

			/* see if context allows this option */
			if ((flags & OPTF_CLI) &&
			    (info->oi_flags & OPTF_CLI) == 0)
				err(EF_FILE|EF_JMP,
				    "Option '%c' not allowed on "
				    "command line", *ptr);

			if ((flags & OPTF_CONF) &&
			    (info->oi_flags & OPTF_CONF) == 0)
				err(EF_FILE|EF_JMP,
				    "Option '%c' not allowed in "
				    "configuration file", *ptr);

			/* for boolean options, we have all the info we need */
			if (info->oi_t == OPTTYPE_BOOLEAN) {
				(void) opts_set(ret, info->oi_o, "");
				continue;
			}

			/* option expects argument */
			if (*++ptr == '\0' &&
			    ((ptr = *++argv) == NULL || *ptr == '-'))
				err(EF_FILE|EF_JMP,
				    "Option '%c' requires an argument",
				    info->oi_o[0]);
			opts_set(ret, info->oi_o, ptr);
			break;
		}
	}

	return (ret);
}

/*
 * opts_free -- free a struct opts previously allocated by opts_parse()
 */
void
opts_free(struct opts *opts)
{
	if (opts) {
		lut_free(opts->op_raw, NULL);
		lut_free(opts->op_ints, NULL);
		fn_list_free(opts->op_cmdargs);
		FREE(opts);
	}
}

/*
 * opts_set -- set an option
 */
void
opts_set(struct opts *opts, const char *o, const char *optarg)
{
	off_t *rval;
	struct optinfo *info = opt_info(*o);

	rval = MALLOC(sizeof (off_t));
	opts->op_raw = lut_add(opts->op_raw, o, (void *)optarg);

	if (info->oi_parser) {
		*rval = (*info->oi_parser)(o, optarg);
		opts->op_ints = lut_add(opts->op_ints, o, (void *)rval);
	}
}

/*
 * opts_setcmdarg -- add a cmdarg to the list of op_cmdargs
 */
static void
opts_setcmdarg(struct opts *opts, const char *cmdarg)
{
	fn_list_adds(opts->op_cmdargs, cmdarg);
}

/*
 * opts_count -- return count of the options in *options that are set
 */
int
opts_count(struct opts *opts, const char *options)
{
	int count = 0;

	for (; *options; options++) {
		char lhs[2];
		lhs[0] = *options;
		lhs[1] = '\0';
		if (lut_lookup(opts->op_raw, lhs))
			count++;
	}
	return (count);
}

/*
 * opts_optarg -- return the optarg for the given option, NULL if not set
 */
const char *
opts_optarg(struct opts *opts, const char *o)
{
	return ((char *)lut_lookup(opts->op_raw, o));
}

/*
 * opts_optarg_int -- return the int value for the given option
 */
off_t
opts_optarg_int(struct opts *opts, const char *o)
{
	off_t	*ret;

	ret = (off_t *)lut_lookup(opts->op_ints, o);
	if (ret != NULL)
		return (*ret);
	return (0);
}

/*
 * opts_cmdargs -- return list of op_cmdargs
 */
struct fn_list *
opts_cmdargs(struct opts *opts)
{
	return (opts->op_cmdargs);
}

static void
merger(const char *lhs, void *rhs, void *arg)
{
	struct lut **destlutp = (struct lut **)arg;

	*destlutp = lut_add(*destlutp, lhs, rhs);
}

/*
 * opts_merge -- merge two option lists together
 */
struct opts *
opts_merge(struct opts *back, struct opts *front)
{
	struct opts *ret = MALLOC(sizeof (struct opts));

	ret->op_raw = lut_dup(back->op_raw);
	lut_walk(front->op_raw, merger, &(ret->op_raw));

	ret->op_ints = lut_dup(back->op_ints);
	lut_walk(front->op_ints, merger, &(ret->op_ints));

	ret->op_cmdargs = fn_list_dup(back->op_cmdargs);

	return (ret);
}

/*
 * opts_parse_ctime -- parse a ctime format optarg
 */
off_t
opts_parse_ctime(const char *o, const char *optarg)
{
	struct tm tm;
	off_t ret;

	if (strptime(optarg, "%a %b %e %T %Z %Y", &tm) == NULL &&
	    strptime(optarg, "%c", &tm) == NULL)
		err(EF_FILE|EF_JMP,
		    "Option '%c' requires ctime-style time", *o);
	errno = 0;
	if ((ret = (off_t)mktime(&tm)) == -1 && errno)
		err(EF_FILE|EF_SYS|EF_JMP, "Option '%c' Illegal time", *o);

	return (ret);
}

/*
 * opts_parse_atopi -- parse a positive integer format optarg
 */
off_t
opts_parse_atopi(const char *o, const char *optarg)
{
	off_t ret = atoll(optarg);

	while (isdigit(*optarg))
		optarg++;

	if (*optarg)
		err(EF_FILE|EF_JMP,
		    "Option '%c' requires non-negative number", *o);

	return (ret);
}

/*
 * opts_parse_atopi -- parse a size format optarg into bytes
 */
off_t
opts_parse_bytes(const char *o, const char *optarg)
{
	off_t ret = atoll(optarg);
	while (isdigit(*optarg))
		optarg++;

	switch (*optarg) {
	case 'g':
	case 'G':
		ret *= 1024;
		/*FALLTHROUGH*/
	case 'm':
	case 'M':
		ret *= 1024;
		/*FALLTHROUGH*/
	case 'k':
	case 'K':
		ret *= 1024;
		/*FALLTHROUGH*/
	case 'b':
	case 'B':
		if (optarg[1] == '\0')
			return (ret);
	}

	err(EF_FILE|EF_JMP,
	    "Option '%c' requires number with suffix from [bkmg]", *o);
	/*NOTREACHED*/
	return (0);
}

/*
 * opts_parse_seconds -- parse a time format optarg into seconds
 */
off_t
opts_parse_seconds(const char *o, const char *optarg)
{
	off_t ret;

	if (strcasecmp(optarg, "now") == 0)
		return (OPTP_NOW);

	if (strcasecmp(optarg, "never") == 0)
		return (OPTP_NEVER);

	ret = atoll(optarg);
	while (isdigit(*optarg))
		optarg++;

	if (optarg[1] == '\0')
		switch (*optarg) {
		case 'h':
		case 'H':
			ret *= 60 * 60;
			return (ret);
		case 'd':
		case 'D':
			ret *= 60 * 60 * 24;
			return (ret);
		case 'w':
		case 'W':
			ret *= 60 * 60 * 24 * 7;
			return (ret);
		case 'm':
		case 'M':
			ret *= 60 * 60 * 24 * 30;
			return (ret);
		case 'y':
		case 'Y':
			ret *= 60 * 60 * 24 * 365;
			return (ret);
		}

	err(EF_FILE|EF_JMP,
	    "Option '%c' requires number with suffix from [hdwmy]", *o);
	/*NOTREACHED*/
	return (0);
}

/* info passed between opts_print() and printer() */
struct printerinfo {
	FILE *stream;
	int isswitch;
	char *exclude;
};

/* helper function for opts_print() */
static void
printer(const char *lhs, void *rhs, void *arg)
{
	struct printerinfo *pip = (struct printerinfo *)arg;
	char *s = (char *)rhs;

	if (pip->isswitch) {
		char *ep = pip->exclude;
		while (ep && *ep)
			if (*ep++ == *lhs)
				return;
	}

	(void) fprintf(pip->stream, " %s%s", (pip->isswitch) ? "-" : "", lhs);
	if (s && *s) {
		(void) fprintf(pip->stream, " ");
		opts_printword(s, pip->stream);
	}
}

/*
 * opts_printword -- print a word, quoting as necessary
 */
void
opts_printword(const char *word, FILE *stream)
{
	char *q = "";

	if (word != NULL) {
		if (strchr(word, ' ') || strchr(word, '\t') ||
		    strchr(word, '$') || strchr(word, '[') ||
		    strchr(word, '?') || strchr(word, '{') ||
		    strchr(word, '`') || strchr(word, ';')) {
			if (strchr(word, '\''))
				q = "\"";
			else if (strchr(word, '"'))
				err(EF_FILE|EF_JMP,
				    "Can't protect quotes in <%s>", word);
			else
				q = "'";
			(void) fprintf(stream, "%s%s%s", q, word, q);
		} else
			(void) fprintf(stream, "%s", word);
	}
}

/*
 * opts_print -- print options to stream, leaving out those in "exclude"
 */
void
opts_print(struct opts *opts, FILE *stream, char *exclude)
{
	struct printerinfo pi;
	struct fn *fnp;

	pi.stream = stream;
	pi.isswitch = 1;
	pi.exclude = exclude;

	lut_walk(opts->op_raw, printer, &pi);

	fn_list_rewind(opts->op_cmdargs);
	while ((fnp = fn_list_next(opts->op_cmdargs)) != NULL) {
		(void) fprintf(stream, " ");
		opts_printword(fn_s(fnp), stream);
	}
}

#ifdef	TESTMODULE

/* table that drives argument parsing */
static struct optinfo Opttable[] = {
	{ "a", OPTTYPE_BOOLEAN,	NULL,			OPTF_CLI },
	{ "b", OPTTYPE_STRING,	NULL,			OPTF_CLI },
	{ "c", OPTTYPE_INT,	opts_parse_seconds,	OPTF_CLI|OPTF_CONF },
	{ "d", OPTTYPE_INT,	opts_parse_ctime,	OPTF_CLI|OPTF_CONF },
	{ "e", OPTTYPE_INT,	opts_parse_bytes,	OPTF_CLI|OPTF_CONF },
	{ "f", OPTTYPE_INT,	opts_parse_atopi,	OPTF_CLI|OPTF_CONF },
};

/*
 * test main for opts module, usage: a.out options...
 */
int
main(int argc, char *argv[])
{
	struct opts *opts;

	err_init(argv[0]);
	setbuf(stdout, NULL);

	opts_init(Opttable, sizeof (Opttable) / sizeof (struct optinfo));

	argv++;

	if (SETJMP)
		err(0, "opts parsing failed");
	else
		opts = opts_parse(argv, OPTF_CLI);

	printf("options:");
	opts_print(opts, stdout, NULL);
	printf("\n");

	err_done(0);
	/* NOTREACHED */
	return (0);
}

#endif	/* TESTMODULE */
