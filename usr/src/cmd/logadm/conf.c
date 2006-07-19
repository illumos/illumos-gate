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
 * logadm/conf.c -- configuration file module
 */

#include <stdio.h>
#include <libintl.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <ctype.h>
#include <strings.h>
#include <unistd.h>
#include <stdlib.h>
#include "err.h"
#include "lut.h"
#include "fn.h"
#include "opts.h"
#include "conf.h"

/* forward declarations of functions private to this module */
static void fillconflist(int lineno, const char *entry, char **args,
    struct opts *opts, const char *com, int flags);
static void fillargs(char *arg);
static char *nexttok(char **ptrptr);
static void conf_print(FILE *stream);

static const char *Confname;	/* name of the confile file */
static char *Confbuf;		/* copy of the config file (a la mmap()) */
static int Conflen;		/* length of mmap'd area */
static int Conffd = -1;		/* file descriptor for config file */
static boolean_t Confchanged;	/* true if we need to write changes back */

/*
 * our structured representation of the configuration file
 * is made up of a list of these
 */
struct confinfo {
	struct confinfo *cf_next;
	int cf_lineno;		/* line number in file */
	const char *cf_entry;	/* name of entry, if line has an entry */
	char **cf_args;		/* raw rhs of entry */
	struct opts *cf_opts;	/* parsed rhs of entry */
	const char *cf_com;	/* any comment text found */
	int cf_flags;
};

#define	CONFF_DELETED	1	/* entry should be deleted on write back */

static struct confinfo *Confinfo;	/* the entries in the config file */
static struct confinfo *Confinfolast;	/* end of list */
static struct lut *Conflut;		/* lookup table keyed by entry name */
static struct fn_list *Confentries;	/* list of valid entry names */

/* allocate & fill in another entry in our list */
static void
fillconflist(int lineno, const char *entry, char **args,
    struct opts *opts, const char *com, int flags)
{
	struct confinfo *cp = MALLOC(sizeof (*cp));

	cp->cf_next = NULL;
	cp->cf_lineno = lineno;
	cp->cf_entry = entry;
	cp->cf_args = args;
	cp->cf_opts = opts;
	cp->cf_com = com;
	cp->cf_flags = flags;
	if (entry != NULL) {
		Conflut = lut_add(Conflut, entry, cp);
		fn_list_adds(Confentries, entry);
	}
	if (Confinfo == NULL)
		Confinfo = Confinfolast = cp;
	else {
		Confinfolast->cf_next = cp;
		Confinfolast = cp;
	}
}

static char **Args;	/* static buffer for args */
static int ArgsN;	/* size of our static buffer */
static int ArgsI;	/* index into Cmdargs as we walk table */
#define	CONF_ARGS_INC	1024

/* callback for lut_walk to build a cmdargs vector */
static void
fillargs(char *arg)
{
	if (ArgsI >= ArgsN) {
		/* need bigger table */
		Args = REALLOC(Args, sizeof (char *) * (ArgsN + CONF_ARGS_INC));
		ArgsN += CONF_ARGS_INC;
	}
	Args[ArgsI++] = arg;
}

/* isolate and return the next token */
static char *
nexttok(char **ptrptr)
{
	char *ptr = *ptrptr;
	char *eptr;
	char *quote = NULL;

	while (*ptr && isspace(*ptr))
		ptr++;

	if (*ptr == '"' || *ptr == '\'')
		quote = ptr++;

	for (eptr = ptr; *eptr; eptr++)
		if (quote && *eptr == *quote) {
			/* found end quote */
			*eptr++ = '\0';
			*ptrptr = eptr;
			return (ptr);
		} else if (!quote && isspace(*eptr)) {
			/* found end of unquoted area */
			*eptr++ = '\0';
			*ptrptr = eptr;
			return (ptr);
		}

	if (quote != NULL)
		err(EF_FILE|EF_JMP, "Unbalanced %c quote", *quote);
		/*NOTREACHED*/

	*ptrptr = eptr;

	if (ptr == eptr)
		return (NULL);
	else
		return (ptr);
}

/*
 * conf_open -- open the configuration file, lock it if we have write perms
 */
void
conf_open(const char *fname, int needwrite)
{
	struct stat stbuf;
	int lineno = 0;
	char *line;
	char *eline;
	char *ebuf;
	char *comment;

	Confname = fname;
	Confentries = fn_list_new(NULL);

	/* special case this so we don't even try locking the file */
	if (strcmp(Confname, "/dev/null") == 0)
		return;

	if ((Conffd = open(Confname, (needwrite) ? O_RDWR : O_RDONLY)) < 0)
		err(EF_SYS, "%s", Confname);

	if (fstat(Conffd, &stbuf) < 0)
		err(EF_SYS, "fstat on %s", Confname);

	if (needwrite && lockf(Conffd, F_LOCK, 0) < 0)
		err(EF_SYS, "lockf on %s", Confname);

	if (stbuf.st_size == 0)
		return;	/* empty file, don't bother parsing it */

	if ((Confbuf = (char *)mmap(0, stbuf.st_size,
	    PROT_READ | PROT_WRITE, MAP_PRIVATE, Conffd, 0)) == (char *)-1)
		err(EF_SYS, "mmap on %s", Confname);

	Conflen = stbuf.st_size;
	Confchanged = B_FALSE;

	ebuf = &Confbuf[Conflen];

	if (Confbuf[Conflen - 1] != '\n')
		err(EF_WARN|EF_FILE, "config file doesn't end with "
		    "newline, last line ignored.");

	line = Confbuf;
	while (line < ebuf) {
		lineno++;
		err_fileline(Confname, lineno);
		eline = line;
		comment = NULL;
		for (; eline < ebuf; eline++) {
			/* check for continued lines */
			if (comment == NULL && *eline == '\\' &&
			    eline + 1 < ebuf && *(eline + 1) == '\n') {
				*eline = ' ';
				*(eline + 1) = ' ';
				lineno++;
				err_fileline(Confname, lineno);
				continue;
			}

			/* check for comments */
			if (comment == NULL && *eline == '#') {
				*eline = '\0';
				comment = (eline + 1);
				continue;
			}

			/* check for end of line */
			if (*eline == '\n')
				break;
		}
		if (comment >= ebuf)
			comment = NULL;
		if (eline < ebuf) {
			char *entry;

			*eline++ = '\0';

			/*
			 * now we have the entry, if any, at "line"
			 * and the comment, if any, at "comment"
			 */

			/* entry is first token */
			if ((entry = nexttok(&line)) != NULL &&
			    strcmp(entry, "logadm-version") == 0) {
				/*
				 * we somehow opened some future format
				 * conffile that we likely don't understand.
				 * if the given version is "1" then go on,
				 * otherwise someone is mixing versions
				 * and we can't help them other than to
				 * print an error and exit.
				 */
				if ((entry = nexttok(&line)) != NULL &&
				    strcmp(entry, "1") != 0)
					err(0, "%s version not "
					    "supported by "
					    "this version of logadm.",
					    Confname);
			} else if (entry) {
				char *ap;
				char **args;
				int i;

				ArgsI = 0;
				while (ap = nexttok(&line))
					fillargs(ap);
				if (ArgsI == 0) {
					/* short entry allowed */
					fillconflist(lineno, entry,
					    NULL, NULL, comment, 0);
				} else {
					Args[ArgsI++] = NULL;
					args = MALLOC(sizeof (char *) * ArgsI);
					for (i = 0; i < ArgsI; i++)
						args[i] = Args[i];
					fillconflist(lineno, entry,
					    args, NULL, comment, 0);
				}
			} else
				fillconflist(lineno, entry, NULL, NULL,
				    comment, 0);
		}
		line = eline;
	}
	/*
	 * possible future enhancement:  go through and mark any entries:
	 * 		logfile -P <date>
	 * as DELETED if the logfile doesn't exist
	 */
}

/*
 * conf_close -- close the configuration file
 */
void
conf_close(struct opts *opts)
{
	FILE *fp;

	if (Confchanged && opts_count(opts, "n") == 0 && Conffd != -1) {
		if (opts_count(opts, "v"))
			(void) out("# writing changes to %s\n", Confname);
		if (Debug > 1) {
			(void) fprintf(stderr, "conf_close, %s changed to:\n",
			    Confname);
			conf_print(stderr);
		}
		if (lseek(Conffd, (off_t)0, SEEK_SET) < 0)
			err(EF_SYS, "lseek on %s", Confname);
		if (ftruncate(Conffd, (off_t)0) < 0)
			err(EF_SYS, "ftruncate on %s", Confname);
		if ((fp = fdopen(Conffd, "w")) == NULL)
			err(EF_SYS, "fdopen on %s", Confname);
		conf_print(fp);
		if (fclose(fp) < 0)
			err(EF_SYS, "fclose on %s", Confname);
		Conffd = -1;
		Confchanged = B_FALSE;
	} else if (opts_count(opts, "v")) {
		(void) out("# %s unchanged\n", Confname);
	}

	if (Conffd != -1) {
		(void) close(Conffd);
		Conffd = -1;
	}
	if (Conflut) {
		lut_free(Conflut, free);
		Conflut = NULL;
	}
	if (Confentries) {
		fn_list_free(Confentries);
		Confentries = NULL;
	}
}

/*
 * conf_lookup -- lookup an entry in the config file
 */
char **
conf_lookup(const char *lhs)
{
	struct confinfo *cp = lut_lookup(Conflut, lhs);

	if (cp != NULL) {
		err_fileline(Confname, cp->cf_lineno);
		return (cp->cf_args);
	} else
		return (NULL);
}

/*
 * conf_opts -- return the parsed opts for an entry
 */
struct opts *
conf_opts(const char *lhs)
{
	struct confinfo *cp = lut_lookup(Conflut, lhs);

	if (cp != NULL) {
		if (cp->cf_opts)
			return (cp->cf_opts);	/* already parsed */
		err_fileline(Confname, cp->cf_lineno);
		cp->cf_opts = opts_parse(cp->cf_args, OPTF_CONF);
		return (cp->cf_opts);
	}
	return (opts_parse(NULL, OPTF_CONF));
}

/*
 * conf_replace -- replace an entry in the config file
 */
void
conf_replace(const char *lhs, struct opts *newopts)
{
	struct confinfo *cp = lut_lookup(Conflut, lhs);

	if (Conffd == -1)
		return;

	if (cp != NULL) {
		cp->cf_opts = newopts;
		cp->cf_args = NULL;
		if (newopts == NULL)
			cp->cf_flags |= CONFF_DELETED;
	} else
		fillconflist(0, lhs, NULL, newopts, NULL, 0);
	Confchanged = B_TRUE;
}

/*
 * conf_set -- set options for an entry in the config file
 */
void
conf_set(const char *entry, char *o, const char *optarg)
{
	struct confinfo *cp = lut_lookup(Conflut, entry);

	if (Conffd == -1)
		return;

	if (cp != NULL) {
		if (cp->cf_opts == NULL)
			cp->cf_opts = opts_parse(cp->cf_args, OPTF_CONF);
		cp->cf_flags &= ~CONFF_DELETED;
	} else {
		fillconflist(0, STRDUP(entry), NULL,
		    opts_parse(NULL, OPTF_CONF), NULL, 0);
		if ((cp = lut_lookup(Conflut, entry)) == NULL)
			err(0, "conf_set internal error");
	}
	(void) opts_set(cp->cf_opts, o, optarg);
	Confchanged = B_TRUE;
}

/*
 * conf_entries -- list all the entry names
 */
struct fn_list *
conf_entries(void)
{
	return (Confentries);
}

/* print the config file */
static void
conf_print(FILE *stream)
{
	struct confinfo *cp;

	for (cp = Confinfo; cp; cp = cp->cf_next) {
		if (cp->cf_flags & CONFF_DELETED)
			continue;
		if (cp->cf_entry) {
			char **p;

			opts_printword(cp->cf_entry, stream);
			if (cp->cf_opts) {
				/* existence of opts overrides args */
				opts_print(cp->cf_opts, stream, "fhnrvVw");
			} else if (cp->cf_args) {
				for (p = cp->cf_args; *p; p++) {
					(void) fprintf(stream, " ");
					opts_printword(*p, stream);
				}
			}
		}
		if (cp->cf_com) {
			if (cp->cf_entry)
				(void) fprintf(stream, " ");
			(void) fprintf(stream, "#%s", cp->cf_com);
		}
		(void) fprintf(stream, "\n");
	}
}

#ifdef	TESTMODULE

/*
 * test main for conf module, usage: a.out conffile
 */
int
main(int argc, char *argv[])
{
	err_init(argv[0]);
	setbuf(stdout, NULL);

	if (argc != 2)
		err(EF_RAW, "usage: %s conffile\n", argv[0]);

	conf_open(argv[1], 1);

	printf("conffile <%s>:\n", argv[1]);
	conf_print(stdout);

	conf_close(opts_parse(NULL, 0));

	err_done(0);
	/* NOTREACHED */
	return (0);
}

#endif	/* TESTMODULE */
