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
 * Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013, Joyent, Inc. All rights reserved.
 */

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
#include <limits.h>
#include "err.h"
#include "lut.h"
#include "fn.h"
#include "opts.h"
#include "conf.h"

/* forward declarations of functions private to this module */
static void fillconflist(int lineno, const char *entry,
    struct opts *opts, const char *com, int flags);
static void fillargs(char *arg);
static char *nexttok(char **ptrptr);
static void conf_print(FILE *cstream, FILE *tstream);

static const char *Confname;	/* name of the confile file */
static int Conffd = -1;		/* file descriptor for config file */
static char *Confbuf;		/* copy of the config file (a la mmap()) */
static int Conflen;		/* length of mmap'd config file area */
static const char *Timesname;	/* name of the timestamps file */
static int Timesfd = -1;	/* file descriptor for timestamps file */
static char *Timesbuf;		/* copy of the timestamps file (a la mmap()) */
static int Timeslen;		/* length of mmap'd timestamps area */
static int Singlefile;		/* Conf and Times in the same file */
static int Changed;		/* what changes need to be written back */
static int Canchange;		/* what changes can be written back */
static int Changing;		/* what changes have been requested */
#define	CHG_NONE	0
#define	CHG_TIMES	1
#define	CHG_BOTH	3

/*
 * our structured representation of the configuration file
 * is made up of a list of these
 */
struct confinfo {
	struct confinfo *cf_next;
	int cf_lineno;		/* line number in file */
	const char *cf_entry;	/* name of entry, if line has an entry */
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
fillconflist(int lineno, const char *entry,
    struct opts *opts, const char *com, int flags)
{
	struct confinfo *cp = MALLOC(sizeof (*cp));

	cp->cf_next = NULL;
	cp->cf_lineno = lineno;
	cp->cf_entry = entry;
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
 * scan the memory image of a file
 *	returns: 0: error, 1: ok, 3: -P option found
 */
static int
conf_scan(const char *fname, char *buf, int buflen, int timescan)
{
	int ret = 1;
	int lineno = 0;
	char *line;
	char *eline;
	char *ebuf;
	char *entry, *comment;

	ebuf = &buf[buflen];

	if (buf[buflen - 1] != '\n')
		err(EF_WARN|EF_FILE, "file %s doesn't end with newline, "
		    "last line ignored.", fname);

	for (line = buf; line < ebuf; line = eline) {
		char *ap;
		struct opts *opts = NULL;
		struct confinfo *cp;

		lineno++;
		err_fileline(fname, lineno);
		eline = line;
		comment = NULL;
		for (; eline < ebuf; eline++) {
			/* check for continued lines */
			if (comment == NULL && *eline == '\\' &&
			    eline + 1 < ebuf && *(eline + 1) == '\n') {
				*eline = ' ';
				*(eline + 1) = ' ';
				lineno++;
				err_fileline(fname, lineno);
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
		if (eline >= ebuf) {
			/* discard trailing unterminated line */
			continue;
		}
		*eline++ = '\0';

		/*
		 * now we have the entry, if any, at "line"
		 * and the comment, if any, at "comment"
		 */

		/* entry is first token */
		entry = nexttok(&line);
		if (entry == NULL) {
			/* it's just a comment line */
			if (!timescan)
				fillconflist(lineno, entry, NULL, comment, 0);
			continue;
		}
		if (strcmp(entry, "logadm-version") == 0) {
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
				err(0, "%s version not supported "
				    "by this version of logadm.",
				    fname);
			continue;
		}

		/* form an argv array */
		ArgsI = 0;
		while (ap = nexttok(&line))
			fillargs(ap);
		Args[ArgsI] = NULL;

		LOCAL_ERR_BEGIN {
			if (SETJMP) {
				err(EF_FILE, "cannot process invalid entry %s",
				    entry);
				ret = 0;
				LOCAL_ERR_BREAK;
			}

			if (timescan) {
				/* append to config options */
				cp = lut_lookup(Conflut, entry);
				if (cp != NULL) {
					opts = cp->cf_opts;
				}
			}
			opts = opts_parse(opts, Args, OPTF_CONF);
			if (!timescan || cp == NULL) {
				/*
				 * If we're not doing timescan, we track this
				 * entry.  If we are doing timescan and have
				 * what looks like an orphaned entry (cp ==
				 * NULL) then we also have to track. See the
				 * comment in rotatelog. We need to allow for
				 * the case where the logname is not the same as
				 * the log file name.
				 */
				fillconflist(lineno, entry, opts, comment, 0);
			}
		LOCAL_ERR_END }

		if (ret == 1 && opts && opts_optarg(opts, "P") != NULL)
			ret = 3;
	}

	err_fileline(NULL, 0);
	return (ret);
}

/*
 * conf_open -- open the configuration file, lock it if we have write perms
 */
int
conf_open(const char *cfname, const char *tfname, struct opts *cliopts)
{
	struct stat stbuf1, stbuf2, stbuf3;
	struct flock	flock;
	int ret;

	Confname = cfname;
	Timesname = tfname;
	Confentries = fn_list_new(NULL);
	Changed = CHG_NONE;

	Changing = CHG_TIMES;
	if (opts_count(cliopts, "Vn") != 0)
		Changing = CHG_NONE;
	else if (opts_count(cliopts, "rw") != 0)
		Changing = CHG_BOTH;

	Singlefile = strcmp(Confname, Timesname) == 0;
	if (Singlefile && Changing == CHG_TIMES)
		Changing = CHG_BOTH;

	/* special case this so we don't even try locking the file */
	if (strcmp(Confname, "/dev/null") == 0)
		return (0);

	while (Conffd == -1) {
		Canchange = CHG_BOTH;
		if ((Conffd = open(Confname, O_RDWR)) < 0) {
			if (Changing == CHG_BOTH)
				err(EF_SYS, "open %s", Confname);
			Canchange = CHG_TIMES;
			if ((Conffd = open(Confname, O_RDONLY)) < 0)
				err(EF_SYS, "open %s", Confname);
		}

		flock.l_type = (Canchange == CHG_BOTH) ? F_WRLCK : F_RDLCK;
		flock.l_whence = SEEK_SET;
		flock.l_start = 0;
		flock.l_len = 1;
		if (fcntl(Conffd, F_SETLKW, &flock) < 0)
			err(EF_SYS, "flock on %s", Confname);

		/* wait until after file is locked to get filesize */
		if (fstat(Conffd, &stbuf1) < 0)
			err(EF_SYS, "fstat on %s", Confname);

		/* verify that we've got a lock on the active file */
		if (stat(Confname, &stbuf2) < 0 ||
		    !(stbuf2.st_dev == stbuf1.st_dev &&
		    stbuf2.st_ino == stbuf1.st_ino)) {
			/* wrong config file, try again */
			(void) close(Conffd);
			Conffd = -1;
		}
	}

	while (!Singlefile && Timesfd == -1) {
		if ((Timesfd = open(Timesname, O_CREAT|O_RDWR, 0644)) < 0) {
			if (Changing != CHG_NONE)
				err(EF_SYS, "open %s", Timesname);
			Canchange = CHG_NONE;
			if ((Timesfd = open(Timesname, O_RDONLY)) < 0)
				err(EF_SYS, "open %s", Timesname);
		}

		flock.l_type = (Canchange != CHG_NONE) ? F_WRLCK : F_RDLCK;
		flock.l_whence = SEEK_SET;
		flock.l_start = 0;
		flock.l_len = 1;
		if (fcntl(Timesfd, F_SETLKW, &flock) < 0)
			err(EF_SYS, "flock on %s", Timesname);

		/* wait until after file is locked to get filesize */
		if (fstat(Timesfd, &stbuf2) < 0)
			err(EF_SYS, "fstat on %s", Timesname);

		/* verify that we've got a lock on the active file */
		if (stat(Timesname, &stbuf3) < 0 ||
		    !(stbuf2.st_dev == stbuf3.st_dev &&
		    stbuf2.st_ino == stbuf3.st_ino)) {
			/* wrong timestamp file, try again */
			(void) close(Timesfd);
			Timesfd = -1;
			continue;
		}

		/* check that Timesname isn't an alias for Confname */
		if (stbuf2.st_dev == stbuf1.st_dev &&
		    stbuf2.st_ino == stbuf1.st_ino)
			err(0, "Timestamp file %s can't refer to "
			    "Configuration file %s", Timesname, Confname);
	}

	Conflen = stbuf1.st_size;
	Timeslen = stbuf2.st_size;

	if (Conflen == 0)
		return (1);	/* empty file, don't bother parsing it */

	if ((Confbuf = (char *)mmap(0, Conflen,
	    PROT_READ | PROT_WRITE, MAP_PRIVATE, Conffd, 0)) == (char *)-1)
		err(EF_SYS, "mmap on %s", Confname);

	ret = conf_scan(Confname, Confbuf, Conflen, 0);
	if (ret == 3 && !Singlefile && Canchange == CHG_BOTH) {
		/*
		 * arrange to transfer any timestamps
		 * from conf_file to timestamps_file
		 */
		Changing = Changed = CHG_BOTH;
	}

	if (Timesfd != -1 && Timeslen != 0) {
		if ((Timesbuf = (char *)mmap(0, Timeslen,
		    PROT_READ | PROT_WRITE, MAP_PRIVATE,
		    Timesfd, 0)) == (char *)-1)
			err(EF_SYS, "mmap on %s", Timesname);
		ret &= conf_scan(Timesname, Timesbuf, Timeslen, 1);
	}

	/*
	 * possible future enhancement:  go through and mark any entries:
	 * 		logfile -P <date>
	 * as DELETED if the logfile doesn't exist
	 */

	return (ret);
}

/*
 * conf_close -- close the configuration file
 */
void
conf_close(struct opts *opts)
{
	char cuname[PATH_MAX], tuname[PATH_MAX];
	int cfd, tfd;
	FILE *cfp = NULL, *tfp = NULL;
	boolean_t safe_update = B_TRUE;

	if (Changed == CHG_NONE || opts_count(opts, "n") != 0) {
		if (opts_count(opts, "v"))
			(void) out("# %s and %s unchanged\n",
			    Confname, Timesname);
		goto cleanup;
	}

	if (Debug > 1) {
		(void) fprintf(stderr, "conf_close, saving logadm context:\n");
		conf_print(stderr, NULL);
	}

	cuname[0] = tuname[0] = '\0';
	LOCAL_ERR_BEGIN {
		if (SETJMP) {
			safe_update = B_FALSE;
			LOCAL_ERR_BREAK;
		}
		if (Changed == CHG_BOTH) {
			if (Canchange != CHG_BOTH)
				err(EF_JMP, "internal error: attempting "
				    "to update %s without locking", Confname);
			(void) snprintf(cuname, sizeof (cuname), "%sXXXXXX",
			    Confname);
			if ((cfd = mkstemp(cuname)) == -1)
				err(EF_SYS|EF_JMP, "open %s replacement",
				    Confname);
			if (opts_count(opts, "v"))
				(void) out("# writing changes to %s\n", cuname);
			if (fchmod(cfd, 0644) == -1)
				err(EF_SYS|EF_JMP, "chmod %s", cuname);
			if ((cfp = fdopen(cfd, "w")) == NULL)
				err(EF_SYS|EF_JMP, "fdopen on %s", cuname);
		} else {
			/* just toss away the configuration data */
			cfp = fopen("/dev/null", "w");
		}
		if (!Singlefile) {
			if (Canchange == CHG_NONE)
				err(EF_JMP, "internal error: attempting "
				    "to update %s without locking", Timesname);
			(void) snprintf(tuname, sizeof (tuname), "%sXXXXXX",
			    Timesname);
			if ((tfd = mkstemp(tuname)) == -1)
				err(EF_SYS|EF_JMP, "open %s replacement",
				    Timesname);
			if (opts_count(opts, "v"))
				(void) out("# writing changes to %s\n", tuname);
			if (fchmod(tfd, 0644) == -1)
				err(EF_SYS|EF_JMP, "chmod %s", tuname);
			if ((tfp = fdopen(tfd, "w")) == NULL)
				err(EF_SYS|EF_JMP, "fdopen on %s", tuname);
		}

		conf_print(cfp, tfp);
		if (fclose(cfp) < 0)
			err(EF_SYS|EF_JMP, "fclose on %s", Confname);
		if (tfp != NULL && fclose(tfp) < 0)
			err(EF_SYS|EF_JMP, "fclose on %s", Timesname);
	LOCAL_ERR_END }

	if (!safe_update) {
		if (cuname[0] != 0)
			(void) unlink(cuname);
		if (tuname[0] != 0)
			(void) unlink(tuname);
		err(EF_JMP, "unsafe to update configuration file "
		    "or timestamps");
		return;
	}

	/* rename updated files into place */
	if (cuname[0] != '\0')
		if (rename(cuname, Confname) < 0)
			err(EF_SYS, "rename %s to %s", cuname, Confname);
	if (tuname[0] != '\0')
		if (rename(tuname, Timesname) < 0)
			err(EF_SYS, "rename %s to %s", tuname, Timesname);
	Changed = CHG_NONE;

cleanup:
	if (Conffd != -1) {
		(void) close(Conffd);
		Conffd = -1;
	}
	if (Timesfd != -1) {
		(void) close(Timesfd);
		Timesfd = -1;
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
void *
conf_lookup(const char *lhs)
{
	struct confinfo *cp = lut_lookup(Conflut, lhs);

	if (cp != NULL)
		err_fileline(Confname, cp->cf_lineno);
	return (cp);
}

/*
 * conf_opts -- return the parsed opts for an entry
 */
struct opts *
conf_opts(const char *lhs)
{
	struct confinfo *cp = lut_lookup(Conflut, lhs);

	if (cp != NULL)
		return (cp->cf_opts);
	return (opts_parse(NULL, NULL, OPTF_CONF));
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
		/* cp->cf_args = NULL; */
		if (newopts == NULL)
			cp->cf_flags |= CONFF_DELETED;
	} else
		fillconflist(0, lhs, newopts, NULL, 0);

	Changed = CHG_BOTH;
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
		cp->cf_flags &= ~CONFF_DELETED;
	} else {
		fillconflist(0, STRDUP(entry),
		    opts_parse(NULL, NULL, OPTF_CONF), NULL, 0);
		if ((cp = lut_lookup(Conflut, entry)) == NULL)
			err(0, "conf_set internal error");
	}
	(void) opts_set(cp->cf_opts, o, optarg);
	if (strcmp(o, "P") == 0)
		Changed |= CHG_TIMES;
	else
		Changed = CHG_BOTH;
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
conf_print(FILE *cstream, FILE *tstream)
{
	struct confinfo *cp;
	char *exclude_opts = "PFfhnrvVw";
	const char *timestamp;

	if (tstream == NULL) {
		exclude_opts++;		/* -P option goes to config file */
	} else {
		(void) fprintf(tstream, gettext(
		    "# This file holds internal data for logadm(1M).\n"
		    "# Do not edit.\n"));
	}
	for (cp = Confinfo; cp; cp = cp->cf_next) {
		if (cp->cf_flags & CONFF_DELETED)
			continue;
		if (cp->cf_entry) {
			opts_printword(cp->cf_entry, cstream);
			if (cp->cf_opts)
				opts_print(cp->cf_opts, cstream, exclude_opts);
			/* output timestamps to tstream */
			if (tstream != NULL && (timestamp =
			    opts_optarg(cp->cf_opts, "P")) != NULL) {
				opts_printword(cp->cf_entry, tstream);
				(void) fprintf(tstream, " -P ");
				opts_printword(timestamp, tstream);
				(void) fprintf(tstream, "\n");
			}
		}
		if (cp->cf_com) {
			if (cp->cf_entry)
				(void) fprintf(cstream, " ");
			(void) fprintf(cstream, "#%s", cp->cf_com);
		}
		(void) fprintf(cstream, "\n");
	}
}

#ifdef	TESTMODULE

/*
 * test main for conf module, usage: a.out conffile
 */
int
main(int argc, char *argv[])
{
	struct opts *opts;

	err_init(argv[0]);
	setbuf(stdout, NULL);
	opts_init(Opttable, Opttable_cnt);

	opts = opts_parse(NULL, NULL, 0);

	if (argc != 2)
		err(EF_RAW, "usage: %s conffile\n", argv[0]);

	conf_open(argv[1], argv[1], opts);

	printf("conffile <%s>:\n", argv[1]);
	conf_print(stdout, NULL);

	conf_close(opts);

	err_done(0);
	/* NOTREACHED */
	return (0);
}

#endif	/* TESTMODULE */
