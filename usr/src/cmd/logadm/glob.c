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
 *
 * Copyright 2019 Joyent, Inc.
 *
 * logadm/glob.c -- globbing routines
 *
 * these routines support two kinds of globs.  first, the
 * usual kind of filename globbing, like:
 *
 * 	*.c
 * 	/var/log/syslog.?
 * 	log[0-9]*file
 * 	/var/apache/logs/x*{access,error}_log
 *
 * this is basically the same syntax that csh supports for globs and
 * is provided by the routine glob_glob() which takes a filename and
 * returns a list of filenames that match the glob.
 *
 * the second type is something called a "reglob" which is a pathname
 * where the components are regular expressions as described in regex(3c).
 * some examples:
 *
 * 	.*\.c
 * 	/var/log/syslog\..
 * 	log[0-9].*file
 * 	/var/log/syslog\.([0-9]+)$0
 *
 * the last example uses the ()$n form to assign a numeric extension
 * on a filename to the "n" value kept by the fn routines with each
 * filename (see fn_setn() in fn.c).  logadm uses this mechanism to
 * correctly sort lognames when templates containing $n are used.
 *
 * the routine glob_reglob() is used to expand reglobs.  glob_glob()
 * is implemented by expanding the curly braces, converting the globs
 * to reglobs, and then passing the work to glob_reglob().
 *
 * finally, since expanding globs and reglobs requires doing a stat(2)
 * on the files, we store the resulting stat information in the filename
 * struct (see fn_setstat() in fn.c).
 *
 * the glob(3c) routines are not used here since they don't support
 * braces, and don't support the more powerful reglobs required by logadm.
 */

#include <stdio.h>
#include <libintl.h>
#include <stdlib.h>
#include <libgen.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <dirent.h>
#include "err.h"
#include "fn.h"
#include "glob.h"

/* forward declarations for functions used internally by this module */
static struct fn_list *glob_debrace(struct fn *fnp);
static struct fn_list *glob_reglob_list(struct fn_list *fnlp);
static boolean_t glob_magic(struct fn *fnp);

/* expand curly braces (like file{one,two,three}name) */
static struct fn_list *
glob_debrace(struct fn *fnp)
{
	struct fn_list *ret = fn_list_new(NULL);
	struct fn_list *newret;
	char *sp = fn_s(fnp);
	char *left;
	char *right;
	char *comma;

	/* start with an empty string in the list */
	fn_list_adds(ret, "");

	/* while braces remain... */
	while (sp != NULL && (left = strchr(sp, '{')) != NULL)
		if ((right = strchr(left, '}')) == NULL) {
			err(EF_FILE|EF_JMP, "Missing }");
		} else {
			/* stuff before "left" is finished */
			fn_list_appendrange(ret, sp, left);

			/* stuff after "right" still need processing */
			sp = right + 1;

			if (left + 1 == right)
				continue;	/* just an empty {} */

			/* stuff between "left" and "right" is comma-sep list */
			left++;
			newret = fn_list_new(NULL);
			while ((comma = strchr(left, ',')) != NULL) {
				struct fn_list *dup = fn_list_dup(ret);

				/* stuff from left to comma is one variant */
				fn_list_appendrange(dup, left, comma);
				fn_list_addfn_list(newret, dup);
				left = comma + 1;
			}
			/* what's left is the last item in the list */
			fn_list_appendrange(ret, left, right);
			fn_list_addfn_list(newret, ret);
			ret = newret;
		}

	/* anything remaining in "s" is finished */
	fn_list_appendrange(ret, sp, &sp[strlen(sp)]);
	return (ret);
}

/* return true if filename contains any "magic" characters (*,?,[) */
static boolean_t
glob_magic(struct fn *fnp)
{
	char *s = fn_s(fnp);

	for (; s != NULL && *s; s++)
		if (*s == '*' ||
		    *s == '?' ||
		    *s == '[')
			return (B_TRUE);

	return (B_FALSE);
}

/*
 * glob_glob -- given a filename glob, return the list of matching filenames
 *
 * fn_setn() and fn_setstat() are called to set the "n" and stat information
 * for the resulting filenames.
 */
struct fn_list *
glob_glob(struct fn *fnp)
{
	struct fn_list *tmplist = glob_debrace(fnp);
	struct fn_list *ret;
	struct fn *nextfnp;
	struct fn *newfnp;
	int magic = 0;

	/* debracing produced NULL list? */
	if (tmplist == NULL)
		return (NULL);

	/* see if anything in list contains magic characters */
	fn_list_rewind(tmplist);
	while ((nextfnp = fn_list_next(tmplist)) != NULL)
		if (glob_magic(nextfnp)) {
			magic = 1;
			break;
		}

	if (!magic)
		return (tmplist);	/* no globs to expand */

	/* foreach name in the list, call glob_glob() to expand it */
	fn_list_rewind(tmplist);
	ret = fn_list_new(NULL);
	while ((nextfnp = fn_list_next(tmplist)) != NULL) {
		newfnp = glob_to_reglob(nextfnp);
		fn_list_addfn(ret, newfnp);
	}
	fn_list_free(tmplist);
	tmplist = ret;
	ret = glob_reglob_list(tmplist);
	fn_list_free(tmplist);

	return (ret);
}

/*
 * glob_glob_list -- given a list of filename globs, return all matches
 */
struct fn_list *
glob_glob_list(struct fn_list *fnlp)
{
	struct fn_list *ret = fn_list_new(NULL);
	struct fn *fnp;

	fn_list_rewind(fnlp);
	while ((fnp = fn_list_next(fnlp)) != NULL)
		fn_list_addfn_list(ret, glob_glob(fnp));
	return (ret);
}

/*
 * glob_reglob -- given a filename reglob, return a list of matching filenames
 *
 * this routine does all the hard work in this module.
 */
struct fn_list *
glob_reglob(struct fn *fnp)
{
	struct fn_list *ret = fn_list_new(NULL);
	struct fn_list *newret;
	struct fn *nextfnp;
	char *mys = STRDUP(fn_s(fnp));
	char *sp = mys;
	char *slash;
	int skipdotfiles;
	char *re;
	char ret0[MAXPATHLEN];


	/* start with the initial directory in the list */
	if (*sp == '/') {
		fn_list_adds(ret, "/");
		while (*sp == '/')
			sp++;
	} else
		fn_list_adds(ret, "./");

	/* while components remain... */
	do {
		if ((slash = strchr(sp, '/')) != NULL) {
			*slash++ = '\0';
			/* skip superfluous slashes */
			while (*slash == '/')
				slash++;
		}

		/* dot files are skipped unless a dot was specifically given */
		if (sp[0] == '\\' && sp[1] == '.')
			skipdotfiles = 0;
		else
			skipdotfiles = 1;

		/* compile the regex */
		if ((re = regcmp("^", sp, "$", (char *)0)) == NULL)
			err(EF_FILE|EF_JMP, "regcmp failed on <%s>", sp);

		/* apply regex to every filename we've matched so far */
		newret = fn_list_new(NULL);
		fn_list_rewind(ret);
		while ((nextfnp = fn_list_next(ret)) != NULL) {
			DIR *dirp;
			struct dirent *dp;

			/* go through directory looking for matches */
			if ((dirp = opendir(fn_s(nextfnp))) == NULL)
				continue;

			while ((dp = readdir(dirp)) != NULL) {
				if (skipdotfiles && dp->d_name[0] == '.')
					continue;
				*ret0 = '\0';
				if (regex(re, dp->d_name, ret0)) {
					struct fn *matchfnp = fn_dup(nextfnp);
					struct stat stbuf;
					int n;

					fn_puts(matchfnp, dp->d_name);

					if (stat(fn_s(matchfnp), &stbuf) < 0) {
						fn_free(matchfnp);
						continue;
					}

					/* skip non-dirs if more components */
					if (slash &&
					    (stbuf.st_mode & S_IFMT) !=
					    S_IFDIR) {
						fn_free(matchfnp);
						continue;
					}

					/*
					 * component matched, fill in "n"
					 * value, stat information, and
					 * append component to directory
					 * name just searched.
					 */

					if (*ret0)
						n = atoi(ret0);
					else
						n = -1;
					fn_setn(matchfnp, n);
					fn_setstat(matchfnp, &stbuf);

					if (slash)
						fn_putc(matchfnp, '/');

					fn_list_addfn(newret, matchfnp);
				}
			}
			(void) closedir(dirp);
		}
		fn_list_free(ret);
		ret = newret;
		sp = slash;
	} while (slash);

	FREE(mys);

	return (ret);
}

/* reglob a list of filenames */
static struct fn_list *
glob_reglob_list(struct fn_list *fnlp)
{
	struct fn_list *ret = fn_list_new(NULL);
	struct fn *fnp;

	fn_list_rewind(fnlp);
	while ((fnp = fn_list_next(fnlp)) != NULL)
		fn_list_addfn_list(ret, glob_reglob(fnp));
	return (ret);
}

/*
 * glob_to_reglob -- convert a glob (*, ?, etc) to a reglob (.*, ., etc.)
 */
struct fn *
glob_to_reglob(struct fn *fnp)
{
	int c;
	struct fn *ret = fn_new(NULL);

	fn_rewind(fnp);
	while ((c = fn_getc(fnp)) != '\0')
		switch (c) {
		case '.':
		case '(':
		case ')':
		case '^':
		case '+':
		case '{':
		case '}':
		case '$':
			/* magic characters need backslash */
			fn_putc(ret, '\\');
			fn_putc(ret, c);
			break;
		case '?':
			/* change '?' to a single dot */
			fn_putc(ret, '.');
			break;
		case '*':
			/* change '*' to ".*" */
			fn_putc(ret, '.');
			fn_putc(ret, '*');
			break;
		default:
			fn_putc(ret, c);
		}

	return (ret);
}

#ifdef	TESTMODULE

/*
 * test main for glob module, usage: a.out [-r] [pattern...]
 *	-r means the patterns are reglobs instead of globs
 */
int
main(int argc, char *argv[])
{
	int i;
	int reglobs = 0;
	struct fn *argfnp = fn_new(NULL);
	struct fn *fnp;
	struct fn_list *fnlp;

	err_init(argv[0]);
	setbuf(stdout, NULL);

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-r") == 0) {
			reglobs = 1;
			continue;
		}

		if (SETJMP) {
			printf("    skipped due to errors\n");
			continue;
		} else {
			printf("<%s>:\n", argv[i]);
			fn_renew(argfnp, argv[i]);
			if (reglobs)
				fnlp = glob_reglob(argfnp);
			else
				fnlp = glob_glob(argfnp);
		}

		fn_list_rewind(fnlp);
		while ((fnp = fn_list_next(fnlp)) != NULL)
			printf("    <%s>\n", fn_s(fnp));

		printf("total size: %lld\n", fn_list_totalsize(fnlp));

		while ((fnp = fn_list_popoldest(fnlp)) != NULL) {
			printf("    oldest <%s>\n", fn_s(fnp));
			fn_free(fnp);
		}

		fn_list_free(fnlp);
	}
	fn_free(argfnp);

	err_done(0);
	/* NOTREACHED */
	return (0);
}

#endif	/* TESTMODULE */
