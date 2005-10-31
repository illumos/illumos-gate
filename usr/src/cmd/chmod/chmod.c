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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T			*/
/*	  All Rights Reserved						*/
/*									*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * chmod option mode files
 * where
 *	mode is [ugoa][+-=][rwxXlstugo] or an octal number
 *	mode is [<+|->A[# <number] ]<aclspec>
 *	option is -R and -f
 */

/*
 *  Note that many convolutions are necessary
 *  due to the re-use of bits between locking
 *  and setgid
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <locale.h>
#include <string.h>	/* strerror() */
#include <stdarg.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>
#include <sys/acl.h>
#include <aclutils.h>

static int	rflag;
static int	fflag;

extern int	optind;
extern int	errno;

static int	mac;		/* Alternate to argc (for parseargs) */
static char	**mav;		/* Alternate to argv (for parseargs) */

static char	*ms;		/* Points to the mode argument */

#define	ACL_ADD		1
#define	ACL_DELETE	2
#define	ACL_SLOT_DELETE 3
#define	ACL_REPLACE	4
#define	ACL_STRIP	5

typedef struct acl_args {
	acl_t	*acl_aclp;
	int	acl_slot;
	int	acl_action;
} acl_args_t;

extern mode_t
newmode_common(char *ms, mode_t new_mode, mode_t umsk, char *file, char *path,
	o_mode_t *group_clear_bits, o_mode_t *group_set_bits);

static int
dochmod(char *name, char *path, mode_t umsk, acl_args_t *aclp),
chmodr(char *dir, char *path, mode_t mode, mode_t umsk, acl_args_t *aclp);
static int doacl(char *file, struct stat *st, acl_args_t *aclp);

static void handle_acl(char *name, o_mode_t group_clear_bits,
    o_mode_t group_set_bits);

static void usage(void);

void errmsg(int severity, int code, char *format, ...);

static void parseargs(int ac, char *av[]);

int
parse_acl_args(char *arg, acl_args_t **acl_args);

int
main(int argc, char *argv[])
{
	int i, c;
	int status = 0;
	mode_t umsk;
	acl_args_t *acl_args = NULL;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	parseargs(argc, argv);

	while ((c = getopt(mac, mav, "Rf")) != EOF) {
		switch (c) {
		case 'R':
			rflag++;
			break;
		case 'f':
			fflag++;
			break;
		case '?':
			usage();
			exit(2);
		}
	}

	/*
	 * Check for sufficient arguments
	 * or a usage error.
	 */

	mac -= optind;
	mav += optind;

	if (mac >= 2 && (mav[0][0] == 'A')) {
		if (parse_acl_args(*mav, &acl_args)) {
			usage();
			exit(2);
		}
	} else {
		if (mac < 2) {
			usage();
			exit(2);
		}
	}

	ms = mav[0];

	umsk = umask(0);
	(void) umask(umsk);

	for (i = 1; i < mac; i++) {
		status += dochmod(mav[i], mav[i], umsk, acl_args);
	}

	return (fflag ? 0 : status);
}

static int
dochmod(char *name, char *path, mode_t umsk, acl_args_t *aclp)
{
	static struct stat st;
	int linkflg = 0;
	o_mode_t	group_clear_bits, group_set_bits;

	if (lstat(name, &st) < 0) {
		errmsg(2, 0, gettext("can't access %s\n"), path);
		return (1);
	}

	if ((st.st_mode & S_IFMT) == S_IFLNK) {
		linkflg = 1;
		if (stat(name, &st) < 0) {
			errmsg(2, 0, gettext("can't access %s\n"), path);
			return (1);
		}
	}

	/* Do not recurse if directory is object of symbolic link */
	if (rflag && ((st.st_mode & S_IFMT) == S_IFDIR) && !linkflg)
		return (chmodr(name, path, st.st_mode, umsk, aclp));

	if (aclp) {
		return (doacl(name, &st, aclp));
	} else if (chmod(name, newmode_common(ms, st.st_mode, umsk, name, path,
	    &group_clear_bits, &group_set_bits)) == -1) {
		errmsg(2, 0, gettext("can't change %s\n"), path);
		return (1);
	}

	/*
	 * If the group permissions of the file are being modified,
	 * make sure that the file's ACL (if it has one) is
	 * modified also, since chmod is supposed to apply group
	 * permissions changes to both the acl mask and the
	 * general group permissions.
	 */
	if (group_clear_bits || group_set_bits)
		handle_acl(name, group_clear_bits, group_set_bits);

	return (0);
}


static int
chmodr(char *dir, char *path,  mode_t mode, mode_t umsk, acl_args_t *aclp)
{

	DIR *dirp;
	struct dirent *dp;
	char savedir[PATH_MAX];			/* dir name to restore */
	char currdir[PATH_MAX+1];		/* current dir name + '/' */
	char parentdir[PATH_MAX+1];		/* parent dir name  + '/' */
	int ecode;
	struct stat st;
	o_mode_t	group_clear_bits, group_set_bits;

	if (getcwd(savedir, PATH_MAX) == 0)
		errmsg(2, 255, gettext("chmod: could not getcwd %s\n"),
		    savedir);

	/*
	 * Change what we are given before doing it's contents
	 */
	if (aclp) {
		if (lstat(dir, &st) < 0) {
			errmsg(2, 0, gettext("can't access %s\n"), path);
			return (1);
		}
		if (doacl(dir, &st, aclp) != 0)
			return (1);
	} else if (chmod(dir, newmode_common(ms, mode, umsk, dir, path,
	    &group_clear_bits, &group_set_bits)) < 0) {
		errmsg(2, 0, gettext("can't change %s\n"), path);
		return (1);
	}

	/*
	 * If the group permissions of the file are being modified,
	 * make sure that the file's ACL (if it has one) is
	 * modified also, since chmod is supposed to apply group
	 * permissions changes to both the acl mask and the
	 * general group permissions.
	 */

	if (aclp == NULL) { /* only necessary when not setting ACL */
		if (group_clear_bits || group_set_bits)
			handle_acl(dir, group_clear_bits, group_set_bits);
	}

	if (chdir(dir) < 0) {
		errmsg(2, 0, "%s/%s: %s\n", savedir, dir, strerror(errno));
		return (1);
	}
	if ((dirp = opendir(".")) == NULL) {
		errmsg(2, 0, "%s\n", strerror(errno));
		return (1);
	}
	dp = readdir(dirp);
	dp = readdir(dirp); /* read "." and ".." */
	ecode = 0;

	/*
	 * Save parent directory path before recursive chmod.
	 * We'll need this for error printing purposes. Add
	 * a trailing '/' to the path except in the case where
	 * the path is just '/'
	 */

	(void) strcpy(parentdir, path);
	if (strcmp(path, "/") != 0)
		(void) strcat(parentdir, "/");

	for (dp = readdir(dirp); dp != NULL; dp = readdir(dirp))  {
		(void) strcpy(currdir, parentdir);
		(void) strcat(currdir, dp->d_name);
		ecode += dochmod(dp->d_name, currdir, umsk, aclp);
	}
	(void) closedir(dirp);
	if (chdir(savedir) < 0) {
		errmsg(2, 255, gettext("can't change back to %s\n"), savedir);
	}
	return (ecode ? 1 : 0);
}

/* PRINTFLIKE3 */
void
errmsg(int severity, int code, char *format, ...)
{
	va_list ap;
	static char *msg[] = {
	"",
	"ERROR",
	"WARNING",
	""
	};

	va_start(ap, format);

	/*
	 * Always print error message if this is a fatal error (code == 0);
	 * otherwise, print message if fflag == 0 (no -f option specified)
	 */
	if (!fflag || (code != 0)) {
		(void) fprintf(stderr,
			"chmod: %s: ", gettext(msg[severity]));
		(void) vfprintf(stderr, format, ap);
	}

	va_end(ap);

	if (code != 0)
		exit(fflag ? 0 : code);
}

static void
usage(void)
{
	(void) fprintf(stderr, gettext(
	    "usage:\tchmod [-fR] <absolute-mode> file ...\n"));

	(void) fprintf(stderr, gettext(
	    "\tchmod [-fR] <ACL-operation> file ...\n"));

	(void) fprintf(stderr, gettext(
	    "\tchmod [-fR] <symbolic-mode-list> file ...\n"));


	(void) fprintf(stderr, gettext(
	    "where \t<symbolic-mode-list> is a comma-separated list of\n"));

	(void) fprintf(stderr, gettext(
	    "\t[ugoa]{+|-|=}[rwxXlstugo]\n"));

	(void) fprintf(stderr, gettext(
	    "where \t<ACL-operation> is one of the following\n"));
	(void) fprintf(stderr, gettext("\tA-<acl_specification>\n"));
	(void) fprintf(stderr, gettext("\tA[number]-\n"));
	(void) fprintf(stderr, gettext(
	    "\tA[number]{+|=}<acl_specification>\n"));
	(void) fprintf(stderr, gettext(
	    "where \t<acl-specification> is a comma-separated list of ACEs\n"));
}

/*
 *  parseargs - generate getopt-friendly argument list for backwards
 *		compatibility with earlier Solaris usage (eg, chmod -w
 *		foo).
 *
 *  assumes the existence of a static set of alternates to argc and argv,
 *  (namely, mac, and mav[]).
 *
 */

static void
parseargs(int ac, char *av[])
{
	int i;			/* current argument			*/
	int fflag;		/* arg list contains "--"		*/
	size_t mav_num;		/* number of entries in mav[]		*/

	/*
	 * We add an extra argument slot, in case we need to jam a "--"
	 * argument into the list.
	 */

	mav_num = (size_t)ac+2;

	if ((mav = calloc(mav_num, sizeof (char *))) == NULL) {
		perror("chmod");
		exit(2);
	}

	/* scan for the use of "--" in the argument list */

	for (fflag = i = 0; i < ac; i ++) {
		if (strcmp(av[i], "--") == 0)
		    fflag = 1;
	}

	/* process the arguments */

	for (i = mac = 0;
	    (av[i] != (char *)NULL) && (av[i][0] != (char)NULL);
	    i++) {
		if (!fflag && av[i][0] == '-') {
			/*
			 *  If there is not already a "--" argument specified,
			 *  and the argument starts with '-' but does not
			 *  contain any of the official option letters, then it
			 *  is probably a mode argument beginning with '-'.
			 *  Force a "--" into the argument stream in front of
			 *  it.
			 */

			if ((strchr(av[i], 'R') == NULL &&
			    strchr(av[i], 'f') == NULL)) {
				mav[mac++] = strdup("--");
			}
		}

		mav[mac++] = strdup(av[i]);
	}

	mav[mac] = (char *)NULL;
}

int
parse_acl_args(char *arg, acl_args_t **acl_args)
{
	acl_t *new_acl = NULL;
	int slot;
	int error;
	int len;
	int action;
	acl_args_t *new_acl_args;
	char *acl_spec = NULL;
	char *end;

	if (arg[0] != 'A')
		return (1);

	slot = strtol(&arg[1], &end, 10);

	len = strlen(arg);
	switch (*end) {
	case '+':
		action = ACL_ADD;
		acl_spec = ++end;
		break;
	case '-':
		if (len == 2 && arg[0] == 'A' && arg[1] == '-')
			action = ACL_STRIP;
		else
			action = ACL_DELETE;
		if (action != ACL_STRIP) {
			acl_spec = ++end;
			if (acl_spec[0] == '\0') {
				action = ACL_SLOT_DELETE;
				acl_spec = NULL;
			} else if (arg[1] != '-')
				return (1);
		}
		break;
	case '=':
		action = ACL_REPLACE;
		acl_spec = ++end;
		break;
	default:
		return (1);
	}

	if ((action == ACL_REPLACE || action == ACL_ADD) && acl_spec[0] == '\0')
		return (1);

	if (acl_spec) {
		if (error = acl_fromtext(acl_spec, &new_acl)) {
			errmsg(1, 1, "%s\n", acl_strerror(error));
			return (1);
		}
	}

	new_acl_args = malloc(sizeof (acl_args_t));
	if (new_acl_args == NULL)
		return (1);

	new_acl_args->acl_aclp = new_acl;
	new_acl_args->acl_slot = slot;
	new_acl_args->acl_action = action;

	*acl_args = new_acl_args;

	return (0);
}

/*
 * This function is called whenever the group permissions of a file
 * is being modified.  According to the chmod(1) manpage, any
 * change made to the group permissions must be applied to both
 * the acl mask and the acl's GROUP_OBJ.  The chmod(2) already
 * set the mask, so this routine needs to make the same change
 * to the GROUP_OBJ.
 */
static void
handle_acl(char *name, o_mode_t group_clear_bits, o_mode_t group_set_bits)
{
	int aclcnt, n;
	aclent_t *aclp, *tp;
	o_mode_t newperm;

	/*
	 * if this file system support ace_t acl's
	 * then simply return since we don't have an
	 * acl mask to deal with
	 */
	if (pathconf(name, _PC_ACL_ENABLED) == _ACL_ACE_ENABLED)
		return;

	if ((aclcnt = acl(name, GETACLCNT, 0, NULL)) <= MIN_ACL_ENTRIES)
		return;	/* it's just a trivial acl; no need to change it */

	if ((aclp = (aclent_t *)malloc((sizeof (aclent_t)) * aclcnt))
	    == NULL) {
		perror("chmod");
		exit(2);
	}

	if (acl(name, GETACL, aclcnt, aclp) < 0) {
		free(aclp);
		(void) fprintf(stderr, "chmod: ");
		perror(name);
		return;
	}

	for (tp = aclp, n = aclcnt; n--; tp++) {
		if (tp->a_type == GROUP_OBJ) {
			newperm = tp->a_perm;
			if (group_clear_bits != 0)
				newperm &= ~group_clear_bits;
			if (group_set_bits != 0)
				newperm |= group_set_bits;
			if (newperm != tp->a_perm) {
				tp->a_perm = newperm;
				if (acl(name, SETACL, aclcnt, aclp)
				    < 0) {
					(void) fprintf(stderr, "chmod: ");
					perror(name);
				}
			}
			break;
		}
	}
	free(aclp);
}

static int
doacl(char *file, struct stat *st, acl_args_t *acl_args)
{
	acl_t *aclp;
	acl_t *set_aclp;
	int error = 0;
	void *to, *from;
	int len;
	int isdir;

	isdir = S_ISDIR(st->st_mode);

	error = acl_get(file, 0, &aclp);

	if (error != 0) {
		errmsg(1, 1, "%s\n", acl_strerror(error));
		return (1);
	}

	switch (acl_args->acl_action) {
	case ACL_ADD:
		if ((error = acl_addentries(aclp,
			acl_args->acl_aclp, acl_args->acl_slot)) != 0) {
				errmsg(1, 1, "%s\n", acl_strerror(error));
				acl_free(aclp);
				return (1);
		}
		set_aclp = aclp;
		break;
	case ACL_SLOT_DELETE:

		if (acl_args->acl_slot + 1 > aclp->acl_cnt) {
			errmsg(1, 1,
			    gettext("Invalid slot specified for removal\n"));
			acl_free(aclp);
			return (1);
		}

		if (acl_args->acl_slot == 0 && aclp->acl_cnt == 1) {
			errmsg(1, 1,
			    gettext("Can't remove all ACL "
			    "entries from a file\n"));
			acl_free(aclp);
			return (1);
		}

		/*
		 * remove a single entry
		 *
		 * if last entry just adjust acl_cnt
		 */

		if ((acl_args->acl_slot + 1) == aclp->acl_cnt)
			aclp->acl_cnt--;
		else {
			to = (char *)aclp->acl_aclp +
			    (acl_args->acl_slot * aclp->acl_entry_size);
			from = (char *)to + aclp->acl_entry_size;
			len = (aclp->acl_cnt - acl_args->acl_slot - 1) *
			    aclp->acl_entry_size;
			(void) memmove(to, from, len);
			aclp->acl_cnt--;
		}
		set_aclp = aclp;
		break;

	case ACL_DELETE:
		if ((error = acl_removeentries(aclp, acl_args->acl_aclp,
		    acl_args->acl_slot, ACL_REMOVE_ALL)) != 0) {
			errmsg(1, 1, "%s\n", acl_strerror(error));
			acl_free(aclp);
			return (1);
		}

		if (aclp->acl_cnt == 0) {
			errmsg(1, 1,
			    gettext("Can't remove all ACL "
			    "entries from a file\n"));
			acl_free(aclp);
			return (1);
		}

		set_aclp = aclp;
		break;
	case ACL_REPLACE:
		if (acl_args->acl_slot >= 0)  {
			error = acl_modifyentries(aclp, acl_args->acl_aclp,
			    acl_args->acl_slot);
			if (error) {
				errmsg(1, 1, "%s\n", acl_strerror(error));
				acl_free(aclp);
				return (1);
			}
			set_aclp = aclp;
		} else {
			set_aclp = acl_args->acl_aclp;
		}
		break;
	case ACL_STRIP:
		error = acl_strip(file, st->st_uid, st->st_gid, st->st_mode);
		if (error) {
			errmsg(1, 1, "%s\n", acl_strerror(error));
			return (1);
		}
		acl_free(aclp);
		return (0);
		/*NOTREACHED*/
	default:
		errmsg(1, 0, gettext("Unknown ACL action requested\n"));
		return (1);
		break;
	}

	error = acl_check(set_aclp, isdir);

	if (error) {
		errmsg(1, 0, "%s\n%s", acl_strerror(error),
		    gettext("See chmod(1) for more information on "
		    "valid ACL syntax\n"));
		return (1);
	}
	if ((error = acl_set(file, set_aclp)) != 0) {
			errmsg(1, 0, gettext("Failed to set ACL: %s\n"),
			    acl_strerror(error));
			acl_free(aclp);
			return (1);
	}
	acl_free(aclp);
	return (0);
}
