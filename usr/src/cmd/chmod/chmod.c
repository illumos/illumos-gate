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
 * Copyright (c) 1988, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2011 Nexenta Systems, Inc. All rights reserved.
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

/*
 * chmod option mode files
 * where
 *	mode is [ugoa][+-=][rwxXlstugo] or an octal number
 *	mode is [<+|->A[# <number] ]<aclspec>
 *	mode is S<attrspec>
 *	option is -R, -f, and -@
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
#include <fcntl.h>
#include <dirent.h>
#include <locale.h>
#include <string.h>	/* strerror() */
#include <stdarg.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>
#include <sys/acl.h>
#include <aclutils.h>
#include <libnvpair.h>
#include <libcmdutils.h>
#include <libgen.h>
#include <attr.h>

static int	rflag;
static int	fflag;

extern int	optind;
extern int	errno;

static int	mac;		/* Alternate to argc (for parseargs) */
static char	**mav;		/* Alternate to argv (for parseargs) */

static char	*ms;		/* Points to the mode argument */

#define	ACL_ADD			1
#define	ACL_DELETE		2
#define	ACL_SLOT_DELETE		3
#define	ACL_REPLACE		4
#define	ACL_STRIP		5

#define	LEFTBRACE	'{'
#define	RIGHTBRACE	'}'
#define	A_SEP		','
#define	A_SEP_TOK	","

#define	A_COMPACT_TYPE	'c'
#define	A_VERBOSE_TYPE	'v'
#define	A_ALLATTRS_TYPE	'a'

#define	A_SET_OP	'+'
#define	A_INVERSE_OP	'-'
#define	A_REPLACE_OP	'='
#define	A_UNDEF_OP	'\0'

#define	A_SET_TEXT	"set"
#define	A_INVERSE_TEXT	"clear"

#define	A_SET_VAL	B_TRUE
#define	A_CLEAR_VAL	B_FALSE

#define	ATTR_OPTS	0
#define	ATTR_NAMES	1

#define	sec_acls	secptr.acls
#define	sec_attrs	secptr.attrs

typedef struct acl_args {
	acl_t	*acl_aclp;
	int	acl_slot;
	int	acl_action;
} acl_args_t;

typedef enum {
	SEC_ACL,
	SEC_ATTR
} chmod_sec_t;

typedef struct {
	chmod_sec_t		sec_type;
	union {
		acl_args_t	*acls;
		nvlist_t	*attrs;
	} secptr;
} sec_args_t;

typedef struct attr_name {
	char			*name;
	struct attr_name	*next;
} attr_name_t;


extern mode_t newmode_common(char *ms, mode_t new_mode, mode_t umsk,
    char *file, char *path, o_mode_t *group_clear_bits,
    o_mode_t *group_set_bits);

static int chmodr(char *dir, char *path, mode_t mode, mode_t umsk,
    sec_args_t *secp, attr_name_t *attrname);
static int doacl(char *file, struct stat *st, acl_args_t *aclp);
static int dochmod(char *name, char *path, mode_t umsk, sec_args_t *secp,
    attr_name_t *attrnames);
static void handle_acl(char *name, o_mode_t group_clear_bits,
    o_mode_t group_set_bits);
void errmsg(int severity, int code, char *format, ...);
static void free_attr_names(attr_name_t *attrnames);
static void parseargs(int ac, char *av[]);
static int parse_acl_args(char *arg, sec_args_t **sec_args);
static int parse_attr_args(char *arg, sec_args_t **sec_args);
static void print_attrs(int flag);
static int set_attrs(char *file, attr_name_t *attrnames, nvlist_t *attr_nvlist);
static void usage(void);

int
main(int argc, char *argv[])
{
	int		i, c;
	int		status = 0;
	mode_t		umsk;
	sec_args_t	*sec_args = NULL;
	attr_name_t	*attrnames = NULL;
	attr_name_t	*attrend = NULL;
	attr_name_t	*tattr;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	parseargs(argc, argv);

	while ((c = getopt(mac, mav, "Rf@:")) != EOF) {
		switch (c) {
		case 'R':
			rflag++;
			break;
		case 'f':
			fflag++;
			break;
		case '@':
			if (((tattr = malloc(sizeof (attr_name_t))) == NULL) ||
			    ((tattr->name = strdup(optarg)) == NULL)) {
				perror("chmod");
				exit(2);
			}
			if (attrnames == NULL) {
				attrnames = tattr;
				attrnames->next = NULL;
			} else {
				attrend->next = tattr;
			}
			attrend = tattr;
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
	if ((mac >= 2) && (mav[0][0] == 'A')) {
		if (attrnames != NULL) {
			free_attr_names(attrnames);
			attrnames = NULL;
		}
		if (parse_acl_args(*mav, &sec_args)) {
			usage();
			exit(2);
		}
	} else if ((mac >= 2) && (mav[0][0] == 'S')) {
		if (parse_attr_args(*mav, &sec_args)) {
			usage();
			exit(2);

		/* A no-op attribute operation was specified. */
		} else if (sec_args->sec_attrs == NULL) {
			exit(0);
		}
	} else {
		if (mac < 2) {
			usage();
			exit(2);
		}
		if (attrnames != NULL) {
			free_attr_names(attrnames);
			attrnames = NULL;
		}
	}

	ms = mav[0];

	umsk = umask(0);
	(void) umask(umsk);

	for (i = 1; i < mac; i++) {
		status += dochmod(mav[i], mav[i], umsk, sec_args, attrnames);
	}

	return (fflag ? 0 : status);
}

static void
free_attr_names(attr_name_t *attrnames)
{
	attr_name_t	*attrnamesptr = attrnames;
	attr_name_t	*tptr;

	while (attrnamesptr != NULL) {
		tptr = attrnamesptr->next;
		if (attrnamesptr->name != NULL) {
			free(attrnamesptr->name);
		}
		attrnamesptr = tptr;
	}
}

static int
dochmod(char *name, char *path, mode_t umsk, sec_args_t *secp,
    attr_name_t *attrnames)
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
	if (rflag && ((st.st_mode & S_IFMT) == S_IFDIR) && !linkflg) {
		return (chmodr(name, path, st.st_mode, umsk, secp, attrnames));
	}

	if (secp != NULL) {
		if (secp->sec_type == SEC_ACL) {
			return (doacl(name, &st, secp->sec_acls));
		} else if (secp->sec_type == SEC_ATTR) {
			return (set_attrs(name, attrnames, secp->sec_attrs));
		} else {
			return (1);
		}
	} else {
		if (chmod(name, newmode_common(ms, st.st_mode, umsk, name, path,
		    &group_clear_bits, &group_set_bits)) == -1) {
			errmsg(2, 0, gettext("can't change %s\n"), path);
			return (1);
		}
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
chmodr(char *dir, char *path,  mode_t mode, mode_t umsk, sec_args_t *secp,
    attr_name_t *attrnames)
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
	if (secp != NULL) {
		if (lstat(dir, &st) < 0) {
			errmsg(2, 0, gettext("can't access %s\n"), path);
			return (1);
		}
		if (secp->sec_type == SEC_ACL) {
			(void) doacl(dir, &st, secp->sec_acls);
		} else if (secp->sec_type == SEC_ATTR) {
			(void) set_attrs(dir, attrnames, secp->sec_attrs);
		} else {
			return (1);
		}
	} else if (chmod(dir, newmode_common(ms, mode, umsk, dir, path,
	    &group_clear_bits, &group_set_bits)) < 0) {
		errmsg(2, 0, gettext("can't change %s\n"), path);
	}

	/*
	 * If the group permissions of the file are being modified,
	 * make sure that the file's ACL (if it has one) is
	 * modified also, since chmod is supposed to apply group
	 * permissions changes to both the acl mask and the
	 * general group permissions.
	 */

	if (secp != NULL) {
		/* only necessary when not setting ACL or system attributes */
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
	ecode = 0;

	/*
	 * Save parent directory path before recursive chmod.
	 * We'll need this for error printing purposes. Add
	 * a trailing '/' to the path except in the case where
	 * the path is just '/'
	 */

	if (strlcpy(parentdir, path, PATH_MAX + 1) >= PATH_MAX + 1) {
		errmsg(2, 0, gettext("directory path name too long: %s\n"),
		    path);
		return (1);
	}
	if (strcmp(path, "/") != 0)
		if (strlcat(parentdir, "/", PATH_MAX + 1) >= PATH_MAX + 1) {
			errmsg(2, 0,
			    gettext("directory path name too long: %s/\n"),
			    parentdir);
			return (1);
		}


	for (dp = readdir(dirp); dp != NULL; dp = readdir(dirp))  {

		if (strcmp(dp->d_name, ".") == 0 ||	/* skip . and .. */
		    strcmp(dp->d_name, "..") == 0) {
			continue;
		}
		if (strlcpy(currdir, parentdir, PATH_MAX + 1) >= PATH_MAX + 1) {
			errmsg(2, 0,
			    gettext("directory path name too long: %s\n"),
			    parentdir);
			return (1);
		}
		if (strlcat(currdir, dp->d_name, PATH_MAX + 1)
		    >= PATH_MAX + 1) {
			errmsg(2, 0,
			    gettext("directory path name too long: %s%s\n"),
			    currdir, dp->d_name);
			return (1);
		}
		ecode += dochmod(dp->d_name, currdir, umsk, secp, attrnames);
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
	 * Always print error message if this is a fatal error (code != 0);
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
	    "\tchmod [-fR] [-@ attribute] ... "
	    "S<attribute-operation> file ...\n"));

	(void) fprintf(stderr, gettext(
	    "\tchmod [-fR] <ACL-operation> file ...\n"));

	(void) fprintf(stderr, gettext(
	    "\tchmod [-fR] <symbolic-mode-list> file ...\n\n"));

	(void) fprintf(stderr, gettext(
	    "where \t<symbolic-mode-list> is a comma-separated list of\n"));
	(void) fprintf(stderr, gettext(
	    "\t[ugoa]{+|-|=}[rwxXlstugo]\n\n"));

	(void) fprintf(stderr, gettext(
	    "where \t<attribute-operation> is a comma-separated list of\n"
	    "\tone or more of the following\n"));
	(void) fprintf(stderr, gettext(
	    "\t[+|-|=]c[<compact-attribute-list>|{<compact-attribute-list>}]\n"
	    "\t[+|-|=]v[<verbose-attribute-setting>|"
	    "\'{\'<verbose-attribute-setting-list>\'}\']\n"
	    "\t[+|-|=]a\n"));
	(void) fprintf(stderr, gettext(
	    "where \t<compact-attribute-list> is a list of zero or more of\n"));
	print_attrs(ATTR_OPTS);
	(void) fprintf(stderr, gettext(
	    "where \t<verbose-attribute-setting> is one of\n"));
	print_attrs(ATTR_NAMES);
	(void) fprintf(stderr, gettext(
	    "\tand can be, optionally, immediately preceded by \"no\"\n\n"));

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
	    (av[i] != NULL) && (av[i][0] != '\0');
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
			    strchr(av[i], 'f') == NULL) &&
			    strchr(av[i], '@') == NULL) {
				if ((mav[mac++] = strdup("--")) == NULL) {
					perror("chmod");
					exit(2);
				}
			}
		}

		if ((mav[mac++] = strdup(av[i])) == NULL) {
			perror("chmod");
			exit(2);
		}
	}

	mav[mac] = (char *)NULL;
}

static int
parse_acl_args(char *arg, sec_args_t **sec_args)
{
	acl_t *new_acl = NULL;
	int slot;
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
		/*
		 * Was slot specified?
		 */
		if (arg[1] == '=')
			slot = -1;
		action = ACL_REPLACE;
		acl_spec = ++end;
		break;
	default:
		return (1);
	}

	if ((action == ACL_REPLACE || action == ACL_ADD) && acl_spec[0] == '\0')
		return (1);

	if (acl_spec) {
		if (acl_parse(acl_spec, &new_acl)) {
			exit(1);
		}
	}

	new_acl_args = malloc(sizeof (acl_args_t));
	if (new_acl_args == NULL)
		return (1);

	new_acl_args->acl_aclp = new_acl;
	new_acl_args->acl_slot = slot;
	new_acl_args->acl_action = action;

	if ((*sec_args = malloc(sizeof (sec_args_t))) == NULL) {
		perror("chmod");
		exit(2);
	}
	(*sec_args)->sec_type = SEC_ACL;
	(*sec_args)->sec_acls = new_acl_args;

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
		errmsg(1, 0, "%s\n", acl_strerror(error));
		return (1);
	}
	switch (acl_args->acl_action) {
	case ACL_ADD:
		if ((error = acl_addentries(aclp,
		    acl_args->acl_aclp, acl_args->acl_slot)) != 0) {
			errmsg(1, 0, "%s\n", acl_strerror(error));
			acl_free(aclp);
			return (1);
		}
		set_aclp = aclp;
		break;
	case ACL_SLOT_DELETE:
		if (acl_args->acl_slot + 1 > aclp->acl_cnt) {
			errmsg(1, 0,
			    gettext("Invalid slot specified for removal\n"));
			acl_free(aclp);
			return (1);
		}

		if (acl_args->acl_slot == 0 && aclp->acl_cnt == 1) {
			errmsg(1, 0,
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
			errmsg(1, 0, "%s\n", acl_strerror(error));
			acl_free(aclp);
			return (1);
		}

		if (aclp->acl_cnt == 0) {
			errmsg(1, 0,
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
				errmsg(1, 0, "%s\n", acl_strerror(error));
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
			errmsg(1, 0, "%s\n", acl_strerror(error));
			acl_free(aclp);
			return (1);
		}
		acl_free(aclp);
		return (0);
		/*NOTREACHED*/
	default:
		errmsg(1, 2, gettext("Unknown ACL action requested\n"));
		/*NOTREACHED*/
	}
	error = acl_check(set_aclp, isdir);

	if (error) {
		errmsg(1, 2, "%s\n%s", acl_strerror(error),
		    gettext("See chmod(1) for more information on "
		    "valid ACL syntax\n"));
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

/*
 * Prints out the attributes in their verbose form:
 *	'{'[["no"]<attribute-name>][,["no"]<attribute-name>]...'}'
 * similar to output of ls -/v.
 */
static void
print_nvlist(nvlist_t *attr_nvlist)
{
	int		firsttime = 1;
	boolean_t	value;
	nvlist_t	*lptr = attr_nvlist;
	nvpair_t	*pair = NULL;

	(void) fprintf(stderr, "\t%c", LEFTBRACE);
	while (pair = nvlist_next_nvpair(lptr, pair)) {
		if (nvpair_value_boolean_value(pair, &value) == 0) {
			(void) fprintf(stderr, "%s%s%s",
			    firsttime ? "" : A_SEP_TOK,
			    (value == A_SET_VAL) ? "" : "no",
			    nvpair_name(pair));
			firsttime = 0;
		} else {
			(void) fprintf(stderr, gettext(
			    "<error retrieving attributes: %s>"),
			    strerror(errno));
			break;
		}
	}
	(void) fprintf(stderr, "%c\n", RIGHTBRACE);
}

/*
 * Add an attribute name and boolean value to an nvlist if an action is to be
 * performed for that attribute.  The nvlist will be used later to set all the
 * attributes in the nvlist in one operation through a call to setattrat().
 *
 * If a set operation ('+') was specified, then a boolean representation of the
 * attribute's value will be added to the nvlist for that attribute name.  If an
 * inverse operation ('-') was specified, then a boolean representation of the
 * inverse of the attribute's value will be added to the nvlist for that
 * attribute name.
 *
 * Returns an nvlist of attribute name and boolean value pairs if there are
 * attribute actions to be performed, otherwise returns NULL.
 */
static nvlist_t *
set_attrs_nvlist(char *attractptr, int numofattrs)
{
	int		attribute_set = 0;
	f_attr_t	i;
	nvlist_t	*attr_nvlist;

	if (nvlist_alloc(&attr_nvlist, NV_UNIQUE_NAME, 0) != 0) {
		perror("chmod");
		exit(2);
	}

	for (i = 0; i < numofattrs; i++) {
		if (attractptr[i] != '\0') {
			if ((nvlist_add_boolean_value(attr_nvlist,
			    attr_to_name(i),
			    (attractptr[i] == A_SET_OP))) != 0) {
				errmsg(1, 2, gettext(
				    "unable to propagate attribute names and"
				    "values: %s\n"), strerror(errno));
			} else {
				attribute_set = 1;
			}
		}
	}
	return (attribute_set ? attr_nvlist : NULL);
}

/*
 * Set the attributes of file, or if specified, of the named attribute file,
 * attrname.  Build an nvlist of attribute names and values and call setattrat()
 * to set the attributes in one operation.
 *
 * Returns 0 if successful, otherwise returns 1.
 */
static int
set_file_attrs(char *file, char *attrname, nvlist_t *attr_nvlist)
{
	int	rc;
	char	*filename;

	if (attrname != NULL) {
		filename = attrname;
	} else {
		filename = basename(file);
	}

	if ((rc = setattrat(AT_FDCWD, XATTR_VIEW_READWRITE, filename,
	    attr_nvlist)) != 0) {
		char *emsg;
		switch (errno) {
		case EINVAL:
			emsg = gettext("not supported");
			break;
		case EPERM:
			emsg = gettext("not privileged");
			break;
		default:
			emsg = strerror(rc);
		}
		errmsg(1, 0, gettext(
		    "cannot set the following attributes on "
		    "%s%s%s%s: %s\n"),
		    (attrname == NULL) ? "" : gettext("attribute "),
		    (attrname == NULL) ? "" : attrname,
		    (attrname == NULL) ? "" : gettext(" of "),
		    file, emsg);
		print_nvlist(attr_nvlist);
	}

	return (rc);
}

static int
save_cwd(void)
{
	return (open(".", O_RDONLY));
}

static void
rest_cwd(int cwd)
{
	if (cwd != -1) {
		if (fchdir(cwd) != 0) {
			errmsg(1, 1, gettext(
			    "can't change to current working directory\n"));
		}
		(void) close(cwd);
	}
}

/*
 * Returns 1 if filename is a system attribute file, otherwise
 * returns 0.
 */
static int
is_sattr(char *filename)
{
	return (sysattr_type(filename) != _NOT_SATTR);
}

/*
 * Perform the action on the specified named attribute file for the file
 * associated with the input file descriptor.  If the named attribute file
 * is "*", then the action is to be performed on all the named attribute files
 * of the file associated with the input file descriptor.
 */
static int
set_named_attrs(char *file, int parentfd, char *attrname, nvlist_t *attr_nvlist)
{
	int		dirfd;
	int		error = 0;
	DIR		*dirp = NULL;
	struct dirent	*dp;
	struct stat	st;

	if ((attrname == NULL) || (strcmp(attrname, "*") != 0)) {
		/*
		 * Make sure the named attribute exists and extended system
		 * attributes are supported on the underlying file system.
		 */
		if (attrname != NULL) {
			if (fstatat(parentfd, attrname, &st,
			    AT_SYMLINK_NOFOLLOW) < 0) {
				errmsg(2, 0, gettext(
				    "can't access attribute %s of %s\n"),
				    attrname, file);
				return (1);
			}
			if (sysattr_support(attrname, _PC_SATTR_ENABLED) != 1) {
				errmsg(1, 0, gettext(
				    "extended system attributes not supported "
				    "for attribute %s of %s\n"),
				    attrname, file);
				return (1);
			}
		}

		error = set_file_attrs(file, attrname, attr_nvlist);

	} else {
		if (((dirfd = dup(parentfd)) == -1) ||
		    ((dirp = fdopendir(dirfd)) == NULL)) {
			errmsg(1, 0, gettext(
			    "cannot open dir pointer of file %s\n"), file);
			if (dirfd > 0) {
				(void) close(dirfd);
			}
			return (1);
		}

		while (dp = readdir(dirp)) {
			/*
			 * Process all extended attribute files except
			 * ".", "..", and extended system attribute files.
			 */
			if ((strcmp(dp->d_name, ".") == 0) ||
			    (strcmp(dp->d_name, "..") == 0) ||
			    is_sattr(dp->d_name)) {
				continue;
			}

			if (set_named_attrs(file, parentfd, dp->d_name,
			    attr_nvlist) != 0) {
				error++;
			}
		}
		if (dirp != NULL) {
			(void) closedir(dirp);
		}
	}

	return ((error == 0) ? 0 : 1);
}

/*
 * Set the attributes of the specified file, or if specified with -@ on the
 * command line, the specified named attributes of the specified file.
 *
 * Returns 0 if successful, otherwise returns 1.
 */
static int
set_attrs(char *file, attr_name_t *attrnames, nvlist_t *attr_nvlist)
{
	char		*parentd;
	char		*tpath = NULL;
	int		cwd;
	int		error = 0;
	int		parentfd;
	attr_name_t	*tattr = attrnames;

	if (attr_nvlist == NULL) {
		return (0);
	}

	if (sysattr_support(file, _PC_SATTR_ENABLED) != 1) {
		errmsg(1, 0, gettext(
		    "extended system attributes not supported for %s\n"), file);
		return (1);
	}

	/*
	 * Open the parent directory and change into it before attempting
	 * to set the attributes of the file.
	 */
	if (attrnames == NULL) {
		tpath = strdup(file);
		parentd = dirname(tpath);
		parentfd = open(parentd, O_RDONLY);
	} else {
		parentfd = attropen(file, ".", O_RDONLY);
	}
	if (parentfd == -1) {
		errmsg(1, 0, gettext(
		    "cannot open attribute directory of %s\n"), file);
		if (tpath != NULL) {
			free(tpath);
		}
		return (1);
	}

	if ((cwd = save_cwd()) < 0) {
		errmsg(1, 1, gettext(
		    "can't get current working directory\n"));
	}
	if (fchdir(parentfd) != 0) {
		errmsg(1, 0, gettext(
		    "can't change to parent %sdirectory of %s\n"),
		    (attrnames == NULL) ? "" : gettext("attribute "), file);
		(void) close(cwd);
		(void) close(parentfd);
		if (tpath != NULL) {
			free(tpath);
		}
		return (1);
	}

	/*
	 * If no named attribute file names were provided on the command line
	 * then set the attributes of the base file, otherwise, set the
	 * attributes for each of the named attribute files specified.
	 */
	if (attrnames == NULL) {
		error = set_named_attrs(file, parentfd, NULL, attr_nvlist);
		free(tpath);
	} else {
		while (tattr != NULL) {
			if (set_named_attrs(file, parentfd, tattr->name,
			    attr_nvlist) != 0) {
				error++;
			}
			tattr = tattr->next;
		}
	}
	(void) close(parentfd);
	rest_cwd(cwd);

	return ((error == 0) ? 0 : 1);
}

/*
 * Prints the attributes in either the compact or verbose form indicated
 * by flag.
 */
static void
print_attrs(int flag)
{
	f_attr_t	i;
	static int	numofattrs;
	int		firsttime = 1;

	numofattrs = attr_count();

	(void) fprintf(stderr, gettext("\t["));
	for (i = 0; i < numofattrs; i++) {
		if ((attr_to_xattr_view(i) != XATTR_VIEW_READWRITE) ||
		    (attr_to_data_type(i) != DATA_TYPE_BOOLEAN_VALUE)) {
			continue;
		}
		(void) fprintf(stderr, "%s%s",
		    (firsttime == 1) ? "" : gettext("|"),
		    (flag == ATTR_OPTS) ? attr_to_option(i) : attr_to_name(i));
		firsttime = 0;
	}
	(void) fprintf(stderr, gettext("]\n"));
}

/*
 * Record what action should be taken on the specified attribute. Only boolean
 * read-write attributes can be manipulated.
 *
 * Returns 0 if successful, otherwise returns 1.
 */
static int
set_attr_args(f_attr_t attr, char action, char *attractptr)
{
	if ((attr_to_xattr_view(attr) == XATTR_VIEW_READWRITE) &&
	    (attr_to_data_type(attr) == DATA_TYPE_BOOLEAN_VALUE)) {
		attractptr[attr] = action;
		return (0);
	}
	return (1);
}

/*
 * Parses the entry and assigns the appropriate action (either '+' or '-' in
 * attribute's position in the character array pointed to by attractptr, where
 * upon exit, attractptr is positional and the value of each character specifies
 * whether to set (a '+'), clear (a '-'), or leave untouched (a '\0') the
 * attribute value.
 *
 * If the entry is an attribute name, then the A_SET_OP action is to be
 * performed for this attribute.  If the entry is an attribute name proceeded
 * with "no", then the A_INVERSE_OP action is to be performed for this
 * attribute.  If the entry is one or more attribute option letters, then step
 * through each of the option letters marking the action to be performed for
 * each of the attributes associated with the letter as A_SET_OP.
 *
 * Returns 0 if the entry was a valid attribute(s) and the action to be
 * performed on that attribute(s) has been recorded, otherwise returns 1.
 */
static int
parse_entry(char *entry, char action, char atype, int len, char *attractptr)
{
	char		aopt[2] = {'\0', '\0'};
	char		*aptr;
	f_attr_t	attr;

	if (atype == A_VERBOSE_TYPE) {
		if ((attr = name_to_attr(entry)) != F_ATTR_INVAL) {
			return (set_attr_args(attr,
			    (action == A_REPLACE_OP) ? A_SET_OP : action,
			    attractptr));
		} else if ((len > 2) && (strncmp(entry, "no", 2) == 0) &&
		    ((attr = name_to_attr(entry + 2)) != F_ATTR_INVAL)) {
			return (set_attr_args(attr, ((action == A_REPLACE_OP) ||
			    (action == A_SET_OP)) ? A_INVERSE_OP : A_SET_OP,
			    attractptr));
		} else {
			return (1);
		}
	} else if (atype == A_COMPACT_TYPE) {
		for (aptr = entry; *aptr != '\0'; aptr++) {
			*aopt = *aptr;
			/*
			 * The output of 'ls' can be used as the attribute mode
			 * specification for chmod.  This output can contain a
			 * hypen ('-') for each attribute that is not set.  If
			 * so, ignore them.  If a replace action is being
			 * performed, then all attributes that don't have an
			 * action set here, will be cleared down the line.
			 */
			if (*aptr == '-') {
				continue;
			}
			if (set_attr_args(option_to_attr(aopt),
			    (action == A_REPLACE_OP) ? A_SET_OP : action,
			    attractptr) != 0) {
				return (1);
			}
		}
		return (0);
	}
	return (1);
}

/*
 * Parse the attribute specification, aoptsstr.  Upon completion, attr_nvlist
 * will point to an nvlist which contains pairs of attribute names and values
 * to be set; attr_nvlist will be NULL if it is a no-op.
 *
 * The attribute specification format is
 *	S[oper]attr_type[attribute_list]
 * where oper is
 *	+	set operation of specified attributes in attribute list.
 *		This is the default operation.
 *	-	inverse operation of specified attributes in attribute list
 *	=	replace operation of all attributes.  All attribute operations
 *		depend on those specified in the attribute list.  Attributes
 *		not specified in the attribute list will be cleared.
 * where attr_type is
 *	c	compact type.  Each entry in the attribute list is a character
 *		option representing an associated attribute name.
 *	v	verbose type.  Each entry in the attribute list is an
 *		an attribute name which can optionally be preceeded with "no"
 *		(to imply the attribute should be cleared).
 *	a	all attributes type.  The oper should be applied to all
 *		read-write boolean system attributes.  No attribute list should
 *		be specified after an 'a' attribute type.
 *
 * Returns 0 if aoptsstr contained a valid attribute specification,
 * otherwise, returns 1.
 */
static int
parse_attr_args(char *aoptsstr, sec_args_t **sec_args)
{
	char		action;
	char		*attractptr;
	char		atype;
	char		*entry;
	char		*eptr;
	char		*nextattr;
	char		*nextentry;
	char		*subentry;
	char		*teptr;
	char		tok[] = {'\0', '\0'};
	int		len;
	f_attr_t	i;
	int		numofattrs;

	if ((*aoptsstr != 'S') || (*(aoptsstr + 1) == '\0')) {
		return (1);
	}

	if ((eptr = strdup(aoptsstr + 1)) == NULL) {
		perror("chmod");
		exit(2);
	}
	entry = eptr;

	/*
	 * Create a positional character array to determine a single attribute
	 * operation to be performed, where each index represents the system
	 * attribute affected, and it's value in the array represents the action
	 * to be performed, i.e., a value of '+' means to set the attribute, a
	 * value of '-' means to clear the attribute, and a value of '\0' means
	 * to leave the attribute untouched.  Initially, this positional
	 * character array is all '\0's, representing a no-op.
	 */
	if ((numofattrs = attr_count()) < 1) {
		errmsg(1, 1, gettext("system attributes not supported\n"));
	}

	if ((attractptr = calloc(numofattrs, sizeof (char))) == NULL) {
		perror("chmod");
		exit(2);
	}

	if ((*sec_args = malloc(sizeof (sec_args_t))) == NULL) {
		perror("chmod");
		exit(2);
	}
	(*sec_args)->sec_type = SEC_ATTR;
	(*sec_args)->sec_attrs = NULL;

	/* Parse each attribute operation within the attribute specification. */
	while ((entry != NULL) && (*entry != '\0')) {
		action = A_SET_OP;
		atype = '\0';

		/* Get the operator. */
		switch (*entry) {
		case A_SET_OP:
		case A_INVERSE_OP:
		case A_REPLACE_OP:
			action = *entry++;
			break;
		case A_COMPACT_TYPE:
		case A_VERBOSE_TYPE:
		case A_ALLATTRS_TYPE:
			atype = *entry++;
			action = A_SET_OP;
			break;
		default:
			break;
		}

		/* An attribute type must be specified. */
		if (atype == '\0') {
			if ((*entry == A_COMPACT_TYPE) ||
			    (*entry == A_VERBOSE_TYPE) ||
			    (*entry == A_ALLATTRS_TYPE)) {
				atype = *entry++;
			} else {
				return (1);
			}
		}

		/* Get the attribute specification separator. */
		if (*entry == LEFTBRACE) {
			*tok = RIGHTBRACE;
			entry++;
		} else {
			*tok = A_SEP;
		}

		/* Get the attribute operation */
		if ((nextentry = strpbrk(entry, tok)) != NULL) {
			*nextentry = '\0';
			nextentry++;
		}

		/* Check for a no-op */
		if ((*entry == '\0') && (atype != A_ALLATTRS_TYPE) &&
		    (action != A_REPLACE_OP)) {
			entry = nextentry;
			continue;
		}

		/*
		 * Step through the attribute operation, setting the
		 * appropriate values for the specified attributes in the
		 * character array, attractptr. A value of '+' will mean the
		 * attribute is to be set, and a value of '-' will mean the
		 * attribute is to be cleared.  If the value of an attribute
		 * remains '\0', then no action is to be taken on that
		 * attribute.  As multiple operations specified are
		 * accumulated, a single attribute setting operation is
		 * represented in attractptr.
		 */
		len = strlen(entry);
		if ((*tok == RIGHTBRACE) || (action == A_REPLACE_OP) ||
		    (atype == A_ALLATTRS_TYPE)) {

			if ((action == A_REPLACE_OP) ||
			    (atype == A_ALLATTRS_TYPE)) {
				(void) memset(attractptr, '\0', numofattrs);
			}

			if (len > 0) {
				if ((teptr = strdup(entry)) == NULL) {
					perror("chmod");
					exit(2);
				}
				subentry = teptr;
				while (subentry != NULL) {
					if ((nextattr = strpbrk(subentry,
					    A_SEP_TOK)) != NULL) {
						*nextattr = '\0';
						nextattr++;
					}
					if (parse_entry(subentry, action,
					    atype, len, attractptr) != 0) {
						return (1);
					}
					subentry = nextattr;
				}
				free(teptr);
			}

			/*
			 * If performing the replace action, record the
			 * attributes and values for the rest of the
			 * attributes that have not already been recorded,
			 * otherwise record the specified action for all
			 * attributes.  Note: set_attr_args() will only record
			 * the attribute and action if it is a boolean
			 * read-write attribute so we don't need to worry
			 * about checking it here.
			 */
			if ((action == A_REPLACE_OP) ||
			    (atype == A_ALLATTRS_TYPE)) {
				for (i = 0; i < numofattrs; i++) {
					if (attractptr[i] == A_UNDEF_OP) {
						(void) set_attr_args(i,
						    (action == A_SET_OP) ?
						    A_SET_OP : A_INVERSE_OP,
						    attractptr);
					}
				}
			}

		} else {
			if (parse_entry(entry, action, atype, len,
			    attractptr) != 0) {
				return (1);
			}
		}
		entry = nextentry;
	}

	/*
	 * Populate an nvlist with attribute name and boolean value pairs
	 * using the single attribute operation.
	 */
	(*sec_args)->sec_attrs = set_attrs_nvlist(attractptr, numofattrs);
	free(attractptr);
	free(eptr);

	return (0);
}
