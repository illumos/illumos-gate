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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

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
 * nfs share
 */
#define	_REENTRANT

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/param.h>	/* for UID_NOBODY */
#include <sys/stat.h>
#include <errno.h>
#include <rpc/rpc.h>
#include <netconfig.h>
#include <netdir.h>
#include <nfs/nfs_sec.h>
#include <nfs/export.h>
#include <locale.h>
#include <zone.h>
#include <rpcsvc/daemon_utils.h>
#include "../lib/nfslog_config.h"
#include "../lib/sharetab.h"
#include "../lib/nfslogtab.h"

#define	RET_OK		0
#define	RET_ERR		32

static int addlogconfig(struct exportdata *, char *, nfsl_config_t *);
static void configlog(struct exportdata *, char *);
static int direq(char *, char *);
static int newopts(char *);
static void parseopts_old(struct exportdata *, char *);
static void parseopts_new(struct exportdata *, char *);
static void pr_err(char *, ...);
static int shareable(char *);
static int sharetab_add(char *, char *, char *, char *, int);
static int sharepub_exist(char *);
static caddr_t *get_rootnames(seconfig_t *, char *, int *);
static void usage();
static void exportindex(struct exportdata *, char *);
static int nfslogtab_add(char *, char *, char *);
static int nfslogtab_deactivate(char *);

extern int issubdir();
extern int exportfs();
int nfs_getseconfig_byname(char *, seconfig_t *);
static void printarg(char *, struct exportdata *);
static struct exportdata ex;

/*
 * list of support services needed
 */
static char *service_list[] =
	{ STATD, LOCKD, MOUNTD, NFSD, NFSMAPID, RQUOTAD, NULL };

int
main(int argc, char *argv[])
{
	extern int optind;
	extern char *optarg;
	char dir[MAXPATHLEN];
	char *res = "-";
	char *opts = "rw";
	char *descr = "";
	char *services;
	int c;
	int replace = 0;
	int verbose = 0;

	/* Don't drop core if the NFS module isn't loaded. */
	signal(SIGSYS, SIG_IGN);

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "o:d:v")) != EOF) {
		switch (c) {
		case 'o':
			opts = optarg;
			break;
		case 'd':
			descr = optarg;
			break;
		case 'v':
			verbose++;
			break;
		default:
			usage();
			exit(RET_ERR);
		}
	}

	if (argc <= optind || argc - optind > 2) {
		usage();
		exit(RET_ERR);
	}
	if (realpath(argv[optind], dir) == NULL)
		pr_err("%s: %s\n", argv[optind], strerror(errno));

	if (argc - optind > 1)
		res = argv[optind + 1];

	if (getenv("SHARE_NOINUSE_CHECK") == NULL) {
		switch (shareable(dir)) {
		case 0:
			exit(RET_ERR);
			break;
		case 1:
			break;
		case 2:
			replace = 1;
			break;
		}
	}

	ex.ex_path = dir;
	ex.ex_pathlen = strlen(dir) + 1;

	if (newopts(opts))
		parseopts_new(&ex, opts);
	else
		parseopts_old(&ex, opts);

	/*
	 * If -o public was specified, check for any existing directory
	 * shared with -o public. If so, fail.
	 */
	if (ex.ex_flags & EX_PUBLIC) {
		if (sharepub_exist(dir) == 1) {
			errno = 0;
			pr_err(
			gettext("Cannot share more than filesystem with"
				" 'public' option\n"));
		}
	}

	if (verbose)
		printarg(dir, &ex);

	if (exportfs(dir, &ex) < 0) {
		switch (errno) {
		case EREMOTE:
			pr_err(gettext("Cannot share remote filesystem: %s\n"),
				dir);
			break;
		case EPERM:
			if (getzoneid() != GLOBAL_ZONEID) {
				pr_err(gettext("Cannot share filesystems "
					"in non-global zones: %s\n"),
					dir);
				break;
			}
			/* FALLTHRU */
		default:
			pr_err("%s: %s\n", dir, strerror(errno));
			break;
		}
	}

	if (sharetab_add(dir, res, opts, descr, replace) < 0)
		exit(RET_ERR);

	if (ex.ex_flags & EX_LOG)
		if (nfslogtab_add(dir, ex.ex_log_buffer, ex.ex_tag))
			exit(RET_ERR);

	/*
	 * enable services as needed.
	 */
	_check_services(service_list);

	return (RET_OK);
}

/*
 * Check if there already is an entry shared with -o public.
 */
static int
sharepub_exist(char *dir)
{
	struct share *sh;
	int res;
	FILE *f;
	char *val;

	f = fopen(SHARETAB, "r");

	if (f == NULL) {
		if (errno == ENOENT)
			return (0);
		pr_err("%s: %s\n", SHARETAB, strerror(errno));
	}

	while ((res = getshare(f, &sh)) > 0) {
		if (strcmp(sh->sh_fstype, "nfs") != 0)
			continue;

		if (strcmp(sh->sh_path, dir) == 0)
			continue;

		if (val = getshareopt(sh->sh_opts, SHOPT_PUBLIC)) {
			free(val);
			return (1);
		}
	}

	if (res < 0) {
		pr_err(gettext("error reading %s\n"), SHARETAB);
		(void) fclose(f);
	}

	(void) fclose(f);
	return (0);
}

/*
 * Check the nfs share entries in sharetab file.
 * Returns:
 *	0  dir not shareable
 *	1  dir is shareable
 *	2  dir is already shared (can modify options)
 */
static int
shareable(path)
	char *path;
{
	FILE *f;
	struct share *sh;
	struct stat st;
	int res;

	errno = 0;
	if (*path != '/')
		pr_err(gettext("%s: not a full pathname\n"), path);

	if (stat(path, &st) < 0) 	/* does it exist ? */
		pr_err(gettext("%s: %s\n"), path, strerror(errno));

	/*
	 * We make the assumption that if we can't open the SHARETAB
	 * file for some reason other than it doesn't exist, then we
	 * won't share the directory.  Since we can't complete the
	 * operation correctly, then let's not do it at all.
	 */
	f = fopen(SHARETAB, "r");
	if (f == NULL) {
		if (errno == ENOENT)
			return (1);
		pr_err("%s: %s\n", SHARETAB, strerror(errno));
		return (0);
	}

	while ((res = getshare(f, &sh)) > 0) {
		if (strcmp(sh->sh_fstype, "nfs") != 0)
			continue;

		if (direq(path, sh->sh_path)) {
			(void) fclose(f);
			return (2);
		}

		if (issubdir(sh->sh_path, path)) {
			pr_err(gettext("%s: sub-directory "
				"(%s) already shared\n"),
				path, sh->sh_path);
		}
		if (issubdir(path, sh->sh_path)) {
			pr_err(gettext("%s: parent-directory "
				"(%s) already shared\n"),
				path, sh->sh_path);
		}
	}

	if (res < 0)
		pr_err(gettext("error reading %s\n"), SHARETAB);

	(void) fclose(f);
	return (1);
}

static int
direq(dir1, dir2)
	char *dir1, *dir2;
{
	struct stat st1, st2;

	if (strcmp(dir1, dir2) == 0)
		return (1);
	if (stat(dir1, &st1) < 0 || stat(dir2, &st2) < 0)
		return (0);
	return (st1.st_ino == st2.st_ino && st1.st_dev == st2.st_dev);
}

static char *optlist[] = {
#define	OPT_RO		0
	SHOPT_RO,
#define	OPT_RW		1
	SHOPT_RW,
#define	OPT_ROOT	2
	SHOPT_ROOT,
#define	OPT_SECURE	3
	SHOPT_SECURE,
#define	OPT_ANON	4
	SHOPT_ANON,
#define	OPT_WINDOW	5
	SHOPT_WINDOW,
#define	OPT_NOSUID	6
	SHOPT_NOSUID,
#define	OPT_ACLOK	7
	SHOPT_ACLOK,
#define	OPT_NOSUB	8
	SHOPT_NOSUB,
#define	OPT_SEC		9
	SHOPT_SEC,
#define	OPT_PUBLIC	10
	SHOPT_PUBLIC,
#define	OPT_INDEX	11
	SHOPT_INDEX,
#define	OPT_LOG		12
	SHOPT_LOG,
#ifdef VOLATILE_FH_TEST	/* XXX added for testing volatile fh's only */
#define	OPT_VOLFH	13
	SHOPT_VOLFH,
#endif /* VOLATILE_FH_TEST */
	NULL
};

/*
 * If the option string contains a "sec="
 * option, then use new option syntax.
 */
static int
newopts(char *opts)
{
	char *p, *val;

	p = strdup(opts);
	if (p == NULL)
		pr_err(gettext("opts: no memory\n"));

	while (*p)
		if (getsubopt(&p, optlist, &val) == OPT_SEC)
			return (1);

	return (0);
}

#ifdef VOLATILE_FH_TEST	/* XXX added for testing volatile fh's only */
/*
 * Set the ex_flags to indicate which fh expire type. Return 0 for success,
 * error otherwise.
 */
static int
nfs4_set_volfh_flags(struct exportdata *exp, char *volfhtypes)
{
	char	*voltype, *next;
	int	err = 0;

	for (voltype = volfhtypes; !err && voltype != NULL; voltype = next) {
		while (*voltype == ':') voltype++;
		next = strchr(voltype, ':');
		if (next != NULL)
			*next = '\0';
		if (strcmp(voltype, "any") == 0)
			exp->ex_flags |= EX_VOLFH;
		else if (strcmp(voltype, "rnm") == 0)
			exp->ex_flags |= EX_VOLRNM;
		else if (strcmp(voltype, "mig") == 0)
			exp->ex_flags |= EX_VOLMIG;
		else if (strcmp(voltype, "noexpopen") == 0)
			exp->ex_flags |= EX_NOEXPOPEN;
		else {
			err = EINVAL;		/* invalid arg */
		}
		if (next != NULL)
			*next = ':';
	}
	return (err);
}
#endif /* VOLATILE_FH_TEST */

#define	badnum(x) ((x) == NULL || !isdigit(*(x)))
#define	DEF_WIN	30000

/*
 * Parse the share options from the "-o" flag.
 * The extracted data is moved into the exports
 * structure which is passed into the kernel via
 * the exportfs() system call.
 */
static void
parseopts_old(struct exportdata *exp, char *opts)
{
	char *p, *savep, *val, *rootlist;
	struct secinfo *sp;
	int done_aclok = 0;
	int done_nosuid = 0;
	int done_anon = 0;


	p = strdup(opts);
	if (p == NULL)
		pr_err(gettext("opts: no memory\n"));

	exp->ex_version = 2;
	exp->ex_anon = UID_NOBODY;
	exp->ex_seccnt = 1;
	exp->ex_index = NULL;

	sp = (struct secinfo *)calloc(1, sizeof (struct secinfo));
	if (sp == NULL)
		pr_err(gettext("ex_secinfo: no memory\n"));
	exp->ex_secinfo = sp;

	/*
	 * Initialize some fields
	 */
	sp->s_flags = 0;
	sp->s_window = DEF_WIN;
	sp->s_rootcnt = 0;
	sp->s_rootnames = NULL;

	if (nfs_getseconfig_default(&sp->s_secinfo))
		pr_err(gettext("failed to get default security mode\n"));

	while (*p) {
		savep = p;
		switch (getsubopt(&p, optlist, &val)) {

		case OPT_RO:

			sp->s_flags |= val ? M_ROL : M_RO;

			if (sp->s_flags & M_RO && sp->s_flags & M_RW)
				pr_err(gettext("rw vs ro conflict\n"));
			if (sp->s_flags & M_RO && sp->s_flags & M_ROL)
				pr_err(gettext("Ambiguous ro options\n"));
			break;

		case OPT_RW:

			sp->s_flags |= val ? M_RWL : M_RW;

			if (sp->s_flags & M_RO && sp->s_flags & M_RW)
				pr_err(gettext("ro vs rw conflict\n"));
			if (sp->s_flags & M_RW && sp->s_flags & M_RWL)
				pr_err(gettext("Ambiguous rw options\n"));
			break;

		case OPT_ROOT:
			if (val == NULL)
				pr_err(gettext("missing root list\n"));
			rootlist = val;
			sp->s_flags |= M_ROOT;
			break;

		case OPT_SECURE:
			if (nfs_getseconfig_byname("dh", &sp->s_secinfo)) {
				pr_err(gettext("invalid sec name\n"));
			}
			break;

		case OPT_ANON:
			if (done_anon++)
				pr_err(gettext("option anon repeated\n"));

			if (!val) {
				pr_err(gettext("missing anon value\n"));
			}
			/* check for special "-1" value, which is ok */
			if (strcmp(val, "-1") != 0 && badnum(val)) {
				pr_err(gettext("invalid anon value\n"));
			}
			exp->ex_anon = atoi(val);
			break;

		case OPT_WINDOW:
			if (badnum(val))
				pr_err(gettext("invalid window value\n"));
			sp->s_window = atoi(val);
			break;

		case OPT_NOSUID:
			if (done_nosuid++)
				pr_err(gettext("option nosuid repeated\n"));

			exp->ex_flags |= EX_NOSUID;
			break;

		case OPT_ACLOK:
			if (done_aclok++)
				pr_err(gettext("option aclok repeated\n"));
			exp->ex_flags |= EX_ACLOK;
			break;

		case OPT_NOSUB:
			/*
			 * The "don't allow mount of subdirectories" option.
			 */
			exp->ex_flags |= EX_NOSUB;
			break;

		case OPT_PUBLIC:
			exp->ex_flags |= EX_PUBLIC;
			break;

		case OPT_INDEX:
			exportindex(exp, val);
			break;

		case OPT_LOG:
			configlog(exp, val);
			break;

#ifdef VOLATILE_FH_TEST	/* XXX added for testing volatile fh's only */
		case OPT_VOLFH:
			/* volatile filehandles - expire on share */
			if (val == NULL)
				pr_err(gettext("missing volatile fh types\n"));
			if (nfs4_set_volfh_flags(exp, val))
				pr_err(gettext("invalid volatile fh types\n"));
			break;
#endif /* VOLATILE_FH_TEST */

		default:
			pr_err(gettext("invalid share option: '%s'\n"), savep);
		}
	}
	if (sp->s_flags & M_ROOT && sp->s_secinfo.sc_rpcnum != AUTH_UNIX) {
		sp->s_rootnames = get_rootnames(&sp->s_secinfo, rootlist,
				&sp->s_rootcnt);
		if (sp->s_rootnames == NULL)
			pr_err(gettext("Bad root list\n"));
	}

	/*
	 * Set uninitialized flags to "rw"
	 */
	if ((sp->s_flags & (M_RO|M_RW|M_RWL|M_ROL)) == 0)
		sp->s_flags |= M_RW;
}

/*
 * Parse the new share options from the "-o" flag.
 * Parsing is more complicated than the old case
 * Since we may be setting up multiple secinfo entries.
 * Syntax is more restrictive: the flavor-dependent
 * options: ro, rw, root, window can only follow
 * a sec option.
 */
static void
parseopts_new(struct exportdata *exp, char *opts)
{
	char *p, *q, *savep, *val;
	char *f, *lasts;
	struct secinfo *sp1, *sp, *pt;
	int i, secopt;
	int count = 0;
	int done_aclok = 0;
	int done_nosuid = 0;
	int done_anon = 0;

	exp->ex_version = 2;
	exp->ex_anon = UID_NOBODY;
	exp->ex_index = NULL;

	p = strdup(opts);
	if (p == NULL)
		pr_err(gettext("opts: no memory\n"));

	/*
	 * Count the number of security modes
	 */
	while (*p) {
		switch (getsubopt(&p, optlist, &val)) {
		case OPT_SECURE:
			pr_err(gettext("Cannot mix options "
				"secure and sec\n"));
			break;
		case OPT_SEC:
			count++;
			for (q = val; *q; q++)
				if (*q == ':')
					count++;
			break;
		}
	}

	exp->ex_seccnt = count;

	sp = (struct secinfo *)calloc(count, sizeof (struct secinfo));
	if (sp == NULL)
		pr_err(gettext("ex_secinfo: no memory\n"));

	/*
	 * Initialize some fields
	 */
	for (i = 0; i < count; i++) {
		sp[i].s_flags = 0;
		sp[i].s_window = DEF_WIN;
		sp[i].s_rootcnt = 0;
		sp[i].s_rootnames = NULL;
	}

	exp->ex_secinfo = sp;
	sp1 = sp;

	p = strdup(opts);
	if (p == NULL)
		pr_err(gettext("opts: no memory\n"));

	if (nfs_getseconfig_default(&sp->s_secinfo))
		pr_err(gettext("failed to get default security mode\n"));

	secopt = 0;

	while (*p) {
		savep = p;
		switch (getsubopt(&p, optlist, &val)) {

		case OPT_SEC:
			if (secopt)
				sp++;
			sp1 = sp;
			secopt++;

			while ((f = strtok_r(val, ":", &lasts)) != NULL) {
				if (nfs_getseconfig_byname(f, &sp->s_secinfo))
					pr_err(gettext("Invalid security mode"
						" \"%s\"\n"), f);
				val = NULL;
				if (lasts)
					sp++;
			}
			break;

		case OPT_RO:
			if (secopt == 0)
				pr_err(gettext("need sec option before ro\n"));

			sp->s_flags |= val ? M_ROL : M_RO;

			if (sp->s_flags & M_RO && sp->s_flags & M_RW)
				pr_err(gettext("rw vs ro conflict\n"));
			if (sp->s_flags & M_RO && sp->s_flags & M_ROL)
				pr_err(gettext("Ambiguous ro options\n"));

			for (pt = sp1; pt < sp; pt++)
				pt->s_flags = sp->s_flags;
			break;

		case OPT_RW:
			if (secopt == 0)
				pr_err(gettext("need sec option before rw\n"));

			sp->s_flags |= val ? M_RWL : M_RW;

			if (sp->s_flags & M_RO && sp->s_flags & M_RW)
				pr_err(gettext("ro vs rw conflict\n"));
			if (sp->s_flags & M_RW && sp->s_flags & M_RWL)
				pr_err(gettext("Ambiguous rw options\n"));

			for (pt = sp1; pt < sp; pt++)
				pt->s_flags = sp->s_flags;
			break;

		case OPT_ROOT:
			if (secopt == 0)
				pr_err(gettext("need sec option before "
					"root\n"));

			if (val == NULL)
				pr_err(gettext("missing root list\n"));

			for (pt = sp1; pt <= sp; pt++) {
				pt->s_flags |= M_ROOT;

				/*
				 * Can treat AUTH_UNIX root lists
				 * as a special case and have
				 * the nfsauth service check the
				 * list just like any other access
				 * list, i.e. supports netgroups,
				 * domain suffixes, etc.
				 */
				if (pt->s_secinfo.sc_rpcnum == AUTH_UNIX)
					continue;

				/*
				 * Root lists for other sec types
				 * need to be checked in the
				 * kernel. Build a list of names
				 * to be fed into the kernel via
				 * exportfs().
				 */
				pt->s_rootnames =
					get_rootnames(&pt->s_secinfo, val,
						&pt->s_rootcnt);
				if (pt->s_rootnames == NULL)
					pr_err(gettext("Bad root list\n"));
			}
			break;

		case OPT_WINDOW:
			if (secopt == 0)
				pr_err(gettext("need sec option before "
					"window\n"));

			if (badnum(val))
				pr_err(gettext("invalid window value\n"));
			sp->s_window = atoi(val);

			for (pt = sp1; pt < sp; pt++)
				pt->s_window = sp->s_window;
			break;

		case OPT_ANON:
			if (done_anon++)
				pr_err(gettext("option anon repeated\n"));

			if (!val) {
				pr_err(gettext("missing anon value\n"));
			}
			/* check for special "-1" value, which is ok */
			if (strcmp(val, "-1") != 0 && badnum(val))
				pr_err(gettext("invalid anon value\n"));

			exp->ex_anon = atoi(val);
			break;

		case OPT_NOSUID:
			if (done_nosuid++)
				pr_err(gettext("option nosuid repeated\n"));

			exp->ex_flags |= EX_NOSUID;
			break;

		case OPT_ACLOK:
			if (done_aclok++)
				pr_err(gettext("option aclok repeated\n"));
			exp->ex_flags |= EX_ACLOK;
			break;

		case OPT_NOSUB:
			/*
			 * The "don't allow mount of subdirectories" option.
			 */
			exp->ex_flags |= EX_NOSUB;
			break;

		case OPT_PUBLIC:
			exp->ex_flags |= EX_PUBLIC;
			break;

		case OPT_INDEX:
			exportindex(exp, val);
			break;

		case OPT_LOG:
			configlog(exp, val);
			break;

#ifdef VOLATILE_FH_TEST	/* XXX added for testing volatile fh's only */
		case OPT_VOLFH:
			/* volatile filehandles - expire on share */
			if (val == NULL)
				pr_err(gettext("missing volatile fh types\n"));
			if (nfs4_set_volfh_flags(exp, val))
				pr_err(gettext("invalid volatile fh types\n"));
			break;
#endif /* VOLATILE_FH_TEST */

		default:
			pr_err(gettext("invalid share option: '%s'\n"), savep);
		}
	}

	/*
	 * Set uninitialized flags to "rw"
	 */
	sp = exp->ex_secinfo;
	for (i = 0; i < count; i++) {
		if ((sp[i].s_flags & (M_RO|M_RW|M_RWL|M_ROL)) == 0)
			sp[i].s_flags |= M_RW;
	}
}

/*
 * check the argument specified with the index option and set
 * export index file and flags
 */
static void
exportindex(struct exportdata *exp, char *val)
{
	char *p = val;

	if (val == NULL)
		goto badindexarg;

	p = val;
	while (*p != '\0') {
		if (*p == '/')
			goto badindexarg;
		p++;
	}

	if (strcmp(val, "..") == 0)
		goto badindexarg;

	/*
	 * treat a "." or an empty index string as if the
	 * index option is not present.
	 */
	if (val[0] == '\0' || (strcmp(val, ".") == 0))
		return;

	exp->ex_index = strdup(val);
	if (!exp->ex_index) {
		pr_err(gettext("exportindex: out of memory\n"));
		return;
	}
	exp->ex_flags |= EX_INDEX;

	return;

badindexarg:
	pr_err(gettext("index option requires a filename as argument\n"));
}

/*
 * Given a seconfig entry and a colon-separated
 * list of names, allocate an array big enough
 * to hold the root list, then convert each name to
 * a principal name according to the security
 * info and assign it to an array element.
 * Return the array and its size.
 */
static caddr_t *
get_rootnames(seconfig_t *sec, char *list, int *count)
{
	caddr_t *a;
	int c, i;
	char *host, *p;

	list = strdup(list);
	if (list == NULL)
		pr_err(gettext("get_rootnames: no memory\n"));

	/*
	 * Count the number of strings in the list.
	 * This is the number of colon separators + 1.
	 */
	c = 1;
	for (p = list; *p; p++)
		if (*p == ':')
			c++;
	*count = c;

	a = (caddr_t *)malloc(c * sizeof (char *));
	if (a == NULL)
		pr_err(gettext("get_rootnames: no memory\n"));

	for (i = 0; i < c; i++) {
		host = strtok(list, ":");
		if (!nfs_get_root_principal(sec, host, &a[i])) {
			a = NULL;
			break;
		}
		list = NULL;
	}

	return (a);
}

/*
 * Append an entry to the sharetab file
 */
static int
sharetab_add(dir, res, opts, descr, replace)
	char *dir, *res, *opts, *descr;
	int replace;
{
	int ret;
	FILE *f;
	struct share sh;
	int logging = 0;

	/*
	 * Open the file for update and create it if necessary.
	 * This may leave the I/O offset at the end of the file,
	 * so rewind back to the beginning of the file.
	 */
	f = fopen(SHARETAB, "a+");
	if (f == NULL) {
		pr_err("%s: %s\n", SHARETAB, strerror(errno));
		return (-1);
	}
	rewind(f);

	if (lockf(fileno(f), F_LOCK, 0L) < 0) {
		pr_err(gettext("cannot lock %s: %s\n"),
			SHARETAB, strerror(errno));
		(void) fclose(f);
		return (-1);
	}

	/*
	 * If re-sharing an old share with new options
	 * then first remove the old share entry.
	 */
	if (replace) {
		if ((ret = remshare(f, dir, &logging)) < 0) {
			switch (ret) {
			case -1:
				pr_err(gettext("share complete, however, "
					"failed to remove old sharetab"
					" entry, no memory\n"));
				break;
			case -2:
				pr_err(gettext("share complete, however, "
					"sharetab may be corrupt, ftrucate call"
					" failure during sharetab update\n"));
				break;
			case -3:
				pr_err(gettext("share complete, however, "
					"failed to remove old sharetab entry,"
					" corrupt sharetab file\n"));
				break;
			}
		}

		if (logging) {
			/*
			 * Entry replaced was logged, deactivate it in
			 * nfslogtab.
			 */
			(void) nfslogtab_deactivate(dir);
		}
	}

	sh.sh_path = dir;
	sh.sh_res = res;
	sh.sh_fstype = "nfs";
	sh.sh_opts = opts;
	sh.sh_descr = descr;

	if (putshare(f, &sh) < 0)
		pr_err(gettext("addshare: couldn't add %s to %s\n"),
			dir, SHARETAB);

	(void) fclose(f);
	return (0);
}

/*
 * Append an entry to the nfslogtab file
 */
static int
nfslogtab_add(dir, buffer, tag)
	char *dir, *buffer, *tag;
{
	FILE *f;
	struct logtab_ent lep;
	int error = 0;

	/*
	 * Open the file for update and create it if necessary.
	 * This may leave the I/O offset at the end of the file,
	 * so rewind back to the beginning of the file.
	 */
	f = fopen(NFSLOGTAB, "a+");
	if (f == NULL) {
		error = errno;
		pr_err(gettext(
			"share complete, however failed to open %s "
			"for update: %s\n"), NFSLOGTAB, strerror(errno));
		goto out;
	}
	rewind(f);

	if (lockf(fileno(f), F_LOCK, 0L) < 0) {
		pr_err(gettext(
			"share complete, however failed to lock %s "
			"for update: %s\n"), NFSLOGTAB, strerror(errno));
		error = -1;
		goto out;
	}

	if (logtab_deactivate_after_boot(f) == -1) {
		pr_err(gettext(
			"share complete, however could not deactivate "
			"entries in %s\n"), NFSLOGTAB);
		error = -1;
		goto out;
	}

	/*
	 * Remove entries matching buffer and sharepoint since we're
	 * going to replace it with perhaps an entry with a new tag.
	 */
	if (logtab_rement(f, buffer, dir, NULL, -1)) {
		pr_err(gettext(
			"share complete, however could not remove matching "
			"entries in %s\n"), NFSLOGTAB);
		error = -1;
		goto out;
	}

	/*
	 * Deactivate all active entries matching this sharepoint
	 */
	if (logtab_deactivate(f, NULL, dir, NULL)) {
		pr_err(gettext(
			"share complete, however could not deactivate matching "
			"entries in %s\n"), NFSLOGTAB);
		error = -1;
		goto out;
	}

	lep.le_buffer = buffer;
	lep.le_path = dir;
	lep.le_tag = tag;
	lep.le_state = LES_ACTIVE;

	/*
	 * Add new sharepoint / buffer location to nfslogtab
	 */
	if (logtab_putent(f, &lep) < 0) {
		pr_err(gettext(
			"share complete, however could not add %s to %s\n"),
			dir, NFSLOGTAB);
		error = -1;
	}

out:
	if (f != NULL)
		(void) fclose(f);
	return (error);
}

/*
 * Deactivate an entry from the nfslogtab file
 */
static int
nfslogtab_deactivate(path)
	char *path;
{
	FILE *f;
	int error = 0;

	f = fopen(NFSLOGTAB, "r+");
	if (f == NULL) {
		error = errno;
		fprintf(stderr, gettext(
			"share complete, however could not open %s for "
			"update: %s\n"), NFSLOGTAB, strerror(error));
		goto out;
	}
	if (lockf(fileno(f), F_LOCK, 0L) < 0) {
		error = errno;
		pr_err(gettext(
			"share complete, however could not lock %s for "
			"update: %s\n"), NFSLOGTAB, strerror(error));
		goto out;
	}
	if (logtab_deactivate(f, NULL, path, NULL) == -1) {
		error = -1;
		pr_err(gettext("share complete, however could not "
			"deactivate %s in %s\n"), path, NFSLOGTAB);
		goto out;
	}

out:	if (f != NULL)
		(void) fclose(f);

	return (error);
}

static void
usage()
{
	(void) fprintf(stderr,
	    "Usage: share [-o options] [-d description] pathname [resource]\n");
}

/*
 * This is for testing only
 * It displays the export structure that
 * goes into the kernel.
 */
static void
printarg(char *path, struct exportdata *ep)
{
	int i, j;
	struct secinfo *sp;

	printf("%s:\n", path);
	printf("\tex_version = %d\n", ep->ex_version);
	printf("\tex_path = %s\n", ep->ex_path);
	printf("\tex_pathlen = %d\n", ep->ex_pathlen);
	printf("\tex_flags: (0x%02x) ", ep->ex_flags);
	if (ep->ex_flags & EX_NOSUID)
		printf("NOSUID ");
	if (ep->ex_flags & EX_ACLOK)
		printf("ACLOK ");
	if (ep->ex_flags & EX_PUBLIC)
		printf("PUBLIC ");
	if (ep->ex_flags & EX_NOSUB)
		printf("NOSUB ");
	if (ep->ex_flags & EX_LOG)
		printf("LOG ");
	if (ep->ex_flags & EX_LOG_ALLOPS)
		printf("LOG_ALLOPS ");
	if (ep->ex_flags == 0)
		printf("(none)");
	printf("\n");
	if (ep->ex_flags & EX_LOG) {
		printf("\tex_log_buffer = %s\n",
			(ep->ex_log_buffer ? ep->ex_log_buffer : "(NULL)"));
		printf("\tex_tag = %s\n", (ep->ex_tag ? ep->ex_tag : "(NULL)"));
	}
	printf("\tex_anon = %d\n", ep->ex_anon);
	printf("\tex_seccnt = %d\n", ep->ex_seccnt);
	printf("\n");
	for (i = 0; i < ep->ex_seccnt; i++) {
		sp = &ep->ex_secinfo[i];
		printf("\t\ts_secinfo = %s\n", sp->s_secinfo.sc_name);
		printf("\t\ts_flags: (0x%02x) ", sp->s_flags);
		if (sp->s_flags & M_ROOT) printf("M_ROOT ");
		if (sp->s_flags & M_RO) printf("M_RO ");
		if (sp->s_flags & M_ROL) printf("M_ROL ");
		if (sp->s_flags & M_RW) printf("M_RW ");
		if (sp->s_flags & M_RWL) printf("M_RWL ");
		if (sp->s_flags == 0) printf("(none)");
		printf("\n");
		printf("\t\ts_window = %d\n", sp->s_window);
		printf("\t\ts_rootcnt = %d ", sp->s_rootcnt);
		for (j = 0; j < sp->s_rootcnt; j++)
			printf("%s ", sp->s_rootnames[j]);
		printf("\n\n");
	}
}

/*
 * Look for the specified tag in the configuration file. If it is found,
 * enable logging and set the logging configuration information for exp.
 */
static void
configlog(struct exportdata *exp, char *tag)
{
	nfsl_config_t *configlist, *configp;
	int error = 0;
	char globaltag[] = DEFAULTTAG;

	/*
	 * Sends config errors to stderr
	 */
	nfsl_errs_to_syslog = B_FALSE;

	/*
	 * get the list of configuration settings
	 */
	error = nfsl_getconfig_list(&configlist);
	if (error) {
		pr_err(gettext("Cannot get log configuration: %s\n"),
			strerror(error));
	}

	if (tag == NULL)
		tag = globaltag;
	if ((configp = nfsl_findconfig(configlist, tag, &error)) == NULL) {
		nfsl_freeconfig_list(&configlist);
		pr_err(gettext("No tags matching \"%s\"\n"), tag);
	}

	if ((exp->ex_tag = strdup(tag)) == NULL) {
		error = ENOMEM;
		goto out;
	}
	if ((exp->ex_log_buffer = strdup(configp->nc_bufferpath)) == NULL) {
		error = ENOMEM;
		goto out;
	}
	exp->ex_flags |= EX_LOG;
	if (configp->nc_rpclogpath != NULL)
		exp->ex_flags |= EX_LOG_ALLOPS;
out:
	nfsl_freeconfig_list(&configlist);
	if (error != 0) {
		if (exp->ex_flags != NULL)
			free(exp->ex_tag);
		if (exp->ex_log_buffer != NULL)
			free(exp->ex_log_buffer);
		pr_err(gettext("Cannot set log configuration: %m"),
			strerror(error));
	}
}

/*VARARGS1*/
static void
pr_err(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) fprintf(stderr, "share_nfs: ");
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);
	exit(RET_ERR);
}
