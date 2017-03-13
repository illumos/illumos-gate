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
 * Copyright (c) 2017 Peter Tribble.
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */


#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>
#include <pkginfo.h>
#include <pkglocs.h>
#include <sys/types.h>
#include <pkgstrct.h>
#include <pkgtrans.h>
#include <locale.h>
#include <libintl.h>
#include <pkglib.h>
#include <libadm.h>
#include <libinst.h>

#define	MAXPATHS	1024

#define	MSG_CHK_STRM	"Checking uninstalled stream format package " \
				"<%s> from <%s>\n"
#define	MSG_CHK_DIR	"Checking uninstalled directory format package " \
				"<%s> from <%s>\n"
#define	MSG_NOTROOT	"NOTE: \"root\" permission may be required to " \
				"validate all objects in the client filesystem."
#define	MSG_CONT	"Continuing."

#define	WRN_F_SPOOL	"WARNING: %s is spooled. Ignoring \"f\" argument"

#define	ERR_ROOT_SET	"Could not set install root from the environment."
#define	ERR_ROOT_CMD	"Command line install root contends with environment."
#define	ERR_IOPEN	"unable to open input file <%s>"
#define	ERR_IEMPTY	"no pathnames in file specified by -i option"
#define	ERR_POPTION	"no pathname included with -p option"
#define	ERR_PARTIAL_POPTION	"no pathname included with -P option"
#define	ERR_MAXPATHS	"too many pathnames in option list (limit is %d)"
#define	ERR_NOTROOT	"You must be \"root\" for \"%s -f\" to" \
					"execute properly."
#define	ERR_SEL_PKG "No packages selected for verification."
#define	ERR_CAT_LNGTH "The category argument exceeds the SVr4 ABI\n" \
		"        defined maximum supported length of 16 characters."
#define	ERR_CAT_FND "Category argument <%s> cannot be found."
#define	ERR_CAT_INV "Category argument <%s> is invalid."
#define	ERR_TOO_MANY "too many pathnames in list, limit is %d"
#define	ERR_PATHS_INVALID "Pathnames in %s are not valid."
#define	ERR_MKDIR "unable to make directory <%s>"
#define	ERR_USAGE	"usage:\n" \
		"\t%s [-l|vqacnxf] [-R rootdir] [-p path[, ...] | " \
		"-P path[, ...]]\n" \
		"\t\t[-i file] [options]\n" \
		"\t%s -d device [-f][-l|v] [-p path[, ...] | " \
		"-P path[, ...]]\n" \
		"\t\t[-V ...] [-M] [-i file] [-Y category[, ...] | " \
		"pkginst [...]]\n" \
		"\twhere options may include ONE of the " \
		"following:\n " \
		"\t\t-m pkgmap [-e envfile]\n" \
		"\t\tpkginst [...]\n" \
		"\t\t-Y category[, ...]\n"

#define	LINK	1

char	**pkg = NULL;
int	pkgcnt = 0;
char	*basedir;
char	*pathlist[MAXPATHS], *ppathlist[MAXPATHS], pkgspool[PATH_MAX];
short	used[MAXPATHS];
short	npaths;
struct cfent **eptlist;

int	aflag = (-1);
int	cflag = (-1);
int	vflag = 0;
int	nflag = 0;
int	lflag = 0;
int	Lflag = 0;
int	fflag = 0;
int	xflag = 0;
int	qflag = 0;
int	Rflag = 0;
int	dflag = 0;
char 	*device;

char	*uniTmp;

static char	*mapfile,
		*spooldir,
		*tmpdir,
		*envfile;
static int	errflg = 0;
static int	map_client = 1;

void	quit(int);
static void	setpathlist(char *);
static void	usage(void);

extern	char	**environ;
extern	char	*pkgdir;

/* checkmap.c */
extern int	checkmap(int, int, char *, char *, char *, char *, int);
/* scriptvfy.c */
extern int	checkscripts(char *inst_dir, int silent);

int
main(int argc, char *argv[])
{
	int	pkgfmt = 0;	/* Makes more sense as a pointer, but */
				/*	18N is compromised. */
	char	file[PATH_MAX+1],
		*abi_sym_ptr,
		*vfstab_file = NULL;
	char *all_pkgs[4] = {"all", NULL};
	char **category = NULL;
	char *catg_arg = NULL;
	int	c;
	int	n = 0;
	char	*prog,
		*Rvalue,
		*dvalue;
	int dbcreate = 0;
	int pathtype;

	/* initialize locale mechanism */

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	/* determine program name */

	prog = set_prog_name(argv[0]);

	/* establish installation root directory */

	if (!set_inst_root(getenv("PKG_INSTALL_ROOT"))) {
		progerr(gettext(ERR_ROOT_SET));
		quit(1);
	}

	/* check if not ABI compliant mode */
	abi_sym_ptr = getenv("PKG_NONABI_SYMLINKS");
	if (abi_sym_ptr && strncasecmp(abi_sym_ptr, "TRUE", 4) == 0) {
		set_nonABI_symlinks();
	}

	/* bugId 4012147 */
	if ((uniTmp = getenv("PKG_NO_UNIFIED")) != NULL)
		map_client = 0;

	while ((c = getopt(argc, argv, "Y:R:e:p:d:nLli:vaV:Mm:cqxfQP:?"))
			!= EOF) {
		switch (c) {
		case 'p':
			pathlist[npaths] = strtok(optarg, " , ");
			if (pathlist[npaths++] == NULL) {
				progerr(gettext(ERR_POPTION));
				quit(1);
			}
			while (pathlist[npaths] = strtok(NULL, " , ")) {
				if (npaths++ >= MAXPATHS) {
					progerr(gettext(ERR_MAXPATHS),
						MAXPATHS);
					quit(1);
				}
			}
			break;

		case 'd':
			dvalue = optarg;
			dflag = 1;
			break;

		case 'n':
			nflag++;
			break;

		case 'M':
			map_client = 0;
			break;

		/*
		 * Allow admin to establish the client filesystem using a
		 * vfstab-like file of stable format.
		 */
		case 'V':
			vfstab_file = flex_device(optarg, 2);
			map_client = 1;
			break;

		case 'f':
			if (getuid()) {
				progerr(gettext(ERR_NOTROOT), prog);
				quit(1);
			}
			fflag++;
			break;

		case 'i':
			setpathlist(optarg);
			break;

		case 'v':
			vflag++;
			break;

		case 'l':
			lflag++;
			break;

		case 'L':
			Lflag++;
			break;

		case 'x':
			if (aflag < 0)
				aflag = 0;
			if (cflag < 0)
				cflag = 0;
			xflag++;
			break;

		case 'q':
			qflag++;
			break;

		case 'a':
			if (cflag < 0)
				cflag = 0;
			aflag = 1;
			break;

		case 'c':
			if (aflag < 0)
				aflag = 0;
			cflag = 1;
			break;

		case 'e':
			envfile = optarg;
			break;

		case 'm':
			mapfile = optarg;
			break;

		case 'R':
			Rvalue = optarg;
			Rflag = 1;
			break;

		case 'Y':
			catg_arg = strdup(optarg);

			if ((category = get_categories(catg_arg)) == NULL) {
				progerr(gettext(ERR_CAT_INV), catg_arg);
				quit(1);
			} else if (is_not_valid_length(category)) {
				progerr(gettext(ERR_CAT_LNGTH));
				quit(1);
			}
			break;

		case 'Q':
			dbcreate++;
			break;

		case 'P':
			ppathlist[npaths] = strtok(optarg, " , ");
			if ((ppathlist[npaths] == NULL) ||
			    (ppathlist[npaths][0] == '-')) {
				progerr(gettext(ERR_PARTIAL_POPTION));
				quit(1);
			}
			npaths++;
			while (ppathlist[npaths] = strtok(NULL, " , ")) {
				if (npaths++ >= MAXPATHS) {
					progerr(gettext(ERR_MAXPATHS),
						MAXPATHS);
					quit(1);
				}
			}
			break;

		default:
			usage();
			/*NOTREACHED*/
			/*
			 * Although usage() calls a noreturn function,
			 * needed to add return (1);  so that main() would
			 * pass compilation checks. The statement below
			 * should never be executed.
			 */
			return (1);
		}
	}

	/* Check for incompatible options */
	if (dflag && Rflag)
		usage();

	/* Check for root dir and device dir if set */
	if (Rflag) {
		if (!set_inst_root(Rvalue)) {
			progerr(gettext(ERR_ROOT_CMD));
			quit(1);
		}
	}

	if (dflag)
		device = flex_device(dvalue, 1);

	if (lflag || Lflag) {
		/* we're only supposed to list information */
		if ((cflag >= 0) || (aflag >= 0) ||
		qflag || xflag || fflag || nflag || vflag)
			usage();
	}

	set_PKGpaths(get_inst_root());

	if (catg_arg != NULL && device == NULL) {
		if (argc - optind) {
			usage();
		}
		pkg = gpkglist(pkgdir, all_pkgs, category);
		if (pkg == NULL) {
			progerr(gettext(ERR_CAT_FND), catg_arg);
			quit(1);
		} else {
			for (pkgcnt = 0; pkg[pkgcnt] != NULL; pkgcnt++);
		}
	} else if (catg_arg != NULL && optind < argc) {
		usage();
	} else {
		pkg = &argv[optind];
		pkgcnt = (argc - optind);
	}

	/* read the environment for the pkgserver */
	pkgserversetmode(DEFAULTMODE);

	environ = NULL;		/* Sever the parent environment. */

	if (vcfile() == 0) {
		quit(99);
	}

	errflg = 0;
	if (mapfile) {
		/* check for incompatible options */
		if (device || pkgcnt)
			usage();
		put_path_params();	/* Restore what's needed. */

		/* send pathtype if partial path */
		pathtype = (ppathlist[0] != NULL) ? 1 : 0;
		if (checkmap(0, (device != NULL), mapfile, envfile, NULL,
		    NULL, pathtype))
			errflg++;
	} else if (device) {
		/* check for incompatible options */
		if ((cflag >= 0) || (aflag >= 0))
			usage();
		if (qflag || xflag || nflag || envfile)
			usage();
		tmpdir = NULL;
		if ((spooldir = devattr(device, "pathname")) == NULL)
			spooldir = device;
		if (isdir(spooldir)) {
			tmpdir = spooldir = qstrdup(tmpnam(NULL));
			if (fflag) {
				logerr(gettext(WRN_F_SPOOL), *pkg);
				fflag = 0;
			}
			if (mkdir(spooldir, 0755)) {
				progerr(gettext(ERR_MKDIR), spooldir);
				quit(99);
			}
			if (n = pkgtrans(device, spooldir, pkg, PT_SILENT))
				quit(n);
			if (catg_arg != NULL)
				pkg = gpkglist(spooldir, all_pkgs, category);
			else
				pkg = gpkglist(spooldir, all_pkgs, NULL);
			pkgfmt = 0;
		} else {
			if (catg_arg != NULL)
				pkg = gpkglist(spooldir,
					pkgcnt ? pkg : all_pkgs, category);
			else
				pkg = gpkglist(spooldir,
					pkgcnt ? pkg : all_pkgs, NULL);
			pkgfmt = 1;
		}

		/*
		 * At this point pkg[] is the list of packages to check. They
		 * are in directory format in spooldir.
		 */
		if (pkg == NULL) {
			if (catg_arg != NULL) {
				progerr(gettext(ERR_CAT_FND), catg_arg);
				quit(1);
			} else {
				progerr(gettext(ERR_SEL_PKG));
				quit(1);
			}
		}

		aflag = 0;

		for (n = 0; pkg[n]; n++) {
			char locenv[PATH_MAX];

			if (pkgfmt)
				(void) printf(
					gettext(MSG_CHK_DIR), pkg[n], device);
			else
				(void) printf(
					gettext(MSG_CHK_STRM), pkg[n], device);

			(void) snprintf(pkgspool, sizeof (pkgspool),
				"%s/%s", spooldir, pkg[n]);
			(void) snprintf(file, sizeof (file),
				"%s/install", pkgspool);
			/* Here we check the install scripts. */
			(void) printf(
				gettext("## Checking control scripts.\n"));
			(void) checkscripts(file, 0);
			/* Verify consistency with the pkgmap. */
			(void) printf(
				gettext("## Checking package objects.\n"));
			(void) snprintf(file, sizeof (file),
				"%s/pkgmap", pkgspool);
			(void) snprintf(locenv, sizeof (locenv),
				"%s/pkginfo", pkgspool);
			envfile = locenv;

			/*
			 * NOTE : checkmap() frees the environ data and
			 * pointer when it's through with them.
			 */
			if (checkmap(0, (device != NULL), file, envfile,
					pkg[n], NULL, 0))
				errflg++;
			(void) printf(
				gettext("## Checking is complete.\n"));
		}
	} else {
		if (envfile)
			usage();

		put_path_params();	/* Restore what's needed. */

		/*
		 * If this is a check of a client of some sort, we'll need to
		 * mount up the client's filesystems. If the caller isn't
		 * root, this may not be possible.
		 */
		if (is_an_inst_root()) {
			if (getuid()) {
				logerr(gettext(MSG_NOTROOT));
				logerr(gettext(MSG_CONT));
			} else {
				if (get_mntinfo(map_client, vfstab_file))
					map_client = 0;
				if (map_client)
					mount_client();
			}
		}

		(void) snprintf(file, sizeof (file),
			"%s/contents", get_PKGADM());
		if (ppathlist[0] != NULL) {
			for (n = 0; ppathlist[n]; n++) {
				if (checkmap(1, (device != NULL), file, NULL,
						NULL, ppathlist[n], 1))
					errflg++;
			}
		} else if (pkg[0] != NULL) {
				if (checkmap(1, (device != NULL), file, NULL,
					pkg[0], NULL, 0)) {
					errflg++;
				}
		} else {
			if (checkmap(1, (device != NULL), file, NULL,
					NULL, NULL, 0)) {
				errflg++;
			}
		}

		if (map_client) {
			unmount_client();
		}
	}
	quit(errflg ? 1 : 0);
	/* LINTED: no return */
}

static void
setpathlist(char *file)
{
	int fd;
	struct stat st;
	FILE *fplist;
	char pathname[PATH_MAX];
	/*
	 * This trap laid to catch a mismatch between the declaration above and
	 * the hard-coded constant in the fscanf below
	 */
#if PATH_MAX != 1024
#error "PATH_MAX changed, so we have a bug to fix"
#endif

	if (strcmp(file, "-") == 0) {
		fplist = stdin;
	} else {
		if ((fd = open(file, O_RDONLY)) == -1) {
			progerr(gettext(ERR_IOPEN), file);
			quit(1);
		}
		if (fstat(fd, &st) == -1) {
			progerr(gettext(ERR_IOPEN), file);
			quit(1);
		}
		if (S_ISDIR(st.st_mode) || S_ISBLK(st.st_mode)) {
			progerr(gettext(ERR_PATHS_INVALID), file);
			quit(1);
		}
		if ((fplist = fdopen(fd, "r")) == NULL) {
			progerr(gettext(ERR_IOPEN), file);
			quit(1);
		}
	}
	while (fscanf(fplist, "%1024s", pathname) == 1) {
		if (*pathname == '\0') {
			progerr(gettext(ERR_PATHS_INVALID), file);
			quit(1);
		}
		pathlist[npaths] = qstrdup(pathname);
		if (npaths++ > MAXPATHS) {
			progerr(gettext(ERR_TOO_MANY), MAXPATHS);
			quit(1);
		}
	}
	if (npaths == 0) {
		progerr(gettext(ERR_IEMPTY));
		quit(1);
	}
	(void) fclose(fplist);
}

void
quit(int n)
{
	/* cleanup any temporary directories */
	(void) chdir("/");
	if (tmpdir != NULL) {
		(void) rrmdir(tmpdir);
		free(tmpdir);
		tmpdir = NULL;
	}
	(void) pkghead(NULL);
	exit(n);
	/*NOTREACHED*/
}

static void
usage(void)
{
	char *prog = get_prog_name();

	(void) fprintf(stderr, gettext(ERR_USAGE), prog, prog);
	quit(1);
	/*NOTREACHED*/
}
