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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */


#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <malloc.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <ctype.h>
#include <sys/mman.h>
#include <sys/sysmacros.h>
#include <strings.h>
#include <pkgstrct.h>
#include <pkgdev.h>
#include <pkginfo.h>
#include <pkglocs.h>
#include <locale.h>
#include <libintl.h>
#include <sys/statvfs.h>
#include <sys/utsname.h>
#include <instzones_api.h>
#include <pkglib.h>
#include <libadm.h>
#include <libinst.h>

extern char	**environ, *pkgdir;

/* mkpkgmap.c */
extern int	mkpkgmap(char *outfile, char *protofile, char **cmdparam);
/* splpkgmap.c */
extern int	splpkgmap(struct cfent **eptlist, unsigned int eptnum,
    char *order[], ulong_t bsize, ulong_t frsize, fsblkcnt_t *plimit,
    fsfilcnt_t *pilimit, fsblkcnt_t *pllimit);
/* scriptvfy.c */
extern int	checkscripts(char *inst_dir, int silent);

/* libpkg/gpkgmap.c */
extern void	setmapmode(int mode_no);

static boolean_t valid_zone_attr(struct cfent **eptlist);

#define	MALSIZ	16
#define	NROOT	8
#define	SPOOLDEV	"spool"

#define	MSG_PROTOTYPE	"## Building pkgmap from package prototype file.\n"
#define	MSG_PKGINFO	"## Processing pkginfo file.\n"
#define	MSG_VOLUMIZE	"## Attempting to volumize %d entries in pkgmap.\n"
#define	MSG_PACKAGE1	"## Packaging one part.\n"
#define	MSG_PACKAGEM	"## Packaging %d parts.\n"
#define	MSG_VALSCRIPTS	"## Validating control scripts.\n"

/* Other problems */
#define	ERR_MEMORY	"memory allocation failure, errno=%d"
#define	ERR_NROOT	"too many paths listed with -r option, limit is %d"
#define	ERR_PKGINST	"invalid package instance identifier <%s>"
#define	ERR_PKGABRV	"invalid package abbreviation <%s>"
#define	ERR_BADDEV	"unknown or invalid device specified <%s>"
#define	ERR_TEMP	"unable to obtain temporary file resources, errno=%d"
#define	ERR_DSTREAM	"invalid device specified (datastream) <%s>"
#define	ERR_SPLIT	"unable to volumize package"
#define	ERR_MKDIR	"unable to make directory <%s>"
#define	ERR_SYMLINK	"unable to create symbolic link for <%s>"
#define	ERR_OVERWRITE	"must use -o option to overwrite <%s>"
#define	ERR_UMOUNT	"unable to unmount device <%s>"
#define	ERR_NOPKGINFO	"required pkginfo file is not specified in prototype " \
			"file"
#define	ERR_RDPKGINFO	"unable to process pkginfo file <%s>"
#define	ERR_PROTOTYPE	"unable to locate prototype file"
#define	ERR_STATVFS	"unable to stat filesystem <%s>"
#define	ERR_WHATVFS	"unable to determine or access output filesystem for " \
			"device <%s>"
#define	ERR_DEVICE	"unable to find info for device <%s>"
#define	ERR_BUILD	"unable to build pkgmap from prototype file"
#define	ERR_ONEVOL	"other packages found - package must fit on a single " \
			"volume"
#define	ERR_NOPARAM	"parameter <%s> is not defined in <%s>"
#define	ERR_PKGMTCH	"PKG parameter <%s> does not match instance <%s>"
#define	ERR_NO_PKG_INFOFILE	"unable to open pkginfo file <%s>: %s"
#define	ERR_ALLZONES_AND_THISZONE	"The package <%s> has <%s> = true " \
					"and <%s> = true: the package may " \
					"set either parameter to true, but " \
					"may not set both parameters to " \
					"true. NOTE: if the package " \
					"contains a request script, it is " \
					"treated as though it has " \
					"<SUNW_PKG_THISZONE> = true"
#define	ERR_NO_ALLZONES_AND_HOLLOW	"The package <%s> has <%s> = false " \
					"and <%s> = true: a hollow package " \
					"must also be set to install in all " \
					"zones"
#define	ERR_PKGINFO_INVALID_OPTION_COMB	"Invalid combinations of zone " \
					"parameters in pkginfo file"

#define	ERR_USAGE	"usage: %s [options] [VAR=value [VAR=value]] " \
			"[pkginst]\n" \
			"   where options may include:\n" \
			"\t-o\n" \
			"\t-a arch\n" \
			"\t-v version\n" \
			"\t-p pstamp\n" \
			"\t-l limit\n" \
			"\t-r rootpath\n" \
			"\t-b basedir\n" \
			"\t-d device\n" \
			"\t-f protofile\n"
#define	WRN_MISSINGDIR	"WARNING: missing directory entry for <%s>"
#define	WRN_SETPARAM	"WARNING: parameter <%s> set to \"%s\""
#define	WRN_CLASSES	"WARNING: unreferenced class <%s> in prototype file"

#define	LINK    1

struct pkgdev pkgdev; 	/* holds info about the installation device */
int	started;
char	pkgloc[PATH_MAX];
char	*basedir;
char	*root;
char	*rootlist[NROOT];
char	*t_pkgmap;
char	*t_pkginfo;

static struct cfent *svept;
static char	*protofile,
		*device;
static fsblkcnt_t limit = 0;
static fsblkcnt_t llimit = 0;
static fsfilcnt_t ilimit = 0;
static int	overwrite,
		nflag,
		sflag;
static void	ckmissing(char *path, char type);
static void	outvol(struct cfent **eptlist, unsigned int eptnum, int part,
			int nparts);
static void	trap(int n);
static void	usage(void);

static int	slinkf(char *from, char *to);

int
main(int argc, char *argv[])
{
	struct utsname utsbuf;
	struct statvfs64 svfsb;
	struct cfent	**eptlist;
	FILE	*fp;
	VFP_T	*vfp;
	int	c, n, found;
	int	part, nparts, npkgs, objects;
	char	buf[MAX_PKG_PARAM_LENGTH];
	char	temp[MAX_PKG_PARAM_LENGTH];
	char	param[MAX_PKG_PARAM_LENGTH];
	char	*pt, *value, *pkginst, *tmpdir, *abi_sym_ptr,
		**cmdparam;
	char	*pkgname;
	char	*pkgvers;
	char	*pkgarch;
	char	*pkgcat;
	void	(*func)();
	time_t	clock;
	ulong_t	bsize = 0;
	ulong_t	frsize = 0;
	struct cl_attr	**allclass = NULL;
	struct cl_attr	**order;
	unsigned int eptnum, i;

	/* initialize locale environment */

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	/* initialize program name */

	(void) set_prog_name(argv[0]);

	/* tell spmi zones interface how to access package output functions */

	z_set_output_functions(echo, echoDebug, progerr);

	func = sigset(SIGINT, trap);
	if (func != SIG_DFL)
		func = sigset(SIGINT, func);
	func = sigset(SIGHUP, trap);
	setmapmode(MAPBUILD);	/* variable binding */
	if (func != SIG_DFL)
		func = sigset(SIGHUP, func);

	environ = NULL;
	while ((c = getopt(argc, argv, "osnp:l:r:b:d:f:a:v:?")) != EOF) {
		switch (c) {
		    case 'n':
			nflag++;
			break;

		    case 's':
			sflag++;
			break;

		    case 'o':
			overwrite++;
			break;

		    case 'p':
			putparam("PSTAMP", optarg);
			break;

		    case 'l':
			llimit = strtoull(optarg, NULL, 10);
			break;

		    case 'r':
			pt = strtok(optarg, " \t\n, ");
			n = 0;
			do {
				rootlist[n++] = flex_device(pt, 0);
				if (n >= NROOT) {
					progerr(gettext(ERR_NROOT), NROOT);
					quit(1);
				}
			} while (pt = strtok(NULL, " \t\n, "));
			rootlist[n] = NULL;
			break;

		    case 'b':
			basedir = optarg;
			break;

		    case 'f':
			protofile = optarg;
			break;

		    case 'd':
			device = flex_device(optarg, 1);
			break;

		    case 'a':
			putparam("ARCH", optarg);
			break;

		    case 'v':
			putparam("VERSION", optarg);
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

	/*
	 * Store command line variable assignments for later
	 * incorporation into the environment.
	 */
	cmdparam = &argv[optind];

	/* Skip past equates. */
	while (argv[optind] && strchr(argv[optind], '='))
		optind++;

	/* Confirm that the instance name is valid */
	if ((pkginst = argv[optind]) != NULL) {
		if (pkgnmchk(pkginst, "all", 0)) {
			progerr(gettext(ERR_PKGINST), pkginst);
			quit(1);
		}
		argv[optind++] = NULL;
	}
	if (optind != argc)
		usage();

	tmpdir = getenv("TMPDIR");
	if (tmpdir == NULL)
		tmpdir = P_tmpdir;

	/* bug id 4244631, not ABI compliant */
	abi_sym_ptr = getenv("PKG_NONABI_SYMLINKS");
	if (abi_sym_ptr && (strncasecmp(abi_sym_ptr, "TRUE", 4) == 0)) {
		set_nonABI_symlinks();
	}

	if (device == NULL) {
		device = devattr(SPOOLDEV, "pathname");
		if (device == NULL) {
			progerr(gettext(ERR_DEVICE), SPOOLDEV);
			exit(99);
		}
	}

	if (protofile == NULL) {
		if (access("prototype", 0) == 0)
			protofile = "prototype";
		else if (access("Prototype", 0) == 0)
			protofile = "Prototype";
		else {
			progerr(gettext(ERR_PROTOTYPE));
			quit(1);
		}
	}

	if (devtype(device, &pkgdev)) {
		progerr(gettext(ERR_BADDEV), device);
		quit(1);
	}
	if (pkgdev.norewind) {
		/* initialize datastream */
		progerr(gettext(ERR_DSTREAM), device);
		quit(1);
	}
	if (pkgdev.mount) {
		if (n = pkgmount(&pkgdev, NULL, 0, 0, 1))
			quit(n);
	}

	/*
	 * convert prototype file to a pkgmap, while locating
	 * package objects in the current environment
	 */
	t_pkgmap = tempnam(tmpdir, "tmpmap");
	if (t_pkgmap == NULL) {
		progerr(gettext(ERR_TEMP), errno);
		exit(99);
	}

	(void) fprintf(stderr, gettext(MSG_PROTOTYPE));
	if (n = mkpkgmap(t_pkgmap, protofile, cmdparam)) {
		progerr(gettext(ERR_BUILD));
		quit(1);
	}

	setmapmode(MAPNONE);	/* All appropriate variables are now bound */

	if (vfpOpen(&vfp, t_pkgmap, "r", VFP_NEEDNOW) != 0) {
		progerr(gettext(ERR_TEMP), errno);
		quit(99);
	}

	eptlist = procmap(vfp, 0, NULL);

	if (eptlist == NULL) {
		quit(1);
	}

	(void) vfpClose(&vfp);

	/* Validate the zone attributes in pkginfo, before creation */
	if (!valid_zone_attr(eptlist)) {
		progerr(ERR_PKGINFO_INVALID_OPTION_COMB);
		quit(1);
	}

	(void) fprintf(stderr, gettext(MSG_PKGINFO));
	pt = NULL;
	for (i = 0; eptlist[i]; i++) {
		ckmissing(eptlist[i]->path, eptlist[i]->ftype);
		if (eptlist[i]->ftype != 'i')
			continue;
		if (strcmp(eptlist[i]->path, "pkginfo") == 0)
			svept = eptlist[i];
	}
	if (svept == NULL) {
		progerr(gettext(ERR_NOPKGINFO));
		quit(99);
	}
	eptnum = i;

	/*
	 * process all parameters from the pkginfo file
	 * and place them in the execution environment
	 */

	if ((fp = fopen(svept->ainfo.local, "r")) == NULL) {
		progerr(gettext(ERR_RDPKGINFO), svept->ainfo.local);
		quit(99);
	}
	param[0] = '\0';
	while (value = fpkgparam(fp, param)) {
		if (getenv(param) == NULL)
			putparam(param, value);
		free((void *)value);
		param[0] = '\0';
	}
	(void) fclose(fp);

	/* add command line variables */
	while (*cmdparam && (value = strchr(*cmdparam, '=')) != NULL) {
		*value = '\0';	/* terminate the parameter */
		value++;	/* value is now the value (not '=') */
		putparam(*cmdparam++, value);  /* store it in environ */
	}

	/* make sure parameters are valid */
	(void) time(&clock);
	if (pt = getenv("PKG")) {
		if (pkgnmchk(pt, NULL, 0) || strchr(pt, '.')) {
			progerr(gettext(ERR_PKGABRV), pt);
			quit(1);
		}
		if (pkginst == NULL)
			pkginst = pt;
	} else {
		progerr(gettext(ERR_NOPARAM), "PKG", svept->path);
		quit(1);
	}
	/*
	 * verify consistency between PKG parameter and pkginst
	 */
	(void) snprintf(param, sizeof (param), "%s.*", pt);
	if (pkgnmchk(pkginst, param, 0)) {
		progerr(gettext(ERR_PKGMTCH), pt, pkginst);
		quit(1);
	}

	if ((pkgname = getenv("NAME")) == NULL) {
		progerr(gettext(ERR_NOPARAM), "NAME", svept->path);
		quit(1);
	}
	if (ckparam("NAME", pkgname))
		quit(1);
	if ((pkgvers = getenv("VERSION")) == NULL) {
		/* XXX - I18n */
		/* LINTED do not use cftime(); use strftime instead */
		(void) cftime(buf, "\045m/\045d/\045Y", &clock);
		(void) snprintf(temp, sizeof (temp),
			gettext("Dev Release %s"), buf);
		putparam("VERSION", temp);
		pkgvers = getenv("VERSION");
		logerr(gettext(WRN_SETPARAM), "VERSION", temp);
	}
	if (ckparam("VERSION", pkgvers))
		quit(1);
	if ((pkgarch = getenv("ARCH")) == NULL) {
		(void) uname(&utsbuf);
		putparam("ARCH", utsbuf.machine);
		pkgarch = getenv("ARCH");
		logerr(gettext(WRN_SETPARAM), "ARCH", utsbuf.machine);
	}
	if (ckparam("ARCH", pkgarch))
		quit(1);
	if (getenv("PSTAMP") == NULL) {
		/* use octal value of '%' to fight sccs expansion */
		/* XXX - I18n */
		/* LINTED do not use cftime(); use strftime instead */
		(void) cftime(buf, "\045Y\045m\045d\045H\045M\045S", &clock);
		(void) uname(&utsbuf);
		(void) snprintf(temp, sizeof (temp), "%s%s",
			utsbuf.nodename, buf);
		putparam("PSTAMP", temp);
		logerr(gettext(WRN_SETPARAM), "PSTAMP", temp);
	}
	if ((pkgcat = getenv("CATEGORY")) == NULL) {
		progerr(gettext(ERR_NOPARAM), "CATEGORY", svept->path);
		quit(1);
	}
	if (ckparam("CATEGORY", pkgcat))
		quit(1);

	/*
	 * warn user of classes listed in package which do
	 * not appear in CLASSES variable in pkginfo file
	 */
	objects = 0;
	for (i = 0; eptlist[i]; i++) {
		if (eptlist[i]->ftype != 'i') {
			objects++;
			addlist(&allclass, eptlist[i]->pkg_class);
		}
	}

	if ((pt = getenv("CLASSES")) == NULL) {
		if (allclass && *allclass) {
			cl_setl(allclass);
			cl_putl("CLASSES", allclass);
			logerr(gettext(WRN_SETPARAM), "CLASSES",
			    getenv("CLASSES"));
		}
	} else {
		cl_sets(qstrdup(pt));
		if (allclass && *allclass) {
			for (i = 0; allclass[i]; i++) {
				found = 0;
				if (cl_idx(allclass[i]->name) != -1) {
					found++;
					break;
				}
				if (!found) {
					logerr(gettext(WRN_CLASSES),
					    (char *)allclass[i]);
				}
			}
		}
	}

	(void) fprintf(stderr, gettext(MSG_VOLUMIZE), objects);
	order = (struct cl_attr **)0;
	if (pt = getenv("ORDER")) {
		pt = qstrdup(pt);
		(void) setlist(&order, pt);
		cl_putl("ORDER", order);
	}

	/* stat the intended output filesystem to get blocking information */
	if (pkgdev.dirname == NULL) {
		progerr(gettext(ERR_WHATVFS), device);
		quit(99);
	}
	if (statvfs64(pkgdev.dirname, &svfsb)) {
		progerr(gettext(ERR_STATVFS), pkgdev.dirname);
		quit(99);
	}

	if (bsize == 0) {
		bsize = svfsb.f_bsize;
	}
	if (frsize == 0) {
		frsize = svfsb.f_frsize;
	}

	if (limit == 0)
		/*
		 * bavail is in terms of fragment size blocks - change
		 * to 512 byte blocks
		 */
		limit = (fsblkcnt_t)(((fsblkcnt_t)frsize > 0) ?
			howmany(frsize, DEV_BSIZE) :
			howmany(bsize, DEV_BSIZE)) * svfsb.f_bavail;

	if (ilimit == 0) {
		ilimit = (svfsb.f_favail > 0) ?
		    svfsb.f_favail : svfsb.f_ffree;
	}

	nparts = splpkgmap(eptlist, eptnum, (char **)order, bsize, frsize,
	    &limit, &ilimit, &llimit);

	if (nparts <= 0) {
		progerr(gettext(ERR_SPLIT));
		quit(1);
	}

	if (nflag) {
		for (i = 0; eptlist[i]; i++)
			(void) ppkgmap(eptlist[i], stdout);
		exit(0);
		/*NOTREACHED*/
	}

	(void) snprintf(pkgloc, sizeof (pkgloc), "%s/%s",
			pkgdev.dirname, pkginst);
	if (!isdir(pkgloc) && !overwrite) {
		progerr(gettext(ERR_OVERWRITE), pkgloc);
		quit(1);
	}

	/* output all environment install parameters */
	t_pkginfo = tempnam(tmpdir, "pkginfo");
	if ((fp = fopen(t_pkginfo, "w")) == NULL) {
		progerr(gettext(ERR_TEMP), errno);
		exit(99);
	}
	for (i = 0; environ[i]; i++) {
		if (isupper(*environ[i])) {
			(void) fputs(environ[i], fp);
			(void) fputc('\n', fp);
		}
	}
	(void) fclose(fp);

	started++;
	(void) rrmdir(pkgloc);
	if (mkdir(pkgloc, 0755)) {
		progerr(gettext(ERR_MKDIR), pkgloc);
		quit(1);
	}

	/* determine how many packages already reside on the medium */
	pkgdir = pkgdev.dirname;
	npkgs = 0;
	while (pt = fpkginst("all", NULL, NULL))
		npkgs++;
	(void) fpkginst(NULL); /* free resource usage */

	if (nparts > 1) {
		if (pkgdev.mount && npkgs) {
			progerr(gettext(ERR_ONEVOL));
			quit(1);
		}
	}

	/*
	 *  update pkgmap entry for pkginfo file, since it may
	 *  have changed due to command line or failure to
	 *  specify all neccessary parameters
	 */
	for (i = 0; eptlist[i]; i++) {
		if (eptlist[i]->ftype != 'i')
			continue;
		if (strcmp(eptlist[i]->path, "pkginfo") == 0) {
			svept = eptlist[i];
			svept->ftype = '?';
			svept->ainfo.local = t_pkginfo;
			(void) cverify(0, &svept->ftype, t_pkginfo,
				&svept->cinfo, 1);
			svept->ftype = 'i';
			break;
		}
	}

	if (nparts > 1)
		(void) fprintf(stderr, gettext(MSG_PACKAGEM), nparts);
	else
		(void) fprintf(stderr, gettext(MSG_PACKAGE1));

	for (part = 1; part <= nparts; part++) {
		if ((part > 1) && pkgdev.mount) {
			if (pkgumount(&pkgdev)) {
				progerr(gettext(ERR_UMOUNT), pkgdev.mount);
				quit(99);
			}
			if (n = pkgmount(&pkgdev, NULL, part, nparts, 1))
				quit(n);
			(void) rrmdir(pkgloc);
			if (mkdir(pkgloc, 0555)) {
				progerr(gettext(ERR_MKDIR), pkgloc);
				quit(99);
			}
		}
		outvol(eptlist, eptnum, part, nparts);

		/* Validate (as much as possible) the control scripts. */
		if (part == 1) {
			char inst_path[PATH_MAX];

			(void) fprintf(stderr, gettext(MSG_VALSCRIPTS));
			(void) snprintf(inst_path, sizeof (inst_path),
					"%s/install", pkgloc);
			checkscripts(inst_path, 0);
		}
	}

	quit(0);
	/* LINTED: no return */
}

static void
trap(int n)
{
	(void) signal(SIGINT, SIG_IGN);
	(void) signal(SIGHUP, SIG_IGN);

	if (n == SIGINT)
		quit(3);
	else {
		(void) fprintf(stderr, gettext("%s terminated (signal %d).\n"),
				get_prog_name(), n);
		quit(99);
	}
}

static void
outvol(struct cfent **eptlist, unsigned int eptnum, int part, int nparts)
{
	FILE	*fp;
	char	*svpt, *path, temp[PATH_MAX];
	unsigned int	i;


	if (nparts > 1)
		(void) fprintf(stderr, gettext(" -- part %2d:\n"), part);
	if (part == 1) {
		/* re-write pkgmap, but exclude local pathnames */
		(void) snprintf(temp, sizeof (temp), "%s/pkgmap", pkgloc);
		if ((fp = fopen(temp, "w")) == NULL) {
			progerr(gettext(ERR_TEMP), errno);
			quit(99);
		}
		(void) fprintf(fp, ": %d %llu\n", nparts, limit);
		for (i = 0; eptlist[i]; i++) {
			svpt = eptlist[i]->ainfo.local;
			if (!strchr("sl", eptlist[i]->ftype))
				eptlist[i]->ainfo.local = NULL;
			if (ppkgmap(eptlist[i], fp)) {
				progerr(gettext(ERR_TEMP), errno);
				quit(99);
			}
			eptlist[i]->ainfo.local = svpt;
		}
		(void) fclose(fp);
		(void) fprintf(stderr, "%s\n", temp);
	}

	(void) snprintf(temp, sizeof (temp), "%s/pkginfo", pkgloc);
	if (copyf(svept->ainfo.local, temp, svept->cinfo.modtime))
		quit(1);
	(void) fprintf(stderr, "%s\n", temp);

	for (i = 0; i < eptnum; i++) {
		if (eptlist[i]->volno != part)
			continue;
		if (strchr("dxslcbp", eptlist[i]->ftype))
			continue;
		if (eptlist[i]->ftype == 'i') {
			if (eptlist[i] == svept)
				continue; /* don't copy pkginfo file */
			(void) snprintf(temp, sizeof (temp),
				"%s/install/%s", pkgloc,
				eptlist[i]->path);
			path = temp;
		} else
			path = srcpath(pkgloc, eptlist[i]->path, part, nparts);
		if (sflag) {
			if (slinkf(eptlist[i]->ainfo.local, path))
				quit(1);
		} else if (copyf(eptlist[i]->ainfo.local, path,
				eptlist[i]->cinfo.modtime)) {
			quit(1);
		}

		/*
		 * If the package file attributes can be sync'd up with
		 * the pkgmap, we fix the attributes here.
		 */
		if (*(eptlist[i]->ainfo.owner) != '$' &&
		    *(eptlist[i]->ainfo.group) != '$') {
			/* Clear dangerous bits. */
			eptlist[i]->ainfo.mode=
			    (eptlist[i]->ainfo.mode & S_IAMB);
			/*
			 * Make sure it can be read by the world and written
			 * by the owner.
			 */
			eptlist[i]->ainfo.mode |= 0644;
			if (!strchr("in", eptlist[i]->ftype)) {
				/* Set the safe attributes. */
				averify(1, &(eptlist[i]->ftype),
				    path, &(eptlist[i]->ainfo));
			}
		}

		(void) fprintf(stderr, "%s\n", path);
	}
}

static void
ckmissing(char *path, char type)
{
	static char	**dir;
	static int	ndir;
	char	*pt;
	int	i, found;

	if (dir == NULL) {
		dir = (char **)calloc(MALSIZ, sizeof (char *));
		if (dir == NULL) {
			progerr(gettext(ERR_MEMORY), errno);
			quit(99);
		}
	}

	if (strchr("dx", type)) {
		dir[ndir] = path;
		if ((++ndir % MALSIZ) == 0) {
			dir = (char **)realloc((void *)dir,
				(ndir+MALSIZ)*sizeof (char *));
			if (dir == NULL) {
				progerr(gettext(ERR_MEMORY), errno);
				quit(99);
			}
		}
		dir[ndir] = (char *)NULL;
	}

	pt = path;
	if (*pt == '/')
		pt++;
	while (pt = strchr(pt, '/')) {
		*pt = '\0';
		found = 0;
		for (i = 0; i < ndir; i++) {
			if (strcmp(path, dir[i]) == 0) {
				found++;
				break;
			}
		}
		if (!found) {
			logerr(gettext(WRN_MISSINGDIR), path);
			ckmissing(qstrdup(path), 'd');
		}
		*pt++ = '/';
	}
}

static int
slinkf(char *from, char *to)
{
	char	*pt;

	pt = to;
	while (pt = strchr(pt+1, '/')) {
		*pt = '\0';
		if (isdir(to) && mkdir(to, 0755)) {
			progerr(gettext(ERR_MKDIR), to);
			*pt = '/';
			return (-1);
		}
		*pt = '/';
	}
	if (symlink(from, to)) {
		progerr(gettext(ERR_SYMLINK), to);
		return (-1);
	}
	return (0);
}

static void
usage(void)
{
	(void) fprintf(stderr, gettext(ERR_USAGE), get_prog_name());
	exit(1);
	/*NOTREACHED*/
}

/*
 * valid_zone_attr:	Validates the zone attributes specified in
 *			pkginfo file for this package. The package
 *			can not be created with certain combinations
 *			of the attributes.
 */
static boolean_t
valid_zone_attr(struct cfent **eptlist)
{
	FILE		*pkginfoFP;
	boolean_t	all_zones;	/* pkg is "all zones" only */
	boolean_t	is_hollow;	/* pkg is "hollow" */
	boolean_t	this_zone;	/* pkg is "this zone" only */
	char 		pkginfoPath[PATH_MAX];	/* pkginfo file path */
	char		*pkgInst;
	int i;

	/* Path to pkginfo file within the package to be installed */

	this_zone = B_FALSE;
	for (i = 0; eptlist[i]; i++) {
		if (eptlist[i]->ftype != 'i')
			continue;
		if (strcmp(eptlist[i]->path, "pkginfo") == 0)
			(void) strcpy(pkginfoPath, eptlist[i]->ainfo.local);

		/*
		 * Check to see if this package has a request script. If this
		 * package does have a request script, then mark the package
		 * for installation in this zone only. Any package with a
		 * request script cannot be installed outside of the zone the
		 * pkgadd command is being run in, nor can such a package be
		 * installed as part of a new zone install. A new zone install
		 * must be non-interactive, which is required by all packages
		 * integrated into the Solaris WOS.
		 * If request file is set in prototype, then this_zone is TRUE.
		 */
		if (strcmp(eptlist[i]->path, "request") == 0)
			this_zone = B_TRUE;
	}

	/* Gather information from the pkginfo file */

	pkginfoFP = fopen(pkginfoPath, "r");

	if (pkginfoFP == NULL) {
		progerr(ERR_NO_PKG_INFOFILE, pkginfoPath, strerror(errno));
		return (B_FALSE);
	}

	if ((pkgInst = fpkgparam(pkginfoFP, "PKG")) == NULL) {
		progerr(gettext(ERR_NOPARAM), "PKG", pkginfoPath);
		return (B_FALSE);
	}


	/* Determine "HOLLOW" setting for this package */
	is_hollow = pkginfoParamTruth(pkginfoFP, PKG_HOLLOW_VARIABLE,
			"true", B_FALSE);

	/* Determine "ALLZONES" setting for this package */
	all_zones = pkginfoParamTruth(pkginfoFP, PKG_ALLZONES_VARIABLE,
			"true", B_FALSE);

	/* Determine "THISZONE" setting for this package, if no request file */
	if (!this_zone)
		this_zone = pkginfoParamTruth(pkginfoFP, PKG_THISZONE_VARIABLE,
			"true", B_FALSE);

	/* Close pkginfo file */
	(void) fclose(pkginfoFP);

	/*
	 * Validate zone attributes based on information gathered,
	 * and validate the three SUNW_PKG_ options:
	 *
	 * -----------------------------|---------------|
	 * <ALLZONES><HOLLOW><THISZONE> |  If Allowed   |
	 * ----1------------------------|---------------|
	 *		F F F		|	OK	|
	 *		F F T		|	OK	|
	 *		F T *		|	NO	|
	 * ----2------------------------|---------------|
	 *		T F F		|	OK	|
	 *		T T F		|	OK	|
	 *		T * T		|	NO	|
	 * -----------------------------|---------------|
	 */

	/* pkg "all zones" && "this zone" (#2) */

	if (all_zones && this_zone) {
		progerr(ERR_ALLZONES_AND_THISZONE, pkgInst,
		    PKG_ALLZONES_VARIABLE, PKG_THISZONE_VARIABLE);
		return (B_FALSE);
	}

	/* pkg "!all zones" && "hollow" (#1) */

	if ((!all_zones) && is_hollow) {
		progerr(ERR_NO_ALLZONES_AND_HOLLOW, pkgInst,
		    PKG_ALLZONES_VARIABLE, PKG_HOLLOW_VARIABLE);
		return (B_FALSE);
	}

	return (B_TRUE);
}
