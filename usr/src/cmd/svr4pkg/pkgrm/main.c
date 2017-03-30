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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */


/*
 * System includes
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <locale.h>
#include <libintl.h>
#include <pkgstrct.h>
#include <pkgdev.h>
#include <pkginfo.h>
#include <pkglocs.h>
#include <pkglib.h>
#include <assert.h>

/*
 * libinstzones includes
 */

#include <instzones_api.h>

/*
 * consolidation pkg command library includes
 */

#include <pkglib.h>

/*
 * local pkg command library includes
 */

#include "install.h"
#include "libinst.h"
#include "libadm.h"
#include "messages.h"

/*
 * pkgrm local includes
 */

#include "quit.h"

/*
 * exported global variables
 */

/* these globals are set by ckreturn and used by quit.c */

int	admnflag = 0;	/* != 0 if any pkg op admin setting failure (4) */
int	doreboot = 0;	/* != 0 if reboot required after installation */
int	failflag = 0;	/* != 0 if fatal error has occurred (1) */
int	intrflag = 0;	/* != 0 if user selected quit (3) */
int	ireboot = 0;	/* != 0 if immediate reboot required */
int	nullflag = 0;	/* != 0 if admin interaction required (5) */
int	warnflag = 0;	/* != 0 if non-fatal error has occurred (2) */

/* imported by quit.c */
int	npkgs = 0;	/* the number of packages yet to be installed */

/* imported by presvr4.c */
int	started = 0;
char	*tmpdir = NULL;	/* location to place temporary files */

/* imported by various (many) */
struct admin	adm;	/* holds info about installation admin */
struct pkgdev	pkgdev;	/* holds info about the installation device */

/*
 * internal global variables
 */

static char	*admnfile = NULL;	/* file to use for installation admin */
static char	*pkginst = NULL;	/* current pkg/src instance 2 process */
static char	*vfstab_file = NULL;
static char	*zoneTempDir = (char *)NULL;

/* set by ckreturn() */

static int	interrupted = 0;	/* last pkg op was quit (1,2,3,4,5) */

static int	nointeract = 0;		/* non-zero - no user interaction */
static int	pkgrmremote = 0;	/* remove pkg objs stored remotely  */
static int	pkgverbose = 0;		/* non-zero if verbose mode selected */

/*
 * Assume the package complies with the standards as regards user
 * interaction during procedure scripts.
 */

static int	old_pkg = 0;
static int	old_symlinks = 0;
static int	no_map_client = 0;

/* Set by -O nozones: do not process any zones */

static boolean_t	noZones = B_FALSE;

/* Set by -O zonelist=<names...>: process only named zones */

static boolean_t	usedZoneList = B_FALSE;

/* Set by -O debug: debug output is enabled? */

static boolean_t	debugFlag = B_FALSE;

/*
 * imported (external) functions
 */

/* check.c */

extern int	preremove_verify(char **a_pkgList, zoneList_t a_zlst,
			char *a_zoneTempDir);
/* quit.c */

extern void	quitSetZonelist(zoneList_t a_zlst);

/*
 * imported (external) variables
 */

extern char	*pkgdir;

/* printable string - if string is null results in ??? */

#define	PSTR(STR) (((STR) == (char *)NULL) ? "???" : (STR))

#define	MAX_FDS	20

#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"
#endif

/*
 * forward declarations
 */

static void		ckreturn(int retcode);
static void		create_zone_adminfile(char **r_zoneAdminFile,
				char *a_zoneTempDir, char *a_admnfile);
static void		create_zone_tempdir(char **r_zoneTempDir,
				char *a_tmpdir);
static int		doRemove(int a_nodelete, char *a_altBinDir,
				int a_longestPkg, char *a_adminFile,
				char *a_zoneAdminFile, zoneList_t zlst);
static int		pkgRemove(int a_nodelete, char *a_altBinDir,
				char *a_adminFile);
static int		pkgZoneCheckRemove(char *a_zoneName, char *a_altBinDir,
				char *a_adminFile, char *a_stdoutPath,
				zone_state_t a_zoneState, boolean_t tmpzone);
static int		pkgZoneRemove(char *a_zoneName, int a_nodelete,
				char *a_altBinDir, char *a_adminFile,
				zone_state_t a_zoneState, boolean_t tmpzone);
static void		resetreturn();
static void		usage(void);
static boolean_t	check_applicability(char *a_packageDir,
				char *a_pkgInst, char *a_rootPath,
				CAF_T a_flags);
static boolean_t	check_packages(char **a_pkgList, char *a_packageDir);
static boolean_t	remove_packages(char **a_pkgList, int a_nodelete,
				int a_longestPkg, int a_repeat,
				char *a_altBinDir, char *a_pkgdir,
				char *a_spoolDir, boolean_t a_noZones);
static boolean_t	remove_packages_from_spool_directory(char **a_pkgList,
				int a_nodelete, int a_longestPkg, int a_repeat,
				char *a_altBinDir);
static boolean_t	remove_packages_in_global_no_zones(char **a_pkgList,
				int a_nodelete, int a_longestPkg, int a_repeat,
				char *a_altBinDir);
static boolean_t	remove_packages_in_global_with_zones(char **a_pkgList,
				int a_nodelete, int a_longestPkg, int a_repeat,
				char *a_altBinDir, char *a_pkgdir,
				zoneList_t a_zlst);
static boolean_t	remove_packages_in_nonglobal_zone(char **a_pkgList,
				int a_nodelete, int a_longestPkg, int a_repeat,
				char *a_altBinDir, char *a_pkgdir);
static boolean_t	shall_we_continue(char *a_pkgInst, int a_npkgs);

/*
 * *****************************************************************************
 * global external (public) functions
 * *****************************************************************************
 */

/*
 * Name:	main
 * Description:	main entry point for pkgrm
 * Returns:	int
 *   0        Successful completion
 *   1        Fatal error.
 *   2        Warning.
 *   3        Interruption.
 *   4        Administration.
 *   5        Administration. Interaction is required. Do not use pkgrm -n.
 *  10       Reboot after removal of all packages.
 *  20       Reboot after removal of this package.
 */

int
main(int argc, char **argv)
{
	char			**category = NULL;
	char			*altBinDir = (char *)NULL;
	char			*catg_arg = NULL;
	char			*p;
	char			*prog_full_name = NULL;
	char			*spoolDir = 0;
	int			c;
	int			longestPkg = 0;
	int			n;
	int			nodelete = 0;	/* dont rm files/run scripts */
	int			pkgLgth = 0;
	int			repeat;
	struct sigaction	nact;
	struct sigaction	oact;

	/* initialize locale environment */

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	/* initialize program name */

	prog_full_name = argv[0];
	(void) set_prog_name(argv[0]);

	/* tell spmi zones interface how to access package output functions */

	z_set_output_functions(echo, echoDebug, progerr);

	/* tell quit which ckreturn function to call */

	quitSetCkreturnFunc(&ckreturn);

	/* Read PKG_INSTALL_ROOT from the environment, if it's there. */

	if (!set_inst_root(getenv("PKG_INSTALL_ROOT"))) {
		progerr(ERR_ROOT_SET);
		exit(1);
	}

	if (z_running_in_global_zone() && !enable_local_fs()) {
		progerr(ERR_CANNOT_ENABLE_LOCAL_FS);
	}

	pkgserversetmode(DEFAULTMODE);

	/*
	 * ********************************************************************
	 * parse command line options
	 * ********************************************************************
	 */

	while ((c = getopt(argc, argv, "?Aa:b:FMnO:R:s:V:vY:Z")) != EOF) {
		switch (c) {
		/*
		 * Public interface: Allow admin to remove objects
		 * from a service area via a reference client.
		 * Remove the package files from the client's file
		 * system, absolutely. If a file is shared with other
		 * packages, the default behavior is to not remove
		 * the file from the client's file system.
		 */
		case 'A':
		    pkgrmremote++;
		    break;

		/*
		 * Public interface: Use the installation
		 * administration file, admin, in place of the
		 * default admin file. pkgrm first looks in the
		 * current working directory for the administration
		 * file.  If the specified administration file is not
		 * in the current working directory, pkgrm looks in
		 * the /var/sadm/install/admin directory for the
		 * administra- tion file.
		 */
		case 'a':
		    admnfile = flex_device(optarg, 0);
		    break;

		/*
		 * Not a public interface:  location where package executables
		 * can be found - default is /usr/sadm/install/bin.
		 */
		case 'b':
			if (!path_valid(optarg)) {
				progerr(ERR_PATH, optarg);
				quit(1);
			}
			if (isdir(optarg) != 0) {
				p = strerror(errno);
				progerr(ERR_CANNOT_USE_DIR, optarg, p);
				quit(1);
			}
			altBinDir = optarg;
			break;

		/*
		 * Not a public interface: pass -F option to
		 * pkgremove which suppresses the removal of any
		 * files and any class action scripts, and suppresses
		 * the running of any class action scripts.  The
		 * package files remain but the package looks like it
		 * is not installed. This is mainly for use by the
		 * upgrade process.
		 */
		case 'F':
		    nodelete++;
		    break;

		/*
		 * Public interface: Instruct pkgrm not to use the
		 * $root_path/etc/vfstab file for determining the
		 * client's mount points. This option assumes the
		 * mount points are correct on the server and it
		 * behaves consistently with Solaris 2.5 and earlier
		 * releases.
		 */
		case 'M':
		    no_map_client = 1;
		    break;

		/*
		 * Public interface: package removal occurs in
		 * non-interactive mode.  Suppress output of the list of
		 * removed files. The default mode is interactive.
		 */
		case 'n':
		    nointeract++;
		    (void) echoSetFlag(B_FALSE);
		    break;

		/*
		 * Not a public interface: the -O option allows the behavior
		 * of the package tools to be modified. Recognized options:
		 * -> debug
		 * ---> enable debugging output
		 * -> nozones
		 * ---> act as though in global zone with no non-global zones
		 * -> enable-hollow-package-support
		 * --> Enable hollow package support. When specified, for any
		 * --> package that has SUNW_PKG_HOLLOW=true:
		 * --> Do not calculate and verify package size against target
		 * --> Do not run any package procedure or class action scripts
		 * --> Do not create or remove any target directories
		 * --> Do not perform any script locking
		 * --> Do not install or uninstall any components of any package
		 * --> Do not output any status or database update messages
		 * -> zonelist="<names...>"
		 * ---> add package to space-separated list of zones only
		 */

		case 'O':
			for (p = strtok(optarg, ","); p != (char *)NULL;
				p = strtok(NULL, ",")) {

				if (strcmp(p, "nozones") == 0) {
					noZones = B_TRUE;
					continue;
				}

				if (strcmp(p,
					"enable-hollow-package-support") == 0) {
					set_depend_pkginfo_DB(B_TRUE);
					continue;
				}

				if (strcmp(p, "debug") == 0) {
					/* set debug flag/enable debug output */
					debugFlag = B_TRUE;
					(void) echoDebugSetFlag(debugFlag);

					/* debug info on arguments to pkgadd */
					for (n = 0; n < argc && argv[n]; n++) {
						echoDebug(DBG_ARG, n, argv[n]);
					}

					continue;
				}

				if (strncmp(p, "zonelist=", 9) == 0) {
					if (z_set_zone_spec(p + 9) == -1)
						quit(1);
					usedZoneList = B_TRUE;
					continue;
				}

				/* -O option not recognized - issue warning */

				progerr(ERR_INVALID_O_OPTION, p);
				continue;
			}
			break;

		/*
		 * Public interface: defines the full path name of a
		 * directory to use as the root_path.  All files,
		 * including package system information files, are
		 * relocated to a directory tree starting in the
		 * specified root_path.
		 */
		case 'R':
		    if (!set_inst_root(optarg)) {
			    progerr(ERR_ROOT_CMD);
			    exit(1);
		    }
		    break;

		/*
		 * Public interface: remove the specified package(s)
		 * from the directory spool.  The default directory
		 * for spooled packages is /var/sadm/pkg.
		 */
		case 's':
		    spoolDir = flex_device(optarg, 1);
		    break;

		/*
		 * Public interface: Allow admin to establish the client
		 * filesystem using a vfstab-like file of stable format.
		 */
		case 'V':
		    vfstab_file = flex_device(optarg, 2);
		    no_map_client = 0;
		    break;

		/*
		 * Public interface: trace all of the scripts that
		 * get executed by pkgrm, located in the
		 * pkginst/install directory. This option is used for
		 * debugging the procedural and non- procedural
		 * scripts.
		 */
		case 'v':
		    pkgverbose++;
		    break;

		/*
		 * Public interface: remove packages based on the
		 * CATEGORY variable from the installed/spooled
		 * pkginfo file
		 */
		case 'Y':
		    catg_arg = strdup(optarg);

		    if ((category = get_categories(catg_arg)) == NULL) {
			    progerr(ERR_CAT_INV, catg_arg);
			    exit(1);
		    } else if (is_not_valid_category(category,
				    get_prog_name())) {
			    progerr(ERR_CAT_SYS);
			    exit(1);
		    } else if (is_not_valid_length(category)) {
			    progerr(ERR_CAT_LNGTH);
			    exit(1);
		    }

		    break;

		/*
		 * unrecognized option
		 */
		default:
		    usage();
		    /* NOTREACHED */
		}
	}

	/*
	 * ********************************************************************
	 * validate command line options
	 * ********************************************************************
	 */

	/* set "debug echo" flag according to setting of "-O debug" option */

	(void) echoDebugSetFlag(debugFlag);

	/* output entry debugging information */

	if (z_running_in_global_zone()) {
		echoDebug(DBG_ENTRY_IN_GZ, prog_full_name);
	} else {
		echoDebug(DBG_ENTRY_IN_LZ, prog_full_name, getzoneid(),
			z_get_zonename());
	}

	/* -s cannot be used with several */

	if (spoolDir != (char *)NULL) {
		if (admnfile != (char *)NULL) {
			progerr(ERR_SPOOLDIR_AND_ADMNFILE);
			usage();
			/* NOTREACHED */
		}

		if (pkgrmremote != 0) {
			progerr(ERR_SPOOLDIR_AND_PKGRMREMOTE);
			usage();
			/* NOTREACHED */
		}

		if (pkgverbose != 0) {
			progerr(ERR_SPOOLDIR_AND_PKGVERBOSE);
			usage();
			/* NOTREACHED */
		}

		if (is_an_inst_root() != 0) {
			progerr(ERR_SPOOLDIR_AND_INST_ROOT);
			usage();
			/* NOTREACHED */
		}
	}

	/* -V cannot be used with -A */

	if (no_map_client && pkgrmremote) {
		progerr(ERR_V_USED_AND_PKGRMREMOTE);
		usage();
		/* NOTREACHED */
	}

	/* -n used without pkg names or category */

	if (nointeract && (optind == argc) && (catg_arg == NULL)) {
		progerr(ERR_BAD_N_PKGRM);
		usage();
		/* NOTREACHED */
	}

	/* Error if specified zone list isn't valid on target */
	if (usedZoneList && z_verify_zone_spec() == -1)
		usage();

	/*
	 * hook SIGINT and SIGHUP interrupts into quit.c's trap handler
	 */

	/* hold SIGINT/SIGHUP interrupts */

	(void) sighold(SIGHUP);
	(void) sighold(SIGINT);

	/* connect quit.c:trap() to SIGINT */

	nact.sa_handler = quitGetTrapHandler();
	nact.sa_flags = SA_RESTART;
	(void) sigemptyset(&nact.sa_mask);

	(void) sigaction(SIGINT, &nact, &oact);

	/* connect quit.c:trap() to SIGHUP */

	nact.sa_handler = quitGetTrapHandler();
	nact.sa_flags = SA_RESTART;
	(void) sigemptyset(&nact.sa_mask);

	(void) sigaction(SIGHUP, &nact, &oact);

	/* release hold on signals */

	(void) sigrelse(SIGHUP);
	(void) sigrelse(SIGINT);

	/* establish temporary directory to use */

	tmpdir = getenv("TMPDIR");
	if (tmpdir == NULL) {
		tmpdir = P_tmpdir;
	}

	echoDebug(DBG_PKGRM_TMPDIR, tmpdir);

	/* initialize path parameters */

	set_PKGpaths(get_inst_root());

	/*
	 * initialize installation admin parameters - if removing from a spool
	 * directory then the admin file is ignore.
	 */

	if (spoolDir == NULL) {
		echoDebug(DBG_PKGRM_ADMINFILE, admnfile ? admnfile : "");
		setadminFile(admnfile);
	}

	/*
	 * if running in the global zone, and non-global zones exist, then
	 * enable hollow package support so that any packages that are marked
	 * SUNW_PKG_HOLLOW=true will be correctly removed in non-global zones
	 * when removed directly in the global zone by the global zone admin.
	 */

	if (is_depend_pkginfo_DB()) {
		echoDebug(DBG_PKGRM_HOLLOW_ENABLED);
	} else if ((z_running_in_global_zone() == B_TRUE) &&
		(z_non_global_zones_exist() == B_TRUE)) {
		echoDebug(DBG_PKGRM_ENABLING_HOLLOW);
		set_depend_pkginfo_DB(B_TRUE);
	}

	/*
	 * See if user wants this to be handled as an old style pkg.
	 * NOTE : the ``exception_pkg()'' stuff is to be used only
	 * through on495. This function comes out for on1095. See
	 * PSARC 1993-546. -- JST
	 */
	if (getenv("NONABI_SCRIPTS") != NULL) {
		old_pkg = 1;
	}

	/*
	 * See if the user wants to process symlinks consistent with
	 * the old behavior.
	 */

	if (getenv("PKG_NONABI_SYMLINKS") != NULL) {
		old_symlinks = 1;
	}

	if (devtype((spoolDir ? spoolDir : get_PKGLOC()), &pkgdev) ||
	    pkgdev.dirname == NULL) {
		progerr(ERR_BAD_DEVICE, spoolDir ? spoolDir : get_PKGLOC());
		quit(1);
		/* NOTREACHED */
	}

	pkgdir = pkgdev.dirname;
	repeat = ((optind >= argc) && pkgdev.mount);

	/*
	 * error if there are packages on the command line and a category
	 * was specified
	 */

	if (optind < argc && catg_arg != NULL) {
		progerr(ERR_PKGS_AND_CAT_PKGRM);
		usage();
		/* NOTREACHED */
	}

	/*
	 * ********************************************************************
	 * main package processing "loop"
	 * ********************************************************************
	 */

	for (;;) {
		boolean_t	b;
		char		**pkglist;	/* points to array of pkgs */

		/*
		 * mount the spool device if required
		 */

		if (pkgdev.mount) {
			if (n = pkgmount(&pkgdev, NULL, 0, 0, 1)) {
				quit(n);
				/* NOTREACHED */
			}
		}

		if (chdir(pkgdev.dirname)) {
			progerr(ERR_CHDIR, pkgdev.dirname);
			quit(1);
			/* NOTREACHED */
		}

		/*
		 * spool device mounted/available - get the list of the
		 * packages to remove
		 */

		n = pkgGetPackageList(&pkglist, argv, optind,
			catg_arg, category, &pkgdev);

		switch (n) {
			case -1:	/* no packages found */
				echoDebug(DBG_PKGLIST_RM_NONFOUND,
					PSTR(pkgdev.dirname));
				progerr(ERR_NOPKGS, pkgdev.dirname);
				quit(1);
				/* NOTREACHED */

			case 0:		/* packages found */
				break;

			default:	/* "quit" error */
				echoDebug(DBG_PKGLIST_RM_ERROR,
					pkgdev.dirname, n);
				quit(n);
				/* NOTREACHED */
		}

		/*
		 * count the number of packages to remove
		 * NOTE: npkgs is a global variable that is referenced by quit.c
		 * when error messages are generated - it is referenced directly
		 * by the other functions called below...
		 */

		for (npkgs = 0; pkglist[npkgs] != (char *)NULL; /* void */) {
			pkgLgth = strlen(pkglist[npkgs]);
			if (pkgLgth > longestPkg) {
				longestPkg = pkgLgth;
			}
			echoDebug(DBG_PKG_SELECTED, npkgs, pkglist[npkgs]);
			npkgs++;
		}

		/* output number of packages to be removed */

		echoDebug(DBG_NUM_PKGS_TO_REMOVE, npkgs, longestPkg);

		/*
		 * package list generated - remove packages
		 */

		b = remove_packages(pkglist, nodelete, longestPkg, repeat,
			altBinDir, pkgdev.dirname, spoolDir, noZones);

		/*
		 * unmount the spool directory if necessary
		 */

		if (pkgdev.mount) {
			(void) chdir("/");
			if (pkgumount(&pkgdev)) {
				progerr(ERR_PKGUNMOUNT, pkgdev.bdevice);
				quit(99);
				/* NOTREACHED */

			}
		}

		/*
		 * continue with next sequence of packages if continue set
		 */

		if (b == B_TRUE) {
			continue;
		}

		/*
		 * not continuing - quit with 0 exit code
		 */

		quit(0);
		/* NOTREACHED */
#ifdef lint
		return (0);
#endif	/* lint */
	}
}

/*
 * *****************************************************************************
 * static internal (private) functions
 * *****************************************************************************
 */

/*
 * Name:	doRemove
 * Description:	Remove a package from the global zone, and optionally from one
 *		or more non-global zones.
 * Arguments:	a_nodelete: should the files and scripts remain installed?
 *			- if != 0 pass -F flag to pkgremove - suppress
 *			the removal of any files and any class action scripts
 *			and suppress the running of any class action scripts.
 *			The package files remain but the package looks like it
 *			is not installed. This is mainly for use by upgrade.
 *			- if == 0 do not pass -F flag to pkgremove - all
 *			files and class action scripts are removed, and any
 *			appropriate class action scripts are run.
 *		a_altBinDir - pointer to string representing location of the
 *			pkgremove executable to run. If not NULL, then pass
 *			the path specified to the -b option to pkgremove.
 *		a_longestPkg - length of the longest package "name" (for
 *			output format alignment)
 *		a_adminFile - pointer to string representing the admin
 *			file to pass to pkgremove when removing a package from
 *			the global zone only. Typically the admin file used for
 *			the global zone is the admin file passed in by the user.
 *			If this is == NULL no admin file is given to pkgremove.
 *		a_zoneAdminFile - pointer to string representing the admin
 *			file to pass to pkgremove when removing the package
 *			from a non-global zone only. Typically the admin file
 *			used for non-global zones supresses all checks since
 *			the dependency checking is done for all zones first
 *			before proceeding.
 *			A zoneAdminFile MUST be specified if a_zlst != NULL.
 *			A zoneAdminFile must NOT be specified if a_zlst == NULL.
 *		a_zlst - list of zones to process; NULL if no zones to process.
 * Returns:	int	(see ckreturn() function for details)
 *		0 - success
 *		1 - package operation failed (fatal error)
 *		2 - non-fatal error (warning)
 *		3 - user selected quit (operation interrupted)
 *		4 - admin settings prevented operation
 *		5 - interaction required and -n (non-interactive) specified
 *		"10" will be added to indicate "immediate reboot required"
 *		"20" will be added to indicate "reboot after install required"
 */

static int
doRemove(int a_nodelete, char *a_altBinDir, int a_longestPkg, char *a_adminFile,
	char *a_zoneAdminFile, zoneList_t a_zlst)
{
	boolean_t	b;
	char		*zoneName;
	char		ans[MAX_INPUT];
	int		n;
	int		zoneIndex;
	int		zonesSkipped;
	struct pkginfo	*pinfo = (struct pkginfo *)NULL;
	zone_state_t	zst;

	/* entry assertions */

	if (a_zlst != (zoneList_t)NULL) {
		/* zone list specified - zone admin file required */
		assert(a_zoneAdminFile != (char *)NULL);
		assert(*a_zoneAdminFile != '\0');
	} else {
		/* no zone list specified - no zone admin file needed */
		assert(a_zoneAdminFile == (char *)NULL);
	}

	/* NOTE: required 'pkgdir' set to spool directory or NULL */
	b = pkginfoIsPkgInstalled(&pinfo, pkginst);
	if (b == B_FALSE) {
		progerr(ERR_NO_SUCH_INSTANCE, pkginst);
		pkginfoFree(&pinfo);
		return (2);
	}

	/* entry debugging info */

	echoDebug(DBG_DOREMOVE_ENTRY);
	echoDebug(DBG_DOREMOVE_ARGS, PSTR(pinfo->pkginst), PSTR(pinfo->name),
		PSTR(pinfo->arch), PSTR(pinfo->version), PSTR(pinfo->basedir),
		PSTR(pinfo->catg), pinfo->status);

	if (!nointeract) {
		char	fmt1[100];

		/* create format based on max pkg name length */

		(void) snprintf(fmt1, sizeof (fmt1), "   %%-%d.%ds  %%s",
				a_longestPkg, a_longestPkg);

		if (pinfo->status == PI_SPOOLED) {
			echo(INFO_SPOOLED);
		} else {
			if (getuid()) {
				progerr(ERR_NOT_ROOT, get_prog_name());
				exit(1);
			}
			echo(INFO_INSTALL);
		}

		echo(fmt1, pinfo->pkginst, pinfo->name);

		if (pinfo->arch || pinfo->version) {
			char	fmt2[100];

			/* create format based on max pkg name length */

			(void) snprintf(fmt2, sizeof (fmt2), "   %%%d.%ds  ",
					a_longestPkg, a_longestPkg);

			/* LINTED variable format specifier to fprintf() */
			(void) fprintf(stderr, fmt2, "");

			if (pinfo->arch) {
				(void) fprintf(stderr, "(%s) ", pinfo->arch);
			}

			if (pinfo->version) {
				(void) fprintf(stderr, "%s", pinfo->version);
			}

			(void) fprintf(stderr, "\n");
		}

		n = ckyorn(ans, NULL, NULL, NULL, ASK_CONFIRM);
		if (n != 0) {
			quit(n);
			/* NOTREACHED */
		}

		if (strchr("yY", *ans) == NULL) {
			pkginfoFree(&pinfo);
			return (0);
		}
	}

	if (pinfo->status == PI_SPOOLED) {
		/* removal from a directory */
		echo(INFO_RMSPOOL, pkginst);
		pkginfoFree(&pinfo);
		return (rrmdir(pkginst));
	}

	/* exit if not root */

	if (getuid()) {
		progerr(ERR_NOT_ROOT, get_prog_name());
		exit(1);
	}

	pkginfoFree(&pinfo);

	zonesSkipped = 0;

	if (interrupted != 0) {
		echo(MSG_DOREMOVE_INTERRUPTED_B4_Z, pkginst);
		echoDebug(MSG_DOREMOVE_INTERRUPTED_B4_Z, pkginst);
		return (n);
	}

	echoDebug(DBG_REMOVE_FLAG_VALUES, "before pkgZoneRemove",
		admnflag, doreboot, failflag, interrupted,
		intrflag, ireboot, nullflag, warnflag);

	for (zoneIndex = 0;
	    a_zlst != NULL &&
	    (zoneName = z_zlist_get_zonename(a_zlst, zoneIndex)) != NULL;
	    zoneIndex++) {

		/* skip the zone if it is NOT running */

		zst = z_zlist_get_current_state(a_zlst, zoneIndex);
		if (zst != ZONE_STATE_RUNNING && zst != ZONE_STATE_MOUNTED) {
			zonesSkipped++;
			echoDebug(DBG_SKIPPING_ZONE, zoneName);
			continue;
		}

		echo(MSG_REMOVE_PKG_FROM_ZONE, pkginst, zoneName);
		echoDebug(DBG_REMOVE_PKG_FROM_ZONE, pkginst, zoneName);

		/*
		 * remove package from zone; use the zone admin file which
		 * suppresses all checks.
		 */

		n = pkgZoneRemove(z_zlist_get_scratch(a_zlst, zoneIndex),
			a_nodelete, a_altBinDir, a_zoneAdminFile,
			zst, B_FALSE);

		/* set success/fail condition variables */

		ckreturn(n);

		echoDebug(DBG_REMOVE_FLAG_VALUES, "after pkgZoneRemove",
			admnflag, doreboot, failflag, interrupted, intrflag,
			ireboot, nullflag, warnflag);
	}

	if (zonesSkipped > 0) {
		echoDebug(DBG_ZONES_SKIPPED, zonesSkipped);

		for (zoneIndex = 0;
			(zoneName = z_zlist_get_zonename(a_zlst, zoneIndex)) !=
				(char *)NULL; zoneIndex++) {

			/* skip the zone if it IS running */

			zst = z_zlist_get_current_state(a_zlst, zoneIndex);
			if (zst == ZONE_STATE_RUNNING ||
			    zst == ZONE_STATE_MOUNTED) {
				zonesSkipped++;
				echoDebug(DBG_SKIPPING_ZONE_BOOT, zoneName);
				continue;
			}

			/* skip the zone if it is NOT bootable */

			if (z_zlist_is_zone_runnable(a_zlst,
						zoneIndex) == B_FALSE) {
				echo(MSG_SKIPPING_ZONE_NOT_RUNNABLE, zoneName);
				echoDebug(DBG_SKIPPING_ZONE_NOT_RUNNABLE,
					zoneName);
				continue;
			}

			/* mount up the zone */

			echo(MSG_BOOTING_ZONE, zoneName);
			echoDebug(DBG_BOOTING_ZONE, zoneName);

			b = z_zlist_change_zone_state(a_zlst, zoneIndex,
				ZONE_STATE_MOUNTED);
			if (b == B_FALSE) {
				progerr(ERR_CANNOT_BOOT_ZONE, zoneName);
				/* set fatal error return condition */
				ckreturn(1);
				continue;
			}

			echo(MSG_REMOVE_PKG_FROM_ZONE, pkginst, zoneName);

			/*
			 * remove package from zone; use the zone admin file
			 * which suppresses all checks.
			 */

			n = pkgZoneRemove(z_zlist_get_scratch(a_zlst,
				zoneIndex), a_nodelete, a_altBinDir,
				a_zoneAdminFile, ZONE_STATE_MOUNTED, B_TRUE);

			/* set success/fail condition variables */

			ckreturn(n);

			echoDebug(DBG_REMOVE_FLAG_VALUES, "after pkgZoneRemove",
				admnflag, doreboot, failflag, interrupted,
				intrflag, ireboot, nullflag, warnflag);

			/* restore original state of zone */

			echo(MSG_RESTORE_ZONE_STATE, zoneName);
			echoDebug(DBG_RESTORE_ZONE_STATE, zoneName);

			b = z_zlist_restore_zone_state(a_zlst, zoneIndex);
		}
	}

	/*
	 * Process global zone if it was either the only possible
	 * target (no list of zones specified) or it appears in the list
	 */
	if (a_zlst == NULL || z_on_zone_spec(GLOBAL_ZONENAME)) {
		/* reset interrupted flag before calling pkgremove */
		interrupted = 0;	/* last action was NOT quit */

		/*
		 * call pkgremove for this package for the global zone;
		 * use the admin file passed in by the user via -a.
		 */
		n = pkgRemove(a_nodelete, a_altBinDir, a_adminFile);

		/* set success/fail condition variables */
		ckreturn(n);
	}

	return (n);
}

/*
 *  function to clear out any exisiting error return conditions that may have
 *  been set by previous calls to ckreturn()
 */
static void
resetreturn()
{
	admnflag = 0;	/* != 0 if any pkg op admin setting failure (4) */
	doreboot = 0;	/* != 0 if reboot required after installation (>= 10) */
	failflag = 0;	/* != 0 if fatal error has occurred (1) */
	intrflag = 0;	/* != 0 if user selected quit (3) */
	ireboot = 0;	/* != 0 if immediate reboot required (>= 20) */
	nullflag = 0;	/* != 0 if admin interaction required (5) */
	warnflag = 0;	/* != 0 if non-fatal error has occurred (2) */
	interrupted = 0;	/* last pkg op was quit (1,2,3,4,5) */
}

/*
 *  function which checks the indicated return value
 *  and indicates disposition of installation
 */
static void
ckreturn(int retcode)
{
	/*
	 * entry debugging info
	 */

	echoDebug(DBG_PKGRM_CKRETURN, retcode, PSTR(pkginst));

	switch (retcode) {
	    case  0:		/* successful */
	    case 10:
	    case 20:
		break; /* empty case */

	    case  1:		/* package operation failed (fatal error) */
	    case 11:
	    case 21:
		failflag++;
		interrupted++;
		break;

	    case  2:		/* non-fatal error (warning) */
	    case 12:
	    case 22:
		warnflag++;
		interrupted++;
		break;

	    case  3:		/* user selected quit; operation interrupted */
	    case 13:
	    case 23:
		intrflag++;
		interrupted++;
		break;

	    case  4:		/* admin settings prevented operation */
	    case 14:
	    case 24:
		admnflag++;
		interrupted++;
		break;

	    case  5:		/* administration: interaction req (no -n) */
	    case 15:
	    case 25:
		nullflag++;
		interrupted++;
		break;

	    default:
		failflag++;
		interrupted++;
		return;
	}

	if (retcode >= 20) {
		ireboot++;
	} else if (retcode >= 10) {
		doreboot++;
	}
}

static int
pkgZoneCheckRemove(char *a_zoneName, char *a_altBinDir, char *a_adminFile,
	char *a_stdoutPath, zone_state_t a_zoneState, boolean_t tmpzone)
{
	char	*arg[MAXARGS];
	char	*p;
	char	adminfd_path[PATH_MAX];
	char	path[PATH_MAX];
	int	fds[MAX_FDS];
	int	maxfds;
	int	n;
	int	nargs;

	/* entry assertions */

	assert(a_zoneName != (char *)NULL);
	assert(*a_zoneName != '\0');

	/* entry debugging info */

	echoDebug(DBG_PKGZONECHECKREMOVE_ENTRY);
	echoDebug(DBG_PKGZONECHECKREMOVE_ARGS, a_zoneName, PSTR(pkginst),
		PSTR(pkgdev.dirname), PSTR(a_adminFile), PSTR(a_stdoutPath));

	/* generate path to pkgremove */

	(void) snprintf(path, sizeof (path), "%s/pkgremove",
		a_altBinDir == (char *)NULL ? PKGBIN : a_altBinDir);

	/* start at first file descriptor */

	maxfds = 0;

	/*
	 * generate argument list for call to pkgremove
	 */

	/* start at argument 0 */

	nargs = 0;

	/* first argument is path to executable */

	arg[nargs++] = strdup(path);

	/* second argument is always: pass -O debug to pkgremove: debug mode */

	if (debugFlag == B_TRUE) {
		arg[nargs++] = "-O";
		arg[nargs++] = "debug";
	}

	/* pkgrm -b dir: pass -b to pkgremove */

	if (a_altBinDir != (char *)NULL) {
		arg[nargs++] = "-b";
		arg[nargs++] = a_altBinDir;
	}

	/*
	 * NONABI_SCRIPTS defined: pass -o to pkgremove; refers to a
	 * pkg requiring operator interaction during a procedure script
	 * (common before on1093)
	 */

	if (old_pkg) {
		arg[nargs++] = "-o";
	}

	/*
	 * PKG_NONABI_SYMLINKS defined: pass -y to pkgremove; process
	 * symlinks consistent with old behavior
	 */

	if (old_symlinks) {
		arg[nargs++] = "-y";
	}

	/* pkgrm -M: pass -M to pkgremove: don't mount client file systems */

	arg[nargs++] = "-M";

	/* pkgrm -A: pass -A to pkgremove */

	if (pkgrmremote) {
		arg[nargs++] = "-A";
	}

	/* pkgrm -v: pass -v to pkgremove: never trace scripts */

	/* pass "-O enable-hollow-package-support" */

	if (is_depend_pkginfo_DB()) {
		arg[nargs++] = "-O";
		arg[nargs++] = "enable-hollow-package-support";
	}

	/* pass -n to pkgremove: always in noninteractive mode */

	arg[nargs++] = "-n";

	/* pkgrm -a admin: pass -a admin to pkgremove: admin file */

	if (a_adminFile) {
		int fd;
		fd = openLocal(a_adminFile, O_RDONLY, tmpdir);
		if (fd < 0) {
			progerr(ERR_CANNOT_COPY_LOCAL, a_adminFile,
				errno, strerror(errno));
			return (1);
		}
		(void) snprintf(adminfd_path, sizeof (adminfd_path),
			"/proc/self/fd/%d", fd);
		fds[maxfds++] = fd;
		arg[nargs++] = "-a";
		arg[nargs++] = strdup(adminfd_path);
	}

	/*
	 * pkgadd -R root: pass -R /a to pkgremove in mounted zone
	 */
	if (a_zoneState == ZONE_STATE_MOUNTED) {
		arg[nargs++] = "-R";
		arg[nargs++] = "/a";
	}

	/* pkgrm -F: pass -F to pkgremove: always update DB only */

	arg[nargs++] = "-F";

	/* pass "-O preremovecheck" */

	arg[nargs++] = "-O";
	arg[nargs++] = "preremovecheck";

	/* add "-O addzonename" */

	arg[nargs++] = "-O";
	arg[nargs++] = "addzonename";

	/*
	 * add parent zone info/type
	 */

	p = z_get_zonename();
	if ((p != NULL) && (*p != '\0')) {
			char	zn[MAXPATHLEN];
			(void) snprintf(zn, sizeof (zn),
				"parent-zone-name=%s", p);
			arg[nargs++] = "-O";
			arg[nargs++] = strdup(zn);
	}

	/* current zone type */

	arg[nargs++] = "-O";
	if (z_running_in_global_zone() == B_TRUE) {
			char	zn[MAXPATHLEN];
			(void) snprintf(zn, sizeof (zn),
				"parent-zone-type=%s",
				TAG_VALUE_GLOBAL_ZONE);
			arg[nargs++] = strdup(zn);
	} else {
			char	zn[MAXPATHLEN];
			(void) snprintf(zn, sizeof (zn),
				"parent-zone-type=%s",
				TAG_VALUE_NONGLOBAL_ZONE);
			arg[nargs++] = strdup(zn);
	}

	/* Add arguments how to start the pkgserv */

	arg[nargs++] = "-O";
	arg[nargs++] = pkgmodeargument(tmpzone ? RUN_ONCE : pkgservergetmode());

	/* pass -N to pkgremove: program name to report */

	arg[nargs++] = "-N";
	arg[nargs++] = get_prog_name();

	/* add package instance name */

	arg[nargs++] = pkginst;

	/* terminate argument list */

	arg[nargs++] = NULL;

	/* execute pkgremove command */

	if (debugFlag == B_TRUE) {
		echoDebug(DBG_ZONE_EXEC_ENTER, a_zoneName, arg[0]);
		for (n = 0; arg[n]; n++) {
			echoDebug(DBG_ARG, n, arg[n]);
		}
	}

	/* terminate file descriptor list */

	fds[maxfds] = -1;

	/* exec command in zone */

	n = z_zone_exec(a_zoneName, path, arg, a_stdoutPath, (char *)NULL, fds);

	echoDebug(DBG_ZONE_EXEC_EXIT, a_zoneName, arg[0], n,
			PSTR(a_stdoutPath));

	/*
	 * close any files that were opened for use by the
	 * /proc/self/fd interface so they could be passed to programs
	 * via the z_zone_exec() interface
	 */

	for (; maxfds > 0; maxfds--) {
		(void) close(fds[maxfds-1]);
	}

	/* return results of pkgremove in zone execution */

	return (n);
}

static int
pkgZoneRemove(char *a_zoneName, int a_nodelete, char *a_altBinDir,
	char *a_adminFile, zone_state_t a_zoneState, boolean_t tmpzone)
{
	char	*arg[MAXARGS];
	char	*p;
	char	adminfd_path[PATH_MAX];
	char	path[PATH_MAX];
	int	fds[MAX_FDS];
	int	maxfds;
	int	n;
	int	nargs;

	/* entry assertions */

	assert(a_zoneName != (char *)NULL);
	assert(*a_zoneName != '\0');

	/* entry debugging info */

	echoDebug(DBG_PKGZONEREMOVE_ENTRY);
	echoDebug(DBG_PKGZONEREMOVE_ARGS, a_zoneName, PSTR(pkginst),
		PSTR(pkgdev.dirname), a_nodelete, PSTR(a_adminFile));

	/* generate path to pkgremove */

	(void) snprintf(path, sizeof (path), "%s/pkgremove",
		a_altBinDir == (char *)NULL ? PKGBIN : a_altBinDir);

	/* start at first file descriptor */

	maxfds = 0;

	/*
	 * generate argument list for call to pkgremove
	 */

	/* start at argument 0 */

	nargs = 0;

	/* first argument is path to executable */

	arg[nargs++] = strdup(path);

	/* second argument is always: pass -O debug to pkgremove: debug mode */

	if (debugFlag == B_TRUE) {
		arg[nargs++] = "-O";
		arg[nargs++] = "debug";
	}

	/* pkgrm -b dir: pass -b to pkgremove */

	if (a_altBinDir != (char *)NULL) {
		arg[nargs++] = "-b";
		arg[nargs++] = a_altBinDir;
	}

	/*
	 * NONABI_SCRIPTS defined: pass -o to pkgremove; refers to a
	 * pkg requiring operator interaction during a procedure script
	 * (common before on1093)
	 */

	if (old_pkg) {
		arg[nargs++] = "-o";
	}

	/*
	 * PKG_NONABI_SYMLINKS defined: pass -y to pkgremove; process
	 * symlinks consistent with old behavior
	 */

	if (old_symlinks) {
		arg[nargs++] = "-y";
	}

	/* pkgrm -M: pass -M to pkgremove: don't mount client file systems */

	arg[nargs++] = "-M";

	/* pkgrm -A: pass -A to pkgremove */

	if (pkgrmremote) {
		arg[nargs++] = "-A";
	}

	/* pkgrm -v: pass -v to pkgremove: trace scripts */

	if (pkgverbose) {
		arg[nargs++] = "-v";
	}

	/* pass "-O enable-hollow-package-support" */

	if (is_depend_pkginfo_DB()) {
		arg[nargs++] = "-O";
		arg[nargs++] = "enable-hollow-package-support";
	}

	/* pkgrm -n: pass -n to pkgremove: noninteractive mode */

	if (nointeract) {
		arg[nargs++] = "-n";
	}

	/* pkgrm -a admin: pass -a admin to pkgremove: admin file */

	if (a_adminFile) {
		int fd;
		fd = openLocal(a_adminFile, O_RDONLY, tmpdir);
		if (fd < 0) {
			progerr(ERR_CANNOT_COPY_LOCAL, a_adminFile,
				errno, strerror(errno));
			return (1);
		}
		(void) snprintf(adminfd_path, sizeof (adminfd_path),
			"/proc/self/fd/%d", fd);
		fds[maxfds++] = fd;
		arg[nargs++] = "-a";
		arg[nargs++] = adminfd_path;
	}

	/*
	 * pkgadd -R root: pass -R /a to pkgremove in mounted zone
	 */
	if (a_zoneState == ZONE_STATE_MOUNTED) {
		arg[nargs++] = "-R";
		arg[nargs++] = "/a";
	}

	/* pkgrm -F: pass -F to pkgremove: update DB only */

	if (a_nodelete) {
		arg[nargs++] = "-F";
	}

	/* add "-O addzonename" */

	arg[nargs++] = "-O";
	arg[nargs++] = "addzonename";

	/*
	 * add parent zone info/type
	 */

	p = z_get_zonename();
	if ((p != NULL) && (*p != '\0')) {
			char	zn[MAXPATHLEN];
			(void) snprintf(zn, sizeof (zn),
				"parent-zone-name=%s", p);
			arg[nargs++] = "-O";
			arg[nargs++] = strdup(zn);
	}

	/* current zone type */

	arg[nargs++] = "-O";
	if (z_running_in_global_zone() == B_TRUE) {
			char	zn[MAXPATHLEN];
			(void) snprintf(zn, sizeof (zn),
				"parent-zone-type=%s",
				TAG_VALUE_GLOBAL_ZONE);
			arg[nargs++] = strdup(zn);
	} else {
			char	zn[MAXPATHLEN];
			(void) snprintf(zn, sizeof (zn),
				"parent-zone-type=%s",
				TAG_VALUE_NONGLOBAL_ZONE);
			arg[nargs++] = strdup(zn);
	}

	/* Add arguments how to start the pkgserv */

	arg[nargs++] = "-O";
	arg[nargs++] = pkgmodeargument(tmpzone ? RUN_ONCE : pkgservergetmode());

	/* pass -N to pkgremove: program name to report */

	arg[nargs++] = "-N";
	arg[nargs++] = get_prog_name();

	/* add package instance name */

	arg[nargs++] = pkginst;

	/* terminate argument list */

	arg[nargs++] = NULL;

	/* execute pkgremove command */

	if (debugFlag == B_TRUE) {
		echoDebug(DBG_ZONE_EXEC_ENTER, a_zoneName, arg[0]);
		for (n = 0; arg[n]; n++) {
			echoDebug(DBG_ARG, n, arg[n]);
		}
	}

	/* terminate file descriptor list */

	fds[maxfds] = -1;

	/* exec command in zone */

	n = z_zone_exec(a_zoneName, path, arg, (char *)NULL, (char *)NULL, fds);

	/*
	 * close any files that were opened for use by the
	 * /proc/self/fd interface so they could be passed to programs
	 * via the z_zone_exec() interface
	 */

	for (; maxfds > 0; maxfds--) {
		(void) close(fds[maxfds-1]);
	}

	return (n);
}

/*
 * Name:	pkgRemove
 * Description:	Invoke pkgremove in the current zone to perform a remove
 *		of a single package from the current zone or standalone system
 * Arguments:	a_nodelete: should the files and scripts remain installed?
 *			- if != 0 pass -F flag to pkgremove - suppress
 *			the removal of any files and any class action scripts
 *			and suppress the running of any class action scripts.
 *			The package files remain but the package looks like it
 *			is not installed. This is mainly for use by upgrade.
 *			- if == 0 do not pass -F flag to pkgremove - all
 *			files and class action scripts are removed, and any
 *			appropriate class action scripts are run.
 *		a_altBinDir - pointer to string representing location of the
 *			pkgremove executable to run. If not NULL, then pass
 *			the path specified to the -b option to pkgremove.
 *		a_adminFile - pointer to string representing the admin
 *			file to pass to pkgremove when removing the package.
 *			If this is == NULL no admin file is given to pkgremove.
 * Returns:	int	(see ckreturn() function for details)
 *		0 - success
 *		1 - package operation failed (fatal error)
 *		2 - non-fatal error (warning)
 *		3 - user selected quit (operation interrupted)
 *		4 - admin settings prevented operation
 *		5 - interaction required and -n (non-interactive) specified
 *		"10" will be added to indicate "immediate reboot required"
 *		"20" will be added to indicate "reboot after install required"
 */

static int
pkgRemove(int a_nodelete, char *a_altBinDir, char *a_adminFile)
{
	char	*arg[MAXARGS];
	char	*p;
	char	path[PATH_MAX];
	int	n;
	int	nargs;

	/* entry debugging info */

	echoDebug(DBG_PKGREMOVE_ENTRY);
	echoDebug(DBG_PKGREMOVE_ARGS, PSTR(pkginst), PSTR(pkgdev.dirname),
		a_nodelete, PSTR(a_adminFile));

	(void) snprintf(path, sizeof (path), "%s/pkgremove",
		a_altBinDir == (char *)NULL ? PKGBIN : a_altBinDir);

	nargs = 0;

	/* first argument is path to executable */

	arg[nargs++] = strdup(path);

	/* second argument is always: pass -O debug to pkgremove: debug mode */

	if (debugFlag == B_TRUE) {
		arg[nargs++] = "-O";
		arg[nargs++] = "debug";
	}

	/* Add arguments how to start the pkgserv */

	arg[nargs++] = "-O";
	arg[nargs++] = pkgmodeargument(pkgservergetmode());

	/* pkgrm -b dir: pass -b to pkgremove */

	if (a_altBinDir != (char *)NULL) {
		arg[nargs++] = "-b";
		arg[nargs++] = a_altBinDir;
	}

	/*
	 * NONABI_SCRIPTS defined: pass -o to pkgremove; refers to a
	 * pkg requiring operator interaction during a procedure script
	 * (common before on1093)
	 */

	if (old_pkg) {
		arg[nargs++] = "-o";
	}

	/*
	 * PKG_NONABI_SYMLINKS defined: pass -y to pkgremove; process
	 * symlinks consistent with old behavior
	 */

	if (old_symlinks) {
		arg[nargs++] = "-y";
	}

	/* pkgrm -M: pass -M to pkgrm: dont mount client file systems */

	if (no_map_client) {
		arg[nargs++] = "-M";
	}

	/* pkgrm -A: pass -A to pkgrm */

	if (pkgrmremote) {
		arg[nargs++] = "-A";
	}

	/* pkgrm -v: pass -v to pkgremove: trace scripts */

	if (pkgverbose) {
		arg[nargs++] = "-v";
	}

	/* pkgrm -n: pass -n to pkgremove: noninteractive mode */

	if (nointeract) {
		arg[nargs++] = "-n";
	}

	/* pkgrm -a admin: pass -a admin to pkgremove: admin file */

	if (a_adminFile) {
		arg[nargs++] = "-a";
		arg[nargs++] = strdup(a_adminFile);
	}

	/* pkgrm -V vfstab: pass -V vfstab to pkgremove: alternate vfstab */

	if (vfstab_file) {
		arg[nargs++] = "-V";
		arg[nargs++] = vfstab_file;
	}

	/* pkgrm -R root: pass -R root to pkgremove: alternative root */

	if (is_an_inst_root()) {
		arg[nargs++] = "-R";
		arg[nargs++] = get_inst_root();
	}

	/* pkgrm -F: pass -F to pkgremove: update DB only */

	if (a_nodelete) {
		arg[nargs++] = "-F";
	}

	/*
	 * add parent zone info/type
	 */

	p = z_get_zonename();
	if ((p != NULL) && (*p != '\0')) {
			char	zn[MAXPATHLEN];
			(void) snprintf(zn, sizeof (zn),
				"parent-zone-name=%s", p);
			arg[nargs++] = "-O";
			arg[nargs++] = strdup(zn);
	}

	/* current zone type */

	arg[nargs++] = "-O";
	if (z_running_in_global_zone() == B_TRUE) {
			char	zn[MAXPATHLEN];
			(void) snprintf(zn, sizeof (zn),
				"parent-zone-type=%s",
				TAG_VALUE_GLOBAL_ZONE);
			arg[nargs++] = strdup(zn);
	} else {
			char	zn[MAXPATHLEN];
			(void) snprintf(zn, sizeof (zn),
				"parent-zone-type=%s",
				TAG_VALUE_NONGLOBAL_ZONE);
			arg[nargs++] = strdup(zn);
	}

	/* pass -N to pkgremove: program name to report */

	arg[nargs++] = "-N";
	arg[nargs++] = get_prog_name();

	/* add package instance name */

	arg[nargs++] = pkginst;

	/* terminate argument list */

	arg[nargs++] = NULL;

	/*
	 * run the appropriate pkgremove command in the specified zone
	 */

	if (debugFlag == B_TRUE) {
		echoDebug(DBG_ZONE_EXEC_ENTER, "global", arg[0]);
		for (n = 0; arg[n]; n++) {
			echoDebug(DBG_ARG, n, arg[n]);
		}
	}

	/* execute pkgremove command */

	n = pkgexecv(NULL, NULL, NULL, NULL, arg);

	/* return results of pkgrm in this zone */

	return (n);
}

static void
usage(void)
{
	char	*prog = get_prog_name();

	(void) fprintf(stderr, ERR_USAGE_PKGRM, prog, prog);
	exit(1);
}

/*
 * Name:	remove_packages_in_global_with_zones
 * Description:	Remove packages from the global zone and from non-global zones
 *		when run from the global zone and when non-global zones are
 *		present.
 * Arguments:	a_pkgList - pointer to array of strings, each string specifying
 *			the name of one package to be removed.
 *		a_nodelete: should the files and scripts remain installed?
 *			- if != 0 pass -F flag to pkgremove - suppress
 *			the removal of any files and any class action scripts
 *			and suppress the running of any class action scripts.
 *			The package files remain but the package looks like it
 *			is not installed. This is mainly for use by upgrade.
 *			- if == 0 do not pass -F flag to pkgremove - all
 *			files and class action scripts are removed, and any
 *			appropriate class action scripts are run.
 *		a_longestPkg - length of the longest package "name" (for
 *			output format alignment)
 *		a_repeat - are there more packages avialable in "optind"
 *			- B_TRUE - process packages from optind
 *			- B_FALSE - do not process packages from optind
 *		a_altBinDir - pointer to string representing location of the
 *			pkgremove executable to run. If not NULL, then pass
 *			the path specified to the -b option to pkgremove.
 *		a_pkgdir - pointer to string representing the directory
 *			where the packages to be removed are located.
 *		a_zlst - list of zones to process; NULL if no zones to process.
 * Returns:	int	(see ckreturn() function for details)
 *		0 - success
 *		1 - package operation failed (fatal error)
 *		2 - non-fatal error (warning)
 *		3 - user selected quit (operation interrupted)
 *		4 - admin settings prevented operation
 *		5 - interaction required and -n (non-interactive) specified
 *		"10" will be added to indicate "immediate reboot required"
 *		"20" will be added to indicate "reboot after install required"
 */

static boolean_t
remove_packages_in_global_with_zones(char **a_pkgList, int a_nodelete,
	int a_longestPkg, int a_repeat, char *a_altBinDir, char *a_pkgdir,
	zoneList_t a_zlst)
{
static	char		*zoneAdminFile = (char *)NULL;

	boolean_t	b;
	char		*zoneName;
	char		*scratchName;
	char		preremovecheckPath[PATH_MAX+1];
	int		i;
	int		n;
	int		savenpkgs = npkgs;
	int		zoneIndex;
	int		zonesSkipped;
	zone_state_t	zst;

	/* entry assertions */

	assert(a_zlst != (zoneList_t)NULL);
	assert(a_pkgList != (char **)NULL);
	assert(a_longestPkg > 0);
	assert(a_pkgdir != (char *)NULL);
	assert(*a_pkgdir != '\0');

	/* entry debugging info */

	echoDebug(DBG_PKGREMPKGSGZWNGZ_ENTRY);
	echoDebug(DBG_PKGREMPKGSGZWNGZ_ARGS, a_nodelete, a_longestPkg,
		a_repeat, PSTR(a_altBinDir), PSTR(a_pkgdir));

	/* check all packages */

	if (check_packages(a_pkgList, a_pkgdir) != B_TRUE) {
		quit(1);
	}

	/* create temporary directory for use by zone operations */

	create_zone_tempdir(&zoneTempDir, tmpdir);

	/* create hands off settings admin file for use in a non-global zone */

	create_zone_adminfile(&zoneAdminFile, zoneTempDir, admnfile);

	/*
	 * all of the packages (as listed in the package list) are
	 * removed one at a time from all non-global zones and then
	 * from the global zone.
	 */

	for (i = 0; (pkginst = a_pkgList[i]) != NULL; i++) {
		/* reset interrupted flag before calling pkgremove */

		interrupted = 0;	/* last action was NOT quit */

		/* skip package if it is "in the global zone only" */

		if (pkgIsPkgInGzOnly(get_inst_root(), pkginst) == B_TRUE) {
			continue;
		}

		/*
		 * if operation failed in global zone do not propagate to
		 * non-global zones
		 */

		zonesSkipped = 0;

		if (interrupted != 0) {
			echo(MSG_DOREMOVE_INTERRUPTED, pkginst);
			echoDebug(DBG_DOREMOVE_INTERRUPTED, pkginst);
			break;
		}

		echoDebug(DBG_REMOVE_FLAG_VALUES, "before loop",
			admnflag, doreboot, failflag, interrupted,
			intrflag, ireboot, nullflag, warnflag);

		for (zoneIndex = 0;
			(zoneName = z_zlist_get_zonename(a_zlst, zoneIndex)) !=
				(char *)NULL; zoneIndex++) {

			/* skip the zone if it is NOT running */

			zst = z_zlist_get_current_state(a_zlst, zoneIndex);
			if (zst != ZONE_STATE_RUNNING &&
			    zst != ZONE_STATE_MOUNTED) {
				zonesSkipped++;
				echoDebug(DBG_SKIPPING_ZONE, zoneName);
				continue;
			}

			echo(MSG_CHECKREMOVE_PKG_IN_ZONE, pkginst, zoneName);
			echoDebug(DBG_CHECKREMOVE_PKG_IN_ZONE, pkginst,
				zoneName);

			scratchName = z_zlist_get_scratch(a_zlst, zoneIndex);

			(void) snprintf(preremovecheckPath,
				sizeof (preremovecheckPath),
				"%s/%s.%s.preremovecheck.txt",
				zoneTempDir, pkginst, scratchName);

			/*
			 * dependency check this package this zone; use the
			 * user supplied admin file so that the appropriate
			 * level of dependency checking is (or is not) done.
			 */

			n = pkgZoneCheckRemove(scratchName, a_altBinDir,
				admnfile, preremovecheckPath,
				zst, B_FALSE);

			/* set success/fail condition variables */

			ckreturn(n);

			echoDebug(DBG_REMOVE_FLAG_VALUES,
				"after pkgzonecheckremove",
				admnflag, doreboot, failflag, interrupted,
				intrflag, ireboot, nullflag, warnflag);
		}

		if (zonesSkipped == 0) {
			continue;
		}

		echoDebug(DBG_ZONES_SKIPPED, zonesSkipped);

		for (zoneIndex = 0;
			(zoneName = z_zlist_get_zonename(a_zlst, zoneIndex)) !=
				(char *)NULL; zoneIndex++) {

			/* skip the zone if it IS running */

			zst = z_zlist_get_current_state(a_zlst, zoneIndex);
			if (zst == ZONE_STATE_RUNNING ||
			    zst == ZONE_STATE_MOUNTED) {
				zonesSkipped++;
				echoDebug(DBG_SKIPPING_ZONE_BOOT, zoneName);
				continue;
			}

			/* skip the zone if it is NOT bootable */

			if (z_zlist_is_zone_runnable(a_zlst,
						zoneIndex) == B_FALSE) {
				echo(MSG_SKIPPING_ZONE_NOT_RUNNABLE, zoneName);
				echoDebug(DBG_SKIPPING_ZONE_NOT_RUNNABLE,
					zoneName);
				continue;
			}

			/* mount up the zone */

			echo(MSG_BOOTING_ZONE, zoneName);
			echoDebug(DBG_BOOTING_ZONE, zoneName);

			b = z_zlist_change_zone_state(a_zlst, zoneIndex,
				ZONE_STATE_MOUNTED);
			if (b == B_FALSE) {
				progerr(ERR_CANNOT_BOOT_ZONE, zoneName);
				/* set fatal error return condition */
				ckreturn(1);
				continue;
			}

			echo(MSG_CHECKREMOVE_PKG_IN_ZONE, pkginst, zoneName);
			echoDebug(DBG_CHECKREMOVE_PKG_IN_ZONE, pkginst,
					zoneName);

			scratchName = z_zlist_get_scratch(a_zlst, zoneIndex);

			(void) snprintf(preremovecheckPath,
				sizeof (preremovecheckPath),
				"%s/%s.%s.preremovecheck.txt",
				zoneTempDir, pkginst, scratchName);

			/*
			 * dependency check this package this zone; use the
			 * user supplied admin file so that the appropriate
			 * level of dependency checking is (or is not) done.
			 */

			n = pkgZoneCheckRemove(scratchName, a_altBinDir,
				admnfile, preremovecheckPath,
				ZONE_STATE_MOUNTED, B_TRUE);

			/* set success/fail condition variables */

			ckreturn(n);

			echoDebug(DBG_REMOVE_FLAG_VALUES,
				"after pkgzonecheckremove",
				admnflag, doreboot, failflag, interrupted,
				intrflag, ireboot, nullflag, warnflag);

			/* restore original state of zone */

			echo(MSG_RESTORE_ZONE_STATE, zoneName);
			echoDebug(DBG_RESTORE_ZONE_STATE, zoneName);

			b = z_zlist_restore_zone_state(a_zlst, zoneIndex);
		}
		npkgs--;
	}

	/*
	 * look at all pre-remove check files
	 */

	i = preremove_verify(a_pkgList, a_zlst, zoneTempDir);
	if (i != 0) {
		quit(i);
	}

	npkgs = savenpkgs;

	/*
	 * reset all error return condition variables that may have been
	 * set during package removal dependency checking so that they
	 * do not reflect on the success/failure of the actual package
	 * removal operations
	 */

	resetreturn();

	/*
	 * all of the packages (as listed in the package list) are
	 * removed one at a time.
	 */

	interrupted = 0;
	for (i = 0; (pkginst = a_pkgList[i]) != NULL; i++) {
		boolean_t	in_gz_only;
		started = 0;

		if (shall_we_continue(pkginst, npkgs) == B_FALSE) {
			continue;
		}

		in_gz_only = pkgIsPkgInGzOnly(get_inst_root(), pkginst);

		/* reset interrupted flag before calling pkgremove */

		interrupted = 0;

		/*
		 * pkgrm invoked from within the global zone and there are
		 * non-global zones configured:
		 * Remove the package from the global zone.
		 * If not removing the package from the global zone only,
		 * then remove the package from the list of zones specified.
		 */

		if (in_gz_only) {
			/* global zone only */
			n = doRemove(a_nodelete, a_altBinDir, a_longestPkg,
				admnfile, (char *)NULL, (zoneList_t)NULL);
		} else {
			/* global zone and non-global zones */
			n = doRemove(a_nodelete, a_altBinDir, a_longestPkg,
				zoneAdminFile, zoneAdminFile, a_zlst);
		}

		/* set success/fail condition variables */

		ckreturn(n);

		npkgs--;
	}

	/*
	 * all packages in the package list have been removed.
	 * Continue with removal if:
	 * -- immediate reboot is NOT required
	 * -- there are more packages to remove
	 * else return do NOT continue.
	 */

	if ((ireboot == 0) && (a_repeat != 0)) {
		return (B_TRUE);
	}

	/* return 'dont continue' */

	return (B_FALSE);
}

/*
 * Name:	remove_packages_in_nonglobal_zone
 * Description:	Remove packages in a non-global zone when run from a
 *		non-global zone.
 * Arguments:	a_pkgList - pointer to array of strings, each string specifying
 *			the name of one package to be removed.
 *		a_nodelete: should the files and scripts remain installed?
 *			- if != 0 pass -F flag to pkgremove - suppress
 *			the removal of any files and any class action scripts
 *			and suppress the running of any class action scripts.
 *			The package files remain but the package looks like it
 *			is not installed. This is mainly for use by upgrade.
 *			- if == 0 do not pass -F flag to pkgremove - all
 *			files and class action scripts are removed, and any
 *			appropriate class action scripts are run.
 *		a_longestPkg - length of the longest package "name" (for
 *			output format alignment)
 *		a_repeat - are there more packages avialable in "optind"
 *			- B_TRUE - process packages from optind
 *			- B_FALSE - do not process packages from optind
 *		a_altBinDir - pointer to string representing location of the
 *			pkgremove executable to run. If not NULL, then pass
 *			the path specified to the -b option to pkgremove.
 *		a_pkgdir - pointer to string representing the directory
 *			where the packages to be removed are located.
 * Returns:	int	(see ckreturn() function for details)
 *		0 - success
 *		1 - package operation failed (fatal error)
 *		2 - non-fatal error (warning)
 *		3 - user selected quit (operation interrupted)
 *		4 - admin settings prevented operation
 *		5 - interaction required and -n (non-interactive) specified
 *		"10" will be added to indicate "immediate reboot required"
 *		"20" will be added to indicate "reboot after install required"
 */

static boolean_t
remove_packages_in_nonglobal_zone(char **a_pkgList, int a_nodelete,
	int a_longestPkg, int a_repeat, char *a_altBinDir, char *a_pkgdir)
{
static	char		*zoneAdminFile = (char *)NULL;

	int		n;
	int		i;

	/* entry assertions */

	assert(a_pkgList != (char **)NULL);
	assert(a_longestPkg > 0);
	assert(a_pkgdir != (char *)NULL);
	assert(*a_pkgdir != '\0');

	/* entry debugging info */

	echoDebug(DBG_PKGREMPKGSNGZ_ENTRY);
	echoDebug(DBG_PKGREMPKGSNGZ_ARGS, a_nodelete, a_longestPkg,
		a_repeat, PSTR(a_altBinDir), PSTR(a_pkgdir));

	/* check all package */

	if (check_packages(a_pkgList, a_pkgdir) != B_TRUE) {
		quit(1);
	}

	/* create temporary directory for use by zone operations */

	create_zone_tempdir(&zoneTempDir, tmpdir);

	/* create hands off settings admin file for use in a non-global zone */

	create_zone_adminfile(&zoneAdminFile, zoneTempDir, admnfile);

	/*
	 * all of the packages (as listed in the package list) are
	 * removed one at a time.
	 */

	interrupted = 0;
	for (i = 0; (pkginst = a_pkgList[i]) != NULL; i++) {
		started = 0;

		if (shall_we_continue(pkginst, npkgs) == B_FALSE) {
			continue;
		}

		interrupted = 0;

		/*
		 * pkgrm invoked from within a non-global zone: remove
		 * the package from the current zone only - no non-global
		 * zones are possible.
		 */

		n = doRemove(a_nodelete, a_altBinDir, a_longestPkg,
			admnfile, (char *)NULL, (zoneList_t)NULL);

		/* set success/fail condition variables */

		ckreturn(n);

		npkgs--;
	}

	/*
	 * all packages in the package list have been removed.
	 * Continue with removal if:
	 * -- immediate reboot is NOT required
	 * -- there are more packages to remove
	 * else return do NOT continue.
	 */

	if ((ireboot == 0) && (a_repeat != 0)) {
		return (B_TRUE);
	}

	/* return 'dont continue' */

	return (B_FALSE);
}

/*
 * Name:	remove_packages_in_global_no_zones
 * Description:	Remove packages from the global zone only when run in the
 *		global zone and no non-global zones are installed.
 * Arguments:	a_pkgList - pointer to array of strings, each string specifying
 *			the name of one package to be removed.
 *		a_nodelete: should the files and scripts remain installed?
 *			- if != 0 pass -F flag to pkgremove - suppress
 *			the removal of any files and any class action scripts
 *			and suppress the running of any class action scripts.
 *			The package files remain but the package looks like it
 *			is not installed. This is mainly for use by upgrade.
 *			- if == 0 do not pass -F flag to pkgremove - all
 *			files and class action scripts are removed, and any
 *			appropriate class action scripts are run.
 *		a_longestPkg - length of the longest package "name" (for
 *			output format alignment)
 *		a_repeat - are there more packages avialable in "optind"
 *			- B_TRUE - process packages from optind
 *			- B_FALSE - do not process packages from optind
 *		a_altBinDir - pointer to string representing location of the
 *			pkgremove executable to run. If not NULL, then pass
 *			the path specified to the -b option to pkgremove.
 * Returns:	int	(see ckreturn() function for details)
 *		0 - success
 *		1 - package operation failed (fatal error)
 *		2 - non-fatal error (warning)
 *		3 - user selected quit (operation interrupted)
 *		4 - admin settings prevented operation
 *		5 - interaction required and -n (non-interactive) specified
 *		"10" will be added to indicate "immediate reboot required"
 *		"20" will be added to indicate "reboot after install required"
 */

static boolean_t
remove_packages_in_global_no_zones(char **a_pkgList, int a_nodelete,
	int a_longestPkg, int a_repeat, char *a_altBinDir)
{
	int	n;
	int	i;

	/* entry assertions */

	assert(a_pkgList != (char **)NULL);
	assert(a_longestPkg > 0);

	/* entry debugging info */

	echoDebug(DBG_PKGREMPKGSGZNNGZ_ENTRY);
	echoDebug(DBG_PKGREMPKGSGZNNGZ_ARGS, a_nodelete, a_longestPkg,
		a_repeat, PSTR(a_altBinDir));

	/*
	 * all of the packages (as listed in the package list) are
	 * removed one at a time.
	 */

	interrupted = 0;
	for (i = 0; (pkginst = a_pkgList[i]) != NULL; i++) {
		started = 0;

		if (shall_we_continue(pkginst, npkgs) == B_FALSE) {
			continue;
		}

		interrupted = 0;

		/*
		 * pkgrm invoked from within the global zone and there are
		 * NO non-global zones configured:
		 * Remove the package from the global zone only.
		 */

		n = doRemove(a_nodelete, a_altBinDir, a_longestPkg,
				admnfile, (char *)NULL, (zoneList_t)NULL);

		/* set success/fail condition variables */

		ckreturn(n);

		npkgs--;
	}

	/*
	 * all packages in the package list have been removed.
	 * Continue with removal if:
	 * -- immediate reboot is NOT required
	 * -- there are more packages to remove
	 * else return do NOT continue.
	 */

	if ((ireboot == 0) && (a_repeat != 0)) {
		return (B_TRUE);
	}

	/* return 'dont continue' */

	return (B_FALSE);
}

/*
 * Name:	remove_packages_from_spool_directory
 * Description:	Remove packages from a spool directory only.
 * Arguments:	a_pkgList - pointer to array of strings, each string specifying
 *			the name of one package to be removed.
 *		a_nodelete: should the files and scripts remain installed?
 *			- if != 0 pass -F flag to pkgremove - suppress
 *			the removal of any files and any class action scripts
 *			and suppress the running of any class action scripts.
 *			The package files remain but the package looks like it
 *			is not installed. This is mainly for use by upgrade.
 *			- if == 0 do not pass -F flag to pkgremove - all
 *			files and class action scripts are removed, and any
 *			appropriate class action scripts are run.
 *		a_longestPkg - length of the longest package "name" (for
 *			output format alignment)
 *		a_repeat - are there more packages avialable in "optind"
 *			- B_TRUE - process packages from optind
 *			- B_FALSE - do not process packages from optind
 *		a_altBinDir - pointer to string representing location of the
 *			pkgremove executable to run. If not NULL, then pass
 *			the path specified to the -b option to pkgremove.
 * Returns:	int	(see ckreturn() function for details)
 *		0 - success
 *		1 - package operation failed (fatal error)
 *		2 - non-fatal error (warning)
 *		3 - user selected quit (operation interrupted)
 *		4 - admin settings prevented operation
 *		5 - interaction required and -n (non-interactive) specified
 *		"10" will be added to indicate "immediate reboot required"
 *		"20" will be added to indicate "reboot after install required"
 */

static boolean_t
remove_packages_from_spool_directory(char **a_pkgList, int a_nodelete,
	int a_longestPkg, int a_repeat, char *a_altBinDir)
{
	int	n;
	int	i;

	/* entry assertions */

	assert(a_pkgList != (char **)NULL);
	assert(a_longestPkg > 0);

	/*
	 * all of the packages (as listed in the package list) are
	 * removed one at a time.
	 */

	interrupted = 0;
	for (i = 0; (pkginst = a_pkgList[i]) != NULL; i++) {
		started = 0;

		if (shall_we_continue(pkginst, npkgs) == B_FALSE) {
			continue;
		}

		interrupted = 0;

		/*
		 * pkgrm invoked from any type of zone BUT the target
		 * to be removed is a local spool directory: remove the
		 * packages from the spool directory only.
		 */

		n = doRemove(a_nodelete, a_altBinDir, a_longestPkg,
			admnfile, (char *)NULL, (zoneList_t)NULL);

		/* set success/fail condition variables */

		ckreturn(n);

		npkgs--;
	}

	/*
	 * all packages in the package list have been removed.
	 * Continue with removal if:
	 * -- immediate reboot is NOT required
	 * -- there are more packages to remove
	 * else return do NOT continue.
	 */

	if ((ireboot == 0) && (a_repeat != 0)) {
		return (B_TRUE);
	}

	/* return 'dont continue' */

	return (B_FALSE);
}

/*
 * Name:	remove_packages
 * Description:	Remove packages from the global zone, and optionally from one
 *		or more non-global zones, or from a specified spool directory.
 * Arguments:	a_pkgList - pointer to array of strings, each string specifying
 *			the name of one package to be removed.
 *		a_nodelete: should the files and scripts remain installed?
 *			- if != 0 pass -F flag to pkgremove - suppress
 *			the removal of any files and any class action scripts
 *			and suppress the running of any class action scripts.
 *			The package files remain but the package looks like it
 *			is not installed. This is mainly for use by upgrade.
 *			- if == 0 do not pass -F flag to pkgremove - all
 *			files and class action scripts are removed, and any
 *			appropriate class action scripts are run.
 *		a_longestPkg - length of the longest package "name" (for
 *			output format alignment)
 *		a_repeat - are there more packages avialable in "optind"
 *			- B_TRUE - process packages from optind
 *			- B_FALSE - do not process packages from optind
 *		a_altBinDir - pointer to string representing location of the
 *			pkgremove executable to run. If not NULL, then pass
 *			the path specified to the -b option to pkgremove.
 *		a_pkgdir - pointer to string representing the directory
 *			where the packages to be removed are located.
 *		a_spoolDir - pointer to string specifying spool directory
 *			to remove packages from. If != NULL then all zones
 *			processing is bypassed and the packages are removed
 *			from the specified spool directory only.
 *		a_noZones - if non-global zones are configured, should the
 *			packages be removed from the non-global zones?
 *			- B_TRUE - do NOT remove packages from non-global zones
 *			- B_FALSE - remove packages from non-global zones
 * Returns:	int	(see ckreturn() function for details)
 *		0 - success
 *		1 - package operation failed (fatal error)
 *		2 - non-fatal error (warning)
 *		3 - user selected quit (operation interrupted)
 *		4 - admin settings prevented operation
 *		5 - interaction required and -n (non-interactive) specified
 *		"10" will be added to indicate "immediate reboot required"
 *		"20" will be added to indicate "reboot after install required"
 */

static boolean_t
remove_packages(char **a_pkgList, int a_nodelete, int a_longestPkg,
	int a_repeat, char *a_altBinDir, char *a_pkgdir, char *a_spoolDir,
	boolean_t a_noZones)
{
	zoneList_t	zlst;
	boolean_t	b;

	/* entry assertions */

	assert(a_pkgList != (char **)NULL);

	echoDebug(DBG_REMOVEPKGS_ENTRY);
	echoDebug(DBG_REMOVEPKGS_ARGS, npkgs, a_nodelete, a_longestPkg,
		a_repeat, PSTR(a_pkgdir), PSTR(a_spoolDir));

	/*
	 * if removing from spool directory, bypass all zones checks
	 */

	if (a_spoolDir != (char *)NULL) {
		/* in non-global zone */

		echoDebug(DBG_REMOVE_PKGS_FROM_SPOOL, a_spoolDir);

		b = remove_packages_from_spool_directory(a_pkgList, a_nodelete,
			a_longestPkg, a_repeat, a_altBinDir);

		return (B_FALSE);
	}

	/* exit if not root */

	if (getuid()) {
		progerr(ERR_NOT_ROOT, get_prog_name());
		exit(1);
	}

	/*
	 * if running in the global zone AND one or more non-global
	 * zones exist, add packages in a 'zones aware' manner, else
	 * add packages in the standard 'non-zones aware' manner.
	 */

	if ((a_noZones == B_FALSE) && (z_running_in_global_zone() == B_FALSE)) {
		/* in non-global zone */

		echoDebug(DBG_IN_LZ);

		b = z_lock_this_zone(ZLOCKS_PKG_ADMIN);
		if (b != B_TRUE) {
			progerr(ERR_CANNOT_LOCK_THIS_ZONE);
			/* set fatal error return condition */
			ckreturn(1);
			return (B_FALSE);
		}

		b = remove_packages_in_nonglobal_zone(a_pkgList, a_nodelete,
			a_longestPkg, a_repeat, a_altBinDir, a_pkgdir);

		(void) z_unlock_this_zone(ZLOCKS_ALL);

		return (B_FALSE);
	}

	/* running in the global zone */

	b = z_non_global_zones_exist();
	if ((a_noZones == B_FALSE) && (b == B_TRUE)) {

		echoDebug(DBG_IN_GZ_WITH_LZ);

		/* get a list of all non-global zones */
		zlst = z_get_nonglobal_zone_list();
		if (zlst == (zoneList_t)NULL) {
			progerr(ERR_CANNOT_GET_ZONE_LIST);
			quit(1);
		}

		/* need to lock all of the zones */

		quitSetZonelist(zlst);
		b = z_lock_zones(zlst, ZLOCKS_PKG_ADMIN);
		if (b == B_FALSE) {
			z_free_zone_list(zlst);
			progerr(ERR_CANNOT_LOCK_ZONES);
			/* set fatal error return condition */
			ckreturn(1);
			return (B_FALSE);
		}

		/* add packages to all zones */

		b = remove_packages_in_global_with_zones(a_pkgList, a_nodelete,
			a_longestPkg, a_repeat, a_altBinDir, a_pkgdir, zlst);

		/* unlock all zones */

		(void) z_unlock_zones(zlst, ZLOCKS_ALL);
		quitSetZonelist((zoneList_t)NULL);

		/* free list of all non-global zones */

		z_free_zone_list(zlst);

		return (B_FALSE);
	}

	/* in global zone no non-global zones */

	echoDebug(DBG_IN_GZ_NO_LZ);

	b = z_lock_this_zone(ZLOCKS_PKG_ADMIN);
	if (b != B_TRUE) {
		progerr(ERR_CANNOT_LOCK_THIS_ZONE);
		/* set fatal error return condition */
		ckreturn(1);
		return (B_FALSE);
	}

	b = remove_packages_in_global_no_zones(a_pkgList, a_nodelete,
			a_longestPkg, a_repeat, a_altBinDir);

	(void) z_unlock_this_zone(ZLOCKS_ALL);

	return (B_FALSE);
}

/*
 */

static boolean_t
check_packages(char **a_pkgList, char *a_packageDir)
{
	int	savenpkgs = npkgs;
	int	i;
	CAF_T	flags = 0;

	/* set flags for applicability check */

	if (z_running_in_global_zone() == B_TRUE) {
		flags |= CAF_IN_GLOBAL_ZONE;
	}

	/*
	 * for each package to remove, verify that the package is installed
	 * and is removable.
	 */

	for (i = 0; (pkginst = a_pkgList[i]) != NULL; i++) {
		/* check package applicability */
		if (check_applicability(a_packageDir, pkginst, get_inst_root(),
			flags) == B_FALSE) {
			progerr(ERR_PKG_NOT_REMOVABLE, pkginst);
			npkgs = savenpkgs;
			return (B_FALSE);
		}
		npkgs--;
	}

	npkgs = savenpkgs;
	return (B_TRUE);
}

/*
 * - is this package removable from this zone?
 * - does the scope of remove conflict with existing installation
 */

static boolean_t
check_applicability(char *a_packageDir, char *a_pkgInst,
	char *a_rootPath, CAF_T a_flags)
{
	FILE		*pkginfoFP;
	boolean_t	all_zones;	/* pkg is "all zones" only */
	char		pkginfoPath[PATH_MAX];
	char		pkgpath[PATH_MAX];
	int		len;

	/* entry assertions */

	assert(a_packageDir != (char *)NULL);
	assert(*a_packageDir != '\0');
	assert(a_pkgInst != (char *)NULL);
	assert(*a_pkgInst != '\0');

	/* normalize root path */

	if (a_rootPath == (char *)NULL) {
		a_rootPath = "";
	}

	/*
	 * determine if this package is currently installed
	 * if not installed return success - operation will fail
	 * when the removal is attempted
	 */

	if (pkginfoIsPkgInstalled((struct pkginfo **)NULL, a_pkgInst) !=
		B_TRUE) {
		return (B_TRUE);
	}

	/*
	 * calculate paths to various objects
	 */

	len = snprintf(pkgpath, sizeof (pkgpath), "%s/%s", a_packageDir,
			a_pkgInst);
	if (len > sizeof (pkgpath)) {
		progerr(ERR_CREATE_PATH_2, a_packageDir, a_pkgInst);
		return (B_FALSE);
	}

	/* if not installed then just return */

	if (isdir(pkgpath) != 0) {
		progerr(ERR_NO_PKGDIR, pkgpath, a_pkgInst, strerror(errno));
		return (B_TRUE);
	}

	len = snprintf(pkginfoPath, sizeof (pkginfoPath),
			"%s/pkginfo", pkgpath);
	if (len > sizeof (pkgpath)) {
		progerr(ERR_CREATE_PATH_2, pkgpath, "pkginfo");
		return (B_FALSE);
	}

	/*
	 * gather information from this packages pkginfo file
	 */

	pkginfoFP = fopen(pkginfoPath, "r");

	if (pkginfoFP == (FILE *)NULL) {
		progerr(ERR_NO_PKG_INFOFILE, a_pkgInst, pkginfoPath,
							strerror(errno));
		return (B_FALSE);
	}

	/* determine "ALLZONES" setting for this package */

	all_zones = pkginfoParamTruth(pkginfoFP, PKG_ALLZONES_VARIABLE,
			"true", B_FALSE);

	/* close pkginfo file */

	(void) fclose(pkginfoFP);

	/* gather information from the global zone only file */

	/*
	 * verify package applicability based on information gathered;
	 * the package IS currently installed....
	 */

	/* pkg ALLZONES=true & not running in global zone */

	if ((all_zones == B_TRUE) && (!(a_flags & CAF_IN_GLOBAL_ZONE))) {
		progerr(ERR_ALLZONES_AND_IN_LZ_PKGRM, a_pkgInst);
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Name:	shall_we_continue
 * Description: Called from within a loop that is installing packages,
 *		this function examines various global variables and decides
 *		whether or not to ask an appropriate question, and wait for
 *		and appropriate reply.
 * Arguments:	<<global variables>>
 * Returns:	B_TRUE - continue processing with next package
 *		B_FALSE - do not continue processing with next package
 */

static boolean_t
shall_we_continue(char *a_pkgInst, int a_npkgs)
{
	char	ans[MAX_INPUT];
	int	n;

	/* return FALSE if immediate reboot required */

	if (ireboot) {
		ptext(stderr, MSG_SUSPEND_RM, a_pkgInst);
		return (B_FALSE);
	}

	/* return TRUE if not interrupted */

	if (!interrupted) {
		return (B_TRUE);
	}

	/* output appropriate interrupt message */

	echo(a_npkgs == 1 ? MSG_1MORETODO : MSG_MORETODO, a_npkgs);

	/* if running with no interaction (-n) do not ask question */

	if (nointeract) {
		quit(0);
		/* NOTREACHED */
	}

	/* interaction possible: ask question */

	n = ckyorn(ans, NULL, NULL, NULL, ASK_CONTINUE_RM);
	if (n != 0) {
		quit(n);
		/* NOTREACHED */
	}

	if (strchr("yY", *ans) == NULL) {
		quit(0);
		/* NOTREACHED */
	}
	return (B_TRUE);
}

/*
 * Name:	create_zone_adminfile
 * Description: Given a zone temporary directory and optionally an existing
 *		administration file, generate an administration file that
 *		can be used to perform "non-interactive" operations in a
 *		non-global zone.
 * Arguments:	r_zoneAdminFile - pointer to handle that will contain a
 *			string representing the path to the temporary
 *			administration file created - this must be NULL
 *			before the first call to this function - on
 *			subsequent calls if the pointer is NOT null then
 *			the existing string will NOT be overwritten.
 *		a_zoneTempDir - pointer to string representing the path
 *			to the zone temporary directory to create the
 *			temporary administration file in
 *		a_admnfile - pointer to string representing the path to
 *			an existing "user" administration file - the
 *			administration file created will contain the
 *			settings contained in this file, modified as
 *			appropriate to supress any interaction;
 *			If this is == NULL then the administration file
 *			created will not contain any extra settings
 * Returns:	void
 * NOTE:	Any string returned is placed in new storage for the
 *		calling method. The caller must use 'free' to dispose
 *		of the storage once the string is no longer needed.
 * NOTE:	On any error this function will call 'quit(1)'
 */

static void
create_zone_adminfile(char **r_zoneAdminFile, char *a_zoneTempDir,
	char *a_admnfile)
{
	boolean_t	b;

	/* entry assertions */

	assert(r_zoneAdminFile != (char **)NULL);
	assert(a_zoneTempDir != (char *)NULL);
	assert(*a_zoneTempDir != '\0');

	/* entry debugging info */

	echoDebug(DBG_CREATE_ZONE_ADMINFILE, a_zoneTempDir, PSTR(a_admnfile));

	/* if temporary name already exists, do not overwrite */

	if (*r_zoneAdminFile != (char *)NULL) {
		return;
	}

	/* create temporary name */

	*r_zoneAdminFile = tempnam(a_zoneTempDir, "zadmn");
	b = z_create_zone_admin_file(*r_zoneAdminFile, a_admnfile);
	if (b == B_FALSE) {
		progerr(ERR_CREATE_TMPADMIN, *r_zoneAdminFile,
			strerror(errno));
		quit(1);
		/* NOTREACHED */
	}

	echoDebug(DBG_CREATED_ZONE_ADMINFILE, *r_zoneAdminFile);
}

/*
 * Name:	create_zone_tempdir
 * Description: Given a system temporary directory, create a "zone" specific
 *		temporary directory and return the path to the directory
 *		created.
 * Arguments:	r_zoneTempDir - pointer to handle that will contain a
 *			string representing the path to the temporary
 *			directory created - this must be NULL before the
 *			first call to this function - on subsequent calls
 *			if the pointer is NOT null then the existing string
 *			will NOT be overwritten.
 *		a_zoneTempDir - pointer to string representing the path
 *			to the system temporary directory to create the
 *			temporary zone directory in
 * Returns:	void
 * NOTE:	Any string returned is placed in new storage for the
 *		calling method. The caller must use 'free' to dispose
 *		of the storage once the string is no longer needed.
 * NOTE:	On any error this function will call 'quit(1)'
 * NOTE:	This function calls "quitSetZoneTmpdir" on success to
 *		register the directory created with quit() so that the
 *		directory will be automatically deleted on exit.
 */

static void
create_zone_tempdir(char **r_zoneTempDir, char *a_tmpdir)
{
	boolean_t	b;

	/* entry assertions */

	assert(r_zoneTempDir != (char **)NULL);
	assert(a_tmpdir != (char *)NULL);
	assert(*a_tmpdir != '\0');

	/* entry debugging info */

	echoDebug(DBG_CREATE_ZONE_TEMPDIR, a_tmpdir);

	/* if temporary directory already exists, do not overwrite */

	if (*r_zoneTempDir != (char *)NULL) {
		return;
	}

	/* create temporary directory */

	b = setup_temporary_directory(r_zoneTempDir, a_tmpdir, "ztemp");
	if (b == B_FALSE) {
		progerr(ERR_ZONETEMPDIR, a_tmpdir, strerror(errno));
		quit(1);
		/* NOTREACHED */
	}

	/* register with quit() to directory is removed on exit */

	quitSetZoneTmpdir(*r_zoneTempDir);

	/* exit debugging info */

	echoDebug(DBG_CREATED_ZONE_TEMPDIR, *r_zoneTempDir);
}
