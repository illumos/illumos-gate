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
 * Copyright (c) 2018 Peter Tribble.
 */

/*
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */


/*
 * Program:	pkgadd / pkgask
 *
 * Function:	public command and private utility functions that
 *		implement the package add and package ask operations.
 *
 */

/*
 * System includes
 */

#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <errno.h>
#include <pkgdev.h>
#include <pkginfo.h>
#include <pkglocs.h>
#include <locale.h>
#include <libintl.h>
#include <pkgtrans.h>
#include <assert.h>

/*
 * consolidation pkg command library includes
 */
#include <pkglib.h>

#include <instzones_api.h>

/*
 * local pkg command library includes
 */
#include <install.h>
#include <libinst.h>
#include <libadm.h>
#include <messages.h>


/*
 * pkgadd local includes
 */

#include "quit.h"

/*
 * imported global variables/functions
 */

/* check.c */
extern int	preinstall_verify(char **a_pkgList, zoneList_t a_zlst,
			char *a_zoneTempDir);

/*
 * ckquit is a global that controls 'ckyorn' (defined in libadm)
 * If ckquit is non-zero, then "quit" is allowed as an answer when
 * ckyorn is called. If is it zero, then "quit" is not an allowed answer.
 */
extern int	ckquit;

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

/* imported by various (many) */
char	*respfile = NULL;	/* response pathname (or NULL) */
char	*tmpdir = NULL;		/* location to place temporary files */

struct admin	adm;		/* holds info about installation admin */
struct pkgdev	pkgdev;		/* holds info about the installation device */

/*
 * internal global variables
 */

static char	*admnfile = NULL;	/* file to use for installation admin */
static char	*ids_name = NULL;	/* name of data stream device */
static char	*pkgcontsrc = NULL;	/* continuation file (-c option) */
static char	*pkgdrtarg = NULL;	/* dry run file (-D option) */
static char	*pkginst = NULL;	/* current pkg/src instance 2 process */
static char	*respdir = NULL;	/* respfile is a directory spec */
static char	*rw_block_size = NULL;
static char	*vfstab_file = NULL;
static int	askflag = 0;		/* non-zero if invoked as "pkgask" */
static int	disableAttributes = 0;	/* Disabling attribute checking */
static int	disableChecksum = 0;	/* Disable checksumming */
static int	disableSaveSpool = 0;	/* Disable partial spool dir create */
static int	init_install = 0;	/* inform scripts initial install */
static int	no_map_client = 0;	/* do not map from vfstab file */
static int	nointeract = 0;		/* non-zero - no user interaction */
static int	pkgverbose = 0;		/* non-zero if verbose mode selected */
static int	saveSpoolInstall = 0;	/* installing from save spool dir */
static int	suppressCopyright = 0;	/* suppress copyright notices */

/* set by ckreturn() */

static int	interrupted = 0;	/* last pkg op was quit (1,2,3,4,5) */
static int	needconsult = 0;	/* essential ask admin now (1,2,3,5) */

/* Set by -O nozones: do not process any zones */

static boolean_t	noZones = B_FALSE;

/* Set by -O zonelist=<names...>: process only named zones */

static boolean_t	usedZoneList = B_FALSE;

/* Set by -O debug: debug output is enabled? */

static boolean_t	debugFlag = B_FALSE;

/* Set by the -G option: install packages in global zone only */

static boolean_t	globalZoneOnly = B_FALSE;

/*
 * Assume the package is ABI and POSIX compliant as regards user
 * interactiion during procedure scripts.
 */

static int	old_pkg = 0;

/* Assume pkg should be installed according to the ABI */

static int	old_symlinks = 0;

/*
 * Default name length will be 32 chars - if this is set,
 * disable the 32 char name limit extension
 */

static int	ABI_namelength = 0;

#if	!defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

/* printable string - if string is null results in ??? */

#define	PSTR(STR) (((STR) == (char *)NULL) ? "???" : (STR))

#define	MAX_FDS	20

/*
 * forward declarations
 */

static int		boot_and_pkginstall_check_in_zones(zoneList_t a_zlst,
				char *a_idsName, char *a_altBinDir,
				char *a_zoneAdminFile, char *a_zoneTempDir);
static int		boot_and_install_in_zones(zoneList_t a_zlst,
				char *a_idsName, char *a_altBinDir,
				char *a_zoneAdminFile, char *a_zoneTempDir);
static void		pkginstall_check_in_one_zone(char *a_zoneName,
				char *a_idsName, char *a_zoneAdminFile,
				char *a_zoneTempDir, char *a_altBinDir,
				char *a_scratchName, zone_state_t a_zoneState,
				boolean_t a_tmpzn);
static void		ckreturn(int retcode);
static void		create_zone_adminfile(char **r_zoneAdminFile,
				char *a_zoneTempDir, char *a_admnfile);
static void		create_zone_tempdir(char **r_zoneTempDir,
				char *a_tmpdir);
static void		install_in_one_zone(char *a_zoneName, char *a_idsName,
				char *a_zoneAdminFile, char *a_zoneTempDir,
				char *a_altBinDir, zone_state_t a_zoneState,
				boolean_t a_tmpzn);
static int		pkginstall_check_in_zones(zoneList_t a_zlst,
				char *a_idsName, char *a_altBinDir,
				char *a_zoneAdminFile, char *a_zoneTempDir);
static int		install_in_zones(zoneList_t a_zlst, char *a_idsName,
				char *a_altBinDir, char *a_zoneAdminFile,
				char *a_zoneTempDir);
static int		pkgInstall(char *ir, char *a_idsName, char *a_pkgDir,
				char *a_altBinDir);
static int		pkgZoneCheckInstall(char *a_zoneName,
				zone_state_t a_zoneState,
				char *a_idsName, char *a_altBinDir,
				char *a_adminFile, char *a_stdoutPath,
				boolean_t a_tmpzn);
static int		pkgZoneInstall(char *a_zoneName,
				zone_state_t a_zoneState,
				char *a_idsName, char *a_altBinDir,
				char *a_adminFile, boolean_t a_tmpzn);
static void		resetreturn();
static void		usage(void);
static boolean_t	add_packages(char **a_pkgList,
				char *a_idsName, int a_repeat,
				char *a_altBinDir, char *a_device,
				boolean_t a_noZones);
static boolean_t	add_packages_in_global_no_zones(char **a_pkgList,
				char *a_idsName, int a_repeat,
				char *a_altBinDir, char *a_device);
static boolean_t	add_packages_in_global_with_zones(char **a_pkgList,
				char *a_idsName, int a_repeat,
				char *a_altBinDir, char *a_device,
				zoneList_t a_zlst);
static boolean_t	add_packages_in_nonglobal_zone(char **a_pkgList,
				char *a_idsName, int a_repeat,
				char *a_altBinDir, char *a_device);
static boolean_t	check_applicability(char *a_packageDir,
				char *a_pkgInst, char *a_rootPath,
				CAF_T a_flags);
static boolean_t	get_package_list(char ***r_pkgList, char **a_argv,
				char *a_categories, char **a_categoryList,
				char *a_idsName, int *r_repeat);
static boolean_t	continue_installation(void);
static boolean_t	unpack_and_check_packages(char **a_pkgList,
				char *a_idsName, char *a_packageDir);
/*
 * *****************************************************************************
 * global external (public) functions
 * *****************************************************************************
 */

/*
 * Name:	main
 * Description:	main entry point for pkgadd/pkgask
 * Returns:	int
 *   0        Successful completion
 *   1        Fatal error.
 *   2        Warning.
 *   3        Interruption.
 *   4        Administration.
 *   5        Administration. Interaction is required. Do not use pkgadd -n.
 * In addition, one of the following values may be added to the previous value
 * as appropriate:
 *  10       Reboot after installation of all packages.
 *  20       Reboot after installation of this package.
 * For example, "14" would indicate both "administration" and "reboot after
 * installation of all packages".
 */

int
main(int argc, char **argv)
{
	char			**category = NULL;
	char			*abiPtr;
	char			*altBinDir = (char *)NULL;
	char			*catg_arg = NULL;
	char			*device = NULL;		/* dev pkg stored on */
	char			*p;
	char			*q;
	char			*prog;
	char			*prog_full_name = NULL;
	char			*spoolDir = NULL;	/* specified with -s */
	char			Rpath[PATH_MAX+1] = {'\0'};
	int			c;
	int			n;
	int			repeat;
	struct sigaction	nact;
	struct sigaction	oact;

	/* initialize locale environment */

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	/* initialize program name */

	prog_full_name = argv[0];
	prog = set_prog_name(argv[0]);

	/* tell spmi zones interface how to access package output functions */

	z_set_output_functions(echo, echoDebug, progerr);

	askflag = (strcmp(prog, "pkgask") == 0);

	/* set sane umask */

	(void) umask(0022);

	/* tell quit which ckreturn function to call */

	quitSetCkreturnFunc(&ckreturn);

	/* initially no source "device" */

	device = NULL;

	/* reset npkgs (used as pkg remaining count in quit.c) */

	npkgs = 0;

	if (z_running_in_global_zone() && !enable_local_fs()) {
		progerr(ERR_CANNOT_ENABLE_LOCAL_FS);
	}

	pkgserversetmode(DEFAULTMODE);

	/*
	 * ********************************************************************
	 * parse command line options
	 * ********************************************************************
	 */

	while ((c = getopt(argc, argv,
	    "?Aa:b:B:Cc:D:d:GhIMnO:R:r:Ss:tV:vY:z")) != EOF) {
		switch (c) {

		/*
		 * Not a public interface: This disables attribute checking.
		 * It speeds up installation a little bit.
		 */
		case 'A':
			disableAttributes++;
			break;

		/*
		 * Public interface: Define an installation administration
		 * file, admin, to be used in place of the default
		 * administration file.	 The token none overrides the use
		 * of any admin file, and thus forces interaction with the
		 * user. Unless a full path name is given, pkgadd first
		 * looks in the current working directory for the
		 * administration file.	 If the specified administration
		 * file is not in the current working directory, pkgadd
		 * looks in the /var/sadm/install/admin directory for the
		 * administration file.
		 */
		case 'a':
			admnfile = flex_device(optarg, 0);
			break;

		/*
		 * Not a public interface: control block size given to
		 * pkginstall - block size used in read()/write() loop;
		 * default is st_blksize from stat() of source file.
		 */
		case 'B':
			if (optarg[0] == '-') {
				usage();
				quit(1);
			}
			rw_block_size = optarg;
			break;

		/*
		 * Not a public interface:  location where package executables
		 * can be found - default is /usr/sadm/install/bin.
		 */
		case 'b':
			if (optarg[0] == '-') {
				usage();
				quit(1);
			}
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
		 * Not a public interface: This disables checksum tests on
		 * the source files. It speeds up installation a little bit.
		 */
		case 'C':
			disableChecksum++;
			break;

		/*
		 * Not a public interface: This allows designation of a
		 * continuation file. It is the same format as a dryrun file
		 * but it is used to take up where the dryrun left off.
		 */
		case 'c':
			pkgcontsrc = flex_device(optarg, 0);
			break;

		/*
		 * Not a public interface: This allows designation of a
		 * dryrun file. This pkgadd will create dryrun files
		 * in the directory provided.
		 */
		case 'D':
			if (optarg[0] == '-') {
				usage();
				quit(1);
			}
			pkgdrtarg = flex_device(optarg, 0);
			break;

		/*
		 * Public interface: Install or copy a package from
		 * device. device can be a full path name to a directory
		 * or the identifiers for tape, floppy disk, or removable
		 * disk - for example, /var/tmp or /floppy/floppy_name.
		 * It can also be a device alias - for example,
		 * /floppy/floppy0, or a datastream created by pkgtrans.
		 */
		case 'd':
			if (optarg[0] == '-') {
				usage();
				quit(1);
			}
			if (!path_valid(optarg)) {
				progerr(ERR_PATH, optarg);
				quit(1);
				/* NOTREACHED */
			}

			device = flex_device(optarg, 1);
			break;

		/*
		 * Public interface: install package in global zone only.
		 */
		case 'G':
			globalZoneOnly = B_TRUE;
			break;

		/*
		 * Not a public interface: Enable hollow package support. When
		 * specified, for any package that has SUNW_PKG_HOLLOW=true:
		 *  Do not calculate and verify package size against target.
		 *  Do not run any package procedure or class action scripts.
		 *  Do not create any target directories.
		 *  Do not perform any script locking.
		 *  Do not install any components of any package.
		 *  Do not output any status or database update messages.
		 */
		case 'h':
			set_depend_pkginfo_DB(B_TRUE);
			break;

		/*
		 * Not a public interface: Informs scripts that this is
		 * an initial install by setting the environment parameter
		 * PKG_INIT_INSTALL=TRUE for all scripts. They may use it as
		 * they see fit, safe in the knowledge that the target
		 * filesystem is tabula rasa.
		 */
		case 'I':
			init_install++;
			break;

		/*
		 * Public interface: Instruct pkgadd not to use the
		 * $root_path/etc/vfstab file for determining the client's
		 * mount points. This option assumes the mount points are
		 * correct on the server and it behaves consistently with
		 * Solaris 2.5 and earlier releases.
		 */
		case 'M':
			no_map_client = 1;
			break;

		/*
		 * Not a public interface: the -O option allows the behavior
		 * of the package tools to be modified. Recognized options:
		 * -> debug
		 * ---> enable debugging output
		 * -> addzonename
		 * ---> add zone name to appropriate messages
		 * -> nozones
		 * ---> act as though in global zone with no non-global zones
		 * -> enable-hollow-package-support
		 * ---> Enable hollow package support. When specified, for any
		 * ---> package that has SUNW_PKG_HOLLOW=true:
		 * ---> Do not calculate and verify package size against target
		 * ---> Do not run any package procedure or class action scripts
		 * ---> Do not create any target directories
		 * ---> Do not perform any script locking
		 * ---> Do not install any components of any package
		 * ---> Do not output any status or database update messages
		 * -> zonelist="<names...>"
		 * ---> add package to space/colon separated list of zones only
		 */

		case 'O':
			for (p = strtok(optarg, ","); p != (char *)NULL;
			    p = strtok(NULL, ",")) {

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

				if (strcmp(p,
				    "enable-hollow-package-support") == 0) {
					set_depend_pkginfo_DB(B_TRUE);
					continue;
				}

				if (strcmp(p, "addzonename") == 0) {
					quitSetZoneName(z_get_zonename());
					continue;
				}

				if (strcmp(p, "nozones") == 0) {
					noZones = B_TRUE;
					continue;
				}

				if (strncmp(p, "zonelist=", 9) == 0) {
					/*
					 * If colons used as separators,
					 * convert to spaces.
					 */
					q = p + 9;
					while (*q != '\0') {
						if (*q == ':') {
							*q = ' ';
						}
						q++;
					}

					if (z_set_zone_spec(p + 9) == -1)
						quit(1);
					usedZoneList = B_TRUE;
					continue;
				}

				progerr(ERR_INVALID_O_OPTION, p);
				continue;
			}
			break;

		/*
		 * Public interface: installation occurs in
		 * non-interactive mode.  Suppress output of the list of
		 * installed files. The default mode is interactive.
		 */
		case 'n':
			nointeract++;
			(void) echoSetFlag(B_FALSE);
			break;

		/*
		 * Public interface: Define the full path name of a
		 * directory to use as the root_path.  All files,
		 * including package system information files, are
		 * relocated to a directory tree starting in the specified
		 * root_path. The root_path may be specified when
		 * installing to a client from a server (for example,
		 * /export/root/client1).
		 */
		case 'R':
			if (optarg[0] == '-') {
				usage();
				quit(1);
			}
			/* determine the real path specified */

			n = resolvepath(optarg, Rpath, sizeof (Rpath)-1);

			/* use supplied path if not resolvable */

			if (n == -1) {
				(void) strlcpy(Rpath, optarg, sizeof (Rpath));
			} else {
				/* null terminate string */
				Rpath[n] = '\0';
			}

			/* set the alternative root path */

			if (!set_inst_root(Rpath)) {
				progerr(ERR_ROOT_CMD);
				exit(1);
			}
			break;

		/*
		 * Public interface: Identify a file or directory which
		 * contains output from a previous pkgask(1M)
		 * session. This file supplies the interaction responses
		 * that would be requested by the package in interactive
		 * mode. response must be a full pathname.
		 */
		case 'r':
			if (optarg[0] == '-') {
				usage();
				quit(1);
			}
			respfile = flex_device(optarg, 2);
			if (isdir(respfile) == 0)
				respdir = respfile;
			break;

		/*
		 * Not a public interface: suppress copyright notice being
		 * output during installation.
		 */
		case 'S':
			suppressCopyright++;
			break;

		/*
		 * Public interface: Write the package into the directory
		 * spool instead of installing it. The default directory
		 * for spooled packages is /var/sadm/pkg.
		 */
		case 's':
			spoolDir = flex_device(optarg, 1);
			break;

		/*
		 * Not a public interface: disable save spool area creation;
		 * suppress the creation and population of the package save
		 * spool area (var/sadm/pkg/PKG/save/pspool/PKG).
		 */
		case 't':
			disableSaveSpool++;
			break;

		/*
		 * Public interface: Specify an alternative fs_file to map
		 * the client's file systems.  For example, used in
		 * situations where the $root_path/etc/vfstab file is
		 * non-existent or unreliable. Informs the pkginstall
		 * portion to mount up a client filesystem based upon the
		 * supplied vfstab-like file of stable format.
		 */
		case 'V':
			vfstab_file = flex_device(optarg, 2);
			no_map_client = 0;
			break;

		/*
		 * Public interface: Trace all of the scripts that get
		 * executed by pkgadd, located in the pkginst/install
		 * directory. This option is used for debugging the
		 * procedural and non-procedural scripts
		 */
		case 'v':
			pkgverbose++;
			break;

		/*
		 * Public interface: Install packages based on the value
		 * of the CATEGORY parameter stored in the package's
		 * pkginfo(4) file. All packages on the source medium
		 * whose CATEGORY matches one of the specified categories
		 * will be selected for installation or spooling. Install
		 * packages that contain the same CATEGORY as the one
		 * provided on the command line.
		 */
		case 'Y':
			if (optarg[0] == '-') {
				usage();
				quit(1);
			}
			catg_arg = strdup(optarg);

			if ((category = get_categories(catg_arg)) == NULL) {
				progerr(ERR_CAT_INV, catg_arg);
				exit(1);
			} else if (is_not_valid_length(category)) {
				progerr(ERR_CAT_LNGTH);
				exit(1);
			}
			break;

		/*
		 * Not a public interface: perform fresh install from
		 * package save spool area. When set, the package contents
		 * are installed from the package spool save area instead
		 * of from the package root area, so that the original
		 * source packages are not required to install the
		 * package. If the -h option is also specified and the
		 * package is hollow, then this option is ignored. When -z
		 * is specified:
		 *  - Editable files are installed from the package instance
		 *    save area.
		 *  - Volatile files are installed from the package instance
		 *    save area.
		 *  - Executable and data files are installed from the final
		 *    installed location as specified in the pkgmap file.
		 *  - Installation scripts are run from the package spool
		 *    save area.
		 */
		case 'z':
			saveSpoolInstall++;
			break;

		/*
		 * unrecognized option
		 */

		default:
			usage();
			return (1);
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

	/*
	 * Later, it may be decided to pursue this ability to continue to an
	 * actual installation based only on the dryrun data. At this time,
	 * it is too risky.
	 */

	if (pkgcontsrc && !pkgdrtarg) {
		progerr(ERR_NO_LIVE_MODE);
		usage();
		return (1);
	}

	/* ignore -G option if not used in the global zone */

	if (!z_running_in_global_zone()) {
		globalZoneOnly = B_FALSE;
	}

	/* if zonelist used, must be in global zone */

	if (usedZoneList && !z_running_in_global_zone()) {
		progerr(ERR_Z_USED_IN_NONGLOBAL_ZONE);
		return (1);
	}

	/* -G and zonelist cannot be used together */

	if (globalZoneOnly && usedZoneList) {
		progerr(ERR_GZ_USED_TOGETHER);
		usage();
		return (1);
	}

	/* -s cannot be used with either -G or zonelist */

	if (spoolDir != NULL) {
		if (globalZoneOnly) {
			progerr(ERR_SPOOLDIR_USED_WITH_G);
			usage();
			return (1);
		}
		if (usedZoneList) {
			progerr(ERR_SPOOLDIR_USED_WITH_Z);
			usage();
			return (1);
		}
		if (strcmp(spoolDir, "/var/sadm/pkg") == 0) {
			progerr(ERR_SPOOLDIR_CANNOT_BE_SYS, "/var/sadm/pkg");
			usage();
			return (1);
		}
	}

	/* pkgask does not support the same options as pkgadd */

	if (askflag && spoolDir) {
		progerr(ERR_PKGASK_AND_SPOOLDIR);
		usage();
		return (1);
	}

	if (askflag && nointeract) {
		progerr(ERR_PKGASK_AND_NOINTERACT);
		usage();
		return (1);
	}

	/* cannot use response file/not-interactive and spool-to directory */

	if (spoolDir && nointeract) {
		progerr(ERR_SPOOLDIR_AND_NOINTERACT);
		usage();
		return (1);
	}

	if (spoolDir && respfile) {
		progerr(ERR_SPOOLDIR_AND_RESPFILE);
		usage();
		return (1);
	}

	if (usedZoneList) {
		/* Verify supplied zone list valid for the target */
		if (z_verify_zone_spec() == -1)
			return (1);

		/* -z zonelist=global is logically the same as -G */
		if (z_global_only() && z_running_in_global_zone())
			globalZoneOnly = B_TRUE;
	}

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

	/*
	 * This function is in the libadm library; it sets:
	 * -> get_PKGLOC() = <install_root>/var/sadm/pkg
	 * -> get_PKGADM() = <install_root>/var/sadm/install
	 * -> pkgdir = <install_root>/var/sadm/pkg
	 * -> pkg_install_root = <install_root>
	 * This controls operations of libadm functions such as:
	 * -> pkginfofind, pkginfopen, fpkgparam, pkgparam, get_PKGLOC,
	 * -> get_PKGADM, get_install_root
	 */

	set_PKGpaths(get_inst_root());
	echoDebug(DBG_PKGADD_PKGPATHS,
	    get_PKGLOC() ? get_PKGLOC() : "",
	    get_PKGADM() ? get_PKGADM() : "");

	/*
	 * This function is in the libinst library; it reads the specified
	 * admin(4) file and, using fpkgparam(), sets the global "adm" structure
	 * values to match what is in the specified admin file.
	 */

	echoDebug(DBG_PKGADD_ADMINFILE, admnfile ? admnfile : "");
	setadminFile(admnfile);

	/*
	 * if running in the global zone, and non-global zones exist, then
	 * enable hollow package support so that any packages that are marked
	 * SUNW_PKG_HOLLOW=true will be correctly installed in non-global zones
	 * when added directly in the global zone by the global zone admin.
	 */

	if (is_depend_pkginfo_DB()) {
		echoDebug(DBG_PKGADD_HOLLOW_ENABLED);
	} else if ((z_running_in_global_zone() == B_TRUE) &&
	    (z_non_global_zones_exist() == B_TRUE)) {
		echoDebug(DBG_PKGADD_ENABLING_HOLLOW);
		set_depend_pkginfo_DB(B_TRUE);
	}

	/* if no device, get and validate default device */

	if (device == NULL) {
		device = devattr("spool", "pathname");
		if (device == NULL) {
			progerr(ERR_NODEVICE);
			quit(1);
			/* NOTREACHED */
		}
	}

	/* must be root if not directing results to spool directory */

	if ((getuid() != 0) && (spoolDir == NULL)) {
		progerr(ERR_NOT_ROOT, prog);
		exit(1);
	}

	/*
	 * process response file argument
	 */

	if (respfile) {
		echoDebug(DBG_PKGADD_RESPFILE,
		    respfile, respdir ? respdir : "");

		if (respfile[0] != '/') {
			progerr(ERR_RSP_FILE_NOTFULLPATH, respfile);
			quit(1);
			/* NOTREACHED */
		}
		if (respdir == NULL) {
			if (askflag) {
				if (access(respfile, F_OK) == 0) {
					progerr(ERR_NORESP, respfile);
					quit(1);
					/* NOTREACHED */
				}
			} else if (access(respfile, F_OK) != 0) {
				progerr(ERR_ACCRESP, respfile);
				quit(1);
				/* NOTREACHED */
			}
		}
	} else if (askflag) {
		progerr(ERR_RSP_FILE_NOT_GIVEN);
		usage();
		quit(1);
		/* NOTREACHED */
	}

	/* establish temporary directory to use */

	if ((tmpdir = getenv("TMPDIR")) == NULL) {
		/* use default - no override specified */
		tmpdir = P_tmpdir;
	}

	echoDebug(DBG_PKGADD_TMPDIR, tmpdir);

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

	/*
	 * See if the user wants the package name length restricted.
	 */

	abiPtr = getenv("PKG_ABI_NAMELENGTH");
	if (abiPtr && strncasecmp(abiPtr, "TRUE", 4) == 0) {
		ABI_namelength = 1;
	}

	/*
	 * validate the package source device - return pkgdev info that
	 * describes the package source device.
	 */

	if (devtype(device, &pkgdev)) {
		progerr(ERR_BAD_DEVICE, device);
		quit(1);
		/* NOTREACHED */
	}

	/*
	 * If writing the packages into a spool directory instead of
	 * installing the packages, open the package datastream and
	 * invoke pkgtrans to perform the conversion and exit.
	 */

	if (spoolDir != (char *)NULL) {
		boolean_t	b;
		int		n;

		echoDebug(DBG_INSTALLING_TO_SPOOL, spoolDir);

		b = open_package_datastream(argc, argv, spoolDir, device,
		    &repeat, &ids_name, tmpdir,
		    &pkgdev, optind);

		quitSetIdsName(ids_name);

		if (b != B_TRUE) {
			progerr(ERR_CANNOT_OPEN_PKG_STREAM, PSTR(device));
			quit(1);
		}

		n = pkgtrans(device, spoolDir, &argv[optind], 0);
		quit(n);
		/* NOTREACHED */
	}

	/*
	 * error if there are packages on the command line and a category
	 * was specified
	 */

	if ((optind < argc) && (catg_arg != NULL)) {
		progerr(ERR_PKGS_AND_CAT_PKGADD);
		usage();
		quit(1);
		/* NOTREACHED */
	}

	/*
	 * ********************************************************************
	 * main package processing "loop"
	 * ********************************************************************
	 */

	ids_name = NULL;
	quitSetIdsName(ids_name);

	for (;;) {
		boolean_t	b;
		char		**pkglist;	/* points to array of pkgs */

		/*
		 * open next package data stream
		 */

		b = open_package_datastream(argc, argv, spoolDir, device,
		    &repeat, &ids_name, tmpdir,
		    &pkgdev, optind);

		quitSetIdsName(ids_name);

		if (b == B_FALSE) {
			echoDebug(ERR_CANNOT_OPEN_PKG_STREAM, PSTR(device));
			continue;
		}

		/*
		 * package source data stream open - get the package list
		 */

		b = get_package_list(&pkglist, argv, catg_arg, category,
		    ids_name, &repeat);

		if (b == B_FALSE) {
			echoDebug(DBG_CANNOT_GET_PKGLIST);

			progerr(ERR_NOPKGS, pkgdev.dirname);
			quit(1);
			/* NOTREACHED */
		}

		/*
		 * count the number of packages to install
		 * NOTE: npkgs is a global variable that is referenced by quit.c
		 * when error messages are generated - it is referenced directly
		 * by the other functions called below...
		 */

		for (npkgs = 0; pkglist[npkgs] != (char *)NULL; /* void */) {
			echoDebug(DBG_PKG_SELECTED, npkgs, pkglist[npkgs]);
			npkgs++;
		}

		/* output number of packages to be added */

		echoDebug(DBG_NUM_PKGS_TO_ADD, npkgs);

		/*
		 * if pkgask and response container is a file (not a directory),
		 * and there is more than one package to install, then it is an
		 * error - too many packages to install when response container
		 * is a file.
		 */

		if ((askflag != 0) && (respdir == (char *)NULL) &&
		    (npkgs > 1)) {
			progerr(ERR_TOO_MANY_PKGS);
			quit(1);
			/* NOTREACHED */
		}

		/*
		 * package list generated - add packages
		 */

		b = add_packages(pkglist, ids_name, repeat,
		    altBinDir, device, noZones);

		/*
		 * close open input data stream (source package) if left open.
		 */

		if (ids_name) {
			echoDebug(DBG_CLOSING_STREAM, ids_name,
			    PSTR(pkgdev.dirname));
			(void) ds_close(1);
			rrmdir(pkgdev.dirname);
			ids_name = NULL;
			quitSetIdsName(ids_name);
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
	}

	/* NOTREACHED */
}

/*
 * *****************************************************************************
 * static internal (private) functions
 * *****************************************************************************
 */

/*
 * Name:	pkgZoneCheckInstall
 * Description:	Invoke pkginstall in a specified zone to perform a preinstall
 *		check of the a single package in the specified zone
 * Arguments:	a_zoneName - pointer to string representing the name of the
 *			zone to check install the package in.
 *		a_zoneState - current state of the zone; must be mounted or
 *			running.
 *		a_idsName - pointer to string representing the data stream
 *			device (input data stream) containing the package to
 *			be check installed.
 *		a_altBinDir - pointer to string representing an alternative
 *			binary location directory to pass to pkginstall.
 *			If this is == NULL no alternative binary location is
 *			passed to pkginstall.
 *		a_adminFile - pointer to string representing the admin
 *			file to pass to pkginstall when installing the package.
 *			If this is == NULL no admin file is given to pkginstall.
 *		a_stdoutPath - pointer to string representing the local path
 *			into which all output written by pkginstall to stdout
 *			is stored.
 *			If this is == NULL stdout is redirected to /dev/null
 *		a_tmpzn - B_TRUE when this zone is booted by the package
 *			command or B_FALSE if it was running before.
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
pkgZoneCheckInstall(char *a_zoneName, zone_state_t a_zoneState,
    char *a_idsName, char *a_altBinDir, char *a_adminFile,
    char *a_stdoutPath, boolean_t a_tmpzn)
{
	char	*arg[MAXARGS];
	char	*p;
	char	adminfd_path[PATH_MAX];
	char	path[PATH_MAX];
	char	pkgstreamfd_path[PATH_MAX];
	int	fds[MAX_FDS];
	int	maxfds;
	int	n;
	int	nargs;

	/* entry assertions */

	assert(a_zoneName != (char *)NULL);
	assert(*a_zoneName != '\0');

	/* entry debugging info */

	echoDebug(DBG_PKGZONECHECKINSTALL_ENTRY);
	echoDebug(DBG_PKGZONECHECKINSTALL_ARGS, a_zoneName, PSTR(pkginst),
	    PSTR(pkgdev.dirname), PSTR(pkgdev.mount), PSTR(pkgdev.bdevice),
	    a_zoneState == ZONE_STATE_MOUNTED ? "/a" : "/",
	    PSTR(a_idsName), PSTR(a_adminFile), PSTR(a_stdoutPath));

	/* generate full path to 'phatinstall' to run in zone */

	(void) snprintf(path, sizeof (path), "%s/pkginstall",
	    "/usr/sadm/install/bin");

	/* start at first file descriptor */

	maxfds = 0;

	/*
	 * generate argument list for call to pkginstall
	 */

	/* start at argument 0 */

	nargs = 0;

	/* first argument is always: full path to executable */

	arg[nargs++] = path;

	/*
	 * second argument is always: pass -O debug to pkginstall: debug mode
	 */
	if (debugFlag == B_TRUE) {
		arg[nargs++] = "-O";
		arg[nargs++] = "debug";
	}

	/* pkgadd -G: pass -G to pkginstall */

	if (globalZoneOnly == B_TRUE) {
		arg[nargs++] = "-G";
	}

	/* pkgadd -b dir: pass -b to pkginstall */

	if (a_altBinDir != (char *)NULL) {
		arg[nargs++] = "-b";
		arg[nargs++] = a_altBinDir;
	}

	/* pkgadd -C: pass -C to pkginstall: disable checksum */

	if (disableChecksum) {
		arg[nargs++] = "-C";
	}

	/* pkgadd -A: pass -A to pkginstall: disable attribute checking */

	if (disableAttributes) {
		arg[nargs++] = "-A";
	}

	/*
	 * NONABI_SCRIPTS defined: pass -o to pkginstall; refers to a
	 * pkg requiring operator interaction during a procedure script
	 * (common before on1093)
	 */

	if (old_pkg) {
		arg[nargs++] = "-o";
	}

	/*
	 * PKG_NONABI_SYMLINKS defined: pass -y to pkginstall; process
	 * symlinks consistent with old behavior
	 */

	if (old_symlinks) {
		arg[nargs++] = "-y";
	}

	/*
	 * PKG_ABI_NAMELENGTH defined: pass -e to pkginstall; causes
	 * package name length to be restricted
	 */

	if (ABI_namelength) {
		arg[nargs++] = "-e";
	}

	/* pkgadd -S: pass -S to pkginstall: suppress copyright notices */

	arg[nargs++] = "-S";

	/* pkgadd -M: pass -M to pkginstall: dont mount client file systems */

	arg[nargs++] = "-M";

	/* pkgadd -v: pass -v to pkginstall: never trace scripts */

	/* if running pkgask, pass -i to pkginstall: running pkgask */

	if (askflag) {
		return (0);
	}

	/* pass "-O enable-hollow-package-support" */

	if (is_depend_pkginfo_DB()) {
		arg[nargs++] = "-O";
		arg[nargs++] = "enable-hollow-package-support";
	}

	/* check is always in non-interactive mode */

	arg[nargs++] = "-n";

	/* pkgadd -a admin: pass -a admin to pkginstall in zone: admin file */

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

	/* pkgadd -R root: pass -R /a to pkginstall when zone is mounted */

	if (a_zoneState == ZONE_STATE_MOUNTED) {
		arg[nargs++] = "-R";
		arg[nargs++] = "/a";
	}

	/* pass -N to pkginstall: program name to report */

	arg[nargs++] = "-N";
	arg[nargs++] = get_prog_name();

	/* pass "-O preinstallcheck" */

	arg[nargs++] = "-O";
	arg[nargs++] = "preinstallcheck";

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

	/* Add the pkgserv options */
	arg[nargs++] = "-O";
	arg[nargs++] = pkgmodeargument(a_tmpzn ? RUN_ONCE : pkgservergetmode());

	/* add in the package stream file */

	if (a_idsName != NULL) {
		int fd;
		fd = openLocal(a_idsName, O_RDONLY, tmpdir);
		if (fd < 0) {
			progerr(ERR_STREAM_UNAVAILABLE, a_idsName,
			    pkginst, strerror(errno));
			quit(1);
		}
		(void) snprintf(pkgstreamfd_path, sizeof (pkgstreamfd_path),
		    "/proc/self/fd/%d", fd);
		fds[maxfds++] = fd;
		arg[nargs++] = pkgstreamfd_path;
	} else {
		progerr(ERR_PKGZONEINSTALL_NO_STREAM);
		quit(1);
	}

	/* add package instance name */

	arg[nargs++] = pkginst;

	/* terminate the argument list */

	arg[nargs++] = NULL;

	/*
	 * run the appropriate pkginstall command in the specified zone
	 */

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

	/* return results of pkginstall in zone execution */

	return (n);
}

/*
 * Name:	pkgZoneInstall
 * Description:	Invoke pkginstall in a specified zone to perform an install
 *		of a single package in the specified zone
 * Arguments:	a_zoneName - pointer to string representing the name of the
 *			zone to install the package in.
 *		a_zoneState - current state of the zone; must be mounted or
 *			running.
 *		a_idsName - pointer to string representing the data stream
 *			device (input data stream) containing the package to
 *			be installed.
 *		a_altBinDir - pointer to string representing an alternative
 *			binary location directory to pass to pkginstall.
 *			If this is == NULL no alternative binary location is
 *			passed to pkginstall.
 *		a_adminFile - pointer to string representing the admin
 *			file to pass to pkginstall when installing the package.
 *			If this is == NULL no admin file is given to pkginstall.
 *		a_stdoutPath - pointer to string representing the local path
 *			into which all output written by pkginstall to stdout
 *			is stored.
 *			If this is == NULL stdout is redirected to /dev/null
 *		a_tmpzn - B_TRUE when this zone is booted by the package
 *			command or B_FALSE if it was running before.
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
pkgZoneInstall(char *a_zoneName, zone_state_t a_zoneState, char *a_idsName,
    char *a_altBinDir, char *a_adminFile, boolean_t a_tmpzn)
{
	char	*arg[MAXARGS];
	char	*p;
	char	adminfd_path[PATH_MAX];
	char	path[PATH_MAX];
	char	pkgstreamfd_path[PATH_MAX];
	char	respfilefd_path[PATH_MAX];
	int	fds[MAX_FDS];
	int	maxfds;
	int	n;
	int	nargs;

	/* entry assertions */

	assert(a_zoneName != (char *)NULL);
	assert(*a_zoneName != '\0');

	/* entry debugging info */

	echoDebug(DBG_PKGZONEINSTALL_ENTRY);
	echoDebug(DBG_PKGZONEINSTALL_ARGS, a_zoneName, PSTR(pkginst),
	    PSTR(pkgdev.dirname), PSTR(pkgdev.mount), PSTR(pkgdev.bdevice),
	    a_zoneState == ZONE_STATE_MOUNTED ? "/a" : "", PSTR(a_idsName),
	    a_adminFile);

	/* generate path to pkginstall */

	(void) snprintf(path, sizeof (path), "%s/pkginstall", PKGBIN);

	/* start at first file descriptor */

	maxfds = 0;

	/*
	 * generate argument list for call to pkginstall
	 */

	/* start at argument 0 */

	nargs = 0;

	/* first argument is path to executable */

	arg[nargs++] = path;

	/*
	 * second argument is always: pass -O debug to pkginstall: debug mode
	 */
	if (debugFlag == B_TRUE) {
		arg[nargs++] = "-O";
		arg[nargs++] = "debug";
	}

	/* pkgadd -G: pass -G to pkginstall */

	if (globalZoneOnly == B_TRUE) {
		arg[nargs++] = "-G";
	}

	/* pkgadd -b dir: pass -b to pkginstall in zone */

	if (a_altBinDir != (char *)NULL) {
		arg[nargs++] = "-b";
		arg[nargs++] = a_altBinDir;
	}

	/* pkgadd -B blocksize: pass -B to pkginstall in zone */

	if (rw_block_size != NULL) {
		arg[nargs++] = "-B";
		arg[nargs++] = rw_block_size;
	}

	/* pkgadd -C: pass -C to pkgadd in zone: disable checksum */

	if (disableChecksum) {
		arg[nargs++] = "-C";
	}

	/* pkgadd -A: pass -A to pkgadd in zone: disable attribute checking */

	if (disableAttributes) {
		arg[nargs++] = "-A";
	}

	/* pkgadd -S: pass -S to pkgadd in zone: suppress copyright notices */

	arg[nargs++] = "-S";

	/* pkgadd -I: pass -I to pkgadd in zone: initial install */

	if (init_install) {
		arg[nargs++] = "-I";
	}

	/* pkgadd -M: pass -M to pkgadd in zone: dont mount client file sys */

	arg[nargs++] = "-M";

	/* pkgadd -v: pass -v to pkgadd in zone: trace scripts */

	if (pkgverbose) {
		arg[nargs++] = "-v";
	}

	/* pkgadd -z: pass -z to pkgadd in zone fresh inst from pkg save area */

	if (saveSpoolInstall) {
		arg[nargs++] = "-z";
	}

	/* pass "-O enable-hollow-package-support" */

	if (is_depend_pkginfo_DB()) {
		arg[nargs++] = "-O";
		arg[nargs++] = "enable-hollow-package-support";
	}

	/* pkgadd -t pass -t to pkgadd in zone disable save spool area create */

	if (disableSaveSpool) {
		arg[nargs++] = "-t";
	}

	/* if running pkgask, pass -i to pkgadd in zone: running pkgask */

	if (askflag) {
		echo(MSG_BYPASSING_ZONE, a_zoneName);
		return (0);
	}

	/*
	 * pkgadd -n (not pkgask): pass -n to pkginstall: noninteractive mode
	 */
	if (nointeract && !askflag) {
		arg[nargs++] = "-n";
	}

	/* pkgadd -a admin: pass -a admin to pkginstall in zone: admin file */

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

	/* pkgadd -R root: pass -R /a to pkginstall when zone is mounted */
	if (a_zoneState == ZONE_STATE_MOUNTED) {
		arg[nargs++] = "-R";
		arg[nargs++] = "/a";
	}

	/*
	 * pkgadd -D arg: pass -D dryrun to pkginstall in zone: dryrun
	 * mode/file
	 */
	if (pkgdrtarg) {
		arg[nargs++] = "-D";
		arg[nargs++] = pkgdrtarg;
	}

	/*
	 * pkgadd -c cont: pass -c cont to pkginstall in zone: continuation
	 * file
	 */
	if (pkgcontsrc) {
		arg[nargs++] = "-c";
		arg[nargs++] = pkgcontsrc;
	}

	/* pkgadd -r resp: pass -r resp to pkginstall in zone: response file */

	if (respfile) {
		int fd;
		fd = openLocal(respfile, O_RDONLY, tmpdir);
		if (fd < 0) {
			progerr(ERR_CANNOT_COPY_LOCAL, a_adminFile,
			    errno, strerror(errno));
			return (1);
		}
		(void) snprintf(respfilefd_path,
		    sizeof (respfilefd_path),
		    "/proc/self/fd/%d", fd);
		fds[maxfds++] = fd;
		arg[nargs++] = "-r";
		arg[nargs++] = respfilefd_path;
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

	/* Add the pkgserv options */
	arg[nargs++] = "-O";
	arg[nargs++] = pkgmodeargument(a_tmpzn ? RUN_ONCE : pkgservergetmode());

	/* add in the package stream file */

	if (a_idsName != NULL) {
		int fd;
		fd = openLocal(a_idsName, O_RDONLY, tmpdir);
		if (fd < 0) {
			progerr(ERR_STREAM_UNAVAILABLE, a_idsName,
			    pkginst, strerror(errno));
			quit(1);
		}
		(void) snprintf(pkgstreamfd_path, sizeof (pkgstreamfd_path),
		    "/proc/self/fd/%d", fd);
		fds[maxfds++] = fd;
		arg[nargs++] = pkgstreamfd_path;
	} else {
		progerr(ERR_PKGZONEINSTALL_NO_STREAM);
		quit(1);
	}

	/* add package instance name */

	arg[nargs++] = pkginst;

	/* terminate the argument list */

	arg[nargs++] = NULL;

	/*
	 * run the appropriate pkginstall command in the specified zone
	 */

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

	echoDebug(DBG_ZONE_EXEC_EXIT, a_zoneName, arg[0], n, "");

	/*
	 * close any files that were opened for use by the
	 * /proc/self/fd interface so they could be passed to programs
	 * via the z_zone_exec() interface
	 */

	for (; maxfds > 0; maxfds--) {
		(void) close(fds[maxfds-1]);
	}

	/* return results of pkginstall in zone execution */

	return (n);
}

/*
 * Name:	pkgInstall
 * Description:	Invoke pkginstall in the current zone to perform an install
 *		of a single package to the current zone or standalone system
 * Arguments:	a_altRoot - pointer to string representing the alternative
 *			root to use for the install
 *		a_idsName - pointer to string representing the data stream
 *			device (input data stream) containing the package to
 *			be installed.
 *		a_pkgDir - pointer to string representing the path to the
 *			directory containing the package
 *		a_altBinDir - pointer to string representing location of the
 *			pkginstall executable to run. If not NULL, then pass
 *			the path specified to the -b option to pkginstall.
 * Returns:	int	(see ckreturn() function for details)
 *		0 - success
 *		1 - package operation failed (fatal error)
 *		2 - non-fatal error (warning)
 *		3 - user selected quit (operation interrupted)
 *		4 - admin settings prevented operation
 *		5 - interaction required and -n (non-interactive) specified
 *		"10" will be added to indicate "immediate reboot required"
 *		"20" will be added to indicate "reboot after install required"
 * NOTE:	Both a_idsName and a_pkgDir are used to determine where the
 *		package to be installed is located. If a_idsName is != NULL
 *		then it must be the path to a device containing a package
 *		stream that contains the package to be installed. If a_idsName
 *		is == NULL then a_pkgDir must contain a full path to a directory
 *		that contains the package to be installed.
 */

static int
pkgInstall(char *a_altRoot, char *a_idsName, char *a_pkgDir, char *a_altBinDir)
{
	char	*arg[MAXARGS];
	char	*p;
	char	path[PATH_MAX];
	char	buffer[256];
	int	n, nargs;

	/* entry debugging info */

	echoDebug(DBG_PKGINSTALL_ENTRY);
	echoDebug(DBG_PKGINSTALL_ARGS, PSTR(pkginst), PSTR(pkgdev.dirname),
	    PSTR(pkgdev.mount), PSTR(pkgdev.bdevice), PSTR(a_altRoot),
	    PSTR(a_idsName), PSTR(a_pkgDir));

	/* generate full path to 'pkginstall' to run in zone */

	(void) snprintf(path, sizeof (path), "%s/pkginstall",
	    a_altBinDir == (char *)NULL ? PKGBIN : a_altBinDir);
	/*
	 * generate argument list for call to pkginstall
	 */

	/* start at argument 0 */

	nargs = 0;

	/* first argument is path to executable */

	arg[nargs++] = path;

	/*
	 * second argument is always: pass -O debug to pkginstall: debug mode
	 */
	if (debugFlag == B_TRUE) {
		arg[nargs++] = "-O";
		arg[nargs++] = "debug";
	}

	arg[nargs++] = "-O";
	arg[nargs++] = pkgmodeargument(pkgservergetmode());

	/*
	 * pkgadd -G: pass -G to pkginstall if:
	 *  - the -G option is specified on the pkgadd command line
	 *  - this package is marked 'this zone only':
	 *  -- package has SUNW_PKG_THISZONE=true, or
	 *  -- package has a request script
	 * Setting -G for pkginstall causes pkginstall to install the package
	 * in the target zone. If running in the global zone, will install the
	 * package and mark the package as installed "in the global zone only".
	 * If running in a non-global zone, will just install the package.
	 */

	if (globalZoneOnly == B_TRUE) {
		arg[nargs++] = "-G";
	} else if (pkgPackageIsThisZone(pkginst) == B_TRUE) {
		arg[nargs++] = "-G";
	}

	/* pkgadd -b dir: pass -b to pkginstall */

	if (a_altBinDir != (char *)NULL) {
		arg[nargs++] = "-b";
		arg[nargs++] = a_altBinDir;
	}

	/* pkgadd -B blocksize: pass -B to pkginstall */

	if (rw_block_size != NULL) {
		arg[nargs++] = "-B";
		arg[nargs++] = rw_block_size;
	}

	/* pkgadd -C: pass -C to pkginstall: disable checksum */

	if (disableChecksum) {
		arg[nargs++] = "-C";
	}

	/* pkgadd -A: pass -A to pkginstall: disable attribute checking */

	if (disableAttributes) {
		arg[nargs++] = "-A";
	}

	/*
	 * NONABI_SCRIPTS defined: pass -o to pkginstall; refers to a
	 * pkg requiring operator interaction during a procedure script
	 * (common before on1093)
	 */

	if (old_pkg) {
		arg[nargs++] = "-o";
	}

	/*
	 * PKG_NONABI_SYMLINKS defined: pass -y to pkginstall; process
	 * symlinks consistent with old behavior
	 */

	if (old_symlinks) {
		arg[nargs++] = "-y";
	}

	/*
	 * PKG_ABI_NAMELENGTH defined: pass -e to pkginstall; causes
	 * package name length to be restricted
	 */

	if (ABI_namelength) {
		arg[nargs++] = "-e";
	}

	/* pkgadd -S: pass -S to pkginstall: suppress copyright notices */

	if (suppressCopyright) {
		arg[nargs++] = "-S";
	}

	/* pkgadd -I: pass -I to pkginstall: initial install being performed */

	if (init_install) {
		arg[nargs++] = "-I";
	}

	/* pkgadd -M: pass -M to pkginstall: dont mount client file systems */

	if (no_map_client) {
		arg[nargs++] = "-M";
	}

	/* pkgadd -v: pass -v to pkginstall: trace scripts */

	if (pkgverbose) {
		arg[nargs++] = "-v";
	}

	/* pkgadd -z: pass -z to pkginstall: fresh install from pkg save area */

	if (saveSpoolInstall) {
		arg[nargs++] = "-z";
	}

	/*
	 * if running in a non-global zone and the 'hollow' attribute is
	 * passed in, then pass -h to pkginstall so that it knows how to
	 * handle hollow packages for this local zone.
	 */

	if (!z_running_in_global_zone() && is_depend_pkginfo_DB()) {
		arg[nargs++] = "-h";
	}

	/* pkgadd -t: pass -t to pkginstall: disable save spool area creation */

	if (disableSaveSpool) {
		arg[nargs++] = "-t";
	}

	/* if running pkgask, pass -i to pkginstall: running pkgask */

	if (askflag) {
		arg[nargs++] = "-i";
	}

	/* pkgadd -n (not pkgask): pass -n to pkginstall: noninteractive mode */

	if (nointeract && !askflag) {
		arg[nargs++] = "-n";
	}

	/* pkgadd -a admin: pass -a admin to pkginstall: admin file */

	if (admnfile) {
		arg[nargs++] = "-a";
		arg[nargs++] = admnfile;
	}

	/* pkgadd -D dryrun: pass -D dryrun to pkginstall: dryrun mode/file */

	if (pkgdrtarg) {
		arg[nargs++] = "-D";
		arg[nargs++] = pkgdrtarg;
	}

	/* pkgadd -c cont: pass -c cont to pkginstall: continuation file */

	if (pkgcontsrc) {
		arg[nargs++] = "-c";
		arg[nargs++] = pkgcontsrc;
	}

	/* pkgadd -V vfstab: pass -V vfstab to pkginstall: alternate vfstab */

	if (vfstab_file) {
		arg[nargs++] = "-V";
		arg[nargs++] = vfstab_file;
	}

	/* pkgadd -r resp: pass -r resp to pkginstall: response file */

	if (respfile) {
		arg[nargs++] = "-r";
		arg[nargs++] = respfile;
	}

	/* pkgadd -R root: pass -R root to pkginstall: alternative root */

	if (a_altRoot && *a_altRoot) {
		arg[nargs++] = "-R";
		arg[nargs++] = a_altRoot;
	}

	/*
	 * If input data stream is available,
	 * - add: -d ids_name -p number_of_parts
	 * else,
	 * - add: -d device -m mount [-f type]
	 */

	if (a_idsName != NULL) {
		arg[nargs++] = "-d";
		arg[nargs++] = a_idsName;
		arg[nargs++] = "-p";
		ds_close(1);
		ds_putinfo(buffer, sizeof (buffer));
		arg[nargs++] = buffer;
	} else if (pkgdev.mount != NULL) {
		arg[nargs++] = "-d";
		arg[nargs++] = pkgdev.bdevice;
		arg[nargs++] = "-m";
		arg[nargs++] = pkgdev.mount;
		if (pkgdev.fstyp != NULL) {
			arg[nargs++] = "-f";
			arg[nargs++] = pkgdev.fstyp;
		}
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

	/* pass -N to pkginstall: program name to report */

	arg[nargs++] = "-N";
	arg[nargs++] = get_prog_name();

	/* add package directory name */

	arg[nargs++] = a_pkgDir;

	/* add package instance name */

	arg[nargs++] = pkginst;

	/* terminate the argument list */

	arg[nargs++] = NULL;

	/*
	 * run the appropriate pkginstall command in the specified zone
	 */

	if (debugFlag == B_TRUE) {
		echoDebug(DBG_ZONE_EXEC_ENTER, "global", arg[0]);
		for (n = 0; arg[n]; n++) {
			echoDebug(DBG_ARG, n, arg[n]);
		}
	}

	/* execute pkginstall command */

	n = pkgexecv(NULL, NULL, NULL, NULL, arg);

	/* return results of pkginstall execution */

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
	needconsult = 0;	/* essential ask admin now (1,2,3,5) */
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

	echoDebug(DBG_PKGADD_CKRETURN, retcode, PSTR(pkginst));

	/* reset needconsult so it only reflects this call to ckreturn */
	needconsult = 0;

	switch (retcode) {
	case  0:	/* successful */
	case 10:
	case 20:
		break; /* empty case */

	case  1:	/* package operation failed (fatal error) */
	case 11:
	case 21:
		failflag++;
		interrupted++;
		needconsult++;
		break;

	case  2:	/* non-fatal error (warning) */
	case 12:
	case 22:
		warnflag++;
		interrupted++;
		needconsult++;
		break;

	case  3:	/* user selected quit; operation interrupted */
	case 13:
	case 23:
		intrflag++;
		interrupted++;
		needconsult++;
		break;

	case  4:	/* admin settings prevented operation */
	case 14:
	case 24:
		admnflag++;
		interrupted++;
		break;

	case  5:	/* administration: interaction req (no -n) */
	case 15:
	case 25:
		nullflag++;
		interrupted++;
		needconsult++;
		break;

	default:
		failflag++;
		interrupted++;
		needconsult++;
		return;
	}

	if (retcode >= 20) {
		ireboot++;
	} else if (retcode >= 10) {
		doreboot++;
	}
}

static void
usage(void)
{
	char *prog = get_prog_name();

	if (askflag) {
		(void) fprintf(stderr, ERR_USAGE_PKGASK, prog);
	} else if (z_running_in_global_zone() == B_FALSE) {
		(void) fprintf(stderr, ERR_USAGE_PKGADD_NONGLOBALZONE,
		    prog, prog);
	} else {
		(void) fprintf(stderr, ERR_USAGE_PKGADD_GLOBALZONE,
		    prog, prog);
	}
}

/*
 * Name:	check_applicability
 * Description:	determine if a package is installable in this zone; that is,
 *		does the scope of install conflict with existing installation
 *		or can the package be installed
 * Arguments:	a_packageDir - [RO, *RO] - (char *)
 *			Pointer to string representing the directory where the
 *			package is located
 *		a_pkgInst - [RO, *RO] - (char *)
 *			Pointer to string representing the name of the package
 *			to check
 *		a_rootPath - [RO, *RO] - (char *)
 *			Pointer to string representing path to the root of the
 *			file system where the package is to be installed - this
 *			is usually the same as the "-R" argument to pkgadd
 *		a_flags - [RO, *RO] - (CAF_T)
 *			Flags set by the caller to indicate the conditions
 *			under which the package is to be installed:
 *				CAF_IN_GLOBAL_ZONE - in global zone
 *				CAF_SCOPE_GLOBAL - -G specified
 * Returns:	boolean_t
 *			B_TRUE - the package can be installed
 *			B_FALSE - the package can not be installed
 */

static boolean_t
check_applicability(char *a_packageDir, char *a_pkgInst, char *a_rootPath,
    CAF_T a_flags)
{
	FILE		*pkginfoFP;
	FILE		*pkgmapFP;
	boolean_t	all_zones;	/* pkg is "all zones" only */
	boolean_t	in_gz_only;	/* pkg installed in global zone only */
	boolean_t	is_hollow;	/* pkg is "hollow" */
	boolean_t	pkg_installed;	/* pkg is installed */
	boolean_t	this_zone;	/* pkg is "this zone" only */
	boolean_t	reqfile_found = B_FALSE;
	char		instPkg[PKGSIZ+1];	/* installed pkg instance nam */
	char		instPkgPath[PATH_MAX];	/* installed pkg toplevel dir */
	char		pkginfoPath[PATH_MAX];	/* pkg 2 install pkginfo file */
	char		pkgmapPath[PATH_MAX];	/* pkg 2 install pkgmap file */
	char		pkgpath[PATH_MAX];	/* pkg 2 install toplevel dir */
	int		len;
	char		line[LINE_MAX];

	/* entry assertions */

	assert(a_packageDir != (char *)NULL);
	assert(*a_packageDir != '\0');
	assert(a_pkgInst != (char *)NULL);
	assert(*a_pkgInst != '\0');

	/* normalize root path */

	if (a_rootPath == (char *)NULL) {
		a_rootPath = "";
	}

	/* entry debugging info */

	echoDebug(DBG_CHECKAPP_ENTRY);
	echoDebug(DBG_CHECKAPP_ARGS, a_pkgInst, a_packageDir, a_rootPath);

	/*
	 * calculate paths to various objects
	 */

	/* path to package to be installed top level (main) directory */

	len = snprintf(pkgpath, sizeof (pkgpath), "%s/%s", a_packageDir,
	    a_pkgInst);
	if (len > sizeof (pkgpath)) {
		progerr(ERR_CREATE_PATH_2, a_packageDir, a_pkgInst);
		return (B_FALSE);
	}

	/* error if package top level directory does not exist */

	if (isdir(pkgpath) != 0) {
		progerr(ERR_NO_PKGDIR, pkgpath, a_pkgInst, strerror(errno));
		return (B_FALSE);
	}

	/* path to pkginfo file within the package to be installed */

	len = snprintf(pkginfoPath, sizeof (pkginfoPath), "%s/pkginfo",
	    pkgpath);
	if (len > sizeof (pkginfoPath)) {
		progerr(ERR_CREATE_PATH_2, pkgpath, "pkginfo");
		return (B_FALSE);
	}

	/* path to highest instance of package currently installed */

	pkgLocateHighestInst(instPkgPath, sizeof (instPkgPath),
	    instPkg, sizeof (instPkg), a_rootPath, a_pkgInst);

	/*
	 * gather information from this package's pkginfo file
	 */

	pkginfoFP = fopen(pkginfoPath, "r");

	if (pkginfoFP == (FILE *)NULL) {
		progerr(ERR_NO_PKG_INFOFILE, a_pkgInst, pkginfoPath,
		    strerror(errno));
		return (B_FALSE);
	}

	/* determine "HOLLOW" setting for this package */

	is_hollow = pkginfoParamTruth(pkginfoFP, PKG_HOLLOW_VARIABLE,
	    "true", B_FALSE);

	/* determine "ALLZONES" setting for this package */

	all_zones = pkginfoParamTruth(pkginfoFP, PKG_ALLZONES_VARIABLE,
	    "true", B_FALSE);

	/* determine "THISZONE" setting for this package */

	this_zone = pkginfoParamTruth(pkginfoFP, PKG_THISZONE_VARIABLE,
	    "true", B_FALSE);

	/* close pkginfo file */

	(void) fclose(pkginfoFP);

	/*
	 * If request file is not found, it may be in the datastream which
	 * is not yet unpacked. Check in the pkgmap file.
	 */
	if (isfile(pkgpath, REQUEST_FILE) != 0) {

		/* path to pkgmap file within the package to be installed */
		(void) snprintf(pkgmapPath, sizeof (pkgmapPath), "%s/pkgmap",
		    pkgpath);

		pkgmapFP = fopen(pkgmapPath, "r");

		if (pkgmapFP == NULL) {
			progerr(ERR_NO_PKG_MAPFILE, a_pkgInst,
			    pkgmapPath, strerror(errno));
			return (B_FALSE);
		}

		while (fgets(line, LINE_MAX, pkgmapFP) != NULL) {
			if (strstr(line, " i request") != NULL) {
				reqfile_found = B_TRUE;
				break;
			}
		}
		(void) fclose(pkgmapFP);
	} else {
		reqfile_found = B_TRUE;
	}

	/*
	 * If this package is not marked for installation in this zone only,
	 * check to see if this package has a request script. If this package
	 * does have a request script, then mark the package for installation
	 * in this zone only. Any package with a request script cannot be
	 * installed outside of the zone the pkgadd command is being run in,
	 * nor can such a package be installed as part of a new zone install.
	 * A new zone install must be non-interactive, which is required
	 * by all packages integrated into the Solaris WOS.
	 */

	if ((!this_zone) && (reqfile_found)) {
		if (a_flags & CAF_IN_GLOBAL_ZONE) {
			echoDebug(DBG_CHECKAPP_THISZONE_REQUEST, a_pkgInst);
		}
		this_zone = B_TRUE;
	}

	/*
	 * If this package is already installed, see if the current installation
	 * of the package has a request file - if it does, then act as though
	 * the current package to be added has a request file - install the
	 * package in the current zone only.
	 */

	if ((!this_zone) && (instPkgPath[0] != '\0') &&
	    (isfile(instPkgPath, REQUEST_FILE) == 0)) {
		if (a_flags & CAF_IN_GLOBAL_ZONE) {
			echoDebug(DBG_CHECKAPP_THISZONE_INSTREQ,
			    a_pkgInst, instPkg);
		}
		this_zone = B_TRUE;
	}

	/* gather information from the global zone only file */

	in_gz_only = B_FALSE;
	if (a_flags & CAF_IN_GLOBAL_ZONE) {
		in_gz_only = pkgIsPkgInGzOnly(a_rootPath, a_pkgInst);
	}

	/* determine if this package is currently installed */

	pkg_installed = pkginfoIsPkgInstalled((struct pkginfo **)NULL,
	    a_pkgInst);

	/*
	 * verify package applicability based on information gathered,
	 * and validate the three SUNW_PKG_ options:
	 *
	 * -----------|--------------|-------------|-------------|-----------
	 * - - - - - -| GLOBAL ZONE -| GLOBAL ZONE | LOCAL ZONE	 | LOCAL ZONE
	 * - - - - - -|	- - pkgadd - | pkgadd -G   | pkgadd	 | pkgadd -G
	 * ----1------|--------------|-------------|-------------|------------
	 * ALLZONES f | add to gz    | add to gz   | add to ls	 | add to ls
	 * HOLLOW   f | current lz   | not to curr | only - - - -| only - - -
	 * THISZONE f | futr lz - - -| or futr lz  | - - - - - - | - - - - - -
	 * ----2------|--------------|-------------|-------------|------------
	 * ALLZONES T | add to gz    | operation   | operation	 | operation
	 * HOLLOW   f | current lz   | not allowed | not allowed | not allowed
	 * THISZONE f | future lz    | - - - - - - | - - - - - - | - - - - - -
	 * ----3------|--------------|-------------|-------------|------------
	 * ALLZONES T | add to gz    | operation   | operation	 | operation
	 * HOLLOW   T | pkg db only  | not allowed | not allowed | not allowed
	 * THISZONE f | curr/futr lz | - - - - - - | - - - - - - | - - - - - -
	 * ----4------|--------------|-------------|-------------|------------
	 * ALLZONES T | bad option   | bad option  | bad option	 | bad option
	 * HOLLOW   * | combo - - - -| combo - - - | combo - - - | combo - -
	 * THISZONE T |	- - - - - - -|- - - - - - -|- - - - - - -|- - - - - -
	 * ----5------|--------------|-------------|-------------|------------
	 * ALLZONES f | bad option   | bad option  | bad option	 | bad option
	 * HOLLOW   T | combo - - - -| combo - - - | combo - - - | combo - - -
	 * THISZONE * | - - - - - - -| - - - - - - | - - - - - - | - - - - - -
	 * ----6------|--------------|-------------|-------------|------------
	 * ALLZONES f | add to gz    | add to gz   | add to lz	 | add to lz
	 * HOLLOW   f | not current  | not current | only - - -	 | only - - -
	 * THISZONE T | or future lz | or futr lz  | - - - - - - | - - - - - -
	 * -----------|--------------|-------------|-------------|-----------
	 */

	/* pkg "all zones" && "this zone" (#4) */

	if (all_zones && this_zone) {
		progerr(ERR_ALLZONES_AND_THISZONE, a_pkgInst,
		    PKG_ALLZONES_VARIABLE, PKG_THISZONE_VARIABLE);
		return (B_FALSE);
	}

	/* pkg "!all zones" && "hollow" (#5) */

	if ((!all_zones) && is_hollow) {
		progerr(ERR_NOW_ALLZONES_AND_HOLLOW, a_pkgInst,
		    PKG_ALLZONES_VARIABLE, PKG_HOLLOW_VARIABLE);
		return (B_FALSE);
	}

	/* pkg ALLZONES=true & not running in global zone (#2/#3) */

	if (all_zones && (!(a_flags & CAF_IN_GLOBAL_ZONE))) {
		progerr(ERR_ALLZONES_AND_IN_LZ, a_pkgInst);
		return (B_FALSE);
	}

	/* pkg "in gz only" & pkg "NOT installed" */

	if (in_gz_only && (!pkg_installed)) {
		/* MAKE A WARNING */
		echo(ERR_IN_GZ_AND_NOT_INSTALLED, a_pkgInst,
		    pkgGetGzOnlyPath());
	}

	/* pkg ALLZONES=true & pkg "in gz only" & pkg "is installed" */

	if (all_zones && in_gz_only && pkg_installed) {
		progerr(ERR_IN_GZ_AND_ALLZONES_AND_INSTALLED, a_pkgInst);
		return (B_FALSE);
	}

	/* pkg ALLZONES=true && -G specified (#2/#3) */

	if (all_zones && (a_flags & CAF_SCOPE_GLOBAL)) {
		progerr(ERR_ALLZONES_AND_G_USED, a_pkgInst);
		return (B_FALSE);
	}

	/* pkg "!this zone" && "in gz only" & -G not specified */

	if ((!this_zone) && in_gz_only && (!(a_flags & CAF_SCOPE_GLOBAL))) {
		progerr(ERR_IN_GZ_AND_NO_G_USED, a_pkgInst);
		return (B_FALSE);
	}

	/*
	 * If this package is marked 'this zone only', then mark the package
	 * as "add to this zone only". This is referenced by the various
	 * add_package_... functions to determine if the package should be
	 * added to the current zone, or to all zones, depending on the
	 * zone in which the command is being run.
	 */

	if (this_zone) {
		pkgAddThisZonePackage(a_pkgInst);
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

	/* register with quit() so directory is removed on exit */

	quitSetZoneTmpdir(*r_zoneTempDir);

	/* exit debugging info */

	echoDebug(DBG_CREATED_ZONE_TEMPDIR, *r_zoneTempDir);
}

/*
 * Name:	continue_installation
 * Description: Called from within a loop that is installing packages,
 *		this function examines various global variables and decides
 *		whether or not to ask an appropriate question, and wait for
 *		and appropriate reply.
 * Arguments:	<<global variables>>
 * Returns:	B_TRUE - continue processing with next package
 *		B_FALSE - do not continue processing with next package
 */

static boolean_t
continue_installation(void)
{
	char	ans[MAX_INPUT];
	int	n;

	/* return TRUE if not interrupted */

	if (!interrupted) {
		return (B_TRUE);
	}

	/*
	 * process interrupted - determine whether or not to continue
	 */

	/* output appropriate interrupted message */

	if (askflag) {
		echo(npkgs == 1 ? MSG_1MORE_PROC : MSG_MORE_PROC, npkgs);
	} else {
		echo(npkgs == 1 ? MSG_1MORE_INST : MSG_MORE_INST, npkgs);
	}

	/* if running with no interaction (-n) do not ask question */

	if (nointeract) {
		/* if admin required return 'dont continue' */
		if (needconsult) {
			return (B_FALSE);
		}
		ckquit = 1;
		return (B_TRUE);
	}

	/* interaction possible: ask question */

	ckquit = 0;
	n = ckyorn(ans, NULL, NULL, NULL, ASK_CONTINUE_ADD);
	if (n != 0) {
		quit(n);
		/* NOTREACHED */
	}
	ckquit = 1;
	if (strchr("yY", *ans) == NULL) {
		return (B_FALSE);
	}
	return (B_TRUE);
}

/*
 * package can be in a number of formats:
 * - file containing package stream (pkgadd -d file [pkgs])
 * - directory containing packages (pkgadd -d /dir [pkgs])
 * - device containing packages (pkgadd -d diskette1 [pkgs])
 * non-global zones can be passed open files and strings as arguments
 * - for file containing package stream
 * -- the stream can be passed directly to the non-global zone
 * - for directory
 * -- convert packages to datastream to pass to the non-global zone
 * - for device
 * -- ?
 */

static boolean_t
unpack_and_check_packages(char **a_pkgList, char *a_idsName, char *a_packageDir)
{
	int	savenpkgs = npkgs;
	int	i;
	CAF_T	flags = 0;

	/* entry assertions */

	assert(a_pkgList != (char **)NULL);

	/* entry debugging info */

	echoDebug(DBG_UNPACKCHECK_ENTRY);
	echoDebug(DBG_UNPACKCHECK_ARGS, PSTR(a_idsName), PSTR(a_packageDir));

	/*
	 * set flags for applicability check
	 */

	/* determine if running in the global zone */

	if (z_running_in_global_zone() == B_TRUE) {
		flags |= CAF_IN_GLOBAL_ZONE;
	}

	/* set -G flag */

	if (globalZoneOnly == B_TRUE) {
		flags |= CAF_SCOPE_GLOBAL;
	}

	/*
	 * for each package to install:
	 * - if packages from datastream, unpack package into package dir
	 * - check applicability of installing package on this system/zone
	 */

	for (i = 0; (pkginst = a_pkgList[i]) != NULL; i++) {
		if (a_idsName != (char *)NULL) {
			/* create stream out of package if not already one */
			if (unpack_package_from_stream(a_idsName, pkginst,
			    a_packageDir) == B_FALSE) {
				progerr(ERR_CANNOT_UNPACK_PKGSTRM,
				    PSTR(pkginst), PSTR(a_idsName),
				    PSTR(a_packageDir));

				npkgs = savenpkgs;
				return (B_FALSE);
			}
		} else {
			echoDebug(DBG_PKG_IN_DIR, pkginst, a_packageDir);
		}

		/* check package applicability */
		if (check_applicability(a_packageDir,
		    pkginst, get_inst_root(), flags) == B_FALSE) {
			progerr(ERR_PKG_NOT_INSTALLABLE, pkginst);
			npkgs = savenpkgs;
			return (B_FALSE);
		}
		npkgs--;
	}

	npkgs = savenpkgs;
	return (B_TRUE);
}

/*
 * returns:
 *	B_TRUE - package list generated
 *	B_FALSE - failed to generate package list
 *	Will call quit(n) on fatal error.
 */

static boolean_t
get_package_list(char ***r_pkgList, char **a_argv, char *a_categories,
    char **a_categoryList, char *a_idsName, int *r_repeat)
{
	int		n;

	/* entry assertions */

	assert(r_repeat != (int *)NULL);

	/* entry debugging info */

	echoDebug(DBG_GETPKGLIST_ENTRY);
	echoDebug(DBG_GETPKGLIST_ARGS, PSTR(a_idsName), PSTR(pkgdev.dirname),
	    *r_repeat);

	/*
	 * get the list of the packages to add
	 */

	n = pkgGetPackageList(r_pkgList, a_argv, optind, a_categories,
	    a_categoryList, &pkgdev);

	switch (n) {
		case -1:	/* no packages found */
			echoDebug(DBG_PKGLIST_NONFOUND, PSTR(a_idsName),
			    pkgdev.dirname);
			return (B_FALSE);

		case 0:		/* packages found */
			break;

		default:	/* "quit" error */
			echoDebug(DBG_PKGLIST_ERROR, PSTR(a_idsName),
			    pkgdev.dirname, n);
			quit(n);
			/* NOTREACHED */
	}

	/* order package list if input data stream specified */

	if (a_idsName) {
		ds_order(*r_pkgList);
	}

	return (B_TRUE);
}

/*
 * Name:	install_in_one_zone
 * Description:	Install a single package in a single zone
 * Arguments:	a_zoneName - pointer to string representing the name of the
 *			zone to install the package into.
 *		a_idsName - pointer to string representing the data stream
 *			device (input data stream) containing the package to
 *			be installed.
 *			If this is == NULL the package is assumed to be
 *			spooled in the zone temporary directory.
 *		a_zoneAdminFile - pointer to string representing the admin
 *			file to pass to pkginstall when installing the package.
 *			If this is == NULL no admin file is given to pkginstall.
 *		a_zoneTempDir - pointer to string representing the temporary
 *			directory in which spooled packages can be found if
 *			a_idsName is == NULL.
 *		a_altBinDir - pointer to string representing an alternative
 *			binary location directory to pass to pkginstall.
 *			If this is == NULL no alternative binary location is
 *			passed to pkginstall.
 *		a_scratchName - pointer to string representing the name of the
 *			scratch zone to use for installation.
 *		a_zoneState - state of the zone; must be mounted or running.
 *		a_tmpzn - B_TRUE when this zone is booted by the package
 *			command or B_FALSE if it was running before.
 * Returns:	void
 * NOTE:	As a side effect, "ckreturn" is called on the result returned
 *		from running 'pkginstall' in the zone; this sets several global
 *		variables which allows the caller to determine the result of
 *		the installation operation.
 */

static void
install_in_one_zone(char *a_zoneName, char *a_idsName,
    char *a_zoneAdminFile, char *a_zoneTempDir,
    char *a_altBinDir, zone_state_t a_zoneState, boolean_t a_tmpzn)
{
	char	zoneStreamName[PATH_MAX] = {'\0'};
	int	n;

	/* entry assertions */

	assert(a_zoneName != (char *)NULL);
	assert(*a_zoneName != '\0');

	/* entry debugging info */

	echoDebug(DBG_INSTINONEZONE_ENTRY);
	echoDebug(DBG_INSTINONEZONE_ARGS, a_zoneName, PSTR(a_idsName),
	    PSTR(a_zoneAdminFile), PSTR(a_zoneTempDir),
	    PSTR(a_altBinDir));

	/* echo operation to perform to stdout */

	echo(MSG_INSTALL_PKG_IN_ZONE, pkginst, a_zoneName);

	/* determine path to the package stream */

	if (a_idsName == (char *)NULL) {
		/* locate temp stream created earlier */
		(void) snprintf(zoneStreamName, sizeof (zoneStreamName),
		    "%s/%s.dstream", a_zoneTempDir, pkginst);
	} else {
		/* use stream passed in on command line */
		(void) snprintf(zoneStreamName, sizeof (zoneStreamName),
		    "%s", a_idsName);
	}

	echoDebug(DBG_INSTALL_IN_ZONE, pkginst, a_zoneName, zoneStreamName);

	n = pkgZoneInstall(a_zoneName, a_zoneState, zoneStreamName,
	    a_altBinDir, a_zoneAdminFile, a_tmpzn);

	/* set success/fail condition variables */

	ckreturn(n);

	/* exit debugging info */

	echoDebug(DBG_INSTALL_FLAG_VALUES, "after install", admnflag, doreboot,
	    failflag, interrupted, intrflag, ireboot, needconsult,
	    nullflag, warnflag);
}

/*
 * Name:	install_in_zones
 * Description:	Install a single package in the zones that are running from
 *		a list of zones
 * Arguments:	a_zlst - list of zones to install the package into
 *		a_idsName - pointer to string representing the data stream
 *			device (input data stream) containing the package to
 *			be installed.
 *			If this is == NULL the package is assumed to be
 *			spooled in the zone temporary directory.
 *		a_altBinDir - pointer to string representing an alternative
 *			binary location directory to pass to pkginstall.
 *			If this is == NULL no alternative binary location is
 *			passed to pkginstall.
 *		a_zoneAdminFile - pointer to string representing the admin
 *			file to pass to pkginstall when installing the package.
 *			If this is == NULL no admin file is given to pkginstall.
 *		a_zoneTempDir - pointer to string representing the temporary
 *			directory in which spooled packages can be found if
 *			a_idsName is == NULL.
 */

static int
install_in_zones(zoneList_t a_zlst, char *a_idsName, char *a_altBinDir,
    char *a_zoneAdminFile, char *a_zoneTempDir)
{
	char		*zoneName;
	int		zoneIndex;
	int		zonesSkipped = 0;
	zone_state_t	zst;

	/* entry assertions */

	assert(a_zlst != (zoneList_t)NULL);

	/* entry debugging info */

	echoDebug(DBG_INSTALLINZONES_ENTRY);
	echoDebug(DBG_INSTALLINZONES_ARGS, PSTR(a_idsName),
	    PSTR(a_zoneAdminFile), PSTR(a_zoneTempDir));

	/* process each zone in the list */

	for (zoneIndex = 0;
	    (zoneName = z_zlist_get_zonename(a_zlst, zoneIndex)) != NULL;
	    zoneIndex++) {

		/* skip the zone if it is NOT running */

		zst = z_zlist_get_current_state(a_zlst, zoneIndex);
		if (zst != ZONE_STATE_RUNNING && zst != ZONE_STATE_MOUNTED) {
			zonesSkipped++;
			echoDebug(DBG_SKIPPING_ZONE, zoneName);
			continue;
		}

		/* install the package in this zone */

		install_in_one_zone(z_zlist_get_scratch(a_zlst, zoneIndex),
		    a_idsName, a_zoneAdminFile, a_zoneTempDir, a_altBinDir,
		    zst, B_FALSE);
	}

	return (zonesSkipped);
}

/*
 * Name:	boot_and_install_in_zones
 * Description:	Install a single package in the zones that are NOT running from
 *		a list of zones - each zone is booted, the package installed,
 *		and the zone is halted
 * Arguments:	a_zlst - list of zones to install the package into
 *		a_idsName - pointer to string representing the data stream
 *			device (input data stream) containing the package to
 *			be installed.
 *			If this is == NULL the package is assumed to be
 *			spooled in the zone temporary directory.
 *		a_altBinDir - pointer to string representing an alternative
 *			binary location directory to pass to pkginstall.
 *			If this is == NULL no alternative binary location is
 *			passed to pkginstall.
 *		a_zoneAdminFile - pointer to string representing the admin
 *			file to pass to pkginstall when installing the package.
 *			If this is == NULL no admin file is given to pkginstall.
 *		a_zoneTempDir - pointer to string representing the temporary
 *			directory in which spooled packages can be found if
 *			a_idsName is == NULL.
 */

static int
boot_and_install_in_zones(zoneList_t a_zlst, char *a_idsName, char *a_altBinDir,
    char *a_zoneAdminFile, char *a_zoneTempDir)
{
	boolean_t	b;
	char		*zoneName;
	int		zoneIndex;
	int		zonesSkipped = 0;
	zone_state_t	zst;

	/* entry assertions */

	assert(a_zlst != (zoneList_t)NULL);

	/* entry debugging info */

	echoDebug(DBG_BOOTINSTALLINZONES_ENTRY);
	echoDebug(DBG_BOOTINSTALLINZONES_ARGS, PSTR(a_idsName),
	    PSTR(a_zoneAdminFile), PSTR(a_zoneTempDir));

	/* process each zone in the list */

	for (zoneIndex = 0;
	    (zoneName = z_zlist_get_zonename(a_zlst, zoneIndex)) != NULL;
	    zoneIndex++) {

		/* skip the zone if it IS running */

		zst = z_zlist_get_current_state(a_zlst, zoneIndex);
		if (zst == ZONE_STATE_RUNNING || zst == ZONE_STATE_MOUNTED) {
			echoDebug(DBG_SKIPPING_ZONE_BOOT, zoneName);
			continue;
		}

		/* skip the zone if it is NOT bootable */

		if (z_zlist_is_zone_runnable(a_zlst, zoneIndex) == B_FALSE) {
			echo(MSG_SKIPPING_ZONE_NOT_RUNNABLE, zoneName);
			echoDebug(DBG_SKIPPING_ZONE_NOT_RUNNABLE, zoneName);
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
			zonesSkipped++;
			continue;
		}

		/* install the package in this zone */

		install_in_one_zone(z_zlist_get_scratch(a_zlst, zoneIndex),
		    a_idsName, a_zoneAdminFile, a_zoneTempDir, a_altBinDir,
		    ZONE_STATE_MOUNTED, B_TRUE);

		/* restore original state of zone */

		echo(MSG_RESTORE_ZONE_STATE, zoneName);
		echoDebug(DBG_RESTORE_ZONE_STATE, zoneName);

		b = z_zlist_restore_zone_state(a_zlst, zoneIndex);
	}

	return (zonesSkipped);
}

/*
 * Name:	pkginstall_check_in_one_zone
 * Description:	Do a pre install check of a single package in a single zone
 * Arguments:	a_zoneName - pointer to string representing the name of the
 *			zone to check install the package in.
 *		a_idsName - pointer to string representing the data stream
 *			device (input data stream) containing the package to
 *			be check installed.
 *			If this is == NULL the package is assumed to be
 *			spooled in the zone temporary directory.
 *		a_zoneAdminFile - pointer to string representing the admin
 *			file to pass to pkginstall when installing the package.
 *			If this is == NULL no admin file is given to pkginstall.
 *		a_zoneTempDir - pointer to string representing the temporary
 *			directory in which spooled packages can be found if
 *			a_idsName is == NULL.
 *		a_altBinDir - pointer to string representing an alternative
 *			binary location directory to pass to pkginstall.
 *			If this is == NULL no alternative binary location is
 *			passed to pkginstall.
 *		a_scratchName - pointer to string representing the name of the
 *			scratch zone to use for installation.
 *		a_zoneState - state of the zone; must be mounted or running.
 *		a_tmpzn - B_TRUE when this zone is booted by the package
 *			command or B_FALSE if it was running before.
 * Returns:	void
 * NOTE:	As a side effect, "ckreturn" is called on the result returned
 *		from running 'pkginstall' in the zone; this sets several global
 *		variables which allows the caller to determine the result of
 *		the pre installation check operation.
 */

static void
pkginstall_check_in_one_zone(char *a_zoneName,
    char *a_idsName, char *a_zoneAdminFile, char *a_zoneTempDir,
    char *a_altBinDir, char *a_scratchName, zone_state_t a_zoneState,
    boolean_t a_tmpzn)
{
	char	preinstallcheckPath[PATH_MAX+1];
	char	zoneStreamName[PATH_MAX] = {'\0'};
	int	n;

	echo(MSG_CHECKINSTALL_PKG_IN_ZONE, pkginst, a_zoneName);
	echoDebug(MSG_CHECKINSTALL_PKG_IN_ZONE, pkginst, a_zoneName);

	(void) snprintf(preinstallcheckPath, sizeof (preinstallcheckPath),
	    "%s/%s.%s.preinstallcheck.txt", a_zoneTempDir, pkginst,
	    a_zoneName);

	if (a_idsName == (char *)NULL) {
		/* locate temporary stream created earlier */
		(void) snprintf(zoneStreamName, sizeof (zoneStreamName),
		    "%s/%s.dstream", a_zoneTempDir, pkginst);
	} else {
		(void) snprintf(zoneStreamName, sizeof (zoneStreamName),
		    "%s", a_idsName);
	}

	echoDebug(DBG_CHECKINSTALL_IN_ZONE, pkginst, a_zoneName,
	    zoneStreamName);

	n = pkgZoneCheckInstall(a_scratchName, a_zoneState, zoneStreamName,
	    a_altBinDir, a_zoneAdminFile, preinstallcheckPath, a_tmpzn);

	/* set success/fail condition variables */

	ckreturn(n);

	echoDebug(DBG_INSTALL_FLAG_VALUES, "after preinstall check",
	    admnflag, doreboot, failflag, interrupted, intrflag,
	    ireboot, needconsult, nullflag, warnflag);
}

/*
 * Name:	pkginstall_check_in_zones
 * Description:	Check installation of a single package in the zones that
 *		are running from a list of zones
 * Arguments:	a_zlst - list of zones to check install the package
 *		a_idsName - pointer to string representing the data stream
 *			device (input data stream) containing the package to
 *			be check installed.
 *			If this is == NULL the package is assumed to be
 *			spooled in the zone temporary directory.
 *		a_altBinDir - pointer to string representing an alternative
 *			binary location directory to pass to pkginstall.
 *			If this is == NULL no alternative binary location is
 *			passed to pkginstall.
 *		a_zoneAdminFile - pointer to string representing the admin
 *			file to pass to pkginstall when checking the installing
 *			of the package.
 *			If this is == NULL no admin file is given to pkginstall.
 *		a_zoneTempDir - pointer to string representing the temporary
 *			directory in which spooled packages can be found if
 *			a_idsName is == NULL.
 */

static int
pkginstall_check_in_zones(zoneList_t a_zlst, char *a_idsName, char *a_altBinDir,
    char *a_zoneAdminFile, char *a_zoneTempDir)
{
	char		*zoneName;
	int		zoneIndex;
	int		zonesSkipped = 0;
	zone_state_t	zst;

	for (zoneIndex = 0;
	    (zoneName = z_zlist_get_zonename(a_zlst, zoneIndex)) != NULL;
	    zoneIndex++) {

		zst = z_zlist_get_current_state(a_zlst, zoneIndex);
		if (zst != ZONE_STATE_RUNNING && zst != ZONE_STATE_MOUNTED) {
			zonesSkipped++;
			echoDebug(DBG_SKIPPING_ZONE, zoneName);
			continue;
		}

		pkginstall_check_in_one_zone(zoneName, a_idsName,
		    a_zoneAdminFile, a_zoneTempDir, a_altBinDir,
		    z_zlist_get_scratch(a_zlst, zoneIndex), zst, B_FALSE);
	}

	return (zonesSkipped);
}

/*
 * Name:	boot_and_pkginstall_check_in_zones
 * Description:	Check installation of a single package in the zones that
 *		are NOT running from a list of zones - each zone is booted,
 *		the package installation is checked, and the zone is halted.
 * Arguments:	a_zlst - list of zones to install the package into
 *		a_idsName - pointer to string representing the data stream
 *			device (input data stream) containing the package to
 *			be check installed.
 *			If this is == NULL the package is assumed to be
 *			spooled in the zone temporary directory.
 *		a_altBinDir - pointer to string representing an alternative
 *			binary location directory to pass to pkginstall.
 *			If this is == NULL no alternative binary location is
 *			passed to pkginstall.
 *		a_zoneAdminFile - pointer to string representing the admin
 *			file to pass to pkginstall when check installing the
 *			package.
 *			If this is == NULL no admin file is given to pkginstall.
 *		a_zoneTempDir - pointer to string representing the temporary
 *			directory in which spooled packages can be found if
 *			a_idsName is == NULL.
 */

static int
boot_and_pkginstall_check_in_zones(zoneList_t a_zlst, char *a_idsName,
    char *a_altBinDir, char *a_zoneAdminFile, char *a_zoneTempDir)
{
	int		zoneIndex;
	int		zonesSkipped = 0;
	char		*zoneName;
	boolean_t	b;
	zone_state_t	zst;

	/* entry assertions */

	assert(a_zlst != (zoneList_t)NULL);

	/* entry debugging info */

	echoDebug(DBG_BOOTCHECKINSTALLINZONES_ENTRY);
	echoDebug(DBG_BOOTCHECKINSTALLINZONES_ARGS, PSTR(a_idsName),
	    PSTR(a_zoneAdminFile), PSTR(a_zoneTempDir));

	/* process each zone in the list */

	for (zoneIndex = 0;
	    (zoneName = z_zlist_get_zonename(a_zlst, zoneIndex)) != NULL;
	    zoneIndex++) {

		/* skip the zone if it IS running */

		zst = z_zlist_get_current_state(a_zlst, zoneIndex);
		if (zst == ZONE_STATE_RUNNING || zst == ZONE_STATE_MOUNTED) {
			echoDebug(DBG_SKIPPING_ZONE_BOOT, zoneName);
			continue;
		}

		/* skip the zone if it is NOT bootable */

		if (z_zlist_is_zone_runnable(a_zlst, zoneIndex) == B_FALSE) {
			echo(MSG_SKIPPING_ZONE_NOT_RUNNABLE, zoneName);
			echoDebug(DBG_SKIPPING_ZONE_NOT_RUNNABLE, zoneName);
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
			zonesSkipped++;
			continue;
		}

		/* pre-installation check of the package in this zone */

		pkginstall_check_in_one_zone(zoneName, a_idsName,
		    a_zoneAdminFile, a_zoneTempDir, a_altBinDir,
		    z_zlist_get_scratch(a_zlst, zoneIndex),
		    ZONE_STATE_MOUNTED, B_TRUE);

		/* restore original state of zone */

		echo(MSG_RESTORE_ZONE_STATE, zoneName);
		echoDebug(DBG_RESTORE_ZONE_STATE, zoneName);

		b = z_zlist_restore_zone_state(a_zlst, zoneIndex);
	}

	return (zonesSkipped);
}

/*
 * Function:	add_packages_in_global_with_zones
 * Description: call this function to add a list of packages in the global zone
 *		when one or more non-global zones exist
 * returns:
 *	B_TRUE to process next data stream
 *	B_FALSE to exit
 */

static boolean_t
add_packages_in_global_with_zones(char **a_pkgList,
    char *a_idsName, int a_repeat, char *a_altBinDir,
    char *a_device, zoneList_t a_zlst)
{
static	char		*zoneTempDir = (char *)NULL;
static	char		*zoneAdminFile = (char *)NULL;

	boolean_t	b;
	char		*packageDir;
	char		instdir[PATH_MAX];
	char		respfile_path[PATH_MAX];
	char		zoneStreamName[PATH_MAX] = {'\0'};
	int		i;
	int		n;
	int		savenpkgs = npkgs;
	int		zonesSkipped;
	boolean_t	globalPresent;

	/* entry assertions */

	assert(a_pkgList != (char **)NULL);
	assert(a_zlst != (zoneList_t)NULL);

	echoDebug(DBG_ADDPACKAGES_GZ_W_LZ_ENTRY);
	echoDebug(DBG_ADDPACKAGES_GZ_W_LZ_ARGS, npkgs,
	    PSTR(a_idsName), a_repeat, PSTR(a_device));

	/* create temporary directory for use by zone operations */

	create_zone_tempdir(&zoneTempDir, tmpdir);

	/* create hands off settings admin file for use in a non-global zone */

	create_zone_adminfile(&zoneAdminFile, zoneTempDir, admnfile);

	/* determine directory where packages can be found */

	if (a_idsName == (char *)NULL) {
		/* no stream - directory containing packages provided */
		packageDir = pkgdev.dirname;
	} else {
		packageDir = zoneTempDir;
	}

	/* unpack and check all packages */

	b = unpack_and_check_packages(a_pkgList, a_idsName, packageDir);
	if (b != B_TRUE) {
		quit(1);
	}

	/*
	 * if the packages are contained in a directory, convert the
	 * packages into individual streams because pkgZoneInstall is only able
	 * to pass a stream to the non-global zone's pkginstall command.
	 * After this code is executed:
	 * if the original input was a datastream:
	 * -> that datastream has been unpacked into "instdir"
	 * if the original input was a directory with packages in it:
	 * -> those packages have been placed into a single datastream
	 */

	if (a_idsName == (char *)NULL) {
		for (i = 0; (pkginst = a_pkgList[i]) != NULL; i++) {
			char	*pkgs[2];

			/* package is not a stream - create one */

			(void) snprintf(zoneStreamName, sizeof (zoneStreamName),
			    "%s/%s.dstream", zoneTempDir, pkginst);

			echoDebug(DBG_CONVERTING_PKG, packageDir, pkginst,
			    zoneStreamName);

			/* set up list of packages to be this package only */

			pkgs[0] = pkginst;
			pkgs[1] = (char *)NULL;

			n = pkgtrans(packageDir, zoneStreamName, pkgs,
			    PT_SILENT|PT_ODTSTREAM);
			if (n != 0) {
				progerr(ERR_CANNOT_CONVERT_PKGSTRM,
				    pkginst, packageDir, zoneStreamName);
				quit(1);
			}
			npkgs--;
		}
		npkgs = savenpkgs;
	}

	/*
	 * Phase I - run collect dependency information for all packages for all
	 * zones - this involves running pkginstall with the "preinstallcheck"
	 * option which causes all dependency checks to be performed without
	 * actually doing the installation of the packages. This information is
	 * gathered in the zone temporary directory and is used later to present
	 * the dependency check results to the system administrator depending
	 * on the administration settings.
	 */

	for (i = 0; (pkginst = a_pkgList[i]) != NULL; i++) {

		/* reset interrupted flag before calling pkginstall */

		interrupted = 0;	/* last action was NOT quit */

		/*
		 * if this package is marked "install in this zone only", then
		 * do not check dependencies in any other zone
		 */

		if (pkgPackageIsThisZone(pkginst) == B_TRUE) {
			echoDebug(DBG_VERIFY_SKIP_THISZONE, pkginst);
			npkgs--;
			continue;
		}

		/*
		 * if operation failed in global zone do not propagate
		 * to any non-global zones
		 */

		if (interrupted != 0) {
			echo(MSG_CHECKINSTALL_INTERRUPT_B4_Z, pkginst);
			echoDebug(MSG_CHECKINSTALL_INTERRUPT_B4_Z, pkginst);
			break;
		}

		echoDebug(DBG_INSTALL_FLAG_VALUES, "after pkginstall",
		    admnflag, doreboot, failflag, interrupted, intrflag,
		    ireboot, needconsult, nullflag, warnflag);

		/*
		 * call pkginstall to verify this package for all non-global
		 * zones that are currently booted
		 */

		zonesSkipped = pkginstall_check_in_zones(a_zlst, a_idsName,
		    a_altBinDir, admnfile, zoneTempDir);

		/*
		 * if any zones were skipped (becuase they are not currently
		 * booted), boot each zone one at a time and call pkginstall
		 * to verify this package for each such non-global zone
		 */

		if (zonesSkipped > 0) {
			echoDebug(DBG_ZONES_SKIPPED, zonesSkipped);

			zonesSkipped =
			    boot_and_pkginstall_check_in_zones(a_zlst,
			    a_idsName, a_altBinDir, admnfile,
			    zoneTempDir);

			if (zonesSkipped > 0) {
				progerr(ERR_INSTALL_ZONES_SKIPPED,
				    zonesSkipped);
			}
		}

		npkgs--;
	}

	/*
	 * At this point, all of the dependency information has been gathered
	 * and is ready to be analyzed. This function processes all of that
	 * dependency information and presents the results to the system
	 * administrator, depending on the current administration settings.
	 */

	i = preinstall_verify(a_pkgList, a_zlst, zoneTempDir);
	if (i != 0) {
		/* dependency checks failed - exit */
		quit(i);
	}

	npkgs = savenpkgs;

	/*
	 * reset all error return condition variables that may have been
	 * set during package installation dependency checking so that they
	 * do not reflect on the success/failure of the actual package
	 * installation operations
	 */

	resetreturn();

	/*
	 * At this point, all of the dependency checking is completed, and
	 * the installation of the packages can proceed. Install each package
	 * one at a time, starting with the global zone, and the for each
	 * non-global zone that is booted, and then for each non-global zone
	 * that is not currently booted.
	 */

	globalPresent = z_on_zone_spec(GLOBAL_ZONENAME);

	for (i = 0; (pkginst = a_pkgList[i]) != NULL; i++) {
		/*
		 * if immediate reboot required from last package and this is
		 * not 'pkgask' then suspend installation of remaining packages
		 */

		if ((ireboot != 0) && (askflag == 0)) {
			ptext(stderr, MSG_SUSPEND_ADD, pkginst);
				continue;
		}

		/*
		 * handle interrupt if the previous pkginstall was interrupted
		 */

		if (continue_installation() == B_FALSE) {
			return (B_FALSE);
		}

		/*
		 * if pkgask, handle response file creation:
		 * - if the response file is a directory, then create a path to
		 * -- a package instance within the response file directory.
		 * - If the response file is NOT a directory, if more than one
		 * -- package is to be installed.
		 */

		if ((askflag != 0) && (respdir != (char *)NULL)) {
			(void) snprintf(respfile_path, sizeof (respfile_path),
			    "%s/%s", respdir, pkginst);
			respfile = respfile_path;
		}

		echo(MSG_PROC_INST, pkginst, a_device);

		/*
		 * If we're installing another package in the same
		 * session, the second through nth pkginstall, must
		 * continue from where the prior one left off. For this
		 * reason, the continuation feature (implied by the
		 * nature of the command) is used for the remaining
		 * packages.
		 */

		if ((i == 1) && (pkgdrtarg != (char *)NULL)) {
			pkgcontsrc = pkgdrtarg;
		}

		if (globalPresent) {
			/*
			 * call pkginstall for this package for the global zone
			 */

			echo(MSG_INSTALLING_PKG_IN_GZ, pkginst);

			/* reset interrupted flag before calling pkginstall */

			interrupted = 0;	/* last action was NOT quit */

			n = pkgInstall(get_inst_root(), NULL, packageDir,
			    a_altBinDir);

			/* set success/fail condition variables */

			ckreturn(n);

			/*
			 * if operation failed in global zone do not propagate
			 * to any non-global zones
			 */

			if (interrupted != 0) {
				echo(MSG_INSTALL_INTERRUPT_B4_ZONES, pkginst);
				echoDebug(MSG_INSTALL_INTERRUPT_B4_ZONES,
				    pkginst);
				break;
			}
		}

		/*
		 * if this package is marked "install in this zone only",
		 * then only need to install the package in the global zone;
		 * skip installation in any non-global zones.
		 */

		if (pkgPackageIsThisZone(pkginst) == B_TRUE) {
			echoDebug(DBG_INSTALL_SKIP_THISZONE, pkginst);
			npkgs--;
			continue;
		}

		echoDebug(DBG_INSTALL_FLAG_VALUES, "install in running zones",
		    admnflag, doreboot, failflag, interrupted, intrflag,
		    ireboot, needconsult, nullflag, warnflag);

		/* install package in currently booted zones */

		zonesSkipped = install_in_zones(a_zlst, a_idsName, a_altBinDir,
		    zoneAdminFile, zoneTempDir);

		/* install package in zones that are not currently booted */

		if (zonesSkipped > 0) {
			echoDebug(DBG_ZONES_SKIPPED, zonesSkipped);

			zonesSkipped = boot_and_install_in_zones(a_zlst,
			    a_idsName, a_altBinDir, zoneAdminFile,
			    zoneTempDir);

			if (zonesSkipped > 0) {
				progerr(ERR_INSTALL_ZONES_SKIPPED,
				    zonesSkipped);
			}
		}

		/*
		 * package completely installed - remove any temporary stream
		 * of the package that might have been created
		 */

		if (a_idsName == (char *)NULL) {
			/* locate temporary stream created earlier */
			(void) snprintf(zoneStreamName, sizeof (zoneStreamName),
			    "%s/%s.dstream", zoneTempDir, pkginst);
			/* remove stream - no longer needed */
			echoDebug(DBG_REMOVING_DSTREAM_PKGDIR, zoneStreamName,
			    pkginst);
			(void) remove(zoneStreamName);
		} else {
			/* remove package - no longer needed */
			if (snprintf(instdir, sizeof (instdir), "%s/%s",
			    zoneTempDir, pkginst) >= PATH_MAX) {
				progerr(ERR_CANNOT_CREATE_PKGPATH, tmpdir);
				quit(1);
			}
			echoDebug(DBG_REMOVING_PKG_TMPDIR, instdir, pkginst);
			(void) remove(instdir);
		}

		/* decrement number of packages left to install */

		npkgs--;

		/*
		 * if no packages left to install, unmount package source
		 * device if appropriate
		 */

		if ((npkgs <= 0) && (pkgdev.mount || a_idsName)) {
			(void) chdir("/");
			if (!a_idsName) {
				echoDebug(DBG_UNMOUNTING_DEV,
				    PSTR(pkgdev.mount));
				(void) pkgumount(&pkgdev);
			}
		}
	}

	/*
	 * all packages in the package list have been installed.
	 * Continue with installation if:
	 * -- immediate reboot is NOT required
	 * -- there are more packages to install
	 * -- the package source is a path to a file
	 * else return do NOT continue.
	 */

	if ((ireboot == 0) && (a_repeat != 0) &&
	    (pkgdev.pathname == (char *)NULL)) {
		return (B_TRUE);
	}

	/* return 'dont continue' */

	return (B_FALSE);
}

/*
 * Function:	add_packages_in_nonglobal_zone
 * Description: call this function to add a list of packages in a non-global
 *		zone
 * returns:
 *	B_TRUE to process next data stream
 *	B_FALSE to exit
 */

static boolean_t
add_packages_in_nonglobal_zone(char **a_pkgList,
    char *a_idsName, int a_repeat, char *a_altBinDir, char *a_device)
{
static	char		*zoneTempDir = (char *)NULL;

	char		*packageDir;
	char		respfile_path[PATH_MAX];
	int		i;
	int		n;
	boolean_t	b;
	int		savenpkgs = npkgs;

	/* entry assertions */

	assert(a_pkgList != (char **)NULL);

	/* entry debugging info */

	echoDebug(DBG_ADDPACKAGES_LZ_ENTRY);
	echoDebug(DBG_ADDPACKAGES_LZ_ARGS, npkgs, PSTR(a_idsName),
	    a_repeat, PSTR(a_device));

	/* create temporary directory for use by zone operations */

	create_zone_tempdir(&zoneTempDir, tmpdir);

	/*
	 * package can be in a number of formats:
	 * - file containing package stream (pkgadd -d file [pkgs])
	 * - directory containing packages (pkgadd -d /dir [pkgs])
	 * - device containing packages (pkgadd -d diskette1 [pkgs])
	 * non-global zones can be passed open file drescriptors and
	 * strings as arguments
	 * - for file containing package stream
	 * -- the stream can be passed directly to the non-global zone
	 * - for directory
	 * -- convert packages to datastream to pass to the non-global zone
	 * - for device
	 */

	/* determine directory where packages can be found */

	if (a_idsName == (char *)NULL) {
		/* no stream - directory containing packages provided */
		packageDir = pkgdev.dirname;
	} else {
		packageDir = zoneTempDir;
	}

	b = unpack_and_check_packages(a_pkgList, a_idsName, packageDir);
	if (b != B_TRUE) {
		quit(1);
	}

	/*
	 * this is the main loop where all of the packages (as listed in the
	 * package list) are added one at a time.
	 */

	for (i = 0; (pkginst = a_pkgList[i]) != NULL; i++) {
		npkgs--;
	}

	npkgs = savenpkgs;

	/*
	 * this is the main loop where all of the packages (as listed in the
	 * package list) are added one at a time.
	 */

	for (i = 0; (pkginst = a_pkgList[i]) != NULL; i++) {
		/*
		 * if immediate reboot required from last package and this is
		 * not 'pkgask' then suspend installation of remaining packages
		 */

		if ((ireboot != 0) && (askflag == 0)) {
			ptext(stderr, MSG_SUSPEND_ADD, pkginst);
				continue;
		}

		/*
		 * handle interrupt if the previous pkginstall was interrupted
		 */

		if (continue_installation() == B_FALSE) {
			return (B_FALSE);
		}

		/*
		 * if pkgask, handle response file creation:
		 * - if the response file is a directory, then create a path to
		 * -- a package instance within the response file directory.
		 * - If the response file is NOT a directory, if more than one
		 * -- package is to be installed.
		 */

		if ((askflag != 0) && (respdir != (char *)NULL)) {
			(void) snprintf(respfile_path, sizeof (respfile_path),
			    "%s/%s", respdir, pkginst);
			respfile = respfile_path;
		}

		echo(MSG_PROC_INST, pkginst, a_device);

		/*
		 * If we're installing another package in the same
		 * session, the second through nth pkginstall, must
		 * continue from where the prior one left off. For this
		 * reason, the continuation feature (implied by the
		 * nature of the command) is used for the remaining
		 * packages.
		 */

		if ((i == 1) && (pkgdrtarg != (char *)NULL)) {
			pkgcontsrc = pkgdrtarg;
		}

		/* reset interrupted flag before calling pkginstall */

		interrupted = 0;	/* last action was NOT quit */

		/* call pkginstall for this package */

		n = pkgInstall(get_inst_root(), NULL,
		    packageDir, a_altBinDir);

		/* set success/fail condition variables */

		ckreturn(n);

		/* decrement number of packages left to install */

		npkgs--;

		/*
		 * if no packages left to install, unmount package source
		 * device if appropriate
		 */

		if ((npkgs <= 0) && (pkgdev.mount || a_idsName)) {
			(void) chdir("/");
			if (!a_idsName) {
				(void) pkgumount(&pkgdev);
			}
		}
	}

	/*
	 * all packages in the package list have been installed.
	 * Continue with installation if:
	 * -- immediate reboot is NOT required
	 * -- there are more packages to install
	 * -- the package source is a path to a file
	 * else return do NOT continue.
	 */

	if ((ireboot == 0) && (a_repeat != 0) &&
	    (pkgdev.pathname == (char *)NULL)) {
		return (B_TRUE);
	}

	/* return 'dont continue' */

	return (B_FALSE);
}

/*
 * Function:	add_packages_in_global_no_zones
 * Description: call this function to add a list of packages in the global zone
 *		when no non-global zones exist
 * returns:
 *	B_TRUE to process next data stream
 *	B_FALSE to exit
 */

static boolean_t
add_packages_in_global_no_zones(char **a_pkgList,
    char *a_idsName, int a_repeat, char *a_altBinDir, char *a_device)
{
	int		n;
	int		i;
	char		respfile_path[PATH_MAX];
	CAF_T		flags = 0;

	/* entry assertions */

	assert(a_pkgList != (char **)NULL);

	echoDebug(DBG_ADDPACKAGES_GZ_NO_LZ_ENTRY);
	echoDebug(DBG_ADDPACKAGES_GZ_NO_LZ_ARGS, npkgs,
	    PSTR(a_idsName), a_repeat, PSTR(a_device));

	/*
	 * set flags for applicability check
	 */

	/* in the global zone */

	flags |= CAF_IN_GLOBAL_ZONE;

	/* set -G flag */

	if (globalZoneOnly == B_TRUE) {
		flags |= CAF_SCOPE_GLOBAL;
	}

	/*
	 * this is the main loop where all of the packages (as listed in the
	 * package list) are added one at a time.
	 */

	for (i = 0; (pkginst = a_pkgList[i]) != NULL; i++) {
		/*
		 * if immediate reboot required from last package and this is
		 * not 'pkgask' then suspend installation of remaining packages
		 */

		if ((ireboot != 0) && (askflag == 0)) {
			ptext(stderr, MSG_SUSPEND_ADD, pkginst);
				continue;
		}

		/*
		 * handle interrupt if the previous pkginstall was interrupted
		 */

		if (continue_installation() == B_FALSE) {
			return (B_FALSE);
		}

		/*
		 * check package applicability to install in this context
		 */

		if (check_applicability(pkgdev.dirname,
		    pkginst, get_inst_root(), flags) == B_FALSE) {
			progerr(ERR_PKG_NOT_APPLICABLE, pkginst);
			quit(1);
		}

		/*
		 * if pkgask, handle response file creation:
		 * - if the response file is a directory, then create a path to
		 * -- a package instance within the response file directory.
		 * - If the response file is NOT a directory, if more than one
		 * -- package is to be installed.
		 */

		if ((askflag != 0) && (respdir != (char *)NULL)) {
			(void) snprintf(respfile_path, sizeof (respfile_path),
			    "%s/%s", respdir, pkginst);
			respfile = respfile_path;
		}

		echo(MSG_PROC_INST, pkginst, a_device);

		/*
		 * If we're installing another package in the same
		 * session, the second through nth pkginstall, must
		 * continue from where the prior one left off. For this
		 * reason, the continuation feature (implied by the
		 * nature of the command) is used for the remaining
		 * packages.
		 */

		if ((i == 1) && (pkgdrtarg != (char *)NULL)) {
			pkgcontsrc = pkgdrtarg;
		}

		/* reset interrupted flag before calling pkginstall */

		interrupted = 0;	/* last action was NOT quit */

		/* call pkginstall for this package */

		n = pkgInstall(get_inst_root(), a_idsName,
		    pkgdev.dirname, a_altBinDir);

		/* set success/fail condition variables */

		ckreturn(n);

		/* decrement number of packages left to install */

		npkgs--;

		/*
		 * if no packages left to install, unmount package source
		 * device if appropriate
		 */

		if ((npkgs <= 0) && (pkgdev.mount || a_idsName)) {
			(void) chdir("/");
			if (!a_idsName) {
				(void) pkgumount(&pkgdev);
			}
		}
	}

	/*
	 * all packages in the package list have been installed.
	 * Continue with installation if:
	 * -- immediate reboot is NOT required
	 * -- there are more packages to install
	 * -- the package source is a path to a file
	 * else return do NOT continue.
	 */

	if ((ireboot == 0) && (a_repeat != 0) &&
	    (pkgdev.pathname == (char *)NULL)) {
		return (B_TRUE);
	}

	/* return 'dont continue' */

	return (B_FALSE);
}

/*
 * returns:
 *	B_TRUE to process next data stream
 *	B_FALSE to exit
 */

static boolean_t
add_packages(char **a_pkgList,
    char *a_idsName, int a_repeat, char *a_altBinDir, char *a_device,
    boolean_t a_noZones)
{
	zoneList_t	zlst;
	boolean_t	b;

	/* entry assertions */

	assert(a_pkgList != (char **)NULL);

	echoDebug(DBG_ADDPACKAGES_ENTRY);
	echoDebug(DBG_ADDPACKAGES_ARGS, npkgs, PSTR(a_idsName),
	    a_repeat, PSTR(a_altBinDir), PSTR(a_device));

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

		b = add_packages_in_nonglobal_zone(a_pkgList, a_idsName,
		    a_repeat, a_altBinDir, a_device);

		(void) z_unlock_this_zone(ZLOCKS_ALL);

		return (B_FALSE);
	}

	/* running in the global zone */

	b = z_non_global_zones_exist();
	if ((a_noZones == B_FALSE) && (b == B_TRUE) &&
	    (globalZoneOnly == B_FALSE)) {

		echoDebug(DBG_IN_GZ_WITH_LZ);

		/* error if -V specified - what to use in non-global zone? */

		if (vfstab_file) {
			progerr(ERR_V_USED_WITH_GZS);
			quit(1);
		}

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

		b = add_packages_in_global_with_zones(a_pkgList,
		    a_idsName, a_repeat, a_altBinDir, a_device, zlst);

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

	b = add_packages_in_global_no_zones(a_pkgList, a_idsName,
	    a_repeat, a_altBinDir, a_device);

	(void) z_unlock_this_zone(ZLOCKS_ALL);

	return (B_FALSE);
}
