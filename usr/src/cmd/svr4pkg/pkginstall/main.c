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


#include <stdio.h>
#include <time.h>
#include <wait.h>
#include <stdlib.h>
#include <unistd.h>
#include <ulimit.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <string.h>
#include <signal.h>
#include <locale.h>
#include <libintl.h>
#include <pkgstrct.h>
#include <pkginfo.h>
#include <pkgdev.h>
#include <pkglocs.h>
#include <pwd.h>
#include <assert.h>
#include <instzones_api.h>
#include <pkglib.h>
#include <install.h>
#include <libinst.h>
#include <libadm.h>
#include <dryrun.h>
#include <messages.h>
#include "pkginstall.h"

/* imported globals */

extern char	**environ;
extern char	*pkgabrv;
extern char	*pkgname;
extern char	*pkgarch;
extern char	*pkgvers;
extern char	pkgwild[];

/* libadm(3LIB) */

extern char	*get_install_root(void);

/* quit.c */

extern sighdlrFunc_t	*quitGetTrapHandler(void);
extern void		quitSetDstreamTmpdir(char *a_dstreamTempDir);
extern void		quitSetInstallStarted(boolean_t a_installStarted);
extern void		quitSetPkgask(boolean_t a_pkgaskFlag);
extern void		quitSetSilentExit(boolean_t a_silentExit);
extern void		quitSetUpdatingExisting(boolean_t a_updatingExisting);
extern void		quitSetZoneName(char *a_zoneName);


/* static globals */

static char	path[PATH_MAX];
static int	ck_instbase(void);
static int	cp_pkgdirs(void);
static int	merg_pkginfos(struct cl_attr **pclass,
		struct cl_attr ***mpclass);
static int	merg_respfile(void);
static int	mv_pkgdirs(void);
static int	rdonly(char *p);
static void	ck_w_dryrun(int (*func)(), int type);
static void	copyright(void), usage(void);
static void	do_pkgask(boolean_t a_run_request_as_root);
static void	rm_icas(char *casdir);
static void	set_dryrun_dir_loc(void);
static void	unpack(void);

void	ckreturn(int retcode, char *msg);

static char	*ro_params[] = {
	"PATH", "NAME", "PKG", "PKGINST",
	"VERSION", "ARCH",
	"INSTDATE", "CATEGORY",
	NULL
};

/*
 * The following variable is the name of the device to which stdin
 * is connected during execution of a procedure script. PROC_STDIN is
 * correct for all ABI compliant packages. For non-ABI-compliant
 * packages, the '-o' command line switch changes this to PROC_XSTDIN
 * to allow user interaction during these scripts. -- JST
 */
static char	*script_in = PROC_STDIN;	/* assume ABI compliance */

static char	*pkgdrtarg = NULL;
static char	*pkgcontsrc = NULL;
static int	non_abi_scripts = 0;
static char	*respfile = NULL;
static char	*srcinst = NULL;
static int	suppressCopyright = 0;
static int	nointeract = 0;

/* exported globals */

char		*msgtext;
char		*pkginst = (char *)NULL;
char		*rw_block_size = NULL;
char		ilockfile[PATH_MAX];
char		instdir[PATH_MAX];
char		saveSpoolInstallDir[PATH_MAX];
char		pkgbin[PATH_MAX];
char		pkgloc[PATH_MAX];
char		pkgloc_sav[PATH_MAX];
char		pkgsav[PATH_MAX];
char		rlockfile[PATH_MAX];
char		savlog[PATH_MAX];
char		tmpdir[PATH_MAX];
int		dbchg;
int		dparts = 0;
int		dreboot = 0;
int		failflag = 0;
static int	askflag = 0;		/* non-zero if invoked as "pkgask" */
int		ireboot = 0;
int		maxinst = 1;
int		nocnflct;
int		nosetuid;
int		pkgverbose = 0;
int		rprcflag;
int		warnflag = 0;
struct admin	adm;
struct cfextra	**extlist; /* pkgmap structure and other path info */
struct pkgdev	pkgdev;
fsblkcnt_t	pkgmap_blks = 0LL;

/*
 * this global is referenced by:
 * getinst - [RW] - incremented if:
 * - installing same instance again
 * - overwriting an existing instance
 * - not installing a new instance
 * quit - [RO] - if non-zero and started non-zero:
 * - the new <PKGINST>/install directory and rename <PKGINST>/install.save
 * - back to <PKGINST>/install
 * main.c - [RO] - if non-zero:
 * - alter manner in which parameters are setup for scripts
 * - set UPDATE=yes in environment
 */
static int		update = 0;

/* Set by -O debug: debug output is enabled? */

static boolean_t	debugFlag = B_FALSE;

/* Set by the -G option: install packages in global zone only */

static boolean_t	globalZoneOnly = B_FALSE;

/* Set by -O preinstallcheck */

static boolean_t	preinstallCheck = B_FALSE;

/* Set by -O parent-zone-name= */

static char		*parentZoneName = (char *)NULL;

/* Set by -O parent-zone-type= */

static char		*parentZoneType = (char *)NULL;

#define	DEFPATH		"/sbin:/usr/sbin:/usr/bin"
#define	MALSIZ	4	/* best guess at likely maximum value of MAXINST */
#define	LSIZE	256	/* maximum line size supported in copyright file */

#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"
#endif

/* This is the text for the "-O parent-zone-name=" option */

#define	PARENTZONENAME	"parent-zone-name="
#define	PARENTZONENAME_LEN	((sizeof (PARENTZONENAME))-1)

/* This is the text for the "-O parent-zone-type=" option */

#define	PARENTZONETYPE	"parent-zone-type="
#define	PARENTZONETYPE_LEN	((sizeof (PARENTZONETYPE))-1)

static char *cpio_names[] = {
	"root",
	"root.cpio",
	"reloc",
	"reloc.cpio",
	"root.Z",
	"root.cpio.Z",
	"reloc.Z",
	"reloc.cpio.Z",
	0
};

int
main(int argc, char *argv[])
{
	VFP_T			*cfTmpVfp = NULL;	/* temporary */
	VFP_T			*pkgmapVfp;	/* "../pkgmap" file */
	boolean_t		run_request_as_root = B_FALSE;
	char			**np;
	char			*abi_comp_ptr;
	char			*abi_nm_ptr;
	char			*abi_sym_ptr;
	char			*admnfile = NULL;
	char			*device;
	char			*p;
	char			*prog_full_name = NULL;
	char			*pt;
	char			*updated = (char *)NULL;
	char			*vfstab_file = NULL;
	char			*zoneName = (char *)NULL;
	char			cbuf[MAX_PKG_PARAM_LENGTH];
	char			cmdbin[PATH_MAX];
	char			p_pkginfo[PATH_MAX];
	char			p_pkgmap[PATH_MAX];
	char			param[MAX_PKG_PARAM_LENGTH];
	char			script[PATH_MAX];
	char			altscript[PATH_MAX];
	char			*temp;
	int			c;
	int			disableAttributes = 0;
	int			err;
	int			init_install = 0;
	int			is_comp_arch;
	int			live_continue = 0;
	int			map_client = 1;
	int			n;
	int			nparts;
	int			npkgs;
	int			part;
	int			saveSpoolInstall = 0;
	boolean_t		cont_file_read;
	struct cl_attr		**pclass = NULL;
	struct cl_attr		**mergd_pclass = NULL;
	struct pkginfo		*prvinfo;
	struct sigaction	nact;
	struct sigaction	oact;
	struct stat		statb;
	struct statvfs64	svfsb;
	time_t			clock;
	PKGserver		pkgserver = NULL;

	/* reset contents of all default paths */

	(void) memset(path, '\0', sizeof (path));
	(void) memset(cmdbin, '\0', sizeof (cmdbin));
	(void) memset(script, '\0', sizeof (script));
	(void) memset(cbuf, '\0', sizeof (cbuf));
	(void) memset(param, '\0', sizeof (param));

	/* initialize locale environment */

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	/* initialize program name */

	prog_full_name = argv[0];
	(void) set_prog_name(argv[0]);

	/* tell spmi zones interface how to access package output functions */

	z_set_output_functions(echo, echoDebug, progerr);

	/* exit if not root */

	if (getuid()) {
		progerr(ERR_NOT_ROOT, get_prog_name());
		exit(1);
		/* NOTREACHED */
	}

	/*
	 * determine how pkgmap() deals with environment variables:
	 *  - MAPALL - resolve all variables
	 *  - MAPBUILD - map only build variables
	 *  - MAPINSTALL - map only install variables
	 *  - MAPNONE - map no variables
	 */

	setmapmode(MAPINSTALL);

	/* set sane umask */

	(void) umask(0022);

	/* initially no source "device" */

	device = NULL;

	/* reset npkgs (used as pkg remaining count in quit.c) */

	npkgs = 0;

	/* Read PKG_INSTALL_ROOT from the environment, if it's there. */

	if (!set_inst_root(getenv("PKG_INSTALL_ROOT"))) {
		progerr(ERR_ROOT_SET);
		exit(1);
	}

	pkgserversetmode(DEFAULTMODE);

	/* parse command line options */

	while ((c = getopt(argc, argv,
		"?Aa:B:b:Cc:D:d:eFf:GhIiMm:N:noO:p:R:r:StV:vyz")) != EOF) {

		switch (c) {

		/*
		 * Same as pkgadd: This disables attribute checking.
		 * It speeds up installation a little bit.
		 */
		case 'A':
			disableAttributes++;
			break;

		/*
		 * Same as pkgadd: Define an installation administration
		 * file, admin, to be used in place of the default
		 * administration file.  The token none overrides the use
		 * of any admin file, and thus forces interaction with the
		 * user. Unless a full path name is given, pkgadd first
		 * looks in the current working directory for the
		 * administration file.  If the specified administration
		 * file is not in the current working directory, pkgadd
		 * looks in the /var/sadm/install/admin directory for the
		 * administration file.
		 */
		case 'a':
			admnfile = flex_device(optarg, 0);
			break;

		/*
		 * Same as pkgadd: control block size given to
		 * pkginstall - block size used in read()/write() loop;
		 * default is st_blksize from stat() of source file.
		 */
		case 'B':
			rw_block_size = optarg;
			break;

		/*
		 * Same as pkgadd: location where executables needed
		 * by procedure scripts can be found
		 * default is /usr/sadm/install/bin.
		 */
		case 'b':
			if (!path_valid(optarg)) {
				progerr(ERR_PATH, optarg);
				exit(1);
			}
			if (isdir(optarg) != 0) {
				char *p = strerror(errno);
				progerr(ERR_CANNOT_USE_DIR, optarg, p);
				exit(1);
			}
			(void) strlcpy(cmdbin, optarg, sizeof (cmdbin));
			break;

		/*
		 * Same as pkgadd: This disables checksum tests on
		 * the source files. It speeds up installation a little bit.
		 */
		case 'C':
			(void) checksum_off();
			break;

		/*
		 * Same as pkgadd: This allows designation of a
		 * continuation file. It is the same format as a dryrun file
		 * but it is used to take up where the dryrun left off.
		 */
		case 'c':
			pkgcontsrc = optarg;
			set_continue_mode();
			set_dr_info(DR_TYPE, INSTALL_TYPE);
			init_contfile(pkgcontsrc);
			break;

		/*
		 * Same as pkgadd: This allows designation of a
		 * dryrun file. This pkgadd will create dryrun files
		 * in the directory provided.
		 */
		case 'D':
			pkgdrtarg = optarg;
			set_dryrun_mode();
			set_dr_info(DR_TYPE, INSTALL_TYPE);
			break;

		/*
		 * Same as pkgadd: Install or copy a package from
		 * device. device can be a full path name to a directory
		 * or the identifiers for tape, floppy disk, or removable
		 * disk - for example, /var/tmp or /floppy/floppy_name.
		 * It can also be a device alias - for example,
		 * /floppy/floppy0, or a datastream created by pkgtrans.
		 */
		case 'd':
			device = flex_device(optarg, 1);
			break;

		/*
		 * Different from pkgadd: disable the 32 char name
		 * limit extension
		 */
		case 'e':
			(void) set_ABI_namelngth();
			break;

		/*
		 * Different from pkgadd: specify file system type for
		 * the package device. Must be used with -m.
		 */
		case 'f':
			pkgdev.fstyp = optarg;
			break;

		/*
		 * Same as pkgadd: install package in global zone only.
		 */
		case 'G':
			globalZoneOnly = B_TRUE;
			break;

		/*
		 * Same as pkgadd: Enable hollow package support. When
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
		 * Same as pkgadd: Informs scripts that this is
		 * an initial install by setting the environment parameter
		 * PKG_INIT_INSTALL=TRUE for all scripts. They may use it as
		 * they see fit, safe in the knowledge that the target
		 * filesystem is tabula rasa.
		 */
		case 'I':
			init_install++;
			break;

		/*
		 * Different from pkgadd: use by pkgask.
		 */
		case 'i':
			askflag++;
			quitSetPkgask(B_TRUE);
			break;

		/*
		 * Same as pkgadd: Instruct pkgadd not to use the
		 * $root_path/etc/vfstab file for determining the client's
		 * mount points. This option assumes the mount points are
		 * correct on the server and it behaves consistently with
		 * Solaris 2.5 and earlier releases.
		 */
		case 'M':
			map_client = 0;
			break;

		/*
		 * Different from pkgadd: specify device to use for package
		 * source.
		 */
		case 'm':
			pkgdev.mount = optarg;
			pkgdev.rdonly++;
			pkgdev.mntflg++;
			break;

		/*
		 * Different from pkgadd: specify program name to use
		 * for messages.
		 */
		case 'N':
			(void) set_prog_name(optarg);
			break;

		/*
		 * Same as pkgadd: installation occurs in
		 * non-interactive mode.  Suppress output of the list of
		 * installed files. The default mode is interactive.
		 */
		case 'n':
			nointeract++;
			(void) echoSetFlag(B_FALSE);
			break;

		/*
		 * Almost same as pkgadd: the -O option allows the behavior
		 * of the package tools to be modified. Recognized options:
		 * -> debug
		 * ---> enable debugging output
		 * -> preinstallcheck
		 * ---> perform a "pre installation" check of the specified
		 * ---> package - suppress all regular output and cause a
		 * ---> series of one or more "name=value" pair format lines
		 * ---> to be output that describes the "installability" of
		 * ---> the specified package
		 * -> enable-hollow-package-support
		 * --> Enable hollow package support. When specified, for any
		 * --> package that has SUNW_PKG_HOLLOW=true:
		 * --> Do not calculate and verify package size against target
		 * --> Do not run any package procedure or class action scripts
		 * --> Do not create or remove any target directories
		 * --> Do not perform any script locking
		 * --> Do not install or uninstall any components of any package
		 * --> Do not output any status or database update messages
		 */
		case 'O':
			for (p = strtok(optarg, ","); p != (char *)NULL;
				p = strtok(NULL, ",")) {

				/* process debug option */

				if (strcmp(p, "debug") == 0) {
					/* set debug flag/enable debug output */
					if (debugFlag == B_TRUE) {
						smlSetVerbose(B_TRUE);
					}
					debugFlag = B_TRUE;
					(void) echoDebugSetFlag(debugFlag);

					/* debug info on arguments to pkgadd */
					for (n = 0; n < argc && argv[n]; n++) {
						echoDebug(DBG_ARG, n, argv[n]);
					}

					continue;
				}

				/* process enable-hollow-package-support opt */

				if (strcmp(p,
					"enable-hollow-package-support") == 0) {
					set_depend_pkginfo_DB(B_TRUE);
					continue;
				}

				/* process preinstallcheck option */

				if (strcmp(p, "preinstallcheck") == 0) {
					preinstallCheck = B_TRUE;
					nointeract++;	/* -n */
					suppressCopyright++;	/* -S */
					quitSetSilentExit(B_TRUE);
					continue;
				}

				/* process addzonename option */

				if (strcmp(p, "addzonename") == 0) {
					/*
					 * set zone name to add to messages;
					 * first look in the current environment
					 * and use the default package zone name
					 * if it is set; otherwise, use the name
					 * of the current zone
					 */
					zoneName =
						getenv(PKG_ZONENAME_VARIABLE);

					if ((zoneName == (char *)NULL) ||
							(*zoneName == '\0')) {
						zoneName = z_get_zonename();
					}

					if (zoneName != (char *)NULL) {
						if (*zoneName != '\0') {
							quitSetZoneName(
								zoneName);
						} else {
							zoneName = (char *)NULL;
						}
					}
					continue;
				}

				/* process parent-zone-name option */

				if (strncmp(p, PARENTZONENAME,
						PARENTZONENAME_LEN) == 0) {
					parentZoneName = p+PARENTZONENAME_LEN;
					continue;
				}

				/* process parent-zone-type option */

				if (strncmp(p, PARENTZONETYPE,
						PARENTZONETYPE_LEN) == 0) {
					parentZoneType = p+PARENTZONETYPE_LEN;
					continue;
				}

				if (strncmp(p, PKGSERV_MODE,
				    PKGSERV_MODE_LEN) == 0) {
					pkgserversetmode(pkgparsemode(p +
					    PKGSERV_MODE_LEN));
					continue;
				}

				/* option not recognized - issue warning */

				progerr(ERR_INVALID_O_OPTION, p);
				continue;

			}
			break;

		/*
		 * Different from pkgadd: This is an old non-ABI package
		 */
		case 'o':
			non_abi_scripts++;
			break;

		/*
		 * Different from pkgadd: specify number of parts to package.
		 */
		case 'p':
			dparts = ds_getinfo(optarg);
			break;

		/*
		 * Same as pkgadd: Define the full path name of a
		 * directory to use as the root_path.  All files,
		 * including package system information files, are
		 * relocated to a directory tree starting in the specified
		 * root_path. The root_path may be specified when
		 * installing to a client from a server (for example,
		 * /export/root/client1).
		 */
		case 'R':
			if (!set_inst_root(optarg)) {
				progerr(ERR_ROOT_CMD);
				exit(1);
			}
			break;

		/*
		 * Same as pkgadd: Identify a file or directory which
		 * contains output from a previous pkgask(1M)
		 * session. This file supplies the interaction responses
		 * that would be requested by the package in interactive
		 * mode. response must be a full pathname.
		 */
		case 'r':
			respfile = flex_device(optarg, 2);
			break;

		/*
		 * Same as pkgadd: suppress copyright notice being
		 * output during installation.
		 */
		case 'S':
			suppressCopyright++;
			break;

		/*
		 * Same as pkgadd: disable save spool area creation;
		 * do not spool any partial package contents, that is,
		 * suppress the creation and population of the package save
		 * spool area (var/sadm/pkg/PKG/save/pspool/PKG).
		 */
		case 't':
			disable_spool_create();
			break;

		/*
		 * Same as pkgadd: Specify an alternative fs_file to map
		 * the client's file systems.  For example, used in
		 * situations where the $root_path/etc/vfstab file is
		 * non-existent or unreliable. Informs the pkginstall
		 * portion to mount up a client filesystem based upon the
		 * supplied vfstab-like file of stable format.
		 */
		case 'V':
			vfstab_file = flex_device(optarg, 2);
			map_client = 1;
			break;

		/*
		 * Same as pkgadd: Trace all of the scripts that get
		 * executed by pkgadd, located in the pkginst/install
		 * directory. This option is used for debugging the
		 * procedural and non-procedural scripts
		 */
		case 'v':
			pkgverbose++;
			break;

		/*
		 * Different from pkgadd: process this package using
		 * old non-ABI symlinks
		 */
		case 'y':
			set_nonABI_symlinks();
			break;

		/*
		 * Same as pkgadd: perform fresh install from
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
	 * ********************************************************************
	 * validate command line options
	 * ********************************************************************
	 */

	/* set "debug echo" flag according to setting of "-O debug" option */

	(void) echoDebugSetFlag(debugFlag);
	(void) log_set_verbose(debugFlag);

	/* output entry debugging information */

	if (z_running_in_global_zone()) {
		echoDebug(DBG_ENTRY_IN_GZ, prog_full_name);
	} else {
		echoDebug(DBG_ENTRY_IN_LZ, prog_full_name, getzoneid(),
		    z_get_zonename());
	}

	if (in_continue_mode() && !in_dryrun_mode()) {
		progerr(ERR_LIVE_CONTINUE_NOT_SUPPORTED);
		usage();
		/*NOTREACHED*/
	}

	/* pkgask requires a response file */

	if (askflag && (respfile == NULL)) {
		usage();
		/*NOTREACHED*/
	}

	/* if device specified, set appropriate device in pkgdev */

	if (device) {
		if (pkgdev.mount) {
			pkgdev.bdevice = device;
		} else {
			pkgdev.cdevice = device;
		}
	}

	/* if file system type specified, must have a device to mount */

	if (pkgdev.fstyp && !pkgdev.mount) {
		progerr(ERR_F_REQUIRES_M);
		usage();
		/*NOTREACHED*/
	}

	/* BEGIN DATA GATHERING PHASE */

	/*
	 * Get the mount table info and store internally.
	 */
	cont_file_read = B_FALSE;
	if (in_continue_mode()) {
		int error;
		cont_file_read = read_continuation(&error);
		if (error == -1) {
			quit(99);
			/*NOTREACHED*/
		}
		if (!in_dryrun_mode()) {
			live_continue = 1;
		}
	}
	/* Read the mount table if not done in continuation mode */
	if (!cont_file_read) {
		if (get_mntinfo(map_client, vfstab_file)) {
			quit(99);
			/*NOTREACHED*/
		}
	}

	/*
	 * This function defines the standard /var/... directories used later
	 * to construct the paths to the various databases.
	 */

	set_PKGpaths(get_inst_root());

	/*
	 * If this is being installed on a client whose /var filesystem is
	 * mounted in some odd way, remap the administrative paths to the
	 * real filesystem. This could be avoided by simply mounting up the
	 * client now; but we aren't yet to the point in the process where
	 * modification of the filesystem is permitted.
	 */
	if (is_an_inst_root()) {
		int fsys_value;

		fsys_value = fsys(get_PKGLOC());
		if (use_srvr_map_n(fsys_value))
			set_PKGLOC(server_map(get_PKGLOC(), fsys_value));

		fsys_value = fsys(get_PKGADM());
		if (use_srvr_map_n(fsys_value))
			set_PKGADM(server_map(get_PKGADM(), fsys_value));
	}

	/*
	 * Initialize pkginfo PKGSAV entry, just in case we dryrun to
	 * somewhere else.
	 */
	set_infoloc(get_PKGLOC());

	/* pull off directory and package name from end of command line */

	switch (argc-optind) {
	case 0:	/* missing directory and package instance */
		progerr(ERR_MISSING_DIR_AND_PKG);
		usage();
		/*NOTREACHED*/
	case 1: /* missing package instance */
		progerr(ERR_MISSING_PKG_INSTANCE);
		usage();
		/*NOTREACHED*/
	case 2:	/* just right! */
		pkgdev.dirname = argv[optind++];
		srcinst = argv[optind++];
		break;
	default:	/* too many args! */
		progerr(ERR_TOO_MANY_CMD_ARGS);
		usage();
		break;
	}

	(void) pkgparam(NULL, NULL);  /* close up prior pkg file if needed */

	/*
	 * Initialize installation admin parameters by reading
	 * the adminfile.
	 */

	if (!askflag && !live_continue) {
		echoDebug(DBG_PKGINSTALL_ADMINFILE, admnfile ? admnfile : "");
		setadminFile(admnfile);
	}

	/*
	 * about to perform first operation that could be modified by the
	 * preinstall check option - if preinstall check is selected (that is,
	 * only gathering dependencies), then output a debug message to
	 * indicate that the check is beginning. Also turn echo() output
	 * off and set various other flags.
	 */

	if (preinstallCheck == B_TRUE) {
		(void) echoSetFlag(B_FALSE);
		echoDebug(DBG_PKGINSTALL_PREINSCHK,
			pkginst ? pkginst : (srcinst ? srcinst : ""),
			zoneName ? zoneName : "global");
		cksetPreinstallCheck(B_TRUE);
		cksetZoneName(zoneName);
		/* inform quit that the install has started */
		quitSetInstallStarted(B_TRUE);
	}

	/*
	 * validate the "rscriptalt" admin file setting
	 * The rscriptalt admin file parameter may be set to either
	 * RSCRIPTALT_ROOT or RSCRIPTALT_NOACCESS:
	 * --> If rscriptalt is not set, or is set to RSCRIPTALT_NOACCESS,
	 * --> or is set to any value OTHER than RSCRIPTALT_ROOT, then
	 * --> assume that the parameter is set to RSCRIPTALT_NOACCESS
	 * If rscriptalt is set to RSCRIPTALT_ROOT, then run request scripts
	 * as the "root" user if user "install" is not defined.
	 * Otherwise, assume rscriptalt is set to RSCRIPTALT_NOACCESS, and run
	 * request scripts as the "alternative" user if user "install" is not
	 * defined, as appropriate for the current setting of the NONABI_SCRIPTS
	 * environment variable.
	 */

	if (ADMSET(RSCRIPTALT)) {
		p = adm.RSCRIPTALT;
		echoDebug(DBG_PKGINSTALL_RSCRIPT_SET_TO, RSCRIPTALT_KEYWORD, p);
		if (strcasecmp(p, RSCRIPTALT_ROOT) == 0) {
			/* rscriptalt=root */
			run_request_as_root = B_TRUE;
		} else if (strcasecmp(p, RSCRIPTALT_NOACCESS) == 0) {
			/* rscriptalt=noaccess */
			run_request_as_root = B_FALSE;
		} else {
			/* rscriptalt=??? */
			logerr(WRN_RSCRIPTALT_BAD, RSCRIPTALT_KEYWORD, p,
				RSCRIPTALT_ROOT, RSCRIPTALT_NOACCESS);
			logerr(WRN_RSCRIPTALT_USING, RSCRIPTALT_KEYWORD,
				RSCRIPTALT_NOACCESS);
			run_request_as_root = B_FALSE;
		}
	} else {
		/* rscriptalt not set - assume rscriptalt=noaccess */
		echoDebug(DBG_PKGINSTALL_RSCRIPT_NOT_SET, RSCRIPTALT_KEYWORD);
		run_request_as_root = B_FALSE;
	}

	echoDebug(DBG_PKGINSTALL_RSCRIPT_IS_ROOT, run_request_as_root);

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
	 * create required /var... directories if they do not exist;
	 * this function will call quit(99) if any required path cannot
	 * be created.
	 */

	ckdirs();

	tzset();

	/*
	 * create path to temporary directory "installXXXXXX" - if TMPDIR
	 * environment variable is set, create the directory in $TMPDIR;
	 * otherwise, create the directory in P_tmpdir.
	 */

	pt = getenv("TMPDIR");
	(void) snprintf(tmpdir, sizeof (tmpdir), "%s/installXXXXXX",
		((pt != (char *)NULL) && (*pt != '\0')) ? pt : P_tmpdir);

	echoDebug(DBG_PKGINSTALL_TMPDIR, tmpdir);

	if ((mktemp(tmpdir) == NULL) || mkdir(tmpdir, 0771)) {
		progerr(ERR_MKDIR, tmpdir);
		quit(99);
		/*NOTREACHED*/
	}

	/*
	 * if the package device is a file containing a package stream,
	 * unpack the stream into a temporary directory
	 */

	if ((isdir(pkgdev.dirname) != 0) &&
		(pkgdev.cdevice == (char *)NULL) &&
		(pkgdev.bdevice == (char *)NULL) &&
		(isfile((char *)NULL, pkgdev.dirname) == 0)) {

		char		*idsName = (char *)NULL;
		char		*pkgnames[2];
		char		*device = pkgdev.dirname;
		boolean_t	b;

		echoDebug(DBG_PKGINSTALL_DS_ISFILE, pkgdev.dirname);

		/*
		 * validate the package source device - return pkgdev info that
		 * describes the package source device.
		 */

		if (devtype(device, &pkgdev)) {
			progerr(ERR_BAD_DEVICE, device);
			quit(99);
			/* NOTREACHED */
		}

		/* generate the list of packages to verify */

		pkgnames[0] = srcinst;
		pkgnames[1] = (char *)NULL;

		b = open_package_datastream(1, pkgnames, (char *)NULL,
			pkgdev.dirname, (int *)NULL, &idsName, tmpdir, &pkgdev,
			1);

		if (b == B_FALSE) {
			progerr(ERR_CANNOT_OPEN_PKG_STREAM,
				pkgdev.dirname ? pkgdev.dirname : "?");
			quit(99);
			/*NOTREACHED*/
		}

		/* make sure temporary directory is removed on exit */

		quitSetDstreamTmpdir(pkgdev.dirname);

		/* unpack the package instance from the data stream */

		b = unpack_package_from_stream(idsName, srcinst,
							pkgdev.dirname);
		if (b == B_FALSE) {
			progerr(ERR_CANNOT_UNPACK_PKGSTRM,
				srcinst ? srcinst : "?",
				idsName ? idsName : "?",
				pkgdev.dirname ? pkgdev.dirname : "?");
			quit(99);
			/*NOTREACHED*/
		}

		/* close the datastream - no longer needed */

		echoDebug(DBG_CLOSING_STREAM, idsName, pkgdev.dirname);
		(void) ds_close(1);
	}

	if (snprintf(instdir, PATH_MAX, "%s/%s", pkgdev.dirname, srcinst)
	    >= PATH_MAX) {
		progerr(ERR_SNPRINTF, instdir);
		quit(99);
		/*NOTREACHED*/
	}

	zoneName = getenv(PKG_ZONENAME_VARIABLE);

	/*
	 * If the environment has a CLIENT_BASEDIR, that takes precedence
	 * over anything we will construct. We need to save it here because
	 * in three lines, the current environment goes away.
	 */
	(void) set_env_cbdir();	/* copy over environ */

	getuserlocale();

	/*
	 * current environment has been read; clear environment out
	 * so putparam() can be used to populate the new environment
	 * to be passed to any executables/scripts.
	 */

	environ = NULL;

	/* write parent condition information to environment */

	putConditionInfo(parentZoneName, parentZoneType);

	putuserlocale();

	if (init_install) {
		putparam("PKG_INIT_INSTALL", "TRUE");
	}

	if (is_an_inst_root()) {
		export_client_env(get_inst_root());
	}

	if (zoneName != (char *)NULL) {
		putparam(PKG_ZONENAME_VARIABLE, zoneName);
	}

	putparam("INST_DATADIR", pkgdev.dirname);

	if (non_abi_scripts) {
		putparam("NONABI_SCRIPTS", "TRUE");
	}

	if (nonABI_symlinks()) {
		putparam("PKG_NONABI_SYMLINKS", "TRUE");
	}

	if (get_ABI_namelngth()) {
		putparam("PKG_ABI_NAMELENGTH", "TRUE");
	}

	/* establish path and oambase */

	if (cmdbin[0] == '\0') {
		(void) strlcpy(cmdbin, PKGBIN, sizeof (cmdbin));
	}

	(void) snprintf(path, sizeof (path), "%s:%s", DEFPATH, cmdbin);

	putparam("PATH", path);

	putparam("OAMBASE", OAMBASE);

	(void) snprintf(p_pkginfo, sizeof (p_pkginfo),
			"%s/%s", instdir, PKGINFO);
	(void) snprintf(p_pkgmap, sizeof (p_pkgmap),
			"%s/%s", instdir, PKGMAP);

	/* Read the environment (from pkginfo or '-e') ... */
	abi_nm_ptr = getenv("PKG_ABI_NAMELENGTH");

	/* Disable the 32 char name limit extension */
	if (abi_nm_ptr && strncasecmp(abi_nm_ptr, "TRUE", 4) == 0) {
		(void) set_ABI_namelngth();
	}

	/*
	 * This tests the pkginfo and pkgmap files for validity and
	 * puts all delivered pkginfo variables (except for PATH) into
	 * our environment. This is where a delivered pkginfo BASEDIR
	 * would come from. See set_basedirs() below.
	 */

	if (pkgenv(srcinst, p_pkginfo, p_pkgmap)) {
		quit(1);
		/*NOTREACHED*/
	}

	echo("\n%s(%s) %s", pkgname, pkgarch, pkgvers);

	/*
	 * If this script was invoked by 'pkgask', just
	 * execute request script and quit (do_pkgask()).
	 */

	if (askflag) {
		do_pkgask(run_request_as_root);
	}

	/* validate package contents file */

	if (vcfile() == 0) {
		quit(99);
	}

	/* if not in dryrun mode aquire packaging lock */

	if (!in_dryrun_mode()) {
		/* acquire the package lock - at install initialization */
		if (!lockinst(get_prog_name(), srcinst, "install-initial")) {
			quit(99);
			/*NOTREACHED*/
		}
	}

	/*
	 * Now do all the various setups based on ABI compliance
	 */

	/* Read the environment (from pkginfo or '-o') ... */
	abi_comp_ptr = getenv("NONABI_SCRIPTS");

	/* Read the environment (from pkginfo or '-y') ... */
	abi_sym_ptr = getenv("PKG_NONABI_SYMLINKS");

	/* bug id 4244631, not ABI compliant */
	if (abi_comp_ptr && strncasecmp(abi_comp_ptr, "TRUE", 4) == 0) {
		script_in = PROC_XSTDIN;
		non_abi_scripts = 1;
	}

	/* Set symlinks to be processed the old way */
	if (abi_sym_ptr && strncasecmp(abi_sym_ptr, "TRUE", 4) == 0) {
		set_nonABI_symlinks();
	}

	/*
	 * At this point, script_in, non_abi_scripts & the environment are
	 * all set correctly for the ABI status of the package.
	 */

	if (pt = getenv("MAXINST")) {
		maxinst = atol(pt);
	}

	/*
	 * See if were are installing a package that only wants to update
	 * the database or only install files associated with CAS's. We
	 * only check the PKG_HOLLOW_VARIABLE variable if told to do so by
	 * the caller.
	 */

	if (is_depend_pkginfo_DB()) {
		pt = getenv(PKG_HOLLOW_VARIABLE);
		if ((pt != NULL) && (strncasecmp(pt, "true", 4) == 0)) {
			echoDebug(DBG_PKGREMOVE_HOLLOW_ENABLED);
			if (disableAttributes) {
				disable_attribute_check();
			}

			/*
			 * this is a hollow package and hollow package support
			 * is enabled -- override admin settings to suppress
			 * checks that do not make sense since no scripts will
			 * be executed and no files will be installed.
			 */

			setadminSetting("conflict", "nocheck");
			setadminSetting("setuid", "nocheck");
			setadminSetting("action", "nocheck");
			setadminSetting("partial", "nocheck");
			setadminSetting("space", "nocheck");
			setadminSetting("authentication", "nocheck");
		} else {
			echoDebug(DBG_PKGREMOVE_HOLLOW_DISABLED);
			set_depend_pkginfo_DB(B_FALSE);
		}
	}

	/*
	 * if performing a fresh install to a non-global zone, and doing
	 * more than just updating the package database (that is, the
	 * package to install is NOT "hollow"), then set the global flag
	 * that directs installation is from partially spooled packages
	 * (that is, packages installed in the global zone).
	 */

	if (saveSpoolInstall && (!is_depend_pkginfo_DB())) {
		set_partial_inst();
	} else {
		saveSpoolInstall = 0;
	}

	/*
	 * verify that we are not trying to install an
	 * INTONLY package with no interaction
	 */

	if (pt = getenv("INTONLY")) {
		if (askflag || nointeract) {
			progerr(ERR_INTONLY, pkgabrv ? pkgabrv : "?");
			quit(1);
			/*NOTREACHED*/
		}
	}

	if (!suppressCopyright && !pkgdev.cdevice) {
		copyright();
	}

	/*
	 * inspect the system to determine if any instances of the
	 * package being installed already exist on the system
	 */

	prvinfo = (struct pkginfo *)calloc(MALSIZ, sizeof (struct pkginfo));
	if (prvinfo == NULL) {
		progerr(ERR_MEMORY, errno);
		quit(99);
		/*NOTREACHED*/
	}

	for (;;) {
		if (pkginfo(&prvinfo[npkgs], pkgwild, NULL, NULL)) {
			if ((errno == ESRCH) || (errno == ENOENT)) {
				break;
			}
			progerr(ERR_SYSINFO, errno);
			quit(99);
			/*NOTREACHED*/
		}
		if ((++npkgs % MALSIZ) == 0) {
			prvinfo = (struct pkginfo *)realloc(prvinfo,
				(npkgs+MALSIZ) * sizeof (struct pkginfo));
			if (prvinfo == NULL) {
				progerr(ERR_MEMORY, errno);
				quit(99);
				/*NOTREACHED*/
			}
		}
	}

	/*
	 * Determine the correct package instance based on how many packages are
	 * already installed. If there are none (npkgs == 0), getinst() just
	 * returns the package abbreviation. Otherwise, getinst() interacts with
	 * the user (or reads the admin file) to determine if an instance which
	 * is already installed should be overwritten, or possibly install a new
	 * instance of this package
	 */

	pkginst = getinst(&update, prvinfo, npkgs, preinstallCheck);

	/* set "update flag" if updating an existing instance of this package */

	if (update) {
		setUpdate();
	}

	/*
	 * Some pkgs (SUNWcsr) already spooled to the zone, check the
	 * value of UPDATE in their postinstall script.  After a pkg
	 * has been patched UPDATE exists statically in the pkginfo
	 * file and this value must be reset when installing a zone.
	 */

	if (saveSpoolInstall != 0 && !isUpdate()) {
		putparam("UPDATE", "");
	}

	/* inform quit() if updating existing or installing new instance */

	quitSetUpdatingExisting(update ? B_TRUE : B_FALSE);

	if (respfile) {
		(void) set_respfile(respfile, pkginst, RESP_RO);
	}

	(void) snprintf(pkgloc, sizeof (pkgloc),
			"%s/%s", get_PKGLOC(), pkginst);

	(void) snprintf(pkgbin, sizeof (pkgbin),
			"%s/install", pkgloc);

	(void) snprintf(pkgsav, sizeof (pkgsav),
			"%s/save", pkgloc);

	if (snprintf(saveSpoolInstallDir, PATH_MAX, "%s/pspool/%s", pkgsav,
			pkginst) < 0) {
		progerr(ERR_SNPRINTF, saveSpoolInstallDir);
		quit(99);
		/*NOTREACHED*/
	}

	(void) snprintf(ilockfile, sizeof (ilockfile),
			"%s/!I-Lock!", pkgloc);
	(void) snprintf(rlockfile, sizeof (rlockfile),
			"%s/!R-Lock!", pkgloc);
	(void) snprintf(savlog, sizeof (savlog),
			"%s/logs/%s", get_PKGADM(), pkginst);

	putparam("PKGINST", pkginst);
	putparam("PKGSAV", pkgsav);

	/*
	 * Be sure request script has access to PKG_INSTALL_ROOT if there is
	 * one
	 */

	put_path_params();

	if (!map_client) {
		putparam("PKG_NO_UNIFIED", "TRUE");
	}

	/*
	 * This maps the client filesystems into the server's space.
	 */

	if (map_client && !mount_client()) {
		logerr(MSG_MANMOUNT);
	}

	/*
	 * If this is an UPDATE then either this is exactly the same version
	 * and architecture of an installed package or a different package is
	 * intended to entirely replace an installed package of the same name
	 * with a different VERSION or ARCH string.
	 * Don't merge any databases if only gathering dependencies.
	 */

	if ((preinstallCheck == B_FALSE) && (update)) {
		/*
		 * If this version and architecture is already installed,
		 * merge the installed and installing parameters and inform
		 * all procedure scripts by defining UPDATE in the
		 * environment.
		 */

		if (is_samepkg()) {
			/*
			 * If it's the same ARCH and VERSION, then a merge
			 * and copy operation is necessary.
			 */

			if (n = merg_pkginfos(pclass, &mergd_pclass)) {
				quit(n);
				/*NOTREACHED*/
			}

			if (n = cp_pkgdirs()) {
				quit(n);
				/*NOTREACHED*/
			}

		} else {
			/*
			 * If it's a different ARCH and/or VERSION then this
			 * is an "instance=overwrite" situation. The
			 * installed base needs to be confirmed and the
			 * package directories renamed.
			 */

			if (n = ck_instbase()) {
				quit(n);
				/*NOTREACHED*/
			}

			if (n = mv_pkgdirs()) {
				quit(n);
				/*NOTREACHED*/
			}
		}

		putparam("UPDATE", "yes");

	}

	if (in_dryrun_mode()) {
		set_dryrun_dir_loc();
	}

	if (preinstallCheck == B_FALSE) {
		/*
		 * Determine if the package has been partially installed on or
		 * removed from this system.
		 */
		ck_w_dryrun(ckpartial, PARTIAL);

		/*
		 * make sure current runlevel is appropriate
		 */
		ck_w_dryrun(ckrunlevel, RUNLEVEL);
	} else {
		int	r;

		/*
		 * Just gathering dependencies - determine if the package has
		 * been partially installed on or removed from this system and
		 * output information to stdout
		 */
		r = ckpartial();
		(void) fprintf(stdout, "ckpartialinstall=%d\n", r == 8 ? 1 : 0);
		(void) fprintf(stdout, "ckpartialremove=%d\n", r == 9 ? 1 : 0);

		/*
		 * make sure current runlevel is appropriate
		 */
		r = ckrunlevel();
		(void) fprintf(stdout, "ckrunlevel=%d\n", r);
	}

	if (pkgdev.cdevice) {
		/* get first volume which contains info files */
		unpack();
		if (!suppressCopyright) {
			copyright();
		}
	}

	/* update the lock - at the request script */

	lockupd("request");

	/*
	 * If no response file has been provided, initialize response file by
	 * executing any request script provided by this package. Initialize
	 * the response file if not gathering dependencies only.
	 */

	if ((!rdonly_respfile()) && (preinstallCheck == B_FALSE)) {
		(void) snprintf(path, sizeof (path),
			"%s/%s", instdir, REQUEST_FILE);
		n = reqexec(update, path, non_abi_scripts,
			run_request_as_root);
		if (in_dryrun_mode()) {
			set_dr_info(REQUESTEXITCODE, n);
		}

		ckreturn(n, ERR_REQUEST);
	}

	/*
	 * Look for all parameters in response file which begin with a
	 * capital letter, and place them in the environment.
	 */

	if ((is_a_respfile()) && (preinstallCheck == B_FALSE)) {
		if (n = merg_respfile()) {
			quit(n);
			/*NOTREACHED*/
		}
	}

	/*
	 * Run a checkinstall script if one is provided by the package.
	 * Don't execute checkinstall script if we are only updating the DB.
	 * Don't execute checkinstall script if only gathering dependencies.
	 */

	/* update the lock - at the checkinstall script */
	lockupd("checkinstall");

	/* Execute checkinstall script if one is provided. */
	(void) snprintf(script, sizeof (script), "%s/install/checkinstall",
			instdir);
	if (access(script, F_OK) != 0) {
		/* no script present */
		echoDebug(DBG_PKGINSTALL_COC_NONE, pkginst, script,
			zoneName ? zoneName : "global");
	} else if (is_depend_pkginfo_DB()) {
		/* updating db only: skip checkinstall script */
		echoDebug(DBG_PKGINSTALL_COC_DBUPD, pkginst, script,
			zoneName ? zoneName : "global");
	} else if (preinstallCheck == B_TRUE) {
		/* only gathering dependencies: skip checkinstall script */
		echoDebug(DBG_PKGINSTALL_COC_NODEL, pkginst, script,
			zoneName ? zoneName : "global");
	} else {
		/* script present and ok to run: run the script */
		if (zoneName == (char *)NULL) {
			echo(MSG_PKGINSTALL_EXECOC_GZ);
			echoDebug(DBG_PKGINSTALL_EXECOC_GZ, pkginst, script);
		} else {
			echo(MSG_PKGINSTALL_EXECOC_LZ, zoneName);
			echoDebug(DBG_PKGINSTALL_EXECOC_LZ, pkginst, script,
				zoneName);
		}
		n = chkexec(update, script);
		if (in_dryrun_mode()) {
			set_dr_info(CHECKEXITCODE, n);
		}

		if (n == 3) {
			echo(WRN_CHKINSTALL);
			ckreturn(4, NULL);
		} else if (n == 7) {
			/* access returned error */
			progerr(ERR_CHKINSTALL_NOSCRIPT, script);
			ckreturn(4, ERR_CHKINSTALL);
		} else {
			ckreturn(n, ERR_CHKINSTALL);
		}
	}

	/*
	 * Now that the internal data structures are initialized, we can
	 * initialize the dryrun files (which may be the same files).
	 */

	if (pkgdrtarg) {
		init_dryrunfile(pkgdrtarg);
	}

	/*
	 * Look for all parameters in response file which begin with a
	 * capital letter, and place them in the environment.
	 */
	if (is_a_respfile()) {
		if (n = merg_respfile()) {
			quit(n);
			/*NOTREACHED*/
		}
	}

	/* update the lock - doing analysis */

	lockupd("analysis");

	/*
	 * Determine package base directory and client base directory
	 * if appropriate. Then encapsulate them for future retrieval.
	 */
	if ((err = set_basedirs(isreloc(instdir), adm.basedir, pkginst,
		nointeract)) != 0) {
		quit(err);
		/*NOTREACHED*/
	}

	/*
	 * Create the base directory if specified.
	 * Don't create if we are only updating the DB.
	 * Don't create if only gathering dependencies.
	 */

	if (!is_depend_pkginfo_DB() &&
		!preinstallCheck && is_a_basedir()) {
		mkbasedir(!nointeract, get_basedir());
		echo(MSG_BASE_USED, get_basedir());
	}

	/*
	 * Store PKG_INSTALL_ROOT, BASEDIR & CLIENT_BASEDIR in our
	 * environment for later use by procedure scripts.
	 */
	put_path_params();

	/*
	 * the following two checks are done in the corresponding
	 * ck() routine, but are repeated here to avoid re-processing
	 * the database if we are administered to not include these
	 * processes
	 */
	if (ADM(setuid, "nochange")) {
		nosetuid++;	/* Clear setuid/gid bits. */
	}

	if (ADM(conflict, "nochange")) {
		nocnflct++;	/* Don't install conflicting files. */
	}

	/*
	 * Get the filesystem space information for the filesystem on which
	 * the "contents" file resides.
	 */

	svfsb.f_bsize = 8192;
	svfsb.f_frsize = 1024;

	if (statvfs64(get_PKGADM(), &svfsb) == -1) {
		int	lerrno = errno;
		if (!access(get_PKGADM(), F_OK)) {
			progerr(ERR_PKGINSTALL_STATVFS, get_PKGADM(),
				strerror(errno));
			logerr("(errno %d)", lerrno);
			quit(99);
			/*NOTREACHED*/
		}
	}

	/*
	 * Get the number of blocks used by the pkgmap, ocfile()
	 * needs this to properly determine its space requirements.
	 */

	if (stat(p_pkgmap, &statb) == -1) {
		progerr(ERR_PKGINSTALL_STATOF, p_pkgmap, strerror(errno));
		quit(99);
		/*NOTREACHED*/
	}

	pkgmap_blks = nblk(statb.st_size, svfsb.f_bsize, svfsb.f_frsize);

	/*
	 * Merge information in memory with the "contents" file; this creates
	 * a temporary version of the "contents" file. Note that in dryrun
	 * mode, we still need to record the contents file data somewhere,
	 * but we do it in the dryrun directory.
	 */

	if (in_dryrun_mode()) {
		if (n = set_cfdir(pkgdrtarg)) {
			quit(n);
			/*NOTREACHED*/
		}
	} else {
		if (n = set_cfdir(NULL)) {
			quit(n);
			/*NOTREACHED*/
		}
	}
	if (!ocfile(&pkgserver, &cfTmpVfp, pkgmap_blks)) {
		quit(99);
		/*NOTREACHED*/
	}

	/*
	 * if cpio is being used,  tell pkgdbmerg since attributes will
	 * have to be check and repaired on all file and directories
	 */
	for (np = cpio_names; *np != NULL; np++) {
		(void) snprintf(path, sizeof (path),
			"%s/%s", instdir, *np);
		if (iscpio(path, &is_comp_arch)) {
			is_WOS_arch();
			break;
		}
	}

	/* Establish the class list and the class attributes. */
	cl_sets(getenv("CLASSES"));
	find_CAS(I_ONLY, pkgbin, instdir);

	if (vfpOpen(&pkgmapVfp, p_pkgmap, "r", VFP_NEEDNOW) != 0) {
		progerr(ERR_PKGMAP, p_pkgmap);
		quit(99);
		/*NOTREACHED*/
	}

	/*
	 * This modifies the path list entries in memory to reflect
	 * how they should look after the merg is complete
	 */

	nparts = sortmap(&extlist, pkgmapVfp, pkgserver, cfTmpVfp, zoneName);

	if ((n = files_installed()) > 0) {
		if (n > 1) {
			echo(MSG_INST_MANY, n);
		} else {
			echo(MSG_INST_ONE, n);
		}
	}

	/*
	 * Check ulimit requirement (provided in pkginfo). The purpose of
	 * this limit is to terminate pathological file growth resulting from
	 * file edits in scripts. It does not apply to files in the pkgmap
	 * and it does not apply to any database files manipulated by the
	 * installation service.
	 */
	if (pt = getenv("ULIMIT")) {
		if (assign_ulimit(pt) == -1) {
			progerr(ERR_BADULIMIT, pt);
			quit(99);
			/*NOTREACHED*/
		}
		putparam("PKG_ULIMIT", "TRUE");
	}

	/*
	 * If only gathering dependencies, check and output status of all
	 * remaining dependencies and exit.
	 */

	if (preinstallCheck == B_TRUE) {
		/* update the lock file - final checking */

		lockupd("preinstallcheck");

		/* verify package information files are not corrupt */

		(void) fprintf(stdout, "ckpkgfiles=%d\n", ckpkgfiles());

		/* verify package dependencies */

		(void) fprintf(stdout, "ckdepend=%d\n", ckdepend());

		/* Check space requirements */

		(void) fprintf(stdout, "ckspace=%d\n", ckspace());

		/*
		 * Determine if any objects provided by this package conflict
		 * with the files of previously installed packages.
		 */

		(void) fprintf(stdout, "ckconflict=%d\n", ckconflct());

		/*
		 * Determine if any objects provided by this package will be
		 * installed with setuid or setgid enabled.
		 */

		(void) fprintf(stdout, "cksetuid=%d\n", cksetuid());

		/*
		 * Determine if any packaging scripts provided with this package
		 * will execute as a priviledged user.
		 */

		(void) fprintf(stdout, "ckpriv=%d\n", ckpriv());

		/* Verify neccessary package installation directories exist */

		(void) fprintf(stdout, "ckpkgdirs=%d\n", ckpkgdirs());

		/*
		 * ****** preinstall check done - exit ******
		 */

		echoDebug(DBG_PKGINSTALL_PREINSCHK_OK);
		quit(0);
		/*NOTREACHED*/
	}

	/*
	 * Not gathering dependencies only, proceed to check dependencies
	 * and continue with the package installation operation.
	 */

	/*
	 * verify package information files are not corrupt
	 */
	ck_w_dryrun(ckpkgfiles, PKGFILES);

	/*
	 * verify package dependencies
	 */
	ck_w_dryrun(ckdepend, DEPEND);

	/*
	 * Check space requirements.
	 */
	ck_w_dryrun(ckspace, SPACE);

	/*
	 * Determine if any objects provided by this package conflict with
	 * the files of previously installed packages.
	 */
	ck_w_dryrun(ckconflct, CONFLICT);

	/*
	 * Determine if any objects provided by this package will be
	 * installed with setuid or setgid enabled.
	 */
	ck_w_dryrun(cksetuid, SETUID);

	/*
	 * Determine if any packaging scripts provided with this package will
	 * execute as a priviledged user.
	 */
	ck_w_dryrun(ckpriv, PRIV);

	/*
	 * Verify neccessary package installation directories exist.
	 */
	ck_w_dryrun(ckpkgdirs, PKGDIRS);

	/*
	 * If we have assumed that we were installing setuid or conflicting
	 * files, and the user chose to do otherwise, we need to read in the
	 * package map again and re-merg with the "contents" file
	 */

	if (rprcflag) {
		nparts = sortmap(&extlist, pkgmapVfp, pkgserver,
				cfTmpVfp, zoneName);
	}

	(void) vfpClose(&pkgmapVfp);

	/* BEGIN INSTALLATION PHASE */
	if (in_dryrun_mode()) {
		echo(MSG_PKGINSTALL_DRYRUN, pkgname, pkginst);
	} else if (zoneName == (char *)NULL) {
		echo(MSG_PKGINSTALL_INSIN_GZ, pkgname, pkginst);
	} else {
		echo(MSG_PKGINSTALL_INSIN_LZ, pkgname, pkginst, zoneName);
	}

	/* inform quit that the install has started */

	quitSetInstallStarted(B_TRUE);

	/*
	 * This replaces the contents file with recently created temp version
	 * which contains information about the objects being installed.
	 * Under old lock protocol it closes both files and releases the
	 * locks. Beginning in Solaris 2.7, this lock method should be
	 * reviewed.
	 */

	n = swapcfile(pkgserver, &cfTmpVfp, pkginst, dbchg);
	if (n == RESULT_WRN) {
		warnflag++;
	} else if (n == RESULT_ERR) {
		quit(99);
		/*NOTREACHED*/
	}

	/*
	 * Create install-specific lockfile to indicate start of
	 * installation. This is really just an information file. If the
	 * process dies, the initial lockfile (from lockinst(), is
	 * relinquished by the kernel, but this one remains in support of the
	 * post-mortem.
	 */

	if (access(ilockfile, F_OK) == 0) {
		(void) remove(ilockfile);
	}

	if (open(ilockfile, O_WRONLY|O_CREAT|O_TRUNC|O_EXCL, 0644) < 0) {
		progerr(ERR_LOCKFILE, ilockfile);
		quit(99);
		/*NOTREACHED*/
	}

	(void) time(&clock);

	/*
	 * We do not want the time in locale in the pkginfo.
	 * save the LC_TIME and set it to C. Reset it with saved one
	 * after cftime().
	 */
	temp = setlocale(LC_TIME, NULL);
	(void) setlocale(LC_TIME, "C");

	/* LINTED warning: do not use cftime(); ... */
	(void) cftime(cbuf, "%b %d \045Y \045H:\045M", &clock);
	putparam("INSTDATE", qstrdup(cbuf));
	(void) setlocale(LC_TIME, temp);

	/*
	 * Store information about package being installed;
	 * modify installation parameters as neccessary and
	 * copy contents of 'install' directory into $pkgloc
	 */
	merginfo(mergd_pclass, saveSpoolInstall);

	/* If this was just a dryrun, then quit() will write out that file. */
	if (in_dryrun_mode()) {
		quit(0);
		/*NOTREACHED*/
	}

	/*
	 * Execute preinstall script, if one was provided with the
	 * package. We check the package to avoid running an old
	 * preinstall script if one was provided with a prior instance.
	 * Don't execute preinstall script if we are only updating the DB.
	 */

	/* update the lock - at the preinstall altscript */
	lockupd("preinstall");

	/* preinstall script in the media (package source) */
	(void) snprintf(altscript, sizeof (altscript), "%s/install/preinstall",
			instdir);

	/* preinstall script in the pkgbin instead of media */
	(void) snprintf(script, sizeof (script), "%s/preinstall", pkgbin);

	if (access(altscript, F_OK) != 0) {
		/* no script present */
		echoDebug(DBG_PKGINSTALL_POCALT_NONE, pkginst, altscript,
			zoneName ? zoneName : "global");
	} else if (access(script, F_OK) != 0) {
		/* no script present */
		echoDebug(DBG_PKGINSTALL_POC_NONE, pkginst, script,
			zoneName ? zoneName : "global");
	} else if (is_depend_pkginfo_DB()) {
		/* updating db only: skip preinstall script */
		echoDebug(DBG_PKGINSTALL_POC_DBUPD, pkginst, script,
			zoneName ? zoneName : "global");
	} else {
		/* script present and ok to run: run the script */
		assert(preinstallCheck == B_FALSE);

		set_ulimit("preinstall", ERR_PREINSTALL);
		if (zoneName == (char *)NULL) {
			echo(MSG_PKGINSTALL_EXEPOC_GZ);
			echoDebug(DBG_PKGINSTALL_EXEPOC_GZ, pkginst, script);
		} else {
			echo(MSG_PKGINSTALL_EXEPOC_LZ, zoneName);
			echoDebug(DBG_PKGINSTALL_EXEPOC_LZ, pkginst, script,
				zoneName);
		}
		putparam("PKG_PROC_script", "preinstall");
		if (pkgverbose) {
			ckreturn(pkgexecl(script_in, PROC_STDOUT,
				PROC_USER, PROC_GRP, SHELL, "-x",
				script, NULL), ERR_PREINSTALL);
		} else {
			ckreturn(pkgexecl(script_in, PROC_STDOUT,
				PROC_USER, PROC_GRP, SHELL, script,
				NULL), ERR_PREINSTALL);
		}

		clr_ulimit();
		(void) remove(script);	/* no longer needed. */
	}

	/*
	 * Check delivered package for a postinstall script while
	 * we're still on volume 1.
	 */

	(void) snprintf(script, sizeof (script),
			"%s/install/postinstall", instdir);
	if (access(script, F_OK) == 0) {
		(void) snprintf(script, sizeof (script),
					"%s/postinstall", pkgbin);
	} else {
		script[0] = '\0';
	}

	/* update the lock - at the install phase */

	lockupd("install");

	/*
	 * install package one part (volume) at a time
	 */

	part = 1;
	while (part <= nparts) {
		if ((part > 1) && pkgdev.cdevice) {
			unpack();
		}

		instvol(extlist, srcinst, part, nparts,
			pkgserver, &cfTmpVfp, &updated, zoneName);

		if (part++ >= nparts) {
			break;
		}
	}

	z_destroyMountTable();

	/*
	 * Now that all install class action scripts have been used, we
	 * delete them from the package directory.
	 */
	rm_icas(pkgbin);

	if (globalZoneOnly) {
		boolean_t   b;
		b = pkgAddPackageToGzonlyList(pkginst, get_inst_root());
		if (b == B_FALSE) {
			progerr(ERR_PKGINSTALL_GZONLY_ADD, pkginst);
			ckreturn(1, NULL);
		}
	}

	/*
	 * Execute postinstall script, if any
	 * Don't execute postinstall script if we are only updating the DB.
	 */

	echoDebug(DBG_PKGINSTALL_INSDONE, is_depend_pkginfo_DB(),
		is_depend_pkginfo_DB(), saveSpoolInstall,
		updated ? updated : "",
		script ? script : "",
		script ? access(script, F_OK) : -1);

	/* update the lock - at the postinstall script */
	lockupd("postinstall");

	if ((script == (char *)NULL) || (*script == '\0')) {
		echoDebug(DBG_PKGINSTALL_POIS_NOPATH, pkginst,
			zoneName ? zoneName : "global");
	} else if (access(script, F_OK) != 0) {
		echoDebug(DBG_PKGINSTALL_POIS_NONE, pkginst, script,
			zoneName ? zoneName : "global");
	} else if (is_depend_pkginfo_DB()) {
		echoDebug(DBG_PKGINSTALL_POIS_DBUPD, pkginst, script,
			zoneName ? zoneName : "global");
	} else if ((saveSpoolInstall != 0) && (updated == (char *)NULL)) {
		/*
		 * fresh installing into non-global zone, no object was
		 * updated (installed/verified in area), so do not run
		 * the postinstall script.
		 */
		echoDebug(DBG_PKGINSTALL_POIS_NOUPDATING,
			zoneName ? zoneName : "global", pkginst, script);
	} else {
		/* script present and ok to run: run the script */
		set_ulimit("postinstall", ERR_POSTINSTALL);
		if (zoneName == (char *)NULL) {
			echo(MSG_PKGINSTALL_EXEPIC_GZ);
			echoDebug(DBG_PKGINSTALL_EXEPIC_GZ, pkginst, script);
		} else {
			echo(MSG_PKGINSTALL_EXEPIC_LZ, zoneName);
			echoDebug(DBG_PKGINSTALL_EXEPIC_LZ, pkginst, script,
				zoneName);
		}
		putparam("PKG_PROC_SCRIPT", "postinstall");
		putparam("TMPDIR", tmpdir);
		if (pkgverbose) {
			ckreturn(pkgexecl(script_in, PROC_STDOUT,
				PROC_USER, PROC_GRP, SHELL, "-x",
				script, NULL), ERR_POSTINSTALL);
		} else {
			ckreturn(pkgexecl(script_in, PROC_STDOUT,
				PROC_USER, PROC_GRP, SHELL, script,
				NULL), ERR_POSTINSTALL);
		}

		clr_ulimit();
		(void) remove(script);	/* no longer needed */
	}

	if (!warnflag && !failflag) {
		(void) remove(rlockfile);
		(void) remove(ilockfile);
		(void) remove(savlog);
	}

	/* release the generic package lock */

	(void) unlockinst();

	pkgcloseserver(pkgserver);

	quit(0);
	/* LINTED: no return */
}

/*
 * This function merges the environment data in the response file with the
 * current environment.
 */
static int
merg_respfile()
{
	int retcode = 0;
	char *resppath = get_respfile();
	char *locbasedir;
	char param[MAX_PKG_PARAM_LENGTH], *value;
	FILE *fp;

	if ((fp = fopen(resppath, "r")) == NULL) {
		progerr(ERR_RESPONSE, resppath);
		return (99);
	}

	param[0] = '\0';

	while (value = fpkgparam(fp, param)) {
		if (!isupper(param[0])) {
			param[0] = '\0';
			continue;
		}

		if (rdonly(param)) {
			progerr(ERR_RDONLY, param);
			param[0] = '\0';
			continue;
		}

		/*
		 * If this is an update, and the response file
		 * specifies the BASEDIR, make sure it matches the
		 * existing installation base. If it doesn't, we have
		 * to quit.
		 */
		if (update && strcmp("BASEDIR", param) == 0) {
			locbasedir = getenv("BASEDIR");
			if (locbasedir && strcmp(value, locbasedir) != 0) {
				char *dotptr;
				/* Get srcinst down to a name. */
				if (dotptr = strchr(srcinst, '.'))
					*dotptr = '\000';
				progerr(ERR_NEWBD, srcinst,
					locbasedir, value);
				retcode = 99;
			}
		}

		putparam(param, value);
		param[0] = '\0';
	}
	(void) fclose(fp);

	return (retcode);
}

/*
 * This scans the installed pkginfo file for the current BASEDIR. If this
 * BASEDIR is different from the current BASEDIR, there will definitely be
 * problems.
 */
static int
ck_instbase(void)
{
	int retcode = 0;
	char param[MAX_PKG_PARAM_LENGTH], *value;
	char pkginfo_path[PATH_MAX];
	FILE *fp;

	/* Open the old pkginfo file. */
	(void) snprintf(pkginfo_path, sizeof (pkginfo_path),
			"%s/%s", pkgloc, PKGINFO);
	if ((fp = fopen(pkginfo_path, "r")) == NULL) {
		progerr(ERR_PKGINFO, pkginfo_path);
		return (99);
	}

	param[0] = '\000';

	while (value = fpkgparam(fp, param)) {
		if (strcmp("BASEDIR", param) == 0) {
			if (adm.basedir && *(adm.basedir) &&
				strchr("/$", *(adm.basedir))) {
				char *dotptr;

				/*
				 * Get srcinst down to a name.
				 */
				if (dotptr = strchr(srcinst, '.'))
					*dotptr = '\000';
				if (strcmp(value,
					adm.basedir) != 0) {
					progerr(ERR_ADMBD, srcinst,
						value, adm.basedir);
					retcode = 4;
					break;
				}
			} else if (ADM(basedir, "ask"))
				/*
				 * If it's going to ask later, let it know
				 * that it *must* agree with the BASEDIR we
				 * just picked up.
				 */
				adm.basedir = "update";

			putparam(param, value);
			break;
		}

		param[0] = '\0';
	}
	(void) fclose(fp);

	return (retcode);
}

/*
 * Since this is an overwrite of a different version of the package, none of
 * the old files should remain, so we rename them.
 */
static int
mv_pkgdirs(void)
{
	/*
	 * If we're not in dryrun mode and we can find an old set of package
	 * files over which the new ones will be written, do the rename.
	 */
	if (!in_dryrun_mode() && pkgloc[0] && !access(pkgloc, F_OK)) {
		(void) snprintf(pkgloc_sav, sizeof (pkgloc_sav),
			"%s/.save.%s", get_PKGLOC(),
			pkginst);
		if (pkgloc_sav[0] && !access(pkgloc_sav, F_OK)) {
			(void) rrmdir(pkgloc_sav);
		}

		if (rename(pkgloc, pkgloc_sav) == -1) {
			progerr(ERR_PKGBINREN, pkgloc, pkgloc_sav);
			return (99);
		}
	}

	return (0);
}

/*
 * Name:	merg_pkginfos
 * Description:	This function scans the installed pkginfo and merges that
 *		environment with the installing environment according to
 *		the following rules:
 *
 *		1. CLASSES is a union of the installed and installing CLASSES
 *			lists.
 *		2. The installed BASEDIR takes precedence. If it doesn't agree
 *		   with an administratively imposed BASEDIR, an ERROR is issued.
 *		3. All other installing parameters are preserved.
 *		4. All installed parameters are added if they do not overwrite
 *		   an existing installing parameter.
 *
 *		The current environment contains the pkginfo settings for the
 *		new package to be installed or to be updated.
 *
 * Arguments:	pclass - returned list of current classes involved in install
 *		mpclass - pointer to returned list of current install classes
 * Returns:	int
 *		== 0 - all OK
 *		!= 0 - an error code if a fatal error occurred
 */

static int
merg_pkginfos(struct cl_attr **pclass, struct cl_attr ***mpclass)
{
	FILE	*fp;
	char	SUNW_PKG_ALLZONES[MAX_PKG_PARAM_LENGTH] = {'\0'};
	char	SUNW_PKG_HOLLOW[MAX_PKG_PARAM_LENGTH] = {'\0'};
	char	SUNW_PKG_THISZONE[MAX_PKG_PARAM_LENGTH] = {'\0'};
	char	*newValue;
	char	*oldValue;
	char	*pkgName;
	char	*pkgVersion;
	char	param[MAX_PKG_PARAM_LENGTH];
	char	pkginfo_path[PATH_MAX];
	int	retcode = 0;

	/* obtain the name of the package (for error messages) */

	pkgName = getenv("PKG");
	if (pkgName == NULL) {
		pkgName = "*current*";	/* default name */
	}

	/* obtain the version of the package (for error messages) */

	pkgVersion = getenv("VERSION");
	if (pkgVersion == NULL) {
		pkgVersion = "*current*";	/* default version */
	}

	/* open installed package pkginfo file */

	(void) snprintf(pkginfo_path, sizeof (pkginfo_path),
			"%s/%s", pkgloc, PKGINFO);
	if ((fp = fopen(pkginfo_path, "r")) == NULL) {
		progerr(ERR_PKGINFO, pkginfo_path);
		return (99);
	}

	/* entry debugging info */

	echoDebug(DBG_MERGINFOS_ENTRY, pkginfo_path);

	/*
	 * cycle through the currently installed package's pkginfo parameters
	 * and let the currently installed package's settings survive if the
	 * update to the package does not provide an overriding value
	 */

	for (param[0] = '\0'; (oldValue = fpkgparam(fp, param)) != NULL;
		param[0] = '\0') {

		boolean_t	setZoneAttribute = B_FALSE;

		/* debug info - attribute currently set to value */

		echoDebug(DBG_MERGINFOS_SET_TO, param, oldValue);

		/*
		 * if zone package attribute is present in the currently
		 * installed package, then remember the value for the
		 * specific zone package attribute, and set the flag that
		 * indicates a zone package attribute is being processed.
		 */

		if (strcmp(param, PKG_THISZONE_VARIABLE) == 0) {
			/* SUNW_PKG_THISZONE currently set */
			setZoneAttribute = B_TRUE;
			(void) strlcpy(SUNW_PKG_THISZONE, oldValue,
					sizeof (SUNW_PKG_THISZONE));
		} else if (strcmp(param, PKG_ALLZONES_VARIABLE) == 0) {
			/* SUNW_PKG_ALLZONES currently set */
			setZoneAttribute = B_TRUE;
			(void) strlcpy(SUNW_PKG_ALLZONES, oldValue,
					sizeof (SUNW_PKG_ALLZONES));
		} else if (strcmp(param, PKG_HOLLOW_VARIABLE) == 0) {
			/* SUNW_PKG_THISZONE currently set */
			setZoneAttribute = B_TRUE;
			(void) strlcpy(SUNW_PKG_HOLLOW, oldValue,
					sizeof (SUNW_PKG_HOLLOW));
		}

		/* handle CLASSES currently being set */

		if (strcmp(param, "CLASSES") == 0) {
			echoDebug(DBG_MERGINFOS_SET_CLASSES, oldValue);
			/* create a list of the current classes */
			(void) setlist(&pclass, qstrdup(oldValue));
			/* set pointer to list of current classes */
			*mpclass = pclass;
			continue;
		}

		/* handle BASEDIR currently being set */

		if (strcmp("BASEDIR", param) == 0) {
			if (adm.basedir && *(adm.basedir) &&
				strchr("/$", *(adm.basedir))) {
				char *dotptr;

				/* Get srcinst down to a* name */

				if (dotptr = strchr(srcinst, '.')) {
					*dotptr = '\000';
				}
				if (strcmp(oldValue, adm.basedir) != 0) {
					progerr(ERR_ADMBD, srcinst,
						oldValue, adm.basedir);
					/* administration */
					retcode = 4;
					break;
				}
			} else if (ADM(basedir, "ask")) {
				/*
				 * If it's going to ask
				 * later, let it know that it
				 * *must* agree with the
				 * BASEDIR we just picked up.
				 */
				adm.basedir = "update";
				echoDebug(DBG_MERGINFOS_ASK_BASEDIR);
			}

			echoDebug(DBG_MERGINFOS_SET_BASEDIR, oldValue);
			putparam(param, oldValue);
			continue;
		}

		/*
		 * determine if there is a new value for this attribute.
		 */

		newValue = getenv(param);

		/*
		 * If there is no new value, and a zone attribute
		 * is being changed, it is the same as setting the zone package
		 * attribute to 'false' - make sure current setting is 'false'.
		 */

		if ((newValue == NULL) &&
		    (setZoneAttribute == B_TRUE) &&
		    (strcasecmp(oldValue, "false") != 0)) {

			/* unset existing non-"false" zone pkg attr */
			progerr(ERR_MERGINFOS_UNSET_ZONEATTR,
				pkgName, pkgVersion, param, oldValue);
			retcode = 1;
			break;
		}

		/* retain old value if no new value specified */

		if (newValue == NULL) {
			/* no new value - retain the old value */
			echoDebug(DBG_MERGINFOS_RETAIN_OLD, param, oldValue);
			putparam(param, oldValue);
			continue;
		}

		/* note if the old and new values are the same */

		if (strcmp(newValue, oldValue) == 0) {
			/* set existing package parameter to same value */
			echoDebug(DBG_MERGINFOS_SET_DUPLICATE, param, oldValue);
			continue;
		}

		/*
		 * Check if old and new values differ.
		 * Error if zone parameter
		 */

		if (setZoneAttribute == B_TRUE) {
			/* illegal change to zone attribute */

			progerr(ERR_MERGINFOS_CHANGE_ZONEATTR, pkgName,
				pkgVersion, param, oldValue, newValue);

			/* set return code to "fatal error" */
			retcode = 1;
			break;
		}

		/* note valid change to existing package parameter */

		echoDebug(DBG_MERGINFOS_SET_CHANGE, param,
				oldValue, newValue);
	}

	/* close handle on currently installed package's pkginfo file */

	(void) fclose(fp);

	/* return error if not successful up to this point */

	if (retcode != 0) {
		echoDebug(DBG_MERGINFOS_EXIT, pkginfo_path, retcode);

		return (retcode);
	}

	/*
	 * verify that no zone attribute has been
	 * set to an invalid value
	 */

	/* SUNW_PKG_ALLZONES */

	newValue = getenv(PKG_ALLZONES_VARIABLE);

	/*
	 * complain if setting SUNW_PKG_ALLZONES to other than "false"
	 */


	if ((newValue != NULL) && (*SUNW_PKG_ALLZONES == '\0') &&
	    (strcasecmp(newValue, "false") != 0)) {
		/* change ALLZONES from "true" to "false" (unset) */
		progerr(ERR_MERGINFOS_SET_ZONEATTR, pkgName,
		    pkgVersion, PKG_ALLZONES_VARIABLE, newValue);
		return (1);
	}

	/* SUNW_PKG_THISZONE */

	newValue = getenv(PKG_THISZONE_VARIABLE);

	/*
	 * complain if setting SUNW_PKG_THISZONE to other than "false"
	 */

	if ((newValue != NULL) && (*SUNW_PKG_THISZONE == '\0') &&
	    (strcasecmp(newValue, "false") != 0)) {
		/* change THISZONE from "true" to "false" (unset) */
		progerr(ERR_MERGINFOS_SET_ZONEATTR, pkgName,
		    pkgVersion, PKG_THISZONE_VARIABLE, newValue);
		return (1);
	}

	/* SUNW_PKG_HOLLOW */

	newValue = getenv(PKG_HOLLOW_VARIABLE);

	/* complain if setting SUNW_PKG_HOLLOW to other than "false" */

	if ((newValue != NULL) && (*SUNW_PKG_HOLLOW == '\0') &&
	    (strcasecmp(newValue, "false") != 0)) {
		/* change HOLLOW from "true" to 'false" (unset) */
		progerr(ERR_MERGINFOS_SET_ZONEATTR, pkgName,
		    pkgVersion, PKG_HOLLOW_VARIABLE, newValue);
		return (1);
	}

	echoDebug(DBG_MERGINFOS_EXIT, pkginfo_path, 0);

	return (0);
}

static void
set_dryrun_dir_loc(void)
{
	/* Set pkg location to the dryrun directory */
	set_PKGLOC(pkgdrtarg);
	(void) snprintf(pkgloc, sizeof (pkgloc),
			"%s/%s", get_PKGLOC(), pkginst);
	(void) snprintf(pkgbin, sizeof (pkgbin),
			"%s/install", pkgloc);
	(void) snprintf(pkgsav, sizeof (pkgsav),
			"%s/save", pkgloc);
	(void) snprintf(ilockfile, sizeof (ilockfile),
			"%s/!I-Lock!", pkgloc);
	(void) snprintf(rlockfile, sizeof (rlockfile),
			"%s/!R-Lock!", pkgloc);
	(void) snprintf(savlog, sizeof (savlog),
			"%s/logs/%s", get_PKGADM(), pkginst);
}

/*
 * If we are updating a pkg, then we need to copy the "old" pkgloc so that
 * any scripts that got removed in the new version aren't left around.  So we
 * copy it here to .save.pkgloc, then in quit() we can restore our state, or
 * remove it.
 */
static int
cp_pkgdirs(void)
{
	if (in_dryrun_mode()) {
		set_dryrun_dir_loc();
	}

	/*
	 * If we're not in dryrun mode and we can find an old set of package
	 * files over which the new ones will be written, do the copy.
	 */
	if (!in_dryrun_mode() && pkgloc[0] && !access(pkgloc, F_OK)) {
		int status;
		int r;

		(void) snprintf(pkgloc_sav, sizeof (pkgloc_sav), "%s/.save.%s",
			get_PKGLOC(), pkginst);

		/*
		 * Even though it takes a while, we use a recursive copy here
		 * because if the current pkgadd fails for any reason, we
		 * don't want to lose this data.
		 */
		r = e_ExecCmdList(&status, (char **)NULL, (char *)NULL,
			"/usr/bin/cp", "cp", "-r", pkgloc, pkgloc_sav,
			(char *)NULL);

		if ((r != 0) || (status == -1) || (WEXITSTATUS(status) != 0)) {
			progerr(ERR_PKGBINCP, pkgloc, pkgloc_sav);
			return (99);
		}
	}

	return (0);
}

/*
 * This implements the pkgask function. It just executes the request script
 * and stores the results in a response file.
 */
static void
do_pkgask(boolean_t a_run_request_as_root)
{
	if (pkgdev.cdevice) {
		unpack();
		if (!suppressCopyright) {
			copyright();
		}
	}
	(void) snprintf(path, sizeof (path), "%s/%s", instdir, REQUEST_FILE);
	if (access(path, F_OK)) {
		progerr(ERR_NOREQUEST);
		quit(1);
		/*NOTREACHED*/
	}

	(void) set_respfile(respfile, srcinst, RESP_WR);

	if (is_a_respfile()) {
		ckreturn(reqexec(update, path, non_abi_scripts,
			a_run_request_as_root), ERR_REQUEST);
	} else {
		failflag++;
	}

	if (warnflag || failflag) {
		(void) remove(respfile);
		echo("\nResponse file <%s> was not created.",
			get_respfile());
	} else {
		echo("\nResponse file <%s> was created.",
			get_respfile());
	}

	quit(0);
	/*NOTREACHED*/
}

/*
 * This function runs a check utility and acts appropriately based upon the
 * return code. It deals appropriately with the dryrun file if it is present.
 */
static void
ck_w_dryrun(int (*func)(), int type)
{
	int n;

	n = func();
	if (in_dryrun_mode())
		set_dr_info(type, !n);

	if (n) {
		quit(n);
		/*NOTREACHED*/
	}
}

/*
 * This function deletes all install class action scripts from the package
 * directory on the root filesystem.
 */
static void
rm_icas(char *cas_dir)
{
	DIR	*pdirfp;
	struct	dirent *dp;
	char path[PATH_MAX];

	if ((pdirfp = opendir(cas_dir)) == NULL)
		return;

	while ((dp = readdir(pdirfp)) != NULL) {
		if (dp->d_name[0] == '.')
			continue;

		if (dp->d_name[0] == 'i' && dp->d_name[1] == '.') {
			(void) snprintf(path, sizeof (path),
				"%s/%s", cas_dir, dp->d_name);
			(void) remove(path);
		}
	}
	(void) closedir(pdirfp);
}

void
ckreturn(int retcode, char *msg)
{
	switch (retcode) {
		case 2:
		case 12:
		case 22:
		warnflag++;
		if (msg) {
			progerr("%s", msg);
		}
		/*FALLTHRU*/
		case 10:
		case 20:
		if (retcode >= 10 && retcode < 20) {
			dreboot++;
		}
		if (retcode >= 20) {
			ireboot++;
		}
		/*FALLTHRU*/
		case 0:
		break; /* okay */

		case -1:
		retcode = 99;
		/*FALLTHRU*/
		case 99:
		case 1:
		case 11:
		case 21:
		case 4:
		case 14:
		case 24:
		case 5:
		case 15:
		case 25:
		if (msg) {
			progerr("%s", msg);
		}
		/*FALLTHRU*/
		case 3:
		case 13:
		case 23:
		quit(retcode);
		/*NOTREACHED*/
		default:
		if (msg) {
			progerr("%s", msg);
		}
		quit(1);
		/*NOTREACHED*/
	}
}

static void
copyright(void)
{
	FILE	*fp;
	char	line[LSIZE];
	char	path[PATH_MAX];

	/* Compose full path for copyright file */
	(void) snprintf(path, sizeof (path), "%s/%s", instdir, COPYRIGHT_FILE);

	if ((fp = fopen(path, "r")) == NULL) {
		if (getenv("VENDOR") != NULL)
			echo(getenv("VENDOR"));
	} else {
		while (fgets(line, LSIZE, fp))
			(void) fprintf(stdout, "%s", line); /* bug #1083713 */
		(void) fclose(fp);
	}
}

static int
rdonly(char *p)
{
	int	i;

	for (i = 0; ro_params[i]; i++) {
		if (strcmp(p, ro_params[i]) == 0)
			return (1);
	}
	return (0);
}

static void
unpack(void)
{
	/*
	 * read in next part from stream, even if we decide
	 * later that we don't need it
	 */
	if (dparts < 1) {
		progerr(ERR_DSTREAMCNT);
		quit(99);
		/*NOTREACHED*/
	}
	if ((access(instdir, F_OK) == 0) && rrmdir(instdir)) {
		progerr(ERR_RMDIR, instdir);
		quit(99);
		/*NOTREACHED*/
	}
	if (mkdir(instdir, 0755)) {
		progerr(ERR_MKDIR, instdir);
		quit(99);
		/*NOTREACHED*/
	}
	if (chdir(instdir)) {
		progerr(ERR_CHDIR, instdir);
		quit(99);
		/*NOTREACHED*/
	}
	if (!ds_fd_open()) {
		dparts = ds_findpkg(pkgdev.cdevice, srcinst);
		if (dparts < 1) {
			progerr(ERR_DSARCH, srcinst);
			quit(99);
			/*NOTREACHED*/
		}
	}

	dparts--;

	if (ds_next(pkgdev.cdevice, instdir)) {
		progerr(ERR_DSTREAM);
		quit(99);
		/*NOTREACHED*/
	}
	if (chdir(get_PKGADM())) {
		progerr(ERR_CHDIR, get_PKGADM());
		quit(99);
		/*NOTREACHED*/
	}
	ds_close(1);
}

static void
usage(void)
{
	(void) fprintf(stderr, ERR_USAGE_PKGINSTALL);
	exit(1);
	/*NOTREACHED*/
}
