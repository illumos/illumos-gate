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


#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pkgstrct.h>
#include <pkginfo.h>
#include <pkglocs.h>
#include <locale.h>
#include <libintl.h>
#include <assert.h>
#include <cfext.h>
#include <instzones_api.h>
#include <pkglib.h>
#include <install.h>
#include <libinst.h>
#include <libadm.h>
#include <messages.h>

struct cfent **eptlist;
extern int	eptnum;

extern char	*pkgdir;
extern char	**environ;

/* quit.c */
extern sighdlrFunc_t	*quitGetTrapHandler(void);
extern void		quitSetSilentExit(boolean_t a_silentExit);
extern void		quitSetZoneName(char *a_zoneName);



/* check.c */
extern void	rcksetPreremoveCheck(boolean_t);
extern void	rcksetZoneName(char *);
extern int	rckpriv(void);
extern int	rckdepend(void);
extern int	rckrunlevel(void);

/* delmap.c */
extern int delmap(int flag, char *pkginst, PKGserver *server, VFP_T **tfp);

#define	DEFPATH		"/sbin:/usr/sbin:/usr/bin"

#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"
#endif

/* This is the text for the "-O parent-zone-name=" option */

#define	PARENTZONENAME	"parent-zone-name="
#define	PARENTZONENAME_LEN	((sizeof (PARENTZONENAME))-1)

/* This is the text for the "-O parent-zone-type=" option */

#define	PARENTZONETYPE	"parent-zone-type="
#define	PARENTZONETYPE_LEN	((sizeof (PARENTZONETYPE))-1)

struct	admin adm; 	/* holds info about installation admin */
int	dreboot; 	/* non-zero if reboot required after installation */
int	ireboot;	/* non-zero if immediate reboot required */
int	failflag;	/* non-zero if fatal error has occurred */
int	warnflag;	/* non-zero if non-fatal error has occurred */
int	pkgverbose;	/* non-zero if verbose mode is selected */
int	started;
int	nocnflct = 0; 	/* pkgdbmerg needs this defined */
int	nosetuid = 0; 	/* pkgdbmerg needs this defined */

char	*pkginst; 	/* current package (source) instance to process */

int	dbchg;
char	*msgtext;
char	pkgloc[PATH_MAX];

/*
 * The following variable is the name of the device to which stdin
 * is connected during execution of a procedure script. /dev/null is
 * correct for all ABI compliant packages. For non-ABI-compliant
 * packages, the '-o' command line switch changes this to /dev/tty
 * to allow user interaction during these scripts. -- JST
 */
static char 	*script_in = PROC_STDIN;	/* assume ABI compliance */

static char	*client_mntdir; 	/* mount point for client's basedir */
static char	pkgbin[PATH_MAX],
		rlockfile[PATH_MAX],
		*admnfile, 		/* file to use for installation admin */
		*tmpdir; 		/* location to place temporary files */

static void		ckreturn(int retcode, char *msg);
static void		rmclass(char *aclass, int rm_remote, char *a_zoneName);
static void		usage(void);

/*
 * Set by -O debug: debug output is enabled?
 */
static boolean_t	debugFlag = B_FALSE;

/*
 * Set by -O preremovecheck: do remove dependency checking only
 */
static boolean_t	preremoveCheck = B_FALSE;

/* Set by -O parent-zone-name= */

static char		*parentZoneName = (char *)NULL;

/* Set by -O parent-zone-type= */

static char		*parentZoneType = (char *)NULL;

static int	nointeract;	/* != 0 no interaction with user should occur */



int
main(int argc, char *argv[])
{
	FILE		*fp;
	char		*abi_comp_ptr;
	char		*abi_sym_ptr;
	char		*p;
	char		*prog_full_name = NULL;
	char		*pt;
	char		*value;
	char		*vfstab_file = NULL;
	char		*zoneName = (char *)NULL;
	char		cmdbin[PATH_MAX];
	char		param[MAX_PKG_PARAM_LENGTH];
	char		path[PATH_MAX];
	char		script[PATH_MAX];
	int		c;
	int		err;
	int		fd;
	int		i;
	int		map_client = 1;
	int		n;
	int		nodelete = 0; 	/* do not delete file or run scripts */
	int		pkgrmremote = 0;	/* dont remove remote objects */
	struct sigaction	nact;
	struct sigaction	oact;
	PKGserver	pkgserver = NULL;
	VFP_T		*tmpfp;

	/* reset contents of all default paths */

	(void) memset(cmdbin, '\0', sizeof (cmdbin));

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

	/* Read PKG_INSTALL_ROOT from the environment, if it's there. */

	if (!set_inst_root(getenv("PKG_INSTALL_ROOT"))) {
		progerr(ERR_ROOT_SET);
		exit(1);
	}

	pkgserversetmode(DEFAULTMODE);

	/* parse command line options */

	while ((c = getopt(argc, argv, "?Aa:b:FMN:nO:oR:V:vy")) != EOF) {
		switch (c) {
		/*
		 * Same as pkgrm: Allow admin to remove package objects from
		 * a shared area from a reference client.
		 */
		case 'A':
			pkgrmremote++;
			break;

		/*
		 * Same as pkgrm: Use the installation
		 * administration file, admin, in place of the
		 * default admin file. pkgrm first looks in the
		 * current working directory for the administration
		 * file.  If the specified administration file is not
		 * in the current working directory, pkgrm looks in
		 * the /var/sadm/install/admin directory for the
		 * administration file.
		 */
		case 'a':
			admnfile = flex_device(optarg, 0);
			break;

		/*
		 * Same as pkgrm: location where package executables
		 * can be found - default is /usr/sadm/install/bin.
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
		 * Same as pkgrm: suppresses the removal of any
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
		 * Same as pkgrm: Instruct pkgrm not to use the
		 * $root_path/etc/vfstab file for determining the
		 * client's mount points. This option assumes the
		 * mount points are correct on the server and it
		 * behaves consistently with Solaris 2.5 and earlier
		 * releases.
		 */
		case 'M':
			map_client = 0;
			break;

		/*
		 * Different from pkgrm: specify program name to use
		 * for messages.
		 */
		case 'N':
			(void) set_prog_name(optarg);
			break;

		/*
		 * Same as pkgrm: package removal occurs in
		 * non-interactive mode.  Suppress output of the list of
		 * removed files. The default mode is interactive.
		 */
		case 'n':
			nointeract++;
			(void) echoSetFlag(B_FALSE);
			break;

		/*
		 * Almost same as pkgrm: the -O option allows the behavior
		 * of the package tools to be modified. Recognized options:
		 * -> debug
		 * ---> enable debugging output
		 * -> preremovecheck
		 * ---> perform a "pre removal" check of the specified
		 * ---> package - suppress all regular output and cause a
		 * ---> series of one or more "name=value" pair format lines
		 * ---> to be output that describes the "removability" of
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

				/* process preremovecheck option */

				if (strcmp(p, "preremovecheck") == 0) {
					preremoveCheck = B_TRUE;
					nointeract++;	/* -n */
					nodelete++;	/* -F */
					quitSetSilentExit(B_TRUE);
					continue;
				}

				/* process addzonename option */

				if (strcmp(p, "addzonename") == 0) {
					zoneName = z_get_zonename();
					quitSetZoneName(zoneName);
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
		 * Different from pkgrm: This is an old non-ABI package
		 */

		case 'o':
			script_in = PROC_XSTDIN;
			break;

		/*
		 * Same as pkgrm: defines the full path name of a
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
		 * Same as pkgrm: allow admin to establish the client
		 * filesystem using a vfstab-like file of stable format.
		 */
		case 'V':
			vfstab_file = flex_device(optarg, 2);
			map_client = 1;
			break;

		/*
		 * Same as pkgrm: trace all of the scripts that
		 * get executed by pkgrm, located in the
		 * pkginst/install directory. This option is used for
		 * debugging the procedural and non-procedural
		 * scripts.
		 */
		case 'v':
			pkgverbose++;
			break;

		/*
		 * Different from pkgrm: process this package using
		 * old non-ABI symlinks
		 */
		case 'y':
			set_nonABI_symlinks();
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
	 * ********************************************************************
	 * validate command line options
	 * ********************************************************************
	 */

	(void) echoDebugSetFlag(debugFlag);
	(void) log_set_verbose(debugFlag);

	if (z_running_in_global_zone()) {
		echoDebug(DBG_ENTRY_IN_GZ, prog_full_name);
	} else {
		echoDebug(DBG_ENTRY_IN_LZ, prog_full_name, getzoneid(),
		    z_get_zonename());
	}

	/* establish cmdbin path */

	if (cmdbin[0] == '\0') {
		(void) strlcpy(cmdbin, PKGBIN, sizeof (cmdbin));
	}

	/* Read the mount table */

	if (get_mntinfo(map_client, vfstab_file)) {
		quit(99);
	}

	/*
	 * This function defines the standard /var/... directories used later
	 * to construct the paths to the various databases.
	 */

	set_PKGpaths(get_inst_root());

	/*
	 * If this is being removed from a client whose /var filesystem is
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
	} else {
		pkgrmremote = 0;	/* Makes no sense on local host. */
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

	pkginst = argv[optind++];
	if (optind != argc) {
		usage();
	}

	/* validate package software database (contents) file */

	if (vcfile() == 0) {
		quit(99);
	}

	/*
	 * Acquire the package lock - currently at "remove initialization"
	 */

	if (!lockinst(get_prog_name(), pkginst, "remove-initial")) {
		quit(99);
	}

	/* establish temporary directory to use */

	tmpdir = getenv("TMPDIR");
	if (tmpdir == NULL) {
		tmpdir = P_tmpdir;
	}

	echoDebug(DBG_PKGREMOVE_TMPDIR, tmpdir);

	/*
	 * Initialize installation admin parameters by reading
	 * the adminfile.
	 */

	echoDebug(DBG_PKGREMOVE_ADMINFILE, admnfile ? admnfile : "");
	setadminFile(admnfile);

	/*
	 * about to perform first operation that could be modified by the
	 * preremove check option - if preremove check is selected (that is,
	 * only gathering dependencies), then output a debug message to
	 * indicate that the check is beginning. Also turn echo() output
	 * off and set various other flags.
	 */

	if (preremoveCheck == B_TRUE) {
		(void) echoSetFlag(B_FALSE);
		echoDebug(DBG_PKGREMOVE_PRERMCHK, pkginst ? pkginst : "",
		    zoneName ? zoneName : "global");
		rcksetPreremoveCheck(B_TRUE);
		rcksetZoneName(zoneName);
	}

	(void) snprintf(pkgloc, sizeof (pkgloc), "%s/%s", get_PKGLOC(),
	    pkginst);
	(void) snprintf(pkgbin, sizeof (pkgbin), "%s/install", pkgloc);
	(void) snprintf(rlockfile, sizeof (rlockfile), "%s/!R-Lock!", pkgloc);

	if (chdir(pkgbin)) {
		progerr(ERR_CHDIR, pkgbin);
		quit(99);
	}

	echo(MSG_PREREMOVE_REMINST, pkginst);

	/*
	 * if a lock file is present, then a previous attempt to remove this
	 * package may have been unsuccessful.
	 */

	if (access(rlockfile, F_OK) == 0) {
		echo(ERR_UNSUCC);
		echoDebug(DBG_PKGINSTALL_HAS_LOCKFILE, pkginst, rlockfile,
		    zoneName ? zoneName : "global");
	}

	/*
	 * Process all parameters from the pkginfo file
	 * and place them in the execution environment
	 */

	/* Add DB retreival of the pkginfo parameters here */
	(void) snprintf(path, sizeof (path), "%s/pkginfo", pkgloc);
	if ((fp = fopen(path, "r")) == NULL) {
		progerr(ERR_PKGINFO, path);
		quit(99);
	}

	/* Mount up the client if necessary. */
	if (map_client && !mount_client()) {
		logerr(MSG_MANMOUNT);
	}

	/* Get mount point of client */
	client_mntdir = getenv("CLIENT_MNTDIR");

	getuserlocale();

	/*
	 * current environment has been read; clear environment out
	 * so putparam() can be used to populate the new environment
	 * to be passed to any executables/scripts.
	 */

	environ = NULL;

	if (nonABI_symlinks()) {
		putparam("PKG_NONABI_SYMLINKS", "TRUE");
	}

	/*
	 * read the pkginfo file and fix any PKGSAV path - the correct
	 * install_root will be prepended to the existing path.
	 */

	param[0] = '\0';
	while (value = fpkgparam(fp, param)) {
		int validx = 0;
		char *newvalue;

		/* strip out any setting of PATH */

		if (strcmp(param, "PATH") == 0) {
			free(value);
			param[0] = '\0';
			continue;
		}

		/* if not PKGSAV then write out unchanged */

		if (strcmp(param, "PKGSAV") != 0) {
			putparam(param, value);
			free(value);
			param[0] = '\0';
			continue;
		}

		/*
		 * PKGSAV parameter found - interpret the directory:
		 * If in host:path format or marked with the leading "//",
		 * then there is no client-relative translation - take it
		 * literally later rather than use fixpath().
		 */

		if (strstr(value, ":/")) {
			/* no modification needed */
			validx = 0;
		} else if (strstr(value, "//") == value) {
			validx = 1;
		} else if (is_an_inst_root()) {
			/* This PKGSAV needs to be made client-relative. */
			newvalue = fixpath(value);
			free(value);
			value = newvalue;
		}
		putparam(param, value+validx);
		free(value);
		param[0] = '\0';
	}

	(void) fclose(fp);

	/* write parent condition information to environment */

	putConditionInfo(parentZoneName, parentZoneType);

	putuserlocale();

	/*
	 * Now do all the various setups based on ABI compliance
	 */

	/* Read the environment provided by the pkginfo file */
	abi_comp_ptr = getenv("NONABI_SCRIPTS");

	/* if not ABI compliant set global flag */
	abi_sym_ptr = getenv("PKG_NONABI_SYMLINKS");
	if (abi_sym_ptr && strncasecmp(abi_sym_ptr, "TRUE", 4) == 0) {
		set_nonABI_symlinks();
	}

	/*
	 * If pkginfo says it's not compliant then set non_abi_scripts.
	 */
	if (abi_comp_ptr && strncmp(abi_comp_ptr, "TRUE", 4) == 0) {
		script_in = PROC_XSTDIN;
	}

	/*
	 * Since this is a removal, we can tell whether it's absolute or
	 * not from the resident pkginfo file read above.
	 */
	if ((err = set_basedirs((getenv("BASEDIR") != NULL), adm.basedir,
	    pkginst, nointeract)) != 0) {
		quit(err);
	}

	/*
	 * See if were are removing a package that only wants to update
	 * the database or only remove files associated with CAS's. We
	 * only check the PKG_HOLLOW_VARIABLE variable if told to do so by
	 * the caller.
	 */

	if (is_depend_pkginfo_DB()) {
		pt = getenv(PKG_HOLLOW_VARIABLE);

		if ((pt != NULL) && (strncasecmp(pt, "true", 4) == 0)) {
			echoDebug(DBG_PKGREMOVE_HOLLOW_ENABLED);

			/*
			 * this is a hollow package and hollow package support
			 * is enabled -- override admin settings to suppress
			 * checks that do not make sense since no scripts will
			 * be executed and no files will be removed.
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

	put_path_params();

	/* If client mount point, add it to pkgremove environment */

	if (client_mntdir != NULL) {
		putparam("CLIENT_MNTDIR", client_mntdir);
	}

	/* Establish the class list and the class attributes. */

	if ((value = getenv("CLASSES")) != NULL) {
		cl_sets(qstrdup(value));
	} else {
		progerr(ERR_CLASSES, path);
		quit(99);
	}

	/* establish path and tmpdir */

	if (cmdbin[0] == '\0') {
		(void) strlcpy(cmdbin, PKGBIN, sizeof (cmdbin));
	}

	(void) snprintf(path, sizeof (path), "%s:%s", DEFPATH, cmdbin);
	putparam("PATH", path);

	putparam("TMPDIR", tmpdir);

	/*
	 * Check ulimit requirement (provided in pkginfo). The purpose of
	 * this limit is to terminate pathological file growth resulting from
	 * file edits in scripts. It does not apply to files in the pkgmap
	 * and it does not apply to any database files manipulated by the
	 * installation service.
	 */
	if (value = getenv("ULIMIT")) {
		if (assign_ulimit(value) == -1) {
			progerr(ERR_BADULIMIT, value);
			warnflag++;
		}
		putparam("PKG_ULIMIT", "TRUE");
	}

	/*
	 * If only gathering dependencies, check and output status of all
	 * remaining dependencies and exit.
	 */

	if (preremoveCheck == B_TRUE) {
		/*
		 * make sure current runlevel is appropriate
		 */

		(void) fprintf(stdout, "rckrunlevel=%d\n", rckrunlevel());

		/*
		 * determine if any packaging scripts provided with
		 * this package will execute as a priviledged user
		 */

		(void) fprintf(stdout, "rckpriv=%d\n", rckpriv());

		/*
		 * verify package dependencies
		 */

		(void) fprintf(stdout, "rckdepend=%d\n", rckdepend());

		/*
		 * ****** preremove check done - exit ******
		 */

		echoDebug(DBG_PKGREMOVE_PRERMCHK_OK);
		quit(0);
		/*NOTREACHED*/
	}

	/*
	 * Not gathering dependencies only, proceed to check dependencies
	 * and continue with the package removal operation.
	 */

	/*
	 * make sure current runlevel is appropriate
	 */

	n = rckrunlevel();

	if (n != 0) {
		quit(n);
		/* NOTREACHED */
	}

	/*
	 * determine if any packaging scripts provided with
	 * this package will execute as a priviledged user
	 */

	n = rckpriv();

	if (n != 0) {
		quit(n);
		/* NOTREACHED */
	}

	/*
	 * verify package dependencies
	 */
	n = rckdepend();

	if (n != 0) {
		quit(n);
		/* NOTREACHED */
	}

	/*
	 * *********************************************************************
	 * the actual removal of the package begins here
	 * *********************************************************************
	 */

	/*
	 * create lockfile to indicate start of removal
	 */
	started++;
	if ((fd = open(rlockfile, O_WRONLY|O_CREAT|O_TRUNC, 0644)) < 0) {
		progerr(ERR_LOCKFILE, rlockfile);
		quit(99);
	} else {
		(void) close(fd);
	}

	if (zoneName == (char *)NULL) {
		echo(MSG_PKGREMOVE_PROCPKG_GZ);
		echoDebug(DBG_PKGREMOVE_PROCPKG_GZ, pkginst, rlockfile);
	} else {
		echo(MSG_PKGREMOVE_PROCPKG_LZ, zoneName);
		echoDebug(DBG_PKGREMOVE_PROCPKG_LZ, pkginst, rlockfile,
		    zoneName);
	}
	if (delmap(0, pkginst, &pkgserver, &tmpfp) != 0) {
		progerr(ERR_DB_QUERY, pkginst);
		quit(99);
	}

	/*
	 * Run a preremove script if one is provided by the package.
	 * Don't execute preremove script if only updating the DB.
	 * Don't execute preremove script if files are not being deleted.
	 */

	/* update the lock - at the preremove script */
	lockupd("preremove");

	/* execute preremove script if one is provided */
	(void) snprintf(script, sizeof (script), "%s/preremove", pkgbin);
	if (access(script, F_OK) != 0) {
		/* no script present */
		echoDebug(DBG_PKGREMOVE_POC_NONE, pkginst,
		    zoneName ? zoneName : "global");
	} else if (nodelete) {
		/* not deleting files: skip preremove script */
		echoDebug(DBG_PKGREMOVE_POC_NODEL, pkginst, script,
		    zoneName ? zoneName : "global");
	} else if (is_depend_pkginfo_DB()) {
		/* updating db only: skip preremove script */
		echoDebug(DBG_PKGREMOVE_POC_DBUPD, pkginst, script,
		    zoneName ? zoneName : "global");
	} else {
		/* script present and ok to run: run the script */
		set_ulimit("preremove", ERR_PREREMOVE);
		if (zoneName == (char *)NULL) {
			echo(MSG_PKGREMOVE_EXEPOC_GZ);
			echoDebug(DBG_PKGREMOVE_EXEPOC_GZ, pkginst, script);
		} else {
			echo(MSG_PKGREMOVE_EXEPOC_LZ, zoneName);
			echoDebug(DBG_PKGREMOVE_EXEPOC_LZ, pkginst, script,
			    zoneName);
		}
		putparam("PKG_PROC_SCRIPT", "preremove");
		if (pkgverbose) {
			ckreturn(pkgexecl(script_in, PROC_STDOUT,
			    PROC_USER, PROC_GRP, SHELL, "-x",
			    script, NULL), ERR_PREREMOVE);
		} else {
			ckreturn(pkgexecl(script_in, PROC_STDOUT,
			    PROC_USER, PROC_GRP, SHELL, script,
			    NULL), ERR_PREREMOVE);
		}
		clr_ulimit();
	}

	/* update the lock - doing removal */

	lockupd("remove");

	/*
	 * Remove all components belonging to this package.
	 * Don't remove components if only updating the DB.
	 * Don't remove components if files are not being deleted.
	 */

	if (nodelete) {
		echoDebug(DBG_PKGREMOVE_REM_NODEL, pkginst,
		    zoneName ? zoneName : "global");
	} else if (is_depend_pkginfo_DB()) {
		echoDebug(DBG_PKGREMOVE_REM_DBUPD, pkginst,
		    zoneName ? zoneName : "global");
	} else {
		echoDebug(DBG_PKGREMOVE_REM, pkginst,
		    zoneName ? zoneName : "global");
		/*
		 * remove package one class at a time
		 */

		/* reverse order of classes */
		for (i = cl_getn() - 1; i >= 0; i--) {
			rmclass(cl_nam(i), pkgrmremote, zoneName);
		}

		rmclass(NULL, pkgrmremote, zoneName);
	}

	z_destroyMountTable();

	/*
	 * Execute postremove script, if any
	 * Don't execute postremove script if only updating the DB.
	 * Don't execute postremove script if files are not being deleted.
	 */

	/* update the lock - at the postremove script */
	lockupd("postremove");

	/* execute postremove script if one is provided */
	(void) snprintf(script, sizeof (script), "%s/postremove", pkgbin);
	if (access(script, F_OK) != 0) {
		/* no script present */
		echoDebug(DBG_PKGREMOVE_PIC_NONE, pkginst,
		    zoneName ? zoneName : "global");
	} else if (nodelete) {
		/* not deleting files: skip postremove script */
		echoDebug(DBG_PKGREMOVE_PIC_NODEL, pkginst, script,
		    zoneName ? zoneName : "global");
	} else if (is_depend_pkginfo_DB()) {
		/* updating db only: skip postremove script */
		echoDebug(DBG_PKGREMOVE_PIC_DBUPD, pkginst, script,
		    zoneName ? zoneName : "global");
	} else {
		/* script present and ok to run: run the script */
		set_ulimit("postremove", ERR_POSTREMOVE);
		if (zoneName == (char *)NULL) {
			echo(MSG_PKGREMOVE_EXEPIC_GZ);
			echoDebug(DBG_PKGREMOVE_EXEPIC_GZ, pkginst, script);
		} else {
			echo(MSG_PKGREMOVE_EXEPIC_LZ, zoneName);
			echoDebug(DBG_PKGREMOVE_EXEPIC_LZ, pkginst, script,
			    zoneName);
		}
		putparam("PKG_PROC_SCRIPT", "postremove");
		putparam("TMPDIR", tmpdir);
		if (pkgverbose) {
			ckreturn(pkgexecl(script_in, PROC_STDOUT, PROC_USER,
			    PROC_GRP, SHELL, "-x", script, NULL),
			    ERR_POSTREMOVE);
		} else {
			ckreturn(pkgexecl(script_in, PROC_STDOUT, PROC_USER,
			    PROC_GRP, SHELL, script, NULL),
			    ERR_POSTREMOVE);
		}
		clr_ulimit();
	}

	if (zoneName == (char *)NULL) {
		echo(MSG_PKGREMOVE_UPDINF_GZ);
	} else {
		echo(MSG_PKGREMOVE_UPDINF_LZ, zoneName);
	}

	if (delmap(1, pkginst, &pkgserver, &tmpfp) != 0) {
		progerr(ERR_DB_QUERY, pkginst);
		quit(99);
	}

	if (!warnflag && !failflag) {
		(void) chdir("/");
		if (rrmdir(pkgloc))
			warnflag++;
	}

	if ((z_running_in_global_zone() == B_TRUE) &&
	    (pkgIsPkgInGzOnly(get_inst_root(), pkginst) == B_TRUE)) {
		boolean_t	b;

		b = pkgRemovePackageFromGzonlyList(get_inst_root(), pkginst);
		if (b == B_FALSE) {
			progerr(ERR_PKGREMOVE_GZONLY_REMOVE, pkginst);
			ckreturn(1, NULL);
		}
	}

	/* release the generic package lock */

	(void) unlockinst();

	pkgcloseserver(pkgserver);

	quit(0);
	/* LINTED: no return */
}

int
issymlink(char *path)
{
	struct stat statbuf;

	/*
	 * Obtain status of path; if symbolic link get link's status
	 */

	if (lstat(path, &statbuf) != 0) {
		return (1);	/* not symlink */
	}

	/*
	 * Status obtained - if symbolic link, return 0
	 */

	if ((statbuf.st_mode & S_IFMT) == S_IFLNK) {
		return (0);	/* is a symlink */
	}

	/*
	 * Not a symbolic link - return 1
	 */

	return (1);		/* not symlink */
}

static void
rmclass(char *aclass, int rm_remote, char *a_zoneName)
{
	struct cfent	*ept;
	FILE	*fp;
	char	tmpfile[PATH_MAX];
	char	script[PATH_MAX];
	int	i;
	char	*tmp_path;
	char	*save_path = NULL;
	struct stat st;

	if (aclass == NULL) {
		for (i = 0; i < eptnum; i++) {
			if (eptlist[i] != NULL) {
				rmclass(eptlist[i]->pkg_class,
				    rm_remote, a_zoneName);
			}
		}
		return;
	}

	/* locate class action script to execute */
	(void) snprintf(script, sizeof (script), "%s/r.%s", pkgbin, aclass);
	if (access(script, F_OK) != 0) {
		(void) snprintf(script, sizeof (script), "%s/r.%s",
		    PKGSCR, aclass);
		if (access(script, F_OK) != 0)
			script[0] = '\0';
	}
	if (script[0] != '\0') {
		int td;

		(void) snprintf(tmpfile, sizeof (tmpfile), "%s/RMLISTXXXXXX",
		    tmpdir);
		td = mkstemp(tmpfile);
		if (td == -1) {
			progerr(ERR_TMPFILE);
			quit(99);
		}
		if ((fp = fdopen(td, "w")) == NULL) {
			progerr(ERR_WTMPFILE, tmpfile);
			quit(99);
		}
	}

	if (a_zoneName == (char *)NULL) {
		echo(MSG_PKGREMOVE_REMPATHCLASS_GZ, aclass);
	} else {
		echo(MSG_PKGREMOVE_REMPATHCLASS_LZ, aclass, a_zoneName);
	}

	/* process paths in reverse order */
	i = eptnum;
	while (--i >= 0) {
		ept = eptlist[i];

		if ((ept == NULL) || strcmp(aclass, ept->pkg_class)) {
			continue;
		}

		/* save the path, and prepend the ir */
		if (is_an_inst_root()) {
			save_path = ept->path;
			tmp_path = fixpath(ept->path);
			ept->path = tmp_path;
		}

		if (!ept->ftype || (ept->ftype == '^' && !script[0])) {
			/*
			 * A path owned by more than one package is marked with
			 * a NULL ftype (seems odd, but that's how it's
			 * done). Such files are sacro sanct. Shared editable
			 * files are a special case, and are marked with an
			 * ftype of '^'. These files should only be ignored if
			 * no class action script is present. It is the CAS's
			 * responsibility to not remove the editable object.
			 */
			echo(MSG_SHARED, ept->path);
		} else if (ept->pinfo->status == SERVED_FILE && !rm_remote) {
			/*
			 * If the path is provided to the client from a
			 * server, don't remove anything unless explicitly
			 * requested through the "-f" option.
			 */
			echo(MSG_SERVER, ept->path);
		} else if (script[0]) {
			/*
			 * If there's a class action script, just put the
			 * path name into the list.
			 */
			(void) fprintf(fp, "%s\n", ept->path);
		} else if (strchr("dx", ept->ftype) != NULL ||
		    (lstat(ept->path, &st) == 0 && S_ISDIR(st.st_mode))) {
			/* Directories are rmdir()'d. */

			if (rmdir(ept->path)) {
				if (errno == EBUSY) {
					echo(MSG_DIRBUSY, ept->path);
				} else if (errno == EEXIST) {
					echo(MSG_NOTEMPTY, ept->path);
				} else if (errno != ENOENT) {
					progerr(ERR_RMDIR, ept->path);
					warnflag++;
				}
			} else {
				if (ept->pinfo->status == SERVED_FILE) {
					echo(MSG_RMSRVR, ept->path);
				} else {
					echo("%s", ept->path);
				}
			}

		} else {
			/*
			 * Before removing this object one more
			 * check should be done to assure that a
			 * shared object is not removed.
			 * This can happen if the original object
			 * was incorrectly updated with the
			 * incorrect class identifier.
			 * This handles pathologcal cases that
			 * weren't handled above.
			 */
			if (ept->npkgs > 1) {
				echo(MSG_SHARED, ept->path);
				continue;
			}

			/* Regular files are unlink()'d. */

			if (unlink(ept->path)) {
				if (errno != ENOENT) {
					progerr(ERR_RMPATH, ept->path);
					warnflag++;
				}
			} else {
				if (ept->pinfo->status == SERVED_FILE) {
					echo(MSG_RMSRVR, ept->path);
				} else {
					echo("%s", ept->path);
				}
			}
		}

		/* restore the original path */

		if (is_an_inst_root()) {
			ept->path = save_path;
		}

		/*
		 * free memory allocated for this entry memory used for
		 * pathnames will be freed later by a call to pathdup()
		 */

		if (eptlist[i]) {
			free(eptlist[i]);
		}
		eptlist[i] = NULL;
	}
	if (script[0]) {
		(void) fclose(fp);
		set_ulimit(script, ERR_CASFAIL);
		if (pkgverbose)
			ckreturn(pkgexecl(tmpfile, CAS_STDOUT, CAS_USER,
			    CAS_GRP, SHELL, "-x", script, NULL),
			    ERR_CASFAIL);
		else
			ckreturn(pkgexecl(tmpfile, CAS_STDOUT, CAS_USER,
			    CAS_GRP, SHELL, script, NULL),
			    ERR_CASFAIL);
		clr_ulimit();
		if (isfile(NULL, tmpfile) == 0) {
			if (unlink(tmpfile) == -1)
				progerr(ERR_RMPATH, tmpfile);
		}
	}
}

static void
ckreturn(int retcode, char *msg)
{
	switch (retcode) {
	case 2:
	case 12:
	case 22:
		warnflag++;
		if (msg)
			progerr(msg);
		/* FALLTHROUGH */
	case 10:
	case 20:
		if (retcode >= 10)
			dreboot++;
		if (retcode >= 20)
			ireboot++;
		/* FALLTHROUGH */
	case 0:
		break; /* okay */

	case -1:
		retcode = 99;
		/* FALLTHROUGH */
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
		if (msg)
			progerr(msg);
		/* FALLTHROUGH */
	case 3:
	case 13:
	case 23:
		quit(retcode);
		/* NOT REACHED */
	default:
		if (msg)
			progerr(msg);
		quit(1);
	}
}

static void
usage(void)
{
	(void) fprintf(stderr, ERR_USAGE_PKGREMOVE);

	exit(1);
}
