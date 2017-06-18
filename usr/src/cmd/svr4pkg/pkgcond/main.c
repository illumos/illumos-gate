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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */


/*
 * Program:	pkgcond
 *
 * Function:	Implements the package command suite public utility pkgcond(1M)
 *
 * Usage:	pkgcond [-nv] [-O debug] condition [ argument ]
 *
 *		command options:
 *			-n - negate results of condition test
 *			-v - verbose output of condition testing
 *
 *		<condition> may be any one of:
 *			can_add_driver [path]
 *			can_remove_driver [path]
 *			can_update_driver [path]
 *			is_alternative_root [path]
 *			is_boot_environment [path]
 *			is_diskless_client [path]
 *			is_global_zone [path]
 *			is_mounted_miniroot [path]
 *			is_netinstall_image [path]
 *			is_nonglobal_zone [path]
 *			is_path_writable path
 *			is_running_system [path]
 *			is_what [path]
 *			is_whole_root_nonglobal_zone [path]
 *
 *		<option(s)> are specific to the condition used
 *
 * Input:	depends on command
 *
 * Output:	depends on command
 *
 * Exit status:	If the -n option is not specified:
 *		== 0 - the specified condition is true (or exists).
 *		== 1 - the specified condition is false (or does not exist).
 *		== 2 - command line usage errors (including bad keywords)
 *		== 3 - command failed to perform the test due to a fatal error
 *
 *		If the -n option is specified:
 *		== 0 - the specified condition is false (or does not exist).
 *		== 1 - the specified condition is true (or exists).
 *		== 2 - command line usage errors (including bad keywords)
 *		== 3 - command failed to perform the test due to a fatal error
 */

#include <stdio.h>
#include <sys/mnttab.h>
#include <sys/mntent.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <locale.h>
#include <errno.h>
#include <sys/param.h>
#include <assert.h>

#include <instzones_api.h>
#include <pkglib.h>
#include <install.h>
#include <libinst.h>
#include <libadm.h>
#include <messages.h>
#include "pkgcond.h"
#include "pkgcond_msgs.h"

/* Should be defined by cc -D */

#if	!defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif

/* commands to execute */

#define	LS_CMD		"/usr/bin/ls"

/*
 * type definition and "types" for testPath()
 */

typedef enum {
	TEST_EXISTS = 0x01,
	TEST_NOT_EXISTS = 0x02,
	TEST_IS_DIRECTORY = 0x04,
	TEST_IS_FILE = 0x08,
	TEST_NOT_DIRECTORY = 0x10,
	TEST_NOT_FILE = 0x20,
	TEST_IS_SYMBOLIC_LINK = 0x40,
	TEST_NOT_SYMBOLIC_LINK = 0x80,
	TEST_GLOBAL_TOKEN_IN_FILE = 0x100
} TEST_TYPES;

/* holds file system info */

struct fsi_t {
	char	*fsi_mntOptions;
	char	*fsi_fsType;
	char	*fsi_mntPoint;
};
typedef struct fsi_t	FSI_T;

/* holds parsed global data */

struct globalData_t {
		/* initial install: PKG_INIT_INSTALL=true */
	boolean_t gd_initialInstall;
		/* global zone install: SUNW_PKG_INSTALL_ZONENAME=global */
	boolean_t gd_globalZoneInstall;
		/* non-global zone install: SUNW_PKG_INSTALL_ZONENAME!=global */
	boolean_t gd_nonglobalZoneInstall;
		/* non-global zone is in a mounted state */
	boolean_t inMountedState;
		/* sorted list of all mounted file systems */
	FSI_T	*gd_fileSystemConfig;
		/* number of mounted file systems in list */
	long	gd_fileSystemConfigLen;
		/* current zone name */
	char	*gd_zoneName;
		/* SUNW_PKGCOND_GLOBAL_DATA:parentZone:zoneName */
	char	*gd_parentZoneName;
		/* SUNW_PKGCOND_GLOBAL_DATA:parentZone:zoneType */
	char	*gd_parentZoneType;
		/* root path to target: PKG_INSTALL_ROOT */
	char	*gd_installRoot;
		/* SUNW_PKGCOND_GLOBAL_DATA:currentZone:zoneName */
	char	*gd_currentZoneName;
		/* SUNW_PKGCOND_GLOBAL_DATA:currentZone:zoneType */
	char	*gd_currentZoneType;
		/* path provided on command line */
	char	*gd_cmdline_path;
};
typedef struct globalData_t	GLOBALDATA_T;

/* holds subcommands and their definitions */

struct cmd_t {
	char		*c_name;
	char		*c_args;
	int		(*c_func)(int argc, char **argv, GLOBALDATA_T *a_gdt);
};
typedef struct cmd_t	CMD_T;

/* Command function prototypes */

static int		cmd_can_add_driver(int argc, char **argv,
				GLOBALDATA_T *a_gdt);
static int		cmd_can_remove_driver(int argc, char **argv,
				GLOBALDATA_T *a_gdt);
static int		cmd_can_update_driver(int argc, char **argv,
				GLOBALDATA_T *a_gdt);
static int		cmd_is_alternative_root(int argc, char **argv,
				GLOBALDATA_T *a_gdt);
static int		cmd_is_boot_environment(int argc, char **argv,
				GLOBALDATA_T *a_gdt);
static int		cmd_is_diskless_client(int argc, char **argv,
				GLOBALDATA_T *a_gdt);
static int		cmd_is_global_zone(int argc, char **argv,
				GLOBALDATA_T *a_gdt);
static int		cmd_is_mounted_miniroot(int argc, char **argv,
				GLOBALDATA_T *a_gdt);
static int		cmd_is_netinstall_image(int argc, char **argv,
				GLOBALDATA_T *a_gdt);
static int		cmd_is_nonglobal_zone(int argc, char **argv,
				GLOBALDATA_T *a_gdt);
static int		cmd_is_path_writable(int argc, char **argv,
				GLOBALDATA_T *a_gdt);
static int		cmd_is_running_system(int argc, char **argv,
				GLOBALDATA_T *a_gdt);
static int		cmd_is_what(int argc, char **argv,
				GLOBALDATA_T *a_gdt);

/* Utility function Prototypes */

static boolean_t	getNegateResults(void);
static boolean_t	recursionCheck(int *r_recursion, char *a_function);
static int		adjustResults(int a_result);
static int		calculateFileSystemConfig(GLOBALDATA_T *a_gdt);
static int		getRootPath(char **r_rootPath);
static int		getZoneName(char **r_zoneName);
static int		mountOptionPresent(char *a_mntOptions, char *a_opt);
static int		parseGlobalData(char *a_envVar, GLOBALDATA_T **a_gdt);
static int		resolvePath(char **r_path);
static int		setRootPath(char *a_path, char *a_envVar,
    boolean_t a_mustExist);
static int		testPath(TEST_TYPES a_tt, char *format, ...);
static int		usage(char *a_format, ...);
static int		findToken(char *path, char *token);
static char		*getMountOption(char **p);
static void		dumpGlobalData(GLOBALDATA_T *a_gdt);
static void		removeLeadingWhitespace(char **a_str);
static void		setNegateResults(boolean_t setting);
static void		setVerbose(boolean_t);
static void		sortedInsert(FSI_T **r_list, long *a_listSize,
    char *a_mntPoint, char *a_fsType, char *a_mntOptions);
static void		setCmdLinePath(char **a_path, char **args,
    int num_args);

/* local static data */

static boolean_t	_negateResults = B_FALSE;
static char		*_rootPath = "/";

/* define subcommand data structure */

static CMD_T cmds[] = {
	{ "can_add_driver",		" [path]",
		cmd_can_add_driver },
	{ "can_remove_driver",		" [path]",
		cmd_can_remove_driver },
	{ "can_update_driver",		" [path]",
		cmd_can_update_driver },
	{ "is_alternative_root",	" [path]",
		cmd_is_alternative_root },
	{ "is_boot_environment",	" [path]",
		cmd_is_boot_environment },
	{ "is_diskless_client",		" [path]",
		cmd_is_diskless_client },
	{ "is_global_zone",		" [path]",
		cmd_is_global_zone },
	{ "is_mounted_miniroot",	" [path]",
		cmd_is_mounted_miniroot },
	{ "is_netinstall_image",	" [path]",
		cmd_is_netinstall_image },
	{ "is_nonglobal_zone",		" [path]",
		cmd_is_nonglobal_zone },
	{ "is_path_writable",		" path",
		cmd_is_path_writable },
	{ "is_running_system",		" [path]",
		cmd_is_running_system },
	{ "is_what", " [path]",
		cmd_is_what },
	/* last one must be all NULLs */
	{ NULL, NULL, NULL }
};

/*
 * *****************************************************************************
 * main
 * *****************************************************************************
 */

/*
 * Name:	main
 * Description:	main processing loop for pkgcond *
 * Return:	0 - condition is satisfied (true)
 *		1 - condition is not satisfied (false)
 *		2 - command line usage errors
 *		3 - failure to determine condition
 */

int
main(int argc, char **argv)
{
	GLOBALDATA_T	*gdt = NULL;
	char		**newargv;
	char		*p;
	int		cur_cmd;
	int		i;
	int		newargc;

	/* make standard output non-buffered */

	setbuf(stdout, NULL);

	/* set the default text domain for messaging */

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	/* remember command name */

	set_prog_name(argv[0]);

	/* tell spmi zones interface how to access package output functions */

	z_set_output_functions(echo, echoDebug, progerr);

	/* set verbose mode if appropriate environment variable is set */

	if (getenv(ENV_VAR_VERBOSE)) {
		/* same as -v */
		setVerbose(B_TRUE);
	}

	/* set debug mode if appropriate environment variable is set */

	if (getenv(ENV_VAR_DEBUG)) {
		/* same as -O debug */

		/* set sml tracing (sml.c) */
		smlSetVerbose(B_TRUE);

		/* set log and echo (interactive) message tracing */
		setVerbose(B_TRUE);

		/* enable echoDebug debugging messages */
		echoDebugSetFlag(B_TRUE);
	}

	/* generate usage if no options or arguments specified */

	if (argc <= 1) {
		(void) usage(MSG_NO_ARGUMENTS_SPECIFIED);
		return (R_USAGE);
	}

	/*
	 * process any arguments that can appear before the subcommand
	 */

	while ((i = getopt(argc, argv, ":O:vn?")) != EOF) {
		switch (i) {
		/*
		 * Not a public interface: the -O option allows the behavior
		 * of the package tools to be modified. Recognized options:
		 * -> debug
		 * ---> enable debugging output
		 */

		case 'O':
			for (p = strtok(optarg, ","); p != NULL;
			    p = strtok(NULL, ",")) {

				/* debug - enable all tracing */

				if (strcmp(p, "debug") == 0) {
					/* set sml tracing */
					smlSetVerbose(B_TRUE);
					/* set log/echo tracing */
					setVerbose(B_TRUE);
					/* enable debugging messages */
					echoDebugSetFlag(B_TRUE);
					continue;
				}

				progerr(ERR_INVALID_O_OPTION, p);
				return (adjustResults(R_USAGE));
			}
			break;

		/*
		 * Public interface: enable verbose (debug) output.
		 */

		case 'v':	/* verbose mode enabled */
			/* set command tracing only */
			setVerbose(B_TRUE);
			break;

		/*
		 * Public interface: negate output results.
		 */

		case 'n':
			setNegateResults(B_TRUE);
			break;

		/*
		 * unrecognized option
		 */

		case '?':
		default:
			(void) usage(MSG_INVALID_OPTION_SPECIFIED, optopt);
			return (R_USAGE);
		}
	}

	/*
	 * done processing options that can preceed subcommand
	 */

	/* error if no subcommand specified */

	if ((argc-optind) <= 0) {
		(void) usage(MSG_NO_ARGUMENTS_SPECIFIED);
		return (R_USAGE);
	}

	/* parse global data if environment variable set */

	if (parseGlobalData(PKGCOND_GLOBAL_VARIABLE, &gdt) != R_SUCCESS) {
		log_msg(LOG_MSG_ERR, ERR_CANNOT_USE_GLOBAL_DATA,
		    PKGCOND_GLOBAL_VARIABLE);
		return (R_ERROR);
	}

	if (setRootPath(gdt->gd_installRoot,
	    (strcmp(gdt->gd_installRoot, "/") == 0) ? NULL :
	    ENV_VAR_SET, B_TRUE) != R_SUCCESS) {
		log_msg(LOG_MSG_ERR, ERR_CANNOT_SET_ROOT_PATH,
		    ENV_VAR_PKGROOT);
		return (R_ERROR);
	}

	/* set path provided on the command line */

	setCmdLinePath(&(gdt->gd_cmdline_path), argv, argc);
	echoDebug(DBG_CMDLINE_PATH,
	    gdt->gd_cmdline_path == NULL ? "" : gdt->gd_cmdline_path);

	/* determine how file systems are layered in this zone */

	if (calculateFileSystemConfig(gdt) != R_SUCCESS) {
		log_msg(LOG_MSG_ERR, ERR_CANNOT_CALC_FS_CONFIG);
		return (R_ERROR);
	}

	/* dump global data read in (only if debugging) */

	dumpGlobalData(gdt);

	/* search for specified subcommand and execute if found */

	for (cur_cmd = 0; cmds[cur_cmd].c_name != NULL; cur_cmd++) {
		if (ci_streq(argv[optind], cmds[cur_cmd].c_name)) {
			int	result;

			/* make subcommand the first option */

			newargc = argc - optind;
			newargv = argv + optind;
			opterr = optind = 1; optopt = 0;


			/* call subcommand with its own argc/argv */

			result = cmds[cur_cmd].c_func(newargc, newargv, gdt);

			/* process result code and exit */

			result = adjustResults(result);
			log_msg(LOG_MSG_DEBUG, DBG_RESULTS, result);
			return (result);
		}
	}

	/* subcommand not found - output error message and exit with error */

	log_msg(LOG_MSG_ERR, ERR_BAD_SUB, argv[optind]);
	(void) usage(MSG_UNRECOGNIZED_CONDITION_SPECIFIED);
	return (R_USAGE);
}

/*
 * *****************************************************************************
 * command implementation functions
 * *****************************************************************************
 */

/*
 * Name:	cmd_is_diskless_client
 * Description:	determine if target is a diskless client
 * Scope:	public
 * Arguments:	argc,argv:
 *		  - optional path to target to test
 * Returns:	int
 *			== 0 - success
 *			!= 0 - failure
 * IMPLEMENTATION:
 *  - must not be initial installation to the install root
 *  - must not be installation of a zone
 *  - must not be a whole root non-global zone
 *  - must not be a non-global zone
 *  - must not be a mounted mini-root
 *  - must not be a netinstall image
 *  - must not be a boot environment
 *  - The package "SUNWdclnt" must be installed at "/"
 *  - The root path must not be "/"
 *  - The path "/export/exec/Solaris_\*\/usr" must exist at "/"
 *  - The directory "$ROOTDIR/../templates" must exist
 */

static int
cmd_is_diskless_client(int argc, char **argv, GLOBALDATA_T *a_gdt)
{
	char	*rootPath = NULL;
	char	cmd[MAXPATHLEN+1];
	int	c;
	int	r;
	int	rc;
static	char	*cmdName = "is_diskless_client";
static	int	recursion = 0;

	/* process any command line options */

	while ((c = getopt(argc, argv, ":")) != EOF) {
		switch (c) {
		case '\0':	/* prevent end-of-loop not reached warning */
			break;
		case '?':
		default:
			(void) usage(MSG_IS_INVALID_OPTION, optopt, cmdName);
			return (R_USAGE);
		}
	}

	/* prevent recursion */

	if (recursionCheck(&recursion, cmdName) == B_FALSE) {

		/*
		 * a diskless client cannot be any of the following
		 */

		/* cannot be non-global zone */

		r = cmd_is_nonglobal_zone(argc, argv, a_gdt);

		/* cannot be mounted miniroot */

		if (r != R_SUCCESS) {
			r = cmd_is_mounted_miniroot(argc, argv, a_gdt);
		}

		/* cannot be a netinstall image */

		if (r != R_SUCCESS) {
			r = cmd_is_netinstall_image(argc, argv, a_gdt);
		}

		/* cannot be a boot environment */

		if (r != R_SUCCESS) {
			r = cmd_is_boot_environment(argc, argv, a_gdt);
		}

		/* no need to guard against recursion any more */

		recursion--;

		/* return failure if any of the preceeding are true */

		switch (r) {
			case R_SUCCESS:
				return (R_FAILURE);
			case R_FAILURE:
				break;
			case R_USAGE:
			case R_ERROR:
			default:
				return (r);
		}
	}

	/* normalize argc/argv */

	argc -= optind;
	argv += optind;

	/* error if more than one argument */

	if (argc > 1) {
		log_msg(LOG_MSG_ERR, ERR_UNRECOGNIZED_OPTION, argv[1]);
		(void) usage(MSG_IS_INVALID_OPTION, argv[1]);
		return (R_USAGE);
	}

	/* process root path if first argument present */

	if (argc == 1) {
		if (setRootPath(argv[0], "argv[0]", B_TRUE) != R_SUCCESS) {
			return (R_ERROR);
		}
	}

	/* get current root path */

	r = getRootPath(&rootPath);
	if (r != R_SUCCESS) {
		return (r);
	}

	/* start of command debugging information */

	echoDebug(DBG_ROOTPATH_IS, rootPath);

	/* SUNWdclnt must be installed */

	if (pkgTestInstalled("SUNWdclnt", "/") != B_TRUE) {
		log_msg(LOG_MSG_DEBUG, DBG_IDLC_PKG_NOT_INSTALLED,
		    rootPath, "SUNWdclnt", "/");
		return (R_FAILURE);
	}

	/*   - $ROOTDIR must not be "/" */

	if (strcmp(rootPath, "/") == 0) {
		log_msg(LOG_MSG_DEBUG, DBG_IDLC_ROOTPATH_BAD, rootPath, "/");
		return (R_FAILURE);
	}

	/*   - zone name must be global */

	if (strcmp(a_gdt->gd_zoneName, GLOBAL_ZONENAME) != 0) {
		log_msg(LOG_MSG_DEBUG, DBG_IDLC_ZONE_BAD, rootPath,
		    GLOBAL_ZONENAME);
		return (R_FAILURE);
	}

	/*
	 * /export/exec/Solaris_"*"/usr must exist;
	 * create ls command to test:
	 * /usr/bin/ls /export/exec/Solaris_"*"/usr
	 */

	(void) snprintf(cmd, sizeof (cmd), "%s %s >/dev/null 2>&1",
	    LS_CMD, "/export/exec/Solaris_*/usr");

	/* execute command */

	rc = system(cmd);

	/* return error if ls returns something other than "0" */

	if (rc != 0) {
		log_msg(LOG_MSG_DEBUG, DBG_IDLC_PATH_MISSING,
		    rootPath, "/export/exec/Solaris_*/usr");
		return (R_FAILURE);
	}

	/*
	 * /usr must be empty on a diskless client:
	 * create ls command to test:
	 * /usr/bin/ls -d1 $ROOTDIR/usr/\*
	 */
	(void) snprintf(cmd, sizeof (cmd), "%s %s %s/%s >/dev/null 2>&1",
	    LS_CMD, "-1d", rootPath, "usr/*");

	/* execute command */

	rc = system(cmd);

	/* return error if ls returns "0" */

	if (rc == 0) {
		log_msg(LOG_MSG_DEBUG, DBG_IDLC_USR_IS_NOT_EMPTY,
		    rootPath);
		return (R_FAILURE);
	}

	/* there must be a templates directory at ${ROOTPATH}/../templates */

	r = testPath(TEST_EXISTS|TEST_IS_DIRECTORY,
	    "%s/%s", rootPath, "../templates");
	if (r != R_SUCCESS) {
		log_msg(LOG_MSG_DEBUG, DBG_IDLC_NO_TEMPLATES_PATH,
		    rootPath, rootPath, "../templates");
		return (R_FAILURE);
	}

	/* must not be initial installation to the install root */

	if ((a_gdt->gd_initialInstall == B_TRUE) &&
	    (strcmp(a_gdt->gd_installRoot, rootPath) == 0)) {
		/* initial install: install root cannot be diskless client */
		log_msg(LOG_MSG_DEBUG, DBG_IDLC_INITIAL_INSTALL, rootPath);
		return (R_FAILURE);
	}

	/* must not be installation of a zone */

	if ((a_gdt->gd_globalZoneInstall == B_TRUE) ||
	    (a_gdt->gd_nonglobalZoneInstall == B_TRUE)) {
		/* initial zone install: no path can be diskless client */
		log_msg(LOG_MSG_DEBUG, DBG_IDLC_ZONE_INSTALL, rootPath);
		return (R_FAILURE);
	}

	/* the path is a diskless client */

	log_msg(LOG_MSG_DEBUG, DBG_IDLC_PATH_IS_DISKLESS_CLIENT, rootPath);

	return (R_SUCCESS);
}

/*
 * Name:	cmd_is_global_zone
 * Description:	determine if target is a global zone
 * Scope:	public
 * Arguments:	argc,argv:
 *		  - optional path to target to test
 * Returns:	int
 *			== 0 - success
 *			!= 0 - failure
 * IMPLEMENTATION:
 *  - must not be initial installation to the install root
 *  - must not be installation of a non-global zone
 *  - must not be a non-global zone
 *  - must not be a mounted mini-root
 *  - must not be a netinstall image
 *  - must not be a diskless client
 *  - if $ROOTDIR is "/":
 *  -- if zone name is "GLOBAL", then is a global zone;
 *  -- else not a global zone.
 *  - $ROOTDIR/etc/zones must exist and be a directory
 *  - $ROOTDIR/.tmp_proto must not exist
 *  - $ROOTDIR/var must exist and must not be a symbolic link
 */

static int
cmd_is_global_zone(int argc, char **argv, GLOBALDATA_T *a_gdt)
{
	char	*rootPath = NULL;
	int	c;
	int	r;
static	char	*cmdName = "is_global_zone";
static	int	recursion = 0;

	/* process any command line options */

	while ((c = getopt(argc, argv, ":")) != EOF) {
		switch (c) {
		case '\0':	/* prevent end-of-loop not reached warning */
			break;
		case '?':
		default:
			(void) usage(MSG_IS_INVALID_OPTION, optopt, cmdName);
			return (R_USAGE);
		}
	}

	/* prevent recursion */

	if (recursionCheck(&recursion, cmdName) == B_FALSE) {

		/*
		 * a global zone cannot be any of the following
		 */

		/* cannot be a non-global zone */

		r = cmd_is_nonglobal_zone(argc, argv, a_gdt);

		/* cannot be a mounted miniroot */

		if (r != R_SUCCESS) {
			r = cmd_is_mounted_miniroot(argc, argv, a_gdt);
		}

		/* cannot be a netinstall image */

		if (r != R_SUCCESS) {
			r = cmd_is_netinstall_image(argc, argv, a_gdt);
		}

		/* cannot be a diskless client */

		if (r != R_SUCCESS) {
			r = cmd_is_diskless_client(argc, argv, a_gdt);
		}

		/* no need to guard against recursion any more */

		recursion--;

		/* return failure if any of the preceeding are true */

		switch (r) {
			case R_SUCCESS:
				return (R_FAILURE);
			case R_FAILURE:
				break;
			case R_USAGE:
			case R_ERROR:
			default:
				return (r);
		}
	}

	/* normalize argc/argv */

	argc -= optind;
	argv += optind;

	/* error if more than one argument */

	if (argc > 1) {
		log_msg(LOG_MSG_ERR, ERR_UNRECOGNIZED_OPTION, argv[1]);
		(void) usage(MSG_IS_INVALID_OPTION, argv[1]);
		return (R_USAGE);
	}

	/* process root path if first argument present */

	if (argc == 1) {
		if (setRootPath(argv[0], "argv[0]", B_TRUE) != R_SUCCESS) {
			return (R_ERROR);
		}
	}

	/* get current root path */

	r = getRootPath(&rootPath);
	if (r != R_SUCCESS) {
		return (r);
	}

	/* start of command debugging information */

	echoDebug(DBG_ROOTPATH_IS, rootPath);

	/* must not be initial installation to the install root */

	if ((a_gdt->gd_initialInstall == B_TRUE) &&
	    (strcmp(a_gdt->gd_installRoot, rootPath) == 0)) {
		/* initial install: install root cannot be global zone */
		log_msg(LOG_MSG_DEBUG, DBG_ISGZ_INITIAL_INSTALL, rootPath);
		return (R_FAILURE);
	}

	/* must not be installation of a non-global zone */

	if (a_gdt->gd_nonglobalZoneInstall == B_TRUE) {
		/* initial nonglobal zone install: no path can be global zone */
		log_msg(LOG_MSG_DEBUG, DBG_ISGZ_NGZ_ZONE_INSTALL, rootPath);
		return (R_FAILURE);
	}

	/* handle if global zone installation to the install root */

	if ((a_gdt->gd_globalZoneInstall == B_TRUE) &&
	    (strcmp(a_gdt->gd_installRoot, rootPath) == 0)) {
			/* the path is a global zone */

			log_msg(LOG_MSG_DEBUG, DBG_ISGZ_PATH_IS_GLOBAL_ZONE,
			    rootPath);

			return (R_SUCCESS);
	}

	/* true if current root is "/" and zone name is GLOBAL_ZONENAME */

	if (strcmp(rootPath, "/") == 0) {
		if (strcmp(a_gdt->gd_zoneName, GLOBAL_ZONENAME) == 0) {
			/* the path is a global zone */

			log_msg(LOG_MSG_DEBUG, DBG_ISGZ_PATH_IS_GLOBAL_ZONE,
			    rootPath);

			return (R_SUCCESS);
		}

		/* inside a non-global zone */

		log_msg(LOG_MSG_DEBUG, DBG_ISGZ_ZONENAME_ISNT_GLOBAL,
		    rootPath, a_gdt->gd_zoneName);

		return (R_FAILURE);
	}

	/*
	 * current root is not "/" - see if target looks like a global zone
	 *
	 * - rootpath is not "/"
	 * - and $ROOTDIR/etc/zones exists
	 * - and $ROOTDIR/.tmp_proto does not exist
	 * - and $ROOTDIR/var is not a symbolic link
	 */

	/* not global zone if /etc/zones does not exist */

	r = testPath(TEST_EXISTS|TEST_IS_DIRECTORY,
	    "%s/%s", rootPath, "/etc/zones");
	if (r != R_SUCCESS) {
		log_msg(LOG_MSG_DEBUG, DBG_ISGZ_PATH_ISNT_DIRECTORY,
		    rootPath, "/etc/zones");
		return (R_FAILURE);
	}

	/* .tmp_proto must not exist */

	r = testPath(TEST_NOT_EXISTS,
	    "%s/%s", rootPath, ".tmp_proto");
	if (r != R_SUCCESS) {
		log_msg(LOG_MSG_DEBUG, DBG_ISGZ_PATH_EXISTS,
		    rootPath, "/.tmp_proto");
		return (R_FAILURE);
	}

	/* /var must not be a symbolic link */

	r = testPath(TEST_EXISTS|TEST_NOT_SYMBOLIC_LINK,
	    "%s/%s", rootPath, "/var");
	if (r != R_SUCCESS) {
		log_msg(LOG_MSG_DEBUG, DBG_ISGZ_PATH_IS_SYMLINK,
		    rootPath, "/var");
		return (R_FAILURE);
	}

	/* the path is a global zone */

	log_msg(LOG_MSG_DEBUG, DBG_ISGZ_PATH_IS_GLOBAL_ZONE, rootPath);

	return (R_SUCCESS);
}

/*
 * Name:	cmd_is_netinstall_image
 * Description:	determine if target is a net install image
 * Scope:	public
 * Arguments:	argc,argv:
 *		  - optional path to target to test
 * Returns:	int
 *			== 0 - success
 *			!= 0 - failure
 * IMPLEMENTATION:
 *  - must not be initial installation to the install root
 *  - must not be installation of a zone
 *  - must not be a global zone
 *  - must not be a mounted mini-root
 *  - zone name must be "global"
 *  - $ROOTDIR/.tmp_proto must exist and must be a directory
 *  - $ROOTDIR/var must exist and must be a symbolic link
 *  - $ROOTDIR/tmp/kernel must exist and must be a directory
 *  - $ROOTDIR/.tmp_proto/kernel must exist and must be a symbolic link
 */

static int
cmd_is_netinstall_image(int argc, char **argv, GLOBALDATA_T *a_gdt)
{
	char	*rootPath = NULL;
	int	c;
	int	r;
static	char	*cmdName = "is_netinstall_image";
static	int	recursion = 0;

	/* process any command line options */

	while ((c = getopt(argc, argv, ":")) != EOF) {
		switch (c) {
		case '\0':	/* prevent end-of-loop not reached warning */
			break;
		case '?':
		default:
			(void) usage(MSG_IS_INVALID_OPTION, optopt, cmdName);
			return (R_USAGE);
		}
	}

	/* prevent recursion */

	if (recursionCheck(&recursion, cmdName) == B_FALSE) {

		/* a netinstall image cannot be a global zone */

		r = cmd_is_global_zone(argc, argv, a_gdt);

		/* no need to guard against recursion any more */

		recursion--;

		switch (r) {
			case R_SUCCESS:
				return (R_FAILURE);
			case R_FAILURE:
				break;
			case R_USAGE:
			case R_ERROR:
			default:
				return (r);
		}
	}

	/* normalize argc/argv */

	argc -= optind;
	argv += optind;

	/* error if more than one argument */

	if (argc > 1) {
		log_msg(LOG_MSG_ERR, ERR_UNRECOGNIZED_OPTION, argv[1]);
		(void) usage(MSG_IS_INVALID_OPTION, argv[1]);
		return (R_USAGE);
	}

	/* process root path if first argument present */

	if (argc == 1) {
		if (setRootPath(argv[0], "argv[0]", B_TRUE) != R_SUCCESS) {
			return (R_ERROR);
		}
	}

	/* get current root path */

	r = getRootPath(&rootPath);
	if (r != R_SUCCESS) {
		return (r);
	}

	/* start of command debugging information */

	echoDebug(DBG_ROOTPATH_IS, rootPath);

	/* current zone name must be "global" */

	if (strcmp(a_gdt->gd_zoneName, GLOBAL_ZONENAME) != 0) {
		log_msg(LOG_MSG_DEBUG, DBG_INIM_BAD_CURRENT_ZONE,
		    rootPath, GLOBAL_ZONENAME);
		return (R_FAILURE);
	}

	/* cannot be a mounted_miniroot */

	if (cmd_is_mounted_miniroot(argc, argv, a_gdt) == R_SUCCESS) {
		log_msg(LOG_MSG_DEBUG, DBG_IMRT_PATH_IS_MOUNTED_MINIROOT,
		    rootPath);
		return (R_FAILURE);
	}

	/* $ROOTDIR/.tmp_proto exists */

	r = testPath(TEST_EXISTS|TEST_IS_DIRECTORY,
	    "%s/%s", rootPath, ".tmp_proto");
	if (r != R_SUCCESS) {
		log_msg(LOG_MSG_DEBUG, DBG_INIM_PATH_ISNT_DIRECTORY,
		    rootPath, "/.tmp_proto");
		return (R_FAILURE);
	}

	/* $ROOTDIR/var is a symbolic link */

	r = testPath(TEST_IS_SYMBOLIC_LINK,
	    "%s/%s", rootPath, "/var");
	if (r != R_SUCCESS) {
		log_msg(LOG_MSG_DEBUG, DBG_INIM_PATH_ISNT_SYMLINK,
		    rootPath, "/var");
		return (R_FAILURE);
	}

	/* $ROOTDIR/tmp/kernel does exist */

	r = testPath(TEST_EXISTS|TEST_IS_DIRECTORY,
	    "%s/%s", rootPath, "/tmp/kernel");
	if (r != R_SUCCESS) {
		log_msg(LOG_MSG_DEBUG, DBG_INIM_PATH_ISNT_DIRECTORY,
		    rootPath, "/tmp/kernel");
		return (R_FAILURE);
	}

	/* $ROOTDIR/.tmp_proto/kernel is a symbolic link */

	r = testPath(TEST_IS_SYMBOLIC_LINK,
	    "%s/%s", rootPath, "/.tmp_proto/kernel");
	if (r != R_SUCCESS) {
		log_msg(LOG_MSG_DEBUG, DBG_INIM_PATH_ISNT_SYMLINK,
		    rootPath, "/.tmp_proto/kernel");
		return (R_FAILURE);
	}

	/* must not be initial installation to the install root */

	if ((a_gdt->gd_initialInstall == B_TRUE) &&
	    (strcmp(a_gdt->gd_installRoot, rootPath) == 0)) {
		/* initial install: install root cannot be netinstall image */
		log_msg(LOG_MSG_DEBUG, DBG_INIM_INITIAL_INSTALL, rootPath);
		return (R_FAILURE);
	}

	/* must not be installation of a zone */

	if ((a_gdt->gd_globalZoneInstall == B_TRUE) ||
	    (a_gdt->gd_nonglobalZoneInstall == B_TRUE)) {
		/* initial zone install: no path can be netinstall image */
		log_msg(LOG_MSG_DEBUG, DBG_INIM_ZONE_INSTALL, rootPath);
		return (R_FAILURE);
	}

	/* target is a netinstall image */

	log_msg(LOG_MSG_DEBUG, DBG_INIM_PATH_IS_NETINSTALL_IMAGE, rootPath);

	return (R_SUCCESS);
}

/*
 * Name:	cmd_is_mounted_miniroot
 * Description:	determine if target is a mounted miniroot image
 * Scope:	public
 * Arguments:	argc,argv:
 *		  - optional path to target to test
 * Returns:	int
 *			== 0 - success
 *			!= 0 - failure
 * IMPLEMENTATION:
 *  - must not be initial installation to the install root
 *  - must not be installation of a zone
 *  - zone name must be "global"
 *  - $ROOTDIR/tmp/kernel must exist and must be a symbolic link
 *  - $ROOTDIR/tmp/root/kernel must exist and must be a directory
 */

static int
cmd_is_mounted_miniroot(int argc, char **argv, GLOBALDATA_T *a_gdt)
{
	char	*rootPath = NULL;
	int	c;
	int	r;
static	char	*cmdName = "is_mounted_miniroot";
static	int	recursion = 0;

	/* process any command line options */

	while ((c = getopt(argc, argv, ":")) != EOF) {
		switch (c) {
		case '\0':	/* prevent end-of-loop not reached warning */
			break;
		case '?':
		default:
			(void) usage(MSG_IS_INVALID_OPTION, optopt, cmdName);
			return (R_USAGE);
		}
	}

	/* prevent recursion */

	if (recursionCheck(&recursion, cmdName) == B_FALSE) {
		recursion--;
	}

	/* normalize argc/argv */

	argc -= optind;
	argv += optind;

	/* error if more than one argument */

	if (argc > 1) {
		log_msg(LOG_MSG_ERR, ERR_UNRECOGNIZED_OPTION, argv[1]);
		(void) usage(MSG_IS_INVALID_OPTION, argv[1]);
		return (R_USAGE);
	}

	/* process root path if first argument present */

	if (argc == 1) {
		if (setRootPath(argv[0], "argv[0]", B_TRUE) != R_SUCCESS) {
			return (R_ERROR);
		}
	}

	/* get current root path */

	r = getRootPath(&rootPath);
	if (r != R_SUCCESS) {
		return (r);
	}

	/* start of command debugging information */

	echoDebug(DBG_ROOTPATH_IS, rootPath);

	/* current zone name must be "global" */

	if (strcmp(a_gdt->gd_zoneName, GLOBAL_ZONENAME) != 0) {
		log_msg(LOG_MSG_DEBUG, DBG_IMRT_BAD_CURRENT_ZONE,
		    rootPath, GLOBAL_ZONENAME);
		return (R_FAILURE);
	}

	/* $ROOTDIR/tmp/kernel is a symbolic link */

	r = testPath(TEST_IS_SYMBOLIC_LINK,
	    "%s/%s", rootPath, "/tmp/kernel");
	if (r != R_SUCCESS) {
		log_msg(LOG_MSG_DEBUG, DBG_IMRT_PATH_ISNT_SYMLINK,
		    rootPath, "/tmp/kernel");
		return (R_FAILURE);
	}

	/* $ROOTDIR/tmp/root/kernel is a directory */

	r = testPath(TEST_EXISTS|TEST_IS_DIRECTORY,
	    "%s/%s", rootPath, "/tmp/root/kernel");
	if (r != R_SUCCESS) {
		log_msg(LOG_MSG_DEBUG, DBG_IMRT_PATH_ISNT_DIRECTORY,
		    rootPath, "/tmp/root/kernel");
		return (R_FAILURE);
	}

	/* must not be initial installation to the install root */

	if ((a_gdt->gd_initialInstall == B_TRUE) &&
	    (strcmp(a_gdt->gd_installRoot, rootPath) == 0)) {
		/* initial install: install root cannot be mounted miniroot */
		log_msg(LOG_MSG_DEBUG, DBG_IMRT_INITIAL_INSTALL, rootPath);
		return (R_FAILURE);
	}

	/* must not be installation of a zone */

	if ((a_gdt->gd_globalZoneInstall == B_TRUE) ||
	    (a_gdt->gd_nonglobalZoneInstall == B_TRUE)) {
		/* initial zone install: no path can be mounted miniroot */
		log_msg(LOG_MSG_DEBUG, DBG_IMRT_ZONE_INSTALL, rootPath);
		return (R_FAILURE);
	}

	/* target is a mounted miniroot */

	log_msg(LOG_MSG_DEBUG, DBG_IMRT_PATH_IS_MOUNTED_MINIROOT, rootPath);

	return (R_SUCCESS);
}

/*
 * Name:	cmd_is_nonglobal_zone
 * Description:	determine if target is a global zone
 * Scope:	public
 * Arguments:	argc,argv:
 *		  - optional path to target to test
 * Returns:	int
 *			== 0 - success
 *			!= 0 - failure
 *  - must not be initial installation to the install root
 *  - must not be installation of a global zone
 *  - success if installation of a non-global zone
 */

static int
cmd_is_nonglobal_zone(int argc, char **argv, GLOBALDATA_T *a_gdt)
{
	char	*rootPath = NULL;
	int	c;
	int	r;
static	char	*cmdName = "is_nonglobal_zone";
static	int	recursion = 0;

	/* process any command line options */

	while ((c = getopt(argc, argv, ":")) != EOF) {
		switch (c) {
		case '\0':	/* prevent end-of-loop not reached warning */
			break;
		case '?':
		default:
			(void) usage(MSG_IS_INVALID_OPTION, optopt, cmdName);
			return (R_USAGE);
		}
	}

	/* prevent recursion */

	if (recursionCheck(&recursion, cmdName) == B_FALSE) {
		recursion--;
	}

	/* normalize argc/argv */

	argc -= optind;
	argv += optind;

	/* error if more than one argument */

	if (argc > 1) {
		log_msg(LOG_MSG_ERR, ERR_UNRECOGNIZED_OPTION, argv[1]);
		(void) usage(MSG_IS_INVALID_OPTION, argv[1]);
		return (R_USAGE);
	}

	/* process root path if first argument present */

	if (argc == 1) {
		if (setRootPath(argv[0], "argv[0]", B_TRUE) != R_SUCCESS) {
			return (R_ERROR);
		}
	}

	/* get current root path */

	r = getRootPath(&rootPath);
	if (r != R_SUCCESS) {
		return (r);
	}

	/* start of command debugging information */

	echoDebug(DBG_ROOTPATH_IS, rootPath);

	/* handle if non-global zone installation to the install root */

	if ((a_gdt->gd_nonglobalZoneInstall == B_TRUE) &&
	    (strcmp(a_gdt->gd_installRoot, rootPath) == 0)) {
		log_msg(LOG_MSG_DEBUG, DBG_NGZN_INSTALL_ZONENAME_IS_NGZ,
		    rootPath, a_gdt->gd_zoneName);
		return (R_SUCCESS);
	}

	/* must not be initial installation to the install root */

	if ((a_gdt->gd_initialInstall == B_TRUE) &&
	    (strcmp(a_gdt->gd_installRoot, rootPath) == 0)) {
		/* initial install: install root cannot be non-global zone */
		log_msg(LOG_MSG_DEBUG, DBG_NGZN_INITIAL_INSTALL, rootPath);
		return (R_FAILURE);
	}

	/* must not be installation of a global zone */

	if ((a_gdt->gd_globalZoneInstall == B_TRUE) ||
	    (a_gdt->gd_nonglobalZoneInstall == B_TRUE)) {
		/* initial global zone install: no path can be nonglobal zone */
		log_msg(LOG_MSG_DEBUG, DBG_NGZN_GLOBAL_ZONE_INSTALL, rootPath);
		return (R_FAILURE);
	}

	/*
	 * *********************************************************************
	 * if root directory is "/" then the only thing that needs to be done is
	 * to test the zone name directly - if the zone name is "global" then
	 * the target is not a non-global zone; otherwise if the zone name is
	 * not "global" then the target IS a non-global zone.
	 * *********************************************************************
	 */

	if (strcmp(rootPath, "/") == 0) {
		/* target is current running root */
		if (strcmp(a_gdt->gd_zoneName, GLOBAL_ZONENAME) == 0) {
			/* in the global zone */
			log_msg(LOG_MSG_DEBUG, DBG_NGZN_ZONENAME_ISNT_NGZ,
			    rootPath, a_gdt->gd_zoneName);
			return (R_FAILURE);
		}
		/* in a non-global zone */
		log_msg(LOG_MSG_DEBUG, DBG_NGZN_ZONENAME_IS_NGZ,
		    rootPath, a_gdt->gd_zoneName);
		return (R_SUCCESS);
	}

	/*
	 * $ROOTDIR/etc/zones/index must exist in a global zone. It also
	 * exists in a non-global zone after s10u4 but we can't check that
	 * since it is undeterministic for all releases so we only check
	 * for the global zone here.
	 */

	r = testPath(TEST_EXISTS, "%s/%s", rootPath, "/etc/zones/index");
	if (r == R_SUCCESS) {

		/* See if "global" exists in .../etc/zones/index */

		if (testPath(TEST_GLOBAL_TOKEN_IN_FILE, "%s/%s", rootPath,
		    "/etc/zones/index") != R_SUCCESS) {
			log_msg(LOG_MSG_DEBUG, DBG_NGZN_ZONENAME_ISNT_NGZ,
			    rootPath, GLOBAL_ZONENAME);
			return (R_FAILURE);
		}
	}

	/*
	 * *********************************************************************
	 * If the root directory is "/" then you can use only the zone
	 * name to determine if the zone is non-global or not since the
	 * package is being installed or removed to the current "zone".
	 *
	 * Since the root directory being tested is not "/" then you have to
	 * look into the target to try and infer zone type using means other
	 * than the zone name only.
	 * *********************************************************************
	 */

	/* reject if any items found that cannot be in a non-global zone */

	/* .tmp_proto must not exist */

	r = testPath(TEST_NOT_EXISTS, "%s/%s", rootPath, ".tmp_proto");
	if (r != R_SUCCESS) {
		/* $R/.tmp_proto cannot exist in a non-global zone */
		log_msg(LOG_MSG_DEBUG, DBG_NGZN_PATH_EXISTS,
		    rootPath, "/.tmp_proto");
		return (R_FAILURE);
	}

	/* /var must not be a symbolic link */

	r = testPath(TEST_EXISTS|TEST_NOT_SYMBOLIC_LINK,
	    "%s/%s", rootPath, "/var");
	if (r != R_SUCCESS) {
		/* $R/var cannot be a symbolic link in a non-global zone */
		log_msg(LOG_MSG_DEBUG, DBG_NGZN_PATH_DOES_NOT_EXIST,
		    rootPath, "/var");
		return (R_FAILURE);
	}

	/* $ROOTDIR/tmp/root/kernel must not exist */

	r = testPath(TEST_NOT_EXISTS,
	    "%s/%s", rootPath, "/tmp/root/kernel");
	if (r != R_SUCCESS) {
		/* $R/tmp/root/kernel cannot exist in a non-global zone */
		log_msg(LOG_MSG_DEBUG, DBG_NGZN_PATH_EXISTS,
		    rootPath, "/tmp/root/kernel");
		return (R_FAILURE);
	}

	/*
	 * *********************************************************************
	 * no items exist in $ROOTDIR that identify something other than
	 * a non-global zone.
	 *
	 * if in global zone no more tests possible: is a non-global zone
	 * *********************************************************************
	 */

	if (strcmp(a_gdt->gd_zoneName, GLOBAL_ZONENAME) == 0) {
		/* in the global zone */
		log_msg(LOG_MSG_DEBUG, DBG_NGZN_IN_GZ_IS_NONGLOBAL_ZONE,
		    rootPath);
		return (R_SUCCESS);
	}

	/*
	 * *********************************************************************
	 * In non-global zone: interrogate zone name and type.
	 *
	 * The parent zone is the zone that the "pkgadd" or "pkgrm" command was
	 * run in. The child zone is the zone that the "pkginstall" or
	 * "pkgremove" command was run in.
	 * *********************************************************************
	 */

	/*
	 * If parent zone name and current zone name defined, and
	 * both zone names are the same, since pkgcond is running
	 * inside of a non-global zone, this is how the scratch
	 * zone is implemented, so target is a non-global zone
	 */

	if ((a_gdt->gd_parentZoneName != NULL) &&
	    (a_gdt->gd_currentZoneName != NULL) &&
	    (strcmp(a_gdt->gd_parentZoneName,
	    a_gdt->gd_currentZoneName) == 0)) {
			/* parent and current zone name identical: non-gz */
			log_msg(LOG_MSG_DEBUG, DBG_NGZN_PARENT_CHILD_SAMEZONE,
			    rootPath, a_gdt->gd_parentZoneName);
			return (R_SUCCESS);
	}

	/*
	 * In non-global zone if zone specific read only FS's exist
	 * or it is in a mounted state.
	 */

	if (a_gdt->inMountedState) {
		log_msg(LOG_MSG_DEBUG, DBG_NGZN_IS_NONGLOBAL_ZONE, rootPath);
		return (R_SUCCESS);
	}

	/*
	 * the parent and current zone name are not the same;
	 * interrogate the zone types: the parent must be global
	 * and the current must be non-global, which would be set
	 * when a package command is run in the global zone that in
	 * turn runs a package command within the non-global zone.
	 */

	/* if defined, parent zone type must be "global" */

	if ((a_gdt->gd_parentZoneType != NULL) &&
	    (strcmp(a_gdt->gd_parentZoneType, "nonglobal") == 0)) {
		log_msg(LOG_MSG_DEBUG, DBG_NGZN_BAD_PARENT_ZONETYPE,
		    rootPath, "nonglobal");
		return (R_FAILURE);
	}

	/* if defined, current zone type must be "nonglobal" */

	if ((a_gdt->gd_currentZoneType != NULL) &&
	    (strcmp(a_gdt->gd_currentZoneType, GLOBAL_ZONENAME) == 0)) {
		log_msg(LOG_MSG_DEBUG, DBG_NGZN_BAD_CURRENT_ZONETYPE,
		    rootPath, GLOBAL_ZONENAME);
		return (R_FAILURE);
	}

	/*
	 * *********************************************************************
	 * no other tests possible: target is a non-global zone
	 * *********************************************************************
	 */

	log_msg(LOG_MSG_DEBUG, DBG_NGZN_IS_NONGLOBAL_ZONE, rootPath);

	return (R_SUCCESS);
}

/*
 * Name:	cmd_is_running_system
 * Description:	determine if target is a global zone
 * Scope:	public
 * Arguments:	argc,argv:
 *		  - optional path to target to test
 * Returns:	int
 *			== 0 - success
 *			!= 0 - failure
 * IMPLEMENTATION:
 *  - must not be initial installation to the install root
 *  - must not be installation of a zone
 *  - must not be a diskless client
 *  - $ROOTDIR must be "/"
 *  - zone name must be "global"
 */

static int
cmd_is_running_system(int argc, char **argv, GLOBALDATA_T *a_gdt)
{
	char	*rootPath = NULL;
	int	c;
	int	r;
static	char	*cmdName = "is_running_system";
static	int	recursion = 0;

	/* process any command line options */

	while ((c = getopt(argc, argv, ":")) != EOF) {
		switch (c) {
		case '\0':	/* prevent end-of-loop not reached warning */
			break;
		case '?':
		default:
			(void) usage(MSG_IS_INVALID_OPTION, optopt, cmdName);
			return (R_USAGE);
		}
	}

	/* prevent recursion */

	if (recursionCheck(&recursion, cmdName) == B_FALSE) {

		/* a running system cannot be a diskless client */

		r = cmd_is_diskless_client(argc, argv, a_gdt);

		/* no need to guard against recursion any more */

		recursion--;

		switch (r) {
			case R_SUCCESS:
				return (R_FAILURE);
			case R_FAILURE:
				break;
			case R_USAGE:
			case R_ERROR:
			default:
				return (r);
		}
	}

	/* normalize argc/argv */

	argc -= optind;
	argv += optind;

	/* error if more than one argument */

	if (argc > 1) {
		log_msg(LOG_MSG_ERR, ERR_UNRECOGNIZED_OPTION, argv[1]);
		(void) usage(MSG_IS_INVALID_OPTION, argv[1]);
		return (R_USAGE);
	}

	/* process root path if first argument present */

	if (argc == 1) {
		if (setRootPath(argv[0], "argv[0]", B_TRUE) != R_SUCCESS) {
			return (R_ERROR);
		}
	}

	/* get current root path */

	r = getRootPath(&rootPath);
	if (r != R_SUCCESS) {
		return (r);
	}

	/* start of command debugging information */

	echoDebug(DBG_ROOTPATH_IS, rootPath);

	/* if root path is "/" then check zone name */

	if (strcmp(rootPath, "/") != 0) {
		log_msg(LOG_MSG_DEBUG, DBG_IRST_ROOTPATH_BAD, rootPath, "/");
		return (R_FAILURE);
	}

	/* zone name must be global */

	if (strcmp(a_gdt->gd_zoneName, GLOBAL_ZONENAME) != 0) {
		log_msg(LOG_MSG_DEBUG, DBG_IRST_ZONE_BAD, rootPath,
		    GLOBAL_ZONENAME);
		return (R_FAILURE);
	}

	/* must not be initial installation to the install root */

	if ((a_gdt->gd_initialInstall == B_TRUE) &&
	    (strcmp(a_gdt->gd_installRoot, rootPath) == 0)) {
		/* initial install: install root cannot be the running system */
		log_msg(LOG_MSG_DEBUG, DBG_IRST_INITIAL_INSTALL, rootPath);
		return (R_FAILURE);
	}

	/* must not be installation of a zone */

	if ((a_gdt->gd_globalZoneInstall == B_TRUE) ||
	    (a_gdt->gd_nonglobalZoneInstall == B_TRUE)) {
		/* initial zone install: no path can be running system */
		log_msg(LOG_MSG_DEBUG, DBG_IRST_ZONE_INSTALL, rootPath);
		return (R_FAILURE);
	}

	/* target is a running system */

	log_msg(LOG_MSG_DEBUG, DBG_IRST_PATH_IS_RUNNING_SYSTEM, rootPath);

	return (R_SUCCESS);
}

/*
 * Name:	cmd_can_add_driver
 * Description:	determine if target is a global zone
 * Scope:	public
 * Arguments:	argc,argv:
 *		  - optional path to target to test
 * Returns:	int
 *			== 0 - success
 *			!= 0 - failure
 * Implementation:
 * A driver can be added to the system if the components of a Solaris
 * instance capable of loading drivers is present and it is not the
 * currently running system.
 */

static int
cmd_can_add_driver(int argc, char **argv, GLOBALDATA_T *a_gdt)
{
	char	*rootPath = NULL;
	int	c;
	int	r;
static	char	*cmdName = "can_add_driver";
static	int	recursion = 0;

	/* process any command line options */

	while ((c = getopt(argc, argv, ":")) != EOF) {
		switch (c) {
		case '\0':	/* prevent end-of-loop not reached warning */
			break;
		case '?':
		default:
			(void) usage(MSG_IS_INVALID_OPTION, optopt, cmdName);
			return (R_USAGE);
		}
	}

	/* prevent recursion */

	if (recursionCheck(&recursion, cmdName) == B_FALSE) {

		/* see if this is the current running system */

		r = cmd_is_running_system(argc, argv, a_gdt);

		/* cannot be a diskless client */

		if (r != R_SUCCESS) {
			r = cmd_is_diskless_client(argc, argv, a_gdt);
		}

		/* no need to guard against recursion any more */

		recursion--;

		switch (r) {
			case R_SUCCESS:
				/* is a running system */
				return (R_FAILURE);
			case R_FAILURE:
				/* not a running syste */
				break;
			case R_USAGE:
			case R_ERROR:
			default:
				/* cannot determine if is a running system */
				return (r);
		}
	}

	/* normalize argc/argv */

	argc -= optind;
	argv += optind;

	/* error if more than one argument */

	if (argc > 1) {
		log_msg(LOG_MSG_ERR, ERR_UNRECOGNIZED_OPTION, argv[1]);
		(void) usage(MSG_IS_INVALID_OPTION, argv[1]);
		return (R_USAGE);
	}

	/* process root path if first argument present */

	if (argc == 1) {
		if (setRootPath(argv[0], "argv[0]", B_TRUE) != R_SUCCESS) {
			return (R_ERROR);
		}
	}

	/* get current root path */

	r = getRootPath(&rootPath);
	if (r != R_SUCCESS) {
		return (r);
	}

	/* start of command debugging information */

	echoDebug(DBG_ROOTPATH_IS, rootPath);

	/* /etc must exist and must not be a symbolic link */

	r = testPath(TEST_EXISTS|TEST_NOT_SYMBOLIC_LINK,
	    "%s/%s", rootPath, "/etc");
	if (r != R_SUCCESS) {
		log_msg(LOG_MSG_DEBUG, DBG_ADDV_PATH_IS_SYMLINK,
		    rootPath, "/etc");
		return (R_FAILURE);
	}

	/* /platform must exist and must not be a symbolic link */

	r = testPath(TEST_EXISTS|TEST_NOT_SYMBOLIC_LINK,
	    "%s/%s", rootPath, "/platform");
	if (r != R_SUCCESS) {
		log_msg(LOG_MSG_DEBUG, DBG_ADDV_PATH_IS_SYMLINK,
		    rootPath, "/platform");
		return (R_FAILURE);
	}

	/* /kernel must exist and must not be a symbolic link */

	r = testPath(TEST_EXISTS|TEST_NOT_SYMBOLIC_LINK,
	    "%s/%s", rootPath, "/kernel");
	if (r != R_SUCCESS) {
		log_msg(LOG_MSG_DEBUG, DBG_ADDV_PATH_IS_SYMLINK,
		    rootPath, "/kernel");
		return (R_FAILURE);
	}

	/* can add a driver */

	log_msg(LOG_MSG_DEBUG, DBG_ADDV_YES, rootPath);

	return (R_SUCCESS);
}

/*
 * Name:	cmd_can_update_driver
 * Description:	determine if target is a global zone
 * Scope:	public
 * Arguments:	argc,argv:
 *		  - optional path to target to test
 * Returns:	int
 *			== 0 - success
 *			!= 0 - failure
 * Implementation:
 * A driver can be added to the system if the components of a Solaris
 * instance capable of loading drivers is present and it is not the
 * currently running system.
 */

static int
cmd_can_update_driver(int argc, char **argv, GLOBALDATA_T *a_gdt)
{
	char	*rootPath = NULL;
	int	c;
	int	r;
static	char	*cmdName = "can_update_driver";
static	int	recursion = 0;

	/* process any command line options */

	while ((c = getopt(argc, argv, ":")) != EOF) {
		switch (c) {
		case '\0':	/* prevent end-of-loop not reached warning */
			break;
		case '?':
		default:
			(void) usage(MSG_IS_INVALID_OPTION, optopt, cmdName);
			return (R_USAGE);
		}
	}

	/* prevent recursion */

	if (recursionCheck(&recursion, cmdName) == B_FALSE) {

		/* see if this is the current running system */

		r = cmd_is_running_system(argc, argv, a_gdt);

		/* cannot be a diskless client */

		if (r != R_SUCCESS) {
			r = cmd_is_diskless_client(argc, argv, a_gdt);
		}

		/* no need to guard against recursion any more */

		recursion--;

		switch (r) {
			case R_SUCCESS:
				/* is a running system */
				return (R_FAILURE);
			case R_FAILURE:
				/* not a running syste */
				break;
			case R_USAGE:
			case R_ERROR:
			default:
				/* cannot determine if is a running system */
				return (r);
		}
	}

	/* normalize argc/argv */

	argc -= optind;
	argv += optind;

	/* error if more than one argument */

	if (argc > 1) {
		log_msg(LOG_MSG_ERR, ERR_UNRECOGNIZED_OPTION, argv[1]);
		(void) usage(MSG_IS_INVALID_OPTION, argv[1]);
		return (R_USAGE);
	}

	/* process root path if first argument present */

	if (argc == 1) {
		if (setRootPath(argv[0], "argv[0]", B_TRUE) != R_SUCCESS) {
			return (R_ERROR);
		}
	}

	/* get current root path */

	r = getRootPath(&rootPath);
	if (r != R_SUCCESS) {
		return (r);
	}

	/* start of command debugging information */

	echoDebug(DBG_ROOTPATH_IS, rootPath);

	/* /etc must exist and must not be a symbolic link */

	r = testPath(TEST_EXISTS|TEST_NOT_SYMBOLIC_LINK,
	    "%s/%s", rootPath, "/etc");
	if (r != R_SUCCESS) {
		log_msg(LOG_MSG_DEBUG, DBG_UPDV_PATH_IS_SYMLINK,
		    rootPath, "/etc");
		return (R_FAILURE);
	}

	/* /platform must exist and must not be a symbolic link */

	r = testPath(TEST_EXISTS|TEST_NOT_SYMBOLIC_LINK,
	    "%s/%s", rootPath, "/platform");
	if (r != R_SUCCESS) {
		log_msg(LOG_MSG_DEBUG, DBG_UPDV_PATH_IS_SYMLINK,
		    rootPath, "/platform");
		return (R_FAILURE);
	}

	/* /kernel must exist and must not be a symbolic link */

	r = testPath(TEST_EXISTS|TEST_NOT_SYMBOLIC_LINK,
	    "%s/%s", rootPath, "/kernel");
	if (r != R_SUCCESS) {
		log_msg(LOG_MSG_DEBUG, DBG_UPDV_PATH_IS_SYMLINK,
		    rootPath, "/kernel");
		return (R_FAILURE);
	}

	/* can update driver */

	log_msg(LOG_MSG_DEBUG, DBG_UPDV_YES, rootPath);

	return (R_SUCCESS);
}

/*
 * Name:	cmd_can_remove_driver
 * Description:	determine if target is a global zone
 * Scope:	public
 * Arguments:	argc,argv:
 *		  - optional path to target to test
 * Returns:	int
 *			== 0 - success
 *			!= 0 - failure
 * Implementation:
 * A driver can be added to the system if the components of a Solaris
 * instance capable of loading drivers is present and it is not the
 * currently running system.
 */

static int
cmd_can_remove_driver(int argc, char **argv, GLOBALDATA_T *a_gdt)
{
	char	*rootPath = NULL;
	int	c;
	int	r;
static	char	*cmdName = "can_remove_driver";
static	int	recursion = 0;

	/* process any command line options */

	while ((c = getopt(argc, argv, ":")) != EOF) {
		switch (c) {
		case '\0':	/* prevent end-of-loop not reached warning */
			break;
		case '?':
		default:
			(void) usage(MSG_IS_INVALID_OPTION, optopt, cmdName);
			return (R_USAGE);
		}
	}

	/* prevent recursion */

	if (recursionCheck(&recursion, cmdName) == B_FALSE) {

		/* see if this is the current running system */

		r = cmd_is_running_system(argc, argv, a_gdt);

		/* cannot be a diskless client */

		if (r != R_SUCCESS) {
			r = cmd_is_diskless_client(argc, argv, a_gdt);
		}

		/* no need to guard against recursion any more */

		recursion--;

		switch (r) {
			case R_SUCCESS:
				/* is a running system */
				return (R_FAILURE);
			case R_FAILURE:
				/* not a running syste */
				break;
			case R_USAGE:
			case R_ERROR:
			default:
				/* cannot determine if is a running system */
				return (r);
		}
	}

	/* normalize argc/argv */

	argc -= optind;
	argv += optind;

	/* error if more than one argument */

	if (argc > 1) {
		log_msg(LOG_MSG_ERR, ERR_UNRECOGNIZED_OPTION, argv[1]);
		(void) usage(MSG_IS_INVALID_OPTION, argv[1]);
		return (R_USAGE);
	}

	/* process root path if first argument present */

	if (argc == 1) {
		if (setRootPath(argv[0], "argv[0]", B_TRUE) != R_SUCCESS) {
			return (R_ERROR);
		}
	}

	/* get current root path */

	r = getRootPath(&rootPath);
	if (r != R_SUCCESS) {
		return (r);
	}

	/* start of command debugging information */

	echoDebug(DBG_ROOTPATH_IS, rootPath);

	/* /etc must exist and must not be a symbolic link */

	r = testPath(TEST_EXISTS|TEST_NOT_SYMBOLIC_LINK,
	    "%s/%s", rootPath, "/etc");
	if (r != R_SUCCESS) {
		log_msg(LOG_MSG_DEBUG, DBG_RMDV_PATH_IS_SYMLINK,
		    rootPath, "/etc");
		return (R_FAILURE);
	}

	/* /platform must exist and must not be a symbolic link */

	r = testPath(TEST_EXISTS|TEST_NOT_SYMBOLIC_LINK,
	    "%s/%s", rootPath, "/platform");
	if (r != R_SUCCESS) {
		log_msg(LOG_MSG_DEBUG, DBG_RMDV_PATH_IS_SYMLINK,
		    rootPath, "/platform");
		return (R_FAILURE);
	}

	/* /kernel must exist and must not be a symbolic link */

	r = testPath(TEST_EXISTS|TEST_NOT_SYMBOLIC_LINK,
	    "%s/%s", rootPath, "/kernel");
	if (r != R_SUCCESS) {
		log_msg(LOG_MSG_DEBUG, DBG_RMDV_PATH_IS_SYMLINK,
		    rootPath, "/kernel");
		return (R_FAILURE);
	}

	/* can remove driver */

	log_msg(LOG_MSG_DEBUG, DBG_RMDV_YES, rootPath);

	return (R_SUCCESS);
}

/*
 * Name:	cmd_is_path_writable
 * Description:	determine if target path is writable
 * Scope:	public
 * Arguments:	argc,argv:
 *		  - optional path to target to test
 * Returns:	int
 *			== 0 - success
 *			!= 0 - failure
 * IMPLEMENTATION:
 * - path must be found in the file systems configured
 * - mount options must not include "read only"
 */

static int
cmd_is_path_writable(int argc, char **argv, GLOBALDATA_T *a_gdt)
{
	FSI_T	*list;
	char	*rootPath = NULL;
	int	c;
	int	n;
	int	nn;
	int	r;
	long	listSize;
	long	rootPathLen;
static	char	*cmdName = "is_path_writable";
static	int	recursion = 0;

	/* process any command line options */

	while ((c = getopt(argc, argv, ":")) != EOF) {
		switch (c) {
		case '\0':	/* prevent end-of-loop not reached warning */
			break;
		case '?':
		default:
			(void) usage(MSG_IS_INVALID_OPTION, optopt, cmdName);
			return (R_USAGE);
		}
	}

	/* prevent recursion */

	if (recursionCheck(&recursion, cmdName) == B_FALSE) {
		recursion--;
	}

	/* normalize argc/argv */

	argc -= optind;
	argv += optind;

	/* error if more than one argument */

	if (argc > 1) {
		log_msg(LOG_MSG_ERR, ERR_UNRECOGNIZED_OPTION, argv[1]);
		(void) usage(MSG_IS_INVALID_OPTION, argv[1]);
		return (R_USAGE);
	}

	/* process root path if first argument present */

	if (argc != 1) {
		(void) usage(ERR_REQUIRED_ROOTPATH_MISSING, cmdName);
		return (R_USAGE);
	}

	if (setRootPath(argv[0], "argv[0]", B_TRUE) != R_SUCCESS) {
		return (R_ERROR);
	}

	/* get current root path */

	r = getRootPath(&rootPath);
	if (r != R_SUCCESS) {
		return (r);
	}

	/* start of command debugging information */

	echoDebug(DBG_ROOTPATH_IS, rootPath);

	/* search file system conf for this path */

	rootPathLen = strlen(rootPath);
	list = a_gdt->gd_fileSystemConfig;
	listSize = a_gdt->gd_fileSystemConfigLen;
	for (nn = 0, n = 0; n < listSize; n++) {
		long	mplen = strlen(list[n].fsi_mntPoint);
		if (rootPathLen < mplen) {
			/* root path is longer than target, ignore */
			continue;
		}
		if (strncmp(rootPath, list[n].fsi_mntPoint, mplen) == 0) {
			/* remember last partial match */
			nn = n;
		}
	}

	log_msg(LOG_MSG_DEBUG, DBG_PWRT_INFO,
	    rootPath, list[nn].fsi_mntPoint, list[nn].fsi_fsType,
	    list[nn].fsi_mntOptions);

	/*
	 * need to determine if the mount point is writeable:
	 */

	/* see if the file system is mounted with the "read only" option */

	r = mountOptionPresent(list[nn].fsi_mntOptions, MNTOPT_RO);
	if (r == R_SUCCESS) {
		log_msg(LOG_MSG_DEBUG, DBG_PWRT_READONLY,
		    rootPath, list[nn].fsi_mntOptions);
		return (R_FAILURE);
	}

	/* target path is writable */

	log_msg(LOG_MSG_DEBUG, DBG_PWRT_IS, rootPath);

	return (R_SUCCESS);
}

/*
 * Name:	cmd_is_alternative_root
 * Description:	determine if target is an alternative root
 * Scope:	public
 * Arguments:	argc,argv:
 *		  - optional path to target to test
 * Returns:	int
 *			== 0 - success
 *			!= 0 - failure
 * Implementation:
 *  - success if an initial installation to the install root
 *	(an initial install to $PKG_INSTALL_ROOT means that $PKG_INSTALL_ROOT
 *	points to an alternative root that is under construction)
 *  - must not be installation of a zone
 *  - must not be a boot environment
 *  - must not be a diskless client
 *  - must not be a mounted miniroot
 *  - must not be a netinstall image
 *  - must not be a nonglobal zone
 *  - must not be a running system
 *  - $ROOTDIR must not be "/"
 *  - $ROOTDIR/var must exist
 */

static int
cmd_is_alternative_root(int argc, char **argv, GLOBALDATA_T *a_gdt)
{
	char	*rootPath = NULL;
	int	c;
	int	r;
static	char	*cmdName = "is_alternative_root";
static	int	recursion = 0;

	/* process any command line options */

	while ((c = getopt(argc, argv, ":")) != EOF) {
		switch (c) {
		case '\0':	/* prevent end-of-loop not reached warning */
			break;
		case '?':
		default:
			(void) usage(MSG_IS_INVALID_OPTION, optopt, cmdName);
			return (R_USAGE);
		}
	}

	/* prevent recursion */

	if (recursionCheck(&recursion, cmdName) == B_FALSE) {

		/*
		 * an alternative root cannot be any of the following
		 */

		/* cannot be a boot_environment */

		r = cmd_is_boot_environment(argc, argv, a_gdt);

		/* cannot be a diskless_client */

		if (r != R_SUCCESS) {
			r = cmd_is_diskless_client(argc, argv, a_gdt);
		}

		/* cannot be a mounted_miniroot */

		if (r != R_SUCCESS) {
			r = cmd_is_mounted_miniroot(argc, argv, a_gdt);
		}

		/* cannot be a netinstall_image */

		if (r != R_SUCCESS) {
			r = cmd_is_netinstall_image(argc, argv, a_gdt);
		}

		/* cannot be a nonglobal_zone */

		if (r != R_SUCCESS) {
			r = cmd_is_nonglobal_zone(argc, argv, a_gdt);
		}

		/* cannot be a running_system */

		if (r != R_SUCCESS) {
			r = cmd_is_running_system(argc, argv, a_gdt);
		}

		/* no need to guard against recursion any more */

		recursion--;

		/* return failure if any of the preceeding are true */

		switch (r) {
			case R_SUCCESS:
				return (R_FAILURE);
			case R_FAILURE:
				break;
			case R_USAGE:
			case R_ERROR:
			default:
				return (r);
		}
	}

	/* normalize argc/argv */

	argc -= optind;
	argv += optind;

	/* error if more than one argument */

	if (argc > 1) {
		log_msg(LOG_MSG_ERR, ERR_UNRECOGNIZED_OPTION, argv[1]);
		(void) usage(MSG_IS_INVALID_OPTION, argv[1]);
		return (R_USAGE);
	}

	/* process root path if first argument present */

	if (argc == 1) {
		if (setRootPath(argv[0], "argv[0]", B_TRUE) != R_SUCCESS) {
			return (R_ERROR);
		}
	}

	/* get current root path */

	r = getRootPath(&rootPath);
	if (r != R_SUCCESS) {
		return (r);
	}

	/* start of command debugging information */

	echoDebug(DBG_ROOTPATH_IS, rootPath);

	/* return success if initial installation */

	if ((a_gdt->gd_initialInstall == B_TRUE) &&
	    (strcmp(a_gdt->gd_installRoot, rootPath) == 0)) {
		log_msg(LOG_MSG_DEBUG, DBG_IALR_INITIAL_INSTALL, rootPath);
		return (R_SUCCESS);
	}

	/* root path must not be "/" */

	if (strcmp(rootPath, "/") == 0) {
		log_msg(LOG_MSG_DEBUG, DBG_IALR_BAD_ROOTPATH, rootPath, "/");
		return (R_FAILURE);
	}

	/* /var must exist */

	r = testPath(TEST_EXISTS,
	    "%s/%s", rootPath, "/var");
	if (r != R_SUCCESS) {
		log_msg(LOG_MSG_DEBUG, DBG_IALR_PATH_DOES_NOT_EXIST,
		    rootPath, "/var");
		return (R_FAILURE);
	}

	/* must not be installation of a zone */

	if ((a_gdt->gd_globalZoneInstall == B_TRUE) ||
	    (a_gdt->gd_nonglobalZoneInstall == B_TRUE)) {
		/* initial zone install: no path can be alternative root */
		log_msg(LOG_MSG_DEBUG, DBG_IALR_ZONE_INSTALL, rootPath);
		return (R_FAILURE);
	}

	/* target is an alternative root */

	log_msg(LOG_MSG_DEBUG, DBG_IALR_IS, rootPath);

	return (R_SUCCESS);
}

/*
 * Name:	cmd_is_boot_environment
 * Description:	determine if target is an alternative, inactive boot environment
 * Scope:	public
 * Arguments:	argc,argv:
 *		  - optional path to target to test
 * Returns:	int
 *			== 0 - success
 *			!= 0 - failure
 * IMPLEMENTATION:
 *  - must not be initial installation to the install root
 *  - must not be installation of a zone
 *  - must not be a diskless client
 *  - must not be a netinstall image
 *  - must not be a mounted miniroot
 *  - $ROOTDIR must not be "/"
 *  - $ROOTDIR/etc/lutab must exist
 *  - $ROOTDIR/etc/lu must exist and must be a directory
 */

static int
cmd_is_boot_environment(int argc, char **argv, GLOBALDATA_T *a_gdt)
{
	char	*rootPath = NULL;
	int	c;
	int	r;
static	char	*cmdName = "is_boot_environment";
static	int	recursion = 0;

	/* process any command line options */

	while ((c = getopt(argc, argv, ":")) != EOF) {
		switch (c) {
		case '\0':	/* prevent end-of-loop not reached warning */
			break;
		case '?':
		default:
			(void) usage(MSG_IS_INVALID_OPTION, optopt, cmdName);
			return (R_USAGE);
		}
	}

	/* prevent recursion */

	if (recursionCheck(&recursion, cmdName) == B_FALSE) {
		/*
		 * a boot environment cannot be any of the following
		 */

		/* cannot be a diskless client */

		r = cmd_is_diskless_client(argc, argv, a_gdt);

		/* cannot be a netinstall_image */

		if (r != R_SUCCESS) {
			r = cmd_is_netinstall_image(argc, argv, a_gdt);
		}

		/* cannot be a mounted_miniroot */

		if (r != R_SUCCESS) {
			r = cmd_is_mounted_miniroot(argc, argv, a_gdt);
		}

		/* no need to guard against recursion any more */

		recursion--;

		/* return failure if any of the preceeding are true */

		switch (r) {
			case R_SUCCESS:
				return (R_FAILURE);
			case R_FAILURE:
				break;
			case R_USAGE:
			case R_ERROR:
			default:
				return (r);
		}
	}

	/* normalize argc/argv */

	argc -= optind;
	argv += optind;

	/* error if more than one argument */

	if (argc > 1) {
		log_msg(LOG_MSG_ERR, ERR_UNRECOGNIZED_OPTION, argv[1]);
		(void) usage(MSG_IS_INVALID_OPTION, argv[1]);
		return (R_USAGE);
	}

	/* process root path if first argument present */

	if (argc == 1) {
		if (setRootPath(argv[0], "argv[0]", B_TRUE) != R_SUCCESS) {
			return (R_ERROR);
		}
	}

	/* get current root path */

	r = getRootPath(&rootPath);
	if (r != R_SUCCESS) {
		return (r);
	}

	/* start of command debugging information */

	echoDebug(DBG_ROOTPATH_IS, rootPath);

	/* root path must not be "/" */

	if (strcmp(rootPath, "/") == 0) {
		log_msg(LOG_MSG_DEBUG, DBG_BENV_BAD_ROOTPATH, rootPath, "/");
		return (R_FAILURE);
	}

	/* zone name must be global */

	if (strcmp(a_gdt->gd_zoneName, GLOBAL_ZONENAME) != 0) {
		log_msg(LOG_MSG_DEBUG, DBG_BENV_BAD_ZONE, rootPath,
		    GLOBAL_ZONENAME);
		return (R_FAILURE);
	}

	/* $ROOTDIR/etc/lutab must exist */

	r = testPath(TEST_EXISTS, "%s/%s", rootPath, "/etc/lutab");
	if (r != R_SUCCESS) {
		log_msg(LOG_MSG_DEBUG, DBG_BENV_NO_ETCLUTAB, rootPath,
		    "/etc/lutab");
		return (R_FAILURE);
	}

	/* $ROOTDIR/etc/lu must exist */

	r = testPath(TEST_EXISTS|TEST_IS_DIRECTORY,
	    "%s/%s", rootPath, "/etc/lu");
	if (r != R_SUCCESS) {
		log_msg(LOG_MSG_DEBUG, DBG_BENV_NO_ETCLU, rootPath, "/etc/lu");
		return (R_FAILURE);
	}

	/* must not be initial installation */

	if ((a_gdt->gd_initialInstall == B_TRUE) &&
	    (strcmp(a_gdt->gd_installRoot, rootPath) == 0)) {
		log_msg(LOG_MSG_DEBUG, DBG_BENV_INITIAL_INSTALL, rootPath);
		return (R_FAILURE);
	}

	/* must not be installation of a zone */

	if ((a_gdt->gd_globalZoneInstall == B_TRUE) ||
	    (a_gdt->gd_nonglobalZoneInstall == B_TRUE)) {
		/* initial zone install: no path can be boot environment */
		log_msg(LOG_MSG_DEBUG, DBG_BENV_ZONE_INSTALL, rootPath);
		return (R_FAILURE);
	}

	/* target is a boot environment */

	log_msg(LOG_MSG_DEBUG, DBG_BENV_IS, rootPath);

	return (R_SUCCESS);
}

/*
 * Name:	cmd_is_what
 * Description:	determine what the target is
 * Scope:	public
 * Arguments:	argc,argv:
 *		  - optional path to target to test
 * Returns:	int
 *			== 0 - success
 *			!= 0 - failure
 */

static int
cmd_is_what(int argc, char **argv, GLOBALDATA_T *a_gdt)
{
	char	*rootPath = NULL;
	int	c;
	int	cur_cmd;
	int	r;
static	char	*cmdName = "is_what";

	/* process any command line options */

	while ((c = getopt(argc, argv, ":")) != EOF) {
		switch (c) {
		case '\0':	/* prevent end-of-loop not reached warning */
			break;
		case '?':
		default:
			(void) usage(MSG_IS_INVALID_OPTION, optopt, cmdName);
			return (R_USAGE);
		}
	}

	/* normalize argc/argv */

	argc -= optind;
	argv += optind;

	/* error if more than one argument */

	if (argc > 1) {
		log_msg(LOG_MSG_ERR, ERR_UNRECOGNIZED_OPTION, argv[1]);
		(void) usage(MSG_IS_INVALID_OPTION, argv[1]);
		return (R_USAGE);
	}

	/* process root path if first argument present */

	if (argc == 1) {
		if (setRootPath(argv[0], "argv[0]", B_TRUE) != R_SUCCESS) {
			return (R_ERROR);
		}
	}

	/* get current root path */

	r = getRootPath(&rootPath);
	if (r != R_SUCCESS) {
		return (r);
	}

	/*
	 * construct the command line for all of the packages
	 */

	argc = 0;
	argv[argc++] = strdup(get_prog_name());
	argv[argc++] = strdup(rootPath);

	/* start of command debugging information */

	echoDebug(DBG_ROOTPATH_IS, rootPath);

	/* search for specified subcommand and execute if found */

	for (cur_cmd = 0; cmds[cur_cmd].c_name != NULL; cur_cmd++) {
		int	result;

		/* do not recursively call this function */

		if (cmds[cur_cmd].c_func == cmd_is_what) {
			continue;
		}

		/* call subcommand with its own argc/argv */

		result = cmds[cur_cmd].c_func(argc, argv, a_gdt);

		/* process result code and exit */

		result = adjustResults(result);
		log_msg(LOG_MSG_INFO, MSG_IS_WHAT_RESULT,
		    cmds[cur_cmd].c_name, result);
	}
	return (R_SUCCESS);
}

/*
 * *****************************************************************************
 * utility support functions
 * *****************************************************************************
 */

/*
 * Name:	getMountOption
 * Description:	return next mount option in a string
 * Arguments:	p - pointer to string containing mount options
 * Output:	none
 * Returns:	char * - pointer to next option in string "p"
 * Side Effects: advances input "p" and inserts \0 in place of the
 *		option separator found.
 */

static char *
getMountOption(char **p)
{
	char *cp = *p;
	char *retstr;

	/* advance past all white space */

	while (*cp && isspace(*cp))
		cp++;

	/* remember start of next option */

	retstr = cp;

	/* advance to end of string or option separator */

	while (*cp && *cp != ',')
		cp++;

	/* replace separator with '\0' if not at end of string */
	if (*cp) {
		*cp = '\0';
		cp++;
	}

	/* reset caller's pointer and return pointer to option */

	*p = cp;
	return (retstr);
}

/*
 * Name:	mountOptionPresent
 * Description:	determine if specified mount option is present in list
 *		of mount point options
 * Arguments:	a_mntOptions - pointer to string containing list of mount
 *			point options to search
 *		a_opt - pointer to string containing option to search for
 * Output:	none
 * Returns:	R_SUCCESS - option is present in list of mount point options
 *		R_FAILURE - options is not present
 *		R_ERROR - unable to determine if option is present or not
 */

static int
mountOptionPresent(char *a_mntOptions, char *a_opt)
{
	char tmpopts[MNT_LINE_MAX];
	char *f, *opts = tmpopts;

	/* return false if no mount options present */

	if ((a_opt == NULL) || (*a_opt == '\0')) {
		return (R_FAILURE);
	}

	/* return not present if no list of options to search */

	if (a_mntOptions == NULL) {
		return (R_FAILURE);
	}

	/* return not present if list of options to search is empty */

	if (*a_mntOptions == '\0') {
		return (R_FAILURE);
	}

	/* make local copy of option list to search */

	(void) strcpy(opts, a_mntOptions);

	/* scan each option looking for the specified option */

	f = getMountOption(&opts);
	for (; *f; f = getMountOption(&opts)) {
		/* return success if option matches target */
		if (strncmp(a_opt, f, strlen(a_opt)) == 0) {
			return (R_SUCCESS);
		}
	}

	/* option not found */

	return (R_FAILURE);
}

/*
 * Name:	sortedInsert
 * Description:	perform an alphabetical sorted insert into a list
 * Arguments:	r_list - pointer to list to insert next entry into
 *		a_listSize - pointer to current list size
 *		a_mntPoint - mount point to insert (is sort key)
 *		a_fsType - file system type for mount point
 *		a_mntOptions - file syste mount options for mount point
 * Output:	None
 * Returns:	None
 */

static void
sortedInsert(FSI_T **r_list, long *a_listSize, char *a_mntPoint,
    char *a_fsType, char *a_mntOptions)
{
	int	listSize;
	FSI_T	*list;
	int	n;

	/* entry assertions */

	assert(a_listSize != (long *)NULL);
	assert(a_mntPoint != NULL);
	assert(a_fsType != NULL);
	assert(a_mntOptions != NULL);

	/* entry debugging info */

	echoDebug(DBG_SINS_ENTRY, a_mntPoint, a_fsType, a_mntOptions);

	/* localize references to the list and list size */

	listSize = *a_listSize;
	list = *r_list;

	/*
	 * if list empty insert this entry as the first one in the list
	 */

	if (listSize == 0) {
		/* allocate new entry for list */
		listSize++;
		list = (FSI_T *)realloc(list, sizeof (FSI_T)*(listSize+1));

		/* first entry is data passed to this function */
		list[0].fsi_mntPoint = strdup(a_mntPoint);
		list[0].fsi_fsType = strdup(a_fsType);
		list[0].fsi_mntOptions = strdup(a_mntOptions);

		/* second entry is all NULL - end of entry marker */
		list[1].fsi_mntPoint = NULL;
		list[1].fsi_fsType = NULL;
		list[1].fsi_mntOptions = NULL;

		/* restore list and list size references to caller */
		*a_listSize = listSize;
		*r_list = list;

		return;
	}

	/*
	 * list not empty - scan looking for largest match
	 */

	for (n = 0; n < listSize; n++) {
		int	c;

		/* compare target with current list entry */

		c = strcmp(list[n].fsi_mntPoint, a_mntPoint);

		if (c == 0) {
			char	*me;
			long	len;

			/* entry already in list -- merge entries */

			len = strlen(list[n].fsi_mntOptions) +
			    strlen(a_mntOptions) + 2;
			me = (char *)calloc(1, len);

			/* merge two mount options lists into one */

			(void) strlcat(me, list[n].fsi_mntOptions, len);
			(void) strlcat(me, ",", len);
			(void) strlcat(me, a_mntOptions, len);

			/* free old list, replace with merged one */

			free(list[n].fsi_mntOptions);
			list[n].fsi_mntOptions = me;

			echoDebug(DBG_SORTEDINS_SKIPPED,
			    n, list[n].fsi_mntPoint, a_fsType,
			    list[n].fsi_fsType, a_mntOptions,
			    list[n].fsi_mntOptions);

			continue;
		} else if (c < 0) {
			/* entry before this one - skip */
			continue;
		}

		/*
		 * entry after this one - insert new entry
		 */

		/* allocate one more entry and make space for new entry */
		listSize++;
		list = (FSI_T *)realloc(list,
		    sizeof (FSI_T)*(listSize+1));
		(void) memmove(&(list[n+1]), &(list[n]),
		    sizeof (FSI_T)*(listSize-n));

		/* insert this entry into list */
		list[n].fsi_mntPoint = strdup(a_mntPoint);
		list[n].fsi_fsType = strdup(a_fsType);
		list[n].fsi_mntOptions = strdup(a_mntOptions);

		/* restore list and list size references to caller */
		*a_listSize = listSize;
		*r_list = list;

		return;
	}

	/*
	 * all entries are before this one - append to end of list
	 */

	/* allocate new entry at end of list */
	listSize++;
	list = (FSI_T *)realloc(list, sizeof (FSI_T)*(listSize+1));

	/* append this entry to the end of the list */
	list[listSize-1].fsi_mntPoint = strdup(a_mntPoint);
	list[listSize-1].fsi_fsType = strdup(a_fsType);
	list[listSize-1].fsi_mntOptions = strdup(a_mntOptions);

	/* restore list and list size references to caller */
	*a_listSize = listSize;
	*r_list = list;
}

/*
 * Name:	calculateFileSystemConfig
 * Description:	generate sorted list of all mounted file systems
 * Arguments:	a_gdt - global data structure to place sorted entries into
 * Output:	None
 * Returns:	R_SUCCESS - successfully generated mounted file systems list
 *		R_FAILURE - options is not present
 *		R_ERROR - unable to determine if option is present or not
 */

static int
calculateFileSystemConfig(GLOBALDATA_T *a_gdt)
{
	FILE		*fp;
	struct mnttab	mntbuf;
	FSI_T		*list;
	long		listSize;

	/* entry assetions */

	assert(a_gdt != (GLOBALDATA_T *)NULL);

	/* allocate a list that has one termination entry */

	list = (FSI_T *)calloc(1, sizeof (FSI_T));
	list[0].fsi_mntPoint = NULL;
	list[0].fsi_fsType = NULL;
	list[0].fsi_mntOptions = NULL;
	listSize = 0;

	/* open the mount table for reading */

	fp = fopen(MNTTAB, "r");
	if (fp == (FILE *)NULL) {
		return (R_ERROR);
	}

	/* debugging info */

	echoDebug(DBG_CALCSCFG_MOUNTED);

	/* go through all the specials looking for the device */

	while (getmntent(fp, &mntbuf) == 0) {
		if (mntbuf.mnt_mountp[0] == '/') {
			sortedInsert(&list, &listSize,
			    strdup(mntbuf.mnt_mountp),
			    strdup(mntbuf.mnt_fstype),
			    strdup(mntbuf.mnt_mntopts ?
			    mntbuf.mnt_mntopts : ""));
		}

		/*
		 * Set flag if we are in a non-global zone and it is in
		 * the mounted state.
		 */

		if (strcmp(mntbuf.mnt_mountp, "/a") == 0 &&
		    strcmp(mntbuf.mnt_special, "/a") == 0 &&
		    strcmp(mntbuf.mnt_fstype, "lofs") == 0) {
			a_gdt->inMountedState = B_TRUE;
		}

	}

	/* close mount table file */

	(void) fclose(fp);

	/* store list pointers in global data structure */

	a_gdt->gd_fileSystemConfig = list;
	a_gdt->gd_fileSystemConfigLen = listSize;

	return (R_SUCCESS);
}

/*
 * Name: 	adjustResults
 * Description:	adjust output result code before existing
 * Arguments:	a_result - result code to adjust
 * Returns:	int - adjusted result code
 */

static int
adjustResults(int a_result)
{
	boolean_t	negate = getNegateResults();
	int		realResult;

	/* adjust code as appropriate */

	switch (a_result) {
	case R_SUCCESS:		/* condition satisfied */
		realResult = ((negate == B_TRUE) ? 1 : 0);
		break;
	case R_FAILURE:		/* condition not satisfied */
		realResult = ((negate == B_TRUE) ? 0 : 1);
		break;
	case R_USAGE:		/* usage errors */
		realResult = 2;
		break;
	case R_ERROR:		/* condition could not be determined */
	default:
		realResult = 3;
		break;
	}

	/* debugging output */

	log_msg(LOG_MSG_DEBUG, DBG_ADJUST_RESULTS, a_result, negate,
	    realResult);

	/* return results */

	return (realResult);
}

/*
 * Name:        setCmdLinePath
 * Description:	set global command line path
 * Arguments:   path - path to set from the command line
 *              args - command line args
 *              num_args - number of command line args
 * Returns:     R_SUCCESS - root path successfully set
 *              R_FAILURE - root path could not be set
 *              R_ERROR - fatal error attempting to set root path
 */

static void
setCmdLinePath(char **path, char **args, int num_args)
{
	char   rp[PATH_MAX] = { '\0' };
	struct stat statbuf;

	if (*path != NULL) {
		return;
	}

	/*
	 * If a path "pkgcond is_global_zone [path]" is provided on the
	 * command line it must be the last argument.
	 */

	if (realpath(args[num_args - 1], rp) != NULL) {
		if (stat(rp, &statbuf) == 0) {
			/* make sure the target is a directory */
			if ((statbuf.st_mode & S_IFDIR)) {
				*path = strdup(rp);
			} else {
				*path = NULL;
			}
		}
	}
}

/*
 * Name:	setRootPath
 * Description:	set global root path returned by getRootPath
 * Arguments:	a_path - root path to set
 *		a_mustExist - B_TRUE if path must exist (else error)
 *			- B_FALSE if path may not exist
 * Returns:	R_SUCCESS - root path successfully set
 *		R_FAILURE - root path could not be set
 *		R_ERROR - fatal error attempting to set root path
 */

static int
setRootPath(char *a_path, char *a_envVar, boolean_t a_mustExist)
{
	char		rp[PATH_MAX] = { '\0' };
	struct stat	statbuf;

	/* if no data then issue warning and return success */

	if ((a_path == NULL) || (*a_path == '\0')) {
		echoDebug(DBG_NO_DEFAULT_ROOT_PATH_SET);
		return (R_SUCCESS);
	}

	/* path present - resolve to absolute path */

	if (realpath(a_path, rp) == NULL) {
		if (a_mustExist == B_TRUE) {
			/* must exist ... error */
			log_msg(LOG_MSG_ERR, ERR_DEFAULT_ROOT_INVALID,
			    a_path, strerror(errno));
			return (R_ERROR);
		} else {
			/* may not exist - use path as specified */
			(void) strcpy(rp, a_path);
		}
	}

	/* debugging output */

	echoDebug(DBG_DEFAULT_ROOT_PATH_SET, rp, a_envVar ? a_envVar : "");

	/* validate path existence if it must exist */

	if (a_mustExist == B_TRUE) {

		/* get node status */

		if (stat(rp, &statbuf) != 0) {
			log_msg(LOG_MSG_ERR, ERR_DEFAULT_ROOT_INVALID,
			    rp, strerror(errno));
			return (R_ERROR);
		}

		/* make sure the target is a directory */

		if (!(statbuf.st_mode & S_IFDIR)) {
			log_msg(LOG_MSG_ERR, ERR_DEFAULT_ROOT_NOT_DIR, rp);
			return (R_ERROR);
		}
	}

	/* target exists and is a directory - set */

	echoDebug(DBG_SET_ROOT_PATH_TO, rp);

	/* store copy of resolved root path */

	_rootPath = strdup(rp);

	/* success! */

	return (R_SUCCESS);
}

/*
 * Name:	testPath
 * Description:	determine if a path meets the specified conditions
 * Arguments:	a_tt - conditions to test path against
 * 		a_format - format to use to generate path
 *		arguments following a_format - as needed for a_format
 * Returns:	R_SUCCESS - the path meets all of the specified conditions
 *		R_FAILURE - the path does not meet all of the conditions
 *		R_ERROR - error attempting to test path
 */

/*PRINTFLIKE2*/
static int
testPath(TEST_TYPES a_tt, char *a_format, ...)
{
	char		*mbPath;	/* copy for the path to be returned */
	char		bfr[1];
	int		r;
	size_t		vres = 0;
	struct stat	statbuf;
	va_list		ap;
	int		fd;

	/* entry assertions */

	assert(a_format != NULL);
	assert(*a_format != '\0');

	/* determine size of the message in bytes */

	va_start(ap, a_format);
	vres = vsnprintf(bfr, 1, a_format, ap);
	va_end(ap);

	assert(vres > 0);

	/* allocate storage to hold the message */

	mbPath = (char *)calloc(1, vres+2);
	assert(mbPath != NULL);

	/* generate the results of the printf conversion */

	va_start(ap, a_format);
	vres = vsnprintf(mbPath, vres+1, a_format, ap);
	va_end(ap);

	assert(vres > 0);

	echoDebug(DBG_TEST_PATH, mbPath, (unsigned long)a_tt);

	/*
	 * When a path given to open(2) contains symbolic links, the
	 * open system call first resolves all symbolic links and then
	 * opens that final "resolved" path. As a result, it is not
	 * possible to check the result of an fstat(2) against the
	 * file descriptor returned by open(2) for S_IFLNK (a symbolic
	 * link) since all symbolic links are resolved before the
	 * target is opened.
	 *
	 * When testing the target as being (or not being) a symbolic
	 * link, first use lstat(2) against the target to determine
	 * whether or not the specified target itself is (or is not) a
	 * symbolic link.
	 */

	if (a_tt & (TEST_IS_SYMBOLIC_LINK|TEST_NOT_SYMBOLIC_LINK)) {
		/*
		 * testing target is/is not a symbolic link; use lstat
		 * to determine the status of the target itself rather
		 * than what the target might finally address.
		 */

		if (lstat(mbPath, &statbuf) != 0) {
			echoDebug(DBG_CANNOT_LSTAT_PATH, mbPath,
			    strerror(errno));
			free(mbPath);
			return (R_FAILURE);
		}

		/* Is the target required to be a symbolic link? */

		if (a_tt & TEST_IS_SYMBOLIC_LINK) {
			/* target must be a symbolic link */
			if (!(statbuf.st_mode & S_IFLNK)) {
				/* failure: target is not a symbolic link */
				echoDebug(DBG_IS_NOT_A_SYMLINK, mbPath);
				free(mbPath);
				return (R_FAILURE);
			}
			/* success: target is a symbolic link */
			echoDebug(DBG_SYMLINK_IS, mbPath);
		}

		/* Is the target required to not be a symbolic link? */

		if (a_tt & TEST_NOT_SYMBOLIC_LINK) {
			/* target must not be a symbolic link */
			if (statbuf.st_mode & S_IFLNK) {
				/* failure: target is a symbolic link */
				echoDebug(DBG_IS_A_SYMLINK, mbPath);
				free(mbPath);
				return (R_FAILURE);
			}
			/* success: target is not a symbolic link */
			echoDebug(DBG_SYMLINK_NOT, mbPath);
		}

		/*
		 * if only testing is/is not a symbolic link, then
		 * no need to open the target: return success.
		 */

		if (!(a_tt &
		    (~(TEST_IS_SYMBOLIC_LINK|TEST_NOT_SYMBOLIC_LINK)))) {
			free(mbPath);
			return (R_SUCCESS);
		}
	}

	/* resolve path and remove any whitespace */

	r = resolvePath(&mbPath);
	if (r != R_SUCCESS) {
		echoDebug(DBG_TEST_PATH_NO_RESOLVE, mbPath);
		free(mbPath);
		if (a_tt & TEST_NOT_EXISTS) {
			return (R_SUCCESS);
		}
		return (r);
	}

	echoDebug(DBG_TEST_PATH_RESOLVE, mbPath);

	/* open the file - this is the basic existence test */

	fd = open(mbPath, O_RDONLY|O_LARGEFILE, 0);

	/* existence test failed if file cannot be opened */

	if (fd < 0) {
		/*
		 * target could not be opened - if testing for non-existence,
		 * return success, otherwise return failure
		 */
		if (a_tt & TEST_NOT_EXISTS) {
			echoDebug(DBG_CANNOT_ACCESS_PATH_OK, mbPath);
			free(mbPath);
			return (R_SUCCESS);
		}

		echoDebug(DBG_CANNOT_ACCESS_PATH_BUT_SHOULD,
		    mbPath, strerror(errno));
		free(mbPath);

		return (R_FAILURE);
	}

	/*
	 * target successfully opened - if testing for non-existence,
	 * return failure, otherwise continue with specified tests
	 */

	if (a_tt & TEST_NOT_EXISTS) {
		/* testing for non-existence: return failure */
		echoDebug(DBG_TEST_EXISTS_SHOULD_NOT, mbPath);
		free(mbPath);
		(void) close(fd);
		return (R_FAILURE);
	}

	/* get the file status */

	r = fstat(fd, &statbuf);
	if (r != 0) {
		echoDebug(DBG_PATH_DOES_NOT_EXIST, mbPath, strerror(errno));
		(void) close(fd);
		free(mbPath);
		return (R_FAILURE);
	}

	/* required to be a directory? */

	if (a_tt & TEST_IS_DIRECTORY) {
		if (!(statbuf.st_mode & S_IFDIR)) {
			/* is not a directory */
			echoDebug(DBG_IS_NOT_A_DIRECTORY, mbPath);
			free(mbPath);
			return (R_FAILURE);
		}
		/* a directory */
		echoDebug(DBG_DIRECTORY_IS, mbPath);
	}

	/* required to not be a directory? */

	if (a_tt & TEST_NOT_DIRECTORY) {
		if (statbuf.st_mode & S_IFDIR) {
			/* is a directory */
			echoDebug(DBG_IS_A_DIRECTORY, mbPath);
			free(mbPath);
			return (R_FAILURE);
		}
		/* not a directory */
		echoDebug(DBG_DIRECTORY_NOT, mbPath);
	}

	/* required to be a file? */

	if (a_tt & TEST_IS_FILE) {
		if (!(statbuf.st_mode & S_IFREG)) {
			/* is not a regular file */
			echoDebug(DBG_IS_NOT_A_FILE, mbPath);
			free(mbPath);
			return (R_FAILURE);
		}
		/* a regular file */
		echoDebug(DBG_FILE_IS, mbPath);
	}

	/* required to not be a file? */

	if (a_tt & TEST_NOT_FILE) {
		if (statbuf.st_mode & S_IFREG) {
			/* is a regular file */
			echoDebug(DBG_IS_A_FILE, mbPath);
			free(mbPath);
			return (R_FAILURE);
		}
		/* not a regular file */
		echoDebug(DBG_FILE_NOT, mbPath);
	}

	/*
	 * Find token (global) in file pointed to by mbPath.
	 * token is only compared to first word in mbPath.
	 */

	if (a_tt & TEST_GLOBAL_TOKEN_IN_FILE) {
		if (!(statbuf.st_mode & S_IFREG)) {
			/* is not a regular file */
			echoDebug(DBG_IS_NOT_A_FILE, mbPath);
			free(mbPath);
			return (R_FAILURE);
		}
		/* If global exists then we're not in a non-global zone */
		if (findToken(mbPath, GLOBAL_ZONENAME) == R_SUCCESS) {
			echoDebug(DBG_TOKEN__EXISTS, GLOBAL_ZONENAME, mbPath);
			free(mbPath);
			return (R_FAILURE);
		}
	}

	(void) close(fd);

	/* success! */

	echoDebug(DBG_TESTPATH_OK, mbPath);

	/* free up temp storage used to hold path to test */

	free(mbPath);

	return (R_SUCCESS);
}

/*
 * Name:        findToken
 * Description:	Find first token in file.
 * Arguments:
 *              path - file to search for token
 *              token - string to search for
 * Returns:
 *              R_SUCCESS - the token exists
 *              R_FAILURE - the token does not exist
 *              R_ERROR - fatal error attempting to find token
 */

static int
findToken(char *path, char *token)
{
	FILE	*fp;
	char	*cp;
	char	line[MAXPATHLEN];

	if (path == NULL || token == NULL) {
		return (R_ERROR);
	}
	if ((fp = fopen(path, "r")) == NULL) {
		return (R_ERROR);
	}

	while (fgets(line, sizeof (line), fp) != NULL) {
		for (cp = line; *cp && isspace(*cp); cp++)
			;
		/* skip comments */
		if (*cp == '#') {
			continue;
		}
		if (pkgstrContainsToken(cp, token, ":")) {
			(void) fclose(fp);
			return (R_SUCCESS);
		}
	}
	(void) fclose(fp);
	return (R_FAILURE);
}


/*
 * Name:	resolvePath
 * Description:	fully resolve a path to an absolute real path
 * Arguments:	r_path - pointer to pointer to malloc()ed storage containing
 *			the path to resolve - this path may be reallocated
 *			as necessary to hold the fully resolved path
 * Output:	r_path - is realloc()ed as necessary
 * Returns:	R_SUCCESS - the path is fully resolved
 *		R_FAILURE - the path could not be resolved
 *		R_ERROR - fatal error attempting to resolve path
 */

static int
resolvePath(char **r_path)
{
	int		i;
	char		resolvedPath[MAXPATHLEN+1] = {'\0'};
	size_t		mbPathlen;	/* length of multi-byte path */
	size_t		wcPathlen;	/* length of wide-character path */
	wchar_t		*wcPath;	/* wide-character version of the path */
	wchar_t		*wptr;		/* scratch pointer */

	/* entry assertions */

	assert(r_path != (char **)NULL);

	/* return error if the path is completely empty */

	if (*r_path == '\0') {
		return (R_FAILURE);
	}

	/* remove all leading whitespace */

	removeLeadingWhitespace(r_path);

	/*
	 * convert to real path: an absolute pathname that names the same file,
	 * whose resolution does not involve ".", "..",  or  symbolic links.
	 */

	if (realpath(*r_path, resolvedPath) != NULL) {
		free(*r_path);
		*r_path = strdup(resolvedPath);
	}

	/*
	 *  convert the multi-byte version of the path to a
	 *  wide-character rendering, for doing our figuring.
	 */

	mbPathlen = strlen(*r_path);

	if ((wcPath = (wchar_t *)
	    calloc(1, sizeof (wchar_t)*(mbPathlen+1))) == NULL) {
		return (R_FAILURE);
	}

	/*LINTED*/
	if ((wcPathlen = mbstowcs(wcPath, *r_path, mbPathlen)) == -1) {
		free(wcPath);
		return (R_FAILURE);
	}

	/*
	 *  remove duplicate slashes first ("//../" -> "/")
	 */

	for (wptr = wcPath, i = 0; i < wcPathlen; i++) {
		*wptr++ = wcPath[i];

		if (wcPath[i] == '/') {
			i++;

			while (wcPath[i] == '/') {
				i++;
			}

			i--;
		}
	}

	*wptr = '\0';

	/*
	 *  now convert back to the multi-byte format.
	 */

	/*LINTED*/
	if (wcstombs(*r_path, wcPath, mbPathlen) == -1) {
		free(wcPath);
		return (R_FAILURE);
	}

	/* at this point have a path */

	/* free up temporary storage */

	free(wcPath);

	return (R_SUCCESS);
}

/*
 * Name:	removeLeadingWhitespace
 * Synopsis:	Remove leading whitespace from string
 * Description:	Remove all leading whitespace characters from a string
 * Arguments:	a_str - [RO, *RW] - (char **)
 *			Pointer to handle to string (in allocated storage) to
 *			remove all leading whitespace from
 * Returns:	void
 *			The input string is modified as follows:
 *			== NULL:
 *				- input string was NULL
 *				- input string is all whitespace
 *			!= NULL:
 *				- copy of input string with leading
 *				  whitespace removed
 * CAUTION:	The input string must be allocated space (via malloc() or
 *		strdup()) - it must not be a static or inline character string
 * NOTE:	The input string a_str will be freed with 'free'
 *		if it is all whitespace, or if it contains any leading
 *		whitespace characters
 * NOTE:    	Any string returned is placed in new storage for the
 *		calling method. The caller must use 'free' to dispose
 *		of the storage once the string is no longer needed.
 * Errors:	If the string cannot be created, the process exits
 */

static void
removeLeadingWhitespace(char **a_str)
{
	char	*o_str;

	/* entry assertions */

	assert(a_str != (char **)NULL);

	/* if string is null, just return */

	if (*a_str == NULL) {
		return;
	}
	o_str = *a_str;

	/* if string is empty, deallocate and return NULL */

	if (*o_str == '\0') {
		/* free string */
		free(*a_str);
		*a_str = NULL;
		return;
	}

	/* if first character is not a space, just return */

	if (!isspace(*o_str)) {
		return;
	}

	/* advance past all space characters */

	while ((*o_str != '\0') && (isspace(*o_str))) {
		o_str++;
	}

	/* if string was all space characters, deallocate and return NULL */

	if (*o_str == '\0') {
		/* free string */
		free(*a_str);
		*a_str = NULL;
		return;
	}

	/* have non-space/null byte, return dup, deallocate original */

	o_str = strdup(o_str);
	free(*a_str);
	*a_str = o_str;
}

/*
 * Name:	getZoneName
 * Description:	get the name of the zone this process is running in
 * Arguments:	r_zoneName - pointer to pointer to receive zone name
 * Output:	r_zoneName - a pointer to malloc()ed storage containing
 *			the zone name this process is running in is stored
 *			in the location pointed to by r_zoneName
 * Returns:	R_SUCCESS - the zone name is successfully returned
 *		R_FAILURE - the zone name is not successfully returned
 *		R_ERROR - error attempting to get the zone name
 */

static int
getZoneName(char **r_zoneName)
{
static char zoneName[ZONENAME_MAX] = { '\0' };

	/* if zone name not already present, retrieve and cache name */

	if (zoneName[0] == '\0') {
		if (getzonenamebyid(getzoneid(), zoneName,
		    sizeof (zoneName)) < 0) {
			log_msg(LOG_MSG_ERR, ERR_CANNOT_GET_ZONENAME);
			return (R_ERROR);
		}
	}

	/* return cached zone name */

	*r_zoneName = zoneName;
	return (R_SUCCESS);
}

/*
 * Name:	getRootPath
 * Description:	get the root path being tested by this process
 * Arguments:	r_rootPath - pointer to pointer to receive root path
 * Output:	r_rootPath - a pointer to malloc()ed storage containing
 *			the root path name this process is testing
 * Returns:	R_SUCCESS - the root path is successfully returned
 *		R_FAILURE - the root path is not successfully returned
 *		R_ERROR - error attempting to get the root path
 */

static int
getRootPath(char **r_rootPath)
{
	*r_rootPath = _rootPath;
	return (R_SUCCESS);
}

/*
 * Name:	setVerbose
 * Description:	Turns on verbose output
 * Scope:	public
 * Arguments:	verbose = B_TRUE indicates verbose mode
 * Returns:	none
 */

static void
setVerbose(boolean_t setting)
{
	/* set log verbose messages */

	log_set_verbose(setting);

	/* set interactive messages */

	echoSetFlag(setting);
}

/*
 * Name:	negate_results
 * Description:	control negation of results
 * Scope:	public
 * Arguments:	setting
 *		== B_TRUE indicates negated results mode
 *		== B_FALSE indicates non-negated results mode
 * Returns:	none
 */

static void
setNegateResults(boolean_t setting)
{
	log_msg(LOG_MSG_DEBUG, DBG_SET_NEGATE_RESULTS,
	    _negateResults, setting);

	_negateResults = setting;
}

/*
 * Name:	getNegateResults
 * Description:	Returns whether or not to results are negated
 * Scope:	public
 * Arguments:	none
 * Returns:	B_TRUE - results are negated
 *		B_FALSE - results are not negated
 */

static boolean_t
getNegateResults(void)
{
	return (_negateResults);
}

/*
 * Name:	usage
 * Description:	output usage string
 * Arguments:	a_format - format to use to generate message
 *		arguments following a_format - as needed for a_format
 * Output:	Outputs the usage string to stderr.
 * Returns:	R_ERROR
 */

static int
usage(char *a_format, ...)
{
	int		cur_cmd;
	char		cmdlst[LINE_MAX+1] = { '\0' };
	char		*message;
	char		bfr[1];
	char		*p = get_prog_name();
	size_t		vres = 0;
	va_list		ap;

	/* entry assertions */

	assert(a_format != NULL);
	assert(*a_format != '\0');

	/* determine size of the message in bytes */

	va_start(ap, a_format);
	/* LINTED warning: variable format specifier to vsnprintf(); */
	vres = vsnprintf(bfr, 1, a_format, ap);
	va_end(ap);

	assert(vres > 0);

	/* allocate storage to hold the message */

	message = (char *)calloc(1, vres+2);
	assert(message != NULL);

	/* generate the results of the printf conversion */

	va_start(ap, a_format);
	/* LINTED warning: variable format specifier to vsnprintf(); */
	vres = vsnprintf(message, vres+1, a_format, ap);
	va_end(ap);

	assert(vres > 0);

	/* generate list of all defined conditions */

	for (cur_cmd = 0; cmds[cur_cmd].c_name != NULL; cur_cmd++) {
		(void) strlcat(cmdlst, "\t", sizeof (cmdlst));
		(void) strlcat(cmdlst, cmds[cur_cmd].c_name, sizeof (cmdlst));
		if (cmds[cur_cmd].c_args != NULL) {
			(void) strlcat(cmdlst, cmds[cur_cmd].c_args,
			    sizeof (cmdlst));
		}
		(void) strlcat(cmdlst, "\n", sizeof (cmdlst));
	}

	/* output usage with conditions */

	log_msg(LOG_MSG_INFO, MSG_USAGE, message, p ? p : "pkgcond", cmdlst);

	return (R_ERROR);
}

/*
 * Name:	parseGlobalData
 * Description:	parse environment global data and store in global data structure
 * Arguments:	a_envVar - pointer to string representing the name of the
 *			environment variable to get and parse
 *		r_gdt - pointer to pointer to global data structure to fill in
 *			using the parsed data from a_envVar
 * Output:	none
 * Returns:	R_SUCCESS - the global data is successfully parsed
 *		R_FAILURE - problem parsing global data
 *		R_ERROR - fatal error attempting to parse global data
 */

static int
parseGlobalData(char *a_envVar, GLOBALDATA_T **r_gdt)
{
	int		r;
	char		*a;
	SML_TAG		*tag;
	SML_TAG		*ntag;

	assert(r_gdt != (GLOBALDATA_T **)NULL);

	/*
	 * allocate space for global data structure if needed
	 */

	if (*r_gdt == (GLOBALDATA_T *)NULL) {
		*r_gdt = (GLOBALDATA_T *)calloc(1, sizeof (GLOBALDATA_T));
	}

	/*
	 * get initial installation indication:
	 * If the initial install variable is set to "true", then an initial
	 * installation of Solaris is underway. When this condition is true:
	 * - if the path being checked is the package install root, then
	 *   the path is considered to be an 'alternative root' which is
	 *   currently being installed.
	 * - if the path being checked is not the package install root, then
	 *   the path needs to be further analyzed to determine what it may
	 *   be referring to.
	 */

	a = getenv(ENV_VAR_INITIAL_INSTALL);
	if ((a != NULL) && (strcasecmp(a, "true") == 0)) {
		(*r_gdt)->gd_initialInstall = B_TRUE;
	}

	/* get current zone name */

	r = getZoneName(&(*r_gdt)->gd_zoneName);
	if (r != R_SUCCESS) {
		(*r_gdt)->gd_zoneName = "";
	}

	/*
	 * get zone installation status:
	 * - If the package install zone name is not set, then an installation
	 *   of a global zone, or of a non-global zone, is not underway.
	 * - If the package install zone name is set to "global", then an
	 *   installation of a global zone is underway. In this case, no path
	 *   can be a netinstall image, diskless client, mounted miniroot,
	 *   non-global zone, the current running system, alternative root,
	 *   or alternative boot environment.
	 * - If the package install zone name is set to a value other than
	 *   "global", then an installation of a non-global zone with that name
	 *   is underway.  In this case, no path can be a netinstall image,
	 *   diskless client, mounted miniroot, global zone, the current
	 *   running system, alternative root, or alternative boot environment.
	 */

	a = getenv(ENV_VAR_PKGZONENAME);
	if ((a == NULL) || (*a == '\0')) {
		/* not installing a zone */
		(*r_gdt)->gd_globalZoneInstall = B_FALSE;
		(*r_gdt)->gd_nonglobalZoneInstall = B_FALSE;
	} else if (strcmp(a, GLOBAL_ZONENAME) == 0) {
		/* installing a global zone */
		(*r_gdt)->gd_globalZoneInstall = B_TRUE;
		(*r_gdt)->gd_nonglobalZoneInstall = B_FALSE;
		(*r_gdt)->gd_zoneName = a;
	} else {
		/* installing a non-global zone by that name */
		(*r_gdt)->gd_globalZoneInstall = B_FALSE;
		(*r_gdt)->gd_nonglobalZoneInstall = B_TRUE;
		(*r_gdt)->gd_zoneName = a;
	}

	/*
	 * get package install root.
	 */

	a = getenv(ENV_VAR_PKGROOT);
	if ((a != NULL) && (*a != '\0')) {
		(*r_gdt)->gd_installRoot = a;
	} else {
		(*r_gdt)->gd_installRoot = "/";
	}

	/* get the global data environment variable */

	a = getenv(a_envVar);

	/* if no data then issue warning and return success */

	if ((a == NULL) || (*a_envVar == '\0')) {
		log_msg(LOG_MSG_DEBUG, DBG_NO_GLOBAL_DATA_AVAILABLE, a_envVar);
		return (R_SUCCESS);
	}

	/* data present - parse into SML structure */

	log_msg(LOG_MSG_DEBUG, DBG_PARSE_GLOBAL, a);

	r = smlConvertStringToTag(&tag, a);
	if (r != R_SUCCESS) {
		log_msg(LOG_MSG_ERR, ERR_CANNOT_PARSE_GLOBAL_DATA, a);
		return (R_FAILURE);
	}

	smlDbgPrintTag(tag, DBG_PARSED_ENVIRONMENT, a_envVar);

	/* fill in global data structure */

	/* find the environment condition information structure */

	ntag = smlGetTagByName(tag, 0, TAG_COND_TOPLEVEL);
	if (ntag == SML_TAG__NULL) {
		log_msg(LOG_MSG_WRN, WRN_PARSED_DATA_MISSING,
		    TAG_COND_TOPLEVEL);
		return (R_FAILURE);
	}

	/*
	 * data found - extract what we know about
	 */

	/* parent zone name */

	a = smlGetParamByTag(ntag, 0, TAG_COND_PARENT_ZONE, TAG_COND_ZONE_NAME);
	(*r_gdt)->gd_parentZoneName = a;

	/* parent zone type */

	a = smlGetParamByTag(ntag, 0, TAG_COND_PARENT_ZONE, TAG_COND_ZONE_TYPE);
	(*r_gdt)->gd_parentZoneType = a;

	/* current zone name */

	a = smlGetParamByTag(ntag, 0, TAG_COND_CURRENT_ZONE,
	    TAG_COND_ZONE_NAME);
	(*r_gdt)->gd_currentZoneName = a;

	/* current zone type */

	a = smlGetParamByTag(ntag, 0, TAG_COND_CURRENT_ZONE,
	    TAG_COND_ZONE_TYPE);
	(*r_gdt)->gd_currentZoneType = a;

	return (R_SUCCESS);
}

/*
 * Name:	dumpGlobalData
 * Description:	dump global data structure using echoDebug
 * Arguments:	a_gdt - pointer to global data structure to dump
 * Outputs:	echoDebug is called to output global data strucutre information
 * Returns:	void
 */

static void
dumpGlobalData(GLOBALDATA_T *a_gdt)
{
	/* entry assertions */

	assert(a_gdt != (GLOBALDATA_T *)NULL);

	/* debugging enabled, dump the global data structure */

	echoDebug(DBG_DUMP_GLOBAL_ENTRY);
	echoDebug(DBG_DUMP_GLOBAL_PARENT_ZONE,
	    a_gdt->gd_parentZoneName ? a_gdt->gd_parentZoneName : "",
	    a_gdt->gd_parentZoneType ? a_gdt->gd_parentZoneType : "");
	echoDebug(DBG_DUMP_GLOBAL_CURRENT_ZONE,
	    a_gdt->gd_currentZoneName ? a_gdt->gd_currentZoneName : "",
	    a_gdt->gd_currentZoneType ? a_gdt->gd_currentZoneType : "");

}

/*
 * Name:	recursionCheck
 * Description:	prevent recursive calling of functions
 * Arguments:	r_recursion - pointer to int recursion counter
 *		a_function - pointer to name of function
 * Returns:	B_TRUE - function is recursively called
 *		B_FALSE - function not recursively called
 */

static boolean_t
recursionCheck(int *r_recursion, char *a_function)
{
	/* prevent recursion */

	(*r_recursion)++;
	if (*r_recursion > 1) {
		echoDebug(DBG_RECURSION, a_function, *r_recursion);
		(*r_recursion)--;
		return (B_TRUE);
	}

	echoDebug(DBG_NO_RECURSION, a_function);
	return (B_FALSE);
}

/*
 * Name:	quit
 * Description:	cleanup and exit
 * Arguments:	a_retcode - the code to use to determine final exit status;
 *			if this is NOT "99" and if a "ckreturnFunc" is
 *			set, then that function is called with a_retcode
 *			to set the final exit status.
 *		Valid values are:
 *		0 - success
 *		1 - package operation failed (fatal error)
 *		2 - non-fatal error (warning)
 *		3 - user selected quit (operation interrupted)
 *		4 - admin settings prevented operation
 *		5 - interaction required and -n (non-interactive) specified
 *		"10" is added to indicate "immediate reboot required"
 *		"20" is be added to indicate "reboot after install required"
 *		99 - do not interpret the code - just exit "99"
 * Returns:	<<this function does not return - calls exit()>>
 * NOTE:	This is needed because libinst functions can call "quit(99)"
 *		to force an error exit.
 */

void
quit(int a_retcode)
{
	/* process return code if not quit(99) */

	if (a_retcode == 99) {
		exit(0x7f);	/* processing error (127) */
	}

	exit(R_FAILURE);
}
