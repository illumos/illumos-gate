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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Milan Jurik. All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*
 * ldapclient command. To make (initiailize) or uninitialize a machines as
 * and LDAP client.  This command MUST be run as root (or it will simply exit).
 *
 *	-I	Install. No file_backup/recover for installing only (no doc).
 *
 *	init	Initialze (create) an LDAP client from a profile stored
 *		in a directory-server.
 *	manual	Initialze (create) an LDAP client by hand (-file option
 *		reads from file).
 *	mod	Modify the LDAP client configuration on this machine by hand.
 *	list	List the contents of the LDAP client cache files.
 *	uninit	Uninitialize this machine.
 *
 *	-v	Verbose flag.
 *	-q	Quiet flag (mutually exclusive with -v).
 *
 *	-a attrName=attrVal
 *	<attrName> can be one of the following:
 *
 *	attributeMap
 *		Attribute map.  Can be multiple instances of this option.
 *		(no former option)
 *	authenticationMethod
 *		Authentication method (formerly -a)
 *	bindTimeLimit
 *		Bind time limit. (no former option)
 *	certificatePath
 *		Path to certificates used for secure bind (no former option)
 *	credentialLevel
 *		Client credential level (no former option)
 *	defaultServerList
 *		Default server (no former option) Refer to DUA Config
 *		Schema draft.
 *	defaultSearchBase
 *		Search Base DN. e.g. dc=eng,dc=sun,dc=com (formerly -b)
 *	defaultSearchScope
 *		Search scope. (formerly -s)
 *	domainName
 *		Hosts lookup domain (DNS)  Ex. eng.sun.com (formerly -d)
 *	followReferrals
 *		Search dereference. followref or noref (default followref)
 *		(formerly -r)
 *	objectclassMap
 *		Objectclass map.  Can be multiple instances of this option.
 *		(no former option)
 *	preferredServerList
 *		Server preference list. Comma ',' seperated list of IPaddr.
 *		(formerly -p)
 *	profileName
 *		Profile name to use for init (ldapclient) or
 *		generate (gen_profile). (formerly -P)
 *	profileTTL
 *		Client info TTL.  If set to 0 this information will not be
 *		automatically updated by the ldap_cachemgr(1M).
 *		(formerly -e)
 *	proxyDN
 *		Binding DN.  Ex. cn=client,ou=people,cd=eng,dc=sun,dc=com
 *		(formerly -D)
 *	proxyPassword
 *		Client password not needed for authentication "none".
 *		(formerly -w)
 *	adminDN
 *		Administrator DN for updating naming data.
 *	adminPassword
 *		Administrator password
 *	enableShadowUpdate
 *		Allow Administrator to change shadow data in LDAP
 *	searchTimeLimit
 *		Timeout value. (formerly -o)
 *	serviceSearchDescriptor
 *		Service search scope. (no former option)
 *	serviceAuthenticationMethod
 *		Service authenticaion method (no former option)
 *	serviceCredentialLevel
 *		Service credential level (no former option)
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <time.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/systeminfo.h>
#include <fcntl.h>
#include <xti.h>
#include <strings.h>
#include <limits.h>
#include <locale.h>
#include <syslog.h>
#include <libscf.h>
#include <assert.h>

#include "standalone.h"

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SUNW_OST_OSCMD"
#endif

/* error codes */
/* The manpage doc only allows for SUCCESS(0), FAIL(1) and CRED(2) on exit */
#define	CLIENT_SUCCESS		0
#define	CLIENT_ERR_PARSE	-1
#define	CLIENT_ERR_FAIL		1
#define	CLIENT_ERR_CREDENTIAL	2
#define	CLIENT_ERR_MEMORY	3
#define	CLIENT_ERR_RESTORE	4
#define	CLIENT_ERR_RENAME	5
#define	CLIENT_ERR_RECOVER	6
#define	CLIENT_ERR_TIMEDOUT	7
#define	CLIENT_ERR_MAINTENANCE	8

/* Reset flag for start_services() */
#define	START_INIT	1
#define	START_RESET	2
#define	START_UNINIT	3

/* Reset flag for stop_services() */
#define	STATE_NOSAVE	0
#define	STATE_SAVE	1

/* files to (possibiliy) restore */
#define	LDAP_RESTORE_DIR	"/var/ldap/restore"

#define	DOMAINNAME_DIR		"/etc"
#define	DOMAINNAME_FILE		"defaultdomain"
#define	DOMAINNAME		DOMAINNAME_DIR "/" DOMAINNAME_FILE
#define	DOMAINNAME_BACK		LDAP_RESTORE_DIR "/" DOMAINNAME_FILE

#define	NSSWITCH_DIR		"/etc"
#define	NSSWITCH_FILE		"nsswitch.conf"
#define	NSSWITCH_CONF		NSSWITCH_DIR "/" NSSWITCH_FILE
#define	NSSWITCH_BACK		LDAP_RESTORE_DIR "/" NSSWITCH_FILE
#define	NSSWITCH_LDAP		"/etc/nsswitch.ldap"

#define	YP_BIND_DIR		"/var/yp/binding"

/* Define the service FMRIs */
#define	SENDMAIL_FMRI		"network/smtp:sendmail"
#define	NSCD_FMRI		"system/name-service-cache:default"
#define	AUTOFS_FMRI		"system/filesystem/autofs:default"
#define	LDAP_FMRI		"network/ldap/client:default"
#define	YP_FMRI			"network/nis/client:default"
#define	NS_MILESTONE_FMRI	"milestone/name-services:default"

/* Define flags for checking if services were enabled */
#define	SENDMAIL_ON	0x1
#define	NSCD_ON		0x10
#define	AUTOFS_ON	0x100

#define	CMD_DOMAIN_START	"/usr/bin/domainname"

/* Command to copy files */
#define	CMD_CP			"/bin/cp -f"
#define	CMD_MV			"/bin/mv -f"
#define	CMD_RM			"/bin/rm -f"

#define	TO_DEV_NULL		" >/dev/null 2>&1"

/* Files that need to be just removed */
#define	LDAP_CACHE_LOG		"/var/ldap/cachemgr.log"

/* Output defines to supress if quiet mode set */
#define	CLIENT_FPUTS if (!mode_quiet) (void) fputs
#define	CLIENT_FPRINTF if (!mode_quiet) (void) fprintf
#define	CLIENT_FPUTC if (!mode_quiet) (void) fputc

#define	restart_service(fmri, waitflag)\
		do_service(fmri, waitflag, RESTART_SERVICE,\
		SCF_STATE_STRING_ONLINE)
#define	start_service(fmri, waitflag)	\
		do_service(fmri, waitflag, START_SERVICE,\
		SCF_STATE_STRING_ONLINE)
#define	disable_service(fmri, waitflag)	\
		do_service(fmri, waitflag, STOP_SERVICE,\
		SCF_STATE_STRING_DISABLED)

/*
 * There isn't a domainName defined as a param, so we set a value here
 * (1001) should be big enough
 */
#define	LOCAL_DOMAIN_P 1001

#define	START_SERVICE	1
#define	STOP_SERVICE	2
#define	RESTART_SERVICE	3

#define	DEFAULT_TIMEOUT	60000000

#define	INIT_WAIT_USECS	50000

/* Used to turn off profile checking */
#define	CACHETTL_OFF "0"

/* Globals */
static char *cmd;

static char *dname = NULL;
static char dname_buf[BUFSIZ];

static boolean_t sysid_install = B_FALSE;

static int mode_verbose = 0;
static int mode_quiet = 0;
static int gen = 0;

static int gStartLdap = 0;
static int gStartYp = 0;

static int enableFlag = 0;

/* multival_t is used to hold params that can have more than one value */
typedef struct {
	int count;
	char **optlist;
} multival_t;

static multival_t *multival_new();
static int multival_add(multival_t *list, char *opt);
static void multival_free(multival_t *list);

/*
 * clientopts_t is used to hold and pass around the param values from
 * the cmd line
 */
typedef struct {
	multival_t	*attributeMap;
	char		*authenticationMethod;
	char		*bindTimeLimit;
	char		*certificatePath;
	char		*credentialLevel;
	char		*defaultSearchBase;
	char		*defaultServerList;
	char		*domainName;
	char		*followReferrals;
	multival_t	*objectclassMap;
	char		*preferredServerList;
	char		*profileName;
	char		*profileTTL;
	char		*proxyDN;
	char		*proxyPassword;
	char		*enableShadowUpdate;
	char		*adminDN;
	char		*adminPassword;
	char		*bindDN;
	char		*bindPasswd;
	char		*defaultSearchScope;
	char		*searchTimeLimit;
	multival_t	*serviceAuthenticationMethod;
	multival_t	*serviceCredentialLevel;
	multival_t	*serviceSearchDescriptor;
} clientopts_t;

static clientopts_t *clientopts_new();
static void clientopts_free(clientopts_t *list);

extern ns_ldap_error_t *__ns_ldap_print_config(int);
extern void __ns_ldap_default_config();
extern int __ns_ldap_download(const char *, char *, char *, ns_ldap_error_t **);

/* Function prototypes (these could be static) */
static void usage(void);

static int credCheck(clientopts_t *arglist);
static int adminCredCheck(clientopts_t *arglist);
static int clientSetParam(clientopts_t *optlist, int paramFlag, char *attrVal);
static int parseParam(char *param, char **paramVal);
static void dumpargs(clientopts_t *arglist);
static int num_args(clientopts_t *arglist);

static int file_backup(void);
static int recover(int saveState);
static int mod_backup(void);
static int mod_recover(void);
static void mod_cleanup(void);

static int client_list(clientopts_t *arglist);
static int client_manual(clientopts_t *arglist);
static int client_mod(clientopts_t *arglist);
static int client_uninit(clientopts_t *arglist);
static int client_genProfile(clientopts_t *arglist);
static int client_init(clientopts_t *arglist);
static int file_move(const char *from, const char *to);

static int start_services(int flag);
static int stop_services(int saveState);
static boolean_t is_service(const char *fmri, const char *state);
static int wait_till(const char *fmri, const char *state, useconds_t max,
		const char *what, boolean_t check_maint);
static int do_service(const char *fmri, boolean_t waitflag, int dowhat,
		const char *state);
static useconds_t get_timeout_value(int dowhat, const char *fmri,
		useconds_t default_val);

int
main(int argc, char **argv)
{
	char		*ret_locale, *ret_textdomain;
	int		retcode;
	int		paramFlag;
	char		*attrVal;
	int		sysinfostatus;
	clientopts_t	*optlist = NULL;
	int		op_manual = 0, op_mod = 0, op_uninit = 0;
	int		op_list = 0, op_init = 0, op_genprofile = 0;
	extern char	*optarg;
	extern int	optind;
	int		option;

	ret_locale = setlocale(LC_ALL, "");
	if (ret_locale == NULL) {
		CLIENT_FPUTS(gettext("Unable to set locale.\n"), stderr);
	}
	ret_textdomain = textdomain(TEXT_DOMAIN);
	if (ret_textdomain == NULL) {
		CLIENT_FPUTS(gettext("Unable to set textdomain.\n"), stderr);
	}

	openlog("ldapclient", LOG_PID, LOG_USER);

	/* get name that invoked us */
	if (cmd = strrchr(argv[0], '/'))
		++cmd;
	else
		cmd = argv[0];

	sysinfostatus = sysinfo(SI_SRPC_DOMAIN, dname_buf, BUFSIZ);
	if (0 < sysinfostatus)
		dname = &dname_buf[0];

	optlist = clientopts_new();
	if (optlist == NULL) {
		CLIENT_FPUTS(
		    gettext("Error getting optlist (malloc fail)\n"),
		    stderr);
		exit(CLIENT_ERR_FAIL);
	}

	optind = 1;
	while (optind < argc) {
		option = getopt(argc, argv, "vqa:ID:w:j:y:z:");

		switch (option) {
		case 'v':
			mode_verbose = 1;
			break;
		case 'q':
			mode_quiet = 1;
			break;
		case 'a':
			attrVal = NULL;
			paramFlag = parseParam(optarg, &attrVal);
			if (paramFlag == CLIENT_ERR_PARSE) {
				CLIENT_FPRINTF(stderr,
				    gettext("Unrecognized "
				    "parameter \"%s\"\n"),
				    optarg);
				usage();
				exit(CLIENT_ERR_FAIL);
			}
			if (paramFlag == NS_LDAP_BINDPASSWD_P &&
			    optlist->proxyPassword != NULL) {
				(void) fprintf(stderr,
				    gettext("The -a proxyPassword option is "
				    "mutually exclusive of -y. "
				    "-a proxyPassword is ignored.\n"));
				break;
			}
			if (paramFlag == NS_LDAP_ADMIN_BINDPASSWD_P &&
			    optlist->adminPassword != NULL) {
				(void) fprintf(stderr,
				    gettext("The -a adminPassword option is "
				    "mutually exclusive of -z. "
				    "-a adminPassword is ignored.\n"));
				break;
			}
			retcode = clientSetParam(optlist, paramFlag, attrVal);
			if (retcode != CLIENT_SUCCESS) {
				CLIENT_FPRINTF(
				    stderr,
				    gettext("Error (%d) setting "
				    "param \"%s\"\n"),
				    retcode, optarg);
				usage();
				exit(CLIENT_ERR_FAIL);
			}
			break;
		case 'D':
			optlist->bindDN = strdup(optarg);
			break;
		case 'w':
			if (optlist->bindPasswd != NULL) {
				CLIENT_FPRINTF(stderr,
				    gettext("The -w option is mutually "
				    "exclusive of -j. -w is ignored."));
				break;
			}

			if (optarg[0] == '-' && optarg[1] == '\0') {
				/* Ask for a password later */
				break;
			}

			optlist->bindPasswd = strdup(optarg);
			break;
		case 'j':
			if (optlist->bindPasswd != NULL) {
				(void) fprintf(stderr,
				    gettext("The -w option is mutually "
				    "exclusive of -j. -w is ignored.\n"));
				free(optlist->bindPasswd);
			}
			optlist->bindPasswd = readPwd(optarg);
			if (optlist->bindPasswd == NULL) {
				exit(CLIENT_ERR_FAIL);
			}
			break;
		case 'y':
			if (optlist->proxyPassword != NULL) {
				(void) fprintf(stderr,
				    gettext("The -a proxyPassword option is "
				    "mutually exclusive of -y. "
				    "-a proxyPassword is ignored.\n"));
			}
			optlist->proxyPassword = readPwd(optarg);
			if (optlist->proxyPassword == NULL) {
				exit(CLIENT_ERR_FAIL);
			}
			break;
		case 'z':
			if (optlist->adminPassword != NULL) {
				(void) fprintf(stderr,
				    gettext("The -a adminPassword option is "
				    "mutually exclusive of -z. "
				    "-a adminPassword is ignored.\n"));
			}
			optlist->adminPassword = readPwd(optarg);
			if (optlist->adminPassword == NULL) {
				exit(CLIENT_ERR_FAIL);
			}
			break;
		case EOF:
			if (strcmp(argv[optind], "init") == 0) {
				op_init = 1;
			} else if (strcmp(argv[optind], "manual") == 0) {
				op_manual = 1;
			} else if (strcmp(argv[optind], "mod") == 0) {
				op_mod = 1;
			} else if (strcmp(argv[optind], "list") == 0) {
				op_list = 1;
			} else if (strcmp(argv[optind], "uninit") == 0) {
				op_uninit = 1;
			} else if (strcmp(argv[optind], "genprofile") == 0) {
				gen = 1;
				op_genprofile = 1;
			} else if (optind == argc-1) {
				retcode = clientSetParam(
				    optlist,
				    NS_LDAP_SERVERS_P,
				    argv[optind]);	/* ipAddr */
				if (retcode != CLIENT_SUCCESS) {
					CLIENT_FPRINTF(
					    stderr,
					    gettext("Error (%d) setting "
					    "serverList param.\n"),
					    retcode);
					usage();
					exit(CLIENT_ERR_FAIL);
				}
			} else {
				CLIENT_FPUTS(
				    gettext("Error parsing "
				    "command line\n"),
				    stderr);
				usage();
				exit(CLIENT_ERR_FAIL);
			}
			optind++;	/* get past the verb and keep trying */
			break;
		/* Backwards compatibility to support system install */
		case 'I':
			sysid_install = B_TRUE;
			op_init = 1;
			mode_quiet = 1;
			break;
		case '?':
			usage();
			CLIENT_FPUTS(gettext("\nOr\n\n"), stderr);
			gen = 1;
			usage();
			exit(CLIENT_ERR_FAIL);
			break;
		}

	}

	if ((getuid() != 0) && (!op_genprofile)) {
		(void) puts(
		    "You must be root (SuperUser) to run this command.");
		usage();
		exit(CLIENT_ERR_FAIL);
	}

/*
 *	All command line arguments are finished being parsed now
 */

/* *** Do semantic checking here *** */

/* if gen and no no searchBase then err */
	if (gen && !optlist->defaultSearchBase) {
		CLIENT_FPUTS(
		    gettext("ldapclient: Missing required attrName "
		    "defaultSearchBase\n"),
		    stderr);
		usage();
		clientopts_free(optlist);
		exit(CLIENT_ERR_FAIL);
	}

/*
 * if init or manual, and if adminDN is specified then enableShadowUpdate
 * must be set to TRUE.
 */
	if ((op_init || op_manual) &&
	    (!optlist->enableShadowUpdate ||
	    strcasecmp(optlist->enableShadowUpdate, "TRUE") != 0) &&
	    (optlist->adminDN || optlist->adminPassword)) {
		CLIENT_FPUTS(
		    gettext("ldapclient: adminDN and adminPassword must not "
		    "be specified if enableShadowUpdate is not set to TRUE \n"),
		    stderr);
		usage();
		clientopts_free(optlist);
		exit(CLIENT_ERR_FAIL);
	}

/* Only one verb can be specified */
	if ((op_init + op_manual + op_mod + op_uninit +
	    op_list + op_genprofile) != 1) {
		usage();
		clientopts_free(optlist);
		exit(CLIENT_ERR_FAIL);
	}

/* *** We passed semantic checking, so now do the operation *** */

	if (mode_verbose) {
		CLIENT_FPUTS(gettext("Arguments parsed:\n"), stderr);
		dumpargs(optlist);
	}


/* handle "ldapclient list" here.  err checking done in func */
	if (op_list) {
		if (mode_verbose)
			CLIENT_FPUTS(
			    gettext("Handling list option\n"),
			    stderr);
		retcode = client_list(optlist);
	}

/* handle "ldapclient uninit" here */
	if (op_uninit) {
		if (mode_verbose)
			CLIENT_FPUTS(
			    gettext("Handling uninit option\n"),
			    stderr);
		retcode = client_uninit(optlist);
	}

/* handle "ldapclient init" (profile) */
	if (op_init) {
		if (mode_verbose)
			CLIENT_FPUTS(
			    gettext("Handling init option\n"),
			    stderr);
		retcode = client_init(optlist);
	}

/* handle "genprofile" here */
	if (op_genprofile) {
		if (mode_verbose)
			CLIENT_FPUTS(
			    gettext("Handling genProfile\n"),
			    stderr);
		retcode = client_genProfile(optlist);
	}

/* handle "ldapclient manual" here */
	if (op_manual) {
		if (mode_verbose)
			CLIENT_FPUTS(
			    gettext("Handling manual option\n"),
			    stderr);
		retcode = client_manual(optlist);
	}

/* handle "ldapclient mod" here */
	if (op_mod) {
		if (mode_verbose)
			CLIENT_FPUTS(
			    gettext("Handling mod option\n"),
			    stderr);
		retcode = client_mod(optlist);
	}

	clientopts_free(optlist);
	if ((retcode == CLIENT_SUCCESS) ||
	    (retcode == CLIENT_ERR_FAIL) ||
	    (retcode == CLIENT_ERR_CREDENTIAL))
		return (retcode);
	else
		return (CLIENT_ERR_FAIL);
}

static int
client_list(clientopts_t *arglist)
{
	ns_ldap_error_t *errorp;
	int retcode = CLIENT_SUCCESS;

	if (num_args(arglist) > 0) {
		CLIENT_FPUTS(
		    gettext("No args supported with \"list\" option\n"),
		    stderr);
		usage();
		return (CLIENT_ERR_FAIL);	/* exit code here ? */
	}
	if ((errorp = __ns_ldap_print_config(mode_verbose)) != NULL) {
		retcode = CLIENT_ERR_FAIL;
		CLIENT_FPUTS(
		    gettext("Cannot get print configuration\n"),
		    stderr);
		CLIENT_FPUTS(errorp->message, stderr);
		(void) __ns_ldap_freeError(&errorp);
		CLIENT_FPUTC('\n', stderr);
	}

	return (retcode);
}

static int
client_uninit(clientopts_t *arglist)
{
	int retcode = CLIENT_SUCCESS;
	ns_ldap_self_gssapi_config_t config = NS_LDAP_SELF_GSSAPI_CONFIG_NONE;

	if (mode_verbose) {
		CLIENT_FPUTS(
		    gettext("Restoring machine to previous "
		    "configuration state\n"),
		    stderr);
	}

	if (num_args(arglist) > 0) {
		CLIENT_FPUTS(
		    gettext("No args supported with \"uninit\" option\n"),
		    stderr);
		usage();
		return (CLIENT_ERR_FAIL);
	}

	(void) __ns_ldap_self_gssapi_config(&config);

	retcode = stop_services(STATE_SAVE);

	if (config != NS_LDAP_SELF_GSSAPI_CONFIG_NONE)
		(void) system("/usr/sbin/cryptoadm enable metaslot");

	if (retcode != CLIENT_SUCCESS) {
		CLIENT_FPUTS(
		    gettext("Errors stopping network services.\n"), stderr);
		/* restart whatever services we can */
		(void) start_services(START_RESET);
		return (CLIENT_ERR_FAIL);
	}

	retcode = recover(STATE_SAVE);
	if (retcode != CLIENT_SUCCESS) {
		CLIENT_FPUTS(
		    gettext("Cannot recover the configuration on "
		    "this machine.\n"),
		    stderr);
		(void) start_services(START_RESET);
	} else {
		retcode = start_services(START_UNINIT);
		if (retcode != CLIENT_SUCCESS) {
			CLIENT_FPUTS(
			    gettext("Config restored but problems "
			    "encountered resetting network "
			    "services.\n"),
			    stderr);
		}
	}

	if (retcode == CLIENT_SUCCESS) {
		CLIENT_FPUTS(
		    gettext("System successfully recovered\n"),
		    stderr);
	}

	return (retcode);
}

/*
 * The following macro is used to do a __ns_ldap_setParam().
 * On every call, the return code is checked, and if there was
 * a problem then the error message is printed, the ldaperr
 * is freed and we return from the function with the offending
 * error return code.  This macro keeps us from having to
 * repeat this code for every call to setParam as was done
 * in the previous incarnation of ldapclient.
 *
 * assumes a "retcode" variable is available for status
 */
#define	LDAP_SET_PARAM(argval, argdef)	\
retcode = 0;	\
if (NULL != argval) {	\
	ns_ldap_error_t *ldaperr;	\
	retcode = __ns_ldap_setParam(argdef, (void *)argval, &ldaperr);	\
	if (retcode != NS_LDAP_SUCCESS) {	\
		if (NULL != ldaperr) {	\
			CLIENT_FPUTS(ldaperr->message, stderr);	\
			CLIENT_FPUTC('\n', stderr);	\
			(void) __ns_ldap_freeError(&ldaperr);	\
		}	\
		return (retcode ? CLIENT_ERR_FAIL : CLIENT_SUCCESS);	\
	}	\
}

/*
 * The following macro is used to check if an arg has already been set
 * and issues an error message, a usage message and then returns an error.
 * This was made into a macro to avoid the duplication of this code many
 * times in the function below.
 */
#define	LDAP_CHECK_INVALID(arg, param)	\
if (arg) {	\
	CLIENT_FPRINTF(stderr, gettext("Invalid parameter (%s) " \
	    "specified\n"), param);	\
	usage();	\
	return (CLIENT_ERR_FAIL);	\
}

static int
client_manual(clientopts_t *arglist)
{
	int counter;
	int domain_fp;
	ns_ldap_error_t *errorp;
	int ret_copy;
	int reset_ret;
	int retcode = CLIENT_SUCCESS;

	if (dname == NULL) {
		CLIENT_FPUTS(
		    gettext("Manual failed: System domain not set and "
		    "no domainName specified.\n"),
		    stderr);
		return (CLIENT_ERR_FAIL);
	}

	if (arglist->defaultSearchBase == NULL) {
		CLIENT_FPUTS(
		    gettext("Manual failed: Missing required "
		    "defaultSearchBase attribute.\n"),
		    stderr);
		return (CLIENT_ERR_FAIL);
	}

	if ((arglist->defaultServerList == NULL) &&
	    (arglist->preferredServerList == NULL)) {
		CLIENT_FPUTS(
		    gettext("Manual failed: Missing required "
		    "defaultServerList or preferredServerList "
		    "attribute.\n"),
		    stderr);
		return (CLIENT_ERR_FAIL);
	}

	if (arglist->profileTTL != NULL) {
		CLIENT_FPUTS(
		    gettext("Manual aborted: profileTTL is not supported "
		    "in manual mode.\n"),
		    stderr);
		return (CLIENT_ERR_FAIL);
	}

	if (arglist->profileName != NULL) {
		CLIENT_FPUTS(
		    gettext("Manual aborted: profileName is not supported "
		    "in manual mode.\n"),
		    stderr);
		return (CLIENT_ERR_FAIL);
	}

	LDAP_CHECK_INVALID(arglist->bindDN, "bind DN");
	LDAP_CHECK_INVALID(arglist->bindPasswd, "bind password");

	__ns_ldap_setServer(TRUE);	/* Need this for _ns_setParam() */
	__ns_ldap_default_config();

	/* Set version to latest (not version 1) */
	LDAP_SET_PARAM(NS_LDAP_VERSION, NS_LDAP_FILE_VERSION_P);

	/* Set profileTTL to 0 since NO profile on manual */
	LDAP_SET_PARAM(CACHETTL_OFF, NS_LDAP_CACHETTL_P);

	/* Set additional valid params from command line */
	LDAP_SET_PARAM(arglist->authenticationMethod, NS_LDAP_AUTH_P);
	LDAP_SET_PARAM(arglist->defaultSearchBase, NS_LDAP_SEARCH_BASEDN_P);
	LDAP_SET_PARAM(arglist->credentialLevel, NS_LDAP_CREDENTIAL_LEVEL_P);
	LDAP_SET_PARAM(arglist->proxyDN, NS_LDAP_BINDDN_P);
	LDAP_SET_PARAM(arglist->enableShadowUpdate,
	    NS_LDAP_ENABLE_SHADOW_UPDATE_P);
	LDAP_SET_PARAM(arglist->adminDN, NS_LDAP_ADMIN_BINDDN_P);
	LDAP_SET_PARAM(arglist->searchTimeLimit, NS_LDAP_SEARCH_TIME_P);
	LDAP_SET_PARAM(arglist->preferredServerList, NS_LDAP_SERVER_PREF_P);
	LDAP_SET_PARAM(arglist->profileName, NS_LDAP_PROFILE_P);
	LDAP_SET_PARAM(arglist->followReferrals, NS_LDAP_SEARCH_REF_P);
	LDAP_SET_PARAM(arglist->defaultSearchScope, NS_LDAP_SEARCH_SCOPE_P);
	LDAP_SET_PARAM(arglist->bindTimeLimit, NS_LDAP_BIND_TIME_P);
	LDAP_SET_PARAM(arglist->proxyPassword, NS_LDAP_BINDPASSWD_P);
	LDAP_SET_PARAM(arglist->adminPassword, NS_LDAP_ADMIN_BINDPASSWD_P);
	LDAP_SET_PARAM(arglist->defaultServerList, NS_LDAP_SERVERS_P);
	LDAP_SET_PARAM(arglist->certificatePath, NS_LDAP_HOST_CERTPATH_P);

	for (counter = 0;
	    counter < arglist->serviceAuthenticationMethod->count;
	    counter++) {

		LDAP_SET_PARAM(
		    arglist->serviceAuthenticationMethod->optlist[counter],
		    NS_LDAP_SERVICE_AUTH_METHOD_P);
	}
	for (counter = 0;
	    counter < arglist->serviceCredentialLevel->count;
	    counter++) {

		LDAP_SET_PARAM(
		    arglist->serviceCredentialLevel->optlist[counter],
		    NS_LDAP_SERVICE_CRED_LEVEL_P);
	}
	for (counter = 0;
	    counter < arglist->objectclassMap->count;
	    counter++) {

		LDAP_SET_PARAM(arglist->objectclassMap->optlist[counter],
		    NS_LDAP_OBJECTCLASSMAP_P);
	}
	for (counter = 0; counter < arglist->attributeMap->count; counter++) {
		LDAP_SET_PARAM(arglist->attributeMap->optlist[counter],
		    NS_LDAP_ATTRIBUTEMAP_P);
	}
	for (counter = 0;
	    counter < arglist->serviceSearchDescriptor->count;
	    counter++) {

		LDAP_SET_PARAM(
		    arglist->serviceSearchDescriptor->optlist[counter],
		    NS_LDAP_SERVICE_SEARCH_DESC_P);
	}

	retcode = credCheck(arglist);
	if (retcode == CLIENT_SUCCESS)
		retcode = adminCredCheck(arglist);
	if (retcode != CLIENT_SUCCESS) {
		CLIENT_FPUTS(
		    gettext("Error in setting up credentials\n"),
		    stderr);
		return (retcode);
	}

	if (mode_verbose)
		CLIENT_FPUTS(
		    gettext("About to modify this machines "
		    "configuration by writing the files\n"),
		    stderr);

	/* get ready to start playing with files */
	retcode = stop_services(STATE_SAVE);
	if (retcode != CLIENT_SUCCESS) {
		CLIENT_FPUTS(
		    gettext("Errors stopping network services.\n"), stderr);
		return (CLIENT_ERR_FAIL);
	}

	/* Save orig versions of files */
	retcode = file_backup();
	if (retcode == CLIENT_ERR_RESTORE) {
		CLIENT_FPUTS(
		    gettext("System not in state to enable ldap client.\n"),
		    stderr);

		reset_ret = start_services(START_RESET);
		if (reset_ret != CLIENT_SUCCESS) {
			CLIENT_FPRINTF(stderr, gettext("Error (%d) while "
			    "starting services during reset\n"),
			    reset_ret);
		}
		return (retcode);
	} else if (retcode != CLIENT_SUCCESS) {
		CLIENT_FPUTS(
		    gettext("Save of system configuration failed!  "
		    "Attempting recovery.\n"),
		    stderr);
		retcode = recover(STATE_NOSAVE);
		if (retcode != CLIENT_SUCCESS) {
			CLIENT_FPUTS(
			    gettext("Recovery of systems configuration "
			    "failed.  Manual intervention of "
			    "config files is required.\n"),
			    stderr);
			return (retcode);
		}

		reset_ret = start_services(START_RESET);
		if (reset_ret != CLIENT_SUCCESS) {
			CLIENT_FPRINTF(stderr, gettext("Error (%d) while "
			    "starting services during reset\n"),
			    reset_ret);
		}

		return (retcode);
	}

	/* Dump new files */
	errorp = __ns_ldap_DumpConfiguration(NSCONFIGFILE);
	if (errorp != NULL) {
		CLIENT_FPRINTF(stderr,
		    gettext("%s manual: errorp is not NULL; %s\n"),
		    cmd, errorp->message);
		retcode = recover(STATE_NOSAVE);
		if (retcode != CLIENT_SUCCESS) {
			CLIENT_FPUTS(
			    gettext("Recovery of systems configuration "
			    "failed.  Manual intervention of "
			    "config files is required.\n"),
			    stderr);
			return (retcode);
		}
		reset_ret = start_services(START_RESET);
		if (reset_ret != CLIENT_SUCCESS) {
			CLIENT_FPRINTF(stderr, gettext("Error (%d) while "
			    "starting services during reset\n"),
			    reset_ret);
		}
		(void) __ns_ldap_freeError(&errorp);
		return (CLIENT_ERR_FAIL);
	}

	/* if (credargs(arglist)) */
	errorp = __ns_ldap_DumpConfiguration(NSCREDFILE);
	if (errorp != NULL) {
		CLIENT_FPRINTF(stderr,
		    gettext("%s init: errorp is not NULL; %s\n"),
		    cmd, errorp->message);
		retcode = recover(STATE_NOSAVE);
		if (retcode != CLIENT_SUCCESS) {
			CLIENT_FPUTS(
			    gettext("Recovery of systems configuration "
			    "failed.  Manual intervention of "
			    "config files is required.\n"),
			    stderr);
			return (retcode);
		}
		reset_ret = start_services(START_RESET);
		if (reset_ret != CLIENT_SUCCESS) {
			CLIENT_FPRINTF(stderr, gettext("Error (%d) while "
			    "starting services during reset\n"),
			    reset_ret);
		}
		(void) __ns_ldap_freeError(&errorp);
		return (CLIENT_ERR_FAIL);
	}

	ret_copy = system(CMD_CP " " NSSWITCH_LDAP " " NSSWITCH_CONF);
	if (ret_copy != 0) {
		CLIENT_FPRINTF(stderr,
		    gettext("Error %d copying (%s) -> (%s)\n"),
		    ret_copy, NSSWITCH_LDAP, NSSWITCH_CONF);
		retcode = recover(STATE_NOSAVE);
		if (retcode != CLIENT_SUCCESS) {
			CLIENT_FPUTS(
			    gettext("Recovery of systems configuration "
			    "failed.  Manual intervention of "
			    "config files is required.\n"),
			    stderr);
		}
		reset_ret = start_services(START_RESET);
		if (reset_ret != CLIENT_SUCCESS) {
			CLIENT_FPRINTF(stderr, gettext("Error (%d) while "
			    "starting services during reset\n"),
			    reset_ret);
		}
		return (CLIENT_ERR_FAIL);
	}

	if ((domain_fp = open(DOMAINNAME, O_WRONLY|O_CREAT|O_TRUNC,
	    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1) { /* 0644 */
		CLIENT_FPRINTF(stderr, gettext("Cannot open %s\n"), DOMAINNAME);
		retcode = recover(STATE_NOSAVE);
		if (retcode != CLIENT_SUCCESS) {
			CLIENT_FPUTS(
			    gettext("Recovery of systems configuration "
			    "failed.  Manual intervention of "
			    "config files is required.\n"),
			    stderr);
			return (CLIENT_ERR_FAIL);
		}
		reset_ret = start_services(START_RESET);
		if (reset_ret != CLIENT_SUCCESS) {
			CLIENT_FPRINTF(stderr, gettext("Error (%d) while "
			    "starting services during reset\n"),
			    reset_ret);
		}
		return (CLIENT_ERR_FAIL);
	}
	(void) write(domain_fp, dname, strlen(dname));
	(void) write(domain_fp, "\n", 1);
	(void) close(domain_fp);

	retcode = start_services(START_INIT);

	if (retcode == CLIENT_SUCCESS) {
		CLIENT_FPUTS(gettext("System successfully configured\n"),
		    stderr);
	} else {
		CLIENT_FPUTS(gettext("Error resetting system.\n"
		    "Recovering old system settings.\n"), stderr),

		    /* stop any started services for recover */
		    /* don't stomp on history of saved services state */
		    reset_ret = stop_services(STATE_NOSAVE);
		if (reset_ret != CLIENT_SUCCESS) {
			CLIENT_FPRINTF(stderr, gettext("Error (%d) while "
			    "stopping services during reset\n"),
			    reset_ret);
			/* Coninue and try to recover what we can */
		}
		reset_ret = recover(STATE_NOSAVE);
		if (reset_ret != CLIENT_SUCCESS) {
			CLIENT_FPRINTF(stderr, gettext("Error (%d) while "
			    "recovering service files during "
			    "reset\n"), reset_ret);
			/* Continue and start what we can */
		}
		reset_ret = start_services(START_RESET);
		if (reset_ret != CLIENT_SUCCESS) {
			CLIENT_FPRINTF(stderr, gettext("Error (%d) while "
			    "starting services during reset\n"),
			    reset_ret);
		}
	}

	return (retcode);
}

static int
client_mod(clientopts_t *arglist)
{
	int counter;
	int domain_fp;
	ns_ldap_error_t *errorp;
	int reset_ret;
	int retcode = CLIENT_SUCCESS;

	__ns_ldap_setServer(TRUE);	/* Need this for _ns_setParam() */
	if ((errorp = __ns_ldap_LoadConfiguration()) != NULL) {
		CLIENT_FPUTS(gettext("Cannot get load configuration\n"),
		    stderr);
		CLIENT_FPUTS(errorp->message, stderr);
		CLIENT_FPUTC('\n', stderr);
		(void) __ns_ldap_freeError(&errorp);
		return (CLIENT_ERR_FAIL);
	}

	if (arglist->profileTTL != NULL) {
		CLIENT_FPUTS(
		    gettext("Mod aborted: profileTTL modification is "
		    "not allowed in mod mode.\n"),
		    stderr);
		return (CLIENT_ERR_FAIL);
	}

	if (arglist->profileName != NULL) {
		CLIENT_FPUTS(
		    gettext("Mod aborted: profileName modification is "
		    "not allowed.  If you want to use profiles "
		    "generate one with genProfile and load it "
		    "on the server with ldapadd.\n"),
		    stderr);
		return (CLIENT_ERR_FAIL);
	}

	LDAP_CHECK_INVALID(arglist->bindDN, "bind DN");
	LDAP_CHECK_INVALID(arglist->bindPasswd, "bind password");

	/* Set additional valid params from command line */
	LDAP_SET_PARAM(arglist->authenticationMethod, NS_LDAP_AUTH_P);
	LDAP_SET_PARAM(arglist->defaultSearchBase, NS_LDAP_SEARCH_BASEDN_P);
	LDAP_SET_PARAM(arglist->credentialLevel, NS_LDAP_CREDENTIAL_LEVEL_P);
	LDAP_SET_PARAM(arglist->proxyDN, NS_LDAP_BINDDN_P);
	LDAP_SET_PARAM(arglist->adminDN, NS_LDAP_ADMIN_BINDDN_P);
	LDAP_SET_PARAM(arglist->profileTTL, NS_LDAP_CACHETTL_P);
	LDAP_SET_PARAM(arglist->searchTimeLimit, NS_LDAP_SEARCH_TIME_P);
	LDAP_SET_PARAM(arglist->preferredServerList, NS_LDAP_SERVER_PREF_P);
	LDAP_SET_PARAM(arglist->profileName, NS_LDAP_PROFILE_P);
	LDAP_SET_PARAM(arglist->followReferrals, NS_LDAP_SEARCH_REF_P);
	LDAP_SET_PARAM(arglist->defaultSearchScope, NS_LDAP_SEARCH_SCOPE_P);
	LDAP_SET_PARAM(arglist->bindTimeLimit, NS_LDAP_BIND_TIME_P);
	LDAP_SET_PARAM(arglist->proxyPassword, NS_LDAP_BINDPASSWD_P);
	LDAP_SET_PARAM(arglist->adminPassword, NS_LDAP_ADMIN_BINDPASSWD_P);
	LDAP_SET_PARAM(arglist->defaultServerList, NS_LDAP_SERVERS_P);
	LDAP_SET_PARAM(arglist->enableShadowUpdate,
	    NS_LDAP_ENABLE_SHADOW_UPDATE_P);
	LDAP_SET_PARAM(arglist->certificatePath, NS_LDAP_HOST_CERTPATH_P);

	for (counter = 0;
	    counter < arglist->serviceAuthenticationMethod->count;
	    counter++) {

		LDAP_SET_PARAM(
		    arglist->serviceAuthenticationMethod->optlist[counter],
		    NS_LDAP_SERVICE_AUTH_METHOD_P);
	}
	for (counter = 0;
	    counter < arglist->serviceCredentialLevel->count;
	    counter++) {

		LDAP_SET_PARAM(
		    arglist->serviceCredentialLevel->optlist[counter],
		    NS_LDAP_SERVICE_CRED_LEVEL_P);
	}
	for (counter = 0;
	    counter < arglist->objectclassMap->count;
	    counter++) {

		LDAP_SET_PARAM(
		    arglist->objectclassMap->optlist[counter],
		    NS_LDAP_OBJECTCLASSMAP_P);
	}
	for (counter = 0;
	    counter < arglist->attributeMap->count;
	    counter++) {

		LDAP_SET_PARAM(
		    arglist->attributeMap->optlist[counter],
		    NS_LDAP_ATTRIBUTEMAP_P);
	}
	for (counter = 0;
	    counter < arglist->serviceSearchDescriptor->count;
	    counter++) {

		LDAP_SET_PARAM(
		    arglist->serviceSearchDescriptor->optlist[counter],
		    NS_LDAP_SERVICE_SEARCH_DESC_P);
	}

	retcode = credCheck(arglist);
	if (retcode == CLIENT_SUCCESS)
		retcode = adminCredCheck(arglist);
	if (retcode != CLIENT_SUCCESS) {
		CLIENT_FPUTS(
		    gettext("Error in setting up credentials\n"),
		    stderr);
		return (retcode);
	}

	if (mode_verbose)
		CLIENT_FPUTS(
		    gettext("About to modify this machines configuration "
		    "by writing the files\n"),
		    stderr);

	/* get ready to start playing with files */
	retcode = stop_services(STATE_SAVE);
	if (retcode != CLIENT_SUCCESS) {
		CLIENT_FPUTS(
		    gettext("Errors stopping network services.\n"), stderr);
		return (CLIENT_ERR_FAIL);
	}

	/* Temporarily save orig versions of files */
	retcode = mod_backup();
	if (retcode != CLIENT_SUCCESS) {
		CLIENT_FPUTS(
		    gettext("Unable to backup the ldap client files!\n"),
		    stderr);

		return (retcode);

	}

	/* Dump new files */
	errorp = __ns_ldap_DumpConfiguration(NSCONFIGFILE);
	if (errorp != NULL) {
		CLIENT_FPRINTF(stderr,
		    gettext("%s mod: errorp is not NULL; %s\n"),
		    cmd, errorp->message);
		retcode = mod_recover();
		if (retcode != CLIENT_SUCCESS) {
			CLIENT_FPUTS(
			    gettext("Recovery of systems configuration "
			    "failed.  Manual intervention of "
			    "config files is required.\n"),
			    stderr);
		}
		(void) __ns_ldap_freeError(&errorp);
		reset_ret = start_services(START_RESET);
		if (reset_ret != CLIENT_SUCCESS) {
			CLIENT_FPRINTF(stderr, gettext("Error (%d) while "
			    "starting services during reset\n"),
			    reset_ret);
		}
		return (CLIENT_ERR_FAIL);
	}

	/* if (credargs(arglist)) */
	errorp = __ns_ldap_DumpConfiguration(NSCREDFILE);
	if (errorp != NULL) {
		CLIENT_FPRINTF(stderr,
		    gettext("%s mod: errorp is not NULL; %s\n"),
		    cmd, errorp->message);
		retcode = mod_recover();
		if (retcode != CLIENT_SUCCESS) {
			CLIENT_FPUTS(
			    gettext("Recovery of systems configuration "
			    "failed.  Manual intervention of "
			    "config files is required.\n"),
			    stderr);
		}
		(void) __ns_ldap_freeError(&errorp);
		reset_ret = start_services(START_RESET);
		if (reset_ret != CLIENT_SUCCESS) {
			CLIENT_FPRINTF(stderr, gettext("Error (%d) while "
			    "starting services during reset\n"),
			    reset_ret);
		}
		return (CLIENT_ERR_FAIL);
	}

	if ((domain_fp = open(DOMAINNAME, O_WRONLY|O_CREAT|O_TRUNC,
	    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1) { /* 0644 */
		CLIENT_FPRINTF(stderr, gettext("Cannot open %s\n"), DOMAINNAME);
		retcode = mod_recover();
		if (retcode != CLIENT_SUCCESS) {
			CLIENT_FPUTS(
			    gettext("Recovery of systems configuration "
			    "failed!  Machine needs to be "
			    "fixed!\n"),
			    stderr);
		}
		reset_ret = start_services(START_RESET);
		if (reset_ret != CLIENT_SUCCESS) {
			CLIENT_FPRINTF(stderr, gettext("Error (%d) while "
			    "starting services during reset\n"),
			    reset_ret);
		}
		return (CLIENT_ERR_FAIL);
	}
	(void) write(domain_fp, dname, strlen(dname));
	(void) write(domain_fp, "\n", 1);
	(void) close(domain_fp);

	retcode = start_services(START_INIT);

	if (retcode == CLIENT_SUCCESS) {
		CLIENT_FPUTS(gettext("System successfully configured\n"),
		    stderr);
	} else {
		CLIENT_FPUTS(gettext("Error resetting system.\n"
		    "Recovering old system settings.\n"), stderr),

		    /* stop any started services for recover */
		    /* don't stomp on history of saved services state */
		    reset_ret = stop_services(STATE_NOSAVE);
		if (reset_ret != CLIENT_SUCCESS) {
			CLIENT_FPRINTF(stderr, gettext("Error (%d) while "
			    "stopping services during reset\n"),
			    reset_ret);
			/* Coninue and try to recover what we can */
		}
		reset_ret = mod_recover();
		if (reset_ret != CLIENT_SUCCESS) {
			CLIENT_FPRINTF(stderr, gettext("Error (%d) while "
			    "recovering service files during "
			    "reset\n"), reset_ret);
			/* Continue and start what we can */
		}
		reset_ret = start_services(START_RESET);
		if (reset_ret != CLIENT_SUCCESS) {
			CLIENT_FPRINTF(stderr, gettext("Error (%d) while "
			    "starting services during reset\n"),
			    reset_ret);
		}
	}

	/* Cleanup temporary files created by mod_backup() */
	mod_cleanup();

	return (retcode);
}


static int
client_genProfile(clientopts_t *arglist)
{
	int counter;
	int retcode;	/* required for LDAP_SET_PARAM macro */
	ns_ldap_error_t *errorp;

	if (mode_verbose)
		CLIENT_FPUTS(gettext("About to generate a profile\n"), stderr);

	/* *** Check for invalid args *** */
	LDAP_CHECK_INVALID(arglist->proxyDN, "proxyDN");
	LDAP_CHECK_INVALID(arglist->proxyPassword, "proxyPassword");
	LDAP_CHECK_INVALID(arglist->enableShadowUpdate,
	    "enableShadowUpdate");
	LDAP_CHECK_INVALID(arglist->adminDN, "adminDN");
	LDAP_CHECK_INVALID(arglist->adminPassword, "adminPassword");
	LDAP_CHECK_INVALID(arglist->certificatePath, "certificatePath");
	LDAP_CHECK_INVALID(arglist->domainName, "domainName");
	LDAP_CHECK_INVALID(arglist->bindDN, "bind DN");
	LDAP_CHECK_INVALID(arglist->bindPasswd, "bind password");
	/* *** End check for invalid args *** */

	if (arglist->profileName == NULL) {
		if (mode_verbose)
			CLIENT_FPUTS(
			    gettext("No profile specified. "
			    "Using \"default\"\n"),
			    stderr);
		arglist->profileName = "default";
	}

	__ns_ldap_setServer(TRUE);
	__ns_ldap_default_config();

	/* Set version to latest (not version 1) */
	LDAP_SET_PARAM(NS_LDAP_VERSION, NS_LDAP_FILE_VERSION_P);

	/* Set additional valid params from command line */
	LDAP_SET_PARAM(arglist->authenticationMethod, NS_LDAP_AUTH_P);
	LDAP_SET_PARAM(arglist->defaultSearchBase, NS_LDAP_SEARCH_BASEDN_P);
	LDAP_SET_PARAM(arglist->credentialLevel, NS_LDAP_CREDENTIAL_LEVEL_P);
	LDAP_SET_PARAM(arglist->profileTTL, NS_LDAP_CACHETTL_P);
	LDAP_SET_PARAM(arglist->searchTimeLimit, NS_LDAP_SEARCH_TIME_P);
	LDAP_SET_PARAM(arglist->preferredServerList, NS_LDAP_SERVER_PREF_P);
	LDAP_SET_PARAM(arglist->profileName, NS_LDAP_PROFILE_P);
	LDAP_SET_PARAM(arglist->followReferrals, NS_LDAP_SEARCH_REF_P);
	LDAP_SET_PARAM(arglist->defaultSearchScope, NS_LDAP_SEARCH_SCOPE_P);
	LDAP_SET_PARAM(arglist->bindTimeLimit, NS_LDAP_BIND_TIME_P);
	LDAP_SET_PARAM(arglist->defaultServerList, NS_LDAP_SERVERS_P);

	for (counter = 0;
	    counter < arglist->serviceAuthenticationMethod->count;
	    counter++) {

		LDAP_SET_PARAM(
		    arglist->serviceAuthenticationMethod->optlist[counter],
		    NS_LDAP_SERVICE_AUTH_METHOD_P);
	}
	for (counter = 0;
	    counter < arglist->serviceCredentialLevel->count;
	    counter++) {

		LDAP_SET_PARAM(
		    arglist->serviceCredentialLevel->optlist[counter],
		    NS_LDAP_SERVICE_CRED_LEVEL_P);
	}
	for (counter = 0;
	    counter < arglist->objectclassMap->count;
	    counter++) {

		LDAP_SET_PARAM(
		    arglist->objectclassMap->optlist[counter],
		    NS_LDAP_OBJECTCLASSMAP_P);
	}
	for (counter = 0;
	    counter < arglist->attributeMap->count;
	    counter++) {

		LDAP_SET_PARAM(
		    arglist->attributeMap->optlist[counter],
		    NS_LDAP_ATTRIBUTEMAP_P);
	}
	for (counter = 0;
	    counter < arglist->serviceSearchDescriptor->count;
	    counter++) {

		LDAP_SET_PARAM(
		    arglist->serviceSearchDescriptor->optlist[counter],
		    NS_LDAP_SERVICE_SEARCH_DESC_P);
	}

	errorp = __ns_ldap_DumpLdif(NULL);
	if (errorp != NULL) {
		CLIENT_FPUTS(errorp->message, stderr);
		CLIENT_FPUTC('\n', stderr);
		(void) __ns_ldap_freeError(&errorp);
		return (CLIENT_ERR_FAIL);
	}

	return (CLIENT_SUCCESS);
}

/* INET6_ADDRSTRLEN + ":" + <5-digit port> + some round-up */
#define	MAX_HOSTADDR_LEN (INET6_ADDRSTRLEN + 6 + 12)

static int
client_init(clientopts_t *arglist)
{
	int			profile_fp;
	int			retcode = CLIENT_SUCCESS;
	ns_ldap_error_t		*errorp;
	int			reset_ret;
	int			ret_copy;
	ns_standalone_conf_t	cfg = standaloneDefaults;
	ns_auth_t		auth = {NS_LDAP_AUTH_NONE,
					NS_LDAP_TLS_NONE,
					NS_LDAP_SASL_NONE,
					NS_LDAP_SASLOPT_NONE};
	char			peer[MAX_HOSTADDR_LEN];
	ns_auth_t		**authMethod;
	int			**credLevel, i;
	char			*cred;

	if (mode_verbose)
		CLIENT_FPUTS(
		    gettext("About to configure machine by downloading "
		    "a profile\n"),
		    stderr);

	if (dname == NULL) {
		CLIENT_FPUTS(
		    gettext("Init failed: System domain not set and "
		    "no domainName specified.\n"),
		    stderr);
		return (CLIENT_ERR_FAIL);
	}

	if (!arglist->defaultServerList) {
		CLIENT_FPUTS(gettext("Missing LDAP server address\n"), stderr);
		return (CLIENT_ERR_FAIL);
	}

	/* *** Check for invalid args *** */
	LDAP_CHECK_INVALID(arglist->defaultSearchBase,
	    "defaultSearchBase");
	LDAP_CHECK_INVALID(arglist->profileTTL,
	    "profileTTL");
	LDAP_CHECK_INVALID(arglist->searchTimeLimit,
	    "searchTimeLimit");
	LDAP_CHECK_INVALID(arglist->preferredServerList,
	    "preferredServerList");
	LDAP_CHECK_INVALID(arglist->followReferrals,
	    "followReferrals");
	LDAP_CHECK_INVALID(arglist->defaultSearchScope,
	    "defaultSearchScope");
	LDAP_CHECK_INVALID(arglist->bindTimeLimit,
	    "bindTimeLimit");

	LDAP_CHECK_INVALID(arglist->objectclassMap->count,
	    "objectclassMap");
	LDAP_CHECK_INVALID(arglist->attributeMap->count,
	    "attributeMap");
	LDAP_CHECK_INVALID(arglist->serviceAuthenticationMethod->count,
	    "serviceAuthenticationMethod");
	LDAP_CHECK_INVALID(arglist->serviceCredentialLevel->count,
	    "serviceCredentialLevel");
	LDAP_CHECK_INVALID(arglist->serviceSearchDescriptor->count,
	    "serviceSearchDescriptor");
	/* *** End check for invalid args *** */

	if (arglist->profileName == NULL) {
		if (mode_verbose)
			CLIENT_FPUTS(
			    gettext("No profile specified. "
			    "Using \"default\"\n"),
			    stderr);
		arglist->profileName = "default";
	}

	(void) strncpy(peer, arglist->defaultServerList, MAX_HOSTADDR_LEN - 1);
	if (separatePort(peer, &cfg.SA_SERVER, &cfg.SA_PORT) > 0) {
		return (CLIENT_ERR_FAIL);
	}

	if (arglist->bindDN != NULL) {
		cfg.SA_CRED = "proxy";
		/*
		 * We don't want to force users to always specify authentication
		 * method when we can infer it. If users want SSL, they would
		 * have to specify appropriate -a though.
		 */
		auth.type = NS_LDAP_AUTH_SIMPLE;
		if (arglist->bindPasswd == NULL) {
			arglist->bindPasswd =
			    getpassphrase("Bind Password:");
			if (arglist->bindPasswd == NULL) {
				CLIENT_FPUTS(gettext("Get password failed\n"),
				    stderr);

				if (gStartLdap == START_RESET)
					(void) start_service(LDAP_FMRI, B_TRUE);

				return (CLIENT_ERR_CREDENTIAL);
			}
		}
	}
	cfg.SA_BIND_DN = arglist->bindDN;
	cfg.SA_BIND_PWD = arglist->bindPasswd;

	if (arglist->authenticationMethod != NULL) {
		if (__ns_ldap_initAuth(arglist->authenticationMethod,
		    &auth, &errorp) != NS_LDAP_SUCCESS) {
			if (errorp != NULL) {
				CLIENT_FPRINTF(stderr, "%s", errorp->message);
				(void) __ns_ldap_freeError(&errorp);
			}

			if (gStartLdap == START_RESET)
				(void) start_service(LDAP_FMRI, B_TRUE);

			return (CLIENT_ERR_FAIL);
		}
		cfg.SA_AUTH = &auth;
	}
	cfg.SA_CRED = arglist->credentialLevel;

	cfg.SA_DOMAIN = arglist->domainName;
	cfg.SA_PROFILE_NAME = arglist->profileName;
	cfg.SA_CERT_PATH = arglist->certificatePath;

	cfg.type = NS_LDAP_SERVER;

	if (__ns_ldap_initStandalone(&cfg, &errorp) != NS_LDAP_SUCCESS) {
		if (errorp != NULL) {
			CLIENT_FPRINTF(stderr, "%s", errorp->message);
			(void) __ns_ldap_freeError(&errorp);
		}

		if (gStartLdap == START_RESET)
			(void) start_service(LDAP_FMRI, B_TRUE);

		return (CLIENT_ERR_FAIL);
	}

	if (arglist->proxyDN != NULL && arglist->proxyPassword == NULL) {
		arglist->proxyPassword = getpassphrase("Proxy Bind Password:");
		if (arglist->proxyPassword == NULL) {
			CLIENT_FPUTS(gettext("Get password failed\n"), stderr);

			if (gStartLdap == START_RESET)
				(void) start_service(LDAP_FMRI, B_TRUE);

			return (CLIENT_ERR_CREDENTIAL);
		}
	}
	if (arglist->proxyDN != NULL && arglist->proxyPassword != NULL) {
		if (__ns_ldap_setParam(NS_LDAP_BINDDN_P,
		    arglist->proxyDN, &errorp) != NS_LDAP_SUCCESS) {
			if (errorp != NULL) {
				CLIENT_FPRINTF(stderr, "%s", errorp->message);
				(void) __ns_ldap_freeError(&errorp);
			}
			return (CLIENT_ERR_CREDENTIAL);
		}
		if (__ns_ldap_setParam(NS_LDAP_BINDPASSWD_P,
		    arglist->proxyPassword, &errorp) != NS_LDAP_SUCCESS) {
			if (errorp != NULL) {
				CLIENT_FPRINTF(stderr, "%s", errorp->message);
				(void) __ns_ldap_freeError(&errorp);
			}
			return (CLIENT_ERR_CREDENTIAL);
		}
	}

	if (arglist->enableShadowUpdate != NULL) {
		LDAP_SET_PARAM(arglist->enableShadowUpdate,
		    NS_LDAP_ENABLE_SHADOW_UPDATE_P);
	}

	if (arglist->enableShadowUpdate &&
	    strcasecmp(arglist->enableShadowUpdate, "TRUE") == 0 &&
	    arglist->adminDN != NULL && arglist->adminPassword == NULL) {
		arglist->adminPassword = getpassphrase("admin Bind Password:");
		if (arglist->adminPassword == NULL) {
			CLIENT_FPUTS(gettext("Get password failed\n"), stderr);

			if (gStartLdap == START_RESET)
				(void) start_service(LDAP_FMRI, B_TRUE);

			return (CLIENT_ERR_CREDENTIAL);
		}
	}
	if (arglist->adminDN != NULL && arglist->adminPassword != NULL) {
		if (__ns_ldap_setParam(NS_LDAP_ADMIN_BINDDN_P,
		    arglist->adminDN, &errorp) != NS_LDAP_SUCCESS) {
			if (errorp != NULL) {
				CLIENT_FPRINTF(stderr, "%s\n", errorp->message);
				(void) __ns_ldap_freeError(&errorp);
			}
			return (CLIENT_ERR_CREDENTIAL);
		}
		if (__ns_ldap_setParam(NS_LDAP_ADMIN_BINDPASSWD_P,
		    arglist->adminPassword, &errorp) != NS_LDAP_SUCCESS) {
			if (errorp != NULL) {
				CLIENT_FPRINTF(stderr, "%s\n", errorp->message);
				(void) __ns_ldap_freeError(&errorp);
			}
			return (CLIENT_ERR_CREDENTIAL);
		}
	}

	if (arglist->authenticationMethod != NULL) {
		if (__ns_ldap_getParam(NS_LDAP_AUTH_P,
		    (void ***)&authMethod, &errorp) != NS_LDAP_SUCCESS) {
			if (errorp != NULL) {
				CLIENT_FPRINTF(stderr, "%s", errorp->message);
				(void) __ns_ldap_freeError(&errorp);
			}
			return (CLIENT_ERR_CREDENTIAL);
		}

		if (authMethod != NULL) {
			for (i = 0; authMethod[i] != NULL; ++i) {
				if (authMethod[i]->type == auth.type) {
					break;
				}
			}

			if (authMethod[i] == NULL) {
				CLIENT_FPRINTF(stderr, gettext(
				    "Warning: init authentication method "
				    "not found in DUAConfigProfile.\n"));
			} else {
				if (i != 0) {
					CLIENT_FPRINTF(stderr,
					    gettext(
					    "Warning: init authentication"
					    "method using secondary "
					    "authentication method from "
					    "DUAConfigProfile.\n"));
				}
			}
			(void) __ns_ldap_freeParam((void ***) &authMethod);
		}
	}

	if (arglist->credentialLevel != NULL) {
		if (__ns_ldap_getParam(NS_LDAP_CREDENTIAL_LEVEL_P,
		    (void ***)&credLevel, &errorp) != NS_LDAP_SUCCESS) {
			if (errorp != NULL) {
				CLIENT_FPRINTF(stderr, "%s", errorp->message);
				(void) __ns_ldap_freeError(&errorp);
			}
			return (CLIENT_ERR_CREDENTIAL);
		}
		if (credLevel != NULL) {
			for (i = 0; credLevel[i] != NULL; ++i) {
				switch (*credLevel[i]) {
				case NS_LDAP_CRED_ANON :
					cred = "none";
					break;
				case NS_LDAP_CRED_PROXY :
					cred = "proxy";
					break;
				case NS_LDAP_CRED_SELF :
					cred = "self";
					break;
				default:
					continue;
				}
				if (strcmp(cred,
				    arglist->credentialLevel) == 0) {
					break;
				}
			}
			if (credLevel[i] == NULL) {
				CLIENT_FPRINTF(stderr, gettext(
				    "Warning: init credential level not found "
				    "in DUAConfigProfile.\n"));
			} else {
				if (i != 0) {
					CLIENT_FPRINTF(stderr,
					    gettext("Warning: "
					    "init credential level using "
					    "secondary credential level from "
					    "DUAConfigProfile.\n"));
				}
			}
			(void) __ns_ldap_freeParam((void ***) &credLevel);
		}
	}

	retcode = credCheck(arglist);
	if (retcode == CLIENT_SUCCESS)
		retcode = adminCredCheck(arglist);
	if (retcode != CLIENT_SUCCESS) {
		CLIENT_FPUTS(
		    gettext("Error in setting up credentials\n"), stderr);

		if (gStartLdap == START_RESET)
			(void) start_service(LDAP_FMRI, B_TRUE);

		return (retcode);
	}

	if (mode_verbose)
		CLIENT_FPUTS(
		    gettext("About to modify this machines configuration "
		    "by writing the files\n"),
		    stderr);

	/* get ready to start playing with files */
	retcode = stop_services(STATE_SAVE);
	if (retcode != CLIENT_SUCCESS) {
		CLIENT_FPUTS(
		    gettext("Errors stopping network services.\n"), stderr);

		if (gStartLdap == START_RESET)
			(void) start_service(LDAP_FMRI, B_TRUE);

		return (CLIENT_ERR_FAIL);
	}

	/* Save orig versions of files */
	retcode = file_backup();
	if (retcode == CLIENT_ERR_RESTORE) {
		CLIENT_FPUTS(
		    gettext("System not in state to enable ldap client.\n"),
		    stderr);

		return (retcode);

	} else if (retcode != CLIENT_SUCCESS) {
		CLIENT_FPUTS(
		    gettext("Save of system configuration failed.  "
		    "Attempting recovery.\n"),
		    stderr);
		retcode = recover(STATE_NOSAVE);
		if (retcode != CLIENT_SUCCESS) {
			CLIENT_FPUTS(
			    gettext("Recovery of systems configuration "
			    "failed.  Manual intervention of "
			    "config files is required.\n"),
			    stderr);
		}

		reset_ret = start_services(START_RESET);
		if (reset_ret != CLIENT_SUCCESS) {
			CLIENT_FPRINTF(stderr, gettext("Error (%d) while "
			    "starting services during reset\n"),
			    reset_ret);
		}

		return (retcode);
	}

	/* Dump new files */
	errorp = __ns_ldap_DumpConfiguration(NSCONFIGFILE);
	if (NULL != errorp) {
		CLIENT_FPRINTF(stderr,
		    gettext("%s init: errorp is not NULL; %s\n"),
		    cmd, errorp->message);
		retcode = recover(STATE_NOSAVE);
		if (retcode != CLIENT_SUCCESS) {
			CLIENT_FPUTS(
			    gettext("Recovery of systems configuration "
			    "failed.  Manual intervention of "
			    "config files is required.\n"),
			    stderr);
			return (CLIENT_ERR_FAIL);
		}
		(void) __ns_ldap_freeError(&errorp);
		reset_ret = start_services(START_RESET);
		if (reset_ret != CLIENT_SUCCESS) {
			CLIENT_FPRINTF(stderr, gettext("Error (%d) while "
			    "starting services during reset\n"),
			    reset_ret);
		}
		return (CLIENT_ERR_FAIL);
	}

	/* if (credargs(arglist)) */
	errorp = __ns_ldap_DumpConfiguration(NSCREDFILE);
	if (NULL != errorp) {
		CLIENT_FPRINTF(stderr,
		    gettext("%s init: errorp is not NULL; %s\n"),
		    cmd, errorp->message);
		retcode = recover(STATE_NOSAVE);
		if (retcode != CLIENT_SUCCESS) {
			CLIENT_FPUTS(
			    gettext("Recovery of systems configuration "
			    "failed.  Manual intervention of "
			    "config files is required.\n"),
			    stderr);
			return (CLIENT_ERR_FAIL);
		}
		(void) __ns_ldap_freeError(&errorp);
		reset_ret = start_services(START_RESET);
		if (reset_ret != CLIENT_SUCCESS) {
			CLIENT_FPRINTF(stderr, gettext("Error (%d) while "
			    "starting services during reset\n"),
			    reset_ret);
		}
		return (CLIENT_ERR_FAIL);
	}

	ret_copy = system(CMD_CP " " NSSWITCH_LDAP " " NSSWITCH_CONF);
	if (ret_copy != 0) {
		CLIENT_FPRINTF(stderr,
		    gettext("Error %d copying (%s) -> (%s)\n"),
		    ret_copy, NSSWITCH_LDAP, NSSWITCH_CONF);
		retcode = recover(STATE_NOSAVE);
		if (retcode != CLIENT_SUCCESS) {
			CLIENT_FPUTS(
			    gettext("Recovery of systems configuration "
			    "failed.  Manual intervention of "
			    "config files is required.\n"),
			    stderr);
		}
		reset_ret = start_services(START_RESET);
		if (reset_ret != CLIENT_SUCCESS) {
			CLIENT_FPRINTF(stderr, gettext("Error (%d) while "
			    "starting services during reset\n"),
			    reset_ret);
		}
		return (CLIENT_ERR_FAIL);
	}

	if ((profile_fp = open(DOMAINNAME, O_WRONLY|O_CREAT|O_TRUNC,
	    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1) { /* 0644 */
		CLIENT_FPRINTF(stderr, gettext("Cannot open %s\n"), DOMAINNAME);
		retcode = recover(STATE_NOSAVE);
		if (retcode != CLIENT_SUCCESS) {
			CLIENT_FPUTS(
			    gettext("Recovery of systems configuration "
			    "failed.  Manual intervention of "
			    "config files is required.\n"),
			    stderr);
			return (CLIENT_ERR_FAIL);
		}
		reset_ret = start_services(START_RESET);
		if (reset_ret != CLIENT_SUCCESS) {
			CLIENT_FPRINTF(stderr, gettext("Error (%d) while "
			    "starting services during reset\n"),
			    reset_ret);
		}
		return (CLIENT_ERR_FAIL);
	}
	(void) write(profile_fp, dname, strlen(dname));
	(void) write(profile_fp, "\n", 1);
	(void) close(profile_fp);

	retcode = start_services(START_INIT);

	if (retcode == CLIENT_SUCCESS) {
		CLIENT_FPUTS(gettext("System successfully configured\n"),
		    stderr);
	} else {
		CLIENT_FPUTS(gettext("Error resetting system.\n"
		    "Recovering old system settings.\n"), stderr),

		    /* stop any started services for recover */
		    /* don't stomp on history of saved services state */
		    reset_ret = stop_services(STATE_NOSAVE);
		if (reset_ret != CLIENT_SUCCESS) {
			CLIENT_FPRINTF(stderr, gettext("Error (%d) while "
			    "stopping services during reset\n"),
			    reset_ret);
			/* Coninue and try to recover what we can */
		}
		reset_ret = recover(STATE_NOSAVE);
		if (reset_ret != CLIENT_SUCCESS) {
			CLIENT_FPRINTF(stderr, gettext("Error (%d) while "
			    "recovering service files during "
			    "reset\n"), reset_ret);
			/* Continue and start what we can */
		}
		reset_ret = start_services(START_RESET);
		if (reset_ret != CLIENT_SUCCESS) {
			CLIENT_FPRINTF(stderr, gettext("Error (%d) while "
			    "starting services during reset\n"),
			    reset_ret);
		}
	}

	return (retcode);
}


static void
usage(void)
{
	if (mode_quiet)
		return;

	if (gen == 0) {
		CLIENT_FPRINTF(stderr,
		    gettext("Usage: %s [-v | -q] init | manual | mod | "
		    "list | uninit [<args>]\n"),
		    cmd);

		CLIENT_FPRINTF(stderr,
		    gettext("\n       %s [-v | -q] [-a authenticationMethod]"
		    " [-D bindDN]\n\t[-w bindPassword] [-j passswdFile]"
		    " [-y proxyPasswordFile]\n\t"
		    "[-z adminPasswordFile] init [<args>]\n"),
		    cmd);

		CLIENT_FPUTS(
		    gettext("\nSet up a server or workstation as a "
		    "client of an LDAP namespace.\n"),
		    stderr);
	} else {	/* genprofile */
		CLIENT_FPRINTF(stderr,
		    gettext("Usage: %s [-v | -q] genprofile "
		    "-a profileName=<name> "
		    "-a defaultSearchBase=<base> <args>\n"),
		    cmd);

		CLIENT_FPUTS(
		    gettext("\nGenerate a profile used to set up clients "
		    "of an LDAP namespace.\n"),
		    stderr);
	}
	CLIENT_FPUTS(
	    gettext("<args> take the form of \'-a attrName=attrVal\' as "
	    "described in the\n"),
	    stderr);
	CLIENT_FPUTS(gettext("man page: ldapclient(1M)\n"), stderr);
}


/*
 * stop_services is called to stop network services prior to their
 * config files being moved/changed.  In case a later recovery is needed
 * (an error occurs during config), we detect whether the service is
 * running and store that info so that a reset will only start services
 * that were stopped here.
 *
 * In terms of SMF, this translates to disabling the services. So we
 * try to disable them if they are in any other state
 *
 * Stop order :
 * sendmail, nscd, autofs, ldap.client, nisd (rpc), inetinit(domainname)
 */
static int
stop_services(int saveState)
{
	int ret;

	if (mode_verbose) {
		CLIENT_FPUTS(gettext("Stopping network services\n"), stderr);
	}

	if (!is_service(SENDMAIL_FMRI, SCF_STATE_STRING_DISABLED)) {
		if (mode_verbose)
			CLIENT_FPUTS(gettext("Stopping sendmail\n"), stderr);
		ret = disable_service(SENDMAIL_FMRI, B_TRUE);
		if (ret != CLIENT_SUCCESS) {
			/* Not serious, but tell user what to do */
			CLIENT_FPRINTF(stderr, gettext("Stopping sendmail "
			    "failed with (%d). You may need to restart "
			    "it manually for changes to take effect.\n"),
			    ret);
		} else enableFlag |= SENDMAIL_ON;
	} else {
		if (mode_verbose)
			CLIENT_FPUTS(gettext("sendmail not running\n"), stderr);
	}

	if (!is_service(NSCD_FMRI, SCF_STATE_STRING_DISABLED)) {
		if (mode_verbose)
			CLIENT_FPUTS(gettext("Stopping nscd\n"), stderr);
		ret = disable_service(NSCD_FMRI, B_TRUE);
		if (ret != CLIENT_SUCCESS) {
			CLIENT_FPRINTF(stderr, gettext("Stopping nscd "
			    "failed with (%d)\n"), ret);
			return (CLIENT_ERR_FAIL);
		} else enableFlag |= NSCD_ON;
	} else {
		if (mode_verbose)
			CLIENT_FPUTS(gettext("nscd not running\n"), stderr);
	}

	if (!is_service(AUTOFS_FMRI, SCF_STATE_STRING_DISABLED)) {
		if (mode_verbose)
			CLIENT_FPUTS(gettext("Stopping autofs\n"), stderr);
		ret = disable_service(AUTOFS_FMRI, B_TRUE);
		if (ret != CLIENT_SUCCESS) {
			/* Not serious, but tell user what to do */
			CLIENT_FPRINTF(stderr, gettext("Stopping autofs "
			    "failed with (%d). You may need to restart "
			    "it manually for changes to take effect.\n"),
			    ret);
		} else enableFlag |= AUTOFS_ON;
	} else {
		if (mode_verbose)
			CLIENT_FPUTS(gettext("autofs not running\n"), stderr);
	}

	if (!is_service(LDAP_FMRI, SCF_STATE_STRING_DISABLED)) {
		if (saveState)
			gStartLdap = START_RESET;
		if (mode_verbose)
			CLIENT_FPUTS(gettext("Stopping ldap\n"), stderr);
		ret = disable_service(LDAP_FMRI, B_TRUE);
		if (ret != CLIENT_SUCCESS) {
			CLIENT_FPRINTF(stderr, gettext("Stopping ldap "
			    "failed with (%d)\n"), ret);
			return (CLIENT_ERR_FAIL);
		}
	} else {
		if (mode_verbose)
			CLIENT_FPUTS(gettext("ldap not running\n"),
			    stderr);
	}

	if (!is_service(YP_FMRI, SCF_STATE_STRING_DISABLED)) {
		if (saveState)
			gStartYp = START_RESET;
		if (mode_verbose)
			CLIENT_FPUTS(gettext("Stopping nis(yp)\n"), stderr);
		ret = disable_service(YP_FMRI, B_TRUE);
		if (ret != 0) {
			CLIENT_FPRINTF(stderr, gettext("Stopping nis(yp) "
			    "failed with (%d)\n"), ret);
			return (CLIENT_ERR_FAIL);
		}
	} else {
		if (mode_verbose)
			CLIENT_FPUTS(gettext("nis(yp) not running\n"),
			    stderr);
	}

	return (CLIENT_SUCCESS);
}

/*
 * start_services is called to start up network services after config
 * files have all been setup or recovered.  In the case of an error, the
 * files will be recovered and start_services will be called with the
 * "reset" flag set so that only those services that were earlier stopped
 * will be started.  If it is not a reset, then the services associated
 * with files "recovered" will attempt to be started.
 */
static int
start_services(int flag)
{
	int sysret, retcode = CLIENT_SUCCESS, rc = NS_LDAP_SUCCESS;
	FILE *domain_fp;
	char domainname[BUFSIZ];
	char cmd_domain_start[BUFSIZ];
	int domainlen;
	ns_ldap_self_gssapi_config_t config = NS_LDAP_SELF_GSSAPI_CONFIG_NONE;
	ns_ldap_error_t		*errorp = NULL;

	if (mode_verbose) {
		CLIENT_FPUTS(gettext("Starting network services\n"), stderr);
	}

	/* Read in current defaultdomain so we can set it */
	domain_fp = fopen(DOMAINNAME, "r");
	if (domain_fp == NULL) {
		CLIENT_FPRINTF(stderr, gettext("Error opening defaultdomain "
		    "(%d)\n"), errno);
		/* if we did an ldap init, we must have domain */
		if (flag == START_INIT)
			return (CLIENT_ERR_FAIL);
	} else {
		if (fgets(domainname, BUFSIZ, domain_fp) == NULL) {
			CLIENT_FPUTS(gettext("Error reading defaultdomain\n"),
			    stderr);
			return (CLIENT_ERR_FAIL);
		}

		if (fclose(domain_fp) != 0) {
			CLIENT_FPRINTF(stderr,
			    gettext("Error closing defaultdomain (%d)\n"),
			    errno);
			return (CLIENT_ERR_FAIL);
		}
		domainlen = strlen(domainname);
		/* sanity check to make sure sprintf will fit */
		if (domainlen > (BUFSIZE - sizeof (CMD_DOMAIN_START) -
		    sizeof (TO_DEV_NULL) - 3)) {
			CLIENT_FPUTS(gettext("Specified domainname is "
			    "too large\n"), stderr);
			return (CLIENT_ERR_FAIL);
		}
		if (domainname[domainlen-1] == '\n')
			domainname[domainlen-1] = 0;
		/* buffer size is checked above */
		(void) snprintf(cmd_domain_start, BUFSIZ, "%s %s %s",
		    CMD_DOMAIN_START, domainname, TO_DEV_NULL);
	}

	/*
	 * We can be starting services after an init in which case
	 * we want to start ldap and not start yp.
	 */
	if (flag == START_INIT) {
		sysret = system(cmd_domain_start);
		if (mode_verbose)
			CLIENT_FPRINTF(stderr, "start: %s %s... %s\n",
			    CMD_DOMAIN_START, domainname,
			    (sysret == 0) ? gettext("success") :
			    gettext("failed"));
		if (sysret != 0) {
			CLIENT_FPRINTF(stderr, gettext("\"%s\" returned: %d\n"),
			    CMD_DOMAIN_START, sysret);

			retcode = CLIENT_ERR_FAIL;
		}

		if ((rc = __ns_ldap_self_gssapi_config(&config)) !=
		    NS_LDAP_SUCCESS) {
			CLIENT_FPRINTF(stderr, gettext("Error (%d) while "
			    "checking sasl/GSSAPI configuration\n"),
			    rc);
			retcode = CLIENT_ERR_FAIL;
		}

		if (config != NS_LDAP_SELF_GSSAPI_CONFIG_NONE) {

			rc = __ns_ldap_check_dns_preq(
			    1, mode_verbose, mode_quiet,
			    NSSWITCH_LDAP, config, &errorp);
			if (errorp)
				(void) __ns_ldap_freeError(&errorp);

			if (rc != NS_LDAP_SUCCESS)
				retcode = CLIENT_ERR_FAIL;
		}

		if (rc == NS_LDAP_SUCCESS &&
		    start_service(LDAP_FMRI, B_TRUE) != CLIENT_SUCCESS)
			retcode = CLIENT_ERR_FAIL;

		if (config != NS_LDAP_SELF_GSSAPI_CONFIG_NONE &&
		    rc == NS_LDAP_SUCCESS && retcode == CLIENT_SUCCESS) {
			rc = __ns_ldap_check_gssapi_preq(
			    1, mode_verbose, mode_quiet, config,
			    &errorp);
			if (errorp)
				(void) __ns_ldap_freeError(&errorp);

			if (rc != NS_LDAP_SUCCESS)
				retcode = CLIENT_ERR_FAIL;

		}
		/* No YP after init */
	/*
	 * Or we can be starting services after an uninit or error
	 * recovery.  We want to start whatever services were running
	 * before.  In the case of error recovery, it is the services
	 * that were running before we stopped them (flags set in
	 * stop_services).  If it is an uninit then we determine
	 * which services to start based on the files we recovered
	 * (flags set in recover).
	 */
	} else {
		/* uninit and recover should set flags of what to start */
		if (domain_fp) {
			sysret = system(cmd_domain_start);
			if (mode_verbose)
				CLIENT_FPRINTF(stderr, "start: %s %s... %s\n",
				    CMD_DOMAIN_START, domainname,
				    (sysret == 0) ? gettext("success") :
				    gettext("failed"));
			if (sysret != 0) {
				CLIENT_FPRINTF(stderr, gettext("\"%s\" "
				    "returned: %d\n"),
				    CMD_DOMAIN_START, sysret);

				retcode = CLIENT_ERR_FAIL;
			}
		}

		if (gStartLdap == flag) {
			if (!(is_service(LDAP_FMRI, SCF_STATE_STRING_ONLINE)))
				if (start_service(LDAP_FMRI, B_TRUE)
				    != CLIENT_SUCCESS)
					retcode = CLIENT_ERR_FAIL;
		}

		if (gStartYp == flag) {
			if (!(is_service(YP_FMRI, SCF_STATE_STRING_ONLINE)))
				(void) start_service(YP_FMRI, B_TRUE);
		}
	}
	if ((enableFlag & AUTOFS_ON) &&
	    !(is_service(AUTOFS_FMRI, SCF_STATE_STRING_ONLINE)))
		(void) start_service(AUTOFS_FMRI, B_TRUE);

	if ((enableFlag & NSCD_ON) &&
	    !(is_service(NSCD_FMRI, SCF_STATE_STRING_ONLINE)))
		(void) start_service(NSCD_FMRI, B_TRUE);

#if 0
	if (flag == START_INIT && config != NS_LDAP_SELF_GSSAPI_CONFIG_NONE &&
	    retcode == CLIENT_SUCCESS &&
	    !(is_service(NSCD_FMRI, SCF_STATE_STRING_ONLINE))) {
		CLIENT_FPRINTF(stderr, "start: %s\n",
		    gettext("self/sasl/GSSAPI is configured"
		    " but nscd is not online"));
		retcode = CLIENT_ERR_FAIL;
	}
#endif

	if ((enableFlag & SENDMAIL_ON) &&
	    !(is_service(SENDMAIL_FMRI, SCF_STATE_STRING_ONLINE)))
		(void) start_service(SENDMAIL_FMRI, B_TRUE);

	/*
	 * Restart name-service milestone so that any consumer
	 * which depends on it will be restarted.
	 */
	(void) restart_service(NS_MILESTONE_FMRI, B_TRUE);
	return (retcode);
}

/*
 * credCheck is called to check if credentials are required for this
 * configuration.  Currently, this means that if any credentialLevel is
 * proxy and any authenticationMethod is something other than none, then
 * credential info is required (proxyDN and proxyPassword).
 */
static int
credCheck(clientopts_t *arglist)
{
	int counter;
	int **credLevel;
	ns_auth_t **authMethod;
	char **proxyDN, **proxyPassword;
	ns_ldap_error_t *errorp;
	int credProxy, authNotNone;
	int retcode;

/* If credentialLevel is proxy, make sure we have proxyDN and proxyPassword */
	retcode = __ns_ldap_getParam(NS_LDAP_CREDENTIAL_LEVEL_P,
	    (void ***)&credLevel, &errorp);
	if (retcode != 0) {
		CLIENT_FPRINTF(stderr,
		    gettext("Error %d while trying to retrieve "
		    "credLevel\n"),
		    retcode);
		return (CLIENT_ERR_FAIL);
	}
	retcode = __ns_ldap_getParam(NS_LDAP_AUTH_P,
	    (void ***)&authMethod, &errorp);
	if (retcode != 0) {
		CLIENT_FPRINTF(stderr,
		    gettext("Error %d while trying to retrieve "
		    "authMethod\n"), retcode);
		return (CLIENT_ERR_FAIL);
	}
	retcode = __ns_ldap_getParam(NS_LDAP_BINDDN_P,
	    (void ***)&proxyDN, &errorp);
	if (retcode != 0) {
		CLIENT_FPRINTF(stderr,
		    gettext("Error %d while trying to retrieve proxyDN\n"),
		    retcode);
		return (CLIENT_ERR_FAIL);
	}
	retcode = __ns_ldap_getParam(NS_LDAP_BINDPASSWD_P,
	    (void ***)&proxyPassword, &errorp);
	if (retcode != 0) {
		CLIENT_FPRINTF(stderr,
		    gettext("Error %d while trying to retrieve "
		    "proxyPassword\n"), retcode);
		return (CLIENT_ERR_FAIL);
	}

	if (mode_verbose) {
		CLIENT_FPRINTF(stderr,
		    gettext("Proxy DN: %s\n"),
		    (proxyDN && proxyDN[0]) ? proxyDN[0] : "NULL");
		CLIENT_FPRINTF(stderr,
		    gettext("Proxy password: %s\n"),
		    (proxyPassword && proxyPassword[0]) ?
		    proxyPassword[0] : "NULL");
	}

	credProxy = 0;	/* flag to indicate if we have a credLevel of proxy */
	for (counter = 0; credLevel && credLevel[counter] != NULL; counter++) {
		if (mode_verbose)
			CLIENT_FPRINTF(stderr,
			    gettext("Credential level: %d\n"),
			    *credLevel[counter]);
		if (*credLevel[counter] == NS_LDAP_CRED_PROXY) {
			credProxy = 1;
			break;
		}
	}

	authNotNone = 0;	/* flag for authMethod other than none */
	for (counter = 0;
	    authMethod && authMethod[counter] != NULL;
	    counter++) {

		if (mode_verbose)
			CLIENT_FPRINTF(stderr,
			    gettext("Authentication method: %d\n"),
			    authMethod[counter]->type);
		if (authMethod[counter]->type != NS_LDAP_AUTH_NONE &&
		    !(authMethod[counter]->type == NS_LDAP_AUTH_TLS &&
		    authMethod[counter]->tlstype == NS_LDAP_TLS_NONE)) {
			authNotNone = 1;
			break;
		}
	}

	/* First, if we don't need proxyDN/Password then just return ok */
	if (!(credProxy && authNotNone)) {
		if (mode_verbose)
			CLIENT_FPUTS(
			    gettext("No proxyDN/proxyPassword required\n"),
			    stderr);
		return (CLIENT_SUCCESS);
	}

	/* Now let's check if we have the cred stuff we need */
	if (!proxyDN || !proxyDN[0]) {
		CLIENT_FPUTS(
		    gettext("credentialLevel is proxy and no proxyDN "
		    "specified\n"),
		    stderr);
		return (CLIENT_ERR_CREDENTIAL);
	}

	/* If we need proxyPassword (prompt) */
	if (!proxyPassword || !proxyPassword[0]) {
		CLIENT_FPUTS(
		    gettext("credentialLevel requires proxyPassword\n"),
		    stderr);
		arglist->proxyPassword = getpassphrase("Proxy Bind Password:");
		if (arglist->proxyPassword == NULL) {
			CLIENT_FPUTS(gettext("Get password failed\n"), stderr);
			return (CLIENT_ERR_CREDENTIAL);
		}
		LDAP_SET_PARAM(arglist->proxyPassword, NS_LDAP_BINDPASSWD_P);
		if (retcode != 0) {
			CLIENT_FPUTS(
			    gettext("setParam proxyPassword failed.\n"),
			    stderr);
			return (CLIENT_ERR_CREDENTIAL);
		}
	}

	return (CLIENT_SUCCESS);
}

/*
 * adminCredCheck is called to check if the admin credential is required
 * for this configuration. This means that if enableShadowUpdate is set
 * to TRUE then credential info is required (adminDN and adminPassword).
 * One exception is that if there is a 'self' credentialLevel and
 * 'sasl/GSSAPI' authenticationMethod (i.e., possibly using Kerberos
 * host credential) then adminDN and adminPassword are not required.
 */
static int
adminCredCheck(clientopts_t *arglist)
{
	int counter;
	int **enabled = NULL;
	int **credLevel = NULL;
	char **adminDN = NULL;
	char **adminPassword = NULL;
	ns_auth_t **authMethod = NULL;
	ns_ldap_error_t *errorp = NULL;
	int credSelf, authSASLgss;
	int retcode, rc;

	/* If shadow update not enabled, then no need to check */
	retcode = __ns_ldap_getParam(NS_LDAP_ENABLE_SHADOW_UPDATE_P,
	    (void ***)&enabled, &errorp);
	if (retcode != 0) {
		CLIENT_FPRINTF(stderr,
		    gettext("Error %d while trying to retrieve "
		    "enableShadowUpdate\n"), retcode);
		rc = CLIENT_ERR_FAIL;
		goto out;
	}
	if (enabled == NULL ||
	    *enabled[0] != NS_LDAP_ENABLE_SHADOW_UPDATE_TRUE) {
		if (mode_verbose)
			CLIENT_FPUTS(
			    gettext("Shadow Update is not enabled, "
			    "no adminDN/adminPassword is required.\n"), stderr);
		rc = CLIENT_SUCCESS;
		goto out;
	}

	/* get credentialLevel */
	retcode = __ns_ldap_getParam(NS_LDAP_CREDENTIAL_LEVEL_P,
	    (void ***)&credLevel, &errorp);
	if (retcode != 0) {
		CLIENT_FPRINTF(stderr,
		    gettext("Error %d while trying to retrieve credLevel\n"),
		    retcode);
		rc = CLIENT_ERR_FAIL;
		goto out;
	}

	/* get AuthenticationMethod */
	retcode = __ns_ldap_getParam(NS_LDAP_AUTH_P,
	    (void ***)&authMethod, &errorp);
	if (retcode != 0) {
		CLIENT_FPRINTF(stderr,
		    gettext("Error %d while trying to retrieve authMethod\n"),
		    retcode);
		rc = CLIENT_ERR_FAIL;
		goto out;
	}

	/* get adminDN */
	retcode = __ns_ldap_getParam(NS_LDAP_ADMIN_BINDDN_P,
	    (void ***)&adminDN, &errorp);
	if (retcode != 0) {
		CLIENT_FPRINTF(stderr,
		    gettext("Error %d while trying to retrieve adminDN\n"),
		    retcode);
		rc = CLIENT_ERR_FAIL;
		goto out;
	}

	/* get adminPassword */
	retcode = __ns_ldap_getParam(NS_LDAP_ADMIN_BINDPASSWD_P,
	    (void ***)&adminPassword, &errorp);
	if (retcode != 0) {
		CLIENT_FPRINTF(stderr,
		    gettext("Error %d while trying to retrieve "
		    "adminPassword\n"), retcode);
		rc = CLIENT_ERR_FAIL;
		goto out;
	}

	if (mode_verbose) {
		CLIENT_FPRINTF(stderr,
		    gettext("admin DN: %s\n"),
		    (adminDN && adminDN[0]) ? adminDN[0] : "NULL");
		CLIENT_FPRINTF(stderr,
		    gettext("admin password: %s\n"),
		    (adminPassword && adminPassword[0]) ?
		    adminPassword[0] : "NULL");
	}

	credSelf = 0;	/* flag to indicate if we have a credLevel of self */
	for (counter = 0; credLevel && credLevel[counter] != NULL; counter++) {
		if (mode_verbose)
			CLIENT_FPRINTF(stderr,
			    gettext("Credential level: %d\n"),
			    *credLevel[counter]);
		if (*credLevel[counter] == NS_LDAP_CRED_SELF) {
			credSelf = 1;
			break;
		}
	}

	authSASLgss = 0;	/* flag for authMethod of SASL/gssapi */
	for (counter = 0;
	    authMethod && authMethod[counter] != NULL;
	    counter++) {

		if (mode_verbose)
			CLIENT_FPRINTF(stderr,
			    gettext("Authentication sasl mechanism: %d\n"),
			    authMethod[counter]->saslmech);
		if (authMethod[counter]->saslmech == NS_LDAP_SASL_GSSAPI) {
			authSASLgss = 1;
			break;
		}
	}

	/* First, if we don't need adminDN/adminPassword then just return ok */
	if (credSelf && authSASLgss) {
		if (mode_verbose)
			CLIENT_FPUTS(
			    gettext("A credential Level of self and an "
			    "authentication method of sasl/GSSAPI is "
			    "configured, no adminDN/adminPassword "
			    "is required.\n"), stderr);
		rc = CLIENT_SUCCESS;
		goto out;
	}

	/* Now let's check if we have the cred stuff we need */
	if (adminDN == NULL || adminDN[0] == '\0') {
		CLIENT_FPUTS(
		    gettext("Shadow Update is enabled, but "
		    "no adminDN is configured.\n"), stderr);
		rc = CLIENT_ERR_CREDENTIAL;
		goto out;
	}

	/* If we need adminPassword (prompt) */
	if (adminPassword == NULL || adminPassword[0] == '\0') {
		CLIENT_FPUTS(
		    gettext("Shadow Update requires adminPassword\n"),
		    stderr);
		arglist->adminPassword = getpassphrase("admin Password:");
		if (arglist->adminPassword == NULL) {
			CLIENT_FPUTS(gettext("Unable to get admin password\n"),
			    stderr);
			rc = CLIENT_ERR_CREDENTIAL;
			goto out;
		}
		LDAP_SET_PARAM(arglist->adminPassword,
		    NS_LDAP_ADMIN_BINDPASSWD_P);
		if (retcode != 0) {
			CLIENT_FPUTS(
			    gettext("setParam adminPassword failed.\n"),
			    stderr);
			rc = CLIENT_ERR_CREDENTIAL;
			goto out;
		}
	}

	rc = CLIENT_SUCCESS;

	out:
	if (enabled != NULL)
		(void) __ns_ldap_freeParam((void ***)&enabled);
	if (credLevel != NULL)
		(void) __ns_ldap_freeParam((void ***)&credLevel);
	if (authMethod != NULL)
		(void) __ns_ldap_freeParam((void ***)&authMethod);
	if (adminDN != NULL)
		(void) __ns_ldap_freeParam((void ***)&adminDN);
	if (adminPassword != NULL)
		(void) __ns_ldap_freeParam((void ***)&adminPassword);

	return (rc);
}

/*
 * try to restore the previous name space on this machine
 */
static int
recover(int saveState)
{
	struct stat buf;
	int stat_ret, retcode, fd;
	int domain = 0, domainlen;
	char yp_dir[BUFSIZE], yp_dir_back[BUFSIZE];
	char name[BUFSIZ];
	char *ldap_conf_file, *ldap_cred_file;
	char ldap_file_back[BUFSIZE], ldap_cred_back[BUFSIZE];

	/* If running as Sysid Install become a no-op */
	if (sysid_install == B_TRUE)
		return (CLIENT_SUCCESS);

	stat_ret = stat(LDAP_RESTORE_DIR, &buf);
	if (stat_ret != 0) {
		CLIENT_FPUTS(
		    gettext("Cannot recover.  No backup files "
		    "found.\n"),
		    stderr);
		CLIENT_FPUTS(
		    gettext("\t Either this machine was not initialized\n"),
		    stderr);
		CLIENT_FPUTS(
		    gettext("\t by ldapclient or the backup files "
		    "have been\n"),
		    stderr);
		CLIENT_FPUTS(
		    gettext("\t removed manually or with an \"uninit\"\n"),
		    stderr);
		return (CLIENT_ERR_RESTORE);	/* invalid backup */
	}

	/*
	 * Get domainname.  Allow no domainname for the case where "files"
	 * config was backed up.
	 */
	stat_ret = stat(DOMAINNAME_BACK, &buf);
	if (mode_verbose)
		CLIENT_FPRINTF(stderr,
		    gettext("recover: stat(%s)=%d\n"),
		    DOMAINNAME_BACK, stat_ret);
	if (stat_ret == 0) {
		if (mode_verbose)
			CLIENT_FPRINTF(stderr,
			    gettext("recover: open(%s)\n"),
			    DOMAINNAME_BACK);
		fd = open(DOMAINNAME_BACK, O_RDONLY);
		if (mode_verbose)
			CLIENT_FPRINTF(stderr,
			    gettext("recover: read(%s)\n"),
			    DOMAINNAME_BACK);
		domainlen = read(fd, &(name[0]), BUFSIZ-1);
		(void) close(fd);
		if (domainlen < 0) {
			CLIENT_FPUTS(
			    gettext("Cannot recover.  Cannot determine "
			    "previous domain name.\n"),
			    stderr);
			return (CLIENT_ERR_RESTORE);	/* invalid backup */
		} else 	{
			char *ptr;

			ptr = strchr(&(name[0]), '\n');
			if (ptr != NULL)
				*ptr = '\0';
			else
				name[domainlen] = '\0';

			if (mode_verbose)
				CLIENT_FPRINTF(stderr,
				    gettext("recover: old domainname "
				    "\"%s\"\n"), name);

			if (strlen(name) == 0)
				domain = 0;
			else
				domain = 1;	/* flag that we have domain */

		}
	}


	/*
	 * we can recover at this point
	 * remove LDAP config files before restore
	 */
	(void) unlink(NSCONFIGFILE);
	(void) unlink(NSCREDFILE);

	ldap_conf_file = strrchr(NSCONFIGFILE, '/') + 1;
	ldap_cred_file = strrchr(NSCREDFILE, '/') + 1;

	(void) strlcpy(ldap_file_back, LDAP_RESTORE_DIR "/", BUFSIZE);
	(void) strlcat(ldap_file_back, ldap_conf_file, BUFSIZE);

	stat_ret = stat(ldap_file_back, &buf);
	if (mode_verbose)
		CLIENT_FPRINTF(stderr,
		    gettext("recover: stat(%s)=%d\n"),
		    ldap_file_back, stat_ret);
	if (stat_ret == 0) {
		if (saveState)
			gStartLdap = START_UNINIT;
		retcode = file_move(ldap_file_back, NSCONFIGFILE);
		if (mode_verbose)
			CLIENT_FPRINTF(stderr,
			    gettext("recover: file_move(%s, %s)=%d\n"),
			    ldap_file_back, NSCONFIGFILE, retcode);
		if (retcode != 0)
			CLIENT_FPRINTF(stderr,
			    gettext("recover: file_move(%s, %s) failed\n"),
			    ldap_file_back, NSCONFIGFILE);
	}

	(void) strlcpy(ldap_cred_back, LDAP_RESTORE_DIR "/", BUFSIZE);
	(void) strlcat(ldap_cred_back, ldap_cred_file, BUFSIZE);

	stat_ret = stat(ldap_cred_back, &buf);
	if (mode_verbose)
		CLIENT_FPRINTF(stderr,
		    gettext("recover: stat(%s)=%d\n"),
		    ldap_cred_back, stat_ret);
	if (stat_ret == 0) {
		retcode = file_move(ldap_cred_back, NSCREDFILE);
		if (mode_verbose)
			CLIENT_FPRINTF(stderr,
			    gettext("recover: file_move(%s, %s)=%d\n"),
			    ldap_cred_back, NSCREDFILE, retcode);
		if (retcode != 0)
			CLIENT_FPRINTF(stderr,
			    gettext("recover: file_move(%s, %s) failed\n"),
			    ldap_cred_back, NSCREDFILE);
	}

	/* Check for recovery of NIS(YP) if we have a domainname */
	if (domain) {
		/* "name" would have to be huge for this, but just in case */
		if (strlen(name) >= (BUFSIZE - strlen(LDAP_RESTORE_DIR)))
			return (CLIENT_ERR_FAIL);
		if (strlen(name) >= (BUFSIZE - strlen(YP_BIND_DIR)))
			return (CLIENT_ERR_FAIL);

		(void) strlcpy(yp_dir_back, LDAP_RESTORE_DIR "/", BUFSIZE);
		(void) strlcat(yp_dir_back, name, BUFSIZE);
		stat_ret = stat(yp_dir_back, &buf);
		if (mode_verbose)
			CLIENT_FPRINTF(stderr,
			    gettext("recover: stat(%s)=%d\n"),
			    yp_dir_back, stat_ret);
		if (stat_ret == 0) {
			(void) strlcpy(yp_dir, YP_BIND_DIR "/", BUFSIZE);
			(void) strlcat(yp_dir, name, BUFSIZE);
			retcode = file_move(yp_dir_back, yp_dir);
			if (mode_verbose)
				CLIENT_FPRINTF(stderr,
				    gettext("recover: file_move(%s, "
				    "%s)=%d\n"),
				    yp_dir_back, yp_dir, retcode);
			if (retcode != 0) {
				CLIENT_FPRINTF(stderr,
				    gettext("recover: file_move(%s, "
				    "%s) failed!\n"),
				    yp_dir_back, yp_dir);
			} else {
				if (saveState)
					gStartYp = START_UNINIT;
			}
		}
	}

	/* restore machine configuration */
	stat_ret = stat(NSSWITCH_BACK, &buf);
	if (mode_verbose)
		CLIENT_FPRINTF(stderr,
		    gettext("recover: stat(%s)=%d\n"),
		    NSSWITCH_BACK, stat_ret);
	if (stat_ret == 0) {
		retcode = file_move(NSSWITCH_BACK, NSSWITCH_CONF);
		if (mode_verbose)
			CLIENT_FPRINTF(stderr,
			    gettext("recover: file_move(%s, %s)=%d\n"),
			    NSSWITCH_BACK, NSSWITCH_CONF, retcode);
		if (retcode != 0)
			CLIENT_FPRINTF(stderr,
			    gettext("recover: file_move(%s, %s) failed\n"),
			    NSSWITCH_BACK, NSSWITCH_CONF);
	}

	stat_ret = stat(DOMAINNAME_BACK, &buf);
	if (mode_verbose)
		CLIENT_FPRINTF(stderr,
		    gettext("recover: stat(%s)=%d\n"),
		    DOMAINNAME_BACK, stat_ret);
	if (stat_ret == 0) {
		retcode = file_move(DOMAINNAME_BACK, DOMAINNAME);
		if (mode_verbose)
			CLIENT_FPRINTF(stderr,
			    gettext("recover: file_move(%s, %s)=%d\n"),
			    DOMAINNAME_BACK, DOMAINNAME, retcode);
		if (retcode != 0)
			CLIENT_FPRINTF(stderr,
			    gettext("recover: file_move(%s, %s) failed\n"),
			    DOMAINNAME_BACK, DOMAINNAME);
	}

	retcode = rmdir(LDAP_RESTORE_DIR);
	if (retcode != 0) {
		CLIENT_FPRINTF(stderr,
		    gettext("Error removing \"%s\" directory.\n"),
		    LDAP_RESTORE_DIR);
	}

	return (CLIENT_SUCCESS);
}

/*
 * try to save the current state of this machine.
 * this just overwrites any old saved configration files.
 *
 * This function should only be called after network services have been stopped.
 *
 * Returns 0 on successful save
 * Otherwise returns -1
 */
static int
file_backup(void)
{
	struct stat buf;
	int domain_stat, conf_stat, ldap_stat;
	int yp_stat, restore_stat;
	int retcode, namelen, ret;
	char yp_dir[BUFSIZ], yp_dir_back[BUFSIZ];
	char name[BUFSIZ];
	char *ldap_conf_file, *ldap_cred_file;
	char ldap_file_back[BUFSIZE], ldap_cred_back[BUFSIZE];

	ret = CLIENT_SUCCESS;
	/* If running as Sysid Install become a no-op */
	if (sysid_install == B_TRUE)
		return (CLIENT_SUCCESS);

	/* If existing backup files, clear for this run */
	restore_stat = stat(LDAP_RESTORE_DIR, &buf);
	if (restore_stat == 0) {
		if (mode_verbose) {
			CLIENT_FPUTS(
			    gettext("Removing existing restore "
			    "directory\n"),
			    stderr);
		}
		(void) system("/bin/rm -fr " LDAP_RESTORE_DIR);
		restore_stat = stat(LDAP_RESTORE_DIR, &buf);
		if (restore_stat == 0) {
			CLIENT_FPRINTF(stderr,
			    gettext("Unable to remove backup "
			    "directory (%s)\n"),
			    LDAP_RESTORE_DIR);
			return (CLIENT_ERR_RESTORE);
		}
	}

	retcode = mkdir(LDAP_RESTORE_DIR, 0755);
	if (retcode != 0) {
		CLIENT_FPRINTF(stderr,
		    gettext("file_backup: Failed to make %s backup "
		    "directory. mkdir=%d\n"),
		    LDAP_RESTORE_DIR, retcode);
		return (CLIENT_ERR_FAIL);
	}

	conf_stat = stat(NSSWITCH_CONF, &buf);
	if (mode_verbose)
		CLIENT_FPRINTF(stderr,
		    gettext("file_backup: stat(%s)=%d\n"),
		    NSSWITCH_CONF, conf_stat);
	if (conf_stat == 0) {
		if (mode_verbose)
			CLIENT_FPRINTF(stderr,
			    gettext("file_backup: (%s -> %s)\n"),
			    NSSWITCH_CONF, NSSWITCH_BACK);
		retcode = file_move(NSSWITCH_CONF, NSSWITCH_BACK);
		if (retcode != 0) {
			CLIENT_FPRINTF(stderr,
			    gettext("file_backup: file_move(%s, %s) failed "
			    "with %d\n"),
			    NSSWITCH_CONF, NSSWITCH_BACK, retcode);
			ret = CLIENT_ERR_RENAME;
		}
	} else {
		if (mode_verbose)
			CLIENT_FPRINTF(stderr,
			    gettext("file_backup: No %s file.\n"),
			    NSSWITCH_CONF);
	}

	domain_stat = stat(DOMAINNAME, &buf);
	if (mode_verbose)
		CLIENT_FPRINTF(stderr,
		    gettext("file_backup: stat(%s)=%d\n"),
		    DOMAINNAME, domain_stat);
	if ((domain_stat == 0) && (buf.st_size > 0)) {
		if (mode_verbose)
			CLIENT_FPRINTF(stderr,
			    gettext("file_backup: (%s -> %s)\n"),
			    DOMAINNAME, DOMAINNAME_BACK);
		retcode = file_move(DOMAINNAME, DOMAINNAME_BACK);
		if (retcode != 0) {
			CLIENT_FPRINTF(stderr,
			    gettext("file_backup: file_move(%s, %s) failed "
			    "with %d\n"),
			    DOMAINNAME, DOMAINNAME_BACK, retcode);
			ret = CLIENT_ERR_RENAME;
		}
	} else {
		if (mode_verbose)
			if (domain_stat != 0) {
				CLIENT_FPRINTF(stderr,
				    gettext("file_backup: No %s file.\n"),
				    DOMAINNAME);
			} else {
				CLIENT_FPRINTF(stderr,
				    gettext("file_backup: Empty %s "
				    "file.\n"),
				    DOMAINNAME);
			}
	}

	namelen = BUFSIZ;
	(void) sysinfo(SI_SRPC_DOMAIN, &(name[0]), namelen);
	namelen = strlen(name);

	if (mode_verbose)
		CLIENT_FPRINTF(stderr,
		    gettext("file_backup: nis domain is \"%s\"\n"),
		    (namelen > 0) ? name : "EMPTY");
	/* check for domain name if not set cannot save NIS(YP) state */
	if (namelen > 0) {
		/* moving /var/yp/binding will cause ypbind to core dump */
		(void) strlcpy(yp_dir, YP_BIND_DIR "/", BUFSIZE);
		(void) strlcat(yp_dir, name, BUFSIZE);
		yp_stat = stat(yp_dir, &buf);
		if (mode_verbose)
			CLIENT_FPRINTF(stderr,
			    gettext("file_backup: stat(%s)=%d\n"),
			    yp_dir, yp_stat);
		if (yp_stat == 0) {
			(void) strlcpy(yp_dir_back, LDAP_RESTORE_DIR "/",
			    BUFSIZE);
			(void) strlcat(yp_dir_back, name, BUFSIZE);
			if (mode_verbose)
				CLIENT_FPRINTF(stderr,
				    gettext("file_backup: (%s -> %s)\n"),
				    yp_dir, yp_dir_back);
			retcode = file_move(yp_dir, yp_dir_back);
			if (retcode != 0) {
				CLIENT_FPRINTF(stderr,
				    gettext("file_backup: file_move(%s, %s)"
				    " failed with %d\n"),
				    yp_dir, yp_dir_back, retcode);
				ret = CLIENT_ERR_RENAME;
			}
		} else {
			if (mode_verbose)
				CLIENT_FPRINTF(stderr,
				    gettext("file_backup: No %s "
				    "directory.\n"), yp_dir);
		}
	}


	/* point to file name, not path delim (/) */
	ldap_conf_file = strrchr(NSCONFIGFILE, '/') + 1;
	ldap_cred_file = strrchr(NSCREDFILE, '/') + 1;

	ldap_stat = stat(NSCONFIGFILE, &buf);
	if (mode_verbose)
		CLIENT_FPRINTF(stderr,
		    gettext("file_backup: stat(%s)=%d\n"),
		    NSCONFIGFILE, ldap_stat);
	if (ldap_stat == 0) {
		(void) strlcpy(ldap_file_back, LDAP_RESTORE_DIR "/", BUFSIZE);
		(void) strlcat(ldap_file_back, ldap_conf_file, BUFSIZE);
		if (mode_verbose)
			CLIENT_FPRINTF(stderr,
			    gettext("file_backup: (%s -> %s)\n"),
			    NSCONFIGFILE, ldap_file_back);
		retcode = file_move(NSCONFIGFILE, ldap_file_back);
		if (retcode != 0) {
			CLIENT_FPRINTF(stderr,
			    gettext("file_backup: file_move(%s, %s) failed "
			    "with %d\n"),
			    NSCONFIGFILE, ldap_file_back, retcode);
			ret = CLIENT_ERR_RENAME;
		}

		(void) strlcpy(ldap_cred_back, LDAP_RESTORE_DIR "/", BUFSIZE);
		(void) strlcat(ldap_cred_back, ldap_cred_file, BUFSIZE);
		if (mode_verbose)
			CLIENT_FPRINTF(stderr,
			    gettext("file_backup: (%s -> %s)\n"),
			    NSCREDFILE, ldap_cred_back);
		retcode = file_move(NSCREDFILE, ldap_cred_back);
		if (retcode != 0) {
			CLIENT_FPRINTF(stderr,
			    gettext("file_backup: file_move(%s, %s) failed "
			    "with %d\n"),
			    NSCREDFILE, ldap_cred_back, retcode);
			ret = CLIENT_ERR_RENAME;
		}
	} else {
		if (mode_verbose)
			CLIENT_FPRINTF(stderr,
			    gettext("file_backup: No %s file.\n"),
			    NSCONFIGFILE);
	}

	return (ret);
}

/*
 * mod_backup()
 *
 * This function is used to temporily backup the LDAP client files in /var/ldap
 * that the "mod" operation needs to update.  If an error occurs then the
 * function mod_recover() can be invoke to recover the unmodified files.
 */
static int
mod_backup(void)
{
	int rc;
	int retcode = CLIENT_SUCCESS;

	rc = system(CMD_CP " " NSCONFIGFILE " " NSCONFIGFILE ".mod");
	retcode += rc;
	if (mode_verbose)
		CLIENT_FPRINTF(stderr,
		    gettext("mod_backup: backup %s for %s\n"),
		    rc ? "failed" : "successful", NSCONFIGFILE);

	rc = system(CMD_CP " " NSCREDFILE " " NSCREDFILE ".mod");
	retcode += rc;
	if (mode_verbose)
		CLIENT_FPRINTF(stderr,
		    gettext("mod_backup: backup %s for %s\n"),
		    rc ? "failed" : "successful", NSCREDFILE);

	rc = system(CMD_CP " " DOMAINNAME " " DOMAINNAME ".mod");
	retcode += rc;
	if (mode_verbose)
		CLIENT_FPRINTF(stderr,
		    gettext("mod_backup: backup %s for %s\n"),
		    rc ? "failed" : "successful", DOMAINNAME);

	if (retcode != CLIENT_SUCCESS)
		retcode = CLIENT_ERR_RENAME;
	return (retcode);
}

/*
 * mod_recover()
 *
 * This function is used to recover the temporily backed up files by
 * the mod_backup() function if an error occurs during the "mod"
 * operation.
 */
static int
mod_recover(void)
{
	int rc;
	int retcode = CLIENT_SUCCESS;

	rc = system(CMD_MV " " NSCONFIGFILE ".mod " NSCONFIGFILE);
	retcode += rc;
	if (mode_verbose)
		CLIENT_FPRINTF(stderr,
		    gettext("mod_recover: recovery %s for %s\n"),
		    rc ? "failed" : "successful", NSCONFIGFILE);

	rc = system(CMD_MV " " NSCREDFILE ".mod " NSCREDFILE);
	retcode += rc;
	if (mode_verbose)
		CLIENT_FPRINTF(stderr,
		    gettext("mod_recover: recovery %s for %s\n"),
		    rc ? "failed" : "successful", NSCREDFILE);

	rc = system(CMD_MV " " DOMAINNAME ".mod " DOMAINNAME);
	retcode += rc;
	if (mode_verbose)
		CLIENT_FPRINTF(stderr,
		    gettext("mod_recover: recovery %s for %s\n"),
		    rc ? "failed" : "successful", DOMAINNAME);

	if (retcode != CLIENT_SUCCESS)
		retcode = CLIENT_ERR_RENAME;
	return (retcode);
}

/*
 * mod_cleanup()
 *
 * This function removes the .mod files in /var/ldap.
 */
static void
mod_cleanup(void)
{
	(void) system(CMD_RM " " NSCONFIGFILE ".mod " TO_DEV_NULL);
	(void) system(CMD_RM " " NSCREDFILE ".mod " TO_DEV_NULL);
	(void) system(CMD_RM " " DOMAINNAME ".mod " TO_DEV_NULL);
}

#define	MAX_DN_ARRAY 100
#define	LDAP_NAMINGCONTEXTS	"namingcontexts"

static multival_t *
multival_new()
{
	multival_t *hold;

	hold = calloc(1, sizeof (multival_t));
	if (hold == NULL) {
		CLIENT_FPUTS(
		    gettext("multival_new: Memory allocation error\n"),
		    stderr);
	}
	return (hold);	/* NULL -> error */
}

static int
multival_add(multival_t *list, char *opt)
{
	if (opt == NULL) {
		CLIENT_FPUTS(
		    gettext("Empty value passed to multival_add\n"),
		    stderr);
		return (CLIENT_ERR_FAIL);
	}

	if (list->count == 0) {
		list->optlist = (char **)malloc(sizeof (char **));
	} else {
		list->optlist = (char **)realloc(list->optlist,
		    (list->count + 1) * sizeof (char **));
	}

	if (list->optlist == NULL) {
		CLIENT_FPUTS(gettext("Error allocating memory\n"), stderr);
		return (CLIENT_ERR_MEMORY);	/* 0 is success */
	}

	list->optlist[list->count] = opt;
	list->count++;

	return (CLIENT_SUCCESS);
}

static void
multival_free(multival_t *list)
{
	if (list == NULL)
		return;

	if (list->optlist != NULL)
		free(list->optlist);
	free(list);
}

static clientopts_t *
clientopts_new()
{
	clientopts_t *hold;

	hold = calloc(1, sizeof (clientopts_t));
	if (NULL == hold) {
		CLIENT_FPUTS(gettext("Error allocating memory for "
		    "clientopts structure\n"), stderr);
		return (hold);	/* NULL -> error */
	}

	hold->serviceAuthenticationMethod = multival_new();
	if (NULL == hold->serviceAuthenticationMethod) {
		CLIENT_FPUTS(gettext("Error allocating memory for "
		    "serviceAuthenticationMethod\n"), stderr);
		free(hold);
		return (NULL);	/* NULL -> error */
	}

	hold->serviceCredentialLevel = multival_new();
	if (NULL == hold->serviceCredentialLevel) {
		CLIENT_FPUTS(gettext("Error allocating memory for "
		    "serviceCredentialLevel\n"), stderr);
		multival_free(hold->serviceAuthenticationMethod);
		free(hold);
		return (NULL);	/* NULL -> error */
	}

	hold->objectclassMap = multival_new();
	if (NULL == hold->objectclassMap) {
		CLIENT_FPUTS(gettext("Error allocating memory for "
		    "objectclassMap\n"), stderr);
		multival_free(hold->serviceAuthenticationMethod);
		multival_free(hold->serviceCredentialLevel);
		free(hold);
		return (NULL);	/* NULL -> error */
	}

	hold->attributeMap = multival_new();
	if (NULL == hold->attributeMap) {
		CLIENT_FPUTS(gettext("Error allocating memory for "
		    "attributeMap\n"), stderr);
		multival_free(hold->serviceAuthenticationMethod);
		multival_free(hold->serviceCredentialLevel);
		multival_free(hold->objectclassMap);
		free(hold);
		return (NULL);	/* NULL -> error */
	}

	hold->serviceSearchDescriptor = multival_new();
	if (NULL == hold->serviceSearchDescriptor) {
		CLIENT_FPUTS(gettext("Error allocating memory for "
		    "serviceSearchDescriptor\n"), stderr);
		multival_free(hold->serviceAuthenticationMethod);
		multival_free(hold->serviceCredentialLevel);
		multival_free(hold->objectclassMap);
		multival_free(hold->attributeMap);
		free(hold);
		return (NULL);	/* NULL -> error */
	}

	return (hold);
}

static void
clientopts_free(clientopts_t *list)
{
	if (NULL == list)
		return;

	multival_free(list->serviceAuthenticationMethod);
	multival_free(list->serviceCredentialLevel);
	multival_free(list->objectclassMap);
	multival_free(list->attributeMap);
	multival_free(list->serviceSearchDescriptor);

	free(list);

}

static void
multival_list(char *opt, multival_t *list)
{
	int i;

	if (list->count == 0)
		return;

	(void) puts(opt);
	for (i = 0; i < list->count; i++) {
		(void) printf("\t\targ[%d]: %s\n", i, list->optlist[i]);
	}
}

/* return the number of arguments specified in the command line */
static int
num_args(clientopts_t *list)
{
	int arg_count = 0;

	arg_count += list->authenticationMethod ? 1 : 0;
	arg_count += list->serviceAuthenticationMethod->count;
	arg_count += list->defaultSearchBase ? 1 : 0;
	arg_count += list->credentialLevel ? 1 : 0;
	arg_count += list->serviceCredentialLevel->count;
	arg_count += list->domainName ? 1 : 0;
	arg_count += list->proxyDN ? 1 : 0;
	arg_count += list->enableShadowUpdate ? 1 : 0;
	arg_count += list->adminDN ? 1 : 0;
	arg_count += list->profileTTL ? 1 : 0;
	arg_count += list->objectclassMap->count;
	arg_count += list->searchTimeLimit ? 1 : 0;
	arg_count += list->preferredServerList ? 1 : 0;
	arg_count += list->profileName ? 1 : 0;
	arg_count += list->followReferrals ? 1 : 0;
	arg_count += list->attributeMap->count;
	arg_count += list->defaultSearchScope ? 1 : 0;
	arg_count += list->serviceSearchDescriptor->count;
	arg_count += list->bindTimeLimit ? 1 : 0;
	arg_count += list->proxyPassword ? 1 : 0;
	arg_count += list->adminPassword ? 1 : 0;
	arg_count += list->defaultServerList ? 1 : 0;
	arg_count += list->certificatePath ? 1 : 0;

	return (arg_count);
}

#define	CLIENT_PRINT(opt, str) if (str) \
		(void) printf("%s%s\n", (opt), (str))

static void
dumpargs(clientopts_t *list)
{
	CLIENT_PRINT("\tauthenticationMethod: ", list->authenticationMethod);
	multival_list("\tserviceAuthenticationMethod: ",
	    list->serviceAuthenticationMethod);
	CLIENT_PRINT("\tdefaultSearchBase: ", list->defaultSearchBase);
	CLIENT_PRINT("\tcredentialLevel: ", list->credentialLevel);
	multival_list("\tserviceCredentialLevel: ",
	    list->serviceCredentialLevel);
	CLIENT_PRINT("\tdomainName: ", list->domainName);
	CLIENT_PRINT("\tproxyDN: ", list->proxyDN);
	CLIENT_PRINT("\tadminDN: ", list->adminDN);
	CLIENT_PRINT("\tenableShadowUpdate: ", list->enableShadowUpdate);
	CLIENT_PRINT("\tprofileTTL: ", list->profileTTL);
	multival_list("\tobjectclassMap: ", list->objectclassMap);
	CLIENT_PRINT("\tsearchTimeLimit: ", list->searchTimeLimit);
	CLIENT_PRINT("\tpreferredServerList: ", list->preferredServerList);
	CLIENT_PRINT("\tprofileName: ", list->profileName);
	CLIENT_PRINT("\tfollowReferrals: ", list->followReferrals);
	multival_list("\tattributeMap: ", list->attributeMap);
	CLIENT_PRINT("\tdefaultSearchScope: ", list->defaultSearchScope);
	multival_list("\tserviceSearchDescriptor: ",
	    list->serviceSearchDescriptor);
	CLIENT_PRINT("\tbindTimeLimit: ", list->bindTimeLimit);
	CLIENT_PRINT("\tproxyPassword: ", list->proxyPassword);
	CLIENT_PRINT("\tadminPassword: ", list->adminPassword);
	CLIENT_PRINT("\tdefaultServerList: ", list->defaultServerList);
	CLIENT_PRINT("\tcertificatePath: ", list->certificatePath);
}


/* These definitions are only used in parseParam() below. */
struct param {
	char	*name;
	int	index;
};

static struct param paramArray[] = {
	{"proxyDN", NS_LDAP_BINDDN_P},
	{"proxyPassword", NS_LDAP_BINDPASSWD_P},
	{"defaultServerList", NS_LDAP_SERVERS_P},
	{"defaultSearchBase", NS_LDAP_SEARCH_BASEDN_P},
	{"authenticationMethod", NS_LDAP_AUTH_P},
	{"followReferrals", NS_LDAP_SEARCH_REF_P},
	{"profileTTL", NS_LDAP_CACHETTL_P},
	{"certificatePath", NS_LDAP_HOST_CERTPATH_P},
	{"defaultSearchScope", NS_LDAP_SEARCH_SCOPE_P},
	{"bindTimeLimit", NS_LDAP_BIND_TIME_P},
	{"searchTimeLimit", NS_LDAP_SEARCH_TIME_P},
	{"preferredServerList", NS_LDAP_SERVER_PREF_P},
	{"profileName", NS_LDAP_PROFILE_P},
	{"credentialLevel", NS_LDAP_CREDENTIAL_LEVEL_P},
	{"serviceSearchDescriptor", NS_LDAP_SERVICE_SEARCH_DESC_P},
	{"attributeMap", NS_LDAP_ATTRIBUTEMAP_P},
	{"objectclassMap", NS_LDAP_OBJECTCLASSMAP_P},
	{"serviceAuthenticationMethod", NS_LDAP_SERVICE_AUTH_METHOD_P},
	{"serviceCredentialLevel", NS_LDAP_SERVICE_CRED_LEVEL_P},
	{"domainName", LOCAL_DOMAIN_P},
	{"enableShadowUpdate", NS_LDAP_ENABLE_SHADOW_UPDATE_P},
	{"adminDN", NS_LDAP_ADMIN_BINDDN_P},
	{"adminPassword", NS_LDAP_ADMIN_BINDPASSWD_P},
	{NULL, 0}
};

static int
parseParam(char *param, char **paramVal)
{
	char *val = NULL;
	int counter;

	if (mode_verbose) {
		CLIENT_FPRINTF(stderr, gettext("Parsing %s\n"), param);
	}

	val = strchr(param, '=');
	if (val == NULL) {
		CLIENT_FPUTS(
		    gettext("Didn\'t find \'=\' character in string\n"),
		    stderr);
		paramVal = NULL;
		return (CLIENT_ERR_PARSE);
	}

	*val = '\0';

	for (counter = 0; paramArray[counter].name != NULL; counter++) {
		if (strcasecmp(paramArray[counter].name, param) == 0) {
			*paramVal = val+1;
			*val = '=';	/* restore original param */
			return (paramArray[counter].index);
		}
	}

	/* Not found */
	*val = '=';	/* restore original param */
	*paramVal = NULL;
	return (CLIENT_ERR_PARSE);
}

/*
 * The following macro checks if an option has already been specified
 * and errs out with usage if so
 */
#define	CLIENT_OPT_CHECK(opt, optarg)	\
if (optarg) {			\
	CLIENT_FPUTS(gettext("Invalid use of option\n"), stderr);	\
	usage();		\
	clientopts_free(optlist); \
	return (CLIENT_ERR_FAIL);		\
}

static int
clientSetParam(clientopts_t *optlist, int paramFlag, char *attrVal)
{
	int retcode = 0;
	int counter;


	switch (paramFlag) {
	case NS_LDAP_AUTH_P:
		CLIENT_OPT_CHECK(paramFlag, optlist->authenticationMethod);
		optlist->authenticationMethod = attrVal;
		break;

	case NS_LDAP_SERVICE_AUTH_METHOD_P:	/* multiple allowed */
		retcode = multival_add(optlist->serviceAuthenticationMethod,
		    attrVal);
		if (retcode != CLIENT_SUCCESS) {
			CLIENT_FPRINTF(stderr,
			    gettext("Error processing attrVal %s\n"),
			    attrVal?attrVal:"NULL");
			usage();
			clientopts_free(optlist);
			return (CLIENT_ERR_FAIL);
		}
		break;

	case NS_LDAP_SEARCH_BASEDN_P:
		CLIENT_OPT_CHECK(paramFlag, optlist->defaultSearchBase);
		optlist->defaultSearchBase = attrVal;
		break;

	case NS_LDAP_CREDENTIAL_LEVEL_P:
		CLIENT_OPT_CHECK(paramFlag, optlist->credentialLevel);
		optlist->credentialLevel = attrVal;
		break;

	case NS_LDAP_SERVICE_CRED_LEVEL_P:	/* multiple allowed */
		retcode = multival_add(optlist->serviceCredentialLevel,
		    attrVal);
		if (retcode != CLIENT_SUCCESS) {
			CLIENT_FPRINTF(stderr,
			    gettext("Error processing attrVal %s\n"),
			    attrVal?attrVal:"NULL");
			usage();
			clientopts_free(optlist);
			return (CLIENT_ERR_FAIL);
		}
		break;

	case LOCAL_DOMAIN_P:
		CLIENT_OPT_CHECK(paramFlag, optlist->domainName);
		optlist->domainName = attrVal;
		dname = optlist->domainName;
		break;

	case NS_LDAP_BINDDN_P:
		CLIENT_OPT_CHECK(paramFlag, optlist->proxyDN);
		optlist->proxyDN = attrVal;
		break;

	case NS_LDAP_ENABLE_SHADOW_UPDATE_P:
		CLIENT_OPT_CHECK(paramFlag, optlist->enableShadowUpdate);
		optlist->enableShadowUpdate = attrVal;
		break;

	case NS_LDAP_ADMIN_BINDDN_P:
		CLIENT_OPT_CHECK(paramFlag, optlist->adminDN);
		optlist->adminDN = attrVal;
		break;

	case NS_LDAP_CACHETTL_P:
		CLIENT_OPT_CHECK(paramFlag, optlist->profileTTL);
		optlist->profileTTL = attrVal;
		break;

	case NS_LDAP_OBJECTCLASSMAP_P:	/* multiple allowed */
		retcode = multival_add(optlist->objectclassMap, attrVal);
		if (retcode != CLIENT_SUCCESS) {
			CLIENT_FPRINTF(stderr,
			    gettext("Error processing attrVal %s\n"),
			    attrVal?attrVal:"NULL");
			usage();
			clientopts_free(optlist);
			return (CLIENT_ERR_FAIL);
		}
		break;

	case NS_LDAP_SEARCH_TIME_P:
		CLIENT_OPT_CHECK(paramFlag, optlist->searchTimeLimit);
		optlist->searchTimeLimit = attrVal;
		break;

	case NS_LDAP_SERVER_PREF_P:
		CLIENT_OPT_CHECK(paramFlag, optlist->preferredServerList);
		optlist->preferredServerList = attrVal;
		/* replace ',' chars with ' ' for proper syntax */
		for (counter = 0;
		    counter < strlen(optlist->preferredServerList);
		    counter++) {

			if (optlist->preferredServerList[counter] == ',')
				optlist->preferredServerList[counter] = ' ';
		}
		break;

	case NS_LDAP_PROFILE_P:
		CLIENT_OPT_CHECK(paramFlag, optlist->profileName);
		optlist->profileName = attrVal;
		break;

	case NS_LDAP_SEARCH_REF_P:
		CLIENT_OPT_CHECK(paramFlag, optlist->followReferrals);
		if (0 == strcasecmp(attrVal, "followref"))
			optlist->followReferrals = "TRUE";
		else if (0 == strcasecmp(attrVal, "noref"))
			optlist->followReferrals = "FALSE";
		else
			optlist->followReferrals = attrVal;
		break;

	case NS_LDAP_ATTRIBUTEMAP_P:	/* multiple allowed */
		retcode = multival_add(optlist->attributeMap, attrVal);
		if (retcode != CLIENT_SUCCESS) {
			CLIENT_FPRINTF(stderr,
			    gettext("Error processing attrVal %s\n"),
			    attrVal?attrVal:"NULL");
			usage();
			clientopts_free(optlist);
			return (CLIENT_ERR_FAIL);
		}
		break;

	case NS_LDAP_SEARCH_SCOPE_P:
		CLIENT_OPT_CHECK(paramFlag, optlist->defaultSearchScope);
		optlist->defaultSearchScope = attrVal;
		break;

	case NS_LDAP_SERVICE_SEARCH_DESC_P:	/* multiple allowed */
		retcode = multival_add(optlist->serviceSearchDescriptor,
		    attrVal);
		if (retcode != CLIENT_SUCCESS) {
			CLIENT_FPRINTF(stderr,
			    gettext("Error processing attrVal %s\n"),
			    attrVal?attrVal:"NULL");
			usage();
			clientopts_free(optlist);
			return (CLIENT_ERR_FAIL);
		}
		break;

	case NS_LDAP_BIND_TIME_P:
		CLIENT_OPT_CHECK(paramFlag, optlist->bindTimeLimit);
		optlist->bindTimeLimit = attrVal;
		break;

	case NS_LDAP_BINDPASSWD_P:
		CLIENT_OPT_CHECK(paramFlag, optlist->proxyPassword);
		optlist->proxyPassword = attrVal;
		break;

	case NS_LDAP_ADMIN_BINDPASSWD_P:
		CLIENT_OPT_CHECK(paramFlag, optlist->adminPassword);
		optlist->adminPassword = attrVal;
		break;

	case NS_LDAP_HOST_CERTPATH_P:
		CLIENT_OPT_CHECK(paramFlag, optlist->certificatePath);
		optlist->certificatePath = attrVal;
		break;

	case NS_LDAP_SERVERS_P:
		CLIENT_OPT_CHECK(paramFlag, optlist->defaultServerList);
		optlist->defaultServerList = attrVal;
		break;

	default:
		usage();
		return (CLIENT_ERR_FAIL);
		/* break;  lint doesn't like break before end of switch */
	}

	return (retcode);
}

/*
 * file_move() - Used to move a config file (backup/restore).
 *
 * This function uses a system() call with /bin/mv to handle the
 * case where the backup directory (/var) is on a different file
 * system than the config file (typically /etc).
 */
static int
file_move(const char *from, const char *to)
{
	int retcode;
	char mvCommand[] = CMD_MV;
	char cmd_buffer[(2 * MAXPATHLEN) + sizeof (mvCommand) + 3];

	(void) snprintf(cmd_buffer, sizeof (cmd_buffer), "%s %s %s",
	    mvCommand, from, to);

	/*
	 * This function should only be used internally to move
	 * system files to/from the backup directory.  For security
	 * reasons (this is run as root), don't use this function
	 * with arguments passed into the program.
	 */
	retcode = system(cmd_buffer);

	return (retcode);
}


/*
 * Manipulate the service as instructed by "dowhat"
 */
static int
do_service(const char *fmri, boolean_t waitflag, int dowhat,
		const char *state) {

	int		status;
	boolean_t	is_maint;
	const char	*what = gettext("not set");
	useconds_t	max;

	/* Check if we are in maintenance */
	is_maint = is_service(fmri, SCF_STATE_STRING_MAINT);

	switch (dowhat) {
	case START_SERVICE:
		what = gettext("start");
		status = smf_enable_instance(fmri,
			(sysid_install == B_TRUE)?SMF_TEMPORARY:0);
		break;
	case STOP_SERVICE:
		what = gettext("stop");
		status = smf_disable_instance(fmri,
			(sysid_install == B_TRUE)?SMF_TEMPORARY:0);
		break;
	case RESTART_SERVICE:
		what = gettext("restart");
		status = smf_restart_instance(fmri);
		break;
	default:
		/* coding error; will not happen */
		assert(0);
	}

	/*
	 * If the service was previously in maintenance then we need to
	 * clear it immediately.  The "dowhat" action will set the
	 * enabled property of the service as intended by the caller while
	 * clear will actually cause it to be enabled/disabled.
	 * We assume that the caller has called us after taking some
	 * recovery action. Even if it's not the case, we don't lose
	 * anything.
	 */
	if (status == 0 && is_maint == B_TRUE) {
		if (mode_verbose)
			CLIENT_FPRINTF(stderr,
				"%s: %s... %s\n",
				what,
				fmri,
				gettext("restoring from maintenance state"));
		status = smf_restore_instance(fmri);
	}

	if (status == 0) {
		/* Check if we need to wait ? */
		if (waitflag == B_FALSE) {
			if (mode_verbose)
				CLIENT_FPRINTF(stderr,
					"%s: %s... %s\n",
					what,
					fmri,
					gettext("success"));
			return (CLIENT_SUCCESS);
		}

		/* Otherwise wait for max seconds (from the manifest) */
		max = get_timeout_value(dowhat, fmri, DEFAULT_TIMEOUT);
		status = wait_till(fmri, state, max, what, !is_maint);
		if (status == CLIENT_SUCCESS)
			return (CLIENT_SUCCESS);
		/* For error fall through for corrective action */
	} else {
		/* Well, service failed ... */
		if (mode_verbose)
			CLIENT_FPRINTF(stderr, "%s: %s... %s: %s\n",
				what,
				fmri,
				gettext("failed"),
				scf_strerror(scf_error()));
		status = CLIENT_ERR_FAIL;
		/* For error fall through for corrective action */
	}

	/*
	 * If service is still offline after start/restart, then transitioning
	 * failed and guess is restarter failed to apply the timeout as well.
	 * So instead of leaving it offline, let's just disable it until we have
	 * some other mechanism available from smf to handle such situation.
	 */
	if (dowhat != STOP_SERVICE)
		if (is_service(fmri, SCF_STATE_STRING_OFFLINE)) {
			if (mode_verbose)
				CLIENT_FPRINTF(stderr,
					"%s: %s... %s\n",
					what,
					fmri,
					gettext("offline to disable"));
			(void) disable_service(fmri, waitflag);
		}

	return (status);
}


/*
 * Wait for "max" usecs for the service described by "fmri" to change
 * to "state". If check_maint is true then return immediately if
 * service goes into maintenance
 */
static int
wait_till(const char *fmri, const char *state, useconds_t max,
		const char *what, boolean_t check_maint) {
	char *st;
	useconds_t usecs = INIT_WAIT_USECS;

	for (; max > 0; max -= usecs) {
		/* incremental wait */
		usecs *= 2;
		usecs = (usecs > max)?max:usecs;
		if (mode_verbose)
			CLIENT_FPRINTF(stderr,
				"%s: %s %u %s\n",
				what, gettext("sleep"), usecs,
				gettext("microseconds"));
		(void) usleep(usecs);

		/* Check state after the wait */
		if ((st = smf_get_state(fmri)) != NULL) {
			if (strcmp(st, state) == 0) {
				if (mode_verbose)
					CLIENT_FPRINTF(stderr,
						"%s: %s... %s\n",
						what,
						fmri,
						gettext("success"));
				free(st);
				return (CLIENT_SUCCESS);
			}

			/*
			 * If service has gone into maintenance then
			 * we will time out anyway, so we are better
			 * off returning now
			 */
			if (check_maint &&
				strcmp(st, SCF_STATE_STRING_MAINT) == 0) {
				if (mode_verbose)
					CLIENT_FPRINTF(stderr,
						"%s: %s... %s\n",
						what,
						fmri,
						gettext("maintenance"));
				free(st);
				return (CLIENT_ERR_MAINTENANCE);
			}
			free(st);
		} else {
			if (mode_verbose)
				CLIENT_FPRINTF(stderr,
						"%s: %s... %s: %s\n",
						what,
						fmri,
						gettext("failed"),
						scf_strerror(scf_error()));
			return (CLIENT_ERR_FAIL);
		}
	}

	/* Timed out waiting */
	if (mode_verbose)
		CLIENT_FPRINTF(stderr,
			"%s: %s... %s\n",
			what,
			fmri,
			gettext("timed out"));
	return (CLIENT_ERR_TIMEDOUT);
}


static boolean_t
is_service(const char *fmri, const char *state) {
	char		*st;
	boolean_t	result = B_FALSE;

	if ((st = smf_get_state(fmri)) != NULL) {
		if (strcmp(st, state) == 0)
			result = B_TRUE;
		free(st);
	}
	return (result);
}


/*
 *
 * get_timeout_val : returns the timeout value set in fmri manifest
 * 	inputs	: action(start/stop)
 *	fmri(defined fmri string)
 *	Returns default if error, the timeout val otherwise
 *
 */

static useconds_t
get_timeout_value(int dowhat, const char *fmri, useconds_t default_val)
{
	scf_simple_prop_t	*sp = NULL;
	uint64_t		*cp = NULL;
	int			timeout = default_val/1000000;
	char			*action = NULL;
	const char		*actionstr = NULL;

	switch (dowhat)  {
		case START_SERVICE:
		case RESTART_SERVICE:
				action = "start";
				actionstr = gettext("start");
				break;
		case STOP_SERVICE:
				action = "stop";
				actionstr = gettext("stop");
				break;
		default:
			assert(0);
	}


	sp = scf_simple_prop_get(NULL, fmri, action, SCF_PROPERTY_TIMEOUT);
	if (sp == NULL) {
		if (mode_verbose)
			CLIENT_FPRINTF(stderr, "%s: %s... %s: %s\n",
			    actionstr,
			    fmri,
			    gettext("failed to retrieve timeout property"),
			    scf_strerror(scf_error()));
		return (default_val);
	}

	cp = scf_simple_prop_next_count(sp);
	if (cp == NULL) {
		if (mode_verbose)
			CLIENT_FPRINTF(stderr, "%s: %s... %s: %s\n",
			    actionstr,
			    fmri,
			    gettext("failed to retrieve timeout value"),
			    scf_strerror(scf_error()));
		scf_simple_prop_free(sp);
		return (default_val);
	}

	if (*cp != 0)
		timeout = *cp;
	scf_simple_prop_free(sp);
	return (timeout * 1000000);
}
