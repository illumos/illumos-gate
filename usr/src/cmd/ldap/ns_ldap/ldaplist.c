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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2011 Nexenta Systems, Inc. All rights reserved.
 */


#include <stdio.h>
#include <stdlib.h>
#include <libintl.h>
#include <strings.h>
#include <locale.h>
#include <syslog.h>

#include "standalone.h"

extern char *set_filter(char **, char *, char **);
extern char *set_filter_publickey(char **, char *, int, char **);
extern void _printResult(ns_ldap_result_t *);
extern void printMapping();

int listflag = 0;



static struct database_t {
	const char *database;
	const char *sortattr;
}databaselist[] = {
	{ NS_LDAP_TYPE_HOSTS, "cn" },
	{ NS_LDAP_TYPE_IPNODES, "cn" },
	{ NS_LDAP_TYPE_RPC, "cn" },
	{ NS_LDAP_TYPE_PROTOCOLS, "cn" },
	{ NS_LDAP_TYPE_NETWORKS, "ipnetworknumber" },
	{ NS_LDAP_TYPE_SERVICES, "cn" },
	{ NS_LDAP_TYPE_GROUP, "gidnumber" },
	{ NS_LDAP_TYPE_NETMASKS, "ipnetworknumber"},
	{ NS_LDAP_TYPE_ETHERS, "cn" },
	{ NS_LDAP_TYPE_NETGROUP, "cn" },
	{ NS_LDAP_TYPE_BOOTPARAMS, "cn" },
	{ NS_LDAP_TYPE_PUBLICKEY, "cn" },
	{ NS_LDAP_TYPE_PASSWD, "uid" },
	{ NS_LDAP_TYPE_SHADOW, "uid" },
	{ NS_LDAP_TYPE_ALIASES, "cn" },
	{ NS_LDAP_TYPE_AUTOMOUNT, "automountKey" },
	{ NS_LDAP_TYPE_USERATTR, "uid" },
	{ NS_LDAP_TYPE_PROFILE, "cn" },
	{ NS_LDAP_TYPE_EXECATTR, "cn" },
	{ NS_LDAP_TYPE_AUTHATTR, "cn" },
	{ NS_LDAP_TYPE_AUUSER, "uid" },
	{ NS_LDAP_TYPE_TNRHDB, "ipTnetNumber" },
	{ NS_LDAP_TYPE_TNRHTP, "ipTnetTemplateName" },
	{ NS_LDAP_TYPE_PROJECT, "SolarisProjectName" },
	{ 0, 0 }
};


void
usage(char *msg)
{
	if (msg)
		(void) fprintf(stderr, "%s\n", msg);

	(void) fprintf(stderr, gettext(
	"\n"
	"usage: ldaplist [-dlv] [-h LDAP_server[:serverPort] [-M domainName]\n"
	"[-N  profileName] [-a  authenticationMethod] [-P certifPath]\n"
	"[-D  bindDN] [-w bindPassword] [-j passwdFile]]\n"
	"[<database> [<key>] ...]\n\n"
	"usage: ldaplist -h\n"
	"\n"
	"usage: ldaplist -g\n\n"
	"\tOptions:\n"
	"\t    -l list all the attributes found in entry.\n"
	"\t       By default, it lists only the DNs.\n"
	"\t    -d list attributes for the database instead of its entries\n"
	"\t    -v print out the LDAP search filter.\n"
	"\t    -g list the database mappings.\n"
	"\t    -h An address (or a name) and a port of the LDAP server in\n"
	"\t       which the entries will be stored. The default value for\n"
	"\t       the port is 389 (or 636 for TLS connections).\n"
	"\t    -M The name of a domain served by the specified server.\n"
	"\t       If not specified, the default domain name will be used.\n"
	"\t    -N Specifies a DUAProfile name.\n"
	"\t       The default value is \"default\".\n"
	"\t    -a Specifies an authentication method.\n"
	"\t    -P The certificate path for the location of the certificate\n"
	"\t       database.\n"
	"\t    -D Specifies an entry which has read permission to\n"
	"\t       the requested database.\n"
	"\t    -w Password to be used for authenticating the bindDN.\n"
	"\t    -j File containing the password for bindDN or SSL key db.\n"
	"\t<database> is the database to be searched in.  Standard system\n"
	"\tdatabases are:\n"
	"\t\tpassword, printers, group, hosts, ethers, networks, netmasks,\n"
	"\t\trpc, bootparams, protocols, services, netgroup, auto_*.\n"
	"\tNon-standard system databases can be specified as follows:\n"
	"\t\tby specific container: ou=<dbname> or\n"
	"\t\tby default container: <dbname>.  In this case, 'nismapname'\n"
	"\t\twill be used, thus mapping this to nismapname=<dbname>.\n"
	"\t<key> is the key to search in the database.  For the standard\n"
	"\tdatabases, the search type for the key is predefined.  You can\n"
	"\toverride this by specifying <type>=<key>.\n"
	"\nNOTE: The old -h option printing the mapping information is "
	"deprecated.\nFor backward compatibility the following mode is "
	"available:\nldaplist -h\n"));
	exit(1);
}

/*
 * This is a generic filter call back function for
 * merging the filter from service search descriptor with
 * an existing search filter. This routine expects userdata
 * contain a format string with a single %s in it, and will
 * use the format string with sprintf() to insert the SSD filter.
 *
 * This routine is passed to the __ns_ldap_list() or
 * __ns_ldap_firstEntry() APIs as the filter call back
 * together with the userdata. For example,
 * the "ldaplist hosts sys1" processing may call __ns_ldap_list()
 * with "(&(objectClass=ipHost)(cn=sys1))" as filter, this function
 * as the filter call back, and "(&(%s)(cn=sys1))" as the
 * userdata, this routine will in turn gets call to produce
 * "(&(department=sds)(cn=sys1))" as the real search
 * filter, if the input SSD contains a filter "department=sds".
 */
static int
merge_SSD_filter(const ns_ldap_search_desc_t *desc, char **realfilter,
    const void *userdata)
{
	int	len;
	char *checker;

	/* sanity check */
	if (realfilter == NULL)
		return (NS_LDAP_INVALID_PARAM);
	*realfilter = NULL;

	if (desc == NULL || desc->filter == NULL ||
	    userdata == NULL)
		return (NS_LDAP_INVALID_PARAM);

	/* Parameter check.  We only want one %s here, otherwise bail. */
	len = 0;	/* Reuse 'len' as "Number of %s hits"... */
	checker = (char *)userdata;
	do {
		checker = strchr(checker, '%');
		if (checker != NULL) {
			if (len > 0 || *(checker + 1) != 's')
				return (NS_LDAP_INVALID_PARAM);
			len++;	/* Got our %s. */
			checker += 2;
		} else if (len != 1)
			return (NS_LDAP_INVALID_PARAM);
	} while (checker != NULL);

	len = strlen(userdata) + strlen(desc->filter) + 1;

	*realfilter = (char *)malloc(len);
	if (*realfilter == NULL)
		return (NS_LDAP_MEMORY);

	(void) sprintf(*realfilter, (char *)userdata,
	    desc->filter);

	return (NS_LDAP_SUCCESS);
}

/* returns 0=success, 1=error */
int
list(char *database, char *ldapfilter, char **ldapattribute,
    char **err, char *userdata)
{
	ns_ldap_result_t	*result;
	ns_ldap_error_t	*errorp;
	int		rc;
	char		buf[500];
	const char	*sort = NULL;
	int		i;

	if (database) {
		for (i = 0; databaselist[i].database; i++) {
			if (strcmp(databaselist[i].database, database) == 0) {
				sort = databaselist[i].sortattr;
				break;
			}
			if (strcmp(databaselist[i].database,
			    NS_LDAP_TYPE_AUTOMOUNT) == 0 &&
			    strncmp(database, NS_LDAP_TYPE_AUTOMOUNT,
			    sizeof (NS_LDAP_TYPE_AUTOMOUNT) - 1) == 0) {
				sort = databaselist[i].sortattr;
				break;
			}
		}
	}

	*err = NULL;
	buf[0] = '\0';
	rc = __ns_ldap_list_sort(database, (const char *)ldapfilter,
	    sort, merge_SSD_filter, (const char **)ldapattribute, NULL,
	    listflag, &result, &errorp, NULL, userdata);
	if (rc != NS_LDAP_SUCCESS) {
		char *p;
		(void) __ns_ldap_err2str(rc, &p);
		if (errorp && errorp->message) {
			(void) snprintf(buf, sizeof (buf), "%s (%s)",
			    p, errorp->message);
			(void) __ns_ldap_freeError(&errorp);
		} else
			(void) snprintf(buf, sizeof (buf), "%s\n", p);
		*err = strdup(buf);
		return (rc);
	}

	_printResult(result);
	(void) __ns_ldap_freeResult(&result);
	return (0);
}


int
switch_err(int rc)
{
	switch (rc) {
	case NS_LDAP_SUCCESS:
		return (0);
	case NS_LDAP_NOTFOUND:
		return (1);
	}
	return (2);
}

int
main(int argc, char **argv)
{

	extern int		optind;
	char			*database = NULL;
	char			*ldapfilter = NULL;
	char			*attribute = "dn";
	char			**key = NULL;
	char			**ldapattribute = NULL;
	char			*buffer[100];
	char			*err = NULL;
	char			*p;
	int			index = 1;
	int			c;
	int			rc;
	int			verbose = 0;
	char			*udata = NULL;

	ns_standalone_conf_t	standalone_cfg = standaloneDefaults;
	ns_ldap_error_t		*errorp = NULL;
	char			*authmech = NULL;
	ns_auth_t		auth = {NS_LDAP_AUTH_NONE,
					NS_LDAP_TLS_NONE,
					NS_LDAP_SASL_NONE,
					NS_LDAP_SASLOPT_NONE};

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	openlog("ldaplist", LOG_PID, LOG_USER);

	if (argc == 2 &&
	    strlen(argv[1]) == 2 && strncmp(argv[1], "-h", 2) == 0) {
		/* preserve backwards compatability, support old -h option */
		(void) printMapping();
		exit(0);
	}

	while ((c = getopt(argc, argv, "h:M:N:P:r:a:D:w:j:dgvl")) != EOF) {
		switch (c) {
		case 'd':
			listflag |= NS_LDAP_SCOPE_BASE;
			break;
		case 'g':
			(void) printMapping();
			exit(0);
			break; /* Never reached */
		case 'l':
			attribute = "NULL";
			break;
		case 'v':
			verbose = 1;
			break;
		case 'M':
			standalone_cfg.type = NS_LDAP_SERVER;
			standalone_cfg.SA_DOMAIN = optarg;
			break;
		case 'h':
			standalone_cfg.type = NS_LDAP_SERVER;
			if (separatePort(optarg,
			    &standalone_cfg.SA_SERVER,
			    &standalone_cfg.SA_PORT) > 0) {
				exit(1);
			}
			break;
		case 'P':
			standalone_cfg.type = NS_LDAP_SERVER;
			standalone_cfg.SA_CERT_PATH = optarg;
			break;
		case 'N':
			standalone_cfg.type = NS_LDAP_SERVER;
			standalone_cfg.SA_PROFILE_NAME = optarg;
			break;
		case 'D':
			standalone_cfg.type = NS_LDAP_SERVER;
			standalone_cfg.SA_BIND_DN = strdup(optarg);
			break;
		case 'w':
			if (standalone_cfg.SA_BIND_PWD != NULL) {
				(void) fprintf(stderr,
				    gettext("The -w option is mutually "
				    "exclusive of -j. -w is ignored.\n"));
				break;
			}

			if (optarg != NULL &&
			    optarg[0] == '-' && optarg[1] == '\0') {
				/* Ask for a password later */
				break;
			}

			standalone_cfg.type = NS_LDAP_SERVER;
			standalone_cfg.SA_BIND_PWD = strdup(optarg);
			break;
		case 'j':
			if (standalone_cfg.SA_BIND_PWD != NULL) {
				(void) fprintf(stderr,
				    gettext("The -w option is mutually "
				    "exclusive of -j. -w is ignored.\n"));
				free(standalone_cfg.SA_BIND_PWD);
			}
			standalone_cfg.type = NS_LDAP_SERVER;
			standalone_cfg.SA_BIND_PWD = readPwd(optarg);
			if (standalone_cfg.SA_BIND_PWD == NULL) {
				exit(1);
			}
			break;
		case 'a':
			authmech = optarg;
			break;
		default:
			usage(gettext("Invalid option"));
		}
	}

	if (standalone_cfg.type == NS_LDAP_SERVER &&
	    standalone_cfg.SA_SERVER == NULL) {
		(void) fprintf(stderr,
		    gettext("Please specify an LDAP server you want "
		    "to connect to. \n"));
		exit(1);
	}

	if ((c = argc - optind) > 0)
		database = argv[optind++];
	if ((--c) > 0)
		key = &argv[optind];

	if (authmech != NULL) {
		if (__ns_ldap_initAuth(authmech,
		    &auth,
		    &errorp) != NS_LDAP_SUCCESS) {
			if (errorp) {
				(void) fprintf(stderr, "%s", errorp->message);
				(void) __ns_ldap_freeError(&errorp);
			}
			exit(1);
		}
	}

	if (auth.saslmech != NS_LDAP_SASL_GSSAPI &&
	    standalone_cfg.SA_BIND_DN != NULL &&
	    standalone_cfg.SA_BIND_PWD == NULL) {
		/* If password is not specified, then prompt user for it. */
		standalone_cfg.SA_BIND_PWD =
		    strdup(getpassphrase("Enter password:"));
	}

	standalone_cfg.SA_AUTH = (authmech == NULL) ? NULL : &auth;

	if (__ns_ldap_initStandalone(&standalone_cfg,
	    &errorp) != NS_LDAP_SUCCESS) {
		if (errorp) {
			(void) fprintf(stderr, "%s\n", errorp->message);
			(void) __ns_ldap_freeError(&errorp);
		}
		exit(1);
	}

	if (authmech != NULL) {
		if (__ns_ldap_setParam(NS_LDAP_AUTH_P,
		    authmech, &errorp) != NS_LDAP_SUCCESS) {
			__ns_ldap_cancelStandalone();
			if (errorp != NULL) {
				(void) fprintf(stderr, "%s", errorp->message);
				(void) __ns_ldap_freeError(&errorp);
			}
			exit(1);
		}
	}
	if (standalone_cfg.SA_CRED != NULL) {
		if (__ns_ldap_setParam(NS_LDAP_CREDENTIAL_LEVEL_P,
		    standalone_cfg.SA_CRED, &errorp) != NS_LDAP_SUCCESS) {
			__ns_ldap_cancelStandalone();
			if (errorp != NULL) {
				(void) fprintf(stderr, "%s", errorp->message);
				(void) __ns_ldap_freeError(&errorp);
			}
			exit(1);
		}
	}

	if (standalone_cfg.type != NS_CACHEMGR &&
	    standalone_cfg.SA_BIND_DN != NULL) {
		ns_auth_t **authpp = NULL, **authp = NULL;

		if (__ns_ldap_getParam(NS_LDAP_AUTH_P,
		    (void ***)&authpp,
		    &errorp) != NS_LDAP_SUCCESS || authpp == NULL) {
			__ns_ldap_cancelStandalone();
			(void) __ns_ldap_freeParam((void ***)&authpp);
			if (errorp) {
				(void) fprintf(stderr,
				    gettext(errorp->message));
				(void) __ns_ldap_freeError(&errorp);
			}
			exit(1);
		}
		for (authp = authpp; *authp; authp++) {
			if ((*authp)->saslmech == NS_LDAP_SASL_GSSAPI) {
				/*
				 * For now we have no use for bindDN and
				 * bindPassword when using SASL/GSSAPI.
				 */
				(void) fprintf(stderr,
				    gettext("Warning: SASL/GSSAPI will be "
				    "used as an authentication method"
				    "The bind DN and password will "
				    "be ignored.\n"));
				break;
			}
		}
	}

	/*
	 * If dumpping a database,
	 * or all the containers,
	 * use page control just
	 * in case there are too many entries
	 */
	if (!key && !(listflag & NS_LDAP_SCOPE_BASE))
		listflag |= NS_LDAP_PAGE_CTRL;

	/* build the attribute array */
	if (strncasecmp(attribute, "NULL", 4) == 0)
		ldapattribute = NULL;
	else {
		buffer[0] = strdup(attribute);
		while ((p = strchr(attribute, ',')) != NULL) {
			buffer[index++] = attribute = p + 1;
			*p = '\0';
		}
		buffer[index] = NULL;
		ldapattribute = buffer;
	}

	/* build the filter */
	if (database && (strcasecmp(database, "publickey") == 0)) {
		/* user publickey lookup */
		char *err1 = NULL;
		int  rc1;

		rc = rc1 = -1;
		ldapfilter = set_filter_publickey(key, database, 0, &udata);
		if (ldapfilter) {
			if (verbose) {
				(void) fprintf(stdout,
				    gettext("+++ database=%s\n"),
				    (database ? database : "NULL"));
				(void) fprintf(stdout,
				    gettext("+++ filter=%s\n"),
				    (ldapfilter ? ldapfilter : "NULL"));
				(void) fprintf(stdout,
				gettext("+++ template for merging"
				    "SSD filter=%s\n"),
				    (udata ? udata : "NULL"));
			}
			rc = list("passwd", ldapfilter, ldapattribute,
			    &err, udata);
			free(ldapfilter);
			free(udata);
		}
		/* hosts publickey lookup */
		ldapfilter = set_filter_publickey(key, database, 1, &udata);
		if (ldapfilter) {
			if (verbose) {
				(void) fprintf(stdout,
				    gettext("+++ database=%s\n"),
				    (database ? database : "NULL"));
				(void) fprintf(stdout,
				    gettext("+++ filter=%s\n"),
				    (ldapfilter ? ldapfilter : "NULL"));
				(void) fprintf(stdout,
				gettext("+++ template for merging"
				    "SSD filter=%s\n"),
				    (udata ? udata : "NULL"));
			}
			rc1 = list("hosts", ldapfilter, ldapattribute,
			    &err1, udata);
			free(ldapfilter);
			free(udata);
		}
		if (rc == -1 && rc1 == -1) {
			/* this should never happen */
			(void) fprintf(stderr,
			    gettext("ldaplist: invalid publickey lookup\n"));
			rc = 2;
		} else if (rc != 0 && rc1 != 0) {
			(void) fprintf(stderr,
			gettext("ldaplist: %s\n"), (err ? err : err1));
			if (rc == -1)
				rc = rc1;
		} else
			rc = 0;
		exit(switch_err(rc));
	}

	/*
	 * we set the search filter to (objectclass=*) when we want
	 * to list the directory attribute instead of the entries
	 * (the -d option).
	 */
	if (((ldapfilter = set_filter(key, database, &udata)) == NULL) ||
	    (listflag == NS_LDAP_SCOPE_BASE)) {
		ldapfilter = strdup("objectclass=*");
		udata = strdup("%s");
	}

	if (verbose) {
		(void) fprintf(stdout, gettext("+++ database=%s\n"),
		    (database ? database : "NULL"));
		(void) fprintf(stdout, gettext("+++ filter=%s\n"),
		    (ldapfilter ? ldapfilter : "NULL"));
		(void) fprintf(stdout,
		    gettext("+++ template for merging SSD filter=%s\n"),
		    (udata ? udata : "NULL"));
	}
	if (rc = list(database, ldapfilter, ldapattribute, &err, udata))
		(void) fprintf(stderr, gettext("ldaplist: %s\n"), err);

	__ns_ldap_cancelStandalone();

	if (ldapfilter)
		free(ldapfilter);
	if (udata)
		free(udata);
	exit(switch_err(rc));
	return (0); /* Never reached */
}
