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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <libintl.h>
#include <strings.h>
#include <locale.h>
#include <syslog.h>
#include "../../../lib/libsldap/common/ns_sldap.h"

extern char *set_filter(char **, char *, char **);
extern char *set_filter_publickey(char **, char *, int, char **);
extern void _printResult(ns_ldap_result_t *);
extern void printMapping();

int listflag = 0;

void
usage(char *msg) {
	if (msg)
		(void) fprintf(stderr, "%s\n", msg);

	(void) fprintf(stderr,
	gettext(
	"ldaplist [-lvh] [<database> [<key>] ...]\n"
	"\tOptions:\n"
	"\t    -l list all the attributes found in entry.\n"
	"\t       By default, it lists only the DNs.\n"
	"\t    -d list attributes for the database instead of its entries\n"
	"\t    -v print out the LDAP search filter.\n"
	"\t    -h list the database mappings.\n"
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
	"\toverride this by specifying <type>=<key>.\n"));
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
merge_SSD_filter(const ns_ldap_search_desc_t *desc,
			char **realfilter,
			const void *userdata)
{
	int	len;

	/* sanity check */
	if (realfilter == NULL)
		return (NS_LDAP_INVALID_PARAM);
	*realfilter = NULL;

	if (desc == NULL || desc->filter == NULL ||
			userdata == NULL)
		return (NS_LDAP_INVALID_PARAM);

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

	*err = NULL;
	buf[0] = '\0';
	rc = __ns_ldap_list(database, (const char *)ldapfilter,
		merge_SSD_filter, (const char **)ldapattribute, NULL,
		listflag, &result, &errorp, NULL, userdata);
	if (rc != NS_LDAP_SUCCESS) {
		char *p;
		(void) __ns_ldap_err2str(rc, &p);
		if (errorp && errorp->message) {
			(void) snprintf(buf, sizeof (buf), "%s (%s)",
					p, errorp->message);
			(void) __ns_ldap_freeError(&errorp);
		} else
			(void) snprintf(buf, sizeof (buf), "%s", p);
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

	extern int optind;
	char	*database = NULL;
	char	*ldapfilter = NULL;
	char	*attribute = "dn";
	char	**key = NULL;
	char	**ldapattribute = NULL;
	char 	*buffer[100];
	char	*err = NULL;
	char	*p;
	int	index = 1;
	int	c;
	int	rc;
	int	verbose = 0;
	char	*udata = NULL;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	openlog("ldaplist", LOG_PID, LOG_USER);

	while ((c = getopt(argc, argv, "dhvl")) != EOF) {
		switch (c) {
		case 'd':
			listflag |= NS_LDAP_SCOPE_BASE;
			break;
		case 'h':
			(void) printMapping();
			exit(0);
			break; /* Never reached */
		case 'l':
			attribute = "NULL";
			break;
		case 'v':
			verbose = 1;
			break;
		default:
			usage(gettext("Invalid option"));
		}
	}
	if ((c = argc - optind) > 0)
		database = argv[optind++];
	if ((--c) > 0)
		key = &argv[optind];

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
	if (database && (strcasecmp(database, "publickey") == NULL)) {
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
		} if (rc != 0 && rc1 != 0) {
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
	if (ldapfilter)
		free(ldapfilter);
	if (udata)
		free(udata);
	exit(switch_err(rc));
	return (0); /* Never reached */
}
