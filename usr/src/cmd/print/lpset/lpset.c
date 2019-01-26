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
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdarg.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <locale.h>
#ifndef SUNOS_4
#include <libintl.h>
#endif
#include <pwd.h>
#include <alloca.h>

#include <ns.h>
#include <list.h>

extern char *optarg;
extern int optind, opterr, optopt;
extern char *getenv(const char *);

static void _decode_ldapResult(int result, char *printerName);

static int
authorized()
{
	struct passwd *pw;
	uid_t uid;
	gid_t *list;
	int len;
	int maxgrp;

	if ((uid = getuid()) == 0)
		return (1);	/* "root" is authorized */

	if (((pw = getpwnam("lp")) != NULL) && (uid == pw->pw_uid))
		return (1);	/* "lp" is authorized */

	if ((pw = getpwuid(uid)) == NULL)
		return (0);	/* intruders are not authorized */

	if (chkauthattr("solaris.print.admin", pw->pw_name) == 1)
		return (1);	/* "solaris.print.admin" is authorized */

	/* How many supplemental groups do we have? */
	maxgrp = getgroups(0, NULL);
	list = alloca(maxgrp * sizeof (gid_t));

	if ((len = getgroups(maxgrp, list)) != -1)
		while (len-- > 0)
			if (list[len] == 14)
				return (1);	/* group 14 is authorized */

	return (0);	/* nobody else is authorized */
}

static void
Usage(char *name)
{
	(void) fprintf(stderr,
	    gettext("Usage: %s [-n files | ldap] [-x] "
	    "[-h ldaphost] [-D binddn] [-w passwd] "
	    "[-a key=value] [-d key] (printer)\n"),
	    name);
	exit(1);
}


/*
 *  main() calls the appropriate routine to parse the command line arguments
 *	and then calls the local remove routine, followed by the remote remove
 *	routine to remove jobs.
 */
int
main(int ac, char *av[])
{
	int result = 0;
	int delete_printer = 0;
	int c;
	char	*program = NULL,
	    *printer = NULL,
	    *host = NULL,
	    *binddn = NULL,
	    *passwd = NULL,
	    *ins = NULL,
	    *ons = "files";
	char	**changes = NULL;
	ns_cred_t	*cred = NULL;
	ns_printer_t 	*printer_obj = NULL;

	(void) setlocale(LC_ALL, "");

#if	!defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	if ((program = strrchr(av[0], '/')) == NULL)
		program = av[0];
	else
		program++;

	openlog(program, LOG_PID, LOG_LPR);

	if (ac < 2)
		Usage(program);

	while ((c = getopt(ac, av, "a:d:D:h:n:r:w:x")) != EOF)
		switch (c) {
		case 'd':
			if (strchr(optarg, '=') != NULL)
				Usage(program);
			/* FALLTHRU */
		case 'a':
			changes = (char **)list_append((void**)changes,
			    (void *)strdup(optarg));
			break;
		case 'D':
			binddn = optarg;
			break;
		case 'h':
			host = optarg;
			break;
		case 'n':
			ons = optarg;
			break;
		case 'r':
			ins = optarg;
			break;
		case 'w':
			passwd = optarg;
			break;
		case 'x':
			delete_printer++;
			break;
		default:
			Usage(program);
		}

	if (optind != ac-1)
		Usage(program);

	/*
	 * Check required options have been given: [ -x | [ -a | -d ]]
	 */
	if ((changes == NULL) && (delete_printer == 0)) {
		Usage(program);
	}

	printer = av[optind];

	if (strchr(printer, ':') != NULL) {
		(void) fprintf(stderr, gettext(
		    "POSIX-Style names are not valid destinations (%s)\n"),
		    printer);
		return (1);
	}

	ins = normalize_ns_name(ins);
	ons = normalize_ns_name(ons);
	if (ins == NULL)
		ins = ons;

	/* check / set the name service for writing */
	if (strcasecmp("user", ons) == 0) {
		(void) setuid(getuid());
		ons = "user";
	} else if (strcasecmp("files", ons) == 0) {
		if (authorized() == 0) {
			(void) fprintf(stderr, gettext(
			    "Permission denied: not authorized\n"));
			return (1);
		}
		ons = "files";
	} else if (strcasecmp("ldap", ons) == 0) {
		if ((cred = calloc(1, sizeof (*cred))) == NULL) {
			(void) fprintf(stderr,
			    gettext("could not initialize credential\n"));
			return (1);
		}

		if (binddn == NULL) {
			(void) fprintf(stderr,
			    gettext("Distinguished Name is required.\n"));
			return (1);
		}

		if (passwd == NULL) {
			passwd = getpassphrase(gettext("Bind Password:"));
		}

		/*
		 * Setup LDAP bind credentials, so that it uses
		 * the default ldap port, and the NS domain for this
		 * ldapclient box. Note: passwdType is currently not
		 * used but once the ldap native function can select
		 * secure or insure password it will pass the user selected
		 * security type.
		 */
		cred->passwd = passwd;
		cred->passwdType = NS_PW_INSECURE; /* use default */
		cred->binddn = binddn;
		cred->host = host;
		cred->port = 0;		/* use default */
		cred->domainDN = NULL;	/* use default */

		ons = "ldap";
		(void) setuid(getuid());
	} else {
		(void) fprintf(stderr,
		    gettext("%s is not a supported name service.\n"),
		    ons);
		return (1);
	}

	if (strcasecmp(NS_SVC_LDAP, ons) != 0) {

	    /* Naming Service is not LDAP */

	    /* get the printer object */
		if ((printer_obj = ns_printer_get_name(printer, ins)) == NULL) {
			if (delete_printer != 0) {
				(void) fprintf(stderr, gettext
				    ("%s: unknown printer\n"), printer);
			return (1);
			}
			if ((printer_obj = calloc(1, sizeof (*printer_obj)))
			    == NULL) {
				(void) fprintf(stderr, gettext(
				    "could not initialize printer object\n"));
				return (1);
			}
			printer_obj->name = strdup(printer);
		}

		printer_obj->source = ons;

		if (cred != NULL) {
			printer_obj->cred = cred;
		}

	    /* make the changes to it */
		while (changes != NULL && *changes != NULL) {
			int has_equals = (strchr(*changes, '=') != NULL);
			char *p, *key = NULL, *value = NULL;

			key = *(changes++);

			for (p = key; ((p != NULL) && (*p != '\0')); p++)
				if (*p == '=') {
					*p = '\0';
					value = ++p;
					break;
				} else if (*p == '\\')
					p++;

			if ((value != NULL) && (*value == '\0'))
				value = NULL;

			if ((key != NULL) && (key[0] != '\0')) {
				if ((value == NULL) &&
				    (ns_get_value(key, printer_obj) == NULL) &&
				    (has_equals == 0)) {
					fprintf(stderr,
					    gettext("%s: unknown attribute\n"),
					    key);
					result = 1;
				} else
				(void) ns_set_value_from_string(key, value,
				    printer_obj);
			}
		}
		if (delete_printer != 0)
			printer_obj->attributes = NULL;

		/* write it back */
		if (ns_printer_put(printer_obj) != 0) {
			(void) fprintf(stderr,
			    gettext("Failed to write into %s database\n"),
			    ons);
			result = 1;
		}
	}

	else {
		/*
		 * Naming Service is LDAP
		 *
		 * Action the request by calling ns ldap functions to
		 * add, modify or delete the printer object.
		 */

		if ((printer_obj = calloc(1, sizeof (*printer_obj))) == NULL) {
			(void) fprintf(stderr, gettext(
			    "could not initialize printer object\n"));
			return (1);
		}

		if ((cred != NULL) && (printer_obj != NULL)) {
			printer_obj->name = strdup(printer);
			printer_obj->cred = cred;
			printer_obj->cred->domainDN = NULL; /* use default */
			printer_obj->source = ons;
			printer_obj->nsdata = malloc(sizeof (NS_LDAPDATA));

			if (printer_obj->nsdata != NULL) {
				/*
				 * Update the LDAP directory for this printer
				 */

				if (delete_printer != 0) {
					/* Delete the printer object */
					((NS_LDAPDATA *)
					    (printer_obj->nsdata))->attrList
					    = NULL;
				} else {
					/* Add or modify the printer object */
					((NS_LDAPDATA *)
					    (printer_obj->nsdata))->attrList =
					    changes;
				}

				result = ns_printer_put(printer_obj);
				if (result != 0) {
					/* display LDAP specific message */
					_decode_ldapResult(result, printer);

					(void) fprintf(stderr, gettext(
					"Failed to update %s database\n"), ons);
					result = 1;
				}

				free(printer_obj->nsdata);
			}

			else {
				_decode_ldapResult(NSL_ERR_MEMORY, NULL);
				result = 1;
			}
		}

		else {
			result = 1;
			(void) fprintf(stderr,
			    gettext("Error - no LDAP credentials\n"));
		}

		if (printer_obj != NULL) {
			if (printer_obj->name != NULL) {
				free(printer_obj->name);
			}
			free(printer_obj);
		}

	}

	return (result);
} /* main */




/*
 * *****************************************************************************
 *
 * Function:    _decode_ldapResult()
 *
 * Description: Decode the ldap_put_printer specific error codes and display
 *              the appropriate error message.
 *
 * Parameters:
 * Input:       int result - contains the NSL_RESULT codes
 *              char *printerName - name of printer
 * Output:      None
 *
 * Returns:     void
 *
 * *****************************************************************************
 */

static void
_decode_ldapResult(int result, char *printerName)

{
	NSL_RESULT lresult = (NSL_RESULT)result;

	/* ------------- */

	switch (lresult)
	{
		case NSL_OK:
		{
			break;
		}

		case NSL_ERR_INTERNAL:
		{
			(void) fprintf(stderr,
				gettext("Unexpected software error\n"));
			break;
		}

		case NSL_ERR_ADD_FAILED:
		{
			(void) fprintf(stderr, "%s %s\n",
				gettext("Failed to add printer:"), printerName);
			break;
		}

		case NSL_ERR_MOD_FAILED:
		{
			(void) fprintf(stderr, "%s %s\n",
				gettext("Failed to modify printer:"),
					printerName);
			break;
		}

		case NSL_ERR_DEL_FAILED:
		{
			(void) fprintf(stderr, "%s %s\n",
				gettext("Failed to delete printer:"),
					printerName);
			break;
		}


		case NSL_ERR_UNKNOWN_PRINTER:
		{
			(void) fprintf(stderr, "%s %s\n",
				gettext("Unknown printer:"), printerName);
			break;
		}

		case NSL_ERR_CREDENTIALS:
		{
			(void) fprintf(stderr, "%s\n",
		gettext("Missing LDAP credential information for printer:"));
			break;
		}

		case NSL_ERR_CONNECT:
		{
			(void) fprintf(stderr, "%s\n",
				gettext("Failed to connect to LDAP server"));
			break;
		}

		case NSL_ERR_BIND:
		{
			(void) fprintf(stderr, gettext("LDAP bind failed\n"));
			break;
		}

		case NSL_ERR_RENAME:
		{
			(void) fprintf(stderr, "%s %s\n",
			    gettext("Object rename not allowed for printer:"),
			    printerName);
			break;
		}

		case NSL_ERR_KVP:
		{
			(void) fprintf(stderr, "%s",
			    gettext("Setting sun-printer-kvp attribute is "
				"not supported through this command.\n"));
			break;
		}

		case NSL_ERR_BSDADDR:
		{
			(void) fprintf(stderr, "%s",
			    gettext("Setting sun-printer-bsdaddr attribute is "
				"not supported through this command.\n"
				"Use the bsaddr attribute instead.\n"));
			break;
		}

		case NSL_ERR_PNAME:
		{
			(void) fprintf(stderr, "%s",
			    gettext("Setting printer-name attribute is "
				"not supported through this command.\n"));
			break;
		}

		case NSL_ERR_MEMORY:
		{
			(void) fprintf(stderr,
					gettext("Memory allocation error\n"));
			break;
		}

		case NSL_ERR_MULTIOP:
		{
			(void) fprintf(stderr,
				gettext("Delete and add operation on the "
					"same key attribute is not allowed\n"));
			break;
		}

		case NSL_ERR_NOTALLOWED:
		{
			(void) fprintf(stderr,
				gettext("KVP attribute is not allowed\n"));
			break;
		}

		default:
		{
			(void) fprintf(stderr,
					gettext("Error code = %d\n"), result);
			break;
		}
	}

} /* _decode_ldapResult */
