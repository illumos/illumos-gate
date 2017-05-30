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
 *
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <strings.h>
#include <ctype.h>
#include <libgen.h>
#include <libintl.h>
#include <locale.h>

#include <kmfapiP.h>

#include "util.h"

/*
 * The verbcmd construct allows genericizing information about a verb so
 * that it is easier to manipulate.  Makes parsing code easier to read,
 * fix, and extend with new verbs.
 */
typedef struct verbcmd_s {
	char    	*verb;
	int		(*action)(int, char *[]);
	char    	*synopsis;
} verbcmd;

int	kc_list(int argc, char *argv[]);
int	kc_delete(int argc, char *argv[]);
int	kc_create(int argc, char *argv[]);
int	kc_modify(int argc, char *argv[]);
int	kc_export(int argc, char *argv[]);
int	kc_import(int argc, char *argv[]);
int	kc_install(int argc, char *argv[]);
int	kc_uninstall(int argc, char *argv[]);

static int	kc_help();

static verbcmd cmds[] = {
	{ "list",	kc_list,
		"list [dbfile=dbfile] [policy=policyname]\n"
		"\tlist plugin" },
	{ "delete",	kc_delete, "delete [dbfile=dbfile] "
		"policy=policyname" },
	{ "create",	kc_create,
		"create [dbfile=dbfile] policy=policyname\n"
		"\t\t[ignore-date=true|false]\n"
		"\t\t[ignore-unknown-eku=true|false]\n"
		"\t\t[ignore-trust-anchor=true|false]\n"
		"\t\t[validity-adjusttime=adjusttime]\n"
		"\t\t[ta-name=trust anchor subject DN]\n"
		"\t\t[ta-serial=trust anchor serial number]\n"
		"\t\t[ocsp-responder=URL]\n"
		"\t\t[ocsp-proxy=URL]\n"
		"\t\t[ocsp-use-cert-responder=true|false]\n"
		"\t\t[ocsp-response-lifetime=timelimit]\n"
		"\t\t[ocsp-ignore-response-sign=true|false]\n"
		"\t\t[ocsp-responder-cert-name=Issuer DN]\n"
		"\t\t[ocsp-responder-cert-serial=serial number]\n"
		"\t\t[crl-basefilename=basefilename]\n"
		"\t\t[crl-directory=directory]\n"
		"\t\t[crl-get-crl-uri=true|false]\n"
		"\t\t[crl-proxy=URL]\n"
		"\t\t[crl-ignore-crl-sign=true|false]\n"
		"\t\t[crl-ignore-crl-date=true|false]\n"
		"\t\t[keyusage=digitalSignature|nonRepudiation\n\t"
		"\t\t|keyEncipherment | dataEncipherment |\n\t"
		"\t\tkeyAgreement |keyCertSign |\n\t"
		"\t\tcRLSign | encipherOnly | decipherOnly],[...]\n"
		"\t\t[ekunames=serverAuth | clientAuth |\n\t"
		"\t\tcodeSigning | emailProtection |\n\t"
		"\t\tipsecEndSystem | ipsecTunnel |\n\t"
		"\t\tipsecUser | timeStamping |\n\t"
		"\t\tOCSPSigning],[...]\n"
		"\t\t[ekuoids=OID,OID,OID...]\n"
		"\t\t[mapper-name=name of mapper library]\n"
		"\t\t[mapper-directory=dir where mapper library resides]\n"
		"\t\t[mapper-path=full pathname of mapper library]\n"
		"\t\t[mapper-options=mapper options]\n"},
	{ "modify",	kc_modify,
		"modify [dbfile=dbfile] policy=policyname\n"
		"\t\t[ignore-date=true|false]\n"
		"\t\t[ignore-unknown-eku=true|false]\n"
		"\t\t[ignore-trust-anchor=true|false]\n"
		"\t\t[validity-adjusttime=adjusttime]\n"
		"\t\t[ta-name=trust anchor subject DN | search]\n"
		"\t\t[ta-serial=trust anchor serial number]\n"
		"\t\t[ocsp-responder=URL]\n"
		"\t\t[ocsp-proxy=URL]\n"
		"\t\t[ocsp-use-cert-responder=true|false]\n"
		"\t\t[ocsp-response-lifetime=timelimit]\n"
		"\t\t[ocsp-ignore-response-sign=true|false]\n"
		"\t\t[ocsp-responder-cert-name=Issuer DN]\n"
		"\t\t[ocsp-responder-cert-serial=serial number]\n"
		"\t\t[ocsp-none=true|false]\n"
		"\t\t[crl-basefilename=basefilename]\n"
		"\t\t[crl-directory=directory]\n"
		"\t\t[crl-get-crl-uri=true|false]\n"
		"\t\t[crl-proxy=URL]\n"
		"\t\t[crl-ignore-crl-sign=true|false]\n"
		"\t\t[crl-ignore-crl-date=true|false]\n"
		"\t\t[crl-none=true|false]\n"
		"\t\t[keyusage=digitalSignature|nonRepudiation\n\t"
		"\t\t|keyEncipherment | dataEncipherment |\n\t"
		"\t\tkeyAgreement |keyCertSign |\n\t"
		"\t\tcRLSign | encipherOnly | decipherOnly],[...]\n"
		"\t\t[keyusage-none=true|false]\n"
		"\t\t[ekunames=serverAuth | clientAuth |\n\t"
		"\t\tcodeSigning | emailProtection |\n\t"
		"\t\tipsecEndSystem | ipsecTunnel |\n\t"
		"\t\tipsecUser | timeStamping |\n\t"
		"\t\tOCSPSigning],[...]\n"
		"\t\t[ekuoids=OID,OID,OID...]\n"
		"\t\t[eku-none=true|false]\n\n"
		"\t\t[mapper-name=name of mapper library]\n"
		"\t\t[mapper-directory=dir where mapper library resides]\n"
		"\t\t[mapper-path=full pathname of mapper library]\n"
		"\t\t[mapper-options=mapper options]\n"
		"\tmodify plugin keystore=keystorename option=optionstring\n"},

	{ "import",	kc_import, "import [dbfile=dbfile] policy=policyname "
		"infile=inputdbfile\n" },
	{ "export",	kc_export, "export [dbfile=dbfile] policy=policyname "
		"outfile=newdbfile\n" },
	{ "install", 	kc_install, "install keystore=keystorename "
		"modulepath=path [option=optionstring]\n"},
	{ "uninstall", 	kc_uninstall, "uninstall keystore=keystorename\n"},
	{ "-?",		kc_help, 	"help"},
	{ "help",	kc_help, 	""}
};

static int num_cmds = sizeof (cmds) / sizeof (verbcmd);
static char *prog;

static void
usage(void)
{
	int i;

	/* Display this block only in command-line mode. */
	(void) fprintf(stdout, gettext("Usage:\n"));
	(void) fprintf(stdout, gettext("\t%s -?\t(help and usage)\n"), prog);
	(void) fprintf(stdout, gettext("\t%s subcommand [options...]\n"), prog);
	(void) fprintf(stdout, gettext("where subcommands may be:\n"));

	/* Display only those verbs that match the current tool mode. */
	for (i = 0; i < num_cmds; i++) {
		/* Do NOT i18n/l10n. */
		(void) fprintf(stdout, "\t%s\n", cmds[i].synopsis);
	}
}

static int
kc_help()
{
	usage();
	return (0);
}

int
main(int argc, char *argv[])
{
	int ret;
	int found;
	int i;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)		/* Should be defined by cc -D. */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it isn't. */
#endif
	(void) textdomain(TEXT_DOMAIN);

	prog = basename(argv[0]);
	argv++; argc--;

	if (argc == 0) {
		usage();
		exit(1);
	}

	if (argc == 1 && argv[0][0] == '-') {
		switch (argv[0][1]) {
			case '?':
				return (kc_help());
			default:
				usage();
				exit(1);
		}
	}

	found = -1;
	for (i = 0; i < num_cmds; i++) {
		if (strcmp(cmds[i].verb, argv[0]) == 0) {
			found = i;
			break;
		}
	}

	if (found < 0) {
		(void) fprintf(stderr, gettext("Invalid command: %s\n"),
		    argv[0]);
		exit(1);
	}

	/*
	 * Note the action functions can return values from
	 * the key management framework, and those values can conflict
	 * with the utility error codes.
	 */
	ret = (*cmds[found].action)(argc, argv);

	switch (ret) {
		case KC_OK:
			break;
		case KC_ERR_USAGE:
			break;
		case KC_ERR_LOADDB:
			(void) fprintf(stderr,
			    gettext("Error loading database\n"));
			break;
		case KC_ERR_FIND_POLICY:
			break;
		case KC_ERR_DELETE_POLICY:
			(void) fprintf(stderr, gettext("Error deleting policy "
			    "from database.\n"));
			break;
		case KC_ERR_ADD_POLICY:
			break;
		case KC_ERR_VERIFY_POLICY:
			break;
		case KC_ERR_INCOMPLETE_POLICY:
			break;
		case KC_ERR_MEMORY:
			(void) fprintf(stderr, gettext("Out of memory.\n"));
			break;
		case KC_ERR_ACCESS:
			break;
		case KC_ERR_INSTALL:
			break;
		case KC_ERR_UNINSTALL:
			break;
		default:
			(void) fprintf(stderr, gettext("%s operation failed. "
			    "error 0x%02x\n"), cmds[found].verb, ret);
			break;
	}

	return (ret);
}
