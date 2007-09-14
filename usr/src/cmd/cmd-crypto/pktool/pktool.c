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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file comprises the main driver for this tool.
 * Upon parsing the command verbs from user input, it
 * branches to the appropriate modules to perform the
 * requested task.
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <malloc.h>
#include <libgen.h>
#include <errno.h>
#include <cryptoutil.h>
#include <security/cryptoki.h>
#include "common.h"

/*
 * The verbcmd construct allows genericizing information about a verb so
 * that it is easier to manipulate.  Makes parsing code easier to read,
 * fix, and extend with new verbs.
 */
typedef struct verbcmd_s {
	char	*verb;
	int	(*action)(int, char *[]);
	int	mode;
	char	*summary;
	char	*synopsis;
} verbcmd;

/* External declarations for supported verb actions. */
extern int	pk_setpin(int argc, char *argv[]);
extern int	pk_list(int argc, char *argv[]);
extern int	pk_delete(int argc, char *argv[]);
extern int	pk_import(int argc, char *argv[]);
extern int	pk_export(int argc, char *argv[]);
extern int	pk_tokens(int argc, char *argv[]);
extern int	pk_gencert(int argc, char *argv[]);
extern int	pk_gencsr(int argc, char *argv[]);
extern int	pk_download(int argc, char *argv[]);
extern int	pk_genkey(int argc, char *argv[]);

/* Forward declarations for "built-in" verb actions. */
static int	pk_help(int argc, char *argv[]);

/* Command structure for verbs and their actions.  Do NOT i18n/l10n. */
static verbcmd	cmds[] = {
	{ "tokens",	pk_tokens,	0,
		"lists all visible PKCS#11 tokens", "tokens" },
	{ "setpin",	pk_setpin,	0,
		"changes user authentication passphrase for keystore access",
		"setpin [ keystore=pkcs11 ]\n\t\t"
		"[ token=token[:manuf[:serial]]]\n\t"

		"setpin keystore=nss\n\t\t"
		"[ token=token ]\n\t\t"
		"[ dir=directory-path ]\n\t\t"
		"[ prefix=DBprefix ]\n\t"
	},
	{ "list",	pk_list,	0,
		"lists a summary of objects in the keystore",
	"list [ token=token[:manuf[:serial]]]\n\t\t"
		"[ objtype=private|public|both ]\n\t\t"
		"[ label=label ]\n\t"

	"list objtype=cert[:[public | private | both ]]\n\t\t"
		"[ subject=subject-DN ]\n\t\t"
		"[ keystore=pkcs11 ]\n\t\t"
		"[ issuer=issuer-DN ]\n\t\t"
		"[ serial=serial number ]\n\t\t"
		"[ label=cert-label ]\n\t\t"
		"[ token=token[:manuf[:serial]]]\n\t\t"
		"[ criteria=valid|expired|both ]\n\t"

	"list objtype=key[:[public | private | both ]]\n\t\t"
		"[ keystore=pkcs11 ]\n\t\t"
		"[ subject=subject-DN ]\n\t\t"
		"[ label=key-label ]\n\t\t"
		"[ token=token[:manuf[:serial]]]\n\t"

	"list keystore=pkcs11 objtype=crl\n\t\t"
		"infile=crl-fn\n\t\t"
		"[ dir=directory-path ]\n\t"

	"list keystore=nss objtype=cert\n\t\t"
		"[ subject=subject-DN ]\n\t\t"
		"[ issuer=issuer-DN ]\n\t\t"
		"[ serial=serial number ]\n\t\t"
		"[ nickname=cert-nickname ]\n\t\t"
		"[ token=token[:manuf[:serial]]]\n\t\t"
		"[ dir=directory-path ]\n\t\t"
		"[ prefix=DBprefix ]\n\t\t"
		"[ criteria=valid|expired|both ]\n\t"

	"list keystore=nss objtype=key\n\t\t"
		"[ token=token[:manuf[:serial]]]\n\t\t"
		"[ dir=directory-path ]\n\t\t"
		"[ prefix=DBprefix ]\n\t\t"
		"[ nickname=key-nickname ]\n\t"

	"list keystore=file objtype=cert\n\t\t"
		"[ subject=subject-DN ]\n\t\t"
		"[ issuer=issuer-DN ]\n\t\t"
		"[ serial=serial number ]\n\t\t"
		"[ infile=cert-fn ]\n\t\t"
		"[ dir=directory-path ]\n\t\t"
		"[ criteria=valid|expired|both ]\n\t"

	"list keystore=file objtype=key\n\t\t"
		"[ infile=key-fn ]\n\t\t"
		"[ dir=directory-path ]\n\t"

	"list keystore=file objtype=crl\n\t\t"
		"infile=crl-fn\n\t\t"
		"[ dir=directory-path ]\n\t"
	},

	{ "delete",	pk_delete,	0,
		"deletes objects in the keystore",

	"delete [ token=token[:manuf[:serial]]]\n\t\t"
		"[ objtype=private|public|both ]\n\t\t"
		"[ label=object-label ]\n\t"

	"delete keystore=nss objtype=cert\n\t\t"
		"[ subject=subject-DN ]\n\t\t"
		"[ issuer=issuer-DN ]\n\t\t"
		"[ serial=serial number ]\n\t\t"
		"[ label=cert-label ]\n\t\t"
		"[ token=token[:manuf[:serial]]]\n\t\t"
		"[ dir=directory-path ]\n\t\t"
		"[ prefix=DBprefix ]\n\t\t"
		"[ criteria=valid|expired|both ]\n\t"

	"delete keystore=nss objtype=key\n\t\t"
		"[ token=token[:manuf[:serial]]]\n\t\t"
		"[ dir=directory-path ]\n\t\t"
		"[ prefix=DBprefix ]\n\t\t"
		"[ nickname=key-nickname ]\n\t\t"

	"delete keystore=nss objtype=crl\n\t\t"
		"[ nickname=issuer-nickname ]\n\t\t"
		"[ subject=subject-DN ]\n\t\t"
		"[ token=token[:manuf[:serial]]]\n\t\t"
		"[ dir=directory-path ]\n\t\t"
		"[ prefix=DBprefix ]\n\t"

	"delete keystore=pkcs11 objtype=cert[:[public | private | both]]\n\t\t"
		"[ subject=subject-DN ]\n\t\t"
		"[ issuer=issuer-DN ]\n\t\t"
		"[ serial=serial number ]\n\t\t"
		"[ label=cert-label ]\n\t\t"
		"[ token=token[:manuf[:serial]]]\n\t\t"
		"[ criteria=valid|expired|both ]\n\t"

	"delete keystore=pkcs11 objtype=key[:[public | private | both]]\n\t\t"
		"[ subject=subject-DN ]\n\t\t"
		"[ label=key-label ]\n\t\t"
		"[ token=token[:manuf[:serial]]]\n\t"

	"delete keystore=pkcs11 objtype=crl\n\t\t"
		"infile=crl-fn\n\t\t"
		"[ dir=directory-path ]\n\t"

	"delete keystore=file objtype=cert\n\t\t"
		"[ subject=subject-DN ]\n\t\t"
		"[ issuer=issuer-DN ]\n\t\t"
		"[ serial=serial number ]\n\t\t"
		"[ infile=cert-fn ]\n\t\t"
		"[ dir=directory-path ]\n\t\t"
		"[ criteria=valid|expired|both ]\n\t"

	"delete keystore=file objtype=key\n\t\t"
		"[ infile=key-fn ]\n\t\t"
		"[ dir=directory-path ]\n\t"

	"delete keystore=file objtype=crl\n\t\t"
		"infile=crl-fn\n\t\t"
		"[ dir=directory-path ]\n\t"
	},
	{ "import",	pk_import,	0,
		"imports objects from an external source",

	"import [token=token[:manuf[:serial]]]\n\t\t"
	"infile=input-fn\n\t"

	"import keystore=nss objtype=cert\n\t\t"
		"infile=input-fn\n\t\t"
		"label=cert-label\n\t\t"
		"[ trust=trust-value ]\n\t\t"
		"[ token=token[:manuf[:serial]]]\n\t\t"
		"[ dir=directory-path ]\n\t\t"
		"[ prefix=DBprefix ]\n\t"

	"import keystore=nss objtype=crl\n\t\t"
		"infile=input-fn\n\t\t"
		"[ verifycrl=y|n ]\n\t\t"
		"[ token=token[:manuf[:serial]]]\n\t\t"
		"[ dir=directory-path ]\n\t\t"
		"[ prefix=DBprefix ]\n\t"

	"import keystore=pkcs11\n\t\t"
		"infile=input-fn\n\t\t"
		"label=label\n\t\t"
		"[ objtype=cert|key ]\n\t\t"
		"[ keytype=aes|arcfour|des|3des|generic ]\n\t\t"
		"[ sensitive=y|n ]\n\t\t"
		"[ extractable=y|n ]\n\t\t"
		"[ token=token[:manuf[:serial]]]\n\t"

	"import keystore=pkcs11 objtype=crl\n\t\t"
		"infile=input-crl-fn\n\t\t"
		"outcrl=output-crl-fn\n\t\t"
		"outformat=pem|der\n\t\t"
		"[ dir=output-crl-directory-path ]\n\t"

	"import keystore=file\n\t\t"
		"infile=input-fn\n\t\t"
		"outkey=output-key-fn\n\t\t"
		"outcert=output-cert-fn\n\t\t"
		"[ dir=output-cert-dir-path ]\n\t\t"
		"[ keydir=output-key-dir-path ]\n\t\t"
		"[ outformat=pem|der|pkcs12 ]\n\t"

	"import keystore=file objtype=crl\n\t\t"
		"infile=input-crl-fn\n\t\t"
		"outcrl=output-crl-fn\n\t\t"
		"outformat=pem|der\n\t\t"
		"[ dir=output-crl-directory-path ]\n\t"
	},

	{ "export",	pk_export,	0,
		"exports objects from the keystore to a file",

	"export [token=token[:manuf[:serial]]]\n\t\t"
	"outfile=output-fn\n\t"

	"export keystore=nss\n\t\t"
		"outfile=output-fn\n\t\t"
		"[ objtype=cert|key ]\n\t\t"
		"[ subject=subject-DN ]\n\t\t"
		"[ issuer=issuer-DN ]\n\t\t"
		"[ serial=serial number ]\n\t\t"
		"[ nickname=cert-nickname ]\n\t\t"
		"[ token=token[:manuf[:serial]]]\n\t\t"
		"[ dir=directory-path ]\n\t\t"
		"[ prefix=DBPrefix ]\n\t\t"
		"[ outformat=pem|der|pkcs12 ]\n\t"

	"export keystore=pkcs11\n\t\t"
		"outfile=output-fn\n\t\t"
		"[ objtype=cert|key ]\n\t\t"
		"[ label=label ]\n\t\t"
		"[ subject=subject-DN ]\n\t\t"
		"[ issuer=issuer-DN ]\n\t\t"
		"[ serial=serial number ]\n\t\t"
		"[ outformat=pem|der|pkcs12|raw ]\n\t\t"
		"[ token=token[:manuf[:serial]]]\n\t"

	"export keystore=file\n\t\t"
		"certfile=cert-input-fn\n\t\t"
		"keyfile=key-input-fn\n\t\t"
		"outfile=output-pkcs12-fn\n\t\t"
		"[ dir=directory-path ]\n\t"
	},

	{ "gencert",	pk_gencert,	0,
		"creates a self-signed X.509v3 certificate",

	"gencert [-i] keystore=nss\n\t\t"
		"label=cert-nickname\n\t\t"
		"serial=serial number hex string]\n\t\t"
		"subject=subject-DN\n\t\t"
		"[ altname=[critical:]SubjectAltName ]\n\t\t"
		"[ keyusage=[critical:]usage,usage,...]\n\t\t"
		"[ token=token[:manuf[:serial]]]\n\t\t"
		"[ dir=directory-path ]\n\t\t"
		"[ prefix=DBprefix ]\n\t\t"
		"[ keytype=rsa|dsa ]\n\t\t"
		"[ keylen=key-size ]\n\t\t"
		"[ trust=trust-value ]\n\t\t"
		"[ lifetime=number-hour|number-day|number-year ]\n\t"

	"gencert [-i] [ keystore=pkcs11 ]\n\t\t"
		"label=key/cert-label\n\t\t"
		"subject=subject-DN\n\t\t"
		"serial=serial number hex string\n\t\t"
		"[ altname=[critical:]SubjectAltName ]\n\t\t"
		"[ keyusage=[critical:]usage,usage,...]\n\t\t"
		"[ token=token[:manuf[:serial]]]\n\t\t"
		"[ keytype=rsa|dsa ]\n\t\t"
		"[ keylen=key-size ]\n\t\t"
		"[ lifetime=number-hour|number-day|number-year ]\n\t"

	"gencert [-i] keystore=file\n\t\t"
		"outcert=cert_filename\n\t\t"
		"outkey=key_filename\n\t\t"
		"subject=subject-DN\n\t\t"
		"serial=serial number hex string\n\t\t"
		"[ altname=[critical:]SubjectAltName ]\n\t\t"
		"[ keyusage=[critical:]usage,usage,...]\n\t\t"
		"[ format=der|pem ]\n\t\t"
		"[ dir=directory-path ]\n\t\t"
		"[ prefix=DBprefix ]\n\t\t"
		"[ keytype=rsa|dsa ]\n\t\t"
		"[ keylen=key-size ]\n\t\t"
		"[ lifetime=number-hour|number-day|number-year ]\n\t"
	},
	{ "gencsr",	pk_gencsr,	0,
		"creates a PKCS#10 certificate signing request file",
	"gencsr [-i] keystore=nss \n\t\t"
		"nickname=cert-nickname\n\t\t"
		"outcsr=csr-fn\n\t\t"
		"subject=subject-DN\n\t\t"
		"[ altname=[critical:]SubjectAltName ]\n\t\t"
		"[ keyusage=[critical:]usage,usage,...]\n\t\t"
		"[ token=token[:manuf[:serial]]]\n\t\t"
		"[ dir=directory-path ]\n\t\t"
		"[ prefix=DBprefix ]\n\t\t"
		"[ keytype=rsa|dsa ]\n\t\t"
		"[ keylen=key-size ]\n\t\t"
		"[ format=pem|der ]\n\t"
	"gencsr [-i] [ keystore=pkcs11 ]\n\t\t"
		"label=key-label\n\t\t"
		"outcsr=csr-fn\n\t\t"
		"subject=subject-DN\n\t\t"
		"[ altname=[critical:]SubjectAltName ]\n\t\t"
		"[ keyusage=[critical:]usage,usage,...]\n\t\t"
		"[ token=token[:manuf[:serial]]]\n\t\t"
		"[ keytype=rsa|dsa ]\n\t\t"
		"[ keylen=key-size ]\n\t\t"
		"[ format=pem|der ]]\n\t"
	"gencsr [-i] keystore=file\n\t\t"
		"outcsr=csr-fn\n\t\t"
		"outkey=key-fn\n\t\t"
		"subject=subject-DN\n\t\t"
		"[ altname=[critical:]SubjectAltName ]\n\t\t"
		"[ keyusage=[critical:]usage,usage,...]\n\t\t"
		"[ keytype=rsa|dsa ]\n\t\t"
		"[ keylen=key-size ]\n\t\t"
		"[ dir=directory-path ]\n\t\t"
		"[ format=pem|der ]\n\t"
	},

	{ "download",	pk_download,	0,
		"downloads a CRL or certificate file from an external source",

	"download url=url_str\n\t\t"
		"[ objtype=crl|cert ]\n\t\t"
		"[ http_proxy=proxy_str ]\n\t\t"
		"[ outfile = outfile ]\n\t\t"
	},

	{ "genkey",	pk_genkey,	0,
		"creates a symmetric key in the keystore",

	"genkey [ keystore=pkcs11 ]\n\t\t"
		"label=key-label\n\t\t"
		"[ keytype=aes|arcfour|des|3des|generic ]\n\t\t"
		"[ keylen=key-size (AES, ARCFOUR or GENERIC only)]\n\t\t"
		"[ token=token[:manuf[:serial]]]\n\t\t"
		"[ sensitive=y|n ]\n\t\t"
		"[ extractable=y|n ]\n\t\t"
		"[ print=y|n ]\n\t"

	"genkey keystore=nss\n\t\t"
		"label=key-label\n\t\t"
		"[ keytype=aes|arcfour|des|3des|generic ]\n\t\t"
		"[ keylen=key-size (AES, ARCFOUR or GENERIC only)]\n\t\t"
		"[ token=token[:manuf[:serial]]]\n\t\t"
		"[ dir=directory-path ]\n\t\t"
		"[ prefix=DBprefix ]\n\t"

	"genkey keystore=file\n\t\t"
		"outkey=key-fn\n\t\t"
		"[ keytype=aes|arcfour|des|3des|generic ]\n\t\t"
		"[ keylen=key-size (AES, ARCFOUR or GENERIC only)]\n\t\t"
		"[ dir=directory-path ]\n\t\t"
		"[ print=y|n ]\n\t"
	},

	{ "help",	pk_help,	0,
		"displays help message",
		"help\t(help and usage)" }
};

static int	num_cmds = sizeof (cmds) / sizeof (verbcmd);

static char	*prog;
static void	usage(int);

/*
 * Usage information.  This function must be updated when new verbs or
 * options are added.
 */
static void
usage(int idx)
{
	int	i;

	/* Display this block only in command-line mode. */
	(void) fprintf(stdout, gettext("Usage:\n"));
	(void) fprintf(stdout, gettext("   %s -?\t(help and usage)\n"),
	    prog);
	(void) fprintf(stdout, gettext("   %s -f option_file\n"), prog);
	(void) fprintf(stdout, gettext("   %s subcommand [options...]\n"),
	    prog);
	(void) fprintf(stdout, gettext("where subcommands may be:\n"));

	/* Display only those verbs that match the current tool mode. */
	if (idx == -1) {
		for (i = 0; i < num_cmds; i++) {
			/* Do NOT i18n/l10n. */
			(void) fprintf(stdout, "   %-8s	- %s\n",
			    cmds[i].verb, cmds[i].summary);
		}
		(void) fprintf(stdout, gettext("\nFurther details on the "
		    "subcommands can be found by adding \'help\'.\n"
		    "Ex: pktool gencert help\n\n"));
	} else {
		(void) fprintf(stdout, "\t%s\n", cmds[idx].synopsis);
	}
}

/*
 * Provide help, in the form of displaying the usage.
 */
static int
pk_help(int argc, char *argv[])
/* ARGSUSED */
{
	usage(-1);
	return (0);
}

/*
 * Process arguments from the argfile and create a new
 * argv/argc list to be processed later.
 */
static int
process_arg_file(char *argfile, char ***argv, int *argc)
{
	FILE *fp;
	char argline[2 * BUFSIZ]; /* 2048 bytes should be plenty */
	char *p;
	int nargs = 0;

	if ((fp = fopen(argfile, "rF")) == NULL) {
		(void) fprintf(stderr,
		    gettext("Cannot read argfile %s: %s\n"),
		    argfile, strerror(errno));
		return (errno);
	}

	while (fgets(argline, sizeof (argline), fp) != NULL) {
		int j;
		/* remove trailing whitespace */
		j = strlen(argline) - 1;
		while (j >= 0 && isspace(argline[j])) {
			argline[j] = 0;
			j--;
		}
		/* If it was a blank line, get the next one. */
		if (!strlen(argline))
			continue;

		(*argv) = realloc((*argv),
		    (nargs + 1) * sizeof (char *));
		if ((*argv) == NULL) {
			perror("memory error");
			(void) fclose(fp);
			return (errno);
		}
		p = (char *)strdup(argline);
		if (p == NULL) {
			perror("memory error");
			(void) fclose(fp);
			return (errno);
		}
		(*argv)[nargs] = p;
		nargs++;
	}
	*argc = nargs;
	(void) fclose(fp);
	return (0);
}

/*
 * MAIN() -- where all the action is
 */
int
main(int argc, char *argv[], char *envp[])
/* ARGSUSED2 */
{
	int	i, found = -1;
	int	rv;
	int	pk_argc = 0;
	char	**pk_argv = NULL;
	int	save_errno = 0;

	/* Set up for i18n/l10n. */
	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)		/* Should be defined by cc -D. */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it isn't. */
#endif
	(void) textdomain(TEXT_DOMAIN);

	/* Get program base name and move pointer over 0th arg. */
	prog = basename(argv[0]);
	argv++, argc--;

	/* Set up for debug and error output. */
	if (argc == 0) {
		usage(-1);
		return (1);
	}

	/* Check for help options.  For CLIP-compliance. */
	if (strcmp(argv[0], "-?") == 0) {
		return (pk_help(argc, argv));
	} else if (strcmp(argv[0], "-f") == 0 && argc == 2) {
		rv = process_arg_file(argv[1], &pk_argv, &pk_argc);
		if (rv)
			return (rv);
	} else if (argc >= 1 && argv[0][0] == '-') {
		usage(-1);
		return (1);
	}

	/* Always turns off Metaslot so that we can see softtoken. */
	if (setenv("METASLOT_ENABLED", "false", 1) < 0) {
		save_errno = errno;
		cryptoerror(LOG_STDERR,
		    gettext("Disabling Metaslot failed (%s)."),
		    strerror(save_errno));
		return (1);
	}

	/* Begin parsing command line. */
	if (pk_argc == 0 && pk_argv == NULL) {
		pk_argc = argc;
		pk_argv = argv;
	}

	/* Check for valid verb (or an abbreviation of it). */
	found = -1;
	for (i = 0; i < num_cmds; i++) {
		if (strcmp(cmds[i].verb, pk_argv[0]) == 0) {
			if (found < 0) {
				found = i;
				break;
			}
		}
	}
	/* Stop here if no valid verb found. */
	if (found < 0) {
		cryptoerror(LOG_STDERR, gettext("Invalid verb: %s"),
		    pk_argv[0]);
		return (1);
	}

	/* Get to work! */
	rv = (*cmds[found].action)(pk_argc, pk_argv);
	switch (rv) {
	case PK_ERR_NONE:
		break;		/* Command succeeded, do nothing. */
	case PK_ERR_USAGE:
		usage(found);
		break;
	case PK_ERR_QUIT:
		exit(0);
		/* NOTREACHED */
	case PK_ERR_PK11:
	case PK_ERR_SYSTEM:
	case PK_ERR_OPENSSL:
	case PK_ERR_NSS:
	default:
		break;
	}
	return (rv);
}
