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
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <locale.h>
#include <sys/param.h>
#include <openssl/bio.h>

#include <libinst.h>
#include <pkglib.h>
#include <pkgerr.h>
#include <keystore.h>
#include "pkgadm.h"
#include "pkgadm_msgs.h"

/*
 * Name:	listcert
 * Desc:  Lists one or more certificates from the keystore
 * Syntax:	listcert [-a app] [-f format] [-k keystore] \
 *	[-n name] [-o outfile] [-P passarg] [-R altroot]
 */
int
listcert(int argc, char **argv)
{
	int				i;
	char				keystore_file[MAXPATHLEN] = "";
	char				*keystore_base = NULL;
	char				*homedir;
	char				*passarg = NULL;
	char				*altroot = NULL;
	char				*prog = NULL;
	char				*format_str = NULL;
	keystore_encoding_format_t	format;
	char				*alias = NULL;
	char				*outfile_str = NULL;
	FILE				*outfile = NULL;
	int				ret = 1;
	PKG_ERR				*err = NULL;
	keystore_handle_t		keystore = NULL;

	while ((i = getopt(argc, argv, ":a:f:k:n:o:P:R:")) != EOF) {
		switch (i) {
		case 'a':
			prog = optarg;
			break;
		case 'f':
			format_str = optarg;
			break;
		case 'k':
			keystore_base = optarg;
			break;
		case 'n':
			alias = optarg;
			break;
		case 'o':
			outfile_str = optarg;
			break;
		case 'P':
			passarg = optarg;
			break;
		case 'R':
			altroot = optarg;
			break;
		case ':':
			log_msg(LOG_MSG_ERR, MSG_MISSING_OPERAND, optopt);
			/* fallthrough intentional */
		case '?':
		default:
			log_msg(LOG_MSG_ERR, MSG_USAGE);
			goto cleanup;
		}
	}

	/* should be no arguments left */
	if ((argc-optind) > 0) {
		log_msg(LOG_MSG_ERR, MSG_USAGE);
		goto cleanup;
	}

	/* figure out format */
	if (format_str == NULL) {
		format = KEYSTORE_FORMAT_TEXT;
	} else {
		if (ci_streq(format_str, "text")) {
			format = KEYSTORE_FORMAT_TEXT;
		} else if (ci_streq(format_str, "pem")) {
			format = KEYSTORE_FORMAT_PEM;
		} else if (ci_streq(format_str, "der")) {
			format = KEYSTORE_FORMAT_DER;
		} else {
			log_msg(LOG_MSG_ERR, MSG_BAD_FORMAT, format_str);
			goto cleanup;
		}
	}

	/* open output file */
	if (outfile_str == NULL) {
		outfile = stdout;
		outfile_str = "stdout";
	} else {
		if ((outfile = fopen(outfile_str, "w+")) == NULL) {
			log_msg(LOG_MSG_ERR, MSG_OPEN_WRITE, outfile_str);
			goto cleanup;
		}
	}

	/* set up proper keystore */
	if (altroot != NULL) {
	    if (strlcpy(keystore_file, altroot, MAXPATHLEN) >= MAXPATHLEN) {
		log_msg(LOG_MSG_ERR, MSG_TOO_LONG, altroot);
		goto cleanup;
	    }

	    if (strlcat(keystore_file, "/", MAXPATHLEN) >= MAXPATHLEN) {
		log_msg(LOG_MSG_ERR, MSG_TOO_LONG, altroot);
		goto cleanup;
	    }
	}

	if (keystore_base == NULL) {
		if (geteuid() == 0 || altroot != NULL) {
				/*
				 * If we have an alternate
				 * root, then we have no choice but to use
				 * root's keystore on that alternate root,
				 * since there is no way to resolve a
				 * user's home dir given an alternate root
				 */
			if (strlcat(keystore_file, PKGSEC,
			    MAXPATHLEN) >= MAXPATHLEN) {
				log_msg(LOG_MSG_ERR, MSG_TOO_LONG,
				    keystore_file);
				goto cleanup;
			}
		} else {
			if ((homedir = getenv("HOME")) == NULL) {
				/*
				 * not superuser, but no home dir, so
				 * use superuser's keystore
				 */
				if (strlcat(keystore_file, PKGSEC,
				    MAXPATHLEN) >= MAXPATHLEN) {
					log_msg(LOG_MSG_ERR, MSG_TOO_LONG,
					    keystore_file);
					goto cleanup;
				}
			} else {
				if (strlcat(keystore_file, homedir,
				    MAXPATHLEN) >= MAXPATHLEN) {
					log_msg(LOG_MSG_ERR, MSG_TOO_LONG,
					    homedir);
					goto cleanup;
				}
				if (strlcat(keystore_file, "/.pkg/security",
				    MAXPATHLEN) >= MAXPATHLEN) {
					log_msg(LOG_MSG_ERR, MSG_TOO_LONG,
					    keystore_file);
					goto cleanup;
				}
			}
		}
	} else {
		if (strlcat(keystore_file, keystore_base,
		    MAXPATHLEN) >= MAXPATHLEN) {
		    log_msg(LOG_MSG_ERR, MSG_TOO_LONG,
			keystore_base);
		    goto cleanup;
		}
	}
	err = pkgerr_new();

	/* now load the key store */
	log_msg(LOG_MSG_DEBUG, "Loading keystore <%s>", keystore_file);

	set_passphrase_prompt(MSG_KEYSTORE_PASSPROMPT);
	set_passphrase_passarg(passarg);
	if (open_keystore(err, keystore_file, prog,
	    pkg_passphrase_cb, KEYSTORE_DFLT_FLAGS,
	    &keystore) != 0) {
		log_pkgerr(LOG_MSG_ERR, err);
		log_msg(LOG_MSG_ERR, MSG_PRINT, outfile_str);
		goto cleanup;
	}

	/* list the certs */
	log_msg(LOG_MSG_DEBUG, "Listing certificates");
	if (print_certs(err, keystore, alias, format, outfile) != 0) {
		log_pkgerr(LOG_MSG_ERR, err);
	    log_msg(LOG_MSG_ERR, MSG_PRINT, outfile_str);
		goto cleanup;
	}

	/* now close it out */
	log_msg(LOG_MSG_DEBUG, "Closing keystore");
	set_passphrase_prompt(MSG_KEYSTORE_PASSOUTPROMPT);
	set_passphrase_passarg(passarg);
	if (close_keystore(err, keystore, pkg_passphrase_cb) != 0) {
		log_pkgerr(LOG_MSG_ERR, err);
		log_msg(LOG_MSG_ERR, MSG_PRINT, outfile_str);
		goto cleanup;
	}

	/* everything worked */
	ret = 0;

	/* fallthrough intentional */
cleanup:
	if (outfile != NULL)
		(void) fclose(outfile);

	if (err != NULL)
		pkgerr_free(err);

	return (ret);
}
