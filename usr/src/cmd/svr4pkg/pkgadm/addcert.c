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
#include <openssl/x509v3.h>
#include <openssl/ui.h>

#include <pkglib.h>
#include <libinst.h>
#include <pkgerr.h>
#include <keystore.h>
#include "pkgadm.h"
#include "pkgadm_msgs.h"

typedef enum {
	VerifyFailed,
	Accept,
	Reject
} VerifyStatus;

static VerifyStatus	verify_trust(X509 *);
static boolean_t	is_ca_cert(X509 *);

/*
 * Name:	addcert
 * Desc:  	Imports a user certificate into the keystore, along with a
 *		private key.
 * Returns:	0 on success, non-zero otherwise.
 */
int
addcert(int argc, char **argv)
{
	int i;
	char	keystore_file[MAXPATHLEN] = "";
	char	*keystore_base = NULL;
	char	*homedir;
	char	*passarg = NULL;
	char	*import_passarg = NULL;
	char	*altroot = NULL;
	char	*prog = NULL;
	char	*alias = NULL;
	char	*infile = NULL;
	char	*inkeyfile = NULL;
	keystore_encoding_format_t	informat = NULL;
	char	*informat_str = NULL;
	int	ret = 1;
	boolean_t	trusted = B_FALSE;
	boolean_t	implicit_trust = B_FALSE;

	FILE	*certfile = NULL;
	FILE	*keyfile = NULL;
	X509	*cert = NULL;
	STACK_OF(X509) *trustcerts = NULL;
	EVP_PKEY *key = NULL;
	PKG_ERR	*err = NULL;
	keystore_handle_t	keystore = NULL;

	while ((i = getopt(argc, argv, ":a:k:e:f:n:P:p:R:ty")) != EOF) {
		switch (i) {
		case 'a':
			prog = optarg;
			break;
		case 'k':
			keystore_base = optarg;
			break;
		case 'e':
			inkeyfile = optarg;
			break;
		case 'f':
			informat_str = optarg;
			break;
		case 'n':
			alias = optarg;
			break;
		case 'P':
			passarg = optarg;
			break;
		case 'p':
			import_passarg = optarg;
			break;
		case 'R':
			altroot = optarg;
			break;
		case 't':
			trusted = B_TRUE;
			break;
		case 'y':
			implicit_trust = B_TRUE;
			break;
		case ':':
			log_msg(LOG_MSG_ERR, MSG_MISSING_OPERAND, optopt);
			/* LINTED fallthrough intentional */
		case '?':
		default:
			log_msg(LOG_MSG_ERR, MSG_USAGE);
			goto cleanup;
		}
	}

	if (!trusted && alias == NULL) {
		/* for untrusted (user) certs, we require a name */
		log_msg(LOG_MSG_ERR, MSG_USER_NAME);
		log_msg(LOG_MSG_ERR, MSG_USAGE);
		goto cleanup;
	} else if (trusted && alias != NULL) {
		/* for trusted certs, we cannot have a name */
		log_msg(LOG_MSG_ERR, MSG_TRUSTED_NAME);
		log_msg(LOG_MSG_ERR, MSG_USAGE);
		goto cleanup;
	}

	if (trusted && inkeyfile != NULL) {
		/* for trusted certs, we cannot have a private key */
		log_msg(LOG_MSG_ERR, MSG_TRUSTED_KEY);
		log_msg(LOG_MSG_ERR, MSG_USAGE);
		goto cleanup;
	}

	/* last argument should be the path to the certificate */
	if ((argc-optind) > 1) {
	    log_msg(LOG_MSG_ERR, MSG_USAGE);
	    goto cleanup;
	} else if ((argc-optind) < 1) {
		infile = "stdin";
		certfile = stdin;
		log_msg(LOG_MSG_DEBUG, "Loading stdin certificate");
	} else {
		infile = argv[optind];
		log_msg(LOG_MSG_DEBUG, "Loading <%s> certificate",
		    argv[optind]);
		if ((certfile = fopen(infile, "r")) == NULL) {
			log_msg(LOG_MSG_ERR, MSG_OPEN, infile);
			goto cleanup;
		}
	}

	/*
	 * if specific key file supplied, open it, otherwise open
	 * default (stdin)
	 */
	if (inkeyfile != NULL) {
		if ((keyfile = fopen(inkeyfile, "r")) == NULL) {
			log_msg(LOG_MSG_ERR, MSG_OPEN, inkeyfile);
			goto cleanup;
		}
	} else {
		inkeyfile = "stdin";
		keyfile = stdin;
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

	/* figure out input format */
	if (informat_str == NULL) {
		informat = KEYSTORE_FORMAT_PEM;
	} else {
		if (ci_streq(informat_str, "pem")) {
			informat = KEYSTORE_FORMAT_PEM;
		} else if (ci_streq(informat_str, "der")) {
			informat = KEYSTORE_FORMAT_DER;
		} else {
			log_msg(LOG_MSG_ERR, MSG_BAD_FORMAT, informat_str);
			goto cleanup;
		}
	}

	err = pkgerr_new();

	if (trusted) {
		/* load all possible certs */
		if (load_all_certs(err, certfile, informat, import_passarg,
		    &trustcerts) != 0) {
			log_pkgerr(LOG_MSG_ERR, err);
			log_msg(LOG_MSG_ERR, MSG_NO_ADDCERT, infile);
			goto cleanup;
		}

		/* we must have gotten at least one cert, if not, fail */
		if (sk_X509_num(trustcerts) < 1) {
			log_msg(LOG_MSG_ERR, MSG_NO_CERTS, infile);
			goto cleanup;
		}
	} else {
		/* first, try to load user certificate and key */
		if (load_cert_and_key(err, certfile, informat, import_passarg,
		    &key, &cert) != 0) {
			log_pkgerr(LOG_MSG_ERR, err);
			log_msg(LOG_MSG_ERR, MSG_NO_ADDCERT, infile);
			goto cleanup;
		}

		/* we must have gotten a cert, if not, fail */
		if (cert == NULL) {
			log_msg(LOG_MSG_ERR, MSG_NO_CERTS, infile);
			goto cleanup;
		}

		if (key == NULL) {
			/*
			 * if we are importing a user cert, and did not get
			 * a key, try to load it from the key file
			 */
			if (keyfile == NULL) {
				log_msg(LOG_MSG_ERR, MSG_NEED_KEY, infile);
				goto cleanup;
			} else {
				log_msg(LOG_MSG_DEBUG,
				    "Loading private key <%s>", inkeyfile);
				if (load_cert_and_key(err, keyfile, informat,
				    import_passarg,
				    &key, NULL) != 0) {
					log_pkgerr(LOG_MSG_ERR, err);
					log_msg(LOG_MSG_ERR,
					    MSG_NO_ADDKEY, inkeyfile);
					goto cleanup;
				}

				if (key == NULL) {
					log_msg(LOG_MSG_ERR, MSG_NO_PRIVKEY,
					    inkeyfile);
					log_msg(LOG_MSG_ERR,
					    MSG_NO_ADDKEY, inkeyfile);
					goto cleanup;
				}
			}
		}
	}

	if (trusted) {
		/* check validity date of all certificates */
		for (i = 0; i < sk_X509_num(trustcerts); i++) {
			/* LINTED pointer cast may result in improper algnmnt */
			cert = sk_X509_value(trustcerts, i);
			if (check_cert(err, cert) != 0) {
				log_pkgerr(LOG_MSG_ERR, err);
				log_msg(LOG_MSG_ERR, MSG_NO_ADDCERT,
				    infile);
				goto cleanup;
			}
		}
	} else {
		/* check validity date of user certificate */
		if (check_cert_and_key(err, cert, key) != 0) {
			log_pkgerr(LOG_MSG_ERR, err);
			log_msg(LOG_MSG_ERR, MSG_NO_ADDCERT, infile);
			goto cleanup;
		}
	}

	if (trusted && !implicit_trust) {
		/*
		 * if importing more than one cert, must use implicit trust,
		 * because we can't ask the user to individually trust
		 * each one, since there may be many
		 */
		if (sk_X509_num(trustcerts) != 1) {
			log_pkgerr(LOG_MSG_ERR, err);
			log_msg(LOG_MSG_ERR, MSG_MULTIPLE_TRUST, infile, "-y");
			goto cleanup;
		} else {
			/* LINTED pointer cast may result in improper algnmnt */
			cert = sk_X509_value(trustcerts, 0);
		}

		/* ask the user */
		switch (verify_trust(cert)) {
		case Accept:
			/* user accepted */
			break;
		case Reject:
			/* user aborted operation */
			log_msg(LOG_MSG_ERR, MSG_ADDCERT_ABORT);
			goto cleanup;
		case VerifyFailed:
		default:
			log_msg(LOG_MSG_ERR, MSG_NO_ADDCERT, infile);
			goto cleanup;
		}
	}

	/* now load the key store */
	log_msg(LOG_MSG_DEBUG, "Loading keystore <%s>", keystore_file);

	set_passphrase_prompt(MSG_KEYSTORE_PASSPROMPT);
	set_passphrase_passarg(passarg);
	if (open_keystore(err, keystore_file, prog, pkg_passphrase_cb,
	    KEYSTORE_ACCESS_READWRITE | KEYSTORE_PATH_HARD, &keystore) != 0) {
		log_pkgerr(LOG_MSG_ERR, err);
		log_msg(LOG_MSG_ERR, MSG_NO_ADDCERT, infile);
		goto cleanup;
	}

	/* now merge the new cert into the keystore */
	log_msg(LOG_MSG_DEBUG, "Merging certificate <%s>",
	    get_subject_display_name(cert));
	if (trusted) {
		/* merge all trusted certs found */
		for (i = 0; i < sk_X509_num(trustcerts); i++) {
			/* LINTED pointer cast may result in improper algnmnt */
			cert = sk_X509_value(trustcerts, i);
			if (merge_ca_cert(err, cert, keystore) != 0) {
				log_pkgerr(LOG_MSG_ERR, err);
				log_msg(LOG_MSG_ERR,
				    MSG_NO_ADDCERT, infile);
				goto cleanup;

			} else {
				log_msg(LOG_MSG_INFO, MSG_TRUSTING,
				    get_subject_display_name(cert));
			}
		}
	} else {
		/* merge user cert */
		if (merge_cert_and_key(err, cert, key, alias, keystore) != 0) {
			log_pkgerr(LOG_MSG_ERR, err);
			log_msg(LOG_MSG_ERR, MSG_NO_ADDCERT, infile);
			goto cleanup;
		}
	}

	/* now write it back out */
	log_msg(LOG_MSG_DEBUG, "Closing keystore");
	set_passphrase_prompt(MSG_KEYSTORE_PASSOUTPROMPT);
	set_passphrase_passarg(passarg);
	if (close_keystore(err, keystore, pkg_passphrase_cb) != 0) {
		log_pkgerr(LOG_MSG_ERR, err);
		log_msg(LOG_MSG_ERR, MSG_NO_ADDCERT, infile);
		goto cleanup;
	}

	if (trusted) {
		log_msg(LOG_MSG_INFO, MSG_TRUSTED, infile);
	} else {
		log_msg(LOG_MSG_INFO, MSG_ADDED, infile, alias);
	}

	ret = 0;

	/* fallthrough intentional */
cleanup:
	if (err != NULL)
		pkgerr_free(err);

	if (certfile != NULL)
		(void) fclose(certfile);

	if (keyfile != NULL)
		(void) fclose(keyfile);

	return (ret);
	}

/* Asks user to verify certificate data before proceeding */
static VerifyStatus verify_trust(X509 *cert)
{
	char		vfy_trust = 'y';
	VerifyStatus	ret = Accept;
	PKG_ERR		*err;
	UI		*ui = NULL;

	err = pkgerr_new();
	/* print cert data */
	if (print_cert(err, cert, KEYSTORE_FORMAT_TEXT,
	    get_subject_display_name(cert), B_TRUE, stdout) != 0) {
		log_pkgerr(LOG_MSG_ERR, err);
		ret = VerifyFailed;
		goto cleanup;
	}

	if ((ui = UI_new()) == NULL) {
		log_msg(LOG_MSG_ERR, MSG_MEM);
		ret = VerifyFailed;
		goto cleanup;
	}

	/*
	 * The prompt is internationalized, but the valid
	 * response values are fixed, to avoid any complex
	 * multibyte processing that results in bugs
	 */
	if (UI_add_input_boolean(ui, MSG_VERIFY_TRUST,
	    "",
	    "yY", "nN",
	    UI_INPUT_FLAG_ECHO, &vfy_trust) <= 0) {
		log_msg(LOG_MSG_ERR, MSG_MEM);
		ret = VerifyFailed;
		goto cleanup;
	}

	if (UI_process(ui) != 0) {
		log_msg(LOG_MSG_ERR, MSG_MEM);
		ret = VerifyFailed;
		goto cleanup;
	}

	if (vfy_trust != 'y') {
		ret = Reject;
		goto cleanup;
	}

	/*
	 * if the cert does not appear to be a CA cert
	 * r is not self-signed, verify that as well
	 */
	if (!is_ca_cert(cert)) {
		UI_free(ui);
		if ((ui = UI_new()) == NULL) {
			log_msg(LOG_MSG_ERR, MSG_MEM);
			ret = VerifyFailed;
			goto cleanup;
		}

		if (UI_add_input_boolean(ui,
		    MSG_VERIFY_NOT_CA,
		    "",
		    "yY", "nN",
		    UI_INPUT_FLAG_ECHO, &vfy_trust) <= 0) {
			ret = VerifyFailed;
			goto cleanup;
		}

		if (UI_process(ui) != 0) {
			log_msg(LOG_MSG_ERR, MSG_MEM);
			ret = VerifyFailed;
			goto cleanup;
		}

		if (vfy_trust != 'y') {
			ret = Reject;
			goto cleanup;
		}
	}

cleanup:
	if (ui != NULL)
		UI_free(ui);

	if (err != NULL)
		pkgerr_free(err);

	return (ret);
}
/*
 *	Name:	is_ca_cert
 *	Desc:	Determines if a given certificate has the attributes
 *		of a CA certificate
 *	Returns: B_TRUE if certificate has attributes of a CA cert
 *		B_FALSE otherwise
 */
static boolean_t
is_ca_cert(X509 *x)
{

	/*
	 * X509_check_purpose causes the extensions that we
	 * care about to be decoded and stored in the X509
	 * structure, so we must call it first
	 * before checking for CA extensions in the X509
	 * structure
	 */
	(void) X509_check_purpose(x, X509_PURPOSE_ANY, 0);

	/* keyUsage if present should allow cert signing */
	if ((x->ex_flags & EXFLAG_KUSAGE) &&
	    !(x->ex_kusage & KU_KEY_CERT_SIGN)) {
		return (B_FALSE);
	}

	/* If basicConstraints says not a CA then say so */
	if (x->ex_flags & EXFLAG_BCONS) {
		if (!(x->ex_flags & EXFLAG_CA)) {
			return (B_FALSE);
		}
	}

	/* no explicit not-a-CA flags set, so assume that it is */
	return (B_TRUE);
}
