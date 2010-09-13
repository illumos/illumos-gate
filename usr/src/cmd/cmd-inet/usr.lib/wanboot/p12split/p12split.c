/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <libintl.h>
#include <locale.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wanboot_impl.h>
#include <unistd.h>
#include <string.h>
#include <libinetutil.h>
#include <wanbootutil.h>

#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>
#include <openssl/evp.h>
#include <p12aux.h>

static boolean_t verbose = B_FALSE;	/* When nonzero, do in verbose mode */

/* The following match/cert values require PKCS12 */
static int  matchty;		/* Type of matching do to on input */
static char *k_matchval;	/* localkeyid value to match */
static uint_t k_len;		/* length of k_matchval */

#define	IO_KEYFILE	1	/* Have a separate key file or data */
#define	IO_CERTFILE	2	/* Have a separate cert file or data */
#define	IO_TRUSTFILE	4	/* Have a separate trustanchor file */

static char *input = NULL;	/* Consolidated input file */
static char *key_out = NULL;	/* Key file to be output */
static char *cert_out = NULL;	/* Cert file to be output */
static char *trust_out = NULL;	/* Trust anchor file to be output */
static uint_t outfiles;		/* What files are there for output */
static char *progname;

/* Returns from time_check */
typedef enum {
	CHK_TIME_OK = 0,		/* Cert in effect and not expired */
	CHK_TIME_BEFORE_BAD,		/* not_before field is invalid */
	CHK_TIME_AFTER_BAD,		/* not_after field is invalid */
	CHK_TIME_IS_BEFORE,		/* Cert not yet in force */
	CHK_TIME_HAS_EXPIRED		/* Cert has expired */
} time_errs_t;

static int parse_keyid(const char *);
static int do_certs(void);
static int read_files(STACK_OF(X509) **, X509 **, EVP_PKEY **);
static void check_certs(STACK_OF(X509) *, X509 **);
static time_errs_t time_check_print(X509 *);
static time_errs_t time_check(X509 *);
static int write_files(STACK_OF(X509) *, X509 *, EVP_PKEY *);
static int get_ifile(char *, char *, EVP_PKEY **, X509 **, STACK_OF(X509) **);
static int do_ofile(char *, EVP_PKEY *, X509 *, STACK_OF(X509) *);
static void usage(void);
static const char *cryptoerr(void);

int
main(int argc, char **argv)
{
	int	i;

	/*
	 * Do the necessary magic for localization support.
	 */
	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	progname = strrchr(argv[0], '/');
	if (progname != NULL)
		progname++;
	else
		progname = argv[0];

	wbku_errinit(progname);

	matchty = DO_FIRST_PAIR;
	while ((i = getopt(argc, argv, "vc:i:k:l:t:")) != -1) {
		switch (i) {
		case 'v':
			verbose = B_TRUE;
			break;

		case 'l':
			if (parse_keyid(optarg) < 0)
				return (EXIT_FAILURE);
			matchty = DO_FIND_KEYID;
			break;

		case 'c':
			cert_out = optarg;
			outfiles |= IO_CERTFILE;
			break;

		case 'k':
			key_out = optarg;
			outfiles |= IO_KEYFILE;
			break;

		case 't':
			trust_out = optarg;
			outfiles |= IO_TRUSTFILE;
			break;

		case 'i':
			input = optarg;
			break;

		default:
			usage();
		}
	}

	if (input == NULL) {
		wbku_printerr("no input file specified\n");
		usage();
	}

	/*
	 * Need output files.
	 */
	if (outfiles == 0) {
		wbku_printerr("at least one output file must be specified\n");
		usage();
	}

	if (do_certs() < 0)
		return (EXIT_FAILURE);

	return (EXIT_SUCCESS);
}

static int
parse_keyid(const char *keystr)
{
	const char 	*rp;
	char		*wp;
	char		*nkeystr;
	uint_t 		nkeystrlen;

	/*
	 * In the worst case, we'll need one additional character in our
	 * output string -- e.g. "A\0" -> "0A\0"
	 */
	nkeystrlen = strlen(keystr) + 2;
	k_len = (nkeystrlen + 1) / 2;
	nkeystr = malloc(nkeystrlen);
	k_matchval = malloc(k_len);
	if (nkeystr == NULL || k_matchval == NULL) {
		free(nkeystr);
		free(k_matchval);
		wbku_printerr("cannot allocate keyid");
		return (-1);
	}

	/*
	 * For convenience, we allow the user to put spaces between each digit
	 * when entering it on the command line.  As a result, we need to
	 * process it into a format that hexascii_to_octet() can handle.  Note
	 * that we're careful to map strings like "AA B CC D" to "AA0BCC0D".
	 */
	for (rp = keystr, wp = nkeystr; *rp != '\0'; rp++) {
		if (*rp == ' ')
			continue;

		if (rp[1] == ' ' || rp[1] == '\0') {
			*wp++ = '0';	/* one character sequence; prepend 0 */
			*wp++ = *rp;
		} else {
			*wp++ = *rp++;
			*wp++ = *rp;
		}
	}
	*wp = '\0';

	if (hexascii_to_octet(nkeystr, wp - nkeystr, k_matchval, &k_len) != 0) {
		free(nkeystr);
		free(k_matchval);
		wbku_printerr("invalid keyid `%s'\n", keystr);
		return (-1);
	}

	free(nkeystr);
	return (0);
}

static int
do_certs(void)
{
	char *bufp;
	STACK_OF(X509) *ta_in = NULL;
	EVP_PKEY *pkey_in = NULL;
	X509 *xcert_in = NULL;

	sunw_crypto_init();

	if (read_files(&ta_in, &xcert_in, &pkey_in) < 0)
		return (-1);

	if (verbose) {
		if (xcert_in != NULL) {
			(void) printf(gettext("\nMain cert:\n"));

			/*
			 * sunw_subject_attrs() returns a pointer to
			 * memory allocated on our behalf. The same
			 * behavior is exhibited by sunw_issuer_attrs().
			 */
			bufp = sunw_subject_attrs(xcert_in, NULL, 0);
			if (bufp != NULL) {
				(void) printf(gettext("  Subject: %s\n"),
				    bufp);
				OPENSSL_free(bufp);
			}

			bufp = sunw_issuer_attrs(xcert_in, NULL, 0);
			if (bufp != NULL) {
				(void) printf(gettext("  Issuer: %s\n"), bufp);
				OPENSSL_free(bufp);
			}

			(void) sunw_print_times(stdout, PRNT_BOTH, NULL,
			    xcert_in);
		}

		if (ta_in != NULL) {
			X509 *x;
			int i;

			for (i = 0; i < sk_X509_num(ta_in); i++) {
				/* LINTED */
				x = sk_X509_value(ta_in, i);
				(void) printf(
				    gettext("\nTrust Anchor cert %d:\n"), i);

				/*
				 * sunw_subject_attrs() returns a pointer to
				 * memory allocated on our behalf. We get the
				 * same behavior from sunw_issuer_attrs().
				 */
				bufp = sunw_subject_attrs(x, NULL, 0);
				if (bufp != NULL) {
					(void) printf(
					    gettext("  Subject: %s\n"), bufp);
					OPENSSL_free(bufp);
				}

				bufp = sunw_issuer_attrs(x, NULL, 0);
				if (bufp != NULL) {
					(void) printf(
					    gettext("  Issuer: %s\n"), bufp);
					OPENSSL_free(bufp);
				}

				(void) sunw_print_times(stdout, PRNT_BOTH,
					NULL, x);
			}
		}
	}

	check_certs(ta_in, &xcert_in);
	if (xcert_in != NULL && pkey_in != NULL) {
		if (sunw_check_keys(xcert_in, pkey_in) == 0) {
			wbku_printerr("warning: key and certificate do "
			    "not match\n");
		}
	}

	return (write_files(ta_in, xcert_in, pkey_in));
}

static int
read_files(STACK_OF(X509) **t_in, X509 **c_in, EVP_PKEY **k_in)
{
	char *i_pass;

	i_pass = getpassphrase(gettext("Enter key password: "));

	if (get_ifile(input, i_pass, k_in, c_in, t_in) < 0)
		return (-1);

	/*
	 * If we are only interested in getting a trust anchor, and if there
	 * is no trust anchor but is a regular cert, use it instead.  Do this
	 * to handle the insanity with openssl, which requires a matching cert
	 * and key in order to write a PKCS12 file.
	 */
	if (outfiles == IO_TRUSTFILE) {
		if (c_in != NULL && *c_in != NULL && t_in != NULL) {
			if (*t_in == NULL) {
				if ((*t_in = sk_X509_new_null()) == NULL) {
					wbku_printerr("out of memory\n");
					return (-1);
				}
			}

			if (sk_X509_num(*t_in) == 0) {
				if (sk_X509_push(*t_in, *c_in) == 0) {
					wbku_printerr("out of memory\n");
					return (-1);
				}
				*c_in = NULL;
			}
		}
	}

	if ((outfiles & IO_KEYFILE) && *k_in == NULL) {
		wbku_printerr("no matching key found\n");
		return (-1);
	}
	if ((outfiles & IO_CERTFILE) && *c_in == NULL) {
		wbku_printerr("no matching certificate found\n");
		return (-1);
	}
	if ((outfiles & IO_TRUSTFILE) && *t_in == NULL) {
		wbku_printerr("no matching trust anchor found\n");
		return (-1);
	}

	return (0);
}

static void
check_certs(STACK_OF(X509) *ta_in, X509 **c_in)
{
	X509 *curr;
	time_errs_t ret;
	int i;
	int del_expired = (outfiles != 0);

	if (c_in != NULL && *c_in != NULL) {
		ret = time_check_print(*c_in);
		if ((ret != CHK_TIME_OK && ret != CHK_TIME_IS_BEFORE) &&
		    del_expired) {
			(void) fprintf(stderr, gettext("  Removing cert\n"));
			X509_free(*c_in);
			*c_in = NULL;
		}
	}

	if (ta_in == NULL)
		return;

	for (i = 0; i < sk_X509_num(ta_in); ) {
		/* LINTED */
		curr = sk_X509_value(ta_in, i);
		ret = time_check_print(curr);
		if ((ret != CHK_TIME_OK && ret != CHK_TIME_IS_BEFORE) &&
		    del_expired) {
			(void) fprintf(stderr, gettext("  Removing cert\n"));
			/* LINTED */
			curr = sk_X509_delete(ta_in, i);
			X509_free(curr);
			continue;
		}
		i++;
	}
}

static time_errs_t
time_check_print(X509 *cert)
{
	char buf[256];
	int ret;

	ret = time_check(cert);
	if (ret == CHK_TIME_OK)
		return (CHK_TIME_OK);

	(void) fprintf(stderr, gettext("  Subject: %s"),
	    sunw_subject_attrs(cert, buf, sizeof (buf)));
	(void) fprintf(stderr, gettext("  Issuer:  %s"),
	    sunw_issuer_attrs(cert, buf, sizeof (buf)));

	switch (ret) {
	case CHK_TIME_BEFORE_BAD:
		(void) fprintf(stderr,
		    gettext("\n  Invalid cert 'not before' field\n"));
		break;

	case CHK_TIME_AFTER_BAD:
		(void) fprintf(stderr,
		    gettext("\n  Invalid cert 'not after' field\n"));
		break;

	case CHK_TIME_HAS_EXPIRED:
		(void) sunw_print_times(stderr, PRNT_NOT_AFTER,
		    gettext("\n  Cert has expired\n"), cert);
		break;

	case CHK_TIME_IS_BEFORE:
		(void) sunw_print_times(stderr, PRNT_NOT_BEFORE,
		    gettext("\n  Warning: cert not yet valid\n"), cert);
		break;

	default:
		break;
	}

	return (ret);
}

static time_errs_t
time_check(X509 *cert)
{
	int i;

	i = X509_cmp_time(X509_get_notBefore(cert), NULL);
	if (i == 0)
		return (CHK_TIME_BEFORE_BAD);
	if (i > 0)
		return (CHK_TIME_IS_BEFORE);
	/* After 'not before' time */

	i = X509_cmp_time(X509_get_notAfter(cert), NULL);
	if (i == 0)
		return (CHK_TIME_AFTER_BAD);
	if (i < 0)
		return (CHK_TIME_HAS_EXPIRED);
	return (CHK_TIME_OK);
}

static int
write_files(STACK_OF(X509) *t_out, X509 *c_out, EVP_PKEY *k_out)
{
	if (key_out != NULL) {
		if (verbose)
			(void) printf(gettext("%s: writing key\n"), progname);
		if (do_ofile(key_out, k_out, NULL, NULL) < 0)
			return (-1);
	}

	if (cert_out != NULL) {
		if (verbose)
			(void) printf(gettext("%s: writing cert\n"), progname);
		if (do_ofile(cert_out, NULL, c_out, NULL) < 0)
			return (-1);
	}

	if (trust_out != NULL) {
		if (verbose)
			(void) printf(gettext("%s: writing trust\n"),
			    progname);
		if (do_ofile(trust_out, NULL, NULL, t_out) < 0)
			return (-1);
	}

	return (0);
}

static int
get_ifile(char *name, char *pass, EVP_PKEY **tmp_k, X509 **tmp_c,
    STACK_OF(X509) **tmp_t)
{
	PKCS12		*p12;
	FILE		*fp;
	int		ret;
	struct stat	sbuf;

	if (stat(name, &sbuf) == 0 && !S_ISREG(sbuf.st_mode)) {
		wbku_printerr("%s is not a regular file\n", name);
		return (-1);
	}

	if ((fp = fopen(name, "r")) == NULL) {
		wbku_printerr("cannot open input file %s", name);
		return (-1);
	}

	p12 = d2i_PKCS12_fp(fp, NULL);
	if (p12 == NULL) {
		wbku_printerr("cannot read file %s: %s\n", name, cryptoerr());
		(void) fclose(fp);
		return (-1);
	}
	(void) fclose(fp);

	ret = sunw_PKCS12_parse(p12, pass, matchty, k_matchval, k_len,
	    NULL, tmp_k, tmp_c, tmp_t);
	if (ret <= 0) {
		if (ret == 0)
			wbku_printerr("cannot find matching cert and key\n");
		else
			wbku_printerr("cannot parse %s: %s\n", name,
			    cryptoerr());
		PKCS12_free(p12);
		return (-1);
	}
	return (0);
}

static int
do_ofile(char *name, EVP_PKEY *pkey, X509 *cert, STACK_OF(X509) *ta)
{
	STACK_OF(EVP_PKEY) *klist = NULL;
	STACK_OF(X509)	*clist = NULL;
	PKCS12		*p12 = NULL;
	int		ret = 0;
	FILE		*fp;
	struct stat	sbuf;

	if (stat(name, &sbuf) == 0 && !S_ISREG(sbuf.st_mode)) {
		wbku_printerr("%s is not a regular file\n", name);
		return (-1);
	}

	if ((fp = fopen(name, "w")) == NULL) {
		wbku_printerr("cannot open output file %s", name);
		return (-1);
	}

	if ((clist = sk_X509_new_null()) == NULL ||
	    (klist = sk_EVP_PKEY_new_null()) == NULL) {
		wbku_printerr("out of memory\n");
		ret = -1;
		goto cleanup;
	}

	if (cert != NULL && sk_X509_push(clist, cert) == 0) {
		wbku_printerr("out of memory\n");
		ret = -1;
		goto cleanup;
	}

	if (pkey != NULL && sk_EVP_PKEY_push(klist, pkey) == 0) {
		wbku_printerr("out of memory\n");
		ret = -1;
		goto cleanup;
	}

	p12 = sunw_PKCS12_create(WANBOOT_PASSPHRASE, klist, clist, ta);
	if (p12 == NULL) {
		wbku_printerr("cannot create %s: %s\n", name, cryptoerr());
		ret = -1;
		goto cleanup;
	}

	if (i2d_PKCS12_fp(fp, p12) == 0) {
		wbku_printerr("cannot write %s: %s\n", name, cryptoerr());
		ret = -1;
		goto cleanup;
	}

cleanup:
	(void) fclose(fp);
	if (p12 != NULL)
		PKCS12_free(p12);
	/*
	 * Put the cert and pkey off of the stack so that they won't
	 * be freed two times.  (If they get left in the stack then
	 * they will be freed with the stack.)
	 */
	if (clist != NULL) {
		if (cert != NULL && sk_X509_num(clist) == 1) {
			/* LINTED */
			(void) sk_X509_delete(clist, 0);
		}
		sk_X509_pop_free(clist, X509_free);
	}
	if (klist != NULL) {
		if (pkey != NULL && sk_EVP_PKEY_num(klist) == 1) {
			/* LINTED */
			(void) sk_EVP_PKEY_delete(klist, 0);
		}
		sk_EVP_PKEY_pop_free(klist, sunw_evp_pkey_free);
	}

	return (ret);
}

static void
usage(void)
{
	(void) fprintf(stderr,
	    gettext("usage:\n"
	    "     %s -i <file> -c <file> -k <file> -t <file> [-l <keyid> -v]\n"
	    "\n"),
	    progname);
	(void) fprintf(stderr,
	    gettext(" where:\n"
	    "  -i - input file to be split into component parts and put in\n"
	    "       files given by -c, -k and -t\n"
	    "  -c - output file for the client certificate\n"
	    "  -k - output file for the client private key\n"
	    "  -t - output file for the remaining certificates (assumed\n"
	    "       to be trust anchors)\n"
	    "\n Files are assumed to be pkcs12-format files.\n\n"
	    "  -v - verbose\n"
	    "  -l - value of 'localkeyid' attribute in client cert and\n"
	    "       private key to be selected from the input file.\n\n"));
	exit(EXIT_FAILURE);
}

/*
 * Return a pointer to a static buffer that contains a listing of crypto
 * errors.  We presume that the user doesn't want more than 8KB of error
 * messages :-)
 */
static const char *
cryptoerr(void)
{
	static char	errbuf[8192];
	ulong_t		err;
	const char	*pfile;
	int		line;
	unsigned int	nerr = 0;

	errbuf[0] = '\0';
	while ((err = ERR_get_error_line(&pfile, &line)) != 0) {
		if (++nerr > 1)
			(void) strlcat(errbuf, "\n\t", sizeof (errbuf));

		if (err == (ulong_t)-1) {
			(void) strlcat(errbuf, strerror(errno),
			    sizeof (errbuf));
			break;
		}
		(void) strlcat(errbuf, ERR_reason_error_string(err),
		    sizeof (errbuf));
	}

	return (errbuf);
}
