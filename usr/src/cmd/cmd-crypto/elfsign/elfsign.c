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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Developer command for adding the signature section to an ELF object
 * PSARC 2001/488
 *
 * DEBUG Information:
 * This command uses the cryptodebug() function from libcryptoutil.
 * Set SUNW_CRYPTO_DEBUG to stderr or syslog for all debug to go to auth.debug
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libintl.h>
#include <locale.h>
#include <errno.h>
#include <strings.h>

#include <cryptoutil.h>
#include <sys/crypto/elfsign.h>
#include <libelfsign.h>

#include <kmfapi.h>

#define	SIGN		"sign"
#define	SIGN_OPTS	"c:e:F:k:P:T:v"
#define	VERIFY		"verify"
#define	VERIFY_OPTS	"c:e:v"
#define	REQUEST		"request"
#define	REQUEST_OPTS	"i:k:r:T:"
#define	LIST		"list"
#define	LIST_OPTS	"c:e:f:"

enum cmd_e {
	ES_SIGN,
	ES_VERIFY,
	ES_REQUEST,
	ES_LIST
};

enum field_e {
	FLD_UNKNOWN,
	FLD_SUBJECT,
	FLD_ISSUER,
	FLD_FORMAT,
	FLD_SIGNER,
	FLD_TIME
};

#define	MIN_ARGS	3	/* The minimum # args to do anything */
#define	ES_DEFAULT_KEYSIZE 1024

static struct {
	enum cmd_e	cmd;	/* sub command: sign | verify | request */
	char	*cert;		/* -c <certificate_file> | */
				/* -r <certificate_request_file> */
	char	**elfobj;	/* -e <elf_object> */
	int	elfcnt;
	enum ES_ACTION	es_action;
	ELFsign_t	ess;	/* libelfsign opaque "state" */
	int	extracnt;
	enum field_e	field;	/* -f <field> */
	char internal_req;	/* Sun internal certificate request */
	char	*pinpath;	/* -P <pin> */
	char	*privpath;	/* -k <private_key> */
	char	*token_label;	/* -T <token_label> */
	boolean_t verbose;	/* chatty output */
} cmd_info;

enum ret_e {
	EXIT_OKAY,
	EXIT_INVALID_ARG,
	EXIT_VERIFY_FAILED,
	EXIT_CANT_OPEN_ELF_OBJECT,
	EXIT_BAD_CERT,
	EXIT_BAD_PRIVATEKEY,
	EXIT_SIGN_FAILED,
	EXIT_VERIFY_FAILED_UNSIGNED,
	EXIT_CSR_FAILED,
	EXIT_MEMORY_ERROR
};

struct field_s {
	char	*name;
	enum field_e	field;
} fields[] = {
	{ "subject", FLD_SUBJECT },
	{ "issuer", FLD_ISSUER },
	{ "format", FLD_FORMAT },
	{ "signer", FLD_SIGNER },
	{ "time", FLD_TIME },
	NULL, 0
};

typedef enum ret_e ret_t;

static void usage(void);
static ret_t getelfobj(char *);
static char *getpin(void);
static ret_t do_sign(char *);
static ret_t do_verify(char *);
static ret_t do_cert_request(char *);
static ret_t do_list(char *);
static void es_error(const char *fmt, ...);
static char *time_str(time_t t);
static void sig_info_print(struct ELFsign_sig_info *esip);

int
main(int argc, char **argv)
{
	extern char *optarg;
	char *scmd = NULL;
	char *opts;		/* The set of flags for cmd */
	int errflag = 0;	/* We had an options parse error */
	char c;			/* current getopts flag */
	ret_t (*action)(char *);	/* Function pointer for the action */
	ret_t ret;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defiend by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	cryptodebug_init("elfsign");

	if (argc < MIN_ARGS) {
		es_error(gettext("invalid number of arguments"));
		usage();
		return (EXIT_INVALID_ARG);
	}

	scmd = argv[1];
	cmd_info.cert = NULL;
	cmd_info.elfobj = NULL;
	cmd_info.elfcnt = 0;
	cmd_info.es_action = ES_GET;
	cmd_info.ess = NULL;
	cmd_info.extracnt = 0;
	cmd_info.field = FLD_UNKNOWN;
	cmd_info.internal_req = '\0';
	cmd_info.pinpath = NULL;
	cmd_info.privpath = NULL;
	cmd_info.token_label = NULL;
	cmd_info.verbose = B_FALSE;

	if (strcmp(scmd, SIGN) == 0) {
		cmd_info.cmd = ES_SIGN;
		opts = SIGN_OPTS;
		cryptodebug("cmd=sign opts=%s", opts);
		action = do_sign;
		cmd_info.es_action = ES_UPDATE_RSA_SHA1;
	} else if (strcmp(scmd, VERIFY) == 0) {
		cmd_info.cmd = ES_VERIFY;
		opts = VERIFY_OPTS;
		cryptodebug("cmd=verify opts=%s", opts);
		action = do_verify;
	} else if (strcmp(scmd, REQUEST) == 0) {
		cmd_info.cmd = ES_REQUEST;
		opts = REQUEST_OPTS;
		cryptodebug("cmd=request opts=%s", opts);
		action = do_cert_request;
	} else if (strcmp(scmd, LIST) == 0) {
		cmd_info.cmd = ES_LIST;
		opts = LIST_OPTS;
		cryptodebug("cmd=list opts=%s", opts);
		action = do_list;
	} else {
		es_error(gettext("Unknown sub-command: %s"),
		    scmd);
		usage();
		return (EXIT_INVALID_ARG);
	}

	/*
	 * Note:  There is no need to check that optarg isn't NULL
	 *	  because getopt does that for us.
	 */
	while (!errflag && (c = getopt(argc - 1, argv + 1, opts)) != EOF) {
		if (strchr("ceFihkPTr", c) != NULL)
			cryptodebug("c=%c, '%s'", c, optarg);
		else
			cryptodebug("c=%c", c);

		switch (c) {
		case 'c':
			cmd_info.cert = optarg;
			break;
		case 'e':
			cmd_info.elfcnt++;
			cmd_info.elfobj = (char **)realloc(cmd_info.elfobj,
			    sizeof (char *) * cmd_info.elfcnt);
			if (cmd_info.elfobj == NULL) {
				es_error(gettext(
				    "Too many elf objects specified."));
				return (EXIT_INVALID_ARG);
			}
			cmd_info.elfobj[cmd_info.elfcnt - 1] = optarg;
			break;
		case 'f':
			{
				struct field_s	*fp;
				cmd_info.field = FLD_UNKNOWN;
				for (fp = fields; fp->name != NULL; fp++) {
					if (strcasecmp(optarg, fp->name) == 0) {
						cmd_info.field = fp->field;
						break;
					}
				}
				if (cmd_info.field == FLD_UNKNOWN) {
					cryptodebug("Invalid field option");
					errflag++;
				}
			}
			break;
		case 'F':
			if (strcasecmp(optarg, ES_FMT_RSA_MD5_SHA1) == 0)
				cmd_info.es_action = ES_UPDATE_RSA_MD5_SHA1;
			else if (strcasecmp(optarg, ES_FMT_RSA_SHA1) == 0)
				cmd_info.es_action = ES_UPDATE_RSA_SHA1;
			else {
				cryptodebug("Invalid format option");
				errflag++;
			}
			break;
		case 'i':	 /* Undocumented internal Sun use only */
			cmd_info.internal_req = *optarg;
			break;
		case 'k':
			cmd_info.privpath = optarg;
			if (cmd_info.token_label != NULL ||
			    cmd_info.pinpath != NULL)
				errflag++;
			break;
		case 'P':
			cmd_info.pinpath = optarg;
			if (cmd_info.privpath != NULL)
				errflag++;
			break;
		case 'r':
			cmd_info.cert = optarg;
			break;
		case 'T':
			cmd_info.token_label = optarg;
			if (cmd_info.privpath != NULL)
				errflag++;
			break;
		case 'v':
			cmd_info.verbose = B_TRUE;
			break;
		default:
			errflag++;
		}
	}

	optind++;	/* we skipped over subcommand */
	cmd_info.extracnt = argc - optind;

	if (cmd_info.extracnt != 0 &&
	    cmd_info.cmd != ES_SIGN && cmd_info.cmd != ES_VERIFY) {
		cryptodebug("Extra arguments, optind=%d, argc=%d",
		    optind, argc);
		errflag++;
	}

	switch (cmd_info.cmd) {
	case ES_VERIFY:
		if (cmd_info.elfcnt + argc - optind == 0) {
			cryptodebug("Missing elfobj");
			errflag++;
		}
		break;

	case ES_SIGN:
		if (((cmd_info.privpath == NULL) &&
		    (cmd_info.token_label == NULL)) ||
		    (cmd_info.cert == NULL) ||
		    (cmd_info.elfcnt + argc - optind == 0)) {
			cryptodebug("Missing privpath|token_label/cert/elfobj");
			errflag++;
		}
		break;

	case ES_REQUEST:
		if (((cmd_info.privpath == NULL) &&
		    (cmd_info.token_label == NULL)) ||
		    (cmd_info.cert == NULL)) {
			cryptodebug("Missing privpath|token_label/certreq");
			errflag++;
		}
		break;
	case ES_LIST:
		if ((cmd_info.cert != NULL) == (cmd_info.elfcnt > 0)) {
			cryptodebug("Neither or both of cert/elfobj");
			errflag++;
		}
		break;
	}

	if (errflag) {
		usage();
		return (EXIT_INVALID_ARG);
	}

	switch (cmd_info.cmd) {
	case ES_REQUEST:
	case ES_LIST:
		ret = action(NULL);
		break;
	default:
		{
		int i;
		ret_t	iret;

		ret = EXIT_OKAY;
		iret = EXIT_OKAY;
		for (i = 0; i < cmd_info.elfcnt &&
		    (ret == EXIT_OKAY || cmd_info.cmd != ES_SIGN); i++) {
			iret = action(cmd_info.elfobj[i]);
			if (iret > ret)
				ret = iret;
		}
		for (i = optind; i < argc &&
		    (ret == EXIT_OKAY || cmd_info.cmd != ES_SIGN); i++) {
			iret = action(argv[i]);
			if (iret > ret)
				ret = iret;
		}
		break;
		}
	}

	if (cmd_info.elfobj != NULL)
		free(cmd_info.elfobj);

	return (ret);
}


static void
usage(void)
{
/* BEGIN CSTYLED */
	(void) fprintf(stderr, gettext(
 "usage:\n"
 "\telfsign sign [-v] [-e <elf_object>] -c <certificate_file>\n"
 "\t\t[-F <format>] -k <private_key_file> [elf_object]..."
 "\n"
 "\telfsign sign [-v] [-e <elf_object>] -c <certificate_file>\n"
 "\t\t[-F <format>] -T <token_label> [-P <pin_file>] [elf_object]..."
 "\n\n"
 "\telfsign verify [-v] [-c <certificate_file>] [-e <elf_object>]\n"
 "\t\t[elf_object]..."
 "\n\n"
 "\telfsign request -r <certificate_request_file> -k <private_key_file>"
 "\n"
 "\telfsign request -r <certificate_request_file> -T <token_label>"
 "\n\n"
 "\telfsign list -f field -c <certificate_file>"
 "\n"
 "\telfsign list -f field -e <elf_object>"
 "\n"));
/* END CSTYLED */
}

static ret_t
getelfobj(char *elfpath)
{
	ELFsign_status_t estatus;
	ret_t	ret = EXIT_SIGN_FAILED;

	estatus = elfsign_begin(elfpath, cmd_info.es_action, &(cmd_info.ess));
	switch (estatus) {
	case ELFSIGN_SUCCESS:
		ret = EXIT_OKAY;
		break;
	case ELFSIGN_INVALID_ELFOBJ:
		es_error(gettext(
		    "Unable to open %s as an ELF object."),
		    elfpath);
		ret = EXIT_CANT_OPEN_ELF_OBJECT;
		break;
	default:
		es_error(gettext("unexpected failure: %d"), estatus);
		if (cmd_info.cmd == ES_SIGN) {
			ret = EXIT_SIGN_FAILED;
		} else if (cmd_info.cmd == ES_VERIFY) {
			ret = EXIT_VERIFY_FAILED;
		}
	}

	return (ret);
}

static ret_t
setcertpath(void)
{
	ELFsign_status_t estatus;
	ret_t	ret = EXIT_SIGN_FAILED;

	if (cmd_info.cert == NULL)
		return (EXIT_OKAY);
	estatus = elfsign_setcertpath(cmd_info.ess, cmd_info.cert);
	switch (estatus) {
	case ELFSIGN_SUCCESS:
		ret = EXIT_OKAY;
		break;
	case ELFSIGN_INVALID_CERTPATH:
		if (cmd_info.cert != NULL) {
			es_error(gettext("Unable to open %s as a certificate."),
			    cmd_info.cert);
		}
		ret = EXIT_BAD_CERT;
		break;
	default:
		es_error(gettext("unusable certificate: %s"), cmd_info.cert);
		if (cmd_info.cmd == ES_SIGN) {
			ret = EXIT_SIGN_FAILED;
		} else if (cmd_info.cmd == ES_VERIFY) {
			ret = EXIT_VERIFY_FAILED;
		}
	}

	return (ret);
}

/*
 * getpin - return pointer to token PIN in static storage
 */
static char *
getpin(void)
{
	static char	pinbuf[PASS_MAX + 1];
	char	*pp;
	FILE	*pinfile;

	if (cmd_info.pinpath == NULL)
		return (getpassphrase(
		    gettext("Enter PIN for PKCS#11 token: ")));
	if ((pinfile = fopen(cmd_info.pinpath, "r")) == NULL) {
		es_error(gettext("failed to open %s."),
		    cmd_info.pinpath);
		return (NULL);
	}

	pp = fgets(pinbuf, sizeof (pinbuf), pinfile);
	(void) fclose(pinfile);
	if (pp == NULL) {
		es_error(gettext("failed to read PIN from %s."),
		    cmd_info.pinpath);
		return (NULL);
	}
	pp = &pinbuf[strlen(pinbuf) - 1];
	if (*pp == '\n')
		*pp = '\0';
	return (pinbuf);
}

/*
 * Add the .SUNW_signature sections for the ELF signature
 */
static ret_t
do_sign(char *object)
{
	ret_t 	ret;
	ELFsign_status_t	elfstat;
	struct filesignatures	*fssp = NULL;
	size_t fs_len;
	uchar_t sig[SIG_MAX_LENGTH];
	size_t	sig_len = SIG_MAX_LENGTH;
	uchar_t	hash[SIG_MAX_LENGTH];
	size_t	hash_len = SIG_MAX_LENGTH;
	ELFCert_t	cert = NULL;
	char	*dn;
	size_t	dn_len;

	cryptodebug("do_sign");
	if ((ret = getelfobj(object)) != EXIT_OKAY)
		return (ret);

	if (cmd_info.token_label &&
	    !elfcertlib_settoken(cmd_info.ess, cmd_info.token_label)) {
		es_error(gettext("Unable to access token: %s"),
		    cmd_info.token_label);
		ret = EXIT_SIGN_FAILED;
		goto cleanup;
	}

	if ((ret = setcertpath()) != EXIT_OKAY)
		goto cleanup;

	if (!elfcertlib_getcert(cmd_info.ess, cmd_info.cert, NULL, &cert,
	    cmd_info.es_action)) {
		es_error(gettext("Unable to load certificate: %s"),
		    cmd_info.cert);
		ret = EXIT_BAD_CERT;
		goto cleanup;
	}

	if (cmd_info.privpath != NULL) {
		if (!elfcertlib_loadprivatekey(cmd_info.ess, cert,
		    cmd_info.privpath)) {
			es_error(gettext("Unable to load private key: %s"),
			    cmd_info.privpath);
			ret = EXIT_BAD_PRIVATEKEY;
			goto cleanup;
		}
	} else {
		char *pin = getpin();
		if (pin == NULL) {
			es_error(gettext("Unable to get PIN"));
			ret = EXIT_BAD_PRIVATEKEY;
			goto cleanup;
		}
		if (!elfcertlib_loadtokenkey(cmd_info.ess, cert,
		    cmd_info.token_label, pin)) {
			es_error(gettext("Unable to access private key "
			    "in token %s"), cmd_info.token_label);
			ret = EXIT_BAD_PRIVATEKEY;
			goto cleanup;
		}
	}

	/*
	 * Get the DN from the certificate.
	 */
	if ((dn = elfcertlib_getdn(cert)) == NULL) {
		es_error(gettext("Unable to find DN in certificate %s"),
		    cmd_info.cert);
		ret = EXIT_SIGN_FAILED;
		goto cleanup;
	}
	dn_len = strlen(dn);
	cryptodebug("DN = %s", dn);

	elfstat = elfsign_signatures(cmd_info.ess, &fssp, &fs_len, ES_GET);
	if (elfstat != ELFSIGN_SUCCESS) {
		if (elfstat != ELFSIGN_NOTSIGNED) {
			es_error(gettext("Unable to retrieve existing "
			    "signature block in %s"), object);
			ret = EXIT_SIGN_FAILED;
			goto cleanup;
		}
		fssp = NULL;
		/*
		 * force creation and naming of signature section
		 * so the hash doesn't change
		 */
		if (elfsign_signatures(cmd_info.ess, &fssp, &fs_len,
		    cmd_info.es_action) != ELFSIGN_SUCCESS) {
			es_error(gettext("Unable to insert "
			    "signature block into %s"), object);
			ret = EXIT_SIGN_FAILED;
			goto cleanup;
		}
	}

	bzero(hash, sizeof (hash));
	if (elfsign_hash(cmd_info.ess, hash, &hash_len) != ELFSIGN_SUCCESS) {
		es_error(gettext("Unable to calculate hash of ELF object %s"),
		    object);
		ret = EXIT_SIGN_FAILED;
		goto cleanup;
	}

	bzero(sig, sizeof (sig));
	if (!elfcertlib_sign(cmd_info.ess, cert,
	    hash, hash_len, sig, &sig_len)) {
		es_error(gettext("Unable to sign %s using key from %s"),
		    object, cmd_info.privpath ?
		    cmd_info.privpath : cmd_info.token_label);
		ret = EXIT_SIGN_FAILED;
		goto cleanup;
	}

	{ /* DEBUG START */
		const int sigstr_len = sizeof (char) * sig_len * 2 + 1;
		char *sigstr = malloc(sigstr_len);

		tohexstr(sig, sig_len, sigstr, sigstr_len);
		cryptodebug("sig value is: %s", sigstr);
		free(sigstr);
	} /* DEBUG END */

	fssp = elfsign_insert_dso(cmd_info.ess, fssp,
	    dn, dn_len, sig, sig_len, NULL, 0);
	if (fssp == NULL) {
		es_error(gettext("Unable to prepare signature for %s"),
		    object);
		ret = EXIT_SIGN_FAILED;
		goto cleanup;
	}
	if (elfsign_signatures(cmd_info.ess, &fssp, &fs_len,
	    cmd_info.es_action) != ELFSIGN_SUCCESS) {
		es_error(gettext("Unable to update %s: with signature"),
		    object);
		ret = EXIT_SIGN_FAILED;
		goto cleanup;
	}
	if (cmd_info.verbose || (cmd_info.elfcnt + cmd_info.extracnt) > 1) {
		(void) fprintf(stdout,
		    gettext("elfsign: %s signed successfully.\n"),
		    object);
	}
	if (cmd_info.verbose) {
		struct ELFsign_sig_info *esip;

		if (elfsign_sig_info(fssp, &esip)) {
			sig_info_print(esip);
			elfsign_sig_info_free(esip);
		}
	}

	ret = EXIT_OKAY;

cleanup:
	free(fssp);
	bzero(sig, sig_len);
	bzero(hash, hash_len);

	if (cert != NULL)
		elfcertlib_releasecert(cmd_info.ess, cert);
	if (cmd_info.ess != NULL)
		elfsign_end(cmd_info.ess);

	return (ret);
}

/*
 * Verify the signature of the object
 * This subcommand is intended to be used by developers during their build
 * processes.  Therefore we can not assume that the certificate is in
 * /etc/crypto/certs so we must use the path we got from the commandline.
 */
static ret_t
do_verify(char *object)
{
	ELFsign_status_t res;
	struct ELFsign_sig_info	*esip;
	ret_t	retval;

	cryptodebug("do_verify");
	if ((retval = getelfobj(object)) != EXIT_OKAY)
		return (retval);

	if ((retval = setcertpath()) != EXIT_OKAY) {
		elfsign_end(cmd_info.ess);
		return (retval);
	}

	res = elfsign_verify_signature(cmd_info.ess, &esip);
	switch (res) {
	case ELFSIGN_SUCCESS:
		(void) fprintf(stdout,
		    gettext("elfsign: verification of %s passed.\n"),
		    object);
		if (cmd_info.verbose)
			sig_info_print(esip);
		retval = EXIT_OKAY;
		break;
	case ELFSIGN_FAILED:
	case ELFSIGN_INVALID_CERTPATH:
		es_error(gettext("verification of %s failed."),
		    object);
		if (cmd_info.verbose)
			sig_info_print(esip);
		retval = EXIT_VERIFY_FAILED;
		break;
	case ELFSIGN_NOTSIGNED:
		es_error(gettext("no signature found in %s."),
		    object);
		retval = EXIT_VERIFY_FAILED_UNSIGNED;
		break;
	default:
		es_error(gettext("unexpected failure attempting verification "
		    "of %s."), object);
		retval = EXIT_VERIFY_FAILED_UNSIGNED;
		break;
	}

	if (esip != NULL)
		elfsign_sig_info_free(esip);
	if (cmd_info.ess != NULL)
		elfsign_end(cmd_info.ess);
	return (retval);
}

#define	SET_VALUE(f, s) \
	kmfrv = f; \
	if (kmfrv != KMF_OK) { \
		char *e = NULL; \
		(void) kmf_get_kmf_error_str(kmfrv, &e); \
		cryptoerror(LOG_STDERR, \
			gettext("Failed to %s: %s\n"), \
			s, (e ? e : "unknown error")); \
		if (e) free(e); \
		goto cleanup; \
	}

static KMF_RETURN
create_csr(char *dn)
{
	KMF_RETURN kmfrv = KMF_OK;
	KMF_HANDLE_T kmfhandle = NULL;
	KMF_KEY_HANDLE pubk, prik;
	KMF_X509_NAME csrSubject;
	KMF_CSR_DATA csr;
	KMF_ALGORITHM_INDEX sigAlg = KMF_ALGID_MD5WithRSA;
	KMF_DATA signedCsr = { 0, NULL };
	char *err;
	KMF_ATTRIBUTE	attrlist[16];
	KMF_ENCODE_FORMAT	format;
	KMF_KEYSTORE_TYPE	kstype;
	KMF_KEY_ALG	keytype;
	uint32_t	keylength;
	KMF_CREDENTIAL	cred;
	char	*pin = NULL;
	int	numattr;

	if ((kmfrv = kmf_initialize(&kmfhandle, NULL, NULL)) != KMF_OK) {
		(void) kmf_get_kmf_error_str(kmfrv, &err);
		cryptoerror(LOG_STDERR,
		    gettext("Error initializing KMF: %s\n"),
		    (err ? err : "unknown error"));
		if (err)
			free(err);
		return (kmfrv);
	}
	(void) memset(&csr, 0, sizeof (csr));
	(void) memset(&csrSubject, 0, sizeof (csrSubject));

	if (cmd_info.privpath != NULL) {
		kstype = KMF_KEYSTORE_OPENSSL;
		format = KMF_FORMAT_ASN1;
	} else {
		boolean_t	readonly;
		/* args checking verified (cmd_info.token_label != NULL) */

		/* Get a PIN to store the private key in the token */
		pin = getpin();

		if (pin == NULL) {
			(void) kmf_finalize(kmfhandle);
			return (KMF_ERR_AUTH_FAILED);
		}

		kstype = KMF_KEYSTORE_PK11TOKEN;
		readonly = B_FALSE;

		numattr = 0;
		kmf_set_attr_at_index(attrlist, numattr++,
		    KMF_KEYSTORE_TYPE_ATTR, &kstype, sizeof (kstype));
		kmf_set_attr_at_index(attrlist, numattr++,
		    KMF_TOKEN_LABEL_ATTR, cmd_info.token_label,
		    strlen(cmd_info.token_label));
		kmf_set_attr_at_index(attrlist, numattr++,
		    KMF_READONLY_ATTR, &readonly, sizeof (readonly));
		kmfrv = kmf_configure_keystore(kmfhandle, numattr, attrlist);
		if (kmfrv != KMF_OK) {
			goto cleanup;
		}
	}

	/* Create the RSA keypair */
	keytype = KMF_RSA;
	keylength = ES_DEFAULT_KEYSIZE;
	(void) memset(&prik, 0, sizeof (prik));
	(void) memset(&pubk, 0, sizeof (pubk));

	numattr = 0;
	kmf_set_attr_at_index(attrlist, numattr++,
	    KMF_KEYSTORE_TYPE_ATTR, &kstype, sizeof (kstype));
	kmf_set_attr_at_index(attrlist, numattr++,
	    KMF_KEYALG_ATTR, &keytype, sizeof (keytype));
	kmf_set_attr_at_index(attrlist, numattr++,
	    KMF_KEYLENGTH_ATTR, &keylength, sizeof (keylength));
	if (pin != NULL) {
		cred.cred = pin;
		cred.credlen = strlen(pin);
		kmf_set_attr_at_index(attrlist, numattr++,
		    KMF_CREDENTIAL_ATTR, &cred, sizeof (KMF_CREDENTIAL));
	}
	kmf_set_attr_at_index(attrlist, numattr++,
	    KMF_PRIVKEY_HANDLE_ATTR, &prik, sizeof (KMF_KEY_HANDLE));
	kmf_set_attr_at_index(attrlist, numattr++,
	    KMF_PUBKEY_HANDLE_ATTR, &pubk, sizeof (KMF_KEY_HANDLE));
	if (kstype == KMF_KEYSTORE_OPENSSL) {
		kmf_set_attr_at_index(attrlist, numattr++,
		    KMF_KEY_FILENAME_ATTR, cmd_info.privpath,
		    strlen(cmd_info.privpath));
		kmf_set_attr_at_index(attrlist, numattr++,
		    KMF_ENCODE_FORMAT_ATTR, &format, sizeof (format));
	}

	kmfrv = kmf_create_keypair(kmfhandle, numattr, attrlist);
	if (kmfrv != KMF_OK) {
		(void) kmf_get_kmf_error_str(kmfrv, &err);
		cryptoerror(LOG_STDERR,
		    gettext("Create RSA keypair failed: %s"),
		    (err ? err : "unknown error"));
		free(err);
		goto cleanup;
	}

	kmfrv = kmf_dn_parser(dn, &csrSubject);
	if (kmfrv != KMF_OK) {
		(void) kmf_get_kmf_error_str(kmfrv, &err);
		cryptoerror(LOG_STDERR,
		    gettext("Error parsing subject name: %s\n"),
		    (err ? err : "unknown error"));
		free(err);
		goto cleanup;
	}

	SET_VALUE(kmf_set_csr_pubkey(kmfhandle, &pubk, &csr), "keypair");

	SET_VALUE(kmf_set_csr_version(&csr, 2), "version number");

	SET_VALUE(kmf_set_csr_subject(&csr, &csrSubject), "subject name");

	SET_VALUE(kmf_set_csr_sig_alg(&csr, sigAlg), "SignatureAlgorithm");

	if ((kmfrv = kmf_sign_csr(kmfhandle, &csr, &prik, &signedCsr)) ==
	    KMF_OK) {
		kmfrv = kmf_create_csr_file(&signedCsr, KMF_FORMAT_PEM,
		    cmd_info.cert);
	}

cleanup:
	(void) kmf_free_kmf_key(kmfhandle, &prik);
	(void) kmf_free_data(&signedCsr);
	(void) kmf_free_signed_csr(&csr);
	(void) kmf_finalize(kmfhandle);

	return (kmfrv);
}


#define	CN_MAX_LENGTH	64	/* Verisign implementation limit */
/*
 * Generate a certificate request into the file named cmd_info.cert
 */
/*ARGSUSED*/
static ret_t
do_cert_request(char *object)
{
	const char	 PartnerDNFMT[] =
	    "CN=%s, "
	    "OU=Class B, "
	    "OU=Solaris Cryptographic Framework, "
	    "OU=Partner Object Signing, "
	    "O=Sun Microsystems Inc";
	const char	 SunCDNFMT[] =
	    "CN=%s, "
	    "OU=Class B, "
	    "OU=Solaris Cryptographic Framework, "
	    "OU=Corporate Object Signing, "
	    "O=Sun Microsystems Inc";
	const char	 SunSDNFMT[] =
	    "CN=%s, "
	    "OU=Class B, "
	    "OU=Solaris Signed Execution, "
	    "OU=Corporate Object Signing, "
	    "O=Sun Microsystems Inc";
	const char	 *dnfmt = NULL;
	char	cn[CN_MAX_LENGTH + 1];
	char	*dn = NULL;
	size_t	dn_len;
	KMF_RETURN   kmfret;
	cryptodebug("do_cert_request");

	/*
	 * Get the DN prefix from the user
	 */
	switch (cmd_info.internal_req) {
	case 'c':
		dnfmt = SunCDNFMT;
		(void) fprintf(stdout, gettext(
		    "Enter Sun Microsystems, Inc. Release name.\n"
		    "This will be the prefix of the Certificate DN: "));
		break;
	case 's':
		dnfmt = SunSDNFMT;
		(void) fprintf(stdout, gettext(
		    "Enter Sun Microsystems, Inc. Release name.\n"
		    "This will be the prefix of the Certificate DN: "));
		break;
	default:
		dnfmt = PartnerDNFMT;
		(void) fprintf(stdout, gettext(
		    "Enter Company Name / Stock Symbol"
		    " or some other globally unique identifier.\n"
		    "This will be the prefix of the Certificate DN: "));
		break;
	}
	if ((fgets(cn, sizeof (cn), stdin) == NULL) || (cn[0] == '\n')) {
		es_error(gettext("you must specify a Certificate DN prefix"));
		return (EXIT_INVALID_ARG);
	}

	if (cn[strlen(cn) - 1] == '\n') {
		cn[strlen(cn) - 1] = '\0';	/* chop trailing \n */
	} else {
		es_error(gettext("You must specify a Certificate DN prefix "
		    "of no more than %d characters"), CN_MAX_LENGTH);
		return (EXIT_INVALID_ARG);
	}

	/* Update DN string */
	dn_len = strlen(cn) + strlen(dnfmt);
	dn = malloc(dn_len + 1);
	(void) snprintf(dn, dn_len, dnfmt, cn);

	cryptodebug("Generating Certificate request for DN: %s", dn);
	kmfret = create_csr(dn);
	free(dn);
	if (kmfret == KMF_OK)
		return (EXIT_OKAY);
	else
		return (EXIT_CSR_FAILED);
}

static void
str_print(char *s)
{
	if (s == NULL)
		return;
	(void) fprintf(stdout, "%s\n", s);
}

/*ARGSUSED*/
static ret_t
do_list(char *object)
{
	ret_t	retval;

	if (cmd_info.elfcnt > 0) {
		ELFsign_status_t	elfstat;
		struct filesignatures	*fssp = NULL;
		size_t fs_len;
		struct ELFsign_sig_info	*esip;

		if ((retval = getelfobj(cmd_info.elfobj[0])) != EXIT_OKAY)
			return (retval);
		elfstat = elfsign_signatures(cmd_info.ess,
		    &fssp, &fs_len, ES_GET);
		if (elfstat == ELFSIGN_SUCCESS) {
			retval = EXIT_OKAY;
			if (elfsign_sig_info(fssp, &esip)) {
				switch (cmd_info.field) {
				case FLD_FORMAT:
					str_print(esip->esi_format);
					break;
				case FLD_SIGNER:
					str_print(esip->esi_signer);
					break;
				case FLD_TIME:
					if (esip->esi_time == 0)
						retval = EXIT_INVALID_ARG;
					else
						str_print(time_str(
						    esip->esi_time));
					break;
				default:
					retval = EXIT_INVALID_ARG;
				}
				elfsign_sig_info_free(esip);
			}
			free(fssp);
		} else
			retval = EXIT_VERIFY_FAILED_UNSIGNED;
		elfsign_end(cmd_info.ess);
	} else {
		ELFCert_t	cert;
		/*
		 * Initialize the ESS record here even though we are not
		 * actually opening any ELF files.
		 */
		if (elfsign_begin(NULL, ES_GET, &(cmd_info.ess)) !=
		    ELFSIGN_SUCCESS)
			return (EXIT_MEMORY_ERROR);

		if (elfcertlib_getcert(cmd_info.ess, cmd_info.cert, NULL,
		    &cert, cmd_info.es_action)) {
			retval = EXIT_OKAY;
			switch (cmd_info.field) {
			case FLD_SUBJECT:
				str_print(elfcertlib_getdn(cert));
				break;
			case FLD_ISSUER:
				str_print(elfcertlib_getissuer(cert));
				break;
			default:
				retval = EXIT_INVALID_ARG;
			}
			elfcertlib_releasecert(cmd_info.ess, cert);
		} else
			retval = EXIT_BAD_CERT;
		elfsign_end(cmd_info.ess);
	}

	return (retval);
}

static void
es_error(const char *fmt, ...)
{
	char msgbuf[BUFSIZ];
	va_list	args;

	va_start(args, fmt);
	(void) vsnprintf(msgbuf, sizeof (msgbuf), fmt, args);
	va_end(args);
	(void) fflush(stdout);
	cryptoerror(LOG_STDERR, "%s", msgbuf);
	(void) fflush(stderr);
}

static char *
time_str(time_t t)
{
	static char	buf[80];
	char		*bufp;

	bufp = buf;
	if (strftime(buf, sizeof (buf), NULL, localtime(&t)) == 0)
		bufp = ctime(&t);
	return (bufp);
}

static void
sig_info_print(struct ELFsign_sig_info *esip)
{
	if (esip == NULL)
		return;
	(void) fprintf(stdout, gettext("format: %s.\n"), esip->esi_format);
	(void) fprintf(stdout, gettext("signer: %s.\n"), esip->esi_signer);
	if (esip->esi_time == 0)
		return;
	(void) fprintf(stdout, gettext("signed on: %s.\n"),
	    time_str(esip->esi_time));
}
