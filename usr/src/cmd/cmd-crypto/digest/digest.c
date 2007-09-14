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
 * digest.c
 *
 * Implements digest(1) and mac(1) commands
 * If command name is mac, performs mac operation
 * else perform digest operation
 *
 * See the man pages for digest and mac for details on
 * how these commands work.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <strings.h>
#include <libintl.h>
#include <libgen.h>
#include <locale.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <security/cryptoki.h>
#include <limits.h>
#include <cryptoutil.h>
#include <kmfapi.h>

#define	BUFFERSIZE	(4096)		/* Buffer size for reading file */

/*
 * RESULTLEN - large enough size in bytes to hold result for
 * digest and mac results for all mechanisms
 */
#define	RESULTLEN	(512)

/*
 * Default parameters for PBKDF2 algorithm
 */
#define	PBKD2_ITERATIONS (1000)
#define	PBKD2_SALT_SIZE 16

/*
 * Exit Status codes
 */
#ifndef	EXIT_SUCCESS
#define	EXIT_SUCCESS	0	/* No errors */
#define	EXIT_FAILURE	1	/* All errors except usage */
#endif /* EXIT_SUCCESS */

#define	EXIT_USAGE	2	/* usage/syntax error */

#define	MAC_NAME	"mac"		/* name of mac command */
#define	MAC_OPTIONS	"lva:k:T:K:"		/* for getopt */
#define	DIGEST_NAME	"digest"	/* name of mac command */
#define	DIGEST_OPTIONS	"lva:"		/* for getopt */
#define	DEFAULT_TOKEN_PROMPT	"Enter PIN for %s: "
#define	PK_DEFAULT_PK11TOKEN	SOFT_TOKEN_LABEL

static boolean_t vflag = B_FALSE;	/* -v (verbose) flag, optional */
static boolean_t aflag = B_FALSE;	/* -a <algorithm> flag, required */
static boolean_t lflag = B_FALSE;	/* -l flag, for mac and digest */
static boolean_t kflag = B_FALSE;
static boolean_t Tflag = B_FALSE;
static boolean_t Kflag = B_FALSE;

static char *keyfile = NULL;	/* name of keyfile */
static char *token_label = NULL;
static char *key_label = NULL;

static CK_BYTE buf[BUFFERSIZE];

struct mech_alias {
	CK_MECHANISM_TYPE type;
	char *alias;
	CK_ULONG keysize_min;
	CK_ULONG keysize_max;
	int keysize_unit;
	boolean_t available;
};

#define	MECH_ALIASES_COUNT 11

static struct mech_alias mech_aliases[] = {
	{ CKM_SHA_1, "sha1", ULONG_MAX, 0L, 8, B_FALSE },
	{ CKM_MD5, "md5", ULONG_MAX, 0L, 8, B_FALSE },
	{ CKM_DES_MAC, "des_mac", ULONG_MAX, 0L, 8, B_FALSE },
	{ CKM_SHA_1_HMAC, "sha1_hmac", ULONG_MAX, 0L, 8, B_FALSE },
	{ CKM_MD5_HMAC, "md5_hmac", ULONG_MAX, 0L, 8, B_FALSE },
	{ CKM_SHA256, "sha256", ULONG_MAX, 0L, 8, B_FALSE },
	{ CKM_SHA384, "sha384", ULONG_MAX, 0L, 8, B_FALSE },
	{ CKM_SHA512, "sha512", ULONG_MAX, 0L, 8, B_FALSE },
	{ CKM_SHA256_HMAC, "sha256_hmac", ULONG_MAX, 0L, 8, B_FALSE },
	{ CKM_SHA384_HMAC, "sha384_hmac", ULONG_MAX, 0L, 8, B_FALSE },
	{ CKM_SHA512_HMAC, "sha512_hmac", ULONG_MAX, 0L, 8, B_FALSE }
};

static CK_BBOOL true = TRUE;

static void usage(boolean_t mac_cmd);
static int execute_cmd(char *algo_str, int filecount,
	char **filelist, boolean_t mac_cmd);
static CK_RV do_mac(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pmech,
	int fd, CK_OBJECT_HANDLE key, CK_BYTE_PTR *psignature,
	CK_ULONG_PTR psignaturelen);
static CK_RV do_digest(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pmech,
	int fd, CK_BYTE_PTR *pdigest, CK_ULONG_PTR pdigestlen);
static int getkey(char *filename, CK_BYTE_PTR *pkeydata);
static int getpasswd(char *token_spec, CK_BYTE_PTR *pdata, CK_ULONG_PTR psize);

int
main(int argc, char **argv)
{

	extern char *optarg;
	extern int optind;
	int errflag = 0;	/* We had an optstr parse error */
	char c;			/* current getopts flag */
	char *algo_str;		/* mechanism/algorithm string */
	int filecount;
	boolean_t mac_cmd;	/* if TRUE, do mac, else do digest */
	char *optstr;
	char **filelist;	/* list of files */
	char *cmdname = NULL;	/* name of command */

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defiend by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	/*
	 * Based on command name, determine
	 * type of command. mac is mac
	 * everything else is digest.
	 */
	cmdname = basename(argv[0]);

	cryptodebug_init(cmdname);

	if (strcmp(cmdname, MAC_NAME) == 0)
		mac_cmd = B_TRUE;
	else if (strcmp(cmdname, DIGEST_NAME) == 0)
		mac_cmd = B_FALSE;
	else {
		cryptoerror(LOG_STDERR, gettext(
		    "command name must be either digest or mac\n"));
		exit(EXIT_USAGE);
	}

	if (mac_cmd) {
		optstr = MAC_OPTIONS;
	} else {
		optstr = DIGEST_OPTIONS;
	}

	/* Parse command line arguments */
	while (!errflag && (c = getopt(argc, argv, optstr)) != -1) {

		switch (c) {
		case 'v':
			vflag = B_TRUE;
			break;
		case 'a':
			aflag = B_TRUE;
			algo_str = optarg;
			break;
		case 'k':
			kflag = B_TRUE;
			keyfile = optarg;
			break;
		case 'l':
			lflag = B_TRUE;
			break;
		case 'T':
			Tflag = B_TRUE;
			token_label = optarg;
			break;
		case 'K':
			Kflag = B_TRUE;
			key_label = optarg;
			break;
		default:
			errflag++;
		}
	}

	filecount = argc - optind;
	if (errflag || (!aflag && !lflag) || (lflag && argc > 2) ||
	    (kflag && Kflag) || (Tflag && !Kflag) || filecount < 0) {
		usage(mac_cmd);
		exit(EXIT_USAGE);
	}

	if (filecount == 0) {
		filelist = NULL;
	} else {
		filelist = &argv[optind];
	}

	return (execute_cmd(algo_str, filecount, filelist, mac_cmd));
}

/*
 * usage message for digest/mac
 */
static void
usage(boolean_t mac_cmd)
{
	(void) fprintf(stderr, gettext("Usage:\n"));
	if (mac_cmd) {
		(void) fprintf(stderr, gettext("  mac -l\n"));
		(void) fprintf(stderr, gettext("  mac [-v] -a <algorithm> "
		    "[-k <keyfile> | -K <keylabel> [-T <tokenspec>]] "
		    "[file...]\n"));
	} else {
		(void) fprintf(stderr, gettext("  digest -l | [-v] "
		    "-a <algorithm> [file...]\n"));
	}
}

/*
 * Print out list of available algorithms.
 */
static void
algorithm_list(boolean_t mac_cmd)
{
	int mech;

	if (mac_cmd)
		(void) printf(gettext("Algorithm       Keysize:  Min   "
		    "Max (bits)\n"
		    "------------------------------------------\n"));

	for (mech = 0; mech < MECH_ALIASES_COUNT; mech++) {

		if (mech_aliases[mech].available == B_FALSE)
			continue;

		if (mac_cmd) {
			(void) printf("%-15s", mech_aliases[mech].alias);

			if (mech_aliases[mech].keysize_min != ULONG_MAX &&
			    mech_aliases[mech].keysize_max != 0)
				(void) printf("         %5lu %5lu\n",
				    (mech_aliases[mech].keysize_min *
				    mech_aliases[mech].keysize_unit),
				    (mech_aliases[mech].keysize_max *
				    mech_aliases[mech].keysize_unit));
			else
				(void) printf("\n");

		} else
			(void) printf("%s\n", mech_aliases[mech].alias);

	}
}

static CK_RV
generate_pkcs5_key(CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR	pSaltData,
		CK_ULONG	saltLen,
		CK_ULONG	iterations,
		CK_BYTE_PTR	pkeydata, /* user entered passphrase */
		CK_KEY_TYPE	keytype,
		CK_ULONG	passwd_size,
		CK_ULONG	keylen,	 /* desired length of generated key */
		CK_OBJECT_HANDLE *hKey)
{
	CK_RV rv;
	CK_PKCS5_PBKD2_PARAMS params;
	CK_MECHANISM mechanism;
	CK_OBJECT_CLASS class = CKO_SECRET_KEY;
	CK_ATTRIBUTE tmpl[4];
	int attrs = 0;

	tmpl[attrs].type = CKA_CLASS;
	tmpl[attrs].pValue = &class;
	tmpl[attrs].ulValueLen = sizeof (class);
	attrs++;

	tmpl[attrs].type = CKA_KEY_TYPE;
	tmpl[attrs].pValue = &keytype;
	tmpl[attrs].ulValueLen = sizeof (keytype);
	attrs++;

	tmpl[attrs].type = CKA_SIGN;
	tmpl[attrs].pValue = &true;
	tmpl[attrs].ulValueLen = sizeof (CK_BBOOL);
	attrs++;

	if (keylen > 0) {
		tmpl[attrs].type = CKA_VALUE_LEN;
		tmpl[attrs].pValue = &keylen;
		tmpl[attrs].ulValueLen = sizeof (keylen);
		attrs++;
	}

	params.saltSource = CKZ_SALT_SPECIFIED;
	params.pSaltSourceData = (void *)pSaltData;
	params.ulSaltSourceDataLen = saltLen;
	params.iterations = iterations;
	params.prf = CKP_PKCS5_PBKD2_HMAC_SHA1;
	params.pPrfData = NULL;
	params.ulPrfDataLen = 0;
	params.pPassword = (CK_UTF8CHAR_PTR)pkeydata;
	params.ulPasswordLen = &passwd_size;

	mechanism.mechanism = CKM_PKCS5_PBKD2;
	mechanism.pParameter = &params;
	mechanism.ulParameterLen = sizeof (params);

	rv = C_GenerateKey(hSession, &mechanism, tmpl, attrs, hKey);

	return (rv);
}


static int
get_token_key(CK_SESSION_HANDLE hSession, CK_KEY_TYPE keytype,
    char *keylabel, CK_BYTE *password, int password_len,
    CK_OBJECT_HANDLE *keyobj)
{
	CK_RV rv;
	CK_ATTRIBUTE pTmpl[10];
	CK_OBJECT_CLASS class = CKO_SECRET_KEY;
	CK_BBOOL true = 1;
	CK_BBOOL is_token = 1;
	CK_ULONG key_obj_count = 1;
	int i;
	CK_KEY_TYPE ckKeyType = keytype;


	rv = C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)password,
	    password_len);
	if (rv != CKR_OK) {
		(void) fprintf(stderr, "Cannot login to the token."
		    " error = %s\n", pkcs11_strerror(rv));
		return (-1);
	}

	i = 0;
	pTmpl[i].type = CKA_TOKEN;
	pTmpl[i].pValue = &is_token;
	pTmpl[i].ulValueLen = sizeof (CK_BBOOL);
	i++;

	pTmpl[i].type = CKA_CLASS;
	pTmpl[i].pValue = &class;
	pTmpl[i].ulValueLen = sizeof (class);
	i++;

	pTmpl[i].type = CKA_LABEL;
	pTmpl[i].pValue = keylabel;
	pTmpl[i].ulValueLen = strlen(keylabel);
	i++;

	pTmpl[i].type = CKA_KEY_TYPE;
	pTmpl[i].pValue = &ckKeyType;
	pTmpl[i].ulValueLen = sizeof (ckKeyType);
	i++;

	pTmpl[i].type = CKA_PRIVATE;
	pTmpl[i].pValue = &true;
	pTmpl[i].ulValueLen = sizeof (true);
	i++;

	rv = C_FindObjectsInit(hSession, pTmpl, i);
	if (rv != CKR_OK) {
		goto out;
	}

	rv = C_FindObjects(hSession, keyobj, 1, &key_obj_count);
	(void) C_FindObjectsFinal(hSession);

out:
	if (rv != CKR_OK) {
		(void) fprintf(stderr,
		    "Cannot retrieve key object. error = %s\n",
		    pkcs11_strerror(rv));
		return (-1);
	}

	if (key_obj_count == 0) {
		(void) fprintf(stderr, "Cannot find the key object.\n");
		return (-1);
	}

	return (0);
}


/*
 * Execute the command.
 *   algo_str - name of algorithm
 *   filecount - no. of files to process, if 0, use stdin
 *   filelist - list of files
 *   mac_cmd - if true do mac else do digest
 */
static int
execute_cmd(char *algo_str, int filecount, char **filelist, boolean_t mac_cmd)
{
	int fd;
	char *filename = NULL;
	CK_RV rv;
	CK_ULONG slotcount;
	CK_SLOT_ID slotID;
	CK_SLOT_ID_PTR pSlotList = NULL;
	CK_MECHANISM_TYPE mech_type;
	CK_MECHANISM_INFO info;
	CK_MECHANISM mech;
	CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
	CK_BYTE_PTR resultbuf = NULL;
	CK_ULONG resultlen;
	CK_BYTE_PTR	pkeydata = NULL;
	CK_OBJECT_HANDLE key = (CK_OBJECT_HANDLE) 0;
	int keylen = 0;		/* key length */
	char *resultstr = NULL;	/* result in hex string */
	int resultstrlen;	/* result string length */
	int i;
	int exitcode = EXIT_SUCCESS;		/* return code */
	int slot, mek;			/* index variables */
	int mech_match = 0;
	CK_BYTE		salt[PBKD2_SALT_SIZE];
	CK_ULONG	keysize;
	CK_ULONG	iterations = PBKD2_ITERATIONS;
	CK_KEY_TYPE keytype;
	KMF_RETURN kmfrv;
	CK_SLOT_ID token_slot_id;

	if (aflag) {
		/*
		 * Determine if algorithm/mechanism is valid
		 */
		for (mech_match = 0; mech_match < MECH_ALIASES_COUNT;
		    mech_match++) {
			if (strcmp(algo_str,
			    mech_aliases[mech_match].alias) == 0) {
				mech_type = mech_aliases[mech_match].type;
				break;
			}

		}

		if (mech_match == MECH_ALIASES_COUNT) {
			cryptoerror(LOG_STDERR,
			    gettext("unknown algorithm -- %s"), algo_str);
			return (EXIT_FAILURE);
		}

		/* Get key to do a MAC operation */
		if (mac_cmd) {
			if (Kflag) {
				int status;

				if (token_label == NULL ||
				    !strlen(token_label)) {
					token_label = PK_DEFAULT_PK11TOKEN;
				}

				status = getpasswd(token_label, &pkeydata,
				    (CK_ULONG *)&keylen);
				if (status == -1) {
					cryptoerror(LOG_STDERR,
					    gettext("invalid passphrase."));
					return (EXIT_FAILURE);
				}

			} else {
				keylen = getkey(keyfile, &pkeydata);
				if (keylen <= 0 || pkeydata == NULL) {
					cryptoerror(LOG_STDERR,
					    gettext("invalid key."));
					return (EXIT_FAILURE);
				}
			}
		}
	}

	/* Initialize, and get list of slots */
	rv = C_Initialize(NULL);
	if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		cryptoerror(LOG_STDERR,
		    gettext("failed to initialize PKCS #11 framework: %s"),
		    pkcs11_strerror(rv));
		return (EXIT_FAILURE);
	}

	/* Get slot count */
	rv = C_GetSlotList(0, NULL_PTR, &slotcount);
	if (rv != CKR_OK || slotcount == 0) {
		cryptoerror(LOG_STDERR, gettext(
		    "failed to find any cryptographic provider,"
		    "please check with your system administrator: %s"),
		    pkcs11_strerror(rv));
		exitcode = EXIT_FAILURE;
		goto cleanup;
	}

	/* Found at least one slot, allocate memory for slot list */
	pSlotList = malloc(slotcount * sizeof (CK_SLOT_ID));
	if (pSlotList == NULL_PTR) {
		int err = errno;
		cryptoerror(LOG_STDERR, gettext("malloc: %s\n"),
		    strerror(err));
		exitcode = EXIT_FAILURE;
		goto cleanup;
	}

	/* Get the list of slots */
	if ((rv = C_GetSlotList(0, pSlotList, &slotcount)) != CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "failed to find any cryptographic provider,"
		    "please check with your system administrator: %s"),
		    pkcs11_strerror(rv));
		exitcode = EXIT_FAILURE;
		goto cleanup;
	}

	/*
	 * Obtain list of algorithms if -l option was given
	 */
	if (lflag) {

		for (slot = 0; slot < slotcount; slot++) {

			/* Iterate through each mechanism */
			for (mek = 0; mek < MECH_ALIASES_COUNT; mek++) {
				rv = C_GetMechanismInfo(pSlotList[slot],
				    mech_aliases[mek].type, &info);

				/* Only check algorithms that can be used */
				if ((rv != CKR_OK) ||
				    (!mac_cmd && (info.flags & CKF_SIGN)) ||
				    (mac_cmd && (info.flags & CKF_DIGEST)))
					continue;

				/*
				 * Set to minimum/maximum key sizes assuming
				 * the values available are not 0.
				 */
				if (info.ulMinKeySize && (info.ulMinKeySize <
				    mech_aliases[mek].keysize_min))
					mech_aliases[mek].keysize_min =
					    info.ulMinKeySize;

				if (info.ulMaxKeySize && (info.ulMaxKeySize >
				    mech_aliases[mek].keysize_max))
					mech_aliases[mek].keysize_max =
					    info.ulMaxKeySize;

				mech_aliases[mek].available = B_TRUE;
			}

		}

		algorithm_list(mac_cmd);

		goto cleanup;
	}

	/*
	 * Find a slot with matching mechanism
	 *
	 * If -K is specified, we find the slot id for the token first, then
	 * check if the slot supports the algorithm.
	 */
	i = 0;
	if (Kflag) {
		kmfrv = kmf_pk11_token_lookup(NULL, token_label,
		    &token_slot_id);
		if (kmfrv != KMF_OK) {
			cryptoerror(LOG_STDERR,
			    gettext("no matching PKCS#11 token"));
			exitcode = EXIT_FAILURE;
			goto cleanup;
		}
		rv = C_GetMechanismInfo(token_slot_id, mech_type, &info);
		if (rv == CKR_OK && (info.flags & CKF_SIGN))
			slotID = token_slot_id;
		else
			i = slotcount;

	} else {
		for (i = 0; i < slotcount; i++) {
			slotID = pSlotList[i];
			rv = C_GetMechanismInfo(slotID, mech_type, &info);
			if (rv != CKR_OK) {
				continue; /* to the next slot */
			} else {
				if (mac_cmd) {
					/*
					 * Make sure the slot supports
					 * PKCS5 key generation if we
					 * will be using it later.
					 * We use it whenever the key
					 * is entered at command line.
					 */
					if ((info.flags & CKF_SIGN) &&
					    (keyfile == NULL)) {
						CK_MECHANISM_INFO kg_info;
						rv = C_GetMechanismInfo(slotID,
						    CKM_PKCS5_PBKD2, &kg_info);
						if (rv == CKR_OK)
							break;
					} else if (info.flags & CKF_SIGN) {
						break;
					}
				} else {
					if (info.flags & CKF_DIGEST)
						break;
				}
			}
		}
	}

	/* Show error if no matching mechanism found */
	if (i == slotcount) {
		cryptoerror(LOG_STDERR,
		    gettext("no cryptographic provider was "
		    "found for this algorithm -- %s"), algo_str);
		exitcode = EXIT_FAILURE;
		goto cleanup;
	}

	/* Mechanism is supported. Go ahead & open a session */
	rv = C_OpenSession(slotID, CKF_SERIAL_SESSION,
	    NULL_PTR, NULL, &hSession);

	if (rv != CKR_OK) {
		cryptoerror(LOG_STDERR,
		    gettext("can not open PKCS#11 session: %s"),
		    pkcs11_strerror(rv));
		exitcode = EXIT_FAILURE;
		goto cleanup;
	}

	/* Create a key object for mac operation */
	if (mac_cmd) {
		/*
		 * If we read keybytes from a file,
		 * do NOT process them with C_GenerateKey,
		 * treat them as raw keydata bytes and
		 * create a key object for them.
		 */
		if (keyfile) {
			CK_OBJECT_CLASS class = CKO_SECRET_KEY;
			CK_KEY_TYPE tmpl_keytype = CKK_GENERIC_SECRET;
			CK_BBOOL false = FALSE;
			int nattr = 0;
			CK_ATTRIBUTE template[5];

			if (mech_type == CKM_DES_MAC) {
				tmpl_keytype = CKK_DES;
			}
			template[nattr].type = CKA_CLASS;
			template[nattr].pValue = &class;
			template[nattr].ulValueLen = sizeof (class);
			nattr++;

			template[nattr].type = CKA_KEY_TYPE;
			template[nattr].pValue = &tmpl_keytype;
			template[nattr].ulValueLen = sizeof (tmpl_keytype);
			nattr++;

			template[nattr].type = CKA_SIGN;
			template[nattr].pValue = &true;
			template[nattr].ulValueLen = sizeof (true);
			nattr++;

			template[nattr].type = CKA_TOKEN;
			template[nattr].pValue = &false;
			template[nattr].ulValueLen = sizeof (false);
			nattr++;

			template[nattr].type = CKA_VALUE;
			template[nattr].pValue = pkeydata;
			template[nattr].ulValueLen = keylen;
			nattr++;

			rv = C_CreateObject(hSession, template, nattr, &key);

		} else if (Kflag) {

			if (mech_type == CKM_DES_MAC) {
				keytype = CKK_DES;
			} else {
				keytype = CKK_GENERIC_SECRET;
			}

			rv = get_token_key(hSession, keytype, key_label,
			    pkeydata, keylen, &key);
			if (rv != CKR_OK) {
				exitcode = EXIT_FAILURE;
				goto cleanup;
			}
		} else {
			CK_KEY_TYPE keytype;
			if (mech_type == CKM_DES_MAC) {
				keytype = CKK_DES;
				keysize = 0;
			} else {
				keytype = CKK_GENERIC_SECRET;
				keysize = 16; /* 128 bits */
			}
			/*
			 * We use a fixed salt (0x0a, 0x0a, 0x0a ...)
			 * for creating the key so that the end user
			 * will be able to generate the same 'mac'
			 * using the same passphrase.
			 */
			(void) memset(salt, 0x0a, sizeof (salt));
			rv = generate_pkcs5_key(hSession,
			    salt, sizeof (salt), iterations, pkeydata,
			    keytype, keylen, keysize, &key);
		}

		if (rv != CKR_OK) {
			cryptoerror(LOG_STDERR,
			    gettext("unable to create key for crypto "
			    "operation: %s"), pkcs11_strerror(rv));
			exitcode = EXIT_FAILURE;
			goto cleanup;
		}
	}

	/* Allocate a buffer to store result. */
	resultlen = RESULTLEN;
	if ((resultbuf = malloc(resultlen)) == NULL) {
		int err = errno;
		cryptoerror(LOG_STDERR, gettext("malloc: %s\n"),
		    strerror(err));
		exitcode = EXIT_FAILURE;
		goto cleanup;
	}

	/* Allocate a buffer to store result string */
	resultstrlen = RESULTLEN;
	if ((resultstr = malloc(resultstrlen)) == NULL) {
		int err = errno;
		cryptoerror(LOG_STDERR, gettext("malloc: %s\n"),
		    strerror(err));
		exitcode = EXIT_FAILURE;
		goto cleanup;
	}

	mech.mechanism = mech_type;
	mech.pParameter = NULL_PTR;
	mech.ulParameterLen = 0;
	exitcode = EXIT_SUCCESS;
	i = 0;

	do {
		if (filecount > 0 && filelist != NULL) {
			filename = filelist[i];
			if ((fd = open(filename, O_RDONLY | O_NONBLOCK)) ==
			    -1) {
				cryptoerror(LOG_STDERR, gettext(
				    "can not open input file %s\n"), filename);
				exitcode = EXIT_USAGE;
				continue;
			}
		} else {
			fd = 0; /* use stdin */
		}

		/*
		 * Perform the operation
		 */
		if (mac_cmd) {
			rv = do_mac(hSession, &mech, fd, key, &resultbuf,
			    &resultlen);
		} else {
			rv = do_digest(hSession, &mech, fd, &resultbuf,
			    &resultlen);
		}

		if (rv != CKR_OK) {
			cryptoerror(LOG_STDERR,
			    gettext("crypto operation failed for "
			    "file %s: %s\n"),
			    filename ? filename : "STDIN",
			    pkcs11_strerror(rv));
			exitcode = EXIT_FAILURE;
			continue;
		}

		/* if result size has changed, allocate a bigger resulstr buf */
		if (resultlen != RESULTLEN) {
			resultstrlen = 2 * resultlen + 1;
			resultstr = realloc(resultstr, resultstrlen);

			if (resultstr == NULL) {
				int err = errno;
				cryptoerror(LOG_STDERR,
				    gettext("realloc: %s\n"), strerror(err));
				exitcode =  EXIT_FAILURE;
				goto cleanup;
			}
		}

		/* Output the result */
		tohexstr(resultbuf, resultlen, resultstr, resultstrlen);

		/* Include mechanism name for verbose */
		if (vflag)
			(void) fprintf(stdout, "%s ", algo_str);

		/* Include file name for multiple files, or if verbose */
		if (filecount > 1 || (vflag && filecount > 0)) {
			(void) fprintf(stdout, "(%s) = ", filename);
		}

		(void) fprintf(stdout, "%s\n", resultstr);
		(void) close(fd);


	} while (++i < filecount);


	/* clear and free the key */
	if (mac_cmd) {
		(void) memset(pkeydata, 0, keylen);
		free(pkeydata);
		pkeydata = NULL;
	}

cleanup:
	if (resultbuf != NULL) {
		free(resultbuf);
	}

	if (resultstr != NULL) {
		free(resultstr);
	}

	if (pSlotList != NULL) {
		free(pSlotList);
	}

	if (!Kflag && key != (CK_OBJECT_HANDLE) 0) {
		(void) C_DestroyObject(hSession, key);
	}

	if (hSession != CK_INVALID_HANDLE)
		(void) C_CloseSession(hSession);

	(void) C_Finalize(NULL_PTR);

	return (exitcode);
}

/*
 * do_digest - Compute digest of a file
 *
 *  hSession - session
 *  pmech - ptr to mechanism to be used for digest
 *  fd  - file descriptor
 *  pdigest - buffer  where digest result is returned
 *  pdigestlen - length of digest buffer on input,
 *               length of result on output
 */
static CK_RV
do_digest(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pmech,
	int fd, CK_BYTE_PTR *pdigest, CK_ULONG_PTR pdigestlen)
{
	CK_RV rv;
	ssize_t nread;
	int saved_errno;

	if ((rv = C_DigestInit(hSession, pmech)) != CKR_OK) {
		return (rv);
	}

	while ((nread = read(fd, buf, sizeof (buf))) > 0) {
		/* Get the digest */
		rv = C_DigestUpdate(hSession, buf, (CK_ULONG)nread);
		if (rv != CKR_OK)
			return (rv);
	}

	saved_errno = errno; /* for later use */

	/*
	 * Perform the C_DigestFinal, even if there is a read error.
	 * Otherwise C_DigestInit will return CKR_OPERATION_ACTIVE
	 * next time it is called (for another file)
	 */

	rv = C_DigestFinal(hSession, *pdigest, pdigestlen);

	/* result too big to fit? Allocate a bigger buffer */
	if (rv == CKR_BUFFER_TOO_SMALL) {
		*pdigest = realloc(*pdigest, *pdigestlen);

		if (*pdigest == NULL_PTR) {
			int err = errno;
			cryptoerror(LOG_STDERR,
			    gettext("realloc: %s\n"), strerror(err));
			return (CKR_HOST_MEMORY);
		}

		rv = C_DigestFinal(hSession, *pdigest, pdigestlen);
	}


	/* There was a read error */
	if (nread == -1) {
		cryptoerror(LOG_STDERR, gettext(
		    "error reading file: %s"), strerror(saved_errno));
		return (CKR_GENERAL_ERROR);
	} else {
		return (rv);
	}
}

/*
 * do_mac - Compute mac of a file
 *
 *  hSession - session
 *  pmech - ptr to mechanism to be used
 *  fd  - file descriptor
 *  key - key to be used
 *  psignature - ptr buffer  where mac result is returned
 *		returns new buf if current buf is small
 *  psignaturelen - length of mac buffer on input,
 *               length of result on output
 */
static CK_RV
do_mac(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pmech,
	int fd, CK_OBJECT_HANDLE key, CK_BYTE_PTR *psignature,
	CK_ULONG_PTR psignaturelen)
{
	CK_RV rv;
	ssize_t nread;
	int saved_errno;

	if ((rv = C_SignInit(hSession, pmech, key)) != CKR_OK) {
		return (rv);
	}

	while ((nread = read(fd, buf, sizeof (buf))) > 0) {
		/* Get the MAC */
		rv = C_SignUpdate(hSession, buf, (CK_ULONG)nread);
		if (rv != CKR_OK)
			return (rv);
	}

	saved_errno = errno; /* for later use */

	/*
	 * Perform the C_SignFinal, even if there is a read error.
	 * Otherwise C_SignInit will return CKR_OPERATION_ACTIVE
	 * next time it is called (for another file)
	 */

	rv = C_SignFinal(hSession, *psignature, psignaturelen);

	/* result too big to fit? Allocate a bigger buffer */
	if (rv == CKR_BUFFER_TOO_SMALL) {
		*psignature = realloc(*psignature, *psignaturelen);

		if (*psignature == NULL_PTR) {
			int err = errno;
			cryptoerror(LOG_STDERR,
			    gettext("realloc: %s\n"), strerror(err));
			return (CKR_HOST_MEMORY);
		}

		rv = C_SignFinal(hSession, *psignature, psignaturelen);
	}

	/* There was a read error */
	if (nread == -1) {
		cryptoerror(LOG_STDERR, gettext("error reading file: %s"),
		    strerror(saved_errno));
		return (CKR_GENERAL_ERROR);
	} else {
		return (rv);
	}
}


/*
 * getkey - gets keydata from file specified
 *
 *  filename - name of file, if null, prompt for pass phrase
 *  pkeydata - binary key data is returned in this buf
 *
 * returns length of key, or -1 if error
 */
static int
getkey(char *filename, CK_BYTE_PTR *pkeydata)
{
	struct stat statbuf;
	char *keybuf = NULL;
	char *tmpbuf;
	int keylen;
	int fd;

	if (filename != NULL) {

		/* read the key file into a buffer */
		if ((fd = open(filename, O_RDONLY | O_NONBLOCK)) == -1) {
			cryptoerror(LOG_STDERR, gettext(
			    "can't open %s\n"), filename);
			return (-1);

		}

		if (fstat(fd, &statbuf) == -1) {
			cryptoerror(LOG_STDERR, gettext(
			    "can't stat %s\n"), filename);
			(void) close(fd);
			return (-1);
		}

		if (!S_ISREG(statbuf.st_mode)) {
			cryptoerror(LOG_STDERR, gettext(
			    "%s not a regular file\n"), filename);
			(void) close(fd);
			return (-1);
		}

		keylen = (size_t)statbuf.st_size;

		if (keylen > 0) {
			/* allocate a buffer to hold the entire key */
			if ((keybuf = malloc(keylen)) == NULL) {
				int err = errno;
				cryptoerror(LOG_STDERR, gettext("malloc: %s\n"),
				    strerror(err));
				(void) close(fd);
				return (-1);
			}

			if (read(fd, keybuf, keylen) != keylen) {
				cryptoerror(LOG_STDERR, gettext(
				    "can't read %s\n"), filename);
				(void) close(fd);
				return (-1);
			}
		}
		(void) close(fd);

	} else {

		/* No file, prompt for a pass phrase */
		tmpbuf = getpassphrase(gettext("Enter key:"));

		if (tmpbuf == NULL) {
			return (-1);	/* error */
		} else {
			keybuf = strdup(tmpbuf);
			(void) memset(tmpbuf, 0, strlen(tmpbuf));
		}
		keylen = strlen(keybuf);
	}

	*pkeydata = (CK_BYTE_PTR)keybuf;

	return (keylen);
}

static int
getpasswd(char *token_spec, CK_BYTE_PTR *pdata, CK_ULONG *psize)
{
	char *databuf;
	char *tmpbuf;
	char prompt[1024];

	if (token_spec == NULL)
		return (-1);

	(void) snprintf(prompt, sizeof (prompt), DEFAULT_TOKEN_PROMPT,
	    token_spec);
	tmpbuf = getpassphrase(gettext(prompt));

	if (tmpbuf == NULL) {
		return (-1);	/* error */
	}

	databuf = strdup(tmpbuf);
	(void) memset(tmpbuf, 0, strlen(tmpbuf));
	if (databuf == NULL)
		return (-1);

	*pdata = (CK_BYTE_PTR)databuf;
	*psize = (CK_ULONG)strlen(databuf);

	return (0);
}
