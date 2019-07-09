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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * This file contains the functions that are shared among
 * the various services this tool will ultimately provide.
 * The functions in this file return PKCS#11 CK_RV errors.
 * Only one session and one login per token is supported
 * at this time.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <tzfile.h>
#include <cryptoutil.h>
#include <security/cryptoki.h>
#include <kmfapi.h>

#include "common.h"

/* Local status variables. */
static boolean_t	initialized = B_FALSE;
static boolean_t	session_opened = B_FALSE;
static boolean_t	logged_in = B_FALSE;

/* Supporting structures and global variables for getopt_av(). */
typedef struct	av_opts_s {
	int		shortnm;	/* short name character */
	char		*longnm;	/* long name string, NOT terminated */
	int		longnm_len;	/* length of long name string */
	boolean_t	has_arg;	/* takes optional argument */
} av_opts;
static av_opts		*opts_av = NULL;
static const char	*_save_optstr = NULL;
static int		_save_numopts = 0;

int			optind_av = 1;
char			*optarg_av = NULL;

static void close_sess(CK_SESSION_HANDLE);
static void logout_token(CK_SESSION_HANDLE);

struct oid_table_entry {
	const KMF_OID *oid;
	char *name;
};

struct oid_table_entry oid_table[] = {
	{ &KMFOID_ECC_secp112r1, "secp112r1"},
	{ &KMFOID_ECC_secp112r2, "secp112r2"},
	{ &KMFOID_ECC_secp128r1, "secp128r1"},
	{ &KMFOID_ECC_secp128r2, "secp128r2"},
	{ &KMFOID_ECC_secp160k1, "secp160k1"},
	{ &KMFOID_ECC_secp160r1, "secp160r1"},
	{ &KMFOID_ECC_secp160r2, "secp160r2"},
	{ &KMFOID_ECC_secp192k1, "secp192k1"},
	{ &KMFOID_ECC_secp192r1, "secp192r1"},
	{ &KMFOID_ECC_secp224k1, "secp224k1"},
	{ &KMFOID_ECC_secp224r1, "secp224r1"},
	{ &KMFOID_ECC_secp256k1, "secp256k1"},
	{ &KMFOID_ECC_secp256r1, "secp256r1"},
	{ &KMFOID_ECC_secp384r1, "secp384r1"},
	{ &KMFOID_ECC_secp521r1, "secp521r1"},
	{ &KMFOID_ECC_sect113r1, "sect113r1"},
	{ &KMFOID_ECC_sect113r2, "sect113r2"},
	{ &KMFOID_ECC_sect131r1, "sect131r1"},
	{ &KMFOID_ECC_sect131r2, "sect131r2"},
	{ &KMFOID_ECC_sect163k1, "sect163k1"},
	{ &KMFOID_ECC_sect163r1, "sect163r1"},
	{ &KMFOID_ECC_sect163r2, "sect163r2"},
	{ &KMFOID_ECC_sect193r1, "sect193r1"},
	{ &KMFOID_ECC_sect193r2, "sect193r2"},
	{ &KMFOID_ECC_sect233k1, "sect233k1"},
	{ &KMFOID_ECC_sect233r1, "sect233r1"},
	{ &KMFOID_ECC_sect239k1, "sect239k1"},
	{ &KMFOID_ECC_sect283k1, "sect283k1"},
	{ &KMFOID_ECC_sect283r1, "sect283r1"},
	{ &KMFOID_ECC_sect409k1, "sect409k1"},
	{ &KMFOID_ECC_sect409r1, "sect409r1"},
	{ &KMFOID_ECC_sect571k1, "sect571k1"},
	{ &KMFOID_ECC_sect571r1, "sect571r1"},
	{ &KMFOID_ECC_c2pnb163v1, "c2pnb163v1"},
	{ &KMFOID_ECC_c2pnb163v2, "c2pnb163v2"},
	{ &KMFOID_ECC_c2pnb163v3, "c2pnb163v3"},
	{ &KMFOID_ECC_c2pnb176v1, "c2pnb176v1"},
	{ &KMFOID_ECC_c2tnb191v1, "c2tnb191v1"},
	{ &KMFOID_ECC_c2tnb191v2, "c2tnb191v2"},
	{ &KMFOID_ECC_c2tnb191v3, "c2tnb191v3"},
	{ &KMFOID_ECC_c2pnb208w1, "c2pnb208w1"},
	{ &KMFOID_ECC_c2tnb239v1, "c2tnb239v1"},
	{ &KMFOID_ECC_c2tnb239v2, "c2tnb239v2"},
	{ &KMFOID_ECC_c2tnb239v3, "c2tnb239v3"},
	{ &KMFOID_ECC_c2pnb272w1, "c2pnb272w1"},
	{ &KMFOID_ECC_c2pnb304w1, "c2pnb304w1"},
	{ &KMFOID_ECC_c2tnb359v1, "c2tnb359v1"},
	{ &KMFOID_ECC_c2pnb368w1, "c2pnb368w1"},
	{ &KMFOID_ECC_c2tnb431r1, "c2tnb431r1"},
	{ &KMFOID_ECC_prime192v2, "prime192v2"},
	{ &KMFOID_ECC_prime192v3, "prime192v3"},
	{ &KMFOID_MD5, "md5"},
	{ &KMFOID_SHA1, "sha1"},
	{ &KMFOID_SHA256, "sha256"},
	{ &KMFOID_SHA384, "sha384"},
	{ &KMFOID_SHA512, "sha512"}
};
int number_of_oids = sizeof (oid_table) / sizeof (struct oid_table_entry);
#define	number_of_curves (number_of_oids - 5)

/*
 * Perform PKCS#11 setup here.  Currently only C_Initialize is required,
 * along with setting/resetting state variables.
 */
static CK_RV
init_pkcs11(void)
{
	CK_RV		rv = CKR_OK;

	/* If C_Initialize() already called, nothing to do here. */
	if (initialized == B_TRUE)
		return (CKR_OK);

	/* Reset state variables because C_Initialize() not yet done. */
	session_opened = B_FALSE;
	logged_in = B_FALSE;

	/* Initialize PKCS#11 library. */
	if ((rv = C_Initialize(NULL_PTR)) != CKR_OK &&
	    rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		return (rv);
	}

	initialized = B_TRUE;
	return (CKR_OK);
}

/*
 * Finalize PKCS#11 library and reset state variables.  Open sessions,
 * if any, are closed, and thereby any logins are logged out also.
 */
void
final_pk11(CK_SESSION_HANDLE sess)
{

	/* If the library wasn't initialized, nothing to do here. */
	if (!initialized)
		return;

	/* Make sure the sesion is closed first. */
	close_sess(sess);

	(void) C_Finalize(NULL);
	initialized = B_FALSE;
}

/*
 * Close PKCS#11 session and reset state variables.  Any logins are
 * logged out.
 */
static void
close_sess(CK_SESSION_HANDLE sess)
{

	if (sess == 0) {
		return;
	}

	/* If session is already closed, nothing to do here. */
	if (!session_opened)
		return;

	/* Make sure user is logged out of token. */
	logout_token(sess);

	(void) C_CloseSession(sess);
	session_opened = B_FALSE;
}

/*
 * Log user out of token and reset status variable.
 */
static void
logout_token(CK_SESSION_HANDLE sess)
{

	if (sess == 0) {
		return;
	}

	/* If already logged out, nothing to do here. */
	if (!logged_in)
		return;

	(void) C_Logout(sess);
	logged_in = B_FALSE;
}

/*
 * Gets PIN from user.  Caller needs to free the returned PIN when done.
 * If two prompts are given, the PIN is confirmed with second prompt.
 * Note that getphassphrase() may return data in static memory area.
 */
CK_RV
get_pin(char *prompt1, char *prompt2, CK_UTF8CHAR_PTR *pin, CK_ULONG *pinlen)
{
	char *save_phrase, *phrase1, *phrase2;

	/* Prompt user for a PIN. */
	if (prompt1 == NULL) {
		return (CKR_ARGUMENTS_BAD);
	}
	if ((phrase1 = getpassphrase(prompt1)) == NULL) {
		return (CKR_FUNCTION_FAILED);
	}

	/* Duplicate 1st PIN in separate chunk of memory. */
	if ((save_phrase = strdup(phrase1)) == NULL)
		return (CKR_HOST_MEMORY);

	/* If second prompt given, PIN confirmation is requested. */
	if (prompt2 != NULL) {
		if ((phrase2 = getpassphrase(prompt2)) == NULL) {
			free(save_phrase);
			return (CKR_FUNCTION_FAILED);
		}
		if (strcmp(save_phrase, phrase2) != 0) {
			free(save_phrase);
			return (CKR_PIN_INCORRECT);
		}
	}

	*pin = (CK_UTF8CHAR_PTR)save_phrase;
	*pinlen = strlen(save_phrase);
	return (CKR_OK);
}

int
yn_to_int(char *ynstr)
{
	char *y = gettext("yes");
	char *n = gettext("no");
	if (ynstr == NULL)
		return (-1);

	if (strncasecmp(ynstr, y, 1) == 0)
		return (1);
	else if (strncasecmp(ynstr, n, 1) == 0)
		return (0);
	else
		return (-1);
}

/*
 * Gets yes/no response from user.  If either no prompt is supplied, a
 * default prompt is used.  If not message for invalid input is supplied,
 * a default will not be provided.  If the user provides no response,
 * the input default B_TRUE == yes, B_FALSE == no is returned.
 * Otherwise, B_TRUE is returned for yes, and B_FALSE for no.
 */
boolean_t
yesno(char *prompt, char *invalid, boolean_t dflt)
{
	char	*response, buf[1024];
	int	ans;

	if (prompt == NULL)
		prompt = gettext("Enter (y)es or (n)o? ");

	for (;;) {
		/* Prompt user. */
		(void) printf("%s", prompt);
		(void) fflush(stdout);

		/* Get the response. */
		if ((response = fgets(buf, sizeof (buf), stdin)) == NULL)
			break;		/* go to default response */

		/* Skip any leading white space. */
		while (isspace(*response))
			response++;
		if (*response == '\0')
			break;		/* go to default response */

		ans = yn_to_int(response);
		if (ans == 1)
			return (B_TRUE);
		else if (ans == 0)
			return (B_FALSE);

		/* Indicate invalid input, and try again. */
		if (invalid != NULL)
			(void) printf("%s", invalid);
	}
	return (dflt);
}

/*
 * Gets the list of slots which have tokens in them.  Keeps adjusting
 * the size of the slot list buffer until the call is successful or an
 * irrecoverable error occurs.
 */
CK_RV
get_token_slots(CK_SLOT_ID_PTR *slot_list, CK_ULONG *slot_count)
{
	CK_ULONG	tmp_count = 0;
	CK_SLOT_ID_PTR	tmp_list = NULL_PTR, tmp2_list = NULL_PTR;
	int		rv = CKR_OK;

	if (!initialized)
		if ((rv = init_pkcs11()) != CKR_OK)
			return (rv);

	/*
	 * Get the slot count first because we don't know how many
	 * slots there are and how many of those slots even have tokens.
	 * Don't specify an arbitrary buffer size for the slot list;
	 * it may be too small (see section 11.5 of PKCS#11 spec).
	 * Also select only those slots that have tokens in them,
	 * because this tool has no need to know about empty slots.
	 */
	if ((rv = C_GetSlotList(1, NULL_PTR, &tmp_count)) != CKR_OK)
		return (rv);

	if (tmp_count == 0) {
		*slot_list = NULL_PTR;
		*slot_count = 0;
		return (CKR_OK);
	}

	/* Allocate initial space for the slot list. */
	if ((tmp_list = (CK_SLOT_ID_PTR) malloc(tmp_count *
	    sizeof (CK_SLOT_ID))) == NULL)
		return (CKR_HOST_MEMORY);

	/* Then get the slot list itself. */
	for (;;) {
		if ((rv = C_GetSlotList(1, tmp_list, &tmp_count)) == CKR_OK) {
			*slot_list = tmp_list;
			*slot_count = tmp_count;
			break;
		}

		if (rv != CKR_BUFFER_TOO_SMALL) {
			free(tmp_list);
			break;
		}

		/* If the number of slots grew, try again. */
		if ((tmp2_list = (CK_SLOT_ID_PTR) realloc(tmp_list,
		    tmp_count * sizeof (CK_SLOT_ID))) == NULL) {
			free(tmp_list);
			rv = CKR_HOST_MEMORY;
			break;
		}
		tmp_list = tmp2_list;
	}

	return (rv);
}

/*
 * Breaks out the getopt-style option string into a structure that can be
 * traversed later for calls to getopt_av().  Option string is NOT altered,
 * but the struct fields point to locations within option string.
 */
static int
populate_opts(char *optstring)
{
	int		i;
	av_opts		*temp;
	char		*marker;

	if (optstring == NULL || *optstring == '\0')
		return (0);

	/*
	 * This tries to imitate getopt(3c) Each option must conform to:
	 * <short name char> [ ':' ] [ '(' <long name string> ')' ]
	 * If long name is missing, the short name is used for long name.
	 */
	for (i = 0; *optstring != '\0'; i++) {
		if ((temp = (av_opts *)((i == 0) ? malloc(sizeof (av_opts)) :
		    realloc(opts_av, (i+1) * sizeof (av_opts)))) == NULL) {
			if (opts_av != NULL)
				free(opts_av);
			opts_av = NULL;
			return (0);
		} else {
			opts_av = (av_opts *)temp;
		}

		(void) memset(&opts_av[i], 0, sizeof (av_opts));
		marker = optstring;		/* may need optstring later */

		opts_av[i].shortnm = *marker++;	/* set short name */

		if (*marker == ':') {		/* check for opt arg */
			marker++;
			opts_av[i].has_arg = B_TRUE;
		}

		if (*marker == '(') {		/* check and set long name */
			marker++;
			opts_av[i].longnm = marker;
			opts_av[i].longnm_len = strcspn(marker, ")");
			optstring = marker + opts_av[i].longnm_len + 1;
		} else {
			/* use short name option character */
			opts_av[i].longnm = optstring;
			opts_av[i].longnm_len = 1;
			optstring = marker;
		}
	}

	return (i);
}

/*
 * getopt_av() is very similar to getopt(3c) in that the takes an option
 * string, compares command line arguments for matches, and returns a single
 * letter option when a match is found.  However, getopt_av() differs from
 * getopt(3c) by requiring that only longname options and values be found
 * on the command line and all leading dashes are omitted.  In other words,
 * it tries to enforce only longname "option=value" arguments on the command
 * line.  Boolean options are not allowed either.
 */
int
getopt_av(int argc, char * const *argv, const char *optstring)
{
	int	i;
	int	len;
	char   *cur_option;

	if (optind_av >= argc)
		return (EOF);

	/* First time or when optstring changes from previous one */
	if (_save_optstr != optstring) {
		if (opts_av != NULL)
			free(opts_av);
		opts_av = NULL;
		_save_optstr = optstring;
		_save_numopts = populate_opts((char *)optstring);
	}

	for (i = 0; i < _save_numopts; i++) {
		cur_option = argv[optind_av];

		if (strcmp(cur_option, "--") == 0) {
			optind_av++;
			break;
		}

		if (cur_option[0] == '-' && strlen(cur_option) == 2) {
			len = 1;
			cur_option++; /* remove "-" */
		} else {
			len = strcspn(cur_option, "=");
		}

		if (len == opts_av[i].longnm_len && strncmp(cur_option,
		    opts_av[i].longnm, opts_av[i].longnm_len) == 0) {
			/* matched */
			if (!opts_av[i].has_arg) {
				optind_av++;
				return (opts_av[i].shortnm);
			}

			/* needs optarg */
			if (cur_option[len] == '=') {
				optarg_av = &(cur_option[len+1]);
				optind_av++;
				return (opts_av[i].shortnm);
			}

			optarg_av = NULL;
			optind_av++;
			return ((int)'?');
		}
	}

	return (EOF);
}

KMF_KEYSTORE_TYPE
KS2Int(char *keystore_str)
{
	if (keystore_str == NULL)
		return (0);
	if (strcasecmp(keystore_str, "pkcs11") == 0)
		return (KMF_KEYSTORE_PK11TOKEN);
	else if (strcasecmp(keystore_str, "nss") == 0)
		return (KMF_KEYSTORE_NSS);
	else if (strcasecmp(keystore_str, "file") == 0)
		return (KMF_KEYSTORE_OPENSSL);
	else
		return (0);
}

/*
 * compare_oids
 * return 1 if equal
 */
boolean_t
compare_oids(KMF_OID *oid1, const KMF_OID *oid2)
{
	return ((oid1->Length == oid2->Length) &&
	    !memcmp(oid1->Data, oid2->Data, oid1->Length));
}

int
Str2KeyType(char *algm, KMF_OID *hashoid, KMF_KEY_ALG *ktype,
    KMF_ALGORITHM_INDEX *sigAlg)
{
	if (algm == NULL) {
		/* Default to SHA1+RSA */
		*sigAlg = KMF_ALGID_SHA1WithRSA;
		*ktype = KMF_RSA;
	} else if (strcasecmp(algm, "DSA") == 0) {
		if (hashoid == NULL ||
		    compare_oids(hashoid, &KMFOID_SHA1))
			*sigAlg = KMF_ALGID_SHA1WithDSA;
		else if (compare_oids(hashoid, &KMFOID_SHA256))
			*sigAlg = KMF_ALGID_SHA256WithDSA;
		else
			return (-1); /* unsupported hash/key combo */
		*ktype = KMF_DSA;
	} else if (strcasecmp(algm, "RSA") == 0) {
		if (hashoid == NULL ||
		    compare_oids(hashoid, &KMFOID_SHA1))
			*sigAlg = KMF_ALGID_SHA1WithRSA;
		else if (compare_oids(hashoid, &KMFOID_SHA256))
			*sigAlg = KMF_ALGID_SHA256WithRSA;
		else if (compare_oids(hashoid, &KMFOID_SHA384))
			*sigAlg = KMF_ALGID_SHA384WithRSA;
		else if (compare_oids(hashoid, &KMFOID_SHA512))
			*sigAlg = KMF_ALGID_SHA512WithRSA;
		else if (compare_oids(hashoid, &KMFOID_MD5))
			*sigAlg = KMF_ALGID_MD5WithRSA;
		else
			return (-1); /* unsupported hash/key combo */
		*ktype = KMF_RSA;
	} else if (strcasecmp(algm, "EC") == 0) {
		/* EC keys may be used with some SHA2 hashes */
		if (hashoid == NULL ||
		    compare_oids(hashoid, &KMFOID_SHA1))
			*sigAlg = KMF_ALGID_SHA1WithECDSA;
		else if (compare_oids(hashoid, &KMFOID_SHA256))
			*sigAlg = KMF_ALGID_SHA256WithECDSA;
		else if (compare_oids(hashoid, &KMFOID_SHA384))
			*sigAlg = KMF_ALGID_SHA384WithECDSA;
		else if (compare_oids(hashoid, &KMFOID_SHA512))
			*sigAlg = KMF_ALGID_SHA512WithECDSA;
		else
			return (-1); /* unsupported hash/key combo */

		*ktype = KMF_ECDSA;
	} else {
		return (-1);
	}
	return (0);
}

int
Str2SymKeyType(char *algm, KMF_KEY_ALG *ktype)
{
	if (algm == NULL)
		*ktype = KMF_AES;
	else if (strcasecmp(algm, "aes") == 0)
		*ktype = KMF_AES;
	else if (strcasecmp(algm, "arcfour") == 0)
		*ktype = KMF_RC4;
	else if (strcasecmp(algm, "des") == 0)
		*ktype = KMF_DES;
	else if (strcasecmp(algm, "3des") == 0)
		*ktype = KMF_DES3;
	else if (strcasecmp(algm, "generic") == 0)
		*ktype = KMF_GENERIC_SECRET;
	else
		return (-1);

	return (0);
}

int
Str2Lifetime(char *ltimestr, uint32_t *ltime)
{
	int num;
	char timetok[6];

	if (ltimestr == NULL || strlen(ltimestr) == 0) {
		/* default to 1 year lifetime */
		*ltime = SECSPERDAY * DAYSPERNYEAR;
		return (0);
	}

	(void) memset(timetok, 0, sizeof (timetok));
	if (sscanf(ltimestr, "%d-%06s", &num, timetok) != 2)
		return (-1);

	if (strcasecmp(timetok, "day") == 0||
	    strcasecmp(timetok, "days") == 0) {
		*ltime = num * SECSPERDAY;
	} else if (strcasecmp(timetok, "hour") == 0||
	    strcasecmp(timetok, "hours") == 0) {
		*ltime = num * SECSPERHOUR;
	} else if (strcasecmp(timetok, "year") == 0 ||
	    strcasecmp(timetok, "years") == 0) {
		*ltime = num * SECSPERDAY * DAYSPERNYEAR;
	} else {
		*ltime = 0;
		return (-1);
	}

	return (0);
}

int
OT2Int(char *objclass)
{
	char *c = NULL;
	int retval = 0;

	if (objclass == NULL)
		return (-1);

	c = strchr(objclass, ':');
	if (c != NULL) {
		if (strcasecmp(c, ":private") == 0)
			retval = PK_PRIVATE_OBJ;
		else if (strcasecmp(c, ":public") == 0)
			retval = PK_PUBLIC_OBJ;
		else if (strcasecmp(c, ":both") == 0)
			retval = PK_PRIVATE_OBJ | PK_PUBLIC_OBJ;
		else /* unrecognized option */
			return (-1);

		*c = '\0';
	}

	if (strcasecmp(objclass, "public") == 0) {
		if (retval)
			return (-1);
		return (retval | PK_PUBLIC_OBJ | PK_CERT_OBJ | PK_PUBKEY_OBJ);
	} else if (strcasecmp(objclass, "private") == 0) {
		if (retval)
			return (-1);
		return (retval | PK_PRIKEY_OBJ | PK_PRIVATE_OBJ);
	} else if (strcasecmp(objclass, "both") == 0) {
		if (retval)
			return (-1);
		return (PK_KEY_OBJ | PK_PUBLIC_OBJ | PK_PRIVATE_OBJ);
	} else if (strcasecmp(objclass, "cert") == 0) {
		return (retval | PK_CERT_OBJ);
	} else if (strcasecmp(objclass, "key") == 0) {
		if (retval == 0) /* return all keys */
			return (retval | PK_KEY_OBJ);
		else if (retval == (PK_PRIVATE_OBJ | PK_PUBLIC_OBJ))
			/* return all keys */
			return (retval | PK_KEY_OBJ);
		else if (retval & PK_PUBLIC_OBJ)
			/* Only return public keys */
			return (retval | PK_PUBKEY_OBJ);
		else if (retval & PK_PRIVATE_OBJ)
			/* Only return private keys */
			return (retval | PK_PRIKEY_OBJ);
	} else if (strcasecmp(objclass, "crl") == 0) {
		if (retval)
			return (-1);
		return (retval | PK_CRL_OBJ);
	}

	if (retval == 0) /* No matches found */
		retval = -1;
	return (retval);
}

KMF_ENCODE_FORMAT
Str2Format(char *formstr)
{
	if (formstr == NULL || strcasecmp(formstr, "der") == 0)
		return (KMF_FORMAT_ASN1);
	if (strcasecmp(formstr, "pem") == 0)
		return (KMF_FORMAT_PEM);
	if (strcasecmp(formstr, "pkcs12") == 0)
		return (KMF_FORMAT_PKCS12);
	if (strcasecmp(formstr, "raw") == 0)
		return (KMF_FORMAT_RAWKEY);

	return (KMF_FORMAT_UNDEF);
}

KMF_RETURN
select_token(void *kmfhandle, char *token, int readonly)
{
	KMF_ATTRIBUTE attlist[10];
	int i = 0;
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_PK11TOKEN;
	KMF_RETURN rv = KMF_OK;

	if (token == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	kmf_set_attr_at_index(attlist, i,
	    KMF_KEYSTORE_TYPE_ATTR, &kstype,
	    sizeof (kstype));
	i++;

	if (token) {
		kmf_set_attr_at_index(attlist, i,
		    KMF_TOKEN_LABEL_ATTR, token,
		    strlen(token));
		i++;
	}

	kmf_set_attr_at_index(attlist, i,
	    KMF_READONLY_ATTR, &readonly,
	    sizeof (readonly));
	i++;

	rv = kmf_configure_keystore(kmfhandle, i, attlist);
	if (rv == KMF_ERR_TOKEN_SELECTED)
		rv = KMF_OK;
	return (rv);
}

KMF_RETURN
configure_nss(void *kmfhandle, char *dir, char *prefix)
{
	KMF_ATTRIBUTE attlist[10];
	int i = 0;
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_NSS;
	KMF_RETURN rv = KMF_OK;

	kmf_set_attr_at_index(attlist, i,
	    KMF_KEYSTORE_TYPE_ATTR, &kstype,
	    sizeof (kstype));
	i++;

	if (dir) {
		kmf_set_attr_at_index(attlist, i,
		    KMF_DIRPATH_ATTR, dir,
		    strlen(dir));
		i++;
	}

	if (prefix) {
		kmf_set_attr_at_index(attlist, i,
		    KMF_CERTPREFIX_ATTR, prefix,
		    strlen(prefix));
		i++;

		kmf_set_attr_at_index(attlist, i,
		    KMF_KEYPREFIX_ATTR, prefix,
		    strlen(prefix));
		i++;
	}

	rv = kmf_configure_keystore(kmfhandle, i, attlist);
	if (rv == KMF_KEYSTORE_ALREADY_INITIALIZED)
		rv = KMF_OK;

	return (rv);
}

KMF_RETURN
get_pk12_password(KMF_CREDENTIAL *cred)
{
	KMF_RETURN rv = KMF_OK;
	char prompt[1024];

	/*
	 * Get the password to use for the PK12 encryption.
	 */
	(void) strlcpy(prompt,
	    gettext("Enter password to use for "
	    "accessing the PKCS12 file: "), sizeof (prompt));

	if (get_pin(prompt, NULL, (uchar_t **)&cred->cred,
	    (ulong_t *)&cred->credlen) != CKR_OK) {
		cred->cred = NULL;
		cred->credlen = 0;
	}

	return (rv);
}

#define	FILENAME_PROMPT gettext("Filename:")
#define	FILENAME_MINLEN	1
#define	FILENAME_MAXLEN MAXPATHLEN

#define	COUNTRY_PROMPT	gettext("Country Name (2 letter code) [US]:")
#define	STATE_PROMPT	gettext("State or Province Name (full name) " \
	"[Some-State]:")
#define	LOCALITY_PROMPT	gettext("Locality Name (eg, city) []:")
#define	ORG_PROMPT	gettext("Organization Name (eg, company) []:")
#define	UNIT_PROMPT	gettext("Organizational Unit Name (eg, section) []:")
#define	NAME_PROMPT	gettext("Common Name (eg, YOUR name) []:")
#define	EMAIL_PROMPT	gettext("Email Address []:")

#define	SERNO_PROMPT	gettext("Serial Number (hex value, example: " \
	"0x01020304):")
#define	SERNO_MINLEN	3
#define	SERNO_MAXLEN	42

#define	LABEL_PROMPT	gettext("Enter a label for the certificate:")
#define	LABEL_MINLEN	1
#define	LABEL_MAXLEN	1024

#define	COUNTRY_DEFAULT "US"
#define	STATE_DEFAULT	NULL
#define	INVALID_INPUT	gettext("Invalid input; please re-enter ...")

#define	SUBNAMESIZ	1024
#define	RDN_MIN		1
#define	RDN_MAX		64
#define	COUNTRYNAME_MIN	2
#define	COUNTRYNAME_MAX	2

static char *
get_input_string(char *prompt, char *default_str, int min_len, int max_len)
{
	char buf[1024];
	char *response = NULL;
	char *ret = NULL;
	int len;

	for (;;) {
		(void) printf("\t%s", prompt);
		(void) fflush(stdout);

		response = fgets(buf, sizeof (buf), stdin);
		if (response == NULL) {
			if (default_str != NULL) {
				ret = strdup(default_str);
			}
			break;
		}

		/* Skip any leading white space. */
		while (isspace(*response))
			response++;
		if (*response == '\0') {
			if (default_str != NULL) {
				ret = strdup(default_str);
			}
			break;
		}

		len = strlen(response);
		response[len-1] = '\0'; /* get rid of "LF" */
		len--;
		if (len >= min_len && len <= max_len) {
			ret = strdup(response);
			break;
		}

		(void) printf("%s\n", INVALID_INPUT);

	}

	return (ret);
}

int
get_filename(char *txt, char **result)
{
	char prompt[1024];
	char *fname = NULL;

	(void) snprintf(prompt, sizeof (prompt),
	    gettext("Enter filename for the %s: "),
	    txt);
	fname = get_input_string(prompt, NULL,
	    FILENAME_MINLEN, FILENAME_MAXLEN);
	*result = fname;
	return (0);
}

int
get_certlabel(char **result)
{
	char *label = NULL;

	label = get_input_string(LABEL_PROMPT, NULL,
	    LABEL_MINLEN, LABEL_MAXLEN);
	*result = label;
	return (0);
}

int
get_serial(char **result)
{
	char *serial = NULL;

	serial = get_input_string(SERNO_PROMPT, NULL, SERNO_MINLEN,
	    SERNO_MAXLEN);

	*result = serial;
	return (0);
}

int
get_subname(char **result)
{
	char *country = NULL;
	char *state = NULL;
	char *locality = NULL;
	char *org = NULL;
	char *unit = NULL;
	char *name = NULL;
	char *email = NULL;
	char *subname = NULL;

	(void) printf("Entering following fields for subject (a DN) ...\n");
	country = get_input_string(COUNTRY_PROMPT, COUNTRY_DEFAULT,
	    COUNTRYNAME_MIN, COUNTRYNAME_MAX);
	if (country == NULL)
		return (-1);

	state = get_input_string(STATE_PROMPT, STATE_DEFAULT,
	    RDN_MIN, RDN_MAX);

	locality = get_input_string(LOCALITY_PROMPT, NULL, RDN_MIN, RDN_MAX);
	org = get_input_string(ORG_PROMPT, NULL, RDN_MIN, RDN_MAX);
	unit = get_input_string(UNIT_PROMPT, NULL, RDN_MIN, RDN_MAX);
	name = get_input_string(NAME_PROMPT, NULL, RDN_MIN, RDN_MAX);
	email = get_input_string(EMAIL_PROMPT, NULL, RDN_MIN, RDN_MAX);

	/* Now create a subject name from the input strings */
	if ((subname = malloc(SUBNAMESIZ)) == NULL)
		goto out;

	(void) memset(subname, 0, SUBNAMESIZ);
	(void) strlcpy(subname, "C=", SUBNAMESIZ);
	(void) strlcat(subname, country, SUBNAMESIZ);
	if (state != NULL) {
		(void) strlcat(subname, ", ST=", SUBNAMESIZ);
		(void) strlcat(subname, state, SUBNAMESIZ);
	}

	if (locality != NULL) {
		(void) strlcat(subname, ", L=", SUBNAMESIZ);
		(void) strlcat(subname, locality, SUBNAMESIZ);
	}

	if (org != NULL) {
		(void) strlcat(subname, ", O=", SUBNAMESIZ);
		(void) strlcat(subname, org, SUBNAMESIZ);
	}

	if (unit != NULL) {
		(void) strlcat(subname, ", OU=", SUBNAMESIZ);
		(void) strlcat(subname, unit, SUBNAMESIZ);
	}

	if (name != NULL) {
		(void) strlcat(subname, ", CN=", SUBNAMESIZ);
		(void) strlcat(subname, name, SUBNAMESIZ);
	}

	if (email != NULL) {
		(void) strlcat(subname, ", E=", SUBNAMESIZ);
		(void) strlcat(subname, email, SUBNAMESIZ);
	}

out:
	if (country)
		free(country);
	if (state)
		free(state);
	if (locality)
		free(locality);
	if (org)
		free(org);
	if (unit)
		free(unit);
	if (name)
		free(name);
	if (email)
		free(email);

	if (subname == NULL)
		return (-1);
	else {
		*result = subname;
		return (0);
	}
}

/*
 * Parse a string of KeyUsage values and convert
 * them to the correct KU Bits.
 * The field may be marked "critical" by prepending
 * "critical:" to the list.
 * EX:  critical:digitialSignature,keyEncipherment
 */
KMF_RETURN
verify_keyusage(char *kustr, uint16_t *kubits, int *critical)
{
	KMF_RETURN ret = KMF_OK;
	uint16_t kuval;
	char *k;

	*kubits = 0;
	if (kustr == NULL || strlen(kustr) == 0)
		return (KMF_ERR_BAD_PARAMETER);

	/* Check to see if this is critical */
	if (strncasecmp(kustr, "critical:", strlen("critical:")) == 0) {
		*critical = TRUE;
		kustr += strlen("critical:");
	} else {
		*critical = FALSE;
	}

	k = strtok(kustr, ",");
	while (k != NULL) {
		kuval = kmf_string_to_ku(k);
		if (kuval == 0) {
			*kubits = 0;
			return (KMF_ERR_BAD_PARAMETER);
		}
		*kubits |= kuval;
		k = strtok(NULL, ",");
	}

	return (ret);
}

/*
 * Verify the alternate subject label is real or invalid.
 *
 * The field may be marked "critical" by prepending
 * "critical:" to the list.
 * EX:  "critical:IP=1.2.3.4"
 */
KMF_RETURN
verify_altname(char *arg, KMF_GENERALNAMECHOICES *type, int *critical)
{
	char *p;
	KMF_RETURN rv = KMF_OK;

	/* Check to see if this is critical */
	if (strncasecmp(arg, "critical:", strlen("critical:")) == 0) {
		*critical = TRUE;
		arg += strlen("critical:");
	} else {
		*critical = FALSE;
	}

	/* Make sure there is an "=" sign */
	p = strchr(arg, '=');
	if (p == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	p[0] = '\0';

	if (strcmp(arg, "IP") == 0)
		*type = GENNAME_IPADDRESS;
	else if (strcmp(arg, "DNS") == 0)
		*type = GENNAME_DNSNAME;
	else if (strcmp(arg, "EMAIL") == 0)
		*type = GENNAME_RFC822NAME;
	else if (strcmp(arg, "URI") == 0)
		*type = GENNAME_URI;
	else if (strcmp(arg, "DN") == 0)
		*type = GENNAME_DIRECTORYNAME;
	else if (strcmp(arg, "RID") == 0)
		*type = GENNAME_REGISTEREDID;
	else if (strcmp(arg, "KRB") == 0)
		*type = GENNAME_KRB5PRINC;
	else if (strcmp(arg, "UPN") == 0)
		*type = GENNAME_SCLOGON_UPN;
	else
		rv = KMF_ERR_BAD_PARAMETER;

	p[0] = '=';

	return (rv);
}

int
get_token_password(KMF_KEYSTORE_TYPE kstype,
	char *token_spec, KMF_CREDENTIAL *cred)
{
	char	prompt[1024];
	char	temptoken[32];
	char	*p = NULL;
	char	*t = NULL;
	int	len;

	(void) memset(temptoken, 0, sizeof (temptoken));
	if (kstype == KMF_KEYSTORE_PK11TOKEN) {
		p = strchr(token_spec, ':');
		if (p != NULL)
			*p = 0;
	}
	len = strlen(token_spec);
	if (len > sizeof (temptoken))
		len = sizeof (temptoken);

	(void) strncpy(temptoken, token_spec, len);

	/*
	 * Strip trailing whitespace
	 */
	t = temptoken + (len - 1);
	while (isspace(*t) && t >= temptoken) {
		*t = 0x00;
		t--;
	}

	/*
	 * Login to the token first.
	 */
	(void) snprintf(prompt, sizeof (prompt),
	    gettext(DEFAULT_TOKEN_PROMPT), temptoken);

	if (get_pin(prompt, NULL, (uchar_t **)&cred->cred,
	    (ulong_t *)&cred->credlen) != CKR_OK) {
		cred->cred = NULL;
		cred->credlen = 0;
	}

	if (kstype == KMF_KEYSTORE_PK11TOKEN && p != NULL)
		*p = ':';
	return (KMF_OK);
}

KMF_RETURN
verify_file(char *filename)
{
	KMF_RETURN ret = KMF_OK;
	int fd;

	/*
	 * Attempt to open with  the EXCL flag so that if
	 * it already exists, the open will fail.  It will
	 * also fail if the file cannot be created due to
	 * permissions on the parent directory, or if the
	 * parent directory itself does not exist.
	 */
	fd = open(filename, O_CREAT | O_EXCL, 0600);
	if (fd == -1) {
		if (errno == EEXIST)
			return (KMF_ERR_OPEN_FILE);
		else
			return (KMF_ERR_WRITE_FILE);
	}

	/* If we were able to create it, delete it. */
	(void) close(fd);
	(void) unlink(filename);

	return (ret);
}

void
display_error(void *handle, KMF_RETURN errcode, char *prefix)
{
	KMF_RETURN rv1, rv2;
	char *plugin_errmsg = NULL;
	char *kmf_errmsg = NULL;

	rv1 = kmf_get_plugin_error_str(handle, &plugin_errmsg);
	rv2 = kmf_get_kmf_error_str(errcode, &kmf_errmsg);

	cryptoerror(LOG_STDERR, "%s:", prefix);
	if (rv1 == KMF_OK && plugin_errmsg) {
		cryptoerror(LOG_STDERR, gettext("keystore error: %s"),
		    plugin_errmsg);
		kmf_free_str(plugin_errmsg);
	}

	if (rv2 == KMF_OK && kmf_errmsg) {
		cryptoerror(LOG_STDERR, gettext("libkmf error: %s"),
		    kmf_errmsg);
		kmf_free_str(kmf_errmsg);
	}

	if (rv1 != KMF_OK && rv2 != KMF_OK)
		cryptoerror(LOG_STDERR, gettext("<unknown error>\n"));

}

static KMF_RETURN
addToEKUList(EKU_LIST *ekus, int critical, KMF_OID *newoid)
{
	if (newoid != NULL && ekus != NULL) {
		ekus->eku_count++;

		ekus->critlist = realloc(ekus->critlist,
		    ekus->eku_count * sizeof (int));
		if (ekus->critlist != NULL)
			ekus->critlist[ekus->eku_count-1] = critical;
		else
			return (KMF_ERR_MEMORY);

		ekus->ekulist = realloc(
		    ekus->ekulist, ekus->eku_count * sizeof (KMF_OID));
		if (ekus->ekulist != NULL)
			ekus->ekulist[ekus->eku_count-1] = *newoid;
		else
			return (KMF_ERR_MEMORY);
	}
	return (KMF_OK);
}

void
free_eku_list(EKU_LIST *ekus)
{
	if (ekus != NULL && ekus->eku_count > 0) {
		int i;
		for (i = 0; i < ekus->eku_count; i++) {
			kmf_free_data(&ekus->ekulist[i]);
		}
		free(ekus->ekulist);
		free(ekus->critlist);
		free(ekus);
	}
}

static KMF_RETURN
parse_ekus(char *ekustr, EKU_LIST *ekus)
{
	KMF_RETURN rv = KMF_OK;
	KMF_OID *newoid;
	int critical;

	if (strncasecmp(ekustr, "critical:",
	    strlen("critical:")) == 0) {
		critical = TRUE;
		ekustr += strlen("critical:");
	} else {
		critical = FALSE;
	}
	newoid = kmf_ekuname_to_oid(ekustr);
	if (newoid != NULL) {
		rv = addToEKUList(ekus, critical, newoid);
		free(newoid);
	} else {
		rv = PK_ERR_USAGE;
	}

	return (rv);
}

KMF_RETURN
verify_ekunames(char *ekuliststr, EKU_LIST **ekulist)
{
	KMF_RETURN rv = KMF_OK;
	char *p;
	EKU_LIST *ekus = NULL;

	if (ekuliststr == NULL || strlen(ekuliststr) == 0)
		return (0);

	ekus = calloc(sizeof (EKU_LIST), 1);
	if (ekus == NULL)
		return (KMF_ERR_MEMORY);

	/*
	 * The list should be comma separated list of EKU Names.
	 */
	p = strtok(ekuliststr, ",");

	/* If no tokens found, then maybe it's just a single EKU value */
	if (p == NULL) {
		rv = parse_ekus(ekuliststr, ekus);
	}

	while (p != NULL) {
		rv = parse_ekus(p, ekus);

		if (rv != KMF_OK)
			break;
		p = strtok(NULL, ",");
	}

	if (rv != KMF_OK)
		free_eku_list(ekus);
	else
		*ekulist = ekus;

	return (rv);
}

KMF_RETURN
token_auth_needed(KMF_HANDLE_T handle, char *tokenlabel, int *auth)
{
	CK_TOKEN_INFO info;
	CK_SLOT_ID slot;
	CK_RV ckrv;
	KMF_RETURN rv;

	*auth = 0;
	rv = kmf_pk11_token_lookup(handle, tokenlabel, &slot);
	if (rv != KMF_OK)
		return (rv);

	ckrv = C_GetTokenInfo(slot, &info);
	if (ckrv != KMF_OK)
		return (KMF_ERR_INTERNAL);

	*auth = (info.flags & CKF_LOGIN_REQUIRED);

	return (KMF_OK);
}

void
show_ecc_curves()
{
	int i;

	(void) printf(gettext("Supported ECC curve names:\n"));
	for (i = 0; i < number_of_curves; i++) {
		(void) printf("%s", oid_table[i].name);
		if (i > 0 && ((i+1) % 5) == 0)
			(void) printf("\n");
		else if (i+1 < number_of_curves)
			(void) printf(", ");
	}
	(void) printf("\n");
}

KMF_OID *
ecc_name_to_oid(char *name)
{
	int i;
	for (i = 0; i < number_of_oids; i++) {
		if (strcasecmp(name, oid_table[i].name) == 0)
			return ((KMF_OID *)oid_table[i].oid);
	}
	return (NULL);
}
