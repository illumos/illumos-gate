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
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

/*
 * This file implements the setpin operation for this tool.
 * The basic flow of the process is to load the PKCS#11 module,
 * finds the soft token, prompt the user for the old PIN (if
 * any) and the new PIN, change the token's PIN, and clean up.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <cryptoutil.h>
#include <security/cryptoki.h>
#include "common.h"

static int
setpin_nss(KMF_HANDLE_T handle,
	char *token_spec, char *dir, char *prefix)
{
	int rv = 0;
	KMF_CREDENTIAL		oldcred = { NULL, 0 };
	KMF_CREDENTIAL		newpincred = { NULL, 0 };
	CK_UTF8CHAR_PTR		old_pin = NULL, new_pin = NULL;
	CK_ULONG		old_pinlen = 0, new_pinlen = 0;
	KMF_ATTRIBUTE		setpinattrs[6];
	KMF_KEYSTORE_TYPE	kstype = KMF_KEYSTORE_NSS;
	int			numattrs = 0;

	rv = configure_nss(handle, dir, prefix);
	if (rv != KMF_OK)
		return (rv);

	kmf_set_attr_at_index(setpinattrs, numattrs, KMF_KEYSTORE_TYPE_ATTR,
	    &kstype, sizeof (kstype));
	numattrs++;
	if (token_spec != NULL) {
		kmf_set_attr_at_index(setpinattrs, numattrs,
		    KMF_TOKEN_LABEL_ATTR,
		    token_spec, strlen(token_spec));
		numattrs++;
	}

	if ((rv = get_pin(gettext("Enter current token passphrase "
	    "(<CR> if not set):"), NULL, &old_pin, &old_pinlen)) != CKR_OK) {
		cryptoerror(LOG_STDERR,
		    gettext("Unable to get token passphrase."));
		return (PK_ERR_NSS);
	}
	/* Get the user's new PIN. */
	if ((rv = get_pin(gettext("Create new passphrase:"), gettext(
	    "Re-enter new passphrase:"), &new_pin, &new_pinlen)) != CKR_OK) {
		if (rv == CKR_PIN_INCORRECT)
			cryptoerror(LOG_STDERR, gettext(
			    "Passphrases do not match."));
		else
			cryptoerror(LOG_STDERR, gettext(
			    "Unable to get and confirm new passphrase."));
		if (old_pin != NULL)
			free(old_pin);
		return (PK_ERR_NSS);
	}

	oldcred.cred = (char *)old_pin;
	oldcred.credlen = old_pinlen;

	kmf_set_attr_at_index(setpinattrs, numattrs, KMF_CREDENTIAL_ATTR,
	    &oldcred, sizeof (oldcred));
	numattrs++;

	newpincred.cred = (char *)new_pin;
	newpincred.credlen = new_pinlen;
	kmf_set_attr_at_index(setpinattrs, numattrs, KMF_NEWPIN_ATTR,
	    &newpincred, sizeof (newpincred));
	numattrs++;

	rv = kmf_set_token_pin(handle, numattrs, setpinattrs);

	if (new_pin)
		free(new_pin);
	if (old_pin)
		free(old_pin);

	return (rv);
}

static int
setpin_pkcs11(KMF_HANDLE_T handle, char *token_spec, boolean_t souser)
{
	CK_SLOT_ID		slot_id;
	CK_FLAGS		pin_state;
	CK_UTF8CHAR_PTR		old_pin = NULL, new_pin = NULL;
	CK_ULONG		old_pinlen = 0, new_pinlen = 0;
	CK_RV			rv = CKR_OK;
	char			*token_name = NULL;
	CK_TOKEN_INFO		token_info;
	KMF_CREDENTIAL		newpincred = { NULL, 0 };
	KMF_CREDENTIAL		oldcred = { NULL, 0 };
	KMF_KEYSTORE_TYPE	kstype = KMF_KEYSTORE_PK11TOKEN;
	KMF_ATTRIBUTE		attrlist[6];
	CK_USER_TYPE		user = CKU_USER;
	int			numattr = 0;

	/* If nothing is specified, default is to use softtoken. */
	if (token_spec == NULL) {
		token_spec = SOFT_TOKEN_LABEL ":" SOFT_MANUFACTURER_ID;
		token_name = SOFT_TOKEN_LABEL;
	}

	rv = kmf_pk11_token_lookup(NULL, token_spec, &slot_id);
	if (rv == KMF_OK) {
		/* find the pin state for the selected token */
		if (C_GetTokenInfo(slot_id, &token_info) != CKR_OK)
			return (PK_ERR_PK11);

		pin_state = token_info.flags & CKF_USER_PIN_TO_BE_CHANGED;
		if (token_name == NULL)
			token_name = (char *)token_info.label;
	}

	/*
	 * If the token is the softtoken, check if the token flags show the
	 * PIN has not been set yet.  If not then set the old PIN to the
	 * default "changeme".  Otherwise, let user type in the correct old
	 * PIN to unlock token.
	 */
	if (pin_state == CKF_USER_PIN_TO_BE_CHANGED &&
	    strcmp(token_name, SOFT_TOKEN_LABEL) == 0) {
		if ((old_pin = (CK_UTF8CHAR_PTR) strdup(SOFT_DEFAULT_PIN)) ==
		    NULL) {
			cryptoerror(LOG_STDERR, "%s.", strerror(errno));
			final_pk11(NULL);
			return (PK_ERR_PK11);
		}
		old_pinlen = strlen(SOFT_DEFAULT_PIN);
	} else {
		if ((rv = get_pin(gettext("Enter token passphrase:"), NULL,
		    &old_pin, &old_pinlen)) != CKR_OK) {
			cryptoerror(LOG_STDERR,
			    gettext("Unable to get token passphrase (%s)."),
			    pkcs11_strerror(rv));
			final_pk11(NULL);
			return (PK_ERR_PK11);
		}
	}

	/* Get the user's new PIN. */
	if ((rv = get_pin(gettext("Create new passphrase:"), gettext(
	    "Re-enter new passphrase:"), &new_pin, &new_pinlen)) != CKR_OK) {
		if (rv == CKR_PIN_INCORRECT)
			cryptoerror(LOG_STDERR, gettext(
			    "Passphrases do not match."));
		else
			cryptoerror(LOG_STDERR, gettext(
			    "Unable to get and confirm new passphrase (%s)."),
			    pkcs11_strerror(rv));
		free(old_pin);
		final_pk11(NULL);
		return (PK_ERR_PK11);
	}

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
	    &kstype, sizeof (kstype));
	numattr++;
	if (token_name != NULL) {
		kmf_set_attr_at_index(attrlist, numattr, KMF_TOKEN_LABEL_ATTR,
		    token_name, strlen(token_name));
		numattr++;
	}
	oldcred.cred = (char *)old_pin;
	oldcred.credlen = old_pinlen;
	kmf_set_attr_at_index(attrlist, numattr, KMF_CREDENTIAL_ATTR,
	    &oldcred, sizeof (oldcred));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_SLOT_ID_ATTR,
	    &slot_id, sizeof (slot_id));
	numattr++;

	newpincred.cred = (char *)new_pin;
	newpincred.credlen = new_pinlen;
	kmf_set_attr_at_index(attrlist, numattr, KMF_NEWPIN_ATTR,
	    &newpincred, sizeof (newpincred));
	numattr++;

	if (souser) {
		user = CKU_SO;
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_PK11_USER_TYPE_ATTR,
		    &user, sizeof (user));
		numattr++;
	}

	rv = kmf_set_token_pin(handle, numattr, attrlist);

	/* Clean up. */
	if (old_pin != NULL)
		free(old_pin);
	if (new_pin != NULL)
		free(new_pin);

	return (rv);
}

/*
 * Changes the token's PIN.
 */
int
pk_setpin(int argc, char *argv[])
/* ARGSUSED */
{
	int		opt;
	int		rv;
	extern int	optind_av;
	extern char	*optarg_av;
	char		*token_spec = NULL;
	char		*dir = NULL;
	char		*prefix = NULL;
	char		*utype = NULL;
	KMF_HANDLE_T	handle;
	KMF_KEYSTORE_TYPE	kstype = KMF_KEYSTORE_PK11TOKEN;
	boolean_t	souser = 0;

	/* Parse command line options.  Do NOT i18n/l10n. */
	while ((opt = getopt_av(argc, argv,
		"T:(token)k:(keystore)d:(dir)"
		"p:(prefix)u:(usertype)")) != EOF) {
		switch (opt) {
			case 'k':
				kstype = KS2Int(optarg_av);
				if (kstype == 0)
					return (PK_ERR_USAGE);
				break;
			case 'T':	/* token specifier */
				if (token_spec)
					return (PK_ERR_USAGE);
				token_spec = optarg_av;
				break;
			case 'd':
				if (dir)
					return (PK_ERR_USAGE);
				dir = optarg_av;
				break;
			case 'p':
				if (prefix)
					return (PK_ERR_USAGE);
				prefix = optarg_av;
				break;
			case 'u':
				utype = optarg_av;
				break;
			default:
				return (PK_ERR_USAGE);
		}
	}


	/* No additional args allowed. */
	argc -= optind_av;
	argv += optind_av;
	if (argc != 0)
		return (PK_ERR_USAGE);

	/* Done parsing command line options. */
	if (kstype == KMF_KEYSTORE_PK11TOKEN && EMPTYSTRING(token_spec)) {
		token_spec = PK_DEFAULT_PK11TOKEN;
	} else if (kstype == KMF_KEYSTORE_NSS && EMPTYSTRING(token_spec)) {
		token_spec = DEFAULT_NSS_TOKEN;
	}

	if ((rv = kmf_initialize(&handle, NULL, NULL)) != KMF_OK)
		return (rv);

	if (utype != NULL) {
		if (strcmp(utype, "so") == 0)
			souser = 1;
		else if (strcmp(utype, "user") == 0)
			souser = 0;
		else /* Wrong option string */
			return (PK_ERR_USAGE);
	}

	switch (kstype) {
		case KMF_KEYSTORE_PK11TOKEN:
			rv = setpin_pkcs11(handle, token_spec, souser);
			break;
		case KMF_KEYSTORE_NSS:
			rv = setpin_nss(handle, token_spec, dir, prefix);
			break;
		default:
			cryptoerror(LOG_STDERR,
			    gettext("incorrect keystore."));
			return (PK_ERR_USAGE);
	}

	(void) kmf_finalize(handle);

	if (rv == KMF_ERR_AUTH_FAILED) {
		cryptoerror(LOG_STDERR,
		    gettext("Incorrect passphrase."));
		return (PK_ERR_SYSTEM);
	} else if (rv != CKR_OK) {
		cryptoerror(LOG_STDERR,
		    gettext("Unable to change passphrase."));
		return (PK_ERR_SYSTEM);
	} else {
		(void) fprintf(stdout, gettext("Passphrase changed.\n"));
	}
	return (0);
}
