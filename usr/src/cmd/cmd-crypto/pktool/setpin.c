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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
	KMF_SETPIN_PARAMS	params;
	KMF_CREDENTIAL		newpincred = { NULL, 0 };
	CK_UTF8CHAR_PTR		old_pin = NULL, new_pin = NULL;
	CK_ULONG		old_pinlen = 0, new_pinlen = 0;

	rv = configure_nss(handle, dir, prefix);
	if (rv != KMF_OK)
		return (rv);

	(void) memset(&params, 0, sizeof (params));
	params.kstype = KMF_KEYSTORE_NSS;
	params.tokenname = token_spec;
	params.nssparms.slotlabel = token_spec;

	if ((rv = get_pin(gettext("Enter current token passphrase "
		"(<CR> if not set):"), NULL, &old_pin, &old_pinlen)) !=
		CKR_OK) {
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

	params.cred.cred = (char *)old_pin;
	params.cred.credlen = old_pinlen;

	newpincred.cred = (char *)new_pin;
	newpincred.credlen = new_pinlen;

	rv = KMF_SetTokenPin(handle, &params, &newpincred);

	if (new_pin)
		free(new_pin);
	if (old_pin)
		free(old_pin);

	return (rv);
}

static int
setpin_pkcs11(KMF_HANDLE_T handle, char *token_spec)
{
	CK_SLOT_ID		slot_id;
	CK_FLAGS		pin_state;
	CK_UTF8CHAR_PTR		old_pin = NULL, new_pin = NULL;
	CK_ULONG		old_pinlen = 0, new_pinlen = 0;
	CK_RV			rv = CKR_OK;
	char			*token_name = NULL;
	KMF_SETPIN_PARAMS	params;
	CK_TOKEN_INFO		token_info;
	KMF_CREDENTIAL		newpincred = { NULL, 0 };

	/* If nothing is specified, default is to use softtoken. */
	if (token_spec == NULL) {
		token_spec = SOFT_TOKEN_LABEL ":" SOFT_MANUFACTURER_ID;
		token_name = SOFT_TOKEN_LABEL;
	}

	rv = KMF_PK11TokenLookup(NULL, token_spec, &slot_id);
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

	(void) memset(&params, 0, sizeof (params));
	params.kstype = KMF_KEYSTORE_PK11TOKEN;
	params.tokenname = (char *)token_info.label;
	params.cred.cred = (char *)old_pin;
	params.cred.credlen = old_pinlen;
	params.pkcs11parms.slot = slot_id;

	newpincred.cred = (char *)new_pin;
	newpincred.credlen = new_pinlen;

	rv = KMF_SetTokenPin(handle, &params, &newpincred);

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
	KMF_HANDLE_T	handle;
	KMF_KEYSTORE_TYPE	kstype = KMF_KEYSTORE_PK11TOKEN;

	/* Parse command line options.  Do NOT i18n/l10n. */
	while ((opt = getopt_av(argc, argv,
		"T:(token)k:(keystore)d:(dir)"
		"p:(prefix)")) != EOF) {
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
			default:
				return (PK_ERR_USAGE);
				break;
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

	if ((rv = KMF_Initialize(&handle, NULL, NULL)) != KMF_OK)
		return (rv);

	switch (kstype) {
		case KMF_KEYSTORE_PK11TOKEN:
			rv = setpin_pkcs11(handle, token_spec);
			break;
		case KMF_KEYSTORE_NSS:
			rv = setpin_nss(handle, token_spec, dir, prefix);
			break;
		default:
			cryptoerror(LOG_STDERR,
				gettext("incorrect keystore."));
			return (PK_ERR_USAGE);
	}

	(void) KMF_Finalize(handle);

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
