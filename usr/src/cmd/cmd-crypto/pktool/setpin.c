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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
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

/*
 * Changes the token's PIN.
 */
int
pk_setpin(int argc, char *argv[])
/* ARGSUSED */
{
	char		*token_name = NULL;
	char		*manuf_id = NULL;
	char		*serial_no = NULL;
	CK_SLOT_ID		slot_id;
	CK_FLAGS		pin_state;
	CK_SESSION_HANDLE	sess;
	CK_UTF8CHAR_PTR		old_pin = NULL, new_pin = NULL;
	CK_ULONG		old_pinlen = 0, new_pinlen = 0;
	CK_RV			rv = CKR_OK;
	char		full_name[FULL_NAME_LEN];

	cryptodebug("inside pk_setpin");

	/* Get rid of subcommand word "setpin". */
	argc--;
	argv++;

	/* No additional args allowed. */
	if (argc != 0)
		return (PK_ERR_USAGE);
	/* Done parsing command line options. */

	/*
	 * Token_name, manuf_id, and serial_no are all optional.
	 * If unspecified, token_name must have a default value
	 * at least, so set it to the default softtoken value.
	 */
	if (token_name == NULL)
		token_name = SOFT_TOKEN_LABEL;
	if (manuf_id == NULL)
		manuf_id = SOFT_MANUFACTURER_ID;
	if (serial_no == NULL)
		serial_no = SOFT_TOKEN_SERIAL;
	full_token_name(token_name, manuf_id, serial_no, full_name);

	/* Find the slot with token. */
	if ((rv = find_token_slot(token_name, manuf_id, serial_no, &slot_id,
	    &pin_state)) != CKR_OK) {
		cryptoerror(LOG_STDERR,
		    gettext("Unable to find token %s (%s)."), full_name,
		    pkcs11_strerror(rv));
		final_pk11(NULL);
		return (PK_ERR_PK11);
	}

	/*
	 * If the token is the softtoken, check if the token flags show the
	 * PIN has not been set yet.  If not then set the old PIN to the
	 * default "changeme".  Otherwise, let user type in the correct old
	 * PIN to unlock token.
	 */
	if (pin_state == CKF_USER_PIN_TO_BE_CHANGED &&
	    strcmp(token_name, SOFT_TOKEN_LABEL) == 0) {
		cryptodebug("pin_state: first time passphrase is being set");
		if ((old_pin = (CK_UTF8CHAR_PTR) strdup(SOFT_DEFAULT_PIN)) ==
		    NULL) {
			cryptoerror(LOG_STDERR, "%s.", strerror(errno));
			final_pk11(NULL);
			return (PK_ERR_PK11);
		}
		old_pinlen = strlen(SOFT_DEFAULT_PIN);
	} else {
		cryptodebug("pin_state: changing an existing pin ");
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

	/* Open a R/W session to the token to change the PIN. */
	if ((rv = open_sess(slot_id, CKF_RW_SESSION, &sess)) != CKR_OK) {
		cryptoerror(LOG_STDERR,
		    gettext("Unable to open token session (%s)."),
		    pkcs11_strerror(rv));
		free(old_pin);
		final_pk11(NULL);
		return (PK_ERR_PK11);
	}

	/* Change the PIN if possible. */
	cryptodebug("calling C_SetPIN");
	rv = C_SetPIN(sess, old_pin, old_pinlen, new_pin, new_pinlen);

	/* Clean up. */
	free(old_pin);
	free(new_pin);
	quick_finish(sess);

	if (rv != CKR_OK) {
		if (rv == CKR_PIN_INCORRECT)
			cryptoerror(LOG_STDERR,
			    gettext("Incorrect passphrase."));
		else
			cryptoerror(LOG_STDERR,
			    gettext("Unable to change passphrase (%s)."),
			    pkcs11_strerror(rv));
		return (PK_ERR_PK11);
	}

	(void) fprintf(stdout, gettext("Passphrase changed.\n"));
	return (0);
}
